//! 记录模型账号的实时额度用量（5 小时 / 周）曲线，供监控页展示。
//! 上游每次 /v1/messages 响应（含 200）都带 `anthropic-ratelimit-unified-{5h,7d}-{utilization,reset}`。
//!
//! 热路径只做一件事：把这个账号的最新观测记进内存（一把短锁，不碰数据库）。
//! 后台单独一个写入任务、专用 1 个连接的独立连接池，每分钟把这一分钟里有过响应的账号各写一行
//! （取这一分钟内最后一次观测）。这一分钟没有响应的账号不写。前台连接池完全不被占用，
//! 冷却读取、请求日志不受影响；写库失败只告警，下一分钟重试。
use hyper::HeaderMap;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        LazyLock, Mutex, OnceLock,
    },
    time::Duration,
};
use tracing::{info, warn};

const FLUSH_INTERVAL: Duration = Duration::from_secs(60);
const DB_TIMEOUT: Duration = Duration::from_secs(5);

/// 每个账号每分钟一行。同一分钟重复写入（比如刚好跨了两次 flush）时保留更新的观测。
const UPSERT: &str = "INSERT INTO secret_quota_usage (secret_id, minute, five_hour_utilization, five_hour_reset, \
     seven_day_utilization, seven_day_reset, unified_status, http_status, observed_at) \
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) \
     ON CONFLICT (secret_id, minute) DO UPDATE SET five_hour_utilization=EXCLUDED.five_hour_utilization, \
     five_hour_reset=EXCLUDED.five_hour_reset, seven_day_utilization=EXCLUDED.seven_day_utilization, \
     seven_day_reset=EXCLUDED.seven_day_reset, unified_status=EXCLUDED.unified_status, \
     http_status=EXCLUDED.http_status, observed_at=EXCLUDED.observed_at \
     WHERE secret_quota_usage.observed_at <= EXCLUDED.observed_at";

#[derive(Debug, Clone, Default, PartialEq)]
pub(super) struct QuotaUsage {
    pub five_hour_utilization: Option<f64>,
    pub five_hour_reset: Option<i64>,
    pub seven_day_utilization: Option<f64>,
    pub seven_day_reset: Option<i64>,
    /// `anthropic-ratelimit-unified-status`（allowed / allowed_warning / rejected）
    pub status: Option<String>,
}

fn header<'a>(headers: &'a HeaderMap, key: &str) -> Option<&'a str> {
    headers
        .get(format!("anthropic-ratelimit-unified-{key}"))
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

/// 用量是 0~1 的比例（超额时可能略大于 1）；非数、负数、离谱的值都丢弃
fn utilization(headers: &HeaderMap, window: &str) -> Option<f64> {
    header(headers, &format!("{window}-utilization"))
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| v.is_finite() && (0.0..=10.0).contains(v))
}

fn reset(headers: &HeaderMap, window: &str) -> Option<i64> {
    header(headers, &format!("{window}-reset"))
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|&v| v > 0 && time::OffsetDateTime::from_unix_timestamp(v).is_ok())
}

/// 两个窗口的用量都没有 → None（比如 API key 账号不带这些头），不写库
pub(super) fn parse(headers: &HeaderMap) -> Option<QuotaUsage> {
    let usage = QuotaUsage {
        five_hour_utilization: utilization(headers, "5h"),
        five_hour_reset: reset(headers, "5h"),
        seven_day_utilization: utilization(headers, "7d"),
        seven_day_reset: reset(headers, "7d"),
        status: header(headers, "status").map(str::to_owned),
    };
    if usage.five_hour_utilization.is_none() && usage.seven_day_utilization.is_none() {
        return None;
    }
    Some(usage)
}

#[derive(Debug, Clone, PartialEq)]
struct Observation {
    usage: QuotaUsage,
    http_status: i32,
    /// 观测时刻（毫秒）
    observed_at: i64,
    /// 进程内单调序号：同一毫秒到达的两条也能分先后
    seq: u64,
}

static SEQ: AtomicU64 = AtomicU64::new(0);
/// 还没写库的观测：每个账号只留最新一条（写完即清）
static PENDING: LazyLock<Mutex<HashMap<String, Observation>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static STARTED: OnceLock<()> = OnceLock::new();

fn remember(id: &str, obs: Observation) {
    let mut pending = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    match pending.get(id) {
        Some(old) if old.seq > obs.seq => {}
        _ => {
            pending.insert(id.to_owned(), obs);
        }
    }
}

/// 热路径：只读响应头、记内存，不碰数据库
pub(super) fn record(id: Option<&str>, host: &str, path: &str, response: &reqwest::Response) {
    if !super::cooldown::applies(host, path) {
        return;
    }
    let Some(id) = id else {
        return;
    };
    let Some(usage) = parse(response.headers()) else {
        return;
    };
    let observed_at = (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64;
    remember(
        id,
        Observation {
            usage,
            http_status: response.status().as_u16() as i32,
            observed_at,
            seq: SEQ.fetch_add(1, Ordering::Relaxed),
        },
    );
}

/// 把内存里待写的观测各写一行（按观测所在的分钟归桶）。写失败的放回去，下一轮重试；
/// 放回时如果期间又来了更新的观测，以更新的为准。
async fn flush(pool: &PgPool) -> usize {
    let batch: Vec<(String, Observation)> = {
        let mut pending = PENDING.lock().unwrap_or_else(|e| e.into_inner());
        pending.drain().collect()
    };
    let mut written = 0;
    for (id, obs) in batch {
        let minute = obs.observed_at / 60_000 * 60;
        let result = tokio::time::timeout(
            DB_TIMEOUT,
            sqlx::query(UPSERT)
                .bind(&id)
                .bind(minute)
                .bind(obs.usage.five_hour_utilization)
                .bind(obs.usage.five_hour_reset)
                .bind(obs.usage.seven_day_utilization)
                .bind(obs.usage.seven_day_reset)
                .bind(obs.usage.status.clone())
                .bind(obs.http_status)
                .bind(obs.observed_at)
                .execute(pool),
        )
        .await;
        match result {
            Ok(Ok(_)) => written += 1,
            Ok(Err(e)) if is_missing_secret(&e) => {
                // 账号已删除：外键拒绝，丢弃这条，不重试
            }
            _ => {
                warn!(secret_id = %id, reason = "quota_usage_write_failed", "额度用量写入失败，下一分钟重试，不影响转发");
                remember(&id, obs);
            }
        }
    }
    written
}

fn is_missing_secret(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .is_some_and(|d| d.is_foreign_key_violation())
}

/// 启动后台写入：独立连接池（最多 1 个连接、懒连接，数据库暂时不可用也不影响网关启动）。
/// 只启动一次。
pub(crate) fn start(database_url: &str) {
    if STARTED.set(()).is_err() {
        return;
    }
    let pool = match PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(DB_TIMEOUT)
        .connect_lazy(database_url)
    {
        Ok(pool) => pool,
        Err(e) => {
            warn!(error = %e, "额度用量写入连接池创建失败，本次运行不记录用量");
            return;
        }
    };
    info!("额度用量记录已启动：每分钟写一次，专用 1 个数据库连接");
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(FLUSH_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            flush(&pool).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                format!("anthropic-ratelimit-unified-{k}")
                    .parse::<hyper::header::HeaderName>()
                    .unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    #[test]
    fn full_headers() {
        let h = headers(&[
            ("status", "allowed"),
            ("5h-utilization", "0.42"),
            ("5h-reset", "1793142000"),
            ("7d-utilization", "0.87"),
            ("7d-reset", "1793500000"),
        ]);
        assert_eq!(
            parse(&h),
            Some(QuotaUsage {
                five_hour_utilization: Some(0.42),
                five_hour_reset: Some(1793142000),
                seven_day_utilization: Some(0.87),
                seven_day_reset: Some(1793500000),
                status: Some("allowed".into()),
            })
        );
    }

    #[test]
    fn one_window_is_enough() {
        let usage = parse(&headers(&[("7d-utilization", "1.0")])).unwrap();
        assert_eq!(usage.seven_day_utilization, Some(1.0));
        assert_eq!(usage.five_hour_utilization, None);
    }

    #[test]
    fn no_utilization_no_record() {
        assert_eq!(parse(&HeaderMap::new()), None);
        // 只有状态和重置时间、没有用量 → 不记
        assert_eq!(
            parse(&headers(&[
                ("status", "allowed"),
                ("5h-reset", "1793142000")
            ])),
            None
        );
    }

    #[test]
    fn bad_values_dropped() {
        for v in ["", "abc", "-0.1", "NaN", "inf", "11"] {
            let h = headers(&[("5h-utilization", v), ("7d-utilization", "0.5")]);
            assert_eq!(parse(&h).unwrap().five_hour_utilization, None, "{v}");
        }
        let h = headers(&[
            ("7d-utilization", "0.5"),
            ("7d-reset", "bad"),
            ("5h-reset", "-5"),
        ]);
        let usage = parse(&h).unwrap();
        assert_eq!(usage.seven_day_reset, None);
        assert_eq!(usage.five_hour_reset, None);
    }
}

#[cfg(test)]
#[tokio::test]
#[ignore = "需要专用隔离库 COOLDOWN_TEST_DATABASE_URL"]
async fn one_row_per_account_per_minute() {
    let url = std::env::var("COOLDOWN_TEST_DATABASE_URL").expect("只允许隔离测试库");
    let pool = PgPool::connect(&url).await.unwrap();
    sqlx::raw_sql("CREATE TABLE IF NOT EXISTS secrets(id TEXT PRIMARY KEY); DROP TABLE IF EXISTS secret_quota_usage;")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::raw_sql(include_str!(
        "../../../../packages/db/prisma/migrations/20261031010000_secret_quota_usage/migration.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO secrets(id) VALUES('q1'),('q2') ON CONFLICT DO NOTHING")
        .execute(&pool)
        .await
        .unwrap();
    let response = |util: &str| {
        reqwest::Response::from(
            hyper::Response::builder()
                .status(200)
                .header("anthropic-ratelimit-unified-status", "allowed")
                .header("anthropic-ratelimit-unified-5h-utilization", "0.25")
                .header("anthropic-ratelimit-unified-7d-utilization", util)
                .header("anthropic-ratelimit-unified-7d-reset", "1793500000")
                .body(Vec::<u8>::new())
                .unwrap(),
        )
    };
    let rows = || async {
        sqlx::query_as::<_, (String, i64, Option<f64>, Option<f64>, Option<i64>, Option<String>, i32)>(
            "SELECT secret_id, minute, five_hour_utilization, seven_day_utilization, seven_day_reset, unified_status, http_status \
             FROM secret_quota_usage ORDER BY secret_id, minute",
        )
        .fetch_all(&pool)
        .await
        .unwrap()
    };
    // 走真实入口 cooldown::observe（转发三处都调它）。非模型接口、没有账号 id：都不记
    super::cooldown::observe(
        &pool,
        Some("q1"),
        "api.anthropic.com",
        "/v1/models",
        &response("0.9"),
    )
    .await;
    super::cooldown::observe(
        &pool,
        None,
        "api.anthropic.com",
        "/v1/messages",
        &response("0.9"),
    )
    .await;
    // 同一分钟内 q1 来了三次：只留最后一次；q2 一次
    for util in ["0.5", "0.6", "0.7"] {
        super::cooldown::observe(
            &pool,
            Some("q1"),
            "api.anthropic.com:443",
            "/v1/messages?beta=true",
            &response(util),
        )
        .await;
    }
    super::cooldown::observe(
        &pool,
        Some("q2"),
        "api.anthropic.com",
        "/v1/messages",
        &response("0.3"),
    )
    .await;
    // 热路径不写库
    assert!(rows().await.is_empty());
    assert_eq!(flush(&pool).await, 2);
    let got = rows().await;
    assert_eq!(got.len(), 2);
    assert_eq!(
        (got[0].0.as_str(), got[0].3, got[0].4, got[0].6),
        ("q1", Some(0.7), Some(1793500000), 200)
    );
    assert_eq!(got[0].1 % 60, 0);
    assert_eq!((got[1].0.as_str(), got[1].3), ("q2", Some(0.3)));
    // 这一分钟没有新响应：不写
    assert_eq!(flush(&pool).await, 0);
    assert_eq!(rows().await.len(), 2);
    // 同一分钟桶里迟到的旧观测不覆盖
    sqlx::query(UPSERT)
        .bind("q1")
        .bind(got[0].1)
        .bind(None::<f64>)
        .bind(None::<i64>)
        .bind(Some(0.1))
        .bind(None::<i64>)
        .bind(None::<String>)
        .bind(200)
        .bind(1_i64)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(rows().await[0].3, Some(0.7));
    // 下一分钟的观测是新的一行
    remember(
        "q1",
        Observation {
            usage: parse(response("0.8").headers()).unwrap(),
            http_status: 200,
            observed_at: (got[0].1 + 60) * 1000 + 5,
            seq: SEQ.fetch_add(1, Ordering::Relaxed),
        },
    );
    assert_eq!(flush(&pool).await, 1);
    assert_eq!(rows().await.len(), 3);
    // 账号删了：用量级联删除；之后到来的观测写不进去也不重试
    sqlx::query("DELETE FROM secrets WHERE id='q2'")
        .execute(&pool)
        .await
        .unwrap();
    super::cooldown::observe(
        &pool,
        Some("q2"),
        "api.anthropic.com",
        "/v1/messages",
        &response("0.4"),
    )
    .await;
    assert_eq!(flush(&pool).await, 0);
    assert!(PENDING.lock().unwrap().get("q2").is_none());
    assert!(rows().await.iter().all(|r| r.0 == "q1"));
}

#[test]
fn newer_seq_wins_in_memory() {
    let obs = |util: f64, seq: u64| Observation {
        usage: QuotaUsage {
            seven_day_utilization: Some(util),
            ..Default::default()
        },
        http_status: 200,
        observed_at: 1000,
        seq,
    };
    remember("mem", obs(0.5, 10));
    remember("mem", obs(0.4, 9)); // 同毫秒、更早到达
    assert_eq!(
        PENDING
            .lock()
            .unwrap()
            .get("mem")
            .unwrap()
            .usage
            .seven_day_utilization,
        Some(0.5)
    );
    remember("mem", obs(0.6, 11));
    assert_eq!(
        PENDING
            .lock()
            .unwrap()
            .remove("mem")
            .unwrap()
            .usage
            .seven_day_utilization,
        Some(0.6)
    );
}
