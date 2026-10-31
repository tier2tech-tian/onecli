//! 记录模型账号的实时额度用量（5 小时 / 周）明细，供监控页画曲线、做统计。
//! 上游每次 /v1/messages 响应（含 200）都带 `anthropic-ratelimit-unified-{5h,7d}-{utilization,reset}`，
//! 每个带用量的响应都记一行。
//!
//! 性能：热路径只把观测压进内存队列（一把短锁，不碰数据库）。后台单独一个写入任务、
//! 专用 1 个连接的独立连接池，每 5 秒把队列里攒下的观测用一条多行 INSERT 批量写入。
//! 前台连接池完全不被占用，冷却读取、请求日志不受影响。
//! 队列有上限：数据库长时间写不进时丢最旧的、告警，不会把网关内存撑爆。写失败的整批放回，下一轮重试。
//!
//! token 用量（10-31）：成功回复（2xx）的观测先按网关自己的请求编号（每次转发唯一的 UUID）暂存，
//! 等 `token_usage` 旁路读完回复正文再连同 token 数一起入队，同一行写库；`observed_at` 仍是收到回复头的时刻。
//! 暂存有上限，超过 30 分钟没人认领（比如回复没走到转发出口）的按无 token 入队，保证额度那几列不丢。
use hyper::HeaderMap;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{
    collections::{HashMap, VecDeque},
    sync::{LazyLock, Mutex, OnceLock},
    time::{Duration, Instant},
};

use super::token_usage::TokenUsage;
use tracing::{info, warn};

const FLUSH_INTERVAL: Duration = Duration::from_secs(5);
const DB_TIMEOUT: Duration = Duration::from_secs(10);
/// 一条 INSERT 最多写多少行
const BATCH: usize = 1000;
/// 内存里最多攒多少条（约 1.5 万条/天的量，够撑数据库断开好几天）
const MAX_PENDING: usize = 100_000;
/// 等 token 的暂存最多多少条（≈ 同时在流式输出的回复数），满了就不等 token 直接入队
const MAX_HELD: usize = 10_000;
/// 暂存最久多久；超时按无 token 入队
const HOLD_MAX: Duration = Duration::from_secs(30 * 60);

/// 批量写入：数组展开成多行。账号已被删除的行跳过（不让整批因外键失败）。
const INSERT: &str = "INSERT INTO secret_quota_usage (secret_id, observed_at, five_hour_utilization, five_hour_reset, \
     seven_day_utilization, seven_day_reset, unified_status, http_status, \
     model, input_tokens, output_tokens, cache_creation_input_tokens, cache_read_input_tokens) \
     SELECT u.* FROM UNNEST($1::text[], $2::bigint[], $3::float8[], $4::bigint[], $5::float8[], $6::bigint[], $7::text[], $8::int4[], \
       $9::text[], $10::bigint[], $11::bigint[], $12::bigint[], $13::bigint[]) \
       AS u(secret_id, observed_at, five_hour_utilization, five_hour_reset, seven_day_utilization, seven_day_reset, unified_status, http_status, \
       model, input_tokens, output_tokens, cache_creation_input_tokens, cache_read_input_tokens) \
     WHERE EXISTS (SELECT 1 FROM secrets s WHERE s.id = u.secret_id)";

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
pub(super) struct Observation {
    secret_id: String,
    usage: QuotaUsage,
    http_status: i32,
    /// 观测时刻（毫秒）
    observed_at: i64,
    /// 回复正文里的 token 用量；没读到就是 None
    tokens: Option<TokenUsage>,
}

static PENDING: LazyLock<Mutex<VecDeque<Observation>>> =
    LazyLock::new(|| Mutex::new(VecDeque::new()));
static STARTED: OnceLock<()> = OnceLock::new();
/// 等 token 的观测：网关请求编号 → (暂存时刻, 观测)。不用上游 request-id，避免外部值重复时认领错（6号 P2）
static HELD: LazyLock<Mutex<HashMap<u128, (Instant, Observation)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// 入队；超过上限丢最旧的。返回丢掉的条数。
fn push(obs: Observation) -> usize {
    let mut q = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    push_bounded(&mut q, obs)
}

fn push_bounded(q: &mut VecDeque<Observation>, obs: Observation) -> usize {
    q.push_back(obs);
    let mut dropped = 0;
    while q.len() > MAX_PENDING {
        q.pop_front();
        dropped += 1;
    }
    dropped
}

fn push_logged(obs: Observation) {
    let dropped = push(obs);
    if dropped > 0 {
        warn!(
            dropped,
            reason = "quota_usage_queue_full",
            "额度用量队列已满，丢弃最旧记录"
        );
    }
}

/// 暂存等 token；暂存满了或编号重复就交回调用方直接入队
fn hold(request_id: uuid::Uuid, obs: Observation) -> Option<Observation> {
    let mut held = HELD.lock().unwrap_or_else(|e| e.into_inner());
    let key = request_id.as_u128();
    if held.len() >= MAX_HELD || held.contains_key(&key) {
        return Some(obs);
    }
    held.insert(key, (Instant::now(), obs));
    None
}

/// 转发出口认领暂存的观测（token 旁路用）
pub(super) fn take_held(request_id: uuid::Uuid) -> Option<Observation> {
    HELD.lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&request_id.as_u128())
        .map(|(_, obs)| obs)
}

/// 旁路读完回复：填上 token 数（可能没有）入队
pub(super) fn complete(mut obs: Observation, tokens: Option<TokenUsage>) {
    obs.tokens = tokens;
    push_logged(obs);
}

/// 测试用：取出队列里某个账号的观测（只看 token 部分）
#[cfg(test)]
pub(super) fn drain_for_test(secret_id: &str) -> Vec<Option<TokenUsage>> {
    let mut q = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    let (mine, rest): (VecDeque<_>, VecDeque<_>) =
        q.drain(..).partition(|o| o.secret_id == secret_id);
    *q = rest;
    mine.into_iter().map(|o| o.tokens).collect()
}

/// 超时没人认领的暂存按无 token 入队，返回条数
fn sweep_held(max_age: Duration) -> usize {
    let expired: Vec<Observation> = {
        let mut held = HELD.lock().unwrap_or_else(|e| e.into_inner());
        let keys: Vec<u128> = held
            .iter()
            .filter(|(_, (at, _))| at.elapsed() >= max_age)
            .map(|(k, _)| *k)
            .collect();
        keys.iter()
            .filter_map(|k| held.remove(k))
            .map(|(_, obs)| obs)
            .collect()
    };
    let n = expired.len();
    for obs in expired {
        push_logged(obs);
    }
    n
}

/// 热路径：只读响应头、入内存队列（或暂存等 token），不碰数据库
pub(super) fn record(
    id: Option<&str>,
    host: &str,
    path: &str,
    response: &reqwest::Response,
    request_id: Option<uuid::Uuid>,
) {
    if !super::cooldown::applies(host, path) {
        return;
    }
    let Some(id) = id else {
        return;
    };
    let Some(usage) = parse(response.headers()) else {
        return;
    };
    let obs = Observation {
        secret_id: id.to_owned(),
        usage,
        http_status: response.status().as_u16() as i32,
        observed_at: (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64,
        tokens: None,
    };
    // 只有成功回复会原样转发给调用方、正文里才有用量；429 等轮换掉的回复直接入队。
    // 一次转发里成功回复至多一个，所以网关请求编号能唯一对上转发出口的那条回复。
    let obs = match request_id {
        Some(rid) if response.status().is_success() => hold(rid, obs),
        _ => Some(obs),
    };
    if let Some(obs) = obs {
        push_logged(obs);
    }
}

/// 把队列里攒下的观测分批写库，返回写入行数。某批失败就把这批及之后的放回队头，下一轮重试。
async fn flush(pool: &PgPool) -> u64 {
    let mut written = 0;
    loop {
        let batch: Vec<Observation> = {
            let mut q = PENDING.lock().unwrap_or_else(|e| e.into_inner());
            let n = q.len().min(BATCH);
            q.drain(..n).collect()
        };
        if batch.is_empty() {
            return written;
        }
        let col = |f: fn(&Observation) -> Option<f64>| batch.iter().map(f).collect::<Vec<_>>();
        let coli = |f: fn(&Observation) -> Option<i64>| batch.iter().map(f).collect::<Vec<_>>();
        let tok = |f: fn(&TokenUsage) -> Option<i64>| {
            batch
                .iter()
                .map(|o| o.tokens.as_ref().and_then(f))
                .collect::<Vec<_>>()
        };
        let result = tokio::time::timeout(
            DB_TIMEOUT,
            sqlx::query(INSERT)
                .bind(
                    batch
                        .iter()
                        .map(|o| o.secret_id.clone())
                        .collect::<Vec<_>>(),
                )
                .bind(batch.iter().map(|o| o.observed_at).collect::<Vec<_>>())
                .bind(col(|o| o.usage.five_hour_utilization))
                .bind(coli(|o| o.usage.five_hour_reset))
                .bind(col(|o| o.usage.seven_day_utilization))
                .bind(coli(|o| o.usage.seven_day_reset))
                .bind(
                    batch
                        .iter()
                        .map(|o| o.usage.status.clone())
                        .collect::<Vec<_>>(),
                )
                .bind(batch.iter().map(|o| o.http_status).collect::<Vec<_>>())
                .bind(
                    batch
                        .iter()
                        .map(|o| o.tokens.as_ref().and_then(|t| t.model.clone()))
                        .collect::<Vec<_>>(),
                )
                .bind(tok(|t| t.input_tokens))
                .bind(tok(|t| t.output_tokens))
                .bind(tok(|t| t.cache_creation_input_tokens))
                .bind(tok(|t| t.cache_read_input_tokens))
                .execute(pool),
        )
        .await;
        match result {
            Ok(Ok(r)) => written += r.rows_affected(),
            _ => {
                warn!(
                    rows = batch.len(),
                    reason = "quota_usage_write_failed",
                    "额度用量写入失败，下一轮重试，不影响转发"
                );
                let mut q = PENDING.lock().unwrap_or_else(|e| e.into_inner());
                for obs in batch.into_iter().rev() {
                    q.push_front(obs);
                }
                while q.len() > MAX_PENDING {
                    q.pop_front();
                }
                return written;
            }
        }
    }
}

/// 启动后台写入：独立连接池（最多 1 个连接、懒连接，数据库暂时不可用也不影响网关启动）。只启动一次。
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
    info!("额度用量记录已启动：每条请求都记（成功回复连同 token 数），每 5 秒批量写库，专用 1 个数据库连接");
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(FLUSH_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            sweep_held(HOLD_MAX);
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
async fn every_response_recorded_in_batches() {
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
    sqlx::raw_sql(include_str!(
        "../../../../packages/db/prisma/migrations/20261031120000_secret_quota_usage_tokens/migration.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO secrets(id) VALUES('q1'),('q2') ON CONFLICT DO NOTHING")
        .execute(&pool)
        .await
        .unwrap();
    PENDING.lock().unwrap().clear();
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
    let count = || async {
        sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM secret_quota_usage")
            .fetch_one(&pool)
            .await
            .unwrap()
            .0
    };
    // 走真实入口 cooldown::observe（转发三处都调它）。非模型接口、没有账号 id：都不记
    super::cooldown::observe(
        &pool,
        Some("q1"),
        "api.anthropic.com",
        "/v1/models",
        &response("0.9"),
        None,
    )
    .await;
    super::cooldown::observe(
        &pool,
        None,
        "api.anthropic.com",
        "/v1/messages",
        &response("0.9"),
        None,
    )
    .await;
    for util in ["0.5", "0.6", "0.7"] {
        super::cooldown::observe(
            &pool,
            Some("q1"),
            "api.anthropic.com:443",
            "/v1/messages?beta=true",
            &response(util),
            None,
        )
        .await;
    }
    super::cooldown::observe(
        &pool,
        Some("q2"),
        "api.anthropic.com",
        "/v1/messages",
        &response("0.3"),
        None,
    )
    .await;
    // 热路径不写库
    assert_eq!(count().await, 0);
    assert_eq!(PENDING.lock().unwrap().len(), 4);
    // 每条都记，顺序与值都在
    assert_eq!(flush(&pool).await, 4);
    let q1: Vec<(Option<f64>, Option<f64>, Option<i64>, Option<String>, i32)> = sqlx::query_as(
        "SELECT five_hour_utilization, seven_day_utilization, seven_day_reset, unified_status, http_status \
         FROM secret_quota_usage WHERE secret_id='q1' ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        q1.iter().map(|r| r.1).collect::<Vec<_>>(),
        vec![Some(0.5), Some(0.6), Some(0.7)]
    );
    assert_eq!(
        q1[2],
        (
            Some(0.25),
            Some(0.7),
            Some(1793500000),
            Some("allowed".into()),
            200
        )
    );
    // 队列空了：再 flush 不写
    assert_eq!(flush(&pool).await, 0);
    // 多于一批：2500 条分 3 批写完
    for _ in 0..2500 {
        super::cooldown::observe(
            &pool,
            Some("q2"),
            "api.anthropic.com",
            "/v1/messages",
            &response("0.4"),
            None,
        )
        .await;
    }
    assert_eq!(flush(&pool).await, 2500);
    assert_eq!(count().await, 2504);
    // 已删除账号的观测跳过，不让整批失败；同批其他账号照常写入
    sqlx::query("DELETE FROM secrets WHERE id='q2'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(count().await, 3, "删账号连带删其用量");
    super::cooldown::observe(
        &pool,
        Some("q2"),
        "api.anthropic.com",
        "/v1/messages",
        &response("0.4"),
        None,
    )
    .await;
    super::cooldown::observe(
        &pool,
        Some("q1"),
        "api.anthropic.com",
        "/v1/messages",
        &response("0.8"),
        None,
    )
    .await;
    assert_eq!(flush(&pool).await, 1);
    assert_eq!(count().await, 4);
    // 写失败：整批放回，顺序不变，下一轮补写
    sqlx::raw_sql("ALTER TABLE secret_quota_usage RENAME TO secret_quota_usage_off")
        .execute(&pool)
        .await
        .unwrap();
    super::cooldown::observe(
        &pool,
        Some("q1"),
        "api.anthropic.com",
        "/v1/messages",
        &response("0.81"),
        None,
    )
    .await;
    super::cooldown::observe(
        &pool,
        Some("q1"),
        "api.anthropic.com",
        "/v1/messages",
        &response("0.82"),
        None,
    )
    .await;
    assert_eq!(flush(&pool).await, 0);
    assert_eq!(PENDING.lock().unwrap().len(), 2);
    sqlx::raw_sql("ALTER TABLE secret_quota_usage_off RENAME TO secret_quota_usage")
        .execute(&pool)
        .await
        .unwrap();
    super::cooldown::observe(
        &pool,
        Some("q1"),
        "api.anthropic.com",
        "/v1/messages",
        &response("0.83"),
        None,
    )
    .await;
    assert_eq!(flush(&pool).await, 3);
    let tail: Vec<(Option<f64>,)> = sqlx::query_as(
        "SELECT seven_day_utilization FROM secret_quota_usage WHERE secret_id='q1' ORDER BY id DESC LIMIT 3",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(tail, vec![(Some(0.83),), (Some(0.82),), (Some(0.81),)]);
    // token 用量：成功回复暂存 → 认领填 token → 与额度同一行写入；老行 token 列为空
    let rid = uuid::Uuid::new_v4();
    let ok = reqwest::Response::from(
        hyper::Response::builder()
            .status(200)
            .header("anthropic-ratelimit-unified-5h-utilization", "0.11")
            .body(Vec::<u8>::new())
            .unwrap(),
    );
    super::cooldown::observe(
        &pool,
        Some("q1"),
        "api.anthropic.com",
        "/v1/messages",
        &ok,
        Some(rid),
    )
    .await;
    assert_eq!(flush(&pool).await, 0, "等 token 期间不写");
    complete(
        take_held(rid).unwrap(),
        Some(TokenUsage {
            model: Some("claude-haiku-4-5-20251001".into()),
            input_tokens: Some(18),
            output_tokens: Some(177),
            cache_creation_input_tokens: Some(0),
            cache_read_input_tokens: Some(4096),
        }),
    );
    assert_eq!(flush(&pool).await, 1);
    type TokenRow = (
        Option<f64>,
        Option<String>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
    );
    let row: TokenRow = sqlx::query_as(
        "SELECT five_hour_utilization, model, input_tokens, output_tokens, cache_creation_input_tokens, cache_read_input_tokens \
         FROM secret_quota_usage ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        row,
        (
            Some(0.11),
            Some("claude-haiku-4-5-20251001".into()),
            Some(18),
            Some(177),
            Some(0),
            Some(4096)
        )
    );
    let empty: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM secret_quota_usage WHERE input_tokens IS NULL AND model IS NULL",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(empty.0, 7, "之前没带 token 的 7 行，token 列为空");
}

#[test]
fn held_until_claimed_or_expired() {
    let resp = |status: u16| {
        reqwest::Response::from(
            hyper::Response::builder()
                .status(status)
                .header("anthropic-ratelimit-unified-7d-utilization", "0.5")
                .body(Vec::<u8>::new())
                .unwrap(),
        )
    };
    let (r1, r2, r3) = (
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
    );
    let rec = |secret: &str, status: u16, rid: Option<uuid::Uuid>| {
        record(
            Some(secret),
            "api.anthropic.com",
            "/v1/messages",
            &resp(status),
            rid,
        )
    };
    // 成功 + 有网关请求编号：暂存，不入队
    rec("hold1", 200, Some(r1));
    assert!(drain_for_test("hold1").is_empty());
    // 429（会被轮换掉）、没有请求编号：直接入队
    rec("hold1", 429, Some(r2));
    rec("hold1", 200, None);
    assert_eq!(drain_for_test("hold1"), vec![None, None]);
    // 认领后填 token 入队；只能认领一次
    let obs = take_held(r1).unwrap();
    assert!(take_held(r1).is_none(), "只能认领一次");
    assert!(take_held(r2).is_none(), "429 没暂存");
    let t = TokenUsage {
        output_tokens: Some(9),
        ..Default::default()
    };
    complete(obs, Some(t.clone()));
    assert_eq!(drain_for_test("hold1"), vec![Some(t)]);
    // 没人认领：超时按无 token 入队
    rec("hold2", 200, Some(r3));
    sweep_held(HOLD_MAX);
    assert!(drain_for_test("hold2").is_empty(), "没超时不动");
    // 只把这一条的暂存时刻拨到超时前（不用 ZERO 全扫，免得扫走并行测试的暂存）
    if let Some(entry) = HELD.lock().unwrap().get_mut(&r3.as_u128()) {
        entry.0 = Instant::now().checked_sub(HOLD_MAX * 2).unwrap();
    }
    sweep_held(HOLD_MAX);
    assert_eq!(drain_for_test("hold2"), vec![None]);
    assert!(take_held(r3).is_none());
}

#[test]
fn queue_is_bounded_and_drops_oldest() {
    // 用本地队列测上限，不碰全局 PENDING（6号 P2：并行测试互扰）
    let mk = |i: i64| Observation {
        secret_id: "cap".into(),
        usage: QuotaUsage::default(),
        http_status: 200,
        observed_at: i,
        tokens: None,
    };
    let mut q: VecDeque<Observation> = VecDeque::new();
    let mut dropped = 0;
    for i in 0..(MAX_PENDING as i64 + 3) {
        dropped += push_bounded(&mut q, mk(i));
    }
    assert_eq!(dropped, 3);
    assert_eq!(q.len(), MAX_PENDING);
    assert_eq!(q.front().unwrap().observed_at, 3);
}
