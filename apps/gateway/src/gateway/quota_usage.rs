//! 记录模型账号的实时额度用量（5 小时 / 周），供监控页展示。
//! 上游每次 /v1/messages 响应（含 200）都带 `anthropic-ratelimit-unified-{5h,7d}-{utilization,reset}`；
//! 这里只读响应头、后台写库，不改响应、不阻塞转发，写库失败只告警。
use hyper::HeaderMap;
use sqlx::PgPool;
use std::time::Duration;
use tracing::warn;

const DB_TIMEOUT: Duration = Duration::from_millis(500);

/// 每个账号一行、新观测覆盖旧观测；迟到的旧响应（observed_at 更小）不覆盖
const UPSERT: &str = "INSERT INTO secret_quota_usage (secret_id, five_hour_utilization, five_hour_reset, \
     seven_day_utilization, seven_day_reset, unified_status, http_status, observed_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) \
     ON CONFLICT (secret_id) DO UPDATE SET five_hour_utilization=EXCLUDED.five_hour_utilization, \
     five_hour_reset=EXCLUDED.five_hour_reset, seven_day_utilization=EXCLUDED.seven_day_utilization, \
     seven_day_reset=EXCLUDED.seven_day_reset, unified_status=EXCLUDED.unified_status, \
     http_status=EXCLUDED.http_status, observed_at=EXCLUDED.observed_at \
     WHERE secret_quota_usage.observed_at <= EXCLUDED.observed_at";

#[derive(Debug, Default, PartialEq)]
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

/// 后台写入这个账号的最新用量。observed_at 用毫秒，迟到的旧响应不会覆盖较新的观测。
pub(super) fn record(
    pool: &PgPool,
    id: Option<&str>,
    host: &str,
    path: &str,
    response: &reqwest::Response,
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
    let observed_at = time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    let http_status = response.status().as_u16() as i32;
    let pool = pool.clone();
    let id = id.to_owned();
    tokio::spawn(async move {
        let result = tokio::time::timeout(
            DB_TIMEOUT,
            sqlx::query(UPSERT)
                .bind(&id)
                .bind(usage.five_hour_utilization)
                .bind(usage.five_hour_reset)
                .bind(usage.seven_day_utilization)
                .bind(usage.seven_day_reset)
                .bind(usage.status)
                .bind(http_status)
                .bind(observed_at as i64)
                .execute(&pool),
        )
        .await;
        if !matches!(result, Ok(Ok(_))) {
            warn!(secret_id = %id, reason = "quota_usage_write_failed", "额度用量写入失败，不影响转发");
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
async fn records_in_background_and_keeps_newest() {
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
    sqlx::query("INSERT INTO secrets(id) VALUES('q1') ON CONFLICT DO NOTHING")
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
    let read = || async {
        sqlx::query_as::<_, (Option<f64>, Option<f64>, Option<i64>, Option<String>, i32)>(
            "SELECT five_hour_utilization, seven_day_utilization, seven_day_reset, unified_status, http_status \
             FROM secret_quota_usage WHERE secret_id='q1'",
        )
        .fetch_optional(&pool)
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
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(read().await, None);
    // 200 响应：后台写入
    super::cooldown::observe(
        &pool,
        Some("q1"),
        "api.anthropic.com:443",
        "/v1/messages?beta=true",
        &response("0.6"),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        read().await,
        Some((
            Some(0.25),
            Some(0.6),
            Some(1793500000),
            Some("allowed".into()),
            200
        ))
    );
    // 迟到的旧观测不覆盖
    sqlx::query(UPSERT)
        .bind("q1")
        .bind(Some(0.1))
        .bind(None::<i64>)
        .bind(Some(0.1))
        .bind(None::<i64>)
        .bind(None::<String>)
        .bind(200)
        .bind(1_i64)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(read().await.unwrap().1, Some(0.6));
    // 删账号连带删用量
    sqlx::query("DELETE FROM secrets WHERE id='q1'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(read().await, None);
}
