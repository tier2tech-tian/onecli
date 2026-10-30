//! 共享模型账号额度冷却；存储异常按用户决定保持原轮换。
use hyper::{HeaderMap, StatusCode};
use sqlx::PgPool;
use std::{collections::HashMap, time::Duration};
use tracing::{info, warn};

const DB_TIMEOUT: Duration = Duration::from_millis(500);

pub(super) fn applies(host: &str, path: &str) -> bool {
    super::strip_port(host) == "api.anthropic.com" && path.split('?').next() == Some("/v1/messages")
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct QuotaLock {
    pub reason: &'static str,
    pub until: i64,
}

pub(super) fn parse(headers: &HeaderMap, now: i64) -> Result<Option<QuotaLock>, &'static str> {
    for (window, reason) in [("7d", "seven_day"), ("5h", "five_hour")] {
        let status = format!("anthropic-ratelimit-unified-{window}-status");
        if headers.get(&status).and_then(|v| v.to_str().ok()) != Some("rejected") {
            continue;
        }
        let key = format!("anthropic-ratelimit-unified-{window}-reset");
        let until = headers
            .get(&key)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<i64>().ok())
            .filter(|&v| v > now && time::OffsetDateTime::from_unix_timestamp(v).is_ok())
            .ok_or("额度耗尽但重置时间无效，不新增冷却")?;
        return Ok(Some(QuotaLock { reason, until }));
    }
    Ok(None)
}

pub(super) fn beijing(until: i64) -> String {
    let t = time::OffsetDateTime::from_unix_timestamp(until)
        .unwrap()
        .to_offset(time::UtcOffset::from_hms(8, 0, 0).unwrap());
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}+08:00",
        t.year(),
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

pub(super) async fn active(pool: &PgPool, ids: &[String]) -> HashMap<String, i64> {
    if ids.is_empty() {
        return HashMap::new();
    }
    let result = tokio::time::timeout(DB_TIMEOUT,
        sqlx::query_as::<_, (String, i64)>("SELECT secret_id, reset_at FROM secret_cooldowns WHERE secret_id = ANY($1) AND reset_at > EXTRACT(EPOCH FROM clock_timestamp())")
            .bind(ids).fetch_all(pool)).await;
    match result {
        Ok(Ok(rows)) => rows.into_iter().collect(),
        _ => {
            warn!(
                reason = "cooldown_read_failed",
                "冷却状态读取失败，按原有方式轮换"
            );
            HashMap::new()
        }
    }
}

pub(super) async fn observe(
    pool: &PgPool,
    id: Option<&str>,
    host: &str,
    path: &str,
    response: &reqwest::Response,
) {
    // 每次模型响应（含 200）顺手把账号实时用量记进内存，后台每分钟用专用连接写库
    super::quota_usage::record(id, host, path, response);
    if !applies(host, path) || response.status() != StatusCode::TOO_MANY_REQUESTS {
        return;
    }
    let Some(id) = id else {
        return;
    };
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let lock = match parse(response.headers(), now) {
        Ok(Some(v)) => v,
        Ok(None) => return,
        Err(reason) => {
            warn!(secret_id = id, reason, "忽略无效额度重置时间");
            return;
        }
    };
    // 原子合并：有效周锁不降级；同窗口不被迟到响应缩短。到期无需定时删除。
    let result = tokio::time::timeout(DB_TIMEOUT, sqlx::query(
        "INSERT INTO secret_cooldowns (secret_id, reason, reset_at) VALUES ($1,$2,$3) \
         ON CONFLICT (secret_id) DO UPDATE SET reason=EXCLUDED.reason, reset_at=EXCLUDED.reset_at \
         WHERE secret_cooldowns.reset_at <= EXTRACT(EPOCH FROM clock_timestamp()) \
         OR (secret_cooldowns.reason='five_hour' AND EXCLUDED.reason='seven_day') \
         OR (secret_cooldowns.reason=EXCLUDED.reason AND EXCLUDED.reset_at>secret_cooldowns.reset_at)"
    ).bind(id).bind(lock.reason).bind(lock.until).execute(pool)).await;
    match result {
        Ok(Ok(result)) if result.rows_affected() > 0 => {
            info!(secret_id=id, reason=lock.reason, reset_at=lock.until, reset_beijing=%beijing(lock.until), "账号冷却已更新")
        }
        Ok(Ok(_)) => info!(secret_id = id, "保留已有冷却，忽略较低优先级或较旧响应"),
        _ => warn!(
            secret_id = id,
            reason = "cooldown_write_failed",
            "冷却写入失败，保留上游响应并继续原轮换"
        ),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn blocked(
    until: i64,
    request_id: uuid::Uuid,
    ctx: &super::ProxyContext,
    host: &str,
    method: &str,
    path: &str,
    latency_ms: u32,
    approval: (Option<&str>, Option<&str>, Option<&str>),
) -> hyper::Response<super::hooks::ForwardResponseBody> {
    let timestamp = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Iso8601::DEFAULT)
        .unwrap_or_default();
    if let (Some(project), Some(agent)) = (&ctx.project_id, &ctx.agent_id) {
        crate::telemetry::on_request(crate::telemetry::RequestEvent {
            org_id: ctx.organization_id.clone().unwrap_or_default(),
            project_id: project.clone(),
            agent_id: agent.clone(),
            agent_name: ctx.agent_name.clone().unwrap_or_default(),
            method: method.into(),
            host: host.into(),
            path: path.split('?').next().unwrap_or(path).into(),
            provider: super::strip_port(host).into(),
            status: 429,
            latency_ms,
            injection_count: 0,
            timestamp: timestamp.clone(),
            injected: false,
            decision: match approval {
                (Some(_), Some(id), Some(triggered)) => {
                    crate::telemetry_core::RequestDecision::ApprovalApproved {
                        approval_id: id.into(),
                        triggered_at: triggered.into(),
                        resolved_at: timestamp,
                    }
                }
                _ => crate::telemetry_core::RequestDecision::Allowed,
            },
            connection_label: None,
            existing_log_id: approval.0.map(str::to_owned),
            log_id: None,
            budget_charge: None,
            diagnostics: Some(
                serde_json::json!({"request_id":request_id.to_string(),"gateway_status":429,"final_status":null,"end_reason":"quota_cooldown","retry_at":until,"retry_at_beijing":beijing(until),"attempts":[]}),
            ),
        });
    }
    let seconds = (until - time::OffsetDateTime::now_utc().unix_timestamp()).max(1);
    info!(%request_id,agent_id=?ctx.agent_id,reset_at=until, reset_beijing=%beijing(until), "所有匹配账号处于冷却，未访问上游");
    let mut response = super::response::json(
        StatusCode::TOO_MANY_REQUESTS,
        serde_json::json!({
            "type":"error", "error":{"type":"rate_limit_error", "message":format!("所有可用账号额度暂不可用，最早 {} 重试",beijing(until))},
            "retry_at":until
        }),
    );
    response
        .headers_mut()
        .insert("retry-after", seconds.to_string().parse().unwrap());
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    fn headers(week: &str, week_time: &str, hour: &str, hour_time: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in [
            ("7d-status", week),
            ("7d-reset", week_time),
            ("5h-status", hour),
            ("5h-reset", hour_time),
        ] {
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
    fn weekly_wins_even_when_hour_reset_is_later() {
        assert_eq!(
            parse(&headers("rejected", "200", "rejected", "300"), 100).unwrap(),
            Some(QuotaLock {
                reason: "seven_day",
                until: 200
            })
        );
    }
    #[test]
    fn hourly_only() {
        assert_eq!(
            parse(&headers("allowed", "400", "rejected", "300"), 100).unwrap(),
            Some(QuotaLock {
                reason: "five_hour",
                until: 300
            })
        );
    }
    #[test]
    fn invalid_week_never_falls_back_to_hour() {
        for v in ["", "bad", "100", "99", "9223372036854775807"] {
            assert!(parse(&headers("rejected", v, "rejected", "300"), 100).is_err());
        }
    }
    #[test]
    fn no_rejection_no_lock() {
        assert_eq!(parse(&HeaderMap::new(), 100), Ok(None));
    }
    #[test]
    fn timestamp_display_is_beijing() {
        assert_eq!(beijing(1793142000), "2026-10-28 07:00:00+08:00");
    }
    #[test]
    fn only_model_endpoint() {
        assert!(applies("api.anthropic.com:443", "/v1/messages?beta=true"));
        assert!(!applies("api.anthropic.com.evil", "/v1/messages"));
        assert!(!applies("api.anthropic.com", "/mcp-registry/v0/servers"));
    }
}

#[cfg(test)]
#[path = "cooldown_e2e.rs"]
mod e2e;
