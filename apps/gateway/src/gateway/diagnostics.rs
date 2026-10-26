//! 上游错误诊断：有界采样，不改变返回给调用方的响应字节。
use futures_util::StreamExt;
use serde_json::{json, Value};
use std::time::Duration;

const BODY_LIMIT: usize = 8192;
const TEXT_LIMIT: usize = 2048;

fn redact(value: &str, secrets: &[String]) -> String {
    let mut text = value.to_owned();
    // 先去除已知凭据，再限长，避免截断后无法匹配完整凭据。
    for secret in secrets.iter().filter(|s| !s.is_empty()) {
        text = text.replace(secret, "[REDACTED]");
        if let Some((scheme, raw)) = secret.split_once(char::is_whitespace) {
            if !raw.trim().is_empty()
                && (scheme.eq_ignore_ascii_case("bearer") || scheme.eq_ignore_ascii_case("basic"))
            {
                text = text.replace(raw.trim(), "[REDACTED]");
            }
        }
    }
    text.split_whitespace()
        .map(|word| {
            if word.contains("sk-ant-")
                || word.contains("sk-")
                || word.contains("aoc_")
                || word.starts_with("eyJ")
                || word.len() > 128
            {
                "[REDACTED]".to_string()
            } else {
                word.chars().filter(|c| !c.is_control()).collect()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(TEXT_LIMIT)
        .collect()
}

pub(super) async fn capture(
    mut response: reqwest::Response,
    secrets: &[String],
) -> (reqwest::Response, Value) {
    let mut details = json!({"capture": "not_error"});
    let status = response.status();
    let version = response.version();
    let headers = response.headers().clone();
    let mut safe_headers = serde_json::Map::new();
    for (key, value) in &headers {
        let name = key.as_str();
        if safe_headers.len() < 24
            && (matches!(name, "request-id" | "x-request-id" | "retry-after")
                || name.starts_with("anthropic-ratelimit-")
                || name.starts_with("x-ratelimit-"))
        {
            if let Ok(value) = value.to_str() {
                safe_headers.insert(name.to_owned(), json!(redact(value, secrets)));
            }
        }
    }
    details["headers"] = json!(safe_headers);
    if !status.is_client_error() && !status.is_server_error() {
        return (response, details);
    }
    let ct = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let is_json = ct.contains("application/json") || ct.contains("+json");
    let is_text = ct.starts_with("text/plain");
    if !is_json && !is_text {
        details["capture"] = json!("unsupported_content_type");
        return (response, details);
    }
    let mut replay = Vec::new();
    let mut preview = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(250);
    let outcome = loop {
        match tokio::time::timeout_at(deadline, response.chunk()).await {
            Ok(Ok(Some(chunk))) => {
                let remaining = BODY_LIMIT.saturating_sub(preview.len());
                preview.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
                let too_large = chunk.len() > remaining;
                replay.push(Ok(chunk));
                if too_large {
                    break "body_limit";
                }
            }
            Ok(Ok(None)) => break "complete",
            Ok(Err(err)) => {
                replay.push(Err(err));
                break "body_read_error";
            }
            Err(_) => break "body_timeout",
        }
    };
    details["capture"] = json!(outcome);
    details["sampled_bytes"] = json!(preview.len());
    // 不保留任意JSON对象，尤其不保存上游回显的请求正文或用户数据。
    if outcome == "complete" {
        if is_json {
            if let Ok(body) = serde_json::from_slice::<Value>(&preview) {
                let error = body.get("error").unwrap_or(&body);
                if let Some(message) = error
                    .get("message")
                    .and_then(Value::as_str)
                    .or_else(|| error.as_str())
                    .or_else(|| body.get("message").and_then(Value::as_str))
                {
                    details["message"] = json!(redact(message, secrets));
                }
                for (from, to) in [("type", "error_type"), ("code", "error_code")] {
                    if let Some(value) = error.get(from) {
                        if value.is_string() || value.is_number() {
                            details[to] = json!(redact(
                                value
                                    .as_str()
                                    .map(str::to_owned)
                                    .unwrap_or_else(|| value.to_string())
                                    .as_str(),
                                secrets
                            ));
                        }
                    }
                }
            } else {
                details["capture"] = json!("invalid_json");
            }
        } else {
            details["message"] = json!(redact(&String::from_utf8_lossy(&preview), secrets));
        }
    }
    // 已读的块逐字节放回原响应前缀，超限/超时仍继续透传余流。
    let stream = futures_util::stream::iter(replay).chain(response.bytes_stream());
    let mut rebuilt = hyper::Response::new(reqwest::Body::wrap_stream(stream));
    *rebuilt.status_mut() = status;
    *rebuilt.version_mut() = version;
    *rebuilt.headers_mut() = headers;
    (rebuilt.into(), details)
}

pub(super) async fn record_attempt(
    response: reqwest::Response,
    request_id: uuid::Uuid,
    secret_id: Option<&str>,
    latency_ms: u64,
    secrets: &[String],
    attempts: &mut Vec<Value>,
) -> reqwest::Response {
    let status = response.status().as_u16();
    let (response, error) = capture(response, secrets).await;
    let attempt = json!({
        "attempt": attempts.len() + 1, "secret_id": secret_id,
        "status": status, "latency_to_headers_ms": latency_ms,
        "timestamp": time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Iso8601::DEFAULT).unwrap_or_default(),
        "error": error,
    });
    tracing::info!(%request_id, details = %attempt, "上游尝试诊断");
    attempts.push(attempt);
    response
}

/// 请求失败时仍保存之前的429与本次传输失败；不记录可能含敏感URL的错误字符串。
#[allow(clippy::too_many_arguments)]
pub(super) fn record_transport_error(
    error: &reqwest::Error,
    request_id: uuid::Uuid,
    secret_id: Option<&str>,
    latency_ms: u64,
    attempts: &mut Vec<Value>,
    ctx: &super::ProxyContext,
    host: &str,
    method: &str,
    path: &str,
    approval: (Option<&str>, Option<&str>, Option<&str>),
) {
    let kind = if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else {
        "transport"
    };
    let timestamp = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Iso8601::DEFAULT)
        .unwrap_or_default();
    let attempt = json!({"attempt": attempts.len()+1, "secret_id": secret_id, "status": null,
        "timestamp": timestamp, "latency_to_headers_ms": latency_ms,
        "error": {"capture": "no_response", "error_type": kind}});
    tracing::warn!(%request_id, details=%attempt, "上游连接失败，结束当前请求");
    attempts.push(attempt);
    if let (Some(project), Some(agent)) = (&ctx.project_id, &ctx.agent_id) {
        crate::telemetry::on_request(crate::telemetry::RequestEvent {
            org_id: ctx.organization_id.clone().unwrap_or_default(),
            project_id: project.clone(),
            agent_id: agent.clone(),
            agent_name: ctx.agent_name.clone().unwrap_or_default(),
            method: method.to_string(),
            host: host.to_string(),
            path: path.split('?').next().unwrap_or(path).to_string(),
            provider: super::strip_port(host).to_string(),
            status: 502,
            latency_ms: latency_ms.min(u32::MAX as u64) as u32,
            injection_count: 0,
            timestamp: timestamp.clone(),
            injected: false,
            decision: match approval {
                (Some(_), Some(id), Some(triggered)) => {
                    crate::telemetry_core::RequestDecision::ApprovalApproved {
                        approval_id: id.to_string(),
                        triggered_at: triggered.to_string(),
                        resolved_at: timestamp.clone(),
                    }
                }
                _ => crate::telemetry_core::RequestDecision::Allowed,
            },
            connection_label: None,
            existing_log_id: approval.0.map(str::to_string),
            log_id: None,
            budget_charge: None,
            diagnostics: Some(
                json!({"request_id": request_id.to_string(), "final_status": null,
                "gateway_status": 502, "end_reason": "transport_error", "attempts": attempts}),
            ),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn response(
        status: u16,
        content_type: &str,
        body: impl Into<reqwest::Body>,
    ) -> reqwest::Response {
        hyper::Response::builder()
            .status(status)
            .header("content-type", content_type)
            .header("retry-after", "30")
            .body(body.into())
            .unwrap()
            .into()
    }
    #[tokio::test]
    async fn captures_message_headers_but_preserves_response() {
        let body = r#"{"error":{"type":"rate_limit_error","message":"Too many requests"},"request":{"prompt":"private prompt"}}"#;
        let (r, d) = capture(response(429, "application/json", body), &[]).await;
        assert_eq!(d["message"], "Too many requests");
        assert_eq!(d["error_type"], "rate_limit_error");
        assert_eq!(d["headers"]["retry-after"], "30");
        assert!(!d.to_string().contains("private prompt"));
        assert_eq!(r.status(), 429);
        assert_eq!(r.text().await.unwrap(), body);
    }
    #[tokio::test]
    async fn redacts_echoed_credential() {
        let body = r#"{"error":{"message":"Invalid Bearer example-sensitive-value"}}"#;
        let (r, d) = capture(
            response(401, "application/json", body),
            &["example-sensitive-value".into()],
        )
        .await;
        assert!(!d.to_string().contains("example-sensitive-value"));
        assert!(d["message"].as_str().unwrap().contains("[REDACTED]"));
        assert_eq!(r.text().await.unwrap(), body);
    }
    #[tokio::test]
    async fn lowercase_bearer_is_redacted() {
        let (_, d) = capture(
            response(
                401,
                "application/json",
                r#"{"error":{"message":"Invalid token opaque-secret-123"}}"#,
            ),
            &["bearer opaque-secret-123".into()],
        )
        .await;
        assert_eq!(d["message"], "Invalid token [REDACTED]");
    }
    #[tokio::test]
    async fn successful_stream_is_not_consumed() {
        let (r, d) = capture(response(200, "text/event-stream", "data: hello\n\n"), &[]).await;
        assert_eq!(d["capture"], "not_error");
        assert_eq!(d["headers"]["retry-after"], "30");
        assert_eq!(r.text().await.unwrap(), "data: hello\n\n");
    }
    #[tokio::test]
    async fn slow_error_prefix_is_replayed_after_timeout() {
        let stream = futures_util::stream::once(async {
            Ok::<_, std::io::Error>(hyper::body::Bytes::from_static(b"first"))
        })
        .chain(futures_util::stream::once(async {
            tokio::time::sleep(Duration::from_millis(400)).await;
            Ok::<_, std::io::Error>(hyper::body::Bytes::from_static(b"second"))
        }));
        let (r, d) = capture(
            response(429, "text/plain", reqwest::Body::wrap_stream(stream)),
            &[],
        )
        .await;
        assert_eq!(d["capture"], "body_timeout");
        assert_eq!(r.text().await.unwrap(), "firstsecond");
    }
    #[tokio::test]
    async fn oversized_and_html_are_not_logged_as_messages() {
        for (ct, body) in [
            ("text/html", "<html>private</html>".to_string()),
            ("application/json", "x".repeat(20000)),
        ] {
            let (r, d) = capture(response(500, ct, body.clone()), &[]).await;
            assert!(d.get("message").is_none());
            assert_eq!(r.text().await.unwrap(), body);
        }
    }
}
