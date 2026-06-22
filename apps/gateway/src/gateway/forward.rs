//! HTTP request forwarding: send requests upstream, apply injection/policy rules,
//! stream responses back, and intercept auth failures for unconnected apps.

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex};

use anyhow::{Context, Result};
use futures_util::TryStreamExt;
use http_body_util::{BodyExt, Either, Full, StreamBody};
use hyper::body::{Bytes, Frame, Incoming};
use hyper::header::{HeaderName, CONTENT_LENGTH};
use hyper::{Request, Response, StatusCode};
use lru::LruCache;
use tracing::{info, warn};

use crate::apps;
use crate::cache::CacheStore;
use crate::connect::SecretCandidate;
use crate::inject::{self, InjectionRule};
use crate::policy::{self, PolicyDecision, PolicyRule};

use super::response;

// ── Injection source selection ─────────────────────────────────────────

/// 注入源选择结果：决定用哪套 injection rules 以及是否支持 retry。
#[derive(Debug)]
pub(crate) enum InjectionSource<'a> {
    /// 多个 secret 匹配，支持 429 轮换重试
    MultiSecret {
        candidates: Vec<&'a SecretCandidate>,
        offset: usize,
    },
    /// 恰好一个 secret 匹配，单次注入
    SingleSecret { candidate: &'a SecretCandidate },
    /// 无 secret 匹配，使用 app connection / vault fallback rules
    AppFallback { rules: &'a [InjectionRule] },
    /// 无任何注入规则
    None,
}

/// 纯函数：根据 secret_candidates、app_injection_rules 和请求 path 选择注入源。
/// host 级 secret 优先：只有 secret_candidates 为空时才 fallback 到 app rules。
pub(crate) fn select_injection_source<'a>(
    secret_candidates: &'a [SecretCandidate],
    app_rules: &'a [InjectionRule],
    request_path: &str,
    rotation_offset: usize,
) -> InjectionSource<'a> {
    let matched: Vec<&SecretCandidate> = secret_candidates
        .iter()
        .filter(|c| inject::path_matches(request_path, &c.rule.path_pattern))
        .collect();

    match matched.len() {
        0 => {
            if secret_candidates.is_empty() && !app_rules.is_empty() {
                InjectionSource::AppFallback { rules: app_rules }
            } else {
                // secret_candidates 非空但 path 都不匹配 → None（不 fallback 到 app rules）
                InjectionSource::None
            }
        }
        1 => InjectionSource::SingleSecret {
            candidate: matched[0],
        },
        n => InjectionSource::MultiSecret {
            candidates: matched,
            offset: rotation_offset % n,
        },
    }
}

// ── Rotation offset ────────────────────────────────────────────────────

/// body buffer 上限：4MB。超过此大小不 buffer，走单次流式转发。
const RETRY_BODY_LIMIT: u64 = 4 * 1024 * 1024;

/// LRU 容量上限。
const ROTATION_CACHE_CAP: usize = 1024;

/// Per (account_id, host) 的 rotation 计数器，进程级。
static ROTATION_OFFSETS: LazyLock<Mutex<LruCache<(String, String), AtomicUsize>>> =
    LazyLock::new(|| Mutex::new(LruCache::new(NonZeroUsize::new(ROTATION_CACHE_CAP).unwrap())));

/// 获取并递增 rotation offset。
fn get_rotation_offset(account_id: &str, host: &str) -> usize {
    let key = (account_id.to_string(), host.to_string());
    let mut cache = ROTATION_OFFSETS.lock().unwrap();
    if let Some(counter) = cache.get(&key) {
        return counter.fetch_add(1, Ordering::Relaxed);
    }
    // 新 entry，从 0 开始，返回 0 后递增到 1
    cache.put(key, AtomicUsize::new(1));
    0
}

// ── Header filtering ────────────────────────────────────────────────────

/// Hop-by-hop headers that should never be forwarded in either direction.
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

/// Returns true if a request header should be forwarded to the upstream server.
///
/// Strips hop-by-hop headers plus `host` (set by the upstream URL) and
/// `content-length` (recalculated by reqwest from the body).
fn is_forwarded_request_header(name: &HeaderName) -> bool {
    let s = name.as_str();
    if s == "host" || s == "content-length" {
        return false;
    }
    !HOP_BY_HOP_HEADERS.contains(&s)
}

/// Returns true if a response header should be forwarded back to the client.
///
/// Strips hop-by-hop headers only. `content-length` is preserved — it is
/// required for HEAD responses and correct HTTP/1.1 framing.
fn is_forwarded_response_header(name: &HeaderName) -> bool {
    !HOP_BY_HOP_HEADERS.contains(&name.as_str())
}

// ── Request forwarding ──────────────────────────────────────────────────

/// Forward a single HTTP request to the real upstream server and stream the response back.
///
/// Both request and response bodies are streamed — no full buffering in memory.
/// This is critical for SSE (Server-Sent Events) and large payloads.
///
/// The flow:
/// 1. Check policy rules (block/rate-limit → 403/429)
/// 2. Apply injection rules to request headers
/// 3. Send to upstream
/// 4. If no credentials were injected and upstream returns 401/403, check if the
///    host belongs to a known app → return an actionable error for the agent
/// 5. Stream response back to client
#[allow(clippy::too_many_arguments)]
pub(crate) async fn forward_request(
    req: Request<Incoming>,
    host: &str,
    scheme: &str,
    http_client: reqwest::Client,
    secret_candidates: &[SecretCandidate],
    app_injection_rules: &[InjectionRule],
    policy_rules: &[PolicyRule],
    cache: &dyn CacheStore,
    agent_token: &str,
    account_id: Option<&str>,
) -> Result<
    Response<
        Either<
            Full<Bytes>,
            StreamBody<impl futures_util::Stream<Item = Result<Frame<Bytes>, reqwest::Error>>>,
        >,
    >,
> {
    let method = req.method().clone();
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let url = format!("{scheme}://{host}{path}");

    // Check policy rules before forwarding
    match policy::evaluate(method.as_str(), &path, policy_rules, agent_token, cache).await {
        PolicyDecision::Blocked => {
            warn!(method = %method, url = %url, "BLOCKED by policy rule");
            let body = serde_json::json!({
                "error": "blocked_by_policy",
                "message": "This request was blocked by an OneCLI policy rule. Check your rules at https://onecli.sh or your OneCLI dashboard.",
                "method": method.as_str(),
                "path": path,
            })
            .to_string();
            let mut response = Response::new(Either::Left(Full::new(Bytes::from(body))));
            *response.status_mut() = StatusCode::FORBIDDEN;
            response
                .headers_mut()
                .insert("content-type", "application/json".parse().unwrap());
            return Ok(response);
        }
        PolicyDecision::RateLimited {
            limit,
            window,
            retry_after_secs,
        } => {
            warn!(method = %method, url = %url, limit, window, "RATE LIMITED by policy rule");
            let body = serde_json::json!({
                "error": "rate_limited",
                "message": "This request was rate-limited by an OneCLI policy rule.",
                "limit": limit,
                "window": window,
            })
            .to_string();
            let mut response = Response::new(Either::Left(Full::new(Bytes::from(body))));
            *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
            response
                .headers_mut()
                .insert("content-type", "application/json".parse().unwrap());
            response
                .headers_mut()
                .insert("retry-after", retry_after_secs.to_string().parse().unwrap());
            return Ok(response);
        }
        PolicyDecision::Allow => {}
    }

    let (parts, body) = req.into_parts();

    // Collect forwarded headers into a mutable map for injection
    let mut headers = hyper::HeaderMap::new();
    for (name, value) in parts.headers.iter() {
        if is_forwarded_request_header(name) {
            headers.append(name.clone(), value.clone());
        }
    }

    // 选择注入源
    let rotation_offset = account_id
        .map(|aid| get_rotation_offset(aid, host))
        .unwrap_or(0);
    let source = select_injection_source(secret_candidates, app_injection_rules, &path, rotation_offset);

    // Content-Length gate：决定是否进入 buffer + retry 路径
    let content_length: Option<u64> = parts
        .headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    let can_retry = matches!(&source, InjectionSource::MultiSecret { .. });
    let use_retry_path =
        can_retry && content_length.is_some_and(|cl| cl <= RETRY_BODY_LIMIT);

    // --- retry 路径：MultiSecret + CL <= 4MB ---
    if let (true, InjectionSource::MultiSecret { candidates, offset }) = (use_retry_path, &source) {
        let body_bytes = read_body_with_limit(body, RETRY_BODY_LIMIT).await?;
        let n = candidates.len();

        for attempt in 0..n {
            let idx = (offset + attempt) % n;
            let candidate = candidates[idx];

            let mut attempt_headers = headers.clone();
            let rules = std::slice::from_ref(&candidate.rule);
            inject::apply_injections(&mut attempt_headers, &path, rules);

            let mut upstream = http_client.request(method.clone(), &url);
            for (name, value) in attempt_headers.iter() {
                upstream = upstream.header(name.clone(), value.clone());
            }
            upstream = upstream.body(reqwest::Body::from(body_bytes.clone()));

            // transport error 不轮换，直接返回
            let upstream_resp = match upstream.send().await {
                Ok(resp) => resp,
                Err(e) => {
                    warn!(
                        secret_id = %candidate.secret_id,
                        attempt = attempt + 1,
                        total = n,
                        error = %e,
                        "upstream transport error, not rotating"
                    );
                    return Err(e).with_context(|| format!("forwarding to {url}"));
                }
            };

            let status = upstream_resp.status();

            // 仅 429 且还有下一个 candidate 时才轮换
            if status == StatusCode::TOO_MANY_REQUESTS && attempt < n - 1 {
                warn!(
                    secret_id = %candidate.secret_id,
                    attempt = attempt + 1,
                    total = n,
                    "upstream 429, rotating to next secret"
                );
                continue;
            }

            // 非 429 或最后一次 → 返回
            let resp_headers = upstream_resp.headers().clone();
            let content_type = resp_headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("-");
            info!(
                method = %method,
                url = %url,
                status = %status.as_u16(),
                content_type = %content_type,
                secret_id = %candidate.secret_id,
                attempt = attempt + 1,
                total = n,
                "MITM (retry path)"
            );

            let resp_stream = upstream_resp.bytes_stream().map_ok(Frame::data);
            let body = StreamBody::new(resp_stream);
            let mut response = Response::new(Either::Right(body));
            *response.status_mut() = status;
            for (name, value) in resp_headers.iter() {
                if is_forwarded_response_header(name) {
                    response.headers_mut().append(name.clone(), value.clone());
                }
            }
            return Ok(response);
        }
        unreachable!("retry loop always returns");
    }

    // --- 单次转发路径（SingleSecret / AppFallback / None / MultiSecret CL 不符合）---
    let rules: Vec<&InjectionRule> = match &source {
        InjectionSource::SingleSecret { candidate } => vec![&candidate.rule],
        InjectionSource::AppFallback { rules } => rules.iter().collect(),
        InjectionSource::MultiSecret { candidates, offset } => {
            // CL gate 未通过，用 offset 位的 candidate 单次转发
            if account_id.is_none() {
                warn!("MultiSecret but account_id missing, degrading to first candidate");
            }
            vec![&candidates[*offset].rule]
        }
        InjectionSource::None => vec![],
    };

    let owned_rules: Vec<InjectionRule> = rules.into_iter().cloned().collect();
    let injection_count = inject::apply_injections(&mut headers, &path, &owned_rules);

    // Build upstream request with (possibly modified) headers
    let mut upstream = http_client.request(method.clone(), &url);
    for (name, value) in headers.iter() {
        upstream = upstream.header(name.clone(), value.clone());
    }

    // Stream request body to upstream via HttpBody wrapper
    upstream = upstream.body(reqwest::Body::wrap(body));

    // Send to real server
    let upstream_resp = upstream
        .send()
        .await
        .with_context(|| format!("forwarding to {url}"))?;

    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();

    // If no credentials were injected and upstream returned 401/403,
    // check if this host belongs to a known app that needs connecting.
    if injection_count == 0
        && (status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN)
    {
        let hostname = super::strip_port(host);
        if let Some((provider, display_name)) = apps::provider_for_host_and_path(hostname, &path) {
            info!(
                method = %method,
                url = %url,
                status = %status.as_u16(),
                provider = %provider,
                "app not connected"
            );
            return Ok(response::app_not_connected(status, provider, display_name));
        }
    }

    // Log before streaming response body
    let content_type = resp_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-");

    info!(
        method = %method,
        url = %url,
        status = %status.as_u16(),
        content_type = %content_type,
        injections_applied = injection_count,
        "MITM"
    );

    // Stream response body to client (no buffering — critical for SSE)
    let resp_stream = upstream_resp.bytes_stream().map_ok(Frame::data);
    let body = StreamBody::new(resp_stream);

    let mut response = Response::new(Either::Right(body));
    *response.status_mut() = status;

    // Forward response headers, skipping hop-by-hop
    for (name, value) in resp_headers.iter() {
        if is_forwarded_response_header(name) {
            response.headers_mut().append(name.clone(), value.clone());
        }
    }

    Ok(response)
}

// ── Body reading ───────────────────────────────────────────────────────

/// 读取请求 body 到 Bytes，hard limit 兜底（防恶意/错误 Content-Length）。
async fn read_body_with_limit(body: Incoming, limit: u64) -> Result<Bytes> {
    let collected = http_body_util::Limited::new(body, limit as usize)
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("reading request body (limit {limit}B): {e}"))?;
    Ok(collected.to_bytes())
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_forwarded_request_header ──────────────────────────────────────

    #[test]
    fn request_header_strips_hop_by_hop() {
        for &name in HOP_BY_HOP_HEADERS {
            let header = HeaderName::from_static(name);
            assert!(
                !is_forwarded_request_header(&header),
                "{name} should be stripped from requests"
            );
        }
    }

    #[test]
    fn request_header_strips_host_and_content_length() {
        assert!(!is_forwarded_request_header(&HeaderName::from_static(
            "host"
        )));
        assert!(!is_forwarded_request_header(&HeaderName::from_static(
            "content-length"
        )));
    }

    #[test]
    fn request_header_passes_application_headers() {
        let forwarded = [
            "content-type",
            "authorization",
            "accept",
            "user-agent",
            "x-api-key",
            "cache-control",
        ];
        for name in forwarded {
            let header = HeaderName::from_static(name);
            assert!(
                is_forwarded_request_header(&header),
                "{name} should be forwarded in requests"
            );
        }
    }

    // ── is_forwarded_response_header ─────────────────────────────────────

    #[test]
    fn response_header_strips_hop_by_hop() {
        for &name in HOP_BY_HOP_HEADERS {
            let header = HeaderName::from_static(name);
            assert!(
                !is_forwarded_response_header(&header),
                "{name} should be stripped from responses"
            );
        }
    }

    #[test]
    fn response_header_preserves_content_length() {
        assert!(is_forwarded_response_header(&HeaderName::from_static(
            "content-length"
        )));
    }

    #[test]
    fn response_header_passes_application_headers() {
        let forwarded = [
            "content-type",
            "content-length",
            "authorization",
            "accept",
            "user-agent",
            "x-api-key",
            "cache-control",
        ];
        for name in forwarded {
            let header = HeaderName::from_static(name);
            assert!(
                is_forwarded_response_header(&header),
                "{name} should be forwarded in responses"
            );
        }
    }

    // ── select_injection_source ─────────────────────────────────────────

    fn make_candidate(id: &str, path: &str) -> SecretCandidate {
        SecretCandidate {
            secret_id: id.to_string(),
            rule: InjectionRule {
                path_pattern: path.to_string(),
                injections: vec![],
            },
        }
    }

    fn make_app_rule(path: &str) -> InjectionRule {
        InjectionRule {
            path_pattern: path.to_string(),
            injections: vec![],
        }
    }

    #[test]
    fn select_multi_secret() {
        let candidates = vec![
            make_candidate("s1", "*"),
            make_candidate("s2", "*"),
            make_candidate("s3", "*"),
        ];
        let app_rules = vec![make_app_rule("*")];
        match select_injection_source(&candidates, &app_rules, "/v1/messages", 5) {
            InjectionSource::MultiSecret { candidates: matched, offset } => {
                assert_eq!(matched.len(), 3);
                assert_eq!(offset, 5 % 3); // 2
            }
            other => panic!("expected MultiSecret, got {other:?}"),
        }
    }

    #[test]
    fn select_single_secret_by_path_filter() {
        let candidates = vec![
            make_candidate("s1", "/v1/*"),
            make_candidate("s2", "/v2/*"),
            make_candidate("s3", "/v2/*"),
        ];
        match select_injection_source(&candidates, &[], "/v1/messages", 0) {
            InjectionSource::SingleSecret { candidate } => {
                assert_eq!(candidate.secret_id, "s1");
            }
            other => panic!("expected SingleSecret, got {other:?}"),
        }
    }

    #[test]
    fn select_app_fallback_when_no_secrets() {
        let app_rules = vec![make_app_rule("*")];
        match select_injection_source(&[], &app_rules, "/v1/messages", 0) {
            InjectionSource::AppFallback { rules } => {
                assert_eq!(rules.len(), 1);
            }
            other => panic!("expected AppFallback, got {other:?}"),
        }
    }

    #[test]
    fn select_none_when_empty() {
        match select_injection_source(&[], &[], "/v1/messages", 0) {
            InjectionSource::None => {}
            other => panic!("expected None, got {other:?}"),
        }
    }

    #[test]
    fn select_none_when_secrets_exist_but_path_mismatches() {
        // host 级有 secret 但 path 不匹配 → None，不 fallback 到 app rules
        let candidates = vec![make_candidate("s1", "/v2/*")];
        let app_rules = vec![make_app_rule("*")];
        match select_injection_source(&candidates, &app_rules, "/v1/messages", 0) {
            InjectionSource::None => {}
            other => panic!("expected None (no path-level fallback to app), got {other:?}"),
        }
    }

    #[test]
    fn select_single_secret_does_not_mix_app_rules() {
        let candidates = vec![make_candidate("s1", "*")];
        let app_rules = vec![make_app_rule("*")];
        match select_injection_source(&candidates, &app_rules, "/v1/messages", 0) {
            InjectionSource::SingleSecret { candidate } => {
                assert_eq!(candidate.secret_id, "s1");
                // app_rules 不参与
            }
            other => panic!("expected SingleSecret, got {other:?}"),
        }
    }

    #[test]
    fn select_multi_secret_offset_wraps() {
        let candidates = vec![make_candidate("s1", "*"), make_candidate("s2", "*")];
        match select_injection_source(&candidates, &[], "/v1/messages", 100) {
            InjectionSource::MultiSecret { offset, .. } => {
                assert_eq!(offset, 0); // 100 % 2 = 0
            }
            other => panic!("expected MultiSecret, got {other:?}"),
        }
    }
}
