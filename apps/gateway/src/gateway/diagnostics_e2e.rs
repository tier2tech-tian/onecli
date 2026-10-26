//! 本地HTTP上游→实际转发函数→真实Postgres的诊断回归。显式设置隔离测试库后运行。
use super::*;
use crate::connect::SecretCandidate;
use crate::inject::{Injection, InjectionRule};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use std::sync::atomic::{AtomicUsize, Ordering};

#[tokio::test]
#[ignore = "需要ONECLI_DIAGNOSTIC_TEST_DB指向隔离Postgres"]
async fn real_forwarding_persists_attempt_chain() {
    let url = std::env::var("ONECLI_DIAGNOSTIC_TEST_DB").expect("必须指定隔离测试库");
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    sqlx::query("CREATE TABLE IF NOT EXISTS request_logs (id text,project_id text,agent_id text,method text,host text,path text,provider text,status integer,latency_ms integer,injection_count integer,extra_data jsonb)").execute(&pool).await.unwrap();
    let cache = crate::cache::create_store().await.unwrap();
    crate::telemetry::init(pool.clone(), cache.clone());
    let approvals = crate::approval::create_store().await.unwrap();
    for (name, statuses, candidates, size) in [
        ("retry_success", vec![429, 200], 2, 3usize),
        ("exhausted", vec![429, 429, 429], 3, 3),
        ("stop_other_error", vec![429, 401], 3, 3),
        ("single", vec![403], 1, 3),
        ("oversized", vec![429], 3, 4 * 1024 * 1024 + 1),
        ("transport_after_429", vec![429, 0], 2, 3),
    ] {
        let seen = Arc::new(AtomicUsize::new(0));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let host = listener.local_addr().unwrap().to_string();
        let transport_failure = statuses.last() == Some(&0);
        let expected_status = if transport_failure {
            502
        } else {
            *statuses.last().unwrap()
        };
        let expected_count = statuses.len();
        let seen_server = seen.clone();
        let upstream = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let seen = seen_server.clone();
                let statuses = statuses.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let index = seen.fetch_add(1, Ordering::SeqCst);
                        let code = statuses[index.min(statuses.len() - 1)];
                        let credential = req
                            .headers()
                            .get("authorization")
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_owned();
                        async move {
                            let _ = req.into_body().collect().await.unwrap();
                            if code == 0 {
                                return Err(std::io::Error::other("测试断开连接"));
                            }
                            let body = if code == 200 {
                                "data: success\n\n".into()
                            } else {
                                serde_json::json!({"error":{"type":"rate_limit_error","message":format!("Rejected {credential}")}}).to_string()
                            };
                            Ok::<_, std::io::Error>(
                                Response::builder()
                                    .status(code)
                                    .header(
                                        "content-type",
                                        if code == 200 {
                                            "text/event-stream"
                                        } else {
                                            "application/json"
                                        },
                                    )
                                    .header("request-id", format!("upstream-{index}"))
                                    .header("retry-after", "30")
                                    .body(Full::new(Bytes::from(body)))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(socket), svc)
                        .await;
                });
            }
        });
        let candidate_rules: Vec<_> = (0..candidates)
            .map(|i| SecretCandidate {
                secret_id: format!("account-{i}"),
                rule: InjectionRule {
                    path_pattern: "*".into(),
                    injections: vec![Injection::SetHeader {
                        name: "authorization".into(),
                        value: format!("Bearer mock-secret-{i}"),
                    }],
                },
            })
            .collect();
        let rules = Arc::new(mitm::ResolvedRules {
            injection_rules: vec![candidate_rules[0].rule.clone()],
            secret_candidates: candidate_rules,
            policy_rules: vec![],
            access_restricted: false,
            intercept_token: None,
            plan: "free".into(),
            rewrite_host: None,
            connection_label: None,
            finalizer: None,
            body_transform: None,
            policy_mode: "allow".into(),
            claim_token: None,
            session_policy: None,
            budget_bindings: vec![],
        });
        let agent = format!("diag-{name}-{}", uuid::Uuid::new_v4());
        let ctx = Arc::new(ProxyContext {
            project_id: Some("test".into()),
            organization_id: Some("test".into()),
            agent_id: Some(agent.clone()),
            agent_name: Some("test".into()),
            agent_identifier: None,
            agent_token: None,
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let cache = cache.clone();
        let approvals = approvals.clone();
        let pool_server = pool.clone();
        let proxy = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let svc = service_fn(move |req| {
                let rules = rules.clone();
                let cache = cache.clone();
                let ctx = ctx.clone();
                let approvals = approvals.clone();
                let pool = pool_server.clone();
                let host = host.clone();
                async move {
                    Ok::<_, std::convert::Infallible>(
                        forward::forward_request(
                            req,
                            &host,
                            "http",
                            reqwest::Client::new(),
                            &rules,
                            &*cache,
                            &ctx,
                            &approvals,
                            &pool,
                        )
                        .await
                        .unwrap_or_else(|_| response::resolution_failed()),
                    )
                }
            });
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(socket), svc)
                .await;
        });
        let response = reqwest::Client::new()
            .post(format!("http://{proxy_addr}/v1/messages"))
            .body(vec![b'x'; size])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), expected_status);
        let body = response.text().await.unwrap();
        if expected_status == 200 {
            assert_eq!(body, "data: success\n\n");
        } else if transport_failure {
            assert!(body.contains("resolution_failed"));
        } else {
            assert!(body.contains("mock-secret-"), "原上游响应不得被脱敏或吞掉");
        }
        assert_eq!(seen.load(Ordering::SeqCst), expected_count);
        let mut saved = None;
        for _ in 0..70 {
            saved = sqlx::query_scalar::<_, String>(
                "SELECT extra_data::text FROM request_logs WHERE agent_id=$1",
            )
            .bind(&agent)
            .fetch_optional(&pool)
            .await
            .unwrap();
            if saved.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        let saved = saved.expect("日志未落库");
        assert!(!saved.contains("mock-secret-"));
        let data: serde_json::Value = serde_json::from_str(&saved).unwrap();
        let d = &data["upstream"];
        assert_eq!(d["attempts"].as_array().unwrap().len(), expected_count);
        if transport_failure {
            assert!(d["final_status"].is_null());
            assert_eq!(d["gateway_status"], 502);
            assert_eq!(d["attempts"][1]["error"]["capture"], "no_response");
        } else {
            assert_eq!(d["final_status"], expected_status);
        }
        assert_eq!(d["attempts"][0]["error"]["headers"]["retry-after"], "30");
        assert!(d["attempts"][0]["error"]["message"]
            .as_str()
            .unwrap()
            .contains("[REDACTED]"));
        println!("真实转发与落库通过：{name}, attempts={expected_count}, status={expected_status}");
        proxy.abort();
        upstream.abort();
    }
    // 审批通过后断连必须更新原记录，不另建一条脱离审批的日志。
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO request_logs(id,status,extra_data) VALUES($1,202,'{\"approval_marker\":true}')")
        .bind(&id).execute(&pool).await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_addr = listener.local_addr().unwrap();
    drop(listener);
    let error = reqwest::Client::new()
        .get(format!("http://{closed_addr}/"))
        .send()
        .await
        .unwrap_err();
    let ctx = ProxyContext {
        project_id: Some("test".into()),
        organization_id: Some("test".into()),
        agent_id: Some("approval-test".into()),
        agent_name: None,
        agent_identifier: None,
        agent_token: None,
    };
    diagnostics::record_transport_error(
        &error,
        uuid::Uuid::new_v4(),
        None,
        5,
        &mut vec![],
        &ctx,
        "localhost",
        "GET",
        "/",
        (Some(&id), Some("approval-1"), Some("2026-10-26T00:00:00Z")),
    );
    let mut updated = None;
    for _ in 0..70 {
        updated = sqlx::query_scalar::<_, String>(
            "SELECT extra_data::text FROM request_logs WHERE id=$1 AND status=502",
        )
        .bind(&id)
        .fetch_optional(&pool)
        .await
        .unwrap();
        if updated.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let d: serde_json::Value = serde_json::from_str(&updated.expect("审批日志未更新")).unwrap();
    assert_eq!(d["decision"], "approval_approved");
    assert_eq!(d["approval_marker"], true);
    assert_eq!(d["upstream"]["end_reason"], "transport_error");
    println!("真实审批日志更新通过：保留原行及原字段");
}
