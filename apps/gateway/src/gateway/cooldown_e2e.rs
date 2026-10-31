//! 本地HTTP与隔离Postgres冷却验收，不访问真实模型账号。

#[cfg(test)]
#[tokio::test]
#[ignore = "需要专用隔离库 COOLDOWN_TEST_DATABASE_URL"]
async fn persisted_locks_and_http_forwarding() {
    use super::super::*;
    use super::*;
    use crate::{
        connect::SecretCandidate,
        inject::{Injection, InjectionRule},
    };
    use http_body_util::{BodyExt, Full};
    use hyper::{
        body::{Bytes, Incoming},
        service::service_fn,
        Request, Response,
    };
    use hyper_util::rt::TokioIo;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;
    let url = std::env::var("COOLDOWN_TEST_DATABASE_URL").expect("只允许隔离测试库");
    let pool = PgPool::connect(&url).await.unwrap();
    sqlx::raw_sql("CREATE TABLE IF NOT EXISTS secrets(id TEXT PRIMARY KEY);")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::raw_sql(include_str!(
        "../../../../packages/db/prisma/migrations/20261027020000_secret_cooldowns/migration.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    for id in ["a", "b", "c", "d"] {
        sqlx::query("INSERT INTO secrets(id) VALUES($1)")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
    }
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen_upstream = seen.clone();
    let reset = time::OffsetDateTime::now_utc().unix_timestamp() + 3600;
    let upstream = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let seen = seen_upstream.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let auth = req
                        .headers()
                        .get("authorization")
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned();
                    seen.lock().unwrap().push(auth.clone());
                    async move {
                        req.into_body().collect().await.unwrap();
                        let code = if auth == "a" || auth == "d" { 429 } else { 200 };
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(code)
                                .header(
                                    "anthropic-ratelimit-unified-7d-status",
                                    if code == 429 { "rejected" } else { "allowed" },
                                )
                                .header(
                                    "anthropic-ratelimit-unified-7d-reset",
                                    if auth == "d" {
                                        "invalid".to_string()
                                    } else {
                                        reset.to_string()
                                    },
                                )
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(if code == 200 {
                                    "ok"
                                } else {
                                    "quota"
                                })))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(socket), svc)
                    .await;
            });
        }
    });
    let client = reqwest::Client::builder()
        .no_proxy()
        .resolve("api.anthropic.com", addr)
        .build()
        .unwrap();
    // 使用显式端口指向本地上游；applies仍识别真实模型主机。
    let host = format!("api.anthropic.com:{}", addr.port());
    let cache = crate::cache::create_store().await.unwrap();
    let approvals = crate::approval::create_store().await.unwrap();
    for (label, ids, size, expected, expected_seen) in [
        ("首次429写库并轮换", vec!["a", "b"], 3, 200, vec!["a", "b"]),
        ("另一Agent跳过已锁账号", vec!["a", "b"], 3, 200, vec!["b"]),
        ("单账号锁定", vec!["a"], 3, 429, vec![]),
        (
            "大请求跳过锁定",
            vec!["a", "b", "c"],
            4 * 1024 * 1024 + 1,
            200,
            vec!["b"],
        ),
        ("无效时间不新增锁", vec!["d", "b"], 3, 200, vec!["d", "b"]),
        ("全池锁定", vec!["a", "c"], 3, 429, vec![]),
        ("到期自动解锁", vec!["c"], 3, 200, vec!["c"]),
        ("存储故障继续轮换", vec!["a", "b"], 3, 200, vec!["a", "b"]),
    ] {
        if label == "全池锁定" {
            sqlx::query("INSERT INTO secret_cooldowns VALUES ('c','five_hour',$1)")
                .bind(reset)
                .execute(&pool)
                .await
                .unwrap();
        }
        if label == "到期自动解锁" {
            sqlx::query("UPDATE secret_cooldowns SET reset_at=1 WHERE secret_id='c'")
                .execute(&pool)
                .await
                .unwrap();
        }
        let case_pool = if label == "存储故障继续轮换" {
            sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/unavailable")
                .unwrap()
        } else {
            PgPool::connect(&url).await.unwrap()
        }; // 新连接验证状态持久化，不等同于真实网关重启。
        seen.lock().unwrap().clear();
        let candidates: Vec<_> = ids
            .iter()
            .map(|id| SecretCandidate {
                secret_id: id.to_string(),
                rule: InjectionRule {
                    path_pattern: "*".into(),
                    injections: vec![Injection::SetHeader {
                        name: "authorization".into(),
                        value: id.to_string(),
                    }],
                },
            })
            .collect();
        // 故意把锁定账号放在旧规则末尾，检测单候选注入绕过。
        let mut injection_rules: Vec<_> = candidates.iter().map(|c| c.rule.clone()).collect();
        injection_rules.reverse();
        let rules = Arc::new(mitm::ResolvedRules {
            injection_rules,
            secret_candidates: candidates,
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
        let ctx = Arc::new(ProxyContext {
            project_id: None,
            organization_id: None,
            agent_id: Some(uuid::Uuid::new_v4().to_string()),
            agent_name: None,
            agent_identifier: None,
            agent_token: None,
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let cache = cache.clone();
        let approvals = approvals.clone();
        let client = client.clone();
        let host = host.clone();
        let proxy = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let svc = service_fn(move |req| {
                let (rules, ctx, cache, approvals, pool, client, host) = (
                    rules.clone(),
                    ctx.clone(),
                    cache.clone(),
                    approvals.clone(),
                    case_pool.clone(),
                    client.clone(),
                    host.clone(),
                );
                async move {
                    Ok::<_, std::convert::Infallible>(
                        forward::forward_request(
                            req, &host, "http", client, &rules, &*cache, &ctx, &approvals, &pool,
                        )
                        .await
                        .unwrap(),
                    )
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(socket), svc)
                .await;
        });
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .post(format!("http://{proxy_addr}/v1/messages"))
            .body(vec![b'x'; size])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "{label}");
        if expected == 429 {
            assert!(response.headers().contains_key("retry-after"));
            assert!(response.text().await.unwrap().contains("+08:00"));
        } else {
            assert_eq!(response.text().await.unwrap(), "ok");
        }
        assert_eq!(*seen.lock().unwrap(), expected_seen, "{label}");
        println!("通过：{label}");
        proxy.abort();
    }
    // 周锁不能被并发5小时响应缩短：使用同一个生产SQL入口observe。
    let weekly = sqlx::query_as::<_, (String, i64)>(
        "SELECT reason,reset_at FROM secret_cooldowns WHERE secret_id='a'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(weekly, ("seven_day".into(), reset));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM secret_cooldowns WHERE secret_id='d'")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    let quota_response = |reason: &str, until: i64| -> reqwest::Response {
        let prefix = if reason == "seven_day" { "7d" } else { "5h" };
        Response::builder()
            .status(429)
            .header(
                format!("anthropic-ratelimit-unified-{prefix}-status"),
                "rejected",
            )
            .header(
                format!("anthropic-ratelimit-unified-{prefix}-reset"),
                until.to_string(),
            )
            .body(reqwest::Body::from("quota"))
            .unwrap()
            .into()
    };
    let week = quota_response("seven_day", reset + 200);
    let hour = quota_response("five_hour", reset + 500);
    observe(
        &pool,
        Some("b"),
        "api.anthropic.com",
        "/v1/messages",
        &hour,
        None,
    )
    .await;
    observe(
        &pool,
        Some("b"),
        "api.anthropic.com",
        "/v1/messages",
        &week,
        None,
    )
    .await;
    observe(
        &pool,
        Some("b"),
        "api.anthropic.com",
        "/v1/messages",
        &hour,
        None,
    )
    .await;
    let older = quota_response("seven_day", reset + 100);
    observe(
        &pool,
        Some("b"),
        "api.anthropic.com",
        "/v1/messages",
        &older,
        None,
    )
    .await;
    let invalid = quota_response("seven_day", 1);
    observe(
        &pool,
        Some("b"),
        "api.anthropic.com",
        "/v1/messages",
        &invalid,
        None,
    )
    .await;
    let row = sqlx::query_as::<_, (String, i64)>(
        "SELECT reason,reset_at FROM secret_cooldowns WHERE secret_id='b'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row, ("seven_day".into(), reset + 200));
    // 并发到达顺序不影响周优先。
    sqlx::query("DELETE FROM secret_cooldowns WHERE secret_id='b'")
        .execute(&pool)
        .await
        .unwrap();
    tokio::join!(
        observe(
            &pool,
            Some("b"),
            "api.anthropic.com",
            "/v1/messages",
            &week,
            None
        ),
        observe(
            &pool,
            Some("b"),
            "api.anthropic.com",
            "/v1/messages",
            &hour,
            None
        )
    );
    let row = sqlx::query_as::<_, (String, i64)>(
        "SELECT reason,reset_at FROM secret_cooldowns WHERE secret_id='b'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row, ("seven_day".into(), reset + 200));
    println!("通过：周锁优先、同窗口旧响应不缩短、无效时间不改已有锁、并发优先级");
    // 本地冷却拒绝必须入库，并更新已有审批记录。
    sqlx::raw_sql("CREATE TABLE request_logs(id TEXT PRIMARY KEY,project_id TEXT,agent_id TEXT,method TEXT,host TEXT,path TEXT,provider TEXT,status INTEGER,latency_ms INTEGER,injection_count INTEGER,extra_data JSONB DEFAULT '{}'::jsonb);").execute(&pool).await.unwrap();
    let cache = crate::cache::create_store().await.unwrap();
    crate::telemetry::init(pool.clone(), cache);
    let ctx = ProxyContext {
        project_id: Some("test".into()),
        organization_id: Some("test".into()),
        agent_id: Some("test".into()),
        agent_name: None,
        agent_identifier: None,
        agent_token: None,
    };
    let _ = blocked(
        reset,
        uuid::Uuid::new_v4(),
        &ctx,
        "api.anthropic.com",
        "POST",
        "/v1/messages",
        1,
        (None, None, None),
    );
    sqlx::query(
        "INSERT INTO request_logs(id,status,extra_data) VALUES('approval',202,'{\"marker\":true}')",
    )
    .execute(&pool)
    .await
    .unwrap();
    let _ = blocked(
        reset,
        uuid::Uuid::new_v4(),
        &ctx,
        "api.anthropic.com",
        "POST",
        "/v1/messages",
        2,
        (
            Some("approval"),
            Some("approval-id"),
            Some("2026-10-27T00:00:00Z"),
        ),
    );
    let mut rows = Vec::new();
    for _ in 0..60 {
        rows = sqlx::query_as::<_, (String, String)>(
            "SELECT id,extra_data::text FROM request_logs WHERE status=429",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        if rows.len() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(rows.len(), 2);
    for (id, value) in rows {
        let v: serde_json::Value = serde_json::from_str(&value).unwrap();
        assert_eq!(v["upstream"]["end_reason"], "quota_cooldown");
        assert_eq!(v["upstream"]["attempts"], serde_json::json!([]));
        if id == "approval" {
            assert_eq!(v["marker"], true);
            assert_eq!(v["decision"], "approval_approved");
        }
    }
    println!("通过：本地429入库和审批终态原行更新");
    upstream.abort();
}

#[tokio::test]
#[ignore = "须在持久化HTTP用例退出后，使用同一隔离库单独启动测试进程"]
async fn fresh_process_reads_persisted_cooldown() {
    use super::*;
    let url = std::env::var("COOLDOWN_TEST_DATABASE_URL").unwrap();
    let pool = PgPool::connect(&url).await.unwrap();
    let locks = active(&pool, &["a".into(), "c".into()]).await;
    assert!(locks.contains_key("a"));
    assert!(!locks.contains_key("c"));
    println!("新测试进程读取到未过期周锁，并忽略已过期锁");
}
