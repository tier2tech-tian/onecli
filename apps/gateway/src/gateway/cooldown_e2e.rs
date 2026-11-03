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
            None,
            None,
        ),
        observe(
            &pool,
            Some("b"),
            "api.anthropic.com",
            "/v1/messages",
            &hour,
            None,
            None,
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

/// 会话粘号 × 429（大杰 11-03 要求）：固定的号 429 时照常换下一个，成功后改记新号；冷却中的号直接跳过不打
#[cfg(test)]
#[tokio::test]
#[ignore = "需要专用隔离库 COOLDOWN_TEST_DATABASE_URL"]
async fn session_sticky_switches_on_429_and_repins() {
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
    .ok();
    for id in ["sa", "sb", "sc"] {
        sqlx::query("INSERT INTO secrets(id) VALUES($1) ON CONFLICT DO NOTHING")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::query("DELETE FROM secret_cooldowns WHERE secret_id IN ('sa','sb','sc')")
        .execute(&pool)
        .await
        .unwrap();
    // 上游：sa 回 429（5 小时额度用完），其余 200
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_addr = up.local_addr().unwrap();
    let reset = time::OffsetDateTime::now_utc().unix_timestamp() + 3600;
    let seen_up = seen.clone();
    tokio::spawn(async move {
        loop {
            let (socket, _) = up.accept().await.unwrap();
            let seen = seen_up.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let auth = req.headers().get("authorization").unwrap().to_str().unwrap().to_owned();
                    seen.lock().unwrap().push(auth.clone());
                    async move {
                        req.into_body().collect().await.unwrap();
                        let code = if auth == "sa" { 429 } else { 200 };
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(code)
                                .header("anthropic-ratelimit-unified-5h-status", if code == 429 { "rejected" } else { "allowed" })
                                .header("anthropic-ratelimit-unified-5h-reset", reset.to_string())
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(if code == 200 { "ok" } else { "quota" })))
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
    let client = reqwest::Client::builder().no_proxy().resolve("api.anthropic.com", up_addr).build().unwrap();
    let host = format!("api.anthropic.com:{}", up_addr.port());
    let cache = crate::cache::create_store().await.unwrap();
    let approvals = crate::approval::create_store().await.unwrap();
    let candidates: Vec<_> = ["sa", "sb", "sc"]
        .iter()
        .map(|id| SecretCandidate {
            secret_id: id.to_string(),
            rule: InjectionRule {
                path_pattern: "*".into(),
                injections: vec![Injection::SetHeader { name: "authorization".into(), value: id.to_string() }],
            },
        })
        .collect();
    let rules = Arc::new(mitm::ResolvedRules {
        injection_rules: vec![],
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
    let agent = uuid::Uuid::new_v4().to_string();
    let ctx = Arc::new(ProxyContext {
        project_id: None,
        organization_id: None,
        agent_id: Some(agent.clone()),
        agent_name: None,
        agent_identifier: None,
        agent_token: None,
    });
    let px = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let px_addr = px.local_addr().unwrap();
    let pool2 = pool.clone();
    tokio::spawn(async move {
        loop {
            let (socket, _) = px.accept().await.unwrap();
            let (rules, ctx, cache, approvals, pool, client, host) =
                (rules.clone(), ctx.clone(), cache.clone(), approvals.clone(), pool2.clone(), client.clone(), host.clone());
            tokio::spawn(async move {
                let svc = service_fn(move |req| {
                    let (rules, ctx, cache, approvals, pool, client, host) =
                        (rules.clone(), ctx.clone(), cache.clone(), approvals.clone(), pool.clone(), client.clone(), host.clone());
                    async move {
                        Ok::<_, std::convert::Infallible>(
                            forward::forward_request(req, &host, "http", client, &rules, &*cache, &ctx, &approvals, &pool)
                                .await
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), svc).await;
            });
        }
    });
    let send = |session: &'static str| {
        let px_addr = px_addr;
        async move {
            reqwest::Client::builder()
                .no_proxy()
                .build()
                .unwrap()
                .post(format!("http://{px_addr}/v1/messages"))
                .header("x-claude-code-session-id", session)
                .body("x")
                .send()
                .await
                .unwrap()
                .status()
        }
    };
    let take = || std::mem::take(&mut *seen.lock().unwrap());

    // 1. 会话 S 原先固定在 sa；sa 这次 429 → 换到 sb 成功
    forward::remember_sticky_for_test(&agent, "S", "sa");
    assert_eq!(send("S").await, 200);
    assert_eq!(take(), vec!["sa", "sb"], "固定的号 429 要照常换下一个");
    // 2. 同一会话下一轮直接用 sb，不再先打 sa
    assert_eq!(send("S").await, 200);
    assert_eq!(take(), vec!["sb"], "成功后改记新号");
    // 3. 另一个会话也固定在 sa，但 sa 已进冷却 → 直接跳过不打，用下一个
    forward::remember_sticky_for_test(&agent, "U", "sa");
    assert_eq!(send("U").await, 200);
    assert_eq!(take(), vec!["sb"], "冷却中的号不打");
    // 4. 会话 U 之后固定在 sb
    assert_eq!(send("U").await, 200);
    assert_eq!(take(), vec!["sb"]);
    println!("会话粘号 × 429 / 冷却：通过");
}

/// 会话粘号 × 网络错误 / 单候选（6号 PR#10 复审 P1/P2）：固定号连接被断 → 绑定清掉；单候选成功 → 记绑定
#[cfg(test)]
#[tokio::test]
#[ignore = "需要专用隔离库 COOLDOWN_TEST_DATABASE_URL"]
async fn session_sticky_network_error_and_single_candidate() {
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
    sqlx::raw_sql("CREATE TABLE IF NOT EXISTS secrets(id TEXT PRIMARY KEY);").execute(&pool).await.unwrap();
    sqlx::raw_sql(include_str!(
        "../../../../packages/db/prisma/migrations/20261027020000_secret_cooldowns/migration.sql"
    ))
    .execute(&pool)
    .await
    .ok();
    for id in ["nd", "nb", "ma", "mb", "mc"] {
        sqlx::query("INSERT INTO secrets(id) VALUES($1) ON CONFLICT DO NOTHING").bind(id).execute(&pool).await.unwrap();
    }
    sqlx::query("DELETE FROM secret_cooldowns WHERE secret_id IN ('ma','mb','mc')").execute(&pool).await.unwrap();
    // 上游：nd 收到请求后直接断连接（服务返回错误 → 连接关闭），nb 正常 200
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_addr = up.local_addr().unwrap();
    let seen_up = seen.clone();
    tokio::spawn(async move {
        loop {
            let (socket, _) = up.accept().await.unwrap();
            let seen = seen_up.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let auth = req.headers().get("authorization").unwrap().to_str().unwrap().to_owned();
                    seen.lock().unwrap().push(auth.clone());
                    async move {
                        req.into_body().collect().await.unwrap();
                        if auth == "nd" {
                            return Err::<Response<Full<Bytes>>, std::io::Error>(std::io::Error::other("断开"));
                        }
                        // ma：5 小时额度用完（429 + 冷却头）；mb：403；其余 200
                        if auth == "ma" || auth == "mb" {
                            let reset = time::OffsetDateTime::now_utc().unix_timestamp() + 3600;
                            return Ok(Response::builder()
                                .status(if auth == "ma" { 429 } else { 403 })
                                .header("anthropic-ratelimit-unified-5h-status", "rejected")
                                .header("anthropic-ratelimit-unified-5h-reset", reset.to_string())
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from("err")))
                                .unwrap());
                        }
                        Ok(Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(Full::new(Bytes::from("ok")))
                            .unwrap())
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), svc).await;
            });
        }
    });
    let client = reqwest::Client::builder().no_proxy().resolve("api.anthropic.com", up_addr).build().unwrap();
    let host = format!("api.anthropic.com:{}", up_addr.port());
    let cache = crate::cache::create_store().await.unwrap();
    let approvals = crate::approval::create_store().await.unwrap();
    let agent = uuid::Uuid::new_v4().to_string();
    let rules_of = |ids: &[&str]| {
        Arc::new(mitm::ResolvedRules {
            injection_rules: vec![],
            secret_candidates: ids
                .iter()
                .map(|id| SecretCandidate {
                    secret_id: id.to_string(),
                    rule: InjectionRule {
                        path_pattern: "*".into(),
                        injections: vec![Injection::SetHeader { name: "authorization".into(), value: id.to_string() }],
                    },
                })
                .collect(),
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
        })
    };
    let ctx = Arc::new(ProxyContext {
        project_id: None,
        organization_id: None,
        agent_id: Some(agent.clone()),
        agent_name: None,
        agent_identifier: None,
        agent_token: None,
    });
    // 网关：forward_request 出错（上游断开）时回 502，不让测试服务崩
    let spawn_proxy = |rules: Arc<mitm::ResolvedRules>| {
        let (ctx, cache, approvals, pool, client, host) =
            (ctx.clone(), cache.clone(), approvals.clone(), pool.clone(), client.clone(), host.clone());
        async move {
            let px = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = px.local_addr().unwrap();
            tokio::spawn(async move {
                loop {
                    let (socket, _) = px.accept().await.unwrap();
                    let (rules, ctx, cache, approvals, pool, client, host) =
                        (rules.clone(), ctx.clone(), cache.clone(), approvals.clone(), pool.clone(), client.clone(), host.clone());
                    tokio::spawn(async move {
                        let svc = service_fn(move |req| {
                            let (rules, ctx, cache, approvals, pool, client, host) =
                                (rules.clone(), ctx.clone(), cache.clone(), approvals.clone(), pool.clone(), client.clone(), host.clone());
                            async move {
                                match forward::forward_request(req, &host, "http", client, &rules, &*cache, &ctx, &approvals, &pool).await {
                                    Ok(r) => Ok::<_, std::convert::Infallible>(r.map(http_body_util::Either::Left)),
                                    Err(_) => Ok(Response::builder()
                                        .status(502)
                                        .body(http_body_util::Either::Right(Full::new(Bytes::from("upstream error"))))
                                        .unwrap()),
                                }
                            }
                        });
                        let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), svc).await;
                    });
                }
            });
            addr
        }
    };
    let send = |addr: std::net::SocketAddr, session: &'static str| async move {
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .post(format!("http://{addr}/v1/messages"))
            .header("x-claude-code-session-id", session)
            .body("x")
            .send()
            .await
            .unwrap()
            .status()
    };
    let take = || std::mem::take(&mut *seen.lock().unwrap());

    // 1. 会话 V 固定在 nd，nd 连接被断 → 这次 502，绑定被清掉（下次不再先打 nd）
    let multi = spawn_proxy(rules_of(&["nd", "nb"])).await;
    forward::remember_sticky_for_test(&agent, "V", "nd");
    assert_eq!(send(multi, "V").await, 502);
    assert_eq!(take(), vec!["nd"]);
    assert_eq!(forward::sticky_bound_for_test(&agent, "V"), None, "网络错误要清掉固定号");
    // 2. 只有一个候选 nb：成功后也要记绑定
    let single = spawn_proxy(rules_of(&["nb"])).await;
    assert_eq!(send(single, "W").await, 200);
    assert_eq!(take(), vec!["nb"]);
    assert_eq!(forward::sticky_bound_for_test(&agent, "W").as_deref(), Some("nb"), "单候选成功要记绑定");
    // 3. 池子扩容成 [nd, nb] 后，会话 W 仍从 nb 开始，不先打 nd
    assert_eq!(send(multi, "W").await, 200);
    assert_eq!(take(), vec!["nb"]);
    // 4. 6号 PR#10 三审：固定号 ma 429（进冷却）→ 备用 mb 403 → 之后不能一直卡在 mb，健康的 mc 要能轮到
    let combo = spawn_proxy(rules_of(&["ma", "mb", "mc"])).await;
    forward::remember_sticky_for_test(&agent, "Z", "ma");
    assert_eq!(send(combo, "Z").await, 403);
    assert_eq!(take(), vec!["ma", "mb"]);
    assert_eq!(forward::sticky_bound_for_test(&agent, "Z"), None, "429 的固定号要解绑");
    let mut got = Vec::new();
    for _ in 0..3 {
        got.push(send(combo, "Z").await);
    }
    assert!(got.contains(&reqwest::StatusCode::OK), "后续请求要能轮到健康的 mc：{got:?}");
    assert_eq!(forward::sticky_bound_for_test(&agent, "Z").as_deref(), Some("mc"));
    take();
    assert_eq!(send(combo, "Z").await, 200);
    assert_eq!(take(), vec!["mc"], "改绑 mc 后直接用 mc");
    println!("会话粘号 × 网络错误 / 单候选 / 429→备用失败：通过");
}
