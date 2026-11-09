//! 按账号分出口的端到端回归：本地假"出口代理"+ 假直连上游 → 实际转发函数。不连数据库、不碰任何真实账号。
//! 主机用非 Anthropic 地址，额度冷却不参与（cooldown::applies 为假），只验出口选择与不回落。
use super::*;
use crate::connect::SecretCandidate;
use crate::inject::{Injection, InjectionRule};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::sync::Mutex;
use tokio::net::TcpListener;

type Seen = Arc<Mutex<Vec<String>>>;

/// 起一个 HTTP 服务：记下 "名字:authorization"，按 authorization 决定状态码（含 "429" 的回 429）
async fn spawn_recorder(name: &'static str, seen: Seen) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let seen = seen.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let auth = req
                        .headers()
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("-")
                        .to_owned();
                    seen.lock().unwrap().push(format!("{name}:{auth}"));
                    async move {
                        let len = req.into_body().collect().await.unwrap().to_bytes().len();
                        let code = if auth.contains("429") { 429 } else { 200 };
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(code)
                                .body(Full::new(Bytes::from(format!("{name} {len}"))))
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
    addr
}

fn candidate(id: &str, auth: &str, egress: Option<&str>) -> SecretCandidate {
    SecretCandidate {
        secret_id: id.into(),
        rule: InjectionRule {
            path_pattern: "*".into(),
            injections: vec![Injection::SetHeader {
                name: "authorization".into(),
                value: auth.into(),
            }],
        },
        egress: egress.map(str::to_owned),
    }
}

/// 经实际 forward_request 发一次 POST，返回（状态码，正文）
async fn send(
    upstream: &str,
    registry: Arc<egress::EgressRegistry>,
    candidates: Vec<SecretCandidate>,
    body_len: usize,
) -> (u16, String) {
    let rules = Arc::new(mitm::ResolvedRules {
        injection_rules: candidates.iter().map(|c| c.rule.clone()).collect(),
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
        agent_id: Some(format!("egress-{}", uuid::Uuid::new_v4())),
        agent_name: None,
        agent_identifier: None,
        agent_token: None,
        client_user: None,
    });
    let cache = crate::cache::create_store().await.unwrap();
    let approvals = crate::approval::create_store().await.unwrap();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/unused")
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front = listener.local_addr().unwrap();
    let host = upstream.to_owned();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let svc = service_fn(move |req| {
            let (rules, ctx, cache, approvals, pool, host, registry) = (
                rules.clone(),
                ctx.clone(),
                cache.clone(),
                approvals.clone(),
                pool.clone(),
                host.clone(),
                registry.clone(),
            );
            async move {
                // 默认连接显式不走任何代理，模拟"美国出口"直连假上游
                let default = reqwest::Client::builder().no_proxy().build().unwrap();
                Ok::<_, std::convert::Infallible>(
                    forward::forward_request(
                        req, &host, "http", default, &registry, &rules, &*cache, &ctx, &approvals,
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
    let resp = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(format!("http://{front}/v1/messages"))
        .body(vec![b'x'; body_len])
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.text().await.unwrap())
}

#[tokio::test]
async fn tagged_secrets_use_only_their_egress() {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let direct = spawn_recorder("direct", seen.clone()).await;
    let kr_proxy = spawn_recorder("kr", seen.clone()).await;
    let upstream = direct.to_string();
    let kr_url = format!("http://{kr_proxy}");
    let up = Arc::new(egress::EgressRegistry::for_test(&[("kr", &kr_url)], true));
    let down = Arc::new(egress::EgressRegistry::for_test(&[("kr", &kr_url)], false));
    let take = |seen: &Seen| std::mem::take(&mut *seen.lock().unwrap());

    // 1. 单个韩国号：请求只经过韩国代理，不碰直连上游
    let (st, body) = send(
        &upstream,
        up.clone(),
        vec![candidate("k1", "Bearer kr-1", Some("kr"))],
        3,
    )
    .await;
    assert_eq!((st, body.as_str()), (200, "kr 3"));
    assert_eq!(take(&seen), vec!["kr:Bearer kr-1"]);

    // 2. 没标出口的号：照旧走默认连接
    let (st, body) = send(
        &upstream,
        up.clone(),
        vec![candidate("u1", "Bearer us-1", None)],
        3,
    )
    .await;
    assert_eq!((st, body.as_str()), (200, "direct 3"));
    assert_eq!(take(&seen), vec!["direct:Bearer us-1"]);

    // 3. 韩国出口不通：单个韩国号返回 503，两边都没收到请求（不回落默认出口）
    let (st, body) = send(
        &upstream,
        down.clone(),
        vec![candidate("k1", "Bearer kr-1", Some("kr"))],
        3,
    )
    .await;
    assert_eq!(st, 503);
    assert!(body.contains("egress_unavailable"));
    assert!(take(&seen).is_empty());

    // 4. 出口名不在清单里：同样 503，不回落
    let (st, _) = send(
        &upstream,
        up.clone(),
        vec![candidate("j1", "Bearer jp-1", Some("jp"))],
        3,
    )
    .await;
    assert_eq!(st, 503);
    assert!(take(&seen).is_empty());

    // 5. 全是韩国号且出口不通（轮换路径）：503，一个请求都不发
    let pool_kr = vec![
        candidate("k1", "Bearer kr-1", Some("kr")),
        candidate("k2", "Bearer kr-2", Some("kr")),
    ];
    let (st, _) = send(&upstream, down.clone(), pool_kr.clone(), 3).await;
    assert_eq!(st, 503);
    assert!(take(&seen).is_empty());

    // 6. 韩国号 429 换到下一个韩国号：两次都经韩国代理
    let pool_kr_429 = vec![
        candidate("k1", "Bearer kr-429", Some("kr")),
        candidate("k2", "Bearer kr-2", Some("kr")),
    ];
    let (st, body) = send(&upstream, up.clone(), pool_kr_429, 3).await;
    assert_eq!((st, body.as_str()), (200, "kr 3"));
    let got = take(&seen);
    assert!(
        got.iter().all(|s| s.starts_with("kr:")),
        "换号后仍须走韩国出口：{got:?}"
    );

    // 7. 混合候选里韩国号 429 换到美国号：各走各的出口
    let mixed = vec![
        candidate("k1", "Bearer kr-429", Some("kr")),
        candidate("u1", "Bearer us-1", None),
    ];
    let (st, _) = send(&upstream, up.clone(), mixed.clone(), 3).await;
    assert_eq!(st, 200);
    let got = take(&seen);
    for s in &got {
        assert!(
            (s.starts_with("kr:") && s.contains("kr-"))
                || (s.starts_with("direct:") && s.contains("us-")),
            "账号和出口不得串：{got:?}"
        );
    }

    // 8. 超过重试缓冲的大请求（单次发送路径）也按号选出口
    let big = 32 * 1024 * 1024 + 1;
    let (st, body) = send(&upstream, up.clone(), pool_kr.clone(), big).await;
    assert_eq!((st, body), (200, format!("kr {big}")));
    assert!(take(&seen).iter().all(|s| s.starts_with("kr:")));
    let (st, _) = send(&upstream, down.clone(), pool_kr, big).await;
    assert_eq!(st, 503);
    assert!(take(&seen).is_empty());
}

#[tokio::test]
async fn transport_error_pauses_egress_until_probe_recovers() {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let direct = spawn_recorder("direct", seen.clone()).await;
    // 拿一个空闲端口再关掉，当作"隧道断了"的代理
    let dead = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let registry = Arc::new(egress::EgressRegistry::for_test(
        &[("kr", &format!("http://{dead}"))],
        true,
    ));
    let one = vec![candidate("k1", "Bearer kr-1", Some("kr"))];

    // 第一次：经韩国代理连不上 → 网关报错（502），且不改走直连
    let (st, _) = send(&direct.to_string(), registry.clone(), one.clone(), 3).await;
    assert_eq!(st, 502);
    assert!(seen.lock().unwrap().is_empty());
    // 出口被停用，之后直接 503，不再尝试
    assert!(matches!(
        registry.pick(Some("kr")),
        egress::EgressPick::Unavailable { reason: "down", .. }
    ));
    let (st, _) = send(&direct.to_string(), registry.clone(), one, 3).await;
    assert_eq!(st, 503);

    // 探测：代理不通保持停用；换成能通的探测地址后恢复
    registry.probe_for_test("http://example.invalid/ip").await;
    assert!(matches!(
        registry.pick(Some("kr")),
        egress::EgressPick::Unavailable { .. }
    ));
    let kr_ok = spawn_recorder("kr", seen.clone()).await;
    let healthy = egress::EgressRegistry::for_test(&[("kr", &format!("http://{kr_ok}"))], false);
    healthy.probe_for_test("http://probe.test/ip").await;
    assert!(matches!(
        healthy.pick(Some("kr")),
        egress::EgressPick::Route(_)
    ));
    assert_eq!(
        seen.lock().unwrap().as_slice(),
        ["kr:-"],
        "探测请求必须经出口代理发出"
    );
}
