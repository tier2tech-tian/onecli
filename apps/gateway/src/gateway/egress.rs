//! 按账号分出口（大杰 11-10）：账号 metadata.egress 写出口名（如 "kr"），网关为每个出口建独立上游连接，
//! 选中哪个号就用哪个号的出口。没写出口的号照旧用默认连接（读 HTTPS_PROXY），行为不变。
//!
//! 隔离规则：
//! - 出口连接显式指定代理，不读 HTTPS_PROXY / NO_PROXY，连接池互不复用。
//! - 标了出口的号只走自己的出口：出口没配置、或探测/转发判定不通时，这个号本次不可用，绝不回落默认出口。
//! - 出口不通是"整组号暂停"，跟单号额度冷却（secret_cooldowns）分开，不写冷却表。
//!
//! 配置：`GATEWAY_EGRESS_PROXIES=kr=http://127.0.0.1:20178[,名字=代理地址…]`；
//! 探测地址 `GATEWAY_EGRESS_PROBE_URL`（默认 https://ipinfo.io/ip，无鉴权），每 15 秒经各出口探一次。

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tracing::{info, warn};

const PROBE_INTERVAL: Duration = Duration::from_secs(15);
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_PROBE_URL: &str = "https://ipinfo.io/ip";

struct Route {
    proxy: String,
    client: reqwest::Client,
    /// 启动时按"不通"算，第一次探测成功才放行，免得隧道没起来时把请求打进去
    up: AtomicBool,
}

/// 出口清单。空清单 = 没开按账号分出口，所有号走默认连接。
#[derive(Default)]
pub(crate) struct EgressRegistry {
    routes: HashMap<String, Route>,
}

/// 某个号这次能不能发、用哪个连接
pub(crate) enum EgressPick<'a> {
    /// 没标出口：用调用方传入的默认连接
    Default,
    /// 标了出口且可用
    Route(&'a reqwest::Client),
    /// 标了出口但不可用（reason：unknown = 清单里没有，down = 探测/转发判定不通）
    Unavailable {
        egress: String,
        reason: &'static str,
    },
}

/// 账号 metadata 里的出口名（去空白、转小写；没写或空串 = 默认出口）
pub(crate) fn from_metadata(metadata: Option<&serde_json::Value>) -> Option<String> {
    metadata
        .and_then(|m| m.get("egress"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
}

/// 解析 `名字=代理地址` 列表；坏条目记日志跳过（对应的号会因 unknown 不可用，不影响其他号）
fn parse(spec: &str) -> Vec<(String, String)> {
    spec.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|entry| match entry.split_once('=') {
            Some((name, url)) if !name.trim().is_empty() && !url.trim().is_empty() => {
                Some((name.trim().to_lowercase(), url.trim().to_string()))
            }
            _ => {
                warn!(
                    entry,
                    "GATEWAY_EGRESS_PROXIES 条目格式不对，已跳过（应为 名字=代理地址）"
                );
                None
            }
        })
        .collect()
}

impl EgressRegistry {
    pub(crate) fn from_env(accept_invalid_certs: bool) -> Self {
        let spec = std::env::var("GATEWAY_EGRESS_PROXIES").unwrap_or_default();
        Self::build(&parse(&spec), accept_invalid_certs)
    }

    fn build(entries: &[(String, String)], accept_invalid_certs: bool) -> Self {
        let mut routes = HashMap::new();
        for (name, proxy) in entries {
            let built = reqwest::Proxy::all(proxy.as_str()).and_then(|p| {
                reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .danger_accept_invalid_certs(accept_invalid_certs)
                    // 显式代理会关掉 HTTPS_PROXY 等环境变量代理（reqwest proxy() 置 auto_sys_proxy=false）
                    .proxy(p)
                    .build()
            });
            match built {
                Ok(client) => {
                    info!(egress = %name, proxy = %proxy, "已配置账号出口");
                    routes.insert(
                        name.clone(),
                        Route {
                            proxy: proxy.clone(),
                            client,
                            up: AtomicBool::new(false),
                        },
                    );
                }
                Err(error) => {
                    warn!(egress = %name, proxy = %proxy, %error, "账号出口配置无效，已跳过")
                }
            }
        }
        Self { routes }
    }

    pub(crate) fn pick(&self, egress: Option<&str>) -> EgressPick<'_> {
        let Some(name) = egress else {
            return EgressPick::Default;
        };
        match self.routes.get(name) {
            None => EgressPick::Unavailable {
                egress: name.to_owned(),
                reason: "unknown",
            },
            Some(route) if !route.up.load(Ordering::Relaxed) => EgressPick::Unavailable {
                egress: name.to_owned(),
                reason: "down",
            },
            Some(route) => EgressPick::Route(&route.client),
        }
    }

    /// 经这个出口转发出现网络错误：整组号先停用，等下一次探测成功再放行
    pub(crate) fn mark_down(&self, egress: Option<&str>) {
        if let Some(route) = egress.and_then(|name| self.routes.get(name)) {
            if route.up.swap(false, Ordering::Relaxed) {
                warn!(
                    egress = egress.unwrap_or_default(),
                    "账号出口转发失败，暂停这组账号直到探测恢复"
                );
            }
        }
    }

    fn set_up(&self, name: &str, up: bool, detail: &str) {
        let Some(route) = self.routes.get(name) else {
            return;
        };
        if route.up.swap(up, Ordering::Relaxed) != up {
            if up {
                info!(egress = %name, proxy = %route.proxy, detail, "账号出口探测恢复，放行这组账号");
            } else {
                warn!(egress = %name, proxy = %route.proxy, detail, "账号出口探测不通，暂停这组账号");
            }
        }
    }

    /// 后台定时探测各出口；清单为空时不启动
    pub(crate) fn spawn_probe(self: &Arc<Self>) {
        if self.routes.is_empty() {
            return;
        }
        let url = std::env::var("GATEWAY_EGRESS_PROBE_URL")
            .unwrap_or_else(|_| DEFAULT_PROBE_URL.to_string());
        let registry = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                registry.probe_once(&url).await;
                tokio::time::sleep(PROBE_INTERVAL).await;
            }
        });
    }

    async fn probe_once(&self, url: &str) {
        for (name, route) in &self.routes {
            let result = route.client.get(url).timeout(PROBE_TIMEOUT).send().await;
            match result {
                Ok(resp) if resp.status().is_success() => self.set_up(name, true, "ok"),
                Ok(resp) => self.set_up(name, false, &format!("status {}", resp.status().as_u16())),
                Err(error) => self.set_up(name, false, &error.to_string()),
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(entries: &[(&str, &str)], up: bool) -> Self {
        let owned: Vec<_> = entries
            .iter()
            .map(|(n, u)| (n.to_string(), u.to_string()))
            .collect();
        let registry = Self::build(&owned, false);
        for route in registry.routes.values() {
            route.up.store(up, Ordering::Relaxed);
        }
        registry
    }

    #[cfg(test)]
    pub(crate) async fn probe_for_test(&self, url: &str) {
        self.probe_once(url).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_egress_is_trimmed_and_lowercased() {
        let m = serde_json::json!({"egress": "  KR "});
        assert_eq!(from_metadata(Some(&m)).as_deref(), Some("kr"));
        assert_eq!(
            from_metadata(Some(&serde_json::json!({"egress": ""}))),
            None
        );
        assert_eq!(from_metadata(Some(&serde_json::json!({"egress": 1}))), None);
        assert_eq!(from_metadata(Some(&serde_json::json!({}))), None);
        assert_eq!(from_metadata(None), None);
    }

    #[test]
    fn parse_skips_bad_entries() {
        assert_eq!(
            parse(" kr=http://127.0.0.1:20178 , bad, =x, jp= ,US=http://h:1"),
            vec![
                ("kr".to_string(), "http://127.0.0.1:20178".to_string()),
                ("us".to_string(), "http://h:1".to_string()),
            ]
        );
    }

    #[test]
    fn pick_never_falls_back_for_tagged_secrets() {
        let registry = EgressRegistry::for_test(&[("kr", "http://127.0.0.1:9")], false);
        assert!(matches!(registry.pick(None), EgressPick::Default));
        assert!(matches!(
            registry.pick(Some("kr")),
            EgressPick::Unavailable { reason: "down", .. }
        ));
        assert!(matches!(
            registry.pick(Some("jp")),
            EgressPick::Unavailable {
                reason: "unknown",
                ..
            }
        ));
        registry.set_up("kr", true, "test");
        assert!(matches!(registry.pick(Some("kr")), EgressPick::Route(_)));
        registry.mark_down(Some("kr"));
        assert!(matches!(
            registry.pick(Some("kr")),
            EgressPick::Unavailable { reason: "down", .. }
        ));
    }

    #[test]
    fn empty_registry_marks_every_tag_unknown() {
        let registry = EgressRegistry::default();
        assert!(matches!(
            registry.pick(Some("kr")),
            EgressPick::Unavailable {
                reason: "unknown",
                ..
            }
        ));
    }
}
