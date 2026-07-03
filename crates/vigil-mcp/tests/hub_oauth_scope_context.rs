//! OAuth scope 上下文接线(hub → firewall)集成测试。
//!
//! 修复对象:Hub 出站 `tools/call` 评估此前 hardcode `OAuthScopeContext::NonOauth`,
//! 使 `Condition::ScopeNotInAllowList` 规则**静默永不触发**(文档教用户配 scope 白名单
//! Deny 规则 → 用户以为有保护,实际没有 —— 虚假安全感)。修复后:
//!   - 经 [`Hub::attach_upstream_with_oauth_scopes`] 挂上的 upstream → 评估走
//!     `Scopes(快照)`,越界 scope 命中 Deny 规则;空 scope 集 fail-closed 同样命中。
//!   - 经 [`Hub::attach_upstream`](stdio / Bearer / 无鉴权)→ 仍走 `NonOauth`,
//!     规则不适用(不会因 scope 规则误拦本地上游)。
//!
//! 三个用例共用同一条 `ScopeNotInAllowList` Deny 规则 + 同一 allowlist,唯一自变量是
//! attach 方式 / scope 集 —— 干净对照。**不**预埋 approval(与 `hub_http_transport_inherits`
//! 相反):请求必须落进 `firewall.evaluate` 才能测到 scope 分支。

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::err_expect,
    clippy::panic
)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

use vigil_audit::Ledger;
use vigil_firewall::{scorer::StaticDescriptorOracle, Firewall, FirewallConfig};
use vigil_mcp::protocol::JsonRpcRequest;
use vigil_mcp::upstream::{McpUpstream, UpstreamError};
use vigil_mcp::{Hub, HubConfig};
use vigil_policy::{defaults::default_ruleset, Condition, PolicyAction, PolicyEngine, PolicyRule};
use vigil_types::{ServerProfile, TransportKind, TrustLevel};

const SCOPE_RULE_ID: &str = "scope-allowlist-deny";

#[derive(Debug)]
struct HttpMockUpstream {
    server_id: String,
    canned: Mutex<Value>,
}

impl McpUpstream for HttpMockUpstream {
    fn server_id(&self) -> &str {
        &self.server_id
    }
    fn transport(&self) -> TransportKind {
        TransportKind::Http
    }
    fn call(
        &self,
        _method: &str,
        _params: Option<Value>,
        _timeout: Duration,
    ) -> Result<Value, UpstreamError> {
        Ok(self.canned.lock().unwrap().clone())
    }
    fn shutdown(&self) {}
}

/// 装 Hub(default ruleset + 一条 `ScopeNotInAllowList` Deny 规则,allowlist =
/// `oauth_scopes: ["mcp:tools.read"]`),attach 一个 HTTP mock 上游。
/// `oauth_scopes = Some(...)` → 走 [`Hub::attach_upstream_with_oauth_scopes`];
/// `None` → 普通 [`Hub::attach_upstream`](NonOauth 对照)。
fn setup(oauth_scopes: Option<Vec<String>>) -> (Arc<Ledger>, Arc<Hub>, String) {
    let l = Arc::new(Ledger::open_in_memory().unwrap());

    let mut rules = default_ruleset();
    rules.push(PolicyRule {
        id: SCOPE_RULE_ID.into(),
        match_effects: vec![],
        conditions: vec![Condition::ScopeNotInAllowList {
            allowlist_key: "oauth_scopes".into(),
        }],
        action: PolicyAction::Deny,
        priority: 100,
    });
    let policy = PolicyEngine::new(rules);

    let fw = Arc::new(Firewall::new(
        l.clone(),
        policy,
        FirewallConfig {
            project_roots: vec!["/proj".into()],
            allowed_scopes: HashMap::from([(
                "oauth_scopes".to_string(),
                vec!["mcp:tools.read".to_string()],
            )]),
            ..Default::default()
        },
    ));
    let oracle: Arc<dyn vigil_firewall::scorer::DescriptorOracle> = Arc::new(
        StaticDescriptorOracle(vigil_firewall::scorer::DescriptorStatus::ApprovedStable),
    );
    let hub = Arc::new(Hub::new(
        l.clone(),
        fw,
        oracle,
        HubConfig {
            approval_wait: Duration::from_millis(200),
            ..Default::default()
        },
        vigil_mcp::SecretAliasMap::default(),
    ));

    let profile = ServerProfile {
        server_id: "remote".into(),
        transport: TransportKind::Http,
        command: None,
        url: Some("https://mcp.example.com/rpc".into()),
        first_seen_at: 0,
        command_hash: None,
        descriptor_hash: None,
        trust_level: TrustLevel::Untrusted,
        sandbox_profile_id: None,
    };
    l.register_server(&profile).unwrap();
    l.approve_server("remote", TrustLevel::Limited).unwrap();

    let mock = Arc::new(HttpMockUpstream {
        server_id: "remote".into(),
        canned: Mutex::new(json!({"ok": true})),
    });
    match oauth_scopes {
        Some(scopes) => hub
            .attach_upstream_with_oauth_scopes("remote", &[], mock, scopes)
            .unwrap(),
        None => hub.attach_upstream("remote", &[], mock).unwrap(),
    }

    let session_id = l.start_session("oauth_scope_ctx_test", None).unwrap();
    hub.set_session_id_for_test(&session_id).unwrap();
    hub.inject_route_for_test("remote", "read_file", "hash_abc")
        .unwrap();

    (l, hub, session_id)
}

fn call_tool(hub: &Hub) -> vigil_mcp::protocol::JsonRpcResponse {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: Some(json!(7)),
        method: "tools/call".into(),
        params: Some(json!({ "name": "remote__read_file", "arguments": {} })),
    };
    hub.handle_request(req).unwrap().unwrap()
}

/// 审计里是否出现过 scope 规则 id(decision 事件的 policy_ids 会进 payload)。
fn audit_mentions_scope_rule(l: &Ledger, session_id: &str) -> bool {
    l.replay_session_verified(session_id)
        .unwrap()
        .iter()
        .any(|e| e.payload.to_string().contains(SCOPE_RULE_ID))
}

/// OAuth upstream 的 token scope 越界 allowlist → `ScopeNotInAllowList` Deny 命中,
/// 调用被拒 + 规则 id 进审计(修复前:NonOauth hardcode → 本用例静默放行到后续规则)。
#[test]
fn oauth_scope_out_of_allowlist_denied_at_gateway() {
    let (l, hub, sid) = setup(Some(vec!["admin:org".to_string()]));
    let resp = call_tool(&hub);
    assert!(
        resp.error.is_some(),
        "越界 scope 必须被 deny,实际 result: {:?}",
        resp.result
    );
    assert!(
        audit_mentions_scope_rule(&l, &sid),
        "deny 决策必须携带 {SCOPE_RULE_ID} 进审计"
    );
}

/// OAuth upstream 但 token **零 scope** → 三态语义的 `Some(vec![])` fail-closed 分支:
/// 同样命中 Deny(有规则要求 scope 在 allowlist 内,却连 scope 都没有 → 视同越界)。
#[test]
fn oauth_empty_scope_set_fails_closed() {
    let (l, hub, sid) = setup(Some(vec![]));
    let resp = call_tool(&hub);
    assert!(resp.error.is_some(), "空 scope 集必须 fail-closed deny");
    assert!(audit_mentions_scope_rule(&l, &sid));
}

/// 对照:普通 attach(stdio / Bearer / 无鉴权语义)→ `NonOauth` → scope 规则**不适用**,
/// 绝不因它 deny(本用例最终结局由其它规则决定 —— 断言仅"审计从未出现 scope 规则 id",
/// 证明规则没有被错误地应用到非 OAuth 上游)。
#[test]
fn non_oauth_upstream_scope_rule_not_applicable() {
    let (l, hub, sid) = setup(None);
    let _resp = call_tool(&hub);
    assert!(
        !audit_mentions_scope_rule(&l, &sid),
        "非 OAuth 上游不得触发 {SCOPE_RULE_ID}(NonOauth = 条件不适用)"
    );
}
