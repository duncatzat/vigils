//! 守门:`HubConfig::auto_approve_first_seen_tools` 对 `tools/list` **暴露**的影响。
//!
//! 背景:`vigil-hub wrap`(turnkey)端到端实测发现 —— 用 `false`(serve 默认)时被包裹 server 的
//! `tools/list` **空**,agent 看不到任何工具 = wrap **无用**。wrap 因此改用 `true`(用户在 agent 里
//! 配置该 server 即表达信任,auto-pin 暴露首见 descriptor)。本测试把这一关键集成行为转为 **cargo
//! 回归守门**,防有人改回 false 静默破 turnkey。
//!
//! 关键不变量:`auto_approve_first_seen_tools` **只**影响 descriptor **暴露/批准**(tools/list 侧),
//! **不**影响 call 时 firewall 决策(那条路径 handle_tools_call 独立 evaluate)。drift 仍被排除+审计。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use vigil_audit::Ledger;
use vigil_firewall::scorer::{DescriptorOracle, DescriptorStatus, StaticDescriptorOracle};
use vigil_firewall::{Firewall, FirewallConfig};
use vigil_mcp::protocol::JsonRpcRequest;
use vigil_mcp::upstream::{McpUpstream, UpstreamError};
use vigil_mcp::{Hub, HubConfig};
use vigil_policy::{defaults::default_ruleset, PolicyEngine};
use vigil_types::{ServerProfile, TransportKind, TrustLevel};

/// mock upstream:`tools/list` 返一个工具(echo);其它方法返空。
#[derive(Debug)]
struct ToolsMock(String);
impl McpUpstream for ToolsMock {
    fn server_id(&self) -> &str {
        &self.0
    }
    fn transport(&self) -> TransportKind {
        TransportKind::Stdio
    }
    fn call(&self, method: &str, _p: Option<Value>, _t: Duration) -> Result<Value, UpstreamError> {
        if method == "tools/list" {
            Ok(json!({"tools": [
                {"name": "echo", "description": "echo back", "inputSchema": {"type": "object"}}
            ]}))
        } else {
            Ok(json!({}))
        }
    }
    fn shutdown(&self) {}
}

fn build_hub(auto_approve: bool) -> (Arc<Ledger>, Arc<Hub>) {
    let l = Arc::new(Ledger::open_in_memory().unwrap());
    let policy = PolicyEngine::new(default_ruleset());
    let fw = Arc::new(Firewall::new(l.clone(), policy, FirewallConfig::default()));
    let oracle: Arc<dyn DescriptorOracle> =
        Arc::new(StaticDescriptorOracle(DescriptorStatus::ApprovedStable));
    let hub = Arc::new(Hub::new(
        l.clone(),
        fw,
        oracle,
        HubConfig {
            auto_approve_first_seen_tools: auto_approve,
            upstream_list_timeout: Duration::from_millis(500),
            ..Default::default()
        },
        vigil_mcp::SecretAliasMap::default(),
    ));
    (l, hub)
}

fn register_approve_attach(l: &Ledger, hub: &Hub) {
    // command_hash 用真 argv hash —— 否则 attach_upstream 的 argv-drift gate 会先触发 CommandDrift。
    let argv = ["mock".to_string()];
    let p = ServerProfile {
        server_id: "mock".into(),
        transport: TransportKind::Stdio,
        command: Some(argv.to_vec()),
        url: None,
        first_seen_at: 0,
        command_hash: Some(vigil_audit::argv_hash(&argv)),
        descriptor_hash: None,
        trust_level: TrustLevel::Untrusted,
        sandbox_profile_id: None,
    };
    l.register_server(&p).unwrap();
    l.approve_server("mock", TrustLevel::Limited).unwrap();
    hub.attach_upstream("mock", &argv, Arc::new(ToolsMock("mock".into())))
        .unwrap();
}

fn init(hub: &Hub) {
    let r = hub
        .handle_request(JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(json!(1)),
            method: "initialize".into(),
            params: Some(json!({})),
        })
        .unwrap()
        .unwrap();
    assert!(r.error.is_none());
}

fn list_tools(hub: &Hub) -> Vec<Value> {
    let r = hub
        .handle_request(JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(json!(2)),
            method: "tools/list".into(),
            params: None,
        })
        .unwrap()
        .unwrap();
    r.result
        .unwrap()
        .get("tools")
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn auto_approve_true_exposes_first_seen_tools() {
    // wrap turnkey 路径:auto_approve=true → 首见工具被 auto-pin+批准 → 暴露在 tools/list。
    // 否则 agent 看不到任何工具 = wrap 无用(E2E 实测发现的 turnkey bug)。
    let (l, hub) = build_hub(true);
    init(&hub);
    register_approve_attach(&l, &hub);
    let tools = list_tools(&hub);
    assert_eq!(
        tools.len(),
        1,
        "auto_approve=true 应暴露首见工具;实际 {tools:?}"
    );
    assert!(tools[0]["name"].as_str().unwrap().ends_with("echo"));
}

#[test]
fn auto_approve_false_hides_first_seen_tools() {
    // 对照:auto_approve=false(serve 默认 / 零信任)→ 首见未批准 → tools/list 空(fail-closed)。
    // 这正是 wrap 改 true 之前的行为(turnkey 下 = agent 零工具)。
    let (l, hub) = build_hub(false);
    init(&hub);
    register_approve_attach(&l, &hub);
    let tools = list_tools(&hub);
    assert!(
        tools.is_empty(),
        "auto_approve=false 应隐藏未批准的首见工具;实际 {tools:?}"
    );
}
