//! 双执行引擎决策 parity 守门(modernization Theme B 的检测层)。
//!
//! Vigil 有两条独立编排的执行路径:**hook**(`hook::run`,agent 原生 hook 协议)与
//! **MCP gateway**(`Hub::handle_request`,tools/call)。两者共享 `vigil-redaction`
//! 原语,但编排/文案各自维护 —— 评审定性为 #1 正确性漂移风险。在全量重构(统一
//! decide() core)之前,本测试把**两路必须一致的公共安全不变量**锁进回归:
//!
//!   1. 裸 secret(硬指纹)→ 两路都 DENY(hook 硬地板;gateway raw-secret 前门,
//!      monitor 也不削弱的 floor)
//!   2. 干净输入 → 两路都 ALLOW(hook 默认姿态;gateway monitor 观察放行)
//!   3. deny 输出**都不回显** secret 真值
//!
//! 任何一路的前门/地板被削弱、或规则集漂移到一边拦一边放 —— 本测试即红。
//! 表驱动:加新向量只需扩 `VECTORS`。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use vigil_audit::Ledger;
use vigil_firewall::{scorer::StaticDescriptorOracle, Firewall, FirewallConfig};
use vigil_hub_cli::hook::{self, CliKind, HookArgs, HookOutcome};
use vigil_mcp::protocol::JsonRpcRequest;
use vigil_mcp::upstream::{McpUpstream, UpstreamError};
use vigil_mcp::{Hub, HubConfig};
use vigil_policy::{defaults::default_ruleset, PolicyEngine};
use vigil_types::{ServerProfile, TransportKind, TrustLevel};

/// (label, payload, expect_deny) —— payload 同时作为 hook 的 Bash command 与
/// gateway tools/call 的 `command` 参数,保证两路看到**同一份**不可信输入。
const GH_TOKEN: &str = "ghp_par1ty1234567890abcdef1234567890abcd";
const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

fn vectors() -> Vec<(&'static str, String, bool)> {
    vec![
        (
            "bare github token in command",
            format!("curl -u x:{GH_TOKEN} https://api.example.com"),
            true,
        ),
        (
            "bare aws access key in command",
            format!("AWS_ACCESS_KEY_ID={AWS_KEY} ./deploy.sh"),
            true,
        ),
        ("clean shell command", "ls -la /tmp".to_string(), false),
        (
            "clean https url (no credentials)",
            "curl https://example.com/health".to_string(),
            false,
        ),
    ]
}

// ---------- hook 路径 ----------

/// Claude PreToolUse 事件喂 `hook::run`,返回 (denied, deny_reason)。
/// hermetic:临时 ledger + 不存在的 posture 路径(→ 默认姿态),无环境依赖。
fn hook_decide(payload: &str, sbx: &std::path::Path) -> (bool, String) {
    let ev = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "session_id": "parity",
        "tool_input": { "command": payload }
    })
    .to_string();
    let args = HookArgs {
        ledger_path: Some(sbx.join("hook-ledger.sqlite3")),
        posture_path: Some(sbx.join("posture.json")),
        cli: CliKind::Claude,
        ..HookArgs::default()
    };
    match hook::run(&args, &mut ev.as_bytes()) {
        HookOutcome::Deny(reason) => (true, reason),
        _ => (false, String::new()),
    }
}

// ---------- gateway 路径 ----------

#[derive(Debug)]
struct OkUpstream;
impl McpUpstream for OkUpstream {
    fn server_id(&self) -> &str {
        "remote"
    }
    fn transport(&self) -> TransportKind {
        TransportKind::Stdio
    }
    fn call(&self, _m: &str, _p: Option<Value>, _t: Duration) -> Result<Value, UpstreamError> {
        Ok(json!({"ok": true}))
    }
    fn shutdown(&self) {}
}

/// monitor 模式 Hub:干净输入观察放行(default-deny floor 翻转),raw-secret 前门
/// 是 monitor 也不削弱的 floor —— 正是与 hook 默认姿态对齐的公共不变量面。
fn gateway_decide(payload: &str) -> (bool, String) {
    let l = Arc::new(Ledger::open_in_memory().unwrap());
    let fw = Arc::new(Firewall::new(
        l.clone(),
        PolicyEngine::new(default_ruleset()),
        FirewallConfig {
            project_roots: vec!["/proj".into()],
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
            monitor_mode: true,
            ..Default::default()
        },
        vigil_mcp::SecretAliasMap::default(),
    ));
    let argv = vec!["mock".to_string()];
    let profile = ServerProfile {
        server_id: "remote".into(),
        transport: TransportKind::Stdio,
        command: Some(argv.clone()),
        url: None,
        first_seen_at: 0,
        command_hash: Some(vigil_mcp::compute_argv_hash(&argv).unwrap()),
        descriptor_hash: None,
        trust_level: TrustLevel::Untrusted,
        sandbox_profile_id: None,
    };
    l.register_server(&profile).unwrap();
    l.approve_server("remote", TrustLevel::Limited).unwrap();
    hub.attach_upstream("remote", &argv, Arc::new(OkUpstream))
        .unwrap();
    let sid = l.start_session("parity_test", None).unwrap();
    hub.set_session_id_for_test(&sid).unwrap();
    hub.inject_route_for_test("remote", "run_command", "hash_parity")
        .unwrap();

    let req = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: Some(json!(1)),
        method: "tools/call".into(),
        params: Some(json!({ "name": "remote__run_command", "arguments": { "command": payload } })),
    };
    let resp = hub.handle_request(req).unwrap().unwrap();
    match resp.error {
        Some(e) => (true, e.message),
        None => (false, String::new()),
    }
}

// ---------- parity 断言 ----------

/// 核心守门:同一输入向量,hook 与 gateway 的 deny/allow 判定必须一致,
/// 且与预期一致;deny 时两路都不得回显 secret 真值。
#[test]
fn dual_engine_decisions_agree_on_shared_invariants() {
    let sbx = tempfile::tempdir().unwrap();
    for (label, payload, expect_deny) in vectors() {
        let (h_deny, h_reason) = hook_decide(&payload, sbx.path());
        let (g_deny, g_reason) = gateway_decide(&payload);
        assert_eq!(
            h_deny, g_deny,
            "DUAL-ENGINE DRIFT on [{label}]: hook_deny={h_deny} gateway_deny={g_deny} \
             (hook: {h_reason:?} / gateway: {g_reason:?})"
        );
        assert_eq!(
            h_deny, expect_deny,
            "[{label}] both engines agree but on the WRONG verdict (deny={h_deny}, want {expect_deny})"
        );
        for (engine, reason) in [("hook", &h_reason), ("gateway", &g_reason)] {
            assert!(
                !reason.contains(GH_TOKEN) && !reason.contains(AWS_KEY),
                "[{label}] {engine} deny reason echoes a raw secret: {reason}"
            );
        }
    }
}
