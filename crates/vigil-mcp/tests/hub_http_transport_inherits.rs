//! ADR 0021 §5 Slice 1 验收 item #3 的 HTTP-传输专项:**传输无关不变量对 `TransportKind::Http`
//! 上游同样生效**。
//!
//! `Hub::invoke_upstream` 在 `upstream.call()` **之后**做 alias-agnostic 硬指纹 leak 扫描 +
//! (flag 开时)in-band 结果脱敏。该 seam **不读 `upstream.transport()`** —— 故对 stdio / http
//! 行为应完全一致。本文件用一个 `transport() == Http` 的 mock 上游把这条"传输无关"锁进回归测试:
//! 若将来有人误加 `if transport == Http { skip_scan }`(例如"HTTP 已 TLS,无需再扫"的错误优化),
//! 这两个测试即破。
//!
//! 与 `hub_leak_scan.rs`(stdio mock)构成同断言、异传输的正交对照;复用其 mock/seed 形态,
//! 唯一差异是 `transport()=Http` + Http server profile(`command=None` / `url=Some` /
//! `command_hash=None`,与 `serve.rs::attach_http_upstream` 的真实 attach 口径一致)。

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::err_expect,
    clippy::panic
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use vigil_audit::Ledger;
use vigil_firewall::{scorer::StaticDescriptorOracle, Firewall, FirewallConfig};
use vigil_mcp::protocol::JsonRpcRequest;
use vigil_mcp::upstream::{McpUpstream, UpstreamError};
use vigil_mcp::{Hub, HubConfig, EVENT_SECRET_LEAK_DETECTED};
use vigil_policy::{defaults::default_ruleset, PolicyEngine};
use vigil_types::{
    ApprovalScope, DecisionKind, DecisionRecord, EffectVector, ServerProfile, TransportKind,
    TrustLevel,
};

/// 预设 response 的 Mock 上游,**报告 `transport()=Http`** —— 用来证明 Hub 的 post-exec
/// 结果处理 seam 对 HTTP 上游与 stdio 一视同仁。(上游确实被调到由 `leak_detected_count()==1`
/// 间接证明:扫描跑在 upstream 返回的 result 上。)
#[derive(Debug)]
struct HttpMockUpstream {
    server_id: String,
    canned: Mutex<Value>,
}

impl HttpMockUpstream {
    fn new(server_id: &str, canned: Value) -> Self {
        Self {
            server_id: server_id.to_string(),
            canned: Mutex::new(canned),
        }
    }
}

impl McpUpstream for HttpMockUpstream {
    fn server_id(&self) -> &str {
        &self.server_id
    }
    fn transport(&self) -> TransportKind {
        TransportKind::Http // ← 与 hub_leak_scan.rs 的 stdio mock 的唯一实质差异
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

/// 装 Hub + ledger + **HTTP** mock 上游,预埋 route + ThisSession approval 让 `tools/call` 走 scope
/// 快路径直达 `invoke_upstream`。Server profile 按 HTTP attach 的真实口径:`command=None` /
/// `url=Some` / `command_hash=None`,且 `attach_upstream(name, &[], ..)`(空 argv,drift gate no-op)。
fn setup_http_mock(canned: Value, redact_tool_results: bool) -> (Arc<Ledger>, Arc<Hub>, String) {
    let l = Arc::new(Ledger::open_in_memory().unwrap());
    let policy = PolicyEngine::new(default_ruleset());
    let fw = Arc::new(Firewall::new(
        l.clone(),
        policy,
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
            redact_tool_results,
            ..Default::default()
        },
        vigil_mcp::SecretAliasMap::default(),
    ));

    // HTTP server profile(口径同 serve.rs::attach_http_upstream)。
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

    // attach HTTP mock(空 argv,与真实 HTTP attach 一致)。
    let mock = Arc::new(HttpMockUpstream::new("remote", canned));
    hub.attach_upstream("remote", &[], mock).unwrap();

    // 注入 session + route,跳过 initialize / tools/list。
    let session_id = l.start_session("http_inherit_test", None).unwrap();
    hub.set_session_id_for_test(&session_id).unwrap();
    hub.inject_route_for_test("remote", "read_file", "hash_abc")
        .unwrap();

    // 埋一条 ThisSession approval,匹配 (remote, read_file, hash(json!({})))。
    let args = json!({});
    let args_hash = {
        let b = serde_jcs::to_vec(&args).unwrap();
        let mut h = Sha256::new();
        h.update(&b);
        hex::encode(h.finalize())
    };
    let dec = DecisionRecord {
        decision_id: "d-prev".into(),
        invocation_id: "inv-prev".into(),
        decision: DecisionKind::Approve,
        risk_score: 0,
        reasons: vec![],
        policy_ids: vec![],
        created_at: 0,
    };
    let ctx = vigil_audit::ApprovalTargetContext {
        server_id: Some("remote"),
        tool_name: Some("read_file"),
        args_hash: Some(&args_hash),
    };
    let prev = l
        .create_approval(
            &session_id,
            &dec,
            &EffectVector::default(),
            "t",
            "s",
            600,
            ctx,
        )
        .unwrap();
    l.approve(&prev.approval_id, ApprovalScope::ThisSession, Some("u"))
        .unwrap();

    (l, hub, session_id)
}

fn call_tool(hub: &Hub) -> vigil_mcp::protocol::JsonRpcResponse {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: Some(json!(42)),
        method: "tools/call".into(),
        params: Some(json!({ "name": "remote__read_file", "arguments": {} })),
    };
    hub.handle_request(req).unwrap().unwrap()
}

/// HTTP 上游返含 `ghp_` token 的 result → post-exec leak 扫描**对 HTTP 同样命中** →
/// 计数器 +1 + `secret.leak_detected` 审计事件(证扫描 seam 不因传输是 Http 而跳过)。
#[test]
fn http_transport_upstream_leak_detected_and_audited() {
    let canned = json!({
        "content": "here is your token: ghp_1234567890abcdef1234567890abcdef12345678",
        "ok": true
    });
    let (l, hub, session_id) = setup_http_mock(canned, false);

    assert_eq!(hub.leak_detected_count(), 0);
    let resp = call_tool(&hub);
    assert!(resp.error.is_none(), "HTTP 上游正常返 Ok,不应走 error 分支");

    assert_eq!(
        hub.leak_detected_count(),
        1,
        "HTTP 上游 result 的 post-exec leak 扫描应命中(传输无关)"
    );
    let events = l.replay_session_verified(&session_id).unwrap();
    assert!(
        events
            .iter()
            .any(|e| e.event_type == EVENT_SECRET_LEAK_DETECTED),
        "HTTP 上游也必须产 secret.leak_detected 审计事件,实际: {:?}",
        events.iter().map(|e| &e.event_type).collect::<Vec<_>>()
    );
}

/// `redact_tool_results=true` 时,HTTP 上游 result 里的原始 `ghp_` token **同样**被 in-band
/// 脱敏后才返 agent —— 证 ADR 0021 §1.3"redaction 传输无关"对 HTTP 成立(堵 HTTP 工具输出
/// 把 secret 回吐给远端 LLM)。
#[test]
fn http_transport_upstream_result_redacted_when_flag_on() {
    let raw = "ghp_1234567890abcdef1234567890abcdef12345678";
    let canned = json!({ "content": format!("leaked: {raw}"), "ok": true });
    let (_l, hub, _sid) = setup_http_mock(canned, true);

    let resp = call_tool(&hub);
    assert!(resp.error.is_none());
    let result_str = serde_json::to_string(resp.result.as_ref().unwrap()).unwrap();

    assert!(
        !result_str.contains(raw),
        "HTTP 上游 result 不得把原始 secret 透传给 agent,实际: {result_str}"
    );
    assert!(
        result_str.contains("[REDACTED"),
        "result 应含 [REDACTED ...] 占位符,实际: {result_str}"
    );
    assert_eq!(hub.leak_detected_count(), 1);
    assert!(
        result_str.contains("\"ok\""),
        "非敏感字段应保留: {result_str}"
    );
}
