//! ISS-016 post-exec leak scan 集成测试。
//!
//! 验证 `Hub::handle_request("tools/call")` 走完 firewall + scope 快路径后,
//! 在 `invoke_upstream` 的 `Ok(result)` 分支对 upstream response 做 alias-agnostic
//! 硬指纹扫描:
//! - 命中 → `leak_detected_count` +1,写 `secret.leak_detected` 审计事件;默认
//!   (`redact_tool_results=false`)**不改**返给 agent 的 result(out-of-band);
//!   flag 开则 **in-band** 脱敏 result(键+值)再返回(可逆脱敏 Slice 1 hook c)
//! - 未命中 → 计数器不变,无 `secret.leak_detected` 事件
//!
//! 测试用 `MockUpstream` 替代真实 stdio / http transport,直接注入预设 response。

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
use vigil_mcp::{compute_argv_hash, Hub, HubConfig, EVENT_SECRET_LEAK_DETECTED};
use vigil_policy::{defaults::default_ruleset, PolicyEngine};
use vigil_types::{
    ApprovalScope, DecisionKind, DecisionRecord, EffectVector, ServerProfile, TransportKind,
    TrustLevel,
};

/// 预设 response 的 Mock 上游。
#[derive(Debug)]
struct MockUpstream {
    server_id: String,
    /// 调用 `tools/call` 时返回的 JSON。
    canned: Mutex<Value>,
}

impl MockUpstream {
    fn new(server_id: &str, canned: Value) -> Self {
        Self {
            server_id: server_id.to_string(),
            canned: Mutex::new(canned),
        }
    }
}

impl McpUpstream for MockUpstream {
    fn server_id(&self) -> &str {
        &self.server_id
    }
    fn transport(&self) -> TransportKind {
        TransportKind::Stdio
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

/// 构造一个 Hub + ledger + mock upstream,且预先注入一条 ToolRoute + session scope
/// Approved 记录,让 `tools/call` 能直接走 scope 快路径进 `invoke_upstream`。
fn setup_with_mock(canned: Value) -> (Arc<Ledger>, Arc<Hub>, String) {
    setup_with_mock_cfg(canned, false)
}

/// 同 `setup_with_mock`,但可指定 `redact_tool_results`(可逆脱敏 Slice 1:in-band 结果脱敏)。
fn setup_with_mock_cfg(
    canned: Value,
    redact_tool_results: bool,
) -> (Arc<Ledger>, Arc<Hub>, String) {
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

    // 注册并审批 server(command_hash 必须与 argv 实际 hash 对齐,否则 attach_upstream 拒)
    let argv = vec!["mock".to_string()];
    let command_hash = compute_argv_hash(&argv).unwrap();
    let profile = ServerProfile {
        server_id: "fs".into(),
        transport: TransportKind::Stdio,
        command: Some(argv.clone()),
        url: None,
        first_seen_at: 0,
        command_hash: Some(command_hash),
        descriptor_hash: None,
        trust_level: TrustLevel::Untrusted,
        sandbox_profile_id: None,
    };
    l.register_server(&profile).unwrap();
    l.approve_server("fs", TrustLevel::Limited).unwrap();

    // attach mock upstream
    let mock = Arc::new(MockUpstream::new("fs", canned));
    hub.attach_upstream("fs", &argv, mock).unwrap();

    // 注入 session + route,跳过 initialize / tools/list
    let session_id = l.start_session("leak_test", None).unwrap();
    hub.set_session_id_for_test(&session_id).unwrap();
    hub.inject_route_for_test("fs", "read_file", "hash_abc")
        .unwrap();

    // 埋一条 ThisSession approval,匹配 (fs, read_file, args_hash=json!({}) 的 hash)
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
        server_id: Some("fs"),
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
        params: Some(json!({
            "name": "fs__read_file",
            "arguments": {}
        })),
    };
    hub.handle_request(req).unwrap().unwrap()
}

/// ISS-016-A:upstream response 含 ghp_ github token → post-exec scan 命中 →
/// `leak_detected_count` == 1,审计里有 `secret.leak_detected` 事件。
#[test]
fn post_exec_leak_scan_detects_secret_in_upstream_response() {
    let canned = json!({
        "content": "here is your token: ghp_1234567890abcdef1234567890abcdef12345678",
        "ok": true
    });
    let (l, hub, session_id) = setup_with_mock(canned);

    assert_eq!(hub.leak_detected_count(), 0);
    let resp = call_tool(&hub);
    assert!(resp.error.is_none(), "upstream 正常返 Ok,不应走 error 分支");

    assert_eq!(
        hub.leak_detected_count(),
        1,
        "post-exec scan 命中应 +1 计数器"
    );

    let events = l.replay_session_verified(&session_id).unwrap();
    let leak_evt = events
        .iter()
        .find(|e| e.event_type == EVENT_SECRET_LEAK_DETECTED);
    assert!(
        leak_evt.is_some(),
        "必须产生 secret.leak_detected 审计事件,实际事件: {:?}",
        events.iter().map(|e| &e.event_type).collect::<Vec<_>>()
    );
    // payload 应含 rule 名(已脱敏,但 rule 名 `github_token` 本身不含 secret)
    let evt = leak_evt.unwrap();
    let rule = evt.payload.get("rule").and_then(Value::as_str);
    assert_eq!(rule, Some("github_token"));
}

/// ISS-016-B:upstream response 完全干净 → 计数器不变,无 `secret.leak_detected` 事件。
#[test]
fn post_exec_leak_scan_clean_response_no_event() {
    let canned = json!({"content": "clean readme content", "bytes": 42});
    let (l, hub, session_id) = setup_with_mock(canned);

    assert_eq!(hub.leak_detected_count(), 0);
    let resp = call_tool(&hub);
    assert!(resp.error.is_none());

    assert_eq!(hub.leak_detected_count(), 0, "干净 response 不应增计数器");

    let events = l.replay_session_verified(&session_id).unwrap();
    assert!(
        events
            .iter()
            .all(|e| e.event_type != EVENT_SECRET_LEAK_DETECTED),
        "干净 response 不应产 secret.leak_detected 事件"
    );
}

/// ISS-016-C:命中 leak 时**不改**返给 agent 的 result(out-of-band 设计保证 MCP
/// 协议透明;agent 拿到的 JSON 与 upstream 返的完全一致)。
#[test]
fn post_exec_leak_does_not_modify_response_to_agent() {
    let canned = json!({
        "content": "leaked: ghp_1234567890abcdef1234567890abcdef12345678",
        "ok": true
    });
    let (_l, hub, _sid) = setup_with_mock(canned.clone());

    let resp = call_tool(&hub);
    assert!(resp.error.is_none());
    // result 应与 canned 逐字节相等(序列化层已透传)
    let result = resp.result.as_ref().unwrap();
    assert_eq!(
        serde_json::to_string(result).unwrap(),
        serde_json::to_string(&canned).unwrap(),
        "post-exec leak 是 out-of-band,不得改变返给 agent 的 result"
    );
    // 计数器证明扫描确实跑了
    assert_eq!(hub.leak_detected_count(), 1);
}

/// 可逆脱敏 Slice 1:`redact_tool_results=true` 时,命中 leak 的 result 被 **in-band** 脱敏后
/// 才返回 agent —— 原始 ghp_ token 不再出现在返给 agent 的 result 里(堵住工具输出把 secret
/// 回吐给远端 LLM)。与 Test C(默认 out-of-band 不改 result)构成正反对照。
#[test]
fn post_exec_leak_redacts_response_when_flag_on() {
    let raw = "ghp_1234567890abcdef1234567890abcdef12345678";
    let canned = json!({
        "content": format!("leaked: {raw}"),
        "ok": true
    });
    let (_l, hub, _sid) = setup_with_mock_cfg(canned, true);

    let resp = call_tool(&hub);
    assert!(resp.error.is_none(), "upstream 正常返 Ok");
    let result = resp.result.as_ref().unwrap();
    let result_str = serde_json::to_string(result).unwrap();

    // 核心:原始 token 不得出现在返给 agent 的 result 里
    assert!(
        !result_str.contains(raw),
        "redact_tool_results=true 时 result 不得含原始 secret,实际: {result_str}"
    );
    // 应被占位符化(redact 产 [REDACTED ...])
    assert!(
        result_str.contains("[REDACTED"),
        "result 应含 [REDACTED ...] 占位符,实际: {result_str}"
    );
    // 扫描仍跑了(计数器 +1);非敏感字段 "ok" 仍在
    assert_eq!(hub.leak_detected_count(), 1);
    assert!(
        result_str.contains("\"ok\""),
        "非敏感字段应保留: {result_str}"
    );
}

/// Codex review NEEDS-FIX 回归:secret 落在 JSON **key 位** 时也必须被脱敏。
/// `redact(&Value)` 只脱敏 object **值**、保留键,会漏 key 位 secret;Hub 改用序列化串
/// `scrub_text` 重解析覆盖键位。flag 开时,key 位原始 token 不得出现在返给 agent 的 result。
#[test]
fn post_exec_leak_redacts_secret_in_object_key_when_flag_on() {
    let raw = "ghp_1234567890abcdef1234567890abcdef12345678";
    // secret 作为 object KEY(而非 value)
    let mut obj = serde_json::Map::new();
    obj.insert(raw.to_string(), json!("ok"));
    obj.insert("note".to_string(), json!("v"));
    let canned = Value::Object(obj);

    let (_l, hub, _sid) = setup_with_mock_cfg(canned, true);
    let resp = call_tool(&hub);
    assert!(resp.error.is_none());
    let result_str = serde_json::to_string(resp.result.as_ref().unwrap()).unwrap();
    assert!(
        !result_str.contains(raw),
        "key 位 secret 也不得透传给 agent,实际: {result_str}"
    );
    assert_eq!(hub.leak_detected_count(), 1);
}

/// Vigil×AURA 交叉测试(2026-09-11)回归:真实 MCP server 的 tool result 是 `content[].text` 里
/// **再序列化**的 JSON(含 `\r\n` 转义;AURA `run_command` 即如此)。旧实现对 JCS 文本 scrub 吞掉
/// 转义反斜杠 → 重解析失败 → 返回 `{"vigil_redacted":…}` 裸对象 —— 不是合法 CallToolResult,
/// Codex 报 "Unexpected response type",守门变成了工具故障。现在:返给 agent 的 result 必须仍是
/// `content[]` 形状、内层 JSON 仍可解析、token 消失、占位符在、不是协议错误。
#[test]
fn post_exec_leak_redaction_keeps_call_tool_result_shape_for_reserialized_json() {
    let raw = "ghp_1234567890abcdef1234567890abcdef12345678";
    let inner = format!(
        "{{\"data\":{{\"exit_code\":0,\"stdout\":\"[github]\\r\\ntoken={raw}\\r\\nregion=us-east-1\\r\\n\"}},\"ok\":true}}"
    );
    let canned = json!({
        "content": [{ "type": "text", "text": inner }],
        "structuredContent": { "data": { "stdout": format!("[github]\r\ntoken={raw}\r\n") } },
        "isError": false
    });
    let (_l, hub, _sid) = setup_with_mock_cfg(canned, true);
    let resp = call_tool(&hub);
    assert!(
        resp.error.is_none(),
        "a governance redaction must not surface as a protocol error"
    );
    let result = resp.result.as_ref().unwrap();
    let result_str = serde_json::to_string(result).unwrap();
    assert!(
        !result_str.contains(raw),
        "token must not reach the agent: {result_str}"
    );
    assert!(
        result.get("vigil_redacted").is_none(),
        "no bare placeholder object: {result_str}"
    );
    let content = result["content"]
        .as_array()
        .expect("content[] must survive redaction");
    assert_eq!(content[0]["type"], "text");
    let text = content[0]["text"].as_str().unwrap();
    assert!(
        text.contains("[REDACTED"),
        "placeholder inside the text: {text}"
    );
    assert!(
        serde_json::from_str::<Value>(text).is_ok(),
        "inner JSON must still parse after in-place scrubbing: {text}"
    );
    assert_eq!(result["isError"], false);
    assert_eq!(hub.leak_detected_count(), 1);
}
