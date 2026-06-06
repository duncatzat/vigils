//! D2 monitor posture 守门(Codex wrap R1 MEDIUM):`HubConfig::monitor_mode` 开启时,
//! 本应人审批(`FirewallOutcome::Approve`)的风险调用被**自动放行 + 完整审计**且**不阻塞**;
//! 关闭时(enforce)无 resolver 仍阻塞至超时 deny。
//!
//! 构造:注入一条 catch-all `Approve` policy 规则,让任意工具调用都路由到 Approve(等价
//! turnkey 场景里风险工具会撞上的人审批路径),再对照 monitor on/off 的终态:
//! - monitor on  → 到达 `invoke_upstream`(无 attach 上游故返 `UPSTREAM_UNAVAILABLE`,
//!   **证明被放行而非阻塞/deny**)+ 账本有 `approval.resolved{resolved_by="vigil-monitor-mode"}`
//! - monitor off → 阻塞 `wait_for_resolution`(测试 200ms)无人解决 → `APPROVAL_REJECTED`(超时)

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use vigil_audit::Ledger;
use vigil_firewall::scorer::{DescriptorOracle, DescriptorStatus, StaticDescriptorOracle};
use vigil_firewall::{Firewall, FirewallConfig};
use vigil_mcp::protocol::{JsonRpcError, JsonRpcRequest};
use vigil_mcp::upstream::{McpUpstream, UpstreamError};
use vigil_mcp::{Hub, HubConfig};
use vigil_policy::{defaults::default_ruleset, PolicyAction, PolicyEngine, PolicyRule};
use vigil_types::TransportKind;

/// 建一个带 catch-all `Approve` 规则的 Hub —— 任意无特定风险规则匹配的工具都路由到人审批路径。
/// `monitor` 控制被测的 `HubConfig::monitor_mode`。复用给三个测试(共享/文件账本均可)。
fn build_approve_hub(l: &Arc<Ledger>, monitor: bool) -> Arc<Hub> {
    let mut policy = PolicyEngine::new(default_ruleset());
    // catch-all → Approve(最低优先级):无特定风险规则匹配的工具一律走人审批路径,
    // 等价 dev_permissive_firewall 的兜底,稳定触发 `FirewallOutcome::Approve`。
    policy.add_rule(PolicyRule {
        id: "test-catchall-approve".into(),
        match_effects: vec![],
        conditions: vec![],
        action: PolicyAction::Approve,
        priority: 1,
    });
    let fw = Arc::new(Firewall::new(l.clone(), policy, FirewallConfig::default()));
    let oracle: Arc<dyn DescriptorOracle> =
        Arc::new(StaticDescriptorOracle(DescriptorStatus::ApprovedStable));
    Arc::new(Hub::new(
        l.clone(),
        fw,
        oracle,
        HubConfig {
            // 短 approval_wait:enforce 对照路径无 resolver 时快速超时(不等默认 300s)。
            approval_wait: Duration::from_millis(200),
            upstream_call_timeout: Duration::from_millis(500),
            monitor_mode: monitor,
            ..Default::default()
        },
        vigil_mcp::SecretAliasMap::default(),
    ))
}

fn setup_approve_hub(monitor: bool) -> (Arc<Ledger>, Arc<Hub>, String) {
    let l = Arc::new(Ledger::open_in_memory().unwrap());
    let hub = build_approve_hub(&l, monitor);
    let session = l.start_session("monitor_test", None).unwrap();
    hub.set_session_id_for_test(session.clone()).unwrap();
    // 注入一条 route(避开真实 tools/list / 上游);工具名取中性的 "compute" 避免撞特定风险规则。
    hub.inject_route_for_test("calc", "compute", "hash_abc")
        .unwrap();
    (l, hub, session)
}

fn call_compute(hub: &Hub) -> vigil_mcp::protocol::JsonRpcResponse {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: Some(json!(1)),
        method: "tools/call".into(),
        params: Some(json!({
            "name": "calc__compute",
            "arguments": {"x": 1},
        })),
    };
    hub.handle_request(req).unwrap().unwrap()
}

#[test]
fn monitor_mode_auto_allows_approve_and_audits() {
    let (l, hub, session) = setup_approve_hub(true);
    let resp = call_compute(&hub);

    // 关键 1:被**放行**到 invoke_upstream(未阻塞、未 deny)。无 attach 上游 → upstream_unavailable。
    assert_eq!(
        resp.error.as_ref().unwrap().code,
        JsonRpcError::VIGIL_UPSTREAM_UNAVAILABLE,
        "monitor 模式应把 Approve 降级放行,一路到 invoke_upstream;实际 resp={resp:?}"
    );

    // 关键 2:审计链如实记录 —— approval 被创建,且由 `vigil-monitor-mode` 自动解决。
    let events = l.replay_session_verified(&session).unwrap();
    assert!(
        events.iter().any(|e| e.event_type == "approval.created"),
        "应创建 approval(firewall 判定 Approve)"
    );
    assert!(
        events.iter().any(|e| e.event_type == "approval.resolved"
            && e.payload.get("resolved_by").and_then(|v| v.as_str()) == Some("vigil-monitor-mode")),
        "approval 应由 vigil-monitor-mode 自动解决(完整审计,非静默放行)"
    );
}

#[test]
fn enforce_mode_blocks_approve_until_timeout() {
    // 对照:monitor off 时,同一 Approve 路径无 resolver → 阻塞至 200ms 超时 deny。
    let (_l, hub, _session) = setup_approve_hub(false);
    let resp = call_compute(&hub);
    assert_eq!(
        resp.error.as_ref().unwrap().code,
        JsonRpcError::VIGIL_APPROVAL_REJECTED,
        "enforce 模式无 resolver 应阻塞至超时 deny(与 monitor 对照);实际 resp={resp:?}"
    );
}

#[derive(Debug)]
struct NoopUpstream(String);
impl McpUpstream for NoopUpstream {
    fn server_id(&self) -> &str {
        &self.0
    }
    fn transport(&self) -> TransportKind {
        TransportKind::Stdio
    }
    fn call(&self, _m: &str, _p: Option<Value>, _t: Duration) -> Result<Value, UpstreamError> {
        Ok(json!({}))
    }
    fn shutdown(&self) {}
}

/// Codex D2 review finding 守门:monitor 模式**不得**因非阻塞就跳过 outbox 控制面。
/// 含 `url` 参数的调用 → `NetOutbound` 效应 → default_ruleset 路由到 Approve →
/// 应 draft outbox。monitor 须 draft+submit→标 approved→传 outbox_id 进 invoke_upstream
/// (NoopUpstream 成功 → mark_outbox_executed)。验证账本里恰一条 outbox 且走完终态。
#[test]
fn monitor_mode_preserves_outbox_for_outbound_effects() {
    // 文件账本:用第二个 rusqlite 连接直接查 outbox_items(Hub 内部不暴露 outbox_id)。
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_path_buf();
    let l = Arc::new(Ledger::open(&path).unwrap());
    let hub = build_approve_hub(&l, true);
    let session = l.start_session("monitor_outbox_test", None).unwrap();
    hub.set_session_id_for_test(session.clone()).unwrap();
    hub.inject_route_for_test("net", "fetch", "hash_net")
        .unwrap();
    // 真 mock 上游:让 invoke_upstream 成功 → outbox 走到 Executed 终态。
    hub.attach_upstream(
        "net",
        &["mock".to_string()],
        Arc::new(NoopUpstream("net".into())),
    )
    .unwrap();

    // url 参数 → NetOutbound 效应 → Approve → monitor 自动放行 + 保留 outbox。
    let req = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: Some(json!(1)),
        method: "tools/call".into(),
        params: Some(json!({
            "name": "net__fetch",
            "arguments": {"url": "https://example.com/x"},
        })),
    };
    let resp = hub.handle_request(req).unwrap().unwrap();
    assert!(
        resp.error.is_none(),
        "monitor + NoopUpstream 应成功放行出站调用(非阻塞);实际 resp={resp:?}"
    );

    // 第二连接查 outbox_items:恰一条,走 draft→approved(monitor 自动)→executed 终态。
    let conn = rusqlite::Connection::open(&path).unwrap();
    let (count, status): (i64, String) = conn
        .query_row(
            "SELECT COUNT(*), COALESCE(MAX(status), '') FROM outbox_items WHERE session_id = ?1",
            [&session],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        count, 1,
        "monitor 模式 NetOutbound 调用必须创建 outbox(不能因非阻塞跳过出站控制面)"
    );
    assert_eq!(
        status, "Executed",
        "outbox 应走 draft→approved(monitor 自动)→executed 终态;实际 {status}"
    );
}

/// Codex audit MEDIUM 守门:approved outbox 不得因 `invoke_upstream` **pre-call 早返**(上游缺失)
/// 而悬挂在 Approved。monitor 标 outbox approved 后调 invoke_upstream,上游未 attach → 早返时
/// 须 finalize 为 Failed。
#[test]
fn monitor_mode_finalizes_outbox_when_upstream_missing() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_path_buf();
    let l = Arc::new(Ledger::open(&path).unwrap());
    let hub = build_approve_hub(&l, true);
    let session = l.start_session("monitor_outbox_fail_test", None).unwrap();
    hub.set_session_id_for_test(session.clone()).unwrap();
    hub.inject_route_for_test("net", "fetch", "hash_net")
        .unwrap();
    // **不** attach 上游 → invoke_upstream 在真正调用前早返 UPSTREAM_UNAVAILABLE。

    let req = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: Some(json!(1)),
        method: "tools/call".into(),
        params: Some(json!({
            "name": "net__fetch",
            "arguments": {"url": "https://example.com/x"},
        })),
    };
    let resp = hub.handle_request(req).unwrap().unwrap();
    assert_eq!(
        resp.error.as_ref().unwrap().code,
        JsonRpcError::VIGIL_UPSTREAM_UNAVAILABLE,
        "上游未 attach 应早返 UPSTREAM_UNAVAILABLE;实际 resp={resp:?}"
    );

    let conn = rusqlite::Connection::open(&path).unwrap();
    let (count, status): (i64, String) = conn
        .query_row(
            "SELECT COUNT(*), COALESCE(MAX(status), '') FROM outbox_items WHERE session_id = ?1",
            [&session],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(count, 1, "应创建 outbox");
    assert_eq!(
        status, "Failed",
        "approved outbox 在 pre-call 早返时必须 finalize 为 Failed,不得悬挂 Approved;实际 {status}"
    );
}

/// F2 守门(Codex holistic + 真实-server E2E 发现):monitor 模式把 **default-deny FLOOR**
/// (无规则匹配的未分类工具,如第三方 MCP server 的 read_file —— effect 提取器不认其工具名)
/// 降级为「观察放行」,使被包裹的真实 server **开箱可用**;enforce 仍 deny。**只翻 floor**。
/// 不注入 catch-all,用 default_ruleset + 中性工具(无 effect)稳定撞 default-deny。
fn build_plain_hub(l: &Arc<Ledger>, monitor: bool) -> Arc<Hub> {
    let policy = PolicyEngine::new(default_ruleset()); // 无 catch-all → 中性工具撞 default-deny
    let fw = Arc::new(Firewall::new(l.clone(), policy, FirewallConfig::default()));
    let oracle: Arc<dyn DescriptorOracle> =
        Arc::new(StaticDescriptorOracle(DescriptorStatus::ApprovedStable));
    Arc::new(Hub::new(
        l.clone(),
        fw,
        oracle,
        HubConfig {
            approval_wait: Duration::from_millis(200),
            upstream_call_timeout: Duration::from_millis(500),
            monitor_mode: monitor,
            ..Default::default()
        },
        vigil_mcp::SecretAliasMap::default(),
    ))
}

#[test]
fn monitor_mode_allows_default_deny_floor() {
    // 中性工具(无 url/path,无 effect)→ 无规则匹配 → default-deny floor。monitor 应降级放行
    // → 一路到 invoke_upstream(NoopUpstream 成功 → resp 无 error)。这是 wrap 真实 server 可用的关键。
    let l = Arc::new(Ledger::open_in_memory().unwrap());
    let hub = build_plain_hub(&l, true);
    let session = l.start_session("monitor_floor_test", None).unwrap();
    hub.set_session_id_for_test(session.clone()).unwrap();
    hub.inject_route_for_test("calc", "compute", "hash_abc")
        .unwrap();
    hub.attach_upstream(
        "calc",
        &["mock".to_string()],
        Arc::new(NoopUpstream("calc".into())),
    )
    .unwrap();

    let resp = call_compute(&hub);
    assert!(
        resp.error.is_none(),
        "monitor 应把 default-deny floor 降级放行到 invoke_upstream;实际 resp={resp:?}"
    );
    // 审计诚实:override 记一条 vigil-monitor-mode 的决策(非"deny 后却执行")。
    let events = l.replay_session_verified(&session).unwrap();
    assert!(
        events.iter().any(|e| e
            .payload
            .get("policy_ids")
            .map(|v| v.to_string().contains("vigil-monitor-mode"))
            .unwrap_or(false)),
        "monitor floor 放行须记一条 vigil-monitor-mode 决策入审计链(诚实);events={events:?}"
    );
}

#[test]
fn enforce_mode_denies_default_deny_floor() {
    // 对照:enforce(monitor off)下 default-deny floor 仍 deny —— F2 只动 monitor,enforce 不变。
    let l = Arc::new(Ledger::open_in_memory().unwrap());
    let hub = build_plain_hub(&l, false);
    let session = l.start_session("enforce_floor_test", None).unwrap();
    hub.set_session_id_for_test(session).unwrap();
    hub.inject_route_for_test("calc", "compute", "hash_abc")
        .unwrap();
    let resp = call_compute(&hub);
    assert_eq!(
        resp.error.as_ref().unwrap().code,
        JsonRpcError::VIGIL_DENIED,
        "enforce 下 default-deny floor 必须仍 deny;实际 resp={resp:?}"
    );
}
