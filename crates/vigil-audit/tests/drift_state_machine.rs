//! I05 drift 状态机 + re-approval API 回归(ADR 0005 §D1 §D2 §D4)。
//!
//! 覆盖:
//! - pin_tool_descriptor 的三态:FirstSeen / Unchanged / Drifted
//! - approve_tool_descriptor_to:drift → approved 转换
//! - reject_tool_descriptor_drift:保留旧 hash 清 pending
//! - check_server_command_drift:equal / drift / 无 server
//! - approve_server_command_drift / reject_server_command_drift
//! - list_pending_tool_approvals / list_drifted_tools / list_pending_server_onboardings / list_drifted_servers
//! - §12.3 I05-3 descriptor 变化触发再审批
//! - §12.3 I05-4 command hash 变化触发再审批

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::err_expect,
    clippy::panic
)]

use vigil_audit::{
    argv_hash, AuditError, CommandDrift, Ledger, PinOutcome, ResolvedProgramDrift,
    ResolvedProgramOutcome,
};
use vigil_types::{ServerProfile, TransportKind, TrustLevel};

fn setup() -> Ledger {
    Ledger::open_in_memory().unwrap()
}

fn argv_v1() -> Vec<String> {
    vec!["uvx".into(), "mcp-server-fs".into(), "/proj".into()]
}

fn argv_v2() -> Vec<String> {
    vec!["uvx".into(), "mcp-server-fs".into(), "/new".into()]
}

fn register_fs_server(l: &Ledger) {
    let argv = argv_v1();
    let hash = argv_hash(&argv);
    l.register_server(&ServerProfile {
        server_id: "fs".into(),
        transport: TransportKind::Stdio,
        command: Some(argv),
        url: None,
        first_seen_at: 0,
        command_hash: Some(hash),
        descriptor_hash: None,
        trust_level: TrustLevel::Untrusted,
        sandbox_profile_id: None,
    })
    .unwrap();
}

#[test]
fn pin_outcome_first_seen_then_unchanged() {
    let l = setup();
    let o1 = l.pin_tool_descriptor("fs", "read", "h1").unwrap();
    assert!(matches!(o1, PinOutcome::FirstSeen));
    let o2 = l.pin_tool_descriptor("fs", "read", "h1").unwrap();
    assert!(matches!(o2, PinOutcome::Unchanged));
}

/// §12.3 I05-3:descriptor 变化触发再审批
#[test]
fn pin_outcome_drifted_triggers_reapproval() {
    let l = setup();
    l.pin_tool_descriptor("fs", "read", "h1").unwrap();
    l.approve_tool_descriptor("fs", "read").unwrap();
    // 上游改 schema → 新 hash
    let o = l.pin_tool_descriptor("fs", "read", "h2").unwrap();
    match o {
        PinOutcome::Drifted { old, new } => {
            assert_eq!(old, "h1");
            assert_eq!(new, "h2");
        }
        other => panic!("期望 Drifted,得到 {:?}", other),
    }
    // drifted 列表出现该 tool
    let drifted = l.list_drifted_tools().unwrap();
    assert_eq!(drifted.len(), 1);
    assert_eq!(drifted[0].proposed_hash.as_deref(), Some("h2"));
}

#[test]
fn approve_drift_to_new_hash_clears_pending() {
    let l = setup();
    l.pin_tool_descriptor("fs", "read", "h1").unwrap();
    l.approve_tool_descriptor("fs", "read").unwrap();
    l.pin_tool_descriptor("fs", "read", "h2").unwrap();
    l.approve_tool_descriptor_to("fs", "read", "h2").unwrap();
    assert!(l.list_drifted_tools().unwrap().is_empty());
    // descriptor_hash 现在是 h2
    let h = l.get_pinned_tool_hash("fs", "read").unwrap();
    assert_eq!(h.as_deref(), Some("h2"));
}

#[test]
fn reject_drift_keeps_old_hash() {
    let l = setup();
    l.pin_tool_descriptor("fs", "read", "h1").unwrap();
    l.approve_tool_descriptor("fs", "read").unwrap();
    l.pin_tool_descriptor("fs", "read", "h2").unwrap();
    l.reject_tool_descriptor_drift("fs", "read").unwrap();
    assert!(l.list_drifted_tools().unwrap().is_empty());
    let h = l.get_pinned_tool_hash("fs", "read").unwrap();
    assert_eq!(h.as_deref(), Some("h1"), "reject 后应保留旧 hash");
}

#[test]
fn approve_to_wrong_hash_fails() {
    let l = setup();
    l.pin_tool_descriptor("fs", "read", "h1").unwrap();
    l.approve_tool_descriptor("fs", "read").unwrap();
    l.pin_tool_descriptor("fs", "read", "h2").unwrap();
    // 尝试批准成 h3(不是 pending 里的 h2)
    assert!(matches!(
        l.approve_tool_descriptor_to("fs", "read", "h3"),
        Err(AuditError::InvalidInput { .. })
    ));
}

/// §12.3 I05-4:command hash 变化触发再审批
#[test]
fn check_command_drift_detects_argv_change() {
    let l = setup();
    register_fs_server(&l);
    let v1 = argv_v1();
    let v2 = argv_v2();
    let h1 = argv_hash(&v1);
    let h2 = argv_hash(&v2);
    // 相同 hash → None
    assert!(l
        .check_server_command_drift("fs", &v1, &h1)
        .unwrap()
        .is_none());
    // 不同 hash → drift
    let d = l
        .check_server_command_drift("fs", &v2, &h2)
        .unwrap()
        .expect("应检测到 drift");
    assert_eq!(
        d,
        CommandDrift {
            old: h1.clone(),
            new: h2.clone(),
        }
    );
    // drifted server 列表
    let drifted = l.list_drifted_servers().unwrap();
    assert_eq!(drifted.len(), 1);
    assert_eq!(
        drifted[0].pending_command_hash.as_deref(),
        Some(h2.as_str())
    );
}

#[test]
fn approve_command_drift_updates_hash_and_argv() {
    let l = setup();
    register_fs_server(&l);
    let v2 = argv_v2();
    let h2 = argv_hash(&v2);
    l.check_server_command_drift("fs", &v2, &h2).unwrap();
    l.approve_server_command_drift("fs").unwrap();
    let p = l.get_server("fs").unwrap().unwrap();
    assert_eq!(p.command_hash.as_deref(), Some(h2.as_str()));
    // I08 R1 BLOCKER:approve 后 command argv 也更新为 pending argv
    assert_eq!(p.command, Some(v2));
    assert!(p.pending_command_hash.is_none());
    assert!(l.list_drifted_servers().unwrap().is_empty());
}

#[test]
fn reject_command_drift_keeps_old_hash() {
    let l = setup();
    register_fs_server(&l);
    let v1 = argv_v1();
    let v2 = argv_v2();
    let h1 = argv_hash(&v1);
    let h2 = argv_hash(&v2);
    l.check_server_command_drift("fs", &v2, &h2).unwrap();
    l.reject_server_command_drift("fs").unwrap();
    let p = l.get_server("fs").unwrap().unwrap();
    assert_eq!(p.command_hash.as_deref(), Some(h1.as_str()));
    assert_eq!(p.command, Some(v1));
    assert!(p.pending_command_hash.is_none());
}

#[test]
fn list_pending_onboardings_and_approvals() {
    let l = setup();
    // 未批准 server
    register_fs_server(&l);
    let pending = l.list_pending_server_onboardings().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].server_id, "fs");
    assert_eq!(pending[0].trust_level, TrustLevel::Untrusted);

    // 未批准 tool
    l.pin_tool_descriptor("fs", "read", "h1").unwrap();
    let pend_tools = l.list_pending_tool_approvals().unwrap();
    assert_eq!(pend_tools.len(), 1);
    assert_eq!(pend_tools[0].tool_name, "read");
    assert!(pend_tools[0].approved_at.is_none());

    // 批准后 list_pending 不含它
    l.approve_tool_descriptor("fs", "read").unwrap();
    assert!(l.list_pending_tool_approvals().unwrap().is_empty());
}

#[test]
fn get_onboarding_data_returns_full_dto() {
    let l = setup();
    register_fs_server(&l);
    let d = l.get_onboarding_data("fs").unwrap().expect("应存在");
    assert_eq!(d.server_id, "fs");
    assert_eq!(d.transport, TransportKind::Stdio);
    assert_eq!(
        d.command.as_ref().map(|v| v.join(" ")).as_deref(),
        Some("uvx mcp-server-fs /proj")
    );
    assert_eq!(
        d.command_hash.as_deref(),
        Some(argv_hash(&argv_v1()).as_str())
    );
    assert!(d.pending_command_hash.is_none());
    assert!(
        d.requested_env_keys.is_none(),
        "I05 未知状态(Option::None),I06 lease 层补"
    );
    assert_eq!(d.trust_level, TrustLevel::Untrusted);
}

#[test]
fn drift_twice_keeps_first_drift_at_stable() {
    let l = setup();
    l.pin_tool_descriptor("fs", "read", "h1").unwrap();
    l.approve_tool_descriptor("fs", "read").unwrap();
    l.pin_tool_descriptor("fs", "read", "h2").unwrap();
    let list1 = l.list_drifted_tools().unwrap();
    let first_drift_at = list1[0].last_drift_at;

    // 再次 drift 到 h3:last_drift_at 不应被覆盖(仍是首次 drift 时间)
    l.pin_tool_descriptor("fs", "read", "h3").unwrap();
    let list2 = l.list_drifted_tools().unwrap();
    assert_eq!(list2[0].proposed_hash.as_deref(), Some("h3"));
    assert_eq!(
        list2[0].last_drift_at, first_drift_at,
        "last_drift_at 仅在首次 drift 设置,后续 drift 不覆盖"
    );
}

#[test]
fn command_drift_on_unknown_server_returns_none() {
    let l = setup();
    let argv = argv_v2();
    let h = argv_hash(&argv);
    assert!(l
        .check_server_command_drift("nonexistent", &argv, &h)
        .unwrap()
        .is_none());
}

#[test]
fn cannot_approve_drift_without_pending() {
    let l = setup();
    register_fs_server(&l);
    assert!(matches!(
        l.approve_server_command_drift("fs"),
        Err(AuditError::InvalidInput { .. })
    ));
}

/// Codex R2 MUST-FIX:tool drift 后上游回退到已批准 hash,pending_hash 必须被清零,
/// 否则账本会停在"伪 drift"状态,list_drifted_tools 持续误报。
#[test]
fn tool_drift_revert_to_approved_hash_self_heals_pending() {
    let l = setup();
    l.pin_tool_descriptor("fs", "read", "h1").unwrap();
    l.approve_tool_descriptor("fs", "read").unwrap();
    // 上游 drift
    let o = l.pin_tool_descriptor("fs", "read", "h2").unwrap();
    assert!(matches!(o, PinOutcome::Drifted { .. }));
    assert_eq!(l.list_drifted_tools().unwrap().len(), 1);
    // 上游回退到已批准 hash(可能源于 rollback / 网络抖动读到旧版)
    let o2 = l.pin_tool_descriptor("fs", "read", "h1").unwrap();
    assert!(matches!(o2, PinOutcome::Unchanged));
    assert_eq!(
        l.list_drifted_tools().unwrap().len(),
        0,
        "drift 自愈:pending_hash 必须清零"
    );
}

/// Codex R2 MUST-FIX:server command drift 后,下次 spawn 恢复到已批准 argv,
/// pending_command_hash 必须自愈清零。
#[test]
fn command_drift_revert_to_approved_argv_self_heals_pending() {
    let l = setup();
    register_fs_server(&l);
    let v1 = argv_v1();
    let v2 = argv_v2();
    let h1 = argv_hash(&v1);
    let h2 = argv_hash(&v2);
    // 先 drift
    let d = l.check_server_command_drift("fs", &v2, &h2).unwrap();
    assert!(matches!(d, Some(CommandDrift { .. })));
    assert_eq!(l.list_drifted_servers().unwrap().len(), 1);
    // 回退到已批准 argv
    let d2 = l.check_server_command_drift("fs", &v1, &h1).unwrap();
    assert!(d2.is_none());
    assert_eq!(
        l.list_drifted_servers().unwrap().len(),
        0,
        "command drift 自愈:pending_command_hash 必须清零"
    );
}

/// Codex R2 NICE-TO-HAVE:register_server 对 Stdio 缺失 command / command_hash 必须拒绝
/// (MUST-FIX 2 的直接回归)。
#[test]
fn register_server_rejects_stdio_without_command_hash() {
    let l = setup();
    let err = l.register_server(&ServerProfile {
        server_id: "bad".into(),
        transport: TransportKind::Stdio,
        command: Some(vec!["x".into()]),
        url: None,
        first_seen_at: 0,
        command_hash: None, // 缺 hash
        descriptor_hash: None,
        trust_level: TrustLevel::Untrusted,
        sandbox_profile_id: None,
    });
    assert!(matches!(err, Err(AuditError::InvalidInput { .. })));

    let err2 = l.register_server(&ServerProfile {
        server_id: "bad2".into(),
        transport: TransportKind::Stdio,
        command: None, // 缺 command
        url: None,
        first_seen_at: 0,
        command_hash: Some("h".into()),
        descriptor_hash: None,
        trust_level: TrustLevel::Untrusted,
        sandbox_profile_id: None,
    });
    assert!(matches!(err2, Err(AuditError::InvalidInput { .. })));
}

// ===================== V1.1 resolved-program drift(ADR 0007 §I-7.1 / ADR 0005)=====================
// 与 argv command drift 正交的第二独立状态机:argv 不变但裸命令解析后绝对路径变(PATH shadow /
// 重定位)时触发。覆盖 spike §6 收敛判据 2/3/6 + 护栏 1。

fn register_http_server(l: &Ledger) {
    // Http server:无 command / command_hash(resolved-program drift 不适用)
    l.register_server(&ServerProfile {
        server_id: "remote".into(),
        transport: TransportKind::Http,
        command: None,
        url: Some("https://mcp.example.com".into()),
        first_seen_at: 0,
        command_hash: None,
        descriptor_hash: None,
        trust_level: TrustLevel::Untrusted,
        sandbox_profile_id: None,
    })
    .unwrap();
}

/// 判据 2:首见建立本机基线 pin(不报 drift);再次同路径 → Unchanged。
#[test]
fn resolved_program_first_seen_pins_then_unchanged() {
    let l = setup();
    register_fs_server(&l);
    let o1 = l
        .check_server_resolved_program_drift("fs", "/usr/bin/node")
        .unwrap();
    assert!(
        matches!(o1, ResolvedProgramOutcome::Pinned { ref resolved } if resolved == "/usr/bin/node"),
        "首见必须 Pinned 建立基线,got {o1:?}"
    );
    let o2 = l
        .check_server_resolved_program_drift("fs", "/usr/bin/node")
        .unwrap();
    assert!(
        matches!(o2, ResolvedProgramOutcome::Unchanged),
        "同路径再查必须 Unchanged,got {o2:?}"
    );
}

/// 判据 3:argv 不变但解析路径变 → Drifted(fail-closed);approve 后新路径成基线。
#[test]
fn resolved_program_drift_detected_then_approve() {
    let l = setup();
    register_fs_server(&l);
    // 建立基线
    l.check_server_resolved_program_drift("fs", "/usr/bin/node")
        .unwrap();
    // PATH shadow:同 argv,解析到 /tmp/evil/node
    let d = l
        .check_server_resolved_program_drift("fs", "/tmp/evil/node")
        .unwrap();
    assert!(
        matches!(
            d,
            ResolvedProgramOutcome::Drifted(ResolvedProgramDrift { ref old, ref new })
                if old == "/usr/bin/node" && new == "/tmp/evil/node"
        ),
        "解析路径变必须 Drifted{{old,new}},got {d:?}"
    );
    // 批准 drift:pending → 新基线
    l.approve_server_resolved_program_drift("fs").unwrap();
    let o = l
        .check_server_resolved_program_drift("fs", "/tmp/evil/node")
        .unwrap();
    assert!(
        matches!(o, ResolvedProgramOutcome::Unchanged),
        "批准后新路径成基线,再查必须 Unchanged,got {o:?}"
    );
}

/// reject 保留旧基线:drift 后 reject,旧路径仍是基线,新路径再查仍 Drifted。
#[test]
fn resolved_program_drift_reject_keeps_baseline() {
    let l = setup();
    register_fs_server(&l);
    l.check_server_resolved_program_drift("fs", "/usr/bin/node")
        .unwrap();
    let d = l
        .check_server_resolved_program_drift("fs", "/opt/node/bin/node")
        .unwrap();
    assert!(matches!(d, ResolvedProgramOutcome::Drifted(_)));
    l.reject_server_resolved_program_drift("fs").unwrap();
    // 旧基线保留:原路径 Unchanged
    let o = l
        .check_server_resolved_program_drift("fs", "/usr/bin/node")
        .unwrap();
    assert!(matches!(o, ResolvedProgramOutcome::Unchanged));
    // 新路径仍 Drifted(基线未变)
    let d2 = l
        .check_server_resolved_program_drift("fs", "/opt/node/bin/node")
        .unwrap();
    assert!(matches!(d2, ResolvedProgramOutcome::Drifted(_)));
}

/// 回退到已 pin 路径自愈 pending:drift 写 pending 后,回退到基线 → Unchanged + pending 清零
/// (清零通过"随后 approve 报无 pending"间接证明,镜像 command drift 自愈语义)。
#[test]
fn resolved_program_revert_to_baseline_self_heals_pending() {
    let l = setup();
    register_fs_server(&l);
    l.check_server_resolved_program_drift("fs", "/usr/bin/node")
        .unwrap();
    // drift → 写 pending
    let d = l
        .check_server_resolved_program_drift("fs", "/tmp/evil/node")
        .unwrap();
    assert!(matches!(d, ResolvedProgramOutcome::Drifted(_)));
    // 回退到基线 → Unchanged + 清 pending
    let o = l
        .check_server_resolved_program_drift("fs", "/usr/bin/node")
        .unwrap();
    assert!(matches!(o, ResolvedProgramOutcome::Unchanged));
    // pending 已清:approve 应报"无 pending"
    let err = l.approve_server_resolved_program_drift("fs");
    assert!(
        matches!(err, Err(AuditError::InvalidInput { .. })),
        "pending 已自愈清零,approve 必须报无 pending,got {err:?}"
    );
}

/// 护栏 1:Http server(无 command_hash)resolved-program drift 不适用 → 永远 Unchanged,
/// 且不建立基线(第二个不同路径仍 Unchanged,证明未 pin)。
#[test]
fn resolved_program_not_applicable_for_http_server() {
    let l = setup();
    register_http_server(&l);
    let o1 = l
        .check_server_resolved_program_drift("remote", "/usr/bin/whatever")
        .unwrap();
    assert!(matches!(o1, ResolvedProgramOutcome::Unchanged));
    // 未建立基线:不同路径仍 Unchanged(若误 pin 了第一个,这里会 Drifted)
    let o2 = l
        .check_server_resolved_program_drift("remote", "/totally/different")
        .unwrap();
    assert!(
        matches!(o2, ResolvedProgramOutcome::Unchanged),
        "Http server 不应建立 resolved 基线,got {o2:?}"
    );
}

/// 未登记 server → Unchanged(不报错,交由 register 常规路径)。
#[test]
fn resolved_program_drift_on_unknown_server_unchanged() {
    let l = setup();
    let o = l
        .check_server_resolved_program_drift("ghost", "/usr/bin/node")
        .unwrap();
    assert!(matches!(o, ResolvedProgramOutcome::Unchanged));
}

/// approve / reject 无 pending 时报错(第二状态机的护栏)。
#[test]
fn resolved_program_approve_reject_without_pending_errors() {
    let l = setup();
    register_fs_server(&l);
    l.check_server_resolved_program_drift("fs", "/usr/bin/node")
        .unwrap();
    assert!(matches!(
        l.approve_server_resolved_program_drift("fs"),
        Err(AuditError::InvalidInput { .. })
    ));
    assert!(matches!(
        l.reject_server_resolved_program_drift("fs"),
        Err(AuditError::InvalidInput { .. })
    ));
}

/// 正交性:command drift 与 resolved-program drift 互不干扰(两个独立状态机,
/// 不 overload pending_command_hash —— Codex R1 ADR 0005 边界)。
#[test]
fn command_drift_and_resolved_program_drift_are_orthogonal() {
    let l = setup();
    register_fs_server(&l);
    // 建立 resolved 基线
    l.check_server_resolved_program_drift("fs", "/usr/bin/node")
        .unwrap();
    // 触发 argv command drift(独立维度)
    let v2 = argv_v2();
    let h2 = argv_hash(&v2);
    let cd = l.check_server_command_drift("fs", &v2, &h2).unwrap();
    assert!(matches!(cd, Some(CommandDrift { .. })));
    assert_eq!(l.list_drifted_servers().unwrap().len(), 1);
    // resolved-program 维度不受 command drift 影响:同路径仍 Unchanged
    let rp = l
        .check_server_resolved_program_drift("fs", "/usr/bin/node")
        .unwrap();
    assert!(matches!(rp, ResolvedProgramOutcome::Unchanged));
    // 批准 command drift 不应碰 resolved pending;批准 resolved 应报无 pending
    l.approve_server_command_drift("fs").unwrap();
    assert!(matches!(
        l.approve_server_resolved_program_drift("fs"),
        Err(AuditError::InvalidInput { .. })
    ));
}
