//! I08a §12.3 I08 四条验收 + ADR 0008 §D5 argv lint 红线。
//!
//! 通过直调 `dispatch()`(纯函数)覆盖:
//! - I08-1 approval can be resolved
//! - I08-2 session replay loads + verify_chain
//! - I08-3 server command visible(exact argv §4.7)
//! - I08-4 secret never visible(SENTINEL 全路径扫描)
//! - D5 argv lint(register_server 拒绝硬指纹)
//! - D6 sandbox profile CRUD + JCS hash 稳定 + 绑定
//! - §I-8.4 capability gate(read 不能跑 write)

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::err_expect,
    clippy::panic
)]

use vigil_audit::{Ledger, ToolSecretBinding};
use vigil_desktop::dispatch;
use vigil_lease::{InMemorySecretStore, LeaseBroker, ResolveContext, SecretStore, SecretValue};
use vigil_runner::SandboxProfile;
use vigil_types::{
    ApprovalScope, DecisionKind, DecisionRecord, EffectVector, ServerProfile, TransportKind,
    TrustLevel,
};
use vigil_ui_protocol::{
    ApprovalAction, ApproveServerCommandDriftReq, BindServerSandboxProfileReq, Capability,
    GetServerOnboardingReq, ListPendingApprovalsReq, ListRecentEventsReq, ListSessionsReq,
    RejectServerCommandDriftReq, ReplaySessionReq, ResolveApprovalReq, UiCommand, UiError,
    UiResponse, UpsertSandboxProfileReq,
};

/// 用于红线扫描的唯一哨兵:与其他硬指纹不重叠,仅本测试存在。
const SENTINEL: &str = "ghp_REDLINEZZZ_SUPERSENTINEL_1234567890abcdef";

fn setup() -> (Ledger, String) {
    let l = Ledger::open_in_memory().unwrap();
    let sid = l.start_session("i08_test", None).unwrap();
    (l, sid)
}

/// §12.3 I08-1:approval can be resolved from UI(CLI 闭环)
#[test]
fn cli_resolves_approval_updates_ledger() {
    let (l, sid) = setup();
    // 构造一条 Pending approval
    let dec = DecisionRecord {
        decision_id: "d1".into(),
        invocation_id: "i1".into(),
        decision: DecisionKind::Approve,
        risk_score: 50,
        reasons: vec![],
        policy_ids: vec![],
        created_at: 0,
    };
    let ctx = vigil_audit::ApprovalTargetContext {
        server_id: Some("fs"),
        tool_name: Some("write_file"),
        args_hash: Some("hash1"),
    };
    let req = l
        .create_approval(
            &sid,
            &dec,
            &EffectVector::default(),
            "Write project/x.md",
            "approve to write file",
            600,
            ctx,
        )
        .unwrap();

    // UI 走 ResolveApproval
    let cmd = UiCommand::ResolveApproval(ResolveApprovalReq {
        approval_id: req.approval_id.clone(),
        action: ApprovalAction::Approve,
        scope: Some(ApprovalScope::Once),
        resolved_by: "alice".into(),
        reason: None,
    });
    let resp = dispatch(cmd, &l, Capability::Write).unwrap();
    match resp {
        UiResponse::ApprovalResolution(r) => {
            assert_eq!(r.approval_id, req.approval_id);
            assert_eq!(r.status, vigil_types::ApprovalStatus::Approved);
            assert_eq!(r.scope, Some(ApprovalScope::Once));
            assert_eq!(r.resolved_by.as_deref(), Some("alice"));
        }
        other => panic!("期望 ApprovalResolution,得到 {other:?}"),
    }

    // Ledger 状态已更新
    let after = l.get_approval(&req.approval_id).unwrap().unwrap();
    assert_eq!(after.status, vigil_types::ApprovalStatus::Approved);
}

/// §12.3 I08-2:session replay loads
#[test]
fn cli_replay_prints_events_and_verifies_chain() {
    let (l, sid) = setup();
    // 写几条非保留前缀的审计事件(保留前缀 tool_call./decision./approval./lease. 走 typed API)
    l.append_event(
        &sid,
        "server.command_approved",
        &serde_json::json!({"x":1}),
        None,
    )
    .unwrap();
    l.append_event(
        &sid,
        "tool_approval.created",
        &serde_json::json!({"y":2}),
        None,
    )
    .unwrap();

    let resp = dispatch(
        UiCommand::ReplaySession(ReplaySessionReq {
            session_id: sid.clone(),
            verify: true,
        }),
        &l,
        Capability::Read,
    )
    .unwrap();
    match resp {
        UiResponse::ReplayDump(r) => {
            assert_eq!(r.session_id, sid);
            assert!(r.event_count >= 2);
            // start_session 也会产事件;至少总数 >= 2
            let verified = r.chain_verified.expect("verify=true requested");
            assert!(verified.ok, "chain should be intact");
        }
        other => panic!("期望 ReplayDump,得到 {other:?}"),
    }
}

/// §12.3 I08-3:server command visible(exact argv §4.7)
#[test]
fn cli_server_show_prints_exact_argv() {
    let (l, _sid) = setup();
    let argv = vec![
        "uvx".into(),
        "mcp-server-fs".into(),
        "--root".into(),
        "/proj".into(),
    ];
    l.register_server(&ServerProfile {
        server_id: "fs".into(),
        transport: TransportKind::Stdio,
        command: Some(argv.clone()),
        url: None,
        first_seen_at: 0,
        command_hash: Some("h".into()),
        descriptor_hash: None,
        trust_level: TrustLevel::Untrusted,
        sandbox_profile_id: None,
    })
    .unwrap();

    let resp = dispatch(
        UiCommand::GetServerOnboarding(GetServerOnboardingReq {
            server_id: "fs".into(),
        }),
        &l,
        Capability::Read,
    )
    .unwrap();
    match resp {
        UiResponse::ServerOnboarding(data) => {
            assert_eq!(data.command.as_deref(), Some(argv.as_slice()));
        }
        other => panic!("期望 ServerOnboarding,得到 {other:?}"),
    }
}

/// §12.3 I08-4 + ADR §D5:SENTINEL 注入 secret/env/audit 全路径,CLI 任何 response
/// 的 JSON 序列化都不得包含 SENTINEL 字面。
#[test]
fn cli_redline_sentinel_never_in_any_output() {
    let l = Ledger::open_in_memory().unwrap();
    let sid = l.start_session("redline", None).unwrap();

    // 建 secret + binding,真实值 = SENTINEL,只在 InMemoryStore 持有
    l.register_secret_ref("secret://red", "Redline", "mock")
        .unwrap();
    l.bind_tool_secret(&ToolSecretBinding {
        server_id: "gh".into(),
        tool_name: "*".into(),
        secret_ref: "secret://red".into(),
        injection_method: "ChildEnv".into(),
        env_var_name: Some("REDLINE_TOKEN".into()),
    })
    .unwrap();

    // 合法 server(argv 里**不含** SENTINEL,因为 D5 lint 会拒)
    l.register_server(&ServerProfile {
        server_id: "gh".into(),
        transport: TransportKind::Stdio,
        command: Some(vec!["gh-mcp".into()]),
        url: None,
        first_seen_at: 0,
        command_hash: Some("h".into()),
        descriptor_hash: None,
        trust_level: TrustLevel::Untrusted,
        sandbox_profile_id: None,
    })
    .unwrap();

    // 模拟 lease mint 产生 audit(真实值仅在 store 存,不入 audit payload)
    let store: std::sync::Arc<InMemorySecretStore> =
        std::sync::Arc::new(InMemorySecretStore::new());
    store
        .put("secret://red", SecretValue::new(SENTINEL))
        .unwrap();
    let broker = std::sync::Arc::new(LeaseBroker::new(
        store,
        std::sync::Arc::new(Ledger::open_in_memory().unwrap()),
    ));
    // 注:broker 用独立 ledger 以避免污染 redline 测试的主 ledger;
    // 但我们也想验主 ledger 的 events 无 SENTINEL —— 重建 broker 走主 ledger
    drop(broker);
    let store2: std::sync::Arc<InMemorySecretStore> =
        std::sync::Arc::new(InMemorySecretStore::new());
    store2
        .put("secret://red", SecretValue::new(SENTINEL))
        .unwrap();
    let main_ledger_arc = std::sync::Arc::new(l);
    let broker2 = std::sync::Arc::new(LeaseBroker::new(store2, main_ledger_arc.clone()));
    let lease = broker2
        .mint_lease(vigil_lease::MintRequest {
            secret_ref: "secret://red".into(),
            session_id: sid.clone(),
            server_id: "gh".into(),
            tool_name: "use".into(),
            approval_id: None,
            injection_method: vigil_types::InjectionMethod::ChildEnv,
            ttl_secs: 60,
        })
        .unwrap();
    let _v = broker2
        .resolve_value(
            &lease.lease_id,
            &ResolveContext {
                session_id: sid.clone(),
                server_id: "gh".into(),
                tool_name: "use".into(),
            },
        )
        .unwrap();
    broker2.revoke_lease(&lease.lease_id).unwrap();

    // ---- 现在跑 CLI dispatch 覆盖 4 大读命令 + sandbox,断言 SENTINEL 不出现在任何 response ----
    let l_ref = main_ledger_arc.as_ref();
    let responses: Vec<UiResponse> = vec![
        dispatch(
            UiCommand::ListRecentEvents(ListRecentEventsReq {
                session_id: None,
                event_type_filter: None,
                limit: 1000,
            }),
            l_ref,
            Capability::Read,
        )
        .unwrap(),
        dispatch(
            UiCommand::ReplaySession(ReplaySessionReq {
                session_id: sid.clone(),
                verify: false,
            }),
            l_ref,
            Capability::Read,
        )
        .unwrap(),
        dispatch(
            UiCommand::ListSessions(ListSessionsReq {
                source: None,
                limit: 100,
            }),
            l_ref,
            Capability::Read,
        )
        .unwrap(),
        dispatch(UiCommand::ListServers, l_ref, Capability::Read).unwrap(),
        dispatch(
            UiCommand::GetServerOnboarding(GetServerOnboardingReq {
                server_id: "gh".into(),
            }),
            l_ref,
            Capability::Read,
        )
        .unwrap(),
    ];
    for r in &responses {
        let s = serde_json::to_string(r).unwrap();
        assert!(
            !s.contains(SENTINEL),
            "SENTINEL leaked into response: kind={:?} body={}",
            std::mem::discriminant(r),
            s
        );
    }
}

/// ADR §D5:argv 含硬指纹 secret 直接拒注册
#[test]
fn server_register_rejects_secret_in_argv() {
    let (l, _sid) = setup();
    // GitHub PAT 形态 40 字符
    let bad_token = "ghp_1234567890abcdef1234567890abcdef12345678";
    let err = l.register_server(&ServerProfile {
        server_id: "bad".into(),
        transport: TransportKind::Stdio,
        command: Some(vec!["gh-mcp".into(), "--token".into(), bad_token.into()]),
        url: None,
        first_seen_at: 0,
        command_hash: Some("h".into()),
        descriptor_hash: None,
        trust_level: TrustLevel::Untrusted,
        sandbox_profile_id: None,
    });
    match err {
        Err(vigil_audit::AuditError::InvalidInput { reason }) => {
            assert!(
                reason.starts_with("argv_contains_secret:"),
                "expected argv_contains_secret:* reason, got {reason}"
            );
        }
        other => panic!("期望 InvalidInput(argv_contains_secret),得到 {other:?}"),
    }
}

/// §I-8.4:Read capability 不能执行 Write 命令
#[test]
fn capability_read_cannot_execute_write_commands() {
    let (l, _sid) = setup();
    let err = dispatch(
        UiCommand::ApproveServerCommandDrift(ApproveServerCommandDriftReq {
            server_id: "x".into(),
        }),
        &l,
        Capability::Read,
    )
    .unwrap_err();
    match err {
        UiError::CapabilityDenied { required } => assert_eq!(required, "ui.write"),
        other => panic!("期望 CapabilityDenied,得到 {other:?}"),
    }
}

/// ADR §D6 + §I-8.5:sandbox profile upsert idempotent + JCS hash 稳定
#[test]
fn sandbox_profile_upsert_idempotent_and_hash_stable() {
    let (l, _sid) = setup();
    let profile = SandboxProfile {
        id: "p1".into(),
        read_dirs: vec!["/tmp/x".into()],
        write_dirs: vec!["/tmp/x".into()],
        allow_hosts: vec![],
        env_inherit: false,
        wall_ms: 5000,
        memory_mb: 64,
    };
    let cmd = UiCommand::UpsertSandboxProfile(UpsertSandboxProfileReq {
        profile: profile.clone(),
    });
    // 第一次 insert
    let r1 = dispatch(cmd.clone(), &l, Capability::Write).unwrap();
    let h1 = match r1 {
        UiResponse::SandboxProfileUpserted(d) => {
            assert!(d.inserted);
            d.profile_hash
        }
        _ => panic!(),
    };
    // 第二次 update,同 profile,hash 应相同
    let r2 = dispatch(cmd, &l, Capability::Write).unwrap();
    let h2 = match r2 {
        UiResponse::SandboxProfileUpserted(d) => {
            assert!(!d.inserted);
            d.profile_hash
        }
        _ => panic!(),
    };
    assert_eq!(h1, h2, "hash 必须稳定(JCS 规范化)");
}

/// D6:bind roundtrip
#[test]
fn bind_server_sandbox_profile_roundtrip() {
    let (l, _sid) = setup();
    // 准备 profile 和 server
    let profile = SandboxProfile {
        id: "p1".into(),
        read_dirs: vec![],
        write_dirs: vec![],
        allow_hosts: vec![],
        env_inherit: false,
        wall_ms: 1000,
        memory_mb: 64,
    };
    dispatch(
        UiCommand::UpsertSandboxProfile(UpsertSandboxProfileReq { profile }),
        &l,
        Capability::Write,
    )
    .unwrap();
    l.register_server(&ServerProfile {
        server_id: "s1".into(),
        transport: TransportKind::Stdio,
        command: Some(vec!["x".into()]),
        url: None,
        first_seen_at: 0,
        command_hash: Some("h".into()),
        descriptor_hash: None,
        trust_level: TrustLevel::Untrusted,
        sandbox_profile_id: None,
    })
    .unwrap();

    dispatch(
        UiCommand::BindServerSandboxProfile(BindServerSandboxProfileReq {
            server_id: "s1".into(),
            profile_id: Some("p1".into()),
        }),
        &l,
        Capability::Write,
    )
    .unwrap();
    // 解绑
    dispatch(
        UiCommand::BindServerSandboxProfile(BindServerSandboxProfileReq {
            server_id: "s1".into(),
            profile_id: None,
        }),
        &l,
        Capability::Write,
    )
    .unwrap();
}

/// D6 变种:绑一个不存在的 profile_id → Invalid
#[test]
fn bind_nonexistent_sandbox_profile_rejected() {
    let (l, _sid) = setup();
    l.register_server(&ServerProfile {
        server_id: "s1".into(),
        transport: TransportKind::Stdio,
        command: Some(vec!["x".into()]),
        url: None,
        first_seen_at: 0,
        command_hash: Some("h".into()),
        descriptor_hash: None,
        trust_level: TrustLevel::Untrusted,
        sandbox_profile_id: None,
    })
    .unwrap();
    let err = dispatch(
        UiCommand::BindServerSandboxProfile(BindServerSandboxProfileReq {
            server_id: "s1".into(),
            profile_id: Some("not-exist".into()),
        }),
        &l,
        Capability::Write,
    )
    .unwrap_err();
    match err {
        UiError::Invalid(_) => {}
        other => panic!("期望 Invalid,得到 {other:?}"),
    }
}

/// Codex R1 NICE-TO-HAVE:Cancel 走 audit cancel,最终状态 Cancelled(不是 Denied)
#[test]
fn resolve_approval_cancel_maps_to_cancelled_status() {
    let (l, sid) = setup();
    let dec = DecisionRecord {
        decision_id: "d".into(),
        invocation_id: "i".into(),
        decision: DecisionKind::Approve,
        risk_score: 0,
        reasons: vec![],
        policy_ids: vec![],
        created_at: 0,
    };
    let ctx = vigil_audit::ApprovalTargetContext {
        server_id: None,
        tool_name: None,
        args_hash: None,
    };
    let req = l
        .create_approval(&sid, &dec, &EffectVector::default(), "t", "s", 600, ctx)
        .unwrap();
    let resp = dispatch(
        UiCommand::ResolveApproval(ResolveApprovalReq {
            approval_id: req.approval_id.clone(),
            action: ApprovalAction::Cancel,
            scope: None,
            resolved_by: "user".into(),
            reason: None,
        }),
        &l,
        Capability::Write,
    )
    .unwrap();
    match resp {
        UiResponse::ApprovalResolution(r) => {
            assert_eq!(r.status, vigil_types::ApprovalStatus::Cancelled);
        }
        other => panic!("期望 Cancelled,得到 {other:?}"),
    }
}

/// Codex R1 NICE-TO-HAVE:Deny 走 ledger.deny,状态 Denied;reason 仅审计,不泄漏到 response
#[test]
fn resolve_approval_deny_maps_to_denied() {
    let (l, sid) = setup();
    let dec = DecisionRecord {
        decision_id: "d".into(),
        invocation_id: "i".into(),
        decision: DecisionKind::Approve,
        risk_score: 0,
        reasons: vec![],
        policy_ids: vec![],
        created_at: 0,
    };
    let ctx = vigil_audit::ApprovalTargetContext {
        server_id: None,
        tool_name: None,
        args_hash: None,
    };
    let req = l
        .create_approval(&sid, &dec, &EffectVector::default(), "t", "s", 600, ctx)
        .unwrap();
    let resp = dispatch(
        UiCommand::ResolveApproval(ResolveApprovalReq {
            approval_id: req.approval_id.clone(),
            action: ApprovalAction::Deny,
            scope: None,
            resolved_by: "user".into(),
            reason: Some("policy deny".into()),
        }),
        &l,
        Capability::Write,
    )
    .unwrap();
    match resp {
        UiResponse::ApprovalResolution(r) => {
            assert_eq!(r.status, vigil_types::ApprovalStatus::Denied);
        }
        other => panic!("期望 Denied,得到 {other:?}"),
    }
}

/// Codex R1 BLOCKER:server command drift approve 后 UI 展示新 argv(§4.7)
#[test]
fn drift_approve_persists_new_argv_for_ui() {
    let (l, _sid) = setup();
    let argv_v1 = vec!["mock".into()];
    let argv_v2 = vec!["mock".into(), "--new-flag".into()];
    let h1 = vigil_audit::argv_hash(&argv_v1);
    let h2 = vigil_audit::argv_hash(&argv_v2);
    l.register_server(&ServerProfile {
        server_id: "s".into(),
        transport: TransportKind::Stdio,
        command: Some(argv_v1.clone()),
        url: None,
        first_seen_at: 0,
        command_hash: Some(h1.clone()),
        descriptor_hash: None,
        trust_level: TrustLevel::Untrusted,
        sandbox_profile_id: None,
    })
    .unwrap();
    // 触发 drift
    l.check_server_command_drift("s", &argv_v2, &h2).unwrap();
    // UI 批准 drift
    dispatch(
        UiCommand::ApproveServerCommandDrift(ApproveServerCommandDriftReq {
            server_id: "s".into(),
        }),
        &l,
        Capability::Write,
    )
    .unwrap();
    // 批准后 server.command 必须是 argv_v2(§4.7 exact argv visible)
    let data = l.get_onboarding_data("s").unwrap().unwrap();
    assert_eq!(data.command.as_ref(), Some(&argv_v2));
    assert_eq!(data.command_hash.as_deref(), Some(h2.as_str()));
    assert!(data.pending_command_hash.is_none());
}

/// Codex R1 NICE-TO-HAVE:Reject drift 保留旧 argv 文本
#[test]
fn drift_reject_keeps_old_argv() {
    let (l, _sid) = setup();
    let argv_v1 = vec!["mock".into()];
    let argv_v2 = vec!["mock".into(), "--evil".into()];
    let h1 = vigil_audit::argv_hash(&argv_v1);
    let h2 = vigil_audit::argv_hash(&argv_v2);
    l.register_server(&ServerProfile {
        server_id: "s".into(),
        transport: TransportKind::Stdio,
        command: Some(argv_v1.clone()),
        url: None,
        first_seen_at: 0,
        command_hash: Some(h1.clone()),
        descriptor_hash: None,
        trust_level: TrustLevel::Untrusted,
        sandbox_profile_id: None,
    })
    .unwrap();
    l.check_server_command_drift("s", &argv_v2, &h2).unwrap();
    dispatch(
        UiCommand::RejectServerCommandDrift(RejectServerCommandDriftReq {
            server_id: "s".into(),
        }),
        &l,
        Capability::Write,
    )
    .unwrap();
    let data = l.get_onboarding_data("s").unwrap().unwrap();
    assert_eq!(data.command.as_ref(), Some(&argv_v1));
    assert_eq!(data.command_hash.as_deref(), Some(h1.as_str()));
    assert!(data.pending_command_hash.is_none());
}

/// Codex R1 NICE-TO-HAVE:list_pending_approvals 直接 SQL 查询
#[test]
fn list_pending_approvals_direct_sql() {
    let (l, sid) = setup();
    let dec = DecisionRecord {
        decision_id: "d".into(),
        invocation_id: "i".into(),
        decision: DecisionKind::Approve,
        risk_score: 0,
        reasons: vec![],
        policy_ids: vec![],
        created_at: 0,
    };
    let ctx = vigil_audit::ApprovalTargetContext {
        server_id: None,
        tool_name: None,
        args_hash: None,
    };
    let req = l
        .create_approval(&sid, &dec, &EffectVector::default(), "t", "s", 600, ctx)
        .unwrap();
    let resp = dispatch(
        UiCommand::ListPendingApprovals(ListPendingApprovalsReq { session_id: None }),
        &l,
        Capability::Read,
    )
    .unwrap();
    match resp {
        UiResponse::ApprovalList(list) => {
            assert_eq!(list.len(), 1);
            assert_eq!(list[0].approval_id, req.approval_id);
        }
        other => panic!("期望 ApprovalList,得到 {other:?}"),
    }
}

/// Codex R1 MUST-FIX 3:Ledger 层自证 —— caller 传非 canonical JSON,Ledger 内部规范化
#[test]
fn ledger_upsert_canonicalizes_profile_json_internally() {
    let (l, _sid) = setup();
    // 手工塞非规范化 JSON(字段顺序乱 + 多空格)—— Ledger 应内部重排
    let non_canonical = r#"{ "memory_mb": 64, "id": "x", "read_dirs": [], "write_dirs": [],
        "allow_hosts": [], "env_inherit": false, "wall_ms": 1000 }"#;
    let r1 = l.upsert_sandbox_profile("x", non_canonical).unwrap();
    // 规范化 JSON 应得相同 hash
    let canonical = r#"{"allow_hosts":[],"env_inherit":false,"id":"x","memory_mb":64,"read_dirs":[],"wall_ms":1000,"write_dirs":[]}"#;
    let r2 = l.upsert_sandbox_profile("x", canonical).unwrap();
    assert_eq!(
        r1.profile_hash, r2.profile_hash,
        "非规范化 JSON 应被 Ledger 内部 canonicalize 到相同 hash"
    );
    assert!(r1.inserted);
    assert!(!r2.inserted);
}

/// Codex R1 MUST-FIX 3:Ledger 层自证 —— env_inherit=true 在 Ledger 公共 API 直接拒绝
#[test]
fn ledger_upsert_rejects_env_inherit_true_even_bypass_dispatcher() {
    let (l, _sid) = setup();
    let bad = r#"{"id":"x","read_dirs":[],"write_dirs":[],"allow_hosts":[],
                  "env_inherit":true,"wall_ms":1000,"memory_mb":64}"#;
    let err = l.upsert_sandbox_profile("x", bad).unwrap_err();
    assert!(matches!(err, vigil_audit::AuditError::InvalidInput { .. }));
}

/// Codex R2 BLOCKER:老 schema 升级后 drift API 可用。
/// 模拟"I07 时代的 server_profiles 缺 pending_command_json 列",手工 CREATE 老结构,
/// 然后 Ledger::open 应 ALTER TABLE ADD COLUMN,随后 drift 流程可正常写读。
///
/// V1.1 扩展:该老库同样缺 `resolved_program_path` / `pending_resolved_program_path` 两列;
/// 升级后这两列也须可用,且 legacy 行(NULL 基线)首次 spawn 建立基线不 block(spike §3.2 护栏)。
#[test]
fn legacy_schema_upgrades_to_add_pending_command_json() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("legacy.db");
    // 手工建一个缺列的老 server_profiles + 最小 sessions / events 兼容
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE server_profiles (
              server_id TEXT PRIMARY KEY,
              transport TEXT NOT NULL,
              command_json TEXT,
              url TEXT,
              first_seen_at INTEGER NOT NULL,
              command_hash TEXT,
              descriptor_hash TEXT,
              trust_level TEXT NOT NULL,
              sandbox_profile_id TEXT,
              pending_command_hash TEXT,
              last_drift_at INTEGER
            );
            INSERT INTO server_profiles
              (server_id, transport, command_json, url, first_seen_at, command_hash, trust_level)
            VALUES
              ('legacy-fs', 'Stdio', '["mock"]', NULL, 0,
               '9d0fa0df6a51b1c23fd3ce00e30d0bc3b8c1d1dd95b8a6d00efe7d6d9ce9d1df', 'Untrusted');
            "#,
        )
        .unwrap();
    }
    // Ledger::open 应自动 ALTER 老表 + run full CREATE IF NOT EXISTS for other tables
    let l = Ledger::open(&db_path).unwrap();
    // 老行里的 command_hash 是 bogus 的 sha256 长度串;触发 drift
    let new_argv = vec!["mock".into(), "--upgraded".into()];
    let h = vigil_audit::argv_hash(&new_argv);
    // drift 成功(老库 pending_command_json 已 ALTER 存在)
    let _ = l
        .check_server_command_drift("legacy-fs", &new_argv, &h)
        .unwrap();
    // drift approve 读 pending_command_json 也不炸
    l.approve_server_command_drift("legacy-fs").unwrap();
    let data = l.get_onboarding_data("legacy-fs").unwrap().unwrap();
    assert_eq!(data.command.as_ref(), Some(&new_argv));

    // V1.1:老库升级后两新列可用 —— legacy 行 NULL 基线,首次 spawn 建立基线(不 block),
    // 随后异路径触发 resolved-program drift(第二独立维度)。
    let pinned = l
        .check_server_resolved_program_drift("legacy-fs", "/usr/bin/mock")
        .unwrap();
    assert!(
        matches!(pinned, vigil_audit::ResolvedProgramOutcome::Pinned { .. }),
        "legacy NULL 基线首次 spawn 必须 Pinned(不 block),got {pinned:?}"
    );
    let drifted = l
        .check_server_resolved_program_drift("legacy-fs", "/tmp/evil/mock")
        .unwrap();
    assert!(
        matches!(drifted, vigil_audit::ResolvedProgramOutcome::Drifted(_)),
        "升级后 resolved-program drift 须正常触发,got {drifted:?}"
    );
}

/// D6 变种:env_inherit=true 拒绝(保险网)
#[test]
fn upsert_sandbox_profile_rejects_env_inherit_true() {
    let (l, _sid) = setup();
    let profile = SandboxProfile {
        id: "bad".into(),
        read_dirs: vec![],
        write_dirs: vec![],
        allow_hosts: vec![],
        env_inherit: true, // 违反 AGENTS §7
        wall_ms: 1000,
        memory_mb: 64,
    };
    let err = dispatch(
        UiCommand::UpsertSandboxProfile(UpsertSandboxProfileReq { profile }),
        &l,
        Capability::Write,
    )
    .unwrap_err();
    assert!(matches!(err, UiError::Invalid(_)));
}
