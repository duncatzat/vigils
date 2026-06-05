//! Codex audit MEDIUM 守门:approvals **表**是 SQLite ledger 的持久面,`create_approval` 落表前
//! 必须 `scrub_text` title/summary/effect_json —— 此前原样 INSERT 绕过了 `append_event` 的硬指纹
//! fail-closed 自检(no-plaintext-ledger 不变量漏洞)。monitor 模式会自动建+解 approval,使此 sink
//! 在无 GUI 时也活跃。
//!
//! 不变量:approvals 表读回(`get_approval` 从表 SELECT)绝不含原始硬指纹 secret;但**返回的
//! in-memory `ApprovalRequest` 保留原文**(Hub 进程内决策用,不落盘)。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use vigil_audit::{ApprovalTargetContext, Ledger};
use vigil_types::{DecisionKind, DecisionRecord, EffectVector};

#[test]
fn create_approval_scrubs_hard_secret_in_table_keeps_inmemory_raw() {
    let l = Ledger::open_in_memory().unwrap();
    let sid = l.start_session("approvals_redaction", None).unwrap();
    // 一个真硬指纹(github PAT 形态),分别埋进 title / summary / effect 字段。
    let secret = "ghp_1234567890abcdef1234567890abcdef12345678";

    let dec = DecisionRecord {
        decision_id: "d1".into(),
        invocation_id: "inv1".into(),
        decision: DecisionKind::Approve,
        risk_score: 50,
        reasons: vec![],
        policy_ids: vec![],
        created_at: 0,
    };
    // secret 落 effect 字段(模拟工具 effect 元数据里偶含 secret-like 串)。
    let mut effects = EffectVector::default();
    effects.paths_write.push(format!("/tmp/{secret}.txt"));

    let ctx = ApprovalTargetContext {
        server_id: Some("fs"),
        tool_name: Some("write"),
        args_hash: Some("h"),
    };
    let req = l
        .create_approval(
            &sid,
            &dec,
            &effects,
            &format!("write {secret}"),            // secret 落 title
            &format!("summary touching {secret}"), // secret 落 summary
            600,
            ctx,
        )
        .unwrap();

    // in-memory 返回保留原文(Hub 进程内决策用,不落盘)。
    assert!(
        req.title.contains(secret),
        "in-memory 返回的 ApprovalRequest 应保留原文 title(供进程内决策)"
    );

    // 表读回(get_approval 从 approvals 表 SELECT)必须已 scrub —— 这才是落盘 ledger 的形态。
    let stored = l.get_approval(&req.approval_id).unwrap().unwrap();
    assert!(
        !stored.title.contains(secret),
        "approvals 表 title 不得存原始硬指纹 secret;实际 {}",
        stored.title
    );
    assert!(
        stored.title.contains("[REDACTED"),
        "title 里的硬指纹应被 scrub 为占位符;实际 {}",
        stored.title
    );
    assert!(
        !stored.summary.contains(secret),
        "approvals 表 summary 不得存原始 secret;实际 {}",
        stored.summary
    );
    // effect_json 经 scrub 后仍是合法 JSON、可反序列化;paths_write 里的 secret 也被遮蔽。
    let ev_dbg = format!("{:?}", stored.effect_vector);
    assert!(
        !ev_dbg.contains(secret),
        "approvals 表 effect_json 不得存原始 secret;实际 {ev_dbg}"
    );
}

/// Codex audit R2 守门:approvals 表的**第二个写入口** `store_pending_approval_skeleton`
/// (I01 遗留骨架 API)同样必须 scrub —— 否则即是绕过表不变量的旁路。用第二连接直接查表证实。
#[test]
fn skeleton_insert_also_scrubs_approvals_table() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_path_buf();
    let l = Ledger::open(&path).unwrap();
    let sid = l.start_session("skeleton_redaction", None).unwrap();
    let secret = "ghp_1234567890abcdef1234567890abcdef12345678";

    l.store_pending_approval_skeleton(
        "appr-x",
        "dec-x",
        &sid,
        &format!("title {secret}"),
        &format!("summary {secret}"),
        &format!(r#"{{"hosts":["{secret}"]}}"#),
        9_999_999_999,
    )
    .unwrap();

    let conn = rusqlite::Connection::open(&path).unwrap();
    let (title, summary, effect): (String, String, String) = conn
        .query_row(
            "SELECT title, summary, effect_json FROM approvals WHERE approval_id = 'appr-x'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert!(
        !title.contains(secret) && title.contains("[REDACTED"),
        "skeleton 写入口 title 须 scrub;实际 {title}"
    );
    assert!(
        !summary.contains(secret),
        "skeleton summary 须 scrub;实际 {summary}"
    );
    assert!(
        !effect.contains(secret),
        "skeleton effect_json 须 scrub;实际 {effect}"
    );
}
