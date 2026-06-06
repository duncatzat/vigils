//! `Ledger::protection_summary` 的数据层测试:`inspect protection` 的"保护成效"汇总。
//!
//! 覆盖:三类保护事件计数 + 审计总量(含非保护事件)+ session 覆盖 + recent 只含保护类且 DESC +
//! limit 只截 recent 不截计数 + 空账本全零且链 trivially 完整。

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::json;
use vigil_audit::{
    Ledger, EVENT_TYPE_RAW_SECRET_BLOCKED, EVENT_TYPE_SECRET_ALIAS_UNRESOLVED,
    EVENT_TYPE_TOOL_RESULT_LEAK,
};

#[test]
fn protection_summary_counts_recent_and_chain() {
    let l = Ledger::open_in_memory().unwrap();
    let sid = l.start_session("test", Some("unit")).unwrap();
    // 2 裸 secret 拦截 + 3 tool-result 泄漏 + 1 alias 未解析 + 2 条非保护噪声事件。
    for i in 0..2 {
        l.append_event(
            &sid,
            EVENT_TYPE_RAW_SECRET_BLOCKED,
            &json!({"rule":"github_token","i":i}),
            Some("raw secret blocked"),
        )
        .unwrap();
    }
    for i in 0..3 {
        l.append_event(
            &sid,
            EVENT_TYPE_TOOL_RESULT_LEAK,
            &json!({"rule":"github_token","i":i}),
            Some("leak redacted"),
        )
        .unwrap();
    }
    l.append_event(
        &sid,
        EVENT_TYPE_SECRET_ALIAS_UNRESOLVED,
        &json!({"alias":"x"}),
        Some("alias unresolved"),
    )
    .unwrap();
    l.append_event(&sid, "hello.world", &json!({"x":1}), Some("noise"))
        .unwrap();
    l.append_event(&sid, "another.event", &json!({"y":2}), Some("noise2"))
        .unwrap();

    let s = l.protection_summary(10).unwrap();
    assert_eq!(s.raw_secrets_blocked, 2);
    assert_eq!(s.tool_result_leaks_detected, 3);
    assert_eq!(s.secret_aliases_unresolved, 1);
    assert_eq!(s.total_events_audited, 8, "总量含非保护事件(2+3+1+2)");
    assert_eq!(s.sessions_covered, 1);
    assert!(s.chain_intact);

    // recent 只含 6 条保护事件、DESC by event_id、绝无噪声。
    assert_eq!(s.recent.len(), 6);
    assert!(s.recent.iter().all(|e| {
        e.event_type == EVENT_TYPE_RAW_SECRET_BLOCKED
            || e.event_type == EVENT_TYPE_TOOL_RESULT_LEAK
            || e.event_type == EVENT_TYPE_SECRET_ALIAS_UNRESOLVED
    }));
    for w in s.recent.windows(2) {
        assert!(w[0].event_id > w[1].event_id, "recent 必须 event_id DESC");
    }
    assert!(
        !s.recent.iter().any(|e| e.event_type == "hello.world"),
        "非保护事件不得进 recent"
    );
}

#[test]
fn protection_summary_limit_caps_recent_but_not_counts() {
    let l = Ledger::open_in_memory().unwrap();
    let sid = l.start_session("test", Some("unit")).unwrap();
    for i in 0..5 {
        l.append_event(
            &sid,
            EVENT_TYPE_TOOL_RESULT_LEAK,
            &json!({"i":i}),
            Some("leak"),
        )
        .unwrap();
    }
    let s = l.protection_summary(2).unwrap();
    assert_eq!(
        s.tool_result_leaks_detected, 5,
        "计数覆盖全部事件,不受 limit 影响"
    );
    assert_eq!(s.recent.len(), 2, "recent 受 limit 截断");
}

#[test]
fn protection_summary_distinct_sessions_counted() {
    let l = Ledger::open_in_memory().unwrap();
    let s1 = l.start_session("proj-a", Some("unit")).unwrap();
    let s2 = l.start_session("proj-b", Some("unit")).unwrap();
    l.append_event(&s1, EVENT_TYPE_RAW_SECRET_BLOCKED, &json!({}), Some("a"))
        .unwrap();
    l.append_event(&s2, EVENT_TYPE_RAW_SECRET_BLOCKED, &json!({}), Some("b"))
        .unwrap();
    let s = l.protection_summary(10).unwrap();
    assert_eq!(s.raw_secrets_blocked, 2);
    assert_eq!(s.sessions_covered, 2, "两个不同 session 各有事件");
}

#[test]
fn protection_summary_fail_closed_suppresses_recent_when_chain_tampered() {
    use rusqlite::Connection;
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    {
        let l = Ledger::open(&path).unwrap();
        let sid = l.start_session("test", Some("unit")).unwrap();
        l.append_event(
            &sid,
            EVENT_TYPE_TOOL_RESULT_LEAK,
            &json!({"rule":"github_token"}),
            Some("leak redacted"),
        )
        .unwrap();
        l.verify_chain().unwrap();
    } // drop → 连接关闭 → WAL checkpoint

    // 模拟磁盘篡改:绕过 Ledger API 直接 UPDATE 保护事件的 redacted_text(注入伪造摘要)。
    // redacted_text 在 SEC-001 v2 哈希链摘要内 → 此改写必破坏 verify_chain。
    {
        let c = Connection::open(&path).unwrap();
        c.execute(
            "UPDATE events SET redacted_text = ?1 WHERE event_id = 1",
            rusqlite::params!["INJECTED-not-actually-redacted-marker"],
        )
        .unwrap();
    }

    let l = Ledger::open(&path).unwrap();
    let s = l.protection_summary(10).unwrap();
    assert!(!s.chain_intact, "篡改后哈希链必须不完整");
    assert!(
        s.recent.is_empty(),
        "fail-closed:链不可信时 recent 明细(redacted_text)必须被抑制,绝不回显可能被注入的内容"
    );
    // 整数计数不泄密,仍可给出(用户已见 chain TAMPERED 警告)。
    assert_eq!(s.tool_result_leaks_detected, 1);
}

#[test]
fn protection_summary_empty_ledger_is_all_zero_chain_intact() {
    let l = Ledger::open_in_memory().unwrap();
    let s = l.protection_summary(10).unwrap();
    assert_eq!(s.raw_secrets_blocked, 0);
    assert_eq!(s.tool_result_leaks_detected, 0);
    assert_eq!(s.secret_aliases_unresolved, 0);
    assert_eq!(s.total_events_audited, 0);
    assert_eq!(s.sessions_covered, 0);
    assert!(s.chain_intact, "空链 trivially 完整");
    assert!(s.recent.is_empty());
}
