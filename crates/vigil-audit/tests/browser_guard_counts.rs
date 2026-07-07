//! `Ledger::browser_guard_counts` 的数据层测试(Phase 2「策略+观测」:桌面
//! Protection Overview 浏览器防线卡的 24h 窗口统计)。
//!
//! 覆盖:三类 browser.* 事件按 payload `action` 归类计数 + 非浏览器噪声不入统计 +
//! 畸形 payload 只计 checks 不计动作 + 窗口过滤(未来 cutoff → 全零)+ 空账本全零。

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::json;
use vigil_audit::{Ledger, BROWSER_GUARD_EVENT_TYPES};

#[test]
fn browser_guard_counts_by_action_and_window() {
    let l = Ledger::open_in_memory().unwrap();
    let sid = l.start_session("browser_host", None).unwrap();

    // 2 block + 3 redact + 1 allow,分布在三类事件类型上(与 native-host 真实写入同形:
    // metadata-only payload,action 字段承载动作)。
    l.append_event(
        &sid,
        "browser.paste_checked",
        &json!({"action":"block","origin":"https://x.com"}),
        Some("browser.paste_checked origin:https://x.com action:\"block\""),
    )
    .unwrap();
    l.append_event(
        &sid,
        "browser.submit_checked",
        &json!({"action":"block","origin":"https://y.com"}),
        None,
    )
    .unwrap();
    for _ in 0..3 {
        l.append_event(
            &sid,
            "browser.input_checked",
            &json!({"action":"redact","origin":"https://z.com"}),
            None,
        )
        .unwrap();
    }
    l.append_event(
        &sid,
        "browser.paste_checked",
        &json!({"action":"allow","origin":"https://ok.com"}),
        None,
    )
    .unwrap();
    // 噪声:非浏览器事件绝不入统计。
    l.append_event(&sid, "hello.world", &json!({"action":"block"}), None)
        .unwrap();

    let c = l.browser_guard_counts(0).unwrap();
    assert_eq!(c.checks, 6, "三类 browser.* 全计,噪声不计");
    assert_eq!(c.blocked, 2);
    assert_eq!(c.redacted, 3);

    // 窗口过滤:cutoff 在未来 → 全零(created_at 为写入时刻)。
    let far_future = 4_102_444_800; // 2100-01-01
    let none = l.browser_guard_counts(far_future).unwrap();
    assert_eq!((none.checks, none.blocked, none.redacted), (0, 0, 0));
}

#[test]
fn malformed_payload_counts_check_but_no_action() {
    let l = Ledger::open_in_memory().unwrap();
    let sid = l.start_session("browser_host", None).unwrap();
    // payload 无 action 字段 / action 非字符串:计 checks,不计 blocked/redacted,不 Err。
    l.append_event(&sid, "browser.paste_checked", &json!({"x":1}), None)
        .unwrap();
    l.append_event(&sid, "browser.input_checked", &json!({"action":7}), None)
        .unwrap();
    let c = l.browser_guard_counts(0).unwrap();
    assert_eq!((c.checks, c.blocked, c.redacted), (2, 0, 0));
}

#[test]
fn empty_ledger_is_all_zero() {
    let l = Ledger::open_in_memory().unwrap();
    let c = l.browser_guard_counts(0).unwrap();
    assert_eq!((c.checks, c.blocked, c.redacted), (0, 0, 0));
}

/// 常量本身的最小卫生守门:恰 3 类、全 `browser.` 前缀(与写入端的精确集合相等性
/// 由 native-host 侧 `browser_guard_event_types_exactly_match_event_type_for` 守门,
/// 那里能同时看到 vigil-browser 与本 crate)。
#[test]
fn event_types_const_shape() {
    assert_eq!(BROWSER_GUARD_EVENT_TYPES.len(), 3);
    assert!(BROWSER_GUARD_EVENT_TYPES
        .iter()
        .all(|t| t.starts_with("browser.")));
}
