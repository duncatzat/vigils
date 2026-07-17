//! v0.5 P1 ADR 0014 α1 — embed Hub 骨架守门测试。
//!
//! 4 条断言:
//! - (a) `gui_build_hub` 真组装出 `Arc<Hub>`,且 `approval_wait` == 300s
//!   (ISS-019 Phase 2 不变量,α1 不得回退到 v0.3 Stage 3 的 3s timing 权宜)
//! - (b) `Arc<Hub>` 满足 `Send + Sync + 'static`(`app.manage()` 的隐式约束)
//! - (c) Hub 内部与 caller 共享同一份 `Arc<Ledger>`(strong_count 至少 +1),
//!   证明 `gui_build_hub` **没**重 open ledger(避免与 gui.rs single-open 冲突)
//! - (d) `INVOKE_COMMANDS.len() == 22`(快照守门:α2 本身不新增 #[tauri::command],但其后
//!   α3-α5 / ISS / D19 新增 handler 时本断言随 SSOT 同步,漂移即失败)
//!
//! 本文件只在 `--features gui` 下编译,与 lib 模块 `vigil_desktop::embed`
//! 保持同步(模块本身也是 gui-feature-gated)。

#![cfg(feature = "gui")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use vigil_audit::Ledger;
use vigil_desktop::embed::gui_build_hub;
use vigil_mcp::Hub;

/// (a) approval_wait 默认 300s(ISS-019 Phase 2 守门)。
#[test]
fn gui_build_hub_returns_hub_with_default_approval_wait() {
    let ledger = Arc::new(Ledger::open_in_memory().expect("open in-memory ledger"));
    let hub = gui_build_hub(Arc::clone(&ledger)).expect("gui_build_hub should succeed");

    assert_eq!(
        hub.approval_wait(),
        Duration::from_secs(300),
        "embed Hub 必须保持 HubConfig::default().approval_wait = 300s,\
         不得回退到 v0.3 Stage 3 dev_permissive_firewall 的 3s timing 权宜 \
         (ISS-019 Phase 2 不变量;短轮询 fallback 见 \
         crates/vigil-audit/src/approvals.rs::wait_for_resolution)"
    );
}

/// (b) `Arc<Hub>` 编译期 Send + Sync + 'static —— `tauri::Manager::manage` 的隐式约束。
#[test]
fn arc_hub_is_send_sync_static() {
    const fn assert_send_sync_static<T: Send + Sync + 'static>() {}
    assert_send_sync_static::<Arc<Hub>>();
}

/// (c) Hub 与 caller 共享 `Arc<Ledger>`(strong_count 至少 +1),
/// 证明 `gui_build_hub` 没重 open ledger。
#[test]
fn gui_build_hub_shares_ledger_arc() {
    let ledger = Arc::new(Ledger::open_in_memory().expect("open in-memory ledger"));
    let pre = Arc::strong_count(&ledger);
    let _hub = gui_build_hub(Arc::clone(&ledger)).expect("gui_build_hub should succeed");
    let post = Arc::strong_count(&ledger);

    assert!(
        post > pre,
        "Hub 必须持 Arc<Ledger>(共享同一份,不重 open):\
         pre strong_count={pre} post strong_count={post};\
         若 post == pre 说明 Hub 内部没持 Ledger Arc,\
         那将与 ADR 0014 §3.4 的 single-ledger-open 约束相违"
    );
}

/// (d) INVOKE_COMMANDS 快照守门(现 = 26)—— α2 本身通过 Hub.resolve_approval 委托不新增 handler;
/// 其后 α3-α5 / ISS / D19(protection_summary)新增时本断言随 SSOT 同步。
///
/// 与 C1/C2 的关键区别:α2 的功能升级在既有 handler 函数体内部(改走
/// `hub.resolve_approval`)而非新增 #[tauri::command]。SSOT 三件套
/// (commands.rs / gui.rs generate_handler! / capabilities/default.json)零修改。
/// 见 ADR 0014 Revised α2 (TASK-005)。
#[test]
fn invoke_commands_count_unchanged_in_alpha2() {
    assert_eq!(
        vigil_desktop::commands::INVOKE_COMMANDS.len(),
        26,
        "SSOT handler 数 = 26(α1=1 + α2=3 + α3=3 + α4=10 + α5=2 + ISS-017=1 + ISS-018=1 + D19=1 + P1.3=2 + ③引擎=2)。\
         α2 本身不新增 handler(功能升级在 hub.resolve_approval 函数体内,见 ADR 0014 Revised α2);\
         其后 α3-α5 / ISS / D19(protection_summary)新增 handler 时,本快照 + commands.rs SSOT 三件套\
         必须同步。新增 handler 漂移即本断言失败,强制三处同步。"
    );
}
