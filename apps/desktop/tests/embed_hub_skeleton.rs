//! v0.5 P1 ADR 0014 α1 — embed Hub 骨架守门测试。
//!
//! 4 条断言:
//! - (a) `gui_build_hub` 真组装出 `Arc<Hub>`,且 `approval_wait` == 300s
//!   (ISS-019 Phase 2 不变量,α1 不得回退到 v0.3 Stage 3 的 3s timing 权宜)
//! - (b) `Arc<Hub>` 满足 `Send + Sync + 'static`(`app.manage()` 的隐式约束)
//! - (c) Hub 内部与 caller 共享同一份 `Arc<Ledger>`(strong_count 至少 +1),
//!   证明 `gui_build_hub` **没**重 open ledger(避免与 gui.rs single-open 冲突)
//! - (d) `INVOKE_COMMANDS.len() == 28`(快照守门:gui-gated handler 总数;R3 ADR 0024 daemon/model
//!   接入 +5。注:公开仓 CI 不跑 `--features gui`,本快照仅本地 / release gui 测时校验,新增须人工同步)
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

/// (d) INVOKE_COMMANDS 快照守门(现 = 28)—— gui-gated handler 总数的人工快照。
///
/// R3(ADR 0024)接入 daemon/model GUI 卡:`daemon_status/start/stop` + `model_status/install`
/// = +5,接到公开仓既有 23 → **28**。本快照 `#![cfg(feature="gui")]`,而公开仓 CI 不跑
/// `--features gui`(见 ci.yml)→ 仅本地 / release gui 测时校验,故新增/删除 #[tauri::command]
/// 必须**人工**同步本断言 + commands.rs SSOT 三件套(commands.rs / vigils.rs generate_handler! /
/// capabilities/default.json);commands.rs 内的 in-sync 测只验三处一致,不锁绝对数,故由本快照兜底。
#[test]
fn invoke_commands_count_unchanged_in_alpha2() {
    assert_eq!(
        vigil_desktop::commands::INVOKE_COMMANDS.len(),
        28,
        "SSOT handler 数 = 28(既有 23 + R3 daemon/model 5:daemon_status/start/stop + \
         model_status/install)。新增/删除 #[tauri::command] 时,本快照 + commands.rs SSOT 三件套\
         (commands.rs / vigils.rs generate_handler! / capabilities/default.json)必须同步。"
    );
}
