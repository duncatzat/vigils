//! vigil-desktop I08a:CLI 协议消费层。
//!
//! 拆成 lib + bin 两份:lib 实现 `dispatch(cmd, ledger, capability) -> Result<UiResponse, UiError>`
//! 纯函数,binary 做 clap 解析 + ANSI 渲染。这让 §12.3 I08 四条验收可通过**集成测试**直接跑
//! `dispatch(...)`,无需 subprocess。
//!
//! 安全契约(ADR 0008 §I-8.1 ~ §I-8.6):
//! - 协议层不直接暴露 Ledger;只通过 `&Ledger` 借用
//! - 写命令必经 `capability == Capability::Write` 检查
//! - argv 由 registry 层已 lint secret-in-argv,此处只复述

#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

/// I08b-β1 Tauri `#[tauri::command]` 真白名单 SSOT(与 build.rs 通过 `include!` 共用)。
///
/// 详见 `commands.rs` 顶部注释(因 include! 约束采用 `//` 而非 `//!`)。
pub mod commands;
pub mod dispatcher;
/// ISS-018 — Safe Export 渲染层(MD / HTML)。读已脱敏 payload,纯字符串组装。
pub mod export;
/// I08b-β5 Ledger 磁盘持久化路径解析(依赖注入 + 在默认 feature 下测试守门)。
///
/// 详见 `ledger_path.rs` 顶部注释。
pub mod ledger_path;
pub mod render;

/// v0.5 P1 ADR 0014 α1 — GUI bin embed Hub 骨架(gui-feature-gated)。
///
/// 详见 `embed.rs` 顶部注释。
#[cfg(feature = "gui")]
pub mod embed;

/// ADR 0024 — 「ML 控制平面」GUI 驱动 vigil-hub CLI 的常驻 daemon 生命周期 + ML 模型安装
/// (gui-feature-gated;shell-out 调度,不把 ort 拉进 GUI)。
///
/// 详见 `ml_control.rs` 顶部注释。
#[cfg(feature = "gui")]
pub mod ml_control;

pub use dispatcher::dispatch;
