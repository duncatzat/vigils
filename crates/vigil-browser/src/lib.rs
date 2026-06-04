//! vigil-browser
//!
//! I09a(ADR 0009):Browser Extension 的 Core/Host 契约层。
//!
//! 对外 API:
//! - [`BrowserCheckRequest`] / [`BrowserCheckResponse`] / [`FindingKind`] / [`BrowserAction`] /
//!   [`BrowserErrorFrame`] / [`BrowserErrorCode`]
//! - [`classify`] + [`ClassifyOutcome`]
//! - [`read_frame`] / [`write_frame`] / [`MAX_MESSAGE_BYTES`]
//! - [`build_audit_payload`] / [`event_type_for`]
//! - [`validate_browser_origin`]
//!
//! 严格遵守 ADR 0009 的 6 条安全不变量(§I-9.1 ~ §I-9.6)。

#![deny(missing_docs)]
#![forbid(unsafe_code)]
// 仅允许 `Regex::new(...).expect("regex")` 形式的启动期静态编译(失败即开发期 bug,
// 启动即崩更易发现)。运行时数据路径上不含任何 unwrap/expect;规则同 vigil-redaction。
#![allow(clippy::expect_used)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::panic))]

mod audit;
mod classifier;
mod framing;
mod origin;
mod protocol;

pub use audit::{
    build_audit_payload, event_type_for, BrowserAuditMeta, EVENT_INPUT, EVENT_PASTE, EVENT_SUBMIT,
};
pub use classifier::{classify, ClassifyOutcome};
pub use framing::{read_frame, write_frame, MAX_MESSAGE_BYTES};
pub use origin::validate_browser_origin;
pub use protocol::{
    BrowserAction, BrowserCheckRequest, BrowserCheckResponse, BrowserErrorCode, BrowserErrorFrame,
    BrowserEventKind, FindingKind, RULE_PROFILE_VERSION,
};

/// 当前迭代号。
pub const ITERATION: &str = "I09a";
