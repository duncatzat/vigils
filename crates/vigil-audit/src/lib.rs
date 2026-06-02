//! vigil-audit
//!
//! I01 实装:SQLite (WAL) append-only 账本 + hash chain + FTS5 检索 + ToolCallSpan
//! 时序约束 + approval 最小原语。详见 ADR 0002。

#![deny(missing_docs)]
#![forbid(unsafe_code)]
// 测试代码允许 unwrap/expect(AGENTS.md "Implementation rules" 明确允许)。
// 运行时路径(ledger/span)维持 workspace lint 的 warn 级别限制。
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod approvals;
pub mod error;
pub mod hash;
mod ledger;
mod outbox;
mod registry;
mod span;

pub use approvals::ApprovalTargetContext;
// v0.7-α6 A1(E6a):engine.degraded 事件 typed payload(audit/firewall 解耦,
// 用 stable string code 而非 enum,防 audit crate 循环依赖 firewall 类型)
pub use approvals::EngineDegradedPayload;
pub use error::{AuditError, Result};
#[allow(deprecated)]
pub use ledger::RESERVED_EVENT_PREFIX;
pub use ledger::{
    AppendedEvent, EventDetailRow, EventHit, Ledger, NewRedactionFinding, NewRedactionScan,
    RedactionFindingRow, RedactionScanRow, ReplayEvent, SessionSummaryRow,
    ALLOWED_REDACTION_LABELS, RESERVED_EVENT_PREFIXES,
};
pub use outbox::{OutboxItem, OutboxKind, OutboxStatus};
pub use registry::{
    argv_hash, is_reserved_env_key_name, secret_ref_fingerprint, vigil_http_auth_metadata,
    CommandDrift, PinOutcome, RegistryError, ResolvedProgramDrift, ResolvedProgramOutcome,
    SandboxProfileRow, SandboxProfileUpsertResult, SecretRefEntry, ServerOnboardingData,
    StoredServerProfile, ToolApprovalCard, ToolSecretBinding,
};
pub use span::{Decided, Opened, ToolCallSpan};

/// 当前迭代号。
pub const ITERATION: &str = "I01";

#[cfg(test)]
mod smoke {
    use super::*;

    #[test]
    fn iteration_is_i01() {
        assert_eq!(ITERATION, "I01");
    }

    #[test]
    fn re_export_vigil_types() {
        // 保留 I00 的可见性检查
        let _ = std::mem::size_of::<vigil_types::AuditEvent>();
    }
}
