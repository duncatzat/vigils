//! vigil-runner-types
//!
//! Pure types + env policy for Vigil sandbox runner(ADR 0018 v0.13 split)。
//!
//! 公共 API:
//! - `ExecutionPlan` / `RunnerKind` / `RunnerSpecific` / `ExecutionResult` / `SandboxProfile`
//! - `RunnerError` / `RejectField`
//! - `NullAuditSink` / `RunnerAuditSink` / `RunnerEvent`
//! - `ScrubCallback`(type alias)
//! - `apply_native_env_policy` / `RESERVED_SYSTEM_ENV_KEYS` / `is_reserved_env_key`
//!
//! **不在**:`WasmRunner` / `spawn_native` / `default_scrub` / `leak_scan`
//! (这些含 wasmtime / sandbox-linux / vigil-redaction impl,留 `vigil-runner` 主 crate)。

#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod audit;
pub mod env_policy;
pub mod error;
pub mod plan;

pub use audit::{NullAuditSink, RunnerAuditSink, RunnerEvent};
pub use env_policy::{
    apply_mcp_upstream_env_policy, apply_native_env_policy, is_reserved_env_key, ScrubCallback,
    MCP_UPSTREAM_ENV_ALLOWLIST, RESERVED_SYSTEM_ENV_KEYS,
};
pub use error::{RejectField, RunnerError};
pub use plan::{ExecutionPlan, ExecutionResult, RunnerKind, RunnerSpecific, SandboxProfile};
