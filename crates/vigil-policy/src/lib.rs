//! vigil-policy —— Rust 内置 policy DSL + 规则引擎(ADR 0003 §D3)。
//!
//! 核心数据:
//! - [`PolicyRule`] 由 `match_effects` / `conditions` / `action` / `priority` 组成
//! - [`PolicyEngine`] 负责对 `(ToolInvocation, EffectVector, risk_score)` 做裁决
//!
//! 评估顺序:
//! 1. 按 `priority` 降序遍历规则
//! 2. 规则 `match_effects` 与 `conditions` 全部成立才算"命中"
//! 3. 同 priority 多条命中时,fail-closed 偏序:`Deny > Approve > Allow`
//! 4. 无规则命中 → 兜底 `Deny`(AGENTS.md §6)

#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod defaults;
mod engine;

pub use defaults::default_pii_rules;
pub use engine::{
    Condition, DescriptorState, EffectField, PiiFindingSummary, PolicyAction, PolicyContext,
    PolicyDecision, PolicyEngine, PolicyError, PolicyRule, PolicyValue, DEFAULT_DENY_POLICY_ID,
};

/// 当前迭代号。
pub const ITERATION: &str = "I02+I03";
