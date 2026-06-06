//! vigil-firewall —— I02+I03 Firewall Core(ADR 0003)。
//!
//! 组件:
//! - [`EffectExtractor`](extract::EffectExtractor) trait + 7 个内置 extractor
//! - [`RiskScorer`](scorer::RiskScorer):可解释权重表
//! - [`Firewall`]:把上述三者缝合成 `evaluate_tool_call` 的高层流程
//!
//! 使用流程(由 I04 MCP Hub 调用):
//! ```text
//! Firewall::evaluate(invocation)
//!     ├─ extractors.extract() → EffectVector
//!     ├─ scorer.score()       → (risk, reasons)
//!     ├─ policy.evaluate()    → PolicyDecision
//!     ├─ audit.record_decision(...)
//!     └─ 若 Approve → ledger.create_approval(...) → 返回 Approve(request)
//! ```

#![deny(missing_docs)]
#![forbid(unsafe_code)]
// extract.rs 静态 Regex 使用 expect("regex")(字面常量,编译期错误立刻发现)。
// 运行时路径不含 unwrap;测试中 unwrap 由 cfg_attr 放开。
#![allow(clippy::expect_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]
// FirewallOutcome 的三个 variant 大小差异较大,但语义上用值传递、频率低,
// 额外的 Box 不值得(审计路径上这些值生命周期短)。
#![allow(clippy::large_enum_variant)]

mod engine;
pub mod extract;
// ISS-010 R2:T0 preflight helper + PiiScanner trait。主体 pub(crate),仅把 trait
// 和 test-only scanner 通过 lib 级 re-export 暴露(允许 integration test 注入 mock)。
mod preflight;
pub mod scorer;

pub use engine::{Firewall, FirewallConfig, FirewallError, FirewallOutcome, OAuthScopeContext};
// 转发 policy 的兜底 floor 保留 id —— 下游(vigil-mcp 的 monitor floor 降级)用它**不可伪造**地
// 识别 default-deny floor;vigil-mcp 只把 vigil-policy 作 dev-dep,故经 vigil-firewall 这条正式依赖暴露。
pub use vigil_policy::DEFAULT_DENY_POLICY_ID;
// R2 BLOCKER 2 + R2 NICE:只暴露 `PiiScanner` trait(Firewall::with_scanner 签名需要)。
// `DefaultScanner` 和 `FailingScanner` 是实现细节 —— 生产 caller 不需直接构造
// DefaultScanner(Firewall::new 内部选择);测试可本地实现 PiiScanner trait(见
// tests/preflight.rs::TestFailingScanner)。
pub use preflight::PiiScanner;
// v0.8 Sprint 1 A2 — scanner 状态汇报枚举(Codex § 2 改进版 A:default Unsupported)。
// `Firewall::evaluate` hook 用此判 scanner 是否退化,落 engine_degraded 审计。
pub use preflight::EngineStatusReport;
// ISS-008 Phase 2 T3:`--features ort` 路径下额外暴露 OrtEngine 工厂。
// 类型 `OrtPiiScanner` 保持 crate-private —— caller 只感知 `Arc<dyn PiiScanner>`,
// 不接触 ort 边界(避免 caller 间接拉 ort 类型)。
#[cfg(feature = "ort")]
pub use preflight::ort_scanner_arc_from_env;
// v0.7-α2 Phase 2D-fw(ADR 0016 § 5.4):带 budget 版本的 ORT scanner 工厂,
// 模型推理超 budget 即退化 Hard-only(fail-closed)。生产推荐 budget = 2s。
#[cfg(feature = "ort")]
pub use preflight::ort_scanner_arc_from_env_with_budget;
// v0.7-α5 R1g+(E6a):三引擎 ensemble scanner 工厂 — 把 vigil-redaction
// EnsembleEngine 接到 PiiScanner trait,production firewall 多语言 recall 路径。
// 需 VIGIL_ENSEMBLE_{OPENAI,XLMR,YONIGO}_DIR 三 env;1.4-2.2GB RAM,opt-in。
#[cfg(feature = "ort")]
pub use preflight::ort_ensemble_scanner_arc_from_env;
// v0.10 Sprint 1 F 续 — typed XlmrProfileMode 工厂入口(忽略 VIGIL_XLMR_PROFILE env)
#[cfg(feature = "ort")]
pub use preflight::ort_ensemble_scanner_arc_from_env_with_xlmr_mode;

/// 当前迭代号。
pub const ITERATION: &str = "I02+I03";
