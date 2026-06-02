//! # vigil-sdk
//!
//! Minimal stable SDK facade for embedding Vigil's local AI safety runtime into
//! 3rd-party tools. Published on crates.io as `vigil-sdk` (Apache-2.0).
//!
//! ## Status
//!
//! **已发布 0.1.0**(crates.io)。SDK pub surface 经 Codex review 守门。
//! 当前暴露的是**最小核心**:typed decisions/audit records + high-level
//! firewall execution + high-level redaction scanning。
//!
//! 显式**不在** SDK 中:server runtime(Hub / oracle)/ 运行时 backend(NoopEngine /
//! MockEngine / OrtEngine)/ ops 基建(bootstrap / model 分发)/ MCP 路由
//! / 凭据 (lease) / policy 引擎 internals。
//! 增加新项必经 codex review;**移除现项视为 breaking change,需 ADR 决策**。
//!
//! ## Quickstart
//!
//! ```rust
//! use vigil_sdk::prelude::*;
//!
//! // 高层 redaction:默认路径(NoopEngine + Hard 规则)即可命中 secret 类。
//! // soft 标签(email / phone / person 等)需 vigil-redaction 的 `ort` feature
//! // + 模型环境;不在 SDK Phase 1 暴露,sdk 给 consumer 用 default safe path。
//! let token = "ghp_0123456789abcdefghijklmnopqrstuvwxyz12";
//! let result: RedactionResult = scan_text(token).unwrap();
//! assert!(result.findings.iter().any(|f| f.kind == "github_token"));
//! ```
//!
//! ## Invariant 约定(SDK consumer 必须遵守)
//!
//! 1. **Fail-closed**:任何 SDK 函数返 [`ScanError`] / [`FirewallError`] 时,
//!    consumer **不可**降级为"放行"。所有错误路径默认走 deny。
//! 2. **绝不存原文**:SDK 接收的 input 文本不会被 SDK 持久化;consumer 也不应
//!    把原文写入 audit / log / 网络。审计走 [`DecisionRecord`] / [`AuditEvent`]
//!    (已守 no-plaintext 不变量)。
//! 3. **DecisionRecord 强制**:任何 effect 触发(tool invocation / approval / etc)
//!    必须 first 产出 [`DecisionRecord`]。**不存在** SDK API 让 consumer 跳过这步。
//! 4. **接口稳定**:SDK pub items 在 0.x 阶段允许小改进,但**移除**视为 breaking change;
//!    v1.0 freeze 后**仅可加,不可删**(SDK SemVer 政策守门,见下)。
//!
//! ## SemVer 政策
//!
//! - 当前在 0.1.x:可能小改 SDK item 签名(必经 codex review + ADR)
//! - v1.0 之后:freeze SDK pub items;新加项允许,删除/改签名禁止
//! - **non-SDK** crate(vigil-policy 等)仍可独立演进,与 SDK 解耦
//!
//! ## 哪些 v0.7 sprint 会扩 SDK?
//!
//! - **Phase 2 Performance**:可能加 `PiiScanner::scan_perf` benchmark hooks(roadmap-only)
//! - **Phase 3 Multi-Model**:加 ModelDescriptor + selection API
//!
//! ## 引用
//!
//! - 项目仓库:<https://github.com/duncatzat/vigils>

#![deny(unsafe_code)]
// v0.13.1 C5(2026-05-15):SDK 公开 surface 100% rustdoc coverage gate。
// 任何新加 pub item 缺 doc comment 即编译失败,SDK SemVer 稳定性的硬门。
#![deny(missing_docs)]

// ─────────────── Stable SDK re-exports(Phase 1)───────────────

// vigil-types: typed decisions / audit / approval / effect
pub use vigil_types::{
    ApprovalRequest, ApprovalResolution, ApprovalScope, ApprovalStatus, AuditEvent, DecisionKind,
    DecisionRecord, EffectKind, EffectVector, ToolInvocation,
};

// vigil-firewall: high-level firewall execution
pub use vigil_firewall::{
    EngineStatusReport, // v0.8 Sprint 1 A2(commit 68683e1)— Sprint 4 R1 补 re-export(Codex 019deb53)
    Firewall,
    FirewallConfig,
    FirewallError,
    FirewallOutcome,
    OAuthScopeContext,
    PiiScanner,
};

// vigil-redaction: high-level redaction scanning
pub use vigil_redaction::{
    // v0.10 Sprint 6 — advisory lang detect(Heuristic;永不可信,仅 advisory)
    detect_lang_heuristic,
    scan_text,
    scan_text_with_engine,
    // v0.7-α2 Phase 2D(ADR 0016 Fail-Closed Bottom Line):budget-aware scan +
    // 模型路径超时/错误退化 Hard-only。SDK consumer 用 budget API 对应 invariant #13
    // Enhanced path 超 budget 的退化路径决策。
    scan_text_with_engine_budgeted,
    scan_text_with_engine_with_hint,
    BudgetedScanOutcome,
    EngineStatus,
    Finding,
    FindingSource,
    // v0.10 Sprint 2 — typed LanguageHint(Decision A-prime;SDK 友好,fail-closed)
    LangHintSource,
    LanguageHint,
    PrivacyLabel,
    RedactionEngine,
    RedactionResult,
    RiskSignals,
    ScanError,
};

// vigil-mcp: descriptor hash(用于 audit 关联,不暴露 router/upstream/server 内部)
pub use vigil_mcp::descriptor_hash;

// ─────────────── v0.16 — high-level firewall facade(SDK-owned builder)───────────────
//
// 补全 SDK "firewall execution" 卖点:消费者只用 vigil-sdk 即可起 firewall 跑决策,
// 不暴露 Ledger / PolicyEngine / DescriptorOracle(内化,守 SDK 边界)。
// 设计 + Codex review trajectory:docs/operations/sdk-firewall-builder/spike.md。
pub mod firewall_builder;
pub use firewall_builder::{FirewallBuildError, FirewallBuilder, SdkFirewall};

// ─────────────── v0.8 Sprint 4 P3.1 — ensemble 浅级暴露(opt-in `ort` feature)───────────────
//
// **roadmap-v0.8 §2.4 ACCEPT**:暴露**配置级 API**(model_id 常量 + ensemble 工厂入口)
// 而**非**完整 trait(ModelDescriptor / EnsembleEngine 等等 dual_confirm 算法稳定再暴露)。
//
// **当前 v0.8 暴露范围**(锁定 SemVer):
// - 三 model_id 常量(stable string,SDK consumer 用作配置 / audit 跨表 join)
// - `ort_ensemble_scanner_arc_from_env`(企业 release runner 工厂入口 — 三模型 union)
//
// **不**暴露(留 v0.9+ 视 dual_confirm 真稳后视情决定):
// - `EnsembleEngine` 直接构造(避免 caller 自组 engines vec)
// - `EngineAttribution`(P2.0 内部诊断,Sprint 3 P2.1 决议不引入 per_label_min_engines)
// - `ModelDescriptor` trait(降模型变更频率风险)

/// SDK consumer 配置 / 审计跨表 join 用的稳定 model_id 字符串常量(v0.8)。
///
/// 与 `vigil_redaction::model_descriptor::OpenAIPrivacyFilterDescriptor.model_id()`
/// 等同源(若内部 ID 改,守门测试会捕捉)。
pub const SDK_MODEL_ID_OPENAI_PRIVACY_FILTER_V1: &str = "openai-privacy-filter-v1";
/// xlmr-pii-v1 stable model_id(35 BIO labels,multilang strong on address/account)。
pub const SDK_MODEL_ID_XLMR_PII_V1: &str = "xlmr-pii-v1";
/// yonigo-pii-v1 stable model_id(38 BIO labels,strong on email/phone)。
pub const SDK_MODEL_ID_YONIGO_PII_V1: &str = "yonigo-pii-v1";

/// **R1 MUST-FIX(Codex 019deb53)** — SDK 自拥有的 ensemble 工厂错误类型。
///
/// 直接 re-export `vigil-firewall` 工厂会让 vigil-firewall / vigil-redaction 的
/// `EngineError` 签名变化级联破 SDK SemVer。**SDK-owned wrapper**:thin facade
/// + 自有 `EngineFactoryError` enum,内部 wrap `vigil_redaction::engine::EngineError`,
///   暴露 stable variant + Display(consumer 可 match 主路径,Other 兜底未来扩展)。
///
/// **SemVer 政策**:`#[non_exhaustive]` 强制 caller 写 `_` 通配,允许加 variant
/// 不破 SemVer。Display 字符串可演进(MINOR);variant 名锁定(MAJOR 改)。
#[cfg(feature = "ort")]
#[derive(Debug)]
#[non_exhaustive]
pub enum EngineFactoryError {
    /// 模型目录不存在(env 未设 / 路径错 / 文件未下载完整)
    ModelNotFound {
        /// 上下文(env var 名 + 路径,无 PII)
        context: String,
    },
    /// ORT session / tokenizer 初始化失败(模型损坏 / ORT 版本不兼容)
    SessionInit {
        /// 失败原因(stable string,无 PII / 无原文)
        reason: String,
    },
    /// 其他底层错误(留 SemVer 缓冲)
    Other {
        /// 失败原因(可能含 vigil-redaction EngineError 的 Display)
        reason: String,
    },
}

#[cfg(feature = "ort")]
impl std::fmt::Display for EngineFactoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ModelNotFound { context } => write!(f, "model not found: {context}"),
            Self::SessionInit { reason } => write!(f, "session init failed: {reason}"),
            Self::Other { reason } => write!(f, "engine factory error: {reason}"),
        }
    }
}

#[cfg(feature = "ort")]
impl std::error::Error for EngineFactoryError {}

#[cfg(feature = "ort")]
impl From<vigil_redaction::engine::EngineError> for EngineFactoryError {
    fn from(e: vigil_redaction::engine::EngineError) -> Self {
        use vigil_redaction::engine::EngineError;
        match e {
            EngineError::ModelNotFound { dir } => Self::ModelNotFound { context: dir },
            EngineError::SessionInit(reason) | EngineError::TokenizerLoad(reason) => {
                Self::SessionInit { reason }
            }
            // 其他 variant(InferRun / DecodeShape / Internal 等)兜底 Other。
            // EngineError 是 non_exhaustive 的话此 _ 通配也 forward-compat。
            other => Self::Other {
                reason: format!("{other:?}"),
            },
        }
    }
}

/// 企业 release runner 三引擎 ensemble 工厂入口(opt-in `ort` feature)。
///
/// **SDK-owned wrapper(R1 MUST-FIX,Codex 019deb53)**:thin facade 委托
/// `vigil_firewall::ort_ensemble_scanner_arc_from_env`,但签名 pin 在 SDK 层
/// (输入 `()` / 输出 `Result<Arc<dyn PiiScanner>, EngineFactoryError>`),
/// vigil-firewall / vigil-redaction `EngineError` 签名变化不破 SDK SemVer。
///
/// 启动期 fail-fast:
/// - `VIGIL_ENSEMBLE_OPENAI_DIR` / `VIGIL_ENSEMBLE_XLMR_DIR` / `VIGIL_ENSEMBLE_YONIGO_DIR`
///   任一缺失 → [`EngineFactoryError::ModelNotFound`]
/// - ORT init 失败 → [`EngineFactoryError::SessionInit`]
/// - 三模型同时 init(eager;~17s cold,1.4-2.2GB RAM)
///
/// 适用场景:**企业 release runner**(EU recall 0.904 baseline 2026-05-03 P1.3 实测);
/// **不**适用 default GUI / hub-cli — 推荐 `ort_scanner_arc_from_env` 单 OpenAI engine
/// 路径(838MB RAM)。
///
/// # Errors
/// 见 [`EngineFactoryError`] 三 variant + 未来 SemVer-friendly 扩展。
#[cfg(feature = "ort")]
pub fn ort_ensemble_scanner_arc_from_env(
) -> Result<std::sync::Arc<dyn PiiScanner>, EngineFactoryError> {
    vigil_firewall::ort_ensemble_scanner_arc_from_env().map_err(Into::into)
}

// ─────────────── v0.10 Sprint 1 F 续 — typed XlmrProfileMode SDK 暴露 ───────────────

/// **v0.10 Sprint 1 F 续** — typed xlmr profile mode(替代裸 env)。
///
/// SDK consumer 用此 typed enum 替代 `VIGIL_XLMR_PROFILE` env 配置 xlmr 路径
/// threshold profile;**reproducible / inspectable / 可进 DecisionRecord**。
///
/// 行为(详见 [`vigil_redaction::model_descriptor::XlmrProfileMode`] doc):
/// - `Default`:v0.8 baseline(屏蔽 Email/Phone/Address;Person 不屏蔽,EU recall 0.904)
/// - `FpStrict`:v0.9 P0 opt-in(Default + Person 1.1;EU recall 0.887,FP -22%,
///   漏报 +45% — 仅企业 / 高 FP-strict 偏好场景)
///
/// **SemVer**:`#[non_exhaustive]` re-export from vigil-redaction;未来 vigil-redaction
/// 加 variant(如 `RecallFirst`)透传到此(MINOR)。variant 名锁定(MAJOR 改)。
pub use vigil_redaction::model_descriptor::XlmrProfileMode;

/// **v0.10 Sprint 1 F 续** — typed xlmr profile mode 的 ensemble 工厂入口。
///
/// **与 [`ort_ensemble_scanner_arc_from_env`] 区别**:caller 显式传 typed
/// [`XlmrProfileMode`],**忽略** `VIGIL_XLMR_PROFILE` env(SDK reproducible /
/// inspectable;不依赖 env 漂移)。三 model dir env(`VIGIL_ENSEMBLE_OPENAI_DIR` /
/// `_XLMR_DIR` / `_YONIGO_DIR`)仍读 — 这些是 ops 部署配置。
///
/// **SDK-owned wrapper**(对齐 v0.8 R1 教训):签名 pin SDK 层
/// (`-> Result<Arc<dyn PiiScanner>, EngineFactoryError>`),底层 vigil-firewall /
/// vigil-redaction `EngineError` 签名变化不破 SDK SemVer。
///
/// **典型用法**:
/// ```ignore
/// use vigil_sdk::{ort_ensemble_scanner_arc_with_xlmr_mode, XlmrProfileMode};
/// // SDK consumer 不依赖 env,reproducible 选 default(等价 v0.8 baseline)
/// let scanner = ort_ensemble_scanner_arc_with_xlmr_mode(XlmrProfileMode::Default)?;
/// // 企业 / 高 FP-strict 模式
/// let scanner = ort_ensemble_scanner_arc_with_xlmr_mode(XlmrProfileMode::FpStrict)?;
/// ```
///
/// # Errors
/// 见 [`EngineFactoryError`]:env unset(三 model dir 任一)/ 模型缺失 / ORT init 失败。
#[cfg(feature = "ort")]
pub fn ort_ensemble_scanner_arc_with_xlmr_mode(
    mode: XlmrProfileMode,
) -> Result<std::sync::Arc<dyn PiiScanner>, EngineFactoryError> {
    vigil_firewall::ort_ensemble_scanner_arc_from_env_with_xlmr_mode(mode).map_err(Into::into)
}

// ─────────────── Prelude — default safe path ───────────────

/// Prelude — 默认安全路径的常用导入。
///
/// `use vigil_sdk::prelude::*;` 即可获得 99% SDK consumer 需要的类型。
///
/// **不含**:`scan_text_with_engine`(高级 — 需自构 [`RedactionEngine`])、
/// `RedactionEngine` trait(扩展点,大多 consumer 用 default `scan_text`)、
/// `descriptor_hash`(audit 关联,advanced)。这些仍可显式从 `vigil_sdk::*`
/// 直接 import。
pub mod prelude {
    pub use crate::{
        scan_text, ApprovalRequest, ApprovalResolution, ApprovalScope, ApprovalStatus, AuditEvent,
        DecisionKind, DecisionRecord, EffectKind, EffectVector, Finding, FindingSource, Firewall,
        FirewallBuildError, FirewallBuilder, FirewallConfig, FirewallError, FirewallOutcome,
        OAuthScopeContext, PiiScanner, PrivacyLabel, RedactionResult, RiskSignals, ScanError,
        SdkFirewall, ToolInvocation,
    };
}

// ─────────────── SDK contract doc-tests ───────────────

/// 验证 SDK pub items 跨 crate 边界稳定可见(编译期 + doc-test 守门)。
///
/// ```
/// // 1. 类型可 import
/// use vigil_sdk::{Finding, FindingSource, PrivacyLabel};
/// use vigil_sdk::prelude::*;
///
/// // 2. scan_text 高层 API:secret 类(github_token)走 Hard rule(默认路径)
/// let r: RedactionResult = vigil_sdk::scan_text(
///     "ghp_0123456789abcdefghijklmnopqrstuvwxyz12"
/// ).unwrap();
/// assert!(!r.findings.is_empty(), "github_token Hard rule 应命中");
///
/// // 3. PrivacyLabel enum 完整:8 类
/// let _all = PrivacyLabel::ALL;
///
/// // 4. FindingSource 区分 Hard / Model 来源
/// let _hard = FindingSource::Hard;
/// ```
#[doc(hidden)]
pub fn __sdk_contract_visible() {}

/// v0.8 Sprint 4 P3.1 — ensemble 浅级暴露 doc-test 守门。
///
/// ```
/// // 1. model_id 常量可 import + 字符串语义稳定
/// use vigil_sdk::{
///     SDK_MODEL_ID_OPENAI_PRIVACY_FILTER_V1,
///     SDK_MODEL_ID_XLMR_PII_V1,
///     SDK_MODEL_ID_YONIGO_PII_V1,
/// };
///
/// assert_eq!(SDK_MODEL_ID_OPENAI_PRIVACY_FILTER_V1, "openai-privacy-filter-v1");
/// assert_eq!(SDK_MODEL_ID_XLMR_PII_V1, "xlmr-pii-v1");
/// assert_eq!(SDK_MODEL_ID_YONIGO_PII_V1, "yonigo-pii-v1");
///
/// // 2. 三常量字符串 distinct(防漂移到同一字符串)
/// let ids = [
///     SDK_MODEL_ID_OPENAI_PRIVACY_FILTER_V1,
///     SDK_MODEL_ID_XLMR_PII_V1,
///     SDK_MODEL_ID_YONIGO_PII_V1,
/// ];
/// let unique: std::collections::HashSet<_> = ids.iter().collect();
/// assert_eq!(unique.len(), 3, "三 model_id 必须 distinct");
/// ```
#[doc(hidden)]
pub fn __sdk_ensemble_v0_8_visible() {}

/// v0.7-α2 Phase 2D — budget-aware scan + EngineStatus 类型可见性守门
/// (ADR 0016 Fail-Closed Bottom Line)。
///
/// ```
/// use vigil_sdk::{BudgetedScanOutcome, EngineStatus};
///
/// // EngineStatus 三 variant 完整(Ok / DegradedTimeout / DegradedError)
/// let _ok = EngineStatus::Ok;
/// let _to = EngineStatus::DegradedTimeout;
/// let _er = EngineStatus::DegradedError;
///
/// // 类型可 import,签名稳定 — 函数实际用法见 vigil-redaction crate doc
/// let _budgeted_fn = vigil_sdk::scan_text_with_engine_budgeted;
/// // BudgetedScanOutcome 结构可见(构造由 SDK 内部完成)
/// fn _accept_outcome(_o: BudgetedScanOutcome) {}
/// ```
#[doc(hidden)]
pub fn __sdk_budgeted_visible() {}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// SDK pub items 必须能跨 crate 边界 import 且在编译期可见。
    /// 这个守门测试编译过即守住"SDK re-export 完整性"不变量。
    #[test]
    fn sdk_pub_items_compile_visible() {
        // 类型可 import + 实例化(编译期 + 运行期 sanity)
        let _: Option<DecisionKind> = None;
        let _: Option<EffectKind> = None;
        let _: Option<ApprovalStatus> = None;
        let _: Option<FindingSource> = Some(FindingSource::Hard);
        let _: Option<PrivacyLabel> = Some(PrivacyLabel::Email);
    }

    /// scan_text 默认路径:无 engine 注入 = NoopEngine(只跑 Hard 规则)。
    /// Hard 规则当前主要覆盖 secret 类(github_token / openai_secret / etc),
    /// soft 标签(email/phone/person/etc)依赖可选 ort engine model。
    /// 这是 SDK consumer 的 default-safe path 守门。
    #[test]
    fn sdk_scan_text_default_path() {
        // secret 类 Hard rule 命中 — github personal access token
        let secret = "ghp_0123456789abcdefghijklmnopqrstuvwxyz12";
        let r = scan_text(secret).expect("scan_text 成功");
        assert!(
            r.findings.iter().any(|f| f.kind == "github_token"),
            "Hard rule 应命中 github_token,findings: {:?}",
            r.findings
        );
    }

    /// scan_text 对 clean 文本不应误报 — 默认路径不会因为没 model engine 而崩。
    #[test]
    fn sdk_scan_text_clean_text_no_secret_findings() {
        let r = scan_text("This is a perfectly normal sentence.").expect("scan_text 成功");
        // 默认路径 0 model 推理,clean 文本不应有 secret 类 finding(soft 依赖 ort)
        assert!(
            !r.findings.iter().any(|f| f.kind == "github_token"
                || f.kind == "openai_secret_key"
                || f.kind == "stripe_secret_key"),
            "clean 文本不应触发任何 secret-类 hard rule"
        );
    }

    /// PrivacyLabel ALL 完整(防止 SDK 暴露的 enum 添加新 variant 时遗漏)。
    /// 当前 8 类:secret/account_number/email/phone/person/address/date/url。
    #[test]
    fn sdk_privacy_label_all_count() {
        // 这个 assert 在 PrivacyLabel 添加新 variant 时会 fail,触发 SDK 边界
        // review(SDK consumer 可能依赖 ALL 长度做 exhaustive 处理)
        assert_eq!(
            PrivacyLabel::ALL.len(),
            8,
            "PrivacyLabel ALL 长度变化是 SDK breaking change,需 ADR 决策"
        );
    }

    /// v0.8 Sprint 4 P3.1 — model_id 常量与 vigil-redaction descriptor 同源守门。
    ///
    /// SDK 暴露三 model_id 字符串常量,**必须**等于
    /// `OpenAIPrivacyFilterDescriptor / XlmrPiiDescriptor / YonigoPiiDescriptor`
    /// 内部 `model_id()` 返值。任一漂移即 SDK 与 backend 解耦,SDK consumer 用
    /// 常量 join audit ledger 会查不到。守门在此精确等值断言。
    #[test]
    fn sdk_model_id_constants_match_descriptor_source() {
        use vigil_redaction::model_descriptor::{
            ModelDescriptor, OpenAIPrivacyFilterDescriptor, XlmrPiiDescriptor, YonigoPiiDescriptor,
        };
        assert_eq!(
            SDK_MODEL_ID_OPENAI_PRIVACY_FILTER_V1,
            OpenAIPrivacyFilterDescriptor.model_id(),
            "SDK_MODEL_ID_OPENAI_PRIVACY_FILTER_V1 必须与 OpenAIPrivacyFilterDescriptor.model_id() 同源"
        );
        assert_eq!(
            SDK_MODEL_ID_XLMR_PII_V1,
            XlmrPiiDescriptor::default().model_id(),
            "SDK_MODEL_ID_XLMR_PII_V1 必须与 XlmrPiiDescriptor.model_id() 同源"
        );
        assert_eq!(
            SDK_MODEL_ID_YONIGO_PII_V1,
            YonigoPiiDescriptor.model_id(),
            "SDK_MODEL_ID_YONIGO_PII_V1 必须与 YonigoPiiDescriptor.model_id() 同源"
        );
    }

    /// v0.8 Sprint 4 P3.1 — `ort_ensemble_scanner_arc_from_env` 工厂入口可见性守门
    /// (`ort` feature 启用时)。
    ///
    /// 不实际跑工厂(需要 VIGIL_ENSEMBLE_*_DIR + 真模型);只验函数签名 import
    /// 跨 SDK 边界,等同 doc-test 编译期守门。
    #[cfg(feature = "ort")]
    #[test]
    fn sdk_ort_ensemble_factory_visible_with_feature() {
        let _factory: fn() -> Result<std::sync::Arc<dyn PiiScanner>, super::EngineFactoryError> =
            super::ort_ensemble_scanner_arc_from_env;
    }

    /// **v0.10 Sprint 6** — advisory lang detect re-export 守门。
    /// 关键不变量:detect 返 Heuristic source,lang_str 永返 None(D=C 锁定)。
    #[test]
    fn sdk_detect_lang_heuristic_advisory_only() {
        // CJK 高 confidence 但仍不可信任(Heuristic source)
        let h = super::detect_lang_heuristic("田中太郎さんが昨日来ました");
        assert_eq!(h.lang, "ja");
        assert_eq!(h.source, super::LangHintSource::Heuristic);
        assert!(h.confidence >= 0.85);
        assert_eq!(
            h.lang_str(),
            None,
            "advisory detect 必须返 None(防 production 决策 — D=C / feedback_lang_review_authoritative)"
        );

        // 短文本无关键词 → en 低 confidence
        let h_en = super::detect_lang_heuristic("John Smith works here.");
        assert_eq!(h_en.lang, "en");
        assert!(h_en.confidence < vigil_redaction::LANG_HINT_TRUSTED_CONFIDENCE);
    }

    /// **v0.10 Sprint 2** — LanguageHint typed wrapper re-export 守门
    /// (Decision A-prime;SDK 友好 + fail-closed 决策)。
    #[test]
    fn sdk_language_hint_typed_wrapper_visible() {
        // 1. typed wrapper 工厂方法
        let h_caller = super::LanguageHint::caller_provided("de");
        assert_eq!(h_caller.source, super::LangHintSource::CallerProvided);
        assert_eq!(h_caller.lang_str(), Some("de"));

        let h_fixture = super::LanguageHint::fixture("it");
        assert_eq!(h_fixture.source, super::LangHintSource::FixtureExperimental);

        // **关键不变量**:Heuristic source 即使 confidence=1.0 也返 None
        // (D=C 锁定下的 SDK 边界 — heuristic 不可作 production 决策权威)
        let h_heuristic = super::LanguageHint::heuristic("de", 1.0);
        assert_eq!(
            h_heuristic.lang_str(),
            None,
            "Heuristic source 必须返 None(feedback_lang_review_authoritative 约束)"
        );

        // 2. scan_text_with_engine_with_hint pub 可见
        let _scan: fn(
            &str,
            &dyn super::RedactionEngine,
            Option<&super::LanguageHint>,
        ) -> Result<super::RedactionResult, super::ScanError> =
            super::scan_text_with_engine_with_hint;

        // 3. non_exhaustive enum SemVer 文档化
        let _label = match super::LangHintSource::CallerProvided {
            super::LangHintSource::CallerProvided => "caller",
            super::LangHintSource::FixtureExperimental => "fixture",
            super::LangHintSource::Heuristic => "heuristic",
            _ => "unknown_future",
        };
    }

    /// **v0.10 Sprint 1 F 续** — XlmrProfileMode re-export + typed 工厂入口可见性守门。
    /// 编译期类型 + variant 完整性检查;运行期不跑(需 VIGIL_ENSEMBLE_*_DIR + 真模型)。
    #[cfg(feature = "ort")]
    #[test]
    fn sdk_ort_ensemble_with_xlmr_mode_factory_visible() {
        // 1. XlmrProfileMode re-export(2 variants 完整)
        let _default = super::XlmrProfileMode::Default;
        let _strict = super::XlmrProfileMode::FpStrict;

        // 2. 工厂入口签名 pin SDK 层
        let _factory: fn(
            super::XlmrProfileMode,
        )
            -> Result<std::sync::Arc<dyn PiiScanner>, super::EngineFactoryError> =
            super::ort_ensemble_scanner_arc_with_xlmr_mode;

        // 3. non_exhaustive 强制 _ 通配(SemVer 文档化)
        let _label = match super::XlmrProfileMode::Default {
            super::XlmrProfileMode::Default => "default",
            super::XlmrProfileMode::FpStrict => "fp_strict",
            _ => "unknown_future",
        };
    }

    /// v0.8 Sprint 4 R1(Codex 019deb53)— EngineFactoryError 类型守门:
    /// SDK consumer 必须能 match 主 variant + Other 兜底(non_exhaustive)。
    #[cfg(feature = "ort")]
    #[test]
    fn sdk_engine_factory_error_variants_matchable() {
        let e = super::EngineFactoryError::ModelNotFound {
            context: "test".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("model not found"));

        // crate 内部穷举所有 variant(EngineFactoryError 在本 crate 同 module);
        // 加新 variant 时 compiler force update 本 test。**外部 SDK consumer** 因
        // #[non_exhaustive] 必须写 `_` 兜底 — 这条不变量由 sdk_engine_factory_error_*
        // 类守门测试覆盖,本 test 验内部使用契约。
        match e {
            super::EngineFactoryError::ModelNotFound { .. } => {}
            super::EngineFactoryError::SessionInit { .. } => {}
            super::EngineFactoryError::Other { .. } => {}
        }
    }

    /// v0.8 Sprint 4 R1 — EngineStatusReport re-export 守门(Codex MUST-FIX 3)。
    /// guide §4.2 列 EngineStatusReport 是 v0.8 SDK pub item;此测试断言真可见。
    #[test]
    fn sdk_engine_status_report_pub_re_exported() {
        let _ok = super::EngineStatusReport::Ok;
        let _to = super::EngineStatusReport::DegradedTimeout;
        let _err = super::EngineStatusReport::DegradedError;
        let _un = super::EngineStatusReport::Unsupported;
    }
}
