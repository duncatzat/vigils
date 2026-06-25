//! ISS-005:Stage 2 T0 统一 scan 入口(`scan_text`)。
//!
//! **本 Stage 1 scaffold 语义**(ADR 0013 + `docs/design/vigil-redaction-selection.md`):
//! - 只跑 v0.3 硬指纹路径(`HARD_RULES`)→ 映射成 `Vec<Finding>` 作为 merge 的 hard 侧输入
//! - Model 侧置空(真模型推理接入留给 **ISS-008**;届时在本函数内部扩 hard + model 组合
//!   调用 `merge_findings`,外部 API 形态保持不变)
//! - 产出统一 `RedactionResult { findings, redacted_text, risk_signals }`
//!
//! **fail-closed 不变量**:
//! - 空输入返 `Err(EmptyInput)`(**不**返 OK 空 findings,避免 caller 误判"已扫并安全")
//! - 内部纯字符串运算,不引入 panic 路径;未来 ISS-008 接入模型时,推理失败应返
//!   `Err(InferenceFailed { .. })`,由 caller 决定 block 还是降级
//!
//! **risk_delta 分级**(ADR 0012 §1.3,Stage 1 简化实装):
//! - Secret 类(服务凭证泄漏):25
//! - Email / Internal IP / URL(识别身份/拓扑):10
//! - 其它 PII(person / phone / address / date / account_number):5
//!
//! **Stage 1 简化口径说明**(ISS-010 R1 新发现 2):roadmap 曾提议细粒度分级
//! (如 account_number +15 / phone +10 / 多命中 +10),但 Stage 1 scaffold 为保持
//! 实装最小 / 测试可守门,采用**粗粒度 3 档**(Secret / Url&Email / 其他)。
//! 细粒度分级 + 多命中加权留给 **ISS-008 真模型接入**同步实装;届时 ADR 0012 §1.3
//! Revised 段会明确新口径。在那之前,firewall 侧 `PolicyContext.risk_score` 仅
//! 消费本层透传的 `total_risk_delta`,不在 caller 重算分级(避免规则漂移)。
//!
//! 本层不关心 "caller 要不要 block" —— 只给数据,由 ISS-010 firewall preflight 决策。

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use crate::engine::{NoopEngine, RedactionEngine};
use crate::label::PrivacyLabel;
use crate::merge::{merge_findings, Finding};
use crate::HARD_RULES;

/// `scan_text` 的综合输出。
///
/// 与 v0.3 `(Value, String)` 的 `redact` 返值不同:本 API 面向 **Stage 2 文本扫描**
/// 场景(firewall preflight / browser classifier / CLI scan),返回结构化 findings
/// 供 caller 按需拼 UI / 累加 risk。
#[derive(Debug, Clone, PartialEq)]
pub struct RedactionResult {
    /// 合并后的 findings,按 `span.start` 升序(继承 `merge_findings` 不变量)。
    /// 元素类型是 ISS-013 的 `Finding`,`source` 字段可区分 Hard / Model。
    pub findings: Vec<Finding>,
    /// 原文按 findings 的 span 全部替换为 `[REDACTED <label>]` 后的脱敏文本。
    ///
    /// 替换策略:
    /// - `PrivacyLabel::from_kind` 命中 → `[REDACTED <label.as_str()>]`(稳定外部契约)
    /// - 未命中 → `[REDACTED <raw_kind>]`(兼容未来新 kind,不阻塞实装)
    pub redacted_text: String,
    /// 聚合风险信号,供 caller 快速判定"是否有 secret"/"总风险分"。
    pub risk_signals: RiskSignals,
}

/// 聚合风险信号。纯派生数据,可从 `findings` 重算;先算好避免 caller 每次重跑。
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RiskSignals {
    /// 按 `PrivacyLabel` 分档计数(未识别 kind 不计入此 map,但仍保留在 findings)。
    pub counts_by_label: BTreeMap<PrivacyLabel, u32>,
    /// 总风险分 = `sum(finding.risk_delta)`。
    /// 继承 ISS-013 D4 不变量:同 span 重叠时 Model 已在 merge 时被 drop,不双倍。
    pub total_risk_delta: u32,
    /// 是否含至少一个 `Secret` 类 finding(caller 可直接作 fail-closed 早判)。
    pub has_secret: bool,
}

/// `scan_text` 错误类型。Stage 1 scaffold 主要覆盖 `EmptyInput`;
/// `InferenceFailed` 为 ISS-008 真模型接入预留 variant,现阶段不会由本函数返出。
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    /// 未来真模型(onnxruntime / Transformers.js via native host)推理失败时返此。
    /// caller 应视为 fail-closed:不要降级为"空 findings = 安全"。
    #[error("inference failed: {reason}")]
    InferenceFailed {
        /// 失败原因(模型名 / backend / errno 等);不应含用户原文内容。
        reason: String,
    },
    /// 空输入约定:scaffold 对空输入返 Err 而非空 OK,避免 caller 误以为"已扫并安全"。
    /// 调用点应该在上游用 `if input.is_empty() { .. }` 明确决策分支。
    #[error("empty input not allowed (use Option before calling)")]
    EmptyInput,
}

/// Stage 2 T0 统一入口:扫描文本,产出 findings + 脱敏文本 + 风险信号。
///
/// # Stage 1 scaffold 可产出边界(R1 MUST-FIX 1 修复)
///
/// **本函数当前(Stage 1)只运行 `HARD_RULES`**,因此能端到端产出 finding 的
/// `PrivacyLabel` 仅覆盖**硬指纹可识别**的 3 类:
///
/// | 可产出 | label 对应 kind(HARD_RULES name) |
/// |--|--|
/// | [`PrivacyLabel::Secret`] | aws_access_key_id / github_token / anthropic_api_key / openai_api_key / jwt / pem_private_key / env_assignment / slack_webhook / stripe_secret_key / google_api_key / gitlab_pat / database_url |
/// | [`PrivacyLabel::Email`]  | email(**注**:v0.3 HARD_RULES 的 `email` 规则在 `ALL_RULES` 里,但 **不在 `HARD_RULES` 里**,因此当前 Stage 1 `scan_text` 实际**也不会产出 Email finding**。见下文"Stage 1 实测覆盖") |
/// | [`PrivacyLabel::Url`]    | internal_ipv4(同上,`internal_ipv4` 不在 `HARD_RULES`,Stage 1 也不产出) |
///
/// **Stage 1 实测覆盖**:上表的 Email / Url 受 `HARD_RULES` 豁免影响,当前 scan_text
/// 只对 `Secret` 类输入端到端产 finding。其余 5 类 —— [`PrivacyLabel::AccountNumber`] /
/// [`PrivacyLabel::Phone`] / [`PrivacyLabel::Person`] / [`PrivacyLabel::Address`] /
/// [`PrivacyLabel::Date`] —— 需要 **ISS-008 真模型(OpenAI Privacy Filter via ONNX
/// Runtime 1.24)**接入后才会被识别。caller **不应**假设 Stage 1 能覆盖 8 类全部。
///
/// ## 为什么 email / internal_ipv4 不在 HARD_RULES
/// 见 `crates/vigil-redaction/src/lib.rs` §HARD_RULES 注释:这两类在合法业务上下文
/// 里频繁出现,硬指纹直接拦会导致大量误报;改由 ISS-008 模型层给出软标签 + 上下文
/// 加权,而不是零门槛 regex。
///
/// # Errors
/// - [`ScanError::EmptyInput`]:`input` 为空字符串(fail-closed:**不**返 OK 空 findings)
/// - [`ScanError::InferenceFailed`]:Stage 1 不会触发(留给 ISS-008 真模型路径)
pub fn scan_text(input: &str) -> Result<RedactionResult, ScanError> {
    // ISS-008 Phase 1:`scan_text` 等价委托到 `scan_text_with_engine(input, &NoopEngine)`。
    // NoopEngine.infer 永远返 Ok(vec![]),与 Stage 1 scaffold 原 "merge_findings(&hard, &[])"
    // 行为完全一致 —— v0.3 公共 API 形态 / `scan_text_v03_public_api_intact` 守门测试均不动。
    scan_text_with_engine(input, &NoopEngine)
}

/// 引擎可注入版本的 [`scan_text`](ISS-008 Phase 1)。
///
/// 与 [`scan_text`] 唯一区别:Model 侧 findings 由 `engine.infer(input)` 产出,
/// 而非硬编码空向量。所有 hard / merge / redact / aggregate 逻辑零分叉复用。
///
/// # 不变量
/// - **EmptyInput fail-closed**:与 [`scan_text`] 一致,空输入返 [`ScanError::EmptyInput`]
/// - **engine 失败 fail-closed**:`engine.infer` 返 `Err` → 经
///   `From<crate::engine::EngineError> for ScanError` 塌缩到
///   [`ScanError::InferenceFailed`](`reason` 不含 input 内容,由 caller 保证)
/// - **risk_delta 注入**:engine 产 Finding 时不知道 risk 分级表(ADR 0012 §1.3 SSOT
///   在本层),本函数逐条按 [`risk_of`] 补值;engine 与 risk 表彻底解耦,避免新增 kind
///   时出现"两处都写错就漂移"
/// - **merge 策略 SSOT 不下放**:hard × model 重叠决策仍由 [`merge_findings`] 编排
///   (ADR 0013 D3)
///
/// # Errors
/// - [`ScanError::EmptyInput`]:`input` 为空字符串
/// - [`ScanError::InferenceFailed`]:`engine.infer` 失败
pub fn scan_text_with_engine(
    input: &str,
    engine: &dyn RedactionEngine,
) -> Result<RedactionResult, ScanError> {
    // **v0.9 Sprint 1 P1.2**:legacy 路径 → scan_text_with_engine_with_lang(.., None)
    // (lang None 等价 v0.8 行为;不命中 lang_conditional_profile.overrides)
    scan_text_with_engine_with_lang(input, engine, None)
}

/// **v0.9 Sprint 1 P1.2** — lang-aware 版本(spike)。
///
/// 与 [`scan_text_with_engine`] 同口径(Hard + Model 合并 / risk_delta 注入 /
/// merge_findings 决策),唯一区别:**engine.infer_with_lang(input, lang)** 取代
/// `engine.infer(input)`,让 engine 内部 threshold 应用走 lang-conditional 路径
/// (若 engine 实现支持,如 `OrtEngine` for `XlmrPiiDescriptor`)。
///
/// **lang 参数**:
/// - `Some("en"|"de"|"it"|"fr"|...)`:case-sensitive,推荐 ISO 639-1 lowercase;
///   命中 (lang, label) override 即按 lang-conditional threshold 屏蔽
/// - `None`:等价 [`scan_text_with_engine`],engine 走 default `threshold_profile()`
///
/// **caller 责任**:lang 来源 — fixture lang 字段透传 / 业务上下文 / 启发式
/// (`feedback_lang_review_authoritative` 警告:启发式不可作权威);若不确定
/// 应传 `None` 走 default 安全路径。
///
/// # Errors
/// 同 [`scan_text_with_engine`]:[`ScanError::EmptyInput`] / [`ScanError::InferenceFailed`]
pub fn scan_text_with_engine_with_lang(
    input: &str,
    engine: &dyn RedactionEngine,
    lang: Option<&str>,
) -> Result<RedactionResult, ScanError> {
    if input.is_empty() {
        return Err(ScanError::EmptyInput);
    }

    // engine 失败 → ? + From<EngineError> for ScanError → InferenceFailed(fail-closed)
    let mut model_findings = engine.infer_with_lang(input, lang)?;
    // risk_delta 由 caller 补(C-7);engine 不依赖 risk 表,避免分级口径双写漂移。
    for f in &mut model_findings {
        f.risk_delta = risk_of(f.kind);
    }

    // v0.7-α3 R1a:除 HARD_RULES(secret 类子集)外,补 ALL_RULES url 类
    // (generic_url + internal_ipv4)— Phase 3 ensemble 路径需 url canonical
    // 兜底(yonigo 仅 IP / xlmr 无 url native)。提升 hard 路径完备性,无回归
    // risk:既有测试 Hard secret 仍命中,新增 url canonical 通过 PrivacyLabel::Url
    // 累加 risk_delta=10。
    let mut hard_findings = collect_hard_findings(input);
    hard_findings.extend(collect_url_hard_findings(input));
    let merged = merge_findings(&hard_findings, &model_findings);

    let redacted_text = build_redacted_text(input, &merged);
    let risk_signals = aggregate_risk(&merged);
    Ok(RedactionResult {
        findings: merged,
        redacted_text,
        risk_signals,
    })
}

/// v0.7-α2 Phase 2D(ADR 0016 Fail-Closed Bottom Line):模型路径执行状态。
///
/// caller 通过 [`BudgetedScanOutcome::status`] 拿到本枚举,用于审计 ledger
/// 标记(`decision_id = model_path_degraded`)与 UI 展示退化原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineStatus {
    /// 模型路径在 budget 内成功完成;`findings` 含 Hard + Model 完整合并
    Ok,
    /// 模型路径超 budget(timeout);退化到 Hard-only,`findings` 缺 Model 增强语义
    /// (Hard 路径继续守 secret 类,fail-closed 不变量保留)
    DegradedTimeout,
    /// 模型路径返 [`crate::engine::EngineError`];同样退化到 Hard-only。
    /// 字段为 stringified reason(诊断用,`reason` 不含 input 内容)
    DegradedError,
}

/// v0.7-α2 Phase 2D — [`scan_text_with_engine_budgeted`] 输出。
///
/// 区别于 [`RedactionResult`]:多带一个 [`EngineStatus`] 标记供 caller 决策审计/UI。
#[derive(Debug, Clone)]
pub struct BudgetedScanOutcome {
    /// 与 [`scan_text_with_engine`] 同形态;findings 已合并(Hard + 可能的 Model)
    pub result: RedactionResult,
    /// 模型路径执行状态(Ok / DegradedTimeout / DegradedError)
    pub status: EngineStatus,
}

/// v0.7-α2 Phase 2D(ADR 0016)— 带 budget 的 scan,模型路径超时即退化 Hard-only。
///
/// **不变量**(ADR 0016 § 2.2 Fail-Closed Bottom Line):
/// - **空输入 fail-closed**:与 [`scan_text`] 一致,空输入返 [`ScanError::EmptyInput`]
/// - **退化非 fail-open**:模型 timeout / error → 退化路径仍跑 Hard 规则,Hard 类
///   `secret` 命中正常拦截;**绝不**返空 findings 假装"已扫并安全"
/// - **engine.infer 不可被中断**:`std::sync::mpsc::recv_timeout` 仅放弃等待,后台
///   worker thread 继续跑直到 ORT inference 自然结束(orphan thread 风险可控,因
///   ORT 推理终会 ~462ms 自然完成)
/// - **caller 责任**:拿到 `EngineStatus::Degraded*` 后,审计 ledger 应 append
///   `engine.degraded` 事件 + `decision_id = model_path_degraded`(本层不写 ledger,
///   保持纯函数语义)
///
/// **线程模型**:engine 必须 `Arc<dyn RedactionEngine + 'static>`(spawn 需 'static)。
///
/// # Errors
/// - [`ScanError::EmptyInput`]:`input` 为空字符串
///
/// 注意:engine 失败 / timeout **不** propagate 为 Err;退化为 Hard-only 成功路径,
/// caller 通过 `status` 字段判断。这是与 [`scan_text_with_engine`] 的核心区别 ——
/// 后者 fail-closed 把 engine 错误传给 caller,本 API 把"模型路径增强"视为 best-effort。
pub fn scan_text_with_engine_budgeted(
    input: &str,
    engine: Arc<dyn RedactionEngine>,
    budget: Duration,
) -> Result<BudgetedScanOutcome, ScanError> {
    if input.is_empty() {
        return Err(ScanError::EmptyInput);
    }

    // 启 worker thread 跑 engine.infer;主线程等 budget,超时则放弃等待
    let (tx, rx) = std::sync::mpsc::channel();
    let input_owned = input.to_string();
    let engine_for_thread = Arc::clone(&engine);
    std::thread::spawn(move || {
        let res = engine_for_thread.infer(&input_owned);
        // tx.send 失败(接收端已 timeout drop)即静默丢弃,worker 自然结束
        let _ = tx.send(res);
    });

    let (mut model_findings, status) = match rx.recv_timeout(budget) {
        Ok(Ok(findings)) => (findings, EngineStatus::Ok),
        Ok(Err(_engine_err)) => {
            // engine 内部失败 → 退化 Hard-only;诊断信息丢弃避免 reason 泄露 input
            (Vec::new(), EngineStatus::DegradedError)
        }
        Err(_recv_timeout) => {
            // budget 超 → 放弃等待 worker(后台仍跑直到自然结束)
            (Vec::new(), EngineStatus::DegradedTimeout)
        }
    };

    // risk_delta 注入(与 scan_text_with_engine 同口径)
    for f in &mut model_findings {
        f.risk_delta = risk_of(f.kind);
    }

    // v0.7-α3 R1a:除 HARD_RULES(secret 类子集)外,补 ALL_RULES url 类
    // (generic_url + internal_ipv4)— Phase 3 ensemble 路径需 url canonical
    // 兜底(yonigo 仅 IP / xlmr 无 url native)。提升 hard 路径完备性,无回归
    // risk:既有测试 Hard secret 仍命中,新增 url canonical 通过 PrivacyLabel::Url
    // 累加 risk_delta=10。
    let mut hard_findings = collect_hard_findings(input);
    hard_findings.extend(collect_url_hard_findings(input));
    let merged = merge_findings(&hard_findings, &model_findings);
    let redacted_text = build_redacted_text(input, &merged);
    let risk_signals = aggregate_risk(&merged);

    Ok(BudgetedScanOutcome {
        result: RedactionResult {
            findings: merged,
            redacted_text,
            risk_signals,
        },
        status,
    })
}

/// 把 v0.3 `HARD_RULES` 的命中转换成带 span 的 `Finding` 列表。
///
/// 与 `scan_hard_findings`(v0.3 只返规则名)的区别:这里需要 `find_iter` 拿出
/// 每个命中的 `(start, end)`,供 `merge_findings` 做 span-overlap 决策。
///
/// **纪律**:
/// - 同规则可在同文本多次命中 → 产出多个 Finding(每个 Match 一条)
/// - 不同规则命中重叠片段时,保留两条 —— 由 `merge_findings` 的后续稳定排序
///   与 caller 审计侧决策是否去重(这里不做筛选,避免吃掉 caller 信息)
/// - 顺序:按 `HARD_RULES` 声明顺序 × `find_iter` 位置顺序 append;
///   `merge_findings` 最后按 `span.start` 升序稳定排序
fn collect_hard_findings(text: &str) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    for rule in HARD_RULES.iter() {
        for m in rule.pattern.find_iter(text) {
            out.push(Finding::hard(
                rule.name,
                (m.start(), m.end()),
                risk_of(rule.name),
            ));
        }
    }
    out
}

/// v0.7-α3 R1a(E6a) — 收集 ALL_RULES 中 **url 类** 命中(`generic_url` +
/// `internal_ipv4`),补 [`HARD_RULES`] secret-only 子集对 url canonical 的覆盖
/// 不足(P3-spike R1 暴露 gap)。
///
/// **设计纪律**:
/// - 不动 [`HARD_RULES`](保 vigil-browser RULE_PROFILE_VERSION v5 守门数字)
/// - 仅在 `scan_text_with_engine` 路径调用(scan_text 默认调 NoopEngine 也走此
///   路径,默认 v0.3 测试不破:secret 仍命中,新增 url 是增量信号)
/// - canonical 经 [`crate::PrivacyLabel::from_kind`] 路由:`generic_url` /
///   `internal_ipv4` → [`crate::PrivacyLabel::Url`]
/// - risk_delta = 10(URL 类,ADR 0012 §1.3)
fn collect_url_hard_findings(text: &str) -> Vec<Finding> {
    use crate::ALL_RULES;
    let mut out: Vec<Finding> = Vec::new();
    for rule in ALL_RULES.iter() {
        // 只挑 url canonical 类(generic_url + internal_ipv4);其他 ALL_RULES 命中
        // 应仍由 HARD_RULES 走默认路径(避免 email 等被加进 hard 路径破 v0.3 期望)
        if rule.name == "generic_url" || rule.name == "internal_ipv4" {
            for m in rule.pattern.find_iter(text) {
                out.push(Finding::hard(
                    rule.name,
                    (m.start(), m.end()),
                    risk_of(rule.name),
                ));
            }
        }
    }
    out
}

/// 风险分级(ADR 0012 §1.3):Secret = 25 / Email | Url = 10 / 其它 PII = 5。
///
/// 入参是 `Finding.kind` 字面量;未知 kind 走 PII 默认 5(保守估值,不 0 避免"隐式忽略")。
///
/// **可见性**:`pub(crate)` 因为 `scan_text_with_engine` 内部要按 kind 给 engine 产出的
/// model findings 补 risk_delta;crate 外不应直接调,risk 注入是本层职责。
pub(crate) fn risk_of(kind: &str) -> u32 {
    match PrivacyLabel::from_kind(kind) {
        Some(PrivacyLabel::Secret) => 25,
        Some(PrivacyLabel::Email) | Some(PrivacyLabel::Url) => 10,
        Some(_) => 5,
        None => 5,
    }
}

/// 按 findings 的 span 替换为 `[REDACTED <label>]`;替换文案走 `PrivacyLabel::as_str()`
/// (稳定契约),未识别 kind 降级用原字面量,保证不丢信息。
///
/// **重叠 span 的 leak 安全性(VIGIL-SEC-OVERLAP 审计修正)**:`merge_findings` 只去掉与
/// Hard 重叠的 Model,但 **Hard×Hard / Model×Model 内部仍会重叠**(env_assignment 套
/// github_token;模型对相邻实体吐嵌套 person/address span)。
///
/// 旧实现靠"按 start **降序** + 内层先 `replace_range` + 外层 `end > out.len()` 越界跳过"
/// 达成 leak 安全 —— 但该不变量**仅当外层独有前缀非密时成立**(env_assignment 的 `KEY=` 前缀)。
/// 若外层独有前缀本身是 PII(模型嵌套 span:外 `[0,40]` person 套内 `[15,40]` person),内层
/// 替换缩短串令外层 `end > len` 被跳过 → 外层前缀 `[0,15]` 明文 PII **泄漏**(标准复现:
/// `"Jonathan Whitfield Robert Smith Junior"` → `"Jonathan Whitfi[REDACTED person]"`)。
///
/// 故改为与网关 [`crate::redact_string`] 同款 **并集合并**:重叠 span 先合并成互不重叠的
/// `[min_start, max_end)` 区间,再单次替换。保证每个被任一 finding 命中的字节都落入某个被替换
/// 区间(leak-safe),且占位符良构(无嵌套破碎)。`overlapping_hard_spans_no_leak` +
/// `model_overlap_no_leak` 回归测试锁定该不变量。
fn build_redacted_text(input: &str, findings: &[Finding]) -> String {
    // 拷贝 + 排序:start 升序;同 start 时 end **降序**(长 span 作并集代表名,与网关
    // redact_string 对齐)。不改 caller 给的 findings。
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by(|a, b| a.span.0.cmp(&b.span.0).then(b.span.1.cmp(&a.span.1)));

    // 重叠区间**并集合并**(leak-safe):代表 kind 取并集内 start 最小→span 最长者(排序已保证)。
    // 越界 / 非 char boundary 的手工构造 Finding 在并入前剔除,避免 replace_range panic。
    let mut merged: Vec<(usize, usize, &str)> = Vec::with_capacity(sorted.len());
    for f in sorted {
        let (start, end) = f.span;
        if start > end
            || end > input.len()
            || !input.is_char_boundary(start)
            || !input.is_char_boundary(end)
        {
            continue;
        }
        match merged.last_mut() {
            // 重叠(strict-less,相邻 end==start 不算)→ 扩展并集上界;代表名保持先者
            Some(last) if start < last.1 => {
                if end > last.1 {
                    last.1 = end;
                }
            }
            _ => merged.push((start, end, f.kind)),
        }
    }

    // 右→左替换:merged 已 start 升序且互不重叠,从后往前替换不影响前面区间 index。
    let mut out = input.to_string();
    for &(start, end, kind) in merged.iter().rev() {
        let placeholder = match PrivacyLabel::from_kind(kind) {
            Some(label) => format!("[REDACTED {}]", label.as_str()),
            None => format!("[REDACTED {}]", kind),
        };
        out.replace_range(start..end, &placeholder);
    }
    out
}

/// 聚合 findings 为 `RiskSignals`。
fn aggregate_risk(findings: &[Finding]) -> RiskSignals {
    let mut counts: BTreeMap<PrivacyLabel, u32> = BTreeMap::new();
    let mut total: u32 = 0;
    for f in findings {
        total = total.saturating_add(f.risk_delta);
        if let Some(label) = PrivacyLabel::from_kind(f.kind) {
            *counts.entry(label).or_insert(0) += 1;
        }
        // 未识别 kind:risk 已累加,count 不落档(避免"未知桶"污染精确断言)
    }
    let has_secret = counts.contains_key(&PrivacyLabel::Secret);
    RiskSignals {
        counts_by_label: counts,
        total_risk_delta: total,
        has_secret,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{EngineError, RedactionEngine};
    use crate::merge::{Finding, FindingSource};
    use std::sync::Mutex;

    // ─── v0.9 Sprint 1 P1.2 — lang transport 守门 ───

    /// 捕获 caller 传入的 lang 参数,验证 scan_text_with_engine_with_lang 真把
    /// lang 透传到 engine.infer_with_lang,且 legacy scan_text_with_engine 调用
    /// engine.infer(lang None 等价路径)。
    struct LangCapturingMockEngine {
        captured: Mutex<Vec<Option<String>>>,
    }

    impl LangCapturingMockEngine {
        fn new() -> Self {
            Self {
                captured: Mutex::new(Vec::new()),
            }
        }

        fn captured(&self) -> Vec<Option<String>> {
            self.captured.lock().unwrap().clone()
        }
    }

    impl RedactionEngine for LangCapturingMockEngine {
        fn infer(&self, _text: &str) -> Result<Vec<Finding>, EngineError> {
            // legacy 路径:走 default(等价 infer_with_lang(text, None))
            self.captured.lock().unwrap().push(None);
            Ok(Vec::new())
        }

        fn infer_with_lang(
            &self,
            text: &str,
            lang: Option<&str>,
        ) -> Result<Vec<Finding>, EngineError> {
            // P1.2 路径:override 捕获 lang;若 caller 传 None 走 self.infer
            // (与 trait default 一致;但本测试 override 让两路径可分辨)
            if lang.is_none() {
                return self.infer(text);
            }
            self.captured.lock().unwrap().push(lang.map(String::from));
            Ok(Vec::new())
        }
    }

    /// scan_text_with_engine(legacy 入口)→ engine.infer(等价 lang None)
    #[test]
    fn scan_text_with_engine_calls_infer_no_lang() {
        let engine = LangCapturingMockEngine::new();
        let _ = scan_text_with_engine("hello world test", &engine).unwrap();
        let captured = engine.captured();
        assert_eq!(captured, vec![None], "legacy 路径应走 infer (lang=None)");
    }

    /// scan_text_with_engine_with_lang(text, engine, None)→ engine.infer
    /// (lang None 等价 legacy 路径,不走 lang-conditional)
    #[test]
    fn scan_text_with_engine_with_lang_none_equivalent_to_legacy() {
        let engine = LangCapturingMockEngine::new();
        let _ = scan_text_with_engine_with_lang("hello world test", &engine, None).unwrap();
        let captured = engine.captured();
        assert_eq!(
            captured,
            vec![None],
            "lang None 应等价 legacy 路径(走 infer)"
        );
    }

    /// scan_text_with_engine_with_lang(text, engine, Some("de"))→ engine.infer_with_lang
    /// 透传真实 lang 字符串
    #[test]
    fn scan_text_with_engine_with_lang_transports_real_lang() {
        let engine = LangCapturingMockEngine::new();
        let _ = scan_text_with_engine_with_lang("hello world test", &engine, Some("de")).unwrap();
        let captured = engine.captured();
        assert_eq!(
            captured,
            vec![Some("de".to_string())],
            "lang Some 应通过 infer_with_lang 透传 caller 字符串"
        );
    }

    /// EmptyInput fail-closed 路径在 lang-aware 入口同样成立(不应调用 engine)
    #[test]
    fn scan_text_with_engine_with_lang_empty_input_fail_closed() {
        let engine = LangCapturingMockEngine::new();
        let r = scan_text_with_engine_with_lang("", &engine, Some("de"));
        assert!(matches!(r, Err(ScanError::EmptyInput)));
        assert!(engine.captured().is_empty(), "空输入早返,不应调用 engine");
    }

    // ──────────────────────────── 空输入 fail-closed ────────────────────────────
    #[test]
    fn scan_text_empty_input_fail_closed() {
        let r = scan_text("");
        assert!(
            matches!(r, Err(ScanError::EmptyInput)),
            "空输入应返 EmptyInput,实际: {:?}",
            r
        );
    }

    // ──────────────────────────── Secret 类(Hard 路径)────────────────────────────
    #[test]
    fn scan_text_secret_variant() {
        // 用真实 github token 形态(ghp_ + 40 chars)
        let text = "log: token = ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ is rotated";
        let r = scan_text(text).expect("非空应成功");
        assert!(!r.findings.is_empty(), "应命中 github_token");
        assert!(r.findings.iter().any(|f| f.kind == "github_token"));
        assert!(r.risk_signals.has_secret, "counts 应含 Secret 桶");
        assert!(
            r.risk_signals
                .counts_by_label
                .get(&PrivacyLabel::Secret)
                .copied()
                .unwrap_or(0)
                >= 1
        );
        // redacted_text 不得含原 token
        assert!(!r
            .redacted_text
            .contains("ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"));
        assert!(r.redacted_text.contains("[REDACTED secret]"));
    }

    // ──────────────────────────── Email 类 ────────────────────────────
    // 注:HARD_RULES 不含 email(email 在 ALL_RULES 但 HARD_RULES 刻意豁免,
    // 避免误伤合法上下文;见 lib.rs §HARD_RULES 注释)。因此 Hard 路径不产生
    // email finding;必须走 Model 路径(直接构造)来验证 Email 桶映射。
    // 该覆盖在 scan_text_email_via_model_mock 中完成。
    //
    // 但 scan_hard_findings(v0.3 公开 API)对 email 的覆盖已由现有 lib.rs 测试保障,
    // 本层只保证:若 caller 将来把 email 塞进 Finding,映射正确。

    #[test]
    fn scan_text_email_via_model_mock() {
        // 构造 Model 侧 Finding,验证 from_kind("private_email") 进 Email 桶
        let model_email = Finding::model("private_email", (8, 28), 0.99, 10);
        let merged = merge_findings(&[], &[model_email]);
        let signals = aggregate_risk(&merged);
        assert_eq!(
            signals.counts_by_label.get(&PrivacyLabel::Email).copied(),
            Some(1)
        );
    }

    // ──────────────────────────── Url 类(internal_ipv4)────────────────────────────
    // internal_ipv4 同样不在 HARD_RULES(见 lib.rs 注释)。走 Model 构造验证映射。
    #[test]
    fn scan_text_url_variant() {
        // 直接校验 PrivacyLabel 映射契约
        assert_eq!(
            PrivacyLabel::from_kind("internal_ipv4"),
            Some(PrivacyLabel::Url)
        );
        // 通过构造 Finding 走 aggregate_risk 路径验证
        let ip = Finding::model("private_url", (12, 25), 0.95, 10);
        let merged = merge_findings(&[], &[ip]);
        let signals = aggregate_risk(&merged);
        assert_eq!(
            signals.counts_by_label.get(&PrivacyLabel::Url).copied(),
            Some(1)
        );
    }

    // ──────────────────────────── Model 专属标签映射 ────────────────────────────
    #[test]
    fn scan_text_person_via_model_mock() {
        let f = Finding::model("private_person", (0, 13), 0.9, 5);
        let merged = merge_findings(&[], &[f]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].source, FindingSource::Model);
        assert_eq!(
            PrivacyLabel::from_kind(merged[0].kind),
            Some(PrivacyLabel::Person)
        );
        let signals = aggregate_risk(&merged);
        assert_eq!(
            signals.counts_by_label.get(&PrivacyLabel::Person).copied(),
            Some(1)
        );
    }

    #[test]
    fn scan_text_phone_via_model_mock() {
        let f = Finding::model("private_phone", (5, 18), 0.88, 5);
        let merged = merge_findings(&[], &[f]);
        let signals = aggregate_risk(&merged);
        assert_eq!(
            signals.counts_by_label.get(&PrivacyLabel::Phone).copied(),
            Some(1)
        );
    }

    #[test]
    fn scan_text_address_via_model_mock() {
        let f = Finding::model("private_address", (10, 50), 0.91, 5);
        let merged = merge_findings(&[], &[f]);
        let signals = aggregate_risk(&merged);
        assert_eq!(
            signals.counts_by_label.get(&PrivacyLabel::Address).copied(),
            Some(1)
        );
    }

    #[test]
    fn scan_text_date_via_model_mock() {
        let f = Finding::model("private_date", (20, 30), 0.96, 5);
        let merged = merge_findings(&[], &[f]);
        let signals = aggregate_risk(&merged);
        assert_eq!(
            signals.counts_by_label.get(&PrivacyLabel::Date).copied(),
            Some(1)
        );
    }

    #[test]
    fn scan_text_account_number_via_model_mock() {
        let f = Finding::model("private_account_number", (0, 16), 0.97, 5);
        let merged = merge_findings(&[], &[f]);
        let signals = aggregate_risk(&merged);
        assert_eq!(
            signals
                .counts_by_label
                .get(&PrivacyLabel::AccountNumber)
                .copied(),
            Some(1)
        );
    }

    // ──────────────────────────── 完整脱敏往返 ────────────────────────────
    #[test]
    fn scan_text_roundtrip_redacts_all_findings() {
        // 两类 secret:github + anthropic
        let token = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ";
        let anth = "sk-ant-api03_ABCDEFGHIJKLMNOPQRSTUVWX";
        let text = format!("one {token} two {anth} three");
        let r = scan_text(&text).expect("非空");
        assert!(
            r.findings.len() >= 2,
            "至少 2 条 finding,实际 {}: {:?}",
            r.findings.len(),
            r.findings
        );
        // 脱敏文本完全不含原始 secret
        assert!(
            !r.redacted_text.contains(token),
            "github token 原文泄漏:{}",
            r.redacted_text
        );
        assert!(
            !r.redacted_text.contains(anth),
            "anthropic key 原文泄漏:{}",
            r.redacted_text
        );
        // 替换后应含两处 [REDACTED secret]
        let count = r.redacted_text.matches("[REDACTED secret]").count();
        assert!(count >= 2, "应至少 2 处 [REDACTED secret],实际 {count}");
        // has_secret 必为真
        assert!(r.risk_signals.has_secret);
    }

    // ──────────────────────────── D4 不双倍加权回归 ────────────────────────────
    #[test]
    fn scan_text_risk_signals_no_double_weighting() {
        // 复用 ISS-013 merge 决策:Hard + 同 span Model 应只计 Hard 一次
        // 直接构造两侧 Finding 走 aggregate_risk(因为 scan_text Stage 1 model 置空)
        let hard = vec![Finding::hard("email", (10, 30), 10)];
        let model = vec![Finding::model("private_email", (10, 30), 1.0, 10)];
        let merged = merge_findings(&hard, &model);
        assert_eq!(merged.len(), 1, "同 span 重叠应只留 Hard");
        let signals = aggregate_risk(&merged);
        assert_eq!(
            signals.total_risk_delta, 10,
            "重叠时只计 Hard 一次,不应累加到 20"
        );
        // 对照:非重叠时两者都计
        let model2 = vec![Finding::model("private_email", (100, 120), 1.0, 10)];
        let merged2 = merge_findings(&hard, &model2);
        let s2 = aggregate_risk(&merged2);
        assert_eq!(s2.total_risk_delta, 20, "非重叠时应 Hard + Model 累加");
    }

    // ──────────────── D16 审计:重叠 Hard span 的 leak 安全性回归 ────────────────
    /// `env_assignment` 包裹内层硬 secret(`KEY=ghp_...`)会让两条 Hard 规则同位重叠。
    /// 锁定 `build_redacted_text` 在此重叠下:① 绝不泄漏内层硬 secret;② 占位符良构
    /// (无 D16 那种破碎 `] github_token]`)。本路径靠"内层(start 更大)先 replace_range +
    /// 外层越界跳过"达成 leak 安全,而非并集合并 —— 此测试防未来规则改动破坏该不变量。
    #[test]
    fn overlapping_hard_spans_no_leak() {
        let gh = "ghp_aBcD1234567890aBcD1234567890aBcD1234"; // 40 字符硬指纹(非真实 secret)
        for input in [
            format!("api_token={gh}"),        // env_assignment 与 github 共终点
            format!("token={gh}.suffixdata"), // github 内层结束于 env 之前(非共终点)
            format!("a={gh} b={gh}"),         // 两段独立重叠组
        ] {
            let r = scan_text(&input).unwrap();
            assert!(
                !r.redacted_text.contains(gh),
                "内层硬 secret 泄漏:in={input:?} out={:?}",
                r.redacted_text
            );
            // 占位符良构:`[REDACTED` 与 `]` 数量相等(D16 破碎占位符会不等)
            let opens = r.redacted_text.matches("[REDACTED").count();
            let closes = r.redacted_text.matches(']').count();
            assert_eq!(
                opens, closes,
                "占位符不配对(破碎):in={input:?} out={:?}",
                r.redacted_text
            );
            assert!(
                opens >= 1,
                "应至少一处脱敏:in={input:?} out={:?}",
                r.redacted_text
            );
        }
    }

    // ──────────────────────────── v0.3 pub API 不变回归 ────────────────────────────
    // 证据等级:feedback_production_logic_testable —— 公共 API 必须进默认测试矩阵,
    // 任何删除 / 重命名 / 签名漂移都应被此测试捕获。
    #[test]
    fn scan_text_v03_public_api_intact() {
        // 1) redact(&Value) -> (Value, String)
        let v = serde_json::json!({"token": "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"});
        let (redacted, summary) = crate::redact(&v);
        let s = serde_json::to_string(&redacted).expect("ser");
        assert!(!s.contains("ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"));
        // key-hint 命中,summary 应有 finding 条目
        assert!(summary.contains("finding:"));

        // 2) scrub_text(&str) -> String
        let out = crate::scrub_text("token = ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ");
        assert!(!out.contains("ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"));
        assert!(out.contains("[REDACTED"));

        // 3) scan_hard_findings(&str) -> Vec<&'static str>
        let names = crate::scan_hard_findings("x = ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ");
        assert!(names.contains(&"github_token"));

        // 4) detect_hard_secret(&str) -> Option<&'static str>
        assert_eq!(
            crate::detect_hard_secret("x=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"),
            Some("github_token")
        );
        assert_eq!(crate::detect_hard_secret("hello"), None);

        // 5) ITERATION 常量不变
        assert_eq!(crate::ITERATION, "I01");
    }

    // ──────────────────────────── build_redacted_text 边界防御 ────────────────────────────
    /// 手工构造越界 span 不应 panic(防御性测试)
    #[test]
    fn build_redacted_text_out_of_bounds_span_is_skipped() {
        let bad_finding = Finding::hard("github_token", (100, 200), 25);
        let out = build_redacted_text("short text", &[bad_finding]);
        assert_eq!(out, "short text", "越界 span 应跳过,原文不变");
    }

    /// UTF-8 非 char boundary span 不应 panic
    #[test]
    fn build_redacted_text_non_char_boundary_is_skipped() {
        // "你好" 在 UTF-8 下每字 3 字节;span (1, 5) 切在中间
        let text = "你好 world";
        let bad = Finding::model("private_person", (1, 5), 0.9, 5);
        let out = build_redacted_text(text, &[bad]);
        // 跳过则原文不变;不崩就算通过
        assert_eq!(out, text);
    }

    /// VIGIL-SEC-OVERLAP 回归:**模型嵌套 / 跨类重叠 span** 必须 leak-safe + 占位符良构。
    /// 旧"右→左 + 越界跳过"实现下,内层(start 更大)替换缩短串令外层 `end > len` 被跳过,
    /// 外层独有的 PII 前缀明文泄漏。union-merge 修复后并集全覆盖,无泄漏、无破碎占位符。
    #[test]
    fn model_overlap_no_leak() {
        // ① 嵌套同类:外 person [0,40] 套内 person [15,40](内层长→缩串→旧实现跳外层)。
        //    旧输出 "Jonathan Whitfi[REDACTED person]"(前缀泄漏);修复后并集 [0,40) 全脱敏。
        let input = "Jonathan Whitfield Robert Smith Junior!!";
        let findings = vec![
            Finding::model("private_person", (0, 40), 0.9, 5),
            Finding::model("private_person", (15, 40), 0.9, 5),
        ];
        let out = build_redacted_text(input, &findings);
        assert!(!out.contains("Jonathan"), "外层 PII 前缀泄漏:{out:?}");
        assert!(!out.contains("Whitfi"), "外层 PII 前缀泄漏:{out:?}");
        assert_eq!(out, "[REDACTED person]", "嵌套同类应并集为单一占位符");

        // ② 跨类部分重叠:address [0,47] 与 email [41,54] 交叠(a<c<b<d)。
        //    旧实现产 "[REDACTED address]TED email]"(破碎);修复后并集 [0,54) 良构。
        let input2 = "742 Evergreen Terrace Springfield, email jw@clinic.org";
        let findings2 = vec![
            Finding::model("private_address", (0, 47), 0.9, 5),
            Finding::model("private_email", (41, 54), 0.9, 5),
        ];
        let out2 = build_redacted_text(input2, &findings2);
        assert!(!out2.contains("Evergreen"), "address 泄漏:{out2:?}");
        assert!(!out2.contains("jw@clinic.org"), "email 泄漏:{out2:?}");
        assert_eq!(
            out2.matches("[REDACTED").count(),
            out2.matches(']').count(),
            "占位符破碎(开闭不配对):{out2:?}"
        );

        // ③ 非重叠 span 仍各自独立占位符(防 union-merge 过度合并回归)。
        let input3 = "Bob from Berlin";
        let findings3 = vec![
            Finding::model("private_person", (0, 3), 0.9, 5),
            Finding::model("private_address", (9, 15), 0.9, 5),
        ];
        let out3 = build_redacted_text(input3, &findings3);
        assert_eq!(
            out3.matches("[REDACTED").count(),
            2,
            "非重叠应保两占位符:{out3:?}"
        );
    }

    // ──────────────────────────── risk_of 分级回归 ────────────────────────────
    #[test]
    fn risk_of_tiers_match_adr_0012() {
        assert_eq!(risk_of("github_token"), 25, "Secret = 25");
        assert_eq!(risk_of("anthropic_api_key"), 25);
        assert_eq!(risk_of("email"), 10, "Email = 10");
        assert_eq!(risk_of("internal_ipv4"), 10, "Url = 10");
        assert_eq!(risk_of("private_person"), 5, "Person = 5");
        assert_eq!(risk_of("private_date"), 5, "Date = 5");
        // 未知 kind 保守 5
        assert_eq!(risk_of("not_a_kind"), 5, "未知 kind 保守 5");
    }

    // ──────────────────── v0.7-α2 Phase 2D — budgeted scan + degraded fallback ────────────────────
    // EngineError 已在测试模块顶层 import(P1.2 加,line 433)

    /// 慢 engine mock:用 sleep 模拟 ORT inference 长延迟,触发 budget timeout
    struct SleepyEngine {
        dur: Duration,
    }
    impl RedactionEngine for SleepyEngine {
        fn infer(&self, _text: &str) -> Result<Vec<Finding>, EngineError> {
            std::thread::sleep(self.dur);
            Ok(Vec::new())
        }
    }

    /// 错误 engine mock:立即返 Err,触发 DegradedError 路径
    struct ErrorEngine;
    impl RedactionEngine for ErrorEngine {
        fn infer(&self, _text: &str) -> Result<Vec<Finding>, EngineError> {
            Err(EngineError::InferRun("mock failure".to_string()))
        }
    }

    /// budget 内完成 → status = Ok;findings 含 Hard 命中(NoopEngine 模型路径返空)
    #[test]
    fn budgeted_scan_within_budget_returns_ok() {
        let engine: Arc<dyn RedactionEngine> = Arc::new(NoopEngine);
        let outcome = scan_text_with_engine_budgeted(
            "token=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
            engine,
            Duration::from_millis(500),
        )
        .expect("budgeted scan should succeed within budget");
        assert_eq!(outcome.status, EngineStatus::Ok, "NoopEngine 立即返,应 Ok");
        // Hard 路径 github_token 必须命中(fail-closed 守 secret 类)
        assert!(
            outcome
                .result
                .findings
                .iter()
                .any(|f| f.kind == "github_token"),
            "Hard 路径应命中 github_token"
        );
    }

    /// 模型路径超 budget → status = DegradedTimeout;Hard 路径 secret 仍命中(fail-closed)
    #[test]
    fn budgeted_scan_timeout_degrades_to_hardonly() {
        let engine: Arc<dyn RedactionEngine> = Arc::new(SleepyEngine {
            dur: Duration::from_millis(500), // engine 慢
        });
        let outcome = scan_text_with_engine_budgeted(
            "token=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
            engine,
            Duration::from_millis(50), // budget 短
        )
        .expect("budgeted scan should return outcome even on timeout");
        assert_eq!(
            outcome.status,
            EngineStatus::DegradedTimeout,
            "engine 500ms vs budget 50ms 应触发 timeout"
        );
        // 关键不变量:即使 model 超时,Hard 规则仍守 secret 类
        assert!(
            outcome
                .result
                .findings
                .iter()
                .any(|f| f.kind == "github_token"),
            "DegradedTimeout 路径下 Hard secret 必须仍命中(fail-closed bottom line)"
        );
    }

    /// 模型路径返 Err → status = DegradedError;Hard 路径 secret 仍命中
    #[test]
    fn budgeted_scan_engine_error_degrades_to_hardonly() {
        let engine: Arc<dyn RedactionEngine> = Arc::new(ErrorEngine);
        let outcome = scan_text_with_engine_budgeted(
            "token=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
            engine,
            Duration::from_millis(500),
        )
        .expect("budgeted scan should not propagate engine error");
        assert_eq!(
            outcome.status,
            EngineStatus::DegradedError,
            "engine InferRun 应触发 DegradedError"
        );
        // fail-closed 不变量保留
        assert!(
            outcome
                .result
                .findings
                .iter()
                .any(|f| f.kind == "github_token"),
            "DegradedError 路径下 Hard secret 必须仍命中"
        );
    }

    /// v0.7-α3 R1a — generic_url 通过 ALL_RULES → scan_text_with_engine 路径命中。
    /// scan_text 默认走 NoopEngine 也激活此路径,公网 URL 应抓 url canonical。
    #[test]
    fn r1a_scan_text_generic_url_hard_match() {
        let text = "Visit https://api.example.com/v1/users for docs.";
        let r = scan_text(text).expect("scan ok");
        let url_findings: Vec<_> = r
            .findings
            .iter()
            .filter(|f| crate::PrivacyLabel::from_kind(f.kind) == Some(crate::PrivacyLabel::Url))
            .collect();
        assert!(
            !url_findings.is_empty(),
            "generic_url 应命中,实际 findings={:?}",
            r.findings
        );
        // 应覆盖 https URL 起始(span.0 == "Visit ".len() == 6)
        assert!(
            url_findings.iter().any(|f| f.span.0 == 6),
            "url span 应起 idx=6,实际: {:?}",
            url_findings
        );
    }

    /// internal_ipv4 仍命中(回归不破)
    #[test]
    fn r1a_internal_ipv4_still_matches() {
        let text = "Server at 10.0.0.5 in cluster.";
        let r = scan_text(text).expect("scan ok");
        let url_findings: Vec<_> = r
            .findings
            .iter()
            .filter(|f| crate::PrivacyLabel::from_kind(f.kind) == Some(crate::PrivacyLabel::Url))
            .collect();
        assert!(
            !url_findings.is_empty(),
            "internal_ipv4 应继续命中,findings={:?}",
            r.findings
        );
    }

    /// generic_url canonical 经 PrivacyLabel::Url 走 risk_delta=10
    #[test]
    fn r1a_generic_url_risk_delta_is_10() {
        assert_eq!(
            risk_of("generic_url"),
            10,
            "generic_url 应走 Url canonical risk = 10(ADR 0012 §1.3)"
        );
    }

    /// 空输入 fail-closed(与 scan_text 同口径)
    #[test]
    fn budgeted_scan_empty_input_fail_closed() {
        let engine: Arc<dyn RedactionEngine> = Arc::new(NoopEngine);
        let r = scan_text_with_engine_budgeted("", engine, Duration::from_millis(500));
        assert!(
            matches!(r, Err(ScanError::EmptyInput)),
            "空输入应返 EmptyInput,实际: {:?}",
            r
        );
    }
}
