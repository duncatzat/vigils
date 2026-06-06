//! PolicyEngine —— 规则数据结构与评估逻辑。

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use vigil_types::{EffectKind, EffectVector};

/// 引擎错误(评估期)。
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// 规则引用的 `roots_key` / `allowlist_key` 在 PolicyContext 里未绑定。
    #[error("unknown context key: {key}")]
    UnknownContextKey {
        /// 缺失的 key
        key: String,
    },

    /// 规则内部字段类型错配(如 Eq 的 value 与 field 语义不兼容)。
    #[error("type mismatch: {reason}")]
    TypeMismatch {
        /// 人读原因
        reason: &'static str,
    },
}

/// 规则动作。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[serde(rename_all = "PascalCase")]
pub enum PolicyAction {
    /// 直接放行。
    Allow,
    /// 直接拒绝。
    Deny,
    /// 进入审批队列。
    Approve,
}

impl PolicyAction {
    /// fail-closed 偏序:Deny > Approve > Allow。
    fn severity(self) -> u8 {
        match self {
            PolicyAction::Deny => 2,
            PolicyAction::Approve => 1,
            PolicyAction::Allow => 0,
        }
    }
}

/// 可被 Condition 引用的 EffectVector 字段。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum EffectField {
    /// `EffectVector::paths_read`
    PathsRead,
    /// `EffectVector::paths_write`
    PathsWrite,
    /// `EffectVector::network_hosts`
    NetworkHosts,
    /// `EffectVector::secret_refs`
    SecretRefs,
    /// `EffectVector::recipients`
    Recipients,
    /// `EffectVector::destructive`
    Destructive,
    /// `EffectVector::reversible`
    Reversible,
}

/// Condition 的字面值(当前支持布尔 / 字符串)。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
#[serde(untagged)]
pub enum PolicyValue {
    /// 布尔
    Bool(bool),
    /// 字符串字面量
    Str(String),
}

/// Descriptor 审批/漂移状态的规则标签。与 `vigil_firewall::scorer::DescriptorStatus`
/// 对应,但独立放在 policy crate 以保持依赖方向。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[serde(rename_all = "PascalCase")]
pub enum DescriptorState {
    /// 已审批且未漂移
    ApprovedStable,
    /// 首次见到
    FirstSeen,
    /// descriptor hash 漂移
    Drifted,
}

/// 规则条件。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Condition {
    /// `field` 中每一项都**属于** `${roots_key}` 的某个前缀
    /// (e.g. paths_write ⊂ project_roots)
    Inside {
        /// 被约束的 Effect 字段
        field: EffectField,
        /// 对 `PolicyContext::roots` 的键
        roots_key: String,
    },
    /// `field` 中**至少有一项**不在 `${roots_key}` 内 —— 用于"越界检测"
    Outside {
        /// 被约束的 Effect 字段
        field: EffectField,
        /// 对 `PolicyContext::roots` 的键
        roots_key: String,
    },
    /// `field` 的 bool 值等于 value(只适用 Destructive / Reversible)
    Eq {
        /// 被约束的 Effect 字段
        field: EffectField,
        /// 对照值
        value: PolicyValue,
    },
    /// `network_hosts` 中有任一主机不在 `${allowlist_key}` 的集合里
    HostNotInAllowList {
        /// 对 `PolicyContext::allowlists` 的键
        allowlist_key: String,
    },
    /// 风险评分 ≥ 阈值
    RiskScoreAtLeast(u8),
    /// effect_vector.effects 中含某种效应
    EffectIncludes(EffectKind),
    /// 当前调用的 descriptor 状态 == 指定值(ADR 0003 §D3 drift/first-seen 入规则)
    DescriptorIs(DescriptorState),
    /// I10c-β2(ADR 0011 §8):`PolicyContext.requested_scopes` 的 OAuth scope
    /// **有任一项**不在 `${allowlist_key}` 的允许集合里 —— 用于"OAuth scope 越界检测"。
    ///
    /// 这是 ADR 0011 §8 中 **"allowed_scopes" 功能** 的底层 DSL 原语。
    /// 对外功能名是 `allowed_scopes`(即"允许这些 scope"); DSL `op` 名是 `scope_not_in_allow_list`
    /// (即"断言当前 scope 集有越界"),两者语义互补 —— 用 Deny 规则 + `ScopeNotInAllowList`
    /// 表达"只允许 allowlist 内的 scope"。
    ///
    /// # 三态语义(R2 修订)
    ///
    /// 对 [`PolicyContext::requested_scopes`] 三态的处理:
    /// - `None`       —— 非 OAuth 调用 → 条件 false(规则不适用)
    /// - `Some(vec![])` —— OAuth 调用但未带 scope → 条件 true(fail-closed 触发 Deny)
    /// - `Some(scopes)` —— 按 RFC 6749 §3.3 精确相等(case-sensitive)检查每项
    ///
    /// Scope 比较刻意**不**采用 host 的 ASCII-ci/后缀匹配,因 OAuth scope 是 opaque token
    /// 而非域名,AS 侧语义保留字面量(如 `"Repo"` ≠ `"repo"`)。
    ///
    /// # 典型用法
    /// ```ignore
    /// PolicyRule {
    ///     id: "enforce_allowed_scopes".into(),
    ///     match_effects: vec![],
    ///     conditions: vec![Condition::ScopeNotInAllowList {
    ///         allowlist_key: "github_scopes".into(),
    ///     }],
    ///     action: PolicyAction::Deny,
    ///     priority: 100,
    /// }
    /// ```
    /// Context 带 `allowlists: { "github_scopes": ["repo", "workflow"] }`;
    /// `requested_scopes = Some(vec!["admin:org"])` → 命中 Deny。
    ScopeNotInAllowList {
        /// 对 `PolicyContext::allowlists` 的键
        allowlist_key: String,
    },
    /// ISS-012:[`PolicyContext::pii_findings`] 中 `label == ${label}` 的 finding 条数
    /// **≥ `min_count`** 时条件成立(AND 语义:与其他 conditions 一起 AND)。
    ///
    /// 用于把 ISS-005 `vigil-redaction::scan_text` 产出的 findings 接入 PolicyEngine
    /// 决策。典型用法:`label="secret", min_count=1` 代表"含至少 1 条 secret",配合
    /// `EffectIncludes(EffectKind::NetOutbound)` 表达"有 secret 还外发"。
    ///
    /// # 不变量
    /// - `label` 比较**大小写敏感**(对齐 [`vigil_redaction::PrivacyLabel::as_str`] 的
    ///   lowercase 字面量:`secret / account_number / email / phone / person / address /
    ///   date / url`);其他字面量将永远不匹配(ISS-011 allowlist 已在 audit 层守门)。
    /// - `min_count == 0` 被视作**平凡条件**(始终真),对齐 SQL `HAVING COUNT(*) >= 0`。
    ///   caller 应显式写 `min_count=1` 表达"至少一条"。
    /// - findings 条数是 **`pii_findings` 里 `label == target` 的元素计数**(含重复)。
    ///   `merge_findings` 已确保同 span 不重复(ADR 0013 D3),caller 无须再去重。
    ///
    /// # 典型用法
    /// ```ignore
    /// PolicyRule {
    ///     id: "secret_outbound_network".into(),
    ///     match_effects: vec![EffectKind::NetOutbound],
    ///     conditions: vec![
    ///         Condition::PiiContains { label: "secret".into(), min_count: 1 },
    ///         Condition::HostNotInAllowList { allowlist_key: "allowed_hosts".into() },
    ///     ],
    ///     action: PolicyAction::Deny,
    ///     priority: 100,
    /// }
    /// ```
    PiiContains {
        /// 目标 label 字面量(与 `PrivacyLabel::as_str()` 对齐)
        label: String,
        /// 最少命中条数(≥ 1 时才有实际意义)
        min_count: u32,
    },
}

/// 一条策略规则。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyRule {
    /// 规则唯一 id(进审计)
    pub id: String,
    /// 所有 `conditions` 成立,且 EffectVector 含有这些效应的**至少一种**。
    /// 空集表示不以 effects 作为触发条件(如只看 risk_score)。
    pub match_effects: Vec<EffectKind>,
    /// 必须全部满足的条件(AND)
    pub conditions: Vec<Condition>,
    /// 命中后的动作
    pub action: PolicyAction,
    /// 数值越大越先评估;默认 0
    #[serde(default)]
    pub priority: i32,
}

/// 评估结果。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDecision {
    /// 最终动作(Deny > Approve > Allow,或兜底 Deny)
    pub action: PolicyAction,
    /// 命中规则 id 列表(按 priority 降序,同优先级按输入顺序)
    pub policy_ids: Vec<String>,
    /// 人读原因(每条规则贡献一行)
    pub reasons: Vec<String>,
}

/// ISS-010:T0 redaction scan 产出的 PII finding 轻量摘要。
///
/// 刻意**不**复用 `vigil_redaction::Finding`(含 span / confidence / risk_delta 字段),
/// 原因:避免 vigil-policy 反向依赖 vigil-redaction(保持规则引擎纯粹性,依赖方向
/// 只能 vigil-policy ← caller)。caller(vigil-firewall)把 `Vec<Finding>` 聚合成
/// `Vec<PiiFindingSummary>` 再塞入 `PolicyContext`。
///
/// `label` 字面量契约与 `vigil_redaction::PrivacyLabel::as_str()` 对齐(见 ISS-005),
/// 字符串比较 **case-sensitive**。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PiiFindingSummary {
    /// 对齐 `PrivacyLabel::as_str()`:secret / account_number / email / phone /
    /// person / address / date / url(lowercase)
    pub label: String,
    /// 原 `Vec<Finding>` 里该 label 的出现次数。Condition::PiiContains 与此做 ≥ min_count 比较。
    pub count: u32,
}

/// 评估上下文:规则里 `${project_roots}` / `${allowed_hosts}` 的真实绑定。
#[derive(Debug, Clone)]
pub struct PolicyContext {
    /// `roots_key -> 允许的根目录前缀`。比较是字符串前缀匹配,按绝对 POSIX 规范化过的路径
    pub roots: HashMap<String, Vec<String>>,
    /// `allowlist_key -> 允许的主机 / scope 集合`(HostNotInAllowList / ScopeNotInAllowList 共用)
    pub allowlists: HashMap<String, Vec<String>>,
    /// 可选:风险评分。若 Condition::RiskScoreAtLeast 被使用,引擎从这里读取
    pub risk_score: u8,
    /// 当前调用的 descriptor 状态。默认 ApprovedStable。
    pub descriptor: DescriptorState,
    /// ISS-010:T0 redaction scan 产出的 PII findings 聚合摘要。
    ///
    /// 由 caller(vigil-firewall preflight)在走 `Firewall::evaluate` 前填充:扫 tool
    /// args 长文本 → `vigil_redaction::scan_text` → 按 label 聚合条数 → 塞入本字段。
    /// 空 vec 代表"未扫出任何 PII"(不是"未扫"—— caller 另走 fail-closed Deny)。
    ///
    /// `Condition::PiiContains` 消费本字段。默认空 vec,对不接 T0 的 caller 透明。
    pub pii_findings: Vec<PiiFindingSummary>,
    /// I10c-β2(ADR 0011 §8):当前 invocation 的 OAuth scope 上下文。
    ///
    /// **三态语义**(R1 MUST-FIX 修订 —— 区分"无 OAuth"与"OAuth 但漏传 scope"):
    /// - `None` —— 非 OAuth 调用路径(本地工具 / stdio MCP / 无 token)。
    ///   `ScopeNotInAllowList` 视作不适用,**不触发**规则。
    /// - `Some(vec![])` —— 调用走了 OAuth,但 token 不带任何 scope(或未透传)。
    ///   `ScopeNotInAllowList` **fail-closed 触发**(有规则要求 scope 在 allowlist 内,
    ///   却连 scope 都没有 → 视同越界),避免静默绕过。
    /// - `Some(scopes)` —— 正常 OAuth 上下文,按精确相等(case-sensitive,RFC 6749 §3.3)
    ///   对每个 scope 检查是否在 allowlist 里。
    ///
    /// 默认 `None`(caller 未显式接入 OAuth 上下文)。
    pub requested_scopes: Option<Vec<String>>,
}

impl Default for PolicyContext {
    fn default() -> Self {
        Self {
            roots: HashMap::new(),
            allowlists: HashMap::new(),
            risk_score: 0,
            descriptor: DescriptorState::ApprovedStable,
            requested_scopes: None,
            pii_findings: Vec::new(),
        }
    }
}

/// 引擎 **fail-closed 兜底 floor** 的保留 policy id —— 无规则匹配时 [`PolicyEngine::evaluate`] 产出
/// `policy_ids == [DEFAULT_DENY_POLICY_ID]`。**任何规则都不得占用此 id**(`new`/`add_rule` 会过滤掉),
/// 这样下游(如 monitor 降级 default-deny floor)可凭此 id **唯一且不可伪造**地识别"兜底拒绝"
/// 与"显式 Deny 规则"(Codex review HIGH:否则一条 id 为 default-deny 的显式 Deny 会被误当 floor)。
pub const DEFAULT_DENY_POLICY_ID: &str = "default-deny";

/// 规则引擎。
#[derive(Debug, Clone, Default)]
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
}

impl PolicyEngine {
    /// 用一组规则构造引擎。规则内部可乱序,引擎会按 priority 自排。
    pub fn new(rules: Vec<PolicyRule>) -> Self {
        // 过滤掉**保留 id** [`DEFAULT_DENY_POLICY_ID`] 的规则:该 id 专属引擎的 fail-closed 兜底
        // floor(无规则匹配时产出)。若允许某规则携带此 id,下游("policy_ids == [floor id]"判定
        // floor,如 monitor 降级)会把一条**显式 Deny 规则**误当兜底 floor(Codex review HIGH:可伪造)。
        let rules: Vec<PolicyRule> = rules
            .into_iter()
            .filter(|r| r.id != DEFAULT_DENY_POLICY_ID)
            .collect();
        let mut e = Self { rules };
        e.rules
            .sort_by(|a, b| b.priority.cmp(&a.priority).then_with(|| a.id.cmp(&b.id)));
        e
    }

    /// 追加一条规则(测试 / 动态装载)。携带保留 id [`DEFAULT_DENY_POLICY_ID`] 的规则被**拒绝**
    /// (静默忽略)—— 该 id 专属引擎 floor,不得被任何规则占用(否则 floor 检测可被伪造,Codex HIGH)。
    pub fn add_rule(&mut self, r: PolicyRule) {
        if r.id == DEFAULT_DENY_POLICY_ID {
            return;
        }
        self.rules.push(r);
        self.rules
            .sort_by(|a, b| b.priority.cmp(&a.priority).then_with(|| a.id.cmp(&b.id)));
    }

    /// 规则数。
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// 是否空。
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// 求值。
    ///
    /// 算法:
    /// 1. 遍历(已排序)规则,收集全部命中
    /// 2. 按 fail-closed 偏序合并命中:Deny > Approve > Allow
    /// 3. 无命中兜底 Deny
    pub fn evaluate(
        &self,
        effects: &EffectVector,
        ctx: &PolicyContext,
    ) -> Result<PolicyDecision, PolicyError> {
        let mut hits: Vec<&PolicyRule> = Vec::new();
        for r in &self.rules {
            if rule_matches(r, effects, ctx)? {
                hits.push(r);
            }
        }

        if hits.is_empty() {
            return Ok(PolicyDecision {
                action: PolicyAction::Deny,
                policy_ids: vec![DEFAULT_DENY_POLICY_ID.to_string()],
                reasons: vec!["no rule matched; fail-closed default deny".to_string()],
            });
        }

        // 合并:取最严动作
        let action = hits
            .iter()
            .map(|r| r.action)
            .max_by_key(|a| a.severity())
            .unwrap_or(PolicyAction::Deny);

        let policy_ids = hits.iter().map(|r| r.id.clone()).collect();
        let reasons = hits
            .iter()
            .map(|r| format!("rule `{}` → {:?}", r.id, r.action))
            .collect();

        Ok(PolicyDecision {
            action,
            policy_ids,
            reasons,
        })
    }
}

fn rule_matches(
    r: &PolicyRule,
    effects: &EffectVector,
    ctx: &PolicyContext,
) -> Result<bool, PolicyError> {
    if !r.match_effects.is_empty() {
        let any = r
            .match_effects
            .iter()
            .any(|me| effects.effects.contains(me));
        if !any {
            return Ok(false);
        }
    }
    for c in &r.conditions {
        if !condition_matches(c, effects, ctx)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn condition_matches(
    c: &Condition,
    effects: &EffectVector,
    ctx: &PolicyContext,
) -> Result<bool, PolicyError> {
    match c {
        Condition::Inside { field, roots_key } => {
            let roots = ctx
                .roots
                .get(roots_key)
                .ok_or_else(|| PolicyError::UnknownContextKey {
                    key: roots_key.clone(),
                })?;
            let items = read_path_field(effects, *field)?;
            // 空 items 视为不 inside(没有有意义的断言)
            if items.is_empty() {
                return Ok(false);
            }
            Ok(items.iter().all(|p| under_any_root(p, roots)))
        }
        Condition::Outside { field, roots_key } => {
            let roots = ctx
                .roots
                .get(roots_key)
                .ok_or_else(|| PolicyError::UnknownContextKey {
                    key: roots_key.clone(),
                })?;
            let items = read_path_field(effects, *field)?;
            Ok(items.iter().any(|p| !under_any_root(p, roots)))
        }
        Condition::Eq { field, value } => match (field, value) {
            (EffectField::Destructive, PolicyValue::Bool(b)) => Ok(effects.destructive == *b),
            (EffectField::Reversible, PolicyValue::Bool(b)) => Ok(effects.reversible == *b),
            _ => Err(PolicyError::TypeMismatch {
                reason: "Eq only supports Destructive/Reversible bool",
            }),
        },
        Condition::HostNotInAllowList { allowlist_key } => {
            let allow = ctx.allowlists.get(allowlist_key).ok_or_else(|| {
                PolicyError::UnknownContextKey {
                    key: allowlist_key.clone(),
                }
            })?;
            Ok(effects
                .network_hosts
                .iter()
                .any(|h| !allow.iter().any(|a| host_matches(h, a))))
        }
        Condition::RiskScoreAtLeast(t) => Ok(ctx.risk_score >= *t),
        Condition::EffectIncludes(k) => Ok(effects.effects.contains(k)),
        Condition::DescriptorIs(s) => Ok(ctx.descriptor == *s),
        Condition::ScopeNotInAllowList { allowlist_key } => {
            // I10c-β2 R2 修订:严格区分三态,避免静默绕过。
            //   None             → 非 OAuth 调用路径,规则不适用 → false
            //                      (**在 allowlist 查找前短路**,这样非 OAuth 调用不会
            //                      因为"调用方未配置 OAuth scope allowlist"而触发错误)
            //   Some(vec![])     → 有 OAuth 上下文但 scope 缺失 → fail-closed true
            //                      (有规则要求 scope 在 allowlist 内,却连 scope 都没有 = 越界)
            //   Some(scopes)     → 精确相等(RFC 6749 §3.3 case-sensitive)检查每个
            //                      此路径要求 allowlist 必须已配置,否则 UnknownContextKey 上抛
            let Some(scopes) = ctx.requested_scopes.as_ref() else {
                return Ok(false);
            };
            let allow = ctx.allowlists.get(allowlist_key).ok_or_else(|| {
                PolicyError::UnknownContextKey {
                    key: allowlist_key.clone(),
                }
            })?;
            if scopes.is_empty() {
                return Ok(true);
            }
            Ok(scopes.iter().any(|s| !allow.iter().any(|a| a == s)))
        }
        Condition::PiiContains { label, min_count } => {
            // ISS-012:遍历 ctx.pii_findings,统计 label == target 的元素数量。
            // `merge_findings`(ADR 0013)已保证同 span 不重复,caller 不再做去重。
            // case-sensitive:对齐 PrivacyLabel::as_str() 的 lowercase 契约。
            // min_count == 0 是平凡条件(永真),交给 caller 自行避免。
            let hits: u32 = ctx
                .pii_findings
                .iter()
                .filter(|f| f.label == *label)
                .map(|f| f.count)
                .sum();
            Ok(hits >= *min_count)
        }
    }
}

fn read_path_field(effects: &EffectVector, f: EffectField) -> Result<Vec<String>, PolicyError> {
    match f {
        EffectField::PathsRead => Ok(effects.paths_read.clone()),
        EffectField::PathsWrite => Ok(effects.paths_write.clone()),
        _ => Err(PolicyError::TypeMismatch {
            reason: "Inside/Outside only applies to PathsRead/PathsWrite",
        }),
    }
}

/// `p` 是否落在任一 root 下。前缀比较,要求 root 以 `/` 结尾或 p == root。
/// PathExtractor 已保证两边都是 POSIX 风格规范化路径。
fn under_any_root(p: &str, roots: &[String]) -> bool {
    roots.iter().any(|r| is_under(p, r))
}

fn is_under(p: &str, root: &str) -> bool {
    let normalized_root = if root.ends_with('/') {
        root.to_string()
    } else {
        format!("{}/", root)
    };
    // Windows 路径大小写不敏感;其它平台严格匹配。
    // PathExtractor 已把路径规范化为 POSIX `/` 风格,盘符(C:)前缀仍保留。
    #[cfg(target_os = "windows")]
    let result = {
        let p_lc = p.to_ascii_lowercase();
        let root_lc = root.to_ascii_lowercase();
        let nr_lc = normalized_root.to_ascii_lowercase();
        p_lc == root_lc || p_lc.starts_with(&nr_lc)
    };
    #[cfg(not(target_os = "windows"))]
    let result = p == root || p.starts_with(&normalized_root);
    result
}

/// 宿主匹配:精确匹配 host,或 allowlist 条目以 `.` 开头时允许后缀匹配
/// (如 `.github.com` 匹配 `api.github.com`)。
fn host_matches(host: &str, pattern: &str) -> bool {
    if pattern.starts_with('.') {
        host.ends_with(pattern) || host == &pattern[1..]
    } else {
        host.eq_ignore_ascii_case(pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigil_types::EffectKind;

    fn mk_effects(
        effects: Vec<EffectKind>,
        paths_write: Vec<&str>,
        hosts: Vec<&str>,
    ) -> EffectVector {
        EffectVector {
            effects,
            paths_write: paths_write.into_iter().map(String::from).collect(),
            network_hosts: hosts.into_iter().map(String::from).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn default_deny_when_no_rules() {
        let e = PolicyEngine::default();
        let res = e
            .evaluate(&EffectVector::default(), &PolicyContext::default())
            .unwrap();
        assert_eq!(res.action, PolicyAction::Deny);
        assert!(res.policy_ids.contains(&"default-deny".to_string()));
    }

    #[test]
    fn fail_closed_combines_deny_over_approve() {
        let rules = vec![
            PolicyRule {
                id: "approve-rule".into(),
                match_effects: vec![EffectKind::FsWrite],
                conditions: vec![],
                action: PolicyAction::Approve,
                priority: 0,
            },
            PolicyRule {
                id: "deny-rule".into(),
                match_effects: vec![EffectKind::FsWrite],
                conditions: vec![],
                action: PolicyAction::Deny,
                priority: 0,
            },
        ];
        let e = PolicyEngine::new(rules);
        let eff = mk_effects(vec![EffectKind::FsWrite], vec![], vec![]);
        let res = e.evaluate(&eff, &PolicyContext::default()).unwrap();
        assert_eq!(
            res.action,
            PolicyAction::Deny,
            "同优先级 Deny 应压倒 Approve"
        );
    }

    #[test]
    fn inside_and_outside_project_roots() {
        let mut ctx = PolicyContext::default();
        ctx.roots
            .insert("project_roots".into(), vec!["/proj".into()]);

        let eff_inside = mk_effects(vec![EffectKind::FsWrite], vec!["/proj/src/main.rs"], vec![]);
        let eff_outside = mk_effects(vec![EffectKind::FsWrite], vec!["/etc/hosts"], vec![]);

        let inside_cond = Condition::Inside {
            field: EffectField::PathsWrite,
            roots_key: "project_roots".into(),
        };
        let outside_cond = Condition::Outside {
            field: EffectField::PathsWrite,
            roots_key: "project_roots".into(),
        };

        let r_in = PolicyRule {
            id: "approve-inside".into(),
            match_effects: vec![EffectKind::FsWrite],
            conditions: vec![inside_cond],
            action: PolicyAction::Approve,
            priority: 0,
        };
        let r_out = PolicyRule {
            id: "deny-outside".into(),
            match_effects: vec![EffectKind::FsWrite],
            conditions: vec![outside_cond],
            action: PolicyAction::Deny,
            priority: 10,
        };

        let e = PolicyEngine::new(vec![r_in.clone(), r_out.clone()]);
        assert_eq!(
            e.evaluate(&eff_inside, &ctx).unwrap().action,
            PolicyAction::Approve
        );
        assert_eq!(
            e.evaluate(&eff_outside, &ctx).unwrap().action,
            PolicyAction::Deny
        );
    }

    #[test]
    fn host_not_in_allowlist_triggers() {
        let mut ctx = PolicyContext::default();
        ctx.allowlists
            .insert("allowed_hosts".into(), vec!["api.github.com".into()]);
        let eff = mk_effects(vec![EffectKind::NetOutbound], vec![], vec!["evil.example"]);
        let r = PolicyRule {
            id: "approve-unknown-host".into(),
            match_effects: vec![EffectKind::NetOutbound],
            conditions: vec![Condition::HostNotInAllowList {
                allowlist_key: "allowed_hosts".into(),
            }],
            action: PolicyAction::Approve,
            priority: 0,
        };
        let e = PolicyEngine::new(vec![r]);
        assert_eq!(
            e.evaluate(&eff, &ctx).unwrap().action,
            PolicyAction::Approve
        );
    }

    #[test]
    fn host_suffix_pattern_matches() {
        assert!(host_matches("api.github.com", ".github.com"));
        assert!(host_matches("github.com", ".github.com"));
        assert!(!host_matches("fakegithub.com", ".github.com"));
        assert!(host_matches("API.GITHUB.COM", "api.github.com"));
    }

    #[test]
    fn destructive_eq_condition() {
        let eff = EffectVector {
            effects: vec![EffectKind::DbWrite],
            destructive: true,
            ..Default::default()
        };
        let r = PolicyRule {
            id: "deny-destructive-sql".into(),
            match_effects: vec![EffectKind::DbWrite],
            conditions: vec![Condition::Eq {
                field: EffectField::Destructive,
                value: PolicyValue::Bool(true),
            }],
            action: PolicyAction::Deny,
            priority: 100,
        };
        let e = PolicyEngine::new(vec![r]);
        assert_eq!(
            e.evaluate(&eff, &PolicyContext::default()).unwrap().action,
            PolicyAction::Deny
        );
    }

    // ───────────────────────── I10c-β2:ScopeNotInAllowList ─────────────────────────

    /// 构造 scope enforcement 测试夹具:
    /// - allowlists["oauth_scopes"] = ["repo", "workflow"]
    /// - 一条 Deny 规则:`ScopeNotInAllowList { "oauth_scopes" }`
    ///
    /// `requested`:`None` → 模拟"非 OAuth 调用";`Some(vec![...])` → 显式 OAuth 上下文。
    fn scope_fixture(requested: Option<Vec<&str>>) -> (PolicyEngine, EffectVector, PolicyContext) {
        let ctx = PolicyContext {
            allowlists: {
                let mut m = HashMap::new();
                m.insert(
                    "oauth_scopes".into(),
                    vec!["repo".into(), "workflow".into()],
                );
                m
            },
            requested_scopes: requested.map(|v| v.into_iter().map(String::from).collect()),
            ..Default::default()
        };
        let rule = PolicyRule {
            id: "deny-out-of-scope".into(),
            // match_effects 空 → 不以 effects 作为触发前提,任意 invocation 都会进条件检查
            match_effects: vec![],
            conditions: vec![Condition::ScopeNotInAllowList {
                allowlist_key: "oauth_scopes".into(),
            }],
            action: PolicyAction::Deny,
            priority: 100,
        };
        let eff = EffectVector::default();
        (PolicyEngine::new(vec![rule]), eff, ctx)
    }

    #[test]
    fn scope_not_in_allowlist_triggers_deny() {
        // requested 含 "admin:org" 越界 → 条件成立 → Deny
        let (e, eff, ctx) = scope_fixture(Some(vec!["repo", "admin:org"]));
        let res = e.evaluate(&eff, &ctx).unwrap();
        assert_eq!(res.action, PolicyAction::Deny);
        assert!(res.policy_ids.contains(&"deny-out-of-scope".to_string()));
    }

    #[test]
    fn scope_subset_does_not_trigger() {
        // 所有 requested ⊂ allowlist → 条件不成立 → 规则未命中
        // 无其它规则 → 兜底 default-deny(非 deny-out-of-scope)
        let (e, eff, ctx) = scope_fixture(Some(vec!["repo", "workflow"]));
        let res = e.evaluate(&eff, &ctx).unwrap();
        assert_eq!(res.action, PolicyAction::Deny);
        assert_eq!(res.policy_ids, vec!["default-deny".to_string()]);
    }

    #[test]
    fn none_requested_scopes_is_no_op_for_non_oauth_invocations() {
        // 非 OAuth 调用(None) → 条件不适用 → 规则不触发 → 兜底 default-deny
        // 避免本地工具 / stdio MCP 被无关的 scope 规则误伤。
        let (e, eff, ctx) = scope_fixture(None);
        let res = e.evaluate(&eff, &ctx).unwrap();
        assert_eq!(res.action, PolicyAction::Deny);
        assert_eq!(
            res.policy_ids,
            vec!["default-deny".to_string()],
            "None(非 OAuth)不应命中 deny-out-of-scope"
        );
    }

    #[test]
    fn empty_requested_scopes_fail_closed_triggers_deny() {
        // R2 关键修订:OAuth 调用但 scope 缺失(Some(vec![]))→ **fail-closed 触发**
        // 防止调用链漏传 scope 成为静默绕过面。
        let (e, eff, ctx) = scope_fixture(Some(vec![]));
        let res = e.evaluate(&eff, &ctx).unwrap();
        assert_eq!(res.action, PolicyAction::Deny);
        assert!(
            res.policy_ids.contains(&"deny-out-of-scope".to_string()),
            "Some(vec![]) 必须命中 deny-out-of-scope(fail-closed),实际 policy_ids={:?}",
            res.policy_ids
        );
    }

    #[test]
    fn unknown_allowlist_key_errors() {
        // 故意不在 allowlists 里插入 "oauth_scopes"
        let ctx = PolicyContext {
            requested_scopes: Some(vec!["repo".into()]),
            ..Default::default()
        };
        let rule = PolicyRule {
            id: "deny-out-of-scope".into(),
            match_effects: vec![],
            conditions: vec![Condition::ScopeNotInAllowList {
                allowlist_key: "oauth_scopes".into(),
            }],
            action: PolicyAction::Deny,
            priority: 100,
        };
        let e = PolicyEngine::new(vec![rule]);
        let err = e.evaluate(&EffectVector::default(), &ctx).unwrap_err();
        assert!(
            matches!(err, PolicyError::UnknownContextKey { ref key } if key == "oauth_scopes"),
            "expected UnknownContextKey {{ key: \"oauth_scopes\" }}, got {:?}",
            err
        );
    }

    #[test]
    fn scope_exact_match_is_case_sensitive() {
        // scope 按 AS 原样精确相等(与 host_matches 的 ASCII-ci 不同)
        // "Repo" ≠ "repo" → 越界 → Deny
        let (e, eff, ctx) = scope_fixture(Some(vec!["Repo"]));
        let res = e.evaluate(&eff, &ctx).unwrap();
        assert_eq!(res.action, PolicyAction::Deny);
        assert!(res.policy_ids.contains(&"deny-out-of-scope".to_string()));
    }

    // ───────────────────────── ISS-012:PiiContains ─────────────────────────

    fn summary(label: &str, count: u32) -> PiiFindingSummary {
        PiiFindingSummary {
            label: label.into(),
            count,
        }
    }

    #[test]
    fn pii_contains_matches_when_count_ge_threshold() {
        let rule = PolicyRule {
            id: "test_secret_1".into(),
            match_effects: vec![],
            conditions: vec![Condition::PiiContains {
                label: "secret".into(),
                min_count: 1,
            }],
            action: PolicyAction::Deny,
            priority: 100,
        };
        let effects = EffectVector::default();
        let ctx = PolicyContext {
            pii_findings: vec![summary("secret", 1)],
            ..Default::default()
        };
        assert!(rule_matches(&rule, &effects, &ctx).unwrap());
    }

    #[test]
    fn pii_contains_rejects_when_count_below_threshold() {
        let rule = PolicyRule {
            id: "test_multi".into(),
            match_effects: vec![],
            conditions: vec![Condition::PiiContains {
                label: "email".into(),
                min_count: 2,
            }],
            action: PolicyAction::Approve,
            priority: 50,
        };
        let effects = EffectVector::default();
        let ctx = PolicyContext {
            pii_findings: vec![summary("email", 1)],
            ..Default::default()
        };
        assert!(!rule_matches(&rule, &effects, &ctx).unwrap());
    }

    #[test]
    fn pii_contains_sums_across_duplicate_labels() {
        // 防御性:若 caller 传 2 条相同 label 的 summary(`merge_findings` 已去重,
        // 但保险起见引擎做 sum)。2 + 1 = 3 ≥ 3 → true。
        let rule = PolicyRule {
            id: "test_sum".into(),
            match_effects: vec![],
            conditions: vec![Condition::PiiContains {
                label: "phone".into(),
                min_count: 3,
            }],
            action: PolicyAction::Deny,
            priority: 10,
        };
        let effects = EffectVector::default();
        let ctx = PolicyContext {
            pii_findings: vec![summary("phone", 2), summary("phone", 1)],
            ..Default::default()
        };
        assert!(rule_matches(&rule, &effects, &ctx).unwrap());
    }

    #[test]
    fn pii_contains_case_sensitive_no_match_on_wrong_case() {
        // 对齐 PrivacyLabel::as_str() 契约(全小写);大写 "Secret" 永不命中 "secret" findings
        let rule = PolicyRule {
            id: "case".into(),
            match_effects: vec![],
            conditions: vec![Condition::PiiContains {
                label: "Secret".into(), // 大写 S(非契约)
                min_count: 1,
            }],
            action: PolicyAction::Deny,
            priority: 10,
        };
        let effects = EffectVector::default();
        let ctx = PolicyContext {
            pii_findings: vec![summary("secret", 5)],
            ..Default::default()
        };
        assert!(
            !rule_matches(&rule, &effects, &ctx).unwrap(),
            "PiiContains label 比较必须 case-sensitive(PrivacyLabel::as_str 契约 lowercase)"
        );
    }

    #[test]
    fn pii_contains_empty_findings_no_match() {
        let rule = PolicyRule {
            id: "empty".into(),
            match_effects: vec![],
            conditions: vec![Condition::PiiContains {
                label: "secret".into(),
                min_count: 1,
            }],
            action: PolicyAction::Deny,
            priority: 10,
        };
        let effects = EffectVector::default();
        let ctx = PolicyContext::default(); // pii_findings 默认空
        assert!(!rule_matches(&rule, &effects, &ctx).unwrap());
    }

    #[test]
    fn pii_contains_min_count_zero_is_trivially_true() {
        // min_count=0 平凡条件(SQL HAVING COUNT(*) >= 0 对齐),任何输入都 true
        let rule = PolicyRule {
            id: "trivial".into(),
            match_effects: vec![],
            conditions: vec![Condition::PiiContains {
                label: "anything".into(),
                min_count: 0,
            }],
            action: PolicyAction::Allow,
            priority: 0,
        };
        let effects = EffectVector::default();
        let ctx = PolicyContext::default();
        assert!(
            rule_matches(&rule, &effects, &ctx).unwrap(),
            "min_count=0 是平凡条件,应永真"
        );
    }

    #[test]
    fn pii_contains_composable_with_effect_includes() {
        // AND 语义:PiiContains + EffectIncludes 两条都要满足
        // 注:EffectKind 无 NetworkSend,用 NetOutbound(出站网络)代之 —— 语义等价
        let rule = PolicyRule {
            id: "compose".into(),
            match_effects: vec![],
            conditions: vec![
                Condition::PiiContains {
                    label: "secret".into(),
                    min_count: 1,
                },
                Condition::EffectIncludes(EffectKind::NetOutbound),
            ],
            action: PolicyAction::Deny,
            priority: 100,
        };
        let effects = EffectVector {
            effects: vec![EffectKind::NetOutbound],
            ..Default::default()
        };
        let ctx = PolicyContext {
            pii_findings: vec![summary("secret", 1)],
            ..Default::default()
        };
        assert!(rule_matches(&rule, &effects, &ctx).unwrap());

        // 反例:PII 命中但无 NetOutbound effect
        let effects_noop = EffectVector::default();
        assert!(!rule_matches(&rule, &effects_noop, &ctx).unwrap());
    }

    #[test]
    fn scope_deny_overrides_approve_at_same_priority() {
        // R1 NICE 要求:scope deny 的 fail-closed 偏序在与 Allow/Approve 并存时仍成立。
        // 构造两条同优先级规则,同一 invocation 同时命中 —— 结果必须是 Deny。
        let ctx = PolicyContext {
            allowlists: {
                let mut m = HashMap::new();
                m.insert(
                    "oauth_scopes".into(),
                    vec!["repo".into(), "workflow".into()],
                );
                m
            },
            requested_scopes: Some(vec!["admin:org".into()]),
            ..Default::default()
        };
        let rules = vec![
            PolicyRule {
                id: "approve-any".into(),
                match_effects: vec![],
                conditions: vec![], // 无条件 → 总命中
                action: PolicyAction::Approve,
                priority: 0,
            },
            PolicyRule {
                id: "deny-out-of-scope".into(),
                match_effects: vec![],
                conditions: vec![Condition::ScopeNotInAllowList {
                    allowlist_key: "oauth_scopes".into(),
                }],
                action: PolicyAction::Deny,
                priority: 0, // 同优先级
            },
        ];
        let e = PolicyEngine::new(rules);
        let res = e.evaluate(&EffectVector::default(), &ctx).unwrap();
        assert_eq!(
            res.action,
            PolicyAction::Deny,
            "scope deny 必须压倒 approve(fail-closed 偏序),reasons={:?}",
            res.reasons
        );
    }

    #[test]
    fn default_deny_policy_id_is_reserved_and_unspoofable() {
        // Codex review HIGH:下游凭 `policy_ids == [DEFAULT_DENY_POLICY_ID]` 识别"兜底 floor"
        // (如 monitor 降级)。必须保证**没有任何规则**能占用此 id —— 否则一条 id 恰为 default-deny 的
        // **显式 Deny 规则**单独命中时也产出同样 policy_ids,把"显式拒绝"伪装成"兜底拒绝"被误降级放行。
        let reserved_rule = PolicyRule {
            id: DEFAULT_DENY_POLICY_ID.into(),
            match_effects: vec![],
            conditions: vec![], // 无条件 → 若未被过滤会总命中
            action: PolicyAction::Deny,
            priority: 1000,
        };
        // new() 过滤掉保留 id 规则
        let e = PolicyEngine::new(vec![reserved_rule.clone()]);
        assert_eq!(e.len(), 0, "new() 必须过滤掉占用保留 id 的规则");
        // add_rule() 也拒绝
        let mut e2 = PolicyEngine::new(vec![]);
        e2.add_rule(reserved_rule);
        assert_eq!(e2.len(), 0, "add_rule() 必须拒绝占用保留 id 的规则");
        // 结论:`policy_ids == [DEFAULT_DENY_POLICY_ID]` 只可能来自引擎 floor(无规则匹配),
        // 不可能来自某条命中规则 → 下游 floor 检测不可伪造。
        let res = e
            .evaluate(&EffectVector::default(), &PolicyContext::default())
            .unwrap();
        assert_eq!(res.policy_ids, vec![DEFAULT_DENY_POLICY_ID.to_string()]);
        assert!(
            res.reasons.iter().any(|r| r.contains("no rule matched")),
            "此 id 必来自 floor(no rule matched),非规则命中"
        );
    }
}
