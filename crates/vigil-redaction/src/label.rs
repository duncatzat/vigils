//! ISS-005:Stage 2 T0 标签化枚举(ADR 0013 + `docs/design/vigil-redaction-selection.md`)。
//!
//! 8 个业务标签,聚合两层来源:
//! - **v0.3 硬指纹规则**(`HARD_RULES` 12 项):aws / github / anthropic / openai / jwt /
//!   pem / stripe / google / gitlab / slack / env_assignment / database_url / email /
//!   internal_ipv4
//! - **Privacy Filter 33-class id2label**(Stage 2 模型,`private_*` 前缀)
//!
//! 标签体系是"业务视角"的归并 —— caller 在 UI / 审计 / 风险累加时看到的是 8 类;
//! 原始 `Finding.kind` 字面量保留在 `Finding` 上以便调试与规则名反查。
//!
//! **不变量**:
//! - `PrivacyLabel::from_kind` 是**封闭映射**(ISS-005 明确列出所有支持 kind);未识别
//!   kind 返 `None`,caller 可选择 fail-closed。feedback_extend_enum_sync_tests:
//!   新 variant 必须同时扩 `from_kind` + `as_str` + 测试。
//! - `as_str` 返回的字面量是**外部契约**(落 JSON / 审计 / UI 文案),禁改串。

/// Stage 2 T0 业务标签枚举(ADR 0013)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PrivacyLabel {
    /// 服务 API 密钥 / 凭证类:aws / github / anthropic / openai / jwt / pem /
    /// stripe / google / gitlab / slack / env_assignment / database_url。泄漏即越权,
    /// caller 应走 fail-closed。
    Secret,
    /// 账户号码类(Privacy Filter `private_account_number` 等):银行卡 / 社保号等。
    AccountNumber,
    /// 邮箱:Hard `email` + Model `private_email`。
    Email,
    /// 电话号码:Model `private_phone`。
    Phone,
    /// 人名:Model `private_person`。
    Person,
    /// 地址:Model `private_address`。
    Address,
    /// 日期(可能是 PII 生日 / 关键事件日):Model `private_date`。
    Date,
    /// URL / IP 类:Hard `internal_ipv4` + Model `private_url`。
    /// 注:内网 IP 归入此类(可能是拓扑信息);公网 URL 也可能含凭证(如 Slack webhook),
    /// 但 Slack webhook 的完整结构由 `Secret` 承担,`Url` 仅承担通用 URL/IP 场景。
    Url,
}

impl PrivacyLabel {
    /// 返回稳定的外部字面量(UI / 审计 / JSON 序列化契约)。
    ///
    /// **纪律**:feedback_ssot_drift_guard —— 任何对这里字面量的修改都应同步
    /// `privacy_label_as_str_stable` 精确集合测试。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::AccountNumber => "account_number",
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Person => "person",
            Self::Address => "address",
            Self::Date => "date",
            Self::Url => "url",
        }
    }

    /// 全量 variant 数组(守门测试消费;同时作为"新增 variant 必测"的对账单)。
    pub const ALL: [PrivacyLabel; 8] = [
        Self::Secret,
        Self::AccountNumber,
        Self::Email,
        Self::Phone,
        Self::Person,
        Self::Address,
        Self::Date,
        Self::Url,
    ];

    /// 从 `Finding.kind` 字面量反查标签。
    ///
    /// 覆盖两层来源:
    /// - Hard(`HARD_RULES.name`):aws / github / anthropic / openai / jwt / pem /
    ///   env_assignment / slack / stripe / google / gitlab / database_url / email /
    ///   internal_ipv4
    /// - Model(Privacy Filter):`private_*` 前缀 8 类 + 裸 `secret` / `account_number`
    ///
    /// 返回 `None` 表示 kind 不在封闭集合中 —— caller 可选择:
    /// - 继续保留 Finding(本 Stage scaffold 的默认行为,兼容未来新 kind)
    /// - 或视为 fail-closed 拒入(安全关键路径)
    pub fn from_kind(kind: &str) -> Option<Self> {
        match kind {
            // ─── Hard rules(`HARD_RULES.name`)→ Secret 大类 ───
            // 这些 kind 在 HARD_RULES 中都有对应 Regex 命中;新增 HARD_RULES 时
            // 请同步这里 + 单测(feedback_extend_enum_sync_tests)。
            "aws_access_key_id"
            | "github_token"
            | "anthropic_api_key"
            | "openai_api_key"
            | "jwt"
            | "pem_private_key"
            | "env_assignment"
            | "slack_webhook"
            | "stripe_secret_key"
            | "google_api_key"
            | "gitlab_pat"
            | "database_url"
            | "aliyun_access_key_id"
            | "tencent_secret_id"
            | "slack_token"
            | "huggingface_token"
            | "secret" => Some(Self::Secret),

            // ─── Email:Hard `email` + Model `private_email` ───
            "email" | "private_email" => Some(Self::Email),

            // ─── URL/IP:Hard `internal_ipv4` + `generic_url`(R1a 加)+ Model `private_url` / `url` ───
            "internal_ipv4" | "generic_url" | "private_url" | "url" => Some(Self::Url),

            // ─── Model 专属标签(`private_*` + 裸名兼容)───
            "private_phone" | "phone" => Some(Self::Phone),
            "private_person" | "person" => Some(Self::Person),
            "private_address" | "address" => Some(Self::Address),
            "private_date" | "date" => Some(Self::Date),
            "private_account_number" | "account_number" => Some(Self::AccountNumber),

            _ => None,
        }
    }
}

impl std::fmt::Display for PrivacyLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// feedback_ssot_drift_guard:精确集合双向 diff(sorted vec assert_eq!)。
    /// 任何 variant 字面量漂移或新增/删除都会让本测试失败。
    #[test]
    fn privacy_label_as_str_stable() {
        let got: Vec<&'static str> = PrivacyLabel::ALL.iter().map(|l| l.as_str()).collect();
        let mut got_sorted = got.clone();
        got_sorted.sort_unstable();

        let mut expected = vec![
            "secret",
            "account_number",
            "email",
            "phone",
            "person",
            "address",
            "date",
            "url",
        ];
        expected.sort_unstable();

        assert_eq!(got_sorted, expected, "PrivacyLabel 字面量集合漂移");
        assert_eq!(got.len(), 8, "必须恰好 8 个 variant");

        // 顺手守:Display == as_str
        for l in PrivacyLabel::ALL {
            assert_eq!(format!("{l}"), l.as_str());
        }
    }

    /// 每个 variant 至少一个 kind 字面量可命中 from_kind(覆盖 8 个桶)。
    #[test]
    fn privacy_label_from_kind_all_variants() {
        // 每个 variant 挑一个代表性 kind
        let samples: &[(&str, PrivacyLabel)] = &[
            ("github_token", PrivacyLabel::Secret),
            ("private_account_number", PrivacyLabel::AccountNumber),
            ("email", PrivacyLabel::Email),
            ("private_phone", PrivacyLabel::Phone),
            ("private_person", PrivacyLabel::Person),
            ("private_address", PrivacyLabel::Address),
            ("private_date", PrivacyLabel::Date),
            ("internal_ipv4", PrivacyLabel::Url),
        ];
        // 确认样本本身覆盖所有 8 个 variant(防测试对照表遗漏)
        let mut seen: Vec<PrivacyLabel> = samples.iter().map(|(_, l)| *l).collect();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), 8, "样本未覆盖所有 variant");

        for (kind, expected) in samples {
            assert_eq!(
                PrivacyLabel::from_kind(kind),
                Some(*expected),
                "kind {kind:?} 期望映射到 {expected:?}"
            );
        }
    }

    /// 未识别 kind 返 None(fail-closed 信号)。
    #[test]
    fn privacy_label_from_kind_unknown_returns_none() {
        assert_eq!(PrivacyLabel::from_kind("not_a_kind"), None);
        assert_eq!(PrivacyLabel::from_kind(""), None);
        assert_eq!(PrivacyLabel::from_kind("PRIVATE_PERSON"), None); // 大小写敏感
    }

    /// 双向兼容:`private_*` 前缀 + 裸名都能命中(Stage 2 模型 vs. 调试 / 手搓样本)。
    #[test]
    fn privacy_label_from_kind_accepts_both_model_and_bare() {
        assert_eq!(
            PrivacyLabel::from_kind("private_email"),
            PrivacyLabel::from_kind("email")
        );
        assert_eq!(
            PrivacyLabel::from_kind("private_phone"),
            PrivacyLabel::from_kind("phone")
        );
    }
}
