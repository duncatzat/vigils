//! Browser native messaging 协议类型(ADR 0009 §4)。
//!
//! serde tagged unions,Chrome service worker 可直接序列化 JSON 发送。

use serde::{Deserialize, Serialize};

/// 当前规则集版本;新增 finding 或调整策略时 bump。审计 payload 保留此字段,
/// 支持日后回溯"某条审计是由哪一版规则产生"。
///
/// **版本历史**:
/// - `v1`:I09a 初始规则集(8 FindingKind:github / openai / anthropic / aws / jwt /
///   env_assignment / pem / localhost_url)
/// - `v2`:I09c 扩展(+ slack_webhook / stripe_secret_key → 10 FindingKind)
/// - `v3`:I09c 第二批(+ google_api_key / gitlab_pat → 12 FindingKind)
/// - `v4`:I09c 第三批(+ database_url → 13 FindingKind)
/// - `v5`:ISS-021 加 PrivacyLabel 维度对齐(无新 FindingKind)。
///   `FindingKind::as_str()` 12 项 LOCAL_ONLY 除外**经 alias 归一化后**
///   (rule_sync.rs `iss_021_finding_kind_maps_to_privacy_label_via_alias`
///   定义的短形 → 长形 BTreeMap),由 `vigil_redaction::PrivacyLabel::from_kind`
///   必返 `Some(_)`。**注**:vigil-browser 用短形(`openai_key` / `anthropic_key` /
///   `aws_access_key`),vigil-redaction `HARD_RULES.name` 用长形(`openai_api_key` /
///   `anthropic_api_key` / `aws_access_key_id`),两侧不直接相等,**必须经 alias
///   归一化**才能互查;详见 ADR 0013 Revised "alias 漂移点" + ISS-021 跨 crate 不变量段。
///   ADR 0013 Revised 段把硬指纹层最终定位为 fast-path + fallback,跨 crate 矩阵
///   golden 守门;详见 `docs/adr/0013-hardfp-model-merge.md` "Revised — ISS-021" 段
pub const RULE_PROFILE_VERSION: &str = "v5";

/// 浏览器事件:粘贴 / 手动输入 / 提交。`Ask` 交互延 I09c。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BrowserEventKind {
    /// 用户触发 `paste` 事件
    Paste,
    /// 用户触发普通 `input` 事件,由扩展防抖后检查
    Input,
    /// 用户触发 submit(button click / form submit / contenteditable 回车)
    Submit,
}

/// Core 返回的 action 三态(ADR 0009 §D6)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BrowserAction {
    /// 无 finding,放行
    Allow,
    /// 有 finding,扩展应用 `redacted_text` 替换 textarea
    Redact,
    /// 高风险(private key 等),扩展必须阻断 event
    Block,
}

/// classifier 可识别的 finding 类别(ADR §D3)。
///
/// 严格保持与 `vigil_redaction::detect_hard_secret` 的 rule name 对齐,便于
/// 跨 crate 的 `rule_profile_version` 一致性。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// GitHub personal access token
    GithubToken,
    /// OpenAI API key
    OpenaiKey,
    /// Anthropic / Claude API key
    AnthropicKey,
    /// AWS access key id
    AwsAccessKey,
    /// JWT(base64 header.payload.signature)
    Jwt,
    /// `.env` 风格赋值(KEY=...)
    EnvAssignment,
    /// PEM 私钥块(BEGIN PRIVATE KEY)
    PemPrivateKey,
    /// `http(s)://(localhost|127.0.0.1|::1|*.local)` URL
    LocalhostUrl,
    /// Slack incoming webhook URL(I09c 扩展;泄漏即任意人可 post 到该频道)
    SlackWebhook,
    /// Stripe live/test secret API key `sk_(live|test)_...`(I09c 扩展)
    StripeSecretKey,
    /// Google API key(Maps/YouTube/Gemini 等);`AIza` 前缀 + 35 chars(I09c 第二批)
    GoogleApiKey,
    /// GitLab personal access token;`glpat-` 前缀 + 20+ chars(I09c 第二批)
    GitlabPat,
    /// 含凭证的 database URL(`scheme://user:password@host[:port][/path]`);
    /// 白名单 scheme:postgres(ql)/ mysql / mongodb(+srv) / redis(s) / amqp(s)(I09c 第三批)
    DatabaseUrl,
}

impl FindingKind {
    /// 稳定字符串(审计 payload / finding_kinds)。
    pub fn as_str(self) -> &'static str {
        match self {
            FindingKind::GithubToken => "github_token",
            FindingKind::OpenaiKey => "openai_key",
            FindingKind::AnthropicKey => "anthropic_key",
            FindingKind::AwsAccessKey => "aws_access_key",
            FindingKind::Jwt => "jwt",
            FindingKind::EnvAssignment => "env_assignment",
            FindingKind::PemPrivateKey => "pem_private_key",
            FindingKind::LocalhostUrl => "localhost_url",
            FindingKind::SlackWebhook => "slack_webhook",
            FindingKind::StripeSecretKey => "stripe_secret_key",
            FindingKind::GoogleApiKey => "google_api_key",
            FindingKind::GitlabPat => "gitlab_pat",
            FindingKind::DatabaseUrl => "database_url",
        }
    }
}

/// 扩展 service worker → Core 的请求。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserCheckRequest {
    /// UUIDv4,caller 生成;Core 透传到 response + audit payload 供关联
    pub request_id: String,
    /// 完整 origin,形如 `https://chatgpt.com`;Core 做特权 scheme fail-closed 校验(ADR §D7)
    pub origin: String,
    /// `paste` / `input` / `submit`
    pub event_kind: BrowserEventKind,
    /// 原文;**仅在 Host 进程内存停留**,分类完立即 drop(ADR §I-9.1)
    pub text: String,
}

/// Core → 扩展 service worker 的响应。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserCheckResponse {
    /// 来自 request 的 id(便于扩展匹配)
    pub request_id: String,
    /// 本次决策
    pub action: BrowserAction,
    /// finding 类别清单(**不含** matched span;§D5)
    pub findings: Vec<FindingKind>,
    /// action=Redact 时为 Some(已经过 scrub + 硬指纹 re-scan 兜底,§I-9.6)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted_text: Option<String>,
}

/// Core 层错误码(Host 在 framing 层也会用相同 error schema 返扩展)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserErrorCode {
    /// frame length > 1 MB(防内存炸弹)
    TooLarge,
    /// JSON 解析失败
    BadJson,
    /// origin 是特权 scheme(chrome-extension / file / devtools / chrome / about)
    OriginDenied,
    /// request_id 格式不合法(空或非 ASCII)
    BadRequestId,
    /// 其他内部错误
    Internal,
}

impl BrowserErrorCode {
    /// 稳定字符串(与 serde 输出一致)。
    pub fn as_str(self) -> &'static str {
        match self {
            BrowserErrorCode::TooLarge => "too_large",
            BrowserErrorCode::BadJson => "bad_json",
            BrowserErrorCode::OriginDenied => "origin_denied",
            BrowserErrorCode::BadRequestId => "bad_request_id",
            BrowserErrorCode::Internal => "internal",
        }
    }
}

/// Host 返扩展的错误帧。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserErrorFrame {
    /// 错误码(稳定 snake_case 字符串)
    pub error: BrowserErrorCode,
    /// 若能关联到 request_id 则附带
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}
