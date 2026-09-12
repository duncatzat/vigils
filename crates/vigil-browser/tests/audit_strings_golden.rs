//! Golden test:锁定 `FindingKind::as_str` + `BrowserErrorCode::as_str` 的稳定字符串契约。
//!
//! 这些字符串同时是 serde snake_case 输出 + 审计 finding_kinds 列表 + Core→扩展的 error
//! schema,跨进程、跨语言(Rust ↔ Chrome MV3 JS)消费,任何漂移都会断裂 IPC 契约。
//!
//! 参见 `crates/vigil-lease/tests/audit_strings_golden.rs` 的失败处理指南。

#![allow(clippy::unwrap_used)]

use vigil_browser::{BrowserErrorCode, FindingKind};

#[test]
fn finding_kind_as_str_golden() {
    assert_eq!(FindingKind::GithubToken.as_str(), "github_token");
    assert_eq!(FindingKind::OpenaiKey.as_str(), "openai_key");
    assert_eq!(FindingKind::AnthropicKey.as_str(), "anthropic_key");
    assert_eq!(FindingKind::AwsAccessKey.as_str(), "aws_access_key");
    assert_eq!(FindingKind::Jwt.as_str(), "jwt");
    assert_eq!(FindingKind::EnvAssignment.as_str(), "env_assignment");
    assert_eq!(FindingKind::PemPrivateKey.as_str(), "pem_private_key");
    assert_eq!(FindingKind::LocalhostUrl.as_str(), "localhost_url");
    // I09c 扩展
    assert_eq!(FindingKind::SlackWebhook.as_str(), "slack_webhook");
    assert_eq!(FindingKind::StripeSecretKey.as_str(), "stripe_secret_key");
    // I09c 第二批
    assert_eq!(FindingKind::GoogleApiKey.as_str(), "google_api_key");
    assert_eq!(FindingKind::GitlabPat.as_str(), "gitlab_pat");
    // I09c 第三批
    assert_eq!(FindingKind::DatabaseUrl.as_str(), "database_url");
    // v6(2026-09-12 maskit 对照)
    assert_eq!(FindingKind::AliyunAccessKey.as_str(), "aliyun_access_key");
    assert_eq!(FindingKind::TencentSecretId.as_str(), "tencent_secret_id");
    assert_eq!(FindingKind::SlackToken.as_str(), "slack_token");
    assert_eq!(FindingKind::HuggingfaceToken.as_str(), "huggingface_token");

    // variant 计数 guard:穷举 match;新增 variant → 编译错误提示更新 golden
    fn count(v: FindingKind) -> u8 {
        match v {
            FindingKind::GithubToken => 1,
            FindingKind::OpenaiKey => 2,
            FindingKind::AnthropicKey => 3,
            FindingKind::AwsAccessKey => 4,
            FindingKind::Jwt => 5,
            FindingKind::EnvAssignment => 6,
            FindingKind::PemPrivateKey => 7,
            FindingKind::LocalhostUrl => 8,
            FindingKind::SlackWebhook => 9,
            FindingKind::StripeSecretKey => 10,
            FindingKind::GoogleApiKey => 11,
            FindingKind::GitlabPat => 12,
            FindingKind::DatabaseUrl => 13,
            FindingKind::AliyunAccessKey => 14,
            FindingKind::TencentSecretId => 15,
            FindingKind::SlackToken => 16,
            FindingKind::HuggingfaceToken => 17,
        }
    }
    assert_eq!(count(FindingKind::HuggingfaceToken), 17);
}

#[test]
fn browser_error_code_as_str_golden() {
    assert_eq!(BrowserErrorCode::TooLarge.as_str(), "too_large");
    assert_eq!(BrowserErrorCode::BadJson.as_str(), "bad_json");
    assert_eq!(BrowserErrorCode::OriginDenied.as_str(), "origin_denied");
    assert_eq!(BrowserErrorCode::BadRequestId.as_str(), "bad_request_id");
    assert_eq!(BrowserErrorCode::Internal.as_str(), "internal");

    fn count(v: BrowserErrorCode) -> u8 {
        match v {
            BrowserErrorCode::TooLarge => 1,
            BrowserErrorCode::BadJson => 2,
            BrowserErrorCode::OriginDenied => 3,
            BrowserErrorCode::BadRequestId => 4,
            BrowserErrorCode::Internal => 5,
        }
    }
    assert_eq!(count(BrowserErrorCode::Internal), 5);
}

/// serde 契约验证:`as_str` 的输出应与 `serde_json` 序列化后的字符串一致
/// (两者都是 `snake_case`,但 serde 不依赖 `as_str`,需守门一致性)。
#[test]
fn as_str_matches_serde_snake_case_for_finding_kind() {
    let cases: &[(FindingKind, &str)] = &[
        (FindingKind::GithubToken, "github_token"),
        (FindingKind::OpenaiKey, "openai_key"),
        (FindingKind::LocalhostUrl, "localhost_url"),
    ];
    for &(v, expected) in cases {
        let serde_out = serde_json::to_string(&v).unwrap();
        // serde 字符串会被双引号包裹,strip 之
        let serde_unquoted = serde_out.trim_matches('"');
        assert_eq!(
            v.as_str(),
            serde_unquoted,
            "as_str vs serde mismatch for {:?}",
            v
        );
        assert_eq!(v.as_str(), expected);
    }
}
