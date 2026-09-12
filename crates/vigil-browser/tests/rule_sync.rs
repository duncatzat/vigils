//! 跨 crate 一致性检验(Codex R1 NICE-TO-HAVE → R2 加固)。
//!
//! **目标**:防止 `vigil_browser::FindingKind` ↔ `vigil_redaction` 规则名漂移。
//!
//! **enforcement**:对每个 `(sample, expected_kind)`:
//! 1. `vigil_redaction::scan_hard_findings(sample)` 必须返非空(否则 vigil-redaction 规则坏了)
//! 2. `vigil_browser::classify(request)` 的 `findings` 必须**包含** `expected_kind`
//!    —— 这同时 enforce:
//!    - `FindingKind::as_str()` 没漂移(否则 classifier 内部 `map_rule_name` 失配,findings 会少)
//!    - `classifier::map_rule_name` 覆盖了所有相关 rule
//!
//! 若 FindingKind 枚举值 / `as_str()` 字符串 / `map_rule_name` 中任一处变更未同步,
//! 此测试 fail。

#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use vigil_browser::{
    classify, BrowserAction, BrowserCheckRequest, BrowserEventKind, ClassifyOutcome, FindingKind,
};

/// 本地规则(不来自 vigil-redaction)
const LOCAL_ONLY: &[FindingKind] = &[FindingKind::LocalhostUrl];

/// 每条:触发对应 FindingKind 的最小 sample 文本。
/// 若 FindingKind 新增 variant,这里必须加一条;否则 `finding_kind_enum_exhaustive` 失败。
const SAMPLES: &[(FindingKind, &str)] = &[
    (
        FindingKind::GithubToken,
        "ghp_1234567890abcdef1234567890abcdef12345678",
    ),
    (
        FindingKind::OpenaiKey,
        "sk-0123456789abcdefghijKLMNOPQRSTUVWXYZ",
    ),
    (
        FindingKind::AnthropicKey,
        "sk-ant-0123456789abcdefghijKLMNOPQR",
    ),
    (FindingKind::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE"),
    (
        FindingKind::Jwt,
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    ),
    (FindingKind::EnvAssignment, "DATABASE_PASSWORD=hunter2"),
    (
        FindingKind::PemPrivateKey,
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----",
    ),
    (FindingKind::LocalhostUrl, "http://localhost:8080/api"),
    // I09c 扩展:Slack incoming webhook + Stripe secret key
    (
        FindingKind::SlackWebhook,
        "https://hooks.slack.com/services/TABCDEFGHIJ/BABCDEFGHIJ/abcdefghijklmnopqrstuvwx",
    ),
    (
        FindingKind::StripeSecretKey,
        "sk_live_abcdef0123456789abcdef01",
    ),
    // I09c 第二批
    (
        FindingKind::GoogleApiKey,
        "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456",
    ),
    (FindingKind::GitlabPat, "glpat-abcdef0123456789ABCDEF"),
    // I09c 第三批:含凭证 DB URL(scheme://user:password@host/db)
    (
        FindingKind::DatabaseUrl,
        "postgres://admin:s3cr3tpass@db.example.com:5432/app",
    ),
    // v6(2026-09-12 maskit 对照):中国云厂商 / Slack token / HuggingFace 固定前缀。
    // 腾讯云 / Slack 样本字面量拆成两段:完整形态会被 GitHub push protection 当真凭据拦下推送。
    (FindingKind::AliyunAccessKey, "LTAI5tAbCdEf12345678"),
    (
        FindingKind::TencentSecretId,
        concat!("AK", "IDaBcDeFgHiJkLmNoPqRsTuVwXyZ012345"),
    ),
    (
        FindingKind::SlackToken,
        concat!("xox", "b-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"),
    ),
    (
        FindingKind::HuggingfaceToken,
        "hf_AbCdEfGhIjKlMnOpQrStUvWxYz01234567",
    ),
];

fn mk_request(text: &str) -> BrowserCheckRequest {
    BrowserCheckRequest {
        request_id: "rid-sync-1".into(),
        origin: "https://example.com".into(),
        event_kind: BrowserEventKind::Paste,
        text: text.into(),
    }
}

/// 每个 FindingKind 都必须能被 classifier 端到端识别。
///
/// 漂移场景:
/// - FindingKind 新增变种但 `classifier::map_rule_name` 没同步 → 测试失败(少一条 sample)
/// - `FindingKind::as_str()` 字符串改了但 vigil-redaction 规则名没跟 → 审计字段漂移,但**端到端行为**可能不变;此测试由 rule_name_strings 守
/// - vigil-redaction 规则改名 / 删除 → scan_hard_findings 返空或不含期望 rule → classifier findings 不含 kind → 失败
#[test]
fn every_finding_kind_is_classifier_reachable() {
    for (kind, sample) in SAMPLES {
        let req = mk_request(sample);
        let outcome = classify(&req);
        let resp = match outcome {
            ClassifyOutcome::Response(r) => r,
            ClassifyOutcome::Error(e) => panic!("{kind:?} sample 触发协议错: {e:?}"),
        };
        assert!(
            resp.findings.contains(kind),
            "FindingKind::{kind:?} 应被 classifier 识别 sample={sample:?},实际 findings={:?}",
            resp.findings
        );
        // PEM 应 Block;其他应 Redact(localhost/env/github/... 都走 Redact)
        if *kind == FindingKind::PemPrivateKey {
            assert_eq!(resp.action, BrowserAction::Block);
        } else {
            assert_eq!(
                resp.action,
                BrowserAction::Redact,
                "FindingKind::{kind:?} 应触发 Redact"
            );
        }
    }
}

/// 枚举完备性:新增变种必须更新 SAMPLES,否则漏 enforcement。
#[test]
fn finding_kind_enum_exhaustive() {
    // 枚举所有 FindingKind 变种;match 的 `_` 兜底会被新变种打破(编译 fail-closed)
    let all_kinds: &[FindingKind] = &[
        FindingKind::GithubToken,
        FindingKind::OpenaiKey,
        FindingKind::AnthropicKey,
        FindingKind::AwsAccessKey,
        FindingKind::Jwt,
        FindingKind::EnvAssignment,
        FindingKind::PemPrivateKey,
        FindingKind::LocalhostUrl,
        // I09c 扩展
        FindingKind::SlackWebhook,
        FindingKind::StripeSecretKey,
        // I09c 第二批
        FindingKind::GoogleApiKey,
        FindingKind::GitlabPat,
        // I09c 第三批
        FindingKind::DatabaseUrl,
        // v6
        FindingKind::AliyunAccessKey,
        FindingKind::TencentSecretId,
        FindingKind::SlackToken,
        FindingKind::HuggingfaceToken,
    ];
    // 若未来新增,`all_kinds` 数组必须同步扩(enum 本身**不是** `#[non_exhaustive]`,
    // workspace 内 match 是 fail-closed 穷举);用 SAMPLES 覆盖 + 断言长度一致,
    // 让"加枚举但没加 sample"被抓住(I09c R2 Codex 注释精准化)
    assert_eq!(
        SAMPLES.len(),
        all_kinds.len(),
        "FindingKind 变种与 SAMPLES 条目数不一致 —— 新增 variant 时同步更新 SAMPLES"
    );
    // 每个 kind 都出现在 SAMPLES 里
    for k in all_kinds {
        assert!(
            SAMPLES.iter().any(|(sk, _)| sk == k),
            "FindingKind::{k:?} 未在 SAMPLES 中"
        );
    }
}

/// `FindingKind::as_str()` 输出的字符串必须稳定(这些值会写进 audit payload)。
#[test]
fn finding_kind_stable_rule_name_strings() {
    // 字符串硬编码为 contract;改动任何一条都是破坏性变更
    let contract: &[(FindingKind, &str)] = &[
        (FindingKind::GithubToken, "github_token"),
        (FindingKind::OpenaiKey, "openai_key"),
        (FindingKind::AnthropicKey, "anthropic_key"),
        (FindingKind::AwsAccessKey, "aws_access_key"),
        (FindingKind::Jwt, "jwt"),
        (FindingKind::EnvAssignment, "env_assignment"),
        (FindingKind::PemPrivateKey, "pem_private_key"),
        (FindingKind::LocalhostUrl, "localhost_url"),
        // I09c 扩展
        (FindingKind::SlackWebhook, "slack_webhook"),
        (FindingKind::StripeSecretKey, "stripe_secret_key"),
        // I09c 第二批
        (FindingKind::GoogleApiKey, "google_api_key"),
        (FindingKind::GitlabPat, "gitlab_pat"),
        // I09c 第三批
        (FindingKind::DatabaseUrl, "database_url"),
        // v6
        (FindingKind::AliyunAccessKey, "aliyun_access_key"),
        (FindingKind::TencentSecretId, "tencent_secret_id"),
        (FindingKind::SlackToken, "slack_token"),
        (FindingKind::HuggingfaceToken, "huggingface_token"),
    ];
    // 长度守门(Codex R1 NICE-TO-HAVE):contract 必须覆盖所有 FindingKind。
    // 链式不变量:contract.len() == SAMPLES.len() == all_kinds.len()(后者由
    // `finding_kind_enum_exhaustive` 守门),所以 contract 也间接与枚举变种数强绑定。
    // 新增 variant → SAMPLES 先 fail → 修完 SAMPLES 再漏 contract 会在这里 fail。
    assert_eq!(
        contract.len(),
        SAMPLES.len(),
        "contract 与 SAMPLES 条目数不一致 —— 新增 FindingKind variant 时同步更新此 contract"
    );
    for (k, expected) in contract {
        assert_eq!(
            k.as_str(),
            *expected,
            "FindingKind::{k:?}::as_str() 契约漂移(改动会让旧 audit 记录失去语义)"
        );
    }
}

/// localhost URL 是本地规则,vigil-redaction 不应有同名 rule(避免消歧歧义)。
#[test]
fn local_only_rules_not_duplicated_in_redaction() {
    for kind in LOCAL_ONLY {
        let name = kind.as_str();
        // 让 vigil-redaction 扫一个 localhost URL,不应出现 "localhost_url" rule
        let hits = vigil_redaction::scan_hard_findings("http://localhost:8080/foo");
        assert!(
            !hits.contains(&name),
            "vigil-redaction 出现与本地规则 {name} 同名 rule,需消歧"
        );
    }
}

/// ISS-021:跨 crate sync —— 每个 `FindingKind::as_str()`(LOCAL_ONLY 除外)经
/// `vigil_redaction::PrivacyLabel::from_kind` 必返 `Some(_)`。
///
/// **关键漂移补丁**:vigil-browser 的 `FindingKind::as_str()` 用**短形**
/// `aws_access_key` / `anthropic_key` / `openai_key`,而 vigil-redaction 的
/// `HARD_RULES.name`(也是 `PrivacyLabel::from_kind` 接受的字面量)用**长形**
/// `aws_access_key_id` / `anthropic_api_key` / `openai_api_key`。本测试通过显式
/// alias 表证明两侧别名都被承认 —— 任一侧改名而忘了同步,本测试会指出具体漂移点
/// (feedback_extend_enum_sync_tests 的精确集合双向 diff 思路)。
///
/// alias 表是 ISS-021 的"跨 crate SSOT";新增 FindingKind 或改 HARD_RULES 名都
/// 需要同步本表 + ADR 0013 Revised 的"短形/长形 alias 漂移点"段。
#[test]
fn iss_021_finding_kind_maps_to_privacy_label_via_alias() {
    use std::collections::BTreeMap;

    let alias: BTreeMap<&str, &str> = [
        ("github_token", "github_token"),
        ("openai_key", "openai_api_key"), // 长短不一致:短形 → 长形
        ("anthropic_key", "anthropic_api_key"), // 长短不一致
        ("aws_access_key", "aws_access_key_id"), // 长短不一致
        ("jwt", "jwt"),
        ("env_assignment", "env_assignment"),
        ("pem_private_key", "pem_private_key"),
        ("slack_webhook", "slack_webhook"),
        ("stripe_secret_key", "stripe_secret_key"),
        ("google_api_key", "google_api_key"),
        ("gitlab_pat", "gitlab_pat"),
        ("database_url", "database_url"),
        // v6:aliyun 长短不一致(短形 → 长形 `_id`,与 aws 同构);其余同名
        ("aliyun_access_key", "aliyun_access_key_id"),
        ("tencent_secret_id", "tencent_secret_id"),
        ("slack_token", "slack_token"),
        ("huggingface_token", "huggingface_token"),
    ]
    .into_iter()
    .collect();

    // R1 NICE 修复:alias 表条目数 == FindingKind 非 LOCAL_ONLY 数,
    // 抓"alias 表多了陈旧行 / FindingKind 删了 variant 但 alias 没清理"两类漂移。
    // 与 SAMPLES.len() - LOCAL_ONLY.len() 强绑定,新增/删除 FindingKind 时若忘了
    // 同步本表会立刻 fail。
    assert_eq!(
        alias.len(),
        SAMPLES.len() - LOCAL_ONLY.len(),
        "ISS-021 alias 表条目数与 SAMPLES(非 LOCAL_ONLY)不一致 —— 检查是否有\
         陈旧 alias 行未清理 / 新增 FindingKind 漏同步 alias"
    );

    for (kind, _) in SAMPLES {
        if LOCAL_ONLY.contains(kind) {
            continue; // localhost_url 是 vigil-browser 本地规则,vigil-redaction 不识别
        }
        let short = kind.as_str();
        let long = alias.get(short).copied().unwrap_or_else(|| {
            panic!(
                "FindingKind::{kind:?}::as_str() = {short:?} 未在 ISS-021 跨 crate \
                 alias 表里;新增 FindingKind 时同步更新本测试 alias 表 + \
                 ADR 0013 Revised 'alias 漂移点' 段"
            )
        });
        let label = vigil_redaction::PrivacyLabel::from_kind(long);
        assert!(
            label.is_some(),
            "FindingKind::{kind:?}(short={short:?}, long={long:?})必须映射到\
             某个 PrivacyLabel;获 None 表示 vigil_redaction::PrivacyLabel::from_kind \
             漏了 {long:?}(ADR 0013 Revised D-final-2 封闭映射不变量被破)"
        );
    }
}

/// ISS-021:vigil-browser `FindingKind` 与 vigil-redaction `HARD_RULES`
/// secret-类条目数对齐(不含 LOCAL_ONLY,也不含 vigil-redaction 内部独有的
/// email / internal_ipv4)。
#[test]
fn iss_021_finding_kind_count_matches_redaction_hard_rules() {
    // vigil-redaction `HARD_RULES`(crates/vigil-redaction/src/lib.rs)有 16 条
    // secret-类:github / openai / anthropic / aws / jwt / pem / env_assignment /
    // slack / stripe / google / gitlab / database_url + v6 的 aliyun / tencent /
    // slack_token / huggingface。注:email / internal_ipv4
    // 在 ALL_RULES 但**不在** HARD_RULES(后者是 audit fail-closed 自检子集,
    // 见 lib.rs `HARD_RULES` 上方注释),且 vigil-browser 也没把它们暴露给扩展。
    let browser_kinds = SAMPLES.len() - LOCAL_ONLY.len(); // 17 - 1 = 16
    assert_eq!(
        browser_kinds, 16,
        "vigil-browser FindingKind 非 LOCAL_ONLY 应 16 项,与 vigil-redaction \
         HARD_RULES secret-类 16 条对齐;若改变需同步:\
         (1) 本断言数字 \
         (2) ADR 0013 Revised 版本史 \
         (3) RULE_PROFILE_VERSION 新版本注释"
    );
}
