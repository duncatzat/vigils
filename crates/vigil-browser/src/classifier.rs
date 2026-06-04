//! Browser classifier(ADR 0009 §D3 §D6):text → `BrowserCheckResponse`。
//!
//! 流程:
//! 1. origin 校验(特权 scheme 拒 → Block + OriginDenied)
//! 2. `vigil_redaction::scan_hard_findings` 扫硬指纹
//! 3. 本地 localhost URL 规则追加扫描
//! 4. 决定 action:
//!    - `pem_private_key` 命中 → Block(ADR §D6)
//!    - 任一其他 finding → Redact(调 `scrub_text` 得 `redacted_text`)
//!    - 无 finding → Allow
//! 5. Redact 分支做 fail-closed re-scan(§I-9.6):若 redacted 文本仍含硬指纹,
//!    说明 scrub 不彻底 → 升级为 Block,`redacted_text = None`。

use once_cell::sync::Lazy;
use regex::Regex;

use crate::origin::validate_browser_origin;
use crate::protocol::{
    BrowserAction, BrowserCheckRequest, BrowserCheckResponse, BrowserErrorCode, FindingKind,
};

/// `http(s)://(localhost|127.0.0.1|::1|*.local)` URL 识别。
///
/// 粗匹配即可 —— 分类器只需决定"是否含 localhost 链接",不参与地址解析。
static LOCALHOST_URL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\bhttps?://(?:localhost|127\.0\.0\.1|\[::1\]|[a-z0-9\-]+\.local)(?::\d+)?(?:/[^\s]*)?",
    )
    .expect("regex")
});

/// classifier 结果或协议级错误(origin 非法等)。
#[derive(Debug)]
pub enum ClassifyOutcome {
    /// 正常返 response
    Response(BrowserCheckResponse),
    /// 协议级错误(request 本身就不合法)
    Error(BrowserErrorCode),
}

/// 主入口:消费 `BrowserCheckRequest`,返 `ClassifyOutcome`。
///
/// **内存契约**(ADR §I-9.1):`request.text` 在本函数末尾 drop;
/// 不进入 log / tracing。
pub fn classify(request: &BrowserCheckRequest) -> ClassifyOutcome {
    // 0. request_id 合法性
    if request.request_id.is_empty() || !request.request_id.is_ascii() {
        return ClassifyOutcome::Error(BrowserErrorCode::BadRequestId);
    }
    // 1. origin 校验
    if let Err(code) = validate_browser_origin(&request.origin) {
        return ClassifyOutcome::Error(code);
    }

    // 2. 硬指纹扫描
    let raw_findings = vigil_redaction::scan_hard_findings(&request.text);
    let mut kinds: Vec<FindingKind> = Vec::new();
    let mut has_pem = false;
    for name in &raw_findings {
        if let Some(k) = map_rule_name(name) {
            if !kinds.contains(&k) {
                if k == FindingKind::PemPrivateKey {
                    has_pem = true;
                }
                kinds.push(k);
            }
        }
    }

    // 3. localhost URL(额外规则)
    if LOCALHOST_URL_RE.is_match(&request.text) && !kinds.contains(&FindingKind::LocalhostUrl) {
        kinds.push(FindingKind::LocalhostUrl);
    }

    // 4. 决策
    let (action, redacted_text) = if kinds.is_empty() {
        (BrowserAction::Allow, None)
    } else if has_pem {
        // §D6 MVP:PEM 私钥直接 Block
        (BrowserAction::Block, None)
    } else {
        // Redact:用 scrub_text 得占位符文本
        let scrubbed = vigil_redaction::scrub_text(&request.text);
        // §I-9.6:re-scan 兜底,若占位符化后仍含硬指纹说明 scrub 不彻底 → 升级 Block
        if !vigil_redaction::scan_hard_findings(&scrubbed).is_empty() {
            (BrowserAction::Block, None)
        } else {
            (BrowserAction::Redact, Some(scrubbed))
        }
    };

    ClassifyOutcome::Response(BrowserCheckResponse {
        request_id: request.request_id.clone(),
        action,
        findings: kinds,
        redacted_text,
    })
}

/// `vigil_redaction` 的 rule name 映射到 `FindingKind`。
/// 未知规则名(未列入 FindingKind 的 email / internal_ipv4 等)返 None → I09a 忽略。
fn map_rule_name(rule: &str) -> Option<FindingKind> {
    match rule {
        "github_token" => Some(FindingKind::GithubToken),
        "openai_api_key" => Some(FindingKind::OpenaiKey),
        "anthropic_api_key" => Some(FindingKind::AnthropicKey),
        "aws_access_key_id" => Some(FindingKind::AwsAccessKey),
        "jwt" => Some(FindingKind::Jwt),
        "env_assignment" => Some(FindingKind::EnvAssignment),
        "pem_private_key" => Some(FindingKind::PemPrivateKey),
        // I09c 扩展:新增 2 条 hard-rule 映射
        "slack_webhook" => Some(FindingKind::SlackWebhook),
        "stripe_secret_key" => Some(FindingKind::StripeSecretKey),
        // I09c 第二批
        "google_api_key" => Some(FindingKind::GoogleApiKey),
        "gitlab_pat" => Some(FindingKind::GitlabPat),
        // I09c 第三批
        "database_url" => Some(FindingKind::DatabaseUrl),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::BrowserEventKind;

    fn req(text: &str) -> BrowserCheckRequest {
        BrowserCheckRequest {
            request_id: "11111111-1111-1111-1111-111111111111".into(),
            origin: "https://chatgpt.com".into(),
            event_kind: BrowserEventKind::Paste,
            text: text.into(),
        }
    }

    fn resp(outcome: ClassifyOutcome) -> BrowserCheckResponse {
        match outcome {
            ClassifyOutcome::Response(r) => r,
            ClassifyOutcome::Error(e) => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn classifier_plain_text_allows() {
        let r = resp(classify(&req("Hello world, this is a normal message.")));
        assert_eq!(r.action, BrowserAction::Allow);
        assert!(r.findings.is_empty());
        assert!(r.redacted_text.is_none());
    }

    #[test]
    fn classifier_github_token_triggers_redact() {
        let text = "please set token ghp_1234567890abcdef1234567890abcdef12345678 for use";
        let r = resp(classify(&req(text)));
        assert_eq!(r.action, BrowserAction::Redact);
        assert_eq!(r.findings, vec![FindingKind::GithubToken]);
        let redacted = r.redacted_text.unwrap();
        assert!(!redacted.contains("ghp_1234567890abcdef1234567890abcdef12345678"));
        assert!(redacted.contains("[REDACTED"));
    }

    #[test]
    fn classifier_pem_private_key_triggers_block() {
        let text =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----";
        let r = resp(classify(&req(text)));
        assert_eq!(r.action, BrowserAction::Block);
        assert!(r.findings.contains(&FindingKind::PemPrivateKey));
        assert!(r.redacted_text.is_none(), "Block 不返 redacted_text");
    }

    #[test]
    fn classifier_jwt_redacts() {
        let text =
            "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let r = resp(classify(&req(text)));
        assert_eq!(r.action, BrowserAction::Redact);
        assert!(r.findings.contains(&FindingKind::Jwt));
    }

    #[test]
    fn classifier_env_assignment_redacts() {
        let text = "DATABASE_PASSWORD=hunter2_secret_dont_share";
        let r = resp(classify(&req(text)));
        assert_eq!(r.action, BrowserAction::Redact);
        assert!(r.findings.contains(&FindingKind::EnvAssignment));
    }

    #[test]
    fn classifier_bare_token_assignment_redacts() {
        let text = "token=sadqwdzcfqdqdwqdqdq";
        let r = resp(classify(&req(text)));
        assert_eq!(r.action, BrowserAction::Redact);
        assert_eq!(r.findings, vec![FindingKind::EnvAssignment]);
        let redacted = r.redacted_text.unwrap();
        assert_eq!(redacted, "[REDACTED env_assignment]");
    }

    #[test]
    fn classifier_localhost_url_redacts() {
        let text = "run against http://localhost:8080/api/debug";
        let r = resp(classify(&req(text)));
        assert_eq!(r.action, BrowserAction::Redact);
        assert!(r.findings.contains(&FindingKind::LocalhostUrl));
    }

    #[test]
    fn classifier_slack_webhook_redacts() {
        // I09c:泄漏后任意人可 post 到该频道
        let text = "notify via https://hooks.slack.com/services/TABCDEFGHIJ/BABCDEFGHIJ/abcdefghijklmnopqrstuvwx please";
        let r = resp(classify(&req(text)));
        assert_eq!(r.action, BrowserAction::Redact);
        assert!(r.findings.contains(&FindingKind::SlackWebhook));
        let redacted = r.redacted_text.unwrap();
        assert!(
            !redacted.contains("hooks.slack.com/services/TABCDEFGHIJ"),
            "redacted_text 不得保留 Slack webhook 原文片段: {redacted}"
        );
    }

    #[test]
    fn classifier_stripe_secret_key_redacts() {
        // I09c:Stripe live/test 密钥 `sk_(live|test)_...`
        for prefix in ["sk_live_", "sk_test_"] {
            let text = format!("Set STRIPE_KEY to {prefix}abcdef0123456789abcdef0123 then submit");
            let r = resp(classify(&req(&text)));
            assert_eq!(r.action, BrowserAction::Redact, "prefix {prefix}");
            assert!(
                r.findings.contains(&FindingKind::StripeSecretKey),
                "{prefix} should trigger StripeSecretKey"
            );
            let redacted = r.redacted_text.unwrap();
            assert!(
                !redacted.contains(prefix),
                "redacted_text 含原文前缀: {redacted}"
            );
        }
    }

    #[test]
    fn classifier_google_api_key_redacts() {
        // I09c 第二批:Google API key(`AIza` + 35 chars = 39 chars total)
        let text = "GOOGLE_MAPS_KEY = AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456";
        let r = resp(classify(&req(text)));
        assert_eq!(r.action, BrowserAction::Redact);
        assert!(r.findings.contains(&FindingKind::GoogleApiKey));
        let redacted = r.redacted_text.unwrap();
        assert!(
            !redacted.contains("AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456"),
            "redacted_text 不得保留 Google API key 原文: {redacted}"
        );
    }

    #[test]
    fn classifier_gitlab_pat_redacts() {
        // I09c 第二批:GitLab PAT(`glpat-` + 20+ chars)
        let text = "CI token: glpat-abcdef0123456789ABCDEF";
        let r = resp(classify(&req(text)));
        assert_eq!(r.action, BrowserAction::Redact);
        assert!(r.findings.contains(&FindingKind::GitlabPat));
        let redacted = r.redacted_text.unwrap();
        assert!(
            !redacted.contains("glpat-abcdef0123456789"),
            "redacted_text 不得保留 GitLab PAT 原文片段: {redacted}"
        );
    }

    #[test]
    fn classifier_database_url_redacts() {
        // I09c 第三批:含凭证的 postgres URL(`scheme://user:password@host/db`)
        let text = "DSN postgres://admin:s3cr3tP%40ss@db.internal.example.com:5432/app_prod";
        let r = resp(classify(&req(text)));
        assert_eq!(r.action, BrowserAction::Redact);
        assert!(
            r.findings.contains(&FindingKind::DatabaseUrl),
            "含凭证 DB URL 应触发 DatabaseUrl findings={:?}",
            r.findings
        );
        let redacted = r.redacted_text.unwrap();
        assert!(
            !redacted.contains("s3cr3tP%40ss"),
            "redacted_text 不得保留 DB password 原文: {redacted}"
        );
        assert!(
            !redacted.contains("admin:s3cr3tP"),
            "redacted_text 不得保留 user:password 片段: {redacted}"
        );
    }

    #[test]
    fn classifier_database_url_without_credentials_does_not_match() {
        // 防御:无 user:password 的 DB URL 不算敏感(误报抑制)。
        // `postgres://host/db` 或 `postgres://host:5432/db` 应走普通 LocalhostUrl 或 allow
        // 路径,不触发 DatabaseUrl。
        let text = "DSN postgres://db.internal.example.com:5432/app_prod";
        let r = resp(classify(&req(text)));
        assert!(
            !r.findings.contains(&FindingKind::DatabaseUrl),
            "无凭证 DB URL 不应触发 DatabaseUrl findings={:?}",
            r.findings
        );
    }

    #[test]
    fn classifier_database_url_mongodb_srv_redacts() {
        // longest-first scheme alternation 验证:`mongodb+srv` 必须优先于 `mongodb` 匹配
        // (regex alternation 顺序敏感,若写反 `mongodb` 会先吃掉 scheme 前缀 → match 失败)。
        let text = "conn = mongodb+srv://dbuser:SuperSecret123@cluster0.mongodb.net/appdb";
        let r = resp(classify(&req(text)));
        assert_eq!(r.action, BrowserAction::Redact);
        assert!(
            r.findings.contains(&FindingKind::DatabaseUrl),
            "mongodb+srv scheme 应被 longest-first 分支命中 findings={:?}",
            r.findings
        );
        let redacted = r.redacted_text.unwrap();
        assert!(
            !redacted.contains("SuperSecret123"),
            "redacted_text 不得保留 mongodb password: {redacted}"
        );
    }

    #[test]
    fn classifier_google_key_coexists_with_env_assignment() {
        // 防御(R1 MUST-FIX 精准化):`GOOGLE_MAPS_KEY=AIzaSy...` 同时触发两条规则:
        // ① env_assignment(KEY=VALUE 形状)② google_api_key(独立 regex)
        // 断言**两者共存**,语义确认"GoogleApiKey 独立识别不被 env_assignment 吸收"。
        // 若未来规则顺序 / 优先级重排需要 GoogleApiKey "优先" 展示给用户,再另加顺序断言。
        let text = "GOOGLE_MAPS_KEY=AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456";
        let r = resp(classify(&req(text)));
        assert!(
            r.findings.contains(&FindingKind::GoogleApiKey),
            "Google key regex 应独立识别 findings={:?}",
            r.findings
        );
        assert!(
            r.findings.contains(&FindingKind::EnvAssignment),
            "KEY=VALUE 形状应仍被 env_assignment 命中(两条规则共存,非互斥) findings={:?}",
            r.findings
        );
        // redacted_text 不得留原文 —— 两条规则都应让值被 scrub
        let redacted = r.redacted_text.unwrap();
        assert!(
            !redacted.contains("AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456"),
            "redacted_text 不得留 Google key 原文: {redacted}"
        );
    }

    #[test]
    fn classifier_stripe_live_does_not_match_anthropic() {
        // 防御:stripe `sk_` 和 anthropic `sk-` 字符不同,规则隔离
        let text = "use sk-ant-0123456789abcdefghijklmnop as fallback";
        let r = resp(classify(&req(text)));
        assert!(r.findings.contains(&FindingKind::AnthropicKey));
        assert!(
            !r.findings.contains(&FindingKind::StripeSecretKey),
            "anthropic sk-... 不应误判为 stripe sk_..."
        );
    }

    #[test]
    fn classifier_multiple_findings_block_wins_on_pem() {
        let text = format!(
            "token ghp_1234567890abcdef1234567890abcdef12345678 and {}",
            "-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----"
        );
        let r = resp(classify(&req(&text)));
        assert_eq!(r.action, BrowserAction::Block, "pem 存在应优先 Block");
        assert!(r.findings.contains(&FindingKind::PemPrivateKey));
        assert!(r.findings.contains(&FindingKind::GithubToken));
    }

    #[test]
    fn origin_scheme_denied() {
        let mut r = req("hi");
        r.origin = "chrome-extension://abc/".into();
        match classify(&r) {
            ClassifyOutcome::Error(BrowserErrorCode::OriginDenied) => {}
            other => panic!("期望 OriginDenied,得到 {other:?}"),
        }
    }

    #[test]
    fn empty_request_id_rejected() {
        let mut r = req("hi");
        r.request_id = String::new();
        match classify(&r) {
            ClassifyOutcome::Error(BrowserErrorCode::BadRequestId) => {}
            other => panic!("期望 BadRequestId,得到 {other:?}"),
        }
    }

    #[test]
    fn redacted_text_does_not_leak_matched_spans() {
        // 多条 finding 混合,redacted_text 应只含占位符,不含任一原文片段
        let text = "key ghp_1234567890abcdef1234567890abcdef12345678 + sk-ant-aaaaaaaaaaaaaaaaaaaaaa + jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.aaaaaaaaaaaaaaaaaaaaaa";
        let r = resp(classify(&req(text)));
        assert_eq!(r.action, BrowserAction::Redact);
        let redacted = r.redacted_text.unwrap();
        for span in [
            "ghp_1234567890abcdef",
            "sk-ant-aaaaaaaaaaaaaaaaaaaaaa",
            "eyJhbGciOiJIUzI1NiJ9",
        ] {
            assert!(
                !redacted.contains(span),
                "redacted_text 不得含原文片段 {span}: {redacted}"
            );
        }
    }
}
