//! 审计 payload 构造(ADR 0009 §D5)。
//!
//! 固定字段白名单:`origin / event_kind / finding_kinds / finding_count /
//! length_bucket / action / redacted / request_id / rule_profile_version`。
//!
//! **严禁**:原文 / redacted_text / 全量文本 sha256。新增字段须同步更新
//! `audit_payload_schema_whitelist` 测试。

use serde_json::{json, Value};

use crate::protocol::{
    BrowserAction, BrowserCheckResponse, BrowserEventKind, RULE_PROFILE_VERSION,
};

/// `browser.paste_checked` 审计事件类型。
pub const EVENT_PASTE: &str = "browser.paste_checked";

/// `browser.input_checked` 审计事件类型。
pub const EVENT_INPUT: &str = "browser.input_checked";

/// `browser.submit_checked` 审计事件类型。
pub const EVENT_SUBMIT: &str = "browser.submit_checked";

/// `build_audit_payload` 的入参 —— **只**含 metadata 字段,**不**持 raw text 引用。
///
/// **Codex R1 MUST-FIX 修复**:把"不得带 raw text"编码进类型边界。构造本 struct
/// 只需 length + 枚举 + id,不会让未来的重构误触 `request.text`。
#[derive(Debug, Clone)]
pub struct BrowserAuditMeta<'a> {
    /// 来自 request(已过 `validate_browser_origin` 纯 origin 校验)
    pub origin: &'a str,
    /// 来自 request
    pub event_kind: BrowserEventKind,
    /// 来自 request
    pub request_id: &'a str,
    /// 原文字节长度 —— `audit_payload` 只用桶化值
    pub text_len: usize,
}

/// 给定 `meta` + `response` 组装审计 payload(仅 metadata,**严格不含** raw text / redacted_text)。
pub fn build_audit_payload(meta: &BrowserAuditMeta<'_>, response: &BrowserCheckResponse) -> Value {
    let finding_kinds: Vec<&'static str> = response.findings.iter().map(|f| f.as_str()).collect();
    let event_kind = match meta.event_kind {
        BrowserEventKind::Paste => "paste",
        BrowserEventKind::Input => "input",
        BrowserEventKind::Submit => "submit",
    };
    let action = match response.action {
        BrowserAction::Allow => "allow",
        BrowserAction::Redact => "redact",
        BrowserAction::Block => "block",
    };
    json!({
        "origin": meta.origin,
        "event_kind": event_kind,
        "finding_kinds": finding_kinds,
        "finding_count": finding_kinds.len(),
        "length_bucket": length_bucket(meta.text_len),
        "action": action,
        "redacted": matches!(response.action, BrowserAction::Redact),
        "request_id": meta.request_id,
        "rule_profile_version": RULE_PROFILE_VERSION,
    })
}

/// 给定 request 返对应 event type(`browser.*_checked`)。
pub fn event_type_for(kind: BrowserEventKind) -> &'static str {
    match kind {
        BrowserEventKind::Paste => EVENT_PASTE,
        BrowserEventKind::Input => EVENT_INPUT,
        BrowserEventKind::Submit => EVENT_SUBMIT,
    }
}

/// 长度桶(ADR §D5)。
fn length_bucket(n: usize) -> &'static str {
    match n {
        0..=99 => "0-100",
        100..=499 => "100-500",
        500..=1999 => "500-2000",
        _ => "2000+",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{BrowserAction, FindingKind};

    fn mk_meta(origin: &'static str) -> BrowserAuditMeta<'static> {
        BrowserAuditMeta {
            origin,
            event_kind: BrowserEventKind::Paste,
            request_id: "rid-1",
            text_len: 42,
        }
    }

    fn mk_resp(action: BrowserAction, findings: Vec<FindingKind>) -> BrowserCheckResponse {
        BrowserCheckResponse {
            request_id: "rid-1".into(),
            action,
            findings,
            redacted_text: match action {
                BrowserAction::Redact => Some("[REDACTED x]".into()),
                _ => None,
            },
        }
    }

    /// ADR §D5 + §I-9.2:payload 字段集合必须**恰好**等于白名单。
    #[test]
    fn audit_payload_schema_whitelist() {
        let p = build_audit_payload(
            &mk_meta("https://x.com"),
            &mk_resp(BrowserAction::Allow, vec![]),
        );
        let obj = p.as_object().unwrap();
        let keys: std::collections::BTreeSet<&str> = obj.keys().map(|s| s.as_str()).collect();
        let expected: std::collections::BTreeSet<&str> = [
            "origin",
            "event_kind",
            "finding_kinds",
            "finding_count",
            "length_bucket",
            "action",
            "redacted",
            "request_id",
            "rule_profile_version",
        ]
        .into_iter()
        .collect();
        assert_eq!(
            keys, expected,
            "audit payload 字段集合偏离白名单,更新 ADR §D5 后同步更新此测试"
        );
    }

    #[test]
    fn length_bucket_boundaries() {
        assert_eq!(length_bucket(0), "0-100");
        assert_eq!(length_bucket(99), "0-100");
        assert_eq!(length_bucket(100), "100-500");
        assert_eq!(length_bucket(499), "100-500");
        assert_eq!(length_bucket(500), "500-2000");
        assert_eq!(length_bucket(1999), "500-2000");
        assert_eq!(length_bucket(2000), "2000+");
    }

    #[test]
    fn input_event_maps_to_input_audit_type_and_payload_kind() {
        let meta = BrowserAuditMeta {
            origin: "https://chatgpt.com",
            event_kind: BrowserEventKind::Input,
            request_id: "rid-input",
            text_len: 42,
        };
        let resp = mk_resp(BrowserAction::Redact, vec![FindingKind::EnvAssignment]);
        let payload = build_audit_payload(&meta, &resp);
        assert_eq!(event_type_for(BrowserEventKind::Input), EVENT_INPUT);
        assert_eq!(payload["event_kind"], "input");
        assert_eq!(payload["action"], "redact");
    }

    /// ADR §I-9.1:audit payload 不得含原文 / redacted_text
    ///
    /// 现在接口层已强制(`BrowserAuditMeta` 不持 raw text),测试仍保留作 SENTINEL 扫描
    /// 兜底 —— 若未来误重构回接 raw,本测试会失败。
    #[test]
    fn audit_payload_never_contains_raw_or_redacted_text() {
        const SENTINEL: &str = "ghp_SUPERLONGSECRETSENTINEL_1234567890abcdef12";
        let meta = BrowserAuditMeta {
            origin: "https://chatgpt.com",
            event_kind: BrowserEventKind::Paste,
            request_id: "rid-1",
            text_len: SENTINEL.len(),
        };
        let resp = BrowserCheckResponse {
            request_id: "rid-1".into(),
            action: BrowserAction::Redact,
            findings: vec![FindingKind::GithubToken],
            redacted_text: Some("[REDACTED github_token]".into()),
        };
        let p = build_audit_payload(&meta, &resp);
        let s = serde_json::to_string(&p).unwrap();
        assert!(!s.contains(SENTINEL), "raw SENTINEL 泄漏到 audit payload");
        assert!(
            !s.contains("[REDACTED github_token]"),
            "redacted_text 不得出现在 audit payload"
        );
    }
}
