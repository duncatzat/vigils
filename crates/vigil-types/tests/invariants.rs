//! I00 安全不变量的占位测试。这些测试编译通过即保证类型层面上对应 AGENTS.md 的约束成立。
//! 运行时 / 持久化的不变量将在 I01+ 对应 crate 的测试中补齐。
//!
//! 本文件是测试代码,AGENTS.md "Implementation rules" 明确允许 unwrap/expect。
//! workspace lint 把 unwrap/expect 设为 warn 以覆盖运行时路径,这里显式放开。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use vigil_types::{
    ApprovalStatus, DecisionKind, EffectKind, InjectionMethod, PrincipalKind, SecretLease,
    SessionSource, TransportKind, TrustLevel,
};

/// 不变量 §6：Side effects require allow / deny / approve decisions.
/// 这三种裁决必须存在且相互区分。
#[test]
fn decision_kind_has_three_distinct_variants() {
    let variants = [
        DecisionKind::Allow,
        DecisionKind::Deny,
        DecisionKind::Approve,
    ];
    for (i, a) in variants.iter().enumerate() {
        for (j, b) in variants.iter().enumerate() {
            if i == j {
                assert_eq!(a, b);
            } else {
                assert_ne!(a, b);
            }
        }
    }
}

/// TrustLevel::default() 必须是 Untrusted —— 新注册主体不得自动获得信任。
#[test]
fn trust_level_defaults_to_untrusted() {
    assert_eq!(TrustLevel::default(), TrustLevel::Untrusted);
    // 序不变：Untrusted < Limited < Trusted（供策略做分级判断）
    assert!(TrustLevel::Untrusted < TrustLevel::Limited);
    assert!(TrustLevel::Limited < TrustLevel::Trusted);
}

/// 不变量 §4(类型层,字段名防御):SecretLease 不得出现典型敏感字段名。
/// 未来有人不小心在结构体里加 `pub token: String`,Debug 会自动打印,本测试立刻炸掉。
#[test]
fn secret_lease_debug_does_not_leak_token_field_names() {
    let lease = sample_lease();
    let dbg = format!("{:?}", lease);
    let forbidden = ["token", "password", "secret_value", "bearer", "api_key"];
    for needle in forbidden {
        assert!(
            !dbg.to_lowercase().contains(needle),
            "SecretLease Debug 泄漏了敏感字段字面量: {}(在输出中找到 `{}`)",
            dbg,
            needle
        );
    }
    // 但 alias 本身是允许出现的(它就是为了展示用的标识)
    assert!(dbg.contains("secret://github/repo-write"));
}

/// 不变量 §4(类型层,序列化表面边界):
/// `SecretLease` 的 Debug / Display / serde 输出的**字段集合必须保持已知且固定**。
///
/// 本测试**不**主张"完全不出现魔法字符串" —— 既有字段 `lease_id`/`secret_ref` 就是
/// 字符串,打印/序列化它们的值是被允许的设计。本测试要守住的更严格的不变量是:
///
/// 1. Debug 输出的字段集合 = {lease_id, secret_ref, injection_method, expires_at}。
///    bound_*/approval_id 字段**绝不**出现在 Debug 里。
/// 2. Display 输出形式 = `SecretLease(<alias>)`,出现 alias 值恰好 1 次。
/// 3. serde_json 输出的字段集合 = 预声明的 8 个,不多不少。若未来新增字段,本测试会
///    主动失败,强迫开发者同步审查 `vigil-redaction` 的脱敏规则与 §1 不变量(字段不
///    得承载真实 secret 值)。
#[test]
fn secret_lease_serialization_surface_is_stable_and_bounded() {
    const MAGIC: &str = "ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

    let lease = SecretLease {
        lease_id: MAGIC.into(),
        secret_ref: MAGIC.into(),
        bound_session_id: MAGIC.into(),
        bound_server_id: MAGIC.into(),
        bound_tool_name: MAGIC.into(),
        approval_id: Some(MAGIC.into()),
        injection_method: InjectionMethod::HttpHeader,
        expires_at: 0,
    };

    // (1) Debug:只允许 MAGIC 在 lease_id 和 secret_ref 两处出现,共 2 次。
    let dbg = format!("{:?}", lease);
    assert_eq!(
        dbg.matches(MAGIC).count(),
        2,
        "Debug 字段集合越界(应只含 lease_id + secret_ref + injection_method + expires_at): {}",
        dbg
    );
    // bound_*/approval_id 的字段名不得出现在 Debug 中。
    for forbidden_field in [
        "bound_session_id",
        "bound_server_id",
        "bound_tool_name",
        "approval_id",
    ] {
        assert!(
            !dbg.contains(forbidden_field),
            "Debug 泄漏了 bound 关联字段 `{}`: {}",
            forbidden_field,
            dbg
        );
    }

    // (2) Display:MAGIC 恰好出现 1 次(仅作为 secret_ref alias)。
    let disp = format!("{}", lease);
    assert_eq!(disp, format!("SecretLease({})", MAGIC));

    // (3) serde_json:字段集合精确等于 8 个预声明项。
    let json = serde_json::to_string(&lease).unwrap();
    let expected_keys: &[&str] = &[
        "lease_id",
        "secret_ref",
        "bound_session_id",
        "bound_server_id",
        "bound_tool_name",
        "approval_id",
        "injection_method",
        "expires_at",
    ];
    for k in expected_keys {
        assert!(
            json.contains(&format!(r#""{}""#, k)),
            "序列化缺字段 {}: {}",
            k,
            json
        );
    }
    // 字段总数 = 8;若新增字段会让本断言失败 —— 这是 feature 不是 bug:
    // 新增字段必须人工评审是否可能承载 secret 值,并同步更新 vigil-redaction。
    let key_count = json.matches(r#"":"#).count();
    assert_eq!(
        key_count, 8,
        "SecretLease 序列化字段数从 8 变为 {},请先更新本测试 + vigil-redaction 脱敏规则: {}",
        key_count, json
    );
}

/// Display 必须是脱敏的单行,只含 alias 信息。
#[test]
fn secret_lease_display_only_shows_alias() {
    let lease = sample_lease();
    let s = format!("{}", lease);
    assert_eq!(s, "SecretLease(secret://github/repo-write)");
}

/// 核心枚举必须以稳定的 PascalCase 文本序列化 —— 这是跨版本账本/审批记录兼容的基础。
/// 不要依赖 serde 默认行为,值要与主方案 §2 的 Rust 写法一一对应。
#[test]
fn core_enums_serialize_as_pascal_case_stable_tokens() {
    // 每条断言:(值, 期望 JSON 字符串)
    let effect_cases: &[(EffectKind, &str)] = &[
        (EffectKind::FsRead, r#""FsRead""#),
        (EffectKind::FsWrite, r#""FsWrite""#),
        (EffectKind::DbRead, r#""DbRead""#),
        (EffectKind::DbWrite, r#""DbWrite""#),
        (EffectKind::NetOutbound, r#""NetOutbound""#),
        (EffectKind::ExecWasm, r#""ExecWasm""#),
        (EffectKind::ExecNative, r#""ExecNative""#),
        (EffectKind::SecretUse, r#""SecretUse""#),
        (EffectKind::BrowserSubmit, r#""BrowserSubmit""#),
        (EffectKind::CommSend, r#""CommSend""#),
        (EffectKind::CredentialExchange, r#""CredentialExchange""#),
    ];
    for (v, expected) in effect_cases {
        let actual = serde_json::to_string(v).unwrap();
        assert_eq!(&actual, expected, "EffectKind::{:?}", v);
        let back: EffectKind = serde_json::from_str(&actual).unwrap();
        assert_eq!(back, *v);
    }

    let session_cases: &[(SessionSource, &str)] = &[
        (SessionSource::McpClient, r#""McpClient""#),
        (SessionSource::Browser, r#""Browser""#),
        (SessionSource::Desktop, r#""Desktop""#),
        (SessionSource::Cli, r#""Cli""#),
    ];
    for (v, expected) in session_cases {
        assert_eq!(serde_json::to_string(v).unwrap(), *expected);
    }

    let transport_cases: &[(TransportKind, &str)] = &[
        (TransportKind::Stdio, r#""Stdio""#),
        (TransportKind::Http, r#""Http""#),
    ];
    for (v, expected) in transport_cases {
        assert_eq!(serde_json::to_string(v).unwrap(), *expected);
    }

    let principal_cases: &[(PrincipalKind, &str)] = &[
        (PrincipalKind::User, r#""User""#),
        (PrincipalKind::Agent, r#""Agent""#),
        (PrincipalKind::BrowserExtension, r#""BrowserExtension""#),
        (PrincipalKind::McpServer, r#""McpServer""#),
    ];
    for (v, expected) in principal_cases {
        assert_eq!(serde_json::to_string(v).unwrap(), *expected);
    }

    let decision_cases: &[(DecisionKind, &str)] = &[
        (DecisionKind::Allow, r#""Allow""#),
        (DecisionKind::Deny, r#""Deny""#),
        (DecisionKind::Approve, r#""Approve""#),
    ];
    for (v, expected) in decision_cases {
        assert_eq!(serde_json::to_string(v).unwrap(), *expected);
    }

    let approval_cases: &[(ApprovalStatus, &str)] = &[
        (ApprovalStatus::Pending, r#""Pending""#),
        (ApprovalStatus::Approved, r#""Approved""#),
        (ApprovalStatus::Denied, r#""Denied""#),
        (ApprovalStatus::Expired, r#""Expired""#),
        (ApprovalStatus::Cancelled, r#""Cancelled""#),
    ];
    for (v, expected) in approval_cases {
        assert_eq!(serde_json::to_string(v).unwrap(), *expected);
    }

    let trust_cases: &[(TrustLevel, &str)] = &[
        (TrustLevel::Untrusted, r#""Untrusted""#),
        (TrustLevel::Limited, r#""Limited""#),
        (TrustLevel::Trusted, r#""Trusted""#),
    ];
    for (v, expected) in trust_cases {
        assert_eq!(serde_json::to_string(v).unwrap(), *expected);
    }

    let injection_cases: &[(InjectionMethod, &str)] = &[
        (InjectionMethod::HttpHeader, r#""HttpHeader""#),
        (InjectionMethod::ChildEnv, r#""ChildEnv""#),
        (InjectionMethod::Pipe, r#""Pipe""#),
        (InjectionMethod::TempFile, r#""TempFile""#),
        (InjectionMethod::HookCommand, r#""HookCommand""#),
    ];
    for (v, expected) in injection_cases {
        assert_eq!(serde_json::to_string(v).unwrap(), *expected);
    }
}

fn sample_lease() -> SecretLease {
    SecretLease {
        lease_id: "lease-1".into(),
        secret_ref: "secret://github/repo-write".into(),
        bound_session_id: "sess-1".into(),
        bound_server_id: "github".into(),
        bound_tool_name: "github__create_issue".into(),
        approval_id: None,
        injection_method: InjectionMethod::HttpHeader,
        expires_at: 0,
    }
}
