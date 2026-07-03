//! I10a §12.3 I10 三条验收 + token store + 红线集成测试。
//!
//! I10b-α1 起迁移到 `ExpectedBinding + AlwaysAcceptVerifier`(ADR 0011 §α1-D3);
//! 不保留任何 compat shim / feature 后门。
//!
//! 全 mock:`MockHttpClient` + `InMemorySecretStore` + `Ledger::open_in_memory`。

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::err_expect,
    clippy::panic
)]

mod common;

use std::sync::Arc;

use base64::Engine;
#[allow(unused_imports)]
use common::{binding_for_test, AlwaysAcceptVerifier};
use oauth2::CsrfToken;
use vigil_audit::Ledger;
use vigil_http_auth::{
    build_authorization_url, event_type_for, exchange_code_for_token, fetch_and_validate_prm,
    new_pkce_pair, plan_authorized_request, token_ref_for_access, ExpectedBinding, HttpAuthError,
    HttpAuthEvent, HttpClient, HttpMethod, HttpResponse, MockHttpClient, OAuthTokenMetadata,
    ProtectedResourceMetadata, ResolvedAccessToken, TokenKind, TokenStore,
};
use vigil_lease::{InMemorySecretStore, SecretValue};

const TEST_ISSUER: &str = "https://auth.example.com";

fn sample_prm() -> ProtectedResourceMetadata {
    ProtectedResourceMetadata {
        resource: "https://mcp.example.com/".parse().unwrap(),
        authorization_servers: vec!["https://auth.example.com/".parse().unwrap()],
        bearer_methods_supported: vec!["header".into()],
        scopes_supported: vec!["mcp:tools.read".into(), "mcp:tools.write".into()],
        resource_documentation: None,
    }
}

/// 生成 unsigned JWT(I10a 不验签)。
fn mk_jwt(payload: &serde_json::Value) -> String {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = engine.encode(br#"{"alg":"none","typ":"JWT"}"#);
    let payload_bytes = serde_json::to_vec(payload).unwrap();
    let payload_b64 = engine.encode(&payload_bytes);
    let sig = engine.encode(b"sig");
    format!("{header}.{payload_b64}.{sig}")
}

// ================================================================
// §12.3 I10-1: token for wrong resource rejected
// ================================================================
#[test]
fn wrong_resource_rejected_when_jwt_aud_mismatches_prm_resource() {
    // JWT 的 aud 是 https://other.example.com/;PRM.resource = mcp.example.com/
    // I10b-α1 R1 修订:走 sealed `TokenStore::resolve_access_token`,
    // 不再调 crate-internal `validate_and_resolve_access_token`。
    let token_str = mk_jwt(&serde_json::json!({
        "iss": TEST_ISSUER,
        "aud": "https://other.example.com/",
        "scope": "mcp:tools.read",
        "exp": 9_999_999_999i64
    }));
    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    let ts = TokenStore::new(store, ledger);
    let token_ref = token_ref_for_access("https://other.example.com/", "c");
    let meta = OAuthTokenMetadata {
        token_ref: token_ref.clone(),
        resource: "https://other.example.com/".into(),
        authorization_server: "https://auth.example.com/".into(),
        issuer: TEST_ISSUER.into(),
        scope_set: vec!["mcp:tools.read".into()],
        token_kind: TokenKind::Access,
        expires_at: None,
        created_at: 0,
    };
    ts.put_access_token(&meta, SecretValue::new(token_str))
        .unwrap();

    let err = ts
        .resolve_access_token(
            &token_ref,
            &binding_for_test("https://mcp.example.com/", TEST_ISSUER, &["mcp:tools.read"]),
            1_700_000_000,
        )
        .unwrap_err();
    match err {
        HttpAuthError::AudienceMismatch { expected, actual } => {
            assert_eq!(expected, "https://mcp.example.com/");
            assert!(actual.contains("other.example.com"));
        }
        other => panic!("expected AudienceMismatch, got {other:?}"),
    }
}

// ================================================================
// §12.3 I10-2: passthrough fails closed(incoming Authorization 不转发)
// ================================================================
#[test]
fn incoming_authorization_header_is_never_forwarded_to_upstream() {
    // I10b-α1 R1 修订:走 sealed 入口得 resolved,然后喂 planner。
    let token_str = mk_jwt(&serde_json::json!({
        "iss": TEST_ISSUER,
        "aud": "https://mcp.example.com/",
        "scope": "mcp:tools.read",
        "exp": 9_999_999_999i64
    }));
    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    let ts = TokenStore::new(store, ledger);
    let token_ref = token_ref_for_access("https://mcp.example.com/", "c");
    let meta = OAuthTokenMetadata {
        token_ref: token_ref.clone(),
        resource: "https://mcp.example.com/".into(),
        authorization_server: "https://auth.example.com/".into(),
        issuer: TEST_ISSUER.into(),
        scope_set: vec!["mcp:tools.read".into()],
        token_kind: TokenKind::Access,
        expires_at: None,
        created_at: 0,
    };
    ts.put_access_token(&meta, SecretValue::new(token_str))
        .unwrap();

    let resolved = ts
        .resolve_access_token(
            &token_ref,
            &binding_for_test("https://mcp.example.com/", TEST_ISSUER, &["mcp:tools.read"]),
            1_700_000_000,
        )
        .unwrap();

    let incoming = vec![
        (
            "Authorization".to_string(),
            "Bearer CLIENT_EVIL_TOKEN".into(),
        ),
        ("X-API-Key".to_string(), "CLIENT_LEAK".into()),
        ("Content-Type".to_string(), "application/json".into()),
    ];
    let (req, report) = plan_authorized_request(
        &incoming,
        &resolved,
        "https://mcp.example.com/rpc".parse().unwrap(),
        HttpMethod::PostForm,
        Some(b"{}".to_vec()),
    )
    .unwrap();

    // 最终上游 request 无 client token
    let serialized = serde_json::to_string(req.headers()).unwrap();
    assert!(!serialized.contains("CLIENT_EVIL_TOKEN"));
    assert!(!serialized.contains("CLIENT_LEAK"));
    // Authorization 只能是 gateway 签出的
    let auth = req
        .headers()
        .iter()
        .find(|(k, _)| k == "Authorization")
        .unwrap();
    assert!(auth.1.starts_with("Bearer "));
    assert!(!auth.1.contains("CLIENT_EVIL_TOKEN"));
    // 报告列出剥离的 header(不含 value)
    assert!(report
        .stripped_header_names
        .contains(&"Authorization".into()));
    assert!(report.stripped_header_names.contains(&"X-API-Key".into()));
    let rep_ser = serde_json::to_string(&report.stripped_header_names).unwrap();
    assert!(!rep_ser.contains("CLIENT_EVIL_TOKEN"));
    assert!(!rep_ser.contains("CLIENT_LEAK"));
}

// ================================================================
// §12.3 I10-3: scoped token works end-to-end
// ================================================================
#[test]
fn scoped_token_authorizes_mock_tools_call_successfully() {
    // 1. 构造 PRM,mock .well-known 返回 PRM JSON
    let prm_json = serde_json::to_vec(&sample_prm()).unwrap();
    let mock = MockHttpClient::new();
    mock.register(
        HttpMethod::Get,
        "https://mcp.example.com/.well-known/oauth-protected-resource",
        HttpResponse {
            status: 200,
            body: prm_json,
        },
    );
    // mock AS /token 返 access_token(JWT,iss / aud 对,scope 覆盖)
    let access_jwt = mk_jwt(&serde_json::json!({
        "iss": TEST_ISSUER,
        "aud": "https://mcp.example.com/",
        "scope": "mcp:tools.read",
        "exp": 9_999_999_999i64
    }));
    mock.register(
        HttpMethod::PostForm,
        "https://auth.example.com/token",
        HttpResponse {
            status: 200,
            body: format!(
                r#"{{"access_token":"{access_jwt}","token_type":"Bearer","expires_in":3600,"scope":"mcp:tools.read"}}"#
            )
            .into_bytes(),
        },
    );
    // mock upstream tools/call 返 JSON-RPC response
    mock.register(
        HttpMethod::PostForm,
        "https://mcp.example.com/rpc",
        HttpResponse {
            status: 200,
            body: br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_vec(),
        },
    );

    // 2. PRM discover
    let prm = fetch_and_validate_prm(&mock, &"https://mcp.example.com/".parse().unwrap()).unwrap();
    assert_eq!(prm.resource.as_str(), "https://mcp.example.com/");

    // 3. PKCE + authorize URL(不访问 AS;假设用户已拿到 code)
    let pkce = new_pkce_pair();
    let state = CsrfToken::new_random();
    let _authz_url = build_authorization_url(
        &prm.authorization_servers[0].join("authorize").unwrap(),
        "client-123",
        &"http://127.0.0.1:9876/callback".parse().unwrap(),
        &["mcp:tools.read".into()],
        &state,
        &pkce.challenge,
        &prm.resource,
    )
    .unwrap();

    // 4. Exchange code → token
    let tr = exchange_code_for_token(
        &mock,
        &"https://auth.example.com/token".parse().unwrap(),
        "client-123",
        &"http://127.0.0.1:9876/callback".parse().unwrap(),
        "AUTH_CODE_ABC",
        &pkce.verifier,
        &prm.resource,
    )
    .unwrap();
    assert_eq!(tr.access_token, access_jwt);

    // 5. Validate + resolve(I10b-α1:走 sealed `TokenStore::resolve_access_token`)
    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    let ts = TokenStore::new(store, ledger);
    let token_ref = token_ref_for_access(prm.resource.as_str(), "client-123");
    let meta = OAuthTokenMetadata {
        token_ref: token_ref.clone(),
        resource: prm.resource.as_str().into(),
        authorization_server: prm.authorization_servers[0].as_str().into(),
        issuer: TEST_ISSUER.into(),
        scope_set: vec!["mcp:tools.read".into()],
        token_kind: TokenKind::Access,
        expires_at: Some(9_999_999_999),
        created_at: 1_700_000_000,
    };
    ts.put_access_token(&meta, SecretValue::new(tr.access_token.clone()))
        .unwrap();
    let resolved = ts
        .resolve_access_token(
            &token_ref,
            &binding_for_test(prm.resource.as_str(), TEST_ISSUER, &["mcp:tools.read"]),
            1_700_000_000,
        )
        .unwrap();

    // 6. Plan upstream request(incoming 无 passthrough)
    let incoming = vec![("Content-Type".to_string(), "application/json".into())];
    let (authorized, _report) = plan_authorized_request(
        &incoming,
        &resolved,
        "https://mcp.example.com/rpc".parse().unwrap(),
        HttpMethod::PostForm,
        Some(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#.to_vec()),
    )
    .unwrap();
    // Authorization 来自 gateway
    let auth_hdr = authorized
        .headers()
        .iter()
        .find(|(k, _)| k == "Authorization")
        .unwrap();
    assert!(auth_hdr.1.starts_with("Bearer "));

    // 7. 发送 → mock upstream 返 200
    let resp = mock
        .send(&vigil_http_auth::HttpRequest {
            url: authorized.url().clone(),
            method: authorized.method(),
            headers: authorized.headers().to_vec(),
            body: authorized.body().map(|b| b.to_vec()),
        })
        .unwrap();
    assert_eq!(resp.status, 200);
    assert!(String::from_utf8_lossy(&resp.body).contains(r#""ok":true"#));

    // 8. 验证 mock 记录的 upstream 调用 headers **不含** client 透传
    let calls = mock.calls();
    let upstream_call = calls
        .iter()
        .find(|c| c.url.as_str() == "https://mcp.example.com/rpc")
        .unwrap();
    let call_ser = serde_json::to_string(&upstream_call.headers).unwrap();
    assert!(call_ser.contains("Bearer ")); // gateway token 存在
}

// ================================================================
// Codex R1 BLOCKER 2:封闭 API —— `resolve_access_token` 端到端
// ================================================================
#[test]
fn resolve_access_token_end_to_end_via_token_store() {
    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    let ts = TokenStore::new(store, ledger);

    // JWT 必须带 iss claim,过新 sealed API 的 iss 校验(I10b-α1 ExpectedBinding 必填 issuer)
    let jwt = mk_jwt(&serde_json::json!({
        "iss": TEST_ISSUER,
        "aud": "https://mcp.example.com/",
        "scope": "mcp:tools.read mcp:tools.write",
        "exp": 9_999_999_999i64
    }));
    let token_ref = token_ref_for_access("https://mcp.example.com/", "client-X");
    let meta = OAuthTokenMetadata {
        token_ref: token_ref.clone(),
        resource: "https://mcp.example.com/".into(),
        authorization_server: "https://auth.example.com/".into(),
        issuer: TEST_ISSUER.into(),
        scope_set: vec!["mcp:tools.read".into(), "mcp:tools.write".into()],
        token_kind: TokenKind::Access,
        expires_at: Some(9_999_999_999),
        created_at: 1_700_000_000,
    };
    ts.put_access_token(&meta, SecretValue::new(jwt)).unwrap();

    // 通过封闭 API 一步:查 token_ref → verifier → 验 iss/aud/scope/exp → 返 ResolvedAccessToken
    let resolved = ts
        .resolve_access_token(
            &token_ref,
            &binding_for_test("https://mcp.example.com/", TEST_ISSUER, &["mcp:tools.read"]),
            1_700_000_000,
        )
        .unwrap();
    assert_eq!(resolved.resource, "https://mcp.example.com/");

    // list metadata 能看到这条
    let list = ts.list_metadata().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].token_ref, token_ref);
}

/// Codex R1 BLOCKER 2:resource 不匹配 → JWT gate 在封闭 API 里失败
#[test]
fn resolve_access_token_rejects_wrong_expected_resource() {
    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    let ts = TokenStore::new(store, ledger);

    let jwt = mk_jwt(&serde_json::json!({
        "iss": TEST_ISSUER,
        "aud": "https://mcp-A.example.com/",
        "scope": "mcp:tools.read",
        "exp": 9_999_999_999i64
    }));
    let token_ref = token_ref_for_access("https://mcp-A.example.com/", "c");
    let meta = OAuthTokenMetadata {
        token_ref: token_ref.clone(),
        resource: "https://mcp-A.example.com/".into(),
        authorization_server: "https://auth.example.com/".into(),
        issuer: TEST_ISSUER.into(),
        scope_set: vec!["mcp:tools.read".into()],
        token_kind: TokenKind::Access,
        expires_at: None,
        created_at: 0,
    };
    ts.put_access_token(&meta, SecretValue::new(jwt)).unwrap();

    // caller 手误想用 A 的 token 去 B
    let err = ts
        .resolve_access_token(
            &token_ref,
            &binding_for_test(
                "https://mcp-B.example.com/",
                TEST_ISSUER,
                &["mcp:tools.read"],
            ),
            0,
        )
        .unwrap_err();
    assert!(matches!(err, HttpAuthError::AudienceMismatch { .. }));
}

/// Codex R1 BLOCKER 2:resolve 返 MissingToken(不再返 None)
#[test]
fn resolve_access_token_missing_returns_missing_token() {
    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    let ts = TokenStore::new(store, ledger);
    let err = ts
        .resolve_access_token(
            &token_ref_for_access("https://x/", "c"),
            &binding_for_test("https://x/", TEST_ISSUER, &[]),
            0,
        )
        .unwrap_err();
    assert_eq!(err, HttpAuthError::MissingToken);
}

// ================================================================
// Token store 集成测试:value 进 SecretStore,metadata 进 SQLite;SENTINEL 不入 DB
// ================================================================
#[test]
fn token_value_never_in_sqlite_or_audit() {
    const SENTINEL: &str = "SENTINEL_TOKEN_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ";
    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    let sid = ledger.start_session("http_auth_test", None).unwrap();
    let ts = TokenStore::new(store.clone(), ledger.clone());

    let token_ref = token_ref_for_access("https://mcp.example.com/", "client-123");
    let metadata = OAuthTokenMetadata {
        token_ref: token_ref.clone(),
        resource: "https://mcp.example.com/".into(),
        authorization_server: "https://auth.example.com/".into(),
        issuer: TEST_ISSUER.into(),
        scope_set: vec!["mcp:tools.read".into()],
        token_kind: TokenKind::Access,
        expires_at: Some(9_999_999_999),
        created_at: 1_700_000_000,
    };
    ts.put_access_token(&metadata, SecretValue::new(SENTINEL))
        .unwrap();

    // 写一条 audit(caller 自己写;metadata only)
    ledger
        .append_event(
            &sid,
            event_type_for(HttpAuthEvent::TokenStored),
            &serde_json::json!({
                "token_ref": token_ref,
                "resource": metadata.resource,
                "authorization_server": metadata.authorization_server,
                "scope_set": metadata.scope_set,
                "token_kind": metadata.token_kind.as_str(),
                "expires_at": metadata.expires_at
            }),
            Some("http_auth token_stored"),
        )
        .unwrap();

    // SecretStore 里有 value
    let resolved_v = ts.resolve_access_value(&token_ref).unwrap().unwrap();
    assert_eq!(resolved_v.expose(), SENTINEL);

    // metadata 查回去
    let md = ts.get_metadata(&token_ref).unwrap().unwrap();
    assert_eq!(md.resource, "https://mcp.example.com/");
    assert_eq!(md.token_kind, TokenKind::Access);

    // 扫全 session events — SENTINEL **不**得出现
    let events = ledger.replay_session(&sid).unwrap();
    for e in &events {
        let payload_s = serde_json::to_string(&e.payload).unwrap();
        assert!(
            !payload_s.contains(SENTINEL),
            "SENTINEL 泄漏到 event {} payload: {}",
            e.event_type,
            payload_s
        );
        if let Some(rt) = &e.redacted_text {
            assert!(
                !rt.contains(SENTINEL),
                "SENTINEL 泄漏到 redacted_text: {rt}"
            );
        }
    }

    // metadata DTO 序列化也不含 SENTINEL(JSON round-trip)
    let md_s = serde_json::to_string(&md).unwrap();
    assert!(!md_s.contains(SENTINEL));
}

// ================================================================
// Token store:缺失 token → MissingToken(request planner 调用前 caller 检测)
// ================================================================
#[test]
fn missing_token_returns_none_from_store() {
    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    let ts = TokenStore::new(store, ledger);
    let token_ref = token_ref_for_access("https://x.example.com/", "client-404");
    let v = ts.resolve_access_value(&token_ref).unwrap();
    assert!(v.is_none(), "未登记 token_ref 应返 None");
}

// ================================================================
// Caller 手工拼 MissingToken 错语义:无 token 时 planner 不可用(靠 caller 检测)
// ================================================================
#[test]
fn missing_token_sentinel_check_for_planner_caller() {
    // 本测试纪念不变量 §I-10.4:caller 在无 token 时应直接抛 MissingToken 而**不**给
    // planner 传 ResolvedAccessToken;planner 本身不做 missing 检测。
    let err = HttpAuthError::MissingToken;
    assert_eq!(err.to_string(), "missing_token");
}

// ================================================================
// put_access_token 入参错 kind → TokenStoreError
// ================================================================
#[test]
fn put_access_token_rejects_wrong_kind() {
    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    let ts = TokenStore::new(store, ledger);
    let token_ref = token_ref_for_access("https://mcp.example.com/", "c");
    let bad = OAuthTokenMetadata {
        token_ref,
        resource: "https://mcp.example.com/".into(),
        authorization_server: "https://auth.example.com/".into(),
        issuer: TEST_ISSUER.into(),
        scope_set: vec![],
        token_kind: TokenKind::Refresh, // 错:put_access_token 期望 Access
        expires_at: None,
        created_at: 0,
    };
    let err = ts
        .put_access_token(&bad, SecretValue::new("x"))
        .unwrap_err();
    assert_eq!(err, HttpAuthError::TokenStoreError("token_kind_mismatch"));
}

// ================================================================
// 编译/使用 ResolvedAccessToken debug 不印 raw
// ================================================================
#[test]
fn resolved_access_token_debug_does_not_leak_raw() {
    let r = ResolvedAccessToken {
        raw: SecretValue::new("RAW_ZZZZZZZZZZZZZZ_TOKEN_SHOULD_NOT_PRINT"),
        resource: "https://mcp.example.com/".into(),
        scope_set: vec!["mcp:tools.read".into()],
        expires_at: None,
    };
    let s = format!("{r:?}");
    assert!(!s.contains("RAW_ZZZZZZZZZZZZZZ_TOKEN_SHOULD_NOT_PRINT"));
    // SecretValue 本身也不暴露
    let raw_s = format!("{:?}", r.raw);
    assert!(!raw_s.contains("RAW_ZZZZZZZZZZZZZZ_TOKEN_SHOULD_NOT_PRINT"));
    // 但 scope / resource 要可见
    assert!(s.contains("mcp.example.com"));
    assert!(s.contains("mcp:tools.read"));
}

// ================================================================
// R2 NICE-TO-HAVE(已消化):list_metadata 遇未知 token_kind 立即报错,
// 与 get_metadata 行为一致(fail-closed)。走 vigil-audit `test-util` feature
// 暴露的 raw insert helper 构造脏行。
// ================================================================
#[test]
fn list_metadata_fails_closed_on_unknown_token_kind() {
    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());

    // 绕 API 直接写一条 kind="garbage" 的行(模拟脏数据 / 手改 / 老迁移遗留);
    // issuer 给一个合法值,确保本测试只回归 "kind 未知" 这一条边界。
    ledger
        .__insert_oauth_token_metadata_raw_for_test(
            "token://oauth/access/abc/def",
            "https://mcp.example.com/",
            "https://auth.example.com/",
            &["mcp:tools.read".into()],
            "garbage",
            None,
            Some("https://auth.example.com"),
        )
        .unwrap();

    let ts = TokenStore::new(store, ledger);

    // list_metadata:必须报错,不得静默跳过
    let err = ts.list_metadata().unwrap_err();
    assert_eq!(err, HttpAuthError::TokenStoreError("unknown_token_kind"));

    // get_metadata(已有行为):同样报错 — 两条路径对齐
    let err2 = ts.get_metadata("token://oauth/access/abc/def").unwrap_err();
    assert_eq!(err2, HttpAuthError::TokenStoreError("unknown_token_kind"));
}

// ================================================================
// I10b-α1 新增回归(ADR 0011 §α1-D1 / §α1-D3)
// ================================================================

/// legacy I10a 磁盘行(issuer=NULL)→ row_to_typed fail-closed。
#[test]
fn legacy_null_issuer_row_fails_closed() {
    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());

    // 模拟 legacy 行:kind=access 合法,issuer=**显式 NULL**(R1 MUST-FIX:不依赖
    // "省列 → schema 默认 NULL" 的隐式行为,显式传 `None` 确保测试意图不漂移)。
    ledger
        .__insert_oauth_token_metadata_raw_for_test(
            "token://oauth/access/legacy/c",
            "https://mcp.example.com/",
            "https://auth.example.com/",
            &["mcp:tools.read".into()],
            "access",
            None,
            None, // issuer = NULL (显式)
        )
        .unwrap();

    let ts = TokenStore::new(store, ledger);
    let err = ts
        .get_metadata("token://oauth/access/legacy/c")
        .unwrap_err();
    assert_eq!(
        err,
        HttpAuthError::TokenStoreError("issuer_missing_legacy_row")
    );

    let err2 = ts.list_metadata().unwrap_err();
    assert_eq!(
        err2,
        HttpAuthError::TokenStoreError("issuer_missing_legacy_row")
    );
}

/// metadata.issuer 与 ExpectedBinding.issuer 不等 → TokenRejectedWrongIssuer。
#[test]
fn resolve_access_token_rejects_wrong_issuer_from_metadata() {
    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    let ts = TokenStore::new(store, ledger);

    let jwt = mk_jwt(&serde_json::json!({
        "iss": "https://auth-A.example.com",
        "aud": "https://mcp.example.com/",
        "scope": "mcp:tools.read",
        "exp": 9_999_999_999i64
    }));
    let token_ref = token_ref_for_access("https://mcp.example.com/", "c");
    let meta = OAuthTokenMetadata {
        token_ref: token_ref.clone(),
        resource: "https://mcp.example.com/".into(),
        authorization_server: "https://auth-A.example.com/".into(),
        issuer: "https://auth-A.example.com".into(),
        scope_set: vec!["mcp:tools.read".into()],
        token_kind: TokenKind::Access,
        expires_at: None,
        created_at: 0,
    };
    ts.put_access_token(&meta, SecretValue::new(jwt)).unwrap();

    // caller 期望的 issuer 跟 metadata 里不匹配
    let err = ts
        .resolve_access_token(
            &token_ref,
            &binding_for_test(
                "https://mcp.example.com/",
                "https://auth-B.example.com",
                &["mcp:tools.read"],
            ),
            1_700_000_000,
        )
        .unwrap_err();
    match err {
        HttpAuthError::TokenRejectedWrongIssuer { expected, actual } => {
            assert_eq!(expected, "https://auth-B.example.com");
            assert_eq!(actual, "https://auth-A.example.com");
        }
        other => panic!("expected TokenRejectedWrongIssuer, got {other:?}"),
    }
}

/// JWT `iss` claim 缺失 → TokenRejectedWrongIssuer { actual: "(missing)" }。
#[test]
fn resolve_access_token_rejects_missing_iss_claim() {
    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    let ts = TokenStore::new(store, ledger);

    let jwt_no_iss = mk_jwt(&serde_json::json!({
        // 无 iss
        "aud": "https://mcp.example.com/",
        "scope": "mcp:tools.read",
        "exp": 9_999_999_999i64
    }));
    let token_ref = token_ref_for_access("https://mcp.example.com/", "c");
    let meta = OAuthTokenMetadata {
        token_ref: token_ref.clone(),
        resource: "https://mcp.example.com/".into(),
        authorization_server: "https://auth.example.com/".into(),
        issuer: TEST_ISSUER.into(),
        scope_set: vec!["mcp:tools.read".into()],
        token_kind: TokenKind::Access,
        expires_at: None,
        created_at: 0,
    };
    ts.put_access_token(&meta, SecretValue::new(jwt_no_iss))
        .unwrap();

    let err = ts
        .resolve_access_token(
            &token_ref,
            &binding_for_test("https://mcp.example.com/", TEST_ISSUER, &["mcp:tools.read"]),
            1_700_000_000,
        )
        .unwrap_err();
    match err {
        HttpAuthError::TokenRejectedWrongIssuer { expected, actual } => {
            assert_eq!(expected, TEST_ISSUER);
            assert_eq!(actual, "(missing)");
        }
        other => panic!("expected TokenRejectedWrongIssuer(missing), got {other:?}"),
    }
}

/// metadata 存在但 SecretStore 查不到 value → TokenRehydrateRequired。
/// 模拟:写 metadata 后手动从 SecretStore 删除 value(或跨重启场景)。
#[test]
fn token_rehydrate_required_when_secret_missing_but_metadata_exists() {
    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());

    // 只写 metadata,不写 value
    ledger
        .register_oauth_token_metadata(
            "token://oauth/access/orphan/c",
            "https://mcp.example.com/",
            "https://auth.example.com/",
            &["mcp:tools.read".into()],
            "access",
            None,
            TEST_ISSUER,
        )
        .unwrap();

    let ts = TokenStore::new(store, ledger);
    let err = ts
        .resolve_access_token(
            "token://oauth/access/orphan/c",
            &binding_for_test("https://mcp.example.com/", TEST_ISSUER, &["mcp:tools.read"]),
            1_700_000_000,
        )
        .unwrap_err();
    match err {
        HttpAuthError::TokenRehydrateRequired { reason_code } => {
            assert_eq!(reason_code, "secret_missing_for_known_metadata");
        }
        other => panic!("expected TokenRehydrateRequired, got {other:?}"),
    }
}

/// 编译时守门:`ExpectedBinding.key_verifier` **必填** —— 若有人不慎把它改成
/// Option,本测试会编译失败(字段缺失构造)。
#[test]
fn expected_binding_key_verifier_is_mandatory() {
    let b = ExpectedBinding {
        resource: "https://mcp.example.com/".to_string(),
        issuer: TEST_ISSUER.to_string(),
        scopes: vec!["mcp:tools.read".to_string()],
        key_verifier: Arc::new(AlwaysAcceptVerifier),
        introspection: None,
    };
    assert_eq!(b.resource, "https://mcp.example.com/");
    // 若未来 key_verifier 改成 Option,此构造语法会破坏;回归守门。
}
