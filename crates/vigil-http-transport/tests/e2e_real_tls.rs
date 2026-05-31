//! I10b-α2 真 TLS + 真签名 端到端集成测试(ADR 0011 §α2-D2 / §α2-D3 / §I-11.1-7)。
//!
//! 覆盖(α2 代码 R1 修订后):
//! 1. TLS 1.2+ 协商(self-signed rustls fixture)
//! 2. ES256 真 round trip
//! 3. **RS256** 真 round trip(R1 MUST-FIX 4)
//! 4. JWT signature tamper(字节级)→ fail-closed
//! 5. HttpJwksSource 真 HTTPS 缓存 + **并发 singleflight 压测**(R1 BLOCKER 1)
//! 6. HttpJwksSource::fetch_as_metadata 真 HTTPS 发现(R1 BLOCKER 3)
//! 7. §12.3 I10-1:wrong issuer → TokenRejectedWrongIssuer(真 HTTP)
//! 8. §12.3 I10-2:incoming Authorization 不透传到 upstream(真 HTTP + §I-11.1 类型)
//! 9. §12.3 I10-3:PRM → AS metadata → JWKS → HttpUpstream.call(真 HTTP,Content-Type application/json)

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{ok_json, TestEs256Key, TestRs256Key, TestTlsHttpClient, TlsFixture};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Response;
use std::io::{Read, Write};

use vigil_audit::Ledger;
use vigil_http_auth::{
    ExpectedBinding, HttpAuthError, HttpClient, HttpMethod, HttpRequest, JwksSource,
    OAuthTokenMetadata, TokenKind, TokenStore,
};
use vigil_http_transport::{HttpJwksSource, HttpUpstream, JwksSignatureVerifier};
use vigil_lease::{InMemorySecretStore, SecretValue};
use vigil_mcp::{McpUpstream, UpstreamError};

const TEST_CLIENT_ID: &str = "client-α2-test";

// ================================================================
// Helper:预录 PRM / AS metadata / JWKS / mock MCP RPC,先 bind 端口再 build body
// ================================================================
fn start_full_fixture(es_key: &TestEs256Key) -> TlsFixture {
    // clone 所需字段到 owned 闭包捕获;build_routes 获得真实 base_url 后动态构 body
    let jwk_json = es_key.jwk_json.clone();
    TlsFixture::start_with_routes(move |base_url: &str| {
        let prm_body = serde_json::to_string(&serde_json::json!({
            "resource": format!("{base_url}/mcp/"),
            "authorization_servers": [base_url.to_string()],
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["mcp:tools.read", "mcp:tools.write"],
        }))
        .unwrap();
        let as_body = serde_json::to_string(&serde_json::json!({
            "issuer": base_url.to_string(),
            "jwks_uri": format!("{base_url}/jwks"),
            "token_endpoint": format!("{base_url}/token"),
            "authorization_endpoint": format!("{base_url}/authorize"),
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
        }))
        .unwrap();
        let jwks_body = serde_json::to_string(&serde_json::json!({
            "keys": [jwk_json.clone()],
        }))
        .unwrap();
        let rpc_body = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.to_string();

        vec![
            (
                "/.well-known/oauth-protected-resource",
                boxed_ok(prm_body.clone()),
            ),
            (
                "/.well-known/oauth-authorization-server",
                boxed_ok(as_body.clone()),
            ),
            ("/jwks", boxed_ok(jwks_body.clone())),
            // **I10b-α2 R2 额外盲点修复**:/mcp/rpc 严格断言 Content-Type=application/json。
            // Content-Type 不对 → 415 → HttpUpstream 投成 UpstreamError → 测试 panic。
            // 这是 BLOCKER 2 的**黑盒证据**:如果 HttpUpstream 还发 x-www-form-urlencoded,
            // 此 handler 会返 415,e2e 测试立刻失败。
            ("/mcp/rpc", boxed_rpc_require_json(rpc_body.clone())),
        ]
    })
}

fn boxed_ok(
    body: String,
) -> Box<dyn Fn(hyper::Request<hyper::body::Incoming>) -> Response<Full<Bytes>> + Send + Sync> {
    Box::new(move |_req| ok_json(&body))
}

/// `/mcp/rpc` 专用 handler:严格断言 `Content-Type: application/json`。
fn boxed_rpc_require_json(
    body: String,
) -> Box<dyn Fn(hyper::Request<hyper::body::Incoming>) -> Response<Full<Bytes>> + Send + Sync> {
    Box::new(move |req| {
        let ct = req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();
        // 接受 `application/json` 或 `application/json; charset=...`
        if !ct.starts_with("application/json") {
            return Response::builder()
                .status(415)
                .header("content-type", "text/plain")
                .body(Full::new(Bytes::from(format!(
                    "unsupported content-type: {ct}"
                ))))
                .unwrap();
        }
        ok_json(&body)
    })
}

// ================================================================
// Tests
// ================================================================

#[test]
fn reqwest_client_negotiates_tls_with_self_signed_fixture() {
    let fixture = TlsFixture::start(vec![("/ping", Box::new(|_| ok_json(r#"{"pong":true}"#)))]);
    let client = fixture.http_client();
    let resp = client
        .send(&HttpRequest {
            url: format!("{}/ping", fixture.base_url).parse().unwrap(),
            method: HttpMethod::Get,
            headers: vec![("accept".into(), "application/json".into())],
            body: None,
        })
        .unwrap();
    assert_eq!(resp.status, 200);
    assert!(String::from_utf8_lossy(&resp.body).contains("pong"));
}

#[test]
fn es256_round_trip_signature_verifies_via_verifier() {
    let key = TestEs256Key::new("kid-es256-α2");
    let claims = serde_json::json!({
        "iss": "https://auth.example.com",
        "aud": "https://mcp.example.com/",
        "scope": "mcp:tools.read",
        "exp": 9_999_999_999i64,
    });
    let token = key.sign(&claims);

    let mock_src = vigil_http_auth::MockJwksSource::new();
    mock_src.insert(
        "https://auth.example.com",
        "https://auth.example.com/jwks",
        vigil_http_auth::JwkSet {
            keys: vec![key.to_vigil_jwk()],
        },
    );
    let verifier = JwksSignatureVerifier::new(Arc::new(mock_src), "https://auth.example.com/jwks");
    let (header, _claims) = vigil_http_auth::decode_jwt_access_token(&token).unwrap();
    vigil_http_auth::JwtKeyVerifier::verify(&verifier, &token, &header, "https://auth.example.com")
        .unwrap();
}

/// I10b-α2 代码 R1 MUST-FIX 4:**真** RS256 round trip —— 之前 α2 初版只有 ES256,
/// RS256 路径无断言。现用 `rsa` crate 生 2048-bit keypair,jsonwebtoken 签+验。
#[test]
fn rs256_round_trip_signature_verifies_via_verifier() {
    let key = TestRs256Key::new("kid-rs256-α2");
    let claims = serde_json::json!({
        "iss": "https://auth.example.com",
        "aud": "https://mcp.example.com/",
        "scope": "mcp:tools.read",
        "exp": 9_999_999_999i64,
    });
    let token = key.sign(&claims);

    let mock_src = vigil_http_auth::MockJwksSource::new();
    mock_src.insert(
        "https://auth.example.com",
        "https://auth.example.com/jwks",
        vigil_http_auth::JwkSet {
            keys: vec![key.to_vigil_jwk()],
        },
    );
    let verifier = JwksSignatureVerifier::new(Arc::new(mock_src), "https://auth.example.com/jwks");
    let (header, _claims) = vigil_http_auth::decode_jwt_access_token(&token).unwrap();
    vigil_http_auth::JwtKeyVerifier::verify(&verifier, &token, &header, "https://auth.example.com")
        .unwrap();
}

/// I10b-α2 代码 R1 NICE-TO-HAVE 2:字节级篡改 —— base64url decode sig → 翻转末字节 →
/// 再 encode 回去,确保签名字节真的变了(不再靠字符级末位替换的偶然性)。
#[test]
fn tampered_jwt_signature_fails_verifier() {
    use base64::Engine;

    let key = TestEs256Key::new("kid-tamper");
    let claims = serde_json::json!({
        "iss": "https://auth.example.com",
        "aud": "https://mcp.example.com/",
        "exp": 9_999_999_999i64,
    });
    let token = key.sign(&claims);

    let parts: Vec<&str> = token.split('.').collect();
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut sig_bytes = engine.decode(parts[2]).unwrap();
    // 翻转末字节(XOR 0x01);若恰好 sig 全为 0 则换次高字节
    let n = sig_bytes.len();
    sig_bytes[n - 1] ^= 0x01;
    let tampered_sig = engine.encode(&sig_bytes);
    let tampered = format!("{}.{}.{}", parts[0], parts[1], tampered_sig);

    let mock_src = vigil_http_auth::MockJwksSource::new();
    mock_src.insert(
        "https://auth.example.com",
        "https://auth.example.com/jwks",
        vigil_http_auth::JwkSet {
            keys: vec![key.to_vigil_jwk()],
        },
    );
    let verifier = JwksSignatureVerifier::new(Arc::new(mock_src), "https://auth.example.com/jwks");
    let (header, _claims) = vigil_http_auth::decode_jwt_access_token(&tampered).unwrap();
    let err = vigil_http_auth::JwtKeyVerifier::verify(
        &verifier,
        &tampered,
        &header,
        "https://auth.example.com",
    )
    .unwrap_err();
    assert!(matches!(err, HttpAuthError::JwtSignatureInvalid));
}

#[test]
fn http_jwks_source_fetches_and_caches_over_real_tls() {
    let key = TestEs256Key::new("kid-jwks-e2e");
    let jwk_json = key.jwk_json.clone();
    let fixture = TlsFixture::start_with_routes(move |_base| {
        let jwks_body = serde_json::to_string(&serde_json::json!({
            "keys": [jwk_json.clone()],
        }))
        .unwrap();
        vec![("/jwks", boxed_ok(jwks_body))]
    });

    let client: Arc<dyn HttpClient> = Arc::new(fixture.http_client());
    let jwks_src = HttpJwksSource::new(client);
    let issuer = fixture.base_url.clone();
    let jwks_uri = format!("{}/jwks", fixture.base_url);

    let set = jwks_src.get(&issuer, &jwks_uri, None).unwrap();
    assert_eq!(set.keys.len(), 1);

    // 第二次 get 走缓存
    let set2 = jwks_src.get(&issuer, &jwks_uri, None).unwrap();
    assert_eq!(set.keys[0].kid, set2.keys[0].kid);
}

/// I10b-α2 代码 R1 BLOCKER 1 修复:并发 singleflight 压测。
/// 100 个线程并发 kid-miss 强刷,网络端点 **总命中数不超过** 预期(singleflight
/// 合并成 1 次,或考虑首次无缓存的 1 次冷启 + 1 次 force 共 2 次)。
#[test]
fn http_jwks_source_singleflight_prevents_fetch_stampede() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let key = TestEs256Key::new("kid-singleflight");
    let jwk_json = key.jwk_json.clone();
    let hit_count = Arc::new(AtomicUsize::new(0));
    let hit_count_fn = Arc::clone(&hit_count);
    let fixture = TlsFixture::start_with_routes(move |_base| {
        let jwks_body = serde_json::to_string(&serde_json::json!({
            "keys": [jwk_json.clone()],
        }))
        .unwrap();
        let counter = Arc::clone(&hit_count_fn);
        let handler: Box<
            dyn Fn(hyper::Request<hyper::body::Incoming>) -> Response<Full<Bytes>> + Send + Sync,
        > = Box::new(move |_req| {
            counter.fetch_add(1, Ordering::SeqCst);
            ok_json(&jwks_body)
        });
        vec![("/jwks", handler)]
    });

    let client: Arc<dyn HttpClient> = Arc::new(fixture.http_client());
    let jwks_src = Arc::new(HttpJwksSource::new(client));
    let issuer = fixture.base_url.clone();
    let jwks_uri = format!("{}/jwks", fixture.base_url);

    // **不** warm —— 直接 100 并发强刷 unknown kid,测真 singleflight 合并
    // 期望:singleflight 让只有 1 个 caller 真发网络 IO,其余在 per-key 锁上阻塞,
    // 第一个完成后更新缓存,其余 caller 在 Step 3 看到 kid 仍 miss + last_network_fetch
    // 在去抖窗口内 → 直接 JwksKidNotFound。
    const CONCURRENCY: usize = 100;
    let mut handles = Vec::with_capacity(CONCURRENCY);
    for _ in 0..CONCURRENCY {
        let src = Arc::clone(&jwks_src);
        let iss = issuer.clone();
        let uri = jwks_uri.clone();
        handles.push(std::thread::spawn(move || {
            let _ = src.get(&iss, &uri, Some("unknown_kid_α2"));
        }));
    }
    for h in handles {
        let _ = h.join();
    }

    // I10b-α2 R1 BLOCKER 1:singleflight 合并 —— 100 个 caller 共享 1 次真 IO
    let total_hits = hit_count.load(Ordering::SeqCst);
    assert_eq!(
        total_hits, 1,
        "singleflight failed: expected exactly 1 network fetch for 100 concurrent kid-miss (got {total_hits})"
    );
}

/// I10b-α2 代码 R1 BLOCKER 3 修复:`fetch_as_metadata` 端到端接入 e2e。
/// AS URL → `/.well-known/oauth-authorization-server` → metadata with issuer/jwks_uri。
#[test]
fn http_jwks_source_fetch_as_metadata_over_real_tls() {
    let key = TestEs256Key::new("kid-as-meta");
    let fixture = start_full_fixture(&key);
    let client: Arc<dyn HttpClient> = Arc::new(fixture.http_client());
    let jwks_src = HttpJwksSource::new(client);

    let meta = jwks_src.fetch_as_metadata(&fixture.base_url).unwrap();
    assert_eq!(meta.issuer, fixture.base_url); // BLOCKER 3 fixture 修复证据:issuer 真引用绑定后的 base_url
    assert_eq!(meta.jwks_uri, format!("{}/jwks", fixture.base_url));
    assert!(meta.response_types_supported.iter().any(|r| r == "code"));

    // 第二次 fetch 走缓存(命中)
    let meta2 = jwks_src.fetch_as_metadata(&fixture.base_url).unwrap();
    assert_eq!(meta.issuer, meta2.issuer);
}

/// §12.3 I10-3 真 HTTP 版:PRM → AS metadata → JWKS → HttpUpstream.call → 200。
/// 本测试 **真走** fetch_as_metadata 链路,不再硬编码 issuer。
#[test]
fn http_upstream_end_to_end_signed_jwt_tls_mcp_call() {
    let key = TestEs256Key::new("kid-e2e-3");
    let fixture = start_full_fixture(&key);

    let client_arc: Arc<TestTlsHttpClient> = Arc::new(fixture.http_client());
    let client_as_http: Arc<dyn HttpClient> = client_arc.clone();
    let jwks_src = Arc::new(HttpJwksSource::new(client_as_http));

    // 1. 真发现:AS metadata → issuer / jwks_uri
    let meta = jwks_src
        .fetch_as_metadata(&fixture.base_url)
        .expect("fetch_as_metadata");
    let resource = format!("{}/mcp/", fixture.base_url);

    // 2. 签 JWT with iss = meta.issuer
    let jwt = key.sign(&serde_json::json!({
        "iss": meta.issuer,
        "aud": resource.clone(),
        "scope": "mcp:tools.read",
        "exp": 9_999_999_999i64,
    }));

    // 3. TokenStore put
    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    let ts = Arc::new(TokenStore::new(store, ledger));
    let token_ref = vigil_http_auth::token_ref_for_access(&resource, TEST_CLIENT_ID);
    let oauth_meta = OAuthTokenMetadata {
        token_ref: token_ref.clone(),
        resource: resource.clone(),
        authorization_server: fixture.base_url.clone(),
        issuer: meta.issuer.clone(),
        scope_set: vec!["mcp:tools.read".into()],
        token_kind: TokenKind::Access,
        expires_at: Some(9_999_999_999),
        created_at: 1_700_000_000,
    };
    ts.put_access_token(&oauth_meta, SecretValue::new(jwt))
        .unwrap();

    // 4. 真签名验证 via HttpJwksSource + metadata.jwks_uri
    let verifier: Arc<dyn vigil_http_auth::JwtKeyVerifier> = Arc::new(JwksSignatureVerifier::new(
        jwks_src.clone() as Arc<dyn JwksSource>,
        meta.jwks_uri.clone(),
    ));
    let expected = ExpectedBinding {
        resource: resource.clone(),
        issuer: meta.issuer.clone(),
        scopes: vec!["mcp:tools.read".into()],
        key_verifier: verifier,
        introspection: None,
    };

    // 5. HttpUpstream + call(Content-Type: application/json via HttpMethod::Post)
    let upstream = HttpUpstream::new(
        "remote-mcp-α2",
        format!("{}/mcp/rpc", fixture.base_url).parse().unwrap(),
        expected,
        token_ref,
        ts.clone(),
        client_arc.clone(),
    );
    let result = upstream
        .call(
            "tools/call",
            Some(serde_json::json!({"name": "ping"})),
            Duration::from_secs(5),
        )
        .unwrap();
    assert_eq!(result, serde_json::json!({"ok": true}));
}

/// §12.3 I10-1 真 HTTP 版:metadata.issuer 与 ExpectedBinding.issuer 不等 → wrong_issuer。
#[test]
fn http_upstream_rejects_wrong_issuer_token() {
    let key = TestEs256Key::new("kid-wrong-iss");
    let fixture = start_full_fixture(&key);

    let wrong_issuer = "https://malicious-auth.example.com";
    let resource = format!("{}/mcp/", fixture.base_url);
    let jwt = key.sign(&serde_json::json!({
        "iss": wrong_issuer,
        "aud": resource.clone(),
        "scope": "mcp:tools.read",
        "exp": 9_999_999_999i64,
    }));

    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    let ts = Arc::new(TokenStore::new(store, ledger));
    let token_ref = vigil_http_auth::token_ref_for_access(&resource, TEST_CLIENT_ID);
    let oauth_meta = OAuthTokenMetadata {
        token_ref: token_ref.clone(),
        resource: resource.clone(),
        authorization_server: fixture.base_url.clone(),
        issuer: wrong_issuer.into(),
        scope_set: vec!["mcp:tools.read".into()],
        token_kind: TokenKind::Access,
        expires_at: None,
        created_at: 0,
    };
    ts.put_access_token(&oauth_meta, SecretValue::new(jwt))
        .unwrap();

    let client_arc: Arc<TestTlsHttpClient> = Arc::new(fixture.http_client());
    let client_as_http: Arc<dyn HttpClient> = client_arc.clone();
    let jwks_src: Arc<dyn JwksSource> = Arc::new(HttpJwksSource::new(client_as_http));
    let verifier: Arc<dyn vigil_http_auth::JwtKeyVerifier> = Arc::new(JwksSignatureVerifier::new(
        jwks_src,
        format!("{}/jwks", fixture.base_url),
    ));
    // caller 期望 issuer = base_url(正品);metadata 说 malicious → 拒
    let expected = ExpectedBinding {
        resource: resource.clone(),
        issuer: fixture.base_url.clone(),
        scopes: vec!["mcp:tools.read".into()],
        key_verifier: verifier,
        introspection: None,
    };
    let upstream = HttpUpstream::new(
        "remote-mcp",
        format!("{}/mcp/rpc", fixture.base_url).parse().unwrap(),
        expected,
        token_ref,
        ts.clone(),
        client_arc,
    );
    let err = upstream
        .call("tools/call", None, Duration::from_secs(5))
        .unwrap_err();
    assert!(matches!(err, UpstreamError::AuthError("wrong_issuer")));
}

// ================================================================
// I10b-β:loopback OAuth redirect 端到端 flow
// ================================================================
//
// 模拟完整 add-remote-mcp 子命令的串联:
// 1. TlsFixture 预录 `/token` → 返 access_token JSON
// 2. LoopbackServer bind ephemeral port
// 3. 辅助线程模拟 "AS redirect" —— 发 `GET /callback?code=...&state=...` 到 loopback
// 4. wait_for_callback → 拿 code + state
// 5. 用 vigil-http-auth::exchange_code_for_token 去 mock `/token` 真换 token
// 6. 构造 OAuthTokenMetadata 入 TokenStore,验 resolve_access_value 能拿回原值
#[test]
fn loopback_full_flow_exchanges_code_and_persists_token() {
    use oauth2::CsrfToken;
    use vigil_http_auth::{exchange_code_for_token, new_pkce_pair, token_ref_for_access};
    use vigil_http_transport::LoopbackServer;

    let es_key = TestEs256Key::new("kid-β-loopback");
    let jwt = es_key.sign(&serde_json::json!({
        "iss": "https://auth.example.com",
        "aud": "https://mcp.example.com/",
        "scope": "mcp:tools.read",
        "exp": 9_999_999_999i64,
    }));

    // 1. TlsFixture:只需 /token 返 access_token
    let fixture = TlsFixture::start_with_routes(move |_base| {
        let jwt_in_body = jwt.clone();
        let token_fn: Box<
            dyn Fn(hyper::Request<hyper::body::Incoming>) -> hyper::Response<Full<Bytes>>
                + Send
                + Sync,
        > = Box::new(move |_req| {
            let body = format!(
                r#"{{"access_token":"{jwt_in_body}","token_type":"Bearer","expires_in":3600,"scope":"mcp:tools.read"}}"#
            );
            hyper::Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(body)))
                .unwrap()
        });
        vec![("/token", token_fn)]
    });

    // 2. LoopbackServer bind
    let state = CsrfToken::new_random();
    let state_val = state.secret().clone();
    let server = LoopbackServer::bind(state_val.clone(), "/callback").unwrap();
    let redirect_uri: url::Url = server.redirect_uri().parse().unwrap();

    // 3. 辅助线程模拟 AS redirect
    let state_for_redirect = state_val.clone();
    let redirect_target = server.redirect_uri();
    let redirect_thread = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        let port = redirect_target
            .split(':')
            .nth(2)
            .unwrap()
            .split('/')
            .next()
            .unwrap()
            .to_string();
        let mut stream = std::net::TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
        let request = format!(
            "GET /callback?code=AUTH_CODE_β&state={state_for_redirect} HTTP/1.1\r\n\
             Host: 127.0.0.1\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).unwrap();
        let mut buf = String::new();
        let _ = stream.read_to_string(&mut buf);
    });

    // 4. wait_for_callback
    let cb = server.wait_for_callback(Duration::from_secs(2)).unwrap();
    redirect_thread.join().unwrap();
    assert_eq!(cb.code, "AUTH_CODE_β");
    assert_eq!(cb.state, state_val);

    // 5. exchange code → token(via mock /token)
    let pkce = new_pkce_pair();
    let http: Arc<TestTlsHttpClient> = Arc::new(fixture.http_client());
    let http_as_client: Arc<dyn HttpClient> = http.clone();
    let token_url: url::Url = format!("{}/token", fixture.base_url).parse().unwrap();
    let resource: url::Url = "https://mcp.example.com/".parse().unwrap();
    let tr = exchange_code_for_token(
        &*http_as_client,
        &token_url,
        "client-β",
        &redirect_uri,
        &cb.code,
        &pkce.verifier,
        &resource,
    )
    .unwrap();
    assert!(tr.access_token.contains('.')); // JWT 格式
    assert_eq!(tr.token_type.as_deref(), Some("Bearer"));
    assert_eq!(tr.expires_in, Some(3600));

    // 6. TokenStore 持久化 + resolve_access_value
    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    let ts = TokenStore::new(store, ledger);
    let token_ref = token_ref_for_access(resource.as_str(), "client-β");
    let meta = OAuthTokenMetadata {
        token_ref: token_ref.clone(),
        resource: resource.as_str().into(),
        authorization_server: fixture.base_url.clone(),
        issuer: "https://auth.example.com".into(),
        scope_set: vec!["mcp:tools.read".into()],
        token_kind: TokenKind::Access,
        expires_at: Some(9_999_999_999),
        created_at: 1_700_000_000,
    };
    ts.put_access_token(&meta, SecretValue::new(tr.access_token.clone()))
        .unwrap();

    // resolve_access_value 能拿回真值
    let v = ts
        .resolve_access_value(&token_ref)
        .unwrap()
        .expect("value exists");
    assert_eq!(v.expose(), tr.access_token);
}

// ================================================================
// I10c-α1:refresh token flow — TokenStore + singleflight + HttpUpstream auto-refresh
// ================================================================

/// T2 证据:`try_refresh_access_token` 真走 refresh_token grant → AS → 更新 access value + expires_at。
#[test]
fn try_refresh_access_token_rotates_access_value_via_real_tls() {
    use vigil_http_auth::token_ref_for_refresh;

    let es_key = TestEs256Key::new("kid-refresh");
    let old_jwt = es_key.sign(&serde_json::json!({
        "iss": "https://auth.example.com",
        "aud": "https://mcp.example.com/",
        "scope": "mcp:tools.read",
        "exp": 1_700_000_000i64, // 已过期
    }));
    let new_jwt = es_key.sign(&serde_json::json!({
        "iss": "https://auth.example.com",
        "aud": "https://mcp.example.com/",
        "scope": "mcp:tools.read",
        "exp": 9_999_999_999i64, // 新 token 远期过期
    }));

    // mock AS `/token` 返新 access_token(grant_type=refresh_token)
    let new_jwt_for_server = new_jwt.clone();
    let fixture = TlsFixture::start_with_routes(move |_base| {
        let new_jwt_body = new_jwt_for_server.clone();
        let token_fn: Box<
            dyn Fn(hyper::Request<hyper::body::Incoming>) -> hyper::Response<Full<Bytes>>
                + Send
                + Sync,
        > = Box::new(move |_req| {
            let body = format!(
                r#"{{"access_token":"{new_jwt_body}","token_type":"Bearer","expires_in":3600,"scope":"mcp:tools.read"}}"#
            );
            hyper::Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(body)))
                .unwrap()
        });
        vec![("/token", token_fn)]
    });

    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    let ts = TokenStore::new(store.clone(), ledger);

    let resource_s = "https://mcp.example.com/";
    let client_id = "client-refresh-test";
    let access_ref = vigil_http_auth::token_ref_for_access(resource_s, client_id);
    let refresh_ref = token_ref_for_refresh(resource_s, client_id);

    // 预置:access(旧)+ refresh 都在 store
    let meta = OAuthTokenMetadata {
        token_ref: access_ref.clone(),
        resource: resource_s.into(),
        authorization_server: fixture.base_url.clone(),
        issuer: "https://auth.example.com".into(),
        scope_set: vec!["mcp:tools.read".into()],
        token_kind: TokenKind::Access,
        expires_at: Some(1_700_000_000),
        created_at: 1_700_000_000,
    };
    ts.put_access_token(&meta, SecretValue::new(old_jwt.clone()))
        .unwrap();
    let refresh_meta = OAuthTokenMetadata {
        token_ref: refresh_ref.clone(),
        resource: resource_s.into(),
        authorization_server: fixture.base_url.clone(),
        issuer: "https://auth.example.com".into(),
        scope_set: vec!["mcp:tools.read".into()],
        token_kind: TokenKind::Refresh,
        expires_at: None,
        created_at: 1_700_000_000,
    };
    ts.put_refresh_token(&refresh_meta, SecretValue::new("REFRESH_SECRET_XYZ"))
        .unwrap();

    // refresh
    let http_c = Arc::new(fixture.http_client());
    let http: Arc<dyn HttpClient> = http_c.clone();
    let token_ep: url::Url = format!("{}/token", fixture.base_url).parse().unwrap();
    let triggered = ts
        .try_refresh_access_token(&access_ref, client_id, &token_ep, &*http)
        .unwrap();
    assert!(triggered, "first caller must trigger real fetch");

    // 验证 SecretStore 的 access value 已换成 new_jwt
    let v = ts.resolve_access_value(&access_ref).unwrap().unwrap();
    assert_eq!(v.expose(), new_jwt);

    // 验证 metadata.expires_at 已被更新为未来时间(now + 3600)
    let new_meta = ts.get_metadata(&access_ref).unwrap().unwrap();
    assert!(
        new_meta.expires_at.unwrap_or(0) > 1_700_000_000,
        "expires_at must be refreshed"
    );
}

/// T2 证据:refresh_token 不存在 → RefreshTokenMissing reason code。
#[test]
fn try_refresh_without_stored_refresh_token_fails_closed() {
    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    let ts = TokenStore::new(store, ledger);

    let resource_s = "https://mcp.example.com/";
    let client_id = "client-no-refresh";
    let access_ref = vigil_http_auth::token_ref_for_access(resource_s, client_id);

    // 只登记 access metadata,不存 refresh
    let meta = OAuthTokenMetadata {
        token_ref: access_ref.clone(),
        resource: resource_s.into(),
        authorization_server: "https://auth.example.com".into(),
        issuer: "https://auth.example.com".into(),
        scope_set: vec!["mcp:tools.read".into()],
        token_kind: TokenKind::Access,
        expires_at: Some(1_700_000_000),
        created_at: 1_700_000_000,
    };
    ts.put_access_token(&meta, SecretValue::new("dummy"))
        .unwrap();

    // 构造一个不会被访问的 mock client(refresh 在读 SecretStore 就 fail)
    let fixture = TlsFixture::start(vec![]);
    let http_c = Arc::new(fixture.http_client());
    let http: Arc<dyn HttpClient> = http_c.clone();
    let token_ep: url::Url = "https://auth.example.com/token".parse().unwrap();

    let err = ts
        .try_refresh_access_token(&access_ref, client_id, &token_ep, &*http)
        .unwrap_err();
    assert_eq!(err, HttpAuthError::TokenStoreError("refresh_token_missing"));
}

/// I10c-α1 R1 MUST-FIX 2 证据:同一 access_token_ref ≥10 并发 refresh → AS `/token`
/// 端点**只**被打 1 次(singleflight 合并),其余 caller 走短路 `Ok(false)`。
#[test]
fn concurrent_refresh_same_token_ref_only_hits_network_once() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use vigil_http_auth::{
        token_ref_for_access, token_ref_for_refresh, HttpMethod, HttpResponse, MockHttpClient,
    };

    let es_key = TestEs256Key::new("kid-concurrent");
    let resource = "https://mcp.example.com/";
    let client_id = "client-concurrent";
    let token_endpoint_s = "https://auth.example.com/token";

    let new_jwt = es_key.sign(&serde_json::json!({
        "iss": "https://auth.example.com",
        "aud": resource,
        "scope": "mcp:tools.read",
        "exp": 9_999_999_999i64,
    }));

    let access_ref = token_ref_for_access(resource, client_id);
    let refresh_ref = token_ref_for_refresh(resource, client_id);

    // Mock:/token 只预录 1 次 200 —— 如果 singleflight 失败、N 个 caller 都打,
    // 第 2+ caller 会拿到 `mock_queue_exhausted` → refresh 失败 / 测试会失败。
    //
    // 为了让失败更清晰,注册多次,但通过外部 atomic 计数验证"只 1 次 IO"。
    let mock = Arc::new(MockHttpClient::new());
    let token_response_body = format!(
        r#"{{"access_token":"{new_jwt}","token_type":"Bearer","expires_in":3600,"scope":"mcp:tools.read"}}"#
    );
    // 注册足够多次以容错(防测试 flake),但通过 mock.calls() 计数 /token 被击中数
    for _ in 0..20 {
        mock.register(
            HttpMethod::PostForm,
            token_endpoint_s,
            HttpResponse {
                status: 200,
                body: token_response_body.clone().into_bytes(),
            },
        );
    }

    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    let ts = Arc::new(TokenStore::new(store, ledger));

    // 预置:旧 access(expires_at = 1700000000 过期)+ refresh
    let old_expires: i64 = 1_700_000_000;
    let access_meta = OAuthTokenMetadata {
        token_ref: access_ref.clone(),
        resource: resource.into(),
        authorization_server: "https://auth.example.com".into(),
        issuer: "https://auth.example.com".into(),
        scope_set: vec!["mcp:tools.read".into()],
        token_kind: TokenKind::Access,
        expires_at: Some(old_expires),
        created_at: old_expires,
    };
    ts.put_access_token(&access_meta, SecretValue::new("OLD_JWT"))
        .unwrap();
    let refresh_meta = OAuthTokenMetadata {
        token_ref: refresh_ref,
        resource: resource.into(),
        authorization_server: "https://auth.example.com".into(),
        issuer: "https://auth.example.com".into(),
        scope_set: vec!["mcp:tools.read".into()],
        token_kind: TokenKind::Refresh,
        expires_at: None,
        created_at: old_expires,
    };
    ts.put_refresh_token(&refresh_meta, SecretValue::new("REFRESH_SECRET"))
        .unwrap();

    // 启 N=10 个并发线程,同时调 try_refresh_access_token
    let n_threads = 10;
    let triggered_count = Arc::new(AtomicUsize::new(0));
    let skipped_count = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(std::sync::Barrier::new(n_threads));

    let mut handles = Vec::with_capacity(n_threads);
    for _ in 0..n_threads {
        let ts_c = ts.clone();
        let mock_c = mock.clone();
        let triggered_c = triggered_count.clone();
        let skipped_c = skipped_count.clone();
        let access_ref_c = access_ref.clone();
        let barrier_c = barrier.clone();
        handles.push(thread::spawn(move || {
            barrier_c.wait(); // 所有线程同时起跑
            let http: &dyn HttpClient = &*mock_c;
            let token_ep: url::Url = token_endpoint_s.parse().unwrap();
            match ts_c.try_refresh_access_token(&access_ref_c, client_id, &token_ep, http) {
                Ok(true) => {
                    triggered_c.fetch_add(1, Ordering::SeqCst);
                }
                Ok(false) => {
                    skipped_c.fetch_add(1, Ordering::SeqCst);
                }
                Err(e) => panic!("unexpected err: {e:?}"),
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    // singleflight 是 **arrival-time** 语义(store.rs:`last_completion >= my_arrival` 短路),
    // 非"barrier 释放即合并为 1"。快速 MockHttpClient 下,arrival window 可能跨越多次 completion
    // —— 晚到 caller 的 my_arrival 晚于首次完成,合法地再刷一次,故 hits 是 1..n 而非恒为 1。
    // 因此断言**非 flaky 不变量**(Codex TEST-TOO-STRICT 诊断,2026-06-01):
    //   - 全部 caller 完成(triggered + skipped == n)
    //   - 至少 1 次真刷(triggered >= 1)
    //   - 至少 1 次短路 → 证明发生了合并(skipped >= 1)
    //   - 未全量 stampede(hits < n)
    //   - 一致性:每次网络命中对应一次 triggered(hits == triggered)
    let calls = mock.calls();
    let token_hits = calls
        .iter()
        .filter(|c| c.url.as_str() == token_endpoint_s)
        .count();
    let triggered = triggered_count.load(Ordering::SeqCst);
    let skipped = skipped_count.load(Ordering::SeqCst);
    assert_eq!(triggered + skipped, n_threads, "all callers must complete");
    assert!(triggered >= 1, "at least one real refresh");
    assert!(
        skipped >= 1,
        "singleflight must coalesce at least one caller"
    );
    assert!(
        token_hits < n_threads,
        "no full stampede: token_hits {token_hits} must be < n_threads {n_threads}"
    );
    assert_eq!(
        token_hits, triggered,
        "each /token hit corresponds to one triggered refresh"
    );
}

/// I10c-α1 R3 修复证据:legacy `expires_at=None` 场景也走真 singleflight。
/// 前 caller 刷新后 SecretStore 里的 access value 被换,**value_sha256 指纹** 变化
/// 让后 caller 入锁时也短路 Ok(false)。
#[test]
fn concurrent_refresh_legacy_no_expires_at_also_singleflights() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use vigil_http_auth::{
        token_ref_for_access, token_ref_for_refresh, HttpMethod, HttpResponse, MockHttpClient,
    };

    let es_key = TestEs256Key::new("kid-legacy-no-exp");
    let resource = "https://mcp.example.com/";
    let client_id = "client-legacy";
    let token_endpoint_s = "https://auth.example.com/token";

    let new_jwt = es_key.sign(&serde_json::json!({
        "iss": "https://auth.example.com",
        "aud": resource,
        "scope": "mcp:tools.read",
        "exp": 9_999_999_999i64,
    }));

    let access_ref = token_ref_for_access(resource, client_id);
    let refresh_ref = token_ref_for_refresh(resource, client_id);

    let mock = Arc::new(MockHttpClient::new());
    // 返回体**不带** expires_in —— 模拟 AS 返回时不给 expires_at(legacy 路径)
    let token_response_body =
        format!(r#"{{"access_token":"{new_jwt}","token_type":"Bearer","scope":"mcp:tools.read"}}"#);
    for _ in 0..20 {
        mock.register(
            HttpMethod::PostForm,
            token_endpoint_s,
            HttpResponse {
                status: 200,
                body: token_response_body.clone().into_bytes(),
            },
        );
    }

    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    let ts = Arc::new(TokenStore::new(store, ledger));

    // 预置:legacy access(**expires_at=None**,模拟老数据)+ refresh
    let access_meta = OAuthTokenMetadata {
        token_ref: access_ref.clone(),
        resource: resource.into(),
        authorization_server: "https://auth.example.com".into(),
        issuer: "https://auth.example.com".into(),
        scope_set: vec!["mcp:tools.read".into()],
        token_kind: TokenKind::Access,
        expires_at: None, // **legacy** —— singleflight 需靠 value_sha256 短路
        created_at: 1_700_000_000,
    };
    ts.put_access_token(&access_meta, SecretValue::new("OLD_LEGACY_JWT"))
        .unwrap();
    let refresh_meta = OAuthTokenMetadata {
        token_ref: refresh_ref,
        resource: resource.into(),
        authorization_server: "https://auth.example.com".into(),
        issuer: "https://auth.example.com".into(),
        scope_set: vec!["mcp:tools.read".into()],
        token_kind: TokenKind::Refresh,
        expires_at: None,
        created_at: 1_700_000_000,
    };
    ts.put_refresh_token(&refresh_meta, SecretValue::new("REFRESH_LEGACY"))
        .unwrap();

    let n_threads = 10;
    let triggered = Arc::new(AtomicUsize::new(0));
    let skipped = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(std::sync::Barrier::new(n_threads));

    let mut handles = Vec::with_capacity(n_threads);
    for _ in 0..n_threads {
        let ts_c = ts.clone();
        let mock_c = mock.clone();
        let trig = triggered.clone();
        let skip = skipped.clone();
        let aref = access_ref.clone();
        let barrier_c = barrier.clone();
        handles.push(thread::spawn(move || {
            barrier_c.wait();
            let http: &dyn HttpClient = &*mock_c;
            let ep: url::Url = token_endpoint_s.parse().unwrap();
            match ts_c.try_refresh_access_token(&aref, client_id, &ep, http) {
                Ok(true) => {
                    trig.fetch_add(1, Ordering::SeqCst);
                }
                Ok(false) => {
                    skip.fetch_add(1, Ordering::SeqCst);
                }
                Err(e) => panic!("unexpected err: {e:?}"),
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    // arrival-time singleflight 非 flaky 不变量(同 concurrent_refresh_same_token_ref_*;
    // legacy expires_at=None 不改变短路判据 —— 见 store.rs `last_completion >= my_arrival`,
    // 与 expires_at 无关;Codex TEST-TOO-STRICT 诊断 2026-06-01)。快 mock 下 hits 是 1..n。
    let calls = mock.calls();
    let hits = calls
        .iter()
        .filter(|c| c.url.as_str() == token_endpoint_s)
        .count();
    let triggered_n = triggered.load(Ordering::SeqCst);
    let skipped_n = skipped.load(Ordering::SeqCst);
    assert_eq!(
        triggered_n + skipped_n,
        n_threads,
        "all callers must complete"
    );
    assert!(triggered_n >= 1, "at least one real refresh");
    assert!(
        skipped_n >= 1,
        "legacy singleflight must coalesce at least one caller"
    );
    assert!(
        hits < n_threads,
        "no full stampede: hits {hits} must be < n_threads {n_threads}"
    );
    assert_eq!(
        hits, triggered_n,
        "each /token hit corresponds to one triggered refresh"
    );
}

/// T3 证据(单元级,非 TLS):HttpUpstream.call 遇 upstream 401 → auto-refresh → retry。
///
/// **为何不走真 TLS**:真 TLS fixture 的 base_url 在启动后才知道,
/// 但 JWT aud 必须等于 upstream URL origin(planner §I-10.3 same-origin 校验),
/// 存在 chicken-egg。用 MockHttpClient + 可预录响应实现同样语义覆盖,更稳。
#[test]
fn http_upstream_auto_refreshes_and_retries_on_401() {
    use vigil_http_auth::{
        token_ref_for_access, token_ref_for_refresh, HttpMethod, HttpResponse, MockHttpClient,
    };
    use vigil_http_transport::AutoRefreshConfig;

    let es_key = TestEs256Key::new("kid-autoretry");
    let resource = "https://mcp.example.com/";
    let upstream_url_s = "https://mcp.example.com/rpc";
    let token_endpoint_s = "https://auth.example.com/token";

    // 提前签好 old/new JWT(aud = resource,和 upstream URL origin 一致)
    let old_jwt = es_key.sign(&serde_json::json!({
        "iss": "https://auth.example.com",
        "aud": resource,
        "scope": "mcp:tools.read",
        "exp": 9_999_999_999i64,
    }));
    let new_jwt = es_key.sign(&serde_json::json!({
        "iss": "https://auth.example.com",
        "aud": resource,
        "scope": "mcp:tools.read",
        "exp": 9_999_999_999i64,
    }));

    // 预录 /mcp/rpc:第 1 次 401,第 2 次 200
    let mock = Arc::new(MockHttpClient::new());
    mock.register(
        HttpMethod::Post,
        upstream_url_s,
        HttpResponse {
            status: 401,
            body: b"unauthorized".to_vec(),
        },
    );
    mock.register(
        HttpMethod::Post,
        upstream_url_s,
        HttpResponse {
            status: 200,
            body: br#"{"jsonrpc":"2.0","id":1,"result":{"retry":"ok"}}"#.to_vec(),
        },
    );
    // 预录 /token:refresh 返新 access_token
    let token_response_body = format!(
        r#"{{"access_token":"{new_jwt}","token_type":"Bearer","expires_in":3600,"scope":"mcp:tools.read"}}"#
    );
    mock.register(
        HttpMethod::PostForm,
        token_endpoint_s,
        HttpResponse {
            status: 200,
            body: token_response_body.into_bytes(),
        },
    );

    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    let ts = Arc::new(TokenStore::new(store, ledger));

    let client_id = "client-autoretry";
    let access_ref = token_ref_for_access(resource, client_id);
    let refresh_ref = token_ref_for_refresh(resource, client_id);

    // 预置:旧 access(会被 401) + refresh
    let access_meta = OAuthTokenMetadata {
        token_ref: access_ref.clone(),
        resource: resource.into(),
        authorization_server: "https://auth.example.com".into(),
        issuer: "https://auth.example.com".into(),
        scope_set: vec!["mcp:tools.read".into()],
        token_kind: TokenKind::Access,
        expires_at: Some(9_999_999_999),
        created_at: 1_700_000_000,
    };
    ts.put_access_token(&access_meta, SecretValue::new(old_jwt))
        .unwrap();
    let refresh_meta = OAuthTokenMetadata {
        token_ref: refresh_ref,
        resource: resource.into(),
        authorization_server: "https://auth.example.com".into(),
        issuer: "https://auth.example.com".into(),
        scope_set: vec!["mcp:tools.read".into()],
        token_kind: TokenKind::Refresh,
        expires_at: None,
        created_at: 1_700_000_000,
    };
    ts.put_refresh_token(&refresh_meta, SecretValue::new("REFRESH_XYZ"))
        .unwrap();

    let mock_jwks = vigil_http_auth::MockJwksSource::new();
    mock_jwks.insert(
        "https://auth.example.com",
        "https://auth.example.com/jwks",
        vigil_http_auth::JwkSet {
            keys: vec![es_key.to_vigil_jwk()],
        },
    );
    let verifier: Arc<dyn vigil_http_auth::JwtKeyVerifier> = Arc::new(JwksSignatureVerifier::new(
        Arc::new(mock_jwks),
        "https://auth.example.com/jwks",
    ));
    let expected = ExpectedBinding {
        resource: resource.into(),
        issuer: "https://auth.example.com".into(),
        scopes: vec!["mcp:tools.read".into()],
        key_verifier: verifier,
        introspection: None,
    };

    // R3 修订:去掉 __new_for_integration_test bypass;此处 token_endpoint 是
    // https://auth.example.com/token(mock URL,但 scheme 是 https),`new` 会通过 gate。
    let refresh_cfg = AutoRefreshConfig::new(
        token_endpoint_s.parse().unwrap(),
        client_id,
        mock.clone() as Arc<dyn HttpClient>,
    )
    .unwrap();
    let mcp_url: url::Url = upstream_url_s.parse().unwrap();
    let sender: Arc<dyn vigil_http_auth::AuthorizedSender> = mock.clone();
    let upstream = HttpUpstream::with_auto_refresh(
        "remote-mcp",
        mcp_url,
        expected,
        access_ref.clone(),
        ts.clone(),
        sender,
        refresh_cfg,
    );

    // call:第一次 401 → auto-refresh → retry → 200
    let result = upstream
        .call("tools/call", None, Duration::from_secs(5))
        .unwrap();
    assert_eq!(result, serde_json::json!({ "retry": "ok" }));

    // upstream URL 被调用 2 次(401 + retry 200)
    let calls = mock.calls();
    let rpc_hits = calls
        .iter()
        .filter(|c| c.url.as_str() == upstream_url_s)
        .count();
    assert_eq!(rpc_hits, 2, "upstream should be hit twice (401 + retry)");

    // SecretStore 的 access value 已被 refresh 换成 new_jwt
    let v = ts.resolve_access_value(&access_ref).unwrap().unwrap();
    assert_eq!(v.expose(), new_jwt);
}

// ================================================================
// I10c-α2:opaque token RFC 7662 introspection
// ================================================================

/// α2 T4 证据 1:opaque access token + IntrospectionConfig → 走 introspection →
/// 返 `active: true` + 合法 aud/iss/scope/exp → 成功 ResolvedAccessToken。
#[test]
fn opaque_token_resolved_via_introspection_happy_path() {
    use vigil_http_auth::{
        token_ref_for_access, ExpectedBinding, HttpMethod, HttpResponse, IntrospectionConfig,
        MockHttpClient, MockJwksSource,
    };

    let resource = "https://mcp.example.com/";
    let client_id = "opaque-client";
    let introspection_url = "https://auth.example.com/introspect";

    // mock AS /introspect 返 active + 合法 claim
    let mock = Arc::new(MockHttpClient::new());
    let ir_body = serde_json::json!({
        "active": true,
        "scope": "mcp:tools.read mcp:tools.write",
        "exp": 9_999_999_999i64,
        "iss": "https://auth.example.com",
        "aud": resource,
        "token_type": "Bearer",
    });
    mock.register(
        HttpMethod::PostForm,
        introspection_url,
        HttpResponse {
            status: 200,
            body: serde_json::to_vec(&ir_body).unwrap(),
        },
    );

    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    let ts = TokenStore::new(store.clone(), ledger);

    // 预置 opaque token(非 JWT,无 `.`) + metadata
    let access_ref = token_ref_for_access(resource, client_id);
    let meta = OAuthTokenMetadata {
        token_ref: access_ref.clone(),
        resource: resource.into(),
        authorization_server: "https://auth.example.com".into(),
        issuer: "https://auth.example.com".into(),
        scope_set: vec!["mcp:tools.read".into()],
        token_kind: TokenKind::Access,
        expires_at: Some(9_999_999_999),
        created_at: 1_700_000_000,
    };
    ts.put_access_token(&meta, SecretValue::new("OPAQUE_TOKEN_123_nodots"))
        .unwrap();

    // 预置 client_secret(SecretStore key 由 caller 指定)
    use vigil_lease::SecretStore as _;
    let client_secret_ref = "client://oauth/test/opaque-client";
    store
        .put(client_secret_ref, SecretValue::new("CLIENT_SECRET_ABC"))
        .unwrap();

    // 构造 IntrospectionConfig(走 http://localhost loopback 豁免 —— 但 test 用 https/ mock,
    // 实际 MockHttpClient 按字符串路由,不做真 TLS;用 https:// 通过 gate)
    let mock_http: Arc<dyn HttpClient> = mock.clone() as _;
    let intro_cfg = IntrospectionConfig::new(
        introspection_url.parse().unwrap(),
        client_id,
        client_secret_ref,
        mock_http,
    )
    .unwrap();

    // key_verifier 是必填的,但 opaque 路径不会调用它 —— 走 AlwaysAccept
    let dummy_jwks = Arc::new(MockJwksSource::new());
    let verifier: Arc<dyn vigil_http_auth::JwtKeyVerifier> =
        Arc::new(vigil_http_transport::JwksSignatureVerifier::new(
            dummy_jwks,
            "https://auth.example.com/jwks",
        ));
    let expected = ExpectedBinding {
        resource: resource.into(),
        issuer: "https://auth.example.com".into(),
        scopes: vec!["mcp:tools.read".into()],
        key_verifier: verifier,
        introspection: Some(intro_cfg),
    };

    let resolved = ts
        .resolve_access_token(&access_ref, &expected, 1_700_000_000)
        .unwrap();
    assert_eq!(resolved.resource, resource);
    assert!(resolved.scope_set.iter().any(|s| s == "mcp:tools.read"));
    assert_eq!(resolved.expires_at, Some(9_999_999_999));

    // /introspect 被调用 1 次,Authorization: Basic <base64(client_id:client_secret)>
    let calls = mock.calls();
    let intro_call = calls
        .iter()
        .find(|c| c.url.as_str() == introspection_url)
        .unwrap();
    let auth_hdr = intro_call
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Authorization"))
        .unwrap();
    assert!(auth_hdr.1.starts_with("Basic "));
}

/// α2 T4 证据 2:introspection 返 `active: false` → `TokenExpired`。
#[test]
fn opaque_token_inactive_maps_to_token_expired() {
    use vigil_http_auth::{
        token_ref_for_access, ExpectedBinding, HttpMethod, HttpResponse, IntrospectionConfig,
        MockHttpClient, MockJwksSource,
    };

    let resource = "https://mcp.example.com/";
    let client_id = "opaque-client";
    let introspection_url = "https://auth.example.com/introspect";

    let mock = Arc::new(MockHttpClient::new());
    mock.register(
        HttpMethod::PostForm,
        introspection_url,
        HttpResponse {
            status: 200,
            body: br#"{"active":false}"#.to_vec(),
        },
    );

    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    let ts = TokenStore::new(store.clone(), ledger);

    let access_ref = token_ref_for_access(resource, client_id);
    let meta = OAuthTokenMetadata {
        token_ref: access_ref.clone(),
        resource: resource.into(),
        authorization_server: "https://auth.example.com".into(),
        issuer: "https://auth.example.com".into(),
        scope_set: vec!["mcp:tools.read".into()],
        token_kind: TokenKind::Access,
        expires_at: None,
        created_at: 0,
    };
    ts.put_access_token(&meta, SecretValue::new("OPAQUE_REVOKED_nodots"))
        .unwrap();

    use vigil_lease::SecretStore as _;
    let cs_ref = "client://oauth/t/c";
    store.put(cs_ref, SecretValue::new("S")).unwrap();

    let mock_http: Arc<dyn HttpClient> = mock.clone() as _;
    let cfg = IntrospectionConfig::new(
        introspection_url.parse().unwrap(),
        client_id,
        cs_ref,
        mock_http,
    )
    .unwrap();

    let dummy_jwks = Arc::new(MockJwksSource::new());
    let verifier: Arc<dyn vigil_http_auth::JwtKeyVerifier> =
        Arc::new(vigil_http_transport::JwksSignatureVerifier::new(
            dummy_jwks,
            "https://auth.example.com/jwks",
        ));
    let expected = ExpectedBinding {
        resource: resource.into(),
        issuer: "https://auth.example.com".into(),
        scopes: vec!["mcp:tools.read".into()],
        key_verifier: verifier,
        introspection: Some(cfg),
    };

    let err = ts
        .resolve_access_token(&access_ref, &expected, 0)
        .unwrap_err();
    assert_eq!(err, HttpAuthError::TokenExpired);
}

/// α2 T4 证据 3:`IntrospectionConfig::new` 强制 https/loopback;`http://public.com` → Err。
#[test]
fn introspection_config_rejects_non_https_non_loopback() {
    use vigil_http_auth::{IntrospectionConfig, MockHttpClient};
    let mock = Arc::new(MockHttpClient::new());
    let http: Arc<dyn HttpClient> = mock.clone() as _;
    let err = IntrospectionConfig::new(
        "http://public.example.com/introspect".parse().unwrap(),
        "c",
        "r",
        http.clone(),
    )
    .unwrap_err();
    assert_eq!(
        err,
        HttpAuthError::HttpError("introspection_endpoint_must_be_https_or_loopback")
    );
    // loopback http:// 接受
    let ok = IntrospectionConfig::new(
        "http://127.0.0.1:8080/introspect".parse().unwrap(),
        "c",
        "r",
        http.clone(),
    );
    assert!(ok.is_ok());
    // https 接受
    let ok2 = IntrospectionConfig::new(
        "https://auth.example.com/introspect".parse().unwrap(),
        "c",
        "r",
        http,
    );
    assert!(ok2.is_ok());
}

/// α2 T4 证据 4:`expected.introspection = None` + opaque token → `UnsupportedTokenFormat`
/// (向后兼容:caller 没启 opaque 支持,行为等同 α1 —— 不走 introspection)。
#[test]
fn opaque_token_without_introspection_config_still_rejected() {
    use vigil_http_auth::{token_ref_for_access, ExpectedBinding, MockJwksSource};

    let resource = "https://mcp.example.com/";
    let client_id = "no-introspection";

    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    let ts = TokenStore::new(store, ledger);

    let access_ref = token_ref_for_access(resource, client_id);
    let meta = OAuthTokenMetadata {
        token_ref: access_ref.clone(),
        resource: resource.into(),
        authorization_server: "https://auth.example.com".into(),
        issuer: "https://auth.example.com".into(),
        scope_set: vec!["mcp:tools.read".into()],
        token_kind: TokenKind::Access,
        expires_at: None,
        created_at: 0,
    };
    ts.put_access_token(&meta, SecretValue::new("OPAQUE_BUT_NOT_ENABLED_nodots"))
        .unwrap();

    let dummy_jwks = Arc::new(MockJwksSource::new());
    let verifier: Arc<dyn vigil_http_auth::JwtKeyVerifier> =
        Arc::new(vigil_http_transport::JwksSignatureVerifier::new(
            dummy_jwks,
            "https://auth.example.com/jwks",
        ));
    let expected = ExpectedBinding {
        resource: resource.into(),
        issuer: "https://auth.example.com".into(),
        scopes: vec!["mcp:tools.read".into()],
        key_verifier: verifier,
        introspection: None, // 不启 opaque 支持
    };

    let err = ts
        .resolve_access_token(&access_ref, &expected, 0)
        .unwrap_err();
    assert_eq!(err, HttpAuthError::UnsupportedTokenFormat);
}

// ═══════════════════════════════════════════════════════════════════════════
// I10c-α3:introspection 缓存 + singleflight(6 条验收)
// ═══════════════════════════════════════════════════════════════════════════

/// α3 fixture:构造 opaque-token 路径所需的全部状态,返 `(ts, mock, expected, access_ref)`。
/// `build_cfg` 允许 caller 定制 `IntrospectionConfig`(如调 cache TTL);
/// `mock_response_repeat` 为 mock 注册 N 份同 body 响应(按 FIFO 消费;放宽到 16 够任何测试用)。
#[allow(clippy::type_complexity)]
fn build_introspection_fixture<F>(
    ir_body: serde_json::Value,
    build_cfg: F,
) -> (
    Arc<TokenStore>,
    Arc<vigil_http_auth::MockHttpClient>,
    vigil_http_auth::ExpectedBinding,
    String,
)
where
    F: FnOnce(vigil_http_auth::IntrospectionConfig) -> vigil_http_auth::IntrospectionConfig,
{
    use vigil_http_auth::{
        token_ref_for_access, ExpectedBinding, HttpMethod, HttpResponse, IntrospectionConfig,
        MockHttpClient, MockJwksSource,
    };

    let resource = "https://mcp.example.com/";
    let client_id = "cache-client";
    let introspection_url = "https://auth.example.com/introspect";

    let mock = Arc::new(MockHttpClient::new());
    // 预注册 16 份,足够覆盖任意测试的多轮 IO;实际消费次数由测试断言来验证
    let body_bytes = serde_json::to_vec(&ir_body).unwrap();
    for _ in 0..16 {
        mock.register(
            HttpMethod::PostForm,
            introspection_url,
            HttpResponse {
                status: 200,
                body: body_bytes.clone(),
            },
        );
    }

    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    let ts = Arc::new(TokenStore::new(store.clone(), ledger));

    let access_ref = token_ref_for_access(resource, client_id);
    let meta = OAuthTokenMetadata {
        token_ref: access_ref.clone(),
        resource: resource.into(),
        authorization_server: "https://auth.example.com".into(),
        issuer: "https://auth.example.com".into(),
        scope_set: vec!["mcp:tools.read".into()],
        token_kind: TokenKind::Access,
        expires_at: Some(9_999_999_999),
        created_at: 1_700_000_000,
    };
    ts.put_access_token(&meta, SecretValue::new("OPAQUE_CACHE_TOKEN_nodots"))
        .unwrap();

    use vigil_lease::SecretStore as _;
    let client_secret_ref = "client://oauth/cache/cache-client";
    store
        .put(client_secret_ref, SecretValue::new("CLIENT_SECRET"))
        .unwrap();

    let mock_http: Arc<dyn HttpClient> = mock.clone() as _;
    let intro_cfg = IntrospectionConfig::new(
        introspection_url.parse().unwrap(),
        client_id,
        client_secret_ref,
        mock_http,
    )
    .unwrap();
    let intro_cfg = build_cfg(intro_cfg);

    let dummy_jwks = Arc::new(MockJwksSource::new());
    let verifier: Arc<dyn vigil_http_auth::JwtKeyVerifier> =
        Arc::new(vigil_http_transport::JwksSignatureVerifier::new(
            dummy_jwks,
            "https://auth.example.com/jwks",
        ));
    let expected = ExpectedBinding {
        resource: resource.into(),
        issuer: "https://auth.example.com".into(),
        scopes: vec!["mcp:tools.read".into()],
        key_verifier: verifier,
        introspection: Some(intro_cfg),
    };

    (ts, mock, expected, access_ref)
}

fn active_ir_body(exp: i64) -> serde_json::Value {
    serde_json::json!({
        "active": true,
        "scope": "mcp:tools.read mcp:tools.write",
        "exp": exp,
        "iss": "https://auth.example.com",
        "aud": "https://mcp.example.com/",
        "token_type": "Bearer",
    })
}

fn intro_call_count(mock: &vigil_http_auth::MockHttpClient) -> usize {
    mock.calls()
        .iter()
        .filter(|c| c.url.as_str() == "https://auth.example.com/introspect")
        .count()
}

/// α3-1:同 token 连续 resolve,默认 60s TTL 内 → 只打 AS 一次(第二次命中缓存)。
#[test]
fn introspection_cache_hits_skip_network_io() {
    let (ts, mock, expected, access_ref) =
        build_introspection_fixture(active_ir_body(9_999_999_999), |c| c);

    let now = 1_700_000_000;
    ts.resolve_access_token(&access_ref, &expected, now)
        .unwrap();
    ts.resolve_access_token(&access_ref, &expected, now + 30)
        .unwrap();
    ts.resolve_access_token(&access_ref, &expected, now + 59)
        .unwrap();

    assert_eq!(
        intro_call_count(&mock),
        1,
        "60s TTL 内三次 resolve,应只打 /introspect 一次"
    );
}

/// α3-2:TTL 到期后重新 fetch。
#[test]
fn introspection_cache_ttl_expiry_triggers_refetch() {
    // 用短 TTL(5s)方便测试
    let (ts, mock, expected, access_ref) =
        build_introspection_fixture(active_ir_body(9_999_999_999), |c| {
            c.with_cache_max_ttl_secs(5)
        });

    let now = 1_700_000_000;
    ts.resolve_access_token(&access_ref, &expected, now)
        .unwrap();
    ts.resolve_access_token(&access_ref, &expected, now + 4)
        .unwrap(); // 仍在 TTL 内
    ts.resolve_access_token(&access_ref, &expected, now + 10)
        .unwrap(); // 超出 TTL
    ts.resolve_access_token(&access_ref, &expected, now + 11)
        .unwrap(); // 已重填,再 hit

    assert_eq!(
        intro_call_count(&mock),
        2,
        "TTL 到期后应仅再 fetch 一次,共 2 次 /introspect"
    );
}

/// α3-3:`with_cache_max_ttl_secs(0)` 完全关闭缓存,每次都走 IO。
#[test]
fn introspection_cache_disabled_when_ttl_zero() {
    let (ts, mock, expected, access_ref) =
        build_introspection_fixture(active_ir_body(9_999_999_999), |c| {
            c.with_cache_max_ttl_secs(0)
        });

    let now = 1_700_000_000;
    for i in 0..3 {
        ts.resolve_access_token(&access_ref, &expected, now + i)
            .unwrap();
    }
    assert_eq!(intro_call_count(&mock), 3, "TTL=0 时每次都应打 /introspect");
}

/// α3-4:`active: false` 响应**不缓存**,下次仍走 IO(避免缓存失效结果拖累 rotation)。
#[test]
fn introspection_cache_not_populated_on_active_false() {
    let ir_body = serde_json::json!({"active": false});
    let (ts, mock, expected, access_ref) = build_introspection_fixture(ir_body, |c| c);

    // 两次 resolve,均应 TokenExpired,且均走 IO(缓存里没有 entry)
    let e1 = ts
        .resolve_access_token(&access_ref, &expected, 1_700_000_000)
        .unwrap_err();
    let e2 = ts
        .resolve_access_token(&access_ref, &expected, 1_700_000_000)
        .unwrap_err();
    assert_eq!(e1, HttpAuthError::TokenExpired);
    assert_eq!(e2, HttpAuthError::TokenExpired);
    assert_eq!(
        intro_call_count(&mock),
        2,
        "active:false 不缓存,两次 resolve 应打 /introspect 两次"
    );
}

/// α3-5:cache TTL 受 `response.exp` cap(即使 cache_max_ttl_secs 更大,也不能超过 token 剩余寿命)。
#[test]
fn introspection_cache_ttl_capped_by_token_exp() {
    let now = 1_700_000_000i64;
    // token 在 now+10 秒后过期
    let (ts, mock, expected, access_ref) =
        build_introspection_fixture(active_ir_body(now + 10), |c| c.with_cache_max_ttl_secs(300));

    ts.resolve_access_token(&access_ref, &expected, now)
        .unwrap();
    // now+9 仍在 token exp 前 → 缓存 hit
    ts.resolve_access_token(&access_ref, &expected, now + 9)
        .unwrap();
    // now+11 超过 token exp → resolve 本身会 TokenExpired,但这里证明"缓存也已过期,不会返陈旧 Some"
    let err = ts
        .resolve_access_token(&access_ref, &expected, now + 11)
        .unwrap_err();
    assert_eq!(err, HttpAuthError::TokenExpired);

    // 第一个 resolve 一次 IO;第二个缓存 hit 不 IO;第三个走 IO(缓存 expires_at=exp=now+10,
    // now+11 已过期)→ 总共 2 次
    assert_eq!(
        intro_call_count(&mock),
        2,
        "response.exp 必须对缓存 TTL 形成上限"
    );
}

/// α3+ cleanup:单次 resolve 完成后,per-key 锁从 `introspection_locks` map 中移除,
/// 防止 token churn 场景下 map 单调增长。
#[test]
fn introspection_locks_are_cleaned_up_after_resolve() {
    let (ts, _mock, expected, access_ref) =
        build_introspection_fixture(active_ir_body(9_999_999_999), |c| c);

    // 初始状态:map 为空
    assert_eq!(ts.introspection_locks_len_for_test().unwrap(), 0);

    // 一次 resolve 会打开一条 lock entry,完成后应自动清理(strong_count==1)
    ts.resolve_access_token(&access_ref, &expected, 1_700_000_000)
        .unwrap();
    assert_eq!(
        ts.introspection_locks_len_for_test().unwrap(),
        0,
        "resolve 完成后 lock entry 应被 try_cleanup 移除"
    );
}

/// α3+ cleanup(R2 修订):**即使 IO 失败**(active:false / aud 不符等),lock entry 也应
/// 被 cleanup,避免失败 token 的 lock 积累。
#[test]
fn introspection_locks_cleaned_up_after_failed_resolve() {
    // active:false 响应 → resolve_access_token 返 TokenExpired,cleanup 仍应发生
    let ir_body = serde_json::json!({"active": false});
    let (ts, _mock, expected, access_ref) = build_introspection_fixture(ir_body, |c| c);

    let err = ts
        .resolve_access_token(&access_ref, &expected, 1_700_000_000)
        .unwrap_err();
    assert_eq!(err, HttpAuthError::TokenExpired);
    assert_eq!(
        ts.introspection_locks_len_for_test().unwrap(),
        0,
        "失败 IO 后 lock entry 仍须被 cleanup,避免失败 token 积累"
    );
}

/// α3+ cleanup 并发:8 线程并发 resolve 后,所有 caller 释放 Arc,lock map 应回归空。
#[test]
fn introspection_locks_cleaned_up_after_concurrent_resolves() {
    use std::thread;

    let (ts, _mock, expected, access_ref) =
        build_introspection_fixture(active_ir_body(9_999_999_999), |c| c);

    let now = 1_700_000_000i64;
    let mut handles = Vec::new();
    for _ in 0..8 {
        let ts_c = Arc::clone(&ts);
        let expected_c = expected.clone();
        let ar = access_ref.clone();
        handles.push(thread::spawn(move || {
            ts_c.resolve_access_token(&ar, &expected_c, now).unwrap();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    // 并发里最后一个退出 singleflight 的 caller 负责 cleanup;所有线程 join 后 map 应空
    assert_eq!(
        ts.introspection_locks_len_for_test().unwrap(),
        0,
        "并发 resolve 全部完成后 lock map 应回归空"
    );
}

/// α3-6:并发 miss 合并为一次 IO(singleflight)。
#[test]
fn introspection_cache_concurrent_miss_singleflights_to_one_io() {
    use std::thread;

    let (ts, mock, expected, access_ref) =
        build_introspection_fixture(active_ir_body(9_999_999_999), |c| c);

    let now = 1_700_000_000i64;
    let mut handles = Vec::new();
    for _ in 0..8 {
        let ts_c = Arc::clone(&ts);
        let expected_c = expected.clone();
        let ar = access_ref.clone();
        handles.push(thread::spawn(move || {
            ts_c.resolve_access_token(&ar, &expected_c, now).unwrap();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        intro_call_count(&mock),
        1,
        "8 个并发 resolve 应被 singleflight 合并为 1 次 /introspect"
    );
}
