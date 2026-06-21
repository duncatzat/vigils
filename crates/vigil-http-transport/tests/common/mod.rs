//! I10b-α2 integration test 共享夹具。
//!
//! **范围约束**(ADR 0011 §I-11.3):这些 TLS / 签发密钥生成、自签 CA 信任,**只**在
//! integration test crate 编译(Cargo 视作独立 crate,不进 lib)。生产路径严禁信任
//! 任何非 webpki-roots 根证书。
//!
//! 提供:
//! - `TlsFixture`:用 rcgen 生成自签 CA + server cert,启动 hyper + tokio-rustls
//!   TLS server,根据路径分发 handler。**`start_with_routes` 在 bind 端口之后再
//!   build routes**,确保 handler body 可引用真实 `base_url`
//! - `TestTlsHttpClient`:信任自签 CA 的 reqwest blocking 封装,impl
//!   `vigil_http_auth::{HttpClient, AuthorizedSender}` —— integration test 专用,
//!   **替代** 已删除的 `ReqwestHttpClient::__new_for_integration_test`
//! - `TestEs256Key` / `TestRs256Key`:签发 JWT 用的 keypair + JWK 公钥投影

#![allow(dead_code, unreachable_pub)]

use std::collections::HashMap;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

use rcgen::{CertificateParams, DistinguishedName, KeyPair, SanType};

use vigil_http_auth::{
    AuthorizedHttpRequest, AuthorizedSender, HttpAuthError, HttpClient, HttpMethod, HttpRequest,
    HttpResponse,
};

/// 路由 handler:按 path 分发;handler 接 `Request<Incoming>`,返 `Response<Full<Bytes>>`。
pub(crate) type ResponseFn = Box<dyn Fn(Request<Incoming>) -> Response<Full<Bytes>> + Send + Sync>;

pub(crate) struct TlsFixture {
    pub base_url: String,
    pub ca_der: Vec<u8>,
    #[allow(dead_code)]
    rt: Runtime,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl TlsFixture {
    /// 简单入口:路径不依赖 base_url 时用。
    pub fn start(routes: Vec<(&'static str, ResponseFn)>) -> Self {
        Self::start_with_routes(|_base_url: &str| routes)
    }

    /// **I10b-α2 代码 R1 BLOCKER 3 修复**:先 bind TCP listener 拿到真实 `base_url`,
    /// 再调 `build_routes(base_url)` 构造路由 —— 这样 handler body 里可以引用真实 URL
    /// (PRM / AS metadata 的 `issuer` / `jwks_uri` / `token_endpoint` 等)。
    pub fn start_with_routes<F>(build_routes: F) -> Self
    where
        F: FnOnce(&str) -> Vec<(&'static str, ResponseFn)>,
    {
        // 1. 生成自签 CA + server cert
        let ca_key = KeyPair::generate().expect("ca keypair");
        let mut ca_params = CertificateParams::new(vec![]).unwrap();
        ca_params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(rcgen::DnType::CommonName, "vigil-test-ca");
            dn
        };
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca self-sign");

        let server_key = KeyPair::generate().expect("server keypair");
        let mut server_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        server_params.subject_alt_names = vec![
            SanType::DnsName("localhost".try_into().unwrap()),
            SanType::IpAddress("127.0.0.1".parse().unwrap()),
        ];
        server_params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(rcgen::DnType::CommonName, "localhost");
            dn
        };
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .expect("server sign");
        let server_cert_der = server_cert.der().to_vec();
        let server_key_pem = server_key.serialize_pem();
        let ca_der = ca_cert.der().to_vec();

        // 2. rustls ServerConfig
        let mut key_pem_reader = BufReader::new(server_key_pem.as_bytes());
        let key = rustls_pemfile::private_key(&mut key_pem_reader)
            .expect("parse server key pem")
            .expect("key pem had a key");
        let tls_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(server_cert_der)],
                key,
            )
            .expect("rustls server config");
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));

        // 3. tokio runtime + TcpListener :127.0.0.1:0 → 拿真实 port
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let listener =
            rt.block_on(async { TcpListener::bind("127.0.0.1:0").await.expect("bind 0") });
        let addr: SocketAddr = listener.local_addr().unwrap();
        let base_url = format!("https://127.0.0.1:{}", addr.port());

        // 4. 关键:用真实 base_url build routes(R1 BLOCKER 3:不再用 dummy fixture 的旧 port)
        let routes_raw = build_routes(&base_url);
        let routes: Arc<HashMap<String, ResponseFn>> = Arc::new(
            routes_raw
                .into_iter()
                .map(|(p, h)| (p.to_string(), h))
                .collect(),
        );

        let (tx, mut rx) = oneshot::channel::<()>();
        let routes_for_task = Arc::clone(&routes);
        let acceptor_for_task = acceptor.clone();
        rt.spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    accept = listener.accept() => {
                        let Ok((stream, _peer)) = accept else { continue };
                        let routes = Arc::clone(&routes_for_task);
                        let acceptor = acceptor_for_task.clone();
                        tokio::spawn(async move {
                            let Ok(tls_stream) = acceptor.accept(stream).await else { return };
                            let io = TokioIo::new(tls_stream);
                            let svc = service_fn(move |req: Request<Incoming>| {
                                let routes = Arc::clone(&routes);
                                async move {
                                    let path = req.uri().path().to_string();
                                    let resp = match routes.get(&path) {
                                        Some(handler) => handler(req),
                                        None => Response::builder()
                                            .status(StatusCode::NOT_FOUND)
                                            .body(Full::new(Bytes::from("not found")))
                                            .unwrap(),
                                    };
                                    Ok::<_, std::convert::Infallible>(resp)
                                }
                            });
                            let _ = auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                                .serve_connection(io, svc)
                                .await;
                        });
                    }
                }
            }
        });

        // 等 listener ready
        std::thread::sleep(Duration::from_millis(50));

        TlsFixture {
            base_url,
            ca_der,
            rt,
            shutdown_tx: Some(tx),
        }
    }

    /// 为测试 caller 构造一个信任本 CA 的 `TestTlsHttpClient`。
    pub fn http_client(&self) -> TestTlsHttpClient {
        TestTlsHttpClient::new_with_ca(&self.ca_der)
    }
}

impl Drop for TlsFixture {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

// ================================================================
// TestTlsHttpClient —— integration test 专用,信任 self-signed CA
// ================================================================
//
// **替代**(I10b-α2 代码 R1 BLOCKER 4)已删除的
// `ReqwestHttpClient::__new_for_integration_test`:该 API 之前是 `pub` 在生产 crate,
// 下游可调。现在把 "信任自签 CA" 的能力**全部**收拢到本 test 夹具(integration test
// crate 编译,不进 lib)。
//
// 实现等价于 `ReqwestHttpClient` 的 send_inner(受约束的 TLS 1.2+ / no_gzip / no_proxy),
// 但注入了 fixture 的 CA 到 rustls root store。prod build 看不到此类型。

pub(crate) struct TestTlsHttpClient {
    inner: reqwest::blocking::Client,
}

impl std::fmt::Debug for TestTlsHttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestTlsHttpClient")
            .field("ctx", &"test-only, self-signed CA")
            .finish_non_exhaustive()
    }
}

impl TestTlsHttpClient {
    pub fn new_with_ca(ca_der: &[u8]) -> Self {
        // 确保 rustls 的默认 crypto provider 被安装
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(ca_der.to_vec()))
            .expect("add ca");
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let inner = reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_proxy()
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .use_preconfigured_tls(tls_config)
            .build()
            .expect("test tls http client");
        Self { inner }
    }
}

fn send_via_reqwest(
    client: &reqwest::blocking::Client,
    method: HttpMethod,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    per_call_timeout: Option<Duration>,
) -> Result<HttpResponse, HttpAuthError> {
    let mut builder = match method {
        HttpMethod::Get => client.get(url),
        HttpMethod::PostForm => client
            .post(url)
            .header("content-type", "application/x-www-form-urlencoded"),
        HttpMethod::Post => client.post(url).header("content-type", "application/json"),
        _ => return Err(HttpAuthError::Internal("unsupported_http_method")),
    };
    for (k, v) in headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    if let Some(b) = body {
        builder = builder.body(b.to_vec());
    }
    if let Some(t) = per_call_timeout {
        builder = builder.timeout(t);
    }
    let resp = builder
        .send()
        .map_err(|_| HttpAuthError::HttpError("reqwest_send_failed"))?;
    let status = resp.status().as_u16();
    let bytes = resp
        .bytes()
        .map_err(|_| HttpAuthError::HttpError("reqwest_body_read_failed"))?;
    Ok(HttpResponse {
        status,
        body: bytes.to_vec(),
    })
}

impl HttpClient for TestTlsHttpClient {
    fn send(&self, req: &HttpRequest) -> Result<HttpResponse, HttpAuthError> {
        send_via_reqwest(
            &self.inner,
            req.method,
            req.url.as_str(),
            &req.headers,
            req.body.as_deref(),
            None,
        )
    }
}

impl AuthorizedSender for TestTlsHttpClient {
    fn send_authorized(&self, req: &AuthorizedHttpRequest) -> Result<HttpResponse, HttpAuthError> {
        send_via_reqwest(
            &self.inner,
            req.method(),
            req.url().as_str(),
            req.headers(),
            req.body(),
            None,
        )
    }

    fn send_authorized_with_timeout(
        &self,
        req: &AuthorizedHttpRequest,
        timeout: Duration,
    ) -> Result<HttpResponse, HttpAuthError> {
        send_via_reqwest(
            &self.inner,
            req.method(),
            req.url().as_str(),
            req.headers(),
            req.body(),
            Some(timeout),
        )
    }
}

// ================================================================
// JWT 签发 helper —— ES256 / RS256 keypair + JWK 公钥投影
// ================================================================

pub(crate) struct TestEs256Key {
    pub kid: String,
    pub encoding_key: jsonwebtoken::EncodingKey,
    pub jwk_json: serde_json::Value,
}

impl TestEs256Key {
    pub fn new(kid: &str) -> Self {
        use base64::Engine;

        let kp = KeyPair::generate().expect("es256 keypair");
        let pem = kp.serialize_pem();
        let encoding_key =
            jsonwebtoken::EncodingKey::from_ec_pem(pem.as_bytes()).expect("jwt ec_pem");

        let uncompressed = kp.public_key_raw();
        assert!(
            uncompressed.len() == 65 && uncompressed[0] == 0x04,
            "expected P-256 uncompressed public key"
        );
        let x = &uncompressed[1..33];
        let y = &uncompressed[33..65];

        let url_safe = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let jwk_json = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "kid": kid,
            "x": url_safe.encode(x),
            "y": url_safe.encode(y),
        });

        Self {
            kid: kid.to_string(),
            encoding_key,
            jwk_json,
        }
    }

    pub fn sign(&self, claims: &serde_json::Value) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(self.kid.clone());
        header.typ = Some("JWT".to_string());
        jsonwebtoken::encode(&header, claims, &self.encoding_key).expect("jwt sign")
    }

    pub fn to_vigil_jwk(&self) -> vigil_http_auth::Jwk {
        serde_json::from_value(self.jwk_json.clone()).expect("jwk parse")
    }
}

/// **I10b-α2 代码 R1 MUST-FIX 4**:真 RS256 sign/verify round trip 证据。
///
/// rcgen 只支持 ECDSA key generation(底层用 ring),RSA 需要独立 keygen。用
/// `rsa` crate 在 test-only 路径生成 RS256 key pair,然后手工组装 PEM + JWK。
pub(crate) struct TestRs256Key {
    pub kid: String,
    pub encoding_key: jsonwebtoken::EncodingKey,
    pub jwk_json: serde_json::Value,
}

impl TestRs256Key {
    pub fn new(kid: &str) -> Self {
        use base64::Engine;
        use rsa::pkcs1::EncodeRsaPublicKey;
        use rsa::pkcs8::{EncodePrivateKey, LineEnding};
        use rsa::traits::PublicKeyParts;
        use rsa::{RsaPrivateKey, RsaPublicKey};

        // 2048 bit RSA(最小安全尺寸;test-only)
        let mut rng = rand_08::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
        let pub_key = RsaPublicKey::from(&priv_key);

        let pem = priv_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("rsa private pem");
        let encoding_key =
            jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes()).expect("jwt rsa pem");

        // JWK 需要 `n`(modulus)和 `e`(exponent),base64url 无填充
        let url_safe = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let n_bytes = pub_key.n().to_bytes_be();
        let e_bytes = pub_key.e().to_bytes_be();
        let jwk_json = serde_json::json!({
            "kty": "RSA",
            "alg": "RS256",
            "kid": kid,
            "n": url_safe.encode(&n_bytes),
            "e": url_safe.encode(&e_bytes),
        });
        let _ = pub_key.to_pkcs1_der(); // silence unused import if EncodeRsaPublicKey unused

        Self {
            kid: kid.to_string(),
            encoding_key,
            jwk_json,
        }
    }

    pub fn sign(&self, claims: &serde_json::Value) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        header.typ = Some("JWT".to_string());
        jsonwebtoken::encode(&header, claims, &self.encoding_key).expect("jwt sign")
    }

    pub fn to_vigil_jwk(&self) -> vigil_http_auth::Jwk {
        serde_json::from_value(self.jwk_json.clone()).expect("jwk parse")
    }
}

/// 便捷构造:文本 body response。
pub(crate) fn ok_json(body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

/// 读请求 body → Bytes(for assert)。
pub(crate) async fn read_body(req: Request<Incoming>) -> Bytes {
    req.into_body().collect().await.unwrap().to_bytes()
}
