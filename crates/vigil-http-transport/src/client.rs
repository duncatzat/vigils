//! I10b-α2(ADR 0011 §α2-D1):`reqwest::blocking` 封装,同时实装
//! `vigil_http_auth::HttpClient`(发现路径)和 `AuthorizedSender`(upstream 专用)。
//!
//! **关键不变量**:
//! - `default-features = false`;TLS 栈锁为 `rustls-tls`(workspace Cargo.toml 约束)
//! - 连接约束:`connect_timeout = 5s` / `timeout = 30s`
//! - TLS 最低 1.2(rustls 默认不接受 SSLv3 / TLS 1.0 / 1.1)
//! - HTTP/2 启;但不会主动降级到 HTTP/1.0
//! - **不**信任系统根证书 —— 用 `webpki-roots`(ADR 0011 §α2-D1:跨平台一致)

use std::time::Duration;

use reqwest::blocking::{Client, ClientBuilder};
use vigil_http_auth::{
    AuthorizedSender, HttpAuthError, HttpClient, HttpMethod, HttpRequest, HttpResponse,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(30);

/// Production HTTP client —— reqwest + rustls;**没有**同步 / 异步之争,走 blocking。
pub struct ReqwestHttpClient {
    inner: Client,
}

impl std::fmt::Debug for ReqwestHttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReqwestHttpClient")
            .field("tls", &"rustls + webpki-roots")
            .field("connect_timeout", &CONNECT_TIMEOUT)
            .field("total_timeout", &TOTAL_TIMEOUT)
            .finish_non_exhaustive()
    }
}

impl ReqwestHttpClient {
    /// 构造 —— 默认配置锁死 TLS + 超时 + 禁 cookies/gzip。
    ///
    /// prod 路径使用 `webpki-roots`(rustls feature `tls12` 默认启用,低于 1.2 的版本
    /// rustls 本身不支持)。测试路径如需信任自签证书,用 [`ReqwestHttpClient::builder_for_test`]
    /// (仅 `cfg(test)` 可调)。
    pub fn new() -> Result<Self, HttpAuthError> {
        let inner = default_builder()
            .build()
            .map_err(|_| HttpAuthError::HttpError("reqwest_build_failed"))?;
        Ok(Self { inner })
    }

    // I10b-α2 代码 R1 BLOCKER 4 修复:已删除 `__new_for_integration_test`。
    //
    // 历史:α2 初版用 `#[doc(hidden)] pub fn __new_for_integration_test` 让
    // integration test 注入自签 CA。Codex R1 指出这仍是**生产可达公开入口**,违背
    // ADR 0011 §I-11.3 "不信任非 webpki-roots 根证书" 承诺。
    //
    // 当前:信任自签 CA 的能力**完全**收拢到 `tests/common::TestTlsHttpClient`
    // (integration test crate 编译,不进 lib)。`ReqwestHttpClient` 生产面只剩
    // `new()` 一个构造器,强制 webpki-roots。
}

fn default_builder() -> ClientBuilder {
    // rustls + webpki-roots 由 workspace feature `rustls-tls` 固化;
    // 此处不显式切换 tls,避免误关。
    // 默认 `cookies` feature 未启(workspace Cargo.toml 只开 rustls-tls/http2/json/blocking),
    // Client 不会注入 cookie jar。此处**不**调 `cookie_store(...)` —— 该方法仅在 cookies
    // feature 下可用;保持 default-features=false + 不触碰 cookie API 是"静态证据"。
    Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(TOTAL_TIMEOUT)
        .no_gzip()
        .no_brotli()
        .no_deflate()
        // 不自动 proxy 系统环境(避免把 token 漏到 corp proxy;用户要 proxy 走 ADR)
        .no_proxy()
        // **不跟随重定向**(ADR 0021 hostile review CRITICAL)。reqwest 默认跟随 ≤10 跳;
        // 否则一个通过 validate-time SSRF gate 的公网 URL 可经 3xx 把带 token 的请求
        // 重定向到 169.254.169.254 / 内网(SSRF gate 只在 attach 期校验一次,跟随重定向
        // 直接绕过它)。MCP RPC / OAuth 发现路径均无合法重定向需求 → fail-closed 拒跟随。
        .redirect(reqwest::redirect::Policy::none())
        // TLS 最低 1.2;reqwest 0.12 默认已是 1.2,这里显式声明防回退
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
}

// `ReqwestHttpClient` 允许 Arc 包装用作两条 trait,这不是 "绕过" 而是同一具体类型
// 实现两个 trait。`HttpUpstream` 只接 `Arc<dyn AuthorizedSender>`,外部若误把
// Arc<ReqwestHttpClient> 当 HttpClient 用只能发无 Authorization 的 request —— 不影响
// upstream 路径的类型约束(ADR 0011 §α1-D2)。

impl HttpClient for ReqwestHttpClient {
    fn send(&self, req: &HttpRequest) -> Result<HttpResponse, HttpAuthError> {
        send_inner(
            &self.inner,
            req.method,
            req.url.as_str(),
            &req.headers,
            req.body.as_deref(),
            None,
        )
    }
}

impl AuthorizedSender for ReqwestHttpClient {
    fn send_authorized(
        &self,
        req: &vigil_http_auth::AuthorizedHttpRequest,
    ) -> Result<HttpResponse, HttpAuthError> {
        // AuthorizedHttpRequest 的字段集是 HttpRequest 的严格子集;
        // planner 已保证 headers 不含 passthrough(§I-10.3),同时已拼 Authorization。
        // ADR 0021 MF#1:字段已封印,读取走访问器。
        send_inner(
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
        req: &vigil_http_auth::AuthorizedHttpRequest,
        timeout: Duration,
    ) -> Result<HttpResponse, HttpAuthError> {
        // I10b-α2 代码 R1 MUST-FIX 1:per-call timeout 透传到 reqwest RequestBuilder
        send_inner(
            &self.inner,
            req.method(),
            req.url().as_str(),
            req.headers(),
            req.body(),
            Some(timeout),
        )
    }
}

fn send_inner(
    client: &Client,
    method: HttpMethod,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    // I10b-α2 代码 R1 MUST-FIX 1:Some(d) 覆盖 Client 默认 30s 总超时(per-call)
    per_call_timeout: Option<Duration>,
) -> Result<HttpResponse, HttpAuthError> {
    let mut builder = match method {
        HttpMethod::Get => client.get(url),
        HttpMethod::PostForm => client
            .post(url)
            .header("content-type", "application/x-www-form-urlencoded"),
        // I10b-α2 代码 R1 BLOCKER 2:JSON-RPC 专用;MCP spec 要求 application/json
        HttpMethod::Post => client.post(url).header("content-type", "application/json"),
        // `#[non_exhaustive]` HttpMethod 的兜底 —— 未来新增 method 必须显式处理;
        // 否则 fail-closed 避免按错 content-type 发送。
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
    let resp = builder.send().map_err(|e| map_reqwest_error(&e))?;
    let status = resp.status().as_u16();
    let bytes = resp
        .bytes()
        .map_err(|_| HttpAuthError::HttpError("reqwest_body_read_failed"))?;
    Ok(HttpResponse {
        status,
        body: bytes.to_vec(),
    })
}

// 仅把 reqwest 错误**大类**映射到稳定 reason code,**不**透传 underlying message
// (ADR §I-10.1 审计不泄漏底层细节)。
fn map_reqwest_error(e: &reqwest::Error) -> HttpAuthError {
    if e.is_timeout() {
        HttpAuthError::HttpError("reqwest_timeout")
    } else if e.is_connect() {
        HttpAuthError::HttpError("reqwest_connect_failed")
    } else if e.is_request() {
        HttpAuthError::HttpError("reqwest_request_invalid")
    } else {
        HttpAuthError::HttpError("reqwest_other")
    }
}
