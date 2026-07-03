//! HTTP 客户端抽象(ADR 0010 §D8 / ADR 0011 §α1-D2)。
//!
//! **两条面,独立 DI**(BLOCKER 2 修复):
//! - `HttpClient` —— 通用发送面,发现路径用(PRM / AS metadata / JWKS),接受任意
//!   `HttpRequest`,**不**做 Authorization 约束
//! - `AuthorizedSender` —— upstream 请求**专用**面,只接 `AuthorizedHttpRequest`
//!   (必经 `plan_authorized_request` 构造)。`HttpUpstream`(α2)只持
//!   `Arc<dyn AuthorizedSender>`,类型上不可能拿原 `HttpClient` 绕过 planner。
//!
//! α1 两条面都只定义 + mock;真 reqwest 实装在 α2 `vigil-http-transport`。

use std::collections::HashMap;
use std::sync::Mutex;

use url::Url;

use crate::error::HttpAuthError;
use crate::planner::AuthorizedHttpRequest;

/// HTTP 方法。
///
/// I10a 定义 Get / PostForm(OAuth token 端点);I10b-α2 加 `Post` 变体承载 JSON body
/// (JSON-RPC over HTTP,MCP spec 要求 `Content-Type: application/json`)。
/// `#[non_exhaustive]` 让未来新增 method 不破坏消费 match。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HttpMethod {
    /// GET
    Get,
    /// POST with `application/x-www-form-urlencoded`(OAuth token / PKCE exchange)
    PostForm,
    /// POST with `application/json`(MCP JSON-RPC body,I10b-α2 新增)
    Post,
}

/// HTTP 请求。
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// 目标 URL
    pub url: Url,
    /// 方法
    pub method: HttpMethod,
    /// headers(name, value)—— **禁止**有任何 bearer-like header(由 caller 保证)
    pub headers: Vec<(String, String)>,
    /// body(POST form 时为 `key=value&...` UTF-8)
    pub body: Option<Vec<u8>>,
}

/// HTTP 响应(最小投影)。
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code(100-599)
    pub status: u16,
    /// response body 原始字节
    pub body: Vec<u8>,
}

/// HTTP 客户端 trait —— 通用发送面(发现路径用 PRM / AS metadata / JWKS)。
///
/// I10a 只测 mock;I10b-α2 接 reqwest。**不**允许 `HttpUpstream` 持有这个 trait;
/// upstream 请求必经 `AuthorizedSender`(ADR 0011 §α1-D2)。
pub trait HttpClient: Send + Sync {
    /// 同步请求(I10a 不做 async 以简化 ADR 0010 §D8 的边界定义)。
    fn send(&self, req: &HttpRequest) -> Result<HttpResponse, HttpAuthError>;
}

/// Upstream 请求**专用**发送面(ADR 0011 §α1-D2 / §I-11.1)。
///
/// 类型约束:入参只能是 `AuthorizedHttpRequest` —— 这个类型**只能**由
/// `plan_authorized_request` 构造(planner 模块内 header 剥离 + same-origin 校验已做),
/// 因此 `HttpUpstream` 只持 `Arc<dyn AuthorizedSender>` 时**无法**自拼 Authorization
/// 或绕过 planner。
///
/// α1 mock 实装在 `MockHttpClient`(复用,见下);α2 真实装在 `vigil-http-transport`。
pub trait AuthorizedSender: Send + Sync + std::fmt::Debug {
    /// 发送已鉴权的 upstream 请求(使用默认超时)。
    fn send_authorized(&self, req: &AuthorizedHttpRequest) -> Result<HttpResponse, HttpAuthError>;

    /// 发送已鉴权的 upstream 请求,带**显式 per-call timeout**(I10b-α2 代码 R1 MUST-FIX 1)。
    ///
    /// 默认实现忽略 timeout 回退 `send_authorized`;真实装(`ReqwestHttpClient`)应覆盖,
    /// 把 timeout 传给底层 request builder。`HttpUpstream::call(method, params, timeout)` 契约
    /// 要求 per-call timeout 生效 —— HttpUpstream 必须调此方法而非 `send_authorized`。
    fn send_authorized_with_timeout(
        &self,
        req: &AuthorizedHttpRequest,
        _timeout: std::time::Duration,
    ) -> Result<HttpResponse, HttpAuthError> {
        self.send_authorized(req)
    }
}

/// Mock HTTP client —— 按 `(method, url)` 预录响应,未注册的请求返
/// `HttpError("unregistered_mock")`。
#[derive(Debug, Default)]
pub struct MockHttpClient {
    // (method, url_string) → response(多次响应按序出队)
    registrations: Mutex<HashMap<(HttpMethod, String), Vec<HttpResponse>>>,
    // 记录所有发出的请求(供断言 passthrough-deny 等)
    calls: Mutex<Vec<HttpRequest>>,
}

impl MockHttpClient {
    /// 新建空 mock。
    pub fn new() -> Self {
        Self::default()
    }

    /// 预录一条响应。同一 key 多次预录会按 FIFO 出队。
    pub fn register(&self, method: HttpMethod, url: &str, response: HttpResponse) {
        let mut g = self.registrations.lock().expect("mock lock");
        g.entry((method, url.to_string()))
            .or_default()
            .push(response);
    }

    /// 返回已发出的请求(拷贝一份)。测试用来断言 headers 等。
    pub fn calls(&self) -> Vec<HttpRequest> {
        self.calls.lock().expect("mock lock").clone()
    }
}

impl HttpClient for MockHttpClient {
    fn send(&self, req: &HttpRequest) -> Result<HttpResponse, HttpAuthError> {
        // 记录调用(含 headers 便于 passthrough-deny 断言;mock 内存只测试用)
        self.calls.lock().expect("mock lock").push(req.clone());
        let key = (req.method, req.url.as_str().to_string());
        let mut g = self.registrations.lock().expect("mock lock");
        let queue = g
            .get_mut(&key)
            .ok_or(HttpAuthError::HttpError("unregistered_mock"))?;
        if queue.is_empty() {
            return Err(HttpAuthError::HttpError("mock_queue_exhausted"));
        }
        Ok(queue.remove(0))
    }
}

impl AuthorizedSender for MockHttpClient {
    fn send_authorized(&self, req: &AuthorizedHttpRequest) -> Result<HttpResponse, HttpAuthError> {
        // 把 AuthorizedHttpRequest 投影回 HttpRequest 复用 mock 查表;
        // 真实装(reqwest)会直接发出去,**不**经 HttpRequest。
        let projected = HttpRequest {
            url: req.url().clone(),
            method: req.method(),
            headers: req.headers().to_vec(),
            body: req.body().map(|b| b.to_vec()),
        };
        self.send(&projected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_returns_registered_response() {
        let m = MockHttpClient::new();
        let url: Url = "https://example.com/x".parse().unwrap();
        m.register(
            HttpMethod::Get,
            url.as_str(),
            HttpResponse {
                status: 200,
                body: b"ok".to_vec(),
            },
        );
        let resp = m
            .send(&HttpRequest {
                url,
                method: HttpMethod::Get,
                headers: vec![],
                body: None,
            })
            .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"ok");
    }

    #[test]
    fn mock_unregistered_returns_http_error() {
        let m = MockHttpClient::new();
        let err = m
            .send(&HttpRequest {
                url: "https://nope.example.com/".parse().unwrap(),
                method: HttpMethod::Get,
                headers: vec![],
                body: None,
            })
            .unwrap_err();
        assert!(matches!(err, HttpAuthError::HttpError("unregistered_mock")));
    }

    /// I10b-α1 §α1-D2 守门:`AuthorizedSender` trait object 必须 `Send + Sync + Debug`,
    /// 且能被 `Arc<dyn AuthorizedSender>` 包装 —— 这是 `HttpUpstream` 在 α2 持有它的
    /// 基础。运行时 smoke,不做 trybuild(MSRV 避免引入额外 dev-dep)。
    #[test]
    fn authorized_sender_is_dyn_compatible() {
        use std::sync::Arc;

        let m: Arc<dyn AuthorizedSender> = Arc::new(MockHttpClient::new());
        // Debug 可打印
        let s = format!("{m:?}");
        assert!(s.contains("MockHttpClient"));
        // Send + Sync:能跨线程 move / share
        let m2 = Arc::clone(&m);
        std::thread::spawn(move || {
            let _ = &m2;
        })
        .join()
        .unwrap();
    }

    /// 类型守门:`HttpClient` 和 `AuthorizedSender` 是**不同**的 trait —— 同一
    /// 具体类型可以同时实现,但 `Arc<dyn HttpClient>` 不等于 `Arc<dyn AuthorizedSender>`,
    /// 必须显式选择其中一个。这保证 `HttpUpstream`(α2)持 `Arc<dyn AuthorizedSender>`
    /// 时无法"顺便用作" `HttpClient` 自拼 Authorization。
    #[test]
    fn http_client_and_authorized_sender_are_distinct_traits() {
        use std::sync::Arc;

        let mock = Arc::new(MockHttpClient::new());
        let _as_http: Arc<dyn HttpClient> = mock.clone();
        let _as_auth: Arc<dyn AuthorizedSender> = mock;
        // 两条面类型不相容:Rust 编译器禁止 `Arc<dyn HttpClient>` 隐式转成
        // `Arc<dyn AuthorizedSender>` —— `HttpUpstream` 字段类型写死为后者即封死。
    }
}
