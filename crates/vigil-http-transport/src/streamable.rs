//! ADR 0021 Slice 1:`StreamableHttpUpstream` —— 远端 Streamable-HTTP MCP 上游接入 Vigil 网关。
//!
//! 与 α2 [`crate::HttpUpstream`](OAuth-only,保留)**并存**的新传输实现(§2.3)。Slice 1 只处理
//! `application/json` 响应(单条 JSON-RPC);`text/event-stream`(SSE)响应留 Slice 2。
//!
//! **安全**:不改 `McpUpstream` 契约 → 挂进 `Hub.upstreams` 即继承全部传输无关不变量
//! (firewall default-deny / detokenize / redaction / audit)。上游 token **只**经 sealed
//! [`vigil_http_auth::AuthorizedHttpRequest`](MF#1)+ planner 注入 —— 类型上不可 passthrough;
//! plain Bearer 与 OAuth **统一**走同一 planner 路径(Bearer 本地造 `ResolvedAccessToken`)。
//! 上游 `error.message` sha256 折叠(MF#5b),token 只活内存非-Debug `SecretValue`。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use url::Url;
use vigil_lease::SecretValue;

use vigil_http_auth::{
    plan_authorized_request, plan_unauthorized_request, AuthorizedSender, ExpectedBinding,
    HttpMethod, ResolvedAccessToken, TokenStore,
};
use vigil_mcp::{
    safe_protocol_version, McpUpstream, UpstreamError, MAX_SUPPORTED_LISTED, MODERN_PROBE_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS, UNSUPPORTED_PROTOCOL_VERSION_CODE,
};
use vigil_types::TransportKind;

use crate::upstream::{map_auth_error, now_unix_secs};

/// `Mcp-Session-Id` 的接受上限(spec:visible ASCII;上游不可信,再钳长度)。
const MAX_SESSION_ID_LEN: usize = 256;

/// `StreamableHttpUpstream` 的鉴权来源(ADR 0021 §3.3)。两种均经 sealed planner 注入
/// `Authorization: Bearer`,**不可 passthrough**。(`HttpAuth::None` 的无鉴权 public 上游留后续。)
enum StreamableAuth {
    /// 无鉴权(public MCP / loopback mock)—— 不注入 Authorization。
    None,
    /// 静态 Bearer / PAT —— token 只活内存 `SecretValue`(非 Debug,Zeroize)。
    Bearer { token: SecretValue },
    /// OAuth access token —— 复用 α2 `TokenStore` sealed resolve(issuer/aud/scope 校验在内)。
    /// `Box` 因 OAuth 形态显著大于 Bearer(clippy::large_enum_variant)。
    OAuth(Box<OAuthAuth>),
}

/// OAuth 鉴权参数(boxed 进 [`StreamableAuth::OAuth`])。
struct OAuthAuth {
    token_store: Arc<TokenStore>,
    token_ref: String,
    expected: ExpectedBinding,
}

/// 远端 Streamable-HTTP MCP 上游(ADR 0021 Slice 1,**JSON-only**)。
pub struct StreamableHttpUpstream {
    server_id: String,
    mcp_url: Url,
    auth: StreamableAuth,
    sender: Arc<dyn AuthorizedSender>,
    /// `initialize` 响应头 `Mcp-Session-Id`(有状态服务器要求后续请求回带;无状态服务器不发)。
    session_id: Mutex<Option<String>>,
    /// 协商到的协议版本(`MCP-Protocol-Version` 请求头);握手前用本端最高支持版本。
    protocol_version: Mutex<String>,
    /// JSON-RPC 请求 id 单调递增(此前恒为 1)。
    next_id: AtomicU64,
}

impl std::fmt::Debug for StreamableHttpUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // **不**打印 auth(含 token / token_ref)。
        f.debug_struct("StreamableHttpUpstream")
            .field("server_id", &self.server_id)
            .field("mcp_url", &self.mcp_url.as_str())
            .finish_non_exhaustive()
    }
}

impl StreamableHttpUpstream {
    /// 构造无鉴权(public)上游 —— 不注入 Authorization(用于无凭证的 public / loopback MCP)。
    pub fn with_none(
        server_id: impl Into<String>,
        mcp_url: Url,
        sender: Arc<dyn AuthorizedSender>,
    ) -> Self {
        Self {
            server_id: server_id.into(),
            mcp_url,
            auth: StreamableAuth::None,
            sender,
            session_id: Mutex::new(None),
            protocol_version: Mutex::new(SUPPORTED_PROTOCOL_VERSIONS[0].to_string()),
            next_id: AtomicU64::new(1),
        }
    }

    /// 构造 plain-Bearer 上游(静态 token / PAT)。`token` 应为 `env:` / `keyring:` 读出的真值。
    pub fn with_bearer(
        server_id: impl Into<String>,
        mcp_url: Url,
        token: SecretValue,
        sender: Arc<dyn AuthorizedSender>,
    ) -> Self {
        Self {
            server_id: server_id.into(),
            mcp_url,
            auth: StreamableAuth::Bearer { token },
            sender,
            session_id: Mutex::new(None),
            protocol_version: Mutex::new(SUPPORTED_PROTOCOL_VERSIONS[0].to_string()),
            next_id: AtomicU64::new(1),
        }
    }

    /// 构造 OAuth 上游(复用 α2 `TokenStore`;`token_ref` = `token_ref_for_access(resource, client_id)`)。
    pub fn with_oauth(
        server_id: impl Into<String>,
        mcp_url: Url,
        token_store: Arc<TokenStore>,
        token_ref: impl Into<String>,
        expected: ExpectedBinding,
        sender: Arc<dyn AuthorizedSender>,
    ) -> Self {
        Self {
            server_id: server_id.into(),
            mcp_url,
            auth: StreamableAuth::OAuth(Box::new(OAuthAuth {
                token_store,
                token_ref: token_ref.into(),
                expected,
            })),
            sender,
            session_id: Mutex::new(None),
            protocol_version: Mutex::new(SUPPORTED_PROTOCOL_VERSIONS[0].to_string()),
            next_id: AtomicU64::new(1),
        }
    }

    /// 发送一条 JSON-RPC 消息(请求或通知)并带回完整响应。Streamable HTTP 头:`Accept`、
    /// 协商到的 `MCP-Protocol-Version`、握手拿到的 `Mcp-Session-Id`(有则带)。`Content-Type`
    /// 由 sender 按 method 设置(此前这里再传一份造成重复头)。
    fn send_rpc(
        &self,
        rpc: &Value,
        timeout: Duration,
    ) -> Result<vigil_http_auth::HttpResponseFull, UpstreamError> {
        let body =
            serde_json::to_vec(rpc).map_err(|_| UpstreamError::Internal("rpc_encode_failed"))?;
        let mut incoming: Vec<(String, String)> = vec![
            (
                "Accept".to_string(),
                "application/json, text/event-stream".to_string(),
            ),
            (
                "MCP-Protocol-Version".to_string(),
                self.protocol_version
                    .lock()
                    .map_err(|_| UpstreamError::Internal("lock_poisoned"))?
                    .clone(),
            ),
        ];
        if let Some(sid) = self
            .session_id
            .lock()
            .map_err(|_| UpstreamError::Internal("lock_poisoned"))?
            .as_ref()
        {
            incoming.push(("Mcp-Session-Id".to_string(), sid.clone()));
        }
        // None → plan_unauthorized(无 Authorization);Bearer 本地造 ResolvedAccessToken;OAuth 经
        // sealed TokenStore resolve。三者均产 sealed AuthorizedHttpRequest(no passthrough)。
        let (authorized, _report) = match &self.auth {
            StreamableAuth::None => plan_unauthorized_request(
                &incoming,
                self.mcp_url.clone(),
                HttpMethod::Post,
                Some(body),
            ),
            StreamableAuth::Bearer { token } => {
                let resolved = ResolvedAccessToken {
                    raw: token.clone(),
                    resource: self.mcp_url.as_str().to_string(), // same-origin 天然通过
                    scope_set: Vec::new(),
                    expires_at: None,
                };
                plan_authorized_request(
                    &incoming,
                    &resolved,
                    self.mcp_url.clone(),
                    HttpMethod::Post,
                    Some(body),
                )
                .map_err(map_auth_error)?
            }
            StreamableAuth::OAuth(o) => {
                let resolved = o
                    .token_store
                    .resolve_access_token(&o.token_ref, &o.expected, now_unix_secs())
                    .map_err(map_auth_error)?;
                plan_authorized_request(
                    &incoming,
                    &resolved,
                    self.mcp_url.clone(),
                    HttpMethod::Post,
                    Some(body),
                )
                .map_err(map_auth_error)?
            }
        };
        // per-call timeout 生效;sealed request → 类型上只能是已鉴权请求。
        self.sender
            .send_authorized_full_with_timeout(&authorized, timeout)
            .map_err(map_auth_error)
    }

    /// 单条请求(带递增 id)→ `result`。状态码分流:200 解析;202/204 = 通知已接受(空结果);
    /// 401/403 映射;404 且持有会话 = 会话过期(清会话,下次握手重建)。
    fn call_once(
        &self,
        method: &str,
        params: Option<Value>,
        timeout: Duration,
    ) -> Result<Value, UpstreamError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let rpc = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let resp = self.send_rpc(&rpc, timeout)?;
        self.map_status(resp)
    }

    fn map_status(&self, resp: vigil_http_auth::HttpResponseFull) -> Result<Value, UpstreamError> {
        match resp.status {
            200 => parse_json_rpc_result(&resp.body),
            202 | 204 => Ok(Value::Null),
            401 => Err(UpstreamError::Unauthorized {
                reason_code: "upstream_401",
            }),
            403 => Err(UpstreamError::Forbidden),
            404 => {
                let had_session = self
                    .session_id
                    .lock()
                    .map(|mut g| g.take().is_some())
                    .unwrap_or(false);
                Err(UpstreamError::TransportIo(if had_session {
                    "upstream_session_expired"
                } else {
                    "upstream_non_2xx"
                }))
            }
            _ => Err(UpstreamError::TransportIo("upstream_non_2xx")),
        }
    }

    /// MCP 客户端生命周期握手:`initialize` → 校验协商版本 → 记 `Mcp-Session-Id` → `notifications/initialized`。
    ///
    /// 此前 HTTP 上游**从不握手**(直接 tools/list,id 恒 1,协议头写死 2025-03-26):无状态服务器
    /// (AURA / rmcp stateless)侥幸可用,有状态 Streamable HTTP 服务器(要求 `Mcp-Session-Id`)会
    /// 对每个请求回 400/404 —— Vigil×AURA 交叉测试 2026-09-11 线上抓到。与 stdio 路径同一套
    /// 版本白名单与 2026-07-28 现代专属判别(`server/discover` 探针)。
    pub fn initialize_handshake(&self, timeout: Duration) -> Result<(), UpstreamError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let rpc = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": {
                "protocolVersion": SUPPORTED_PROTOCOL_VERSIONS[0],
                "capabilities": {},
                "clientInfo": { "name": "vigil-hub", "version": env!("CARGO_PKG_VERSION") },
            },
        });
        let resp = self.send_rpc(&rpc, timeout)?;
        // 会话 id:spec 要求 visible ASCII;上游不可信,钳长度 + 字符集,不合格当作没有。
        let sid = resp
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("mcp-session-id"))
            .map(|(_, v)| v.trim().to_string())
            .filter(|v| {
                !v.is_empty()
                    && v.len() <= MAX_SESSION_ID_LEN
                    && v.bytes().all(|b| (0x21..=0x7e).contains(&b))
            });
        let result = match self.map_status(resp) {
            Ok(v) => v,
            // 上游以 JSON-RPC error 拒绝 initialize:可能是现代专属服务器(2026-07-28+ 无此方法)。
            // 用 server/discover 探针确定性判别(探针超时收紧:上游已证明在线会应答)。
            Err(orig @ UpstreamError::JsonRpc { .. }) => {
                return Err(
                    self.classify_initialize_rejection(orig, timeout.min(Duration::from_secs(5)))
                );
            }
            Err(e) => return Err(e),
        };
        if let Some(neg) = result.get("protocolVersion").and_then(Value::as_str) {
            if !SUPPORTED_PROTOCOL_VERSIONS.contains(&neg) {
                return Err(UpstreamError::ProtocolVersionUnsupported {
                    negotiated: safe_protocol_version(neg),
                    supported: SUPPORTED_PROTOCOL_VERSIONS.join(", "),
                });
            }
            *self
                .protocol_version
                .lock()
                .map_err(|_| UpstreamError::Internal("lock_poisoned"))? = neg.to_string();
        }
        if let Ok(mut g) = self.session_id.lock() {
            *g = sid;
        }
        let notif = serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        let r = self.send_rpc(&notif, timeout)?;
        if !(200..300).contains(&r.status) {
            return Err(UpstreamError::TransportIo(
                "initialized_notification_rejected",
            ));
        }
        Ok(())
    }

    /// 与 stdio 路径同源的 2026-07-28「Backward Compatibility」三分支裁决:探针成功 → 现代专属;
    /// 探针回 -32022 → 同样是现代服务器;其它 → 保留原 initialize 错误。
    fn classify_initialize_rejection(
        &self,
        orig: UpstreamError,
        probe_timeout: Duration,
    ) -> UpstreamError {
        let params = serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MODERN_PROBE_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {
                    "name": "vigil-hub",
                    "version": env!("CARGO_PKG_VERSION"),
                },
            }
        });
        match self.call_once("server/discover", Some(params), probe_timeout) {
            Ok(result) => {
                let listed: Vec<String> = result
                    .get("supportedVersions")
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter_map(Value::as_str)
                            .take(MAX_SUPPORTED_LISTED)
                            .map(safe_protocol_version)
                            .collect()
                    })
                    .unwrap_or_default();
                UpstreamError::ModernOnlyUpstream {
                    supported: if listed.is_empty() {
                        "no version list".to_string()
                    } else {
                        listed.join(", ")
                    },
                    latest: SUPPORTED_PROTOCOL_VERSIONS[0],
                }
            }
            Err(UpstreamError::JsonRpc { code, .. })
                if code == i64::from(UNSUPPORTED_PROTOCOL_VERSION_CODE) =>
            {
                UpstreamError::ModernOnlyUpstream {
                    supported: "no version list".to_string(),
                    latest: SUPPORTED_PROTOCOL_VERSIONS[0],
                }
            }
            Err(_) => orig,
        }
    }
}

impl McpUpstream for StreamableHttpUpstream {
    fn server_id(&self) -> &str {
        &self.server_id
    }

    fn transport(&self) -> TransportKind {
        TransportKind::Http
    }

    fn call(
        &self,
        method: &str,
        params: Option<Value>,
        timeout: Duration,
    ) -> Result<Value, UpstreamError> {
        self.call_once(method, params, timeout)
    }

    fn shutdown(&self) {
        // reqwest 连接池 drop 自动 flush;无显式 shutdown。
    }
}

/// 解析 200 响应 body 为 JSON-RPC result。
///
/// body 是 SSE 流(`text/event-stream`,Slice 2)→ [`parse_sse_final_response`] 折叠;否则按单条
/// `application/json` JSON-RPC 解析。(reqwest blocking 已把整流 buffer 进 body,故 SSE 是**纯解析**,
/// 无需流式读循环。)上游 `error.message` **sha256 折叠**(MF#5b),不泄漏明文。
fn parse_json_rpc_result(body: &[u8]) -> Result<Value, UpstreamError> {
    if looks_like_sse(body) {
        return parse_sse_final_response(body);
    }
    let v: Value =
        serde_json::from_slice(body).map_err(|_| UpstreamError::Internal("rpc_decode_failed"))?;
    json_rpc_value_to_result(v)
}

/// 从一条 JSON-RPC value 取 `result`;若含 `error` → sha256 折叠 message(MF#5b),不泄漏明文。
fn json_rpc_value_to_result(v: Value) -> Result<Value, UpstreamError> {
    if let Some(err) = v.get("error") {
        let code = err.get("code").and_then(Value::as_i64).unwrap_or(-1);
        let msg = err.get("message").and_then(Value::as_str).unwrap_or("");
        let mut h = sha2::Sha256::default();
        sha2::Digest::update(&mut h, msg.as_bytes());
        return Err(UpstreamError::JsonRpc {
            code,
            message_sha256: hex::encode(sha2::Digest::finalize(h)),
        });
    }
    Ok(v.get("result").cloned().unwrap_or(Value::Null))
}

/// Streamable HTTP 的 `text/event-stream` 响应(ADR 0021 Slice 2):折叠为最终 JSON-RPC response。
///
/// 流里中间 message(progress/log notification —— data 是合法 JSON 但**无** `result`/`error`)
/// 在本层**丢弃**(M2 不回放给 agent;审计是 Hub 的事);凡 data 含 `result`/`error` 即最终响应。
/// 防御:body 总字节上限(reqwest 已 buffer,这里再钳防恶意大流)。
fn parse_sse_final_response(body: &[u8]) -> Result<Value, UpstreamError> {
    const MAX_SSE_BYTES: usize = 8 * 1024 * 1024;
    if body.len() > MAX_SSE_BYTES {
        return Err(UpstreamError::TransportIo("sse_stream_too_large"));
    }
    let text = std::str::from_utf8(body).map_err(|_| UpstreamError::Internal("sse_not_utf8"))?;
    for data in sse_data_payloads(text) {
        if let Ok(v) = serde_json::from_str::<Value>(&data) {
            if v.get("result").is_some() || v.get("error").is_some() {
                return json_rpc_value_to_result(v); // 最终响应
            }
            // 否则 notification(无 result/error)→ 丢弃,继续。
        }
    }
    Err(UpstreamError::TransportIo("sse_no_final_response"))
}

/// 极简 SSE 解析(纯函数,按 SSE 规范):累积 `data:` 行,空行 dispatch 一个 event 的 data payload
/// (多行 data 以 `\n` join);忽略 `:` 注释 + `event:`/`id:`/`retry:` 字段(M2 只需 data)。
/// 兼容 `\r\n`。可独立单测,不依赖网络。
fn sse_data_payloads(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur: Vec<&str> = Vec::new();
    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.is_empty() {
            if !cur.is_empty() {
                out.push(cur.join("\n"));
                cur.clear();
            }
            continue;
        }
        if line.starts_with(':') {
            continue; // 注释行
        }
        if let Some(d) = line.strip_prefix("data:") {
            cur.push(d.strip_prefix(' ').unwrap_or(d)); // 去 data: 后的一个前导空格
        }
        // event:/id:/retry: 等字段 M2 忽略
    }
    if !cur.is_empty() {
        out.push(cur.join("\n")); // 末尾无空行也 dispatch(宽容)
    }
    out
}

/// body 是否看起来是 SSE 流(`data:` / `event:` / `id:` / `retry:` / `:comment` 起头)。
fn looks_like_sse(body: &[u8]) -> bool {
    let s = String::from_utf8_lossy(body);
    let t = s.trim_start();
    t.starts_with("data:")
        || t.starts_with("event:")
        || t.starts_with("id:")
        || t.starts_with("retry:")
        || t.starts_with(':')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use vigil_http_auth::{AuthorizedHttpRequest, HttpAuthError, HttpResponse};

    /// 录制响应 + 捕获发往 upstream 的 sealed 请求头(供 token / passthrough 断言)。
    struct CannedSender {
        status: u16,
        body: Vec<u8>,
        captured: Mutex<Vec<(String, String)>>,
    }
    impl CannedSender {
        fn ok(body: &[u8]) -> Self {
            Self {
                status: 200,
                body: body.to_vec(),
                captured: Mutex::new(Vec::new()),
            }
        }
        fn status(status: u16, body: &[u8]) -> Self {
            Self {
                status,
                body: body.to_vec(),
                captured: Mutex::new(Vec::new()),
            }
        }
        fn captured_headers(&self) -> Vec<(String, String)> {
            self.captured.lock().unwrap().clone()
        }
    }
    impl std::fmt::Debug for CannedSender {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("CannedSender").finish_non_exhaustive()
        }
    }
    impl AuthorizedSender for CannedSender {
        fn send_authorized(
            &self,
            req: &AuthorizedHttpRequest,
        ) -> Result<HttpResponse, HttpAuthError> {
            *self.captured.lock().unwrap() = req.headers().to_vec();
            Ok(HttpResponse {
                status: self.status,
                body: self.body.clone(),
            })
        }
    }

    fn url() -> Url {
        "https://mcp.example.com/rpc".parse().unwrap()
    }

    /// 一条预录响应:(status, body, headers)。
    type Scripted = (u16, Vec<u8>, Vec<(String, String)>);
    /// 一次捕获的请求:(headers, JSON body)。
    type Captured = (Vec<(String, String)>, Value);
    /// 测试脚本里的一条预录响应(借用形态)。
    type ScriptedIn<'a> = (u16, &'a str, Vec<(&'a str, &'a str)>);

    /// 按序回放响应并记录每次请求的 (headers, body) 的 sender。
    struct ScriptedSender {
        responses: Mutex<std::collections::VecDeque<Scripted>>,
        requests: Mutex<Vec<Captured>>,
    }
    impl ScriptedSender {
        fn new(responses: Vec<ScriptedIn<'_>>) -> Self {
            Self {
                responses: Mutex::new(
                    responses
                        .into_iter()
                        .map(|(s, b, h)| {
                            (
                                s,
                                b.as_bytes().to_vec(),
                                h.into_iter()
                                    .map(|(k, v)| (k.to_string(), v.to_string()))
                                    .collect(),
                            )
                        })
                        .collect(),
                ),
                requests: Mutex::new(Vec::new()),
            }
        }
        fn requests(&self) -> Vec<Captured> {
            self.requests.lock().unwrap().clone()
        }
    }
    impl std::fmt::Debug for ScriptedSender {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ScriptedSender").finish_non_exhaustive()
        }
    }
    impl AuthorizedSender for ScriptedSender {
        fn send_authorized(
            &self,
            req: &AuthorizedHttpRequest,
        ) -> Result<HttpResponse, HttpAuthError> {
            let full = self.send_authorized_full_with_timeout(req, Duration::from_secs(1))?;
            Ok(HttpResponse {
                status: full.status,
                body: full.body,
            })
        }
        fn send_authorized_full_with_timeout(
            &self,
            req: &AuthorizedHttpRequest,
            _timeout: Duration,
        ) -> Result<vigil_http_auth::HttpResponseFull, HttpAuthError> {
            let body: Value =
                serde_json::from_slice(req.body().unwrap_or(&[])).unwrap_or(Value::Null);
            self.requests
                .lock()
                .unwrap()
                .push((req.headers().to_vec(), body));
            let (status, body, headers) = self.responses.lock().unwrap().pop_front().unwrap_or((
                500,
                b"unscripted".to_vec(),
                Vec::new(),
            ));
            Ok(vigil_http_auth::HttpResponseFull {
                status,
                body,
                headers,
            })
        }
    }
    fn hdr<'a>(hdrs: &'a [(String, String)], name: &str) -> Option<&'a str> {
        hdrs.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn handshake_negotiates_version_and_carries_session_id() {
        // Vigil×AURA 交叉测试 2026-09-11:此前 HTTP 上游不握手、id 恒 1、协议头写死 2025-03-26。
        let sender = Arc::new(ScriptedSender::new(vec![
            (
                200,
                r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"s","version":"1"}}}"#,
                vec![("Mcp-Session-Id", "sess-abc")],
            ),
            (202, "", vec![]),
            (
                200,
                r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}"#,
                vec![],
            ),
        ]));
        let up = StreamableHttpUpstream::with_none("s", url(), sender.clone());
        up.initialize_handshake(Duration::from_secs(5)).unwrap();
        let r = up.call("tools/list", None, Duration::from_secs(5)).unwrap();
        assert_eq!(r, serde_json::json!({"tools": []}));
        let reqs = sender.requests();
        assert_eq!(reqs.len(), 3, "{reqs:?}");
        // 1) initialize:提议本端最高版本,带 clientInfo
        assert_eq!(reqs[0].1["method"], "initialize");
        assert_eq!(
            reqs[0].1["params"]["protocolVersion"],
            SUPPORTED_PROTOCOL_VERSIONS[0]
        );
        assert_eq!(reqs[0].1["params"]["clientInfo"]["name"], "vigil-hub");
        assert!(hdr(&reqs[0].0, "mcp-session-id").is_none());
        // 2) initialized 通知:无 id;已带协商后的版本头 + 会话
        assert_eq!(reqs[1].1["method"], "notifications/initialized");
        assert!(reqs[1].1.get("id").is_none());
        assert_eq!(hdr(&reqs[1].0, "mcp-protocol-version"), Some("2025-06-18"));
        assert_eq!(hdr(&reqs[1].0, "mcp-session-id"), Some("sess-abc"));
        // 3) tools/list:id 递增(initialize 用了 1)、头同上
        assert_eq!(reqs[2].1["id"], 2);
        assert_eq!(hdr(&reqs[2].0, "mcp-protocol-version"), Some("2025-06-18"));
        assert_eq!(hdr(&reqs[2].0, "mcp-session-id"), Some("sess-abc"));
    }

    #[test]
    fn handshake_rejects_unsupported_negotiated_version() {
        let sender = Arc::new(ScriptedSender::new(vec![(
            200,
            r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"1999-01-01"}}"#,
            vec![],
        )]));
        let up = StreamableHttpUpstream::with_none("s", url(), sender);
        let err = up.initialize_handshake(Duration::from_secs(5)).unwrap_err();
        assert!(
            matches!(err, UpstreamError::ProtocolVersionUnsupported { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains("1999-01-01"), "{err}");
    }

    #[test]
    fn handshake_classifies_modern_only_upstream_via_discover_probe() {
        let sender = Arc::new(ScriptedSender::new(vec![
            (
                200,
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"initialize"}}"#,
                vec![],
            ),
            (
                200,
                r#"{"jsonrpc":"2.0","id":2,"result":{"supportedVersions":["2026-07-28","<script>"]}}"#,
                vec![],
            ),
        ]));
        let up = StreamableHttpUpstream::with_none("s", url(), sender.clone());
        let err = up.initialize_handshake(Duration::from_secs(5)).unwrap_err();
        match &err {
            UpstreamError::ModernOnlyUpstream { supported, latest } => {
                assert!(supported.contains("2026-07-28"), "{supported}");
                assert!(
                    !supported.contains("<script>"),
                    "untrusted list must be sanitized: {supported}"
                );
                assert_eq!(*latest, SUPPORTED_PROTOCOL_VERSIONS[0]);
            }
            other => panic!("expected ModernOnlyUpstream, got {other:?}"),
        }
        let reqs = sender.requests();
        assert_eq!(reqs[1].1["method"], "server/discover");
    }

    #[test]
    fn plain_initialize_error_is_kept_when_probe_fails() {
        let sender = Arc::new(ScriptedSender::new(vec![
            (
                200,
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"nope"}}"#,
                vec![],
            ),
            (
                200,
                r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"server/discover"}}"#,
                vec![],
            ),
        ]));
        let up = StreamableHttpUpstream::with_none("s", url(), sender);
        let err = up.initialize_handshake(Duration::from_secs(5)).unwrap_err();
        assert!(
            matches!(err, UpstreamError::JsonRpc { code: -32000, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn session_404_clears_session_and_reports_expiry() {
        let sender = Arc::new(ScriptedSender::new(vec![
            (
                200,
                r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}"#,
                vec![("mcp-session-id", "S1")],
            ),
            (202, "", vec![]),
            (404, "", vec![]),
            (
                200,
                r#"{"jsonrpc":"2.0","id":3,"result":{"ok":true}}"#,
                vec![],
            ),
        ]));
        let up = StreamableHttpUpstream::with_none("s", url(), sender.clone());
        up.initialize_handshake(Duration::from_secs(5)).unwrap();
        let err = up
            .call("tools/list", None, Duration::from_secs(5))
            .unwrap_err();
        assert!(
            matches!(err, UpstreamError::TransportIo("upstream_session_expired")),
            "{err:?}"
        );
        // 会话已清:下一次请求不再带 Mcp-Session-Id
        let _ = up.call("tools/list", None, Duration::from_secs(5)).unwrap();
        let reqs = sender.requests();
        assert_eq!(hdr(&reqs[2].0, "mcp-session-id"), Some("S1"));
        assert!(
            hdr(&reqs[3].0, "mcp-session-id").is_none(),
            "{:?}",
            reqs[3].0
        );
    }

    #[test]
    fn stateless_server_without_session_header_works_and_bad_session_ids_are_ignored() {
        let sender = Arc::new(ScriptedSender::new(vec![
            (
                200,
                r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}"#,
                vec![("Mcp-Session-Id", "bad id with spaces")],
            ),
            (200, "", vec![]),
            (200, r#"{"jsonrpc":"2.0","id":2,"result":{}}"#, vec![]),
        ]));
        let up = StreamableHttpUpstream::with_none("s", url(), sender.clone());
        up.initialize_handshake(Duration::from_secs(5)).unwrap();
        let _ = up.call("ping", None, Duration::from_secs(5)).unwrap();
        let reqs = sender.requests();
        assert!(
            hdr(&reqs[2].0, "mcp-session-id").is_none(),
            "{:?}",
            reqs[2].0
        );
    }

    #[test]
    fn bearer_happy_path_returns_result_and_injects_streamable_headers() {
        let sender = Arc::new(CannedSender::ok(
            br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
        ));
        let up = StreamableHttpUpstream::with_bearer(
            "gh",
            url(),
            SecretValue::new("SECRET_TOK"),
            sender.clone(),
        );
        let r = up.call("tools/call", None, Duration::from_secs(5)).unwrap();
        assert_eq!(r, serde_json::json!({"ok": true}));

        let hdrs = sender.captured_headers();
        // token 经 planner 注入 Authorization(发往 upstream 是正确的)。
        assert!(hdrs
            .iter()
            .any(|(k, v)| k == "Authorization" && v == "Bearer SECRET_TOK"));
        // Streamable 头注入。
        assert!(hdrs.iter().any(|(k, _)| k == "MCP-Protocol-Version"));
        assert!(hdrs
            .iter()
            .any(|(k, v)| k == "Accept" && v.contains("text/event-stream")));
        // Content-Type 由 sender 按 method 设置,本层**不再**注入(此前重复发两份)。
        assert!(
            !hdrs
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-type")),
            "planner headers must not carry Content-Type (sender sets exactly one): {hdrs:?}"
        );
    }

    #[test]
    fn no_auth_sends_no_authorization_header() {
        let sender = Arc::new(CannedSender::ok(
            br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
        ));
        let up = StreamableHttpUpstream::with_none("pub", url(), sender.clone());
        let r = up.call("tools/call", None, Duration::from_secs(5)).unwrap();
        assert_eq!(r, serde_json::json!({"ok": true}));
        let hdrs = sender.captured_headers();
        // 无鉴权 → 绝不发 Authorization。
        assert!(
            !hdrs
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("authorization")),
            "no-auth must not send Authorization: {hdrs:?}"
        );
        // 但 Streamable 头仍注入。
        assert!(hdrs.iter().any(|(k, _)| k == "MCP-Protocol-Version"));
    }

    #[test]
    fn token_not_in_debug_or_error() {
        let sender = Arc::new(CannedSender::status(401, b""));
        let up = StreamableHttpUpstream::with_bearer(
            "gh",
            url(),
            SecretValue::new("SECRET_TOK"),
            sender,
        );
        // Debug 不含 token。
        let dbg = format!("{up:?}");
        assert!(!dbg.contains("SECRET_TOK"), "debug leaked token: {dbg}");
        // 401 → Unauthorized;错误串不含 token。
        let err = up
            .call("tools/call", None, Duration::from_secs(5))
            .unwrap_err();
        assert!(matches!(err, UpstreamError::Unauthorized { .. }));
        assert!(!format!("{err:?}").contains("SECRET_TOK"));
    }

    #[test]
    fn upstream_jsonrpc_error_message_is_sha256_folded() {
        let sender = Arc::new(CannedSender::ok(
            br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"secret detail xyz"}}"#,
        ));
        let up = StreamableHttpUpstream::with_bearer("gh", url(), SecretValue::new("t"), sender);
        let err = up
            .call("tools/call", None, Duration::from_secs(5))
            .unwrap_err();
        match err {
            UpstreamError::JsonRpc {
                code,
                message_sha256,
            } => {
                assert_eq!(code, -32000);
                assert!(!message_sha256.contains("secret detail")); // 明文不泄漏
                assert_eq!(message_sha256.len(), 64); // sha256 hex
            }
            other => panic!("expected JsonRpc, got {other:?}"),
        }
    }

    #[test]
    fn sse_response_with_notifications_then_final_returns_result() {
        // 2 条 progress notification(无 result/error)+ 1 条最终 response → 折叠返 result。
        let body = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"progress\",\"params\":{\"p\":1}}\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"progress\",\"params\":{\"p\":2}}\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n";
        let sender = Arc::new(CannedSender::ok(body));
        let up = StreamableHttpUpstream::with_bearer("gh", url(), SecretValue::new("t"), sender);
        let r = up.call("tools/call", None, Duration::from_secs(5)).unwrap();
        assert_eq!(r, serde_json::json!({"ok": true}));
    }

    #[test]
    fn sse_response_without_final_yields_no_final_error() {
        // 全是 notification(无 result/error)→ sse_no_final_response(不吊死)。
        let sender = Arc::new(CannedSender::ok(
            b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"log\"}\n\n",
        ));
        let up = StreamableHttpUpstream::with_bearer("gh", url(), SecretValue::new("t"), sender);
        let err = up
            .call("tools/call", None, Duration::from_secs(5))
            .unwrap_err();
        match err {
            UpstreamError::TransportIo(r) => assert_eq!(r, "sse_no_final_response"),
            other => panic!("expected sse_no_final_response, got {other:?}"),
        }
    }

    #[test]
    fn sse_response_error_is_sha256_folded() {
        // SSE 流里的最终 response 是 error → 同样 sha256 折叠,不泄漏明文。
        let sender = Arc::new(CannedSender::ok(
            b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32001,\"message\":\"secret xyz\"}}\n\n",
        ));
        let up = StreamableHttpUpstream::with_bearer("gh", url(), SecretValue::new("t"), sender);
        let err = up
            .call("tools/call", None, Duration::from_secs(5))
            .unwrap_err();
        match err {
            UpstreamError::JsonRpc {
                code,
                message_sha256,
            } => {
                assert_eq!(code, -32001);
                assert!(!message_sha256.contains("secret xyz"));
            }
            other => panic!("expected JsonRpc, got {other:?}"),
        }
    }

    #[test]
    fn sse_data_payloads_parses_frames() {
        let frames = sse_data_payloads(
            ": comment\nevent: x\ndata: line1\ndata: line2\n\ndata: {\"a\":1}\n\n",
        );
        assert_eq!(
            frames,
            vec!["line1\nline2".to_string(), "{\"a\":1}".to_string()]
        );
        assert!(sse_data_payloads(": just a comment\n\n").is_empty());
    }

    #[test]
    fn non_json_garbage_body_is_decode_error_not_sse() {
        let sender = Arc::new(CannedSender::ok(b"\xff\xfe not json at all"));
        let up = StreamableHttpUpstream::with_bearer("gh", url(), SecretValue::new("t"), sender);
        let err = up
            .call("tools/call", None, Duration::from_secs(5))
            .unwrap_err();
        assert!(matches!(err, UpstreamError::Internal("rpc_decode_failed")));
    }

    #[test]
    fn transport_kind_is_http_and_server_id() {
        let sender = Arc::new(CannedSender::ok(b"{}"));
        let up = StreamableHttpUpstream::with_bearer("gh", url(), SecretValue::new("t"), sender);
        assert_eq!(up.transport(), TransportKind::Http);
        assert_eq!(up.server_id(), "gh");
    }

    #[test]
    fn looks_like_sse_classifies() {
        assert!(looks_like_sse(b"data: {}\n\n"));
        assert!(looks_like_sse(b"  event: x"));
        assert!(looks_like_sse(b": keepalive comment"));
        assert!(!looks_like_sse(b"{\"jsonrpc\":\"2.0\"}"));
        assert!(!looks_like_sse(b"[1,2,3]"));
    }
}
