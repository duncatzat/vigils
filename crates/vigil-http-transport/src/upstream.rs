//! I10b-α2(ADR 0011 §α2-D4 / §I-11.1):`HttpUpstream` impl `McpUpstream`。
//!
//! 严格类型约束:`HttpUpstream` 只持 `Arc<dyn AuthorizedSender>`(planner 已拼 Authorization),
//! **拿不到** 原 `HttpClient`,因此类型上就不可能"自拼 Authorization 发 upstream"。
//!
//! 调用固定顺序:
//! 1. `TokenStore::resolve_access_token(token_ref, &ExpectedBinding, now)`
//! 2. `plan_authorized_request(incoming_headers=EMPTY, resolved, upstream_url, method, body)`
//! 3. `AuthorizedSender::send_authorized(&req)`
//! 4. 解析 JSON-RPC response 或投影 4xx/5xx 到 `UpstreamError`

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;
use url::Url;

use vigil_http_auth::{
    plan_authorized_request, AuthorizedSender, ExpectedBinding, HttpAuthError, HttpMethod,
    TokenStore,
};
use vigil_mcp::{McpUpstream, UpstreamError};
use vigil_types::TransportKind;

/// HTTP MCP upstream —— 持有 TokenStore 引用 + 固定 resource/issuer/scopes 绑定。
///
/// I10c-α1 新增 `auto_refresh` 字段:若 `Some(cfg)`,则 `call` 在遇到 `TokenExpired`
/// (pre-flight)或 upstream 401(post-send)时**自动**触发一次 refresh retry;
/// 失败仍返 `Unauthorized` 让 caller(Hub / UI)走 rehydrate UX。
pub struct HttpUpstream {
    server_id: String,
    mcp_url: Url,
    expected: ExpectedBinding,
    token_ref: String,
    token_store: Arc<TokenStore>,
    sender: Arc<dyn AuthorizedSender>,
    auto_refresh: Option<AutoRefreshConfig>,
}

/// 自动 refresh 配置(I10c-α1 §6)。
///
/// - `token_endpoint`:AS 的 `/token` 端点(复用 `exchange_refresh_token_for_token`)
/// - `client_id`:OAuth public client id(与 `add-remote-mcp --client-id` 一致)
/// - `http_client`:发现 / token 路径专用 client(**不**走 planner;refresh 是 OAuth
///   协议层,不是 MCP upstream 请求)
///
/// **I10c-α1 R1 BLOCKER 5**:`token_endpoint` **必须** https(`AutoRefreshConfig::new`
/// 构造时校验);`http://` 会把 refresh_token 明文暴露给任意中间人。
///
/// **字段 `pub(crate)`**(I10c-α1 R2 修订):外部 caller **不可**直接 struct literal 绕过
/// [`AutoRefreshConfig::new`] 的 https/loopback gate;`new` 是**唯一**合法入口。
#[derive(Clone)]
pub struct AutoRefreshConfig {
    /// AS token endpoint URL(必须 https,由 `new` 强制)
    pub(crate) token_endpoint: Url,
    /// OAuth public client id
    pub(crate) client_id: String,
    /// 发现路径 HTTP client(ReqwestHttpClient 或 mock)
    pub(crate) http_client: Arc<dyn vigil_http_auth::HttpClient>,
}

impl AutoRefreshConfig {
    /// 构造 AutoRefreshConfig(I10c-α1 R1 BLOCKER 5 / R3 修订)。
    ///
    /// `token_endpoint` 必须满足以下之一,否则 fail-closed:
    /// - `scheme == "https"`(prod 常态)
    /// - `scheme == "http"` **且** `host` 是 loopback(`127.0.0.1` / `[::1]` / `localhost`)
    ///   —— 用于本地 mock AS 测试;loopback 不出本机,不存在 MITM 风险
    ///
    /// 其他 `http://` 端点一律拒 —— refresh_token 是明文 OAuth secret,绝不允许发给
    /// 公网 `http://` endpoint(§I-11.3)。
    ///
    /// **唯一构造入口**:外部 caller 不能 struct literal 绕过(字段 `pub(crate)`),
    /// 只能经本函数。R3 去掉了历史的 test-only bypass 通道,prod 与 test 路径一致。
    pub fn new(
        token_endpoint: Url,
        client_id: impl Into<String>,
        http_client: Arc<dyn vigil_http_auth::HttpClient>,
    ) -> Result<Self, vigil_http_auth::HttpAuthError> {
        if !is_safe_token_endpoint(&token_endpoint) {
            return Err(vigil_http_auth::HttpAuthError::HttpError(
                "auto_refresh_token_endpoint_must_be_https_or_loopback",
            ));
        }
        Ok(Self {
            token_endpoint,
            client_id: client_id.into(),
            http_client,
        })
    }
}

/// 判定 `token_endpoint` 是否允许:`https://` 或 `http://` + loopback host。
///
/// Loopback 判定遵循 RFC 6761:`127.0.0.1` / `localhost` / IPv6 `::1`。
fn is_safe_token_endpoint(url: &Url) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => {
            let host = url.host_str().unwrap_or("");
            matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]")
                || host.eq_ignore_ascii_case("localhost")
        }
        _ => false,
    }
}

impl std::fmt::Debug for AutoRefreshConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutoRefreshConfig")
            .field("token_endpoint", &self.token_endpoint.as_str())
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for HttpUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpUpstream")
            .field("server_id", &self.server_id)
            .field("mcp_url", &self.mcp_url.as_str())
            .field("sender", &self.sender)
            .finish_non_exhaustive()
    }
}

impl HttpUpstream {
    /// 构造 HTTP upstream 连接(不启 auto-refresh;token 过期 → Unauthorized 返 caller)。
    ///
    /// `token_ref` 由 caller 调用 `token_ref_for_access(resource, client_id)` 得到。
    pub fn new(
        server_id: impl Into<String>,
        mcp_url: Url,
        expected: ExpectedBinding,
        token_ref: impl Into<String>,
        token_store: Arc<TokenStore>,
        sender: Arc<dyn AuthorizedSender>,
    ) -> Self {
        Self {
            server_id: server_id.into(),
            mcp_url,
            expected,
            token_ref: token_ref.into(),
            token_store,
            sender,
            auto_refresh: None,
        }
    }

    /// I10c-α1:构造带 auto-refresh 的 HttpUpstream。
    ///
    /// `call` 遇 `TokenExpired` / 401 → 自动跑一次 `exchange_refresh_token_for_token` →
    /// 重 resolve + retry 原 RPC。失败仍返 `Unauthorized`。
    pub fn with_auto_refresh(
        server_id: impl Into<String>,
        mcp_url: Url,
        expected: ExpectedBinding,
        token_ref: impl Into<String>,
        token_store: Arc<TokenStore>,
        sender: Arc<dyn AuthorizedSender>,
        refresh: AutoRefreshConfig,
    ) -> Self {
        Self {
            server_id: server_id.into(),
            mcp_url,
            expected,
            token_ref: token_ref.into(),
            token_store,
            sender,
            auto_refresh: Some(refresh),
        }
    }
}

pub(crate) fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl McpUpstream for HttpUpstream {
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
        // I10b-α2 代码 R1 MUST-FIX 1:Hub 传进来的 `timeout` 必须生效 per-call。
        // I10c-α1:加 auto-refresh —— resolve 返 TokenExpired / send 返 401 时,
        // 若 auto_refresh 启用,调 try_refresh_access_token 后重试一次。

        // Pass 1:正常路径
        match self.call_once(method, params.clone(), timeout) {
            Ok(v) => Ok(v),
            Err(UpstreamError::Unauthorized { reason_code })
                if self.auto_refresh.is_some()
                    && matches!(
                        reason_code,
                        "token_expired" | "upstream_401" | "missing_token"
                    ) =>
            {
                // Pass 2:尝试 refresh + retry 一次
                if let Some(cfg) = &self.auto_refresh {
                    match self.token_store.try_refresh_access_token(
                        &self.token_ref,
                        &cfg.client_id,
                        &cfg.token_endpoint,
                        &*cfg.http_client,
                    ) {
                        Ok(_) => self.call_once(method, params, timeout),
                        Err(e) => Err(map_auth_error(e)),
                    }
                } else {
                    Err(UpstreamError::Unauthorized { reason_code })
                }
            }
            Err(other) => Err(other),
        }
    }

    fn shutdown(&self) {
        // reqwest::Client 有内部连接池;drop 时自动 flush。无显式 shutdown。
    }
}

impl HttpUpstream {
    fn call_once(
        &self,
        method: &str,
        params: Option<Value>,
        timeout: Duration,
    ) -> Result<Value, UpstreamError> {
        // 1. sealed resolve_access_token — issuer / verifier / claims 都在这关
        let resolved = self
            .token_store
            .resolve_access_token(&self.token_ref, &self.expected, now_unix_secs())
            .map_err(map_auth_error)?;

        // 2. 必经 planner —— incoming headers **空**,因为 Hub 入口已经把 client
        //    headers 剥离;这里再显式传空确保**不可能**透传 bearer。
        //    body = JSON-RPC 2.0 request
        let rpc = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let body =
            serde_json::to_vec(&rpc).map_err(|_| UpstreamError::Internal("rpc_encode_failed"))?;
        let (authorized, _report) = plan_authorized_request(
            &[], // incoming headers 严格为空 —— planner 保证无 passthrough
            &resolved,
            self.mcp_url.clone(),
            // I10b-α2 代码 R1 BLOCKER 2:JSON body 走 Post(application/json);
            // MCP spec 要求 JSON-RPC over HTTP 使用 application/json 而非 form-urlencoded。
            HttpMethod::Post,
            Some(body),
        )
        .map_err(map_auth_error)?;

        // 3. send_authorized_with_timeout —— 类型上只能是已鉴权请求;per-call timeout 生效
        let resp = self
            .sender
            .send_authorized_with_timeout(&authorized, timeout)
            .map_err(map_auth_error)?;

        // 4. 解析响应;4xx/5xx 投影到 UpstreamError
        match resp.status {
            200 => {
                let v: Value = serde_json::from_slice(&resp.body)
                    .map_err(|_| UpstreamError::Internal("rpc_decode_failed"))?;
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
            401 => Err(UpstreamError::Unauthorized {
                reason_code: "upstream_401",
            }),
            403 => Err(UpstreamError::Forbidden),
            _ => Err(UpstreamError::TransportIo("upstream_non_2xx")),
        }
    }
}

pub(crate) fn map_auth_error(e: HttpAuthError) -> UpstreamError {
    use HttpAuthError as E;
    match e {
        E::MissingToken => UpstreamError::Unauthorized {
            reason_code: "missing_token",
        },
        E::TokenRehydrateRequired { reason_code } => {
            UpstreamError::TokenRehydrateRequired { reason_code }
        }
        E::TokenExpired => UpstreamError::Unauthorized {
            reason_code: "token_expired",
        },
        E::TokenRejectedWrongIssuer { .. } => UpstreamError::AuthError("wrong_issuer"),
        E::AudienceMismatch { .. } => UpstreamError::AuthError("audience_mismatch"),
        E::ScopeMissing(_) => UpstreamError::AuthError("scope_missing"),
        E::JwtSignatureInvalid => UpstreamError::AuthError("jwt_signature_invalid"),
        E::JwtAlgRejected(_) => UpstreamError::AuthError("jwt_alg_rejected"),
        E::JwksKidNotFound => UpstreamError::AuthError("jwks_kid_not_found"),
        E::HttpError(_) => UpstreamError::TransportIo("http_error"),
        _ => UpstreamError::AuthError("auth_other"),
    }
}
