//! 环回 HTTP/1.1 服务端 + 上游转发。独立线程内跑 tokio 运行时,daemon 的同步主循环不感知异步。

use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited, StreamBody};
use hyper::body::{Bytes, Frame, Incoming};
use hyper::header::{
    HeaderName, HeaderValue, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, EXPECT,
    HOST, ORIGIN, TRANSFER_ENCODING,
};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::rewrite::{rewrite_json, AliasSink, RewriteReport};
use crate::route::{RouteKind, Routes};

/// 默认监听地址:`127.0.0.1:8445`(电话键盘 V-I-G-L)。
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8445";
/// 默认请求体上限 64 MiB(长上下文 + 内联图片够用;超限 413 fail-closed)。
pub const DEFAULT_MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Body = BoxBody<Bytes, BoxError>;

/// 闸门配置。
#[derive(Debug, Clone)]
pub struct GateConfig {
    /// 监听地址(只接受环回 peer)
    pub listen: SocketAddr,
    /// 上游根集合
    pub routes: Routes,
    /// 请求体上限
    pub max_body_bytes: usize,
    /// 上游连接超时(生成流本身不设总超时:模型可能跑几分钟)
    pub connect_timeout: Duration,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            listen: DEFAULT_LISTEN
                .parse()
                .unwrap_or(SocketAddr::from(([127, 0, 0, 1], 8445))),
            routes: Routes::default(),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            connect_timeout: Duration::from_secs(30),
        }
    }
}

/// 审计出口(daemon 接账本;测试用 [`NoopAudit`])。payload **只**含规则名 / 计数 / 别名 / 路由,
/// 绝不含请求体、请求头或凭据字节 —— 账本 `append_event` 自检会拒掉任何含硬指纹的 payload。
pub trait GateAudit: Send + Sync {
    /// 请求体被改写(至少一处命中)。
    fn rewritten(&self, route: RouteKind, report: &RewriteReport);
    /// 请求被闸门拒绝(未到上游)。`code` 是稳定字面量。
    fn blocked(&self, route: Option<RouteKind>, code: &'static str);
    /// 上游不可达 / 超时。
    fn upstream_error(&self, route: RouteKind, code: &'static str);

    /// 因账本写失败而**被丢弃**的事件数(累计)。默认 0 —— 不可能丢事件的实现无需覆盖。
    ///
    /// 账本写不进去时请求仍会放行,所以 `healthz` / `status --json` 必须能把「没有改写」和
    /// 「改写了但没记上」区分开;否则两者在任何外部观测面上长得一模一样,事后取证会得出
    /// 错误结论(敌意评审 2026-09-12 L3)。
    fn dropped_events(&self) -> u64 {
        0
    }
}

/// 不审计(测试 / 未接账本时)。
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopAudit;

impl GateAudit for NoopAudit {
    fn rewritten(&self, _route: RouteKind, _report: &RewriteReport) {}
    fn blocked(&self, _route: Option<RouteKind>, _code: &'static str) {}
    fn upstream_error(&self, _route: RouteKind, _code: &'static str) {}
}

/// 运行期计数(`/vigil/healthz` 与 `outbound status` 读)。
#[derive(Debug, Default)]
pub struct Counters {
    /// 收到的请求数
    pub requests: AtomicU64,
    /// 改写过请求体的请求数
    pub rewritten: AtomicU64,
    /// 被闸门拒绝的请求数
    pub blocked: AtomicU64,
    /// 上游错误数
    pub upstream_errors: AtomicU64,
}

/// 外部注入的依赖。
pub struct GateDeps {
    /// Tier-B 别名扩展点(默认 [`crate::NoAlias`])
    pub aliases: Arc<dyn AliasSink>,
    /// 审计出口
    pub audit: Arc<dyn GateAudit>,
}

impl fmt::Debug for GateDeps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GateDeps").finish_non_exhaustive()
    }
}

/// 启动 / 绑定错误。
#[derive(Debug, thiserror::Error)]
pub enum GateError {
    /// 监听地址绑定失败(端口被占 / 权限)
    #[error("bind {addr}: {source}")]
    Bind {
        /// 试图绑定的地址
        addr: SocketAddr,
        /// 底层错误
        #[source]
        source: std::io::Error,
    },
    /// 其它 IO 错误
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// 运行中的闸门句柄:丢弃即请求关停(不阻塞等待);[`GateHandle::shutdown`] 会等线程退出。
#[derive(Debug)]
pub struct GateHandle {
    addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    thread: Option<std::thread::JoinHandle<()>>,
    counters: Arc<Counters>,
}

impl GateHandle {
    /// 实际绑定地址(端口 0 时有用)。
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// 共享计数器。
    pub fn counters(&self) -> Arc<Counters> {
        Arc::clone(&self.counters)
    }

    /// 请求关停并等待服务线程退出。
    pub fn shutdown(mut self) {
        let _ = self.shutdown.send(true);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for GateHandle {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

struct Gate {
    cfg: GateConfig,
    deps: GateDeps,
    client: reqwest::Client,
    counters: Arc<Counters>,
    started: Instant,
}

/// 在独立线程里启动闸门(同步 API,供 daemon / CLI 调用)。绑定失败立刻返回错误。
pub fn spawn(cfg: GateConfig, deps: GateDeps) -> Result<GateHandle, GateError> {
    let std_listener =
        std::net::TcpListener::bind(cfg.listen).map_err(|source| GateError::Bind {
            addr: cfg.listen,
            source,
        })?;
    std_listener.set_nonblocking(true)?;
    let addr = std_listener.local_addr()?;
    let (tx, rx) = watch::channel(false);
    let counters = Arc::new(Counters::default());
    let thread_counters = Arc::clone(&counters);
    let thread = std::thread::Builder::new()
        .name("vigil-outbound".to_string())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!(error = %e, "outbound gate: tokio runtime build failed");
                    return;
                }
            };
            rt.block_on(async move {
                let client = match reqwest::Client::builder()
                    .connect_timeout(cfg.connect_timeout)
                    // 代理**绝不**跟随重定向:跟随会带着 `x-api-key` 去 Location 指定的**任意**主机
                    //(reqwest 跨主机只清 `Authorization` 类头,不清 `x-api-key`),等于绕开固定上游
                    // 集合。3xx 原样中继给客户端,由它自己决定(Codex 审计 2026-09-12 第 5 条)。
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!(error = %e, "outbound gate: http client build failed");
                        return;
                    }
                };
                let listener = match TcpListener::from_std(std_listener) {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::error!(error = %e, "outbound gate: listener conversion failed");
                        return;
                    }
                };
                let gate = Arc::new(Gate {
                    cfg,
                    deps,
                    client,
                    counters: thread_counters,
                    started: Instant::now(),
                });
                serve(listener, gate, rx).await;
            });
        })?;
    Ok(GateHandle {
        addr,
        shutdown: tx,
        thread: Some(thread),
        counters,
    })
}

/// 同时在途的连接上限。闸门是**本机单用户**设施:真实 agent 只用个位数连接,64 已经宽裕。
///
/// 常态路径上**每条**连接都可能吃掉一次最多 64 MiB 的读取 + 解析 + 全量扫描,而 accept 循环此前
/// **对并发完全没有上限** —— 这是所有预算都约束不到的那一项(敌意评审 2026-09-12)。超限直接关掉
/// 连接而不是排队:排队会让 agent 在不知情的情况下挂起,关连接是**显眼地坏掉**,与闸门其余部分
/// 的 fail-closed 姿态一致。
const MAX_INFLIGHT_CONNECTIONS: usize = 64;

/// 在途连接计数守卫:随连接任务一起 drop,异常退出也会归还。
struct InflightGuard(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn serve(listener: TcpListener, gate: Arc<Gate>, mut shutdown: watch::Receiver<bool>) {
    tracing::info!(addr = %gate.cfg.listen, "outbound gate listening");
    let inflight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::warn!(error = %e, "outbound gate: accept failed");
                        continue;
                    }
                };
                if !peer.ip().is_loopback() {
                    // 只可能在监听地址被配成非环回时发生;仍拒绝,闸门不是给局域网用的
                    continue;
                }
                if inflight.fetch_add(1, Ordering::Relaxed) >= MAX_INFLIGHT_CONNECTIONS {
                    inflight.fetch_sub(1, Ordering::Relaxed);
                    tracing::warn!(
                        limit = MAX_INFLIGHT_CONNECTIONS,
                        "outbound gate: too many in-flight connections; closing this one"
                    );
                    drop(stream);
                    continue;
                }
                let guard = InflightGuard(Arc::clone(&inflight));
                let gate = Arc::clone(&gate);
                tokio::spawn(async move {
                    let _guard = guard;
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req| handle(Arc::clone(&gate), req));
                    if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                        tracing::debug!(error = %e, "outbound gate: connection ended with error");
                    }
                });
            }
        }
    }
}

fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

/// 错误体同时满足 Anthropic(`type:"error"` + `error.type/message`)与 OpenAI(`error.message`)
/// 客户端的解析,用户在 agent 里能直接看到「Vigil outbound gate: …」。
fn error_response(status: StatusCode, code: &str, message: &str) -> Response<Body> {
    let body = serde_json::json!({
        "type": "error",
        "error": {
            "type": format!("vigil_outbound_{code}"),
            "message": format!("Vigil outbound gate: {message}"),
        }
    });
    let mut resp = Response::new(full(body.to_string()));
    *resp.status_mut() = status;
    resp.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn looks_like_json(content_type: Option<&HeaderValue>, body: &[u8]) -> bool {
    if let Some(ct) = content_type.and_then(|v| v.to_str().ok()) {
        if ct.to_ascii_lowercase().contains("json") {
            return true;
        }
    }
    matches!(
        body.iter().find(|b| !b.is_ascii_whitespace()),
        Some(b'{') | Some(b'[')
    )
}

async fn handle(gate: Arc<Gate>, req: Request<Incoming>) -> Result<Response<Body>, hyper::Error> {
    gate.counters.requests.fetch_add(1, Ordering::Relaxed);
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    // 浏览器页面发起的跨站请求带 Origin;闸门只服务本机 CLI 客户端。
    //
    // **必须排在 healthz 之前。** 顺序反过来时,任意网页的
    // `fetch('http://127.0.0.1:8445/vigil/healthz')` 会真实落地并返 200:浏览器因无 CORS 头读不到
    // body,但 load / error 的时序差足以当作「这台机器装没装闸门、在哪个端口」的存在性探针 ——
    // 等于白送一个本机指纹接口(敌意评审 2026-09-12 L1)。
    if req.headers().contains_key(ORIGIN) {
        return Ok(gate.block(
            None,
            StatusCode::FORBIDDEN,
            "browser_origin",
            "browser-originated requests are not accepted",
        ));
    }

    if req.method() == Method::GET && path_and_query == "/vigil/healthz" {
        return Ok(healthz(&gate));
    }

    let Some(resolved) = gate.cfg.routes.resolve(&path_and_query, req.headers()) else {
        return Ok(gate.block(
            None,
            StatusCode::NOT_FOUND,
            "unknown_route",
            "unknown route prefix (expected /anthropic, /openai, /codex or /gemini)",
        ));
    };
    let route = resolved.kind;
    let method = req.method().clone();
    let headers = req.headers().clone();

    let has_body = !matches!(
        method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::DELETE
    );
    let body_bytes: Bytes = if has_body {
        if headers.contains_key(CONTENT_ENCODING) {
            return Ok(gate.block(
                Some(route),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "request_content_encoding",
                "compressed request bodies cannot be inspected; send the body uncompressed",
            ));
        }
        match Limited::new(req.into_body(), gate.cfg.max_body_bytes)
            .collect()
            .await
        {
            Ok(collected) => collected.to_bytes(),
            Err(_) => {
                return Ok(gate.block(
                    Some(route),
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "body_too_large",
                    "request body exceeds the inspection limit",
                ));
            }
        }
    } else {
        Bytes::new()
    };

    // 解析结果提到块外:拒绝路径上要用它定位残留。此前那里是**对同一段字节再解析一次** ——
    // 不是「第二个解析器」(差分解析风险来自两个**不同实现**给出不同的树;这里同一个
    // `serde_json`、同一份字节、同一套 `preserve_order`,结果必然逐位一致),而是**纯粹的浪费**:
    // 最多 64 MiB 的完整解析加整棵树的重新分配(敌意评审 2026-09-12)。
    let mut parsed: Option<serde_json::Value> = None;
    let forwarded_body: Bytes = if has_body && !body_bytes.is_empty() {
        if !looks_like_json(headers.get(CONTENT_TYPE), &body_bytes) {
            return Ok(gate.block(
                Some(route),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "non_json_body",
                "only JSON request bodies can be inspected; non-JSON bodies are refused",
            ));
        }
        let mut value: serde_json::Value = match serde_json::from_slice(&body_bytes) {
            Ok(v) => v,
            Err(_) => {
                return Ok(gate.block(
                    Some(route),
                    StatusCode::BAD_REQUEST,
                    "unparseable_json",
                    "request body is not valid JSON",
                ));
            }
        };
        let report = rewrite_json(&mut value, gate.deps.aliases.as_ref());
        let out = if report.rewrote() {
            gate.counters.rewritten.fetch_add(1, Ordering::Relaxed);
            gate.deps.audit.rewritten(route, &report);
            match serde_json::to_vec(&value) {
                Ok(v) => Bytes::from(v),
                Err(_) => {
                    return Ok(gate.block(
                        Some(route),
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "reserialize_failed",
                        "rewritten body could not be serialized",
                    ));
                }
            }
        } else {
            // 无命中:原字节直通(与客户端发出的完全一致,提示缓存前缀不受格式化影响)
            body_bytes
        };
        parsed = Some(value);
        out
    } else {
        body_bytes
    };

    // ── 出站字节自检(与 MCP 网关「序列化后自检 → 整包扣留」同一纪律)──
    //
    // 改写走的是**解析后的 JSON 树**,真正上行的却是**字节**,两者可以不一致:重复键(解析器只
    // 留最后一个,原字节里的前一个仍在)、按键名跳过的协议信封字段、伪媒体载荷、base64 预算耗尽。
    // 所以在**真正要发的字节**上再查一遍硬指纹,仍命中就拒绝 —— 改写是尽力而为,这一道才是底线。
    // `detect_hard_secret` 会先剥掉我们刚插入的 `[REDACTED …]` 占位符,不会自我误报。
    if !forwarded_body.is_empty() {
        if let Ok(text) = std::str::from_utf8(&forwarded_body) {
            if let Some(kind) = vigil_redaction::detect_hard_secret(text) {
                // 报**位置**不报内容:用户据此只裁掉那一个 assistant 轮次,而不是丢掉整段上下文。
                // 用已经解析好的 `parsed`,不重解析。定位不到的三种情形都落到通用文案:重复 JSON 键
                // (树里已经没有前一个值了)、凭据出现在**键名**位置(只看字符串叶子,不看键)、
                // 以及树太大触到检查预算(敌意评审 2026-09-12)。
                let at = parsed
                    .as_ref()
                    .and_then(crate::rewrite::locate_residual)
                    .unwrap_or_else(|| {
                        "a duplicated JSON key, a field name, or a part too large to pin down"
                            .to_string()
                    });
                return Ok(gate.block(
                    Some(route),
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "residual_secret",
                    &format!(
                        "a {kind} credential survives at {at}, a part of the request the gate cannot \
                         safely rewrite (a protocol envelope field such as a signed `thinking` block, \
                         or a duplicate JSON key); refusing to forward it. Signed reasoning blocks are \
                         replayed on every later turn, so this will keep happening for the rest of \
                         this session: drop that one assistant turn, or start a new session, and \
                         remove the credential from whatever the agent is reading"
                    ),
                ));
            }
        }
    }

    let mut upstream = gate.client.request(method.clone(), &resolved.url);
    for (name, value) in headers.iter() {
        if is_hop_by_hop(name) || name == HOST || name == CONTENT_LENGTH || name == EXPECT {
            continue;
        }
        upstream = upstream.header(name.clone(), value.clone());
    }
    if has_body {
        upstream = upstream.body(forwarded_body);
    }
    let resp = match upstream.send().await {
        Ok(r) => r,
        Err(e) => {
            let (status, code, msg) = if e.is_timeout() {
                (
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream_timeout",
                    "upstream did not answer in time",
                )
            } else if e.is_connect() {
                (
                    StatusCode::BAD_GATEWAY,
                    "upstream_connect",
                    "could not connect to the upstream API",
                )
            } else {
                (
                    StatusCode::BAD_GATEWAY,
                    "upstream_error",
                    "upstream request failed",
                )
            };
            gate.counters
                .upstream_errors
                .fetch_add(1, Ordering::Relaxed);
            gate.deps.audit.upstream_error(route, code);
            return Ok(error_response(status, code, msg));
        }
    };

    let status = resp.status();
    let mut out = Response::builder().status(status);
    if let Some(h) = out.headers_mut() {
        for (name, value) in resp.headers().iter() {
            if is_hop_by_hop(name) || name == CONTENT_LENGTH || name == TRANSFER_ENCODING {
                continue;
            }
            h.append(name.clone(), value.clone());
        }
        h.remove(CONNECTION);
    }
    // 按块直通(SSE 不缓冲)。用 `Response::chunk()` + `unfold` 而非 `bytes_stream()`:后者要 reqwest 的
    // `stream` feature,那会拉进 wasm32-only 的 wasm-streams(licenses 白名单外)并触碰 deny.toml 的
    // reqwest feature 显式白名单。状态用 `Option<Response>`:上游流出错时吐出错误并**终止**(state 置
    // None),绝不在错误后继续拉同一个响应(否则死循环)。
    let stream = futures_util::stream::unfold(Some(resp), |state| async move {
        let mut resp = state?;
        match resp.chunk().await {
            Ok(Some(bytes)) => Some((Ok(Frame::data(bytes)), Some(resp))),
            Ok(None) => None,
            Err(e) => Some((Err(Box::new(e) as BoxError), None)),
        }
    });
    let body: Body = StreamBody::new(stream).boxed();
    Ok(out.body(body).unwrap_or_else(|_| {
        error_response(
            StatusCode::BAD_GATEWAY,
            "response_build",
            "could not relay the upstream response",
        )
    }))
}

fn healthz(gate: &Gate) -> Response<Body> {
    let c = &gate.counters;
    let body = serde_json::json!({
        "ok": true,
        "requests": c.requests.load(Ordering::Relaxed),
        "rewritten": c.rewritten.load(Ordering::Relaxed),
        "blocked": c.blocked.load(Ordering::Relaxed),
        "upstream_errors": c.upstream_errors.load(Ordering::Relaxed),
        // 账本写失败而丢掉的事件数(见 `GateAudit::dropped_events`)
        "audit_dropped": gate.deps.audit.dropped_events(),
        "uptime_secs": gate.started.elapsed().as_secs(),
    });
    let mut resp = Response::new(full(body.to_string()));
    resp.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}

impl Gate {
    fn block(
        &self,
        route: Option<RouteKind>,
        status: StatusCode,
        code: &'static str,
        message: &str,
    ) -> Response<Body> {
        self.counters.blocked.fetch_add(1, Ordering::Relaxed);
        self.deps.audit.blocked(route, code);
        error_response(status, code, message)
    }
}
