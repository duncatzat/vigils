//! 出站闸门端到端:真 TCP、真 HTTP/1.1、mock 上游记录收到的请求,SSE 按块直通。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Bytes, Frame, Incoming};
use hyper::header::HeaderMap;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use vigil_outbound::{
    spawn, GateAudit, GateConfig, GateDeps, NoAlias, RewriteReport, RouteKind, Routes,
};

const GH: &str = "ghp_1234567890abcdef1234567890abcdef12345678";

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Clone)]
struct Captured {
    method: String,
    path: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

type Kinds = Vec<(&'static str, usize)>;

#[derive(Default)]
struct RecordingAudit {
    rewritten: Mutex<Vec<(RouteKind, Kinds)>>,
    blocked: Mutex<Vec<(Option<RouteKind>, &'static str)>>,
    upstream_errors: Mutex<Vec<(RouteKind, &'static str)>>,
}

impl GateAudit for RecordingAudit {
    fn rewritten(&self, route: RouteKind, report: &RewriteReport) {
        self.rewritten
            .lock()
            .unwrap()
            .push((route, report.kinds.clone()));
    }
    fn blocked(&self, route: Option<RouteKind>, code: &'static str) {
        self.blocked.lock().unwrap().push((route, code));
    }
    fn upstream_error(&self, route: RouteKind, code: &'static str) {
        self.upstream_errors.lock().unwrap().push((route, code));
    }
}

/// mock 上游:记录每个请求;`/v1/messages` 回 3 帧 SSE(带间隔),其它回 JSON echo。
async fn start_mock() -> (SocketAddr, Arc<Mutex<Vec<Captured>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let captured: Arc<Mutex<Vec<Captured>>> = Arc::new(Mutex::new(Vec::new()));
    let cap = Arc::clone(&captured);
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => break,
            };
            let cap = Arc::clone(&cap);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let cap = Arc::clone(&cap);
                    async move {
                        let method = req.method().to_string();
                        let path = req
                            .uri()
                            .path_and_query()
                            .map(|p| p.as_str().to_string())
                            .unwrap_or_default();
                        let headers = req.headers().clone();
                        let body = req.into_body().collect().await.unwrap().to_bytes().to_vec();
                        cap.lock().unwrap().push(Captured {
                            method,
                            path: path.clone(),
                            headers,
                            body,
                        });
                        let bare = path.split('?').next().unwrap_or("");
                        if bare.ends_with("/redirect") {
                            let body: BoxBody<Bytes, BoxErr> = Full::new(Bytes::new())
                                .map_err(|never| match never {})
                                .boxed();
                            return Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(307)
                                    .header("location", "/anthropic-up/elsewhere")
                                    .body(body)
                                    .unwrap(),
                            );
                        }
                        if bare.ends_with("/v1/messages") {
                            let frames = vec![
                                "event: message_start\ndata: {\"type\":\"message_start\"}\n\n",
                                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hi\"}}\n\n",
                                "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
                            ];
                            let stream = futures_util::stream::iter(frames).then(|f| async move {
                                tokio::time::sleep(Duration::from_millis(30)).await;
                                Ok::<_, BoxErr>(Frame::data(Bytes::from(f)))
                            });
                            let body: BoxBody<Bytes, BoxErr> =
                                BodyExt::boxed(StreamBody::new(stream));
                            let resp = Response::builder()
                                .status(200)
                                .header("content-type", "text/event-stream")
                                .header("x-upstream", "mock")
                                .header("connection", "keep-alive")
                                .body(body)
                                .unwrap();
                            Ok::<_, std::convert::Infallible>(resp)
                        } else {
                            let body: BoxBody<Bytes, BoxErr> =
                                Full::new(Bytes::from_static(b"{\"echo\":true}"))
                                    .map_err(|never| match never {})
                                    .boxed();
                            Ok(Response::builder()
                                .status(200)
                                .header("content-type", "application/json")
                                .body(body)
                                .unwrap())
                        }
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    (addr, captured)
}

fn gate_for(
    mock: SocketAddr,
    audit: Arc<RecordingAudit>,
    max_body: Option<usize>,
) -> vigil_outbound::GateHandle {
    let base = format!("http://{mock}");
    let cfg = GateConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        routes: Routes {
            anthropic: format!("{base}/anthropic-up"),
            openai: format!("{base}/platform"),
            codex_chatgpt: format!("{base}/chatgpt"),
            gemini: format!("{base}/gemini-up"),
        },
        max_body_bytes: max_body.unwrap_or(vigil_outbound::server::DEFAULT_MAX_BODY_BYTES),
        connect_timeout: Duration::from_secs(5),
    };
    spawn(
        cfg,
        GateDeps {
            aliases: Arc::new(NoAlias),
            audit,
        },
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewrites_body_forwards_headers_and_streams_sse_through() {
    let (mock, captured) = start_mock().await;
    let audit = Arc::new(RecordingAudit::default());
    let gate = gate_for(mock, Arc::clone(&audit), None);
    let client = reqwest::Client::new();

    let body = serde_json::json!({
        "model": "claude-sonnet-4-5",
        "stream": true,
        "messages": [{"role": "user", "content": format!("my token is {GH}")}]
    });
    let resp = client
        .post(format!(
            "http://{}/anthropic/v1/messages?beta=true",
            gate.addr()
        ))
        .header("x-api-key", "sk-ant-api03-TESTKEY")
        .header("anthropic-version", "2023-06-01")
        .header("authorization", "Bearer eyJoauth.token.here")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "text/event-stream"
    );
    assert_eq!(resp.headers().get("x-upstream").unwrap(), "mock");

    // 用 `chunk()` 逐块读(reqwest 的 `stream` feature 被 deny.toml 的 feature 白名单挡住,
    // 生产侧也走同一条路);收到几块就证明几块,能区分「按块直通」与「整包缓冲后一次性给」。
    let mut chunks: Vec<Bytes> = Vec::new();
    let mut resp = resp;
    while let Some(chunk) = resp.chunk().await.unwrap() {
        chunks.push(chunk);
    }
    let joined: Vec<u8> = chunks.iter().flat_map(|c| c.to_vec()).collect();
    let text = String::from_utf8(joined).unwrap();
    assert!(text.starts_with("event: message_start"), "{text}");
    assert!(
        text.ends_with("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"),
        "{text}"
    );
    assert!(
        chunks.len() >= 2,
        "SSE 应按块到达而非整包缓冲,收到 {} 块",
        chunks.len()
    );

    let got = captured.lock().unwrap().clone();
    assert_eq!(got.len(), 1);
    let c = &got[0];
    assert_eq!(c.method, "POST");
    assert_eq!(c.path, "/anthropic-up/v1/messages?beta=true");
    assert_eq!(c.headers.get("x-api-key").unwrap(), "sk-ant-api03-TESTKEY");
    assert_eq!(c.headers.get("anthropic-version").unwrap(), "2023-06-01");
    assert_eq!(
        c.headers.get("authorization").unwrap(),
        "Bearer eyJoauth.token.here"
    );
    let forwarded = String::from_utf8(c.body.clone()).unwrap();
    assert!(
        !forwarded.contains(GH),
        "raw token reached upstream: {forwarded}"
    );
    assert!(forwarded.contains("[REDACTED github_token]"), "{forwarded}");
    let v: serde_json::Value = serde_json::from_str(&forwarded).unwrap();
    assert_eq!(v["model"], "claude-sonnet-4-5");
    assert_eq!(v["stream"], true);

    let rewrites = audit.rewritten.lock().unwrap().clone();
    assert_eq!(
        rewrites,
        vec![(RouteKind::Anthropic, vec![("github_token", 1)])]
    );
    assert_eq!(
        gate.counters()
            .rewritten
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    gate.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clean_body_is_forwarded_byte_identical() {
    let (mock, captured) = start_mock().await;
    let gate = gate_for(mock, Arc::new(RecordingAudit::default()), None);
    let raw = "{ \"model\" : \"gpt-5.5\",\n  \"input\": \"nothing secret here\" }";
    let resp = reqwest::Client::new()
        .post(format!("http://{}/openai/responses", gate.addr()))
        .header("content-type", "application/json")
        .body(raw)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "{\"echo\":true}");
    let got = captured.lock().unwrap().clone();
    assert_eq!(got[0].path, "/platform/responses");
    assert_eq!(got[0].body, raw.as_bytes());
    gate.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn codex_route_picks_upstream_by_auth_shape() {
    let (mock, captured) = start_mock().await;
    let gate = gate_for(mock, Arc::new(RecordingAudit::default()), None);
    let client = reqwest::Client::new();
    let body = serde_json::json!({"model": "gpt-5.5-codex", "input": "hello"});
    client
        .post(format!("http://{}/codex/responses", gate.addr()))
        .header("authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig")
        .header("chatgpt-account-id", "acct_123")
        .json(&body)
        .send()
        .await
        .unwrap();
    client
        .post(format!("http://{}/codex/responses", gate.addr()))
        .header("authorization", "Bearer sk-proj-platformkey")
        .json(&body)
        .send()
        .await
        .unwrap();
    let got = captured.lock().unwrap().clone();
    assert_eq!(got[0].path, "/chatgpt/responses");
    assert_eq!(
        got[0].headers.get("chatgpt-account-id").unwrap(),
        "acct_123"
    );
    assert_eq!(got[1].path, "/platform/responses");
    gate.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocked_shapes_never_reach_upstream() {
    let (mock, captured) = start_mock().await;
    let audit = Arc::new(RecordingAudit::default());
    let gate = gate_for(mock, Arc::clone(&audit), Some(200));
    let client = reqwest::Client::new();
    let base = format!("http://{}", gate.addr());

    let r = client
        .post(format!("{base}/anthropic/v1/messages"))
        .header("content-type", "multipart/form-data; boundary=x")
        .body("--x--")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let err: serde_json::Value = r.json().await.unwrap();
    assert_eq!(err["type"], "error");
    assert_eq!(err["error"]["type"], "vigil_outbound_non_json_body");
    assert!(err["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("Vigil outbound gate:"));

    let r = client
        .post(format!("{base}/anthropic/v1/messages"))
        .header("content-type", "application/json")
        .body("{not json")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    let r = client
        .post(format!("{base}/v1/messages"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);

    let r = client
        .post(format!("{base}/anthropic/v1/messages"))
        .header("origin", "https://evil.example")
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    let big = serde_json::json!({"input": "x".repeat(500)});
    let r = client
        .post(format!("{base}/anthropic/v1/messages"))
        .json(&big)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let r = client
        .post(format!("{base}/anthropic/v1/messages"))
        .header("content-encoding", "gzip")
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    assert!(
        captured.lock().unwrap().is_empty(),
        "blocked requests must not reach upstream"
    );
    let codes: Vec<&str> = audit
        .blocked
        .lock()
        .unwrap()
        .iter()
        .map(|(_, c)| *c)
        .collect();
    assert_eq!(
        codes,
        vec![
            "non_json_body",
            "unparseable_json",
            "unknown_route",
            "browser_origin",
            "body_too_large",
            "request_content_encoding"
        ]
    );

    let h: serde_json::Value = client
        .get(format!("{base}/vigil/healthz"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(h["ok"], true);
    assert_eq!(h["blocked"], 6);
    assert_eq!(h["requests"], 7);
    gate.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn healthz_is_refused_for_browser_origins_not_just_proxied_requests() {
    let (mock, _captured) = start_mock().await;
    let gate = gate_for(mock, Arc::new(RecordingAudit::default()), None);
    let url = format!("http://{}/vigil/healthz", gate.addr());
    let client = reqwest::Client::new();

    // 网页 `fetch()` 必带 Origin —— 必须 403。否则 load / error 的时序差就是一个
    // 「本机装没装闸门、在哪个端口」的存在性探针(敌意评审 2026-09-12 L1)。
    let r = client
        .get(&url)
        .header("origin", "https://evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    // 本机 CLI 不带 Origin,照常可读
    let r = client.get(&url).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v: serde_json::Value = r.json().await.unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["audit_dropped"], 0);
    gate.shutdown();
}

#[tokio::test]
async fn read_only_methods_pass_through_without_body_inspection() {
    let (mock, captured) = start_mock().await;
    let gate = gate_for(mock, Arc::new(RecordingAudit::default()), None);
    let r = reqwest::Client::new()
        .get(format!("http://{}/openai/models", gate.addr()))
        .header("authorization", "Bearer sk-x")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let got = captured.lock().unwrap().clone();
    assert_eq!(got[0].method, "GET");
    assert_eq!(got[0].path, "/platform/models");
    gate.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_down_is_a_visible_gateway_error() {
    let audit = Arc::new(RecordingAudit::default());
    // 占一个端口再释放:几乎肯定无人监听
    let dead = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let cfg = GateConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        routes: Routes {
            anthropic: format!("http://{dead}"),
            ..Routes::default()
        },
        max_body_bytes: 1024,
        connect_timeout: Duration::from_secs(3),
    };
    let gate = spawn(
        cfg,
        GateDeps {
            aliases: Arc::new(NoAlias),
            audit: audit.clone(),
        },
    )
    .unwrap();
    let r = reqwest::Client::new()
        .post(format!("http://{}/anthropic/v1/messages", gate.addr()))
        .json(&serde_json::json!({"model": "m"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_GATEWAY);
    let err: serde_json::Value = r.json().await.unwrap();
    assert_eq!(err["error"]["type"], "vigil_outbound_upstream_connect");
    assert_eq!(audit.upstream_errors.lock().unwrap().len(), 1);
    gate.shutdown();
}

/// 代理绝不跟随重定向:跟随会把 `x-api-key` 带去 `Location` 指定的任意主机,等于绕开固定上游
/// 集合(Codex 审计 2026-09-12 第 5 条)。3xx 应原样中继给客户端。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_redirect_is_relayed_not_followed() {
    let (mock, captured) = start_mock().await;
    let gate = gate_for(mock, Arc::new(RecordingAudit::default()), None);
    let r = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .post(format!("http://{}/anthropic/redirect", gate.addr()))
        .header("x-api-key", "sk-ant-api03-TESTKEY")
        .json(&serde_json::json!({"model": "m"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(
        r.headers().get("location").unwrap(),
        "/anthropic-up/elsewhere"
    );
    let got = captured.lock().unwrap().clone();
    assert_eq!(got.len(), 1, "只该打到第一跳;跟随重定向会出现第二条记录");
    assert_eq!(got[0].path, "/anthropic-up/redirect");
    gate.shutdown();
}

/// 出站字节自检:改写基于**解析后的 JSON 树**,上行的却是**字节**。按键名跳过的协议信封字段、
/// **把「递归深度由解析器负责」写成可执行的事实。** `locate_residual` 与 `rewrite::walk` 都是递归,
/// 但它们消费的树在跑起来之前深度就已经被钉死:`serde_json` 默认开 128 层递归限制,本仓既没有
/// `unbounded_depth` 也没有 `disable_recursion_limit`,所以超深 body 在入口 `from_slice` 就失败、
/// 被映射成 400 `unparseable_json`,根本走不到自检与定位。
///
/// 这条不变量是**借来的** —— 由依赖的默认值提供,我们自己的代码里没有任何东西表达它。哪天有人开了
/// `unbounded_depth`、换了解析器,界限会无声消失。这条测试就是那根钉子(敌意评审 2026-09-12)。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn excessively_nested_bodies_are_refused_before_any_recursion_of_ours() {
    let (mock, captured) = start_mock().await;
    let gate = gate_for(mock, Arc::new(RecordingAudit::default()), None);
    let deep = format!("{}1{}", "[".repeat(200), "]".repeat(200));
    let r = reqwest::Client::new()
        .post(format!("http://{}/anthropic/v1/messages", gate.addr()))
        .header("content-type", "application/json")
        .body(deep)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let err: serde_json::Value = r.json().await.unwrap();
    assert_eq!(err["error"]["type"], "vigil_outbound_unparseable_json");
    assert!(
        captured.lock().unwrap().is_empty(),
        "超深 body 一条都不许上行"
    );
    gate.shutdown();
}

/// **已知未修的缺口,断言按「应当的行为」写死。** 填充**不必**和载荷在同一个叶子里:字节自检扫的
/// 是整包序列化字节、按文档顺序走,于是 256 段解不出文本的 base64 填充能在 `pad` 上把扫描预算烧光,
/// 永远走不到 `thinking` 里那段真载荷 —— 当前结果是 200,凭据上线。
///
/// 下面那条已通过的拒绝用例用的是**明文** token,明文路径不吃 base64 预算,所以它必然通过 ——
/// 它证明的只是容易的那一半(敌意评审 2026-09-12)。
///
/// `#[ignore]` 在这里的作用是让缺口**可见**而不是把它藏起来:断言写的就是 422,修好预算口径
/// (见 ADR 0025 §6,改法在 `vigil-redaction`,hook / 网关共用)当天删掉这行即转绿。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "base64 扫描预算可被非凭据填充饿死;修法在 vigil-redaction 共用面,见 ADR 0025 §6"]
async fn cross_leaf_base64_padding_must_not_starve_the_byte_self_check() {
    let (mock, captured) = start_mock().await;
    let gate = gate_for(mock, Arc::new(RecordingAudit::default()), None);

    // 解出来全是 0xFF 的 base64 段:既不是凭据、也解不出文本,所以不被改写,原样进入上行字节
    let pad = vec!["/"; 44].concat();
    let pad = vec![pad.as_str(); 300].join(" ");
    let body = serde_json::json!({
        "model": "m",
        "pad": pad,
        "messages": [{"role": "assistant", "content": [
            {"type": "thinking", "thinking": "R0lUSFVCX1RPS0VOPWdocF8xMjM0NTY3ODkwYWJjZGVmMTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4Cg==", "signature": "sigAAAA"}
        ]}]
    });
    let r = reqwest::Client::new()
        .post(format!("http://{}/anthropic/v1/messages", gate.addr()))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        captured.lock().unwrap().is_empty(),
        "预算被填充烧光时凭据仍不许上行"
    );
    gate.shutdown();
}

/// 伪媒体载荷、以及重复键(解析器只留最后一个)都会让两者不一致 —— 这些请求必须被拒绝,
/// 绝不能「改写没命中」就原样放行(Codex 审计 2026-09-12 第 1 / 2 / 3 条)。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secret_in_unrewritable_position_is_refused_not_forwarded() {
    let (mock, captured) = start_mock().await;
    let audit = Arc::new(RecordingAudit::default());
    let gate = gate_for(mock, Arc::clone(&audit), None);
    let client = reqwest::Client::new();
    let url = format!("http://{}/anthropic/v1/messages", gate.addr());

    for body in [
        // 信封键名在任意层级都跳过改写
        serde_json::json!({"model": "m", "input": {"name": GH}}),
        serde_json::json!({"model": "m", "input": {"customer_id": GH}}),
        // `thinking` 是模型生成的**自由文本**且会跨轮回传,但受 signature 保护、改不得 —— 只能拒。
        // (这里原先还有两条「伪装成媒体载荷」用例:它们当时靠「跳过改写 + 字节自检」才拒。删掉
        //  媒体跳过之后它们变成正常改写后放行,断言已移到 rewrite.rs 的单测里。)
        serde_json::json!({"model": "m", "messages": [{"role": "assistant", "content": [
            {"type": "thinking", "thinking": format!("the token is {GH}"), "signature": "sigAAAA"}
        ]}]}),
    ] {
        let r = client.post(&url).json(&body).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        let err: serde_json::Value = r.json().await.unwrap();
        assert_eq!(err["error"]["type"], "vigil_outbound_residual_secret");
    }

    // 重复 JSON 键:`serde_json` 只保留最后一个,于是改写「没命中」,但原字节里第一个仍含凭据
    let raw = format!("{{\"model\":\"m\",\"content\":\"{GH}\",\"content\":\"ok\"}}");
    let r = client
        .post(&url)
        .header("content-type", "application/json")
        .body(raw)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);

    assert!(
        captured.lock().unwrap().is_empty(),
        "含残留凭据的请求一条都不许上行"
    );
    let codes: Vec<&str> = audit
        .blocked
        .lock()
        .unwrap()
        .iter()
        .map(|(_, c)| *c)
        .collect();
    assert!(
        codes.iter().all(|c| *c == "residual_secret"),
        "got {codes:?}"
    );
    assert_eq!(codes.len(), 4);
    gate.shutdown();
}
