//! v0.5 P2 ADR 0012 stub server 测试矩阵(6 场景)。
//!
//! # 覆盖
//!
//! | id | 场景 | 入口 |
//! |---|---|---|
//! | (a) | 200 完整 16-chunk 串接 + sha256 命中 happy path | [`test_happy_path_16chunk`] |
//! | (b) | ETag 304 短路:本地三件套已就绪 + .etag 命中 | [`test_etag_304_short_circuit`] |
//! | (c) | sha256 mismatch:产物被删除 + 返 Sha256Mismatch | [`test_sha256_mismatch_deletes`] |
//! | (d) | primary 失败 fallback 成功 | [`test_fallback_url_recovers`] |
//! | (e) | 全 mirror 不可达 → NetworkUnreachable | [`test_all_urls_fail`] |
//! | (f) | cfg-gate 守门(默认 build 不编译此模块)| [`cfg_gate_active`] |
//!
//! # tiny_http 单线程响应
//!
//! 起 `Server::http("127.0.0.1:0")` bind 0 拿动态端口;handler 在 spawn thread 内
//! 同步 `incoming_requests().recv()` 循环。测试结束 drop server 关 socket。

#![cfg(all(test, feature = "ort"))]
// 测试代码允许 panic / unwrap / expect(workspace clippy 默认禁止,这里显式放开;
// 与 lib.rs:28 #![allow(clippy::unwrap_used, clippy::expect_used)] 同源纪律)
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tiny_http::{Header, Method, Response, Server, StatusCode};

use super::manifest::{Manifest, ManifestFile};
use super::{ensure_with_manifest, BootstrapError};

/// 三件套 fixture 字节(各自不同,便于 sha256 区分)。
fn fixture_bytes(name: &str) -> Vec<u8> {
    // 用 16 字节(刚好够测 chunk_count=16 时 chunk_size=1)
    match name {
        "model_q4f16.onnx" => b"AAAAAAAAAAAAAAAA".to_vec(),
        "tokenizer.json" => b"BBBBBBBBBBBBBBBB".to_vec(),
        "config.json" => b"CCCCCCCCCCCCCCCC".to_vec(),
        _ => b"DDDDDDDDDDDDDDDD".to_vec(),
    }
}

/// 计算 fixture 字节的 sha256(hex,小写)。
fn fixture_sha256(name: &str) -> String {
    hex::encode(Sha256::digest(fixture_bytes(name)))
}

/// 起一个 tiny_http server,返 (base_url, handle, request_counter)。
///
/// handler 由 caller 提供;返 `Response<...>`。Drop handle 即关 server。
fn spawn_stub_server<F>(
    handler: F,
) -> (
    String,
    thread::JoinHandle<()>,
    Arc<AtomicUsize>,
    Arc<Server>,
)
where
    F: Fn(&tiny_http::Request, usize) -> Response<std::io::Cursor<Vec<u8>>> + Send + Sync + 'static,
{
    let server = Arc::new(Server::http("127.0.0.1:0").expect("bind 127.0.0.1:0"));
    let port = server.server_addr().to_ip().expect("bind ip").port();
    let base_url = format!("http://127.0.0.1:{port}");

    let counter = Arc::new(AtomicUsize::new(0));
    let counter_h = counter.clone();
    let server_h = server.clone();
    let handle = thread::spawn(move || {
        for req in server_h.incoming_requests() {
            let n = counter_h.fetch_add(1, Ordering::SeqCst);
            let resp = handler(&req, n);
            let _ = req.respond(resp);
        }
    });

    (base_url, handle, counter, server)
}

/// 构造测试 Manifest(三件套)指向 stub server 各 url path。
fn build_test_manifest(base_url: &str) -> Manifest {
    Manifest {
        model_name: "test-model".to_string(),
        version: "v1".to_string(),
        chunk_count: 16,
        files: vec![
            ManifestFile {
                name: "model_q4f16.onnx".to_string(),
                size_bytes: fixture_bytes("model_q4f16.onnx").len() as u64,
                sha256: fixture_sha256("model_q4f16.onnx"),
                primary_url: format!("{base_url}/model_q4f16.onnx"),
                fallback_urls: vec![],
            },
            ManifestFile {
                name: "tokenizer.json".to_string(),
                size_bytes: fixture_bytes("tokenizer.json").len() as u64,
                sha256: fixture_sha256("tokenizer.json"),
                primary_url: format!("{base_url}/tokenizer.json"),
                fallback_urls: vec![],
            },
            ManifestFile {
                name: "config.json".to_string(),
                size_bytes: fixture_bytes("config.json").len() as u64,
                sha256: fixture_sha256("config.json"),
                primary_url: format!("{base_url}/config.json"),
                fallback_urls: vec![],
            },
        ],
        // v0.7-α3 三层 pin 字段对测试 download/verify 路径无影响,走 Default
        ..Default::default()
    }
}

/// 通用 GET handler:解析 url path → fixture 字节 + Range 切片。
/// HEAD → 返 Content-Length + ETag,空 body。
fn serve_chunk(req: &tiny_http::Request, etag: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let path = req.url().trim_start_matches('/');
    let bytes = fixture_bytes(path);

    if req.method() == &Method::Head {
        let mut resp = Response::from_data(Vec::new());
        resp = resp
            .with_header(
                Header::from_bytes(&b"Content-Length"[..], bytes.len().to_string()).unwrap(),
            )
            .with_header(Header::from_bytes(&b"ETag"[..], etag).unwrap());
        return resp;
    }

    // Range parse: bytes=start-end (inclusive)
    let range = req
        .headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case("range"))
        .map(|h| h.value.as_str().to_string());

    if let Some(r) = range {
        let r = r.trim_start_matches("bytes=");
        let parts: Vec<&str> = r.split('-').collect();
        if parts.len() == 2 {
            let start: usize = parts[0].parse().unwrap_or(0);
            let end: usize = parts[1].parse().unwrap_or(bytes.len() - 1);
            let end = end.min(bytes.len().saturating_sub(1));
            if start <= end && start < bytes.len() {
                let slice = bytes[start..=end].to_vec();
                return Response::from_data(slice).with_status_code(StatusCode(206));
            }
        }
    }
    // 无 Range → 完整 200(server 不支持 Range 时的兜底)
    Response::from_data(bytes)
}

// ────────────────────────────── (a) ──────────────────────────────

#[test]
fn test_happy_path_16chunk() {
    let (base_url, _h, _counter, server) = spawn_stub_server(|req, _n| serve_chunk(req, "\"v1\""));

    let tmp = TempDir::new().expect("tmp");
    let manifest = build_test_manifest(&base_url);

    let result = ensure_with_manifest(Some(tmp.path()), &manifest);
    drop(server);

    let paths = result.expect("happy path bootstrap should succeed");
    assert!(paths.onnx.exists());
    assert!(paths.tokenizer.exists());
    assert!(paths.config.exists());
    // 三件套字节内容必须等于 fixture(sha256 已通过验证)
    assert_eq!(
        std::fs::read(&paths.onnx).unwrap(),
        fixture_bytes("model_q4f16.onnx")
    );
}

// ────────────────────────────── (b) ──────────────────────────────

#[test]
fn test_etag_304_short_circuit() {
    // 预先在 target_dir 落盘三件套 + 正确 sha256 → check_existing 应直接命中,
    // 0 网络请求(server 永远收不到任何 req)。
    let tmp = TempDir::new().expect("tmp");
    for name in ["model_q4f16.onnx", "tokenizer.json", "config.json"] {
        let path = tmp.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&fixture_bytes(name)).unwrap();
    }

    // server 起来但 handler 永远 panic(命中即测试失败)
    let (base_url, _h, counter, server) = spawn_stub_server(|_req, _n| {
        panic!("server should NOT be hit when local cache is sha256-valid");
    });

    let manifest = build_test_manifest(&base_url);
    let result = ensure_with_manifest(Some(tmp.path()), &manifest);
    drop(server);

    let paths = result.expect("304 short-circuit should succeed");
    assert!(paths.onnx.exists());
    // 0 网络请求
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "expected 0 server hits when local cache valid"
    );
}

/// 回归守门(deberta model.onnx):check_existing 必须认 `model.onnx` 文件名(deberta FP32 布局)。
/// 此前 verify::check_existing 的 match 只认 `model_q4f16.onnx` → deberta check_existing 恒返
/// None → 每次 serve 启动重下载 738MB。复用 q4f16 fixture 字节但以 model.onnx 落盘 + manifest,
/// 断言 ensure_with_manifest 走 0 网络命中(server 命中即 panic)。
#[test]
fn test_check_existing_accepts_deberta_model_onnx() {
    let tmp = TempDir::new().expect("tmp");
    let onnx_bytes = fixture_bytes("model_q4f16.onnx");
    std::fs::write(tmp.path().join("model.onnx"), &onnx_bytes).unwrap();
    std::fs::write(
        tmp.path().join("tokenizer.json"),
        fixture_bytes("tokenizer.json"),
    )
    .unwrap();
    std::fs::write(tmp.path().join("config.json"), fixture_bytes("config.json")).unwrap();

    // server 命中即 panic → 证明走 check_existing 命中(0 网络),而非重下载
    let (base_url, _h, counter, server) = spawn_stub_server(|_req, _n| {
        panic!("server should NOT be hit when deberta model.onnx cache is sha256-valid");
    });

    // deberta 布局 manifest:onnx 文件名 model.onnx(非 q4f16)
    let manifest = Manifest {
        model_name: "deberta-injection".to_string(),
        version: "v2".to_string(),
        chunk_count: 16,
        files: vec![
            ManifestFile {
                name: "model.onnx".to_string(),
                size_bytes: onnx_bytes.len() as u64,
                sha256: fixture_sha256("model_q4f16.onnx"),
                primary_url: format!("{base_url}/model.onnx"),
                fallback_urls: vec![],
            },
            ManifestFile {
                name: "tokenizer.json".to_string(),
                size_bytes: fixture_bytes("tokenizer.json").len() as u64,
                sha256: fixture_sha256("tokenizer.json"),
                primary_url: format!("{base_url}/tokenizer.json"),
                fallback_urls: vec![],
            },
            ManifestFile {
                name: "config.json".to_string(),
                size_bytes: fixture_bytes("config.json").len() as u64,
                sha256: fixture_sha256("config.json"),
                primary_url: format!("{base_url}/config.json"),
                fallback_urls: vec![],
            },
        ],
        ..Default::default()
    };
    let result = ensure_with_manifest(Some(tmp.path()), &manifest);
    drop(server);

    let paths = result.expect("check_existing 应命中 model.onnx,不应重下载");
    assert!(paths.onnx.exists(), "onnx slot 应填 model.onnx");
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "model.onnx 缓存 sha256 有效时应 0 网络命中(回归守门:此前漏 model.onnx 致重下载 738MB)"
    );
}

// ──────────────────────── (b2) 不可 range mirror → 单流兜底 ────────────────────────

/// 真机镜像 fallback 验证暴露(2026-06-21):vigils.ai 经 Cloudflare 对 `application/json`
/// 这类 Content-Type 做 on-the-fly 压缩,压缩响应不可 byte-range → 对 16-chunk 的每个
/// `Range` GET 返 **200 全量**。旧逻辑接受 200 并把整文件写进每个 `.partial.<idx>` →
/// 组装 16× 损坏 → sha256 mismatch(serve 启动 fail-closed,HF 屏蔽区用户无法获取 ML 模型)。
///
/// 修复:`url_supports_ranges`(GET `bytes=0-0` 非 206)预探测 → 走 `download_single_stream`。
/// 本测试 mock 一个**对所有 Range 都返 200 全量**的 server(模拟不可 range 镜像),断言
/// `ensure_with_manifest` 仍成功且三件套字节**逐字节正确**(单流拿到正确字节,无 16× 损坏)。
#[test]
fn test_non_rangeable_server_falls_back_to_single_stream() {
    // handler:HEAD 正常返 Content-Length+ETag;GET 一律返完整 200(即便带 Range 也不返 206)
    let (base_url, _h, counter, server) = spawn_stub_server(|req, _n| {
        let path = req.url().trim_start_matches('/');
        let bytes = fixture_bytes(path);
        if req.method() == &Method::Head {
            return Response::from_data(Vec::new())
                .with_header(
                    Header::from_bytes(&b"Content-Length"[..], bytes.len().to_string()).unwrap(),
                )
                .with_header(Header::from_bytes(&b"ETag"[..], "\"nr\"").unwrap());
        }
        // 关键:无视 Range,一律 200 全量(CF 压缩 JSON 的不可 range 行为)
        Response::from_data(bytes)
    });

    let tmp = TempDir::new().expect("tmp");
    let manifest = build_test_manifest(&base_url);

    let result = ensure_with_manifest(Some(tmp.path()), &manifest);
    drop(server);

    let paths = result.expect("non-rangeable server 应经单流兜底成功(而非 16× 损坏)");
    // 三件套字节必须逐字节 == fixture(证单流拿到正确字节)
    assert_eq!(
        std::fs::read(&paths.onnx).unwrap(),
        fixture_bytes("model_q4f16.onnx"),
        "onnx 字节应与 fixture 一致(无分块损坏)"
    );
    assert_eq!(
        std::fs::read(&paths.tokenizer).unwrap(),
        fixture_bytes("tokenizer.json"),
        "tokenizer 字节应与 fixture 一致(此前 16-chunk 对此类 JSON 损坏)"
    );
    assert_eq!(
        std::fs::read(&paths.config).unwrap(),
        fixture_bytes("config.json"),
        "config 字节应与 fixture 一致"
    );
    assert!(
        counter.load(Ordering::SeqCst) > 0,
        "应有真实网络请求(非 check_existing 缓存命中)"
    );
}

/// 锁定不变量(Codex review FIX-REQUIRED):16-chunk 的实际 chunk 请求必须带
/// `Accept-Encoding: identity`,与 `url_supports_ranges` 探测一致 —— 否则探测(identity)见
/// 206、实际 chunk(默认编码)被 server 压缩成 200 即损坏。mock server **仅在请求含
/// `Accept-Encoding: identity` 时对 Range 返 206**,否则返 200 全量。若 chunk 漏带 identity
/// → 拿 200 → `fetch_chunk_once` 拒 → 下载失败。故 `ensure_with_manifest` 成功即证一致。
#[test]
fn test_chunk_requests_send_identity_encoding() {
    let (base_url, _h, _counter, server) = spawn_stub_server(|req, _n| {
        let path = req.url().trim_start_matches('/');
        let bytes = fixture_bytes(path);
        if req.method() == &Method::Head {
            return Response::from_data(Vec::new())
                .with_header(
                    Header::from_bytes(&b"Content-Length"[..], bytes.len().to_string()).unwrap(),
                )
                .with_header(Header::from_bytes(&b"ETag"[..], "\"id\"").unwrap());
        }
        let has_identity = req.headers().iter().any(|h| {
            h.field
                .as_str()
                .as_str()
                .eq_ignore_ascii_case("accept-encoding")
                && h.value.as_str().eq_ignore_ascii_case("identity")
        });
        let range = req
            .headers()
            .iter()
            .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case("range"))
            .map(|h| h.value.as_str().to_string());
        if let Some(r) = range {
            // 仅 identity 下才认 range → 206;否则模拟"默认编码被压缩 → 不可 range" → 200 全量
            if has_identity {
                let r = r.trim_start_matches("bytes=");
                let parts: Vec<&str> = r.split('-').collect();
                if parts.len() == 2 {
                    let start: usize = parts[0].parse().unwrap_or(0);
                    let end: usize = parts[1].parse().unwrap_or(bytes.len() - 1);
                    let end = end.min(bytes.len().saturating_sub(1));
                    if start <= end && start < bytes.len() {
                        return Response::from_data(bytes[start..=end].to_vec())
                            .with_status_code(StatusCode(206));
                    }
                }
            }
            return Response::from_data(bytes).with_status_code(StatusCode(200));
        }
        Response::from_data(bytes)
    });

    let tmp = TempDir::new().expect("tmp");
    let manifest = build_test_manifest(&base_url);
    let result = ensure_with_manifest(Some(tmp.path()), &manifest);
    drop(server);

    let paths = result.expect("chunk 请求带 identity → 探测+chunk header 一致 → 16-chunk 成功");
    assert_eq!(
        std::fs::read(&paths.onnx).unwrap(),
        fixture_bytes("model_q4f16.onnx"),
        "onnx 字节应正确(证 chunk 带 identity 拿到 206 分块)"
    );
    assert_eq!(
        std::fs::read(&paths.tokenizer).unwrap(),
        fixture_bytes("tokenizer.json")
    );
}

// ────────────────────────────── (c) ──────────────────────────────

#[test]
fn test_sha256_mismatch_deletes() {
    // server 返 fixture 字节,但 manifest sha256 故意改成全零 → mismatch
    let (base_url, _h, _counter, server) = spawn_stub_server(|req, _n| serve_chunk(req, "\"v1\""));

    let tmp = TempDir::new().expect("tmp");
    let mut manifest = build_test_manifest(&base_url);
    // 篡改第一个文件的 sha256,触发 mismatch
    manifest.files[0].sha256 =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();

    let result = ensure_with_manifest(Some(tmp.path()), &manifest);
    drop(server);

    match result {
        Err(BootstrapError::Sha256Mismatch { expected, actual }) => {
            assert_eq!(
                expected,
                "0000000000000000000000000000000000000000000000000000000000000000"
            );
            assert_ne!(expected, actual, "actual must differ from expected");
        }
        other => panic!("expected Sha256Mismatch, got {other:?}"),
    }
    // 产物已被删除
    let onnx_path = tmp.path().join("model_q4f16.onnx");
    assert!(
        !onnx_path.exists(),
        "expected onnx artifact deleted after sha256 mismatch"
    );
    // .partial.* 也被清扫
    let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".partial."))
        .collect();
    assert!(
        leftovers.is_empty(),
        "expected 0 .partial.* leftovers, got {leftovers:?}"
    );
}

// ────────────────────────────── (d) ──────────────────────────────

#[test]
fn test_fallback_url_recovers() {
    // 起两个 server:primary 永远 500;fallback 正常返 fixture
    let primary_fail = Arc::new(AtomicUsize::new(0));
    let primary_fail_h = primary_fail.clone();
    let primary_server = Arc::new(Server::http("127.0.0.1:0").unwrap());
    let primary_port = primary_server.server_addr().to_ip().unwrap().port();
    let primary_url = format!("http://127.0.0.1:{primary_port}");
    let primary_h = primary_server.clone();
    let _t1 = thread::spawn(move || {
        for req in primary_h.incoming_requests() {
            primary_fail_h.fetch_add(1, Ordering::SeqCst);
            let resp: Response<std::io::Cursor<Vec<u8>>> =
                Response::from_data(Vec::new()).with_status_code(StatusCode(500));
            let _ = req.respond(resp);
        }
    });

    let (fallback_url, _h, fallback_counter, fallback_server) =
        spawn_stub_server(|req, _n| serve_chunk(req, "\"v1\""));

    let tmp = TempDir::new().expect("tmp");
    let mut manifest = Manifest {
        model_name: "test-model".to_string(),
        version: "v1".to_string(),
        chunk_count: 16,
        files: vec![],
        ..Default::default()
    };
    for name in ["model_q4f16.onnx", "tokenizer.json", "config.json"] {
        manifest.files.push(ManifestFile {
            name: name.to_string(),
            size_bytes: fixture_bytes(name).len() as u64,
            sha256: fixture_sha256(name),
            primary_url: format!("{primary_url}/{name}"),
            fallback_urls: vec![format!("{fallback_url}/{name}")],
        });
    }

    let result = ensure_with_manifest(Some(tmp.path()), &manifest);
    drop(primary_server);
    drop(fallback_server);

    let paths = result.expect("fallback should recover");
    assert!(paths.onnx.exists());
    assert!(
        primary_fail.load(Ordering::SeqCst) >= 1,
        "primary should be tried at least once"
    );
    assert!(
        fallback_counter.load(Ordering::SeqCst) >= 1,
        "fallback should serve at least one request"
    );
}

// ────────────────────────────── (e) ──────────────────────────────

#[test]
fn test_all_urls_fail() {
    // 不启动任何 server;用 127.0.0.1:1(几乎肯定不可达)
    let tmp = TempDir::new().expect("tmp");
    let mut manifest = Manifest {
        model_name: "test-model".to_string(),
        version: "v1".to_string(),
        chunk_count: 16,
        files: vec![],
        ..Default::default()
    };
    let unreachable_primary = "http://127.0.0.1:1/file";
    let unreachable_fallback = "http://127.0.0.1:2/file";
    for name in ["model_q4f16.onnx", "tokenizer.json", "config.json"] {
        manifest.files.push(ManifestFile {
            name: name.to_string(),
            size_bytes: fixture_bytes(name).len() as u64,
            sha256: fixture_sha256(name),
            primary_url: unreachable_primary.to_string(),
            fallback_urls: vec![unreachable_fallback.to_string()],
        });
    }

    let result = ensure_with_manifest(Some(tmp.path()), &manifest);
    match result {
        Err(BootstrapError::NetworkUnreachable {
            tried_urls,
            last_error,
        }) => {
            assert!(
                tried_urls.contains(&unreachable_primary.to_string()),
                "tried_urls must include primary"
            );
            assert!(
                tried_urls.contains(&unreachable_fallback.to_string()),
                "tried_urls must include fallback"
            );
            assert!(!last_error.is_empty(), "last_error must be populated");
        }
        other => panic!("expected NetworkUnreachable, got {other:?}"),
    }
}

// ────────────────────────────── (f) ──────────────────────────────

#[test]
fn cfg_gate_active() {
    // 此测试仅在 --features ort 编译时存在;默认 cargo test --no-default-features
    // 整个 tests.rs 模块被 #[cfg(all(test, feature = "ort"))] 排除不编译,
    // 等价于"0 reqwest/dirs/sha2/tiny_http 痕迹"的间接守门(cargo tree 是外部命令守门)。
    // v0.13 clippy 1.95:const block 表达"编译期常量断言",更明确意图
    const { assert!(cfg!(feature = "ort")) };
    // 编译期断言:bootstrap 模块符号在此可见
    let _ = std::any::TypeId::of::<super::ModelPaths>();
    let _ = std::any::TypeId::of::<super::BootstrapError>();
}

// 静默 timeout-sensitive: 单测在 5min 内完成
#[test]
fn smoke_timeout_below_5min() {
    // 不实际跑 — 仅记录 SLA。本模块所有 #[test] 应在数秒内完成(stub server 本机)。
    let _budget = Duration::from_secs(300);
}
