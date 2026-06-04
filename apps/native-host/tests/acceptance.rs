//! I09a §12.3 I09 四条验收 + framing / audit 红线集成测试。
//!
//! 不 spawn 真子进程:用 `Cursor<Vec<u8>>` 注入 stdin / 收集 stdout,`run()`
//! 是 lib 公开 API。

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::err_expect,
    clippy::panic
)]

use std::io::Cursor;

use vigil_audit::Ledger;
use vigil_browser::{
    BrowserAction, BrowserCheckRequest, BrowserCheckResponse, BrowserErrorFrame, BrowserEventKind,
    FindingKind,
};

/// 编码一条 request frame。
fn encode_request(req: &BrowserCheckRequest) -> Vec<u8> {
    let body = serde_json::to_vec(req).unwrap();
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(&body);
    frame
}

/// 从 stdout 缓冲读**所有**响应 frame。
fn decode_responses(buf: &[u8]) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + 4 <= buf.len() {
        let len = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
        pos += 4;
        let end = pos + len as usize;
        if end > buf.len() {
            break;
        }
        out.push(serde_json::from_slice(&buf[pos..end]).unwrap());
        pos = end;
    }
    out
}

fn run_once(req: &BrowserCheckRequest) -> (Ledger, String, serde_json::Value) {
    let ledger = Ledger::open_in_memory().unwrap();
    let sid = ledger.start_session("browser_host", None).unwrap();
    let input = encode_request(req);
    let mut stdin = Cursor::new(input);
    let mut stdout: Vec<u8> = Vec::new();
    vigil_native_host::run(&mut stdin, &mut stdout, &ledger, &sid).unwrap();
    let frames = decode_responses(&stdout);
    assert_eq!(frames.len(), 1, "每个 request 应产一个 frame");
    (ledger, sid, frames.into_iter().next().unwrap())
}

fn make_req(text: &str, origin: &str) -> BrowserCheckRequest {
    BrowserCheckRequest {
        request_id: "aa000000-0000-0000-0000-000000000001".into(),
        origin: origin.into(),
        event_kind: BrowserEventKind::Paste,
        text: text.into(),
    }
}

fn make_input_req(text: &str, origin: &str) -> BrowserCheckRequest {
    BrowserCheckRequest {
        request_id: "aa000000-0000-0000-0000-000000000002".into(),
        origin: origin.into(),
        event_kind: BrowserEventKind::Input,
        text: text.into(),
    }
}

/// §12.3 I09-1:GitHub token paste → Redact(有 finding + 有 redacted_text)
#[test]
fn i09_github_token_triggers_redact() {
    let req = make_req(
        "token = ghp_1234567890abcdef1234567890abcdef12345678",
        "https://chatgpt.com",
    );
    let (_l, _sid, v) = run_once(&req);
    let resp: BrowserCheckResponse = serde_json::from_value(v).unwrap();
    assert_eq!(resp.action, BrowserAction::Redact);
    assert!(resp.findings.contains(&FindingKind::GithubToken));
    let r = resp.redacted_text.unwrap();
    assert!(!r.contains("ghp_1234567890abcdef1234567890abcdef12345678"));
}

/// §12.3 I09-2:private key paste → Block
#[test]
fn i09_private_key_triggers_block() {
    let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----";
    let req = make_req(text, "https://claude.ai");
    let (_l, _sid, v) = run_once(&req);
    let resp: BrowserCheckResponse = serde_json::from_value(v).unwrap();
    assert_eq!(resp.action, BrowserAction::Block);
    assert!(resp.findings.contains(&FindingKind::PemPrivateKey));
    assert!(resp.redacted_text.is_none());
}

/// §12.3 I09-3:普通文本 → Allow,无 finding
#[test]
fn i09_normal_paste_allows() {
    let req = make_req(
        "Hello, can you help me write a poem about autumn?",
        "https://chatgpt.com",
    );
    let (_l, _sid, v) = run_once(&req);
    let resp: BrowserCheckResponse = serde_json::from_value(v).unwrap();
    assert_eq!(resp.action, BrowserAction::Allow);
    assert!(resp.findings.is_empty());
    assert!(resp.redacted_text.is_none());
}

#[test]
fn i09_manual_input_token_assignment_triggers_redact_and_input_audit() {
    let req = make_input_req("token=sadqwdzcfqdqdwqdqdq", "https://chatgpt.com");
    let (ledger, sid, v) = run_once(&req);
    let resp: BrowserCheckResponse = serde_json::from_value(v).unwrap();
    assert_eq!(resp.action, BrowserAction::Redact);
    assert!(resp.findings.contains(&FindingKind::EnvAssignment));
    assert_eq!(
        resp.redacted_text.as_deref(),
        Some("[REDACTED env_assignment]")
    );

    let events = ledger.replay_session(&sid).unwrap();
    assert!(
        events
            .iter()
            .any(|e| e.event_type == "browser.input_checked"),
        "input 请求应写 browser.input_checked 审计事件"
    );
}

/// §12.3 I09-4:SENTINEL 注入原文,audit payload 和任一响应 JSON **都不含**原文
const SENTINEL: &str = "ghp_SENTINELZZZZZZZZ_12345678901234567890xy";

#[test]
fn i09_audit_payload_never_contains_raw_text() {
    let req = make_req(
        &format!("my token is {SENTINEL} do not leak"),
        "https://chatgpt.com",
    );
    let (ledger, sid, response_value) = run_once(&req);

    // response JSON 不得含 SENTINEL(redacted_text 应是占位符)
    let resp_s = serde_json::to_string(&response_value).unwrap();
    assert!(!resp_s.contains(SENTINEL), "SENTINEL 泄漏到响应: {resp_s}");

    // 扫 session 所有事件 payload + redacted_text
    let events = ledger.replay_session(&sid).unwrap();
    assert!(!events.is_empty(), "至少有一条 browser.paste_checked");
    for e in &events {
        let payload_s = serde_json::to_string(&e.payload).unwrap();
        assert!(
            !payload_s.contains(SENTINEL),
            "SENTINEL 泄漏到 event {}: {}",
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
}

/// §D7:chrome-extension:// origin 被 fail-closed 拒绝
#[test]
fn origin_scheme_denylist_returns_error_frame() {
    let req = make_req("anything", "chrome-extension://abc/");
    let (_l, _sid, v) = run_once(&req);
    // 不是 BrowserCheckResponse,是 error frame
    let ef: BrowserErrorFrame = serde_json::from_value(v).unwrap();
    assert_eq!(ef.error, vigil_browser::BrowserErrorCode::OriginDenied);
    assert_eq!(ef.request_id.as_deref(), Some(req.request_id.as_str()));
}

/// framing:写一个超长 length prefix,host 应回 too_large error frame 并继续等下一帧
#[test]
fn oversized_length_prefix_returns_too_large() {
    let ledger = Ledger::open_in_memory().unwrap();
    let sid = ledger.start_session("h", None).unwrap();
    let mut input = Vec::new();
    // length = 10 MB,远超上限 1 MB
    input.extend_from_slice(&(10u32 * 1024 * 1024).to_le_bytes());
    // 不写 payload(host 应直接 reject 不读 body)
    let mut stdin = Cursor::new(input);
    let mut stdout: Vec<u8> = Vec::new();
    vigil_native_host::run(&mut stdin, &mut stdout, &ledger, &sid).unwrap();
    let frames = decode_responses(&stdout);
    assert_eq!(frames.len(), 1);
    let ef: BrowserErrorFrame = serde_json::from_value(frames[0].clone()).unwrap();
    assert_eq!(ef.error, vigil_browser::BrowserErrorCode::TooLarge);
}

/// framing:bad JSON body → BadJson error frame
#[test]
fn bad_json_payload_returns_bad_json() {
    let ledger = Ledger::open_in_memory().unwrap();
    let sid = ledger.start_session("h", None).unwrap();
    let body = b"not a json";
    let mut input = Vec::new();
    input.extend_from_slice(&(body.len() as u32).to_le_bytes());
    input.extend_from_slice(body);
    let mut stdin = Cursor::new(input);
    let mut stdout: Vec<u8> = Vec::new();
    vigil_native_host::run(&mut stdin, &mut stdout, &ledger, &sid).unwrap();
    let frames = decode_responses(&stdout);
    assert_eq!(frames.len(), 1);
    let ef: BrowserErrorFrame = serde_json::from_value(frames[0].clone()).unwrap();
    assert_eq!(ef.error, vigil_browser::BrowserErrorCode::BadJson);
}

/// 多帧 roundtrip:连续 3 个 request 全部被正确处理
#[test]
fn multi_frame_sequence_roundtrip() {
    let ledger = Ledger::open_in_memory().unwrap();
    let sid = ledger.start_session("h", None).unwrap();
    let req1 = make_req("normal", "https://x.com");
    let req2 = make_req(
        "token ghp_1111111111111111111111111111111111111111",
        "https://y.com",
    );
    let req3 = make_req(
        "-----BEGIN RSA PRIVATE KEY-----\nz\n-----END RSA PRIVATE KEY-----",
        "https://z.com",
    );
    let mut input: Vec<u8> = Vec::new();
    input.extend(encode_request(&req1));
    input.extend(encode_request(&req2));
    input.extend(encode_request(&req3));
    let mut stdin = Cursor::new(input);
    let mut stdout: Vec<u8> = Vec::new();
    vigil_native_host::run(&mut stdin, &mut stdout, &ledger, &sid).unwrap();
    let frames = decode_responses(&stdout);
    assert_eq!(frames.len(), 3);
    let r1: BrowserCheckResponse = serde_json::from_value(frames[0].clone()).unwrap();
    let r2: BrowserCheckResponse = serde_json::from_value(frames[1].clone()).unwrap();
    let r3: BrowserCheckResponse = serde_json::from_value(frames[2].clone()).unwrap();
    assert_eq!(r1.action, BrowserAction::Allow);
    assert_eq!(r2.action, BrowserAction::Redact);
    assert_eq!(r3.action, BrowserAction::Block);
}
