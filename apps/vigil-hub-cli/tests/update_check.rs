//! P0-1 每日更新检查(再评估 §9 D1)—— 走生产路径(`spawn_daily_with`)对着本地一次性 HTTP
//! 服务器验证隐私不变量:只发一次、只带平台 + 版本、无多余头、24h 节流、三种关闭方式都零出站;
//! 外加源码守门:`hook` 路径永不引用更新检查。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use vigil_hub_cli::i18n::Lang;
use vigil_hub_cli::update_check::{spawn_daily_with, VERSION};
use vigil_update_check::{
    current_platform_key, ENV_DISABLE, ENV_DO_NOT_TRACK, ENV_ENDPOINT, LAST_ATTEMPT_FILE,
};

/// 一次抓到的请求头(整块原文 + 拆好的请求行与头名)。
struct Hit {
    request_line: String,
    headers: HashMap<String, String>,
}

/// 起一个只会回固定清单的 HTTP/1.1 服务器;每个请求经 channel 送出。
fn manifest_server(manifest: &'static str) -> (String, mpsc::Receiver<Hit>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let base = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
            let mut raw = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        raw.extend_from_slice(&buf[..n]);
                        if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                }
            }
            let head = String::from_utf8_lossy(&raw).to_string();
            let mut lines = head.split("\r\n");
            let request_line = lines.next().unwrap_or_default().to_string();
            let headers = lines
                .take_while(|l| !l.is_empty())
                .filter_map(|l| l.split_once(':'))
                .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
                .collect();
            let body = manifest.as_bytes();
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(body);
            let _ = s.flush();
            let _ = tx.send(Hit {
                request_line,
                headers,
            });
        }
    });
    (base, rx)
}

fn env_with(base: &str, extra: &[(&str, &str)]) -> HashMap<String, String> {
    let mut m: HashMap<String, String> = extra
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    m.insert(ENV_ENDPOINT.to_string(), base.to_string());
    m
}

fn files_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

const MANIFEST: &str = r#"{"version":"0.0.1","notes":"test","platforms":{}}"#;

#[test]
fn serve_path_pings_once_a_day_with_platform_and_version_only() {
    let (base, rx) = manifest_server(MANIFEST);
    let state = tempfile::tempdir().unwrap();
    let env = env_with(&base, &[]);
    let lookup = |k: &str| env.get(k).cloned();

    let handle = spawn_daily_with(Lang::En, &lookup, Some(state.path()))
        .expect("first run with nothing disabled must fetch");
    handle
        .join()
        .expect("background fetch thread must not panic");

    let hit = rx
        .recv_timeout(Duration::from_secs(15))
        .expect("exactly one request must arrive");
    let expected_path = format!(
        "/desktop-updates/{}/{}.json",
        current_platform_key(),
        VERSION
    );
    assert_eq!(hit.request_line, format!("GET {expected_path} HTTP/1.1"));
    assert!(!hit.request_line.contains('?'), "no query string");
    assert_eq!(
        hit.headers.get("user-agent").map(String::as_str),
        Some(format!("vigil-hub/{VERSION}").as_str())
    );
    // 除 HTTP 客户端的基本头外不得出现任何自定义头(没有标识可携带的通道)。
    let allowed = [
        "host",
        "user-agent",
        "accept",
        "accept-encoding",
        "connection",
    ];
    for name in hit.headers.keys() {
        assert!(
            allowed.contains(&name.as_str()),
            "unexpected request header `{name}` — the ping must carry nothing but UA"
        );
    }
    assert!(
        rx.recv_timeout(Duration::from_millis(500)).is_err(),
        "must be a single request"
    );

    // 唯一落盘 = 节流文件,内容是一个整数
    assert_eq!(files_in(state.path()), vec![LAST_ATTEMPT_FILE.to_string()]);
    let stamp = std::fs::read_to_string(state.path().join(LAST_ATTEMPT_FILE)).unwrap();
    stamp.trim().parse::<u64>().expect("unix seconds");

    // 同一天再启动 → 节流,零请求
    assert!(spawn_daily_with(Lang::Zh, &lookup, Some(state.path())).is_none());
    assert!(rx.recv_timeout(Duration::from_millis(500)).is_err());
}

#[test]
fn every_kill_switch_means_zero_bytes_and_zero_files() {
    let (base, rx) = manifest_server(MANIFEST);
    for switch in [(ENV_DISABLE, "1"), (ENV_DO_NOT_TRACK, "true")] {
        let state = tempfile::tempdir().unwrap();
        let env = env_with(&base, &[switch]);
        let lookup = |k: &str| env.get(k).cloned();
        assert!(
            spawn_daily_with(Lang::En, &lookup, Some(state.path())).is_none(),
            "{} must disable",
            switch.0
        );
        assert!(
            files_in(state.path()).is_empty(),
            "{} must not write",
            switch.0
        );
    }
    // 用户显式 `version-ping off`(标记文件)
    let state = tempfile::tempdir().unwrap();
    vigil_update_check::set_enabled(state.path(), false).unwrap();
    let env = env_with(&base, &[]);
    let lookup = |k: &str| env.get(k).cloned();
    assert!(spawn_daily_with(Lang::En, &lookup, Some(state.path())).is_none());
    // 无状态目录 → 无法节流 → 不发
    assert!(spawn_daily_with(Lang::En, &lookup, None).is_none());
    assert!(
        rx.recv_timeout(Duration::from_millis(500)).is_err(),
        "no kill-switch path may reach the network"
    );
}

/// 源码守门:短进程 / 安全决策模块永不引用更新检查;长驻入口两处都已接线。
#[test]
fn hook_path_never_references_update_check_and_long_running_entries_do() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for quiet in ["hook.rs", "command_guard.rs", "posture.rs"] {
        let src = std::fs::read_to_string(root.join(quiet)).unwrap();
        assert!(
            !src.contains("update_check"),
            "{quiet} must never touch the update check (per-tool-call path is offline by contract)"
        );
    }
    for (wired, needle) in [
        ("main.rs", "update_check::spawn_daily(lang)"),
        ("daemon/lifecycle.rs", "update_check::spawn_daily(lang)"),
    ] {
        let src = std::fs::read_to_string(root.join(wired)).unwrap();
        assert!(
            src.contains(needle),
            "{wired} must wire the daily update check (`{needle}`)"
        );
    }
}
