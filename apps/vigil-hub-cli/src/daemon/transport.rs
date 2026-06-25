//! daemon 本地 socket transport(ADR 0024 §4/§5)。`interprocess` LocalSocket(Unix UDS /
//! Windows named pipe)+ **R2** 总读截止 + 单实例(bind 失败守门)。
//!
//! - **单实例** = OS bind 失败守门([`bind`] 已有 listener → Err;一名一 listener)。
//! - **R2**:整段查询(连接 + 握手 + 请求 + 读响应)跑在工作线程,主线程 `recv_timeout` 总截止;
//!   超时 → None → 硬指纹(防慢 / 挤牙膏 daemon 楔死每次工具调用)。
//! - **R1**(peer-credential):连接后核对**对端(server)进程 PID == `daemon.json.pid`**,经
//!   interprocess **原生** `peer_creds().pid()`(其内部封装平台 unsafe;故本 crate 仍 forbid unsafe,
//!   无需自有 FFI)。防同用户冒充 daemon(token 自洽不够 —— 冒充者伪造不了真 daemon 的 PID)。
//!   取不到 / 不符 → fail-closed → 硬指纹。
//! - **R6**(socket 权限硬化,后续):Unix 0600 / Windows pipe DACL。

use std::sync::mpsc;
use std::time::Duration;
use std::{io, thread};

use interprocess::local_socket::prelude::*;
use interprocess::local_socket::{GenericNamespaced, ListenerOptions, Stream as LocalStream};

use super::client::{daemon_info_path, exchange, read_daemon_info, DaemonInfo};
use super::protocol::{Request, Response};
use super::server::{handle_connection, DaemonCaps};

/// 默认 daemon socket 名(namespaced:Unix 抽象 UDS / Windows `\\.\pipe\`)。
pub fn default_socket_name() -> String {
    "vigil-daemon.sock".to_string()
}

/// 绑定 socket(server)。**单实例**:已有同名 listener → `Err`(OS 强制一名一 listener)。
pub fn bind(socket_name: &str) -> io::Result<interprocess::local_socket::Listener> {
    let name = socket_name.to_ns_name::<GenericNamespaced>()?;
    ListenerOptions::new().name(name).create_sync()
}

/// server accept 循环:每连接 spawn [`handle_connection`](thread-per-conn,简化;bounded 后续)。
pub fn serve(listener: interprocess::local_socket::Listener, caps: DaemonCaps) {
    for conn in listener.incoming() {
        let mut stream = match conn {
            Ok(s) => s,
            Err(_) => continue,
        };
        let caps = caps.clone();
        thread::spawn(move || handle_connection(&mut stream, &caps));
    }
}

/// **R1 peer-credential**:取连接对端(server)进程 PID,经 interprocess **原生** `peer_creds()`
/// (其内部封装平台 unsafe `SO_PEERCRED` / `GetNamedPipeServerProcessId`;故本 crate 仍满足
/// `forbid(unsafe_code)`,无需自有 FFI)。取不到 → `None`(上游 fail-closed)。
// interprocess `Pid` 平台相异:Windows = `u32`(`try_from` 是 no-op),Unix = `pid_t`(i32,需转 +
// 滤负)。allow 让单一跨平台函数在两侧都正确(Windows 上的"多余转换"被刻意接受)。
#[allow(clippy::useless_conversion)]
fn peer_pid(stream: &LocalStream) -> Option<u32> {
    let pid = stream.peer_creds().ok()?.pid()?;
    u32::try_from(pid).ok()
}

/// 连接 socket(**无 R1**)。供 transport 机制测试 + R1 落地后内部复用。
fn connect_raw(socket_name: &str) -> Option<LocalStream> {
    let name = socket_name.to_ns_name::<GenericNamespaced>().ok()?;
    LocalStream::connect(name).ok()
}

/// 连接 + **R1** 校验:对端 server pid 必须 == `expected_pid`(daemon.json.pid)。
/// 取不到对端 pid(无凭据 / `peer_creds` 失败)→ 整体 fail-closed `None`(绝不连未经身份核验的 daemon)。
fn connect_and_verify(socket_name: &str, expected_pid: u32) -> Option<LocalStream> {
    let stream = connect_raw(socket_name)?;
    let pid = peer_pid(&stream)?;
    if pid != expected_pid {
        return None;
    }
    Some(stream)
}

/// 用一个 [`DaemonInfo`] 跑一次查询(连接其 socket_path + R1 核 pid + exchange)。fail-closed。
fn query_with(info: &DaemonInfo, request: &Request) -> Option<Response> {
    let mut stream = connect_and_verify(&info.socket_path, info.pid)?;
    exchange(&mut stream, &info.token, request)
}

/// hook 公共入口:read daemon.json → connect + R1 → exchange,**整体 R2 总截止**
/// (工作线程 + `recv_timeout`;超时 → `None` → 硬指纹)。任何环节失败均 fail-closed。
/// **消费方(已 live)**:hook PostToolUse ML PII 增强(engine=ml/auto)+ `vigil-hub daemon status`。
pub fn query_daemon(request: Request, deadline: Duration) -> Option<Response> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let result = (|| {
            let info = read_daemon_info(&daemon_info_path()?)?;
            query_with(&info, &request)
        })();
        let _ = tx.send(result);
    });
    // R2:整段有界;超时(RecvTimeoutError)→ None。
    rx.recv_timeout(deadline).ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::super::client::DaemonInfo;
    use super::super::protocol::{Request, Response, PROTOCOL_VERSION};
    use super::super::server::DaemonCaps;
    use super::{bind, connect_and_verify, query_with, serve};

    fn unique_sock(tag: &str) -> String {
        // 唯一名(进程 id + tag):防与真 daemon / 并行测试碰撞;**不碰真 daemon.json**。
        format!("vigil-itest-{}-{}.sock", tag, std::process::id())
    }

    fn spawn_daemon(sock: &str, token: &str, up: u64) {
        let caps = DaemonCaps {
            token: token.to_string(),
            scanner: None,
            ledger: None,
            #[cfg(feature = "ort")]
            injection: None,
            pii_loaded: false,
            inj_loaded: false,
            uptime_secs: up,
        };
        let listener = bind(sock).unwrap();
        std::thread::spawn(move || serve(listener, caps));
    }

    /// 同进程 daemon 的 DaemonInfo:`pid = 本进程` → R1 匹配(对端 server pid 即本进程)。
    fn info_for(sock: &str, token: &str) -> DaemonInfo {
        DaemonInfo {
            pid: std::process::id(),
            socket_path: sock.to_string(),
            token: token.to_string(),
            protocol_version: PROTOCOL_VERSION,
            pii_loaded: false,
            inj_loaded: false,
        }
    }

    #[test]
    fn end_to_end_query_with_real_socket_r1_and_exchange() {
        // 真 socket 全路径:connect + **R1**(同进程 server pid 匹配)+ 握手 + Status dispatch。
        let sock = unique_sock("e2e");
        spawn_daemon(&sock, "itest-token", 1);
        let resp = query_with(&info_for(&sock, "itest-token"), &Request::Status);
        assert!(
            matches!(resp, Some(Response::Status { uptime_secs: 1, .. })),
            "真 socket 全路径 Status 往返应成功,got {resp:?}"
        );
    }

    #[test]
    fn r1_accepts_same_process_server_pid() {
        // R1:对端(同进程 server)pid == expected → connect_and_verify 返 Some。
        let sock = unique_sock("r1ok");
        spawn_daemon(&sock, "t", 0);
        assert!(
            connect_and_verify(&sock, std::process::id()).is_some(),
            "R1:对端 server pid == 本进程 pid → 通过"
        );
    }

    #[test]
    fn r1_rejects_wrong_expected_pid() {
        // R1:对端真实 pid = 本进程;expected 设不可能值 → fail-closed None(防冒充 daemon)。
        let sock = unique_sock("r1bad");
        spawn_daemon(&sock, "t", 0);
        assert!(
            connect_and_verify(&sock, u32::MAX).is_none(),
            "R1:对端 pid != expected_pid → None(防冒充)"
        );
    }

    #[test]
    fn handshake_bad_token_over_real_socket_rejected() {
        // R1 通过(同进程)但 token 错 → 服务端回 Error → query_with 返 None(fail-closed)。
        let sock = unique_sock("badtok");
        spawn_daemon(&sock, "right-token", 0);
        assert!(
            query_with(&info_for(&sock, "wrong-token"), &Request::Status).is_none(),
            "错 token → 服务端 Error → None"
        );
    }
}
