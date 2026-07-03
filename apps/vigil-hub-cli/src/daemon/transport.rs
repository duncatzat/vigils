//! daemon 本地 socket transport(ADR 0024 §4/§5)。`interprocess` LocalSocket(Unix UDS /
//! Windows named pipe)+ **R2** 总读截止 + 单实例(bind 失败守门)。
//!
//! - **单实例** = OS bind 失败守门([`bind`] 已有 listener → Err;一名一 listener)。
//! - **R2**:整段查询(连接 + 握手 + 请求 + 读响应)跑在工作线程,主线程 `recv_timeout` 总截止;
//!   超时 → None → 硬指纹(防慢 / 挤牙膏 daemon 楔死每次工具调用)。
//! - **R1**(peer-credential):**Linux/Windows** 连接后核对**对端(server)进程 PID ==
//!   `daemon.json.pid`**(经 interprocess 原生 `peer_creds().pid()`)。**macOS** 上
//!   `peer_creds().pid()` 恒 None(无 `SO_PEERCRED`)→ 退化为 **euid 校验**(对端必须以**本用户**
//!   身份运行)。注意:macOS 为 **euid-only,不作 pid 绑定**,故不主张 pid-reuse 保护——cross-user
//!   由用户私有目录权限排除,同用户冒充由 token + 单实例 bind 兜底;且**永不 fail-open**(硬指纹
//!   底座在 hook 内先跑,冒充/缺失至多抑制 ML recall)。取不到 / 不符 → fail-closed → 硬指纹。
//! - **R6**(socket 权限硬化,后续):Unix 0600 / Windows pipe DACL。

use std::sync::mpsc;
use std::time::Duration;
use std::{io, thread};

use interprocess::local_socket::prelude::*;
#[cfg(target_os = "macos")]
use interprocess::local_socket::GenericFilePath;
#[cfg(not(target_os = "macos"))]
use interprocess::local_socket::GenericNamespaced;
use interprocess::local_socket::{ListenerOptions, Stream as LocalStream};

use super::client::{daemon_info_path, exchange, read_daemon_info, DaemonInfo};
use super::protocol::{Request, Response};
use super::server::{handle_connection, DaemonCaps};

/// 默认 daemon socket 标识。
///
/// - **Linux**:`GenericNamespaced` → 抽象 UDS(`\0` 前缀,内核在进程死亡时自动回收,无 stale)。
/// - **Windows**:`GenericNamespaced` → `\\.\pipe\vigil-daemon.sock`(named pipe,句柄关即清)。
/// - **macOS**:**无抽象命名空间** —— namespaced 会落到世界可读的 `/tmp` 文件 socket、非干净
///   退出不回收(EADDRINUSE 永久卡死重启)、且 `peer_creds().pid()` 恒 None(R1 失效)。故改用
///   **用户私有数据目录下的显式文件 socket**(与 daemon.json 同目录;cross-user 由目录权限排除),
///   配合 bind 前 stale 清理 + euid 版 R1(见 [`bind`] / [`connect_and_verify`])。
pub fn default_socket_name() -> String {
    // `VIGIL_DAEMON_SOCKET`(非空)显式覆盖:测试确定性 + 企业网络/深 HOME(默认路径撑爆
    // macOS `sun_path` 104 时,见 [`bind`] 守门)的逃生口。否则按平台默认。
    resolve_socket_name(std::env::var("VIGIL_DAEMON_SOCKET").ok().as_deref())
}

/// socket 名解析:显式覆盖(非空)优先,否则平台默认。抽纯函数以单测覆盖逻辑(免动全局 env)。
fn resolve_socket_name(explicit: Option<&str>) -> String {
    match explicit {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => platform_default_socket_name(),
    }
}

/// 平台默认 socket 标识(无 env 覆盖时)。见 [`default_socket_name`] 的平台行为说明。
fn platform_default_socket_name() -> String {
    #[cfg(target_os = "macos")]
    {
        dirs::data_local_dir()
            .map(|dir| {
                dir.join("Vigil")
                    .join("vigil-daemon.sock")
                    .to_string_lossy()
                    .into_owned()
            })
            .unwrap_or_else(|| {
                // 回退也用**每用户私有** temp(macOS `$TMPDIR` = /var/folders/.../T,0700),
                // 绝不用世界可写的 `/tmp`(防跨用户 squat / stale 不清 —— 正是本修复要消灭的类)。
                std::env::temp_dir()
                    .join("vigil-daemon.sock")
                    .to_string_lossy()
                    .into_owned()
            })
    }
    #[cfg(not(target_os = "macos"))]
    {
        "vigil-daemon.sock".to_string()
    }
}

/// 绑定 socket(server)。**单实例**:已有**存活**同名 listener → `Err`(OS 强制一名一 listener)。
///
/// macOS:文件 socket 在非干净退出(kill/crash,Drop 不跑)后残留 → 旧版 namespaced 永久
/// `EADDRINUSE`。此处 bind 前 **probe-then-unlink**:文件在但连不通(stale)→ 删之重绑;
/// 连得通(真有存活 daemon)→ 保留 → `create_sync` 返 `AddrInUse` → 单实例守门不破。
pub fn bind(socket_name: &str) -> io::Result<interprocess::local_socket::Listener> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::PermissionsExt;
        // macOS `sockaddr_un.sun_path` = 104(含 NUL):深 HOME(企业网络 home / 自定义 data dir)
        // 下 socket 路径可能超限,libc 仅给晦涩 "exceeds capacity"。提前用可操作错误拒绝并指向
        // `VIGIL_DAEMON_SOCKET` 逃生口(否则 daemon 静默启动失败 → ML 防护降级硬指纹)。
        check_macos_sun_path_len(socket_name)?;
        // bind 早于 write_daemon_info(其会建目录)→ 先确保父目录在并 **0700**(仅 owner;
        // 不把 `~/Library` 默认权限当唯一屏障 —— 防同主机跨用户连接,且回退 temp 路径下也成立)。
        if let Some(parent) = std::path::Path::new(socket_name).parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }
        reclaim_stale_socket(socket_name);
        let name = socket_name.to_fs_name::<GenericFilePath>()?;
        let listener = ListenerOptions::new().name(name).create_sync()?;
        // R6:socket 节点 0600(仅 owner 可连),目录权限之外再加一层。
        let _ = std::fs::set_permissions(socket_name, std::fs::Permissions::from_mode(0o600));
        Ok(listener)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let name = socket_name.to_ns_name::<GenericNamespaced>()?;
        ListenerOptions::new().name(name).create_sync()
    }
}

/// macOS:bind 前清理 stale 文件 socket。存活 daemon(连得通)→ 不动,让 `create_sync` 以
/// `AddrInUse` 守单实例;连不通(unclean exit 残留)→ unlink,使重绑成功。
#[cfg(target_os = "macos")]
fn reclaim_stale_socket(path: &str) {
    if !std::path::Path::new(path).exists() {
        return;
    }
    // 存活探测带短重试:活 daemon(即便 accept backlog 瞬时满)会在几 ms 内接受连接,真 stale
    // socket 永不接受。重试收窄 false-stale 窗口——瞬时不可达 + 并发 daemon start 竞态(给对端
    // create_sync 完成的时间)——避免误删存活 daemon 的 socket(codex/hostile 双审 item 2)。
    for _ in 0..5 {
        if connect_raw(path).is_some() {
            return; // 活 daemon —— 保留,单实例由 create_sync 的 AddrInUse 守门
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let _ = std::fs::remove_file(path); // 连续探测均失败 → 确属 stale → 删之以便重绑
}

/// macOS:socket 路径 byte 长度须 < `sockaddr_un.sun_path` 容量(104,含末尾 NUL)。超限 →
/// 可操作 `InvalidInput`(指向 `VIGIL_DAEMON_SOCKET`),而非 libc 晦涩错误 / 静默 bind 失败。
#[cfg(target_os = "macos")]
fn check_macos_sun_path_len(socket_name: &str) -> io::Result<()> {
    const SUN_PATH_MAX: usize = 104; // sizeof(sockaddr_un.sun_path),含末尾 NUL
    if socket_name.len() >= SUN_PATH_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "daemon socket path is {} bytes, exceeds macOS sun_path capacity ({}); \
                 set VIGIL_DAEMON_SOCKET to a shorter path",
                socket_name.len(),
                SUN_PATH_MAX
            ),
        ));
    }
    Ok(())
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
// macOS 上 `peer_creds().pid()` 恒 None(无 SO_PEERCRED)→ pid 版 R1 不适用,仅非 macOS 编译。
#[cfg(not(target_os = "macos"))]
#[allow(clippy::useless_conversion)]
fn peer_pid(stream: &LocalStream) -> Option<u32> {
    let pid = stream.peer_creds().ok()?.pid()?;
    u32::try_from(pid).ok()
}

/// 连接 socket(**无 R1**)。供 transport 机制测试 + R1 落地后内部复用。
fn connect_raw(socket_name: &str) -> Option<LocalStream> {
    #[cfg(target_os = "macos")]
    let name = socket_name.to_fs_name::<GenericFilePath>().ok()?;
    #[cfg(not(target_os = "macos"))]
    let name = socket_name.to_ns_name::<GenericNamespaced>().ok()?;
    LocalStream::connect(name).ok()
}

/// 连接 + **R1** 校验:对端 server pid 必须 == `expected_pid`(daemon.json.pid)。
/// 取不到对端 pid(无凭据 / `peer_creds` 失败)→ 整体 fail-closed `None`(绝不连未经身份核验的 daemon)。
fn connect_and_verify(socket_name: &str, expected_pid: u32) -> Option<LocalStream> {
    let stream = connect_raw(socket_name)?;
    #[cfg(not(target_os = "macos"))]
    {
        // Linux/Windows:对端 server pid 必须 == daemon.json.pid。
        if peer_pid(&stream)? != expected_pid {
            return None;
        }
    }
    #[cfg(target_os = "macos")]
    {
        // macOS:peer_creds().pid() 恒 None(无 SO_PEERCRED);euid 可用。socket + daemon.json
        // 均在用户私有目录(cross-user 由目录权限排除)→ R1 等价检查 = 对端 server 必须以**本
        // 用户**身份运行(euid 相等);pid 在此无意义。
        let _ = expected_pid;
        if !peer_is_current_user(&stream) {
            return None;
        }
    }
    Some(stream)
}

/// macOS R1:对端(server)euid == 本进程 euid(都是当前用户)。取不到 → fail-closed。
/// `rustix::process::geteuid` 安全封装(本 crate 仍 `forbid(unsafe_code)`)。
#[cfg(target_os = "macos")]
fn peer_is_current_user(stream: &LocalStream) -> bool {
    match stream.peer_creds().ok().and_then(|c| c.euid()) {
        Some(peer_euid) => peer_euid == rustix::process::geteuid().as_raw(),
        None => false,
    }
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
    #[cfg(target_os = "macos")]
    use super::check_macos_sun_path_len;
    use super::{
        bind, connect_and_verify, platform_default_socket_name, query_with, resolve_socket_name,
        serve,
    };

    fn unique_sock(tag: &str) -> String {
        // 唯一名(进程 id + tag):防与真 daemon / 并行测试碰撞;**不碰真 daemon.json**。
        // macOS 用 GenericFilePath(文件路径)→ 落 temp 绝对路径,避免污染 CWD。
        #[cfg(target_os = "macos")]
        {
            std::env::temp_dir()
                .join(format!("vigil-itest-{}-{}.sock", tag, std::process::id()))
                .to_string_lossy()
                .into_owned()
        }
        #[cfg(not(target_os = "macos"))]
        {
            format!("vigil-itest-{}-{}.sock", tag, std::process::id())
        }
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
            started: std::time::Instant::now() - std::time::Duration::from_secs(up),
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

    // pid 版 R1 仅非 macOS;macOS 走 euid(同进程必同 euid,无法用 pid 构造拒绝用例)。
    #[cfg(not(target_os = "macos"))]
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

    #[test]
    fn explicit_socket_override_is_honored() {
        // 非空 VIGIL_DAEMON_SOCKET 字面值优先(测试确定性 + 企业深 HOME 逃生口)。
        assert_eq!(resolve_socket_name(Some("/short/d.sock")), "/short/d.sock");
    }

    #[test]
    fn empty_or_absent_override_falls_back_to_platform_default() {
        // 空串 / 未设 → 平台默认(不让空 env 顶掉真实路径)。
        assert_eq!(
            resolve_socket_name(Some("")),
            platform_default_socket_name()
        );
        assert_eq!(resolve_socket_name(None), platform_default_socket_name());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_overlong_socket_path_rejected_with_actionable_error() {
        // 超 sun_path(104)→ 可操作 InvalidInput,文案含逃生口 env 名;典型生产路径放行。
        let long = format!("/{}", "a".repeat(110));
        let err = check_macos_sun_path_len(&long).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("VIGIL_DAEMON_SOCKET"));
        check_macos_sun_path_len("/Users/u/Library/Application Support/Vigil/vigil-daemon.sock")
            .unwrap();
    }
}
