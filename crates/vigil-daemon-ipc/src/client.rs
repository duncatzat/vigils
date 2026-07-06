//! hook 瘦客户端(ADR 0024 §5)。**零 ort**:hook 二进制无需模型,只经 IPC 向 daemon 查询。
//!
//! 本 slice = **可单测的 fail-closed 核心**:
//! - [`DaemonInfo`] / [`read_daemon_info`]:`daemon.json` 契约(fail-closed 解析 + 版本校验)。
//! - [`exchange`]:握手 → 校验 HelloOk 版本 → 请求 → 响应的**序列逻辑**;**任何** IO 错误 /
//!   版本不符 / 非 HelloOk / `Error` 响应 → `None`(调用方据此降级硬指纹,永不 fail-open)。
//!
//! 平台 + 安全层在 [`crate::transport`] 实现(`interprocess` 跨平台本地 socket):`connect_and_verify`
//! 做 **R1** peer-credential 校验(对端 server pid == `daemon.json.pid`,经 `peer_creds`)、`query_daemon`
//! 用工作线程 + `recv_timeout` 做 **R2** 总读截止。公共 `query_daemon` = `read_daemon_info` →
//! `connect_and_verify`(R1)→ [`exchange`],全程 fail-closed。

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::protocol::{read_frame, write_frame, Hello, Request, Response, PROTOCOL_VERSION};

/// `daemon.json` 契约(daemon 启动期原子写,`0600`;hook 同用户可读)。
///
/// 仅含**发现 + 鉴权**所需:`pid`(R1 peer-cred 核对)、`socket_path`(连接目标)、
/// `token`(per-launch 握手)、`protocol_version`(不符即 fail-closed)、能力位(GUI 展示)。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonInfo {
    /// daemon 进程 PID(R1:连接后核对对端 server pid 是否 == 此值)。
    pub pid: u32,
    /// UDS 路径 / named pipe 名(连接目标)。
    pub socket_path: String,
    /// per-launch token(握手出示)。
    pub token: String,
    /// daemon 协议版本(≠ [`PROTOCOL_VERSION`] → 当不可用)。
    pub protocol_version: u32,
    /// 隐私模型是否暖载就绪(GUI / 决策展示)。
    pub pii_loaded: bool,
    /// 注入分类器是否暖载就绪。
    pub inj_loaded: bool,
}

/// 规范 `daemon.json` 路径:`<data_local>/Vigil/daemon.json`(与 engine.json / posture.json 同目录)。
pub fn daemon_info_path() -> Option<PathBuf> {
    dirs::data_local_dir().map(|b| b.join("Vigil").join("daemon.json"))
}

/// 读 `daemon.json` → [`DaemonInfo`]。**fail-closed**:文件缺失 / 读失败 / 非法 JSON /
/// 版本不识别 → `None`(调用方当 daemon 不可用 → 硬指纹)。绝不因损坏配置静默连一个可疑 daemon。
pub fn read_daemon_info(path: &Path) -> Option<DaemonInfo> {
    let raw = std::fs::read_to_string(path).ok()?;
    let info: DaemonInfo = serde_json::from_str(&raw).ok()?;
    if info.protocol_version != PROTOCOL_VERSION {
        return None;
    }
    Some(info)
}

/// 原子写 `daemon.json`(daemon 启动期调用;tmp + `rename`,绝不留半截;父目录自建)。
/// Unix 下设 `0600`(仅 owner 可读 token —— R6 文件权限纪律,同 engine_config / posture)。
///
/// 注:`socket_path` 由 daemon 选定后写入;hook 读回连接。单实例由**绑定 socket 失败**守门
/// (OS 强制一名一 listener),不靠本文件做锁。
pub fn write_daemon_info(path: &Path, info: &DaemonInfo) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut rendered = serde_json::to_string_pretty(info).map_err(std::io::Error::other)?;
    rendered.push('\n');

    let tmp = {
        let mut s = path.as_os_str().to_os_string();
        s.push(".vigil-tmp");
        PathBuf::from(s)
    };
    if let Err(e) = std::fs::write(&tmp, rendered.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    // R6:token 只 owner 可读(Unix);Windows 侧由 named-pipe DACL 守门(transport slice)。
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// 在**已连接 + 已 R1 校验**的流上跑握手 + 请求/响应序列。
///
/// **fail-closed**:写/读 IO 错误、HelloOk 版本不符、首响应非 HelloOk、或任何 [`Response::Error`]
/// → `None`。调用方(hook)收到 `None` 即用纯硬指纹结果继续(ADR 0024 D3/D7,**永不 fail-open**)。
///
/// 注:本函数的 `read_frame` **自身可无限阻塞**(stream 未设 `set_read_timeout`);R2 总读
/// 截止由调用方 `transport::query_daemon` 强制 —— 本函数跑在其 detached 工作线程内,主线程
/// `recv_timeout(deadline)` 到期即弃结果返 `None`(worker 随 one-shot hook 进程退出回收)。
pub fn exchange<S: Read + Write>(
    stream: &mut S,
    token: &str,
    request: &Request,
) -> Option<Response> {
    // 握手:出示 token + 本端协议版本。
    let hello = Hello {
        version: PROTOCOL_VERSION,
        token: token.to_string(),
    };
    write_frame(stream, &hello).ok()?;
    match read_frame::<_, Response>(stream).ok()? {
        Response::HelloOk {
            protocol_version, ..
        } if protocol_version == PROTOCOL_VERSION => {}
        // 版本不符 / 非 HelloOk(含 Error)→ daemon 不可用。
        _ => return None,
    }
    // 请求 → 响应。
    write_frame(stream, request).ok()?;
    match read_frame::<_, Response>(stream).ok()? {
        // daemon 自报错误 → 降级硬指纹(绝不把 Error 当结果)。
        Response::Error { .. } => None,
        other => Some(other),
    }
}

#[cfg(test)]
mod tests {
    use super::{exchange, read_daemon_info, DaemonInfo};
    use crate::protocol::{
        read_frame, write_frame, Hello, Request, Response, ScanKind, WireFinding, PROTOCOL_VERSION,
    };
    use std::io::{Cursor, Read, Write};

    /// 预载 inbound(模拟 daemon 响应)+ 捕获 outbound(client 实际写出),验序列逻辑。
    struct MockStream {
        inbound: Cursor<Vec<u8>>,
        outbound: Vec<u8>,
    }
    impl MockStream {
        fn new(inbound: Vec<u8>) -> Self {
            Self {
                inbound: Cursor::new(inbound),
                outbound: Vec::new(),
            }
        }
    }
    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inbound.read(buf)
        }
    }
    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.outbound.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn framed(responses: &[&Response]) -> Vec<u8> {
        let mut v = Vec::new();
        for r in responses {
            write_frame(&mut v, r).unwrap();
        }
        v
    }

    #[test]
    fn exchange_happy_path_returns_findings_and_writes_hello_then_request() {
        let inbound = framed(&[
            &Response::HelloOk {
                protocol_version: PROTOCOL_VERSION,
                pii_loaded: true,
                inj_loaded: true,
            },
            &Response::Findings {
                findings: vec![WireFinding {
                    label: "private_email".into(),
                    start: 0,
                    end: 5,
                }],
            },
        ]);
        let mut s = MockStream::new(inbound);
        let req = Request::RedactScan {
            kind: ScanKind::Result,
            text: "hello".into(),
        };
        let resp = exchange(&mut s, "tok", &req);
        assert!(matches!(resp, Some(Response::Findings { .. })));
        // client 必须先写 Hello(带 token)再写 Request —— 解析 outbound 两帧核对。
        let mut out = Cursor::new(s.outbound);
        let hello: Hello = read_frame(&mut out).unwrap();
        assert_eq!(hello.version, PROTOCOL_VERSION);
        assert_eq!(hello.token, "tok");
        let sent: Request = read_frame(&mut out).unwrap();
        assert_eq!(sent, req);
    }

    #[test]
    fn exchange_version_mismatch_is_fail_closed_none() {
        let inbound = framed(&[&Response::HelloOk {
            protocol_version: 999,
            pii_loaded: true,
            inj_loaded: true,
        }]);
        let mut s = MockStream::new(inbound);
        assert!(
            exchange(&mut s, "tok", &Request::Status).is_none(),
            "握手版本不符必须 fail-closed None"
        );
    }

    #[test]
    fn exchange_error_at_handshake_is_none() {
        let inbound = framed(&[&Response::Error {
            message: "bad_token".into(),
        }]);
        let mut s = MockStream::new(inbound);
        assert!(exchange(&mut s, "tok", &Request::Status).is_none());
    }

    #[test]
    fn exchange_error_response_to_request_is_none() {
        let inbound = framed(&[
            &Response::HelloOk {
                protocol_version: PROTOCOL_VERSION,
                pii_loaded: true,
                inj_loaded: true,
            },
            &Response::Error {
                message: "scan_failed".into(),
            },
        ]);
        let mut s = MockStream::new(inbound);
        let req = Request::RedactScan {
            kind: ScanKind::Result,
            text: "x".into(),
        };
        assert!(
            exchange(&mut s, "tok", &req).is_none(),
            "daemon Error 响应 → 降级硬指纹"
        );
    }

    #[test]
    fn exchange_non_hellook_first_response_is_none() {
        let inbound = framed(&[&Response::Ack]);
        let mut s = MockStream::new(inbound);
        assert!(exchange(&mut s, "tok", &Request::Status).is_none());
    }

    #[test]
    fn exchange_truncated_stream_is_none() {
        // 空 inbound → 握手 read_frame EOF → None(模拟连接被对端关 / R2 截止)。
        let mut s = MockStream::new(Vec::new());
        assert!(exchange(&mut s, "tok", &Request::Status).is_none());
    }

    #[test]
    fn read_daemon_info_valid_roundtrips() {
        let td = tempfile::TempDir::new().unwrap();
        let p = td.path().join("daemon.json");
        let info = DaemonInfo {
            pid: 4321,
            socket_path: "/tmp/vigil.sock".into(),
            token: "abc".into(),
            protocol_version: PROTOCOL_VERSION,
            pii_loaded: true,
            inj_loaded: false,
        };
        std::fs::write(&p, serde_json::to_string(&info).unwrap()).unwrap();
        let got = read_daemon_info(&p).unwrap();
        assert_eq!(got.pid, 4321);
        assert_eq!(got.token, "abc");
        assert_eq!(got.protocol_version, PROTOCOL_VERSION);
    }

    #[test]
    fn read_daemon_info_version_mismatch_is_none() {
        let td = tempfile::TempDir::new().unwrap();
        let p = td.path().join("daemon.json");
        std::fs::write(
            &p,
            br#"{"pid":1,"socket_path":"/x","token":"t","protocol_version":999,"pii_loaded":false,"inj_loaded":false}"#,
        )
        .unwrap();
        assert!(
            read_daemon_info(&p).is_none(),
            "版本不识别 → fail-closed None"
        );
    }

    #[test]
    fn read_daemon_info_malformed_is_none() {
        let td = tempfile::TempDir::new().unwrap();
        let p = td.path().join("daemon.json");
        std::fs::write(&p, b"not json at all").unwrap();
        assert!(read_daemon_info(&p).is_none());
    }

    #[test]
    fn read_daemon_info_missing_file_is_none() {
        let td = tempfile::TempDir::new().unwrap();
        assert!(read_daemon_info(&td.path().join("nope.json")).is_none());
    }

    #[test]
    fn write_then_read_daemon_info_roundtrips_and_creates_dirs() {
        use super::write_daemon_info;
        let td = tempfile::TempDir::new().unwrap();
        // 父目录不存在 → write_daemon_info 自建(原子 tmp+rename)。
        let p = td.path().join("Vigil").join("daemon.json");
        let info = DaemonInfo {
            pid: 99,
            socket_path: "/run/user/1000/vigil.sock".into(),
            token: "per-launch-token".into(),
            protocol_version: PROTOCOL_VERSION,
            pii_loaded: true,
            inj_loaded: true,
        };
        write_daemon_info(&p, &info).unwrap();
        assert_eq!(read_daemon_info(&p).unwrap(), info, "写读必须无损往返");
    }
}
