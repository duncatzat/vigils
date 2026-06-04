//! Upstream stdio 子进程适配器(ADR 0004 §D2)。
//!
//! 每个上游 MCP server 在 Hub 里对应一个 `StdioUpstream`:
//! - 一对 reader / writer 线程
//! - 一个 pending-request 表(`id → Sender<Response>`,`std::sync::mpsc`)
//! - 一个独立 stderr 吞吐线程,把 server 的 log 转发到 audit(I04 内做最小:写到 stderr)
//!
//! I04 范围:**最小可运行**。更鲁棒的崩溃检测 / 自动重启放 I10(HTTP MCP + 远端)
//! 一起做。

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::protocol::{read_message, write_message, JsonRpcRequest, ProtocolError};

/// Stdio adapter 错误。
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StdioError {
    /// IO / 协议错误
    #[error("protocol: {0}")]
    Protocol(#[from] ProtocolError),
    /// 响应超时
    #[error("upstream response timeout after {0:?}")]
    Timeout(Duration),
    /// 上游返回 JSON-RPC error
    #[error("upstream error: code={code} message={message}")]
    Upstream {
        /// JSON-RPC error code
        code: i32,
        /// 人读 message
        message: String,
    },
    /// 锁污染
    #[error("internal lock poisoned")]
    LockPoisoned,
    /// 进程启动失败
    #[error("failed to spawn upstream: {0}")]
    Spawn(std::io::Error),
    /// argv[0] 程序无法在 PATH 中解析(O3 / ADR 0007 §I-7.1 amendment)。
    ///
    /// 因 spawn 走 `env_clear()` 清掉 PATH,裸命令需在 spawn 前用**宿主 PATH** 解析为绝对路径
    /// (见 `resolve_program`)。解析失败时返回本变体而非笼统 `Spawn(NotFound)`,便于诊断。
    #[error("upstream program not found on PATH: {program}")]
    ProgramNotFound {
        /// 未能解析的裸命令(argv[0])
        program: String,
    },
    /// 进程已经关闭
    #[error("upstream already closed")]
    Closed,
    /// `initialize` 响应里 server 协商出我们不支持的 MCP 协议版本(不在
    /// `SUPPORTED_PROTOCOL_VERSIONS`)。按 MCP spec 客户端遇此应断开 → fail-closed
    /// (Codex review SHOULD-FIX:此前硬编码版本且忽略协商结果,对仅支持旧版/未来漂移的
    /// server 有互操作风险)。
    #[error("upstream negotiated unsupported MCP protocol version: {negotiated}")]
    ProtocolVersionUnsupported {
        /// server 在 `initialize` 响应里回的版本
        negotiated: String,
    },
}

type PendingTable = Arc<Mutex<HashMap<String, Sender<Value>>>>;

/// 客户端支持的 MCP 协议版本集(新→旧)。`initialize` 以 `[0]`(最新)发起提议;server 可在
/// 响应里协商回另一受支持版本(MCP 生命周期),收到后用本集合核对 —— 不在集合内即 fail-closed
/// (`ProtocolVersionUnsupported`)。
///
/// 版本来源:MCP spec 历次修订(modelcontextprotocol.io/specification)。新增协议修订时在此登记。
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

/// O3(ADR 0007 §I-7.1 amendment,Codex ACCEPT-design 2026-06-01):把 `argv[0]` 解析为
/// **绝对路径**。
///
/// **为何需要**:`spawn` 经 `apply_native_env_policy` 做 `env_clear()`,子进程 env 无 PATH;
/// 而 `std::process::Command` 在 Unix 按 command 自身 env 的 PATH 解析裸名 → 裸命令(`node`/
/// `npx`/`python`,MCP 生态惯例)在被清环境里解析失败(`NotFound`)。本函数在 **spawn 前、
/// 用宿主进程 PATH** 把裸名解析为绝对路径;随后 `Command::new(<absolute>)` + `env_clear` 即可
/// —— **子进程 env 仍被完全清空**(§I-7.1 不变量保留),仅"程序定位"用了父进程 PATH。
///
/// 规则(Codex review 要求):
/// - argv[0] 含路径分隔符 → 视为路径,`canonicalize` 校验存在并转绝对(**不**做 PATH 搜索)
/// - 裸名 → 遍历宿主 `PATH`;Unix 要求可执行位(X_OK),Windows 叠加 `PATHEXT`
/// - 找不到 → `ProgramNotFound`(fail-closed),不退化为笼统 `Spawn`
///
/// **V1.1(已实现,Codex Design R2 ACCEPT)**:解析后绝对路径现由 `Hub::spawn_attach_stdio_upstream`
/// 在 spawn **之前**纳入 server command pinning 的第二独立维度(列 `resolved_program_path` 与审计
/// `server.resolved_program_drifted`),抓"裸 `node` 解析到不同二进制"。TOCTOU(解析时刻 vs exec
/// 时刻二进制替换)仍 O-D 超范围(无 inode/content pinning)。`pub(crate)` 供 Hub 调用。
pub(crate) fn resolve_program(argv0: &str) -> Result<std::path::PathBuf, StdioError> {
    let not_found = || StdioError::ProgramNotFound {
        program: argv0.to_string(),
    };
    // 含路径分隔符 → 当作路径,直接 canonicalize(不 PATH 搜索)
    let has_sep = argv0.contains('/') || (cfg!(windows) && argv0.contains('\\'));
    if has_sep {
        return std::path::Path::new(argv0)
            .canonicalize()
            .map_err(|_| not_found());
    }
    // 裸名 → 遍历宿主 PATH
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path_var) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        // canonicalize 成功即返(转绝对 + 解 symlink,利于审计);失败则回落 join 后的绝对路径
        let canon = |p: std::path::PathBuf| p.canonicalize().unwrap_or(p);

        #[cfg(unix)]
        {
            let cand = dir.join(argv0);
            if is_executable_file(&cand) {
                return Ok(canon(cand));
            }
        }
        #[cfg(windows)]
        {
            // 已带扩展名(含 '.')先试裸名本身;否则按 PATHEXT 逐个试
            let direct = dir.join(argv0);
            if argv0.contains('.') && direct.is_file() {
                return Ok(canon(direct));
            }
            let pathext =
                std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
            for ext in pathext.split(';').filter(|e| !e.is_empty()) {
                let cand = dir.join(format!("{argv0}{ext}"));
                if cand.is_file() {
                    return Ok(canon(cand));
                }
            }
        }
    }
    Err(not_found())
}

/// Unix:文件存在且 owner/group/other 任一有执行位(X_OK 近似)。
#[cfg(unix)]
fn is_executable_file(p: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(p) {
        Ok(m) => m.is_file() && (m.permissions().mode() & 0o111 != 0),
        Err(_) => false,
    }
}

/// 一个上游 stdio server 的连接。
pub struct StdioUpstream {
    server_id: String,
    child: Mutex<Option<Child>>,
    stdin: Mutex<Option<ChildStdin>>,
    pending: PendingTable,
}

impl std::fmt::Debug for StdioUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StdioUpstream")
            .field("server_id", &self.server_id)
            .finish()
    }
}

impl StdioUpstream {
    /// 启动一个 stdio 上游(V1.1,ADR 0007 §I-7.1 / ADR 0005,Codex R2 ACCEPT)。
    ///
    /// **唯一** stdio 构造路径,接收已由 `Hub::spawn_attach_stdio_upstream` 解析 + 双 drift gate
    /// (argv + resolved-program)通过的绝对路径 `program`。`pub(crate)` —— 外部 caller 不得绕过
    /// Hub gate 直接起进程(封死历史的 public 裸 argv `spawn` 旁路;Codex R2 实施铁律)。
    ///
    /// 参数:
    ///
    /// - `program`:Hub 用宿主 PATH 解析出的绝对路径(`resolve_program`);argv 已由 caller 审批
    /// - `argv_tail`:`argv[1..]`(参数,不参与解析)
    /// - `env`:批准注入的环境变量。进程先 `env_clear()`(§I-7.1 不变量保留),然后:
    ///   - **Windows**:注入 `RESERVED_SYSTEM_ENV_KEYS`(SystemRoot 等,让 cmd.exe / ping
    ///     等系统命令能解析 System32 DLL;见 ADR 0007 §I-7.1 helper)
    ///   - 最后注入 caller 批准的 `env`(优先级最高,覆盖同名 system 保留键)
    ///
    /// env 政策全路径由 `vigil_runner_types::apply_native_env_policy` 统一实现,与 `spawn_native`
    /// 共享,消除跨 crate 漂移(I07.5+ / ADR 0007 §I-7.1 / ADR 0018);仅"程序定位"用了父 PATH。
    pub(crate) fn spawn_resolved(
        server_id: impl Into<String>,
        program: std::path::PathBuf,
        argv_tail: &[String],
        env: &[(String, String)],
    ) -> Result<Self, StdioError> {
        let mut cmd = Command::new(program);
        for a in argv_tail {
            cmd.arg(a);
        }
        // I07.5+ (ADR 0007 §I-7.1):与 vigil-runner::spawn_native 共享 env 政策 helper,
        // 消除历史漂移(此前 StdioUpstream 缺失 Windows SystemRoot 注入 → cmd.exe / ping
        // 作为 MCP server 时无法解析 System32 DLL)。
        // helper 签名要求 IntoIterator<Item=(K,V)>,slice iter 的 items 是 &(String,String),
        // 通过 map(|(k,v)| (k,v)) 解构为引用元组,AsRef<OsStr> blanket impl 覆盖 &String。
        vigil_runner_types::apply_native_env_policy(&mut cmd, env.iter().map(|(k, v)| (k, v)));
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn().map_err(StdioError::Spawn)?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| StdioError::Spawn(std::io::Error::other("upstream stdout not piped")))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| StdioError::Spawn(std::io::Error::other("upstream stderr not piped")))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| StdioError::Spawn(std::io::Error::other("upstream stdin not piped")))?;

        let pending: PendingTable = Arc::new(Mutex::new(HashMap::new()));

        // reader 线程:持续读 NDJSON,分发给 pending.get(id) 的 channel
        let sid = server_id.into();
        {
            let pending_r = pending.clone();
            let tag = sid.clone();
            thread::Builder::new()
                .name(format!("vigil-mcp-stdio-reader-{tag}"))
                .spawn(move || {
                    let mut r = BufReader::new(stdout);
                    loop {
                        match read_message(&mut r) {
                            Ok(v) => {
                                let id_key = v.get("id").map(|x| x.to_string()).unwrap_or_default();
                                if id_key.is_empty() || id_key == "null" {
                                    // notification / server→client request;I04 暂不处理
                                    continue;
                                }
                                let sender_opt = {
                                    let mut g = pending_r.lock().unwrap_or_else(|p| p.into_inner());
                                    g.remove(&id_key)
                                };
                                if let Some(tx) = sender_opt {
                                    let _ = tx.send(v);
                                }
                            }
                            Err(crate::protocol::ProtocolError::Eof) => {
                                // 上游关闭:清空所有等待方,让它们立即 timeout
                                break;
                            }
                            Err(e) => {
                                // M2(Codex I04 review):非法 JSON 不再静默吞掉让 reader
                                // 永久空转;log 一条并继续尝试下一行(rust-style 宽容),
                                // 但上游如果连续坏很快触发 Eof。
                                eprintln!("[vigil-hub upstream {tag}] stdio parse error: {e}");
                                // 继续循环:下一个 read_line 会消费下一行
                                continue;
                            }
                        }
                    }
                    // 退出前把所有 pending sender 清空,让等待方立即拿到 channel close
                    let mut g = pending_r.lock().unwrap_or_else(|p| p.into_inner());
                    g.clear();
                })
                .ok();
        }

        // stderr 线程:吞掉上游日志,转发到本进程 stderr(I04 最小实装)。
        // I08 UI 接入后可改为写入 audit.
        {
            let tag = sid.clone();
            thread::Builder::new()
                .name(format!("vigil-mcp-stdio-stderr-{tag}"))
                .spawn(move || {
                    let r = BufReader::new(stderr);
                    for line in r.lines().map_while(Result::ok) {
                        eprintln!("[upstream {tag}] {line}");
                    }
                })
                .ok();
        }

        Ok(Self {
            server_id: sid,
            child: Mutex::new(Some(child)),
            stdin: Mutex::new(Some(stdin)),
            pending,
        })
    }

    /// 发一条 request 并等待响应。
    ///
    /// `id` 由本函数生成(UUID);超时到达返 `Timeout`。
    ///
    /// I10b-α1 代码 R1 MUST-FIX:收窄到 `pub(crate)` —— 仅本 crate 内的
    /// `impl McpUpstream for StdioUpstream::call` 用;外部 caller 一律走 trait
    /// method `McpUpstream::call`(返统一 `UpstreamError`),**不**得绕开。
    pub(crate) fn call_raw(
        &self,
        method: &str,
        params: Option<Value>,
        timeout: Duration,
    ) -> Result<Value, StdioError> {
        let id = Uuid::new_v4().to_string();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(Value::String(id.clone())),
            method: method.to_string(),
            params,
        };
        let (tx, rx): (Sender<Value>, Receiver<Value>) = channel();
        {
            let mut g = self.pending.lock().map_err(|_| StdioError::LockPoisoned)?;
            g.insert(format!("\"{id}\""), tx);
        }

        // 写请求
        {
            let mut g = self.stdin.lock().map_err(|_| StdioError::LockPoisoned)?;
            let stdin = g.as_mut().ok_or(StdioError::Closed)?;
            let v = serde_json::to_value(&req)
                .map_err(|e| StdioError::Protocol(ProtocolError::Json(e)))?;
            write_message(stdin, &v).map_err(StdioError::Protocol)?;
        }

        // 等响应
        let resp = match rx.recv_timeout(timeout) {
            Ok(v) => v,
            Err(_) => {
                // 清理 pending 条目
                let _ = self
                    .pending
                    .lock()
                    .map(|mut g| g.remove(&format!("\"{id}\"")));
                return Err(StdioError::Timeout(timeout));
            }
        };

        if let Some(err) = resp.get("error") {
            let code = err.get("code").and_then(Value::as_i64).unwrap_or(-1) as i32;
            let message = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            return Err(StdioError::Upstream { code, message });
        }
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    }

    /// 发一条 JSON-RPC **notification**(无 `id`,不注册 pending、不等响应)。
    ///
    /// 用于 MCP 客户端生命周期的 `notifications/initialized`:server 在收到此通知前不进入
    /// operational 状态(spec 要求)。
    pub(crate) fn notify_raw(&self, method: &str, params: Option<Value>) -> Result<(), StdioError> {
        let mut notif = json!({ "jsonrpc": "2.0", "method": method });
        if let Some(p) = params {
            notif["params"] = p;
        }
        let mut g = self.stdin.lock().map_err(|_| StdioError::LockPoisoned)?;
        let stdin = g.as_mut().ok_or(StdioError::Closed)?;
        write_message(stdin, &notif).map_err(StdioError::Protocol)
    }

    /// MCP 客户端生命周期握手:`initialize` 请求 →(等响应)→ `notifications/initialized` 通知。
    ///
    /// **必须在任何 `tools/list` / `tools/call` 之前完成** —— MCP SDK server(filesystem / github
    /// 等官方 server)在 initialize 握手完成前会**拒绝**普通请求,导致 Hub 聚合不到任何工具
    /// (Codex E2E 实测发现:vigil spawn 了 upstream 但 tools/list 始终空)。
    ///
    /// `timeout` 给 server 冷启动留余量(npx/uvx server 首跑可能较慢;真正的慢冷启动建议预装
    /// server 二进制避免 `npx -y` 每次重解析)。失败(timeout / server error)即返 Err,
    /// caller(`spawn_attach_stdio_upstream`)fail-closed 不 attach 未初始化的上游。
    pub(crate) fn initialize_handshake(&self, timeout: Duration) -> Result<(), StdioError> {
        // 提议最新支持版本;server 可在响应里回另一受支持版本(MCP 版本协商)
        let params = json!({
            "protocolVersion": SUPPORTED_PROTOCOL_VERSIONS[0],
            "capabilities": {},
            "clientInfo": { "name": "vigil-hub", "version": env!("CARGO_PKG_VERSION") },
        });
        // initialize 请求:等响应 = 确认 server 就绪 + 完成协议协商
        let result = self.call_raw("initialize", Some(params), timeout)?;
        // 版本协商核对(Codex review SHOULD-FIX):server 在响应里回它选定的版本;若回的版本不在
        // 我们支持集内,按 MCP spec 客户端应断开 → fail-closed 返 Err(caller NON-FATAL:log +
        // attach 但其 tools 不可用,避免"以为协商成功却跑在不兼容协议上")。
        // server 省略 protocolVersion 时宽容放行(部分实现不回显;保持此前行为)。
        if let Some(neg) = result.get("protocolVersion").and_then(Value::as_str) {
            if !SUPPORTED_PROTOCOL_VERSIONS.contains(&neg) {
                return Err(StdioError::ProtocolVersionUnsupported {
                    negotiated: neg.to_string(),
                });
            }
        }
        // initialized 通知:无此通知 server 不进入 operational 状态(MCP 生命周期)
        self.notify_raw("notifications/initialized", None)
    }

    /// 关闭 stdin 并等待子进程终止。best-effort,不抛异常。
    /// I10b-α1 代码 R1 MUST-FIX:改 `pub(crate)`;外部走 trait method `McpUpstream::shutdown`。
    pub(crate) fn shutdown_raw(&self) {
        if let Ok(mut g) = self.stdin.lock() {
            *g = None; // drop ChildStdin → 上游 stdin 关闭
        }
        if let Ok(mut g) = self.child.lock() {
            if let Some(mut c) = g.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }
}

impl crate::upstream::McpUpstream for StdioUpstream {
    fn server_id(&self) -> &str {
        &self.server_id
    }

    fn transport(&self) -> vigil_types::TransportKind {
        vigil_types::TransportKind::Stdio
    }

    fn call(
        &self,
        method: &str,
        params: Option<Value>,
        timeout: Duration,
    ) -> Result<Value, crate::upstream::UpstreamError> {
        use crate::upstream::UpstreamError;
        match self.call_raw(method, params, timeout) {
            Ok(v) => Ok(v),
            Err(StdioError::Timeout(d)) => Err(UpstreamError::TimedOut(d)),
            Err(StdioError::Upstream { code, message }) => {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(message.as_bytes());
                Err(UpstreamError::JsonRpc {
                    code: code as i64,
                    message_sha256: hex::encode(h.finalize()),
                })
            }
            Err(StdioError::Protocol(_)) => Err(UpstreamError::TransportIo("stdio_protocol")),
            Err(StdioError::Closed) => Err(UpstreamError::TransportIo("stdio_closed")),
            Err(StdioError::Spawn(_)) => Err(UpstreamError::TransportIo("stdio_spawn_failed")),
            // spawn 期错误,正常不会经 call_raw 流到此;为 exhaustive 完整性映射为 transport 失败
            Err(StdioError::ProgramNotFound { .. }) => {
                Err(UpstreamError::TransportIo("stdio_program_not_found"))
            }
            // 仅 initialize_handshake 路径产生(不经 trait `call`);exhaustive 完整性映射为 transport 失败
            Err(StdioError::ProtocolVersionUnsupported { .. }) => Err(UpstreamError::TransportIo(
                "stdio_protocol_version_unsupported",
            )),
            Err(StdioError::LockPoisoned) => Err(UpstreamError::Internal("stdio_lock_poisoned")),
        }
    }

    fn shutdown(&self) {
        self.shutdown_raw();
    }
}

impl Drop for StdioUpstream {
    fn drop(&mut self) {
        self.shutdown_raw();
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod resolve_program_tests {
    use super::{resolve_program, StdioError};

    /// 一个在测试平台上几乎必然存在于 PATH 的系统命令。
    #[cfg(unix)]
    const SYSTEM_CMD: &str = "sh";
    #[cfg(windows)]
    const SYSTEM_CMD: &str = "cmd";

    #[test]
    fn resolves_bare_system_command_to_absolute_existing_path() {
        let resolved = resolve_program(SYSTEM_CMD)
            .unwrap_or_else(|e| panic!("expected {SYSTEM_CMD} resolvable on PATH: {e:?}"));
        assert!(
            resolved.is_absolute(),
            "resolved path must be absolute: {resolved:?}"
        );
        assert!(resolved.exists(), "resolved path must exist: {resolved:?}");
    }

    #[test]
    fn bare_unknown_command_fails_closed_with_program_not_found() {
        let err = resolve_program("vigil_definitely_not_a_real_command_xyz")
            .expect_err("unknown bare command must not resolve");
        assert!(
            matches!(err, StdioError::ProgramNotFound { .. }),
            "must be ProgramNotFound (fail-closed), got {err:?}"
        );
    }

    #[test]
    fn path_with_separator_is_not_path_searched_and_fails_closed_when_missing() {
        // 含分隔符 → 当作路径(不 PATH 搜索);不存在 → ProgramNotFound
        let missing = if cfg!(windows) {
            "C:\\vigil\\nope\\not_here.exe"
        } else {
            "/vigil/nope/not_here"
        };
        let err = resolve_program(missing).expect_err("missing explicit path must fail");
        assert!(
            matches!(err, StdioError::ProgramNotFound { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn absolute_path_to_existing_binary_resolves() {
        // 先解析系统命令拿到一个真实绝对路径,再用该绝对路径走"含分隔符"分支
        let abs = resolve_program(SYSTEM_CMD).expect("system cmd resolvable");
        let again = resolve_program(&abs.to_string_lossy())
            .expect("absolute path to existing binary must resolve");
        assert!(again.is_absolute() && again.exists());
    }
}
