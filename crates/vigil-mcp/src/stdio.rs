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
    #[error("upstream error: code={code} message_sha256={}", upstream_message_fingerprint(.message))]
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
    #[error("upstream negotiated unsupported MCP protocol version: {}", safe_protocol_version(.negotiated))]
    ProtocolVersionUnsupported {
        /// server 在 `initialize` 响应里回的版本(不可信上游输入;Display 经 `safe_protocol_version`
        /// 净化后才渲染,字段本身保留原值供程序判定)。
        negotiated: String,
    },
    /// 上游**只讲现代时代 MCP**(2026-07-28+:无 `initialize` 握手、版本随每请求 `_meta` 协商)。
    ///
    /// 判定依据(2026-07-28 spec「Backward Compatibility」):`initialize` 被上游以 JSON-RPC error
    /// 拒绝后,用 `server/discover` 探针确定性判别 —— 探针得到 `DiscoverResult`(或
    /// `UnsupportedProtocolVersionError` -32022)即现代服务器;其它错误/超时才是旧时代服务器
    /// (此时保留原 `initialize` 错误)。按兼容矩阵「Legacy client × Modern server = Fails」,
    /// vigil-hub 当前作为旧时代客户端无法接入 → fail-closed,但给出**可操作**诊断而非笼统 protocol
    /// 错误(P0-3a:doctor 显式报「版本不兼容」而非静默断开)。
    #[error(
        "upstream speaks modern-era MCP only (no initialize handshake; it advertises {}) - vigil-hub \
         currently speaks legacy MCP up to {}; modern-era client support is planned",
        render_supported(.supported),
        SUPPORTED_PROTOCOL_VERSIONS[0]
    )]
    ModernOnlyUpstream {
        /// 上游 `server/discover` 结果里的 `supportedVersions`(不可信上游输入;已截断到
        /// `MAX_SUPPORTED_LISTED` 条,Display 逐条经 `safe_protocol_version` 净化)。
        supported: Vec<String>,
    },
}

/// `ProtocolVersionUnsupported.negotiated` 的 Display 净化(Codex D18 R2 Medium):该值来自上游
/// `initialize` 响应、属**不可信输入**,可能被恶意 server 塞入任意字节(含 secret)。`Display` 经任何
/// `{e}` 格式化会流入本进程 stderr(serve/wrap 诊断)或 doctor `--probe` 失败原因。合法 protocolVersion
/// 是短日期串(如 `2025-06-18`),故仅在「短 + 安全字符集」时原样显示(保诊断价值),否则降级为 sha256
/// 指纹(绝不渲染原始字节)。与 `StdioError::Upstream` 的 `message` 指纹化同源思路。
///
/// 安全字符集**刻意排除字母**:合法 MCP protocolVersion 是纯数字日期串(`2025-06-18`),而绝大多数
/// secret 含字母 —— 故只放行「短 + 仅数字/`-`/`.`」者原样显示,其余(含任何字母/异常字符/超长)一律
/// 指纹化。即便一个 ≤20 位纯数字串理论上可能是 secret,渲染纯数字 token 的泄漏价值也极低(Codex R2)。
pub fn safe_protocol_version(negotiated: &str) -> String {
    let safe = !negotiated.is_empty()
        && negotiated.len() <= 20
        && negotiated
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '-' | '.'));
    if safe {
        negotiated.to_string()
    } else {
        format!("sha256:{}", upstream_message_fingerprint(negotiated))
    }
}

/// `ModernOnlyUpstream.supported` 的 Display 渲染:逐条 `safe_protocol_version` 净化(同源不可信输入
/// 处理),空列表给出明确占位而非空串。列表长度在采集侧已截断(`MAX_SUPPORTED_LISTED`)。
fn render_supported(supported: &[String]) -> String {
    if supported.is_empty() {
        return "no version list".to_string();
    }
    supported
        .iter()
        .map(|v| safe_protocol_version(v))
        .collect::<Vec<_>>()
        .join(", ")
}

/// 把不可信的上游错误 `message` 折叠成 sha256 指纹供 `StdioError::Upstream` 的 `Display`。
///
/// 上游 JSON-RPC `error.message` 由远端 server 控制、属不可信输入,可能携带 secret。若原样进
/// `Display`,会经任何 `{e}` 格式化(如 Hub 初始化握手失败的 stderr 诊断,见 `hub.rs`)流入本
/// 进程 stderr 并可能被 agent harness 捕获进 transcript。故指纹化 —— 与 `impl McpUpstream for
/// StdioUpstream::call` 把 `Upstream.message` 投影为 `UpstreamError::JsonRpc { message_sha256 }`
/// 的处理**保持一致**(同一不可信输入,单一脱敏收敛)。
fn upstream_message_fingerprint(message: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(message.as_bytes());
    hex::encode(h.finalize())
}

type PendingTable = Arc<Mutex<HashMap<String, Sender<Value>>>>;

/// 客户端支持的 MCP 协议版本集(新→旧)。`initialize` 以 `[0]`(最新)发起提议;server 可在
/// 响应里协商回另一受支持版本(MCP 生命周期),收到后用本集合核对 —— 不在集合内即 fail-closed
/// (`ProtocolVersionUnsupported`)。
///
/// 版本来源:MCP spec 历次修订(modelcontextprotocol.io/specification)。新增协议修订时在此登记。
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] =
    &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// `server/discover` 探针携带的现代时代版本(2026-07-28 为首个「无握手、按请求 `_meta` 协商」修订)。
/// 仅用于**判别上游时代**,vigil-hub 尚未实现现代时代客户端语义(Phase 1 第二刀)。
pub const MODERN_PROBE_VERSION: &str = "2026-07-28";

/// 2026-07-28 `UnsupportedProtocolVersionError` 的错误码:现代服务器对未支持版本的**确定性**回答
/// (spec:收到它的客户端应从 `supported` 列表重选版本重试,**不得**回退 `initialize`)。
pub const UNSUPPORTED_PROTOCOL_VERSION_CODE: i32 = -32022;

/// 采集上游 `supportedVersions` 的上限(不可信输入:防恶意上游塞超长列表撑爆诊断/日志)。
pub const MAX_SUPPORTED_LISTED: usize = 8;

/// 2026-07-28 stdio「Backward Compatibility」三分支裁决(纯函数,无 I/O):
/// - 探针得到 `DiscoverResult`(含 `supportedVersions`)→ 现代专属上游(`ModernOnlyUpstream`);
/// - 探针得到 `UnsupportedProtocolVersionError`(-32022)→ 同样是现代服务器(它认识现代协议,
///   只是不支持探针版本;spec 明确此时不得回退 initialize);
/// - 其它错误 / 超时 → 旧时代服务器:保留**原 initialize 错误**,不因探针改写诊断。
fn classify_probe_outcome(
    init_code: i32,
    init_message: String,
    probe: Result<Value, StdioError>,
) -> StdioError {
    match probe {
        Ok(result) => {
            let supported = result
                .get("supportedVersions")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .take(MAX_SUPPORTED_LISTED)
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            StdioError::ModernOnlyUpstream { supported }
        }
        Err(StdioError::Upstream { code, .. }) if code == UNSUPPORTED_PROTOCOL_VERSION_CODE => {
            StdioError::ModernOnlyUpstream {
                supported: Vec::new(),
            }
        }
        Err(_) => StdioError::Upstream {
            code: init_code,
            message: init_message,
        },
    }
}

/// O3(ADR 0007 §I-7.1 amendment,Codex ACCEPT-design 2026-06-01):把 `argv[0]` 解析为
/// **绝对路径**。
///
/// **为何需要**:即便 MCP upstream env 政策(`apply_mcp_upstream_env_policy`)现在会把宿主 PATH
/// 纳入子进程白名单,程序定位仍**坚持在 spawn 前、用宿主 PATH** 把裸名解析为绝对路径,原因有二:
/// (1) **安全**:解析出的绝对路径喂给 V1.1 resolved-program drift gate(抓"裸 `node` 解析到不同
/// 二进制"),这是独立于 env 政策的 pin 维度,不能依赖子进程自解析;(2) **确定性**:`Command::new(
/// <absolute>)` 让程序定位与子进程 env 政策解耦,不受白名单内容变动影响。裸命令(`node`/`npx`/
/// `python`,MCP 生态惯例)由此稳定解析。
///
/// 规则(Codex review 要求):
/// - argv[0] 含路径分隔符 → 视为路径,`canonicalize` 校验存在并转绝对(**不**做 PATH 搜索)
/// - 裸名 → 遍历宿主 `PATH`;Unix 要求可执行位(X_OK),Windows 叠加 `PATHEXT`
/// - 找不到 → `ProgramNotFound`(fail-closed),不退化为笼统 `Spawn`
///
/// **V1.1(已实现,Codex Design R2 ACCEPT)**:解析后绝对路径现由 `Hub::spawn_attach_stdio_upstream`
/// 在 spawn **之前**纳入 server command pinning 的第二独立维度(列 `resolved_program_path` 与审计
/// `server.resolved_program_drifted`),抓"裸 `node` 解析到不同二进制"。TOCTOU(解析时刻 vs exec
/// 时刻二进制替换)仍 O-D 超范围(无 inode/content pinning)。
///
/// `pub`:Hub 在 spawn 前调用(gate 维度),同时 `setup --mcp --doctor` 用它做**与网关一致**的程序
/// PATH 可解析预检(SSOT —— doctor 的 ✓/✗ 判定必须与真实 spawn 行为同源,否则误报)。
pub fn resolve_program(argv0: &str) -> Result<std::path::PathBuf, StdioError> {
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

/// **Doctor 深度探测(D18)**:真 spawn 一个 stdio 上游 + 完成 MCP `initialize` 握手,
/// **返回真实握手结果**后立即关停 —— 仅验证"该 server 在本环境真能起来并说 MCP",**不 attach、
/// 不建 descriptor 基线、不改任何 drift 状态**。与 [`Hub::spawn_attach_stdio_upstream`](握手失败
/// 仍 attach、优雅降级)**有意分叉**:doctor 要的是诊断结论,故握手失败必须如实返出。
///
/// 进程在函数返回(`upstream` 离开作用域 → `Drop` → `shutdown_raw`)时 **kill + wait 直接子进程**。
/// **限界(Codex D18 R2 Medium)**:只 kill 直接子进程,**不强制 contain 其后代**。`npx`/`uvx` 这类
/// 启动器会再 spawn `node`/解释器孙进程;正常 MCP server 在其 stdin 关闭(随父被 kill)时会自行退出,
/// 但一个行为异常的孙进程可能短暂存活(未做 Unix process-group / Windows Job Object 容器化 —— 作为
/// 后续硬化项跟踪)。probe 是 opt-in 且短时,故此限界可接受。
///
/// env 走与真实运行**完全相同**的 [`StdioUpstream::spawn_resolved`](MCP upstream env 政策:
/// env_clear → 非敏感运行时白名单 → 批准 user_env),故 probe 忠实复现 agent 真实启动该 server 的条件。
///
/// **副作用警示**:本函数会真启动 server 进程(执行其 init 代码)。仅在用户显式 `--probe` 时调用;
/// 默认 doctor 保持纯静态、无副作用。`timeout` 对慢/挂起 server 设上界,防诊断被拖住。
///
/// # Errors
/// - [`StdioError::ProgramNotFound`]:`argv[0]` 不在 PATH(与静态 doctor `resolve_program` 同源)
/// - [`StdioError::Spawn`]:`argv` 为空 / 进程起不来
/// - [`StdioError::Timeout`] / [`StdioError::Protocol`] / [`StdioError::ProtocolVersionUnsupported`] /
///   [`StdioError::Upstream`]:server 起来了但未在 `timeout` 内完成合法 MCP `initialize` 握手
pub fn probe_stdio_initialize(
    server_id: &str,
    argv: &[String],
    env: &[(String, String)],
    timeout: Duration,
) -> Result<(), StdioError> {
    let program = argv
        .first()
        .ok_or_else(|| StdioError::Spawn(std::io::Error::other("probe: empty argv")))?;
    let resolved = resolve_program(program)?;
    // spawn_resolved 应用 MCP upstream env 政策(与真实运行一致);upstream 在函数末尾 drop → kill+wait。
    // forward_diagnostics=false:probe 不转发上游 stderr/parse 错误(消除 env 值回显泄漏面;Codex R1)。
    let upstream = StdioUpstream::spawn_resolved(server_id, resolved, &argv[1..], env, false)?;
    upstream.initialize_handshake(timeout)
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
    /// - `env`:批准注入的环境变量。进程先 `env_clear()`,然后:
    ///   - 注入 `MCP_UPSTREAM_ENV_ALLOWLIST` 里**当前进程存在**的非敏感运行时 env
    ///     (PATH/HOME/APPDATA/SystemRoot…)—— 让 `npx`/`uvx`/`node` 启动器能定位解释器与
    ///     包管理器 cache 而真正起来(否则永不就绪,Hub 聚合 0 工具)
    ///   - 最后注入 caller 批准的 `env`(优先级最高)
    ///
    /// env 政策由 `vigil_runner_types::apply_mcp_upstream_env_policy` 实现 —— 与沙箱 runner 的
    /// `apply_native_env_policy`(完全 env_clear)**有意分叉**(ADR 0007 §I-7.1 amendment):MCP
    /// upstream 是可信启动器需运行时 env,沙箱跑不可信代码故全清;白名单 deny-by-default 不含密钥,
    /// 父进程的 API key/token 仍不泄漏。仅"程序定位"用了父 PATH(`resolve_program`)。
    pub(crate) fn spawn_resolved(
        server_id: impl Into<String>,
        program: std::path::PathBuf,
        argv_tail: &[String],
        env: &[(String, String)],
        // `forward_diagnostics`:是否把上游 stderr / stdout 解析错误转发到本进程 stderr。
        // serve/wrap = true(运维需看上游诊断,已过 scrub)。**doctor `--probe` = false**:probe 用
        // 用户真实 env 值启动 server,而 server 可能在自己 stderr 回显该 env 值(非硬指纹形态,scrub
        // 抓不住)→ 转发即泄漏。probe 不需要上游 stderr(只看 initialize 成败),故全程吞掉(仍 drain
        // 管道防子进程 stderr 缓冲写满阻塞),消除该泄漏面(Codex D18 R1 High)。
        forward_diagnostics: bool,
    ) -> Result<Self, StdioError> {
        let mut cmd = Command::new(program);
        for a in argv_tail {
            cmd.arg(a);
        }
        // MCP upstream env 政策(ADR 0007 §I-7.1 amendment):与沙箱 runner 的
        // `apply_native_env_policy`(完全 env_clear)**有意分叉**。MCP stdio upstream 是用户配置的
        // 可信启动器(`npx`/`uvx`/`node`),完全清 env 会让它们拿不到 PATH/HOME 而**起不来**
        // (Linux+Windows 实测 `mcp-server-filesystem: not found`,upstream 永不就绪 → Hub 聚合 0 工具)。
        // 改用 `apply_mcp_upstream_env_policy`:env_clear → 注入非敏感运行时 env 白名单
        // (PATH/HOME/APPDATA/SystemRoot…,deny-by-default,不含任何密钥)→ 注入批准 user_env。
        // 父进程的 API key/token 仍不泄漏给 upstream(隔离方向是收紧白名单,而非放开)。
        // helper 签名要 IntoIterator<Item=(K,V)>;slice iter 的 item 是 &(String,String),
        // map(|(k,v)| (k,v)) 解构为引用元组,AsRef<OsStr> blanket impl 覆盖 &String。
        vigil_runner_types::apply_mcp_upstream_env_policy(
            &mut cmd,
            env.iter().map(|(k, v)| (k, v)),
        );
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
                                // `ProtocolError` 的 Display 可能内嵌上游原始字节(malformed
                                // JSON 片段);先过硬指纹 scrub 再转发,避免 server 输出里的
                                // secret 经本进程 stderr 外泄。probe(forward_diagnostics=false)
                                // 全程不转发(消除 env 值回显泄漏面,Codex D18 R1 High)。
                                if forward_diagnostics {
                                    let safe = vigil_redaction::scrub_text(&e.to_string());
                                    eprintln!(
                                        "[vigil-hub upstream {tag}] stdio parse error: {safe}"
                                    );
                                }
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
                    // **始终 drain**(读完每一行)防子进程 stderr 缓冲写满阻塞;**是否转发**由
                    // forward_diagnostics 决定。probe(false)全程吞掉:server 可能在 stderr 回显
                    // 注入的真实 env 值(非硬指纹形态,scrub 抓不住),转发即泄漏(Codex D18 R1 High)。
                    for line in r.lines().map_while(Result::ok) {
                        if forward_diagnostics {
                            // 上游 MCP server 的 stderr 可能记录它收到的凭证(如
                            // "authenticated with ghp_…")。wrap/serve 把 Vigil 置于中间,原样转发
                            // 会二次扩大泄漏面(可能被 agent harness 捕获)。过硬指纹 scrub:保留
                            // 可读诊断、遮蔽已知 secret 形态(redaction-first 边界,见 scrub_text)。
                            let safe = vigil_redaction::scrub_text(&line);
                            eprintln!("[upstream {tag}] {safe}");
                        }
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
        let result = match self.call_raw("initialize", Some(params), timeout) {
            Ok(v) => v,
            // 上游以 JSON-RPC error 拒绝 initialize:可能是现代专属服务器(2026-07-28+ 无此方法,
            // 以实现自定义错误拒绝)。按 spec 用 server/discover 探针确定性判别,探针超时收紧
            // (上游已证明在线且会应答,不必再给冷启动余量)。超时/协议错误不在此分支:无法与
            // 慢启动区分,保持原语义。
            Err(StdioError::Upstream { code, message }) => {
                let probe_timeout = timeout.min(Duration::from_secs(5));
                return Err(self.classify_initialize_rejection(code, message, probe_timeout));
            }
            Err(e) => return Err(e),
        };
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

    /// `initialize` 被上游拒绝后的时代判别:发 `server/discover` 探针(带现代 `_meta`),把探针
    /// 结果交给纯函数 [`classify_probe_outcome`] 裁决。网络与裁决分离,便于对裁决逻辑做无进程单测。
    fn classify_initialize_rejection(
        &self,
        init_code: i32,
        init_message: String,
        probe_timeout: Duration,
    ) -> StdioError {
        let params = json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MODERN_PROBE_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {
                    "name": "vigil-hub",
                    "version": env!("CARGO_PKG_VERSION"),
                },
            }
        });
        let probe = self.call_raw("server/discover", Some(params), probe_timeout);
        classify_probe_outcome(init_code, init_message, probe)
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
            // 仅 initialize_handshake 路径产生;现代专属上游 = 传输层不兼容(fail-closed)
            Err(StdioError::ModernOnlyUpstream { .. }) => {
                Err(UpstreamError::TransportIo("stdio_upstream_modern_era_only"))
            }
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

    // ──────────────── D18 doctor 深度探测:失败路径(无外部依赖) ────────────────
    #[test]
    fn probe_nonexistent_program_returns_program_not_found() {
        let err = super::probe_stdio_initialize(
            "doctor-probe-test",
            &["vigil_definitely_not_a_real_command_xyz".to_string()],
            &[],
            std::time::Duration::from_millis(500),
        )
        .expect_err("probing a non-existent program must fail (same source as static doctor)");
        assert!(
            matches!(err, StdioError::ProgramNotFound { .. }),
            "must be ProgramNotFound, got {err:?}"
        );
    }

    #[test]
    fn probe_empty_argv_errors() {
        let err = super::probe_stdio_initialize(
            "doctor-probe-test",
            &[],
            &[],
            std::time::Duration::from_millis(500),
        )
        .expect_err("empty argv must error");
        assert!(matches!(err, StdioError::Spawn(_)), "got {err:?}");
    }

    #[test]
    fn probe_non_mcp_program_fails_within_timeout_and_cleans_up() {
        // SYSTEM_CMD(sh/cmd)会启动但**不说 MCP** —— 不回 initialize 响应 → probe 必须在超时内返
        // Err(而非挂死),并在返回时已 kill 子进程(StdioUpstream::Drop → shutdown_raw)。
        let start = std::time::Instant::now();
        let err = super::probe_stdio_initialize(
            "doctor-probe-test",
            &[SYSTEM_CMD.to_string()],
            &[],
            std::time::Duration::from_millis(700),
        )
        .expect_err("a non-MCP program must not complete an MCP initialize handshake");
        let elapsed = start.elapsed();
        // 不挂:应在 timeout + 合理裕量内返回(宿主慢 spawn 留 5s 裕量)。
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "probe must not hang; took {elapsed:?}"
        );
        // 程序存在故失败必是握手失败(Timeout/Protocol/Eof…),**不**是 ProgramNotFound。
        assert!(
            !matches!(err, StdioError::ProgramNotFound { .. }),
            "program exists → failure must be a handshake failure, not ProgramNotFound: {err:?}"
        );
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod display_redaction_tests {
    use super::*;

    /// stderr-leak HIGH(Codex wrap R1 守门):`StdioError::Upstream` 的 `Display` 绝不原样回显
    /// 上游不可信 `message`;只暴露 sha256 指纹(与 `impl McpUpstream::call` 的
    /// `message_sha256` 投影一致)。本测试守 `hub.rs` 初始化握手失败 `{e}` 诊断路径不泄漏 secret。
    #[test]
    fn upstream_display_fingerprints_message_not_raw() {
        let secret = "authenticated with ghp_1234567890abcdef1234567890abcdef12345678";
        let err = StdioError::Upstream {
            code: -32000,
            message: secret.to_string(),
        };
        let shown = err.to_string();
        assert!(
            !shown.contains(secret),
            "Display 不得包含原始 message: {shown}"
        );
        assert!(
            !shown.contains("ghp_1234567890abcdef1234567890abcdef12345678"),
            "Display 不得泄漏 secret 形态: {shown}"
        );
        assert!(
            shown.contains("message_sha256="),
            "Display 须含 sha256 指纹字段: {shown}"
        );
        // 指纹须为 message 的确定性 sha256(同 message 同指纹,便于关联诊断)。
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(secret.as_bytes());
        let expect = hex::encode(h.finalize());
        assert!(
            shown.contains(&expect),
            "指纹须为 message 的 sha256: {shown}"
        );
    }

    /// Codex D18 R2 Medium 守门:`ProtocolVersionUnsupported` 的 `negotiated` 来自不可信上游 initialize
    /// 响应。合法短日期串原样显示(诊断);含异常字符 / 超长(可能藏 secret)的降级为 sha256 指纹,
    /// **绝不**原样渲染上游字节。
    #[test]
    fn protocol_version_display_sanitizes_untrusted_negotiated() {
        // 1) 合法版本:原样显示(诊断价值)
        let ok = StdioError::ProtocolVersionUnsupported {
            negotiated: "2099-01-01".to_string(),
        }
        .to_string();
        assert!(ok.contains("2099-01-01"), "合法版本应原样显示: {ok}");
        assert!(!ok.contains("sha256:"), "合法版本不该被指纹化: {ok}");

        // 2) 恶意/异常 negotiated(内嵌 secret + 非安全字符)→ 指纹化,不泄漏
        let secret = "ghp_1234567890abcdef1234567890abcdef12345678 leaked!";
        let bad = StdioError::ProtocolVersionUnsupported {
            negotiated: secret.to_string(),
        }
        .to_string();
        assert!(!bad.contains(secret), "不得原样渲染上游字节: {bad}");
        assert!(
            !bad.contains("ghp_1234567890abcdef1234567890abcdef12345678"),
            "不得泄漏 secret 形态: {bad}"
        );
        assert!(bad.contains("sha256:"), "异常 negotiated 应降级指纹: {bad}");
    }

    /// P0-3a:版本白名单纳入 2025-11-25(stdio 工具面无强制新语义),且以最新版本发起提议。
    #[test]
    fn supported_versions_include_2025_11_25_and_propose_newest_first() {
        assert!(SUPPORTED_PROTOCOL_VERSIONS.contains(&"2025-11-25"));
        assert!(SUPPORTED_PROTOCOL_VERSIONS.contains(&"2025-06-18"));
        assert_eq!(SUPPORTED_PROTOCOL_VERSIONS[0], "2025-11-25");
        // 新→旧单调(提议顺序 = 偏好顺序)
        let mut sorted = SUPPORTED_PROTOCOL_VERSIONS.to_vec();
        sorted.sort_unstable_by(|a, b| b.cmp(a));
        assert_eq!(sorted, SUPPORTED_PROTOCOL_VERSIONS);
        // 现代探针版本**不在**白名单:尚未实现现代客户端语义,绝不能把它当作已支持
        assert!(!SUPPORTED_PROTOCOL_VERSIONS.contains(&MODERN_PROBE_VERSION));
    }

    /// 探针得到 DiscoverResult → 现代专属上游,supportedVersions 被采集并截断。
    #[test]
    fn classify_discover_result_as_modern_only_and_caps_supported_list() {
        let many: Vec<Value> = (0..20)
            .map(|i| Value::String(format!("2026-07-{:02}", i + 1)))
            .collect();
        let probe = Ok(json!({
            "resultType": "complete",
            "supportedVersions": many,
            "capabilities": {},
            "cacheScope": "public",
            "ttlMs": 60000,
        }));
        match classify_probe_outcome(-32601, "method not found".into(), probe) {
            StdioError::ModernOnlyUpstream { supported } => {
                assert_eq!(supported.len(), MAX_SUPPORTED_LISTED);
                assert_eq!(supported[0], "2026-07-01");
            }
            other => panic!("expected ModernOnlyUpstream, got {other:?}"),
        }
    }

    /// 探针得到 -32022 → 现代服务器(spec:不得回退 initialize),supported 为空但判定不变。
    #[test]
    fn classify_unsupported_protocol_version_error_as_modern_only() {
        let probe = Err(StdioError::Upstream {
            code: UNSUPPORTED_PROTOCOL_VERSION_CODE,
            message: "Unsupported protocol version".into(),
        });
        match classify_probe_outcome(-32601, "method not found".into(), probe) {
            StdioError::ModernOnlyUpstream { supported } => assert!(supported.is_empty()),
            other => panic!("expected ModernOnlyUpstream, got {other:?}"),
        }
    }

    /// 探针得到其它错误 / 超时 → 旧时代服务器:原 initialize 错误原样保留(不被探针改写)。
    #[test]
    fn classify_other_probe_failures_preserve_original_initialize_error() {
        for probe in [
            Err(StdioError::Upstream {
                code: -32601,
                message: "unknown method".into(),
            }),
            Err(StdioError::Timeout(Duration::from_millis(1))),
        ] {
            match classify_probe_outcome(-32000, "init rejected".into(), probe) {
                StdioError::Upstream { code, message } => {
                    assert_eq!(code, -32000);
                    assert_eq!(message, "init rejected");
                }
                other => panic!("expected original Upstream error, got {other:?}"),
            }
        }
    }

    /// ModernOnlyUpstream 的 Display:合法版本原样、异常条目指纹化、空列表有占位;
    /// 且点名当前最高旧时代版本(可操作诊断)。
    #[test]
    fn modern_only_display_is_actionable_and_sanitized() {
        let shown = StdioError::ModernOnlyUpstream {
            supported: vec![
                "2026-07-28".into(),
                "ghp_1234567890abcdef1234567890abcdef12345678".into(),
            ],
        }
        .to_string();
        assert!(shown.contains("2026-07-28"), "{shown}");
        assert!(shown.contains("sha256:"), "异常条目应指纹化: {shown}");
        assert!(
            !shown.contains("ghp_1234567890"),
            "不得泄漏上游字节: {shown}"
        );
        assert!(shown.contains(SUPPORTED_PROTOCOL_VERSIONS[0]), "{shown}");
        assert!(shown.contains("modern-era"), "{shown}");

        let empty = StdioError::ModernOnlyUpstream { supported: vec![] }.to_string();
        assert!(empty.contains("no version list"), "{empty}");
    }
}
