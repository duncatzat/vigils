//! `vigil-hub serve --stdio` —— 把 Vigil Hub 暴露为 MCP stdio server,供 CLI agent
//! (Claude Code / Codex / OpenCode / Cursor / Zed / 任何支持 MCP 的工具)通过
//! stdio transport 连接。
//!
//! # 架构(v0.3 Stage 1)
//!
//! ```text
//! agent (MCP client) ──stdio─→ vigil-hub serve ──→ Hub::handle_request
//!                                                          │
//!                                                          ├─→ vigil-firewall(策略决策)
//!                                                          ├─→ vigil-audit(事件链)
//!                                                          └─→ upstream MCP server(stdio/http,Stage 2)
//! ```
//!
//! # 范围(Stage 1 + Stage 2)
//!
//! - ✓ 建立 Ledger / Firewall / Hub,进 stdin→handle_request→stdout 主循环
//! - ✓ 响应 `initialize` / `ping` / `notifications/cancelled` / `shutdown` 协议握手
//! - ✓ `tools/list` 聚合 upstream(命名空间化;零 upstream 时返空)
//! - ✓ 审计事件写入指定 Ledger(支持跨 session 持久化)
//! - ✓ **Stage 2**:`--upstream-config` 自动化 onboarding —— 对每个 upstream
//!   `ServerProfile` → `Ledger::register_server`(幂等)→ `approve_server(Limited)`
//!   → `Hub::spawn_attach_stdio_upstream`(V1.1 gate-before-spawn:argv + resolved-program 双 drift 闭环)
//!
//! # 非目标
//!
//! 本模块**不**做 HTTP transport(MCP 规范 2025-03 SSE / HTTP stream 留后续);
//! 仅 stdio,兼容主流 agent 的 MCP 默认模式。HTTP upstream 用户走
//! `vigil-hub add-remote-mcp` 完成 OAuth 后由 Stage 3 拾取。

#![allow(clippy::uninlined_format_args)]

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use thiserror::Error;

use vigil_audit::Ledger;
use vigil_firewall::scorer::{DescriptorOracle, DescriptorStatus, StaticDescriptorOracle};
use vigil_firewall::{Firewall, FirewallConfig};
use vigil_mcp::protocol::{read_message, write_message, ProtocolError};
use vigil_mcp::{compute_argv_hash, Hub, HubConfig, HubError, JsonRpcRequest};
use vigil_policy::{defaults::default_ruleset, PolicyAction, PolicyEngine, PolicyRule};
use vigil_types::{ServerProfile, TransportKind, TrustLevel};

/// `serve` 子命令参数。
#[derive(Debug, Clone)]
pub struct ServeArgs {
    /// SQLite Ledger 路径。None = 内存 ledger(重启丢失审计链,仅 smoke 测试)。
    pub ledger_path: Option<PathBuf>,
    /// Upstream 配置 JSON 路径(见 [`UpstreamsConfig`] schema)。None = 零 upstream。
    pub upstreams_config: Option<PathBuf>,
    /// 开发模式:tools/list 首次见到的 descriptor 自动批准。生产必须 false。
    pub auto_approve_first_seen: bool,
    /// 开发模式:给 PolicyEngine 注入 "catch-all → Approve" 兜底规则,
    /// 让无 EffectKind 匹配的纯计算工具(如 mock echo/sum)走 Approval 路径而非
    /// 默认 default-deny。**生产必须 false**(否则 default-deny fail-safe 失守)。
    ///
    /// 用途:Stage 3 端到端 approval 闭环演示 —— agent 调 tool → Pending →
    /// mock approver 批准 → 放行。
    ///
    /// **ISS-019 Phase 1 之后**(2026-04-28):**仅**控制 catch-all Approve 规则,
    /// 与 cross-proc timing 解耦。`approval_wait` 已直接走 HubConfig::default()
    /// 300s;cross-proc approve 通过 `wait_for_resolution` 500ms 短轮询 fallback 检出
    /// (实测 ~1.3s,远低于 timeout)。
    pub dev_permissive_firewall: bool,

    /// ISS-008 Phase 2:启用 T0 Privacy Filter(ORT 真模型推理)。
    ///
    /// **fail-closed 不变量**:
    /// - flag on + 编译期未启 `ort` feature → 启动期返 [`ServeError::PrivacyFilterUnavailable`],
    ///   严禁静默回退 NoopEngine
    /// - flag on + `OrtEngine::from_env()` Err → 返 [`ServeError::PrivacyFilterInit`]
    ///   (env unset / 模型缺失 / ORT 初始化失败)
    /// - flag off → 走 v0.4 默认 [`vigil_firewall::PiiScanner`] = `DefaultScanner`
    ///   (Stage 1 scaffold,Hard 路径 + NoopEngine model 侧空)
    ///
    /// 运行期前置:`VIGIL_PRIVACY_FILTER_MODEL_DIR` 指向含 tokenizer.json /
    /// config.json / model_q4f16.onnx 三件套的目录。
    pub enable_privacy_filter: bool,
}

/// JSON 配置 schema(`--upstream-config` 指向的文件)。
///
/// 示例:
/// ```json
/// {
///   "upstreams": [
///     {"name": "filesystem", "argv": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]},
///     {"name": "time",       "argv": ["python", "-m", "mcp_server_time"]}
///   ]
/// }
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamsConfig {
    /// Upstream 列表。Stage 1 仅 stdio transport(argv 启动)。
    #[serde(default)]
    pub upstreams: Vec<UpstreamEntry>,
}

/// 单条 upstream 定义(Stage 1 仅 stdio)。
#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamEntry {
    /// server 名(在 Vigil 内部唯一,namespace 暴露给 agent 时也用这个)
    pub name: String,
    /// 子进程 argv(第一个元素是可执行,后续参数)
    pub argv: Vec<String>,
}

/// `serve` 错误(transparent wrap 下游各子系统)。
#[derive(Debug, Error)]
pub enum ServeError {
    /// 审计层
    #[error("audit: {0}")]
    Audit(#[from] vigil_audit::AuditError),
    /// Hub
    #[error("hub: {0}")]
    Hub(#[from] HubError),
    /// IO(stdin/stdout/config 文件)
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// MCP 协议 framing
    #[error("protocol: {0}")]
    Protocol(#[from] ProtocolError),
    /// JSON 解析(config / JSON-RPC payload)
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    // V1.1:stdio spawn 失败现统一经 `Hub::spawn_attach_stdio_upstream` → `HubError::StdioSpawn`
    //       → `ServeError::Hub` 投影,移除冗余的 `ServeError::StdioSpawn` 变体。
    /// Upstream entry 配置非法(argv 空 / name 空等)
    #[error("upstream entry `{name}` invalid: {reason}")]
    InvalidUpstream {
        /// 名字(若 config 里有)
        name: String,
        /// 具体原因
        reason: &'static str,
    },

    /// ISS-008 Phase 2:运行期 `--enable-privacy-filter` 请求 T0 Privacy Filter,
    /// 但当前二进制**未**用 `--features ort` 编译。fail-closed 启动失败,
    /// **绝不**降级到 NoopEngine(否则用户感知"已启用 privacy filter"实际未生效)。
    #[error(
        "privacy filter requested via --enable-privacy-filter, \
         but vigil-hub-cli was not built with `--features ort`"
    )]
    PrivacyFilterUnavailable,

    /// ISS-008 Phase 2:`OrtEngine::from_env()` 启动期失败(env 未设 / 模型缺失 /
    /// Session init 失败 / config.json 解析等)。fail-fast 在启动期吃掉 cold-start
    /// ~7s,首请求 SLA 不再受影响。
    #[error("privacy filter init failed: {0}")]
    PrivacyFilterInit(#[from] vigil_redaction::engine::EngineError),

    /// v0.5 P2 ADR 0012:`ensure_model_available` 启动期失败(下载 / sha256 / 磁盘 /
    /// 全 mirror 不可达)。BootstrapError 5 变体 fail-closed,**绝不**降级 NoopEngine,
    /// 与 PrivacyFilterUnavailable / PrivacyFilterInit 同级。
    #[cfg(feature = "ort")]
    #[error("model bootstrap failed: {0}")]
    BootstrapFailed(#[from] vigil_redaction::BootstrapError),
}

/// 构建 Hub + Ledger。供 serve 主入口和 test 共用。
///
/// **session 语义**:每次 `serve` 启动开新 session(source=`"vigil-hub-serve"`)。
/// agent 连接期间的所有 tool call / 审批都归在此 session,退出即结束。
pub fn build_hub(args: &ServeArgs) -> Result<(Arc<Hub>, Arc<Ledger>), ServeError> {
    // 1. Ledger(磁盘或内存)
    let ledger = Arc::new(match args.ledger_path.as_deref() {
        Some(p) => Ledger::open(p)?,
        None => Ledger::open_in_memory()?,
    });
    let session_id = ledger.start_session("vigil-hub-serve", Some("vigil-hub"))?;

    // 2. Firewall(默认策略集 + 空 project_roots)
    //    dev_permissive_firewall 加一条最低 priority 的"catch-all → Approve"兜底 —
    //    让无 EffectKind 匹配的纯计算工具(如 mock echo/sum)走 ApprovalBroker
    //    而非 default-deny。生产模式保持 false。
    let mut policy = PolicyEngine::new(default_ruleset());
    if args.dev_permissive_firewall {
        policy.add_rule(PolicyRule {
            id: "dev-catchall-approve".into(),
            match_effects: vec![], // 空 = 适用任何 effect 组合(含空 EffectVector)
            conditions: vec![],    // 空 = 任何 context 都匹配
            action: PolicyAction::Approve,
            priority: 1, // 最低,让正常 rule 先接管
        });
    }
    // ISS-008 Phase 2 T6:Privacy Filter 注入(fail-fast on startup)。
    //
    // 决策路径:
    //   flag on  + feature on  → OrtPiiScanner(ort_scanner_arc_from_env)
    //                            cold-start ~7 s 在此一次性吃掉,首请求 SLA 不再受影响
    //   flag on  + feature off → ServeError::PrivacyFilterUnavailable(fail-closed)
    //                            **绝不**降级 NoopEngine —— 用户感知 != 实际行为是安全事故
    //   flag off              → 走 Firewall::new 默认(DefaultScanner = NoopEngine model)
    //
    // 不走 OnceLock / Lazy 的理由:启动期一次性 from_env() 失败立即退出更易诊断,
    // 也避免首请求 cold-start latency 暴露给 agent。
    let firewall = if args.enable_privacy_filter {
        #[cfg(feature = "ort")]
        {
            // v0.5 P2 ADR 0012:模型 first-run-download。失败 fail-closed,绝不静默降级
            // NoopEngine —— 用户感知"已启用 Privacy Filter"但实际未生效是安全事故。
            // 内部并发 16 chunk byte-range,sha256 校验,ETag 304 短路。
            let model_paths = vigil_redaction::ensure_model_available(None)
                .map_err(ServeError::BootstrapFailed)?;
            // 桥接到既有 OrtEngine::from_env 接口(env var SSOT;不改 from_env 签名)
            std::env::set_var("VIGIL_PRIVACY_FILTER_MODEL_DIR", model_paths.dir());
            eprintln!(
                "vigil-hub serve: model bootstrap = ok (sha256 verified, dir={})",
                model_paths.dir().display()
            );

            let scanner = vigil_firewall::ort_scanner_arc_from_env()
                .map_err(ServeError::PrivacyFilterInit)?;
            // 启动 banner:stderr 一行标识当前 PiiScanner 类型,运维可观测
            eprintln!("vigil-hub serve: PiiScanner = ort (T0 Privacy Filter active)");
            Arc::new(vigil_firewall::Firewall::with_scanner(
                ledger.clone(),
                policy,
                FirewallConfig::default(),
                scanner,
            ))
        }
        #[cfg(not(feature = "ort"))]
        {
            // fail-closed:flag on 但二进制未编译 ort feature
            return Err(ServeError::PrivacyFilterUnavailable);
        }
    } else {
        eprintln!(
            "vigil-hub serve: PiiScanner = noop \
             (default; pass --enable-privacy-filter + build with --features ort to activate)"
        );
        Arc::new(Firewall::new(
            ledger.clone(),
            policy,
            FirewallConfig::default(),
        ))
    };

    // 3. DescriptorOracle —— Stage 1:静态 ApprovedStable 兜底
    //    Stage 2 应换成 `RegistryDescriptorOracle`,从 Ledger 查 descriptor 实时状态
    let oracle: Arc<dyn DescriptorOracle> =
        Arc::new(StaticDescriptorOracle(DescriptorStatus::ApprovedStable));

    // 4. Hub
    //    **ISS-019 Phase 1 之后**(2026-04-28):approval_wait 直接走 HubConfig::default()
    //    300s,不再被 dev_permissive_firewall 强制缩短到 3s。cross-process approve
    //    (Desktop CLI 写 ledger)由 `wait_for_resolution` 内置 500ms 短轮询 fallback
    //    检出(参见 `crates/vigil-audit/src/approvals.rs::WAIT_POLL_INTERVAL` 注释 +
    //    `crates/vigil-audit/tests/approval_cross_proc_wait.rs` 守门测试 ——
    //    cross-proc approve 实测 ~1.3s 内返回,远低于 300s timeout)。
    //
    //    `dev_permissive_firewall` 现仅控制上面第 2 步的 catch-all Approve 规则
    //    (让 mock echo/sum 等无 EffectKind 工具走 Approval 路径,而非 default-deny);
    //    与 timing 已**完全解耦**。生产仍保持 false。
    let hub_cfg = HubConfig {
        auto_approve_first_seen_tools: args.auto_approve_first_seen,
        ..Default::default()
    };
    let hub = Arc::new(Hub::new(ledger.clone(), firewall, oracle, hub_cfg));
    // set_session_id_for_test 是 lib API 的命名纪律瑕疵(见 feedback);serve 是
    // 生产入口,但 Hub 目前对外只暴露这一个 session 注入方法。v0.3 Stage 2 再
    // 把它改名为 `set_session_id`(同时 `_for_test` 作为 guard 仅 cfg(test) 暴露)。
    hub.set_session_id_for_test(session_id)?;

    // 5. Upstream attach(Stage 2):对 config 的每个 entry 跑完整 onboarding
    if let Some(cfg_path) = args.upstreams_config.as_deref() {
        let raw = std::fs::read_to_string(cfg_path)?;
        let cfg: UpstreamsConfig = serde_json::from_str(&raw)?;
        for entry in &cfg.upstreams {
            attach_stdio_upstream(&ledger, &hub, entry)?;
        }
    }

    Ok((hub, ledger))
}

/// 对单条 upstream entry:
///
/// 1. 构造 `ServerProfile` + `Ledger::register_server`(幂等;already-exists 视为 OK)
/// 2. `Ledger::approve_server(server_id, TrustLevel::Limited)` —— serve 模式下
///    所有 config 里的 upstream 都是用户显式声明要信任的(否则用户不会写到 config)
/// 3. `Hub::spawn_attach_stdio_upstream(name, argv, [])`(V1.1)—— Hub-owned 单一路径:
///    resolve → argv-drift → resolved-program-drift 双 gate → **才** spawn 子进程 → attach。
///    进程在双 gate 通过之前绝不 spawn;`command_hash` 必须与第 1 步算出一致。
///
/// 任一失败即返 Err,caller 决定是否 abort 整个 serve。
pub fn attach_stdio_upstream(
    ledger: &Arc<Ledger>,
    hub: &Arc<Hub>,
    entry: &UpstreamEntry,
) -> Result<(), ServeError> {
    // argv 必须非空(下游 spawn 会拒,但在此提前 fail-closed 给更清晰错)
    if entry.argv.is_empty() {
        return Err(ServeError::InvalidUpstream {
            name: entry.name.clone(),
            reason: "argv is empty",
        });
    }
    if entry.name.is_empty() {
        return Err(ServeError::InvalidUpstream {
            name: String::new(),
            reason: "name is empty",
        });
    }

    // 1. 算 command_hash(与 Hub::attach_upstream 内部算法一致,避免 drift 误判)
    let command_hash = compute_argv_hash(&entry.argv)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let profile = ServerProfile {
        server_id: entry.name.clone(),
        transport: TransportKind::Stdio,
        command: Some(entry.argv.clone()),
        url: None,
        first_seen_at: now,
        command_hash: Some(command_hash),
        descriptor_hash: None,
        trust_level: TrustLevel::Untrusted,
        sandbox_profile_id: None,
    };

    // 2. register(幂等 — 同 command_hash 不会重复插入,返 Ok(false))
    ledger.register_server(&profile)?;
    // 3. approve 到 Limited(serve 模式:config 里声明 = 用户信任)
    ledger.approve_server(&entry.name, TrustLevel::Limited)?;

    // 4. Hub-owned gate-before-spawn(V1.1):resolve → argv-drift → resolved-program-drift → spawn → attach
    //    单一路径替代旧的 StdioUpstream::spawn + attach_upstream 两步,确保进程在双 drift gate
    //    通过**之前绝不 spawn**(封死 public 裸 argv spawn 旁路)。
    hub.spawn_attach_stdio_upstream(&entry.name, &entry.argv, &[])?;

    Ok(())
}

/// stdio 主循环:逐条 JSON-RPC → `Hub::handle_request` → 写响应。
///
/// - EOF(上游关流或 agent 断连)→ `Ok(())` 正常退出
/// - JSON 格式错误 → `Err(ServeError::Json)`,调用方决定是否重启
/// - Hub 错误 → **不**中断循环,把 JSON-RPC error 写回(agent 不应因为单次工具失败断开)
///
/// 通过泛型 `R: BufRead + W: Write` 供测试用 `Cursor` 注入。
pub fn run_stdio_loop<R: BufRead, W: Write>(
    hub: &Hub,
    reader: &mut R,
    writer: &mut W,
) -> Result<(), ServeError> {
    loop {
        let raw = match read_message(reader) {
            Ok(v) => v,
            Err(ProtocolError::Eof) => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        // JSON → JsonRpcRequest(字段缺失也是 protocol error,但不终止循环)
        let req: JsonRpcRequest = match serde_json::from_value(raw.clone()) {
            Ok(r) => r,
            Err(e) => {
                // 返 -32700 Parse error(JSON-RPC 约定)
                let err_resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": raw.get("id"),
                    "error": {"code": -32700, "message": format!("parse error: {}", e)},
                });
                write_message(writer, &err_resp)?;
                continue;
            }
        };

        match hub.handle_request(req) {
            Ok(Some(resp)) => {
                let val = serde_json::to_value(&resp)?;
                write_message(writer, &val)?;
            }
            Ok(None) => {
                // notification,无响应(正常路径)
            }
            Err(e) => {
                // Hub 错误不终止循环,返 JSON-RPC internal error
                let err_resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": raw.get("id"),
                    "error": {"code": -32603, "message": format!("internal: {}", e)},
                });
                write_message(writer, &err_resp)?;
            }
        }
    }
}

/// 实际入口:`vigil-hub serve` 子命令分派到此。
///
/// 从 stdin/stdout 真实 IO 跑循环,阻塞到 agent 断连或 EOF。
pub fn run(args: ServeArgs) -> Result<(), ServeError> {
    let (hub, _ledger) = build_hub(&args)?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = std::io::BufReader::new(stdin.lock());
    let mut writer = stdout.lock();
    run_stdio_loop(&hub, &mut reader, &mut writer)?;
    Ok(())
}

/// 工具函数:检查 config 路径可读,供 CLI 参数预校验使用。
pub fn validate_config_path(path: &Path) -> Result<UpstreamsConfig, ServeError> {
    let raw = std::fs::read_to_string(path)?;
    let cfg: UpstreamsConfig = serde_json::from_str(&raw)?;
    Ok(cfg)
}
