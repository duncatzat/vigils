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

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use thiserror::Error;

use vigil_audit::Ledger;
use vigil_firewall::scorer::DescriptorOracle;
use vigil_firewall::{Firewall, FirewallConfig};
// 可逆脱敏 Slice 2:从 `upstreams.json` 的 `secrets` map 读 env:/keyring: 源装 SecretAliasMap。
use vigil_lease::{KeyringSecretStore, SecretStore, SecretValue};
use vigil_mcp::protocol::{read_message, write_message, ProtocolError};
use vigil_mcp::{
    compute_argv_hash, Hub, HubConfig, HubError, JsonRpcRequest, RegistryDescriptorOracle,
    SecretAliasMap,
};
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

    /// 可逆脱敏 Slice 1:上游工具响应命中硬指纹 secret 时,**in-band** 脱敏 result 后再返回
    /// agent/LLM(默认 off = 既有 out-of-band 仅审计行为)。见 HubConfig::redact_tool_results。
    pub redact_tool_results: bool,

    /// **Monitor posture**(opt-in,非阻塞观察;Codex wrap R1 MEDIUM)。直通 [`HubConfig::monitor_mode`]:
    /// turnkey 无 GUI resolver 时,把本应人审批的风险调用自动放行 + 完整审计(不阻塞),而非阻塞
    /// `approval_wait` 300s 看似卡死。`Denied`/raw-secret/结果脱敏不变量仍在。默认 false = enforce。
    pub monitor: bool,
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
    /// 可逆脱敏 Slice 2:`secret://<alias>` → 真值声明(alias 名 → [`SecretDecl`])。
    ///
    /// agent 在 tool args 里写 `secret://<alias>` 占位,远端 LLM 只见占位符;Vigil 在工具边界
    /// 把它替换成真值(`env:`/`keyring:` 源读取)。**绝不**接受 `literal:`(明文落配置是反模式)。
    /// 每个 alias 必须限定 `server`(D1:最小注入面)。无 `secrets` 段 = 空 map = 任何
    /// `secret://x` 引用都 fail-closed deny。
    #[serde(default)]
    pub secrets: HashMap<String, SecretDecl>,
}

/// 单条 `secret://<alias>` 声明(可逆脱敏 Slice 2)。
#[derive(Debug, Clone, Deserialize)]
pub struct SecretDecl {
    /// 真值来源:`env:<VAR>`(启动期从进程环境读)或 `keyring:<service>/<account>`(OS keychain)。
    /// **拒** `literal:<...>`(secrets-in-config 反模式;dev 用 `env:`)与任何未知 scheme。
    pub source: String,
    /// 限定的上游 server_id —— 该 alias **只**能被解析给这个 server 的 tool call(跨 server
    /// 解析 deny,H5 oracle 防御)。Slice 2 **必填**(设计 D1);留空视为非法声明。
    pub server: String,
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

    /// 可逆脱敏 Slice 2:`secrets` map 里某条 `secret://<alias>` 声明非法
    /// (未知 source scheme / 拒 literal: / 缺 server scope / env var 未设 / keyring 读失败)。
    /// fail-closed 启动失败 —— 绝不带半截 alias map 起 serve(否则用户以为某 alias 可用实际不可)。
    /// **注意**:`reason` 只描述**结构性**问题,绝不含任何真值。
    #[error("secret alias `{alias}` declaration invalid: {reason}")]
    InvalidSecretDecl {
        /// alias 名(非密钥)
        alias: String,
        /// 结构性原因(不含真值)
        reason: String,
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
    // 读 upstreams config 文件(若有)→ 解析,再委托 build_hub_with_config。
    let upstreams_cfg = match args.upstreams_config.as_deref() {
        Some(cfg_path) => {
            let raw = std::fs::read_to_string(cfg_path)?;
            Some(serde_json::from_str::<UpstreamsConfig>(&raw)?)
        }
        None => None,
    };
    build_hub_with_config(args, upstreams_cfg)
}

/// 同 [`build_hub`],但接受**已解析**的 upstreams 配置 —— 供 `vigil-hub wrap` 注入"单 upstream"
/// (透明 shim:把一个已存在的 MCP server 命令作唯一 upstream,无需写临时配置文件)。
pub fn build_hub_with_config(
    args: &ServeArgs,
    upstreams_cfg: Option<UpstreamsConfig>,
) -> Result<(Arc<Hub>, Arc<Ledger>), ServeError> {
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

    // 3. DescriptorOracle —— ledger-backed,call 时实时查 descriptor 状态(取代早期静态
    //    ApprovedStable 兜底)。Codex auto_approve posture review(NIT-1)指出:静态 oracle
    //    会在 call-time 对**任何**工具一律返 ApprovedStable,等于对 descriptor 漂移/未批准
    //    橡皮图章。改用 `RegistryDescriptorOracle` 后,call-time descriptor 状态独立于
    //    `tools/list` 的路由过滤再核一道:
    //      - 已批准且 hash 未变(正常可路由工具)→ ApprovedStable(零额外摩擦);
    //      - 漏到 call 路径的未批准/漂移工具 → FirstSeen/Drifted → 触发审批(fail-closed
    //        纵深防御,不再被静态 oracle 放行)。
    //    Posture 一句话:**信任已配置 server 的 descriptor 用于发现,但 call 仍逐条强制/监控**。
    //    `auto_approve_first_seen_tools` 只控制 `tools/list` 的首见**暴露**,不改这条 call-time 路径。
    let oracle: Arc<dyn DescriptorOracle> = Arc::new(RegistryDescriptorOracle::new(ledger.clone()));

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
        redact_tool_results: args.redact_tool_results,
        monitor_mode: args.monitor,
        ..Default::default()
    };

    // 4'. 可逆脱敏 Slice 2:`secrets` map 在 Hub::new 前就绪 —— alias 真值映射是 Hub 的构造参数
    //     (运行时 only,绝不入账本)。`upstreams_cfg` 由 caller 传入(已解析),既供 secrets 装配
    //     也供下面的 upstream attach。
    let secret_aliases = match &upstreams_cfg {
        Some(cfg) => build_secret_alias_map(&cfg.secrets)?,
        None => SecretAliasMap::default(),
    };

    let hub = Arc::new(Hub::new(
        ledger.clone(),
        firewall,
        oracle,
        hub_cfg,
        secret_aliases,
    ));
    // set_session_id_for_test 是 lib API 的命名纪律瑕疵(见 feedback);serve 是
    // 生产入口,但 Hub 目前对外只暴露这一个 session 注入方法。v0.3 Stage 2 再
    // 把它改名为 `set_session_id`(同时 `_for_test` 作为 guard 仅 cfg(test) 暴露)。
    hub.set_session_id_for_test(session_id)?;

    // 5. Upstream attach(Stage 2):对 config 的每个 entry 跑完整 onboarding。
    //    serve 模式传空 env(走 MCP env 白名单);wrap 模式由 caller 自己 attach 并透传 env。
    if let Some(cfg) = &upstreams_cfg {
        for entry in &cfg.upstreams {
            attach_stdio_upstream(&ledger, &hub, entry, &[])?;
        }
    }

    Ok((hub, ledger))
}

/// 可逆脱敏 Slice 2:从 `secrets` 声明 map 装配 [`SecretAliasMap`](启动期读 env/keyring 真值)。
///
/// fail-closed:任一声明非法(缺 server / 未知 scheme / 拒 literal: / env 未设 / keyring 读失败)
/// 即返 [`ServeError::InvalidSecretDecl`],**绝不**带半截 map 起 serve。`reason` 只描述结构性
/// 问题,不含真值。
fn build_secret_alias_map(
    secrets: &HashMap<String, SecretDecl>,
) -> Result<SecretAliasMap, ServeError> {
    let mut map = SecretAliasMap::default();
    for (alias, decl) in secrets {
        // D1:每个 alias 必须限定 server(最小注入面);空 server 视为非法声明。
        if decl.server.trim().is_empty() {
            return Err(ServeError::InvalidSecretDecl {
                alias: alias.clone(),
                reason: "missing required `server` scope (Slice 2 requires every alias to name a server)"
                    .to_string(),
            });
        }
        let value = resolve_secret_source(alias, &decl.source)?;
        map.insert(alias.clone(), value, decl.server.clone());
    }
    Ok(map)
}

/// 解析单条 secret `source` → 真值(可逆脱敏 Slice 2)。
///
/// 支持 `env:<VAR>` 与 `keyring:<service>/<account>`;**拒** `literal:`(secrets-in-config 反模式)
/// 与任何未知 scheme。错误 `reason` 绝不含真值。
fn resolve_secret_source(alias: &str, source: &str) -> Result<SecretValue, ServeError> {
    let bad = |reason: String| ServeError::InvalidSecretDecl {
        alias: alias.to_string(),
        reason,
    };
    if let Some(var) = source.strip_prefix("env:") {
        if var.is_empty() {
            return Err(bad("empty env var name (expected `env:<VAR>`)".to_string()));
        }
        // 启动期从进程环境读;未设 → fail-closed(不静默置空值)。
        // Code R2 Medium 修复:**不**回显 var 名 —— 误配 `source:"env:<secret>"` 时 var 名可能
        // 本身是误填的 secret。alias 名(operator 配置 key,由 `bad()` 带上)+ operator 自己的
        // 配置已足够定位是哪条 env 源,无需在错误里回显 var 名。
        let v = std::env::var(var).map_err(|_| {
            bad("environment variable referenced by `env:` source is not set".to_string())
        })?;
        Ok(SecretValue::new(v))
    } else if let Some(rest) = source.strip_prefix("keyring:") {
        // 形如 `service/account`;account 部分可含 `/`(取首个 `/` 切分 service)。
        let (service, account) = rest.split_once('/').ok_or_else(|| {
            bad("keyring source must be `keyring:<service>/<account>`".to_string())
        })?;
        if service.is_empty() || account.is_empty() {
            return Err(bad(
                "keyring source must be `keyring:<service>/<account>` (non-empty)".to_string(),
            ));
        }
        // KeyringSecretStore 错误已结构化(不含原文),映射为 reason(仍不含真值)。
        KeyringSecretStore::new(service)
            .get(account)
            .map_err(|e| bad(format!("keyring read failed: {e}")))
    } else if source.starts_with("literal:") {
        Err(bad(
            "`literal:` source is refused (secrets-in-config is an anti-pattern; use `env:` or `keyring:`)"
                .to_string(),
        ))
    } else {
        // Code R1 Medium 修复:**不**回显整个 `source` —— 无 scheme 的误配置(如直接写裸 secret)
        // 会把明文带进启动错误。只描述期望格式;alias 名(operator 配置 key,非密钥)已由 `bad()` 带上。
        Err(bad(
            "unknown secret source scheme (expected `env:<VAR>` or `keyring:<service>/<account>`)"
                .to_string(),
        ))
    }
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
    env: &[(String, String)],
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
    hub.spawn_attach_stdio_upstream(&entry.name, &entry.argv, env)?;

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
/// 网关(优雅 EOF 或错误)关闭时 **best-effort** 锚定审计链头(ADR 0020),让 threat #7(整链
/// 重写)保护对 turnkey 用户**自动生效** —— 他们不会手动跑 `vigil-hub checkpoint`,但每次 agent
/// 会话结束都会自动留下一个锚点(单调:无新事件则不追加)。仅磁盘账本(内存账本无 sidecar);
/// emit 失败只记 stderr,**绝不**影响关闭。stderr 而非 stdout —— stdout 是 MCP 协议通道,不得污染。
///
/// 注:本地 sidecar 锚点检出"仅改数据库"的整链重写;完全闭合还需把 `<ledger>.checkpoints` 外部化
/// (append-only / 异地),见 ADR 0020。
pub fn anchor_checkpoint_on_shutdown(ledger_path: Option<&std::path::Path>, ledger: &Arc<Ledger>) {
    let Some(path) = ledger_path else {
        return; // 内存账本无 sidecar,跳过
    };
    // emit 做**同步阻塞** FS I/O(read_to_string + append + flush + sync_data)。Codex review:放在
    // 关闭主路径上,wedged / remote(NFS/SMB)账本可能卡住网关退出。故把它放独立线程,主线程**有界
    // 等待**(5s);超时即放弃(detached 线程随进程退出结束;atomic append 即便被中断,load 端撕裂行
    // 守门 fail-closed,不留半行污染)。
    let path = path.to_path_buf();
    let ledger = ledger.clone();
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        let log = vigil_audit::CheckpointLog::sidecar_for(&path);
        match log.emit(&ledger) {
            Ok(Some(cp)) => eprintln!(
                "vigil-hub: anchored audit checkpoint at event #{} (full-chain-rewrite guard) -> {}",
                cp.event_id,
                log.path().display()
            ),
            // 空账本 / 自上次锚点无新事件 → 静默(常态,不刷屏)。
            Ok(None) => {}
            Err(e) => eprintln!("vigil-hub: checkpoint on shutdown skipped (non-fatal): {e}"),
        }
        let _ = tx.send(()); // 完成信号;忽略 send 错误(主线程可能已超时离开)
    });
    if rx.recv_timeout(std::time::Duration::from_secs(5)).is_err() {
        eprintln!("vigil-hub: checkpoint on shutdown timed out (>5s), exiting promptly");
    }
}

pub fn run(args: ServeArgs) -> Result<(), ServeError> {
    let (hub, ledger) = build_hub(&args)?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = std::io::BufReader::new(stdin.lock());
    let mut writer = stdout.lock();
    let loop_result = run_stdio_loop(&hub, &mut reader, &mut writer);
    // 无论优雅 EOF 还是协议错误退出,都 best-effort 锚定本会话已写入的审计链头。
    anchor_checkpoint_on_shutdown(args.ledger_path.as_deref(), &ledger);
    loop_result
}

/// 工具函数:检查 config 路径可读,供 CLI 参数预校验使用。
pub fn validate_config_path(path: &Path) -> Result<UpstreamsConfig, ServeError> {
    let raw = std::fs::read_to_string(path)?;
    let cfg: UpstreamsConfig = serde_json::from_str(&raw)?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use vigil_audit::{Anchored, CheckpointLog};

    #[test]
    fn shutdown_anchor_emits_checkpoint_for_disk_ledger() {
        // turnkey 自动锚定:有内容的会话关闭后,sidecar 产出且 verify 通过。
        let dir = tempdir().unwrap();
        let path = dir.path().join("ledger.db");
        let ledger = Arc::new(Ledger::open(&path).unwrap());
        let sid = ledger.start_session("test", None).unwrap();
        ledger
            .append_event(&sid, "test.event", &serde_json::json!({"k":"v"}), None)
            .unwrap();

        anchor_checkpoint_on_shutdown(Some(path.as_path()), &ledger);

        let log = CheckpointLog::sidecar_for(&path);
        assert!(log.path().exists(), "关闭后应产出 checkpoint sidecar");
        assert!(matches!(
            log.verify_anchored(&ledger).unwrap(),
            Anchored::Verified { .. }
        ));
    }

    #[test]
    fn shutdown_anchor_is_noop_for_memory_ledger() {
        // 内存账本(无路径)→ 安全 no-op,不 panic。
        let ledger = Arc::new(Ledger::open_in_memory().unwrap());
        anchor_checkpoint_on_shutdown(None, &ledger);
    }

    #[test]
    fn shutdown_anchor_empty_ledger_writes_no_sidecar() {
        // 空账本(无事件)→ emit None → 不留空 sidecar(不刷屏、不产无意义文件)。
        let dir = tempdir().unwrap();
        let path = dir.path().join("ledger.db");
        let ledger = Arc::new(Ledger::open(&path).unwrap());
        anchor_checkpoint_on_shutdown(Some(path.as_path()), &ledger);
        assert!(
            !CheckpointLog::sidecar_for(&path).path().exists(),
            "空账本不应产 sidecar"
        );
    }
}
