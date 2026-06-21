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
use vigil_http_transport::{
    HttpJwksSource, JwksSignatureVerifier, ReqwestHttpClient, StreamableHttpUpstream,
};
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

    /// DEF-004:firewall 项目边界根(`deny-outside-project` / `approve-repo-write` 的
    /// Inside/Outside 判定基准)。**必须**是经 `normalize_project_root` POSIX 归一后的
    /// 字符串(CLI 层已处理),否则 Windows 下与 PathExtractor 输出前缀不可比 → 边界不绑。
    /// 空 = 不配置边界(policy 引擎空 roots 守门让两条规则都不匹配,FsWrite 落
    /// default-deny floor;monitor 姿态下 floor 被观察放行)。CLI 缺省 = 进程 CWD。
    pub project_roots: Vec<String>,

    /// P0 注入防护 Slice D:启用 DeBERTa prompt-injection 软信号检测(serve warm session)。
    /// fail-closed 同 [`enable_privacy_filter`](Self::enable_privacy_filter):
    /// - flag on + feature on → 启动期 ensure 模型 + warm-load + warmup,descriptor/result 软信号扫描
    /// - flag on + feature off → [`ServeError::InjectionClassifierUnavailable`](绝不静默跳过)
    /// - flag off → 不加载(0 推理开销)
    ///
    /// **软信号铁律**:命中只 bump session risk + 审计,**绝不** deny。
    pub enable_injection_classifier: bool,

    /// ADR 0022 `--engine auto`:**best-effort ML**。`true` 时 ML 引擎只用**本地已缓存**模型
    /// (`model_cached` / `injection_model_cached`,**绝不**触发下载),且 init 失败 / 缓存缺失
    /// → **降级硬指纹**(warn,不 fail-closed 拒启)。`false`(`ml` / legacy)= 严格:
    /// `ensure_*` 可下载 + 缺失/失败 fail-closed 拒启。**硬指纹底座两种模式都常开**。
    /// 注:真 init *hang*(loader-lock)仍由 `run_ort_init_with_timeout` 的 `abort()` 兜底
    /// (ADR 0022 D7;auto 探测要求 dylib 就位已挡掉纯缺失,残留仅"存在但版本错"的罕见情形)。
    pub ml_best_effort: bool,
}

/// DEF-004:把 CLI `--project-root` 解析成 [`ServeArgs::project_roots`]。
///
/// 空 = 缺省**进程 CWD**(serve/wrap 由 agent 在项目目录里启动,CWD 即项目根 —
/// 与 git/cargo 等工具的目录语义一致)。每个 root 经 `normalize_project_root`
/// POSIX 归一,保证与 PathExtractor 输出可比。CWD 不可得(极端:启动目录已删)
/// 时返回空 → 边界不绑但 policy 空 roots 守门兜底 fail-closed,并 stderr 警告。
pub fn resolve_project_roots(cli_roots: &[PathBuf]) -> Vec<String> {
    if cli_roots.is_empty() {
        match std::env::current_dir() {
            Ok(cwd) => vec![vigil_firewall::extract::normalize_project_root(&cwd)],
            Err(e) => {
                eprintln!(
                    "vigil-hub: cannot resolve CWD as project root ({e}); \
                     project boundary rules (deny-outside-project / approve-repo-write) \
                     will not match — pass --project-root <DIR> explicitly."
                );
                Vec::new()
            }
        }
    } else {
        cli_roots
            .iter()
            .map(|p| vigil_firewall::extract::normalize_project_root(p))
            .collect()
    }
}

// ───────────────────────── ADR 0022:引擎选择(hardfp / ml / auto)─────────────────────────

/// 用户面引擎选择三态(`--engine <hardfp|ml|auto>`)。
///
/// 不改 merge 语义(ADR 0013);只决定 **ML 层是否运行**。硬指纹脱敏在三态下**始终常开**。
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum EngineMode {
    /// 仅硬指纹(默认):正则脱敏常开,完全不加载 ML 模型 / onnxruntime。
    /// = 当前发行二进制的实际行为(离线、确定性、零模型依赖)。
    Hardfp,
    /// 严格 ML:启用 OpenAI PII + DeBERTa 注入分类器。缺 feature/模型/dylib → **拒绝启动**
    /// (保留既有 fail-closed:明确要 ML 就必须知道它是否可用,绝不静默裸奔)。
    Ml,
    /// 自动:**仅当**模型已本地缓存且 onnxruntime dylib 就位时启用 ML;否则降级硬指纹 + warn。
    /// 永不触发大文件下载,永不进入 loader-lock 卡死路径(ADR 0022 D4)。
    Auto,
}

/// [`resolve_engine_selection`] 的纯输出:两引擎开关。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineSelection {
    /// → [`ServeArgs::enable_privacy_filter`]
    pub enable_privacy_filter: bool,
    /// → [`ServeArgs::enable_injection_classifier`]
    pub enable_injection_classifier: bool,
}

/// ADR 0022 纯决策函数(无 IO,进默认测试矩阵守门 —— feedback_production_logic_testable)。
///
/// - `engine`:`--engine` 显式值;`None` = 未传(legacy 路径,由裸 `--enable-*` 决定)。
/// - `ort_compiled`:`cfg!(feature = "ort")`(由 caller 传入,便于测试两侧)。
/// - `pf_ready` / `ic_ready`:auto 探测结果(模型已缓存 + dylib 就位);仅 `Auto` 使用。
/// - `bare_privacy` / `bare_injection`:裸 `--enable-privacy-filter` / `--enable-injection-classifier`。
///
/// 决策:
/// - `None`(legacy):严格沿用裸开关(与 ADR 0022 前行为逐字节一致)。
/// - `Hardfp`:两关(若同时给裸开关,由 caller 打 conflict warn,取保守)。
/// - `Ml`:两开(严格;`ort_compiled`/`ready` 不影响决策,缺失由下游 fail-closed 处理)。
/// - `Auto`:ort 未编译 → 两关(静默硬指纹);ort 编译 → 各引擎按 `ready` 探测开关。
pub fn resolve_engine_selection(
    engine: Option<EngineMode>,
    ort_compiled: bool,
    pf_ready: bool,
    ic_ready: bool,
    bare_privacy: bool,
    bare_injection: bool,
) -> EngineSelection {
    match engine {
        None => EngineSelection {
            enable_privacy_filter: bare_privacy,
            enable_injection_classifier: bare_injection,
        },
        Some(EngineMode::Hardfp) => EngineSelection {
            enable_privacy_filter: false,
            enable_injection_classifier: false,
        },
        Some(EngineMode::Ml) => EngineSelection {
            enable_privacy_filter: true,
            enable_injection_classifier: true,
        },
        Some(EngineMode::Auto) if ort_compiled => EngineSelection {
            enable_privacy_filter: pf_ready,
            enable_injection_classifier: ic_ready,
        },
        // Auto on a non-ort build:ML 从未编译进来 → 静默硬指纹(默认发行件的本来形态)。
        Some(EngineMode::Auto) => EngineSelection {
            enable_privacy_filter: false,
            enable_injection_classifier: false,
        },
    }
}

/// CLI → [`EngineSelection`] 解析(含 `auto` 的真实只读探测 + stderr 提示)。
///
/// `From<CliServeArgs>` 调用。探测**只读 fs**(模型已缓存 + dylib 就位),不下载、不调任何
/// ort API(避免 loader-lock hang;ADR 0022 D4)。
pub fn resolve_engine_args(
    engine: Option<EngineMode>,
    bare_privacy: bool,
    bare_injection: bool,
) -> EngineSelection {
    let ort_compiled = cfg!(feature = "ort");

    // auto 探测:模型已本地缓存 + dylib 就位才算 ready(仅 auto 探测;其它模式不触 fs)。
    let (pf_ready, ic_ready) = match engine {
        Some(EngineMode::Auto) => probe_ml_ready(),
        _ => (false, false),
    };

    // 冲突提示:`--engine hardfp` 同时给了裸 `--enable-*` → 取保守(hardfp),stderr 说明(ADR 0022 §4 Q1)。
    if engine == Some(EngineMode::Hardfp) && (bare_privacy || bare_injection) {
        eprintln!(
            "vigil-hub: --engine hardfp overrides --enable-privacy-filter / \
             --enable-injection-classifier (conservative: ML stays off)"
        );
    }

    let sel = resolve_engine_selection(
        engine,
        ort_compiled,
        pf_ready,
        ic_ready,
        bare_privacy,
        bare_injection,
    );

    // auto 降级可观测:请求了 auto 但某引擎未 ready → stderr 说明走硬指纹(ADR 0022 D4)。
    if engine == Some(EngineMode::Auto) {
        if !ort_compiled {
            eprintln!(
                "vigil-hub: --engine auto on a non-ort build → hard-fingerprint only \
                 (rebuild with `--features ort` to enable the ML privacy filter)"
            );
        } else {
            if !sel.enable_privacy_filter {
                eprintln!(
                    "vigil-hub: --engine auto → privacy-filter model not cached or onnxruntime \
                     dylib missing; running hard-fingerprint only (use `--engine ml` to fetch)"
                );
            }
            if !sel.enable_injection_classifier {
                eprintln!(
                    "vigil-hub: --engine auto → injection-classifier model not cached or dylib \
                     missing; injection detection off"
                );
            }
        }
    }
    sel
}

/// `auto` 只读探测:两套模型各自是否已本地缓存,且 onnxruntime dylib 就位。
/// **不**下载、**不**调用任何 ort API(纯 fs 检查,避免 loader-lock hang)。
#[cfg(feature = "ort")]
fn probe_ml_ready() -> (bool, bool) {
    let dylib = ort_dylib_ready();
    let pf = dylib && vigil_redaction::model_cached(None).is_some();
    let ic = dylib && vigil_redaction::injection_model_cached(None).is_some();
    (pf, ic)
}

/// 非 ort build:ML 从未编译进来,探测恒 `(false, false)`。
#[cfg(not(feature = "ort"))]
fn probe_ml_ready() -> (bool, bool) {
    (false, false)
}

/// onnxruntime dylib 是否就位:用户已显式设 `ORT_DYLIB_PATH`,或 exe 同目录有合理大小(>1MB)
/// 的 dylib。**纯只读,无 `set_var` 副作用**(探测期不可改 env —— 见 `build_hub_with_config`
/// 的 set_var 时序不变量)。
#[cfg(feature = "ort")]
fn ort_dylib_ready() -> bool {
    std::env::var_os("ORT_DYLIB_PATH").is_some() || exe_local_dylib_candidate().is_some()
}

/// exe 同目录的 onnxruntime dylib 候选(存在且 >1MB)。纯只读;`prepare_ort_dylib_path` 与
/// `ort_dylib_ready` 共用此判定(SSOT,避免大小启发式漂移)。
#[cfg(feature = "ort")]
fn exe_local_dylib_candidate() -> Option<PathBuf> {
    let dylib_name = if cfg!(target_os = "windows") {
        "onnxruntime.dll"
    } else if cfg!(target_os = "macos") {
        "libonnxruntime.dylib"
    } else {
        "libonnxruntime.so"
    };
    let candidate = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(dylib_name)))?;
    // 大小启发式:真 ORT ~10-15MB;排除 System32 KB 级 stub / 0 字节占位。
    if candidate
        .metadata()
        .map(|m| m.len() > 1_000_000)
        .unwrap_or(false)
    {
        Some(candidate)
    } else {
        None
    }
}

#[cfg(test)]
mod engine_selection_tests {
    use super::{resolve_engine_selection as r, EngineMode, EngineSelection};

    fn sel(pf: bool, ic: bool) -> EngineSelection {
        EngineSelection {
            enable_privacy_filter: pf,
            enable_injection_classifier: ic,
        }
    }

    #[test]
    fn legacy_none_uses_bare_flags() {
        // None = --engine 未传 → 逐字节沿用裸开关(ADR 0022 前行为)。
        assert_eq!(r(None, true, false, false, false, false), sel(false, false));
        assert_eq!(r(None, true, false, false, true, false), sel(true, false));
        assert_eq!(r(None, false, false, false, true, true), sel(true, true));
    }

    #[test]
    fn hardfp_forces_both_off_ignoring_bare() {
        assert_eq!(
            r(Some(EngineMode::Hardfp), true, true, true, true, true),
            sel(false, false)
        );
    }

    #[test]
    fn ml_forces_both_on_regardless_of_compile_or_ready() {
        // 严格:决策恒两开;缺 feature/模型由下游 fail-closed 处理,不在本纯函数。
        assert_eq!(
            r(Some(EngineMode::Ml), false, false, false, false, false),
            sel(true, true)
        );
    }

    #[test]
    fn auto_on_non_ort_is_silent_hardfp() {
        assert_eq!(
            r(Some(EngineMode::Auto), false, true, true, false, false),
            sel(false, false)
        );
    }

    #[test]
    fn auto_on_ort_follows_per_engine_readiness() {
        assert_eq!(
            r(Some(EngineMode::Auto), true, true, true, false, false),
            sel(true, true)
        );
        assert_eq!(
            r(Some(EngineMode::Auto), true, false, false, false, false),
            sel(false, false)
        );
        // 各引擎独立:PII 就位、注入未就位。
        assert_eq!(
            r(Some(EngineMode::Auto), true, true, false, false, false),
            sel(true, false)
        );
    }
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

/// 远端 HTTP MCP 上游的鉴权来源(ADR 0021 §3.3)。token 经 planner 注入,类型上不可 passthrough。
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HttpAuth {
    /// 无鉴权(public MCP / 本地 mock)。
    #[default]
    None,
    /// 静态 Bearer / PAT —— `source` 走 `env:<VAR>` 或 `keyring:<svc>/<acct>`(**拒** literal,
    /// 同 secrets 纪律);token 启动期读出后只活内存 `SecretValue`,绝不入审计 / 错误(Slice 4)。
    Bearer {
        /// 真值来源(`env:` / `keyring:`)。
        source: String,
    },
    /// OAuth access token —— 复用 `add-remote-mcp` 持久化的 token(以 resource + client_id 引用)。
    OAuth {
        /// 受保护资源 URL(token 绑定的 audience)。
        resource: String,
        /// OAuth client_id。
        client_id: String,
    },
}

/// MCP HTTP 传输修订提示(ADR 0021 §1.2)。
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HttpTransportHint {
    /// Streamable HTTP(2025-03,现行,默认)。
    Streamable,
    /// Legacy HTTP+SSE 双 endpoint(2024-11,Slice 5)。
    LegacySse,
}

/// 单条 upstream 定义。**加性**:旧 `{name,argv}` config 仍命中 [`UpstreamEntry::Stdio`] → 零破坏;
/// 新增 `{name,url,..}` 命中 [`UpstreamEntry::Http`]。
///
/// 用**自定义 [`Deserialize`]**(经 [`UpstreamEntryRaw`] flat 中间体)做 `argv` XOR `url` 显式分流:
/// `{name,argv,url}` 歧义、两者皆缺、stdio 上误挂 `auth`/`transport_hint` 全 **fail-closed 报错**
/// (MF#3:非静默丢字段)。注:`#[serde(untagged)]` + 每变体 `deny_unknown_fields` **serde 不支持**
/// (untagged 下 deny_unknown_fields 致 derive 不生成 `Deserialize` impl,实测 E0277),故手写。
#[derive(Debug, Clone)]
pub enum UpstreamEntry {
    /// stdio 子进程上游(argv 启动)。
    Stdio {
        /// server 名(Vigil 内部唯一 + namespace 暴露给 agent)。
        name: String,
        /// 子进程 argv(argv[0]=可执行,后续参数)。
        argv: Vec<String>,
    },
    /// 远端 HTTP MCP 上游(Streamable HTTP,ADR 0021 Slice 1+)。
    Http {
        /// server 名。
        name: String,
        /// MCP endpoint(生产仅 `https://`;`http://` 仅 loopback 本地 mock)。
        url: String,
        /// 鉴权来源(默认 [`HttpAuth::None`])。
        auth: HttpAuth,
        /// 传输修订提示(默认 Streamable)。
        transport_hint: Option<HttpTransportHint>,
    },
}

/// [`UpstreamEntry`] 的 flat 反序列化中间体:`deny_unknown_fields` 拒未知键;`argv`/`url` 用
/// `Option` 区分"是否给出",由 [`UpstreamEntry`] 的手写 `Deserialize` 做 XOR 分流。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpstreamEntryRaw {
    name: String,
    #[serde(default)]
    argv: Option<Vec<String>>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    auth: Option<HttpAuth>,
    #[serde(default)]
    transport_hint: Option<HttpTransportHint>,
}

impl<'de> Deserialize<'de> for UpstreamEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;
        let raw = UpstreamEntryRaw::deserialize(deserializer)?;
        match (raw.argv, raw.url) {
            (Some(argv), None) => {
                // stdio:不接受 http-only 字段(防误配被静默忽略)。
                if raw.auth.is_some() || raw.transport_hint.is_some() {
                    return Err(D::Error::custom(
                        "`auth`/`transport_hint` are only valid for http upstreams (this entry has `argv` = stdio)",
                    ));
                }
                Ok(UpstreamEntry::Stdio {
                    name: raw.name,
                    argv,
                })
            }
            (None, Some(url)) => Ok(UpstreamEntry::Http {
                name: raw.name,
                url,
                auth: raw.auth.unwrap_or_default(),
                transport_hint: raw.transport_hint,
            }),
            (Some(_), Some(_)) => Err(D::Error::custom(
                "upstream entry has both `argv` (stdio) and `url` (http); specify exactly one",
            )),
            (None, None) => Err(D::Error::custom(
                "upstream entry needs either `argv` (stdio) or `url` (http)",
            )),
        }
    }
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
        "the ML redaction engine (requested via `--engine ml`, or the legacy \
         `--enable-privacy-filter`) needs a build with `--features ort`, but this `vigil-hub` was \
         not built with it. Use the ML variant `vigils-cli-ml-<platform>` from the releases page, \
         or rebuild with `--features ort`."
    )]
    PrivacyFilterUnavailable,

    /// ISS-008 Phase 2:`OrtEngine::from_env()` 启动期失败(env 未设 / 模型缺失 /
    /// Session init 失败 / config.json 解析等)。fail-fast 在启动期吃掉 cold-start
    /// ~7s,首请求 SLA 不再受影响。
    #[error("privacy filter init failed: {0}")]
    PrivacyFilterInit(#[from] vigil_redaction::engine::EngineError),

    /// P0 注入防护 Slice D:运行期 `--enable-injection-classifier` 请求 DeBERTa 注入分类器,
    /// 但当前二进制**未**用 `--features ort` 编译。fail-closed 启动失败,绝不静默跳过
    /// (否则用户感知"已启用注入检测"实际未生效是安全事故)。
    #[error(
        "the DeBERTa injection classifier (requested via `--enable-injection-classifier`) needs a \
         build with `--features ort`, but this `vigil-hub` was not built with it. Use the ML \
         variant `vigils-cli-ml-<platform>` from the releases page, or rebuild with `--features ort`."
    )]
    InjectionClassifierUnavailable,

    /// P0 注入防护 Slice D:DeBERTa 分类器装载失败(Session init / config 解析 / tokenizer)。
    /// 与 [`PrivacyFilterInit`](Self::PrivacyFilterInit)同级 fail-closed;独立 variant 便于诊断
    /// 是哪个引擎失败(`EngineError` 已被 `PrivacyFilterInit` `#[from]`,故此处手动 `map_err`)。
    #[error("injection classifier init failed: {0}")]
    InjectionClassifierInit(vigil_redaction::engine::EngineError),

    /// v0.5 P2 ADR 0012:`ensure_model_available` 启动期失败(下载 / sha256 / 磁盘 /
    /// 全 mirror 不可达)。BootstrapError 5 变体 fail-closed,**绝不**降级 NoopEngine,
    /// 与 PrivacyFilterUnavailable / PrivacyFilterInit 同级。
    #[cfg(feature = "ort")]
    #[error("model bootstrap failed: {0}")]
    BootstrapFailed(#[from] vigil_redaction::BootstrapError),

    /// 优化问题 B(Codex 交叉审查 MEDIUM):ort 初始化工作线程 **panic**(channel Disconnected,
    /// **非**超时)。panic unwind 已正常释放栈,**不**持 Windows loader lock → 可干净
    /// fail-closed 返 Err,而非走超时分支的 `abort()`。`what` 标明是哪条 ort 路径
    /// (injection classifier / privacy filter),静态字面量、不含任何敏感值。
    #[cfg(feature = "ort")]
    #[error(
        "{what} init worker panicked (not a timeout — check model / onnxruntime.dll integrity)"
    )]
    OrtInitPanicked {
        /// 出错的 ort 路径名(静态字面量,非敏感)
        what: &'static str,
    },
}

/// 优化问题 B:DeBERTa 装载超时上限(秒)。正常 warm-load(ensure 命中 + from_model_dir + warmup)
/// 在几秒内;远超此值几乎必然是 ort 误加载错误 onnxruntime.dll 后的 init hang。45s 给真慢磁盘
/// + 738MB FP32 模型 cold-load 留足余量。
#[cfg(feature = "ort")]
const ORT_INIT_TIMEOUT_SECS: u64 = 45;

/// 优化问题 B:在任何 ort API 调用前,优先把 `ORT_DYLIB_PATH` 指向**可执行文件同目录**的
/// onnxruntime dylib,绕开 ort load-dynamic 默认走系统 LoadLibrary 误命中 System32 错误/stub
/// dll(实测 2.8KB 假 dll)导致的 init hang。
///
/// 纪律:① 用户已显式设 `ORT_DYLIB_PATH` → 尊重不覆盖;② 仅当 exe 同目录存在**合理大小**
/// (>1MB,排除 KB 级 stub)的 dylib 才设 —— 注:大小启发式**不**校验版本/ABI,放错版本的
/// 大 dll 仍可能被选中,需 operator 保证是 ORT 1.24;③ 找不到则不设 —— 交给 ort 默认查找 +
/// 下游 [`run_ort_init_with_timeout`] 超时兜底(真超时 `abort()` / worker panic 返
/// [`ServeError::OrtInitPanicked`])。
#[cfg(feature = "ort")]
fn prepare_ort_dylib_path() {
    if std::env::var_os("ORT_DYLIB_PATH").is_some() {
        return; // 尊重用户显式指定
    }
    // SSOT:与 `ort_dylib_ready`(auto 探测)共用 exe-local 候选判定(>1MB 启发式),避免漂移。
    if let Some(candidate) = exe_local_dylib_candidate() {
        std::env::set_var("ORT_DYLIB_PATH", &candidate);
        eprintln!(
            "vigil-hub serve: ORT_DYLIB_PATH = {} (exe-local; avoids system stub dll; \
             size>1MB heuristic only — ensure it is ORT 1.24)",
            candidate.display()
        );
    }
}

/// 优化问题 B(hostile + Codex 交叉审查 H-1):ort 初始化结局三态。`run_ort_init_with_timeout`
/// 返回此枚举,封死"只保护一条 ort 路径"的不对称缺口。
#[cfg(feature = "ort")]
enum OrtInitOutcome {
    /// build 自身干净返 Err(env 缺 / 模型缺 / Session init 失败 —— 可恢复诊断)。
    Failed(vigil_redaction::engine::EngineError),
    /// worker 线程 **panic**(channel `Disconnected`;**非**超时)。panic unwind 已释放栈、
    /// 不持 loader lock → 调用方干净 fail-closed 返 Err,**不** abort。
    Panicked,
}

/// 优化问题 B(hostile + Codex 交叉审查 H-1):把"ort 初始化(dlopen + Session 创建)放工作
/// 线程 + 主线程 `recv_timeout` 超时"封装成**共享** helper —— injection classifier 与
/// privacy filter 两条 ort 路径**都**经此,补齐此前仅 injection 有兜底、privacy 路径 ort init
/// hang 原样残留的不对称缺口。
///
/// 三种结局:
/// - `Ok(value)` —— build 成功(已含调用方在闭包内的 warmup 等副作用)。
/// - `Err(OrtInitOutcome::Failed(e))` —— build 干净返 Err。
/// - `Err(OrtInitOutcome::Panicked)` —— worker panic(`Disconnected`;非超时)。Codex 审查
///   MEDIUM:`Disconnected` 不能与超时混判,否则误诊断 + 不必要 abort;panic 不持 loader
///   lock,可干净返 Err。
/// - **真超时不返回**:worker 极可能 hang 在 ort `LoadLibrary` 持 **Windows loader lock**,
///   优雅退出(ExitProcess)会等 loader lock → 死锁(实测进程残留,连 `taskkill /F` 都杀不掉)。
///   故 `abort()`(经 `__fastfail` 内核级立即终止,绕过 loader lock)。
///
/// `what` 仅用于超时诊断打印(静态字面量,非敏感)。
#[cfg(feature = "ort")]
fn run_ort_init_with_timeout<T: Send + 'static>(
    what: &'static str,
    build: impl FnOnce() -> Result<T, vigil_redaction::engine::EngineError> + Send + 'static,
) -> Result<T, OrtInitOutcome> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(build()); // 接收端超时/panic 后本 send 失败,无害
    });
    match rx.recv_timeout(std::time::Duration::from_secs(ORT_INIT_TIMEOUT_SECS)) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(OrtInitOutcome::Failed(e)),
        // worker 未 send 即退出(panic):栈已 unwind,不持 loader lock → 干净返 Err。
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(OrtInitOutcome::Panicked),
        // 真超时:worker 极可能 hang 在 loader lock,只能 abort 绕过(见上文)。
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            eprintln!(
                "vigil-hub serve: {what} init timed out (~{ORT_INIT_TIMEOUT_SECS}s) — likely a \
                 wrong/stub onnxruntime.dll on the system path, or model cold-load on a very slow / \
                 remote disk. Place the correct ORT 1.24 onnxruntime.dll next to the executable or \
                 set ORT_DYLIB_PATH, then retry. Aborting."
            );
            std::process::abort();
        }
    }
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

    // 优化问题 B:在**任何 ort 路径**(privacy filter / injection classifier)前稳住 onnxruntime
    // dylib 来源 —— ort load-dynamic 默认走系统 LoadLibrary,Windows 上可能命中 System32 的
    // 错误/stub onnxruntime.dll → init 静默 hang。优先用 exe 同目录的 dll(未设 ORT_DYLIB_PATH 时)。
    //
    // **并发安全不变量(必须维持 —— hostile L-1 + Codex HIGH-2)**:此处 `set_var(ORT_DYLIB_PATH)`
    // 与下方 privacy 分支的 `set_var(VIGIL_PRIVACY_FILTER_MODEL_DIR)` 必须在**任何 `thread::spawn`
    // 之前**完成 —— `set_var` 在有其他线程并发读环境时是 data-race UB(glibc setenv/getenv)。
    // 当前到此点为止全程单线程(ledger open 无后台线程;模型下载用 `thread::scope` 已 join);
    // 唯一的 ort 工作线程由 `run_ort_init_with_timeout` 在更后面才 spawn → set_var happens-before
    // 成立。谁在这两个 set_var 之前新增 `thread::spawn`,谁就破坏此不变量。
    #[cfg(feature = "ort")]
    if args.enable_injection_classifier || args.enable_privacy_filter {
        prepare_ort_dylib_path();
    }

    // 2. Firewall(默认策略集 + project_roots 边界)
    //    dev_permissive_firewall 加一条最低 priority 的"catch-all → Approve"兜底 —
    //    让无 EffectKind 匹配的纯计算工具(如 mock echo/sum)走 ApprovalBroker
    //    而非 default-deny。生产模式保持 false。
    //
    // DEF-004:project_roots 装进 FirewallConfig,让 deny-outside-project /
    // approve-repo-write 真正绑定边界(此前所有生产入口都是空 roots,Outside
    // 语义反转把整盘判成"项目外")。roots 由 CLI 层归一(normalize_project_root)。
    let firewall_config = FirewallConfig {
        project_roots: args.project_roots.clone(),
        ..FirewallConfig::default()
    };
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
    // ADR 0022:先解析 ML scanner(`Some`=启用 / `None`=硬指纹),再统一建 firewall。
    //   - 严格(`ml` / legacy,`ml_best_effort=false`):`ensure_model_available` 可下载;模型
    //     缺失 / init 失败 → fail-closed 拒启(感知"已启用"但未生效是安全事故)。
    //   - best-effort(`--engine auto`,`ml_best_effort=true`):只用**本地已缓存**模型
    //     (`model_cached`,**绝不**下载;消除 TOCTOU 重下载窗口);缓存缺失 / init 失败(可捕获)
    //     → 降级硬指纹 + warn(D6)。真 init *hang* 仍由 `run_ort_init_with_timeout` `abort()`
    //     兜底(D7;auto 探测已要求 dylib 就位,残留仅"存在但版本错"的罕见情形)。
    let ort_scanner: Option<Arc<dyn vigil_firewall::PiiScanner>> = if args.enable_privacy_filter {
        #[cfg(feature = "ort")]
        {
            let model_dir = if args.ml_best_effort {
                vigil_redaction::model_cached(None).map(|p| p.dir().to_path_buf())
            } else {
                // v0.5 P2 ADR 0012:first-run-download(16 chunk byte-range + sha256 + ETag 304)。
                Some(
                    vigil_redaction::ensure_model_available(None)
                        .map_err(ServeError::BootstrapFailed)?
                        .dir()
                        .to_path_buf(),
                )
            };
            match model_dir {
                None => {
                    // best-effort + 模型未缓存 → 降级硬指纹(绝不触发下载)。
                    eprintln!(
                        "vigil-hub serve: --engine auto: privacy-filter model not cached; \
                         hard-fingerprint only"
                    );
                    None
                }
                Some(dir) => {
                    // 桥接到既有 OrtEngine::from_env 接口(env var SSOT;不改 from_env 签名)。
                    std::env::set_var("VIGIL_PRIVACY_FILTER_MODEL_DIR", &dir);
                    eprintln!(
                        "vigil-hub serve: privacy model ready (dir={})",
                        dir.display()
                    );
                    // 共享 `run_ort_init_with_timeout`:真超时 → `abort()`(loader-lock 安全);
                    // Failed/Panicked → 严格 fail-closed,或 best-effort 降级硬指纹。
                    match run_ort_init_with_timeout(
                        "privacy filter",
                        vigil_firewall::ort_scanner_arc_from_env,
                    ) {
                        Ok(scanner) => Some(scanner),
                        Err(o) if args.ml_best_effort => {
                            let reason = match o {
                                OrtInitOutcome::Failed(e) => format!("init failed: {e}"),
                                OrtInitOutcome::Panicked => "init worker panicked".to_string(),
                            };
                            eprintln!(
                                "vigil-hub serve: --engine auto: privacy filter {reason}; \
                                 degrading to hard-fingerprint only"
                            );
                            None
                        }
                        Err(OrtInitOutcome::Failed(e)) => {
                            return Err(ServeError::PrivacyFilterInit(e))
                        }
                        Err(OrtInitOutcome::Panicked) => {
                            return Err(ServeError::OrtInitPanicked {
                                what: "privacy filter",
                            })
                        }
                    }
                }
            }
        }
        #[cfg(not(feature = "ort"))]
        {
            // flag on 但未编译 ort:严格 → fail-closed 拒启;best-effort → 降级硬指纹。
            if args.ml_best_effort {
                eprintln!(
                    "vigil-hub serve: --engine auto on a non-ort build: privacy filter \
                     unavailable; hard-fingerprint only"
                );
                None
            } else {
                return Err(ServeError::PrivacyFilterUnavailable);
            }
        }
    } else {
        None
    };
    let firewall: Arc<Firewall> = match ort_scanner {
        Some(scanner) => {
            // 启动 banner:stderr 一行标识当前 PiiScanner 类型,运维可观测。
            eprintln!("vigil-hub serve: PiiScanner = ort (T0 Privacy Filter active)");
            Arc::new(vigil_firewall::Firewall::with_scanner(
                ledger.clone(),
                policy,
                firewall_config,
                scanner,
            ))
        }
        None => {
            eprintln!(
                "vigil-hub serve: PiiScanner = noop \
                 (hard-fingerprint redaction active; ML privacy filter off)"
            );
            Arc::new(Firewall::new(ledger.clone(), policy, firewall_config))
        }
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

    #[cfg_attr(not(feature = "ort"), allow(unused_mut))]
    let mut hub_inner = Hub::new(ledger.clone(), firewall, oracle, hub_cfg, secret_aliases);

    // P0 注入防护 Slice D:DeBERTa 注入分类器 warm-load(fail-closed 双分支,复刻上面
    // enable_privacy_filter 的 fail-closed 纪律 —— flag on + feature off 绝不静默降级)。
    if args.enable_injection_classifier {
        #[cfg(feature = "ort")]
        {
            // best-effort(auto):只用本地已缓存(无下载);严格(ml/legacy)走 ensure(可下载)。
            let model_dir = if args.ml_best_effort {
                vigil_redaction::injection_model_cached(None).map(|p| p.dir().to_path_buf())
            } else {
                // 独立 manifest(deberta-injection-v2/ 目录)→ ensure 三件套(16 chunk + sha256)。
                Some(
                    vigil_redaction::ensure_injection_model_available(None)
                        .map_err(ServeError::BootstrapFailed)?
                        .dir()
                        .to_path_buf(),
                )
            };
            match model_dir {
                None => {
                    // best-effort + 模型未缓存 → 注入检测 off(绝不下载;软信号缺位不破 fail-safe)。
                    eprintln!(
                        "vigil-hub serve: --engine auto: injection-classifier model not cached; \
                         injection detection off"
                    );
                }
                Some(dir) => {
                    // from_model_dir 内部 ort dlopen + Session;错误 dll 静默 hang → 共享
                    // `run_ort_init_with_timeout`(真超时 abort loader-lock 安全;panic 转清晰报错)。
                    // warmup 一并纳入超时窗口。
                    let banner_dir = dir.clone();
                    let init = run_ort_init_with_timeout("injection classifier", move || {
                        vigil_redaction::InjectionClassifier::from_model_dir(&dir).inspect(|c| {
                            let _ = c.warmup(); // graph optimize / kernel JIT cold-path 前移到启动期
                        })
                    });
                    match init {
                        Ok(classifier) => {
                            eprintln!(
                                "vigil-hub serve: InjectionClassifier = deberta (warm; dir={})",
                                banner_dir.display()
                            );
                            hub_inner = hub_inner.with_injection_classifier(Arc::new(classifier));
                        }
                        Err(o) if args.ml_best_effort => {
                            let reason = match o {
                                OrtInitOutcome::Failed(e) => format!("init failed: {e}"),
                                OrtInitOutcome::Panicked => "init worker panicked".to_string(),
                            };
                            eprintln!(
                                "vigil-hub serve: --engine auto: injection classifier {reason}; \
                                 injection detection off"
                            );
                        }
                        Err(OrtInitOutcome::Failed(e)) => {
                            return Err(ServeError::InjectionClassifierInit(e))
                        }
                        Err(OrtInitOutcome::Panicked) => {
                            return Err(ServeError::OrtInitPanicked {
                                what: "injection classifier",
                            })
                        }
                    }
                }
            }
        }
        #[cfg(not(feature = "ort"))]
        {
            // flag on 但未编译 ort:严格 → fail-closed 拒启;best-effort → 注入检测 off。
            if args.ml_best_effort {
                eprintln!(
                    "vigil-hub serve: --engine auto on a non-ort build: injection \
                     classifier unavailable; injection detection off"
                );
            } else {
                return Err(ServeError::InjectionClassifierUnavailable);
            }
        }
    } else {
        eprintln!(
            "vigil-hub serve: InjectionClassifier = off \
             (default; pass --enable-injection-classifier + build with --features ort to activate)"
        );
    }

    let hub = Arc::new(hub_inner);
    // set_session_id_for_test 是 lib API 的命名纪律瑕疵(见 feedback);serve 是
    // 生产入口,但 Hub 目前对外只暴露这一个 session 注入方法。v0.3 Stage 2 再
    // 把它改名为 `set_session_id`(同时 `_for_test` 作为 guard 仅 cfg(test) 暴露)。
    hub.set_session_id_for_test(session_id)?;

    // 5. Upstream attach(Stage 2):对 config 的每个 entry 跑完整 onboarding。
    //    serve 模式传空 env(走 MCP env 白名单);wrap 模式由 caller 自己 attach 并透传 env。
    if let Some(cfg) = &upstreams_cfg {
        for entry in &cfg.upstreams {
            match entry {
                UpstreamEntry::Stdio { name, argv } => {
                    attach_stdio_upstream(&ledger, &hub, name, argv, &[])?;
                }
                UpstreamEntry::Http {
                    name,
                    url,
                    auth,
                    transport_hint,
                } => {
                    attach_http_upstream(&ledger, &hub, name, url, auth, *transport_hint)?;
                }
            }
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
    name: &str,
    argv: &[String],
    env: &[(String, String)],
) -> Result<(), ServeError> {
    // argv 必须非空(下游 spawn 会拒,但在此提前 fail-closed 给更清晰错)
    if argv.is_empty() {
        return Err(ServeError::InvalidUpstream {
            name: name.to_string(),
            reason: "argv is empty",
        });
    }
    if name.is_empty() {
        return Err(ServeError::InvalidUpstream {
            name: String::new(),
            reason: "name is empty",
        });
    }

    // 1. 算 command_hash(与 Hub::attach_upstream 内部算法一致,避免 drift 误判)
    let command_hash = compute_argv_hash(argv)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let profile = ServerProfile {
        server_id: name.to_string(),
        transport: TransportKind::Stdio,
        command: Some(argv.to_vec()),
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
    ledger.approve_server(name, TrustLevel::Limited)?;

    // 4. Hub-owned gate-before-spawn(V1.1):resolve → argv-drift → resolved-program-drift → spawn → attach
    //    单一路径替代旧的 StdioUpstream::spawn + attach_upstream 两步,确保进程在双 drift gate
    //    通过**之前绝不 spawn**(封死 public 裸 argv spawn 旁路)。
    hub.spawn_attach_stdio_upstream(name, argv, env)?;

    Ok(())
}

/// 远端 HTTP MCP 上游 onboarding(ADR 0021 Slice 1)。
///
/// 先 [`validate_http_upstream_config`](纯:scheme / **SSRF** / auth-format / transport),
/// 再构造 [`StreamableHttpUpstream`] + register/approve + `hub.attach_upstream` —— 挂上即
/// 继承全部传输无关安全不变量(firewall/detokenize/redaction/audit)。
///
/// Slice 1 只 wire **Bearer**(`env:`/`keyring:` 静态 token);OAuth / 无鉴权(public)留后续,
/// 命中即 fail-closed 报错(绝不静默忽略一个 HTTP upstream config)。
fn attach_http_upstream(
    ledger: &Arc<Ledger>,
    hub: &Arc<Hub>,
    name: &str,
    url: &str,
    auth: &HttpAuth,
    transport_hint: Option<HttpTransportHint>,
) -> Result<(), ServeError> {
    let invalid = |reason: &'static str| ServeError::InvalidUpstream {
        name: name.to_string(),
        reason,
    };
    // 1. 纯校验(scheme / SSRF / auth-format / transport)。
    let parsed = validate_http_upstream_config(name, url, auth, transport_hint)?;

    // 2. 构造 upstream(Slice 1:Bearer wired;OAuth/None 留后续)。
    let sender: Arc<dyn vigil_http_auth::AuthorizedSender> =
        Arc::new(ReqwestHttpClient::new().map_err(|_| invalid("failed to build https client"))?);
    let upstream: Arc<dyn vigil_mcp::McpUpstream> = match auth {
        HttpAuth::Bearer { source } => {
            // 启动期读真值(env:/keyring:);token 只活内存 SecretValue,绝不入审计/错误。
            let token = resolve_secret_source(name, source)?;
            Arc::new(StreamableHttpUpstream::with_bearer(
                name, parsed, token, sender,
            ))
        }
        HttpAuth::OAuth {
            resource,
            client_id,
        } => {
            // OAuth serve 期接线:从 `add-remote-mcp` 已落库 token metadata 重建 ExpectedBinding
            // (含 JWKS 验证器),经 AS re-discovery 拿 jwks_uri ——**无需浏览器**(token 已在库)。
            // prod deps:一个 ReqwestHttpClient 同时充当 discovery HttpClient 与 sealed
            // AuthorizedSender;keyring service "vigil"(与 add_remote.rs 落库一致)。DI seam =
            // [`build_oauth_upstream`](供 mock-AS 单测验 positive / issuer-drift 安全分支)。
            let client = Arc::new(
                ReqwestHttpClient::new().map_err(|_| invalid("failed to build https client"))?,
            );
            let http: Arc<dyn vigil_http_auth::HttpClient> = client.clone();
            let oauth_sender: Arc<dyn vigil_http_auth::AuthorizedSender> = client;
            let secret_store: Arc<dyn SecretStore> = Arc::new(KeyringSecretStore::new("vigil"));
            build_oauth_upstream(
                ledger,
                name,
                parsed,
                resource,
                client_id,
                http,
                secret_store,
                oauth_sender,
            )?
        }
        HttpAuth::None => Arc::new(StreamableHttpUpstream::with_none(name, parsed, sender)),
    };

    // 3. register(幂等)→ approve(Limited)→ attach(HTTP 无 argv → 空 argv,drift gate no-op)。
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let profile = ServerProfile {
        server_id: name.to_string(),
        transport: TransportKind::Http,
        command: None,
        url: Some(url.to_string()),
        first_seen_at: now,
        command_hash: None,
        descriptor_hash: None,
        trust_level: TrustLevel::Untrusted,
        sandbox_profile_id: None,
    };
    ledger.register_server(&profile)?;
    ledger.approve_server(name, TrustLevel::Limited)?;
    hub.attach_upstream(name, &[], upstream)?;
    Ok(())
}

/// 构造 OAuth `StreamableHttpUpstream`(DI seam —— `http`=discovery+JWKS client、`secret_store`=
/// token 库、`sender`=sealed 发送器;prod 由 [`attach_http_upstream`] 注入 ReqwestHttpClient +
/// KeyringSecretStore("vigil"),单测注入 MockHttpClient + InMemorySecretStore)。
///
/// 从 `add-remote-mcp` 已落库 token metadata 重建 [`vigil_http_auth::ExpectedBinding`](含 JWKS
/// 验证器):`get_metadata` 取 issuer / AS url / scope → AS re-discovery 拿 `jwks_uri` → 建 verifier。
/// **fail-closed**:metadata 缺失(没 onboard)/ resource 与 mcp_url 异源 / AS 或 jwks_uri 命中
/// SSRF denylist / AS 不可达 / **issuer 漂移**(AS 改 issuer = 可疑,拒)→ 不构造(绝不放未验证
/// 上游;错误 verifier = 接受伪造 token,安全最敏感一环)。仅支持 JWT access token
/// (`introspection=None`);opaque token 走 introspection 留后续。
///
/// **信任边界(hostile review Finding 7,tracked follow-up)**:整条验证信任链(issuer / AS /
/// resource)从 `oauth_token_metadata` SQLite 行重建,而该行**未**进 `vigil-audit` 哈希链 —— 能写
/// ledger DB **且**能写 keyring 者可篡改信任锚伪造 token(本地篡改,高门槛威胁)。审计链绑定 / 行
/// MAC 是跨 onboarding + audit 的独立 slice,留后续。
#[allow(clippy::too_many_arguments)]
fn build_oauth_upstream(
    ledger: &Arc<Ledger>,
    name: &str,
    mcp_url: url::Url,
    resource: &str,
    client_id: &str,
    http: Arc<dyn vigil_http_auth::HttpClient>,
    secret_store: Arc<dyn SecretStore>,
    sender: Arc<dyn vigil_http_auth::AuthorizedSender>,
) -> Result<Arc<dyn vigil_mcp::McpUpstream>, ServeError> {
    let invalid = |reason: &'static str| ServeError::InvalidUpstream {
        name: name.to_string(),
        reason,
    };
    let token_store = Arc::new(vigil_http_auth::TokenStore::new(
        secret_store,
        ledger.clone(),
    ));
    let token_ref = vigil_http_auth::token_ref_for_access(resource, client_id);

    // 持久化 metadata(issuer / AS url / scope)。None = 没 onboard → 指向 add-remote-mcp。
    let meta = token_store
        .get_metadata(&token_ref)
        .map_err(|_| invalid("oauth token metadata query failed"))?
        .ok_or_else(|| {
            invalid("oauth upstream not onboarded — run `add-remote-mcp` first (same --ledger)")
        })?;

    // Finding 3(hostile review,defense-in-depth):onboarded resource 与 config mcp_url 必同源,
    // 否则 attach 期即 fail-closed(而非首次 call 才被 planner same-origin 拒;明确 audience 绑定)。
    let resource_url: url::Url = meta
        .resource
        .parse()
        .map_err(|_| invalid("onboarded oauth resource is not a valid URL"))?;
    if resource_url.origin() != mcp_url.origin() {
        return Err(invalid(
            "oauth upstream url origin != onboarded resource origin (audience mismatch)",
        ));
    }

    // Finding 1(hostile review,HIGH):AS 发现端点必须过 SSRF gate —— authorization_server 取自
    // 持久化行(可被篡改 / 来自恶意 resource 的 PRM),不 gate 则启动期请求可被引向内网 / 云元数据。
    assert_url_safe(name, &meta.authorization_server)?;

    // AS re-discovery → jwks_uri(启动期一次 network);issuer 漂移防御(AS 改 issuer = 可疑)。
    let jwks_src = Arc::new(HttpJwksSource::new(http));
    let as_meta = jwks_src
        .fetch_as_metadata(&meta.authorization_server)
        .map_err(|_| invalid("oauth AS metadata discovery failed at startup"))?;
    if as_meta.issuer != meta.issuer {
        return Err(invalid(
            "oauth AS issuer changed since onboarding (refusing — possible AS compromise)",
        ));
    }

    // Finding 1(hostile review,HIGH):jwks_uri 取自 AS 响应体(恶意 AS 可填内网 / 元数据 IP)——
    // 建 verifier(其惰性 fetch 此 URL)前先过 SSRF gate。
    assert_url_safe(name, &as_meta.jwks_uri)?;

    // JWKS 签名验证器 + ExpectedBinding(issuer/aud/scope/签名校验在 resolve_access_token 内)。
    let key_verifier: Arc<dyn vigil_http_auth::JwtKeyVerifier> = Arc::new(
        JwksSignatureVerifier::new(jwks_src, as_meta.jwks_uri.clone()),
    );
    let expected = vigil_http_auth::ExpectedBinding {
        resource: meta.resource.clone(),
        issuer: meta.issuer.clone(),
        scopes: meta.scope_set.clone(),
        key_verifier,
        introspection: None,
    };

    Ok(Arc::new(StreamableHttpUpstream::with_oauth(
        name,
        mcp_url,
        token_store,
        token_ref,
        expected,
        sender,
    )))
}

/// 对一个 URL 做 SSRF 安全校验(scheme gate + host→IP denylist),返解析后的 [`url::Url`]。
///
/// 供 mcp `url`(attach 期 [`validate_http_upstream_config`])与 **OAuth AS / JWKS 发现端点**
/// (serve 期 [`build_oauth_upstream`] 重建 verifier)**复用** —— 后者若不 gate,恶意 / 被篡改的 AS
/// 可经 `authorization_server` 或响应里的 `jwks_uri` 把 Vigil 启动期请求引向内网 / 云元数据
/// (`169.254.169.254`)端点(hostile review Finding 1)。生产仅 `https`;`http` 仅 loopback(本地
/// mock)。域名 DNS 解析后对解析出的 IP 复核;DNS-rebind 的**连接期**复核留 Slice 3。
fn assert_url_safe(name: &str, url: &str) -> Result<url::Url, ServeError> {
    use std::net::ToSocketAddrs;
    let invalid = |reason: &'static str| ServeError::InvalidUpstream {
        name: name.to_string(),
        reason,
    };
    let parsed = url::Url::parse(url).map_err(|_| invalid("url is not a valid absolute URL"))?;
    let host = parsed.host_str().unwrap_or("");
    match parsed.scheme() {
        "https" => {}
        "http" => {
            let is_loopback = matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]")
                || host == "0:0:0:0:0:0:0:1";
            if !is_loopback {
                return Err(invalid(
                    "http:// upstream allowed only for loopback (use https://)",
                ));
            }
        }
        _ => {
            return Err(invalid(
                "upstream url scheme must be https (or http loopback)",
            ))
        }
    }
    // SSRF denylist(MF#2):拒私网/链路本地/元数据(loopback 是显式本地-mock 例外)。
    // 经 `url::Host` 分流:IP 字面量直接判定(无 DNS,正确处理 IPv6 / v4-mapped);域名才 DNS 解析。
    let blocked_ip =
        invalid("upstream url resolves to a private/link-local/reserved IP (SSRF guard)");
    match parsed.host() {
        Some(url::Host::Ipv4(v4)) => {
            if is_blocked_ssrf_ip(&std::net::IpAddr::V4(v4)) {
                return Err(blocked_ip);
            }
        }
        Some(url::Host::Ipv6(v6)) => {
            if is_blocked_ssrf_ip(&std::net::IpAddr::V6(v6)) {
                return Err(blocked_ip);
            }
        }
        Some(url::Host::Domain(d)) => {
            let port = parsed.port_or_known_default().unwrap_or(443);
            let addrs: Vec<std::net::IpAddr> = (d, port)
                .to_socket_addrs()
                .map_err(|_| invalid("upstream host failed to resolve"))?
                .map(|sa| sa.ip())
                .collect();
            if addrs.is_empty() {
                return Err(invalid("upstream host resolved to no address"));
            }
            if addrs.iter().any(is_blocked_ssrf_ip) {
                return Err(blocked_ip);
            }
        }
        None => return Err(invalid("upstream url has no host")),
    }
    Ok(parsed)
}

/// 纯校验 HTTP upstream config(无副作用,offline 可测):name / URL scheme gate /
/// **SSRF denylist(MF#2)** / auth 源格式 / 传输修订。返解析后的 [`url::Url`]。
///
/// **SSRF 边界(诚实口径,ADR 0021 hostile review)**:此校验在 **attach 期**对 URL host 判定一次,
/// 配合 `ReqwestHttpClient` 的 `redirect(Policy::none())`(client.rs,防 3xx 把 token-bearing 请求
/// 重定向到内网/元数据)。**剩余**:域名的 DNS-rebind(attach 解析公网、连接时解析内网)——连接 IP
/// pinning 留 **Slice 3**;在此之前 token-bearing HTTP 上游应仅指向可信 URL。Bearer 路径的
/// planner same-origin 校验对静态 token 是**恒真**的(resource 即 upstream URL),非独立 audience
/// 绑定 —— Bearer 安全依赖此 SSRF + redirect 控制,而非 token 自身的 audience。
fn validate_http_upstream_config(
    name: &str,
    url: &str,
    auth: &HttpAuth,
    transport_hint: Option<HttpTransportHint>,
) -> Result<url::Url, ServeError> {
    let invalid = |reason: &'static str| ServeError::InvalidUpstream {
        name: name.to_string(),
        reason,
    };
    if name.is_empty() {
        return Err(invalid("name is empty"));
    }
    // URL scheme gate + SSRF denylist(提取为 `assert_url_safe`,OAuth AS / JWKS 发现端点亦复用)。
    let parsed = assert_url_safe(name, url)?;
    // auth 源格式(token 解析在 attach 期做)。
    match auth {
        HttpAuth::None => {}
        HttpAuth::Bearer { source } => {
            if !(source.starts_with("env:") || source.starts_with("keyring:")) {
                return Err(invalid(
                    "bearer source must be env:<VAR> or keyring:<svc>/<acct> (literal rejected)",
                ));
            }
        }
        HttpAuth::OAuth {
            resource,
            client_id,
        } => {
            if resource.is_empty() || client_id.is_empty() {
                return Err(invalid(
                    "oauth auth requires non-empty resource and client_id",
                ));
            }
        }
    }
    // 传输修订:Streamable(默认)支持;legacy_sse 留 Slice 5。
    if matches!(transport_hint, Some(HttpTransportHint::LegacySse)) {
        return Err(invalid(
            "legacy HTTP+SSE transport lands in ADR 0021 Slice 5",
        ));
    }
    Ok(parsed)
}

/// SSRF denylist(ADR 0021 §4.2 / MF#2):`ip` 是否应拒(私网 / 链路本地 / 保留段 / 云元数据)。
/// **loopback 例外**(`127/8` / `::1` 允许本地 mock)。DNS-rebind 复核留 Slice 3。
fn is_blocked_ssrf_ip(ip: &std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    // loopback 例外**先于** v4 解包(否则 `::1` → to_ipv4 → 0.0.0.1 被误判 blocked)。
    if ip.is_loopback() {
        return false; // 127/8 / ::1 显式本地-mock 例外
    }
    // IPv4-mapped(`::ffff:a.b.c.d`)**与** IPv4-compatible(`::a.b.c.d`,deprecated)均按 V4 判定
    // —— 防 `::ffff:169.254.169.254` / `::169.254.169.254` 绕过 V6 分支(hostile review HIGH + LOW)。
    // `to_ipv4()` 覆盖两形;`::1`/`::` 已分别由上方 is_loopback / 下方 is_unspecified 兜住。
    if let IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4() {
            return is_blocked_ssrf_ip(&IpAddr::V4(v4));
        }
    }
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()        // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local() // 169.254/16(含云元数据 169.254.169.254)
                || v4.is_unspecified() // 0.0.0.0
                || v4.is_broadcast()
                || v4.octets()[0] == 0 // 0.0.0.0/8
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 0x40) // 100.64/10 CGNAT
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            v6.is_unspecified()
                || (seg[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || (seg[0] & 0xfe00) == 0xfc00 // fc00::/7 ULA
                || (seg[0] == 0x0064 && seg[1] == 0xff9b) // 64:ff9b::/96 NAT64
        }
    }
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
    // DEF-001 诊断:启动即在 stderr 打印解析后的账本路径 —— 桌面 GUI 看不到 CLI 写入事件的最
    // 常见根因是 writer/reader 路径不一致(如文件名 ledger.sqlite vs ledger.sqlite3),打印出来
    // 便于与桌面读的路径肉眼比对。内存账本(无 --ledger)显式警告:不持久、桌面看不到。
    match args.ledger_path.as_deref() {
        Some(p) => eprintln!("vigil-hub serve: audit ledger -> {}", p.display()),
        None => eprintln!(
            "vigil-hub serve: audit ledger = IN-MEMORY (no --ledger) -- events are NOT persisted \
             and the desktop app will NOT see them; pass --ledger <shared path> or use `setup --mcp`"
        ),
    }
    // DEF-004 可见性:把实际绑定的项目边界根打出来 —— 宿主 spawn 时 CWD 不是项目目录的话,
    // 边界会静默绑错(enforce 下项目内写被误拦),打印让误绑可被肉眼发现。
    if args.project_roots.is_empty() {
        eprintln!(
            "vigil-hub serve: project boundary = NONE (FsWrite falls to default-deny floor; \
             pass --project-root <DIR> to enable boundary rules)"
        );
    } else {
        eprintln!(
            "vigil-hub serve: project boundary -> {}",
            args.project_roots.join(", ")
        );
    }
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

    // ── ADR 0021 Slice 1:UpstreamEntry untagged schema + HTTP upstream 校验 ──
    #[test]
    fn upstream_entry_parses_legacy_stdio() {
        let e: UpstreamEntry =
            serde_json::from_str(r#"{"name":"fs","argv":["npx","server"]}"#).unwrap();
        assert!(matches!(e, UpstreamEntry::Stdio { .. }));
    }

    #[test]
    fn upstream_entry_parses_http_defaults() {
        let e: UpstreamEntry =
            serde_json::from_str(r#"{"name":"gh","url":"https://mcp.github.com"}"#).unwrap();
        match e {
            UpstreamEntry::Http {
                name,
                url,
                auth,
                transport_hint,
            } => {
                assert_eq!(name, "gh");
                assert_eq!(url, "https://mcp.github.com");
                assert!(matches!(auth, HttpAuth::None));
                assert!(transport_hint.is_none());
            }
            other => panic!("expected Http, got {other:?}"),
        }
    }

    #[test]
    fn upstream_entry_http_bearer_and_oauth_parse() {
        let b: UpstreamEntry = serde_json::from_str(
            r#"{"name":"gh","url":"https://x","auth":{"bearer":{"source":"env:GH"}}}"#,
        )
        .unwrap();
        assert!(matches!(
            b,
            UpstreamEntry::Http {
                auth: HttpAuth::Bearer { .. },
                ..
            }
        ));
        let o: UpstreamEntry = serde_json::from_str(
            r#"{"name":"gh","url":"https://x","auth":{"oauth":{"resource":"https://x","client_id":"c"}}}"#,
        )
        .unwrap();
        assert!(matches!(
            o,
            UpstreamEntry::Http {
                auth: HttpAuth::OAuth { .. },
                ..
            }
        ));
    }

    /// 测试夹具:onboard 一个 OAuth token(`OAuthTokenMetadata.{authorization_server,issuer}` 用
    /// `as_url`/`stored_issuer`,落 in-memory ledger + InMemorySecretStore)+ mock AS discovery 返
    /// `discovered_issuer` + `jwks_uri`(AS 响应体里的 JWKS 端点),跑 [`build_oauth_upstream`]。
    /// loopback `as_url`+`jwks_uri` + `stored==discovered` = positive;`discovered!=stored` = issuer
    /// 漂移;`as_url` 或 `jwks_uri`=元数据 IP = SSRF reject。**hermetic**:MockHttpClient 供 AS
    /// metadata,sender 仅构造不 send,无真网络 / DNS。
    fn onboard_and_build_oauth(
        as_url: &str,
        jwks_uri: &str,
        stored_issuer: &str,
        discovered_issuer: &str,
    ) -> Result<Arc<dyn vigil_mcp::McpUpstream>, ServeError> {
        use vigil_http_auth::{
            token_ref_for_access, HttpMethod, HttpResponse, MockHttpClient, OAuthTokenMetadata,
            TokenKind, TokenStore,
        };
        use vigil_lease::InMemorySecretStore;

        let ledger = Arc::new(Ledger::open_in_memory().unwrap());
        let resource = "https://mcp.example.com/";
        let client_id = "cid";

        // onboard:token + metadata 落库(同一 ledger,与 serve 读取一致)。
        let secret_store: Arc<dyn SecretStore> = Arc::new(InMemorySecretStore::new());
        let token_ref = token_ref_for_access(resource, client_id);
        let ts = TokenStore::new(secret_store.clone(), ledger.clone());
        let meta = OAuthTokenMetadata {
            token_ref,
            resource: resource.to_string(),
            authorization_server: as_url.to_string(),
            issuer: stored_issuer.to_string(),
            scope_set: vec!["mcp:tools.read".to_string()],
            token_kind: TokenKind::Access,
            expires_at: None,
            created_at: 0,
        };
        ts.put_access_token(&meta, SecretValue::new("dummy.jwt.token"))
            .unwrap();

        // mock AS discovery:GET {as_url}/.well-known/oauth-authorization-server → 200。jwks_uri 与
        // AS 同源(loopback 用例过 SSRF gate)。注:SSRF-reject 用例在 discovery 前即 fail,mock 不被命中。
        let http_mock = MockHttpClient::new();
        http_mock.register(
            HttpMethod::Get,
            &format!("{as_url}/.well-known/oauth-authorization-server"),
            HttpResponse {
                status: 200,
                body: format!(r#"{{"issuer":"{discovered_issuer}","jwks_uri":"{jwks_uri}"}}"#)
                    .into_bytes(),
            },
        );
        let http: Arc<dyn vigil_http_auth::HttpClient> = Arc::new(http_mock);
        // build 只构造 upstream(不 send);用真 ReqwestHttpClient 当 sender 占位,绝不被调用。
        let sender: Arc<dyn vigil_http_auth::AuthorizedSender> =
            Arc::new(ReqwestHttpClient::new().unwrap());

        build_oauth_upstream(
            &ledger,
            "remote",
            "https://mcp.example.com/rpc".parse().unwrap(),
            resource,
            client_id,
            http,
            secret_store,
            sender,
        )
    }

    /// OAuth serve 接线 **positive**:onboard(ledger 有 metadata)+ AS issuer 匹配 + AS/jwks 过
    /// SSRF gate(loopback)→ 构造成功的 HTTP 上游(`transport()=Http`)。证 wiring 真打通。
    #[test]
    fn build_oauth_upstream_succeeds_when_onboarded_and_as_matches() {
        let up = onboard_and_build_oauth(
            "https://127.0.0.1:8765",
            "https://127.0.0.1:8765/jwks",
            "https://127.0.0.1:8765",
            "https://127.0.0.1:8765",
        )
        .unwrap();
        assert_eq!(up.transport(), TransportKind::Http);
        assert_eq!(up.server_id(), "remote");
    }

    /// OAuth serve 接线 **issuer 漂移 fail-closed**:onboard issuer=A,AS discovery 现返 issuer=B →
    /// 拒(可疑 AS;错误 verifier = 接受伪造 token,安全最敏感一环)。
    #[test]
    fn build_oauth_upstream_refuses_on_issuer_drift() {
        let err = onboard_and_build_oauth(
            "https://127.0.0.1:8765",
            "https://127.0.0.1:8765/jwks",
            "https://127.0.0.1:8765",
            "https://evil.example.com",
        )
        .unwrap_err();
        match err {
            ServeError::InvalidUpstream { reason, .. } => {
                assert!(reason.contains("issuer changed"), "reason: {reason}")
            }
            other => panic!("预期 InvalidUpstream(issuer drift),实际 {other:?}"),
        }
    }

    /// Finding 1(hostile review,HIGH)回归之一:**AS 发现端点**是云元数据 IP(169.254.169.254)→
    /// SSRF gate 在 discovery 前 fail-closed(证 OAuth AS 发现端点也走 SSRF denylist,非只 mcp url)。
    #[test]
    fn build_oauth_upstream_refuses_ssrf_as_endpoint() {
        let err = onboard_and_build_oauth(
            "https://169.254.169.254",
            "https://169.254.169.254/jwks",
            "https://169.254.169.254",
            "https://169.254.169.254",
        )
        .unwrap_err();
        match err {
            ServeError::InvalidUpstream { reason, .. } => {
                assert!(reason.contains("SSRF"), "reason: {reason}")
            }
            other => panic!("预期 InvalidUpstream(SSRF),实际 {other:?}"),
        }
    }

    /// Finding 1(hostile review,HIGH)回归之二:**AS 通过 gate,但响应体里的 `jwks_uri` 指向元数据
    /// IP**(良性公开 AS 可填内网 JWKS)→ 建 verifier 前的 jwks_uri SSRF gate fail-closed。pin 住该
    /// gate(reviewer 指出:positive 只用安全 jwks_uri,reject 分支若被未来重构悄悄删除也不会变红)。
    #[test]
    fn build_oauth_upstream_refuses_ssrf_jwks_uri_from_as_body() {
        let err = onboard_and_build_oauth(
            "https://127.0.0.1:8765",       // AS 端点安全(过 gate)
            "https://169.254.169.254/jwks", // 但 AS 响应体里的 jwks_uri 指向云元数据
            "https://127.0.0.1:8765",
            "https://127.0.0.1:8765", // issuer 不漂移 → 走到 jwks_uri gate
        )
        .unwrap_err();
        match err {
            ServeError::InvalidUpstream { reason, .. } => {
                assert!(reason.contains("SSRF"), "reason: {reason}")
            }
            other => panic!("预期 InvalidUpstream(jwks_uri SSRF),实际 {other:?}"),
        }
    }

    /// MF#3:`{name,argv,url}` 歧义 —— 两变体 deny_unknown_fields 都拒 → 整体报错(非静默 Stdio 丢 url)。
    #[test]
    fn upstream_entry_ambiguous_argv_plus_url_rejected() {
        let r: Result<UpstreamEntry, _> =
            serde_json::from_str(r#"{"name":"x","argv":["a"],"url":"https://y"}"#);
        assert!(
            r.is_err(),
            "ambiguous {{name,argv,url}} must be rejected, got {r:?}"
        );
    }

    /// 未知字段同样被拒(每变体 deny_unknown_fields)。
    #[test]
    fn upstream_entry_unknown_field_rejected() {
        let r: Result<UpstreamEntry, _> =
            serde_json::from_str(r#"{"name":"x","argv":["a"],"bogus":1}"#);
        assert!(r.is_err(), "unknown field must be rejected, got {r:?}");
    }

    // 校验用 IP 字面量(offline,不做 DNS)。
    #[test]
    fn validate_rejects_non_loopback_http() {
        let err = validate_http_upstream_config("gh", "http://10.0.0.5", &HttpAuth::None, None)
            .unwrap_err();
        assert!(matches!(err, ServeError::InvalidUpstream { .. }));
    }

    #[test]
    fn validate_allows_loopback_http() {
        // loopback http 过 scheme gate + SSRF(loopback 例外)→ Ok。
        let u =
            validate_http_upstream_config("m", "http://127.0.0.1:9000/mcp", &HttpAuth::None, None)
                .unwrap();
        assert_eq!(u.scheme(), "http");
    }

    #[test]
    fn validate_accepts_valid_public_https() {
        let u =
            validate_http_upstream_config("gh", "https://1.1.1.1", &HttpAuth::None, None).unwrap();
        assert_eq!(u.host_str(), Some("1.1.1.1"));
    }

    #[test]
    fn validate_rejects_literal_bearer() {
        let err = validate_http_upstream_config(
            "gh",
            "https://1.1.1.1",
            &HttpAuth::Bearer {
                source: "literal:abc".into(),
            },
            None,
        )
        .unwrap_err();
        assert!(matches!(err, ServeError::InvalidUpstream { .. }));
    }

    #[test]
    fn validate_rejects_legacy_sse() {
        let err = validate_http_upstream_config(
            "gh",
            "https://1.1.1.1",
            &HttpAuth::None,
            Some(HttpTransportHint::LegacySse),
        )
        .unwrap_err();
        match err {
            ServeError::InvalidUpstream { reason, .. } => assert!(reason.contains("Slice 5")),
            other => panic!("expected Slice-5 InvalidUpstream, got {other:?}"),
        }
    }

    /// MF#2 SSRF:私网 / 元数据 IP 被拒(scheme https 也拦)。
    #[test]
    fn validate_rejects_private_and_metadata_ip() {
        for bad in [
            "https://10.0.0.5",
            "https://192.168.1.1",
            "https://172.16.0.1",
            "https://169.254.169.254",
        ] {
            let err = validate_http_upstream_config("x", bad, &HttpAuth::None, None).unwrap_err();
            match err {
                ServeError::InvalidUpstream { reason, .. } => {
                    assert!(reason.contains("SSRF"), "{bad}: {reason}")
                }
                other => panic!("{bad}: expected InvalidUpstream, got {other:?}"),
            }
        }
    }

    #[test]
    fn is_blocked_ssrf_ip_classifies() {
        use std::net::IpAddr;
        let blocked = |s: &str| is_blocked_ssrf_ip(&s.parse::<IpAddr>().unwrap());
        assert!(blocked("10.0.0.5"));
        assert!(blocked("192.168.1.1"));
        assert!(blocked("172.16.0.1"));
        assert!(blocked("169.254.169.254")); // 云元数据
        assert!(blocked("0.0.0.0"));
        assert!(blocked("100.64.0.1")); // CGNAT
        assert!(blocked("fc00::1")); // ULA
        assert!(blocked("fe80::1")); // link-local
        assert!(!blocked("1.1.1.1")); // 公网
        assert!(!blocked("8.8.8.8"));
        assert!(!blocked("127.0.0.1")); // loopback 例外
        assert!(!blocked("::1"));
        // IPv4-mapped IPv6 必须解包按 V4 判定(hostile review HIGH)。
        assert!(blocked("::ffff:169.254.169.254")); // 云元数据 via mapped
        assert!(blocked("::ffff:10.0.0.1"));
        assert!(blocked("::ffff:192.168.1.1"));
        assert!(blocked("64:ff9b::a00:1")); // NAT64 64:ff9b::/96 → 10.0.0.1
        assert!(!blocked("::ffff:1.1.1.1")); // mapped 公网 → 放行
        assert!(!blocked("::ffff:127.0.0.1")); // mapped loopback → 放行(例外)
                                               // IPv4-compatible ::a.b.c.d(deprecated)也须解包(hostile review LOW residual)。
        assert!(blocked("::169.254.169.254")); // compatible 元数据
        assert!(blocked("::10.0.0.5"));
        assert!(!blocked("::1")); // loopback 例外(reorder 后仍正确,先于 v4 解包)
    }

    /// MF#2 / hostile review HIGH:`https://[::ffff:169.254.169.254]` 经 url::Host::Ipv6 → 解包 → 拒。
    #[test]
    fn validate_rejects_v4_mapped_ipv6_metadata() {
        let err = validate_http_upstream_config(
            "x",
            "https://[::ffff:169.254.169.254]",
            &HttpAuth::None,
            None,
        )
        .unwrap_err();
        match err {
            ServeError::InvalidUpstream { reason, .. } => assert!(reason.contains("SSRF")),
            other => panic!("expected SSRF InvalidUpstream, got {other:?}"),
        }
    }

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

    /// DEF-004 回归门:CLI 不带 `--project-root` 时缺省必须解析出**非空** CWD 根。
    /// 任何回归(缺省又变回空 roots)会让 serve enforce 的项目边界整体失效 ——
    /// 这正是 DEF-004 的原始 bug(所有生产入口空 roots → Inside/Outside 语义反转)。
    #[test]
    fn def004_resolve_project_roots_defaults_to_cwd_normalized() {
        let roots = resolve_project_roots(&[]);
        assert_eq!(roots.len(), 1, "缺省应解析出恰好 1 个根(进程 CWD)");
        let root = &roots[0];
        // POSIX 归一不变量:与 PathExtractor 输出同款,否则 is_under 前缀比较静默不匹配。
        assert!(!root.is_empty(), "CWD 根不应为空字符串");
        assert!(!root.contains('\\'), "归一后不应残留反斜杠: {root}");
        assert!(
            !root.starts_with(r"//?/") && !root.starts_with(r"\\?\"),
            "归一后不应残留 Windows 扩展长度前缀: {root}"
        );
        // 非循环结构校验(hostile review):不与 normalize_project_root 输出比较 ——
        // 那是被测函数自身的实现链,两边同时坏会伪绿。改验 CWD 末段目录名真出现在根里
        // (大小写不敏感:canonicalize 可能修正盘符/目录真实大小写)。
        let cwd = std::env::current_dir().unwrap();
        // cargo test 的 CWD 是 package 目录,必有末段(unwrap 与本 crate test 配置一致)。
        let leaf = cwd
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_ascii_lowercase();
        assert!(
            root.to_ascii_lowercase().ends_with(&leaf),
            "根应以 CWD 末段 `{leaf}` 结尾: {root}"
        );
    }

    /// DEF-004:显式 `--project-root`(含相对路径)也必须经同款 POSIX 归一。
    #[test]
    fn def004_resolve_project_roots_explicit_paths_normalized() {
        let dir = tempdir().unwrap();
        let roots = resolve_project_roots(&[dir.path().to_path_buf()]);
        assert_eq!(roots.len(), 1);
        assert_eq!(
            roots[0],
            vigil_firewall::extract::normalize_project_root(dir.path()),
            "显式根必须与 normalize_project_root 输出一致"
        );
        // 相对路径 "." 应被解析为绝对 CWD(而非原样保留相对形式)。
        let rel = resolve_project_roots(&[PathBuf::from(".")]);
        assert_eq!(rel.len(), 1);
        assert!(
            !rel[0].starts_with('.'),
            "相对路径必须被解析为绝对路径: {}",
            rel[0]
        );
    }

    /// 交叉审查 MEDIUM 守门(Codex):ort-init worker **panic**(channel Disconnected)必须
    /// 映射为 [`OrtInitOutcome::Panicked`](干净 fail-closed),**绝不**误入超时分支的
    /// `abort()`。若有人回归成 `Err(_) => abort()`,本测试会让进程直接 abort → 测试框架
    /// 报 crash 立即暴露(panic=unwind 前提下 worker panic 不持 loader lock,可干净返回)。
    #[cfg(feature = "ort")]
    #[test]
    fn ort_init_worker_panic_maps_to_panicked_not_abort() {
        let outcome =
            run_ort_init_with_timeout::<()>("test-panic", || panic!("simulated init panic"));
        assert!(matches!(outcome, Err(OrtInitOutcome::Panicked)));
    }

    /// ort-init helper 正常路径:build 成功值原样透传(不被超时/panic 分支误吞)。
    #[cfg(feature = "ort")]
    #[test]
    fn ort_init_success_passes_through() {
        let outcome = run_ort_init_with_timeout("test-ok", || {
            Ok::<_, vigil_redaction::engine::EngineError>(42u32)
        });
        assert!(matches!(outcome, Ok(42)));
    }
}
