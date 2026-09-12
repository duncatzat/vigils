//! 出站 LLM-API 闸门(opt-in)的 CLI 面:配置落盘、agent 适配(Claude Code / Codex CLI)、
//! `outbound status|on|off|serve`、daemon 内启动。引擎(环回代理 + 请求体改写)在 `vigil-outbound`。
//!
//! # 纪律
//! - **默认关**:`outbound.json` 缺失 = 未开启;损坏 / 版本不识别 → fail-closed 当作关闭 + warning
//!   (不回显文件原文)。
//! - **改 agent 配置只动自己写的键**:Claude `settings.json` 的 `env.ANTHROPIC_BASE_URL` /
//!   `env.ENABLE_TOOL_SEARCH`;Codex `config.toml` 的 `model_provider` + `[model_providers.vigil]`。
//!   用户既有的其它键一律不碰;`off` 只在值仍是我们写的那个时才还原(绝不 clobber)。
//! - **既有网关不抢**:用户已把 `ANTHROPIC_BASE_URL` 指向自家网关(LiteLLM / Portkey …)时,闸门
//!   串在它前面 —— 记住原地址作 anthropic 上游,`off` 时还原。
//! - **诚实边界**:Bedrock / Vertex / Foundry 模式(签整个请求体或不走 base URL)拒绝开启;Codex 用
//!   自定义 `model_provider` 时拒绝开启;Gemini CLI 第二批。
//! - 备份 + 原子写 + TOCTOU 守护全部复用 [`crate::setup`] 的同一段写盘核心。

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use vigil_audit::Ledger;
use vigil_outbound::{
    GateAudit, GateConfig, GateDeps, GateHandle, NoAlias, RewriteReport, RouteKind, Routes,
};

use crate::i18n::Lang;
use crate::setup::{self, SetupError};

const OUTBOUND_FILENAME: &str = "outbound.json";
const OUTBOUND_FILE_VERSION: u64 = 1;
/// 默认监听地址(与引擎一致)。
pub const DEFAULT_LISTEN: &str = vigil_outbound::server::DEFAULT_LISTEN;
/// Codex 自定义 provider 的 id(`model_provider = "vigil"`)。
pub const CODEX_PROVIDER_ID: &str = "vigil";
const CLAUDE_BASE_URL_KEY: &str = "ANTHROPIC_BASE_URL";
const CLAUDE_TOOL_SEARCH_KEY: &str = "ENABLE_TOOL_SEARCH";
const CLAUDE_UNSUPPORTED_MODES: [&str; 3] = [
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
];

// ─────────────────────────── 配置落盘 ───────────────────────────

/// 磁盘 shape:`<data_local>/Vigil/outbound.json`。同 version 内允许前向追加字段。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboundFile {
    version: u64,
    /// 是否开启(daemon 启动时据此决定要不要起闸门)
    pub enabled: bool,
    /// 监听地址(环回)
    pub listen: String,
    /// 上游根(可被「串在既有网关前面」改写)
    #[serde(default)]
    pub upstreams: Routes,
    /// 各 agent 已写入的内容(`off` 时据此还原)
    #[serde(default)]
    pub agents: AppliedAgents,
}

impl Default for OutboundFile {
    fn default() -> Self {
        Self {
            version: OUTBOUND_FILE_VERSION,
            enabled: false,
            listen: DEFAULT_LISTEN.to_string(),
            upstreams: Routes::default(),
            agents: AppliedAgents::default(),
        }
    }
}

/// 已写入 agent 配置的记录。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppliedAgents {
    /// Claude Code
    pub claude: Option<ClaudeApplied>,
    /// Codex CLI
    pub codex: Option<CodexApplied>,
}

/// Claude Code 适配记录。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaudeApplied {
    /// 写入的 settings.json 路径
    pub config_path: String,
    /// 开启前 `ANTHROPIC_BASE_URL` 的值(用户自家网关;`off` 时还原,期间作 anthropic 上游)
    pub previous_base_url: Option<String>,
    /// `ENABLE_TOOL_SEARCH` 是我们加的(用户原本没设)→ `off` 时删掉
    pub set_tool_search: bool,
}

/// Codex CLI 适配记录。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodexApplied {
    /// 写入的 config.toml 路径
    pub config_path: String,
    /// 开启前顶层 `model_provider` 的值(`None` = 未设,即内置 openai)
    pub previous_model_provider: Option<String>,
}

/// [`load_outbound`] 结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedOutbound {
    /// 生效配置(损坏时为默认 = 关闭)
    pub file: OutboundFile,
    /// 非 None = 配置异常已 fail-closed 当作关闭;只含原因类别 + 路径
    pub warning: Option<String>,
}

/// 默认配置路径 `<data_local>/Vigil/outbound.json`。
pub fn default_outbound_path() -> Option<PathBuf> {
    dirs::data_local_dir().map(|b| b.join(setup::VIGIL_SUBDIR).join(OUTBOUND_FILENAME))
}

/// 读配置。永不 panic / Err:不存在 → 默认(关闭);损坏 / 未知版本 → 默认 + warning。
pub fn load_outbound(path: &Path) -> LoadedOutbound {
    let fail_closed = |reason: &str| LoadedOutbound {
        file: OutboundFile::default(),
        warning: Some(format!(
            "outbound config at {} is {reason}; treating the gate as disabled",
            path.display()
        )),
    };
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return LoadedOutbound {
                file: OutboundFile::default(),
                warning: None,
            }
        }
        Err(_) => return fail_closed("unreadable"),
    };
    let parsed: OutboundFile = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return fail_closed("malformed"),
    };
    if parsed.version != OUTBOUND_FILE_VERSION {
        return fail_closed("of an unrecognized version");
    }
    if parse_listen(&parsed.listen).is_err() {
        return fail_closed("pointing at a non-loopback or invalid listen address");
    }
    LoadedOutbound {
        file: parsed,
        warning: None,
    }
}

/// 原子写配置(同 engine.json:同目录 tmp + rename,父目录自建)。
pub fn store_outbound(path: &Path, file: &OutboundFile) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut rendered = serde_json::to_string_pretty(file)?;
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
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// 解析监听地址并强制环回(闸门不是给局域网用的:它透传鉴权头)。
pub fn parse_listen(listen: &str) -> Result<SocketAddr, String> {
    let addr: SocketAddr = listen
        .parse()
        .map_err(|_| format!("invalid listen address `{listen}` (expected host:port)"))?;
    if !addr.ip().is_loopback() {
        return Err(format!(
            "listen address `{listen}` is not loopback; the gate forwards your API credentials and must stay local"
        ));
    }
    Ok(addr)
}

// ─────────────────────────── agent 状态模型 ───────────────────────────

/// 单个 agent 的适配状态(`status --json` 字面量稳定)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentState {
    /// 本机没装这个 agent
    NotInstalled,
    /// 装了,但配置里没有闸门
    NotConfigured,
    /// 配置指向本闸门(当前 listen)
    Active,
    /// 配置指向一个旧的 / 不同端口的 Vigil 闸门地址
    Stale,
    /// 配置指向用户自家网关(未开启时看到;开启会串在它前面)
    Foreign(String),
    /// 无法开启(原因)
    Unsupported(String),
}

impl AgentState {
    /// 稳定字面量。
    pub fn as_str(&self) -> &'static str {
        match self {
            AgentState::NotInstalled => "not_installed",
            AgentState::NotConfigured => "not_configured",
            AgentState::Active => "active",
            AgentState::Stale => "stale",
            AgentState::Foreign(_) => "foreign",
            AgentState::Unsupported(_) => "unsupported",
        }
    }

    fn detail(&self) -> Option<&str> {
        match self {
            AgentState::Foreign(s) | AgentState::Unsupported(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

/// 一次 apply / revert 的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentOutcome {
    /// 操作后的状态
    pub state: AgentState,
    /// 是否真的改了文件
    pub changed: bool,
    /// 备份路径(改了既有文件时)
    pub backup: Option<PathBuf>,
}

// ─────────────────────────── Claude Code(~/.claude/settings.json)───────────────────────────

/// Claude Code 的闸门 base URL(路径前缀 `/anthropic`)。
pub fn claude_gate_url(listen: &str) -> String {
    format!("http://{listen}/anthropic")
}

/// 是不是某个 Vigil 闸门地址(环回 + 指定路径),不论端口。
///
/// **必须用真正的 URL 解析器**:手工切串会被 userinfo 伪装骗过 ——
/// `http://127.0.0.1:80@evil.com/anthropic` 的真实主机是 `evil.com`,而按最后一个 `:` 切会得到
/// 「host = 127.0.0.1」,于是 `off` 会把一个**远程**地址当成自家闸门删掉(Codex 审计 2026-09-12
/// 第 10 条)。带 userinfo 的一律不认。
fn is_gate_url(raw: &str, expected_path: &str) -> bool {
    let Ok(u) = url::Url::parse(raw.trim()) else {
        return false;
    };
    if u.scheme() != "http" || !u.username().is_empty() || u.password().is_some() {
        return false;
    }
    matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "::1"))
        && u.path().trim_end_matches('/') == expected_path
}

/// Claude 面的闸门地址判定(路径 `/anthropic`)。
fn is_vigil_gate_url(raw: &str) -> bool {
    is_gate_url(raw, "/anthropic")
}

/// **回显**用户自家网关地址前剥掉 userinfo。LiteLLM / Portkey 之类常见 `https://<key>@host` 形态,
/// 原样打进 `status` 输出、`--json`、GUI 标签,就是把凭据抄进日志与界面(敌意评审 2026-09-12 MEDIUM-5)。
///
/// 只用在**展示**路径:落盘的恢复记录必须保持原样,否则 `off` 还原出来的网关地址缺凭据、不可用。
/// 解析失败(非标准 URL)→ 原样返回,不猜。
fn redact_userinfo(raw: &str) -> String {
    match url::Url::parse(raw.trim()) {
        Ok(mut u) if !u.username().is_empty() || u.password().is_some() => {
            let _ = u.set_username("");
            let _ = u.set_password(None);
            u.to_string()
        }
        _ => raw.to_string(),
    }
}

fn env_truthy(v: &Value) -> bool {
    match v {
        Value::Bool(b) => *b,
        Value::String(s) => matches!(s.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"),
        Value::Number(n) => n.as_i64().is_some_and(|i| i != 0),
        _ => false,
    }
}

/// `settings.json` 顶层与 `env` 的形状检查(root 对象;`env` 若存在须为对象)。
fn claude_env_map<'a>(
    settings: &'a Value,
    path: &Path,
) -> Result<Option<&'a serde_json::Map<String, Value>>, SetupError> {
    let Some(root) = settings.as_object() else {
        return Err(SetupError::UnsupportedConfigShape {
            path: path.to_path_buf(),
            field: "root",
        });
    };
    match root.get("env") {
        None => Ok(None),
        Some(Value::Object(m)) => Ok(Some(m)),
        Some(_) => Err(SetupError::UnsupportedConfigShape {
            path: path.to_path_buf(),
            field: "env",
        }),
    }
}

fn claude_unsupported(env: Option<&serde_json::Map<String, Value>>) -> Option<String> {
    let env = env?;
    CLAUDE_UNSUPPORTED_MODES
        .iter()
        .find(|k| env.get(**k).is_some_and(env_truthy))
        .map(|k| format!("{k} is set: Bedrock / Vertex / Foundry traffic does not go through ANTHROPIC_BASE_URL (Bedrock also signs the request body)"))
}

/// Claude Code 当前适配状态(只读)。
pub fn claude_state(home: &Path, listen: &str) -> Result<AgentState, SetupError> {
    if !setup::claude_detected(home) {
        return Ok(AgentState::NotInstalled);
    }
    let path = setup::claude_settings_path(home);
    let Some(settings) = setup::read_settings(&path)? else {
        return Ok(AgentState::NotConfigured);
    };
    let env = claude_env_map(&settings, &path)?;
    if let Some(reason) = claude_unsupported(env) {
        return Ok(AgentState::Unsupported(reason));
    }
    let current = env
        .and_then(|m| m.get(CLAUDE_BASE_URL_KEY))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    Ok(match current {
        None => AgentState::NotConfigured,
        Some(url) if url == claude_gate_url(listen) => AgentState::Active,
        Some(url) if is_vigil_gate_url(url) => AgentState::Stale,
        Some(url) => AgentState::Foreign(url.to_string()),
    })
}

/// 把 Claude Code 指到闸门。返回结果与「记录」(供 `off` 还原;`None` = 没写)。
pub fn claude_apply(
    home: &Path,
    listen: &str,
    prior: Option<&ClaudeApplied>,
) -> Result<(AgentOutcome, Option<ClaudeApplied>), SetupError> {
    if !setup::claude_detected(home) {
        return Ok((outcome(AgentState::NotInstalled), None));
    }
    let path = setup::claude_settings_path(home);
    // stamp **先于**读取取得:反过来(读完再 stat)会漏掉「读取与 stat 之间」的并发写 —— 那时
    // stamp 属于新文件、待写内容却来自旧快照,写前比对反而放行(Codex 审计 2026-09-12 第 9 条)。
    // 注:`setup` / `setup_mcp` 既有调用点仍是先读后 stamp,那是仓库既有面,不在本次改动范围。
    let stamp = setup::stamp_for_existing(&path).ok();
    let existing = setup::read_settings(&path)?;
    let stamp = if existing.is_some() { stamp } else { None };
    let mut settings = existing.unwrap_or_else(|| json!({}));
    let env_view = claude_env_map(&settings, &path)?;
    if let Some(reason) = claude_unsupported(env_view) {
        return Ok((outcome(AgentState::Unsupported(reason)), None));
    }
    let gate_url = claude_gate_url(listen);
    let current = env_view
        .and_then(|m| m.get(CLAUDE_BASE_URL_KEY))
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let tool_search_present = env_view.is_some_and(|m| m.contains_key(CLAUDE_TOOL_SEARCH_KEY));

    // 既有值分类:已被本功能接管(保留**首次** on 记下的恢复信息)/ 用户网关(记 previous,串在
    // 前面)/ 无。**绝不**用当前值覆盖恢复记录 —— 当前值正是我们自己写的,连续两次 `on` 会把
    // 首次记下的企业网关抹成 None,`off` 就再也还不回去了(Codex 审计 2026-09-12 第 6 条)。
    let managed = current
        .as_deref()
        .is_some_and(|u| u == gate_url || is_vigil_gate_url(u));
    let previous_base_url = match current.as_deref() {
        _ if managed => prior.and_then(|p| p.previous_base_url.clone()),
        Some(u) => Some(u.to_string()),
        None => None,
    };
    // 同理:`ENABLE_TOOL_SEARCH` 现在在位,可能是**我们首次**加的(那么 `off` 该删),
    // 也可能本来就是用户的(那么永远别碰)。答案只存在于首次记录里。
    let set_tool_search = if tool_search_present {
        managed && prior.is_some_and(|p| p.set_tool_search)
    } else {
        true
    };
    let already = current.as_deref() == Some(gate_url.as_str());
    let record = ClaudeApplied {
        config_path: path.display().to_string(),
        previous_base_url: previous_base_url.clone(),
        set_tool_search,
    };
    if already && tool_search_present {
        return Ok((outcome(AgentState::Active), Some(record)));
    }

    let root = settings
        .as_object_mut()
        .ok_or_else(|| SetupError::UnsupportedConfigShape {
            path: path.clone(),
            field: "root",
        })?;
    let env = root
        .entry("env")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| SetupError::UnsupportedConfigShape {
            path: path.clone(),
            field: "env",
        })?;
    env.insert(CLAUDE_BASE_URL_KEY.to_string(), Value::String(gate_url));
    if !tool_search_present {
        // 非一方 base URL 会让 Claude Code 默认关掉 MCP tool search;闸门原样透传 tool_reference,
        // 所以显式开回来(用户自己设过就不碰)。
        env.insert(
            CLAUDE_TOOL_SEARCH_KEY.to_string(),
            Value::String("true".to_string()),
        );
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| SetupError::Io {
            what: "create Claude config directory",
            path: parent.to_path_buf(),
        })?;
    }
    let backup = setup::atomic_write_with_backup(&path, &settings, stamp)?;
    Ok((
        AgentOutcome {
            state: AgentState::Active,
            changed: true,
            backup,
        },
        Some(record),
    ))
}

/// 撤掉我们写进 Claude Code 的键:只在值仍是闸门地址时还原;用户改过就不碰。
pub fn claude_revert(
    home: &Path,
    listen: &str,
    applied: Option<&ClaudeApplied>,
) -> Result<AgentOutcome, SetupError> {
    if !setup::claude_detected(home) {
        return Ok(outcome(AgentState::NotInstalled));
    }
    let path = setup::claude_settings_path(home);
    let Some(mut settings) = setup::read_settings(&path)? else {
        return Ok(outcome(AgentState::NotConfigured));
    };
    let stamp = setup::stamp_for_existing(&path)?;
    let mut changed = false;
    {
        let root = settings
            .as_object_mut()
            .ok_or_else(|| SetupError::UnsupportedConfigShape {
                path: path.clone(),
                field: "root",
            })?;
        if let Some(env) = root.get_mut("env").and_then(Value::as_object_mut) {
            let ours = env
                .get(CLAUDE_BASE_URL_KEY)
                .and_then(Value::as_str)
                .is_some_and(|u| {
                    u.trim() == claude_gate_url(listen) || is_vigil_gate_url(u.trim())
                });
            if ours {
                match applied.and_then(|a| a.previous_base_url.clone()) {
                    Some(prev) => {
                        env.insert(CLAUDE_BASE_URL_KEY.to_string(), Value::String(prev));
                    }
                    None => {
                        env.remove(CLAUDE_BASE_URL_KEY);
                    }
                }
                changed = true;
            }
            if applied.is_some_and(|a| a.set_tool_search)
                && env
                    .get(CLAUDE_TOOL_SEARCH_KEY)
                    .and_then(Value::as_str)
                    .is_some_and(|v| v == "true")
            {
                env.remove(CLAUDE_TOOL_SEARCH_KEY);
                changed = true;
            }
            let env_now_empty = env.is_empty();
            if env_now_empty {
                root.remove("env");
            }
        }
    }
    if !changed {
        return Ok(outcome(claude_state(home, listen)?));
    }
    let backup = setup::atomic_write_with_backup(&path, &settings, Some(stamp))?;
    Ok(AgentOutcome {
        state: claude_state(home, listen)?,
        changed: true,
        backup,
    })
}

// ─────────────────────────── Codex CLI(<CODEX_HOME>/config.toml)───────────────────────────

/// Codex 的闸门 base URL(路径前缀 `/codex`;Codex 自己会拼 `/responses`)。
pub fn codex_gate_url(listen: &str) -> String {
    format!("http://{listen}/codex")
}

fn codex_provider_base_url(doc: &toml_edit::DocumentMut) -> Option<String> {
    doc.get("model_providers")?
        .as_table_like()?
        .get(CODEX_PROVIDER_ID)?
        .as_table_like()?
        .get("base_url")?
        .as_str()
        .map(str::to_string)
}

fn codex_model_provider(doc: &toml_edit::DocumentMut) -> Option<String> {
    doc.get("model_provider")?.as_str().map(str::to_string)
}

/// Codex CLI 当前适配状态(只读)。`codex_home` 由调用方按 `CODEX_HOME` 解析。
pub fn codex_state(codex_home: &Path, listen: &str) -> Result<AgentState, SetupError> {
    if !codex_home.is_dir() {
        return Ok(AgentState::NotInstalled);
    }
    let path = codex_home.join("config.toml");
    let Some(doc) = crate::setup_mcp::read_codex_config(&path)? else {
        return Ok(AgentState::NotConfigured);
    };
    let provider = codex_model_provider(&doc);
    let base = codex_provider_base_url(&doc);
    Ok(match (provider.as_deref(), base.as_deref()) {
        (Some(CODEX_PROVIDER_ID), Some(u)) if u == codex_gate_url(listen) => AgentState::Active,
        (Some(CODEX_PROVIDER_ID), _) => AgentState::Stale,
        (None | Some("openai"), Some(_)) => AgentState::Stale,
        (None | Some("openai"), None) => AgentState::NotConfigured,
        (Some(other), _) => AgentState::Unsupported(format!(
            "model_provider `{other}` is in use; the gate only takes over the built-in openai provider"
        )),
    })
}

/// 把 Codex CLI 指到闸门:写 `[model_providers.vigil]` 并把顶层 `model_provider` 切到它。
pub fn codex_apply(
    codex_home: &Path,
    listen: &str,
) -> Result<(AgentOutcome, Option<CodexApplied>), SetupError> {
    if !codex_home.is_dir() {
        return Ok((outcome(AgentState::NotInstalled), None));
    }
    let path = codex_home.join("config.toml");
    let existing = crate::setup_mcp::read_codex_config(&path)?;
    let stamp = if existing.is_some() {
        Some(setup::stamp_for_existing(&path)?)
    } else {
        None
    };
    let mut doc = existing.unwrap_or_default();
    let current = codex_model_provider(&doc);
    let previous_model_provider = match current.as_deref() {
        None | Some("openai") => current.clone(),
        Some(CODEX_PROVIDER_ID) => None,
        Some(other) => {
            return Ok((
                outcome(AgentState::Unsupported(format!(
                    "model_provider `{other}` is in use; the gate only takes over the built-in openai provider"
                ))),
                None,
            ))
        }
    };
    let gate_url = codex_gate_url(listen);
    // 已有同名 provider 但不指向闸门 = 用户自己的配置,绝不覆盖(Codex 审计 2026-09-12 第 8 条)。
    if let Some(existing_base) = codex_provider_base_url(&doc) {
        if existing_base != gate_url && !is_gate_url(&existing_base, "/codex") {
            return Ok((
                outcome(AgentState::Unsupported(format!(
                    "a model provider named `{CODEX_PROVIDER_ID}` already exists and does not point \
                     at the gate; refusing to overwrite it"
                ))),
                None,
            ));
        }
    }
    if current.as_deref() == Some(CODEX_PROVIDER_ID)
        && codex_provider_base_url(&doc).as_deref() == Some(gate_url.as_str())
    {
        return Ok((
            outcome(AgentState::Active),
            Some(CodexApplied {
                config_path: path.display().to_string(),
                previous_model_provider: None,
            }),
        ));
    }

    doc["model_provider"] = toml_edit::value(CODEX_PROVIDER_ID);
    let providers = doc.entry("model_providers").or_insert(toml_edit::table());
    let Some(table) = providers.as_table_mut() else {
        return Err(SetupError::UnsupportedConfigShape {
            path,
            field: "model_providers",
        });
    };
    table.set_implicit(true);
    let mut entry = toml_edit::Table::new();
    entry.insert("name", toml_edit::value("Vigil outbound gate"));
    entry.insert("base_url", toml_edit::value(gate_url));
    entry.insert("wire_api", toml_edit::value("responses"));
    entry.insert("requires_openai_auth", toml_edit::value(true));
    table.insert(CODEX_PROVIDER_ID, toml_edit::Item::Table(entry));

    let backup = setup::atomic_write_str_with_backup(&path, &doc.to_string(), stamp)?;
    Ok((
        AgentOutcome {
            state: AgentState::Active,
            changed: true,
            backup,
        },
        Some(CodexApplied {
            config_path: path.display().to_string(),
            previous_model_provider,
        }),
    ))
}

/// 撤掉我们写进 Codex 的 provider:只在 `model_provider` 仍是 `vigil` 时还原之前的值。
pub fn codex_revert(
    codex_home: &Path,
    listen: &str,
    applied: Option<&CodexApplied>,
) -> Result<AgentOutcome, SetupError> {
    if !codex_home.is_dir() {
        return Ok(outcome(AgentState::NotInstalled));
    }
    let path = codex_home.join("config.toml");
    // stamp 先于读取(理由同 `claude_apply`)。
    let stamp = setup::stamp_for_existing(&path)?;
    let Some(mut doc) = crate::setup_mcp::read_codex_config(&path)? else {
        return Ok(outcome(AgentState::NotConfigured));
    };
    // 这张表**现在**还指向闸门吗?用户改过 `base_url`、或本来就有同名 provider 时,它已经不是
    // 我们的了 —— 无条件删会毁掉用户配置(Codex 审计 2026-09-12 第 8 条)。
    let still_ours = doc
        .get("model_providers")
        .and_then(|i| i.as_table_like())
        .and_then(|t| t.get(CODEX_PROVIDER_ID))
        .and_then(|i| i.as_table_like())
        .and_then(|t| t.get("base_url"))
        .and_then(|v| v.as_str())
        .is_some_and(|u| u == codex_gate_url(listen) || is_gate_url(u, "/codex"));
    let mut changed = false;
    if still_ours && codex_model_provider(&doc).as_deref() == Some(CODEX_PROVIDER_ID) {
        match applied.and_then(|a| a.previous_model_provider.clone()) {
            Some(prev) => doc["model_provider"] = toml_edit::value(prev),
            None => {
                doc.remove("model_provider");
            }
        }
        changed = true;
    }
    if still_ours {
        if let Some(table) = doc
            .get_mut("model_providers")
            .and_then(|i| i.as_table_like_mut())
        {
            if table.remove(CODEX_PROVIDER_ID).is_some() {
                changed = true;
            }
        }
    }
    if !changed {
        return Ok(outcome(codex_state(codex_home, listen)?));
    }
    let backup = setup::atomic_write_str_with_backup(&path, &doc.to_string(), Some(stamp))?;
    Ok(AgentOutcome {
        state: codex_state(codex_home, listen)?,
        changed: true,
        backup,
    })
}

fn outcome(state: AgentState) -> AgentOutcome {
    AgentOutcome {
        state,
        changed: false,
        backup: None,
    }
}

// ─────────────────────────── 账本审计 ───────────────────────────

/// 把闸门事件写进 canonical 账本。payload 只有路由 / 规则名 / 计数 / 别名 / 错误码。
pub struct LedgerAudit {
    ledger: Arc<Ledger>,
    session: Mutex<Option<String>>,
    /// 账本写失败而被丢弃的事件数 —— 经 `healthz` / `status --json` 暴露,见
    /// `GateAudit::dropped_events`(敌意评审 2026-09-12 L3)
    dropped: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for LedgerAudit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LedgerAudit").finish_non_exhaustive()
    }
}

impl LedgerAudit {
    /// 绑定账本;会话在首个事件时懒启动。
    pub fn new(ledger: Arc<Ledger>) -> Self {
        Self {
            ledger,
            session: Mutex::new(None),
            dropped: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn append(&self, event_type: &str, payload: Value, summary: &str) {
        let sid = {
            let mut guard = match self.session.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if guard.is_none() {
                match self.ledger.start_session("vigil-outbound", None) {
                    Ok(s) => *guard = Some(s),
                    Err(e) => {
                        eprintln!(
                            "vigil-outbound: audit start_session failed ({e}); event dropped"
                        );
                        self.dropped
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        return;
                    }
                }
            }
            guard.clone().unwrap_or_default()
        };
        if let Err(e) = self
            .ledger
            .append_event(&sid, event_type, &payload, Some(summary))
        {
            eprintln!("vigil-outbound: audit append_event failed ({e}); event dropped");
            self.dropped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

impl GateAudit for LedgerAudit {
    fn dropped_events(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn rewritten(&self, route: RouteKind, report: &RewriteReport) {
        let kinds: Vec<Value> = report
            .kinds
            .iter()
            .map(|(k, n)| json!({"kind": k, "count": n}))
            .collect();
        let total: usize = report.kinds.iter().map(|(_, n)| n).sum();
        let listing = report
            .kinds
            .iter()
            .map(|(k, n)| format!("{k} x{n}"))
            .collect::<Vec<_>>()
            .join(", ");
        self.append(
            "outbound.request.redacted",
            json!({
                "route": route.as_str(),
                "kinds": kinds,
                "aliases": report.aliases,
            }),
            &format!(
                "outbound: redacted {total} secret span(s) on {} ({listing})",
                route.as_str()
            ),
        );
    }

    fn blocked(&self, route: Option<RouteKind>, code: &'static str) {
        self.append(
            "outbound.request.blocked",
            json!({ "route": route.map(RouteKind::as_str), "code": code }),
            &format!("outbound: blocked request ({code})"),
        );
    }

    fn upstream_error(&self, route: RouteKind, code: &'static str) {
        self.append(
            "outbound.upstream.error",
            json!({ "route": route.as_str(), "code": code }),
            &format!("outbound: upstream error on {} ({code})", route.as_str()),
        );
    }
}

// ─────────────────────────── daemon / 前台启动 ───────────────────────────

fn gate_config(file: &OutboundFile) -> Result<GateConfig, String> {
    Ok(GateConfig {
        listen: parse_listen(&file.listen)?,
        routes: file.upstreams.clone(),
        ..GateConfig::default()
    })
}

fn spawn_gate(file: &OutboundFile, ledger: Option<Arc<Ledger>>) -> Result<GateHandle, String> {
    let cfg = gate_config(file)?;
    let audit: Arc<dyn GateAudit> = match ledger {
        Some(l) => Arc::new(LedgerAudit::new(l)),
        None => Arc::new(vigil_outbound::NoopAudit),
    };
    vigil_outbound::spawn(
        cfg,
        GateDeps {
            aliases: Arc::new(NoAlias),
            audit,
        },
    )
    .map_err(|e| e.to_string())
}

/// daemon 启动时调用:配置开启才起闸门;绑定失败(端口被占)只报 stderr,daemon 其余功能照常。
/// 返回的句柄须活到 daemon 退出(丢弃即关停)。
pub fn spawn_for_daemon(lang: Lang, ledger: Option<Arc<Ledger>>) -> Option<GateHandle> {
    let path = default_outbound_path()?;
    let loaded = load_outbound(&path);
    if let Some(w) = &loaded.warning {
        eprintln!("vigil-hub daemon: {w}");
    }
    if !loaded.file.enabled {
        return None;
    }
    match spawn_gate(&loaded.file, ledger) {
        Ok(handle) => {
            match lang {
                Lang::En => eprintln!(
                    "vigil-hub daemon: outbound gate listening on http://{} (routes: /anthropic /codex /openai /gemini)",
                    handle.addr()
                ),
                Lang::Zh => eprintln!(
                    "vigil-hub daemon:出站闸门监听 http://{}(路由:/anthropic /codex /openai /gemini)",
                    handle.addr()
                ),
            }
            Some(handle)
        }
        Err(e) => {
            match lang {
                Lang::En => eprintln!(
                    "vigil-hub daemon: outbound gate NOT started ({e}); agents pointed at the gate will fail closed until it is fixed"
                ),
                Lang::Zh => eprintln!(
                    "vigil-hub daemon:出站闸门未启动({e});指向闸门的 agent 在修好前会 fail-closed"
                ),
            }
            None
        }
    }
}

/// `outbound serve`:前台跑闸门(不经 daemon;调试 / 没有 daemon 的机器)。阻塞直到进程被杀。
pub fn run_serve(lang: Lang, listen: Option<String>) -> Result<(), String> {
    let path = default_outbound_path().ok_or_else(|| no_data_dir(lang))?;
    let loaded = load_outbound(&path);
    if let Some(w) = &loaded.warning {
        eprintln!("vigil-hub outbound: {w}");
    }
    let mut file = loaded.file;
    if let Some(l) = listen {
        file.listen = l;
    }
    let ledger = setup::default_ledger_path().and_then(|p| {
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        Ledger::open(&p).ok().map(Arc::new)
    });
    let handle = spawn_gate(&file, ledger)?;
    match lang {
        Lang::En => eprintln!(
            "vigil-hub outbound: gate listening on http://{} (Ctrl-C to stop)",
            handle.addr()
        ),
        Lang::Zh => eprintln!(
            "vigil-hub outbound:闸门监听 http://{}(Ctrl-C 停止)",
            handle.addr()
        ),
    }
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

// ─────────────────────────── status / on / off ───────────────────────────

fn no_data_dir(lang: Lang) -> String {
    match lang {
        Lang::En => "cannot locate the local data directory for outbound.json".to_string(),
        Lang::Zh => "无法定位本机数据目录(outbound.json)".to_string(),
    }
}

fn no_home(lang: Lang) -> String {
    match lang {
        Lang::En => "cannot locate the home directory".to_string(),
        Lang::Zh => "无法定位用户主目录".to_string(),
    }
}

fn codex_home_from_env(home: &Path) -> PathBuf {
    let env = std::env::var("CODEX_HOME").ok();
    crate::setup_hooks::resolve_codex_home(home, env.as_deref())
}

/// 探活:GET `/vigil/healthz`,1 秒超时。`None` = 闸门没在监听。
pub fn probe_gate(listen: &str) -> Option<Value> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .ok()?;
    let resp = client
        .get(format!("http://{listen}/vigil/healthz"))
        .send()
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<Value>().ok()
}

fn agent_row(agent: &str, state: &Result<AgentState, SetupError>, config_path: &Path) -> Value {
    match state {
        Ok(s) => json!({
            "agent": agent,
            "state": s.as_str(),
            // `Foreign` 的 detail 是用户自家网关 URL,可能带 userinfo 凭据 → 回显前剥掉
            "detail": s.detail().map(redact_userinfo),
            "config_path": config_path.display().to_string(),
        }),
        Err(e) => json!({
            "agent": agent,
            "state": "error",
            "detail": e.to_string(),
            "config_path": config_path.display().to_string(),
        }),
    }
}

fn describe_state(lang: Lang, s: &Result<AgentState, SetupError>) -> String {
    match s {
        Ok(AgentState::Active) => tr(lang, "active (routed through the gate)", "已生效(经闸门)"),
        Ok(AgentState::NotInstalled) => tr(lang, "not installed", "未安装"),
        Ok(AgentState::NotConfigured) => tr(lang, "not configured", "未配置"),
        Ok(AgentState::Stale) => tr(
            lang,
            "stale (points at an older gate address; run `outbound on` again)",
            "陈旧(指向旧的闸门地址;重跑 `outbound on`)",
        ),
        Ok(AgentState::Foreign(u)) => format!(
            "{} {}",
            tr(lang, "own gateway:", "自家网关:"),
            redact_userinfo(u)
        ),
        Ok(AgentState::Unsupported(r)) => format!("{} {r}", tr(lang, "unsupported:", "不支持:")),
        Err(e) => format!("{} {e}", tr(lang, "error:", "错误:")),
    }
}

fn tr(lang: Lang, en: &str, zh: &str) -> String {
    match lang {
        Lang::En => en.to_string(),
        Lang::Zh => zh.to_string(),
    }
}

/// `outbound status [--json]`。JSON schema 稳定:`enabled` / `listen` / `config_path` /
/// `gate{up,requests,rewritten,blocked,upstream_errors,audit_dropped,uptime_secs}` /
/// `agents[]{agent,state,detail,config_path}` /
/// `upstreams{}` / `warning`。
pub fn run_status(lang: Lang, json_out: bool) -> Result<(), String> {
    let path = default_outbound_path().ok_or_else(|| no_data_dir(lang))?;
    let home = dirs::home_dir().ok_or_else(|| no_home(lang))?;
    let loaded = load_outbound(&path);
    let file = &loaded.file;
    let claude_path = setup::claude_settings_path(&home);
    let codex_home = codex_home_from_env(&home);
    let claude = claude_state(&home, &file.listen);
    let codex = codex_state(&codex_home, &file.listen);
    let probe = probe_gate(&file.listen);

    if json_out {
        let gate = match &probe {
            Some(h) => json!({
                "up": true,
                // 账本写失败被丢弃的事件数:没有它,「没改写」与「改写了但没记上」在外部
                // 观测面上无法区分(敌意评审 2026-09-12 L3)
                "audit_dropped": h.get("audit_dropped"),
                "requests": h.get("requests"),
                "rewritten": h.get("rewritten"),
                "blocked": h.get("blocked"),
                "upstream_errors": h.get("upstream_errors"),
                "uptime_secs": h.get("uptime_secs"),
            }),
            None => json!({ "up": false }),
        };
        let doc = json!({
            "enabled": file.enabled,
            "listen": file.listen,
            "config_path": path.display().to_string(),
            "gate": gate,
            "agents": [
                agent_row("claude", &claude, &claude_path),
                agent_row("codex", &codex, &codex_home.join("config.toml")),
                { "agent": "gemini", "state": "unsupported", "detail": "planned: API-key mode via GOOGLE_GEMINI_BASE_URL; Google-login mode uses a different endpoint", "config_path": Value::Null },
            ],
            // 上游根可能是用户自带凭据的网关 URL;回显前剥 userinfo(落盘仍原样,以便 `off` 还原)
            "upstreams": {
                "anthropic": redact_userinfo(&file.upstreams.anthropic),
                "openai": redact_userinfo(&file.upstreams.openai),
                "codex_chatgpt": redact_userinfo(&file.upstreams.codex_chatgpt),
                "gemini": redact_userinfo(&file.upstreams.gemini),
            },
            "warning": loaded.warning,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?
        );
        return Ok(());
    }

    let enabled = if file.enabled {
        tr(lang, "on", "开启")
    } else {
        tr(lang, "off", "关闭")
    };
    let gate = match &probe {
        Some(h) => format!(
            "{} (requests {}, rewritten {}, blocked {})",
            tr(lang, "up", "运行中"),
            h.get("requests").and_then(Value::as_u64).unwrap_or(0),
            h.get("rewritten").and_then(Value::as_u64).unwrap_or(0),
            h.get("blocked").and_then(Value::as_u64).unwrap_or(0),
        ),
        None => tr(
            lang,
            "down (start it: `vigil-hub daemon start`, or `vigil-hub outbound serve`)",
            "未运行(启动:`vigil-hub daemon start`,或 `vigil-hub outbound serve`)",
        ),
    };
    if let Some(w) = &loaded.warning {
        eprintln!("warning: {w}");
    }
    match lang {
        Lang::En => println!(
            "outbound gate: {enabled}\n  \
             listen:   http://{}\n  \
             gate:     {gate}\n  \
             claude:   {}\n  \
             codex:    {}\n  \
             gemini:   not yet supported\n  \
             config:   {}",
            file.listen,
            describe_state(lang, &claude),
            describe_state(lang, &codex),
            path.display()
        ),
        Lang::Zh => println!(
            "出站闸门:{enabled}\n  \
             监听:    http://{}\n  \
             闸门:    {gate}\n  \
             Claude:  {}\n  \
             Codex:   {}\n  \
             Gemini:  暂不支持\n  \
             配置:    {}",
            file.listen,
            describe_state(lang, &claude),
            describe_state(lang, &codex),
            path.display()
        ),
    }
    Ok(())
}

fn print_outcome(lang: Lang, agent: &str, r: &Result<AgentOutcome, SetupError>) {
    match r {
        Ok(o) => {
            let mut line = format!(
                "  {agent:<8}{}",
                describe_state(lang, &Ok::<_, SetupError>(o.state.clone()))
            );
            if o.changed {
                line.push_str(&tr(lang, " [written", " [已写入"));
                if let Some(b) = &o.backup {
                    line.push_str(&format!(", backup {}", b.display()));
                }
                line.push(']');
            }
            println!("{line}");
        }
        Err(e) => println!("  {agent:<8}{} {e}", tr(lang, "error:", "错误:")),
    }
}

/// `outbound on [--listen host:port]`:落盘开启 + 把 Claude Code / Codex 指到闸门。
pub fn run_on(lang: Lang, listen: Option<String>) -> Result<(), String> {
    let path = default_outbound_path().ok_or_else(|| no_data_dir(lang))?;
    let home = dirs::home_dir().ok_or_else(|| no_home(lang))?;
    let loaded = load_outbound(&path);
    let mut file = loaded.file;
    if let Some(l) = listen {
        parse_listen(&l)?;
        file.listen = l;
    }
    let prior_claude = file.agents.claude.clone();
    let claude = claude_apply(&home, &file.listen, prior_claude.as_ref()).map(|(o, rec)| {
        if let Some(rec) = rec {
            if let Some(prev) = &rec.previous_base_url {
                file.upstreams.anthropic = prev.trim_end_matches('/').to_string();
            }
            file.agents.claude = Some(rec);
        }
        o
    });
    let codex_home = codex_home_from_env(&home);
    let codex = codex_apply(&codex_home, &file.listen).map(|(o, rec)| {
        if let Some(rec) = rec {
            file.agents.codex = Some(rec);
        }
        o
    });
    // **一个 agent 都没真正接上就别落 `enabled`**:否则开关说「开着」、流量却照旧直连,
    // 是最坏的一种安全产品状态(Codex 审计 2026-09-12 第 7 条)。
    let any_active = [&claude, &codex]
        .iter()
        .any(|r| matches!(r, Ok(o) if o.state == AgentState::Active));
    file.enabled = any_active;
    store_outbound(&path, &file).map_err(|e| format!("write {}: {e}", path.display()))?;
    if !any_active {
        print_outcome(lang, "claude", &claude);
        print_outcome(lang, "codex", &codex);
        return Err(tr(
            lang,
            "no agent could be pointed at the gate; the switch was left off",
            "没有任何 agent 被成功指向闸门;开关保持关闭",
        ));
    }

    println!(
        "{}",
        tr(
            lang,
            &format!("outbound gate: on (http://{})", file.listen),
            &format!("出站闸门:已开启(http://{})", file.listen)
        )
    );
    print_outcome(lang, "claude", &claude);
    print_outcome(lang, "codex", &codex);
    if let Some(rec) = &file.agents.claude {
        // 回显前剥 userinfo(落盘的恢复记录保持原样,否则 `off` 还原回去的地址会缺凭据)
        if let Some(prev) = rec.previous_base_url.as_deref().map(redact_userinfo) {
            println!(
                "{}",
                tr(
                    lang,
                    &format!(
                        "  note:   Claude traffic will be chained to your existing gateway {prev}"
                    ),
                    &format!("  说明:   Claude 流量会串到你原来的网关 {prev}")
                )
            );
        }
    }
    let gate_line = if probe_gate(&file.listen).is_some() {
        tr(lang, "  gate:   up", "  闸门:   运行中")
    } else {
        tr(
            lang,
            "  gate:   down -- start it with `vigil-hub daemon start` (or `vigil-hub outbound serve`); until then agents pointed at it fail closed",
            "  闸门:   未运行 —— 用 `vigil-hub daemon start`(或 `vigil-hub outbound serve`)启动;启动前指向它的 agent 会 fail-closed",
        )
    };
    println!("{gate_line}");
    println!(
        "{}",
        tr(
            lang,
            "  next:   restart open agent sessions (they read the base URL at startup)",
            "  下一步:重启已打开的 agent 会话(base URL 在启动时读取)"
        )
    );
    // 任一**已检测到**的 agent 接线失败 ⇒ 非零退出码。否则脚本与 GUI 会把「只接上了一半」读成
    // 全绿,而那台机器上恰恰有一条链路完全不过闸门(敌意评审 2026-09-12 MEDIUM-2)。
    if claude.is_err() || codex.is_err() {
        return Err(tr(
            lang,
            "at least one detected agent could not be wired to the gate (see above); its traffic still bypasses the gate",
            "至少有一个已检测到的 agent 没能接到闸门(见上);它的流量仍然绕过闸门",
        ));
    }
    Ok(())
}

/// `outbound off`:还原 agent 配置 + 落盘关闭(daemon 下次启动不再起闸门;已在跑的需重启 daemon)。
pub fn run_off(lang: Lang) -> Result<(), String> {
    let path = default_outbound_path().ok_or_else(|| no_data_dir(lang))?;
    let home = dirs::home_dir().ok_or_else(|| no_home(lang))?;
    let loaded = load_outbound(&path);
    let mut file = loaded.file;
    let claude = claude_revert(&home, &file.listen, file.agents.claude.as_ref());
    let codex_home = codex_home_from_env(&home);
    let codex = codex_revert(&codex_home, &file.listen, file.agents.codex.as_ref());
    file.enabled = false;
    // 恢复**失败**的 agent 记录必须留着:它是下一次 `off` 唯一的还原依据,清掉就永远还不回
    // 用户原来的网关了(Codex 审计 2026-09-12 第 7 条 B)。
    if claude.is_ok() {
        file.agents.claude = None;
        file.upstreams.anthropic = Routes::default().anthropic;
    }
    if codex.is_ok() {
        file.agents.codex = None;
    }
    store_outbound(&path, &file).map_err(|e| format!("write {}: {e}", path.display()))?;
    println!("{}", tr(lang, "outbound gate: off", "出站闸门:已关闭"));
    print_outcome(lang, "claude", &claude);
    print_outcome(lang, "codex", &codex);
    if probe_gate(&file.listen).is_some() {
        println!(
            "{}",
            tr(
                lang,
                "  note:   a gate is still listening; restart the daemon to stop it",
                "  说明:   闸门仍在监听;重启 daemon 即停"
            )
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home_with_claude() -> tempfile::TempDir {
        let td = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(td.path().join(".claude")).unwrap();
        td
    }

    fn read_json(p: &Path) -> Value {
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    }

    #[test]
    fn config_roundtrip_and_fail_closed() {
        let td = tempfile::tempdir().unwrap();
        let p = td.path().join("Vigil").join("outbound.json");
        assert_eq!(load_outbound(&p).file, OutboundFile::default());
        let f = OutboundFile {
            enabled: true,
            listen: "127.0.0.1:9000".into(),
            ..OutboundFile::default()
        };
        store_outbound(&p, &f).unwrap();
        let l = load_outbound(&p);
        assert_eq!(l.file, f);
        assert!(l.warning.is_none());

        std::fs::write(&p, "{not json").unwrap();
        let l = load_outbound(&p);
        assert!(!l.file.enabled);
        assert!(l.warning.as_deref().unwrap().contains("malformed"));

        std::fs::write(
            &p,
            r#"{"version":99,"enabled":true,"listen":"127.0.0.1:1"}"#,
        )
        .unwrap();
        assert!(!load_outbound(&p).file.enabled);

        std::fs::write(
            &p,
            r#"{"version":1,"enabled":true,"listen":"0.0.0.0:8445"}"#,
        )
        .unwrap();
        let l = load_outbound(&p);
        assert!(!l.file.enabled, "非环回监听地址必须 fail-closed 当作关闭");
        assert!(l.warning.is_some());
    }

    #[test]
    fn listen_must_be_loopback() {
        assert!(parse_listen("127.0.0.1:8445").is_ok());
        assert!(parse_listen("[::1]:8445").is_ok());
        assert!(parse_listen("0.0.0.0:8445").is_err());
        assert!(parse_listen("192.168.1.5:8445").is_err());
        assert!(parse_listen("nonsense").is_err());
    }

    #[test]
    fn claude_apply_creates_env_and_revert_removes_only_ours() {
        let td = home_with_claude();
        let home = td.path();
        assert_eq!(
            claude_state(home, DEFAULT_LISTEN).unwrap(),
            AgentState::NotConfigured
        );

        let (o, rec) = claude_apply(home, DEFAULT_LISTEN, None).unwrap();
        assert_eq!(o.state, AgentState::Active);
        assert!(o.changed);
        let rec = rec.unwrap();
        assert_eq!(rec.previous_base_url, None);
        assert!(rec.set_tool_search);
        let v = read_json(&setup::claude_settings_path(home));
        assert_eq!(
            v["env"]["ANTHROPIC_BASE_URL"],
            "http://127.0.0.1:8445/anthropic"
        );
        assert_eq!(v["env"]["ENABLE_TOOL_SEARCH"], "true");
        assert_eq!(
            claude_state(home, DEFAULT_LISTEN).unwrap(),
            AgentState::Active
        );

        // 幂等:再 apply 不改文件
        let (o2, _) = claude_apply(home, DEFAULT_LISTEN, None).unwrap();
        assert_eq!(o2.state, AgentState::Active);
        assert!(!o2.changed);

        let r = claude_revert(home, DEFAULT_LISTEN, Some(&rec)).unwrap();
        assert!(r.changed);
        assert_eq!(r.state, AgentState::NotConfigured);
        let v = read_json(&setup::claude_settings_path(home));
        assert!(v.get("env").is_none(), "空 env 应整个移除: {v}");
    }

    #[test]
    fn claude_apply_preserves_other_keys_and_chains_foreign_gateway() {
        let td = home_with_claude();
        let home = td.path();
        let p = setup::claude_settings_path(home);
        std::fs::write(
            &p,
            r#"{"permissions":{"allow":["Bash(ls)"]},"env":{"ANTHROPIC_BASE_URL":"https://litellm.corp.example/","ENABLE_TOOL_SEARCH":"false","OTHER":"1"},"hooks":{}}"#,
        )
        .unwrap();
        assert_eq!(
            claude_state(home, DEFAULT_LISTEN).unwrap(),
            AgentState::Foreign("https://litellm.corp.example/".into())
        );
        let (o, rec) = claude_apply(home, DEFAULT_LISTEN, None).unwrap();
        assert_eq!(o.state, AgentState::Active);
        assert!(o.backup.is_some(), "改既有文件必须留备份");
        let rec = rec.unwrap();
        assert_eq!(
            rec.previous_base_url.as_deref(),
            Some("https://litellm.corp.example/")
        );
        assert!(
            !rec.set_tool_search,
            "用户自己设过 ENABLE_TOOL_SEARCH 就不动它"
        );
        let v = read_json(&p);
        assert_eq!(
            v["env"]["ANTHROPIC_BASE_URL"],
            "http://127.0.0.1:8445/anthropic"
        );
        assert_eq!(v["env"]["ENABLE_TOOL_SEARCH"], "false");
        assert_eq!(v["env"]["OTHER"], "1");
        assert_eq!(v["permissions"]["allow"][0], "Bash(ls)");
        // 键序保留:permissions 仍在 env 之前
        let s = std::fs::read_to_string(&p).unwrap();
        assert!(s.find("permissions").unwrap() < s.find("\"env\"").unwrap());

        let r = claude_revert(home, DEFAULT_LISTEN, Some(&rec)).unwrap();
        assert!(r.changed);
        let v = read_json(&p);
        assert_eq!(
            v["env"]["ANTHROPIC_BASE_URL"],
            "https://litellm.corp.example/"
        );
        assert_eq!(v["env"]["ENABLE_TOOL_SEARCH"], "false");
        assert_eq!(v["env"]["OTHER"], "1");
    }

    #[test]
    fn claude_revert_leaves_user_changed_value_alone() {
        let td = home_with_claude();
        let home = td.path();
        let (_, rec) = claude_apply(home, DEFAULT_LISTEN, None).unwrap();
        let p = setup::claude_settings_path(home);
        std::fs::write(&p, r#"{"env":{"ANTHROPIC_BASE_URL":"https://user.changed.example","ENABLE_TOOL_SEARCH":"true"}}"#).unwrap();
        let r = claude_revert(home, DEFAULT_LISTEN, rec.as_ref()).unwrap();
        // base URL 不是我们的 → 不还原;但 ENABLE_TOOL_SEARCH 是我们加的且仍为 true → 删
        let v = read_json(&p);
        assert_eq!(
            v["env"]["ANTHROPIC_BASE_URL"],
            "https://user.changed.example"
        );
        assert!(v["env"].get("ENABLE_TOOL_SEARCH").is_none());
        assert!(r.changed);
        assert_eq!(
            r.state,
            AgentState::Foreign("https://user.changed.example".into())
        );
    }

    #[test]
    fn claude_stale_gate_url_is_replaced_without_recording_previous() {
        let td = home_with_claude();
        let home = td.path();
        let p = setup::claude_settings_path(home);
        std::fs::write(
            &p,
            r#"{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:9999/anthropic"}}"#,
        )
        .unwrap();
        assert_eq!(
            claude_state(home, DEFAULT_LISTEN).unwrap(),
            AgentState::Stale
        );
        let (o, rec) = claude_apply(home, DEFAULT_LISTEN, None).unwrap();
        assert_eq!(o.state, AgentState::Active);
        assert_eq!(rec.unwrap().previous_base_url, None);
    }

    #[test]
    fn claude_bedrock_mode_is_unsupported_and_untouched() {
        let td = home_with_claude();
        let home = td.path();
        let p = setup::claude_settings_path(home);
        let original = r#"{"env":{"CLAUDE_CODE_USE_BEDROCK":"1","AWS_REGION":"us-east-1"}}"#;
        std::fs::write(&p, original).unwrap();
        let (o, rec) = claude_apply(home, DEFAULT_LISTEN, None).unwrap();
        assert!(matches!(o.state, AgentState::Unsupported(_)));
        assert!(!o.changed);
        assert!(rec.is_none());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), original);
        assert!(matches!(
            claude_state(home, DEFAULT_LISTEN).unwrap(),
            AgentState::Unsupported(_)
        ));
    }

    #[test]
    fn claude_malformed_settings_abort() {
        let td = home_with_claude();
        let home = td.path();
        let p = setup::claude_settings_path(home);
        std::fs::write(&p, "{oops").unwrap();
        assert!(matches!(
            claude_apply(home, DEFAULT_LISTEN, None),
            Err(SetupError::MalformedConfig { .. })
        ));
        std::fs::write(&p, r#"{"env":"not-an-object"}"#).unwrap();
        assert!(matches!(
            claude_apply(home, DEFAULT_LISTEN, None),
            Err(SetupError::UnsupportedConfigShape { .. })
        ));
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            r#"{"env":"not-an-object"}"#
        );
    }

    #[test]
    fn claude_not_installed_is_reported_without_writing() {
        let td = tempfile::tempdir().unwrap();
        let (o, rec) = claude_apply(td.path(), DEFAULT_LISTEN, None).unwrap();
        assert_eq!(o.state, AgentState::NotInstalled);
        assert!(rec.is_none());
        assert!(!setup::claude_settings_path(td.path()).exists());
    }

    #[test]
    fn codex_apply_writes_provider_preserving_comments_and_revert_restores() {
        let td = tempfile::tempdir().unwrap();
        let codex_home = td.path().join(".codex");
        std::fs::create_dir_all(&codex_home).unwrap();
        let p = codex_home.join("config.toml");
        std::fs::write(
            &p,
            "# my codex config\nmodel = \"gpt-5.5\"\nmodel_provider = \"openai\"\n\n[mcp_servers.fs]\ncommand = \"npx\"\nargs = [\"-y\", \"fs\"]\n",
        )
        .unwrap();
        assert_eq!(
            codex_state(&codex_home, DEFAULT_LISTEN).unwrap(),
            AgentState::NotConfigured
        );

        let (o, rec) = codex_apply(&codex_home, DEFAULT_LISTEN).unwrap();
        assert_eq!(o.state, AgentState::Active);
        assert!(o.changed);
        assert!(o.backup.is_some());
        let rec = rec.unwrap();
        assert_eq!(rec.previous_model_provider.as_deref(), Some("openai"));
        let s = std::fs::read_to_string(&p).unwrap();
        assert!(s.starts_with("# my codex config\n"), "注释须保留: {s}");
        assert!(s.contains("model = \"gpt-5.5\""));
        assert!(s.contains("model_provider = \"vigil\""));
        assert!(s.contains("[model_providers.vigil]"));
        assert!(s.contains("base_url = \"http://127.0.0.1:8445/codex\""));
        assert!(s.contains("wire_api = \"responses\""));
        assert!(s.contains("requires_openai_auth = true"));
        assert!(s.contains("[mcp_servers.fs]"));
        let doc: toml_edit::DocumentMut = s.parse().unwrap();
        assert_eq!(doc["model_provider"].as_str(), Some("vigil"));
        assert_eq!(
            codex_state(&codex_home, DEFAULT_LISTEN).unwrap(),
            AgentState::Active
        );

        let (o2, _) = codex_apply(&codex_home, DEFAULT_LISTEN).unwrap();
        assert!(!o2.changed, "幂等");

        let r = codex_revert(&codex_home, DEFAULT_LISTEN, Some(&rec)).unwrap();
        assert!(r.changed);
        assert_eq!(r.state, AgentState::NotConfigured);
        let s = std::fs::read_to_string(&p).unwrap();
        assert!(s.contains("model_provider = \"openai\""));
        assert!(!s.contains("model_providers.vigil"));
        assert!(s.contains("[mcp_servers.fs]"));
        assert!(s.starts_with("# my codex config\n"));
    }

    #[test]
    fn codex_without_config_file_gets_a_fresh_one_and_revert_drops_provider() {
        let td = tempfile::tempdir().unwrap();
        let codex_home = td.path().join(".codex");
        std::fs::create_dir_all(&codex_home).unwrap();
        let (o, rec) = codex_apply(&codex_home, DEFAULT_LISTEN).unwrap();
        assert_eq!(o.state, AgentState::Active);
        let rec = rec.unwrap();
        assert_eq!(rec.previous_model_provider, None);
        let s = std::fs::read_to_string(codex_home.join("config.toml")).unwrap();
        let doc: toml_edit::DocumentMut = s.parse().unwrap();
        assert_eq!(doc["model_provider"].as_str(), Some("vigil"));
        let r = codex_revert(&codex_home, DEFAULT_LISTEN, Some(&rec)).unwrap();
        assert!(r.changed);
        let s = std::fs::read_to_string(codex_home.join("config.toml")).unwrap();
        assert!(!s.contains("model_provider"), "{s}");
    }

    #[test]
    fn codex_custom_provider_is_unsupported_and_untouched() {
        let td = tempfile::tempdir().unwrap();
        let codex_home = td.path().join(".codex");
        std::fs::create_dir_all(&codex_home).unwrap();
        let p = codex_home.join("config.toml");
        let original = "model_provider = \"litellm\"\n\n[model_providers.litellm]\nbase_url = \"http://localhost:4000\"\nwire_api = \"responses\"\n";
        std::fs::write(&p, original).unwrap();
        let (o, rec) = codex_apply(&codex_home, DEFAULT_LISTEN).unwrap();
        assert!(matches!(o.state, AgentState::Unsupported(_)));
        assert!(rec.is_none());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), original);
    }

    #[test]
    fn codex_not_installed_and_stale_detection() {
        let td = tempfile::tempdir().unwrap();
        let codex_home = td.path().join(".codex");
        assert_eq!(
            codex_state(&codex_home, DEFAULT_LISTEN).unwrap(),
            AgentState::NotInstalled
        );
        std::fs::create_dir_all(&codex_home).unwrap();
        std::fs::write(
            codex_home.join("config.toml"),
            "model_provider = \"vigil\"\n[model_providers.vigil]\nbase_url = \"http://127.0.0.1:9999/codex\"\nwire_api = \"responses\"\n",
        )
        .unwrap();
        assert_eq!(
            codex_state(&codex_home, DEFAULT_LISTEN).unwrap(),
            AgentState::Stale
        );
        let (o, _) = codex_apply(&codex_home, DEFAULT_LISTEN).unwrap();
        assert_eq!(o.state, AgentState::Active);
        assert!(o.changed);
    }

    /// 手工切串会被 userinfo 伪装骗过:`http://127.0.0.1:80@evil.com/anthropic` 的真实主机是
    /// `evil.com`,按最后一个 `:` 切却得到「host = 127.0.0.1」,于是 `off` 会把一个**远程**
    /// 地址当成自家闸门删掉(Codex 审计 2026-09-12 第 10 条)。
    #[test]
    fn gate_url_matcher_rejects_userinfo_spoofing() {
        assert!(is_vigil_gate_url("http://127.0.0.1:8445/anthropic"));
        assert!(is_vigil_gate_url("http://localhost:8445/anthropic/"));
        assert!(is_gate_url("http://127.0.0.1:8445/codex", "/codex"));

        assert!(!is_vigil_gate_url("http://127.0.0.1:80@evil.com/anthropic"));
        assert!(!is_vigil_gate_url(
            "http://user:pw@127.0.0.1:8445/anthropic"
        ));
        assert!(!is_vigil_gate_url("http://127.0.0.1.evil.com/anthropic"));
        assert!(!is_vigil_gate_url("https://127.0.0.1:8445/anthropic"));
        assert!(!is_vigil_gate_url("http://127.0.0.1:8445/openai"));
        assert!(!is_vigil_gate_url("not a url"));
    }

    /// 连续两次 `on`:第二次看到的当前值正是**我们自己**写的闸门地址,绝不能据此把首次记下的
    /// 企业网关抹成 `None` —— 那样 `off` 就再也还不回去了(Codex 审计 2026-09-12 第 6 条)。
    #[test]
    fn repeated_apply_preserves_the_first_restore_record() {
        let td = home_with_claude();
        let home = td.path();
        let p = setup::claude_settings_path(home);
        std::fs::write(
            &p,
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://gateway.corp.example"}}"#,
        )
        .unwrap();

        let (_, rec1) = claude_apply(home, DEFAULT_LISTEN, None).unwrap();
        let rec1 = rec1.unwrap();
        assert_eq!(
            rec1.previous_base_url.as_deref(),
            Some("https://gateway.corp.example")
        );

        let (o2, rec2) = claude_apply(home, DEFAULT_LISTEN, Some(&rec1)).unwrap();
        assert_eq!(o2.state, AgentState::Active);
        let rec2 = rec2.unwrap();
        assert_eq!(
            rec2.previous_base_url.as_deref(),
            Some("https://gateway.corp.example"),
            "第二次 on 不得覆盖首次的恢复记录"
        );

        let r = claude_revert(home, DEFAULT_LISTEN, Some(&rec2)).unwrap();
        assert!(r.changed);
        let v = read_json(&p);
        assert_eq!(
            v["env"]["ANTHROPIC_BASE_URL"], "https://gateway.corp.example",
            "off 必须还原企业网关"
        );
    }

    /// `off` 只删**仍指向闸门**的 provider 表:用户改过 `base_url` 就已经不是我们的了
    /// (Codex 审计 2026-09-12 第 8 条)。
    #[test]
    fn codex_revert_leaves_a_user_edited_provider_alone() {
        let td = tempfile::tempdir().unwrap();
        let codex_home = td.path().join(".codex");
        std::fs::create_dir_all(&codex_home).unwrap();
        let (_, rec) = codex_apply(&codex_home, DEFAULT_LISTEN).unwrap();
        let p = codex_home.join("config.toml");
        let edited = std::fs::read_to_string(&p).unwrap().replace(
            "http://127.0.0.1:8445/codex",
            "https://gateway.corp.example",
        );
        std::fs::write(&p, &edited).unwrap();

        let r = codex_revert(&codex_home, DEFAULT_LISTEN, rec.as_ref()).unwrap();
        assert!(!r.changed, "用户改过的 provider 不得被删除");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), edited);
    }

    /// 已有同名 provider 但不指向闸门 = 用户自己的配置,`on` 绝不覆盖。
    #[test]
    fn codex_apply_refuses_to_overwrite_a_foreign_provider_of_the_same_name() {
        let td = tempfile::tempdir().unwrap();
        let codex_home = td.path().join(".codex");
        std::fs::create_dir_all(&codex_home).unwrap();
        let p = codex_home.join("config.toml");
        let original = "[model_providers.vigil]\nbase_url = \"https://gateway.corp.example\"\nwire_api = \"responses\"\n";
        std::fs::write(&p, original).unwrap();

        let (o, rec) = codex_apply(&codex_home, DEFAULT_LISTEN).unwrap();
        assert!(matches!(o.state, AgentState::Unsupported(_)), "{o:?}");
        assert!(rec.is_none());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), original);
    }

    #[test]
    fn ledger_audit_payloads_carry_no_secret_bytes() {
        let td = tempfile::tempdir().unwrap();
        let ledger = Arc::new(Ledger::open(td.path().join("ledger.sqlite3")).unwrap());
        let audit = LedgerAudit::new(Arc::clone(&ledger));
        let report = RewriteReport {
            kinds: vec![("github_token", 2), ("env_assignment", 1)],
            aliases: vec![],
            skipped_envelope_fields: 3,
        };
        audit.rewritten(RouteKind::Anthropic, &report);
        audit.blocked(None, "unknown_route");
        audit.upstream_error(RouteKind::Codex, "upstream_connect");
        let events = ledger.list_recent_events(None, None, 10).unwrap();
        let types: Vec<String> = events.iter().map(|e| e.event_type.clone()).collect();
        assert!(
            types.contains(&"outbound.request.redacted".to_string()),
            "{types:?}"
        );
        assert!(types.contains(&"outbound.request.blocked".to_string()));
        assert!(types.contains(&"outbound.upstream.error".to_string()));
    }
}
