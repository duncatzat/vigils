//! `vigil-hub setup` 的多 agent hook 注册面(TASK-002):Codex CLI / Gemini CLI / Cursor。
//!
//! 与 [`crate::setup`](Claude 注册面)同纪律:**检测到才注册**(对应配置目录存在)、幂等合并、
//! sentinel(`--vigil-managed` 精确 token)识别/卸载、abort-on-unexpected-shape、原子写 + 备份、
//! 诚实 status 分级、错误脱敏 —— 六安全门全部复用 `setup` 的 `pub(crate)` 基础设施,不重复实现。
//!
//! # 三家 hooks 配置契约(官方文档核实,2026-06;**不**沿用 CodeIsland 过时参考)
//! - **Codex CLI**(developers.openai.com/codex/hooks):`$CODEX_HOME/hooks.json`(默认 `~/.codex/`)。
//!   形状 = `{"hooks": {<事件>: [<matcher 组>]}}`,matcher 组 = `{matcher?, "hooks": [{type:"command",
//!   command, timeout}]}`(与 Claude settings.json 的条目同构,matcher 可省略 = 全工具)。
//!   `timeout` 单位**秒**(默认 600)。hooks 功能现已**默认开启**;显式 `[features] hooks = false`
//!   时我们**只警告不改写**(用户刻意关闭安全开关,静默翻转违反 abort-on-unexpected 纪律)。
//! - **Gemini CLI**(geminicli.com/docs/hooks):`~/.gemini/settings.json` 顶层 `hooks` 下
//!   `BeforeTool` / `AfterTool` 事件,matcher 组形状同上,但 `timeout` 单位**毫秒**(默认 60000)。
//! - **Cursor**(cursor.com/docs/hooks):`~/.cursor/hooks.json` = `{"version": 1, "hooks": {<事件>:
//!   [{command, timeout, failClosed}]}}`(**扁平** entry,无 matcher 组嵌套)。事件名官方为
//!   `beforeShellExecution` / `beforeMCPExecution`(大写 MCP)/ `afterShellExecution` /
//!   `afterMCPExecution`。`timeout` 单位**秒**。注册带 **`failClosed: true`**:hook 崩溃/超时/
//!   坏 JSON 时 Cursor 拦截而非放行(安全 hook 必须 fail-closed;hook 侧 Allow 因此显式输出
//!   `{"permission":"allow"}`,不能静默 exit 0)。
//!
//! # command 形状
//! 每面写入 `<exe> hook --vigil-managed --cli <agent> --ledger <ledger>`(路径 shell-转义),
//! `--cli` 让 hook 选对事件名归一映射与响应输出形状(Gemini 顶层 `decision` / Cursor 顶层
//! `permission` / Codex `hookSpecificOutput`)。Claude 注册面**不带** `--cli`(canonical 串
//! 向后兼容,见 [`crate::setup::hook_command_with_cli`])。

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::Digest;

use crate::setup::{
    atomic_write_with_backup, command_is_vigil_managed, hook_command_with_cli, is_vigil_entry,
    read_settings, validate_path_for_command, ProtectionState, SetupError,
};

// ── 超时常量(单位随各家契约,见模块 doc)──
/// Codex PreToolUse 超时(秒):共同批准(co-approval)在 Codex 侧用长阻塞等待 Vigil 裁决
/// (等待预算 86000s),hook timeout 须大于它;86400s = 24h,与 PermissionRequest 类长交互对齐。
const CODEX_PRE_TOOL_USE_TIMEOUT_SECS: u64 = 86_400;
/// Codex PostToolUse 超时(秒):结果再脱敏是本地快速操作,60s 与 Claude 注册面一致。
const CODEX_POST_TOOL_USE_TIMEOUT_SECS: u64 = 60;
/// Codex UserPromptSubmit 超时(秒):对 prompt 扫裸硬指纹 secret 是本地快速操作,不走 co-approval,60s 充裕。
const CODEX_USER_PROMPT_SUBMIT_TIMEOUT_SECS: u64 = 60;
/// Gemini hook 超时(**毫秒**,官方契约单位):co-approval 等待预算 45s + 输出余量 → 60000ms。
const GEMINI_HOOK_TIMEOUT_MS: u64 = 60_000;
/// Cursor hook 超时(秒):co-approval 等待预算 45s + 输出余量 → 60s。
const CURSOR_HOOK_TIMEOUT_SECS: u64 = 60;

/// 单个事件的注册规格:事件名 + 超时值(单位由所属 agent 的契约决定,写入时原样落 `timeout` 字段)。
#[derive(Debug)]
struct EventSpec {
    event: &'static str,
    timeout: u64,
}

/// Codex 注册事件集:PreToolUse(输入守门 + co-approval 长等待)+ PostToolUse(再脱敏面,TASK-006)
/// + UserPromptSubmit(prompt 输入侧守门,根因 B —— 贴进对话框的裸 secret 走此事件,非工具调用)。
const CODEX_EVENTS: [EventSpec; 3] = [
    EventSpec {
        event: "PreToolUse",
        timeout: CODEX_PRE_TOOL_USE_TIMEOUT_SECS,
    },
    EventSpec {
        event: "PostToolUse",
        timeout: CODEX_POST_TOOL_USE_TIMEOUT_SECS,
    },
    // 根因 B:用户直接把裸凭据贴进 codex 对话框(非工具调用)时,secret 走 UserPromptSubmit;
    // 此前只注册 Pre/PostToolUse → 完全绕过 Vigil。hook 侧 [`handle_user_prompt_submit`] 扫裸硬指纹 block。
    EventSpec {
        event: "UserPromptSubmit",
        timeout: CODEX_USER_PROMPT_SUBMIT_TIMEOUT_SECS,
    },
];
/// Gemini 注册事件集(官方事件名 BeforeTool/AfterTool;hook 侧归一为 PreToolUse/PostToolUse)。
const GEMINI_EVENTS: [EventSpec; 2] = [
    EventSpec {
        event: "BeforeTool",
        timeout: GEMINI_HOOK_TIMEOUT_MS,
    },
    EventSpec {
        event: "AfterTool",
        timeout: GEMINI_HOOK_TIMEOUT_MS,
    },
];
/// Cursor 注册事件集:shell 与 MCP 执行边界各前后两面(官方名,大写 MCP)。
const CURSOR_EVENTS: [EventSpec; 4] = [
    EventSpec {
        event: "beforeShellExecution",
        timeout: CURSOR_HOOK_TIMEOUT_SECS,
    },
    EventSpec {
        event: "beforeMCPExecution",
        timeout: CURSOR_HOOK_TIMEOUT_SECS,
    },
    EventSpec {
        event: "afterShellExecution",
        timeout: CURSOR_HOOK_TIMEOUT_SECS,
    },
    EventSpec {
        event: "afterMCPExecution",
        timeout: CURSOR_HOOK_TIMEOUT_SECS,
    },
];

/// 条目形状:Codex/Gemini = matcher 组嵌套(与 Claude 同构);Cursor = 扁平 `{command, timeout, failClosed}`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryStyle {
    Nested,
    Flat,
}

/// 一个 agent hook 注册面的完整规格(路径 DI,便于 tempfile 测试)。
#[derive(Debug)]
pub struct AgentHookSpec {
    /// 稳定小写名,同时是 hook command 的 `--cli` 值(须与 `hook::CliKind` 的 clap 名一致)。
    pub agent: &'static str,
    /// 人类可读名(报告用)。
    pub display_name: &'static str,
    /// "已安装"检测目录(存在才注册,不为不存在的 agent 创建配置)。
    detect_dir: PathBuf,
    /// hooks 配置文件路径。
    pub config_path: PathBuf,
    events: &'static [EventSpec],
    style: EntryStyle,
    /// Cursor hooks.json 的 `version: 1` 根字段(schema 版本;非 1 则 abort 不动)。
    versioned_root: bool,
}

/// 通用 agent 配置目录解析:env 非空白 → 该值(`~`/`~/...` 展开到 home;**无根相对路径在本
/// 进程 CWD 绝对化**);否则 `default()`。Codex(`CODEX_HOME`)与 pi(`PI_AGENT_DIR`)共用
/// 同一展开语义(SSOT,注入式可测)。
///
/// 相对路径语义**对齐 vendor**:openai/codex(`codex-utils-home-dir`,源码实证)把 env 值
/// `canonicalize()` —— 即按 codex 进程 CWD 解析;pi adapter 为 node 生态同 CWD 惯例。用户在
/// 项目目录内 `setup`,写入位置与其在同目录跑 agent 时 vendor 读取的位置一致。此前相对值
/// 原样透传,后续 join 出 CWD 依赖的未绝对化路径 —— setup/status/doctor 换目录即漂移且不
/// 自知;绝对化后单次调用内确定,跨目录差异回归 vendor 本身的语义。判据用 `has_root`(非
/// `is_absolute`):Windows 上 `/x`(root-relative)与 `C:x`(drive-relative)保持原样交 OS
/// 按其规则解析,不强行拼接。
pub(crate) fn resolve_agent_dir(
    home: &Path,
    env_val: Option<&str>,
    default: impl FnOnce() -> PathBuf,
) -> PathBuf {
    let cwd = std::env::current_dir().unwrap_or_default();
    resolve_agent_dir_with_cwd(home, &cwd, env_val, default)
}

/// [`resolve_agent_dir`] 的纯核心(cwd 注入可测)。`cwd` 空(取 CWD 失败)→ 相对值退回
/// 原样透传(不 panic,行为等同旧版)。
fn resolve_agent_dir_with_cwd(
    home: &Path,
    cwd: &Path,
    env_val: Option<&str>,
    default: impl FnOnce() -> PathBuf,
) -> PathBuf {
    match env_val.map(str::trim).filter(|s| !s.is_empty()) {
        Some("~") => home.to_path_buf(),
        Some(s) => {
            if let Some(rest) = s.strip_prefix("~/").or_else(|| s.strip_prefix("~\\")) {
                home.join(rest)
            } else if Path::new(s).has_root() || cwd.as_os_str().is_empty() {
                PathBuf::from(s)
            } else {
                cwd.join(s)
            }
        }
        None => default(),
    }
}

/// 解析 `$CODEX_HOME`:env 非空白 → 该值(`~`/`~/...` 展开到 home);否则默认 `~/.codex`。
/// `pub(crate)`:MCP 接入面([`crate::setup_mcp::codex_config_path`])与 hook 注册面共用**同一**
/// 解析(SSOT)—— 此前 MCP 面固定 `~/.codex`,自定义 `CODEX_HOME` 的用户其 MCP server 全部
/// 漏保护且 status/doctor 不可见(agent-surface review 2026-07-17 HIGH-1)。
pub(crate) fn resolve_codex_home(home: &Path, env_val: Option<&str>) -> PathBuf {
    resolve_agent_dir(home, env_val, || home.join(".codex"))
}

/// Codex CLI 注册面规格。`codex_home_env` = `CODEX_HOME` 环境变量值(生产由 [`all_agent_specs`] 读)。
pub fn codex_spec(home: &Path, codex_home_env: Option<&str>) -> AgentHookSpec {
    let codex_home = resolve_codex_home(home, codex_home_env);
    AgentHookSpec {
        agent: "codex",
        display_name: "Codex CLI",
        config_path: codex_home.join("hooks.json"),
        detect_dir: codex_home,
        events: &CODEX_EVENTS,
        style: EntryStyle::Nested,
        versioned_root: false,
    }
}

/// Gemini CLI 注册面规格(`~/.gemini/settings.json` 是共享设置文件,只动其 `hooks` 子树)。
pub fn gemini_spec(home: &Path) -> AgentHookSpec {
    AgentHookSpec {
        agent: "gemini",
        display_name: "Gemini CLI",
        detect_dir: home.join(".gemini"),
        config_path: home.join(".gemini").join("settings.json"),
        events: &GEMINI_EVENTS,
        style: EntryStyle::Nested,
        versioned_root: false,
    }
}

/// Cursor 注册面规格(`~/.cursor/hooks.json` 是 hooks 专属文件,根带 `version: 1`)。
pub fn cursor_spec(home: &Path) -> AgentHookSpec {
    AgentHookSpec {
        agent: "cursor",
        display_name: "Cursor",
        detect_dir: home.join(".cursor"),
        config_path: home.join(".cursor").join("hooks.json"),
        events: &CURSOR_EVENTS,
        style: EntryStyle::Flat,
        versioned_root: true,
    }
}

/// 生产入口:全部三个 agent 规格(Codex 的 `CODEX_HOME` 从环境读)。
pub fn all_agent_specs(home: &Path) -> [AgentHookSpec; 3] {
    let codex_home_env = std::env::var("CODEX_HOME").ok();
    [
        codex_spec(home, codex_home_env.as_deref()),
        gemini_spec(home),
        cursor_spec(home),
    ]
}

/// 渲染该面的 canonical 条目。
fn canonical_entry(style: EntryStyle, command: &str, ev: &EventSpec) -> Value {
    match style {
        // Codex/Gemini matcher 组:省略 matcher = 匹配全部工具(官方契约,matcher 可选)。
        EntryStyle::Nested => json!({
            "hooks": [{ "type": "command", "command": command, "timeout": ev.timeout }]
        }),
        // Cursor 扁平条目:failClosed=true 让 hook 自身故障也拦截(安全 hook 不 fail-open)。
        EntryStyle::Flat => json!({
            "command": command, "timeout": ev.timeout, "failClosed": true
        }),
    }
}

/// 条目是否 Vigil 托管(sentinel 精确 token 匹配,两种形状各走各的识别路径)。
fn entry_is_managed(style: EntryStyle, entry: &Value) -> bool {
    match style {
        // matcher 组与 Claude settings.json 条目同构,直接复用 setup 的识别器。
        EntryStyle::Nested => is_vigil_entry(entry),
        EntryStyle::Flat => entry
            .get("command")
            .and_then(Value::as_str)
            .map(command_is_vigil_managed)
            .unwrap_or(false),
    }
}

/// 形状校验(install 前):顶层 object;`version`(若有且该面带版本根)必须 == 1;`hooks`(若有)
/// 是 object;我们要写的每个事件键(若有)是 array。不符 → abort 不归一化(与 setup 同纪律)。
fn ensure_agent_shape(spec: &AgentHookSpec, settings: &Value) -> Result<(), SetupError> {
    let bad = |field: &'static str| {
        Err(SetupError::UnsupportedConfigShape {
            path: spec.config_path.clone(),
            field,
        })
    };
    if !settings.is_object() {
        return bad("<root>");
    }
    if spec.versioned_root {
        if let Some(v) = settings.get("version") {
            if v.as_u64() != Some(1) {
                return bad("version");
            }
        }
    }
    if let Some(hooks) = settings.get("hooks") {
        if !hooks.is_object() {
            return bad("hooks");
        }
        for ev in spec.events {
            if let Some(arr) = hooks.get(ev.event) {
                if !arr.is_array() {
                    // field 直接用事件名(&'static):错误文案已带配置路径,足以定位。
                    return bad(ev.event);
                }
            }
        }
    }
    Ok(())
}

/// 幂等合并安装(形状须已 [`ensure_agent_shape`] 校验过)。语义同 `setup::merge_install`:
/// 每事件剥掉所有托管条目、追加唯一 canonical;非托管条目原样保留。
fn merge_install_agent(spec: &AgentHookSpec, mut settings: Value, command: &str) -> (bool, Value) {
    let mut changed = false;

    // Cursor 根 version 字段:缺则补 1(schema 必填;存在且非 1 已被形状校验 abort)。
    if spec.versioned_root {
        if let Some(obj) = settings.as_object_mut() {
            if !obj.contains_key("version") {
                obj.insert("version".to_string(), json!(1));
                changed = true;
            }
        }
    }

    for ev in spec.events {
        let canonical = canonical_entry(spec.style, command, ev);
        let existing: Vec<Value> = settings
            .get("hooks")
            .and_then(|h| h.get(ev.event))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let managed: Vec<&Value> = existing
            .iter()
            .filter(|e| entry_is_managed(spec.style, e))
            .collect();
        let already_correct = managed.len() == 1 && managed[0] == &canonical;
        changed |= !already_correct;

        let mut new_arr: Vec<Value> = existing
            .iter()
            .filter(|e| !entry_is_managed(spec.style, e))
            .cloned()
            .collect();
        new_arr.push(canonical);

        let obj = match settings.as_object_mut() {
            Some(o) => o,
            // 不可达(已 ensure_agent_shape),但避免 expect:退化为仅含我们条目的配置。
            None => return (true, json!({ "hooks": { ev.event: new_arr } })),
        };
        let hooks = obj.entry("hooks").or_insert_with(|| json!({}));
        if let Some(ho) = hooks.as_object_mut() {
            ho.insert(ev.event.to_string(), Value::Array(new_arr));
        }
    }
    (changed, settings)
}

/// 幂等卸载:扫 `hooks` 下**所有**事件键(旧版本注册过的事件也清干净),只删托管条目;
/// 非数组事件值保守不动;清空数组删事件键,空 hooks 删容器(version 根字段保留)。
fn merge_uninstall_agent(spec: &AgentHookSpec, mut settings: Value) -> (bool, Value) {
    let Some(obj) = settings.as_object_mut() else {
        return (false, settings);
    };
    let Some(hooks) = obj.get_mut("hooks").and_then(Value::as_object_mut) else {
        return (false, settings);
    };
    let mut changed = false;
    let events: Vec<String> = hooks.keys().cloned().collect();
    for event in events {
        let Some(arr) = hooks.get_mut(&event).and_then(Value::as_array_mut) else {
            continue; // 非数组事件值:不动它(保守)
        };
        let before = arr.len();
        arr.retain(|e| !entry_is_managed(spec.style, e));
        changed |= arr.len() != before;
        if arr.is_empty() {
            hooks.remove(&event);
        }
    }
    if hooks.is_empty() {
        obj.remove("hooks");
    }
    (changed, settings)
}

/// 把一条托管条目里 hook command 的 `--ledger <值>` 归一为占位符 —— 让 staleness **忽略 ledger 路径**
/// (与 `setup::entry_ledger_normalized` 同策:ledger 是用户可配的共享审计路径,不应判漂移;exe / flag /
/// 结构仍精确比对)。两种 [`EntryStyle`] 各取各的 command 字段。返回 None = 取不到 command 或缺 `--ledger`
/// (本身非 canonical → Stale)。取**首个** ` --ledger ` 切分(prefix 不含该字面子串;避免 ledger 路径
/// 恰含字面时误切,Codex review Low,fail-safe)。
fn entry_ledger_normalized(style: EntryStyle, entry: &Value) -> Option<Value> {
    let cmd = match style {
        EntryStyle::Nested => entry
            .get("hooks")
            .and_then(Value::as_array)
            .filter(|h| h.len() == 1)?
            .first()?
            .get("command")
            .and_then(Value::as_str)?,
        EntryStyle::Flat => entry.get("command").and_then(Value::as_str)?,
    };
    let (prefix, ledger) = cmd.split_once(" --ledger ")?;
    if ledger.trim().is_empty() {
        return None;
    }
    let new_cmd = Value::String(format!("{prefix} --ledger <vigil-ledger>"));
    let mut normalized = entry.clone();
    match style {
        EntryStyle::Nested => normalized["hooks"][0]["command"] = new_cmd,
        EntryStyle::Flat => normalized["command"] = new_cmd,
    }
    Some(normalized)
}

/// 诚实保护状态:该面**每个**注册事件都恰好一条托管条目且 == canonical(**ledger 路径除外**,见
/// [`entry_ledger_normalized`])且 exe 存在 → Active;有任何托管条目但不满足(exe/flag 漂移 / 缺事件 /
/// exe 缺失)→ Stale;全无 → NotInstalled。
fn agent_state(
    spec: &AgentHookSpec,
    settings: Option<&Value>,
    command: &str,
    exe: &Path,
) -> ProtectionState {
    let Some(s) = settings else {
        return ProtectionState::NotInstalled;
    };
    let mut any_managed = false;
    let mut all_canonical = true;
    for ev in spec.events {
        // canonical 也按 ledger 归一:status 不带 --ledger 时按默认 ledger 重算,但注册串可能是用户安装
        // 时给的自定义 ledger —— 归一后只比 exe/flag/结构,自定义 ledger 不再误报 STALE。
        let canonical_norm =
            entry_ledger_normalized(spec.style, &canonical_entry(spec.style, command, ev));
        let managed: Vec<&Value> = s
            .get("hooks")
            .and_then(|h| h.get(ev.event))
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter(|e| entry_is_managed(spec.style, e))
                    .collect()
            })
            .unwrap_or_default();
        any_managed |= !managed.is_empty();
        all_canonical &= canonical_norm.is_some()
            && managed.len() == 1
            && entry_ledger_normalized(spec.style, managed[0]) == canonical_norm;
    }
    if !any_managed {
        return ProtectionState::NotInstalled;
    }
    if all_canonical && exe.exists() {
        ProtectionState::Active
    } else {
        ProtectionState::Stale
    }
}

/// Codex `config.toml` 的 `[features] hooks = false` 检测(best-effort 警告,**绝不改写**:
/// hooks 现已默认开启,显式 false 是用户刻意关闭 —— 安全产品静默翻转用户配置违反
/// abort-on-unexpected 纪律,诚实警告替代)。`codex_hooks` 是官方 deprecated alias,
/// canonical 键 `hooks` 优先。读不到文件 / 无该配置 → 无警告。
fn codex_hooks_disabled(config_toml_raw: &str) -> bool {
    let mut in_features = false;
    let mut hooks_val: Option<bool> = None;
    let mut alias_val: Option<bool> = None;
    for line in config_toml_raw.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_features = t == "[features]";
            continue;
        }
        if !in_features {
            continue;
        }
        let Some((k, v)) = t.split_once('=') else {
            continue;
        };
        // 值截到行内注释为止再判 true/false(TOML bool 字面量不含 '#')。
        let v = v.split('#').next().unwrap_or("").trim();
        let parsed = match v {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        };
        match k.trim() {
            "hooks" => hooks_val = parsed,
            "codex_hooks" => alias_val = parsed,
            _ => {}
        }
    }
    hooks_val.or(alias_val) == Some(false)
}

// ───────────────────── Codex hook trust(状态诚实化)─────────────────────
//
// codex(实证 0.144.6)只执行 `Managed | Trusted` 的 hook:用户级 `hooks.json` 条目须经
// 交互式 `/hooks` review,trust 决定持久化在 `$CODEX_HOME/config.toml`:
//
//   [hooks.state.'<hooks.json 绝对路径>:<event 蛇形名>:<组索引>:<处理器索引>']
//   trusted_hash = "sha256:<hex>"        # 另可有 enabled = false(用户在 /hooks 里禁用)
//
// headless(`codex exec`)既不能交互 trust 也不默认 bypass → 未信任的 hook 打印
// `hook: PreToolUse Failed` 后 **fail-open 放行**。因此「配置在位」≠「防护生效」——
// 此前 Active 判定只看前者,桌面 Aegis 卡对未信任 codex 谎报「已保护」(真机取证 2026-07-20)。
//
// hash 复刻(源码:codex-rs `hooks/src/engine/discovery.rs::command_hook_hash` +
// `config/src/fingerprint.rs::version_for_toml`;三条真机 trust 样本逐字节验证,见测试):
// NormalizedHookIdentity → JSON、对象键**字典序**、compact 序列化、UTF-8 → SHA-256。
// 归一化语义(照抄 codex):handler = {async(缺省 false), command, statusMessage(None 略),
// timeout(缺省 600、下限 1), type:"command"},commandWindows 强制剥除;matcher 对
// Pre/PostToolUse 透传、UserPromptSubmit 恒无;event 名蛇形化。
//
// 判定方向 **fail-honest**:state 键查无 / config.toml 缺失或不可解析 / hash 不符 /
// enabled=false → 一律降 [`ProtectionState::PendingTrust`](宁把已信任误报待信任 ——
// 用户跑一次 /hooks 即自愈;绝不把未信任虚报 Active)。诚实边界:锚定 0.144.6 的持久化
// schema,codex 未来变更该 schema → 读不到 → 保守降级,不虚报。Vigil 绝不替用户 trust /
// 写 managed hooks 配置(越权企业 policy 层),只报告 + 引导。

/// Camel 事件名 → codex state key 的蛇形 label(`PreToolUse` → `pre_tool_use`)。
fn codex_event_label(event: &str) -> String {
    let mut out = String::with_capacity(event.len() + 4);
    for (i, c) in event.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// 复刻 codex `command_hook_hash`:对磁盘 hooks.json 中一条 matcher 组(Nested 形状、单
/// handler)算 trust hash。输入是**磁盘实际内容**(用户 trust 的就是这份,与 canonical 无关,
/// 自定义 ledger 也不影响)。返回 None = 取不出 command(仅防御:调用前提是结构已 canonical)。
///
/// 边界(codex 侧另有两条本函数不处理的语义,均被 Active 前提天然挡住 —— 带这些字段的
/// 条目≠canonical,先判 Stale 不进 trust 检查):`commandWindows` 存在时 Windows 上 codex
/// 以它为 hash 的 command;`async=true` / 空 command 的 handler codex 直接跳过不算 hash。
fn codex_trust_hash(event: &str, entry: &Value) -> Option<String> {
    let handler = entry.get("hooks").and_then(Value::as_array)?.first()?;
    let command = handler.get("command").and_then(Value::as_str)?;
    let timeout = handler
        .get("timeout")
        .and_then(Value::as_u64)
        .unwrap_or(600)
        .max(1);
    let is_async = handler
        .get("async")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let status_message = handler.get("statusMessage").and_then(Value::as_str);
    // UserPromptSubmit 不支持 matcher,codex 归一化时恒丢弃;其余事件透传磁盘值。
    let matcher = (event != "UserPromptSubmit")
        .then(|| entry.get("matcher").and_then(Value::as_str))
        .flatten();
    // canonical JSON:键按**字典序字面书写**(serde_json 开 preserve_order = 保插入序,
    // 插入序即输出序);`to_string` 的 compact 输出与 codex `serde_json::to_vec` 逐字节一致。
    let handler_json = match status_message {
        Some(sm) => json!({
            "async": is_async, "command": command, "statusMessage": sm,
            "timeout": timeout, "type": "command"
        }),
        None => json!({
            "async": is_async, "command": command, "timeout": timeout, "type": "command"
        }),
    };
    let identity = match matcher {
        Some(m) => {
            json!({ "event_name": codex_event_label(event), "hooks": [handler_json], "matcher": m })
        }
        None => json!({ "event_name": codex_event_label(event), "hooks": [handler_json] }),
    };
    let digest = sha2::Sha256::digest(identity.to_string().as_bytes());
    Some(format!("sha256:{}", hex::encode(digest)))
}

/// codex trust 判定(Active 前提下调用)。返回 `None` = 全部注册事件已信任且未禁用;
/// `Some(warnings)` = 存在未信任 / 已改动 / 已禁用 / 无法确认,按问题类聚合的引导文案。
fn codex_trust_problems(
    spec: &AgentHookSpec,
    settings: &Value,
    config_toml_raw: Option<&str>,
) -> Option<Vec<String>> {
    // config.toml 在但不是合法 TOML → trust 无从确认,单条保守警告(fail-honest)。
    let doc: Option<toml_edit::DocumentMut> = match config_toml_raw {
        Some(raw) => match raw.parse::<toml_edit::DocumentMut>() {
            Ok(d) => Some(d),
            Err(_) => {
                return Some(vec![format!(
                    "cannot verify codex hook trust ({} is not valid TOML); codex only runs \
                     hooks it has trusted via /hooks",
                    spec.detect_dir.join("config.toml").display()
                )]);
            }
        },
        // config.toml 缺失 = codex 从未持久化任何 trust → 按未信任处理(准确)。
        None => None,
    };
    let state_table = doc
        .as_ref()
        .and_then(|d| d.get("hooks"))
        .and_then(|h| h.as_table_like())
        .and_then(|h| h.get("state"))
        .and_then(|s| s.as_table_like());
    // state key 的 source 候选:codex 对 `CODEX_HOME` env 值 canonicalize(vendor 语义),
    // 与 vigil 的 display 构造可能有 `\\?\` 前缀 / 符号链接差异 → display + canonicalize
    // (含剥前缀变体)多候选,任一命中即可;全部查无 → 保守按未信任(不虚报)。
    let mut sources = vec![spec.config_path.display().to_string()];
    if let Ok(canon) = std::fs::canonicalize(&spec.config_path) {
        let c = canon.display().to_string();
        let stripped = c.strip_prefix(r"\\?\").map(str::to_string);
        for cand in [Some(c), stripped].into_iter().flatten() {
            if !sources.contains(&cand) {
                sources.push(cand);
            }
        }
    }
    let (mut untrusted, mut modified, mut disabled) = (Vec::new(), Vec::new(), Vec::new());
    for ev in spec.events {
        let label = codex_event_label(ev.event);
        // state key 按**磁盘数组位置**寻址:取托管条目的实际索引(Active 前提 = 恰一条)。
        let found = settings
            .get("hooks")
            .and_then(|h| h.get(ev.event))
            .and_then(Value::as_array)
            .and_then(|a| {
                a.iter()
                    .enumerate()
                    .find(|(_, e)| entry_is_managed(spec.style, e))
            });
        let Some((gi, entry)) = found else {
            untrusted.push(ev.event); // 防御(Active 前提下不可达)
            continue;
        };
        let Some(current) = codex_trust_hash(ev.event, entry) else {
            untrusted.push(ev.event);
            continue;
        };
        let item = state_table.and_then(|t| {
            sources
                .iter()
                .find_map(|s| t.get(&format!("{s}:{label}:{gi}:0")))
        });
        let Some(item) = item else {
            untrusted.push(ev.event);
            continue;
        };
        let field = |k: &str| item.as_table_like().and_then(|t| t.get(k));
        if field("enabled").and_then(|v| v.as_bool()) == Some(false) {
            disabled.push(ev.event);
            continue;
        }
        match field("trusted_hash").and_then(|v| v.as_str()) {
            Some(h) if h == current => {}
            Some(_) => modified.push(ev.event),
            None => untrusted.push(ev.event),
        }
    }
    let mut problems = Vec::new();
    if !untrusted.is_empty() {
        problems.push(format!(
            "codex has not trusted the Vigil hook(s) for {} — codex will not run them until \
             you review once: run codex, type /hooks, and trust the Vigil entries",
            untrusted.join(", ")
        ));
    }
    if !modified.is_empty() {
        problems.push(format!(
            "codex trust for the Vigil hook(s) {} is out of date (definition changed since \
             trusted); re-review via /hooks in codex",
            modified.join(", ")
        ));
    }
    if !disabled.is_empty() {
        problems.push(format!(
            "the Vigil hook(s) for {} are disabled inside codex; re-enable via /hooks in codex",
            disabled.join(", ")
        ));
    }
    (!problems.is_empty()).then_some(problems)
}

/// [`agent_state`] + codex trust 诚实化:结构 Active 的 codex 面再过 trust 门,未全数
/// 信任 → 降 [`ProtectionState::PendingTrust`] 并附引导警告。其余 agent 原样透传。
fn agent_state_honest(
    spec: &AgentHookSpec,
    settings: Option<&Value>,
    command: &str,
    exe: &Path,
    config_toml_raw: Option<&str>,
) -> (ProtectionState, Vec<String>) {
    let state = agent_state(spec, settings, command, exe);
    if spec.agent == "codex" && state == ProtectionState::Active {
        if let Some(settings) = settings {
            if let Some(problems) = codex_trust_problems(spec, settings, config_toml_raw) {
                return (ProtectionState::PendingTrust, problems);
            }
        }
    }
    (state, Vec::new())
}

/// 一个 agent 面的操作:只读状态 / 安装 / 卸载(dry_run 只算不写)。
#[derive(Debug, Clone, Copy)]
pub enum AgentHookOp {
    /// 只读:报告当前状态,不写盘。
    Status,
    /// 注册(幂等合并)。
    Install {
        /// 只打印将做的改动,不写盘。
        dry_run: bool,
    },
    /// 移除 Vigil 托管条目(仅 sentinel 命中的;用户其它 hook 不动)。
    Uninstall {
        /// 只打印将做的改动,不写盘。
        dry_run: bool,
    },
}

/// 单个 agent 面的执行结果(供 CLI 层诚实打印)。
#[derive(Debug)]
pub struct AgentHookReport {
    /// 稳定小写名(= `--cli` 值)。
    pub agent: &'static str,
    /// 人类可读名。
    pub display_name: &'static str,
    /// 是否检测到该 agent(配置目录存在)。
    pub detected: bool,
    /// hooks 配置文件路径。
    pub config_path: PathBuf,
    /// 本次是否真实改动配置。
    pub changed: bool,
    /// 保护状态(诚实分级)。
    pub state: ProtectionState,
    /// 备份文件路径(若产生)。
    pub backup_path: Option<PathBuf>,
    /// dry-run / status(未写盘)。
    pub dry_run: bool,
    /// 非阻塞警告(如 Codex `[features] hooks = false`)。
    pub warnings: Vec<String>,
}

/// 执行一个 agent 面。镜像 `setup::run_with` 的编排:读 → 状态 → 合并 → 原子写 + 备份。
/// 未检测到该 agent 且非卸载 → no-op 报告(不为不存在的 agent 创建配置)。
pub fn run_agent_hook(
    spec: &AgentHookSpec,
    exe: &Path,
    ledger: &Path,
    op: AgentHookOp,
) -> Result<AgentHookReport, SetupError> {
    // 检测 = 配置目录存在 或 agent CLI 二进制在 PATH 可解析(#13:覆盖"已装未首跑")。
    // Cursor 的 CLI 二进制名歧义(`cursor` 多为 GUI launcher)→ 仅目录检测,避免误判(评审 #13c)。
    let path_binary = (spec.agent != "cursor").then_some(spec.agent);
    let detected = crate::setup::agent_installed(&spec.detect_dir, path_binary);
    let command = hook_command_with_cli(exe, ledger, Some(spec.agent));
    let existing = read_settings(&spec.config_path)?; // 非法 JSON → abort(MalformedConfig)
                                                      // TOCTOU stamp:文件存在则捕获读取时刻 (mtime, len),写前比对(codex review 2026-07-20
                                                      // HIGH-2:Gemini 的 settings.json 是 hook + MCP-wrap **两面共写**的共享文件,此前 hook 侧
                                                      // `None` = 不比对,可用旧快照覆盖并发写入的 wrap 改动)。不存在 → None(hook install 允许
                                                      // 创建新配置,与 MCP 面 never-create 语义不同)。
    let stamp = match existing.is_some() {
        true => Some(crate::setup::stamp_for_existing(&spec.config_path)?),
        false => None,
    };
    // Codex 面读一次 config.toml:hooks 开关警告 + trust 诚实化共用(best-effort,绝不改写)。
    let config_toml_raw = (spec.agent == "codex" && detected)
        .then(|| std::fs::read_to_string(spec.detect_dir.join("config.toml")).ok())
        .flatten();
    let mut warnings = Vec::new();
    if let Some(raw) = config_toml_raw.as_deref() {
        if codex_hooks_disabled(raw) {
            warnings.push(format!(
                "Codex hooks are disabled ([features] hooks = false in {}); the Vigil hook \
                 is registered but will not run until you re-enable hooks",
                spec.detect_dir.join("config.toml").display()
            ));
        }
    }
    let (state, trust_warnings) = agent_state_honest(
        spec,
        existing.as_ref(),
        &command,
        exe,
        config_toml_raw.as_deref(),
    );
    // status 时刻的完整警告(基础 + trust);install 真写盘后按新内容重算 trust 部分。
    let status_warnings = |mut base: Vec<String>| -> Vec<String> {
        base.extend(trust_warnings.iter().cloned());
        base
    };

    let no_op = |state: ProtectionState, warnings: Vec<String>| AgentHookReport {
        agent: spec.agent,
        display_name: spec.display_name,
        detected,
        config_path: spec.config_path.clone(),
        changed: false,
        state,
        backup_path: None,
        dry_run: true,
        warnings,
    };

    let (uninstall, dry_run) = match op {
        AgentHookOp::Status => return Ok(no_op(state, status_warnings(warnings))),
        AgentHookOp::Install { dry_run } => (false, dry_run),
        AgentHookOp::Uninstall { dry_run } => (true, dry_run),
    };

    if !detected && !uninstall {
        return Ok(no_op(state, status_warnings(warnings)));
    }

    let base = existing.unwrap_or_else(|| json!({}));
    let (changed, new_settings) = if uninstall {
        merge_uninstall_agent(spec, base)
    } else {
        // 写入可能被 shell 执行的 command 前,拒绝危险路径(与 setup 同门禁)。
        validate_path_for_command(exe, "executable")?;
        validate_path_for_command(ledger, "ledger")?;
        ensure_agent_shape(spec, &base)?;
        merge_install_agent(spec, base, &command)
    };

    let backup_path = if changed && !dry_run {
        atomic_write_with_backup(&spec.config_path, &new_settings, stamp)?
    } else {
        None
    };

    // 写盘后按**新内容**重算状态与 trust 警告(codex 面:刚写入的新条目 codex 端必然未
    // 信任 → 诚实报 PendingTrust 并引导,而非谎报 Active)。
    let (final_state, final_warnings) = if dry_run {
        (state, status_warnings(warnings))
    } else {
        let (st, trust) = agent_state_honest(
            spec,
            Some(&new_settings),
            &command,
            exe,
            config_toml_raw.as_deref(),
        );
        let mut w = warnings;
        w.extend(trust);
        (st, w)
    };

    Ok(AgentHookReport {
        agent: spec.agent,
        display_name: spec.display_name,
        detected,
        config_path: spec.config_path.clone(),
        changed,
        state: final_state,
        backup_path,
        dry_run,
        warnings: final_warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn exe() -> PathBuf {
        // 真实存在的 exe 让 agent_state 的 exe.exists() 为真。
        std::env::current_exe().unwrap()
    }
    fn ledger() -> PathBuf {
        PathBuf::from("/data/Vigil/ledger.sqlite3")
    }

    /// 建好 detect 目录的 tempdir home,返回 (home guard, spec)。
    fn detected_spec(make: impl Fn(&Path) -> AgentHookSpec) -> (tempfile::TempDir, AgentHookSpec) {
        let td = tempfile::TempDir::new().unwrap();
        let spec = make(td.path());
        std::fs::create_dir_all(&spec.detect_dir).unwrap();
        (td, spec)
    }

    // ── command 形状 ──

    #[test]
    fn agent_command_carries_marker_and_cli_flag() {
        for (spec_fn, cli) in [
            (
                Box::new(|h: &Path| codex_spec(h, None)) as Box<dyn Fn(&Path) -> AgentHookSpec>,
                "codex",
            ),
            (Box::new(gemini_spec), "gemini"),
            (Box::new(cursor_spec), "cursor"),
        ] {
            let (_td, spec) = detected_spec(&*spec_fn);
            assert_eq!(spec.agent, cli);
            let cmd = hook_command_with_cli(&exe(), &ledger(), Some(spec.agent));
            assert!(command_is_vigil_managed(&cmd), "sentinel token required");
            let tokens: Vec<&str> = cmd.split_whitespace().collect();
            let pos = tokens.iter().position(|t| *t == "--cli").unwrap();
            assert_eq!(tokens[pos + 1], cli, "--cli must name the agent kind");
        }
    }

    // ── CODEX_HOME 解析 ──

    #[test]
    fn codex_home_resolution_env_tilde_and_default() {
        let home = Path::new("/home/u");
        // 未设 / 空白 → 默认 ~/.codex
        assert_eq!(
            resolve_codex_home(home, None),
            PathBuf::from("/home/u/.codex")
        );
        assert_eq!(
            resolve_codex_home(home, Some("   ")),
            PathBuf::from("/home/u/.codex")
        );
        // ~ 展开
        assert_eq!(
            resolve_codex_home(home, Some("~")),
            PathBuf::from("/home/u")
        );
        assert_eq!(
            resolve_codex_home(home, Some("~/custom")),
            PathBuf::from("/home/u").join("custom")
        );
        // 绝对路径原样
        assert_eq!(
            resolve_codex_home(home, Some("/opt/codex")),
            PathBuf::from("/opt/codex")
        );
    }

    #[test]
    fn relative_agent_dir_env_is_absolutized_against_cwd() {
        // vendor 契约(openai/codex `codex-utils-home-dir`,源码实证):相对 CODEX_HOME 按
        // 进程 CWD canonicalize。本解析对齐之 —— 绝不原样透传相对路径(那会随每次调用的
        // CWD 漂移且不自知)。
        let home = Path::new("/home/u");
        let cwd = Path::new(if cfg!(windows) { r"C:\proj" } else { "/proj" });
        assert_eq!(
            super::resolve_agent_dir_with_cwd(home, cwd, Some("./ch"), || unreachable!()),
            cwd.join("./ch")
        );
        assert_eq!(
            super::resolve_agent_dir_with_cwd(home, cwd, Some("sub/dir"), || unreachable!()),
            cwd.join("sub/dir")
        );
        // 有根路径原样(Windows `/x` root-relative 交 OS 解析,不强行拼接)
        assert_eq!(
            super::resolve_agent_dir_with_cwd(home, cwd, Some("/opt/codex"), || unreachable!()),
            PathBuf::from("/opt/codex")
        );
        // 取 CWD 失败(空 cwd)→ 相对值退回原样透传(不 panic,等同旧行为)
        assert_eq!(
            super::resolve_agent_dir_with_cwd(home, Path::new(""), Some("rel"), || {
                unreachable!()
            }),
            PathBuf::from("rel")
        );
        // 默认分支不受影响
        assert_eq!(
            super::resolve_agent_dir_with_cwd(home, cwd, None, || PathBuf::from("/d")),
            PathBuf::from("/d")
        );
    }

    // ── 新装形状 fixture(三面逐字段)──

    #[test]
    fn codex_fresh_install_writes_nested_matcher_groups() {
        let (_td, spec) = detected_spec(|h| codex_spec(h, None));
        let rep = run_agent_hook(
            &spec,
            &exe(),
            &ledger(),
            AgentHookOp::Install { dry_run: false },
        )
        .unwrap();
        assert!(rep.changed);
        // 新装的用户级 hook codex 端必然未信任(trust 须用户在 codex `/hooks` 一次性 review)
        // → 诚实报 PendingTrust 而非 Active,并附引导警告。
        assert_eq!(rep.state, ProtectionState::PendingTrust);
        assert!(
            rep.warnings.iter().any(|w| w.contains("/hooks")),
            "install report guides the user to codex /hooks: {:?}",
            rep.warnings
        );

        let out = read_settings(&spec.config_path).unwrap().unwrap();
        let cmd = hook_command_with_cli(&exe(), &ledger(), Some("codex"));
        // UserPromptSubmit(根因 B)与 Pre/PostToolUse 同注册面 —— sync 守门:三事件都须 canonical。
        for (event, timeout) in [
            ("PreToolUse", 86_400u64),
            ("PostToolUse", 60u64),
            ("UserPromptSubmit", 60u64),
        ] {
            let arr = out["hooks"][event].as_array().unwrap();
            assert_eq!(arr.len(), 1, "{event}: exactly one matcher group");
            let group = &arr[0];
            assert!(
                group.get("matcher").is_none(),
                "matcher omitted = all tools"
            );
            let handlers = group["hooks"].as_array().unwrap();
            assert_eq!(handlers.len(), 1);
            assert_eq!(handlers[0]["type"], "command");
            assert_eq!(handlers[0]["command"], json!(cmd));
            assert_eq!(
                handlers[0]["timeout"],
                json!(timeout),
                "{event} timeout (secs)"
            );
        }
    }

    #[test]
    fn gemini_fresh_install_uses_official_event_names_and_ms_timeout() {
        let (_td, spec) = detected_spec(gemini_spec);
        let rep = run_agent_hook(
            &spec,
            &exe(),
            &ledger(),
            AgentHookOp::Install { dry_run: false },
        )
        .unwrap();
        assert!(rep.changed);
        assert_eq!(rep.state, ProtectionState::Active);

        let out = read_settings(&spec.config_path).unwrap().unwrap();
        for event in ["BeforeTool", "AfterTool"] {
            let arr = out["hooks"][event].as_array().unwrap();
            assert_eq!(arr.len(), 1);
            let handlers = arr[0]["hooks"].as_array().unwrap();
            // Gemini 契约:timeout 单位毫秒(默认 60000)—— 不是秒。
            assert_eq!(
                handlers[0]["timeout"],
                json!(60_000u64),
                "{event} timeout (ms)"
            );
            assert_eq!(handlers[0]["type"], "command");
        }
    }

    #[test]
    fn cursor_fresh_install_writes_version_flat_entries_fail_closed() {
        let (_td, spec) = detected_spec(cursor_spec);
        let rep = run_agent_hook(
            &spec,
            &exe(),
            &ledger(),
            AgentHookOp::Install { dry_run: false },
        )
        .unwrap();
        assert!(rep.changed);
        assert_eq!(rep.state, ProtectionState::Active);

        let out = read_settings(&spec.config_path).unwrap().unwrap();
        assert_eq!(out["version"], json!(1), "schema version root field");
        let cmd = hook_command_with_cli(&exe(), &ledger(), Some("cursor"));
        // 官方事件名:大写 MCP(beforeMCPExecution),不是 CodeIsland 旧名 beforeMcpToolExecution。
        for event in [
            "beforeShellExecution",
            "beforeMCPExecution",
            "afterShellExecution",
            "afterMCPExecution",
        ] {
            let arr = out["hooks"][event].as_array().unwrap();
            assert_eq!(arr.len(), 1, "{event}: exactly one entry");
            assert_eq!(arr[0]["command"], json!(cmd));
            assert_eq!(arr[0]["timeout"], json!(60u64));
            // 安全 hook 必须 failClosed:hook 自身故障(崩溃/超时/坏 JSON)拦截而非放行。
            assert_eq!(
                arr[0]["failClosed"],
                json!(true),
                "{event} must fail closed"
            );
        }
    }

    // ── 幂等 + 卸载往返 ──

    #[test]
    fn install_is_idempotent_for_all_agents() {
        for spec_fn in [
            Box::new(|h: &Path| codex_spec(h, None)) as Box<dyn Fn(&Path) -> AgentHookSpec>,
            Box::new(gemini_spec),
            Box::new(cursor_spec),
        ] {
            let (_td, spec) = detected_spec(&*spec_fn);
            let r1 = run_agent_hook(
                &spec,
                &exe(),
                &ledger(),
                AgentHookOp::Install { dry_run: false },
            )
            .unwrap();
            assert!(r1.changed, "{}: first install changes", spec.agent);
            let r2 = run_agent_hook(
                &spec,
                &exe(),
                &ledger(),
                AgentHookOp::Install { dry_run: false },
            )
            .unwrap();
            assert!(!r2.changed, "{}: second install is a no-op", spec.agent);
            // codex 面:tempdir 无 trust 持久化 → 诚实 PendingTrust;其余面无 trust 概念 → Active。
            let expected = if spec.agent == "codex" {
                ProtectionState::PendingTrust
            } else {
                ProtectionState::Active
            };
            assert_eq!(r2.state, expected, "{}", spec.agent);
        }
    }

    #[test]
    fn uninstall_removes_only_vigil_entries_and_preserves_user_hooks() {
        // Gemini(嵌套)与 Cursor(扁平)各放一条用户自己的 hook,验证卸载只删托管条目。
        let (_td, gem) = detected_spec(gemini_spec);
        std::fs::write(
            &gem.config_path,
            serde_json::to_string(&json!({
                "theme": "dark",
                "hooks": { "BeforeTool": [
                    { "matcher": "Bash", "hooks": [{ "type": "command", "command": "/usr/bin/mine" }] }
                ]}
            }))
            .unwrap(),
        )
        .unwrap();
        run_agent_hook(
            &gem,
            &exe(),
            &ledger(),
            AgentHookOp::Install { dry_run: false },
        )
        .unwrap();
        let rep = run_agent_hook(
            &gem,
            &exe(),
            &ledger(),
            AgentHookOp::Uninstall { dry_run: false },
        )
        .unwrap();
        assert!(rep.changed);
        assert_eq!(rep.state, ProtectionState::NotInstalled);
        let out = read_settings(&gem.config_path).unwrap().unwrap();
        assert_eq!(out["theme"], "dark", "non-hook settings untouched");
        let arr = out["hooks"]["BeforeTool"].as_array().unwrap();
        assert_eq!(arr.len(), 1, "user hook survives uninstall");
        assert_eq!(arr[0]["hooks"][0]["command"], "/usr/bin/mine");

        let (_td2, cur) = detected_spec(cursor_spec);
        std::fs::write(
            &cur.config_path,
            serde_json::to_string(&json!({
                "version": 1,
                "hooks": { "beforeShellExecution": [ { "command": "./hooks/mine.sh" } ] }
            }))
            .unwrap(),
        )
        .unwrap();
        run_agent_hook(
            &cur,
            &exe(),
            &ledger(),
            AgentHookOp::Install { dry_run: false },
        )
        .unwrap();
        let rep = run_agent_hook(
            &cur,
            &exe(),
            &ledger(),
            AgentHookOp::Uninstall { dry_run: false },
        )
        .unwrap();
        assert!(rep.changed);
        let out = read_settings(&cur.config_path).unwrap().unwrap();
        assert_eq!(out["version"], json!(1), "version root survives uninstall");
        let arr = out["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(arr.len(), 1, "user flat hook survives uninstall");
        assert_eq!(arr[0]["command"], "./hooks/mine.sh");
        // Vigil 写过的其余三个事件应被整键清掉(空数组不残留)。
        for event in [
            "beforeMCPExecution",
            "afterShellExecution",
            "afterMCPExecution",
        ] {
            assert!(
                out["hooks"].get(event).is_none(),
                "{event} emptied and removed"
            );
        }
    }

    // ── abort-on-unexpected-shape / malformed ──

    #[test]
    fn malformed_json_aborts_without_writing() {
        let (_td, spec) = detected_spec(|h| codex_spec(h, None));
        std::fs::write(&spec.config_path, b"{ not valid json").unwrap();
        let err = run_agent_hook(
            &spec,
            &exe(),
            &ledger(),
            AgentHookOp::Install { dry_run: false },
        )
        .unwrap_err();
        assert!(matches!(err, SetupError::MalformedConfig { .. }));
        // 原文件未动(abort 不覆盖)。
        let raw = std::fs::read(&spec.config_path).unwrap();
        assert_eq!(raw, b"{ not valid json");
    }

    #[test]
    fn unexpected_shape_aborts_for_hooks_and_event_and_version() {
        // hooks 非 object
        let (_td, spec) = detected_spec(gemini_spec);
        std::fs::write(&spec.config_path, br#"{"hooks": "surprise"}"#).unwrap();
        let err = run_agent_hook(
            &spec,
            &exe(),
            &ledger(),
            AgentHookOp::Install { dry_run: false },
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                SetupError::UnsupportedConfigShape { field: "hooks", .. }
            ),
            "got {err:?}"
        );

        // 事件键非 array
        let (_td2, spec2) = detected_spec(gemini_spec);
        std::fs::write(&spec2.config_path, br#"{"hooks": {"BeforeTool": {}}}"#).unwrap();
        let err = run_agent_hook(
            &spec2,
            &exe(),
            &ledger(),
            AgentHookOp::Install { dry_run: false },
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                SetupError::UnsupportedConfigShape {
                    field: "BeforeTool",
                    ..
                }
            ),
            "got {err:?}"
        );

        // Cursor version != 1 → abort 不猜未来 schema
        let (_td3, spec3) = detected_spec(cursor_spec);
        std::fs::write(&spec3.config_path, br#"{"version": 2, "hooks": {}}"#).unwrap();
        let err = run_agent_hook(
            &spec3,
            &exe(),
            &ledger(),
            AgentHookOp::Install { dry_run: false },
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                SetupError::UnsupportedConfigShape {
                    field: "version",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    // ── 检测门 / dry-run / status ──

    #[test]
    fn not_detected_skips_install_without_creating_config() {
        let td = tempfile::TempDir::new().unwrap();
        let spec = cursor_spec(td.path()); // 不建 ~/.cursor
        let rep = run_agent_hook(
            &spec,
            &exe(),
            &ledger(),
            AgentHookOp::Install { dry_run: false },
        )
        .unwrap();
        assert!(!rep.detected);
        assert!(!rep.changed);
        assert!(
            !spec.config_path.exists(),
            "no config created for absent agent"
        );
    }

    #[test]
    fn dry_run_and_status_do_not_write() {
        let (_td, spec) = detected_spec(|h| codex_spec(h, None));
        let rep = run_agent_hook(
            &spec,
            &exe(),
            &ledger(),
            AgentHookOp::Install { dry_run: true },
        )
        .unwrap();
        assert!(rep.changed, "dry-run reports would-be change");
        assert!(!spec.config_path.exists(), "dry-run writes nothing");

        let rep = run_agent_hook(&spec, &exe(), &ledger(), AgentHookOp::Status).unwrap();
        assert_eq!(rep.state, ProtectionState::NotInstalled);
        assert!(!spec.config_path.exists());
    }

    // ── 诚实状态:漂移 → Stale ──

    #[test]
    fn ledger_difference_is_active_but_reinstall_applies_new_ledger() {
        // 真机回归(E13 在 Codex 面发现):装 ledger A 的条目,再用 ledger B 查 status → 必须 Active。
        // ledger 是用户可配的共享审计路径,不构成漂移(与 Claude 面 status_ledger_difference_* 同策)。
        let (_td, spec) = detected_spec(gemini_spec);
        run_agent_hook(
            &spec,
            &exe(),
            &ledger(),
            AgentHookOp::Install { dry_run: false },
        )
        .unwrap();
        let other = PathBuf::from("/data/Vigil/other.sqlite3");
        let rep = run_agent_hook(&spec, &exe(), &other, AgentHookOp::Status).unwrap();
        assert_eq!(
            rep.state,
            ProtectionState::Active,
            "a different --ledger is the user's choice, not drift -> Active"
        );
        // 但显式重跑 install --ledger B 仍把注册串更新到 B(install 精确幂等,尊重用户显式选择)。
        let rep = run_agent_hook(
            &spec,
            &exe(),
            &other,
            AgentHookOp::Install { dry_run: false },
        )
        .unwrap();
        assert!(
            rep.changed,
            "explicit re-install with a new --ledger updates the registration"
        );
        assert_eq!(rep.state, ProtectionState::Active);
    }

    #[test]
    fn agent_exe_drift_reports_stale() {
        // 守门:exe 漂移(升级 / 移动 binary)在 agent 面仍**必须**报 Stale —— 本修复只放宽 ledger。
        let (_td, spec) = detected_spec(gemini_spec);
        run_agent_hook(
            &spec,
            Path::new("/old/path/vigil-hub"),
            &ledger(),
            AgentHookOp::Install { dry_run: false },
        )
        .unwrap();
        let cur = exe(); // 当前 exe 与注册的不同路径
        let rep = run_agent_hook(&spec, &cur, &ledger(), AgentHookOp::Status).unwrap();
        assert_eq!(
            rep.state,
            ProtectionState::Stale,
            "a hook pointing at a different binary path must stay Stale (exe-drift preserved)"
        );
    }

    // ── Codex hooks 开关警告(只警告不改写)──

    #[test]
    fn codex_hooks_disabled_detection_matrix() {
        // 显式 false → 警告;true / 缺省 / 别的段 → 无警告;canonical 键优先于 deprecated alias。
        assert!(codex_hooks_disabled("[features]\nhooks = false\n"));
        assert!(codex_hooks_disabled("[features]\nhooks = false # off\n"));
        assert!(codex_hooks_disabled("[features]\ncodex_hooks = false\n"));
        assert!(!codex_hooks_disabled("[features]\nhooks = true\n"));
        assert!(!codex_hooks_disabled(""));
        assert!(!codex_hooks_disabled("[other]\nhooks = false\n"));
        // hooks(canonical)优先:即使 alias 为 false,canonical true 算开启。
        assert!(!codex_hooks_disabled(
            "[features]\ncodex_hooks = false\nhooks = true\n"
        ));
    }

    #[test]
    fn codex_disabled_hooks_yields_warning_but_still_installs() {
        let (_td, spec) = detected_spec(|h| codex_spec(h, None));
        std::fs::write(
            spec.detect_dir.join("config.toml"),
            "[features]\nhooks = false\n",
        )
        .unwrap();
        let rep = run_agent_hook(
            &spec,
            &exe(),
            &ledger(),
            AgentHookOp::Install { dry_run: false },
        )
        .unwrap();
        assert!(rep.changed, "registration still happens");
        // 两条警告:hooks 功能被关(disabled)+ 新装条目未信任(pending trust)。
        assert_eq!(rep.warnings.len(), 2, "warnings: {:?}", rep.warnings);
        assert!(rep.warnings[0].contains("hooks = false"));
        assert!(rep.warnings[1].contains("/hooks"));
        // config.toml 原样未动(只警告不改写)。
        let raw = std::fs::read_to_string(spec.detect_dir.join("config.toml")).unwrap();
        assert_eq!(raw, "[features]\nhooks = false\n");
    }

    // ── Codex trust 诚实化:hash 复刻锚 + PendingTrust 判定矩阵 ──

    #[test]
    fn codex_event_label_snake_cases_events() {
        assert_eq!(codex_event_label("PreToolUse"), "pre_tool_use");
        assert_eq!(codex_event_label("PostToolUse"), "post_tool_use");
        assert_eq!(codex_event_label("UserPromptSubmit"), "user_prompt_submit");
        assert_eq!(codex_event_label("SessionStart"), "session_start");
        assert_eq!(codex_event_label("Stop"), "stop");
    }

    /// hash 复刻锚:三条**真机** codex-cli 0.144.6 交互 `/hooks` trust 后 `config.toml`
    /// `[hooks.state]` 落盘样本(2026-07-21 取证;maestro 是取证机上与 Vigil 无关的第三方
    /// hook,借其已 trust 的定义做逐字节校验)。序列化任何细节漂移(键序 / compact / 字段
    /// 名 / 缺省 timeout=600 / matcher 语义)都会在这里炸出来。
    #[test]
    fn codex_trust_hash_replicates_real_codex_persisted_hashes() {
        let cases = [
            (
                "UserPromptSubmit",
                json!({ "hooks": [
                    { "type": "command", "command": "maestro hooks run skill-context" }
                ] }),
                "sha256:9a90ef18f5e346b40e26f389fc6a1501b4829b0672d6963ae06840f010ba11dd",
            ),
            (
                "PreToolUse",
                json!({ "matcher": "Bash", "hooks": [
                    { "type": "command", "command": "maestro hooks run preflight-guard",
                      "statusMessage": "Running preflight checks" }
                ] }),
                "sha256:9068d25fcc3b5239d166d1397e78a353ce6e7e8cde0b578854ad7bde28d0490f",
            ),
            (
                "SessionStart",
                json!({ "matcher": "startup|resume", "hooks": [
                    { "type": "command", "command": "maestro hooks run session-context",
                      "statusMessage": "Loading workflow context" }
                ] }),
                "sha256:7c3da2a205c35e51efd92df5138605f29f6c4ac5b45309ca374ca4cdb1cec9cb",
            ),
        ];
        for (event, entry, expected) in cases {
            assert_eq!(
                codex_trust_hash(event, &entry).as_deref(),
                Some(expected),
                "{event}"
            );
        }
    }

    /// 把磁盘 hooks.json 里 Vigil 条目的 trust hash 种进 config.toml(模拟用户已在 codex
    /// `/hooks` 完成信任)。hash 由 `codex_trust_hash` 计算 —— 其正确性由真机样本锚独立
    /// 守门,这里只打通判定管线。
    fn seed_codex_trust(spec: &AgentHookSpec) {
        let settings = read_settings(&spec.config_path).unwrap().unwrap();
        let mut toml = String::new();
        for ev in spec.events {
            let arr = settings["hooks"][ev.event].as_array().unwrap();
            let (gi, entry) = arr
                .iter()
                .enumerate()
                .find(|(_, e)| entry_is_managed(spec.style, e))
                .unwrap();
            toml.push_str(&format!(
                "[hooks.state.'{}:{}:{}:0']\ntrusted_hash = \"{}\"\n",
                spec.config_path.display(),
                codex_event_label(ev.event),
                gi,
                codex_trust_hash(ev.event, entry).unwrap()
            ));
        }
        std::fs::write(spec.detect_dir.join("config.toml"), toml).unwrap();
    }

    #[test]
    fn codex_trust_matrix_pending_until_trusted() {
        let (_td, spec) = detected_spec(|h| codex_spec(h, None));
        run_agent_hook(
            &spec,
            &exe(),
            &ledger(),
            AgentHookOp::Install { dry_run: false },
        )
        .unwrap();
        let status = || run_agent_hook(&spec, &exe(), &ledger(), AgentHookOp::Status).unwrap();
        let config = spec.detect_dir.join("config.toml");

        // 1. 无 config.toml = codex 从未持久化任何 trust → PendingTrust + /hooks 引导。
        let rep = status();
        assert_eq!(rep.state, ProtectionState::PendingTrust);
        assert!(rep.warnings.iter().any(|w| w.contains("has not trusted")));

        // 2. 有 config.toml 但无 [hooks.state] → 同上。
        std::fs::write(&config, "[features]\n").unwrap();
        assert_eq!(status().state, ProtectionState::PendingTrust);

        // 3. 种上与磁盘定义一致的 trust → Active,零警告(诚实的绿)。
        seed_codex_trust(&spec);
        let rep = status();
        assert_eq!(rep.state, ProtectionState::Active);
        assert!(rep.warnings.is_empty(), "{:?}", rep.warnings);

        // 4. trusted_hash 与磁盘定义不符(定义变更未重审)→ PendingTrust("out of date")。
        let seeded = std::fs::read_to_string(&config).unwrap();
        std::fs::write(&config, seeded.replace("sha256:", "sha256:00")).unwrap();
        let rep = status();
        assert_eq!(rep.state, ProtectionState::PendingTrust);
        assert!(rep.warnings.iter().any(|w| w.contains("out of date")));

        // 5. enabled = false(用户在 codex 里禁用)→ PendingTrust("disabled")。
        seed_codex_trust(&spec);
        let seeded = std::fs::read_to_string(&config).unwrap();
        std::fs::write(
            &config,
            seeded.replace("trusted_hash", "enabled = false\ntrusted_hash"),
        )
        .unwrap();
        let rep = status();
        assert_eq!(rep.state, ProtectionState::PendingTrust);
        assert!(rep
            .warnings
            .iter()
            .any(|w| w.contains("disabled inside codex")));

        // 6. config.toml 非法 TOML → 保守 PendingTrust("cannot verify",fail-honest)。
        std::fs::write(&config, "not [valid toml").unwrap();
        let rep = status();
        assert_eq!(rep.state, ProtectionState::PendingTrust);
        assert!(rep.warnings.iter().any(|w| w.contains("cannot verify")));
    }

    #[test]
    fn codex_trust_key_source_accepts_canonicalized_paths() {
        // codex 对 `CODEX_HOME` env 值 canonicalize(vendor 语义;Windows 产生 `\\?\` 前缀,
        // macOS 解析 /var → /private/var 符号链接)后作 state key 的 source。用 canonicalize
        // 形态的 key 种 trust,判定仍须命中(候选集覆盖)—— 不把已信任误报为待信任。
        let (_td, spec) = detected_spec(|h| codex_spec(h, None));
        run_agent_hook(
            &spec,
            &exe(),
            &ledger(),
            AgentHookOp::Install { dry_run: false },
        )
        .unwrap();
        let canon = std::fs::canonicalize(&spec.config_path).unwrap();
        let settings = read_settings(&spec.config_path).unwrap().unwrap();
        let mut toml = String::new();
        for ev in spec.events {
            let arr = settings["hooks"][ev.event].as_array().unwrap();
            let (gi, entry) = arr
                .iter()
                .enumerate()
                .find(|(_, e)| entry_is_managed(spec.style, e))
                .unwrap();
            toml.push_str(&format!(
                "[hooks.state.'{}:{}:{}:0']\ntrusted_hash = \"{}\"\n",
                canon.display(),
                codex_event_label(ev.event),
                gi,
                codex_trust_hash(ev.event, entry).unwrap()
            ));
        }
        std::fs::write(spec.detect_dir.join("config.toml"), toml).unwrap();
        let rep = run_agent_hook(&spec, &exe(), &ledger(), AgentHookOp::Status).unwrap();
        assert_eq!(rep.state, ProtectionState::Active);
    }

    #[test]
    fn codex_trust_respects_user_hooks_ahead_of_vigil_entry() {
        // state key 按**磁盘数组位置**寻址:用户自己的 hook 排在 Vigil 前面时,组索引随之
        // 偏移 —— 判定必须按实际位置构造 key,不能假定 0。
        let (_td, spec) = detected_spec(|h| codex_spec(h, None));
        std::fs::write(
            &spec.config_path,
            serde_json::to_string(&json!({ "hooks": { "PreToolUse": [
                { "matcher": "Bash",
                  "hooks": [{ "type": "command", "command": "/usr/bin/mine" }] }
            ] } }))
            .unwrap(),
        )
        .unwrap();
        run_agent_hook(
            &spec,
            &exe(),
            &ledger(),
            AgentHookOp::Install { dry_run: false },
        )
        .unwrap();
        // Vigil 的 PreToolUse 条目此时在索引 1(用户条目保留在 0)。
        seed_codex_trust(&spec);
        let rep = run_agent_hook(&spec, &exe(), &ledger(), AgentHookOp::Status).unwrap();
        assert_eq!(rep.state, ProtectionState::Active);
        let seeded = std::fs::read_to_string(spec.detect_dir.join("config.toml")).unwrap();
        assert!(
            seeded.contains(":pre_tool_use:1:0'"),
            "vigil entry is addressed at its real on-disk index: {seeded}"
        );
    }
}
