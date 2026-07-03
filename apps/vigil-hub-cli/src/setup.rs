//! `vigil-hub setup` —— turnkey 一键接入:把 Vigil 保护写进已装 AI agent 的配置,
//! 让「从 GitHub 下载 → 运行一次 `vigil-hub setup` → 工具调用直接受保护」成立。
//!
//! # v1 范围(Claude Code PreToolUse hook,最锐的"download→直接保护"首胜)
//! - 检测到 Claude Code(`~/.claude/` 存在)→ 把 [`crate::hook`] 注册为 `PreToolUse` hook
//!   (matcher `*` 覆盖全工具,含 `mcp__*`)→ Claude Code 每次执行工具前都先过 Vigil 的
//!   fail-closed secret 守门 + 本地审计。
//! - `--uninstall` 干净移除 **仅** Vigil 托管的条目(用户自己的 hook / 其它配置不动)。
//! - `--status` 报告 + doctor 自检(含**合成 fake token 跑真 hook 断言被拦**的 in-process smoke test)。
//! - `--dry-run` 只打印将要做的改动,不写盘。
//! - MCP 网关注册留作 `--mcp` 后续增量(codex 设计建议:hook-only 是 sharp first win)。
//!
//! # 编辑用户配置的安全门(比 native-host 写独立文件更高)
//! 1. **绝不 clobber / corrupt / 静默归一化**:读 → 解析 → 幂等合并 → 原子写。既有 `settings.json`
//!    若是非法 JSON,或形状不符预期(顶层非 object / `hooks` 非 object / `PreToolUse` 非 array)即
//!    **abort**([`SetupError::MalformedConfig`] / [`SetupError::UnsupportedConfigShape`]),绝不覆盖
//!    或重置用户数据(Codex R1 BLOCKER)。
//! 2. **托管标记 sentinel**:Vigil 写的 hook 带专属标记 flag `--vigil-managed`,识别/卸载只认它 ——
//!    不靠"command 含 vigil-hub"这种宽/脆匹配(避免误删用户 hook / 二进制改名后漏认,Codex R1 HIGH)。
//! 3. **shell 转义**:hook command 里的 exe/ledger 路径按平台 shell 转义(Unix 单引号 / Windows 双引号),
//!    防 `$(...)`/反引号/`$VAR` 注入(Claude Code shell-执行 command;Codex R1 HIGH)。
//! 4. **诚实 status**:仅当托管条目存在 **且** 其 command 等于当前 canonical(exe/ledger 未漂移)**且**
//!    引用的 exe 存在,才报 ACTIVE;否则 stale/未装,不夸大保护(Codex R1 HIGH)。
//! 5. **备份 + 原子写**:改动前复制到 `<settings>.vigil-bak`(单级"本次操作前"快照);写 `<settings>.vigil-tmp`
//!    再 `rename` 替换;rename 失败 best-effort 清 tmp,原文件保持不动。
//! 6. **错误脱敏**:[`SetupError`] 不透传 io::Error 原文 / secret,仅含稳定文案 + 路径。

#![allow(clippy::uninlined_format_args)]

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

// ── 常量(与 desktop `ledger_path.rs` 约定对齐:同一 ledger → 统一审计)──
const CLAUDE_DIR: &str = ".claude";
const SETTINGS_FILE: &str = "settings.json";
const VIGIL_SUBDIR: &str = "Vigil";
const LEDGER_FILENAME: &str = "ledger.sqlite3";
const LEDGER_ENV_VAR: &str = "VIGIL_LEDGER_PATH";
/// Vigil 托管 hook 的专属标记 flag —— 唯一识别 Vigil 写的条目(避免宽/脆匹配)。
/// hook 子命令接受并忽略它(纯标记)。识别/卸载只认 command 含此精确 token。
pub const VIGIL_HOOK_MARKER: &str = "--vigil-managed";
/// hook 默认超时(秒)。Claude Code command hook 默认 600s;我们显式设 60s:既给共同批准
/// (co-approval,TASK-004)留出"hook 内有界等待 Vigil 侧裁决"的窗口(等待预算 45s + 输出余量),
/// 又不至于让异常 hook 长挂起。超时是 non-blocking(fail-open),短于默认让异常更早暴露。
pub(crate) const HOOK_TIMEOUT_SECS: u64 = 60;
/// Vigil 在 Claude `settings.json` 注册的 hook 事件集。PreToolUse = 输入侧守门(secret 拦截 +
/// posture 决策);PostToolUse = 结果再脱敏面(TASK-006 消费;在此前 hook 对该事件 pass-through,
/// 注册无副作用,属前向兼容)。新增事件须同步 [`ensure_mergeable_shape`] 的形状校验。
const CLAUDE_HOOK_EVENTS: [&str; 2] = ["PreToolUse", "PostToolUse"];

/// `setup` 子命令参数。
#[derive(Debug, Clone, Default)]
pub struct SetupArgs {
    /// 移除 Vigil 托管配置(仅 Vigil 的,不动用户其它配置)。
    pub uninstall: bool,
    /// 报告当前保护状态 + 跑 doctor 自检(含 in-process smoke test)。
    pub status: bool,
    /// 只打印将要做的改动,不写盘。
    pub dry_run: bool,
    /// 覆盖 ledger 路径;省略 = `VIGIL_LEDGER_PATH` 或 `<data_local>/Vigil/ledger.sqlite3`。
    pub ledger: Option<PathBuf>,
}

/// `setup` 错误(脱敏:不透传 io 原文 / secret)。
#[derive(Debug)]
pub enum SetupError {
    /// 无法定位用户 home(`dirs::home_dir()` 返 None,headless 等)。
    MissingHomeDir,
    /// 无法定位 OS local data 目录(算默认 ledger 路径时,且未设 `VIGIL_LEDGER_PATH`)。
    MissingDataDir,
    /// 无法定位本进程可执行文件路径(`std::env::current_exe()` 失败)。
    MissingCurrentExe,
    /// 既有 agent 配置不是合法 JSON —— **abort 不覆盖**(配置损坏属安全事件类)。
    MalformedConfig {
        /// 出问题的配置文件路径(供用户自查;非密钥)。
        path: PathBuf,
    },
    /// 既有配置 JSON 合法,但某处形状不符预期(如 `hooks` 是字符串、`PreToolUse` 是对象)。
    /// **abort 不归一化** —— 绝不把用户那处数据重置掉(Codex R1 BLOCKER)。
    UnsupportedConfigShape {
        /// 配置文件路径。
        path: PathBuf,
        /// 不符预期的字段(如 `hooks` / `hooks.PreToolUse` / `<root>`)。
        field: &'static str,
    },
    /// exe / ledger 路径含对 hook command 串不安全的字符(换行,或 Windows shell 可展开的
    /// `%VAR%` / `$()` / 反引号 / cmd 元字符)。拒绝写入,绝不产出可被注入的 command(Codex R2 HIGH)。
    UnsafePath {
        /// 哪个路径(`executable` / `ledger`)。
        which: &'static str,
        /// 不安全的具体字符(供用户定位;非密钥)。
        offending: char,
    },
    /// 文件 IO 失败(读/写/备份/建目录)。不透传 io::Error 原文。
    Io {
        /// 失败的动作(稳定文案)。
        what: &'static str,
        /// 目标路径。
        path: PathBuf,
    },
}

impl std::fmt::Display for SetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingHomeDir => {
                write!(f, "could not resolve user home directory (dirs::home_dir() returned None)")
            }
            Self::MissingDataDir => write!(
                f,
                "could not resolve OS local data directory for the default ledger path \
                 (set {LEDGER_ENV_VAR} or pass --ledger to override)"
            ),
            Self::MissingCurrentExe => {
                write!(f, "could not resolve this executable's own path (std::env::current_exe failed)")
            }
            Self::MalformedConfig { path } => write!(
                f,
                "existing config at {} is not valid JSON; refusing to modify it (fix or remove it, then re-run)",
                path.display()
            ),
            Self::UnsupportedConfigShape { path, field } => write!(
                f,
                "existing config at {} has an unexpected shape at `{}`; refusing to modify it to avoid \
                 destroying your data (fix that field by hand, then re-run)",
                path.display(),
                field
            ),
            Self::UnsafePath { which, offending } => write!(
                f,
                "the {} path contains a character ({:?}) that is unsafe inside a shell-executed hook \
                 command; choose a path without shell metacharacters or newlines, or pass a safe --ledger",
                which, offending
            ),
            Self::Io { what, path } => {
                write!(f, "failed to {} at {}", what, path.display())
            }
        }
    }
}

/// 校验一个将被写进 hook command 串的路径不含危险字符。
///
/// - 跨平台:换行/回车/NUL 一律拒(任何 shell 都危险)。
/// - Windows:双引号包裹**挡不住** `%VAR%`(cmd)/`$()`·`$env:`·反引号(PowerShell)/cmd 元字符,
///   故额外拒绝这些字符。Unix 走单引号转义已字面化,无需额外拒绝,但统一拒换行类。
pub(crate) fn validate_path_for_command(p: &Path, which: &'static str) -> Result<(), SetupError> {
    let s = p.display().to_string();
    for c in s.chars() {
        if matches!(c, '\n' | '\r' | '\0') {
            return Err(SetupError::UnsafePath {
                which,
                offending: c,
            });
        }
        #[cfg(windows)]
        {
            if matches!(
                c,
                '%' | '$' | '`' | '"' | '&' | '|' | '<' | '>' | '^' | '(' | ')' | '!' | ';'
            ) {
                return Err(SetupError::UnsafePath {
                    which,
                    offending: c,
                });
            }
        }
    }
    Ok(())
}

impl std::error::Error for SetupError {}

// ─────────────────────────── 纯函数(DI:home/exe/ledger 参数化,便于测试)───────────────

/// Claude Code 用户级配置文件路径 `~/.claude/settings.json`。
fn claude_settings_path(home: &Path) -> PathBuf {
    home.join(CLAUDE_DIR).join(SETTINGS_FILE)
}

// 测试中 PATH 检测默认**关**(thread-local 开关,默认 false),保持既有高层 setup 测试 hermetic
// —— 不受宿主是否装了 claude/codex 等影响。真实 PATH 解析这条生产 glue 由 [`binary_on_path_real`]
// 的专项测试直接覆盖(评审 #13b),不经此 stub。需验 stub 分支的测试显式置 true。
#[cfg(test)]
thread_local! {
    static TEST_BINARY_ON_PATH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// 二进制名是否在宿主 PATH 可解析(生产路径)。复用网关同款 `resolve_program`(SSOT,含 Windows
/// PATHEXT)。抽成独立函数,使单测能在不破坏其它测试 hermetic 的前提下直接覆盖真实解析(评审 #13b)。
fn binary_on_path_real(binary: &str) -> bool {
    vigil_mcp::stdio::resolve_program(binary).is_ok()
}

/// 生产走 [`binary_on_path_real`];测试走 thread-local 开关(默认关)以保持高层 setup 测试 hermetic。
fn binary_on_path(binary: &str) -> bool {
    #[cfg(test)]
    {
        let _ = binary;
        TEST_BINARY_ON_PATH.with(|c| c.get())
    }
    #[cfg(not(test))]
    {
        binary_on_path_real(binary)
    }
}

/// agent 检测:配置目录存在 **或**(给定 CLI 二进制名时)该二进制在宿主 PATH 可解析。
/// `binary = None` → 仅目录检测(用于 CLI 二进制名不确定的 agent,如 Cursor;评审 #13c)。
/// 解决 #13:已装(二进制在 PATH)但从未首跑(配置目录尚未生成)的 agent 此前被误判"未安装"。
pub(crate) fn agent_installed(config_dir: &Path, binary: Option<&str>) -> bool {
    config_dir.is_dir() || binary.is_some_and(binary_on_path)
}

/// Claude Code 是否"已安装"= `~/.claude/` 目录存在 **或** `~/.claude.json` 用户级配置文件存在
/// **或** `claude` 二进制在 PATH。
///
/// **修 ISS-20260621-001(QA HIGH)**:此前只查 `~/.claude/` 目录 + `claude` PATH,漏了
/// `~/.claude.json` —— 而 [`setup_mcp`] 的 MCP 步正是读/改 `~/.claude.json`。导致同一条
/// `setup --all` 对"Claude Code 是否在场"两步判定**矛盾**:MCP 步据 `~/.claude.json` 成功
/// wrap,hook 步却判"未检测到"而跳过,最终仍打印 "Protected" —— 而 Claude 的原生工具 secret
/// 守门 hook 实际缺失(虚假保护承诺)。`~/.claude.json` 是 Claude Code 用户级配置(MCP / projects
/// / oauth),其存在即 Claude Code 在场 → hook 应安装(install 路径会按需创建 `~/.claude/`)。
fn claude_detected(home: &Path) -> bool {
    agent_installed(&home.join(CLAUDE_DIR), Some("claude")) || home.join(".claude.json").is_file()
}

/// 解析默认 ledger 路径(与 desktop `ledger_path::resolve_ledger_path` 同语义,
/// 但**不**在此创建父目录 —— setup 只把路径写进配置,实际建目录交给 hook 运行时)。
fn resolve_ledger(
    explicit: Option<&Path>,
    env_override: Option<&str>,
    data_local_dir: Option<&Path>,
) -> Result<PathBuf, SetupError> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    if let Some(raw) = env_override {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    let base = data_local_dir.ok_or(SetupError::MissingDataDir)?;
    Ok(base.join(VIGIL_SUBDIR).join(LEDGER_FILENAME))
}

/// 默认共享 ledger 路径(生产):`VIGIL_LEDGER_PATH` > `<data_local>/Vigil/ledger.sqlite3`;
/// 无法解析 → `None`。供 `inspect` 等消费方默认打开**与 setup/hook 同一个**账本 —— 让用户
/// `vigil-hub setup` 后直接 `vigil-hub inspect activity` 就能看到被拦的内容(闭合"看见保护"回路)。
pub fn default_ledger_path() -> Option<PathBuf> {
    if let Ok(raw) = std::env::var(LEDGER_ENV_VAR) {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return Some(PathBuf::from(trimmed));
        }
    }
    dirs::data_local_dir().map(|b| b.join(VIGIL_SUBDIR).join(LEDGER_FILENAME))
}

/// 按平台 shell 转义一段路径,使其在 Claude Code shell-执行 hook command 时被当作**单一字面参数**,
/// 不发生 `$(...)`/反引号/`$VAR`/通配等展开。
///
/// - Unix(sh):单引号包裹,内部 `'` → `'\''`(单引号内一切都是字面)。
/// - Windows(cmd):双引号包裹。Windows 路径不能含 `"`,双引号内 `&|<>^` 不被解释;`%VAR%`(cmd)/
///   `$()`·反引号(PowerShell)等会展开的字符由 [`validate_path_for_command`] 在写入前**直接拒绝**
///   (不靠引号),故此处只需基础包裹。
pub(crate) fn shell_quote(s: &str) -> String {
    #[cfg(not(windows))]
    {
        let escaped = s.replace('\'', "'\\''");
        format!("'{escaped}'")
    }
    #[cfg(windows)]
    {
        // 路径不含 `"`(Windows 文件名非法字符),直接双引号包裹即可。
        format!("\"{}\"", s)
    }
}

/// 渲染 hook 的 command 字符串:`<exe> hook --vigil-managed [--cli <kind>] --ledger <ledger>`,
/// 路径均 shell-转义。`cli`=None 走 Claude 默认 —— **不带** `--cli`,保持既有注册的 canonical
/// 串不漂移(否则升级后所有已装用户被误报 Stale 并触发一次无意义重写);其它 agent 显式
/// `--cli <kind>` 让 hook 选对事件名归一映射与响应输出形状(`setup_hooks` 消费)。
pub(crate) fn hook_command_with_cli(exe: &Path, ledger: &Path, cli: Option<&str>) -> String {
    let cli_part = match cli {
        Some(kind) => format!(" --cli {kind}"),
        None => String::new(),
    };
    // Claude(cli=None)默认开 `--redact-results`(#12):PostToolUse 硬指纹结果 scrub,无状态、
    // 独立于 `--inject`,防 agent 把磁盘上真实 ghp_/AKIA 读回模型。其它 CLI 不支持 updatedToolOutput
    // → 不加(加了也 no-op)。注:这改变 Claude canonical 串 → 既有安装升级后报 Stale(诚实信号:
    // 重跑 setup 补全新保护),re-setup 后即生效。降级(旧 binary + 新命令)时旧 binary 不识别该 flag
    // → clap 拒 → exit 2 = deny-all,即 **fail-closed**(安全工具宁拦不漏;非 fail-open;评审 #12d)。
    let redact_part = if cli.is_none() {
        " --redact-results"
    } else {
        ""
    };
    format!(
        "{} hook {}{}{} --ledger {}",
        shell_quote(&exe.display().to_string()),
        VIGIL_HOOK_MARKER,
        cli_part,
        redact_part,
        shell_quote(&ledger.display().to_string()),
    )
}

/// Claude 的 canonical hook command(向后兼容形状,无 `--cli`)。
fn hook_command(exe: &Path, ledger: &Path) -> String {
    hook_command_with_cli(exe, ledger, None)
}

/// 一条 PreToolUse entry 是否由 Vigil 托管:其任一 hook 的 command 把 [`VIGIL_HOOK_MARKER`] 作为
/// **独立 argv token** 出现(精确 token 匹配,非子串 —— 避免 `--vigil-managed-old` 等误判;Codex R2 LOW)。
pub(crate) fn is_vigil_entry(entry: &Value) -> bool {
    entry
        .get("hooks")
        .and_then(Value::as_array)
        .map(|hooks| {
            hooks.iter().any(|h| {
                h.get("command")
                    .and_then(Value::as_str)
                    .map(command_is_vigil_managed)
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

/// command 串里 [`VIGIL_HOOK_MARKER`] 是否作为独立 token 出现(按空白切分精确比对)。
pub(crate) fn command_is_vigil_managed(command: &str) -> bool {
    command.split_whitespace().any(|t| t == VIGIL_HOOK_MARKER)
}

/// Vigil 的 canonical PreToolUse 条目。
fn vigil_entry(command: &str) -> Value {
    json!({
        "matcher": "*",
        "hooks": [{ "type": "command", "command": command, "timeout": HOOK_TIMEOUT_SECS }]
    })
}

/// 校验既有配置形状,**只接受**能安全合并的形状,否则返 [`SetupError::UnsupportedConfigShape`]。
/// 检查:顶层是 object;`hooks`(若存在)是 object;我们要写的每个事件键(若存在)是 array。
fn ensure_mergeable_shape(settings: &Value, path: &Path) -> Result<(), SetupError> {
    let bad = |field| {
        Err(SetupError::UnsupportedConfigShape {
            path: path.to_path_buf(),
            field,
        })
    };
    if !settings.is_object() {
        return bad("<root>");
    }
    if let Some(hooks) = settings.get("hooks") {
        if !hooks.is_object() {
            return bad("hooks");
        }
        for (event, field) in [
            ("PreToolUse", "hooks.PreToolUse"),
            ("PostToolUse", "hooks.PostToolUse"),
        ] {
            if let Some(arr) = hooks.get(event) {
                if !arr.is_array() {
                    return bad(field);
                }
            }
        }
    }
    Ok(())
}

/// 幂等地把 Vigil hook 合并进 `settings`(形状须已 [`ensure_mergeable_shape`] 校验过)。
/// 返回 `(changed, new_settings)`。对 [`CLAUDE_HOOK_EVENTS`] 每个事件:剥掉**所有** Vigil 托管条目,
/// 追加唯一 canonical;非 Vigil 条目原样保留。`changed` = 任一事件原本不是"恰好一条且等于 canonical"
/// (覆盖:新装 / ledger/exe 漂移替换 / 去重 / 旧版只注册了 PreToolUse 的升级补全)。
fn merge_install(mut settings: Value, command: &str) -> (bool, Value) {
    let canonical = vigil_entry(command);
    let mut changed = false;

    for event in CLAUDE_HOOK_EVENTS {
        let existing: Vec<Value> = settings
            .get("hooks")
            .and_then(|h| h.get(event))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let vigil_existing: Vec<&Value> = existing.iter().filter(|e| is_vigil_entry(e)).collect();
        let already_correct = vigil_existing.len() == 1 && vigil_existing[0] == &canonical;
        changed |= !already_correct;

        let mut new_arr: Vec<Value> = existing
            .iter()
            .filter(|e| !is_vigil_entry(e))
            .cloned()
            .collect();
        new_arr.push(canonical.clone());

        // 写回:顶层与 hooks 已校验为 object;仅替换本事件键,用户其它事件原样保留。
        let obj = match settings.as_object_mut() {
            Some(o) => o,
            // 不可达(已 ensure_mergeable_shape),但避免 expect:退化为重建仅含我们条目的配置。
            None => return (true, json!({ "hooks": { event: new_arr } })),
        };
        let hooks = obj.entry("hooks").or_insert_with(|| json!({}));
        if let Some(ho) = hooks.as_object_mut() {
            ho.insert(event.to_string(), Value::Array(new_arr));
        }
    }
    (changed, settings)
}

/// 幂等地移除 Vigil hook(扫 `hooks` 下**所有**事件键,不限 [`CLAUDE_HOOK_EVENTS`] —— 旧版本注册过的
/// 事件也要清干净)。返回 `(changed, new_settings)`。清掉 Vigil 造成的空事件数组 / 空 hooks 容器。
/// 形状不符的配置一律 no-op(保守:不动它)。
fn merge_uninstall(mut settings: Value) -> (bool, Value) {
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
        arr.retain(|e| !is_vigil_entry(e));
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

// ─────────────────────────── IO 编排(原子写 + 备份 + abort-on-malformed)───────────────

/// 读 settings:不存在 → `Ok(None)`;存在但非法 JSON → `Err(MalformedConfig)`(abort)。
/// `pub(crate)`:`setup_hooks` 读各 agent 的 hooks 配置复用同一 abort-on-malformed 语义。
pub(crate) fn read_settings(path: &Path) -> Result<Option<Value>, SetupError> {
    match std::fs::read_to_string(path) {
        Ok(s) => {
            if s.trim().is_empty() {
                return Ok(Some(json!({})));
            }
            match serde_json::from_str::<Value>(&s) {
                Ok(v) => Ok(Some(v)),
                Err(_) => Err(SetupError::MalformedConfig {
                    path: path.to_path_buf(),
                }),
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(SetupError::Io {
            what: "read settings file",
            path: path.to_path_buf(),
        }),
    }
}

/// 原子写 `value`(JSON)到 `path`:pretty-print 保持可读后委托 [`atomic_write_str_with_backup`]。
/// `pub(crate)`:`setup_mcp` 改写 `~/.claude.json` 复用同一原子写/备份机制
/// (serde_json preserve_order 保留用户键序)。
pub(crate) fn atomic_write_with_backup(
    path: &Path,
    value: &Value,
    expect_unchanged: Option<(std::time::SystemTime, u64)>,
) -> Result<Option<PathBuf>, SetupError> {
    let mut rendered = serde_json::to_string_pretty(value).map_err(|_| SetupError::Io {
        what: "serialize config",
        path: path.to_path_buf(),
    })?;
    rendered.push('\n');
    atomic_write_str_with_backup(path, &rendered, expect_unchanged)
}

/// 原子写**已渲染字符串** `rendered` 到 `path`:先备份原文件 → 写 tmp →(TOCTOU 校验)→ rename 替换。
/// rename 失败时 best-effort 清理 tmp(原文件未动)。**序列化无关**的写盘核心 —— JSON
/// (`~/.claude.json`,经 [`atomic_write_with_backup`])与 TOML(Codex `~/.codex/config.toml`,经
/// `setup_mcp::run_codex_apply`)共用同一备份 / 原子替换 / 并发改写防护,避免重复实现这段安全敏感逻辑。
pub(crate) fn atomic_write_str_with_backup(
    path: &Path,
    rendered: &str,
    // TOCTOU 防护(Codex mutation review Medium):caller 传"读取时刻"的 `(mtime, len)`;rename 替换
    // **前**再 stat 比对,若文件已被(如 Claude Code / Codex)并发改写则 abort 不覆盖,防 lost-update。
    // `None` = 不检查(hook setup 改的 settings.json 无活跃并发写者)。
    expect_unchanged: Option<(std::time::SystemTime, u64)>,
) -> Result<Option<PathBuf>, SetupError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| SetupError::Io {
            what: "create config directory",
            path: parent.to_path_buf(),
        })?;
    }

    let mut backup_path = None;
    if path.exists() {
        let bak = backup_path_for(path);
        std::fs::copy(path, &bak).map_err(|_| SetupError::Io {
            what: "back up existing config",
            path: bak.clone(),
        })?;
        backup_path = Some(bak);
    }

    let tmp = tmp_path_for(path);
    std::fs::write(&tmp, rendered.as_bytes()).map_err(|_| SetupError::Io {
        what: "write temp config",
        path: tmp.clone(),
    })?;
    // TOCTOU(Codex mutation review Medium):替换前再 stat;若文件在我们读取后被并发改写
    // (mtime/len 变)→ abort,清理 tmp,绝不用陈旧 clone 覆盖(用户的并发新写不丢)。窗口收窄到
    // 此 stat 与下面 rename 之间(微秒级)。serialize/temp-write 的耗时已在 stat **之前**发生。
    if let Some((exp_mtime, exp_len)) = expect_unchanged {
        if let Ok(m) = std::fs::metadata(path) {
            let changed =
                m.len() != exp_len || m.modified().map(|t| t != exp_mtime).unwrap_or(true);
            if changed {
                let _ = std::fs::remove_file(&tmp);
                return Err(SetupError::Io {
                    what: "config changed during update (close Claude Code, then re-run; original left intact)",
                    path: path.to_path_buf(),
                });
            }
        }
    }
    // 现代 Rust `std::fs::rename` 在 Windows 走 `MoveFileExW(.., MOVEFILE_REPLACE_EXISTING)`,
    // 原子替换既有目标(测试 install_creates_backup_of_existing + 真机 E2E 实证可覆盖既有
    // settings.json)。极少数 target 被占用/AV 锁定时 rename 失败 —— 此时**原文件未动**(fail-safe,
    // 已有 .vigil-bak),清理泄漏的 tmp 并返清晰错误,绝不留半截/损坏文件(Codex R2)。
    if let Err(_e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(SetupError::Io {
            what: "atomically replace config (target may be locked; original left intact)",
            path: path.to_path_buf(),
        });
    }

    Ok(backup_path)
}

fn backup_path_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".vigil-bak");
    PathBuf::from(s)
}
fn tmp_path_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".vigil-tmp");
    PathBuf::from(s)
}

// ─────────────────────────── 报告结构 ───────────────────────────

/// 安装状态(诚实分级;不夸大保护)。
#[derive(Debug, PartialEq, Eq)]
pub enum ProtectionState {
    /// 无 Vigil 托管条目。
    NotInstalled,
    /// 有 Vigil 托管条目,且 == 当前 canonical command 且 exe 存在 → 真正生效。
    Active,
    /// 有 Vigil 托管条目,但 command 与当前 canonical 不符(exe/ledger 漂移)或 exe 缺失 → 需重跑 setup。
    Stale,
}

/// 安装/卸载/状态结果(供 CLI 层打印)。
#[derive(Debug)]
pub struct SetupReport {
    /// 目标配置文件。
    pub settings_path: PathBuf,
    /// 是否检测到 Claude Code。
    pub claude_detected: bool,
    /// 本次是否真实改动了配置。
    pub changed: bool,
    /// 当前保护状态(status 模式有意义;install/uninstall 也会算出供打印)。
    pub state: ProtectionState,
    /// hook 将写入/已写入的 canonical command(含 ledger 路径)。
    pub hook_command: String,
    /// ledger 路径。
    pub ledger: PathBuf,
    /// 备份文件路径(若产生)。
    pub backup_path: Option<PathBuf>,
    /// dry-run 模式(未写盘)。
    pub dry_run: bool,
}

// ─────────────────────────── 入口 ───────────────────────────

/// `setup` 子命令入口。生产侧用 `dirs` 解析 home/data_local + `current_exe()`;测试走 [`run_with`] 注入。
pub fn run(args: &SetupArgs) -> Result<SetupReport, SetupError> {
    let home = dirs::home_dir().ok_or(SetupError::MissingHomeDir)?;
    let exe = std::env::current_exe().map_err(|_| SetupError::MissingCurrentExe)?;
    let env_ledger = std::env::var(LEDGER_ENV_VAR).ok();
    let data_local = dirs::data_local_dir();
    let ledger = resolve_ledger(
        args.ledger.as_deref(),
        env_ledger.as_deref(),
        data_local.as_deref(),
    )?;
    run_with(args, &home, &exe, &ledger)
}

/// 可注入的核心逻辑(测试用)。
pub fn run_with(
    args: &SetupArgs,
    home: &Path,
    exe: &Path,
    ledger: &Path,
) -> Result<SetupReport, SetupError> {
    let settings_path = claude_settings_path(home);
    let detected = claude_detected(home);
    let command = hook_command(exe, ledger);

    // 计算当前保护状态(诚实分级)。读 settings;malformed → abort。
    let existing = read_settings(&settings_path)?;
    let state = protection_state(existing.as_ref(), &command, exe);

    // --status:只读 + 报告,不改动。
    if args.status {
        return Ok(SetupReport {
            settings_path,
            claude_detected: detected,
            changed: false,
            state,
            hook_command: command,
            ledger: ledger.to_path_buf(),
            backup_path: None,
            dry_run: true,
        });
    }

    // 未检测到 Claude Code 且非 uninstall:不给不存在的 agent 创建配置。
    if !detected && !args.uninstall {
        return Ok(SetupReport {
            settings_path,
            claude_detected: false,
            changed: false,
            state,
            hook_command: command,
            ledger: ledger.to_path_buf(),
            backup_path: None,
            dry_run: args.dry_run,
        });
    }

    // install / uninstall:先校验形状(install 才需 mergeable;uninstall 本身保守)。
    let base = existing.unwrap_or_else(|| json!({}));
    let (changed, new_settings) = if args.uninstall {
        merge_uninstall(base)
    } else {
        // install/dry-run:在产出/写入可能被 shell 执行的 command 前,拒绝危险路径(Codex R2 HIGH)。
        validate_path_for_command(exe, "executable")?;
        validate_path_for_command(ledger, "ledger")?;
        ensure_mergeable_shape(&base, &settings_path)?; // 形状不符 → abort 不归一化
        merge_install(base, &command)
    };

    let backup_path = if changed && !args.dry_run {
        atomic_write_with_backup(&settings_path, &new_settings, None)?
    } else {
        None
    };

    // 改动后重算 state(install 成功后应为 Active;uninstall 后为 NotInstalled)。
    let final_state = if args.dry_run {
        state
    } else {
        protection_state(Some(&new_settings), &command, exe)
    };

    Ok(SetupReport {
        settings_path,
        claude_detected: detected,
        changed,
        state: final_state,
        hook_command: command,
        ledger: ledger.to_path_buf(),
        backup_path,
        dry_run: args.dry_run,
    })
}

/// 把一条 entry 的 hook command 里 `--ledger <值>` 归一为占位符 —— 让 staleness 比较**忽略 ledger 路径**。
/// ledger 是用户可配的共享审计路径(文档明确建议自定义,以与桌面 GUI 共享),**不应**被当作漂移。exe /
/// flag / 结构(matcher / timeout / type)仍精确比对,故升级换 binary、缺 PostToolUse、缺 `--redact-results`
/// 等**真**漂移照常报 Stale。返回 None = 该 entry 不含可识别的单条 command hook 或缺 `--ledger`(本身即非
/// canonical → 判 Stale)。取**首个** ` --ledger ` 切分:prefix(quoted-exe + hook + marker + 可选 flag)
/// 不含该字面子串,首个 occurrence 即真 flag;避免 ledger 路径恰含字面 ` --ledger ` 时误切(Codex review
/// Low;无论如何 fail-safe —— 最坏多报一次 Stale,绝不误判 Active)。
fn entry_ledger_normalized(entry: &Value) -> Option<Value> {
    let hooks = entry.get("hooks").and_then(Value::as_array)?;
    if hooks.len() != 1 {
        return None;
    }
    let cmd = hooks[0].get("command").and_then(Value::as_str)?;
    let (prefix, ledger) = cmd.split_once(" --ledger ")?;
    if ledger.trim().is_empty() {
        return None;
    }
    let mut normalized = entry.clone();
    normalized["hooks"][0]["command"] = Value::String(format!("{prefix} --ledger <vigil-ledger>"));
    Some(normalized)
}

/// 诚实判定保护状态:[`CLAUDE_HOOK_EVENTS`] **每个事件**都恰好一条托管条目且 == 当前 canonical
/// (**ledger 路径除外**,见 [`entry_ledger_normalized`])且 exe 存在 → Active;有任何托管条目但不满足上述
/// (exe/flag 漂移 / 缺事件 / exe 缺失)→ Stale;完全无托管条目 → NotInstalled。旧版只注册 PreToolUse 的
/// 安装被诚实报 Stale(提示重跑 setup 补全)。
fn protection_state(
    settings: Option<&Value>,
    canonical_command: &str,
    exe: &Path,
) -> ProtectionState {
    let Some(s) = settings else {
        return ProtectionState::NotInstalled;
    };
    // canonical 也按 ledger 归一:status 不带 --ledger 时按默认 ledger 重算 canonical,但注册串可能是用户
    // 安装时给的自定义 ledger —— 归一后只比 exe/flag/结构,自定义 ledger 不再误报 STALE(真机回归)。
    let canonical_norm = entry_ledger_normalized(&vigil_entry(canonical_command));
    let mut any_vigil = false;
    let mut all_canonical = canonical_norm.is_some();
    for event in CLAUDE_HOOK_EVENTS {
        let vigil: Vec<&Value> = s
            .get("hooks")
            .and_then(|h| h.get(event))
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter(|e| is_vigil_entry(e)).collect())
            .unwrap_or_default();
        any_vigil |= !vigil.is_empty();
        // 恰好一条且(ledger 归一后)等于 canonical 才算该事件就位。
        all_canonical &= vigil.len() == 1 && entry_ledger_normalized(vigil[0]) == canonical_norm;
    }
    if !any_vigil {
        return ProtectionState::NotInstalled;
    }
    if all_canonical && exe.exists() {
        ProtectionState::Active
    } else {
        ProtectionState::Stale
    }
}

/// doctor 自检:**in-process** 用合成的 fake github token 跑真 [`crate::hook::run`],断言被拦
/// (`Deny`)。证明"这个二进制的保护逻辑真的会拦 secret",不依赖外部进程。
pub fn doctor_self_test() -> bool {
    let synthetic = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo ghp_0123456789abcdef0123456789abcdef0123"}}"#;
    let mut cur = std::io::Cursor::new(synthetic.as_bytes());
    matches!(
        crate::hook::run(&crate::hook::HookArgs::default(), &mut cur),
        crate::hook::HookOutcome::Deny(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn exe() -> PathBuf {
        // 用真实存在的 exe 让 protection_state 的 exe.exists() 为真(测试机当前进程 exe)。
        std::env::current_exe().unwrap()
    }
    fn ledger() -> PathBuf {
        PathBuf::from("/data/Vigil/ledger.sqlite3")
    }
    fn cmd(exe: &Path, led: &Path) -> String {
        hook_command(exe, led)
    }

    #[test]
    fn fresh_install_appends_vigil_hook() {
        let c = cmd(&exe(), &ledger());
        let (changed, out) = merge_install(json!({}), &c);
        assert!(changed);
        // 注册面完整化:PreToolUse(输入守门)+ PostToolUse(结果再脱敏面)两个事件都注册。
        for event in CLAUDE_HOOK_EVENTS {
            let arr = out["hooks"][event].as_array().unwrap();
            assert_eq!(arr.len(), 1, "{event} must have exactly one entry");
            assert!(
                is_vigil_entry(&arr[0]),
                "{event} entry must be Vigil-managed"
            );
            assert_eq!(arr[0]["matcher"], "*");
            assert_eq!(
                arr[0]["hooks"][0]["timeout"],
                json!(HOOK_TIMEOUT_SECS),
                "{event} timeout must be explicit (co-approval wait window contract)"
            );
        }
    }

    #[test]
    fn legacy_pretooluse_only_install_is_upgraded_and_reported_stale_before() {
        // 旧版只注册了 PreToolUse:status 应诚实报 Stale(注册面不完整),重跑 setup 补全 PostToolUse。
        let c = cmd(&exe(), &ledger());
        let legacy = json!({ "hooks": { "PreToolUse": [vigil_entry(&c)] } });
        assert_eq!(
            protection_state(Some(&legacy), &c, &exe()),
            ProtectionState::Stale,
            "missing PostToolUse registration must not be reported Active"
        );
        let (changed, out) = merge_install(legacy, &c);
        assert!(changed, "upgrade must report a change");
        assert!(out["hooks"]["PostToolUse"].as_array().unwrap().len() == 1);
        assert_eq!(
            protection_state(Some(&out), &c, &exe()),
            ProtectionState::Active
        );
    }

    #[test]
    fn custom_ledger_install_is_active_not_stale() {
        // 回归(真机发现):`setup --ledger <自定义共享路径>` 安装后,`setup --status`(不重复 --ledger)
        // 此前误报 "INSTALLED but STALE / 重跑 setup" —— canonical 用**默认** ledger 重算、与注册串的
        // 自定义 ledger 不等。ledger 是用户可配的共享审计路径(文档建议自定义以共享桌面 GUI),不应触发漂移。
        let e = exe();
        let installed = merge_install(
            json!({}),
            &cmd(&e, &PathBuf::from("/shared/team/ledger.sqlite3")),
        )
        .1;
        // status 侧不带 --ledger → 按**默认(不同)** ledger 重算 canonical:
        let status_canonical = cmd(
            &e,
            &PathBuf::from("/home/u/.local/share/Vigil/ledger.sqlite3"),
        );
        assert_eq!(
            protection_state(Some(&installed), &status_canonical, &e),
            ProtectionState::Active,
            "custom-ledger install must be Active under status without a matching --ledger"
        );
    }

    #[test]
    fn different_binary_path_is_still_stale() {
        // 守门:exe 漂移(升级 / 移动 binary)**仍必须**报 Stale —— 本修复只放宽 ledger,不放宽 exe/flag。
        let installed =
            merge_install(json!({}), &cmd(Path::new("/old/path/vigil-hub"), &ledger())).1;
        let cur = exe(); // 当前 exe 与注册的不同路径
        let status_canonical = cmd(&cur, &ledger());
        assert_eq!(
            protection_state(Some(&installed), &status_canonical, &cur),
            ProtectionState::Stale,
            "a hook pointing at a different binary path must stay Stale (exe-drift detection preserved)"
        );
    }

    #[test]
    fn missing_ledger_arg_entry_is_stale() {
        // 守门:注册串缺 `--ledger`(形状异常 / 被手改)→ 归一返回 None → Stale(不误判 Active)。
        let e = exe();
        let canonical = cmd(&e, &ledger());
        let broken_cmd = format!(
            "{} hook --vigil-managed --redact-results",
            shell_quote("vigil-hub")
        );
        let broken = json!({ "hooks": {
            "PreToolUse":  [vigil_entry(&broken_cmd)],
            "PostToolUse": [vigil_entry(&broken_cmd)],
        }});
        assert_eq!(
            protection_state(Some(&broken), &canonical, &e),
            ProtectionState::Stale,
            "a managed entry without --ledger must not be reported Active"
        );
    }

    #[test]
    fn ledger_path_containing_ledger_substring_still_active() {
        // Codex review Low:ledger 路径字面含 " --ledger " 时,split_once(取**首个**)仍切在真 flag 处 →
        // 归一一致 → Active(rsplit 末段会误切致假 Stale)。fail-safe 硬化验证。
        let e = exe();
        let weird = PathBuf::from("/data/x --ledger y/ledger.sqlite3");
        let (_, settings) = merge_install(json!({}), &cmd(&e, &weird));
        // status 用**默认(不同且不含该子串)** ledger:
        let status_canonical = cmd(
            &e,
            &PathBuf::from("/home/u/.local/share/Vigil/ledger.sqlite3"),
        );
        assert_eq!(
            protection_state(Some(&settings), &status_canonical, &e),
            ProtectionState::Active,
            "a ledger path literally containing ' --ledger ' must still normalize correctly -> Active"
        );
    }

    #[test]
    fn reinstall_is_idempotent_no_change() {
        let c = cmd(&exe(), &ledger());
        let (_, once) = merge_install(json!({}), &c);
        let (changed, _twice) = merge_install(once, &c);
        assert!(
            !changed,
            "re-running with identical command must be a no-op"
        );
    }

    #[test]
    fn stale_ledger_command_is_replaced_not_duplicated() {
        let e = exe();
        let (_, first) = merge_install(json!({}), &cmd(&e, Path::new("/OLD")));
        let (changed, second) = merge_install(first, &cmd(&e, Path::new("/NEW")));
        assert!(changed);
        let arr = second["hooks"]["PreToolUse"].as_array().unwrap();
        let vigil: Vec<_> = arr.iter().filter(|e| is_vigil_entry(e)).collect();
        assert_eq!(vigil.len(), 1, "must replace, not duplicate");
        let command = vigil[0]["hooks"][0]["command"].as_str().unwrap();
        assert!(command.contains("/NEW") && !command.contains("/OLD"));
    }

    #[test]
    fn user_hooks_are_preserved_on_install() {
        let user = json!({
            "model": "claude-opus",
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "my-own-linter"}]}
                ],
                "PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "x"}]}]
            }
        });
        let (changed, out) = merge_install(user, &cmd(&exe(), &ledger()));
        assert!(changed);
        assert_eq!(out["model"], "claude-opus");
        assert!(out["hooks"]["PostToolUse"].is_array());
        let pre = out["hooks"]["PreToolUse"].as_array().unwrap();
        assert!(
            pre.iter()
                .any(|e| e["hooks"][0]["command"] == "my-own-linter"),
            "user hook kept"
        );
        assert!(pre.iter().any(is_vigil_entry), "vigil hook added");
    }

    #[test]
    fn user_hook_mentioning_vigil_hub_but_not_marker_is_not_clobbered() {
        // Codex R1 HIGH:marker 是 --vigil-managed,不是宽泛的 "vigil-hub"+"hook"。
        // 用户自己写了个 wrap vigil-hub 的 hook(无 marker)不应被认作 Vigil 托管。
        let user = json!({
            "hooks": {"PreToolUse": [
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "my-wrapper vigil-hub hook --foo"}]}
            ]}
        });
        let entry = &user["hooks"]["PreToolUse"][0];
        assert!(
            !is_vigil_entry(entry),
            "user wrapper without marker must NOT be treated as Vigil-managed"
        );
        let (_, out) = merge_install(user, &cmd(&exe(), &ledger()));
        let pre = out["hooks"]["PreToolUse"].as_array().unwrap();
        assert!(
            pre.iter()
                .any(|e| e["hooks"][0]["command"] == "my-wrapper vigil-hub hook --foo"),
            "user wrapper kept"
        );
    }

    #[test]
    fn uninstall_removes_only_vigil_and_cleans_empty() {
        let (_, installed) = merge_install(json!({}), &cmd(&exe(), &ledger()));
        let (changed, out) = merge_uninstall(installed);
        assert!(changed);
        assert!(
            out.get("hooks").is_none(),
            "empty hooks container cleaned up"
        );
    }

    #[test]
    fn uninstall_keeps_user_hooks() {
        let user = json!({
            "hooks": {"PreToolUse": [
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "my-own-linter"}]}
            ]}
        });
        let (_, installed) = merge_install(user, &cmd(&exe(), &ledger()));
        let (changed, out) = merge_uninstall(installed);
        assert!(changed);
        let pre = out["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 1);
        assert_eq!(pre[0]["hooks"][0]["command"], "my-own-linter");
        assert!(!pre.iter().any(is_vigil_entry));
    }

    #[test]
    fn uninstall_when_absent_is_noop() {
        let (changed, _) = merge_uninstall(json!({"model": "x"}));
        assert!(!changed);
    }

    #[test]
    fn malformed_existing_config_aborts() {
        use std::io::Write;
        let td = tempfile::TempDir::new().unwrap();
        let p = td.path().join("settings.json");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(b"{ this is not json ]]").unwrap();
        match read_settings(&p) {
            Err(SetupError::MalformedConfig { .. }) => {}
            other => panic!("malformed config must abort, got {other:?}"),
        }
    }

    #[test]
    fn unexpected_shapes_abort_not_normalize() {
        // Codex R1 BLOCKER:合法 JSON 但形状不符 → abort,绝不归一化掉用户数据。
        let p = Path::new("/x/settings.json");
        assert!(matches!(
            ensure_mergeable_shape(&json!("a string"), p),
            Err(SetupError::UnsupportedConfigShape {
                field: "<root>",
                ..
            })
        ));
        assert!(matches!(
            ensure_mergeable_shape(&json!([1, 2, 3]), p),
            Err(SetupError::UnsupportedConfigShape {
                field: "<root>",
                ..
            })
        ));
        assert!(matches!(
            ensure_mergeable_shape(&json!({"hooks": "not-an-object"}), p),
            Err(SetupError::UnsupportedConfigShape { field: "hooks", .. })
        ));
        assert!(matches!(
            ensure_mergeable_shape(&json!({"hooks": {"PreToolUse": {"not": "array"}}}), p),
            Err(SetupError::UnsupportedConfigShape {
                field: "hooks.PreToolUse",
                ..
            })
        ));
        // 正常形状放行
        assert!(ensure_mergeable_shape(&json!({}), p).is_ok());
        assert!(ensure_mergeable_shape(&json!({"hooks": {"PreToolUse": []}}), p).is_ok());
    }

    #[test]
    fn run_with_aborts_on_unexpected_shape_without_writing() {
        let td = tempfile::TempDir::new().unwrap();
        let home = td.path();
        std::fs::create_dir_all(home.join(CLAUDE_DIR)).unwrap();
        let sp = claude_settings_path(home);
        std::fs::write(&sp, br#"{"hooks":"oops-a-string"}"#).unwrap();
        let before = std::fs::read_to_string(&sp).unwrap();
        let err = run_with(&SetupArgs::default(), home, &exe(), &ledger()).unwrap_err();
        assert!(matches!(
            err,
            SetupError::UnsupportedConfigShape { field: "hooks", .. }
        ));
        let after = std::fs::read_to_string(&sp).unwrap();
        assert_eq!(before, after, "config must be untouched on abort");
    }

    #[test]
    fn install_then_uninstall_roundtrip_on_disk() {
        let td = tempfile::TempDir::new().unwrap();
        let home = td.path();
        std::fs::create_dir_all(home.join(CLAUDE_DIR)).unwrap();

        let rep = run_with(&SetupArgs::default(), home, &exe(), &ledger()).unwrap();
        assert!(rep.changed && rep.claude_detected);
        assert_eq!(
            rep.state,
            ProtectionState::Active,
            "install -> Active (exe exists)"
        );
        let on_disk = read_settings(&claude_settings_path(home)).unwrap().unwrap();
        assert_eq!(
            protection_state(Some(&on_disk), &rep.hook_command, &exe()),
            ProtectionState::Active
        );

        let rep2 = run_with(&SetupArgs::default(), home, &exe(), &ledger()).unwrap();
        assert!(!rep2.changed, "second install must be no-op");

        let args_un = SetupArgs {
            uninstall: true,
            ..Default::default()
        };
        let rep3 = run_with(&args_un, home, &exe(), &ledger()).unwrap();
        assert!(rep3.changed);
        assert_eq!(rep3.state, ProtectionState::NotInstalled);
    }

    #[test]
    fn status_ledger_difference_is_active_not_stale() {
        // 真机回归(end-to-end run_with):装一个自定义 ledger 的条目,再用**不同** ledger 查 status →
        // 必须 Active(不是 Stale)。ledger 是用户可配的共享审计路径;`setup --status` 不带 --ledger 会按
        // 默认重算 canonical,但注册串用的是用户安装时给的路径 —— 二者不同**不构成漂移**。
        let td = tempfile::TempDir::new().unwrap();
        let home = td.path();
        std::fs::create_dir_all(home.join(CLAUDE_DIR)).unwrap();
        run_with(
            &SetupArgs::default(),
            home,
            &exe(),
            Path::new("/OLD/ledger.sqlite3"),
        )
        .unwrap();
        // 现在用不同 ledger 查 status(模拟用户没重复 --ledger):
        let st = SetupArgs {
            status: true,
            ..Default::default()
        };
        let rep = run_with(&st, home, &exe(), Path::new("/NEW/ledger.sqlite3")).unwrap();
        assert_eq!(
            rep.state,
            ProtectionState::Active,
            "a different --ledger is the user's choice, not drift -> Active"
        );
    }

    #[test]
    fn status_active_only_when_exe_exists() {
        let td = tempfile::TempDir::new().unwrap();
        let home = td.path();
        std::fs::create_dir_all(home.join(CLAUDE_DIR)).unwrap();
        let missing_exe = Path::new("/no/such/vigil-hub-binary");
        run_with(&SetupArgs::default(), home, missing_exe, &ledger()).unwrap();
        let st = SetupArgs {
            status: true,
            ..Default::default()
        };
        let rep = run_with(&st, home, missing_exe, &ledger()).unwrap();
        assert_eq!(
            rep.state,
            ProtectionState::Stale,
            "missing exe -> Stale, never Active"
        );
    }

    #[test]
    fn install_creates_backup_of_existing() {
        let td = tempfile::TempDir::new().unwrap();
        let home = td.path();
        std::fs::create_dir_all(home.join(CLAUDE_DIR)).unwrap();
        let sp = claude_settings_path(home);
        std::fs::write(&sp, br#"{"model":"x"}"#).unwrap();
        let rep = run_with(&SetupArgs::default(), home, &exe(), &ledger()).unwrap();
        let bak = rep.backup_path.unwrap();
        assert!(bak.exists());
        // 备份是改动前原文
        assert!(std::fs::read_to_string(&bak).unwrap().contains("\"model\""));
        // 关键(Codex R2):rename 成功**覆盖了既有文件** —— 新内容含 marker + 保留了 model 键
        let after = read_settings(&claude_settings_path(home)).unwrap().unwrap();
        assert_eq!(after["model"], "x", "existing key preserved across replace");
        assert_eq!(
            protection_state(Some(&after), &rep.hook_command, &exe()),
            ProtectionState::Active,
            "new content written over existing file (vigil hook present + canonical)"
        );
    }

    #[test]
    fn marker_token_match_rejects_lookalikes() {
        // Codex R2 LOW:精确 token,不是子串。
        let mk = |cmd: &str| json!({"hooks": [{"type": "command", "command": cmd}]});
        assert!(is_vigil_entry(&mk(
            "/x/vigil-hub hook --vigil-managed --ledger /l"
        )));
        assert!(
            !is_vigil_entry(&mk("/x/tool --vigil-managed-old --ledger /l")),
            "lookalike token must not match"
        );
        assert!(
            !is_vigil_entry(&mk("/x/tool --not-vigil-managed")),
            "substring must not match"
        );
    }

    #[test]
    fn unsafe_path_chars_are_rejected_for_install() {
        // 跨平台:换行类一律拒。
        let td = tempfile::TempDir::new().unwrap();
        let home = td.path();
        std::fs::create_dir_all(home.join(CLAUDE_DIR)).unwrap();
        let nl_ledger = PathBuf::from("/tmp/a\nb.db");
        let err = run_with(&SetupArgs::default(), home, &exe(), &nl_ledger).unwrap_err();
        assert!(matches!(
            err,
            SetupError::UnsafePath {
                which: "ledger",
                ..
            }
        ));
        assert!(
            !claude_settings_path(home).exists(),
            "must not write on unsafe path"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_shell_metachars_in_ledger_rejected() {
        // Windows:双引号挡不住 %VAR%/$()/反引号 → 必须拒。
        let td = tempfile::TempDir::new().unwrap();
        let home = td.path();
        std::fs::create_dir_all(home.join(CLAUDE_DIR)).unwrap();
        for bad in ["C:/t/%USERNAME%/l.db", "C:/t/$(x)/l.db", "C:/t/`x`/l.db"] {
            let err = run_with(&SetupArgs::default(), home, &exe(), Path::new(bad)).unwrap_err();
            assert!(
                matches!(err, SetupError::UnsafePath { .. }),
                "{bad} must be rejected"
            );
        }
    }

    #[test]
    fn dry_run_does_not_write() {
        let td = tempfile::TempDir::new().unwrap();
        let home = td.path();
        std::fs::create_dir_all(home.join(CLAUDE_DIR)).unwrap();
        let args = SetupArgs {
            dry_run: true,
            ..Default::default()
        };
        let rep = run_with(&args, home, &exe(), &ledger()).unwrap();
        assert!(rep.changed, "dry-run still reports intended change");
        assert!(
            !claude_settings_path(home).exists(),
            "dry-run must not write"
        );
    }

    #[test]
    fn not_detected_when_no_claude_dir() {
        let td = tempfile::TempDir::new().unwrap();
        let rep = run_with(&SetupArgs::default(), td.path(), &exe(), &ledger()).unwrap();
        assert!(!rep.claude_detected && !rep.changed);
        assert!(
            !claude_settings_path(td.path()).exists(),
            "no config created for undetected agent"
        );
    }

    /// ISS-20260621-001 守门:`~/.claude.json`(Claude Code 用户级配置)存在即视 Claude Code 在场,
    /// hook 步不再跳过 —— 此前只查 `~/.claude/` 目录 + `claude` PATH 漏了它,致同一条 `setup --all`
    /// 的 MCP 步(读 `~/.claude.json`)wrap 成功而 hook 步跳过,却仍打印 "Protected"(原生工具守门缺失)。
    #[test]
    fn detected_when_claude_json_exists() {
        let td = tempfile::TempDir::new().unwrap();
        std::fs::write(td.path().join(".claude.json"), "{\"mcpServers\":{}}").unwrap();
        let rep = run_with(&SetupArgs::default(), td.path(), &exe(), &ledger()).unwrap();
        assert!(
            rep.claude_detected,
            "~/.claude.json 存在应判定 Claude Code 在场(与 MCP 步一致)"
        );
        assert!(rep.changed, "检测到即应安装 hook");
        assert!(
            claude_settings_path(td.path()).exists(),
            "hook 应写入 ~/.claude/settings.json(install 路径按需创建 ~/.claude/)"
        );
    }

    #[test]
    fn ledger_resolution_precedence() {
        let exp = PathBuf::from("/explicit/l.db");
        assert_eq!(
            resolve_ledger(Some(&exp), Some("/env/l"), Some(Path::new("/d"))).unwrap(),
            exp
        );
        assert_eq!(
            resolve_ledger(None, Some("  /env/l  "), Some(Path::new("/d"))).unwrap(),
            PathBuf::from("/env/l")
        );
        assert_eq!(
            resolve_ledger(None, Some("   "), Some(Path::new("/d"))).unwrap(),
            PathBuf::from("/d").join(VIGIL_SUBDIR).join(LEDGER_FILENAME)
        );
        assert!(matches!(
            resolve_ledger(None, None, None),
            Err(SetupError::MissingDataDir)
        ));
    }

    #[test]
    fn doctor_self_test_blocks_fake_secret() {
        assert!(doctor_self_test(), "hook must block a synthetic fake token");
    }

    #[test]
    fn agent_installed_dir_or_binary_or_neither() {
        let td = tempfile::TempDir::new().unwrap();
        let absent = td.path().join("nope");
        // 1) 二进制在 PATH、目录不存在 → detected(#13 核心:已装未首跑算已安装)。
        TEST_BINARY_ON_PATH.with(|c| c.set(true));
        assert!(
            agent_installed(&absent, Some("claude")),
            "binary on PATH => detected"
        );
        // 2) 既无目录也无二进制 → not detected;binary=None(如 Cursor)→ 仅目录检测。
        TEST_BINARY_ON_PATH.with(|c| c.set(false));
        assert!(
            !agent_installed(&absent, Some("claude")),
            "neither dir nor binary => not detected"
        );
        assert!(
            !agent_installed(&absent, None),
            "binary=None + no dir => not detected"
        );
        // 3) 目录存在 → detected(向后兼容既有目录检测)。
        std::fs::create_dir_all(&absent).unwrap();
        assert!(
            agent_installed(&absent, Some("claude")),
            "config dir present => detected"
        );
        assert!(
            agent_installed(&absent, None),
            "config dir present (binary=None) => detected"
        );
    }

    #[test]
    fn binary_on_path_real_resolves_present_binary() {
        // 评审 #13b:直接覆盖生产 glue(resolve_program 整合),不经 thread-local stub。
        // 用 PATH 上必有的二进制(sh/cmd)验证真实解析 true;不存在的名 false。
        let present = if cfg!(windows) { "cmd" } else { "sh" };
        assert!(
            binary_on_path_real(present),
            "a binary present on PATH must resolve"
        );
        assert!(
            !binary_on_path_real("vigil-nonexistent-binary-xyz"),
            "a missing binary must not resolve"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn shell_quote_neutralizes_injection_on_unix() {
        // Codex R1 HIGH:含 $() 的路径必须被单引号包成字面,不展开。
        let q = shell_quote("/tmp/$(touch pwned)/l.db");
        assert!(q.starts_with('\'') && q.ends_with('\''));
        assert!(
            q.contains("$(touch pwned)"),
            "literal preserved inside single quotes"
        );
        // 含单引号的路径正确转义
        let q2 = shell_quote("/it's/here");
        assert_eq!(q2, "'/it'\\''s/here'");
    }

    #[test]
    fn hook_command_contains_marker_and_quoted_paths() {
        let c = hook_command(Path::new("/opt/vigil-hub"), Path::new("/l/x.db"));
        assert!(c.contains(VIGIL_HOOK_MARKER));
        assert!(c.contains(" hook "));
        assert!(c.contains("--ledger"));
    }

    #[test]
    fn claude_hook_command_enables_result_redaction_others_do_not() {
        // #12:Claude canonical hook command 默认带 `--redact-results`(turnkey 开启结果硬指纹 scrub)。
        let claude = hook_command(Path::new("/opt/vigil-hub"), Path::new("/l/x.db"));
        assert!(
            claude.contains("--redact-results"),
            "Claude hook must enable result scrub: {claude}"
        );
        // 其它 CLI(显式 `--cli`)不带(不支持 updatedToolOutput,加了也是 no-op)。
        let codex = hook_command_with_cli(
            Path::new("/opt/vigil-hub"),
            Path::new("/l/x.db"),
            Some("codex"),
        );
        assert!(
            !codex.contains("--redact-results"),
            "non-Claude hook must not add it: {codex}"
        );
    }
}
