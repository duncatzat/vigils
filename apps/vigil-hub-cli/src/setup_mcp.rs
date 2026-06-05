//! `vigil-hub setup --mcp` —— turnkey:把 Claude Code 的 stdio MCP server 改写为
//! `vigil-hub wrap ...`(逐 server 网关),可逆。
//!
//! # 范围(Claude Code user scope)
//! **`~/.claude.json` 顶层 `mcpServers`** 的枚举 + 分类 + 预览 + **改写 / 还原**:
//! - `setup --mcp`:只读预览;`--apply`:改写为 wrap;`--uninstall`:self-describing 还原;`--dry-run` 只算不写。
//! - **改写直接编辑文件**(非 `claude mcp` CLI)—— 关键理由是「生产逻辑可测」:CLI 始终操作**真实**
//!   `~/.claude.json` 无法测;直接编辑用**可注入路径**,能在 tempfile 上跑完整 apply→验证→uninstall→还原
//!   功能测试而**绝不**碰用户真实配置。写盘复用 [`crate::setup::atomic_write_with_backup`]
//!   (原子 temp+rename + 备份 + preserve_order 保留用户键序)。
//! - **local scope**(`projects.<path>.mcpServers`)有未保护 server 时 apply **fail-closed 拒绝**
//!   (Codex guardrail:漏 scope=fail-open),除非 `--user-scope-only`。**project scope**(`.mcp.json`
//!   独立文件)v1 不枚举 —— 后续增量补。
//! - 用户须**关闭 Claude Code 后再 `--apply`**(避免与其并发写 claude.json 的 lost-update;有备份兜底)。
//!
//! # 设计基线(已定)
//! - **默认 enforce** posture(Codex audit 论证:monitor 自动放行恰恰该拦的风险动作 → 不作 turnkey
//!   默认;monitor 保持显式 opt-in)。故预览的 wrap argv **不含** `--monitor`。
//! - 改写形态:`vigil-hub wrap --server-id <名> [--env-key <K>]... --vigil-managed-mcp -- <原 cmd> <原 args>`。
//! - **env key-only**:只透传 agent 为该 server 配的 env **键名**(值由 wrap 运行时从自身 env 读),
//!   生成的配置里**绝不**出现 secret 值(复用 wrap `--env-key` allowlist,Codex R1 HIGH 决策)。
//! - **sentinel `--vigil-managed-mcp`**:幂等防双重 wrap + 标识 Vigil 托管条目(供未来 uninstall 识别)。
//! - 分类 + argv 构造是**纯函数**(fixture 可测),IO 边界(读真实文件)单独一层 —— 单测**绝不**碰真实配置。

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::setup::SetupError;

/// `~/.claude.json` 解析允许的最大字节(防病态超大文件 OOM;真实文件含会话历史可达数十 MB)。
const MAX_CLAUDE_JSON_BYTES: u64 = 256 * 1024 * 1024;

/// Vigil 托管 wrap 的 sentinel arg(幂等防双重 wrap + uninstall 识别)。与 `main.rs` 的
/// `--vigil-managed-mcp` clap flag 一致;也是 `wrap` 子命令忽略的托管标记。
pub const VIGIL_MANAGED_MCP_MARKER: &str = "--vigil-managed-mcp";

/// 一个枚举到的 MCP server 条目分类。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpServerClass {
    /// stdio server,可被 wrap(尚未托管)。
    Wrappable {
        /// agent 配置里的 server 名(= wrap `--server-id`)。
        name: String,
        /// 原始 `command`(argv[0])。
        command: String,
        /// 原始 `args`(argv[1..])。
        args: Vec<String>,
        /// agent 为该 server 配的 env **键名**(不含值;只这些键被 `--env-key` 透传)。
        env_keys: Vec<String>,
    },
    /// 已是 Vigil 托管的 wrap(sentinel 命中)—— 幂等跳过,不重复包裹。
    AlreadyWrapped {
        /// server 名。
        name: String,
    },
    /// 非 stdio(http/sse)或形状异常 —— v1 跳过(原样不动)。
    Skipped {
        /// server 名。
        name: String,
        /// 跳过原因(稳定文案,非密钥)。
        reason: &'static str,
    },
}

/// `~/.claude.json` 路径(user scope MCP 配置所在)。
pub fn claude_json_path(home: &Path) -> PathBuf {
    home.join(".claude.json")
}

/// 读 + 解析 `~/.claude.json`。不存在 → `Ok(None)`;损坏 / 超大 → abort
/// (`MalformedConfig`,绝不臆测覆盖 —— 与 `setup` 的 abort-on-unexpected 同纪律)。
pub fn read_claude_json(path: &Path) -> Result<Option<Value>, SetupError> {
    match std::fs::metadata(path) {
        Err(_) => Ok(None), // 不存在 = 用户未配 MCP(或未装 Claude Code)
        Ok(m) if m.len() > MAX_CLAUDE_JSON_BYTES => Err(SetupError::MalformedConfig {
            path: path.to_path_buf(),
        }),
        Ok(_) => {
            let raw = std::fs::read_to_string(path).map_err(|_| SetupError::Io {
                what: "read MCP config",
                path: path.to_path_buf(),
            })?;
            match serde_json::from_str::<Value>(&raw) {
                Ok(v) => Ok(Some(v)),
                Err(_) => Err(SetupError::MalformedConfig {
                    path: path.to_path_buf(),
                }),
            }
        }
    }
}

/// 从已解析的 `~/.claude.json` 枚举 **user scope**(顶层 `mcpServers`)的 server 并分类。
/// 纯函数 —— 不碰文件系统,fixture 直接可测。无 `mcpServers` / 形状不符 → 空 Vec(无可保护项)。
pub fn classify_user_scope_servers(claude_cfg: &Value) -> Vec<McpServerClass> {
    let Some(servers) = claude_cfg.get("mcpServers").and_then(Value::as_object) else {
        return Vec::new();
    };
    // `serde_json` 启用 preserve_order(workspace 级),迭代即配置插入序,确定性。
    servers
        .iter()
        .map(|(name, entry)| classify_one(name, entry))
        .collect()
}

/// 分类单个 server 条目(纯函数)。
fn classify_one(name: &str, entry: &Value) -> McpServerClass {
    let command = entry.get("command").and_then(Value::as_str);
    let raw_args = entry.get("args").and_then(Value::as_array);

    // 已托管?(HIGH,Codex setup_mcp review)**收紧**判定:必须同时满足
    //   ① command basename == vigil-hub[.exe]  ② args[0] == "wrap"  ③ args 含 sentinel。
    // 仅"sentinel 在 args 里"会误判一个**自带 `--vigil-managed-mcp` 参数的正常 server** 为已保护
    // → 被 mutation 增量跳过 → fail-open(该 server 永不受保护)。三条合取后正常 server 不可能误命中。
    if let (Some(cmd), Some(args)) = (command, raw_args) {
        let basename_is_vigil = std::path::Path::new(cmd)
            .file_stem()
            .and_then(|s| s.to_str())
            .map(|s| s.eq_ignore_ascii_case("vigil-hub"))
            .unwrap_or(false);
        let args0_is_wrap = args.first().and_then(Value::as_str) == Some("wrap");
        let has_sentinel = args.iter().filter_map(Value::as_str).any(|a| {
            a == VIGIL_MANAGED_MCP_MARKER || a.starts_with(&format!("{VIGIL_MANAGED_MCP_MARKER}="))
        });
        if basename_is_vigil && args0_is_wrap && has_sentinel {
            return McpServerClass::AlreadyWrapped { name: name.into() };
        }
    }

    // 远程(http/sse):有 `url` → 跳过(HTTP MCP wrap 留后续)。`has_url` 先于 `command` 判,
    // 故 url+command 并存的异常条目也被正确跳过(Codex checked-OK)。
    if entry.get("url").is_some() {
        return McpServerClass::Skipped {
            name: name.into(),
            reason: "remote (http/sse) server — wrapping HTTP MCP is a later increment",
        };
    }
    // `type`:缺省 = stdio(隐含);显式 "stdio" 放行;**其它任何形态**(非 stdio 字符串 / 非字符串
    // type,Low Codex)→ 跳过,绝不臆测改写一个形状异常的条目。
    match entry.get("type") {
        None => {}
        Some(Value::String(t)) if t == "stdio" => {}
        Some(_) => {
            return McpServerClass::Skipped {
                name: name.into(),
                reason: "non-stdio or malformed `type` — not wrapped in v1",
            }
        }
    }
    // args 若**存在但不是数组**(如 `"args":"bad"`)→ 跳过(High,Codex mutation review)。否则
    // `as_array()` 返 None 会被当"无 args"→ 改写成 `args:[]`→ uninstall 永久丢失原 malformed 值。
    if entry.get("args").is_some_and(|a| !a.is_array()) {
        return McpServerClass::Skipped {
            name: name.into(),
            reason: "`args` is present but not an array (unexpected shape) — left untouched",
        };
    }
    let Some(command) = command else {
        return McpServerClass::Skipped {
            name: name.into(),
            reason: "entry has no `command` (unexpected shape) — left untouched",
        };
    };

    // 原始 args 必须**全为字符串**(Medium,Codex):混入非字符串元素 → 跳过,绝不 `filter_map`
    // 静默丢弃后 lossy 改写(否则违反"原 argv 逐字保留",mutation 会发出与原意不符的 argv)。
    let args: Vec<String> = match raw_args {
        None => Vec::new(),
        Some(a) => {
            if a.iter().any(|v| !v.is_string()) {
                return McpServerClass::Skipped {
                    name: name.into(),
                    reason: "`args` has a non-string element (unexpected shape) — left untouched",
                };
            }
            a.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        }
    };
    // env **键名**(只键不值;绝不读 secret 值)。
    let env_keys: Vec<String> = entry
        .get("env")
        .and_then(Value::as_object)
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();

    McpServerClass::Wrappable {
        name: name.into(),
        command: command.into(),
        args,
        env_keys,
    }
}

/// 为一个 Wrappable server 构造 wrap 改写后的**完整 argv**(预览 / 未来 mutation 共用)。
/// 返回 `[exe, "wrap", "--server-id", name, ("--env-key" K)*, sentinel, "--", orig_cmd, orig_args*]`。
/// 配置落地时:`[0]` = 新 `command`,`[1..]` = 新 `args`。enforce posture(**不**加 `--monitor`)。
pub fn wrapped_argv(
    exe: &str,
    name: &str,
    command: &str,
    args: &[String],
    env_keys: &[String],
) -> Vec<String> {
    let mut out = Vec::with_capacity(6 + env_keys.len() * 2 + args.len());
    out.push(exe.to_string());
    out.push("wrap".into());
    out.push("--server-id".into());
    out.push(name.into());
    for k in env_keys {
        out.push("--env-key".into());
        out.push(k.clone());
    }
    out.push(VIGIL_MANAGED_MCP_MARKER.into()); // sentinel(幂等 + uninstall 识别)
    out.push("--".into()); // 分隔:之后是被包裹 server 的原 argv(逐字保留)
    out.push(command.to_string());
    out.extend(args.iter().cloned());
    out
}

/// `setup --mcp`(只读)的预览报告 —— 供 CLI 层渲染。
#[derive(Debug, Clone)]
pub struct McpPreviewReport {
    /// `~/.claude.json` 路径。
    pub claude_json: PathBuf,
    /// 配置文件是否存在。
    pub exists: bool,
    /// 用于改写的 vigil-hub 可执行路径。
    pub exe: String,
    /// user scope server 分类结果。
    pub servers: Vec<McpServerClass>,
}

impl McpPreviewReport {
    /// 可被 wrap 的 server 数。
    pub fn wrappable_count(&self) -> usize {
        self.servers
            .iter()
            .filter(|s| matches!(s, McpServerClass::Wrappable { .. }))
            .count()
    }
}

/// 读真实 `~/.claude.json`(IO 边界)→ 枚举 + 分类,产出只读预览报告。**不写任何东西**。
/// `home` / `exe` 注入 → 测试可指向 fixture 而**绝不**碰真实用户配置。
pub fn run_preview(home: &Path, exe: &str) -> Result<McpPreviewReport, SetupError> {
    let path = claude_json_path(home);
    let cfg = read_claude_json(&path)?;
    let (exists, servers) = match cfg {
        Some(v) => (true, classify_user_scope_servers(&v)),
        None => (false, Vec::new()),
    };
    Ok(McpPreviewReport {
        claude_json: path,
        exists,
        exe: exe.to_string(),
        servers,
    })
}

/// CLI 入口:解析用户 home + 本进程 exe → [`run_preview`]。生产路径;测试走 `run_preview` 注入。
pub fn run() -> Result<McpPreviewReport, SetupError> {
    let home = dirs::home_dir().ok_or(SetupError::MissingHomeDir)?;
    let exe = std::env::current_exe()
        .map_err(|_| SetupError::MissingCurrentExe)?
        .to_string_lossy()
        .to_string();
    run_preview(&home, &exe)
}

// ============================ mutation 增量(D3 增量 2) ============================
//
// **自描述可逆**:wrap 条目保留原 `env`/`type`/未知字段**逐字**,只改 `command`+`args`;`--` 之后
// 即原始 argv → uninstall 从 wrap 条目**自还原**,无需独立 snapshot 文件(reversal 信息随条目走)。
// 写盘经 `setup::atomic_write_with_backup`(原子 temp+rename + 备份 + preserve_order 保留用户键序)。
// **仅 user scope**(顶层 mcpServers);local scope(`projects.<path>.mcpServers`)有未保护 server 时
// **fail-closed 拒绝**(Codex setup_mcp review guardrail:漏 scope=fail-open),除非 `--user-scope-only`。

/// 把一个 stdio 条目改写为 wrap 条目(纯函数)。`original` 的 env/type/未知字段**逐字保留**
/// (self-describing 可逆基石);只 `command`+`args` 改写。
fn wrap_entry(
    original: &Value,
    exe: &str,
    name: &str,
    command: &str,
    args: &[String],
    env_keys: &[String],
) -> Value {
    let argv = wrapped_argv(exe, name, command, args, env_keys);
    let mut e = original.clone();
    if let Some(obj) = e.as_object_mut() {
        // **不**插入 `type:stdio`(Medium,Codex mutation review):clone 已保留原 type
        // (present→保留 / absent→仍 absent);加默认会让原本无 type 的条目 uninstall 后多出 type =
        // 非 byte-faithful。Claude Code 见 `command` 无 `url` 即按 stdio 处理,无需显式 type。
        obj.insert("command".into(), Value::String(argv[0].clone())); // exe
        let rest: Vec<Value> = argv[1..].iter().map(|s| Value::String(s.clone())).collect();
        obj.insert("args".into(), Value::Array(rest)); // wrap ... -- origcmd origargs
    }
    e
}

/// 从 wrap 条目 self-describing 还原原始条目(纯函数)。非 Vigil 托管 / 形状异常 → `None`(不动)。
/// 判据与 `classify_one` 的 AlreadyWrapped 一致:basename==vigil-hub + args[0]=="wrap" + sentinel。
fn unwrap_entry(wrapped: &Value) -> Option<Value> {
    let obj = wrapped.as_object()?;
    let args = obj.get("args")?.as_array()?;
    let cmd_is_vigil = obj
        .get("command")
        .and_then(Value::as_str)
        .map(|c| {
            std::path::Path::new(c)
                .file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("vigil-hub"))
                .unwrap_or(false)
        })
        .unwrap_or(false);
    let args0_wrap = args.first().and_then(Value::as_str) == Some("wrap");
    // **sentinel-anchored 分隔符**:`wrapped_argv` 里 sentinel **紧跟** `--`,故 separator = sentinel_idx+1。
    // **不**用 `position("--")` 找第一个 `--` —— 若 server 名 / env-key 字面恰是 `--`(病态但可能)会撞
    // 错分隔符导致还原失败/错乱。锚定 sentinel 后取其紧邻 `--` 才鲁棒(name/env-key 在 sentinel 之前)。
    let sent = args.iter().position(|a| {
        a.as_str()
            .map(|s| {
                s == VIGIL_MANAGED_MCP_MARKER
                    || s.starts_with(&format!("{VIGIL_MANAGED_MCP_MARKER}="))
            })
            .unwrap_or(false)
    })?;
    if args.get(sent + 1).and_then(Value::as_str) != Some("--") {
        return None; // sentinel 后必紧跟 `--`;否则非 Vigil 标准 wrap 形态,不动(fail-safe)
    }
    if !(cmd_is_vigil && args0_wrap) {
        return None;
    }
    // sentinel 之后第 2 元素起即原始 argv(逐字还原)。
    let orig = &args[sent + 2..];
    let orig_cmd = orig.first()?.as_str()?;
    let orig_args: Vec<Value> = orig[1..].to_vec();
    let mut e = wrapped.clone();
    let o = e.as_object_mut()?;
    o.insert("command".into(), Value::String(orig_cmd.into()));
    o.insert("args".into(), Value::Array(orig_args));
    Some(e)
}

/// user scope(顶层 mcpServers)对所有 Wrappable 应用 wrap(纯函数)。返回 (新 cfg, 改写数)。
pub fn apply_wrap_to_config(cfg: &Value, exe: &str) -> (Value, usize) {
    let mut new = cfg.clone();
    let mut count = 0;
    if let Some(servers) = new.get_mut("mcpServers").and_then(Value::as_object_mut) {
        let names: Vec<String> = servers.keys().cloned().collect();
        for name in names {
            let Some(entry) = servers.get(&name).cloned() else {
                continue;
            };
            if let McpServerClass::Wrappable {
                command,
                args,
                env_keys,
                ..
            } = classify_one(&name, &entry)
            {
                let wrapped = wrap_entry(&entry, exe, &name, &command, &args, &env_keys);
                servers.insert(name, wrapped);
                count += 1;
            }
        }
    }
    (new, count)
}

/// user scope 对所有 Vigil 托管条目 self-describing 还原(纯函数)。返回 (新 cfg, 还原数)。
pub fn apply_unwrap_config(cfg: &Value) -> (Value, usize) {
    let mut new = cfg.clone();
    let mut count = 0;
    if let Some(servers) = new.get_mut("mcpServers").and_then(Value::as_object_mut) {
        let names: Vec<String> = servers.keys().cloned().collect();
        for name in names {
            let Some(entry) = servers.get(&name).cloned() else {
                continue;
            };
            if let Some(orig) = unwrap_entry(&entry) {
                servers.insert(name, orig);
                count += 1;
            }
        }
    }
    (new, count)
}

/// 统计 **local scope**(`projects.<path>.mcpServers`)里**未保护**(Wrappable)的 server 数。
/// 返回值非 0 时 apply 须 fail-closed 拒绝(Codex guardrail:漏 scope=fail-open),除非 `--user-scope-only`。
/// 注:project scope(`<root>/.mcp.json` 独立文件)v1 不枚举 —— 后续增量补。
pub fn count_unprotected_local_scope(cfg: &Value) -> usize {
    let mut n = 0;
    if let Some(projects) = cfg.get("projects").and_then(Value::as_object) {
        for proj in projects.values() {
            if let Some(servers) = proj.get("mcpServers").and_then(Value::as_object) {
                for (name, entry) in servers {
                    if matches!(classify_one(name, entry), McpServerClass::Wrappable { .. }) {
                        n += 1;
                    }
                }
            }
        }
    }
    n
}

/// apply / uninstall 的结果报告(供 CLI 渲染)。
#[derive(Debug, Clone)]
pub struct McpApplyReport {
    /// `~/.claude.json` 路径。
    pub claude_json: PathBuf,
    /// 实际(或 dry-run 将)改写/还原的 server 数。
    pub changed: usize,
    /// 仅预览不写盘。
    pub dry_run: bool,
    /// 写盘时产生的备份路径(若有)。
    pub backup: Option<PathBuf>,
    /// 非 0 = 因 local scope 有未保护 server 被 **fail-closed 拒绝**(**未写任何东西**);CLI 应报错退出。
    pub blocked_local_scope: usize,
}

/// `setup --mcp --apply`:读 → wrap user scope → 原子写。local scope 有未保护 server →
/// fail-closed 拒绝(除非 `user_scope_only`)。`dry_run` 只算不写。home/exe 注入 → 测试走 tempfile。
pub fn run_apply(
    home: &Path,
    exe: &str,
    dry_run: bool,
    user_scope_only: bool,
) -> Result<McpApplyReport, SetupError> {
    let path = claude_json_path(home);
    let cfg = match read_claude_json(&path)? {
        Some(v) => v,
        None => {
            return Ok(McpApplyReport {
                claude_json: path,
                changed: 0,
                dry_run,
                backup: None,
                blocked_local_scope: 0,
            })
        }
    };
    // Codex guardrail:local scope 有未保护 server → fail-closed,**不写任何东西**(漏 scope=fail-open)。
    let local_unprotected = count_unprotected_local_scope(&cfg);
    if local_unprotected > 0 && !user_scope_only {
        return Ok(McpApplyReport {
            claude_json: path,
            changed: 0,
            dry_run,
            backup: None,
            blocked_local_scope: local_unprotected,
        });
    }
    // 读取时刻的 (mtime, len) → TOCTOU 防护(替换前比对;Claude Code 并发改写则 abort 不覆盖)。
    let stamp = std::fs::metadata(&path)
        .ok()
        .and_then(|m| m.modified().ok().map(|t| (t, m.len())));
    let (new_cfg, changed) = apply_wrap_to_config(&cfg, exe);
    let backup = if !dry_run && changed > 0 {
        crate::setup::atomic_write_with_backup(&path, &new_cfg, stamp)?
    } else {
        None
    };
    Ok(McpApplyReport {
        claude_json: path,
        changed,
        dry_run,
        backup,
        blocked_local_scope: 0,
    })
}

/// `setup --mcp --uninstall`:读 → 还原所有 Vigil 托管条目 → 原子写。`dry_run` 只算不写。
pub fn run_uninstall(home: &Path, dry_run: bool) -> Result<McpApplyReport, SetupError> {
    let path = claude_json_path(home);
    let cfg = match read_claude_json(&path)? {
        Some(v) => v,
        None => {
            return Ok(McpApplyReport {
                claude_json: path,
                changed: 0,
                dry_run,
                backup: None,
                blocked_local_scope: 0,
            })
        }
    };
    let stamp = std::fs::metadata(&path)
        .ok()
        .and_then(|m| m.modified().ok().map(|t| (t, m.len())));
    let (new_cfg, changed) = apply_unwrap_config(&cfg);
    let backup = if !dry_run && changed > 0 {
        crate::setup::atomic_write_with_backup(&path, &new_cfg, stamp)?
    } else {
        None
    };
    Ok(McpApplyReport {
        claude_json: path,
        changed,
        dry_run,
        backup,
        blocked_local_scope: 0,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn classifies_stdio_remote_and_wrapped() {
        let cfg = json!({
            "mcpServers": {
                "filesystem": {
                    "type": "stdio",
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
                    "env": {"FOO_TOKEN": "shh", "BAR": "x"}
                },
                "remote": { "type": "http", "url": "https://mcp.example.com/" },
                "already": {
                    "command": "vigil-hub",
                    "args": ["wrap", "--server-id", "already", "--vigil-managed-mcp", "--", "npx", "x"]
                }
            }
        });
        let classes = classify_user_scope_servers(&cfg);
        assert_eq!(classes.len(), 3);

        // filesystem → Wrappable,env 只取键名(无值)
        let fs = classes
            .iter()
            .find(|c| matches!(c, McpServerClass::Wrappable { name, .. } if name == "filesystem"))
            .expect("filesystem wrappable");
        if let McpServerClass::Wrappable {
            command,
            args,
            env_keys,
            ..
        } = fs
        {
            assert_eq!(command, "npx");
            assert_eq!(args[0], "-y");
            // env 只键名,绝无值 "shh"
            assert!(env_keys.contains(&"FOO_TOKEN".to_string()));
            assert!(!env_keys.iter().any(|k| k.contains("shh")));
        }

        // remote(http url)→ Skipped
        assert!(classes
            .iter()
            .any(|c| matches!(c, McpServerClass::Skipped { name, .. } if name == "remote")));
        // already(sentinel)→ AlreadyWrapped(幂等)
        assert!(classes
            .iter()
            .any(|c| matches!(c, McpServerClass::AlreadyWrapped { name } if name == "already")));
    }

    #[test]
    fn wrapped_argv_is_enforce_and_env_key_only() {
        let argv = wrapped_argv(
            "C:/Vigil/vigil-hub.exe",
            "filesystem",
            "npx",
            &["-y".into(), "/data".into()],
            &["FOO_TOKEN".into()],
        );
        // 形态:exe wrap --server-id filesystem --env-key FOO_TOKEN --vigil-managed-mcp -- npx -y /data
        assert_eq!(argv[0], "C:/Vigil/vigil-hub.exe");
        assert_eq!(argv[1], "wrap");
        assert_eq!(argv[2], "--server-id");
        assert_eq!(argv[3], "filesystem");
        assert!(argv.windows(2).any(|w| w == ["--env-key", "FOO_TOKEN"]));
        // enforce:绝不含 --monitor(turnkey 默认不自动放行风险动作)
        assert!(!argv.iter().any(|a| a == "--monitor"));
        // sentinel + 分隔符 + 原 argv 逐字保留
        let sep = argv.iter().position(|a| a == "--").unwrap();
        assert_eq!(argv[sep - 1], VIGIL_MANAGED_MCP_MARKER);
        assert_eq!(&argv[sep + 1..], &["npx", "-y", "/data"]);
        // env 值绝不出现在 argv(只键名)
        assert!(!argv.iter().any(|a| a.contains("shh")));
    }

    #[test]
    fn no_mcp_servers_yields_empty() {
        assert!(classify_user_scope_servers(&json!({})).is_empty());
        assert!(classify_user_scope_servers(&json!({"mcpServers": {}})).is_empty());
        // mcpServers 形状异常(数组而非对象)→ 容错空,不 panic
        assert!(classify_user_scope_servers(&json!({"mcpServers": []})).is_empty());
    }

    #[test]
    fn read_claude_json_missing_is_none_not_error() {
        let p = Path::new("/__vigil_definitely_no_such_claude_json__/.claude.json");
        assert!(matches!(read_claude_json(p), Ok(None)));
    }

    // ---- Codex setup_mcp review 守门:收紧后的边界 ----

    #[test]
    fn sentinel_alone_is_not_already_wrapped() {
        // HIGH:正常 server 把 `--vigil-managed-mcp` 当自己的参数(command 非 vigil-hub)→ 必须
        // Wrappable,绝不误判 AlreadyWrapped(否则被 mutation 跳过 = fail-open,该 server 永不受保护)。
        let cfg = json!({"mcpServers": {
            "tricky": {"command": "npx", "args": ["server", "--vigil-managed-mcp"]}
        }});
        let c = classify_user_scope_servers(&cfg);
        assert!(
            matches!(c[0], McpServerClass::Wrappable { .. }),
            "command 非 vigil-hub + args[0] 非 wrap → 不得判 AlreadyWrapped;实际 {:?}",
            c[0]
        );
    }

    #[test]
    fn real_wrapped_entry_is_detected() {
        // 真·已托管(vigil-hub + args[0]==wrap + sentinel)→ AlreadyWrapped(幂等,不重复包裹)。
        let cfg = json!({"mcpServers": {
            "fs": {"command": "C:/v/vigil-hub.exe",
                   "args": ["wrap", "--server-id", "fs", "--vigil-managed-mcp", "--", "npx", "x"]}
        }});
        let c = classify_user_scope_servers(&cfg);
        assert!(
            matches!(c[0], McpServerClass::AlreadyWrapped { .. }),
            "vigil-hub + wrap + sentinel 须判 AlreadyWrapped;实际 {:?}",
            c[0]
        );
    }

    #[test]
    fn malformed_shapes_are_skipped_not_wrapped() {
        let cfg = json!({"mcpServers": {
            "badargs": {"command": "npx", "args": ["ok", 42, "more"]}, // 非字符串 args 元素
            "nonarrayargs": {"command": "npx", "args": "bad"},         // args 非数组(High Codex)
            "badtype": {"type": 123, "command": "npx"},                // 非字符串 type
            "remote_with_cmd": {"url": "https://x", "command": "npx"}   // url + command 并存
        }});
        let c = classify_user_scope_servers(&cfg);
        let is_skipped = |n: &str| {
            c.iter()
                .any(|x| matches!(x, McpServerClass::Skipped { name, .. } if name == n))
        };
        assert!(
            is_skipped("badargs"),
            "非字符串 args 须 Skipped(不 lossy 改写)"
        );
        assert!(
            is_skipped("nonarrayargs"),
            "args 非数组须 Skipped(否则当 args=[] 改写永久丢原值)"
        );
        assert!(is_skipped("badtype"), "非字符串 type 须 Skipped(不臆测)");
        assert!(
            is_skipped("remote_with_cmd"),
            "url+command 并存须 Skipped(远程优先)"
        );
    }

    // ---- mutation 增量:wrap/unwrap 往返 + 功能测试 ----

    #[test]
    fn wrap_unwrap_round_trip_preserves_original_fields() {
        // self-describing 可逆:wrap 保留 env/未知字段逐字 → unwrap 完整还原。
        let original = json!({
            "type": "stdio",
            "command": "npx",
            "args": ["-y", "pkg", "/data"],
            "env": {"TOKEN": "secret-value"},
            "someUnknownField": {"keep": true}
        });
        let wrapped = wrap_entry(
            &original,
            "C:/v/vigil-hub.exe",
            "fs",
            "npx",
            &["-y".into(), "pkg".into(), "/data".into()],
            &["TOKEN".into()],
        );
        assert_eq!(wrapped["command"], json!("C:/v/vigil-hub.exe"));
        assert_eq!(
            wrapped["env"],
            json!({"TOKEN": "secret-value"}),
            "env 逐字保留(wrap 运行时注入子进程)"
        );
        assert_eq!(
            wrapped["someUnknownField"],
            json!({"keep": true}),
            "未知字段逐字保留"
        );
        let restored = unwrap_entry(&wrapped).expect("wrapped entry must unwrap");
        assert_eq!(restored["command"], json!("npx"));
        assert_eq!(restored["args"], json!(["-y", "pkg", "/data"]));
        assert_eq!(restored["env"], json!({"TOKEN": "secret-value"}));
        assert_eq!(restored["someUnknownField"], json!({"keep": true}));
    }

    #[test]
    fn wrap_unwrap_does_not_add_type_when_absent() {
        // 原条目**无 type**(Codex Medium):wrap 不加 type → unwrap 后仍无 type(byte-faithful)。
        let original = json!({"command": "npx", "args": ["x"]});
        let wrapped = wrap_entry(&original, "vigil-hub", "fs", "npx", &["x".into()], &[]);
        assert!(
            wrapped.get("type").is_none(),
            "wrap 不得给原本无 type 的条目加 type"
        );
        let restored = unwrap_entry(&wrapped).unwrap();
        assert!(
            restored.get("type").is_none(),
            "unwrap 后仍无 type(byte-faithful)"
        );
        assert_eq!(restored["command"], json!("npx"));
        assert_eq!(restored["args"], json!(["x"]));
    }

    #[test]
    fn unwrap_refuses_non_vigil_entry() {
        // 非 Vigil 托管条目(命令非 vigil-hub)→ unwrap 返 None,绝不误动用户条目。
        let normal = json!({"command": "npx", "args": ["server", "--", "x"]});
        assert!(unwrap_entry(&normal).is_none());
    }

    #[test]
    fn unwrap_robust_against_dashdash_in_name_and_original_args() {
        // 病态:server 名字面是 "--" + 原始 args 也含 "--"。sentinel-anchored 分隔符必须仍正确还原
        // (旧 `position("--")` 会撞到 name 处的 "--" 导致还原失败)。
        let original = json!({"command": "tool", "args": ["a", "--", "b"]});
        let wrapped = wrap_entry(
            &original,
            "vigil-hub",
            "--",
            "tool",
            &["a".into(), "--".into(), "b".into()],
            &[],
        );
        let restored = unwrap_entry(&wrapped).expect("must unwrap despite -- collisions");
        assert_eq!(restored["command"], json!("tool"));
        assert_eq!(
            restored["args"],
            json!(["a", "--", "b"]),
            "原始 args 里的 -- 必须逐字还原"
        );
    }

    /// **功能测试**:tempfile 真文件 apply → 验证 → uninstall → 还原(绝不碰真实 ~/.claude.json)。
    #[test]
    fn functional_apply_uninstall_round_trip_on_tempfile() {
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let claude = home.join(".claude.json");
        fs::write(
            &claude,
            json!({"mcpServers": {
                "fs": {"command": "npx", "args": ["-y", "pkg"], "env": {"T": "v"}}
            }})
            .to_string(),
        )
        .unwrap();

        // apply
        let rep = run_apply(home, "vigil-hub", false, false).unwrap();
        assert_eq!(rep.changed, 1);
        assert_eq!(rep.blocked_local_scope, 0);
        assert!(rep.backup.is_some(), "改写应产生备份");
        let after: Value = serde_json::from_str(&fs::read_to_string(&claude).unwrap()).unwrap();
        assert_eq!(after["mcpServers"]["fs"]["command"], json!("vigil-hub"));
        assert!(after["mcpServers"]["fs"]["args"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a == "--vigil-managed-mcp"));
        assert_eq!(
            after["mcpServers"]["fs"]["env"],
            json!({"T": "v"}),
            "env 逐字保留"
        );

        // uninstall 还原
        let rep2 = run_uninstall(home, false).unwrap();
        assert_eq!(rep2.changed, 1);
        let restored: Value = serde_json::from_str(&fs::read_to_string(&claude).unwrap()).unwrap();
        assert_eq!(
            restored["mcpServers"]["fs"]["command"],
            json!("npx"),
            "uninstall 必须还原 command"
        );
        assert_eq!(
            restored["mcpServers"]["fs"]["args"],
            json!(["-y", "pkg"]),
            "还原 args"
        );
        assert_eq!(restored["mcpServers"]["fs"]["env"], json!({"T": "v"}));
    }

    #[test]
    fn apply_refuses_when_local_scope_has_unprotected_servers() {
        // Codex guardrail:local scope 有未保护 server → fail-closed,不写;--user-scope-only 显式放行。
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let claude = home.join(".claude.json");
        fs::write(
            &claude,
            json!({
                "mcpServers": {"fs": {"command": "npx", "args": ["x"]}},
                "projects": {"/proj": {"mcpServers": {"local_srv": {"command": "uvx", "args": ["y"]}}}}
            })
            .to_string(),
        )
        .unwrap();

        let rep = run_apply(home, "vigil-hub", false, false).unwrap();
        assert_eq!(rep.blocked_local_scope, 1, "local scope 1 未保护 → 拒绝");
        assert_eq!(rep.changed, 0, "拒绝时不改写");
        assert!(rep.backup.is_none(), "拒绝时不写不备份");
        let unchanged: Value = serde_json::from_str(&fs::read_to_string(&claude).unwrap()).unwrap();
        assert_eq!(
            unchanged["mcpServers"]["fs"]["command"],
            json!("npx"),
            "拒绝时文件原样"
        );

        // --user-scope-only 显式放行 → 只 wrap user scope
        let rep2 = run_apply(home, "vigil-hub", false, true).unwrap();
        assert_eq!(
            rep2.changed, 1,
            "--user-scope-only 应 wrap user scope 的 fs"
        );
        assert_eq!(rep2.blocked_local_scope, 0);
    }
}
