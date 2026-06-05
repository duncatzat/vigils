//! `vigil-hub setup --mcp` —— turnkey:把 Claude Code 的 stdio MCP server 改写为
//! `vigil-hub wrap ...`(逐 server 网关),可逆。
//!
//! # 范围(Claude Code user scope + local scope)
//! **`~/.claude.json`** 的 user scope(顶层 `mcpServers`)**与** local scope(`projects.<path>.mcpServers`)
//! 枚举 + 分类 + 预览 + **改写 / 还原**:
//! - `setup --mcp`:只读预览;`--apply`:改写为 wrap;`--uninstall`:self-describing 还原;`--dry-run` 只算不写。
//! - **改写直接编辑文件**(非 `claude mcp` CLI)—— 关键理由是「生产逻辑可测」:CLI 始终操作**真实**
//!   `~/.claude.json` 无法测;直接编辑用**可注入路径**,能在 tempfile 上跑完整 apply→验证→uninstall→还原
//!   功能测试而**绝不**碰用户真实配置。写盘复用 [`crate::setup::atomic_write_with_backup`]
//!   (原子 temp+rename + 备份 + preserve_order 保留用户键序)。
//! - **local scope**(`projects.<path>.mcpServers`)**默认也被保护**(`claude mcp add` 默认就写这里)。
//!   关键:local scope 的 server 名只在单项目内唯一 → 用 [`local_scope_server_id`] 派生**项目限定
//!   server-id**(`local-<sha256(projpath)[:32]>-<name>`,与 user scope 的 `user-<name>` 命名空间
//!   不相交)防跨项目同名在共享账本里身份塌缩。`--user-scope-only`
//!   显式跳过 local(诚实报告 `local_skipped`)。**project scope**(`<root>/.mcp.json` 独立**提交**文件)
//!   仍不枚举/不改 —— 改写提交文件会波及没装 vigil 的队友,刻意不碰。
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
use sha2::{Digest, Sha256};

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

/// local scope server-id 用的 SHA-256 截断长度(hex 字符数)。32 hex = **128 bit**:跨项目 birthday
/// 碰撞概率 ~ n²/2¹²⁸,对任何现实项目数天文级不可能(Codex D8 review:8 hex/32-bit 太短,要求 ≥128-bit)。
const LOCAL_ID_HASH_HEX: usize = 32;

/// 为 **user scope**(顶层 `mcpServers`)的 server 派生 server-id:`user-<name>`。
///
/// 加 `user-` 前缀(而非裸 `<name>`)是为与 [`local_scope_server_id`] 的 `local-` 命名空间**可证不相交**
/// —— Codex D8 R1 指出:裸名会与 local id 撞(用户若把 user-scope server 命名成形似 local id 的串,
/// 两者在共享账本里塌缩)。两侧都由 Vigil 加 disjoint 前缀后,任意用户取名都不可能跨 scope 撞 id。
/// 分隔符用 `-`(**非** `:`)—— `:` 不在网关 `SERVER_ID_RE = ^[a-z0-9_-]+$` 字符集内会 attach 失败
/// (Codex D8 R2 抓的回归);`-` 合法。
pub fn user_scope_server_id(name: &str) -> String {
    format!("user-{name}")
}

/// 为 **local scope**(`projects.<path>.mcpServers`)的 server 派生**项目限定** server-id。
///
/// **为何不能直接用 name 当 server-id**:local scope 的 server 名只在**单个项目内**唯一 —— 两个不同项目
/// 都可能有名为 `filesystem` 的 server(`claude mcp add` 默认就写 local scope)。若都用 `--server-id
/// filesystem` 写**共享账本**,descriptor pin / 审批会跨项目串(项目 A 批准 filesystem → 项目 B 的
/// filesystem 被自动放行 = fail-open;正是 wrap 基石 R1 Codex 抓的"固定 server-id 身份塌缩"BLOCKER)。
///
/// 方案:`local-<sha256(project_path)[:32]>-<name>` —— 稳定(同项目恒同 id)、跨项目碰撞天文级不可能
/// (128-bit hash)、与 user scope 的 `user-<name>` 命名空间**可证不相交**(`local-` ≠ `user-` 前缀,
/// 与用户取名无关,Codex D8 R1)。分隔符用 `-` 保持在网关 `SERVER_ID_RE` 合法字符集内(Codex D8 R2)。
/// unwrap 是 self-describing(从 `-- origcmd origargs` 逐字还原),**与 server-id 无关**,故反向不受影响。
pub fn local_scope_server_id(project_path: &str, name: &str) -> String {
    let digest = Sha256::digest(project_path.as_bytes());
    let hash = &hex::encode(digest)[..LOCAL_ID_HASH_HEX];
    format!("local-{hash}-{name}")
}

/// 枚举 **local scope**(`projects.<path>.mcpServers`)所有 server → `(project_path, 分类)`。纯函数。
/// 供预览展示 + apply/uninstall 复用同一分类口径。无 `projects` / 形状不符 → 空 Vec。
pub fn classify_local_scope_servers(claude_cfg: &Value) -> Vec<(String, McpServerClass)> {
    let mut out = Vec::new();
    let Some(projects) = claude_cfg.get("projects").and_then(Value::as_object) else {
        return out;
    };
    for (proj_path, proj) in projects {
        if let Some(servers) = proj.get("mcpServers").and_then(Value::as_object) {
            for (name, entry) in servers {
                out.push((proj_path.clone(), classify_one(name, entry)));
            }
        }
    }
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
    /// user scope(顶层 mcpServers)server 分类结果。
    pub servers: Vec<McpServerClass>,
    /// local scope(`projects.<path>.mcpServers`)分类结果:`(project_path, 分类)`。
    /// `--apply` 默认也保护这些(用项目限定 server-id);`--user-scope-only` 跳过。
    pub local_servers: Vec<(String, McpServerClass)>,
}

impl McpPreviewReport {
    /// user scope 可被 wrap 的 server 数。
    pub fn wrappable_count(&self) -> usize {
        self.servers
            .iter()
            .filter(|s| matches!(s, McpServerClass::Wrappable { .. }))
            .count()
    }

    /// local scope 可被 wrap 的 server 数。
    pub fn local_wrappable_count(&self) -> usize {
        self.local_servers
            .iter()
            .filter(|(_, s)| matches!(s, McpServerClass::Wrappable { .. }))
            .count()
    }
}

/// 读真实 `~/.claude.json`(IO 边界)→ 枚举 + 分类,产出只读预览报告。**不写任何东西**。
/// `home` / `exe` 注入 → 测试可指向 fixture 而**绝不**碰真实用户配置。
pub fn run_preview(home: &Path, exe: &str) -> Result<McpPreviewReport, SetupError> {
    let path = claude_json_path(home);
    let cfg = read_claude_json(&path)?;
    let (exists, servers, local_servers) = match cfg {
        Some(v) => (
            true,
            classify_user_scope_servers(&v),
            classify_local_scope_servers(&v),
        ),
        None => (false, Vec::new(), Vec::new()),
    };
    Ok(McpPreviewReport {
        claude_json: path,
        exists,
        exe: exe.to_string(),
        servers,
        local_servers,
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

/// 在一个 `mcpServers` 对象上对所有 Wrappable 应用 wrap(内部)。`id_for(name)` 派生 server-id
/// (user scope = 裸 name;local scope = 项目限定 [`local_scope_server_id`])。返回改写数。
fn wrap_servers_object(
    servers: &mut serde_json::Map<String, Value>,
    exe: &str,
    id_for: impl Fn(&str) -> String,
) -> usize {
    let mut count = 0;
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
            let sid = id_for(&name);
            let wrapped = wrap_entry(&entry, exe, &sid, &command, &args, &env_keys);
            servers.insert(name, wrapped);
            count += 1;
        }
    }
    count
}

/// 在一个 `mcpServers` 对象上对所有 Vigil 托管条目 self-describing 还原(内部)。返回还原数。
fn unwrap_servers_object(servers: &mut serde_json::Map<String, Value>) -> usize {
    let mut count = 0;
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
    count
}

/// 对 user scope(裸 name id)+ 可选 local scope(项目限定 id)应用 wrap(纯函数)。
/// 返回 `(新 cfg, user_changed, local_changed)`。`user_scope_only` = true 时跳过 local(projects.*)。
pub fn apply_wrap_to_config(
    cfg: &Value,
    exe: &str,
    user_scope_only: bool,
) -> (Value, usize, usize) {
    let mut new = cfg.clone();
    let user_changed = new
        .get_mut("mcpServers")
        .and_then(Value::as_object_mut)
        .map(|servers| wrap_servers_object(servers, exe, user_scope_server_id))
        .unwrap_or(0);

    let mut local_changed = 0;
    if !user_scope_only {
        if let Some(projects) = new.get_mut("projects").and_then(Value::as_object_mut) {
            for (proj_path, proj) in projects.iter_mut() {
                // key 与 value 借用分离;clone 项目路径供闭包派生限定 id,避免与 servers 的 &mut 纠缠。
                let proj_path = proj_path.clone();
                if let Some(servers) = proj.get_mut("mcpServers").and_then(Value::as_object_mut) {
                    local_changed += wrap_servers_object(servers, exe, |name| {
                        local_scope_server_id(&proj_path, name)
                    });
                }
            }
        }
    }
    (new, user_changed, local_changed)
}

/// 对 user scope + local scope 所有 Vigil 托管条目 self-describing 还原(纯函数)。
/// 返回 `(新 cfg, user_changed, local_changed)`。uninstall **始终**还原两个 scope —— 还原是 self-describing
/// (从 `-- origcmd origargs` 逐字),与 wrap 时用的 server-id 无关,故不受 `--user-scope-only` 影响。
pub fn apply_unwrap_config(cfg: &Value) -> (Value, usize, usize) {
    let mut new = cfg.clone();
    let user_changed = new
        .get_mut("mcpServers")
        .and_then(Value::as_object_mut)
        .map(unwrap_servers_object)
        .unwrap_or(0);

    let mut local_changed = 0;
    if let Some(projects) = new.get_mut("projects").and_then(Value::as_object_mut) {
        for (_proj_path, proj) in projects.iter_mut() {
            if let Some(servers) = proj.get_mut("mcpServers").and_then(Value::as_object_mut) {
                local_changed += unwrap_servers_object(servers);
            }
        }
    }
    (new, user_changed, local_changed)
}

/// 统计 **local scope**(`projects.<path>.mcpServers`)里**未保护**(Wrappable)的 server 数。
/// 现用途:`--user-scope-only` 跳过 local 时,诚实报告**被跳过**(留作不保护)的 local server 数
/// (`McpApplyReport::local_skipped`)。默认 `--apply` 已会保护 local scope(项目限定 id),不再拒绝。
/// 注:project scope(`<root>/.mcp.json` 独立提交文件)仍不枚举 —— 改写提交文件会波及队友,刻意不碰。
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
    /// **user scope**(顶层 mcpServers)实际(或 dry-run 将)改写/还原的 server 数。
    pub changed: usize,
    /// **local scope**(`projects.<path>.mcpServers`)改写/还原的 server 数(项目限定 server-id)。
    pub local_changed: usize,
    /// `--user-scope-only` 时**被跳过**(留作不保护)的 local scope Wrappable server 数(诚实报告)。
    pub local_skipped: usize,
    /// 仅预览不写盘。
    pub dry_run: bool,
    /// 写盘时产生的备份路径(若有)。
    pub backup: Option<PathBuf>,
}

impl McpApplyReport {
    /// 两个 scope 合计改写/还原数(决定是否需要写盘)。
    pub fn total_changed(&self) -> usize {
        self.changed + self.local_changed
    }
}

/// `setup --mcp --apply`:读 → wrap **user scope + local scope**(默认两者都保护)→ 原子写。
/// `user_scope_only` = true 时只保护 user scope,跳过 local(`local_skipped` 诚实报告)。`dry_run` 只算不写。
/// home/exe 注入 → 测试走 tempfile。
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
                local_changed: 0,
                local_skipped: 0,
                dry_run,
                backup: None,
            })
        }
    };
    // `--user-scope-only` 显式跳过 local scope —— 诚实报告被留作不保护的 local Wrappable 数。
    let local_skipped = if user_scope_only {
        count_unprotected_local_scope(&cfg)
    } else {
        0
    };
    // 读取时刻的 (mtime, len) → TOCTOU 防护(替换前比对;Claude Code 并发改写则 abort 不覆盖)。
    let stamp = std::fs::metadata(&path)
        .ok()
        .and_then(|m| m.modified().ok().map(|t| (t, m.len())));
    let (new_cfg, changed, local_changed) = apply_wrap_to_config(&cfg, exe, user_scope_only);
    let backup = if !dry_run && (changed + local_changed) > 0 {
        crate::setup::atomic_write_with_backup(&path, &new_cfg, stamp)?
    } else {
        None
    };
    Ok(McpApplyReport {
        claude_json: path,
        changed,
        local_changed,
        local_skipped,
        dry_run,
        backup,
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
                local_changed: 0,
                local_skipped: 0,
                dry_run,
                backup: None,
            })
        }
    };
    let stamp = std::fs::metadata(&path)
        .ok()
        .and_then(|m| m.modified().ok().map(|t| (t, m.len())));
    let (new_cfg, changed, local_changed) = apply_unwrap_config(&cfg);
    let backup = if !dry_run && (changed + local_changed) > 0 {
        crate::setup::atomic_write_with_backup(&path, &new_cfg, stamp)?
    } else {
        None
    };
    Ok(McpApplyReport {
        claude_json: path,
        changed,
        local_changed,
        local_skipped: 0,
        dry_run,
        backup,
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
        assert_eq!(rep.local_changed, 0, "无 local scope server");
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
    fn apply_protects_local_scope_by_default_with_user_scope_only_escape() {
        // 默认 --apply 保护 user **和** local scope(local scope 用项目限定 server-id);
        // --user-scope-only 跳过 local 并诚实报告 local_skipped。
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let claude = home.join(".claude.json");
        let initial = json!({
            "mcpServers": {"fs": {"command": "npx", "args": ["x"]}},
            "projects": {"/proj": {"mcpServers": {"local_srv": {"command": "uvx", "args": ["y"]}}}}
        });
        fs::write(&claude, initial.to_string()).unwrap();

        // 默认:user(fs)+ local(local_srv)都被保护
        let rep = run_apply(home, "vigil-hub", false, false).unwrap();
        assert_eq!(rep.changed, 1, "user scope fs 被 wrap");
        assert_eq!(rep.local_changed, 1, "local scope local_srv 被 wrap");
        assert_eq!(rep.local_skipped, 0);
        assert!(rep.backup.is_some());
        let after: Value = serde_json::from_str(&fs::read_to_string(&claude).unwrap()).unwrap();
        let local_entry = &after["projects"]["/proj"]["mcpServers"]["local_srv"];
        assert_eq!(
            local_entry["command"],
            json!("vigil-hub"),
            "local 也被 wrap"
        );
        // local scope 的 --server-id 必须是**项目限定**(local-<hash>-local_srv),非裸 "local_srv"
        let expected_id = local_scope_server_id("/proj", "local_srv");
        assert!(
            expected_id.starts_with("local-") && expected_id.ends_with("-local_srv"),
            "id 应项目限定 local- 命名空间:{expected_id}"
        );
        let local_args: Vec<String> = local_entry["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap().to_string())
            .collect();
        let sid_idx = local_args.iter().position(|a| a == "--server-id").unwrap();
        assert_eq!(
            local_args[sid_idx + 1],
            expected_id,
            "local scope 必须用项目限定 server-id 防跨项目身份塌缩"
        );
        // user scope 的 fs 用 user: 前缀(与 local: 命名空间不相交)
        let user_args: Vec<String> = after["mcpServers"]["fs"]["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap().to_string())
            .collect();
        let usid = user_args.iter().position(|a| a == "--server-id").unwrap();
        assert_eq!(
            user_args[usid + 1],
            user_scope_server_id("fs"),
            "user scope 用 user: 前缀 id"
        );

        // uninstall 还原**两个** scope(self-describing,与 id 无关)
        let rep_u = run_uninstall(home, false).unwrap();
        assert_eq!(rep_u.changed, 1);
        assert_eq!(rep_u.local_changed, 1, "local scope 也被还原");
        let restored: Value = serde_json::from_str(&fs::read_to_string(&claude).unwrap()).unwrap();
        assert_eq!(restored, initial, "往返后与初始**逐字**一致");

        // --user-scope-only:只 wrap user,跳过 local,诚实报告 local_skipped
        fs::write(&claude, initial.to_string()).unwrap();
        let rep2 = run_apply(home, "vigil-hub", false, true).unwrap();
        assert_eq!(rep2.changed, 1, "user scope fs 被 wrap");
        assert_eq!(rep2.local_changed, 0, "--user-scope-only 跳过 local");
        assert_eq!(
            rep2.local_skipped, 1,
            "诚实报告 1 个 local server 留作不保护"
        );
        let after2: Value = serde_json::from_str(&fs::read_to_string(&claude).unwrap()).unwrap();
        assert_eq!(
            after2["projects"]["/proj"]["mcpServers"]["local_srv"]["command"],
            json!("uvx"),
            "--user-scope-only 下 local server 原样未动"
        );
    }

    #[test]
    fn server_ids_are_stable_unique_and_namespace_disjoint() {
        // 同项目+同名 → 恒同 id(稳定);不同项目+同名 → 不同 id(防身份塌缩);
        // 格式 local-<32hex>-<name>(128-bit hash);user scope = user-<name>;两命名空间**可证不相交**。
        let a1 = local_scope_server_id("/home/u/projA", "filesystem");
        let a2 = local_scope_server_id("/home/u/projA", "filesystem");
        let b = local_scope_server_id("/home/u/projB", "filesystem");
        assert_eq!(a1, a2, "同项目同名 → 稳定同 id");
        assert_ne!(a1, b, "不同项目同名 → 不同 id(防跨项目身份塌缩)");
        // 格式:local-<32 hex>-<name>
        assert!(a1.starts_with("local-"), "local 前缀:{a1}");
        assert!(a1.ends_with("-filesystem"));
        let hash = a1
            .strip_prefix("local-")
            .unwrap()
            .strip_suffix("-filesystem")
            .unwrap();
        assert_eq!(hash.len(), 32, "128-bit = 32 hex(Codex D8 R1:8 hex 太短)");
        assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));

        // **命名空间不相交**(Codex D8 R1 critical):无论用户给 user-scope server 取什么名,
        // user-<name> 永不等于任一 local-<hash>-<name>(前缀 user- ≠ local-)。
        let u = user_scope_server_id("filesystem");
        assert_eq!(u, "user-filesystem");
        assert_ne!(u, a1, "user id 不撞 local id");
        // 即便用户把 user-scope server 命名成形似 local id 的串,加 user- 前缀后仍不相交
        let evil = user_scope_server_id("local-deadbeefdeadbeefdeadbeefdeadbeef-filesystem");
        assert!(evil.starts_with("user-"), "user 前缀兜住:{evil}");
        assert_ne!(evil, a1);

        // **守门(Codex D8 R2 回归):生成的 id 必须过网关真验证器 `validate_server_id`**
        // (`SERVER_ID_RE = ^[a-z0-9_-]+$`)—— `:` 等非法分隔符会让 wrap attach 在网关启动时失败。
        // 此处直接调真验证器(非重造正则),防 id scheme 再改成非法字符集时漏测。
        for id in [&a1, &b, &u, &evil] {
            vigil_mcp::namespace::validate_server_id(id)
                .unwrap_or_else(|e| panic!("生成的 server-id `{id}` 必须过网关校验:{e:?}"));
        }
    }

    #[test]
    fn classify_local_scope_enumerates_per_project() {
        let cfg = json!({
            "projects": {
                "/p1": {"mcpServers": {"fs": {"command": "npx", "args": ["a"]}}},
                "/p2": {"mcpServers": {"git": {"command": "uvx", "args": ["b"]}}}
            }
        });
        let local = classify_local_scope_servers(&cfg);
        assert_eq!(local.len(), 2);
        assert!(local.iter().any(|(p, c)| p == "/p1"
            && matches!(c, McpServerClass::Wrappable { name, .. } if name == "fs")));
        assert!(local.iter().any(|(p, c)| p == "/p2"
            && matches!(c, McpServerClass::Wrappable { name, .. } if name == "git")));
    }
}
