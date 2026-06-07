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
//! - **默认 monitor** posture(D10,评估增量 #1):被 wrap 的是用户自配**第三方** server,其工具名不在
//!   firewall effect 词表 → enforce 下一律 default-deny = 真实 server **全不可用**(turnkey 接入即打挂
//!   用户工作流 = 采用毒药)。monitor 保留全部硬地板(裸 secret 拦截 + 结果脱敏可逆往返 + 显式 Deny +
//!   descriptor drift),只把 default-deny **地板**降级为观察放行。故默认预览/落盘的 wrap argv **含**
//!   `--monitor`;`--enforce`(`monitor = !enforce`)是显式硬化档(default-deny + 阻塞审批),供已知
//!   工具集 / 自建 server / 高保障场景。详见 `main.rs` `CliSetupArgs::enforce` doc + 评估文档
//!   `docs/strategy/mcp-gateway-design-assessment.md`。
//! - 改写形态:`vigil-hub wrap --server-id <名> [--env-key <K>]... --vigil-managed-mcp -- <原 cmd> <原 args>`。
//! - **env key-only(指 wrap argv,非整个条目)**:改写产出的 **wrap 命令行**只含 env **键名**
//!   (`--env-key K`,值由 wrap 运行时从自身 env 读),**argv 里绝不出现 secret 值**。注意:被包裹
//!   条目原有的 `env` 对象(含用户**早已写入**的值)**逐字保留**(reversible 需要 + Claude 仍按它设
//!   wrap 的 env)—— wrap **既不新增也不复制** secret 值,只是不让值出现在 argv;原值本就在用户配置里,
//!   故"配置 at-rest 无 secret"**不**成立(Codex holistic MEDIUM 澄清;`--env-key` 只限子进程转发)。
//! - **sentinel `--vigil-managed-mcp`**:幂等防双重 wrap + 标识 Vigil 托管条目(供未来 uninstall 识别)。
//! - 分类 + argv 构造是**纯函数**(fixture 可测),IO 边界(读真实文件)单独一层 —— 单测**绝不**碰真实配置。

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;
use sha2::{Digest, Sha256};
use toml_edit::DocumentMut;

use crate::setup::SetupError;

/// `setup --mcp --doctor --probe` 每 server 的 MCP `initialize` 握手上界。
/// 取较宽松值:`npx`/`uvx` server **首次**启动会下载包(冷缓存可能数十秒)—— 同样的延迟 agent
/// 真实首启也会遇到,故 probe 超时本身是有用信号(慢=坏首启体验),但默认给足时间避免对冷缓存
/// 误报 FAIL。caller 可经 `--probe` 触发;默认 doctor 纯静态不调用本路径。
pub const DOCTOR_PROBE_TIMEOUT: Duration = Duration::from_secs(20);

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
        // **真不存在** = 用户未配 MCP(或未装该 agent)→ Ok(None)。但**存在却不可访问**(权限等其它 stat
        // 错误)绝不当"未配置"静默跳过(Codex D28 #8:那会 fail-open —— 一个存在的配置被悄悄漏保护),
        // 诚实报 IO 错(fail-closed)。
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(SetupError::Io {
            what: "stat MCP config",
            path: path.to_path_buf(),
        }),
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

    // 远程(http/sse):有 `url`(Claude/Cursor/Codex/Cline/Zed)或 `serverUrl`(Windsurf 专用字段)
    // → 跳过(HTTP MCP wrap 留后续)。远程判定先于 `command`,故 url+command 并存的异常条目也被正确
    // 跳过(Codex checked-OK)。stdio 条目绝不含 url/serverUrl,故加 serverUrl 对其它 agent 是 no-op。
    if entry.get("url").is_some() || entry.get("serverUrl").is_some() {
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
    // F3(Codex holistic MEDIUM):server-id 由 name 派生(`user-<name>` / `local-<hash>-<name>`),
    // 但网关 attach 时只接受 `^[a-z0-9_-]+$`(namespace::validate_server_id)。若 name 含大写/空格/点/
    // 斜杠等(Claude server 名可任意),改写会"apply 成功但 wrap 启动失败"(配置坏了却看不出)。
    // 用**真验证器**校验 name —— 名合法则 `user-`/`local-<hash>-` 前缀拼接后必合法;不合法则 Skip
    // (不改写),让用户改名后再保护,而非产出一个起不来的网关条目。
    if vigil_mcp::namespace::validate_server_id(name).is_err() {
        return McpServerClass::Skipped {
            name: name.into(),
            reason: "server name has characters not allowed in a gateway id (use a-z 0-9 _ -); \
                     rename it in your MCP config to protect it",
        };
    }

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

/// 为一个 Wrappable server 构造 wrap 改写后的**完整 argv**(预览 / mutation 共用)。
/// 返回 `[exe, "wrap", "--server-id", name, ("--env-key" K)*, ("--monitor")?, sentinel, "--", orig_cmd, orig_args*]`。
/// 配置落地时:`[0]` = 新 `command`,`[1..]` = 新 `args`。
///
/// `monitor`:**默认 true**(setup --mcp 的默认姿态)。理由(战略评估三视角收敛,见
/// docs/strategy/mcp-gateway-design-assessment.md):firewall 对未分类第三方工具空转 → enforce 只会
/// default-deny **破坏**被包裹的真实 server;且 93% 审批提示被无视 = 审批门是剧场;而真价值
/// (result 脱敏 + 裸 secret 拦截 + 审计)在 monitor 也全跑。**可用的 monitor >> 被绕过的 enforce**。
/// `monitor=false` = `--enforce` 硬化档(显式 opt-in:default-deny + 阻塞审批)。
pub fn wrapped_argv(
    exe: &str,
    name: &str,
    command: &str,
    args: &[String],
    env_keys: &[String],
    monitor: bool,
) -> Vec<String> {
    let mut out = Vec::with_capacity(7 + env_keys.len() * 2 + args.len());
    out.push(exe.to_string());
    out.push("wrap".into());
    out.push("--server-id".into());
    out.push(name.into());
    for k in env_keys {
        out.push("--env-key".into());
        out.push(k.clone());
    }
    if monitor {
        out.push("--monitor".into()); // 默认观察姿态(脱敏+审计+裸 secret 拦截,非阻塞)
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
    /// 将写入 wrap argv 的守门姿态:`true` = monitor(默认,观察放行+脱敏+审计+裸 secret 拦截),
    /// `false` = enforce(default-deny 硬拦)。预览据此渲染真实 argv,与 `--apply` 落盘一致。
    pub monitor: bool,
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
pub fn run_preview(home: &Path, exe: &str, monitor: bool) -> Result<McpPreviewReport, SetupError> {
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
        monitor,
    })
}

/// CLI 入口:解析用户 home + 本进程 exe → [`run_preview`]。生产路径;测试走 `run_preview` 注入。
/// `monitor` 反映将要落盘的姿态(由 CLI `--enforce` 反推:`monitor = !enforce`,默认 monitor)。
pub fn run(monitor: bool) -> Result<McpPreviewReport, SetupError> {
    let home = dirs::home_dir().ok_or(SetupError::MissingHomeDir)?;
    let exe = std::env::current_exe()
        .map_err(|_| SetupError::MissingCurrentExe)?
        .to_string_lossy()
        .to_string();
    run_preview(&home, &exe, monitor)
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
    monitor: bool,
) -> Value {
    let argv = wrapped_argv(exe, name, command, args, env_keys, monitor);
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
    monitor: bool,
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
            let wrapped = wrap_entry(&entry, exe, &sid, &command, &args, &env_keys, monitor);
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
    monitor: bool,
) -> (Value, usize, usize) {
    let mut new = cfg.clone();
    let user_changed = new
        .get_mut("mcpServers")
        .and_then(Value::as_object_mut)
        .map(|servers| wrap_servers_object(servers, exe, monitor, user_scope_server_id))
        .unwrap_or(0);

    let mut local_changed = 0;
    if !user_scope_only {
        if let Some(projects) = new.get_mut("projects").and_then(Value::as_object_mut) {
            for (proj_path, proj) in projects.iter_mut() {
                // key 与 value 借用分离;clone 项目路径供闭包派生限定 id,避免与 servers 的 &mut 纠缠。
                let proj_path = proj_path.clone();
                if let Some(servers) = proj.get_mut("mcpServers").and_then(Value::as_object_mut) {
                    local_changed += wrap_servers_object(servers, exe, monitor, |name| {
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
    monitor: bool,
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
    let (new_cfg, changed, local_changed) =
        apply_wrap_to_config(&cfg, exe, user_scope_only, monitor);
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

// ============================ Codex 接入面(`~/.codex/config.toml`)============================
//
// Codex CLI 与 Claude Code 并列,是本命令第二个受保护的 agent 配置面。Codex 用 TOML
// **`[mcp_servers.<name>]`** 表配 stdio MCP server,**每条目形状几乎与 Claude 的
// `mcpServers.<name>` 对象一致**(`command` / `args` / `env`)。故策略 = **最大化复用 Claude 路径的
// 安全机制**:把每个 TOML 条目桥接成 `serde_json::Value` 后,走**同一个** [`classify_one`]
// (全部安全护栏:sentinel 精确匹配 / 危险字符拒绝 / 非 stdio 跳过 / server-id 校验)、
// 同一个 [`wrapped_argv`](wrap argv 构造 SSOT)、同一个 [`unwrap_entry`](还原 SSOT)。
// Codex 专属的只有 TOML 读写管道。
//
// **格式保留**:Codex 的 `config.toml` 常含用户手写注释 + model/approval 等其它设置段。用 `toml_edit`
// 的 `DocumentMut` 做**外科手术式**改写(只替换命中条目的 `command`+`args` 两个值),保留注释 / 键序 /
// 其它段 —— 与 cargo 自身编辑 Cargo.toml 同款。绝不整篇 `to_string` 重排丢注释。
//
// **server-id 命名空间**:Codex 条目派生 `codex-<name>`,与 user scope 的 `user-` / local scope 的
// `local-` **可证不相交**(共享账本里跨 agent 同名 server 身份不塌缩)。

/// Codex CLI 的 MCP 配置文件路径(`~/.codex/config.toml`)。
pub fn codex_config_path(home: &Path) -> PathBuf {
    home.join(".codex").join("config.toml")
}

/// 为 Codex `[mcp_servers.<name>]` 条目派生 server-id:`codex-<name>`。
///
/// 加 `codex-` 前缀与 [`user_scope_server_id`](`user-`)/ [`local_scope_server_id`](`local-`)
/// 命名空间不相交。`name` 已由 [`classify_one`] 用真验证器 `validate_server_id` 过滤(`^[a-z0-9_-]+$`),
/// 故 `codex-<name>` 拼接后必合法(`codex-` 全在字符集内)。
pub fn codex_scope_server_id(name: &str) -> String {
    format!("codex-{name}")
}

/// 读 + 解析 `~/.codex/config.toml`(格式保留)。不存在 → `Ok(None)`;损坏 / 超大 → abort
/// (`MalformedConfig`,绝不臆测覆盖 —— 与 [`read_claude_json`] 同纪律,仅解析器从 JSON 换成 TOML)。
pub fn read_codex_config(path: &Path) -> Result<Option<DocumentMut>, SetupError> {
    match std::fs::metadata(path) {
        // 真不存在 → Ok(None);存在但不可访问(权限等)→ 诚实 IO 错,绝不当"未配置"静默跳过
        // (Codex D28 #8,与 read_claude_json 同纪律)。
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(SetupError::Io {
            what: "stat Codex config",
            path: path.to_path_buf(),
        }),
        Ok(m) if m.len() > MAX_CLAUDE_JSON_BYTES => Err(SetupError::MalformedConfig {
            path: path.to_path_buf(),
        }),
        Ok(_) => {
            let raw = std::fs::read_to_string(path).map_err(|_| SetupError::Io {
                what: "read Codex config",
                path: path.to_path_buf(),
            })?;
            match raw.parse::<DocumentMut>() {
                Ok(d) => Ok(Some(d)),
                Err(_) => Err(SetupError::MalformedConfig {
                    path: path.to_path_buf(),
                }),
            }
        }
    }
}

/// 取 `[mcp_servers]` 表(标准 sub-table 形态;`mcp_servers = {..}` 内联 / 缺省 → `None` = 无可保护项)。
fn codex_servers_table(doc: &DocumentMut) -> Option<&toml_edit::Table> {
    doc.get("mcp_servers").and_then(|i| i.as_table())
}
fn codex_servers_table_mut(doc: &mut DocumentMut) -> Option<&mut toml_edit::Table> {
    doc.get_mut("mcp_servers").and_then(|i| i.as_table_mut())
}

/// 把一个 `toml_edit` 条目桥接成 `serde_json::Value`,喂给共享的 [`classify_one`]。
/// 只忠实复制值(string/array/table/...),**不**捏造任何字段 —— 故桥接 bug 至多让条目被分类成
/// `Skipped`(不动 = fail-safe),绝不可能凭空造出 `vigil-hub`/sentinel 而误判 AlreadyWrapped(fail-open)。
/// MCP 条目只含 string / array-of-string / table,无 TOML datetime;datetime 退化为字符串(不影响 classify)。
fn item_to_json(item: &toml_edit::Item) -> Value {
    match item {
        toml_edit::Item::Value(v) => value_to_json(v),
        toml_edit::Item::Table(t) => {
            let mut map = serde_json::Map::new();
            for (k, v) in t.iter() {
                map.insert(k.to_string(), item_to_json(v));
            }
            Value::Object(map)
        }
        toml_edit::Item::ArrayOfTables(a) => Value::Array(
            a.iter()
                .map(|t| {
                    let mut map = serde_json::Map::new();
                    for (k, v) in t.iter() {
                        map.insert(k.to_string(), item_to_json(v));
                    }
                    Value::Object(map)
                })
                .collect(),
        ),
        toml_edit::Item::None => Value::Null,
    }
}
fn value_to_json(v: &toml_edit::Value) -> Value {
    match v {
        toml_edit::Value::String(s) => Value::String(s.value().clone()),
        toml_edit::Value::Integer(i) => Value::Number((*i.value()).into()),
        toml_edit::Value::Float(f) => serde_json::Number::from_f64(*f.value())
            .map(Value::Number)
            .unwrap_or(Value::Null),
        toml_edit::Value::Boolean(b) => Value::Bool(*b.value()),
        toml_edit::Value::Datetime(d) => Value::String(d.value().to_string()),
        toml_edit::Value::Array(a) => Value::Array(a.iter().map(value_to_json).collect()),
        toml_edit::Value::InlineTable(t) => {
            let mut map = serde_json::Map::new();
            for (k, v) in t.iter() {
                map.insert(k.to_string(), value_to_json(v));
            }
            Value::Object(map)
        }
    }
}

/// 在一个 `toml_edit` 条目上就地设 `command`+`args`(wrap / unwrap 共用的唯一写盘点)。
/// `insert` 替换既有键的值、保留其位置与周围 trivia(注释/空白),只这两个值变。
/// 用 `as_table_like_mut` 同时覆盖 `[mcp_servers.x]`(Table)与 `x = {..}`(InlineTable)两种条目
/// 形态,且条目非表(理论不可达 —— 调用方只对 classify 确认含 `command` 字段的条目调用)时**安全 no-op**
/// 而非 panic。
fn set_codex_command_args(entry: &mut toml_edit::Item, command: &str, args: &[String]) {
    if let Some(tbl) = entry.as_table_like_mut() {
        tbl.insert("command", toml_edit::value(command));
        let mut arr = toml_edit::Array::new();
        for a in args {
            arr.push(a.as_str());
        }
        tbl.insert("args", toml_edit::value(arr));
    }
}

/// 从已解析的 Codex `DocumentMut` 枚举 `[mcp_servers.*]` 并分类(纯函数,不碰文件系统)。
pub fn classify_codex_servers(doc: &DocumentMut) -> Vec<McpServerClass> {
    let Some(servers) = codex_servers_table(doc) else {
        return Vec::new();
    };
    servers
        .iter()
        .map(|(name, item)| classify_one(name, &item_to_json(item)))
        .collect()
}

/// 对 Codex `[mcp_servers.*]` 里每个 Wrappable 条目就地 wrap(`command`→vigil-hub,`args`→wrap 包裹 argv;
/// 格式保留)。返回改写数。server-id = `codex-<name>`。
pub fn apply_wrap_to_codex(doc: &mut DocumentMut, exe: &str, monitor: bool) -> usize {
    // 先按分类器选出 Wrappable 的 (name, command, args, env_keys)(只读借用),再改写,
    // 避免迭代期对 servers 的 &mut 借用纠缠;且确保"预览说会改的" == "apply 真改的"(同一 classify_one)。
    let plan: Vec<(String, String, Vec<String>, Vec<String>)> = {
        let Some(servers) = codex_servers_table(doc) else {
            return 0;
        };
        servers
            .iter()
            .filter_map(
                |(name, item)| match classify_one(name, &item_to_json(item)) {
                    McpServerClass::Wrappable {
                        name,
                        command,
                        args,
                        env_keys,
                    } => Some((name, command, args, env_keys)),
                    _ => None,
                },
            )
            .collect()
    };
    let Some(servers) = codex_servers_table_mut(doc) else {
        return 0;
    };
    let mut changed = 0;
    for (name, command, args, env_keys) in plan {
        if let Some(entry) = servers.get_mut(&name) {
            let argv = wrapped_argv(
                exe,
                &codex_scope_server_id(&name),
                &command,
                &args,
                &env_keys,
                monitor,
            );
            // argv[0] = 新 command(vigil-hub),argv[1..] = 新 args(wrap ... -- origcmd origargs)。
            set_codex_command_args(entry, &argv[0], &argv[1..]);
            changed += 1;
        }
    }
    changed
}

/// 对 Codex `[mcp_servers.*]` 里所有 Vigil 托管条目 self-describing 还原(格式保留)。返回还原数。
/// 复用 [`unwrap_entry`](sentinel-anchored 反解 SSOT):桥接条目→json 反解,再把还原出的 command+args 写回。
pub fn apply_unwrap_codex(doc: &mut DocumentMut) -> usize {
    let names: Vec<String> = match codex_servers_table(doc) {
        Some(t) => t.iter().map(|(n, _)| n.to_string()).collect(),
        None => return 0,
    };
    let Some(servers) = codex_servers_table_mut(doc) else {
        return 0;
    };
    let mut changed = 0;
    for name in names {
        if let Some(entry) = servers.get_mut(&name) {
            // 桥接→json 走共享反解;非 Vigil 托管 / 形态异常 → None(不动,fail-safe)。
            if let Some(restored) = unwrap_entry(&item_to_json(entry)) {
                let cmd = restored.get("command").and_then(Value::as_str);
                let args_arr = restored.get("args").and_then(Value::as_array);
                // **abort-on-unexpected(Codex review #3 MEDIUM)**:Vigil 产出的 wrap 尾部原 argv
                // **必然全字符串**(classify_one 改写前已拒非字符串 args + wrapped_argv 只产字符串)。
                // 若某条目的还原 args 含**非字符串**元素(只可能来自用户手改注入,如 `args=[..,"--",123]`),
                // 绝不 `filter_map` 静默丢弃 → 跳过该条目(留作 wrapped,数据不丢),而非 lossy 还原。
                match (cmd, args_arr) {
                    (Some(cmd), Some(arr)) if arr.iter().all(Value::is_string) => {
                        let args: Vec<String> = arr
                            .iter()
                            .filter_map(Value::as_str)
                            .map(String::from)
                            .collect();
                        set_codex_command_args(entry, cmd, &args);
                        changed += 1;
                    }
                    // 形态异常(非常规手改):不动,fail-safe(原非字符串值仍以 wrapped 形式保留)。
                    _ => {}
                }
            }
        }
    }
    changed
}

/// Codex 接入面的只读预览报告(供 CLI 渲染)。
#[derive(Debug, Clone)]
pub struct CodexPreviewReport {
    /// `~/.codex/config.toml` 路径。
    pub codex_config: PathBuf,
    /// 配置文件是否存在(不存在 = 用户未用 Codex,诚实标记)。
    pub exists: bool,
    /// 本进程 exe(预览 wrap argv 用)。
    pub exe: String,
    /// `[mcp_servers.*]` 逐条目分类。
    pub servers: Vec<McpServerClass>,
    /// 将落盘的姿态(`monitor` / `--enforce`),供预览文案一致。
    pub monitor: bool,
}

impl CodexPreviewReport {
    /// 可被保护(Wrappable)的 server 数。
    pub fn wrappable_count(&self) -> usize {
        self.servers
            .iter()
            .filter(|s| matches!(s, McpServerClass::Wrappable { .. }))
            .count()
    }
}

/// Codex 接入面 apply / uninstall 的结果报告。
#[derive(Debug, Clone)]
pub struct CodexApplyReport {
    /// `~/.codex/config.toml` 路径。
    pub codex_config: PathBuf,
    /// 实际(或 dry-run 将)改写 / 还原的 server 数。
    pub changed: usize,
    /// 仅预览不写盘。
    pub dry_run: bool,
    /// 写盘时产生的备份路径(若有)。
    pub backup: Option<PathBuf>,
}

/// 读真实 `~/.codex/config.toml`(IO 边界)→ 枚举 + 分类,产出只读预览。**不写任何东西**。
/// `home` / `exe` 注入 → 测试走 fixture 而**绝不**碰真实用户配置。
pub fn run_codex_preview(
    home: &Path,
    exe: &str,
    monitor: bool,
) -> Result<CodexPreviewReport, SetupError> {
    let path = codex_config_path(home);
    let doc = read_codex_config(&path)?;
    let (exists, servers) = match doc {
        Some(d) => (true, classify_codex_servers(&d)),
        None => (false, Vec::new()),
    };
    Ok(CodexPreviewReport {
        codex_config: path,
        exists,
        exe: exe.to_string(),
        servers,
        monitor,
    })
}

/// `setup --mcp --apply`(Codex 面):读 → wrap 全部 Wrappable → 格式保留原子写。`dry_run` 只算不写。
pub fn run_codex_apply(
    home: &Path,
    exe: &str,
    dry_run: bool,
    monitor: bool,
) -> Result<CodexApplyReport, SetupError> {
    let path = codex_config_path(home);
    let mut doc = match read_codex_config(&path)? {
        Some(d) => d,
        None => {
            return Ok(CodexApplyReport {
                codex_config: path,
                changed: 0,
                dry_run,
                backup: None,
            })
        }
    };
    // 读取时刻的 (mtime, len) → TOCTOU 防护(替换前比对;Codex 并发改写则 abort 不覆盖)。
    let stamp = std::fs::metadata(&path)
        .ok()
        .and_then(|m| m.modified().ok().map(|t| (t, m.len())));
    let changed = apply_wrap_to_codex(&mut doc, exe, monitor);
    let backup = if !dry_run && changed > 0 {
        let rendered = doc.to_string(); // 格式保留序列化(只命中条目的 command+args 变)
        crate::setup::atomic_write_str_with_backup(&path, &rendered, stamp)?
    } else {
        None
    };
    Ok(CodexApplyReport {
        codex_config: path,
        changed,
        dry_run,
        backup,
    })
}

/// `setup --mcp --uninstall`(Codex 面):读 → 还原所有 Vigil 托管条目 → 格式保留原子写。`dry_run` 只算不写。
pub fn run_codex_uninstall(home: &Path, dry_run: bool) -> Result<CodexApplyReport, SetupError> {
    let path = codex_config_path(home);
    let mut doc = match read_codex_config(&path)? {
        Some(d) => d,
        None => {
            return Ok(CodexApplyReport {
                codex_config: path,
                changed: 0,
                dry_run,
                backup: None,
            })
        }
    };
    let stamp = std::fs::metadata(&path)
        .ok()
        .and_then(|m| m.modified().ok().map(|t| (t, m.len())));
    let changed = apply_unwrap_codex(&mut doc);
    let backup = if !dry_run && changed > 0 {
        let rendered = doc.to_string();
        crate::setup::atomic_write_str_with_backup(&path, &rendered, stamp)?
    } else {
        None
    };
    Ok(CodexApplyReport {
        codex_config: path,
        changed,
        dry_run,
        backup,
    })
}

// ============================ JSON `mcpServers` agent 接入面(Cursor / Windsurf) ============================
//
// Cursor(`~/.cursor/mcp.json`)与 Windsurf(`~/.codeium/windsurf/mcp_config.json`)的 MCP 配置**形态与
// Claude user scope 完全一致**:专用 JSON 文件、顶层 `mcpServers` 对象、条目 `command`/`args`/`env`、
// 远程用 `url`(Windsurf 另用 `serverUrl`,已并入 `classify_one` 远程检测)。故**直接复用 Claude 路径的
// read/classify/wrap/unwrap/atomic-write 机制**,仅 config 路径与 server-id 前缀不同;无 `projects.*` 嵌套
// (那是 Claude 专有),只处理顶层 scope。server-id 用 `<prefix>-<name>`(`cursor-`/`windsurf-`,与
// `user-`/`local-`/`codex-` 命名空间不相交)。
//
// **范围**:Cursor + Windsurf —— 均为专用、安全可重写文件、零形态差异。Cline(globalStorage 路径随
// VS Code 版本/fork 漂移 + 有删配置数据丢失史)、Zed(`context_servers` 键且嵌入共享 settings.json/JSONC)、
// VS Code(`servers` 键 + 显式 `type`)形态/风险不同,留后续专门增量。

/// 一个"JSON `mcpServers` 形态"的 agent 接入面描述符(Cursor / Windsurf)。
#[derive(Debug, Clone)]
pub struct JsonMcpAgent {
    /// 人类可读名(报告/预览用)。
    pub display_name: &'static str,
    /// 配置文件绝对路径(已注入 home → 测试可指向 fixture,绝不碰真实用户配置)。
    pub config_path: PathBuf,
    /// server-id 前缀(`cursor` / `windsurf`)。
    pub id_prefix: &'static str,
}

impl JsonMcpAgent {
    /// Cursor:`~/.cursor/mcp.json`(user scope;项目级 `<repo>/.cursor/mcp.json` 是独立提交文件,不碰)。
    pub fn cursor(home: &Path) -> Self {
        JsonMcpAgent {
            display_name: "Cursor",
            config_path: home.join(".cursor").join("mcp.json"),
            id_prefix: "cursor",
        }
    }
    /// Windsurf:`~/.codeium/windsurf/mcp_config.json`(唯一 scope —— Windsurf 无项目级 MCP 配置)。
    pub fn windsurf(home: &Path) -> Self {
        JsonMcpAgent {
            display_name: "Windsurf",
            config_path: home
                .join(".codeium")
                .join("windsurf")
                .join("mcp_config.json"),
            id_prefix: "windsurf",
        }
    }
    /// 派生 server-id:`<prefix>-<name>`(与 `user-`/`local-`/`codex-` 命名空间不相交)。
    /// `name` 已由 [`classify_one`] 用真验证器过滤,前缀全在 `^[a-z0-9_-]+$` 字符集内,拼接后必合法。
    fn server_id(&self, name: &str) -> String {
        format!("{}-{}", self.id_prefix, name)
    }
}

/// JSON-agent 接入面的只读预览报告。
#[derive(Debug, Clone)]
pub struct JsonAgentPreviewReport {
    /// 人类可读 agent 名。
    pub display_name: &'static str,
    /// 配置文件路径。
    pub config_path: PathBuf,
    /// 文件是否存在(不存在 = 用户未用该 agent,诚实标记)。
    pub exists: bool,
    /// 本进程 exe(预览 wrap argv 用)。
    pub exe: String,
    /// 顶层 `mcpServers` 逐条目分类。
    pub servers: Vec<McpServerClass>,
    /// 将落盘的姿态(`monitor` / `--enforce`)。
    pub monitor: bool,
    /// server-id 前缀(预览渲染 wrap argv 用)。
    pub id_prefix: &'static str,
}

impl JsonAgentPreviewReport {
    /// 可被保护(Wrappable)的 server 数。
    pub fn wrappable_count(&self) -> usize {
        self.servers
            .iter()
            .filter(|s| matches!(s, McpServerClass::Wrappable { .. }))
            .count()
    }
}

/// JSON-agent 接入面 apply/uninstall 的结果报告。
#[derive(Debug, Clone)]
pub struct JsonAgentApplyReport {
    /// 人类可读 agent 名。
    pub display_name: &'static str,
    /// 配置文件路径。
    pub config_path: PathBuf,
    /// 实际(或 dry-run 将)改写 / 还原的 server 数。
    pub changed: usize,
    /// 仅预览不写盘。
    pub dry_run: bool,
    /// 写盘时产生的备份路径(若有)。
    pub backup: Option<PathBuf>,
}

/// 读真实配置(IO 边界)→ 枚举 + 分类,产出只读预览。**不写**。home/exe 注入 → 测试走 fixture。
pub fn run_json_agent_preview(
    agent: &JsonMcpAgent,
    exe: &str,
    monitor: bool,
) -> Result<JsonAgentPreviewReport, SetupError> {
    let cfg = read_claude_json(&agent.config_path)?;
    let (exists, servers) = match cfg {
        Some(v) => (true, classify_user_scope_servers(&v)),
        None => (false, Vec::new()),
    };
    Ok(JsonAgentPreviewReport {
        display_name: agent.display_name,
        config_path: agent.config_path.clone(),
        exists,
        exe: exe.to_string(),
        servers,
        monitor,
        id_prefix: agent.id_prefix,
    })
}

/// `setup --mcp --apply`(JSON-agent):读 → wrap 顶层 `mcpServers` → 原子写。`dry_run` 只算不写。
/// 复用 Claude 路径的 [`wrap_servers_object`](仅 server-id 派生器换成 `<prefix>-<name>`)。
pub fn run_json_agent_apply(
    agent: &JsonMcpAgent,
    exe: &str,
    dry_run: bool,
    monitor: bool,
) -> Result<JsonAgentApplyReport, SetupError> {
    let cfg = match read_claude_json(&agent.config_path)? {
        Some(v) => v,
        None => {
            return Ok(JsonAgentApplyReport {
                display_name: agent.display_name,
                config_path: agent.config_path.clone(),
                changed: 0,
                dry_run,
                backup: None,
            })
        }
    };
    let stamp = std::fs::metadata(&agent.config_path)
        .ok()
        .and_then(|m| m.modified().ok().map(|t| (t, m.len())));
    let mut new_cfg = cfg.clone();
    let changed = new_cfg
        .get_mut("mcpServers")
        .and_then(Value::as_object_mut)
        .map(|servers| wrap_servers_object(servers, exe, monitor, |n| agent.server_id(n)))
        .unwrap_or(0);
    let backup = if !dry_run && changed > 0 {
        crate::setup::atomic_write_with_backup(&agent.config_path, &new_cfg, stamp)?
    } else {
        None
    };
    Ok(JsonAgentApplyReport {
        display_name: agent.display_name,
        config_path: agent.config_path.clone(),
        changed,
        dry_run,
        backup,
    })
}

/// `setup --mcp --uninstall`(JSON-agent):读 → 还原顶层 `mcpServers` 全部 Vigil 托管条目 → 原子写。
/// 复用 Claude 路径的 [`unwrap_servers_object`](self-describing 反解 SSOT)。
pub fn run_json_agent_uninstall(
    agent: &JsonMcpAgent,
    dry_run: bool,
) -> Result<JsonAgentApplyReport, SetupError> {
    let cfg = match read_claude_json(&agent.config_path)? {
        Some(v) => v,
        None => {
            return Ok(JsonAgentApplyReport {
                display_name: agent.display_name,
                config_path: agent.config_path.clone(),
                changed: 0,
                dry_run,
                backup: None,
            })
        }
    };
    let stamp = std::fs::metadata(&agent.config_path)
        .ok()
        .and_then(|m| m.modified().ok().map(|t| (t, m.len())));
    let mut new_cfg = cfg.clone();
    let changed = new_cfg
        .get_mut("mcpServers")
        .and_then(Value::as_object_mut)
        .map(unwrap_servers_object)
        .unwrap_or(0);
    let backup = if !dry_run && changed > 0 {
        crate::setup::atomic_write_with_backup(&agent.config_path, &new_cfg, stamp)?
    } else {
        None
    };
    Ok(JsonAgentApplyReport {
        display_name: agent.display_name,
        config_path: agent.config_path.clone(),
        changed,
        dry_run,
        backup,
    })
}

// ============================ setup --mcp --doctor(健壮性预检) ============================
//
// **采用关键**:`setup --mcp --apply` 后,若某被包裹 server 的底层程序根本起不来(最常见 = 程序不在
// PATH / 没装,如 `npx` 没装 Node、`uvx` 没装 uv),agent 只见工具静默坏掉、无诊断 → 归咎 Vigil。
// doctor 对每个 MCP server **预检底层 stdio 程序能否被网关解析**(用网关同款 `resolve_program`,SSOT),
// 逐 server 给 ✓/✗ + 可操作原因。**纯静态**(不 spawn 真 server,无副作用/无延迟/无挂起风险);更深的
// spawn+handshake 健康检查留后续增量。

/// 单个 MCP server 的启动可行性诊断结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoctorStatus {
    /// 底层程序可在 PATH 解析 → 大概率可启动。`resolved` = 解析到的绝对路径(诊断用)。
    Launchable { program: String, resolved: String },
    /// 底层程序在 PATH 找不到 → 起不来(最常见、最可操作的失败;提示装对应运行时)。
    ProgramNotFound { program: String },
    /// 非本地 stdio 程序(remote/http MCP 或无 `command`)→ doctor 不适用,跳过。
    Skipped { reason: String },
    /// Vigil 托管条目但形态异常无法还原出底层程序(诚实标记,不静默忽略)。
    Malformed,
    /// 某 agent 的**整个配置文件**坏了:malformed(解析失败)**或** unreadable(存在但 IO/权限读不了)。
    /// 区别于"未配置"(无文件 → 无行):配置存在却查不了 = 该 agent 的 server **可能存在但对 doctor 不可见**,
    /// 故**计入失败**(非静默 skip),不让 doctor 谎称"全部正常"(Codex D29 #6/#8)。`reason` 区分两类成因。
    ConfigError { reason: String },
}

/// `--probe` 深度探测结果(真 spawn server + MCP `initialize` 握手)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// **底层 server** 真启动并在超时内完成合法 MCP `initialize` 握手。注:这只证明底层 server 能
    /// 起 + 说 MCP;对已 vigil-wrapped 条目,真实网关启动还会强制 descriptor drift gate(probe 刻意
    /// 不走),故 Initialized **不等同**"agent 一定见到工具"(Codex D18 R2)。
    Initialized,
    /// server 起来了但未完成握手(超时 / 不说 MCP / 协议不兼容)→ agent 会看不到它的工具。
    /// `reason` 已过 value-aware 脱敏 + `scrub_text`(上游错误可能含 secret 片段)。
    Failed {
        /// 脱敏后的失败原因(诊断用,不含明文 secret)。
        reason: String,
    },
}

/// `setup --mcp --doctor` 的单行结果。
#[derive(Debug, Clone)]
pub struct McpDoctorRow {
    /// server 名(agent 配置里的 key)。
    pub name: String,
    /// 作用域:`"user"`(顶层 mcpServers)或项目路径(local scope)。
    pub scope: String,
    /// 是否 Vigil 托管(已 wrap)。未托管的也检查(预告它若被 wrap 能否启动)。
    pub wrapped: bool,
    /// 静态诊断结论(PATH 可解析性)。
    pub status: DoctorStatus,
    /// `--probe` 深度探测结果;`None` = 未探测(默认静态档 / 静态判定就起不来 / Skipped/Malformed)。
    pub probe: Option<ProbeOutcome>,
}

/// 从一个 server 条目取**底层 stdio 程序**(供 doctor 解析)。纯函数(可单测,不碰 PATH/FS)。
/// 返回 `Ok((program, wrapped))`;`Err(DoctorStatus)` 表示无需解析(Skipped/Malformed)直接定论。
fn doctor_target_for(name: &str, entry: &Value) -> Result<(String, bool), DoctorStatus> {
    match classify_one(name, entry) {
        // 未托管的 stdio server:底层程序就是其 command。
        McpServerClass::Wrappable { command, .. } => Ok((command, false)),
        // 已 Vigil 包裹:self-describing 还原出 `-- <原 cmd>` 的原始程序再检查(检查的是**真正会被起的**程序,
        // 而非 vigil-hub 自身;否则 doctor 永远只在验 vigil-hub 可达,毫无意义)。
        McpServerClass::AlreadyWrapped { .. } => unwrap_entry(entry)
            .and_then(|v| v.get("command").and_then(Value::as_str).map(String::from))
            .map(|prog| (prog, true))
            .ok_or(DoctorStatus::Malformed),
        // remote/http/无 command:非本地程序,doctor 不适用。
        McpServerClass::Skipped { reason, .. } => Err(DoctorStatus::Skipped {
            reason: reason.to_string(),
        }),
    }
}

/// probe 失败原因的 **value-aware** 脱敏(Codex D18 R1 High 防御):probe 用用户真实 env **值**启动
/// server,失败原因(如 server 回的 malformed JSON 内嵌该值)可能带出 env 值,而这些值未必是硬指纹
/// 形态(`scrub_text` 抓不住)。先按**注入的精确 env 值**逐个子串替换(我们确知它们就是要遮的),再过
/// `scrub_text` 兜硬指纹。过度遮蔽(短值)只影响诊断可读性、不泄漏 —— 安全优先。
fn redact_probe_reason(raw: &str, env: &[(String, String)]) -> String {
    let mut s = raw.to_string();
    for (_, v) in env {
        if !v.is_empty() {
            s = s.replace(v.as_str(), "[REDACTED env-value]");
        }
    }
    vigil_redaction::scrub_text(&s)
}

/// 从一个条目的 `env` 对象抽 `(key, value)` 对(probe 真 spawn 时注入子进程,同真实运行)。
/// 非字符串值跳过。**仅 probe 内部用**;绝不进日志/审计(probe 失败 reason 走 `redact_probe_reason`)。
fn entry_env_pairs(entry: &Value) -> Vec<(String, String)> {
    entry
        .get("env")
        .and_then(Value::as_object)
        .map(|o| {
            o.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

/// probe 真 spawn 所需的 `(完整 argv, env 键值对)`。
type ProbeArgvEnv = (Vec<String>, Vec<(String, String)>);

/// 取**可 spawn 的完整 argv + env**(`--probe` 用,与真实启动该 server 一致)。
/// `Wrappable` = 原 `command` + `args`;`AlreadyWrapped` = `unwrap_entry` 还原原始 argv;
/// 两者 env 都从(还原后的)条目 `env` 取。`None` = Skipped/Malformed(不探测)。
fn doctor_probe_argv_env(name: &str, entry: &Value) -> Option<ProbeArgvEnv> {
    match classify_one(name, entry) {
        McpServerClass::Wrappable { command, args, .. } => {
            let mut argv = Vec::with_capacity(1 + args.len());
            argv.push(command);
            argv.extend(args);
            Some((argv, entry_env_pairs(entry)))
        }
        McpServerClass::AlreadyWrapped { .. } => {
            let inner = unwrap_entry(entry)?;
            let command = inner.get("command").and_then(Value::as_str)?.to_string();
            let args: Vec<String> = inner
                .get("args")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let mut argv = Vec::with_capacity(1 + args.len());
            argv.push(command);
            argv.extend(args);
            Some((argv, entry_env_pairs(&inner)))
        }
        McpServerClass::Skipped { .. } => None,
    }
}

/// 对一个条目产出 doctor 行:取底层程序 → 用网关同款 `resolve_program` 验 PATH 可解析。
/// `probe_timeout=Some(..)` 且静态判定 `Launchable` 时,**额外**真 spawn + MCP `initialize` 握手
/// (深度探测;`--probe`)。静态判定就起不来(`ProgramNotFound`)的不浪费一次 spawn。
fn doctor_row(
    name: &str,
    scope: &str,
    entry: &Value,
    probe_timeout: Option<Duration>,
) -> McpDoctorRow {
    let (status, wrapped) = match doctor_target_for(name, entry) {
        Ok((program, wrapped)) => {
            let st = match vigil_mcp::stdio::resolve_program(&program) {
                Ok(p) => DoctorStatus::Launchable {
                    program,
                    resolved: p.to_string_lossy().into_owned(),
                },
                // 任何解析失败(找不到 / 路径不存在)统一 ProgramNotFound —— 这是可操作信号(装运行时)。
                Err(_) => DoctorStatus::ProgramNotFound { program },
            };
            (st, wrapped)
        }
        Err(skip_or_malformed) => {
            let wrapped = matches!(skip_or_malformed, DoctorStatus::Malformed);
            (skip_or_malformed, wrapped)
        }
    };
    // 深度探测:仅当显式 --probe 且静态判定可启动时才真 spawn(side-effectful,见 probe_stdio_initialize)。
    let probe = match (probe_timeout, &status) {
        (Some(timeout), DoctorStatus::Launchable { .. }) => {
            doctor_probe_argv_env(name, entry).map(|(argv, env)| {
                // server_id 仅作 probe 进程的 reader 线程标签(不持久化/不入账本/不走 namespace 校验);
                // 用 name 即可。失败原因走 value-aware 脱敏(按注入的精确 env 值)+ scrub(Codex R1 High)。
                match vigil_mcp::stdio::probe_stdio_initialize(name, &argv, &env, timeout) {
                    Ok(()) => ProbeOutcome::Initialized,
                    Err(e) => ProbeOutcome::Failed {
                        reason: redact_probe_reason(&e.to_string(), &env),
                    },
                }
            })
        }
        _ => None,
    };
    McpDoctorRow {
        name: name.to_string(),
        scope: scope.to_string(),
        wrapped,
        status,
        probe,
    }
}

/// 某 agent 配置文件读失败时的诚实 doctor 行:不 abort 整个 doctor(其它 agent 仍要查)、不静默漏报、
/// 且**计入失败**(`ConfigError` 在 print 侧累加 failed → exit 1,不让 doctor 谎称"全部正常";Codex D29 #6)。
/// `reason` 按错误成因**区分** malformed(解析失败)与 unreadable(存在但 IO/权限读不了)(Codex D29 #8)。
/// `reason` 含路径,在 print 侧统一过 `scrub`(Codex D29 #5)。
fn config_error_doctor_row(agent_label: &str, path: &Path, err: &SetupError) -> McpDoctorRow {
    let reason = match err {
        SetupError::MalformedConfig { .. } => format!(
            "config could not be parsed ({}); fix it to health-check this agent",
            path.display()
        ),
        // Io / 其它:文件存在但读不了(权限等)—— 不是"未配置",server 可能存在却对 doctor 不可见。
        _ => format!(
            "config exists but could not be read ({}); fix permissions/IO to health-check this agent",
            path.display()
        ),
    };
    McpDoctorRow {
        name: "(config file)".to_string(),
        scope: agent_label.to_string(),
        wrapped: false,
        status: DoctorStatus::ConfigError { reason },
        probe: None,
    }
}

/// 把一个 JSON-`mcpServers` agent(Cursor/Windsurf)顶层 server 逐个产出 doctor 行,追加到 `rows`。
/// 配置不存在 → 无行(用户未用该 agent);读失败 → 一条 `ConfigError` 行(不 abort,计入失败)。`scope`=agent 名。
fn append_json_agent_doctor_rows(
    agent: &JsonMcpAgent,
    probe_timeout: Option<Duration>,
    rows: &mut Vec<McpDoctorRow>,
) {
    match read_claude_json(&agent.config_path) {
        Ok(Some(cfg)) => {
            if let Some(servers) = cfg.get("mcpServers").and_then(Value::as_object) {
                for (name, entry) in servers {
                    rows.push(doctor_row(name, agent.display_name, entry, probe_timeout));
                }
            }
        }
        Ok(None) => {}
        Err(e) => rows.push(config_error_doctor_row(
            agent.display_name,
            &agent.config_path,
            &e,
        )),
    }
}

/// Codex(TOML)doctor 行:每个 `mcp_servers` 条目桥接成 JSON(`item_to_json`)后复用 `doctor_row`。
fn append_codex_doctor_rows(
    home: &Path,
    probe_timeout: Option<Duration>,
    rows: &mut Vec<McpDoctorRow>,
) {
    let path = codex_config_path(home);
    match read_codex_config(&path) {
        Ok(Some(doc)) => {
            if let Some(servers) = codex_servers_table(&doc) {
                for (name, item) in servers.iter() {
                    rows.push(doctor_row(
                        name,
                        "Codex",
                        &item_to_json(item),
                        probe_timeout,
                    ));
                }
            }
        }
        Ok(None) => {}
        Err(e) => rows.push(config_error_doctor_row("Codex", &path, &e)),
    }
}

/// `setup --mcp --doctor`:对**所有** agent 接入面(Claude user+local / Codex / Cursor / Windsurf)的
/// 每个 MCP server 做启动预检 —— 兑现"turnkey wrap 之后,所有 agent 的 server 是否还能起"。
///
/// `probe_timeout`:
/// - `None`(默认 `--doctor`):**纯静态**(只验 `resolve_program` PATH 可解析,不 spawn,无副作用/无延迟)。
/// - `Some(timeout)`(`--doctor --probe`):对静态判定可启动者**额外**真 spawn + MCP `initialize` 握手,
///   逐 server 设 `timeout` 上界 —— 抓"程序在 PATH 但运行时起不来/不说 MCP"(D15 实证的 turnkey 头号
///   静默失败)。**有副作用**(真启动每个 server 进程片刻);每个 server 顺序探测。
///
/// `home` 注入 → 测试走 fixture 绝不碰真实配置。无任何配置 → 空 Vec(诚实:没东西可查)。
/// **错误契约**:Claude(`~/.claude.json`)malformed → abort(`?`,既有契约不变);其余 agent malformed →
/// 一条诚实 Skipped 行,不 abort(读-only 健康检查应能跨 agent 看全,不因一个坏配置全瞎)。
pub fn run_doctor(
    home: &Path,
    probe_timeout: Option<Duration>,
) -> Result<Vec<McpDoctorRow>, SetupError> {
    let mut rows = Vec::new();
    // Claude(~/.claude.json):user + local scope。malformed → abort(既有契约)。缺失 → 跳过(仍查其它 agent)。
    if let Some(cfg) = read_claude_json(&claude_json_path(home))? {
        if let Some(servers) = cfg.get("mcpServers").and_then(Value::as_object) {
            for (name, entry) in servers {
                rows.push(doctor_row(name, "user", entry, probe_timeout));
            }
        }
        if let Some(projects) = cfg.get("projects").and_then(Value::as_object) {
            for (proj_path, proj) in projects {
                if let Some(servers) = proj.get("mcpServers").and_then(Value::as_object) {
                    for (name, entry) in servers {
                        rows.push(doctor_row(name, proj_path, entry, probe_timeout));
                    }
                }
            }
        }
    }
    // 其余 agent 面(best-effort,各自独立文件):Codex(TOML)+ Cursor + Windsurf(JSON)。
    append_codex_doctor_rows(home, probe_timeout, &mut rows);
    for agent in [JsonMcpAgent::cursor(home), JsonMcpAgent::windsurf(home)] {
        append_json_agent_doctor_rows(&agent, probe_timeout, &mut rows);
    }
    Ok(rows)
}

// ============================ setup --all(统一接入:hook + MCP wrap 一条命令) ============================
//
// **采用关键**:全保护此前需两条命令 —— `setup`(hook,原生工具输入侧 secret 拦截)+ `setup --mcp --apply`
// (MCP 网关:脱敏 + 审计 + 审批 + descriptor pin)。与"download → 直接得到保护"相违(用户可能只跑一条、
// 漏掉 MCP 网关的脱敏/审计)。`--all` 一次完成两者。两者写**不同文件**(hook → `~/.claude/settings.json`;
// mcp → `~/.claude.json`),互不冲突、顺序无关、各自原子写 + 备份 + 可逆。

/// `run_all_with` 的失败结果 —— **区分两步**以便 CLI 诚实报告部分应用状态(Codex D13 review HIGH)。
#[derive(Debug)]
pub enum AllError {
    /// **第 1 步(hook)就失败** → 什么都没改(hook 用 abort-on-unexpected + 写盘前 gate,失败即未写)。
    Hook(SetupError),
    /// **hook 成功、第 2 步(MCP)失败** → hook **已应用**(可单独 `setup --uninstall` 撤销)。
    /// 携带 hook 报告供 CLI 把"[1/2] 已完成 + [2/2] 失败 + 如何撤销 hook"如实告知用户。
    McpAfterHook {
        /// 已成功应用的 hook 报告(`Box` 化:SetupReport 较大,避免 `Result` 的 Err 变体超阈值 = clippy
        /// `result_large_err`,也省得正常 Ok 路径背着大 Err)。
        hook: Box<crate::setup::SetupReport>,
        /// MCP 步的失败原因。
        source: SetupError,
    },
}

/// 统一接入编排(注入式 home/exe/ledger → 可测):hook + MCP wrap 一次完成。`uninstall` 撤销两者,
/// `dry_run` 预览两者,`monitor`/`user_scope_only` 透传给 MCP 侧。
///
/// **部分失败诚实**(Codex D13 review HIGH):hook 先做 —— hook 失败 → [`AllError::Hook`](什么都没改);
/// hook 成功后 MCP 失败 → [`AllError::McpAfterHook`](携 hook 报告,CLI 据此告知 hook 已应用 + 如何撤销),
/// **绝不**用裸 `?` 把"hook 已改"信息吞掉只报一句笼统失败。
pub fn run_all_with(
    home: &Path,
    exe: &Path,
    ledger: &Path,
    uninstall: bool,
    dry_run: bool,
    user_scope_only: bool,
    monitor: bool,
) -> Result<(crate::setup::SetupReport, McpApplyReport), AllError> {
    // 1) hook(settings.json):原生工具调用的输入侧裸 secret 拦截(`setup` 的既有逻辑,注入式复用)。
    let hook_args = crate::setup::SetupArgs {
        uninstall,
        status: false,
        dry_run,
        ledger: Some(ledger.to_path_buf()),
    };
    let hook_rep = crate::setup::run_with(&hook_args, home, exe, ledger).map_err(AllError::Hook)?;

    // 2) MCP wrap(.claude.json):把每个 stdio MCP server 套上 Vigil 网关(`setup --mcp` 的既有逻辑)。
    // 失败 → McpAfterHook(**移动** hook 报告进 error,无需 Clone):此时 hook 已应用,绝不假装"什么都没做"。
    let exe_str = exe.to_string_lossy().to_string();
    let mcp_res = if uninstall {
        run_uninstall(home, dry_run)
    } else {
        run_apply(home, &exe_str, dry_run, user_scope_only, monitor)
    };
    match mcp_res {
        Ok(mcp_rep) => Ok((hook_rep, mcp_rep)),
        // 分支互斥:此处把 hook_rep 移入 error;Ok 分支才在元组里用它,借用检查通过(无需 clone)。
        Err(source) => Err(AllError::McpAfterHook {
            hook: Box::new(hook_rep),
            source,
        }),
    }
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
    fn wrapped_argv_posture_and_env_key_only() {
        // 默认 monitor 姿态(turnkey:第三方 server 可用,仍守脱敏+审计+裸 secret 拦截硬地板)。
        let argv = wrapped_argv(
            "C:/Vigil/vigil-hub.exe",
            "filesystem",
            "npx",
            &["-y".into(), "/data".into()],
            &["FOO_TOKEN".into()],
            true, // monitor
        );
        // 形态:exe wrap --server-id filesystem --env-key FOO_TOKEN --monitor --vigil-managed-mcp -- npx -y /data
        assert_eq!(argv[0], "C:/Vigil/vigil-hub.exe");
        assert_eq!(argv[1], "wrap");
        assert_eq!(argv[2], "--server-id");
        assert_eq!(argv[3], "filesystem");
        assert!(argv.windows(2).any(|w| w == ["--env-key", "FOO_TOKEN"]));
        // monitor 默认:必含 --monitor(观察放行,turnkey 接入即可用)
        assert!(argv.iter().any(|a| a == "--monitor"));
        // sentinel + 分隔符 + 原 argv 逐字保留
        let sep = argv.iter().position(|a| a == "--").unwrap();
        assert_eq!(argv[sep - 1], VIGIL_MANAGED_MCP_MARKER);
        assert_eq!(&argv[sep + 1..], &["npx", "-y", "/data"]);
        // env 值绝不出现在 argv(只键名)
        assert!(!argv.iter().any(|a| a.contains("shh")));

        // 显式 enforce(`--enforce` 反推 monitor=false):default-deny 硬拦,绝不含 --monitor。
        let enforce_argv = wrapped_argv(
            "C:/Vigil/vigil-hub.exe",
            "filesystem",
            "npx",
            &["-y".into(), "/data".into()],
            &["FOO_TOKEN".into()],
            false, // enforce
        );
        assert!(!enforce_argv.iter().any(|a| a == "--monitor"));
        // env-key-only + 逐字保留在两种姿态下都成立(姿态切换不动这些不变量)
        assert!(enforce_argv
            .windows(2)
            .any(|w| w == ["--env-key", "FOO_TOKEN"]));
        let esep = enforce_argv.iter().position(|a| a == "--").unwrap();
        assert_eq!(&enforce_argv[esep + 1..], &["npx", "-y", "/data"]);
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

    #[test]
    fn invalid_server_name_skipped_not_wrapped() {
        // F3(Codex holistic MEDIUM):名含网关 server-id 不允许的字符(大写/空格/点/斜杠)→ Skip,
        // 否则 apply 成功但 wrap attach 在 validate_server_id 失败 = 坏配置。逐名核对真验证器口径。
        let cfg = json!({"mcpServers": {
            "Filesystem": {"command": "npx", "args": ["a"]},          // 大写
            "my server": {"command": "npx", "args": ["a"]},          // 空格
            "weather.api": {"command": "npx", "args": ["a"]},        // 点
            "a/b": {"command": "npx", "args": ["a"]},                // 斜杠
            "good-name_1": {"command": "npx", "args": ["a"]}         // 合法
        }});
        let c = classify_user_scope_servers(&cfg);
        let skipped = |n: &str| {
            c.iter()
                .any(|x| matches!(x, McpServerClass::Skipped { name, .. } if name == n))
        };
        for bad in ["Filesystem", "my server", "weather.api", "a/b"] {
            assert!(
                skipped(bad),
                "非法名 `{bad}` 须 Skipped(否则 wrap 启动失败)"
            );
        }
        // 合法名仍 Wrappable
        assert!(c
            .iter()
            .any(|x| matches!(x, McpServerClass::Wrappable { name, .. } if name == "good-name_1")));
        // 真验证器一致性:被 Skip 的名确实过不了 validate_server_id
        assert!(vigil_mcp::namespace::validate_server_id("Filesystem").is_err());
        assert!(vigil_mcp::namespace::validate_server_id("good-name_1").is_ok());
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
            true, // monitor:顺带验证 --monitor flag 不破坏 unwrap 的 sentinel 锚定还原
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
        let wrapped = wrap_entry(
            &original,
            "vigil-hub",
            "fs",
            "npx",
            &["x".into()],
            &[],
            true,
        );
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
            true, // monitor:--monitor + name="--" + args 含 "--" 三重压测 sentinel 锚定还原
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

        // apply(默认 monitor 姿态:turnkey 接入即可用)
        let rep = run_apply(home, "vigil-hub", false, false, true).unwrap();
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
        // monitor 默认必须经整条 apply 链(run_apply→apply_wrap_to_config→wrap_servers_object→
        // wrap_entry→wrapped_argv)真落到磁盘 argv —— 守"turnkey 默认 monitor"不被中间层吃掉。
        assert!(
            after["mcpServers"]["fs"]["args"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a == "--monitor"),
            "默认 monitor 姿态必须写入 wrap argv"
        );
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
        let rep = run_apply(home, "vigil-hub", false, false, true).unwrap();
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
        // user scope 的 fs 用 user- 前缀(与 local- 命名空间不相交)
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
            "user scope 用 user- 前缀 id"
        );

        // uninstall 还原**两个** scope(self-describing,与 id 无关)
        let rep_u = run_uninstall(home, false).unwrap();
        assert_eq!(rep_u.changed, 1);
        assert_eq!(rep_u.local_changed, 1, "local scope 也被还原");
        let restored: Value = serde_json::from_str(&fs::read_to_string(&claude).unwrap()).unwrap();
        assert_eq!(restored, initial, "往返后与初始**逐字**一致");

        // --user-scope-only:只 wrap user,跳过 local,诚实报告 local_skipped
        fs::write(&claude, initial.to_string()).unwrap();
        let rep2 = run_apply(home, "vigil-hub", false, true, true).unwrap();
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
    fn apply_enforce_posture_omits_monitor_flag_end_to_end() {
        // `--enforce`(monitor=false)经整条 apply 链落盘后,wrap argv **绝不**含 --monitor →
        // 网关进 enforce(default-deny 硬拦)。与默认 monitor 路径对照,守姿态开关真正生效到磁盘。
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let claude = home.join(".claude.json");
        fs::write(
            &claude,
            json!({"mcpServers": {"fs": {"command": "npx", "args": ["-y", "pkg"]}}}).to_string(),
        )
        .unwrap();

        let rep = run_apply(home, "vigil-hub", false, false, false).unwrap(); // monitor=false=enforce
        assert_eq!(rep.changed, 1);
        let after: Value = serde_json::from_str(&fs::read_to_string(&claude).unwrap()).unwrap();
        let args = after["mcpServers"]["fs"]["args"].as_array().unwrap();
        // enforce:wrap 仍生效(--vigil-managed-mcp 在),但绝无 --monitor(default-deny 硬拦)
        assert!(
            args.iter().any(|a| a == "--vigil-managed-mcp"),
            "wrap 仍生效"
        );
        assert!(
            !args.iter().any(|a| a == "--monitor"),
            "enforce 姿态绝不含 --monitor(否则降级为观察放行)"
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

    // ---------------- setup --mcp --doctor ----------------

    #[test]
    fn doctor_target_extracts_underlying_program_across_kinds() {
        // 未托管 stdio → 底层程序 = command,wrapped=false
        let wrappable = json!({"command": "npx", "args": ["-y", "pkg"]});
        assert_eq!(
            doctor_target_for("fs", &wrappable),
            Ok(("npx".to_string(), false))
        );

        // 已 Vigil 包裹 → unwrap 取**内部**真实程序(uvx,而非 vigil-hub),wrapped=true
        let wrapped = wrap_entry(
            &json!({"command": "uvx", "args": ["x"]}),
            "vigil-hub",
            "git",
            "uvx",
            &["x".into()],
            &[],
            true,
        );
        assert_eq!(
            doctor_target_for("git", &wrapped),
            Ok(("uvx".to_string(), true)),
            "doctor 检查的必须是被包裹的真实程序,不是 vigil-hub 自身"
        );

        // remote/http → Err(Skipped),不当本地程序解析
        let remote = json!({"url": "https://mcp.example.com/"});
        assert!(matches!(
            doctor_target_for("remote", &remote),
            Err(DoctorStatus::Skipped { .. })
        ));
    }

    #[test]
    fn run_doctor_flags_missing_program_passes_resolvable_skips_remote() {
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        // path-style 的真实存在文件 → resolve_program canonicalize 成功 → Launchable(跨平台确定性)。
        let real = home.join("realprog");
        fs::write(&real, b"x").unwrap();
        let real_str = real.to_string_lossy().to_string();
        fs::write(
            home.join(".claude.json"),
            json!({
                "mcpServers": {
                    "good": {"command": real_str, "args": []},
                    "bad": {"command": "definitely-not-a-real-prog-xyz789", "args": []},
                    "remote": {"url": "https://mcp.example.com/"}
                }
            })
            .to_string(),
        )
        .unwrap();

        let rows = run_doctor(home, None).unwrap();
        let by = |n: &str| &rows.iter().find(|r| r.name == n).unwrap().status;
        assert!(
            matches!(by("good"), DoctorStatus::Launchable { .. }),
            "存在的程序应 Launchable"
        );
        assert!(
            matches!(by("bad"), DoctorStatus::ProgramNotFound { .. }),
            "PATH 找不到的程序应 ProgramNotFound(最常见可操作失败)"
        );
        assert!(
            matches!(by("remote"), DoctorStatus::Skipped { .. }),
            "remote/http server 应 Skipped"
        );
    }

    #[test]
    fn run_doctor_checks_already_wrapped_inner_program() {
        // 已包裹的 server:doctor 必须 unwrap 后检查内部程序(bogus → ProgramNotFound),
        // 证明 doctor 看穿 wrap 看真实程序,且 wrapped 标记为 true。
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let wrapped = wrap_entry(
            &json!({"command": "definitely-not-a-real-prog-xyz789", "args": ["x"]}),
            "vigil-hub",
            "fs",
            "definitely-not-a-real-prog-xyz789",
            &["x".into()],
            &[],
            true,
        );
        fs::write(
            home.join(".claude.json"),
            json!({ "mcpServers": { "fs": wrapped } }).to_string(),
        )
        .unwrap();
        let rows = run_doctor(home, None).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].wrapped, "应识别为 Vigil 托管");
        assert!(
            matches!(rows[0].status, DoctorStatus::ProgramNotFound { .. }),
            "应检查 unwrap 出的内部程序(bogus → ProgramNotFound)"
        );
    }

    #[test]
    fn run_doctor_empty_when_no_config() {
        let dir = tempfile::tempdir().unwrap();
        assert!(run_doctor(dir.path(), None).unwrap().is_empty());
    }

    // ──────────────── D18 --probe:可 spawn argv+env 提取(纯函数,无 spawn) ────────────────
    #[test]
    fn doctor_probe_argv_env_wrappable_extracts_full_argv_and_string_env() {
        let entry = json!({
            "command": "node",
            "args": ["server.js", "--flag"],
            "env": { "API_TOKEN": "ghp_secret", "PORT": 8080, "MODE": "prod" }
        });
        let (argv, env) = doctor_probe_argv_env("srv", &entry).expect("wrappable → Some");
        assert_eq!(
            argv,
            vec!["node", "server.js", "--flag"],
            "完整 argv = command + args"
        );
        // env:仅字符串值入对(PORT=8080 非字符串被跳过);键序按 serde_json 对象迭代。
        let mut keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["API_TOKEN", "MODE"], "非字符串 env 值跳过");
        assert!(
            env.iter()
                .any(|(k, v)| k == "API_TOKEN" && v == "ghp_secret"),
            "字符串 env 值逐字保留(供真 spawn,同真实运行)"
        );
    }

    #[test]
    fn doctor_probe_argv_env_already_wrapped_unwraps_inner() {
        // 已包裹 server:probe 必须 spawn **内部真实程序**(unwrap 还原),而非 vigil-hub。
        let wrapped = wrap_entry(
            &json!({"command": "uvx", "args": ["mcp-server-git"], "env": {"GIT_TOKEN": "t0ken"}}),
            "vigil-hub",
            "git",
            "uvx",
            &["mcp-server-git".into()],
            &[],
            true,
        );
        let (argv, env) = doctor_probe_argv_env("git", &wrapped).expect("already-wrapped → Some");
        assert_eq!(
            argv,
            vec!["uvx", "mcp-server-git"],
            "应还原内部 argv,而非 vigil-hub wrap"
        );
        assert!(
            env.iter().any(|(k, v)| k == "GIT_TOKEN" && v == "t0ken"),
            "wrap 保留的原 env 仍可被 probe 取到"
        );
    }

    #[test]
    fn doctor_probe_argv_env_skipped_returns_none() {
        let http = json!({ "type": "http", "url": "https://mcp.example.com/" });
        assert!(
            doctor_probe_argv_env("remote", &http).is_none(),
            "remote/http 无底层 stdio 程序 → 不探测"
        );
    }

    #[test]
    fn entry_env_pairs_skips_non_string_and_handles_missing() {
        assert!(
            entry_env_pairs(&json!({"command": "x"})).is_empty(),
            "无 env → 空"
        );
        let pairs = entry_env_pairs(&json!({"env": {"A": "1", "B": true, "C": "3"}}));
        let mut keys: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["A", "C"], "非字符串值跳过");
    }

    #[test]
    fn redact_probe_reason_value_aware_redacts_injected_env_secret() {
        // Codex D18 R1 High:server 在失败诊断里回显注入的 env **值**(非硬指纹形态,scrub 抓不住),
        // 必须按精确值遮蔽。这里的 secret 是任意非指纹字符串,scrub_text 单独不会动它。
        let secret = "correct-horse-battery-staple-not-a-fingerprint";
        let env = vec![("MY_SECRET".to_string(), secret.to_string())];
        let raw = format!("upstream said: failed to auth with {secret} during init");
        let out = redact_probe_reason(&raw, &env);
        assert!(!out.contains(secret), "注入的 env 值必须被遮蔽:{out}");
        assert!(out.contains("[REDACTED env-value]"), "应有遮蔽占位:{out}");
        // 空 env 值不参与替换;硬指纹仍由 scrub 兜底。
        let env2 = vec![("EMPTY".to_string(), String::new())];
        let gh = "ghp_aBcD1234567890aBcD1234567890aBcD1234";
        let out2 = redact_probe_reason(&format!("leaked {gh}"), &env2);
        assert!(!out2.contains(gh), "硬指纹仍由 scrub 兜底:{out2}");
    }

    // ---------------- setup --all(统一接入)----------------

    #[test]
    fn run_all_installs_then_uninstalls_both_hook_and_mcp() {
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let exe = home.join("vigil-hub");
        fs::write(&exe, b"x").unwrap(); // hook state 计算要求 exe 存在
        let ledger = home.join("ledger.sqlite3");
        // Claude Code 被检测到的前提:`~/.claude/` 存在(hook 注册条件)。
        fs::create_dir_all(home.join(".claude")).unwrap();
        // MCP 配置:一个可 wrap 的 stdio server。
        let initial = json!({"mcpServers": {"fs": {"command": "npx", "args": ["x"]}}});
        let claude_json = home.join(".claude.json");
        fs::write(&claude_json, initial.to_string()).unwrap();

        // --all 安装:hook + mcp 一次完成。
        let (hook_rep, mcp_rep) =
            run_all_with(home, &exe, &ledger, false, false, false, true).unwrap();
        assert!(hook_rep.changed, "hook 应写入 settings.json");
        assert_eq!(mcp_rep.changed, 1, "user-scope MCP server 应被 wrap");

        // hook 真落 settings.json(含 Vigil 托管 sentinel)。
        let settings: Value = serde_json::from_str(
            &fs::read_to_string(home.join(".claude").join("settings.json")).unwrap(),
        )
        .unwrap();
        assert!(
            settings.to_string().contains("vigil-managed"),
            "settings.json 应含 Vigil 托管 hook"
        );
        // mcp server 真被改写(command 变 wrap exe + 带 sentinel)。
        let claude: Value =
            serde_json::from_str(&fs::read_to_string(&claude_json).unwrap()).unwrap();
        let fs_args = claude["mcpServers"]["fs"]["args"].as_array().unwrap();
        assert!(
            fs_args.iter().any(|a| a == "--vigil-managed-mcp"),
            "MCP server 应被 wrap(带 sentinel)"
        );

        // --all 卸载:两者都被撤销。
        let (hook_rep2, mcp_rep2) =
            run_all_with(home, &exe, &ledger, true, false, false, true).unwrap();
        assert!(hook_rep2.changed, "hook 应被移除");
        assert_eq!(mcp_rep2.changed, 1, "mcp wrap 应被还原");
        // .claude.json 逐字还原回初始(self-describing unwrap)。
        let restored: Value =
            serde_json::from_str(&fs::read_to_string(&claude_json).unwrap()).unwrap();
        assert_eq!(restored, initial, "uninstall 后 MCP 配置与初始一致");
    }

    #[test]
    fn run_all_dry_run_writes_nothing() {
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let exe = home.join("vigil-hub");
        fs::write(&exe, b"x").unwrap();
        let ledger = home.join("ledger.sqlite3");
        fs::create_dir_all(home.join(".claude")).unwrap();
        let initial = json!({"mcpServers": {"fs": {"command": "npx", "args": ["x"]}}});
        let claude_json = home.join(".claude.json");
        fs::write(&claude_json, initial.to_string()).unwrap();

        let (hook_rep, _mcp_rep) =
            run_all_with(home, &exe, &ledger, false, true, false, true).unwrap();
        assert!(hook_rep.dry_run, "dry_run 应透传");
        // settings.json 不应被创建,.claude.json 不应被改。
        assert!(
            !home.join(".claude").join("settings.json").exists(),
            "dry-run 不得写 settings.json"
        );
        let after: Value =
            serde_json::from_str(&fs::read_to_string(&claude_json).unwrap()).unwrap();
        assert_eq!(after, initial, "dry-run 不得改 .claude.json");
    }

    #[test]
    fn run_all_partial_failure_reports_hook_applied_when_mcp_step_fails() {
        // hook 成功、MCP 步失败 → AllError::McpAfterHook(携 hook 报告),绝不吞掉"hook 已应用"。
        // 构造:有效 ~/.claude/(hook 可写)+ **损坏** ~/.claude.json(run_apply 读它即 MalformedConfig)。
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let exe = home.join("vigil-hub");
        fs::write(&exe, b"x").unwrap();
        let ledger = home.join("ledger.sqlite3");
        fs::create_dir_all(home.join(".claude")).unwrap();
        // 损坏的 MCP 配置 → run_apply 的 read_claude_json 报 MalformedConfig。
        fs::write(home.join(".claude.json"), "{ this is not valid json").unwrap();

        let err =
            run_all_with(home, &exe, &ledger, false, false, false, true).expect_err("MCP 步应失败");
        match err {
            AllError::McpAfterHook { hook, source } => {
                assert!(hook.changed, "hook 步应已成功应用(半应用状态须如实携带)");
                assert!(
                    home.join(".claude").join("settings.json").exists(),
                    "hook 真写了 settings.json"
                );
                assert!(
                    matches!(source, SetupError::MalformedConfig { .. }),
                    "MCP 失败原因应为 MalformedConfig,得到 {source:?}"
                );
            }
            AllError::Hook(e) => {
                panic!("hook 不该失败(它读的是 settings.json 非 .claude.json):{e:?}")
            }
        }
    }

    #[test]
    fn run_all_uninstall_partial_failure_reports_hook_removed_when_mcp_step_fails() {
        // 镜像:先正常 install 两者,再损坏 .claude.json,再 uninstall → hook 移除成功、MCP 步失败
        // → McpAfterHook(hook.changed=true 表已移除)。锁定 uninstall-partial 状态与恢复路径(Codex D13 R2)。
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let exe = home.join("vigil-hub");
        fs::write(&exe, b"x").unwrap();
        let ledger = home.join("ledger.sqlite3");
        fs::create_dir_all(home.join(".claude")).unwrap();
        let claude_json = home.join(".claude.json");
        fs::write(
            &claude_json,
            json!({"mcpServers": {"fs": {"command": "npx", "args": ["x"]}}}).to_string(),
        )
        .unwrap();

        // 正常 install 两者(hook 写入 settings.json + mcp wrap)。
        run_all_with(home, &exe, &ledger, false, false, false, true).unwrap();
        assert!(home.join(".claude").join("settings.json").exists());

        // 损坏 .claude.json → 随后 uninstall 的 MCP 步(read_claude_json)失败。
        fs::write(&claude_json, "}{ broken").unwrap();

        let err =
            run_all_with(home, &exe, &ledger, true, false, false, true).expect_err("MCP 步应失败");
        match err {
            AllError::McpAfterHook { hook, source } => {
                assert!(hook.changed, "hook 已被移除(uninstall 改了 settings.json)");
                assert!(
                    matches!(source, SetupError::MalformedConfig { .. }),
                    "MCP uninstall 失败原因应为 MalformedConfig,得到 {source:?}"
                );
            }
            AllError::Hook(e) => panic!("hook uninstall 不该失败:{e:?}"),
        }
    }

    // ============================ Codex 接入面(`~/.codex/config.toml`)============================

    /// Codex TOML `[mcp_servers.*]` 分类:stdio→Wrappable(env 只键名)/ remote(url)→Skipped /
    /// sentinel→AlreadyWrapped。复用同一 `classify_one`,与 Claude 路径同护栏(桥接经 `item_to_json`)。
    #[test]
    fn codex_classifies_toml_servers() {
        let src = r#"
model = "gpt-5"

[mcp_servers.filesystem]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
[mcp_servers.filesystem.env]
FOO_TOKEN = "shh"
BAR = "x"

[mcp_servers.remote]
url = "https://mcp.example.com/"

[mcp_servers.already]
command = "vigil-hub"
args = ["wrap", "--server-id", "codex-already", "--vigil-managed-mcp", "--", "npx", "x"]
"#;
        let doc = src.parse::<DocumentMut>().unwrap();
        let classes = classify_codex_servers(&doc);
        assert_eq!(classes.len(), 3);

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
            assert!(env_keys.contains(&"FOO_TOKEN".to_string()));
            // env 只键名,绝无值 "shh"
            assert!(!env_keys.iter().any(|k| k.contains("shh")));
        }
        assert!(classes
            .iter()
            .any(|c| matches!(c, McpServerClass::Skipped { name, .. } if name == "remote")));
        assert!(classes
            .iter()
            .any(|c| matches!(c, McpServerClass::AlreadyWrapped { name } if name == "already")));
    }

    /// server-id 命名空间:`codex-<name>` 与 `user-`/`local-` 不相交,且仍是合法网关 id。
    #[test]
    fn codex_server_id_is_namespace_disjoint() {
        let id = codex_scope_server_id("filesystem");
        assert_eq!(id, "codex-filesystem");
        assert_ne!(id, user_scope_server_id("filesystem"));
        assert!(!id.starts_with("user-"));
        assert!(!id.starts_with("local-"));
        assert!(vigil_mcp::namespace::validate_server_id(&id).is_ok());
    }

    /// **功能测试**:tempfile 真 `~/.codex/config.toml` apply → 验证 wrap + 格式保留 → uninstall →
    /// 逐字还原(绝不碰真实用户配置)。
    #[test]
    fn codex_apply_uninstall_round_trip_on_tempfile() {
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        fs::create_dir_all(home.join(".codex")).unwrap();
        let cfg = home.join(".codex").join("config.toml");
        let original =
            "# user comment kept\nmodel = \"gpt-5\"\napproval_policy = \"on-request\"\n\n\
                        [mcp_servers.filesystem]\ncommand = \"npx\"\n\
                        args = [\"-y\", \"@modelcontextprotocol/server-filesystem\", \"/data\"]\n\n\
                        [mcp_servers.filesystem.env]\nFOO_TOKEN = \"shh\"\n";
        fs::write(&cfg, original).unwrap();

        // apply(monitor 姿态)
        let rep = run_codex_apply(home, "vigil-hub", false, true).unwrap();
        assert_eq!(rep.changed, 1);
        assert!(rep.backup.is_some(), "写盘应留备份");
        let wrapped = fs::read_to_string(&cfg).unwrap();
        // 格式保留:注释 + 其它配置段存活(外科手术式改写,非整篇重排)
        assert!(wrapped.contains("# user comment kept"));
        assert!(wrapped.contains("model = \"gpt-5\""));
        assert!(wrapped.contains("approval_policy"));

        let doc = wrapped.parse::<DocumentMut>().unwrap();
        // 已成 Vigil 托管(幂等检测能命中)
        assert!(classify_codex_servers(&doc)
            .iter()
            .any(|c| matches!(c, McpServerClass::AlreadyWrapped { name } if name == "filesystem")));
        // env 值仍在条目里(wrap 不动 env),但 secret 值**绝不**出现在 wrap argv(只 --env-key 键名)
        assert!(wrapped.contains("FOO_TOKEN"));
        let fargs: Vec<String> = doc["mcp_servers"]["filesystem"]["args"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        assert!(
            !fargs.iter().any(|a| a.contains("shh")),
            "secret 值绝不进 argv"
        );
        assert!(fargs.iter().any(|a| a == "--env-key"));
        // server-id 用 codex- 前缀
        assert!(fargs.iter().any(|a| a == "codex-filesystem"));

        // uninstall → 逐字还原
        let rep2 = run_codex_uninstall(home, false).unwrap();
        assert_eq!(rep2.changed, 1);
        let restored = fs::read_to_string(&cfg).unwrap();
        let rdoc = restored.parse::<DocumentMut>().unwrap();
        assert_eq!(
            rdoc["mcp_servers"]["filesystem"]["command"].as_str(),
            Some("npx")
        );
        let rargs: Vec<String> = rdoc["mcp_servers"]["filesystem"]["args"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        assert_eq!(
            rargs,
            vec!["-y", "@modelcontextprotocol/server-filesystem", "/data"]
        );
        assert!(restored.contains("# user comment kept"), "还原后注释仍在");
    }

    /// 幂等:apply 两次 → 第二次 0 改写(AlreadyWrapped 跳过,绝不双重 wrap)。
    #[test]
    fn codex_apply_is_idempotent() {
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        fs::create_dir_all(home.join(".codex")).unwrap();
        let cfg = home.join(".codex").join("config.toml");
        fs::write(
            &cfg,
            "[mcp_servers.fs]\ncommand = \"npx\"\nargs = [\"x\"]\n",
        )
        .unwrap();

        assert_eq!(
            run_codex_apply(home, "vigil-hub", false, true)
                .unwrap()
                .changed,
            1
        );
        assert_eq!(
            run_codex_apply(home, "vigil-hub", false, true)
                .unwrap()
                .changed,
            0,
            "已 wrap 条目第二次 apply 必跳过"
        );
    }

    /// 损坏 TOML → `MalformedConfig`,且**原文件未被改写**(fail-safe,绝不臆测覆盖)。
    #[test]
    fn codex_malformed_aborts_without_touching_file() {
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        fs::create_dir_all(home.join(".codex")).unwrap();
        let cfg = home.join(".codex").join("config.toml");
        fs::write(&cfg, "this is ]not[ valid toml =").unwrap();
        let before = fs::read_to_string(&cfg).unwrap();

        assert!(matches!(
            run_codex_apply(home, "vigil-hub", false, true),
            Err(SetupError::MalformedConfig { .. })
        ));
        assert_eq!(
            fs::read_to_string(&cfg).unwrap(),
            before,
            "损坏配置绝不被覆盖"
        );
    }

    /// 无 `~/.codex/config.toml` → 0 改写、无错、无备份(用户未用 Codex)。
    #[test]
    fn codex_no_config_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let rep = run_codex_apply(home, "vigil-hub", false, true).unwrap();
        assert_eq!(rep.changed, 0);
        assert!(rep.backup.is_none());
        assert!(!run_codex_preview(home, "vigil-hub", true).unwrap().exists);
    }

    /// 非法 server 名(含大写 / 点)→ Skipped(不产出一个起不来的网关条目)。
    #[test]
    fn codex_invalid_server_name_skipped() {
        let doc = "[mcp_servers.\"Bad.Name\"]\ncommand = \"npx\"\nargs = [\"x\"]\n"
            .parse::<DocumentMut>()
            .unwrap();
        let classes = classify_codex_servers(&doc);
        assert_eq!(classes.len(), 1);
        assert!(matches!(&classes[0], McpServerClass::Skipped { name, .. } if name == "Bad.Name"));
    }

    /// 内联表条目形态(`[mcp_servers]` 表内 `foo = { command=.., args=.. }`)也能 wrap/unwrap 往返,
    /// 不 panic(`as_table_like_mut` 覆盖 InlineTable)。
    #[test]
    fn codex_inline_table_entry_round_trips() {
        let mut doc = "[mcp_servers]\nfoo = { command = \"npx\", args = [\"-y\", \"pkg\"] }\n"
            .parse::<DocumentMut>()
            .unwrap();
        assert_eq!(apply_wrap_to_codex(&mut doc, "vigil-hub", true), 1);
        assert!(classify_codex_servers(&doc)
            .iter()
            .any(|c| matches!(c, McpServerClass::AlreadyWrapped { name } if name == "foo")));
        assert_eq!(apply_unwrap_codex(&mut doc), 1);
        let rdoc = doc.to_string().parse::<DocumentMut>().unwrap();
        assert_eq!(rdoc["mcp_servers"]["foo"]["command"].as_str(), Some("npx"));
        let rargs: Vec<String> = rdoc["mcp_servers"]["foo"]["args"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        assert_eq!(rargs, vec!["-y", "pkg"]);
    }

    /// 安全(Codex review #3):用户手改在 wrap 尾部注入**非字符串** arg → uninstall **拒绝 lossy 还原**
    /// (跳过该条目、数据不丢),而非 `filter_map` 静默丢弃。正常 Vigil 产出的 wrap 必然全字符串,故此
    /// 路径只对手改的非常规条目生效。
    #[test]
    fn codex_uninstall_refuses_lossy_nonstring_args() {
        // 看似 Vigil 托管(sentinel + wrap + vigil-hub 命中),但 args 尾被手改注入整数 123。
        let src = "[mcp_servers.foo]\ncommand = \"vigil-hub\"\n\
                   args = [\"wrap\", \"--server-id\", \"codex-foo\", \"--vigil-managed-mcp\", \"--\", \"npx\", 123]\n";
        let mut doc = src.parse::<DocumentMut>().unwrap();
        assert!(classify_codex_servers(&doc)
            .iter()
            .any(|c| matches!(c, McpServerClass::AlreadyWrapped { name } if name == "foo")));
        // 含非字符串 arg → 跳过(0 还原),原条目逐字保留(123 不被丢弃)。
        assert_eq!(apply_unwrap_codex(&mut doc), 0);
        let after = doc.to_string();
        assert!(after.contains("123"), "非字符串 arg 必须仍在(不被静默丢弃)");
        assert!(
            after.contains("--vigil-managed-mcp"),
            "条目仍是原样 wrapped"
        );
    }

    // ============================ JSON agent 接入面(Cursor / Windsurf) ============================

    /// Cursor/Windsurf 配置路径正确(home 注入)。
    #[test]
    fn json_agent_config_paths() {
        let home = Path::new("/h");
        assert_eq!(
            JsonMcpAgent::cursor(home).config_path,
            Path::new("/h").join(".cursor").join("mcp.json")
        );
        assert_eq!(
            JsonMcpAgent::windsurf(home).config_path,
            Path::new("/h")
                .join(".codeium")
                .join("windsurf")
                .join("mcp_config.json")
        );
    }

    /// server-id 命名空间:`cursor-`/`windsurf-` 与 `user-`/`local-`/`codex-` 不相交,且合法网关 id。
    #[test]
    fn json_agent_server_id_namespace_disjoint() {
        let home = Path::new("/h");
        let cid = JsonMcpAgent::cursor(home).server_id("fs");
        let wid = JsonMcpAgent::windsurf(home).server_id("fs");
        assert_eq!(cid, "cursor-fs");
        assert_eq!(wid, "windsurf-fs");
        for id in [&cid, &wid] {
            assert!(!id.starts_with("user-"));
            assert!(!id.starts_with("local-"));
            assert!(!id.starts_with("codex-"));
            assert!(vigil_mcp::namespace::validate_server_id(id).is_ok());
        }
        assert_ne!(cid, wid);
    }

    /// Windsurf 远程条目用 `serverUrl`(非 `url`)→ 仍被 `classify_one` 判为远程 Skipped(不 wrap)。
    #[test]
    fn json_agent_windsurf_serverurl_remote_skipped() {
        let cfg = json!({
            "mcpServers": {
                "local": { "command": "npx", "args": ["x"] },
                "remote": { "serverUrl": "https://mcp.example.com/sse" }
            }
        });
        let classes = classify_user_scope_servers(&cfg);
        assert!(classes
            .iter()
            .any(|c| matches!(c, McpServerClass::Wrappable { name, .. } if name == "local")));
        assert!(
            classes
                .iter()
                .any(|c| matches!(c, McpServerClass::Skipped { name, .. } if name == "remote")),
            "serverUrl 远程条目必须被跳过(不当 stdio 误 wrap)"
        );
    }

    /// **功能测试**:tempfile 真 `~/.cursor/mcp.json` apply → 验证 wrap(cursor- id)→ uninstall →
    /// 逐字还原(绝不碰真实用户配置)。复用 Claude JSON 机制。
    #[test]
    fn json_agent_apply_uninstall_round_trip_on_tempfile() {
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let agent = JsonMcpAgent::cursor(home);
        fs::create_dir_all(home.join(".cursor")).unwrap();
        fs::write(
            &agent.config_path,
            json!({
                "mcpServers": {
                    "filesystem": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
                        "env": {"FS_TOKEN": "shh"}
                    },
                    "remote": {"url": "https://mcp.example.com/"}
                }
            })
            .to_string(),
        )
        .unwrap();

        // apply
        let rep = run_json_agent_apply(&agent, "vigil-hub", false, true).unwrap();
        assert_eq!(rep.changed, 1, "只 filesystem 被 wrap;remote(url)跳过");
        assert!(rep.backup.is_some());
        let after: Value =
            serde_json::from_str(&fs::read_to_string(&agent.config_path).unwrap()).unwrap();
        // server-id 用 cursor- 前缀;env 值绝不进 argv
        let fs_args = after["mcpServers"]["filesystem"]["args"]
            .as_array()
            .unwrap();
        let joined: String = fs_args
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(joined.contains("cursor-filesystem"));
        assert!(joined.contains("--env-key"));
        assert!(!joined.contains("shh"), "secret 值绝不进 wrap argv");
        // remote 原样不动
        assert!(after["mcpServers"]["remote"]["url"].is_string());

        // uninstall → 逐字还原
        let rep2 = run_json_agent_uninstall(&agent, false).unwrap();
        assert_eq!(rep2.changed, 1);
        let restored: Value =
            serde_json::from_str(&fs::read_to_string(&agent.config_path).unwrap()).unwrap();
        assert_eq!(
            restored["mcpServers"]["filesystem"]["command"].as_str(),
            Some("npx")
        );
        let rargs: Vec<String> = restored["mcpServers"]["filesystem"]["args"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        assert_eq!(
            rargs,
            vec!["-y", "@modelcontextprotocol/server-filesystem", "/data"]
        );
        // env 逐字保留(reversible 需要)
        assert_eq!(
            restored["mcpServers"]["filesystem"]["env"]["FS_TOKEN"].as_str(),
            Some("shh")
        );
    }

    /// 幂等:apply 两次 → 第二次 0 改写(AlreadyWrapped 跳过)。
    #[test]
    fn json_agent_apply_is_idempotent() {
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let agent = JsonMcpAgent::windsurf(home);
        fs::create_dir_all(home.join(".codeium").join("windsurf")).unwrap();
        fs::write(
            &agent.config_path,
            json!({"mcpServers": {"fs": {"command": "npx", "args": ["x"]}}}).to_string(),
        )
        .unwrap();
        assert_eq!(
            run_json_agent_apply(&agent, "vigil-hub", false, true)
                .unwrap()
                .changed,
            1
        );
        assert_eq!(
            run_json_agent_apply(&agent, "vigil-hub", false, true)
                .unwrap()
                .changed,
            0
        );
    }

    /// 无配置文件 → 0 改写、无错、无备份(用户未用该 agent)。
    #[test]
    fn json_agent_no_config_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let agent = JsonMcpAgent::cursor(dir.path());
        let rep = run_json_agent_apply(&agent, "vigil-hub", false, true).unwrap();
        assert_eq!(rep.changed, 0);
        assert!(rep.backup.is_none());
        assert!(
            !run_json_agent_preview(&agent, "vigil-hub", true)
                .unwrap()
                .exists
        );
    }

    /// 损坏 JSON → `MalformedConfig`,原文件未被改写(fail-safe,复用 read_claude_json 纪律)。
    #[test]
    fn json_agent_malformed_aborts_without_touching_file() {
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let agent = JsonMcpAgent::cursor(home);
        fs::create_dir_all(home.join(".cursor")).unwrap();
        fs::write(&agent.config_path, "}{ not json").unwrap();
        let before = fs::read_to_string(&agent.config_path).unwrap();
        assert!(matches!(
            run_json_agent_apply(&agent, "vigil-hub", false, true),
            Err(SetupError::MalformedConfig { .. })
        ));
        assert_eq!(fs::read_to_string(&agent.config_path).unwrap(), before);
    }

    // ============================ doctor 覆盖全部 agent 面(D29) ============================

    /// doctor 现在覆盖全部 4 个 agent 面:Claude / Codex / Cursor / Windsurf 的 server 都进 doctor 行,
    /// 各带正确 scope 标签;底层程序存在 → 全 Launchable。
    #[test]
    fn doctor_covers_all_four_agents() {
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        // path-style 真实存在文件 → resolve_program 成功 → Launchable(跨平台确定性)。
        let real = home.join("realprog");
        fs::write(&real, b"x").unwrap();
        let real_str = real.to_string_lossy().to_string();
        // Claude(JSON)
        fs::write(
            home.join(".claude.json"),
            json!({"mcpServers": {"cl": {"command": real_str, "args": []}}}).to_string(),
        )
        .unwrap();
        // Codex(TOML)—— {:?} 对路径做转义,Windows 反斜杠也成合法 TOML basic string。
        fs::create_dir_all(home.join(".codex")).unwrap();
        fs::write(
            home.join(".codex").join("config.toml"),
            format!("[mcp_servers.cx]\ncommand = {real_str:?}\nargs = []\n"),
        )
        .unwrap();
        // Cursor(JSON)
        fs::create_dir_all(home.join(".cursor")).unwrap();
        fs::write(
            home.join(".cursor").join("mcp.json"),
            json!({"mcpServers": {"cu": {"command": real_str, "args": []}}}).to_string(),
        )
        .unwrap();
        // Windsurf(JSON)
        fs::create_dir_all(home.join(".codeium").join("windsurf")).unwrap();
        fs::write(
            home.join(".codeium")
                .join("windsurf")
                .join("mcp_config.json"),
            json!({"mcpServers": {"ws": {"command": real_str, "args": []}}}).to_string(),
        )
        .unwrap();

        let rows = run_doctor(home, None).unwrap();
        let scope_of = |n: &str| rows.iter().find(|r| r.name == n).map(|r| r.scope.as_str());
        assert_eq!(scope_of("cl"), Some("user"), "Claude user scope");
        assert_eq!(scope_of("cx"), Some("Codex"));
        assert_eq!(scope_of("cu"), Some("Cursor"));
        assert_eq!(scope_of("ws"), Some("Windsurf"));
        assert!(
            rows.iter()
                .all(|r| matches!(r.status, DoctorStatus::Launchable { .. })),
            "底层程序存在 → 全 Launchable"
        );
    }

    /// Codex 的**已包裹**条目:doctor 看穿 wrap 检查内部程序(bogus → ProgramNotFound),scope=Codex,
    /// wrapped=true —— 证明 doctor 验的是真正会被起的程序,不是 vigil-hub 自身。
    #[test]
    fn doctor_codex_wrapped_checks_inner_program() {
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        fs::create_dir_all(home.join(".codex")).unwrap();
        fs::write(
            home.join(".codex").join("config.toml"),
            "[mcp_servers.cx]\ncommand = \"vigil-hub\"\n\
             args = [\"wrap\", \"--server-id\", \"codex-cx\", \"--vigil-managed-mcp\", \"--\", \"definitely-not-a-real-prog-xyz789\", \"x\"]\n",
        )
        .unwrap();
        let rows = run_doctor(home, None).unwrap();
        let cx = rows.iter().find(|r| r.name == "cx").unwrap();
        assert_eq!(cx.scope, "Codex");
        assert!(cx.wrapped, "应识别为 Vigil 托管");
        assert!(
            matches!(cx.status, DoctorStatus::ProgramNotFound { .. }),
            "应检查 unwrap 出的内部 bogus 程序"
        );
    }

    /// malformed 的**非-Claude** agent 配置 → 一条诚实 `ConfigError` 行(计入失败、不静默漏报),
    /// 但**不 abort**(Claude + 其它 agent 仍可查)(Codex D29 #6/#8)。
    #[test]
    fn doctor_malformed_agent_config_is_config_error_not_abort() {
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let real = home.join("realprog");
        fs::write(&real, b"x").unwrap();
        fs::write(
            home.join(".claude.json"),
            json!({"mcpServers": {"cl": {"command": real.to_string_lossy().to_string(), "args": []}}})
                .to_string(),
        )
        .unwrap();
        // Cursor 配置损坏
        fs::create_dir_all(home.join(".cursor")).unwrap();
        fs::write(home.join(".cursor").join("mcp.json"), "}{ not json").unwrap();

        let rows = run_doctor(home, None).unwrap(); // 不 abort
        assert!(
            rows.iter().any(|r| r.name == "cl" && r.scope == "user"),
            "Claude 行仍在"
        );
        // 损坏的 Cursor 配置 → ConfigError(计入失败,reason 说明可解析性)而非静默 skip。
        let cursor_err = rows
            .iter()
            .find(|r| r.scope == "Cursor")
            .expect("应有一条 Cursor 行");
        match &cursor_err.status {
            DoctorStatus::ConfigError { reason } => {
                assert!(
                    reason.contains("could not be parsed"),
                    "malformed → parsed 措辞"
                )
            }
            other => panic!("Cursor 坏配置应为 ConfigError,得到 {other:?}"),
        }
    }

    /// **Claude** 配置 malformed → 仍 abort(既有错误契约不变)。
    #[test]
    fn doctor_claude_malformed_still_aborts() {
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        fs::write(home.join(".claude.json"), "}{ broken").unwrap();
        assert!(matches!(
            run_doctor(home, None),
            Err(SetupError::MalformedConfig { .. })
        ));
    }
}
