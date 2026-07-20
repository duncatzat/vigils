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

/// arg 是否 sentinel token(精确 `--vigil-managed-mcp` 或 `--vigil-managed-mcp=...` 形态)。
fn is_sentinel_token(a: &str) -> bool {
    a == VIGIL_MANAGED_MCP_MARKER || a.starts_with(&format!("{VIGIL_MANAGED_MCP_MARKER}="))
}

/// sentinel 在 `args` 中的位置(首个命中;无 → `None`)。
fn sentinel_pos(args: &[Value]) -> Option<usize> {
    args.iter()
        .position(|a| a.as_str().map(is_sentinel_token).unwrap_or(false))
}

/// Vigil 标准托管 wrap 条目的**唯一** grammar 判定(classify 与 unwrap 共用,SSOT):
/// `args[0]=="wrap"` ∧ sentinel 存在 ∧ sentinel **紧邻** `--`([`wrapped_argv`] 恒产出该形态,
/// Vigil 从未写出过其它形态)。此前 classify 只要求 sentinel **在任意位置**:手改出的
/// `args[0]=="wrap"` + sentinel 不邻 `--` 条目被分类 AlreadyWrapped(status 计入已保护),
/// [`unwrap_entry`] 却反解不出(None)→ **不可逆的假托管态**(review 2026-07-17 HIGH-2)。
/// 统一后这类条目按普通条目处理:command 含 vigil-hub 的落 #15 wrapper-前缀 Skipped(不动),
/// 纯第三方伪标记条目则被当普通 server 正常保护(不再因自带 sentinel 逃逸 wrap = 收窄 fail-open)。
fn is_managed_wrap_args(args: &[Value]) -> bool {
    let args0_wrap = args.first().and_then(Value::as_str) == Some("wrap");
    args0_wrap
        && sentinel_pos(args)
            .map(|i| args.get(i + 1).and_then(Value::as_str) == Some("--"))
            .unwrap_or(false)
}

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

/// 校验已解析 JSON 配置的 **MCP 根形状**(读层之后、分类之前的统一守门):根必须是 object;
/// `mcpServers` **存在则必须**是 object;`projects`(Claude 专有)存在则必须是 object,其每个
/// 项目的 `mcpServers` 同。键**不存在** = 合法"未配置"(绝大多数用户),不报错。
///
/// **为什么必须 abort 而不是静默空**:此前"存在但类型错"(如 `"mcpServers": []` / 字符串)被
/// `as_object()` 折叠成"无 server" → preview/apply 假成功、status 报 0、doctor 无行 —— 配置
/// 在场却完全不受保护,用户得不到任何"Vigil 读不懂它"的信号(fail-open;review 2026-07-17
/// MED-1)。与 hook 注册面 [`crate::setup_hooks`] 的 `ensure_agent_shape` 同纪律:绝不臆测。
pub fn ensure_mcp_root_shape(cfg: &Value, path: &Path) -> Result<(), SetupError> {
    let bad = |field: &'static str| {
        Err(SetupError::UnsupportedConfigShape {
            path: path.to_path_buf(),
            field,
        })
    };
    if !cfg.is_object() {
        return bad("<root>");
    }
    if let Some(v) = cfg.get("mcpServers") {
        if !v.is_object() {
            return bad("mcpServers");
        }
    }
    if let Some(projects) = cfg.get("projects") {
        let Some(po) = projects.as_object() else {
            return bad("projects");
        };
        for proj in po.values() {
            if let Some(v) = proj.get("mcpServers") {
                if !v.is_object() {
                    return bad("projects.*.mcpServers");
                }
            }
        }
    }
    Ok(())
}

/// 从已解析的 `~/.claude.json` 枚举 **user scope**(顶层 `mcpServers`)的 server 并分类。
/// 纯函数 —— 不碰文件系统,fixture 直接可测。无 `mcpServers` / 形状不符 → 空 Vec(无可保护项;
/// "存在但类型错"的根形状由调用方先经 [`ensure_mcp_root_shape`] 拦截)。
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

    // 已托管 / Vigil 自身条目判定(DEF-002 修复 + 原 Codex review 防 fail-open)。
    if let (Some(cmd), Some(args)) = (command, raw_args) {
        // 用 file_name()(完整文件名)精确匹配 `vigil-hub` / `vigil-hub.exe` —— **不**用 file_stem():
        // 后者会把 `vigil-hub.sh` / `vigil-hub.py` 等单扩展名也剥成 `vigil-hub`,使一个恰好名为
        // `vigil-hub.sh` 的第三方 server 误命中下面的"自身条目 Skip"→ 漏保护(adversarial review A2)。
        let basename_is_vigil = std::path::Path::new(cmd)
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.eq_ignore_ascii_case("vigil-hub") || s.eq_ignore_ascii_case("vigil-hub.exe"))
            .unwrap_or(false);
        let args0 = args.first().and_then(Value::as_str);
        let has_sentinel = args.iter().filter_map(Value::as_str).any(is_sentinel_token);

        // ① 已托管:与 [`unwrap_entry`] **同一** grammar([`is_managed_wrap_args`]:args[0]=="wrap"
        //    + sentinel 紧邻 `--`)—— 分类说"已托管"的,反解必然能还原(可逆性闭环)。
        //    **DEF-002 trigger B 修复**:不要求 command basename==vigil-hub —— 否则从改名 / 带版本号
        //    的二进制(如 `vigil-hub-0.1.4`、符号链接 `vh`)再跑 setup 时,已 wrap 的条目认不出 → 被
        //    二次 wrap。sentinel + args[0]=="wrap" + 紧邻 `--` 的合取后第三方 server 不可能误命中
        //    (其 args[0] 不会是 "wrap";仅自带 `--vigil-managed-mcp` 参数也被排除,fail-open 仍被堵)。
        if is_managed_wrap_args(args) {
            return McpServerClass::AlreadyWrapped { name: name.into() };
        }

        // #15 嵌套 wrap 盲区:历史/手工配置可能被 `stdbuf`/`sh`/`env` 等包装器**前缀**包裹了一个
        // vigil-hub wrap(`command="stdbuf", args=["-oL","vigil-hub","wrap",...,"--vigil-managed-mcp",...]`)。
        // 此时 args[0] 不是 "wrap" → 上面 AlreadyWrapped 漏判 → 会被二次 wrap 产生嵌套。精确补判:整 argv
        // (含 command)里出现 **vigil-hub basename 紧跟 "wrap"** 的相邻 token + sentinel 在场。判为
        // **Skipped**(非 AlreadyWrapped):Vigil 没写过这种前缀形态、`unwrap_entry` 也只认 args[0]=="wrap",
        // 故不声称能还原它,只**保证不二次 wrap**(诚实 + fail-safe)。第三方 server 不会有 vigil-hub+wrap
        // 相邻序列(除非它确在跑 vigil-hub wrap),故不引入漏保护 fail-open。
        let is_vh_tok = |t: &str| {
            std::path::Path::new(t)
                .file_name()
                .and_then(|s| s.to_str())
                .map(|s| {
                    s.eq_ignore_ascii_case("vigil-hub") || s.eq_ignore_ascii_case("vigil-hub.exe")
                })
                .unwrap_or(false)
        };
        let argv_tokens: Vec<&str> = std::iter::once(cmd)
            .chain(args.iter().filter_map(Value::as_str))
            .collect();
        if has_sentinel
            && argv_tokens
                .windows(2)
                .any(|w| is_vh_tok(w[0]) && w[1] == "wrap")
        {
            return McpServerClass::Skipped {
                name: name.into(),
                reason: "appears already wrapped under a wrapper prefix (stdbuf/sh/env...); \
                         left untouched to avoid double-wrap — unwrap it by hand if needed",
            };
        }

        // ② Vigil 自己的 server/gateway 条目**绝不 wrap**(会自我嵌套)。
        //    **DEF-002 trigger A 修复**:官方文档把 Vigil 暴露为 MCP server 用的是
        //    `{"command":"vigil-hub","args":["serve",...]}`(args[0]=="serve",非 "wrap"),旧逻辑把它
        //    误判 Wrappable → wrap 包 serve 的嵌套网关。这里显式排除 vigil-hub 的 serve/wrap 自指条目。
        //    收紧到 `basename==vigil-hub ∧ args[0]∈{serve,wrap}`,不误伤仅**名为** vigil 或**传** --serve
        //    的第三方 server(它们的 command basename 不是 vigil-hub)。
        if basename_is_vigil && matches!(args0, Some("serve") | Some("wrap")) {
            return McpServerClass::Skipped {
                name: name.into(),
                reason: "Vigil's own server/gateway entry — never wrapped (would nest)",
            };
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
    // server 名可含大写/空格/点等任意字符(如 `Playwright`)—— 网关 id 由各派生函数经
    // [`server_id_component`] 规约(小写 slug + 哈希去歧义),**不再因命名 Skip**(修 F-4:
    // 专有名词大写命名极常见,让用户手动改名=成规模漏保护)。

    // env **键名**(只键不值;绝不读 secret 值)。
    let env_keys: Vec<String> = entry
        .get("env")
        .and_then(Value::as_object)
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();

    // #14:`claude mcp add` 可能把整条命令行塞进 `command` 单串、`args` 空(如 "npx -y pkg /path")。
    // 整串会被当**单一 argv** → execve 找名为 "npx -y ..." 的程序 → ENOENT,server 静默不可用、无 Vigil
    // 关联提示。args 空且 command 含空白时:无引号 → 按空白拆为 program+args(常见形态,wrap 后正常);
    // 含引号(带空格的引用参数,形态不确定)→ 诚实跳过,让用户在配置里拆成 command+args 数组。
    let (command, args): (String, Vec<String>) = if args.is_empty()
        && command.split_whitespace().nth(1).is_some()
    {
        if command.contains('\'') || command.contains('"') {
            return McpServerClass::Skipped {
                name: name.into(),
                reason: "`command` is a single shell string with quotes; split it into a \
                             `command` + `args` array in your MCP config so Vigil can wrap it",
            };
        }
        let mut parts = command.split_whitespace();
        let prog = parts.next().unwrap_or(command);
        // 单串 command 本身就是一次 vigil-hub 调用(wrap/serve/...):此前 has_sentinel 基于**原始**
        // args(空)算得 false,AlreadyWrapped 与 #15 都漏判;拆分后会把
        // `vigil-hub wrap ... --vigil-managed-mcp ...` 当普通 server **二次 wrap**(Codex CONFIRM 的幂等
        // bug)。拆出 program basename 命中 vigil-hub → Skipped:Vigil 没写过这种单串形态、uninstall 也
        // 认不出(只认 args[0]=="wrap"),故只保证不二次 wrap(诚实 + fail-safe),不声称能还原。
        if std::path::Path::new(prog)
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.eq_ignore_ascii_case("vigil-hub") || s.eq_ignore_ascii_case("vigil-hub.exe"))
            .unwrap_or(false)
        {
            return McpServerClass::Skipped {
                name: name.into(),
                reason: "single-string `command` is itself a vigil-hub invocation; not wrapping \
                             (would double-wrap) — split into command+args explicitly if intended",
            };
        }
        (prog.to_string(), parts.map(String::from).collect())
    } else {
        // (c)(Codex CONFIRM):单 token 带前后空白(如 "npx ")走 else 分支,trim 掉,避免拿 "npx "
        // 当 argv0 执行 ENOENT。trim 只剥首尾、保留路径内部空格;结构化条目的 command 本就无首尾空白
        // → no-op,不破坏逐字往返。
        (command.trim().to_string(), args)
    };

    McpServerClass::Wrappable {
        name: name.into(),
        command,
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

/// 把 agent 配置里的 server 名规约成网关 id 合法组件(`^[a-z0-9_-]+$`)。
///
/// 名本就合法 → **原样返回**(既有用户的 server-id 逐字不变 = 向后兼容)。含大写/空格/点等
/// 非法字符(如 `Playwright`)→ 小写化 + 非法字符折叠为 `-`,再追加 `-<sha256(原名)[:8]>`
/// 去歧义:两个仅大小写不同的名 slug 相同,哈希后缀保证身份不塌缩;同名恒同 id(稳定)。
/// 全部字符都不可用(如纯中文名)→ 退化为 `srv-<hash>`。修 F-4:此前直接 Skip 让用户手动
/// 改名 —— 专有名词大写命名极常见,会成规模漏保护。
fn server_id_component(name: &str) -> String {
    let is_valid = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-';
    if !name.is_empty() && name.chars().all(is_valid) {
        return name.to_string();
    }
    let mut slug = String::with_capacity(name.len());
    for c in name.to_lowercase().chars() {
        if is_valid(c) {
            slug.push(c);
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let slug = slug.trim_matches('-');
    let digest = Sha256::digest(name.as_bytes());
    let hash = &hex::encode(digest)[..8];
    if slug.is_empty() {
        format!("srv-{hash}")
    } else {
        format!("{slug}-{hash}")
    }
}

/// 为 **user scope**(顶层 `mcpServers`)的 server 派生 server-id:`user-<组件>`。
///
/// 加 `user-` 前缀(而非裸 `<name>`)是为与 [`local_scope_server_id`] 的 `local-` 命名空间**可证不相交**
/// —— Codex D8 R1 指出:裸名会与 local id 撞(用户若把 user-scope server 命名成形似 local id 的串,
/// 两者在共享账本里塌缩)。两侧都由 Vigil 加 disjoint 前缀后,任意用户取名都不可能跨 scope 撞 id。
/// 分隔符用 `-`(**非** `:`)—— `:` 不在网关 `SERVER_ID_RE = ^[a-z0-9_-]+$` 字符集内会 attach 失败
/// (Codex D8 R2 抓的回归);`-` 合法。名含非法字符时经 [`server_id_component`] 规约。
pub fn user_scope_server_id(name: &str) -> String {
    format!("user-{}", server_id_component(name))
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
    format!("local-{hash}-{}", server_id_component(name))
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

/// 统计 `~/.claude.json` 中已被 Vigil 网关 wrap 的 MCP server 数(user-scope 顶层 +
/// 各 project local-scope 之和)。供 `setup --status` 报告 MCP-wrap 保护层 —— 修
/// **ISS-20260621-002**:此前 status 只看原生 hook 的 [`setup::ProtectionState`],用
/// `setup --mcp` turnkey(只 wrap MCP、不装 hook)的用户被误报 "Protection: not installed"。
/// best-effort 纯展示:读不到 / 解析失败返回 0(非安全判定,不影响实际防护)。
pub fn wrapped_server_count(home: &Path) -> usize {
    let Ok(Some(cfg)) = read_claude_json(&claude_json_path(home)) else {
        return 0;
    };
    let user = classify_user_scope_servers(&cfg)
        .iter()
        .filter(|c| matches!(c, McpServerClass::AlreadyWrapped { .. }))
        .count();
    let local = classify_local_scope_servers(&cfg)
        .iter()
        .filter(|(_, c)| matches!(c, McpServerClass::AlreadyWrapped { .. }))
        .count();
    user + local
}

/// `setup --status` 单 agent 的 MCP 网关覆盖状态。此前返回裸 usize,读/解析失败被折叠成 0 ——
/// 配置存在却损坏/不可读的 agent 与"未配置"不可区分,status 呈现虚假的"全部正常"视图
/// (review 2026-07-17 MED-4)。`ConfigError` 态让渲染层能诚实提示"配置在但查不了,去跑 doctor"。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentWrapStatus {
    /// 配置可读(或不存在 = 0):已被 Vigil wrap 的 server 数。
    Wrapped(usize),
    /// 配置**存在但读取/解析/根形状失败** —— server 可能存在但对 status 不可见,绝不谎报 0。
    ConfigError,
}

/// `setup --status` 的逐 agent MCP 网关覆盖统计:`(agent 显示名, 状态)`,恒含全部接入面
/// (Claude + Codex + 全部 [`all_json_mcp_agents`] registry;0 也返回,渲染层自行取舍)。
/// best-effort 只读(单 agent 配置损坏不使整个 status 失败),但**不再**把读失败折叠成 0
/// (诚实三态,见 [`AgentWrapStatus`])。`env` 注入式(测试 `AgentEnv::default()`)。
pub fn wrapped_server_counts_all_agents(
    home: &Path,
    env: &AgentEnv,
) -> Vec<(&'static str, AgentWrapStatus)> {
    use AgentWrapStatus::{ConfigError, Wrapped};
    let wrapped_in = |cfg: &Value| {
        classify_user_scope_servers(cfg)
            .iter()
            .filter(|c| matches!(c, McpServerClass::AlreadyWrapped { .. }))
            .count()
    };
    // Claude:user scope + local scope 合计(与 [`wrapped_server_count`] 同口径,但读失败诚实报错)。
    let claude_path = claude_json_path(home);
    let claude = match read_claude_json(&claude_path) {
        Ok(Some(cfg)) => match ensure_mcp_root_shape(&cfg, &claude_path) {
            Ok(()) => Wrapped(
                wrapped_in(&cfg)
                    + classify_local_scope_servers(&cfg)
                        .iter()
                        .filter(|(_, c)| matches!(c, McpServerClass::AlreadyWrapped { .. }))
                        .count(),
            ),
            Err(_) => ConfigError,
        },
        Ok(None) => Wrapped(0),
        Err(_) => ConfigError,
    };
    let codex_path = codex_config_path(home, env.codex_home.as_deref());
    let codex = match read_codex_config(&codex_path) {
        Ok(Some(doc)) => match ensure_codex_root_shape(&doc, &codex_path) {
            Ok(()) => Wrapped(
                classify_codex_servers(&doc)
                    .iter()
                    .filter(|c| matches!(c, McpServerClass::AlreadyWrapped { .. }))
                    .count(),
            ),
            Err(_) => ConfigError,
        },
        Ok(None) => Wrapped(0),
        Err(_) => ConfigError,
    };
    let zcode_path = zcode_config_path(home);
    let zcode = match read_claude_json(&zcode_path) {
        Ok(Some(cfg)) => match ensure_zcode_root_shape(&cfg, &zcode_path) {
            Ok(()) => Wrapped(
                zcode_servers_obj(&cfg)
                    .map(|m| {
                        m.iter()
                            .filter(|(name, entry)| {
                                matches!(
                                    classify_one(name, entry),
                                    McpServerClass::AlreadyWrapped { .. }
                                )
                            })
                            .count()
                    })
                    .unwrap_or(0),
            ),
            Err(_) => ConfigError,
        },
        Ok(None) => Wrapped(0),
        Err(_) => ConfigError,
    };
    let mut out = vec![("Claude Code", claude), ("Codex", codex), ("ZCode", zcode)];
    for agent in all_json_mcp_agents(home, env) {
        let st = match read_claude_json(&agent.config_path) {
            Ok(Some(cfg)) => match ensure_mcp_root_shape(&cfg, &agent.config_path) {
                Ok(()) => Wrapped(wrapped_in(&cfg)),
                Err(_) => ConfigError,
            },
            Ok(None) => Wrapped(0),
            Err(_) => ConfigError,
        };
        out.push((agent.display_name, st));
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
        Some(v) => {
            ensure_mcp_root_shape(&v, &path)?; // 存在但类型错的 mcpServers 绝不静默当"无 server"
            (
                true,
                classify_user_scope_servers(&v),
                classify_local_scope_servers(&v),
            )
        }
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
// **可逆边界(诚实声明,review 2026-07-17 MED-3)**:还原目标是**语义等价的可运行形态**,非字节级
// 快照 —— classify 的刻意归一化(#14 单串 command 拆分、首尾空白 trim、缺失 `args` 还原后成 `[]`)
// 不可逆转回原病态形态;整个文件也经 pretty-print 重写(键序/未知字段保留,空白/缩进可能变)。
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
/// 判据与 `classify_one` 的 AlreadyWrapped 一致:args[0]=="wrap" + sentinel + sentinel 紧跟 `--`。
/// **DEF-002 trigger B**:不再要求 command basename==vigil-hub —— 让改名 / 带版本号的二进制
/// (`vigil-hub-0.1.4`、符号链接)写出的 wrap 也能被 `--uninstall` 正确还原。sentinel + 紧邻 `--`
/// 的结构已唯一标识本网关 wrap 形态,basename 冗余且会挡住还原。
fn unwrap_entry(wrapped: &Value) -> Option<Value> {
    let obj = wrapped.as_object()?;
    let args = obj.get("args")?.as_array()?;
    // 与 classify 的 AlreadyWrapped **同一** grammar([`is_managed_wrap_args`],SSOT):
    // args[0]=="wrap" + sentinel 存在 + sentinel **紧邻** `--`。
    // **sentinel-anchored 分隔符**:**不**用 `position("--")` 找第一个 `--` —— 若 server 名 /
    // env-key 字面恰是 `--`(病态但可能)会撞错分隔符导致还原失败/错乱。锚定 sentinel 后取其
    // 紧邻 `--` 才鲁棒(name/env-key 在 sentinel 之前)。
    if !is_managed_wrap_args(args) {
        return None; // 非 Vigil 标准 wrap 形态,不动(fail-safe)
    }
    let sent = sentinel_pos(args)?;
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

/// #16:列出**全部接入面**(Claude user+local / Codex / JSON-agent registry)Wrappable server 中
/// 底层程序在宿主 PATH **不可解析**的 `(接入面标签, server 名, program)`。供 `setup --mcp --apply`
/// 后**非阻塞 WARN** —— 避免给"Protected"虚假安全感(底层程序坏/未装时 server 在 agent 启动才
/// 静默失败,无 Vigil 关联提示)。此前只查 Claude user scope,其余面 wrap 后没有同款即时预警
/// (review 2026-07-17 LOW-1)。必须在 apply **之前**对原始配置调用(apply 后条目变 AlreadyWrapped
/// 不再 Wrappable)。复用网关同款 `resolve_program`(SSOT)。best-effort 只读:读失败按无警告处理
/// (apply 自身会对该面诚实报错,此处不重复)。
pub fn unresolvable_wrappables(home: &Path, env: &AgentEnv) -> Vec<(String, String, String)> {
    let mut out: Vec<(String, String, String)> = Vec::new();
    let mut push_unresolvable = |label: &str, class: McpServerClass| {
        if let McpServerClass::Wrappable { name, command, .. } = class {
            if vigil_mcp::stdio::resolve_program(&command).is_err() {
                out.push((label.to_string(), name, command));
            }
        }
    };
    if let Ok(Some(cfg)) = read_claude_json(&claude_json_path(home)) {
        for class in classify_user_scope_servers(&cfg) {
            push_unresolvable("Claude Code", class);
        }
        for (_proj, class) in classify_local_scope_servers(&cfg) {
            push_unresolvable("Claude Code (project)", class);
        }
    }
    if let Ok(Some(doc)) = read_codex_config(&codex_config_path(home, env.codex_home.as_deref())) {
        for class in classify_codex_servers(&doc) {
            push_unresolvable("Codex", class);
        }
    }
    if let Ok(Some(cfg)) = read_claude_json(&zcode_config_path(home)) {
        if let Some(servers) = zcode_servers_obj(&cfg) {
            for (name, entry) in servers {
                push_unresolvable("ZCode", classify_one(name, entry));
            }
        }
    }
    for agent in all_json_mcp_agents(home, env) {
        if let Ok(Some(cfg)) = read_claude_json(&agent.config_path) {
            for class in classify_user_scope_servers(&cfg) {
                push_unresolvable(agent.display_name, class);
            }
        }
    }
    out
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
        Some(v) => {
            ensure_mcp_root_shape(&v, &path)?; // 类型错的根形状绝不改写(abort-on-unexpected)
            v
        }
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
        Some(v) => {
            ensure_mcp_root_shape(&v, &path)?; // 读不懂的形状绝不声称"还原了 0 个"
            v
        }
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

/// Codex CLI 的 MCP 配置文件路径:`$CODEX_HOME/config.toml`(默认 `~/.codex/config.toml`)。
///
/// `codex_home_env` = `CODEX_HOME` 环境变量值,**注入式**(生产经 [`codex_home_env`] 读;测试传
/// `None`/fixture 值,绝不受开发机真实 env 污染)。解析复用 hook 注册面的
/// [`crate::setup_hooks::resolve_codex_home`](SSOT)—— 此前本面固定 `~/.codex`,与 hook 面分裂:
/// 自定义 `CODEX_HOME` 的用户 hook 写进真实 Codex 目录、MCP wrap 却读写不存在的 `~/.codex`,
/// 其全部 server 漏保护且 status/doctor/quickstart 不可见(review 2026-07-17 HIGH-1)。
pub fn codex_config_path(home: &Path, codex_home_env: Option<&str>) -> PathBuf {
    crate::setup_hooks::resolve_codex_home(home, codex_home_env).join("config.toml")
}

/// 为 Codex `[mcp_servers.<name>]` 条目派生 server-id:`codex-<组件>`。
///
/// 加 `codex-` 前缀与 [`user_scope_server_id`](`user-`)/ [`local_scope_server_id`](`local-`)
/// 命名空间不相交。名经 [`server_id_component`] 规约(合法名原样;非法字符 slug + 哈希),
/// 拼接后必合法(`codex-` 全在字符集内)。
pub fn codex_scope_server_id(name: &str) -> String {
    format!("codex-{}", server_id_component(name))
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

/// 校验 Codex `config.toml` 的 MCP 根形状:`mcp_servers` **存在则必须**是 table-like
/// (`[mcp_servers.x]` 标准 sub-table 或 `mcp_servers = {..}` 内联表都合法)。缺省 = 未配置,合法。
/// 存在但是标量/数组等 → abort —— 此前与"缺失"合并成 `None` 静默当 0 项(fail-open;
/// review 2026-07-17 MED-1 Codex 侧),与 JSON 面 [`ensure_mcp_root_shape`] 同纪律。
pub fn ensure_codex_root_shape(doc: &DocumentMut, path: &Path) -> Result<(), SetupError> {
    match doc.get("mcp_servers") {
        None => Ok(()),
        Some(i) if i.as_table_like().is_some() => Ok(()),
        Some(_) => Err(SetupError::UnsupportedConfigShape {
            path: path.to_path_buf(),
            field: "mcp_servers",
        }),
    }
}

/// 取 `[mcp_servers]` 表。`as_table_like`:标准 sub-table 与 `mcp_servers = {..}` 内联表**都**
/// 支持(此前只认 `as_table()`,内联形态被静默当 0 项 = 漏保护;形状异常由
/// [`ensure_codex_root_shape`] 在调用方先拦)。缺省 → `None` = 无可保护项。
fn codex_servers_table(doc: &DocumentMut) -> Option<&dyn toml_edit::TableLike> {
    doc.get("mcp_servers").and_then(|i| i.as_table_like())
}
fn codex_servers_table_mut(doc: &mut DocumentMut) -> Option<&mut dyn toml_edit::TableLike> {
    doc.get_mut("mcp_servers")
        .and_then(|i| i.as_table_like_mut())
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

/// 读真实 `$CODEX_HOME/config.toml`(IO 边界)→ 枚举 + 分类,产出只读预览。**不写任何东西**。
/// `home` / `codex_home_env` / `exe` 全注入 → 测试走 fixture 而**绝不**碰真实用户配置。
pub fn run_codex_preview(
    home: &Path,
    codex_home_env: Option<&str>,
    exe: &str,
    monitor: bool,
) -> Result<CodexPreviewReport, SetupError> {
    let path = codex_config_path(home, codex_home_env);
    let doc = read_codex_config(&path)?;
    let (exists, servers) = match doc {
        Some(d) => {
            ensure_codex_root_shape(&d, &path)?; // 存在但非 table-like 绝不静默当 0 项
            (true, classify_codex_servers(&d))
        }
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
    codex_home_env: Option<&str>,
    exe: &str,
    dry_run: bool,
    monitor: bool,
) -> Result<CodexApplyReport, SetupError> {
    let path = codex_config_path(home, codex_home_env);
    let mut doc = match read_codex_config(&path)? {
        Some(d) => {
            ensure_codex_root_shape(&d, &path)?; // 类型错的根形状绝不改写
            d
        }
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
pub fn run_codex_uninstall(
    home: &Path,
    codex_home_env: Option<&str>,
    dry_run: bool,
) -> Result<CodexApplyReport, SetupError> {
    let path = codex_config_path(home, codex_home_env);
    let mut doc = match read_codex_config(&path)? {
        Some(d) => {
            ensure_codex_root_shape(&d, &path)?; // 读不懂的形状绝不声称"还原了 0 个"
            d
        }
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

// ============================ JSON `mcpServers` agent 接入面(Cursor / Windsurf / Kimi / pi) ============================
//
// Cursor(`~/.cursor/mcp.json`)、Windsurf(`~/.codeium/windsurf/mcp_config.json`)、Kimi CLI
// (`~/.kimi/mcp.json`)与 pi(`$PI_AGENT_DIR/mcp.json`,经 pi-mcp-adapter)的 MCP 配置**形态与
// Claude user scope 完全一致**:专用 JSON 文件、顶层 `mcpServers` 对象、条目 `command`/`args`/`env`、
// 远程用 `url`(Windsurf 另用 `serverUrl`,已并入 `classify_one` 远程检测)。故**直接复用 Claude 路径的
// read/classify/wrap/unwrap/atomic-write 机制**,仅 config 路径与 server-id 前缀不同;无 `projects.*` 嵌套
// (那是 Claude 专有),只处理顶层 scope。server-id 用 `<prefix>-<name>`(与 `user-`/`local-`/`codex-`
// 命名空间不相交,前缀合法性由 [`JsonMcpAgent::new`] 门禁)。实例清单唯一来源 = [`all_json_mcp_agents`]。
//
// **范围**:上述四家 —— 均为专用、安全可重写文件、零形态差异。Cline(globalStorage 路径随
// VS Code 版本/fork 漂移 + 有删配置数据丢失史)、Zed(`context_servers` 键且嵌入共享 settings.json/JSONC)、
// VS Code(`servers` 键 + 显式 `type`)形态/风险不同,留后续专门增量。ZCode(嵌套 `mcp.servers`
// 键,GUI 管理的共享 `~/.zcode/cli/config.json`)**不走本通用管道** —— 已由下文独立专线覆盖
// (契约 = 解包 vendor app.asar 实锤,见"ZCode 接入面"段)。Kimi 的 hook 面(`~/.kimi/config.toml`
// `[[hooks]]`)**刻意不做**:Beta + 官方 fail-open(hook 超时/崩溃=放行),不满足 Vigil 强保护
// 语义,等 GA 后独立评估。

/// 生产环境变量快照(**注入式**):库函数绝不直接读 env —— 否则 fixture 测试会被开发机真实
/// `CODEX_HOME`/`PI_AGENT_DIR` 污染,apply 类测试甚至可能误写真实配置。main/quickstart 生产
/// 入口取一次后传引用;测试用 `AgentEnv::default()`(全 None = 全默认路径)或注入 fixture 值。
#[derive(Debug, Clone, Default)]
pub struct AgentEnv {
    /// `CODEX_HOME`(Codex 配置根;`None` = 默认 `~/.codex`)。
    pub codex_home: Option<String>,
    /// pi 的 agent 配置目录(`None` = 默认 `~/.pi/agent`)。取自 `PI_CODING_AGENT_DIR`
    /// (pi-mcp-adapter 文档对 mcp.json 点名的变量)或 `PI_AGENT_DIR`(pi 本体文档),前者优先。
    pub pi_agent_dir: Option<String>,
}

impl AgentEnv {
    /// 读真实进程环境(**仅生产调用点**;库/测试路径绝不调用)。
    pub fn from_process_env() -> Self {
        AgentEnv {
            codex_home: std::env::var("CODEX_HOME").ok(),
            pi_agent_dir: std::env::var("PI_CODING_AGENT_DIR")
                .ok()
                .or_else(|| std::env::var("PI_AGENT_DIR").ok()),
        }
    }
}

/// 一个"JSON `mcpServers` 形态"的 agent 接入面描述符(Cursor / Windsurf / Kimi / pi)。
#[derive(Debug, Clone)]
pub struct JsonMcpAgent {
    /// 人类可读名(报告/预览用)。
    pub display_name: &'static str,
    /// 配置文件绝对路径(已注入 home → 测试可指向 fixture,绝不碰真实用户配置)。
    pub config_path: PathBuf,
    /// server-id 前缀(`cursor` / `windsurf` / `kimi` / `pi`)。
    pub id_prefix: &'static str,
}

impl JsonMcpAgent {
    /// 受校验构造器(所有预置构造器的唯一落点):`id_prefix` 必须非空、全 `[a-z0-9]`
    /// (禁 `-`/`_`:防与 [`server_id_component`] 的 `-` 分隔产生歧义,并保持与既有前缀同形),
    /// 且不得撞 `user`/`local`/`codex` 保留命名空间 —— 撞了 = 共享账本跨 agent 身份塌缩,
    /// descriptor pin 与审批串号(review 2026-07-17 HIGH-3)。前缀是编译期字面量,违规属编程
    /// bug → fail-fast panic;registry invariant 测试再兜跨实例唯一性(单实例校验查不了重复)。
    fn new(display_name: &'static str, config_path: PathBuf, id_prefix: &'static str) -> Self {
        assert!(
            !id_prefix.is_empty()
                && id_prefix
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
            "JsonMcpAgent id_prefix must be non-empty [a-z0-9]+: {id_prefix:?}"
        );
        assert!(
            // `zcode` 由嵌套键专线用 [`zcode_scope_server_id`] 派生,与 JsonMcpAgent 同属共享账本
            // 命名空间 —— 一并保留,防未来 JsonMcpAgent::new(_, _, "zcode") 与 ZCode 面 server-id 塌缩。
            !matches!(id_prefix, "user" | "local" | "codex" | "zcode"),
            "JsonMcpAgent id_prefix collides with a reserved namespace: {id_prefix:?}"
        );
        JsonMcpAgent {
            display_name,
            config_path,
            id_prefix,
        }
    }
    /// Cursor:`~/.cursor/mcp.json`(user scope;项目级 `<repo>/.cursor/mcp.json` 是独立提交文件,不碰)。
    pub fn cursor(home: &Path) -> Self {
        Self::new("Cursor", home.join(".cursor").join("mcp.json"), "cursor")
    }
    /// Windsurf:`~/.codeium/windsurf/mcp_config.json`(唯一 scope —— Windsurf 无项目级 MCP 配置)。
    pub fn windsurf(home: &Path) -> Self {
        Self::new(
            "Windsurf",
            home.join(".codeium")
                .join("windsurf")
                .join("mcp_config.json"),
            "windsurf",
        )
    }
    /// Kimi CLI(Moonshot):`~/.kimi/mcp.json`(官方文档核实 2026-07;标准顶层 `mcpServers`,
    /// stdio `command`/`args`/`env` + 远程 `url`/`headers` —— 远程条目由 classify 诚实 Skip)。
    pub fn kimi(home: &Path) -> Self {
        Self::new("Kimi CLI", home.join(".kimi").join("mcp.json"), "kimi")
    }
    /// pi(badlogic/pi-mono)**经 pi-mcp-adapter**:`$PI_AGENT_DIR/mcp.json`(默认 `~/.pi/agent/`)。
    /// pi 本体**设计上无内置 MCP**;该文件是官方 MCP extension 示例与 pi-mcp-adapter 共同的
    /// Pi-global 约定(标准顶层 `mcpServers`)。文件不存在 = 没装 adapter / 没配 MCP → 诚实
    /// `exists:false`,绝不创建。产品文案点名 pi-mcp-adapter,不宣传"pi 原生 MCP"。自定义
    /// agent dir 不并入 server-id(与 `CODEX_HOME` 自定义时 `codex-` 前缀不变的既有决策一致)。
    pub fn pi(home: &Path, pi_agent_dir_env: Option<&str>) -> Self {
        let dir = crate::setup_hooks::resolve_agent_dir(home, pi_agent_dir_env, || {
            home.join(".pi").join("agent")
        });
        Self::new("pi", dir.join("mcp.json"), "pi")
    }
    /// 派生 server-id(经 [`json_agent_server_id`],preview 渲染与 apply 落盘同源)。
    pub fn server_id(&self, name: &str) -> String {
        json_agent_server_id(self.id_prefix, name)
    }
}

/// JSON-agent 面 server-id 派生 SSOT:`<prefix>-<组件>`。preview 渲染与 apply 落盘**必须**同走
/// 本函数 —— 此前 main.rs 预览手拼 `{prefix}-{name}`,名含大写/空格时与 apply 的 slug+hash 规约
/// 不一致,预览展示错误甚至非法 id(review 2026-07-17 MED-6,F-4 的漏网点)。
pub fn json_agent_server_id(prefix: &str, name: &str) -> String {
    format!("{prefix}-{}", server_id_component(name))
}

/// 全部"JSON `mcpServers` 形态" agent 的**唯一清单**(SSOT)。status / doctor / preview / apply /
/// uninstall / quickstart 一律遍历本函数 —— 此前 Cursor/Windsurf 在 4 处各自硬编码,新增 agent
/// 漏一处即该功能的覆盖缺口(review 2026-07-17 MED-2)。**新增同形态 agent 只改这里**
/// (registry invariant 测试自动覆盖新条目)。`env` 注入式(生产 [`AgentEnv::from_process_env`])。
pub fn all_json_mcp_agents(home: &Path, env: &AgentEnv) -> Vec<JsonMcpAgent> {
    vec![
        JsonMcpAgent::cursor(home),
        JsonMcpAgent::windsurf(home),
        JsonMcpAgent::kimi(home),
        JsonMcpAgent::pi(home, env.pi_agent_dir.as_deref()),
    ]
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
        Some(v) => {
            ensure_mcp_root_shape(&v, &agent.config_path)?; // 类型错绝不静默当"无 server"
            (true, classify_user_scope_servers(&v))
        }
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
        Some(v) => {
            ensure_mcp_root_shape(&v, &agent.config_path)?; // 类型错的根形状绝不改写
            v
        }
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
        Some(v) => {
            ensure_mcp_root_shape(&v, &agent.config_path)?; // 读不懂的形状绝不声称"还原了 0 个"
            v
        }
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

// ============================ ZCode 接入面(`~/.zcode/cli/config.json`,嵌套 `mcp.servers`) ============================
//
// ZCode(Z.ai 的 GLM 桌面 Agentic IDE)把 **用户级** MCP server 存在共享设置文件
// `~/.zcode/cli/config.json` 的 **`mcp.servers`** 嵌套键下(非顶层 `mcpServers`,故不走
// [`JsonMcpAgent`] 通用管道,单独一条与 Codex-TOML 并列的专线)。**契约来源 = vendor shipped
// code**(2026-07-17 对 ZCode 3.3.6 安装包解包 app.asar 核实,非仅第三方博客):
// - 路径:`resolveUserHomeDir()`(HOME→USERPROFILE→homedir)+ `[".zcode","cli"]/config.json`;
//   GUI 的新增/编辑**始终写回** `.zcode`(workspace 级 `<ws>/.zcode/config.json` 是项目内文件,
//   与 Cursor 项目级同决策 —— 不碰;`~/.agents/mcp.json` 兼容层是共享标准文件,defer,见下)。
// - 读:`readServerMapFromJson`:`cfg.mcp.servers`,非 object 静默 `{}`(ZCode 自身容错;Vigil 侧
//   仍按 abort-on-unexpected 纪律,存在但类型错 → 拒绝,绝不静默当 0)。
// - 写:`saveMcpToUserDirectory` 是 **read-modify-write**(每次先重读文件再改单个 server),
//   故 Vigil wrap 后 ZCode 保存**其它** server 不会覆掉 wrap;运行中编辑**同一** server 才会
//   (用户显式行为)。风险模型与 Claude Code 并发写 claude.json 同构 → 同款缓解:用户须关闭
//   ZCode 再 `--apply`(TOCTOU stamp + 备份兜底)。
// - 条目:map value 原样存储,禁用时**附加** `enabled: false` 键(启用时删除该键)——
//   [`classify_one`] 的 clone-保留-未知字段纪律天然兼容,`enabled:false` 条目照常 wrap
//   (ZCode 仍视其为禁用;wrap 不改变 enabled 语义)。
// - **已知边界(诚实声明)**:ZCode 在 `.zcode` 无任何条目时 fallback 读 `~/.agents/mcp.json`
//   (共享标准文件,多宿主消费)。wrap 共享文件有跨宿主身份塌缩问题(单一 `zcode-` 前缀对
//   非 ZCode 宿主是错误身份)→ 本增量不碰它;只用 `.zcode` 配置的用户(GUI 用户的默认形态)
//   获得完整保护。
//
// 复用与 Claude/Codex/JSON-agent 完全相同的安全机制:[`classify_one`](全部护栏)、
// [`wrapped_argv`]/[`unwrap_entry`](wrap/反解 SSOT)、[`wrap_servers_object`]/
// [`unwrap_servers_object`](批量改写,仅 server-id 派生器不同)、
// `atomic_write_with_backup`(原子写 + 备份 + preserve_order)。ZCode 专属的只有
// "嵌套键取放"这一层。server-id 前缀 `zcode-`(与 `user-`/`local-`/`codex-` 及
// JSON-agent registry 各前缀可证不相交,见 registry invariant 测试)。

/// ZCode 用户级 MCP 配置路径(`~/.zcode/cli/config.json`)。
pub fn zcode_config_path(home: &Path) -> PathBuf {
    home.join(".zcode").join("cli").join("config.json")
}

/// 为 ZCode 条目派生 server-id:`zcode-<组件>`(命名空间与其它面不相交)。
pub fn zcode_scope_server_id(name: &str) -> String {
    format!("zcode-{}", server_id_component(name))
}

/// 校验 ZCode 配置的 MCP 根形状:根 object;`mcp` **存在则必须** object;`mcp.servers`
/// **存在则必须** object。键不存在 = 未配置(合法)。类型错 → abort(与
/// [`ensure_mcp_root_shape`] 同纪律 —— ZCode 自身对类型错静默 `{}`,Vigil 绝不效仿:
/// 静默 = 配置在场却完全不受保护且无信号)。
pub fn ensure_zcode_root_shape(cfg: &Value, path: &Path) -> Result<(), SetupError> {
    let bad = |field: &'static str| {
        Err(SetupError::UnsupportedConfigShape {
            path: path.to_path_buf(),
            field,
        })
    };
    if !cfg.is_object() {
        return bad("<root>");
    }
    match cfg.get("mcp") {
        None => Ok(()),
        Some(mcp) => {
            let Some(mcp_obj) = mcp.as_object() else {
                return bad("mcp");
            };
            match mcp_obj.get("servers") {
                None => Ok(()),
                Some(v) if v.is_object() => Ok(()),
                Some(_) => bad("mcp.servers"),
            }
        }
    }
}

/// 取 `mcp.servers` 嵌套 map(只读)。缺省 → `None` = 无可保护项(形状异常由
/// [`ensure_zcode_root_shape`] 在调用方先拦)。
fn zcode_servers_obj(cfg: &Value) -> Option<&serde_json::Map<String, Value>> {
    cfg.get("mcp")?.get("servers")?.as_object()
}
fn zcode_servers_obj_mut(cfg: &mut Value) -> Option<&mut serde_json::Map<String, Value>> {
    cfg.get_mut("mcp")?.get_mut("servers")?.as_object_mut()
}

/// 读真实 ZCode 配置(IO 边界)→ 枚举 + 分类,产出只读预览(复用 [`JsonAgentPreviewReport`]
/// 结构;`id_prefix = "zcode"` 供渲染层派生与 apply 一致的 server-id)。**不写任何东西**。
pub fn run_zcode_preview(
    home: &Path,
    exe: &str,
    monitor: bool,
) -> Result<JsonAgentPreviewReport, SetupError> {
    let path = zcode_config_path(home);
    let cfg = read_claude_json(&path)?; // 同款"读 + 解析 JSON"管道(大小上限/损坏 abort)
    let (exists, servers) = match cfg {
        Some(v) => {
            ensure_zcode_root_shape(&v, &path)?;
            let servers = zcode_servers_obj(&v)
                .map(|m| {
                    m.iter()
                        .map(|(name, entry)| classify_one(name, entry))
                        .collect()
                })
                .unwrap_or_default();
            (true, servers)
        }
        None => (false, Vec::new()),
    };
    Ok(JsonAgentPreviewReport {
        display_name: "ZCode",
        config_path: path,
        exists,
        exe: exe.to_string(),
        servers,
        monitor,
        id_prefix: "zcode",
    })
}

/// `setup --mcp --apply`(ZCode 面):读 → wrap `mcp.servers` 全部 Wrappable → 原子写。
/// `dry_run` 只算不写。**用户须关闭 ZCode 后再 apply**(见模块 doc 的并发风险声明)。
pub fn run_zcode_apply(
    home: &Path,
    exe: &str,
    dry_run: bool,
    monitor: bool,
) -> Result<JsonAgentApplyReport, SetupError> {
    let path = zcode_config_path(home);
    let cfg = match read_claude_json(&path)? {
        Some(v) => {
            ensure_zcode_root_shape(&v, &path)?;
            v
        }
        None => {
            return Ok(JsonAgentApplyReport {
                display_name: "ZCode",
                config_path: path,
                changed: 0,
                dry_run,
                backup: None,
            })
        }
    };
    let stamp = std::fs::metadata(&path)
        .ok()
        .and_then(|m| m.modified().ok().map(|t| (t, m.len())));
    let mut new_cfg = cfg.clone();
    let changed = zcode_servers_obj_mut(&mut new_cfg)
        .map(|servers| wrap_servers_object(servers, exe, monitor, zcode_scope_server_id))
        .unwrap_or(0);
    let backup = if !dry_run && changed > 0 {
        crate::setup::atomic_write_with_backup(&path, &new_cfg, stamp)?
    } else {
        None
    };
    Ok(JsonAgentApplyReport {
        display_name: "ZCode",
        config_path: path,
        changed,
        dry_run,
        backup,
    })
}

/// `setup --mcp --uninstall`(ZCode 面):读 → self-describing 还原全部 Vigil 托管条目 → 原子写。
pub fn run_zcode_uninstall(home: &Path, dry_run: bool) -> Result<JsonAgentApplyReport, SetupError> {
    let path = zcode_config_path(home);
    let cfg = match read_claude_json(&path)? {
        Some(v) => {
            ensure_zcode_root_shape(&v, &path)?;
            v
        }
        None => {
            return Ok(JsonAgentApplyReport {
                display_name: "ZCode",
                config_path: path,
                changed: 0,
                dry_run,
                backup: None,
            })
        }
    };
    let stamp = std::fs::metadata(&path)
        .ok()
        .and_then(|m| m.modified().ok().map(|t| (t, m.len())));
    let mut new_cfg = cfg.clone();
    let changed = zcode_servers_obj_mut(&mut new_cfg)
        .map(unwrap_servers_object)
        .unwrap_or(0);
    let backup = if !dry_run && changed > 0 {
        crate::setup::atomic_write_with_backup(&path, &new_cfg, stamp)?
    } else {
        None
    };
    Ok(JsonAgentApplyReport {
        display_name: "ZCode",
        config_path: path,
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

/// 把一个 JSON-`mcpServers` agent(registry 内任一家)顶层 server 逐个产出 doctor 行,追加到 `rows`。
/// 配置不存在 → 无行(用户未用该 agent);读失败**或根形状异常** → 一条 `ConfigError` 行
/// (不 abort,计入失败 —— 形状异常同样意味着"server 可能在但 doctor 看不见")。`scope`=agent 名。
fn append_json_agent_doctor_rows(
    agent: &JsonMcpAgent,
    probe_timeout: Option<Duration>,
    rows: &mut Vec<McpDoctorRow>,
) {
    match read_claude_json(&agent.config_path).and_then(|cfg| match cfg {
        Some(v) => ensure_mcp_root_shape(&v, &agent.config_path).map(|()| Some(v)),
        None => Ok(None),
    }) {
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

/// ZCode(嵌套 `mcp.servers`)doctor 行:逐条复用 `doctor_row`。读失败**或根形状异常** →
/// `ConfigError` 行(不 abort,计入失败)。`scope`="ZCode"。
fn append_zcode_doctor_rows(
    home: &Path,
    probe_timeout: Option<Duration>,
    rows: &mut Vec<McpDoctorRow>,
) {
    let path = zcode_config_path(home);
    match read_claude_json(&path).and_then(|cfg| match cfg {
        Some(v) => ensure_zcode_root_shape(&v, &path).map(|()| Some(v)),
        None => Ok(None),
    }) {
        Ok(Some(cfg)) => {
            if let Some(servers) = zcode_servers_obj(&cfg) {
                for (name, entry) in servers {
                    rows.push(doctor_row(name, "ZCode", entry, probe_timeout));
                }
            }
        }
        Ok(None) => {}
        Err(e) => rows.push(config_error_doctor_row("ZCode", &path, &e)),
    }
}

/// Codex(TOML)doctor 行:每个 `mcp_servers` 条目桥接成 JSON(`item_to_json`)后复用 `doctor_row`。
/// 读失败**或根形状异常**(存在但非 table-like)→ `ConfigError` 行(不 abort,计入失败)。
fn append_codex_doctor_rows(
    home: &Path,
    codex_home_env: Option<&str>,
    probe_timeout: Option<Duration>,
    rows: &mut Vec<McpDoctorRow>,
) {
    let path = codex_config_path(home, codex_home_env);
    match read_codex_config(&path).and_then(|doc| match doc {
        Some(d) => ensure_codex_root_shape(&d, &path).map(|()| Some(d)),
        None => Ok(None),
    }) {
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

/// `setup --mcp --doctor`:对**所有** agent 接入面(Claude user+local / Codex / 全部
/// [`all_json_mcp_agents`] registry)的每个 MCP server 做启动预检 —— 兑现"turnkey wrap 之后,
/// 所有 agent 的 server 是否还能起"。
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
    env: &AgentEnv,
    probe_timeout: Option<Duration>,
) -> Result<Vec<McpDoctorRow>, SetupError> {
    let mut rows = Vec::new();
    // Claude(~/.claude.json):user + local scope。malformed / 根形状异常 → abort(既有契约)。
    // 缺失 → 跳过(仍查其它 agent)。
    let claude_path = claude_json_path(home);
    if let Some(cfg) = read_claude_json(&claude_path)? {
        ensure_mcp_root_shape(&cfg, &claude_path)?;
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
    // 其余 agent 面(best-effort,各自独立文件):Codex(TOML)+ ZCode(嵌套键)+ 全部
    // JSON-agent registry。
    append_codex_doctor_rows(home, env.codex_home.as_deref(), probe_timeout, &mut rows);
    append_zcode_doctor_rows(home, probe_timeout, &mut rows);
    for agent in all_json_mcp_agents(home, env) {
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
        // --all 走 run_with(显式 exe 参数),不读 args.hook_exe;此处恒 None(--all 与 --hook-exe 互斥)。
        hook_exe: None,
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

    /// ISS-20260621-002 守门:`wrapped_server_count` 统计 user-scope + local-scope 中已被 Vigil
    /// 网关 wrap(`AlreadyWrapped`)的 server 数,供 `setup --status` 报告 MCP-wrap 保护层。
    #[test]
    fn wrapped_server_count_counts_already_wrapped_user_and_local() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let wrapped = |id: &str| {
            json!({
                "command": "vigil-hub",
                "args": ["wrap", "--server-id", id, "--vigil-managed-mcp", "--", "npx", "x"]
            })
        };
        let cfg = json!({
            "mcpServers": {
                "plain": { "type": "stdio", "command": "npx", "args": ["x"] }, // Wrappable → 不计
                "w1": wrapped("w1"),                                            // AlreadyWrapped → 计
            },
            "projects": {
                "/proj/a": { "mcpServers": { "w2": wrapped("w2") } },           // local AlreadyWrapped → 计
            }
        });
        std::fs::write(home.join(".claude.json"), cfg.to_string()).unwrap();
        assert_eq!(
            wrapped_server_count(home),
            2,
            "应只计 AlreadyWrapped(user w1 + local w2),不计 Wrappable plain"
        );
    }

    /// 守门:无 `~/.claude.json` 时 best-effort 返回 0(不 panic)。
    #[test]
    fn wrapped_server_count_missing_config_is_zero() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(wrapped_server_count(dir.path()), 0);
    }

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
    fn single_string_command_splits_into_program_and_args() {
        // #14:claude mcp add 的单串 command(空 args)→ 拆为 program+args(无引号),wrap 后正常。
        let cfg = json!({"mcpServers": {
            "fs": {"command": "npx -y @modelcontextprotocol/server-filesystem /tmp", "args": []}
        }});
        let c = classify_user_scope_servers(&cfg);
        let w = c
            .iter()
            .find(|c| matches!(c, McpServerClass::Wrappable { .. }))
            .expect("wrappable");
        if let McpServerClass::Wrappable { command, args, .. } = w {
            assert_eq!(
                command, "npx",
                "single-string command must split into program"
            );
            assert_eq!(
                args,
                &vec![
                    "-y".to_string(),
                    "@modelcontextprotocol/server-filesystem".to_string(),
                    "/tmp".to_string()
                ]
            );
        }
    }

    #[test]
    fn single_string_command_with_quotes_is_skipped() {
        // #14:含引号(带空格引用参数,形态不确定)→ 诚实跳过,不臆测拆分。
        let cfg = json!({"mcpServers": {
            "fs": {"command": "npx -y server \"/path with spaces\"", "args": []}
        }});
        let c = classify_user_scope_servers(&cfg);
        assert!(
            matches!(c[0], McpServerClass::Skipped { .. }),
            "quoted single-string command must be Skipped, got {:?}",
            c[0]
        );
    }

    #[test]
    fn wrapper_prefixed_vigil_wrap_is_skipped_not_rewrapped() {
        // #15:被 stdbuf 前缀包裹的 vigil-hub wrap(args[0]!="wrap")→ Skipped,防二次 wrap 嵌套。
        let cfg = json!({"mcpServers": {
            "nested": {
                "command": "stdbuf",
                "args": ["-oL", "vigil-hub", "wrap", "--server-id", "fs", "--vigil-managed-mcp", "--", "npx", "x"]
            }
        }});
        let c = classify_user_scope_servers(&cfg);
        assert!(
            matches!(c[0], McpServerClass::Skipped { .. }),
            "wrapper-prefixed vigil-hub wrap must be Skipped (not re-wrapped), got {:?}",
            c[0]
        );
        // 反向守门:仅含 sentinel 但**无** vigil-hub+wrap 相邻序列的第三方 server 仍 Wrappable(不 fail-open)。
        let cfg2 = json!({"mcpServers": {
            "thirdparty": {"command": "npx", "args": ["server", "--vigil-managed-mcp"]}
        }});
        let c2 = classify_user_scope_servers(&cfg2);
        assert!(
            matches!(c2[0], McpServerClass::Wrappable { .. }),
            "a third-party server merely containing the sentinel must stay Wrappable, got {:?}",
            c2[0]
        );
    }

    #[test]
    fn unresolvable_wrappables_flags_missing_program() {
        // #16:Wrappable server 底层程序在 PATH 不可解析 → 被列出(供非阻塞 WARN,避免虚假 Protected)。
        let td = tempfile::TempDir::new().unwrap();
        let home = td.path();
        std::fs::write(
            home.join(".claude.json"),
            json!({"mcpServers": {
                "badprog": {"command": "/nonexistent/vigil-xyz-not-real", "args": ["x"]}
            }})
            .to_string(),
        )
        .unwrap();
        let u = unresolvable_wrappables(home, &AgentEnv::default());
        assert!(
            u.iter()
                .any(|(label, n, _)| label == "Claude Code" && n == "badprog"),
            "missing program must be flagged with its agent label, got {:?}",
            u
        );
    }

    #[test]
    fn single_string_vigil_invocation_is_skipped_not_double_wrapped() {
        // #14 hardening(Codex CONFIRM 的幂等 bug):单串 command 内嵌一次 vigil-hub wrap、args 空 →
        // has_sentinel 基于空 args 为 false,AlreadyWrapped/#15 漏判;拆分后 program 命中 vigil-hub →
        // Skipped,绝不二次 wrap。
        let cfg = json!({"mcpServers": {
            "selfwrap": {"command": "vigil-hub wrap --server-id x --vigil-managed-mcp -- npx y", "args": []}
        }});
        let c = classify_user_scope_servers(&cfg);
        assert!(
            matches!(c[0], McpServerClass::Skipped { .. }),
            "single-string vigil-hub wrap must be Skipped (no double-wrap), got {:?}",
            c[0]
        );
        // 单串 vigil-hub serve(网关自身)同理 → Skipped(否则 wrap 包住自己的 serve)。
        let cfg2 = json!({"mcpServers": {
            "selfserve": {"command": "/usr/local/bin/vigil-hub serve --stdio", "args": []}
        }});
        let c2 = classify_user_scope_servers(&cfg2);
        assert!(
            matches!(c2[0], McpServerClass::Skipped { .. }),
            "single-string vigil-hub serve must be Skipped, got {:?}",
            c2[0]
        );
    }

    #[test]
    fn single_token_command_with_trailing_space_is_trimmed() {
        // (c)(Codex CONFIRM):单 token 带尾随空白 → else 分支 trim,不拿 "npx " 当 argv0 执行 ENOENT。
        let cfg = json!({"mcpServers": {"t": {"command": "npx ", "args": []}}});
        let c = classify_user_scope_servers(&cfg);
        if let McpServerClass::Wrappable { command, .. } = &c[0] {
            assert_eq!(
                command, "npx",
                "trailing space must be trimmed from single-token command"
            );
        } else {
            panic!("expected Wrappable, got {:?}", c[0]);
        }
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
        // mcpServers 形状异常(数组而非对象):classify 纯函数层容错空、不 panic ——
        // 但 IO 入口(run_preview/apply/uninstall 等)已先经 ensure_mcp_root_shape **abort**,
        // 生产路径绝不把类型错静默当"无 server"(见 mcp_root_shape_type_error_aborts)。
        assert!(classify_user_scope_servers(&json!({"mcpServers": []})).is_empty());
    }

    #[test]
    fn mcp_root_shape_type_error_aborts() {
        // review 2026-07-17 MED-1:`mcpServers` **存在但类型错** → 所有 IO 入口 abort
        // (UnsupportedConfigShape),绝不静默当"没有 server"(fail-open)。键不存在仍是合法未配置。
        let p = Path::new("/x/.claude.json");
        assert!(ensure_mcp_root_shape(&json!({}), p).is_ok());
        assert!(ensure_mcp_root_shape(&json!({"mcpServers": {}}), p).is_ok());
        for bad in [
            json!({"mcpServers": []}),
            json!({"mcpServers": "oops"}),
            json!({"mcpServers": 3}),
            json!([1, 2]),
            json!({"projects": "oops"}),
            json!({"projects": {"/p": {"mcpServers": []}}}),
        ] {
            assert!(
                matches!(
                    ensure_mcp_root_shape(&bad, p),
                    Err(SetupError::UnsupportedConfigShape { .. })
                ),
                "type-broken root shape must abort, got Ok for {bad}"
            );
        }
        // IO 入口真接线(fixture):preview / apply / uninstall 全部 abort,文件一字不动。
        let td = tempfile::TempDir::new().unwrap();
        let home = td.path();
        let raw = json!({"mcpServers": []}).to_string();
        std::fs::write(home.join(".claude.json"), &raw).unwrap();
        assert!(run_preview(home, "vigil-hub", true).is_err());
        assert!(run_apply(home, "vigil-hub", false, false, true).is_err());
        assert!(run_uninstall(home, false).is_err());
        assert_eq!(
            std::fs::read_to_string(home.join(".claude.json")).unwrap(),
            raw,
            "aborted run must leave the file byte-identical"
        );
        // JSON-agent 面同纪律。
        std::fs::create_dir_all(home.join(".cursor")).unwrap();
        std::fs::write(home.join(".cursor").join("mcp.json"), &raw).unwrap();
        let agent = JsonMcpAgent::cursor(home);
        assert!(run_json_agent_preview(&agent, "vigil-hub", true).is_err());
        assert!(run_json_agent_apply(&agent, "vigil-hub", false, true).is_err());
        assert!(run_json_agent_uninstall(&agent, false).is_err());
    }

    #[test]
    fn codex_root_shape_type_error_aborts_and_inline_table_is_supported() {
        // review 2026-07-17 MED-1(Codex 侧):`mcp_servers` 存在但非 table-like → abort;
        // 内联表 `mcp_servers = {..}` 是合法 TOML,**必须**被枚举(此前被静默当 0 项 = 漏保护)。
        let td = tempfile::TempDir::new().unwrap();
        let home = td.path();
        std::fs::create_dir_all(home.join(".codex")).unwrap();
        let p = home.join(".codex").join("config.toml");
        // 非 table-like → abort。
        std::fs::write(&p, "mcp_servers = 3\n").unwrap();
        assert!(run_codex_preview(home, None, "vigil-hub", true).is_err());
        assert!(run_codex_apply(home, None, "vigil-hub", false, true).is_err());
        // 内联表 → 正常枚举 + wrap。
        std::fs::write(
            &p,
            "mcp_servers = { fs = { command = \"npx\", args = [\"-y\", \"srv\"] } }\n",
        )
        .unwrap();
        let prev = run_codex_preview(home, None, "vigil-hub", true).unwrap();
        assert_eq!(prev.wrappable_count(), 1, "inline table must be enumerated");
        let rep = run_codex_apply(home, None, "vigil-hub", false, true).unwrap();
        assert_eq!(rep.changed, 1, "inline-table entry must be wrappable");
        let after = std::fs::read_to_string(&p).unwrap();
        assert!(after.contains("--vigil-managed-mcp"), "wrapped: {after}");
    }

    #[test]
    fn managed_wrap_grammar_is_symmetric_between_classify_and_unwrap() {
        // review 2026-07-17 HIGH-2:classify 说 AlreadyWrapped ⟺ unwrap 能反解(同一 grammar)。
        // 反例 1:sentinel 不紧邻 `--`(手改插参)→ 不是 AlreadyWrapped,unwrap 也是 None
        //(此前 classify 认、unwrap 不认 → status 报已保护而 uninstall 还原不了 = 假托管态)。
        let drifted = json!({"command": "vigil-hub",
            "args": ["wrap", "--server-id", "x", "--vigil-managed-mcp", "EXTRA", "--", "npx", "y"]});
        assert!(
            !matches!(
                classify_one("d", &drifted),
                McpServerClass::AlreadyWrapped { .. }
            ),
            "sentinel not adjacent to `--` must NOT classify as AlreadyWrapped"
        );
        assert!(unwrap_entry(&drifted).is_none());
        // 反例 2:第三方条目伪造 sentinel(command 非 vigil-hub、args[0]=="wrap"、sentinel 不邻 --)
        // → 当普通 server 正常保护(不再因自带标记逃逸 wrap)。
        let forged = json!({"command": "third-party-tool",
            "args": ["wrap", "--vigil-managed-mcp", "X", "--", "npx", "srv"]});
        assert!(
            matches!(classify_one("f", &forged), McpServerClass::Wrappable { .. }),
            "forged marker with drifted grammar must stay Wrappable, got {:?}",
            classify_one("f", &forged)
        );
        // 正例:Vigil 真实产出的 wrap(sentinel 恒紧邻 --)→ 两边都认,往返成立。
        let argv = wrapped_argv("vigil-hub", "user-x", "npx", &["y".into()], &[], true);
        let real = json!({"command": argv[0],
            "args": argv[1..].iter().map(|s| json!(s)).collect::<Vec<_>>()});
        assert!(matches!(
            classify_one("r", &real),
            McpServerClass::AlreadyWrapped { .. }
        ));
        let restored = unwrap_entry(&real).expect("real wrap must unwrap");
        assert_eq!(restored.get("command").unwrap(), "npx");
    }

    #[test]
    fn wrap_status_reports_config_error_not_zero() {
        // review 2026-07-17 MED-4:配置存在但损坏 → status 三态里是 ConfigError,绝不折叠成 0。
        let td = tempfile::TempDir::new().unwrap();
        let home = td.path();
        std::fs::create_dir_all(home.join(".cursor")).unwrap();
        std::fs::write(home.join(".cursor").join("mcp.json"), "{not json").unwrap();
        let counts = wrapped_server_counts_all_agents(home, &AgentEnv::default());
        let cursor = counts
            .iter()
            .find(|(n, _)| *n == "Cursor")
            .expect("Cursor row");
        assert_eq!(
            cursor.1,
            AgentWrapStatus::ConfigError,
            "broken config must be ConfigError, not Wrapped(0)"
        );
        // 类型错的根形状同样 ConfigError(shape 校验一致过门)。
        std::fs::create_dir_all(home.join(".kimi")).unwrap();
        std::fs::write(
            home.join(".kimi").join("mcp.json"),
            json!({"mcpServers": []}).to_string(),
        )
        .unwrap();
        let counts = wrapped_server_counts_all_agents(home, &AgentEnv::default());
        let kimi = counts
            .iter()
            .find(|(n, _)| *n == "Kimi CLI")
            .expect("Kimi row");
        assert_eq!(kimi.1, AgentWrapStatus::ConfigError);
        // 未配置(无文件)仍是 Wrapped(0):与"配置坏了"可区分。
        let pi = counts.iter().find(|(n, _)| *n == "pi").expect("pi row");
        assert_eq!(pi.1, AgentWrapStatus::Wrapped(0));
    }

    #[test]
    fn json_agent_registry_invariants() {
        // review 2026-07-17 HIGH-3 + MED-2:registry 是唯一清单 —— 前缀/显示名/路径必须两两不同,
        // 前缀必须过构造器门禁(字符集 + 非保留)。**动态遍历** registry,新增 agent 自动被覆盖。
        let home = Path::new("/h");
        let env = AgentEnv {
            codex_home: None,
            pi_agent_dir: None,
        };
        let agents = all_json_mcp_agents(home, &env);
        assert!(agents.len() >= 4, "cursor/windsurf/kimi/pi expected");
        for a in &agents {
            assert!(
                !a.id_prefix.is_empty()
                    && a.id_prefix
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
                "prefix charset: {}",
                a.id_prefix
            );
            assert!(
                !matches!(a.id_prefix, "user" | "local" | "codex"),
                "reserved namespace: {}",
                a.id_prefix
            );
        }
        for i in 0..agents.len() {
            for j in (i + 1)..agents.len() {
                assert_ne!(agents[i].id_prefix, agents[j].id_prefix, "prefix dup");
                assert_ne!(
                    agents[i].display_name, agents[j].display_name,
                    "display dup"
                );
                assert_ne!(
                    agents[i].config_path, agents[j].config_path,
                    "config path dup"
                );
            }
        }
        // 关键成员在场(专项守门:漏加 = 该 agent 全链路无保护)。
        let prefixes: Vec<&str> = agents.iter().map(|a| a.id_prefix).collect();
        for want in ["cursor", "windsurf", "kimi", "pi"] {
            assert!(prefixes.contains(&want), "registry must contain {want}");
        }
    }

    #[test]
    fn preview_and_apply_server_id_agree_for_awkward_names() {
        // review 2026-07-17 MED-6:非法字符名(大写/空格)时 preview 与 apply 的 id 派生必须同源。
        let agent = JsonMcpAgent::cursor(Path::new("/h"));
        for name in ["Playwright", "My Server", "纯中文"] {
            assert_eq!(
                agent.server_id(name),
                json_agent_server_id("cursor", name),
                "preview(json_agent_server_id) and apply(JsonMcpAgent::server_id) must agree"
            );
        }
        // 合法名逐字保留(向后兼容既有账本身份)。
        assert_eq!(agent.server_id("fs"), "cursor-fs");
    }

    #[test]
    fn kimi_and_pi_paths_and_env_override() {
        // C1/C2 接入契约:kimi 固定 ~/.kimi/mcp.json;pi 默认 ~/.pi/agent/mcp.json,
        // 自定义 agent dir(PI_CODING_AGENT_DIR/PI_AGENT_DIR 注入)重定向,`~/` 展开到 home。
        let home = Path::new("/h");
        assert_eq!(
            JsonMcpAgent::kimi(home).config_path,
            home.join(".kimi").join("mcp.json")
        );
        assert_eq!(
            JsonMcpAgent::pi(home, None).config_path,
            home.join(".pi").join("agent").join("mcp.json")
        );
        assert_eq!(
            JsonMcpAgent::pi(home, Some("/custom/pi")).config_path,
            Path::new("/custom/pi").join("mcp.json")
        );
        assert_eq!(
            JsonMcpAgent::pi(home, Some("~/mypi")).config_path,
            home.join("mypi").join("mcp.json")
        );
        assert_eq!(
            JsonMcpAgent::pi(home, Some("   ")).config_path,
            home.join(".pi").join("agent").join("mcp.json"),
            "blank env value falls back to default"
        );
    }

    #[test]
    fn kimi_wrap_roundtrip_and_pi_absent_is_honest_skip() {
        // Kimi:官方文档形状 fixture(stdio + 远程混合)→ wrap 只动 stdio、远程 Skip;uninstall 还原。
        let td = tempfile::TempDir::new().unwrap();
        let home = td.path();
        std::fs::create_dir_all(home.join(".kimi")).unwrap();
        let orig = json!({"mcpServers": {
            "chrome-devtools": {"command": "npx", "args": ["chrome-devtools-mcp@latest"],
                                 "env": {"SOME_VAR": "value"}},
            "context7": {"url": "https://mcp.context7.com/mcp",
                          "headers": {"CONTEXT7_API_KEY": "k"}}
        }});
        std::fs::write(home.join(".kimi").join("mcp.json"), orig.to_string()).unwrap();
        let kimi = JsonMcpAgent::kimi(home);
        let prev = run_json_agent_preview(&kimi, "vigil-hub", true).unwrap();
        assert_eq!(prev.wrappable_count(), 1, "stdio wrappable, remote skipped");
        let rep = run_json_agent_apply(&kimi, "vigil-hub", false, true).unwrap();
        assert_eq!(rep.changed, 1);
        let wrapped: Value = serde_json::from_str(
            &std::fs::read_to_string(home.join(".kimi").join("mcp.json")).unwrap(),
        )
        .unwrap();
        let entry = &wrapped["mcpServers"]["chrome-devtools"];
        assert_eq!(entry["command"], "vigil-hub");
        assert_eq!(entry["args"][2], "kimi-chrome-devtools", "kimi- namespace");
        assert_eq!(
            entry["env"]["SOME_VAR"], "value",
            "env preserved verbatim on the entry"
        );
        assert_eq!(
            wrapped["mcpServers"]["context7"]["url"], "https://mcp.context7.com/mcp",
            "remote entry untouched"
        );
        // uninstall:self-describing 还原(语义等价)。
        let rep2 = run_json_agent_uninstall(&kimi, false).unwrap();
        assert_eq!(rep2.changed, 1);
        let restored: Value = serde_json::from_str(
            &std::fs::read_to_string(home.join(".kimi").join("mcp.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(restored["mcpServers"]["chrome-devtools"]["command"], "npx");
        assert_eq!(
            restored["mcpServers"]["chrome-devtools"]["args"][0],
            "chrome-devtools-mcp@latest"
        );
        // pi:文件不存在 → exists:false + 0 改动 + **绝不创建**文件/目录。
        let pi = JsonMcpAgent::pi(home, None);
        let prev = run_json_agent_preview(&pi, "vigil-hub", true).unwrap();
        assert!(!prev.exists);
        let rep = run_json_agent_apply(&pi, "vigil-hub", false, true).unwrap();
        assert_eq!(rep.changed, 0);
        assert!(
            !home.join(".pi").exists(),
            "absent pi config must never be created"
        );
    }

    #[test]
    fn zcode_nested_key_wrap_roundtrip_preserves_enabled_and_other_settings() {
        // ZCode 契约(2026-07-17 解包 3.3.6 app.asar 核实):`~/.zcode/cli/config.json` 是共享
        // 设置文件,MCP 在 `mcp.servers` 嵌套键;禁用条目带 `enabled:false` 附加键。wrap 必须:
        // 只动 `mcp.servers` 内条目的 command/args;enabled 与文件内其它设置逐字保留;可逆。
        let td = tempfile::TempDir::new().unwrap();
        let home = td.path();
        std::fs::create_dir_all(home.join(".zcode").join("cli")).unwrap();
        let orig = json!({
            "theme": "dark",
            "mcp": {
                "servers": {
                    "memory": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-memory"]},
                    "disabled-one": {"command": "npx", "args": ["srv"], "enabled": false},
                    "remote": {"url": "https://example.com/mcp"}
                },
                "otherMcpSetting": 42
            }
        });
        let p = zcode_config_path(home);
        std::fs::write(&p, orig.to_string()).unwrap();

        let prev = run_zcode_preview(home, "vigil-hub", true).unwrap();
        assert!(prev.exists);
        assert_eq!(prev.id_prefix, "zcode");
        assert_eq!(
            prev.wrappable_count(),
            2,
            "stdio(含 disabled)可保护,remote Skip"
        );

        let rep = run_zcode_apply(home, "vigil-hub", false, true).unwrap();
        assert_eq!(rep.changed, 2);
        let wrapped: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(wrapped["theme"], "dark", "非 MCP 设置逐字保留");
        assert_eq!(wrapped["mcp"]["otherMcpSetting"], 42, "mcp 下其它键保留");
        let mem = &wrapped["mcp"]["servers"]["memory"];
        assert_eq!(mem["command"], "vigil-hub");
        assert_eq!(mem["args"][2], "zcode-memory", "zcode- namespace");
        assert_eq!(
            wrapped["mcp"]["servers"]["disabled-one"]["enabled"], false,
            "enabled:false 附加键逐字保留(wrap 不改变禁用语义)"
        );
        assert_eq!(
            wrapped["mcp"]["servers"]["remote"]["url"], "https://example.com/mcp",
            "远程条目不动"
        );
        // 幂等:再 apply 不二次 wrap。
        let rep_again = run_zcode_apply(home, "vigil-hub", false, true).unwrap();
        assert_eq!(rep_again.changed, 0, "already wrapped must be idempotent");
        // uninstall 还原。
        let rep2 = run_zcode_uninstall(home, false).unwrap();
        assert_eq!(rep2.changed, 2);
        let restored: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(restored["mcp"]["servers"]["memory"]["command"], "npx");
        assert_eq!(
            restored["mcp"]["servers"]["disabled-one"]["enabled"], false,
            "还原后 enabled 仍在"
        );
        assert_eq!(restored["theme"], "dark");
    }

    #[test]
    fn zcode_shape_errors_abort_and_missing_is_honest_skip() {
        // `mcp` / `mcp.servers` 存在但类型错 → abort(ZCode 自身静默 {},Vigil 绝不效仿);
        // 文件不存在 → exists:false,绝不创建。
        let td = tempfile::TempDir::new().unwrap();
        let home = td.path();
        // 不存在:诚实跳过 + 不创建。
        let prev = run_zcode_preview(home, "vigil-hub", true).unwrap();
        assert!(!prev.exists);
        assert_eq!(
            run_zcode_apply(home, "vigil-hub", false, true)
                .unwrap()
                .changed,
            0
        );
        assert!(
            !home.join(".zcode").exists(),
            "must never create the config"
        );
        // 类型错:abort 且文件一字不动。
        std::fs::create_dir_all(home.join(".zcode").join("cli")).unwrap();
        let p = zcode_config_path(home);
        for bad in [
            json!({"mcp": "oops"}).to_string(),
            json!({"mcp": {"servers": []}}).to_string(),
            json!({"mcp": {"servers": "x"}}).to_string(),
        ] {
            std::fs::write(&p, &bad).unwrap();
            assert!(run_zcode_preview(home, "vigil-hub", true).is_err());
            assert!(run_zcode_apply(home, "vigil-hub", false, true).is_err());
            assert!(run_zcode_uninstall(home, false).is_err());
            assert_eq!(std::fs::read_to_string(&p).unwrap(), bad, "file untouched");
        }
        // `mcp` 键缺省 = 未配置,合法(0 项,不报错)。
        std::fs::write(&p, json!({"theme": "dark"}).to_string()).unwrap();
        let prev = run_zcode_preview(home, "vigil-hub", true).unwrap();
        assert!(prev.exists);
        assert_eq!(prev.servers.len(), 0);
        // doctor / counts 覆盖 ZCode 面。
        std::fs::write(
            &p,
            json!({"mcp": {"servers": {"zz": {"command": "npx", "args": []}}}}).to_string(),
        )
        .unwrap();
        let rows = run_doctor(home, &AgentEnv::default(), None).unwrap();
        assert!(
            rows.iter().any(|r| r.scope == "ZCode" && r.name == "zz"),
            "doctor must cover the ZCode surface"
        );
        let counts = wrapped_server_counts_all_agents(home, &AgentEnv::default());
        assert!(
            counts.iter().any(|(n, _)| *n == "ZCode"),
            "status must include the ZCode row"
        );
        // zcode- 前缀与 registry 各前缀 + 保留命名空间不相交(身份塌缩守门)。
        let env = AgentEnv::default();
        for a in all_json_mcp_agents(Path::new("/h"), &env) {
            assert_ne!(
                a.id_prefix, "zcode",
                "zcode prefix reserved for the ZCode lane"
            );
        }
        assert_eq!(
            zcode_scope_server_id("My Srv"),
            json_agent_server_id("zcode", "My Srv"),
            "zcode id derivation must share the same component normalization"
        );
    }

    #[test]
    fn codex_home_env_redirects_all_codex_surfaces() {
        // review 2026-07-17 HIGH-1 守门:自定义 CODEX_HOME 时,MCP 面(preview/apply/doctor/counts)
        // 与 hook 面读写**同一**目录 —— 此前 MCP 面固定 ~/.codex,自定义用户全部 server 漏保护。
        let td = tempfile::TempDir::new().unwrap();
        let home = td.path();
        let custom = home.join("custom-codex-home");
        std::fs::create_dir_all(&custom).unwrap();
        std::fs::write(
            custom.join("config.toml"),
            "[mcp_servers.fs]\ncommand = \"npx\"\nargs = [\"-y\", \"srv\"]\n",
        )
        .unwrap();
        let env_val = custom.to_string_lossy().to_string();
        // 路径解析一致(hook 面 SSOT)。
        assert_eq!(
            codex_config_path(home, Some(&env_val)),
            custom.join("config.toml")
        );
        // 默认 home 下没有配置:不带 env → 未配置;带 env → 找到并可保护。
        assert!(
            !run_codex_preview(home, None, "vigil-hub", true)
                .unwrap()
                .exists
        );
        let prev = run_codex_preview(home, Some(&env_val), "vigil-hub", true).unwrap();
        assert!(prev.exists);
        assert_eq!(prev.wrappable_count(), 1);
        let rep = run_codex_apply(home, Some(&env_val), "vigil-hub", false, true).unwrap();
        assert_eq!(rep.changed, 1);
        // doctor / counts 同样读自定义目录。
        let env = AgentEnv {
            codex_home: Some(env_val.clone()),
            pi_agent_dir: None,
        };
        let rows = run_doctor(home, &env, None).unwrap();
        assert!(
            rows.iter().any(|r| r.scope == "Codex" && r.name == "fs"),
            "doctor must see the custom CODEX_HOME server"
        );
        let counts = wrapped_server_counts_all_agents(home, &env);
        assert!(
            counts
                .iter()
                .any(|(n, st)| *n == "Codex" && *st == AgentWrapStatus::Wrapped(1)),
            "status must count the wrapped server under custom CODEX_HOME, got {counts:?}"
        );
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
    fn vigil_serve_self_entry_is_skipped_not_wrapped() {
        // DEF-002 trigger A:官方文档把 Vigil 暴露为 MCP server 用 `vigil-hub serve --stdio`。
        // 旧逻辑(只认 args[0]=="wrap")把它误判 Wrappable → setup --apply 自我嵌套 wrap(wrap 包 serve)。
        // 现须判 Skipped,绝不 wrap 自身条目。
        let cfg = json!({"mcpServers": {
            "vigil": {"command": "/usr/local/bin/vigil-hub",
                      "args": ["serve", "--stdio", "--ledger", "~/.local/share/Vigil/ledger.sqlite3"]}
        }});
        let c = classify_user_scope_servers(&cfg);
        assert!(
            matches!(c[0], McpServerClass::Skipped { .. }),
            "vigil-hub serve 自指条目须 Skipped(防自我嵌套 wrap);实际 {:?}",
            c[0]
        );
        // 仅**名为** vigil 的第三方 server(command 非 vigil-hub)仍须 Wrappable(不误伤)。
        let cfg2 = json!({"mcpServers": {
            "vigil": {"command": "npx", "args": ["serve", "x"]}
        }});
        assert!(matches!(
            classify_user_scope_servers(&cfg2)[0],
            McpServerClass::Wrappable { .. }
        ));
        // Windows 真二进制 `vigil-hub.exe serve` 也须 Skipped(file_name 精确匹配)。
        let cfg_exe = json!({"mcpServers": {
            "vigil": {"command": "C:/Vigil/vigil-hub.exe", "args": ["serve", "--stdio"]}
        }});
        assert!(matches!(
            classify_user_scope_servers(&cfg_exe)[0],
            McpServerClass::Skipped { .. }
        ));
        // A2 边界:恰名为 `vigil-hub.sh` 的第三方 server 跑 serve **不得**被 Skip(file_stem 会误剥
        // .sh 成 vigil-hub → 漏保护;file_name 精确匹配避免)。须 Wrappable。
        let cfg_sh = json!({"mcpServers": {
            "thirdparty": {"command": "/opt/tools/vigil-hub.sh", "args": ["serve", "--port", "0"]}
        }});
        assert!(
            matches!(
                classify_user_scope_servers(&cfg_sh)[0],
                McpServerClass::Wrappable { .. }
            ),
            "vigil-hub.sh(非 Vigil 真二进制)须 Wrappable,不得 Skip 漏保护;实际 {:?}",
            classify_user_scope_servers(&cfg_sh)[0]
        );
    }

    #[test]
    fn wrapped_from_renamed_binary_is_still_already_wrapped() {
        // DEF-002 trigger B:从改名 / 带版本号的二进制(basename ≠ vigil-hub)写出的 wrap,
        // 再跑 setup 须仍认出 AlreadyWrapped(否则二次 wrap)。判据已放宽为 args[0]=="wrap" + sentinel。
        for cmd in ["/opt/vigil-hub-0.1.4", "/usr/local/bin/vh", "vigilhub"] {
            let cfg = json!({"mcpServers": {
                "fs": {"command": cmd,
                       "args": ["wrap", "--server-id", "fs", "--vigil-managed-mcp", "--", "npx", "x"]}
            }});
            let c = classify_user_scope_servers(&cfg);
            assert!(
                matches!(c[0], McpServerClass::AlreadyWrapped { .. }),
                "改名二进制 {cmd} 写的 wrap 须仍判 AlreadyWrapped(防双包);实际 {:?}",
                c[0]
            );
        }
    }

    #[test]
    fn unwrap_restores_wrap_written_by_renamed_binary() {
        // DEF-002 trigger B 对称:--uninstall 须能还原改名二进制写出的 wrap。
        let wrapped = json!({
            "command": "/opt/vigil-hub-0.1.4",
            "args": ["wrap", "--server-id", "fs", "--vigil-managed-mcp", "--", "npx", "-y", "srv"]
        });
        let restored = unwrap_entry(&wrapped).expect("renamed-binary wrap must be unwrappable");
        assert_eq!(restored.get("command").and_then(Value::as_str), Some("npx"));
        assert_eq!(
            restored
                .get("args")
                .and_then(Value::as_array)
                .map(|a| a.len()),
            Some(2),
            "原 argv [-y, srv] 应逐字还原"
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
    fn invalid_server_name_wrappable_with_valid_derived_id() {
        // F-4 修订:名含网关 server-id 不允许的字符(大写/空格/点/斜杠)不再 Skip ——
        // 派生 id 经 [`server_id_component`] slug 化后必过真验证器,配置键名原样保留。
        // (旧契约「非法名必 Skip」让 Playwright 这类大写命名成规模漏保护。)
        let cfg = json!({"mcpServers": {
            "Filesystem": {"command": "npx", "args": ["a"]},          // 大写
            "my server": {"command": "npx", "args": ["a"]},          // 空格
            "weather.api": {"command": "npx", "args": ["a"]},        // 点
            "a/b": {"command": "npx", "args": ["a"]},                // 斜杠
            "good-name_1": {"command": "npx", "args": ["a"]}         // 合法
        }});
        let c = classify_user_scope_servers(&cfg);
        for n in [
            "Filesystem",
            "my server",
            "weather.api",
            "a/b",
            "good-name_1",
        ] {
            assert!(
                c.iter()
                    .any(|x| matches!(x, McpServerClass::Wrappable { name, .. } if name == n)),
                "名 `{n}` 应 Wrappable(id 由派生函数 slug 化)"
            );
            // 派生 id 必过网关真验证器(原始名不合法时靠 slug + 哈希兜住)
            vigil_mcp::namespace::validate_server_id(&user_scope_server_id(n))
                .unwrap_or_else(|e| panic!("`{n}` 的派生 id 必合法:{e:?}"));
        }
        // 真验证器口径不变:原始非法名裸用仍过不了(slug 收口的必要性)
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
    fn server_id_component_slugs_invalid_names_stably() {
        // 合法名**原样**(既有用户的 server-id 逐字不变 = 向后兼容)。
        assert_eq!(server_id_component("filesystem"), "filesystem");
        assert_eq!(server_id_component("my_srv-2"), "my_srv-2");
        // 大写名(F-4 实测场景 `Playwright`)→ 小写 slug + 8hex 哈希;同名恒同、大小写变体不塌缩。
        let p = server_id_component("Playwright");
        assert!(
            p.starts_with("playwright-") && p.len() == "playwright-".len() + 8,
            "slug+8hex:{p}"
        );
        assert_eq!(p, server_id_component("Playwright"), "同名恒同 id(稳定)");
        assert_ne!(
            p,
            server_id_component("playwright"),
            "大小写变体不得塌缩为同一身份"
        );
        // 全非法字符退化 `srv-<hash>`;空格/点折叠为单个 `-`。
        assert!(server_id_component("数据库").starts_with("srv-"));
        assert!(server_id_component("My Server.v2").starts_with("my-server-v2-"));
        // 一切产物(含前缀拼接后)必过网关真验证器。
        for n in ["Playwright", "My Server.v2", "数据库", "a--B", " x "] {
            let c = server_id_component(n);
            vigil_mcp::namespace::validate_server_id(&c)
                .unwrap_or_else(|e| panic!("slug `{c}` 必合法:{e:?}"));
        }
        vigil_mcp::namespace::validate_server_id(&user_scope_server_id("My Server")).unwrap();
        vigil_mcp::namespace::validate_server_id(&codex_scope_server_id("Chrome DevTools"))
            .unwrap();
    }

    #[test]
    fn classify_accepts_uppercase_server_names_as_wrappable() {
        // F-4:大写名不再 Skip —— 进入可保护集合(id 由派生函数 slug 化,原配置键名不动)。
        let cfg = json!({"mcpServers": {"Playwright":
            {"command": "npx", "args": ["-y", "x"], "type": "stdio"}}});
        let cls = classify_user_scope_servers(&cfg);
        assert_eq!(cls.len(), 1);
        assert!(
            matches!(&cls[0], McpServerClass::Wrappable { name, .. } if name == "Playwright"),
            "大写名应 Wrappable,got {cls:?}"
        );
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

        let rows = run_doctor(home, &AgentEnv::default(), None).unwrap();
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
        let rows = run_doctor(home, &AgentEnv::default(), None).unwrap();
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
        assert!(run_doctor(dir.path(), &AgentEnv::default(), None)
            .unwrap()
            .is_empty());
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
        let rep = run_codex_apply(home, None, "vigil-hub", false, true).unwrap();
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
        let rep2 = run_codex_uninstall(home, None, false).unwrap();
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
            run_codex_apply(home, None, "vigil-hub", false, true)
                .unwrap()
                .changed,
            1
        );
        assert_eq!(
            run_codex_apply(home, None, "vigil-hub", false, true)
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
            run_codex_apply(home, None, "vigil-hub", false, true),
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
        let rep = run_codex_apply(home, None, "vigil-hub", false, true).unwrap();
        assert_eq!(rep.changed, 0);
        assert!(rep.backup.is_none());
        assert!(
            !run_codex_preview(home, None, "vigil-hub", true)
                .unwrap()
                .exists
        );
    }

    /// 非法 server 名(含大写 / 点)→ Wrappable(F-4 修订:id 经 slug 化派生,不再要求用户改名)。
    #[test]
    fn codex_invalid_server_name_wrappable_with_valid_id() {
        let doc = "[mcp_servers.\"Bad.Name\"]\ncommand = \"npx\"\nargs = [\"x\"]\n"
            .parse::<DocumentMut>()
            .unwrap();
        let classes = classify_codex_servers(&doc);
        assert_eq!(classes.len(), 1);
        assert!(
            matches!(&classes[0], McpServerClass::Wrappable { name, .. } if name == "Bad.Name"),
            "非法名应 Wrappable,got {classes:?}"
        );
        vigil_mcp::namespace::validate_server_id(&codex_scope_server_id("Bad.Name")).unwrap();
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
    fn doctor_covers_all_agents() {
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
        // Kimi CLI(JSON)
        fs::create_dir_all(home.join(".kimi")).unwrap();
        fs::write(
            home.join(".kimi").join("mcp.json"),
            json!({"mcpServers": {"km": {"command": real_str, "args": []}}}).to_string(),
        )
        .unwrap();
        // pi(JSON,pi-mcp-adapter 约定路径)
        fs::create_dir_all(home.join(".pi").join("agent")).unwrap();
        fs::write(
            home.join(".pi").join("agent").join("mcp.json"),
            json!({"mcpServers": {"pp": {"command": real_str, "args": []}}}).to_string(),
        )
        .unwrap();

        let rows = run_doctor(home, &AgentEnv::default(), None).unwrap();
        let scope_of = |n: &str| rows.iter().find(|r| r.name == n).map(|r| r.scope.as_str());
        assert_eq!(scope_of("cl"), Some("user"), "Claude user scope");
        assert_eq!(scope_of("cx"), Some("Codex"));
        assert_eq!(scope_of("cu"), Some("Cursor"));
        assert_eq!(scope_of("ws"), Some("Windsurf"));
        assert_eq!(scope_of("km"), Some("Kimi CLI"));
        assert_eq!(scope_of("pp"), Some("pi"));
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
        let rows = run_doctor(home, &AgentEnv::default(), None).unwrap();
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

        let rows = run_doctor(home, &AgentEnv::default(), None).unwrap(); // 不 abort
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
            run_doctor(home, &AgentEnv::default(), None),
            Err(SetupError::MalformedConfig { .. })
        ));
    }
}
