//! 命令帮助文本本地化:运行时把 clap [`Command`] 树的 about / long_about / arg-help
//! 改写为目标语言、且**贴切**(以用户收益为先、去内部黑话)的文案。
//!
//! # 为什么在运行时改写,而非 derive doc 注释
//! clap derive 把 `///` doc 注释在**编译期**烘进帮助文本,无法按运行时 locale 切换。
//! 故源码里的 `///` 仍是面向开发者的中文实现注释(密集、含 ADR / 内部术语),而**用户**
//! 看到的帮助由本模块在 `parse` 前用 builder API 整体覆盖 —— 实现注释与用户文案彻底分离。
//!
//! # 安全契约
//! 本模块**只**改展示文本([`Command::about`] / [`Command::long_about`] /
//! [`Arg::help`](clap::Arg::help)),**绝不**改子命令名、flag 名、arg id、value 解析 ——
//! 那些是 hook / setup / agent 注册依赖的稳定契约。`localize` 末尾的测试用
//! [`Command::debug_assert`] + 渲染断言守住"改写后命令结构不变、且文案确实生效"。
//!
//! # 维护
//! 每个命令一个 `localize_*` 函数,中 / 英文案经 [`s`] 内联并排,便于对照与同步。
//! 多行 long_about 用 [`concat!`] 拼接,保持源码可读。

use clap::{Arg, Command};

use super::Lang;

/// 按语言取文案(把中 / 英并排写在调用点)。
fn s(lang: Lang, en: &'static str, zh: &'static str) -> String {
    match lang {
        Lang::En => en.to_string(),
        Lang::Zh => zh.to_string(),
    }
}

/// 给某命令的一个 arg 覆盖 help 文本(arg id = derive 字段名)。
fn arg_help(cmd: Command, id: &str, lang: Lang, en: &'static str, zh: &'static str) -> Command {
    cmd.mut_arg(id, |a: Arg| a.help(s(lang, en, zh)))
}

/// 同 [`arg_help`],但额外隐藏 clap 为 ValueEnum 自动展示的「Possible values」块 —— 那些块取自
/// enum 变体的开发者 doc 注释(密集、含内部术语、且未本地化,EN 下会泄漏中文,且正是用户嫌"太
/// 抽象"的文本)。arg help 本身已含简洁取值说明;隐藏只影响 `--help` 展示,**不**影响解析,也**不**
/// 影响非法值报错(clap 报错仍会列出合法取值)。
fn arg_help_enum(
    cmd: Command,
    id: &str,
    lang: Lang,
    en: &'static str,
    zh: &'static str,
) -> Command {
    cmd.mut_arg(id, |a: Arg| {
        a.help(s(lang, en, zh)).hide_possible_values(true)
    })
}

/// 本地化整棵 `vigil-hub` 命令树(root + 子命令 + 嵌套子命令 + 各 arg)。
/// 在 `Cli::parse` 前对 `Cli::command()` 调用一次。
pub fn localize(cmd: Command, lang: Lang) -> Command {
    let cmd = cmd
        .about(s(
            lang,
            "A local security gateway that keeps secrets & private data out of your AI agents",
            "把密钥与隐私数据挡在 AI agent 之外的本地安全网关",
        ))
        .long_about(s(
            lang,
            concat!(
                "Vigil sits between your AI coding agents (Claude Code, Codex, Cursor, ...) and the\n",
                "tools and servers they call. It blocks raw secrets, redacts private data before it\n",
                "can reach a model, and records everything in a tamper-evident local audit trail --\n",
                "all on your machine, nothing leaves it.\n",
                "\n",
                "First time here? Run `vigil-hub quickstart` for a read-only tour of this machine,\n",
                "or `vigil-hub demo` to watch Vigil catch a leaking secret in about 30 seconds.",
            ),
            concat!(
                "Vigil 位于你的 AI 编码 agent(Claude Code、Codex、Cursor 等)与它们调用的工具 /\n",
                "服务器之间:拦下明文密钥,在数据抵达模型前脱敏隐私信息,并把一切记入防篡改的\n",
                "本地审计链 —— 全程在本机,数据不外泄。\n",
                "\n",
                "第一次用?运行 `vigil-hub quickstart` 对本机做一次只读巡检,或 `vigil-hub demo`\n",
                "约 30 秒看 Vigil 当场拦下一次密钥外泄。",
            ),
        ));

    cmd.mut_subcommand("add-remote-mcp", |c| localize_add_remote(c, lang))
        .mut_subcommand("serve", |c| localize_serve(c, lang))
        .mut_subcommand("demo", |c| localize_demo(c, lang))
        .mut_subcommand("hook", |c| localize_hook(c, lang))
        .mut_subcommand("setup", |c| localize_setup(c, lang))
        .mut_subcommand("wrap", |c| localize_wrap(c, lang))
        .mut_subcommand("checkpoint", |c| localize_checkpoint(c, lang))
        .mut_subcommand("verify", |c| localize_verify(c, lang))
        .mut_subcommand("quickstart", |c| localize_quickstart(c, lang))
        .mut_subcommand("posture", |c| localize_posture(c, lang))
        .mut_subcommand("engine", |c| localize_engine(c, lang))
        .mut_subcommand("daemon", |c| localize_daemon(c, lang))
        .mut_subcommand("model", |c| localize_model(c, lang))
        .mut_subcommand("inspect", |c| localize_inspect(c, lang))
}

/// `inspect`(只读审计查看;公开仓独有命令)。仅本地化顶层 about / long_about —— 子命令
/// (activity / search / approvals / verify-chain / protection 等)与其参数的深度本地化为
/// 后续增量(inspect 是 advanced 审计面,非首跑 onboarding 路径)。
fn localize_inspect(c: Command, lang: Lang) -> Command {
    c.about(s(
        lang,
        "Read-only view of what Vigil caught -- aggregated from the persisted audit ledger",
        "只读查看 Vigil 拦了什么 —— 基于已持久化的审计账本聚合",
    ))
    .long_about(s(
        lang,
        concat!(
            "Read-only inspection of the persisted audit ledger -- \"see your protection\"\n",
            "after an agent has run:\n",
            "  protection    summary: raw secrets blocked / leaks re-redacted / chain health\n",
            "  activity      recent event stream\n",
            "  search        full-text search over events\n",
            "  approvals     the approval queue\n",
            "  verify-chain  validate the audit hash chain\n",
            "\n",
            "Reads the same shared ledger as `vigil-hub setup` / `hook` (override with --db-path).",
        ),
        concat!(
            "对已持久化审计账本的只读查看 —— 用过 agent 后\"看见保护\":\n",
            "  protection    汇总:拦了多少裸 secret / 脱敏了多少泄漏 / 哈希链是否完整\n",
            "  activity      最近事件流\n",
            "  search        事件全文检索\n",
            "  approvals     审批队列\n",
            "  verify-chain  校验审计哈希链\n",
            "\n",
            "读取与 `vigil-hub setup` / `hook` 同一个共享账本(可用 --db-path 覆盖)。",
        ),
    ))
}

fn localize_add_remote(c: Command, lang: Lang) -> Command {
    let c = c
        .about(s(
            lang,
            "Connect a remote (HTTP) MCP server and sign in with OAuth in your browser",
            "接入一个远程(HTTP)MCP 服务器,并在浏览器里用 OAuth 完成登录授权",
        ))
        .long_about(s(
            lang,
            concat!(
                "Registers a remote MCP server and runs the OAuth sign-in for you: Vigil opens your\n",
                "browser, catches the redirect on a loopback port, and stores the token securely in\n",
                "the OS keychain -- so your agent can use the server without you pasting any keys.\n",
                "\n",
                "Example:\n",
                "  vigil-hub add-remote-mcp --url https://mcp.example.com/ \\\n",
                "    --client-id my-app --scopes mcp:tools.read,mcp:tools.write",
            ),
            concat!(
                "注册一个远程 MCP 服务器,并替你完成 OAuth 登录:Vigil 打开你的浏览器,在 loopback\n",
                "端口接住回调,并把 token 安全存入操作系统钥匙串 —— 这样 agent 就能用上该服务器,\n",
                "你无需手动粘贴任何密钥。\n",
                "\n",
                "示例:\n",
                "  vigil-hub add-remote-mcp --url https://mcp.example.com/ \\\n",
                "    --client-id my-app --scopes mcp:tools.read,mcp:tools.write",
            ),
        ));
    let c = arg_help(
        c,
        "url",
        lang,
        "Base URL of the remote MCP server, e.g. https://mcp.example.com/",
        "远程 MCP 服务器的 base URL,例如 https://mcp.example.com/",
    );
    let c = arg_help(
        c,
        "client_id",
        lang,
        "OAuth client id (a public client -- no secret)",
        "OAuth client_id(公共 client,无 secret)",
    );
    let c = arg_help(
        c,
        "scopes",
        lang,
        "Comma-separated scopes to request, e.g. mcp:tools.read,mcp:tools.write",
        "请求的 scope 列表,逗号分隔,例如 mcp:tools.read,mcp:tools.write",
    );
    let c = arg_help(
        c,
        "ledger",
        lang,
        "Where to store the audit ledger (default: ./vigil.db)",
        "审计账本(SQLite)存放路径(默认 ./vigil.db)",
    );
    arg_help(
        c,
        "timeout_secs",
        lang,
        "Seconds to wait for the browser sign-in to complete (default: 60)",
        "等待浏览器登录回调的超时秒数(默认 60)",
    )
}

fn localize_serve(c: Command, lang: Lang) -> Command {
    let c = c
        .about(s(
            lang,
            "Run Vigil as a local MCP server your agent connects to (Claude Code, Codex, Cursor...)",
            "把 Vigil 作为本地 MCP 服务器运行,供 agent 连接(Claude Code、Codex、Cursor 等)",
        ))
        .long_about(s(
            lang,
            concat!(
                "Exposes Vigil as an MCP server over stdio. Point your agent's MCP config at it and\n",
                "every tool call flows through Vigil's firewall, redaction, approval and audit.\n",
                "\n",
                "Example entry in your agent's MCP config:\n",
                "  {\"vigil\": {\"command\": \"vigil-hub\",\n",
                "             \"args\": [\"serve\", \"--stdio\", \"--ledger\", \"C:\\\\Vigil\\\\ledger.sqlite\"]}}",
            ),
            concat!(
                "把 Vigil 作为 MCP 服务器经 stdio 暴露出来。把你的 agent 的 MCP 配置指向它,之后\n",
                "每一次工具调用都会先经过 Vigil 的防火墙、脱敏、审批、审计这几道处理。\n",
                "\n",
                "在 agent 的 MCP 配置里的示例条目:\n",
                "  {\"vigil\": {\"command\": \"vigil-hub\",\n",
                "             \"args\": [\"serve\", \"--stdio\", \"--ledger\", \"C:\\\\Vigil\\\\ledger.sqlite\"]}}",
            ),
        ));
    let c = arg_help(
        c,
        "stdio",
        lang,
        "Use the stdio transport (required -- the only transport for now)",
        "使用 stdio 通道(必需 —— 目前唯一支持的通道)",
    );
    let c = arg_help(
        c,
        "ledger",
        lang,
        "Persist the audit trail to this SQLite file (omit = in-memory, smoke-test only)",
        "把审计链持久化到该 SQLite 文件(省略 = 内存账本,仅供冒烟测试)",
    );
    let c = arg_help(
        c,
        "upstream_config",
        lang,
        "JSON file describing the upstream MCP servers to attach",
        "描述要挂载的上游 MCP 服务器的 JSON 配置文件",
    );
    let c = arg_help(
        c,
        "auto_approve_first_seen",
        lang,
        "Dev only: auto-approve the first descriptor seen (never use in production)",
        "仅开发:自动批准首次出现的工具描述符(descriptor)(生产务必关闭)",
    );
    let c = arg_help(
        c,
        "dev_permissive_firewall",
        lang,
        "Dev only: let unmatched compute-only tools through instead of default-deny (never in production)",
        "仅开发:对未命中规则的纯计算类工具予以放行,而非默认拒绝(生产务必关闭)",
    );
    let c = arg_help(
        c,
        "enable_privacy_filter",
        lang,
        "Turn on the ML private-data filter (needs an ML build + an installed model)",
        "开启 ML 隐私数据过滤器(需 ML 构建变体 + 已安装模型)",
    );
    let c = arg_help(
        c,
        "redact_tool_results",
        lang,
        "Redact secrets found in a tool's response before returning it to the model",
        "把工具响应里命中的密钥脱敏后,再返回给模型",
    );
    let c = arg_help(
        c,
        "project_root",
        lang,
        "Project boundary root(s) for file-access rules (repeatable; default: current directory)",
        "项目根目录,作为文件访问规则的边界(可多次指定;默认当前目录)",
    );
    let c = arg_help(
        c,
        "enable_injection_classifier",
        lang,
        "Turn on the ML prompt-injection detector (needs an ML build; it flags risk, never blocks)",
        "开启 ML 提示注入检测器(需 ML 构建;只标记风险,绝不拦截)",
    );
    arg_help_enum(
        c,
        "engine",
        lang,
        "Detection engine: hardfp (rules only) | ml (require ML) | auto (ML if ready, else rules)",
        "检测引擎:hardfp(仅硬规则)| ml(强制 ML)| auto(就绪则用 ML,否则降级规则)",
    )
}

fn localize_demo(c: Command, lang: Lang) -> Command {
    let c = c
        .about(s(
            lang,
            "See Vigil block a leaking secret in ~30s -- no account, no network, nothing to set up",
            "约 30 秒看 Vigil 当场拦下一次密钥外泄 —— 无需账号、不联网、零配置",
        ))
        .long_about(s(
            lang,
            concat!(
                "A guided, self-contained walkthrough. It runs Vigil's real firewall, redaction and\n",
                "audit code against a planted scenario, simulating only the model/tool on the other\n",
                "end -- no LLM is ever contacted and no real credentials are used.\n",
                "\n",
                "Add --tamper to also alter an audit row and watch verification FAIL (proof it's real).",
            ),
            concat!(
                "一段有引导、自包含的演示。它对一个预置场景跑 Vigil 真实的防火墙、脱敏与审计代码,\n",
                "只模拟另一端的模型 / 工具 —— 全程不联系任何 LLM,也不使用任何真实凭据。\n",
                "\n",
                "加 --tamper 还会篡改一条账本行,让你看到校验失败(证明它是真的、可证伪)。",
            ),
        ));
    arg_help(
        c,
        "tamper",
        lang,
        "Also alter one audit row and re-verify, proving tampering is detected",
        "额外篡改一条账本行并重新校验,证明篡改会被检测到(可证伪)",
    )
}

fn localize_hook(c: Command, lang: Lang) -> Command {
    let c = c
        .about(s(
            lang,
            "Guard an agent's tool calls (PreToolUse): block any that carry a raw secret",
            "守护 agent 的工具调用(PreToolUse):拦下任何夹带明文密钥的调用",
        ))
        .long_about(s(
            lang,
            concat!(
                "A PreToolUse hook for agent CLIs. It reads one tool-call event from stdin and, if the\n",
                "call carries a raw secret, blocks it (fail-closed) and records it; clean calls pass\n",
                "through with near-zero overhead.\n",
                "\n",
                "Usually registered for you by `vigil-hub setup`. Supports Claude Code (the default)\n",
                "and Codex / Gemini / Cursor via --cli.",
            ),
            concat!(
                "agent CLI 的 PreToolUse 钩子(hook):在每次工具调用前触发。它从 stdin 读取该次调用,\n",
                "若其中夹带明文密钥,就 fail-closed 拦下并记录;干净的调用以近乎零开销放行。\n",
                "\n",
                "通常由 `vigil-hub setup` 替你注册。支持 Claude Code(默认),以及经 --cli 指定的\n",
                "Codex / Gemini / Cursor。",
            ),
        ));
    let c = arg_help(
        c,
        "ledger",
        lang,
        "Audit ledger path (same file as serve, to keep one continuous trail; omit = no audit)",
        "审计账本路径(与 serve 同一文件以保持审计链连续;省略 = 不审计)",
    );
    let c = arg_help_enum(
        c,
        "cli",
        lang,
        "Which agent CLI sent the event (shapes the deny output): claude (default) | codex | gemini | cursor",
        "事件来自哪个 agent CLI(决定 deny 输出形状):claude(默认)| codex | gemini | cursor",
    );
    let c = arg_help(
        c,
        "inject",
        lang,
        "Resolve `secret://<alias>` placeholders to real values at the execution boundary (Claude only)",
        "在执行边界把 `secret://<alias>` 占位符解析为真值(仅 Claude 支持)",
    );
    let c = arg_help(
        c,
        "secrets",
        lang,
        "JSON map of alias -> secret reference for --inject (contains no real values)",
        "--inject 用的 alias→secret 引用映射(JSON;不含任何真值)",
    );
    let c = arg_help(
        c,
        "inject_ttl_secs",
        lang,
        "TTL (seconds) for the one-shot injection lease (default: 300)",
        "一次性注入租约的 TTL 秒数(默认 300)",
    );
    arg_help(
        c,
        "redact_results",
        lang,
        "Redact hard-fingerprint secrets in a tool's result before the model sees it (Claude only)",
        "在模型看到前,把工具结果里能识别出的密钥脱敏(仅 Claude 生效)",
    )
}

fn localize_setup(c: Command, lang: Lang) -> Command {
    let c = c
        .about(s(
            lang,
            "Turn on protection: wire Vigil into your installed AI agents (download -> run -> protected)",
            "一键开启防护:把 Vigil 接入你已装的 AI agent(下载 → 运行一次 → 直接受保护)",
        ))
        .long_about(s(
            lang,
            concat!(
                "Wires Vigil into the AI agents already on this machine, so protection is on without\n",
                "hand-editing any config files.\n",
                "\n",
                "  vigil-hub setup              register the native-tool secret guard (Claude Code)\n",
                "  vigil-hub setup --all        also put your MCP servers behind the Vigil gateway\n",
                "  vigil-hub setup --mcp        preview the MCP changes first (writes nothing)\n",
                "  vigil-hub setup --status     report what's protected + run a self-test\n",
                "  vigil-hub setup --uninstall  cleanly remove everything Vigil added",
            ),
            concat!(
                "把 Vigil 接入本机已安装的 AI agent,无需手改任何配置文件即可开启防护。\n",
                "\n",
                "  vigil-hub setup              注册原生工具的密钥守卫(Claude Code)\n",
                "  vigil-hub setup --all        再把你的 MCP 服务器也纳入 Vigil 网关防护\n",
                "  vigil-hub setup --mcp        先预览 MCP 改动(不写任何文件)\n",
                "  vigil-hub setup --status     报告哪些已受保护 + 跑一次自检\n",
                "  vigil-hub setup --uninstall  干净移除 Vigil 添加的一切",
            ),
        ));
    let c = arg_help(
        c,
        "uninstall",
        lang,
        "Remove the protection Vigil added (only Vigil's own entries)",
        "移除 Vigil 添加的防护(仅 Vigil 自己的条目,不动你其它配置)",
    );
    let c = arg_help(
        c,
        "status",
        lang,
        "Report current protection + run a self-test (a fake credential is blocked)",
        "报告当前防护状态,并跑一次自检(用一个假凭据验证它确实被拦)",
    );
    let c = arg_help(
        c,
        "dry_run",
        lang,
        "Show the changes without writing anything",
        "只展示将做的改动,不写盘",
    );
    let c = arg_help(
        c,
        "ledger",
        lang,
        "Override the audit ledger path",
        "覆盖审计账本路径",
    );
    let c = arg_help(
        c,
        "mcp",
        lang,
        "Act on MCP servers: put them behind the Vigil gateway (preview unless --apply)",
        "作用于 MCP 服务器:把它们纳入 Vigil 网关防护(默认预览,除非加 --apply)",
    );
    let c = arg_help(
        c,
        "apply",
        lang,
        "With --mcp: actually write the changes (atomic, backed up, reversible)",
        "配合 --mcp:真正写入改动(原子写 + 备份 + 可逆)",
    );
    let c = arg_help(
        c,
        "user_scope_only",
        lang,
        "With --mcp --apply: protect only user-scope servers, skip per-project ones",
        "配合 --mcp --apply:只保护用户级(user)服务器,跳过各项目本地(local)的服务器",
    );
    let c = arg_help(
        c,
        "enforce",
        lang,
        "With --mcp: hard-block (default-deny) instead of the default monitor posture",
        "配合 --mcp:改用严格模式(默认拒绝放行),取代默认的观察模式(monitor)",
    );
    let c = arg_help(
        c,
        "doctor",
        lang,
        "With --mcp: health-check that each server's program can actually launch",
        "配合 --mcp:逐个检查每个 server 的底层程序是否确实能启动",
    );
    let c = arg_help(
        c,
        "probe",
        lang,
        "With --doctor: also start each server briefly to test a real MCP handshake (has side effects)",
        "配合 --doctor:再短暂启动每个 server 测真 MCP 握手(有副作用)",
    );
    arg_help(
        c,
        "all",
        lang,
        "Protect everything in one shot: the native-tool hook + the MCP gateway",
        "一条命令全保护:原生工具 hook + MCP 网关一次完成",
    )
}

fn localize_wrap(c: Command, lang: Lang) -> Command {
    let c = c
        .about(s(
            lang,
            "Put an existing MCP server behind Vigil, transparently (redaction + approval + audit)",
            "把一个现有 MCP 服务器透明地纳入 Vigil 防护(脱敏 + 审批 + 审计)",
        ))
        .long_about(s(
            lang,
            concat!(
                "A transparent stdio shim. Your agent connects to `vigil-hub wrap` exactly as if it\n",
                "were the original server, while Vigil guards every call in between.\n",
                "\n",
                "Example (in your agent's MCP config, set command=vigil-hub and prefix the args):\n",
                "  vigil-hub wrap -- npx -y @modelcontextprotocol/server-filesystem /data\n",
                "\n",
                "Usually set up for you by `vigil-hub setup --mcp`.",
            ),
            concat!(
                "一个透明的 stdio 垫片。你的 agent 连到 `vigil-hub wrap`,就像直连原始服务器一样,\n",
                "而中间的每一次调用都被 Vigil 守护。\n",
                "\n",
                "示例(在 agent 的 MCP 配置里把 command 改为 vigil-hub,并给原命令加前缀):\n",
                "  vigil-hub wrap -- npx -y @modelcontextprotocol/server-filesystem /data\n",
                "\n",
                "通常由 `vigil-hub setup --mcp` 替你配置好。",
            ),
        ));
    let c = arg_help(
        c,
        "ledger",
        lang,
        "Audit ledger path (default: <data dir>/Vigil/ledger.sqlite3)",
        "审计账本路径(默认 <本机数据目录>/Vigil/ledger.sqlite3)",
    );
    let c = arg_help(
        c,
        "server_id",
        lang,
        "Stable identity for the wrapped server (= its name in the agent config)",
        "被防护 server 的稳定身份 id(= agent 配置里的 server 名)",
    );
    let c = arg_help(
        c,
        "env_key",
        lang,
        "Env var name to forward to the server (repeatable; nothing is forwarded by default)",
        "要转发给 server 的环境变量名(可重复;默认不转发任何变量)",
    );
    let c = arg_help(
        c,
        "inherit_env",
        lang,
        "Forward ALL of this process's environment to the server (only when it truly needs it)",
        "把本进程的全部环境变量转发给 server(仅在确需全量继承时使用)",
    );
    let c = arg_help(
        c,
        "monitor",
        lang,
        "Monitor posture: allow + audit risky calls instead of blocking (recommended for turnkey)",
        "观察模式(monitor):风险调用放行 + 记入审计而不阻断(开箱即用接入时推荐)",
    );
    let c = arg_help(
        c,
        "project_root",
        lang,
        "Project boundary root(s) for file-access rules (repeatable; default: current directory)",
        "项目根目录,作为文件访问规则的边界(可多次指定;默认当前目录)",
    );
    arg_help(
        c,
        "command",
        lang,
        "The MCP server command to wrap, after `--` (e.g. -- npx -y <pkg> /data)",
        "要加 Vigil 防护的 MCP server 命令,放在 `--` 之后(例:-- npx -y <pkg> /data)",
    )
}

fn localize_checkpoint(c: Command, lang: Lang) -> Command {
    let c = c
        .about(s(
            lang,
            "Anchor the audit trail so a full-history rewrite can't go unnoticed",
            "为审计链打锚点,让有人整体改写历史也无所遁形",
        ))
        .long_about(s(
            lang,
            concat!(
                "Writes a snapshot of the current audit-chain head into a separate append-only file\n",
                "(<ledger>.checkpoints). Run it periodically (or from cron): the hash chain alone\n",
                "can't detect a rewrite of the whole history, but these anchors can.\n",
                "\n",
                "Tip: keep the .checkpoints file append-only (Linux: chattr +a; macOS: chflags \
                 uappnd) or sync it offsite (works on every OS, incl. Windows).",
            ),
            concat!(
                "把当前审计链链头的快照写入一个独立的 append-only 文件(<ledger>.checkpoints)。\n",
                "周期运行(或用 cron):仅靠哈希链检不出「整条历史被重写」,但这些锚点可以。\n",
                "\n",
                "提示:把 .checkpoints 文件设为 append-only(Linux:chattr +a;macOS:chflags uappnd)\n",
                "或异地同步(任何系统含 Windows 都适用)。",
            ),
        ));
    arg_help(
        c,
        "ledger",
        lang,
        "Audit ledger path (default: <data dir>/Vigil/ledger.sqlite3)",
        "审计账本路径(默认 <本机数据目录>/Vigil/ledger.sqlite3)",
    )
}

fn localize_verify(c: Command, lang: Lang) -> Command {
    let c = c
        .about(s(
            lang,
            "Check the audit trail for tampering and confirm it matches its anchors",
            "校验审计链是否被篡改,并比对锚点确认一致",
        ))
        .long_about(s(
            lang,
            concat!(
                "Two checks, reported honestly: first the chain's internal consistency (catches an\n",
                "edited row), then the checkpoint anchors (catches a full-history rewrite). Any\n",
                "tampering or corruption exits non-zero, so you can script it. It never creates a\n",
                "ledger -- a missing file is reported, not silently made.",
            ),
            concat!(
                "两道检查、如实汇报:先查链内部一致性(抓「某行被改」),再比对锚点(抓「整条历史\n",
                "被重写」)。任何篡改 / 损坏都以非零码退出,便于脚本化。它绝不创建账本 —— 文件\n",
                "缺失会如实报告,而非悄悄造一个空账本。",
            ),
        ));
    arg_help(
        c,
        "ledger",
        lang,
        "Audit ledger path (default: <data dir>/Vigil/ledger.sqlite3)",
        "审计账本路径(默认 <本机数据目录>/Vigil/ledger.sqlite3)",
    )
}

fn localize_quickstart(c: Command, lang: Lang) -> Command {
    c.about(s(
        lang,
        "New here? See what's protected on this machine and the 3 steps to lock it down (read-only)",
        "第一次用?看看本机哪些已受保护,以及锁紧防护的三步(只读,不改配置)",
    ))
    .long_about(s(
        lang,
        concat!(
            "A read-only tour for first-timers. It detects the AI agents and MCP servers on this\n",
            "machine, shows how many are already behind Vigil, and lays out the next steps: see the\n",
            "demo -> protect everything -> verify. It changes nothing.",
        ),
        concat!(
            "面向新手的只读巡检。它检测本机的 AI agent 与 MCP 服务器,告诉你有多少已经在 Vigil\n",
            "之后,并给出接下来的三步:看 demo → 一键全保护 → 验证。全程不改动任何东西。",
        ),
    ))
}

fn localize_posture(c: Command, lang: Lang) -> Command {
    let c = c
        .about(s(
            lang,
            "View or switch the security posture (low / medium / high)",
            "查看或切换安全姿态(低 / 中 / 高)—— 即对 `secret://` 占位符的拦截力度",
        ))
        .long_about(s(
            lang,
            concat!(
                "Controls how strictly Vigil handles `secret://` placeholders in native tools:\n",
                "  low     let them through (default -- zero friction)\n",
                "  medium  ask you to confirm\n",
                "  high    block them\n",
                "Raw secrets are ALWAYS blocked at every level -- that hard floor can't be lowered.\n",
                "\n",
                "  vigil-hub posture show\n",
                "  vigil-hub posture set medium",
            ),
            concat!(
                "控制 Vigil 对原生工具里 `secret://` 占位符的处置力度:\n",
                "  low     放行(默认 —— 零摩擦)\n",
                "  medium  交你确认\n",
                "  high    拦截\n",
                "明文密钥在**任何**档位都恒被拦 —— 这条硬底线不可降级。\n",
                "\n",
                "  vigil-hub posture show\n",
                "  vigil-hub posture set medium",
            ),
        ));
    let c = c.mut_subcommand("show", |sc| {
        sc.about(s(lang, "Show the current posture", "显示当前姿态档位"))
    });
    c.mut_subcommand("set", |sc| {
        let sc = sc.about(s(
            lang,
            "Switch to a posture (low / medium / high)",
            "切换到指定姿态档位(低 / 中 / 高)",
        ));
        let sc = arg_help_enum(
            sc,
            "profile",
            lang,
            "Target posture: low | medium | high",
            "目标档位:low | medium | high",
        );
        arg_help(
            sc,
            "ledger",
            lang,
            "Audit ledger to record the change (default: the shared Vigil ledger)",
            "记录本次变更的审计账本(默认共享的 Vigil 账本)",
        )
    })
}

fn localize_engine(c: Command, lang: Lang) -> Command {
    let c = c
        .about(s(
            lang,
            "View or switch the detection engine (hardfp / ml / auto)",
            "查看或切换检测引擎(hardfp / ml / auto)",
        ))
        .long_about(s(
            lang,
            concat!(
                "Selects which detector Vigil uses and persists it for serve / wrap / hook to pick up:\n",
                "  hardfp  fixed-fingerprint rules only (default; what shipped binaries do)\n",
                "  ml      require the ML models (refuses to start if they're missing)\n",
                "  auto    use ML when it's ready, else fall back to rules (never downloads)\n",
                "Actually running ML also needs an ML build (--features ort) + installed models.\n",
                "\n",
                "  vigil-hub engine show\n",
                "  vigil-hub engine set ml",
            ),
            concat!(
                "选择 Vigil 使用哪种检测器并保存,供 serve / wrap / hook 启动时读取生效:\n",
                "  hardfp  仅固定指纹规则(默认;发行二进制的实际行为)\n",
                "  ml      强制使用 ML 模型(缺失则拒绝启动)\n",
                "  auto    就绪时用 ML,否则降级到规则(绝不触发下载)\n",
                "真正跑 ML 还需 ML 构建变体(--features ort)+ 已安装模型。\n",
                "\n",
                "  vigil-hub engine show\n",
                "  vigil-hub engine set ml",
            ),
        ));
    let c = c.mut_subcommand("show", |sc| {
        sc.about(s(lang, "Show the current engine mode", "显示当前引擎模式"))
    });
    c.mut_subcommand("set", |sc| {
        let sc = sc.about(s(
            lang,
            "Switch the engine mode (hardfp / ml / auto)",
            "切换引擎模式(hardfp / ml / auto)",
        ));
        arg_help_enum(
            sc,
            "mode",
            lang,
            "Target mode: hardfp | ml | auto",
            "目标模式:hardfp | ml | auto",
        )
    })
}

fn localize_daemon(c: Command, lang: Lang) -> Command {
    let c = c
        .about(s(
            lang,
            "Start or check the background service that keeps ML models warm for fast checks",
            "启动或查看后台常驻服务 —— 暖载 ML 模型,让检查保持低延迟",
        ))
        .long_about(s(
            lang,
            concat!(
                "Runs a small resident service that pre-loads the ML models so the hook can query\n",
                "them with low latency over a local socket.\n",
                "  start   run it in the foreground (single instance -- exits if already running)\n",
                "  status  check whether it's running\n",
                "  stop    stop it\n",
                "With an ML build + cached models it warms a real scanner; otherwise it runs\n",
                "model-less (the hook falls back to fixed-fingerprint rules).",
            ),
            concat!(
                "运行一个小型常驻服务,预先载入 ML 模型,让 hook 可经本地 socket 低延迟查询。\n",
                "  start   前台运行(单实例 —— 已在运行则退出)\n",
                "  status  查看是否在运行\n",
                "  stop    停止它\n",
                "在 ML 构建 + 模型已缓存时暖载真实扫描器;否则以无模型方式运行\n",
                "(hook 退回固定指纹规则)。",
            ),
        ));
    let c = c.mut_subcommand("start", |sc| {
        sc.about(s(
            lang,
            "Run the daemon in the foreground (single instance)",
            "前台启动 daemon(单实例)",
        ))
    });
    let c = c.mut_subcommand("status", |sc| {
        sc.about(s(
            lang,
            "Check whether the daemon is running",
            "查看 daemon 是否在运行",
        ))
    });
    c.mut_subcommand("stop", |sc| {
        sc.about(s(lang, "Stop the running daemon", "停止正在运行的 daemon"))
    })
}

fn localize_model(c: Command, lang: Lang) -> Command {
    // 非 ML 构建在**顶层命令列表**就标注版本要求(F-14:用户照 help 跑到 `model install`
    // 才被告知要换 ML 变体 = 撞墙式发现)。ML 构建不加噪音。
    let (about_en, about_zh) = if cfg!(feature = "ort") {
        (
            "Download or check the ML models (private-data + injection detectors, ~700MB each)",
            "下载或查看 ML 模型(隐私数据 + 注入检测器,各约 700MB)",
        )
    } else {
        (
            "Download or check the ML models (~700MB each; needs the ML build variant -- \
             this standard binary will point you to it)",
            "下载或查看 ML 模型(各约 700MB;需 ML 版二进制 —— 本标准版会提示你获取)",
        )
    };
    let c = c.about(s(lang, about_en, about_zh)).long_about(s(
        lang,
        concat!(
            "Manages the optional ML models. The turnkey path is:\n",
            "  vigil-hub model install  ->  vigil-hub daemon start  ->  vigil-hub engine set ml\n",
            "\n",
            "  install  download the models (--privacy / --injection to pick one; default both)\n",
            "  status   show whether each model is cached locally\n",
            "Needs an ML build (--features ort); a non-ML binary points you to the ML variant.",
        ),
        concat!(
            "管理可选的 ML 模型。开箱即用的完整流程为:\n",
            "  vigil-hub model install  →  vigil-hub daemon start  →  vigil-hub engine set ml\n",
            "\n",
            "  install  下载模型(--privacy / --injection 只装其一;默认两个都装)\n",
            "  status   查看每个模型是否已在本地缓存\n",
            "需 ML 构建变体(--features ort);非 ML 二进制会提示你改用 ML 变体。",
        ),
    ));
    let c = c.mut_subcommand("install", |sc| {
        let sc = sc.about(s(
            lang,
            "Download the ML models (idempotent -- cached models return instantly)",
            "下载 ML 模型(幂等:已缓存则秒回)",
        ));
        let sc = arg_help(
            sc,
            "privacy",
            lang,
            "Install only the private-data (PII) model",
            "只安装隐私数据(PII)模型",
        );
        arg_help(
            sc,
            "injection",
            lang,
            "Install only the prompt-injection model",
            "只安装提示注入模型",
        )
    });
    c.mut_subcommand("status", |sc| {
        sc.about(s(
            lang,
            "Show whether each model is cached locally",
            "查看每个模型是否已在本地缓存",
        ))
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use clap::{CommandFactory, Parser, Subcommand};
    use std::path::PathBuf;

    /// 最小可解析的镜像 CLI:复刻 `main.rs` 真实命令树的**子命令名 / flag / arg id**
    /// (本测试只验证 `localize` 能命中每个 mut_subcommand / mut_arg —— id 写错会在
    /// `localize` 内 panic,从而被 [`localize_hits_every_subcommand_and_arg`] 抓住)。
    /// 文案内容与真实结构在 main.rs;此处刻意只保留结构以免与生产命令双份维护漂移。
    #[derive(Parser, Debug)]
    #[command(name = "vigil-hub")]
    struct MirrorCli {
        #[command(subcommand)]
        command: Option<MirrorCmd>,
    }

    #[derive(Subcommand, Debug)]
    enum MirrorCmd {
        AddRemoteMcp {
            #[arg(long)]
            url: String,
            #[arg(long)]
            client_id: String,
            #[arg(long, value_delimiter = ',')]
            scopes: Vec<String>,
            #[arg(long, default_value = "vigil.db")]
            ledger: PathBuf,
            #[arg(long, default_value_t = 60u64)]
            timeout_secs: u64,
        },
        Serve {
            #[arg(long)]
            stdio: bool,
            #[arg(long)]
            ledger: Option<PathBuf>,
            #[arg(long = "upstream-config")]
            upstream_config: Option<PathBuf>,
            #[arg(long)]
            auto_approve_first_seen: bool,
            #[arg(long)]
            dev_permissive_firewall: bool,
            #[arg(long = "enable-privacy-filter")]
            enable_privacy_filter: bool,
            #[arg(long = "redact-tool-results")]
            redact_tool_results: bool,
            #[arg(long = "project-root")]
            project_root: Vec<PathBuf>,
            #[arg(long = "enable-injection-classifier")]
            enable_injection_classifier: bool,
            #[arg(long)]
            engine: Option<String>,
        },
        Demo {
            #[arg(long)]
            tamper: bool,
        },
        Hook {
            #[arg(long)]
            ledger: Option<PathBuf>,
            #[arg(long)]
            cli: Option<String>,
            #[arg(long)]
            inject: bool,
            #[arg(long = "secrets")]
            secrets: Option<PathBuf>,
            #[arg(long = "inject-ttl-secs", default_value_t = 300)]
            inject_ttl_secs: i64,
            #[arg(long = "redact-results")]
            redact_results: bool,
        },
        Setup {
            #[arg(long)]
            uninstall: bool,
            #[arg(long)]
            status: bool,
            #[arg(long)]
            dry_run: bool,
            #[arg(long)]
            ledger: Option<PathBuf>,
            #[arg(long = "hook-exe")]
            hook_exe: Option<PathBuf>,
            #[arg(long)]
            json: bool,
            #[arg(long)]
            mcp: bool,
            #[arg(long)]
            apply: bool,
            #[arg(long = "user-scope-only")]
            user_scope_only: bool,
            #[arg(long)]
            enforce: bool,
            #[arg(long)]
            doctor: bool,
            #[arg(long)]
            probe: bool,
            #[arg(long)]
            all: bool,
        },
        Wrap {
            #[arg(long)]
            ledger: Option<PathBuf>,
            #[arg(long = "server-id")]
            server_id: Option<String>,
            #[arg(long = "env-key")]
            env_key: Vec<String>,
            #[arg(long = "inherit-env")]
            inherit_env: bool,
            #[arg(long)]
            monitor: bool,
            #[arg(long = "project-root")]
            project_root: Vec<PathBuf>,
            #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
            command: Vec<String>,
        },
        Checkpoint {
            #[arg(long)]
            ledger: Option<PathBuf>,
        },
        Verify {
            #[arg(long)]
            ledger: Option<PathBuf>,
        },
        Quickstart,
        Posture {
            #[command(subcommand)]
            command: MirrorPosture,
        },
        Engine {
            #[command(subcommand)]
            command: MirrorEngine,
        },
        Daemon {
            #[command(subcommand)]
            command: MirrorDaemon,
        },
        Model {
            #[command(subcommand)]
            command: MirrorModel,
        },
        Inspect,
    }

    #[derive(Subcommand, Debug)]
    enum MirrorPosture {
        Show,
        Set {
            #[arg(value_enum)]
            profile: MirrorEnum,
            #[arg(long)]
            ledger: Option<PathBuf>,
        },
    }
    #[derive(Subcommand, Debug)]
    enum MirrorEngine {
        Show,
        Set {
            #[arg(value_enum)]
            mode: MirrorEnum,
        },
    }
    #[derive(Subcommand, Debug)]
    enum MirrorDaemon {
        Start,
        Status,
        Stop,
    }
    #[derive(Subcommand, Debug)]
    enum MirrorModel {
        Install {
            #[arg(long)]
            privacy: bool,
            #[arg(long)]
            injection: bool,
        },
        Status,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
    enum MirrorEnum {
        Low,
        Medium,
        High,
    }

    /// `localize` 命中每个 mut_subcommand / mut_arg —— 任一 id 写错都会在此 panic;
    /// `debug_assert` 再校验改写后命令结构自洽。两语言各跑一遍。
    #[test]
    fn localize_hits_every_subcommand_and_arg() {
        for lang in [Lang::En, Lang::Zh] {
            let cmd = localize(MirrorCli::command(), lang);
            cmd.debug_assert();
        }
    }

    /// 端到端:改写确实生效(渲染帮助里出现目标语言的标志性短语),且不同语言不同。
    /// 渲染前把 term_width 调到很大,关闭自动折行,保证目标短语逐字出现(尤其无空格的
    /// 中文不会被折行拆断)。
    #[test]
    fn rendered_help_reflects_language() {
        // root long help 展示的是 long_about(非 about),故断言取自 long_about 首句。
        let en_root = render_long(localize(MirrorCli::command(), Lang::En));
        let zh_root = render_long(localize(MirrorCli::command(), Lang::Zh));
        assert!(
            en_root.contains("Vigil sits between your AI coding agents"),
            "EN root long_about missing:\n{en_root}"
        );
        assert!(
            zh_root.contains("Vigil 位于你的 AI 编码 agent"),
            "ZH root long_about missing:\n{zh_root}"
        );
        assert_ne!(en_root, zh_root);

        // 子命令 about 进入 root 帮助的子命令清单(验证 mut_subcommand 生效)。
        assert!(
            en_root.contains("block a leaking secret"),
            "EN root help should list the rewritten demo about:\n{en_root}"
        );
        assert!(
            zh_root.contains("当场拦下一次密钥外泄"),
            "ZH root help should list the rewritten demo about:\n{zh_root}"
        );
    }

    /// 一个子命令的 long_about + arg help 双语生效。
    #[test]
    fn subcommand_long_help_is_localized() {
        let cmd = localize(MirrorCli::command(), Lang::Zh);
        let serve = cmd
            .find_subcommand("serve")
            .expect("serve subcommand exists")
            .clone();
        let help = render_long(serve);
        assert!(
            help.contains("经过 Vigil 的防火墙"),
            "serve ZH long_about missing:\n{help}"
        );
        assert!(
            help.contains("仅供冒烟测试"),
            "serve ZH --ledger arg help missing:\n{help}"
        );
    }

    /// 渲染长帮助;term_width 调大以**关闭折行**,使断言短语逐字保留。
    fn render_long(cmd: Command) -> String {
        let mut cmd = cmd.term_width(10_000);
        cmd.render_long_help().to_string()
    }
}
