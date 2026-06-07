//! Vigil Hub CLI binary —— clap entrypoint,lib 层是 `vigil_hub_cli` crate。
//!
//! I00-I09:占位。
//! I10b-β:`add-remote-mcp` 子命令,串联 PRM discover + loopback OAuth + token persist。
//! v0.3 Stage 1(2026-04-24):`serve` 子命令 —— 把 Hub 暴露为 MCP stdio server,
//! 供 CLI agent(Claude Code / Codex / Cursor / Zed 等)通过 stdio transport 连接。

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use vigil_hub_cli::demo::{self, DemoArgs};
use vigil_hub_cli::hook::{self, HookArgs};
use vigil_hub_cli::inspect::{self, InspectArgs};
use vigil_hub_cli::serve::{self, ServeArgs};
use vigil_hub_cli::setup::{self, SetupArgs};
use vigil_hub_cli::setup_mcp::{self, McpServerClass};
use vigil_hub_cli::wrap::{self, WrapArgs};
use vigil_hub_cli::{add_remote, AddRemoteArgs};

/// Vigil Hub CLI(I10b-β:含 `add-remote-mcp`)。
#[derive(Parser, Debug)]
#[command(name = "vigil-hub", about = "Vigil Hub local proxy + CLI")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// 注册并为一个远程 HTTP MCP server 完成 OAuth(loopback redirect)。
    AddRemoteMcp(CliAddRemoteArgs),
    /// 把 Vigil Hub 暴露为 MCP stdio server;CLI agent 可通过 stdio transport 连接。
    ///
    /// 典型用法(在 agent 侧 MCP 配置):
    /// ```json
    /// {"vigil": {"command": "vigil-hub", "args": ["serve", "--stdio", "--ledger", "C:\\Vigil\\ledger.sqlite"]}}
    /// ```
    Serve(CliServeArgs),
    /// 零设置首次体验:一条命令看完 default-deny 防护 + 可逆脱敏往返 + 防篡改审计。
    ///
    /// 走 Vigil 真实运行时代码(firewall / 脱敏 / 审计),只模拟外部 model/tool;不联系任何 LLM,
    /// 不需账号/key/网络。`--tamper` 额外演示篡改账本被检测(可证伪)。
    Demo(CliDemoArgs),
    /// Claude Code `PreToolUse` hook adapter(P1-α1,guard-only):从 stdin 读 PreToolUse 事件,
    /// 对带 secret 的**原生**工具调用 fail-closed deny(exit 2 + stderr)并审计;干净调用放行(exit 0)。
    ///
    /// settings.json 注册示例(matcher `*` = **所有**工具 —— 裸 secret 纵深防御需覆盖 `mcp__*`,
    /// 故不要把 matcher 限定到 `Bash|Edit|...`,否则 hook 对 MCP 工具根本不触发):
    /// ```json
    /// {"hooks":{"PreToolUse":[{"matcher":"*",
    ///   "hooks":[{"type":"command","command":"vigil-hub hook --ledger C:\\Vigil\\ledger.sqlite"}]}]}}
    /// ```
    /// 注:hook 对**每个**工具调用触发(含 Read);干净调用零开销放行。占位符替换在后续增量加入。
    Hook(CliHookArgs),
    /// 一键接入:把 Vigil 保护写进已装 AI agent 配置,让"下载 → 运行一次 → 直接受保护"成立。
    ///
    /// v1 = 检测 Claude Code → 注册 PreToolUse hook(全工具 secret 守门 + 本地审计)。
    /// `--uninstall` 干净移除;`--status` 报告 + 自检;`--dry-run` 只预览不写盘。
    Setup(CliSetupArgs),
    /// 透明 stdio MCP shim:把一个已存在的 MCP server 命令套上 Vigil 网关(firewall + 脱敏 +
    /// 审批 + 审计)。agent 像直连原 server 一样连 wrap,中间被守护。
    ///
    /// 用法:`vigil-hub wrap -- npx -y @modelcontextprotocol/server-filesystem /data`
    /// (在 agent 的 MCP 配置里把 `command` 改为 `vigil-hub`、args 前缀 `["wrap","--", ...原命令]`)。
    Wrap(CliWrapArgs),
    /// 命令行查询本地审计账本:activity / search / approvals / session / servers / verify-chain。
    ///
    /// 用法:`vigil-hub inspect --db-path ./vigil.db activity --limit 20`。
    Inspect(InspectArgs),
}

#[derive(clap::Args, Debug)]
struct CliDemoArgs {
    /// 额外演示可证伪:篡改一条账本行后真 verify_chain 检测到篡改(失败)。
    #[arg(long)]
    tamper: bool,
}

#[derive(clap::Args, Debug)]
struct CliHookArgs {
    /// 审计账本路径(与 `serve --ledger` 同一文件以保持审计链连续)。
    /// 省略 = 不审计(仍做安全决策;stderr 提示)。
    #[arg(long)]
    ledger: Option<PathBuf>,
    /// 由 `vigil-hub setup` 写入的托管标记(被本命令**忽略**;仅供 setup 识别/卸载其托管条目)。
    #[arg(long = "vigil-managed", hide = true)]
    #[allow(dead_code)]
    // clap 解析后不读取;存在只为接受该 flag,不让 Claude Code 调用报未知参数
    vigil_managed: bool,
}

#[derive(clap::Args, Debug)]
struct CliWrapArgs {
    /// 审计账本路径(默认 `<本机数据目录>/Vigil/ledger.sqlite3`,与 setup/hook/inspect 同一个)。
    #[arg(long)]
    ledger: Option<PathBuf>,
    /// 该被包裹 server 的稳定身份 id(= agent 配置里的 server 名)。缺省由命令 argv 派生(并警告)。
    #[arg(long = "server-id")]
    server_id: Option<String>,
    /// **显式**转发给子进程的 env 键(可重复;= 该 server 配置的 `env{}` 的键)。默认不转发任何 secret。
    #[arg(long = "env-key")]
    env_key: Vec<String>,
    /// 逃生舱:透传 wrap 进程的**全部** env 给子进程(仅确知该 server 本就该拿全量继承 env 时用)。
    #[arg(long = "inherit-env")]
    inherit_env: bool,
    /// **Monitor posture**(opt-in,非阻塞):风险调用自动放行 + 审计,不阻塞(turnkey 无 desktop
    /// resolver 时推荐;否则风险工具阻塞 ~300s 看似卡死)。默认 enforce(阻塞人审批)。
    #[arg(long)]
    monitor: bool,
    /// 由 `vigil-hub setup --mcp` 写入的托管标记(被本命令**忽略**;仅供 setup 识别其托管的 wrap 条目)。
    #[arg(long = "vigil-managed-mcp", hide = true)]
    #[allow(dead_code)]
    vigil_managed_mcp: bool,
    /// 被包裹的 MCP server 命令,放在 `--` 之后(例:`-- npx -y <pkg> /data`)。
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

#[derive(clap::Args, Debug)]
struct CliSetupArgs {
    /// 移除 Vigil 托管配置(仅 Vigil 自己的条目,不动你其它配置)。
    #[arg(long)]
    uninstall: bool,
    /// 报告当前保护状态 + 自检(含合成 fake token 跑真 hook 断言被拦的 smoke test)。
    #[arg(long)]
    status: bool,
    /// 只打印将要做的改动,不写盘。
    #[arg(long)]
    dry_run: bool,
    /// 覆盖审计账本路径(默认 `<本机数据目录>/Vigil/ledger.sqlite3`)。
    #[arg(long)]
    ledger: Option<PathBuf>,
    /// **MCP turnkey**:把 Claude Code(`~/.claude.json`)的 stdio MCP server 改写为 `vigil-hub wrap`
    /// 网关(**默认 monitor 姿态**)。**默认保护 user scope(顶层 mcpServers)+ local scope(`projects.*`,
    /// `claude mcp add` 默认写这里)**;local scope 用项目限定 server-id 防跨项目同名身份塌缩。
    /// `--mcp` 单用 = **只读预览**;`--mcp --apply` 真改写;`--mcp --uninstall` 还原(两 scope);
    /// `--dry-run` 只算不写。
    #[arg(long)]
    mcp: bool,
    /// 配合 `--mcp`:真正改写 `~/.claude.json`(否则 `--mcp` 仅预览)。原子写 + 备份 + 可逆。
    #[arg(long)]
    apply: bool,
    /// 配合 `--mcp --apply`:**只**保护 user scope,显式跳过 local scope(`projects.*`)的 server
    /// (让它们**不被保护**;CLI 会诚实报告被跳过的数量)。默认两个 scope 都保护。
    #[arg(long = "user-scope-only")]
    user_scope_only: bool,
    /// 配合 `--mcp`:把 wrap 网关姿态从默认 **monitor** 升级为 **enforce**(default-deny 硬拦)。
    ///
    /// **为何默认 monitor 而非 enforce**:被 wrap 的是用户自配的**第三方** MCP server,其工具名不在
    /// Vigil 的 effect 提取词表内 → 提取不出 effect → enforce 下一律 default-deny = 真实 server **全部
    /// 不可用**(turnkey 一键接入直接打挂用户现有工作流 = 采用毒药)。monitor 姿态保留全部硬地板
    /// (裸 secret 拦截 + 结果脱敏可逆往返 + 显式 Deny + descriptor drift),只把 default-deny **地板**
    /// 降级为观察放行 —— 实际交付的价值(脱敏 + 审计 + 输入拦截)全在,且 server 可用。Codex 评估
    /// 与三方研究一致(93% 审批被未读即批 → 审批门是剧场;确定性脱敏 >> 阻塞审批)。
    /// 想要硬拦语义(已知工具集 / 自建 server / 高保障场景)再显式 `--enforce`。
    #[arg(long)]
    enforce: bool,
    /// 配合 `--mcp`:**健壮性预检**。对每个 MCP server(含已被 Vigil 包裹的)检查其底层 stdio 程序能否
    /// 在 PATH 解析(用网关同款解析逻辑)→ 逐 server ✓/✗ + 可操作原因。回答"我的接入是否能跑 / 哪个
    /// server 起不来、为什么"(最常见失败 = 程序没装 / 不在 PATH)。**纯静态、只读、不启动任何 server**。
    #[arg(long)]
    doctor: bool,
    /// 配合 `--doctor`:**深度探测**。对静态判定可启动的 server**真启动**其底层程序 + 完成 MCP
    /// `initialize` 握手(逐 server 有超时上界),再立即关停。回答静态档答不了的"程序在 PATH 但**运行时**
    /// 真能起来 + 说 MCP 吗"——抓"装了 Node 但 npx 包拉不动 / server 启动即崩 / 不说 MCP"这类静默失败
    /// (agent 表现为该 server **零工具**)。**有副作用**:会真启动每个 server 进程片刻(执行其 init 代码),
    /// 故 opt-in;默认 `--doctor` 保持纯静态无副作用。`npx`/`uvx` server **首次**探测可能因下包慢而超时
    /// (同 agent 首启;暖缓存后重跑即 OK)。
    #[arg(long, requires = "doctor")]
    probe: bool,
    /// **一条命令全保护**:同时接入 hook(原生工具输入侧 secret 拦截)**和** MCP 网关 wrap(脱敏 +
    /// 审计 + 审批 + descriptor pin),兑现"download → 直接得到保护"。等价于 `setup` + `setup --mcp
    /// --apply` 两步合一(两者写不同文件、互不冲突)。`--all --uninstall` 撤销两者;`--all --dry-run`
    /// 预览两者;MCP 侧默认 monitor 姿态(加 `--enforce` 升级硬拦)。
    ///
    /// 与只读操作 `--status` / `--doctor` **互斥**(Codex D13 HIGH:否则 `--all --status` 会因
    /// `--all` 优先而**变成写操作**,破坏只读契约)—— clap 在 parse 期即拒绝该组合,fail-fast 防惊吓写入。
    /// 也与 `--mcp` 互斥(Codex D13 R2 nit:`--all` 已含 MCP wrap,`--mcp` 此处会被静默忽略 = 歧义;
    /// 拒绝逼用户明确用 `--all` **或** `--mcp` 之一)。
    #[arg(long, conflicts_with_all = ["status", "doctor", "mcp"])]
    all: bool,
}

#[derive(clap::Args, Debug)]
struct CliAddRemoteArgs {
    /// 远程 MCP server 的 base URL,例如 `https://mcp.example.com/`
    #[arg(long)]
    url: String,
    /// OAuth client_id(公共 client,无 secret;I10c 再加 confidential)
    #[arg(long)]
    client_id: String,
    /// 请求的 scope 列表,逗号分隔(例如 `mcp:tools.read,mcp:tools.write`)
    #[arg(long, value_delimiter = ',')]
    scopes: Vec<String>,
    /// SQLite Ledger 路径(默认 `./vigil.db`)
    #[arg(long, default_value = "vigil.db")]
    ledger: PathBuf,
    /// 等 loopback callback 的超时秒数(默认 60)
    #[arg(long, default_value_t = 60u64)]
    timeout_secs: u64,
}

impl From<CliAddRemoteArgs> for AddRemoteArgs {
    fn from(c: CliAddRemoteArgs) -> Self {
        AddRemoteArgs {
            url: c.url,
            client_id: c.client_id,
            scopes: c.scopes,
            ledger: c.ledger,
            timeout_secs: c.timeout_secs,
        }
    }
}

#[derive(clap::Args, Debug)]
struct CliServeArgs {
    /// 使用 stdio transport(v0.3 Stage 1 唯一支持;HTTP 留后续)。必须显式开启。
    #[arg(long)]
    stdio: bool,
    /// SQLite Ledger 持久化路径。省略 = 内存 ledger(仅 smoke 测试用,跨连接不保留审计)。
    #[arg(long)]
    ledger: Option<PathBuf>,
    /// Upstream MCP server 配置 JSON。schema:`{"upstreams":[{"name":..., "argv":[...]}]}`。
    /// Stage 1 仅校验 JSON 格式,实际 attach 留 Stage 2 完成 register_server + approve_server。
    #[arg(long = "upstream-config")]
    upstream_config: Option<PathBuf>,
    /// 开发模式:tools/list 首次见到的 descriptor 自动批准(生产务必保持 false)。
    #[arg(long)]
    auto_approve_first_seen: bool,
    /// 开发模式:注入 "catch-all → Approve" 兜底 policy 规则,让无 EffectKind
    /// 匹配的纯计算工具走 ApprovalBroker 路径而非 default-deny。
    /// **生产必须关闭**(否则零信任 fail-safe 失守)。
    #[arg(long)]
    dev_permissive_firewall: bool,
    /// ISS-008 Phase 2:启用 T0 Privacy Filter(ORT 真模型推理)。
    /// 需要编译期 `--features ort` + 运行期 `VIGIL_PRIVACY_FILTER_MODEL_DIR` 环境变量。
    /// flag on + feature off → 启动失败 `ServeError::PrivacyFilterUnavailable`;
    /// flag off → 走 v0.4 默认 NoopEngine(向后兼容)。
    #[arg(long = "enable-privacy-filter")]
    enable_privacy_filter: bool,
    /// 可逆脱敏 Slice 1:上游工具响应命中硬指纹 secret 时,in-band 脱敏 result 后再返回
    /// agent/LLM(默认 off = 既有 out-of-band 仅审计)。堵住工具输出把 secret 回吐给远端 LLM。
    #[arg(long = "redact-tool-results")]
    redact_tool_results: bool,
}

impl From<CliServeArgs> for ServeArgs {
    fn from(c: CliServeArgs) -> Self {
        ServeArgs {
            ledger_path: c.ledger,
            upstreams_config: c.upstream_config,
            auto_approve_first_seen: c.auto_approve_first_seen,
            dev_permissive_firewall: c.dev_permissive_firewall,
            enable_privacy_filter: c.enable_privacy_filter,
            redact_tool_results: c.redact_tool_results,
            // `serve` 子命令保持既有 enforce(default-deny + 阻塞审批);monitor 是 wrap turnkey 专用。
            monitor: false,
        }
    }
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match cli.command {
        None => {
            // 真实 crate 版本(编译期 CARGO_PKG_VERSION),非内部迭代标记 —— 用户看到的是
            // 发布版本号(如 v0.1.15),既不误导也不泄漏内部 `I0x` 迭代术语。
            eprintln!(
                "vigil-hub {} — MCP proxy + CLI. Use --help for subcommands.",
                concat!("v", env!("CARGO_PKG_VERSION"))
            );
            std::process::ExitCode::SUCCESS
        }
        Some(Command::AddRemoteMcp(args)) => {
            let args: AddRemoteArgs = args.into();
            match add_remote::run(args) {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("vigil-hub add-remote-mcp failed: {e}");
                    std::process::ExitCode::FAILURE
                }
            }
        }
        Some(Command::Serve(args)) => {
            // stdio flag 必须显式给,防止用户误以为能默认启 HTTP
            if !args.stdio {
                eprintln!(
                    "vigil-hub serve: --stdio is required (v0.3 Stage 1 仅支持 stdio transport)"
                );
                return std::process::ExitCode::FAILURE;
            }
            let args: ServeArgs = args.into();
            // NOTE:stderr 打印启动提示;stdout 交给 MCP 协议,**不得污染**
            eprintln!(
                "vigil-hub serve: started stdio MCP server (PID {})",
                std::process::id()
            );
            match serve::run(args) {
                Ok(()) => {
                    eprintln!("vigil-hub serve: stdin closed, shutting down");
                    std::process::ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("vigil-hub serve failed: {e}");
                    std::process::ExitCode::FAILURE
                }
            }
        }
        Some(Command::Demo(args)) => {
            let demo_args = DemoArgs {
                tamper: args.tamper,
            };
            match demo::run(&demo_args) {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("vigil-hub demo failed: {e}");
                    std::process::ExitCode::FAILURE
                }
            }
        }
        Some(Command::Hook(args)) => {
            // Claude Code PreToolUse adapter:stdin 读事件 → 决策。
            // **deny 必须用 exit 2**(blocking error,stderr 回喂模型);exit 1 在 Claude Code
            // 约定里是 **non-blocking**(fail-open),绝不能用作拦截。Allow = exit 0 静默放行。
            let hook_args = HookArgs {
                ledger_path: args.ledger,
            };
            let stdin = std::io::stdin();
            let mut reader = stdin.lock();
            match hook::run(&hook_args, &mut reader) {
                hook::HookOutcome::Allow => std::process::ExitCode::SUCCESS,
                hook::HookOutcome::Deny(reason) => {
                    eprintln!("{reason}");
                    std::process::ExitCode::from(2)
                }
            }
        }
        Some(Command::Setup(args)) => {
            if args.all {
                // 一条命令全保护:hook + MCP wrap 一次完成(兑现 download→直接保护)。
                match run_setup_all(&args) {
                    Ok(code) => code,
                    Err(e) => {
                        eprintln!("vigil-hub setup --all failed: {e}");
                        std::process::ExitCode::FAILURE
                    }
                }
            } else if args.mcp {
                // MCP turnkey:--apply 改写 / --uninstall 还原 / 默认只读预览。
                match setup_mcp_dispatch(&args) {
                    Ok(code) => code,
                    Err(e) => {
                        eprintln!("vigil-hub setup --mcp failed: {e}");
                        std::process::ExitCode::FAILURE
                    }
                }
            } else {
                let setup_args = SetupArgs {
                    uninstall: args.uninstall,
                    status: args.status,
                    dry_run: args.dry_run,
                    ledger: args.ledger,
                };
                match setup::run(&setup_args) {
                    Ok(report) => print_setup_report(&setup_args, &report),
                    Err(e) => {
                        eprintln!("vigil-hub setup failed: {e}");
                        std::process::ExitCode::FAILURE
                    }
                }
            }
        }
        Some(Command::Wrap(args)) => {
            // 透明 stdio MCP shim:stdout 是给 agent 的 MCP 协议通道,**不得污染**(提示走 stderr)。
            let wrap_args = WrapArgs {
                command: args.command,
                ledger: args.ledger,
                server_id: args.server_id,
                env_keys: args.env_key,
                inherit_env: args.inherit_env,
                monitor: args.monitor,
            };
            match wrap::run(&wrap_args) {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("vigil-hub wrap failed: {e}");
                    std::process::ExitCode::FAILURE
                }
            }
        }
        Some(Command::Inspect(args)) => inspect::run(args),
    }
}

/// `setup --mcp` 分发:`--uninstall` 还原 / `--apply` 改写 / 默认只读预览。
fn setup_mcp_dispatch(args: &CliSetupArgs) -> Result<std::process::ExitCode, setup::SetupError> {
    let home = dirs::home_dir().ok_or(setup::SetupError::MissingHomeDir)?;
    let exe = std::env::current_exe()
        .map_err(|_| setup::SetupError::MissingCurrentExe)?
        .to_string_lossy()
        .to_string();
    // wrap 网关姿态:默认 monitor(观察放行+脱敏+审计+裸 secret 拦截);`--enforce` 升级为 default-deny
    // 硬拦。第三方 server 工具名不在 effect 词表 → enforce 一律 default-deny = server 全不可用,故默认 monitor
    // 让 turnkey 接入即可用且仍守全部硬地板(详见 CliSetupArgs::enforce doc)。
    let monitor = !args.enforce;
    if args.doctor {
        // 健壮性预检:默认纯静态只读;`--probe` 升级为深度探测(真 spawn + MCP initialize 握手,
        // 有副作用,见 CliSetupArgs::probe doc)。先于 uninstall/apply,doctor 优先。
        let probe_timeout = if args.probe {
            // Codex D18 R2 Low:probe 真执行每个配置 server 的启动代码 —— 动手**前**(run_doctor 内即
            // 开始 spawn)在 stderr 明确告警,而非仅 help 文案 / 事后表头。
            eprintln!(
                "[vigil-hub] --probe will briefly START each MCP server in ~/.claude.json (runs its \
                 startup code) to test a real MCP handshake, then stop it. Ctrl-C to abort."
            );
            Some(setup_mcp::DOCTOR_PROBE_TIMEOUT)
        } else {
            None
        };
        let rows = setup_mcp::run_doctor(&home, probe_timeout)?;
        Ok(print_mcp_doctor(&rows))
    } else if args.uninstall {
        // 所有 agent 接入面都还原:Claude + Codex + Cursor + Windsurf(各独立文件,逐一诚实报告)。
        let rep = setup_mcp::run_uninstall(&home, args.dry_run)?;
        let mut code = print_mcp_apply(&rep, "uninstall");
        code = run_codex_leg(
            setup_mcp::run_codex_uninstall(&home, args.dry_run),
            "uninstall",
            code,
        );
        for agent in json_mcp_agents(&home) {
            code = run_json_agent_leg(
                setup_mcp::run_json_agent_uninstall(&agent, args.dry_run),
                agent.display_name,
                "uninstall",
                code,
            );
        }
        Ok(code)
    } else if args.apply {
        // 所有面都保护(turnkey:一条命令覆盖用户全部 agent 接入面)。
        let rep = setup_mcp::run_apply(&home, &exe, args.dry_run, args.user_scope_only, monitor)?;
        let mut code = print_mcp_apply(&rep, "apply");
        code = run_codex_leg(
            setup_mcp::run_codex_apply(&home, &exe, args.dry_run, monitor),
            "apply",
            code,
        );
        for agent in json_mcp_agents(&home) {
            code = run_json_agent_leg(
                setup_mcp::run_json_agent_apply(&agent, &exe, args.dry_run, monitor),
                agent.display_name,
                "apply",
                code,
            );
        }
        Ok(code)
    } else {
        let rep = setup_mcp::run_preview(&home, &exe, monitor)?;
        let code = print_mcp_preview(&rep);
        // 预览只读:某 agent 配置 malformed 不硬 abort(什么都没写),优雅降级为一行提示而非突兀报错。
        match setup_mcp::run_codex_preview(&home, &exe, monitor) {
            Ok(codex) => print_codex_preview(&codex),
            Err(e) => {
                println!();
                println!(
                    "  Codex CLI config: {}",
                    setup_mcp::codex_config_path(&home).display()
                );
                println!("  (could not read it: {e} -- fix the file to preview/protect Codex MCP servers)");
            }
        }
        for agent in json_mcp_agents(&home) {
            match setup_mcp::run_json_agent_preview(&agent, &exe, monitor) {
                Ok(r) => print_json_agent_preview(&r),
                Err(e) => {
                    println!();
                    println!(
                        "  {} config: {}",
                        agent.display_name,
                        agent.config_path.display()
                    );
                    println!("  (could not read it: {e} -- fix the file to preview/protect its MCP servers)");
                }
            }
        }
        Ok(code)
    }
}

/// turnkey 覆盖的"JSON `mcpServers` 形态"agent 列表(Cursor + Windsurf)。新增同形态 agent 只在此扩列。
fn json_mcp_agents(home: &std::path::Path) -> [setup_mcp::JsonMcpAgent; 2] {
    [
        setup_mcp::JsonMcpAgent::cursor(home),
        setup_mcp::JsonMcpAgent::windsurf(home),
    ]
}

/// 运行 Codex 接入面的一步(apply/uninstall)并**诚实处理半应用状态**(Codex review #7 MEDIUM):
/// 成功 → 打印 Codex 报告,返回 Claude 侧退出码;失败(如 Codex 配置 malformed)→ **不吞错也不在成功
/// 文案后突兀 `?` 报错**:明确告知 Claude 侧已生效 + Codex 步失败原因 + 恢复指引,返回 FAILURE。
/// 对齐既有 `--all` 的 `McpAfterHook` 部分失败诚实哲学(报告每步状态 + 如何恢复,而非笼统失败)。
fn run_codex_leg(
    res: Result<setup_mcp::CodexApplyReport, setup::SetupError>,
    op: &str,
    claude_code: std::process::ExitCode,
) -> std::process::ExitCode {
    match res {
        Ok(codex) => {
            print_codex_apply(&codex, op);
            claude_code
        }
        Err(e) => {
            eprintln!("  [Codex] the {op} step FAILED (the Claude side already completed): {e}");
            if op == "uninstall" {
                eprintln!(
                    "  The Claude side was restored. Fix ~/.codex/config.toml, then re-run: \
                     vigil-hub setup --mcp --uninstall"
                );
            } else {
                eprintln!(
                    "  The Claude side IS applied. Fix ~/.codex/config.toml and re-run; or undo \
                     the Claude side with: vigil-hub setup --mcp --uninstall"
                );
            }
            std::process::ExitCode::FAILURE
        }
    }
}

/// 运行一个 JSON-agent 接入面(Cursor / Windsurf)的一步并**诚实处理半应用状态**(同 [`run_codex_leg`])。
/// 成功 → 打印报告,返回 `prior_code`(保留前面 leg 可能的 FAILURE);失败 → 打印该 agent 步失败 +
/// 恢复指引(其它 agent 面互不影响),返回 FAILURE。`prior_code` 链式传递 → 任一 leg 失败则总退出码 FAILURE。
fn run_json_agent_leg(
    res: Result<setup_mcp::JsonAgentApplyReport, setup::SetupError>,
    agent_name: &str,
    op: &str,
    prior_code: std::process::ExitCode,
) -> std::process::ExitCode {
    match res {
        Ok(r) => {
            print_json_agent_apply(&r, op);
            prior_code
        }
        Err(e) => {
            eprintln!(
                "  [{agent_name}] the {op} step FAILED (other agent surfaces unaffected): {e}"
            );
            eprintln!("  Fix {agent_name}'s MCP config, then re-run the same command.");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run_setup_all(args: &CliSetupArgs) -> Result<std::process::ExitCode, setup::SetupError> {
    let home = dirs::home_dir().ok_or(setup::SetupError::MissingHomeDir)?;
    let exe = std::env::current_exe().map_err(|_| setup::SetupError::MissingCurrentExe)?;
    // ledger:`--ledger` 覆盖 → 否则默认(`VIGIL_LEDGER_PATH` / `<data 目录>/Vigil/ledger.sqlite3`)。
    let ledger = args
        .ledger
        .clone()
        .or_else(setup::default_ledger_path)
        .ok_or(setup::SetupError::MissingDataDir)?;
    let monitor = !args.enforce;
    let op = if args.uninstall {
        "uninstall"
    } else if args.dry_run {
        "preview"
    } else {
        "apply"
    };
    match setup_mcp::run_all_with(
        &home,
        &exe,
        &ledger,
        args.uninstall,
        args.dry_run,
        args.user_scope_only,
        monitor,
    ) {
        Ok((hook_rep, mcp_rep)) => {
            let mut code = print_setup_all(&hook_rep, &mcp_rep, op);
            // 其余接入面:Codex + Cursor + Windsurf。各独立文件,hook + Claude-MCP 成功后逐一做;失败经
            // `run_*_leg` **诚实半应用报告**(不回滚已应用面 —— 各面独立、各自可逆)。op 在 dry-run 时为
            // "preview";各步只认 apply/uninstall(dry 措辞由报告里 dry_run 决定)。
            let exe_str = exe.to_string_lossy().to_string();
            let mcp_op = if args.uninstall { "uninstall" } else { "apply" };
            let codex_res = if args.uninstall {
                setup_mcp::run_codex_uninstall(&home, args.dry_run)
            } else {
                setup_mcp::run_codex_apply(&home, &exe_str, args.dry_run, monitor)
            };
            code = run_codex_leg(codex_res, mcp_op, code);
            for agent in json_mcp_agents(&home) {
                let res = if args.uninstall {
                    setup_mcp::run_json_agent_uninstall(&agent, args.dry_run)
                } else {
                    setup_mcp::run_json_agent_apply(&agent, &exe_str, args.dry_run, monitor)
                };
                code = run_json_agent_leg(res, agent.display_name, mcp_op, code);
            }
            Ok(code)
        }
        // hook 步就失败 → 什么都没改(hook 写盘前 gate,失败即未写):诚实"nothing changed"。
        Err(setup_mcp::AllError::Hook(e)) => {
            eprintln!("vigil-hub setup --all: hook step failed -- nothing was changed: {e}");
            Ok(std::process::ExitCode::FAILURE)
        }
        // hook 成功、MCP 步失败 → **半应用**:诚实告知 hook 已应用 + 如何单独撤销(Codex D13 HIGH)。
        Err(setup_mcp::AllError::McpAfterHook { hook, source }) => {
            let did = if op == "uninstall" {
                if hook.changed {
                    "removed"
                } else {
                    "nothing to remove"
                }
            } else if hook.changed {
                "applied"
            } else {
                "already up to date"
            };
            println!(
                "Vigil setup --all --{op}: PARTIAL (the hook step completed, the MCP step did not)"
            );
            println!("  [1/2] hook (PreToolUse input-secret guard): {did}");
            eprintln!("  [2/2] MCP gateway step FAILED: {source}");
            if op == "uninstall" {
                // 不声称"hook 已移除"(若 changed=false 则本就没东西可移除,会过度陈述;Codex D13 R2 nit)。
                eprintln!("  The hook step completed (see above); MCP wrap entries may remain. Retry: vigil-hub setup --mcp --uninstall");
            } else {
                eprintln!(
                    "  The hook above IS applied. Undo just the hook with: vigil-hub setup --uninstall"
                );
                eprintln!("  (or fix the cause and re-run: vigil-hub setup --all)");
            }
            Ok(std::process::ExitCode::FAILURE)
        }
    }
}

/// 打印 `setup --all` 合并报告(ASCII-safe)。两段(hook / mcp)各自诚实陈述 + 末尾下一步。
fn print_setup_all(
    hook: &setup::SetupReport,
    mcp: &setup_mcp::McpApplyReport,
    op: &str,
) -> std::process::ExitCode {
    let dry = if hook.dry_run { " (dry-run)" } else { "" };
    println!("Vigil setup --all --{op}{dry}: native-tool hook + MCP gateway in one step");

    // [1/2] hook(原生工具输入侧 secret 拦截)
    if !hook.claude_detected {
        println!(
            "  [1/2] hook: Claude Code not detected (~/.claude not found) -- hook step skipped"
        );
    } else if op == "uninstall" {
        let did = if hook.changed {
            "removed"
        } else {
            "nothing to remove"
        };
        println!("  [1/2] hook (PreToolUse input-secret guard): {did}");
    } else {
        let did = if hook.changed {
            "registered"
        } else {
            "already up to date"
        };
        println!("  [1/2] hook (PreToolUse input-secret guard): {did}");
    }

    // [2/2] MCP 网关 wrap(脱敏 + 审计 + 审批 + descriptor pin)
    let total = mcp.total_changed();
    let verb = if op == "uninstall" {
        "restored"
    } else {
        "wrapped"
    };
    println!("  [2/2] MCP gateway: {verb} {total} server(s)");
    if mcp.local_skipped > 0 {
        println!(
            "        NOTE: {} local-scope server(s) left unprotected (--user-scope-only).",
            mcp.local_skipped
        );
    }

    // 下一步 / 撤销
    println!();
    if op == "preview" {
        println!("  Preview only -- nothing written. Apply with: vigil-hub setup --all");
    } else if op == "uninstall" {
        println!("  Vigil protection removed (hook + MCP gateway). Restart your agent.");
    } else {
        println!(
            "  Protected. Restart your agent to activate. See what Vigil catches: vigil-hub inspect protection"
        );
        println!("  Undo everything with: vigil-hub setup --all --uninstall");
    }
    std::process::ExitCode::SUCCESS
}

/// 打印 `setup --mcp --doctor` 健壮性预检结果(ASCII-safe,cp936/cp437 不乱码)。返回退出码:
/// 有任一 server 起不来(ProgramNotFound/Malformed)→ 退出码 1(脚本可据此判失败);否则 0。
///
/// **truth-in-labeling**(Codex D12 nit):解析用**本进程当前 PATH**,= 网关 spawn 时同款 `resolve_program`
/// (SSOT);但若 agent 启动 `vigil-hub wrap` 的 PATH 与此不同,verdict 可能偏差 → 文案明示"在本环境"。
/// **hygiene**(Codex D12 nit):所有展示字段(name/scope/program/resolved)过 `scrub_text` 再输出 ——
/// argv[0]/路径通常无 secret,但纵深防御统一遵守"绝不把可能含敏感串的值原样进 UI/日志"(与 preview 一致)。
fn print_mcp_doctor(rows: &[setup_mcp::McpDoctorRow]) -> std::process::ExitCode {
    use setup_mcp::{DoctorStatus, ProbeOutcome};
    let scrub = vigil_redaction::scrub_text;
    // 是否处于深度探测档(任一行带 probe 结果)—— 决定表头/表尾措辞与失败语义。
    let probing = rows.iter().any(|r| r.probe.is_some());
    println!("Vigil setup --mcp --doctor: can each MCP server's program be launched in THIS environment?");
    println!("  (resolves argv[0] in the current PATH, exactly as the gateway does at spawn time)");
    if probing {
        // Codex D18 R2 Low:probe 会真执行每个 server 的启动代码 —— 在动手前明确告知(非仅 help 文案)。
        println!("  --probe: WARNING — this briefly STARTS each configured server (runs its startup code)");
        println!("           to complete a real MCP initialize handshake, then stops it. Direct child is killed;");
        println!("           a misbehaving npx/uvx grandchild may survive briefly.");
    }
    if rows.is_empty() {
        println!("  No MCP servers found in ~/.claude.json (nothing to check).");
        return std::process::ExitCode::SUCCESS;
    }
    let mut failed = 0usize;
    for r in rows {
        // scope 标注:user 或项目路径(local)。wrapped 标注是否已受 Vigil 保护。全部过 scrub。
        let name = scrub(&r.name);
        let scope = if r.scope == "user" {
            "user".to_string()
        } else {
            format!("local:{}", scrub(&r.scope))
        };
        let guard = if r.wrapped { " [vigil-wrapped]" } else { "" };
        match &r.status {
            DoctorStatus::Launchable { program, resolved } => {
                println!(
                    "  [OK]   {name} ({scope}){guard}: {} -> {}",
                    scrub(program),
                    scrub(resolved)
                );
                // 深度探测结果(--probe):静态可解析但运行时起不来 = 真失败(agent 会零工具)。
                match &r.probe {
                    Some(ProbeOutcome::Initialized) => {
                        // 措辞:probe 验的是**底层 server** 能起 + 说 MCP;对 vigil-wrapped 条目,真实
                        // 网关启动还会额外强制 descriptor drift gate,故不等同"agent 一定见到工具"(Codex R2 M3)。
                        println!("           probe: the underlying server initialized OK (started + MCP handshake succeeded)");
                    }
                    Some(ProbeOutcome::Failed { reason }) => {
                        failed += 1;
                        // reason 已在 setup_mcp 侧 value-aware 脱敏 + scrub;此处直接展示。
                        println!("           probe: FAILED to initialize: {reason}");
                        println!("           -> the program runs but did not complete an MCP handshake; your agent will see no tools from it.");
                        println!("           -> if it's an npx/uvx server on first run, packages may still be downloading; re-run --probe once warm.");
                    }
                    None => {}
                }
            }
            DoctorStatus::ProgramNotFound { program } => {
                failed += 1;
                println!(
                    "  [FAIL] {name} ({scope}){guard}: program `{}` not found in PATH",
                    scrub(program)
                );
                // 可操作提示:最常见两类运行时。
                let hint = match program.as_str() {
                    "npx" | "node" => "  -> install Node.js (npx/node), then restart your agent",
                    "uvx" | "uv" => "  -> install uv (uvx/uv), then restart your agent",
                    _ => "  -> install this program or fix its PATH, then restart your agent",
                };
                println!("{hint}");
            }
            DoctorStatus::Skipped { reason } => {
                println!("  [skip] {name} ({scope}): {reason}");
            }
            DoctorStatus::Malformed => {
                failed += 1;
                println!(
                    "  [FAIL] {name} ({scope}){guard}: Vigil-managed entry is malformed (cannot determine the underlying program)"
                );
            }
        }
    }
    println!();
    if failed == 0 {
        if probing {
            println!(
                "  All checked servers resolve AND their underlying program completes an MCP handshake here."
            );
            // Codex R2 M3:probe 验底层 server;对已 vigil-wrapped 条目,真实网关启动还会强制 descriptor
            // drift gate(probe 刻意不走、不改状态),故 probe OK 不等同"agent 一定见到工具"。
            println!("  (probe checks the underlying server; for vigil-wrapped entries the live gateway also enforces descriptor drift.)");
        } else {
            println!("  All checked servers resolve in this environment.");
        }
        println!("  Note: your agent must launch vigil-hub with the same PATH for this to hold.");
        std::process::ExitCode::SUCCESS
    } else {
        let what = if probing {
            "will not start / initialize"
        } else {
            "will not start"
        };
        println!(
            "  {failed} server(s) {what} in this environment. Fix the above, then re-run --doctor."
        );
        std::process::ExitCode::from(1)
    }
}

/// 打印 `setup --mcp --apply/--uninstall` 结果(ASCII-safe)。
fn print_mcp_apply(r: &setup_mcp::McpApplyReport, op: &str) -> std::process::ExitCode {
    let dry = if r.dry_run { " (dry-run)" } else { "" };
    let verb = if r.dry_run { "would" } else { "did" };
    let what = if op == "uninstall" { "restore" } else { "wrap" };
    let total = r.total_changed();
    println!(
        "Vigil setup --mcp --{op}{dry}: {verb} {what} {total} MCP server(s) in {}",
        r.claude_json.display()
    );
    // 分 scope 报告:local scope(projects.*)用**项目限定 server-id**(跨项目同名不串账本)。
    if r.local_changed > 0 {
        println!(
            "  ({} user-scope + {} local-scope/per-project)",
            r.changed, r.local_changed
        );
    }
    if let Some(b) = &r.backup {
        println!("  backup of the previous config: {}", b.display());
    }
    if total == 0 && !r.dry_run {
        println!("  (nothing to {what} -- no matching servers)");
    }
    // `--user-scope-only` 跳过了可保护的 local scope server → 诚实提示它们仍未受保护。
    if r.local_skipped > 0 {
        println!(
            "  NOTE: {} local-scope (per-project) MCP server(s) left UNPROTECTED (--user-scope-only).",
            r.local_skipped
        );
    }
    if op == "apply" && total > 0 && !r.dry_run {
        println!(
            "  Restart Claude Code to pick up the change. Undo with: vigil-hub setup --mcp --uninstall"
        );
    }
    std::process::ExitCode::SUCCESS
}

/// 打印 `setup --mcp` 只读预览(ASCII-safe,cp936/cp437 不乱码)。返回退出码。
/// 渲染单个 server 分类的预览行(user / local / Codex scope 各调一次)。`derive_id` 由调用方注入
/// scope 专属的 server-id 派生(user-/local-/codex-,disjoint 命名空间),让 WRAP 渲染逻辑单一真源。
fn print_mcp_server_preview(
    exe: &str,
    derive_id: impl Fn(&str) -> String,
    class: &McpServerClass,
    monitor: bool,
) {
    match class {
        McpServerClass::Wrappable {
            name,
            command,
            args,
            env_keys,
        } => {
            // server-id 由调用方注入的 scope 派生器产出(各 scope 加 disjoint 前缀防身份塌缩)。
            let wrap_id = derive_id(name);
            let argv = setup_mcp::wrapped_argv(exe, &wrap_id, command, args, env_keys, monitor);
            println!("  [WRAP] {name}");
            // 预览里的 command/args 可能含用户内联的 token(如 `--api-key sk-...`)。过硬指纹 scrub
            // 再展示,守"secrets 绝不进 UI/日志"不变量(Codex setup_mcp review hygiene)。
            let from_disp = vigil_redaction::scrub_text(&format!("{} {}", command, args.join(" ")));
            let to_disp = vigil_redaction::scrub_text(&argv.join(" "));
            println!("         from: {from_disp}");
            println!("         to:   {to_disp}");
            if !env_keys.is_empty() {
                println!(
                    "         env (key-only, values never copied): {}",
                    env_keys.join(", ")
                );
            }
        }
        McpServerClass::AlreadyWrapped { name } => {
            println!("  [OK]   {name} -- already Vigil-managed (skipped)");
        }
        McpServerClass::Skipped { name, reason } => {
            println!("  [SKIP] {name} -- {reason}");
        }
    }
}

fn print_mcp_preview(r: &setup_mcp::McpPreviewReport) -> std::process::ExitCode {
    println!("Vigil setup --mcp (PREVIEW ONLY -- nothing is changed)");
    println!("  Claude Code config: {}", r.claude_json.display());
    if !r.exists {
        println!(
            "  (no ~/.claude.json found -- Claude Code not configured, or no MCP servers yet)"
        );
        return std::process::ExitCode::SUCCESS;
    }
    println!("  vigil-hub: {}", r.exe);
    println!();
    if r.servers.is_empty() && r.local_servers.is_empty() {
        println!("  No MCP servers found (user scope or per-project local scope).");
        return std::process::ExitCode::SUCCESS;
    }
    // user scope(顶层 mcpServers)
    if !r.servers.is_empty() {
        println!(
            "  User scope (top-level mcpServers) -- {} can be protected:",
            r.wrappable_count()
        );
        for s in &r.servers {
            print_mcp_server_preview(&r.exe, setup_mcp::user_scope_server_id, s, r.monitor);
        }
    }
    // local scope(projects.<path>.mcpServers)—— claude mcp add 默认写这里
    if !r.local_servers.is_empty() {
        println!();
        println!(
            "  Local scope (per-project mcpServers) -- {} can be protected:",
            r.local_wrappable_count()
        );
        println!(
            "  (wrapped with a project-scoped server-id so same-named servers across projects"
        );
        println!("   don't share audit/approval identity)");
        for (proj, s) in &r.local_servers {
            print_mcp_server_preview(
                &r.exe,
                |n| setup_mcp::local_scope_server_id(proj, n),
                s,
                r.monitor,
            );
        }
    }
    println!();
    // 姿态提示反映将落盘的真实姿态(默认 monitor;`--enforce` 升级硬拦)。
    if r.monitor {
        println!("  Default posture: MONITOR (servers stay usable; result redaction + raw-secret");
        println!(
            "  block + tamper-evident audit always on; add --enforce for default-deny gating)."
        );
    } else {
        println!("  Posture: ENFORCE (default-deny; third-party tools without known effects are");
        println!(
            "  blocked -- use only for known/self-built servers). Omit --enforce for monitor."
        );
    }
    println!(
        "  Apply with:  vigil-hub setup --mcp --apply{}",
        if r.monitor { "" } else { " --enforce" }
    );
    println!(
        "  (protects user + local scope; --user-scope-only skips local; --uninstall reverts)."
    );
    std::process::ExitCode::SUCCESS
}

/// 打印 Codex 接入面只读预览(ASCII-safe)。附在 Claude 预览之后,作为第二个受保护配置面。
/// 复用 [`print_mcp_server_preview`](注入 `codex-` server-id 派生),WRAP 渲染单一真源。
fn print_codex_preview(r: &setup_mcp::CodexPreviewReport) {
    println!();
    println!("  Codex CLI config: {}", r.codex_config.display());
    if !r.exists {
        println!(
            "  (no ~/.codex/config.toml found -- Codex not configured, or no MCP servers yet)"
        );
        return;
    }
    if r.servers.is_empty() {
        println!("  No MCP servers found in Codex [mcp_servers].");
        return;
    }
    println!(
        "  Codex scope ([mcp_servers]) -- {} can be protected:",
        r.wrappable_count()
    );
    for s in &r.servers {
        print_mcp_server_preview(&r.exe, setup_mcp::codex_scope_server_id, s, r.monitor);
    }
}

/// 打印 Codex 接入面 apply/uninstall 结果(ASCII-safe)。附在 Claude 结果之后。
fn print_codex_apply(r: &setup_mcp::CodexApplyReport, op: &str) {
    let dry = if r.dry_run { " (dry-run)" } else { "" };
    let verb = if r.dry_run { "would" } else { "did" };
    let what = if op == "uninstall" { "restore" } else { "wrap" };
    println!(
        "Vigil setup --mcp --{op}{dry} (Codex): {verb} {what} {} MCP server(s) in {}",
        r.changed,
        r.codex_config.display()
    );
    if let Some(b) = &r.backup {
        println!("  backup of the previous config: {}", b.display());
    }
    if r.changed == 0 && !r.dry_run {
        println!("  (nothing to {what} in Codex -- no matching servers)");
    }
    if op == "apply" && r.changed > 0 && !r.dry_run {
        println!(
            "  Restart Codex to pick up the change. Undo with: vigil-hub setup --mcp --uninstall"
        );
    }
}

/// 打印 JSON-agent 接入面(Cursor / Windsurf)只读预览(ASCII-safe)。附在前面各面预览之后。
/// 复用 [`print_mcp_server_preview`](注入 `<prefix>-` server-id 派生,与 apply 真改写一致)。
fn print_json_agent_preview(r: &setup_mcp::JsonAgentPreviewReport) {
    println!();
    println!("  {} config: {}", r.display_name, r.config_path.display());
    if !r.exists {
        println!(
            "  (not found -- {} not configured, or no MCP servers yet)",
            r.display_name
        );
        return;
    }
    if r.servers.is_empty() {
        println!("  No MCP servers found in mcpServers.");
        return;
    }
    println!(
        "  {} scope (mcpServers) -- {} can be protected:",
        r.display_name,
        r.wrappable_count()
    );
    // server-id 派生须与 apply 一致(`<prefix>-<name>`)。prefix 是 &'static str,闭包捕获。
    let prefix = r.id_prefix;
    for s in &r.servers {
        print_mcp_server_preview(&r.exe, |n| format!("{prefix}-{n}"), s, r.monitor);
    }
}

/// 打印 JSON-agent 接入面 apply/uninstall 结果(ASCII-safe)。附在前面各面结果之后。
fn print_json_agent_apply(r: &setup_mcp::JsonAgentApplyReport, op: &str) {
    let dry = if r.dry_run { " (dry-run)" } else { "" };
    let verb = if r.dry_run { "would" } else { "did" };
    let what = if op == "uninstall" { "restore" } else { "wrap" };
    println!(
        "Vigil setup --mcp --{op}{dry} ({}): {verb} {what} {} MCP server(s) in {}",
        r.display_name,
        r.changed,
        r.config_path.display()
    );
    if let Some(b) = &r.backup {
        println!("  backup of the previous config: {}", b.display());
    }
    if r.changed == 0 && !r.dry_run {
        println!(
            "  (nothing to {what} in {} -- no matching servers)",
            r.display_name
        );
    }
    if op == "apply" && r.changed > 0 && !r.dry_run {
        println!(
            "  Restart {} to pick up the change. Undo with: vigil-hub setup --mcp --uninstall",
            r.display_name
        );
    }
}

/// 打印 setup/status 的人类可读报告(ASCII-safe,cp936/cp437 不乱码)。返回退出码。
fn print_setup_report(args: &SetupArgs, r: &setup::SetupReport) -> std::process::ExitCode {
    use setup::ProtectionState;
    if args.status {
        let self_test = setup::doctor_self_test();
        println!("Vigil status");
        println!(
            "  Claude Code:   {}",
            if r.claude_detected {
                "detected"
            } else {
                "not detected (~/.claude not found)"
            }
        );
        // 诚实分级:Active 仅当托管条目存在且 command 未漂移且 exe 存在(Codex R1 HIGH)。
        match r.state {
            ProtectionState::Active => {
                println!("  Protection:    ACTIVE");
                println!("  Hook command:  {}", r.hook_command);
                println!("  Audit ledger:  {}", r.ledger.display());
            }
            ProtectionState::Stale => {
                println!("  Protection:    INSTALLED but STALE");
                println!(
                    "                 the registered hook points at a different binary/ledger,"
                );
                println!("                 or a missing executable. Re-run `vigil-hub setup` to refresh.");
            }
            ProtectionState::NotInstalled => {
                println!("  Protection:    not installed");
            }
        }
        println!(
            "  Self-test:     {}",
            if self_test {
                "PASS - a synthetic fake credential was blocked by the hook logic"
            } else {
                "FAIL - the hook did NOT block a synthetic credential (please report)"
            }
        );
        if r.state != ProtectionState::Active && r.claude_detected {
            println!("\n  Run `vigil-hub setup` to turn on protection.");
        }
        // self-test 失败是真问题 → 非零退出
        return if self_test {
            std::process::ExitCode::SUCCESS
        } else {
            std::process::ExitCode::FAILURE
        };
    }

    if args.uninstall {
        println!("Vigil setup --uninstall");
        if r.changed {
            println!("  Removed Vigil's PreToolUse hook from Claude Code settings.");
            if let Some(b) = &r.backup_path {
                println!("  Backup:        {}", b.display());
            }
        } else {
            println!("  Nothing to remove (Vigil hook was not present).");
        }
        return std::process::ExitCode::SUCCESS;
    }

    // install
    println!("Vigil setup");
    if !r.claude_detected {
        println!("  Claude Code:   not detected (~/.claude not found)");
        println!("  Nothing to do. Install Claude Code, then re-run `vigil-hub setup`.");
        println!("  (For other agents, use the MCP gateway: `vigil-hub serve --stdio`.)");
        return std::process::ExitCode::SUCCESS;
    }
    println!("  Claude Code:   detected");
    if r.dry_run {
        println!("  [dry-run] would register Vigil's PreToolUse hook in:");
        println!("            {}", r.settings_path.display());
        println!("  [dry-run] hook command: {}", r.hook_command);
        println!("  [dry-run] audit ledger: {}", r.ledger.display());
        println!("  (no changes written)");
        return std::process::ExitCode::SUCCESS;
    }
    if r.changed {
        println!("  Protection:    PreToolUse hook registered (all tools)");
        println!("  Hook command:  {}", r.hook_command);
        println!("  Audit ledger:  {}", r.ledger.display());
        if let Some(b) = &r.backup_path {
            println!("  Backup:        {}  (your previous settings)", b.display());
        }
        println!();
        println!("  Your Claude Code tool calls are now guarded by Vigil: raw secrets are");
        println!("  blocked from Bash/Edit/Write/etc., and every block is recorded in a");
        println!("  tamper-evident local audit ledger.");
        println!();
        println!("  Verify:  vigil-hub setup --status");
        println!("  See it:  vigil-hub inspect activity     # what Vigil has blocked, anytime");
        println!("  Undo:    vigil-hub setup --uninstall");
        println!("  Restart Claude Code (or start a new session) for the hook to take effect.");
    } else {
        println!("  Protection:    already active (no change).");
        println!("  Verify:  vigil-hub setup --status");
    }
    std::process::ExitCode::SUCCESS
}
