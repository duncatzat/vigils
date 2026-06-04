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
        }
    }
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match cli.command {
        None => {
            eprintln!(
                "vigil-hub {} — MCP proxy + CLI. Use --help for subcommands.",
                vigil_mcp::ITERATION
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
        Some(Command::Inspect(args)) => inspect::run(args),
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
        println!("  Undo:    vigil-hub setup --uninstall");
        println!("  Restart Claude Code (or start a new session) for the hook to take effect.");
    } else {
        println!("  Protection:    already active (no change).");
        println!("  Verify:  vigil-hub setup --status");
    }
    std::process::ExitCode::SUCCESS
}
