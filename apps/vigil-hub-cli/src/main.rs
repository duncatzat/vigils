//! Vigil Hub CLI binary —— clap entrypoint,lib 层是 `vigil_hub_cli` crate。
//!
//! I00-I09:占位。
//! I10b-β:`add-remote-mcp` 子命令,串联 PRM discover + loopback OAuth + token persist。
//! v0.3 Stage 1(2026-04-24):`serve` 子命令 —— 把 Hub 暴露为 MCP stdio server,
//! 供 CLI agent(Claude Code / Codex / Cursor / Zed 等)通过 stdio transport 连接。

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use vigil_hub_cli::inspect::{self, InspectArgs};
use vigil_hub_cli::serve::{self, ServeArgs};
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
    /// 命令行查询本地审计账本(activity / search / approvals / session / servers /
    /// sandbox / verify-chain);stdout 为单行 JSON,便于 `| jq` 与脚本化。
    Inspect(InspectArgs),
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
}

impl From<CliServeArgs> for ServeArgs {
    fn from(c: CliServeArgs) -> Self {
        ServeArgs {
            ledger_path: c.ledger,
            upstreams_config: c.upstream_config,
            auto_approve_first_seen: c.auto_approve_first_seen,
            dev_permissive_firewall: c.dev_permissive_firewall,
            enable_privacy_filter: c.enable_privacy_filter,
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
        // inspect 自行处理 ExitCode(0=ok / 1=dispatch err / 2=参数或 ledger 错误)
        Some(Command::Inspect(args)) => inspect::run(args),
    }
}
