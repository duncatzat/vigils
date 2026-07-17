//! vigil-desktop CLI(I08a,ADR 0008)。
//!
//! Subcommand 一对一映射到 `UiCommand`;Ledger 由 `--db-path` 或默认内存打开。
//! stdout = 单行 JSON response;stderr = 错误 JSON。

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use vigil_audit::Ledger;
use vigil_desktop::dispatch;
use vigil_desktop::render::{print_error, print_response};
use vigil_runner::SandboxProfile;
use vigil_types::ApprovalScope;
use vigil_ui_protocol::{
    ApprovalAction, ApproveServerCommandDriftReq, ApproveToolDriftReq, ApproveToolReq,
    BindServerSandboxProfileReq, Capability, FtsSearchReq, GetApprovalDetailReq, GetEventDetailReq,
    GetSandboxProfileReq, GetServerOnboardingReq, ListPendingApprovalsReq, ListRecentEventsReq,
    ListSessionsReq, RejectServerCommandDriftReq, RejectToolDriftReq, ReplaySessionReq,
    ResolveApprovalReq, UiCommand, UpsertSandboxProfileReq,
};

#[derive(Debug, Parser)]
#[command(name = "vigil-desktop", about = "Vigil local control plane CLI (I08a)")]
struct Cli {
    /// SQLite DB path(省略 = in-memory,仅本进程可见)
    #[arg(long, global = true)]
    db_path: Option<String>,

    /// capability level:read(默认 / 只读)或 write(允许改 approval / drift / profile)
    #[arg(long, global = true, default_value = "read")]
    capability: CapArg,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum CapArg {
    Read,
    Write,
}

impl From<CapArg> for Capability {
    fn from(c: CapArg) -> Self {
        match c {
            CapArg::Read => Capability::Read,
            CapArg::Write => Capability::Write,
        }
    }
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Activity Feed:列最近事件
    Activity {
        /// 只看某 session
        #[arg(long)]
        session: Option<String>,
        /// 事件类型过滤(重复传多个)
        #[arg(long)]
        event_type: Vec<String>,
        /// 返回上限
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    /// 单条事件详情
    Event {
        /// event_id
        id: i64,
    },
    /// FTS 搜索
    Search {
        /// MATCH 查询
        query: String,
        /// 上限
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// Approval Queue 操作
    Approvals {
        #[command(subcommand)]
        op: ApprovalsOp,
    },
    /// Session Replay
    Session {
        #[command(subcommand)]
        op: SessionOp,
    },
    /// Server Registry
    Servers {
        #[command(subcommand)]
        op: ServersOp,
    },
    /// Sandbox profile 管理
    Sandbox {
        #[command(subcommand)]
        op: SandboxOp,
    },
    /// Hash chain 校验
    VerifyChain,
}

#[derive(Debug, Subcommand)]
enum ApprovalsOp {
    /// 列 Pending approvals
    List {
        #[arg(long)]
        session: Option<String>,
    },
    /// 详情
    Show { approval_id: String },
    /// 解析(批准 / 拒绝 / 取消)
    Resolve {
        approval_id: String,
        #[arg(long, conflicts_with_all = ["deny", "cancel"])]
        approve: bool,
        #[arg(long, conflicts_with_all = ["approve", "cancel"])]
        deny: bool,
        #[arg(long, conflicts_with_all = ["approve", "deny"])]
        cancel: bool,
        /// 批准时的 scope
        #[arg(long, value_parser = parse_scope)]
        scope: Option<ApprovalScope>,
        /// resolved_by
        #[arg(long, default_value = "cli")]
        user: String,
        /// 拒绝原因
        #[arg(long)]
        reason: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum SessionOp {
    /// 列 sessions
    List {
        #[arg(long)]
        source: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    /// 重放
    Replay {
        session_id: String,
        /// 同时 verify hash chain
        #[arg(long)]
        verify: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ServersOp {
    /// 列所有已登记 servers
    List,
    /// 展示某 server 的 onboarding 数据(**exact argv 可见 §4.7**)
    Show { server_id: String },
    /// 列 pending tool 审批
    PendingTools,
    /// 列 drifted tools
    DriftedTools,
    /// 列 drifted servers
    DriftedServers,
    /// 首次批准 tool
    ApproveTool {
        server_id: String,
        tool_name: String,
    },
    /// 批准 tool drift 到新 hash
    ApproveToolDrift {
        server_id: String,
        tool_name: String,
        new_hash: String,
    },
    /// 拒绝 tool drift
    RejectToolDrift {
        server_id: String,
        tool_name: String,
    },
    /// 批准 server command drift
    ApproveCommandDrift { server_id: String },
    /// 拒绝 server command drift
    RejectCommandDrift { server_id: String },
}

#[derive(Debug, Subcommand)]
enum SandboxOp {
    /// 列 profiles
    List,
    /// 显示某 profile
    Show { profile_id: String },
    /// upsert(从 --json 文件或 stdin 读 JSON)
    Upsert {
        /// profile JSON 文件路径(不传则从 stdin 读)
        #[arg(long)]
        json: Option<String>,
    },
    /// 绑定 server → profile(profile_id=空 则解绑)
    Bind {
        server_id: String,
        profile_id: Option<String>,
    },
}

fn parse_scope(s: &str) -> Result<ApprovalScope, String> {
    match s {
        "Once" | "once" => Ok(ApprovalScope::Once),
        "ThisSession" | "this_session" => Ok(ApprovalScope::ThisSession),
        other => Err(format!(
            "unknown scope '{other}'; expected Once or ThisSession"
        )),
    }
}

fn build_command(cmd: Cmd) -> Result<UiCommand, String> {
    Ok(match cmd {
        Cmd::Activity {
            session,
            event_type,
            limit,
        } => UiCommand::ListRecentEvents(ListRecentEventsReq {
            session_id: session,
            event_type_filter: if event_type.is_empty() {
                None
            } else {
                Some(event_type)
            },
            limit,
        }),
        Cmd::Event { id } => UiCommand::GetEventDetail(GetEventDetailReq { event_id: id }),
        Cmd::Search { query, limit } => UiCommand::FtsSearch(FtsSearchReq { query, limit }),
        Cmd::Approvals { op } => match op {
            ApprovalsOp::List { session } => {
                UiCommand::ListPendingApprovals(ListPendingApprovalsReq {
                    session_id: session,
                })
            }
            ApprovalsOp::Show { approval_id } => {
                UiCommand::GetApprovalDetail(GetApprovalDetailReq { approval_id })
            }
            ApprovalsOp::Resolve {
                approval_id,
                approve,
                deny,
                cancel,
                scope,
                user,
                reason,
            } => {
                let action = match (approve, deny, cancel) {
                    (true, false, false) => ApprovalAction::Approve,
                    (false, true, false) => ApprovalAction::Deny,
                    (false, false, true) => ApprovalAction::Cancel,
                    _ => {
                        return Err(
                            "exactly one of --approve / --deny / --cancel is required".into()
                        )
                    }
                };
                UiCommand::ResolveApproval(ResolveApprovalReq {
                    approval_id,
                    action,
                    scope,
                    resolved_by: user,
                    reason,
                })
            }
        },
        Cmd::Session { op } => match op {
            SessionOp::List { source, limit } => {
                UiCommand::ListSessions(ListSessionsReq { source, limit })
            }
            SessionOp::Replay { session_id, verify } => {
                UiCommand::ReplaySession(ReplaySessionReq { session_id, verify })
            }
        },
        Cmd::Servers { op } => match op {
            ServersOp::List => UiCommand::ListServers,
            ServersOp::Show { server_id } => {
                UiCommand::GetServerOnboarding(GetServerOnboardingReq { server_id })
            }
            ServersOp::PendingTools => UiCommand::ListPendingToolApprovals,
            ServersOp::DriftedTools => UiCommand::ListDriftedTools,
            ServersOp::DriftedServers => UiCommand::ListDriftedServers,
            ServersOp::ApproveTool {
                server_id,
                tool_name,
            } => UiCommand::ApproveTool(ApproveToolReq {
                server_id,
                tool_name,
            }),
            ServersOp::ApproveToolDrift {
                server_id,
                tool_name,
                new_hash,
            } => UiCommand::ApproveToolDrift(ApproveToolDriftReq {
                server_id,
                tool_name,
                new_hash,
            }),
            ServersOp::RejectToolDrift {
                server_id,
                tool_name,
            } => UiCommand::RejectToolDrift(RejectToolDriftReq {
                server_id,
                tool_name,
            }),
            ServersOp::ApproveCommandDrift { server_id } => {
                UiCommand::ApproveServerCommandDrift(ApproveServerCommandDriftReq { server_id })
            }
            ServersOp::RejectCommandDrift { server_id } => {
                UiCommand::RejectServerCommandDrift(RejectServerCommandDriftReq { server_id })
            }
        },
        Cmd::Sandbox { op } => match op {
            SandboxOp::List => UiCommand::ListSandboxProfiles,
            SandboxOp::Show { profile_id } => {
                UiCommand::GetSandboxProfile(GetSandboxProfileReq { profile_id })
            }
            SandboxOp::Upsert { json } => {
                let raw = match json {
                    Some(path) => {
                        std::fs::read_to_string(&path).map_err(|e| format!("read {path}: {e}"))?
                    }
                    None => {
                        use std::io::Read;
                        let mut s = String::new();
                        std::io::stdin()
                            .read_to_string(&mut s)
                            .map_err(|e| format!("read stdin: {e}"))?;
                        s
                    }
                };
                let profile: SandboxProfile =
                    serde_json::from_str(&raw).map_err(|e| format!("parse profile json: {e}"))?;
                UiCommand::UpsertSandboxProfile(UpsertSandboxProfileReq { profile })
            }
            SandboxOp::Bind {
                server_id,
                profile_id,
            } => UiCommand::BindServerSandboxProfile(BindServerSandboxProfileReq {
                server_id,
                profile_id: if profile_id.as_deref() == Some("") {
                    None
                } else {
                    profile_id
                },
            }),
        },
        Cmd::VerifyChain => UiCommand::VerifyChain,
    })
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // 打开 Ledger
    let ledger = match &cli.db_path {
        Some(p) => Ledger::open(p),
        None => Ledger::open_in_memory(),
    };
    let ledger = match ledger {
        Ok(l) => l,
        Err(_e) => {
            // Codex R1 MUST-FIX:不把 ledger 底层错误原文(可能含 SQL / 路径 / secret)入 stderr。
            // 只回传稳定 reason_code。开发者可用 RUST_LOG= + tracing 看底层。
            eprintln!(
                r#"{{"kind":"LedgerError","detail":{{"reason_code":"ledger_open_failed"}}}}"#
            );
            return ExitCode::from(2);
        }
    };

    let ui_cmd = match build_command(cli.cmd) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!(
                r#"{{"kind":"Invalid","detail":"{}"}}"#,
                msg.replace('"', "'")
            );
            return ExitCode::from(2);
        }
    };

    match dispatch(ui_cmd, &ledger, cli.capability.into()) {
        Ok(resp) => {
            let mut out = std::io::stdout().lock();
            let _ = print_response(&mut out, &resp);
            ExitCode::SUCCESS
        }
        Err(err) => {
            let mut errw = std::io::stderr().lock();
            let _ = print_error(&mut errw, &err);
            ExitCode::from(1)
        }
    }
}
