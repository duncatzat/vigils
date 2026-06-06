//! `vigil-hub inspect` —— 命令行查询本地审计账本(activity / search / approvals /
//! session / servers / sandbox / verify-chain)。
//!
//! 由 v0.1.1 的 `vigil-desktop` 调试 CLI(I08a)整合而来:原 CLI 是 `apps/desktop` 包的
//! 第二个 `[[bin]]`,会被 `cargo tauri build` 误打进桌面安装包(替换掉真正的 GUI)。
//! v0.1.2 起把该 bin 从 desktop 包移除,能力以子命令形式归入产品主 CLI `vigil-hub`,
//! 复用 `vigil_desktop::{dispatch, render}` 同一套 Ledger 消费逻辑。
//!
//! 约定(沿用 I08a):stdout = 单行 JSON response;stderr = 错误 JSON;
//! 退出码 0=成功 / 1=dispatch 错误 / 2=参数或 ledger 打开失败。

use std::process::ExitCode;

use clap::{Args, Subcommand};
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

/// `vigil-hub inspect` 子命令参数。`--db-path` / `--capability` 对内层子命令全局可见。
#[derive(Debug, Args)]
pub struct InspectArgs {
    /// SQLite DB path(省略 = 默认共享账本 `VIGIL_LEDGER_PATH` / `<data 目录>/Vigil/ledger.sqlite3`,
    /// 即 `vigil-hub setup`/`hook` 用的同一个 → 直接看到被拦内容;无默认路径才退回内存空账本)
    #[arg(long, global = true)]
    db_path: Option<String>,

    /// capability level:read(默认 / 只读)或 write(允许改 approval / drift / profile)
    #[arg(long, global = true, default_value = "read")]
    capability: CapArg,

    #[command(subcommand)]
    cmd: InspectCmd,
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
enum InspectCmd {
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
    /// 保护成效汇总:一眼看清 Vigil 拦了多少裸 secret、脱敏了多少 tool-result 泄漏、审计了多少、
    /// 哈希链是否完整。turnkey(monitor 姿态)的"不阻塞 ≠ 没保护"证据面。
    Protection {
        /// 列出最近多少条保护类事件(裸 secret 拦截 / 泄漏脱敏 / alias 未解析)。
        #[arg(long, default_value_t = 10)]
        limit: u32,
        /// 输出结构化 JSON(默认人类可读摘要;`--json` 供脚本/文档/桌面复用)。
        #[arg(long)]
        json: bool,
    },
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
    /// 展示某 server 的 onboarding 数据(exact argv 可见)
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

fn build_command(cmd: InspectCmd) -> Result<UiCommand, String> {
    Ok(match cmd {
        InspectCmd::Activity {
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
        InspectCmd::Event { id } => UiCommand::GetEventDetail(GetEventDetailReq { event_id: id }),
        InspectCmd::Search { query, limit } => UiCommand::FtsSearch(FtsSearchReq { query, limit }),
        InspectCmd::Approvals { op } => match op {
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
        InspectCmd::Session { op } => match op {
            SessionOp::List { source, limit } => {
                UiCommand::ListSessions(ListSessionsReq { source, limit })
            }
            SessionOp::Replay { session_id, verify } => {
                UiCommand::ReplaySession(ReplaySessionReq { session_id, verify })
            }
        },
        InspectCmd::Servers { op } => match op {
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
        InspectCmd::Sandbox { op } => match op {
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
        InspectCmd::VerifyChain => UiCommand::VerifyChain,
        // Protection 在 run() 中先于 build_command 被拦截直渲染(不走 UiCommand dispatch);
        // 走到这里说明调用顺序被改坏 —— 防御性返回 Err(而非 panic)。
        InspectCmd::Protection { .. } => {
            return Err("protection summary is rendered directly, not via UiCommand".to_string())
        }
    })
}

/// 执行 `vigil-hub inspect <cmd>`:打开 ledger → 构造 UiCommand → dispatch → 渲染 JSON。
/// 渲染 `inspect protection` 的保护成效汇总(ASCII-safe,cp936/cp437 不乱码)。
/// `json=true` → 单行结构化 JSON(脚本/文档/桌面复用);否则人类可读 proof-of-value 摘要。
/// 退出码:0 成功 / 1 聚合查询失败。
fn render_protection(ledger: &Ledger, limit: u32, json: bool) -> ExitCode {
    let summary = match ledger.protection_summary(limit) {
        Ok(s) => s,
        Err(_e) => {
            // 不回显底层错误原文(可能含路径/SQL);只给稳定 reason_code(与 run() 一致)。
            eprintln!(
                r#"{{"kind":"LedgerError","detail":{{"reason_code":"protection_summary_failed"}}}}"#
            );
            return ExitCode::from(1);
        }
    };

    if json {
        // serde 化 ProtectionSummary(含 recent EventHit,均已脱敏);失败极罕见 → reason_code。
        match serde_json::to_string(&summary) {
            Ok(s) => {
                println!("{s}");
                return ExitCode::SUCCESS;
            }
            Err(_) => {
                eprintln!(
                    r#"{{"kind":"SerializeError","detail":{{"reason_code":"protection_json_failed"}}}}"#
                );
                return ExitCode::from(1);
            }
        }
    }

    // 人类可读:计数是主角(proof-of-value);措辞**诚实**——陈述"已观察到的保护结果",不夸大。
    let chain = if summary.chain_intact {
        "intact (audit log not tampered)"
    } else {
        "TAMPERED -- run `vigil-hub inspect verify-chain` for details"
    };
    println!("What Vigil has protected (observed in the local audit ledger)");
    println!(
        "  Secrets blocked at input:     {:>6}   (raw secrets denied before reaching the server/model)",
        summary.raw_secrets_blocked
    );
    println!(
        "  Tool-result leaks detected:   {:>6}   (secrets in tool output; redacted before the agent when result redaction is on)",
        summary.tool_result_leaks_detected
    );
    println!(
        "  Secret aliases withheld:      {:>6}   (secret:// placeholders that did not resolve -> denied)",
        summary.secret_aliases_unresolved
    );
    println!(
        "  Events audited:               {:>6}   across {} session(s)",
        summary.total_events_audited, summary.sessions_covered
    );
    println!("  Audit chain integrity:        {chain}");

    if !summary.chain_intact {
        // fail-closed:链不可信时 protection_summary 已抑制 recent;诚实说明明细被扣留(非"无事件")。
        println!();
        println!(
            "  Recent-event detail withheld: the audit chain failed verification, so the stored"
        );
        println!(
            "  redacted summaries cannot be trusted. Run `vigil-hub inspect verify-chain` to triage."
        );
    } else if summary.recent.is_empty() {
        println!();
        println!(
            "  No protection events yet. Run your MCP tools through Vigil (vigil-hub setup --mcp"
        );
        println!(
            "  --apply, then use your agent normally) -- Vigil records and redacts as they execute."
        );
    } else {
        println!();
        println!("  Recent protection events (redacted summaries only):");
        for e in &summary.recent {
            // session_id 截断展示(短 id 便于扫读);redacted_text 已脱敏,缺省给占位。
            let sid: String = e.session_id.chars().take(8).collect();
            let summ = e.redacted_text.as_deref().unwrap_or("(no summary)");
            println!(
                "    #{:<6} {:<28} [{}] {}",
                e.event_id, e.event_type, sid, summ
            );
        }
    }
    ExitCode::SUCCESS
}

pub fn run(args: InspectArgs) -> ExitCode {
    // 打开 Ledger:--db-path 优先;省略 → 默认**共享账本**(与 setup/hook 同一个,
    // 让 `vigil-hub setup` 后直接 `vigil-hub inspect activity` 就能看到被拦内容);
    // 连默认路径都无法解析(无 data 目录且未设 VIGIL_LEDGER_PATH)才退回内存空账本。
    let ledger = match &args.db_path {
        Some(p) => Ledger::open(p),
        None => match crate::setup::default_ledger_path() {
            Some(p) => Ledger::open(&p),
            None => Ledger::open_in_memory(),
        },
    };
    let ledger = match ledger {
        Ok(l) => l,
        Err(_e) => {
            // 不把 ledger 底层错误原文(可能含 SQL / 路径 / secret)入 stderr;
            // 只回稳定 reason_code。开发者可用 RUST_LOG= + tracing 看底层。
            eprintln!(
                r#"{{"kind":"LedgerError","detail":{{"reason_code":"ledger_open_failed"}}}}"#
            );
            return ExitCode::from(2);
        }
    };

    // protection:CLI 专属"保护成效"汇总(只读聚合,面向用户的 proof-of-value 摘要)。**不**走
    // UiCommand dispatch —— 它不是数据查询,且避免再碰已与内部仓分叉的 ui-protocol/dispatcher/render
    // (本增量刻意把改动收敛到 vigil-audit 数据层 + 本 CLI 文件两处)。按引用匹配,不移动 args.cmd。
    if let InspectCmd::Protection { limit, json } = &args.cmd {
        return render_protection(&ledger, *limit, *json);
    }

    let ui_cmd = match build_command(args.cmd) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!(
                r#"{{"kind":"Invalid","detail":"{}"}}"#,
                msg.replace('"', "'")
            );
            return ExitCode::from(2);
        }
    };

    match dispatch(ui_cmd, &ledger, args.capability.into()) {
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
