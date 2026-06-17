//! I08b-α1+α2 GUI 二进制入口(feature = "gui")。
//!
//! # 架构
//!
//! - `main()` 启动 `tauri::Builder`
//! - invoke handler 调用 `vigil_desktop::dispatch`(复用 I08a CLI 的同一 dispatch 逻辑)
//!
//! # α 范围
//!
//! - α1:`list_sessions`(smoke;本轮顺手修 α1 遗留 DTO 字段 bug — `UiResponse` variant
//!   名应是 `SessionList` 非 `Sessions`,`SessionSummary` 字段名 `started_at` 非
//!   `created_at`)
//! - α2:Approval Queue 全套 — `list_pending_approvals` / `get_approval_detail`
//!   / `resolve_approval`,共 **3 新 invoke handler**
//! - α3:Activity Feed 全套 — `list_recent_events` / `get_event_detail` /
//!   `fts_search`,共 **3 新 invoke handler**(全部 Read)
//! - α4:Server Registry 全套 — 5 Read + 5 Write,共 **10 新 invoke handler**
//!   (list_servers / get_server_onboarding / list_pending_tool_approvals /
//!   list_drifted_tools / list_drifted_servers / approve_tool / approve_tool_drift /
//!   reject_tool_drift / approve_server_command_drift / reject_server_command_drift)
//! - α5:Session Replay —— 2 新 Read handler(`replay_session` /
//!   `verify_chain`);list_sessions α1 已实装直接复用
//! - β1:Tauri `AppManifest::commands` 真白名单(见 `src/commands.rs` SSOT)
//! - β3:`EffectKind` TS enum 强类型化(前端 ApprovalDetailDrawer)
//! - β5(本轮):Ledger 磁盘持久化 —— 从 `open_in_memory` 切换到
//!   `dirs::data_local_dir()/Vigil/ledger.sqlite3`(跨平台);支持
//!   `VIGIL_LEDGER_PATH` 环境变量覆盖;fail-closed(打开失败 exit(1) 不回退 in-memory)
//!
//! # 安全不变量的当前范围
//!
//! - CSP:`script-src 'self'` / 禁 `unsafe-eval`(`tauri.conf.json` 守门)
//! - Capability(`capabilities/default.json`)同时管 **系统能力**(window / core)与
//!   **应用层 invoke 命令白名单**(β1 起由 `AppManifest::commands` 构建期生成 `allow-*`
//!   permission,`capabilities/default.json` 显式引用;未列入 SSOT 的 handler
//!   frontend invoke 会被 ACL 拒绝 —— hard gate)
//! - SSOT:`vigil_desktop::commands::INVOKE_COMMANDS`(三处必须同步:SSOT + 本文件
//!   `generate_handler!` + `capabilities/default.json`;由单元测试精确集合比对守门)
//! - payload 只暴露 redacted 字段(UiCommand / ApprovalSummary 已内建脱敏)
//!
//! # 已知未实装(延 β 后续 / MVP 后)
//!
//! - 实时更新(Tauri event / SSE),当前前端靠 5s polling
//! - E2E(Playwright + tauri-driver 延 β4)
//! - specta TS 类型自动生成(手写 TS 镜像漂移预防,延 β2)

use std::sync::Arc;

use tauri::{Emitter, Manager, State};
use vigil_audit::{
    CheckpointLog, EventHit, Ledger, ProtectionSummary, ServerOnboardingData, StoredServerProfile,
    ToolApprovalCard,
};
use vigil_desktop::dispatch;
use vigil_mcp::Hub;

// ─────────────────────── Theme G(v0.15):real-time ledger poller ───────────────────────
//
// Codex design ACCEPT(spike R2,docs/operations/v0.15-roadmap/theme-g-realtime-spike.md):
// 后台只读 poll `Ledger::latest_event_id()`(MAX(event_id)),变化即 emit
// `ledger-events-changed` → 前端 event-backed 页(Activity/Approval/Server/Replay)单一
// listener 替代 4 路 setInterval。**语义边界**:锚点仅覆盖 event-backed 变更;
// redaction_scans/findings + sessions 直写表不被覆盖,PrivacyFindings 仍走 fallback poll。
//
// **ADR 0014 边界**(Codex 确认):复用既有 `Arc<Ledger>`(不二次 `Ledger::open`);只读
// `SELECT MAX` 与 Hub 写共享同一 `Mutex<Connection>`,1s 间隔锁争用可忽略;emit payload
// 仅 `latest_event_id` 整数(无内容,符合 §I-9.1);fail-soft 不影响 firewall/Hub fail-closed。

/// poll 间隔(ms)。1s 远优于前端原 5s,且后端单点取代 4 路前端 timer。
const LEDGER_POLL_INTERVAL_MS: u64 = 1000;

/// `ledger-events-changed` 事件 payload —— **仅** 单调整数,零内容泄漏。
#[derive(Clone, serde::Serialize)]
struct LedgerEventsChanged {
    latest_event_id: i64,
}
use vigil_ui_protocol::{
    ApprovalDetailDto, ApprovalResolutionDto, ApprovalSummary, ApproveServerCommandDriftReq,
    ApproveToolDriftReq, ApproveToolReq, Capability, ChainVerifyReport, EventDetail, EventSummary,
    ExportSessionReplayReq, FtsSearchReq, GetApprovalDetailReq, GetEventDetailReq,
    GetServerOnboardingReq, ListPendingApprovalsReq, ListPrivacyFindingsReq, ListRecentEventsReq,
    ListSessionsReq, PrivacyFindingsDto, RejectServerCommandDriftReq, RejectToolDriftReq,
    ReplaySessionReq, ResolveApprovalReq, SessionExportDto, SessionReplay, UiCommand, UiResponse,
};

/// Tauri 状态:持有 Ledger 句柄(进程单例,α1 默认内存;β 改为用户数据目录 SQLite)。
///
/// **Capability 策略**(R1 MUST-FIX 修复 — least privilege):
/// - `read_capability = Capability::Read` 是 session 默认,传给只读 handler(list_* / get_*)
/// - 写 handler(`resolve_approval` 等)**内部显式**使用 `Capability::Write`,
///   而不从 state 读 — 让"需要 Write"这个事实**显式声明**在 handler 本身,
///   review 时一眼可见,也避免 renderer bug / bad-cmd 把读 handler 偷偷升级为写。
/// - 后续 α 如果有 "只读 UI 模式"(审计员用),改为 state 里存 AtomicBool guard,
///   对写 handler 额外加 guard 校验;本 α2 MVP 先靠"显式 Write on write handler"双层。
struct AppState {
    ledger: Arc<Ledger>,
    /// session 级默认 capability — **Read**(least privilege)
    read_capability: Capability,
}

/// 前端可读 shape — SessionSummary 投射。
#[derive(serde::Serialize)]
struct SessionView {
    session_id: String,
    source: String,
    app_name: Option<String>,
    started_at: i64,
    ended_at: Option<i64>,
    risk_score: i64,
}

// ─────────────────────────── α1 invoke handler ───────────────────────────

/// `invoke('list_sessions', { req })` → UiCommand::ListSessions → Ledger.list_sessions
#[tauri::command]
async fn list_sessions(
    req: ListSessionsReq,
    state: State<'_, AppState>,
) -> Result<Vec<SessionView>, String> {
    let resp = dispatch(
        UiCommand::ListSessions(req),
        state.ledger.as_ref(),
        state.read_capability,
    )
    .map_err(|e| e.to_string())?;

    match resp {
        UiResponse::SessionList(rows) => Ok(rows
            .into_iter()
            .map(|s| SessionView {
                session_id: s.session_id,
                source: s.source,
                app_name: s.app_name,
                started_at: s.started_at,
                ended_at: s.ended_at,
                risk_score: s.risk_score,
            })
            .collect()),
        other => Err(format!(
            "unexpected response shape for list_sessions: {other:?}"
        )),
    }
}

// ─────────────────────────── α2 invoke handlers ──────────────────────────

/// `invoke('list_pending_approvals', { req })` → UiCommand::ListPendingApprovals →
/// Ledger pending query。
///
/// 返回 `ApprovalSummary` 列表(已脱敏 — 只含 title/summary/status/expires_at)。
#[tauri::command]
async fn list_pending_approvals(
    req: ListPendingApprovalsReq,
    state: State<'_, AppState>,
) -> Result<Vec<ApprovalSummary>, String> {
    let resp = dispatch(
        UiCommand::ListPendingApprovals(req),
        state.ledger.as_ref(),
        state.read_capability,
    )
    .map_err(|e| e.to_string())?;

    match resp {
        UiResponse::ApprovalList(rows) => Ok(rows),
        other => Err(format!(
            "unexpected response shape for list_pending_approvals: {other:?}"
        )),
    }
}

/// `invoke('get_approval_detail', { req })` → UiCommand::GetApprovalDetail →
/// Ledger.get_approval(含 request / invocation_id / decision_id)。
///
/// payload 完全来自 I08a 的 ApprovalDetailDto(ADR 0008 已确认脱敏)。
#[tauri::command]
async fn get_approval_detail(
    req: GetApprovalDetailReq,
    state: State<'_, AppState>,
) -> Result<ApprovalDetailDto, String> {
    let resp = dispatch(
        UiCommand::GetApprovalDetail(req),
        state.ledger.as_ref(),
        state.read_capability,
    )
    .map_err(|e| e.to_string())?;

    match resp {
        UiResponse::ApprovalDetail(dto) => Ok(dto),
        other => Err(format!(
            "unexpected response shape for get_approval_detail: {other:?}"
        )),
    }
}

/// `invoke('export_session_replay', { req })` → UiCommand::ExportSessionReplay →
/// 渲染 MD/HTML 文本(payload 已在 audit 入库时脱敏,渲染层只组装)。
///
/// ISS-018 — Safe Export。caller(前端)拿到 `content` 后用 Blob + `<a download>`
/// 触发浏览器下载;**不**走文件系统(Tauri 进程不直接写文件,避免提权 FS write)。
#[tauri::command]
async fn export_session_replay(
    req: ExportSessionReplayReq,
    state: State<'_, AppState>,
) -> Result<SessionExportDto, String> {
    let resp = dispatch(
        UiCommand::ExportSessionReplay(req),
        state.ledger.as_ref(),
        state.read_capability,
    )
    .map_err(|e| e.to_string())?;

    match resp {
        UiResponse::SessionExport(dto) => Ok(dto),
        other => Err(format!(
            "unexpected response shape for export_session_replay: {other:?}"
        )),
    }
}

/// D19:**保护成效概览**(`invoke('protection_summary')` → `Ledger::protection_summary`)。
///
/// 把 CLI `vigil-hub inspect protection`(D11)的"Vigil 拦下了什么"汇总面延伸到桌面 GUI(面向
/// 非 CLI 受众的 audit 控制台)。**只读**:聚合**持久化**账本事件(裸 secret 拦截 / tool-result
/// 泄漏检测 / secret:// alias 未解析 + 总量 / session 数 / 链完整性 + 最近 N 条脱敏摘要)。
///
/// **fail-closed 不变量沿用 `protection_summary`**(D11-B Codex):内部先 `verify_chain`,链被篡改
/// 时 `recent` **强制为空**(篡改账本的 `redacted_text` 可能被注入原始 secret,链不可信绝不回显明细)。
/// `ProtectionSummary` 本身 `serde::Serialize`,直接作 Tauri 返回(无需独立 DTO);`recent` 的 `EventHit`
/// 只含已脱敏字段。直调 ledger(read-only,与 CLI inspect 同源直调,不经 dispatch 写门)。
#[tauri::command]
async fn protection_summary(state: State<'_, AppState>) -> Result<ProtectionSummary, String> {
    // 最近事件展示条数(与 CLI inspect protection 默认一致量级);链坏时由 protection_summary 抑制为空。
    const RECENT_LIMIT: u32 = 8;
    state
        .ledger
        .protection_summary(RECENT_LIMIT)
        .map_err(|e| e.to_string())
}

/// 手动触发审计检查点锚定(`Settings → Checkpoint anchor`)。
///
/// 绑定到 ledger 同目录 sidecar(`<ledger>.checkpoints`),追加当前链头事件作为锚点。
/// 空账本或链头未前进时返回 `None`,表示没有新的前缀可锚;成功时返回锚点 event_id。
#[tauri::command]
async fn anchor_checkpoint(state: State<'_, AppState>) -> Result<Option<i64>, String> {
    let ledger_path = vigil_desktop::ledger_path::resolve_ledger_path(
        std::env::var(vigil_desktop::ledger_path::LEDGER_ENV_VAR)
            .ok()
            .as_deref(),
        dirs::data_local_dir().as_deref(),
    )
    .map_err(|e| format!("resolve_ledger_path failed: {e}"))?;

    let log = CheckpointLog::sidecar_for(&ledger_path);
    let checkpoint = log.emit(state.ledger.as_ref()).map_err(|e| e.to_string())?;
    Ok(checkpoint.map(|cp| cp.event_id))
}

/// `invoke('list_privacy_findings', { req })` → UiCommand::ListPrivacyFindings →
/// Ledger.aggregate_redaction_labels_global + list_recent_redaction_scans_with_counts.
///
/// ISS-017 — Privacy Findings 面板的全局聚合视图。返回 (label×count) 全局聚合 +
/// 最近 N 条 scans 摘要。**绝不展原文**:DTO 仅含 label / fingerprint / count /
/// bucket 元数据(audit `test_schema_forbids_plaintext_columns` 不变量延伸到 UI 层)。
#[tauri::command]
async fn list_privacy_findings(
    req: ListPrivacyFindingsReq,
    state: State<'_, AppState>,
) -> Result<PrivacyFindingsDto, String> {
    let resp = dispatch(
        UiCommand::ListPrivacyFindings(req),
        state.ledger.as_ref(),
        state.read_capability,
    )
    .map_err(|e| e.to_string())?;

    match resp {
        UiResponse::PrivacyFindings(dto) => Ok(dto),
        other => Err(format!(
            "unexpected response shape for list_privacy_findings: {other:?}"
        )),
    }
}

/// `invoke('resolve_approval', { req })` → `Hub::resolve_approval` 直走 in-process
/// `Ledger::approve/deny/cancel`,内部已 atomic publish-after-write
/// (`crates/vigil-audit/src/approvals.rs:700-704`)。
///
/// **写 handler 语义**:调用 `Hub::resolve_approval` 等价 `Capability::Write`
/// (见 `crates/vigil-mcp/src/hub.rs` doc + ADR 0014 Revised α2)。Hub 不暴露给
/// renderer,renderer 经 Tauri capability ACL gate(`allow-resolve-approval`)
/// 才能 invoke;无绕过路径。
///
/// **dispatch 路径退役**:原走 dispatcher 的 Resolve 分支与本路径功能等价
/// (都最终调 `Ledger::approve/deny/cancel`),改走 Hub 是为对齐
/// ADR 0014 α2 — Hub 是 single point of change for α3+ 优化。
#[tauri::command]
async fn resolve_approval(
    req: ResolveApprovalReq,
    hub: State<'_, Arc<Hub>>,
) -> Result<ApprovalResolutionDto, String> {
    hub.resolve_approval(req).map_err(|e| e.to_string())
}

// ─────────────────────────── α3 invoke handlers(Activity Feed)──────────

/// `invoke('list_recent_events', { req })` → UiCommand::ListRecentEvents →
/// Ledger 事件流查询(可选 session / event_type 过滤,limit 上限)。
///
/// 返回 `EventSummary` 列表(event_id/session_id/event_type/redacted_text/created_at)。
/// `redacted_text` 已经在 vigil-audit 写入时脱敏,前端可直接 `{{ }}` 插值。
#[tauri::command]
async fn list_recent_events(
    req: ListRecentEventsReq,
    state: State<'_, AppState>,
) -> Result<Vec<EventSummary>, String> {
    let resp = dispatch(
        UiCommand::ListRecentEvents(req),
        state.ledger.as_ref(),
        state.read_capability,
    )
    .map_err(|e| e.to_string())?;

    match resp {
        UiResponse::EventList(rows) => Ok(rows),
        other => Err(format!(
            "unexpected response shape for list_recent_events: {other:?}"
        )),
    }
}

/// `invoke('get_event_detail', { req })` → UiCommand::GetEventDetail →
/// Ledger.get_event(含 payload Value + prev_hash + event_hash)。
///
/// payload 是 JCS 规范化后的 JSON Value(已脱敏),前端用 `JSON.stringify(payload, null, 2)`
/// 渲染到 `<pre>{{ }}`。
#[tauri::command]
async fn get_event_detail(
    req: GetEventDetailReq,
    state: State<'_, AppState>,
) -> Result<EventDetail, String> {
    let resp = dispatch(
        UiCommand::GetEventDetail(req),
        state.ledger.as_ref(),
        state.read_capability,
    )
    .map_err(|e| e.to_string())?;

    match resp {
        UiResponse::EventDetail(dto) => Ok(dto),
        other => Err(format!(
            "unexpected response shape for get_event_detail: {other:?}"
        )),
    }
}

/// `invoke('fts_search', { req })` → UiCommand::FtsSearch → Ledger.fts_match。
///
/// query 是 SQLite FTS5 MATCH 语法(`"token"` / `token1 AND token2` / `prefix*`)。
/// 返回 EventHit 列表(字段同 EventSummary,仅语义区分"FTS 命中")。
#[tauri::command]
async fn fts_search(
    req: FtsSearchReq,
    state: State<'_, AppState>,
) -> Result<Vec<EventHit>, String> {
    let resp = dispatch(
        UiCommand::FtsSearch(req),
        state.ledger.as_ref(),
        state.read_capability,
    )
    .map_err(|e| e.to_string())?;

    match resp {
        UiResponse::SearchHits(hits) => Ok(hits),
        other => Err(format!(
            "unexpected response shape for fts_search: {other:?}"
        )),
    }
}

// ─────────────────────────── α4 invoke handlers(Server Registry)────────
//
// 5 Read handler(用 `state.read_capability`)+ 5 Write handler(显式 `Capability::Write`,
// 与 α2 resolve_approval 同一 least-privilege pattern)。
//
// 响应类型全部为 `UiResponse` 真实 variant 经 match 投影(禁伪造),shape 来自
// `apps/desktop/src/dispatcher.rs` L168-L222 真实 match 分支。

/// `invoke('list_servers')` → UiCommand::ListServers → Ledger.list_approved_servers。
/// 返回 `StoredServerProfile` 列表(argv exact / command_hash / trust_level)。
#[tauri::command]
async fn list_servers(state: State<'_, AppState>) -> Result<Vec<StoredServerProfile>, String> {
    let resp = dispatch(
        UiCommand::ListServers,
        state.ledger.as_ref(),
        state.read_capability,
    )
    .map_err(|e| e.to_string())?;
    match resp {
        UiResponse::ServerList(rows) => Ok(rows),
        other => Err(format!(
            "unexpected response shape for list_servers: {other:?}"
        )),
    }
}

/// `invoke('get_server_onboarding', { req })` → UiCommand::GetServerOnboarding。
/// 返回 `ServerOnboardingData`(含 exact argv / env_keys / pending_command_hash 做 drift diff)。
#[tauri::command]
async fn get_server_onboarding(
    req: GetServerOnboardingReq,
    state: State<'_, AppState>,
) -> Result<ServerOnboardingData, String> {
    let resp = dispatch(
        UiCommand::GetServerOnboarding(req),
        state.ledger.as_ref(),
        state.read_capability,
    )
    .map_err(|e| e.to_string())?;
    match resp {
        UiResponse::ServerOnboarding(data) => Ok(data),
        other => Err(format!(
            "unexpected response shape for get_server_onboarding: {other:?}"
        )),
    }
}

/// `invoke('list_pending_tool_approvals')` → UiCommand::ListPendingToolApprovals。
/// 返回 `ToolApprovalCard` 列表(首次见,approved_at == None)。
#[tauri::command]
async fn list_pending_tool_approvals(
    state: State<'_, AppState>,
) -> Result<Vec<ToolApprovalCard>, String> {
    let resp = dispatch(
        UiCommand::ListPendingToolApprovals,
        state.ledger.as_ref(),
        state.read_capability,
    )
    .map_err(|e| e.to_string())?;
    match resp {
        UiResponse::ToolApprovalList(cards) => Ok(cards),
        other => Err(format!(
            "unexpected response shape for list_pending_tool_approvals: {other:?}"
        )),
    }
}

/// `invoke('list_drifted_tools')` → UiCommand::ListDriftedTools。
/// 返回 `ToolApprovalCard` 列表(proposed_hash != current_hash)。
#[tauri::command]
async fn list_drifted_tools(state: State<'_, AppState>) -> Result<Vec<ToolApprovalCard>, String> {
    let resp = dispatch(
        UiCommand::ListDriftedTools,
        state.ledger.as_ref(),
        state.read_capability,
    )
    .map_err(|e| e.to_string())?;
    match resp {
        UiResponse::ToolApprovalList(cards) => Ok(cards),
        other => Err(format!(
            "unexpected response shape for list_drifted_tools: {other:?}"
        )),
    }
}

/// `invoke('list_drifted_servers')` → UiCommand::ListDriftedServers。
/// 返回 `ServerOnboardingData` 列表(pending_command_hash.is_some())。
#[tauri::command]
async fn list_drifted_servers(
    state: State<'_, AppState>,
) -> Result<Vec<ServerOnboardingData>, String> {
    let resp = dispatch(
        UiCommand::ListDriftedServers,
        state.ledger.as_ref(),
        state.read_capability,
    )
    .map_err(|e| e.to_string())?;
    match resp {
        UiResponse::DriftedServerList(rows) => Ok(rows),
        other => Err(format!(
            "unexpected response shape for list_drifted_servers: {other:?}"
        )),
    }
}

/// `invoke('approve_tool', { req })` → UiCommand::ApproveTool(写路径,首次 tool 审批)。
/// **显式 `Capability::Write`**。
#[tauri::command]
async fn approve_tool(req: ApproveToolReq, state: State<'_, AppState>) -> Result<(), String> {
    let resp = dispatch(
        UiCommand::ApproveTool(req),
        state.ledger.as_ref(),
        Capability::Write,
    )
    .map_err(|e| e.to_string())?;
    match resp {
        UiResponse::Ack => Ok(()),
        other => Err(format!(
            "unexpected response shape for approve_tool: {other:?}"
        )),
    }
}

/// `invoke('approve_tool_drift', { req })` → UiCommand::ApproveToolDrift(漂移后认新 hash)。
#[tauri::command]
async fn approve_tool_drift(
    req: ApproveToolDriftReq,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let resp = dispatch(
        UiCommand::ApproveToolDrift(req),
        state.ledger.as_ref(),
        Capability::Write,
    )
    .map_err(|e| e.to_string())?;
    match resp {
        UiResponse::Ack => Ok(()),
        other => Err(format!(
            "unexpected response shape for approve_tool_drift: {other:?}"
        )),
    }
}

/// `invoke('reject_tool_drift', { req })` → UiCommand::RejectToolDrift(拒绝新 descriptor)。
#[tauri::command]
async fn reject_tool_drift(
    req: RejectToolDriftReq,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let resp = dispatch(
        UiCommand::RejectToolDrift(req),
        state.ledger.as_ref(),
        Capability::Write,
    )
    .map_err(|e| e.to_string())?;
    match resp {
        UiResponse::Ack => Ok(()),
        other => Err(format!(
            "unexpected response shape for reject_tool_drift: {other:?}"
        )),
    }
}

/// `invoke('approve_server_command_drift', { req })` → UiCommand::ApproveServerCommandDrift。
#[tauri::command]
async fn approve_server_command_drift(
    req: ApproveServerCommandDriftReq,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let resp = dispatch(
        UiCommand::ApproveServerCommandDrift(req),
        state.ledger.as_ref(),
        Capability::Write,
    )
    .map_err(|e| e.to_string())?;
    match resp {
        UiResponse::Ack => Ok(()),
        other => Err(format!(
            "unexpected response shape for approve_server_command_drift: {other:?}"
        )),
    }
}

/// `invoke('reject_server_command_drift', { req })` → UiCommand::RejectServerCommandDrift。
#[tauri::command]
async fn reject_server_command_drift(
    req: RejectServerCommandDriftReq,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let resp = dispatch(
        UiCommand::RejectServerCommandDrift(req),
        state.ledger.as_ref(),
        Capability::Write,
    )
    .map_err(|e| e.to_string())?;
    match resp {
        UiResponse::Ack => Ok(()),
        other => Err(format!(
            "unexpected response shape for reject_server_command_drift: {other:?}"
        )),
    }
}

// ─────────────────────────── α5 invoke handlers(Session Replay)─────────
//
// 2 新 Read handler:
//   - replay_session(session_id, verify):重放事件流 + 可选 hash chain verify
//   - verify_chain(标准读命令):ledger 级 hash chain 自检
//
// list_sessions 已在 α1 实装(SessionView 投射),α5 页面直接复用。

/// `invoke('replay_session', { req })` → UiCommand::ReplaySession → Ledger.replay_session。
///
/// 返回 `SessionReplay`(event_count + events 完整列表 + 可选 chain_verified)。
/// events 每条含 prev_hash / event_hash / payload(JCS);所有字符串已在 write 时脱敏。
///
/// **verify=true 时 `chain_verified` 是 ledger 级(非 session 级)验证** — 与 α3 EventDetail
/// 展示的哈希链语义一致;UI 应展示 "ledger-wide chain: OK / broken at event_id=XXX"。
#[tauri::command]
async fn replay_session(
    req: ReplaySessionReq,
    state: State<'_, AppState>,
) -> Result<SessionReplay, String> {
    let resp = dispatch(
        UiCommand::ReplaySession(req),
        state.ledger.as_ref(),
        state.read_capability,
    )
    .map_err(|e| e.to_string())?;
    match resp {
        UiResponse::ReplayDump(dump) => Ok(dump),
        other => Err(format!(
            "unexpected response shape for replay_session: {other:?}"
        )),
    }
}

/// `invoke('verify_chain')` → UiCommand::VerifyChain → Ledger.verify_chain。
///
/// `message` 字段经 I08a R1 MUST-FIX 处理:只承载 reason_code(`chain_broken_at=N`)
/// 或固定字符串(`chain_verify_failed`),**不透传底层 SQL / 路径 / secret 派生文本**。
#[tauri::command]
async fn verify_chain(state: State<'_, AppState>) -> Result<ChainVerifyReport, String> {
    let resp = dispatch(
        UiCommand::VerifyChain,
        state.ledger.as_ref(),
        state.read_capability,
    )
    .map_err(|e| e.to_string())?;
    match resp {
        UiResponse::ChainVerification(report) => Ok(report),
        other => Err(format!(
            "unexpected response shape for verify_chain: {other:?}"
        )),
    }
}

// ─────────────────────────── Tauri setup ──────────────────────────────────
//
// β5 Ledger 磁盘持久化:
// - `vigil_desktop::ledger_path::resolve_ledger_path` 是 lib 模块(默认 feature 下
//   含单测守门 fail-closed / env override / parent dir / 错误脱敏 8 条),依赖注入
//   本 binary 提供 `dirs::data_local_dir()` 查询结果
// - Fail-closed:任一步失败立即 `exit(1)`,**不回退 in-memory**,避免审计不变量无声丢失

fn main() {
    // β5:OS local data dir 查询(仅 gui feature 引 dirs;lib 侧 `ledger_path` 模块
    // 不依赖 dirs,测试传 tempdir 模拟)。
    let env_value = std::env::var(vigil_desktop::ledger_path::LEDGER_ENV_VAR).ok();
    let local_data = dirs::data_local_dir();
    let ledger_path = match vigil_desktop::ledger_path::resolve_ledger_path(
        env_value.as_deref(),
        local_data.as_deref(),
    ) {
        Ok(p) => p,
        Err(err) => {
            eprintln!("FATAL: {err}");
            std::process::exit(1);
        }
    };
    let ledger = match Ledger::open(&ledger_path) {
        Ok(l) => l,
        Err(_) => {
            // Ledger 错误含 SQLite 底层文本(可能携带路径等环境信息);只对用户展示
            // 文件位置 + 建议,不透传 thiserror Display 避免环境细节泄漏。
            eprintln!(
                "FATAL: failed to open ledger at {} (检查权限 / 磁盘剩余空间 / SQLite 版本;\
                 可设置 VIGIL_LEDGER_PATH 到其他路径验证)",
                ledger_path.display()
            );
            std::process::exit(1);
        }
    };
    // ledger 立刻 wrap Arc —— AppState 与 embed Hub 共享同一份(strong_count >= 2)
    let ledger = Arc::new(ledger);

    // assembly Hub fail-closed per ADR 0014 §3.4(α1 embed Hub 骨架)
    //
    // EmbedError Display 可能含 SQLite 底层文本(start_session 路径)/ Hub LockPoisoned;
    // 沿用 ledger Err 同款脱敏 pattern,只对用户展示通用建议,不透传 thiserror Display。
    let hub = match vigil_desktop::embed::gui_build_hub(Arc::clone(&ledger)) {
        Ok(h) => h,
        Err(_) => {
            eprintln!(
                "FATAL: failed to assemble Hub for embed Phase 1 \
                 (检查 ledger 写权限 / SQLite 状态;可设 VIGIL_LEDGER_PATH 到其他路径验证)"
            );
            std::process::exit(1);
        }
    };

    // Theme G real-time poller 独立持有一份 ledger Arc(只读;与 AppState / Hub 共享同库)
    let ledger_for_poller = Arc::clone(&ledger);

    tauri::Builder::default()
        .manage(AppState {
            ledger: Arc::clone(&ledger),
            // Least privilege — session 默认 Read;写 handler 内部显式升 Write。
            read_capability: Capability::Read,
        })
        // ADR 0014 α1:Arc<Hub> 独立 manage(Tauri State 按 type 索引);
        // α2 写 resolve_approval handler 时可同时 inject `State<'_, AppState>` +
        // `State<'_, Arc<Hub>>`,把 Ledger-write 与 Hub.approval_broker.publish() 双路 atomic
        .manage(hub)
        .invoke_handler(tauri::generate_handler![
            // α1
            list_sessions,
            // α2(Approval Queue 全套)
            list_pending_approvals,
            get_approval_detail,
            resolve_approval,
            // α3(Activity Feed 全套)
            list_recent_events,
            get_event_detail,
            fts_search,
            // α4(Server Registry 全套 —— 5 read + 5 write)
            list_servers,
            get_server_onboarding,
            list_pending_tool_approvals,
            list_drifted_tools,
            list_drifted_servers,
            approve_tool,
            approve_tool_drift,
            reject_tool_drift,
            approve_server_command_drift,
            reject_server_command_drift,
            // α5(Session Replay —— 2 read)
            replay_session,
            verify_chain,
            // ISS-017(Privacy Findings panel —— 1 read)
            list_privacy_findings,
            // ISS-018(Safe Export —— 1 read)
            export_session_replay,
            // D19(Protection Overview —— 1 read)
            protection_summary,
            // Settings: 手动锚定审计检查点
            anchor_checkpoint,
        ])
        .setup(move |app| {
            let _main_window = app.get_webview_window("main");

            // Theme G:real-time ledger-events-changed poller(read-only,fail-soft)。
            // 专用 OS 线程 + std sleep —— KISS,避免 async runtime 耦合;AppHandle.emit 同步。
            let handle = app.handle().clone();
            let poll_ledger = ledger_for_poller;
            std::thread::spawn(move || {
                let mut last_seen: Option<i64> = None;
                let mut was_err = false; // 防 1/s 错误刷屏:仅在进入错误态时打印一次
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(
                        LEDGER_POLL_INTERVAL_MS,
                    ));
                    match poll_ledger.latest_event_id() {
                        Ok(latest) => {
                            was_err = false;
                            if latest != last_seen {
                                last_seen = latest;
                                // 空 ledger(None)不 emit;有 event 才推送锚点。
                                if let Some(id) = latest {
                                    // emit 失败(无 window 等)忽略 —— 下次变更再推。
                                    let _ = handle.emit(
                                        "ledger-events-changed",
                                        LedgerEventsChanged { latest_event_id: id },
                                    );
                                }
                            }
                        }
                        Err(_) => {
                            // fail-soft:不 panic、不影响 firewall/Hub;脱敏日志(不含 ledger 细节)
                            if !was_err {
                                eprintln!(
                                    "WARN: ledger real-time poller read failed; will retry \
                                     (UI falls back to manual refresh)"
                                );
                                was_err = true;
                            }
                        }
                    }
                }
            });

            Ok(())
        })
        .run(tauri::generate_context!())
        // fail-closed:Tauri runtime 启动失败立即 exit(1)(不静默 panic),
        // 与 ADR 0014 §3.4 + ledger / Hub 组装错误处理同款脱敏 pattern;
        // unwrap_or_else 而非 expect 是 clippy::expect_used + ADR fail-closed 的双兼容。
        .unwrap_or_else(|_| {
            eprintln!("FATAL: tauri runtime failed to start");
            std::process::exit(1);
        });
}
