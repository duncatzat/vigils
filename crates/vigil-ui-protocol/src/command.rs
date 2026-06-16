//! `UiCommand`:typed 枚举协议(ADR 0008 §D3)。
//!
//! 框架无关:CLI(I08a)/ Tauri(I08b)/ 未来 Web / 测试 harness 都可复用同一个枚举。
//!
//! Capability 模型(ADR 0008 §D4 / §I-8.4):
//! - 读命令 → `Capability::Read`
//! - 写命令 → `Capability::Write`
//! - 调用方必须先调 `required_capability()` 做静态配额检查

use serde::{Deserialize, Serialize};
use vigil_types::ApprovalScope;

/// 每条命令所需的权限级别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Capability {
    /// 只读命令(查询 Ledger 不改状态)
    Read,
    /// 写命令(改 approval / drift / sandbox profile 绑定等)
    Write,
}

/// UI 层的所有命令。每个变种带自己的 payload struct。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", content = "args")]
#[non_exhaustive]
pub enum UiCommand {
    // --- Activity / Audit ---
    /// 列最近的 AuditEvents(可选 session / 类型过滤)
    ListRecentEvents(ListRecentEventsReq),
    /// 按 event_id 拿单条详细 payload
    GetEventDetail(GetEventDetailReq),
    /// FTS5 搜索 redacted_text
    FtsSearch(FtsSearchReq),

    // --- Approval Queue ---
    /// 列 Pending 状态的 approvals
    ListPendingApprovals(ListPendingApprovalsReq),
    /// 拿某 approval 的完整细节(effect vector + decision)
    GetApprovalDetail(GetApprovalDetailReq),
    /// 批准 / 拒绝 / 取消
    ResolveApproval(ResolveApprovalReq),

    // --- Privacy Findings(ISS-017,Stage 3 wave-4)---
    /// 全局 Privacy Findings 聚合视图(label × count + 最近 scans 列表)
    ListPrivacyFindings(ListPrivacyFindingsReq),

    // --- Session Replay ---
    /// 列所有 sessions
    ListSessions(ListSessionsReq),
    /// 重放某 session(结构化事件 + 可选 verify_chain)
    ReplaySession(ReplaySessionReq),
    /// 单独触发 hash chain verify
    VerifyChain,
    /// ISS-018 — Safe Export:把 session replay 渲染为 MD / HTML 文本,
    /// **payload 已在 events 入库时由 vigil-redaction 脱敏**,渲染层只读不改;
    /// 输出 content 由 caller 触发浏览器 download。
    ExportSessionReplay(ExportSessionReplayReq),
    /// 将当前链头锚定到 sidecar checkpoint 文件(写命令)
    AnchorCheckpoint,
    /// 实时更新运行中 Hub 的保护策略配置(写命令)
    UpdateHubConfig(UpdateHubConfigReq),

    // --- ONNX Model Management ---
    /// 列出本地 ONNX 模型状态(只读)
    ListOnnxModels,
    /// 触发指定 ONNX 模型的下载/校验(写命令;后台执行)
    EnsureOnnxModel(EnsureOnnxModelReq),

    // --- Server Registry ---
    /// 登记新 server(写命令)
    RegisterServer(RegisterServerReq),
    /// 列已登记的 servers
    ListServers,
    /// 取某 server 的 onboarding 数据(transport / argv / env keys)
    GetServerOnboarding(GetServerOnboardingReq),
    /// 列首次待批准的 tool descriptor
    ListPendingToolApprovals,
    /// 列已 drift 的 tools
    ListDriftedTools,
    /// 列已 drift 的 servers
    ListDriftedServers,
    /// 首次批准 tool descriptor
    ApproveTool(ApproveToolReq),
    /// drift 后批准到新 hash
    ApproveToolDrift(ApproveToolDriftReq),
    /// drift reject(保留旧 hash)
    RejectToolDrift(RejectToolDriftReq),
    /// server command drift 批准
    ApproveServerCommandDrift(ApproveServerCommandDriftReq),
    /// server command drift 拒绝
    RejectServerCommandDrift(RejectServerCommandDriftReq),

    // --- SandboxProfile(I07 延后项) ---
    /// 列所有 sandbox profiles
    ListSandboxProfiles,
    /// 按 id 取 profile
    GetSandboxProfile(GetSandboxProfileReq),
    /// 新建或覆盖 profile(写命令)
    UpsertSandboxProfile(UpsertSandboxProfileReq),
    /// 绑定 server → profile
    BindServerSandboxProfile(BindServerSandboxProfileReq),
}

impl UiCommand {
    /// 返回本命令要求的权限级别(ADR §I-8.4)。
    pub fn required_capability(&self) -> Capability {
        use UiCommand::*;
        match self {
            // Read
            ListRecentEvents(_)
            | GetEventDetail(_)
            | FtsSearch(_)
            | ListPendingApprovals(_)
            | GetApprovalDetail(_)
            | ListPrivacyFindings(_)
            | ListSessions(_)
            | ExportSessionReplay(_)
            | ReplaySession(_)
            | VerifyChain
            | ListServers
            | GetServerOnboarding(_)
            | ListPendingToolApprovals
            | ListDriftedTools
            | ListDriftedServers
            | ListSandboxProfiles
            | GetSandboxProfile(_)
            | ListOnnxModels => Capability::Read,
            // Write
            AnchorCheckpoint
            | UpdateHubConfig(_)
            | EnsureOnnxModel(_)
            | RegisterServer(_)
            | ResolveApproval(_)
            | ApproveTool(_)
            | ApproveToolDrift(_)
            | RejectToolDrift(_)
            | ApproveServerCommandDrift(_)
            | RejectServerCommandDrift(_)
            | UpsertSandboxProfile(_)
            | BindServerSandboxProfile(_) => Capability::Write,
        }
    }
}

// ---------------- Payload structs ----------------

/// ListRecentEvents 参数。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListRecentEventsReq {
    /// 只看某个 session(None = 所有)
    pub session_id: Option<String>,
    /// 事件类型过滤(None = 全部)
    pub event_type_filter: Option<Vec<String>>,
    /// 返回上限
    pub limit: u32,
}

/// GetEventDetail 参数。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetEventDetailReq {
    /// events.event_id
    pub event_id: i64,
}

/// FtsSearch 参数。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FtsSearchReq {
    /// FTS5 MATCH 语法
    pub query: String,
    /// 结果上限
    pub limit: u32,
}

/// ListPendingApprovals 参数。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListPendingApprovalsReq {
    /// 可选 session 过滤
    pub session_id: Option<String>,
}

/// ISS-018 — Safe Export 输出格式。
///
/// MD / HTML 在本 phase 实装;PDF 留 phase 2(需 Rust PDF 库或浏览器侧 print)。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    /// Markdown(`.md`)— 文本可读,易于审计员粘贴 / diff
    Md,
    /// HTML(`.html`)— 含 inline CSS,适合直接在浏览器打开预览
    Html,
}

impl ExportFormat {
    /// 返回该格式的 MIME type(浏览器 download 用)
    pub fn mime(&self) -> &'static str {
        match self {
            ExportFormat::Md => "text/markdown; charset=utf-8",
            ExportFormat::Html => "text/html; charset=utf-8",
        }
    }
    /// 返回该格式的文件扩展名(不含 `.`)
    pub fn extension(&self) -> &'static str {
        match self {
            ExportFormat::Md => "md",
            ExportFormat::Html => "html",
        }
    }
}

/// ISS-018 — ExportSessionReplay 参数。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportSessionReplayReq {
    /// 要导出的 session id
    pub session_id: String,
    /// 输出格式
    pub format: ExportFormat,
}

/// ListPrivacyFindings 参数(ISS-017)。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListPrivacyFindingsReq {
    /// 最近 scans 的返回上限。0 → ledger 用 50 默认;最大被 ledger clamp 到 500。
    /// caller 通常传 50-100 给 UI。
    pub limit_recent_scans: u32,
}

/// GetApprovalDetail 参数。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetApprovalDetailReq {
    /// approval id
    pub approval_id: String,
}

/// ResolveApproval 参数。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolveApprovalReq {
    /// approval id
    pub approval_id: String,
    /// 动作
    pub action: ApprovalAction,
    /// 批准时的 scope(Once / ThisSession);Deny/Cancel 时忽略
    pub scope: Option<ApprovalScope>,
    /// 解析人(审计 payload)
    pub resolved_by: String,
    /// Deny 时的可选原因(纯文本,已脱敏)
    pub reason: Option<String>,
}

/// Resolve approval 的动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalAction {
    /// 批准
    Approve,
    /// 拒绝
    Deny,
    /// 取消(用户主动撤)
    Cancel,
}

/// ListSessions 参数。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListSessionsReq {
    /// source 过滤(mcp_hub / desktop / ...)
    pub source: Option<String>,
    /// 返回上限
    pub limit: u32,
}

/// ReplaySession 参数。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplaySessionReq {
    /// session id
    pub session_id: String,
    /// 是否同时执行 verify_chain
    pub verify: bool,
}

/// RegisterServer 参数。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterServerReq {
    /// server id
    pub server_id: String,
    /// 传输类型("stdio" 或 "http")
    pub transport: String,
    /// Stdio 启动时的 argv；Http 时为 None
    pub command: Option<Vec<String>>,
    /// Http 传输时的 URL；Stdio 时为 None
    pub url: Option<String>,
}

/// GetServerOnboarding 参数。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetServerOnboardingReq {
    /// server id
    pub server_id: String,
}

/// ApproveTool 参数(首次批准)。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApproveToolReq {
    /// server id
    pub server_id: String,
    /// tool name(namespace 内的裸名,不含 `__`)
    pub tool_name: String,
}

/// ApproveToolDrift 参数。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApproveToolDriftReq {
    /// server id
    pub server_id: String,
    /// tool name
    pub tool_name: String,
    /// drift 后的新 hash(必须等于当前 pending_hash,否则 registry 层拒)
    pub new_hash: String,
}

/// RejectToolDrift 参数。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RejectToolDriftReq {
    /// server id
    pub server_id: String,
    /// tool name
    pub tool_name: String,
}

/// ApproveServerCommandDrift 参数。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApproveServerCommandDriftReq {
    /// server id
    pub server_id: String,
}

/// RejectServerCommandDrift 参数。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RejectServerCommandDriftReq {
    /// server id
    pub server_id: String,
}

/// GetSandboxProfile 参数。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetSandboxProfileReq {
    /// profile id
    pub profile_id: String,
}

/// UpsertSandboxProfile 参数。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpsertSandboxProfileReq {
    /// profile 完整 JSON(JCS 规范化前)—— Ledger 内部会 canonicalize + hash
    pub profile: vigil_runner_types::SandboxProfile,
}

/// BindServerSandboxProfile 参数。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BindServerSandboxProfileReq {
    /// server id
    pub server_id: String,
    /// profile id;None = 解绑
    pub profile_id: Option<String>,
}

/// ONNX 模型下载/校验请求。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnsureOnnxModelReq {
    /// 模型逻辑 ID,当前支持 `"privacy-filter"` 与 `"deberta-injection"`。
    pub model_id: String,
}

/// Hub 保护策略配置补丁(运行时热更新)。
///
/// 所有字段均为 `Option`,未提供字段保持原值不变;提供字段立即替换当前 Hub 运行值。
/// 覆盖可由 UI 安全切换的策略开关与时效参数,不涉及涉密参数。
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateHubConfigReq {
    /// `monitor_mode`:true = 观察放行(default-deny floor 与 Approve 路径均降级),
    /// false = enforce(默认)。
    pub monitor_mode: Option<bool>,
    /// `auto_approve_first_seen_tools`:true = tools/list 首次见 descriptor 自动批准。
    pub auto_approve_first_seen_tools: Option<bool>,
    /// `redact_tool_results`:true = 上游结果命中硬指纹时 in-band 脱敏后再返给 agent。
    pub redact_tool_results: Option<bool>,
    /// `outbox_enabled`:true = 对 CommSend/NetOutbound 效应启用 outbox 预览与审批绑定。
    pub outbox_enabled: Option<bool>,
    /// `approval_wait`:等待人工审批的最长时间(秒)。UI 应限制为合理正整数(如 1..=3600)。
    pub approval_wait_secs: Option<u64>,
    /// `upstream_list_timeout`:上游 `tools/list` 超时(秒)。
    pub upstream_list_timeout_secs: Option<u64>,
    /// `upstream_call_timeout`:上游 `tools/call` 超时(秒)。
    pub upstream_call_timeout_secs: Option<u64>,
}
