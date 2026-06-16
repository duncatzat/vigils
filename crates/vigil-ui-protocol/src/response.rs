//! `UiResponse` tagged union(ADR 0008 §D3)。
//!
//! 每个 UiCommand 映射到一个 UiResponse 变种(同名或类型化资源)。

use serde::{Deserialize, Serialize};
use serde_json::Value;

use vigil_audit::{
    EventHit, ReplayEvent, SecretRefEntry, ServerOnboardingData, StoredServerProfile,
    ToolApprovalCard, ToolSecretBinding,
};
use vigil_runner_types::SandboxProfile;
use vigil_types::{ApprovalRequest, ApprovalScope, ApprovalStatus};

/// UI 响应的 tagged union。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data")]
#[non_exhaustive]
pub enum UiResponse {
    /// 无返回数据(写命令成功 / 空查询)
    Ack,
    /// 事件列表(Activity Feed)
    EventList(Vec<EventSummary>),
    /// 单条事件的完整 payload
    EventDetail(EventDetail),
    /// FTS 搜索命中
    SearchHits(Vec<EventHit>),
    /// Pending approval 概要
    ApprovalList(Vec<ApprovalSummary>),
    /// Approval 完整细节
    ApprovalDetail(ApprovalDetailDto),
    /// Session 列表
    SessionList(Vec<SessionSummary>),
    /// Session replay
    ReplayDump(SessionReplay),
    /// hash chain verify 结果
    ChainVerification(ChainVerifyReport),
    /// Server 列表
    ServerList(Vec<StoredServerProfile>),
    /// Server onboarding 数据
    ServerOnboarding(ServerOnboardingData),
    /// Tool approval cards(pending 或 drifted)
    ToolApprovalList(Vec<ToolApprovalCard>),
    /// Drifted servers
    DriftedServerList(Vec<ServerOnboardingData>),
    /// Sandbox profile 列表
    SandboxProfileList(Vec<SandboxProfile>),
    /// 单个 sandbox profile(或 None)
    SandboxProfileOpt(Option<SandboxProfile>),
    /// Approval resolve 后的状态
    ApprovalResolution(ApprovalResolutionDto),
    /// Sandbox profile upsert 后 id + hash
    SandboxProfileUpserted(SandboxProfileUpsertDto),
    /// Secret refs + bindings(辅助 onboarding)
    SecretBinding(SecretBindingSummary),
    /// ISS-017 — Privacy Findings 聚合视图(全局 label × count + 最近 scans)
    PrivacyFindings(PrivacyFindingsDto),
    /// ISS-018 — Safe Export 渲染结果(MD / HTML 字符串内容)
    SessionExport(SessionExportDto),
    /// 链头已锚定到 checkpoint sidecar;data 为 None 表示空账本/链头未前进/内存库
    CheckpointAnchored(Option<CheckpointAnchorDto>),
    /// ONNX 模型状态列表
    OnnxModelList(Vec<OnnxModelInfo>),
    /// ONNX 模型下载/校验任务已接受(background job id)
    OnnxModelEnsured(String),
}

/// Checkpoint anchor 成功后的返回摘要。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointAnchorDto {
    /// 锚定的事件 ID
    pub event_id: i64,
    /// 锚定的事件哈希
    pub event_hash: String,
    /// 锚定时间(Unix 秒)
    pub anchored_at: i64,
}

/// ONNX 模型状态摘要(供 Settings 模型管理面板展示)。
///
/// **零回显**:只暴露模型名、版本、大小等元数据,不暴露任何路径中的用户信息
/// (路径本身由后端解析,UI 只显示存在性与字节大小)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnnxModelInfo {
    /// 模型逻辑 ID(如 `privacy-filter` / `deberta-injection`)。
    pub model_id: String,
    /// 模型展示名。
    pub display_name: String,
    /// 模型版本。
    pub version: String,
    /// 本地是否三件套全部就绪。
    pub installed: bool,
    /// 已下载字节总数(未安装时为 0)。
    pub size_bytes: u64,
    /// 是否正在后台下载/校验中。
    pub busy: bool,
}

// ---------------- DTO ----------------

/// Activity Feed 单行摘要(不含完整 payload)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSummary {
    /// events.event_id
    pub event_id: i64,
    /// 所属 session
    pub session_id: String,
    /// 事件类型
    pub event_type: String,
    /// FTS redacted 摘要(可能为 None)
    pub redacted_text: Option<String>,
    /// Unix 秒
    pub created_at: i64,
}

impl From<ReplayEvent> for EventSummary {
    fn from(e: ReplayEvent) -> Self {
        Self {
            event_id: e.event_id,
            session_id: e.session_id,
            event_type: e.event_type,
            redacted_text: e.redacted_text,
            created_at: e.created_at,
        }
    }
}

/// 单条事件的完整 payload(从 events 表直读,payload 已 JCS 规范化 + 脱敏)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventDetail {
    /// event_id
    pub event_id: i64,
    /// session
    pub session_id: String,
    /// type
    pub event_type: String,
    /// 完整 payload JSON(已脱敏)
    pub payload: Value,
    /// FTS 摘要
    pub redacted_text: Option<String>,
    /// hash chain:前 hash
    pub prev_hash: String,
    /// hash chain:本事件 hash
    pub event_hash: String,
    /// 创建时间
    pub created_at: i64,
}

/// Approval 列表项(不含 effect vector,节省传输)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalSummary {
    /// approval id
    pub approval_id: String,
    /// 所属 session
    pub session_id: String,
    /// 标题
    pub title: String,
    /// 简述
    pub summary: String,
    /// 状态
    pub status: ApprovalStatus,
    /// 到期 Unix 秒
    pub expires_at: i64,
}

impl From<&ApprovalRequest> for ApprovalSummary {
    fn from(r: &ApprovalRequest) -> Self {
        Self {
            approval_id: r.approval_id.clone(),
            session_id: r.session_id.clone(),
            title: r.title.clone(),
            summary: r.summary.clone(),
            status: r.status,
            expires_at: r.expires_at,
        }
    }
}

/// ISS-014 — Privacy Findings 区块单项(按 PrivacyLabel 聚合)。
///
/// **绝不展原文**:仅展示 `{label} × {count}` 元数据,与 `redaction_findings` 表
/// "不存原文"纪律一致(ADR 0013 §I-9.1 + audit `test_schema_forbids_plaintext_columns`)。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivacyFindingDto {
    /// PrivacyLabel 字面量(`secret` / `email` / `private_person` / 等 8 类之一)
    pub label: String,
    /// 该 label 在本 approval 关联 session 内的 finding 命中次数(≥ 1)
    pub count: i64,
}

/// ISS-018 — Safe Export 输出 DTO。
///
/// **不变量**:`content` 来自 `events.payload_json`(已由 `vigil-redaction::redact`
/// 在 audit 入库时脱敏)+ `events.redacted_text`(FTS 摘要)+ 元数据(event_id、
/// event_type、ts、hash 链);**绝不**接触从未脱敏的源。渲染层只组装,不引入新文本。
///
/// `content` 按 `ExportFormat` 编码:`Md` → Markdown 文本,`Html` → 完整 HTML 文档
/// (含 `<!DOCTYPE>` + 最小 inline CSS)。前端用 Blob + `<a download>` 触发下载。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionExportDto {
    /// 被导出的 session id
    pub session_id: String,
    /// 输出格式(Md / Html)
    pub format: crate::ExportFormat,
    /// 渲染后的文本内容
    pub content: String,
    /// 内容字节长度(UI 显示用)
    pub byte_len: usize,
    /// 包含的事件总数
    pub event_count: usize,
    /// 渲染时戳(Unix epoch 秒)
    pub generated_at: i64,
}

/// ISS-017 — Privacy Findings 面板单条 scan 摘要(不含原文)。
///
/// 仅展 metadata + 衍生 finding 数;`fingerprint` 已是 sha256 前 16 字节 hex
/// (32 char),不可逆;`text_length_bucket` 是位宽粗化(MSB 1-based,U64 0-64)。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactionScanSummaryDto {
    /// scan_id(UUIDv4)
    pub scan_id: String,
    /// 关联的 session_id
    pub session_id: String,
    /// Unix epoch 秒(scan 入库时间)
    pub ts: i64,
    /// 来源:`paste` | `tool_arg` | `tool_output` | `export`
    pub source: String,
    /// 文本长度位宽粗化(MSB 1-based,0→0)— **不还原原文长度**
    pub text_length_bucket: i64,
    /// 文本 sha256 前 16 字节 hex-lower(32 字符)— 跨 scan 溯源用,不泄漏原文
    pub fingerprint: String,
    /// 该 scan 下 finding 总数(各 label 合计)
    pub finding_count: i64,
}

/// ISS-017 — Privacy Findings 面板的聚合 payload。
///
/// **绝不展原文**:UI 用此 DTO 渲染时必须仅展示 label 字面量、计数、fingerprint
/// 截断字符串;不得 join span 或还原文本(audit grep 守门 `test_schema_forbids_plaintext_columns`
/// 的语义延伸到 UI 层)。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PrivacyFindingsDto {
    /// 全局 label 聚合(count DESC, label ASC)
    pub by_label_total: Vec<PrivacyFindingDto>,
    /// 最近 N 条 scans 的摘要(按 ts DESC, scan_id DESC)
    pub recent_scans: Vec<RedactionScanSummaryDto>,
}

/// Approval 完整细节。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalDetailDto {
    /// 原始 request
    pub request: ApprovalRequest,
    /// 关联的 invocation id
    pub invocation_id: String,
    /// 关联的 decision id
    pub decision_id: String,
    /// ISS-014 — 关联 session 的 Privacy Findings 聚合(label × count)
    /// 空数组表示该 session 无 PII 命中(或 firewall preflight 未跑)。
    /// **scope 折衷**:按 session_id 聚合而非 invocation_id(redaction_scans 暂无
    /// invocation_id 字段),同 session 多 invocation 的 findings 会一起呈现。
    /// ISS-014 phase 2 / ISS-021 后续可加 invocation 关联。
    #[serde(default)]
    pub privacy_findings: Vec<PrivacyFindingDto>,
}

/// Session 列表项。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    /// session id
    pub session_id: String,
    /// source(mcp_hub / desktop / ...)
    pub source: String,
    /// 应用名(可选)
    pub app_name: Option<String>,
    /// 开始时间
    pub started_at: i64,
    /// 结束时间(未结束 = None)
    pub ended_at: Option<i64>,
    /// 风险分
    pub risk_score: i64,
}

/// Session replay 结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionReplay {
    /// session id
    pub session_id: String,
    /// 事件总数
    pub event_count: usize,
    /// 完整事件流(已脱敏)
    pub events: Vec<EventDetail>,
    /// 可选 verify_chain 结果
    pub chain_verified: Option<ChainVerifyReport>,
}

/// hash chain verify 报告。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVerifyReport {
    /// 是否全部校验通过
    pub ok: bool,
    /// 若 broken,指向第一条断链的 event_id
    pub broken_at_event_id: Option<i64>,
    /// 错误文本(已脱敏)
    pub message: Option<String>,
}

/// Approval resolve 结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalResolutionDto {
    /// approval id
    pub approval_id: String,
    /// 最终状态
    pub status: ApprovalStatus,
    /// 生效 scope(approve 时有值)
    pub scope: Option<ApprovalScope>,
    /// 谁 resolve 的
    pub resolved_by: Option<String>,
}

/// Sandbox profile upsert 结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxProfileUpsertDto {
    /// profile id
    pub profile_id: String,
    /// 新 hash(sha256 JCS)
    pub profile_hash: String,
    /// 是否是新插入(true = INSERT;false = UPDATE)
    pub inserted: bool,
}

/// 某 server 的 secret binding 概览(辅助 onboarding)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretBindingSummary {
    /// 所属 server
    pub server_id: String,
    /// 已登记的 secret refs(仅 alias + metadata)
    pub refs: Vec<SecretRefEntry>,
    /// 该 server 的 ChildEnv 绑定
    pub bindings: Vec<ToolSecretBinding>,
}
