/**
 * I08b-α1/α2 Tauri invoke type-safe wrapper。
 *
 * 类型来源:手写(α1.5 specta 集成延期)。**所有 enum / struct 字段必须与 Rust serde
 * 约定一致** — Codex R1 的 3 BLOCKER 正是由协议漂移引起,本次全面核对 `vigil-types` /
 * `vigil-ui-protocol` 真实 serde 行为后重写。
 *
 * **序列化约定 cheat-sheet**:
 * - `vigil_types::ApprovalStatus`:`#[serde(rename_all = "PascalCase")]`
 * - `vigil_types::ApprovalScope`:`#[serde(rename_all = "PascalCase")]`
 * - `vigil_ui_protocol::ApprovalAction`:`#[serde(rename_all = "lowercase")]`
 * - struct 字段名保持 Rust snake_case
 */
import { invoke } from "@tauri-apps/api/core";

// ─────────────────────────── Shared enums(大小写严格核对 Rust serde)───────────────────────────

/** `vigil_types::ApprovalStatus` — PascalCase */
export type ApprovalStatus =
  | "Pending"
  | "Approved"
  | "Denied"
  | "Expired"
  | "Cancelled";

/** `vigil_types::ApprovalScope` — PascalCase(含 I05+ 占位的 4 个 variant)*/
export type ApprovalScope =
  | "Once"
  | "ThisSession"
  | "ForToolWithSameArgsHash"
  | "ForPolicyTemplate";

/** `vigil_ui_protocol::ApprovalAction` — lowercase */
export type ApprovalAction = "approve" | "deny" | "cancel";

// ─────────────────────────── α1 types ───────────────────────────

/** 对应 Rust `gui.rs::SessionView`(SessionSummary 投射)*/
export interface SessionView {
  session_id: string;
  source: string;
  app_name: string | null;
  started_at: number;
  ended_at: number | null;
  risk_score: number;
}

/**
 * 对应 Rust `vigil_ui_protocol::ListSessionsReq`(command.rs L191)。
 *
 * **α5 修正**:Rust 端 `limit: u32` 是**必填**(非 Option),α1 原来写 `limit?: number`
 * 是协议漂移 —— 实际调用若省略 limit,Tauri 序列化会缺 key,Rust serde 直接 reject。
 * 改为必填 + wrapper 默认 100(与 `ListRecentEventsReq` 对齐)。
 */
export interface ListSessionsReq {
  source?: string | null;
  limit: number;
}

export async function listSessions(
  req: ListSessionsReq = { limit: 100 },
): Promise<SessionView[]> {
  return await invoke<SessionView[]>("list_sessions", { req });
}

// ─────────────────────────── α2 types ───────────────────────────

/** 对应 Rust `vigil_ui_protocol::ApprovalSummary`(vigil-audit 生成,已脱敏)*/
export interface ApprovalSummary {
  approval_id: string;
  session_id: string;
  title: string;
  summary: string;
  status: ApprovalStatus;
  expires_at: number;
}

/**
 * 对应 Rust `vigil_types::EffectKind`(effect.rs L29)。
 *
 * **β3** 修正:α2 原 `effects: string[]` 强类型化为 `EffectKind[]`。
 * Rust 端 `#[serde(rename_all = "PascalCase")]` + `#[non_exhaustive]`,11 variants。
 * TS 用字面量 union 镜像 —— **新增 variant 时必须同步本 union**(手动;无跨语言自动检测)。
 *
 * **跨语言同步守门的范围澄清**(R1 MUST-FIX):
 * - 本文件无法检测 Rust 侧新增 variant —— 除非 TS union 也被更新,TS 编译器看不到 Rust 变更
 * - 真跨语言守门需等 β2 `specta` 代码生成落地(Cargo.lock 当前无 specta,环境限制暂搁)
 * - 在此之前,手工同步 + `effectKindTagMeta` 的 **TS-内部 switch 穷尽检查**
 *   (`never` 断言)只保证"TS union 与 TS 消费点保持同步";Rust ↔ TS 的一致性
 *   **仍靠 code review + 本注释提醒**。若运行时 JSON 带了 TS union 未覆盖的字面量,
 *   tag 走 default 色 + 展示原字面量不崩(见 `effectKindTagMeta` 的 default 分支)。
 *
 * UI 消费处:`ApprovalDetailDrawer.vue` 按 `effectKindTagMeta` 的色彩分类(读 = info,
 * 写 / 执行 / 外联 = warning,凭据 / 对外通讯 = error)渲染 NTag。
 */
export type EffectKind =
  | "FsRead"
  | "FsWrite"
  | "DbRead"
  | "DbWrite"
  | "NetOutbound"
  | "ExecWasm"
  | "ExecNative"
  | "SecretUse"
  | "BrowserSubmit"
  | "CommSend"
  | "CredentialExchange";

/** 对应 Rust `vigil_types::EffectVector`(effect.rs L9)*/
export interface EffectVector {
  effects: EffectKind[];
  paths_read: string[];
  paths_write: string[];
  network_hosts: string[];
  secret_refs: string[];
  recipients: string[];
  destructive: boolean;
  reversible: boolean;
}

/**
 * EffectKind → NTag 视觉元数据(标签颜色 + 中文 label)。
 *
 * **颜色分类启发式**(与 destructive/reversible flag 正交):
 * - 读类(FsRead / DbRead)→ info(蓝)—— 低风险,只读
 * - 写类(FsWrite / DbWrite)→ warning(黄)—— 修改本地状态
 * - 执行类(ExecWasm / ExecNative)→ warning —— 起子进程 / Wasm
 * - 网络出站(NetOutbound)→ warning —— 外联
 * - 敏感类(SecretUse / CredentialExchange)→ error(红)—— 动凭据
 * - 通讯 / 提交(BrowserSubmit / CommSend)→ error —— 对外可见行为
 *
 * 返回 `type` 走 Naive UI 的标签颜色约定(success/info/warning/error/default)。
 */
export function effectKindTagMeta(
  kind: EffectKind,
): { type: "info" | "warning" | "error" | "default"; label: string } {
  switch (kind) {
    case "FsRead":
      return { type: "info", label: "读文件" };
    case "DbRead":
      return { type: "info", label: "读数据库" };
    case "FsWrite":
      return { type: "warning", label: "写文件" };
    case "DbWrite":
      return { type: "warning", label: "写数据库" };
    case "NetOutbound":
      return { type: "warning", label: "网络出站" };
    case "ExecWasm":
      return { type: "warning", label: "执行 Wasm" };
    case "ExecNative":
      return { type: "warning", label: "执行原生进程" };
    case "SecretUse":
      return { type: "error", label: "使用凭据(lease)" };
    case "CredentialExchange":
      return { type: "error", label: "凭据交换" };
    case "BrowserSubmit":
      return { type: "error", label: "浏览器提交" };
    case "CommSend":
      return { type: "error", label: "对外通讯" };
    default: {
      // TS-内部穷尽检查(R1 MUST-FIX 文档修正):`const _exhaustive: never = kind` 只保证
      // 本 switch 覆盖了 TS union 里的**所有**字面量 —— 若 TS union 新增 variant 而本 switch
      // 没跟进,TS 编译失败。**注意**:不能自动检测 Rust 新增 variant(TS 编译器看不到 Rust);
      // 跨语言同步仍靠手工 + code review,直到 β2 specta 引入自动代码生成。
      //
      // 运行时兜底:若 JSON 反序列化出 TS union 未覆盖的字面量(Rust 先升但 TS 未跟),
      // 此分支打 default 色 + 原字面量展示,UI 不崩,审计员仍能看到信号。
      const _exhaustive: never = kind;
      return { type: "default", label: String(_exhaustive) };
    }
  }
}

/**
 * 对应 Rust `vigil_types::ApprovalRequest`(真实字段;R1 BLOCKER 2 修复)。
 *
 * **注意**:只含 request 本身字段。`resolved_by` / `resolved_at` / `scope` / `resolution_note`
 * 是 `ApprovalResolution`(另一结构,wait_for_resolution 的返回)**不在 ApprovalRequest 里**。
 */
export interface ApprovalRequest {
  approval_id: string;
  decision_id: string;
  invocation_id: string;
  session_id: string;
  title: string;
  summary: string;
  effect_vector: EffectVector;
  expires_at: number;
  status: ApprovalStatus;
}

/** 对应 Rust `vigil_ui_protocol::PrivacyFindingDto` (ISS-014)。
 * 仅展示 `{label} × {count}` 元数据 — **绝不展原文** */
export interface PrivacyFindingDto {
  /** PrivacyLabel 字面量(secret / email / private_person 等 8 类之一) */
  label: string;
  /** 该 label 在本 approval 关联 session 的命中次数(≥ 1) */
  count: number;
}

/** ISS-018 — Safe Export 输出格式;字面量与 Rust enum #[serde(rename_all="lowercase")] 对齐 */
export type ExportFormat = "md" | "html";

/** 对应 Rust `vigil_ui_protocol::ExportSessionReplayReq` (ISS-018)。 */
export interface ExportSessionReplayReq {
  session_id: string;
  format: ExportFormat;
}

/** 对应 Rust `vigil_ui_protocol::SessionExportDto` (ISS-018)。
 * `content` 已脱敏(payload 在 audit 入库时由 vigil-redaction 处理),前端可直
 * 接 Blob + `<a download>` 触发下载,无需再过滤。 */
export interface SessionExportDto {
  session_id: string;
  format: ExportFormat;
  /** 渲染后的文本(MD 或 HTML 文档) */
  content: string;
  byte_len: number;
  event_count: number;
  /** Unix epoch 秒 */
  generated_at: number;
}

/** 对应 Rust `vigil_ui_protocol::RedactionScanSummaryDto` (ISS-017)。
 * 仅 metadata + finding 计数,**绝不展原文** */
export interface RedactionScanSummaryDto {
  scan_id: string;
  session_id: string;
  /** Unix epoch 秒 */
  ts: number;
  /** paste | tool_arg | tool_output | export */
  source: string;
  /** 文本长度位宽粗化(0-64,MSB 1-based) */
  text_length_bucket: number;
  /** sha256 前 16 字节 hex-lower(32 字符) */
  fingerprint: string;
  /** 该 scan 下 finding 总数 */
  finding_count: number;
}

/** 对应 Rust `vigil_ui_protocol::PrivacyFindingsDto` (ISS-017)。
 * Privacy Findings 面板 payload(全局 label 聚合 + 最近 scans)。 */
export interface PrivacyFindingsDto {
  /** 全局 label × count(count DESC, label ASC) */
  by_label_total: PrivacyFindingDto[];
  /** 最近 N 条 scans 摘要(ts DESC) */
  recent_scans: RedactionScanSummaryDto[];
}

/** 对应 Rust `vigil_ui_protocol::ListPrivacyFindingsReq` (ISS-017)。 */
export interface ListPrivacyFindingsReq {
  /** 最近 scans 上限。0 → ledger 默认 50;最大 ledger 内 clamp 到 500 */
  limit_recent_scans: number;
}

/** 对应 Rust `vigil_ui_protocol::ApprovalDetailDto` */
export interface ApprovalDetailDto {
  request: ApprovalRequest;
  invocation_id: string;
  decision_id: string;
  /** ISS-014 — 关联 session 的 Privacy Findings 聚合;空数组表示无 PII 命中 */
  privacy_findings: PrivacyFindingDto[];
}

/** 对应 Rust `vigil_ui_protocol::ApprovalResolutionDto` */
export interface ApprovalResolutionDto {
  approval_id: string;
  status: ApprovalStatus;
  scope: ApprovalScope | null;
  resolved_by: string | null;
}

export interface ListPendingApprovalsReq {
  session_id?: string | null;
}

export interface GetApprovalDetailReq {
  approval_id: string;
}

export interface ResolveApprovalReq {
  approval_id: string;
  action: ApprovalAction;
  /** **Approve 时必填**(dispatcher 对缺失 scope 的 Approve 返 Invalid);Deny/Cancel 可为 null */
  scope?: ApprovalScope | null;
  resolved_by: string;
  reason?: string | null;
}

// ─────────────────────────── α2 invoke wrappers ───────────────────────────

export async function listPendingApprovals(
  req: ListPendingApprovalsReq = {},
): Promise<ApprovalSummary[]> {
  return await invoke<ApprovalSummary[]>("list_pending_approvals", { req });
}

export async function getApprovalDetail(
  req: GetApprovalDetailReq,
): Promise<ApprovalDetailDto> {
  return await invoke<ApprovalDetailDto>("get_approval_detail", { req });
}

export async function resolveApproval(
  req: ResolveApprovalReq,
): Promise<ApprovalResolutionDto> {
  return await invoke<ApprovalResolutionDto>("resolve_approval", { req });
}

/** ISS-017 — Privacy Findings 面板:全局 label 聚合 + 最近 scans */
export async function listPrivacyFindings(
  req: ListPrivacyFindingsReq,
): Promise<PrivacyFindingsDto> {
  return await invoke<PrivacyFindingsDto>("list_privacy_findings", { req });
}

/** ISS-018 — Safe Export:把 session replay 渲染为 MD / HTML 文本(payload 已脱敏)。 */
export async function exportSessionReplay(
  req: ExportSessionReplayReq,
): Promise<SessionExportDto> {
  return await invoke<SessionExportDto>("export_session_replay", { req });
}

// ─────────────────────────── α3 types(Activity Feed)───────────────────────────

/**
 * 对应 Rust `vigil_ui_protocol::EventSummary` 与 `vigil_audit::EventHit`(两者字段完全同,
 * 语义区分 list_recent_events vs fts_search)。
 */
export interface EventSummary {
  event_id: number; // Rust i64;JS number 对 2^53 以内的 event_id 安全
  session_id: string;
  event_type: string;
  redacted_text: string | null;
  created_at: number;
}

/** EventHit 字段同 EventSummary;单独声明便于后续独立演化 */
export type EventHit = EventSummary;

/**
 * 对应 Rust `vigil_ui_protocol::EventDetail`(payload 是 serde_json::Value,
 * TS 用 unknown — UI 只做 `JSON.stringify(payload, null, 2)` 展示,不 drill into)。
 */
export interface EventDetail {
  event_id: number;
  session_id: string;
  event_type: string;
  payload: unknown; // JSON value,UI 仅 stringify 展示
  redacted_text: string | null;
  prev_hash: string;
  event_hash: string;
  created_at: number;
}

/** 对应 Rust `vigil_ui_protocol::ListRecentEventsReq` */
export interface ListRecentEventsReq {
  session_id?: string | null;
  event_type_filter?: string[] | null;
  limit: number; // u32,必填(dispatcher 对 limit=0 回退 100 但前端明示更清晰)
}

export interface GetEventDetailReq {
  event_id: number;
}

export interface FtsSearchReq {
  query: string;
  limit: number;
}

// ─────────────────────────── α3 invoke wrappers ───────────────────────────

export async function listRecentEvents(
  req: ListRecentEventsReq,
): Promise<EventSummary[]> {
  return await invoke<EventSummary[]>("list_recent_events", { req });
}

export async function getEventDetail(req: GetEventDetailReq): Promise<EventDetail> {
  return await invoke<EventDetail>("get_event_detail", { req });
}

export async function ftsSearch(req: FtsSearchReq): Promise<EventHit[]> {
  return await invoke<EventHit[]>("fts_search", { req });
}

// ─────────────────────────── α4 types(Server Registry)──────────────────────
//
// 序列化 cheat-sheet(grep 自 Rust serde attr,未做推断):
// - `vigil_types::TransportKind`(server.rs L33) → `#[serde(rename_all = "PascalCase")]`
//     → "Stdio" | "Http"
// - `vigil_types::TrustLevel`(principal.rs L38) → `#[serde(rename_all = "PascalCase")]`
//     → "Untrusted" | "Limited" | "Trusted"
// - 结构体字段 snake_case(Rust 默认,未 override)

/** Rust `vigil_types::TransportKind` serde — `#[non_exhaustive]` */
export type TransportKind = "Stdio" | "Http";

/** Rust `vigil_types::TrustLevel` serde — `#[non_exhaustive]` */
export type TrustLevel = "Untrusted" | "Limited" | "Trusted";

/**
 * 对应 Rust `vigil_audit::StoredServerProfile`(registry.rs L106)。
 *
 * `command` 是 exact argv(stdio 下非 None);**UI 必须原样展示,不做 shell 拼接**。
 */
export interface StoredServerProfile {
  server_id: string;
  transport: TransportKind;
  command: string[] | null;
  url: string | null;
  first_seen_at: number;
  command_hash: string | null;
  descriptor_hash: string | null;
  trust_level: TrustLevel;
  sandbox_profile_id: string | null;
  /** 命令漂移时指向待批准的新 argv hash(I05 drift 状态机) */
  pending_command_hash: string | null;
  /** 首次发现 drift 的时间 */
  last_drift_at: number | null;
}

/**
 * 对应 Rust `vigil_audit::ServerOnboardingData`(registry.rs L34)。
 *
 * **安全契约**:
 * - `command` 是 exact argv,UI 逐元素渲染,禁 `.join(' ')` 式拼接展示
 * - `requested_env_keys`:`null` = 未知(等 lease 分析完成)/ `[]` = 明确无 env /
 *   非空数组 = 已知 key 清单;**值永远不暴露**
 * - `pending_command_hash` 非空时 UI 需提示 drift 状态 + diff 视图
 */
export interface ServerOnboardingData {
  server_id: string;
  transport: TransportKind;
  command: string[] | null;
  url: string | null;
  command_hash: string | null;
  pending_command_hash: string | null;
  requested_env_keys: string[] | null;
  sandbox_profile_id: string | null;
  first_seen_at: number;
  trust_level: TrustLevel;
}

/** 对应 Rust `vigil_audit::ToolApprovalCard`(registry.rs L64)。 */
export interface ToolApprovalCard {
  server_id: string;
  tool_name: string;
  current_hash: string;
  /** drift 时为新 hash;首次 pending 时为 null */
  proposed_hash: string | null;
  first_seen_at: number;
  approved_at: number | null;
  last_drift_at: number | null;
}

// --- 请求 payload 形状(来源 vigil_ui_protocol::command) ---

export interface GetServerOnboardingReq {
  server_id: string;
}

export interface ApproveToolReq {
  server_id: string;
  tool_name: string;
}

export interface ApproveToolDriftReq {
  server_id: string;
  tool_name: string;
  new_hash: string;
}

export interface RejectToolDriftReq {
  server_id: string;
  tool_name: string;
}

export interface ApproveServerCommandDriftReq {
  server_id: string;
}

export interface RejectServerCommandDriftReq {
  server_id: string;
}

// ─────────────────────────── α4 invoke wrappers ───────────────────────────

export async function listServers(): Promise<StoredServerProfile[]> {
  return await invoke<StoredServerProfile[]>("list_servers");
}

export async function getServerOnboarding(
  req: GetServerOnboardingReq,
): Promise<ServerOnboardingData> {
  return await invoke<ServerOnboardingData>("get_server_onboarding", { req });
}

export async function listPendingToolApprovals(): Promise<ToolApprovalCard[]> {
  return await invoke<ToolApprovalCard[]>("list_pending_tool_approvals");
}

export async function listDriftedTools(): Promise<ToolApprovalCard[]> {
  return await invoke<ToolApprovalCard[]>("list_drifted_tools");
}

export async function listDriftedServers(): Promise<ServerOnboardingData[]> {
  return await invoke<ServerOnboardingData[]>("list_drifted_servers");
}

export async function approveTool(req: ApproveToolReq): Promise<void> {
  await invoke<void>("approve_tool", { req });
}

export async function approveToolDrift(req: ApproveToolDriftReq): Promise<void> {
  await invoke<void>("approve_tool_drift", { req });
}

export async function rejectToolDrift(req: RejectToolDriftReq): Promise<void> {
  await invoke<void>("reject_tool_drift", { req });
}

export async function approveServerCommandDrift(
  req: ApproveServerCommandDriftReq,
): Promise<void> {
  await invoke<void>("approve_server_command_drift", { req });
}

export async function rejectServerCommandDrift(
  req: RejectServerCommandDriftReq,
): Promise<void> {
  await invoke<void>("reject_server_command_drift", { req });
}

// ─────────────────────────── α5 types(Session Replay)─────────────────────
//
// 真实字段来自 `crates/vigil-ui-protocol/src/response.rs`:
//   - SessionSummary  L151  (亦即 α1 SessionView 的同形镜像)
//   - SessionReplay   L168
//   - ChainVerifyReport L181
// 请求 payload 来自 `crates/vigil-ui-protocol/src/command.rs::ReplaySessionReq` L200

/**
 * 对应 Rust `vigil_ui_protocol::SessionReplay`(response.rs L168)。
 *
 * `events` 是 EventDetail 列表(payload 为 JCS-规范化 JSON,已脱敏),前端渲染与
 * α3 `EventDetailModal` 同策略:payload 走 `<pre>{{ JSON.stringify(...) }}`。
 *
 * **chain_verified 语义**:verify=true 时返 ledger 级 verify_chain 结果(非仅本 session)
 * —— UI 需明示这是"ledger 全局链校验",而非"仅覆盖本 session 的子链"。
 */
export interface SessionReplay {
  session_id: string;
  event_count: number; // Rust usize,u32 能承载即安全
  events: EventDetail[];
  chain_verified: ChainVerifyReport | null;
}

/**
 * 对应 Rust `vigil_ui_protocol::ChainVerifyReport`(response.rs L181)。
 *
 * **message 不透传底层错误原文**(I08a R1 MUST-FIX):仅 `chain_broken_at=N` /
 * `chain_verify_failed` 两种 reason code;前端可直接 `{{ }}` 插值。
 */
export interface ChainVerifyReport {
  ok: boolean;
  broken_at_event_id: number | null;
  message: string | null;
}

/** 对应 Rust `vigil_ui_protocol::ReplaySessionReq`(command.rs L200) */
export interface ReplaySessionReq {
  session_id: string;
  verify: boolean;
}

// ─────────────────────────── α5 invoke wrappers ───────────────────────────

export async function replaySession(req: ReplaySessionReq): Promise<SessionReplay> {
  return await invoke<SessionReplay>("replay_session", { req });
}

export async function verifyChain(): Promise<ChainVerifyReport> {
  return await invoke<ChainVerifyReport>("verify_chain");
}

// ─────────────────────────── D19 Protection Overview ───────────────────────────

/** 对应 Rust `vigil_audit::EventHit`（`ProtectionSummary.recent` 元素，字段已脱敏） */
export interface ProtectionEventHit {
  event_id: number;
  session_id: string;
  event_type: string;
  redacted_text: string | null;
  created_at: number;
}

/**
 * 对应 Rust `vigil_audit::ProtectionSummary`（ledger.rs；只读保护成效聚合）。
 * = CLI `vigil-hub inspect protection` 的 GUI 等价物。
 * **fail-closed**：`chain_intact=false`（账本被篡改）时 Rust 端强制 `recent=[]`（绝不回显
 * 可能被注入 secret 的明细），计数仍保留。
 */
export interface ProtectionSummary {
  raw_secrets_blocked: number;
  tool_result_leaks_detected: number;
  secret_aliases_unresolved: number;
  total_events_audited: number;
  sessions_covered: number;
  chain_intact: boolean;
  recent: ProtectionEventHit[];
}

/** D19：保护成效概览。只读，无参数。 */
export async function protectionSummary(): Promise<ProtectionSummary> {
  return await invoke<ProtectionSummary>("protection_summary");
}

// ─────────────────────────── ML 控制平面（ADR 0024：daemon + 模型）───────────────────────────
//
// GUI 经 `vigil-hub` CLI shell-out 调度常驻 daemon 生命周期与 ML 模型安装（Rust 侧
// `vigil_desktop::ml_control`）。这些命令仅取 `AppHandle`（Tauri 自动注入），前端不传 payload。
// 字段名为 Rust serde 默认 snake_case（结构体未 override）。

/** 对应 Rust `vigil_desktop::ml_control::DaemonStatus`。 */
export interface DaemonStatus {
  /** daemon 是否在运行 */
  running: boolean;
  /** 隐私 PII 模型是否已暖载（running 且 status 行报 pii_loaded=true 时为 true） */
  pii_loaded: boolean;
  /** vigil-hub 引擎二进制是否就位（false → 守护卡只读，提示先部署引擎） */
  engine_present: boolean;
}

/** 对应 Rust `vigil_desktop::ml_control::ModelStatus`。 */
export interface ModelStatus {
  /** 隐私 PII 模型已安装（本地缓存 sha256 校验通过） */
  privacy_installed: boolean;
  /** 注入分类器模型已安装 */
  injection_installed: boolean;
  /** 当前引擎二进制是否支持 ML（ort 变体）。false = 非 ML 变体，无法安装 */
  ml_supported: boolean;
  /** 引擎二进制是否就位 */
  engine_present: boolean;
}

/** 只读：daemon 运行态（引擎缺失时回 running=false + engine_present=false，不报错）。 */
export async function daemonStatus(): Promise<DaemonStatus> {
  return await invoke<DaemonStatus>("daemon_status");
}

/** 写：detached 启动常驻 daemon（暖载 ML 供 hook 主路径）。回最新状态。 */
export async function daemonStart(): Promise<DaemonStatus> {
  return await invoke<DaemonStatus>("daemon_start");
}

/** 写：停止常驻 daemon。回最新状态。 */
export async function daemonStop(): Promise<DaemonStatus> {
  return await invoke<DaemonStatus>("daemon_stop");
}

/** 只读：ML 模型缓存态（privacy/injection installed + ml_supported）。 */
export async function modelStatus(): Promise<ModelStatus> {
  return await invoke<ModelStatus>("model_status");
}

/** 写：安装 ML 模型（阻塞，数十秒；fail-closed，失败抛错）。回安装后状态。 */
export async function modelInstall(): Promise<ModelStatus> {
  return await invoke<ModelStatus>("model_install");
}
