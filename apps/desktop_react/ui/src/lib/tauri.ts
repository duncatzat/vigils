import { invoke } from "@tauri-apps/api/core";

// ── Request DTOs mirroring vigil-ui-protocol ──

export interface ListSessionsReq {
  source?: string | null;
  limit: number;
}

export interface ListRecentEventsReq {
  session_id?: string | null;
  event_type_filter?: string[] | null;
  limit: number;
}

export interface GetEventDetailReq {
  event_id: number;
}

export interface FtsSearchReq {
  query: string;
  limit: number;
}

export interface ListPendingApprovalsReq {
  session_id?: string | null;
}

export interface GetApprovalDetailReq {
  approval_id: string;
}

export interface ResolveApprovalReq {
  approval_id: string;
  action: "approve" | "deny" | "cancel";
  scope?: string | null;
  resolved_by?: string;
  reason?: string | null;
}

export interface ListPrivacyFindingsReq {
  limit_recent_scans: number;
}

export interface ReplaySessionReq {
  session_id: string;
  verify: boolean;
}

export interface ExportSessionReplayReq {
  session_id: string;
  format: "md" | "html";
}

// ── Response DTOs mirroring backend shapes ──

export interface SessionView {
  session_id: string;
  source: string;
  app_name: string | null;
  started_at: number;
  ended_at: number | null;
  risk_score: number;
}

export interface EventSummary {
  event_id: number;
  session_id: string;
  event_type: string;
  redacted_text: string | null;
  created_at: number;
}

export interface EventDetail {
  event_id: number;
  session_id: string;
  event_type: string;
  payload: Record<string, unknown>;
  redacted_text: string | null;
  prev_hash: string;
  event_hash: string;
  created_at: number;
}

export interface ApprovalSummary {
  approval_id: string;
  session_id: string;
  title: string;
  summary: string;
  status: string;
  expires_at: number;
}

export interface PrivacyFindingDto {
  label: string;
  count: number;
}

export interface RedactionScanSummaryDto {
  scan_id: string;
  session_id: string;
  ts: number;
  source: string;
  text_length_bucket: number;
  fingerprint: string;
  finding_count: number;
}

export interface PrivacyFindingsDto {
  by_label_total: PrivacyFindingDto[];
  recent_scans: RedactionScanSummaryDto[];
}

export interface ApprovalDetailDto {
  request: Record<string, unknown>;
  invocation_id: string;
  decision_id: string;
  privacy_findings: PrivacyFindingDto[];
}

export interface ProtectionSummary {
  raw_secrets_blocked: number;
  tool_result_leaks_detected: number;
  secret_aliases_unresolved: number;
  total_events_audited: number;
  sessions_covered: number;
  chain_intact: boolean;
  recent: EventHit[];
}

export interface EventHit {
  event_id: number;
  event_type: string;
  redacted_text: string | null;
  created_at: number;
}

export interface StoredServerProfile {
  server_id: string;
  transport: string;
  command: string[] | null;
  url: string | null;
  first_seen_at: number;
  command_hash: string | null;
  descriptor_hash: string | null;
  trust_level: string;
  sandbox_profile_id: string | null;
  pending_command_hash: string | null;
  last_drift_at: number | null;
}

export interface RegisterServerReq {
  server_id: string;
  transport: "stdio" | "http";
  command: string[] | null;
  url: string | null;
}

export interface ServerOnboardingData {
  server_id: string;
  transport: string;
  command: string[] | null;
  url: string | null;
  command_hash: string | null;
  pending_command_hash: string | null;
  requested_env_keys: string[] | null;
  sandbox_profile_id: string | null;
  first_seen_at: number;
  trust_level: string;
}

export interface ChainVerifyReport {
  ok: boolean;
  broken_at_event_id: number | null;
  message: string | null;
}

export interface CheckpointAnchorDto {
  event_id: number;
  event_hash: string;
  anchored_at: number;
}

export interface SandboxProfile {
  id: string;
  read_dirs: string[];
  write_dirs: string[];
  allow_hosts: string[];
  env_inherit: boolean;
  wall_ms: number;
  memory_mb: number;
}

export interface SandboxProfileUpsertDto {
  profile_id: string;
  profile_hash: string;
  inserted: boolean;
}

export interface SandboxProfileUpsertReq {
  profile: SandboxProfile;
}

export interface GetSandboxProfileReq {
  profile_id: string;
}

export interface SessionExportDto {
  session_id: string;
  format: string;
  content: string;
  byte_len: number;
  event_count: number;
  generated_at: number;
}

// ── Invoke wrappers ──

export async function listSessions(req: ListSessionsReq): Promise<SessionView[]> {
  return invoke<SessionView[]>("list_sessions", { req });
}

export async function listRecentEvents(req: ListRecentEventsReq): Promise<EventSummary[]> {
  return invoke<EventSummary[]>("list_recent_events", { req });
}

export async function getEventDetail(req: GetEventDetailReq): Promise<EventDetail> {
  return invoke<EventDetail>("get_event_detail", { req });
}

export async function ftsSearch(req: FtsSearchReq): Promise<EventSummary[]> {
  return invoke<EventSummary[]>("fts_search", { req });
}

export async function listPendingApprovals(req: ListPendingApprovalsReq = {}): Promise<ApprovalSummary[]> {
  return invoke<ApprovalSummary[]>("list_pending_approvals", { req });
}

export async function getApprovalDetail(req: GetApprovalDetailReq): Promise<ApprovalDetailDto> {
  return invoke<ApprovalDetailDto>("get_approval_detail", { req });
}

export async function resolveApproval(req: ResolveApprovalReq): Promise<unknown> {
  return invoke<unknown>("resolve_approval", { req });
}

export async function protectionSummary(): Promise<ProtectionSummary> {
  return invoke<ProtectionSummary>("protection_summary", {});
}

export async function listServers(): Promise<StoredServerProfile[]> {
  return invoke<StoredServerProfile[]>("list_servers", {});
}

export async function registerServer(req: RegisterServerReq): Promise<void> {
  return invoke<void>("register_server", { req });
}

export async function getServerOnboarding(serverId: string): Promise<ServerOnboardingData> {
  return invoke<ServerOnboardingData>("get_server_onboarding", { req: { server_id: serverId } });
}

export async function listPrivacyFindings(req: ListPrivacyFindingsReq): Promise<PrivacyFindingsDto> {
  return invoke<PrivacyFindingsDto>("list_privacy_findings", { req });
}

export async function verifyChain(): Promise<ChainVerifyReport> {
  return invoke<ChainVerifyReport>("verify_chain", {});
}

export async function anchorCheckpoint(): Promise<CheckpointAnchorDto | null> {
  return invoke<CheckpointAnchorDto | null>("anchor_checkpoint", {});
}

export async function replaySession(req: ReplaySessionReq): Promise<unknown> {
  return invoke<unknown>("replay_session", { req });
}

export async function exportSessionReplay(req: ExportSessionReplayReq): Promise<SessionExportDto> {
  return invoke<SessionExportDto>("export_session_replay", { req });
}

export async function listSandboxProfiles(): Promise<SandboxProfile[]> {
  return invoke<SandboxProfile[]>("list_sandbox_profiles", {});
}

export async function getSandboxProfile(req: GetSandboxProfileReq): Promise<SandboxProfile | null> {
  return invoke<SandboxProfile | null>("get_sandbox_profile", { req });
}

export async function upsertSandboxProfile(req: SandboxProfileUpsertReq): Promise<SandboxProfileUpsertDto> {
  return invoke<SandboxProfileUpsertDto>("upsert_sandbox_profile", { req });
}

export interface UpdateHubConfigReq {
  monitor_mode?: boolean | null;
  auto_approve_first_seen_tools?: boolean | null;
  redact_tool_results?: boolean | null;
  outbox_enabled?: boolean | null;
  approval_wait_secs?: number | null;
  upstream_list_timeout_secs?: number | null;
  upstream_call_timeout_secs?: number | null;
}

export async function updateHubConfig(req: UpdateHubConfigReq): Promise<void> {
  return invoke<void>("update_hub_config", { req });
}

export interface OnnxModelInfo {
  model_id: string;
  display_name: string;
  version: string;
  installed: boolean;
  size_bytes: number;
  busy: boolean;
}

export interface EnsureOnnxModelReq {
  model_id: string;
}

export async function listOnnxModels(): Promise<OnnxModelInfo[]> {
  return invoke<OnnxModelInfo[]>("list_onnx_models", {});
}

export async function ensureOnnxModel(req: EnsureOnnxModelReq): Promise<string> {
  return invoke<string>("ensure_onnx_model", { req });
}

export interface ToolApprovalCard {
  server_id: string;
  tool_name: string;
  current_hash: string;
  proposed_hash: string | null;
  first_seen_at: number;
  approved_at: number | null;
  last_drift_at: number | null;
}

export async function listPendingToolApprovals(): Promise<ToolApprovalCard[]> {
  return invoke<ToolApprovalCard[]>("list_pending_tool_approvals", {});
}

export async function listDriftedTools(): Promise<ToolApprovalCard[]> {
  return invoke<ToolApprovalCard[]>("list_drifted_tools", {});
}

export async function listDriftedServers(): Promise<ToolApprovalCard[]> {
  return invoke<ToolApprovalCard[]>("list_drifted_servers", {});
}
