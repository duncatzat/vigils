//! vigil-ui-protocol
//!
//! I08a(ADR 0008):framework-agnostic UI protocol —— CLI / Tauri / Web / 测试 harness
//! 都通过本 crate 的 [`UiCommand`][] / [`UiResponse`][] / [`UiError`][] 交互。
//!
//! **安全不变量**(ADR §I-8.1 ~ §I-8.6):
//! - 协议层**不直接持** `Arc<Ledger>`;dispatcher 是集成层的责任
//! - `UiError` 所有变种**不含** raw secret / 后端原始错误文本
//! - 写命令必须 capability=`ui.write`,静态检查
//! - `SandboxProfile.profile_json` 必须 JCS 规范化后 hash

#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod command;
mod error;
mod response;

pub use command::{
    ApprovalAction, ApproveServerCommandDriftReq, ApproveToolDriftReq, ApproveToolReq,
    BindServerSandboxProfileReq, Capability, EnsureOnnxModelReq, ExportFormat,
    ExportSessionReplayReq, FtsSearchReq, GetApprovalDetailReq, GetEventDetailReq,
    GetSandboxProfileReq, GetServerOnboardingReq, ListPendingApprovalsReq, ListPrivacyFindingsReq,
    ListRecentEventsReq, ListSessionsReq, RegisterServerReq, RejectServerCommandDriftReq,
    RejectToolDriftReq, ReplaySessionReq, ResolveApprovalReq, UiCommand, UpdateHubConfigReq,
    UpsertSandboxProfileReq,
};
pub use error::UiError;
pub use response::{
    ApprovalDetailDto, ApprovalResolutionDto, ApprovalSummary, ChainVerifyReport,
    CheckpointAnchorDto, EventDetail, EventSummary, OnnxModelInfo, PrivacyFindingDto,
    PrivacyFindingsDto, RedactionScanSummaryDto, SandboxProfileUpsertDto, SecretBindingSummary,
    SessionExportDto, SessionReplay, SessionSummary, UiResponse,
};

/// 当前迭代号。
pub const ITERATION: &str = "I08a";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_capability_read_for_all_read_commands() {
        let reads = [
            UiCommand::VerifyChain,
            UiCommand::ListServers,
            UiCommand::ListPendingToolApprovals,
            UiCommand::ListDriftedTools,
            UiCommand::ListDriftedServers,
            UiCommand::ListSandboxProfiles,
            UiCommand::ListRecentEvents(Default::default()),
            UiCommand::GetEventDetail(GetEventDetailReq { event_id: 1 }),
            UiCommand::FtsSearch(FtsSearchReq {
                query: "x".into(),
                limit: 10,
            }),
            UiCommand::ListPendingApprovals(Default::default()),
            UiCommand::GetApprovalDetail(GetApprovalDetailReq {
                approval_id: "a".into(),
            }),
            UiCommand::ListSessions(Default::default()),
            UiCommand::ReplaySession(ReplaySessionReq {
                session_id: "s".into(),
                verify: false,
            }),
            UiCommand::GetServerOnboarding(GetServerOnboardingReq {
                server_id: "s".into(),
            }),
            UiCommand::GetSandboxProfile(GetSandboxProfileReq {
                profile_id: "p".into(),
            }),
        ];
        for c in reads {
            assert_eq!(
                c.required_capability(),
                Capability::Read,
                "{c:?} should be Read"
            );
        }
    }

    #[test]
    fn required_capability_write_for_all_write_commands() {
        use vigil_runner_types::{RunnerKind, RunnerSpecific, SandboxProfile};
        let writes = [
            UiCommand::ResolveApproval(ResolveApprovalReq {
                approval_id: "a".into(),
                action: ApprovalAction::Approve,
                scope: None,
                resolved_by: "u".into(),
                reason: None,
            }),
            UiCommand::ApproveTool(ApproveToolReq {
                server_id: "s".into(),
                tool_name: "t".into(),
            }),
            UiCommand::ApproveToolDrift(ApproveToolDriftReq {
                server_id: "s".into(),
                tool_name: "t".into(),
                new_hash: "h".into(),
            }),
            UiCommand::RejectToolDrift(RejectToolDriftReq {
                server_id: "s".into(),
                tool_name: "t".into(),
            }),
            UiCommand::ApproveServerCommandDrift(ApproveServerCommandDriftReq {
                server_id: "s".into(),
            }),
            UiCommand::RejectServerCommandDrift(RejectServerCommandDriftReq {
                server_id: "s".into(),
            }),
            UiCommand::UpsertSandboxProfile(UpsertSandboxProfileReq {
                profile: SandboxProfile {
                    id: "p".into(),
                    read_dirs: vec![],
                    write_dirs: vec![],
                    allow_hosts: vec![],
                    env_inherit: false,
                    wall_ms: 1000,
                    memory_mb: 64,
                },
            }),
            UiCommand::BindServerSandboxProfile(BindServerSandboxProfileReq {
                server_id: "s".into(),
                profile_id: Some("p".into()),
            }),
            UiCommand::RegisterServer(RegisterServerReq {
                server_id: "s".into(),
                transport: "stdio".into(),
                command: Some(vec!["npx".into(), "-y".into(), "@modelcontextprotocol/server-filesystem".into()]),
                url: None,
            }),
            UiCommand::AnchorCheckpoint,
            UiCommand::UpdateHubConfig(UpdateHubConfigReq {
                monitor_mode: Some(true),
                auto_approve_first_seen_tools: Some(false),
                redact_tool_results: None,
                outbox_enabled: Some(true),
                approval_wait_secs: Some(300),
                upstream_list_timeout_secs: Some(10),
                upstream_call_timeout_secs: Some(30),
            }),
        ];
        let _ = RunnerKind::Native;
        let _ = RunnerSpecific::Native {
            rlimit_placeholder: None,
        };
        for c in writes {
            assert_eq!(
                c.required_capability(),
                Capability::Write,
                "{c:?} should be Write"
            );
        }
    }

    #[test]
    fn ui_command_serde_roundtrip() {
        let c = UiCommand::ListRecentEvents(ListRecentEventsReq {
            session_id: Some("sid".into()),
            event_type_filter: Some(vec!["decision.recorded".into()]),
            limit: 100,
        });
        let s = serde_json::to_string(&c).unwrap();
        let back: UiCommand = serde_json::from_str(&s).unwrap();
        assert_eq!(c, back);
    }
}
