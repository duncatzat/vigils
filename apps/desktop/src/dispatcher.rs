//! UiCommand dispatcher(ADR 0008 §D3):把 typed command 翻译为 Ledger 调用 + typed response。
//!
//! 纯 Rust 函数,不启 clap / 不读 stdin / 不渲染 —— 便于 §12.3 I08 验收集成测试直调。

use vigil_audit::{is_reserved_env_key_name, Ledger, ToolApprovalCard};
use vigil_runner::SandboxProfile;
use vigil_ui_protocol::{
    ApprovalAction, ApprovalDetailDto, ApprovalResolutionDto, ApprovalSummary, Capability,
    ChainVerifyReport, EventDetail, EventSummary, PrivacyFindingDto, PrivacyFindingsDto,
    RedactionScanSummaryDto, SandboxProfileUpsertDto, SessionReplay, SessionSummary, UiCommand,
    UiError, UiResponse,
};

use crate::export::render_session_replay;

/// 前端可控读路径的结果集硬上限(审计 ISS-20260702-017):`ListRecentEvents` /
/// `FtsSearch` 的 `limit` 来自渲染层,超大值会拉全表拖垮 UI/内存。服务端 clamp 到此值,
/// 与 DoS 面解耦(正常分页远小于此;需要更多由前端分页续拉)。
const MAX_QUERY_LIMIT: u32 = 1000;

/// 把 typed `UiCommand` 翻译为 Ledger 操作。
///
/// `actor_capability` 来自调用端(CLI `--capability` 或 Tauri capability token);
/// 写命令要求 `Capability::Write`,否则返 `CapabilityDenied`。
pub fn dispatch(
    cmd: UiCommand,
    ledger: &Ledger,
    actor_capability: Capability,
) -> Result<UiResponse, UiError> {
    // §I-8.4 gate:写命令必须持 Write capability
    if cmd.required_capability() == Capability::Write && actor_capability != Capability::Write {
        return Err(UiError::CapabilityDenied {
            required: "ui.write",
        });
    }

    match cmd {
        // --- Activity / Audit ---
        UiCommand::ListRecentEvents(req) => {
            let limit = req.limit.clamp(1, MAX_QUERY_LIMIT);
            let filter = req.event_type_filter.as_deref();
            let hits = ledger
                .list_recent_events(req.session_id.as_deref(), filter, limit)
                .map_err(ledger_err)?;
            let out = hits
                .into_iter()
                .map(|h| EventSummary {
                    event_id: h.event_id,
                    session_id: h.session_id,
                    event_type: h.event_type,
                    redacted_text: h.redacted_text,
                    created_at: h.created_at,
                })
                .collect();
            Ok(UiResponse::EventList(out))
        }
        UiCommand::GetEventDetail(req) => {
            let row = ledger
                .get_event_detail(req.event_id)
                .map_err(ledger_err)?
                .ok_or_else(|| UiError::NotFound(format!("event_id={}", req.event_id)))?;
            Ok(UiResponse::EventDetail(EventDetail {
                event_id: row.event_id,
                session_id: row.session_id,
                event_type: row.event_type,
                payload: row.payload,
                redacted_text: row.redacted_text,
                prev_hash: row.prev_hash,
                event_hash: row.event_hash,
                created_at: row.created_at,
            }))
        }
        UiCommand::FtsSearch(req) => {
            let cap = req.limit.min(MAX_QUERY_LIMIT) as usize;
            let hits = ledger.fts_search(&req.query).map_err(ledger_err)?;
            let limited: Vec<_> = hits.into_iter().take(cap).collect();
            Ok(UiResponse::SearchHits(limited))
        }

        // --- Approval Queue ---
        UiCommand::ListPendingApprovals(req) => {
            let rows = list_pending_approvals_impl(ledger, req.session_id.as_deref())?;
            Ok(UiResponse::ApprovalList(rows))
        }
        UiCommand::GetApprovalDetail(req) => {
            let row = ledger
                .get_approval(&req.approval_id)
                .map_err(ledger_err)?
                .ok_or_else(|| UiError::NotFound(req.approval_id.clone()))?;
            // ISS-014:聚合本 session 的 redaction findings(label × count)。
            // 失败不阻断 detail 返回(审计缺失不应让审批 UI 崩);降级为空 Vec。
            let privacy_findings =
                match ledger.aggregate_redaction_labels_by_session(&row.session_id) {
                    Ok(rows) => rows
                        .into_iter()
                        .map(|(label, count)| PrivacyFindingDto { label, count })
                        .collect(),
                    Err(_) => Vec::new(),
                };
            Ok(UiResponse::ApprovalDetail(ApprovalDetailDto {
                invocation_id: row.invocation_id.clone(),
                decision_id: row.decision_id.clone(),
                privacy_findings,
                request: row,
            }))
        }
        // ISS-017 — Privacy Findings 聚合面板 payload。
        // 关键不变量:**绝不展原文** —— 仅 label/count + fingerprint(hex)+ bucket 元数据。
        UiCommand::ListPrivacyFindings(req) => {
            let by_label_total = ledger
                .aggregate_redaction_labels_global()
                .map_err(ledger_err)?
                .into_iter()
                .map(|(label, count)| PrivacyFindingDto { label, count })
                .collect();
            let recent_scans = ledger
                .list_recent_redaction_scans_with_counts(req.limit_recent_scans)
                .map_err(ledger_err)?
                .into_iter()
                .map(|(row, finding_count)| RedactionScanSummaryDto {
                    scan_id: row.scan_id,
                    session_id: row.session_id,
                    ts: row.ts,
                    source: row.source,
                    text_length_bucket: row.text_length_bucket,
                    fingerprint: row.fingerprint,
                    finding_count,
                })
                .collect();
            Ok(UiResponse::PrivacyFindings(PrivacyFindingsDto {
                by_label_total,
                recent_scans,
            }))
        }
        UiCommand::ResolveApproval(req) => {
            let resolution = match req.action {
                ApprovalAction::Approve => {
                    let scope = req.scope.ok_or(UiError::Invalid(
                        "approve action requires scope (Once / ThisSession)",
                    ))?;
                    ledger
                        .approve(&req.approval_id, scope, Some(&req.resolved_by))
                        .map_err(ledger_err)?
                }
                ApprovalAction::Deny => ledger
                    .deny(
                        &req.approval_id,
                        req.reason.as_deref(),
                        Some(&req.resolved_by),
                    )
                    .map_err(ledger_err)?,
                // Codex R1 MUST-FIX:Cancel 走 audit 新增的 `cancel_approval`,
                // 最终状态 ApprovalStatus::Cancelled(与 Denied 分开审计语义)。
                ApprovalAction::Cancel => ledger
                    .cancel(&req.approval_id, Some(&req.resolved_by))
                    .map_err(ledger_err)?,
            };
            Ok(UiResponse::ApprovalResolution(ApprovalResolutionDto {
                approval_id: resolution.approval_id,
                status: resolution.status,
                scope: resolution.scope,
                resolved_by: resolution.resolved_by,
            }))
        }

        // --- Session Replay ---
        UiCommand::ListSessions(req) => {
            let limit = if req.limit == 0 { 100 } else { req.limit };
            let rows = ledger
                .list_sessions(req.source.as_deref(), limit)
                .map_err(ledger_err)?;
            let out = rows
                .into_iter()
                .map(|r| SessionSummary {
                    session_id: r.session_id,
                    source: r.source,
                    app_name: r.app_name,
                    started_at: r.started_at,
                    ended_at: r.ended_at,
                    risk_score: r.risk_score,
                })
                .collect();
            Ok(UiResponse::SessionList(out))
        }
        UiCommand::ReplaySession(req) => {
            let events = ledger.replay_session(&req.session_id).map_err(ledger_err)?;
            let event_count = events.len();
            let verified = if req.verify {
                Some(verify_chain_report(ledger))
            } else {
                None
            };
            let events = events
                .into_iter()
                .map(|e| EventDetail {
                    event_id: e.event_id,
                    session_id: e.session_id,
                    event_type: e.event_type,
                    payload: e.payload,
                    redacted_text: e.redacted_text,
                    prev_hash: e.prev_hash,
                    event_hash: e.event_hash,
                    created_at: e.created_at,
                })
                .collect();
            Ok(UiResponse::ReplayDump(SessionReplay {
                session_id: req.session_id,
                event_count,
                events,
                chain_verified: verified,
            }))
        }
        UiCommand::VerifyChain => Ok(UiResponse::ChainVerification(verify_chain_report(ledger))),

        // ISS-018 — Safe Export:复用 ReplaySession 结果,渲染为 MD / HTML 文本。
        // 关键不变量:render_session_replay 仅消费已脱敏 payload(events 入库时由
        // vigil-redaction 处理),不接触任何"从未脱敏的源"。
        UiCommand::ExportSessionReplay(req) => {
            let events = ledger.replay_session(&req.session_id).map_err(ledger_err)?;
            let event_count = events.len();
            let events = events
                .into_iter()
                .map(|e| EventDetail {
                    event_id: e.event_id,
                    session_id: e.session_id,
                    event_type: e.event_type,
                    payload: e.payload,
                    redacted_text: e.redacted_text,
                    prev_hash: e.prev_hash,
                    event_hash: e.event_hash,
                    created_at: e.created_at,
                })
                .collect();
            let replay = SessionReplay {
                session_id: req.session_id.clone(),
                event_count,
                events,
                chain_verified: None, // 导出本身不附带 chain verify;UI 已在 replay 时显示
            };
            let dto = render_session_replay(&replay, req.format);
            Ok(UiResponse::SessionExport(dto))
        }

        // --- Server Registry ---
        UiCommand::ListServers => {
            let rows = ledger.list_approved_servers().map_err(ledger_err)?;
            Ok(UiResponse::ServerList(rows))
        }
        UiCommand::GetServerOnboarding(req) => {
            let data = ledger
                .get_onboarding_data(&req.server_id)
                .map_err(ledger_err)?
                .ok_or_else(|| UiError::NotFound(req.server_id.clone()))?;
            Ok(UiResponse::ServerOnboarding(data))
        }
        UiCommand::ListPendingToolApprovals => {
            let cards = ledger.list_pending_tool_approvals().map_err(ledger_err)?;
            Ok(UiResponse::ToolApprovalList(tool_cards_dto(cards)))
        }
        UiCommand::ListDriftedTools => {
            let cards = ledger.list_drifted_tools().map_err(ledger_err)?;
            Ok(UiResponse::ToolApprovalList(tool_cards_dto(cards)))
        }
        UiCommand::ListDriftedServers => {
            let rows = ledger.list_drifted_servers().map_err(ledger_err)?;
            Ok(UiResponse::DriftedServerList(rows))
        }
        UiCommand::ApproveTool(req) => {
            ledger
                .approve_tool_descriptor(&req.server_id, &req.tool_name)
                .map_err(ledger_err)?;
            // 若 server trust_level 仍为 Untrusted 且所有 tools 已 approved,也把 server 升级
            // —— 暂由 UI 调用方另走 ApproveServer(未在 I08a 范围);此处仅 tool 级。
            Ok(UiResponse::Ack)
        }
        UiCommand::ApproveToolDrift(req) => {
            ledger
                .approve_tool_descriptor_to(&req.server_id, &req.tool_name, &req.new_hash)
                .map_err(ledger_err)?;
            Ok(UiResponse::Ack)
        }
        UiCommand::RejectToolDrift(req) => {
            ledger
                .reject_tool_descriptor_drift(&req.server_id, &req.tool_name)
                .map_err(ledger_err)?;
            Ok(UiResponse::Ack)
        }
        UiCommand::ApproveServerCommandDrift(req) => {
            ledger
                .approve_server_command_drift(&req.server_id)
                .map_err(ledger_err)?;
            Ok(UiResponse::Ack)
        }
        UiCommand::RejectServerCommandDrift(req) => {
            ledger
                .reject_server_command_drift(&req.server_id)
                .map_err(ledger_err)?;
            Ok(UiResponse::Ack)
        }

        // --- SandboxProfile ---
        UiCommand::ListSandboxProfiles => {
            let rows = ledger.list_sandbox_profiles().map_err(ledger_err)?;
            let profiles = rows
                .into_iter()
                .map(|r| {
                    serde_json::from_str::<SandboxProfile>(&r.profile_json).map_err(|_| {
                        UiError::LedgerError {
                            reason_code: "profile_json_parse_failed",
                        }
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(UiResponse::SandboxProfileList(profiles))
        }
        UiCommand::GetSandboxProfile(req) => {
            let row = ledger
                .get_sandbox_profile(&req.profile_id)
                .map_err(ledger_err)?;
            let opt = match row {
                Some(r) => Some(
                    serde_json::from_str::<SandboxProfile>(&r.profile_json).map_err(|_| {
                        UiError::LedgerError {
                            reason_code: "profile_json_parse_failed",
                        }
                    })?,
                ),
                None => None,
            };
            Ok(UiResponse::SandboxProfileOpt(opt))
        }
        UiCommand::UpsertSandboxProfile(req) => {
            // Codex R1 MUST-FIX 3:self-validate 下沉到 Ledger 公共 API。
            // 协议层只负责把 `SandboxProfile` 序列化为 JSON 交给 Ledger;Ledger
            // 内部做 parse + env_inherit 校验 + JCS canonicalize + sha256。
            let _ = is_reserved_env_key_name; // 保留 import,未来若加 env key 字段复用
            let raw_json =
                serde_json::to_string(&req.profile).map_err(|_| UiError::ProfileSerializeFailed)?;
            let result = ledger
                .upsert_sandbox_profile(&req.profile.id, &raw_json)
                .map_err(ledger_err)?;
            Ok(UiResponse::SandboxProfileUpserted(
                SandboxProfileUpsertDto {
                    profile_id: req.profile.id.clone(),
                    profile_hash: result.profile_hash,
                    inserted: result.inserted,
                },
            ))
        }

        UiCommand::BindServerSandboxProfile(req) => {
            ledger
                .bind_server_sandbox_profile(&req.server_id, req.profile_id.as_deref())
                .map_err(ledger_err)?;
            Ok(UiResponse::Ack)
        }
        // UiCommand 是 non_exhaustive,兜底 fail-closed
        _ => Err(UiError::Invalid("unknown UiCommand variant")),
    }
}

// ---------------- helpers ----------------

fn ledger_err(e: vigil_audit::AuditError) -> UiError {
    use vigil_audit::AuditError;
    match e {
        AuditError::InvalidInput { reason } => {
            // reason 是 'static str,稳定 code
            if let Some(rest) = reason.strip_prefix("argv_contains_secret:") {
                // 回传 SecretInArgv,由 UI 显示红色警示
                let rule: &'static str = match rest {
                    "github_token" => "github_token",
                    "anthropic_key" => "anthropic_key",
                    "openai_key" => "openai_key",
                    "slack_token" => "slack_token",
                    "aws_access_key" => "aws_access_key",
                    "google_api_key" => "google_api_key",
                    "pem_private_key" => "pem_private_key",
                    _ => "other",
                };
                return UiError::SecretInArgv {
                    server_id: String::new(), // registry 层未返 server_id,占位
                    rule,
                };
            }
            UiError::Invalid(reason)
        }
        AuditError::LockPoisoned => UiError::LedgerError {
            reason_code: "lock_poisoned",
        },
        AuditError::ChainBroken { .. } => UiError::LedgerError {
            reason_code: "chain_broken",
        },
        AuditError::RegistryConflict { .. } => UiError::LedgerError {
            reason_code: "registry_conflict",
        },
        AuditError::HardSecretDetected { .. } => UiError::LedgerError {
            reason_code: "hard_secret_detected",
        },
        _ => UiError::LedgerError {
            reason_code: "ledger_error",
        },
    }
}

fn verify_chain_report(ledger: &Ledger) -> ChainVerifyReport {
    // Codex R1 MUST-FIX:`message` 只承载固定 reason_code / 定位信息,**不**泄漏
    // AuditError::Sqlite/Json 等底层 Display(可能含 SQL / 路径 / secret 派生文本)。
    match ledger.verify_chain() {
        Ok(_) => ChainVerifyReport {
            ok: true,
            broken_at_event_id: None,
            message: None,
        },
        Err(vigil_audit::AuditError::ChainBroken { event_id }) => ChainVerifyReport {
            ok: false,
            broken_at_event_id: Some(event_id),
            message: Some(format!("chain_broken_at={event_id}")),
        },
        Err(_other) => ChainVerifyReport {
            ok: false,
            broken_at_event_id: None,
            message: Some("chain_verify_failed".into()),
        },
    }
}

fn tool_cards_dto(cards: Vec<ToolApprovalCard>) -> Vec<ToolApprovalCard> {
    // 当前 DTO 就是 ToolApprovalCard,直接透传(占位以备未来投影)
    cards
}

fn list_pending_approvals_impl(
    ledger: &Ledger,
    session_id: Option<&str>,
) -> Result<Vec<ApprovalSummary>, UiError> {
    // Codex R1 NICE-TO-HAVE:替代原 FTS + n+1 反推路径,直接用 SQL 过滤
    // `status='Pending'`,避开 redacted_text 格式耦合与 FTS token 拆分不确定性。
    let pending = ledger
        .list_pending_approvals(session_id)
        .map_err(ledger_err)?;
    Ok(pending.iter().map(ApprovalSummary::from).collect())
}
