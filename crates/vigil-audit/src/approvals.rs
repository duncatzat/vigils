//! 审批队列 —— I03 状态机(ADR 0003 §D5-D6)。
//!
//! 承诺的不变量:
//! - 所有状态迁移走单写者 mutex,与 hash chain 相同;不存在同一 approval 被并发
//!   双写的可能。
//! - `pending` 行跨进程重启保留;`wait_for_resolution` 在重启后重新绑定 Condvar,
//!   caller 不需感知中断。
//! - `sweep_expired` 幂等:对已是终态的行 no-op,对 `Pending` 且过期的行置
//!   `Expired` 并 fire Condvar。

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use rusqlite::OptionalExtension;
use serde_json::{json, Value};
use uuid::Uuid;
use vigil_types::{
    ApprovalRequest, ApprovalResolution, ApprovalScope, ApprovalStatus, DecisionRecord,
    EffectVector,
};

use crate::error::{AuditError, Result};
use crate::ledger::{now_secs, AppendedEvent, Ledger};

/// v0.7-α6 A1 — `engine.degraded` 事件 typed payload(schema 锁定)。
///
/// 模型路径在 budget 内未完成 / 推理失败 → caller 退化 Hard-only(fail-closed),
/// 同步本 audit 事件追溯。
///
/// **设计纪律**(Codex § 2 ACCEPT):
/// - 字段集合**冻结**:加新字段视为 SemVer minor;改语义 / 删字段视为 major
/// - **不含原始 input** 文本(no-plaintext invariant)
/// - 用稳定 string code 而非 enum,避免 audit crate 循环依赖 firewall 类型
/// - reason_code 推荐 stable 字面量:`"timeout"` / `"infer_run_error"` /
///   `"engine_not_found"` / `"degraded_audit_failed"` / etc(由 caller 选)
///
/// # 示例 ingest(firewall caller)
///
/// ```ignore
/// let payload = EngineDegradedPayload {
///     engine_id: "openai-privacy-filter-v1".to_string(),
///     status: "degraded_timeout".to_string(),
///     reason_code: "budget_exceeded".to_string(),
///     budget_ms: Some(2000),
///     elapsed_ms: Some(2150),
///     fail_closed_decision: "fall_back_hard_only".to_string(),
///     decision_id: decision.decision_id.clone(),
/// };
/// ledger.record_engine_degraded(session_id, &payload)?;
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EngineDegradedPayload {
    /// 触发退化的 engine model_id(如 `openai-privacy-filter-v1`)
    pub engine_id: String,
    /// stable status string:推荐 `degraded_timeout` / `degraded_error` /
    /// `degraded_audit_failed`(列表锁定,caller 不应自创)
    pub status: String,
    /// stable reason code:`timeout` / `infer_run_error` / `model_not_found` /
    /// `oom` / `engine_panic` / 其他自定义短串(snake_case)
    pub reason_code: String,
    /// budget(若 timeout 触发);非 timeout 路径填 None
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_ms: Option<u64>,
    /// 实际推理耗时(ms);budgeted scan 内部测;若不可测填 None
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
    /// caller 退化决策:`fall_back_hard_only` / `deny_request` / `audit_only`(stable code)
    pub fail_closed_decision: String,
    /// 关联 decision_id(firewall 已生成的 UUID v4),便于 audit 跨表 join
    pub decision_id: String,
}

/// 可选上下文:让 approval 记录 `(server, tool, args_hash)` 三元组,
/// 以便 `ThisSession` scope 的后续匹配消费(ADR 0004 §F1)。
///
/// 非 firewall 来源(如 I05 server onboarding)可全部传 `None`。
#[derive(Debug, Default, Clone, Copy)]
pub struct ApprovalTargetContext<'a> {
    /// 目标 MCP server id
    pub server_id: Option<&'a str>,
    /// 目标工具名
    pub tool_name: Option<&'a str>,
    /// `ToolInvocation.args` 的 JCS+SHA-256 hex 摘要
    pub args_hash: Option<&'a str>,
}

/// 统一对"自由文本"字段做脱敏,保证写入审计账本的 payload 不携带原始 secret / PII。
///
/// 与 ADR 0003 §D8 的"typed API 收口"配套 —— 即使 caller 忘记 pre-redact,系统事件
/// 也能 fail-safe。多条字符串合并成一个 Value::Array 走一次 redact,以便复用正则引擎。
fn redact_free_text(parts: &[&str]) -> Vec<String> {
    let joined = Value::Array(parts.iter().map(|s| Value::String(s.to_string())).collect());
    let (redacted, _fts) = vigil_redaction::redact(&joined);
    match redacted {
        Value::Array(arr) => arr
            .into_iter()
            .map(|v| v.as_str().map(String::from).unwrap_or_default())
            .collect(),
        _ => parts.iter().map(|s| s.to_string()).collect(),
    }
}

/// 用来让 `wait_for_resolution` 阻塞并被 `resolve` 唤醒的条件变量槽。
///
/// 内层 `Mutex<Option<ApprovalResolution>>` 承载最终结果(None 表示仍 Pending)。
type ResolutionSlot = Arc<(Mutex<Option<ApprovalResolution>>, Condvar)>;

/// ISS-019 Phase 1 — `wait_for_resolution` cross-proc DB 轮询间隔。
///
/// **Why 500ms**:
/// - 太短(<200ms)→ DB 锁竞争高,影响其它写路径(append_event / approve)
/// - 太长(>2s)→ cross-proc approve 用户感知卡顿(如 vigil-desktop CLI resolve 后
///   Hub 端 wait_for_resolution 仍卡住)
/// - 500ms 是平衡点:用户感知接近实时,DB 锁竞争可忽略(单 SELECT,毫秒级)
///
/// In-proc 路径(同进程 `publish_resolution`)由 Condvar 立即唤醒,不受此值影响 ——
/// 只有 cross-proc(另一进程更新 DB)场景下,本进程通过此周期轮询检出。
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// 线程安全的 approval broker。内嵌在 `Ledger` 中,生命周期与 ledger 同步。
#[derive(Debug, Default)]
pub(crate) struct ApprovalBroker {
    waiters: Mutex<HashMap<String, ResolutionSlot>>,
}

impl ApprovalBroker {
    /// 取得(或创建)指定 approval 的等待槽。
    fn slot(&self, approval_id: &str) -> ResolutionSlot {
        let mut g = self.waiters.lock().unwrap_or_else(|p| p.into_inner()); // poisoned 时继续,等待 slot 是最终一致的
        g.entry(approval_id.to_string())
            .or_insert_with(|| Arc::new((Mutex::new(None), Condvar::new())))
            .clone()
    }

    /// 有新解析时:写入 slot + 广播。
    fn publish(&self, approval_id: &str, resolution: ApprovalResolution) {
        let slot = self.slot(approval_id);
        let (m, cv) = &*slot;
        let mut guard = m.lock().unwrap_or_else(|p| p.into_inner());
        *guard = Some(resolution);
        cv.notify_all();
    }
}

impl Ledger {
    // ------------------------------------------------------------------
    // 系统事件 API(ADR 0003 §D8):收口 `decision.*` / `approval.*` / `lease.*`
    // ------------------------------------------------------------------

    /// 写入一条 `decision.recorded` 审计事件。
    ///
    /// 此函数**不**自己生成 DecisionRecord,只负责账本化 —— 由 firewall 层产出后传入。
    pub fn record_decision(
        &self,
        session_id: &str,
        decision: &DecisionRecord,
        effects: &EffectVector,
    ) -> Result<AppendedEvent> {
        // 自由文本 reasons 可能包含 caller 拼进去的原始参数片段 —— 在 typed API 层
        // 强制脱敏,保证 §4 "secrets never in SQLite payloads"(ADR 0003 §D8)。
        let reason_strs: Vec<&str> = decision.reasons.iter().map(|s| s.as_str()).collect();
        let redacted_reasons = redact_free_text(&reason_strs);
        let payload = json!({
            "decision_id": decision.decision_id,
            "invocation_id": decision.invocation_id,
            "decision": decision.decision,
            "risk_score": decision.risk_score,
            "reasons": redacted_reasons,
            "policy_ids": decision.policy_ids,
            "effects": effects.effects,
            "destructive": effects.destructive,
            "reversible": effects.reversible,
        });
        let fts = format!(
            "decision_id:{} invocation_id:{} risk:{}",
            decision.decision_id, decision.invocation_id, decision.risk_score
        );
        self.append_event_internal(session_id, "decision.recorded", &payload, Some(&fts))
    }

    /// 写入 `approval.created` 事件。
    pub fn record_approval_created(&self, req: &ApprovalRequest) -> Result<AppendedEvent> {
        // title / summary 是 firewall 拼出的人读卡片文本,拼进去的 tool_name / args 摘要
        // 可能不小心含原始 secret 片段 —— typed API 强制过一次 redaction。
        let redacted = redact_free_text(&[&req.title, &req.summary]);
        let red_title = redacted.first().cloned().unwrap_or_default();
        let red_summary = redacted.get(1).cloned().unwrap_or_default();
        let payload = json!({
            "approval_id": req.approval_id,
            "decision_id": req.decision_id,
            "title": red_title,
            "summary": red_summary,
            "effects": req.effect_vector.effects,
            "expires_at": req.expires_at,
            "status": req.status,
        });
        let fts = format!(
            "approval_id:{} decision_id:{} {}",
            req.approval_id, req.decision_id, red_summary
        );
        self.append_event_internal(&req.session_id, "approval.created", &payload, Some(&fts))
    }

    /// 写入 `approval.resolved` 事件。
    pub fn record_approval_resolved(
        &self,
        req: &ApprovalRequest,
        resolution: &ApprovalResolution,
    ) -> Result<AppendedEvent> {
        let payload = json!({
            "approval_id": resolution.approval_id,
            "status": resolution.status,
            "scope": resolution.scope,
            "resolved_by": resolution.resolved_by,
            "resolved_at": resolution.resolved_at,
        });
        let fts = format!(
            "approval_id:{} resolved:{:?}",
            resolution.approval_id, resolution.status
        );
        self.append_event_internal(&req.session_id, "approval.resolved", &payload, Some(&fts))
    }

    /// I06 skeleton:`lease.minted` 写入。完整 API 在 lease broker 实装。
    pub fn record_lease_minted(
        &self,
        session_id: &str,
        lease_id: &str,
        secret_ref: &str,
        server_id: &str,
        tool_name: &str,
        expires_at: i64,
    ) -> Result<AppendedEvent> {
        let payload = json!({
            "lease_id": lease_id,
            "secret_ref": secret_ref,
            "server_id": server_id,
            "tool_name": tool_name,
            "expires_at": expires_at,
        });
        let fts = format!(
            "lease_id:{} secret_ref:{} server:{} tool:{}",
            lease_id, secret_ref, server_id, tool_name
        );
        self.append_event_internal(session_id, "lease.minted", &payload, Some(&fts))
    }

    /// I06 skeleton:`lease.revoked` 写入。
    pub fn record_lease_revoked(
        &self,
        session_id: &str,
        lease_id: &str,
        reason: &str,
    ) -> Result<AppendedEvent> {
        let payload = json!({"lease_id": lease_id, "reason": reason});
        let fts = format!("lease_id:{} reason:{}", lease_id, reason);
        self.append_event_internal(session_id, "lease.revoked", &payload, Some(&fts))
    }

    /// v0.7-α6 A1(E6a)— `engine.degraded` 事件:模型路径退化(timeout / error)
    /// 触发,审计可追溯 fail-closed 兜底路径。
    ///
    /// **schema 锁定**(Codex § 2 ACCEPT):为避免 v0.8 SDK 暴露后 SemVer 漂,
    /// 字段集合冻结:`engine_id` / `status` / `reason_code` / `budget_ms` /
    /// `elapsed_ms` / `fail_closed_decision` / `decision_id`。**不含**原始 input
    /// 文本(no-plaintext invariant 沿用)。
    ///
    /// **设计纪律**:
    /// - 不依赖 firewall 类型(audit crate 独立);firewall caller 用 stable string
    ///   code 填字段,避免循环依赖
    /// - degraded 必 fail-closed 决策:caller 不能默认 allow,应显式 fall-back
    ///   Hard-only 或 deny;本 method 只记账,不做决策
    /// - ledger 写失败由 [`crate::ledger::Ledger::audit_persist_failures`] 计数;
    ///   不背锅当事(caller 仍走原 deny / degraded 决策)
    pub fn record_engine_degraded(
        &self,
        session_id: &str,
        payload: &EngineDegradedPayload,
    ) -> Result<AppendedEvent> {
        // FTS:加 decision_id + status + engine_id 便于跨索引(用户 query
        // "engine.degraded WHERE status=degraded_timeout")
        let fts = format!(
            "engine_id:{} status:{} decision_id:{} reason:{}",
            payload.engine_id, payload.status, payload.decision_id, payload.reason_code
        );
        let payload_json = serde_json::to_value(payload)
            .unwrap_or_else(|_| json!({"error": "EngineDegradedPayload serialize failed"}));
        self.append_event_internal(session_id, "engine.degraded", &payload_json, Some(&fts))
    }

    // ------------------------------------------------------------------
    // Approval state machine(ADR 0003 §D5)
    // ------------------------------------------------------------------

    /// 由 firewall 在产生 `Approve` 决策后调用,创建待审批条目。
    ///
    /// 行为:生成 `approval_id`,写 `approvals` 表(status=Pending),同时追加
    /// `approval.created` 审计事件。
    // I04:签名扩展到 8 参,承载 server/tool/args_hash 上下文以支持 ThisSession scope
    // (ADR 0004 §F1)。完整参数列表本身是合同,拆 DTO 反而会让 caller 侧更啰嗦。
    #[allow(clippy::too_many_arguments)]
    pub fn create_approval(
        &self,
        session_id: &str,
        decision: &DecisionRecord,
        effects: &EffectVector,
        title: &str,
        summary: &str,
        ttl_secs: u64,
        // I04:server/tool/args_hash 用于 ThisSession scope 消费(ADR 0004 §F1)。
        // 非 firewall 来源的 approval 可传 None。
        context: ApprovalTargetContext<'_>,
    ) -> Result<ApprovalRequest> {
        let approval_id = Uuid::new_v4().to_string();
        let created_at = now_secs();
        // ttl=0 视为立即过期;i64 cast 防大值越界。
        let ttl_i64 = ttl_secs.min(i64::MAX as u64) as i64;
        let expires_at = created_at.saturating_add(ttl_i64);

        let effect_json = serde_json::to_string(effects)?;

        // no-plaintext ledger 守门(Codex audit MEDIUM):approvals **表**是 SQLite ledger 的持久面,
        // 但此前 title/summary/effect_json 原样 INSERT,**绕过**了 `append_event` 的硬指纹 fail-closed
        // 自检(只有 `approval.created` **事件**走 `redact_free_text`)。monitor 模式会自动建+解 approval,
        // 使此 sink 在无 GUI 时也活跃。用 `scrub_text` 在落表前遮蔽硬指纹 secret —— 保留 paths/hosts
        // 可读(GUI 审批仍能判断要批什么),只屏蔽真 secret 形态(proportionate;scrub 后仍是合法 JSON,
        // 读回可反序列化)。返回的 in-memory `ApprovalRequest` 仍保留原文(Hub 进程内决策用,不落盘)。
        let title_db = vigil_redaction::scrub_text(title);
        let summary_db = vigil_redaction::scrub_text(summary);
        let effect_json_db = vigil_redaction::scrub_text(&effect_json);

        {
            let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
            guard.execute(
                "INSERT INTO approvals
                  (approval_id, decision_id, invocation_id, session_id, title, summary,
                   effect_json, status, args_hash, server_id, tool_name,
                   expires_at, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'Pending', ?8, ?9, ?10, ?11, ?12)",
                rusqlite::params![
                    approval_id,
                    decision.decision_id,
                    decision.invocation_id,
                    session_id,
                    title_db,
                    summary_db,
                    effect_json_db,
                    context.args_hash,
                    context.server_id,
                    context.tool_name,
                    expires_at,
                    created_at,
                ],
            )?;
        }

        let req = ApprovalRequest {
            approval_id: approval_id.clone(),
            decision_id: decision.decision_id.clone(),
            invocation_id: decision.invocation_id.clone(),
            session_id: session_id.to_string(),
            title: title.to_string(),
            summary: summary.to_string(),
            effect_vector: effects.clone(),
            expires_at,
            status: ApprovalStatus::Pending,
        };

        self.record_approval_created(&req)?;
        Ok(req)
    }

    /// 列 Pending 状态的 approvals(供 I08 UI `ListPendingApprovals`)。
    ///
    /// Codex R1 NICE-TO-HAVE:替代 FTS + n+1 反推路径,直接 SQL 过滤 status='Pending'。
    pub fn list_pending_approvals(&self, session_id: Option<&str>) -> Result<Vec<ApprovalRequest>> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let (sql, use_sid) = match session_id {
            Some(_) => (
                "SELECT approval_id, decision_id, invocation_id, session_id, title, summary,
                        effect_json, status, expires_at
                 FROM approvals WHERE status = 'Pending' AND session_id = ?1
                 ORDER BY created_at",
                true,
            ),
            None => (
                "SELECT approval_id, decision_id, invocation_id, session_id, title, summary,
                        effect_json, status, expires_at
                 FROM approvals WHERE status = 'Pending'
                 ORDER BY created_at",
                false,
            ),
        };
        let mut stmt = guard.prepare(sql)?;
        let map_row = |r: &rusqlite::Row<'_>| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, i64>(8)?,
            ))
        };
        let rows = if use_sid {
            stmt.query_map(rusqlite::params![session_id.unwrap_or("")], map_row)?
        } else {
            stmt.query_map([], map_row)?
        };
        let mut out = Vec::new();
        for r in rows {
            let (
                approval_id,
                decision_id,
                invocation_id,
                session_id,
                title,
                summary,
                effect_json,
                status,
                expires_at,
            ) = r?;
            let effect_vector: EffectVector = serde_json::from_str(&effect_json)?;
            let status = parse_status(&status)?;
            out.push(ApprovalRequest {
                approval_id,
                decision_id,
                invocation_id,
                session_id,
                title,
                summary,
                effect_vector,
                expires_at,
                status,
            });
        }
        Ok(out)
    }

    /// 读取单条 approval(完整 `ApprovalRequest`)。
    pub fn get_approval(&self, approval_id: &str) -> Result<Option<ApprovalRequest>> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let row = guard
            .query_row(
                "SELECT approval_id, decision_id, invocation_id, session_id, title, summary,
                        effect_json, status, expires_at
                 FROM approvals WHERE approval_id = ?1",
                rusqlite::params![approval_id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, String>(5)?,
                        r.get::<_, String>(6)?,
                        r.get::<_, String>(7)?,
                        r.get::<_, i64>(8)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            approval_id,
            decision_id,
            invocation_id,
            session_id,
            title,
            summary,
            effect_json,
            status,
            expires_at,
        )) = row
        else {
            return Ok(None);
        };
        let effect_vector: EffectVector = serde_json::from_str(&effect_json)?;
        let status = parse_status(&status)?;
        Ok(Some(ApprovalRequest {
            approval_id,
            decision_id,
            invocation_id,
            session_id,
            title,
            summary,
            effect_vector,
            expires_at,
            status,
        }))
    }

    /// 批准。若 approval 已处终态(非 Pending)直接返回现状。
    pub fn approve(
        &self,
        approval_id: &str,
        scope: ApprovalScope,
        resolved_by: Option<&str>,
    ) -> Result<ApprovalResolution> {
        self.resolve(
            approval_id,
            ApprovalStatus::Approved,
            Some(scope),
            resolved_by,
        )
    }

    /// 用户取消(区别于 policy Deny)。I08 `UiCommand::ResolveApproval::Cancel` 走此路径,
    /// 最终状态 `ApprovalStatus::Cancelled`,与"policy 主动拒绝"保留分开审计。
    pub fn cancel(
        &self,
        approval_id: &str,
        resolved_by: Option<&str>,
    ) -> Result<ApprovalResolution> {
        self.resolve(approval_id, ApprovalStatus::Cancelled, None, resolved_by)
    }

    /// 拒绝。`reason` 仅记入审计文本,不影响状态机。
    pub fn deny(
        &self,
        approval_id: &str,
        reason: Option<&str>,
        resolved_by: Option<&str>,
    ) -> Result<ApprovalResolution> {
        let out = self.resolve(approval_id, ApprovalStatus::Denied, None, resolved_by)?;
        if let Some(r) = reason {
            let req = self
                .get_approval(approval_id)?
                .ok_or(AuditError::InvalidInput {
                    reason: "approval disappeared after deny",
                })?;
            // 用户拒绝理由先过 redaction,再写 audit —— 避免用户不小心粘贴
            // 含 secret / PII 的文本进拒绝框时污染账本(ADR 0003 §D8)。
            let red = redact_free_text(&[r]);
            let red_r = red.first().cloned().unwrap_or_default();
            self.append_event_internal(
                &req.session_id,
                "approval.note",
                &json!({"approval_id": approval_id, "reason": red_r}),
                Some(&red_r),
            )?;
        }
        Ok(out)
    }

    /// 查找当前 session 下与 `(server, tool, args_hash)` 匹配、scope=ThisSession、
    /// 未过期的已批准 approval。用于 Hub 在 firewall.evaluate 前快速放行(ADR 0004 §F1)。
    ///
    /// 命中时:返回合成的 [`ApprovalResolution`];Hub 可在审计事件里记录
    /// `tool_call.allowed_by_session_scope` 并跳过 firewall 常规流程。
    pub fn find_session_scope_allow(
        &self,
        session_id: &str,
        server_id: &str,
        tool_name: &str,
        args_hash: &str,
    ) -> Result<Option<ApprovalResolution>> {
        let now = now_secs();
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let row = guard
            .query_row(
                "SELECT approval_id, invocation_id, resolved_at, resolved_by
                 FROM approvals
                 WHERE session_id = ?1 AND server_id = ?2 AND tool_name = ?3
                   AND args_hash = ?4 AND scope = 'ThisSession'
                   AND status = 'Approved' AND expires_at > ?5
                 ORDER BY resolved_at DESC LIMIT 1",
                rusqlite::params![session_id, server_id, tool_name, args_hash, now],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<i64>>(2)?,
                        r.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((approval_id, invocation_id, resolved_at, resolved_by)) = row else {
            return Ok(None);
        };
        Ok(Some(ApprovalResolution {
            approval_id,
            invocation_id,
            status: ApprovalStatus::Approved,
            scope: Some(ApprovalScope::ThisSession),
            resolved_by,
            resolved_at: resolved_at.unwrap_or(now),
        }))
    }

    /// 扫描所有 Pending 且已过期的行,置 `Expired` 并 fire 等待方。
    /// 返回本次解析出的全部 resolution(可能为空)。
    pub fn sweep_expired(&self) -> Result<Vec<ApprovalResolution>> {
        let now = now_secs();
        let ids: Vec<(String, String)> = {
            let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
            let mut stmt = guard.prepare(
                "SELECT approval_id, session_id FROM approvals
                 WHERE status = 'Pending' AND expires_at <= ?1",
            )?;
            let rows = stmt.query_map([now], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?;
            let mut v = Vec::new();
            for r in rows {
                v.push(r?);
            }
            v
        };

        let mut out = Vec::new();
        for (id, _sid) in ids {
            let res = self.resolve(&id, ApprovalStatus::Expired, None, Some("auto-expired"))?;
            out.push(res);
        }
        Ok(out)
    }

    /// 阻塞等待一条 approval 达到终态,最长等 `timeout`;超时返回 `None`。
    ///
    /// 若 approval 已处终态(含 Approved/Denied/Expired/Cancelled),立即返回当前
    /// resolution。线程安全:内部不会长期持有 DB 锁,只在初始查询与每次轮询时加锁。
    ///
    /// **ISS-019 Phase 1(2026-04-28)cross-proc 根治**:
    /// 内 loop 把 `wait_timeout` 切成 `WAIT_POLL_INTERVAL = 500ms` 片段,每片之间
    /// **主动查一次 DB**。这样 cross-proc 写入(如 `vigil-desktop approvals resolve`
    /// 直接 UPDATE 状态行,不经过 Condvar)能在最多 ~500ms 后被本进程感知。
    /// 解决 v0.3 Stage 3 发现的"ApprovalBroker 跨进程无 Condvar 通知"架构债 ——
    /// `vigil-hub serve --dev-permissive-firewall + approval_wait=3s` 的 hack 可下掉。
    ///
    /// **In-proc Condvar 路径仍然有效**:同进程 `Ledger::approve / deny / cancel` 调
    /// `publish_resolution`,Condvar `notify_all` 立即唤醒所有 waiter,延迟仍 ≈ 0;
    /// 短轮询只在 cross-proc 路径下兜底(本进程不会自己 publish)。
    pub fn wait_for_resolution(
        &self,
        approval_id: &str,
        timeout: Duration,
    ) -> Result<Option<ApprovalResolution>> {
        // 1) 快速路径:已终态直接返。
        if let Some(existing) = self.current_resolution(approval_id)? {
            return Ok(Some(existing));
        }

        // 2) 慢路径:Condvar slot 阻塞 + cross-proc DB 短轮询兜底。
        //
        // **race 防御**(Codex I02+I03 review MUST-FIX):`wait_timeout` 返 timed_out
        // 与另一线程 `publish()` 可能并发发生,直接 break 会错把已解析当超时。
        // 改为每次 wait_timeout 后既查 in-proc guard 也查 DB(后者覆盖 cross-proc)。
        let slot = self.approval_broker.slot(approval_id);
        let (mx, cv) = &*slot;
        let deadline = Instant::now() + timeout;
        let mut guard = mx.lock().unwrap_or_else(|p| p.into_inner());
        while guard.is_none() {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            // 每片不超过 WAIT_POLL_INTERVAL,以便 cross-proc 写入能在 ≤500ms 检出
            let remain = deadline - now;
            let slice = remain.min(WAIT_POLL_INTERVAL);
            let (g2, _wait_res) = cv
                .wait_timeout(guard, slice)
                .unwrap_or_else(|p| p.into_inner());
            guard = g2;
            // in-proc publish 已填 guard?直接退 loop。
            if guard.is_some() {
                break;
            }
            // cross-proc 路径:另一进程已写 DB 终态,但本进程 Condvar 不会被通知。
            // 这里手动查一次,命中即返;否则继续 wait 下一片。
            // **注意**:释放 guard 让其它持锁路径不被阻塞 —— DB 查询独立加 conn 锁。
            drop(guard);
            if let Some(existing) = self.current_resolution(approval_id)? {
                return Ok(Some(existing));
            }
            // 重新拿 guard 进入下一轮 wait_timeout
            guard = mx.lock().unwrap_or_else(|p| p.into_inner());
        }
        if let Some(r) = guard.clone() {
            return Ok(Some(r));
        }
        drop(guard);
        // 最后一次 DB 兜底查询(覆盖最后一片 wait 内 cross-proc 写入到本检查间的 race)
        self.current_resolution(approval_id)
    }

    /// 当前状态快照:若 approval 是终态则返 `Some(resolution)`,否则 `None`。
    ///
    /// I04(Codex review M1):从 DB 回读 `scope` 列,避免 fast-path 丢失
    /// `Approved(ThisSession)` 语义回退成 `Approved(None)`。
    fn current_resolution(&self, approval_id: &str) -> Result<Option<ApprovalResolution>> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let row = guard
            .query_row(
                "SELECT status, resolved_at, resolved_by, invocation_id, scope
                 FROM approvals WHERE approval_id = ?1",
                rusqlite::params![approval_id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<i64>>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, Option<String>>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((status_str, resolved_at, resolved_by, invocation_id, scope_str)) = row else {
            return Ok(None);
        };
        let status = parse_status(&status_str)?;
        if matches!(status, ApprovalStatus::Pending) {
            return Ok(None);
        }
        let scope = scope_str.and_then(|s| parse_scope(&s));
        Ok(Some(ApprovalResolution {
            approval_id: approval_id.to_string(),
            invocation_id,
            status,
            scope,
            resolved_by,
            resolved_at: resolved_at.unwrap_or(now_secs()),
        }))
    }

    fn resolve(
        &self,
        approval_id: &str,
        target: ApprovalStatus,
        scope: Option<ApprovalScope>,
        resolved_by: Option<&str>,
    ) -> Result<ApprovalResolution> {
        let now = now_secs();

        // 1) DB 层:Pending → target;已终态不覆盖。I04:scope 同步写入 —— 只在
        // 推进到 Approved 时写入 scope 值,其它终态写 NULL。
        let scope_str = match (target, scope) {
            (ApprovalStatus::Approved, Some(s)) => Some(scope_to_str(s)),
            _ => None,
        };
        let updated_rows = {
            let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
            guard.execute(
                "UPDATE approvals
                 SET status = ?1, resolved_at = ?2, resolved_by = ?3, scope = ?4
                 WHERE approval_id = ?5 AND status = 'Pending'",
                rusqlite::params![status_str(target), now, resolved_by, scope_str, approval_id],
            )?
        };

        // 2) 读当前权威状态(无论是否是本调用更新的)
        let req = self
            .get_approval(approval_id)?
            .ok_or(AuditError::InvalidInput {
                reason: "approval not found",
            })?;

        // 只有"本次调用实际推进了状态"时,才把传入的 scope 带出;否则保持 None,
        // 表示"scope 由首次解析决定,本次调用没有权力覆盖"(Once 语义的回归保护)。
        let effective_scope = if updated_rows > 0 && matches!(req.status, ApprovalStatus::Approved)
        {
            scope
        } else {
            None
        };
        // MUST-FIX(Codex I02+I03 review):若本次调用未真正推进状态(updated_rows == 0),
        // 不能用当前调用方的 resolved_by/now 伪造元数据,必须从 DB 读真实首解析者的值。
        let (effective_resolver, effective_resolved_at) = if updated_rows > 0 {
            (resolved_by.map(str::to_string), now)
        } else {
            read_persisted_resolution_meta(&self.conn, approval_id)?
        };
        let resolution = ApprovalResolution {
            approval_id: approval_id.to_string(),
            invocation_id: req.invocation_id.clone(),
            status: req.status,
            scope: effective_scope,
            resolved_by: effective_resolver,
            resolved_at: effective_resolved_at,
        };

        // 3) 若本次调用确实让状态从 Pending → 终态,记审计 + 广播给等待方。
        if updated_rows > 0 {
            self.record_approval_resolved(&req, &resolution)?;
            self.approval_broker
                .publish(approval_id, resolution.clone());
        }

        Ok(resolution)
    }
}

/// 读持久化的 `resolved_by` / `resolved_at`。
/// 用于"本次调用没有推进状态,返回真实首解析者元数据"的场景。
fn read_persisted_resolution_meta(
    conn: &std::sync::Mutex<rusqlite::Connection>,
    approval_id: &str,
) -> Result<(Option<String>, i64)> {
    let guard = conn.lock().map_err(|_| AuditError::LockPoisoned)?;
    let r = guard
        .query_row(
            "SELECT resolved_by, resolved_at FROM approvals WHERE approval_id = ?1",
            rusqlite::params![approval_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                ))
            },
        )
        .optional()?;
    let (by, at) = r.unwrap_or((None, None));
    Ok((by, at.unwrap_or(0)))
}

fn parse_status(s: &str) -> Result<ApprovalStatus> {
    Ok(match s {
        "Pending" => ApprovalStatus::Pending,
        "Approved" => ApprovalStatus::Approved,
        "Denied" => ApprovalStatus::Denied,
        "Expired" => ApprovalStatus::Expired,
        "Cancelled" => ApprovalStatus::Cancelled,
        _ => {
            return Err(AuditError::InvalidInput {
                reason: "approvals.status contains unknown variant",
            })
        }
    })
}

fn scope_to_str(s: ApprovalScope) -> &'static str {
    match s {
        ApprovalScope::Once => "Once",
        ApprovalScope::ThisSession => "ThisSession",
        ApprovalScope::ForToolWithSameArgsHash => "ForToolWithSameArgsHash",
        ApprovalScope::ForPolicyTemplate => "ForPolicyTemplate",
        // non_exhaustive:未知扩展回落 Once(fail-closed 最窄语义)
        _ => "Once",
    }
}

fn parse_scope(s: &str) -> Option<ApprovalScope> {
    match s {
        "Once" => Some(ApprovalScope::Once),
        "ThisSession" => Some(ApprovalScope::ThisSession),
        "ForToolWithSameArgsHash" => Some(ApprovalScope::ForToolWithSameArgsHash),
        "ForPolicyTemplate" => Some(ApprovalScope::ForPolicyTemplate),
        _ => None,
    }
}

fn status_str(s: ApprovalStatus) -> &'static str {
    match s {
        ApprovalStatus::Pending => "Pending",
        ApprovalStatus::Approved => "Approved",
        ApprovalStatus::Denied => "Denied",
        ApprovalStatus::Expired => "Expired",
        ApprovalStatus::Cancelled => "Cancelled",
        _ => "Pending", // non_exhaustive 兜底:未知值视为 Pending 以免悄然写错
    }
}
