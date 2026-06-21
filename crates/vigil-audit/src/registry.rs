//! Server Registry —— I04 最小版(ADR 0004 §D6)。
//!
//! 负责持久化 MCP server 身份档案,并给 firewall 的 DescriptorOracle 提供查询。
//! I04 范围内只支持 `Unapproved → Approved` 单向过渡;I05 再扩 Drift 再审批。

use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use vigil_types::{ServerProfile, TransportKind, TrustLevel};

use crate::error::{AuditError, Result};
use crate::ledger::Ledger;

/// `pin_tool_descriptor` 的三态输出(ADR 0005 §D1)。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PinOutcome {
    /// (server, tool) 首次登记,`approved_at` 为 NULL,等待显式批准
    FirstSeen,
    /// 同 hash 幂等,仅刷新 last_seen 时间戳
    Unchanged,
    /// 新 hash 与已批准的 `descriptor_hash` 不等,`pending_hash` 被更新
    Drifted {
        /// 已批准的旧 hash
        old: String,
        /// 新看到的 hash
        new: String,
    },
}

/// UI 渲染数据(ADR 0005 §D3):Server 首次接入卡片。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ServerOnboardingData {
    /// server id
    pub server_id: String,
    /// 传输类型
    pub transport: TransportKind,
    /// Stdio 下的完整 argv(exact command,UI 必须原样展示,不做解释)
    pub command: Option<Vec<String>>,
    /// Http 下的 URL
    pub url: Option<String>,
    /// 当前已批准 argv 的 sha256 hex
    pub command_hash: Option<String>,
    /// 若 command 漂移,指向新的 argv hash;UI 展示 diff
    pub pending_command_hash: Option<String>,
    /// 将被注入的环境变量 key 清单(**值永不出现**)。
    ///
    /// 语义(Codex I05 MUST-FIX):
    /// - `None` = **未知**(I05 未知,I06 lease 层未计算完成),UI 应展示为 "等待 lease 分析"
    /// - `Some(vec![])` = 明确 "无 env 需求"
    /// - `Some(vec!["GITHUB_TOKEN", ...])` = 已知的 env key 清单(值永不暴露)
    pub requested_env_keys: Option<Vec<String>>,
    /// 绑定的 sandbox 配置(I07 启用)
    pub sandbox_profile_id: Option<String>,
    /// 首次登记时间
    pub first_seen_at: i64,
    /// 信任等级
    pub trust_level: TrustLevel,
}

/// UI 渲染数据(ADR 0005 §D3):单个 tool 审批卡片。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ToolApprovalCard {
    /// server id
    pub server_id: String,
    /// tool 名
    pub tool_name: String,
    /// DB 中现有的 descriptor_hash(approved 时为已批准版;首次 pin 时为首次见版)
    pub current_hash: String,
    /// 若 drifted,指向新的 hash;首次 pin 时为 None
    pub proposed_hash: Option<String>,
    /// 首次登记时间
    pub first_seen_at: i64,
    /// 批准时间(NULL = 未批准)
    pub approved_at: Option<i64>,
    /// 最近一次漂移时间
    pub last_drift_at: Option<i64>,
}

/// `check_server_command_drift` 返回的 drift 信息(ADR 0005 §D2)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandDrift {
    /// 已批准的旧 argv hash
    pub old: String,
    /// 本次 spawn 检测到的新 argv hash
    pub new: String,
}

/// V1.1:server 裸命令**解析后绝对路径**的 drift 漂移记录(ADR 0007 §I-7.1 / ADR 0005)。
/// 与 [`CommandDrift`](argv 文本 drift)**正交** —— argv 不变但解析二进制变(PATH shadow /
/// 重定位)。`old`/`new` 均为**本机绝对路径**(per-machine,非可移植)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedProgramDrift {
    /// 已 pin 的旧解析路径
    pub old: String,
    /// 本次 spawn 解析出的新路径
    pub new: String,
}

/// V1.1:`check_server_resolved_program_drift` 的三态结果。caller(Hub)据此发不同审计事件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedProgramOutcome {
    /// 解析路径与已 pin 基线一致;**或**本 server 不适用(非 Stdio / 无 `command_hash`)。无需事件。
    Unchanged,
    /// 首见:已建立本机基线 pin(不报 drift)。caller 发 `server.program_pinned` 审计。
    Pinned {
        /// 刚 pin 的本机解析路径
        resolved: String,
    },
    /// 解析路径与已 pin 基线不等 → 已写 pending,fail-closed。caller 发 `server.resolved_program_drifted`。
    Drifted(ResolvedProgramDrift),
}

/// Registry 专用错误(与 AuditError 分开以便 caller 精细分支)。
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RegistryError {
    /// server 已存在且 command_hash / descriptor_hash 不一致,
    /// 需要 I05 的 drift 流程处理;I04 直接拒绝。
    #[error("server `{server_id}` already registered with different identity hash")]
    Conflict {
        /// 冲突的 server id
        server_id: String,
    },
}

/// 从 SQLite 读出的 server profile 投影。与 `vigil_types::ServerProfile` 同字段,
/// 但 `trust_level` 已转成枚举,避免 UI 层重复解析。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredServerProfile {
    /// server id
    pub server_id: String,
    /// 传输类型
    pub transport: TransportKind,
    /// Stdio 下的 argv(完整命令)
    pub command: Option<Vec<String>>,
    /// Http 下的 URL
    pub url: Option<String>,
    /// 首次登记时间
    pub first_seen_at: i64,
    /// `sha256(JCS(command))` hex-lower
    pub command_hash: Option<String>,
    /// 聚合的 descriptor_hash
    pub descriptor_hash: Option<String>,
    /// 信任等级
    pub trust_level: TrustLevel,
    /// 关联的 sandbox 配置(I07 启用)
    pub sandbox_profile_id: Option<String>,
    /// I05:若命令漂移,指向待批准的新 argv hash
    pub pending_command_hash: Option<String>,
    /// I05:首次发现 drift 的时间
    pub last_drift_at: Option<i64>,
}

impl From<&ServerProfile> for StoredServerProfile {
    fn from(p: &ServerProfile) -> Self {
        Self {
            server_id: p.server_id.clone(),
            transport: p.transport,
            command: p.command.clone(),
            url: p.url.clone(),
            first_seen_at: p.first_seen_at,
            command_hash: p.command_hash.clone(),
            descriptor_hash: p.descriptor_hash.clone(),
            trust_level: p.trust_level,
            sandbox_profile_id: p.sandbox_profile_id.clone(),
            pending_command_hash: None,
            last_drift_at: None,
        }
    }
}

impl Ledger {
    /// 登记一个 server profile。
    ///
    /// - 若 `server_id` 不存在:插入,trust_level 按传入值(通常 `Untrusted`,待审批)
    /// - 若已存在且 command_hash 与传入一致:no-op 返回 Ok(`false` = 未新增)
    /// - 否则返回 `Conflict`(I05 会在此处接入 drift 流程)
    pub fn register_server(&self, p: &ServerProfile) -> Result<bool> {
        // MUST-FIX(Codex I05):Stdio transport 必须**同时**带 command 与 command_hash,
        // 否则 check_server_command_drift 会拿到 NULL command_hash → fail-open(等同
        // 任意 argv 都被放行)。此处入口 fail-closed 拒绝。
        if matches!(p.transport, TransportKind::Stdio)
            && (p.command.is_none() || p.command_hash.is_none())
        {
            return Err(AuditError::InvalidInput {
                reason: "stdio server profile requires both command and command_hash",
            });
        }
        // I08 MUST-FIX(ADR 0008 §D5):argv 不得含硬指纹 secret literal。
        // §4.7 要求 UI 原样展示 exact argv,因此在登记入口 fail-closed,保证任何被
        // UI 展示的 argv 都已通过 lint;secret 必须走 env_lease(I06)而非 argv。
        if let Some(argv) = &p.command {
            for elem in argv {
                if let Some(rule) = vigil_redaction::detect_hard_secret(elem) {
                    return Err(AuditError::InvalidInput {
                        reason: secret_in_argv_reason(rule),
                    });
                }
            }
        }
        let stored: StoredServerProfile = p.into();
        let existing = self.get_server(&p.server_id)?;
        if let Some(ex) = existing {
            if ex.command_hash == stored.command_hash {
                // 幂等:相同身份返回 false 表明未插入新行
                return Ok(false);
            }
            // I04 不处理 drift,直接报冲突让 caller 决定
            return Err(AuditError::RegistryConflict {
                server_id: p.server_id.clone(),
            });
        }

        let command_json = p.command.as_ref().map(serde_json::to_string).transpose()?;
        let transport_str = transport_to_str(stored.transport);
        let trust_str = trust_to_str(stored.trust_level);

        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        guard.execute(
            "INSERT INTO server_profiles
              (server_id, transport, command_json, url, first_seen_at,
               command_hash, descriptor_hash, trust_level, sandbox_profile_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                stored.server_id,
                transport_str,
                command_json,
                stored.url,
                stored.first_seen_at,
                stored.command_hash,
                stored.descriptor_hash,
                trust_str,
                stored.sandbox_profile_id,
            ],
        )?;
        Ok(true)
    }

    /// 标记 server 为已审批(把 trust_level 置为 `Limited` 以上)。
    pub fn approve_server(&self, server_id: &str, level: TrustLevel) -> Result<()> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let n = guard.execute(
            "UPDATE server_profiles SET trust_level = ?1 WHERE server_id = ?2",
            rusqlite::params![trust_to_str(level), server_id],
        )?;
        if n == 0 {
            return Err(AuditError::InvalidInput {
                reason: "server_id not found",
            });
        }
        Ok(())
    }

    /// 读一个 server profile,不存在返 None。
    pub fn get_server(&self, server_id: &str) -> Result<Option<StoredServerProfile>> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let row = guard
            .query_row(
                "SELECT server_id, transport, command_json, url, first_seen_at,
                        command_hash, descriptor_hash, trust_level, sandbox_profile_id,
                        pending_command_hash, last_drift_at
                 FROM server_profiles WHERE server_id = ?1",
                rusqlite::params![server_id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, i64>(4)?,
                        r.get::<_, Option<String>>(5)?,
                        r.get::<_, Option<String>>(6)?,
                        r.get::<_, String>(7)?,
                        r.get::<_, Option<String>>(8)?,
                        r.get::<_, Option<String>>(9)?,
                        r.get::<_, Option<i64>>(10)?,
                    ))
                },
            )
            .optional()?;
        let Some((sid, tk, cmd_json, url, first, ch, dh, tl, sp, pch, ldat)) = row else {
            return Ok(None);
        };
        let command = match cmd_json {
            Some(s) => Some(serde_json::from_str(&s)?),
            None => None,
        };
        Ok(Some(StoredServerProfile {
            server_id: sid,
            transport: parse_transport(&tk)?,
            command,
            url,
            first_seen_at: first,
            command_hash: ch,
            descriptor_hash: dh,
            trust_level: parse_trust(&tl)?,
            sandbox_profile_id: sp,
            pending_command_hash: pch,
            last_drift_at: ldat,
        }))
    }

    /// 列出所有 `trust_level >= Limited` 的 server,供 Hub 在 tools/list 时枚举。
    pub fn list_approved_servers(&self) -> Result<Vec<StoredServerProfile>> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let mut stmt = guard.prepare(
            "SELECT server_id, transport, command_json, url, first_seen_at,
                    command_hash, descriptor_hash, trust_level, sandbox_profile_id
             FROM server_profiles
             WHERE trust_level IN ('Limited', 'Trusted')
             ORDER BY first_seen_at",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, Option<String>>(8)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (sid, tk, cmd_json, url, first, ch, dh, tl, sp) = r?;
            let command = match cmd_json {
                Some(s) => Some(serde_json::from_str(&s)?),
                None => None,
            };
            out.push(StoredServerProfile {
                server_id: sid,
                transport: parse_transport(&tk)?,
                command,
                url,
                first_seen_at: first,
                command_hash: ch,
                descriptor_hash: dh,
                trust_level: parse_trust(&tl)?,
                sandbox_profile_id: sp,
                pending_command_hash: None, // list_approved_servers 不需要展示 drift 字段
                last_drift_at: None,
            });
        }
        Ok(out)
    }

    /// 更新 server 的聚合 descriptor_hash(Hub 在 tools/list 成功后调用)。
    pub fn set_descriptor_hash(&self, server_id: &str, hash: &str) -> Result<()> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let n = guard.execute(
            "UPDATE server_profiles SET descriptor_hash = ?1 WHERE server_id = ?2",
            rusqlite::params![hash, server_id],
        )?;
        if n == 0 {
            return Err(AuditError::InvalidInput {
                reason: "server_id not found",
            });
        }
        Ok(())
    }

    // -------- I04 per-tool descriptor pinning (ADR 0004 §D6) --------

    /// tool descriptor 的 pin + drift 检测(ADR 0005 §D1 合并 I04 版本)。
    ///
    /// 语义:
    /// - 首次见:insert,`approved_at = NULL`,`descriptor_hash = last_seen_hash = hash`
    ///   返 `PinOutcome::FirstSeen`
    /// - 已有同 hash:刷新 `last_seen_at / last_seen_hash`,返 `PinOutcome::Unchanged`
    /// - 已有但新 hash 不等:设 `pending_hash = new_hash`(仅首次 drift 时 set
    ///   `last_drift_at = now`);刷新 last_seen,返 `PinOutcome::Drifted { old, new }`
    pub fn pin_tool_descriptor(
        &self,
        server_id: &str,
        tool_name: &str,
        descriptor_hash: &str,
    ) -> Result<PinOutcome> {
        // VIGIL-SEC-004:拒绝**空** descriptor_hash 入库 —— 空 pin 会与空 call hash 相等而经
        // oracle 的 `h == hash` 走 ApprovedStable 自动放行(audit 头号关注的具体利用)。
        // 运行时的完整格式 fail-closed 由 oracle 端 `is_valid_descriptor_hash`(非 64-hex incoming
        // → FirstSeen)承担,故此处只拒空,不强制 64-hex —— 避免破坏用短假 hash 测状态机的单测。
        if descriptor_hash.is_empty() {
            return Err(AuditError::InvalidInput {
                reason: "descriptor_hash must not be empty",
            });
        }
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let now = crate::ledger::now_secs();

        // MUST-FIX(Codex I05):除 descriptor_hash/pending_hash 外还要读 approved_at,
        // 因为 FirstSeen(approved_at IS NULL)与 Approved(approved_at IS NOT NULL)
        // 的 "hash 不等" 语义完全不同:
        //   FirstSeen + 新 hash   → 直接更新首次候选,**不算** drift(re_approved 不应发)
        //   Approved + 新 hash    → 真正的 drift,走 pending_hash + last_drift_at 流程
        let existing: Option<(String, Option<String>, Option<i64>)> = guard
            .query_row(
                "SELECT descriptor_hash, pending_hash, approved_at FROM tool_descriptors
                 WHERE server_id = ?1 AND tool_name = ?2",
                rusqlite::params![server_id, tool_name],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .optional()?;

        match existing {
            None => {
                guard.execute(
                    "INSERT INTO tool_descriptors
                       (server_id, tool_name, descriptor_hash, first_seen_at, approved_at,
                        last_seen_hash, last_seen_at)
                     VALUES (?1, ?2, ?3, ?4, NULL, ?3, ?4)",
                    rusqlite::params![server_id, tool_name, descriptor_hash, now],
                )?;
                Ok(PinOutcome::FirstSeen)
            }
            Some((current, prev_pending, _approved)) if current == descriptor_hash => {
                // Codex R2 MUST-FIX:上游若先 drift 到新 hash 再回退到已批准版本,
                // 必须清理 pending_hash / last_drift_at,否则账本会停在"伪 drift"状态,
                // list_drifted_tools 持续误报,用户可能批准一个已经不存在的旧候选。
                if prev_pending.is_some() {
                    guard.execute(
                        "UPDATE tool_descriptors
                         SET last_seen_hash = ?1, last_seen_at = ?2,
                             pending_hash = NULL, last_drift_at = NULL
                         WHERE server_id = ?3 AND tool_name = ?4",
                        rusqlite::params![descriptor_hash, now, server_id, tool_name],
                    )?;
                } else {
                    guard.execute(
                        "UPDATE tool_descriptors
                         SET last_seen_hash = ?1, last_seen_at = ?2
                         WHERE server_id = ?3 AND tool_name = ?4",
                        rusqlite::params![descriptor_hash, now, server_id, tool_name],
                    )?;
                }
                Ok(PinOutcome::Unchanged)
            }
            Some((_current, _prev_pending, None)) => {
                // MUST-FIX(Codex I05):**未批准**的 FirstSeen 被改 hash,
                // 不算 drift —— 直接覆盖首次候选,保持 approved_at=NULL。
                // 此状态下 list_pending_tool_approvals 仍会把它列出待批准。
                guard.execute(
                    "UPDATE tool_descriptors
                     SET descriptor_hash = ?1, last_seen_hash = ?1, last_seen_at = ?2,
                         pending_hash = NULL, last_drift_at = NULL
                     WHERE server_id = ?3 AND tool_name = ?4",
                    rusqlite::params![descriptor_hash, now, server_id, tool_name],
                )?;
                Ok(PinOutcome::FirstSeen)
            }
            Some((current, prev_pending, Some(_approved_at))) => {
                // 真正的 drift(已批准后 hash 变)
                let set_drift_at = prev_pending.is_none();
                if set_drift_at {
                    guard.execute(
                        "UPDATE tool_descriptors
                         SET pending_hash = ?1, last_seen_hash = ?1, last_seen_at = ?2,
                             last_drift_at = ?2
                         WHERE server_id = ?3 AND tool_name = ?4",
                        rusqlite::params![descriptor_hash, now, server_id, tool_name],
                    )?;
                } else {
                    guard.execute(
                        "UPDATE tool_descriptors
                         SET pending_hash = ?1, last_seen_hash = ?1, last_seen_at = ?2
                         WHERE server_id = ?3 AND tool_name = ?4",
                        rusqlite::params![descriptor_hash, now, server_id, tool_name],
                    )?;
                }
                Ok(PinOutcome::Drifted {
                    old: current,
                    new: descriptor_hash.to_string(),
                })
            }
        }
    }

    /// 显式批准一条首次 pinned 的 tool descriptor(approved_at 从 NULL → now)。
    ///
    /// I08 UI 在用户点击 Approve 后调用;`HubConfig.auto_approve_first_seen_tools = true`
    /// 的**开发模式**下由 Hub 立刻调用。
    pub fn approve_tool_descriptor(&self, server_id: &str, tool_name: &str) -> Result<()> {
        {
            let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
            let now = crate::ledger::now_secs();
            let n = guard.execute(
                "UPDATE tool_descriptors
                 SET approved_at = ?1
                 WHERE server_id = ?2 AND tool_name = ?3 AND approved_at IS NULL",
                rusqlite::params![now, server_id, tool_name],
            )?;
            if n == 0 {
                return Err(AuditError::InvalidInput {
                    reason: "tool descriptor not found or already approved",
                });
            }
        } // 释放 conn 锁 —— append_event_internal 会再次 lock,避免死锁
        let _ = self.append_event_internal(
            "system",
            "tool_approval.first_approved",
            &serde_json::json!({"server_id": server_id, "tool_name": tool_name}),
            Some(&format!(
                "tool_approval server:{server_id} tool:{tool_name}"
            )),
        );
        Ok(())
    }

    /// 接受 drift:把 `pending_hash` 作为新的 `descriptor_hash`,清 pending。
    /// ADR 0005 §D4;I08 UI 的"接受新版本"按钮调用。
    pub fn approve_tool_descriptor_to(
        &self,
        server_id: &str,
        tool_name: &str,
        new_hash: &str,
    ) -> Result<()> {
        {
            let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
            let now = crate::ledger::now_secs();
            // MUST-FIX(Codex I05):加 `approved_at IS NOT NULL` —— 确保本 API 只能对
            // **已批准后漂移** 的 descriptor 生效,FirstSeen 阶段的"首次批准"必须走
            // `approve_tool_descriptor`(无歧义审计事件类型)。
            let n = guard.execute(
                "UPDATE tool_descriptors
                 SET descriptor_hash = ?1, approved_at = ?2,
                     pending_hash = NULL, last_drift_at = NULL
                 WHERE server_id = ?3 AND tool_name = ?4
                   AND pending_hash = ?1 AND approved_at IS NOT NULL",
                rusqlite::params![new_hash, now, server_id, tool_name],
            )?;
            if n == 0 {
                return Err(AuditError::InvalidInput {
                    reason: "no matching drifted descriptor to re-approve (caller must first approve_tool_descriptor for FirstSeen)",
                });
            }
        }
        let _ = self.append_event_internal(
            "system",
            "tool_approval.re_approved",
            &serde_json::json!({
                "server_id": server_id, "tool_name": tool_name, "new_hash": new_hash,
            }),
            Some(&format!(
                "tool_approval re_approved server:{server_id} tool:{tool_name}"
            )),
        );
        Ok(())
    }

    /// 拒绝 drift:保留旧 hash,清 pending。ADR 0005 §D4。
    /// 下次 tools/list 若上游仍返新 hash,会再次触发 pending(UX 上反复提示)。
    pub fn reject_tool_descriptor_drift(&self, server_id: &str, tool_name: &str) -> Result<()> {
        {
            let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
            let n = guard.execute(
                "UPDATE tool_descriptors
                 SET pending_hash = NULL, last_drift_at = NULL
                 WHERE server_id = ?1 AND tool_name = ?2 AND pending_hash IS NOT NULL",
                rusqlite::params![server_id, tool_name],
            )?;
            if n == 0 {
                return Err(AuditError::InvalidInput {
                    reason: "no drift pending on this descriptor",
                });
            }
        }
        let _ = self.append_event_internal(
            "system",
            "tool_approval.drift_rejected",
            &serde_json::json!({"server_id": server_id, "tool_name": tool_name}),
            Some(&format!(
                "tool_approval drift_rejected server:{server_id} tool:{tool_name}"
            )),
        );
        Ok(())
    }

    /// Server command drift 检测:将本次 spawn 的 argv 与已批准的 command_hash 比较。
    /// 不等时写 pending_command_hash + pending_command_json + last_drift_at,返
    /// `Some(drift_event)`;相等或未登记返 None。
    ///
    /// **Codex R1 BLOCKER 修复**:同时持久化**新 argv 文本**(`pending_command_json`),
    /// 让 `approve_server_command_drift` 之后 UI 能按 §4.7 展示 exact new argv。
    /// `new_argv` 必须就是算出 `new_argv_hash` 的那串 argv;两者不一致返 `InvalidInput`。
    pub fn check_server_command_drift(
        &self,
        server_id: &str,
        new_argv: &[String],
        new_argv_hash: &str,
    ) -> Result<Option<CommandDrift>> {
        // 一致性自检:caller 给的 hash 必须 = JCS(new_argv) 的 sha256
        let recomputed = argv_hash(new_argv);
        if recomputed != new_argv_hash {
            return Err(AuditError::InvalidInput {
                reason: "new_argv_hash does not match sha256(JCS(new_argv))",
            });
        }
        // I08 argv-secret-in-argv lint(§D5):pending argv 也不得含硬指纹
        for elem in new_argv {
            if let Some(rule) = vigil_redaction::detect_hard_secret(elem) {
                return Err(AuditError::InvalidInput {
                    reason: secret_in_argv_reason(rule),
                });
            }
        }
        let argv_json = serde_json::to_string(new_argv)?;

        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let existing: Option<(Option<String>, Option<String>)> = guard
            .query_row(
                "SELECT command_hash, pending_command_hash FROM server_profiles
                 WHERE server_id = ?1",
                rusqlite::params![server_id],
                |r| {
                    Ok((
                        r.get::<_, Option<String>>(0)?,
                        r.get::<_, Option<String>>(1)?,
                    ))
                },
            )
            .optional()?;
        let Some((current, prev_pending)) = existing else {
            return Ok(None); // 未登记 → 让 register_server 的常规路径处理
        };
        match current {
            Some(c) if c == new_argv_hash => {
                // Codex R2(I05)MUST-FIX:回退到已批准 argv 时清 pending
                if prev_pending.is_some() {
                    guard.execute(
                        "UPDATE server_profiles
                         SET pending_command_hash = NULL, pending_command_json = NULL,
                             last_drift_at = NULL
                         WHERE server_id = ?1",
                        rusqlite::params![server_id],
                    )?;
                }
                Ok(None)
            }
            Some(c) => {
                let now = crate::ledger::now_secs();
                let set_drift_at = prev_pending.is_none();
                if set_drift_at {
                    guard.execute(
                        "UPDATE server_profiles
                         SET pending_command_hash = ?1, pending_command_json = ?2,
                             last_drift_at = ?3
                         WHERE server_id = ?4",
                        rusqlite::params![new_argv_hash, argv_json, now, server_id],
                    )?;
                } else {
                    guard.execute(
                        "UPDATE server_profiles
                         SET pending_command_hash = ?1, pending_command_json = ?2
                         WHERE server_id = ?3",
                        rusqlite::params![new_argv_hash, argv_json, server_id],
                    )?;
                }
                Ok(Some(CommandDrift {
                    old: c,
                    new: new_argv_hash.to_string(),
                }))
            }
            None => Ok(None), // 已登记但无 command_hash(Http server 等)
        }
    }

    /// 接受 command drift:把 pending 作为新 command_hash + 把 pending_command_json
    /// 作为新 command_json(Codex R1 BLOCKER:保证 §4.7 exact argv 可见)。
    pub fn approve_server_command_drift(&self, server_id: &str) -> Result<()> {
        {
            let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
            let n = guard.execute(
                "UPDATE server_profiles
                 SET command_hash = pending_command_hash,
                     command_json = COALESCE(pending_command_json, command_json),
                     pending_command_hash = NULL,
                     pending_command_json = NULL,
                     last_drift_at = NULL
                 WHERE server_id = ?1 AND pending_command_hash IS NOT NULL",
                rusqlite::params![server_id],
            )?;
            if n == 0 {
                return Err(AuditError::InvalidInput {
                    reason: "server has no pending command drift",
                });
            }
        }
        let _ = self.append_event_internal(
            "system",
            "server.command_re_approved",
            &serde_json::json!({"server_id": server_id}),
            Some(&format!("server command_re_approved {server_id}")),
        );
        Ok(())
    }

    /// 拒绝 command drift:保留旧 command_hash,清 pending(含 argv JSON)。
    pub fn reject_server_command_drift(&self, server_id: &str) -> Result<()> {
        {
            let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
            let n = guard.execute(
                "UPDATE server_profiles
                 SET pending_command_hash = NULL, pending_command_json = NULL,
                     last_drift_at = NULL
                 WHERE server_id = ?1 AND pending_command_hash IS NOT NULL",
                rusqlite::params![server_id],
            )?;
            if n == 0 {
                return Err(AuditError::InvalidInput {
                    reason: "server has no pending command drift",
                });
            }
        }
        let _ = self.append_event_internal(
            "system",
            "server.command_drift_rejected",
            &serde_json::json!({"server_id": server_id}),
            Some(&format!("server command_drift_rejected {server_id}")),
        );
        Ok(())
    }

    // -------- V1.1 resolved-program drift(ADR 0007 §I-7.1 / ADR 0005 第二独立维度)--------

    /// V1.1:检查 server 裸命令**解析后绝对路径**是否漂移。与 [`check_server_command_drift`]
    /// (argv 文本)正交:argv 不变但解析二进制变(PATH shadow / 重定位)时触发。
    ///
    /// **护栏**(spike §3.2,Codex R1 §4 答 2):
    /// - 仅对**已有有效 `command_hash` 的 Stdio 行**建立/比较 resolved 基线(Http / 无 argv pin 不适用)
    /// - 未 pin(`resolved_program_path IS NULL`,legacy 或首见)→ **建立本机基线**(不报 drift),
    ///   caller(Hub)须保证本调用在 spawn **之前**(护栏 2)
    /// - 已 pin 且一致 → `Unchanged`(若有残留 pending 则清,镜像 command drift 回退语义)
    /// - 已 pin 且不等 → 写 `pending_resolved_program_path` + 返 `Drifted`(fail-closed)
    ///
    /// `resolved_path` 须是 caller 用宿主 PATH 解析出的**本机绝对路径**(per-machine,非可移植)。
    pub fn check_server_resolved_program_drift(
        &self,
        server_id: &str,
        resolved_path: &str,
    ) -> Result<ResolvedProgramOutcome> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let existing: Option<(Option<String>, Option<String>, Option<String>)> = guard
            .query_row(
                "SELECT command_hash, resolved_program_path, pending_resolved_program_path
                 FROM server_profiles WHERE server_id = ?1",
                rusqlite::params![server_id],
                |r| {
                    Ok((
                        r.get::<_, Option<String>>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((command_hash, pinned, prev_pending)) = existing else {
            return Ok(ResolvedProgramOutcome::Unchanged); // 未登记 → 不适用
        };
        // 护栏 1:仅对有有效 command_hash 的 Stdio 行建立/比较 resolved 基线
        if command_hash.is_none() {
            return Ok(ResolvedProgramOutcome::Unchanged); // Http / 无 argv pin → 不适用
        }
        match pinned {
            None => {
                // 首见:建立本机基线 pin(护栏 2:caller 保证在 spawn 之前)
                guard.execute(
                    "UPDATE server_profiles SET resolved_program_path = ?1 WHERE server_id = ?2",
                    rusqlite::params![resolved_path, server_id],
                )?;
                Ok(ResolvedProgramOutcome::Pinned {
                    resolved: resolved_path.to_string(),
                })
            }
            Some(p) if p == resolved_path => {
                // 回退到已 pin 路径:清残留 pending(镜像 command drift 回退清 pending 语义)
                if prev_pending.is_some() {
                    guard.execute(
                        "UPDATE server_profiles SET pending_resolved_program_path = NULL
                         WHERE server_id = ?1",
                        rusqlite::params![server_id],
                    )?;
                }
                Ok(ResolvedProgramOutcome::Unchanged)
            }
            Some(p) => {
                guard.execute(
                    "UPDATE server_profiles SET pending_resolved_program_path = ?1
                     WHERE server_id = ?2",
                    rusqlite::params![resolved_path, server_id],
                )?;
                Ok(ResolvedProgramOutcome::Drifted(ResolvedProgramDrift {
                    old: p,
                    new: resolved_path.to_string(),
                }))
            }
        }
    }

    /// V1.1:接受 resolved-program drift(pending 解析路径 → `resolved_program_path` 基线)。
    pub fn approve_server_resolved_program_drift(&self, server_id: &str) -> Result<()> {
        {
            let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
            let n = guard.execute(
                "UPDATE server_profiles
                 SET resolved_program_path = pending_resolved_program_path,
                     pending_resolved_program_path = NULL
                 WHERE server_id = ?1 AND pending_resolved_program_path IS NOT NULL",
                rusqlite::params![server_id],
            )?;
            if n == 0 {
                return Err(AuditError::InvalidInput {
                    reason: "server has no pending resolved-program drift",
                });
            }
        }
        let _ = self.append_event_internal(
            "system",
            "server.resolved_program_re_approved",
            &serde_json::json!({"server_id": server_id}),
            Some(&format!("server resolved_program_re_approved {server_id}")),
        );
        Ok(())
    }

    /// V1.1:拒绝 resolved-program drift(保留旧基线,清 pending)。
    pub fn reject_server_resolved_program_drift(&self, server_id: &str) -> Result<()> {
        {
            let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
            let n = guard.execute(
                "UPDATE server_profiles SET pending_resolved_program_path = NULL
                 WHERE server_id = ?1 AND pending_resolved_program_path IS NOT NULL",
                rusqlite::params![server_id],
            )?;
            if n == 0 {
                return Err(AuditError::InvalidInput {
                    reason: "server has no pending resolved-program drift",
                });
            }
        }
        let _ = self.append_event_internal(
            "system",
            "server.resolved_program_drift_rejected",
            &serde_json::json!({"server_id": server_id}),
            Some(&format!(
                "server resolved_program_drift_rejected {server_id}"
            )),
        );
        Ok(())
    }

    // -------- I05 list_* 查询 API(供 I08 UI)--------

    /// 列出 trust_level = Untrusted 的 server —— 等待 UI 批准首次接入。
    pub fn list_pending_server_onboardings(&self) -> Result<Vec<ServerOnboardingData>> {
        self.list_servers_by_trust(TrustLevel::Untrusted)
    }

    /// 列出 pending_command_hash IS NOT NULL 的 server。
    pub fn list_drifted_servers(&self) -> Result<Vec<ServerOnboardingData>> {
        self.list_servers_where("pending_command_hash IS NOT NULL")
    }

    /// 查单条 server 的 onboarding 数据(UI 展示用)。
    pub fn get_onboarding_data(&self, server_id: &str) -> Result<Option<ServerOnboardingData>> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let row = guard
            .query_row(
                "SELECT server_id, transport, command_json, url, first_seen_at,
                        command_hash, pending_command_hash, trust_level, sandbox_profile_id
                 FROM server_profiles WHERE server_id = ?1",
                rusqlite::params![server_id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, i64>(4)?,
                        r.get::<_, Option<String>>(5)?,
                        r.get::<_, Option<String>>(6)?,
                        r.get::<_, String>(7)?,
                        r.get::<_, Option<String>>(8)?,
                    ))
                },
            )
            .optional()?;
        let Some((sid, tk, cmd_json, url, first, ch, pch, tl, sp)) = row else {
            return Ok(None);
        };
        let command = match cmd_json {
            Some(s) => Some(serde_json::from_str::<Vec<String>>(&s)?),
            None => None,
        };
        // I06:从 tool_secret_bindings 聚合 env key 清单
        let env_keys = Self::server_requested_env_keys(&guard, &sid)?;
        Ok(Some(ServerOnboardingData {
            server_id: sid,
            transport: parse_transport(&tk)?,
            command,
            url,
            first_seen_at: first,
            command_hash: ch,
            pending_command_hash: pch,
            requested_env_keys: env_keys,
            sandbox_profile_id: sp,
            trust_level: parse_trust(&tl)?,
        }))
    }

    /// 列出 approved_at IS NULL 的 tool descriptor —— 首次批准卡片。
    pub fn list_pending_tool_approvals(&self) -> Result<Vec<ToolApprovalCard>> {
        self.list_tool_cards_where("approved_at IS NULL")
    }

    /// 列出 pending_hash IS NOT NULL 的 tool descriptor —— drift 卡片。
    pub fn list_drifted_tools(&self) -> Result<Vec<ToolApprovalCard>> {
        self.list_tool_cards_where("pending_hash IS NOT NULL")
    }

    // -------- 内部辅助 --------

    fn list_servers_by_trust(&self, level: TrustLevel) -> Result<Vec<ServerOnboardingData>> {
        self.list_servers_where_with("trust_level = ?1", rusqlite::params![trust_to_str(level)])
    }

    fn list_servers_where(&self, where_clause: &str) -> Result<Vec<ServerOnboardingData>> {
        self.list_servers_where_with(where_clause, rusqlite::params![])
    }

    fn list_servers_where_with<P: rusqlite::Params>(
        &self,
        where_clause: &str,
        params: P,
    ) -> Result<Vec<ServerOnboardingData>> {
        let sql = format!(
            "SELECT server_id, transport, command_json, url, first_seen_at,
                    command_hash, pending_command_hash, trust_level, sandbox_profile_id
             FROM server_profiles WHERE {where_clause}
             ORDER BY first_seen_at"
        );
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let mut stmt = guard.prepare(&sql)?;
        let rows = stmt.query_map(params, |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, Option<String>>(8)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (sid, tk, cmd_json, url, first, ch, pch, tl, sp) = r?;
            let command = match cmd_json {
                Some(s) => Some(serde_json::from_str::<Vec<String>>(&s)?),
                None => None,
            };
            let env_keys = Self::server_requested_env_keys(&guard, &sid)?;
            out.push(ServerOnboardingData {
                server_id: sid,
                transport: parse_transport(&tk)?,
                command,
                url,
                first_seen_at: first,
                command_hash: ch,
                pending_command_hash: pch,
                requested_env_keys: env_keys,
                sandbox_profile_id: sp,
                trust_level: parse_trust(&tl)?,
            });
        }
        Ok(out)
    }

    fn list_tool_cards_where(&self, where_clause: &str) -> Result<Vec<ToolApprovalCard>> {
        let sql = format!(
            "SELECT server_id, tool_name, descriptor_hash, pending_hash,
                    first_seen_at, approved_at, last_drift_at
             FROM tool_descriptors WHERE {where_clause}
             ORDER BY first_seen_at"
        );
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let mut stmt = guard.prepare(&sql)?;
        let rows = stmt.query_map([], |r| {
            Ok(ToolApprovalCard {
                server_id: r.get(0)?,
                tool_name: r.get(1)?,
                current_hash: r.get(2)?,
                proposed_hash: r.get(3)?,
                first_seen_at: r.get(4)?,
                approved_at: r.get(5)?,
                last_drift_at: r.get(6)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// 查询一条已登记的 (server, tool) → hash。
    pub fn get_pinned_tool_hash(&self, server_id: &str, tool_name: &str) -> Result<Option<String>> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let r = guard
            .query_row(
                "SELECT descriptor_hash FROM tool_descriptors
                 WHERE server_id = ?1 AND tool_name = ?2 AND approved_at IS NOT NULL",
                rusqlite::params![server_id, tool_name],
                |r| r.get::<_, String>(0),
            )
            .optional()?;
        Ok(r)
    }

    // -------- I06 Secret refs + tool-secret bindings(ADR 0006 §3) --------

    /// 登记一个 `secret_ref` alias —— **真实值不在此处**,只存 metadata + fingerprint。
    ///
    /// `fingerprint = SHA-256("vigil.secret_ref.fp.v1" || normalized_secret_ref)`
    /// (ADR 0006 §D5,避免把真实 value 的派生物写入 DB)。
    pub fn register_secret_ref(
        &self,
        secret_ref: &str,
        display_name: &str,
        provider: &str,
    ) -> Result<bool> {
        if !secret_ref.starts_with("secret://") {
            return Err(AuditError::InvalidInput {
                reason: "secret_ref must start with 'secret://'",
            });
        }
        let fp = secret_ref_fingerprint(secret_ref);
        let now = crate::ledger::now_secs();
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let changed = guard.execute(
            "INSERT OR IGNORE INTO secret_refs
               (secret_ref, display_name, provider, fingerprint, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![secret_ref, display_name, provider, fp, now],
        )?;
        Ok(changed > 0)
    }

    /// 列出所有已登记的 secret alias(metadata,不含值)。
    pub fn list_secret_refs(&self) -> Result<Vec<SecretRefEntry>> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let mut stmt = guard.prepare(
            "SELECT secret_ref, display_name, provider, fingerprint, created_at, last_used_at
             FROM secret_refs ORDER BY created_at",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(SecretRefEntry {
                secret_ref: r.get(0)?,
                display_name: r.get(1)?,
                provider: r.get(2)?,
                fingerprint: r.get(3)?,
                created_at: r.get(4)?,
                last_used_at: r.get(5)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// 每次 mint 后更新 `last_used_at`(供 audit / UI 排序)。
    pub fn touch_secret_ref(&self, secret_ref: &str) -> Result<()> {
        let now = crate::ledger::now_secs();
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        guard.execute(
            "UPDATE secret_refs SET last_used_at = ?1 WHERE secret_ref = ?2",
            rusqlite::params![now, secret_ref],
        )?;
        Ok(())
    }

    /// 绑定 `(server, tool, secret_ref, injection_method)` 四元组。`tool_name='*'`
    /// 表示 server 级绑定(全部 tool 可用)。
    pub fn bind_tool_secret(&self, b: &ToolSecretBinding) -> Result<()> {
        if !b.secret_ref.starts_with("secret://") {
            return Err(AuditError::InvalidInput {
                reason: "binding.secret_ref must start with 'secret://'",
            });
        }
        // Codex R1 MUST-FIX:I06 fail-closed —— 只允许 ChildEnv,其他注入方式直接拒绝存入。
        // 避免 resolve_child_env_bindings 静默忽略 + server_requested_env_keys 误报 Some([])。
        if b.injection_method != "ChildEnv" {
            return Err(AuditError::InvalidInput {
                reason:
                    "I06 only supports injection_method='ChildEnv'; other methods delayed to I07+",
            });
        }
        let Some(env_key) = b.env_var_name.as_ref() else {
            return Err(AuditError::InvalidInput {
                reason: "ChildEnv binding requires env_var_name",
            });
        };
        // Codex R1(I07)MUST-FIX 2:Windows 保留系统 env(大小写不敏感)不得被 binding 占用,
        // 否则 native runner 的注入顺序对 caller 不可预期。列表必须与
        // `vigil_runner::RESERVED_SYSTEM_ENV_KEYS` 保持一致 —— 跨 crate 漂移由 vigil-lease
        // 的 reserved_env_keys_in_sync 测试守门。
        if is_reserved_env_key_name(env_key) {
            return Err(AuditError::InvalidInput {
                reason: "env_var_name collides with reserved system env key",
            });
        }
        let now = crate::ledger::now_secs();
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        guard.execute(
            "INSERT OR REPLACE INTO tool_secret_bindings
               (server_id, tool_name, secret_ref, injection_method, env_var_name, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                b.server_id,
                b.tool_name,
                b.secret_ref,
                b.injection_method,
                b.env_var_name,
                now,
            ],
        )?;
        Ok(())
    }

    /// 列出一个 server 下全部绑定。`include_wildcard=true` 时 `tool_name='*'` 也会返回。
    pub fn list_tool_secret_bindings(&self, server_id: &str) -> Result<Vec<ToolSecretBinding>> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let mut stmt = guard.prepare(
            "SELECT server_id, tool_name, secret_ref, injection_method, env_var_name
             FROM tool_secret_bindings WHERE server_id = ?1
             ORDER BY tool_name, secret_ref",
        )?;
        let rows = stmt.query_map(rusqlite::params![server_id], |r| {
            Ok(ToolSecretBinding {
                server_id: r.get(0)?,
                tool_name: r.get(1)?,
                secret_ref: r.get(2)?,
                injection_method: r.get(3)?,
                env_var_name: r.get(4)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// 查某个 `(server, tool)` 下需要注入的 ChildEnv 绑定。
    /// 既匹配精确 tool,也匹配 `'*'` wildcard server 级绑定。
    pub fn resolve_child_env_bindings(
        &self,
        server_id: &str,
        tool_name: &str,
    ) -> Result<Vec<ToolSecretBinding>> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let mut stmt = guard.prepare(
            "SELECT server_id, tool_name, secret_ref, injection_method, env_var_name
             FROM tool_secret_bindings
             WHERE server_id = ?1
               AND injection_method = 'ChildEnv'
               AND (tool_name = ?2 OR tool_name = '*')
             ORDER BY tool_name, secret_ref",
        )?;
        let rows = stmt.query_map(rusqlite::params![server_id, tool_name], |r| {
            Ok(ToolSecretBinding {
                server_id: r.get(0)?,
                tool_name: r.get(1)?,
                secret_ref: r.get(2)?,
                injection_method: r.get(3)?,
                env_var_name: r.get(4)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// 聚合某个 server 下 ChildEnv 绑定的 env_var_name(去重排序)。
    /// 返 Option 以保留 I05 三态语义(见 `ServerOnboardingData.requested_env_keys` 注释)。
    ///
    /// 规则(ADR 0006 §D6):
    /// - 表中无此 server 任何条目 → `None`(=未声明,UI 展示 "待 lease 分析")
    /// - 有条目但 ChildEnv 无 env_var_name → `Some(vec![])`(=明确无 env 需求)
    /// - 有 ChildEnv env_var_name → `Some(dedup_sorted)`
    fn server_requested_env_keys(
        guard: &rusqlite::Connection,
        server_id: &str,
    ) -> Result<Option<Vec<String>>> {
        // 先看是否存在任何绑定(含非 ChildEnv),用于区分 "未声明" vs "明确无需求"
        let any_binding: i64 = guard.query_row(
            "SELECT COUNT(*) FROM tool_secret_bindings WHERE server_id = ?1",
            rusqlite::params![server_id],
            |r| r.get(0),
        )?;
        if any_binding == 0 {
            return Ok(None);
        }
        let mut stmt = guard.prepare(
            "SELECT DISTINCT env_var_name FROM tool_secret_bindings
             WHERE server_id = ?1 AND injection_method = 'ChildEnv' AND env_var_name IS NOT NULL
             ORDER BY env_var_name",
        )?;
        let rows = stmt.query_map(rusqlite::params![server_id], |r| r.get::<_, String>(0))?;
        let mut keys = Vec::new();
        for r in rows {
            keys.push(r?);
        }
        Ok(Some(keys))
    }

    // -------- I08 Sandbox profile 持久化(ADR 0008 §D6) --------

    /// 插入或覆盖 sandbox profile。
    ///
    /// **Codex R1 MUST-FIX 3**:Ledger 层**自证** —— caller 传入原始 profile_json,
    /// Ledger 内部:
    /// 1. `serde_json::from_str::<Value>` 解析
    /// 2. **校验** `env_inherit == false`(AGENTS §7 fail-closed)
    /// 3. `serde_jcs::to_string(&Value)` 重新规范化(抛弃 caller 的空格 / 字段序)
    /// 4. `sha256(canonical)` 计算稳定 hash
    /// 5. 存 canonical JSON + hash
    ///
    /// 返回 `(inserted, profile_hash)`:`inserted=true` 首次插入;Ledger 内部算出的 hash。
    pub fn upsert_sandbox_profile(
        &self,
        profile_id: &str,
        profile_json: &str,
    ) -> Result<SandboxProfileUpsertResult> {
        if profile_id.is_empty() {
            return Err(AuditError::InvalidInput {
                reason: "profile_id must not be empty",
            });
        }
        // 1-3:parse → validate → canonicalize
        let v: serde_json::Value =
            serde_json::from_str(profile_json).map_err(|_| AuditError::InvalidInput {
                reason: "sandbox_profile_json_parse_failed",
            })?;
        let env_inherit =
            v.get("env_inherit")
                .and_then(|x| x.as_bool())
                .ok_or(AuditError::InvalidInput {
                    reason: "sandbox_profile_missing_env_inherit",
                })?;
        if env_inherit {
            return Err(AuditError::InvalidInput {
                reason: "sandbox_profile_env_inherit_must_be_false",
            });
        }
        let canonical = serde_jcs::to_string(&v).map_err(|_| AuditError::InvalidInput {
            reason: "sandbox_profile_jcs_failed",
        })?;
        // 4:hash
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(canonical.as_bytes());
        let profile_hash = hex::encode(h.finalize());

        let now = crate::ledger::now_secs();
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let existing: Option<i64> = guard
            .query_row(
                "SELECT 1 FROM sandbox_profiles WHERE profile_id = ?1",
                rusqlite::params![profile_id],
                |r| r.get(0),
            )
            .optional()?;
        let inserted = if existing.is_some() {
            guard.execute(
                "UPDATE sandbox_profiles
                 SET profile_json = ?1, profile_hash = ?2, updated_at = ?3
                 WHERE profile_id = ?4",
                rusqlite::params![canonical, profile_hash, now, profile_id],
            )?;
            false
        } else {
            guard.execute(
                "INSERT INTO sandbox_profiles
                   (profile_id, profile_json, profile_hash, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?4)",
                rusqlite::params![profile_id, canonical, profile_hash, now],
            )?;
            true
        };
        Ok(SandboxProfileUpsertResult {
            inserted,
            profile_hash,
        })
    }

    /// 按 id 读出 sandbox profile 的原始 JSON + hash。
    pub fn get_sandbox_profile(&self, profile_id: &str) -> Result<Option<SandboxProfileRow>> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        guard
            .query_row(
                "SELECT profile_id, profile_json, profile_hash, created_at, updated_at
                 FROM sandbox_profiles WHERE profile_id = ?1",
                rusqlite::params![profile_id],
                |r| {
                    Ok(SandboxProfileRow {
                        profile_id: r.get(0)?,
                        profile_json: r.get(1)?,
                        profile_hash: r.get(2)?,
                        created_at: r.get(3)?,
                        updated_at: r.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// 列出所有 sandbox profiles。
    pub fn list_sandbox_profiles(&self) -> Result<Vec<SandboxProfileRow>> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let mut stmt = guard.prepare(
            "SELECT profile_id, profile_json, profile_hash, created_at, updated_at
             FROM sandbox_profiles ORDER BY created_at",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(SandboxProfileRow {
                profile_id: r.get(0)?,
                profile_json: r.get(1)?,
                profile_hash: r.get(2)?,
                created_at: r.get(3)?,
                updated_at: r.get(4)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// 绑定 `server_profiles.sandbox_profile_id`;`profile_id=None` 表示解绑。
    /// I05 以前该字段是占位,I08 起真正消费。
    pub fn bind_server_sandbox_profile(
        &self,
        server_id: &str,
        profile_id: Option<&str>,
    ) -> Result<()> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        // 若 profile_id 非 None 则校验 profile 存在(fail-closed:避免 dangling FK)
        if let Some(pid) = profile_id {
            let exists: Option<i64> = guard
                .query_row(
                    "SELECT 1 FROM sandbox_profiles WHERE profile_id = ?1",
                    rusqlite::params![pid],
                    |r| r.get(0),
                )
                .optional()?;
            if exists.is_none() {
                return Err(AuditError::InvalidInput {
                    reason: "sandbox profile_id does not exist",
                });
            }
        }
        let n = guard.execute(
            "UPDATE server_profiles SET sandbox_profile_id = ?1 WHERE server_id = ?2",
            rusqlite::params![profile_id, server_id],
        )?;
        if n == 0 {
            return Err(AuditError::InvalidInput {
                reason: "server_id not found",
            });
        }
        Ok(())
    }

    // -------- I10 OAuth token metadata 持久化(ADR 0010 §D4) --------

    /// 注册 / 覆盖一条 OAuth token metadata。**不**接收 token value —— value 由
    /// `vigil-lease::SecretStore` 单独存,ADR §I-10.1 要求 value 绝不进 SQLite。
    ///
    /// 每个参数都直接对应一列 SQLite 语义字段;打包成 struct 只会增加间接层
    /// (caller 要额外构造一个临时类型),不利于 call-site 可读性。
    #[allow(clippy::too_many_arguments)]
    pub fn register_oauth_token_metadata(
        &self,
        token_ref: &str,
        resource: &str,
        authorization_server: &str,
        scope_set: &[String],
        token_kind: &str,
        expires_at: Option<i64>,
        // I10b-α1(ADR 0011 §α1-D1):新必填字段 —— AS metadata 里的 `issuer`,
        // 与 `authorization_server` URL **可能**不同(差尾斜杠或 subpath)。
        // 空串视为调用方违规,fail-closed。
        issuer: &str,
    ) -> Result<()> {
        if token_ref.is_empty() {
            return Err(AuditError::InvalidInput {
                reason: "token_ref_empty",
            });
        }
        if token_kind != "access" && token_kind != "refresh" {
            return Err(AuditError::InvalidInput {
                reason: "unknown_token_kind",
            });
        }
        if issuer.is_empty() {
            return Err(AuditError::InvalidInput {
                reason: "issuer_empty",
            });
        }
        let scope_json = serde_json::to_string(scope_set)?;
        let now = crate::ledger::now_secs();

        // Finding 7(hostile review):把 metadata 安全字段绑进审计哈希链 —— 此前本行是唯一完全在
        // 链外的安全关键状态(纯 INSERT,`verify_chain` 检测不到改 issuer/AS)。**先 append 绑定事件**
        // 拿 event_id,**再**把行写入并带上该 id —— 使行**永远**携带有效绑定引用(杜绝"INSERT 后 /
        // 绑定前被 kill"的非原子窗口;若在 append 后 / INSERT 前 kill,只留一条无行引用的孤儿事件,
        // 无害且绝不被读)。读侧按**此特定 id** 取事件 + `verify_chain` 校验检测篡改(同级于账本其余
        // 状态;仅完整一致重写整条链才能绕过 —— unkeyed chain 固有限制,需外部 anchoring,hash.rs 头注)。
        let bound = self.append_event_internal(
            "system",
            crate::ledger::EVENT_TYPE_OAUTH_METADATA_BOUND,
            &serde_json::json!({
                "token_ref": token_ref,
                "resource": resource,
                "authorization_server": authorization_server,
                "issuer": issuer,
                "scope_set": scope_set,
                "token_kind": token_kind,
            }),
            None,
        )?;

        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        guard.execute(
            "INSERT INTO oauth_token_metadata
               (token_ref, resource, authorization_server, scope_set_json,
                token_kind, expires_at, created_at, issuer, binding_event_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(token_ref) DO UPDATE SET
               resource = excluded.resource,
               authorization_server = excluded.authorization_server,
               scope_set_json = excluded.scope_set_json,
               token_kind = excluded.token_kind,
               expires_at = excluded.expires_at,
               issuer = excluded.issuer,
               binding_event_id = excluded.binding_event_id",
            rusqlite::params![
                token_ref,
                resource,
                authorization_server,
                scope_json,
                token_kind,
                expires_at,
                now,
                issuer,
                bound.event_id,
            ],
        )?;
        Ok(())
    }

    /// 列 OAuth token metadata(不含 value)。Codex R1 NICE-TO-HAVE + I10.md T4。
    /// I10b-α1:新增读 `issuer` 列(legacy 行为 NULL,由 `TokenStore` 读侧 fail-closed)。
    pub fn list_oauth_token_metadata(
        &self,
    ) -> Result<Vec<vigil_http_auth_metadata::OAuthTokenMetadataRow>> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let mut stmt = guard.prepare(
            "SELECT token_ref, resource, authorization_server, scope_set_json,
                    token_kind, expires_at, created_at, issuer
             FROM oauth_token_metadata ORDER BY created_at",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Option<i64>>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, Option<String>>(7)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (token_ref, resource, authz, scope_json, kind, expires_at, created_at, issuer) = r?;
            let scope_set: Vec<String> = serde_json::from_str(&scope_json)?;
            out.push(vigil_http_auth_metadata::OAuthTokenMetadataRow {
                token_ref,
                resource,
                authorization_server: authz,
                scope_set,
                token_kind: kind,
                expires_at,
                created_at,
                issuer,
            });
        }
        Ok(out)
    }

    /// 读 token metadata(`vigil-http-auth` 路径使用)。
    pub fn get_oauth_token_metadata(
        &self,
        token_ref: &str,
    ) -> Result<Option<vigil_http_auth_metadata::OAuthTokenMetadataRow>> {
        let row = {
            let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
            guard
                .query_row(
                    "SELECT token_ref, resource, authorization_server, scope_set_json,
                        token_kind, expires_at, created_at, issuer, binding_event_id
                 FROM oauth_token_metadata WHERE token_ref = ?1",
                    rusqlite::params![token_ref],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, String>(3)?,
                            r.get::<_, String>(4)?,
                            r.get::<_, Option<i64>>(5)?,
                            r.get::<_, i64>(6)?,
                            r.get::<_, Option<String>>(7)?,
                            r.get::<_, Option<i64>>(8)?,
                        ))
                    },
                )
                .optional()?
        }; // 释放 conn 锁 —— latest_oauth_binding 会再次 lock,避免死锁
        let Some((
            tref,
            resource,
            authz,
            scope_json,
            kind,
            expires_at,
            created_at,
            issuer,
            binding_event_id,
        )) = row
        else {
            return Ok(None);
        };
        let scope_set: Vec<String> = serde_json::from_str(&scope_json)?;

        // Finding 7(hostile review):行已绑定(binding_event_id 非 NULL)→ 校验,使 OAuth metadata
        // 获得与账本其余状态**同级**的篡改可检测性:
        //  (1) `verify_chain()`:events 被 naive 删/改(未一致重写)→ 链断 → Err。
        //  (2) 按**存储的 event_id** 取**特定**绑定事件(非"取最新",杜绝攻击者 append 高 id 伪事件
        //      自动当选);事件缺失(被删)→ fail-closed。
        //  (3) 行字段与该事件 payload JCS 比对,不一致 → fail-closed(疑似行被改 issuer/AS)。
        // 合起来:naive 单点篡改被检出;仅完整一致重写整条链(unkeyed chain 固有限制,需外部
        // anchoring,hash.rs 头注)才能绕过 —— 与账本其余状态同级,非更弱。
        // binding_event_id NULL = legacy 行(本特性前 onboard / 测试 raw 插入)→ 放行(无法回溯)。
        if let Some(eid) = binding_event_id {
            // 注(hostile re-review note c,tracked LOW):verify_chain 全链 O(n),而本读路径经
            // resolve_access_token 在**每次工具调用**触发 → 长生命周期账本上 O(n²)。当前阶段账本
            // 小可忽略;规模化优化 = 只验到 binding_event_id 的**前缀**(绑定事件早,前缀有界),或
            // tail-event_hash 缓存上次 verify 结果。fail-closed 方向正确(账本被篡改即停信任),故非阻塞。
            self.verify_chain()?;
            let bound = self
                .event_payload_by_id(eid)?
                .ok_or(AuditError::InvalidInput {
                    reason: "oauth_binding_event_missing",
                })?;
            let expected = serde_json::json!({
                "token_ref": tref,
                "resource": resource,
                "authorization_server": authz,
                "issuer": issuer,
                "scope_set": scope_set,
                "token_kind": kind,
            });
            if serde_jcs::to_vec(&bound)? != serde_jcs::to_vec(&expected)? {
                return Err(AuditError::InvalidInput {
                    reason: "oauth_metadata_integrity_mismatch",
                });
            }
        }

        Ok(Some(vigil_http_auth_metadata::OAuthTokenMetadataRow {
            token_ref: tref,
            resource,
            authorization_server: authz,
            scope_set,
            token_kind: kind,
            expires_at,
            created_at,
            issuer,
        }))
    }

    /// Finding 7:按 `event_id` 取**绑定事件** payload(读侧按行存储的 `binding_event_id` 取**特定**
    /// 事件,而非"取最新" —— 杜绝攻击者 append 一条高 id 伪绑定事件自动当选)。查询额外约束
    /// `event_type = oauth.token_metadata_bound`(hostile re-review note 2):若行的 binding_event_id
    /// 被改指向**别的**事件,类型不符 → `None` → 调用方 fail-closed(意图显式 + 多一道防御)。
    /// `None` = 该 id 无匹配绑定事件(被删 / 被重指向)→ fail-closed。
    fn event_payload_by_id(&self, event_id: i64) -> Result<Option<serde_json::Value>> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let pj: Option<String> = guard
            .query_row(
                "SELECT payload_json FROM events WHERE event_id = ?1 AND event_type = ?2",
                rusqlite::params![event_id, crate::ledger::EVENT_TYPE_OAUTH_METADATA_BOUND],
                |r| r.get::<_, String>(0),
            )
            .optional()?;
        match pj {
            Some(s) => Ok(Some(serde_json::from_str(&s)?)),
            None => Ok(None),
        }
    }

    /// **仅测试用**:绕过 `register_oauth_token_metadata` 的 kind / issuer 校验,
    /// 直接写 raw 行,用于模拟"脏 SQLite 行 / 手改行 / 老数据 / legacy NULL issuer"
    /// 场景,回归 fail-closed 读路径(ADR 0010 §I-10.1 / ADR 0011 §α1-D1)。
    /// **绝不**在生产构建启用。
    ///
    /// I10b-α1 代码 R1 MUST-FIX:`issuer_raw` 为 `Option<&str>`,显式传 `None` 才写 NULL
    /// —— 不再依赖"省略列 → SQLite 默认 NULL"的 schema 行为,防止未来改
    /// `NOT NULL DEFAULT '...'` 时测试静默假绿。
    #[cfg(feature = "test-util")]
    #[allow(clippy::too_many_arguments)]
    pub fn __insert_oauth_token_metadata_raw_for_test(
        &self,
        token_ref: &str,
        resource: &str,
        authorization_server: &str,
        scope_set: &[String],
        token_kind_raw: &str,
        expires_at: Option<i64>,
        issuer_raw: Option<&str>,
    ) -> Result<()> {
        let scope_json = serde_json::to_string(scope_set)?;
        let now = crate::ledger::now_secs();
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        guard.execute(
            "INSERT INTO oauth_token_metadata
               (token_ref, resource, authorization_server, scope_set_json,
                token_kind, expires_at, created_at, issuer)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(token_ref) DO UPDATE SET
               token_kind = excluded.token_kind,
               issuer = excluded.issuer",
            rusqlite::params![
                token_ref,
                resource,
                authorization_server,
                scope_json,
                token_kind_raw,
                expires_at,
                now,
                issuer_raw,
            ],
        )?;
        Ok(())
    }
}

/// I10 DTO 子模块 —— 避免 `vigil-audit` 循环依赖 `vigil-http-auth`。
/// `OAuthTokenMetadataRow` 是 SQLite 行的 raw 投影,`vigil-http-auth::OAuthTokenMetadata`
/// 是更严格的 typed 版本(kind enum + 方法)。两边在 `store.rs` 里互转。
pub mod vigil_http_auth_metadata {
    use serde::{Deserialize, Serialize};

    /// I10 SQLite `oauth_token_metadata` 行的 raw 投影。
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct OAuthTokenMetadataRow {
        /// SecretStore key
        pub token_ref: String,
        /// 远程 MCP resource URL
        pub resource: String,
        /// AS URL
        pub authorization_server: String,
        /// scope 集合(字母排序)
        pub scope_set: Vec<String>,
        /// `"access"` / `"refresh"`
        pub token_kind: String,
        /// Unix 秒
        pub expires_at: Option<i64>,
        /// Unix 秒
        pub created_at: i64,
        /// I10b-α1:AS metadata `issuer` 字段。legacy I10a 磁盘行为 `None`,
        /// `vigil-http-auth::TokenStore` 读侧把 `None` fail-closed 为
        /// `TokenStoreError("issuer_missing_legacy_row")`(ADR 0011 §α1-D1)。
        pub issuer: Option<String>,
    }
}

/// I08 `upsert_sandbox_profile` 的返回值。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SandboxProfileUpsertResult {
    /// 是否首次插入(true = INSERT;false = UPDATE 已存在行)
    pub inserted: bool,
    /// Ledger 自行 JCS 规范化后算出的 sha256(稳定,不受 caller json 空格影响)
    pub profile_hash: String,
}

/// I08 `sandbox_profiles` 表的单行投影。`profile_json` 已是 JCS 规范化后的字符串,
/// 前端若需 typed view,可用 `serde_json::from_str::<SandboxProfile>(&profile_json)`。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SandboxProfileRow {
    /// profile id(UI 展示)
    pub profile_id: String,
    /// JCS 规范化后的 JSON(稳定字节序)
    pub profile_json: String,
    /// sha256(profile_json)hex-lower
    pub profile_hash: String,
    /// 首次插入时间
    pub created_at: i64,
    /// 最近一次 upsert 时间
    pub updated_at: i64,
}

/// I06 secret_refs 一行(metadata only,不含 value)。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SecretRefEntry {
    /// 'secret://github/repo-write' 形式的 alias
    pub secret_ref: String,
    /// 用户可读显示名
    pub display_name: String,
    /// provider 分类('github' / 'gmail' / ...)
    pub provider: String,
    /// alias 的域分离 hash
    pub fingerprint: String,
    /// 登记时间
    pub created_at: i64,
    /// 最近一次 mint 的时间
    pub last_used_at: Option<i64>,
}

/// I06 tool_secret_bindings 一行。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ToolSecretBinding {
    /// server id
    pub server_id: String,
    /// tool 名;`'*'` 表示 server 级绑定
    pub tool_name: String,
    /// 绑定的 secret alias
    pub secret_ref: String,
    /// 注入方式('ChildEnv' / 'HttpHeader' / 'Pipe' / 'TempFile')
    pub injection_method: String,
    /// ChildEnv 专用;其他方式为 None
    pub env_var_name: Option<String>,
}

/// 保留 env key 名列表(必须与 `vigil_runner::RESERVED_SYSTEM_ENV_KEYS` 一致)。
/// vigil-audit 不依赖 vigil-runner(否则循环),故复制一份 + 跨 crate 测试守门。
const RESERVED_ENV_KEYS: &[&str] = &[
    "SystemRoot",
    "SYSTEMROOT",
    "windir",
    "WINDIR",
    "SystemDrive",
    "SYSTEMDRIVE",
];

/// 判定一个 env key 是否命中保留系统 env 名(大小写不敏感)。
pub fn is_reserved_env_key_name(key: &str) -> bool {
    RESERVED_ENV_KEYS
        .iter()
        .any(|k| k.eq_ignore_ascii_case(key))
}

/// I08 argv-secret-lint 的稳定 reason code(ADR 0008 §D5 / §I-8.3)。
/// 只回传 rule name(硬指纹类别)—— 不回传 raw argv 或 raw secret 任何字节。
fn secret_in_argv_reason(rule: &'static str) -> &'static str {
    match rule {
        "github_token" => "argv_contains_secret:github_token",
        "anthropic_key" => "argv_contains_secret:anthropic_key",
        "openai_key" => "argv_contains_secret:openai_key",
        "slack_token" => "argv_contains_secret:slack_token",
        "aws_access_key" => "argv_contains_secret:aws_access_key",
        "google_api_key" => "argv_contains_secret:google_api_key",
        "pem_private_key" => "argv_contains_secret:pem_private_key",
        _ => "argv_contains_secret:other",
    }
}

/// 计算 argv 的规范化 hash(JCS + sha256 hex-lower)—— 与 Hub `compute_argv_hash`
/// 算法口径一致,供 `check_server_command_drift` 做一致性自检使用。
pub fn argv_hash(argv: &[String]) -> String {
    use sha2::{Digest, Sha256};
    let bytes = serde_jcs::to_vec(argv).unwrap_or_default();
    let mut h = Sha256::new();
    h.update(&bytes);
    hex::encode(h.finalize())
}

/// 对 `secret_ref` 做域分离 SHA-256(ADR 0006 §D5)。
/// 输出 64 字符 hex(小写)。
pub fn secret_ref_fingerprint(secret_ref: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"vigil.secret_ref.fp.v1\0");
    h.update(secret_ref.as_bytes());
    hex::encode(h.finalize())
}

fn transport_to_str(t: TransportKind) -> &'static str {
    match t {
        TransportKind::Stdio => "Stdio",
        TransportKind::Http => "Http",
        _ => "Stdio", // non_exhaustive 兜底
    }
}

fn parse_transport(s: &str) -> Result<TransportKind> {
    Ok(match s {
        "Stdio" => TransportKind::Stdio,
        "Http" => TransportKind::Http,
        _ => {
            return Err(AuditError::InvalidInput {
                reason: "unknown transport kind",
            })
        }
    })
}

fn trust_to_str(l: TrustLevel) -> &'static str {
    match l {
        TrustLevel::Untrusted => "Untrusted",
        TrustLevel::Limited => "Limited",
        TrustLevel::Trusted => "Trusted",
        _ => "Untrusted", // non_exhaustive 兜底:未知扩展按最低信任
    }
}

fn parse_trust(s: &str) -> Result<TrustLevel> {
    Ok(match s {
        "Untrusted" => TrustLevel::Untrusted,
        "Limited" => TrustLevel::Limited,
        "Trusted" => TrustLevel::Trusted,
        _ => {
            return Err(AuditError::InvalidInput {
                reason: "unknown trust level",
            })
        }
    })
}
