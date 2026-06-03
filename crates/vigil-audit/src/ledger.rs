//! Ledger —— SQLite 账本的 open / append / search / verify / checkpoint 主接口。
//!
//! 并发策略:Connection 被 `Mutex` 包裹,保证 hash chain 的**单写者**不变量。
//! 读操作也走同一把锁(I01 范围,桌面本地应用 QPS 极低);I03+ 若需要高并发读,
//! 可改为 "writer conn + reader pool" 双连接模型,但 hash 写仍维持单写者。

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension};
use serde_json::Value;
use uuid::Uuid;

use crate::error::{AuditError, Result};
use crate::hash::{compute_event_hash, compute_event_hash_v2, CURRENT_CHAIN_VERSION};

const SCHEMA_SQL: &str = include_str!("schema.sql");

/// 保留给**专用 API** 的事件类型前缀集合(ADR 0003 §D8)。
///
/// Public `append_event` 命中其中任一前缀 → 返回 `InvalidInput`,强制调用方
/// 走对应的 typed 入口:
/// - `tool_call.*`  → `Ledger::tool_call_span(...)` 产生的 `ToolCallSpan` API
/// - `decision.*`   → `Ledger::record_decision(...)`
/// - `approval.*`   → `Ledger::record_approval_created / record_approval_resolved`
/// - `lease.*`      → `Ledger::record_lease_minted / record_lease_revoked`(I06)
pub const RESERVED_EVENT_PREFIXES: &[&str] = &["tool_call.", "decision.", "approval.", "lease."];

/// 向后兼容:I01 单前缀常量,仍指向 `tool_call.`。新代码请用 `RESERVED_EVENT_PREFIXES`。
#[deprecated(note = "use RESERVED_EVENT_PREFIXES")]
pub const RESERVED_EVENT_PREFIX: &str = "tool_call.";

/// I08 起的轻量 ADD COLUMN 迁移表:`(table, column, sql_type)`。
///
/// 每次新增一列(无论哪个迭代)都在此追加一行;`apply_column_migrations` 逐项
/// 尝试 `ALTER TABLE ADD COLUMN`,捕获 "duplicate column" 错误作为 no-op。
/// 不用第三方 migration 框架,保持零依赖 + 幂等。
const COLUMN_MIGRATIONS: &[(&str, &str, &str)] = &[
    // I08(Codex R2 BLOCKER):server command drift 新 argv 文本
    ("server_profiles", "pending_command_json", "TEXT"),
    // I10b-α1(ADR 0011 §α1-D1 BLOCKER 1):OAuth JWT `issuer` 一级公民
    // 刻意走 nullable + 读侧 fail-closed(legacy I10a 行 NULL → TokenStoreError
    // "issuer_missing_legacy_row")。**不得**改为 NOT NULL —— ADD COLUMN 对非空
    // 表加 NOT NULL 无默认值会失败,破坏迁移幂等性。
    ("oauth_token_metadata", "issuer", "TEXT"),
    // V1.1(ADR 0007 §I-7.1 / ADR 0005 第二独立 drift 维度):裸命令解析后绝对路径 pin。
    // nullable —— legacy 行(列新增前的审批)NULL,首次本机 spawn 建立基线(见 §3.2 4 护栏)。
    ("server_profiles", "resolved_program_path", "TEXT"),
    ("server_profiles", "pending_resolved_program_path", "TEXT"),
    // VIGIL-SEC-001(security audit 2026-06-03):per-event chain 版本。legacy 行(列新增
    // 前写入)DEFAULT 1 → 按 v1 摘要验证(历史链不破);新事件显式写 CURRENT_CHAIN_VERSION(2)
    // → v2 摘要额外绑定 session_id/event_type/redacted_text。verify_chain 按本列分派。
    ("events", "chain_version", "INTEGER NOT NULL DEFAULT 1"),
];

fn apply_column_migrations(conn: &Connection) -> Result<()> {
    for (table, column, sql_type) in COLUMN_MIGRATIONS {
        if column_exists(conn, table, column)? {
            continue;
        }
        let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {sql_type}");
        conn.execute(&sql, [])
            .map_err(|_| AuditError::InvalidInput {
                reason: "column_migration_failed",
            })?;
    }
    Ok(())
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    // PRAGMA table_info 返回每列 (cid, name, type, notnull, dflt_value, pk)
    let sql = format!("PRAGMA table_info({table})");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(1))?;
    for r in rows {
        if r? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

/// 从时间源获取 Unix epoch 秒。拆成函数是为了测试注入。
pub(crate) fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 审计账本的顶层句柄。
#[derive(Debug)]
pub struct Ledger {
    pub(crate) conn: Mutex<Connection>,
    // span Drop 在兜底写 `tool_call.abandoned` 时若失败(极少见,如磁盘已满或底层
    // IO 抽搐),本计数器原子递增。提供最低限度的可观察性,避免静默丢事件。
    // 正常路径(executed/execute_failed/decision_recorded)的错误走 Result,不计入。
    pub(crate) drop_failure_count: AtomicU64,
    // approval 等待/通知中枢(ADR 0003 §D5)。
    pub(crate) approval_broker: crate::approvals::ApprovalBroker,
}

/// `append_event` 成功返回的事件摘要。调用方无须再次查询。
#[derive(Debug, Clone)]
pub struct AppendedEvent {
    /// 自增 id。
    pub event_id: i64,
    /// SHA-256 hex-lower。
    pub event_hash: String,
    /// Unix epoch 秒。
    pub created_at: i64,
}

/// FTS 检索结果的最小投影。需要完整事件时另查 `events` 表。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EventHit {
    /// 自增 id。
    pub event_id: i64,
    /// 所属 session。
    pub session_id: String,
    /// 事件类型。
    pub event_type: String,
    /// 匹配到的已脱敏摘要(若 event 写入时有提供)。
    pub redacted_text: Option<String>,
    /// 创建时间(Unix epoch 秒)。
    pub created_at: i64,
}

/// I08 `list_sessions` 返回的 session 摘要投影。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionSummaryRow {
    /// session id
    pub session_id: String,
    /// source(mcp_hub / desktop / cli / ...)
    pub source: String,
    /// 应用名(可选)
    pub app_name: Option<String>,
    /// 开始时间 Unix 秒
    pub started_at: i64,
    /// 结束时间(None = 未结束)
    pub ended_at: Option<i64>,
    /// 风险分
    pub risk_score: i64,
}

/// I08 `get_event_detail` 返回的完整事件投影。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EventDetailRow {
    /// event_id
    pub event_id: i64,
    /// 所属 session
    pub session_id: String,
    /// 事件类型
    pub event_type: String,
    /// 完整 payload JSON(已脱敏)
    pub payload: Value,
    /// FTS 摘要
    pub redacted_text: Option<String>,
    /// 前 hash
    pub prev_hash: String,
    /// 本事件 hash
    pub event_hash: String,
    /// 创建时间
    pub created_at: i64,
}

/// 一条回放事件 —— 完整投影,供 UI / CLI 重建时间线(方案 §7.4)。
///
/// 与 `vigil_types::AuditEvent` 字段对齐,但 `payload` 已反序列化为 `serde_json::Value`
/// 方便前端直接消费。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReplayEvent {
    /// 自增 id。
    pub event_id: i64,
    /// 所属 session。
    pub session_id: String,
    /// 事件类型(如 `tool_call.opened` / `tool_call.decided` / `secret.lease_minted`)。
    pub event_type: String,
    /// 已脱敏的结构化负载。
    pub payload: Value,
    /// 已脱敏的 FTS 摘要(若有)。
    pub redacted_text: Option<String>,
    /// 本事件的 hash(hex-lower 64 字符)。
    pub event_hash: String,
    /// 前一事件的 hash(genesis 时为空串)。
    pub prev_hash: String,
    /// 创建时间(Unix epoch 秒)。
    pub created_at: i64,
}

impl Ledger {
    /// 打开一个磁盘账本;不存在则创建并建表。
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    /// 打开一个内存账本(测试使用)。
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self> {
        // 尝试启用 WAL。内存库(`:memory:`)会返回 "memory";磁盘库会返回 "wal"。
        // 我们不接受磁盘库退化为 "delete":那意味着本机 SQLite 版本 / 权限异常,
        // 审计不变量将失守 —— fail-closed。
        let mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
        let mode_lc = mode.to_lowercase();
        if mode_lc != "wal" && mode_lc != "memory" {
            return Err(AuditError::InvalidInput {
                reason: "failed to enable WAL journal mode on this database",
            });
        }
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;

        conn.execute_batch(SCHEMA_SQL)?;
        // Codex I08 R2 BLOCKER 修复:老数据库的 ADD COLUMN 迁移。
        // `CREATE TABLE IF NOT EXISTS` 对已存在表是 no-op,任何迭代新增的列都不会
        // 自动出现在老库里。此处显式 `ALTER TABLE ADD COLUMN` 并容忍"已存在"错误,
        // 让 I08 起步的 `pending_command_json` 在磁盘老库上也可用。
        apply_column_migrations(&conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
            drop_failure_count: AtomicU64::new(0),
            approval_broker: crate::approvals::ApprovalBroker::default(),
        })
    }

    /// 返回 span Drop 兜底写 abandoned 事件时发生的失败累计次数(进程生命周期内)。
    ///
    /// 运维 / 测试可用它判断是否出现静默丢失。正常情况应始终为 0。
    pub fn span_drop_failures(&self) -> u64 {
        self.drop_failure_count.load(Ordering::Relaxed)
    }

    /// 新建 session 并返回 `session_id`(UUIDv4)。
    pub fn start_session(&self, source: &str, app_name: Option<&str>) -> Result<String> {
        validate_nonempty("source", source)?;
        let id = Uuid::new_v4().to_string();
        let now = now_secs();
        let conn = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        conn.execute(
            "INSERT INTO sessions (session_id, source, app_name, started_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![id, source, app_name, now],
        )?;
        Ok(id)
    }

    /// 追加一个**非 tool-call 类**事件到账本。
    ///
    /// - **caller 必须先调用 `vigil-redaction::redact`**,本函数不二次脱敏。
    /// - 入口 fail-closed 自检:若 `payload` JCS 化后或 `redacted_text` 命中硬指纹
    ///   (见 `vigil-redaction::detect_hard_secret`),返回 `HardSecretDetected`。
    /// - **拒绝 `event_type` 以 `"tool_call."` 开头**(`RESERVED_EVENT_PREFIX`):
    ///   这类事件必须通过 [`Ledger::tool_call_span`] 的 typestate API 写入,
    ///   以保证 AGENTS.md §1 "Every tool call must create a DecisionRecord before execution"。
    /// - 单事务写入 events + event_fts,保证两表一致。
    pub fn append_event(
        &self,
        session_id: &str,
        event_type: &str,
        payload: &Value,
        redacted_text: Option<&str>,
    ) -> Result<AppendedEvent> {
        for p in RESERVED_EVENT_PREFIXES {
            if event_type.starts_with(p) {
                return Err(AuditError::InvalidInput {
                    reason: "event_type uses a reserved prefix; use the typed Ledger API instead",
                });
            }
        }
        self.append_event_internal(session_id, event_type, payload, redacted_text)
    }

    /// 给 `span.rs` 使用的无前缀检查的底层入口。不对外暴露,保证 `tool_call.*` 事件
    /// 只能来自 typestate 驱动的 span。
    pub(crate) fn append_event_internal(
        &self,
        session_id: &str,
        event_type: &str,
        payload: &Value,
        redacted_text: Option<&str>,
    ) -> Result<AppendedEvent> {
        validate_nonempty("session_id", session_id)?;
        validate_nonempty("event_type", event_type)?;

        // JCS 规范化既用于 fail-closed 扫描,也作为存入 payload_json 的字节形式。
        let payload_bytes = serde_jcs::to_vec(payload)?;
        let payload_str =
            String::from_utf8(payload_bytes).map_err(|_| AuditError::InvalidInput {
                reason: "serde_jcs produced non-utf8(不可能,防御式)",
            })?;

        if let Some(rule) = vigil_redaction::detect_hard_secret(&payload_str) {
            return Err(AuditError::HardSecretDetected { rule });
        }
        if let Some(text) = redacted_text {
            if let Some(rule) = vigil_redaction::detect_hard_secret(text) {
                return Err(AuditError::HardSecretDetected { rule });
            }
        }

        let now = now_secs();
        let mut guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let tx = guard.transaction()?;

        let prev_hash: String = tx
            .query_row(
                "SELECT event_hash FROM events ORDER BY event_id DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap_or_default(); // 表空 → genesis("")

        // VIGIL-SEC-001:新事件用 v2 摘要(额外绑定 session_id/event_type/redacted_text)。
        let event_hash = compute_event_hash_v2(
            &prev_hash,
            payload,
            now,
            session_id,
            event_type,
            redacted_text,
        )?;

        tx.execute(
            "INSERT INTO events (session_id, event_type, payload_json, redacted_text, prev_hash, event_hash, created_at, chain_version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                session_id,
                event_type,
                payload_str,
                redacted_text,
                prev_hash,
                event_hash,
                now,
                CURRENT_CHAIN_VERSION,
            ],
        )?;
        let event_id = tx.last_insert_rowid();

        // FTS5 行:rowid 绑定到 event_id,便于后续 JOIN 回表。
        tx.execute(
            "INSERT INTO event_fts (rowid, session_id, event_type, redacted_text) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                event_id,
                session_id,
                event_type,
                redacted_text.unwrap_or(""),
            ],
        )?;

        tx.commit()?;

        Ok(AppendedEvent {
            event_id,
            event_hash,
            created_at: now,
        })
    }

    /// FTS5 检索。`query` 按 SQLite MATCH 语法(如 `finding:github_token` 或 `auth OR login`)。
    pub fn fts_search(&self, query: &str) -> Result<Vec<EventHit>> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let mut stmt = guard.prepare(
            "SELECT e.event_id, e.session_id, e.event_type, e.redacted_text, e.created_at
             FROM event_fts f JOIN events e ON e.event_id = f.rowid
             WHERE event_fts MATCH ?1
             ORDER BY e.event_id",
        )?;
        let rows = stmt.query_map([query], |row| {
            Ok(EventHit {
                event_id: row.get(0)?,
                session_id: row.get(1)?,
                event_type: row.get(2)?,
                redacted_text: row.get(3)?,
                created_at: row.get(4)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// 校验整条 hash chain。发现第一个不一致即返回 `ChainBroken`。
    ///
    /// VIGIL-SEC-001:按每事件存储的 `chain_version` 分派摘要复算 —— v1 历史事件按 v1
    /// 验证(不破坏旧链),v2 事件用 v2 摘要(额外把 session_id/event_type/redacted_text
    /// 纳入复算,因此这三列的部分篡改会被检测)。
    pub fn verify_chain(&self) -> Result<()> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let mut stmt = guard.prepare(
            "SELECT event_id, payload_json, prev_hash, event_hash, created_at, session_id, event_type, redacted_text, chain_version
             FROM events ORDER BY event_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, i64>(8)?,
            ))
        })?;

        let mut expected_prev = String::new();
        // VIGIL-SEC-001 R1(Codex):chain_version 必须**单调非降**(合法升级链是 v1*→v2*)。
        // 否则攻击者可把一条 v2 行降级回 chain_version=1 + 重算 v1 hash(v1 摘要不含
        // session_id/event_type/redacted_text)→ 重新获得篡改这三列的能力。一旦见过更高
        // 版本,后续出现更低版本即 ChainBroken。
        let mut min_version: i64 = 1;
        for r in rows {
            let (
                event_id,
                payload_json,
                prev_hash,
                event_hash,
                created_at,
                session_id,
                event_type,
                redacted_text,
                chain_version,
            ) = r?;
            if prev_hash != expected_prev {
                return Err(AuditError::ChainBroken { event_id });
            }
            if chain_version < min_version {
                // 版本回滚(downgrade)→ fail-closed
                return Err(AuditError::ChainBroken { event_id });
            }
            min_version = min_version.max(chain_version);
            // 解析 payload 做一次 hash 复算
            let payload: Value = serde_json::from_str(&payload_json)
                .map_err(|_| AuditError::ChainBroken { event_id })?;
            let recomputed = match chain_version {
                1 => compute_event_hash(&prev_hash, &payload, created_at)?,
                2 => compute_event_hash_v2(
                    &prev_hash,
                    &payload,
                    created_at,
                    &session_id,
                    &event_type,
                    redacted_text.as_deref(),
                )?,
                // 未知/未来版本 → fail-closed(不静默接受)
                _ => return Err(AuditError::ChainBroken { event_id }),
            };
            if recomputed != event_hash {
                return Err(AuditError::ChainBroken { event_id });
            }
            expected_prev = event_hash;
        }
        Ok(())
    }

    /// 按 session 时间线回放全部事件(方案 §7.4 "回放不展示原始 prompt,展示事件重建")。
    ///
    /// **注意**:本 API 不做 hash chain 校验。若账本可能被篡改,改用
    /// [`Ledger::replay_session_verified`](Self::replay_session_verified)。
    ///
    /// 返回的顺序严格等于 `event_id` 递增,调用方可按类型过滤(如只取 `tool_call.*`)
    /// 并按 invocation_id 分组,即可重建出一次 tool call 的完整时间线。
    pub fn replay_session(&self, session_id: &str) -> Result<Vec<ReplayEvent>> {
        validate_nonempty("session_id", session_id)?;
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let mut stmt = guard.prepare(
            "SELECT event_id, session_id, event_type, payload_json, redacted_text, prev_hash, event_hash, created_at
             FROM events WHERE session_id = ?1 ORDER BY event_id",
        )?;
        let rows = stmt.query_map([session_id], |row| {
            let payload_json: String = row.get(3)?;
            Ok(ReplayEventRow {
                event_id: row.get(0)?,
                session_id: row.get(1)?,
                event_type: row.get(2)?,
                payload_json,
                redacted_text: row.get(4)?,
                prev_hash: row.get(5)?,
                event_hash: row.get(6)?,
                created_at: row.get(7)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            let row = r?;
            // payload 解析失败意味着账本被直接改写过 —— 对 UI 来说更安全的是抛
            // ChainBroken 让调用方先 verify,而不是展示可能损坏的 JSON。
            let payload: Value =
                serde_json::from_str(&row.payload_json).map_err(|_| AuditError::ChainBroken {
                    event_id: row.event_id,
                })?;
            out.push(ReplayEvent {
                event_id: row.event_id,
                session_id: row.session_id,
                event_type: row.event_type,
                payload,
                redacted_text: row.redacted_text,
                prev_hash: row.prev_hash,
                event_hash: row.event_hash,
                created_at: row.created_at,
            });
        }
        Ok(out)
    }

    /// 带 hash chain 校验的 replay(ADR 0003 §F2 推荐默认路径)。
    ///
    /// 内部流程:先全量 `verify_chain`,通过后再读出事件。若链断裂,调用方拿到
    /// `ChainBroken { event_id }`,永远不会看到半损坏的时间线。
    pub fn replay_session_verified(&self, session_id: &str) -> Result<Vec<ReplayEvent>> {
        self.verify_chain()?;
        self.replay_session(session_id)
    }

    /// 列出所有 sessions(可选 source 过滤)。I08a 为 UI Session Replay 页提供列表。
    pub fn list_sessions(
        &self,
        source: Option<&str>,
        limit: u32,
    ) -> Result<Vec<SessionSummaryRow>> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let sql = match source {
            Some(_) => {
                "SELECT session_id, source, app_name, started_at, ended_at, risk_score
                 FROM sessions WHERE source = ?1 ORDER BY started_at DESC LIMIT ?2"
            }
            None => {
                "SELECT session_id, source, app_name, started_at, ended_at, risk_score
                 FROM sessions ORDER BY started_at DESC LIMIT ?1"
            }
        };
        let mut stmt = guard.prepare(sql)?;
        let map_row = |r: &rusqlite::Row<'_>| {
            Ok(SessionSummaryRow {
                session_id: r.get::<_, String>(0)?,
                source: r.get::<_, String>(1)?,
                app_name: r.get::<_, Option<String>>(2)?,
                started_at: r.get::<_, i64>(3)?,
                ended_at: r.get::<_, Option<i64>>(4)?,
                risk_score: r.get::<_, i64>(5)?,
            })
        };
        let rows = match source {
            Some(s) => stmt.query_map(rusqlite::params![s, limit as i64], map_row)?,
            None => stmt.query_map(rusqlite::params![limit as i64], map_row)?,
        };
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// 拿单条事件完整细节(供 UI `GetEventDetail`)。
    pub fn get_event_detail(&self, event_id: i64) -> Result<Option<EventDetailRow>> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let row = guard
            .query_row(
                "SELECT event_id, session_id, event_type, payload_json, redacted_text,
                        prev_hash, event_hash, created_at
                 FROM events WHERE event_id = ?1",
                rusqlite::params![event_id],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, Option<String>>(4)?,
                        r.get::<_, String>(5)?,
                        r.get::<_, String>(6)?,
                        r.get::<_, i64>(7)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            event_id,
            session_id,
            event_type,
            payload_json,
            redacted_text,
            prev_hash,
            event_hash,
            created_at,
        )) = row
        else {
            return Ok(None);
        };
        let payload: Value = serde_json::from_str(&payload_json)?;
        Ok(Some(EventDetailRow {
            event_id,
            session_id,
            event_type,
            payload,
            redacted_text,
            prev_hash,
            event_hash,
            created_at,
        }))
    }

    /// Activity Feed 后端查询:按 session + event_type 过滤,返回最近 N 条。
    ///
    /// ADR 0008 §D7:后端保留全量查询,默认过滤集由前端决定。
    pub fn list_recent_events(
        &self,
        session_id: Option<&str>,
        event_type_filter: Option<&[String]>,
        limit: u32,
    ) -> Result<Vec<EventHit>> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        // 动态构造 SQL(参数化,无拼接 raw 字符串)
        let mut sql = String::from(
            "SELECT event_id, session_id, event_type, redacted_text, created_at FROM events WHERE 1=1",
        );
        let mut params: Vec<rusqlite::types::Value> = Vec::new();
        if let Some(sid) = session_id {
            sql.push_str(" AND session_id = ?");
            params.push(sid.to_string().into());
        }
        if let Some(types) = event_type_filter {
            if !types.is_empty() {
                sql.push_str(" AND event_type IN (");
                for (i, t) in types.iter().enumerate() {
                    if i > 0 {
                        sql.push_str(", ");
                    }
                    sql.push('?');
                    params.push(t.clone().into());
                }
                sql.push(')');
            }
        }
        sql.push_str(" ORDER BY event_id DESC LIMIT ?");
        params.push((limit as i64).into());

        let mut stmt = guard.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |r| {
            Ok(EventHit {
                event_id: r.get(0)?,
                session_id: r.get(1)?,
                event_type: r.get(2)?,
                redacted_text: r.get(3)?,
                created_at: r.get(4)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// 主动触发 WAL checkpoint(TRUNCATE 模式:尽量缩短 WAL 文件)。
    pub fn checkpoint(&self) -> Result<()> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        // pragma_query:结果三元组 (busy, log, checkpointed)。我们只关心没报错。
        guard.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
        Ok(())
    }

    // ---------------- I01 最小原语:approval 行读写 ----------------
    //
    // I03 会在其上实装完整的 state machine(create/approve/deny/wait_for_resolution)。
    // I01 只暴露最小写/读,供"pending approval 跨重启存活"验收测试使用。

    /// 插入一个 `Pending` 的 approval 行(骨架 API,I03 会替换为完整流程)。
    // I01 骨架 API 直接镜像 SQL 行,多个独立 String/i64。I03 会以 `ApprovalRequest` DTO 收窄签名。
    #[allow(clippy::too_many_arguments)]
    pub fn store_pending_approval_skeleton(
        &self,
        approval_id: &str,
        decision_id: &str,
        session_id: &str,
        title: &str,
        summary: &str,
        effect_json: &str,
        expires_at: i64,
    ) -> Result<()> {
        validate_nonempty("approval_id", approval_id)?;
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        guard.execute(
            "INSERT INTO approvals
               (approval_id, decision_id, session_id, title, summary, effect_json,
                status, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'Pending', ?7, ?8)",
            rusqlite::params![
                approval_id,
                decision_id,
                session_id,
                title,
                summary,
                effect_json,
                expires_at,
                now_secs(),
            ],
        )?;
        Ok(())
    }

    /// 按 id 读取 approval 状态(若不存在返回 `None`)。
    pub fn approval_status(&self, approval_id: &str) -> Result<Option<String>> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let r = guard.query_row(
            "SELECT status FROM approvals WHERE approval_id = ?1",
            rusqlite::params![approval_id],
            |row| row.get::<_, String>(0),
        );
        match r {
            Ok(s) => Ok(Some(s)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// 事件条目数(供测试与 UI 显示使用)。
    pub fn event_count(&self) -> Result<i64> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let n: i64 = guard.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
        Ok(n)
    }

    /// 最新事件 id(`MAX(event_id)`),空 ledger 返回 `None`(Theme G real-time 锚点)。
    ///
    /// `event_id` 是 `INTEGER PRIMARY KEY AUTOINCREMENT`(schema.sql),`MAX` 走主键
    /// 索引,远比 `COUNT(*)` 廉价,且语义精确表达"最后 append 的 event"。
    ///
    /// **语义边界**(ADR 0014 / Theme G spike § 1):本锚点仅覆盖 **event-backed** 变更
    /// (走 `append_event` 的所有 event)。`redaction_scans` / `redaction_findings` /
    /// `sessions` 直写表不 append event,**不被本锚点覆盖** —— 消费方(desktop poller)
    /// 据此只驱动 event-backed 页刷新,Privacy Findings 仍走 fallback poll。
    ///
    /// `MAX(event_id)` 对空表返回一行 `NULL`,用 `Option<i64>` 承载(`get::<_, Option<i64>>`)。
    pub fn latest_event_id(&self) -> Result<Option<i64>> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let max: Option<i64> =
            guard.query_row("SELECT MAX(event_id) FROM events", [], |r| r.get(0))?;
        Ok(max)
    }

    // ---------------- ISS-011 Stage 2:T0 redaction scan 审计 CRUD ----------------
    //
    // 两表 redaction_scans / redaction_findings 落在 schema.sql;此处仅实装 insert +
    // list。**核心不变量:绝不存原文** —— caller 须先走 vigil-redaction,scan 级
    // fingerprint = sha256(input)[..16] hex-lower,finding 级 fingerprint 同理,
    // 文本长度 / offset 均经 `bit_width_bucket` 位宽粗化。
    //
    // label 合法集与 ISS-005 `vigil_redaction::PrivacyLabel::as_str()` 对齐;为避免
    // 反向依赖(vigil-audit → vigil-redaction 已存在一条,但语义仅"硬指纹自检"),
    // 这里手工枚举字符串,并由测试 `test_redaction_label_allowlist_exact_set`
    // 守门("精确集合"feedback_ssot_drift_guard),任一侧漂移即测试失败。

    /// 插入一条 redaction scan,返回新分配的 `scan_id`(UUIDv4)。
    ///
    /// - `source` 必须是 `paste | tool_arg | tool_output | export` 之一,否则返回
    ///   `AuditError::InvalidInput`;
    /// - `fingerprint` 必须是 32 字符(16 字节)hex-lower(caller 自己算 sha256,
    ///   本 crate 不引入 sha 计算以保持职责单一);
    /// - `text_length` 由本 crate 做 `bit_width_bucket` 粗化后落库,**原始长度不持久化**。
    pub fn insert_redaction_scan(&self, scan: NewRedactionScan<'_>) -> Result<String> {
        // source 合法集 —— 与 NewRedactionScan / RedactionScanRow 的 doc 与
        // test_redaction_source_allowlist 形成三边 SSOT diff。
        const ALLOWED_SOURCES: &[&str] = &["paste", "tool_arg", "tool_output", "export"];
        if !ALLOWED_SOURCES.contains(&scan.source) {
            return Err(AuditError::InvalidInput {
                reason: "redaction_scan_source_not_allowed",
            });
        }
        validate_nonempty("session_id", scan.session_id)?;
        // R1 BLOCKER 修复:fingerprint 必须 32 ASCII lowercase hex(不仅长度,还禁原文穿透)
        validate_fingerprint(scan.fingerprint)?;

        let id = Uuid::new_v4().to_string();
        let now = now_secs();
        let bucket = bit_width_bucket(scan.text_length);

        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        guard.execute(
            "INSERT INTO redaction_scans
               (scan_id, session_id, ts, source, text_length_bucket, fingerprint)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                id,
                scan.session_id,
                now,
                scan.source,
                bucket,
                scan.fingerprint
            ],
        )?;
        Ok(id)
    }

    /// 插入一条 redaction finding,返回自增 `finding_id`。
    ///
    /// - `label` 必须是 ISS-005 `PrivacyLabel` 8 枚举之一(见 `ALLOWED_LABELS`);
    /// - `action_taken` 必须是 `redacted | blocked | allowed_once`;
    /// - `fingerprint` 长度校验同 `insert_redaction_scan`;
    /// - `offset` 经 `bit_width_bucket` 粗化。
    pub fn insert_redaction_finding(&self, finding: NewRedactionFinding<'_>) -> Result<i64> {
        if !ALLOWED_REDACTION_LABELS.contains(&finding.label) {
            return Err(AuditError::InvalidInput {
                reason: "redaction_finding_label_not_allowed",
            });
        }
        const ALLOWED_ACTIONS: &[&str] = &["redacted", "blocked", "allowed_once"];
        if !ALLOWED_ACTIONS.contains(&finding.action_taken) {
            return Err(AuditError::InvalidInput {
                reason: "redaction_finding_action_not_allowed",
            });
        }
        validate_nonempty("scan_id", finding.scan_id)?;
        // R1 BLOCKER 修复:fingerprint 严格 hex-lower(不仅长度)
        validate_fingerprint(finding.fingerprint)?;

        // R1 BLOCKER 修复:placeholder 由 audit 内部派生,**不接受 caller 输入**。
        // 原实装把 caller 给的 placeholder 直写 SQLite,攻击者可把真 secret 或
        // `[REDACTED ghp_xxx]` 伪占位符写进来,违背"绝不存原文"不变量。
        // 现在 placeholder 严格对应 label,action_taken 一并体现在形态里(见下)。
        let placeholder = derive_placeholder(finding.label, finding.action_taken);

        let bucket = bit_width_bucket(finding.offset);
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        // RETURNING 是 SQLite 3.35+ 官方语法;rusqlite 已支持。
        let id = guard.query_row(
            "INSERT INTO redaction_findings
               (scan_id, label, offset_bucket, placeholder, fingerprint, action_taken)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             RETURNING finding_id",
            rusqlite::params![
                finding.scan_id,
                finding.label,
                bucket,
                placeholder,
                finding.fingerprint,
                finding.action_taken,
            ],
            |r| r.get::<_, i64>(0),
        )?;
        Ok(id)
    }

    /// 列举某 session 下的全部 redaction scans,按 `ts` 升序 +(同秒时)`scan_id` 升序。
    pub fn list_redaction_scans_by_session(
        &self,
        session_id: &str,
    ) -> Result<Vec<RedactionScanRow>> {
        validate_nonempty("session_id", session_id)?;
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let mut stmt = guard.prepare(
            "SELECT scan_id, session_id, ts, source, text_length_bucket, fingerprint
             FROM redaction_scans WHERE session_id = ?1 ORDER BY ts ASC, scan_id ASC",
        )?;
        let rows = stmt.query_map(rusqlite::params![session_id], |r| {
            Ok(RedactionScanRow {
                scan_id: r.get(0)?,
                session_id: r.get(1)?,
                ts: r.get(2)?,
                source: r.get(3)?,
                text_length_bucket: r.get(4)?,
                fingerprint: r.get(5)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// ISS-014 — 按 session 聚合 PrivacyLabel 统计(`label`, `count`),供审批
    /// UI 的 "Privacy Findings" 区块直接消费(N-Timeline / 桌面 panel 复用)。
    ///
    /// **scope 折衷**:redaction_scans 没有 `invocation_id` 字段,无法精确按
    /// approval 关联;退而求其次按 session_id 聚合 `source = 'tool_arg'`(preflight
    /// 路径写入的)。同 session 多 invocation 的 finding 会一起呈现 —— UI 上
    /// 这是合理近似(用户视角:"这次会话里 Vigil 拦了哪些 PII")。
    /// 精确按 invocation 关联留 ISS-014 phase 2(schema 加 `invocation_id` 列)。
    ///
    /// 排序:`count DESC, label ASC`(相同次数按字母序稳定,UI 视图稳定)。
    pub fn aggregate_redaction_labels_by_session(
        &self,
        session_id: &str,
    ) -> Result<Vec<(String, i64)>> {
        validate_nonempty("session_id", session_id)?;
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let mut stmt = guard.prepare(
            "SELECT f.label, COUNT(*) AS cnt
             FROM redaction_findings f
             JOIN redaction_scans s ON s.scan_id = f.scan_id
             WHERE s.session_id = ?1 AND s.source = 'tool_arg'
             GROUP BY f.label
             ORDER BY cnt DESC, f.label ASC",
        )?;
        let rows = stmt.query_map(rusqlite::params![session_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// ISS-017 — 全局 PrivacyLabel 聚合(`label`, `count`),不限 session,不限 source。
    /// 桌面 Privacy Findings 面板顶部"今日命中"区块直接消费。
    /// 排序与 session 版本一致(count DESC, label ASC)。
    pub fn aggregate_redaction_labels_global(&self) -> Result<Vec<(String, i64)>> {
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let mut stmt = guard.prepare(
            "SELECT label, COUNT(*) AS cnt
             FROM redaction_findings
             GROUP BY label
             ORDER BY cnt DESC, label ASC",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// ISS-017 — 最近 N 条 redaction_scans + 每条的 finding 数(scan_id 维度)。
    /// 按 `ts DESC, scan_id DESC` 排序,UI 展最近事件流。
    /// `limit` 为 0 时按 50 兜底(防止意外全量)。
    pub fn list_recent_redaction_scans_with_counts(
        &self,
        limit: u32,
    ) -> Result<Vec<(RedactionScanRow, i64)>> {
        let lim = if limit == 0 { 50 } else { limit.min(500) }; // 上限防御
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let mut stmt = guard.prepare(
            "SELECT s.scan_id, s.session_id, s.ts, s.source, s.text_length_bucket, s.fingerprint,
                    (SELECT COUNT(*) FROM redaction_findings f WHERE f.scan_id = s.scan_id) AS finding_count
             FROM redaction_scans s
             ORDER BY s.ts DESC, s.scan_id DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(rusqlite::params![lim], |r| {
            Ok((
                RedactionScanRow {
                    scan_id: r.get(0)?,
                    session_id: r.get(1)?,
                    ts: r.get(2)?,
                    source: r.get(3)?,
                    text_length_bucket: r.get(4)?,
                    fingerprint: r.get(5)?,
                },
                r.get::<_, i64>(6)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// 列举某 scan 下的全部 findings,按 `finding_id` 升序。
    pub fn list_redaction_findings_by_scan(
        &self,
        scan_id: &str,
    ) -> Result<Vec<RedactionFindingRow>> {
        validate_nonempty("scan_id", scan_id)?;
        let guard = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let mut stmt = guard.prepare(
            "SELECT finding_id, scan_id, label, offset_bucket, placeholder, fingerprint, action_taken
             FROM redaction_findings WHERE scan_id = ?1 ORDER BY finding_id ASC",
        )?;
        let rows = stmt.query_map(rusqlite::params![scan_id], |r| {
            Ok(RedactionFindingRow {
                finding_id: r.get(0)?,
                scan_id: r.get(1)?,
                label: r.get(2)?,
                offset_bucket: r.get(3)?,
                placeholder: r.get(4)?,
                fingerprint: r.get(5)?,
                action_taken: r.get(6)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}

/// ISS-011 Stage 2 — 合法 PrivacyLabel 字面量集合(与 `vigil_redaction::PrivacyLabel::as_str()`
/// 对齐,但此处手动列出避免反向耦合)。测试 `test_redaction_label_allowlist_exact_set`
/// 精确集合守门,任一侧漂移即测试失败(feedback_ssot_drift_guard)。
pub const ALLOWED_REDACTION_LABELS: &[&str] = &[
    "secret",
    "account_number",
    "email",
    "phone",
    "person",
    "address",
    "date",
    "url",
];

/// ISS-011 Stage 2 — T0 redaction scan 元数据(持久化投影)。
///
/// 不存原文;`text_length_bucket` 为 `bit_width_bucket(len)`(位宽,0 特判为 0),
/// `fingerprint` 为 `sha256(input)` 前 16 字节 hex-lower(32 字符)。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RedactionScanRow {
    /// Scan UUIDv4。
    pub scan_id: String,
    /// 所属 session。
    pub session_id: String,
    /// Unix epoch 秒。
    pub ts: i64,
    /// `paste` | `tool_arg` | `tool_output` | `export` 之一。
    pub source: String,
    /// 输入文本长度的位宽 bucket(粗化);0 长度 → 0。
    pub text_length_bucket: i64,
    /// sha256(input)[..16] hex-lower(32 字符)。
    pub fingerprint: String,
}

/// ISS-011 Stage 2 — T0 redaction finding(对应 `vigil_redaction::Finding` 的持久化投影)。
///
/// `label` 字面量与 `PrivacyLabel::as_str()` 对齐(不 import vigil-redaction 符号,
/// 避免反向语义耦合)。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RedactionFindingRow {
    /// 自增 id。
    pub finding_id: i64,
    /// 所属 scan。
    pub scan_id: String,
    /// 见 `ALLOWED_REDACTION_LABELS`。
    pub label: String,
    /// 命中 span 的 offset 位宽 bucket。
    pub offset_bucket: i64,
    /// 如 `"[REDACTED secret]"`。
    pub placeholder: String,
    /// sha256(原 span)[..16] hex-lower(32 字符)—— 跨 scan 溯源锚点。
    pub fingerprint: String,
    /// `redacted` | `blocked` | `allowed_once`。
    pub action_taken: String,
}

/// `insert_redaction_scan` 的入参。
#[derive(Debug, Clone)]
pub struct NewRedactionScan<'a> {
    /// 所属 session id(非空)。
    pub session_id: &'a str,
    /// `paste` | `tool_arg` | `tool_output` | `export`。
    pub source: &'a str,
    /// 原始文本长度(本 crate 会做 `bit_width_bucket` 粗化,**不**持久化原始值)。
    pub text_length: usize,
    /// sha256(input) 前 16 字节 hex-lower,必须恰好 32 字符([0-9a-f])。
    pub fingerprint: &'a str,
}

/// `insert_redaction_finding` 的入参。
///
/// **R1 BLOCKER 修复**:原设计允许 caller 传 `placeholder: &str`,攻击者/bug 可把真
/// secret 或伪占位符直写 SQLite(违背"绝不存原文"不变量)。现在 `placeholder`
/// 由 audit 内部按 `label × action_taken` 派生(见 `derive_placeholder`),caller
/// 不再传,也不再有可能污染持久层。
#[derive(Debug, Clone)]
pub struct NewRedactionFinding<'a> {
    /// 所属 scan id(非空)。
    pub scan_id: &'a str,
    /// 见 `ALLOWED_REDACTION_LABELS`。
    pub label: &'a str,
    /// span 在原文中的 byte offset(本 crate 做 `bit_width_bucket` 粗化)。
    pub offset: usize,
    /// sha256(原 span) 前 16 字节 hex-lower(32 字符,[0-9a-f])。
    pub fingerprint: &'a str,
    /// `redacted` | `blocked` | `allowed_once`。决定派生 placeholder 的动作前缀。
    pub action_taken: &'a str,
}

/// Bit-width bucket:返回 `n` 的最高有效位位号(1-based),0 特判为 0。
///
/// **命名澄清(R1 NICE-TO-HAVE 修复)**:这不是 `floor(log2(n+1))` 的数学 log2,
/// 而是**位宽**(highest set bit index, 1-based):
///
/// - `bit_width_bucket(n) = if n == 0 { 0 } else { u64::BITS - n.leading_zeros() }`
/// - 等价于 `if n >= 1 { floor(log2(n)) + 1 }`
/// - 样例:`0→0, 1→1, 2→2, 3→2, 4→3, 1023→10, 1024→11`
///
/// schema.sql 的 `text_length_bucket` / `offset_bucket` 语义与此**一致**;
/// 请**不要**按"floor(log2(n+1))"的数学直觉回改实装。
fn bit_width_bucket(n: usize) -> i64 {
    let n = n as u64;
    if n == 0 {
        0
    } else {
        (u64::BITS - n.leading_zeros()) as i64
    }
}

/// 校验 fingerprint 严格是 32 个 ASCII lowercase hex 字符(sha256 前 16 字节 hex-lower)。
///
/// **R1 BLOCKER 修复**:旧实装只检查 `len == 32`,放过 32 字符 secret 原文 /
/// 非 hex / uppercase hex,违背"SQLite 绝不存原文"+fail-closed 不变量。
/// 此 fn 对 `insert_redaction_scan` 和 `insert_redaction_finding` 的 fingerprint
/// 参数统一守门。
fn validate_fingerprint(fp: &str) -> Result<()> {
    if fp.len() != 32 {
        return Err(AuditError::InvalidInput {
            reason: "fingerprint_must_be_sha256_16byte_hex",
        });
    }
    // 仅允许 [0-9a-f]:strictly lowercase hex
    if !fp
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(AuditError::InvalidInput {
            reason: "fingerprint_must_be_lowercase_hex",
        });
    }
    Ok(())
}

/// 由 label + action_taken 派生 placeholder 文本(R1 BLOCKER 修复的核心承载):
///
/// - `redacted`     → `[REDACTED <label>]`
/// - `blocked`      → `[BLOCKED <label>]`
/// - `allowed_once` → `[ALLOWED_ONCE <label>]`
///
/// **不变量**:placeholder 永远只含 label 字面量(ALLOWED_REDACTION_LABELS)+ 固定动作词;
/// 任何 caller 传入的原文都被丢弃,保证 SQLite 不可能存储原文 secret。
/// label 已在 call 点前对 `ALLOWED_REDACTION_LABELS` 做了守门,action_taken 同样。
fn derive_placeholder(label: &str, action_taken: &str) -> String {
    let verb = match action_taken {
        "blocked" => "BLOCKED",
        "allowed_once" => "ALLOWED_ONCE",
        // "redacted" 及兜底(action_taken 已在上层 allowlist 守门,这里理论上不可达)
        _ => "REDACTED",
    };
    format!("[{verb} {label}]")
}

// 内部中转结构:先从 SQL 读出原始列,再在 Rust 侧做 JSON 解析,
// 保持 `query_map` 的 closure 不跨越错误类型(rusqlite vs serde_json)。
struct ReplayEventRow {
    event_id: i64,
    session_id: String,
    event_type: String,
    payload_json: String,
    redacted_text: Option<String>,
    prev_hash: String,
    event_hash: String,
    created_at: i64,
}

fn validate_nonempty(field: &'static str, v: &str) -> Result<()> {
    if v.is_empty() {
        Err(AuditError::InvalidInput {
            reason: match field {
                "source" => "source must be non-empty",
                "session_id" => "session_id must be non-empty",
                "event_type" => "event_type must be non-empty",
                "approval_id" => "approval_id must be non-empty",
                _ => "non-empty field required",
            },
        })
    } else {
        Ok(())
    }
}
