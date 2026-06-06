//! `vigil-audit` 的错误类型。

use thiserror::Error;

/// 审计账本错误。
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuditError {
    /// SQLite 底层错误(连接 / 执行 / schema 迁移等)。
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// 文件系统 IO 错误(如开库前 `create_dir_all` 建账本父目录失败)。
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// JSON 规范化或反序列化错误(影响 hash 计算)。
    #[error("json canonicalization: {0}")]
    Json(#[from] serde_json::Error),

    /// `append_event` 入口 fail-closed 自检命中强指纹 —— 拒绝写入。
    /// Caller 必须先走 `vigil-redaction::redact`。
    #[error("hard-secret detected in payload (rule={rule}); refusing to persist")]
    HardSecretDetected {
        /// 命中的规则名(如 `github_token` / `pem_private_key`)。
        rule: &'static str,
    },

    /// hash chain 在给定 `event_id` 处断裂(可能是存储被篡改或代码 bug)。
    #[error("hash chain broken at event_id={event_id}")]
    ChainBroken {
        /// 首个校验失败的事件 id。
        event_id: i64,
    },

    /// 输入参数无效(非法 hex 长度、空 session_id 等)。
    #[error("invalid input: {reason}")]
    InvalidInput {
        /// 人类可读的失败原因。
        reason: &'static str,
    },

    /// 被内部锁污染(另一个线程在持有 mutex 时 panic)。
    #[error("internal lock poisoned")]
    LockPoisoned,

    /// Server registry 冲突:同 id 但 identity hash 不一致(I05 drift 处理)。
    #[error("server `{server_id}` already registered with different identity hash")]
    RegistryConflict {
        /// 冲突的 server id
        server_id: String,
    },
}

/// 本 crate 专用 Result。
pub type Result<T> = std::result::Result<T, AuditError>;
