//! SecretLease：短期凭据租约。
//!
//! 不变量(AGENTS.md §4):
//!
//! 1. **本类型不得承载任何真实 secret 值**。所有字段要么是 alias(`secret://...`)、
//!    要么是 id(`lease_id` / `session_id` / `server_id` 等)、要么是 metadata
//!    (`expires_at` / `injection_method`)。真实值由 `vigil-lease` crate 在运行时
//!    从 OS Keychain 取出,以 `lease_id → value` 的方式短期缓存。
//! 2. 因为字段本身就不该含 secret 值,serde `Serialize` 的默认行为(序列化全部字段)
//!    对**本类型**是安全的 —— 但这只在不变量 §1 成立时成立。测试
//!    `secret_lease_serialization_surface_is_stable_and_bounded` 通过断言
//!    序列化出的字段数固定,强制未来新增字段时必须人工评审是否违反 §1。
//! 3. `Debug` 手写实现为最小脱敏集;`Display` 手写实现为纯 alias 形式。未定义自动
//!    派生,以防 `#[derive(Debug)]` 等宏在未来被意外恢复。
//!
//! I00 只声明类型,运行时解析与注入在 I06 实现。

use serde::{Deserialize, Serialize};

/// 一次 secret 使用的短期租约元数据。
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretLease {
    /// 唯一 id。
    pub lease_id: String,
    /// 指向 secret 的 alias（`secret://github/repo-write` 形式）。
    pub secret_ref: String,
    /// 绑定 session —— 其它 session 不能复用此 lease。
    pub bound_session_id: String,
    /// 绑定 server —— 其它 server 不能复用。
    pub bound_server_id: String,
    /// 绑定工具名 —— 其它工具不能复用。
    pub bound_tool_name: String,
    /// 若由审批签发，关联审批 id。
    pub approval_id: Option<String>,
    /// 注入方式。
    pub injection_method: InjectionMethod,
    /// 到期时间（Unix epoch 秒）；到期后 `vigil-lease` 必须主动撤销。
    pub expires_at: i64,
}

/// 凭据注入方式。优先级参见主方案 §5.5。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[serde(rename_all = "PascalCase")]
pub enum InjectionMethod {
    /// Gateway 内部在 HTTP header 上注入。
    HttpHeader,
    /// 子进程环境变量（env_clear 后仅此 lease）。
    ChildEnv,
    /// pipe / fd 注入。
    Pipe,
    /// 临时文件（最后手段，需在进程结束时抹除）。
    TempFile,
    /// PreToolUse hook 在 shell 命令内联替换 `secret://<alias>` 占位符（执行边界注入，
    /// TASK-005）。真值经 lease 授权解析后写回 `updatedInput.command`，模型仍只见占位符；
    /// 与 gateway 侧的 [`InjectionMethod::ChildEnv`] 区分（hook 无法对宿主子进程设 OS env，
    /// 只能改写命令本身），故单列一档便于审计区分注入来源。
    HookCommand,
}

// 手写 Debug：本类型不存真实 secret 值（值在 vigil-lease 运行时缓存），
// 但为了不被未来派生宏意外替换，且与 AGENTS.md §4 "secrets never in logs/UI" 在
// 类型层形成双重保险，这里把能打印的字段收紧到最窄集合。
// 面向用户可见的 Display 另行给出并进一步脱敏（**只露 alias**，不含 lease_id/时间）。
impl std::fmt::Debug for SecretLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 只输出:lease_id（可审计关联）、secret_ref（alias，设计上非敏感）、
        // injection_method（非敏感）、expires_at（时间戳）。
        // 明确不打印 bound_* / approval_id —— 它们对日志追踪不是必要项,
        // 若需要请改调 audit payload 专用的 redacted serializer。
        f.debug_struct("SecretLease")
            .field("lease_id", &self.lease_id)
            .field("secret_ref", &self.secret_ref)
            .field("injection_method", &self.injection_method)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

// 手写 Display：作为 UI / 日志字符串插值的安全默认，只露 alias。
// 这是对 AGENTS.md §4 的类型层守卫 —— 即使未来有人派生 thiserror 的 `{0}` 插值，
// 也只会拿到 `secret://...` 这样的 alias，而非任何关联上下文。
impl std::fmt::Display for SecretLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretLease({})", self.secret_ref)
    }
}
