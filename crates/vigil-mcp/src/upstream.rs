//! I10b-α1(ADR 0011 §α1-D4):Hub 上游抽象 `McpUpstream`。
//!
//! 原 Hub 绑死 `Arc<StdioUpstream>` 具体类型,α1 抽出 trait 让 HTTP upstream(α2)也
//! 能插入。
//!
//! **范围约束**:α1/α2 只支持 **unary request/response** —— 不做 server-initiated
//! notifications / SSE(延 I10c 或后续迭代)。
//!
//! **错误模型**:`UpstreamError` 为统一聚合,`StdioError` / α2 `TransportError` 投影
//! 进此枚举。所有外部 consumer(Hub / UI 协议层)只感知 `UpstreamError`,不再绑
//! stdio 具体类型。
//!
//! **非穷举**:`#[non_exhaustive]` —— 未来新增变体不破坏消费方匹配代码,但 caller
//! 必须用 `_ =>` 兜底。

use std::time::Duration;

use serde_json::Value;
use thiserror::Error;

use vigil_types::TransportKind;

/// 上游错误聚合。
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum UpstreamError {
    /// IO / 传输层(stdio pipe 断 / HTTP reset);`reason_code` 稳定。
    #[error("transport_io: {0}")]
    TransportIo(&'static str),
    /// 协议超时
    #[error("timed_out: {0:?}")]
    TimedOut(Duration),
    /// HTTP 401:token 需要 reauth(I10b-β/c 触发 refresh 入口)
    #[error("unauthorized: {reason_code}")]
    Unauthorized {
        /// 稳定 reason code,例如 `"bearer_expired"` / `"invalid_token"`
        reason_code: &'static str,
    },
    /// HTTP 403:policy 拒绝(不等于 reauth;UI 应展示权限不足)
    #[error("forbidden")]
    Forbidden,
    /// 上游返回 JSON-RPC `error` 字段。
    /// 为避免把 tenant / user 信息带进 audit payload,只留 code + `message_sha256`
    /// (NICE-TO-HAVE 1:保留诊断能力但不泄漏内容)。
    #[error("jsonrpc_error: code={code}")]
    JsonRpc {
        /// JSON-RPC error code
        code: i64,
        /// message 的 sha256(审计侧可用于去重 / 追查,但不含明文)
        message_sha256: String,
    },
    /// α1 metadata/secret gap(复用 `HttpAuthError::TokenRehydrateRequired` 的语义层)
    #[error("token_rehydrate_required: {reason_code}")]
    TokenRehydrateRequired {
        /// 稳定 reason code(与 `HttpAuthError::TokenRehydrateRequired` 对齐)
        reason_code: &'static str,
    },
    /// 认证层错误(HttpAuthError 的投影;不展开具体字段以防跨 crate 破坏边界)
    #[error("auth_error: {0}")]
    AuthError(&'static str),
    /// 其它内部错(不变量违反)
    #[error("internal: {0}")]
    Internal(&'static str),
    /// 上游 `initialize` 协商回了不在支持集内的协议版本(按 MCP spec 客户端应断开 → fail-closed)。
    /// `negotiated` 在构造处已经 `safe_protocol_version` 净化(不可信上游输入)。
    #[error("protocol version {negotiated} negotiated by upstream is not supported by this Vigil build (supports {supported})")]
    ProtocolVersionUnsupported {
        /// 上游回的版本(已净化)
        negotiated: String,
        /// 本端支持集(逗号分隔,构造处填)
        supported: String,
    },
    /// 现代专属上游(2026-07-28+ 只认 `server/discover` 开场):`initialize` 被拒且探针成功。
    /// `supported` 是上游宣告的版本列表(已截断 + 逐条净化)。
    #[error("upstream speaks only MCP 2026-07-28+ (advertised: {supported}); this Vigil build talks up to {latest} — upgrade Vigil or pin the server to a legacy protocol")]
    ModernOnlyUpstream {
        /// 上游 `supportedVersions`(已净化,逗号分隔;空 = "no version list")
        supported: String,
        /// 本端最高支持版本
        latest: &'static str,
    },
}

/// Hub 上游抽象。
///
/// 实现者(α1 只有 `StdioUpstream`;α2 补 `HttpUpstream`)必须:
/// - `Send + Sync` 以便 Hub 跨线程持有
/// - `Debug` 以便出错时审计 / 日志能打印 backend 类型
/// - `call` 对外**同步**(I04 全同步模型);timeout 超时返 `UpstreamError::TimedOut`
pub trait McpUpstream: Send + Sync + std::fmt::Debug {
    /// 上游的稳定 ID(server_id,注册时指定)。
    fn server_id(&self) -> &str;
    /// 上游的 transport 类型(审计 / UI 用);与 `TransportKind` 对齐。
    fn transport(&self) -> TransportKind;
    /// 同步 unary 调用。`params` 为 JSON-RPC `params` 字段(`None` = 不传 params)。
    fn call(
        &self,
        method: &str,
        params: Option<Value>,
        timeout: Duration,
    ) -> Result<Value, UpstreamError>;
    /// 优雅关闭(best-effort;stdio: kill 子进程;HTTP: flush 连接池)。
    fn shutdown(&self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[derive(Debug)]
    struct DummyUpstream;

    impl McpUpstream for DummyUpstream {
        fn server_id(&self) -> &str {
            "dummy"
        }
        fn transport(&self) -> TransportKind {
            TransportKind::Stdio
        }
        fn call(&self, _m: &str, _p: Option<Value>, _t: Duration) -> Result<Value, UpstreamError> {
            Ok(Value::Null)
        }
        fn shutdown(&self) {}
    }

    /// α1-D4 守门:`McpUpstream` 是 dyn-compatible(object-safe),
    /// 能被 `Arc<dyn>` 包装;StdioUpstream / HttpUpstream 后续都走这条路径。
    #[test]
    fn mcp_upstream_is_dyn_compatible() {
        let u: Arc<dyn McpUpstream> = Arc::new(DummyUpstream);
        assert_eq!(u.server_id(), "dummy");
        assert_eq!(u.transport(), TransportKind::Stdio);
        u.call("x", None, Duration::from_secs(1)).unwrap();
        u.shutdown();
    }

    // `#[non_exhaustive]` 的 wildcard 守门必须在**消费者 crate**(integration test
    // 视作独立 crate)里才能生效;放在本模块里 `_ =>` 会被 clippy `unreachable_patterns`
    // 判定不可达。守门测试放在 `tests/upstream_non_exhaustive.rs`。
}
