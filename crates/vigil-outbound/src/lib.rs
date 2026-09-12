#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
//! 出站 LLM-API 闸门(opt-in):环回 HTTP 反向代理。
//!
//! agent 客户端把模型 API 的 base URL 指到 `http://127.0.0.1:<port>/<route>`;闸门:
//!
//! 1. 读完整请求体(有上限,fail-closed);JSON 体逐叶子扫 [`vigil_redaction::hard_secret_spans`],
//!    命中的裸凭据**就地**换成占位符(默认 `[REDACTED <kind>]`,与 hook PostToolUse 同形;Tier-B
//!    别名由 [`AliasSink`] 扩展点提供),协议信封字段(id / model / role / signature …)不动;
//! 2. 用 reqwest 转发到固定上游(路径前缀 → 上游根;Codex 按鉴权头选 ChatGPT 后端或平台 API),
//!    请求头原样透传(去 hop-by-hop),鉴权头不落任何日志;
//! 3. 响应**按块直通**(SSE 不缓冲、不解析),只去 hop-by-hop 头。
//!
//! 设计取舍(与 maskit 类可逆脱敏代理的区别):只处理硬指纹凭据、只改出站、不还原响应 —— 模型看到
//! 的占位符与 hook 结果侧一致;不落明文映射表(账本无明文铁律)。非 JSON 的写请求体一律 415 阻断
//! (fail-closed:看不懂的体不放行),只读方法直通。绑定环回地址;带 `Origin` 头的浏览器发起请求拒绝。

pub mod rewrite;
pub mod route;
pub mod server;

pub use rewrite::{locate_residual, AliasSink, NoAlias, RewriteReport};
pub use route::{RouteKind, Routes};
pub use server::{
    spawn, Counters, GateAudit, GateConfig, GateDeps, GateError, GateHandle, NoopAudit,
};
