//! vigil-http-transport
//!
//! I10b-α2(ADR 0011):真 HTTP 栈 + JWKS 签名验证 + HttpUpstream。
//!
//! - `ReqwestHttpClient`:同时 impl `HttpClient`(发现路径)+ `AuthorizedSender`(upstream 专用)
//! - `HttpJwksSource`:真 HTTP JWKS 发现 + `(issuer, jwks_uri)` 双键缓存 + singleflight(§I-11.6)
//! - `JwksSignatureVerifier`:RS256/ES256 白名单(alg=none 永拒),JWT 签名验证
//! - `HttpUpstream`:impl `vigil_mcp::McpUpstream`,只持 `Arc<dyn AuthorizedSender>`
//!
//! ADR 0011 §I-11.1~§I-11.7 严格不变量。

#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![allow(clippy::expect_used)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::panic))]

mod client;
mod jwks;
mod loopback;
mod streamable;
mod upstream;
mod verifier;

pub use client::ReqwestHttpClient;
pub use jwks::{AuthorizationServerMetadata, HttpJwksSource};
pub use loopback::{open_browser, LoopbackCallback, LoopbackServer};
pub use streamable::StreamableHttpUpstream;
pub use upstream::{AutoRefreshConfig, HttpUpstream};
pub use verifier::JwksSignatureVerifier;

/// 当前迭代号。
pub const ITERATION: &str = "I10b-α2";
