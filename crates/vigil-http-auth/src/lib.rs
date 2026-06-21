//! vigil-http-auth
//!
//! I10a(ADR 0010):HTTP MCP Auth 认证核心层。Mock transport + 协议安全边界,
//! 不依赖真实 HTTP 栈。
//!
//! - PRM(RFC 9728 Protected Resource Metadata)types + validate
//! - OAuth 2.1 + PKCE S256(用 `oauth2` crate 核心类型 + Vigil 自己的校验)
//! - JWT access token 本地 decode + `aud/scope/exp` 校验(I10a 不验签;延 I10b)
//! - Token store:真值 → `vigil_lease::SecretStore`;metadata → SQLite
//! - Request planner:**禁止 token passthrough**(§I-10.3 / §I-10.4)
//! - 5 类审计事件(`http_auth.*` 前缀)
//!
//! ADR 0010 §I-10.1 ~ §I-10.7 严格不变量。

#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![allow(clippy::expect_used)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::panic))]

mod audit;
mod client;
mod error;
mod jwks;
mod jwt;
mod oauth;
mod planner;
mod prm;
mod store;
mod types;

pub use audit::{
    event_type_for, HttpAuthEvent, EVENT_AS_METADATA_FETCHED, EVENT_HTTP_UPSTREAM_REQUEST_FAILED,
    EVENT_HTTP_UPSTREAM_REQUEST_SENT, EVENT_JWKS_FETCHED, EVENT_JWT_SIGNATURE_REJECTED,
    EVENT_JWT_SIGNATURE_VERIFIED, EVENT_PASSTHROUGH_BLOCKED, EVENT_PRM_DISCOVERED,
    EVENT_REQUEST_AUTHORIZED, EVENT_TOKEN_REJECTED_WRONG_ISSUER,
    EVENT_TOKEN_REJECTED_WRONG_RESOURCE, EVENT_TOKEN_STORED,
};
pub use client::{
    AuthorizedSender, HttpClient, HttpMethod, HttpRequest, HttpResponse, MockHttpClient,
};
pub use error::HttpAuthError;
pub use jwks::{Jwk, JwkSet, JwksSource, MockJwksSource};
pub use jwt::{
    decode_jwt_access_token, DecodedAccessToken, ExpectedBinding, IntrospectionConfig, JoseHeader,
    JwtKeyVerifier,
};
// (planner/store already re-export below)
pub use oauth::{
    build_authorization_url, exchange_code_for_token, exchange_refresh_token_for_token,
    introspect_token, new_pkce_pair, IntrospectionResponse, PkcePair, TokenResponse,
};
pub use planner::{
    plan_authorized_request, plan_unauthorized_request, AuthorizedHttpRequest, PassthroughReport,
};
pub use prm::{fetch_and_validate_prm, validate_prm_struct, ProtectedResourceMetadata};
pub use store::{
    token_ref_for_access, token_ref_for_refresh, OAuthTokenMetadata, TokenKind, TokenStore,
};
pub use types::{ResolvedAccessToken, SCOPES_CLAIM_DELIMITER};

/// 当前迭代号。
pub const ITERATION: &str = "I10a";
