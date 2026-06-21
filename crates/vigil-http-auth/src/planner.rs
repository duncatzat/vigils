//! Request planner(ADR 0010 §D6):passthrough deny。
//!
//! **Incoming 请求的 `Authorization` / `Proxy-Authorization` / `X-Forwarded-Authorization` 等
//! bearer-like header 一律丢弃**;Gateway 构造 upstream 请求时,只用 `ResolvedAccessToken`
//! 作为 `Authorization: Bearer` 来源。

use url::Url;

use crate::client::HttpMethod;
use crate::error::HttpAuthError;
use crate::types::ResolvedAccessToken;

/// I10a 要剥离的 header 名(大小写不敏感)。
const STRIPPED_HEADER_NAMES: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-forwarded-authorization",
    "x-auth-token",
    "x-api-key",
];

/// 协议规划输出 —— 保证**不含**任何 passthrough bearer。
///
/// **真封印(ADR 0021 MF#1)**:字段**私有** + `#[non_exhaustive]`,唯一构造器是 crate 内的
/// [`plan_authorized_request`](header 剥离 + same-origin 校验在内)。外部 crate **无法**用结构体
/// 字面量自拼 `headers`(否则可绕过 passthrough-deny,注入任意 `Authorization`)。读取一律走访问器。
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AuthorizedHttpRequest {
    url: Url,
    method: HttpMethod,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
}

impl AuthorizedHttpRequest {
    /// 目标 upstream URL。
    pub fn url(&self) -> &Url {
        &self.url
    }
    /// HTTP 方法。
    pub fn method(&self) -> HttpMethod {
        self.method
    }
    /// headers —— 含 planner 注入的 `Authorization: Bearer <gateway_token>`,保证无 passthrough。
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }
    /// body(可选)。
    pub fn body(&self) -> Option<&[u8]> {
        self.body.as_deref()
    }
}

/// passthrough 情况报告:审计 payload 用(不含 value,只含 header 名集合)。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PassthroughReport {
    /// 被剥离的 header 名(大小写按 incoming 原样)
    pub stripped_header_names: Vec<String>,
}

/// 构造授权上游请求。
///
/// 参数:
/// - `incoming_headers`:来自 agent/client 的 headers(可能含 bearer);**会被过滤**
/// - `resolved`:Gateway 自己持有的已验 access token
/// - `upstream_url` / `method` / `body`:Gateway 要发给 upstream 的 request
///
/// 返 `(AuthorizedHttpRequest, PassthroughReport)`:
/// - `AuthorizedHttpRequest.headers` **不**含 `STRIPPED_HEADER_NAMES` 里任一项
/// - 追加 `Authorization: Bearer <raw_token>`
/// - `PassthroughReport` 列出哪些 header 被剥离(供审计)
pub fn plan_authorized_request(
    incoming_headers: &[(String, String)],
    resolved: &ResolvedAccessToken,
    upstream_url: Url,
    method: HttpMethod,
    body: Option<Vec<u8>>,
) -> Result<(AuthorizedHttpRequest, PassthroughReport), HttpAuthError> {
    // Codex R1 BLOCKER 2:二次校验 upstream URL origin 与 resolved token 的 resource 绑定一致。
    // 防止 caller 持 resource A 的 token 去 resource B 的 URL 上发请求(即使通过 JWT aud 校验)。
    let resolved_resource_url: Url = resolved
        .resource
        .parse()
        .map_err(|_| HttpAuthError::Internal("resolved_resource_not_url"))?;
    if !same_origin(&resolved_resource_url, &upstream_url) {
        return Err(HttpAuthError::AudienceMismatch {
            expected: resolved.resource.clone(),
            actual: upstream_url.as_str().to_string(),
        });
    }

    let mut kept_headers: Vec<(String, String)> = Vec::with_capacity(incoming_headers.len());
    let mut stripped_names: Vec<String> = Vec::new();

    for (name, value) in incoming_headers {
        if is_stripped(name) {
            stripped_names.push(name.clone());
            // **不**记 value(§I-10.3)
            let _ = value;
            continue;
        }
        kept_headers.push((name.clone(), value.clone()));
    }

    // 追加 Gateway 自持 token
    kept_headers.push((
        "Authorization".to_string(),
        format!("Bearer {}", resolved.raw.expose()),
    ));

    Ok((
        AuthorizedHttpRequest {
            url: upstream_url,
            method,
            headers: kept_headers,
            body,
        },
        PassthroughReport {
            stripped_header_names: stripped_names,
        },
    ))
}

/// 无鉴权上游(public MCP)的 sealed 请求构造(ADR 0021 Slice 1 no-auth)。
///
/// 同样剥离 incoming bearer-like header(`STRIPPED_HEADER_NAMES`),但**不**追加任何 `Authorization`。
/// 仍返 sealed [`AuthorizedHttpRequest`](私有字段,no passthrough)—— 用于无凭证的 public HTTP MCP。
pub fn plan_unauthorized_request(
    incoming_headers: &[(String, String)],
    upstream_url: Url,
    method: HttpMethod,
    body: Option<Vec<u8>>,
) -> (AuthorizedHttpRequest, PassthroughReport) {
    let mut kept_headers: Vec<(String, String)> = Vec::with_capacity(incoming_headers.len());
    let mut stripped_names: Vec<String> = Vec::new();
    for (name, value) in incoming_headers {
        if is_stripped(name) {
            stripped_names.push(name.clone());
            let _ = value; // **不**记 value(§I-10.3)
            continue;
        }
        kept_headers.push((name.clone(), value.clone()));
    }
    // 无鉴权:不追加任何 Authorization。
    (
        AuthorizedHttpRequest {
            url: upstream_url,
            method,
            headers: kept_headers,
            body,
        },
        PassthroughReport {
            stripped_header_names: stripped_names,
        },
    )
}

fn is_stripped(name: &str) -> bool {
    STRIPPED_HEADER_NAMES
        .iter()
        .any(|s| s.eq_ignore_ascii_case(name))
}

/// scheme + host + port 全部一致(不比 path / query)。
fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigil_lease::SecretValue;

    fn mk_resolved() -> ResolvedAccessToken {
        ResolvedAccessToken {
            raw: SecretValue::new("GATEWAY_TOKEN_XYZ"),
            resource: "https://mcp.example.com/".into(),
            scope_set: vec!["mcp:tools.read".into()],
            expires_at: None,
        }
    }

    #[test]
    fn incoming_authorization_header_is_never_forwarded_to_upstream() {
        let incoming = vec![
            (
                "Authorization".to_string(),
                "Bearer EVIL_CLIENT_TOKEN".to_string(),
            ),
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-API-Key".to_string(), "LEAKED".to_string()),
        ];
        let (req, report) = plan_authorized_request(
            &incoming,
            &mk_resolved(),
            "https://mcp.example.com/rpc".parse().unwrap(),
            HttpMethod::PostForm,
            Some(b"hi".to_vec()),
        )
        .unwrap();

        // kept headers 不得含被 strip 的
        let s = serde_json::to_string(&req.headers).unwrap();
        assert!(!s.contains("EVIL_CLIENT_TOKEN"));
        assert!(!s.contains("LEAKED"));

        // Authorization 只能来自 gateway
        let auth = req
            .headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .unwrap();
        assert_eq!(auth.1, "Bearer GATEWAY_TOKEN_XYZ");

        // 非 strip 的 header 保留
        let ct = req.headers.iter().find(|(k, _)| k == "Content-Type");
        assert!(ct.is_some());

        // 报告列出剥离的 header(大小写保留 incoming 的)
        assert!(report
            .stripped_header_names
            .contains(&"Authorization".to_string()));
        assert!(report
            .stripped_header_names
            .contains(&"X-API-Key".to_string()));
    }

    #[test]
    fn stripping_is_case_insensitive() {
        let incoming = vec![
            ("authorization".to_string(), "Bearer x".to_string()),
            ("AUTHORIZATION".to_string(), "Bearer y".to_string()),
            ("Proxy-Authorization".to_string(), "Basic z".to_string()),
        ];
        let (req, report) = plan_authorized_request(
            &incoming,
            &mk_resolved(),
            "https://mcp.example.com/".parse().unwrap(),
            HttpMethod::Get,
            None,
        )
        .unwrap();
        // 3 都被 strip;报告 3 条
        assert_eq!(report.stripped_header_names.len(), 3);
        // 只 gateway 一条 Authorization
        let auth_count = req
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .count();
        assert_eq!(auth_count, 1);
    }

    /// Codex R1 BLOCKER 2:resolved token 绑到 resource A,但 caller 要发 resource B → 拒
    #[test]
    fn planner_rejects_cross_resource_usage() {
        let resolved = ResolvedAccessToken {
            raw: SecretValue::new("GATEWAY_TOKEN"),
            resource: "https://mcp.example.com/".into(),
            scope_set: vec![],
            expires_at: None,
        };
        let err = plan_authorized_request(
            &[],
            &resolved,
            "https://evil.example.com/rpc".parse().unwrap(),
            HttpMethod::PostForm,
            None,
        )
        .unwrap_err();
        match err {
            HttpAuthError::AudienceMismatch { expected, .. } => {
                assert_eq!(expected, "https://mcp.example.com/");
            }
            other => panic!("expected AudienceMismatch, got {other:?}"),
        }
    }

    #[test]
    fn planner_accepts_same_origin_different_path() {
        let resolved = ResolvedAccessToken {
            raw: SecretValue::new("GATEWAY_TOKEN"),
            resource: "https://mcp.example.com/".into(),
            scope_set: vec![],
            expires_at: None,
        };
        let (req, _) = plan_authorized_request(
            &[],
            &resolved,
            "https://mcp.example.com/rpc/v1".parse().unwrap(),
            HttpMethod::PostForm,
            None,
        )
        .unwrap();
        assert_eq!(req.url.as_str(), "https://mcp.example.com/rpc/v1");
    }

    #[test]
    fn no_incoming_passthrough_means_empty_report() {
        let incoming = vec![("Content-Type".to_string(), "application/json".to_string())];
        let (_req, report) = plan_authorized_request(
            &incoming,
            &mk_resolved(),
            "https://mcp.example.com/".parse().unwrap(),
            HttpMethod::Get,
            None,
        )
        .unwrap();
        assert!(report.stripped_header_names.is_empty());
    }
}
