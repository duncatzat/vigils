//! 路径前缀 → 上游根。上游是**固定集合**(不做任意转发,杜绝 SSRF / 开放代理);每个上游可被
//! 配置覆盖,用于把闸门串在企业网关(LiteLLM / Portkey …)前面。

use hyper::header::{HeaderMap, AUTHORIZATION};
use serde::{Deserialize, Serialize};

/// 路由种类(审计 / 计数用;字面量稳定,进账本 payload)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteKind {
    /// `/anthropic/*` → Anthropic Messages API(Claude Code)
    Anthropic,
    /// `/openai/*` → OpenAI 平台 API
    Openai,
    /// `/codex/*` → 按鉴权头选 ChatGPT Codex 后端或 OpenAI 平台 API(Codex CLI)
    Codex,
    /// `/gemini/*` → Gemini API(API key 模式)
    Gemini,
}

impl RouteKind {
    /// 稳定字面量(账本 payload / 状态 JSON)。
    pub fn as_str(self) -> &'static str {
        match self {
            RouteKind::Anthropic => "anthropic",
            RouteKind::Openai => "openai",
            RouteKind::Codex => "codex",
            RouteKind::Gemini => "gemini",
        }
    }
}

/// 上游根 URL 集合(不带末尾 `/`)。
///
/// **每个字段都有 field 级默认值。** 此前四个全必填,用户手工只改了 `upstreams.anthropic`,
/// `outbound.json` 就整体解析失败 → `fail_closed("malformed")` → `enabled` 被强制为 false,
/// 闸门静默不启动而 agent 配置仍指向它。不是泄漏(连不上即 fail-closed),但是**极难自查的砖化**:
/// warning 只说 malformed,不说缺了哪个字段(敌意评审 2026-09-12 L4)。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Routes {
    /// 默认 `https://api.anthropic.com`
    #[serde(default = "default_anthropic")]
    pub anthropic: String,
    /// 默认 `https://api.openai.com/v1`
    #[serde(default = "default_openai")]
    pub openai: String,
    /// 默认 `https://chatgpt.com/backend-api/codex`(ChatGPT 登录的 Codex)
    #[serde(default = "default_codex_chatgpt")]
    pub codex_chatgpt: String,
    /// 默认 `https://generativelanguage.googleapis.com`
    #[serde(default = "default_gemini")]
    pub gemini: String,
}

fn default_anthropic() -> String {
    "https://api.anthropic.com".to_string()
}
fn default_openai() -> String {
    "https://api.openai.com/v1".to_string()
}
fn default_codex_chatgpt() -> String {
    "https://chatgpt.com/backend-api/codex".to_string()
}
fn default_gemini() -> String {
    "https://generativelanguage.googleapis.com".to_string()
}

impl Default for Routes {
    fn default() -> Self {
        Self {
            anthropic: default_anthropic(),
            openai: default_openai(),
            codex_chatgpt: default_codex_chatgpt(),
            gemini: default_gemini(),
        }
    }
}

/// 一次解析结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// 路由种类
    pub kind: RouteKind,
    /// 完整上游 URL(含路径与 query)
    pub url: String,
}

impl Routes {
    /// 把入站 `path?query` 解析到上游 URL。未知前缀 → `None`(404)。
    ///
    /// Codex:ChatGPT 登录的请求带 `ChatGPT-Account-ID` 头,且 Bearer 是 JWT(`eyJ…`);
    /// API key 登录的 Bearer 是 `sk-…`。两者任一成立即走 ChatGPT 后端,否则平台 API。
    pub fn resolve(&self, path_and_query: &str, headers: &HeaderMap) -> Option<Resolved> {
        let (kind, base, rest) = if let Some(rest) = strip_prefix(path_and_query, "/anthropic") {
            (RouteKind::Anthropic, self.anthropic.as_str(), rest)
        } else if let Some(rest) = strip_prefix(path_and_query, "/openai") {
            (RouteKind::Openai, self.openai.as_str(), rest)
        } else if let Some(rest) = strip_prefix(path_and_query, "/gemini") {
            (RouteKind::Gemini, self.gemini.as_str(), rest)
        } else {
            // 链尾用 `?` 收敛:未知前缀时 `strip_prefix` 返回 None,整个 `resolve` 即 None(404),
            // 与此前 `else { return None; }` 等价。写成 `?` 是 clippy::question_mark 的要求
            // (`-D warnings`);链尾的 if-let + `else { return None }` 一律会被它点名。
            let rest = strip_prefix(path_and_query, "/codex")?;
            let base = if is_chatgpt_auth(headers) {
                self.codex_chatgpt.as_str()
            } else {
                self.openai.as_str()
            };
            (RouteKind::Codex, base, rest)
        };
        Some(Resolved {
            kind,
            url: format!("{}{}", base.trim_end_matches('/'), rest),
        })
    }
}

/// `/prefix` 或 `/prefix/...` 或 `/prefix?...`;`/prefixfoo` 不算。返回剩余部分(以 `/` 或 `?` 开头,或空)。
fn strip_prefix<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = path.strip_prefix(prefix)?;
    if rest.is_empty() || rest.starts_with('/') || rest.starts_with('?') {
        Some(rest)
    } else {
        None
    }
}

fn is_chatgpt_auth(headers: &HeaderMap) -> bool {
    if headers.contains_key("chatgpt-account-id") {
        return true;
    }
    headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            let v = v.trim();
            v.len() > 7
                && v[..7].eq_ignore_ascii_case("bearer ")
                && v[7..].trim_start().starts_with("eyJ")
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 少写一个上游不该把整份配置砖化成「关闭」:缺字段补内置默认
    /// (敌意评审 2026-09-12 L4)。
    #[test]
    fn partial_upstreams_fall_back_to_builtin_defaults() {
        let r: Routes =
            serde_json::from_str(r#"{"anthropic":"https://llm.corp.example"}"#).unwrap();
        assert_eq!(r.anthropic, "https://llm.corp.example");
        let d = Routes::default();
        assert_eq!(r.openai, d.openai);
        assert_eq!(r.codex_chatgpt, d.codex_chatgpt);
        assert_eq!(r.gemini, d.gemini);
    }
    use hyper::header::HeaderValue;

    #[test]
    fn prefixes_map_to_upstreams_and_keep_query() {
        let r = Routes::default();
        let h = HeaderMap::new();
        assert_eq!(
            r.resolve("/anthropic/v1/messages?beta=true", &h).unwrap(),
            Resolved {
                kind: RouteKind::Anthropic,
                url: "https://api.anthropic.com/v1/messages?beta=true".into()
            }
        );
        assert_eq!(
            r.resolve("/gemini/v1beta/models/gemini:generateContent", &h)
                .unwrap()
                .url,
            "https://generativelanguage.googleapis.com/v1beta/models/gemini:generateContent"
        );
        assert_eq!(
            r.resolve("/openai/chat/completions", &h).unwrap().url,
            "https://api.openai.com/v1/chat/completions"
        );
        assert!(r.resolve("/anthropicx/v1", &h).is_none());
        assert!(r.resolve("/", &h).is_none());
        assert!(r.resolve("/v1/messages", &h).is_none());
    }

    #[test]
    fn codex_routes_by_auth_shape() {
        let r = Routes::default();
        let mut api_key = HeaderMap::new();
        api_key.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer sk-proj-abc"),
        );
        assert_eq!(
            r.resolve("/codex/responses", &api_key).unwrap().url,
            "https://api.openai.com/v1/responses"
        );
        let mut jwt = HeaderMap::new();
        jwt.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer eyJhbGciOiJSUzI1NiJ9.x.y"),
        );
        assert_eq!(
            r.resolve("/codex/responses", &jwt).unwrap().url,
            "https://chatgpt.com/backend-api/codex/responses"
        );
        let mut acct = HeaderMap::new();
        acct.insert("chatgpt-account-id", HeaderValue::from_static("acct_1"));
        acct.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer sk-looks-like-key"),
        );
        assert_eq!(
            r.resolve("/codex/responses", &acct).unwrap().kind,
            RouteKind::Codex
        );
        assert!(r
            .resolve("/codex/responses", &acct)
            .unwrap()
            .url
            .starts_with("https://chatgpt.com/"));
    }

    #[test]
    fn overridden_upstream_is_used_and_trailing_slash_tolerated() {
        let r = Routes {
            anthropic: "http://127.0.0.1:4000/".into(),
            ..Routes::default()
        };
        assert_eq!(
            r.resolve("/anthropic/v1/messages", &HeaderMap::new())
                .unwrap()
                .url,
            "http://127.0.0.1:4000/v1/messages"
        );
    }
}
