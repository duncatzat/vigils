//! 请求体改写:JSON 逐叶子把裸硬指纹换成占位符,协议信封不动。

use serde_json::Value;
use vigil_redaction::hard_secret_spans;

/// Tier-B 扩展点:为命中的凭据提供可在执行边界脱别名的别名 body(不含 `secret://` 前缀)。
/// 返回 `None` 即回退 `[REDACTED <kind>]`(与 hook PostToolUse 同形,模型已熟悉)。
pub trait AliasSink: Send + Sync {
    /// `kind` 为规则名;`value` 为原文凭据字节(调用方**绝不**记录它)。
    fn alias_for(&self, kind: &str, value: &str) -> Option<String>;
}

/// 不造别名:一律 `[REDACTED <kind>]`。
#[derive(Debug, Default, Clone, Copy)]
pub struct NoAlias;

impl AliasSink for NoAlias {
    fn alias_for(&self, _kind: &str, _value: &str) -> Option<String> {
        None
    }
}

/// 一次改写的结果:每种规则的命中次数(声明序无关,按首次出现排序)与改写产生的别名。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RewriteReport {
    /// `(kind, 命中次数)`
    pub kinds: Vec<(&'static str, usize)>,
    /// 本次造出的别名 body(已去重;审计可记,别名本身不含明文)
    pub aliases: Vec<String>,
    /// 被信封规则跳过的字段数(诊断用)
    pub skipped_envelope_fields: usize,
}

impl RewriteReport {
    /// 是否有任何改写。
    pub fn rewrote(&self) -> bool {
        !self.kinds.is_empty()
    }

    fn bump(&mut self, kind: &'static str) {
        if let Some(slot) = self.kinds.iter_mut().find(|(k, _)| *k == kind) {
            slot.1 += 1;
        } else {
            self.kinds.push((kind, 1));
        }
    }
}

/// 协议信封字段:改写它们要么破坏协议(id / 签名 / 加密推理块),要么毫无意义(model / role)。
/// 判定按**键名**,与协议无关(Chat Completions / Responses / Messages / Gemini 通吃)。
fn is_envelope_key(key: &str) -> bool {
    key == "id"
        || key.ends_with("_id")
        || matches!(
            key,
            "model"
                | "role"
                | "type"
                | "name"
                | "object"
                | "status"
                | "format"
                | "media_type"
                | "mime_type"
                | "cache_control"
                | "signature"
                | "thinking"
                | "redacted_thinking"
                | "encrypted_content"
                | "anthropic_version"
                | "tool_name"
                | "finish_reason"
        )
}

// **刻意不做「媒体载荷跳过」。** 这里一度有过两个快捷判断:自称 `image/*` 的对象跳过它的 `data`
// 字段,以及 `data:image/...;base64,` 串整体跳过。两者都**纯粹靠自称**,于是:
//   ① `{"media_type":"image/png","data":"<明文凭据>"}` —— `data` 从不校验是不是真 base64;
//   ② `data:image/png,<明文凭据>;base64,AAAA` —— 「前缀是媒体」与「含 `;base64,`」两个条件**不要求
//      相邻**,明文可以夹在中间;
//   ③ 规规矩矩的 `data:image/png;base64,<凭据的 base64>` —— 同一段 base64 不带前缀时明明会被整段
//      替换,加个前缀就免检。
// 换句话说,给任意凭据套层媒体外衣就能一键关掉脱敏(敌意评审 2026-09-12 HIGH-1/2/3)。
//
// 现在一律照扫。`hard_secret_spans` 自己会解 base64 段:真实图片 / 音视频字节解出来含控制字符、
// 不是 UTF-8 文本,`decode_base64_text` 直接返 `None`,本来就不会被标记 —— 省下的那点 CPU
// 不值得换一整类绕过。

/// 改写单个字符串:命中区间从后往前替换(偏移不失效)。无命中返 `None`。
pub fn rewrite_text(s: &str, sink: &dyn AliasSink, report: &mut RewriteReport) -> Option<String> {
    let spans = hard_secret_spans(s);
    if spans.is_empty() {
        return None;
    }
    // **先整体校验,再动手。** 这里一度是 `continue` —— 只跳过越界的那一条,其余替换照做、
    // 函数照返 `Some`。于是被跳过的那条凭据**原样留在转发体里**,结果却看起来「已处理」:
    // 一个本该 fail-closed 的分支写成了 fail-open,还与它自己的注释相反
    // (敌意评审 2026-09-12 L2)。契约一旦破裂就一个字节都不动,残留由出站字节自检转成 422。
    let bounds: Vec<(usize, usize)> = spans.iter().map(|sp| (sp.start, sp.end)).collect();
    if !spans_applicable(s, &bounds) {
        return None;
    }
    let mut out = s.to_string();
    for span in spans.iter().rev() {
        let value = &out[span.start..span.end];
        let replacement = match sink.alias_for(span.kind, value) {
            Some(body) => {
                if !report.aliases.contains(&body) {
                    report.aliases.push(body.clone());
                }
                format!("secret://{body}")
            }
            None => format!("[REDACTED {}]", span.kind),
        };
        out.replace_range(span.start..span.end, &replacement);
        report.bump(span.kind);
    }
    Some(out)
}

/// 定位**两趟共用**的检查预算。
///
/// 曾经只挂在第二趟上,前提是「第一趟只看信封跳过集,那是个固定小集合」。**那个前提是错的**:
/// 这个集合按**键名**固定,不按**数量**固定 —— `is_envelope_key` 含 `ends_with("_id")`,而键名
/// 完全由请求方决定(`a_id` / `b_id` / … 可无限造);就算只用固定名字,`[{"name":"x"}, …]` 每个
/// 数组元素也贡献一片信封叶子。于是构造 body 能稳定换到一次**完整的无上限全扫**:把凭据放进
/// **重复 JSON 键**即可保证两趟都扫到底却都找不到(残留在原字节里,不在解析树里)。
/// `MAX_INFLIGHT_CONNECTIONS` 限的是**并发数**、不是单请求成本,压不住这条
/// (敌意评审 2026-09-12)。
///
/// 两趟共用之后:真实 body 的信封叶子是个位数到几十个,共用上限对常见路径**毫无影响**,
/// 「常见情形必然定位成功」这条性质原样保留;构造 body 在上限处停住,拿不到定位提示即退通用
/// 文案 —— 那是设计好的降级。
///
/// **未做 wall-clock 实测**:这里钉住的是「最多 `LOCATE_MAX_LEAVES` 次 `detect_hard_secret`」
/// 这个结构上界,由单测断言;单次调用的真实耗时没有量过,不假装量过。
const LOCATE_MAX_LEAVES: usize = 20_000;
const LOCATE_MAX_BYTES: usize = 2 * 1024 * 1024;

/// 键名能否原样渲染。
///
/// 形状判据便宜、当主判据;**但安全职责在第二句**。此前只有 `len() <= 24` 挡着,而 HARD_RULES
/// 里 `github_token`(最短 40)、`stripe_secret_key`(32)、`huggingface_token`(33)三条**本来
/// 就可以是全小写 + 数字 + 下划线**,唯一的安全边际是 33 对 24 —— 那是一条**跨模块的隐式
/// 不变量**:本文件的一个长度常量在替 `vigil-redaction` 的规则表做安全保证,中间没有任何东西
/// 相连,将来加一条更短的全小写厂商 token 规则就会无声失效(敌意评审 2026-09-12)。
/// 直接问规则表之后,长度常量只再影响**可读性**,不再承担安全职责。
fn safe_key(key: &str) -> String {
    let shaped = !key.is_empty()
        && key.len() <= 24
        && key.starts_with(|c: char| c.is_ascii_lowercase())
        && key
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if shaped && vigil_redaction::detect_hard_secret(key).is_none() {
        key.to_string()
    } else {
        "<field>".to_string()
    }
}

/// 路径的一段。**walk 期间只携带原始键的借用,命中之后才渲染。**
///
/// 于是 `safe_key`(内含 `detect_hard_secret`)的调用量从「body 里的键**总数**」降到「命中路径的
/// **深度**」(≤128,由解析器的递归限制封顶),顺带消掉「每访问一个节点一次 `format!` 分配」。
///
/// 此前是边走边拼路径:`{"a":1,"b":1,…}` 铺满 64 MiB 就是约 900 万次 `detect_hard_secret`,
/// **而预算只统计字符串叶子、对象键一分钱不收** —— 加预算要掐的正是这条放大路径,它却从旁边
/// 绕了过去(敌意评审 2026-09-12)。
enum Seg<'a> {
    Key(&'a str),
    Index(usize),
}

fn render_path(path: &[Seg<'_>]) -> String {
    if path.is_empty() {
        return "the request body".to_string();
    }
    let mut out = String::new();
    for seg in path {
        match seg {
            Seg::Key(k) => {
                if !out.is_empty() {
                    out.push('.');
                }
                out.push_str(&safe_key(k));
            }
            Seg::Index(i) => {
                out.push('[');
                out.push_str(&i.to_string());
                out.push(']');
            }
        }
    }
    out
}

struct LocateBudget {
    leaves: usize,
    bytes: usize,
}

impl LocateBudget {
    fn new() -> Self {
        Self {
            leaves: 0,
            bytes: 0,
        }
    }

    /// 这一叶能否检查。**超额只跳过这一叶,不中止整次搜索。**
    ///
    /// 此前是先计费后判断、`blown` 全局终止,于是**一个** 300 KiB 的叶子(一次大文件读的工具
    /// 结果、一张内联图片的 base64)不论出现在第几个位置,都会当场把整次定位打爆,哪怕全身只有
    /// 五十个叶子 —— 而这类叶子在真实会话里是常态(敌意评审 2026-09-12)。
    fn allows(&mut self, len: usize) -> bool {
        if self.leaves >= LOCATE_MAX_LEAVES {
            return false;
        }
        if len > LOCATE_MAX_BYTES.saturating_sub(self.bytes) {
            return false;
        }
        self.leaves += 1;
        self.bytes += len;
        true
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pass {
    /// 只看被信封键跳过的叶子(改写那一趟没碰过它们)
    EnvelopeOnly,
    /// 其余叶子
    Rest,
}

fn locate_walk<'a>(
    v: &'a Value,
    parent_key: Option<&'a str>,
    path: &mut Vec<Seg<'a>>,
    pass: Pass,
    budget: &mut LocateBudget,
) -> Option<String> {
    match v {
        Value::String(s) => {
            let skipped_by_envelope = parent_key.is_some_and(is_envelope_key);
            let wanted = match pass {
                Pass::EnvelopeOnly => skipped_by_envelope,
                Pass::Rest => !skipped_by_envelope,
            };
            if !wanted || !budget.allows(s.len()) {
                return None;
            }
            if vigil_redaction::detect_hard_secret(s).is_some() {
                return Some(render_path(path));
            }
            None
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                path.push(Seg::Index(i));
                let hit = locate_walk(item, None, path, pass, budget);
                path.pop();
                if hit.is_some() {
                    return hit;
                }
            }
            None
        }
        Value::Object(obj) => {
            for (k, val) in obj {
                path.push(Seg::Key(k));
                let hit = locate_walk(val, Some(k), path, pass, budget);
                path.pop();
                if hit.is_some() {
                    return hit;
                }
            }
            None
        }
        _ => None,
    }
}

/// 在**将要上行的**树里定位第一个仍含硬指纹的字符串叶子,返回结构路径
/// (如 `messages[0].content[2].thinking`)。找不到 → `None`(例如重复 JSON 键:解析后的树里
/// 已经没有那份残留了;或凭据只出现在**键名**位置 —— 本函数只看字符串叶子)。
///
/// **只回结构,不回内容**,键名渲染口径见 [`safe_key`]。
/// 用途:把「整个会话作废」的 422 降成「裁掉那一个 assistant 轮次」(敌意评审 2026-09-12)。
///
/// **两趟,而不是一趟。** 残留按构造只可能在三处:被信封键跳过的叶子、`hard_secret_spans` 与
/// `detect_hard_secret` 判断分歧的叶子(占位符拼接 / base64 预算耗尽)、或者根本不在叶子里。
/// **其余每一个叶子都已经被改写那一趟证明干净**,重扫它们纯属白花预算。所以:
///
/// 1. 第一趟**只看信封跳过集** —— 真实 body 里个位数到几十个,于是常见情形(凭据落进受签名
///    保护的 `thinking`)**必然定位成功**。
/// 2. 找不到才跑第二趟扫其余叶子。**两趟共用同一个预算**,第一趟优先支取:信封跳过集按**键名**
///    固定、不按**数量**固定,所以它同样必须受限 —— 理由见 [`LOCATE_MAX_LEAVES`]。
///
/// 此前是单趟文档顺序前缀扫描,而真实请求体的键序是 `model` / `system` / `tools` / `messages`:
/// 工具 schema 排在对话**前面**且叶子密度极高(每个属性贡献 `type` / `description` / `enum` 项),
/// 装几十个工具就能吃光预算,而残留几乎总在后半段的 `messages` 里。这个功能是为**长会话**造的,
/// 长会话恰恰意味着**大 body** —— 原形态会在它唯一重要的场景里静默退化成通用文案
/// (敌意评审 2026-09-12)。
///
/// 递归深度**不由本函数负责**:`serde_json` 默认开 128 层递归限制(本仓没有 `unbounded_depth`
/// 也没有 `disable_recursion_limit`),超深 body 在入口 `from_slice` 就失败、被映射成 400
/// `unparseable_json`,根本走不到这里。64 MiB 撑不出深度,只撑得出**宽度**,而宽度走的是循环。
/// 这条不变量是**借来的**,所以有一条 e2e 把它钉成可执行事实
/// (`excessively_nested_bodies_are_refused_before_any_recursion_of_ours`)。
pub fn locate_residual(v: &Value) -> Option<String> {
    // **两趟共用同一个预算**,第一趟优先支取(理由见 `LOCATE_MAX_LEAVES`)。
    let mut budget = LocateBudget::new();
    let mut path = Vec::new();
    if let Some(at) = locate_walk(v, None, &mut path, Pass::EnvelopeOnly, &mut budget) {
        return Some(at);
    }
    path.clear();
    locate_walk(v, None, &mut path, Pass::Rest, &mut budget)
}

/// 区间能否安全应用到 `s`:不倒挂、不越界、两端都落在 char 边界。
///
/// 单独成函数是为了能用**构造出来的**越界区间直接单测这条 fail-closed 契约 —— 正常路径上
/// 区间来自 `hard_secret_spans`、与文本同源,从外部构造不出反例。
fn spans_applicable(s: &str, bounds: &[(usize, usize)]) -> bool {
    bounds.iter().all(|&(start, end)| {
        start <= end && end <= s.len() && s.is_char_boundary(start) && s.is_char_boundary(end)
    })
}

/// 就地改写整棵 JSON:对象按键名跳信封字段,数组 / 嵌套对象递归,字符串叶子走 [`rewrite_text`]。
/// **对象的键名**不改(键名不是凭据载体;改键会破坏协议)。
pub fn rewrite_json(v: &mut Value, sink: &dyn AliasSink) -> RewriteReport {
    let mut report = RewriteReport::default();
    walk(v, sink, &mut report);
    report
}

fn walk(v: &mut Value, sink: &dyn AliasSink, report: &mut RewriteReport) {
    match v {
        Value::String(s) => {
            if let Some(new) = rewrite_text(s, sink, report) {
                *s = new;
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                walk(item, sink, report);
            }
        }
        Value::Object(obj) => {
            for (key, val) in obj.iter_mut() {
                if is_envelope_key(key) && val.is_string() {
                    report.skipped_envelope_fields += 1;
                    continue;
                }
                // 凭据**键名**下的字符串值整段替换(与 MCP 网关 `scrub_object_value` 同口径)。
                // 逐叶子扫会丢掉「键名 + 值」的上下文:`{"password":"hunter2000"}` 的值单独看不像
                // 任何硬指纹,但键名已经说明了它是什么(Codex 审计 2026-09-12 第 2 条)。
                if let Value::String(s) = val {
                    if vigil_redaction::is_secret_key_name(key)
                        && s.chars().count() >= vigil_redaction::secret_value_min_chars(key)
                    {
                        *s = "[REDACTED env_assignment]".to_string();
                        report.bump("env_assignment");
                        continue;
                    }
                }
                walk(val, sink, report);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Map};

    const GH: &str = "ghp_1234567890abcdef1234567890abcdef12345678";

    struct StubSink;
    impl AliasSink for StubSink {
        fn alias_for(&self, kind: &str, value: &str) -> Option<String> {
            Some(format!("auto-{kind}-{}", value.len()))
        }
    }

    #[test]
    fn plain_text_secret_becomes_redacted_placeholder() {
        let mut r = RewriteReport::default();
        let out = rewrite_text(&format!("token {GH} end"), &NoAlias, &mut r).unwrap();
        assert_eq!(out, "token [REDACTED github_token] end");
        assert_eq!(r.kinds, vec![("github_token", 1)]);
        assert!(r.aliases.is_empty());
    }

    #[test]
    fn alias_sink_produces_secret_uri_and_records_alias_only() {
        let mut r = RewriteReport::default();
        let out = rewrite_text(&format!("use {GH}"), &StubSink, &mut r).unwrap();
        assert_eq!(out, "use secret://auto-github_token-44");
        assert_eq!(r.aliases, vec!["auto-github_token-44".to_string()]);
        assert!(!out.contains(GH));
    }

    #[test]
    fn clean_text_is_untouched() {
        let mut r = RewriteReport::default();
        assert_eq!(rewrite_text("nothing to see here", &NoAlias, &mut r), None);
        assert!(!r.rewrote());
    }

    #[test]
    fn anthropic_messages_body_rewrites_content_but_not_envelope() {
        let mut body = json!({
            "model": "claude-sonnet-4-5",
            "system": [{"type": "text", "text": format!("repo uses {GH}"), "cache_control": {"type": "ephemeral"}}],
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": format!("my key is {GH}")}]},
                {"role": "assistant", "content": [
                    {"type": "thinking", "thinking": "plan", "signature": "sigAAAA"},
                    {"type": "tool_use", "id": "toolu_01", "name": "Bash", "input": {"command": format!("export GITHUB_TOKEN={GH}")}}
                ]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_01", "content": "ok"}]}
            ],
            "metadata": {"user_id": "u_123"}
        });
        let report = rewrite_json(&mut body, &NoAlias);
        let s = body.to_string();
        assert!(!s.contains(GH), "raw token survived: {s}");
        assert_eq!(body["model"], "claude-sonnet-4-5");
        assert_eq!(body["messages"][1]["content"][1]["id"], "toolu_01");
        assert_eq!(body["messages"][1]["content"][0]["signature"], "sigAAAA");
        assert_eq!(body["messages"][2]["content"][0]["tool_use_id"], "toolu_01");
        assert_eq!(body["metadata"]["user_id"], "u_123");
        assert_eq!(
            body["messages"][1]["content"][1]["input"]["command"],
            "export [REDACTED env_assignment]"
        );
        assert_eq!(
            report.kinds,
            vec![("github_token", 2), ("env_assignment", 1)]
        );
    }

    #[test]
    fn responses_api_input_items_are_rewritten() {
        let mut body = json!({
            "model": "gpt-5.5",
            "previous_response_id": "resp_abc",
            "instructions": "you are codex",
            "input": [
                {"type": "message", "role": "user", "content": [{"type": "input_text", "text": format!("AWS key AKIAIOSFODNN7EXAMPLE and {GH}")}]},
                {"type": "function_call_output", "call_id": "call_1", "output": "{\"password\": \"hunter2000\"}"},
                {"type": "reasoning", "id": "rs_1", "encrypted_content": "gAAAAAopaque=="}
            ],
            "stream": true
        });
        let report = rewrite_json(&mut body, &NoAlias);
        let s = body.to_string();
        assert!(!s.contains(GH));
        assert!(!s.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!s.contains("hunter2000"));
        assert_eq!(body["previous_response_id"], "resp_abc");
        assert_eq!(body["input"][2]["encrypted_content"], "gAAAAAopaque==");
        assert_eq!(body["stream"], true);
        assert!(report.kinds.iter().any(|(k, _)| *k == "aws_access_key_id"));
        assert!(report.kinds.iter().any(|(k, _)| *k == "env_assignment"));
    }

    /// **这个测试此前断言的正是一条绕过**:它用的 base64 解出来就是一个 GitHub token,却断言
    /// 「不改写」—— 等于把「给凭据套层媒体外衣即免检」钉成了预期行为。三种伪装现在都必须被抓住
    /// (敌意评审 2026-09-12 HIGH-1/2/3)。
    #[test]
    fn media_self_declaration_no_longer_buys_a_free_pass() {
        // ① 自称 image/png 的对象,`data` 里放的是**明文**凭据(从不校验是否真 base64)
        let mut body = json!({"contents": [{"parts": [
            {"inline_data": {"mime_type": "image/png", "data": GH}}
        ]}]});
        assert!(rewrite_json(&mut body, &NoAlias).rewrote());
        assert!(!body.to_string().contains(GH), "{body}");

        // ② 两个条件不相邻的伪 data: URI —— 明文夹在媒体前缀与 `;base64,` 中间
        let smuggled = format!("data:image/png,{GH};base64,AAAA");
        let mut body = json!({"messages": [{"role": "user", "content": smuggled}]});
        assert!(rewrite_json(&mut body, &NoAlias).rewrote());
        assert!(!body.to_string().contains(GH), "{body}");

        // ③ 规规矩矩的 data: URI,但 base64 解出来是凭据
        let b64 = "Z2hwXzEyMzQ1Njc4OTBhYmNkZWYxMjM0NTY3ODkwYWJjZGVmMTIzNDU2Nzg=";
        let mut body = json!({
            "messages": [{"role": "user", "content": format!("data:image/png;base64,{b64}")}]
        });
        let report = rewrite_json(&mut body, &NoAlias);
        assert_eq!(report.kinds, vec![("base64_payload", 1)], "{report:?}");
        assert!(!body.to_string().contains(b64), "{body}");
    }

    /// 定位只回结构、不回内容:凭据当键名时必须渲染成 `<field>`,否则错误信息就替攻击者
    /// 回显了不可信输入(敌意评审 2026-09-12)。
    #[test]
    fn locate_residual_reports_structure_never_content() {
        let v = json!({"model": "m", "messages": [{"role": "assistant", "content": [
            {"type": "text", "text": "ok"},
            {"type": "thinking", "thinking": format!("token {GH}"), "signature": "s"}
        ]}]});
        assert_eq!(
            locate_residual(&v).as_deref(),
            Some("messages[0].content[1].thinking")
        );

        // 凭据被拿来当键名 → 路径里绝不出现它
        let v = json!({ GH: "x", "a": { GH: GH } });
        let at = locate_residual(&v).expect("应当定位到");
        assert!(!at.contains(GH), "位置泄漏了凭据:{at}");
        assert_eq!(at, "a.<field>");

        assert_eq!(locate_residual(&json!({"a": "clean"})), None);
    }

    /// `safe_key` 的安全性**不再依赖那个长度常量**:这三条 HARD_RULES 规则本来就可以是全小写 +
    /// 数字 + 下划线,此前唯一拦住它们的是 `len() <= 24`,最窄余量 33 对 24。现在规则表自己参与
    /// 判定,将来加一条更短的全小写厂商 token 规则也不会让凭据漏进 422 文案(敌意评审 2026-09-12)。
    #[test]
    fn safe_key_asks_the_rule_table_not_just_a_length_margin() {
        for key in [
            "ghp_1234567890abcdef1234567890abcdef12345678",
            "hf_abcdefghijklmnopqrstuvwxyz123456",
            "sk_live_abcdef0123456789abcdef01",
        ] {
            assert!(
                vigil_redaction::detect_hard_secret(key).is_some(),
                "样本应当被规则表认出(否则这条守门就失去意义):{key}"
            );
            let at = locate_residual(&json!({ key: GH })).expect("应当定位到叶子");
            assert_eq!(at, "<field>", "键名位置的凭据泄漏进了路径");
        }
    }

    /// 定位有检查预算:树太大就返 `None` 落通用文案,绝不为一条可被请求方随意点火的路径无限付费。
    #[test]
    fn locate_residual_gives_up_past_its_inspection_budget() {
        let wide: Vec<Value> = (0..LOCATE_MAX_LEAVES + 10)
            .map(|i| Value::String(format!("filler-{i}")))
            .collect();
        let mut items = wide.clone();
        items.push(Value::String(GH.to_string()));
        assert_eq!(locate_residual(&Value::Array(items)), None, "超预算应放弃");

        // 预算之内照常定位
        let mut small = vec![Value::String("x".to_string()); 4];
        small.push(Value::String(GH.to_string()));
        assert_eq!(
            locate_residual(&Value::Array(small)).as_deref(),
            Some("[4]")
        );
    }

    /// 残留几乎总在 `messages` 里,而 `tools` 的 schema 排在它**前面**、叶子密度极高。单趟文档
    /// 顺序扫描会在 schema 区就耗光预算,在这个功能**唯一重要**的场景里静默退化成通用文案;
    /// 两趟之后第一趟只看信封跳过集,必然定位成功(敌意评审 2026-09-12)。
    #[test]
    fn huge_tool_schema_before_messages_does_not_starve_location() {
        let tools: Vec<Value> = (0..400)
            .map(|i| json!({"name": format!("tool_{i}"), "description": "x".repeat(600)}))
            .collect();
        let body = json!({
            "model": "m",
            "tools": tools,
            "messages": [{"role": "assistant", "content": [
                {"type": "thinking", "thinking": format!("token {GH}"), "signature": "s"}
            ]}]
        });
        assert_eq!(
            locate_residual(&body).as_deref(),
            Some("messages[0].content[0].thinking")
        );
    }

    /// 单个超大叶子只跳过它自己,**不中止整次搜索**。此前 `blown` 是全局终止,于是一个大文件
    /// 读结果或内联图片 base64 会当场打爆整次定位,而这类叶子是常态(敌意评审 2026-09-12)。
    #[test]
    fn one_oversized_leaf_does_not_abort_the_whole_search() {
        let big = "y".repeat(LOCATE_MAX_BYTES + 1024);
        // 都不是信封键 → 走第二趟:`big` 超额被**跳过**,搜索继续,`small` 命中
        let body = json!({"a": {"big": big, "small": GH}});
        assert_eq!(locate_residual(&body).as_deref(), Some("a.small"));
    }

    /// 路径延迟构造:只对**命中路径**上的键渲染,而不是边走边对每个键跑 `safe_key`
    /// (内含 `detect_hard_secret`)。宽 body 仍能定位,且路径只含胜出的那一条。
    #[test]
    fn wide_key_bodies_still_locate_and_render_only_the_winning_path() {
        let mut obj = serde_json::Map::new();
        for i in 0..5_000 {
            obj.insert(format!("k{i}"), Value::from(1));
        }
        obj.insert("name".to_string(), Value::String(GH.to_string()));
        assert_eq!(
            locate_residual(&Value::Object(obj)).as_deref(),
            Some("name")
        );
    }

    /// **信封跳过集按「键名」固定,不按「数量」固定** —— `is_envelope_key` 含 `ends_with("_id")`,
    /// 键名完全由请求方决定。此前第一趟是**无预算**全扫,于是构造 body 能稳定换到一次完整的
    /// 无上限扫描(敌意评审 2026-09-12)。现在两趟共用同一预算,用尽即停;代价是这种病态输入
    /// 拿不到定位提示(退通用文案),那正是设计好的降级。
    #[test]
    fn envelope_pass_is_capped_too_because_that_set_is_fixed_by_name_not_by_count() {
        fn id_leaves(n: usize) -> Vec<Value> {
            (0..n)
                .map(|i| {
                    let mut m = serde_json::Map::new();
                    m.insert(format!("k{i}_id"), Value::String("x".to_string()));
                    Value::Object(m)
                })
                .collect()
        }

        // `name` 也是信封键,但排在填充之后:预算已被填充耗尽 → 放弃定位,而不是继续无限扫
        let body = json!({"pad": id_leaves(LOCATE_MAX_LEAVES + 100), "name": GH});
        assert_eq!(locate_residual(&body), None, "第一趟必须同样受预算约束");

        // 常见路径不受影响:少量信封叶子时照常定位
        let body = json!({"pad": id_leaves(8), "name": GH});
        assert_eq!(locate_residual(&body).as_deref(), Some("name"));
    }

    /// 越界 / 非 char 边界的区间必须让**整次**改写返回 `None`(一个字节都不动),而不是跳过那一条
    /// 照常替换其余 —— 后者会把一条完整凭据留在「看起来已处理」的结果里(敌意评审 2026-09-12 L2)。
    #[test]
    fn out_of_bounds_or_misaligned_spans_are_fail_closed() {
        let s = "héllo ghp_1234567890abcdef1234567890abcdef12345678";
        assert!(spans_applicable(s, &[(0, 1)]));
        assert!(spans_applicable(s, &[(0, s.len())]));
        assert!(!spans_applicable(s, &[(0, s.len() + 1)]), "越界");
        assert!(!spans_applicable(s, &[(2, 1)]), "倒挂");
        assert!(!spans_applicable(s, &[(2, 3)]), "'é' 内部,非 char 边界");
    }

    /// 删掉媒体跳过**不会**误伤真实图片:随机二进制的 base64 解出来含控制字符、不是 UTF-8 文本,
    /// `decode_base64_text` 返 `None`,本来就不会被标记。
    #[test]
    fn real_binary_payload_is_left_alone_without_any_media_shortcut() {
        // 1×1 PNG 的完整 base64(解码后是 PNG magic + 大量控制字符)
        let png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
        let mut body = json!({"contents": [{"parts": [
            {"inline_data": {"mime_type": "image/png", "data": png}}
        ]}]});
        let report = rewrite_json(&mut body, &NoAlias);
        assert!(!report.rewrote(), "真实图片不该被改写: {report:?}");
        assert_eq!(body["contents"][0]["parts"][0]["inline_data"]["data"], png);
    }

    #[test]
    fn base64_payload_run_is_replaced_whole() {
        // "GITHUB_TOKEN=ghp_…" 的 base64:明文规则看不见,base64 载荷规则整段换
        let encoded =
            "R0lUSFVCX1RPS0VOPWdocF8xMjM0NTY3ODkwYWJjZGVmMTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4";
        let mut body =
            json!({"messages": [{"role": "user", "content": format!("blob {encoded} tail")}]});
        let report = rewrite_json(&mut body, &NoAlias);
        assert_eq!(
            body["messages"][0]["content"],
            "blob [REDACTED base64_payload] tail"
        );
        assert_eq!(report.kinds, vec![("base64_payload", 1)]);
    }

    #[test]
    fn object_keys_are_never_rewritten() {
        let mut m = Map::new();
        m.insert(GH.to_string(), json!("value"));
        let mut body = Value::Object(m);
        let report = rewrite_json(&mut body, &NoAlias);
        assert!(!report.rewrote());
        assert!(body.get(GH).is_some());
    }

    #[test]
    fn text_data_uri_is_still_scanned() {
        let mut body =
            json!({"messages": [{"role": "user", "content": format!("data:text/plain,{GH}")}]});
        let report = rewrite_json(&mut body, &NoAlias);
        assert_eq!(report.kinds, vec![("github_token", 1)]);
    }

    /// 逐叶子扫会丢掉「键名 + 值」的上下文:`hunter2000` 单独看不像任何硬指纹,但键名已经
    /// 说明了它是什么。与 MCP 网关 `scrub_object_value` 同口径,且同样**不**收泛后缀
    /// (`NextToken` 之类分页游标满地都是)。
    #[test]
    fn secret_key_name_redacts_a_value_that_is_not_a_fingerprint_by_itself() {
        let mut body = json!({
            "input": {"password": "hunter2000", "NextToken": "abcdefghijklmnopqrst"},
            "messages": [{"role": "user", "content": "hello"}]
        });
        let report = rewrite_json(&mut body, &NoAlias);
        assert_eq!(body["input"]["password"], "[REDACTED env_assignment]");
        assert_eq!(
            body["input"]["NextToken"], "abcdefghijklmnopqrst",
            "泛后缀分页游标不得被误脱"
        );
        assert_eq!(body["messages"][0]["content"], "hello");
        assert_eq!(report.kinds, vec![("env_assignment", 1)]);
    }

    #[test]
    fn multiple_hits_in_one_string_all_replaced_in_order() {
        let mut r = RewriteReport::default();
        let text = format!("a {GH} b sk-ant-0123456789abcdefghijKLMNOPQR c");
        let out = rewrite_text(&text, &NoAlias, &mut r).unwrap();
        assert_eq!(
            out,
            "a [REDACTED github_token] b [REDACTED anthropic_api_key] c"
        );
    }
}
