//! `vigil-hub hook` —— Claude Code `PreToolUse` hook adapter(P1-α1,guard-only)。
//!
//! 把 Vigil 的 secret 防护从"仅 MCP 工具"扩到 Claude Code 的**原生**工具调用
//! (Bash / Edit / Write / Read / Grep 等)。Claude Code 在执行任一工具前,把
//! PreToolUse 事件以 JSON 写到本进程 stdin;本 adapter 扫描 `tool_input`,对带 secret
//! 的危险/不可靠 sink **fail-closed deny**,并审计到账本。
//!
//! # α1 范围(guard + audit,bulletproof)
//! - **裸硬指纹 secret**(**任何**工具的 input 里,含 `mcp__*`)→ **deny**(最高价值:堵住真凭据漏进
//!   bash 外泄等;裸 secret 永远不该出现在任何工具调用里。**纵深防御**:用户直连非 Vigil 的 MCP server
//!   时,网关看不到该流量,hook 是唯一防线)。
//! - **`secret://<alias>` / `vigil://redact/` 占位符 ×（原生工具)→ **deny**(α1 不做替换,fail-closed;
//!   替换是 α2)。
//! - **占位符 ×（MCP 工具 `mcp__*`)→ pass-through**:MCP 入站的占位符 detokenize 已由 Vigil MCP 网关
//!   own(Slice 2),hook **绝不**对 MCP 占位符插手,避免双重处理 / 破坏已验证的 MCP 流。
//! - 干净 input → pass-through(exit 0 静默,工具正常执行)。
//!
//! # 拦截机制 = exit 2 + stderr(版本无关的硬拦截)
//! Claude Code 约定:hook **exit 2** = blocking error,stderr 回喂模型,工具被阻止
//! (stdout/JSON 在 exit 2 时忽略)。这是最老、最通用的硬 block 路径,不依赖 `updatedInput`
//! 或 `hookSpecificOutput.permissionDecision` 的版本门(见 research:exit 1 / 超时 / 非 2xx
//! 全 **fail-open**,故 deny **绝不**走 exit 1)。α2 的真替换才需要 exit-0 + JSON +
//! `hookSpecificOutput.updatedInput`(版本门 ≥ 2.0.10 + 逐工具可靠性门)。
//!
//! # fail-closed by construction
//! `run` **永不**返 `Result`/panic:任何 stdin 读取 / 解析 / 内部错误一律收敛为 `Deny`
//! (绝不 fail-open)。审计是 best-effort —— 账本不可用时仍做安全决策,只把审计失败写 stderr,
//! **不**因审计失败 brick 用户的非 secret 工具调用。
//!
//! # 不回显不可信输入
//! deny reason 与审计 payload **绝不**包含任何 secret 真值:reason 只带 FindingKind 名(如
//! `github_token`)与工具名;审计只存 `tool_input` 的 **sha256**(非原文)。见
//! feedback「untrusted input not in errors」。

use std::io::Read;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use vigil_audit::Ledger;

/// hook stdin 上限(Codex R1 HIGH):16 MiB 覆盖任何现实工具入参,封顶防无界输入把
/// OOM/超时变成 fail-open(Claude Code 的 hook 超时/崩溃是 non-blocking = 放行)。
const MAX_HOOK_INPUT_BYTES: u64 = 16 * 1024 * 1024;

/// `hook` 子命令参数。
#[derive(Debug, Clone, Default)]
pub struct HookArgs {
    /// 审计账本路径(与 `serve --ledger` 同一文件以保持链连续)。
    /// None = 不审计(仍做安全决策;stderr 提示)。
    pub ledger_path: Option<PathBuf>,
}

/// Claude Code PreToolUse 事件输入(stdin JSON;只取我们用到的字段,未知字段 serde 忽略)。
///
/// 契约对照官方 Agent SDK hooks 文档:`tool_name` + `tool_input`(任意 shape)+ 通用字段
/// `session_id` / `cwd` / `hook_event_name`。
#[derive(Debug, Deserialize)]
struct PreToolUseInput {
    /// Claude 侧会话 id(用作审计 app_name,关联回 Claude 会话)。
    #[serde(default)]
    session_id: Option<String>,
    /// 触发时的工作目录(审计上下文;非密钥)。
    #[serde(default)]
    cwd: Option<String>,
    /// 事件名;正常恒为 `"PreToolUse"`。防御性:非该值则 pass-through(非本 adapter 的事件)。
    #[serde(default)]
    hook_event_name: Option<String>,
    /// 工具名(如 `Bash`/`Edit`/`Write`/`Read`,或 `mcp__<server>__<tool>`)。
    tool_name: String,
    /// 工具入参(typed `unknown`;shape 随工具而变)。整体序列化后扫描。
    ///
    /// **必填**:缺失视为 schema 漂移 / 畸形事件 → fail-closed deny。**不**加 `#[serde(default)]` ——
    /// 否则缺失会默认成 `null`、序列化为 `"null"` 落到 Allow = fail-open(Codex R1 BLOCKER)。
    /// `Option<Value>`:serde 对缺失的 `Option` 字段填 `None`,由 `run` 显式 deny。
    tool_input: Option<Value>,
}

/// hook 决策结果。
#[derive(Debug, PartialEq, Eq)]
pub enum HookOutcome {
    /// 放行:exit 0,无输出,工具正常执行。
    Allow,
    /// 拦截:exit 2,`reason` 写 stderr 回喂模型(**不含任何 secret 真值**)。
    Deny(String),
}

/// adapter 主逻辑。泛型 `R: Read` 让测试用 `Cursor` 注入 stdin。
///
/// **fail-closed**:内部任何失败都收敛为 `Deny`,绝不返 `Result`/panic(避免 exit 1 fail-open)。
pub fn run<R: Read>(args: &HookArgs, stdin: &mut R) -> HookOutcome {
    // 1) 读 stdin —— **有界**读取(Codex R1 HIGH)。读 MAX+1 字节,超出即 deny;读失败也 deny。
    let mut buf = String::new();
    let mut limited = stdin.by_ref().take(MAX_HOOK_INPUT_BYTES + 1);
    if limited.read_to_string(&mut buf).is_err() {
        return HookOutcome::Deny(
            "Vigil hook: could not read PreToolUse input from stdin (blocked fail-closed).".into(),
        );
    }
    if buf.len() as u64 > MAX_HOOK_INPUT_BYTES {
        return HookOutcome::Deny(
            "Vigil hook: PreToolUse input exceeds the safe size limit (blocked fail-closed)."
                .into(),
        );
    }

    // 2) 解析 PreToolUse。解析失败 = 畸形事件 → fail-closed deny。
    let input: PreToolUseInput = match serde_json::from_str(&buf) {
        Ok(v) => v,
        Err(_) => {
            return HookOutcome::Deny(
                "Vigil hook: malformed PreToolUse input (blocked fail-closed).".into(),
            );
        }
    };

    // 防御性:若事件名存在且非 PreToolUse,说明 hook 被误配到别的事件 → 不插手(pass-through)。
    if let Some(ev) = &input.hook_event_name {
        if ev != "PreToolUse" {
            return HookOutcome::Allow;
        }
    }

    // 3) tool_input 必填:缺失 = schema 漂移/畸形 → fail-closed deny(绝不默认成 null 放行)。
    let Some(tool_input) = input.tool_input.as_ref() else {
        return HookOutcome::Deny(
            "Vigil hook: PreToolUse event is missing `tool_input` (blocked fail-closed).".into(),
        );
    };

    // 4) 扫描序列化后的 tool_input(对**所有**工具,含 `mcp__*` —— 裸 secret 在任何工具调用都要拦)。
    //    - 裸硬指纹 secret:复用 vigil-redaction 的 detect_hard_secret(返回 FindingKind 名,非真值)。
    //    - Vigil 自有占位符:`secret://`(Slice 2 alias)/ `vigil://redact/`(Tier-B 动态 token)。
    let serialized = tool_input.to_string();
    let raw_finding = vigil_redaction::detect_hard_secret(&serialized);
    let has_placeholder =
        serialized.contains("secret://") || serialized.contains("vigil://redact/");
    // 路由判断用**原始** tool_name(必须精确);回显/审计才用 sanitize 后的安全名(见 safe_tool_name)。
    let is_mcp = input.tool_name.starts_with("mcp__");
    let tool_display = safe_tool_name(&input.tool_name);

    // 5) 决策。
    let outcome = if let Some(kind) = raw_finding {
        // 裸真凭据漏进**任何**工具调用(含 MCP)—— 永远 deny。纵深防御:用户直连非 Vigil 的 MCP
        // server 时,网关看不到该流量,hook 是唯一防线。reason 只带 FindingKind 名,**不**回显真值。
        HookOutcome::Deny(format!(
            "Vigil blocked tool `{tool}`: a raw {kind} credential was detected in the tool input. \
             Never put real secrets in tool calls. Declare it as a Vigil secret alias and reference \
             `secret://<alias>` so the real value is injected only at the execution boundary and is \
             never exposed to the model or the audit log.",
            tool = tool_display,
            kind = kind,
        ))
    } else if has_placeholder && !is_mcp {
        // α1 guard-only:占位符出现在**原生**工具里,但 hook-boundary 替换尚未启用 → fail-closed,
        // 绝不把未解析的占位符透传执行。α2 加窄 allowlist 的真替换。
        // (占位符在 **MCP** 工具则交给 Vigil MCP 网关 detokenize,hook 不插手 → 落到下面 Allow。)
        HookOutcome::Deny(format!(
            "Vigil blocked tool `{tool}`: it carries a `secret://`/`vigil://` placeholder, but \
             hook-boundary substitution is not yet enabled for native tools (guard-only stage). \
             Blocked fail-closed to avoid executing an unresolved placeholder.",
            tool = tool_display,
        ))
    } else {
        // 干净 input,或 `secret://alias` 占位符走 MCP 工具(交给网关)→ pass-through。
        HookOutcome::Allow
    };

    // 6) 审计 deny(best-effort;审计失败**不**改变安全决策,只写 stderr)。
    if let HookOutcome::Deny(_) = &outcome {
        let reason_kind = if raw_finding.is_some() {
            "raw_secret"
        } else {
            "placeholder"
        };
        audit_deny(args, &input, reason_kind, raw_finding, &serialized);
    }

    outcome
}

/// best-effort 审计一条 deny 到账本。**绝不** panic / 改变决策。
///
/// 不变量:payload / 摘要 **不含任何 secret 真值** —— 只存 FindingKind 名 + `tool_input` 的 sha256。
fn audit_deny(
    args: &HookArgs,
    input: &PreToolUseInput,
    reason_kind: &str,
    raw_finding: Option<&'static str>,
    serialized_tool_input: &str,
) {
    let Some(path) = &args.ledger_path else {
        // 未配 ledger = 不审计(预期:setup 总会配;手动裸跑 hook 不审计是文档化行为)。
        // 不打印 —— 每次 deny 都 nag 会污染 stderr(self-test / 无审计场景)。
        return;
    };
    let ledger = match Ledger::open(path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("vigil-hook: audit ledger open failed ({e}); decision still enforced");
            return;
        }
    };
    // 用 Claude 会话 id 作 app_name,关联回 Claude 会话(本 Vigil 会话即此次 hook 调用)。
    let sid = match ledger.start_session("vigil-hook", input.session_id.as_deref()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("vigil-hook: audit start_session failed ({e}); decision still enforced");
            return;
        }
    };

    // sha256(tool_input):可审计的指纹,**不**落原文(原文含 secret)。
    let mut h = Sha256::new();
    h.update(serialized_tool_input.as_bytes());
    let tool_input_sha256 = hex::encode(h.finalize());

    // 防御性 sanitize tool_name 再落审计(Codex R1 LOW;trusted-but-harden)。
    let tool_display = safe_tool_name(&input.tool_name);
    let payload = json!({
        "tool_name": tool_display,
        "decision": "deny",
        "reason_kind": reason_kind,       // raw_secret | placeholder
        "finding": raw_finding,           // FindingKind 名(静态串)或 null —— 非真值
        "tool_input_sha256": tool_input_sha256,
        "cwd": input.cwd,
    });
    // matcher 现覆盖全工具(含 mcp__*),故不再称 "native"(Codex R2 NICE)。
    let summary = format!("hook denied tool `{}` ({})", tool_display, reason_kind);
    if let Err(e) = ledger.append_event(&sid, "hook.pretooluse.denied", &payload, Some(&summary)) {
        eprintln!("vigil-hook: audit append_event failed ({e}); decision still enforced");
    }
}

/// 安全显示名(Codex R1 LOW)。`tool_name` 来自 Claude Code(可信 dispatcher),但防御性 sanitize:
/// 截断到 64 char + 仅保留 ASCII 字母数字与 `_-.`,其余替换为 `?`,保证输出纯 ASCII(cp936 终端不乱码),
/// 避免任何畸形 tool_name 注入 stderr / 审计。**路由判断仍用原始 `tool_name`**,只有回显/审计用本函数。
fn safe_tool_name(name: &str) -> String {
    const MAX: usize = 64;
    let mut s: String = name
        .chars()
        .take(MAX)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') {
                c
            } else {
                '?'
            }
        })
        .collect();
    if name.chars().count() > MAX {
        s.push('~'); // 截断标记(ASCII)
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn run_json(v: Value) -> HookOutcome {
        let s = v.to_string();
        let mut cur = Cursor::new(s.into_bytes());
        run(&HookArgs::default(), &mut cur)
    }

    #[test]
    fn raw_secret_in_bash_is_denied() {
        // 形似真实 github token(40 chars,命中 github_token 硬指纹)
        let out = run_json(json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": "gh auth login --with-token ghp_0123456789abcdef0123456789abcdef0123" }
        }));
        assert!(
            matches!(out, HookOutcome::Deny(_)),
            "raw secret must be denied"
        );
    }

    #[test]
    fn raw_secret_reason_does_not_echo_the_secret() {
        // 关键安全不变量:deny reason 绝不回显 secret 真值(只 FindingKind 名)。
        let secret = "ghp_0123456789abcdef0123456789abcdef0123";
        let out = run_json(json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": { "file_path": "/tmp/x", "content": format!("TOKEN={secret}") }
        }));
        match out {
            HookOutcome::Deny(reason) => {
                assert!(
                    !reason.contains(secret),
                    "deny reason must NOT echo the raw secret; got: {reason}"
                );
                assert!(
                    reason.contains("github_token"),
                    "reason should name the FindingKind, not the value"
                );
            }
            HookOutcome::Allow => panic!("expected deny"),
        }
    }

    #[test]
    fn secret_alias_placeholder_in_native_tool_is_denied() {
        let out = run_json(json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": "deploy --token secret://github_pat" }
        }));
        assert!(
            matches!(out, HookOutcome::Deny(_)),
            "placeholder must be guarded (α1)"
        );
    }

    #[test]
    fn vigil_dynamic_token_placeholder_is_denied() {
        let out = run_json(json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": { "file_path": "/tmp/c", "content": "auth=vigil://redact/abc~def" }
        }));
        assert!(matches!(out, HookOutcome::Deny(_)));
    }

    #[test]
    fn clean_native_tool_is_allowed() {
        let out = run_json(json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": { "file_path": "/home/user/project/src/main.rs" }
        }));
        assert_eq!(out, HookOutcome::Allow, "no secret → pass-through");
    }

    #[test]
    fn mcp_tool_is_passed_through_even_with_placeholder() {
        // MCP 网关 own MCP 入站(含 Slice 2);hook 绝不插手 → 即便带占位符也 Allow。
        let out = run_json(json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp__github__create_issue",
            "tool_input": { "token": "secret://github_pat" }
        }));
        assert_eq!(
            out,
            HookOutcome::Allow,
            "MCP tools are owned by the gateway"
        );
    }

    #[test]
    fn mcp_tool_with_raw_secret_is_denied_defense_in_depth() {
        // 纵深防御:裸 secret 在**任何**工具(含 MCP)都 deny —— 用户直连非 Vigil 的 MCP server
        // 时网关看不到,hook 是唯一防线。仅**占位符**在 MCP 工具才交给网关 pass-through。
        let out = run_json(json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp__github__create_issue",
            "tool_input": { "token": "ghp_0123456789abcdef0123456789abcdef0123" }
        }));
        assert!(
            matches!(out, HookOutcome::Deny(_)),
            "raw secret must be denied even in MCP tools (defense in depth)"
        );
    }

    #[test]
    fn malformed_stdin_is_denied_fail_closed() {
        let mut cur = Cursor::new(b"not json at all {{{".to_vec());
        let out = run(&HookArgs::default(), &mut cur);
        assert!(
            matches!(out, HookOutcome::Deny(_)),
            "malformed input must fail closed"
        );
    }

    #[test]
    fn non_pretooluse_event_passes_through() {
        // 防御:hook 被误配到别的事件 → 不插手。
        let out = run_json(json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": "echo ghp_0123456789abcdef0123456789abcdef0123" }
        }));
        assert_eq!(out, HookOutcome::Allow);
    }

    #[test]
    fn empty_tool_input_is_allowed() {
        let out = run_json(json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {}
        }));
        assert_eq!(out, HookOutcome::Allow);
    }

    #[test]
    fn missing_tool_input_is_denied_fail_closed() {
        // Codex R1 BLOCKER:有 tool_name 但**缺** tool_input(schema 漂移)绝不能 fail-open 放行。
        let out = run_json(json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash"
            // 故意无 tool_input
        }));
        assert!(
            matches!(out, HookOutcome::Deny(_)),
            "missing tool_input must fail closed (not default to null→allow)"
        );
    }

    #[test]
    fn oversize_input_is_denied_fail_closed() {
        // Codex R1 HIGH:超界输入(可能触发 OOM/超时 = fail-open)必须 deny。
        // 构造一个 > MAX_HOOK_INPUT_BYTES 的合法 JSON(content 巨大,但**无** secret)。
        let big = "a".repeat((MAX_HOOK_INPUT_BYTES as usize) + 1024);
        let payload = format!(
            r#"{{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{{"file_path":"/tmp/x","content":"{big}"}}}}"#
        );
        let mut cur = Cursor::new(payload.into_bytes());
        let out = run(&HookArgs::default(), &mut cur);
        assert!(
            matches!(out, HookOutcome::Deny(_)),
            "oversize input must be denied before parse (fail-closed)"
        );
    }

    #[test]
    fn pathological_tool_name_is_sanitized_in_reason() {
        // Codex R1 LOW:畸形 tool_name 不得原样注入 stderr/审计。带换行/控制符/超长的 tool_name,
        // 命中裸 secret 触发 deny → reason 里的 tool 段应已 sanitize(无换行、无原始畸形串)。
        let weird = "Bash\n\r\x07evil`$(whoami)";
        let out = run_json(json!({
            "hook_event_name": "PreToolUse",
            "tool_name": weird,
            "tool_input": { "command": "x ghp_0123456789abcdef0123456789abcdef0123" }
        }));
        match out {
            HookOutcome::Deny(reason) => {
                assert!(
                    !reason.contains('\n'),
                    "sanitized name must not carry newlines"
                );
                assert!(
                    !reason.contains("$(whoami)"),
                    "must not echo shell metachars verbatim"
                );
                assert!(
                    reason.contains("github_token"),
                    "still names the finding kind"
                );
            }
            HookOutcome::Allow => panic!("expected deny"),
        }
    }

    #[test]
    fn safe_tool_name_keeps_legit_names_and_caps_length() {
        assert_eq!(safe_tool_name("Bash"), "Bash");
        assert_eq!(
            safe_tool_name("mcp__github__create_issue"),
            "mcp__github__create_issue"
        );
        assert_eq!(safe_tool_name("a\nb c"), "a?b?c");
        let long = "x".repeat(100);
        let out = safe_tool_name(&long);
        assert!(out.len() <= 65, "capped to 64 + 1 truncation marker");
        assert!(out.ends_with('~'));
        // 纯 ASCII 输出(cp936 不乱码)
        assert!(out.is_ascii());
        assert!(
            safe_tool_name("中文工具").is_ascii(),
            "non-ASCII tool name → ASCII-safe"
        );
    }
}
