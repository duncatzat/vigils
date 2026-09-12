//! ISS-020:post-exec leak detection(out-of-band,不改 stdout/stderr)。
//!
//! native + wasm runner 在已 line-by-line `scrub_text` 脱敏的 stdout/stderr
//! 上做**二次防御性扫描**:用 `vigil_redaction::scan_hard_findings` 取**全部**
//! 命中的硬指纹规则名。命中即把 `ExecutionResult` 标 quarantined,并通过
//! `RunnerAuditSink::emit` 发 `RunnerEvent::LeakDetected`。
//!
//! 与 ISS-016(Hub::invoke_upstream 扫 upstream response)同形态对称:
//! 都是"out-of-band metadata + 审计事件",**不修改字节内容**(MCP 协议透明性原则)。
//!
//! 为什么需要二次扫:
//! - line-by-line scrub 在 Unicode 行边界切分,跨行 secret 可能漏脱敏
//! - 攻击者可能构造 lookalike placeholder 绕开窄形剥除(detect_hard_secret 已防,
//!   scan_hard_findings 同源剥除)
//! - 纵深防御:scrub 漏 → quarantine 拦,运行时审计仍可观测

use vigil_redaction::scan_hard_findings;
use vigil_runner_types::{RunnerAuditSink, RunnerEvent};

/// 对已脱敏的 stdout/stderr 做二次防御扫描。
///
/// 返回 `(quarantined, leak_findings)`:
/// - `quarantined = true` 当且仅当 stdout 或 stderr 命中至少一条 hard rule
/// - `leak_findings` 是 stdout findings ∪ stderr findings(去重),**保
///   `vigil_redaction::HARD_RULES` 全局声明顺序**(R2 BLOCKER 修复:旧版用
///   "stdout-first" 局部顺序违反 ExecutionResult 文档契约);`quarantined=false`
///   时为空 Vec
///
/// 命中时通过 `sink` emit `RunnerEvent::LeakDetected`,**分源 emit**:
/// stdout 与 stderr 各发一条(便于审计按 source 聚合),都包含**该源**的命中
/// 列表(各自已按 HARD_RULES 声明顺序,因 `scan_hard_findings` 内部按声明序遍历)。
///
/// 调用契约:
/// - `stdout` / `stderr` 入参必须是**已脱敏**的字节(line-by-line scrub 过)
/// - 本函数**不改动**字节,纯产出 metadata
/// - **非 UTF-8 字节** `from_utf8(..).unwrap_or("")`:该流当作空文本**不扫**
///   (此为 **fail-open / 漏扫**,非 fail-closed quarantine)。生产 native/wasm
///   capture 路径当前都产 UTF-8(`std::process::Stdio` + wasmtime-wasi `MemoryOutputPipe`
///   的字节流由 caller 提供 scrub callback;默认 `default_scrub` 走
///   `vigil_redaction::scrub_text` 仅接受 UTF-8 串)。**已知局限**:若未来加 raw
///   bytes capture caller(如二进制 artifact 写出),需重审本路径,可考虑
///   `from_utf8_lossy()` 或显式 quarantine 非 UTF-8 流
pub(crate) fn post_exec_leak_scan(
    stdout: &[u8],
    stderr: &[u8],
    sink: &dyn RunnerAuditSink,
) -> (bool, Vec<&'static str>) {
    // 非 UTF-8 → 空串(已知局限,见 rustdoc;不破坏主流程)
    let stdout_str = std::str::from_utf8(stdout).unwrap_or("");
    let stderr_str = std::str::from_utf8(stderr).unwrap_or("");

    let stdout_hits = scan_hard_findings(stdout_str);
    let stderr_hits = scan_hard_findings(stderr_str);

    let quarantined = !stdout_hits.is_empty() || !stderr_hits.is_empty();

    // 分源 emit:审计端按 source 聚合,不丢"哪个流出的"信息
    if !stdout_hits.is_empty() {
        sink.emit(RunnerEvent::LeakDetected {
            source: "stdout",
            rules: &stdout_hits,
            quarantined: true,
        });
    }
    if !stderr_hits.is_empty() {
        sink.emit(RunnerEvent::LeakDetected {
            source: "stderr",
            rules: &stderr_hits,
            quarantined: true,
        });
    }

    // R2 BLOCKER 修复:合并去重时**按 HARD_RULES 全局声明顺序**而非 stdout-first 局部
    // 顺序。
    //
    // **R2 round-2 新发现修复**(Codex 提:NUL 拼接可让 env_assignment / database_url
    // 等 negated-char-class 规则**跨流合成命中**,如 stdout 末尾 `API_KEY=` + stderr 开头
    // `abcd` 拼成 `API_KEY=\0abcd` 仍可能命中 env_assignment 规则,违反"stdout_hits ∪
    // stderr_hits"契约)。
    //
    // 修法:重扫 combined 得到 HARD_RULES 全局顺序,然后**过滤掉既不在 stdout_hits 也
    // 不在 stderr_hits 里的**任何 finding(那些是跨流合成命中,非真实流内泄漏)。
    // 结果严格等于 `stdout_hits ∪ stderr_hits`,顺序按 HARD_RULES 声明序。
    let merged: Vec<&'static str> = if quarantined {
        let mut combined = String::with_capacity(stdout_str.len() + stderr_str.len() + 1);
        combined.push_str(stdout_str);
        combined.push('\0');
        combined.push_str(stderr_str);
        scan_hard_findings(&combined)
            .into_iter()
            .filter(|r| stdout_hits.contains(r) || stderr_hits.contains(r))
            .collect()
    } else {
        Vec::new()
    };

    (quarantined, merged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// 测试 sink:把 LeakDetected 序列化为 "source:rule1,rule2" 字符串便于断言。
    #[derive(Debug, Default)]
    struct CollectingSink {
        events: Mutex<Vec<String>>,
    }

    impl RunnerAuditSink for CollectingSink {
        fn emit(&self, event: RunnerEvent<'_>) {
            let tag = match event {
                RunnerEvent::LeakDetected {
                    source,
                    rules,
                    quarantined,
                } => format!("Leak:{source}:q={quarantined}:rules={}", rules.join(",")),
                _ => "Other".to_string(),
            };
            self.events.lock().unwrap().push(tag);
        }
    }

    impl CollectingSink {
        fn tags(&self) -> Vec<String> {
            self.events.lock().unwrap().clone()
        }
    }

    /// 干净的 stdout/stderr 不应触发 quarantine 或 LeakDetected 事件。
    #[test]
    fn post_exec_leak_scan_clean_stdout_stderr_no_quarantine() {
        let sink = CollectingSink::default();
        let (q, findings) = post_exec_leak_scan(
            b"hello world\nthe quick brown fox\n",
            b"warning: nothing serious\n",
            &sink,
        );
        assert!(!q, "干净文本不应 quarantine");
        assert!(findings.is_empty(), "干净文本不应有 findings:{findings:?}");
        assert!(sink.tags().is_empty(), "干净文本不应 emit 任何事件");
    }

    /// stdout 含 ghp_token → quarantined + LeakDetected(source=stdout) + findings 含
    /// "github_token";stderr 干净,所以只 emit 一条。
    #[test]
    fn post_exec_leak_scan_secret_in_stdout_emits_event() {
        let sink = CollectingSink::default();
        // 跨行 secret 模拟 scrub 漏掉的场景(scrub 是 line-by-line,这里直接给一行,
        // 但占位符攻击 / lookalike 也会触发同路径)
        let stdout = b"got token ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ in log\n";
        let stderr = b"all clean here\n";
        let (q, findings) = post_exec_leak_scan(stdout, stderr, &sink);
        assert!(q, "stdout 含 github_token 必须 quarantine");
        assert!(
            findings.contains(&"github_token"),
            "findings 应含 github_token:{findings:?}"
        );
        let tags = sink.tags();
        assert_eq!(tags.len(), 1, "stdout 命中、stderr 干净 → 仅 1 条:{tags:?}");
        assert!(
            tags[0].starts_with("Leak:stdout:q=true:rules=") && tags[0].contains("github_token"),
            "事件格式不符:{tags:?}"
        );
    }

    /// stderr 命中 + stdout 命中不同规则 → 两条事件 + 合并去重 findings **保
    /// HARD_RULES 全局声明顺序**(R2 MUST-FIX 修复)。
    ///
    /// HARD_RULES 声明顺序:aws_access_key_id → github_token → anthropic_api_key →
    /// openai_api_key → pem_private_key → jwt → env_assignment → slack_webhook →
    /// stripe_secret_key → google_api_key → gitlab_pat → database_url →
    /// aliyun_access_key_id → tencent_secret_id → slack_token → huggingface_token(v6)
    ///
    /// 本测试故意选**互不交叉命中**的两条规则避免 `sk-*` 既命中 anthropic 又命中
    /// openai 的干扰:stdout=github_token,stderr=jwt →
    /// merged 必须 `["github_token", "jwt"]`(github 在 HARD_RULES 第 2 条,jwt 第 6 条)。
    #[test]
    fn post_exec_leak_scan_both_streams_emit_two_events_and_merge_findings() {
        let sink = CollectingSink::default();
        // stdout 含 github_token,stderr 含 JWT(三段 base64url)
        let stdout = b"leak1: ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ\n";
        let stderr = b"leak2: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n";
        let (q, findings) = post_exec_leak_scan(stdout, stderr, &sink);
        assert!(q);
        // exact order:HARD_RULES 里 github_token 在 jwt 前
        assert_eq!(
            findings,
            vec!["github_token", "jwt"],
            "merged 必须按 HARD_RULES 声明顺序(github 先于 jwt)"
        );
        let tags = sink.tags();
        assert_eq!(tags.len(), 2, "两源命中各发一条:{tags:?}");
        assert!(tags.iter().any(|t| t.starts_with("Leak:stdout:")));
        assert!(tags.iter().any(|t| t.starts_with("Leak:stderr:")));
    }

    /// **R2 MUST-FIX 守门**:**反向输入**(stdout=后声明的 jwt,stderr=前声明的
    /// github)也必须按 HARD_RULES 全局顺序(github 仍在前),而非"stdout-first
    /// 局部顺序"(那会让 jwt 排在 github 前,违反契约)。
    #[test]
    fn post_exec_leak_scan_reversed_input_still_follows_hard_rules_order() {
        let sink = CollectingSink::default();
        // stdout 含 jwt(HARD_RULES 第 6),stderr 含 github_token(第 2)
        let stdout = b"leak: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n";
        let stderr = b"leak: ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ\n";
        let (q, findings) = post_exec_leak_scan(stdout, stderr, &sink);
        assert!(q);
        // 即便 stdout 先含 jwt,merged 仍按 HARD_RULES:github 在前
        assert_eq!(
            findings,
            vec!["github_token", "jwt"],
            "反向输入仍须按 HARD_RULES 声明顺序;若得到 [jwt, github_token] 即\
             stdout-first 局部顺序漂移(R2 BLOCKER 回归)"
        );
    }

    /// **R2 round-2 守门**:跨流合成命中过滤。stdout 末尾 `API_KEY=` 不形成完整
    /// env_assignment 命中(尾部需要 value 部分);stderr 单独以 `abcd` 开头亦不命中。
    /// 但拼接重扫时 `API_KEY=\0abcd` 经 env_assignment 规则的 negated char class 可能
    /// 把 NUL + abcd 当合法 value 部分误命中。filter 后 merged 应为空。
    #[test]
    fn post_exec_leak_scan_no_synthetic_cross_stream_finding() {
        let sink = CollectingSink::default();
        // stdout 末尾"API_KEY="(不带值,单独扫不命中 env_assignment)
        let stdout = b"prefix log API_KEY=";
        // stderr 以普通文本开头(单独扫干净)
        let stderr = b"abcdefgh xyz";
        let (q, findings) = post_exec_leak_scan(stdout, stderr, &sink);
        assert!(
            !q,
            "两流单独都干净 → 不应 quarantine(即便拼接重扫可能合成命中)"
        );
        assert!(
            findings.is_empty(),
            "merged 应严格等于 stdout_hits ∪ stderr_hits = ∅;合成命中泄漏即\
             R2 round-2 回归:{findings:?}"
        );
    }

    /// **R2 final 守门(直接覆盖 filter 分支)**:`quarantined=true` 时 filter 必须
    /// 真生效 —— stdout 含真实 `github_token`,同时拼接边界让 stderr `API_KEY=` 与
    /// stdout 末尾的 ASCII value 形成 `env_assignment` 合成命中。filter 后 merged
    /// 必须严格等于 `stdout_hits ∪ stderr_hits = ["github_token"]`,**不能**含
    /// 跨流合成的 `env_assignment`。
    #[test]
    fn post_exec_leak_scan_filter_drops_synthetic_when_real_hit_exists() {
        let sink = CollectingSink::default();
        // stdout 含真实 github_token + 末尾"value"前缀 `K=`(本身不命中 env_assignment)
        let stdout = b"real ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ tail K=";
        // stderr 单独干净,但拼接后 `K=\0secretvalue` 可能命中 env_assignment
        let stderr = b"secretvalue trailing";
        let (q, findings) = post_exec_leak_scan(stdout, stderr, &sink);
        assert!(q, "stdout 真实 github_token → 必 quarantine");
        assert_eq!(
            findings,
            vec!["github_token"],
            "filter 必须丢弃跨流合成 env_assignment;merged 严格 = stdout∪stderr 真实命中:\
             {findings:?}"
        );
    }

    /// 非 UTF-8 字节降级为空文本(不扫),不应崩。
    #[test]
    fn post_exec_leak_scan_non_utf8_bytes_fail_safe() {
        let sink = CollectingSink::default();
        // 非法 UTF-8 序列
        let bad = [0xFF, 0xFE, 0xFD, b'\n'];
        let (q, findings) = post_exec_leak_scan(&bad, &bad, &sink);
        assert!(!q);
        assert!(findings.is_empty());
        assert!(sink.tags().is_empty());
    }
}
