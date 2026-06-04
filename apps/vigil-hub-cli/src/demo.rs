//! `vigil-hub demo` —— 零设置客户首次体验(<60s,无账号/key/网络)。
//!
//! 决策见 `docs/research/first-experience-decision.md`(多模型头脑风暴综合)。核心 aha(codex):
//! **"agent 用真实 secret 完成了有用的工作 —— 而模型、日志、审计从未拿到真值。"**
//!
//! **诚实第一**:本 demo 走 Vigil **真实运行时代码路径**(firewall DecisionRecord / SecretAliasMap
//! detokenize seam / 审计 hash-chain),**只模拟**外部 model/tool provider —— 不联系任何 LLM。seeded
//! secret 在进程内**本地生成**、明确标注,且证明它**从不**越过受保护边界(模型/账本)。

#![allow(clippy::uninlined_format_args)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use vigil_audit::{ApprovalTargetContext, Ledger, ReplayEvent};
use vigil_firewall::scorer::{DescriptorStatus, StaticDescriptorOracle};
use vigil_firewall::{Firewall, FirewallConfig};
use vigil_lease::SecretValue;
use vigil_mcp::protocol::JsonRpcRequest;
use vigil_mcp::upstream::{McpUpstream, UpstreamError};
use vigil_mcp::{compute_argv_hash, Hub, HubConfig, JsonRpcResponse, SecretAliasMap};
use vigil_policy::{defaults::default_ruleset, PolicyEngine};
use vigil_types::{
    ApprovalScope, DecisionKind, DecisionRecord, EffectVector, ServerProfile, TransportKind,
    TrustLevel,
};

/// `vigil-hub demo` 参数。
#[derive(Debug, Clone, Default)]
pub struct DemoArgs {
    /// 额外演示**可证伪**:篡改一条账本行,再跑真 `verify_chain` → 检测到篡改(失败)。
    pub tamper: bool,
}

/// demo 错误(任何内部步骤失败都 fail-closed 报错,不伪装成功)。
#[derive(Debug, thiserror::Error)]
pub enum DemoError {
    /// 审计层
    #[error("demo audit error: {0}")]
    Audit(#[from] vigil_audit::AuditError),
    /// Hub
    #[error("demo hub error: {0}")]
    Hub(#[from] vigil_mcp::HubError),
    /// JSON 规范化(compute_argv_hash 等)
    #[error("demo json error: {0}")]
    Json(#[from] serde_json::Error),
    /// 随机源不可用(生成 demo secret)
    #[error("entropy source unavailable for demo secret generation")]
    Entropy,
    /// 内部不变量被违反(demo 自检失败 —— 绝不静默)
    #[error("demo self-check failed: {0}")]
    SelfCheck(String),
    /// tamper 演示的临时账本 IO/SQL
    #[error("demo tamper ledger error: {0}")]
    Tamper(String),
}

const SERVER_ID: &str = "github";
const TOOL_NAME: &str = "create_issue";
const NAMESPACED_TOOL: &str = "github__create_issue";

// ── 捕获 args 的 demo 上游(模拟外部工具;**唯一**被模拟的部分)──
#[derive(Debug)]
struct DemoUpstream {
    /// 最近一次收到的 `arguments`(= detokenize 后送给本地工具的真值)。
    last_arguments: Mutex<Option<Value>>,
    /// 模拟工具"不慎把一个凭据写进了返回结果"——用于演示 Slice 1 结果再脱敏。
    leaked_in_result: String,
}

impl McpUpstream for DemoUpstream {
    fn server_id(&self) -> &str {
        SERVER_ID
    }
    fn transport(&self) -> TransportKind {
        TransportKind::Stdio
    }
    fn call(
        &self,
        _method: &str,
        params: Option<Value>,
        _timeout: Duration,
    ) -> Result<Value, UpstreamError> {
        if let Some(p) = &params {
            if let Ok(mut g) = self.last_arguments.lock() {
                *g = p.get("arguments").cloned();
            }
        }
        // 工具返回结果里"不慎"夹带了一个内部凭据(模拟真实泄漏场景)
        Ok(json!({
            "issue_url": "https://api.github.test/repos/acme/app/issues/42",
            "ok": true,
            "debug_trace": format!("authenticated with {} (internal)", self.leaked_in_result),
        }))
    }
    fn shutdown(&self) {}
}

/// 本地生成一个**形似真实**的 demo GitHub PAT(`ghp_` + 36 hex)。每次运行不同、绝不联网、明确标注 seeded。
fn gen_demo_token() -> Result<String, DemoError> {
    let mut buf = [0u8; 18];
    getrandom::getrandom(&mut buf).map_err(|_| DemoError::Entropy)?;
    Ok(format!("ghp_{}", hex::encode(buf))) // 4 + 36 = 40 chars,命中 github_token 硬指纹
}

/// args(`arguments` object)的规范化 SHA-256 —— 与 Hub 内部 `jcs_sha256` 一致,用于 scope 预批准。
fn jcs_sha256(v: &Value) -> String {
    let bytes = serde_jcs::to_vec(v).unwrap_or_default();
    let mut h = Sha256::new();
    h.update(&bytes);
    hex::encode(h.finalize())
}

fn req(id: i64, args: Value) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: Some(json!(id)),
        method: "tools/call".into(),
        params: Some(json!({ "name": NAMESPACED_TOOL, "arguments": args })),
    }
}

/// demo 主入口。
pub fn run(args: &DemoArgs) -> Result<(), DemoError> {
    banner();

    // ── 装配真 Hub(in-memory 账本 + 真 firewall + 真 SecretAliasMap + 真审计)──
    let ledger = Arc::new(Ledger::open_in_memory()?);
    let session_id = ledger.start_session("vigil-demo", Some("vigil-hub-demo"))?;

    let policy = PolicyEngine::new(default_ruleset());
    let firewall = Arc::new(Firewall::new(
        ledger.clone(),
        policy,
        FirewallConfig::default(),
    ));
    let oracle = Arc::new(StaticDescriptorOracle(DescriptorStatus::ApprovedStable));

    // 本地生成 seeded 真值 + alias 映射(operator 声明的 secret://github_pat → 真值,限定 github)
    let demo_secret = gen_demo_token()?;
    let leaked_secret = gen_demo_token()?; // 工具结果里"泄漏"的另一凭据
    let mut aliases = SecretAliasMap::default();
    aliases.insert(
        "github_pat",
        SecretValue::new(demo_secret.clone()),
        SERVER_ID,
    );

    let hub = Arc::new(Hub::new(
        ledger.clone(),
        firewall,
        oracle,
        HubConfig {
            approval_wait: Duration::from_millis(200),
            redact_tool_results: true, // 开启结果再脱敏(Slice 1),演示工具回吐 secret 被堵
            ..Default::default()
        },
        aliases,
    ));

    // 注册 + 信任 + attach demo 上游(模拟工具),注入 route/session(跳过 stdio 真 spawn)
    let argv = vec!["demo-upstream".to_string()];
    let command_hash = compute_argv_hash(&argv)?;
    ledger.register_server(&ServerProfile {
        server_id: SERVER_ID.into(),
        transport: TransportKind::Stdio,
        command: Some(argv.clone()),
        url: None,
        first_seen_at: 0,
        command_hash: Some(command_hash),
        descriptor_hash: None,
        trust_level: TrustLevel::Untrusted,
        sandbox_profile_id: None,
    })?;
    ledger.approve_server(SERVER_ID, TrustLevel::Limited)?;
    let upstream = Arc::new(DemoUpstream {
        last_arguments: Mutex::new(None),
        leaked_in_result: leaked_secret.clone(),
    });
    hub.attach_upstream(SERVER_ID, &argv, upstream.clone())?;
    hub.set_session_id_for_test(&session_id)?;
    hub.inject_route_for_test(SERVER_ID, TOOL_NAME, "demo_descriptor_hash")?;

    teaching_moment(&demo_secret);

    // ── [1] 默认拒绝:agent 把**裸 secret**塞进工具调用 → 真 firewall 拒,绝不透传 ──
    section("[1] default-deny: agent puts the RAW secret in the tool call");
    let raw_args = json!({ "token": demo_secret });
    let resp_a = hub
        .handle_request(req(1, raw_args))?
        .ok_or_else(|| DemoError::SelfCheck("raw-secret call produced no response".into()))?;
    print_decision(&resp_a, "github.create_issue", &demo_secret)?;
    if resp_a.error.is_none() {
        return Err(DemoError::SelfCheck(
            "expected raw secret to be DENIED, but it was allowed".into(),
        ));
    }
    println!("    -> Vigil refuses to forward a raw secret to a tool/upstream.\n");

    // ── [2] Vigil 之道:agent 改传**占位符** secret://github_pat ──
    section("[2] the Vigil way: the agent passes a PLACEHOLDER instead");
    let alias_args = json!({ "token": "secret://github_pat" });
    // 预批准一次(模拟"你点了 Approve once");走真 scope-allow 路径 → 真 Allow 决策
    seed_one_time_approval(&ledger, &session_id, &alias_args)?;
    let resp_b = hub
        .handle_request(req(2, alias_args.clone()))?
        .ok_or_else(|| DemoError::SelfCheck("alias call produced no response".into()))?;
    if resp_b.error.is_some() {
        return Err(DemoError::SelfCheck(format!(
            "expected alias call to be ALLOWED, got error: {:?}",
            resp_b.error
        )));
    }

    // ── 三份真实 payload + 扫描(可信度命门:展示工具在"做",不是"贴标签")──
    let remote_model_payload = &alias_args; // 模型边界所见 = agent 写的占位符 args
    let local_tool_invocation = upstream
        .last_arguments
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .ok_or_else(|| DemoError::SelfCheck("upstream was never called".into()))?;
    let model_visible_result = resp_b
        .result
        .clone()
        .ok_or_else(|| DemoError::SelfCheck("alias call had no result".into()))?;

    println!("    What the REMOTE MODEL saw (args, as sent to the model boundary):");
    println!("      {}", compact(remote_model_payload));
    print_scan(
        "      plaintext secret?",
        remote_model_payload,
        &demo_secret,
    );
    println!("      [no LLM is contacted in this demo - this is the exact payload Vigil would forward]\n");

    println!("    What the LOCAL TOOL received (detokenized, in-memory only):");
    println!("      {}", compact(&local_tool_invocation));
    print_scan(
        "      contains real value?",
        &local_tool_invocation,
        &demo_secret,
    );
    println!();

    println!("    The tool's result LEAKED a credential; Vigil re-redacted it (Slice 1):");
    println!("      {}", compact(&model_visible_result));
    print_scan(
        "      plaintext secret back to model?",
        &model_visible_result,
        &leaked_secret,
    );
    println!();

    // 自检不变量(诚实:若任一不成立,fail-closed 报错而非伪装)
    self_check(
        remote_model_payload,
        &local_tool_invocation,
        &model_visible_result,
        &demo_secret,
        &leaked_secret,
    )?;

    // ── [3] 防篡改审计账本(零明文)──
    section("[3] tamper-evident audit ledger (no plaintext secrets stored)");
    let events = ledger.replay_session_verified(&session_id)?;
    print_ledger(&events);
    ledger.verify_chain()?;
    let plaintext_in_ledger = events
        .iter()
        .any(|e| event_contains(e, &demo_secret) || event_contains(e, &leaked_secret));
    println!(
        "    hash chain valid: YES        plaintext secret in audit: {}",
        yes_no(!plaintext_in_ledger, /*good_is*/ false)
    );
    if plaintext_in_ledger {
        return Err(DemoError::SelfCheck(
            "INVARIANT VIOLATED: a real secret appeared in the audit ledger".into(),
        ));
    }
    println!();

    // ── [4] 可证伪:篡改账本 → 真 verify 失败 ──
    if args.tamper {
        section("[4] prove it's real - tamper with the ledger and re-verify");
        run_tamper_proof()?;
        println!();
    } else {
        println!("    (run `vigil-hub demo --tamper` to alter a ledger row and watch verification FAIL)\n");
    }

    ending_screen();
    Ok(())
}

/// scope 预批准一次(真 `create_approval` + `approve`,让下一次同 args 调用走真 Allow 路径)。
fn seed_one_time_approval(
    ledger: &Ledger,
    session_id: &str,
    call_args: &Value,
) -> Result<(), DemoError> {
    let args_hash = jcs_sha256(call_args);
    let dec = DecisionRecord {
        decision_id: "demo-approval".into(),
        invocation_id: "demo-inv".into(),
        decision: DecisionKind::Approve,
        risk_score: 0,
        reasons: vec!["approved once for the demo".into()],
        policy_ids: vec![],
        created_at: 0,
    };
    let ctx = ApprovalTargetContext {
        server_id: Some(SERVER_ID),
        tool_name: Some(TOOL_NAME),
        args_hash: Some(&args_hash),
    };
    let prev = ledger.create_approval(
        session_id,
        &dec,
        &EffectVector::default(),
        TOOL_NAME,
        SERVER_ID,
        600,
        ctx,
    )?;
    ledger.approve(&prev.approval_id, ApprovalScope::ThisSession, Some("you"))?;
    println!("    firewall: needs approval -> [you approve once] -> ALLOW");
    Ok(())
}

/// tamper 证明:临时文件账本 → 写 2 条事件(verify 通过)→ 直接 SQL 改一行 → verify 失败。
fn run_tamper_proof() -> Result<(), DemoError> {
    let dir = std::env::temp_dir().join(format!("vigil-demo-tamper-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| DemoError::Tamper(e.to_string()))?;
    let path = dir.join("ledger.sqlite");
    let _ = std::fs::remove_file(&path);

    let result = (|| -> Result<(), DemoError> {
        let ledger = Ledger::open(&path)?;
        let sid = ledger.start_session("vigil-demo-tamper", None)?;
        ledger.append_event(
            &sid,
            "demo.note",
            &json!({"step": "before tamper"}),
            Some("clean row"),
        )?;
        ledger.append_event(
            &sid,
            "demo.note",
            &json!({"step": "second"}),
            Some("another row"),
        )?;
        ledger.verify_chain()?;
        println!("    wrote 2 audit rows -> hash chain valid: YES");

        // 直接改一行的 redacted_text(不更新其 event_hash)→ 链断裂
        let conn =
            rusqlite::Connection::open(&path).map_err(|e| DemoError::Tamper(e.to_string()))?;
        let n = conn
            .execute(
                "UPDATE events SET redacted_text = 'TAMPERED' WHERE rowid = (SELECT MIN(rowid) FROM events)",
                [],
            )
            .map_err(|e| DemoError::Tamper(e.to_string()))?;
        drop(conn);
        println!(
            "    altered {} ledger row in place (changed its content, not its hash)",
            n
        );

        let ledger2 = Ledger::open(&path)?;
        match ledger2.verify_chain() {
            Ok(()) => Err(DemoError::SelfCheck(
                "INVARIANT VIOLATED: ledger tamper was NOT detected".into(),
            )),
            Err(_) => {
                println!(
                    "    re-verify after tamper -> hash chain valid: NO  [x]  tamper DETECTED"
                );
                Ok(())
            }
        }
    })();

    let _ = std::fs::remove_dir_all(&dir); // best-effort cleanup
    result
}

// ── 自检(诚实不变量;任一不成立即 fail,不伪装)──
fn self_check(
    remote: &Value,
    local: &Value,
    result: &Value,
    real_secret: &str,
    leaked: &str,
) -> Result<(), DemoError> {
    let bad = |m: &str| DemoError::SelfCheck(m.to_string());
    if value_contains(remote, real_secret) {
        return Err(bad("remote model payload leaked the real secret"));
    }
    if !value_contains(local, real_secret) {
        return Err(bad(
            "local tool did NOT receive the real value (detokenize failed)",
        ));
    }
    if value_contains(result, leaked) || value_contains(result, real_secret) {
        return Err(bad(
            "model-visible result still contains a plaintext secret",
        ));
    }
    Ok(())
}

// ── 打印 helpers ──
fn banner() {
    println!();
    println!("  ============================================================");
    println!("  VIGIL DEMO - in-memory, planted scenario, NOT guarding real yet");
    println!("  ============================================================");
    println!("  Real Vigil runtime code paths (firewall / redaction / audit).");
    println!("  Only the external model/tool provider is simulated - no LLM is contacted.\n");
}

fn teaching_moment(secret: &str) {
    println!(
        "  A demo secret - freshly generated locally for this run (never leaves this process):"
    );
    println!("    github_pat = {}", secret);
    println!("  Watch: it reaches the tool, but the model & audit never see it.\n");
}

fn section(title: &str) {
    println!("  {}", title);
}

fn print_decision(resp: &JsonRpcResponse, label: &str, _secret: &str) -> Result<(), DemoError> {
    match &resp.error {
        Some(e) => {
            let decision_id = e
                .data
                .as_ref()
                .and_then(|d| d.get("decision_id"))
                .and_then(Value::as_str)
                .unwrap_or("-");
            let rule = e
                .data
                .as_ref()
                .and_then(|d| d.get("rule"))
                .and_then(Value::as_str)
                .unwrap_or("-");
            println!(
                "    tool={}  -> Vigil firewall: DENY  (rule={})  decision_id={}",
                label,
                rule,
                short(decision_id)
            );
        }
        None => println!("    tool={}  -> ALLOW", label),
    }
    Ok(())
}

fn print_scan(label: &str, v: &Value, needle: &str) {
    let present = value_contains(v, needle);
    println!("    {} {}", label, if present { "YES" } else { "NO" });
}

fn print_ledger(events: &[ReplayEvent]) {
    for (i, e) in events.iter().enumerate() {
        println!(
            "      {:04} sha256:{}  {}",
            i + 1,
            short(&e.event_hash),
            e.event_type
        );
    }
}

fn ending_screen() {
    println!("  ============================================================");
    println!("  What just happened");
    println!("  ============================================================");
    println!("    Remote model saw:     secret://github_pat");
    println!("    Local tool received:  the real secret, only at the execution boundary");
    println!("    Tool result returned: re-redacted (no secret back to the model)");
    println!("    Firewall:             default-deny + explicit approval");
    println!("    Audit ledger:         hash-chain valid, no plaintext secrets");
    println!();
    println!("    The agent did useful work with a real secret - while the model,");
    println!("    logs, and audit never received the real value.");
    println!();
    println!("    Philosophy:  local control plane / no token passthrough / fail-closed");
    println!("                 / audit everything / you stay in control");
    println!();
    println!("    This was a planted scenario with a locally-generated fixture. The redaction,");
    println!("    firewall, and audit above are Vigil's real runtime code - only the model/tool");
    println!("    provider was simulated.");
    println!();
    println!("    Protect your real agent:");
    println!("      vigil-hub serve --stdio      # point Claude Code / Codex / Cursor at it");
    println!();
}

// ── 小工具 ──
fn compact(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "<unserializable>".into())
}
fn short(s: &str) -> String {
    s.chars().take(12).collect()
}
fn value_contains(v: &Value, needle: &str) -> bool {
    serde_json::to_string(v)
        .map(|s| s.contains(needle))
        .unwrap_or(false)
}
fn event_contains(e: &ReplayEvent, needle: &str) -> bool {
    value_contains(&e.payload, needle)
        || e.redacted_text
            .as_deref()
            .map(|t| t.contains(needle))
            .unwrap_or(false)
}
/// good_is=false 时,`ok=true`(无明文)显示绿色语义 "NO"。这里只返回展示串。
fn yes_no(ok: bool, _good_is: bool) -> &'static str {
    if ok {
        "NO"
    } else {
        "YES"
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    // demo 内置 self_check 在任一不变量被破坏时 fail-closed(SelfCheck error):
    // remote payload 泄漏真值 / local 没拿到真值 / 结果未脱敏 / 账本含明文 → run() 返 Err。
    // 故 run() 返 Ok 即**证明**整条可逆脱敏往返 + no-plaintext 不变量在真代码路径上成立。
    #[test]
    fn demo_round_trip_and_invariants_hold() {
        run(&DemoArgs { tamper: false })
            .expect("demo round-trip + no-plaintext invariants must hold");
    }

    // run(tamper) 仅当账本篡改被 verify_chain **检测到**才返 Ok(否则 SelfCheck error)。
    #[test]
    fn demo_tamper_is_detected() {
        run(&DemoArgs { tamper: true }).expect("ledger tamper must be detected by verify_chain");
    }
}
