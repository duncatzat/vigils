//! `vigil-hub demo` —— 零设置客户首次体验(<60s,无账号/key/网络)。
//!
//! 决策见 `docs/research/first-experience-decision.md`(多模型头脑风暴综合)。核心 aha(codex):
//! **"agent 用真实 secret 完成了有用的工作 —— 而模型、日志、审计从未拿到真值。"**
//!
//! **诚实第一**:本 demo 走 Vigil **真实运行时代码路径**(firewall DecisionRecord / SecretAliasMap
//! detokenize seam / 审计 hash-chain),**只模拟**外部 model/tool provider —— 不联系任何 LLM。seeded
//! secret 在进程内**本地生成**、明确标注,且证明它**从不**越过受保护边界(模型/账本)。
//!
//! 屏面文案按系统语言本地化(i18n):静态行用 [`tr`] 中 / 英并排,YES/NO 用 [`yn`]。

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

use crate::i18n::Lang;

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
pub fn run(args: &DemoArgs, lang: Lang) -> Result<(), DemoError> {
    banner(lang);

    // ── 装配真 Hub(in-memory 账本 + 真 firewall + 真 SecretAliasMap + 真审计)──
    let ledger = Arc::new(Ledger::open_in_memory()?);
    let session_id = ledger.start_session("vigil-demo", Some("vigil-hub-demo"))?;

    let policy = PolicyEngine::new(default_ruleset());
    // DEF-004:demo 是自包含模拟(planted 场景走 namespaced tool 指纹,不依赖
    // Inside/Outside 项目边界规则),**有意**不绑 CWD 边界,保持 default(空 roots)。
    // 空 roots 语义由 policy 引擎守门兜底:Outside 不匹配 → 落 default-deny floor。
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

    teaching_moment(lang, &demo_secret);

    // ── [1] 默认拒绝:agent 把**裸 secret**塞进工具调用 → 真 firewall 拒,绝不透传 ──
    section(tr(
        lang,
        "[1] default-deny: agent puts the RAW secret in the tool call",
        "[1] 默认拒绝:agent(你接入的 AI 助手)把明文密钥直接塞进工具调用",
    ));
    let raw_args = json!({ "token": demo_secret });
    let resp_a = hub
        .handle_request(req(1, raw_args))?
        .ok_or_else(|| DemoError::SelfCheck("raw-secret call produced no response".into()))?;
    print_decision(lang, &resp_a, "github.create_issue")?;
    if resp_a.error.is_none() {
        return Err(DemoError::SelfCheck(
            "expected raw secret to be DENIED, but it was allowed".into(),
        ));
    }
    println!(
        "    -> {}\n",
        tr(
            lang,
            "Vigil refuses to forward a raw secret to a tool/upstream.",
            "Vigil 拒绝把明文密钥转发给工具 / 上游。",
        )
    );

    // ── [2] Vigil 之道:agent 改传**占位符** secret://github_pat ──
    section(tr(
        lang,
        "[2] the Vigil way: the agent passes a PLACEHOLDER instead",
        "[2] Vigil 之道:agent 改传一个占位符",
    ));
    let alias_args = json!({ "token": "secret://github_pat" });
    // 预批准一次(模拟"你点了 Approve once");走真 scope-allow 路径 → 真 Allow 决策
    seed_one_time_approval(lang, &ledger, &session_id, &alias_args)?;
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

    println!(
        "    {}",
        tr(
            lang,
            "What the REMOTE MODEL saw (the call arguments sent to the model):",
            "远端模型看到的(也就是发给模型的调用参数):",
        )
    );
    println!("      {}", compact(remote_model_payload));
    print_scan(
        lang,
        tr(lang, "      real secret here?", "      含真密钥?"),
        remote_model_payload,
        &demo_secret,
    );
    println!(
        "      {}\n",
        tr(
            lang,
            "[no LLM is contacted in this demo - this is the exact payload Vigil would forward]",
            "[本 demo 不联系任何 LLM —— 这就是 Vigil 会转发的确切载荷]",
        )
    );

    println!(
        "    {}",
        tr(
            lang,
            "What the LOCAL TOOL received (placeholder restored to the real value, in memory only):",
            "本地工具收到的(占位符已还原成真值,只存在于内存里):",
        )
    );
    println!("      {}", compact(&local_tool_invocation));
    print_scan(
        lang,
        tr(lang, "      real secret here?", "      含真密钥?"),
        &local_tool_invocation,
        &demo_secret,
    );
    println!();

    println!(
        "    {}",
        tr(
            lang,
            "The tool's result LEAKED a credential; Vigil caught it before it reached the model:",
            "工具的返回结果里夹带了一个凭据;Vigil 在回传给模型前把它挡了下来:",
        )
    );
    println!("      {}", compact(&model_visible_result));
    print_scan(
        lang,
        tr(lang, "      real secret here?", "      含真密钥?"),
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
    section(tr(
        lang,
        "[3] tamper-evident audit ledger (no plaintext secrets stored)",
        "[3] 防篡改审计账本(不存任何明文密钥)",
    ));
    let events = ledger.replay_session_verified(&session_id)?;
    print_ledger(&events);
    ledger.verify_chain()?;
    let plaintext_in_ledger = events
        .iter()
        .any(|e| event_contains(e, &demo_secret) || event_contains(e, &leaked_secret));
    println!(
        "    {}: {}        {}: {}",
        tr(lang, "hash chain valid", "哈希链有效"),
        yn(lang, true),
        tr(lang, "plaintext secret in audit", "审计中含明文密钥"),
        yn(lang, plaintext_in_ledger),
    );
    if plaintext_in_ledger {
        return Err(DemoError::SelfCheck(
            "INVARIANT VIOLATED: a real secret appeared in the audit ledger".into(),
        ));
    }
    println!();

    // ── [4] 可证伪:篡改账本 → 真 verify 失败 ──
    if args.tamper {
        section(tr(
            lang,
            "[4] prove it's real - tamper with the ledger and re-verify",
            "[4] 证明它是真的 —— 篡改账本再重新校验",
        ));
        run_tamper_proof(lang)?;
        println!();
    } else {
        println!(
            "    {}\n",
            tr(
                lang,
                "(run `vigil-hub demo --tamper` to alter a ledger row and watch verification FAIL)",
                "(运行 `vigil-hub demo --tamper` 篡改一条账本行,看校验失败)",
            )
        );
    }

    ending_screen(lang);
    Ok(())
}

/// scope 预批准一次(真 `create_approval` + `approve`,让下一次同 args 调用走真 Allow 路径)。
fn seed_one_time_approval(
    lang: Lang,
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
    println!(
        "    {}",
        tr(
            lang,
            "firewall: needs approval -> [you approve once] -> ALLOW",
            "防火墙:需要审批 -> [你批准一次] -> ALLOW",
        )
    );
    Ok(())
}

/// tamper 证明:临时文件账本 → 写 2 条事件(verify 通过)→ 直接 SQL 改一行 → verify 失败。
fn run_tamper_proof(lang: Lang) -> Result<(), DemoError> {
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
        println!(
            "    {} -> {}: {}",
            tr(lang, "wrote 2 audit rows", "写入 2 条审计行"),
            tr(lang, "hash chain valid", "哈希链有效"),
            yn(lang, true),
        );

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
        match lang {
            Lang::En => println!(
                "    altered {} ledger row in place (changed its content, not its hash)",
                n
            ),
            Lang::Zh => println!("    就地篡改了 {} 条账本行(改了内容,没改哈希)", n),
        }

        let ledger2 = Ledger::open(&path)?;
        match ledger2.verify_chain() {
            Ok(()) => Err(DemoError::SelfCheck(
                "INVARIANT VIOLATED: ledger tamper was NOT detected".into(),
            )),
            Err(_) => {
                println!(
                    "    {} -> {}: {}  [x]  {}",
                    tr(lang, "re-verify after tamper", "篡改后重新校验"),
                    tr(lang, "hash chain valid", "哈希链有效"),
                    yn(lang, false),
                    tr(lang, "tamper DETECTED", "检测到篡改"),
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

// ── 按语言取文案 / YES-NO ──
/// 静态文案中 / 英并排(无插值的行用它)。
fn tr<'a>(lang: Lang, en: &'a str, zh: &'a str) -> &'a str {
    match lang {
        Lang::En => en,
        Lang::Zh => zh,
    }
}

/// 是/否展示词(YES/NO ↔ 是/否)。
fn yn(lang: Lang, yes: bool) -> &'static str {
    match (lang, yes) {
        (Lang::En, true) => "YES",
        (Lang::En, false) => "NO",
        (Lang::Zh, true) => "是",
        (Lang::Zh, false) => "否",
    }
}

// ── 打印 helpers ──
fn banner(lang: Lang) {
    println!();
    println!("  ============================================================");
    match lang {
        Lang::En => {
            println!("  VIGIL DEMO - in-memory, planted scenario, NOT guarding real yet");
            println!("  ============================================================");
            println!("  Real Vigil runtime code paths (firewall / redaction / audit).");
            println!(
                "  Only the external model/tool provider is simulated - no LLM is contacted.\n"
            );
        }
        Lang::Zh => {
            println!("  VIGIL 演示 —— 内存中、预置场景,尚未守护真实流量");
            println!("  ============================================================");
            println!("  跑的是 Vigil 真实运行时代码路径(防火墙 / 脱敏 / 审计)。");
            println!("  只有外部的模型 / 工具被模拟 —— 全程不联系任何 LLM。\n");
        }
    }
}

fn teaching_moment(lang: Lang, secret: &str) {
    match lang {
        Lang::En => {
            println!(
                "  A demo secret - freshly generated locally for this run (never leaves this process):"
            );
            println!("    github_pat = {}", secret);
            println!("  Watch: it reaches the tool, but the model & audit never see it.\n");
        }
        Lang::Zh => {
            println!("  一个 demo 密钥 —— 本次运行在本地新生成(绝不离开本进程):");
            println!("    github_pat = {}", secret);
            println!("  注意:它会抵达工具,但模型与审计始终看不到它。\n");
        }
    }
}

fn section(title: &str) {
    println!("  {}", title);
}

fn print_decision(lang: Lang, resp: &JsonRpcResponse, label: &str) -> Result<(), DemoError> {
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
                "    tool={}  -> {}: DENY  (rule={})  decision_id={}",
                label,
                tr(lang, "Vigil firewall", "Vigil 防火墙"),
                rule,
                short(decision_id)
            );
        }
        None => println!("    tool={}  -> ALLOW", label),
    }
    Ok(())
}

fn print_scan(lang: Lang, label: &str, v: &Value, needle: &str) {
    let present = value_contains(v, needle);
    println!("    {} {}", label, yn(lang, present));
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

fn ending_screen(lang: Lang) {
    println!("  ============================================================");
    match lang {
        Lang::En => {
            println!("  What just happened");
            println!("  ============================================================");
            println!("    Remote model saw:     secret://github_pat");
            println!("    Local tool received:  the real secret, only when the tool actually runs");
            println!("    Tool result returned: caught before reaching the model (none sent back)");
            println!("    Firewall:             default-deny + explicit approval");
            println!("    Audit ledger:         hash-chain valid, no plaintext secrets");
            println!();
            println!("    The agent did useful work with a real secret - while the model,");
            println!("    logs, and audit never received the real value.");
            println!();
            println!("    Philosophy:  local control plane / no token passthrough / fail-closed");
            println!("                 / audit everything / you stay in control");
            println!();
            println!(
                "    This was a planted scenario with a locally-generated fixture. The redaction,"
            );
            println!(
                "    firewall, and audit above are Vigil's real runtime code - only the model/tool"
            );
            println!("    provider was simulated.");
            println!();
            println!("    Protect your real agent:");
            println!("      vigil-hub setup --all        # one command, reversible");
            println!();
        }
        Lang::Zh => {
            println!("  刚刚发生了什么");
            println!("  ============================================================");
            println!("    远端模型看到的:     secret://github_pat");
            println!("    本地工具收到的:     真实密钥,只在工具实际执行时出现");
            println!("    工具结果返回:       回传前已拦下(没有密钥回流到模型)");
            println!("    防火墙:             默认拒绝 + 显式审批");
            println!("    审计账本:           哈希链有效,无任何明文密钥");
            println!();
            println!("    agent 用真实密钥完成了有用的工作 —— 而模型、日志、审计");
            println!("    始终没拿到那个真值。");
            println!();
            println!("    理念:  本地控制平面 / 不透传 token / fail-closed");
            println!("           / 一切皆审计 / 你始终掌控");
            println!();
            println!("    这是一个用本地生成的样本演的预置场景。上面的脱敏、防火墙与审计");
            println!("    都是 Vigil 真实的运行时代码 —— 只有模型 / 工具一侧是模拟的。");
            println!();
            println!("    保护你真实的 agent:");
            println!("      vigil-hub setup --all        # 一条命令接入,全程可逆");
            println!();
        }
    }
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    // demo 内置 self_check 在任一不变量被破坏时 fail-closed(SelfCheck error):
    // remote payload 泄漏真值 / local 没拿到真值 / 结果未脱敏 / 账本含明文 → run() 返 Err。
    // 故 run() 返 Ok 即**证明**整条可逆脱敏往返 + no-plaintext 不变量在真代码路径上成立。
    // 语言无关(两语言走同一逻辑);用 En 跑。
    #[test]
    fn demo_round_trip_and_invariants_hold() {
        run(&DemoArgs { tamper: false }, Lang::En)
            .expect("demo round-trip + no-plaintext invariants must hold");
    }

    // run(tamper) 仅当账本篡改被 verify_chain **检测到**才返 Ok(否则 SelfCheck error)。
    #[test]
    fn demo_tamper_is_detected() {
        run(&DemoArgs { tamper: true }, Lang::Zh)
            .expect("ledger tamper must be detected by verify_chain");
    }
}
