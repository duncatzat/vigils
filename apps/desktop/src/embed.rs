//! v0.5 P1 ADR 0014 α1 — GUI bin embed Hub 骨架。
//!
//! 把 vigil-desktop GUI bin 从只持 `Arc<Ledger>` 升级为同时持 `Arc<vigil_mcp::Hub>`,
//! 通过 Tauri `app.manage()` 注册为 State;为 α2(Tauri `#[command] resolve_approval`
//! 接通 ApprovalBroker)与 α3(in-process Condvar wakeup,< 100ms)铺底。
//!
//! # 严格范围(α1)
//!
//! - 只做 Hub 组装 + State 注入;**不**新增 `#[tauri::command]` handler
//! - **不**改 ApprovalBroker 路径(继续 ISS-019 Phase 1 短轮询 fallback,
//!   `crates/vigil-audit/src/approvals.rs::wait_for_resolution` 0 触碰)
//! - **不**复用 `apps/vigil-hub-cli/src/serve.rs::build_hub`,因为它内部 `Ledger::open`
//!   会与 `apps/desktop/src/bin/gui.rs` 已经 single-open 的 ledger 冲突
//!
//! # ADR 0014 §3.4 fail-closed 不变量
//!
//! caller(`gui.rs::main`)必须对 `gui_build_hub` 的 `Err` **立即 `exit(1)`**,
//! 绝不静默 fallback 到 "no Hub" 模式 —— 那等价于 firewall 不评估 / approval 不等待,
//! 是 zero-trust default-deny 的根本破坏。
//!
//! # 7 步 Hub 组装(逐步标注是否可失败)
//!
//! caller 已完成的两步(`gui.rs::main` 已 fail-closed):
//! - `vigil_desktop::ledger_path::resolve_ledger_path` — 失败 → `exit(1)`
//! - `Ledger::open(path)` — 失败 → `exit(1)`
//!
//! 本函数 7 步:
//! 1. `PolicyEngine::new(default_ruleset())` — **infallible**(`pub fn new(rules) -> Self`)
//! 2. `Firewall::new(ledger, policy, FirewallConfig::default())`,wrap `Arc::new`
//!    — **infallible**(`pub fn new(...) -> Self`)
//! 3. `StaticDescriptorOracle(DescriptorStatus::ApprovedStable)`,转 `Arc<dyn DescriptorOracle>`
//!    — **infallible**(元组 struct 直接构造)
//! 4. `Hub::new(ledger, firewall, oracle, HubConfig::default())`,wrap `Arc::new`
//!    — **infallible**(`pub fn new(...) -> Self`)
//! 5. `ledger.start_session("vigil-desktop-gui", Some("vigil-desktop"))`
//!    — **fallible** → `EmbedError::Audit`
//! 6. `hub.set_session_id_for_test(session_id)` — **fallible** → `EmbedError::Hub`
//!    (理论上启动期无并发,实际不会触发 `LockPoisoned`,但仍走 `Result` 不假设)
//! 7. 返回 `Arc<Hub>`
//!
//! # 禁止清单(grep 验证 0 命中)
//!
//! - `Ledger::open(`(避免与 caller 的 single-open 冲突)
//! - `attach_stdio_upstream` / `McpUpstream`(α1 不接 upstream,留 α2+)
//! - `OrtEngine` / `enable-privacy-filter`(`vigil-firewall.default-features = false`,
//!   走 `NoopEngine` 默认 PiiScanner;privacy filter 不在 GUI α1 路径)
//! - `unwrap_or` / `let _ =` / `.ok().flatten()`(任何静默 fallback)

use std::sync::Arc;

use thiserror::Error;
use vigil_audit::{AuditError, Ledger};
use vigil_firewall::scorer::{DescriptorOracle, DescriptorStatus, StaticDescriptorOracle};
use vigil_firewall::{Firewall, FirewallConfig};
use vigil_mcp::{Hub, HubConfig, HubError, SecretAliasMap};
use vigil_policy::{defaults::default_ruleset, PolicyEngine};

/// embed Hub 组装失败原因。
///
/// caller(GUI `main`)收到任一 variant 都必须 `exit(1)`(ADR 0014 §3.4)。
#[derive(Debug, Error)]
pub enum EmbedError {
    /// `ledger.start_session` 失败(SQLite 写错误 / lock 等)。
    #[error("audit: {0}")]
    Audit(#[from] AuditError),
    /// `hub.set_session_id_for_test` 失败。启动期无并发,实际不会触发 `LockPoisoned`,
    /// 但 API 是 `Result`,不假设。
    #[error("hub: {0}")]
    Hub(#[from] HubError),
}

/// 组装 GUI embed 用的 `Arc<Hub>`(详见模块级 doc 7 步说明)。
///
/// caller 必须先 `Ledger::open` 成功,再把 `Arc::clone(&ledger)` 喂给本函数 —
/// 这样 GUI `AppState.ledger` 与 Hub 内部 `ledger` 共享同一份(`Arc::strong_count`
/// 至少 +1,见 `tests/embed_hub_skeleton.rs::gui_build_hub_shares_ledger_arc`)。
///
/// # ADR 0014 §3.4 fail-closed 不变量
///
/// 任一步失败 → caller 必须 `exit(1)`,**绝不**静默 fallback。
pub fn gui_build_hub(ledger: Arc<Ledger>) -> Result<Arc<Hub>, EmbedError> {
    // 1. PolicyEngine —— 默认规则集(default_ruleset = v0.3 + PII rules)
    let policy = PolicyEngine::new(default_ruleset());

    // 2. Firewall —— 无 allowed_hosts / project_roots / 自定义 PiiScanner;
    //    走 FirewallConfig::default + 内置 NoopEngine DefaultScanner
    //    (`vigil-firewall.default-features = false` 保证不拉 ort)。
    //    DEF-004:GUI 从开始菜单启动,CWD 不可预测(可能是 system32),**有意**不绑
    //    CWD 边界。空 roots 语义(policy 引擎守门后)= Inside/Outside 双双不匹配,
    //    FsWrite 落 default-deny floor —— 仍 fail-closed,且 reason 诚实。
    let firewall = Arc::new(Firewall::new(
        ledger.clone(),
        policy,
        FirewallConfig::default(),
    ));

    // 3. DescriptorOracle —— Stage 1 静态 ApprovedStable 兜底,与 vigil-hub-cli serve 对齐;
    //    Stage 2 应换 `RegistryDescriptorOracle` 实时查 Ledger(留 P2/P3)
    let oracle: Arc<dyn DescriptorOracle> =
        Arc::new(StaticDescriptorOracle(DescriptorStatus::ApprovedStable));

    // 4. Hub —— `HubConfig::default` 保证 approval_wait = 300s(ISS-019 Phase 2 守门),
    //    auto_approve_first_seen_tools = false(zero-trust default)
    let hub = Arc::new(Hub::new(
        ledger.clone(),
        firewall,
        oracle,
        HubConfig::default(),
        // Desktop embed 暂不声明 `secret://` alias(可逆脱敏 Slice 2 走 CLI serve 配置路径);
        // 空 map = fail-closed(任何 `secret://x` 引用都 deny)。Desktop 审批门控 minting 留后续。
        SecretAliasMap::default(),
    ));

    // 5. 开 session —— GUI bin 启动即等价于 "用户开始使用 vigil-desktop GUI"
    let session_id = ledger.start_session("vigil-desktop-gui", Some("vigil-desktop"))?;

    // 6. 注入 session_id —— set_session_id_for_test 是 vigil-mcp 的命名瑕疵
    //    (见 `crates/vigil-mcp/src/hub.rs` doc),Hub 对外只暴露这一个 session 注入入口;
    //    serve.rs::build_hub 同样使用,P3 重命名为 `set_session_id` 时本处一并改
    hub.set_session_id_for_test(session_id)?;

    // 7. 返回 Arc<Hub> —— caller 通过 `app.manage(hub)` 注册到 Tauri State
    Ok(hub)
}
