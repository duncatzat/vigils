//! Vigil Hub —— 对外暴露为 MCP server,内部聚合并转发到上游(ADR 0004 §D5)。
//!
//! I04 实装**同步**模型:Hub 本身不做 IO,只提供 `handle_request(req) -> response`
//! 供上层驱动(CLI / test)喂 JSON-RPC message。真实的 stdio 入口在 `apps/vigil-hub-cli`。
//!
//! 处理的 method 子集(ADR 0004 §D1):
//! - `initialize` / `initialized` / `shutdown` / `ping` / `notifications/cancelled`
//! - `tools/list` / `tools/call`
//!
//! 未实装的 method → 返回 `METHOD_NOT_FOUND`。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use vigil_audit::{Ledger, ResolvedProgramOutcome};
use vigil_firewall::scorer::DescriptorOracle;
use vigil_firewall::{Firewall, FirewallOutcome, OAuthScopeContext};
use vigil_types::{
    ApprovalStatus, DecisionKind, DecisionRecord, EffectKind, EffectVector, ToolInvocation,
};
use vigil_ui_protocol::{ApprovalAction, ApprovalResolutionDto, ResolveApprovalReq};

use crate::namespace::{self, ToolRouter};
use crate::protocol::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};
use crate::stdio::{resolve_program, StdioError, StdioUpstream};
use crate::upstream::{McpUpstream, UpstreamError};

/// Hub 错误。
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HubError {
    /// 审计层错误
    #[error("audit: {0}")]
    Audit(#[from] vigil_audit::AuditError),
    /// firewall 错误
    #[error("firewall: {0}")]
    Firewall(#[from] vigil_firewall::FirewallError),
    /// namespace 错误
    #[error("namespace: {0}")]
    Namespace(#[from] crate::namespace::NamespaceError),
    /// 上游通用错误(`McpUpstream` trait 统一投影)——
    /// 代码 R1 MUST-FIX:Hub 对上游只暴露**单通道** `UpstreamError`,
    /// `StdioError` 在 `impl McpUpstream for StdioUpstream` 内部被映射为本变体,
    /// 不再从 Hub 层暴露 `HubError::Stdio` 这个旧并列分支。
    #[error("upstream: {0}")]
    Upstream(#[from] UpstreamError),
    /// JSON 错误
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// 锁污染
    #[error("internal lock poisoned")]
    LockPoisoned,
    /// I05:上游 argv 哈希与已批准的 command_hash 不等,拒绝启动
    #[error("server `{server_id}` command hash drift: old={old_hash} new={new_hash}")]
    CommandDrift {
        /// drift 的 server id
        server_id: String,
        /// 已批准的旧 hash
        old_hash: String,
        /// 本次 spawn 检测到的新 hash
        new_hash: String,
    },
    /// V1.1(ADR 0007 §I-7.1 / ADR 0005 第二独立维度):上游裸命令**解析后绝对路径**与已 pin
    /// 基线漂移,拒绝启动。与 `CommandDrift`(argv 文本)正交 —— argv 不变但解析二进制变
    /// (PATH shadow / 重定位)。caller 须先 `Ledger::approve_server_resolved_program_drift`。
    #[error("server `{server_id}` resolved-program drift: old={old} new={new}")]
    ResolvedProgramDrift {
        /// drift 的 server id
        server_id: String,
        /// 已 pin 的旧解析路径
        old: String,
        /// 本次解析出的新路径
        new: String,
    },
    /// V1.1:Hub-owned stdio spawn 路径(`spawn_attach_stdio_upstream`)的 resolve / spawn
    /// 阶段失败。**与请求期的 `Upstream(UpstreamError)` 通道区分** —— 本变体只在 attach 时
    /// 一次性 spawn 出现(resolve PATH 失败 = `StdioError::ProgramNotFound` / 起进程失败 = `Spawn`)。
    #[error("stdio spawn: {0}")]
    StdioSpawn(#[source] StdioError),
    /// v0.5 P1 ADR 0014 α2:caller 传入参数语义不合法(例如 `Hub::resolve_approval`
    /// 在 `ApprovalAction::Approve` 路径上未提供 `scope`)。**仅承载短文本,不含
    /// secret / PII / DB 行内容**(与 `UiError::Invalid` 同语义层级)。
    #[error("invalid request: {0}")]
    Invalid(String),
}

/// Hub 配置。
#[derive(Debug, Clone)]
pub struct HubConfig {
    /// 等待 approval 的最长时间。
    pub approval_wait: Duration,
    /// 上游 tools/list 超时。
    pub upstream_list_timeout: Duration,
    /// 上游 tools/call 超时。
    pub upstream_call_timeout: Duration,
    /// 是否对 CommSend / NetOutbound 效应启用 Outbox 预览(默认 true)。
    pub outbox_enabled: bool,
    /// **开发模式**:tools/list 首次见到的 descriptor 自动批准(AGENTS §5 默认 false)。
    /// 生产必须保持 false,由 UI(I08)触发显式 approve_tool_descriptor。
    pub auto_approve_first_seen_tools: bool,
}

impl Default for HubConfig {
    fn default() -> Self {
        Self {
            approval_wait: Duration::from_secs(300),
            upstream_list_timeout: Duration::from_secs(10),
            upstream_call_timeout: Duration::from_secs(30),
            outbox_enabled: true,
            auto_approve_first_seen_tools: false,
        }
    }
}

/// ISS-015:agent 在 tool args 里直传原 key(非 `secret://alias` 引用)被拦时
/// 的审计事件类型。无保留前缀,可直接走 `append_event`。
pub const EVENT_RAW_SECRET_ATTEMPT_DETECTED: &str = "raw_secret_attempt_detected";

/// ISS-016:upstream response 回吐 secret 被 post-exec 扫到时的审计事件类型。
/// `secret.` 不在 `RESERVED_EVENT_PREFIXES`(仅 `tool_call. / decision. / approval. /
/// lease.` 是保留前缀),因此合法。本事件是 **out-of-band** —— 不改变返给 agent 的
/// result,只在审计链上留痕 + 累加 `Hub::leak_detected_count()`。
pub const EVENT_SECRET_LEAK_DETECTED: &str = "secret.leak_detected";

/// Vigil Hub。
pub struct Hub {
    ledger: Arc<Ledger>,
    firewall: Arc<Firewall>,
    oracle: Arc<dyn DescriptorOracle>,
    router: Mutex<ToolRouter>,
    upstreams: Mutex<HashMap<String, Arc<dyn McpUpstream>>>,
    /// V1.1(Codex code R2):**序列化所有 stdio attach**。`spawn_attach_stdio_upstream` 全程持有,
    /// 让"早 dup 检查 → spawn → insert"对同一/不同 server_id 的并发 attach 串行 —— 杜绝两并发同名
    /// 调用都过早检查后各 spawn 一个进程再 drop 的副作用泄漏。**不**阻塞请求热路径(请求只锁
    /// `upstreams` map,与本锁无关);attach 是启动/低频操作,串行可接受。
    attach_lock: Mutex<()>,
    config: HubConfig,
    session_id: Mutex<Option<String>>,
    /// ISS-016:本进程生命周期内 upstream response 扫到 secret leak 的累计次数。
    /// 未来 feedback loop(lease 收敛)的最小可观察性前置 —— 当前版本只产生审计事件
    /// + 本计数器;真正"命中 N 次自动 revoke lease"延至 Hub 集成 SecretBroker 后实装。
    leak_detected_count: AtomicU64,
}

impl std::fmt::Debug for Hub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hub").field("config", &self.config).finish()
    }
}

// ------------------------------------------------------------------
// 测试辅助 API —— ADR 0005 §D6(FU1)。
//
// **重要**:这两个方法**仅用于 Hub 内部集成测试**。它们不在任何
// AGENTS.md 不变量的 public API 范围内,也不会被 Vigil 生产组件
// 调用。未来若把 vigil-mcp 打包为发行 crate,建议改用 `TestHub`
// 包装类型或独立 `vigil-mcp-test-helpers` crate 收敛。
//
// 此处未用 `#[cfg(any(test, feature = "test-helpers"))]` 是因为 Cargo
// 的自依赖限制让 integration test 无法自动启用 feature;改用
// `#[doc(hidden)]` 从 rustdoc 层面藏起来,加名字前缀 `for_test`
// 作为肉眼可见的警示。
// ------------------------------------------------------------------
impl Hub {
    /// (仅测试)直接塞一条 ToolRoute,绕开 tools/list。
    #[doc(hidden)]
    pub fn inject_route_for_test(
        &self,
        server_id: &str,
        tool_name: &str,
        descriptor_hash: &str,
    ) -> Result<(), HubError> {
        let mut r = self.router.lock().map_err(|_| HubError::LockPoisoned)?;
        r.register(server_id, tool_name, descriptor_hash)?;
        Ok(())
    }

    /// (仅测试)设置 Hub 内部 session_id,跳过 initialize。
    #[doc(hidden)]
    pub fn set_session_id_for_test(&self, session_id: impl Into<String>) -> Result<(), HubError> {
        let mut g = self.session_id.lock().map_err(|_| HubError::LockPoisoned)?;
        *g = Some(session_id.into());
        Ok(())
    }
}

impl Hub {
    /// 组装一个 Hub。
    pub fn new(
        ledger: Arc<Ledger>,
        firewall: Arc<Firewall>,
        oracle: Arc<dyn DescriptorOracle>,
        config: HubConfig,
    ) -> Self {
        Self {
            ledger,
            firewall,
            oracle,
            router: Mutex::new(ToolRouter::default()),
            upstreams: Mutex::new(HashMap::new()),
            attach_lock: Mutex::new(()),
            config,
            session_id: Mutex::new(None),
            leak_detected_count: AtomicU64::new(0),
        }
    }

    /// ISS-016:返回本 Hub 进程生命周期内 upstream response 扫到 secret leak 的
    /// 累计次数。未来做真租约收敛时,此计数器将作为触发阈值的输入。
    pub fn leak_detected_count(&self) -> u64 {
        self.leak_detected_count.load(Ordering::Relaxed)
    }

    /// ISS-019 Phase 2:暴露 approval_wait 配置(单测守门用)。
    ///
    /// caller 通过此 getter 验证 Hub 实际生效的 wait timeout 值,确保 serve.rs
    /// 等组装层不再做 timing hack(如 v0.3 Stage 3 的 `dev_permissive_firewall →
    /// approval_wait=3s` 已被 Phase 1 短轮询 fallback 取代)。
    pub fn approval_wait(&self) -> std::time::Duration {
        self.config.approval_wait
    }

    /// v0.5 P1 ADR 0014 α2 — Approval 解析 thin-wrapper(对应 `Capability::Write`)。
    ///
    /// 在 `Hub` 上集中暴露**唯一**的 approval resolve 入口,作为后续 α3
    /// (in-process Condvar wakeup < 100ms 验证)与 GUI `#[tauri::command]
    /// resolve_approval` 的 single-point-of-change。
    ///
    /// 设计纪律(ADR 0014 Revised α2):
    /// - **不**引入第二个状态机 —— 完全委托给 `Ledger::approve / deny / cancel`,
    ///   状态迁移规则在 audit 层(`crates/vigil-audit/src/approvals.rs::resolve`)。
    /// - **不**做二次 redaction —— audit 层 `record_approval_resolved` /
    ///   `deny` 内部的 `redact_free_text` 已经覆盖。
    /// - **不**新增第二道 capability 闸 —— UI 调用方(dispatcher / Tauri command)
    ///   仍然先按 `UiCommand::required_capability()` 静态守门(Read/Write 配额)
    ///   再下沉到本 wrapper;Hub 这一层不再重复判定。
    ///
    /// In-process Condvar wakeup 由 `Ledger::approve / deny / cancel` 内部经
    /// `ApprovalBroker::publish` 同步触发,见
    /// `crates/vigil-audit/src/approvals.rs::resolve` 末尾的 publish 块
    /// (位于 update + record_approval_resolved 之后,保证 "DB 写完才广播")。
    ///
    /// 错误投影:`Ledger::*` 抛 `AuditError` → `HubError::Audit`(`#[from]`);
    /// `Approve` 缺 `scope` → `HubError::Invalid(...)`。
    pub fn resolve_approval(
        &self,
        req: ResolveApprovalReq,
    ) -> Result<ApprovalResolutionDto, HubError> {
        let resolution = match req.action {
            ApprovalAction::Approve => {
                let scope = req.scope.ok_or_else(|| {
                    HubError::Invalid("approve action requires scope (Once / ThisSession)".into())
                })?;
                self.ledger
                    .approve(&req.approval_id, scope, Some(&req.resolved_by))?
            }
            ApprovalAction::Deny => self.ledger.deny(
                &req.approval_id,
                req.reason.as_deref(),
                Some(&req.resolved_by),
            )?,
            ApprovalAction::Cancel => self
                .ledger
                .cancel(&req.approval_id, Some(&req.resolved_by))?,
        };
        Ok(ApprovalResolutionDto {
            approval_id: resolution.approval_id,
            status: resolution.status,
            scope: resolution.scope,
            resolved_by: resolution.resolved_by,
        })
    }

    /// 读取当前 session_id,用于在 drift 审计事件里填 session_id 字段。
    /// 若 Hub 未 initialize,退回到 `"system"`,让 audit 仍能写入。
    fn current_session_id(&self) -> Result<String, HubError> {
        let g = self.session_id.lock().map_err(|_| HubError::LockPoisoned)?;
        Ok(g.clone().unwrap_or_else(|| "system".to_string()))
    }

    /// 在真实 spawn 上游 stdio 进程**之前**检查 command hash 是否漂移。
    /// 若漂移:写 `server.command_drifted` 审计,返 `Err(HubError::CommandDrift)`,
    /// caller(Hub startup 代码 / I08 UI)必须先 `approve_server_command_drift`。
    pub fn check_upstream_command_drift(
        &self,
        server_id: &str,
        argv: &[String],
    ) -> Result<(), HubError> {
        let new_hash = compute_argv_hash(argv)?;
        // I08 R1 BLOCKER:同时传 argv 文本,Ledger 存 pending_command_json 供 UI §4.7 展示
        let drift = self
            .ledger
            .check_server_command_drift(server_id, argv, &new_hash)?;
        if let Some(d) = drift {
            let _ = self.ledger.append_event(
                &self.current_session_id()?,
                "server.command_drifted",
                &json!({
                    "server_id": server_id,
                    "old_hash": d.old,
                    "new_hash": d.new,
                }),
                Some(&format!("command_drift server:{server_id}")),
            );
            return Err(HubError::CommandDrift {
                server_id: server_id.to_string(),
                old_hash: d.old,
                new_hash: d.new,
            });
        }
        Ok(())
    }

    /// 注册一个已启动的上游 server 连接。caller 负责事先 `register_server` + `approve_server`。
    ///
    /// **I05 BLOCKER 修复**(ADR 0005 §D5 结构化 gate):本 API **强制**要求 caller
    /// 传入 `argv`(Stdio server 的启动命令),内部先调用 `check_server_command_drift`
    /// 确认未漂移,再挂连接。调用方无法绕过 command drift gate。
    ///
    /// 若 drift,返回 `HubError::CommandDrift` 并**不挂** upstream,caller 必须先
    /// `Ledger::approve_server_command_drift` 后重试。
    ///
    /// NICE-TO-HAVE(Codex I04 review):同一 server_id 重复注册静默覆盖是**危险**的
    /// (有 in-flight 请求时新老连接会错乱),改为**拒绝重复注册**。
    pub fn attach_upstream(
        &self,
        server_id: &str,
        argv: &[String],
        upstream: Arc<dyn McpUpstream>,
    ) -> Result<(), HubError> {
        namespace::validate_server_id(server_id).map_err(HubError::Namespace)?;
        // BLOCKER fix(Codex I05):强制 drift 检测 —— 不能再让 caller 选择跳过。
        self.check_upstream_command_drift(server_id, argv)?;
        let mut g = self.upstreams.lock().map_err(|_| HubError::LockPoisoned)?;
        if g.contains_key(server_id) {
            return Err(HubError::Namespace(
                crate::namespace::NamespaceError::Duplicate(server_id.to_string()),
            ));
        }
        g.insert(server_id.to_string(), upstream);
        Ok(())
    }

    /// V1.1:检查上游裸命令**解析后绝对路径**是否漂移(在 spawn **之前**调用)。
    /// - 首见 → 建立本机基线 pin + 写 `server.program_pinned` 审计(bare→resolved 映射)
    /// - 漂移 → 写 `server.resolved_program_drifted` 审计 + 返 `Err(ResolvedProgramDrift)`(fail-closed)
    ///
    /// `bare_program` = `argv[0]`(供审计映射);`resolved` = 宿主 PATH 解析后的本机绝对路径。
    fn check_upstream_resolved_program_drift(
        &self,
        server_id: &str,
        bare_program: &str,
        resolved: &str,
    ) -> Result<(), HubError> {
        match self
            .ledger
            .check_server_resolved_program_drift(server_id, resolved)?
        {
            ResolvedProgramOutcome::Unchanged => Ok(()),
            ResolvedProgramOutcome::Pinned { resolved } => {
                let _ = self.ledger.append_event(
                    &self.current_session_id()?,
                    "server.program_pinned",
                    &json!({
                        "server_id": server_id,
                        "bare": bare_program,
                        "resolved": resolved,
                    }),
                    Some(&format!("program_pinned server:{server_id}")),
                );
                Ok(())
            }
            ResolvedProgramOutcome::Drifted(d) => {
                let _ = self.ledger.append_event(
                    &self.current_session_id()?,
                    "server.resolved_program_drifted",
                    &json!({
                        "server_id": server_id,
                        "old_resolved": d.old,
                        "new_resolved": d.new,
                    }),
                    Some(&format!("resolved_program_drift server:{server_id}")),
                );
                Err(HubError::ResolvedProgramDrift {
                    server_id: server_id.to_string(),
                    old: d.old,
                    new: d.new,
                })
            }
        }
    }

    /// V1.1(ADR 0007 §I-7.1 / ADR 0005,Codex R2 ACCEPT):Hub-owned stdio upstream 启动 ——
    /// **唯一**带 gate 的 stdio spawn 路径。顺序(Codex R2 实施铁律):
    /// `resolve → argv-drift 检查 → resolved-program-drift 检查 → **才** spawn → attach`。
    /// 进程在**双 gate 通过之前绝不 spawn**;`StdioUpstream::spawn_resolved` 已 `pub(crate)` 化,
    /// 外部 caller 无 public 裸 argv 旁路。caller(`serve.rs` / I08 UI)用本方法替代旧的
    /// `StdioUpstream::spawn` + `attach_upstream` 两步。
    pub fn spawn_attach_stdio_upstream(
        &self,
        server_id: &str,
        argv: &[String],
        env: &[(String, String)],
    ) -> Result<(), HubError> {
        namespace::validate_server_id(server_id).map_err(HubError::Namespace)?;
        if argv.is_empty() {
            return Err(HubError::Invalid("argv is empty".to_string()));
        }
        // 0. 序列化所有 stdio attach(Codex code R2):全程持有 attach_lock,让"dup 检查 → spawn →
        //    insert"对并发 attach 串行 —— 杜绝两并发同名调用都过 dup 检查后各 spawn 一个进程再 drop
        //    的副作用泄漏。本锁不阻塞请求热路径(请求只锁 upstreams map)。
        let _attach_guard = self
            .attach_lock
            .lock()
            .map_err(|_| HubError::LockPoisoned)?;
        // 1. dup 检查(在 attach_lock 串行下,这里读 upstreams 即可定论):重复 server_id 必须在
        //    **任何 resolve / gate / spawn 副作用之前**拒绝。短路返回,不触碰 drift 状态机、不 spawn。
        {
            let g = self.upstreams.lock().map_err(|_| HubError::LockPoisoned)?;
            if g.contains_key(server_id) {
                return Err(HubError::Namespace(
                    crate::namespace::NamespaceError::Duplicate(server_id.to_string()),
                ));
            }
        }
        // 2. resolve(spawn 之前):用宿主 PATH 把裸 argv[0] 解析为本机绝对路径
        let resolved = resolve_program(&argv[0]).map_err(HubError::StdioSpawn)?;
        let resolved_str = resolved.to_string_lossy().to_string();
        // 3. argv drift gate(spawn 之前;既有 ADR 0005 §D5 闭环复用)
        self.check_upstream_command_drift(server_id, argv)?;
        // 4. resolved-program drift gate(spawn 之前;首见建基线 / 漂移 fail-closed)
        self.check_upstream_resolved_program_drift(server_id, &argv[0], &resolved_str)?;
        // 5. 双 gate 通过 → 才用已解析路径 spawn(子进程 env 仍 env_clear,§I-7.1 保留)
        let upstream = StdioUpstream::spawn_resolved(server_id, resolved, &argv[1..], env)
            .map_err(HubError::StdioSpawn)?;
        // 6. attach:attach_lock 串行下 step 1 的 dup 判定仍成立(无并发同名插入),直接 insert。
        //    再查一次 contains_key 仅为防御 attach_upstream(mock/HTTP,不走本锁)的极端交叉。
        let mut g = self.upstreams.lock().map_err(|_| HubError::LockPoisoned)?;
        if g.contains_key(server_id) {
            return Err(HubError::Namespace(
                crate::namespace::NamespaceError::Duplicate(server_id.to_string()),
            ));
        }
        g.insert(server_id.to_string(), Arc::new(upstream));
        Ok(())
    }

    /// 处理一条来自 agent client 的 JSON-RPC message。
    ///
    /// 返回:
    /// - `Ok(Some(response))` 常规 request
    /// - `Ok(None)` 收到 notification,无需响应
    /// - `Err` 本身是 Hub 内部错误(IO 之外的);caller 可决定是否把它包成 JSON-RPC error
    pub fn handle_request(&self, req: JsonRpcRequest) -> Result<Option<JsonRpcResponse>, HubError> {
        if req.jsonrpc != "2.0" {
            if req.is_notification() {
                return Ok(None);
            }
            return Ok(Some(req.error(
                JsonRpcError::INVALID_REQUEST,
                "expected jsonrpc=2.0",
                None,
            )));
        }
        match req.method.as_str() {
            "initialize" => self.handle_initialize(req),
            "initialized" | "notifications/initialized" => Ok(None),
            "shutdown" => Ok(Some(req.success(Value::Null))),
            "ping" => Ok(Some(req.success(json!({})))),
            "notifications/cancelled" => Ok(None),
            "tools/list" => self.handle_tools_list(req),
            "tools/call" => self.handle_tools_call(req),
            _ => Ok(Some(req.error(
                JsonRpcError::METHOD_NOT_FOUND,
                format!("method not supported: {}", req.method),
                None,
            ))),
        }
    }

    fn handle_initialize(&self, req: JsonRpcRequest) -> Result<Option<JsonRpcResponse>, HubError> {
        // 创建一个本轮 session(本进程到 shutdown 前共享)
        let sid = self.ledger.start_session("mcp_hub", Some("vigil-hub"))?;
        {
            let mut g = self.session_id.lock().map_err(|_| HubError::LockPoisoned)?;
            *g = Some(sid);
        }
        Ok(Some(req.success(json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {
                "tools": { "listChanged": false }
            },
            "serverInfo": {
                "name": "vigil-hub",
                "version": env!("CARGO_PKG_VERSION"),
            }
        }))))
    }

    fn handle_tools_list(&self, req: JsonRpcRequest) -> Result<Option<JsonRpcResponse>, HubError> {
        let approved = self.ledger.list_approved_servers()?;
        // NICE-TO-HAVE(Codex):先克隆已连接 upstream 的 Arc,然后**立刻释放锁**,
        // 避免持锁做 IO 引发的 contention / 潜在死锁。
        let upstreams: HashMap<String, Arc<dyn McpUpstream>> = {
            let g = self.upstreams.lock().map_err(|_| HubError::LockPoisoned)?;
            g.clone()
        };
        let mut public_tools: Vec<Value> = Vec::new();
        let mut router = ToolRouter::default();
        // 对每个已批准且已连接的 server 拉 tools/list
        for server in approved {
            let Some(up) = upstreams.get(&server.server_id).cloned() else {
                continue; // 尚未 attach_upstream,跳过
            };
            let result = match up.call("tools/list", None, self.config.upstream_list_timeout) {
                Ok(v) => v,
                Err(_) => continue, // 不可达的上游不影响其它;I10 做重试
            };
            let Some(tools) = result.get("tools").and_then(Value::as_array) else {
                continue;
            };
            let mut hashes: Vec<String> = Vec::new();
            for t in tools {
                let Some(tool_name) = t.get("name").and_then(Value::as_str) else {
                    continue;
                };
                let schema = t.get("inputSchema").cloned().unwrap_or(Value::Null);
                let description = t.get("description").and_then(Value::as_str);
                let annotations = t.get("annotations").cloned().unwrap_or(Value::Null);
                let hash = crate::descriptor::descriptor_hash(
                    &server.server_id,
                    tool_name,
                    &schema,
                    description,
                    &annotations,
                )?;

                // B2(Codex I04 review):per-tool pinning gate。
                // pin_tool_descriptor 三种语义(AGENTS §5 对齐):
                //   Ok(true)  首次见,approved_at=NULL(默认不信任,等待显式批准)
                //   Ok(false) 已有同 hash,幂等
                //   Err(RegistryConflict) hash 漂移 —— I04 范围不做 drift re-approval,
                //                          fail-closed 从 tools/list 排除
                // I05(ADR 0005 §D1):pin_tool_descriptor 不再抛 Conflict,而是
                // 返 `PinOutcome::{FirstSeen, Unchanged, Drifted}`。由 Hub 侧决定
                // 如何处理并写审计。
                use vigil_audit::PinOutcome;
                let outcome =
                    self.ledger
                        .pin_tool_descriptor(&server.server_id, tool_name, &hash)?;
                match outcome {
                    PinOutcome::FirstSeen => {
                        if self.config.auto_approve_first_seen_tools {
                            self.ledger
                                .approve_tool_descriptor(&server.server_id, tool_name)?;
                        }
                    }
                    PinOutcome::Unchanged => {}
                    PinOutcome::Drifted { old, new } => {
                        // 写审计让 replay 可见,但不暴露到 agent(fail-closed)
                        let _ = self.ledger.append_event(
                            &self.current_session_id()?,
                            "tool_descriptor.drifted",
                            &json!({
                                "server_id": server.server_id,
                                "tool_name": tool_name,
                                "old_hash": old,
                                "new_hash": new,
                            }),
                            Some(&format!(
                                "descriptor_drift server:{} tool:{tool_name}",
                                server.server_id
                            )),
                        );
                        continue;
                    }
                    // non_exhaustive fail-closed:未来新增 variant 默认不暴露
                    _ => continue,
                }
                // AGENTS §5 gate:只暴露 approved_at IS NOT NULL 的 tool
                if self
                    .ledger
                    .get_pinned_tool_hash(&server.server_id, tool_name)?
                    .is_none()
                {
                    continue;
                }
                hashes.push(hash.clone());

                let public = router.register(&server.server_id, tool_name, &hash)?;

                // 对外暴露时把 name 替换为 namespaced 名
                let mut exposed = t.clone();
                if let Some(obj) = exposed.as_object_mut() {
                    obj.insert("name".into(), Value::String(public));
                }
                public_tools.push(exposed);
            }
            // 聚合 server 的 descriptor_hash:对所有工具 hash 再过一层 SHA-256
            let mut agg = Sha256::new();
            for h in &hashes {
                agg.update(h.as_bytes());
            }
            let server_descriptor_hash = hex::encode(agg.finalize());
            let _ = self
                .ledger
                .set_descriptor_hash(&server.server_id, &server_descriptor_hash);
        }
        // 更新路由表(整体替换,保证与本次 list 结果一致)
        {
            let mut r = self.router.lock().map_err(|_| HubError::LockPoisoned)?;
            *r = router;
        }
        Ok(Some(req.success(json!({ "tools": public_tools }))))
    }

    fn handle_tools_call(&self, req: JsonRpcRequest) -> Result<Option<JsonRpcResponse>, HubError> {
        let Some(params) = req.params.as_ref() else {
            return Ok(Some(req.error(
                JsonRpcError::INVALID_PARAMS,
                "missing params",
                None,
            )));
        };
        let Some(public_name) = params.get("name").and_then(Value::as_str) else {
            return Ok(Some(req.error(
                JsonRpcError::INVALID_PARAMS,
                "missing `name`",
                None,
            )));
        };
        let args = params.get("arguments").cloned().unwrap_or(Value::Null);

        // 路由
        let route = {
            let r = self.router.lock().map_err(|_| HubError::LockPoisoned)?;
            r.resolve(public_name).cloned()
        };
        let Some(route) = route else {
            return Ok(Some(req.error(
                JsonRpcError::VIGIL_UPSTREAM_UNAVAILABLE,
                format!("unknown tool: {public_name}"),
                None,
            )));
        };

        // 构造 ToolInvocation
        let session_id = {
            let g = self.session_id.lock().map_err(|_| HubError::LockPoisoned)?;
            g.clone().unwrap_or_else(|| "no-session".to_string())
        };
        let invocation_id = Uuid::new_v4().to_string();
        // B1(Codex I04 review):用 tools/list 时算出的 **per-tool** descriptor_hash
        // (存在 route 里),让 oracle 能与 server_profiles 的聚合 hash 正确比对。
        let invocation = ToolInvocation {
            invocation_id: invocation_id.clone(),
            session_id: session_id.clone(),
            server_id: route.server_id.clone(),
            tool_name: route.upstream_tool_name.clone(),
            args: args.clone(),
            descriptor_hash: route.descriptor_hash.clone(),
            requested_at: 0,
        };

        // B4(Codex I04 review)+ ISS-015 细化:args hard-secret 扫描,区分
        // `secret://alias` 引用(合法,待 SecretBroker 解析)与真 key 直传(fail-closed
        // Deny,**不**透传给上游,AGENTS §3)。firewall 层也会查,但 scope 快路径不走
        // firewall,必须在此守一道。
        match scan_args_for_raw_secrets(&invocation.args) {
            AliasAwareScanResult::Clean | AliasAwareScanResult::AllAliased => {
                // 通过:要么全无命中,要么所有硬指纹命中都落在 `secret://` alias 段里
            }
            AliasAwareScanResult::RawSecret { rule } => {
                let dec = DecisionRecord {
                    decision_id: Uuid::new_v4().to_string(),
                    invocation_id: invocation_id.clone(),
                    decision: DecisionKind::Deny,
                    risk_score: 100,
                    reasons: vec![format!(
                        "raw secret detected in args (rule={rule}); use secret:// alias"
                    )],
                    policy_ids: vec!["hub-hard-secret-gate".into()],
                    created_at: 0,
                };
                let _ = self
                    .ledger
                    .record_decision(&session_id, &dec, &EffectVector::default());

                // ISS-015 审计:`raw_secret_attempt_detected`。payload 只带 rule 名 +
                // 关联 id(decision/invocation/server/tool),**不带**原文(record_decision
                // 已规避原文存储;此处 append_event 走 redact() 再过一道)。
                let event_payload = json!({
                    "rule": rule,
                    "decision_id": dec.decision_id,
                    "invocation_id": invocation_id,
                    "server_id": route.server_id,
                    "tool_name": route.upstream_tool_name,
                });
                let (redacted_payload, redacted_summary) = vigil_redaction::redact(&event_payload);
                let _ = self.ledger.append_event(
                    &session_id,
                    EVENT_RAW_SECRET_ATTEMPT_DETECTED,
                    &redacted_payload,
                    Some(&redacted_summary),
                );

                return Ok(Some(req.error(
                    JsonRpcError::VIGIL_DENIED,
                    "raw secret detected in tool arguments; use secret:// alias",
                    Some(json!({"rule": rule, "decision_id": dec.decision_id})),
                )));
            }
        }

        // (F1) 查 ThisSession scope 缓存
        let args_hash = jcs_sha256(&args)?;
        if let Some(res) = self.ledger.find_session_scope_allow(
            &session_id,
            &route.server_id,
            &route.upstream_tool_name,
            &args_hash,
        )? {
            // B3(Codex I04 review):scope 快路径也必须产真实 DecisionRecord,
            // 不能只靠一条 generic 事件替代(AGENTS §1)。
            let dec = DecisionRecord {
                decision_id: Uuid::new_v4().to_string(),
                invocation_id: invocation_id.clone(),
                decision: DecisionKind::Allow,
                risk_score: 0,
                reasons: vec![format!(
                    "pre-approved by session scope (approval_id={})",
                    res.approval_id
                )],
                policy_ids: vec!["session-scope-allow".into()],
                created_at: 0,
            };
            self.ledger
                .record_decision(&session_id, &dec, &EffectVector::default())?;
            return self.invoke_upstream(req, &invocation, &route, None, dec);
        }

        // Firewall 评估
        // I10c-β2:当前 MCP Hub 路径是 stdio MCP(无 OAuth);未来 HTTP MCP 集成点
        // 会在此处根据 route.kind 区分,并从 `ResolvedAccessToken.scope_set` 构造
        // `OAuthScopeContext::Scopes`,让 `Condition::ScopeNotInAllowList` 生效。
        let outcome = self.firewall.evaluate(
            &invocation,
            self.oracle.as_ref(),
            OAuthScopeContext::NonOauth,
        )?;
        match outcome {
            FirewallOutcome::Allowed { decision, .. } => {
                self.invoke_upstream(req, &invocation, &route, None, decision)
            }
            FirewallOutcome::Denied { decision, .. } => Ok(Some(req.error(
                JsonRpcError::VIGIL_DENIED,
                "denied by firewall",
                Some(json!({
                    "decision_id": decision.decision_id,
                    "reasons": decision.reasons,
                    "policy_ids": decision.policy_ids,
                    "risk_score": decision.risk_score,
                })),
            ))),
            FirewallOutcome::Approve {
                decision,
                effects,
                approval,
            } => {
                // 若效应含 CommSend / NetOutbound 且开启 outbox:先 draft,绑定本 approval
                let outbox_id = if self.config.outbox_enabled
                    && (effects.effects.contains(&EffectKind::CommSend)
                        || effects.effects.contains(&EffectKind::NetOutbound))
                {
                    let preview = json!({
                        "tool": route.upstream_tool_name,
                        "server": route.server_id,
                        "hosts": effects.network_hosts,
                        "recipients_count": effects.recipients.len(),
                    });
                    let oi = self.ledger.draft_outbox(
                        &invocation_id,
                        &session_id,
                        vigil_audit::OutboxKind::HttpPost,
                        &preview,
                    )?;
                    self.ledger
                        .submit_outbox_for_approval(&oi.outbox_id, &approval.approval_id)?;
                    Some(oi.outbox_id)
                } else {
                    None
                };

                // 阻塞等待审批
                let resolution = self
                    .ledger
                    .wait_for_resolution(&approval.approval_id, self.config.approval_wait)?;
                let Some(res) = resolution else {
                    if let Some(oid) = &outbox_id {
                        let _ = self.ledger.mark_outbox_expired(oid);
                    }
                    return Ok(Some(req.error(
                        JsonRpcError::VIGIL_APPROVAL_REJECTED,
                        "approval timed out",
                        None,
                    )));
                };
                match res.status {
                    ApprovalStatus::Approved => {
                        if let Some(oid) = &outbox_id {
                            self.ledger.mark_outbox_approved(oid)?;
                        }
                        // 若 scope==ThisSession,下次命中 F1 走快路径即可。
                        // 使用 firewall 产出的真实 decision,不伪造(B3 修复)。
                        self.invoke_upstream(req, &invocation, &route, outbox_id, decision)
                    }
                    ApprovalStatus::Denied => {
                        if let Some(oid) = &outbox_id {
                            let _ = self.ledger.mark_outbox_denied(oid);
                        }
                        Ok(Some(req.error(
                            JsonRpcError::VIGIL_APPROVAL_REJECTED,
                            "approval denied",
                            Some(json!({"decision_id": decision.decision_id})),
                        )))
                    }
                    ApprovalStatus::Expired => {
                        if let Some(oid) = &outbox_id {
                            let _ = self.ledger.mark_outbox_expired(oid);
                        }
                        Ok(Some(req.error(
                            JsonRpcError::VIGIL_APPROVAL_REJECTED,
                            "approval expired",
                            None,
                        )))
                    }
                    ApprovalStatus::Cancelled | ApprovalStatus::Pending => {
                        if let Some(oid) = &outbox_id {
                            let _ = self.ledger.cancel_outbox(oid);
                        }
                        Ok(Some(req.error(
                            JsonRpcError::VIGIL_APPROVAL_REJECTED,
                            "approval cancelled or not resolved",
                            None,
                        )))
                    }
                    // non_exhaustive fail-closed
                    _ => Ok(Some(req.error(
                        JsonRpcError::VIGIL_APPROVAL_REJECTED,
                        "approval in unknown state",
                        None,
                    ))),
                }
            }
            // FirewallOutcome non_exhaustive fail-closed
            _ => Ok(Some(req.error(
                JsonRpcError::INTERNAL,
                "firewall returned unknown outcome",
                None,
            ))),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn invoke_upstream(
        &self,
        req: JsonRpcRequest,
        invocation: &ToolInvocation,
        route: &crate::namespace::ToolRoute,
        outbox_id: Option<String>,
        // B3(Codex I04 review):由 caller 提供真实 DecisionRecord,不再合成占位。
        decision: DecisionRecord,
    ) -> Result<Option<JsonRpcResponse>, HubError> {
        let upstream = {
            let g = self.upstreams.lock().map_err(|_| HubError::LockPoisoned)?;
            g.get(&route.server_id).cloned()
        };
        let Some(up) = upstream else {
            return Ok(Some(req.error(
                JsonRpcError::VIGIL_UPSTREAM_UNAVAILABLE,
                "upstream not attached",
                None,
            )));
        };

        // ToolCallSpan 三段式(opened → decided → executed/execute_failed)
        let span = self
            .ledger
            .tool_call_span(&invocation.invocation_id, &invocation.session_id)?;
        let span = span.decision_recorded(&decision)?;

        let up_args = json!({
            "name": route.upstream_tool_name,
            "arguments": invocation.args,
        });
        let upstream_result = up.call(
            "tools/call",
            Some(up_args),
            self.config.upstream_call_timeout,
        );

        match upstream_result {
            Ok(result) => {
                // ISS-016:post-exec leak scan —— 扫 upstream response 是否回吐 secret。
                // **out-of-band** 设计:命中时**不改** result(保持 MCP 协议透明),仅写审
                // 计事件 + 累加 `leak_detected_count`。真租约收敛延至 SecretBroker 集成。
                if let Ok(result_text) = serde_jcs::to_string(&result) {
                    if let Some(rule) = vigil_redaction::detect_hard_secret(&result_text) {
                        self.leak_detected_count.fetch_add(1, Ordering::Relaxed);
                        let event_payload = json!({
                            "rule": rule,
                            "invocation_id": invocation.invocation_id,
                            "server_id": invocation.server_id,
                            "tool_name": invocation.tool_name,
                            "decision_id": decision.decision_id,
                        });
                        let (redacted_payload, redacted_summary) =
                            vigil_redaction::redact(&event_payload);
                        let _ = self.ledger.append_event(
                            &invocation.session_id,
                            EVENT_SECRET_LEAK_DETECTED,
                            &redacted_payload,
                            Some(&redacted_summary),
                        );
                    }
                }

                span.executed(&format!(
                    "tool {} returned {} bytes",
                    route.upstream_tool_name,
                    result.to_string().len()
                ))?;
                if let Some(oid) = outbox_id {
                    self.ledger.mark_outbox_executed(&oid)?;
                }
                Ok(Some(req.success(result)))
            }
            Err(e) => {
                let reason = e.to_string();
                span.execute_failed(&reason)?;
                if let Some(oid) = outbox_id {
                    let _ = self.ledger.mark_outbox_failed(&oid);
                }
                Ok(Some(req.error(
                    JsonRpcError::VIGIL_UPSTREAM_UNAVAILABLE,
                    format!("upstream failed: {reason}"),
                    None,
                )))
            }
        }
    }
}

/// `args_hash` 计算,与 approvals.args_hash / F1 ThisSession scope 查询对齐。
fn jcs_sha256(v: &Value) -> Result<String, serde_json::Error> {
    let bytes = serde_jcs::to_vec(v)?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(hex::encode(h.finalize()))
}

/// ISS-015 alias-aware 扫描结果。
///
/// 三态分类 args 里的硬指纹命中情况,让 Hub 入口能**区分**"原 key 直传"
/// (必须 Deny)与"`secret://alias` 引用"(合法,SecretBroker 稍后解析)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AliasAwareScanResult {
    /// args 里**没有**任何硬指纹命中(包括 alias 内)。
    Clean,
    /// args 里所有硬指纹命中**都**落在 `secret://...` alias token 内部(合法)。
    AllAliased,
    /// args 里**存在**至少一处硬指纹命中**不**在 alias token 内(真 key 直传)。
    RawSecret {
        /// 首个命中的硬指纹规则名(与 `vigil_redaction::detect_hard_secret` 返值一致)。
        rule: &'static str,
    },
}

/// ISS-015:递归扫 `args` 里每个字符串字段,alias-aware 判定是否存在**非** alias
/// 段的硬指纹命中。
///
/// **Alias token 切法**(R2 BLOCKER 2 修复 —— 改用 alias body 字符**白名单**,与
/// `vigil-firewall::extract::SECRET_REF_RE` 的 `[A-Za-z0-9._\-/]+` 契约对齐):
/// - 起点固定 `secret://`(**严格** ASCII 小写 + 双斜杠;`Secret://` / `secret:/` 不算)
/// - Body:连续**白名单**字符 `[A-Za-z0-9/_.\-]`(见 `is_alias_body_char`);任何
///   非白名单字符(`|` / `<` / `>` / `\` / 空白 / 引号 / JSON 分隔符 / 非 ASCII)
///   都立即终止 alias token —— **fail-safe**:未来可能出现的分隔符默认切断 alias
/// - 切出的整段(含 `secret://` 本身)在参与扫描前替换为 `\x00` 占位字节,防止
///   粘连导致误报(`"secret://aa"ghp_...realtoken` 之类)
///
/// **反绕过**:
/// - `"secret://sk-ant-foo"`(alias 名恰巧形如 anthropic key)→ 合法 alias,
///   因为 SecretBroker 解析时只能拿 alias key 查 store,agent 走私不了原文
/// - `"secret:/ghp_xxx"`(单斜杠)→ **不**算 alias 前缀,原串保留,硬指纹命中 →
///   `RawSecret`
/// - `"secret://"`(空 alias,末尾无 token)→ 切出的 alias 段就是 `secret://` 本身;
///   紧跟的真 key 会保留,仍然命中(测试 `scan_args_adversarial_secret_prefix_without_path`)
///
/// **不变量**:纯函数,不改动 args,无 IO,无分配 args 副本(只对每个字符串 allocate
/// 一个 stripped 副本)。
pub(crate) fn scan_args_for_raw_secrets(args: &Value) -> AliasAwareScanResult {
    let mut saw_aliased_hit = false;

    fn walk(v: &Value, saw_aliased_hit: &mut bool) -> Option<&'static str> {
        match v {
            Value::String(s) => scan_string(s, saw_aliased_hit),
            Value::Array(arr) => {
                for item in arr {
                    if let Some(rule) = walk(item, saw_aliased_hit) {
                        return Some(rule);
                    }
                }
                None
            }
            Value::Object(obj) => {
                for (k, val) in obj {
                    // R2 BLOCKER 1 修复:object **key 也必须扫**(否则 `{"ghp_..."_real: "x"}`
                    // 可绕过 B4 直传原 key)。key 不可能承载 `secret://alias` 语义(alias
                    // 只在 value 里有意义;即使 key 含 `secret://xxx`,也视作可疑输入),
                    // 所以 key 上的命中直接判 RawSecret,不走 alias 豁免路径。
                    if let Some(rule) = vigil_redaction::detect_hard_secret(k) {
                        return Some(rule);
                    }
                    if let Some(rule) = walk(val, saw_aliased_hit) {
                        return Some(rule);
                    }
                }
                None
            }
            // 数字/布尔/null:不可能承载字符串指纹
            _ => None,
        }
    }

    fn scan_string(s: &str, saw_aliased_hit: &mut bool) -> Option<&'static str> {
        let stripped = strip_aliases(s);
        // 在剥掉 alias 段后的文本上扫硬指纹
        if let Some(rule) = vigil_redaction::detect_hard_secret(&stripped) {
            return Some(rule);
        }
        // 若 stripped 后无命中,但原串命中 → 说明命中都落在 alias 段内(合法)
        if vigil_redaction::detect_hard_secret(s).is_some() {
            *saw_aliased_hit = true;
        }
        None
    }

    if let Some(rule) = walk(args, &mut saw_aliased_hit) {
        return AliasAwareScanResult::RawSecret { rule };
    }
    if saw_aliased_hit {
        AliasAwareScanResult::AllAliased
    } else {
        AliasAwareScanResult::Clean
    }
}

/// ISS-015 辅助:对单个字符串剥除所有 `secret://<token>` alias 段,返回替换为 `\x00`
/// 占位的副本。占位字节保证不粘连左右邻居字符(硬指纹规则都用 `\b` 词边界,NUL 会
/// 断开词边界)。
///
/// **R2 BLOCKER 2 修复**:alias token body 用**白名单字符集** `[A-Za-z0-9/_.\-]`,
/// 任何非白名单字符(包括 `|` / `<` / `>` / `\` / 空白 / 引号 / JSON 分隔符等)
/// 都立即终止 alias。这防止 `secret://ok|ghp_real_token` 这种"alias 后跟冷门分隔符 +
/// 真 key"被当作**整段** alias 剥掉。
///
/// 白名单选定依据:URL path-safe 字符(RFC 3986 `unreserved` + `/`),足以承载
/// 典型 alias 名(`secret://gh/rw` / `secret://stripe.live_key` / `secret://my-api_v2`)。
fn strip_aliases(s: &str) -> String {
    const ALIAS_PREFIX: &str = "secret://";
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        // 查找下一个 `secret://` 起点(ASCII 精确匹配,不做大小写折叠)
        if i + ALIAS_PREFIX.len() <= bytes.len()
            && &bytes[i..i + ALIAS_PREFIX.len()] == ALIAS_PREFIX.as_bytes()
        {
            // R2 BLOCKER 2 修复:alias body 字符白名单(而非终止符黑名单)。
            // 连续白名单字符构成 alias token;首个非白名单字符即终止。
            let mut j = i + ALIAS_PREFIX.len();
            while j < bytes.len() && is_alias_body_char(bytes[j]) {
                j += 1;
            }
            // 整段 alias token([i, j)) 替换为单个 NUL(长度无关,不影响硬指纹扫描)
            out.push('\x00');
            i = j;
        } else {
            // 非 alias 起点:逐字符拷过去(注意 UTF-8 边界)
            // 这里按字节安全推进:取当前字符长度
            let ch_start = i;
            // 找到下个字符起点(UTF-8 续字节 0b10xxxxxx)
            i += 1;
            while i < bytes.len() && (bytes[i] & 0b1100_0000) == 0b1000_0000 {
                i += 1;
            }
            // SAFETY:i/ch_start 都对齐 UTF-8 字符边界
            out.push_str(&s[ch_start..i]);
        }
    }
    out
}

/// R2 BLOCKER 2 修复:alias token body 合法字符白名单 `[A-Za-z0-9/_.\-]`。
///
/// 任何非白名单字符(包括非 ASCII / `|` / `<` / `>` / `\` / 空白 / 引号 / JSON 分隔符)
/// 都终止 alias token。保守而明确 —— 给"未来可能出现的分隔符"留默认 fail-safe
/// (非白名单即终止),不再依赖"补齐所有可能分隔符"。
#[inline]
fn is_alias_body_char(b: u8) -> bool {
    matches!(b,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'_' | b'.' | b'-'
    )
}

/// 计算 stdio server argv 的规范化 hash(JCS 后 SHA-256 hex-lower)。
/// 必须与 `register_server` 调用者算出并存入 `command_hash` 的算法保持完全一致。
///
/// **v0.3 Stage 2**(2026-04-24):改为 `pub` 以供 `vigil-hub-cli::serve` 实装
/// `--upstream-config` 时填 `ServerProfile::command_hash` 使用。caller 必须用本函数
/// 算 hash,否则 `attach_upstream` 内的 drift 检查会误判漂移。
pub fn compute_argv_hash(argv: &[String]) -> Result<String, serde_json::Error> {
    let v = serde_json::to_value(argv)?;
    jcs_sha256(&v)
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn unknown_method_returns_not_found() {
        // Hub 构造需要 ledger+firewall+oracle;这里只做基本语义测试
        // (缝合测试在 integration tests 里)
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(Value::Number(1.into())),
            method: "does/not/exist".into(),
            params: None,
        };
        assert!(!req.is_notification());
    }

    // ------------------------------------------------------------------
    // ISS-015 `scan_args_for_raw_secrets` 单测(≥ 6 条守门:alias 豁免 vs 真 key 直传)
    // ------------------------------------------------------------------

    #[test]
    fn scan_args_clean_no_secret() {
        // 完全干净的 args:无任何硬指纹
        let args = json!({"path": "/proj/readme.md", "mode": "utf8"});
        assert_eq!(
            scan_args_for_raw_secrets(&args),
            AliasAwareScanResult::Clean
        );
    }

    #[test]
    fn scan_args_all_aliased() {
        // alias 引用不是原 key,合法
        let args = json!({"token": "secret://gh/pat", "repo": "foo/bar"});
        assert_eq!(
            scan_args_for_raw_secrets(&args),
            AliasAwareScanResult::Clean,
            "alias 名本身不形似硬指纹 → Clean(连 AllAliased 都不算)"
        );
    }

    #[test]
    fn scan_args_raw_github_token() {
        // 真 ghp_ 直传必须 RawSecret
        let args = json!({"token": "ghp_1234567890abcdef1234567890abcdef12345678"});
        match scan_args_for_raw_secrets(&args) {
            AliasAwareScanResult::RawSecret { rule } => assert_eq!(rule, "github_token"),
            other => panic!("期望 RawSecret(github_token),得到 {other:?}"),
        }
    }

    #[test]
    fn scan_args_alias_token_with_secret_lookalike() {
        // alias 内恰巧形似 anthropic key → 豁免,判 AllAliased
        // 注意:sk-ant- 必须满足 `\b` 前边界,alias 前缀 `secret://` 末字符 `/` 是非 word
        // 字符,`\b` 成立。
        let args = json!({
            "token": "secret://sk-ant-api03-abcdefghijklmnopqrstuvwxyz"
        });
        assert_eq!(
            scan_args_for_raw_secrets(&args),
            AliasAwareScanResult::AllAliased,
            "alias 内的硬指纹形态必须豁免"
        );
    }

    #[test]
    fn scan_args_mixed_alias_and_raw() {
        // 一处 alias(合法)+ 一处真 key(非法)→ 至少一处真 key 即 RawSecret
        let args = json!({
            "a": "secret://ok/aliased",
            "b": "ghp_1234567890abcdef1234567890abcdef12345678"
        });
        match scan_args_for_raw_secrets(&args) {
            AliasAwareScanResult::RawSecret { rule } => assert_eq!(rule, "github_token"),
            other => panic!("期望 RawSecret(github_token),得到 {other:?}"),
        }
    }

    #[test]
    fn scan_args_nested_arrays_objects() {
        // 嵌套 object + array 里的真 key 也必须被递归扫到
        let args = json!({
            "outer": {
                "list": [
                    {"safe": "ok"},
                    {"leaked": "ghp_1234567890abcdef1234567890abcdef12345678"}
                ]
            }
        });
        match scan_args_for_raw_secrets(&args) {
            AliasAwareScanResult::RawSecret { rule } => assert_eq!(rule, "github_token"),
            other => panic!("期望 RawSecret(github_token),得到 {other:?}"),
        }
    }

    #[test]
    fn scan_args_env_assignment_inline() {
        // 自由文本形态 `FOO_API_KEY=...` 命中 env_assignment 规则
        let args = json!({"cmd": "export OPENAI_API_KEY=sk-realsecret1234567890ABCDEFghij"});
        match scan_args_for_raw_secrets(&args) {
            AliasAwareScanResult::RawSecret { rule } => {
                // 命中规则可能是 env_assignment 或 openai_api_key;HARD_RULES 顺序决定首个
                assert!(
                    rule == "env_assignment" || rule == "openai_api_key",
                    "应命中 env_assignment 或 openai_api_key,实际 {rule}"
                );
            }
            other => panic!("期望 RawSecret,得到 {other:?}"),
        }
    }

    #[test]
    fn scan_args_adversarial_secret_prefix_without_path() {
        // 对抗:`secret://` 空 alias + 后跟真 key(中间有空格终止 alias 段)
        // 真 key 不会被 alias 切掉,仍应命中
        let args = json!({
            "cmd": "secret:// ghp_1234567890abcdef1234567890abcdef12345678"
        });
        match scan_args_for_raw_secrets(&args) {
            AliasAwareScanResult::RawSecret { rule } => assert_eq!(rule, "github_token"),
            other => panic!("期望 RawSecret(github_token),得到 {other:?}"),
        }
    }

    #[test]
    fn scan_args_capital_secret_prefix_not_treated_as_alias() {
        // `Secret://` 大写起 → **不**算 alias 前缀,原串保留,应命中
        let args = json!({
            "cmd": "Secret://ghp_1234567890abcdef1234567890abcdef12345678"
        });
        match scan_args_for_raw_secrets(&args) {
            AliasAwareScanResult::RawSecret { rule } => assert_eq!(rule, "github_token"),
            other => panic!("期望 RawSecret(大小写必须严格):得到 {other:?}"),
        }
    }

    #[test]
    fn scan_args_single_slash_secret_not_alias() {
        // `secret:/` 单斜杠 → **不**算 alias 前缀(契约要求双斜杠)
        let args = json!({
            "cmd": "secret:/ghp_1234567890abcdef1234567890abcdef12345678"
        });
        match scan_args_for_raw_secrets(&args) {
            AliasAwareScanResult::RawSecret { rule } => assert_eq!(rule, "github_token"),
            other => panic!("期望 RawSecret(单斜杠不算 alias):得到 {other:?}"),
        }
    }

    // R2 BLOCKER 1 守门 —— object key 承载的真 key 必须被扫到
    #[test]
    fn scan_args_raw_secret_in_object_key_not_value() {
        // R1 回归面:旧 JCS 扫描全量字符串覆盖 key,新递归实装曾漏掉 key 路径
        let args = json!({
            "ghp_1234567890abcdef1234567890abcdef12345678": "harmless_value"
        });
        match scan_args_for_raw_secrets(&args) {
            AliasAwareScanResult::RawSecret { rule } => assert_eq!(rule, "github_token"),
            other => panic!("object key 里的真 key 必须被拦:得到 {other:?}"),
        }
    }

    #[test]
    fn scan_args_raw_secret_in_nested_object_key() {
        // key 深层嵌套也必须扫到
        let args = json!({
            "outer": {
                "sk-ant-api03-abcdefghijklmnopqrstuvwxyz": "nested harmless value"
            }
        });
        match scan_args_for_raw_secrets(&args) {
            AliasAwareScanResult::RawSecret { rule } => assert_eq!(rule, "anthropic_api_key"),
            other => panic!("嵌套 object key 里的真 key 必须被拦:得到 {other:?}"),
        }
    }

    // R2 BLOCKER 2 守门 —— alias char 白名单:冷门分隔符后跟的 raw secret 不被吞
    #[test]
    fn scan_args_alias_followed_by_pipe_delimiter_then_raw_secret() {
        // `secret://ok|ghp_...`:白名单 body 字符止于 `|`,后续真 key 必须被扫
        let args = json!({
            "cmd": "secret://ok|ghp_1234567890abcdef1234567890abcdef12345678"
        });
        match scan_args_for_raw_secrets(&args) {
            AliasAwareScanResult::RawSecret { rule } => assert_eq!(rule, "github_token"),
            other => panic!("`|` 分隔后的 raw secret 必须不被 alias 吞:得到 {other:?}"),
        }
    }

    #[test]
    fn scan_args_alias_followed_by_xml_tag_then_raw_secret() {
        // `secret://ok</x><y>ghp_...</y>`:`<` 非白名单,alias 止于 `ok`
        let args = json!({
            "cmd": "secret://ok</x><y>ghp_1234567890abcdef1234567890abcdef12345678</y>"
        });
        match scan_args_for_raw_secrets(&args) {
            AliasAwareScanResult::RawSecret { rule } => assert_eq!(rule, "github_token"),
            other => panic!("XML tag 分隔后的 raw secret 必须不被 alias 吞:得到 {other:?}"),
        }
    }

    #[test]
    fn scan_args_alias_followed_by_backslash_then_raw_secret() {
        // `secret://ok\\ghp_...`:反斜杠非白名单,alias 止于 `ok`
        let args = json!({
            "cmd": "secret://ok\\ghp_1234567890abcdef1234567890abcdef12345678"
        });
        match scan_args_for_raw_secrets(&args) {
            AliasAwareScanResult::RawSecret { rule } => assert_eq!(rule, "github_token"),
            other => panic!("`\\` 分隔后的 raw secret 必须不被 alias 吞:得到 {other:?}"),
        }
    }

    #[test]
    fn scan_args_alias_body_whitelist_accepts_legitimate_alias_names() {
        // 正向守门:典型 alias 名 `secret://gh/rw` / `secret://stripe.live_key` /
        // `secret://my-api_v2` 都应作为完整 alias 被剥离(不触发 RawSecret)
        for alias_name in [
            "secret://gh/rw",
            "secret://stripe.live_key",
            "secret://my-api_v2",
        ] {
            let args = json!({ "t": alias_name });
            assert!(
                !matches!(
                    scan_args_for_raw_secrets(&args),
                    AliasAwareScanResult::RawSecret { .. }
                ),
                "合法 alias 名 {alias_name} 不应被误判为 RawSecret"
            );
        }
    }

    #[test]
    fn scan_args_alias_in_json_object_value_string() {
        // 完整 JSON 字符串值里嵌 alias(带 `"` 终止符)→ AllAliased 候选。
        // 注意:alias 里用 anthropic-like 形态触发 saw_aliased_hit。
        let args = json!({
            "payload": "{\"token\": \"secret://sk-ant-api03-abcdefghijklmnopqrstuvwxyz\"}"
        });
        assert_eq!(
            scan_args_for_raw_secrets(&args),
            AliasAwareScanResult::AllAliased,
            "alias 在 JSON 引号内 → `\"` 作为终止符切到 alias token 结尾,内部硬指纹豁免"
        );
    }
}
