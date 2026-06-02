//! 高层 firewall facade(SDK-owned)—— 让消费者**只用 `vigil-sdk`** 就能起一个可用 firewall
//! 并跑一次决策,无需自行装配 `Ledger` / `PolicyEngine` / `DescriptorOracle`(均内化为实现细节,
//! 不进 SDK public API,守住 SDK 边界)。
//!
//! 设计见 `docs/operations/sdk-firewall-builder/spike.md`(O-A:internalize,非 re-export internals)。
//!
//! ## 安全默认(fail-closed)
//!
//! builder 内部用 [`vigil_mcp::RegistryDescriptorOracle`] 作 descriptor oracle:全新(in-memory)
//! ledger 上一切工具描述符是 `FirstSeen` → firewall risk scorer 视为**谨慎**(非 blanket-allow)。
//! **绝不**用 `StaticDescriptorOracle(ApprovedStable)`(那会 defeat descriptor pinning)。消费者按需
//! 注册并审批工具描述符后,匹配的 call 才走 `ApprovedStable` 快路径。
//!
//! ## 审计
//!
//! 默认 ledger 是 **in-memory**(零配置;进程内 `decide` 仍写 `DecisionRecord` 入账本,但**不跨进程
//! 持久化**)。需要持久审计的消费者用 [`FirewallBuilder::ledger_path`] 指定文件路径。

use std::path::PathBuf;
use std::sync::Arc;

use vigil_audit::Ledger;
use vigil_firewall::scorer::DescriptorOracle;
use vigil_mcp::RegistryDescriptorOracle;
use vigil_policy::{defaults::default_ruleset, PolicyEngine};
use vigil_types::ToolInvocation;

use crate::{Firewall, FirewallConfig, FirewallError, FirewallOutcome, OAuthScopeContext};

/// 装配一个可用 [`SdkFirewall`] 的 builder。
///
/// 默认:in-memory ledger + Vigil 默认策略规则集 + fail-closed [`RegistryDescriptorOracle`]。
///
/// ```
/// use vigil_sdk::FirewallBuilder;
/// let fw = FirewallBuilder::new().project_roots(["/proj"]).build().unwrap();
/// ```
#[derive(Debug, Clone, Default)]
pub struct FirewallBuilder {
    project_roots: Vec<String>,
    allowed_hosts: Vec<String>,
    ledger_path: Option<PathBuf>,
}

impl FirewallBuilder {
    /// 新建 builder(默认 in-memory ledger,无 project root / allowed host)。
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置 POSIX 规范化的项目根目录前缀(firewall 用于判定 file effect 是否在项目内)。
    pub fn project_roots<I, S>(mut self, roots: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.project_roots = roots.into_iter().map(Into::into).collect();
        self
    }

    /// 设置允许的出站主机列表(firewall 用于网络 effect 评估)。
    pub fn allowed_hosts<I, S>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_hosts = hosts.into_iter().map(Into::into).collect();
        self
    }

    /// 用**文件持久化**的审计账本替代默认 in-memory(跨进程不丢审计)。
    pub fn ledger_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.ledger_path = Some(path.into());
        self
    }

    /// 装配 [`SdkFirewall`]:打开账本 → 默认策略引擎 → firewall + fail-closed oracle(共享同一账本)。
    ///
    /// 失败仅可能在账本打开阶段(in-memory 初始化 / 文件路径不可用),返 [`FirewallBuildError`]。
    pub fn build(self) -> Result<SdkFirewall, FirewallBuildError> {
        let ledger = match self.ledger_path {
            Some(path) => Ledger::open(path),
            None => Ledger::open_in_memory(),
        }
        .map_err(|e| FirewallBuildError::LedgerOpen {
            reason: e.to_string(),
        })?;
        let ledger = Arc::new(ledger);

        let policy = PolicyEngine::new(default_ruleset());
        let config = FirewallConfig {
            project_roots: self.project_roots,
            allowed_hosts: self.allowed_hosts,
            ..Default::default()
        };
        // firewall 与 oracle 共享**同一** Arc<Ledger>:oracle 查的 descriptor 审批状态
        // 与 firewall 写的 DecisionRecord 在同一账本,语义一致。
        let fw = Firewall::new(Arc::clone(&ledger), policy, config);
        let oracle = RegistryDescriptorOracle::new(ledger);

        Ok(SdkFirewall { fw, oracle })
    }
}

/// 一个就绪的 firewall —— SDK-owned thin wrapper,**不**泄露底层 `Firewall` / `evaluate`,
/// 消费者无法绕过内化的 fail-closed 默认 oracle。
#[derive(Debug)]
pub struct SdkFirewall {
    fw: Firewall,
    oracle: RegistryDescriptorOracle,
}

impl SdkFirewall {
    /// 对一次工具调用跑 firewall 决策。
    ///
    /// 内部用 builder 装配的 fail-closed oracle + 非-OAuth scope。返回三态之一
    /// ([`FirewallOutcome::Allowed`] / [`FirewallOutcome::Denied`] / [`FirewallOutcome::Approve`]),
    /// **均已把 `DecisionRecord` 写入账本**(SDK 不变量:effect 触发前必产决策记录)。
    ///
    /// **fail-closed**:返 `Err(FirewallError)` 时,消费者**必须**当作 deny(SDK 不变量 #1),
    /// 不可降级为放行。
    pub fn decide(&self, call: &ToolInvocation) -> Result<FirewallOutcome, FirewallError> {
        self.fw.evaluate(
            call,
            &self.oracle as &dyn DescriptorOracle,
            OAuthScopeContext::NonOauth,
        )
    }

    /// 便捷决策(ergonomic)—— 从 `(server_id, tool_name, args)` 构造一次性 [`ToolInvocation`]
    /// 并 [`decide`](Self::decide)。免去消费者手填 Vigil 内部样板字段。
    ///
    /// 自动填充:`invocation_id`(UUIDv4)、`requested_at`(当前 Unix epoch 秒)、`session_id`
    /// (固定 `"sdk"`)、`descriptor_hash`(每次唯一的非-pinnable 占位,见下)。
    ///
    /// **不做 descriptor pinning,且 fail-closed by construction**:`descriptor_hash` 填一个**每次
    /// 调用唯一**的占位(`sdk-decide-call:<uuid>`)——它**永不可能等于**任何已 pin 的描述符 hash
    /// (后者是 sha256 hex),故 oracle 的 `pinned == call` 相等分支(→ `ApprovedStable`)**构造上不可达**,
    /// 结果恒为 `FirstSeen`(谨慎)。**不依赖**"空 hash 不会被 pin"这种约定(Codex R1:空占位非
    /// fail-closed by construction)。需要让**已审批**工具走 `ApprovedStable` 快路径(descriptor
    /// pinning)的消费者,改用 [`decide`](Self::decide) 传入带真实 `descriptor_hash` 的完整 [`ToolInvocation`]。
    ///
    /// ```
    /// use vigil_sdk::prelude::*;
    /// let fw = FirewallBuilder::new().project_roots(["/proj"]).build().unwrap();
    /// // 一行跑一次决策:项目外写 → Deny
    /// let outcome = fw
    ///     .decide_call("fs", "fs_write_file", serde_json::json!({"path": "/etc/hosts"}))
    ///     .unwrap();
    /// assert_eq!(outcome.decision_kind(), DecisionKind::Deny);
    /// ```
    pub fn decide_call(
        &self,
        server_id: &str,
        tool_name: &str,
        args: serde_json::Value,
    ) -> Result<FirewallOutcome, FirewallError> {
        let requested_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let call = ToolInvocation {
            invocation_id: uuid::Uuid::new_v4().to_string(),
            session_id: "sdk".into(),
            server_id: server_id.into(),
            tool_name: tool_name.into(),
            args,
            // fail-closed by construction:每次唯一、非 sha256 形态 → 永不匹配已 pin 描述符 hash
            // → oracle 恒 FirstSeen(不依赖"空 hash 不会被 pin"的约定;Codex R1 BLOCKER)。
            descriptor_hash: format!("sdk-decide-call:{}", uuid::Uuid::new_v4()),
            requested_at,
        };
        self.decide(&call)
    }
}

/// [`FirewallBuilder::build`] 的错误(SDK-owned,`#[non_exhaustive]` 允许将来加 variant 不破 SemVer)。
#[derive(Debug)]
#[non_exhaustive]
pub enum FirewallBuildError {
    /// 审计账本打开失败(in-memory 初始化或文件路径不可用)。`reason` 为脱敏文本(无原文 / 无 PII)。
    LedgerOpen {
        /// 失败原因(stable 文本)。
        reason: String,
    },
}

impl std::fmt::Display for FirewallBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LedgerOpen { reason } => {
                write!(f, "firewall build: ledger open failed: {reason}")
            }
        }
    }
}

impl std::error::Error for FirewallBuildError {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use vigil_types::DecisionKind;

    fn mk_call(tool: &str, args: serde_json::Value) -> ToolInvocation {
        ToolInvocation {
            invocation_id: "test-invocation-id".into(),
            session_id: "test-session".into(),
            server_id: "test-srv".into(),
            tool_name: tool.into(),
            args,
            descriptor_hash: "test-hash".into(),
            requested_at: 0,
        }
    }

    /// criterion #1:builder 装配成功(in-memory ledger + default ruleset + oracle)。
    #[test]
    fn build_assembles_usable_firewall() {
        let fw = FirewallBuilder::new().project_roots(["/proj"]).build();
        assert!(
            fw.is_ok(),
            "default build should succeed, got {:?}",
            fw.err()
        );
    }

    /// ★ Codex code review BLOCKER 修复 —— **辨别性** fail-closed 证明:
    /// 同一 in-repo 读在 `StaticDescriptorOracle(ApprovedStable)` 下是 **Allow**(vigil-firewall
    /// §3.5-1);但 builder 默认用 fail-closed `RegistryDescriptorOracle`(fresh ledger 上工具描述符
    /// = `FirstSeen`)→ 触发 "首见描述符需审批" → **Approve**(非 Allow)。断言 Approve 即**区分**出
    /// 默认 oracle 确是 fail-closed,而非 blanket-allow(deny-stays-deny 测试两种 oracle 都过,不能区分)。
    #[test]
    fn decide_fresh_repo_read_is_approve_not_blanket_allow() {
        let fw = FirewallBuilder::new()
            .project_roots(["/proj"])
            .build()
            .unwrap();
        let call = mk_call(
            "fs_read_file",
            serde_json::json!({"path": "/proj/src/main.rs"}),
        );
        let outcome = fw.decide(&call).expect("decide should succeed");
        assert_eq!(
            outcome.decision_kind(),
            DecisionKind::Approve,
            "fresh ledger 上 in-repo 读应因 FirstSeen 走 Approve(证明默认 oracle = RegistryDescriptorOracle,非 ApprovedStable blanket-allow)"
        );
    }

    /// criterion #2(fail-closed 实证,robust):危险调用必 Deny —— FirstSeen 只增不减 risk,
    /// 故 ApprovedStable 下就 Deny 的调用在 builder 默认(RegistryDescriptorOracle,fresh=FirstSeen)
    /// 下仍 Deny。证明 facade 真做风险评估而非 rubber-stamp。
    #[test]
    fn decide_denies_write_outside_project() {
        let fw = FirewallBuilder::new()
            .project_roots(["/proj"])
            .build()
            .unwrap();
        let call = mk_call("fs_write_file", serde_json::json!({"path": "/etc/hosts"}));
        let outcome = fw.decide(&call).expect("decide should succeed");
        assert_eq!(
            outcome.decision_kind(),
            DecisionKind::Deny,
            "项目外写必须 Deny(fail-closed)"
        );
    }

    /// criterion #2(续):破坏性 shell 必 Deny。
    #[test]
    fn decide_denies_destructive_shell() {
        let fw = FirewallBuilder::new()
            .project_roots(["/proj"])
            .build()
            .unwrap();
        let call = mk_call(
            "shell_run",
            serde_json::json!({"argv": ["rm", "-rf", "/home/user/Downloads"]}),
        );
        let outcome = fw.decide(&call).expect("decide should succeed");
        assert_eq!(
            outcome.decision_kind(),
            DecisionKind::Deny,
            "rm -rf 必须 Deny"
        );
    }

    /// 默认 in-memory 不依赖文件;ledger_path 可选(文件持久化)路径也能 build。
    #[test]
    fn build_with_ledger_path() {
        let tmp = std::env::temp_dir().join("vigil_sdk_fwbuilder_test.sqlite3");
        let _ = std::fs::remove_file(&tmp);
        let fw = FirewallBuilder::new().ledger_path(&tmp).build();
        assert!(
            fw.is_ok(),
            "file-backed ledger build should succeed, got {:?}",
            fw.err()
        );
        let _ = std::fs::remove_file(&tmp);
    }

    /// decide_call 便捷路径与 decide 语义一致:危险调用同样 Deny。
    #[test]
    fn decide_call_denies_dangerous_call() {
        let fw = FirewallBuilder::new()
            .project_roots(["/proj"])
            .build()
            .unwrap();
        let outcome = fw
            .decide_call(
                "fs",
                "fs_write_file",
                serde_json::json!({"path": "/etc/hosts"}),
            )
            .expect("decide_call should succeed");
        assert_eq!(outcome.decision_kind(), DecisionKind::Deny);
    }

    /// decide_call 同样走 fail-closed 默认 oracle:fresh ledger 上 in-repo 读 → Approve(FirstSeen),
    /// 与 decide() 一致(空 descriptor_hash 不破 fail-closed,因 fresh ledger 本就 FirstSeen)。
    #[test]
    fn decide_call_fresh_repo_read_is_approve() {
        let fw = FirewallBuilder::new()
            .project_roots(["/proj"])
            .build()
            .unwrap();
        let outcome = fw
            .decide_call(
                "fs",
                "fs_read_file",
                serde_json::json!({"path": "/proj/src/main.rs"}),
            )
            .expect("decide_call should succeed");
        assert_eq!(outcome.decision_kind(), DecisionKind::Approve);
    }
}
