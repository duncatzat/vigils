//! `vigil-hub wrap -- <command> [args...]` —— 透明 stdio MCP shim(逐 server 网关)。
//!
//! 把一个**已存在的 MCP server 命令**作唯一 upstream 起,对它套上 Vigil 网关
//! (default-deny firewall + 硬指纹脱敏 + 可逆结果脱敏 + 人审批 + 防篡改审计),写共享账本。
//! agent 像直连原 server 一样连 `vigil-hub wrap`,中间被 Vigil 守护。
//!
//! # 为何是"逐 server wrap"而非"单 aggregator"(多视角并发分析综合,2026-06-05)
//! - **可逆性逐字**:`setup --mcp` 只需把每条 `command` 改写为 `vigil-hub wrap --server-id <名>
//!   --env-key <配置的env键>... -- <原命令>`,卸载去掉前缀即还原。
//! - **故障爆炸半径每 server 隔离**;保留 agent 原生语义(名字/OAuth/`${VAR}`)。
//! - 同类安全 guardrail(`ressl/mcp-firewall wrap --`)已用同款 per-server shim 发货。
//!
//! 复用 [`crate::serve`] 的 `build_hub_with_config` + `attach_stdio_upstream` + `run_stdio_loop`。
//!
//! # env 转发(Codex R1 HIGH:不盲传全量)
//! 默认**不**把 wrap 进程的全部 env 漏给子进程 —— 只 `--env-key <K>` **显式**指定的键(= agent 为该
//! server 配置的 `env{}` 键)被转发(wrap 从自身 env 读值,经 `apply_mcp_upstream_env_policy` 的
//! `user_env` 注入,优先级最高)。`apply_mcp_upstream_env_policy` 另注非密钥白名单(PATH/HOME/APPDATA…)
//! 让 npx/uvx 起得来。`--inherit-env` 是逃生舱(全量透传),仅确知该 server 本就该拿全量继承 env 时用。

use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::serve::{self, ServeArgs, ServeError};

/// `wrap` 子命令参数。
#[derive(Debug, Clone, Default)]
pub struct WrapArgs {
    /// 被包裹的 MCP server 命令(`--` 之后的 argv:`[cmd, args...]`)。
    pub command: Vec<String>,
    /// 审计账本路径;None = 默认共享账本(与 `setup`/`hook`/`inspect` 同一个)。
    pub ledger: Option<PathBuf>,
    /// 该被包裹 server 的稳定身份 id(= agent 配置里的 server 名)。供账本 / descriptor pin /
    /// 审批命名空间区分不同 server(Codex R1 BLOCKER:固定 `wrapped` 会塌缩多 server 身份)。
    /// None = 由命令 argv 的 sha256 派生抗碰撞 id(并 stderr 警告)。
    pub server_id: Option<String>,
    /// **显式**转发给子进程的 env 键(= agent 为该 server 配的 `env{}` 的键)。wrap 从自身 env 读取
    /// 这些键的值传给子进程。默认空 = 只有非密钥白名单(PATH/HOME…)到达子进程(Codex R1 HIGH:
    /// 不再盲传 `env::vars()` 全量,避免把宿主所有 secret 漏给 upstream)。
    pub env_keys: Vec<String>,
    /// 逃生舱:透传 wrap 进程的**全部** env(仅当确知该 server 本就该拿全量继承 env 时用)。
    pub inherit_env: bool,
    /// **Monitor posture**(opt-in,非阻塞):本应人审批的风险调用自动放行 + 完整审计,不阻塞。
    /// turnkey 无 desktop resolver 时推荐开(否则风险工具阻塞 300s 看似卡死)。默认 false = enforce。
    /// 见 [`crate::serve::ServeArgs::monitor`] / [`vigil_mcp::HubConfig::monitor_mode`]。
    pub monitor: bool,
    /// DEF-004:项目边界根(原始 CLI 值,未归一)。空 = 缺省 CWD。
    /// 经 [`crate::serve::resolve_project_roots`] 归一后装进 firewall。
    pub project_roots: Vec<PathBuf>,
}

/// 透明 shim 主入口:起被包裹 server 作唯一 upstream + Vigil 网关,跑 stdio 主循环。
pub fn run(args: &WrapArgs) -> Result<(), ServeError> {
    // `--` 之后的命令;防御性剥离可能残留的前导 `--`。
    let mut command = args.command.clone();
    if command.first().map(|s| s == "--").unwrap_or(false) {
        command.remove(0);
    }
    if command.is_empty() {
        return Err(ServeError::InvalidUpstream {
            name: "wrapped".to_string(),
            reason: "no command after `--` (usage: vigil-hub wrap -- <mcp-server-cmd> [args...])",
        });
    }

    // 账本:默认共享账本 → wrap 的审计与 hook/inspect 汇到一处。
    let ledger_path = args
        .ledger
        .clone()
        .or_else(crate::setup::default_ledger_path);
    // DEF-001 诊断:把解析后的账本绝对路径打进启动 banner —— 桌面 GUI 看不到 CLI 事件
    // 的最常见根因是 writer/reader 路径不一致(如文件名 ledger.sqlite vs ledger.sqlite3),
    // 打印出来便于与桌面读的路径肉眼比对。
    let ledger_display = ledger_path
        .as_deref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "(in-memory)".to_string());
    let serve_args = ServeArgs {
        ledger_path,
        upstreams_config: None, // 不走文件;wrap 自己 attach(为透传 env)
        // turnkey:auto-pin + 暴露**首见** descriptor。否则 `tools/list` 空 → agent 看不到任何工具 =
        // wrap 对 turnkey 无用(E2E 实测发现)。用户已通过在 agent 里配置该 server 表达信任;Vigil 价值在
        // pin descriptor + 检测**后续** schema drift + 脱敏 + 审计 + (enforce) 拦风险**调用**,而非"隐藏
        // 已配置 server 的工具直到再人审"。`auto_approve_first_seen` 只影响首见**暴露**,不影响 call 时的
        // firewall 决策(enforce 仍 default-deny 风险调用;drift 仍被 gate 抓)。
        auto_approve_first_seen: true,
        dev_permissive_firewall: false, // 生产 default-deny(call 决策仍零信任)
        enable_privacy_filter: false,   // 硬指纹脱敏始终在;ORT 模型层 opt-in(--features ort)
        // 注入分类器仅 serve 直跑 opt-in;wrap turnkey 不默认拉 738MB 模型(用户可改用 serve 直跑)。
        enable_injection_classifier: false,
        redact_tool_results: true, // 可逆脱敏:结果里的 secret 回模型前再脱敏(网关核心价值)
        ml_best_effort: false,     // turnkey wrap = 硬指纹底座;ML 走 `serve --engine ml|auto`
        monitor: args.monitor,     // opt-in 非阻塞观察(turnkey 无 GUI resolver 时)
        // DEF-004:边界根缺省 CWD(wrap 由 agent 在项目目录启动)。
        project_roots: serve::resolve_project_roots(&args.project_roots),
    };

    // 稳定 server 身份(Codex R1 BLOCKER):显式 --server-id;缺省由 argv sha256 派生抗碰撞 id。
    let server_id = match &args.server_id {
        Some(id) => id.clone(),
        None => {
            let mut h = Sha256::new();
            for a in &command {
                h.update(a.as_bytes());
                h.update([0u8]); // 分隔,防 argv 拼接歧义
            }
            let id = format!("wrap-{}", &hex::encode(h.finalize())[..12]);
            eprintln!(
                "vigil-hub wrap: no --server-id given; derived `{id}` from the command. \
                 Pass --server-id <name> (the agent's server name) for stable audit/approval identity."
            );
            id
        }
    };

    // Hub(无 upstream:wrap 自己 attach 以受控转发 env;build_hub_with_config(None) 不自动 attach)。
    let (hub, ledger) = serve::build_hub_with_config(&serve_args, None)?;

    // env 转发(Codex R1 HIGH):**不**盲传全量。默认空 → 子进程只拿非密钥白名单(PATH/HOME…)。
    // --env-key <K> 显式转发该 server 配置的 env 键(wrap 从自身 env 读值);--inherit-env 才全量。
    let env: Vec<(String, String)> = if args.inherit_env {
        // Codex audit HIGH:--inherit-env 把**全部**宿主 env(含所有 API key/云凭证)转发给上游
        // MCP server —— 显式逃生舱但风险高(尤其 monitor 模式风险调用自动放行 → 上游可读并经
        // 工具输出/网络行为外泄;结果脱敏只抓已知指纹)。**响亮警告**(走 stderr 不污染 MCP stdout),
        // 促使用户改用 --env-key 精确 allowlist。
        eprintln!(
            "vigil-hub wrap: WARNING --inherit-env forwards ALL of this process's environment \
             (including every API key / cloud credential it holds) to upstream server `{server_id}`. \
             Prefer --env-key <KEY> to forward only the keys this server actually needs."
        );
        std::env::vars().collect()
    } else {
        args.env_keys
            .iter()
            .filter_map(|k| std::env::var(k).ok().map(|v| (k.clone(), v)))
            .collect()
    };
    serve::attach_stdio_upstream(&ledger, &hub, &server_id, &command, &env)?;

    // 启动提示走 **stderr**(stdout 是给 agent 的 MCP 协议通道,**不得污染**)。
    // 只打印命令名 argv[0],**不**打印完整 argv(防 argv 里偶含 secret 被回显)。
    // 诚实告知当前 posture(enforce 阻塞审批 vs monitor 非阻塞观察)。
    let posture = if args.monitor {
        "MONITOR posture: risky tool calls are auto-allowed + audited (NOT blocked); \
         raw secrets are still blocked and results still redacted"
    } else {
        "ENFORCE posture: risky tool calls pause for approval (run the desktop app to approve, \
         else they time out denied) -- pass --monitor for non-blocking audit-only"
    };
    // DEF-004 可见性:打印实际绑定的项目边界根(宿主 spawn 的 CWD 不是项目目录时,
    // 边界会静默绑错 —— enforce 下项目内写被误拦,打印让误绑可被肉眼发现)。
    let boundary = if serve_args.project_roots.is_empty() {
        "NONE".to_string()
    } else {
        serve_args.project_roots.join(", ")
    };
    eprintln!(
        "vigil-hub wrap: guarding MCP server `{server}` cmd `{cmd}` (PID {pid}); audit ledger -> {ledger}; project boundary -> {boundary}. {posture}.",
        server = server_id,
        cmd = command.first().map(String::as_str).unwrap_or("?"),
        pid = std::process::id(),
        ledger = ledger_display,
    );

    // stdio 主循环:agent <-> wrap(Vigil 网关)<-> 被包裹 server 子进程。
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = std::io::BufReader::new(stdin.lock());
    let mut writer = stdout.lock();
    let loop_result = serve::run_stdio_loop(&hub, &mut reader, &mut writer);
    // 关闭(优雅或错误)时 best-effort 锚定审计链头(ADR 0020):turnkey 用户经 `setup --mcp` 用 wrap,
    // 不会手动 `vigil-hub checkpoint` —— 这里让整链重写保护对他们自动生效。
    serve::anchor_checkpoint_on_shutdown(serve_args.ledger_path.as_deref(), &ledger);
    loop_result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_command_is_rejected() {
        let out = run(&WrapArgs {
            command: vec![],
            ledger: Some(PathBuf::from("ignored")),
            ..Default::default()
        });
        assert!(matches!(out, Err(ServeError::InvalidUpstream { .. })));
    }

    #[test]
    fn leading_double_dash_only_is_rejected() {
        // 只有 `--` 没有命令 → 剥离后为空 → 拒绝。
        let out = run(&WrapArgs {
            command: vec!["--".to_string()],
            ledger: Some(PathBuf::from("ignored")),
            ..Default::default()
        });
        assert!(matches!(out, Err(ServeError::InvalidUpstream { .. })));
    }

    #[test]
    fn derived_server_id_is_stable_and_collision_resistant() {
        // 同 argv → 同 id;不同 argv → 不同 id。
        let id = |argv: &[&str]| -> String {
            let mut h = Sha256::new();
            for a in argv {
                h.update(a.as_bytes());
                h.update([0u8]);
            }
            format!("wrap-{}", &hex::encode(h.finalize())[..12])
        };
        assert_eq!(id(&["npx", "fs", "/a"]), id(&["npx", "fs", "/a"]));
        assert_ne!(id(&["npx", "fs", "/a"]), id(&["npx", "fs", "/b"]));
        // 分隔符防拼接歧义:["a","bc"] != ["ab","c"]
        assert_ne!(id(&["a", "bc"]), id(&["ab", "c"]));
    }

    #[test]
    fn env_forwarding_defaults_to_explicit_keys_only() {
        // 默认(无 env_keys 无 inherit)→ 不转发任何 secret(只白名单经 env policy)。
        std::env::set_var("WRAP_TEST_SECRET", "shh");
        let keys: Vec<String> = Vec::new();
        let fwd: Vec<(String, String)> = keys
            .iter()
            .filter_map(|k: &String| std::env::var(k).ok().map(|v| (k.clone(), v)))
            .collect();
        assert!(fwd.is_empty(), "default forwards no explicit env");
        // --env-key 指定才转发该键
        let keys = ["WRAP_TEST_SECRET".to_string()];
        let fwd: Vec<(String, String)> = keys
            .iter()
            .filter_map(|k| std::env::var(k).ok().map(|v| (k.clone(), v)))
            .collect();
        assert_eq!(
            fwd,
            vec![("WRAP_TEST_SECRET".to_string(), "shh".to_string())]
        );
        std::env::remove_var("WRAP_TEST_SECRET");
    }
}
