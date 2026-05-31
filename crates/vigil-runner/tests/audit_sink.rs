//! Codex R1 MUST-FIX 3 回归:RunnerAuditSink 被 runner 内部所有路径调用。
//!
//! 覆盖 5 条 `runner.*` 事件:Started / Completed / KilledByTimeout / IoError / Rejected

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::err_expect,
    clippy::panic
)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tempfile::TempDir;
use vigil_audit::Ledger;
use vigil_lease::{InMemorySecretStore, LeaseBroker, ResolveContext};
use vigil_runner::{
    default_scrub, spawn_native, ExecutionPlan, RejectField, RunnerAuditSink, RunnerEvent,
    RunnerKind, RunnerSpecific, SandboxProfile,
};

/// 捕获 RunnerEvent 的测试 sink。
#[derive(Debug, Default)]
struct CollectingSink {
    events: Mutex<Vec<String>>,
}

impl RunnerAuditSink for CollectingSink {
    fn emit(&self, event: RunnerEvent<'_>) {
        // 用 kind 字符串 + 关键字段序列化(不含真值)
        let tag = match event {
            RunnerEvent::Started {
                runner_kind,
                wall_ms,
                env_keys,
                ..
            } => format!("Started:{runner_kind}:wall_ms={wall_ms}:envs={}", env_keys.len()),
            RunnerEvent::Completed {
                exit_code,
                wall_elapsed_ms,
                stdout_bytes,
                stderr_bytes,
            } => format!(
                "Completed:exit={exit_code:?}:wall={wall_elapsed_ms}:stdout={stdout_bytes}:stderr={stderr_bytes}"
            ),
            RunnerEvent::KilledByTimeout { wall_ms } => {
                format!("KilledByTimeout:wall_ms={wall_ms}")
            }
            RunnerEvent::IoError { phase, reason_code } => {
                format!("IoError:{phase}:{reason_code}")
            }
            RunnerEvent::Rejected { field, reason_code } => {
                format!("Rejected:{}:{}", field.as_str(), reason_code)
            }
            // ISS-020:LeakDetected 序列化为 "Leak:source:rule1,rule2"
            RunnerEvent::LeakDetected {
                source,
                rules,
                quarantined,
            } => format!(
                "Leak:{source}:q={quarantined}:rules={}",
                rules.join(",")
            ),
            _ => "Unknown".to_string(),
        };
        let mut g = self.events.lock().unwrap();
        g.push(tag);
    }
}

impl CollectingSink {
    fn tags(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
}

fn setup() -> (Arc<LeaseBroker>, String, TempDir) {
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    let sid = ledger.start_session("audit_test", None).unwrap();
    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let broker = Arc::new(LeaseBroker::new(store, ledger));
    let tmp = tempfile::tempdir().unwrap();
    (broker, sid, tmp)
}

fn basic_plan(tmp: &TempDir) -> ExecutionPlan {
    let cwd: PathBuf = tmp.path().to_path_buf();
    // Linux Landlock 强制 FS 白名单(现代内核 ≥ 5.13 + LSM 启用):要 exec 一个系统二进制
    // (`/bin/sh` / `/bin/sleep`),profile 必须允许读取该二进制 + 动态加载器 + 共享库所在目录。
    // 旧内核不强制 Landlock 时这些测试"侥幸"通过;现代内核(GitHub ubuntu / 本地 dev box
    // 均 6.8)强制后会以 `command_spawn_failed` 失败。这里把标准系统只读目录加入 read_dirs
    // (仅加**存在**的目录 —— LandlockPolicy::from_dirs 对不存在路径返 PathOpenFailed)。
    #[allow(unused_mut)] // 非 Linux 下不进入下方 cfg(linux) 追加块,mut 看似多余
    let mut read = vec![cwd.clone()];
    #[cfg(target_os = "linux")]
    for d in ["/bin", "/usr/bin", "/lib", "/lib64", "/usr/lib"] {
        let p = PathBuf::from(d);
        if p.exists() {
            read.push(p);
        }
    }
    let profile = SandboxProfile::new("t", read, vec![cwd.clone()], 5000);
    let mut plan = ExecutionPlan::native_from_profile(&profile, cwd);
    plan.validate().unwrap();
    plan
}

fn empty_prepared(broker: &Arc<LeaseBroker>, sid: &str) -> vigil_lease::PreparedChildEnv {
    broker
        .prepare_child_env(
            &ResolveContext {
                session_id: sid.into(),
                server_id: "s".into(),
                tool_name: "t".into(),
            },
            None,
            60,
        )
        .unwrap()
}

fn shell_abs() -> &'static str {
    if cfg!(windows) {
        r"C:\Windows\System32\cmd.exe"
    } else {
        "/bin/sh"
    }
}

fn echo(text: &str) -> Vec<String> {
    if cfg!(windows) {
        vec![shell_abs().into(), "/c".into(), format!("echo {text}")]
    } else {
        vec![
            shell_abs().into(),
            "-c".into(),
            format!("printf '%s\\n' '{text}'"),
        ]
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn native_happy_path_emits_started_and_completed() {
    let (broker, sid, tmp) = setup();
    let plan = basic_plan(&tmp);
    let prepared = empty_prepared(&broker, &sid);
    let sink = CollectingSink::default();
    let scrub = default_scrub();
    let _ = spawn_native(&plan, &echo("hi"), prepared, &scrub, &sink)
        .await
        .unwrap();
    let tags = sink.tags();
    assert!(
        tags.iter().any(|t| t.starts_with("Started:Native:")),
        "期望 Started 事件,实际 {tags:?}"
    );
    assert!(
        tags.iter().any(|t| t.starts_with("Completed:")),
        "期望 Completed 事件,实际 {tags:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn native_timeout_emits_killed_by_timeout() {
    let (broker, sid, tmp) = setup();
    let mut plan = basic_plan(&tmp);
    plan.wall_ms = 500;
    let prepared = empty_prepared(&broker, &sid);
    let sink = CollectingSink::default();
    let argv: Vec<String> = if cfg!(windows) {
        vec![
            r"C:\Windows\System32\ping.exe".into(),
            "-n".into(),
            "5".into(),
            "-w".into(),
            "1000".into(),
            "127.0.0.1".into(),
        ]
    } else {
        vec!["/bin/sleep".into(), "3".into()]
    };
    let scrub = default_scrub();
    let _ = spawn_native(&plan, &argv, prepared, &scrub, &sink).await;
    let tags = sink.tags();
    assert!(
        tags.iter().any(|t| t.starts_with("Started:Native:")),
        "timeout 前应有 Started 事件: {tags:?}"
    );
    assert!(
        tags.iter()
            .any(|t| t.starts_with("KilledByTimeout:wall_ms=500")),
        "timeout 必须发射 KilledByTimeout 事件: {tags:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn native_rejected_argv_emits_rejected_event() {
    let (broker, sid, tmp) = setup();
    let plan = basic_plan(&tmp);
    let prepared = empty_prepared(&broker, &sid);
    let sink = CollectingSink::default();
    let scrub = default_scrub();
    let err = spawn_native(&plan, &[], prepared, &scrub, &sink)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        vigil_runner::RunnerError::Rejected {
            field: RejectField::Argv,
            ..
        }
    ));
    let tags = sink.tags();
    assert!(
        tags.iter()
            .any(|t| t.starts_with("Rejected:argv:argv_empty")),
        "argv 空应产 Rejected(argv) 事件,实际 {tags:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn native_spawn_failure_emits_io_error() {
    let (broker, sid, tmp) = setup();
    let plan = basic_plan(&tmp);
    let prepared = empty_prepared(&broker, &sid);
    let sink = CollectingSink::default();
    let scrub = default_scrub();
    let _ = spawn_native(
        &plan,
        &["/nonexistent/vigil_xyz".into()],
        prepared,
        &scrub,
        &sink,
    )
    .await;
    let tags = sink.tags();
    assert!(
        tags.iter().any(|t| t.starts_with("IoError:spawn:")),
        "spawn 失败应产 IoError(spawn) 事件,实际 {tags:?}"
    );
}

/// Codex R2 MUST-FIX 1:Wasm `Module::new` 失败 → IoError(wasm_compile) 事件。
#[cfg(feature = "wasm")]
#[test]
fn wasm_invalid_module_emits_io_error_audit() {
    use vigil_runner::WasmRunner;
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path().to_path_buf();
    let profile = SandboxProfile::new("t", vec![cwd.clone()], vec![cwd.clone()], 5000);
    let mut plan = ExecutionPlan::wasm_from_profile(&profile, cwd);
    plan.validate().unwrap();
    let sink = CollectingSink::default();
    let runner = WasmRunner::new(default_scrub()).unwrap();
    let _ = runner.run(&plan, b"not-wasm", &sink);
    let tags = sink.tags();
    assert!(
        tags.iter().any(|t| t.starts_with("IoError:wasm_compile:")),
        "invalid wasm bytes 应产 IoError(wasm_compile) 事件,实际 {tags:?}"
    );
}

/// ISS-020 e2e:native runner 输出含 ghp_token 的 stdout → quarantined=true +
/// leak_findings 含 github_token + sink 收到 LeakDetected(stdout)。
///
/// 注:scrub 是 line-by-line 默认走 `vigil_redaction::scrub_text`,会把 ghp_token
/// 替换为 `[REDACTED github_token]`,**不会**触发 quarantine。要想触发二次扫,需
/// 注入一个**identity scrub**(不脱敏的 callback),模拟"scrub 漏掉" 的场景。
#[tokio::test(flavor = "multi_thread")]
async fn native_runner_quarantined_when_stdout_leaks_secret() {
    use std::sync::Arc;
    let (broker, sid, tmp) = setup();
    let plan = basic_plan(&tmp);
    let prepared = empty_prepared(&broker, &sid);
    let sink = CollectingSink::default();
    // identity scrub:模拟 scrub 漏掉的场景,让原文 ghp_token 漏到 stdout
    let scrub: vigil_runner::ScrubCallback = Arc::new(|s: &str| s.to_string());
    let token = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ";
    let result = spawn_native(&plan, &echo(token), prepared, &scrub, &sink)
        .await
        .unwrap();
    assert!(
        result.quarantined,
        "stdout 含 ghp_token 必须 quarantine:stdout={:?}",
        String::from_utf8_lossy(&result.stdout)
    );
    assert!(
        result.leak_findings.contains(&"github_token"),
        "leak_findings 应含 github_token:{:?}",
        result.leak_findings
    );
    let tags = sink.tags();
    assert!(
        tags.iter()
            .any(|t| t.starts_with("Leak:stdout:q=true:rules=") && t.contains("github_token")),
        "sink 应收到 LeakDetected(stdout/github_token):{tags:?}"
    );
}

/// ISS-020 e2e:输出干净文本 → quarantined=false / leak_findings 空 / 无 LeakDetected。
#[tokio::test(flavor = "multi_thread")]
async fn native_runner_clean_stdout_no_quarantine() {
    let (broker, sid, tmp) = setup();
    let plan = basic_plan(&tmp);
    let prepared = empty_prepared(&broker, &sid);
    let sink = CollectingSink::default();
    let scrub = default_scrub();
    let result = spawn_native(&plan, &echo("hello world"), prepared, &scrub, &sink)
        .await
        .unwrap();
    assert!(!result.quarantined, "干净 stdout 不应 quarantine");
    assert!(
        result.leak_findings.is_empty(),
        "干净 stdout 不应有 findings:{:?}",
        result.leak_findings
    );
    let tags = sink.tags();
    assert!(
        !tags.iter().any(|t| t.starts_with("Leak:")),
        "干净 stdout 不应有 LeakDetected 事件:{tags:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn native_wrong_runner_kind_is_rejected_with_event() {
    let (broker, sid, tmp) = setup();
    let cwd = tmp.path().to_path_buf();
    let profile = SandboxProfile::new("t", vec![cwd.clone()], vec![cwd.clone()], 1000);
    // 构造 Wasm plan 传给 spawn_native
    let mut plan = ExecutionPlan::wasm_from_profile(&profile, cwd);
    plan.validate().unwrap();
    let prepared = empty_prepared(&broker, &sid);
    let sink = CollectingSink::default();
    let scrub = default_scrub();
    let err = spawn_native(&plan, &echo("x"), prepared, &scrub, &sink)
        .await
        .unwrap_err();
    match err {
        vigil_runner::RunnerError::Rejected {
            field: RejectField::Runner,
            ..
        } => {}
        other => panic!("期望 Rejected(Runner),得到 {other:?}"),
    }
    let tags = sink.tags();
    assert!(
        tags.iter().any(|t| t.starts_with("Rejected:runner:")),
        "非 Native plan 应产 Rejected(runner) 事件: {tags:?}"
    );
    // 确保 plan.runner_kind 实际是 Wasm
    assert_eq!(plan.runner_kind, RunnerKind::Wasm);
    assert!(matches!(plan.runner_specific, RunnerSpecific::Wasm { .. }));
}
