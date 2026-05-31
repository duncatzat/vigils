//! I07 §8.7 Native runner 验收测试。
//!
//! 覆盖:
//! - §8.7-3 env_clear(子进程不继承 PATH)
//! - §8.7-4 cwd 越界预检拒绝
//! - §8.7-5 wall_ms 超时 kill
//! - §8.7-6 stdout 脱敏(SENTINEL 不出现)
//! - §8.7-7 PreparedChildEnv Drop 后 lease revoked

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::err_expect,
    clippy::panic
)]

use std::path::PathBuf;
use std::sync::Arc;

use tempfile::TempDir;
use vigil_audit::{Ledger, ToolSecretBinding};
use vigil_lease::{InMemorySecretStore, LeaseBroker, ResolveContext, SecretStore, SecretValue};
use vigil_runner::{
    default_scrub, spawn_native, ExecutionPlan, NullAuditSink, RejectField, RunnerError,
    SandboxProfile,
};

fn setup() -> (Arc<Ledger>, Arc<LeaseBroker>, String, TempDir) {
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    let sid = ledger.start_session("i07_test", None).unwrap();
    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let broker = Arc::new(LeaseBroker::new(store, ledger.clone()));
    let tmp = tempfile::tempdir().unwrap();
    (ledger, broker, sid, tmp)
}

// ---- 跨平台测试子命令:全部用**绝对路径**,不依赖 PATH(env_clear 清了 PATH) ----

fn shell_abs() -> &'static str {
    if cfg!(windows) {
        r"C:\Windows\System32\cmd.exe"
    } else {
        "/bin/sh"
    }
}

fn echo_cmd(text: &str) -> Vec<String> {
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

/// 打印 PATH 环境变量。
fn print_path_cmd() -> Vec<String> {
    if cfg!(windows) {
        vec![shell_abs().into(), "/c".into(), "echo PATH=%PATH%".into()]
    } else {
        vec![shell_abs().into(), "-c".into(), "echo PATH=$PATH".into()]
    }
}

fn basic_plan(tmp: &TempDir) -> ExecutionPlan {
    let cwd: PathBuf = tmp.path().to_path_buf();
    // Linux Landlock 强制 FS 白名单:exec 系统二进制(/bin/sh 等)需 profile 允许读取
    // 该二进制 + 动态加载器 + 共享库目录。加标准系统只读目录(仅存在者 —— from_dirs 对
    // 不存在路径返 PathOpenFailed)。现代内核(≥5.13 + LSM)强制 Landlock 后必需;旧内核
    // 不强制时这些测试曾"侥幸"通过。
    #[allow(unused_mut)] // 非 Linux 下不进入下方 cfg(linux) 追加块,mut 看似多余
    let mut read = vec![cwd.clone()];
    #[cfg(target_os = "linux")]
    for d in ["/bin", "/usr/bin", "/lib", "/lib64", "/usr/lib"] {
        let p = PathBuf::from(d);
        if p.exists() {
            read.push(p);
        }
    }
    let profile = SandboxProfile::new(
        "test",
        read,
        vec![cwd.clone()],
        5000, // 5s wall
    );
    let mut plan = ExecutionPlan::native_from_profile(&profile, cwd);
    plan.validate().expect("plan validate");
    plan
}

fn empty_prepared(broker: &Arc<LeaseBroker>, sid: &str) -> vigil_lease::PreparedChildEnv {
    // 无 binding → 空 env(但仍是 PreparedChildEnv RAII)
    broker
        .prepare_child_env(
            &ResolveContext {
                session_id: sid.into(),
                server_id: "s_no_bindings".into(),
                tool_name: "t".into(),
            },
            None,
            60,
        )
        .unwrap()
}

/// §8.7-3:env_clear → 子进程 PATH 应为空
#[tokio::test(flavor = "multi_thread")]
async fn native_spawn_env_is_cleared() {
    let (_l, broker, sid, tmp) = setup();
    let plan = basic_plan(&tmp);
    let prepared = empty_prepared(&broker, &sid);
    let scrub = default_scrub();

    if cfg!(windows) {
        // Windows:cmd /c echo %PATH% —— env_clear 后变量不存在会输出字面 %PATH% 或为空。
        let argv = print_path_cmd();
        let r = spawn_native(&plan, &argv, prepared, &scrub, &NullAuditSink)
            .await
            .unwrap();
        let stdout = String::from_utf8_lossy(&r.stdout);
        assert!(
            stdout.contains("PATH=%PATH%") || stdout.trim() == "PATH=",
            "Windows env_clear 后 PATH 应未展开或为空,实际: {stdout}"
        );
    } else {
        // Unix:**直接** spawn `/usr/bin/env`(不经 shell)。经 `/bin/sh -c "echo $PATH"` 不可靠
        // —— dash 等在 PATH 未设时会为 `$PATH` 设编译期默认值(`/usr/local/sbin:...:/bin`),
        // 那是 shell 自己的默认,不代表 env_clear 失败。`env` 直接打印 environ:env_clear 后
        // environ 为空 → 无输出,直接证明子进程未继承父进程环境。
        let argv = vec!["/usr/bin/env".to_string()];
        let r = spawn_native(&plan, &argv, prepared, &scrub, &NullAuditSink)
            .await
            .unwrap();
        let stdout = String::from_utf8_lossy(&r.stdout);
        assert!(
            stdout.trim().is_empty(),
            "Unix env_clear 后 environ 应为空(env 无输出),实际: {stdout}"
        );
    }
}

/// §8.7-4:cwd 在 read_dirs 之外 → plan.validate() 拒绝(Rejected)
#[test]
fn native_write_outside_allowlist_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let allowed = tmp.path().to_path_buf();
    // cwd 在 tempdir 之外(直接用 workspace 根)
    let bad_cwd = std::env::current_dir().unwrap();
    let profile = SandboxProfile::new("test", vec![allowed.clone()], vec![allowed], 1000);
    let mut plan = ExecutionPlan::native_from_profile(&profile, bad_cwd);
    let err = plan.validate().unwrap_err();
    match err {
        RunnerError::Rejected { field, reason_code } => {
            assert_eq!(field, RejectField::Cwd);
            assert_eq!(reason_code, "cwd_outside_read_dirs");
        }
        other => panic!("期望 Rejected(Cwd),得到 {other:?}"),
    }
}

/// §8.7-4 变种:write_dir 在 read_dirs 之外被拒
#[test]
fn plan_rejects_write_dir_outside_read_dirs() {
    let tmp = tempfile::tempdir().unwrap();
    let read = tmp.path().to_path_buf();
    let write_outside = std::env::temp_dir(); // 一定在 read 之外
    let profile = SandboxProfile::new("test", vec![read.clone()], vec![write_outside], 1000);
    let mut plan = ExecutionPlan::native_from_profile(&profile, read);
    let err = plan.validate().unwrap_err();
    assert!(matches!(
        err,
        RunnerError::Rejected {
            field: RejectField::WriteDir,
            ..
        }
    ));
}

/// §8.7-5:wall_ms 耗尽 → 子进程被 kill,返 RunnerError::Timeout
///
/// Windows 下直接用 `ping.exe -n N -w 1000` 绝对路径,避免 cmd /c 解析;
/// ping 长驻 ~(N-1) 秒,wall_ms=500 触发 kill。
#[tokio::test(flavor = "multi_thread")]
async fn native_sleep_over_wall_ms_is_killed() {
    let (_l, broker, sid, tmp) = setup();
    let mut plan = basic_plan(&tmp);
    plan.wall_ms = 500; // 0.5s,子进程 sleep ~3s
    let prepared = empty_prepared(&broker, &sid);
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
    let err = match spawn_native(&plan, &argv, prepared, &scrub, &NullAuditSink).await {
        Ok(r) => panic!(
            "期望 Timeout,得到 Ok(exit={:?} wall={}ms stderr={:?})",
            r.exit_code,
            r.wall_elapsed_ms,
            String::from_utf8_lossy(&r.stderr)
        ),
        Err(e) => e,
    };
    match err {
        RunnerError::Timeout { wall_ms } => assert_eq!(wall_ms, 500),
        other => panic!("期望 Timeout,得到 {other:?}"),
    }
}

/// §8.7-6:stdout 含 secret 指纹 → scrub 后不出现明文
#[tokio::test(flavor = "multi_thread")]
async fn capture_scrubs_sentinel_in_stdout() {
    let (_l, broker, sid, tmp) = setup();
    let plan = basic_plan(&tmp);
    let prepared = empty_prepared(&broker, &sid);
    // GitHub 硬指纹(40 字符)
    const SENTINEL: &str = "ghp_1234567890abcdef1234567890abcdef12345678";
    let argv = echo_cmd(SENTINEL);
    let scrub = default_scrub();
    let r = spawn_native(&plan, &argv, prepared, &scrub, &NullAuditSink)
        .await
        .unwrap();
    let out = String::from_utf8_lossy(&r.stdout);
    assert!(
        !out.contains(SENTINEL),
        "SENTINEL 不得出现在 captured stdout: {out}"
    );
    assert!(out.contains("[REDACTED"), "应有 [REDACTED 占位符: {out}");
}

/// §8.7-7:PreparedChildEnv Drop 后 lease revoked(spawn 函数返回即 drop)
#[tokio::test(flavor = "multi_thread")]
async fn prepared_env_drop_revokes_lease_after_spawn() {
    let (l, broker, sid, tmp) = setup();
    // 准备一条 binding + secret
    let store = Arc::new(InMemorySecretStore::new());
    store.put("secret://x", SecretValue::new("val")).unwrap();
    let broker_with_secret = Arc::new(LeaseBroker::new(store, l.clone()));
    l.register_secret_ref("secret://x", "X", "mock").unwrap();
    l.bind_tool_secret(&ToolSecretBinding {
        server_id: "s".into(),
        tool_name: "*".into(),
        secret_ref: "secret://x".into(),
        injection_method: "ChildEnv".into(),
        env_var_name: Some("X_TOKEN".into()),
    })
    .unwrap();

    let plan = basic_plan(&tmp);
    let prepared = broker_with_secret
        .prepare_child_env(
            &ResolveContext {
                session_id: sid.clone(),
                server_id: "s".into(),
                tool_name: "t".into(),
            },
            None,
            60,
        )
        .unwrap();
    assert_eq!(broker_with_secret.cache_len(), 1, "spawn 前应有 1 条 lease");

    let argv = echo_cmd("hi");
    let scrub = default_scrub();
    let _ = spawn_native(&plan, &argv, prepared, &scrub, &NullAuditSink)
        .await
        .unwrap();

    assert_eq!(
        broker_with_secret.cache_len(),
        0,
        "spawn 返回后 PreparedChildEnv drop → lease 必须被 revoke"
    );
    let _ = broker; // silence unused
}

/// T7 边界:argv 为空 → Rejected
#[tokio::test(flavor = "multi_thread")]
async fn native_argv_missing_binary_rejected() {
    let (_l, broker, sid, tmp) = setup();
    let plan = basic_plan(&tmp);
    let prepared = empty_prepared(&broker, &sid);
    let scrub = default_scrub();
    let err = spawn_native(&plan, &[], prepared, &scrub, &NullAuditSink)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        RunnerError::Rejected {
            field: RejectField::Argv,
            ..
        }
    ));
}

/// T7 边界:不存在的 binary → Io error
#[tokio::test(flavor = "multi_thread")]
async fn native_unknown_binary_returns_io_error() {
    let (_l, broker, sid, tmp) = setup();
    let plan = basic_plan(&tmp);
    let prepared = empty_prepared(&broker, &sid);
    let scrub = default_scrub();
    let err = spawn_native(
        &plan,
        &["/nonexistent/vigil_test_binary_xyz".into()],
        prepared,
        &scrub,
        &NullAuditSink,
    )
    .await
    .unwrap_err();
    match err {
        RunnerError::Io { phase, .. } => assert_eq!(phase, "spawn"),
        other => panic!("期望 Io,得到 {other:?}"),
    }
}
