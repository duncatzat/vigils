//! 「ML 控制平面」—— GUI 驱动 `vigil-hub` CLI 的常驻 daemon 生命周期 + ML 模型安装(ADR 0024)。
//!
//! GUI **不是**防护机制本身(防护靠 agent 每次工具调用拉起的 vigil-hub hook 子进程);GUI 是**控制
//! 平面**:经 shell-out 调度 `vigil-hub daemon start|status|stop` 与 `vigil-hub model install|status`,
//! 解析输出回前端。重活(暖载模型 / 下载)全在 CLI;GUI 只调度 + 解析,**不把 ort feature 拉进 GUI**
//! (进程隔离;避免 GUI 冷启动被 ML 拖慢)。
//!
//! daemon **独立于 GUI 生命周期**(detached spawn —— 它要为 agent 的 hook 主路径服务,不随 GUI 关闭
//! 而停);stop 经 `vigil-hub daemon stop`(CLI 侧 R1+token 验存活后杀 pid,防 pid 重用误杀)。

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

const ENGINE_BIN: &str = if cfg!(windows) {
    "vigil-hub.exe"
} else {
    "vigil-hub"
};

const ENGINE_NOT_FOUND: &str =
    "vigil-hub engine not found (bundle it with the app, place it next to the app, or put it on PATH)";

/// 稳定启动器位置:`<data_local>/Vigil/bin/vigil-hub[.exe]`(Win=`%LOCALAPPDATA%`,
/// mac=`~/Library/Application Support`,linux=`~/.local/share`)。**随 app 更新/移动不变** ——
/// hook 钉在这里才扛得住更新(CRIT-1);更新只需重新复制引擎到此处,agent 配置无需重写。
pub fn stable_launcher_path() -> Option<PathBuf> {
    Some(
        dirs::data_local_dir()?
            .join("Vigil")
            .join("bin")
            .join(ENGINE_BIN),
    )
}

/// 解析 vigil-hub 引擎二进制:捆绑 resource → GUI exe 同目录 → 稳定启动器位置 → PATH。优雅 fall-through。
fn resolve_engine(app: &AppHandle) -> Option<PathBuf> {
    if let Ok(dir) = app.path().resource_dir() {
        let p = dir.join(ENGINE_BIN);
        if p.is_file() {
            return Some(p);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(p) = exe.parent().map(|d| d.join(ENGINE_BIN)) {
            if p.is_file() {
                return Some(p);
            }
        }
    }
    // 已下载/部署到稳定启动器位置的引擎。
    if let Some(p) = stable_launcher_path() {
        if p.is_file() {
            return Some(p);
        }
    }
    which_on_path(ENGINE_BIN)
}

fn which_on_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(bin))
        .find(|p| p.is_file())
}

/// Windows:子进程不弹控制台黑窗(GUI 驱动 CLI 引擎时常见的闪窗)。其它平台 no-op。
#[cfg(windows)]
fn no_window(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(CREATE_NO_WINDOW);
}
#[cfg(not(windows))]
fn no_window(_cmd: &mut Command) {}

/// 跑 `<engine> <args...>` 捕获 trimmed stdout(非零退出 → Err 带 stderr 摘要)。
fn run_cli_capture(engine: &Path, args: &[&str]) -> Result<String, String> {
    let mut cmd = Command::new(engine);
    cmd.args(args);
    no_window(&mut cmd);
    let out = cmd
        .output()
        .map_err(|e| format!("failed to run vigil-hub: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "vigil-hub {} failed: {}",
            args.first().copied().unwrap_or(""),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// 行级解析:`out` 中以 `prefix` 起头的行是否含 `installed` 且非 `not installed`。
fn status_line_installed(out: &str, prefix: &str) -> bool {
    out.lines()
        .find(|l| l.trim_start().starts_with(prefix))
        .map(|l| l.contains("installed") && !l.contains("not installed"))
        .unwrap_or(false)
}

/// daemon 运行态(GUI 守护卡)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    /// daemon 是否在运行(`daemon status` 报 `running`)。
    pub running: bool,
    /// 隐私 PII 模型是否已暖载(running 时从 status 行解析;model-less daemon = false)。
    pub pii_loaded: bool,
    /// 引擎二进制是否就位(false → 守护卡只读,提示先部署引擎)。
    pub engine_present: bool,
}

/// ML 模型缓存状态(GUI 模型卡)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelStatus {
    /// 隐私 PII 模型已安装(本地缓存 sha256 校验通过)。
    pub privacy_installed: bool,
    /// 注入分类器模型已安装。
    pub injection_installed: bool,
    /// 当前引擎二进制是否支持 ML(ort 变体)。false = 非 ML 变体,无法安装 → 卡提示换 ML 变体。
    pub ml_supported: bool,
    /// 引擎二进制是否就位。
    pub engine_present: bool,
}

/// 只读:daemon 运行态。`vigil-hub daemon status` 退出码恒 0,解析 stdout 行。引擎缺失 →
/// `running=false` + `engine_present=false`(不报错,前端优雅提示)。
pub fn daemon_status(app: &AppHandle) -> Result<DaemonStatus, String> {
    let Some(engine) = resolve_engine(app) else {
        return Ok(DaemonStatus {
            running: false,
            pii_loaded: false,
            engine_present: false,
        });
    };
    let out = run_cli_capture(&engine, &["daemon", "status"]).unwrap_or_default();
    // 精确匹配运行行 `daemon: running (pid=...` —— 区别于 `daemon: not running` / `not responding`。
    let running = out.contains("daemon: running (");
    let pii_loaded = running && out.contains("pii_loaded=true");
    Ok(DaemonStatus {
        running,
        pii_loaded,
        engine_present: true,
    })
}

/// 写:启动 daemon。**detached spawn**(daemon `start` 阻塞 serve,故不 wait、不持句柄 —— std 不在
/// 父退出/句柄 drop 时杀子,无 job object 绑定 → daemon 独立存活,供 hook 跨 GUI 会话用)。
/// spawn 后短暂等 bind + 写 daemon.json,再回最新状态(model-cached 暖载更久,前端可再轮询)。
pub fn daemon_start(app: &AppHandle) -> Result<DaemonStatus, String> {
    let engine = resolve_engine(app).ok_or_else(|| ENGINE_NOT_FOUND.to_string())?;
    let mut cmd = Command::new(&engine);
    cmd.args(["daemon", "start"]);
    no_window(&mut cmd);
    cmd.spawn()
        .map_err(|e| format!("failed to start the daemon: {e}"))?;
    // model-less / fast 暖载在 ~1s 内写 daemon.json;cached-model 暖载更久(前端 re-poll status)。
    std::thread::sleep(std::time::Duration::from_millis(800));
    daemon_status(app)
}

/// 写:停止 daemon(shell `vigil-hub daemon stop` —— CLI 侧 R1+token 验存活后杀 pid)。回最新状态。
pub fn daemon_stop(app: &AppHandle) -> Result<DaemonStatus, String> {
    let engine = resolve_engine(app).ok_or_else(|| ENGINE_NOT_FOUND.to_string())?;
    run_cli_capture(&engine, &["daemon", "stop"])?;
    daemon_status(app)
}

/// 只读:ML 模型缓存状态。`vigil-hub model status`:非 ort 变体输出 `unsupported` → `ml_supported=false`;
/// ort 变体逐行报 privacy / injection 是否 `installed`。引擎缺失 → 全 false。
pub fn model_status(app: &AppHandle) -> Result<ModelStatus, String> {
    let Some(engine) = resolve_engine(app) else {
        return Ok(ModelStatus {
            privacy_installed: false,
            injection_installed: false,
            ml_supported: false,
            engine_present: false,
        });
    };
    let out = run_cli_capture(&engine, &["model", "status"]).unwrap_or_default();
    let ml_supported = !out.contains("unsupported");
    Ok(ModelStatus {
        privacy_installed: ml_supported && status_line_installed(&out, "privacy"),
        injection_installed: ml_supported && status_line_installed(&out, "injection"),
        ml_supported,
        engine_present: true,
    })
}

/// 写:安装 ML 模型(shell `vigil-hub model install` —— 下载两模型,**阻塞**:16-chunk 并发实测数十秒,
/// 前端转圈)。fail-closed:非 ML 变体 / 网络 / sha256 不符 → 非零退出 → Err 透传前端。回安装后状态。
pub fn model_install(app: &AppHandle) -> Result<ModelStatus, String> {
    let engine = resolve_engine(app).ok_or_else(|| ENGINE_NOT_FOUND.to_string())?;
    run_cli_capture(&engine, &["model", "install"])?;
    model_status(app)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_launcher_path_is_under_vigil_bin() {
        let p = stable_launcher_path().expect("data_local_dir resolves on test host");
        assert!(
            p.ends_with(Path::new("Vigil").join("bin").join(ENGINE_BIN)),
            "stable path should be <data_local>/Vigil/bin/{ENGINE_BIN}, got {p:?}"
        );
    }

    #[test]
    fn status_line_installed_parses_installed_and_not_installed() {
        let out = "privacy: installed (sha256 ok)\ninjection: not installed";
        assert!(status_line_installed(out, "privacy"));
        assert!(!status_line_installed(out, "injection"));
        // 缺失行 → false(不 panic)。
        assert!(!status_line_installed(out, "missing"));
    }

    #[test]
    fn daemon_status_deserializes_json_contract() {
        let json = r#"{"running":true,"pii_loaded":true,"engine_present":true}"#;
        let s: DaemonStatus = serde_json::from_str(json).expect("parse DaemonStatus json contract");
        assert!(s.running);
        assert!(s.pii_loaded);
        assert!(s.engine_present);
    }

    #[test]
    fn model_status_deserializes_json_contract() {
        let json = r#"{"privacy_installed":true,"injection_installed":false,
            "ml_supported":true,"engine_present":true}"#;
        let s: ModelStatus = serde_json::from_str(json).expect("parse ModelStatus json contract");
        assert!(s.privacy_installed);
        assert!(!s.injection_installed);
        assert!(s.ml_supported);
        assert!(s.engine_present);
    }
}
