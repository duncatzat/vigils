//! 「部署守卫 Deploy Guardian」—— GUI 驱动 vigil-hub CLI 引擎的控制层(bundle-and-drive,P1.3)。
//!
//! GUI **不是**防护机制本身(防护靠 agent 每次工具调用拉起的 vigil-hub hook 子进程);GUI 是**控制
//! 平面**:解析引擎二进制 → 复制到**稳定启动器**位置(随 app 更新/移动不变,CRIT-1)→ 跑
//! `setup --hook-exe <稳定> --json` 把 agent 的 hook 钉在稳定路径上 → 解析逐 agent 状态返回前端。
//! 引擎逻辑原封不动(功能不破)。
//!
//! 为何钉稳定路径:hostile review 指出,若 hook 指向 app 包内路径,Tauri 自动更新 / 用户移动后该
//! 路径失效,而 Claude/Codex/Gemini 的 hook 启动失败是 **fail-open(放行)**= 防护静默关闭。

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, TryLockError};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

/// 单 agent 的保护状态(镜像 CLI `setup --json` 的 agent 条目;
/// `status` ∈ active|stale|not_installed|pending_trust)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatus {
    /// 稳定小写名(`claude` / `codex` / `gemini` / `cursor`)。
    pub agent: String,
    /// 人类可读名(`Claude Code` 等)。
    pub display_name: String,
    /// 是否检测到该 agent(配置目录存在)。
    pub detected: bool,
    /// 保护状态:`active` | `stale` | `not_installed` | `pending_trust`(配置在位但
    /// agent 侧未信任 —— 目前仅 codex:须用户在 codex `/hooks` 一次性 review;不算 protected)。
    pub status: String,
}

/// 守卫聚合状态(镜像 CLI `setup --json`;`protected` = 任一 agent state=Active)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianStatus {
    /// 任一 agent 真生效(state=Active)。
    pub protected: bool,
    /// 审计账本路径。
    pub ledger: String,
    /// 写入 hook 的稳定可执行路径(部署后非 None)。
    pub hook_exe: Option<String>,
    /// 写入 agent 配置的 canonical hook command(供展示/诊断)。
    #[serde(default)]
    pub hook_command: String,
    /// 逐 agent 状态(绝不一盏聚合灯)。
    pub agents: Vec<AgentStatus>,
}

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

/// 解析 vigil-hub 引擎二进制。顺序:**已装 ML 变体(稳定目录,dylib 信号)** → 捆绑 resource →
/// GUI exe 同目录 → 稳定启动器(非 ML)→ PATH。优雅 fall-through。
///
/// 为何 ML 变体置顶:用户经 GUI 显式安装 ort 引擎到稳定目录后,必须盖过出厂硬指纹引擎(它可能在
/// exe 同目录 / PATH),否则 model/daemon/hook 仍跑硬指纹 → ML 形同未装。dylib 信号(同目录有
/// ONNX Runtime 库)= "这是用户装的 ML 引擎";无 dylib 的普通下载/部署引擎不触发本分支,顺序不变。
fn resolve_engine(app: &AppHandle) -> Option<PathBuf> {
    if let Some(p) = stable_launcher_path() {
        if p.is_file() && stable_has_ml_dylib(&p) {
            return Some(p);
        }
    }
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
    // 已下载/部署到稳定启动器位置(download_engine / deploy 的落点)。
    if let Some(p) = stable_launcher_path() {
        if p.is_file() {
            return Some(p);
        }
    }
    which_on_path(ENGINE_BIN)
}

/// 稳定启动器目录是否含与当前平台匹配的 ONNX Runtime dylib(`download_ml_engine` 的落点信号)。
/// 用于 [`resolve_engine`] 判定稳定目录里是不是用户装的 ML 引擎变体。
fn stable_has_ml_dylib(engine: &Path) -> bool {
    engine
        .parent()
        .map(|d| d.join(ort_dylib_basename()).is_file())
        .unwrap_or(false)
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

/// 跑 `<engine> setup --json <extra...>`,解析 stdout 为 [`GuardianStatus`]。
fn run_setup_json(engine: &Path, extra: &[&str]) -> Result<GuardianStatus, String> {
    let mut cmd = Command::new(engine);
    cmd.arg("setup").arg("--json").args(extra);
    no_window(&mut cmd);
    let out = cmd
        .output()
        .map_err(|e| format!("failed to run vigil-hub: {e}"))?;
    if out.stdout.is_empty() {
        return Err(format!(
            "vigil-hub setup produced no output: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    serde_json::from_slice(&out.stdout)
        .map_err(|e| format!("failed to parse vigil-hub status JSON: {e}"))
}

/// 只读:当前守卫状态(`setup --status --json`)。若稳定启动器已部署,用它作 `--hook-exe` 让
/// `protection_state` 按稳定 canonical 比对(否则会把"hook 指向稳定路径"误报成 Stale)。
pub fn status(app: &AppHandle) -> Result<GuardianStatus, String> {
    let engine = resolve_engine(app).ok_or_else(|| ENGINE_NOT_FOUND.to_string())?;
    match stable_launcher_path().filter(|p| p.is_file()) {
        Some(stable) => {
            let s = stable.to_string_lossy().to_string();
            run_setup_json(&engine, &["--status", "--hook-exe", &s])
        }
        None => run_setup_json(&engine, &["--status"]),
    }
}

/// 写:部署守卫 —— 把引擎复制到**稳定启动器**位置,再 `setup --hook-exe <稳定> --json`(让 agent 的
/// hook 钉在稳定路径上,抗 app 更新/移动)。返回逐 agent 状态。
///
/// **部署原子性(与 download/ML 安装同款纪律)**:持 [`INSTALL_LOCK`](防与 `download_engine` /
/// `install_ml_engine_into` 并发踩同一 bin 目录);复制先落 `<name>.deploy-stage` 临时件,再经
/// [`swap_in_staged`] 两阶段 rename 进位 —— 稳定启动器**任一时刻要么是完整旧件、要么是完整新件**。
/// 此前的裸 `fs::copy` 直接覆盖:复制中断(崩溃/断电/AV 拦截)= 半写 exe = hook 拉不起 =
/// **fail-open 静默失防**(CRIT-1 的反面),且 hook 正在并发拉起稳定启动器时 Windows 共享锁
/// 会让覆盖直接失败;rename 换装两者皆免疫。
pub fn deploy(app: &AppHandle) -> Result<GuardianStatus, String> {
    let _install = acquire_install_lock()?;
    let engine = resolve_engine(app).ok_or_else(|| ENGINE_NOT_FOUND.to_string())?;
    let stable = stable_launcher_path()
        .ok_or_else(|| "could not resolve a stable install location".to_string())?;
    let parent = stable
        .parent()
        .ok_or_else(|| "invalid stable launcher path".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    sweep_stale_installs(parent);
    // 若解析到的引擎就是稳定启动器本身(已装 ML 变体 / 已下载到位)→ 跳过自我复制:
    // `std::fs::copy(src, src)` 在 Unix 会先 O_TRUNC 目标再读源 → 清零二进制(数据丢失)。
    // 仅当双方都能 canonicalize 且相等才判定同一文件(任一失败 → 不跳过,正常复制)。
    let same_file = engine == stable
        || matches!(
            (std::fs::canonicalize(&engine), std::fs::canonicalize(&stable)),
            (Ok(a), Ok(b)) if a == b
        );
    let s = stable.to_string_lossy().to_string();
    if same_file {
        return run_setup_json(&stable, &["--hook-exe", &s]);
    }
    // 更新时把新引擎刷到稳定位置(staging + 换装);hook 路径(稳定)不变。**旧件保留到
    // setup 成功后**才清理 —— 换装成功但 `setup --hook-exe` 失败(新引擎损坏/不兼容)时,
    // 若旧件已删,用户手上一个可用引擎都不剩(codex review 2026-07-20 HIGH-4)。
    let staged = parent.join(format!("{ENGINE_BIN}.deploy-stage"));
    let _ = std::fs::remove_file(&staged);
    if let Err(e) = std::fs::copy(&engine, &staged) {
        let _ = std::fs::remove_file(&staged);
        return Err(format!("failed to stage the stable launcher: {e}"));
    }
    let aside = parent.join(format!("{ENGINE_BIN}.vigil-old"));
    let _ = std::fs::remove_file(&aside);
    let had_old = stable.exists();
    if had_old {
        if let Err(e) = std::fs::rename(&stable, &aside) {
            let _ = std::fs::remove_file(&staged);
            return Err(format!(
                "failed to move the old launcher aside ({e}) — if the daemon is running from it, \
                 stop it first (Settings → daemon → stop) and retry"
            ));
        }
    }
    if let Err(e) = std::fs::rename(&staged, &stable) {
        let _ = std::fs::remove_file(&staged);
        let mut msg = format!("failed to install the stable launcher: {e}");
        if had_old {
            match std::fs::rename(&aside, &stable) {
                Ok(()) => msg.push_str(" — the previous engine was restored"),
                // 回滚失败绝不静默(HIGH-4):明说磁盘终态,旧件仍在 aside 可手工恢复。
                Err(re) => msg.push_str(&format!(
                    " — rollback also failed ({re}); the stable launcher at {} is currently \
                     missing and the previous engine is preserved at {}",
                    stable.display(),
                    aside.display()
                )),
            }
        }
        return Err(msg);
    }
    match run_setup_json(&stable, &["--hook-exe", &s]) {
        Ok(status) => {
            // 新引擎已被 setup 验证可用 → 此刻才清理旧件(在用删不掉 → sweep 下次收)。
            if had_old {
                let _ = std::fs::remove_file(&aside);
            }
            Ok(status)
        }
        Err(e) => {
            let mut msg = format!("deploy failed while registering hooks: {e}");
            if had_old {
                let _ = std::fs::remove_file(&stable);
                match std::fs::rename(&aside, &stable) {
                    Ok(()) => msg.push_str(" — the previous engine was restored"),
                    Err(re) => msg.push_str(&format!(
                        " — restoring the previous engine also failed ({re}); it is preserved at {}",
                        aside.display()
                    )),
                }
            }
            Err(msg)
        }
    }
}

// ─────────────────────── ③ 缺失引擎:检测 + 提醒 + 安全自动下载 ───────────────────────
//
// 「以后发版时 desktop 缺工具应提醒用户 + 自动下载」。引擎(vigil-hub)正常随 app 捆绑;
// 若缺失(轻量分发 / 资源损坏),GUI 给清晰提醒(非 cryptic 错误)+ 一键下载。
//
// 供应链安全:仅 HTTPS;**SHA-pin** 校验(SHA 随已签名 desktop 烘焙,或 env 注入)——
// 无 pinned SHA 即 **fail-closed 拒绝**(绝不执行未校验二进制);装前再 `--version` 运行核验。

/// 引擎是否就位(resource / 同目录 / 稳定启动器 / PATH 任一)。前端据此决定是否提示下载。
pub fn engine_present(app: &AppHandle) -> bool {
    resolve_engine(app).is_some()
}

/// 引擎下载源(URL + 可选 pinned sha256)。
struct EngineSource {
    url: String,
    sha256: Option<String>,
}

/// 当前平台的引擎资产标识(发布镜像命名)。
fn engine_platform() -> Result<&'static str, String> {
    if cfg!(all(windows, target_arch = "x86_64")) {
        Ok("windows-x64")
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Ok("macos-arm64")
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        Ok("macos-x64")
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Ok("linux-x64")
    } else {
        Err("unsupported platform for engine auto-download".to_string())
    }
}

/// 解析引擎下载源。`VIGIL_ENGINE_URL` / `VIGIL_ENGINE_SHA256` env 覆盖优先(测试 / 私有镜像);
/// 否则按版本 + 平台拼 **GitHub release 资产** URL(去掉 vigils.ai SPA catch-all 软-200)。默认 baked
/// SHA = None → 无 SHA 时 [`download_engine`] 取 URL 前即 fail-closed(绝不执行未校验二进制),故默认
/// 控制平面自动下载为**惰性**,真实使用走 env 覆盖。注:裸二进制名 `vigil-hub-{plat}{ext}` 是内部控制
/// 平面分发形态,公开 release 现以 `vigils-cli-{plat}` 归档分发 → 默认 URL 待分发形态 reconcile。
fn engine_source() -> Result<EngineSource, String> {
    if let Ok(url) = std::env::var("VIGIL_ENGINE_URL") {
        return Ok(EngineSource {
            url,
            sha256: std::env::var("VIGIL_ENGINE_SHA256")
                .ok()
                .filter(|s| !s.is_empty()),
        });
    }
    let ver = env!("CARGO_PKG_VERSION");
    let plat = engine_platform()?;
    let ext = if cfg!(windows) { ".exe" } else { "" };
    Ok(EngineSource {
        url: format!(
            "https://github.com/duncatzat/vigils/releases/download/v{ver}/vigil-hub-{plat}{ext}"
        ),
        sha256: None,
    })
}

fn sha256_file(p: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(p).map_err(|e| format!("open for hashing failed: {e}"))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).map_err(|e| format!("hashing failed: {e}"))?;
    Ok(hex::encode(hasher.finalize()))
}

fn download_to_file(url: &str, dest: &Path) -> Result<(), String> {
    let resp = ureq::get(url)
        .timeout(std::time::Duration::from_secs(120))
        .call()
        .map_err(|e| format!("download request failed: {e}"))?;
    let mut reader = resp.into_reader();
    let mut file =
        std::fs::File::create(dest).map_err(|e| format!("create temp file failed: {e}"))?;
    std::io::copy(&mut reader, &mut file).map_err(|e| format!("writing engine failed: {e}"))?;
    Ok(())
}

/// 安装互斥(M3):`deploy` / `download_engine` / `install_ml_engine_into` / `model_install`
/// 共用,防并发安装踩同一 bin 目录(staging 目录共享 + rename 交错 → 混装)。前端按钮防抖
/// 不是边界 —— 命令层自持不变量。
static INSTALL_LOCK: Mutex<()> = Mutex::new(());

/// 非阻塞取安装锁:安装进行中再点 → 立即可读错误(不排队,前端可提示)。中毒(安装线程
/// panic)→ 收回守卫继续 —— 可用性优先,半成品由 [`sweep_stale_installs`] + 两阶段换装回滚兜底。
fn acquire_install_lock() -> Result<MutexGuard<'static, ()>, String> {
    match INSTALL_LOCK.try_lock() {
        Ok(g) => Ok(g),
        Err(TryLockError::Poisoned(p)) => Ok(p.into_inner()),
        Err(TryLockError::WouldBlock) => Err(
            "another engine/model install is already in progress — wait for it to finish"
                .to_string(),
        ),
    }
}

/// 清扫历史残留:`.ml-staging`(进程中途死亡遗留的下载/解包半成品)+ `*.vigil-old`(上次
/// 换装时在用、删不掉的旧件)+ `*.deploy-stage`(deploy 复制中途死亡的半成品)。尽力而为
/// (仍在用则下次再扫);安装入口调用。
fn sweep_stale_installs(bin_dir: &Path) {
    let _ = std::fs::remove_dir_all(bin_dir.join(".ml-staging"));
    if let Ok(entries) = std::fs::read_dir(bin_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".vigil-old") || name.ends_with(".deploy-stage") {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

/// 两阶段换装(H1):把 staged 成员换进 `bin_dir`,**绝不留混装**(如「新引擎 + 旧 dylib」)。
///
/// - **阶段 A**:已存在的同名目标先 rename 到 `<name>.vigil-old`。Windows 对**在用**文件的
///   namespace rename 也能成功 —— daemon 正跑旧引擎时安装照样完成,旧进程继续用已挪走的旧件
///   直至重启;任一 aside 失败 → 已挪的全部还原,`bin_dir` 回到调用前状态。
/// - **阶段 B**:staged → 目标位(staging 是 `bin_dir` 子目录 → 同卷 rename);失败 → 删已
///   进位的新件 + 还原全部 aside。
/// - 成功尾声:尽力删 aside(在用删不掉 → 留待 [`sweep_stale_installs`])。
fn swap_in_staged(bin_dir: &Path, staged: &[(String, PathBuf)]) -> Result<(), String> {
    // 阶段 A:挪开旧件。
    let mut asides: Vec<(PathBuf, PathBuf)> = Vec::new(); // (原位, aside 位)
    for (name, _) in staged {
        let target = bin_dir.join(name);
        if !target.exists() {
            continue;
        }
        let aside = bin_dir.join(format!("{name}.vigil-old"));
        let _ = std::fs::remove_file(&aside); // 上次残留;删不掉则下方 rename 失败走还原
        if let Err(e) = std::fs::rename(&target, &aside) {
            for (orig, moved) in asides.iter().rev() {
                let _ = std::fs::rename(moved, orig);
            }
            return Err(format!(
                "failed to move the old {name} aside ({e}) — if the daemon is running from the \
                 old engine, stop it first (Settings → daemon → stop) and retry"
            ));
        }
        asides.push((target, aside));
    }
    // 阶段 B:新件进位。
    let mut placed: Vec<PathBuf> = Vec::new();
    for (name, from) in staged {
        let to = bin_dir.join(name);
        if let Err(e) = std::fs::rename(from, &to) {
            for newly in placed.iter().rev() {
                let _ = std::fs::remove_file(newly);
            }
            for (orig, moved) in asides.iter().rev() {
                let _ = std::fs::rename(moved, orig);
            }
            return Err(format!(
                "failed to install {name} to {} ({e})",
                to.display()
            ));
        }
        placed.push(to);
    }
    for (_, moved) in &asides {
        let _ = std::fs::remove_file(moved);
    }
    Ok(())
}

/// 写:下载 vigil-hub 引擎到稳定启动器位置(HTTPS + SHA-pin + 运行核验,fail-closed),
/// 再返回部署后守卫状态。缺 pinned SHA → 拒绝(绝不执行未校验二进制)。
pub fn download_engine(app: &AppHandle) -> Result<GuardianStatus, String> {
    let _install = acquire_install_lock()?;
    let src = engine_source()?;
    if !src.url.starts_with("https://") {
        return Err(format!("refusing non-HTTPS engine URL: {}", src.url));
    }
    let expected_sha = src.sha256.as_deref().ok_or_else(|| {
        "engine auto-download is not configured with a pinned SHA256 (set VIGIL_ENGINE_SHA256, \
         or this build predates the signed release manifest) — refusing to fetch an unverified binary"
            .to_string()
    })?;

    let stable = stable_launcher_path()
        .ok_or_else(|| "could not resolve a stable install location".to_string())?;
    let parent = stable
        .parent()
        .ok_or_else(|| "invalid stable launcher path".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    sweep_stale_installs(parent);

    let tmp = parent.join(format!("{ENGINE_BIN}.download"));
    let _ = std::fs::remove_file(&tmp);
    if let Err(e) = download_to_file(&src.url, &tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    // SHA-pin fail-closed
    let got = match sha256_file(&tmp) {
        Ok(h) => h,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    };
    if !got.eq_ignore_ascii_case(expected_sha) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!(
            "engine SHA256 mismatch (expected {expected_sha}, got {got}) — refusing to install"
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&tmp) {
            let mut perm = meta.permissions();
            perm.set_mode(0o755);
            let _ = std::fs::set_permissions(&tmp, perm);
        }
    }

    // 运行核验(防损坏 / 错平台);失败不安装
    let mut check = Command::new(&tmp);
    check.arg("--version");
    no_window(&mut check);
    let runs = check.output().map(|o| o.status.success()).unwrap_or(false);
    if !runs {
        let _ = std::fs::remove_file(&tmp);
        return Err(
            "downloaded engine failed to run (--version) — refusing to install".to_string(),
        );
    }

    // 两阶段换装(H1):旧引擎先挪 aside(Windows 在用文件也成功 —— daemon 跑着旧引擎
    // 也能装,重启 daemon 后用新件),任一步失败自动还原,绝不半装。
    if let Err(e) = swap_in_staged(parent, &[(ENGINE_BIN.to_string(), tmp.clone())]) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    // 装好后引擎已落稳定路径 → status(app) 经 resolve_engine 命中并钉稳定 hook。
    status(app)
}

// ─────────────────────── R3 Phase 1:Settings(引擎模式 + 姿态)───────────────────────
//
// GUI 控制平面经 vigil-hub CLI 读写落盘配置(engine.json / posture.json),与 Deploy Guardian
// 同款 shell-out 纪律(进程隔离;避免把 ort feature 拉进 GUI)。写入值在 Rust 侧 whitelist 校验
// 后才进 argv(feedback「external contract argv」),并复用 `resolve_engine` 定位引擎二进制。

/// GUI 设置快照(引擎模式 + 姿态 + 引擎二进制是否就位)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsStatus {
    /// 当前引擎模式:`hardfp` | `ml` | `auto`(引擎缺失/未配置时为默认 `hardfp`)。
    pub engine_mode: String,
    /// 当前安全姿态:`low` | `medium` | `high`(引擎缺失/未配置时为默认 `low`)。
    pub posture: String,
    /// vigil-hub 引擎二进制是否就位(false → 设置只读,前端提示先部署/下载引擎)。
    pub engine_present: bool,
}

/// 跑 `<engine> <args...>` 捕获 trimmed stdout(非零退出 → Err 带 stderr 摘要)。
fn run_cli_capture(engine: &Path, args: &[&str]) -> Result<String, String> {
    let mut cmd = Command::new(engine);
    cmd.args(args);
    // 子进程输出只供 GUI 机器解析(如 `model status` 的 "installed" 行判定)—— 钉英文,
    // 否则 CLI 按系统语言输出中文时行匹配恒 false(locale 事故面)。用户可见文案由前端 i18n 渲染。
    cmd.env("VIGIL_LANG", "en");
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

/// 只读:当前设置(引擎模式 + 姿态)。引擎二进制缺失 → 返回默认值 + `engine_present=false`
/// (不报错,让前端优雅提示先部署引擎)。单条 CLI 失败不连坐另一条(各自回落默认)。
pub fn settings_get(app: &AppHandle) -> Result<SettingsStatus, String> {
    let Some(engine) = resolve_engine(app) else {
        return Ok(SettingsStatus {
            engine_mode: "hardfp".to_string(),
            posture: "low".to_string(),
            engine_present: false,
        });
    };
    let engine_mode =
        run_cli_capture(&engine, &["engine", "show"]).unwrap_or_else(|_| "hardfp".to_string());
    let posture =
        run_cli_capture(&engine, &["posture", "show"]).unwrap_or_else(|_| "low".to_string());
    Ok(SettingsStatus {
        engine_mode,
        posture,
        engine_present: true,
    })
}

/// 写:切换安全姿态(low|medium|high)。值在 Rust 侧 whitelist 校验后才进 argv。
/// **即时生效**:hook 每次工具调用经 `posture::load_posture` 消费该配置。
pub fn set_posture(app: &AppHandle, profile: &str) -> Result<SettingsStatus, String> {
    if !matches!(profile, "low" | "medium" | "high") {
        return Err(format!(
            "invalid posture: {profile} (expected low|medium|high)"
        ));
    }
    let engine = resolve_engine(app).ok_or_else(|| ENGINE_NOT_FOUND.to_string())?;
    run_cli_capture(&engine, &["posture", "set", profile])?;
    settings_get(app)
}

/// 写:切换引擎模式(hardfp|ml|auto)。值 whitelist 校验后才进 argv。落盘持久化用户选择;
/// `ml`/`auto` 实际跑 ML 需 ML 引擎变体(`--features ort`)+ 常驻 daemon(ADR 0024,见下)。
pub fn set_engine_mode(app: &AppHandle, mode: &str) -> Result<SettingsStatus, String> {
    if !matches!(mode, "hardfp" | "ml" | "auto") {
        return Err(format!(
            "invalid engine mode: {mode} (expected hardfp|ml|auto)"
        ));
    }
    let engine = resolve_engine(app).ok_or_else(|| ENGINE_NOT_FOUND.to_string())?;
    run_cli_capture(&engine, &["engine", "set", mode])?;
    settings_get(app)
}

// ── R3 Phase 2:常驻 daemon 生命周期 + ML 模型安装(ADR 0024)──────────────────────────────
// GUI 仍走 shell-out 纪律(不把 ort 拉进 GUI):daemon/模型重活在 `vigil-hub` CLI,GUI 只调度 +
// 解析。daemon **独立于 GUI 生命周期**(detached spawn —— 它要为 agent 的 hook 主路径服务,不随
// GUI 关闭而停);stop 经 `vigil-hub daemon stop`(CLI 侧 R1+token 验存活后杀 pid,防 pid 重用误杀)。

/// daemon 运行态(GUI 守护卡)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    /// daemon 是否在运行(`daemon status --json` 的 `running`)。
    pub running: bool,
    /// start 已发出、模型暖载中(daemon.json 尚未就绪;`status --json` reason=warming)。
    /// 暖载最长约 45s —— 前端据此显示「启动中」而非误导性的「未运行」。
    pub warming: bool,
    /// 隐私 PII 模型是否已暖载(model-less daemon = false)。
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

/// 行级解析:`out` 中以 `prefix` 起头的行是否含 `installed` 且非 `not installed`。
fn status_line_installed(out: &str, prefix: &str) -> bool {
    out.lines()
        .find(|l| l.trim_start().starts_with(prefix))
        .map(|l| l.contains("installed") && !l.contains("not installed"))
        .unwrap_or(false)
}

/// 只读:daemon 运行态。走 `daemon status --json` 稳定 schema(字段只增不删)—— 此前解析
/// 英文人类行 `daemon: running (`,CLI 按系统语言输出中文时会恒判未运行(locale 事故面)。
/// 引擎缺失 → `running=false` + `engine_present=false`(不报错,前端优雅提示)。
pub fn daemon_status(app: &AppHandle) -> Result<DaemonStatus, String> {
    let Some(engine) = resolve_engine(app) else {
        return Ok(DaemonStatus {
            running: false,
            warming: false,
            pii_loaded: false,
            engine_present: false,
        });
    };
    let out = run_cli_capture(&engine, &["daemon", "status", "--json"]).unwrap_or_default();
    let v: serde_json::Value = serde_json::from_str(&out).unwrap_or_default();
    let running = v["running"] == true;
    Ok(DaemonStatus {
        running,
        warming: !running && v["reason"] == "warming",
        pii_loaded: running && v["pii_loaded"] == true,
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
    let _install = acquire_install_lock()?;
    let engine = resolve_engine(app).ok_or_else(|| ENGINE_NOT_FOUND.to_string())?;
    run_cli_capture(&engine, &["model", "install"])?;
    model_status(app)
}

// ─────────────── 浏览器防线卡(扩展体系 Phase 2「策略+观测」)───────────────

/// 浏览器防线状态(Protection Overview 卡):native host 注册态 + 最近 24h 守门统计。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserGuardStatus {
    /// Chrome native messaging host manifest 是否在位(Chrome 能否发现 host)。
    pub manifest_present: bool,
    /// Windows:HKCU 注册表键是否在位(`None` = 非 Windows,不适用)。
    pub registry_present: Option<bool>,
    /// 综合注册态:manifest 在位 且(注册表不适用或在位)。false → 卡片提示去扩展
    /// options 页复制 `vigil-native-host install` 命令。
    pub registered: bool,
    /// 最近 24h 浏览器检查总数(paste/input/submit)。
    pub checks_24h: u64,
    /// 其中拦截(block)。
    pub blocked_24h: u64,
    /// 其中脱敏放行(redact)。
    pub redacted_24h: u64,
}

/// 只读:浏览器防线状态。注册态直调 `vigil_native_host::install::status`(复用 host 自身的
/// manifest 路径推导 + Windows 注册表检查,不 shell、不解析人类文本 —— 无 locale 事故面);
/// 24h 统计走 ledger 纯读([`vigil_audit::Ledger::browser_guard_counts`])。
/// 注册态查询失败(home 不可得等)按未注册处理:状态卡宁可保守提示,不报错阻塞整页。
pub fn browser_guard(ledger: &vigil_audit::Ledger) -> Result<BrowserGuardStatus, String> {
    let (manifest_present, registry_present) = match vigil_native_host::install::status(None) {
        Ok(s) => (s.manifest_exists, s.registry_present),
        Err(_) => (false, None),
    };
    let registered = manifest_present && registry_present.unwrap_or(true);
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
        .saturating_sub(24 * 3600);
    let c = ledger
        .browser_guard_counts(since)
        .map_err(|e| e.to_string())?;
    Ok(BrowserGuardStatus {
        manifest_present,
        registry_present,
        registered,
        checks_24h: c.checks,
        blocked_24h: c.blocked,
        redacted_24h: c.redacted,
    })
}

// ── R3 Phase 2.5:GUI 自动安装 ML 引擎变体(端到端 ML「最后一公里」)──────────────────────────
//
// 出厂 GUI 不捆引擎,常态下用户经 `download_engine` 装的是**非 ort** vigil-hub → `model status`
// 报 unsupported、`--engine ml|auto` fail-closed 回落硬指纹 → ML 形同未发布。本步把已发布的
// **ML 引擎变体** archive(`--features ort` 的 vigil-hub + 同目录 ONNX Runtime 库)安全装到
// **稳定启动器目录** → `resolve_engine` 经 dylib 信号优先命中 ort 二进制 → daemon 可暖载、
// `model install/status` 可用、hook 主路径经 daemon 真跑 ML。
//
// 格式现实(经真发布 artifact 核实,勿臆断):公开 v0.4.1 资产 = **Windows `.zip`** / Unix
// `.tar.gz`,且 Windows 包带**多个** ORT 库(`onnxruntime.dll` + `onnxruntime_providers_shared.dll`)。
// 故解包器按**魔数嗅探** zip / tar.gz,并提取**全部** `onnxruntime*` 库(非单个)。
//
// 供应链安全(与 `download_engine` 同纪律):仅 HTTPS;**整包 SHA-pin** fail-closed(无 pinned SHA
// → 拒绝下载未校验产物);解包按 **basename 扁平**(丢弃 archive 内目录前缀 → 防 path-traversal,
// 纵深防御,即便包已被 SHA 锁);装前 `--version` 运行核验。

/// ML 引擎变体下载源(archive URL + 可选 pinned sha256)。
struct MlEngineSource {
    url: String,
    sha256: Option<String>,
}

/// 当前平台主 ONNX Runtime 库 basename(release.yml `dest` / 真发布资产的主库名;也是
/// [`stable_has_ml_dylib`] 的探测名 —— 两套 release 管线均保证此精确名就位)。
fn ort_dylib_basename() -> &'static str {
    if cfg!(windows) {
        "onnxruntime.dll"
    } else if cfg!(target_os = "macos") {
        "libonnxruntime.dylib"
    } else {
        "libonnxruntime.so"
    }
}

/// 是否为 ONNX Runtime 运行时库(跨平台 + 多文件:`onnxruntime.dll` /
/// `onnxruntime_providers_shared.dll` / `libonnxruntime.so[.x]` / `libonnxruntime.*.dylib`)。
/// ML 包可能捆多个 ORT 库 → 全取,勿只取主库。
fn is_ort_lib(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("onnxruntime") || lower.starts_with("libonnxruntime")
}

// ── 签名引擎清单(SHA 信任锚)─────────────────────────────────────────────────────────────
// 引擎自动下载的 SHA 不能来自下载源本身(攻击者控源即同时控 .sha256 sidecar → SHA-pin 失效)。改由
// 发版期生成、**minisign 签名**的 `engine-manifest.json`(列 per-engine × per-platform 的 {url,sha256})
// 提供:GUI 取 manifest + `.minisig` → 用内嵌 pubkey(复用 Tauri 更新器同一把 key 5B4B247DA77CEAC5)
// 验签 → 据此 SHA-pin。签名背书同时解决命名分叉(URL 由 manifest 给,GUI 不硬编码)。env 覆盖保留
// 作测试 / 私有镜像旁路。

/// 复用 Tauri 更新器的 minisign 公钥(key 5B4B247DA77CEAC5;见 tauri.conf.json::plugins.updater.pubkey
/// base64 解码后的第二行)。引擎清单与桌面更新件由同一发布密钥签名 → 单一信任锚。
const ENGINE_MANIFEST_PUBKEY: &str = "RWTF6nynfSRLW//J/K4inS8RdovCJ+MhwtfG5xUJ4sJK/silUB9E8D3c";

/// 引擎清单一个 artifact 条目。
#[derive(Debug, Clone, Deserialize)]
struct EngineArtifact {
    url: String,
    sha256: String,
}

/// 签名引擎清单:`artifacts["vigil-cli-ml"]["windows-x64"]` → {url, sha256}。平台键对齐 `engine_platform()`。
#[derive(Debug, Clone, Deserialize)]
struct EngineManifest {
    artifacts: std::collections::HashMap<String, std::collections::HashMap<String, EngineArtifact>>,
}

/// 签名引擎清单 URL(`VIGIL_ENGINE_MANIFEST_URL` 覆盖,否则取当前版本的 **GitHub release 资产**)。
/// `.minisig` 在 `<url>.minisig`。release.yml 的 `engine-manifest` job 把签名清单上传到此 tag 的 release
/// (可靠;vigils.ai 镜像对 /releases/engine/ 是 SPA catch-all 返 HTML,不可用)。host 即便错 / 被 MITM,
/// 验签失败即 fail-closed → 不损安全。
fn engine_manifest_url() -> String {
    if let Ok(url) = std::env::var("VIGIL_ENGINE_MANIFEST_URL") {
        return url;
    }
    let ver = env!("CARGO_PKG_VERSION");
    format!("https://github.com/duncatzat/vigils/releases/download/v{ver}/engine-manifest.json")
}

/// GET 文本(小文件:清单 + 签名)。
fn fetch_text(url: &str) -> Result<String, String> {
    ureq::get(url)
        .timeout(std::time::Duration::from_secs(30))
        .call()
        .map_err(|e| format!("fetch {url} failed: {e}"))?
        .into_string()
        .map_err(|e| format!("read {url} body failed: {e}"))
}

/// 用 minisign 公钥验签 `data`。`wrapped_sig_b64` = Tauri 风格的 base64(标准 minisign .minisig 全文)。
/// base64 / 格式 / 验签任一失败 → Err,绝不放行未验证内容。
fn verify_minisign(data: &[u8], wrapped_sig_b64: &str, pubkey_b64: &str) -> Result<(), String> {
    use base64::Engine;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(wrapped_sig_b64.trim())
        .map_err(|e| format!("manifest signature base64 decode failed: {e}"))?;
    let sig_text =
        String::from_utf8(sig_bytes).map_err(|e| format!("manifest signature not UTF-8: {e}"))?;
    let pk = minisign_verify::PublicKey::from_base64(pubkey_b64)
        .map_err(|e| format!("bad minisign pubkey: {e}"))?;
    let sig = minisign_verify::Signature::decode(&sig_text)
        .map_err(|e| format!("bad manifest signature: {e}"))?;
    pk.verify(data, &sig, false)
        .map_err(|e| format!("manifest signature verification failed: {e}"))
}

/// 解析引擎清单 JSON。
fn parse_engine_manifest(bytes: &[u8]) -> Result<EngineManifest, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("parse engine manifest failed: {e}"))
}

/// 取并验签引擎清单(GET manifest + `.minisig` → 内嵌 pubkey 验签 → 解析)。
fn fetch_engine_manifest() -> Result<EngineManifest, String> {
    let url = engine_manifest_url();
    if !url.starts_with("https://") {
        return Err(format!("refusing non-HTTPS manifest URL: {url}"));
    }
    let manifest = fetch_text(&url)?;
    let sig = fetch_text(&format!("{url}.minisig"))?;
    verify_minisign(manifest.as_bytes(), &sig, ENGINE_MANIFEST_PUBKEY)?;
    parse_engine_manifest(manifest.as_bytes())
}

/// env 覆盖(测试 / 私有镜像):`VIGIL_ML_ENGINE_URL`(+可选 `_SHA256`)→ 直用,跳过清单。
fn ml_engine_override() -> Option<MlEngineSource> {
    let url = std::env::var("VIGIL_ML_ENGINE_URL").ok()?;
    Some(MlEngineSource {
        url,
        sha256: std::env::var("VIGIL_ML_ENGINE_SHA256")
            .ok()
            .filter(|s| !s.is_empty()),
    })
}

/// 解析当前平台 ML 引擎变体下载源:env 覆盖优先,否则取**签名清单** → `vigil-cli-ml` × `engine_platform()`。
/// 清单提供 url + sha256(信任锚)→ install 据此 SHA-pin。
fn resolve_ml_engine_source() -> Result<MlEngineSource, String> {
    if let Some(src) = ml_engine_override() {
        return Ok(src);
    }
    let plat = engine_platform()?;
    let manifest = fetch_engine_manifest()?;
    let art = manifest
        .artifacts
        .get("vigil-cli-ml")
        .and_then(|m| m.get(plat))
        .ok_or_else(|| format!("engine manifest has no vigil-cli-ml entry for {plat}"))?;
    Ok(MlEngineSource {
        url: art.url.clone(),
        sha256: Some(art.sha256.clone()),
    })
}

/// 把一个解出的成员按 basename 落到 `staging`(引擎二进制设 +x)。仅写文件,不决定取舍。
fn place_ml_member(staging: &Path, name: &str, data: &[u8]) -> Result<(), String> {
    let out = staging.join(name);
    std::fs::write(&out, data).map_err(|e| format!("write {name} failed: {e}"))?;
    #[cfg(unix)]
    if name == ENGINE_BIN {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&out) {
            let mut perm = meta.permissions();
            perm.set_mode(0o755);
            let _ = std::fs::set_permissions(&out, perm);
        }
    }
    Ok(())
}

/// zip 成员遍历(`PK\x03\x04`):basename 扁平,逐成员交 `place`。
fn extract_zip_members<F: FnMut(&str, &[u8]) -> Result<(), String>>(
    archive: &Path,
    place: &mut F,
) -> Result<(), String> {
    use std::io::Read;
    let f = std::fs::File::open(archive).map_err(|e| format!("open ML zip failed: {e}"))?;
    let mut zip = zip::ZipArchive::new(f).map_err(|e| format!("read ML zip failed: {e}"))?;
    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|e| format!("read ML zip entry failed: {e}"))?;
        if !entry.is_file() {
            continue;
        }
        // 只用 basename,扁平丢弃任何目录前缀(防 traversal)。
        let name = match Path::new(entry.name()).file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let mut buf = Vec::new();
        entry
            .read_to_end(&mut buf)
            .map_err(|e| format!("extract {name} failed: {e}"))?;
        place(&name, &buf)?;
    }
    Ok(())
}

/// gzip+tar 成员遍历(`\x1f\x8b`):basename 扁平,逐成员交 `place`。
fn extract_targz_members<F: FnMut(&str, &[u8]) -> Result<(), String>>(
    archive: &Path,
    place: &mut F,
) -> Result<(), String> {
    use std::io::Read;
    let f = std::fs::File::open(archive).map_err(|e| format!("open ML archive failed: {e}"))?;
    let gz = flate2::read::GzDecoder::new(f);
    let mut tar = tar::Archive::new(gz);
    let entries = tar
        .entries()
        .map_err(|e| format!("read ML archive entries failed: {e}"))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| format!("read ML archive entry failed: {e}"))?;
        let name = {
            let path = entry
                .path()
                .map_err(|e| format!("bad entry path in ML archive: {e}"))?;
            match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            }
        };
        let mut buf = Vec::new();
        entry
            .read_to_end(&mut buf)
            .map_err(|e| format!("extract {name} failed: {e}"))?;
        place(&name, &buf)?;
    }
    Ok(())
}

/// 解包 ML archive 到 `staging`:按魔数嗅探 zip / tar.gz,仅提取 `vigil-hub[.exe]` + **全部**
/// `onnxruntime*` 库(basename 扁平,防 traversal),其余(README 等)忽略。引擎或 ORT 库缺失 →
/// Err(拒装半包)。返回落地的引擎二进制路径。调用方保证 `archive` 已 SHA-pin 校验。
fn extract_ml_bundle(archive: &Path, staging: &Path) -> Result<PathBuf, String> {
    let mut head = [0u8; 4];
    {
        use std::io::Read;
        let mut f =
            std::fs::File::open(archive).map_err(|e| format!("open ML archive failed: {e}"))?;
        // 不足 4 字节也无妨:余位为 0,不匹配任何魔数 → 落到下方 Err。
        let _ = f
            .read(&mut head)
            .map_err(|e| format!("read ML archive header failed: {e}"))?;
    }

    let mut engine_found = false;
    let mut ort_found = false;
    let mut place = |name: &str, data: &[u8]| -> Result<(), String> {
        if name == ENGINE_BIN {
            place_ml_member(staging, name, data)?;
            engine_found = true;
        } else if is_ort_lib(name) {
            place_ml_member(staging, name, data)?;
            ort_found = true;
        }
        Ok(())
    };

    if head.starts_with(&[0x50, 0x4b, 0x03, 0x04]) {
        extract_zip_members(archive, &mut place)?;
    } else if head.starts_with(&[0x1f, 0x8b]) {
        extract_targz_members(archive, &mut place)?;
    } else {
        return Err(format!(
            "unrecognized ML archive format (expected .zip or .tar.gz): {}",
            archive.display()
        ));
    }

    if !engine_found {
        return Err(format!(
            "ML archive did not contain {ENGINE_BIN} — refusing to install a partial bundle"
        ));
    }
    if !ort_found {
        return Err(
            "ML archive did not contain an ONNX Runtime library — refusing to install an unusable ML engine"
                .to_string(),
        );
    }
    Ok(staging.join(ENGINE_BIN))
}

/// AppHandle-free 安装核心([`download_ml_engine`] 与对真发布 artifact 的集成测试共用,见
/// [[feedback_production_logic_testable]]):解析源 → 下载 → 整包 SHA-pin → 嗅探解包 → 运行核验 →
/// 把引擎 + 全部 ORT 库移入 `bin_dir`。全程 fail-closed,任何错误清 staging 后 Err。
fn install_ml_engine_into(bin_dir: &Path) -> Result<(), String> {
    let _install = acquire_install_lock()?;
    let src = resolve_ml_engine_source()?;
    if !src.url.starts_with("https://") {
        return Err(format!("refusing non-HTTPS ML engine URL: {}", src.url));
    }
    let expected_sha = src.sha256.as_deref().ok_or_else(|| {
        "ML engine auto-download is not configured with a pinned SHA256 (set VIGIL_ML_ENGINE_SHA256, \
         or this build predates the signed release manifest) — refusing to fetch an unverified bundle"
            .to_string()
    })?;

    std::fs::create_dir_all(bin_dir)
        .map_err(|e| format!("failed to create {}: {e}", bin_dir.display()))?;

    // 隔离 staging 子目录:下载 + 解包 + 核验都在此,全过后才把成员移入 bin_dir(避免半成品被探测命中)。
    // 入口先清扫历史残留(中途死亡的 staging + 上次换装删不掉的 *.vigil-old)。
    sweep_stale_installs(bin_dir);
    let staging = bin_dir.join(".ml-staging");
    std::fs::create_dir_all(&staging)
        .map_err(|e| format!("failed to create ML staging dir: {e}"))?;

    let archive = staging.join("ml-bundle.download");
    if let Err(e) = download_to_file(&src.url, &archive) {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(e);
    }

    // 整包 SHA-pin fail-closed
    let got = match sha256_file(&archive) {
        Ok(h) => h,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(e);
        }
    };
    if !got.eq_ignore_ascii_case(expected_sha) {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(format!(
            "ML engine SHA256 mismatch (expected {expected_sha}, got {got}) — refusing to install"
        ));
    }

    let staged_engine = match extract_ml_bundle(&archive, &staging) {
        Ok(p) => p,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(e);
        }
    };

    // 运行核验(防损坏 / 错平台 / 错架构);`--version` 不加载 ORT,足以证明二进制可执行。
    let mut check = Command::new(&staged_engine);
    check.arg("--version");
    no_window(&mut check);
    let runs = check.output().map(|o| o.status.success()).unwrap_or(false);
    if !runs {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(
            "downloaded ML engine failed to run (--version) — refusing to install".to_string(),
        );
    }

    // 收集 staged 成员(引擎 + 全部 ORT 库,按谓词筛,跳过下载的压缩包)→ 两阶段换装(H1):
    // 先挪旧件 aside 再进位,任一步失败**全量还原** —— 绝不留「新引擎 + 旧 dylib」混装
    // (read_dir 顺序任意,逐文件直换的中途失败会产生这种状态)。staging 是 bin_dir 子目录 →
    // 同卷 rename;Windows 下 daemon 正跑旧件也能完成换装(见 [`swap_in_staged`])。
    let mut staged: Vec<(String, PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(&staging).map_err(|e| format!("read ML staging failed: {e}"))? {
        let from = entry
            .map_err(|e| format!("read ML staging entry failed: {e}"))?
            .path();
        let fname = match from.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if fname != ENGINE_BIN && !is_ort_lib(&fname) {
            continue;
        }
        staged.push((fname, from));
    }
    if let Err(e) = swap_in_staged(bin_dir, &staged) {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(e);
    }
    let _ = std::fs::remove_dir_all(&staging);
    Ok(())
}

/// 写:下载并安装 **ML 引擎变体** 到稳定启动器目录(见 [`install_ml_engine_into`]),装好后返回 ML
/// 模型缓存态(此时 `ml_supported` 应翻 true)。缺 pinned SHA → 拒绝(绝不安装未校验产物)。
pub fn download_ml_engine(app: &AppHandle) -> Result<ModelStatus, String> {
    let stable = stable_launcher_path()
        .ok_or_else(|| "could not resolve a stable install location".to_string())?;
    let bin_dir = stable
        .parent()
        .ok_or_else(|| "invalid stable launcher path".to_string())?;
    install_ml_engine_into(bin_dir)?;
    // 引擎已落稳定目录 + dylib 信号 → resolve_engine 优先命中 ort → model_status 报 ml_supported=true。
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
    fn guardian_status_deserializes_cli_json_contract() {
        // 必须能反序列化 CLI `setup --json` 的真实 shape(否则 GUI 解析会炸)。
        // 含 v0.6.2+ 新增字段:status="pending_trust"(codex trust 诚实化)与 warnings
        // (未知字段,serde 默认忽略 —— 新旧 CLI 输出都要能吃)。
        let json = r#"{"protected":true,"ledger":"/x/l.sqlite3","hook_exe":"/stable/vigil-hub",
            "hook_command":"...","agents":[
              {"agent":"claude","display_name":"Claude Code","detected":true,"status":"active"},
              {"agent":"codex","display_name":"Codex CLI","detected":true,"status":"pending_trust",
               "warnings":["codex has not trusted the Vigil hook(s) ..."]},
              {"agent":"gemini","display_name":"Gemini CLI","detected":false,"status":"not_installed"}]}"#;
        let s: GuardianStatus = serde_json::from_str(json).expect("parse CLI json contract");
        assert!(s.protected);
        assert_eq!(s.agents.len(), 3);
        assert_eq!(s.agents[0].status, "active");
        assert_eq!(s.agents[1].status, "pending_trust");
        assert!(!s.agents[2].detected);
    }

    #[test]
    fn engine_platform_is_known_on_test_host() {
        // CI/dev hosts(win-x64 / mac-arm64 / linux-x64)均受支持。
        assert!(engine_platform().is_ok());
    }

    #[test]
    fn engine_source_default_is_https_and_version_pinned() {
        // env 未覆盖时,默认源 = HTTPS + 版本号 + 平台,且不带 baked SHA(发版期注入)。
        if std::env::var("VIGIL_ENGINE_URL").is_err() {
            let src = engine_source().expect("supported platform");
            assert!(
                src.url.starts_with("https://"),
                "engine URL must be HTTPS: {}",
                src.url
            );
            assert!(
                src.url.contains(env!("CARGO_PKG_VERSION")),
                "engine URL must be version-pinned: {}",
                src.url
            );
            assert!(
                src.sha256.is_none(),
                "default build ships no baked SHA (release-time inject)"
            );
        }
    }

    #[test]
    fn engine_manifest_url_default_https_version_pinned() {
        if std::env::var("VIGIL_ENGINE_MANIFEST_URL").is_err() {
            let url = engine_manifest_url();
            assert!(
                url.starts_with("https://"),
                "manifest URL must be HTTPS: {url}"
            );
            assert!(
                url.contains(env!("CARGO_PKG_VERSION")),
                "manifest URL must be version-pinned: {url}"
            );
            assert!(url.ends_with("engine-manifest.json"), "manifest URL: {url}");
        }
    }

    #[test]
    fn parse_engine_manifest_extracts_platform_artifact() {
        let json = br#"{"schema":1,"version":"0.4.1","artifacts":{
            "vigil-cli-ml":{
                "windows-x64":{"url":"https://x/y/vigils-cli-ml-windows-x64.zip","sha256":"abc123"},
                "linux-x64":{"url":"https://x/y/vigils-cli-ml-linux-x64.tar.gz","sha256":"def456"}
            }}}"#;
        let m = parse_engine_manifest(json).expect("parse ok");
        let art = m
            .artifacts
            .get("vigil-cli-ml")
            .and_then(|p| p.get("windows-x64"))
            .expect("win entry");
        assert_eq!(art.sha256, "abc123");
        assert!(art.url.ends_with("windows-x64.zip"));
        // 未知平台 → None(resolve 会 fail-closed)。
        assert!(m
            .artifacts
            .get("vigil-cli-ml")
            .and_then(|p| p.get("solaris-sparc"))
            .is_none());
    }

    #[test]
    fn parse_engine_manifest_rejects_garbage() {
        assert!(parse_engine_manifest(b"not json at all").is_err());
    }

    #[test]
    fn verify_minisign_accepts_valid_rejects_tampered() {
        use base64::Engine as _;
        use blake2::{Blake2b512, Digest};
        use ed25519_dalek::{Signer, SigningKey};

        let b64 = base64::engine::general_purpose::STANDARD;
        let sk = SigningKey::from_bytes(&[7u8; 32]); // 固定种子 → 确定性
        let keyid = [1u8, 2, 3, 4, 5, 6, 7, 8];

        // minisign pubkey blob = "Ed" + keyid[8] + ed25519_pk[32]
        let mut pkblob = Vec::new();
        pkblob.extend_from_slice(b"Ed");
        pkblob.extend_from_slice(&keyid);
        pkblob.extend_from_slice(&sk.verifying_key().to_bytes());
        let pubkey_b64 = b64.encode(&pkblob);

        let data = br#"{"schema":1,"artifacts":{}}"#;
        // 预哈希 'ED' = Ed25519 over Blake2b-512(data)(Tauri/minisign prehashed 模式)
        let prehash = Blake2b512::digest(data);
        let main_sig = sk.sign(prehash.as_slice());
        let mut sigblob = Vec::new();
        sigblob.extend_from_slice(b"ED");
        sigblob.extend_from_slice(&keyid);
        sigblob.extend_from_slice(&main_sig.to_bytes());
        // 全局签名 = Ed25519 over (sig_bytes || trusted_comment_body)
        let tc_body = "test";
        let mut global_msg = main_sig.to_bytes().to_vec();
        global_msg.extend_from_slice(tc_body.as_bytes());
        let global_sig = sk.sign(&global_msg);

        let minisig_text = format!(
            "untrusted comment: test\n{}\ntrusted comment: {}\n{}\n",
            b64.encode(&sigblob),
            tc_body,
            b64.encode(global_sig.to_bytes())
        );
        let wrapped = b64.encode(minisig_text.as_bytes());

        // 正:有效签名通过
        verify_minisign(data, &wrapped, &pubkey_b64).expect("valid signature must verify");
        // 负:数据被篡改 → 拒
        assert!(verify_minisign(b"tampered-manifest", &wrapped, &pubkey_b64).is_err());
        // 负:垃圾签名 → 拒
        assert!(verify_minisign(data, "!!!not-base64!!!", &pubkey_b64).is_err());
    }

    /// 测试帮手:把 (path, bytes) 列表打成 gzip tar 到 `dest`。
    fn write_test_targz(dest: &Path, files: &[(&str, &[u8])]) {
        let f = std::fs::File::create(dest).expect("create archive");
        let enc = flate2::write::GzEncoder::new(f, flate2::Compression::fast());
        let mut b = tar::Builder::new(enc);
        for (path, data) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            b.append_data(&mut h, *path, *data).expect("append entry");
        }
        let enc = b.into_inner().expect("finish tar");
        enc.finish().expect("finish gzip");
    }

    /// 测试帮手:把 (path, bytes) 列表打成 deflate zip 到 `dest`(复刻真公开 Windows 资产格式)。
    fn write_test_zip(dest: &Path, files: &[(&str, &[u8])]) {
        use std::io::Write;
        let f = std::fs::File::create(dest).expect("create zip");
        let mut z = zip::ZipWriter::new(f);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (path, data) in files {
            z.start_file(*path, opts).expect("start zip entry");
            z.write_all(data).expect("write zip entry");
        }
        z.finish().expect("finish zip");
    }

    #[test]
    fn extract_ml_bundle_targz_takes_binary_and_libs_flattening_paths() {
        let dir = tempfile::tempdir().expect("tempdir");
        let archive = dir.path().join("b.tar.gz");
        let dylib = ort_dylib_basename();
        // 带目录前缀 + 一个无关 README → 提取应扁平化、只取 bin + ORT 库。
        let bin_entry = format!("vigil-cli-ml-x/{ENGINE_BIN}");
        let dylib_entry = format!("vigil-cli-ml-x/{dylib}");
        write_test_targz(
            &archive,
            &[
                (bin_entry.as_str(), b"#!fake-ort-binary"),
                (dylib_entry.as_str(), b"fake-dylib-bytes"),
                ("vigil-cli-ml-x/README-ML.txt", b"ignore me"),
            ],
        );
        let staging = dir.path().join("stage");
        std::fs::create_dir_all(&staging).expect("mk staging");
        let engine = extract_ml_bundle(&archive, &staging).expect("extract ok");

        assert_eq!(engine, staging.join(ENGINE_BIN));
        assert!(staging.join(ENGINE_BIN).is_file(), "binary extracted flat");
        assert!(staging.join(dylib).is_file(), "ORT lib extracted flat");
        // 只取已知文件:README 不提取;目录前缀被丢弃。
        assert!(
            !staging.join("README-ML.txt").exists(),
            "README must be skipped"
        );
        assert!(
            !staging.join("vigil-cli-ml-x").exists(),
            "dir prefix must be flattened away"
        );
    }

    #[test]
    fn extract_ml_bundle_zip_takes_binary_and_all_ort_libs() {
        // 复刻真公开 Windows zip:扁平布局 + 多 ORT 库(含 providers_shared)。
        let dir = tempfile::tempdir().expect("tempdir");
        let archive = dir.path().join("b.zip");
        let dylib = ort_dylib_basename();
        let extra_ort = if cfg!(windows) {
            "onnxruntime_providers_shared.dll"
        } else {
            "libonnxruntime.so.1.24.4"
        };
        write_test_zip(
            &archive,
            &[
                (ENGINE_BIN, b"#!fake-ort-binary"),
                (dylib, b"primary-ort"),
                (extra_ort, b"extra-ort"),
                ("README-ML.txt", b"ignore me"),
            ],
        );
        let staging = dir.path().join("stage");
        std::fs::create_dir_all(&staging).expect("mk staging");
        let engine = extract_ml_bundle(&archive, &staging).expect("extract zip ok");

        assert_eq!(engine, staging.join(ENGINE_BIN));
        assert!(staging.join(ENGINE_BIN).is_file(), "binary from zip");
        assert!(staging.join(dylib).is_file(), "primary ORT lib from zip");
        assert!(
            staging.join(extra_ort).is_file(),
            "extra ORT lib (providers_shared) must also be extracted"
        );
        assert!(!staging.join("README-ML.txt").exists(), "README skipped");
    }

    #[test]
    fn extract_ml_bundle_rejects_archive_missing_binary() {
        let dir = tempfile::tempdir().expect("tempdir");
        let archive = dir.path().join("b.tar.gz");
        let dylib_entry = format!("x/{}", ort_dylib_basename());
        write_test_targz(&archive, &[(dylib_entry.as_str(), b"only-ort-lib")]);
        let staging = dir.path().join("stage");
        std::fs::create_dir_all(&staging).expect("mk staging");
        let err = extract_ml_bundle(&archive, &staging).expect_err("must reject missing binary");
        assert!(
            err.contains(ENGINE_BIN),
            "error names the missing binary: {err}"
        );
    }

    #[test]
    fn extract_ml_bundle_rejects_archive_missing_ort_lib() {
        let dir = tempfile::tempdir().expect("tempdir");
        let archive = dir.path().join("b.tar.gz");
        let bin_entry = format!("x/{ENGINE_BIN}");
        write_test_targz(&archive, &[(bin_entry.as_str(), b"only-binary")]);
        let staging = dir.path().join("stage");
        std::fs::create_dir_all(&staging).expect("mk staging");
        let err = extract_ml_bundle(&archive, &staging).expect_err("must reject missing ORT lib");
        assert!(
            err.contains("ONNX Runtime"),
            "error should mention the missing ONNX Runtime lib: {err}"
        );
    }

    #[test]
    fn stable_has_ml_dylib_detects_colocated_dylib() {
        let dir = tempfile::tempdir().expect("tempdir");
        let engine = dir.path().join(ENGINE_BIN);
        std::fs::write(&engine, b"bin").expect("write engine");
        // 无 dylib → false
        assert!(!stable_has_ml_dylib(&engine));
        // 同目录放 dylib → true
        std::fs::write(dir.path().join(ort_dylib_basename()), b"lib").expect("write dylib");
        assert!(stable_has_ml_dylib(&engine));
    }

    // ── H1/M3:两阶段换装 + 安装互斥 ──

    fn write_file(p: &Path, content: &[u8]) {
        std::fs::write(p, content).expect("write test file");
    }

    #[test]
    fn swap_in_staged_fresh_install_places_all_members() {
        let bin = tempfile::tempdir().expect("tempdir");
        let staging = bin.path().join(".ml-staging");
        std::fs::create_dir_all(&staging).expect("staging");
        write_file(&staging.join("a.bin"), b"new-a");
        write_file(&staging.join("b.bin"), b"new-b");
        let staged = vec![
            ("a.bin".to_string(), staging.join("a.bin")),
            ("b.bin".to_string(), staging.join("b.bin")),
        ];
        swap_in_staged(bin.path(), &staged).expect("fresh swap");
        assert_eq!(std::fs::read(bin.path().join("a.bin")).unwrap(), b"new-a");
        assert_eq!(std::fs::read(bin.path().join("b.bin")).unwrap(), b"new-b");
        assert!(
            !bin.path().join("a.bin.vigil-old").exists(),
            "fresh 装无 aside"
        );
    }

    #[test]
    fn swap_in_staged_replaces_existing_and_cleans_asides() {
        let bin = tempfile::tempdir().expect("tempdir");
        write_file(&bin.path().join("a.bin"), b"old-a");
        let staging = bin.path().join(".ml-staging");
        std::fs::create_dir_all(&staging).expect("staging");
        write_file(&staging.join("a.bin"), b"new-a");
        let staged = vec![("a.bin".to_string(), staging.join("a.bin"))];
        swap_in_staged(bin.path(), &staged).expect("replace swap");
        assert_eq!(std::fs::read(bin.path().join("a.bin")).unwrap(), b"new-a");
        assert!(
            !bin.path().join("a.bin.vigil-old").exists(),
            "换装成功后 aside 应被清掉"
        );
    }

    #[test]
    fn swap_in_staged_midway_failure_restores_bin_dir_exactly() {
        // 阶段 B 中途失败注入:第 2 成员 staged 源不存在 → rename 必败。断言 bin_dir **精确还原**:
        // 旧内容都在、无新件残留、无 aside 残留 —— 绝不留「新 a + 旧 b」混装(H1 核心)。
        let bin = tempfile::tempdir().expect("tempdir");
        write_file(&bin.path().join("a.bin"), b"old-a");
        write_file(&bin.path().join("b.bin"), b"old-b");
        let staging = bin.path().join(".ml-staging");
        std::fs::create_dir_all(&staging).expect("staging");
        write_file(&staging.join("a.bin"), b"new-a");
        let staged = vec![
            ("a.bin".to_string(), staging.join("a.bin")),
            ("b.bin".to_string(), staging.join("missing-b.bin")),
        ];
        let err = swap_in_staged(bin.path(), &staged).unwrap_err();
        assert!(err.contains("b.bin"), "错误应指认失败成员: {err}");
        assert_eq!(
            std::fs::read(bin.path().join("a.bin")).unwrap(),
            b"old-a",
            "旧 a 应还原"
        );
        assert_eq!(
            std::fs::read(bin.path().join("b.bin")).unwrap(),
            b"old-b",
            "旧 b 应未动"
        );
        assert!(
            !bin.path().join("a.bin.vigil-old").exists(),
            "无 aside 残留"
        );
        assert!(
            !bin.path().join("b.bin.vigil-old").exists(),
            "无 aside 残留"
        );
    }

    #[test]
    fn sweep_stale_installs_removes_staging_and_old_files() {
        let bin = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(bin.path().join(".ml-staging")).expect("mk staging");
        write_file(&bin.path().join("x.dll.vigil-old"), b"stale");
        write_file(&bin.path().join("keep.dll"), b"live");
        sweep_stale_installs(bin.path());
        assert!(!bin.path().join(".ml-staging").exists(), "staging 应清掉");
        assert!(
            !bin.path().join("x.dll.vigil-old").exists(),
            "aside 残留应清掉"
        );
        assert!(bin.path().join("keep.dll").exists(), "常规文件不动");
    }

    #[test]
    fn install_lock_rejects_concurrent_second_acquire() {
        // M3:同刻只允许一个安装;第二个立即得可读错误(非阻塞不排队)。释放后可再获取。
        let first = acquire_install_lock().expect("first acquire");
        let err = acquire_install_lock().expect_err("second must be rejected");
        assert!(err.contains("in progress"), "可读的进行中提示: {err}");
        drop(first);
        let reacquired = acquire_install_lock().expect("release 后可再获取");
        drop(reacquired);
    }

    /// 对**真发布 ML artifact** 的端到端验证([[feedback_test_published_artifact_before_promote]]):
    /// 装到临时目录 → 跑装好的 ort 引擎 `model status` → 必报 ML 支持。**不硬编码 URL**(避免版本漂移),
    /// 靠运行方设 `VIGIL_ML_ENGINE_URL` + `VIGIL_ML_ENGINE_SHA256` 喂真包;未设则跳过。默认 `#[ignore]`
    /// (含网络下载)。手动跑(示例,Win):
    ///   set VIGIL_ML_ENGINE_URL=…/v0.4.1/vigils-cli-ml-windows-x64.zip
    ///   set VIGIL_ML_ENGINE_SHA256=73dec08a…
    ///   cargo test -p vigil-desktop --features gui --lib -- --ignored install_real_ml_artifact
    #[test]
    #[ignore = "network + needs VIGIL_ML_ENGINE_URL/SHA256 set to a real ML artifact"]
    fn install_real_ml_artifact_makes_engine_ml_capable() {
        if std::env::var("VIGIL_ML_ENGINE_URL").is_err() {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        install_ml_engine_into(dir.path()).expect("install real ML engine");
        let engine = dir.path().join(ENGINE_BIN);
        assert!(engine.is_file(), "engine binary installed");
        assert!(
            dir.path().join(ort_dylib_basename()).is_file(),
            "primary ORT lib installed alongside"
        );
        // 关键:装好的 ort 引擎 `model status` 必报 ML 支持(非 unsupported)→ 证明 ml_supported 会翻 true。
        let out = std::process::Command::new(&engine)
            .args(["model", "status"])
            .output()
            .expect("run model status");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !combined.to_ascii_lowercase().contains("unsupported"),
            "installed ML engine must report ML support, got: {combined}"
        );
    }
}
