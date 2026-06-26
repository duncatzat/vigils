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

/// 解析 vigil-hub 引擎二进制。顺序:**已装 ML 变体(稳定目录,dylib 信号)** → 捆绑 resource →
/// GUI exe 同目录 → 稳定启动器 → PATH。优雅 fall-through。
///
/// ML 变体置顶:用户经 GUI 安装 ort 引擎到稳定目录后,必须盖过出厂硬指纹引擎(它可能在 exe 同目录 /
/// PATH),否则 model/daemon/hook 仍跑硬指纹 → ML 形同未装。无 dylib 的普通引擎不触发本分支,顺序不变。
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
    // 已下载/部署到稳定启动器位置的引擎。
    if let Some(p) = stable_launcher_path() {
        if p.is_file() {
            return Some(p);
        }
    }
    which_on_path(ENGINE_BIN)
}

/// 稳定启动器目录是否含当前平台 ONNX Runtime dylib(`download_ml_engine` 的落点信号)——
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

// ─────────────────── ML 引擎变体安装(端到端 ML「最后一公里」)───────────────────────────
// 出厂 GUI 不捆引擎,常态下用户装的是**非 ort** vigil-hub → `model status` 报 unsupported、
// `--engine ml|auto` fail-closed 回落硬指纹 → ML 形同未发布。本段把已发布的 **ML 引擎变体** archive
// (`--features ort` 的 vigil-hub + 同目录 ONNX Runtime 库)安全装到**稳定启动器目录** →
// `resolve_engine` 经 dylib 信号优先命中 ort → daemon 可暖载、`model install/status` 可用、hook 真跑 ML。
//
// SHA 信任锚 = 发版期 **minisign 签名**的 `engine-manifest.json`(列 per-平台 {url,sha256});GUI 取
// manifest + `.minisig` → 复用 Tauri 更新器同一把 key 验签 → 据此 SHA-pin(攻击者控下载源也伪造不出
// 有效签名)。签名背书同时解决命名/格式分叉:公开 Windows 资产是 `.zip`(多 ORT 库)、Unix `.tar.gz`
// —— 解包器按**魔数嗅探**。env 覆盖保留作测试 / 私有镜像旁路。

/// 当前平台引擎资产标识(发布镜像命名;与签名清单平台键一致)。
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
        Err("unsupported platform for ML engine auto-download".to_string())
    }
}

/// 当前平台主 ONNX Runtime 库 basename(release.yml `dest` / 真发布资产主库名;也是稳定目录
/// dylib 信号探测名 —— 两套 release 管线均保证此精确名就位)。
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

/// ML 引擎变体下载源(archive URL + 可选 pinned sha256)。
struct MlEngineSource {
    url: String,
    sha256: Option<String>,
}

// ── 签名引擎清单(SHA 信任锚)─────────────────────────────────────────────────────────────
/// 复用 Tauri 更新器的 minisign 公钥(key 5B4B247DA77CEAC5;见 tauri.conf.json::plugins.updater.pubkey
/// base64 解码后第二行)。引擎清单与桌面更新件由同一发布密钥签名 → 单一信任锚。
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

/// 签名引擎清单 URL(`VIGIL_ENGINE_MANIFEST_URL` 覆盖,否则版本拼默认镜像)。`.minisig` 在 `<url>.minisig`。
/// host 即便错 / 被 MITM,验签失败即 fail-closed → host provisional 不损安全。
fn engine_manifest_url() -> String {
    if let Ok(url) = std::env::var("VIGIL_ENGINE_MANIFEST_URL") {
        return url;
    }
    let ver = env!("CARGO_PKG_VERSION");
    format!("https://vigils.ai/releases/engine/v{ver}/engine-manifest.json")
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

/// 用 minisign 公钥验签 `data`。`wrapped_sig_b64` = Tauri 风格 base64(标准 minisign .minisig 全文)。
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
/// `onnxruntime*` 库(basename 扁平,防 traversal),其余忽略。引擎或 ORT 库缺失 → Err(拒装半包)。
/// 返回落地的引擎二进制路径。调用方保证 `archive` 已 SHA-pin 校验。
fn extract_ml_bundle(archive: &Path, staging: &Path) -> Result<PathBuf, String> {
    let mut head = [0u8; 4];
    {
        use std::io::Read;
        let mut f =
            std::fs::File::open(archive).map_err(|e| format!("open ML archive failed: {e}"))?;
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

/// AppHandle-free 安装核心(供 [`download_ml_engine`] 与对真发布 artifact 的集成测试共用):解析源 →
/// 下载 → 整包 SHA-pin → 嗅探解包 → 运行核验 → 把引擎 + 全部 ORT 库移入 `bin_dir`。全程 fail-closed。
fn install_ml_engine_into(bin_dir: &Path) -> Result<(), String> {
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

    let staging = bin_dir.join(".ml-staging");
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging)
        .map_err(|e| format!("failed to create ML staging dir: {e}"))?;

    let archive = staging.join("ml-bundle.download");
    if let Err(e) = download_to_file(&src.url, &archive) {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(e);
    }

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

    // 移入稳定 bin 目录:引擎 + 全部 ORT 库(按谓词筛,跳过下载的压缩包)。Windows 下若旧二进制正被
    // daemon 运行 → rename 失败,提示先停 daemon。
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
        let to = bin_dir.join(&fname);
        if let Err(e) = std::fs::rename(&from, &to) {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(format!(
                "failed to install {fname} to {} ({e}) — if the daemon is running from the old \
                 engine, stop it first (Settings → daemon → stop) and retry",
                to.display()
            ));
        }
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

    // ── ML 引擎变体安装(端到端最后一公里)─────────────────────────────────────────

    #[test]
    fn engine_platform_is_known_on_test_host() {
        assert!(engine_platform().is_ok());
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
        let json = br#"{"schema":1,"version":"0.4.2","artifacts":{
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
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let keyid = [1u8, 2, 3, 4, 5, 6, 7, 8];

        let mut pkblob = Vec::new();
        pkblob.extend_from_slice(b"Ed");
        pkblob.extend_from_slice(&keyid);
        pkblob.extend_from_slice(&sk.verifying_key().to_bytes());
        let pubkey_b64 = b64.encode(&pkblob);

        let data = br#"{"schema":1,"artifacts":{}}"#;
        let prehash = Blake2b512::digest(data);
        let main_sig = sk.sign(prehash.as_slice());
        let mut sigblob = Vec::new();
        sigblob.extend_from_slice(b"ED");
        sigblob.extend_from_slice(&keyid);
        sigblob.extend_from_slice(&main_sig.to_bytes());
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

        verify_minisign(data, &wrapped, &pubkey_b64).expect("valid signature must verify");
        assert!(verify_minisign(b"tampered-manifest", &wrapped, &pubkey_b64).is_err());
        assert!(verify_minisign(data, "!!!not-base64!!!", &pubkey_b64).is_err());
    }

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
        assert!(staging.join(ENGINE_BIN).is_file());
        assert!(staging.join(dylib).is_file());
        assert!(!staging.join("README-ML.txt").exists());
        assert!(!staging.join("vigil-cli-ml-x").exists());
    }

    #[test]
    fn extract_ml_bundle_zip_takes_binary_and_all_ort_libs() {
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
        assert!(staging.join(ENGINE_BIN).is_file());
        assert!(staging.join(dylib).is_file());
        assert!(
            staging.join(extra_ort).is_file(),
            "extra ORT lib (providers_shared) must also be extracted"
        );
        assert!(!staging.join("README-ML.txt").exists());
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
        assert!(!stable_has_ml_dylib(&engine));
        std::fs::write(dir.path().join(ort_dylib_basename()), b"lib").expect("write dylib");
        assert!(stable_has_ml_dylib(&engine));
    }

    /// 对真发布 ML artifact 的端到端验证(不硬编码 URL,靠运行方设 `VIGIL_ML_ENGINE_URL` +
    /// `VIGIL_ML_ENGINE_SHA256` 喂真包;未设则跳过)。默认 `#[ignore]`(含网络下载)。
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
