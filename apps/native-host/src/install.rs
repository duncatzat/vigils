//! I09b-β1 Chrome Native Messaging Host 注册脚本。
//!
//! 兑付 I09a / I09b-α1 README 明示的延后项:**让 Vigil 扩展能真装真用**。
//! Chrome 启动 Native Host 前会按 OS 特定位置查 manifest JSON(通过 `connectNative`
//! 的 name 路由);未注册即 `onDisconnect("Specified native messaging host not found")`,
//! 导致 I09b 扩展 fail-closed 全部 block,功能完全不可用。
//!
//! # 平台对照表(Chrome 官方文档)
//!
//! | OS      | Manifest 位置                                                              |
//! |---------|---------------------------------------------------------------------------|
//! | Windows | HKCU\Software\Google\Chrome\NativeMessagingHosts\com.vigil.host (默认值 = 文件绝对路径) |
//! | macOS   | ~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.vigil.host.json |
//! | Linux   | ~/.config/google-chrome/NativeMessagingHosts/com.vigil.host.json          |
//!
//! # Manifest JSON shape(Chrome 强制字段白名单)
//!
//! ```json
//! {
//!   "name": "com.vigil.host",
//!   "description": "...",
//!   "path": "<absolute path to executable>",
//!   "type": "stdio",
//!   "allowed_origins": ["chrome-extension://<EXT_ID>/"]
//! }
//! ```
//!
//! # 安全契约
//!
//! - `extension_id` 必须形如 `chrome-extension://<32 个 [a-p] 字符>/`,否则 Chrome 拒加载
//! - `allowed_origins` 是白名单:**只有列入的扩展** 可调 connectNative(Chrome 运行时守门)
//! - manifest JSON 写入前校验 `exe_path` 必须绝对路径 —— **Vigil 项目策略**(非 Chrome 规范):
//!   Chrome 只在 Linux/macOS 强制绝对路径,Windows 允许相对 manifest 目录;
//!   Vigil 一律要求绝对,避免"本地调试绝对 / CI 打包相对"的路径歧义
//!
//! # 单元测试策略(DI pattern)
//!
//! Windows 注册表副作用无法在单测中模拟;**跨平台路径计算 + manifest 渲染**抽成纯函数,
//! 通过 `base_dir: &Path` 依赖注入,让测试传 tempdir 模拟各 OS 路径计算。Windows 注册表
//! 路径在集成测试或手工运行时真写,不进 `cargo test --workspace`(避免污染用户 HKCU)。

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::json;

/// Chrome Native Messaging Host name。**不可修改** —— 与扩展 `background.js` 的
/// `NATIVE_HOST_NAME` 和 manifest.json `nativeMessaging` 权限约定。
pub const HOST_NAME: &str = "com.vigil.host";

/// Chrome 规定扩展 ID:32 个小写字母 `a-p`(base16 alphabet mapped to letters)。
const EXTENSION_ID_LEN: usize = 32;

/// 安装 / 状态查询参数。
#[derive(Debug, Clone)]
pub struct InstallConfig {
    /// Chrome 扩展 ID(32 chars `[a-p]`),本 Host 仅对该 ID 开放 connectNative
    pub extension_id: String,
    /// vigil-native-host 可执行文件的**绝对**路径
    pub exe_path: PathBuf,
    /// manifest description 字段(人可读)
    pub description: String,
}

/// install / uninstall / status 失败原因。
#[derive(Debug)]
pub enum InstallError {
    /// `extension_id` 非法(长度 / 字符集)
    InvalidExtensionId(String),
    /// `exe_path` 不是绝对路径。
    ///
    /// **Chrome 规范**:Linux/macOS 严格要求 `path` 绝对;Windows 允许相对 manifest 目录。
    /// **Vigil 策略**(收紧):不论平台一律要求绝对路径,避免"本地调试绝对 / CI 打包相对"
    /// 的路径歧义 + macOS/Linux 上因相对路径静默失败难排错。
    ExePathNotAbsolute(PathBuf),
    /// `exe_path` 指向的文件不存在(可用 --allow-missing-exe 绕过,用于 build-then-install 流程)
    ExePathNotFound(PathBuf),
    /// 无法定位用户数据目录(headless 环境 / `dirs::home_dir()` 返 None)
    MissingHomeDir,
    /// 当前平台非 Windows/macOS/Linux(Chrome MV3 Native Messaging 仅这三个)
    UnsupportedOs,
    /// 目录创建 / manifest 写入失败(权限 / 磁盘)。错误脱敏:**不透传** `io::Error` Display
    Io {
        /// 操作名,如 "write manifest file" / "create manifest directory"
        what: &'static str,
        /// 目标路径,便于用户核对位置
        path: PathBuf,
    },
    /// Windows 注册表操作失败(权限 / HKCU 不可写)
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    Registry {
        /// 操作名,如 "create_subkey" / "set_value(default)" / "delete_subkey_all"
        what: &'static str,
    },
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidExtensionId(id) => write!(
                f,
                "invalid extension id: {id:?} (must be {EXTENSION_ID_LEN} chars in a-p)"
            ),
            Self::ExePathNotAbsolute(p) => write!(
                f,
                "exe path must be absolute (got {}); Vigil requires absolute paths across all \
                 platforms for unambiguous install (Chrome itself requires absolute on Linux/macOS, \
                 allows relative on Windows)",
                p.display()
            ),
            Self::ExePathNotFound(p) => write!(
                f,
                "exe path does not exist: {} (pass --allow-missing-exe to skip,\
                 e.g. for write-manifest-then-build flows)",
                p.display()
            ),
            Self::MissingHomeDir => write!(
                f,
                "failed to resolve user home directory (dirs::home_dir() returned None)"
            ),
            Self::UnsupportedOs => write!(
                f,
                "unsupported OS (Chrome Native Messaging supports Windows / macOS / Linux only)"
            ),
            Self::Io { what, path } => {
                write!(
                    f,
                    "{what} failed at {} (permissions / disk / path invalid)",
                    path.display()
                )
            }
            Self::Registry { what } => {
                write!(f, "{what} failed (HKCU permissions / registry unavailable)")
            }
        }
    }
}

impl std::error::Error for InstallError {}

/// 校验 `extension_id` 合法性(32 个 `a-p` 字符)。
///
/// Chrome 的扩展 ID 实际是 32 个 hex(0-f)字符映射到 a-p(`[0..9] → [a..j]`,`[a..f] → [k..p]`)。
/// 形如 `chrome-extension://<ID>/` 的 origin 才会被 Chrome 接受。
pub fn validate_extension_id(id: &str) -> Result<(), InstallError> {
    if id.len() != EXTENSION_ID_LEN {
        return Err(InstallError::InvalidExtensionId(id.to_string()));
    }
    if !id.chars().all(|c| matches!(c, 'a'..='p')) {
        return Err(InstallError::InvalidExtensionId(id.to_string()));
    }
    Ok(())
}

/// 渲染 Host manifest JSON。
///
/// 产出形如:
/// ```json
/// {
///   "name": "com.vigil.host",
///   "description": "...",
///   "path": "/abs/path/to/exe",
///   "type": "stdio",
///   "allowed_origins": ["chrome-extension://<EXT_ID>/"]
/// }
/// ```
pub fn render_manifest(cfg: &InstallConfig) -> Result<String, InstallError> {
    validate_extension_id(&cfg.extension_id)?;
    if !cfg.exe_path.is_absolute() {
        return Err(InstallError::ExePathNotAbsolute(cfg.exe_path.clone()));
    }
    let manifest = json!({
        "name": HOST_NAME,
        "description": cfg.description,
        "path": cfg.exe_path.to_string_lossy(),
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{}/", cfg.extension_id)],
    });
    // pretty-print 让人手查改 allowed_origins 方便(Chrome 不关心格式)
    Ok(serde_json::to_string_pretty(&manifest).unwrap_or_else(|_| manifest.to_string()))
}

// ─────────────────────────── 平台目录 (DI: base_dir 便于测试) ─────────────────────────────
//
// 真实 Chrome 只查 $HOME 下的特定子目录;我们接受 `home` 参数让测试用 tempdir 模拟,
// 生产代码传 `dirs::home_dir()` 的返回值。

/// macOS: `<home>/Library/Application Support/Google/Chrome/NativeMessagingHosts`
pub fn manifest_dir_macos(home: &Path) -> PathBuf {
    home.join("Library")
        .join("Application Support")
        .join("Google")
        .join("Chrome")
        .join("NativeMessagingHosts")
}

/// Linux: `<home>/.config/google-chrome/NativeMessagingHosts`
///
/// 注:Chromium / Edge / Brave 有各自的 NativeMessagingHosts 目录;本 α1 仅针对 Google
/// Chrome(manifest.json host_permissions 与此匹配)。其它 Chromium 分支的支持留 β 后续。
pub fn manifest_dir_linux(home: &Path) -> PathBuf {
    home.join(".config")
        .join("google-chrome")
        .join("NativeMessagingHosts")
}

/// macOS/Linux 公共 manifest 文件路径计算(DI home)。
///
/// 返回形如 `<dir>/com.vigil.host.json`。
pub fn manifest_file_unixlike(dir: PathBuf) -> PathBuf {
    dir.join(format!("{HOST_NAME}.json"))
}

// ─────────────────────────── 跨平台 install/uninstall/status 入口 ─────────────────────
//
// 生产代码调用路径:
//   install(cfg, home=dirs::home_dir()) / uninstall(home) / status(home)
// 在三个平台上分流;路径都不能绕过"绝对路径 + 扩展 ID 校验"。

/// install 结果;便于 CLI 层输出结构化信息。
#[derive(Debug, Clone)]
pub struct InstallOutcome {
    /// manifest 文件最终写入路径(Windows 也有一份文件,再由注册表指过去)
    pub manifest_path: PathBuf,
    /// Windows 下:HKCU 注册表 key 的完整路径;其它平台为 None
    pub registry_key: Option<String>,
}

/// 安装入口(生产):
/// 1. 渲染 manifest JSON
/// 2. 创建 manifest_dir(recursive)
/// 3. 写入 `com.vigil.host.json`
/// 4. Windows:额外把路径写进 `HKCU\Software\Google\Chrome\NativeMessagingHosts\<HOST_NAME>` 默认值
pub fn install(
    cfg: &InstallConfig,
    allow_missing_exe: bool,
    home: Option<&Path>,
) -> Result<InstallOutcome, InstallError> {
    // exe_path 存在性检查(可用 `allow_missing_exe` 绕过,例如"先 manifest 后构建"流程)
    if !allow_missing_exe && !cfg.exe_path.exists() {
        return Err(InstallError::ExePathNotFound(cfg.exe_path.clone()));
    }
    // 渲染 + 写文件(三平台共用)
    let rendered = render_manifest(cfg)?;
    let manifest_path = write_manifest_file(&rendered, home)?;
    // Windows 特殊:注册表指过去
    let registry_key = platform_register(&manifest_path)?;
    Ok(InstallOutcome {
        manifest_path,
        registry_key,
    })
}

/// 卸载:删 manifest 文件 + Windows 删注册表。幂等(目标不存在时不报错)。
pub fn uninstall(home: Option<&Path>) -> Result<(), InstallError> {
    let manifest_path = compute_manifest_path(home)?;
    if manifest_path.exists() {
        fs::remove_file(&manifest_path).map_err(|_| InstallError::Io {
            what: "remove manifest file",
            path: manifest_path.clone(),
        })?;
    }
    platform_unregister()?;
    Ok(())
}

/// 查询注册状态:返回 (manifest 是否存在, Windows 注册表是否存在)。
pub fn status(home: Option<&Path>) -> Result<StatusReport, InstallError> {
    let manifest_path = compute_manifest_path(home)?;
    let manifest_exists = manifest_path.exists();
    let registry_present = platform_registry_present()?;
    Ok(StatusReport {
        manifest_path,
        manifest_exists,
        registry_present,
    })
}

/// `status()` 返回的信息快照。
#[derive(Debug, Clone)]
pub struct StatusReport {
    /// 计算出的 manifest 文件目标路径(无论是否存在)
    pub manifest_path: PathBuf,
    /// manifest 文件是否存在
    pub manifest_exists: bool,
    /// Windows:HKCU key 是否存在;其它平台恒为 `None`
    pub registry_present: Option<bool>,
}

impl StatusReport {
    /// 综合注册判定:manifest 在位且(Windows 上)HKCU 注册表键在位;
    /// 非 Windows 无注册表概念(`registry_present = None`)→ 仅看 manifest。
    /// 供 CLI `setup --status` 与桌面 Protection Overview 卡共用,防各自重实现漂移。
    pub fn is_registered(&self) -> bool {
        self.manifest_exists && self.registry_present.unwrap_or(true)
    }
}

// ─────────────────────────── 内部辅助:跨平台分流 ─────────────────────────────────────

/// 计算 manifest 文件绝对路径(不负责写;全平台共用)。
fn compute_manifest_path(home: Option<&Path>) -> Result<PathBuf, InstallError> {
    let home_buf = match home {
        Some(h) => h.to_path_buf(),
        None => dirs::home_dir().ok_or(InstallError::MissingHomeDir)?,
    };
    #[cfg(target_os = "macos")]
    {
        Ok(manifest_file_unixlike(manifest_dir_macos(&home_buf)))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(manifest_file_unixlike(manifest_dir_linux(&home_buf)))
    }
    #[cfg(target_os = "windows")]
    {
        // Windows:manifest 文件放 `%LOCALAPPDATA%\Vigil\NativeMessagingHosts\com.vigil.host.json`,
        // 注册表指过去。选 LocalAppData 而非 Roaming(与 desktop β5 本机审计一致)。
        let base = dirs::data_local_dir().unwrap_or_else(|| home_buf.join("AppData").join("Local"));
        Ok(base
            .join("Vigil")
            .join("NativeMessagingHosts")
            .join(format!("{HOST_NAME}.json")))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = home_buf;
        Err(InstallError::UnsupportedOs)
    }
}

/// 实际写 manifest 文件(含递归建父目录)。
fn write_manifest_file(rendered: &str, home: Option<&Path>) -> Result<PathBuf, InstallError> {
    let target = compute_manifest_path(home)?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|_| InstallError::Io {
            what: "create manifest directory",
            path: parent.to_path_buf(),
        })?;
    }
    fs::write(&target, rendered).map_err(|_| InstallError::Io {
        what: "write manifest file",
        path: target.clone(),
    })?;
    Ok(target)
}

// ─────────────────────────── Windows 注册表 ─────────────────────────────────────
#[cfg(target_os = "windows")]
const WINDOWS_REG_PATH: &str = r"Software\Google\Chrome\NativeMessagingHosts\com.vigil.host";

#[cfg(target_os = "windows")]
fn platform_register(manifest_path: &Path) -> Result<Option<String>, InstallError> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu
        .create_subkey(WINDOWS_REG_PATH)
        .map_err(|_| InstallError::Registry {
            what: "create_subkey",
        })?;
    key.set_value("", &manifest_path.to_string_lossy().as_ref())
        .map_err(|_| InstallError::Registry {
            what: "set_value(default)",
        })?;
    Ok(Some(format!(r"HKCU\{WINDOWS_REG_PATH}")))
}

#[cfg(target_os = "windows")]
fn platform_unregister() -> Result<(), InstallError> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    // delete_subkey_all 允许 key 不存在(返 NotFound,我们视为成功 idempotent)
    match hkcu.delete_subkey_all(WINDOWS_REG_PATH) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(InstallError::Registry {
            what: "delete_subkey_all",
        }),
    }
}

#[cfg(target_os = "windows")]
fn platform_registry_present() -> Result<Option<bool>, InstallError> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    match hkcu.open_subkey_with_flags(WINDOWS_REG_PATH, KEY_READ) {
        Ok(_) => Ok(Some(true)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Some(false)),
        Err(_) => Err(InstallError::Registry {
            what: "open_subkey",
        }),
    }
}

// ─────────────────────────── 非 Windows 的 no-op ─────────────────────────────────────
#[cfg(not(target_os = "windows"))]
fn platform_register(_manifest_path: &Path) -> Result<Option<String>, InstallError> {
    Ok(None)
}
#[cfg(not(target_os = "windows"))]
fn platform_unregister() -> Result<(), InstallError> {
    Ok(())
}
#[cfg(not(target_os = "windows"))]
fn platform_registry_present() -> Result<Option<bool>, InstallError> {
    Ok(None)
}

// ═══════════════════════════════════════════════════════════════════════════════════
// 单元测试
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    // Windows 下 install/uninstall 涉及 HKCU 注册表副作用,不做真 install 单测;
    // TempDir 只在 non-windows 的路径写测试里用,所以 import 也 gate 同平台。
    #[cfg(not(target_os = "windows"))]
    use tempfile::TempDir;

    fn valid_id() -> String {
        "a".repeat(32)
    }

    fn cfg(ext_id: &str, exe: PathBuf) -> InstallConfig {
        InstallConfig {
            extension_id: ext_id.to_string(),
            exe_path: exe,
            description: "Vigil test host".to_string(),
        }
    }

    // ─── validate_extension_id ───

    #[test]
    fn extension_id_valid_32_a_to_p_accepted() {
        assert!(validate_extension_id(&valid_id()).is_ok());
        assert!(validate_extension_id("abcdefghijklmnopabcdefghijklmnop").is_ok());
    }

    #[test]
    fn extension_id_wrong_length_rejected() {
        for bad in ["", "aaa", &"a".repeat(31), &"a".repeat(33)] {
            let err = validate_extension_id(bad).unwrap_err();
            match err {
                InstallError::InvalidExtensionId(_) => {}
                other => panic!("expected InvalidExtensionId for {bad:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn extension_id_out_of_alphabet_rejected() {
        // 'q' 不在 a-p 范围;Chrome 扩展 ID 只用 a-p
        let bad = format!("{}{}", "a".repeat(31), "q");
        assert!(matches!(
            validate_extension_id(&bad),
            Err(InstallError::InvalidExtensionId(_))
        ));
        // 含数字也拒
        let bad = format!("{}1", "a".repeat(31));
        assert!(matches!(
            validate_extension_id(&bad),
            Err(InstallError::InvalidExtensionId(_))
        ));
    }

    // ─── render_manifest ───

    #[test]
    fn render_manifest_shape_matches_chrome_spec() {
        #[cfg(not(target_os = "windows"))]
        let exe = PathBuf::from("/abs/path/to/vigil-native-host");
        #[cfg(target_os = "windows")]
        let exe = PathBuf::from(r"C:\Program Files\Vigil\vigil-native-host.exe");
        let c = cfg(&valid_id(), exe.clone());

        let rendered = render_manifest(&c).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(parsed["name"], HOST_NAME);
        assert_eq!(parsed["type"], "stdio");
        assert_eq!(parsed["description"], "Vigil test host");
        assert_eq!(parsed["path"], exe.to_string_lossy().as_ref());
        let allowed = parsed["allowed_origins"].as_array().unwrap();
        assert_eq!(allowed.len(), 1);
        assert_eq!(allowed[0], format!("chrome-extension://{}/", valid_id()));
    }

    #[test]
    fn render_manifest_relative_exe_rejected() {
        let c = cfg(&valid_id(), PathBuf::from("vigil-native-host"));
        let err = render_manifest(&c).unwrap_err();
        match err {
            InstallError::ExePathNotAbsolute(p) => {
                assert_eq!(p, PathBuf::from("vigil-native-host"));
            }
            other => panic!("expected ExePathNotAbsolute, got {other:?}"),
        }
    }

    #[test]
    fn render_manifest_invalid_extension_id_rejected() {
        let exe = if cfg!(target_os = "windows") {
            PathBuf::from(r"C:\x")
        } else {
            PathBuf::from("/x")
        };
        let c = cfg("short", exe);
        assert!(matches!(
            render_manifest(&c),
            Err(InstallError::InvalidExtensionId(_))
        ));
    }

    // ─── 平台目录计算(DI) ───

    #[test]
    fn macos_dir_layout_is_correct() {
        let home = Path::new("/Users/alice");
        let d = manifest_dir_macos(home);
        assert_eq!(
            d,
            PathBuf::from(
                "/Users/alice/Library/Application Support/Google/Chrome/NativeMessagingHosts"
            )
        );
        let f = manifest_file_unixlike(d);
        assert!(f.ends_with("com.vigil.host.json"));
    }

    #[test]
    fn linux_dir_layout_is_correct() {
        let home = Path::new("/home/bob");
        let d = manifest_dir_linux(home);
        assert_eq!(
            d,
            PathBuf::from("/home/bob/.config/google-chrome/NativeMessagingHosts")
        );
        let f = manifest_file_unixlike(d);
        assert!(f.ends_with("com.vigil.host.json"));
    }

    // ─── install / uninstall 路径写入(tempdir)─── ** 跳过 Windows(注册表副作用不便单测)

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn install_writes_manifest_into_expected_dir() {
        let td = TempDir::new().unwrap();
        let exe = td.path().join("fake-exe");
        fs::write(&exe, b"fake").unwrap();
        let c = cfg(&valid_id(), exe.clone());
        let out = install(&c, false, Some(td.path())).unwrap();
        assert!(out.manifest_path.ends_with("com.vigil.host.json"));
        assert!(out.manifest_path.is_file());
        assert_eq!(out.registry_key, None);
        let body = fs::read_to_string(&out.manifest_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["name"], HOST_NAME);
        assert_eq!(parsed["type"], "stdio");
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn install_rejects_missing_exe_unless_allowed() {
        let td = TempDir::new().unwrap();
        let ghost = td.path().join("does-not-exist");
        let c = cfg(&valid_id(), ghost.clone());

        // 默认拒
        let err = install(&c, false, Some(td.path())).unwrap_err();
        assert!(matches!(err, InstallError::ExePathNotFound(_)));

        // allow_missing_exe=true 放行(write-manifest-then-build 流程)
        let out = install(&c, true, Some(td.path())).unwrap();
        assert!(out.manifest_path.exists());
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn uninstall_is_idempotent() {
        let td = TempDir::new().unwrap();
        // uninstall 不存在的 manifest 不应报错
        uninstall(Some(td.path())).unwrap();
        // install 后再 uninstall
        let exe = td.path().join("fake-exe");
        fs::write(&exe, b"fake").unwrap();
        let c = cfg(&valid_id(), exe);
        let out = install(&c, false, Some(td.path())).unwrap();
        assert!(out.manifest_path.is_file());
        uninstall(Some(td.path())).unwrap();
        assert!(!out.manifest_path.exists());
        // 再 uninstall 一次仍成功
        uninstall(Some(td.path())).unwrap();
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn status_reports_manifest_presence() {
        let td = TempDir::new().unwrap();
        let s0 = status(Some(td.path())).unwrap();
        assert!(!s0.manifest_exists);
        assert_eq!(s0.registry_present, None); // 非 Windows 平台恒 None

        let exe = td.path().join("fake-exe");
        fs::write(&exe, b"fake").unwrap();
        let c = cfg(&valid_id(), exe);
        install(&c, false, Some(td.path())).unwrap();

        let s1 = status(Some(td.path())).unwrap();
        assert!(s1.manifest_exists);
        assert!(s1.manifest_path.is_file());
    }

    // ─── Display 脱敏守门 ───

    #[test]
    fn display_messages_redact_io_details() {
        let err = InstallError::Io {
            what: "write manifest file",
            path: PathBuf::from("/tmp/xyz"),
        };
        let msg = format!("{err}");
        assert!(msg.contains("write manifest file"), "保留操作名供排错");
        assert!(msg.contains("/tmp/xyz"), "保留目标路径");
        assert!(!msg.contains("Permission denied"), "不透传 io 原文");
        assert!(!msg.contains("os error"), "不透传 os error");
    }

    #[test]
    fn status_report_is_registered_matrix() {
        use std::path::PathBuf;
        let mk = |manifest_exists, registry_present| super::StatusReport {
            manifest_path: PathBuf::from("/x/com.vigil.host.json"),
            manifest_exists,
            registry_present,
        };
        assert!(
            mk(true, Some(true)).is_registered(),
            "manifest + 注册表在位"
        );
        assert!(
            mk(true, None).is_registered(),
            "非 Windows(无注册表概念)仅看 manifest"
        );
        assert!(
            !mk(true, Some(false)).is_registered(),
            "Windows 注册表键缺失"
        );
        assert!(!mk(false, Some(true)).is_registered(), "manifest 缺失");
        assert!(!mk(false, None).is_registered());
    }
}
