//! AI 引擎模式(EngineMode)落盘持久化(ADR 0022 用户面选择)。
//!
//! 镜像 [`crate::posture`] 的持久化纪律:`<data_local>/Vigil/engine.json`,
//! 形如 `{"version":1,"engine":"hardfp"}`。`vigil-hub engine show|set` 读写本文件;
//! GUI(控制平面)经该 CLI 读写。serve/wrap/hook 的**消费侧接线**(未显式 `--engine` 时
//! 回落本配置)是后续增量 —— 本模块只负责模型 + 持久化,不改任何决策路径。
//!
//! # fail-closed
//! - 文件不存在 → [`LoadedEngine::mode`] = `None`(未配置;调用方走既有默认 = hardfp/legacy)。
//! - 文件存在但损坏 / 未知值 / 版本不识别 → **收敛 [`EngineMode::Hardfp`]** + warning
//!   (损坏配置绝不静默启用 ML —— 与 posture「损坏收敛 High」同精神:宁可更保守)。
//!   warning 文案**不回显文件原文**(内容不可信;见 feedback「untrusted input not in errors」)。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::serve::EngineMode;

// 与 posture / setup 默认目录约定对齐(同一 `<data_local>/Vigil/`)。
const VIGIL_SUBDIR: &str = "Vigil";
const ENGINE_FILENAME: &str = "engine.json";
/// 配置 schema 版本。不识别的版本一律 fail-closed 收敛 hardfp,不按旧语义猜测。
const ENGINE_FILE_VERSION: u64 = 1;

/// 磁盘 shape:`{"version":1,"engine":"hardfp"}`。不加 `deny_unknown_fields`(同 version 内
/// 允许前向追加字段);破坏性变更走 version 提升,由 [`load_engine`] 版本检查兜住。
#[derive(Debug, Serialize, Deserialize)]
struct EngineFileV1 {
    version: u64,
    engine: EngineMode,
}

/// [`load_engine`] 结果:解析出的模式 + 可选 warning(损坏被收敛 hardfp 时说明原因)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedEngine {
    /// 生效引擎模式;`None` = 未配置(文件缺失),调用方用既有默认。
    pub mode: Option<EngineMode>,
    /// 非 None = 配置异常已 fail-closed 收敛 hardfp;只含原因类别 + 路径,不含文件原文。
    pub warning: Option<String>,
}

/// 默认引擎配置路径:`<data_local>/Vigil/engine.json`,与 posture.json / 默认账本同目录。
/// 无法定位本机数据目录 → `None`,由调用方决定如何提示。
pub fn default_engine_path() -> Option<PathBuf> {
    dirs::data_local_dir().map(|b| b.join(VIGIL_SUBDIR).join(ENGINE_FILENAME))
}

/// 读取引擎配置。**永不 panic / 永不 Err** —— 异常收敛为确定结果:
/// - 不存在 → `mode=None`(未配置),无 warning。
/// - 存在但读失败 / 非法 JSON / 未知值 / version 不识别 → **fail-closed `Some(Hardfp)`** + warning。
pub fn load_engine(path: &Path) -> LoadedEngine {
    let fail_closed = |reason: &str| LoadedEngine {
        mode: Some(EngineMode::Hardfp),
        warning: Some(format!(
            "engine config at {} is {reason}; failing closed to hard-fingerprint",
            path.display()
        )),
    };

    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        // 不存在 = 从未配置 → None(唯一允许"不收敛"的分支:无配置即默认)。
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return LoadedEngine {
                mode: None,
                warning: None,
            };
        }
        Err(_) => return fail_closed("unreadable"),
    };

    let parsed: EngineFileV1 = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return fail_closed("malformed (invalid JSON or unknown engine value)"),
    };
    if parsed.version != ENGINE_FILE_VERSION {
        return fail_closed("of an unrecognized version");
    }
    LoadedEngine {
        mode: Some(parsed.engine),
        warning: None,
    }
}

/// 原子写引擎配置(同 posture `store_posture`:同目录 tmp + `rename`,绝不留半截;父目录自建)。
pub fn store_engine(path: &Path, mode: EngineMode) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut rendered = serde_json::to_string_pretty(&EngineFileV1 {
        version: ENGINE_FILE_VERSION,
        engine: mode,
    })?;
    rendered.push('\n');

    let tmp = {
        let mut s = path.as_os_str().to_os_string();
        s.push(".vigil-tmp");
        PathBuf::from(s)
    };
    if let Err(e) = std::fs::write(&tmp, rendered.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// 解析"显式 `--engine`"与"持久化 engine.json"为最终生效模式 + `ml_best_effort` 标志。
///
/// 语义区分(关键安全决策,镜像 ADR 0024 D8 的"响亮降级而非硬阻断"):
/// - **显式 `--engine`** = 命令式:`ml` 严格(缺 ort/模型 → fail-closed **拒启**,用户须知情);
///   `auto` 本就 best-effort;`hardfp` 关 ML。
/// - **持久化 engine.json**(无显式 flag)= standing 偏好:**总是 best-effort** —— 缺 ort/模型时
///   **响亮降级硬指纹而非拒启**(全局偏好不该让每次 serve/wrap 启动失败;且 best-effort 只用
///   **已缓存**模型,绝不下载,turnkey 不会因偏好意外拉 738MB)。
/// - 两者皆无 = legacy(`None`):由裸 `--enable-*` 决定(逐字节沿用 ADR 0022 前行为)。
///
/// 返回 `(生效模式, ml_best_effort)`。纯函数(无 IO),进默认测试矩阵守门
/// (feedback_production_logic_testable);**不**触碰 serve.rs 既有 ADR 0022 决策测试。
pub fn effective_engine(
    cli: Option<EngineMode>,
    persisted: Option<EngineMode>,
) -> (Option<EngineMode>, bool) {
    match cli {
        // 显式 flag 永远压过持久化;仅 `auto` 是 best-effort。
        Some(mode) => (Some(mode), mode == EngineMode::Auto),
        // 无显式 flag → 回落持久化偏好,且**总是 best-effort**(降级不拒启)。
        None => match persisted {
            Some(mode) => (Some(mode), true),
            None => (None, false),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_MODES: [EngineMode; 3] = [EngineMode::Hardfp, EngineMode::Ml, EngineMode::Auto];

    #[test]
    fn missing_file_is_unconfigured_none() {
        let td = tempfile::TempDir::new().unwrap();
        let loaded = load_engine(&td.path().join("does-not-exist.json"));
        assert_eq!(loaded.mode, None, "缺文件 = 未配置(None),不收敛");
        assert!(loaded.warning.is_none());
    }

    #[test]
    fn store_then_load_roundtrip_all_modes() {
        let td = tempfile::TempDir::new().unwrap();
        for mode in ALL_MODES {
            let path = td.path().join(format!("{}.json", mode.as_str()));
            store_engine(&path, mode).unwrap();
            let loaded = load_engine(&path);
            assert_eq!(loaded.mode, Some(mode));
            assert!(loaded.warning.is_none(), "clean roundtrip must not warn");
        }
    }

    #[test]
    fn store_creates_missing_parent_directories() {
        let td = tempfile::TempDir::new().unwrap();
        let path = td.path().join("nested").join("deeper").join("engine.json");
        store_engine(&path, EngineMode::Ml).unwrap();
        assert_eq!(load_engine(&path).mode, Some(EngineMode::Ml));
    }

    #[test]
    fn malformed_fails_closed_to_hardfp_without_echo() {
        let td = tempfile::TempDir::new().unwrap();
        let path = td.path().join("engine.json");
        std::fs::write(&path, b"ENGINE-SENTINEL {{{ not json").unwrap();
        let loaded = load_engine(&path);
        assert_eq!(
            loaded.mode,
            Some(EngineMode::Hardfp),
            "malformed -> fail closed hardfp(绝不静默 ml)"
        );
        let w = loaded.warning.unwrap();
        assert!(!w.contains("ENGINE-SENTINEL"), "warning 不得回显原文: {w}");
        assert!(w.contains("malformed"));
    }

    #[test]
    fn unknown_engine_value_fails_closed_to_hardfp() {
        let td = tempfile::TempDir::new().unwrap();
        let path = td.path().join("engine.json");
        std::fs::write(&path, br#"{"version":1,"engine":"turbo-sentinel"}"#).unwrap();
        let loaded = load_engine(&path);
        assert_eq!(loaded.mode, Some(EngineMode::Hardfp));
        let w = loaded.warning.unwrap();
        assert!(!w.contains("turbo-sentinel"), "warning 不得回显未知值: {w}");
    }

    #[test]
    fn unrecognized_version_fails_closed_to_hardfp() {
        let td = tempfile::TempDir::new().unwrap();
        let path = td.path().join("engine.json");
        std::fs::write(&path, br#"{"version":99,"engine":"ml"}"#).unwrap();
        let loaded = load_engine(&path);
        assert_eq!(
            loaded.mode,
            Some(EngineMode::Hardfp),
            "未知 version 绝不按 ml 解读(fail closed)"
        );
        assert!(loaded.warning.unwrap().contains("version"));
    }

    #[test]
    fn serde_names_are_snake_case_stable() {
        // serde 名是落盘契约,防 rename 漂移破坏已存在的 engine.json(也与 CLI/GUI 字面量对齐)。
        let cases = [
            (EngineMode::Hardfp, "\"hardfp\""),
            (EngineMode::Ml, "\"ml\""),
            (EngineMode::Auto, "\"auto\""),
        ];
        for (mode, name) in cases {
            assert_eq!(serde_json::to_string(&mode).unwrap(), name);
            let back: EngineMode = serde_json::from_str(name).unwrap();
            assert_eq!(back, mode, "serde roundtrip must be lossless");
            assert_eq!(format!("\"{}\"", mode.as_str()), name);
        }
    }

    #[test]
    fn default_engine_path_is_under_vigil_data_dir() {
        if let Some(p) = default_engine_path() {
            assert!(
                p.ends_with(Path::new("Vigil").join("engine.json")),
                "unexpected default engine path: {}",
                p.display()
            );
        }
    }

    #[test]
    fn effective_engine_explicit_flag_overrides_persisted() {
        // 显式 flag 永远压过持久化偏好。
        assert_eq!(
            effective_engine(Some(EngineMode::Hardfp), Some(EngineMode::Ml)),
            (Some(EngineMode::Hardfp), false)
        );
        assert_eq!(
            effective_engine(Some(EngineMode::Ml), Some(EngineMode::Hardfp)),
            (Some(EngineMode::Ml), false),
            "显式 ml = 严格(非 best-effort,缺模型须拒启让用户知情)"
        );
        assert_eq!(
            effective_engine(Some(EngineMode::Auto), Some(EngineMode::Hardfp)),
            (Some(EngineMode::Auto), true),
            "显式 auto = best-effort"
        );
    }

    #[test]
    fn effective_engine_persisted_is_always_best_effort() {
        // 无显式 flag → 回落持久化,且总是 best-effort(缺 ort/模型降级不拒启)。
        assert_eq!(
            effective_engine(None, Some(EngineMode::Ml)),
            (Some(EngineMode::Ml), true),
            "持久化 ml 必须 best-effort,否则默认非-ort 二进制读到 ml 会拒启(回归 P1a 用户)"
        );
        assert_eq!(
            effective_engine(None, Some(EngineMode::Auto)),
            (Some(EngineMode::Auto), true)
        );
        assert_eq!(
            effective_engine(None, Some(EngineMode::Hardfp)),
            (Some(EngineMode::Hardfp), true)
        );
    }

    #[test]
    fn effective_engine_legacy_when_both_unset() {
        // 显式 + 持久化皆无 = legacy(None,裸开关路径,非 best-effort)。
        assert_eq!(effective_engine(None, None), (None, false));
    }
}
