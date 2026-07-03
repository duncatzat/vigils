//! 模型 first-run-download(ADR 0012)。
//!
//! # 职责
//!
//! - 启动期检本地 cache(三件套 sha256 全命中即短路);
//! - 否则按 manifest 顺序下载 onnx / tokenizer / config,16-chunk 并发 byte-range;
//! - 整文件 sha256 校验,任一失败 fail-closed;
//! - 返 [`ModelPaths`] 给 caller 桥接到 [`crate::engine::OrtEngine::from_env`]
//!   (设 `VIGIL_PRIVACY_FILTER_MODEL_DIR` env var)。
//!
//! # fail-closed 不变量
//!
//! 任一 [`BootstrapError`] 变体都不应被 caller 静默吞掉降级 NoopEngine。
//! 与 [`crate::engine::EngineError`] 6 变体语义一致。
//!
//! # 子模块布局
//!
//! - [`error`]:`BootstrapError` 5 变体
//! - [`manifest`]:`Manifest` / `ModelPaths` / `placeholder_manifest()`
//! - [`download`]:HEAD + ETag + 16-chunk byte-range 并发 GET
//! - [`verify`]:sha256 streaming + cleanup_partials + assemble_chunks + check_existing
//!
//! 注:`#[cfg(feature = "ort")]` gate 在 `crate::lib` 的 `pub mod bootstrap;` 声明上,
//! 此处不重复(clippy::duplicated_attributes)。

pub mod download;
pub mod error;
pub mod manifest;
pub mod verify;

#[cfg(test)]
mod tests;

pub use error::BootstrapError;
pub use manifest::{
    injection_classifier_manifest, placeholder_manifest, Manifest, ManifestFile, ModelPaths,
};

use std::path::{Path, PathBuf};

/// 主入口:确保模型三件套就绪(下载或本地命中),返绝对路径句柄。
///
/// # 流程
///
/// 1. `target_dir = caller.unwrap_or(<data_local>/vigil/models/<name>-<version>/)`,
///    不存在则 `create_dir_all`。
/// 2. [`verify::check_existing`] 三件套 sha256 全命中 → 立即 `Ok(ModelPaths)` 短路。
/// 3. [`verify::cleanup_partials`] 清残留(best-effort 失败不阻断)。
/// 4. 对三件套每个文件循环:[`download::download_with_chunks`] +
///    [`verify::verify_sha256_streaming`];任一失败立即 fail-closed 返 Err。
/// 5. 构造 [`ModelPaths`] 返回。
///
/// # 同步阻塞
///
/// 不要求 caller 提供 tokio runtime;内部用 reqwest blocking + std::thread::scope。
/// `build_hub` 启动期一次性吃掉 cold-start(实测 ~280s 并发下载 + sha256 校验数秒)。
///
/// # Errors
///
/// 见 [`BootstrapError`] 5 变体;caller 应让 `vigil-hub serve` 启动失败,
/// 不要降级 NoopEngine。
pub fn ensure_model_available(target_dir: Option<&Path>) -> Result<ModelPaths, BootstrapError> {
    // v0.5 P2:用占位 Manifest;v0.5.1 注入真值(URL/sha256)
    let manifest = placeholder_manifest();
    ensure_with_manifest(target_dir, &manifest)
}

/// P0 注入防护 Slice D:确保 DeBERTa prompt-injection 分类器三件套就绪。
///
/// 与 [`ensure_model_available`](OpenAI PII NER 模型)**解耦**:走
/// [`injection_classifier_manifest`](`deberta-injection-v2/` 独立目录),两套模型的
/// `model.onnx` 不会互相覆盖。`vigil-hub serve --enable-injection-classifier` 启动期调用,
/// 失败 fail-closed(绝不静默跳过 —— 用户感知"已启用注入检测"实际未生效是安全事故)。
///
/// 本函数纯下载/校验逻辑(reqwest blocking),**不**依赖 `ort` feature;真正用模型推理的
/// [`InjectionClassifier`](crate::InjectionClassifier) 才需 `--features ort`。
pub fn ensure_injection_model_available(
    target_dir: Option<&Path>,
) -> Result<ModelPaths, BootstrapError> {
    let manifest = injection_classifier_manifest();
    ensure_with_manifest(target_dir, &manifest)
}

/// `--engine auto` 探测(ADR 0022 D4):OpenAI PII 模型三件套是否**已在本地 cache 命中**
/// (三件套 sha256 全过),**不触发任何下载 / 网络请求 / ort API 调用**。
///
/// - `Some(paths)` = 就绪;caller 可直接启用 ML —— 随后 [`ensure_model_available`] 的
///   `check_existing` 会以同款条件短路,**不会**重新下载。
/// - `None` = 缺失 / 不完整;caller 应走硬指纹降级,**绝不**在 auto 下静默触发大文件下载。
///
/// 与下载路径 **SSOT**:同 [`placeholder_manifest`] + 同 [`resolve_target_dir`] + 同
/// `verify::check_existing` sha256 判定,杜绝"探测说有、下载又重拉"的漂移。
pub fn model_cached(target_dir: Option<&Path>) -> Option<ModelPaths> {
    let manifest = placeholder_manifest();
    let dir = resolve_target_dir(target_dir, &manifest).ok()?;
    verify::check_existing(&dir, &manifest)
}

/// `--engine auto` 探测:DeBERTa 注入分类器三件套是否已本地命中(不下载)。语义同
/// [`model_cached`],走 [`injection_classifier_manifest`] 的独立目录。
pub fn injection_model_cached(target_dir: Option<&Path>) -> Option<ModelPaths> {
    let manifest = injection_classifier_manifest();
    let dir = resolve_target_dir(target_dir, &manifest).ok()?;
    verify::check_existing(&dir, &manifest)
}

/// 内部入口:接受外部 manifest,便于测试注入 stub server 的 url + 真 sha256。
///
/// 公共 [`ensure_model_available`] 只走 [`placeholder_manifest`];测试场景请用本函数。
pub(crate) fn ensure_with_manifest(
    target_dir: Option<&Path>,
    manifest: &Manifest,
) -> Result<ModelPaths, BootstrapError> {
    // 1. 解析 target_dir
    let target_dir_buf = resolve_target_dir(target_dir, manifest)?;
    std::fs::create_dir_all(&target_dir_buf).map_err(|e| BootstrapError::DiskFull {
        path: target_dir_buf.clone(),
        source: e,
    })?;

    // 2. 短路:三件套全 sha256 命中 → 0 网络请求直返
    if let Some(paths) = verify::check_existing(&target_dir_buf, manifest) {
        return Ok(paths);
    }

    // 3. 清残留(best-effort)
    let _ = verify::cleanup_partials(&target_dir_buf);

    // 4. 三件套循环下载 + sha256 校验
    let mut onnx: Option<PathBuf> = None;
    let mut tokenizer: Option<PathBuf> = None;
    let mut config: Option<PathBuf> = None;

    for f in &manifest.files {
        let mut urls: Vec<String> = Vec::with_capacity(1 + f.fallback_urls.len());
        urls.push(f.primary_url.clone());
        urls.extend(f.fallback_urls.iter().cloned());

        // 下载 + 串接(.partial.0..N → final_path),不含 sha256
        let outcome = download::download_with_chunks(
            &urls,
            &target_dir_buf,
            &f.name,
            f.size_bytes,
            manifest.chunk_count,
        )?;

        // 整文件 sha256 校验
        // 304 短路路径(downloaded=false)同样校验:确保本地 cache 未被外部篡改
        if let Err(e) = verify::verify_sha256_streaming(&outcome.final_path, &f.sha256) {
            // mismatch 立即清产物 + 残留,让下次启动重下
            verify::remove_artifact_best_effort(&outcome.final_path);
            let _ = verify::cleanup_partials(&target_dir_buf);
            return Err(e);
        }
        // sha256 通过才清残留
        let _ = verify::cleanup_partials(&target_dir_buf);

        match f.name.as_str() {
            // OpenAI Privacy Filter 用 q4f16 量化 onnx;DeBERTa 注入分类器用 FP32 model.onnx
            // (两套布局共用 ModelPaths.onnx slot)。SSOT:与 verify::check_existing 同经
            // is_onnx_artifact 判定,杜绝文件名 match 漂移。
            n if manifest::is_onnx_artifact(n) => onnx = Some(outcome.final_path),
            "tokenizer.json" => tokenizer = Some(outcome.final_path),
            "config.json" => config = Some(outcome.final_path),
            _ => {} // manifest 额外文件忽略不进 ModelPaths
        }
    }

    // 5. 三件套就绪检查(理论上 manifest 必含三个,但严格 fail-closed)
    let onnx = onnx.ok_or_else(|| BootstrapError::ManifestParse {
        source: serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "manifest missing model_q4f16.onnx entry",
        )),
    })?;
    let tokenizer = tokenizer.ok_or_else(|| BootstrapError::ManifestParse {
        source: serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "manifest missing tokenizer.json entry",
        )),
    })?;
    let config = config.ok_or_else(|| BootstrapError::ManifestParse {
        source: serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "manifest missing config.json entry",
        )),
    })?;

    Ok(ModelPaths {
        onnx,
        tokenizer,
        config,
    })
}

/// 默认 target_dir:`<data_local>/vigil/models/<model_name>-<version>/`。
/// caller 显式传 Some 直返;dirs::data_local_dir 失败转 DiskFull 而非 panic。
fn resolve_target_dir(
    caller: Option<&Path>,
    manifest: &Manifest,
) -> Result<PathBuf, BootstrapError> {
    if let Some(p) = caller {
        return Ok(p.to_path_buf());
    }
    let base = dirs::data_local_dir().ok_or_else(|| BootstrapError::DiskFull {
        path: PathBuf::from("<no data_local_dir>"),
        source: std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "dirs::data_local_dir() returned None",
        ),
    })?;
    Ok(base
        .join("vigil")
        .join("models")
        .join(format!("{}-{}", manifest.model_name, manifest.version)))
}
