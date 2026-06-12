//! sha256 整文件校验 + .partial.* 清扫 + chunk 串接 + 三件套就绪检查。
//!
//! # 关键不变量(ADR 0012 §3.4 / §F-2)
//!
//! 1. **整文件 sha256**:manifest 不含 chunk 级 hash;所有 chunk 串接为最终文件后,
//!    用 sha2 流式分块(64 KB)update + finalize 算 sha256,与 manifest 期望值比较。
//!    mismatch 立即删除产物 + 清残留,返 `Sha256Mismatch`。
//! 2. **简化恢复语义**:不做 chunk 级 resume;残留即清扫,失败即重下整文件。
//!    牺牲少量带宽换语义正确性(v0.5.x 可加 chunk bitmap + fs2 file lock)。
//! 3. **流式校验**:大模型(数百 MB)用 BufReader + 64 KB buffer + Sha256::update,
//!    避免一次性 load 进内存。

use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::error::BootstrapError;
use super::manifest::{is_onnx_artifact, Manifest, ModelPaths};

/// sha256 流式校验缓冲(64 KB)。大文件不一次性 load,内存占用恒定 ~64 KB。
const HASH_READ_BUF: usize = 64 * 1024;

/// 流式 sha256 校验。
///
/// 读取 `path` 全部字节,分块(64 KB)更新 [`Sha256`],finalize 后 hex-encode 与
/// `expected_hex`(小写)比较。任何 io 失败转 [`BootstrapError::DiskFull`];
/// hash 不符返 [`BootstrapError::Sha256Mismatch`]。
pub fn verify_sha256_streaming(path: &Path, expected_hex: &str) -> Result<(), BootstrapError> {
    let f = File::open(path).map_err(|e| BootstrapError::DiskFull {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mut reader = BufReader::with_capacity(HASH_READ_BUF, f);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_READ_BUF];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| BootstrapError::DiskFull {
                path: path.to_path_buf(),
                source: e,
            })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let actual_hex = hex::encode(hasher.finalize());
    if !actual_hex.eq_ignore_ascii_case(expected_hex) {
        return Err(BootstrapError::Sha256Mismatch {
            expected: expected_hex.to_string(),
            actual: actual_hex,
        });
    }
    Ok(())
}

/// 清扫 `target_dir` 下所有 `.partial.*` 残留(best-effort:单文件 remove 失败不阻断)。
///
/// 触发时机:
/// - 启动时检三件套残留;
/// - 单 URL 下载失败切 fallback 前;
/// - sha256 mismatch 删除产物后。
pub fn cleanup_partials(target_dir: &Path) -> std::io::Result<()> {
    let entries = match fs::read_dir(target_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for ent in entries.flatten() {
        let name = ent.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with(".partial.") {
            // best-effort:单文件失败不阻断后续清扫
            let _ = fs::remove_file(ent.path());
        }
    }
    Ok(())
}

/// 串接 `.partial.0..chunk_count` 为最终 `target_dir/<output_name>`。
///
/// 流程:打开新文件 BufWriter → 顺序读每个 partial 字节流 → 写入 → flush。
/// 串接成功后**不**自动 cleanup_partials(由 caller 在 sha256 校验通过后再清,失败时
/// 也在 mismatch 分支自己清,语义更显式)。
///
/// 任一 partial 缺失 / 读失败 / 写失败 → 立即返 `DiskFull` 让 caller 走 fallback。
pub fn assemble_chunks(
    target_dir: &Path,
    chunk_count: u32,
    output_name: &str,
) -> Result<PathBuf, BootstrapError> {
    let out_path = target_dir.join(output_name);
    let out_file = File::create(&out_path).map_err(|e| BootstrapError::DiskFull {
        path: out_path.clone(),
        source: e,
    })?;
    let mut writer = BufWriter::with_capacity(HASH_READ_BUF, out_file);

    for idx in 0..chunk_count {
        let partial_path = target_dir.join(format!(".partial.{idx}"));
        let f = File::open(&partial_path).map_err(|e| BootstrapError::DiskFull {
            path: partial_path.clone(),
            source: e,
        })?;
        let mut reader = BufReader::with_capacity(HASH_READ_BUF, f);
        std::io::copy(&mut reader, &mut writer).map_err(|e| BootstrapError::DiskFull {
            path: partial_path,
            source: e,
        })?;
    }
    writer.flush().map_err(|e| BootstrapError::DiskFull {
        path: out_path.clone(),
        source: e,
    })?;
    // BufWriter drop 会再 flush 一次,这里显式调让错误立即抛
    drop(writer);
    Ok(out_path)
}

/// 启动时短路:三件套全部存在 + 全部 sha256 命中 → 返 `Some(ModelPaths)` 跳过下载。
///
/// 任一文件缺失 / sha256 mismatch / io 错误 → 返 `None`,由上层 cleanup_partials 后
/// 走完整下载。
///
/// **不**返 Result(只是短路决策,失败信息无 actionable 价值;真正的 mismatch 在
/// 下载完成后的 verify 阶段以 Sha256Mismatch 抛出)。
pub fn check_existing(target_dir: &Path, manifest: &Manifest) -> Option<ModelPaths> {
    if !target_dir.exists() {
        return None;
    }
    let mut onnx: Option<PathBuf> = None;
    let mut tokenizer: Option<PathBuf> = None;
    let mut config: Option<PathBuf> = None;

    for f in &manifest.files {
        let path = target_dir.join(&f.name);
        if !path.exists() {
            return None;
        }
        // 占位 manifest sha256 = "<placeholder-v0.5.1>" 必然 mismatch → 短路返 None
        // 走完整下载;真 manifest 注入后才能命中此路径
        if verify_sha256_streaming(&path, &f.sha256).is_err() {
            return None;
        }
        match f.name.as_str() {
            // SSOT:与 mod.rs 下载 assign 同经 is_onnx_artifact —— 此前只认 model_q4f16.onnx,
            // 漏 deberta 的 model.onnx → check_existing 恒返 None → 每次 serve 重下载 738MB。
            n if is_onnx_artifact(n) => onnx = Some(path),
            "tokenizer.json" => tokenizer = Some(path),
            "config.json" => config = Some(path),
            _ => {} // manifest 含其它额外文件不影响三件套就绪判定
        }
    }

    Some(ModelPaths {
        onnx: onnx?,
        tokenizer: tokenizer?,
        config: config?,
    })
}

/// 删除单个产物文件(若存在),用于 sha256 mismatch 后的清理。
/// best-effort:不存在 / 失败均吞掉,只对调用者承诺"已尝试"。
pub fn remove_artifact_best_effort(path: &Path) {
    let _ = fs::remove_file(path);
}
