//! `vigil-hub model install|status`:ML 模型(隐私 PII NER + DeBERTa 注入分类器)下载/状态。
//!
//! 这是「安装模型支持」的 turnkey 入口 —— 此前只有 `serve --engine ml` 启动期顺带下载,没有独立
//! 命令。装好后常驻 daemon([`crate::daemon`])即可暖载它们,让 hook 主防护路径跑 ML PII(ADR 0024)。
//! turnkey 全链:`model install` → `daemon start`(暖载缓存模型)→ `engine set ml` → hook 走 ML。
//!
//! **ort-gated**:模型只对 ML 变体有意义。非 ort 构建 → 报错指向 ML 变体(`vigil-cli-ml-*`),
//! **绝不**静默假装成功。下载复用已验证的 `vigil_redaction::ensure_*_model_available`
//! (16-chunk byte-range 并发 + sha256 校验 + ETag 304;ADR 0012,内部原子落盘)。

/// `model install [--privacy] [--injection]`:下载模型。两者都未指定 = 都装(最常见诉求「装上 ML」)。
///
/// fail-closed:任一下载失败(网络 / sha256 不符)→ `Err`,不留半截缓存假成功(`ensure_*` 内部
/// 原子落盘 + 校验)。已缓存则 `ensure_*` 命中 ETag 304 秒回(幂等,重跑安全)。
pub fn run_install(privacy: bool, injection: bool) -> Result<(), String> {
    let (do_privacy, do_injection) = if !privacy && !injection {
        (true, true) // 都未指定 → 默认两者都装
    } else {
        (privacy, injection)
    };

    #[cfg(not(feature = "ort"))]
    {
        let _ = (do_privacy, do_injection);
        Err(
            "this build has no ML support (hard-fingerprint only). Install the ML variant \
             (vigil-cli-ml-*) to download privacy/injection models."
                .to_string(),
        )
    }

    #[cfg(feature = "ort")]
    {
        if do_privacy {
            println!("vigil-hub model: downloading privacy (PII) model… (~700MB, first run only)");
            let paths = vigil_redaction::ensure_model_available(None)
                .map_err(|e| format!("privacy model install failed: {e}"))?;
            println!(
                "vigil-hub model: privacy model ready at {}",
                paths.dir().display()
            );
        }
        if do_injection {
            println!(
                "vigil-hub model: downloading injection classifier model… (~700MB, first run only)"
            );
            let paths = vigil_redaction::ensure_injection_model_available(None)
                .map_err(|e| format!("injection model install failed: {e}"))?;
            println!(
                "vigil-hub model: injection classifier ready at {}",
                paths.dir().display()
            );
        }
        Ok(())
    }
}

/// `model status`:报告两个模型是否本地已缓存(daemon 暖载 / `--engine auto` best-effort 的前提)。
pub fn run_status() -> Result<(), String> {
    #[cfg(not(feature = "ort"))]
    {
        println!(
            "ML models: unsupported on this build (hard-fingerprint only). \
             Install the ML variant (vigil-cli-ml-*) to enable ML."
        );
        Ok(())
    }

    #[cfg(feature = "ort")]
    {
        let privacy = vigil_redaction::model_cached(None);
        let injection = vigil_redaction::injection_model_cached(None);
        println!(
            "privacy (PII) model:  {}",
            privacy
                .map(|p| format!("installed ({})", p.dir().display()))
                .unwrap_or_else(|| "not installed".to_string())
        );
        println!(
            "injection classifier: {}",
            injection
                .map(|p| format!("installed ({})", p.dir().display()))
                .unwrap_or_else(|| "not installed".to_string())
        );
        Ok(())
    }
}
