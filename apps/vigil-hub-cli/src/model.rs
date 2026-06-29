//! `vigil-hub model install|status`:ML 模型(隐私 PII NER + DeBERTa 注入分类器)下载/状态。
//!
//! 这是「安装模型支持」的 turnkey 入口 —— 此前只有 `serve --engine ml` 启动期顺带下载,没有独立
//! 命令。装好后常驻 daemon([`crate::daemon`])即可暖载它们,让 hook 主防护路径跑 ML PII(ADR 0024)。
//! turnkey 全链:`model install` → `daemon start`(暖载缓存模型)→ `engine set ml` → hook 走 ML。
//!
//! **ort-gated**:模型只对 ML 变体有意义。非 ort 构建 → 报错指向 ML 变体(`vigil-cli-ml-*`),
//! **绝不**静默假装成功。下载复用已验证的 `vigil_redaction::ensure_*_model_available`
//! (16-chunk byte-range 并发 + sha256 校验 + ETag 304;ADR 0012,内部原子落盘)。
//!
//! 用户直面命令,输出按系统语言本地化(i18n)。

use crate::i18n::Lang;

/// 按语言取静态文案(中 / 英并排)。
fn tr(lang: Lang, en: &'static str, zh: &'static str) -> &'static str {
    match lang {
        Lang::En => en,
        Lang::Zh => zh,
    }
}

/// `model install [--privacy] [--injection]`:下载模型。两者都未指定 = 都装(最常见诉求「装上 ML」)。
///
/// fail-closed:任一下载失败(网络 / sha256 不符)→ `Err`,不留半截缓存假成功(`ensure_*` 内部
/// 原子落盘 + 校验)。已缓存则 `ensure_*` 命中 ETag 304 秒回(幂等,重跑安全)。
pub fn run_install(lang: Lang, privacy: bool, injection: bool) -> Result<(), String> {
    let (do_privacy, do_injection) = if !privacy && !injection {
        (true, true) // 都未指定 → 默认两者都装
    } else {
        (privacy, injection)
    };

    #[cfg(not(feature = "ort"))]
    {
        let _ = (do_privacy, do_injection);
        Err(tr(
            lang,
            "this build has no ML support (hard-fingerprint rules only). Install the ML build (vigil-cli-ml-*) to download the privacy / injection models.",
            "当前版本不含 ML 支持(仅硬指纹规则)。请改用 ML 版本(vigil-cli-ml-*)再下载隐私 / 注入模型。",
        )
        .to_string())
    }

    #[cfg(feature = "ort")]
    {
        if do_privacy {
            println!(
                "{}",
                tr(
                    lang,
                    "vigil-hub model: downloading the privacy (PII) model... (~700 MB, first run only)",
                    "vigil-hub model:正在下载隐私(PII)模型…(约 700 MB,仅首次运行需要)",
                )
            );
            let paths = vigil_redaction::ensure_model_available(None).map_err(|e| match lang {
                Lang::En => format!("privacy model install failed: {e}"),
                Lang::Zh => format!("隐私模型安装失败:{e}"),
            })?;
            match lang {
                Lang::En => println!(
                    "vigil-hub model: privacy model ready at {}",
                    paths.dir().display()
                ),
                Lang::Zh => println!(
                    "vigil-hub model:隐私模型已就绪,缓存于 {}",
                    paths.dir().display()
                ),
            }
        }
        if do_injection {
            println!(
                "{}",
                tr(
                    lang,
                    "vigil-hub model: downloading the injection-classifier model... (~700 MB, first run only)",
                    "vigil-hub model:正在下载注入分类器模型…(约 700 MB,仅首次运行需要)",
                )
            );
            let paths =
                vigil_redaction::ensure_injection_model_available(None).map_err(
                    |e| match lang {
                        Lang::En => format!("injection model install failed: {e}"),
                        Lang::Zh => format!("注入模型安装失败:{e}"),
                    },
                )?;
            match lang {
                Lang::En => println!(
                    "vigil-hub model: injection classifier ready at {}",
                    paths.dir().display()
                ),
                Lang::Zh => println!(
                    "vigil-hub model:注入分类器已就绪,缓存于 {}",
                    paths.dir().display()
                ),
            }
        }
        Ok(())
    }
}

/// `model status`:报告两个模型是否本地已缓存(daemon 暖载 / `--engine auto` best-effort 的前提)。
pub fn run_status(lang: Lang) -> Result<(), String> {
    #[cfg(not(feature = "ort"))]
    {
        println!(
            "{}",
            tr(
                lang,
                "ML models: not supported by this build (hard-fingerprint rules only). Install the ML build (vigil-cli-ml-*) to enable ML.",
                "ML 模型:当前版本不支持(仅硬指纹规则)。请改用 ML 版本(vigil-cli-ml-*)以启用 ML。",
            )
        );
        Ok(())
    }

    #[cfg(feature = "ort")]
    {
        let privacy = vigil_redaction::model_cached(None);
        let injection = vigil_redaction::injection_model_cached(None);
        // 状态词本地化为「已安装(路径)/ 未安装」,比裸 true/false 更直白。
        let p_status = match (lang, privacy) {
            (Lang::En, Some(p)) => format!("installed ({})", p.dir().display()),
            (Lang::En, None) => "not installed".to_string(),
            (Lang::Zh, Some(p)) => format!("已安装({})", p.dir().display()),
            (Lang::Zh, None) => "未安装".to_string(),
        };
        let i_status = match (lang, injection) {
            (Lang::En, Some(p)) => format!("installed ({})", p.dir().display()),
            (Lang::En, None) => "not installed".to_string(),
            (Lang::Zh, Some(p)) => format!("已安装({})", p.dir().display()),
            (Lang::Zh, None) => "未安装".to_string(),
        };
        println!(
            "{}{}",
            tr(lang, "privacy (PII) model:  ", "隐私(PII)模型:  "),
            p_status
        );
        println!(
            "{}{}",
            tr(lang, "injection classifier: ", "注入分类器:      "),
            i_status
        );
        Ok(())
    }
}
