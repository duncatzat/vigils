//! CLI 输出国际化(i18n):按系统语言选择中 / 英文案。
//!
//! # 为什么需要
//! `vigil-hub` 的帮助 / 提示原先中英混杂且面向开发者(满是 ADR 引用、`fail-closed`、
//! `default-deny` 等内部黑话),终端用户难以"感受到命令的意义"。本模块按**系统语言**
//! (Windows 用户默认 UI 语言 / Unix `LANG` 等)选择更贴切的中 / 英输出,并集中管理文案。
//!
//! # 结构(三类文案各取所宜)
//! - **命令帮助**([`help`] 子模块):整段、随命令演进 —— 每命令把中 / 英 about /
//!   long_about / arg-help 内联并排,便于对照与同步;运行时 [`help::localize`] 改写
//!   clap [`Command`](clap::Command),**绝不**改子命令名 / flag(那是解析契约)。
//! - **零散运行时短消息**(本模块 [`Msg`] + [`t`]):跨多处复用的提示 / 结果 / 错误 ——
//!   用穷举目录集中,编译器守门(新增 [`Msg`] variant 必补全两语言,否则不编译)。
//! - **整屏首跑界面**([`crate::quickstart`] / [`crate::demo`]):每屏中 / 英整段并排,
//!   内联在各自模块(随屏演进,内联比拆散成几十个 key 更易保持同步)。
//!
//! # 语言选择
//! [`Lang::detect`]:`VIGIL_LANG` 环境变量(`en` / `zh` / `auto`)覆盖 → 系统 locale
//! (`sys-locale`)→ 回落 [`Lang::En`]。纯解析逻辑在 [`Lang::from_tag`] / [`resolve_lang`],
//! 与 IO 分离以便测试。

pub mod help;

/// 受支持的输出语言。
///
/// 新增语言:加 variant,编译器会在 [`t`]、[`help`]、`quickstart`、`demo` 各处的穷举
/// `match lang` 强制提示需补全文案。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    /// 英文(默认 / 回落)。
    #[default]
    En,
    /// 简体中文。
    Zh,
}

impl Lang {
    /// 从 BCP-47 风格 locale 串解析语言:`zh-CN` / `zh_CN` / `zh` / `en-US` / `en` …
    ///
    /// 只看**主语言子标签**(`-` / `_` 之前),大小写不敏感;不识别 → `None`
    /// (交由调用方回落)。
    pub fn from_tag(tag: &str) -> Option<Lang> {
        let primary = tag
            .split(['-', '_'])
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        match primary.as_str() {
            "zh" => Some(Lang::Zh),
            "en" => Some(Lang::En),
            _ => None,
        }
    }

    /// 检测有效输出语言:`VIGIL_LANG` 覆盖 → 系统 locale → [`Lang::En`] 回落。
    ///
    /// 副作用(读环境变量 / 探测系统 locale)隔离在此;纯决议逻辑见 [`resolve_lang`]。
    pub fn detect() -> Lang {
        let override_ = std::env::var("VIGIL_LANG").ok();
        let system = sys_locale::get_locale();
        resolve_lang(override_.as_deref(), system.as_deref())
    }
}

/// 纯函数语言决议(无 IO,便于测试)。
///
/// - `override_`:`VIGIL_LANG` 值。`en` / `zh` 强制对应语言;`auto` / 空 / 仅空白 →
///   回落系统检测。**显式但不识别**的覆盖(如 `fr`)→ [`Lang::En`](尊重"我要覆盖"
///   的意图,绝不再回落系统 —— 否则"我设了 en 却因系统中文出中文"会很意外)。
/// - `system`:系统 locale 串(如 `zh-CN`)。识别失败 / 缺失 → [`Lang::En`]。
pub fn resolve_lang(override_: Option<&str>, system: Option<&str>) -> Lang {
    if let Some(o) = override_ {
        let o = o.trim();
        if !o.is_empty() && !o.eq_ignore_ascii_case("auto") {
            return Lang::from_tag(o).unwrap_or(Lang::En);
        }
    }
    system.and_then(Lang::from_tag).unwrap_or(Lang::En)
}

/// 零散运行时短消息目录(结果 / 提示 / 错误)。借用字段避免复制调用方数据;
/// 渲染见 [`t`]。新增 variant 必在 [`t`] 的穷举 match 补全两语言。
#[derive(Debug)]
pub enum Msg<'a> {
    /// 无子命令时的欢迎 + 引导(`version` = 真实发布版本号,如 `v0.1.7`)。
    NoCommandHint {
        /// 发布版本号(含前缀 `v`)。
        version: &'a str,
    },
    /// 统一的"某子命令失败"前缀 + 错误体。
    CommandFailed {
        /// 子命令展示名(如 `serve` / `setup --all`)。
        command: &'a str,
        /// 底层错误文本。
        error: &'a str,
    },
    /// `serve` 缺少必需的 `--stdio`。
    ServeNeedsStdio,
    /// `serve` 已作为 stdio MCP server 启动(`pid` = 进程号)。
    ServeStarted {
        /// 本进程 PID。
        pid: u32,
    },
    /// `serve` 检测到 stdin 关闭,正常退出。
    ServeStopped,
    /// `quickstart` 无法定位用户主目录。
    QuickstartNoHome,
    /// 无法定位某组件的配置目录(`component` = `posture` / `engine`)。
    ConfigDirNotFound {
        /// 组件名。
        component: &'a str,
    },
    /// 写配置失败(`component` = `posture` / `engine`)。
    ConfigStoreFailed {
        /// 组件名。
        component: &'a str,
        /// 底层错误文本。
        error: &'a str,
    },
    /// 姿态档已切换(`old`→`new`,均为 `low` / `medium` / `high`)。
    PostureChanged {
        /// 原档位。
        old: &'a str,
        /// 新档位。
        new: &'a str,
    },
    /// 引擎模式已切换(`old`→`new`,均为 `hardfp` / `ml` / `auto`)。
    EngineChanged {
        /// 原模式。
        old: &'a str,
        /// 新模式。
        new: &'a str,
    },
    /// 无法定位审计账本(给 `--ledger` 或设 `VIGIL_LEDGER_PATH`)。
    LedgerNotFound,
    /// 打开审计账本失败。
    LedgerOpenFailed {
        /// 底层错误文本。
        error: &'a str,
    },
    /// `verify`:账本文件不存在(只读,绝不创建)。
    LedgerMissingForVerify {
        /// 期望的账本路径。
        path: &'a str,
    },
    /// `checkpoint`:已锚定链头(`event_id` 事件号,`head` 哈希前缀,`path` sidecar 路径)。
    CheckpointAnchored {
        /// 锚定到的事件号。
        event_id: i64,
        /// 链头哈希前缀(展示用)。
        head: &'a str,
        /// 锚点 sidecar 文件路径。
        path: &'a str,
    },
    /// `checkpoint`:把锚点文件设为 append-only / 异地同步的安全建议。
    CheckpointTip,
    /// `checkpoint`:无新事件可锚定(账本空 / 自上次锚点无新增)。
    CheckpointNothing,
    /// `verify`:链内一致且已锚定(`checkpoints` 锚点数,`through` 覆盖到的事件号)。
    VerifyValidAnchored {
        /// 锚点数量。
        checkpoints: usize,
        /// 已覆盖到的事件号。
        through: i64,
    },
    /// `verify`:对锚点能力的诚实框定(非 tamper-proof)。
    VerifyAnchorNote,
    /// `verify`:链内一致但尚无锚点。
    VerifyValidUnanchored,
    /// `verify`:提示运行 `checkpoint` 以防整链重写。
    VerifyRunCheckpointHint,
    /// `verify`:链在某事件号断裂(内部篡改)。
    VerifyChainBroken {
        /// 断裂处事件号。
        event_id: i64,
    },
    /// `verify`:锚点比对不匹配(链前缀可能被重写)。
    VerifyCheckpointMismatch {
        /// 不匹配处事件号。
        event_id: i64,
    },
    /// `verify`:锚点存储损坏。
    VerifyStoreCorrupt {
        /// 损坏原因。
        reason: &'a str,
    },
}

/// 渲染一条 [`Msg`] 为目标语言的整行文本(供 `println!` / `eprintln!` 直接输出)。
///
/// 外层 match `msg`、内层 match `lang`:每 variant 的中 / 英并排,便于对照与同步。
pub fn t(lang: Lang, msg: Msg<'_>) -> String {
    match msg {
        Msg::NoCommandHint { version } => match lang {
            Lang::En => format!(
                "vigil-hub {version} — a local security gateway for your AI agents.\n\
                 New here? Run `vigil-hub quickstart` to see what's protected on this\n\
                 machine, or `vigil-hub --help` to list every command."
            ),
            Lang::Zh => format!(
                "vigil-hub {version} —— 守护 AI agent 的本地安全网关。\n\
                 第一次用?运行 `vigil-hub quickstart` 看看本机的防护现状,\n\
                 或用 `vigil-hub --help` 查看全部命令。"
            ),
        },
        Msg::CommandFailed { command, error } => match lang {
            Lang::En => format!("vigil-hub {command} failed: {error}"),
            Lang::Zh => format!("vigil-hub {command} 执行失败:{error}"),
        },
        Msg::ServeNeedsStdio => match lang {
            Lang::En => {
                "vigil-hub serve: --stdio is required (stdio is the only transport for now)".into()
            }
            Lang::Zh => "vigil-hub serve:必须显式加 --stdio(目前仅支持 stdio 通道)".into(),
        },
        Msg::ServeStarted { pid } => match lang {
            Lang::En => format!(
                "vigil-hub serve: listening as a stdio MCP server (PID {pid}). \
                 Point your agent at it; press Ctrl-C or close stdin to stop."
            ),
            Lang::Zh => format!(
                "vigil-hub serve:已作为 stdio MCP server 启动(PID {pid})。\
                 把你的 agent 指向它即可;Ctrl-C 或关闭 stdin 即停止。"
            ),
        },
        Msg::ServeStopped => match lang {
            Lang::En => "vigil-hub serve: stdin closed, shutting down.".into(),
            Lang::Zh => "vigil-hub serve:stdin 已关闭,正在退出。".into(),
        },
        Msg::QuickstartNoHome => match lang {
            Lang::En => "vigil-hub quickstart: cannot locate your home directory.".into(),
            Lang::Zh => "vigil-hub quickstart:无法定位你的用户主目录。".into(),
        },
        Msg::ConfigDirNotFound { component } => match lang {
            Lang::En => {
                format!("vigil-hub {component}: cannot locate the {component} config directory.")
            }
            Lang::Zh => format!("vigil-hub {component}:无法定位 {component} 配置目录。"),
        },
        Msg::ConfigStoreFailed { component, error } => match lang {
            Lang::En => format!("vigil-hub {component}: failed to save the config ({error})."),
            Lang::Zh => format!("vigil-hub {component}:写入配置失败({error})。"),
        },
        Msg::PostureChanged { old, new } => match lang {
            Lang::En => format!("Security posture: {old} -> {new}"),
            Lang::Zh => format!("安全姿态:{old} -> {new}"),
        },
        Msg::EngineChanged { old, new } => match lang {
            Lang::En => format!("Detection engine: {old} -> {new}"),
            Lang::Zh => format!("检测引擎:{old} -> {new}"),
        },
        Msg::LedgerNotFound => match lang {
            Lang::En => {
                "Cannot locate the audit ledger (pass --ledger or set VIGIL_LEDGER_PATH).".into()
            }
            Lang::Zh => "无法定位审计账本(请给 --ledger,或设置 VIGIL_LEDGER_PATH)。".into(),
        },
        Msg::LedgerOpenFailed { error } => match lang {
            Lang::En => format!("Failed to open the audit ledger: {error}"),
            Lang::Zh => format!("打开审计账本失败:{error}"),
        },
        Msg::LedgerMissingForVerify { path } => match lang {
            Lang::En => format!(
                "Audit ledger not found: {path} — check the --ledger path \
                 (verify is read-only and never creates a ledger)."
            ),
            Lang::Zh => format!(
                "审计账本不存在:{path} —— 请核对 --ledger 路径\
                 (verify 只读,绝不会凭空创建账本)。"
            ),
        },
        Msg::CheckpointAnchored {
            event_id,
            head,
            path,
        } => match lang {
            Lang::En => {
                format!("✓ anchored a checkpoint at event #{event_id} (head {head}…) → {path}")
            }
            Lang::Zh => format!("✓ 已在事件 #{event_id} 处锚定链头(head {head}…)→ {path}"),
        },
        Msg::CheckpointTip => match lang {
            Lang::En => "  tip: keep that file append-only (chattr +a) or synced offsite, so a \
                 full-history rewrite can't also forge the anchor."
                .into(),
            Lang::Zh => "  提示:把锚点文件设为 append-only(chattr +a)或异地同步,\
                 这样即便有人整体重写历史,也伪造不了锚点。"
                .into(),
        },
        Msg::CheckpointNothing => match lang {
            Lang::En => {
                "Nothing to anchor (the ledger is empty, or there are no new events since the last \
                 checkpoint)."
                    .into()
            }
            Lang::Zh => "无需锚定(账本为空,或自上次锚点以来没有新事件)。".into(),
        },
        Msg::VerifyValidAnchored {
            checkpoints,
            through,
        } => match lang {
            Lang::En => format!(
                "✓ the audit chain is internally consistent AND anchored: {checkpoints} \
                 checkpoint(s), through event #{through}."
            ),
            Lang::Zh => {
                format!("✓ 审计链内部一致,且已锚定:{checkpoints} 个锚点,覆盖到事件 #{through}。")
            }
        },
        Msg::VerifyAnchorNote => match lang {
            Lang::En => "  (the anchor catches a database-only full-history rewrite while the \
                 checkpoint file is intact — it is not a tamper-proof guarantee.)"
                .into(),
            Lang::Zh => "  (锚点能在锚点文件完好时,检出仅针对数据库的整链重写 —— \
                 但这不是绝对防篡改的保证。)"
                .into(),
        },
        Msg::VerifyValidUnanchored => match lang {
            Lang::En => {
                "✓ the audit chain is internally consistent; ⚠ no checkpoints found.".into()
            }
            Lang::Zh => "✓ 审计链内部一致;⚠ 但尚未找到任何锚点。".into(),
        },
        Msg::VerifyRunCheckpointHint => match lang {
            Lang::En => {
                "  run `vigil-hub checkpoint` to anchor against a full-history rewrite.".into()
            }
            Lang::Zh => "  运行 `vigil-hub checkpoint` 打锚点,以防整链重写。".into(),
        },
        Msg::VerifyChainBroken { event_id } => match lang {
            Lang::En => {
                format!("✗ the audit chain is BROKEN at event #{event_id} — tampering detected.")
            }
            Lang::Zh => format!("✗ 审计链在事件 #{event_id} 处断裂 —— 检测到篡改。"),
        },
        Msg::VerifyCheckpointMismatch { event_id } => match lang {
            Lang::En => format!(
                "✗ checkpoint MISMATCH at event #{event_id} — the chain prefix may have been \
                 rewritten."
            ),
            Lang::Zh => format!("✗ 锚点在事件 #{event_id} 处不匹配 —— 链前缀可能已被重写。"),
        },
        Msg::VerifyStoreCorrupt { reason } => match lang {
            Lang::En => format!("✗ the checkpoint store is corrupt: {reason}"),
            Lang::Zh => format!("✗ 锚点存储已损坏:{reason}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_tag_parses_primary_subtag_case_insensitively() {
        for t in ["zh", "zh-CN", "zh_CN", "ZH-Hans-CN", "zh-Hant"] {
            assert_eq!(Lang::from_tag(t), Some(Lang::Zh), "tag {t} should be Zh");
        }
        for t in ["en", "en-US", "en_GB", "EN", "en-Latn-US"] {
            assert_eq!(Lang::from_tag(t), Some(Lang::En), "tag {t} should be En");
        }
        for t in ["fr", "de-DE", "ja_JP", "", "x"] {
            assert_eq!(Lang::from_tag(t), None, "tag {t} should be unrecognized");
        }
    }

    #[test]
    fn resolve_lang_override_beats_system() {
        // 显式 en/zh 覆盖系统。
        assert_eq!(resolve_lang(Some("zh"), Some("en-US")), Lang::Zh);
        assert_eq!(resolve_lang(Some("en"), Some("zh-CN")), Lang::En);
        // 大小写 / 带区域子标签同样识别。
        assert_eq!(resolve_lang(Some("ZH-cn"), Some("en-US")), Lang::Zh);
    }

    #[test]
    fn resolve_lang_auto_or_empty_falls_back_to_system() {
        assert_eq!(resolve_lang(Some("auto"), Some("zh-CN")), Lang::Zh);
        assert_eq!(resolve_lang(Some(""), Some("zh-CN")), Lang::Zh);
        assert_eq!(resolve_lang(Some("  "), Some("zh-CN")), Lang::Zh);
        assert_eq!(resolve_lang(None, Some("zh-CN")), Lang::Zh);
    }

    #[test]
    fn resolve_lang_unrecognized_override_pins_english_not_system() {
        // 显式但不识别的覆盖 → En,**不**回落系统中文(尊重"我要覆盖"的意图)。
        assert_eq!(resolve_lang(Some("fr"), Some("zh-CN")), Lang::En);
    }

    #[test]
    fn resolve_lang_defaults_to_english_when_nothing_known() {
        assert_eq!(resolve_lang(None, None), Lang::En);
        assert_eq!(resolve_lang(None, Some("ja-JP")), Lang::En);
        assert_eq!(resolve_lang(Some("auto"), Some("ja-JP")), Lang::En);
    }

    /// 代表性 [`Msg`] 在两语言都渲染出非空、且中 ≠ 英(防漏译 / 复制粘贴遗漏)。
    /// 穷举完整性已由 [`t`] 的 match 编译期强制;此处做内容 sanity。
    #[test]
    fn representative_messages_render_nonempty_and_differ_per_lang() {
        // [`Msg`] 借用字段、无 `Clone`,而 [`t`] 会消费它;用工厂闭包为两语言各现造一次
        //(字符串字面量是 `'static`,故 `Msg<'static>` 成立)。
        let cases: [fn() -> Msg<'static>; 4] = [
            || Msg::NoCommandHint { version: "v9.9.9" },
            || Msg::CommandFailed {
                command: "serve",
                error: "boom",
            },
            || Msg::PostureChanged {
                old: "low",
                new: "high",
            },
            || Msg::VerifyChainBroken { event_id: 7 },
        ];
        for make in cases {
            let en = t(Lang::En, make());
            let zh = t(Lang::Zh, make());
            assert!(!en.trim().is_empty(), "EN render must be non-empty");
            assert!(!zh.trim().is_empty(), "ZH render must be non-empty");
            assert_ne!(en, zh, "EN and ZH must differ for the same message");
        }
    }
}
