//! 三档安全姿态(PostureProfile)数据模型 + 持久化 + 审计(TASK-003,仅模型层)。
//!
//! 为 [`crate::hook`](`vigil-hub hook`)提供「低/中/高」三档姿态的**决策表 SSOT**:
//! 后续增量(TASK-004)由主进程接线消费,本模块只负责模型 + 持久化 + 审计,不改 hook 行为。
//!
//! # 三档语义
//! - **Low(默认)**:只拦极高风险(裸 secret / 账本篡改),占位符等无害文本放行 ——
//!   新用户零摩擦,硬底线仍在。
//! - **Medium**:极高风险拦,占位符类交用户确认(Ask)。
//! - **High**:现行 α1 enforce 全量(占位符在原生工具也 deny)。
//!
//! # 安全不变量(硬底线,不可被档位降级)
//! [`RiskClass::RawSecret`] 与 [`RiskClass::LedgerTamper`] 在**任何**档位都是
//! [`PostureAction::Deny`] —— 姿态只调节"占位符类"的体验摩擦,绝不打开真凭据外泄 /
//! 审计篡改的口子。[`decide`] 用穷举 match(无 `_` 通配)固化这张表,新增档位 / 风险类
//! 必须显式补全,编译器守门。
//!
//! **覆盖边界(诚实声明)**:本表只约束"被分类到该风险类的事件"。`RawSecret` 已由
//! `hook::run` 的硬指纹扫描接线生效;`LedgerTamper` 目前**仅决策表预留** ——
//! hook 生产路径尚无"工具试图写账本文件"的检测逻辑,接线前不产生实际拦截
//! (见 [`RiskClass::LedgerTamper`] 注释,feedback「doc promise scope」)。
//!
//! # fail-closed 持久化
//! 配置文件不存在 → Low(默认档);文件**存在但损坏 / 档位未知 / version 不识别** →
//! 收敛 **High** + warning(配置损坏时宁可更严不可更松)。warning 文案**不回显文件原文**
//! (只说 malformed/unknown + 路径),见 feedback「untrusted input not in errors」。
//!
//! # 审计 = best-effort
//! [`audit_posture_switch`] 照 hook.rs `audit_deny` 模式:账本不可用只 eprintln,
//! 绝不 panic / 不返回 Err —— 审计失败不 brick 姿态切换本身。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::json;

use vigil_audit::Ledger;

// ── 常量(与 setup.rs 的默认 ledger 目录约定对齐:同一 `<data_local>/Vigil/` 目录)──
const VIGIL_SUBDIR: &str = "Vigil";
const POSTURE_FILENAME: &str = "posture.json";
/// 配置文件 schema 版本。不识别的版本(过新 / 过旧)一律 fail-closed 收敛 High,
/// 不猜测语义(未来版本可能改字段含义,按旧语义解读可能更松)。
const POSTURE_FILE_VERSION: u64 = 1;

/// 三档安全姿态。`Low` = 默认(只拦极高风险),`High` = 现行 α1 enforce 全量。
///
/// serde 名固定为 `"low"` / `"medium"` / `"high"`(snake_case),是配置文件与审计
/// payload 的对外契约 —— 有 serde 名稳定性测试守门,改名即破坏已落盘配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum PostureProfile {
    /// 默认档:只拦极高风险,占位符类放行(交工具自然失败)。
    #[default]
    Low,
    /// 中档:极高风险拦,占位符类交用户确认。
    Medium,
    /// 高档:现行 enforce 全量(α1 行为)。
    High,
}

impl PostureProfile {
    /// 稳定的小写名(与 serde 名一致),用于审计摘要 / CLI 回显。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

impl std::fmt::Display for PostureProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// hook 侧可识别的风险类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskClass {
    /// 裸硬指纹 secret 出现在**任何**工具入参(极高风险:真凭据外泄)。
    RawSecret,
    /// 工具调用试图写/改审计账本文件(极高风险:抹审计轨迹)。
    ///
    /// **预留 variant**:决策表已固化"任何档位恒 Deny",但 hook 生产路径目前
    /// 没有把任何事件分类到本风险类的检测逻辑(识别账本路径写操作待后续增量)。
    /// 在接线前本 variant 不产生实际拦截 —— 文档/注释不得宣称该防护已生效。
    LedgerTamper,
    /// `secret://` / `vigil://redact/` 占位符出现在**非 MCP 原生**工具
    /// (占位符本身是无害文本,风险只在"未解析就执行"的体验/语义层)。
    PlaceholderNative,
    /// **灾难级** shell 命令:不可逆 × 全系统爆炸半径(`rm -rf /`·`~`·`$HOME`、fork bomb、
    /// `dd of=/dev/*`、`mkfs`、`curl … | sh` 远程直灌 shell)。由 [`crate::command_guard`]
    /// 分类。**硬底线**:任何档位恒 Deny(类比 [`RiskClass::RawSecret`])—— agent 无论因意图
    /// 漂移 / 注入 / 参数事故产生此类动作,都不放行。
    DestructiveCatastrophic,
    /// **高危** shell 命令:持久化 / 自启(shell rc、cron、systemd、launchd、authorized_keys、
    /// Windows Run 键)、项目根外的递归删除、`rm -rf $VAR/`(空变量展开事故)。姿态分级:
    /// Low/Medium=Ask(重新确认,Claude 下即使「允许所有」也会弹),High=Deny。可确认 = 误报可恢复。
    DangerousCommand,
}

/// 姿态决策动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostureAction {
    /// 放行。
    Allow,
    /// 交用户确认。
    Ask,
    /// 拦截。
    Deny,
}

/// 决策表(SSOT,纯函数):给定姿态档位 × 风险类别 → 动作。
///
/// 穷举 match、**无 `_` 通配** —— 新增 [`PostureProfile`] / [`RiskClass`] variant 时
/// 编译器强制补全本表,避免新风险类静默落入某个默认分支(fail-open)。
pub fn decide(profile: PostureProfile, risk: RiskClass) -> PostureAction {
    match (risk, profile) {
        // 硬底线(安全不变量):裸 secret / 账本篡改在任何档位都 Deny,不可被档位降级。
        (
            RiskClass::RawSecret,
            PostureProfile::Low | PostureProfile::Medium | PostureProfile::High,
        ) => PostureAction::Deny,
        (
            RiskClass::LedgerTamper,
            PostureProfile::Low | PostureProfile::Medium | PostureProfile::High,
        ) => PostureAction::Deny,
        // 占位符 × 原生工具:Low 放行(无害文本,交工具自然失败);Medium 交用户确认;
        // High 维持现行 α1 的 fail-closed deny。
        (RiskClass::PlaceholderNative, PostureProfile::Low) => PostureAction::Allow,
        (RiskClass::PlaceholderNative, PostureProfile::Medium) => PostureAction::Ask,
        (RiskClass::PlaceholderNative, PostureProfile::High) => PostureAction::Deny,
        // 灾难级 shell 命令:硬底线,任何档位恒 Deny(不可被档位降级,类比 RawSecret)。
        (
            RiskClass::DestructiveCatastrophic,
            PostureProfile::Low | PostureProfile::Medium | PostureProfile::High,
        ) => PostureAction::Deny,
        // 高危 shell 命令:Low/Medium 交确认(默认 Low 也确认 —— 「允许所有」下的backstop
        // 正是本层价值);High 收紧为 Deny。
        (RiskClass::DangerousCommand, PostureProfile::Low) => PostureAction::Ask,
        (RiskClass::DangerousCommand, PostureProfile::Medium) => PostureAction::Ask,
        (RiskClass::DangerousCommand, PostureProfile::High) => PostureAction::Deny,
    }
}

// ─────────────────── session risk 反馈环升档(P0 注入防护 Slice 2a)───────────────────
//
// 反馈环:元指令命中累加 session risk → 累积到阈值 → posture **临时**升档收紧后续工具调用。
// 升档**只**作用在 [`effective_profile`] 层(读取磁盘 base 档 + session risk → 算出有效档),
// 绝不改写磁盘 base 档,也绝不动 [`decide`] 的穷举 SSOT 表。调用方先算 effective_profile,
// 再把结果传给 decide。hook 接线是 Slice 2b(本 slice 只提供基础设施)。

/// session risk 触发自动升档的累计分阈值。
///
/// = 3 次元指令命中 × `META_INSTRUCTION_RISK_DELTA`(vigil-redaction,值 8)= 24。
/// 保守阈值:单次/双次命中(8/16)**不**升档,避免个别误报噪声触发升档摩擦;
/// 累计到 3 次才升档(注入往往是多处指令性语言,3 次是"持续可疑"的合理信号)。可调。
pub const SESSION_RISK_ESCALATION_THRESHOLD: i64 = 24;

impl PostureProfile {
    /// 升一档:Low→Medium / Medium→High / High→High(饱和,已是最严)。
    ///
    /// 用于 session risk 累积越阈时把有效档收紧一级;High 已是上限,饱和不再上升。
    pub fn escalate(self) -> Self {
        match self {
            Self::Low => Self::Medium,
            Self::Medium => Self::High,
            Self::High => Self::High,
        }
    }
}

/// 给定磁盘 base 档 + 当前 session risk,算出**有效**姿态档(供 `decide` 消费)。
///
/// session risk ≥ [`SESSION_RISK_ESCALATION_THRESHOLD`] → base 升一档;否则用 base 原档。
/// 这是升档的**唯一**入口 —— 不改 base 档持久化、不改 `decide` SSOT;调用方先调本函数
/// 拿有效档,再 `decide(有效档, risk_class)`。
pub fn effective_profile(base: PostureProfile, session_risk: i64) -> PostureProfile {
    if session_risk >= SESSION_RISK_ESCALATION_THRESHOLD {
        base.escalate()
    } else {
        base
    }
}

// ─────────────────────────── 持久化 ───────────────────────────

/// 磁盘上的 posture 配置 shape:`{"version":1,"posture":"low"}`。
///
/// **不**加 `deny_unknown_fields`:同 version 内允许未来追加字段(前向兼容);
/// 破坏性语义变更走 version 提升,由 [`load_posture`] 的版本检查 fail-closed 兜住。
#[derive(Debug, Serialize, Deserialize)]
struct PostureFileV1 {
    version: u64,
    posture: PostureProfile,
}

/// [`load_posture`] 的结果:解析出的档位 + 可选 warning(配置损坏被收敛 High 时说明原因)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedPosture {
    /// 生效的姿态档位。
    pub profile: PostureProfile,
    /// 非 None = 配置异常已 fail-closed 收敛 High;文案只含原因类别 + 路径,**不含文件原文**。
    pub warning: Option<String>,
}

/// 默认 posture 配置路径:`<data_local>/Vigil/posture.json`,与默认账本
/// (`setup::default_ledger_path` 的 `<data_local>/Vigil/ledger.sqlite3`)同目录。
/// 无法定位本机数据目录(headless 等)→ `None`,由调用方决定如何提示。
///
/// 注意:`VIGIL_LEDGER_PATH` 只重定向**账本文件**,不挪 posture 配置 —— posture 是
/// 本机级姿态开关,锚定 canonical 目录;调用方要自定义位置直接传显式 path。
pub fn default_posture_path() -> Option<PathBuf> {
    dirs::data_local_dir().map(|b| b.join(VIGIL_SUBDIR).join(POSTURE_FILENAME))
}

/// 读取 posture 配置。**永不 panic / 永不 Err** —— 一切异常都收敛为确定档位:
///
/// - 文件不存在 → [`PostureProfile::Low`](默认档),无 warning。
/// - 文件存在但读取失败 / 非法 JSON / 档位未知 / version 不识别 → **fail-closed 收敛
///   [`PostureProfile::High`]** + warning(配置损坏时宁可更严不可更松)。
pub fn load_posture(path: &Path) -> LoadedPosture {
    // fail-closed 收敛分支共用的 warning 文案:只含原因类别 + 路径,绝不回显文件内容原文
    // (内容不可信,可能携带 secret / 注入串;见 feedback「untrusted input not in errors」)。
    let fail_closed = |reason: &str| LoadedPosture {
        profile: PostureProfile::High,
        warning: Some(format!(
            "posture config at {} is {reason}; failing closed to the strictest posture (high)",
            path.display()
        )),
    };

    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        // 不存在 = 用户从未配置 → 默认档 Low(这是唯一允许"更松"的分支:无配置即默认)。
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return LoadedPosture {
                profile: PostureProfile::Low,
                warning: None,
            };
        }
        // 存在但读不了(权限 / 是目录等)→ 状态不明,fail-closed。
        Err(_) => return fail_closed("unreadable"),
    };

    // 解析失败覆盖两类:非法 JSON,或 `posture` 字段是未知档位串(serde 未知 variant)。
    // 统一收敛 High,不区分细节 —— 细节文案可能引诱回显原文。
    let parsed: PostureFileV1 = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return fail_closed("malformed (invalid JSON or unknown posture value)"),
    };
    if parsed.version != POSTURE_FILE_VERSION {
        return fail_closed("of an unrecognized version");
    }
    LoadedPosture {
        profile: parsed.posture,
        warning: None,
    }
}

/// 原子写 posture 配置(与 setup.rs `atomic_write_str_with_backup` 同款安全风格:
/// 同目录 tmp + `rename` 替换,绝不留半截文件;父目录不存在则创建)。失败返回 `io::Error`,
/// 永不 panic。posture.json 内容固定且无并发写者,故不做备份 / TOCTOU 校验(比用户
/// settings.json 的风险面小得多)。
pub fn store_posture(path: &Path, profile: PostureProfile) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    // serde_json::Error 经 From 转 io::Error(本结构序列化实际不可能失败,但绝不 unwrap)。
    let mut rendered = serde_json::to_string_pretty(&PostureFileV1 {
        version: POSTURE_FILE_VERSION,
        posture: profile,
    })?;
    rendered.push('\n');

    // 同目录 tmp(与目标同一文件系统,rename 才是原子替换);后缀风格沿用 setup.rs 的 `.vigil-tmp`。
    let tmp = {
        let mut s = path.as_os_str().to_os_string();
        s.push(".vigil-tmp");
        PathBuf::from(s)
    };
    if let Err(e) = std::fs::write(&tmp, rendered.as_bytes()) {
        let _ = std::fs::remove_file(&tmp); // best-effort 清理半截 tmp
        return Err(e);
    }
    // 现代 Rust `rename` 在 Windows 走 MOVEFILE_REPLACE_EXISTING,原子覆盖既有目标;
    // 失败时原文件未动,清理 tmp 后把错误如实上抛。
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

// ─────────────────────────── 审计 ───────────────────────────

/// best-effort 审计一次姿态切换到账本(照 hook.rs `audit_deny` 模式)。
/// **绝不** panic / 返回 Err —— 账本不可用时姿态切换仍生效,只把审计失败写 stderr。
pub fn audit_posture_switch(ledger_path: &Path, old: PostureProfile, new: PostureProfile) {
    let ledger = match Ledger::open(ledger_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "vigil-posture: audit ledger open failed ({e}); posture change still applied"
            );
            return;
        }
    };
    let sid = match ledger.start_session("vigil-posture", None) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "vigil-posture: audit start_session failed ({e}); posture change still applied"
            );
            return;
        }
    };
    // payload 只含两个稳定档位名(serde 名 "low"/"medium"/"high"),无任何用户输入。
    let payload = json!({ "old": old, "new": new });
    let summary = format!("posture switched {} -> {}", old.as_str(), new.as_str());
    if let Err(e) = ledger.append_event(&sid, "posture.switched", &payload, Some(&summary)) {
        eprintln!("vigil-posture: audit append_event failed ({e}); posture change still applied");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 全档位 / 全风险类清单。decide 的 match 穷举保证新增 variant 必改 decide;
    /// 这两张清单 + 下面的期望表则保证新增 variant 必同步补测试(双向守门)。
    const ALL_PROFILES: [PostureProfile; 3] = [
        PostureProfile::Low,
        PostureProfile::Medium,
        PostureProfile::High,
    ];
    const ALL_RISKS: [RiskClass; 5] = [
        RiskClass::RawSecret,
        RiskClass::LedgerTamper,
        RiskClass::PlaceholderNative,
        RiskClass::DestructiveCatastrophic,
        RiskClass::DangerousCommand,
    ];

    /// 期望决策表(与 `decide` 内的 SSOT 表逐项对照;3 档 × 5 风险 = 15 组合)。
    const EXPECTED_TABLE: [(PostureProfile, RiskClass, PostureAction); 15] = [
        // RawSecret:硬底线,任何档位 Deny
        (
            PostureProfile::Low,
            RiskClass::RawSecret,
            PostureAction::Deny,
        ),
        (
            PostureProfile::Medium,
            RiskClass::RawSecret,
            PostureAction::Deny,
        ),
        (
            PostureProfile::High,
            RiskClass::RawSecret,
            PostureAction::Deny,
        ),
        // LedgerTamper:硬底线,任何档位 Deny
        (
            PostureProfile::Low,
            RiskClass::LedgerTamper,
            PostureAction::Deny,
        ),
        (
            PostureProfile::Medium,
            RiskClass::LedgerTamper,
            PostureAction::Deny,
        ),
        (
            PostureProfile::High,
            RiskClass::LedgerTamper,
            PostureAction::Deny,
        ),
        // PlaceholderNative:档位调节区
        (
            PostureProfile::Low,
            RiskClass::PlaceholderNative,
            PostureAction::Allow,
        ),
        (
            PostureProfile::Medium,
            RiskClass::PlaceholderNative,
            PostureAction::Ask,
        ),
        (
            PostureProfile::High,
            RiskClass::PlaceholderNative,
            PostureAction::Deny,
        ),
        // DestructiveCatastrophic:硬底线,任何档位 Deny
        (
            PostureProfile::Low,
            RiskClass::DestructiveCatastrophic,
            PostureAction::Deny,
        ),
        (
            PostureProfile::Medium,
            RiskClass::DestructiveCatastrophic,
            PostureAction::Deny,
        ),
        (
            PostureProfile::High,
            RiskClass::DestructiveCatastrophic,
            PostureAction::Deny,
        ),
        // DangerousCommand:Low/Medium 确认,High 拒
        (
            PostureProfile::Low,
            RiskClass::DangerousCommand,
            PostureAction::Ask,
        ),
        (
            PostureProfile::Medium,
            RiskClass::DangerousCommand,
            PostureAction::Ask,
        ),
        (
            PostureProfile::High,
            RiskClass::DangerousCommand,
            PostureAction::Deny,
        ),
    ];

    #[test]
    fn decision_table_matches_expected_table_bidirectionally() {
        // 方向 1:期望表每一项都被 decide 覆盖且结果一致(表 ⊆ decide)。
        for (profile, risk, expected) in EXPECTED_TABLE {
            assert_eq!(
                decide(profile, risk),
                expected,
                "decide({profile:?}, {risk:?}) drifted from the expected SSOT table"
            );
        }
        // 方向 2:decide 的输入全集(档位 × 风险)每个组合在期望表中**恰好出现一次**
        // (decide ⊆ 表,且表无重复/无多余项 —— 精确集合双向 diff,非弱 count 断言)。
        for profile in ALL_PROFILES {
            for risk in ALL_RISKS {
                let hits = EXPECTED_TABLE
                    .iter()
                    .filter(|(p, r, _)| *p == profile && *r == risk)
                    .count();
                assert_eq!(
                    hits, 1,
                    "combination ({profile:?}, {risk:?}) must appear exactly once in EXPECTED_TABLE"
                );
            }
        }
        // 最弱兜底:总数恒等(防表被整段误删)。
        assert_eq!(EXPECTED_TABLE.len(), ALL_PROFILES.len() * ALL_RISKS.len());
    }

    #[test]
    fn invariant_raw_secret_and_ledger_tamper_deny_in_every_posture() {
        // 安全不变量(独立于表测试):极高风险类不可被任何档位降级,恒 Deny。
        for profile in ALL_PROFILES {
            assert_eq!(
                decide(profile, RiskClass::RawSecret),
                PostureAction::Deny,
                "RawSecret must be denied regardless of posture ({profile:?})"
            );
            assert_eq!(
                decide(profile, RiskClass::LedgerTamper),
                PostureAction::Deny,
                "LedgerTamper must be denied regardless of posture ({profile:?})"
            );
        }
    }

    #[test]
    fn escalate_covers_all_transitions_with_high_saturation() {
        // 全档位升档转移:Low→Medium / Medium→High / High→High(饱和)。
        assert_eq!(PostureProfile::Low.escalate(), PostureProfile::Medium);
        assert_eq!(PostureProfile::Medium.escalate(), PostureProfile::High);
        assert_eq!(
            PostureProfile::High.escalate(),
            PostureProfile::High,
            "High 已是最严档,升档饱和不再上升"
        );
    }

    #[test]
    fn effective_profile_threshold_boundary() {
        // 阈值边界:23(< 24)不升档;24(= 阈值)升档。
        assert_eq!(SESSION_RISK_ESCALATION_THRESHOLD, 24);
        // 低于阈值:base 原样返回(各档不变)。
        for base in ALL_PROFILES {
            assert_eq!(
                effective_profile(base, 23),
                base,
                "risk 23 (< {SESSION_RISK_ESCALATION_THRESHOLD}) 不应升档"
            );
            // 0 / 负值(防御)同样不升档。
            assert_eq!(effective_profile(base, 0), base);
        }
        // 达到/超过阈值:升一档(High 饱和)。
        assert_eq!(
            effective_profile(PostureProfile::Low, 24),
            PostureProfile::Medium
        );
        assert_eq!(
            effective_profile(PostureProfile::Medium, 24),
            PostureProfile::High
        );
        assert_eq!(
            effective_profile(PostureProfile::High, 24),
            PostureProfile::High
        );
        // 远超阈值同样升一档(不会跳两档)。
        assert_eq!(
            effective_profile(PostureProfile::Low, 1000),
            PostureProfile::Medium
        );
    }

    #[test]
    fn decide_unchanged_under_effective_profile_composition() {
        // 升档只在 effective_profile 层;decide 行为本身不变 —— 用 base 直接 decide
        // 与"未越阈时先算 effective 再 decide"必须完全等价(SSOT 表未被改动)。
        for base in ALL_PROFILES {
            for risk in ALL_RISKS {
                let eff = effective_profile(base, 0); // 未越阈 → eff == base
                assert_eq!(
                    decide(eff, risk),
                    decide(base, risk),
                    "未越阈时 effective_profile 不得改变 decide 结果 ({base:?}, {risk:?})"
                );
            }
        }
        // 越阈时:effective = base.escalate(),decide(effective) 必须等于 decide(升档后的 base)。
        for base in ALL_PROFILES {
            for risk in ALL_RISKS {
                let eff = effective_profile(base, SESSION_RISK_ESCALATION_THRESHOLD);
                assert_eq!(
                    decide(eff, risk),
                    decide(base.escalate(), risk),
                    "越阈时 effective_profile 应等价于 base.escalate() ({base:?}, {risk:?})"
                );
            }
        }
        // 硬底线不可被升档绕过(其实是被升档"更严",但 RawSecret/LedgerTamper 本就恒 Deny):
        // 升档后这两类仍 Deny,且 PlaceholderNative 只会更严不会更松。
        assert_eq!(
            decide(
                effective_profile(PostureProfile::Low, 24),
                RiskClass::RawSecret
            ),
            PostureAction::Deny
        );
        // Low + 越阈 → Medium:PlaceholderNative 由 Allow 收紧到 Ask(更严)。
        assert_eq!(
            decide(
                effective_profile(PostureProfile::Low, 24),
                RiskClass::PlaceholderNative
            ),
            PostureAction::Ask
        );
    }

    #[test]
    fn serde_names_are_stable_snake_case() {
        // serde 名是落盘契约,防 rename 漂移破坏已存在的 posture.json。
        let cases = [
            (PostureProfile::Low, "\"low\""),
            (PostureProfile::Medium, "\"medium\""),
            (PostureProfile::High, "\"high\""),
        ];
        for (profile, name) in cases {
            assert_eq!(serde_json::to_string(&profile).unwrap(), name);
            let back: PostureProfile = serde_json::from_str(name).unwrap();
            assert_eq!(back, profile, "serde roundtrip must be lossless");
            // as_str 与 serde 名一致(审计摘要用 as_str,两者不许分叉)。
            assert_eq!(format!("\"{}\"", profile.as_str()), name);
        }
    }

    #[test]
    fn default_profile_is_low() {
        assert_eq!(PostureProfile::default(), PostureProfile::Low);
    }

    #[test]
    fn store_then_load_roundtrip_for_all_profiles() {
        let td = tempfile::TempDir::new().unwrap();
        for profile in ALL_PROFILES {
            let path = td.path().join(format!("{}.json", profile.as_str()));
            store_posture(&path, profile).unwrap();
            let loaded = load_posture(&path);
            assert_eq!(loaded.profile, profile);
            assert!(loaded.warning.is_none(), "clean roundtrip must not warn");
        }
    }

    #[test]
    fn store_creates_missing_parent_directories() {
        let td = tempfile::TempDir::new().unwrap();
        let path = td.path().join("nested").join("deeper").join("posture.json");
        store_posture(&path, PostureProfile::Medium).unwrap();
        assert_eq!(load_posture(&path).profile, PostureProfile::Medium);
    }

    #[test]
    fn missing_file_defaults_to_low_without_warning() {
        let td = tempfile::TempDir::new().unwrap();
        let loaded = load_posture(&td.path().join("does-not-exist.json"));
        assert_eq!(loaded.profile, PostureProfile::Low);
        assert!(loaded.warning.is_none());
    }

    #[test]
    fn garbage_json_fails_closed_to_high_without_echoing_content() {
        let td = tempfile::TempDir::new().unwrap();
        let path = td.path().join("posture.json");
        // 故意带可识别 sentinel,断言 warning 不回显文件原文。
        std::fs::write(&path, b"GARBAGE-SENTINEL {{{ not json").unwrap();
        let loaded = load_posture(&path);
        assert_eq!(
            loaded.profile,
            PostureProfile::High,
            "malformed -> fail closed"
        );
        let warning = loaded.warning.unwrap(); // 必有 warning(malformed)
        assert!(
            !warning.contains("GARBAGE-SENTINEL"),
            "warning must NOT echo file content; got: {warning}"
        );
        assert!(warning.contains("malformed"));
    }

    #[test]
    fn unknown_posture_value_fails_closed_to_high() {
        let td = tempfile::TempDir::new().unwrap();
        let path = td.path().join("posture.json");
        std::fs::write(&path, br#"{"version":1,"posture":"paranoid-sentinel"}"#).unwrap();
        let loaded = load_posture(&path);
        assert_eq!(loaded.profile, PostureProfile::High);
        let warning = loaded.warning.unwrap(); // 必有 warning(未知档位)
        assert!(
            !warning.contains("paranoid-sentinel"),
            "warning must NOT echo the unknown value; got: {warning}"
        );
    }

    #[test]
    fn unrecognized_version_fails_closed_to_high() {
        let td = tempfile::TempDir::new().unwrap();
        let path = td.path().join("posture.json");
        std::fs::write(&path, br#"{"version":99,"posture":"low"}"#).unwrap();
        let loaded = load_posture(&path);
        assert_eq!(
            loaded.profile,
            PostureProfile::High,
            "unknown version must NOT be read as low (fail closed)"
        );
        let warning = loaded.warning.unwrap(); // 必有 warning(version 不识别)
        assert!(warning.contains("version"));
    }

    #[test]
    fn unreadable_existing_path_fails_closed_to_high() {
        // 路径存在但不是常规文件(目录)→ 读取失败但非 NotFound → fail-closed High。
        let td = tempfile::TempDir::new().unwrap();
        let dir_as_config = td.path().join("posture.json");
        std::fs::create_dir(&dir_as_config).unwrap();
        let loaded = load_posture(&dir_as_config);
        assert_eq!(loaded.profile, PostureProfile::High);
        assert!(loaded.warning.is_some());
    }

    #[test]
    fn default_posture_path_is_under_vigil_data_dir() {
        // headless 环境 dirs 可能返 None,只在能解析时断言形状。
        if let Some(p) = default_posture_path() {
            assert!(
                p.ends_with(Path::new("Vigil").join("posture.json")),
                "unexpected default posture path: {}",
                p.display()
            );
        }
    }

    #[test]
    fn audit_posture_switch_appends_event_with_expected_payload() {
        let td = tempfile::TempDir::new().unwrap();
        let ledger_path = td.path().join("ledger.sqlite3");
        audit_posture_switch(&ledger_path, PostureProfile::Low, PostureProfile::High);

        let ledger = Ledger::open(&ledger_path).unwrap();
        let hits = ledger
            .list_recent_events(None, Some(&["posture.switched".to_string()]), 10)
            .unwrap();
        assert_eq!(hits.len(), 1, "exactly one posture.switched event expected");
        assert_eq!(hits[0].event_type, "posture.switched");
        assert_eq!(
            hits[0].redacted_text.as_deref(),
            Some("posture switched low -> high")
        );
    }

    #[test]
    fn audit_posture_switch_is_best_effort_on_bad_ledger_path() {
        // 把目录当账本路径 → Ledger::open 失败 → 只 eprintln,绝不 panic(best-effort)。
        let td = tempfile::TempDir::new().unwrap();
        audit_posture_switch(td.path(), PostureProfile::Low, PostureProfile::Medium);
    }
}
