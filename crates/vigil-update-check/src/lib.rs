#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
//! 每日一次的更新检查 —— **纯策略层,不含网络**。调用方自带 HTTP 客户端(CLI 用 reqwest,桌面用
//! ureq);本 crate 只回答「现在该不该发、发到哪、带什么、收到后怎么解读」,因此全部逻辑都能在
//! 默认测试矩阵里离线验证。
//!
//! 背景(再评估 §9 D1,2026-09-10 已决):真实更新检查同时就是采用度量 —— 服务端按
//! `(日, 平台, 版本)` 计数得到 ADI(Active Daily Installs),**不是遥测**(Firefox ADI 口径)。
//!
//! 隐私不变量(对应 D1 六条硬约束的第 1 / 3 / 4 条,由本 crate 的类型与测试守住):
//! - 请求只含 URL(`/desktop-updates/<平台>/<本机版本>.json`)与 UA(`<产品>/<版本>`),
//!   **没有任何标识、桶、盐、机器名、用户名、路径**;
//! - 本地只落一个「最近尝试时间」节流文件([`LAST_ATTEMPT_FILE`],功能自身严格必要)
//!   与用户显式写入的关闭标记([`DISABLED_MARKER`]);
//! - `VIGIL_NO_VERSION_PING` / `DO_NOT_TRACK` / 关闭标记任一命中即全停,且优先于一切;
//!   拿不到状态目录(无法节流)也不发 —— 宁可少测,不多发;
//! - 每个安装每 24h 至多一次;失败不重试(调用方**先**记时间戳再发请求,离线也不会连发)。

use std::cmp::Ordering;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// 默认更新源(vigils.ai,Cloudflare 前置,`/desktop-updates/*` 为 no-cache 直达源站)。
pub const DEFAULT_ENDPOINT: &str = "https://vigils.ai";
/// 关闭开关(产品专属):任何真值(非空且非 `0` / `false` / `off` / `no`)即关闭。
pub const ENV_DISABLE: &str = "VIGIL_NO_VERSION_PING";
/// 关闭开关(行业通用,<https://consoledonottrack.com>):同上真值规则。
pub const ENV_DO_NOT_TRACK: &str = "DO_NOT_TRACK";
/// 更新源覆盖(自托管 / 测试):基址,如 `https://mirror.example.com`。
pub const ENV_ENDPOINT: &str = "VIGIL_UPDATE_ENDPOINT";
/// 用户显式关闭的标记文件(状态目录内;`vigil-hub version-ping off` 写入,`on` 删除)。
pub const DISABLED_MARKER: &str = "version-ping.off";
/// 节流文件(状态目录内):最近一次**尝试**的 Unix 秒;唯一会因本功能落盘的运行态。
pub const LAST_ATTEMPT_FILE: &str = "update-check.last";
/// 两次尝试的最小间隔(24h)。
pub const MIN_INTERVAL_SECS: u64 = 24 * 60 * 60;
/// 有新版本时给用户看的下载入口。
pub const RELEASES_URL: &str = "https://github.com/duncatzat/vigils/releases/latest";
/// 用户说明页(发什么 / 不发什么 / 怎么关 / 服务端留什么)。
pub const DOCS_URL: &str =
    "https://github.com/duncatzat/vigils/blob/main/docs/user-guide/update-check.md";
/// 更新清单体积上限:真实清单 < 2 KB;超过即视为异常源,忽略(调用方也据此截断读取)。
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
/// 清单里 `version` 字段的最大长度(展示给用户,须有界)。
const MAX_VERSION_LEN: usize = 64;

/// 读取环境变量的注入点(生产 = `std::env::var`,测试 = 闭包;绝不在库内改全局 env)。
pub type EnvFn<'a> = &'a dyn Fn(&str) -> Option<String>;

/// 本次不发的原因(状态命令与调用方日志用)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skip {
    /// 被环境变量关闭(值为变量名)。
    DisabledByEnv(&'static str),
    /// 被 [`DISABLED_MARKER`] 关闭。
    DisabledByMarker,
    /// 无状态目录 → 无法节流 → 不发。
    NoStateDir,
    /// 24h 内已尝试过。
    Throttled {
        /// 距下次允许还有多少秒。
        next_due_in_secs: u64,
    },
}

/// 该发:调用方按此发起 **一次** `GET`(不带其它头 / 参数 / body)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetch {
    /// 完整 URL:`<base>/desktop-updates/<平台>/<本机版本>.json`。
    pub url: String,
    /// `<产品>/<版本>`;请求里除此之外不带任何自定义头。
    pub user_agent: String,
    /// 从未记录过尝试(第一次)—— 调用方据此打印一次性告知。
    pub first_run: bool,
}

/// [`plan`] 的裁决。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// 不发。
    Skip(Skip),
    /// 发一次。
    Fetch(Fetch),
}

/// 环境变量真值:非空且不是 `0` / `false` / `off` / `no`(大小写不敏感,两端空白忽略)。
pub fn env_is_truthy(value: Option<&str>) -> bool {
    match value.map(str::trim) {
        None | Some("") => false,
        Some(v) => !matches!(
            v.to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        ),
    }
}

/// 命中的关闭变量名(产品专属优先,其次 `DO_NOT_TRACK`)。
pub fn disabled_by_env(env: EnvFn<'_>) -> Option<&'static str> {
    [ENV_DISABLE, ENV_DO_NOT_TRACK]
        .into_iter()
        .find(|name| env_is_truthy(env(name).as_deref()))
}

/// 平台键 = 更新源目录名(与 Tauri updater / 发布产物一致):`macos` 映射为 `darwin`,其余照抄。
pub fn platform_key(os: &str, arch: &str) -> String {
    let os = match os {
        "macos" => "darwin",
        other => other,
    };
    format!("{os}-{arch}")
}

/// 本机平台键(编译期 OS / ARCH)。
pub fn current_platform_key() -> String {
    platform_key(std::env::consts::OS, std::env::consts::ARCH)
}

/// 更新源基址:[`ENV_ENDPOINT`] 非空则用之,否则 [`DEFAULT_ENDPOINT`]。
pub fn endpoint_base(env: EnvFn<'_>) -> String {
    match env(ENV_ENDPOINT).map(|s| s.trim().to_string()) {
        Some(s) if !s.is_empty() => s,
        _ => DEFAULT_ENDPOINT.to_string(),
    }
}

/// `<base>/desktop-updates/<platform>/<version>.json`(与源站 nginx 的 `desktop-updates` 路由一致)。
pub fn request_url(base: &str, platform: &str, version: &str) -> String {
    format!(
        "{}/desktop-updates/{platform}/{version}.json",
        base.trim_end_matches('/')
    )
}

/// `<product>/<version>`。
pub fn user_agent(product: &str, version: &str) -> String {
    format!("{product}/{version}")
}

/// 关闭标记路径。
pub fn marker_path(state_dir: &Path) -> PathBuf {
    state_dir.join(DISABLED_MARKER)
}

/// 节流文件路径。
pub fn last_attempt_path(state_dir: &Path) -> PathBuf {
    state_dir.join(LAST_ATTEMPT_FILE)
}

/// 最近一次尝试的 Unix 秒(文件缺失 / 内容非法 → `None`)。
pub fn last_attempt(state_dir: &Path) -> Option<u64> {
    fs::read_to_string(last_attempt_path(state_dir))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// 记录本次尝试时间(tmp + rename 原子替换;目录不存在则创建)。
pub fn record_attempt(state_dir: &Path, now_secs: u64) -> io::Result<()> {
    fs::create_dir_all(state_dir)?;
    let path = last_attempt_path(state_dir);
    let tmp = state_dir.join(format!("{LAST_ATTEMPT_FILE}.tmp-{}", std::process::id()));
    fs::write(&tmp, now_secs.to_string())?;
    match fs::rename(&tmp, &path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// 用户显式开 / 关:`false` 写入关闭标记,`true` 删除之(幂等)。
pub fn set_enabled(state_dir: &Path, enabled: bool) -> io::Result<()> {
    let marker = marker_path(state_dir);
    if enabled {
        match fs::remove_file(&marker) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    } else {
        fs::create_dir_all(state_dir)?;
        fs::write(&marker, "disabled by `vigil-hub version-ping off`\n")
    }
}

/// 裁决:关闭开关 → 状态目录 → 关闭标记 → 24h 节流 → 发。
///
/// 纯函数(只读文件系统);不写任何东西 —— 调用方决定发之前先 [`record_attempt`]。
pub fn plan(
    now_secs: u64,
    env: EnvFn<'_>,
    state_dir: Option<&Path>,
    product: &str,
    version: &str,
) -> Plan {
    if let Some(name) = disabled_by_env(env) {
        return Plan::Skip(Skip::DisabledByEnv(name));
    }
    let Some(dir) = state_dir else {
        return Plan::Skip(Skip::NoStateDir);
    };
    if marker_path(dir).exists() {
        return Plan::Skip(Skip::DisabledByMarker);
    }
    let last = last_attempt(dir);
    if let Some(last) = last {
        // 时钟被拨回导致 last 在「未来」超过一个间隔:视为非法时间戳,按到期处理(否则会静默永停)。
        let absurd_future = last > now_secs.saturating_add(MIN_INTERVAL_SECS);
        let due_at = last.saturating_add(MIN_INTERVAL_SECS);
        if !absurd_future && now_secs < due_at {
            return Plan::Skip(Skip::Throttled {
                next_due_in_secs: due_at - now_secs,
            });
        }
    }
    Plan::Fetch(Fetch {
        url: request_url(&endpoint_base(env), &current_platform_key(), version),
        user_agent: user_agent(product, version),
        first_run: last.is_none(),
    })
}

/// `version-ping status` 用的快照(只读)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// 当前是否会发(综合三种关闭方式与状态目录)。
    pub enabled: bool,
    /// 关闭原因:`env:<NAME>` / `marker` / `no-state-dir`。
    pub disabled_by: Option<String>,
    /// 生效的更新源基址。
    pub endpoint_base: String,
    /// 最近一次尝试的 Unix 秒。
    pub last_attempt_secs: Option<u64>,
}

/// 只读快照。
pub fn status(env: EnvFn<'_>, state_dir: Option<&Path>) -> Status {
    let disabled_by = match (disabled_by_env(env), state_dir) {
        (Some(name), _) => Some(format!("env:{name}")),
        (None, None) => Some("no-state-dir".to_string()),
        (None, Some(dir)) if marker_path(dir).exists() => Some("marker".to_string()),
        (None, Some(_)) => None,
    };
    Status {
        enabled: disabled_by.is_none(),
        disabled_by,
        endpoint_base: endpoint_base(env),
        last_attempt_secs: state_dir.and_then(last_attempt),
    }
}

// ───────────────────────────── 版本比较(清单 → 是否更新)─────────────────────────────

/// 语义化版本的最小子集:`[v]MAJOR.MINOR.PATCH[-pre.release][+build]`;pre 标识符只允许
/// `[0-9A-Za-z-]`(既是 SemVer 规定,也保证展示给用户的串无控制字符)。
#[derive(Debug, Clone, PartialEq, Eq)]
struct Version {
    core: [u64; 3],
    pre: Vec<String>,
}

fn parse_version(s: &str) -> Option<Version> {
    let s = s.trim();
    if s.is_empty() || s.len() > MAX_VERSION_LEN {
        return None;
    }
    let s = s.strip_prefix('v').unwrap_or(s);
    let s = s.split('+').next()?;
    let (core, pre) = match s.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (s, None),
    };
    let mut parts = core.split('.');
    let mut nums = [0u64; 3];
    for n in nums.iter_mut() {
        let part = parts.next()?;
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *n = part.parse().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    let pre = match pre {
        None => Vec::new(),
        Some(p) => {
            let ids: Vec<String> = p.split('.').map(str::to_string).collect();
            if ids.iter().any(|id| {
                id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }) {
                return None;
            }
            ids
        }
    };
    Some(Version { core: nums, pre })
}

fn cmp_pre_ids(a: &str, b: &str) -> Ordering {
    match (a.parse::<u64>(), b.parse::<u64>()) {
        (Ok(x), Ok(y)) => x.cmp(&y),
        (Ok(_), Err(_)) => Ordering::Less, // 数字标识符 < 字母数字标识符(SemVer §11)
        (Err(_), Ok(_)) => Ordering::Greater,
        (Err(_), Err(_)) => a.cmp(b),
    }
}

fn cmp_versions(a: &Version, b: &Version) -> Ordering {
    match a.core.cmp(&b.core) {
        Ordering::Equal => {}
        other => return other,
    }
    match (a.pre.is_empty(), b.pre.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater, // 正式版 > 预发布
        (false, true) => Ordering::Less,
        (false, false) => {
            for (x, y) in a.pre.iter().zip(b.pre.iter()) {
                match cmp_pre_ids(x, y) {
                    Ordering::Equal => continue,
                    other => return other,
                }
            }
            a.pre.len().cmp(&b.pre.len())
        }
    }
}

/// `candidate` 是否严格新于 `current`;任一无法解析 → `None`。
pub fn is_newer(candidate: &str, current: &str) -> Option<bool> {
    Some(cmp_versions(&parse_version(candidate)?, &parse_version(current)?) == Ordering::Greater)
}

/// 解析更新清单(Tauri updater 格式,只用 `version` 字段)→ 比本机新则返回净化后的版本串。
///
/// 清单是**不可信输入**:体积有上限、`version` 必须能按 SemVer 子集解析(字符集受限)才会被展示。
pub fn newer_version(current: &str, manifest_json: &str) -> Option<String> {
    if manifest_json.len() > MAX_MANIFEST_BYTES {
        return None;
    }
    let doc: serde_json::Value = serde_json::from_str(manifest_json).ok()?;
    let latest = doc.get("version")?.as_str()?.trim();
    if is_newer(latest, current)? {
        Some(latest.strip_prefix('v').unwrap_or(latest).to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_of(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn lookup(map: &HashMap<String, String>) -> impl Fn(&str) -> Option<String> + '_ {
        move |k| map.get(k).cloned()
    }

    #[test]
    fn env_truthiness_follows_do_not_track_convention() {
        for on in ["1", "true", "TRUE", "yes", "anything", " 1 "] {
            assert!(env_is_truthy(Some(on)), "{on:?} must count as on");
        }
        for off in ["", "0", "false", "OFF", "no", "  "] {
            assert!(!env_is_truthy(Some(off)), "{off:?} must count as off");
        }
        assert!(!env_is_truthy(None));
    }

    #[test]
    fn product_switch_wins_over_do_not_track_in_reporting() {
        let both = env_of(&[(ENV_DISABLE, "1"), (ENV_DO_NOT_TRACK, "1")]);
        assert_eq!(disabled_by_env(&lookup(&both)), Some(ENV_DISABLE));
        let dnt = env_of(&[(ENV_DO_NOT_TRACK, "1")]);
        assert_eq!(disabled_by_env(&lookup(&dnt)), Some(ENV_DO_NOT_TRACK));
        let zero = env_of(&[(ENV_DISABLE, "0")]);
        assert_eq!(disabled_by_env(&lookup(&zero)), None);
    }

    #[test]
    fn platform_key_matches_release_directory_names() {
        assert_eq!(platform_key("macos", "aarch64"), "darwin-aarch64");
        assert_eq!(platform_key("windows", "x86_64"), "windows-x86_64");
        assert_eq!(platform_key("linux", "x86_64"), "linux-x86_64");
        let mine = current_platform_key();
        assert!(mine.contains('-') && !mine.contains("macos"), "{mine}");
    }

    #[test]
    fn request_url_has_only_platform_and_version_and_tolerates_trailing_slash() {
        let url = request_url("https://vigils.ai/", "windows-x86_64", "0.7.0-beta.2");
        assert_eq!(
            url,
            "https://vigils.ai/desktop-updates/windows-x86_64/0.7.0-beta.2.json"
        );
        assert!(!url.contains('?'), "no query string, ever");
        assert_eq!(user_agent("vigil-hub", "0.7.0"), "vigil-hub/0.7.0");
    }

    #[test]
    fn endpoint_override_only_when_non_empty() {
        let none = env_of(&[]);
        assert_eq!(endpoint_base(&lookup(&none)), DEFAULT_ENDPOINT);
        let blank = env_of(&[(ENV_ENDPOINT, "   ")]);
        assert_eq!(endpoint_base(&lookup(&blank)), DEFAULT_ENDPOINT);
        let set = env_of(&[(ENV_ENDPOINT, " http://127.0.0.1:9 ")]);
        assert_eq!(endpoint_base(&lookup(&set)), "http://127.0.0.1:9");
    }

    #[test]
    fn plan_env_off_skips_before_touching_the_state_dir() {
        let dir = tempfile::tempdir().unwrap();
        let env = env_of(&[(ENV_DO_NOT_TRACK, "1")]);
        let p = plan(1_000, &lookup(&env), Some(dir.path()), "vigil-hub", "1.0.0");
        assert_eq!(p, Plan::Skip(Skip::DisabledByEnv(ENV_DO_NOT_TRACK)));
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            0,
            "must not write anything"
        );
    }

    #[test]
    fn plan_without_state_dir_never_fetches() {
        let env = env_of(&[]);
        assert_eq!(
            plan(1_000, &lookup(&env), None, "vigil-hub", "1.0.0"),
            Plan::Skip(Skip::NoStateDir)
        );
    }

    #[test]
    fn plan_marker_off_skips_and_on_restores() {
        let dir = tempfile::tempdir().unwrap();
        let env = env_of(&[]);
        set_enabled(dir.path(), false).unwrap();
        assert_eq!(
            plan(1_000, &lookup(&env), Some(dir.path()), "vigil-hub", "1.0.0"),
            Plan::Skip(Skip::DisabledByMarker)
        );
        set_enabled(dir.path(), true).unwrap();
        set_enabled(dir.path(), true).unwrap(); // 幂等
        assert!(matches!(
            plan(1_000, &lookup(&env), Some(dir.path()), "vigil-hub", "1.0.0"),
            Plan::Fetch(_)
        ));
    }

    #[test]
    fn plan_first_run_then_throttled_for_24h_then_due_again() {
        let dir = tempfile::tempdir().unwrap();
        let env = env_of(&[(ENV_ENDPOINT, "http://127.0.0.1:1")]);
        let first = plan(
            10_000,
            &lookup(&env),
            Some(dir.path()),
            "vigil-hub",
            "0.7.0",
        );
        let Plan::Fetch(f) = first else {
            panic!("first run must fetch: {first:?}")
        };
        assert!(f.first_run);
        assert_eq!(
            f.url,
            format!(
                "http://127.0.0.1:1/desktop-updates/{}/0.7.0.json",
                current_platform_key()
            )
        );
        assert_eq!(f.user_agent, "vigil-hub/0.7.0");

        record_attempt(dir.path(), 10_000).unwrap();
        assert_eq!(last_attempt(dir.path()), Some(10_000));
        assert_eq!(
            plan(
                10_000 + MIN_INTERVAL_SECS - 1,
                &lookup(&env),
                Some(dir.path()),
                "vigil-hub",
                "0.7.0"
            ),
            Plan::Skip(Skip::Throttled {
                next_due_in_secs: 1
            })
        );
        let again = plan(
            10_000 + MIN_INTERVAL_SECS,
            &lookup(&env),
            Some(dir.path()),
            "vigil-hub",
            "0.7.0",
        );
        match again {
            Plan::Fetch(f) => assert!(!f.first_run, "second time is not first run"),
            other => panic!("must be due again: {other:?}"),
        }
        // 只落了一个文件,且内容就是那个整数
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec![LAST_ATTEMPT_FILE.to_string()]);
    }

    #[test]
    fn plan_ignores_absurd_future_timestamp_instead_of_stalling_forever() {
        let dir = tempfile::tempdir().unwrap();
        let env = env_of(&[]);
        record_attempt(dir.path(), 5_000_000).unwrap();
        assert!(matches!(
            plan(1_000, &lookup(&env), Some(dir.path()), "vigil-hub", "1.0.0"),
            Plan::Fetch(_)
        ));
    }

    #[test]
    fn record_attempt_overwrites_atomically_and_tolerates_garbage() {
        let dir = tempfile::tempdir().unwrap();
        record_attempt(dir.path(), 1).unwrap();
        record_attempt(dir.path(), 2).unwrap();
        assert_eq!(last_attempt(dir.path()), Some(2));
        fs::write(last_attempt_path(dir.path()), "not a number").unwrap();
        assert_eq!(last_attempt(dir.path()), None);
        assert!(!dir
            .path()
            .join(format!("{LAST_ATTEMPT_FILE}.tmp-{}", std::process::id()))
            .exists());
    }

    #[test]
    fn status_reports_reason_and_last_attempt() {
        let dir = tempfile::tempdir().unwrap();
        let env = env_of(&[]);
        let s = status(&lookup(&env), Some(dir.path()));
        assert!(s.enabled && s.disabled_by.is_none() && s.last_attempt_secs.is_none());
        assert_eq!(s.endpoint_base, DEFAULT_ENDPOINT);
        set_enabled(dir.path(), false).unwrap();
        record_attempt(dir.path(), 77).unwrap();
        let s = status(&lookup(&env), Some(dir.path()));
        assert!(!s.enabled);
        assert_eq!(s.disabled_by.as_deref(), Some("marker"));
        assert_eq!(s.last_attempt_secs, Some(77));
        let env = env_of(&[(ENV_DISABLE, "yes")]);
        assert_eq!(
            status(&lookup(&env), Some(dir.path()))
                .disabled_by
                .as_deref(),
            Some("env:VIGIL_NO_VERSION_PING")
        );
        assert_eq!(
            status(&lookup(&env), None).disabled_by.as_deref(),
            Some("env:VIGIL_NO_VERSION_PING")
        );
        let env = env_of(&[]);
        assert_eq!(
            status(&lookup(&env), None).disabled_by.as_deref(),
            Some("no-state-dir")
        );
    }

    #[test]
    fn version_ordering_follows_semver_including_prerelease() {
        assert_eq!(is_newer("0.7.0", "0.7.0-beta.2"), Some(true));
        assert_eq!(is_newer("0.7.0-beta.2", "0.7.0"), Some(false));
        assert_eq!(is_newer("0.7.0-beta.10", "0.7.0-beta.2"), Some(true));
        assert_eq!(is_newer("0.7.0-rc.1", "0.7.0-beta.2"), Some(true));
        assert_eq!(is_newer("0.6.0", "0.7.0-beta.2"), Some(false));
        assert_eq!(is_newer("v0.8.0", "0.7.9"), Some(true));
        assert_eq!(is_newer("0.7.0", "0.7.0"), Some(false));
        assert_eq!(is_newer("1.0.0+build.5", "1.0.0"), Some(false));
        assert_eq!(is_newer("0.7.0-alpha.1", "0.7.0-alpha"), Some(true));
        assert_eq!(is_newer("0.7", "0.6.0"), None);
        assert_eq!(is_newer("0.7.0.1", "0.6.0"), None);
        assert_eq!(is_newer("0.7.0-be ta", "0.6.0"), None);
        assert_eq!(is_newer("", "0.6.0"), None);
    }

    #[test]
    fn newer_version_treats_manifest_as_untrusted_input() {
        let ok = r#"{"version":"0.6.0","notes":"x","platforms":{}}"#;
        assert_eq!(newer_version("0.1.7", ok), Some("0.6.0".into()));
        assert_eq!(newer_version("0.6.0", ok), None);
        assert_eq!(newer_version("0.7.0-beta.2", ok), None);
        assert_eq!(
            newer_version("0.1.0", r#"{"version":"v9.9.9"}"#),
            Some("9.9.9".into())
        );
        assert_eq!(newer_version("0.1.0", "not json"), None);
        assert_eq!(newer_version("0.1.0", r#"{"notes":"no version"}"#), None);
        assert_eq!(
            newer_version("0.1.0", r#"{"version":"<script>9.9.9</script>"}"#),
            None
        );
        assert_eq!(newer_version("0.1.0", r#"{"version":"9.9.9[31m"}"#), None);
        let huge = format!(
            r#"{{"version":"9.9.9","pad":"{}"}}"#,
            "x".repeat(MAX_MANIFEST_BYTES)
        );
        assert_eq!(newer_version("0.1.0", &huge), None);
    }
}
