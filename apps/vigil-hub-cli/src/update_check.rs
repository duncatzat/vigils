//! `vigil-hub` 侧的每日更新检查(再评估 §9 D1,2026-09-10 已决):把 [`vigil_update_check`]
//! 策略层接到 reqwest 阻塞客户端上。真实更新检查同时就是采用度量(服务端按日 / 平台 / 版本
//! 计数 = ADI),**不是遥测**:请求只含平台与版本号,没有任何标识。
//!
//! 只从**长驻入口**调用:`serve --stdio`(main.rs)与 `daemon start`(daemon/lifecycle.rs)。
//! `hook` 是 per-tool-call 短进程且有延迟预算,**永不出站** —— `tests/update_check.rs` 用源码
//! 守门断言 hook / command_guard / posture 三个模块不引用本模块。
//!
//! 全程 best-effort:任何失败静默(不重试、不阻塞、不影响主功能);stdout 一个字节都不碰
//!(`serve` 的 stdout 属于 MCP 协议),只在 stderr 打两种行:首次告知、有新版本。

use std::io::Read;
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use vigil_update_check::{self as policy, EnvFn, Fetch, Plan};

use crate::i18n::{self, Lang, Msg};

/// UA 里的产品名(桌面端另用 `vigils-desktop`;服务端据此区分两类客户端与 curl / 监控噪声)。
pub const PRODUCT: &str = "vigil-hub";
/// 本机版本 = crate 版本(与 `vigil-hub --version` 一致)。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 状态目录 = `<data_local>/Vigil`(与 ledger / posture / engine 同目录)。
pub fn state_dir() -> Option<PathBuf> {
    dirs::data_local_dir().map(|b| b.join(crate::setup::VIGIL_SUBDIR))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn real_env(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

/// 生产入口:真实 env + 真实状态目录。返回后台线程句柄(调用方可忽略;进程退出即随之结束)。
pub fn spawn_daily(lang: Lang) -> Option<JoinHandle<()>> {
    let dir = state_dir();
    spawn_daily_with(lang, &real_env, dir.as_deref())
}

/// 注入式入口:测试走**同一条**生产路径,只换 env 与状态目录(不改全局 env)。
///
/// 返回 `None` = 本次不发(关闭 / 节流 / 无状态目录 / 记时间戳失败)。
pub fn spawn_daily_with(
    lang: Lang,
    env: EnvFn<'_>,
    state_dir: Option<&Path>,
) -> Option<JoinHandle<()>> {
    let now = now_secs();
    let fetch = match policy::plan(now, env, state_dir, PRODUCT, VERSION) {
        Plan::Skip(_) => return None,
        Plan::Fetch(f) => f,
    };
    let dir = state_dir?; // `Fetch` 蕴含 Some;保持全函数无 panic
    if fetch.first_run {
        eprintln!(
            "{}",
            i18n::t(
                lang,
                Msg::UpdateCheckNotice {
                    docs: policy::DOCS_URL,
                },
            )
        );
    }
    // 先记时间戳再发:离线 / 失败在 24h 内不会重发 —— 节流是隐私约束的一部分,不是优化。
    if policy::record_attempt(dir, now).is_err() {
        return None;
    }
    Some(std::thread::spawn(move || {
        if let Some(latest) = fetch_newer(&fetch) {
            eprintln!(
                "{}",
                i18n::t(
                    lang,
                    Msg::UpdateAvailable {
                        current: VERSION,
                        latest: &latest,
                        url: policy::RELEASES_URL,
                    },
                )
            );
        }
    }))
}

/// 一次 GET(仅 UA,无其它自定义头、无参数、无 body、不跟随跳转)→ 比本机新则返回版本串。
/// 任何失败 → `None`(静默;要看原因用 `vigil-hub version-ping check`)。
fn fetch_newer(fetch: &Fetch) -> Option<String> {
    let body = fetch_manifest(fetch).ok()?;
    policy::newer_version(VERSION, &body)
}

/// 真正的网络往返:返回清单原文(有界),或一条**不含清单内容**的错误说明(供 `check` 显示)。
fn fetch_manifest(fetch: &Fetch) -> Result<String, String> {
    let client = reqwest::blocking::Client::builder()
        .user_agent(fetch.user_agent.as_str())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("http client init failed: {e}"))?;
    let resp = client
        .get(&fetch.url)
        .send()
        .map_err(|e| format!("request failed: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("server answered HTTP {status}"));
    }
    // 有界读取:真实清单 < 2 KB;超过上限即视为异常源,丢弃(清单是不可信输入)。
    let mut body = Vec::with_capacity(4096);
    resp.take(policy::MAX_MANIFEST_BYTES as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|e| format!("reading the manifest failed: {e}"))?;
    if body.len() > policy::MAX_MANIFEST_BYTES {
        return Err(format!(
            "manifest larger than {} bytes; ignored",
            policy::MAX_MANIFEST_BYTES
        ));
    }
    String::from_utf8(body).map_err(|_| "manifest is not UTF-8".to_string())
}

/// `check`:立刻同步检查一次并把结果**说清楚**(用户手动查 / 排障)。仍尊重三种关闭方式
///(关闭 = 零字节,不例外);会记一次尝试时间(与自动检查共用节流,不重复计数)。
pub fn run_check(lang: Lang) -> Result<(), String> {
    let dir = state_dir();
    let s = policy::status(&real_env, dir.as_deref());
    if let Some(reason) = s.disabled_by.as_deref() {
        return Err(match lang {
            Lang::En => format!(
                "version ping is disabled ({reason}); re-enable with `vigil-hub version-ping on` or unset the environment variable, then retry"
            ),
            Lang::Zh => format!(
                "版本 ping 已关闭({reason});先 `vigil-hub version-ping on` 或取消环境变量再试"
            ),
        });
    }
    let fetch = Fetch {
        url: policy::request_url(&s.endpoint_base, &policy::current_platform_key(), VERSION),
        user_agent: policy::user_agent(PRODUCT, VERSION),
        first_run: false,
    };
    if let Some(dir) = dir.as_deref() {
        let _ = policy::record_attempt(dir, now_secs());
    }
    println!(
        "{}",
        tr(lang, "checking: GET ", "正在检查:GET ").to_string() + &fetch.url
    );
    let body = fetch_manifest(&fetch)?;
    match policy::newer_version(VERSION, &body) {
        Some(latest) => println!(
            "{}",
            i18n::t(
                lang,
                Msg::UpdateAvailable {
                    current: VERSION,
                    latest: &latest,
                    url: policy::RELEASES_URL,
                },
            )
        ),
        None => println!(
            "{}",
            match lang {
                Lang::En => format!(
                    "vigil-hub {VERSION} is up to date (manifest has no newer valid version)"
                ),
                Lang::Zh => format!("vigil-hub {VERSION} 已是最新(清单里没有更新的有效版本)"),
            }
        ),
    }
    Ok(())
}

// ───────────────────── `vigil-hub version-ping status|on|off` ─────────────────────

fn tr<'a>(lang: Lang, en: &'a str, zh: &'a str) -> &'a str {
    match lang {
        Lang::En => en,
        Lang::Zh => zh,
    }
}

/// `status`:人类可读,或 `--json`(schema 稳定、与界面语言无关:`enabled` / `disabled_by` /
/// `endpoint` / `user_agent` / `sends` / `last_attempt_unix` / `min_interval_secs`)。
pub fn run_status(lang: Lang, json: bool) -> Result<(), String> {
    let dir = state_dir();
    let s = policy::status(&real_env, dir.as_deref());
    let url = policy::request_url(&s.endpoint_base, &policy::current_platform_key(), VERSION);
    if json {
        let doc = serde_json::json!({
            "enabled": s.enabled,
            "disabled_by": s.disabled_by,
            "endpoint": url,
            "user_agent": policy::user_agent(PRODUCT, VERSION),
            "sends": ["platform", "version"],
            "last_attempt_unix": s.last_attempt_secs,
            "min_interval_secs": policy::MIN_INTERVAL_SECS,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    let state = match s.disabled_by.as_deref() {
        None => tr(lang, "enabled", "已开启").to_string(),
        Some("marker") => tr(
            lang,
            "disabled (by `vigil-hub version-ping off`)",
            "已关闭(由 `vigil-hub version-ping off`)",
        )
        .to_string(),
        Some("no-state-dir") => tr(
            lang,
            "disabled (no local data directory to throttle with)",
            "已关闭(找不到本地数据目录,无法节流)",
        )
        .to_string(),
        Some(other) => {
            let name = other.strip_prefix("env:").unwrap_or(other);
            format!("{} {name}=…", tr(lang, "disabled (by", "已关闭(由环境变量")) + ")"
        }
    };
    let last = match s.last_attempt_secs {
        None => tr(lang, "never", "从未").to_string(),
        Some(t) => {
            let ago = now_secs().saturating_sub(t);
            match lang {
                Lang::En => format!("{}h ago", ago / 3600),
                Lang::Zh => format!("{} 小时前", ago / 3600),
            }
        }
    };
    match lang {
        Lang::En => println!(
            "version ping: {state}\n  \
             what:     one GET per day from `serve` / `daemon start`, to notice a newer release\n  \
             sends:    platform + version only, no identifiers\n  \
             request:  GET {url}\n  \
             last try: {last}\n  \
             turn off: vigil-hub version-ping off   (or VIGIL_NO_VERSION_PING=1 / DO_NOT_TRACK=1)\n  \
             details:  {}",
            policy::DOCS_URL
        ),
        Lang::Zh => println!(
            "版本 ping:{state}\n  \
             做什么:  `serve` / `daemon start` 每天最多一次 GET,看有没有新版本\n  \
             发什么:  只有平台与版本号,不带任何标识\n  \
             请求:    GET {url}\n  \
             上次尝试:{last}\n  \
             关闭:    vigil-hub version-ping off(或 VIGIL_NO_VERSION_PING=1 / DO_NOT_TRACK=1)\n  \
             说明:    {}",
            policy::DOCS_URL
        ),
    }
    Ok(())
}

/// `on` / `off`:写 / 删状态目录里的关闭标记(用户显式操作,幂等)。
pub fn run_set(lang: Lang, enabled: bool) -> Result<(), String> {
    let dir = state_dir().ok_or_else(|| {
        tr(
            lang,
            "cannot locate the local data directory",
            "找不到本地数据目录",
        )
        .to_string()
    })?;
    policy::set_enabled(&dir, enabled).map_err(|e| match lang {
        Lang::En => format!(
            "failed to update `{}`: {e}",
            policy::marker_path(&dir).display()
        ),
        Lang::Zh => format!("更新 `{}` 失败:{e}", policy::marker_path(&dir).display()),
    })?;
    if enabled {
        println!(
            "{}",
            tr(
                lang,
                "version ping: on (daily update check re-enabled)",
                "版本 ping:已开启(恢复每日更新检查)"
            )
        );
        if let Some(name) = policy::disabled_by_env(&real_env) {
            println!(
                "{}",
                match lang {
                    Lang::En =>
                        format!("  note: {name} is set in this environment and still disables it"),
                    Lang::Zh => format!("  注意:当前环境设置了 {name},它仍会禁用更新检查"),
                }
            );
        }
    } else {
        println!(
            "{}",
            tr(
                lang,
                "version ping: off (no update checks will be sent from this machine)",
                "版本 ping:已关闭(本机不再发送任何更新检查)"
            )
        );
    }
    Ok(())
}
