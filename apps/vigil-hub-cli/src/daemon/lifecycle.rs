//! daemon 生命周期(ADR 0024):`vigil-hub daemon start|status|stop` 的实现。
//!
//! `start` = `bind` 本地 socket(单实例守门)→ **ort 暖载 PII scanner + 注入分类器**(进程单线程期,
//! 复用 `crate::serve::warm_load_*_best_effort`)+ **R3** 绑定自有 canonical ledger
//! ([`open_canonical_ledger`])→ 生成 per-launch token → 原子写 daemon.json → `serve`(阻塞)。
//! `status` = 读 daemon.json → `query_daemon(Status)`(R1 peer-cred);`stop` = 验存活后 kill pid。
//!
//! **双模型暖载已落**(ort + 模型已缓存 → 暖载真 scanner / 分类器:`RedactScan` 出真 PII findings、
//! `ClassifyInjection` 真 classify + risk bump;模型未缓存 / 非 ort → `None` = model-less,dispatch 返空
//! findings / no-op = hook 落硬指纹 + 正则元指令,**非 fail-open**)。

use std::time::Duration;

use super::client::{daemon_info_path, read_daemon_info, write_daemon_info, DaemonInfo};
use super::protocol::{Request, Response, PROTOCOL_VERSION};
use super::server::DaemonCaps;
use super::transport::{bind, default_socket_name, query_daemon, serve};
use crate::i18n::Lang;

/// 按语言取静态文案(中 / 英并排)。用户直面命令(`daemon start|status|stop`),输出按系统语言本地化。
fn tr(lang: Lang, en: &'static str, zh: &'static str) -> &'static str {
    match lang {
        Lang::En => en,
        Lang::Zh => zh,
    }
}

/// 生成 per-launch token(128-bit CSPRNG → 32 hex)。熵失败 → `None`。
fn generate_token() -> Option<String> {
    let mut buf = [0u8; 16];
    getrandom::getrandom(&mut buf).ok()?;
    Some(hex::encode(buf))
}

/// 解析并打开 canonical ledger(**R3**)。**复用 [`crate::setup::default_ledger_path`] 作 SSOT**
/// (`VIGIL_LEDGER_PATH`〔trim 非空〕> `<data_local>/Vigil/ledger.sqlite3`)—— 与 hook/setup **逐字节
/// 同一解析**,故 daemon bump 的 session risk 必落 hook `get_session_risk` 读的同一文件(共享 key=
/// upstream session_id)。不自行解析 env(否则 `var_os` 不 trim 与 setup 的 `var`+trim 分叉 → 空白
/// `VIGIL_LEDGER_PATH` 会让两端开不同文件、信号静默丢失;hostile F1)。best-effort:开不了 → `None`
/// (注入信号不落,PII 仍工作)。建父目录避免首次无目录失败。
fn open_canonical_ledger() -> Option<std::sync::Arc<vigil_audit::Ledger>> {
    let path = crate::setup::default_ledger_path()?;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    vigil_audit::Ledger::open(&path)
        .ok()
        .map(std::sync::Arc::new)
}

/// `vigil-hub daemon start`:前台启动 daemon。
///
/// 单实例:`bind` 失败(同名 socket 已被占用 = 已有 daemon)→ `Err` 退出。成功则**阻塞**于
/// `serve` accept 循环直到进程被杀(GUI 生命周期 P2.4 负责 spawn/kill)。
pub fn run_start(lang: Lang) -> Result<(), String> {
    let socket = default_socket_name();
    let listener = bind(&socket).map_err(|e| match lang {
        Lang::En => format!("bind failed (a daemon may already be running): {e}"),
        Lang::Zh => format!("绑定 socket 失败(可能已有 daemon 在运行):{e}"),
    })?;

    // ort 暖载层(ADR 0024):**在 serve spawn 任何线程之前**(进程仍单线程)暖载 PII scanner —— 复用
    // serve 的 ort init 纪律(dylib 稳源 + loader-lock 安全超时 abort)。best-effort:模型未缓存 /
    // init 失败 → None → model-less(hook 落硬指纹,**非 fail-open**)。非 ort 构建恒 None。
    // **并发不变量**:warm-load 内部 set_var 必须先于下方 `serve` 的 thread spawn —— 故顺序固定为
    // bind → warm-load → serve(谁在此之间插入 spawn 谁就破坏不变量,见 warm_load 函数注释)。
    #[cfg(feature = "ort")]
    let scanner = crate::serve::warm_load_pii_scanner_best_effort();
    #[cfg(not(feature = "ort"))]
    let scanner: Option<std::sync::Arc<dyn vigil_firewall::PiiScanner>> = None;
    let pii_loaded = scanner.is_some();

    // 注入分类器暖载(DeBERTa,ort-gated;同 PII 在单线程期)。+ **R3** 绑定自有 canonical ledger
    // (供 `ClassifyInjection` bump session risk;绝不开客户端命名文件)。
    #[cfg(feature = "ort")]
    let injection = crate::serve::warm_load_injection_classifier_best_effort();
    #[cfg(feature = "ort")]
    let inj_loaded = injection.is_some();
    #[cfg(not(feature = "ort"))]
    let inj_loaded = false;
    let ledger = open_canonical_ledger(); // best-effort:开不了 → 注入信号不落(PII 仍工作)

    let token = generate_token().ok_or_else(|| {
        tr(
            lang,
            "failed to generate a token (no entropy)",
            "生成 token 失败(无可用熵源)",
        )
        .to_string()
    })?;

    // daemon.json 的 `pii_loaded` / `inj_loaded` 反映**真实**暖载结果(GUI / `status` 据此显示就绪态)。
    let info = DaemonInfo {
        pid: std::process::id(),
        socket_path: socket,
        token: token.clone(),
        protocol_version: PROTOCOL_VERSION,
        pii_loaded,
        inj_loaded,
    };
    let path = daemon_info_path().ok_or_else(|| {
        tr(
            lang,
            "cannot locate the daemon.json directory",
            "无法定位 daemon.json 所在目录",
        )
        .to_string()
    })?;
    write_daemon_info(&path, &info).map_err(|e| match lang {
        Lang::En => format!("failed to write daemon.json: {e}"),
        Lang::Zh => format!("写入 daemon.json 失败:{e}"),
    })?;

    match lang {
        Lang::En => eprintln!(
            "vigil-hub daemon: listening on `{}` (pid {}); PII {}, injection {}",
            info.socket_path,
            info.pid,
            if pii_loaded { "warm" } else { "off" },
            if inj_loaded { "warm" } else { "off" }
        ),
        Lang::Zh => eprintln!(
            "vigil-hub daemon:正在监听 `{}`(pid {});PII {},注入 {}",
            info.socket_path,
            info.pid,
            if pii_loaded { "已暖载" } else { "未加载" },
            if inj_loaded { "已暖载" } else { "未加载" }
        ),
    }
    let caps = DaemonCaps {
        token,
        scanner,
        ledger,
        #[cfg(feature = "ort")]
        injection,
        pii_loaded,
        inj_loaded,
        started: std::time::Instant::now(),
    };
    serve(listener, caps); // 阻塞;正常不返回(accept 循环)。

    // serve 返回 = listener 终止(罕见)→ best-effort 清理 daemon.json,避免留陈旧记录。
    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// `daemon status --json` 的三态(与人类可读输出同一判定,只换 render)。
enum StatusState {
    NotRunning,
    Running {
        pid: u32,
        pii_loaded: bool,
        inj_loaded: bool,
        uptime_secs: u64,
        inflight: u32,
    },
    /// daemon.json 有记录但 query 联系不上(已退出 / pid 被重用 / 超时)。
    Stale {
        recorded_pid: u32,
    },
}

/// `--json` 的稳定输出 schema:机器可读、与界面语言无关(locale 事故根治面)。
/// 兼容性纪律:字段只增不删不改名;`running` 恒在;非 running 态带 `reason`。
fn status_json(state: &StatusState) -> serde_json::Value {
    match state {
        StatusState::NotRunning => serde_json::json!({
            "running": false,
            "reason": "not-running",
        }),
        StatusState::Running {
            pid,
            pii_loaded,
            inj_loaded,
            uptime_secs,
            inflight,
        } => serde_json::json!({
            "running": true,
            "pid": pid,
            "pii_loaded": pii_loaded,
            "inj_loaded": inj_loaded,
            "uptime_secs": uptime_secs,
            "inflight": inflight,
        }),
        StatusState::Stale { recorded_pid } => serde_json::json!({
            "running": false,
            "reason": "stale-or-unresponsive",
            "recorded_pid": recorded_pid,
        }),
    }
}

/// `vigil-hub daemon status`:读 daemon.json + 试 `query_daemon(Status)` 报告运行态。
///
/// daemon.json 缺 → 未运行;存在但 query 失败(未响应 / R1 不符 / 超时)→ 陈旧或异常。
/// `json=true` 输出 [`status_json`] 的稳定 schema(供脚本/CI;人类文案走 i18n 会随语言变)。
pub fn run_status(lang: Lang, json: bool) -> Result<(), String> {
    let Some(info) = daemon_info_path().and_then(|p| read_daemon_info(&p)) else {
        if json {
            println!("{}", status_json(&StatusState::NotRunning));
        } else {
            println!(
                "{}",
                tr(
                    lang,
                    "daemon: not running (no daemon.json)",
                    "daemon:未运行(无 daemon.json)",
                )
            );
        }
        return Ok(());
    };
    match query_daemon(Request::Status, Duration::from_secs(2)) {
        Some(Response::Status {
            pii_loaded,
            inj_loaded,
            uptime_secs,
            inflight,
        }) => {
            if json {
                println!(
                    "{}",
                    status_json(&StatusState::Running {
                        pid: info.pid,
                        pii_loaded,
                        inj_loaded,
                        uptime_secs,
                        inflight,
                    })
                );
                return Ok(());
            }
            match lang {
                Lang::En => println!(
                    "daemon: running (pid={}, pii_loaded={}, inj_loaded={}, uptime={}s, inflight={})",
                    info.pid, pii_loaded, inj_loaded, uptime_secs, inflight
                ),
                Lang::Zh => println!(
                    "daemon:运行中(pid={};PII 模型 {};注入模型 {};已运行 {}s;处理中 {})",
                    info.pid,
                    if pii_loaded { "已暖载" } else { "未加载" },
                    if inj_loaded { "已暖载" } else { "未加载" },
                    uptime_secs,
                    inflight
                ),
            }
        }
        _ => {
            if json {
                println!(
                    "{}",
                    status_json(&StatusState::Stale {
                        recorded_pid: info.pid
                    })
                );
                return Ok(());
            }
            match lang {
                Lang::En => println!(
                    "daemon: recorded (pid={}) but not responding -- it may have exited, or this pid \
                     is now reused by another program (not the original Vigil daemon). Re-run vigil-hub daemon start.",
                    info.pid
                ),
                Lang::Zh => println!(
                    "daemon:有记录(pid={}),但联系不上 —— 可能已退出,或这个 pid 已被别的程序占用 \
                     (并非原来的 Vigil 守护进程)。可重新运行 vigil-hub daemon start。",
                    info.pid
                ),
            }
        }
    }
    Ok(())
}

/// `vigil-hub daemon stop`:停止常驻 daemon(GUI 守护卡的 stop 按钮经此 shell-out)。
///
/// **防 pid 重用误杀**:先 `query_daemon(Status)` 经 **R1 peer-cred + token** 确认 daemon.json.pid
/// 真是活着的、本人的 Vigil daemon,**才** kill;不响应(可能已死、pid 已被无辜进程重用)→ 只清理
/// 陈旧 daemon.json,**绝不**杀那个 pid。
pub fn run_stop(lang: Lang) -> Result<(), String> {
    let Some(info) = daemon_info_path().and_then(|p| read_daemon_info(&p)) else {
        println!(
            "{}",
            tr(
                lang,
                "daemon: not running (no daemon.json)",
                "daemon:未运行(无 daemon.json)",
            )
        );
        return Ok(());
    };
    let path = daemon_info_path();
    // R1+token 验证存活:仅当 daemon 真应答才杀其 pid(防 pid 重用误杀无辜进程)。
    if query_daemon(Request::Status, Duration::from_secs(2)).is_none() {
        if let Some(p) = &path {
            let _ = std::fs::remove_file(p);
        }
        match lang {
            Lang::En => println!(
                "daemon: not reachable -- likely already exited. Removed the leftover record file; \
                 did NOT kill pid {} (it may now be reused by an unrelated program).",
                info.pid
            ),
            Lang::Zh => println!(
                "daemon:联系不上,可能早已退出。已清理残留的记录文件;没有强行结束进程号 {}(它可能已被其它无关程序占用,以免误杀)。",
                info.pid
            ),
        }
        return Ok(());
    }
    kill_pid(lang, info.pid)?;
    if let Some(p) = &path {
        let _ = std::fs::remove_file(p); // 强杀不会触发 serve 的自清理,这里补上
    }
    match lang {
        Lang::En => println!("daemon: stopped (pid {})", info.pid),
        Lang::Zh => println!("daemon:已停止(pid {})", info.pid),
    }
    Ok(())
}

/// 跨平台按 pid 结束进程(无 `unsafe`:走 OS 工具 `taskkill`/`kill`,不引 libc FFI,守 forbid unsafe)。
fn kill_pid(lang: Lang, pid: u32) -> Result<(), String> {
    let mut cmd = if cfg!(windows) {
        let mut c = std::process::Command::new("taskkill");
        c.args(["/F", "/PID", &pid.to_string()]);
        c
    } else {
        let mut c = std::process::Command::new("kill");
        c.arg(pid.to_string());
        c
    };
    // `output()` 捕获(吞掉)helper 自身的 stdout/stderr:taskkill 的本地化系统消息
    // (非 UTF-8 代码页下还会乱码)不该混进 Vigil 的用户输出;结果仍由退出码判定。
    let status = cmd.output().map(|o| o.status).map_err(|e| match lang {
        Lang::En => format!("failed to spawn the kill helper: {e}"),
        Lang::Zh => format!("启动结束进程助手失败:{e}"),
    })?;
    if !status.success() {
        return Err(match lang {
            Lang::En => format!(
                "failed to stop daemon pid {pid} (kill helper exit {:?})",
                status.code()
            ),
            Lang::Zh => format!(
                "停止 daemon(pid {pid})失败(结束助手退出码 {:?})",
                status.code()
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{generate_token, status_json, StatusState};

    #[test]
    fn generate_token_is_32_hex_chars_and_varies() {
        let a = generate_token().unwrap();
        let b = generate_token().unwrap();
        assert_eq!(a.len(), 32, "128-bit → 32 hex 字符");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()), "必须全 hex: {a}");
        assert_ne!(a, b, "per-launch token 应随机不同");
    }

    /// `--json` 稳定 schema 三态守门:脚本/CI 断言 `"running":true|false` + 各字段名。
    /// 字段只增不删不改名 —— 本测试即该纪律的回归锚。
    #[test]
    fn status_json_stable_schema_three_states() {
        let running = status_json(&StatusState::Running {
            pid: 42,
            pii_loaded: true,
            inj_loaded: false,
            uptime_secs: 7,
            inflight: 3,
        });
        assert_eq!(running["running"], true);
        assert_eq!(running["pid"], 42);
        assert_eq!(running["pii_loaded"], true);
        assert_eq!(running["inj_loaded"], false);
        assert_eq!(running["uptime_secs"], 7);
        assert_eq!(running["inflight"], 3);

        let not_running = status_json(&StatusState::NotRunning);
        assert_eq!(not_running["running"], false);
        assert_eq!(not_running["reason"], "not-running");

        let stale = status_json(&StatusState::Stale { recorded_pid: 42 });
        assert_eq!(stale["running"], false);
        assert_eq!(stale["reason"], "stale-or-unresponsive");
        assert_eq!(stale["recorded_pid"], 42);
    }
}
