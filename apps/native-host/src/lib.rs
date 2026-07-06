//! Vigil Native Messaging Host —— lib 层:纯 I/O 循环供集成测试直接调。
//!
//! bin 入口在 `main.rs`:打开默认 Ledger 路径,调用 `run(stdin, stdout, ledger, session, ml)`。
//! 集成测试在 `tests/` 中注入 `Cursor<Vec<u8>>` 作 stdin / stdout,验证 framing + 分类器 + 审计。
//!
//! # ML 增强(daemon 第二客户端;Phase 1「引擎连接」)
//!
//! 硬指纹分类([`vigil_browser::classify`])仍是**无条件底座**;其上叠加一层可选的 daemon
//! ML PII 增强([`ml_augment`]):daemon(ADR 0024)可用 → 把模型命中的语义 PII
//! (email/person/phone/…)追加脱敏;daemon 缺席/超时/畸形/被 engine.json 关闭 → 行为
//! **逐字节等于**纯硬指纹现状(fail-closed,零回归)。**ML 只能收紧**(Allow→Redact),
//! 绝不放宽(Allow/Block 语义由硬指纹层独占)。
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod install;

/// β1 R1 BLOCKER 修复:判断 argv[1] 是否是管理员 CLI 子命令字面量。
///
/// Chrome 启动 Native Host 时会传 argv(Linux/macOS:`argv[1] = <extension origin>`,
/// Windows 额外 `argv[2] = --parent-window=<HWND>`)。若这些被 clap 解析,会判为未知 subcommand
/// 以 exit 2 退出,扩展看到 onDisconnect。本函数**仅** 返回 true 对白名单子命令字面量,
/// 其它(含无参 / Chrome origin / --parent-window / 任意未识别 argv)返 false → caller 直走
/// stdin/stdout run 循环。
///
/// 本函数是纯函数,接受 `argv` 作参数(`main()` 传 `std::env::args().collect::<Vec<_>>()`)。
/// 单测覆盖 Chrome 真实 argv 场景 + 管理员子命令场景,守门"Chrome 启动路径不被 clap 吃"。
pub fn is_admin_subcommand(args: &[String]) -> bool {
    args.get(1)
        .map(|s| {
            matches!(
                s.as_str(),
                "install" | "uninstall" | "status" | "help" | "--help" | "-h" | "--version" | "-V"
            )
        })
        .unwrap_or(false)
}

/// Ledger 落点解析(纯函数,DI 可测;审核 P1 EXT-01 修复)。优先级:
///
/// 1. `VIGIL_LEDGER_PATH` —— 全产品 canonical 环境变量(与 `vigil-hub-cli` `setup.rs`
///    `default_ledger_path` 一致);此前本 host 只认 `VIGIL_DB_PATH`,与 CLI/桌面分裂,
///    文档所述的对齐方式对 host 无效。
/// 2. `VIGIL_DB_PATH` —— 本 host 历史环境变量,保留为向后兼容别名。
/// 3. 默认 `<data_local_dir>/Vigil/ledger.sqlite3` —— canonical 共享账本(与 CLI/桌面
///    同文件),浏览器审计事件由此在桌面 Activity Feed 可见。此前默认 in-memory,
///    事件随 Chrome 停止 host 即丢(审计链断)。
/// 4. 连 `data_local_dir` 都取不到 → `None`(调用方回退 in-memory:分类防护优先于
///    审计持久化,绝不因审计初始化失败拒绝守门)。
///
/// 空/纯空白的环境变量值按未设置处理(不落进当前目录的空名文件)。
pub fn resolve_ledger_path(
    ledger_env: Option<&str>,
    db_env: Option<&str>,
    data_local: Option<std::path::PathBuf>,
) -> Option<std::path::PathBuf> {
    if let Some(p) = ledger_env.map(str::trim).filter(|s| !s.is_empty()) {
        return Some(std::path::PathBuf::from(p));
    }
    if let Some(p) = db_env.map(str::trim).filter(|s| !s.is_empty()) {
        return Some(std::path::PathBuf::from(p));
    }
    data_local.map(|d| d.join("Vigil").join("ledger.sqlite3"))
}

use std::io::{Read, Write};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use vigil_audit::Ledger;
use vigil_browser::{
    build_audit_payload, classify, event_type_for, read_frame, write_frame, BrowserAction,
    BrowserAuditMeta, BrowserCheckRequest, BrowserCheckResponse, BrowserErrorCode,
    BrowserErrorFrame, ClassifyOutcome,
};
use vigil_daemon_ipc::protocol::{Request, Response, ScanKind, WireFinding};
use vigil_daemon_ipc::transport::query_daemon;
use vigil_daemon_ipc::wire::{apply_wire_spans, cap_to_char_boundary, safe_label};

// ─────────────────────────── daemon ML 增强层(Phase 1「引擎连接」) ───────────────────────────

/// 单次 daemon 查询截止(对齐 hook `ML_QUERY_DEADLINE`;paste 路径最坏 +800ms,可接受)。
const ML_QUERY_DEADLINE: Duration = Duration::from_millis(800);

/// 送 ML 的文本前缀上限(对齐 hook `ML_SCAN_TEXT_CAP`;绝大多数 paste 远小于此。
/// 超出前缀的 suffix 无 ML,硬指纹底座在 classify 已全文扫过)。
const ML_SCAN_TEXT_CAP: usize = 16 * 1024;

/// 低于此长度不查 daemon(对齐 hook `ML_MIN_SEG_LEN`;超短文本无语义 PII 意义,省 RTT)。
const ML_MIN_TEXT_LEN: usize = 8;

/// daemon 查询失败后的冷却窗口:窗口内不再发起查询(降级纯硬指纹)。
///
/// hook 是 one-shot 进程(阻塞 worker 随进程回收);本 host 是 **Chrome 长驻进程**,
/// 慢/挂死 daemon 下若每次 paste 都查询,`query_daemon` 的 detached worker 会逐次累积、
/// 且每次白付 deadline 延迟。首次失败即静默 60s,窗口过后自动重试(daemon 恢复可自愈)。
const ML_FAILURE_COOLDOWN: Duration = Duration::from_secs(60);

/// 失败冷却状态(纯逻辑,DI 可测)。`record_failure` 记时刻;`in_cooldown` 查询窗口。
#[derive(Debug)]
struct FailureCooldown {
    window: Duration,
    last_failure: Mutex<Option<Instant>>,
}

impl FailureCooldown {
    const fn new(window: Duration) -> Self {
        Self {
            window,
            last_failure: Mutex::new(None),
        }
    }

    fn in_cooldown(&self, now: Instant) -> bool {
        let guard = self.last_failure.lock().unwrap_or_else(|e| e.into_inner());
        matches!(*guard, Some(t) if now.duration_since(t) < self.window)
    }

    fn record_failure(&self, now: Instant) {
        let mut guard = self.last_failure.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(now);
    }
}

/// engine.json(`{"version":1,"engine":"hardfp"|"ml"|"auto"}`,SSOT 见 vigil-hub-cli
/// `engine_config.rs`)是否允许查 daemon。**纯函数**(`raw` = 文件内容;`None` = 文件缺失):
///
/// - 缺失 → `true`(未配置 = auto 语义:查 daemon,缺席自然降级,零成本零回归);
/// - 显式 `"hardfp"` → `false`(尊重用户显式选择,与 hook 消费同一 SSOT 一致);
/// - `"ml"` / `"auto"` → `true`;
/// - 损坏 / 版本不识别 / 未知值 → `false`(对齐 engine_config「损坏收敛 hardfp」的
///   fail-closed 方向;本层解析独立于 SSOT 实现,字段漂移时最多退化为不启 ML,不影响防护)。
pub fn engine_allows_ml(raw: Option<&str>) -> bool {
    let Some(raw) = raw else {
        return true; // 文件缺失 = 未配置 → auto
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
        return false; // 损坏 → 收敛 hardfp
    };
    if v.get("version").and_then(serde_json::Value::as_u64) != Some(1) {
        return false; // 版本不识别 → 不按旧语义猜
    }
    matches!(
        v.get("engine").and_then(serde_json::Value::as_str),
        Some("ml") | Some("auto")
    )
}

/// ML 探针(DI 边界,production-logic-testable):`scan` 返 `None` = 本次不可用
/// (daemon 缺席/超时/协议错/被禁用/冷却中),`Some(findings)` = 扫描成功(可为空 = 无命中)。
pub trait MlProbe {
    /// 对 `text` 做一次 daemon ML PII 扫描。
    fn scan(&self, text: &str) -> Option<Vec<WireFinding>>;
}

/// 生产实现:engine.json 门控 + 失败冷却 + `query_daemon(RedactScan)`。
///
/// 每请求现读 engine.json(host 为 Chrome 长驻进程,现读避免配置陈旧;文件极小,
/// paste 为人手频率,成本可忽略)。
#[derive(Debug)]
pub struct DaemonProbe {
    cooldown: FailureCooldown,
}

impl DaemonProbe {
    /// 新建(冷却窗口 [`ML_FAILURE_COOLDOWN`])。
    pub fn new() -> Self {
        Self {
            cooldown: FailureCooldown::new(ML_FAILURE_COOLDOWN),
        }
    }
}

impl Default for DaemonProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl MlProbe for DaemonProbe {
    fn scan(&self, text: &str) -> Option<Vec<WireFinding>> {
        if self.cooldown.in_cooldown(Instant::now()) {
            return None;
        }
        let engine_raw = dirs::data_local_dir()
            .map(|d| d.join("Vigil").join("engine.json"))
            .and_then(|p| std::fs::read_to_string(p).ok());
        if !engine_allows_ml(engine_raw.as_deref()) {
            return None;
        }
        match query_daemon(
            Request::RedactScan {
                kind: ScanKind::Args,
                text: text.to_string(),
            },
            ML_QUERY_DEADLINE,
        ) {
            Some(Response::Findings { findings }) => Some(findings),
            // 缺席/超时/Error/非预期响应 → 记失败进冷却(防长驻进程 worker 累积),降级硬指纹。
            _ => {
                self.cooldown.record_failure(Instant::now());
                None
            }
        }
    }
}

/// 恒不可用探针:集成测试 / 显式关闭用(行为 = 纯硬指纹现状)。
#[derive(Debug)]
pub struct DisabledMlProbe;

impl MlProbe for DisabledMlProbe {
    fn scan(&self, _text: &str) -> Option<Vec<WireFinding>> {
        None
    }
}

/// findings → 去重升序的 sanitize 标签表(进 `BrowserCheckResponse.ml_labels` 与审计;
/// 只含类别名,不含任何 span 文本)。
fn collect_ml_labels(findings: &[WireFinding]) -> Vec<String> {
    let set: std::collections::BTreeSet<String> =
        findings.iter().map(|f| safe_label(&f.label)).collect();
    set.into_iter().collect()
}

/// daemon ML PII 增强(fail-closed 纯加性)。返回参与审计的引擎标识:
/// `"hardfp"`(未查/不可用/Block 短路)或 `"hardfp+ml"`(daemon 扫描成功,含无命中)。
///
/// 语义(与 hook `MlScrub` 同构,ADR 0024 D2):
/// - `Block` 短路:硬指纹已最严,不查(省 RTT);
/// - 基底 = 硬指纹层最终文本(`Redact` → `scrub_text_with_spans` 的占位符文本 + 其
///   **自产占位符区间**作 `protected`;`Allow` → 原文、无保护区),ML 在**基底**上扫 →
///   span 坐标系一致;[`apply_wire_spans`] 做并集合并 + 受保护区减法(VIGIL-SEC-OVERLAP/-PH);
/// - ML 命中露出区间 → `Allow` 升级 `Redact` / `Redact` 文本再遮盖(**只收紧**);
///   全部命中都落在占位符内 → 响应原样;
/// - 纵深防御:ML 改写后再跑一遍硬指纹扫描,残留即 `Block`(与 §I-9.6 同精神;
///   基底已过 classify 的 re-scan,此分支理论不可达,保留作防御层)。
fn ml_augment(text: &str, resp: &mut BrowserCheckResponse, ml: &dyn MlProbe) -> &'static str {
    if matches!(resp.action, BrowserAction::Block) {
        return "hardfp";
    }
    if text.len() < ML_MIN_TEXT_LEN {
        return "hardfp";
    }
    // 基底与保护区:Redact 时重算带区间的 scrub(`scrub_text_with_spans().0 == scrub_text()`
    // 有 vigil-redaction 单测守恒,与 classify 已产出的 redacted_text 一致)。
    let (base, protected) = match resp.action {
        BrowserAction::Redact => vigil_redaction::scrub_text_with_spans(text),
        _ => (text.to_string(), Vec::new()),
    };
    let capped = cap_to_char_boundary(&base, ML_SCAN_TEXT_CAP);
    let scanned_len = capped.len();
    let Some(findings) = ml.scan(capped) else {
        return "hardfp";
    };
    if findings.is_empty() {
        return "hardfp+ml";
    }
    let (out, hits) = apply_wire_spans(&base, scanned_len, &findings, &protected);
    if hits == 0 {
        // 全部 ML 命中都在硬指纹占位符内(已脱敏)→ 响应原样。
        return "hardfp+ml";
    }
    // 纵深防御(§I-9.6 同精神):改写后残留硬指纹 → Block,绝不让半成品进 DOM。
    if !vigil_redaction::scan_hard_findings(&out).is_empty() {
        resp.action = BrowserAction::Block;
        resp.redacted_text = None;
        resp.ml_labels = collect_ml_labels(&findings);
        return "hardfp+ml";
    }
    resp.action = BrowserAction::Redact; // Allow→Redact 升级;Redact 保持
    resp.redacted_text = Some(out);
    resp.ml_labels = collect_ml_labels(&findings);
    "hardfp+ml"
}

// ─────────────────────────── stdin/stdout 主循环 ───────────────────────────

/// 主循环:反复 read_frame → 分类(+ ML 增强)→ write_frame;返 `()` 表示正常 EOF。
///
/// 任何协议错都以 `BrowserErrorFrame` 形式回写给 peer,**不**让错误冒泡到
/// stdout raw bytes(Chrome native messaging 一旦 stdout 写坏就会断连接)。
pub fn run<R: Read, W: Write>(
    stdin: &mut R,
    stdout: &mut W,
    ledger: &Ledger,
    session_id: &str,
    ml: &dyn MlProbe,
) -> Result<(), std::io::Error> {
    loop {
        match read_frame(stdin) {
            Ok(Some(payload)) => {
                handle_one(&payload, stdout, ledger, session_id, ml)?;
            }
            Ok(None) => return Ok(()), // 扩展断开
            Err(code) => {
                // Codex R1 MUST-FIX:protocol-level 错(TooLarge / Internal)**视为致命**,
                // 必须断开连接。不能继续 loop:若 peer 真发了 oversized frame 完整 body,
                // 后续字节会被误判为新帧的 length prefix,连接进入永久乱序。
                write_error(stdout, code, None)?;
                return Ok(());
            }
        }
    }
}

fn handle_one<W: Write>(
    payload: &[u8],
    stdout: &mut W,
    ledger: &Ledger,
    session_id: &str,
    ml: &dyn MlProbe,
) -> Result<(), std::io::Error> {
    // 解析请求
    let req: BrowserCheckRequest = match serde_json::from_slice(payload) {
        Ok(r) => r,
        Err(_) => {
            return write_error(stdout, BrowserErrorCode::BadJson, None);
        }
    };

    // 分类(硬指纹底座)
    match classify(&req) {
        ClassifyOutcome::Error(code) => {
            write_error(stdout, code, Some(req.request_id.clone()))?;
        }
        ClassifyOutcome::Response(mut resp) => {
            // daemon ML 增强(fail-closed 纯加性;daemon 缺席时本行为恒等于现状)。
            let engine = ml_augment(&req.text, &mut resp, ml);
            // 审计(metadata only)—— 用 `BrowserAuditMeta` 接口边界编码"不得含 raw text"
            let meta = BrowserAuditMeta {
                origin: &req.origin,
                event_kind: req.event_kind,
                request_id: &req.request_id,
                text_len: req.text.len(),
                engine,
            };
            let audit_payload = build_audit_payload(&meta, &resp);
            let event_type = event_type_for(req.event_kind);
            // redacted_text 仅作 FTS 提示;不含原文
            let fts = format!(
                "{} origin:{} action:{}",
                event_type, req.origin, audit_payload["action"]
            );
            let _ = ledger.append_event(session_id, event_type, &audit_payload, Some(&fts));

            // 回写 response
            let body = serde_json::to_vec(&resp).unwrap_or_else(|_| b"{}".to_vec());
            if let Err(code) = write_frame(stdout, &body) {
                return write_error(stdout, code, Some(req.request_id));
            }
        }
    }
    Ok(())
}

fn write_error<W: Write>(
    stdout: &mut W,
    code: BrowserErrorCode,
    request_id: Option<String>,
) -> Result<(), std::io::Error> {
    let frame = BrowserErrorFrame {
        error: code,
        request_id,
    };
    let body = serde_json::to_vec(&frame).unwrap_or_else(|_| b"{}".to_vec());
    let _ = write_frame(stdout, &body); // 忽略 framing 失败(stdout 已坏也无能为力)
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════════
// 单元测试(clippy::items-after-test-module 要求测试 module 在文件最底部)
// ═══════════════════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod argv_dispatch_tests {
    use super::is_admin_subcommand;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_args_goes_to_run() {
        // 手工无参启动(非 Chrome 场景;走 run 循环)
        assert!(!is_admin_subcommand(&argv(&["vigil-native-host"])));
    }

    #[test]
    fn chrome_origin_argv_goes_to_run() {
        // Chrome 实际传 extension origin 作 argv[1](Linux/macOS)
        assert!(!is_admin_subcommand(&argv(&[
            "vigil-native-host",
            "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
        ])));
    }

    #[test]
    fn chrome_windows_argv_with_parent_window_goes_to_run() {
        // Windows 额外 --parent-window;argv[1] 仍是 origin,本函数只看 argv[1]
        assert!(!is_admin_subcommand(&argv(&[
            "vigil-native-host.exe",
            "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
            "--parent-window=12345",
        ])));
    }

    #[test]
    fn admin_subcommands_are_recognized() {
        for cmd in ["install", "uninstall", "status", "help"] {
            assert!(
                is_admin_subcommand(&argv(&["vigil-native-host", cmd])),
                "{cmd} should be recognized as admin subcommand"
            );
        }
    }

    #[test]
    fn clap_help_flags_are_recognized() {
        for flag in ["--help", "-h", "--version", "-V"] {
            assert!(
                is_admin_subcommand(&argv(&["vigil-native-host", flag])),
                "{flag} should be recognized"
            );
        }
    }

    #[test]
    fn unknown_flags_and_subcommands_go_to_run() {
        // 防御:未来 Chrome 加新 argv 风格,或其它未预期输入,一律 fallback run
        for bad in [
            "--unknown-flag",
            "install-something",
            "--parent-window=99",
            "chrome-extension://short/",
            "run",
        ] {
            assert!(
                !is_admin_subcommand(&argv(&["vigil-native-host", bad])),
                "{bad} should NOT be recognized as admin subcommand (fallback run)"
            );
        }
    }
}

#[cfg(test)]
mod ledger_path_tests {
    use super::resolve_ledger_path;
    use std::path::PathBuf;

    #[test]
    fn canonical_env_wins_over_alias_and_default() {
        let got = resolve_ledger_path(
            Some("C:/custom/ledger.sqlite3"),
            Some("C:/legacy/db.sqlite"),
            Some(PathBuf::from("C:/data-local")),
        );
        assert_eq!(got, Some(PathBuf::from("C:/custom/ledger.sqlite3")));
    }

    #[test]
    fn legacy_alias_still_honored_when_canonical_unset() {
        let got = resolve_ledger_path(
            None,
            Some("C:/legacy/db.sqlite"),
            Some(PathBuf::from("C:/data-local")),
        );
        assert_eq!(got, Some(PathBuf::from("C:/legacy/db.sqlite")));
    }

    #[test]
    fn default_is_canonical_shared_ledger_under_data_local() {
        // 与 vigil-hub-cli setup.rs default_ledger_path 同构:<data_local>/Vigil/ledger.sqlite3
        let got = resolve_ledger_path(None, None, Some(PathBuf::from("/home/u/.local/share")));
        assert_eq!(
            got,
            Some(PathBuf::from("/home/u/.local/share/Vigil/ledger.sqlite3"))
        );
    }

    #[test]
    fn blank_env_values_treated_as_unset() {
        let got = resolve_ledger_path(Some("  "), Some(""), Some(PathBuf::from("/dl")));
        assert_eq!(got, Some(PathBuf::from("/dl/Vigil/ledger.sqlite3")));
    }

    #[test]
    fn no_env_no_data_local_falls_back_none_for_in_memory() {
        assert_eq!(resolve_ledger_path(None, None, None), None);
    }
}

#[cfg(test)]
mod ml_augment_tests {
    use super::{engine_allows_ml, ml_augment, FailureCooldown, MlProbe};
    use std::cell::Cell;
    use std::time::{Duration, Instant};
    use vigil_browser::{classify, BrowserAction, BrowserCheckRequest, ClassifyOutcome};
    use vigil_daemon_ipc::protocol::WireFinding;

    /// 固定返回 findings 的探针 + 调用计数(验证短路路径确实不查)。
    struct FixedProbe {
        findings: Option<Vec<WireFinding>>,
        calls: Cell<usize>,
    }
    impl FixedProbe {
        fn new(findings: Option<Vec<WireFinding>>) -> Self {
            Self {
                findings,
                calls: Cell::new(0),
            }
        }
    }
    impl MlProbe for FixedProbe {
        fn scan(&self, _text: &str) -> Option<Vec<WireFinding>> {
            self.calls.set(self.calls.get() + 1);
            self.findings.clone()
        }
    }

    fn wf(label: &str, start: usize, end: usize) -> WireFinding {
        WireFinding {
            label: label.to_string(),
            start,
            end,
        }
    }

    fn classified(text: &str) -> vigil_browser::BrowserCheckResponse {
        let req = BrowserCheckRequest {
            request_id: "11111111-1111-1111-1111-111111111111".into(),
            origin: "https://chatgpt.com".into(),
            event_kind: vigil_browser::BrowserEventKind::Paste,
            text: text.into(),
        };
        match classify(&req) {
            ClassifyOutcome::Response(r) => r,
            ClassifyOutcome::Error(e) => panic!("unexpected classify error: {e:?}"),
        }
    }

    #[test]
    fn daemon_unavailable_is_byte_identical_to_hardfp_baseline() {
        // 黄金对照:probe 恒 None → 响应与纯硬指纹现状逐字段相等(fail-closed 零回归)。
        let text = "please check alice@example.com and ghp_0123456789abcdefghijABCDEFGHIJ123456";
        let baseline = classified(text);
        let mut resp = classified(text);
        let engine = ml_augment(text, &mut resp, &FixedProbe::new(None));
        assert_eq!(engine, "hardfp");
        assert_eq!(resp.action, baseline.action);
        assert_eq!(resp.redacted_text, baseline.redacted_text);
        assert_eq!(resp.findings, baseline.findings);
        assert!(resp.ml_labels.is_empty());
    }

    #[test]
    fn ml_only_hit_upgrades_allow_to_redact_with_labels() {
        // 硬指纹 Allow + ML 命中语义 PII → 收紧为 Redact,占位符含 sanitize 标签。
        let text = "contact alice@example.com please";
        let mut resp = classified(text);
        assert_eq!(resp.action, BrowserAction::Allow, "前置:硬指纹应放行");
        let probe = FixedProbe::new(Some(vec![wf("private_email", 8, 25)]));
        let engine = ml_augment(text, &mut resp, &probe);
        assert_eq!(engine, "hardfp+ml");
        assert_eq!(resp.action, BrowserAction::Redact, "ML 命中应收紧为 Redact");
        let out = resp.redacted_text.as_deref().unwrap();
        assert!(!out.contains("alice@example.com"), "PII 应被遮盖:{out}");
        assert!(out.contains("[REDACTED private_email]"));
        assert_eq!(resp.ml_labels, vec!["private_email".to_string()]);
    }

    #[test]
    fn ml_scan_clean_keeps_allow_and_marks_engine() {
        // daemon 扫过但无命中 → Allow 保持;engine 标 hardfp+ml(审计可区分"没扫"与"扫了没中")。
        let text = "just a plain sentence";
        let mut resp = classified(text);
        let engine = ml_augment(text, &mut resp, &FixedProbe::new(Some(vec![])));
        assert_eq!(engine, "hardfp+ml");
        assert_eq!(resp.action, BrowserAction::Allow);
        assert!(resp.ml_labels.is_empty());
    }

    #[test]
    fn redact_base_protects_hardfp_placeholders_from_ml_overcapture() {
        // 硬指纹 Redact 基底上,ML span over-capture 进占位符 → 减法保占位符完整,露出部分被遮。
        let text = "mail bob@x.io token ghp_0123456789abcdefghijABCDEFGHIJ123456";
        let mut resp = classified(text);
        assert_eq!(resp.action, BrowserAction::Redact, "前置:硬指纹应 Redact");
        let base = vigil_redaction::scrub_text_with_spans(text).0;
        // ML 声称从 0 覆盖到占位符内部(over-capture):email "mail bob@x.io" + 深入占位符 3 字节。
        let placeholder_start = base.find("[REDACTED").expect("应有硬指纹占位符");
        let probe = FixedProbe::new(Some(vec![wf("private_email", 0, placeholder_start + 3)]));
        let engine = ml_augment(text, &mut resp, &probe);
        assert_eq!(engine, "hardfp+ml");
        let out = resp.redacted_text.as_deref().unwrap();
        assert!(!out.contains("bob@x.io"), "露出区 PII 应被遮:{out}");
        assert!(
            out.contains("[REDACTED github_token]") || out.contains("[REDACTED "),
            "硬指纹占位符不得被切碎:{out}"
        );
        assert!(
            !out.contains("ghp_0123456789"),
            "硬指纹脱敏不得被 ML 改写回退:{out}"
        );
    }

    #[test]
    fn ml_hits_fully_inside_placeholder_leave_response_unchanged() {
        // ML 命中全落在硬指纹占位符内(已脱敏)→ 减法后零替换,响应原样(仅 engine 标记)。
        let text = "k ghp_0123456789abcdefghijABCDEFGHIJ123456";
        let mut resp = classified(text);
        let before = resp.clone();
        let base = vigil_redaction::scrub_text_with_spans(text).0;
        let ph_start = base.find("[REDACTED").unwrap();
        let probe = FixedProbe::new(Some(vec![wf("secret", ph_start + 2, ph_start + 8)]));
        let engine = ml_augment(text, &mut resp, &probe);
        assert_eq!(engine, "hardfp+ml");
        assert_eq!(resp.action, before.action);
        assert_eq!(resp.redacted_text, before.redacted_text);
        assert!(resp.ml_labels.is_empty(), "零实际替换不应标注 ml_labels");
    }

    #[test]
    fn block_short_circuits_without_probing_daemon() {
        // 硬指纹 Block(PEM)已最严 → 不查 daemon(省 RTT),engine=hardfp。
        let text = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----";
        let mut resp = classified(text);
        assert_eq!(resp.action, BrowserAction::Block, "前置:PEM 应 Block");
        let probe = FixedProbe::new(Some(vec![wf("x", 0, 5)]));
        let engine = ml_augment(text, &mut resp, &probe);
        assert_eq!(engine, "hardfp");
        assert_eq!(probe.calls.get(), 0, "Block 短路不得查 daemon");
        assert_eq!(resp.action, BrowserAction::Block);
    }

    #[test]
    fn short_text_skips_probe() {
        let text = "hi";
        let mut resp = classified(text);
        let probe = FixedProbe::new(Some(vec![wf("x", 0, 2)]));
        let engine = ml_augment(text, &mut resp, &probe);
        assert_eq!(engine, "hardfp");
        assert_eq!(probe.calls.get(), 0);
    }

    #[test]
    fn malicious_labels_are_sanitized_and_deduped() {
        // daemon 响应按不可信处理:label 注入字符被滤、重复去重、输出升序。
        let text = "contact alice@example.com and bob@example.com now";
        let mut resp = classified(text);
        let probe = FixedProbe::new(Some(vec![
            wf("e]mail[inj", 8, 25),
            wf("e]mail[inj", 30, 45),
        ]));
        ml_augment(text, &mut resp, &probe);
        assert_eq!(
            resp.ml_labels,
            vec!["emailinj".to_string()],
            "sanitize + 去重"
        );
        let out = resp.redacted_text.as_deref().unwrap();
        assert!(
            !out.contains(']') || !out.contains("e]mail"),
            "标签注入字符不得入占位符:{out}"
        );
    }

    #[test]
    fn engine_gate_semantics() {
        // 缺失 → auto(查);hardfp 显式关;ml/auto 开;损坏/坏版本/未知值 → fail-closed 关。
        assert!(engine_allows_ml(None));
        assert!(!engine_allows_ml(Some(
            r#"{"version":1,"engine":"hardfp"}"#
        )));
        assert!(engine_allows_ml(Some(r#"{"version":1,"engine":"ml"}"#)));
        assert!(engine_allows_ml(Some(r#"{"version":1,"engine":"auto"}"#)));
        assert!(!engine_allows_ml(Some("not json")));
        assert!(!engine_allows_ml(Some(r#"{"version":2,"engine":"ml"}"#)));
        assert!(!engine_allows_ml(Some(r#"{"version":1,"engine":"turbo"}"#)));
        assert!(!engine_allows_ml(Some(r#"{"version":1}"#)));
    }

    #[test]
    fn failure_cooldown_window_gates_and_expires() {
        let cd = FailureCooldown::new(Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(!cd.in_cooldown(t0), "初始无失败 → 不在冷却");
        cd.record_failure(t0);
        assert!(cd.in_cooldown(t0 + Duration::from_secs(30)), "窗口内跳过");
        assert!(
            !cd.in_cooldown(t0 + Duration::from_secs(61)),
            "窗口过后自动恢复(daemon 复活可自愈)"
        );
    }
}
