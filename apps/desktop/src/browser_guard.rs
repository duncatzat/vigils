//! 浏览器防线状态(Protection Overview 卡):本机 native messaging host 的注册态。
//!
//! 直调 `vigil_native_host::install::status`(结构化返回,免 shell-out 文本解析;
//! 只读,不触任何注册表/manifest 写入)。ML daemon 运行态由既有 `daemon_status`
//! command 提供,前端合并展示(已注册 + ML 运行中 → 深度脱敏全开)。

use serde::Serialize;

/// 浏览器防线(native host)注册状态 + 最近 24h 守门统计 DTO。
#[derive(Debug, Clone, Serialize)]
pub struct BrowserGuardStatus {
    /// 综合判定:manifest 在位且(Windows 上)HKCU 注册表键在位。
    pub registered: bool,
    /// host manifest JSON 是否存在。
    pub manifest_exists: bool,
    /// Windows HKCU 注册表键是否在位;非 Windows 平台恒 `null`。
    pub registry_present: Option<bool>,
    /// 最近 24h 浏览器检查总数(paste/input/submit)。
    pub checks_24h: u64,
    /// 其中拦截(block)。
    pub blocked_24h: u64,
    /// 其中脱敏放行(redact)。
    pub redacted_24h: u64,
}

/// 读取本机 native host 注册状态 + 24h 守门统计(均只读)。
///
/// 注册态查询失败(home 不可得等)按未注册处理:状态卡宁可保守提示,不报错阻塞整页;
/// 统计走 ledger 纯读([`vigil_audit::Ledger::browser_guard_counts`],窗口 = now-24h)。
pub fn browser_guard_status(ledger: &vigil_audit::Ledger) -> Result<BrowserGuardStatus, String> {
    let (manifest_exists, registry_present) = match vigil_native_host::install::status(None) {
        Ok(report) => (report.manifest_exists, report.registry_present),
        Err(_) => (false, None),
    };
    // 非 Windows 无注册表概念(`registry_present = None`)→ 仅看 manifest。
    let registered = manifest_exists && registry_present.unwrap_or(true);
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
        .saturating_sub(24 * 3600);
    let counts = ledger
        .browser_guard_counts(since)
        .map_err(|e| e.to_string())?;
    Ok(BrowserGuardStatus {
        registered,
        manifest_exists,
        registry_present,
        checks_24h: counts.checks,
        blocked_24h: counts.blocked,
        redacted_24h: counts.redacted,
    })
}

#[cfg(test)]
mod tests {
    use super::browser_guard_status;

    /// 只读冒烟:真实环境下(不管是否注册)必须返回 Ok 且字段自洽 ——
    /// `registered` 蕴含 `manifest_exists`(综合判定不得凭空为真)。
    #[test]
    fn status_is_readonly_and_consistent() {
        let ledger = vigil_audit::Ledger::open_in_memory().expect("in-memory ledger");
        let s = browser_guard_status(&ledger).expect("status query must not fail");
        if s.registered {
            assert!(s.manifest_exists, "registered 蕴含 manifest_exists");
        }
        assert_eq!((s.checks_24h, s.blocked_24h, s.redacted_24h), (0, 0, 0));
    }
}
