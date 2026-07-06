//! 浏览器防线状态(Protection Overview 卡):本机 native messaging host 的注册态。
//!
//! 直调 `vigil_native_host::install::status`(结构化返回,免 shell-out 文本解析;
//! 只读,不触任何注册表/manifest 写入)。ML daemon 运行态由既有 `daemon_status`
//! command 提供,前端合并展示(已注册 + ML 运行中 → 深度脱敏全开)。

use serde::Serialize;

/// 浏览器防线(native host)注册状态 DTO。
#[derive(Debug, Clone, Serialize)]
pub struct BrowserGuardStatus {
    /// 综合判定:manifest 在位且(Windows 上)HKCU 注册表键在位。
    pub registered: bool,
    /// host manifest JSON 是否存在。
    pub manifest_exists: bool,
    /// Windows HKCU 注册表键是否在位;非 Windows 平台恒 `null`。
    pub registry_present: Option<bool>,
}

/// 读取本机 native host 注册状态(只读)。
pub fn browser_guard_status() -> Result<BrowserGuardStatus, String> {
    let report = vigil_native_host::install::status(None).map_err(|e| e.to_string())?;
    // 非 Windows 无注册表概念(`registry_present = None`)→ 仅看 manifest。
    let registered = report.manifest_exists && report.registry_present.unwrap_or(true);
    Ok(BrowserGuardStatus {
        registered,
        manifest_exists: report.manifest_exists,
        registry_present: report.registry_present,
    })
}

#[cfg(test)]
mod tests {
    use super::browser_guard_status;

    /// 只读冒烟:真实环境下(不管是否注册)必须返回 Ok 且字段自洽 ——
    /// `registered` 蕴含 `manifest_exists`(综合判定不得凭空为真)。
    #[test]
    fn status_is_readonly_and_consistent() {
        let s = browser_guard_status().expect("status query must not fail");
        if s.registered {
            assert!(s.manifest_exists, "registered 蕴含 manifest_exists");
        }
    }
}
