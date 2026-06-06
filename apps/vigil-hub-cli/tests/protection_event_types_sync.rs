//! SSOT drift guard:`vigil-audit` 的保护事件类型字面量必须与 `vigil-mcp` 的 `EVENT_*` 常量逐字相等。
//!
//! `vigil-mcp` 依赖 `vigil-audit`(不能反向 import,否则成环),故 `inspect protection` 的聚合层
//! (vigil-audit)持有这些 `event_type` 字面量的**副本**。本测试(vigil-hub-cli 同时依赖二者)逐条
//! 核对一致 —— 防 vigil-mcp 改了某常量值而 `protection_summary` 静默计零(SSOT 漂移 = 安全可见性失真)。

use vigil_audit::{
    EVENT_TYPE_RAW_SECRET_BLOCKED, EVENT_TYPE_SECRET_ALIAS_UNRESOLVED, EVENT_TYPE_TOOL_RESULT_LEAK,
};
use vigil_mcp::{
    EVENT_RAW_SECRET_ATTEMPT_DETECTED, EVENT_SECRET_ALIAS_UNRESOLVED, EVENT_SECRET_LEAK_DETECTED,
};

#[test]
fn protection_event_type_literals_match_vigil_mcp_source_of_truth() {
    assert_eq!(
        EVENT_TYPE_RAW_SECRET_BLOCKED, EVENT_RAW_SECRET_ATTEMPT_DETECTED,
        "raw-secret 拦截事件类型漂移:inspect protection 会对裸 secret 拦截计零"
    );
    assert_eq!(
        EVENT_TYPE_TOOL_RESULT_LEAK, EVENT_SECRET_LEAK_DETECTED,
        "tool-result 泄漏事件类型漂移:inspect protection 会对脱敏成效计零"
    );
    assert_eq!(
        EVENT_TYPE_SECRET_ALIAS_UNRESOLVED, EVENT_SECRET_ALIAS_UNRESOLVED,
        "alias-unresolved 事件类型漂移:inspect protection 会对 alias 拒绝计零"
    );
}
