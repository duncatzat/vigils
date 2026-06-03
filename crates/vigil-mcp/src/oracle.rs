//! 生产环境的 `DescriptorOracle` 实现:基于 [`Ledger`] 的 server registry。
//!
//! I04 范围内的信任判定:
//! - 若 server 未登记 / trust_level = Untrusted → `FirstSeen`
//! - 若 server.descriptor_hash 为 None(从未见过任何工具) → `FirstSeen`
//! - 若 server.descriptor_hash 与本次调用传入的 hash 不等 → `Drifted`(I05 再做正式 re-approval)
//! - 否则 → `ApprovedStable`
//!
//! Hub 在 `tools/list` 时会更新 server 的聚合 descriptor_hash;`tools/call`
//! 时传入该工具的 descriptor_hash,oracle 对比判定。

use std::sync::Arc;

use vigil_audit::Ledger;
use vigil_firewall::scorer::{DescriptorOracle, DescriptorStatus};
use vigil_types::TrustLevel;

/// Registry 支持的 DescriptorOracle。
#[derive(Clone)]
pub struct RegistryDescriptorOracle {
    ledger: Arc<Ledger>,
}

impl std::fmt::Debug for RegistryDescriptorOracle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryDescriptorOracle").finish()
    }
}

impl RegistryDescriptorOracle {
    /// 构造。
    pub fn new(ledger: Arc<Ledger>) -> Self {
        Self { ledger }
    }
}

/// 合法 descriptor_hash 必须是 64 字符 sha256 hex —— 真 `descriptor_hash()` 恒产出此形式。
/// 用于 fail-closed 守门:非此形式(空 / 哨兵 / 截断)的 incoming hash 永不可能与真 pin 相等,
/// 直接判 FirstSeen,**绝不**进入 `h == descriptor_hash` 的 ApprovedStable 分支(VIGIL-SEC-004)。
fn is_valid_descriptor_hash(h: &str) -> bool {
    h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())
}

impl DescriptorOracle for RegistryDescriptorOracle {
    fn status(&self, server_id: &str, tool_name: &str, descriptor_hash: &str) -> DescriptorStatus {
        // VIGIL-SEC-004(security audit defense-in-depth):非法/空 descriptor_hash 一律
        // fail-closed 到 FirstSeen —— 即便某个非 64-hex 串被误 pin+approve,带非法 hash 的
        // 调用也无法走 ApprovedStable 自动放行。
        if !is_valid_descriptor_hash(descriptor_hash) {
            return DescriptorStatus::FirstSeen;
        }
        // B1(Codex I04 review):改用 **per-tool** hash 比对。
        // 权威来源是 `tool_descriptors` 表;server trust_level 只作前置门闸。
        let Ok(Some(profile)) = self.ledger.get_server(server_id) else {
            return DescriptorStatus::FirstSeen;
        };
        if !matches!(
            profile.trust_level,
            TrustLevel::Limited | TrustLevel::Trusted
        ) {
            return DescriptorStatus::FirstSeen;
        }
        match self.ledger.get_pinned_tool_hash(server_id, tool_name) {
            Ok(Some(h)) if h == descriptor_hash => DescriptorStatus::ApprovedStable,
            Ok(Some(_)) => DescriptorStatus::Drifted,
            // 未登记或查询失败 → FirstSeen
            _ => DescriptorStatus::FirstSeen,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_valid_descriptor_hash;

    #[test]
    fn valid_descriptor_hash_accepts_64_hex_rejects_malformed() {
        // 真 sha256(64 lower-hex)
        assert!(is_valid_descriptor_hash(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
        // VIGIL-SEC-004:空 / 哨兵 / 截断 / 非 hex / 超长 全部拒(→ 调用方判 FirstSeen)
        assert!(!is_valid_descriptor_hash(""), "empty");
        assert!(
            !is_valid_descriptor_hash("sdk-decide-call:uuid"),
            "sentinel"
        );
        assert!(!is_valid_descriptor_hash("abc"), "too short");
        assert!(
            !is_valid_descriptor_hash(&"g".repeat(64)),
            "64 chars but non-hex"
        );
        assert!(!is_valid_descriptor_hash(&"a".repeat(65)), "too long");
    }
}
