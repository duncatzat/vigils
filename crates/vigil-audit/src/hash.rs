//! Hash chain —— 见 ADR 0002 §D3 + Revised 2026-06-03(security audit VIGIL-SEC-001)。
//!
//! **v1**(`compute_event_hash`,DOMAIN_TAG v1)= SHA-256(
//!     DOMAIN_TAG
//!   ‖ u32_be(32) ‖ prev_hash_bytes(32 字节;genesis 全 0)
//!   ‖ u64_be(len(payload_jcs)) ‖ payload_jcs
//!   ‖ u32_be(8)  ‖ created_at_be(i64)
//! )
//!
//! **v2**(`compute_event_hash_v2`,DOMAIN_TAG v2)= v1 字段 + 额外绑定
//!   ‖ u64_be(len(session_id)) ‖ session_id
//!   ‖ u64_be(len(event_type)) ‖ event_type
//!   ‖ presence_tag(1B) [ ‖ u64_be(len(redacted_text)) ‖ redacted_text ]
//!
//! **为什么有 v2**(security audit VIGIL-SEC-001 / A08):v1 摘要只覆盖 prev_hash/payload/
//! created_at,而 `session_id` / `event_type` / `redacted_text` 是 events 表的独立列且
//! (对 tool_call.* 事件)不在 payload_json 内 —— 本地具 DB 写权限者可改写这三列(把事件
//! 移出某 session 回放、改写 FTS/UI 显示的 redacted_text、翻转 event_type)而 `verify_chain`
//! **检测不到**,部分削弱 threat #7「审计篡改」缓解。v2 把这三列纳入摘要,使**部分篡改**
//! 可被检测。版本化(per-event `chain_version`)保证历史 v1 事件仍按 v1 验证、不被破坏。
//!
//! **固有限制**(非本修复范围):具完整 DB 写权限者仍可一致地重写整条链(任意版本/内容);
//! hash chain 在无外部 anchor(定期把最新 hash 发布到不可变位置)时只能检测**部分**篡改、
//! 抬高门槛,无法防住「全链重写」。外部 checkpoint 锚定是后续增强方向。

use crate::error::{AuditError, Result};
use sha2::{Digest, Sha256};

/// domain tag 固定常量(v1)。修改 = breaking change,需升级 ADR 并提供迁移策略。
pub const DOMAIN_TAG: &[u8] = b"vigil.ledger.event.v1";

/// v2 domain tag(VIGIL-SEC-001):区分 v2 摘要,使 v1/v2 hash 永不混淆。
pub const DOMAIN_TAG_V2: &[u8] = b"vigil.ledger.event.v2";

/// 当前 Ledger 写入新事件使用的 chain 版本。verify 按每事件存储的 `chain_version` 分派。
pub const CURRENT_CHAIN_VERSION: i64 = 2;

/// Genesis 事件的 `prev_hash` 在字节形式上是 32 个 0x00;在 SQL 列里存空串。
pub const GENESIS_PREV_HASH_BYTES: [u8; 32] = [0u8; 32];

/// 计算一个事件的 hash(十六进制小写,64 字符)。
///
/// - `prev_hash_hex` 取空串表示 genesis,非空时必须是 64 字符十六进制。
/// - `payload` 按 RFC 8785 JCS 规范化后参与摘要。
pub fn compute_event_hash(
    prev_hash_hex: &str,
    payload: &serde_json::Value,
    created_at: i64,
) -> Result<String> {
    let prev_bytes = parse_prev_hash(prev_hash_hex)?;
    // JCS 把 object key 排序、数字最短形式、字符串最小 escape、无多余空白
    let payload_bytes = serde_jcs::to_vec(payload)?;

    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_TAG);

    // 字段 1:prev_hash(定长 32 字节,但仍带显式长度前缀,防未来常量变化)
    hasher.update((prev_bytes.len() as u32).to_be_bytes());
    hasher.update(prev_bytes);

    // 字段 2:payload JCS 字节(变长)
    hasher.update((payload_bytes.len() as u64).to_be_bytes());
    hasher.update(&payload_bytes);

    // 字段 3:created_at 大端 i64(定长 8 字节)
    hasher.update(8u32.to_be_bytes());
    hasher.update(created_at.to_be_bytes());

    Ok(hex::encode(hasher.finalize()))
}

/// 计算 v2 事件 hash(VIGIL-SEC-001):在 v1 字段之外把 `session_id` / `event_type` /
/// `redacted_text` 也绑入摘要,使这三列的**部分篡改**可被 `verify_chain` 检测。
///
/// 字段顺序与长度前缀见模块头注释。`redacted_text` 用 1 字节 presence tag 区分
/// `None`(0x00)与 `Some`(0x01 + len + bytes),保证 `None` 与 `Some("")` 不混淆。
pub fn compute_event_hash_v2(
    prev_hash_hex: &str,
    payload: &serde_json::Value,
    created_at: i64,
    session_id: &str,
    event_type: &str,
    redacted_text: Option<&str>,
) -> Result<String> {
    let prev_bytes = parse_prev_hash(prev_hash_hex)?;
    let payload_bytes = serde_jcs::to_vec(payload)?;

    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_TAG_V2);

    // 字段 1-3:与 v1 同(prev_hash / payload jcs / created_at)
    hasher.update((prev_bytes.len() as u32).to_be_bytes());
    hasher.update(prev_bytes);
    hasher.update((payload_bytes.len() as u64).to_be_bytes());
    hasher.update(&payload_bytes);
    hasher.update(8u32.to_be_bytes());
    hasher.update(created_at.to_be_bytes());

    // 字段 4:session_id(v2 新增绑定)
    let sid = session_id.as_bytes();
    hasher.update((sid.len() as u64).to_be_bytes());
    hasher.update(sid);

    // 字段 5:event_type(v2 新增绑定)
    let et = event_type.as_bytes();
    hasher.update((et.len() as u64).to_be_bytes());
    hasher.update(et);

    // 字段 6:redacted_text(Option;presence tag 区分 None / Some(""))
    match redacted_text {
        None => hasher.update([0u8]),
        Some(rt) => {
            hasher.update([1u8]);
            let rb = rt.as_bytes();
            hasher.update((rb.len() as u64).to_be_bytes());
            hasher.update(rb);
        }
    }

    Ok(hex::encode(hasher.finalize()))
}

fn parse_prev_hash(hex_str: &str) -> Result<[u8; 32]> {
    if hex_str.is_empty() {
        return Ok(GENESIS_PREV_HASH_BYTES);
    }
    if hex_str.len() != 64 {
        return Err(AuditError::InvalidInput {
            reason: "prev_hash must be 64-char lower-hex or empty for genesis",
        });
    }
    let v = hex::decode(hex_str).map_err(|_| AuditError::InvalidInput {
        reason: "prev_hash is not valid hex",
    })?;
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_prev_hash_accepts_genesis_empty() {
        assert_eq!(parse_prev_hash("").unwrap(), GENESIS_PREV_HASH_BYTES);
    }

    #[test]
    fn parse_prev_hash_rejects_wrong_length() {
        assert!(parse_prev_hash("abcd").is_err());
    }

    #[test]
    fn compute_event_hash_is_deterministic() {
        let p = json!({"a": 1, "b": "测试"});
        let h1 = compute_event_hash("", &p, 1700000000).unwrap();
        let h2 = compute_event_hash("", &p, 1700000000).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn compute_event_hash_is_jcs_stable() {
        // key 顺序不同,hash 必须相同(JCS 排序)
        let p1 = json!({"a": 1, "b": "测试"});
        let p2 = json!({"b": "测试", "a": 1});
        assert_eq!(
            compute_event_hash("", &p1, 1700000001).unwrap(),
            compute_event_hash("", &p2, 1700000001).unwrap()
        );
    }

    #[test]
    fn compute_event_hash_changes_with_prev() {
        let p = json!({});
        let h1 = compute_event_hash("", &p, 1700000000).unwrap();
        // 用 h1 作为 prev 算下一个(非 genesis)
        let h2 = compute_event_hash(&h1, &p, 1700000000).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn compute_event_hash_changes_with_timestamp() {
        let p = json!({});
        assert_ne!(
            compute_event_hash("", &p, 1700000000).unwrap(),
            compute_event_hash("", &p, 1700000001).unwrap()
        );
    }

    // ─── v2 (VIGIL-SEC-001) ───

    #[test]
    fn v2_is_deterministic_and_distinct_from_v1() {
        let p = json!({"a": 1});
        let v1 = compute_event_hash("", &p, 1700000000).unwrap();
        let v2a =
            compute_event_hash_v2("", &p, 1700000000, "sess-1", "tool_call.opened", None).unwrap();
        let v2b =
            compute_event_hash_v2("", &p, 1700000000, "sess-1", "tool_call.opened", None).unwrap();
        assert_eq!(v2a, v2b, "v2 deterministic");
        assert_ne!(v1, v2a, "v1 / v2 domain-separated, never collide");
    }

    #[test]
    fn v2_binds_session_id() {
        let p = json!({});
        let a = compute_event_hash_v2("", &p, 1, "sess-A", "e", None).unwrap();
        let b = compute_event_hash_v2("", &p, 1, "sess-B", "e", None).unwrap();
        assert_ne!(a, b, "changing session_id must change the v2 hash");
    }

    #[test]
    fn v2_binds_event_type() {
        let p = json!({});
        let a = compute_event_hash_v2("", &p, 1, "s", "tool_call.opened", None).unwrap();
        let b = compute_event_hash_v2("", &p, 1, "s", "tool_call.closed", None).unwrap();
        assert_ne!(a, b, "changing event_type must change the v2 hash");
    }

    #[test]
    fn v2_binds_redacted_text_and_distinguishes_none_from_empty() {
        let p = json!({});
        let none = compute_event_hash_v2("", &p, 1, "s", "e", None).unwrap();
        let empty = compute_event_hash_v2("", &p, 1, "s", "e", Some("")).unwrap();
        let some = compute_event_hash_v2("", &p, 1, "s", "e", Some("redacted")).unwrap();
        assert_ne!(
            none, empty,
            "None must differ from Some(\"\") (presence tag)"
        );
        assert_ne!(empty, some, "redacted_text content is bound");
        assert_ne!(none, some);
    }
}
