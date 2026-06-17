// I08b-β1 真 command 白名单 — **SSOT**(Single Source of Truth)。
//
// 本列表被两处消费:
// 1. `build.rs` → `tauri_build::try_build(Attributes::new().app_manifest(
//    AppManifest::new().commands(INVOKE_COMMANDS)))` 在构建期为每条命令生成
//    `allow-{slugified}` / `deny-{slugified}` 权限(_ → -)
// 2. `apps/desktop/capabilities/default.json` → 引用 `allow-{slugified}` 把命令纳入
//    主窗口 capability(无前缀 = APP_ACL_KEY,tauri-utils::resolved.rs L344 语义)
//
// 本列表必须与 `apps/desktop/src/bin/vigils.rs` 的 `tauri::generate_handler![...]` 严格一致。
// 若新增/删除 handler,三处(本文件 + capabilities/default.json + generate_handler!)必须
// 同步更新。`invoke_commands_count_in_sync` 测试作为最小守门(count 漂移即失败)。
//
// **为什么 SSOT 必要**:在 α1 时 capability gate 仅覆盖系统能力,应用层 invoke handler
// 走软白名单(generate_handler 宏展开)。β1 引入 AppManifest 后,未列入本文件的 handler
// 即使在 generate_handler! 中,也**无对应 allow permission**,capability 不引用就不可达
// —— 这是 hard-gate,也是 ADR 0008 在 α1 时承诺但延期的技术债。
//
// **文件级注释用普通 `//` 而非 `//!`**:本文件通过 `build.rs` 的 `include!` 宏
// 插入构建脚本中段,`//!` inner-doc 在中段触发 E0753("expected outer doc-comment");
// 走普通注释即可,文档价值不丢。

/// Tauri `#[tauri::command]` 真白名单 —— 构建期与运行期 ACL 的 SSOT。
///
/// **顺序不重要**(内部按 slugified 生成 permission);共 **23** 条
/// (α1=1 + α2=3 + α3=3 + α4=10 + α5=2 + ISS-017=1 + ISS-018=1 + D19=1 + checkpoint=1)。
pub const INVOKE_COMMANDS: &[&str] = &[
    // α1(Sessions smoke)
    "list_sessions",
    // α2(Approval Queue 全套 —— 3 handler)
    "list_pending_approvals",
    "get_approval_detail",
    "resolve_approval",
    // α3(Activity Feed 全套 —— 3 handler)
    "list_recent_events",
    "get_event_detail",
    "fts_search",
    // α4(Server Registry 全套 —— 5 read + 5 write)
    "list_servers",
    "get_server_onboarding",
    "list_pending_tool_approvals",
    "list_drifted_tools",
    "list_drifted_servers",
    "approve_tool",
    "approve_tool_drift",
    "reject_tool_drift",
    "approve_server_command_drift",
    "reject_server_command_drift",
    // α5(Session Replay —— 2 read)
    "replay_session",
    "verify_chain",
    // ISS-017(Privacy Findings panel —— 1 read)
    "list_privacy_findings",
    // ISS-018(Safe Export —— 1 read)
    "export_session_replay",
    // D19(Protection Overview —— 1 read)
    "protection_summary",
    // Settings: 手动锚定审计检查点
    "anchor_checkpoint",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// 守门:列表 count 必须等于当前 β1 已实装的 handler 数。
    ///
    /// 这是手工同步的最小断言 —— Rust 的 macro 展开结果不可在测试中反射出
    /// `generate_handler!` 实际注册的 handler 列表,因此 count 漂移(添加 / 删除 handler)
    /// 时必然触发测试失败,强制同步本文件 + `gui.rs` + `capabilities/default.json`。
    #[test]
    fn invoke_commands_count_in_sync() {
        assert_eq!(
            INVOKE_COMMANDS.len(),
            23,
            "INVOKE_COMMANDS 漂移 —— 新增/删除 handler 时必须同步:\n\
             1) 本文件 `apps/desktop/src/commands.rs`\n\
             2) `apps/desktop/src/bin/vigils.rs` 的 `tauri::generate_handler!` 列表\n\
             3) `apps/desktop/capabilities/default.json` 的 `allow-$cmd` permission 清单"
        );
    }

    /// 守门:禁重复(BTreeSet 去重后长度与原长一致)。
    #[test]
    fn invoke_commands_are_unique() {
        let unique: std::collections::BTreeSet<&&str> = INVOKE_COMMANDS.iter().collect();
        assert_eq!(
            unique.len(),
            INVOKE_COMMANDS.len(),
            "INVOKE_COMMANDS 含重复命令 —— tauri-build 对重复的 slugified 命令会生成相同 permission,behavior 未定义"
        );
    }

    /// 守门:snake_case + 不含 `:`(APP_ACL_KEY 分隔符)/ 空白。
    #[test]
    fn invoke_commands_are_well_formed() {
        for cmd in INVOKE_COMMANDS {
            assert!(!cmd.is_empty(), "空命令");
            assert!(
                !cmd.contains(':'),
                "`{cmd}` 含 `:` —— 会被 tauri-utils 解析为 plugin 前缀,破坏 APP_ACL_KEY 归属"
            );
            assert!(
                !cmd.contains(char::is_whitespace),
                "`{cmd}` 含空白 —— slugified permission identifier 会失败"
            );
            assert!(
                cmd.chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()),
                "`{cmd}` 非 snake_case"
            );
        }
    }

    /// 守门(β1 R1 MUST-FIX):**精确集合一致性** —— `capabilities/default.json` 的
    /// `allow-<slugified>` permission 集合必须与 `INVOKE_COMMANDS` 的 slugified 集合
    /// **双向相等**(不允许某一侧多余条目)。
    ///
    /// 仅 count 相等(`invoke_commands_count_in_sync`)不够:如果 gui.rs 的
    /// `generate_handler!` 把某 handler 替换成另一个、总数仍 19,Tauri 运行时
    /// 会因 capability 与实际 handler 不匹配而静默失败(invoke 返 ACL denied)。
    /// 本测试直接 parse JSON 文件,按字符串集合对比,拒绝静默漂移。
    ///
    /// slugified 规则来自 `tauri-utils::acl::build::autogenerate_command_permissions`
    /// L290: `command.replace('_', "-")`。
    #[test]
    fn capability_json_allow_set_matches_invoke_commands() {
        // 读 capabilities/default.json(相对于 Cargo.toml 所在 crate 根)
        let json_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("capabilities")
            .join("default.json");
        let json_text = std::fs::read_to_string(&json_path)
            .unwrap_or_else(|e| panic!("read {json_path:?} failed: {e}"));

        // 最小 JSON parse(避免依赖 serde_json 仅为一个测试):手工抽 "allow-*"
        // 字符串字面量 —— 正则不需要,直接扫 `"allow-<something>"` 模式。
        let mut cap_allow: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for line in json_text.lines() {
            let trimmed = line.trim();
            // 匹配形如 `"allow-xxx",` 或 `"allow-xxx"` 的纯字符串条目;
            // 跳过 `"core:..."` 等带前缀 plugin permission 与对象形 permission
            if let Some(start) = trimmed.find("\"allow-") {
                let after = &trimmed[start + 1..];
                if let Some(end) = after.find('"') {
                    cap_allow.insert(after[..end].to_string());
                }
            }
        }

        let expected: std::collections::BTreeSet<String> = INVOKE_COMMANDS
            .iter()
            .map(|c| format!("allow-{}", c.replace('_', "-")))
            .collect();

        let missing_in_cap: Vec<&String> = expected.difference(&cap_allow).collect();
        let extra_in_cap: Vec<&String> = cap_allow.difference(&expected).collect();

        assert!(
            missing_in_cap.is_empty() && extra_in_cap.is_empty(),
            "capabilities/default.json 与 INVOKE_COMMANDS 漂移:\n\
             missing (在 INVOKE_COMMANDS 里但 capability 没引用): {missing_in_cap:?}\n\
             extra   (capability 多余,INVOKE_COMMANDS 里没有): {extra_in_cap:?}"
        );
    }
}
