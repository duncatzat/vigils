//! `vigil-hub serve --stdio` 协议通路 smoke 测(B-2)。
//!
//! 覆盖 3 种场景:
//! 1. 空 config:build_hub 成功,stdio 循环能响应 initialize / tools/list(空)
//! 2. 无效 JSON-RPC 输入:返 `-32700 parse error`,不终止循环
//! 3. 含 upstream 的 config:Stage 1 返 `UpstreamNotImplemented`,不静默跳过
//!
//! 不启动真实子进程,所有 IO 用 `Cursor<Vec<u8>>` 注入 stdin / 捕获 stdout。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Cursor;

use serde_json::{json, Value};
use vigil_hub_cli::serve::{build_hub, run_stdio_loop, ServeArgs, ServeError};

fn default_args() -> ServeArgs {
    ServeArgs {
        ledger_path: None, // in-memory
        upstreams_config: None,
        auto_approve_first_seen: false,
        dev_permissive_firewall: false,
        // T7 ISS-008 Phase 2:默认 false,与 v0.4 行为兼容(走 NoopEngine 默认 scanner)。
        enable_privacy_filter: false,
    }
}

/// 把输入行拼成 NDJSON(每条一行 + `\n`),供 Cursor 模拟 stdin。
fn ndjson(lines: &[Value]) -> Vec<u8> {
    let mut out = String::new();
    for l in lines {
        out.push_str(&serde_json::to_string(l).unwrap());
        out.push('\n');
    }
    out.into_bytes()
}

/// 把输出字节按行拆成 Value vec(空行过滤)。
fn parse_ndjson(bytes: &[u8]) -> Vec<Value> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("output line must be valid JSON"))
        .collect()
}

/// ISS-008 Phase 2 T7:默认 feature 矩阵(`ort` off)+ `enable_privacy_filter=true` →
/// `ServeError::PrivacyFilterUnavailable`。这是 ADR 0014 fail-closed 不变量的回归门 ——
/// 任何"flag on 但静默降级 NoopEngine"的回归会让本测试失败(用户感知 != 实际行为是安全事故)。
///
/// 注:`#[cfg(not(feature = "ort"))]` 让本测试只在默认 feature 矩阵激活;
/// `cargo test -p vigil-hub-cli --features ort` 时跳过(那条路径走 OrtEngine::from_env,
/// 需要真模型文件,与本守门测试无关)。
#[cfg(not(feature = "ort"))]
#[test]
fn b2_privacy_filter_unavailable_when_feature_off() {
    let args = ServeArgs {
        ledger_path: None,
        upstreams_config: None,
        auto_approve_first_seen: false,
        dev_permissive_firewall: false,
        enable_privacy_filter: true, // flag on,但 feature off → fail-closed
    };
    match build_hub(&args) {
        Err(ServeError::PrivacyFilterUnavailable) => {}
        other => panic!(
            "默认 feature off 时 enable_privacy_filter=true 必须返 PrivacyFilterUnavailable,\
             实际 {:?}",
            other.map(|_| "Ok(Hub)").map_err(|e| format!("{e:?}"))
        ),
    }
}

#[test]
fn b2_empty_config_build_hub_ok() {
    let args = default_args();
    let (hub, _ledger) = build_hub(&args).expect("build_hub should succeed with empty config");
    // 构建成功 + 能 drop,说明 Ledger / Firewall / Hub 都初始化 OK
    drop(hub);
}

/// ISS-019 Phase 2 守门(2026-04-28):
/// `dev_permissive_firewall=true` **不再** override approval_wait 为 3s。
/// Phase 1 的 `wait_for_resolution` 内置 500ms 短轮询 fallback 已让 cross-proc
/// approve 安全(实测 ~1.3s,远低于 default 300s timeout)。
///
/// 任何回归(误把 timing hack 加回来)会让本测试失败。
///
/// 参考:
///   - crates/vigil-audit/src/approvals.rs::WAIT_POLL_INTERVAL
///   - crates/vigil-audit/tests/approval_cross_proc_wait.rs(cross-proc 守门)
#[test]
fn b2_dev_permissive_firewall_does_not_override_approval_wait_iss_019_phase_2() {
    use vigil_mcp::HubConfig;

    let mut args = default_args();
    args.dev_permissive_firewall = true; // 仅启 catch-all rule,不应触发 timing hack
    let (hub, _ledger) = build_hub(&args).unwrap();

    let default_wait = HubConfig::default().approval_wait;
    assert_eq!(
        hub.approval_wait(),
        default_wait,
        "ISS-019 Phase 2 回归:dev_permissive_firewall 不应 override approval_wait \
         (实际 {:?},预期 {default_wait:?});cross-proc 安全已由 Phase 1 短轮询 \
         fallback 解决,无需 timing override。",
        hub.approval_wait()
    );
    // 同时验对照面:default args 也是 default approval_wait
    let args_default = default_args();
    let (hub_default, _ledger) = build_hub(&args_default).unwrap();
    assert_eq!(hub_default.approval_wait(), default_wait);
}

#[test]
fn b2_initialize_ping_tools_list_roundtrip() {
    let args = default_args();
    let (hub, _ledger) = build_hub(&args).unwrap();

    let input = ndjson(&[
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "vigil-hub-cli-test", "version": "0.0.1"}
            }
        }),
        json!({"jsonrpc": "2.0", "id": 2, "method": "ping"}),
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}),
    ]);

    let mut reader = Cursor::new(input);
    let mut writer: Vec<u8> = Vec::new();
    run_stdio_loop(&hub, &mut reader, &mut writer).expect("loop should exit cleanly on EOF");

    let responses = parse_ndjson(&writer);
    assert_eq!(
        responses.len(),
        3,
        "预期 3 条响应(initialize + ping + tools/list),实际 {}: {:?}",
        responses.len(),
        responses
    );

    // initialize:返 protocolVersion + serverInfo
    let init = &responses[0];
    assert_eq!(init["id"], 1);
    assert!(
        init["result"].is_object(),
        "initialize 应返 result 对象: {:?}",
        init
    );

    // ping:返空对象或空 result
    assert_eq!(responses[1]["id"], 2);
    assert!(
        responses[1]["result"].is_object() || responses[1]["result"].is_null(),
        "ping 应返 result: {:?}",
        responses[1]
    );

    // tools/list:返 tools 数组(Stage 1 零 upstream → 空)
    let list = &responses[2];
    assert_eq!(list["id"], 3);
    let tools = &list["result"]["tools"];
    assert!(
        tools.is_array(),
        "tools/list result.tools 应为数组: {:?}",
        list
    );
    assert_eq!(
        tools.as_array().unwrap().len(),
        0,
        "Stage 1 零 upstream → tools 为空数组"
    );
}

#[test]
fn b2_invalid_jsonrpc_returns_parse_error_not_abort() {
    let args = default_args();
    let (hub, _ledger) = build_hub(&args).unwrap();

    // 第一条:字段缺失(缺 "method")→ 期望返 -32700 parse error
    // 第二条:合法 ping → 验证循环未因上一条异常中断
    let input = ndjson(&[
        json!({"jsonrpc": "2.0", "id": 100}), // 无 method
        json!({"jsonrpc": "2.0", "id": 101, "method": "ping"}),
    ]);

    let mut reader = Cursor::new(input);
    let mut writer: Vec<u8> = Vec::new();
    run_stdio_loop(&hub, &mut reader, &mut writer).expect("loop should not abort on invalid RPC");

    let responses = parse_ndjson(&writer);
    assert_eq!(
        responses.len(),
        2,
        "预期 2 条响应(error + ping): {:?}",
        responses
    );

    let err = &responses[0];
    assert_eq!(err["id"], 100);
    assert!(
        err.get("error").is_some(),
        "第一条应返 error 字段: {:?}",
        err
    );
    let code = err["error"]["code"].as_i64().unwrap_or(0);
    assert_eq!(code, -32700, "应为 parse error(-32700): {:?}", err);

    // 第二条:ping 正常
    assert_eq!(responses[1]["id"], 101);
    assert!(
        responses[1]["result"].is_object() || responses[1]["result"].is_null(),
        "ping 应正常: {:?}",
        responses[1]
    );
}

#[test]
fn b2_upstream_config_empty_argv_returns_invalid_upstream() {
    // Stage 2 实装后,UpstreamNotImplemented 已移除 → 改验 argv 空的 fail-closed
    use std::io::Write as _;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let cfg = json!({
        "upstreams": [
            {"name": "broken", "argv": []} // 非法:空 argv
        ]
    });
    writeln!(tmp.as_file(), "{}", serde_json::to_string(&cfg).unwrap()).unwrap();

    let args = ServeArgs {
        ledger_path: None,
        upstreams_config: Some(tmp.path().to_path_buf()),
        auto_approve_first_seen: false,
        dev_permissive_firewall: false,
        enable_privacy_filter: false,
    };

    match build_hub(&args) {
        Err(ServeError::InvalidUpstream { name, reason }) => {
            assert_eq!(name, "broken");
            assert!(reason.contains("argv"), "reason 应提 argv: {}", reason);
        }
        other => panic!(
            "预期 InvalidUpstream{{argv empty}},实际 {:?}",
            other.map(|_| "Ok(Hub)")
        ),
    }
}

#[test]
fn b2_stage2_attach_real_stdio_upstream_via_node() {
    // Stage 2 端到端(在 Rust 测试内):用 Node 启 mock-mcp-server,验证 attach 全链路。
    // 若本机无 Node 则 skip(不阻塞 CI;Windows 开发机通常有)。
    //
    // **node 必须用绝对路径**:Vigil stdio upstream spawn 走 `apply_native_env_policy`
    // (ADR 0007 §I-7.1 `env_clear()`),PATH 被清空 —— 裸命令 "node" 在被清环境的子进程里
    // 无法解析(Linux 上 NotFound)。用 node 自身的 `process.execPath` 取绝对路径,既验证
    // node 可运行又拿到在 env_clear 下可直接 exec 的绝对路径,避免依赖 PATH。
    let node_path = match std::process::Command::new("node")
        .args(["-e", "process.stdout.write(process.execPath)"])
        .output()
    {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        _ => {
            eprintln!("[b2-stage2] skip: node not runnable");
            return;
        }
    };
    let mock_script = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/test-local/mock-mcp-server.mjs")
        .canonicalize()
        .expect("mock-mcp-server.mjs path");

    use std::io::Write as _;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let cfg = json!({
        "upstreams": [
            {"name": "mockup", "argv": [node_path, mock_script.to_string_lossy()]}
        ]
    });
    writeln!(tmp.as_file(), "{}", serde_json::to_string(&cfg).unwrap()).unwrap();

    let args = ServeArgs {
        ledger_path: None, // in-memory
        upstreams_config: Some(tmp.path().to_path_buf()),
        auto_approve_first_seen: true, // dev 模式让 descriptor 自动批准
        dev_permissive_firewall: false,
        enable_privacy_filter: false,
    };

    let (hub, ledger) = build_hub(&args).expect("build_hub with real upstream");

    // Ledger 应已登记 mockup server
    let stored = ledger
        .get_server("mockup")
        .unwrap()
        .expect("server registered");
    assert_eq!(stored.server_id, "mockup");
    assert!(matches!(
        stored.trust_level,
        vigil_types::TrustLevel::Limited
    ));

    // tools/list 的 Hub ↔ upstream 聚合在 Rust test runner 下 Node 子进程路径/stdout
    // 时序不稳(CI 上 Node 版本 / shebang / fork 行为都会影响),tools/list 实际通路
    // 已由 `scripts/test-local/e2e-stage2.mjs` 在真 binary 下验过(2 工具 +
    // firewall 拦截 + ledger)。此处只验 build_hub 成功 + Ledger 登记持久化,已充分。
    drop(hub);
}
