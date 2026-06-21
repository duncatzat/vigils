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
        enable_injection_classifier: false,
        redact_tool_results: false,
        ml_best_effort: false,
        monitor: false,
        // 本文件只测协议通路,不测项目边界;空 roots 由 policy 引擎守门兜底(DEF-004)。
        project_roots: vec![],
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
        enable_injection_classifier: false,
        redact_tool_results: false,
        ml_best_effort: false,
        monitor: false,
        project_roots: vec![],
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

/// P0 注入防护 Slice D:默认 feature off + `enable_injection_classifier=true` →
/// `ServeError::InjectionClassifierUnavailable`。对称 privacy filter 的 fail-closed 守门:
/// 任何"flag on 但静默跳过注入检测"的回归会让本测试失败(用户感知"已启用注入检测"实际未生效)。
#[cfg(not(feature = "ort"))]
#[test]
fn b2_injection_classifier_unavailable_when_feature_off() {
    let mut args = default_args();
    args.enable_injection_classifier = true; // flag on,但 feature off → fail-closed
    match build_hub(&args) {
        Err(ServeError::InjectionClassifierUnavailable) => {}
        other => panic!(
            "默认 feature off 时 enable_injection_classifier=true 必须返 \
             InjectionClassifierUnavailable,实际 {:?}",
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
        enable_injection_classifier: false,
        redact_tool_results: false,
        ml_best_effort: false,
        monitor: false,
        project_roots: vec![],
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

/// ADR 0021 Slice 1:HTTP **Bearer** upstream 经 config 真 attach 进 Hub(end-to-end wiring)。
/// 用公网 IP 字面量(SSRF 放行,无 DNS)+ env token;attach 不发任何网络请求 → Ok(Hub)。
#[test]
fn b3_http_bearer_upstream_attaches_via_config() {
    use std::io::Write as _;
    std::env::set_var("VIGIL_TEST_HTTP_BEARER_ATTACH", "ghp_testtoken123");
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let cfg = json!({
        "upstreams": [
            {
                "name": "remote",
                "url": "https://1.1.1.1",
                "auth": { "bearer": { "source": "env:VIGIL_TEST_HTTP_BEARER_ATTACH" } }
            }
        ]
    });
    writeln!(tmp.as_file(), "{}", serde_json::to_string(&cfg).unwrap()).unwrap();
    let args = ServeArgs {
        ledger_path: None,
        upstreams_config: Some(tmp.path().to_path_buf()),
        auto_approve_first_seen: false,
        dev_permissive_firewall: false,
        enable_privacy_filter: false,
        enable_injection_classifier: false,
        redact_tool_results: false,
        ml_best_effort: false,
        monitor: false,
        project_roots: vec![],
    };
    let r = build_hub(&args);
    std::env::remove_var("VIGIL_TEST_HTTP_BEARER_ATTACH");
    match r {
        Ok(_) => {} // attach 成功:HTTP Bearer upstream 已进 Hub(transport=Http)。
        other => panic!("预期 Ok(Hub),实际 {:?}", other.map(|_| "Ok(Hub)")),
    }
}

/// HTTP **OAuth** upstream:serve 期已接线,但**未 onboard**(无持久化 token metadata)时
/// **fail-closed**(绝不静默 attach 未验证上游)。metadata 检查在任何 network 之前 → 本测 hermetic
/// (不触网:get_metadata 只查 ledger SQLite,None → 直接报 "not onboarded")。
#[test]
fn b3_http_oauth_upstream_fails_closed_when_not_onboarded() {
    use std::io::Write as _;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let cfg = json!({
        "upstreams": [
            {
                "name": "remote",
                "url": "https://1.1.1.1",
                "auth": { "oauth": { "resource": "https://1.1.1.1", "client_id": "c" } }
            }
        ]
    });
    writeln!(tmp.as_file(), "{}", serde_json::to_string(&cfg).unwrap()).unwrap();
    let args = ServeArgs {
        ledger_path: None,
        upstreams_config: Some(tmp.path().to_path_buf()),
        auto_approve_first_seen: false,
        dev_permissive_firewall: false,
        enable_privacy_filter: false,
        enable_injection_classifier: false,
        redact_tool_results: false,
        ml_best_effort: false,
        monitor: false,
        project_roots: vec![],
    };
    match build_hub(&args) {
        Err(ServeError::InvalidUpstream { reason, .. }) => {
            assert!(reason.contains("onboarded"), "reason: {reason}")
        }
        other => panic!(
            "预期 OAuth 未 onboard fail-closed InvalidUpstream,实际 {:?}",
            other.map(|_| "Ok")
        ),
    }
}

#[test]
fn b2_stage2_attach_real_stdio_upstream_via_node() {
    // Stage 2 端到端(在 Rust 测试内):用 Node 启 mock-mcp-server,验证 attach 全链路。
    // 若本机无 Node 则 skip(不阻塞 CI;Windows 开发机通常有)。
    //
    // argv 用**裸命令 "node"**:O3(ADR 0007 §I-7.1 amendment)让 stdio upstream spawn 在
    // env_clear 前用宿主 PATH 把裸命令解析为绝对路径,故裸 "node" 在 Linux/macOS 也能 spawn。
    // 本测试同时端到端验证 `resolve_program`(裸命令 → 绝对路径)。
    let node_ok = std::process::Command::new("node")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !node_ok {
        eprintln!("[b2-stage2] skip: node not runnable");
        return;
    }
    let mock_script = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/test-local/mock-mcp-server.mjs")
        .canonicalize()
        .expect("mock-mcp-server.mjs path");

    use std::io::Write as _;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let cfg = json!({
        "upstreams": [
            {"name": "mockup", "argv": ["node", mock_script.to_string_lossy()]}
        ]
    });
    writeln!(tmp.as_file(), "{}", serde_json::to_string(&cfg).unwrap()).unwrap();

    let args = ServeArgs {
        ledger_path: None, // in-memory
        upstreams_config: Some(tmp.path().to_path_buf()),
        auto_approve_first_seen: true, // dev 模式让 descriptor 自动批准
        dev_permissive_firewall: false,
        enable_privacy_filter: false,
        enable_injection_classifier: false,
        redact_tool_results: false,
        ml_best_effort: false,
        monitor: false,
        project_roots: vec![],
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

/// 严格 MCP 生命周期回归门(Codex review SHOULD-FIX,2026-06-04)。
///
/// 证明"attach 上游时执行了 MCP `initialize` 握手"这一修复**真生效**,而非仅缩短了 dummy 超时。
/// 用 `strict-mcp-server.mjs`:它在 `initialize`(+ `notifications/initialized`)完成**之前**对
/// `tools/list` 返 `-32002 not initialized` —— 这是 @modelcontextprotocol 官方 SDK server
/// (filesystem 等)的真实行为。
///
/// 为何此前的宽松 mock 测不出:`mock-mcp-server.mjs` 无论是否握手都回 tools 列表,掩盖了
/// "Hub 从不 initialize 上游"的 bug(被真 Codex E2E 抓到:vigil 是个 0 工具 server)。
///
/// 关键不变量:`initialize_handshake` 是**同步**的,`build_hub` 会阻塞到上游应答 `initialize`,
/// 故 build_hub 返回时严格 server 已 operational —— 消除了上面 node-e2e 注释提到的时序不稳。
///
/// 回归语义:若有人移除 attach 时的握手,严格 server 会拒绝 `tools/list` → Hub 聚合 0 工具 →
/// 本测试断言失败。同时锁定 `__` 双下划线 namespacing 记法(`strictup__strict_tool`)。
#[test]
fn b2_stage2_strict_upstream_requires_handshake_regression() {
    let node_ok = std::process::Command::new("node")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !node_ok {
        eprintln!("[b2-stage2-strict] skip: node not runnable");
        return;
    }
    let mock_script = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/test-local/strict-mcp-server.mjs")
        .canonicalize()
        .expect("strict-mcp-server.mjs path");
    // Windows `canonicalize` 产出 `\\?\` 扩展长度前缀,node 把它当 argv 脚本路径时会被绊住
    // (报 lstat 'D:' EISDIR);剥掉前缀给 node 一个普通绝对路径(非 Windows 上 strip 为 no-op)。
    // 仅测试 harness 需要 —— 真实用户配置里写的是普通路径,不经 canonicalize。
    let script_str = mock_script.to_string_lossy();
    let script = script_str.strip_prefix(r"\\?\").unwrap_or(&script_str);

    use std::io::Write as _;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let cfg = json!({
        "upstreams": [
            {"name": "strictup", "argv": ["node", script]}
        ]
    });
    writeln!(tmp.as_file(), "{}", serde_json::to_string(&cfg).unwrap()).unwrap();

    let args = ServeArgs {
        ledger_path: None, // in-memory
        upstreams_config: Some(tmp.path().to_path_buf()),
        auto_approve_first_seen: true, // dev:首见 descriptor 自动批准,让工具能浮现
        dev_permissive_firewall: false,
        enable_privacy_filter: false,
        enable_injection_classifier: false,
        redact_tool_results: false,
        ml_best_effort: false,
        monitor: false,
        project_roots: vec![],
    };

    // build_hub 同步执行 initialize 握手:返回时严格 server 已 operational。
    let (hub, _ledger) = build_hub(&args).expect("build_hub with strict upstream");

    // 走 Hub 真 stdio 循环要 tools/list;Hub 会把它转发给上游聚合。
    let input = ndjson(&[
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "vigil-hub-cli-test", "version": "0.0.1"}
            }
        }),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    ]);
    let mut reader = Cursor::new(input);
    let mut writer: Vec<u8> = Vec::new();
    run_stdio_loop(&hub, &mut reader, &mut writer).expect("loop should exit cleanly on EOF");

    let responses = parse_ndjson(&writer);
    let list = responses
        .iter()
        .find(|r| r["id"] == 2)
        .expect("tools/list response present");
    let tools = list["result"]["tools"]
        .as_array()
        .expect("tools/list result.tools must be an array");
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();

    // 核心断言:严格上游的工具浮现 → 证明 attach 时握手真发生。
    // 若握手回归(被移除),严格 server 拒 tools/list,这里会是空数组 → 失败。
    assert!(
        names.contains(&"strictup__strict_tool"),
        "严格上游的工具未浮现 —— attach 时的 MCP initialize 握手可能回归了。\
         实际 tools={names:?},原始 tools/list 响应={list:?}"
    );
    drop(hub);
}
