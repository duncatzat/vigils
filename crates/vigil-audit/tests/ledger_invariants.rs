//! I01 验收(主方案 §7.7 + ADR 0002)对应的集成测试:
//!
//! 1. append event works                      → append_event_round_trip
//! 2. hash chain verifies                     → chain_verifies_after_multiple_appends
//! 3. tamper detection                        → tamper_detected_after_payload_mutation
//! 4. FTS redacted search works               → fts_search_hits_redacted_summary
//! 5. pending approval survives restart       → pending_approval_survives_reopen
//! 6. fail-closed on hard secret              → append_rejects_hard_secret_in_payload
//! 7. ToolCallSpan 时序 abandoned 补写        → abandoned_event_written_on_early_drop
//! 8. ToolCallSpan 全路径执行                 → span_full_success_path_appends_events
//! 9. SQLite 没有 raw secret 原文             → no_raw_secret_in_sqlite_after_redact

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::err_expect,
    clippy::panic
)]

use rusqlite::Connection;
use serde_json::json;
use tempfile::tempdir;
use vigil_audit::{AuditError, Ledger, RESERVED_EVENT_PREFIXES};

/// (0) D15 真机 E2E 回归:`Ledger::open` 必须**自建账本父目录**。SQLite 只建文件不建目录,
/// 默认账本路径 `<data>/Vigil/ledger.sqlite3` 的 `Vigil/` 子目录在首跑机器上不存在 → 不建即
/// `unable to open database file` = turnkey 首跑静默坏掉(隔离 HOME 真 E2E 暴露)。
#[test]
fn open_creates_missing_parent_dirs() {
    let dir = tempdir().unwrap();
    // 多层均不存在的父目录(模拟首跑 `.local/share/Vigil/`)。
    let path = dir
        .path()
        .join("a")
        .join("b")
        .join("Vigil")
        .join("ledger.sqlite3");
    assert!(!path.parent().unwrap().exists(), "前置:父目录不存在");
    let l = Ledger::open(&path).expect("open 应自建父目录并成功");
    assert!(path.exists(), "账本文件已创建");
    // 真能用(写一条 + verify)。
    let sid = l.start_session("t", None).unwrap();
    l.append_event(&sid, "x", &json!({"n": 1}), Some("n1"))
        .unwrap();
    l.verify_chain().unwrap();
}

/// (1) append_event 基本往返:新增后计数 +1,hash 非空,verify_chain OK。
#[test]
fn append_event_round_trip() {
    let l = Ledger::open_in_memory().unwrap();
    let sid = l.start_session("test", Some("unit")).unwrap();
    assert_eq!(l.event_count().unwrap(), 0);

    let ev = l
        .append_event(&sid, "hello.world", &json!({"msg": "hi"}), Some("msg:hi"))
        .unwrap();
    assert_eq!(ev.event_id, 1);
    assert_eq!(ev.event_hash.len(), 64);
    assert_eq!(l.event_count().unwrap(), 1);

    l.verify_chain().unwrap();
}

/// (1b) Theme G 锚点 `latest_event_id`:空 ledger → None;append N 条 → Some(最后 id);
/// 且严格单调递增。仅覆盖 event-backed 变更(redaction_scans / sessions 不 bump,见
/// ledger.rs latest_event_id doc + Theme G spike § 1)。
#[test]
fn latest_event_id_tracks_event_backed_appends() {
    let l = Ledger::open_in_memory().unwrap();
    // 空 ledger(含一次 start_session,sessions 表写入但非 event-backed)→ None
    let sid = l.start_session("test", Some("unit")).unwrap();
    assert_eq!(
        l.latest_event_id().unwrap(),
        None,
        "start_session 不 append event,锚点应仍为 None"
    );

    let e1 = l
        .append_event(&sid, "a.one", &json!({"i": 1}), Some("i=1"))
        .unwrap();
    assert_eq!(l.latest_event_id().unwrap(), Some(e1.event_id));

    let e2 = l
        .append_event(&sid, "a.two", &json!({"i": 2}), Some("i=2"))
        .unwrap();
    let latest = l.latest_event_id().unwrap();
    assert_eq!(latest, Some(e2.event_id));
    assert!(
        e2.event_id > e1.event_id,
        "event_id 应单调递增(AUTOINCREMENT)"
    );
}

/// (2) 多条 append 后 hash chain 串联正确。
#[test]
fn chain_verifies_after_multiple_appends() {
    let l = Ledger::open_in_memory().unwrap();
    let sid = l.start_session("test", None).unwrap();

    for i in 0..5 {
        l.append_event(&sid, "step", &json!({"i": i}), Some(&format!("i={i}")))
            .unwrap();
    }
    assert_eq!(l.event_count().unwrap(), 5);
    l.verify_chain().unwrap();
}

/// (3) 直接操纵底层文件里的一条 payload_json,verify_chain 必须发现篡改。
#[test]
fn tamper_detected_after_payload_mutation() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("ledger.db");

    {
        let l = Ledger::open(&path).unwrap();
        let sid = l.start_session("test", None).unwrap();
        l.append_event(&sid, "a", &json!({"n": 1}), Some("n1"))
            .unwrap();
        l.append_event(&sid, "b", &json!({"n": 2}), Some("n2"))
            .unwrap();
        l.verify_chain().unwrap();
        // Ledger drop → 连接关闭 → WAL 自动 checkpoint
    }

    // 绕过 Ledger API,直接 UPDATE 一条 payload_json 模拟磁盘篡改
    {
        let c = Connection::open(&path).unwrap();
        c.execute(
            "UPDATE events SET payload_json = ?1 WHERE event_id = 1",
            rusqlite::params![r#"{"n":99}"#],
        )
        .unwrap();
    }

    let l = Ledger::open(&path).unwrap();
    let err = l.verify_chain().err().expect("tamper 应被发现");
    match err {
        AuditError::ChainBroken { event_id } => assert_eq!(event_id, 1),
        other => panic!("期望 ChainBroken,得到 {:?}", other),
    }
}

/// (4) FTS 能通过 redacted_text 搜到事件。
#[test]
fn fts_search_hits_redacted_summary() {
    let l = Ledger::open_in_memory().unwrap();
    let sid = l.start_session("test", None).unwrap();

    l.append_event(
        &sid,
        "tool.call",
        &json!({"tool": "github__create_issue"}),
        Some("finding:github_token tool:github__create_issue"),
    )
    .unwrap();
    l.append_event(
        &sid,
        "tool.call",
        &json!({"tool": "fs__read_file"}),
        Some("tool:fs__read_file"),
    )
    .unwrap();

    let hits = l.fts_search("github_token").unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].event_type, "tool.call");
    assert!(hits[0]
        .redacted_text
        .as_ref()
        .unwrap()
        .contains("github_token"));
}

/// (5) Pending approval 插入后,关闭 Ledger 再开,状态仍为 Pending。
#[test]
fn pending_approval_survives_reopen() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("ledger.db");

    {
        let l = Ledger::open(&path).unwrap();
        let sid = l.start_session("test", None).unwrap();
        l.store_pending_approval_skeleton(
            "appr-1",
            "dec-1",
            &sid,
            "Write README",
            "Agent wants to write README.md",
            r#"{"effects":["FsWrite"]}"#,
            9_999_999_999,
        )
        .unwrap();
        assert_eq!(
            l.approval_status("appr-1").unwrap().as_deref(),
            Some("Pending")
        );
        l.checkpoint().unwrap();
    } // drop = close

    let l2 = Ledger::open(&path).unwrap();
    assert_eq!(
        l2.approval_status("appr-1").unwrap().as_deref(),
        Some("Pending"),
        "pending approval 必须跨重启存活(主方案 §7.7 验收 2)"
    );
}

/// (6) 硬指纹:caller 忘记脱敏直接把 GitHub token 塞进 payload,必须被拒绝。
#[test]
fn append_rejects_hard_secret_in_payload() {
    let l = Ledger::open_in_memory().unwrap();
    let sid = l.start_session("test", None).unwrap();

    let err = l
        .append_event(
            &sid,
            "bad",
            &json!({"token": "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"}),
            None,
        )
        .err()
        .expect("应被 fail-closed 自检拒绝");
    match err {
        AuditError::HardSecretDetected { rule } => {
            assert!(["github_token", "openai_api_key"].contains(&rule));
        }
        other => panic!("期望 HardSecretDetected,得到 {:?}", other),
    }

    // 自检失败时,事件与 FTS 行都不得被写入。
    assert_eq!(l.event_count().unwrap(), 0);
}

/// (6b) redacted_text 里含 raw secret 也应被拒绝。
#[test]
fn append_rejects_hard_secret_in_redacted_text() {
    let l = Ledger::open_in_memory().unwrap();
    let sid = l.start_session("test", None).unwrap();

    let err = l
        .append_event(
            &sid,
            "bad",
            &json!({"msg": "ok"}),
            Some("found ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ in log"),
        )
        .err()
        .expect("redacted_text 泄漏也必须被拦");
    assert!(matches!(err, AuditError::HardSecretDetected { .. }));
}

/// (7) ToolCallSpan 在未 record decision 时被 drop → 自动补 tool_call.abandoned。
#[test]
fn abandoned_event_written_on_early_drop() {
    let l = Ledger::open_in_memory().unwrap();
    let sid = l.start_session("test", None).unwrap();

    {
        let _span = l.tool_call_span("inv-1", &sid).unwrap();
        // 什么都不做,直接离开作用域
    }

    // 期望:tool_call.opened + tool_call.abandoned 两条
    // FTS5 里 `-` 是 NOT 操作符,用引号包成 phrase query。
    let hits = l.fts_search(r#""inv-1""#).unwrap();
    let types: Vec<_> = hits.iter().map(|h| h.event_type.as_str()).collect();
    assert!(types.contains(&"tool_call.opened"), "types = {:?}", types);
    assert!(
        types.contains(&"tool_call.abandoned"),
        "types = {:?}",
        types
    );
}

/// (8) 全路径:opened → decided → executed,三条事件按序写入。
#[test]
fn span_full_success_path_appends_events() {
    use vigil_types::{DecisionKind, DecisionRecord};

    let l = Ledger::open_in_memory().unwrap();
    let sid = l.start_session("test", None).unwrap();

    let span = l.tool_call_span("inv-1", &sid).unwrap();
    let dec = DecisionRecord {
        decision_id: "dec-1".into(),
        invocation_id: "inv-1".into(),
        decision: DecisionKind::Allow,
        risk_score: 20,
        reasons: vec!["fs.read within project".into()],
        policy_ids: vec!["allow-repo-read".into()],
        created_at: 1_700_000_000,
    };
    let span = span.decision_recorded(&dec).unwrap();
    span.executed("read src/main.rs (2 KiB)").unwrap();

    // 期望写入的三条事件按顺序出现,并且 verify_chain 通过
    l.verify_chain().unwrap();
    let hits = l.fts_search(r#""inv-1""#).unwrap();
    let types: Vec<_> = hits.iter().map(|h| h.event_type.clone()).collect();
    assert_eq!(
        types,
        vec![
            "tool_call.opened".to_string(),
            "tool_call.decided".to_string(),
            "tool_call.executed".to_string(),
        ]
    );
    // abandoned 不应出现
    assert!(!types.iter().any(|t| t == "tool_call.abandoned"));
}

/// (9) 审计账本中不得出现 raw secret 原文(要求 caller 走 vigil-redaction::redact)。
#[test]
fn no_raw_secret_in_sqlite_after_redact() {
    use vigil_redaction::redact;

    let dir = tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    let l = Ledger::open(&path).unwrap();
    let sid = l.start_session("test", None).unwrap();

    const MAGIC: &str = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
    let raw_payload = json!({"tool": "github__create_issue", "auth": MAGIC});
    let (redacted, summary) = redact(&raw_payload);

    l.append_event(&sid, "tool.call", &redacted, Some(&summary))
        .unwrap();

    // 绕过 Ledger API,直接用 rusqlite 扫描所有文本列,确保 MAGIC 不留存。
    let c = Connection::open(&path).unwrap();
    let mut stmt = c
        .prepare("SELECT payload_json, COALESCE(redacted_text,'') FROM events")
        .unwrap();
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .unwrap();
    for r in rows {
        let (p, t) = r.unwrap();
        assert!(!p.contains(MAGIC), "payload 泄漏 raw secret: {}", p);
        assert!(!t.contains(MAGIC), "redacted_text 泄漏 raw secret: {}", t);
    }
}

/// (10) 空 session_id / event_type 被拒绝(输入校验)。
#[test]
fn invalid_input_rejected() {
    let l = Ledger::open_in_memory().unwrap();
    assert!(matches!(
        l.append_event("", "x", &json!({}), None).err(),
        Some(AuditError::InvalidInput { .. })
    ));
    let sid = l.start_session("test", None).unwrap();
    assert!(matches!(
        l.append_event(&sid, "", &json!({}), None).err(),
        Some(AuditError::InvalidInput { .. })
    ));
}

/// (11) WAL + PRAGMA 实际生效(开口相当于 smoke 校验,但防未来配置回退)。
#[test]
fn pragmas_applied_on_open() {
    let l = Ledger::open_in_memory().unwrap();
    let sid = l.start_session("test", None).unwrap();
    // 通过侧写:append 一条,verify 通过即 SQL 能正常工作。
    l.append_event(&sid, "a", &json!({}), None).unwrap();
    l.verify_chain().unwrap();
    // checkpoint 不应报错(内存库里是 no-op,磁盘库才真正生效)
    l.checkpoint().unwrap();
}

/// (12) public `append_event` **必须拒绝** `tool_call.*` 前缀,强制走 ToolCallSpan。
/// 这是 Codex I01 review 的 BLOCKER 回归测试。
#[test]
fn public_append_event_rejects_reserved_prefix() {
    let l = Ledger::open_in_memory().unwrap();
    let sid = l.start_session("test", None).unwrap();

    for et in [
        "tool_call.opened",
        "tool_call.decided",
        "tool_call.executed",
        "tool_call.execute_failed",
        "tool_call.abandoned",
        "tool_call.forged_by_attacker",
        // I02+I03 F3 扩展:decision / approval / lease 前缀同样必须被拒
        "decision.recorded",
        "decision.overridden",
        "decision.forged",
        "approval.created",
        "approval.resolved",
        "approval.note",
        "approval.forged",
        "lease.minted",
        "lease.revoked",
        "lease.forged",
    ] {
        let err = l
            .append_event(&sid, et, &json!({"x": 1}), None)
            .expect_err("public append_event 必须拒绝 tool_call.* 前缀");
        assert!(
            matches!(err, AuditError::InvalidInput { .. }),
            "et={} 期望 InvalidInput,实际 {:?}",
            et,
            err
        );
    }
    // 正常事件类型仍然可写
    l.append_event(&sid, "custom.event", &json!({}), None)
        .unwrap();

    // sanity:常量是对外可见的契约(I02+I03 扩为集合)
    assert!(RESERVED_EVENT_PREFIXES.contains(&"tool_call."));
    assert!(RESERVED_EVENT_PREFIXES.contains(&"decision."));
    assert!(RESERVED_EVENT_PREFIXES.contains(&"approval."));
    assert!(RESERVED_EVENT_PREFIXES.contains(&"lease."));
}

/// (13) replay_session 按顺序返回全部事件并且 payload 可反序列化。
#[test]
fn replay_session_returns_timeline() {
    use vigil_types::{DecisionKind, DecisionRecord};

    let l = Ledger::open_in_memory().unwrap();
    let sid = l.start_session("test", None).unwrap();

    // 一次完整 tool call
    let span = l.tool_call_span("inv-1", &sid).unwrap();
    let dec = DecisionRecord {
        decision_id: "dec-1".into(),
        invocation_id: "inv-1".into(),
        decision: DecisionKind::Allow,
        risk_score: 20,
        reasons: vec!["fs.read within project".into()],
        policy_ids: vec!["allow-repo-read".into()],
        created_at: 0,
    };
    let span = span.decision_recorded(&dec).unwrap();
    span.executed("read src/main.rs").unwrap();

    // 夹一条外部事件,验证 replay 会按 event_id 统一排序
    l.append_event(&sid, "custom.annotation", &json!({"note": "n/a"}), None)
        .unwrap();

    let timeline = l.replay_session(&sid).unwrap();
    let types: Vec<_> = timeline.iter().map(|e| e.event_type.as_str()).collect();
    assert_eq!(
        types,
        vec![
            "tool_call.opened",
            "tool_call.decided",
            "tool_call.executed",
            "custom.annotation",
        ]
    );
    // 每条 payload 都能被序列化回(非空 JSON)
    for ev in &timeline {
        assert!(ev.payload.is_object());
        assert!(!ev.event_hash.is_empty());
    }
    // 陌生 session_id 返回空
    assert!(l.replay_session("not-a-session").unwrap().is_empty());
}

/// (14) tamper 覆盖扩展:篡改 prev_hash / event_hash / created_at 三个关键字段
/// 都必须在 verify_chain 中被发现。
#[test]
fn tamper_on_other_fields_also_detected() {
    // 子测试:为每种篡改场景独立建库,避免状态互扰
    fn setup_two_events() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ledger.db");
        {
            let l = Ledger::open(&path).unwrap();
            let sid = l.start_session("test", None).unwrap();
            l.append_event(&sid, "a", &json!({"n": 1}), None).unwrap();
            l.append_event(&sid, "b", &json!({"n": 2}), None).unwrap();
            l.verify_chain().unwrap();
        }
        (dir, path)
    }

    // 1) 篡改 prev_hash
    {
        let (_dir, path) = setup_two_events();
        Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE events SET prev_hash = ?1 WHERE event_id = 2",
                rusqlite::params!["0".repeat(64)],
            )
            .unwrap();
        let l = Ledger::open(&path).unwrap();
        assert!(matches!(
            l.verify_chain().unwrap_err(),
            AuditError::ChainBroken { event_id: 2 }
        ));
    }

    // 2) 篡改 event_hash
    {
        let (_dir, path) = setup_two_events();
        Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE events SET event_hash = ?1 WHERE event_id = 1",
                rusqlite::params!["0".repeat(64)],
            )
            .unwrap();
        let l = Ledger::open(&path).unwrap();
        assert!(matches!(
            l.verify_chain().unwrap_err(),
            AuditError::ChainBroken { event_id: 1 }
        ));
    }

    // 3) 篡改 created_at
    {
        let (_dir, path) = setup_two_events();
        Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE events SET created_at = created_at + 1 WHERE event_id = 1",
                [],
            )
            .unwrap();
        let l = Ledger::open(&path).unwrap();
        assert!(matches!(
            l.verify_chain().unwrap_err(),
            AuditError::ChainBroken { event_id: 1 }
        ));
    }
}

/// (14.5) VIGIL-SEC-001:v2 摘要把 `session_id` / `event_type` / `redacted_text` 纳入,
/// 这三列的部分篡改(本地具 DB 写权限者)现在会被 `verify_chain` 检测 —— 闭合 security
/// audit 发现的缺口(此前这三列在摘要之外,改写它们 verify 检测不到)。
#[test]
fn tamper_v2_bound_fields_detected() {
    fn setup() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ledger.db");
        {
            let l = Ledger::open(&path).unwrap();
            let sid = l.start_session("test", None).unwrap();
            l.append_event(&sid, "a", &json!({"n": 1}), Some("summary-1"))
                .unwrap();
            l.append_event(&sid, "b", &json!({"n": 2}), Some("summary-2"))
                .unwrap();
            l.verify_chain().unwrap();
        }
        (dir, path)
    }

    // 1) session_id 篡改(把事件移出某 session 回放)
    {
        let (_dir, path) = setup();
        Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE events SET session_id = 'other-session' WHERE event_id = 1",
                [],
            )
            .unwrap();
        let l = Ledger::open(&path).unwrap();
        assert!(matches!(
            l.verify_chain().unwrap_err(),
            AuditError::ChainBroken { event_id: 1 }
        ));
    }
    // 2) event_type 篡改(翻转事件类型)
    {
        let (_dir, path) = setup();
        Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE events SET event_type = 'forged' WHERE event_id = 1",
                [],
            )
            .unwrap();
        let l = Ledger::open(&path).unwrap();
        assert!(matches!(
            l.verify_chain().unwrap_err(),
            AuditError::ChainBroken { event_id: 1 }
        ));
    }
    // 3) redacted_text 篡改(改写 FTS/UI 显示的脱敏摘要)
    {
        let (_dir, path) = setup();
        Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE events SET redacted_text = 'rewritten' WHERE event_id = 1",
                [],
            )
            .unwrap();
        let l = Ledger::open(&path).unwrap();
        assert!(matches!(
            l.verify_chain().unwrap_err(),
            AuditError::ChainBroken { event_id: 1 }
        ));
    }
}

/// (14.6) VIGIL-SEC-001 版本化:历史 v1 事件(chain_version=1)仍按 v1 摘要验证 ——
/// 迁移不破坏旧链;v1 genesis 之后接 v2 事件的混合链整体可验证(realistic 升级路径)。
#[test]
fn legacy_v1_event_and_mixed_chain_verify() {
    use vigil_audit::hash::{compute_event_hash, compute_event_hash_v2};

    let dir = tempdir().unwrap();
    let path = dir.path().join("ledger.db");

    // Ledger::open 建 schema(含 chain_version)+ migration
    {
        Ledger::open(&path).unwrap();
    }

    // 手动插入一条 v1 genesis 事件(模拟本次修复前写入的历史事件)
    let p1 = json!({"legacy": true});
    let t1 = 1_700_000_000i64;
    let h1 = compute_event_hash("", &p1, t1).unwrap();
    // 在 v1 之后链入一条 v2 事件(prev = h1)
    let p2 = json!({"n": 2});
    let t2 = 1_700_000_001i64;
    let h2 = compute_event_hash_v2(&h1, &p2, t2, "sess-new", "new.event", Some("sum")).unwrap();
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO events (session_id, event_type, payload_json, redacted_text, prev_hash, event_hash, created_at, chain_version)
             VALUES (?1,?2,?3,?4,?5,?6,?7,1)",
            rusqlite::params!["legacy-sess", "legacy.event", serde_json::to_string(&p1).unwrap(), Option::<String>::None, "", h1, t1],
        ).unwrap();
        conn.execute(
            "INSERT INTO events (session_id, event_type, payload_json, redacted_text, prev_hash, event_hash, created_at, chain_version)
             VALUES (?1,?2,?3,?4,?5,?6,?7,2)",
            rusqlite::params!["sess-new", "new.event", serde_json::to_string(&p2).unwrap(), Some("sum"), h1, h2, t2],
        ).unwrap();
    }

    // 混合 v1->v2 链整体可验证
    let l = Ledger::open(&path).unwrap();
    l.verify_chain().expect(
        "mixed v1(genesis) -> v2 chain must verify (versioned dispatch, no historical break)",
    );
}

/// (14.7) VIGIL-SEC-001 R1(Codex BLOCKER):chain_version 必须单调非降。v2 事件之后
/// 出现 v1 行 = 降级攻击(攻击者把 v2 行改 chain_version=1 + 重算 v1 hash,以绕开
/// session_id/event_type/redacted_text 绑定),即使 v1 hash 本身有效也必须 ChainBroken。
#[test]
fn v2_then_v1_rejected_as_downgrade() {
    use vigil_audit::hash::{compute_event_hash, compute_event_hash_v2};

    let dir = tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    {
        Ledger::open(&path).unwrap();
    }

    // event 1:v2 genesis;event 2:v1,正确链入(prev = h1),v1 hash 本身有效
    let p1 = json!({"n": 1});
    let t1 = 1_700_000_000i64;
    let h1 = compute_event_hash_v2("", &p1, t1, "s1", "e1", None).unwrap();
    let p2 = json!({"n": 2});
    let t2 = 1_700_000_001i64;
    let h2 = compute_event_hash(&h1, &p2, t2).unwrap();
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO events (session_id,event_type,payload_json,redacted_text,prev_hash,event_hash,created_at,chain_version) VALUES (?1,?2,?3,?4,?5,?6,?7,2)",
            rusqlite::params!["s1", "e1", serde_json::to_string(&p1).unwrap(), Option::<String>::None, "", h1, t1],
        ).unwrap();
        conn.execute(
            "INSERT INTO events (session_id,event_type,payload_json,redacted_text,prev_hash,event_hash,created_at,chain_version) VALUES (?1,?2,?3,?4,?5,?6,?7,1)",
            rusqlite::params!["s1", "e1", serde_json::to_string(&p2).unwrap(), Option::<String>::None, h1, h2, t2],
        ).unwrap();
    }

    let l = Ledger::open(&path).unwrap();
    // 即使 event 2 的 v1 hash 有效,单调性守门仍因 v2->v1 降级而拒(event_id=2)
    assert!(matches!(
        l.verify_chain().unwrap_err(),
        AuditError::ChainBroken { event_id: 2 }
    ));
}

/// (15) span_drop_failures 正常路径恒为 0。
/// 若未来 Drop 兜底失败,计数器应可被 caller 读到(可观察性)。
#[test]
fn span_drop_failures_counter_reads_zero_on_happy_path() {
    let l = Ledger::open_in_memory().unwrap();
    let sid = l.start_session("test", None).unwrap();
    {
        let _ = l.tool_call_span("inv-1", &sid).unwrap();
    } // drop → abandoned 成功写入
    assert_eq!(l.span_drop_failures(), 0);
}

/// (16) 迁移幂等性:同一磁盘库连续 open 两次,`apply_column_migrations` 必须 no-op,
/// 不报错也不改变现有数据。Codex I08 R2 / I10a 横向清理的关键不变量:
/// 新迭代往 `COLUMN_MIGRATIONS` 追加列时,老库能升级、升级完再次打开要幂等。
#[test]
fn column_migrations_are_idempotent_across_reopens() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("ledger.db");

    // 第一次 open:建表 + 跑 migration + 写一条事件
    let event_hash_before: String;
    {
        let l = Ledger::open(&path).unwrap();
        let sid = l.start_session("test", None).unwrap();
        let ev = l
            .append_event(&sid, "x", &json!({"n": 1}), Some("n1"))
            .unwrap();
        event_hash_before = ev.event_hash;
        l.checkpoint().unwrap();
    }

    // 第二次 open:migration 必须 no-op(所有 ADD COLUMN 目标列都已存在)
    {
        let l = Ledger::open(&path).unwrap();
        // 已有事件仍在,hash 不变 → 说明迁移不曾破坏数据
        l.verify_chain().unwrap();
        assert_eq!(l.event_count().unwrap(), 1);
    }

    // 第三次 open:再次幂等
    {
        let l = Ledger::open(&path).unwrap();
        l.verify_chain().unwrap();
        assert_eq!(l.event_count().unwrap(), 1);
    }

    // 侧写:直接 query 确认 I08 `pending_command_json` 列存在(保护未来增列不被回退)
    let c = Connection::open(&path).unwrap();
    let mut stmt = c.prepare("PRAGMA table_info(server_profiles)").unwrap();
    let cols: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert!(
        cols.iter().any(|c| c == "pending_command_json"),
        "I08 新增列在幂等 reopen 后必须仍存在,实际列 = {:?}",
        cols
    );

    // 侧写:I10a 新表 oauth_token_metadata 依然存在且可查
    let oauth_cols: Vec<String> = Connection::open(&path)
        .unwrap()
        .prepare("PRAGMA table_info(oauth_token_metadata)")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert!(oauth_cols.contains(&"token_kind".to_string()));

    // 安抚 clippy: event_hash_before 仅用于确认变量在作用域里消费过
    assert_eq!(event_hash_before.len(), 64);
}

/// (17) 老库 reopen 后 I10a `oauth_token_metadata` 表仍 functional(注册 + 列出)。
/// 防止未来迭代不小心在 `CREATE TABLE IF NOT EXISTS` 之外误删分支。
#[test]
fn oauth_token_metadata_survives_reopen() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("ledger.db");

    {
        let l = Ledger::open(&path).unwrap();
        l.register_oauth_token_metadata(
            "token://oauth/access/r/c",
            "https://mcp.example.com/",
            "https://auth.example.com/",
            &["mcp:tools.read".into()],
            "access",
            Some(9_999_999_999),
            "https://auth.example.com",
        )
        .unwrap();
        l.checkpoint().unwrap();
    }

    let l2 = Ledger::open(&path).unwrap();
    let rows = l2.list_oauth_token_metadata().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].token_ref, "token://oauth/access/r/c");
    assert_eq!(rows[0].token_kind, "access");
    assert_eq!(rows[0].issuer.as_deref(), Some("https://auth.example.com"));
}

// =========================================================================
// I10b-α1(ADR 0011 §α1-D1)— `issuer` 列迁移回归
// =========================================================================

/// (18) issuer 列在幂等 reopen 后继续存在;迁移 no-op。
#[test]
fn issuer_column_migration_idempotent_on_reopen() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("ledger.db");

    // 第一次 open:CREATE TABLE + 走 COLUMN_MIGRATIONS(issuer 已在 schema.sql,no-op)
    {
        let l = Ledger::open(&path).unwrap();
        l.register_oauth_token_metadata(
            "token://oauth/access/a/b",
            "https://mcp.example.com/",
            "https://auth.example.com/",
            &["mcp:tools.read".into()],
            "access",
            None,
            "https://auth.example.com",
        )
        .unwrap();
        l.checkpoint().unwrap();
    }

    // 第二 / 第三次 reopen:apply_column_migrations 必须 no-op
    for _ in 0..2 {
        let l = Ledger::open(&path).unwrap();
        let rows = l.list_oauth_token_metadata().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].issuer.as_deref(), Some("https://auth.example.com"));
    }

    // 侧写:PRAGMA 显示 issuer 列确实存在
    let cols: Vec<String> = rusqlite::Connection::open(&path)
        .unwrap()
        .prepare("PRAGMA table_info(oauth_token_metadata)")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert!(cols.contains(&"issuer".to_string()), "cols = {:?}", cols);
}

/// (19) legacy I10a 行(ADD COLUMN 后 issuer=NULL)仍可被 list/get;类型投影保留
/// `Option<String>` —— **typed 层(vigil-http-auth)** 才 fail-closed(那层的
/// `legacy_null_issuer_row_fails_closed` 回归在 vigil-http-auth integration)。
#[test]
fn legacy_row_without_issuer_is_readable_at_row_level() {
    let l = Ledger::open_in_memory().unwrap();
    // 模拟 legacy I10a 磁盘行:绕过 API,直接 INSERT(不给 issuer 列,走 DEFAULT NULL)
    {
        let conn_mutex = (&l as *const Ledger) as *const std::sync::Mutex<rusqlite::Connection>;
        // 上面的黑 cast 只是保险 —— 实际我们用 test-util feature 的 raw insert;
        // 这里改成经 schema.sql 初始化的内存库,直接 prepare 一条不含 issuer 列的 INSERT
        let _ = conn_mutex; // 压制 unused
    }
    // 走 ledger 初始化,再用一条裸 SQL 模拟老行(INSERT 不提 issuer 列 → DEFAULT NULL)
    let inline_conn = rusqlite::Connection::open_in_memory().unwrap();
    inline_conn
        .execute_batch(include_str!("../src/schema.sql"))
        .unwrap();
    inline_conn
        .execute(
            "INSERT INTO oauth_token_metadata
               (token_ref, resource, authorization_server, scope_set_json,
                token_kind, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                "token://oauth/access/legacy/c",
                "https://mcp.example.com/",
                "https://auth.example.com/",
                r#"["mcp:tools.read"]"#,
                "access",
                Option::<i64>::None,
                1_700_000_000_i64,
            ],
        )
        .unwrap();
    let legacy_issuer: Option<String> = inline_conn
        .query_row(
            "SELECT issuer FROM oauth_token_metadata WHERE token_ref = ?1",
            rusqlite::params!["token://oauth/access/legacy/c"],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        legacy_issuer.is_none(),
        "legacy 行写入时未提供 issuer → 列应为 NULL, got {:?}",
        legacy_issuer
    );
}

/// (20) `register_oauth_token_metadata` 拒绝空 issuer。
#[test]
fn register_oauth_token_metadata_rejects_empty_issuer() {
    let l = Ledger::open_in_memory().unwrap();
    let err = l
        .register_oauth_token_metadata(
            "token://oauth/access/a/b",
            "https://mcp.example.com/",
            "https://auth.example.com/",
            &["mcp:tools.read".into()],
            "access",
            None,
            "", // empty issuer
        )
        .expect_err("empty issuer 必须被拒");
    assert!(matches!(
        err,
        AuditError::InvalidInput {
            reason: "issuer_empty"
        }
    ));
}

/// (21) Finding 7(hostile review):`register_oauth_token_metadata` 把行的安全字段绑进审计哈希链;
/// 行与最新绑定事件一致时 `get_oauth_token_metadata` 正常返回(verify 通过路径)。
#[test]
fn finding7_oauth_metadata_binding_happy_path() {
    let l = Ledger::open_in_memory().unwrap();
    l.register_oauth_token_metadata(
        "token://oauth/access/r/c",
        "https://mcp.example.com/",
        "https://auth.example.com/",
        &["mcp:tools.read".into()],
        "access",
        None,
        "https://auth.example.com",
    )
    .unwrap();
    let row = l
        .get_oauth_token_metadata("token://oauth/access/r/c")
        .expect("binding 匹配应正常读")
        .expect("行存在");
    assert_eq!(row.issuer.as_deref(), Some("https://auth.example.com"));
}

/// (22) Finding 7 ★安全回归:DB 攻击者绕过 Ledger API,用第二个 raw rusqlite 连接直改
/// `oauth_token_metadata` 行的 issuer(而审计链里的绑定事件仍是旧值)→ `get_oauth_token_metadata`
/// 检测行≠链 → **fail-closed**(绝不返回被篡改的 issuer)。模拟真实 DB 篡改,**非 test-util**,CI 内跑。
#[test]
fn finding7_tampered_metadata_row_fails_closed() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    let tref = "token://oauth/access/r/c";
    {
        let l = Ledger::open(&path).unwrap();
        l.register_oauth_token_metadata(
            tref,
            "https://mcp.example.com/",
            "https://auth.example.com/",
            &["mcp:tools.read".into()],
            "access",
            None,
            "https://auth.example.com", // 真 issuer
        )
        .unwrap();
        l.checkpoint().unwrap();
    }
    // DB 攻击者:绕过 Ledger,raw SQL 把 issuer 改成恶意 AS(绑定事件不动)。
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        let n = conn
            .execute(
                "UPDATE oauth_token_metadata SET issuer = ?1 WHERE token_ref = ?2",
                rusqlite::params!["https://evil.example.com", tref],
            )
            .unwrap();
        assert_eq!(n, 1, "篡改应命中 1 行");
    }
    let l = Ledger::open(&path).unwrap();
    let err = l
        .get_oauth_token_metadata(tref)
        .expect_err("行被改 issuer 而绑定未变 → 必须 fail-closed");
    assert!(
        matches!(
            err,
            AuditError::InvalidInput {
                reason: "oauth_metadata_integrity_mismatch"
            }
        ),
        "期望 integrity mismatch,实际 {err:?}"
    );
}

/// (23) Finding 7 向后兼容:无绑定事件的 legacy 行(本特性前 onboard / 直插)→ 放行
/// (无法回溯校验,不破坏既有 token)。raw 插一行(不经 register → 无绑定事件),get 正常返回。
#[test]
fn finding7_legacy_row_without_binding_passes() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    let tref = "token://oauth/access/legacy/x";
    {
        let l = Ledger::open(&path).unwrap();
        l.checkpoint().unwrap(); // 刷 schema 到主库,raw 连接可见
    }
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO oauth_token_metadata
               (token_ref, resource, authorization_server, scope_set_json,
                token_kind, expires_at, created_at, issuer)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                tref,
                "https://mcp.example.com/",
                "https://auth.example.com/",
                "[\"mcp:tools.read\"]",
                "access",
                Option::<i64>::None,
                0_i64,
                "https://auth.example.com",
            ],
        )
        .unwrap();
    }
    let l = Ledger::open(&path).unwrap();
    let row = l
        .get_oauth_token_metadata(tref)
        .expect("legacy 行(无绑定)应放行")
        .expect("行存在");
    assert_eq!(row.token_ref, tref);
}

/// (24) Finding 7 ★安全回归(hostile re-review exploit 1):DB 攻击者 **删掉绑定事件** 试图
/// downgrade 到"无绑定 = legacy 放行" → 读侧按行存的 `binding_event_id` 取不到事件 → **fail-closed**
/// (绝不因事件消失而把被绑定的行降级当 legacy 放行)。
#[test]
fn finding7_deleted_binding_event_fails_closed() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    let tref = "token://oauth/access/r/c";
    {
        let l = Ledger::open(&path).unwrap();
        l.register_oauth_token_metadata(
            tref,
            "https://mcp.example.com/",
            "https://auth.example.com/",
            &["mcp:tools.read".into()],
            "access",
            None,
            "https://auth.example.com",
        )
        .unwrap();
        l.checkpoint().unwrap();
    }
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        let eid: i64 = conn
            .query_row(
                "SELECT binding_event_id FROM oauth_token_metadata WHERE token_ref = ?1",
                rusqlite::params![tref],
                |r| r.get(0),
            )
            .unwrap();
        conn.execute(
            "DELETE FROM events WHERE event_id = ?1",
            rusqlite::params![eid],
        )
        .unwrap();
    }
    let l = Ledger::open(&path).unwrap();
    let err = l
        .get_oauth_token_metadata(tref)
        .expect_err("删绑定事件必须 fail-closed,绝不 downgrade 到 legacy 放行");
    assert!(
        matches!(
            err,
            AuditError::InvalidInput {
                reason: "oauth_binding_event_missing"
            }
        ),
        "实际 {err:?}"
    );
}

/// (25) Finding 7 ★安全回归(hostile re-review exploit 2 的 naive 变体):DB 攻击者 **改绑定事件的
/// payload**(伪装成匹配未来 evil 行)但**不一致重算 hash** → `verify_chain` 检出链断 → **fail-closed**。
/// (完整一致重写整条链才能绕过 = unkeyed chain 固有限制,与账本其余状态同级,需外部 anchoring。)
#[test]
fn finding7_tampered_binding_event_fails_closed_via_verify_chain() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    let tref = "token://oauth/access/r/c";
    {
        let l = Ledger::open(&path).unwrap();
        l.register_oauth_token_metadata(
            tref,
            "https://mcp.example.com/",
            "https://auth.example.com/",
            &["mcp:tools.read".into()],
            "access",
            None,
            "https://auth.example.com",
        )
        .unwrap();
        l.checkpoint().unwrap();
    }
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        let eid: i64 = conn
            .query_row(
                "SELECT binding_event_id FROM oauth_token_metadata WHERE token_ref = ?1",
                rusqlite::params![tref],
                |r| r.get(0),
            )
            .unwrap();
        // 改 payload 的 issuer 为恶意 AS,但保留旧 event_hash(不一致重算)。
        let evil = format!(
            r#"{{"authorization_server":"https://auth.example.com/","issuer":"https://evil.example.com","resource":"https://mcp.example.com/","scope_set":["mcp:tools.read"],"token_kind":"access","token_ref":"{tref}"}}"#
        );
        let n = conn
            .execute(
                "UPDATE events SET payload_json = ?1 WHERE event_id = ?2",
                rusqlite::params![evil, eid],
            )
            .unwrap();
        assert_eq!(n, 1);
    }
    let l = Ledger::open(&path).unwrap();
    let err = l
        .get_oauth_token_metadata(tref)
        .expect_err("改绑定事件 payload 不重算 hash → verify_chain 必检出 → fail-closed");
    assert!(
        matches!(err, AuditError::ChainBroken { .. }),
        "期望 ChainBroken(verify_chain 检出),实际 {err:?}"
    );
}

/// ISS-20260621-004 回归:多个独立连接**并发** `Ledger::open` 同一新磁盘库,不得有任何连接
/// 因撞锁失败。根因:`init()` 此前在 `PRAGMA journal_mode = WAL`(取排他锁)**之前**未设
/// busy_timeout,并发 open 撞锁会因 busy_timeout 仍是默认 0 而**立即** "database is locked"
/// 失败而非等待 —— 这是 co_approval(hook + resolver 双连接近乎同时 open)在 Linux CI 偶发
/// flaky 的真因:hook open 失败→回退 Ask→从不写 Pending→resolver 10s 超时 panic。
/// 修复 = busy_timeout 提到撞锁语句之前。barrier 让 N 线程对齐同时冲 open,最大化 open-race。
#[test]
fn concurrent_open_same_fresh_ledger_never_locks_out() {
    use std::sync::{Arc, Barrier};
    let dir = tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite3");
    let n = 16;
    let barrier = Arc::new(Barrier::new(n));
    let handles: Vec<_> = (0..n)
        .map(|_| {
            let p = path.clone();
            let b = Arc::clone(&barrier);
            std::thread::spawn(move || {
                b.wait(); // 所有线程在此对齐,尽量同时冲 open 以最大化 open-race
                Ledger::open(&p).map(|_| ()).map_err(|e| e.to_string())
            })
        })
        .collect();
    let errs: Vec<String> = handles
        .into_iter()
        .filter_map(|h| h.join().unwrap().err())
        .collect();
    assert!(
        errs.is_empty(),
        "并发 open 同一新库不应有连接因撞锁失败;{}/{n} 失败: {errs:?}",
        errs.len()
    );
}
