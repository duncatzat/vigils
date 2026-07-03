//! ISS-019 Phase 1 — `wait_for_resolution` cross-proc 路径回归守门。
//!
//! v0.3 Stage 3 发现:`vigil-hub serve` 与 `vigil-desktop CLI resolve` 在不同进程,
//! 桌面 CLI 直接 UPDATE DB 状态行,**不**会 wakeup Hub 进程的 in-proc Condvar
//! (`ApprovalBroker.publish_resolution`),导致 Hub 卡到 timeout 才感知。
//!
//! v0.3 临时 hack:`--dev-permissive-firewall + approval_wait=3s`,把 timeout 缩短
//! 让 final DB fallback 早点跑。**这不是根治** —— 真正的 cross-proc 用户体验
//! 仍然取决于 timeout 长短。
//!
//! ISS-019 Phase 1 根治:`wait_for_resolution` 内 loop 把 `wait_timeout` 切片为
//! 500ms 段,每段后**主动查 DB**,这样 cross-proc 写入最多 500ms 后被检出。
//!
//! 本守门测试用文件 DB + 两个独立 `Ledger` 实例模拟:
//!   - Ledger A:主线程 `wait_for_resolution(timeout=10s)`
//!   - Ledger B:辅线程 800ms 后 `approve()`(B 的 in-proc broker `publish` 只对
//!     B 自己生效;A 的 broker 没收到通知,只能靠短轮询)
//!
//! 期望:A 在 ~1.3s(800ms approve + ≤500ms 下次 poll)内拿到 `Approved`,
//! 远低于 10s timeout。**绝不**依赖 timeout 兜底。

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::err_expect,
    clippy::panic
)]

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use tempfile::tempdir;
use vigil_audit::Ledger;
use vigil_types::{ApprovalScope, ApprovalStatus, DecisionKind, DecisionRecord, EffectVector};

fn make_decision(id: &str) -> DecisionRecord {
    DecisionRecord {
        decision_id: id.into(),
        invocation_id: format!("inv-{id}"),
        decision: DecisionKind::Approve,
        risk_score: 50,
        reasons: vec![],
        policy_ids: vec![],
        created_at: 0,
    }
}

#[test]
fn cross_proc_approve_via_separate_ledger_resolves_via_db_polling() {
    // 文件 DB,模拟跨进程共享(SQLite 默认 shared cache 通过文件路径)
    let dir = tempdir().unwrap();
    let path = dir.path().join("ledger.db");

    // Ledger A — 主线程 wait_for_resolution 用
    let ledger_a = Arc::new(Ledger::open(&path).unwrap());
    let sid = ledger_a.start_session("test", Some("cross-proc")).unwrap();

    // 创建 approval(A 写)
    let req = ledger_a
        .create_approval(
            &sid,
            &make_decision("d-cross"),
            &EffectVector::default(),
            "cross-proc test",
            "wait via DB poll",
            60,
            Default::default(),
        )
        .unwrap();
    let approval_id = req.approval_id.clone();

    // Ledger B — "另一进程" 用,800ms 后 approve
    // 关键:**完全独立**的 Ledger 实例 → 独立 ApprovalBroker;
    // B.publish 只 wakeup B 自己的 Condvar slot,A 收不到通知
    let path_b = path.clone();
    let approval_id_b = approval_id.clone();
    let approver = thread::spawn(move || {
        thread::sleep(Duration::from_millis(800));
        let ledger_b = Ledger::open(&path_b).unwrap();
        ledger_b
            .approve(
                &approval_id_b,
                ApprovalScope::Once,
                Some("cross-proc-actor"),
            )
            .expect("cross-proc approve via Ledger B");
    });

    // 主线程 wait — timeout 远大于实际所需,保证如果短轮询不工作会被 timeout 兜底
    // 暴露(然后用 elapsed 时间断言确实是短轮询而非 final fallback)
    let t0 = Instant::now();
    let resolution = ledger_a
        .wait_for_resolution(&approval_id, Duration::from_secs(10))
        .expect("wait_for_resolution err");
    let elapsed = t0.elapsed();

    approver.join().unwrap();

    // 1. 必须返回 resolution(Some)
    let r = resolution.expect("cross-proc 应返回 Approved,而非 None");
    assert_eq!(r.status, ApprovalStatus::Approved);
    assert_eq!(r.scope, Some(ApprovalScope::Once));
    assert_eq!(r.resolved_by.as_deref(), Some("cross-proc-actor"));

    // 2. 必须在短轮询周期内返回(800ms approve + ≤500ms next poll + 余量),
    //    远小于 10s timeout — 证明走的是短轮询而非 final fallback
    assert!(
        elapsed < Duration::from_millis(2000),
        "cross-proc wait 应在 ~1.3s 内返回(approve 800ms + poll ≤500ms),实际 {elapsed:?} —— \
         短轮询失效,可能 fall back 到 timeout"
    );
    // 3. 也不应早于 approve 时间(approve 在 800ms,不可能更早返回)
    assert!(
        elapsed >= Duration::from_millis(700),
        "实际 {elapsed:?} 早于 approver 调用时间(应 ≥ 800ms - 容差),时间假设有问题"
    );
}

#[test]
fn in_proc_approve_still_wakes_via_condvar_not_polling() {
    // 守门:in-proc 路径(同 Ledger publish_resolution)由 Condvar 立即唤醒,
    // **不**应等到下一个 500ms 轮询。延迟应 ≪ 500ms。
    let l = Arc::new(Ledger::open_in_memory().unwrap());
    let sid = l.start_session("test", Some("in-proc")).unwrap();

    let req = l
        .create_approval(
            &sid,
            &make_decision("d-inproc"),
            &EffectVector::default(),
            "in-proc test",
            "wait via Condvar",
            60,
            Default::default(),
        )
        .unwrap();
    let approval_id = req.approval_id.clone();

    let l_clone = Arc::clone(&l);
    let approval_id_clone = approval_id.clone();
    // 记录 approve **实际触发**时刻,使断言只衡量「唤醒延迟」(approve → wait 返回),与
    // approver 的 100ms sleep 解耦。此前断言 `t0(wait前)..elapsed < 450ms` 把 sleep 计入,
    // 而 `thread::sleep` 在加载的 CI runner 上无上界 overshoot → 与 ISS-20260621-004 同类
    // wall-clock flaky(co_approval)。100ms sleep 仍保留:确保 main 先进入 cv.wait_timeout 再 notify。
    let approve_at = Arc::new(std::sync::Mutex::new(None::<Instant>));
    let approve_at_w = Arc::clone(&approve_at);
    let approver = thread::spawn(move || {
        thread::sleep(Duration::from_millis(100));
        *approve_at_w.lock().unwrap() = Some(Instant::now());
        l_clone
            .approve(&approval_id_clone, ApprovalScope::Once, Some("in-proc"))
            .unwrap();
    });

    let resolution = l
        .wait_for_resolution(&approval_id, Duration::from_secs(10))
        .unwrap()
        .expect("in-proc 应返回 Some");
    let returned_at = Instant::now();
    approver.join().unwrap();

    assert_eq!(resolution.status, ApprovalStatus::Approved);

    // in-proc 由 Condvar **立即**唤醒:approve → wait 返回的唤醒延迟应 ~0(亚毫秒~低毫秒)。
    // 若退化到轮询(ISS-019 设计禁止),需等到下一个 WAIT_POLL_INTERVAL(500ms)轮询边界,
    // 唤醒延迟接近数百毫秒。200ms 阈值两侧充裕,且**不含** approver sleep,故不受 CI 负载下
    // sleep overshoot 影响(根治 ISS-004 同类 wall-clock flaky)。
    let approve_at = approve_at
        .lock()
        .unwrap()
        .expect("approver 应已记录 approve 时刻");
    let wakeup_latency = returned_at.saturating_duration_since(approve_at);
    assert!(
        wakeup_latency < Duration::from_millis(200),
        "in-proc Condvar 唤醒延迟应 < 200ms,实际 {wakeup_latency:?} —— 可能退化到轮询"
    );
}

#[test]
fn timeout_with_no_resolution_returns_none() {
    // 守门:无 cross-proc / in-proc 解析 → 老路径仍 timeout 返 None
    let l = Ledger::open_in_memory().unwrap();
    let sid = l.start_session("test", Some("timeout")).unwrap();

    let req = l
        .create_approval(
            &sid,
            &make_decision("d-timeout"),
            &EffectVector::default(),
            "timeout test",
            "no resolver",
            60,
            Default::default(),
        )
        .unwrap();

    let t0 = Instant::now();
    // 短 timeout(800ms)— 内部应跑 1-2 个 500ms 轮询 + 1 个剩余片;
    // **不**会被任何线程 publish 或 cross-proc 改 DB,故应 timeout 返回 None
    let r = l
        .wait_for_resolution(&req.approval_id, Duration::from_millis(800))
        .unwrap();
    let elapsed = t0.elapsed();

    assert!(r.is_none(), "无 resolver 应 timeout None,得到 {r:?}");
    assert!(
        elapsed >= Duration::from_millis(750),
        "timeout 之前不应早返,实际 {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(1500),
        "timeout 不应严重超过 800ms,实际 {elapsed:?}(轮询调度问题)"
    );
}
