//! Smoke tests for vigil-desktop-react backend dispatch paths.

use std::sync::Arc;

use vigil_audit::Ledger;
use vigil_desktop::dispatch;
use vigil_ui_protocol::{
    Capability, ListPrivacyFindingsReq, ListRecentEventsReq, ListSessionsReq,
    UiCommand,
};

fn setup() -> Arc<Ledger> {
    Arc::new(Ledger::open_in_memory().expect("open in-memory ledger"))
}

#[test]
fn protection_summary_returns_counts() {
    let ledger = setup();
    let resp = dispatch(
        UiCommand::ListRecentEvents(ListRecentEventsReq {
            session_id: None,
            event_type_filter: None,
            limit: 10,
        }),
        ledger.as_ref(),
        Capability::Read,
    );
    assert!(resp.is_ok(), "list_recent_events should succeed on empty ledger");

    let summary = ledger.protection_summary(8).expect("protection summary");
    assert_eq!(summary.total_events_audited, 0);
    assert!(summary.chain_intact);
}

#[test]
fn list_sessions_on_empty_ledger() {
    let ledger = setup();
    let resp = dispatch(
        UiCommand::ListSessions(ListSessionsReq {
            source: None,
            limit: 10,
        }),
        ledger.as_ref(),
        Capability::Read,
    );
    match resp {
        Ok(vigil_ui_protocol::UiResponse::SessionList(rows)) => assert!(rows.is_empty()),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn list_privacy_findings_on_empty_ledger() {
    let ledger = setup();
    let resp = dispatch(
        UiCommand::ListPrivacyFindings(ListPrivacyFindingsReq {
            limit_recent_scans: 10,
        }),
        ledger.as_ref(),
        Capability::Read,
    );
    match resp {
        Ok(vigil_ui_protocol::UiResponse::PrivacyFindings(dto)) => {
            assert!(dto.by_label_total.is_empty());
            assert!(dto.recent_scans.is_empty());
        }
        other => panic!("unexpected response: {other:?}"),
    }
}
