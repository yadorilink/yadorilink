//! Integration tests for the reporting IPC surface exercised over a real control
//! socket, the same pattern `tests/control_socket.rs` already uses for
//! link/status/etc. Covers: report generation, queue management, consent
//! updates, last-error candidate generation, and proof that consent being disabled results in zero
//! network requests reaching a real (mock) endpoint, not just an
//! assertion on internal state.
#![cfg(unix)]

use std::sync::Arc;

use serde_json::json;
use tokio::net::UnixStream;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::ConsentAction;
use yadorilink_ipc_proto::daemonctl::{
    DaemonControlRequest, DaemonControlResponse, DeleteQueueItemRequest, FlushQueueRequest,
    GenerateLastErrorReportRequest, GenerateUsageReportRequest, ListQueueItemsRequest,
    ReportingStatusRequest, ShowQueueItemRequest, SubmitReportRequest, UpdateConsentRequest,
};
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_reporting::builder::{build_usage_envelope, ReportEnvironment};
use yadorilink_reporting::schema::{OsFamily, ReportEnvelope, UsagePayload};

/// `YADORILINK_CONFIG_DIR` is a process-global env var (same pattern used
/// by `yadorilink-cli`'s `tests/materialization.rs`), so every test here
/// holds this mutex for its whole body.
static TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn start_daemon() -> (std::path::PathBuf, tempfile::TempDir, Arc<DaemonState>) {
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
    let store = Arc::new(SegmentBlockStore::new(dir.path().join("blocks")).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open(dir.path().join("sync.sqlite3")).unwrap());
    let state = DaemonState::new("device-under-test".into(), sync_state, store);
    let socket_path = dir.path().join("daemon.sock");

    let serve_path = socket_path.clone();
    let serve_state = state.clone();
    tokio::spawn(async move {
        let _ = yadorilink_daemon::control_socket::unix_transport::serve(
            &serve_path,
            std::sync::Arc::new(yadorilink_daemon::control_context::ControlContext::from_state(
                serve_state,
            )),
        )
        .await;
    });
    yadorilink_daemon::control_socket::unix_transport::wait_until_bound(&socket_path).await;
    (socket_path, dir, state)
}

async fn send(socket_path: &std::path::Path, payload: ReqPayload) -> DaemonControlResponse {
    let mut stream = UnixStream::connect(socket_path).await.unwrap();
    write_message(
        &mut stream,
        &DaemonControlRequest {
            payload: Some(payload),
            protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
        },
    )
    .await
    .unwrap();
    read_message::<DaemonControlResponse>(&mut stream).await.unwrap().unwrap()
}

fn sample_usage_envelope() -> ReportEnvelope {
    build_usage_envelope(
        ReportEnvironment {
            generated_at: "2026-01-01T00:00:00Z".into(),
            yadorilink_version: "0.1.0".into(),
            os_family: OsFamily::Linux,
            os_version_bucket: "24.04".into(),
            arch: "x86_64".into(),
            install_channel: None,
            anonymous_reporter_id: None,
        },
        UsagePayload { daemon_uptime_bucket: "<1h".into(), ..Default::default() },
    )
}

/// default consent is fully disabled and the queue/candidate
/// counts start at zero, all reachable over the real control socket.
#[tokio::test]
async fn reporting_status_reports_default_disabled_consent() {
    let _guard = TEST_MUTEX.lock().await;
    let (socket_path, _dir, _state) = start_daemon().await;

    let resp = send(&socket_path, ReqPayload::ReportingStatus(ReportingStatusRequest {})).await;
    let Some(RespPayload::ReportingStatus(status)) = resp.payload else {
        panic!("wrong response variant")
    };
    let consent = status.consent.unwrap();
    assert!(!consent.usage_submission_enabled);
    assert!(!consent.error_submission_enabled);
    assert!(consent.prompt_to_report_enabled);
    assert_eq!(status.queue_count, 0);
    assert_eq!(status.error_candidate_count, 0);
}

/// the generated usage report is a valid, parseable envelope —
/// exactly the payload a preview/export/submit would use.
#[tokio::test]
async fn generate_usage_report_returns_a_valid_envelope() {
    let _guard = TEST_MUTEX.lock().await;
    let (socket_path, _dir, _state) = start_daemon().await;

    let resp =
        send(&socket_path, ReqPayload::GenerateUsageReport(GenerateUsageReportRequest {})).await;
    let Some(RespPayload::GenerateUsageReport(r)) = resp.payload else {
        panic!("wrong response variant")
    };
    let envelope = ReportEnvelope::from_json(&r.report_json).unwrap();
    envelope.validate().unwrap();
    assert_eq!(envelope.report_type, yadorilink_reporting::schema::ReportType::Usage);
}

/// consent updates round-trip through the control socket and
/// are reflected by a subsequent `ReportingStatus` call.
#[tokio::test]
async fn update_consent_enable_usage_is_reflected_in_status() {
    let _guard = TEST_MUTEX.lock().await;
    let (socket_path, _dir, _state) = start_daemon().await;

    let resp = send(
        &socket_path,
        ReqPayload::UpdateConsent(UpdateConsentRequest {
            action: ConsentAction::EnableUsage as i32,
            bool_value: None,
            string_value: None,
        }),
    )
    .await;
    let Some(RespPayload::UpdateConsent(r)) = resp.payload else {
        panic!("wrong response variant")
    };
    let consent = r.consent.unwrap();
    assert!(consent.usage_submission_enabled);
    assert!(consent.anonymous_reporter_id.is_some());

    let resp = send(&socket_path, ReqPayload::ReportingStatus(ReportingStatusRequest {})).await;
    let Some(RespPayload::ReportingStatus(status)) = resp.payload else {
        panic!("wrong response variant")
    };
    assert!(status.consent.unwrap().usage_submission_enabled);
}

/// A severe-error hook creates a local candidate, and
/// `GenerateLastErrorReport` (no `report_id` — "most recent") returns it
/// with its redaction summary, over the real control socket.
#[tokio::test]
async fn severe_error_hook_candidate_is_returned_by_generate_last_error_report() {
    let _guard = TEST_MUTEX.lock().await;
    let (socket_path, _dir, state) = start_daemon().await;

    let id = yadorilink_daemon::reporting::hooks::record_severe_error(
        &state.reporting,
        "daemon_startup",
        "sync-state",
        vec!["failed to open /Users/alice/sync-state.sqlite3".to_string()],
    );
    assert!(id.is_some());

    let resp = send(
        &socket_path,
        ReqPayload::GenerateLastErrorReport(GenerateLastErrorReportRequest { report_id: None }),
    )
    .await;
    let Some(RespPayload::GenerateLastErrorReport(r)) = resp.payload else {
        panic!("wrong response variant")
    };
    assert_eq!(Some(r.report_id), id);
    assert!(!r.report_json.contains("alice"), "preview must be the already-redacted payload");
    assert!(!r.redaction_summary.is_empty(), "the home-directory redaction should be recorded");
}

/// `GenerateLastErrorReport` with no candidates at all is a clear error,
/// not an empty/zeroed response.
#[tokio::test]
async fn generate_last_error_report_with_no_candidates_is_an_error() {
    let _guard = TEST_MUTEX.lock().await;
    let (socket_path, _dir, _state) = start_daemon().await;

    let resp = send(
        &socket_path,
        ReqPayload::GenerateLastErrorReport(GenerateLastErrorReportRequest { report_id: None }),
    )
    .await;
    assert!(matches!(resp.payload, Some(RespPayload::Error(_))));
}

/// list/show/delete/flush round-trip over
/// the control socket against an entry seeded directly into
/// `state.reporting.queue` (there is no "just enqueue" IPC message —
/// entries reach the queue either via a failed-but-retryable `--submit`
/// or, here, directly for test setup).
#[tokio::test]
async fn queue_list_show_delete_round_trip_over_ipc() {
    let _guard = TEST_MUTEX.lock().await;
    let (socket_path, _dir, state) = start_daemon().await;

    let meta = state.reporting.queue().enqueue(sample_usage_envelope()).unwrap();

    let resp = send(&socket_path, ReqPayload::ListQueueItems(ListQueueItemsRequest {})).await;
    let Some(RespPayload::ListQueueItems(list)) = resp.payload else {
        panic!("wrong response variant")
    };
    assert_eq!(list.items.len(), 1);
    assert_eq!(list.items[0].report_id, meta.report_id);
    assert_eq!(list.items[0].report_type, "usage");

    let resp = send(
        &socket_path,
        ReqPayload::ShowQueueItem(ShowQueueItemRequest { report_id: meta.report_id.clone() }),
    )
    .await;
    let Some(RespPayload::ShowQueueItem(show)) = resp.payload else {
        panic!("wrong response variant")
    };
    let shown = ReportEnvelope::from_json(&show.report_json).unwrap();
    assert_eq!(shown, sample_usage_envelope());

    let resp = send(
        &socket_path,
        ReqPayload::DeleteQueueItem(DeleteQueueItemRequest { report_id: meta.report_id }),
    )
    .await;
    let Some(RespPayload::DeleteQueueItem(del)) = resp.payload else {
        panic!("wrong response variant")
    };
    assert!(del.deleted);

    let resp = send(&socket_path, ReqPayload::ListQueueItems(ListQueueItemsRequest {})).await;
    let Some(RespPayload::ListQueueItems(list)) = resp.payload else {
        panic!("wrong response variant")
    };
    assert!(list.items.is_empty());
}

#[tokio::test]
async fn flush_queue_removes_every_entry_over_ipc() {
    let _guard = TEST_MUTEX.lock().await;
    let (socket_path, _dir, state) = start_daemon().await;
    state.reporting.queue().enqueue(sample_usage_envelope()).unwrap();
    state.reporting.queue().enqueue(sample_usage_envelope()).unwrap();

    let resp = send(&socket_path, ReqPayload::FlushQueue(FlushQueueRequest {})).await;
    let Some(RespPayload::FlushQueue(r)) = resp.payload else { panic!("wrong response variant") };
    assert_eq!(r.removed_count, 2);
    assert!(state.reporting.queue().list().unwrap().is_empty());
}

/// central requirement: with submission consent left at its
/// default (disabled), `SubmitReport` over the real control socket must
/// fail *and* make zero network requests to a real local HTTP listener —
/// not just fail for some other reason while secretly still phoning home.
#[tokio::test]
async fn submit_report_with_consent_disabled_makes_no_network_request() {
    let _guard = TEST_MUTEX.lock().await;
    let (socket_path, _dir, _state) = start_daemon().await;
    let server = MockServer::start().await;
    // No `Mock::given(...)` mounted: any request that did arrive would
    // 404, but the assertion below checks that literally none arrived.

    send(
        &socket_path,
        ReqPayload::UpdateConsent(UpdateConsentRequest {
            action: ConsentAction::SetEndpoint as i32,
            bool_value: None,
            string_value: Some(format!("{}/reports", server.uri())),
        }),
    )
    .await;
    // Deliberately never send EnableUsage — consent stays disabled.

    let resp =
        send(&socket_path, ReqPayload::GenerateUsageReport(GenerateUsageReportRequest {})).await;
    let Some(RespPayload::GenerateUsageReport(r)) = resp.payload else {
        panic!("wrong response variant")
    };

    let resp = send(
        &socket_path,
        ReqPayload::SubmitReport(SubmitReportRequest { report_json: r.report_json }),
    )
    .await;
    assert!(
        matches!(resp.payload, Some(RespPayload::Error(_))),
        "submission must be refused while usage_submission_enabled is false"
    );
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "no request should reach the endpoint while consent is disabled"
    );
}

/// The positive path, for contrast: once usage submission is enabled and
/// an endpoint is configured, `SubmitReport` does reach it and returns a
/// receipt.
#[tokio::test]
async fn submit_report_with_consent_enabled_reaches_the_endpoint() {
    let _guard = TEST_MUTEX.lock().await;
    let (socket_path, _dir, _state) = start_daemon().await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/reports"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "receipt_id": "receipt-ipc-1",
            "submitted_at": "2026-01-01T00:00:05Z",
        })))
        .mount(&server)
        .await;

    send(
        &socket_path,
        ReqPayload::UpdateConsent(UpdateConsentRequest {
            action: ConsentAction::EnableUsage as i32,
            bool_value: None,
            string_value: None,
        }),
    )
    .await;
    send(
        &socket_path,
        ReqPayload::UpdateConsent(UpdateConsentRequest {
            action: ConsentAction::SetEndpoint as i32,
            bool_value: None,
            string_value: Some(format!("{}/reports", server.uri())),
        }),
    )
    .await;

    let resp =
        send(&socket_path, ReqPayload::GenerateUsageReport(GenerateUsageReportRequest {})).await;
    let Some(RespPayload::GenerateUsageReport(r)) = resp.payload else {
        panic!("wrong response variant")
    };

    let resp = send(
        &socket_path,
        ReqPayload::SubmitReport(SubmitReportRequest { report_json: r.report_json }),
    )
    .await;
    let Some(RespPayload::SubmitReport(submit)) = resp.payload else {
        panic!("wrong response variant, got {:?}", resp.payload)
    };
    assert_eq!(submit.receipt_id, "receipt-ipc-1");
    assert!(!submit.queued_for_retry);
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}
