#![cfg(test)]

use std::sync::Arc;

use crate::replica_coordinator::ReplicaCoordinator;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_reporting::builder::{build_usage_envelope, ReportEnvironment};
use yadorilink_reporting::schema::{OsFamily, UsagePayload};
use yadorilink_reporting::submission::{SubmissionClient, SubmissionConfig};

use super::*;

/// `YADORILINK_CONFIG_DIR` is a process-global env var (same pattern as
/// `yadorilink-cli`'s `tests/materialization.rs`'s `YADORILINK_CONTROL_SOCKET`
/// use), so every test in this module that sets it must hold this
/// mutex for its whole body. Shared with `daemon_state.rs` and
/// `device_config.rs` (see `crate::test_support`'s doc comment) — a
/// module-local mutex here alone does not serialize against those
/// other modules' own tests touching the same env var.
use crate::test_support::CONFIG_ENV_MUTEX as TEST_MUTEX;

async fn test_state() -> (tempfile::TempDir, Arc<DaemonState>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(dir.path().join("blocks")).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open(dir.path().join("sync.sqlite3")).unwrap());
    std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
    let state = DaemonState::new("device-under-test".into(), sync_state, store);
    (dir, state)
}

fn sample_envelope() -> yadorilink_reporting::schema::ReportEnvelope {
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

fn fast_client() -> SubmissionClient {
    SubmissionClient::new(SubmissionConfig {
        timeout: std::time::Duration::from_secs(5),
        min_submit_interval: std::time::Duration::from_millis(0),
    })
    .unwrap()
}

/// The core "no network submission when consent is disabled" proof
/// for the retry path — a real local HTTP listener (`wiremock`) with
/// no mock registered, so a request would 404 if it arrived, and
/// `queue_retry_enabled: false` (the default). Asserts zero requests
/// reached the endpoint, not just an assertion on internal state.
#[tokio::test]
async fn retry_sweep_makes_no_network_call_when_queue_retry_consent_is_disabled() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state) = test_state().await;
    let server = MockServer::start().await;
    state.reporting.consent().opt_in_usage().unwrap(); // usage submission on...
    state
        .reporting
        .consent()
        .set_endpoint_override(Some(format!("{}/reports", server.uri())))
        .unwrap();
    // ...but queue_retry_enabled is still false (never set) — the gate
    // this test exists to prove.
    state.reporting.queue().enqueue(sample_envelope()).unwrap();

    let client = fast_client();
    let outcome = run_retry_sweep_once(&state, &client).await;

    assert!(outcome.skipped_by_consent_gate);
    assert_eq!(outcome.attempted, 0);
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "no request should reach the endpoint while queue_retry_enabled is false"
    );
    assert_eq!(state.reporting.queue().list().unwrap().len(), 1, "entry remains queued");
}

/// Same as above, but with `queue_retry_enabled` on and no endpoint
/// configured — still zero requests, since "no endpoint" must be free
/// (mirrors `yadorilink-reporting::submission`'s own test for the
/// same behavior).
#[tokio::test]
async fn retry_sweep_makes_no_network_call_when_no_endpoint_is_configured() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state) = test_state().await;
    let server = MockServer::start().await;
    state.reporting.consent().opt_in_usage().unwrap();
    state.reporting.consent().set_queue_retry_enabled(true).unwrap();
    state.reporting.queue().enqueue(sample_envelope()).unwrap();

    let client = fast_client();
    let outcome = run_retry_sweep_once(&state, &client).await;

    assert!(outcome.skipped_by_consent_gate);
    assert!(server.received_requests().await.unwrap().is_empty());
}

/// The positive path: consent fully enabled, a reachable endpoint —
/// the queued report is submitted and removed from the queue.
#[tokio::test]
async fn retry_sweep_submits_and_clears_a_queued_report_when_fully_consented() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state) = test_state().await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/reports"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "receipt_id": "receipt-xyz",
            "submitted_at": "2026-01-01T00:00:05Z",
        })))
        .mount(&server)
        .await;

    state.reporting.consent().opt_in_usage().unwrap();
    state.reporting.consent().set_queue_retry_enabled(true).unwrap();
    state
        .reporting
        .consent()
        .set_endpoint_override(Some(format!("{}/reports", server.uri())))
        .unwrap();
    state.reporting.queue().enqueue(sample_envelope()).unwrap();

    let client = fast_client();
    let outcome = run_retry_sweep_once(&state, &client).await;

    assert!(!outcome.skipped_by_consent_gate);
    assert_eq!(outcome.attempted, 1);
    assert_eq!(outcome.submitted, 1);
    assert!(state.reporting.queue().list().unwrap().is_empty());
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

/// An entry already at the automatic-retry cap is skipped entirely —
/// no network call, no further attempt-count bump.
#[tokio::test]
async fn retry_sweep_skips_entries_already_at_the_attempt_cap() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state) = test_state().await;
    let server = MockServer::start().await;
    state.reporting.consent().opt_in_usage().unwrap();
    state.reporting.consent().set_queue_retry_enabled(true).unwrap();
    state
        .reporting
        .consent()
        .set_endpoint_override(Some(format!("{}/reports", server.uri())))
        .unwrap();
    let meta = state.reporting.queue().enqueue(sample_envelope()).unwrap();
    for _ in 0..MAX_AUTOMATIC_RETRY_ATTEMPTS {
        state.reporting.queue().increment_submit_attempts(&meta.report_id).unwrap();
    }

    let client = fast_client();
    let outcome = run_retry_sweep_once(&state, &client).await;

    assert_eq!(outcome.attempted, 0);
    assert!(server.received_requests().await.unwrap().is_empty());
}
