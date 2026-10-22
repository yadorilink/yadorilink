//! CLI-level reporting tests, following the same "drive a real daemon
//! over the real control socket"
//! pattern as `tests/materialization.rs`. Covers: preview shows the exact
//! payload, export writes JSON without submitting, consent controls
//! persist, prompts can be disabled, and daemon-unavailable behavior is
//! clear (a specific error, not a silent no-op or a generic failure).
#![cfg(unix)]

use std::sync::Arc;

use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;

/// Tests in this file share two process-global env vars
/// (`YADORILINK_CONFIG_DIR`, `YADORILINK_CONTROL_SOCKET`) and so must not
/// run concurrently with each other (same convention as
/// `materialization.rs`'s `TEST_MUTEX`).
static TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn start_daemon() -> (tempfile::TempDir, Arc<DaemonState>) {
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
    let store = Arc::new(SegmentBlockStore::new(dir.path().join("blocks")).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open(dir.path().join("sync.sqlite3")).unwrap());
    let state = DaemonState::new("device-under-test".into(), sync_state, store);

    let socket_path = dir.path().join("daemon.sock");
    std::env::set_var("YADORILINK_CONTROL_SOCKET", &socket_path);

    let serve_path = socket_path.clone();
    let serve_context = std::sync::Arc::new(
        yadorilink_daemon::control_context::ControlContext::from_state(state.clone()),
    );
    tokio::spawn(async move {
        let _ =
            yadorilink_daemon::control_socket::unix_transport::serve(&serve_path, serve_context)
                .await;
    });
    yadorilink_daemon::control_socket::unix_transport::wait_until_bound(&socket_path).await;
    (dir, state)
}

/// Points both env vars at a fresh, empty directory/socket path with
/// nothing listening — `daemon_available` sees a real connection
/// failure, exactly like a machine where the daemon was never started.
fn point_at_unreachable_daemon() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
    std::env::set_var("YADORILINK_CONTROL_SOCKET", dir.path().join("no-daemon-here.sock"));
    dir
}

/// the JSON `report usage --preview`
/// would print is byte-identical to what the daemon's
/// `GenerateUsageReport` IPC call returns — proven here by generating it
/// the same way `commands::report::usage` does (via the daemon) and
/// checking it parses back to a valid, schema-consistent envelope with
/// the counters we seeded.
#[tokio::test]
async fn usage_preview_reflects_seeded_counters_exactly() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state) = start_daemon().await;
    state.reporting.note_command_category("link");
    state.reporting.note_command_category("link");

    // `commands::report::usage` prints to stdout rather than returning
    // the JSON, so exercise the same underlying IPC call its preview
    // path uses and check the counters round-trip exactly.
    let resp = yadorilink_client_core::daemon::control::send(
        yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload::GenerateUsageReport(
            yadorilink_ipc_proto::daemonctl::GenerateUsageReportRequest {},
        ),
    )
    .await
    .unwrap();
    let Some(
        yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload::GenerateUsageReport(r),
    ) = resp.payload
    else {
        panic!("wrong response variant")
    };
    let envelope = yadorilink_reporting::schema::ReportEnvelope::from_json(&r.report_json).unwrap();
    envelope.validate().unwrap();
    let yadorilink_reporting::schema::ReportPayload::Usage(payload) = envelope.payload else {
        panic!("expected a usage payload")
    };
    assert_eq!(payload.command_category_counts.get("link"), Some(&2));

    // The full command path succeeds and produces the same thing (an
    // end-to-end smoke test of `usage(preview=true,...)`).
    yadorilink_cli::commands::report::usage(true, None).await.unwrap();
}

/// `--export` writes a
/// parseable envelope to disk, and (since `--submit` was not given) never
/// touches the daemon's submission path — checked here by never enabling
/// consent or configuring an endpoint, so any accidental submit attempt
/// would fail loudly rather than silently succeeding.
#[tokio::test]
async fn usage_export_writes_valid_json_and_does_not_submit() {
    let _guard = TEST_MUTEX.lock().await;
    let (dir, _state) = start_daemon().await;
    let export_path = dir.path().join("usage-report.json");

    yadorilink_cli::commands::report::usage(false, Some(export_path.clone())).await.unwrap();

    let contents = std::fs::read_to_string(&export_path).unwrap();
    let envelope = yadorilink_reporting::schema::ReportEnvelope::from_json(&contents).unwrap();
    envelope.validate().unwrap();
    assert_eq!(envelope.report_type, yadorilink_reporting::schema::ReportType::Usage);
}

/// enabling crash/error reporting via the CLI command function is visible
/// in the daemon's own consent store afterward: both automatic error
/// submission and background queue retry are turned on, and an anonymous
/// reporter id is minted. Usage submission stays off (usage is never sent
/// over the network).
#[tokio::test]
async fn consent_enable_persists_in_daemon_state() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state) = start_daemon().await;

    yadorilink_cli::commands::report::consent_enable().await.unwrap();
    let consent = state.reporting.consent_or_default();
    assert!(consent.error_submission_enabled);
    assert!(consent.queue_retry_enabled);
    assert!(!consent.usage_submission_enabled);
    assert!(consent.anonymous_reporter_id.is_some());

    yadorilink_cli::commands::report::consent_disable().await.unwrap();
    assert!(state.reporting.consent_or_default().is_fully_disabled());
}

/// with `prompt_to_report_enabled`
/// turned off, `handle_reportable_error` creates no candidate and (since
/// this is best-effort/local-only either way) still never panics.
#[tokio::test]
async fn reportable_error_hook_creates_no_candidate_when_prompts_are_disabled() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state) = start_daemon().await;

    yadorilink_cli::commands::report::consent_prompts(false).await.unwrap();
    assert!(!state.reporting.consent_or_default().prompt_to_report_enabled);

    let err = yadorilink_cli::error::CliError::Other("synthetic failure for a test".to_string());
    yadorilink_cli::commands::report::handle_reportable_error(&err).await;

    assert!(state.reporting.error_candidates().list().unwrap().is_empty());
}

/// The contrasting case: with prompting on (the default), the same hook
/// creates exactly one local candidate.
#[tokio::test]
async fn reportable_error_hook_creates_a_candidate_when_prompts_are_enabled() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state) = start_daemon().await;

    let err = yadorilink_cli::error::CliError::Other(
        "synthetic failure at /Users/alice/secret".to_string(),
    );
    yadorilink_cli::commands::report::handle_reportable_error(&err).await;

    let candidates = state.reporting.error_candidates().list().unwrap();
    assert_eq!(candidates.len(), 1);
    let envelope =
        state.reporting.error_candidates().show(&candidates[0].report_id).unwrap().unwrap();
    assert!(!envelope.to_json().contains("alice"), "the candidate must already be redacted");
}

/// `report usage --preview`/`--export` still work (providing a limited
/// CLI-only report) even with no daemon running.
#[tokio::test]
async fn daemon_unavailable_usage_preview_still_works() {
    let _guard = TEST_MUTEX.lock().await;
    let _dir = point_at_unreachable_daemon();

    // Limited fallback report generation succeeds even with no daemon.
    yadorilink_cli::commands::report::usage(true, None).await.unwrap();
}

/// Submitting an error report without a daemon is refused with the
/// reporting-specific error, not a generic `DaemonNotRunning`/`Other` —
/// network submission is the one path kept exclusively behind the daemon.
#[tokio::test]
async fn daemon_unavailable_submit_is_refused_clearly() {
    let _guard = TEST_MUTEX.lock().await;
    let _dir = point_at_unreachable_daemon();

    // Capture a local candidate first so `report error --last` finds
    // something to submit and reaches the daemon-required submit gate
    // (rather than failing earlier for lack of a candidate).
    let err = yadorilink_cli::error::CliError::Other("disk full while syncing".to_string());
    yadorilink_cli::commands::report::handle_reportable_error(&err).await;

    let err =
        yadorilink_cli::commands::report::error(None, false, None, true, true).await.unwrap_err();
    assert!(matches!(err, yadorilink_cli::error::CliError::ReportingDaemonRequired(_)));
    assert_eq!(err.exit_code(), 6);
    assert!(err.to_string().contains("daemon"));
}

/// `report error --last` without a daemon and with nothing captured
/// locally yet is also a clear error, not an empty/zeroed report.
#[tokio::test]
async fn daemon_unavailable_error_last_with_nothing_captured_is_clear() {
    let _guard = TEST_MUTEX.lock().await;
    let _dir = point_at_unreachable_daemon();

    let err =
        yadorilink_cli::commands::report::error(None, true, None, false, false).await.unwrap_err();
    assert!(err.to_string().contains("no error candidate"));
}

/// `report error --last` without a daemon, but with a candidate this same
/// CLI process already captured locally (the specific error it just hit),
/// finds it directly.
#[tokio::test]
async fn daemon_unavailable_error_last_finds_a_locally_captured_candidate() {
    let _guard = TEST_MUTEX.lock().await;
    let _dir = point_at_unreachable_daemon();

    let err = yadorilink_cli::error::CliError::Other("disk full while syncing".to_string());
    yadorilink_cli::commands::report::handle_reportable_error(&err).await;

    yadorilink_cli::commands::report::error(None, true, None, false, false).await.unwrap();
}
