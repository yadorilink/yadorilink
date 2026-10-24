//! Tests `yadorilink update status|check|install|config` end-to-end
//! against a real daemon over the actual control socket — same pattern
//! as `tests/limits.rs` (a real `unix_transport::serve` daemon, no
//! coordination-plane/auth setup needed).
#![cfg(unix)]

use std::sync::Arc;

use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_daemon::update::policy::UpdateState;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::UpdateStatusRequest;
use yadorilink_local_storage::SegmentBlockStore;

async fn start_daemon() -> (tempfile::TempDir, Arc<DaemonState>) {
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
    // `DaemonState::new` spawns the periodic update-check scheduler immediately. The manifest
    // URL is an explicit setting of the engine: a local port nothing listens on fails fast and
    // deterministically (connection refused) instead of reaching the production manifest.
    let tuning = yadorilink_daemon::engine_tuning::EngineTuning {
        update_manifest_url: Some("http://127.0.0.1:1/manifest.json".into()),
        witness: yadorilink_daemon::install_witness::WitnessPlacement::BesideDatabase,
        ..Default::default()
    };

    let store = Arc::new(SegmentBlockStore::new(dir.path().join("blocks")).unwrap());
    let sync_state =
        Arc::new(ReplicaCoordinator::open_with(dir.path().join("sync.sqlite3"), tuning).unwrap());
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

/// Tests in this file share `YADORILINK_CONTROL_SOCKET`/`YADORILINK_CONFIG_DIR`
/// (process-global env vars) — same coordination discipline as
/// `tests/limits.rs`'s own `TEST_MUTEX`.
static TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// "Update commands handle daemon-not-running": pointing the control
/// socket at a path nothing is listening on must fail clearly as
/// `DaemonNotRunning`, not hang or panic.
#[tokio::test]
async fn update_status_reports_daemon_not_running_clearly() {
    let _guard = TEST_MUTEX.lock().await;
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONTROL_SOCKET", dir.path().join("no-daemon-here.sock"));

    let result = yadorilink_cli::commands::update::status().await;
    let err = result.expect_err("expected an error with no daemon listening");
    assert_eq!(err.exit_code(), yadorilink_cli::error::CliError::DaemonNotRunning.exit_code());
}

/// "No-update" case: a freshly-started daemon reports the documented
/// safe defaults (checks enabled, manual install, no available version)
/// via the real IPC round trip. Deliberately does *not* assert
/// `state == "idle"`: `DaemonState::new` spawns the periodic update-check
/// scheduler immediately (it checks at daemon startup), and this test's
/// daemon's manifest URL points at a local port nothing listens on,
/// so by the time this reads status the startup check has usually
/// already run and failed fast (connection refused) --
/// `state` can legitimately be `"checking"` or `"failed"` depending on
/// exactly how far that race got, and either is correct behavior, not a
/// bug this test should pin down.
#[tokio::test]
async fn update_status_reflects_fresh_daemon_defaults() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, _state) = start_daemon().await;

    let resp = yadorilink_client_core::daemon::control::send(ReqPayload::UpdateStatus(
        UpdateStatusRequest {},
    ))
    .await
    .unwrap();
    let Some(RespPayload::UpdateStatus(status)) = resp.payload else {
        panic!("expected an UpdateStatus response");
    };
    assert!(status.automatic_checks_enabled);
    assert!(status.available_version.is_empty(), "no update should ever appear out of nowhere");
}

/// "update-available"/"held-back"/"failed" cases: `yadorilink
/// status`'s embedded update fields and `update status`'s own response
/// reflect whatever the daemon's update policy currently records --
/// directly manipulated here (mirrors `tests/limits.rs`'s own
/// `state.governance_config.set_headroom_override_bytes` technique) since
/// exercising a *real* signed manifest fetch/rollout end-to-end belongs to
/// `yadorilink-daemon`'s own manifest/manager unit tests, not this CLI
/// wiring test.
#[tokio::test]
async fn update_status_reflects_an_available_held_back_update() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state) = start_daemon().await;

    state
        .update_manager
        .policy
        .update(|p| {
            p.state = UpdateState::HeldBack;
            p.available_version = Some("0.2.0".into());
            p.holdback_reason = Some("staged rollout at 10%".into());
        })
        .unwrap();

    let resp = yadorilink_client_core::daemon::control::send(ReqPayload::UpdateStatus(
        UpdateStatusRequest {},
    ))
    .await
    .unwrap();
    let Some(RespPayload::UpdateStatus(status)) = resp.payload else {
        panic!("expected an UpdateStatus response");
    };
    assert_eq!(status.state, "held_back");
    assert_eq!(status.available_version, "0.2.0");
    assert_eq!(status.holdback_reason, "staged rollout at 10%");

    // `yadorilink status`'s embedded fields reflect the exact same state.
    let status_resp = yadorilink_client_core::daemon::control::send(ReqPayload::Status(
        yadorilink_ipc_proto::daemonctl::StatusRequest {},
    ))
    .await
    .unwrap();
    let Some(RespPayload::Status(status)) = status_resp.payload else {
        panic!("expected a Status response");
    };
    assert_eq!(status.update_state, "held_back");
    assert_eq!(status.update_available_version, "0.2.0");
    assert_eq!(status.update_holdback_reason, "staged rollout at 10%");
}

/// case.
#[tokio::test]
async fn update_status_reflects_a_failed_check() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state) = start_daemon().await;

    state
        .update_manager
        .policy
        .update(|p| {
            p.state = UpdateState::Failed;
            p.last_error_category = Some("update_manifest_fetch_failed".into());
            p.last_error_message = Some("connection refused".into());
        })
        .unwrap();

    let resp = yadorilink_client_core::daemon::control::send(ReqPayload::UpdateStatus(
        UpdateStatusRequest {},
    ))
    .await
    .unwrap();
    let Some(RespPayload::UpdateStatus(status)) = resp.payload else {
        panic!("expected an UpdateStatus response");
    };
    assert_eq!(status.state, "failed");
    assert_eq!(status.last_error_category, "update_manifest_fetch_failed");
}

/// `update config` persists and is reflected by a
/// subsequent `update status` read, without a daemon restart.
#[tokio::test]
async fn update_config_persists_and_is_reflected_by_status() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state) = start_daemon().await;

    yadorilink_cli::commands::update::config(Some("off".into())).await.unwrap();

    let policy = state.update_manager.policy.load().unwrap();
    assert!(!policy.automatic_checks_enabled);

    let resp = yadorilink_client_core::daemon::control::send(ReqPayload::UpdateStatus(
        UpdateStatusRequest {},
    ))
    .await
    .unwrap();
    let Some(RespPayload::UpdateStatus(status)) = resp.payload else {
        panic!("expected an UpdateStatus response");
    };
    assert!(!status.automatic_checks_enabled);
}

/// v1 ships manual updates: `update download` round-trips to the daemon
/// and succeeds, printing where to get the new version.
#[tokio::test]
async fn update_download_prints_guidance_without_installing() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state) = start_daemon().await;

    let before = state.update_manager.policy.load_or_default().state;
    yadorilink_cli::commands::update::download().await.unwrap();

    let resp = yadorilink_client_core::ops::updates::download_guidance().await.unwrap();
    assert_eq!(resp.outcome, "manual_download");
    assert!(
        resp.guidance.contains("github.com/yadorilink/yadorilink/releases"),
        "{}",
        resp.guidance
    );
    assert_eq!(
        state.update_manager.policy.load_or_default().state,
        before,
        "the download request must not change update state"
    );
}

/// The command line's own table of updaters (`ownership::updater_elsewhere`) and the guidance the
/// daemon gives must say the same thing, so a refusal never contradicts `update status`.
#[test]
fn the_refusal_and_the_daemons_guidance_name_the_same_updater_action() {
    for source in ["app_bundle", "microsoft_store", "homebrew", "apt", "winget", "container"] {
        let how = yadorilink_local_storage::ownership::updater_elsewhere(source).unwrap();
        let guidance = yadorilink_daemon::update::install_source::manual_update_guidance(source);
        assert!(guidance.contains(how), "{source}: {guidance:?} lacks {how:?}");
    }
}

/// `self-update --version X` fails closed: a daemon that cannot obtain a verified channel
/// manifest (here: nothing listens at the manifest URL) refuses the pinned install, which the
/// CLI turns into exit 4 with nothing downloaded.
#[tokio::test]
async fn a_pinned_install_is_refused_when_the_daemon_has_no_verified_manifest() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, _state) = start_daemon().await;

    let check = yadorilink_client_core::ops::updates::check_version("pinned_install", "1.0.0")
        .await
        .expect("the daemon answers");
    assert!(!check.allowed, "an unverifiable manifest must refuse: {check:?}");
    assert!(!check.reason.is_empty());
    let err = yadorilink_cli::commands::update::refuse_unless_allowed(&check, "1.0.0")
        .expect_err("refused");
    assert_eq!(err.exit_code(), 4);
}
