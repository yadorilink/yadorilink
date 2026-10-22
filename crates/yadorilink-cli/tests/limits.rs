//! Tests `yadorilink limits set`/`limits show` end-to-end against a real
//! daemon over the actual control socket — same pattern as
//! `tests/materialization.rs` (a real `unix_transport::serve` daemon, no
//! coordination-plane/auth setup needed). Verifies side effects on
//! `DaemonState` (`governance_config`, `rate_limiters`) rather than
//! captured stdout, matching this file's established convention.
#![cfg(unix)]

use std::sync::Arc;

use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::StatusRequest;
use yadorilink_local_storage::SegmentBlockStore;

async fn start_daemon() -> (tempfile::TempDir, Arc<DaemonState>) {
    let dir = tempfile::tempdir().unwrap();
    // Isolates this test's governance config (`limits set` writes a real
    // file) from the real host config directory — same env var
    // `device_config::config_dir` already supports, same pattern
    // `yadorilink-daemon/tests/reporting_ipc.rs` established for it.
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

/// Tests in this file share both `YADORILINK_CONTROL_SOCKET` and
/// `YADORILINK_CONFIG_DIR` (process-global env vars) and so must not run
/// concurrently with each other, or with `tests/materialization.rs`/
/// `tests/report.rs` (which share `YADORILINK_CONTROL_SOCKET` too) — but
/// those live in separate integration-test binaries (separate processes),
/// so only tests *within this file* need to coordinate.
static TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `limits set` persists to the daemon's governance config and
/// is reflected by a subsequent `limits show`-equivalent read.
#[tokio::test]
async fn limits_set_persists_and_is_reflected_by_a_subsequent_read() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state) = start_daemon().await;

    yadorilink_cli::commands::limits::set(1_000_000, 2_000_000).await.unwrap();

    let config = state.governance_config.load_or_default();
    assert_eq!(config.upload_limit_bytes_per_sec, 1_000_000);
    assert_eq!(config.download_limit_bytes_per_sec, 2_000_000);

    // `limits show`'s underlying IPC round-trip reflects the same values.
    let resp = yadorilink_client_core::daemon::control::send(ReqPayload::LimitsShow(
        yadorilink_ipc_proto::daemonctl::LimitsShowRequest {},
    ))
    .await
    .unwrap();
    let Some(RespPayload::LimitsShow(shown)) = resp.payload else {
        panic!("expected a LimitsShow response");
    };
    assert_eq!(shown.upload_bytes_per_sec, 1_000_000);
    assert_eq!(shown.download_bytes_per_sec, 2_000_000);
}

/// `status` reports the same configured limits `limits set` just
/// applied — the single source of truth (`governance_config`) backs both
/// surfaces.
#[tokio::test]
async fn limits_set_is_reflected_by_status() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, _state) = start_daemon().await;

    yadorilink_cli::commands::limits::set(500_000, 0).await.unwrap();

    let resp = yadorilink_client_core::daemon::control::send(ReqPayload::Status(StatusRequest {}))
        .await
        .unwrap();
    let Some(RespPayload::Status(status)) = resp.payload else {
        panic!("expected a Status response");
    };
    assert_eq!(status.upload_limit_bytes_per_sec, 500_000);
    assert_eq!(status.download_limit_bytes_per_sec, 0);
}

/// A live daemon picks up a `limits set` change without a
/// restart — the *same* `DaemonState` (never reconstructed) reflects the
/// new rate immediately on its shared `rate_limiters`.
#[tokio::test]
async fn live_daemon_applies_limits_without_restart() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state) = start_daemon().await;

    assert_eq!(state.rate_limiters.upload.rate_bytes_per_sec(), 0, "starts unlimited");

    yadorilink_cli::commands::limits::set(3_000_000, 4_000_000).await.unwrap();

    // No daemon restart between `set` and this assertion — same process,
    // same `Arc<DaemonState>`/`Arc<RateLimiters>` the whole time.
    assert_eq!(state.rate_limiters.upload.rate_bytes_per_sec(), 3_000_000);
    assert_eq!(state.rate_limiters.download.rate_bytes_per_sec(), 4_000_000);
}

/// `status` reports free-space state that reflects the
/// local-storage classification — forced deterministically via a headroom
/// override far larger than any real disk's free space, same technique
/// used throughout this change's other tests.
#[tokio::test]
async fn status_reports_free_space_state_from_local_storage_classification() {
    let _guard = TEST_MUTEX.lock().await;
    let (dir, state) = start_daemon().await;
    let folder = dir.path().join("shared");
    std::fs::create_dir_all(&folder).unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&folder.to_string_lossy(), "group-1")
        .unwrap();

    state.governance_config.set_headroom_override_bytes(Some(u64::MAX / 2)).unwrap();

    let resp = yadorilink_client_core::daemon::control::send(ReqPayload::Status(StatusRequest {}))
        .await
        .unwrap();
    let Some(RespPayload::Status(status)) = resp.payload else {
        panic!("expected a Status response");
    };
    let link_volume = status
        .volumes
        .iter()
        .find(|v| v.path == folder.to_string_lossy())
        .expect("expected a volume entry for the linked folder");
    assert_eq!(link_volume.state, "critical");
}
