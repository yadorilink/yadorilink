//! Tests `yadorilink diagnose preview|export` end-to-end against a real
//! daemon over the actual control socket — same harness pattern as
//! `tests/update.rs`/`tests/limits.rs` (a real `unix_transport::serve`
//! daemon, no coordination-plane/auth setup needed).
#![cfg(unix)]

use std::sync::Arc;

use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;

async fn start_daemon() -> (tempfile::TempDir, Arc<DaemonState>) {
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
    // Mirrors `tests/update.rs::start_daemon`'s own rationale: point the
    // periodic update-check scheduler `DaemonState::new` spawns
    // immediately at a local port nothing listens on, so it fails fast
    // and deterministically instead of depending on real network/DNS
    // behavior in this test.
    std::env::set_var("YADORILINK_UPDATE_MANIFEST_URL", "http://127.0.0.1:1/manifest.json");

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

/// Tests in this file share `YADORILINK_CONTROL_SOCKET`/`YADORILINK_CONFIG_DIR`
/// (process-global env vars) — same coordination discipline as
/// `tests/update.rs`'s own `TEST_MUTEX`.
static TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Spec "Daemon unavailable fallback": with no daemon reachable at all,
/// `diagnose export` must still succeed with the limited CLI-only bundle
/// rather than erroring out — pointing the control socket at a path
/// nothing is listening on is this file's stand-in for "daemon not
/// running" (same technique `tests/update.rs` uses for its own
/// `DaemonNotRunning` case).
#[tokio::test]
async fn diagnose_export_falls_back_to_cli_only_bundle_when_daemon_unreachable() {
    let _guard = TEST_MUTEX.lock().await;
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONTROL_SOCKET", dir.path().join("no-daemon-here.sock"));

    let out_path = dir.path().join("bundle.json");
    yadorilink_cli::commands::diagnose::export(out_path.clone())
        .await
        .expect("export must succeed with the CLI-only fallback, not error out");

    let written = std::fs::read_to_string(&out_path).unwrap();
    let value: serde_json::Value = serde_json::from_str(&written).unwrap();
    assert_eq!(value["daemon"]["reachable"], false);
    assert_eq!(value["daemon"]["collection_mode"], "cli-only-fallback");
}

/// + diagnostics redaction: with a real daemon reachable and
/// a real linked folder registered (a realistic home-directory absolute
/// path and a real group id), `diagnose export`'s daemon-backed path must
/// produce a bundle that (a) is clearly daemon-sourced, not the CLI-only
/// fallback, and (b) never leaks the real path or group id anywhere in
/// the written file — proving the daemon-side assembly
/// (`diagnostics_ipc::build_bundle`) actually applies
/// `yadorilink_reporting`'s redaction helpers end-to-end over the real
/// control-socket IPC round trip, not just in the daemon crate's own unit
/// tests.
#[tokio::test]
async fn diagnose_export_via_daemon_redacts_a_real_linked_folder() {
    let _guard = TEST_MUTEX.lock().await;
    let (dir, state) = start_daemon().await;

    let link_root = dir.path().join("Users").join("alice").join("secret-project");
    std::fs::create_dir_all(&link_root).unwrap();
    let link_path = link_root.to_string_lossy().to_string();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&link_path, "11111111-2222-3333-4444-555555555555")
        .unwrap();

    let out_path = dir.path().join("bundle.json");
    yadorilink_cli::commands::diagnose::export(out_path.clone()).await.unwrap();

    let written = std::fs::read_to_string(&out_path).unwrap();
    assert!(!written.contains("alice"), "real path component leaked into the bundle");
    assert!(!written.contains("secret-project"), "real folder name leaked into the bundle");
    assert!(
        !written.contains("11111111-2222-3333-4444-555555555555"),
        "real group id leaked into the bundle"
    );

    let value: serde_json::Value = serde_json::from_str(&written).unwrap();
    assert_eq!(value["daemon"]["reachable"], true);
    // "daemon" (full) or "daemon-partial" (bounded-timeout fallback, task
    // 2.3) are both legitimate daemon-sourced outcomes; "cli-only-fallback"
    // would mean the daemon path wasn't actually exercised.
    let collection_mode = value["daemon"]["collection_mode"].as_str().unwrap();
    assert_ne!(collection_mode, "cli-only-fallback");
    assert!(value["links"].as_array().unwrap().iter().any(|l| l["link_id"] == "link:001"));
}
