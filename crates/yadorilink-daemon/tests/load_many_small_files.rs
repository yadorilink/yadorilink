//! Load/soak test: a folder tree with many small files must
//! survive initial pairing (full index exchange + per-file block fetch)
//! and a subsequent incremental change, through the full daemon stack
//! (real coordination plane, directly-paired peer sessions, real QUIC).

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use support::{real_entry_names, wait_until_with_context};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;

const FILE_COUNT: usize = 200;

/// Same rationale as `live_burst_batching.rs`'s `CONVERGENCE_TIMEOUT` —
/// this is a
/// load/performance smoke test, not a tight correctness timing gate, so
/// a generous bound tolerates real heavy concurrent-agent CPU load
/// without losing the ability to catch a genuine hang or regression.
const CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(180);
const INCREMENTAL_UPDATE_TIMEOUT: Duration = Duration::from_secs(60);

// Not run in CI -- same rationale as
// live_burst_batching.rs's identically-tagged test: a real-wall-clock
// load/performance smoke test's value comes from running it many times
// locally to build statistical confidence, not gating every CI push on
// a single run's luck against whatever else is contending for that
// runner's CPU. Run locally with `cargo test -- --ignored`, repeatedly.
#[ignore = "load/performance smoke test -- run locally with --ignored, not in CI"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_small_files_survive_initial_sync_and_incremental_update() {
    let _ = tracing_subscriber::fmt::try_init();
    let coordination_addr = support::start_coordination_server().await;
    let account = support::register_and_login(&coordination_addr, "load-test@example.com").await;
    let device_a_id = support::register_device(&account, "device-a", [0u8; 32]).await;
    let device_b_id = support::register_device(&account, "device-b", [0u8; 32]).await;

    let group_id = support::create_folder_group(&account, "load-test-group").await;
    support::grant_access(&account, &group_id, &device_a_id).await;
    support::grant_access(&account, &group_id, &device_b_id).await;

    let store_dir_a = tempfile::tempdir().unwrap();
    let store_a = Arc::new(SegmentBlockStore::new(store_dir_a.path()).unwrap());
    let sync_state_a = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state_a = DaemonState::new(device_a_id.clone(), sync_state_a, store_a);
    // Give the device a change-signing key before its link watch starts, so
    // the change-DAG emitter is wired and local edits actually propagate.
    support::ensure_device_signing_key(&state_a);
    let root_a = tempfile::tempdir().unwrap();

    let store_dir_b = tempfile::tempdir().unwrap();
    let store_b = Arc::new(SegmentBlockStore::new(store_dir_b.path()).unwrap());
    let sync_state_b = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state_b = DaemonState::new(device_b_id.clone(), sync_state_b, store_b);
    support::ensure_device_signing_key(&state_b);
    let root_b = tempfile::tempdir().unwrap();

    // Populate device A's folder with many small files *before* B ever
    // connects, so the initial full index carries all of them at once —
    // exercised via the daemon's own link-runtime pre-existing-file scan (the
    // `sync-engine` spec's "Initial Full Sync" requirement), not just the
    // live watcher.
    for i in 0..FILE_COUNT {
        std::fs::write(
            root_a.path().join(format!("file-{i:04}.txt")),
            format!("content of file {i}"),
        )
        .unwrap();
    }

    let local_path_a = root_a.path().to_string_lossy().to_string();
    state_a.replica_coordinator.link_repository().add_link(&local_path_a, &group_id).unwrap();
    LinkRuntimeController::new(state_a.clone()).start(local_path_a, group_id.clone()).unwrap();
    let local_path_b = root_b.path().to_string_lossy().to_string();
    state_b.replica_coordinator.link_repository().add_link(&local_path_b, &group_id).unwrap();
    LinkRuntimeController::new(state_b.clone())
        .start(local_path_b.clone(), group_id.clone())
        .unwrap();

    support::connect_two_daemons(
        &state_a,
        &device_a_id,
        &state_b,
        &device_b_id,
        std::slice::from_ref(&group_id),
    )
    .await;

    let started = Instant::now();
    wait_until_with_context(
        || real_entry_names(root_b.path()).len() >= FILE_COUNT,
        CONVERGENCE_TIMEOUT,
        || {
            let actual = real_entry_names(root_b.path()).len();
            let indexed_a = state_a.replica_coordinator.file_index_repository().list_files(&group_id).map(|files| files.len());
            let indexed_b = state_b.replica_coordinator.file_index_repository().list_files(&group_id).map(|files| files.len());
            format!(
                "expected >= {FILE_COUNT} files in root_b={:?}, found {actual}; indexed_a={indexed_a:?}, indexed_b={indexed_b:?}; device_a: {}; device_b: {}",
                root_b.path(),
                support::daemon_status_summary(&state_a),
                support::daemon_status_summary(&state_b),
            )
        },
    )
    .await;
    tracing::info!(elapsed = ?started.elapsed(), FILE_COUNT, "initial sync of many small files completed");

    // No spurious extra files (e.g. from the self-echo/conflict-storm bug
    // this test caught during development): exactly FILE_COUNT, nothing more.
    // Counted via real_entry_names, not a raw directory entry count -- see
    // its own doc comment for why a raw count can be transiently inflated
    // by unrelated internal artifacts.
    assert_eq!(real_entry_names(root_b.path()).len(), FILE_COUNT);

    for i in [0, FILE_COUNT / 2, FILE_COUNT - 1] {
        let expected = format!("content of file {i}");
        assert_eq!(
            std::fs::read_to_string(root_b.path().join(format!("file-{i:04}.txt"))).unwrap(),
            expected
        );
    }

    // also covers "incremental sync" under load: one more change
    // after the bulk of files has already synced.
    std::fs::write(root_a.path().join("late-arrival.txt"), b"added after initial sync").unwrap();
    wait_until_with_context(
        || root_b.path().join("late-arrival.txt").exists(),
        INCREMENTAL_UPDATE_TIMEOUT,
        || {
            format!(
                "late-arrival.txt never appeared in root_b={:?}; device_b: {}",
                root_b.path(),
                support::daemon_status_summary(&state_b),
            )
        },
    )
    .await;
    assert_eq!(
        std::fs::read(root_b.path().join("late-arrival.txt")).unwrap(),
        b"added after initial sync"
    );

    // Nothing kept changing after settling — the self-echo suppression
    // fix means a converged folder stays converged (no runaway loop).
    assert_eq!(real_entry_names(root_b.path()).len(), FILE_COUNT + 1);
}
