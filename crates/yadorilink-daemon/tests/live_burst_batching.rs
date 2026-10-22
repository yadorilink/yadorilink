//! End-to-end test simulating a burst of many small
//! files created together in one linked folder (approximating a `git
//! checkout`/`git gc` touching hundreds of files in `.git/objects/` at
//! once), created via the *live* watcher (after linking), not the
//! initial-scan path already covered by `load_many_small_files.rs`.
//! The peer must end up with an identical, fully-reconciled index,
//! and the pipeline must not choke or produce spurious extra state along
//! the way (debounce coalescing and batched broadcast).

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use support::{real_entry_names, wait_until_with_context};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;

const BURST_FILE_COUNT: usize = 300;

/// A beta-appropriate convergence timeout for this load/smoke test. The
/// original 60s bound was tight
/// enough to time out under real heavy concurrent-agent CPU load on a
/// dev machine despite the sync pipeline itself being correct (confirmed
/// via `git stash` comparison across multiple runs) — this test is
/// classified as a load/performance smoke test (not a tight correctness
/// timing gate), so a generous bound here still catches a genuine hang
/// or regression while tolerating real host oversubscription.
const CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(180);

// Not run in CI: a load/performance smoke test's
// value is in running it many times to build statistical confidence, not
// once per push -- and its real-wall-clock convergence wait makes it
// inherently sensitive to whatever else is contending for the runner's
// CPU at that moment, so a shared CI runner produces failures unrelated
// to any actual regression. Run
// locally with `cargo test -- --ignored`, repeatedly.
#[ignore = "load/performance smoke test -- run locally with --ignored, not in CI"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_burst_of_many_small_files_converges_via_debounced_batching() {
    let coordination_addr = support::start_coordination_server().await;
    let account = support::register_and_login(&coordination_addr, "burst-test@example.com").await;
    let device_a_id = support::register_device(&account, "device-a", [0u8; 32]).await;
    let device_b_id = support::register_device(&account, "device-b", [0u8; 32]).await;

    let group_id = support::create_folder_group(&account, "burst-test-group").await;
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

    // Link *before* creating any files — everything below arrives through
    // the live watcher -> debounce accumulator -> executor pipeline, not
    // the initial-scan path.
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

    // Give the peer session a moment to establish before the burst, so
    // the burst is genuinely observed live rather than racing session
    // setup (a slower but more realistic ordering than firing files
    // before any connection exists).
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The burst itself: as fast as this process can create files,
    // approximating what `git checkout`/`git gc` does to `.git/objects/`.
    let started = Instant::now();
    for i in 0..BURST_FILE_COUNT {
        std::fs::write(
            root_a.path().join(format!("object-{i:04}.bin")),
            format!("blob content {i}"),
        )
        .unwrap();
    }
    let write_elapsed = started.elapsed();

    wait_until_with_context(
        || real_entry_names(root_b.path()).len() >= BURST_FILE_COUNT,
        CONVERGENCE_TIMEOUT,
        || {
            let actual = real_entry_names(root_b.path()).len();
            format!(
                "expected >= {BURST_FILE_COUNT} files in root_b={:?}, found {actual}; \
                 device_b: {}",
                root_b.path(),
                support::daemon_status_summary(&state_b),
            )
        },
    )
    .await;
    let total_elapsed = started.elapsed();
    tracing::info!(
        BURST_FILE_COUNT,
        ?write_elapsed,
        ?total_elapsed,
        "live burst of many small files converged"
    );

    // Every file present, with correct content — no spurious extras, no
    // dropped files despite debounce coalescing and batched broadcast.
    // Counted via real_file_count, not a raw directory entry count: a
    // materialized file's reconstruction goes through chunker.rs's
    // write-to-unique_tmp_path-then-rename pattern, and this test's own
    // wait condition above can legitimately observe the directory at a
    // moment where the last file's `.yadorilink-tmp.<pid>.<n>` sibling is
    // still present alongside its already-renamed final copy (observed
    // as a spurious 301-vs-300 count on this suite's first real Windows
    // CI run) -- that's an implementation detail of the atomic write, not
    // one of the "spurious extras" this assertion means to catch.
    assert_eq!(real_entry_names(root_b.path()).len(), BURST_FILE_COUNT);
    for i in [0, BURST_FILE_COUNT / 2, BURST_FILE_COUNT - 1] {
        assert_eq!(
            std::fs::read_to_string(root_b.path().join(format!("object-{i:04}.bin"))).unwrap(),
            format!("blob content {i}")
        );
    }

    // The device that made the burst also holds a fully-indexed, correct
    // local view — the debounced/batched local pipeline didn't lose or
    // duplicate anything on its own side either.
    assert_eq!(
        state_a.replica_coordinator.file_index_repository().list_files(&group_id).unwrap().len(),
        BURST_FILE_COUNT
    );
    assert_eq!(
        state_b.replica_coordinator.file_index_repository().list_files(&group_id).unwrap().len(),
        BURST_FILE_COUNT
    );

    // Settling: nothing keeps re-triggering after convergence (a runaway
    // self-echo loop would show up as an ever-growing file count).
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(real_entry_names(root_b.path()).len(), BURST_FILE_COUNT);
}
