//! Editing `.yadorilinkignore` must trigger a rescan of the affected link
//! and reconverge with peers, entirely through the already-running
//! daemon — no stop/start restart anywhere in
//! this test. `LinkRuntimeController::start`'s executor task already
//! wires this (confirmed by reading
//! the daemon's own link-runtime task wiring): a debounced flush that
//! touches the ignore file reloads the effective pattern set and forces a
//! full `RescanRequired` reconciliation scan. This test exercises that path
//! end-to-end via the real OS-level watcher (not a direct call into
//! `local_change`), across two networked devices, the same shape as
//! `live_burst_batching.rs`.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::wait_until;
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn editing_yadorilinkignore_rescans_and_reconverges_without_daemon_restart() {
    let coordination_addr = support::start_coordination_server().await;
    let account =
        support::register_and_login(&coordination_addr, "ignore-rescan@example.com").await;
    let device_a_id = support::register_device(&account, "device-a", [0u8; 32]).await;
    let device_b_id = support::register_device(&account, "device-b", [0u8; 32]).await;

    let group_id = support::create_folder_group(&account, "ignore-rescan-group").await;
    support::grant_access(&account, &group_id, &device_a_id).await;
    support::grant_access(&account, &group_id, &device_b_id).await;

    let store_dir_a = tempfile::tempdir().unwrap();
    let store_a = Arc::new(SegmentBlockStore::new(store_dir_a.path()).unwrap());
    let sync_state_a = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state_a = DaemonState::new(device_a_id.clone(), sync_state_a, store_a);
    // Give the device a change-signing key before its link watch starts, so the
    // change-DAG emitter is wired and local edits actually propagate.
    support::ensure_device_signing_key(&state_a);
    let root_a = tempfile::tempdir().unwrap();

    let store_dir_b = tempfile::tempdir().unwrap();
    let store_b = Arc::new(SegmentBlockStore::new(store_dir_b.path()).unwrap());
    let sync_state_b = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state_b = DaemonState::new(device_b_id.clone(), sync_state_b, store_b);
    // Give the device a change-signing key before its link watch starts, so the
    // change-DAG emitter is wired and local edits actually propagate.
    support::ensure_device_signing_key(&state_b);
    let root_b = tempfile::tempdir().unwrap();

    let local_path_a = root_a.path().to_string_lossy().to_string();
    state_a.replica_coordinator.link_repository().add_link(&local_path_a, &group_id).unwrap();
    LinkRuntimeController::new(state_a.clone()).start(local_path_a, group_id.clone()).unwrap();
    let local_path_b = root_b.path().to_string_lossy().to_string();
    state_b.replica_coordinator.link_repository().add_link(&local_path_b, &group_id).unwrap();
    LinkRuntimeController::new(state_b.clone()).start(local_path_b, group_id.clone()).unwrap();

    support::connect_two_daemons(
        &state_a,
        &device_a_id,
        &state_b,
        &device_b_id,
        std::slice::from_ref(&group_id),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Before any ignore pattern targets it, "build.log" is an entirely
    // ordinary file: created live (through the running watcher, not the
    // initial scan) and synced to device B like anything else.
    std::fs::write(root_a.path().join("keep.txt"), b"keep me").unwrap();
    std::fs::write(root_a.path().join("build.log"), b"noisy build output").unwrap();

    wait_until(|| root_b.path().join("build.log").exists(), Duration::from_secs(15)).await;
    wait_until(|| root_b.path().join("keep.txt").exists(), Duration::from_secs(15)).await;
    assert!(state_a
        .replica_coordinator
        .file_index_repository()
        .get_file(&group_id, "build.log")
        .unwrap()
        .is_some());

    // Edit `.yadorilinkignore` on device A only — device-local, unsynced.
    // No restart: `start_link_watch`'s executor task is still the same
    // one spawned above; `flush_touches_ignore_file` (link_runtime/tasks.rs) is
    // what's expected to notice this write and force a full
    // reconciliation scan with the reloaded pattern set.
    std::fs::write(root_a.path().join(".yadorilinkignore"), "*.log\n").unwrap();

    // the triggered rescan drops "build.log" from device A's own
    // index (dropped, not deleted — the on-disk file is untouched) —
    // this is the observable signal that the rescan actually ran.
    wait_until(
        || {
            state_a
                .replica_coordinator
                .file_index_repository()
                .get_file(&group_id, "build.log")
                .unwrap()
                .is_none()
        },
        Duration::from_secs(15),
    )
    .await;
    assert!(
        root_a.path().join("build.log").exists(),
        "newly-ignored file must be dropped from the index, not deleted from disk"
    );

    // Reconverge, not diverge: no tombstone was produced (nothing to
    // broadcast), so device B's already-synced copy is left untouched —
    // both sides remain internally consistent after the rescan.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(root_b.path().join("build.log").exists());
    let record_b = state_b
        .replica_coordinator
        .file_index_repository()
        .get_file(&group_id, "build.log")
        .unwrap()
        .unwrap();
    assert!(!record_b.deleted, "no tombstone must reach the peer for a newly-ignored file");

    // removing the pattern (editing the ignore file again, still
    // without any daemon restart) must un-ignore "build.log" and let a
    // *newly created* matching file be picked back up by the next
    // triggered rescan.
    std::fs::write(root_a.path().join(".yadorilinkignore"), "").unwrap();
    std::fs::write(root_a.path().join("release-notes.log"), b"now wanted again").unwrap();

    wait_until(|| root_b.path().join("release-notes.log").exists(), Duration::from_secs(15)).await;
    assert_eq!(
        std::fs::read(root_b.path().join("release-notes.log")).unwrap(),
        b"now wanted again"
    );
    assert!(state_a
        .replica_coordinator
        .file_index_repository()
        .get_file(&group_id, "release-notes.log")
        .unwrap()
        .is_some());
}
