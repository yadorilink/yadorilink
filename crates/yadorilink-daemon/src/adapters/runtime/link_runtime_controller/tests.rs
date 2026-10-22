#![cfg(test)]

use super::*;
use crate::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;

fn test_state() -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new("device-a".into(), sync_state, store);
    // A registered device with no signing key fails closed (see
    // `open_group_author`) -- every test using
    // this shared harness needs one wired.
    state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]));
    state
}

fn sample_record(path: &str) -> yadorilink_replica_domain::file::FileRecord {
    yadorilink_replica_domain::file::FileRecord {
        path: path.to_string(),
        size: 10,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    }
}

/// A `FolderWatchSource` whose `watch` always fails — models the OS-level
/// reasons a watcher bind can fail on a perfectly healthy database: the
/// per-user watch limit exhausted on a large tree, an unmounted root, or a
/// permissions error.
struct FailingWatchSource;

impl FolderWatchSource for FailingWatchSource {
    fn watch(
        &self,
        _root: &Path,
        _ignore_set: Arc<EffectiveIgnoreSet>,
    ) -> Result<
        yadorilink_filesystem_sync::watcher::FolderWatcher,
        yadorilink_filesystem_sync::watcher::WatcherError,
    > {
        Err(yadorilink_filesystem_sync::watcher::WatcherError::Io(std::io::Error::other(
            "watch limit reached",
        )))
    }
}

/// When watcher setup fails, the group's gate must exist and be `Failed` —
/// NOT absent. An absent gate reads as Ready (`wait_group_ready` admits a
/// group that never entered startup), so a link whose watcher never bound
/// would admit peer changes into a folder this boot never scanned, letting
/// them overwrite un-indexed local content. The failure is silent at the
/// call site (`app::run` logs and continues), so the gate is the only thing
/// standing between a failed watcher and that overwrite.
#[tokio::test]
async fn failed_watcher_setup_must_fail_the_gate_not_leave_it_absent() {
    let state = test_state();
    let root = tempfile::tempdir().unwrap();
    let controller = LinkRuntimeController::new(state.clone());

    let result = controller.start_with_source(
        root.path().to_string_lossy().into_owned(),
        "g".to_string(),
        Arc::new(FailingWatchSource),
    );
    assert!(result.is_err(), "a failing watch source must surface an error to the caller");

    // The decisive assertion: fail-closed, not fail-open. Before the guard
    // was armed ahead of the fallible setup, `begin_group_startup` was never
    // reached on this path and this returned Ok(()) — the bug.
    let ready = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        state.replica_coordinator.wait_group_ready("g"),
    )
    .await
    .expect("wait_group_ready must resolve, not park forever on a Starting gate");
    assert!(
        ready.is_err(),
        "a link whose watcher failed to bind must DEFER peer apply (Err(StartupFailed)), \
         never admit it as ready"
    );
}

/// A link whose row is already `OnDemand` (e.g. from before the
/// placeholder-pipeline gate existed, or committed by any other path)
/// must refuse to start watching -- the same invariant linking and
/// `set_storage_mode` enforce at *creation* time, applied here to
/// a row that's already on disk, since neither entry point's refusal
/// helps a row that's already committed OnDemand.
#[tokio::test]
async fn an_existing_on_demand_link_refuses_to_start_while_the_pipeline_is_not_connected() {
    let state = test_state();
    let root = tempfile::tempdir().unwrap();
    let local_path = root.path().to_string_lossy().into_owned();
    state.replica_coordinator.link_repository().add_link(&local_path, "g").unwrap();
    state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy(
            &local_path,
            yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
        )
        .unwrap();

    let controller = LinkRuntimeController::new(state.clone());
    let result = controller.start_with_source(
        local_path.clone(),
        "g".to_string(),
        Arc::new(RealFolderWatchSource),
    );

    let error = match result {
        Ok(_) => panic!(
            "an existing OnDemand link must refuse to start while no placeholder pipeline is \
             connected, not silently watch/materialize anyway"
        ),
        Err(error) => error.to_string(),
    };
    assert!(
        error.contains("not a ready provider folder"),
        "the refusal must come from the pipeline gate, not an unrelated failure: {error}"
    );
    assert!(
        !state.links.has_entry(&local_path),
        "a refused start must not leave a zombie Starting/Ready slot behind"
    );
}

#[tokio::test]
async fn resume_refuses_an_orphaned_link() {
    let state = test_state();
    let local_path = "/tmp/photos";
    state.replica_coordinator.link_repository().add_link(local_path, "group-1").unwrap();
    state.replica_coordinator.link_repository().mark_link_orphaned(local_path).unwrap();

    let controller = LinkRuntimeController::new(state.clone());
    let err = controller
        .resume(local_path)
        .await
        .expect_err("an orphaned link must never be re-enabled by Resume");
    assert!(err.to_string().contains("orphaned"), "got {err}");
}

/// Makes every version already in `group_id` look admitted long ago (the
/// epoch), so the retention sweep sees them as beyond the age bound.
fn backdate_admission(state: &DaemonState, group_id: &str) {
    let database = state.replica_coordinator.database();
    let conn = database.pool_for_test().get().unwrap();
    conn.execute(
        "UPDATE files SET admitted_at_unix_nanos = 0 WHERE group_id = ?1",
        rusqlite::params![group_id],
    )
    .unwrap();
}

/// The retention-expiry sweep actually removes aged-out superseded
/// versions under the fixed built-in retention policy — a real, if
/// minimal, end-to-end proof that `DaemonState::new`'s periodic call
/// reaches `SyncState::expire_superseded_and_trashed_versions` correctly.
#[tokio::test]
async fn run_retention_expiry_sweep_removes_aged_out_versions_under_the_fixed_policy() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link("/tmp/photos", "group-1").unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();

    // Thirteen versions: twelve become superseded, one is current.
    // Admission is backdated below, so every superseded row is beyond
    // the age axis; the built-in 10-version count bound then keeps only
    // the ten most recent superseded rows, expiring the two oldest.
    for size in 1..=13u64 {
        let mut record = sample_record("a.jpg");
        record.size = size;
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin("group-1", &record, "device-a", &permit)
            .unwrap();
    }

    assert_eq!(
        state.replica_coordinator.sqlite().dag_list_versions("group-1", "a.jpg").unwrap().len(),
        13
    );

    backdate_admission(&state, "group-1");
    let controller = LinkRuntimeController::new(state.clone());
    controller.run_retention_expiry_sweep();

    let remaining =
        state.replica_coordinator.sqlite().dag_list_versions("group-1", "a.jpg").unwrap();
    assert_eq!(
        remaining.len(),
        11,
        "current version plus the ten most recent superseded ones survive"
    );
}

/// Retention ages a version from the moment it entered this device's
/// history, not from the file's own modification time: a file copied in
/// with an old mtime and edited many times just now keeps all of that
/// fresh history.
#[tokio::test]
async fn run_retention_expiry_sweep_ages_versions_by_admission_not_file_mtime() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link("/tmp/photos", "group-1").unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();

    // `sample_record`'s `mtime_unix_nanos: 0` is far older than the age
    // bound, but every version below was admitted just now.
    for size in 1..=13u64 {
        let mut record = sample_record("a.jpg");
        record.size = size;
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin("group-1", &record, "device-a", &permit)
            .unwrap();
    }

    LinkRuntimeController::new(state.clone()).run_retention_expiry_sweep();

    assert_eq!(
        state.replica_coordinator.sqlite().dag_list_versions("group-1", "a.jpg").unwrap().len(),
        13,
        "recently admitted versions must survive however old the file's mtime is"
    );
}

/// Retention is a version-count cap (`RETENTION_MAX_VERSIONS =
/// 10`) AND an age cap (`RETENTION_MAX_AGE_DAYS = 30`) -- a row is
/// pruned only once it is beyond BOTH. The test above already proves
/// the sweep removes aged-out SUPERSEDED history; this proves the
/// specific boundary that remains: a currently-TRASHED path's history prunes the same way,
/// without disturbing `list_trashed`'s own visibility of it.
///
/// `list_trashed`'s own doc comment is explicit that it always
/// surfaces a currently-deleted path's LATEST trashed version, not
/// every historical one -- which is exactly why that latest version
/// can never itself be the one this sweep prunes (it is always rank
/// 1 among this path's `superseded`/`trashed` rows): only OLDER
/// history goes away, never the entry `list_trashed`/`trash restore`
/// actually needs.
#[tokio::test]
async fn run_retention_expiry_sweep_prunes_old_history_without_disturbing_a_trashed_paths_visibility(
) {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link("/tmp/photos", "group-1").unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();

    // Eleven versions (v1..v11), each admitted long ago (backdated below) -- then a delete, flipping v11
    // from `current` to `trashed` and inserting a fresh tombstone as
    // the path's new `current` row. Ten superseded (v1..v10) + one
    // trashed (v11) = 11 rows in {superseded, trashed}, putting v1
    // (oldest by version_seq) at rank 11, past RETENTION_MAX_VERSIONS.
    for size in 1..=11u64 {
        let mut record = sample_record("gone.jpg");
        record.size = size;
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin("group-1", &record, "device-a", &permit)
            .unwrap();
    }
    state
        .replica_coordinator
        .file_index_repository()
        .mark_deleted("group-1", "gone.jpg", "device-a", &permit)
        .unwrap();

    assert_eq!(
        state.replica_coordinator.sqlite().dag_list_versions("group-1", "gone.jpg").unwrap().len(),
        12,
        "11 upserts plus the delete-created tombstone"
    );
    let trashed =
        state.replica_coordinator.file_index_repository().list_trashed("group-1").unwrap();
    assert_eq!(trashed.len(), 1, "the deleted path must be visible in trash before the sweep");
    assert_eq!(trashed[0].path, "gone.jpg");

    backdate_admission(&state, "group-1");
    let controller = LinkRuntimeController::new(state.clone());
    controller.run_retention_expiry_sweep();

    let remaining =
        state.replica_coordinator.sqlite().dag_list_versions("group-1", "gone.jpg").unwrap();
    assert_eq!(remaining.len(), 11, "exactly the one version beyond the count cap is pruned");
    assert!(
        remaining.iter().all(|v| v.size != 1),
        "specifically the oldest version (size marker 1) must be the one pruned"
    );

    // The still-relevant trash entry itself must be entirely
    // unaffected -- expiry prunes stale HISTORY, never the version
    // `list_trashed`/`trash restore` actually needs.
    let trashed =
        state.replica_coordinator.file_index_repository().list_trashed("group-1").unwrap();
    assert_eq!(trashed.len(), 1, "the trashed path must still be visible after the sweep");
    assert_eq!(trashed[0].path, "gone.jpg");
}

/// A link with no superseded/trashed rows to sweep, or no links at
/// all, is a harmless no-op — the sweep must never error out or panic
/// on an empty/idle daemon.
#[tokio::test]
async fn run_retention_expiry_sweep_is_a_harmless_no_op_with_nothing_to_expire() {
    let state = test_state();
    let controller = LinkRuntimeController::new(state.clone());
    controller.run_retention_expiry_sweep(); // no links registered at all
    state.replica_coordinator.link_repository().add_link("/tmp/photos", "group-1").unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file("group-1", &sample_record("a.jpg"), &permit)
        .unwrap();
    controller.run_retention_expiry_sweep(); // one link, only a current version
    assert_eq!(
        state.replica_coordinator.sqlite().dag_list_versions("group-1", "a.jpg").unwrap().len(),
        1
    );
}

// --- The two-live-roots recovery, at the daemon seam ---------------------

/// Starts a watch the way production does and waits for its initial scan to
/// finish, so the assertion is about what the REAL startup path did rather
/// than about a hand-simulated primitive.
async fn start_watch_and_await_scan(state: &Arc<DaemonState>, root: &Path, group: &str) {
    let controller = LinkRuntimeController::new(state.clone());
    controller
        .start_with_source(
            root.to_string_lossy().into_owned(),
            group.to_string(),
            Arc::new(RealFolderWatchSource),
        )
        .expect("the watch must start");
    // A bound on a hang, not a speed assertion: the backstop-sweep test
    // scans 10,200 directories, which can take well over 10s on a loaded
    // CI runner.
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        state.replica_coordinator.wait_group_ready(group),
    )
    .await
    .expect("the initial scan must finish")
    .expect("the initial scan must succeed");
}

/// THE C15 SEAM, driven through the real watch-start path.
///
/// After a recovery out of the two-live-roots state, the departed root's
/// rows are still in the group's index (`DELETE FROM files` is keyed by
/// path). The survivor's initial scan is root-scoped and authoritative, so
/// unless the additive-scan flag is honoured it reads every one of those
/// paths as deleted and tombstones them to every device -- the remedy
/// deleting the files it was meant to save.
///
/// Deliberately NOT hand-simulated: an earlier test called
/// `suppress_tombstones_for_group` and `scan_existing_files_with_ignore_gated`
/// itself, which meant the ENTIRE daemon wiring could be deleted with
/// "292 passed; 0 failed" -- it exercised the primitives and never the seam
/// that consults them. This one deletes nothing by hand: it starts a watch
/// exactly as `app::run` and the `link` handler do, and only the production
/// read of the flag stands between it and a tombstone.
#[tokio::test]
async fn the_survivors_first_scan_after_a_recovery_emits_no_tombstones() {
    let state = test_state();
    let root = tempfile::tempdir().unwrap();
    let group = "group-1";
    std::fs::write(root.path().join("in-a.txt"), b"aaa").unwrap();

    state
        .replica_coordinator
        .link_repository()
        .add_link(&root.path().to_string_lossy(), group)
        .unwrap();
    // Unlike the other tests sharing `test_state()`, this one pre-seeds
    // the index with rows (below) before the watch starts, so
    // the watch start has indexed rows to author deltas for
    // and genuinely calls into local-emission authorization -- which
    // `DaemonState::new`'s real provider withholds for a linked group
    // with no verified policy loaded (exactly the fail-closed behavior
    // this branch just restored). This test is about tombstone-
    // suppression/duplicate-recovery scan behavior, not policy
    // resolution, so bypass it the same way `index.rs`'s own tests do.
    // Local edits route through `replica_coordinator` exclusively --
    // `DaemonState::new`'s
    // real provider would otherwise withhold exactly as the comment
    // above describes.
    state
        .replica_coordinator
        .set_local_policy_head_provider(std::sync::Arc::new(|_group_id| Ok([0u8; 32])));
    // Both roots' files are captured natively by a first scan: the survivor's
    // own file, and a path that only ever existed under the folder the user
    // just unlinked -- the shape a second root leaves behind.
    std::fs::write(root.path().join("only-in-b.txt"), b"bbb").unwrap();
    let controller = LinkRuntimeController::new(state.clone());
    start_watch_and_await_scan(&state, root.path(), group).await;
    assert!(
        state
            .replica_coordinator
            .file_index_repository()
            .get_file(group, "only-in-b.txt")
            .unwrap()
            .is_some_and(|row| !row.deleted),
        "sanity: the first scan captured the second root's file"
    );
    // The second root departs: its file is gone from this folder, its row stays.
    controller.stop(&root.path().to_string_lossy()).await;
    std::fs::remove_file(root.path().join("only-in-b.txt")).unwrap();

    // Exactly what the unlink handler's recovery arms on the survivor:
    // both the additive-scan flag AND the durable set of paths that must
    // reappear before `duplicate_recovery_pending` will call it resolved
    // (see `control_socket::unlink`'s own pairing of these two calls).
    state.replica_coordinator.link_repository().arm_duplicate_recovery_paths(group).unwrap();
    state
        .replica_coordinator
        .link_repository()
        .set_suppress_tombstones(&root.path().to_string_lossy(), true)
        .unwrap();

    start_watch_and_await_scan(&state, root.path(), group).await;

    let departed = state
        .replica_coordinator
        .file_index_repository()
        .get_file(group, "only-in-b.txt")
        .unwrap()
        .unwrap();
    assert!(
        !departed.deleted,
        "the survivor's first scan after a two-live-roots recovery must delete nothing -- \
         this path can still hydrate from a peer that holds it"
    );
    assert!(
        state.replica_coordinator.link_repository().suppress_tombstones_for_group(group).unwrap(),
        "the gate must remain armed while a live indexed row is still absent from disk"
    );
}

/// Once disk covers the entire live index, ordinary delete propagation can
/// resume. A successful scan alone is insufficient; this converged case
/// pins the stronger clear condition.
#[tokio::test]
async fn a_clean_scan_closes_the_additive_window() {
    let state = test_state();
    let root = tempfile::tempdir().unwrap();
    let group = "group-1";
    std::fs::write(root.path().join("in-a.txt"), b"aaa").unwrap();

    state
        .replica_coordinator
        .link_repository()
        .add_link(&root.path().to_string_lossy(), group)
        .unwrap();
    state
        .replica_coordinator
        .link_repository()
        .set_suppress_tombstones(&root.path().to_string_lossy(), true)
        .unwrap();

    start_watch_and_await_scan(&state, root.path(), group).await;

    assert!(
        !state.replica_coordinator.link_repository().suppress_tombstones_for_group(group).unwrap(),
        "one clean full scan must close the additive window, or ordinary delete propagation \
         is broken for this link forever"
    );
}

/// Sync-root single-instance ownership, driven through
/// the real watch-start/stop path rather than calling
/// `SyncRootLock::acquire` directly: while the watch is running, another
/// attempt to acquire the same root's lock must be refused (a second
/// daemon process pointed at this folder), and once the watch is
/// stopped, that lock must be releasable again (this device re-linking
/// the same folder, or another process taking it over).
#[tokio::test]
async fn starting_a_watch_holds_the_sync_root_lock_until_stopped() {
    let state = test_state();
    let root = tempfile::tempdir().unwrap();
    let group = "group-1";
    std::fs::write(root.path().join("in-a.txt"), b"aaa").unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&root.path().to_string_lossy(), group)
        .unwrap();

    start_watch_and_await_scan(&state, root.path(), group).await;

    let err = yadorilink_root_authority::sync_root_lock::SyncRootLock::acquire(root.path())
        .expect_err("the root must be exclusively owned while its watch is running");
    assert!(err.to_string().contains("already in use"), "unexpected error: {err}");

    let controller = LinkRuntimeController::new(state.clone());
    controller.stop(&root.path().to_string_lossy()).await;

    let _reacquired = yadorilink_root_authority::sync_root_lock::SyncRootLock::acquire(root.path())
        .expect("stopping the watch must release the sync-root lock so it can be re-acquired");
}

/// Unlinking a folder and linking it again straight away, in the same daemon, must not be
/// refused as "already in use": once `stop` has returned the root is free, even when the
/// link is stopped while its initial scan is still running on the blocking pool (aborting
/// the task that awaits the scan does not stop the scan, which still owns the processor and
/// with it the root lease).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stop_returns_only_once_a_running_initial_scan_has_released_the_root() {
    let state = test_state();
    let root = tempfile::tempdir().unwrap();
    let group = "group-707-scan-held";
    std::fs::write(root.path().join("a.txt"), b"aaa").unwrap();
    let path = root.path().to_string_lossy().into_owned();
    state.replica_coordinator.link_repository().add_link(&path, group).unwrap();

    let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let entered_tx = std::sync::Mutex::new(entered_tx);
    let release_rx = std::sync::Mutex::new(release_rx);
    *crate::link_runtime::tasks::INITIAL_SCAN_PROBE.lock().unwrap() = Some(Arc::new(move |g| {
        if g == group {
            entered_tx.lock().unwrap().send(()).unwrap();
            release_rx.lock().unwrap().recv().unwrap();
        }
    }));

    let controller = Arc::new(LinkRuntimeController::new(state.clone()));
    controller
        .start_with_source(path.clone(), group.to_string(), Arc::new(RealFolderWatchSource))
        .expect("the watch must start");
    // The scan is now running on the blocking pool, parked in the probe.
    tokio::task::spawn_blocking(move || entered_rx.recv().unwrap()).await.unwrap();

    let stopping = {
        let controller = controller.clone();
        let path = path.clone();
        tokio::spawn(async move { controller.stop(&path).await })
    };
    let mut stopping = std::pin::pin!(stopping);
    // While the scan owns the root, `stop` must still be waiting for it, not have returned and
    // left a later link to be refused.
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(300), &mut stopping).await.is_err(),
        "stop returned while the initial scan still owned the sync root"
    );
    assert!(
        yadorilink_root_authority::sync_root_lock::SyncRootLock::acquire(root.path()).is_err(),
        "the root must stay owned until the scan has finished"
    );

    release_tx.send(()).unwrap();
    stopping.await.expect("stop must not panic");
    *crate::link_runtime::tasks::INITIAL_SCAN_PROBE.lock().unwrap() = None;

    let _free = yadorilink_root_authority::sync_root_lock::SyncRootLock::acquire(root.path())
        .expect("once stop has returned the root is free to be linked again");
}

/// Control: with the first scan finished, unlinking and linking again repeatedly never finds
/// the root still held.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relinking_right_after_stop_finds_the_sync_root_free() {
    let state = test_state();
    let root = tempfile::tempdir().unwrap();
    let group = "group-707-control";
    for dir in 0..10 {
        let d = root.path().join(format!("d{dir}"));
        std::fs::create_dir_all(&d).unwrap();
        for f in 0..10 {
            std::fs::write(d.join(format!("f{f}.txt")), format!("{dir}-{f}")).unwrap();
        }
    }
    let path = root.path().to_string_lossy().into_owned();
    state.replica_coordinator.link_repository().add_link(&path, group).unwrap();
    let controller = LinkRuntimeController::new(state.clone());
    for round in 0..3 {
        start_watch_and_await_scan(&state, root.path(), group).await;
        controller.stop(&path).await;
        let _free = yadorilink_root_authority::sync_root_lock::SyncRootLock::acquire(root.path())
            .unwrap_or_else(|e| panic!("round {round}: root still held after stop: {e}"));
    }
}

/// Losing the sync-root lock sidecar while the daemon runs is terminal for that link:
/// the repair pass ends (no retry loop, nothing recreated), status says why, and only a
/// relink brings it back.
#[tokio::test]
async fn a_deleted_lock_sidecar_ends_the_links_repair_pass_and_only_relink_restores_it() {
    let state = test_state();
    let root = tempfile::tempdir().unwrap();
    let group = "group-1";
    let path = root.path().to_string_lossy().into_owned();
    std::fs::write(root.path().join("in-a.txt"), b"aaa").unwrap();
    state.replica_coordinator.link_repository().add_link(&path, group).unwrap();
    start_watch_and_await_scan(&state, root.path(), group).await;
    let subscribers_running = state.replica_coordinator.held_path_subscribers();

    let sidecar =
        root.path().join(yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME);
    std::fs::remove_file(&sidecar).unwrap();
    state.replica_coordinator.notify_held_path();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !state.links.is_ownership_lost(&path) {
        assert!(std::time::Instant::now() < deadline, "link never entered OwnershipLost");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    // The repair task has ended: it no longer listens for wakes, however many arrive.
    for _ in 0..100 {
        state.replica_coordinator.notify_held_path();
        tokio::task::yield_now().await;
    }
    assert_eq!(state.replica_coordinator.held_path_subscribers(), subscribers_running - 1);
    // Disk-pressure bookkeeping neither overwrites nor clears the terminal mark.
    state.mark_link_degraded(&path, "disk".into());
    state.clear_link_degraded(&path);
    assert!(state.links.is_ownership_lost(&path));
    assert!(!state.links.mark_ownership_lost(&path, 0), "already terminal: no second transition");
    assert!(!sidecar.exists(), "the sidecar is never recreated automatically");
    assert!(state.links.degraded_due_snapshot(i64::MAX - 1).is_empty(), "never rechecked");
    let info = state.links.degraded_info(&path).unwrap();
    assert_eq!(info.reason, crate::link_registry::OWNERSHIP_LOST_REASON);

    // Relink: stop, start again.
    LinkRuntimeController::new(state.clone()).stop(&path).await;
    start_watch_and_await_scan(&state, root.path(), group).await;
    assert!(!state.links.is_ownership_lost(&path));
    assert!(sidecar.exists());
}

/// HIGH-1 concurrent-stop regression: the control socket spawns one
/// task per connection, so two overlapping `Unlink`s for the same path
/// (a genuine, not hypothetical, shape) both call `stop`.
/// Without `DaemonState::link_watch_stop_locks` serializing them, the
/// second call would find `link_tasks` already emptied by the first
/// and skip waiting entirely, racing ahead to drop the root lock while
/// the first call's own wait (for a still-running task) is still in
/// progress.
///
/// Exercises the serialization primitive directly rather than trying
/// to race a real slow scan (inherently timing-sensitive): pre-holds
/// the per-link stop lock exactly as an in-flight `stop` would,
/// confirms a concurrent second call genuinely blocks on it (not
/// merely "eventually completes", which would also be true if
/// unserialized), then releases and confirms it proceeds.
#[tokio::test]
async fn concurrent_stop_calls_for_the_same_path_are_serialized() {
    let state = test_state();
    let local_path = "/some/link/path".to_string();

    let per_link_lock = state.links.stop_lock(&local_path);
    let held = per_link_lock.lock().await;

    let state_for_task = state.clone();
    let path_for_task = local_path.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let stop_task = tokio::spawn(async move {
        let controller = LinkRuntimeController::new(state_for_task);
        let _ = started_tx.send(());
        controller.stop(&path_for_task).await;
    });
    started_rx.await.unwrap();
    // Give the spawned task every chance to have raced ahead if it
    // were NOT actually serialized -- a generous margin, not a tight
    // race, since this assertion is about "definitely still blocked",
    // not about timing precision.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        !stop_task.is_finished(),
        "a concurrent stop for the same path must block on the held per-link \
         lock, not race ahead while it is held"
    );

    drop(held);
    tokio::time::timeout(std::time::Duration::from_secs(2), stop_task)
        .await
        .expect("stop must proceed once the per-link lock is released")
        .unwrap();
}

/// The per-group refusal at the daemon seam. `start_inner` runs
/// the scan that emits the tombstones, so an ambiguous group must never get
/// a watcher at all -- and the refusal must be scoped to that group, since a
/// per-database halt would brick the daemon for every folder the user has.
#[tokio::test]
async fn an_ambiguous_group_is_refused_a_watcher_while_healthy_groups_still_start() {
    let state = test_state();
    let root_a = tempfile::tempdir().unwrap();
    let root_b = tempfile::tempdir().unwrap();
    let root_c = tempfile::tempdir().unwrap();

    state
        .replica_coordinator
        .link_repository()
        .add_link(&root_a.path().to_string_lossy(), "group-1")
        .unwrap();
    state
        .replica_coordinator
        .link_repository()
        .force_second_live_link_for_test(&root_b.path().to_string_lossy(), "group-1")
        .unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&root_c.path().to_string_lossy(), "group-2")
        .unwrap();

    let controller = LinkRuntimeController::new(state.clone());
    let err = controller
        .start_with_source(
            root_a.path().to_string_lossy().into_owned(),
            "group-1".to_string(),
            Arc::new(RealFolderWatchSource),
        )
        .expect_err("a twice-linked group must not get a watcher: the scan is what deletes");
    assert!(
        format!("{err}").contains("group-1"),
        "the refusal must name the group it is about, got: {err}"
    );

    // The non-negotiable: per-GROUP, never per-DATABASE.
    start_watch_and_await_scan(&state, root_c.path(), "group-2").await;
}

/// The disk-reconcile backstop's per-link operation
/// (`reconcile_added_files_from_disk`) is synchronous and walks the entire
/// linked folder. This pins that the sweep no longer runs it on the worker
/// that polls it.
///
/// Discriminating by construction: the runtime has exactly one worker
/// thread and the sweep runs in a spawned task (not in the test's own
/// `block_on` thread, which is not a worker and would therefore never have
/// held a core to begin with). A second spawned task loops on
/// `tokio::task::yield_now` throughout, counting how many times it gets
/// rescheduled. Run inline, the sweep's task owns the only core from the
/// moment it starts until it returns, and the counter advances zero
/// times for that whole window; offloaded, `block_in_place` hands the
/// core -- and the counter task queued on it -- to a replacement thread
/// before the walk begins, and the count keeps climbing.
///
/// Cooperative rescheduling, not a real-time ticker: an earlier version
/// of this test used a `tokio::time::sleep(1ms)` loop and compared its
/// tick rate against wall-clock elapsed time, which measured this
/// fixture correctly on Linux and macOS but failed on real
/// windows-latest CI runners even when the worker genuinely was freed --
/// confirmed via that failure's own numbers (63 ticks across 675ms,
/// ~10.7ms/tick) that Windows's own timer resolution is coarser than the
/// 1ms this test's old tolerance assumed, not that the offload stopped
/// happening. `yield_now` has no such platform-dependent floor: it is
/// rescheduled the instant the runtime's ready queue reaches it again,
/// bounded only by scheduler overhead, so the offloaded/inline gap stays
/// enormous (thousands of reschedules vs. essentially none) regardless
/// of host OS, CPU speed, or machine load.
///
/// The fixture is directories, not files, deliberately:
/// `local_change.rs`'s own `run_capture_pass_off_worker` covers the
/// per-file chunk/verify passes, which a directory never reaches, so a
/// file-based fixture would measure that offload rather than this one.
///
/// The group has no policy, so the initial scan withholds every directory
/// entry into the dirty journal and the sweep finds all 10,200 of them
/// unindexed. The dirty journal's periodic re-drive must leave those rows
/// alone while the policy is unavailable: re-capturing every one of them on
/// this same single worker would starve the counter whether or not the
/// sweep is offloaded. This test does not wait for a re-drive tick, so it
/// only catches a regression there when a tick lands inside the measured
/// sweep; the deterministic guard for that gate is
/// `redrive_leaves_withheld_paths_untouched_until_the_policy_arrives` in
/// `yadorilink-local-capture`'s `local_change` tests.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn the_disk_reconcile_backstop_sweep_does_not_hold_the_worker_that_polls_it() {
    use std::sync::atomic::{AtomicU64, Ordering};

    let state = test_state();
    let root = tempfile::tempdir().unwrap();
    let group = "group-1";
    for outer in 0..200 {
        let dir = root.path().join(format!("d{outer}"));
        std::fs::create_dir(&dir).unwrap();
        for inner in 0..50 {
            std::fs::create_dir(dir.join(format!("s{inner}"))).unwrap();
        }
    }
    state
        .replica_coordinator
        .link_repository()
        .add_link(&root.path().to_string_lossy(), group)
        .unwrap();
    start_watch_and_await_scan(&state, root.path(), group).await;

    let reschedules = Arc::new(AtomicU64::new(0));
    let counter_started = Arc::new(tokio::sync::Notify::new());
    let counter = {
        let reschedules = reschedules.clone();
        let counter_started = counter_started.clone();
        tokio::spawn(async move {
            counter_started.notify_one();
            loop {
                tokio::task::yield_now().await;
                reschedules.fetch_add(1, Ordering::Relaxed);
            }
        })
    };
    // An explicit signal that the counter task has actually started
    // (rather than a fixed delay guessed to be "surely enough"), so "no
    // reschedules" during the sweep can only mean the worker was held,
    // never that the counter task had not begun running yet.
    counter_started.notified().await;

    let controller = LinkRuntimeController::new(state.clone());
    let before = reschedules.load(Ordering::Relaxed);
    tokio::spawn(async move { controller.run_disk_reconcile_backstop_sweep().await })
        .await
        .expect("the sweep task must not panic");
    let during = reschedules.load(Ordering::Relaxed) - before;
    counter.abort();

    // A generous but still highly discriminating floor: run inline, the
    // counter task cannot be scheduled even once while the sweep holds
    // the only worker (0, plus at most a handful from unavoidable
    // scheduling slop around the spawn boundaries); offloaded, a
    // `yield_now` loop sharing a free worker for the whole multi-
    // hundred-directory walk manages many thousands. 100 sits far above
    // any plausible slop and far below any genuinely offloaded run, with
    // no dependency on wall-clock time at all.
    assert!(
        during > 100,
        "the disk-reconcile backstop's whole-folder walk ran on the worker that polls the \
         sweep: a yield-now loop sharing the runtime's only worker was rescheduled only \
         {during} times while the sweep ran (expected at least 100)"
    );
}

/// Something that still holds the runtime when `stop` removes it (a targeted
/// flush, a File Provider write, a resume or the backstop sweep, each of
/// which clones the `Arc` across long awaits) used to turn `stop` into
/// abort-only teardown: admission was never closed, so the stray operation
/// kept committing after `stop` returned, even after the link was removed.
#[tokio::test]
async fn stop_closes_admission_even_while_something_still_holds_the_runtime() {
    let state = test_state();
    let root = tempfile::tempdir().unwrap();
    let group = "group-1";
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, group).unwrap();
    start_watch_and_await_scan(&state, root.path(), group).await;
    let held = state.links.runtime(&local_path).expect("the link is running");
    let lease = held.root_lease().clone();
    assert!(lease.begin_operation().is_ok(), "sanity: admission is open before the stop");

    let controller = LinkRuntimeController::new(state.clone());
    tokio::time::timeout(std::time::Duration::from_secs(60), controller.stop(&local_path))
        .await
        .expect("stop must return even though the runtime is still held");

    assert!(
        lease.begin_operation().is_err(),
        "an operation begun after stop returned would commit against a link that is gone"
    );
    drop(held);
}

/// An operation already admitted when `stop` runs is waited for, even though
/// the runtime it came through cannot be unwrapped: the root lock is not
/// handed to a new owner under a write still in flight.
#[tokio::test]
async fn stop_waits_for_an_admitted_operation_while_the_runtime_is_still_held() {
    let state = test_state();
    let root = tempfile::tempdir().unwrap();
    let group = "group-1";
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, group).unwrap();
    start_watch_and_await_scan(&state, root.path(), group).await;
    let held = state.links.runtime(&local_path).expect("the link is running");
    let lease = held.root_lease().clone();
    let operation = lease.begin_operation().expect("admitted before the stop");

    let controller = LinkRuntimeController::new(state.clone());
    let stopping = {
        let local_path = local_path.clone();
        tokio::spawn(async move { controller.stop(&local_path).await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let returned_early = stopping.is_finished();
    drop(operation);
    tokio::time::timeout(std::time::Duration::from_secs(60), stopping)
        .await
        .expect("stop returns once the admitted operation finishes")
        .unwrap();

    assert!(!returned_early, "stop returned while an admitted operation was still running");
    drop(held);
}

/// A startup fault that outlasts the immediate attempts used to leave the
/// group's peer-apply gate `Failed` until a relink or restart: nothing
/// re-ran the scan. The executor keeps retrying with backoff for as long as
/// the link runs, so the gate re-opens once the fault clears.
// Multi-threaded on purpose: the executor's live flush loop bridges blocking
// work with `tokio::task::block_in_place`, which panics on a current-thread
// runtime. This test keeps a real watcher alive for seconds, so a filesystem
// event for the folder (macOS FSEvents replays events from just before the
// watch started, e.g. the temp dir's own creation) reaches that loop; on the
// default test flavor it killed the executor and the gate never re-opened.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_startup_fault_that_outlasts_the_immediate_attempts_is_retried_until_it_clears() {
    let state = test_state();
    let root = tempfile::tempdir().unwrap();
    let group = "group-startup-fault";
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, group).unwrap();
    // Five failed attempts: more than the three made back to back.
    crate::link_runtime::tasks::inject_startup_failures(group, 5);

    let controller = LinkRuntimeController::new(state.clone());
    controller
        .start_with_source(local_path.clone(), group.to_string(), Arc::new(RealFolderWatchSource))
        .expect("the watch starts; it is the startup scan that fails");
    let first = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        state.replica_coordinator.wait_group_ready(group),
    )
    .await
    .expect("startup settles");
    assert!(first.is_err(), "sanity: the injected faults fail startup, got {first:?}");

    // Nothing relinks and nothing restarts; the fault simply runs out.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut ready = false;
    while std::time::Instant::now() < deadline {
        if state.replica_coordinator.wait_group_ready(group).await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    assert!(ready, "the gate must re-open once the fault clears, without a relink");
    controller.stop(&local_path).await;
}

/// The backstop used to walk its links one after another, so one link whose
/// whole-folder reconcile stalled held every later link's recovery behind it.
/// Each link's pass now runs on its own: while the first link stalls, the
/// second still gets its pass, and the sweep stops waiting for the stalled
/// one after its time budget instead of holding every later sweep behind it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_link_does_not_hold_the_backstop_pass_of_another_link() {
    let state = test_state();
    let roots = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let paths: Vec<String> =
        roots.iter().map(|root| root.path().to_string_lossy().to_string()).collect();
    for (index, root) in roots.iter().enumerate() {
        let group = format!("backstop-group-{index}");
        state.replica_coordinator.link_repository().add_link(&paths[index], &group).unwrap();
        start_watch_and_await_scan(&state, root.path(), &group).await;
    }

    // Whichever link is reconciled first stalls until released; the other
    // reports that its pass was reached.
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let release_rx = std::sync::Mutex::new(release_rx);
    let (reached_tx, reached_rx) = tokio::sync::oneshot::channel::<String>();
    let reached_tx = std::sync::Mutex::new(Some(reached_tx));
    let stalled: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
    let ours = paths.clone();
    *BACKSTOP_PROBE.lock().unwrap() = Some(Arc::new(move |local_path: &str| {
        if !ours.iter().any(|path| path == local_path) {
            return;
        }
        let first = {
            let mut stalled = stalled.lock().unwrap();
            if stalled.is_none() {
                *stalled = Some(local_path.to_string());
                true
            } else {
                false
            }
        };
        if first {
            let _ = release_rx.lock().unwrap().recv_timeout(std::time::Duration::from_secs(60));
        } else if let Some(tx) = reached_tx.lock().unwrap().take() {
            let _ = tx.send(local_path.to_string());
        }
    }));

    let controller = LinkRuntimeController::new(state.clone());
    let sweep = tokio::spawn(async move { controller.run_disk_reconcile_backstop_sweep().await });
    let reached = tokio::time::timeout(std::time::Duration::from_secs(20), reached_rx).await;
    // The sweep gives up on the stalled link after its budget.
    let returned = tokio::time::timeout(std::time::Duration::from_secs(20), sweep).await;
    release_tx.send(()).unwrap();
    *BACKSTOP_PROBE.lock().unwrap() = None;

    assert!(
        reached.is_ok_and(|reached| reached.is_ok()),
        "the second link's pass never ran while the first link stalled"
    );
    assert!(returned.is_ok(), "one stalled link held the whole sweep");
}

/// A watcher bind refused for lack of OS watches must be visible to
/// `status`/`doctor` (via the registry), not only in the log.
#[tokio::test]
async fn watch_limit_at_startup_is_recorded_for_status() {
    struct LimitedSource;
    impl FolderWatchSource for LimitedSource {
        fn watch(
            &self,
            _root: &Path,
            _ignore_set: Arc<EffectiveIgnoreSet>,
        ) -> Result<
            yadorilink_filesystem_sync::watcher::FolderWatcher,
            yadorilink_filesystem_sync::watcher::WatcherError,
        > {
            Err(notify::Error::new(notify::ErrorKind::MaxFilesWatch).into())
        }
    }

    let state = test_state();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().to_string_lossy().into_owned();
    let controller = LinkRuntimeController::new(state.clone());
    assert!(controller
        .start_with_source(path.clone(), "g".into(), Arc::new(LimitedSource))
        .is_err());

    let reason = state.links.watch_limit_reason(&path).expect("the limit must be recorded");
    assert!(reason.contains("fs.inotify.max_user_watches"), "{reason}");
    assert_eq!(state.links.watch_limited_paths(), vec![path]);
}

/// Any other bind failure is not a watch-limit condition.
#[tokio::test]
async fn other_watcher_failures_are_not_reported_as_the_watch_limit() {
    let state = test_state();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().to_string_lossy().into_owned();
    let controller = LinkRuntimeController::new(state.clone());
    let _ = controller.start_with_source(path.clone(), "g".into(), Arc::new(FailingWatchSource));
    assert!(state.links.watch_limit_reason(&path).is_none());
}

/// A folder linked and running under `state`.
fn running_link(state: &Arc<DaemonState>, group_id: &str) -> (tempfile::TempDir, String) {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().to_string_lossy().into_owned();
    state.replica_coordinator.link_repository().add_link(&path, group_id).unwrap();
    LinkRuntimeController::new(state.clone()).start(path.clone(), group_id.to_string()).unwrap();
    (root, path)
}

/// Tests that install a volume probe hook share one process-wide slot; they take this first.
static VOLUME_HOOK_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn set_volume_probe(hook: Option<VolumeProbeHook>) {
    *VOLUME_PROBE_HOOK.lock().unwrap() = hook;
}

/// A brief outage between two volume passes can latch the root lock as lost
/// while the folder is back by the time the job looks. The job restarts that
/// link instead of leaving it dead until the daemon restarts.
#[tokio::test(flavor = "multi_thread")]
async fn a_running_link_that_lost_its_root_lock_is_restarted_once_available() {
    let state = test_state();
    let (_root, path) = running_link(&state, "g-lost");
    // Holding the old runtime past `stop` keeps its root lock alive, as a scan on the
    // blocking pool does in the field; the restart is then refused as "in use".
    let old = state.links.runtime(&path).unwrap();
    let before = Arc::downgrade(&old);
    assert!(state.mark_link_ownership_lost(&path));

    let controller = LinkRuntimeController::new(state.clone());
    controller.follow_link_volumes().await;
    assert!(state.links.runtime(&path).is_none(), "refused while the old root lock is held");
    assert!(state.links.is_awaiting_volume(&path), "left waiting, not dead");

    drop(old);
    // Shared-runtime stop aborts its tasks without awaiting them, so one may
    // still hold the runtime for a moment.
    let mut waited = 0;
    while before.upgrade().is_some() {
        assert!(waited < 6000, "the old runtime is gone");
        waited += 1;
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    controller.follow_link_volumes().await;

    let after = state.links.runtime(&path).expect("restarted by the next pass");
    assert!(!std::sync::Weak::ptr_eq(&before, &Arc::downgrade(&after)), "a fresh runtime");
    assert!(!state.links.is_ownership_lost(&path));
}

/// A start that ran while the restart's `stop` was awaited leaves a live link;
/// the refused restart must not mark it as waiting for its volume.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_restart_does_not_mark_a_link_started_meanwhile() {
    let state = test_state();
    let (_root, path) = running_link(&state, "g-meanwhile");
    let controller = LinkRuntimeController::new(state.clone());
    controller.wait_unless_started(&path);
    assert!(!state.links.is_awaiting_volume(&path), "a live link is not waiting");
    controller.stop(&path).await;
    controller.wait_unless_started(&path);
    assert!(state.links.is_awaiting_volume(&path), "a stopped link waits");
}

/// A restart refused because a safe stop holds the start gate leaves the link awaiting its
/// volume, and the next volume pass starts it once the gate is open again.
#[tokio::test(flavor = "multi_thread")]
async fn an_away_restart_refused_by_safe_stop_waits_and_restarts_on_the_next_pass() {
    let _hook_slot = VOLUME_HOOK_TESTS.lock().await;
    let state = test_state();
    let (_root, path) = running_link(&state, "g-away-stop");
    let away = path.clone();
    set_volume_probe(Some(Arc::new(move |p| (p == away).then_some(FolderVolume::Away))));
    let gate = LinkRegistry::close_start_gate(&state.links);
    let controller = LinkRuntimeController::new(state.clone());

    controller.follow_link_volumes().await;
    set_volume_probe(None);

    assert!(state.links.runtime(&path).is_none(), "stopped, and the restart was refused");
    assert!(state.links.is_awaiting_volume(&path), "left awaiting its volume");

    drop(gate);
    controller.follow_link_volumes().await;
    assert!(state.links.runtime(&path).is_some(), "restarted by the next volume pass");
}

/// The duplicate-root recovery restarts its survivor through the runtime port; a start refused
/// by a safe stop leaves the survivor awaiting its volume, and the next pass starts it.
#[tokio::test(flavor = "multi_thread")]
async fn a_survivor_start_refused_by_safe_stop_waits_and_restarts_on_the_next_pass() {
    use crate::application::ports::LinkRuntimePort;
    let state = test_state();
    let (_root, path) = running_link(&state, "g-survivor");
    let controller = Arc::new(LinkRuntimeController::new(state.clone()));
    controller.stop(&path).await;
    let adapter =
        crate::adapters::runtime::link_watch::DaemonLinkRuntimeAdapter::new(controller.clone());
    let gate = LinkRegistry::close_start_gate(&state.links);

    assert!(adapter.start_link_watch(path.clone(), "g-survivor".into()).is_err());
    assert!(state.links.is_awaiting_volume(&path), "left awaiting its volume");

    drop(gate);
    controller.follow_link_volumes().await;
    assert!(state.links.runtime(&path).is_some(), "started by the next volume pass");
}

/// One folder whose probe hangs (a dead hard-mounted share) must not hold up
/// the others, and is not probed again while the hung probe is outstanding.
#[tokio::test(flavor = "multi_thread")]
async fn a_hung_volume_probe_does_not_hold_up_other_links() {
    let _hook_slot = VOLUME_HOOK_TESTS.lock().await;
    let state = test_state();
    let (_hung_root, hung) = running_link(&state, "g-hung");
    let back_root = tempfile::tempdir().unwrap();
    let back = back_root.path().to_string_lossy().into_owned();
    state.replica_coordinator.link_repository().add_link(&back, "g-back").unwrap();
    state.links.mark_awaiting_volume(&back);
    let hung_probes = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let (hung_for_hook, probes_for_hook) = (hung.clone(), hung_probes.clone());
    set_volume_probe(Some(Arc::new(move |path| {
        if path == hung_for_hook {
            probes_for_hook.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_secs(12));
            return Some(FolderVolume::Away);
        }
        None
    })));

    let controller = LinkRuntimeController::new(state.clone());
    let started = std::time::Instant::now();
    controller.follow_link_volumes().await;
    controller.follow_link_volumes().await;
    let elapsed = started.elapsed();
    set_volume_probe(None);

    assert!(
        elapsed < std::time::Duration::from_secs(11),
        "the job waited for the hung probe: {elapsed:?}"
    );
    assert!(state.links.runtime(&back).is_some(), "the other folder must still be started");
    assert!(state.links.runtime(&hung).is_some(), "an unanswered probe changes nothing");
    assert_eq!(hung_probes.load(std::sync::atomic::Ordering::SeqCst), 1, "no stacked probe");
}

/// When a folder's volume cannot be told (the link table or the volume could
/// not be read), a healthy running link is left alone.
#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_volume_state_leaves_a_running_link_alone() {
    let _hook_slot = VOLUME_HOOK_TESTS.lock().await;
    let state = test_state();
    let (_root, path) = running_link(&state, "g-unknown");
    let before = state.links.runtime(&path).unwrap();
    let probed = path.clone();
    set_volume_probe(Some(Arc::new(move |p| (p == probed).then_some(FolderVolume::Unknown))));

    LinkRuntimeController::new(state.clone()).follow_link_volumes().await;
    set_volume_probe(None);

    let after = state.links.runtime(&path).expect("still running");
    assert!(Arc::ptr_eq(&before, &after), "not stopped or restarted");
}

/// An unlinked folder is no longer waiting for its volume.
#[tokio::test(flavor = "multi_thread")]
async fn stopping_a_link_clears_its_wait_for_the_volume() {
    let state = test_state();
    let path = tempfile::tempdir().unwrap().path().to_string_lossy().into_owned();
    state.links.mark_awaiting_volume(&path);

    LinkRuntimeController::new(state.clone()).stop(&path).await;

    assert!(!state.links.is_awaiting_volume(&path));
}

/// A re-adoption is the user's word about one folder's disk: it lands only on
/// the live link of that group at that path, never on one that was unlinked or
/// linked elsewhere while the disk was being looked at.
#[tokio::test(flavor = "multi_thread")]
async fn a_volume_confirmation_lands_only_on_the_link_it_was_made_for() {
    let state = test_state();
    // Linked but not started: a running link's first scan would record its own.
    let root = tempfile::tempdir().unwrap();
    let path = root.path().to_string_lossy().into_owned();
    let links = state.replica_coordinator.link_repository();
    links.add_link(&path, "g-confirm").unwrap();

    assert!(!links.confirm_capture_volume_identity("/elsewhere", "g-confirm", "uuid:a").unwrap());
    assert!(!links.confirm_capture_volume_identity(&path, "g-other", "uuid:a").unwrap());
    assert_eq!(links.capture_volume_identity_for_path(&path).unwrap(), None);

    assert!(links.confirm_capture_volume_identity(&path, "g-confirm", "uuid:a").unwrap());
    assert_eq!(links.capture_volume_identity_for_path(&path).unwrap().as_deref(), Some("uuid:a"));

    let missing = LinkRuntimeController::new(state.clone()).readopt_volume("/elsewhere").await;
    assert!(missing.is_err(), "{missing:?}");
}
