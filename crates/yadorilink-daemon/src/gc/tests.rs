#![cfg(test)]

use std::collections::HashSet;
use std::sync::{Condvar, Mutex};

use crate::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::{BlockStore, ContentHash, SegmentBlockStore, StorageError};
use yadorilink_replica_domain::file::{BlockInfo, FileRecord};

use super::*;

/// Returns the `TempDir` guard alongside the state — must stay alive
/// for the whole test (real sweep/usage tests in this module do
/// genuine filesystem I/O against the block store's root), unlike a
/// helper that drops it before returning, which would delete the root
/// directory out from under a later `SegmentBlockStore` operation.
fn test_state() -> (Arc<DaemonState>, tempfile::TempDir) {
    let store_dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap().with_volume_verdict(|_| true));
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    (DaemonState::new("device-a".into(), sync_state, store), store_dir)
}

/// A state whose block store sits on a volume that is not known durable (Windows: unsupported or
/// unknown): every physical deletion must be refused.
fn refused_volume_state() -> (Arc<DaemonState>, tempfile::TempDir) {
    let store_dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap().with_volume_verdict(|_| false));
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    (DaemonState::new("device-a".into(), sync_state, store), store_dir)
}

#[tokio::test]
async fn a_manual_gc_on_a_refused_volume_deletes_nothing() {
    let (state, _dir) = refused_volume_state();
    let hash = state.block_store.put(b"orphaned block, never referenced").unwrap();
    let future_cutoff = SystemTime::now() + Duration::from_secs(1);

    let refused = run_sweep_with_grace_cutoff(state.clone(), false, future_cutoff).await;

    let Err(GcTriggerError::Failed(message)) = refused else { panic!("expected a refusal") };
    assert!(message.contains("deletion refused"), "{message}");
    assert!(state.block_store.exists(&hash).unwrap());
    assert_eq!(state.gc.last_run_unix(), 0);
    // A dry run only reports.
    let dry = run_sweep_with_grace_cutoff(state.clone(), true, future_cutoff).await.unwrap();
    assert_eq!(dry.blocks_deleted, 1);
}

#[tokio::test]
async fn an_idle_gc_on_a_refused_volume_deletes_nothing() {
    let (state, _dir) = refused_volume_state();
    let held = state.block_store.put(b"the only copy of a dropped version").unwrap();
    let loose = state.block_store.put(b"referenced by nothing at all").unwrap();
    hold_with_a_recovery_item(&state, &held);
    let future_cutoff = SystemTime::now() + Duration::from_secs(1);

    let refused = run_idle_sweep_with_grace_cutoff(state.clone(), future_cutoff).await;

    let Err(GcTriggerError::Failed(message)) = refused else { panic!("expected a refusal") };
    assert!(message.contains("deletion refused"), "{message}");
    assert!(state.block_store.exists(&loose).unwrap(), "an unreferenced block stays too");
    assert!(state.block_store.exists(&held).unwrap());
    assert_eq!(state.gc.last_run_unix(), 0);
}

fn hold_with_a_recovery_item(state: &DaemonState, held: &str) {
    state
        .replica_coordinator
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            conn.execute(
                "INSERT INTO native_recovery_item \
                 (group_id, item_id, kind, path, author_device, author_incarnation, seq, \
                  provenance, version_hash, content, size, content_sha256, retained_blocks, \
                  source_recovery_id, created_at) \
                 VALUES ('group-a', ?1, 'remote_only', 'gone.txt', 'device-b', ?2, 1, ?3, ?4, \
                         'unavailable', 0, ?5, ?6, 'recovery', 0)",
                rusqlite::params![
                    "a".repeat(64),
                    vec![0u8; 16],
                    vec![1u8; 32],
                    vec![2u8; 32],
                    vec![3u8; 32],
                    serde_json::to_string(&[held]).unwrap(),
                ],
            )?;
            Ok(())
        })
        .unwrap();
}

struct BarrierBlockStore {
    inner: SegmentBlockStore,
    sweep_started: std::sync::mpsc::SyncSender<()>,
    sweep_release: Arc<(Mutex<bool>, Condvar)>,
}

impl BlockStore for BarrierBlockStore {
    fn put(&self, data: &[u8]) -> Result<ContentHash, StorageError> {
        self.inner.put(data)
    }

    fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        self.inner.get(hash)
    }

    fn delete(&self, hash: &str) -> Result<(), StorageError> {
        self.inner.delete(hash)
    }

    fn exists(&self, hash: &str) -> Result<bool, StorageError> {
        self.inner.exists(hash)
    }

    fn list_by_prefix(&self, prefix: &str) -> Result<Vec<ContentHash>, StorageError> {
        self.inner.list_by_prefix(prefix)
    }

    fn sweep(
        &self,
        live: &HashSet<ContentHash>,
        grace_cutoff: SystemTime,
        dry_run: bool,
    ) -> Result<GcReport, StorageError> {
        self.sweep_started.send(()).unwrap();
        let (released, wake) = &*self.sweep_release;
        let mut released = released.lock().unwrap();
        while !*released {
            released = wake.wait(released).unwrap();
        }
        self.inner.sweep(live, grace_cutoff, dry_run)
    }

    fn reclaim_cached_blocks(&self, hashes: &[ContentHash]) -> Result<GcReport, StorageError> {
        self.sweep_started.send(()).unwrap();
        let (released, wake) = &*self.sweep_release;
        let mut released = released.lock().unwrap();
        while !*released {
            released = wake.wait(released).unwrap();
        }
        self.inner.reclaim_cached_blocks(hashes)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn eviction_without_custody_confirmation_never_reaches_physical_reclaim() {
    use yadorilink_filesystem_sync::materialization_eviction::{
        evict_file, MaterializationContext,
    };
    use yadorilink_replica_domain::file::VersionBlock;
    use yadorilink_replica_domain::ids::VersionHash;

    let store_dir = tempfile::tempdir().unwrap();
    let (reclaim_started_tx, reclaim_started_rx) = std::sync::mpsc::sync_channel(1);
    let store = Arc::new(BarrierBlockStore {
        inner: SegmentBlockStore::new(store_dir.path()).unwrap().with_volume_verdict(|_| true),
        sweep_started: reclaim_started_tx,
        sweep_release: Arc::new((Mutex::new(false), Condvar::new())),
    });
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let materialized_root = tempfile::tempdir().unwrap();
    // `evict_file` now verifies the root's adopted identity before
    // touching it; a real link row is required so the token it writes
    // actually persists (see `materialization.rs`'s own `adopt_root`
    // test helper doc for why -- `set_link_root_token_for_group` is a
    // no-op `UPDATE` without one).
    sync_state
        .link_repository()
        .add_link(&materialized_root.path().to_string_lossy(), "group-a")
        .unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        materialized_root.path(),
        "group-a",
        sync_state.as_ref(),
    )
    .unwrap();
    let state = DaemonState::new("device-a".into(), sync_state, store);
    let bytes = b"shared block adopted during eviction";
    std::fs::write(materialized_root.path().join("evicted.txt"), bytes).unwrap();
    let hash = state.block_store.put(bytes).unwrap();
    let block =
        BlockInfo { hash: hex::decode(&hash).unwrap(), offset: 0, size: bytes.len() as u32 };
    let target = FileRecord {
        path: "evicted.txt".into(),
        size: bytes.len() as u64,
        mtime_unix_nanos: 0,
        blocks: vec![block],
        deleted: false,
    };
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file("group-a", &target, &permit)
        .unwrap();
    state
        .replica_coordinator
        .materialization_state_repository()
        .set_materialization_state(
            "group-a",
            "evicted.txt",
            yadorilink_replica_domain::session_state::MaterializationState::Present,
            &permit,
        )
        .unwrap();
    // On a Windows build, `evict_to_placeholder`'s Windows arm requires
    // a recorded CfAPI placeholder identity for this row (see that
    // function's own doc comment) -- a real precondition this test must
    // seed, same as `dst_eviction_crash_recovery.rs` does, since this
    // row was indexed directly rather than through a real create/hydrate
    // lifecycle. Harmless on non-Windows: `evict_to_placeholder`'s
    // non-Windows arm never reads it.
    state
        .replica_coordinator
        .materialization_state_repository()
        .record_placeholder_generation(
            "group-a",
            "evicted.txt",
            yadorilink_local_storage::PlaceholderDiskIdentity { dev: 0, ino: 1 },
            yadorilink_local_storage::WINDOWS_CFAPI_GENERATION_PROVIDER_KIND,
            &permit,
        )
        .unwrap();
    // Bypasses the real `cfapi-host.exe` pipe round trip on a Windows
    // build -- this test asserts on the custody/lease gate, not on the
    // native dehydrate mechanism, and no live CfAPI provider process
    // runs in this unit test. No-op on non-Windows. See
    // `set_test_windows_dehydrate_confirmed_for_path`'s own doc comment.
    crate::replica_coordinator::set_test_windows_dehydrate_confirmed_for_path(
        &materialized_root.path().join("evicted.txt"),
        true,
    );
    // No full replica confirms custody of this version.
    state.set_custody_confirmer(Arc::new(
        |_: &str, _: &str, _: &VersionHash, _: &[VersionBlock]| false,
    ));

    let reclaim_state = state.clone();
    let reclaim_root = materialized_root.path().to_path_buf();
    let outcome = tokio::task::spawn_blocking(move || {
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        let block_reclamation = BlockStorePortsAdapter::new(reclaim_state.block_store.clone());
        evict_file(
            MaterializationContext {
                state: reclaim_state.replica_coordinator.as_ref(),
                liveness_gate: reclaim_state.block_liveness_gate(),
                store: &block_reclamation,
                root: &reclaim_root,
                permit: &permit,
            },
            "group-a",
            "evicted.txt",
            false,
            reclaim_state.as_ref(),
        )
        .unwrap()
    })
    .await
    .unwrap();

    assert!(outcome.blocks_retained);
    assert!(matches!(reclaim_started_rx.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)));
    assert!(
        state.block_store.exists(&hash).unwrap(),
        "without a custody confirmation the local block must be retained"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gc_must_not_delete_old_deduplicated_block_adopted_after_live_snapshot() {
    let store_dir = tempfile::tempdir().unwrap();
    let (sweep_started_tx, sweep_started_rx) = std::sync::mpsc::sync_channel(1);
    let sweep_release = Arc::new((Mutex::new(false), Condvar::new()));
    let store = Arc::new(BarrierBlockStore {
        inner: SegmentBlockStore::new(store_dir.path()).unwrap().with_volume_verdict(|_| true),
        sweep_started: sweep_started_tx,
        sweep_release: sweep_release.clone(),
    });
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new("device-a".into(), sync_state, store);
    let bytes = b"orphaned before the GC live snapshot";
    let hash = state.block_store.put(bytes).unwrap();

    let sweep_state = state.clone();
    let sweep = tokio::spawn(async move {
        run_sweep_with_grace_cutoff(sweep_state, false, SystemTime::now() + Duration::from_secs(1))
            .await
    });
    tokio::task::spawn_blocking(move || sweep_started_rx.recv().unwrap()).await.unwrap();

    let writer_state = state.clone();
    let writer_hash = hash.clone();
    let (writer_started_tx, writer_started_rx) = std::sync::mpsc::sync_channel(1);
    let (writer_committed_tx, writer_committed_rx) = std::sync::mpsc::sync_channel(1);
    let writer = tokio::task::spawn_blocking(move || {
        writer_started_tx.send(()).unwrap();
        let _write = writer_state.begin_write_activity();
        assert_eq!(
            writer_state.block_store.put(bytes).unwrap(),
            writer_hash,
            "the write must deduplicate"
        );
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        writer_state
            .replica_coordinator
            .file_index_repository()
            .upsert_file(
                "group-a",
                &FileRecord {
                    path: "adopted.txt".into(),
                    size: bytes.len() as u64,
                    mtime_unix_nanos: 0,
                    blocks: vec![BlockInfo {
                        hash: hex::decode(&writer_hash).unwrap(),
                        offset: 0,
                        size: bytes.len() as u32,
                    }],
                    deleted: false,
                },
                &permit,
            )
            .unwrap();
        writer_committed_tx.send(()).unwrap();
    });
    tokio::task::spawn_blocking(move || writer_started_rx.recv().unwrap()).await.unwrap();
    assert!(
        matches!(writer_committed_rx.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)),
        "a write starting during GC must wait until physical deletion completes"
    );

    {
        let (released, wake) = &*sweep_release;
        *released.lock().unwrap() = true;
        wake.notify_all();
    }
    sweep.await.unwrap().unwrap();
    writer.await.unwrap();
    writer_committed_rx.recv().unwrap();

    assert!(
        state.block_store.exists(&hash).unwrap(),
        "GC must preserve a block adopted by a committed version after its live snapshot"
    );
}

/// GC must not start while a sync burst is active —
/// simulated here exactly the way the daemon's own `LinkRuntimeController`'s flush
/// executor and `hydration.rs`'s hydrate/evict/restore paths mark
/// activity in production (`begin_write_activity`'s RAII guard), not
/// by directly poking the write-safe-point flag.
#[tokio::test]
async fn sweep_does_not_run_while_a_sync_critical_write_is_in_progress() {
    let (state, _dir) = test_state();
    let _write_guard = state.begin_write_activity();

    let result = run_sweep(state.clone(), false).await;

    assert_eq!(result, Err(GcTriggerError::SyncBurstInProgress));
}

/// a sweep already in flight (flag pre-claimed here,
/// standing in for a concurrently-running real sweep) makes a second
/// attempt observe `AlreadyRunning` rather than running a second,
/// concurrent sweep.
#[tokio::test]
async fn a_second_sweep_attempt_is_rejected_while_one_is_already_running() {
    let (state, _dir) = test_state();
    state.gc.mark_running_for_test();

    let result = run_sweep(state.clone(), false).await;

    assert_eq!(result, Err(GcTriggerError::AlreadyRunning));
}

/// Exercised with real concurrent tasks (not just the
/// flag pre-claimed by hand, as above) across multiple linked
/// folders: however the two attempts interleave, at most one may
/// actually run a sweep — the other must observe `AlreadyRunning`,
/// never a second concurrent run.
///
/// `BarrierBlockStore` holds the winning sweep inside physical deletion,
/// making the overlap deterministic without relying on thousands of
/// filesystem writes or timing sleeps.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_one_sweep_runs_at_a_time_across_multiple_linked_folders() {
    let store_dir = tempfile::tempdir().unwrap();
    let (sweep_started_tx, sweep_started_rx) = std::sync::mpsc::sync_channel(1);
    let sweep_release = Arc::new((Mutex::new(false), Condvar::new()));
    let store = Arc::new(BarrierBlockStore {
        inner: SegmentBlockStore::new(store_dir.path()).unwrap().with_volume_verdict(|_| true),
        sweep_started: sweep_started_tx,
        sweep_release: sweep_release.clone(),
    });
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new("device-a".into(), sync_state, store);
    state
        .replica_coordinator
        .link_repository()
        .add_link("/tmp/yadorilink-gc-test-a", "group-a")
        .unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link("/tmp/yadorilink-gc-test-b", "group-b")
        .unwrap();

    let first_state = state.clone();
    let first = tokio::spawn(run_sweep(first_state, false));
    tokio::task::spawn_blocking(move || sweep_started_rx.recv().unwrap()).await.unwrap();

    let second = run_sweep(state, false).await;
    assert_eq!(second, Err(GcTriggerError::AlreadyRunning));

    let (released, wake) = &*sweep_release;
    *released.lock().unwrap() = true;
    wake.notify_all();
    first.await.unwrap().unwrap();
}

/// a freshly-constructed daemon (activity recorded as "now")
/// must not fire an idle sweep even against a threshold far shorter
/// than the real `GC_IDLE_THRESHOLD`.
#[tokio::test]
async fn idle_sweep_does_not_fire_before_the_threshold_elapses() {
    let (state, _dir) = test_state();

    let outcome = maybe_run_idle_sweep(&state, Duration::from_secs(3600)).await;

    assert!(outcome.is_none(), "must not attempt a sweep while still within the idle threshold");
}

/// once idle past the threshold, the scheduler tick actually
/// runs a (real, non-dry-run) sweep.
#[tokio::test]
async fn idle_sweep_fires_once_idle_past_the_threshold() {
    let (state, _dir) = test_state();
    state.set_last_activity_unix_for_test(now_unix() - 3600);

    let outcome = maybe_run_idle_sweep(&state, Duration::from_secs(60)).await;

    assert!(matches!(outcome, Some(Ok(_))), "expected a completed sweep, got {outcome:?}");
    assert!(state.gc.last_run_unix() > 0, "a real sweep must record its completion time");
}

/// Native replication is the daemon's peer-reconciliation activity: once a
/// peer connection reports that it admitted deltas (or joined a recovery
/// bundle), the idle scheduler must wait out a fresh idle period instead of
/// sweeping in the middle of a sync.
#[tokio::test]
async fn idle_sweep_waits_out_native_replication_activity() {
    let (state, _dir) = test_state();
    state.set_last_activity_unix_for_test(now_unix() - 3600);
    let env = crate::native_replication_runtime::env_for_peer(&state, "device-peer");

    (env.activity)();
    let outcome = maybe_run_idle_sweep(&state, Duration::from_secs(60)).await;

    assert!(
        outcome.is_none(),
        "peer replication activity must restart the idle period, got {outcome:?}"
    );
}

/// a daemon idle past the threshold, but with sync activity
/// actively in progress right now, still must not sweep — idle-ness
/// alone is not sufficient; the two conditions are independent —
/// this waits for both the idle period and no in-flight
/// hydration/materialization. Starts the write guard *first* (as
/// production does — `begin_write_activity` itself records "now" as
/// the last-activity time) and only afterward backdates
/// `last_activity_unix`, simulating a long-running write/hydration
/// whose start has already receded past the idle threshold while it's
/// still in flight — exactly the case `is_write_safe_point`'s own
/// check inside `run_sweep` exists for, distinct from (and not made
/// redundant by) the idle-scheduler's own idle-duration gate.
#[tokio::test]
async fn idle_sweep_is_skipped_when_a_write_is_in_progress_even_if_idle() {
    let (state, _dir) = test_state();
    let _write_guard = state.begin_write_activity();
    state.set_last_activity_unix_for_test(now_unix() - 3600);

    let outcome = maybe_run_idle_sweep(&state, Duration::from_secs(60)).await;

    assert_eq!(outcome, Some(Err(GcTriggerError::SyncBurstInProgress)));
}

/// An on-demand `gc` trigger firing while
/// an idle-triggered sweep is already underway (simulated here by
/// pre-claiming the flag, as the idle scheduler's own `run_sweep` call
/// would have done) must not start a second, concurrent sweep.
#[tokio::test]
async fn on_demand_trigger_during_an_idle_sweep_does_not_double_run() {
    let (state, _dir) = test_state();
    state.set_last_activity_unix_for_test(now_unix() - 3600);
    state.gc.mark_running_for_test(); // idle sweep already in flight

    let manual = run_sweep(state.clone(), false).await;

    assert_eq!(manual, Err(GcTriggerError::AlreadyRunning));
}

/// `--dry-run` computes the exact same delete set a real sweep would,
/// without deleting anything or updating
/// `last_run_unix`, but does update the reclaimable estimate. Uses
/// `run_sweep_with_grace_cutoff` directly (a future cutoff, mirroring
/// `fs_backend.rs`'s own sweep tests) so this doesn't depend on
/// waiting out the real multi-minute `GC_GRACE_WINDOW` — that
/// grace-window mechanics themselves are already covered by
/// `yadorilink-local-storage`'s own sweep unit tests (section 2).
#[tokio::test]
async fn dry_run_reports_without_deleting_or_advancing_last_run() {
    let (state, _dir) = test_state();
    let hash = state.block_store.put(b"orphaned block, never referenced").unwrap();
    let future_cutoff = SystemTime::now() + Duration::from_secs(1);

    let report = run_sweep_with_grace_cutoff(state.clone(), true, future_cutoff).await.unwrap();

    assert_eq!(report.blocks_deleted, 1);
    assert!(state.block_store.exists(&hash).unwrap(), "dry-run must not actually delete");
    assert_eq!(state.gc.last_run_unix(), 0, "dry-run must not count as a completed real sweep");
    assert_eq!(state.gc.reclaimable_estimate_bytes(), report.bytes_reclaimed);
}

/// The mirror case: a real (non-dry-run) sweep actually deletes the
/// orphaned block and records `last_run_unix`/the reclaimed counts,
/// resetting the reclaimable estimate back to 0 (everything
/// reclaimable as of that snapshot was just reclaimed).
#[tokio::test]
async fn real_sweep_deletes_and_records_last_run_bookkeeping() {
    let (state, _dir) = test_state();
    let hash = state.block_store.put(b"orphaned block, never referenced").unwrap();
    let future_cutoff = SystemTime::now() + Duration::from_secs(1);

    let report = run_sweep_with_grace_cutoff(state.clone(), false, future_cutoff).await.unwrap();

    assert_eq!(report.blocks_deleted, 1);
    assert!(!state.block_store.exists(&hash).unwrap(), "a real sweep must actually delete");
    assert!(state.gc.last_run_unix() > 0);
    assert_eq!(state.gc.last_blocks_deleted(), 1);
    assert_eq!(state.gc.last_bytes_reclaimed(), report.bytes_reclaimed);
    assert_eq!(state.gc.reclaimable_estimate_bytes(), 0);
}

/// A replica whose index references nothing while the block store is full
/// looks exactly like a replica whose database was lost. The automatic idle
/// sweep must not read that as "everything is garbage"; only an explicit
/// on-demand `gc` may reclaim in that state.
#[tokio::test]
async fn idle_sweep_refuses_an_empty_live_set_over_a_populated_store() {
    let (state, _dir) = test_state();
    let hash = state.block_store.put(b"a block the index no longer references").unwrap();
    let future_cutoff = SystemTime::now() + Duration::from_secs(1);

    let outcome = run_idle_sweep_with_grace_cutoff(state.clone(), future_cutoff).await;

    assert!(
        matches!(outcome, Err(GcTriggerError::Failed(_))),
        "an idle sweep over an empty live set must refuse, got {outcome:?}"
    );
    assert!(state.block_store.exists(&hash).unwrap(), "the block must survive");
    assert_eq!(state.gc.last_run_unix(), 0, "a refused sweep is not a completed sweep");

    let report = run_sweep_with_grace_cutoff(state.clone(), false, future_cutoff).await.unwrap();
    assert_eq!(report.blocks_deleted, 1, "an explicit on-demand sweep still reclaims");
}

/// The blocks a recovery item holds are roots of the real sweep: the item may be the last
/// copy of a version the group dropped, and nothing but its discard may release the blocks. A
/// block no row and no item names is still reclaimed, so the sweep is not simply keeping
/// everything.
#[tokio::test]
async fn the_real_sweep_keeps_the_blocks_a_recovery_item_holds() {
    let (state, _dir) = test_state();
    let held = state.block_store.put(b"the only copy of a dropped version").unwrap();
    let loose = state.block_store.put(b"referenced by nothing at all").unwrap();
    hold_with_a_recovery_item(&state, &held);
    let future_cutoff = SystemTime::now() + Duration::from_secs(1);

    let report = run_idle_sweep_with_grace_cutoff(state.clone(), future_cutoff).await.unwrap();

    assert!(state.block_store.exists(&held).unwrap(), "the item's block must survive the sweep");
    assert!(!state.block_store.exists(&loose).unwrap(), "an unreferenced block is reclaimed");
    assert_eq!(report.blocks_deleted, 1);
}

/// A file received with a deferred flush is committed `Present` with its write
/// intent still open until the batch flush. Its blocks are the rebuild source
/// if the flush is lost, and GC keeps them: the live set is every indexed
/// row's blocks, whatever the row's state or intent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gc_keeps_the_blocks_of_a_row_whose_write_intent_is_still_open() {
    let (state, _dir) = test_state();
    let bytes = b"received, flush still owed";
    let hash = state.block_store.put(bytes).unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            "group-a",
            &FileRecord {
                path: "received.txt".into(),
                size: bytes.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![BlockInfo {
                    hash: hex::decode(&hash).unwrap(),
                    offset: 0,
                    size: bytes.len() as u32,
                }],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    state
        .replica_coordinator
        .materialization_intent_repository()
        .begin_materialization_intent("group-a", "received.txt", &[7u8; 32], &permit)
        .unwrap();

    run_sweep_with_grace_cutoff(state.clone(), false, SystemTime::now() + Duration::from_secs(60))
        .await
        .unwrap();

    assert!(state.block_store.exists(&hash).unwrap(), "GC must keep the rebuild source");
}

/// The same with the intent marked as waiting for the batch flush, swept twice:
/// the blocks of the row (the rebuild source of a torn file) stay, the sweep
/// leaves the intent and its marker exactly as they were, and once the barrier
/// clears the intent the row alone keeps the blocks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gc_never_collects_a_block_while_a_marked_flush_pending_intent_is_open() {
    let (state, _dir) = test_state();
    let bytes = b"received, flush owed, marked";
    let hash = state.block_store.put(bytes).unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    let coordinator = state.replica_coordinator.clone();
    coordinator
        .file_index_repository()
        .upsert_file(
            "group-a",
            &FileRecord {
                path: "marked.txt".into(),
                size: bytes.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![BlockInfo {
                    hash: hex::decode(&hash).unwrap(),
                    offset: 0,
                    size: bytes.len() as u32,
                }],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    coordinator
        .materialization_intent_repository()
        .begin_materialization_intent("group-a", "marked.txt", &[7u8; 32], &permit)
        .unwrap();
    let marker = || -> Option<i64> {
        coordinator
            .database()
            .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                Ok(conn
                    .query_row(
                        "SELECT mutation_generation FROM materialization_intents \
                         WHERE group_id = 'group-a' AND path = 'marked.txt'",
                        [],
                        |r| r.get::<_, Option<i64>>(0),
                    )
                    .unwrap())
            })
            .unwrap()
    };
    coordinator
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            conn.execute(
                "UPDATE materialization_intents SET mutation_generation = 5 \
                 WHERE group_id = 'group-a' AND path = 'marked.txt'",
                [],
            )?;
            Ok(())
        })
        .unwrap();

    for _ in 0..2 {
        run_sweep_with_grace_cutoff(
            state.clone(),
            false,
            SystemTime::now() + Duration::from_secs(60),
        )
        .await
        .unwrap();
        assert!(state.block_store.exists(&hash).unwrap(), "the rebuild source is kept");
        assert_eq!(marker(), Some(5), "a sweep does not touch the waiting intent");
    }
    coordinator
        .materialization_intent_repository()
        .clear_materialization_intent("group-a", "marked.txt", &permit)
        .unwrap();
    run_sweep_with_grace_cutoff(state.clone(), false, SystemTime::now() + Duration::from_secs(60))
        .await
        .unwrap();
    assert!(state.block_store.exists(&hash).unwrap(), "the indexed row still references it");
}
