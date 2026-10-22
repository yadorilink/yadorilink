#![cfg(test)]

use super::*;
// This crate's own tests build a real fixture via this crate's own
// `TestReplica` (a thin wrapper around `yadorilink-daemon`'s
// `ReplicaCoordinator` -- see `test_support`'s own doc comment for why a
// bare `ReplicaCoordinator` does not compile in this crate's own
// internal `#[cfg(test)]` code).
use crate::test_support::TestReplica;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_filesystem_sync::watcher::{FsChangeEvent, FsChangeKind};
use yadorilink_fs_platform::fs_identity::disk_race_fingerprint;
use yadorilink_fs_platform::ignore_patterns::EffectiveIgnoreSet;
use yadorilink_local_storage::unix_mode_from_metadata;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::ids::SyncPath;
use yadorilink_replica_domain::local_op::Op;
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_sync_sqlite::SyncSqliteError;

fn processor() -> (LocalChangeProcessor, Arc<TestReplica>, tempfile::TempDir, tempfile::TempDir) {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let state = Arc::new(TestReplica::open_in_memory().unwrap());
    let root_dir = tempfile::tempdir().unwrap();
    (
        LocalChangeProcessor::new(
            state.clone(),
            store,
            "device-a".into(),
            std::sync::Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
        ),
        state,
        store_dir,
        root_dir,
    )
}

// --- `run_capture_pass_off_worker`'s runtime guard ---

/// The bound the offload exists to establish: however long a capture
/// pass runs, it must not hold the tokio worker core it was called on.
///
/// `worker_threads = 1` is the whole point of the test, not an
/// economy. With a single worker, a pass that held its core would leave
/// the ticker spawned below with nowhere to run at all until the pass
/// returned, and the tick count would not move.
///
/// The pass is `tokio::spawn`ed rather than run in the test body for
/// the same reason: `#[tokio::test]` drives the body on `block_on`'s
/// own thread, which is not a worker and holds no core, so blocking
/// there would pin nothing at all. Both tick reads happen on the
/// spawned task's own thread, immediately either side of the blocking
/// call, so the window measured is exactly the pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_capture_pass_does_not_hold_the_worker_core_it_runs_on() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let ticks = Arc::new(AtomicUsize::new(0));
    let ticker_ticks = Arc::clone(&ticks);
    let ticker = tokio::spawn(async move {
        loop {
            ticker_ticks.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    });
    // Let the ticker reach its first await, so the worker is genuinely
    // free to pick the pass up next.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let pass_ticks = Arc::clone(&ticks);
    let (before, after) = tokio::spawn(async move {
        let before = pass_ticks.load(Ordering::SeqCst);
        run_capture_pass_off_worker(|| {
            std::thread::sleep(std::time::Duration::from_millis(300));
        });
        (before, pass_ticks.load(Ordering::SeqCst))
    })
    .await
    .unwrap();
    ticker.abort();

    // ~60 ticks are expected in 300ms; assert on a small fraction of
    // that so a loaded machine cannot make this flaky, while still
    // failing outright on the "nothing ran at all" behavior it pins.
    assert!(
        after >= before + 5,
        "the sole worker made no progress while a capture pass ran on it \
         ({before} -> {after} ticks): the pass held its core instead of \
         handing it off"
    );
}

/// `block_in_place` panics unless a multi-threaded runtime is current,
/// and these passes are reachable from a current-thread one (this
/// module's own function is called from the synchronous
/// `scan_existing_files` public API, which an embedder may drive from
/// any runtime flavor). The guard must degrade to a plain synchronous
/// call there — where there is no worker pool, there is nothing to
/// starve — rather than take the process down.
#[tokio::test(flavor = "current_thread")]
async fn a_capture_pass_runs_inline_on_a_current_thread_runtime() {
    assert_eq!(run_capture_pass_off_worker(|| 42), 42);
}

/// The same degradation with no tokio runtime in the picture at all —
/// the shape the daemon's own initial scan already produces by running
/// `scan_existing_files_with_ignore_gated` inside `spawn_blocking`.
#[test]
fn a_capture_pass_runs_inline_with_no_runtime_at_all() {
    assert_eq!(run_capture_pass_off_worker(|| 42), 42);
}

/// The size gate decides only which thread the verification runs on,
/// never what it concludes — both sides of the cutoff must agree with
/// the unwrapped verifier on the same inputs.
#[test]
fn the_off_worker_verify_gate_does_not_change_the_verdict() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f.bin");
    std::fs::write(&path, b"hello world").unwrap();
    let blocks = yadorilink_local_storage::chunk_file(&store, &path).unwrap();

    for size in [0, OFF_WORKER_VERIFY_MIN_BYTES] {
        assert!(disk_bytes_match_indexed_blocks_off_worker(&path, &blocks, size).unwrap());
    }

    std::fs::write(&path, b"hello worlds").unwrap();
    for size in [0, OFF_WORKER_VERIFY_MIN_BYTES] {
        assert!(!disk_bytes_match_indexed_blocks_off_worker(&path, &blocks, size).unwrap());
    }
}

// --- Startup-scan vs incoming-peer-apply race (group startup barrier) ---
//
// These two tests are the deterministic core of the barrier: the same real
// `scan_existing_files_with_ignore` scan is paused (via `scan_test_hooks`)
// exactly between reading its whole-index snapshot and committing the record
// it derives from that snapshot, while a concurrent peer change for the same
// path is injected. Without the barrier the scan's blind, un-path-locked
// batch commit clobbers the peer change (last-writer overwrite); with the
// barrier the peer apply waits for startup to finish, so it is ordered after
// the scan commit and survives.

const RACE_GROUP: &str = "startup-race-group";
const RACE_PATH: &str = "raced.txt";
const PEER_MTIME: i64 = 7_777_777;

// Serializes the two tests that install the process-wide scan hook so they
// never observe each other's hook. Other scan tests use different group ids,
// and the hook no-ops for any group but `RACE_GROUP`, so they are unaffected.
// An async-aware `Mutex`, not `std::sync::Mutex`: both tests hold this guard
// across `.await` points for their entire body (that's the point -- the
// whole test, not just its setup, must stay serialized against the other),
// which a `std::sync::MutexGuard` cannot safely do.
static SCAN_RACE_TEST_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The scan test hooks are process-global statics, and `cargo test`
/// runs this module's tests concurrently in one process. Two tests
/// that install a hook therefore race twice over: each overwrites the
/// other's registered closure, and whichever finishes first clears the
/// hook the other is still waiting on -- so a test's own injection can
/// silently never fire, and another test's injection can fire into
/// this one's fixture. Every test below that installs a scan hook
/// holds this lock for the whole install/run/clear sequence, which is
/// the only thing that makes those hooks usable at all.
static SCAN_HOOK_INSTALLED: Mutex<()> = Mutex::new(());

/// Takes [`SCAN_HOOK_INSTALLED`], ignoring poisoning: a panicking test
/// that leaves the lock poisoned must not cascade into unrelated
/// failures in every other hook-using test.
fn hold_scan_hook_slot() -> std::sync::MutexGuard<'static, ()> {
    SCAN_HOOK_INSTALLED.lock().unwrap_or_else(|p| p.into_inner())
}

struct Latch {
    raised: Mutex<bool>,
    cv: std::sync::Condvar,
}

impl Latch {
    fn new() -> Self {
        Self { raised: Mutex::new(false), cv: std::sync::Condvar::new() }
    }
    fn raise(&self) {
        *self.raised.lock().unwrap_or_else(|p| p.into_inner()) = true;
        self.cv.notify_all();
    }
    /// Unbounded wait, for the scan thread's own use (waiting on
    /// `release_scan`, which the main test thread always raises promptly
    /// once it reaches that point) -- the main test thread's wait on
    /// `snapshot_read` is the one at risk of the scan never reaching the
    /// hook at all, so that call site uses `wait_timeout` below instead.
    fn wait(&self) {
        let mut raised = self.raised.lock().unwrap_or_else(|p| p.into_inner());
        while !*raised {
            raised = self.cv.wait(raised).unwrap_or_else(|p| p.into_inner());
        }
    }
    /// Bounded wait: returns whether the latch was actually raised, rather
    /// than blocking forever. The scan thread this waits on can fail
    /// *before* ever reaching the hook that raises it (e.g. `VerifiedRoot::
    /// open`'s root-marker write hitting a full disk) -- an unbounded
    /// `Condvar::wait` would then hang the test indefinitely instead of
    /// failing, since nothing else in the test is ever going to raise it.
    fn wait_timeout(&self, timeout: std::time::Duration) -> bool {
        let raised = self.raised.lock().unwrap_or_else(|p| p.into_inner());
        let (raised, result) = self
            .cv
            .wait_timeout_while(raised, timeout, |raised| !*raised)
            .unwrap_or_else(|p| p.into_inner());
        *raised && !result.timed_out()
    }
}

/// Extracts a readable message from a `std::thread::JoinHandle::join`
/// panic payload, for a clearer failure than "the latch never raised" when
/// the actual cause is the scan thread panicking before it could.
fn scan_panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

/// Diagnoses why `snapshot_read.wait_timeout(..)` returned `false`:
/// joins the scan thread (already finished if it panicked before
/// reaching the hook; still running only if the hook itself is somehow
/// stuck, which the hook's own bodies below never do) and reports what
/// happened.
fn describe_scan_timeout(scan_handle: std::thread::JoinHandle<()>) -> String {
    if scan_handle.is_finished() {
        match scan_handle.join() {
            Err(payload) => format!("scan thread panicked: {}", scan_panic_message(&*payload)),
            Ok(()) => "scan thread returned Ok without ever reaching the post-snapshot hook \
                       -- reconcile_disk_with_ignore must not have called it"
                .to_string(),
        }
    } else {
        "scan thread is still running".to_string()
    }
}

/// Builds a fixture whose index already holds an *old* row for `RACE_PATH`
/// and whose on-disk file has different content — so the real scan detects a
/// change and commits a fresh (stale-relative-to-any-peer-write) record.
fn build_race_fixture() -> (
    LocalChangeProcessor,
    Arc<TestReplica>,
    std::path::PathBuf,
    EffectiveIgnoreSet,
    tempfile::TempDir,
    tempfile::TempDir,
) {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let state = Arc::new(TestReplica::open_in_memory().unwrap());
    let root_dir = tempfile::tempdir().unwrap();
    let root = root_dir.path().canonicalize().unwrap();

    state.link_repository().add_link(&root.to_string_lossy(), RACE_GROUP).unwrap();

    let processor = LocalChangeProcessor::new(
        state.clone(),
        store,
        "device-a".into(),
        std::sync::Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
    );

    // Adopt the root identity here, while the index is still empty --
    // matching `adopt_root`'s own doc comment (a real first link always
    // does this before indexing anything). Otherwise the *scan itself*
    // performs first-adoption lazily inside `VerifiedRoot::open`, which
    // includes a marker-file write; if that write fails for any reason
    // (e.g. a full disk), the scan thread panics before ever reaching
    // the race tests' post-snapshot hook, and the test hangs on an
    // unbounded latch wait instead of failing. Adopting up front makes
    // that failure mode surface immediately, in fixture setup, instead.
    adopt_root(&state, RACE_GROUP, &root);

    state
        .file_index_repository()
        .upsert_file(
            RACE_GROUP,
            &FileRecord {
                path: RACE_PATH.to_string(),
                size: 1,
                mtime_unix_nanos: 1,
                blocks: vec![],
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    std::fs::write(root.join(RACE_PATH), b"offline-local-edit-content").unwrap();

    let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();
    (processor, state, root, ignore_set, store_dir, root_dir)
}

/// A concurrent peer change for the same path: a distinct device advances the
/// version, and a sentinel mtime lets the assertion tell whose record is
/// current after the race.
fn race_peer_record() -> FileRecord {
    FileRecord {
        path: RACE_PATH.to_string(),
        size: 4,
        mtime_unix_nanos: PEER_MTIME,
        blocks: vec![],
        deleted: false,
    }
}

/// FIX ASSERTED: with the group startup barrier, a peer change injected
/// after the scan snapshots but before it commits is ordered *after* startup
/// completes and is NOT overwritten by the scan's stale-snapshot record.
#[tokio::test]
async fn startup_barrier_prevents_stale_overwrite_of_concurrent_peer_change() {
    let _serial = SCAN_RACE_TEST_GUARD.lock().await;
    let (processor, state, root, ignore_set, _store_dir, _root_dir) = build_race_fixture();

    // As `start_link_watch` does synchronously before spawning the executor.
    let generation = state.startup_readiness().begin_group_startup(RACE_GROUP);

    let snapshot_read = Arc::new(Latch::new());
    let release_scan = Arc::new(Latch::new());
    {
        let snapshot_read = snapshot_read.clone();
        let release_scan = release_scan.clone();
        scan_test_hooks::set_post_snapshot_hook(Some(Arc::new(move |gid: &str| {
            if gid != RACE_GROUP {
                return;
            }
            snapshot_read.raise();
            release_scan.wait();
        })));
    }

    let scan_root = root.clone();
    let scan_handle = std::thread::spawn(move || {
        processor.scan_existing_files_with_ignore(RACE_GROUP, &scan_root, &ignore_set).unwrap();
    });

    // Scan has read the old snapshot and is paused before its commit.
    if !snapshot_read.wait_timeout(std::time::Duration::from_secs(10)) {
        panic!(
            "scan never reached its post-snapshot hook within 10s: {}",
            describe_scan_timeout(scan_handle)
        );
    }

    // Inject the peer change through the same gated sequence production uses:
    // wait for the group to be ready, then apply under the path lock. The
    // barrier is closed, so this parks instead of racing the scan.
    let peer_state = state.clone();
    let peer_task = tokio::spawn(async move {
        peer_state.wait_group_ready(RACE_GROUP).await.unwrap();
        let path_lock = peer_state.path_lock_registry().path_lock(RACE_GROUP, RACE_PATH);
        let _guard = path_lock.lock().await;
        peer_state
            .file_index_repository()
            .upsert_file(
                RACE_GROUP,
                &race_peer_record(),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
    });

    // Let the scan commit its stale-snapshot record first...
    release_scan.raise();
    scan_handle.join().unwrap();
    // ...then complete startup, which is what releases the parked peer apply.
    state.startup_readiness().mark_group_ready(RACE_GROUP, generation);
    peer_task.await.unwrap();
    scan_test_hooks::set_post_snapshot_hook(None);

    let current = state.file_index_repository().get_file(RACE_GROUP, RACE_PATH).unwrap().unwrap();
    assert_eq!(
        current.mtime_unix_nanos, PEER_MTIME,
        "with the startup barrier the peer change is ordered after the scan's commit and \
         survives as the current record"
    );
}

/// REPRODUCES THE BUG the barrier exists to prevent: an unordered peer apply
/// lands in the scan's snapshot-vs-commit window and the scan's blind batch
/// commit overwrites it. This is the failing-without half of the acceptance
/// pair — the only difference from the test above is that the peer apply is
/// not ordered against the scan.
///
/// It also pins the second mechanism that now prevents this: the apply below
/// skips `wait_group_ready` deliberately, because for a live link with no
/// registered gate that call no longer returns `Ok`. It refuses, which is
/// asserted first — so reaching the overwrite requires bypassing the gate
/// entirely, and both facts are proven in one place: the race is real, and
/// the gate does not admit it.
#[tokio::test]
async fn startup_scan_stale_overwrites_concurrent_peer_change_without_barrier() {
    let _serial = SCAN_RACE_TEST_GUARD.lock().await;
    let (processor, state, root, ignore_set, _store_dir, _root_dir) = build_race_fixture();
    // Deliberately no `begin_group_startup`: models a startup that never
    // registered a gate for a link that is nonetheless live.
    assert!(
        state.wait_group_ready(RACE_GROUP).await.is_err(),
        "a live link with no startup gate must refuse peer apply; the overwrite below is only \
         reachable by bypassing the gate, which is what makes this the negative control"
    );

    let snapshot_read = Arc::new(Latch::new());
    let release_scan = Arc::new(Latch::new());
    {
        let snapshot_read = snapshot_read.clone();
        let release_scan = release_scan.clone();
        scan_test_hooks::set_post_snapshot_hook(Some(Arc::new(move |gid: &str| {
            if gid != RACE_GROUP {
                return;
            }
            snapshot_read.raise();
            release_scan.wait();
        })));
    }

    let scan_root = root.clone();
    let scan_handle = std::thread::spawn(move || {
        processor.scan_existing_files_with_ignore(RACE_GROUP, &scan_root, &ignore_set).unwrap();
    });

    if !snapshot_read.wait_timeout(std::time::Duration::from_secs(10)) {
        panic!(
            "scan never reached its post-snapshot hook within 10s: {}",
            describe_scan_timeout(scan_handle)
        );
    }

    // The peer apply runs immediately in the snapshot-vs-commit window,
    // bypassing the gate that just refused it (asserted above) to show what
    // that refusal is protecting against.
    {
        let path_lock = state.path_lock_registry().path_lock(RACE_GROUP, RACE_PATH);
        let _guard = path_lock.lock().await;
        state
            .file_index_repository()
            .upsert_file(
                RACE_GROUP,
                &race_peer_record(),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
    }

    // The scan now commits its stale record on top of the peer change.
    release_scan.raise();
    scan_handle.join().unwrap();
    scan_test_hooks::set_post_snapshot_hook(None);

    let current = state.file_index_repository().get_file(RACE_GROUP, RACE_PATH).unwrap().unwrap();
    assert_ne!(
        current.mtime_unix_nanos, PEER_MTIME,
        "without the startup barrier the scan's stale-snapshot commit overwrites the \
         concurrent peer change — the race the barrier closes"
    );
}

// --- Live-rescan TOCTOU: a completed held-to-materialize transition
// racing the tombstone-candidate loop's own checks ---
//
// Unlike the group-startup-barrier tests above (which close a race
// between the STARTUP scan and a peer apply, using the barrier itself
// as the fix), this exercises the fresh, lock-covered re-check
// `reconcile_disk_with_ignore` now does immediately before committing
// any tombstone -- reproducing exactly the shape a LIVE rescan
// (`DebounceFlush::RescanRequired`, reachable at any point during an
// established link's life, not confined to any barrier) is exposed to.

const TOCTOU_GROUP: &str = "toctou-group";
const TOCTOU_PATH: &str = "held-then-materialized.bin";

async fn build_toctou_fixture() -> (
    LocalChangeProcessor,
    Arc<TestReplica>,
    std::path::PathBuf,
    EffectiveIgnoreSet,
    tempfile::TempDir,
    tempfile::TempDir,
    Vec<u8>,
) {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let state = Arc::new(TestReplica::open_in_memory().unwrap());
    let root_dir = tempfile::tempdir().unwrap();
    let root = root_dir.path().canonicalize().unwrap();

    state.link_repository().add_link(&root.to_string_lossy(), TOCTOU_GROUP).unwrap();
    state.set_local_change_auth_provider(Arc::new(|_group_id| Ok(())));
    let emitter = Arc::new(LocalAuthorKey::for_tests(
        "device-a",
        ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]),
    ));
    let processor = LocalChangeProcessor::new(
        state.clone(),
        store.clone(),
        "device-a".into(),
        std::sync::Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
    )
    .with_change_emitter(emitter);
    adopt_root(&state, TOCTOU_GROUP, &root);
    // A real, natively admitted edit for TOCTOU_PATH itself -- both tests
    // using this fixture exercise a LIVE rescan
    // (`scan_existing_files_with_ignore`, the same entry point
    // `DebounceFlush::RescanRequired` reaches once a link is
    // established), and a live rescan is only ever reachable once the
    // group's startup scan has already run, which always establishes
    // native history first (`ensure_initial_change_history`) -- so
    // `has_dag_history` must be `true` here to match production, not
    // an artifact of an otherwise-empty test fixture. Without this,
    // `reconcile_disk_with_ignore` takes its OTHER, non-chunked commit
    // path (`upsert_files_batch`, the true first-scan-of-a-brand-new-
    // link case), which has no per-chunk pre-commit re-verification
    // to exercise at all. Going through `process_event` (rather than
    // a direct `upsert_file`) is also what gives this row a real,
    // schema-required native authoring identity -- a current row with
    // none is rejected outright once the group has any native history
    // at all (`files_require_authoring_identity_on_insert`).
    let content = b"real content, written only after the hold clears".to_vec();
    std::fs::write(root.join(TOCTOU_PATH), &content).unwrap();
    processor
        .process_event(
            TOCTOU_GROUP,
            &root,
            &FsChangeEvent { path: root.join(TOCTOU_PATH), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();
    assert_eq!(
        crate::test_support::native_group_heads(&state, TOCTOU_GROUP).len(),
        1,
        "sanity: TOCTOU_PATH's own creation must have established exactly one native head"
    );
    // Now remove the just-indexed content -- everything below mutates
    // ONLY `materialization_state`/`held_reason`/`held_since_unix_
    // nanos` (never `state`/`version_seq`/`native_authoring_identity`, the
    // columns the trigger above actually watches), so the row's valid
    // authoring identity from the real edit just above survives
    // untouched.
    std::fs::remove_file(root.join(TOCTOU_PATH)).unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    // `hold_record`'s own established shape: `Remote`, held, and
    // (deliberately) nothing written under this exact name yet, no
    // intent, no obligation -- the row this whole investigation's bug
    // family is about.
    state
        .materialization_state_repository()
        .set_materialization_state(TOCTOU_GROUP, TOCTOU_PATH, MaterializationState::Remote, &permit)
        .unwrap();
    state
        .materialization_state_repository()
        .set_held(TOCTOU_GROUP, TOCTOU_PATH, "case_collision", 0)
        .unwrap();
    // What this fixture needs is an UNOBLIGATED path: left with an
    // open obligation, `has_unsettled_projection_obligation` alone
    // would exclude every candidate this whole fixture exists to test,
    // for a reason unrelated to what each test actually means to
    // exercise (held vs. cleared).
    //
    // The emission above now reaches that state on its own -- a local
    // emission settles its own obligation in the same transaction that
    // publishes the exact proof justifying it (see
    // `settle_obligation_against_local_presence_in_tx`). When it has
    // not (nothing publishable for this path), settle it here the way
    // `hold_record` itself would, against this row's genuine
    // `Remote` state. Either way the fixture continues from "no
    // open obligation", the precondition it always meant to establish.
    if let Some(obligation) =
        state.sqlite().dag_lookup_projection_obligation(TOCTOU_GROUP, TOCTOU_PATH).unwrap()
    {
        assert!(
            state
                .sqlite()
                .dag_complete_obligation_if_non_exact_proof_current(
                    TOCTOU_GROUP,
                    TOCTOU_PATH,
                    obligation.invalidation_generation,
                    obligation.obligation_incarnation,
                    yadorilink_sync_sqlite::projection_obligations::NonExactProofKind::ContentNotOwed,
                )
                .unwrap(),
            "sanity: settling the obligation against this row's genuine Placeholder state \
             must succeed"
        );
    }
    assert!(
        state
            .sqlite()
            .dag_lookup_projection_obligation(TOCTOU_GROUP, TOCTOU_PATH)
            .unwrap()
            .is_none(),
        "sanity: the fixture must continue from a path with no open obligation"
    );
    assert!(
        !root.join(TOCTOU_PATH).exists(),
        "sanity: nothing must be on disk under this exact name while held"
    );

    let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();
    (processor, state, root, ignore_set, store_dir, root_dir, content)
}

/// FIX ASSERTED (the CANDIDACY-time half -- see the sibling test
/// below for the SEPARATE pre-commit-window half): the probe scenario. A path starts hazard-held
/// (matching `hold_record`'s
/// shape exactly: `Remote`, `held_reason` set, nothing on disk,
/// no intent, no obligation). A live rescan's tombstone-candidate loop
/// reaches this path; the scan is paused right at LOOP ENTRY for this
/// path -- BEFORE `recheck_tombstone_candidate` runs at all (this
/// test's stand-in for the loop simply not having gotten to this path
/// yet, on a real multi-second walk) -- via `fire_pre_tombstone_
/// recheck`. While paused, a concurrent task completes the held-to-
/// materialize transition exactly the way a real `materialize`/
/// `hydrate_file_with_timeout` success does: `clear_held`, write the
/// real content under this exact name, stamp `Present`. Resuming the
/// scan must NOT tombstone this path: `recheck_tombstone_candidate`
/// only ever runs AFTER the hook releases it, so it reads the
/// already-fresh, post-transition state directly -- proving the
/// candidacy-time check itself is correct, not that a candidate which
/// legitimately passed it earlier stays protected all the way to its
/// own chunk's commit (that is what the sibling test below proves).
#[tokio::test]
#[allow(
    clippy::await_holding_lock,
    reason = "the scan-hook slot guard serializes the tests sharing the process-wide \
              scan hook; holding it across awaits is the point"
)]
async fn live_rescan_does_not_tombstone_a_path_that_completed_materializing_during_the_walk() {
    let _hook_slot = hold_scan_hook_slot();
    let (processor, state, root, ignore_set, _store_dir, _root_dir, content) =
        build_toctou_fixture().await;

    let snapshot_read = Arc::new(Latch::new());
    let release_scan = Arc::new(Latch::new());
    {
        let snapshot_read = snapshot_read.clone();
        let release_scan = release_scan.clone();
        scan_test_hooks::set_pre_tombstone_recheck_hook(Some(Arc::new(
            move |gid: &str, path: &str| {
                if gid != TOCTOU_GROUP || path != TOCTOU_PATH {
                    return;
                }
                snapshot_read.raise();
                release_scan.wait();
            },
        )));
    }

    let scan_root = root.clone();
    let scan_handle = std::thread::spawn(move || {
        processor.scan_existing_files_with_ignore(TOCTOU_GROUP, &scan_root, &ignore_set)
    });

    if !snapshot_read.wait_timeout(std::time::Duration::from_secs(10)) {
        let outcome = if scan_handle.is_finished() {
            format!("scan thread already finished: {:?}", scan_handle.join())
        } else {
            "scan thread is still running".to_string()
        };
        panic!("scan never reached its pre-tombstone-recheck hook within 10s: {outcome}");
    }

    // Complete the held-to-materialize transition while the scan is
    // paused exactly at this path's candidacy check -- the identical
    // end state `materialize`'s on-demand-receive branch or
    // `hydrate_file_with_timeout_locked`'s own success path leaves,
    // driven directly here (rather than through the real production
    // function, which lives in a different crate this one cannot
    // depend on) since only the END STATE matters for this scan's own
    // re-check, not which caller produced it.
    let materialize_root = root.clone();
    let materialize_state = state.clone();
    let materialize_content = content.clone();
    let materialize_task = tokio::task::spawn_blocking(move || {
        std::fs::write(materialize_root.join(TOCTOU_PATH), &materialize_content).unwrap();
        materialize_state
            .materialization_state_repository()
            .clear_held(TOCTOU_GROUP, TOCTOU_PATH)
            .unwrap();
        materialize_state
            .materialization_state_repository()
            .set_materialization_state(
                TOCTOU_GROUP,
                TOCTOU_PATH,
                MaterializationState::Present,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
    });
    materialize_task.await.unwrap();
    assert!(
        state
            .materialization_state_repository()
            .get_held_state(TOCTOU_GROUP, TOCTOU_PATH)
            .unwrap()
            .is_none(),
        "sanity: the transition must have genuinely cleared the hold before the scan resumes"
    );

    release_scan.raise();
    let records = scan_handle.join().unwrap().unwrap();

    assert!(
        !records.iter().any(|r| r.path == TOCTOU_PATH && r.deleted),
        "a path that finished materializing DURING the scan's walk must never be \
         tombstoned, even though every check read at this path's loop-entry time (before \
         the transition completed) would have said 'genuinely missing, fully unprotected': \
         {records:?}"
    );
    let indexed =
        state.file_index_repository().get_file(TOCTOU_GROUP, TOCTOU_PATH).unwrap().unwrap();
    assert!(!indexed.deleted, "the index row itself must not have been tombstoned either");
}

/// FIX ASSERTED (the PRE-COMMIT-WINDOW half -- the sibling test above
/// proves the candidacy-time check itself is correct; this proves the
/// window the candidacy-time check ALONE could not close is closed
/// too). The hold is cleared BEFORE the scan even
/// starts, so this path legitimately passes its candidacy-time
/// `recheck_tombstone_candidate` call (nothing protects it, and
/// nothing is on disk yet) and is added to `records` as a genuine
/// tombstone candidate -- the candidacy-time guard from that check is
/// dropped at the end of that loop iteration, long before this exact
/// path's own chunk actually commits. The scan is then paused a
/// SECOND time, at the FINAL pre-commit re-check
/// (`fire_pre_chunk_commit_recheck`, distinct from the candidacy-time
/// hook the sibling test uses) -- exactly the window between
/// "candidate accepted" and "chunk committed" that used to have no
/// re-verification, and no lock held across it, at all. While paused
/// there, a concurrent task completes a legitimate materialization
/// (real content lands under this exact name). Resuming must not
/// tombstone the path: the final re-check's own guard is held all the
/// way through this chunk's actual commit, so nothing can race it a
/// second time.
#[tokio::test]
#[allow(
    clippy::await_holding_lock,
    reason = "the scan-hook slot guard serializes the tests sharing the process-wide \
              scan hook; holding it across awaits is the point"
)]
async fn live_rescan_does_not_tombstone_a_path_materialized_between_its_candidacy_check_and_its_own_chunk_commit(
) {
    let _hook_slot = hold_scan_hook_slot();
    let (processor, state, root, ignore_set, _store_dir, _root_dir, content) =
        build_toctou_fixture().await;
    // Cleared before the scan even starts: this path must legitimately
    // pass its candidacy-time check (nothing protects it, nothing on
    // disk) rather than being excluded there the way the sibling
    // test's still-held row is -- the whole point of this test is the
    // window AFTER that acceptance, not a race with the acceptance
    // itself. It is a `Present` object whose file is gone, the only shape
    // whose absence is evidence of a delete.
    state.materialization_state_repository().clear_held(TOCTOU_GROUP, TOCTOU_PATH).unwrap();
    state
        .materialization_state_repository()
        .set_materialization_state(
            TOCTOU_GROUP,
            TOCTOU_PATH,
            MaterializationState::Present,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    let snapshot_read = Arc::new(Latch::new());
    let release_scan = Arc::new(Latch::new());
    {
        let snapshot_read = snapshot_read.clone();
        let release_scan = release_scan.clone();
        scan_test_hooks::set_pre_chunk_commit_recheck_hook(Some(Arc::new(
            move |gid: &str, path: &str| {
                if gid != TOCTOU_GROUP || path != TOCTOU_PATH {
                    return;
                }
                snapshot_read.raise();
                release_scan.wait();
            },
        )));
    }

    let scan_root = root.clone();
    let scan_handle = std::thread::spawn(move || {
        processor.scan_existing_files_with_ignore(TOCTOU_GROUP, &scan_root, &ignore_set)
    });

    if !snapshot_read.wait_timeout(std::time::Duration::from_secs(10)) {
        let outcome = if scan_handle.is_finished() {
            format!("scan thread already finished: {:?}", scan_handle.join())
        } else {
            "scan thread is still running".to_string()
        };
        panic!("scan never reached its pre-chunk-commit-recheck hook within 10s: {outcome}");
    }

    // Complete a legitimate materialization while the scan is paused
    // exactly between this path's candidacy acceptance and its own
    // chunk's actual commit -- the window that has no lock held
    // across it without this round's fix.
    let materialize_root = root.clone();
    let materialize_state = state.clone();
    let materialize_content = content.clone();
    let materialize_task = tokio::task::spawn_blocking(move || {
        std::fs::write(materialize_root.join(TOCTOU_PATH), &materialize_content).unwrap();
        materialize_state
            .materialization_state_repository()
            .set_materialization_state(
                TOCTOU_GROUP,
                TOCTOU_PATH,
                MaterializationState::Present,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
    });
    materialize_task.await.unwrap();

    release_scan.raise();
    let records = scan_handle.join().unwrap().unwrap();
    scan_test_hooks::set_pre_chunk_commit_recheck_hook(None);

    assert!(
        !records.iter().any(|r| r.path == TOCTOU_PATH && r.deleted),
        "a path materialized between its own candidacy acceptance and its chunk's actual \
         commit must never be tombstoned -- the candidacy-time check alone already passed \
         it (correctly, at the time): {records:?}"
    );
    let indexed =
        state.file_index_repository().get_file(TOCTOU_GROUP, TOCTOU_PATH).unwrap().unwrap();
    assert!(!indexed.deleted, "the index row itself must not have been tombstoned either");
}

/// The path whose content is swapped underneath the scan, in the
/// window between its own `PreparedMutation` completing and the chunk
/// carrying it actually committing. Brand new (never indexed), so the
/// scan reaches it through the ordinary
/// `build_record_for_created_or_modified` branch.
const COMMIT_GAP_VICTIM_PATH: &str = "swapped-between-prepare-and-commit.bin";
/// A sibling of `COMMIT_GAP_VICTIM_PATH` that nothing races. Its proof
/// is the control: it proves the scan does publish actual-state proofs
/// for this fixture's paths, and that the fenced read below can see
/// them -- without it, a `None` for the raced path would be
/// indistinguishable from "this fixture never publishes proofs at
/// all".
const COMMIT_GAP_CONTROL_PATH: &str = "never-raced-control.bin";

/// Replaces `path`'s bytes through a fresh temp file and a `rename`
/// over the original: the object under the name afterwards is a
/// DIFFERENT inode from the one the scan observed.
fn atomically_replace_with(path: &std::path::Path, bytes: &[u8]) {
    let tmp =
        path.with_file_name(format!("{}.replacement", path.file_name().unwrap().to_string_lossy()));
    std::fs::write(&tmp, bytes).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

/// Overwrites `path`'s bytes in place -- same inode, same length,
/// mtime restored to what it was before the write. The hardest shape
/// for anything downstream to notice: every cheap metadata comparison
/// (size, mtime, `(dev, ino)`) still agrees with what was observed
/// before the overwrite, so only the bytes themselves disagree.
fn overwrite_in_place_preserving_size_and_mtime(path: &std::path::Path, bytes: &[u8]) {
    use std::io::Write;
    let before = std::fs::metadata(path).unwrap();
    assert_eq!(
        before.len() as usize,
        bytes.len(),
        "this helper's whole point is a length-preserving overwrite"
    );
    let times = std::fs::FileTimes::new()
        .set_accessed(before.accessed().unwrap())
        .set_modified(before.modified().unwrap());
    let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    file.set_times(times).unwrap();
}

/// Drives one "content swapped in the prepare-to-commit gap" scenario.
///
/// Seeds two brand-new files under the fixture's root, runs a full
/// reconciliation scan, and -- from the pre-chunk-commit seam, which
/// fires for the fixture's tombstone candidate once every present-file
/// mutation in the same chunk has already been fully prepared --
/// applies `swap` to `COMMIT_GAP_VICTIM_PATH`. The scan then commits
/// the chunk exactly as it normally would.
///
/// Returns the replica and the root, for the caller to read back what
/// the commit published.
#[allow(
    clippy::await_holding_lock,
    reason = "the scan-hook slot guard serializes the tests sharing the process-wide \
              scan hook; holding it across awaits is the point"
)]
async fn run_commit_gap_swap(
    original: &[u8],
    replacement: Vec<u8>,
    swap: fn(&std::path::Path, &[u8]),
) -> (Arc<TestReplica>, std::path::PathBuf, tempfile::TempDir, tempfile::TempDir) {
    let _hook_slot = hold_scan_hook_slot();
    let (processor, state, root, ignore_set, store_dir, root_dir, _content) =
        build_toctou_fixture().await;
    // The fixture's held path is only here to give the chunk a
    // tombstone candidate, which is what the pre-chunk-commit seam
    // fires for. Cleared, and made a `Present` object whose file is gone,
    // so it legitimately passes its candidacy check and reaches that seam.
    state.materialization_state_repository().clear_held(TOCTOU_GROUP, TOCTOU_PATH).unwrap();
    state
        .materialization_state_repository()
        .set_materialization_state(
            TOCTOU_GROUP,
            TOCTOU_PATH,
            MaterializationState::Present,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    std::fs::write(root.join(COMMIT_GAP_VICTIM_PATH), original).unwrap();
    std::fs::write(root.join(COMMIT_GAP_CONTROL_PATH), original).unwrap();

    {
        let hook_root = root.clone();
        scan_test_hooks::set_pre_chunk_commit_recheck_hook(Some(Arc::new(
            move |gid: &str, path: &str| {
                if gid != TOCTOU_GROUP || path != TOCTOU_PATH {
                    return;
                }
                swap(&hook_root.join(COMMIT_GAP_VICTIM_PATH), &replacement);
            },
        )));
    }

    let scan_root = root.clone();
    let scan_handle = std::thread::spawn(move || {
        processor.scan_existing_files_with_ignore(TOCTOU_GROUP, &scan_root, &ignore_set)
    });
    let records = scan_handle.join().unwrap().unwrap();
    scan_test_hooks::set_pre_chunk_commit_recheck_hook(None);

    assert!(
        records.iter().any(|r| r.path == COMMIT_GAP_VICTIM_PATH && !r.deleted),
        "sanity: the raced path must have been committed by this scan as a present file, \
         or there is no proof to reason about: {records:?}"
    );
    assert!(
        records.iter().any(|r| r.path == COMMIT_GAP_CONTROL_PATH && !r.deleted),
        "sanity: the control path must have been committed by the same scan: {records:?}"
    );
    assert!(
        state
            .sqlite()
            .dag_lookup_materialized_generation(TOCTOU_GROUP, COMMIT_GAP_CONTROL_PATH)
            .unwrap()
            .is_some(),
        "sanity: the un-raced control path must have a readable, fence-current \
         actual-state proof -- otherwise a missing proof for the raced path proves nothing"
    );

    (state, root, store_dir, root_dir)
}

/// A scan's own bracket (fingerprint, read, observe identity,
/// re-fingerprint) closes successfully for a path, so the mutation it
/// prepared is one the current code considers fully vouched for. The
/// path's content is then replaced -- through a `rename`, so the name
/// now refers to a different object entirely -- after that bracket
/// closed but before the chunk carrying the mutation commits.
///
/// The commit must not publish an actual-state proof from evidence
/// that no longer describes what is under the name: a bracket that
/// cannot vouch for the path at the moment of the commit must yield no
/// proof rather than a wrong one. This is the mechanically simplest
/// shape of that race -- see the sibling test below for the in-place,
/// same-inode form, where nothing about the object's metadata reveals
/// the swap at all.
#[tokio::test]
async fn no_proof_is_published_for_content_replaced_between_prepare_and_chunk_commit() {
    let original = b"the bytes this scan actually read and versioned".to_vec();
    let replacement = b"entirely different bytes, written by another process".to_vec();
    let (state, root, _store_dir, _root_dir) =
        run_commit_gap_swap(&original, replacement.clone(), atomically_replace_with).await;

    let on_disk = std::fs::read(root.join(COMMIT_GAP_VICTIM_PATH)).unwrap();
    assert_eq!(on_disk, replacement, "sanity: the swap must actually have landed");

    let proof = state
        .sqlite()
        .dag_lookup_materialized_generation(TOCTOU_GROUP, COMMIT_GAP_VICTIM_PATH)
        .unwrap();
    assert!(
        proof.is_none(),
        "the commit published an actual-state proof for a path whose content was replaced \
         after the scan's bracket closed and before this chunk committed: {proof:?} -- the \
         proof names the version built from the bytes the scan read, but the name now \
         refers to a different object holding different bytes"
    );
}

/// The other half of in-transaction obligation settlement, and the one
/// that keeps admission universal: a local emission that could NOT
/// publish an exact proof must leave its obligation open for the
/// Convergence Engine, exactly as any other admitted change does.
///
/// Settlement is entitled by the proof, never by the emission being
/// local. This drives the same emission path as
/// `local_capture_of_new_content_publishes_a_usable_exact_actual_state_
/// proof` with the path's content swapped inside the commit gap, so the
/// bracket cannot vouch for it and no proof is written -- and the
/// obligation must then survive. Without this, "local emissions settle
/// their own obligations" would be indistinguishable from "local
/// admission skips obligations", which is the special-casing that must
/// never happen.
#[tokio::test]
async fn local_emission_without_a_publishable_proof_leaves_its_obligation_open() {
    let original = b"the bytes this scan actually read and versioned".to_vec();
    let replacement = b"entirely different bytes, written by another process".to_vec();
    let (state, _root, _store_dir, _root_dir) =
        run_commit_gap_swap(&original, replacement, atomically_replace_with).await;

    assert!(
        state
            .sqlite()
            .dag_lookup_materialized_generation(TOCTOU_GROUP, COMMIT_GAP_VICTIM_PATH)
            .unwrap()
            .is_none(),
        "sanity: this fixture exists to produce an emission with no publishable proof"
    );
    assert!(
        state
            .sqlite()
            .dag_lookup_projection_obligation(TOCTOU_GROUP, COMMIT_GAP_VICTIM_PATH)
            .unwrap()
            .is_some(),
        "a local emission with no exact proof must leave its obligation open: nothing has \
         established the desired state, so the Convergence Engine is still the only thing \
         that can. Settling here would be special-casing local admission"
    );
}

/// The same window as the sibling test above, in the form that defeats
/// every cheap check downstream has: the path's bytes are overwritten
/// IN PLACE, keeping the same inode, the same length and the same
/// mtime. Nothing about the object's metadata differs from what the
/// scan observed, so a proof published from that observation is not
/// merely stale -- it still revalidates as current, and authorizes
/// skipping physical work for content that is no longer on disk.
///
/// Asserts both halves: that no proof is published at all, and (in the
/// failure message) what revalidating the published one against disk
/// would say.
#[tokio::test]
async fn no_proof_is_published_for_content_overwritten_in_place_before_chunk_commit() {
    let original = b"the bytes this scan actually read and versioned!".to_vec();
    let mut replacement = b"a length-matched overwrite by another process..".to_vec();
    replacement.push(b'!');
    assert_eq!(
        original.len(),
        replacement.len(),
        "this test's point is an overwrite that preserves size as well as mtime"
    );
    let (state, root, _store_dir, _root_dir) = run_commit_gap_swap(
        &original,
        replacement.clone(),
        overwrite_in_place_preserving_size_and_mtime,
    )
    .await;

    let victim = root.join(COMMIT_GAP_VICTIM_PATH);
    let on_disk = std::fs::read(&victim).unwrap();
    assert_eq!(on_disk, replacement, "sanity: the in-place overwrite must actually have landed");

    let proof = state
        .sqlite()
        .dag_lookup_materialized_generation(TOCTOU_GROUP, COMMIT_GAP_VICTIM_PATH)
        .unwrap();
    let revalidation = proof.as_ref().map(|basis| {
        yadorilink_sync_sqlite::materialized_generation::revalidate_identity_against_disk(
            basis,
            &victim,
            yadorilink_fs_platform::fs_identity::TimestampGranularity::Fine,
        )
    });
    assert!(
        proof.is_none(),
        "the commit published an actual-state proof for a path overwritten in place -- same \
         inode, same length, same mtime -- between the scan's bracket closing and this \
         chunk's commit: {proof:?}; revalidating it against disk says {revalidation:?}, so \
         nothing downstream can tell that the bytes it vouches for are gone"
    );
}

const OFFLINE_DELETE_GROUP: &str = "offline-delete-proof-group";
const OFFLINE_DELETE_PATH: &str = "removed-while-stopped.bin";

/// A file removed from the folder while nothing was watching is
/// discovered by the next reconciliation scan, which emits the
/// offline-deletion tombstone. That half was already sound. What was
/// not: the same commit left the path's actual-state record exactly as
/// it was, still naming the pre-deletion version and the pre-deletion
/// filesystem identity, and still current against the path's own
/// mutation fence -- so the record read back as "this path holds that
/// file" for a path that holds nothing, and the projection obligation
/// the deletion opened had nothing to close against.
///
/// Absence is a first-class generation, so a deletion's commit must
/// publish one exactly as a present file's commit publishes its own.
///
/// Deliberately at the level of the state transition itself -- prepare
/// a mutation, commit it, read the generation back -- rather than
/// through a whole daemon lifecycle. The daemon-level test exists too;
/// this one is what says WHICH transition is wrong when it fails.
#[tokio::test]
async fn a_scanned_offline_deletion_publishes_an_absent_actual_state_proof() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let state = Arc::new(TestReplica::open_in_memory().unwrap());
    let root_dir = tempfile::tempdir().unwrap();
    let root = root_dir.path().canonicalize().unwrap();

    state.link_repository().add_link(&root.to_string_lossy(), OFFLINE_DELETE_GROUP).unwrap();
    state.set_local_change_auth_provider(Arc::new(|_group_id| Ok(())));
    let emitter = Arc::new(LocalAuthorKey::for_tests(
        "device-a",
        ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]),
    ));
    let processor = LocalChangeProcessor::new(
        state.clone(),
        store,
        "device-a".into(),
        std::sync::Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
    )
    .with_change_emitter(emitter);
    adopt_root(&state, OFFLINE_DELETE_GROUP, &root);

    // A real local emission for the path, so it enters the scan below
    // exactly as a previously-synced file does: a native-backed current
    // row with a genuine authoring identity, and an actual-state proof
    // describing the content that was on disk.
    std::fs::write(root.join(OFFLINE_DELETE_PATH), b"content that later goes away").unwrap();
    processor
        .process_event(
            OFFLINE_DELETE_GROUP,
            &root,
            &FsChangeEvent {
                path: root.join(OFFLINE_DELETE_PATH),
                kind: FsChangeKind::CreatedOrModified,
            },
        )
        .await
        .unwrap();
    let before = state
        .sqlite()
        .dag_lookup_materialized_generation(OFFLINE_DELETE_GROUP, OFFLINE_DELETE_PATH)
        .unwrap();
    assert_eq!(
        before.as_ref().map(|basis| basis.object_kind),
        Some(yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind::RegularFile),
        "sanity: the path must start out with a usable proof naming the present file -- \
         that is the record the deletion below has to move, and without it this test would \
         pass for the wrong reason: {before:?}"
    );

    // The deletion itself: gone from disk with nothing watching, so
    // only the reconciliation scan can notice it.
    std::fs::remove_file(root.join(OFFLINE_DELETE_PATH)).unwrap();
    let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();
    let records = processor
        .scan_existing_files_with_ignore(OFFLINE_DELETE_GROUP, &root, &ignore_set)
        .unwrap();
    assert!(
        records.iter().any(|r| r.path == OFFLINE_DELETE_PATH && r.deleted),
        "sanity: the scan must have committed a tombstone for the removed path, or there is \
         no deletion whose proof to reason about: {records:?}"
    );

    let after = state
        .sqlite()
        .dag_lookup_materialized_generation(OFFLINE_DELETE_GROUP, OFFLINE_DELETE_PATH)
        .unwrap();
    assert_eq!(
        after.as_ref().map(|basis| basis.object_kind),
        Some(yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind::Absent),
        "the commit that emitted the offline-deletion tombstone must have published an \
         absent actual-state generation for the path in the same transaction. `None` is a \
         different answer and not an acceptable one either: absence is a first-class \
         generation, and `None` means no usable record at all, so nothing can conclude the \
         path is already in its desired state without asking a peer. got {after:?}"
    );
    assert!(
        after
            .as_ref()
            .is_some_and(|basis| basis.version.is_none() && basis.filesystem_identity.is_none()),
        "an absent generation describes no object, so it must carry neither the version it \
         used to hold nor a filesystem identity: {after:?}"
    );

    // And the obligation that same commit opened is closed by it too.
    // Nothing downstream would: the zero-work pre-check declines an
    // absent resolution outright, and projecting the deletion does
    // nothing for a path whose index row this commit already
    // tombstoned -- so it produces no evidence to close against, and
    // the obligation retries forever against a peer that may not
    // exist.
    let obligation = state
        .sqlite()
        .dag_lookup_projection_obligation(OFFLINE_DELETE_GROUP, OFFLINE_DELETE_PATH)
        .unwrap();
    assert!(
        obligation.is_none(),
        "the projection obligation the emitted deletion opened must be closed by the same \
         transaction, against the absence that transaction just proved and published: \
         {obligation:?}"
    );
}

const LISTING_ERR_GROUP: &str = "listing-error-group";
const LISTING_ERR_PATH: &str = "sub/still-here.bin";

/// A directory listing that fails for any reason other than "it does not exist" is no
/// evidence the file is gone: the offline-tombstone check must defer the candidate (it is
/// retried by the next pass) instead of authoring a group-wide delete. A genuinely absent
/// file is still a candidate.
#[cfg(unix)]
#[tokio::test]
async fn an_unreadable_parent_listing_never_authorizes_an_offline_tombstone() {
    use super::scan::CommitPathLocks;
    use std::os::unix::fs::PermissionsExt as _;

    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let state = Arc::new(TestReplica::open_in_memory().unwrap());
    let root_dir = tempfile::tempdir().unwrap();
    let root = root_dir.path().canonicalize().unwrap();
    state.link_repository().add_link(&root.to_string_lossy(), LISTING_ERR_GROUP).unwrap();
    state.set_local_change_auth_provider(Arc::new(|_group_id| Ok(())));
    let emitter = Arc::new(LocalAuthorKey::for_tests(
        "device-a",
        ed25519_dalek::SigningKey::from_bytes(&[24u8; 32]),
    ));
    let processor = LocalChangeProcessor::new(
        state.clone(),
        store,
        "device-a".into(),
        std::sync::Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
    )
    .with_change_emitter(emitter);
    adopt_root(&state, LISTING_ERR_GROUP, &root);

    std::fs::create_dir(root.join("sub")).unwrap();
    std::fs::write(root.join(LISTING_ERR_PATH), b"still on disk").unwrap();
    processor
        .process_event(
            LISTING_ERR_GROUP,
            &root,
            &FsChangeEvent {
                path: root.join(LISTING_ERR_PATH),
                kind: FsChangeKind::CreatedOrModified,
            },
        )
        .await
        .unwrap();

    // The listing of the parent fails with EACCES; the file is still there.
    std::fs::set_permissions(root.join("sub"), std::fs::Permissions::from_mode(0o000)).unwrap();
    let unreadable = std::fs::read_dir(root.join("sub")).is_err();
    let deferred = unreadable.then(|| {
        processor
            .recheck_tombstone_candidate(
                LISTING_ERR_GROUP,
                &root,
                LISTING_ERR_PATH,
                &mut CommitPathLocks::default(),
            )
            .unwrap()
    });
    std::fs::set_permissions(root.join("sub"), std::fs::Permissions::from_mode(0o755)).unwrap();
    if !unreadable {
        return; // running with privileges that ignore permission bits
    }
    assert_eq!(
        deferred,
        Some(false),
        "an unreadable parent listing must defer the tombstone candidate, not authorize it"
    );

    // Genuine absence (listing succeeds, no such entry) is still a candidate.
    std::fs::remove_file(root.join(LISTING_ERR_PATH)).unwrap();
    assert!(
        processor
            .recheck_tombstone_candidate(
                LISTING_ERR_GROUP,
                &root,
                LISTING_ERR_PATH,
                &mut CommitPathLocks::default(),
            )
            .unwrap(),
        "a path that is genuinely absent must still be a tombstone candidate"
    );
}

/// `process_event` canonicalizes `root` internally (see its doc
/// comment — real OS watchers report fully-resolved paths, e.g.
/// macOS's `/private/var/...` for what looks like `/var/...`), so
/// tests that hand-construct `FsChangeEvent`s (rather than using a
/// real `watch_folder`) must build paths from an already-canonical
/// root to stay consistent, exactly as a real watcher's paths would be.
fn canonical_root(root_dir: &tempfile::TempDir) -> std::path::PathBuf {
    root_dir.path().canonicalize().unwrap()
}

/// Gives `root` a sync-root marker for `group`, the way a healthy install
/// acquires one: adopt while the index is still empty, which is what a real
/// first link does.
///
/// Needed only by tests that then index a file with no on-disk counterpart.
/// Such a root is empty with a non-empty index — byte-for-byte what an
/// unmounted volume looks like — so `VerifiedRoot::open` would (correctly)
/// refuse to scan it. Adopting first states the thing those tests actually
/// assume but cannot otherwise express: the volume is mounted, and the file
/// really is missing from a folder that really is this link's.
fn adopt_root(state: &ReplicaCoordinator, group: &str, root: &std::path::Path) {
    adopt_root_without_volume_identity(state, group, root);
    let identity = yadorilink_filesystem_sync::device_boundary::root_volume_identity(root).unwrap();
    state.link_repository().set_capture_volume_identity_for_group(group, &identity).unwrap();
}

/// A link as an older build left it: adopted root, no volume identity yet.
fn adopt_root_without_volume_identity(
    state: &ReplicaCoordinator,
    group: &str,
    root: &std::path::Path,
) {
    // A real link row is required: `set_link_root_token_for_group` is an
    // `UPDATE ... WHERE group_id = ?` with no matching row otherwise, so
    // without this the token silently never persists and a later
    // `VerifiedRoot::verify` (which requires the persisted token, unlike
    // `open`) fails with "no previously-adopted root token". `add_link`
    // is idempotent, so this is safe even when a caller already linked
    // the root itself.
    let _ = state.link_repository().add_link(&root.to_string_lossy(), group);
    yadorilink_root_authority::root_identity::VerifiedRoot::open(root, group, state).unwrap();
}

fn expect_file_changed(outcome: LocalChangeOutcome) -> FileRecord {
    match outcome {
        LocalChangeOutcome::FileChanged(record) => record,
        other => panic!("expected FileChanged, got {other:?}"),
    }
}

/// wraps a real `SegmentBlockStore` and counts
/// `put` calls, so a test can prove the size+mtime fast-path actually
/// skipped chunking (chunking always calls `put` at least once per
/// block — see `chunker::chunk_file`) rather than merely asserting on
/// the returned outcome, which the pre-existing self-echo suppression
/// could also produce (just after paying for a full chunk first).
struct CountingBlockStore {
    inner: SegmentBlockStore,
    put_calls: std::sync::atomic::AtomicUsize,
    /// Blocks committed one at a time (`put`/`put_prepared`), as
    /// opposed to through a bulk batch — the two are counted apart so a
    /// test can tell WHICH commit shape a code path took, not just how
    /// many blocks it committed.
    single_commits: std::sync::atomic::AtomicUsize,
    /// One entry per `put_prepared_batch` call, holding that batch's
    /// block count. `[300]` and `[1; 300]` commit the same 300 blocks
    /// and cost completely different numbers of directory fsyncs.
    batches: Mutex<Vec<usize>>,
    /// Fails every bulk flush once armed, for the fail-closed test.
    fail_batches: AtomicBool,
    /// Fails every bulk flush with the exact `StorageError::Io(NotFound)`
    /// shape `SegmentBlockStore::commit_batch`'s own headroom preflight
    /// (`check_headroom` -> `free_space::classify_volume`, which stats the
    /// block-store root) produces when that root has been deleted or its
    /// volume unmounted -- see `record_builder.rs`'s own doc on why this
    /// exact error shape, not merely any `Err`, is what the regression
    /// this fault feeds needs to distinguish from a vanished SOURCE path.
    /// A real deleted store root reproduces the identical shape on Unix,
    /// but deleting a directory a live handle (this store's own open
    /// sqlite index) is still inside is refused outright on Windows, so
    /// this double is what the regression itself runs against on every
    /// platform. (A companion Unix-only test that reproduced the real
    /// fault directly against `SegmentBlockStore` was tried and dropped:
    /// `remove_dir_all` racing the store's own background sqlite/WAL
    /// activity flaked with `DirectoryNotEmpty` under load, which would
    /// have swapped one platform's flake for another's.)
    fail_batches_not_found: AtomicBool,
    /// Fails a bulk flush carrying more than this many bytes; `0`
    /// disables it. A *content*-based discriminator, on purpose: it
    /// makes "the big file fails and the small ones succeed"
    /// deterministic, identical on every retry, and independent of the
    /// machine the test runs on.
    refuse_over_bytes: AtomicU64,
    /// Fails a bulk flush with `Io(PermissionDenied)` -- the store's own fault -- and, in the
    /// same instant, makes the named source file unreadable (mode 000), so the file and the
    /// store both report the same error kind at once.
    deny_batches_and_lock: Mutex<Option<Vec<std::path::PathBuf>>>,
}

impl CountingBlockStore {
    fn new(dir: &std::path::Path) -> Self {
        Self {
            inner: SegmentBlockStore::new(dir).unwrap(),
            put_calls: std::sync::atomic::AtomicUsize::new(0),
            single_commits: std::sync::atomic::AtomicUsize::new(0),
            batches: Mutex::new(Vec::new()),
            fail_batches: AtomicBool::new(false),
            fail_batches_not_found: AtomicBool::new(false),
            refuse_over_bytes: AtomicU64::new(0),
            deny_batches_and_lock: Mutex::new(None),
        }
    }

    /// Every bulk flush fails with `Io(PermissionDenied)`; every file in `lock` is chmod 000
    /// first (the file being built when the flush hits is among them, whichever it is).
    #[cfg(unix)]
    fn deny_every_batch(&self, lock: Vec<std::path::PathBuf>) {
        *self.deny_batches_and_lock.lock().unwrap() = Some(lock);
    }

    /// Blocks committed, however they were committed.
    fn put_call_count(&self) -> usize {
        self.put_calls.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn single_commit_count(&self) -> usize {
        self.single_commits.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn batch_sizes(&self) -> Vec<usize> {
        self.batches.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    fn fail_every_batch(&self) {
        self.fail_batches.store(true, Ordering::SeqCst);
    }

    /// See `fail_batches_not_found`'s own doc for why this exact shape,
    /// not `fail_every_batch`'s generic refusal, is what the block-store
    /// NotFound regression needs.
    fn fail_every_batch_with_not_found(&self) {
        self.fail_batches_not_found.store(true, Ordering::SeqCst);
    }

    /// Refuses any bulk flush carrying more than `bytes`.
    fn refuse_batches_larger_than(&self, bytes: u64) {
        self.refuse_over_bytes.store(bytes, Ordering::SeqCst);
    }
}

impl yadorilink_local_storage::BlockStore for CountingBlockStore {
    fn put(&self, data: &[u8]) -> Result<String, yadorilink_local_storage::StorageError> {
        self.put_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.single_commits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.put(data)
    }

    /// Counted as one block commit, like `put`, and delegated to the
    /// real store's own override so the block genuinely lands.
    fn put_prepared(
        &self,
        prepared: &yadorilink_local_storage::LocallyHashedBlock,
    ) -> Result<(), yadorilink_local_storage::StorageError> {
        self.put_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.single_commits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        yadorilink_local_storage::BlockStore::put_prepared(&self.inner, prepared)
    }

    /// Recorded as one batch of `prepared.len()` blocks, and delegated
    /// to `SegmentBlockStore`'s real batching override — NOT to the trait's
    /// per-block default, which would make every test here measure a
    /// commit shape production does not use.
    fn put_prepared_batch(
        &self,
        prepared: &[yadorilink_local_storage::LocallyHashedBlock],
    ) -> Result<(), yadorilink_local_storage::StorageError> {
        self.batches.lock().unwrap_or_else(|p| p.into_inner()).push(prepared.len());
        if self.fail_batches.load(Ordering::SeqCst) {
            return Err(yadorilink_local_storage::StorageError::Chunking(
                "bulk flush refused by the test double".into(),
            ));
        }
        #[cfg(unix)]
        if let Some(lock) = self.deny_batches_and_lock.lock().unwrap().as_ref() {
            use std::os::unix::fs::PermissionsExt as _;
            for file in lock {
                std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o000)).unwrap();
            }
            return Err(yadorilink_local_storage::StorageError::Io(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            )));
        }
        if self.fail_batches_not_found.load(Ordering::SeqCst) {
            return Err(yadorilink_local_storage::StorageError::Io(std::io::Error::from(
                std::io::ErrorKind::NotFound,
            )));
        }
        let limit = self.refuse_over_bytes.load(Ordering::SeqCst);
        let batch_bytes: u64 = prepared.iter().map(|b| b.bytes().len() as u64).sum();
        if limit != 0 && batch_bytes > limit {
            return Err(yadorilink_local_storage::StorageError::Chunking(format!(
                "bulk flush of {batch_bytes} bytes refused by the test double (limit {limit})"
            )));
        }
        self.put_calls.fetch_add(prepared.len(), std::sync::atomic::Ordering::SeqCst);
        yadorilink_local_storage::BlockStore::put_prepared_batch(&self.inner, prepared)
    }
    fn get(&self, hash: &str) -> Result<Vec<u8>, yadorilink_local_storage::StorageError> {
        self.inner.get(hash)
    }
    fn delete(&self, hash: &str) -> Result<(), yadorilink_local_storage::StorageError> {
        self.inner.delete(hash)
    }
    fn exists(&self, hash: &str) -> Result<bool, yadorilink_local_storage::StorageError> {
        self.inner.exists(hash)
    }
    fn list_by_prefix(
        &self,
        prefix: &str,
    ) -> Result<Vec<String>, yadorilink_local_storage::StorageError> {
        self.inner.list_by_prefix(prefix)
    }
    // This test double's whole job is counting `put` calls (see its
    // own doc comment) — every other method,
    // this one included, is a pure passthrough to the wrapped real
    // `SegmentBlockStore`, not something these tests exercise.
    fn sweep(
        &self,
        live_hashes: &std::collections::HashSet<String>,
        older_than: std::time::SystemTime,
        dry_run: bool,
    ) -> Result<yadorilink_local_storage::GcReport, yadorilink_local_storage::StorageError> {
        self.inner.sweep(live_hashes, older_than, dry_run)
    }
}

fn processor_with_counting_store() -> (
    LocalChangeProcessor,
    Arc<TestReplica>,
    Arc<CountingBlockStore>,
    tempfile::TempDir,
    tempfile::TempDir,
) {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(CountingBlockStore::new(store_dir.path()));
    let state = Arc::new(TestReplica::open_in_memory().unwrap());
    let root_dir = tempfile::tempdir().unwrap();
    (
        LocalChangeProcessor::new(
            state.clone(),
            store.clone(),
            "device-a".into(),
            std::sync::Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
        ),
        state,
        store,
        store_dir,
        root_dir,
    )
}

/// a `CreatedOrModified` event for a file
/// whose size and mtime are both unchanged from the indexed record
/// must resolve via the fast-path — no new block ever gets `put` into
/// the store, proving the file was never re-chunked. The fast-path does
/// now read the bytes once to verify them against the indexed block
/// hashes (`disk_bytes_match_indexed_blocks`, so a size+mtime-preserved
/// content edit can't slip through), but that verification streams and
/// compares without ever re-chunking or writing a block — exactly what
/// the unchanged `put` count proves: no store churn, no re-index.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unchanged_size_and_mtime_skips_rechunking_entirely() {
    let (proc, state, store, _store_dir, root_dir) = processor_with_counting_store();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let file_path = root.join("steady.bin");
    std::fs::write(&file_path, vec![b'x'; 5_000_000]).unwrap();

    expect_file_changed(
        proc.process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap(),
    );
    let calls_after_first = store.put_call_count();
    assert!(calls_after_first > 0, "the initial index must actually chunk the file");

    // No filesystem-level change at all: same bytes, same size, same
    // mtime — exactly what a self-echo or a redundant watcher event
    // for the same save looks like.
    let outcome = proc
        .process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    assert_eq!(outcome, LocalChangeOutcome::None);
    assert_eq!(
        store.put_call_count(),
        calls_after_first,
        "size+mtime fast-path must skip chunking entirely, not just suppress the resulting record"
    );
    assert_eq!(
        state.sqlite().dag_list_versions("group-1", "steady.bin").unwrap().len(),
        1,
        "no spurious version bump from an unchanged file"
    );
}

/// DI-3 tail closed: a content edit that preserves BOTH the byte length
/// AND the mtime (an in-place same-length overwrite, or any writer that
/// restores mtime via `utimes` after editing) must NOT be trusted as
/// unchanged on the strength of the stat metadata alone. The size+mtime
/// fast-path now verifies the on-disk bytes against the indexed block
/// hashes before concluding "no-op", so this edit is detected and
/// re-indexed rather than silently pinning the index at the stale
/// version while disk holds new bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn identical_size_and_mtime_with_different_bytes_is_now_detected() {
    let (proc, state, store, _store_dir, root_dir) = processor_with_counting_store();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let file_path = root.join("edge-case.bin");
    std::fs::write(&file_path, vec![b'A'; 20]).unwrap();

    expect_file_changed(
        proc.process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap(),
    );
    let indexed_before =
        state.file_index_repository().get_file("group-1", "edge-case.bin").unwrap().unwrap();
    let calls_after_first = store.put_call_count();
    let original_mtime = std::time::UNIX_EPOCH
        + std::time::Duration::from_nanos(indexed_before.mtime_unix_nanos as u64);

    // Same length (20 bytes), different bytes, mtime forced back to
    // exactly what was indexed — size AND mtime now both match the
    // index, so only a content comparison can tell this apart from a
    // genuine no-op.
    std::fs::write(&file_path, vec![b'B'; 20]).unwrap();
    // Windows' SetFileTime requires the handle to have been opened with
    // write access -- File::open is read-only there and fails this
    // with ACCESS_DENIED (Unix's utimensat has no such requirement, so
    // this only ever surfaced on this suite's first real Windows run).
    std::fs::OpenOptions::new()
        .write(true)
        .open(&file_path)
        .unwrap()
        .set_modified(original_mtime)
        .unwrap();

    let record = expect_file_changed(
        proc.process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap(),
    );

    assert!(!record.deleted, "the edit must surface as a live change, not a tombstone");
    assert_ne!(
        record.blocks, indexed_before.blocks,
        "the detected edit must carry the new on-disk content's blocks"
    );
    assert!(
        store.put_call_count() > calls_after_first,
        "detecting the size+mtime-preserved edit requires actually re-chunking the new bytes"
    );
    let indexed_after =
        state.file_index_repository().get_file("group-1", "edge-case.bin").unwrap().unwrap();
    assert_ne!(
        indexed_after.blocks, indexed_before.blocks,
        "the index must be re-versioned to the new content, not left at the stale blocks"
    );
}

// --- Regression coverage for two materialized-file exec-bit properties:
//
// Gap 1: a materialized (peer-received) file's on-disk mtime must be
// stamped to match the wire-carried authored mtime the index recorded
// for it (`reconstruct_file` writes a fresh temp file, whose wall-clock
// mtime would otherwise differ), or the size+mtime fast path's
// `metadata_mtime_matches` check could never hold for such a file -- a
// genuine local edit on it would always fall through to the content-only
// self-echo comparison further down instead.
//
// Gap 2: that content-only self-echo comparison must check the exec bit
// too, or a content-identical edit whose exec bit genuinely diverged from
// the index (a chmod-only edit being the paradigm case, but reachable by
// any local write whose freshly-chunked bytes already match what's
// indexed) would be silently dropped -- no version bump, no emitted
// change, no error.

/// Gap 1 + gap 2 together, end to end: materialize a file the real
/// production way (`reconstruct_file`, exactly as `PeerSyncSession::
/// materialize`/`hydrate_file` call it), then perform a genuine
/// chmod-only local edit on it, and confirm it is captured as a real
/// change -- not silently dropped.
#[cfg(unix)]
#[tokio::test]
async fn chmod_only_edit_on_a_peer_materialized_file_is_captured() {
    use std::os::unix::fs::PermissionsExt;

    let (proc, state, store, _store_dir, root_dir) = processor_with_counting_store();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);

    // Simulate a peer materializing a file onto this device: chunk the
    // content into the block store (as the eager fetch in `materialize`
    // would), then write it to disk via the REAL production
    // `reconstruct_file` under a wire-carried authored mtime far from
    // "now" -- a materialized file's indexed mtime is the AUTHORING
    // device's mtime, not this device's wall clock, which is exactly
    // the condition gap 1 was about.
    let content = b"#!/bin/sh\necho hi\n";
    let scratch = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(scratch.path(), content).unwrap();
    let blocks = yadorilink_local_storage::chunk_file(store.as_ref(), scratch.path()).unwrap();
    let file_path = root.join("received.sh");
    const PEER_AUTHORED_MTIME: i64 = 1_600_000_000_000_000_000;
    yadorilink_local_storage::reconstruct_file(
        store.as_ref(),
        &file_path,
        &blocks,
        PEER_AUTHORED_MTIME,
    )
    .unwrap();
    yadorilink_local_storage::apply_unix_mode(&file_path, Some(0o644)).unwrap();

    let record = FileRecord {
        path: "received.sh".to_string(),
        size: content.len() as u64,
        mtime_unix_nanos: PEER_AUTHORED_MTIME,
        blocks: blocks.clone(),
        deleted: false,
    };
    state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .file_index_repository()
        .set_unix_mode(
            "group-1",
            "received.sh",
            Some(0o644),
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    // Sanity: the on-disk mtime really was stamped to match the index
    // -- otherwise this test would not actually be exercising the
    // materialized-file scenario gap 1 was about.
    let disk_mtime_after_materialize = std::fs::metadata(&file_path)
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i64;
    assert_eq!(
        disk_mtime_after_materialize, PEER_AUTHORED_MTIME,
        "sanity: reconstruct_file must stamp disk mtime to match the indexed authored mtime"
    );

    let calls_after_materialize = store.put_call_count();

    // The genuine local edit: chmod +x, content untouched. On POSIX a
    // chmod touches ctime, not mtime, so disk mtime stays exactly what
    // materialize stamped it to -- this is what makes the size+mtime
    // fast path reachable at all for this edit.
    std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let disk_mtime_after_chmod = std::fs::metadata(&file_path)
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i64;
    assert_eq!(
        disk_mtime_after_chmod, PEER_AUTHORED_MTIME,
        "sanity: a chmod alone must not itself change mtime on this platform"
    );

    let outcome = proc
        .process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let record_after = expect_file_changed(outcome);
    assert_eq!(
        record_after.blocks, blocks,
        "content is unchanged -- this must be a metadata-only change, not a re-chunk"
    );
    assert_eq!(
        store.put_call_count(),
        calls_after_materialize,
        "a chmod-only edit on a materialized file must reach the size+mtime fast path (gap 1 \
         fixed), not fall through to a full re-chunk"
    );
    assert_eq!(
        state.file_index_repository().get_unix_mode("group-1", "received.sh").unwrap(),
        Some(0o755),
        "the real chmod +x must be captured and indexed, not silently dropped"
    );
    assert_eq!(
        state.sqlite().dag_list_versions("group-1", "received.sh").unwrap().len(),
        2,
        "the exec-bit-only change must mint a new version alongside the materialized one, not \
         be silently swallowed"
    );
}

/// Gap 2 in isolation: a chmod-only edit that reaches the content-only
/// self-echo comparison specifically (not the size+mtime fast path --
/// forced by desynchronizing the indexed mtime from disk without
/// touching the file) must still be captured, not dropped by a
/// content-only comparison that never looked at the exec bit.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chmod_only_edit_reaching_the_content_only_self_echo_path_is_still_captured() {
    use std::os::unix::fs::PermissionsExt;

    let (proc, state, _store, _store_dir, root_dir) = processor_with_counting_store();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let file_path = root.join("script.sh");
    let content = b"#!/bin/sh\necho hi\n";
    std::fs::write(&file_path, content).unwrap();

    let record_after_create = expect_file_changed(
        proc.process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap(),
    );
    assert!(
        state
            .file_index_repository()
            .get_unix_mode("group-1", "script.sh")
            .unwrap()
            .is_none_or(|mode| mode & 0o100 == 0),
        "sanity: a freshly-written file is not executable by default"
    );

    // Deliberately desynchronize the INDEXED mtime from disk, without
    // touching the file itself -- forces `current_mtime_matches` to be
    // false on the next event, skipping the size+mtime fast path
    // entirely and falling through to the content-only self-echo
    // comparison a few lines further down
    // `build_record_for_created_or_modified`, so this test exercises
    // THAT check specifically, not the fast path's own (already
    // correct, pre-existing) exec-bit comparison.
    let mut desynced = record_after_create.clone();
    desynced.mtime_unix_nanos += 1;
    state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &desynced,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    // The genuine local edit: chmod +x, content untouched.
    std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o755)).unwrap();

    let outcome = proc
        .process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let record_after_chmod = expect_file_changed(outcome);
    assert_eq!(
        record_after_chmod.blocks, record_after_create.blocks,
        "content is genuinely unchanged"
    );
    assert_eq!(
        state.file_index_repository().get_unix_mode("group-1", "script.sh").unwrap(),
        Some(0o755),
        "the chmod +x reaching the content-only self-echo comparison must still be captured, \
         not silently dropped (gap 2)"
    );
}

/// No-regression check for the loop-prevention self-echo suppression
/// the projection fence must not break: a genuine
/// materialization echo (this device's own watcher firing for a write
/// `reconstruct_file` itself just performed, with content AND exec bit
/// both already agreeing with the index) must still resolve to a no-op
/// via the fast path -- no re-chunk, no spurious version, no emitted
/// change.
#[cfg(unix)]
#[tokio::test]
async fn materialize_echo_with_matching_content_and_unix_mode_stays_a_no_op() {
    let (proc, state, store, _store_dir, root_dir) = processor_with_counting_store();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);

    let content = b"peer content, unchanged\n";
    let scratch = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(scratch.path(), content).unwrap();
    let blocks = yadorilink_local_storage::chunk_file(store.as_ref(), scratch.path()).unwrap();
    let file_path = root.join("mirrored.txt");
    const PEER_MTIME: i64 = 1_650_000_000_000_000_000;
    yadorilink_local_storage::reconstruct_file(store.as_ref(), &file_path, &blocks, PEER_MTIME)
        .unwrap();
    yadorilink_local_storage::apply_unix_mode(&file_path, Some(0o755)).unwrap();

    let record = FileRecord {
        path: "mirrored.txt".to_string(),
        size: content.len() as u64,
        mtime_unix_nanos: PEER_MTIME,
        blocks: blocks.clone(),
        deleted: false,
    };
    state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .file_index_repository()
        .set_unix_mode(
            "group-1",
            "mirrored.txt",
            Some(0o755),
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    let calls_before = store.put_call_count();

    // This device's own watcher firing for the write `reconstruct_file`
    // just did, exactly as this module's own doc comment describes --
    // must resolve to a no-op via the fast path (mtime/size/content/
    // exec bit all already agree), the same loop-prevention the
    // projection fence must not break.
    let outcome = proc
        .process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    assert_eq!(
        outcome,
        LocalChangeOutcome::None,
        "a genuine materialization echo must stay suppressed"
    );
    assert_eq!(
        store.put_call_count(),
        calls_before,
        "must resolve via the fast path (mtime matches after gap 1's fix), no re-chunk"
    );
    assert_eq!(
        state.sqlite().dag_list_versions("group-1", "mirrored.txt").unwrap().len(),
        1,
        "must stay at exactly the one version this test's own seeding upsert created -- no \
         spurious second version from the watcher echo"
    );
}

/// Deterministic regression for the self-echo race the projection fence
/// closes: a materialize() write is durably in flight (an open
/// `materialization_intents` row) for content A, the disk write has
/// landed, but the plain `files` index has NOT yet been updated to
/// reflect it (deliberately left un-upserted here, to force exactly the
/// window the fence must not depend on the index having already closed).
/// A watcher event landing in that window must resolve to a no-op, not
/// author a spurious local Change for content this device's own
/// materialize just wrote.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn projection_fence_suppresses_echo_even_when_the_plain_index_has_not_caught_up() {
    let (proc, state, store, _store_dir, root_dir) = processor_with_counting_store();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);

    let content_a = b"content A, projected by a peer's materialize\n";
    let scratch = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(scratch.path(), content_a).unwrap();
    let blocks_a = yadorilink_local_storage::chunk_file(store.as_ref(), scratch.path()).unwrap();
    let target_hash = yadorilink_local_storage::intent_target_hash(&blocks_a);

    let file_path = root.join("projected.bin");
    // The physical write materialize() would have already performed --
    // real content A, really on disk.
    std::fs::write(&file_path, content_a).unwrap();

    // This test is about the CONTENT race specifically -- seed a
    // placeholder row (still with EMPTY blocks, distinct from `blocks_a`
    // -- the plain index still reads as stale on content, preserving
    // this test's whole premise) purely so the indexed mode can be set
    // to already agree with what's genuinely on disk. Without this, the
    // metadata half of the fence (a separate concern, covered by its
    // own dedicated tests below) would interfere with what this test is
    // actually exercising.
    state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &FileRecord {
                path: "projected.bin".to_string(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    let on_disk_mode = unix_mode_from_metadata(&std::fs::metadata(&file_path).unwrap());
    state
        .file_index_repository()
        .set_unix_mode(
            "group-1",
            "projected.bin",
            on_disk_mode,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    // The durable intent materialize() opens BEFORE that write begins,
    // still open (not yet cleared): exactly the window under test.
    state
        .coordinator()
        .materialization_intent_repository()
        .begin_materialization_intent(
            "group-1",
            "projected.bin",
            &target_hash,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    // The seeded row above has EMPTY blocks, not `blocks_a` -- the
    // plain index still reads as stale on CONTENT (it does not yet
    // know about the write that just landed). If the fix only
    // consulted `existing`, this would read as a genuine content
    // change and author a spurious Change.

    let outcome = proc
        .process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    assert_eq!(
        outcome,
        LocalChangeOutcome::None,
        "content a live materialization intent is projecting must never be authored as a \
         local edit, regardless of whether the plain index has caught up yet"
    );
    assert_eq!(
        state.sqlite().dag_list_versions("group-1", "projected.bin").unwrap().len(),
        1,
        "must stay at exactly the one version this test's own seeding upsert created -- no \
         second, spurious local Change for this device's own projected content"
    );
}

/// The other half of the same invariant: a genuine concurrent edit to a
/// DIFFERENT target than what a live materialization intent is
/// projecting must still be captured as a real local Change. Presence
/// of an open intent alone must never be enough to suppress -- only an
/// event whose on-disk content matches that intent's own target.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn projection_fence_never_swallows_a_real_edit_racing_a_different_target() {
    let (proc, state, store, _store_dir, root_dir) = processor_with_counting_store();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);

    let content_a = b"content A, what the open intent is projecting\n";
    let scratch = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(scratch.path(), content_a).unwrap();
    let blocks_a = yadorilink_local_storage::chunk_file(store.as_ref(), scratch.path()).unwrap();
    let target_hash = yadorilink_local_storage::intent_target_hash(&blocks_a);

    state
        .coordinator()
        .materialization_intent_repository()
        .begin_materialization_intent(
            "group-1",
            "racing.bin",
            &target_hash,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    // A genuine, DIFFERENT local edit lands on disk while that intent
    // for A is still open -- content B, never what the intent named.
    let content_b = b"content B, a real concurrent human edit\n";
    let scratch_b = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(scratch_b.path(), content_b).unwrap();
    let blocks_b = yadorilink_local_storage::chunk_file(store.as_ref(), scratch_b.path()).unwrap();

    let file_path = root.join("racing.bin");
    std::fs::write(&file_path, content_b).unwrap();

    let outcome = proc
        .process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let record = expect_file_changed(outcome);
    assert_eq!(
        record.blocks, blocks_b,
        "the real edit's own content must be what gets captured, not suppressed as an echo \
         of the unrelated open intent for A"
    );
}

/// Deterministic regression for the projection fence's metadata-echo
/// case: content matching a live intent's target is necessary but NOT
/// SUFFICIENT to suppress -- the exec-bit/xattr divergence check below it
/// must still run. A real chmod landing on a path
/// whose CONTENT happens to already match an open intent (its own
/// content write already landed; nothing about mode is settled yet)
/// must still be captured -- exactly the failure class the exec-bit
/// check exists to close for the plain-index comparison, which the
/// unconditional content-only return silently reintroduced for the
/// intent comparison.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn projection_fence_never_swallows_a_real_chmod_racing_matching_content() {
    let (proc, state, store, _store_dir, root_dir) = processor_with_counting_store();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);

    let content_a = b"content A -- the intent's target, and what's genuinely on disk\n";
    let scratch = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(scratch.path(), content_a).unwrap();
    let blocks_a = yadorilink_local_storage::chunk_file(store.as_ref(), scratch.path()).unwrap();
    let target_hash = yadorilink_local_storage::intent_target_hash(&blocks_a);

    // What the projection intends: content A at mode 0644 -- the
    // indexed mode a real peer materialize would have this device's
    // `apply_unix_mode` eventually reconcile the file to. Content is
    // seeded as already-caught-up here (`blocks_a`, matching what's
    // about to land on disk) so the ONLY divergence this test exercises
    // is the metadata one -- `set_unix_mode` requires an existing row.
    state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &FileRecord {
                path: "chmodded.bin".to_string(),
                size: content_a.len() as u64,
                mtime_unix_nanos: 0,
                blocks: blocks_a.clone(),
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .file_index_repository()
        .set_unix_mode(
            "group-1",
            "chmodded.bin",
            Some(0o644),
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .coordinator()
        .materialization_intent_repository()
        .begin_materialization_intent(
            "group-1",
            "chmodded.bin",
            &target_hash,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    // Content on disk already matches the open intent's target exactly
    // -- but a real chmod to 0755 has ALSO happened, diverging from the
    // 0644 the projection intends.
    let file_path = root.join("chmodded.bin");
    std::fs::write(&file_path, content_a).unwrap();
    yadorilink_local_storage::apply_unix_mode(&file_path, Some(0o755)).unwrap();

    let outcome = proc
        .process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    expect_file_changed(outcome);
}

/// The unfinished write of a version whose row records no mode (one from a platform with no
/// permission bits): the daemon gives the file the platform's default mode, which differs from
/// the row's `None` only because the row says nothing. With a write of exactly this content
/// still open, that is the write's own echo -- before this was suppressed, the abandoned write
/// of a conflict copy was authored back as a chmod edit of the copy, and the path's winner
/// then depended on the hash of that spurious version.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_open_write_of_a_modeless_row_is_not_authored_back_as_a_chmod() {
    let (proc, state, store, _store_dir, root_dir) = processor_with_counting_store();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);

    let content_a = b"content A, written by this device for a row that records no mode\n";
    let scratch = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(scratch.path(), content_a).unwrap();
    let blocks_a = yadorilink_local_storage::chunk_file(store.as_ref(), scratch.path()).unwrap();
    let target_hash = yadorilink_local_storage::intent_target_hash(&blocks_a);

    let file_path = root.join("modeless.bin");
    std::fs::write(&file_path, content_a).unwrap();
    let mtime_secs = 1_000u64;
    std::fs::OpenOptions::new()
        .write(true)
        .open(&file_path)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(mtime_secs))
        .unwrap();

    state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &FileRecord {
                path: "modeless.bin".to_string(),
                size: content_a.len() as u64,
                mtime_unix_nanos: (mtime_secs * 1_000_000_000) as i64,
                blocks: blocks_a.clone(),
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .coordinator()
        .materialization_intent_repository()
        .begin_materialization_intent(
            "group-1",
            "modeless.bin",
            &target_hash,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    let outcome = proc
        .process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    assert_eq!(
        outcome,
        LocalChangeOutcome::None,
        "the default mode of an unfinished write is not a chmod of a row that records none"
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn projection_fence_never_swallows_a_real_xattr_edit_racing_matching_content() {
    let (proc, state, store, _store_dir, root_dir) = processor_with_counting_store();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);

    let content_a = b"content A -- the intent's target, and what's genuinely on disk\n";
    let scratch = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(scratch.path(), content_a).unwrap();
    let blocks_a = yadorilink_local_storage::chunk_file(store.as_ref(), scratch.path()).unwrap();
    let target_hash = yadorilink_local_storage::intent_target_hash(&blocks_a);

    // The projection intends content A with NO xattrs (the default,
    // matching a fresh index row's empty xattr set).
    state
        .coordinator()
        .materialization_intent_repository()
        .begin_materialization_intent(
            "group-1",
            "xattred.bin",
            &target_hash,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    let file_path = root.join("xattred.bin");
    std::fs::write(&file_path, content_a).unwrap();
    // A real, local xattr edit lands while that intent is still open --
    // content matches the target exactly, but this device's own
    // replicated xattr set now genuinely diverges from what's indexed
    // (none).
    yadorilink_local_storage::apply_xattrs(
        &file_path,
        &[("user.yadorilink-test".to_string(), b"real-local-edit".to_vec())],
    )
    .unwrap();

    let outcome = proc
        .process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    expect_file_changed(outcome);
}

/// The state a repair reconstruct leaves behind when its row is replaced
/// by a newer version between the lane's snapshot and its proof commit:
/// the lane has renamed the OLD version's full bytes into place, its
/// intent (targeting those old bytes) is still open, and the row now
/// names the NEWER version as a `Remote` with no recorded placeholder
/// identity. The settle writes nothing for the newer row, so this is
/// where the path rests until something materializes the newer version.
///
/// Capture must not author the old bytes as a local edit on top of the
/// newer version: that would resurrect the old content for every peer.
/// What holds it is the projection fence, reached because the bytes are
/// real (not an untouched placeholder): they hash to the open intent's
/// target, and with mode and xattrs agreeing with the row, the event is
/// the lane's own echo. The fence only holds while the metadata agrees;
/// an old version whose mode or xattrs differ from the newer row's is
/// captured as an edit, which is the same outcome a row replacement that
/// never touches disk produces for any already-hydrated path.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_old_versions_bytes_under_a_newer_placeholder_row_are_the_open_intents_echo() {
    let (proc, state, store, _store_dir, root_dir) = processor_with_counting_store();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();

    let chunk = |content: &[u8]| {
        let scratch = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(scratch.path(), content).unwrap();
        yadorilink_local_storage::chunk_file(store.as_ref(), scratch.path()).unwrap()
    };
    let old_content = b"the old version the repair lane reconstructed\n";
    let new_content = b"the newer version that replaced the row mid-write, longer than the old\n";
    let old_blocks = chunk(old_content);
    let new_blocks = chunk(new_content);

    // The row as the replacement left it: the newer version, a
    // `Remote`, no placeholder identity recorded.
    state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &FileRecord {
                path: "superseded.bin".to_string(),
                size: new_content.len() as u64,
                mtime_unix_nanos: 0,
                blocks: new_blocks,
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    state
        .materialization_state_repository()
        .set_materialization_state(
            "group-1",
            "superseded.bin",
            MaterializationState::Remote,
            &permit,
        )
        .unwrap();
    // The lane's intent, still open, naming the old bytes.
    state
        .coordinator()
        .materialization_intent_repository()
        .begin_materialization_intent(
            "group-1",
            "superseded.bin",
            &yadorilink_local_storage::intent_target_hash(&old_blocks),
            &permit,
        )
        .unwrap();
    // The lane's write: the old version's full bytes, really on disk.
    let file_path = root.join("superseded.bin");
    std::fs::write(&file_path, old_content).unwrap();
    let on_disk_mode = unix_mode_from_metadata(&std::fs::metadata(&file_path).unwrap());
    state
        .file_index_repository()
        .set_unix_mode("group-1", "superseded.bin", on_disk_mode, &permit)
        .unwrap();
    let versions_before =
        state.sqlite().dag_list_versions("group-1", "superseded.bin").unwrap().len();

    let outcome = proc
        .process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    assert_eq!(
        outcome,
        LocalChangeOutcome::None,
        "the old version's bytes a superseded repair left under the newer row must be read as \
         that repair's own echo, not authored over the newer version"
    );
    assert_eq!(
        state.sqlite().dag_list_versions("group-1", "superseded.bin").unwrap().len(),
        versions_before,
        "no local version may be authored from the old bytes"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn created_file_is_chunked_and_indexed() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let file_path = root.join("hello.txt");
    std::fs::write(&file_path, b"hello world").unwrap();

    let record = expect_file_changed(
        proc.process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap(),
    );

    assert_eq!(record.path, "hello.txt");
    assert_eq!(record.size, 11);
    assert_eq!(record.blocks.len(), 1);
    // Causality is the retained version history now, not a counter: a
    // first indexing must leave exactly one version, authored here.
    let versions = state.sqlite().dag_list_versions("group-1", "hello.txt").unwrap();
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].origin_device_id.as_deref(), Some("device-a"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rename_produces_identical_block_hashes_as_the_original() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let original = root.join("original.txt");
    std::fs::write(&original, b"unchanged content").unwrap();
    let created = expect_file_changed(
        proc.process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: original.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap(),
    );

    // Simulate a rename: delete the old path, create the new one with
    // byte-identical content (nothing edited).
    std::fs::remove_file(&original).unwrap();
    proc.process_event(
        "group-1",
        &root,
        &FsChangeEvent { path: original, kind: FsChangeKind::ObservedRemoval },
    )
    .await
    .unwrap();

    let renamed = root.join("renamed.txt");
    std::fs::write(&renamed, b"unchanged content").unwrap();
    let recreated = expect_file_changed(
        proc.process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: renamed, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap(),
    );

    assert_eq!(created.blocks, recreated.blocks, "unchanged content must hash to identical blocks");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removed_file_is_marked_deleted_with_incremented_version() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let file_path = root.join("bye.txt");
    std::fs::write(&file_path, b"data").unwrap();
    proc.process_event(
        "group-1",
        &root,
        &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
    )
    .await
    .unwrap();

    // `process_event` now derives Removed-vs-CreatedOrModified from
    // the path's actual
    // current disk state rather than trusting `event.kind` verbatim
    // (closing a race where a debounce-coalesced `Removed` could be
    // silently overwritten by an unrelated later write to the same
    // path) -- so this synthetic `Removed` event must correspond to a
    // real deletion, matching what a genuine watcher would only ever
    // report after the fact.
    std::fs::remove_file(&file_path).unwrap();
    let tombstone = expect_file_changed(
        proc.process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: file_path, kind: FsChangeKind::ObservedRemoval },
        )
        .await
        .unwrap(),
    );

    assert!(tombstone.deleted);
    // The tombstone is a second retained version of the same path, not an
    // in-place rewrite of the first.
    assert_eq!(state.sqlite().dag_list_versions("group-1", "bye.txt").unwrap().len(), 2);
}

/// A case-only rename on a case-insensitive volume leaves the old name's
/// lookup answering with the new spelling. The old exact name is gone, so
/// it is an observed removal: the old name's row must be tombstoned.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn case_only_rename_is_captured_as_a_delete_of_the_old_name() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let old = root.join("Photo.jpg");
    std::fs::write(&old, b"data").unwrap();
    proc.process_event(
        "group-1",
        &root,
        &FsChangeEvent { path: old.clone(), kind: FsChangeKind::CreatedOrModified },
    )
    .await
    .unwrap();

    std::fs::rename(&old, root.join("photo.jpg")).unwrap();
    if old.symlink_metadata().is_err() {
        eprintln!("skipped: this volume is case-sensitive, so the old name simply vanishes");
        return;
    }
    let outcome = proc
        .process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: old, kind: FsChangeKind::ObservedRemoval },
        )
        .await
        .unwrap();

    assert!(expect_file_changed(outcome).deleted);
}

/// A file whose parent cannot be listed is not shown absent by that failure:
/// no delete is authored, and the path is looked at again later.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unlistable_parent_is_not_read_as_a_removal() {
    use std::os::unix::fs::PermissionsExt as _;
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let dir = root.join("d");
    std::fs::create_dir(&dir).unwrap();
    let file = dir.join("f.txt");
    std::fs::write(&file, b"data").unwrap();
    proc.process_event(
        "group-1",
        &root,
        &FsChangeEvent { path: file.clone(), kind: FsChangeKind::CreatedOrModified },
    )
    .await
    .unwrap();

    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o111)).unwrap();
    let listable = std::fs::read_dir(&dir).is_ok();
    let outcome = proc
        .process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: file, kind: FsChangeKind::ObservedRemoval },
        )
        .await;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    if listable {
        eprintln!("skipped: permissions do not stop this user from listing the directory");
        return;
    }

    assert!(matches!(outcome.unwrap(), LocalChangeOutcome::RetryLater));
    assert!(
        !state.file_index_repository().get_file("group-1", "d/f.txt").unwrap().unwrap().deleted
    );
}

/// A `Removed` event for a path that is already a tombstone authors
/// nothing. More than one such event per deletion is ordinary: a
/// program that recreates and removes the same scratch name (a lock
/// file, a temp pack) produces one per cycle; the same deletion can
/// surface in more than one debounce window; and a deletion this device
/// projected from a peer comes back through its own watcher. Each used
/// to mint a fresh Delete change on top of the tombstone already there
/// -- several tombstones for one path within a second, and a device
/// re-deleting paths a peer had already deleted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removed_event_for_an_already_tombstoned_path_authors_nothing() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    adopt_root(&state, group, &root);
    let path = root.join("index.lock");
    std::fs::write(&path, b"lock").unwrap();
    expect_file_changed(
        proc.process_event(
            group,
            &root,
            &FsChangeEvent { path: path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap(),
    );
    std::fs::remove_file(&path).unwrap();
    let removed = FsChangeEvent { path: path.clone(), kind: FsChangeKind::ObservedRemoval };
    assert!(expect_file_changed(proc.process_event(group, &root, &removed).await.unwrap()).deleted);
    let tombstone_author =
        state.file_index_repository().row_authoring(group, "index.lock").unwrap();
    let tombstone_versions = state.sqlite().dag_list_versions(group, "index.lock").unwrap().len();

    // The same name comes and goes again without ever being captured,
    // then the deletion is reported again -- directly and through a
    // debounced flush.
    std::fs::write(&path, b"lock").unwrap();
    std::fs::remove_file(&path).unwrap();
    assert_eq!(proc.process_event(group, &root, &removed).await.unwrap(), LocalChangeOutcome::None);
    let flushed = proc
        .process_flush(
            group,
            &root,
            yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![(
                path.clone(),
                FsChangeKind::ObservedRemoval,
                0,
            )]),
        )
        .await
        .unwrap();
    assert!(flushed.records.is_empty(), "a repeated deletion must not author another tombstone");

    assert_eq!(
        state.file_index_repository().row_authoring(group, "index.lock").unwrap(),
        tombstone_author,
        "the path's tombstone must still be the one delta that deleted it"
    );
    assert_eq!(
        state.sqlite().dag_list_versions(group, "index.lock").unwrap().len(),
        tombstone_versions,
        "a repeated deletion must not add another version"
    );
}

#[tokio::test]
async fn deleting_never_indexed_ignored_paths_generates_no_tombstone() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let ignore_set = EffectiveIgnoreSet::from_user_patterns("*.tmp\n");

    let user_ignored = root.join("scratch.tmp");
    let user_outcome = proc
        .process_event_with_ignore(
            "group-1",
            &root,
            &FsChangeEvent { path: user_ignored, kind: FsChangeKind::ObservedRemoval },
            &ignore_set,
        )
        .await
        .unwrap();
    assert_eq!(user_outcome, LocalChangeOutcome::None);
    assert!(state.file_index_repository().get_file("group-1", "scratch.tmp").unwrap().is_none());

    let built_in_ignored = root.join(".DS_Store");
    let built_in_outcome = proc
        .process_event_with_ignore(
            "group-1",
            &root,
            &FsChangeEvent { path: built_in_ignored, kind: FsChangeKind::ObservedRemoval },
            &ignore_set,
        )
        .await
        .unwrap();
    assert_eq!(built_in_outcome, LocalChangeOutcome::None);
    assert!(state.file_index_repository().get_file("group-1", ".DS_Store").unwrap().is_none());
}

/// Without an OS transparent-hydration provider, a `Remote` row's
/// on-disk file is an ordinary sparse file at an ordinary path --
/// nothing stops a user (or an editor) from writing directly to it. If
/// `build_record_for_created_or_modified` treated EVERY
/// `CreatedOrModified` event on a `Remote` path as this crate's own
/// echo, a genuine user edit would be silently and permanently
/// discarded: never chunked, never indexed, with a later `hydrate` then
/// overwriting it with the stale synced content. This is the
/// counterpart to `placeholder_write_is_not_treated_as_a_local_edit`
/// above: that test proves the crate's OWN untouched placeholder write
/// is still correctly ignored; this one proves a REAL edit (here,
/// simulated as different-length content landing at the placeholder's
/// path) is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_direct_edit_to_a_placeholder_file_is_captured_not_silently_discarded() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let file_path = root.join("placeholder.bin");

    state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &FileRecord {
                path: "placeholder.bin".into(),
                size: 5_000_000,
                mtime_unix_nanos: 0,
                blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                    hash: vec![0xAB; 32],
                    offset: 0,
                    size: 5_000_000,
                }],
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .materialization_state_repository()
        .set_materialization_state(
            "group-1",
            "placeholder.bin",
            MaterializationState::Remote,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    // A direct user edit: real content, deliberately a different
    // length than the placeholder's own 5,000,000-byte sparse stand-in
    // -- simulating a user opening what looks like an ordinary file
    // and saving over it.
    std::fs::write(&file_path, b"the user's real, unsaved-by-the-index-yet edit").unwrap();

    let result = proc
        .process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    assert_ne!(
        result,
        LocalChangeOutcome::None,
        "a genuine edit landing at a placeholder's path must not be silently discarded as \
         self-echo"
    );
    let record =
        state.file_index_repository().get_file("group-1", "placeholder.bin").unwrap().unwrap();
    assert_eq!(
        record.size,
        b"the user's real, unsaved-by-the-index-yet edit".len() as u64,
        "the index must reflect the user's real edit, not the stale placeholder size"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_edit_while_hydrating_is_captured() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let file_path = root.join("edited-during-hydration.bin");
    std::fs::write(&file_path, b"initial bytes").unwrap();
    proc.process_event(
        "group-1",
        &root,
        &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
    )
    .await
    .unwrap();
    state
        .materialization_state_repository()
        .set_materialization_state(
            "group-1",
            "edited-during-hydration.bin",
            MaterializationState::Hydrating,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    std::fs::write(&file_path, b"new local bytes that must win").unwrap();
    let outcome = proc
        .process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    let changed = expect_file_changed(outcome);
    assert_eq!(changed.size, b"new local bytes that must win".len() as u64);
    assert_eq!(
        state.sqlite().dag_list_versions("group-1", "edited-during-hydration.bin").unwrap().len(),
        2,
        "the local edit must be retained as a second version"
    );
}

#[test]
fn scan_existing_files_skips_ignored_directories_and_leaf_files() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    let ignore_set = EffectiveIgnoreSet::from_user_patterns("node_modules/\nsrc/*.log\n");
    std::fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("node_modules/pkg/index.js"), b"ignored dependency").unwrap();
    std::fs::write(root.join("src/debug.log"), b"ignored log").unwrap();
    std::fs::write(root.join("src/keep.txt"), b"kept").unwrap();
    std::fs::write(root.join(".yadorilinkignore"), b"node_modules/\n").unwrap();

    let records = proc.scan_existing_files_with_ignore("group-1", &root, &ignore_set).unwrap();
    let paths: Vec<&str> = records.iter().map(|r| r.path.as_str()).collect();
    // `src` is a directory the user made, captured as an entry of its own;
    // the ignored `node_modules/` is not.
    assert_eq!(paths, vec!["src", "src/keep.txt"]);
    assert!(state
        .file_index_repository()
        .get_file("group-1", "node_modules/pkg/index.js")
        .unwrap()
        .is_none());
    assert!(state.file_index_repository().get_file("group-1", "src/debug.log").unwrap().is_none());
    assert!(state
        .file_index_repository()
        .get_file("group-1", ".yadorilinkignore")
        .unwrap()
        .is_none());
}

#[test]
fn scan_existing_files_drops_newly_ignored_index_entries_without_tombstones() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    std::fs::write(root.join("keep.txt"), b"kept").unwrap();
    std::fs::write(root.join("ignored.txt"), b"still on disk").unwrap();
    let first_scan = proc.scan_existing_files("group-1", &root).unwrap();
    assert_eq!(first_scan.len(), 2);
    assert!(state.file_index_repository().get_file("group-1", "ignored.txt").unwrap().is_some());

    let ignore_set = EffectiveIgnoreSet::from_user_patterns("ignored.txt\n");
    let rescan = proc.scan_existing_files_with_ignore("group-1", &root, &ignore_set).unwrap();

    assert!(
        rescan.iter().all(|record| record.path != "ignored.txt"),
        "newly ignored paths must not be emitted as tombstones: {rescan:?}"
    );
    assert!(state.file_index_repository().get_file("group-1", "ignored.txt").unwrap().is_none());
    assert_eq!(std::fs::read(root.join("ignored.txt")).unwrap(), b"still on disk");
    assert!(state.file_index_repository().get_file("group-1", "keep.txt").unwrap().is_some());
}

/// One file the scan cannot read must not abort the whole scan: the rest is
/// still captured.
#[cfg(unix)]
#[test]
fn scan_existing_files_continues_past_an_unreadable_file() {
    use std::os::unix::fs::PermissionsExt as _;
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    std::fs::write(root.join("good.txt"), b"readable").unwrap();
    let bad = root.join("bad.txt");
    std::fs::write(&bad, b"secret").unwrap();
    std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&bad).is_ok() {
        eprintln!("skipped: permissions do not stop this user from reading the file");
        return;
    }

    let scan = proc.scan_existing_files("group-1", &root);

    std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o644)).unwrap();
    scan.expect("an unreadable file must not abort the scan");
    assert!(state.file_index_repository().get_file("group-1", "good.txt").unwrap().is_some());
    assert!(state.file_index_repository().get_file("group-1", "bad.txt").unwrap().is_none());
}

/// Makes `name` under `root` unreadable; `None` when this user can read it anyway (root).
#[cfg(unix)]
fn make_unreadable(root: &std::path::Path, name: &str, bytes: &[u8]) -> Option<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt as _;
    let path = root.join(name);
    std::fs::write(&path, bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&path).is_ok() {
        eprintln!("skipped: permissions do not stop this user from reading the file");
        return None;
    }
    Some(path)
}

#[cfg(unix)]
fn make_readable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
}

/// A file the scan cannot read is reported with its path and reason, the healthy files still sync,
/// and restoring permission clears the report on the next pass with the file captured, no restart.
#[cfg(unix)]
#[test]
fn an_unreadable_file_is_reported_and_clears_when_it_can_be_read_again() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    std::fs::write(root.join("good.txt"), b"readable").unwrap();
    let Some(bad) = make_unreadable(&root, "bad.txt", b"secret") else { return };

    let records = proc.scan_existing_files("group-1", &root);
    let reported = proc.unreadable_ledger().needing_user("group-1");
    let records = records.expect("an unreadable file must not abort the scan");

    assert_eq!(
        reported,
        [crate::unreadable::UnreadableFile {
            path: "bad.txt".to_owned(),
            reason: crate::unreadable::UnreadableReason::PermissionDenied,
        }]
    );
    assert!(records.iter().any(|r| r.path == "good.txt"), "healthy files still sync");
    assert!(state.file_index_repository().get_file("group-1", "bad.txt").unwrap().is_none());

    // Still failing: still reported once, not duplicated.
    proc.scan_existing_files("group-1", &root).unwrap();
    assert_eq!(proc.unreadable_ledger().needing_user("group-1").len(), 1);

    make_readable(&bad);
    let records = proc.scan_existing_files("group-1", &root).unwrap();
    assert!(proc.unreadable_ledger().needing_user("group-1").is_empty());
    assert!(records.iter().any(|r| r.path == "bad.txt"), "the path resumes syncing");
    assert!(state.file_index_repository().get_file("group-1", "bad.txt").unwrap().is_some());
}

/// A file that was already indexed and then became unreadable is never read as deleted or empty:
/// its row and versions stay exactly as they were, no record is produced for it, and the report
/// ends through the add-only backstop (which never re-reads indexed files) once it opens again.
#[cfg(unix)]
#[test]
fn an_indexed_file_that_becomes_unreadable_keeps_its_row_and_clears_through_the_backstop() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let doc = root.join("doc.txt");
    std::fs::write(&doc, b"original bytes").unwrap();
    proc.scan_existing_files("group-1", &root).unwrap();
    let before = state.file_index_repository().get_file("group-1", "doc.txt").unwrap().unwrap();
    let versions_before = state.sqlite().dag_list_versions("group-1", "doc.txt").unwrap().len();

    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&doc, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&doc).is_ok() {
        eprintln!("skipped: permissions do not stop this user from reading the file");
        return;
    }

    let records = proc.scan_existing_files("group-1", &root).unwrap();
    assert!(records.iter().all(|r| r.path != "doc.txt"), "no record, tombstone or empty version");
    let after = state.file_index_repository().get_file("group-1", "doc.txt").unwrap().unwrap();
    assert!(!after.deleted, "an unreadable file is not a deleted one");
    assert_eq!(after.size, before.size);
    assert_eq!(after.blocks, before.blocks, "never recorded as empty");
    assert_eq!(
        state.sqlite().dag_list_versions("group-1", "doc.txt").unwrap().len(),
        versions_before
    );
    assert_eq!(proc.unreadable_ledger().needing_user("group-1").len(), 1);

    // The backstop keeps the report while the file stays unreadable...
    proc.reconcile_added_files("group-1", &root).unwrap();
    assert_eq!(proc.unreadable_ledger().needing_user("group-1").len(), 1);
    // ...and ends it once the file opens again, without a full pass.
    make_readable(&doc);
    proc.reconcile_added_files("group-1", &root).unwrap();
    assert!(proc.unreadable_ledger().needing_user("group-1").is_empty());
}

/// A report whose directory later becomes unreadable is kept: the scan never reached the file,
/// so it cannot say the file recovered.
#[cfg(unix)]
#[test]
fn a_report_under_a_directory_the_scan_cannot_walk_is_kept() {
    use std::os::unix::fs::PermissionsExt as _;
    let (proc, _state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    let dir = root.join("sub");
    std::fs::create_dir(&dir).unwrap();
    let Some(_bad) = make_unreadable(&dir, "bad.txt", b"secret") else { return };
    proc.scan_existing_files("group-1", &root).unwrap();
    assert_eq!(proc.unreadable_ledger().needing_user("group-1").len(), 1);

    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    let scan = proc.scan_existing_files("group-1", &root);
    let kept = proc.unreadable_ledger().needing_user("group-1");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    scan.unwrap();
    let paths: Vec<_> = kept.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(
        paths,
        ["sub", "sub/bad.txt"],
        "an entry the scan could not reach is not read as recovered, and the directory is reported"
    );
}

/// A directory the walk cannot read is reported with its own path and reason, clears through the
/// backstop once it lists again, and clears through a full pass too.
#[cfg(unix)]
#[test]
fn an_unreadable_directory_is_reported_and_clears_when_it_can_be_read_again() {
    use std::os::unix::fs::PermissionsExt as _;
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let dir = root.join("locked");
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("inside.txt"), b"x").unwrap();
    std::fs::write(root.join("good.txt"), b"fine").unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read_dir(&dir).is_ok() {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        eprintln!("skipped: permissions do not stop this user from listing the directory");
        return;
    }

    let scan = proc.scan_existing_files("group-1", &root);
    let reported = proc.unreadable_ledger().needing_user("group-1");
    assert!(scan.is_ok(), "an unreadable directory does not abort the scan");
    assert_eq!(
        reported,
        [crate::unreadable::UnreadableFile {
            path: "locked".to_owned(),
            reason: crate::unreadable::UnreadableReason::PermissionDenied,
        }]
    );

    // The backstop ends the report once the directory lists again, without a full pass.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    proc.reconcile_added_files("group-1", &root).unwrap();
    assert!(proc.unreadable_ledger().needing_user("group-1").is_empty());

    // And a full pass drops it as well.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    proc.scan_existing_files("group-1", &root).unwrap();
    assert_eq!(proc.unreadable_ledger().needing_user("group-1").len(), 1);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    proc.scan_existing_files("group-1", &root).unwrap();
    assert!(proc.unreadable_ledger().needing_user("group-1").is_empty());
}

/// A file that fails to read in the live event path is reported without waiting for a full scan,
/// the event still fails exactly as before (so the flush retries and journals it), and the event
/// that follows restoring permission clears the report at once, even though the indexed file's
/// size and mtime did not change.
#[cfg(unix)]
#[tokio::test]
async fn a_live_event_reports_an_unreadable_file_and_its_restoration_clears_it() {
    use std::os::unix::fs::PermissionsExt as _;
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let doc = root.join("doc.txt");
    std::fs::write(&doc, b"original bytes").unwrap();
    proc.scan_existing_files("group-1", &root).unwrap();
    let event = FsChangeEvent { path: doc.clone(), kind: FsChangeKind::CreatedOrModified };

    std::fs::set_permissions(&doc, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&doc).is_ok() {
        eprintln!("skipped: permissions do not stop this user from reading the file");
        return;
    }
    let failed = proc.process_event("group-1", &root, &event).await;
    assert!(failed.is_err(), "the event fails as before, so the flush retries and journals it");
    assert_eq!(
        proc.unreadable_ledger().needing_user("group-1"),
        [crate::unreadable::UnreadableFile {
            path: "doc.txt".to_owned(),
            reason: crate::unreadable::UnreadableReason::PermissionDenied,
        }],
        "reported by the live path itself, no full scan needed"
    );

    make_readable(&doc);
    proc.process_event("group-1", &root, &event).await.unwrap();
    assert!(
        proc.unreadable_ledger().needing_user("group-1").is_empty(),
        "the attribute-change event clears the report without waiting for the backstop"
    );
}

/// The backstop's check of a standing report never opens a replacement that is not a regular
/// file (a FIFO with no writer would block it forever).
#[cfg(unix)]
#[test]
fn the_backstop_does_not_open_a_fifo_that_replaced_a_reported_file() {
    let (proc, _state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&_state, "group-1", &root);
    let Some(bad) = make_unreadable(&root, "bad.txt", b"secret") else { return };
    proc.scan_existing_files("group-1", &root).unwrap();
    std::fs::remove_file(&bad).unwrap();
    let made = std::process::Command::new("mkfifo").arg(&bad).status().unwrap();
    assert!(made.success());

    proc.reconcile_added_files("group-1", &root).unwrap();

    assert_eq!(proc.unreadable_ledger().needing_user("group-1").len(), 1, "left for a full pass");
}

/// A block-store fault wears the same error shape as a failed read of the file, but the file is
/// readable: the scan still aborts on it and nothing is reported as unreadable.
#[test]
fn a_block_store_fault_is_not_reported_as_an_unreadable_file() {
    let (proc, _state, store, _store_dir, root_dir) = processor_with_counting_store();
    let root = canonical_root(&root_dir);
    // Enough bytes that the scan's staging pool flushes while a file is still being built,
    // which is where a store fault reaches the per-file handling.
    for i in 0..4u8 {
        std::fs::write(root.join(format!("fine{i}.bin")), vec![i + 1; 12 * 1024 * 1024]).unwrap();
    }
    store.fail_every_batch_with_not_found();

    let scan = proc.scan_existing_files("group-1", &root);

    assert!(scan.is_err(), "a store fault aborts the scan as before");
    assert!(proc.unreadable_ledger().standing("group-1").is_empty(), "no file is blamed for it");
}

#[cfg(unix)]
fn write_scan_files(root: &std::path::Path) {
    // Enough bytes that the scan's staging pool flushes while a file is still being built.
    for i in 0..4u8 {
        std::fs::write(root.join(format!("fine{i}.bin")), vec![i + 1; 12 * 1024 * 1024]).unwrap();
    }
}

/// The block store fails with PermissionDenied while the synced file also turns unreadable
/// (PermissionDenied) at that moment: the store's fault is not a user file, so the scan aborts
/// and nothing is reported as unreadable.
#[cfg(unix)]
#[test]
fn a_store_permission_fault_aborts_even_when_the_source_is_also_unreadable() {
    let (proc, _state, store, _store_dir, root_dir) = processor_with_counting_store();
    let root = canonical_root(&root_dir);
    write_scan_files(&root);
    let files: Vec<_> = (0..4u8).map(|i| root.join(format!("fine{i}.bin"))).collect();
    store.deny_every_batch(files.clone());

    let scan = proc.scan_existing_files("group-1", &root);

    let readable = std::fs::File::open(&files[3]).is_ok();
    files.iter().for_each(|f| make_readable(f));
    if readable {
        eprintln!("skipped: permissions do not stop this user from reading the file");
        return;
    }
    assert!(scan.is_err(), "a store fault aborts the scan");
    assert!(proc.unreadable_ledger().standing("group-1").is_empty(), "no file is blamed for it");
}

/// Control: the same store fault with every source readable aborts too.
#[cfg(unix)]
#[test]
fn a_store_permission_fault_with_readable_sources_aborts() {
    let (proc, _state, store, _store_dir, root_dir) = processor_with_counting_store();
    let root = canonical_root(&root_dir);
    write_scan_files(&root);
    store.deny_every_batch(Vec::new());

    assert!(proc.scan_existing_files("group-1", &root).is_err());
    assert!(proc.unreadable_ledger().standing("group-1").is_empty());
}

/// Converse: only the source is unreadable (the store is healthy): the file is skipped and
/// reported, the scan completes.
#[cfg(unix)]
#[test]
fn an_unreadable_source_with_a_healthy_store_is_skipped_and_reported() {
    let (proc, _state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    std::fs::write(root.join("fine.txt"), b"ok").unwrap();
    let Some(bad) = make_unreadable(&root, "bad.txt", b"secret") else { return };

    let scan = proc.scan_existing_files("group-1", &root);
    make_readable(&bad);

    scan.expect("an unreadable file does not abort the scan");
    assert_eq!(proc.unreadable_ledger().standing("group-1"), ["bad.txt"]);
}

/// A read of the file that fails after it opened (an EIO partway through) is the file's failure:
/// the scan skips it and the ledger counts it toward persistent, while the same error shape from
/// the block store still aborts the scan.
#[test]
fn a_read_error_after_the_file_opened_is_the_files_and_a_store_fault_is_not() {
    use crate::unreadable::{UnreadableClass, UnreadableReason};
    use yadorilink_local_storage::StorageError;
    use yadorilink_sync_sqlite::SyncSqliteError;
    let (proc, _state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    std::fs::write(root.join("fine.txt"), b"readable").unwrap();
    // Not a raw errno: on Windows 5 is "access denied", a permission failure.
    let eio = || std::io::Error::other("input/output error");
    let wrap = |e: StorageError| LocalCaptureError::SyncCore(SyncSqliteError::Storage(e));

    let mut failed = Vec::new();
    proc.unreadable_file("group-1", "fine.txt", wrap(StorageError::SourceRead(eio())), &mut failed)
        .expect("a failed read of the source file is skipped");
    assert_eq!(failed, ["fine.txt"], "deletions under the file stay suppressed");
    assert_eq!(proc.unreadable_ledger().standing("group-1"), ["fine.txt"]);
    assert!(
        proc.unreadable_ledger().needing_user("group-1").is_empty(),
        "a first read error is passing, not yet shown"
    );

    let mut failed = Vec::new();
    let store_fault =
        proc.unreadable_file("group-1", "fine2.txt", wrap(StorageError::Io(eio())), &mut failed);
    assert!(store_fault.is_err(), "the same error from the block store aborts the scan");
    assert!(failed.is_empty());
    assert_eq!(proc.unreadable_ledger().standing("group-1"), ["fine.txt"]);

    // Failing again and again over time moves it to the person.
    let t0 = std::time::Instant::now();
    let reason = UnreadableReason::ReadFailed;
    proc.unreadable_ledger().record_failure("group-1", "fine.txt", reason, t0);
    let later = t0 + crate::unreadable::PERSISTENT_AFTER;
    let last = proc.unreadable_ledger().record_failure("group-1", "fine.txt", reason, later);
    assert_eq!(last.class, UnreadableClass::NeedsUser);
}

/// Removing the file ends the report on the next full pass.
#[cfg(unix)]
#[test]
fn removing_an_unreadable_file_clears_its_report() {
    let (proc, _state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    let Some(bad) = make_unreadable(&root, "bad.txt", b"secret") else { return };
    proc.scan_existing_files("group-1", &root).unwrap();
    assert_eq!(proc.unreadable_ledger().needing_user("group-1").len(), 1);

    std::fs::remove_file(&bad).unwrap();
    proc.scan_existing_files("group-1", &root).unwrap();
    assert!(proc.unreadable_ledger().needing_user("group-1").is_empty());
}

#[test]
fn scan_existing_files_indexes_previously_ignored_file_after_pattern_removal() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    std::fs::write(root.join("build.log"), b"now wanted").unwrap();
    let ignored = EffectiveIgnoreSet::from_user_patterns("*.log\n");
    let first_scan = proc.scan_existing_files_with_ignore("group-1", &root, &ignored).unwrap();
    assert!(first_scan.is_empty());
    assert!(state.file_index_repository().get_file("group-1", "build.log").unwrap().is_none());

    let unignored = EffectiveIgnoreSet::defaults_only();
    let rescan = proc.scan_existing_files_with_ignore("group-1", &root, &unignored).unwrap();

    assert_eq!(rescan.len(), 1);
    assert_eq!(rescan[0].path, "build.log");
    assert!(state.file_index_repository().get_file("group-1", "build.log").unwrap().is_some());
}

/// a single scan correctly handles
/// a mix of already-current, changed, and brand-new files together,
/// using the bulk-loaded `list_files`/`list_materialization_states`
/// maps rather than a per-file lookup for any of them.
#[test]
fn scan_existing_files_handles_a_mix_of_unchanged_changed_and_new_files() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);

    std::fs::write(root.join("unchanged.txt"), b"same content").unwrap();
    let first_scan = proc.scan_existing_files("group-1", &root).unwrap();
    assert_eq!(first_scan.len(), 1);
    let original_version_count =
        state.sqlite().dag_list_versions("group-1", "unchanged.txt").unwrap().len();

    // Now: leave "unchanged.txt" alone, modify "unchanged.txt" would
    // contradict its name, so instead add a genuinely-changed file
    // and a genuinely-new file, then rescan everything together.
    std::fs::write(root.join("changed-later.txt"), b"v1").unwrap();
    proc.scan_existing_files("group-1", &root).unwrap();
    std::fs::write(root.join("changed-later.txt"), b"v2, now longer").unwrap();
    std::fs::write(root.join("brand-new.txt"), b"never seen before").unwrap();

    let records = proc.scan_existing_files("group-1", &root).unwrap();
    let paths: std::collections::HashSet<&str> = records.iter().map(|r| r.path.as_str()).collect();
    // "unchanged.txt" is already current (same size) so it's not
    // re-indexed by this final scan; the other two are.
    assert_eq!(paths, std::collections::HashSet::from(["changed-later.txt", "brand-new.txt"]));

    assert_eq!(
        state.sqlite().dag_list_versions("group-1", "unchanged.txt").unwrap().len(),
        original_version_count,
        "untouched file's version must not bump"
    );
    let changed =
        state.file_index_repository().get_file("group-1", "changed-later.txt").unwrap().unwrap();
    assert_eq!(changed.size, "v2, now longer".len() as u64);
}

/// A full scan is authoritative only when its root was actually
/// traversable. A temporarily unavailable mount/root must not look like
/// an empty directory and turn every previously indexed path into a
/// tombstone that is then propagated to the mesh.
#[test]
fn root_unavailable_scan_must_not_tombstone_indexed_files() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    std::fs::write(root.join("survives.txt"), b"durable bytes").unwrap();
    proc.scan_existing_files("group-1", &root).unwrap();

    std::fs::remove_dir_all(&root).unwrap();
    let result = proc.scan_existing_files("group-1", &root);

    assert!(result.is_err(), "an unavailable scan root must not be reported as complete");
    let indexed =
        state.file_index_repository().get_file("group-1", "survives.txt").unwrap().unwrap();
    assert!(!indexed.deleted, "an incomplete scan must never create a tombstone");
}

/// The case an existence check structurally cannot catch, and the reason the
/// guard is an identity check rather than an availability one: unmounting a
/// volume leaves its mountpoint behind as an ordinary EMPTY directory. The
/// root still exists, still canonicalizes, still walks — it just has nothing
/// in it. Every indexed file therefore looks deleted, and a full scan is
/// authoritative, so without this the whole folder tombstones and those
/// tombstones replicate to every device: unplugging a drive destroys the
/// data everywhere.
///
/// Deliberately does NOT `remove_dir_all` the root — that is the
/// already-covered root-*removed* case above, which the old
/// `canonicalize()?` guard caught. The point here is that the directory is
/// present and readable and the scan must still refuse.
#[test]
fn empty_but_present_root_must_not_tombstone_indexed_files() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    std::fs::write(root.join("survives.txt"), b"durable bytes").unwrap();
    proc.scan_existing_files("group-1", &root).unwrap();
    // Simulate the unmount: the mountpoint directory survives, empty. The
    // marker went with the volume, exactly as the content did — that is why
    // it is the marker, and not the path, that carries the identity.
    std::fs::remove_file(root.join("survives.txt")).unwrap();
    std::fs::remove_file(
        root.join(yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME),
    )
    .unwrap();
    assert!(root.is_dir(), "the mountpoint directory must still be present for this test");
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0, "and it must be empty");

    let result = proc.scan_existing_files("group-1", &root);

    assert!(
        result.is_err(),
        "an empty-but-present root is indistinguishable from an unmounted volume and must \
         not be reported as an authoritative empty scan"
    );
    let indexed =
        state.file_index_repository().get_file("group-1", "survives.txt").unwrap().unwrap();
    assert!(
        !indexed.deleted,
        "a scan that could not establish its root's identity must emit no tombstone"
    );
}

/// The wrong-volume variant: something IS mounted at the root and it does
/// carry a marker, but the marker is not this link's. A restored backup,
/// another device's copy of the same folder, or a different volume mounted
/// at the same path. Its contents are not this link's history, so scanning
/// it authoritatively would tombstone everything the real folder holds.
#[test]
fn a_root_marked_for_a_different_link_must_not_tombstone_indexed_files() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    std::fs::write(root.join("survives.txt"), b"durable bytes").unwrap();
    proc.scan_existing_files("group-1", &root).unwrap();

    // Swap in a foreign volume: same path, populated, but a marker naming a
    // different group and token.
    std::fs::remove_file(root.join("survives.txt")).unwrap();
    std::fs::write(root.join("someone-elses-file.txt"), b"not ours").unwrap();
    std::fs::write(
        root.join(yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME),
        br#"{"group_id":"a-different-group","root_token":"0123456789abcdef"}"#,
    )
    .unwrap();

    let result = proc.scan_existing_files("group-1", &root);

    assert!(result.is_err(), "a root carrying another link's marker must be refused");
    let indexed =
        state.file_index_repository().get_file("group-1", "survives.txt").unwrap().unwrap();
    assert!(!indexed.deleted, "refusing must emit no tombstone");
    assert!(
        state
            .file_index_repository()
            .get_file("group-1", "someone-elses-file.txt")
            .unwrap()
            .is_none(),
        "and must not index the foreign volume's contents into this group"
    );
}

/// The token half of the check, isolated: the marker names the right group,
/// so only the persisted token can tell this folder from the real one. This
/// is the restored-backup / duplicated-copy case — the group is genuinely
/// ours, the folder is not.
#[test]
fn a_root_whose_marker_token_is_not_the_adopted_one_must_not_tombstone_indexed_files() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    std::fs::write(root.join("survives.txt"), b"durable bytes").unwrap();
    proc.scan_existing_files("group-1", &root).unwrap();
    state.link_repository().add_link(&root.to_string_lossy(), "group-1").unwrap();
    state
        .link_repository()
        .set_link_root_token_for_group("group-1", "the-token-we-really-adopted")
        .unwrap();

    std::fs::remove_file(root.join("survives.txt")).unwrap();
    std::fs::write(
        root.join(yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME),
        br#"{"group_id":"group-1","root_token":"a-stale-token-from-a-copy"}"#,
    )
    .unwrap();

    let result = proc.scan_existing_files("group-1", &root);

    assert!(result.is_err(), "a marker whose token is not the adopted one must be refused");
    let indexed =
        state.file_index_repository().get_file("group-1", "survives.txt").unwrap().unwrap();
    assert!(!indexed.deleted, "refusing must emit no tombstone");
}

/// The backfill path that makes the guard deployable: an install that
/// predates root identity has no marker on any link. Refusing those would
/// break every existing install on upgrade, so a root that corroborates the
/// index (its files are really there) is adopted in place and scans on.
#[test]
fn an_unmarked_root_that_still_holds_its_indexed_files_is_adopted_on_upgrade() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    std::fs::write(root.join("survives.txt"), b"durable bytes").unwrap();
    proc.scan_existing_files("group-1", &root).unwrap();
    // Rewind to the pre-upgrade shape: index populated, no marker anywhere.
    std::fs::remove_file(
        root.join(yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME),
    )
    .unwrap();

    let records = proc.scan_existing_files("group-1", &root).unwrap();

    assert!(
        root.join(yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME).exists(),
        "the upgrade boot must adopt the folder it just corroborated"
    );
    assert!(!records.iter().any(|r| r.deleted), "adoption must not tombstone anything");
    let indexed =
        state.file_index_repository().get_file("group-1", "survives.txt").unwrap().unwrap();
    assert!(!indexed.deleted);
}

/// Indexes a `Present`-but-missing file: a `FileRecord` with real block
/// info marked `Present`, whose bytes are NOT present on disk. This is the
/// shape the startup Full scan sees for both a crash-mid-materialize (the
/// rename never completed) and a genuine offline deletion — the two are told
/// apart only by the materialization intent.
fn index_hydrated_missing_file(state: &ReplicaCoordinator, group: &str, path: &str) {
    state
        .file_index_repository()
        .upsert_file(
            group,
            &FileRecord {
                path: path.into(),
                size: 11,
                mtime_unix_nanos: 0,
                blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                    hash: vec![0xAB; 32],
                    offset: 0,
                    size: 11,
                }],
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .materialization_state_repository()
        .set_materialization_state(
            group,
            path,
            MaterializationState::Present,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
}

/// The crux crash-safety guarantee: a crash mid-eager-materialize leaves a
/// `Present` row whose file is missing but whose write is still recorded by
/// an OPEN materialization intent. The startup Full scan must NOT tombstone
/// it — it is reconstructable from the locally-present blocks and repair
/// will heal it. Tombstoning here would propagate a `Delete` group-wide and
/// silently destroy a fully-reconstructable file.
#[test]
fn crash_mid_materialize_missing_file_with_open_intent_is_not_tombstoned() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    index_hydrated_missing_file(&state, "group-1", "doc.txt");
    // The durable "materialization write in progress" signal a crash left
    // behind — the disambiguator that makes this a crash, not a deletion.
    state
        .materialization_intent_repository()
        .begin_materialization_intent(
            "group-1",
            "doc.txt",
            &[0xAB; 32],
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    // A normal boot's Full scan (tombstones enabled). The file is absent
    // from disk, so it is a tombstone candidate — but the open intent must
    // veto that.
    let records = proc.scan_existing_files("group-1", &root).unwrap();

    assert!(
        !records.iter().any(|r| r.path == "doc.txt" && r.deleted),
        "a missing file with an open materialization intent must not be tombstoned"
    );
    let indexed = state.file_index_repository().get_file("group-1", "doc.txt").unwrap().unwrap();
    assert!(!indexed.deleted, "the index row must be left intact for repair to reconstruct");
}

/// A hazard-held path -- `hold_record`'s established shape: `Remote`,
/// `held_reason` set, nothing written under this exact name, no
/// materialization intent ever opened, and (simulating the settled state
/// `HazardHeld` completion leaves behind) no projection obligation either
/// -- must never be tombstoned by a Full rescan just because it is absent
/// from disk under that name. It is this device's own deliberate,
/// per-device refusal to materialize a name that collides with something
/// else, not a deletion, and the file stays valid and present on every
/// other peer. Before the `is_held` check, this scenario had NEITHER of
/// the two existing veto signals (no intent, no obligation) and would
/// have been silently tombstoned.
#[test]
fn a_hazard_held_path_is_not_tombstoned_by_a_full_rescan() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &FileRecord {
                path: "CON.txt".into(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    state
        .materialization_state_repository()
        .set_materialization_state("group-1", "CON.txt", MaterializationState::Remote, &permit)
        .unwrap();
    state
        .materialization_state_repository()
        .set_held("group-1", "CON.txt", "invalid_name", 0)
        .unwrap();
    // Deliberately no intent and no seeded projection obligation --
    // exactly the state a settled `HazardHeld` completion (which deletes
    // the obligation row) leaves a held path in.

    let records = proc.scan_existing_files("group-1", &root).unwrap();

    assert!(
        !records.iter().any(|r| r.path == "CON.txt" && r.deleted),
        "a hazard-held path must never be tombstoned by a full rescan: {records:?}"
    );
    let indexed = state.file_index_repository().get_file("group-1", "CON.txt").unwrap().unwrap();
    assert!(!indexed.deleted, "the held row's index must be left intact");
}

/// A metadata-unprovable hold is recorded against a file that was on disk,
/// so unlike a hazard hold it must not protect a missing file from being
/// read as deleted -- even on a `Remote` row, which is exactly where a
/// hazard hold's protection applies. Otherwise a user's delete of a held
/// placeholder is dropped and the next pass writes the placeholder back.
#[test]
fn a_metadata_unprovable_hold_does_not_suppress_a_real_delete() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &FileRecord {
                path: "write-only.txt".into(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    // The user's file stood there (its metadata merely could not be proven),
    // so the row names a local object: `Present`, and held.
    state
        .materialization_state_repository()
        .set_materialization_state(
            "group-1",
            "write-only.txt",
            MaterializationState::Present,
            &permit,
        )
        .unwrap();
    state
        .materialization_state_repository()
        .set_held(
            "group-1",
            "write-only.txt",
            &format!(
                "{}: the existing file is owner-unreadable",
                yadorilink_replica_domain::session_state::HELD_REASON_METADATA_UNPROVABLE
            ),
            0,
        )
        .unwrap();
    // The file itself is gone from disk: the user deleted it.

    let records = proc.scan_existing_files("group-1", &root).unwrap();

    assert!(
        records.iter().any(|r| r.path == "write-only.txt" && r.deleted),
        "a file held only for unprovable metadata that is now missing was deleted: {records:?}"
    );
}

/// The inverse of the test above, in the missed-delete direction: a
/// row that is genuinely, currently `Present` (a later, successful
/// materialize really did write real content and stamp it) but still
/// carries a STALE `held_reason` -- `clear_held`/`set_materialization_
/// state` are separate calls, not one atomic operation, so a crash (or
/// simply an as-yet-unrun hazard recheck) between them can leave this
/// exact combination -- must still be tombstoned like any other
/// genuine offline deletion. `is_held` alone would suppress this
/// forever; the row's own current, real `materialization_state` is
/// what actually decides whether it needs this scan's protection.
#[test]
fn a_stale_held_reason_on_a_genuinely_hydrated_row_does_not_suppress_a_real_delete() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    index_hydrated_missing_file(&state, "group-1", "stale-hold.txt");
    state
        .materialization_state_repository()
        .set_held("group-1", "stale-hold.txt", "invalid_name", 0)
        .unwrap();
    // No intent, no obligation -- same as the genuine-offline-deletion
    // sibling test below; the only difference from the "must NOT
    // tombstone" test above is that this row is `Present`, not
    // `Remote` (via `index_hydrated_missing_file`), with a stale
    // `held_reason` left over from some earlier, now-irrelevant hold.

    let records = proc.scan_existing_files("group-1", &root).unwrap();

    assert!(
        records.iter().any(|r| r.path == "stale-hold.txt" && r.deleted),
        "a genuinely Hydrated row's real deletion must not be suppressed forever by a \
         stale held_reason left over from an earlier, now-irrelevant hold: {records:?}"
    );
    let indexed =
        state.file_index_repository().get_file("group-1", "stale-hold.txt").unwrap().unwrap();
    assert!(indexed.deleted, "the genuine offline deletion must be recorded as a tombstone");
}

/// The behavior that MUST be preserved alongside the fix: a file that was
/// cleanly materialized (no lingering intent) and then deleted or renamed
/// away while the daemon was stopped is a genuine offline deletion. The
/// startup Full scan must still tombstone it so the deletion propagates.
#[test]
fn offline_deleted_hydrated_file_with_no_intent_is_still_tombstoned() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    // The root is verified and really is this link's folder, so a missing
    // file here is a genuine deletion, not an unmounted volume.
    adopt_root(&state, "group-1", &root);
    index_hydrated_missing_file(&state, "group-1", "gone.txt");
    // No materialization intent: the write had completed and its intent was
    // cleared, so the missing file is a real deletion.

    let records = proc.scan_existing_files("group-1", &root).unwrap();

    assert!(
        records.iter().any(|r| r.path == "gone.txt" && r.deleted),
        "a missing file with no materialization intent must still be tombstoned"
    );
    let indexed = state.file_index_repository().get_file("group-1", "gone.txt").unwrap().unwrap();
    assert!(indexed.deleted, "the genuine offline deletion must be recorded as a tombstone");
}

/// Indexes a live, settled explicit Directory row at `path`: blockless,
/// `Present`, no intent and no obligation -- exactly what F4's directory
/// lane leaves behind once it has materialized a peer's Directory version.
fn index_settled_directory(state: &ReplicaCoordinator, group: &str, path: &str) {
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .file_index_repository()
        .upsert_file(
            group,
            &FileRecord {
                path: path.into(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    state
        .file_index_repository()
        .set_record_kind(group, path, RecordKind::Directory, &permit)
        .unwrap();
    state
        .materialization_state_repository()
        .set_materialization_state(group, path, MaterializationState::Present, &permit)
        .unwrap();
}

/// A settled explicit Directory is present when a directory stands at its
/// name. The walk admits only files and symlinks, so without this the full
/// scan reads every settled Directory as an offline deletion and signs a
/// group-wide Delete for it on the next restart.
#[test]
fn full_scan_does_not_tombstone_a_settled_directory_that_is_still_on_disk() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    std::fs::create_dir(root.join("docs")).unwrap();
    index_settled_directory(&state, "group-1", "docs");

    let records = proc.scan_existing_files("group-1", &root).unwrap();

    assert!(
        !records.iter().any(|r| r.path == "docs" && r.deleted),
        "a Directory row whose directory is on disk must not be tombstoned: {records:?}"
    );
    let indexed = state.file_index_repository().get_file("group-1", "docs").unwrap().unwrap();
    assert!(!indexed.deleted, "the settled Directory row must stay live");
}

/// The other half: a settled Directory that is really gone offline is
/// still a deletion.
#[test]
fn full_scan_tombstones_a_settled_directory_removed_offline() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    index_settled_directory(&state, "group-1", "gone");

    let records = proc.scan_existing_files("group-1", &root).unwrap();

    assert!(
        records.iter().any(|r| r.path == "gone" && r.deleted),
        "a Directory removed offline must still be tombstoned: {records:?}"
    );
}

/// The defense-in-depth gate: when the startup interrupted-materialization
/// repair pass ERRORED for the group this boot, its crash-vs-offline-delete
/// disambiguation is unavailable, so the Full scan must emit NO deletes this
/// boot — even for a missing file with no intent (which, on a healthy boot,
/// would be a genuine deletion). The delete is deferred to a later boot on
/// which repair succeeds. Fail-closed.
#[test]
fn repair_errored_boot_suppresses_all_scan_tombstones() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    index_hydrated_missing_file(&state, "group-1", "deferred.txt");
    // Deliberately NO intent: on a healthy boot this would tombstone. The
    // repair-errored gate must still withhold it.
    let ignore_set = EffectiveIgnoreSet::from_user_patterns("");

    let records =
        proc.scan_existing_files_with_ignore_gated("group-1", &root, &ignore_set, false).unwrap();

    assert!(
        !records.iter().any(|r| r.deleted),
        "no delete may be emitted on a boot whose repair errored for the group"
    );
    let indexed =
        state.file_index_repository().get_file("group-1", "deferred.txt").unwrap().unwrap();
    assert!(!indexed.deleted, "the delete decision must be deferred, not recorded this boot");

    // And the same missing file DOES tombstone once repair is healthy
    // (tombstones enabled) — proving the gate, not the file, was the reason
    // it was spared above.
    let healthy =
        proc.scan_existing_files_with_ignore_gated("group-1", &root, &ignore_set, true).unwrap();
    assert!(
        healthy.iter().any(|r| r.path == "deferred.txt" && r.deleted),
        "the deferred deletion must propagate on a later healthy boot"
    );
}

/// A scan's store cost must be exactly known: one `put` per new file's
/// single block on the first pass, and — the part that carries the
/// weight — **zero** puts on a rescan that finds nothing changed.
///
/// This is asserted by counting rather than by timing, because a
/// wall-clock bound cannot express the property. Every `put` costs two
/// fsyncs (the block's own `sync_all`, plus the directory `sync_all` that
/// publishes it), so a scan's elapsed time is set by the filesystem behind
/// `TMPDIR`, not by the scan's algorithm: the same code on the same commit
/// runs in well under a second on tmpfs, where fsync is free, and in tens
/// of seconds to minutes on ext4, overlayfs, or APFS, where it is not. No
/// single bound both fails on a real regression and passes on ordinary
/// hardware, so a timed version of this test measures the disk instead of
/// the code — and a scan that got 50x algorithmically slower would still
/// sit far inside any bound loose enough to be green on a real disk.
///
/// Counting also catches what a timing bound provably cannot. The rescan's
/// no-op is *not* established by the returned records being empty: a
/// rescan that re-chunked every file would still return nothing, because
/// re-chunking unchanged bytes reproduces the identical block hashes and
/// the resulting record is then suppressed as a self-echo — after paying a
/// full re-chunk and two fsyncs per file. Only the put count tells those
/// two apart, which is the reason `CountingBlockStore` exists (see its
/// doc).
///
/// `FILE_COUNT` is deliberately small. Once the assertion is an exact
/// count instead of a stopwatch, per-file work is visible at any count
/// above one, so writing thousands of files — and paying thousands of
/// fsyncs — buys no additional detection.
#[test]
fn scan_puts_one_block_per_new_file_and_rescans_without_touching_the_store() {
    let (proc, state, store, _store_dir, root_dir) = processor_with_counting_store();
    let root = canonical_root(&root_dir);

    // Each file is far below one chunk, so "one put per file" is the
    // entire store cost of indexing the set.
    const FILE_COUNT: usize = 24;
    for i in 0..FILE_COUNT {
        std::fs::write(root.join(format!("object-{i}.bin")), format!("content {i}")).unwrap();
    }

    let records = proc.scan_existing_files("group-1", &root).unwrap();
    assert_eq!(records.len(), FILE_COUNT);
    assert_eq!(state.file_index_repository().list_files("group-1").unwrap().len(), FILE_COUNT);
    assert_eq!(
        store.put_call_count(),
        FILE_COUNT,
        "indexing {FILE_COUNT} single-block files must cost exactly one block put each; \
         a higher count means a file was chunked more than once in a single scan"
    );

    // A rescan with nothing changed must be settled entirely by the
    // size+mtime gate and its content verification, which reads bytes but
    // never writes a block.
    let second_scan = proc.scan_existing_files("group-1", &root).unwrap();
    assert!(second_scan.is_empty(), "an unchanged folder must not be re-indexed on rescan");
    assert_eq!(
        store.put_call_count(),
        FILE_COUNT,
        "a rescan that finds nothing changed must not put a single block; a count that grew \
         here means every unchanged file was re-chunked and re-stored at two fsyncs apiece, \
         which the empty record list asserted above cannot detect"
    );
}

/// The point of the whole cross-file pool: a scan of many small files
/// must commit their blocks as ONE bulk batch, not one batch per file.
///
/// This is the shape that made per-file batching worthless. Every file
/// here is a single block, so a per-file producer -- which is what
/// `chunk_file`/`chunk_file_*_with_callback` are, batching only within
/// the file they were called on -- produces a one-block batch per file
/// and shares no durability barrier with anything. Asserting on the
/// batch SHAPE rather than the block count is deliberate: the block
/// count was already right before this change, and is exactly what
/// failed to notice that each block was paying its own `root/aa`
/// directory fsync.
#[test]
fn a_scan_pools_blocks_across_file_boundaries_into_one_bulk_batch() {
    let (proc, state, store, _store_dir, root_dir) = processor_with_counting_store();
    let root = canonical_root(&root_dir);

    // Well under the 4096-block pool bound and far under its byte
    // bound, so the whole scan is one batch and any second batch means
    // something flushed per file (or per some other sub-scan unit).
    const FILE_COUNT: usize = 300;
    for i in 0..FILE_COUNT {
        std::fs::write(root.join(format!("small-{i}.txt")), format!("content {i}")).unwrap();
    }

    let records = proc.scan_existing_files("group-1", &root).unwrap();
    assert_eq!(records.len(), FILE_COUNT);
    assert_eq!(state.file_index_repository().list_files("group-1").unwrap().len(), FILE_COUNT);

    assert_eq!(
        store.batch_sizes(),
        vec![FILE_COUNT],
        "a scan of {FILE_COUNT} single-block files must commit them as one bulk batch of \
         {FILE_COUNT}; one batch per file (the per-file producers' shape) shares no \
         directory fsync between any two files and is what this pool exists to replace"
    );
    assert_eq!(
        store.single_commit_count(),
        0,
        "no block in a scan may take the single-block commit path; every one of them has \
         a pool to go through"
    );
    assert_eq!(store.put_call_count(), FILE_COUNT, "still exactly one block per file");
}

/// The crash invariant, checked at the only instant it is observable
/// without killing a process: no row may be durable while a block it
/// references is still staged.
///
/// Staging is precisely what makes this violable -- before it, a file's
/// blocks were committed inside the per-file capture, so "the record
/// exists" could not outrun "its blocks exist". Now a file's blocks can
/// sit in a buffer while its `PreparedMutation` waits in the scan's
/// commit set, and only the scan's own flush-before-commit ordering
/// keeps them apart. This reads the store from the index-only commit
/// seam -- the first instant a restart could come back to these rows --
/// and demands every block already be there.
#[test]
fn no_scan_row_becomes_authoritative_before_its_blocks_are_durable() {
    let (proc, _state, store, _store_dir, root_dir) = processor_with_counting_store();
    let root = canonical_root(&root_dir);

    // Each file is a single block, so its content hash IS the one
    // block hash its record will reference.
    const FILE_COUNT: usize = 40;
    let mut expected_hashes = Vec::new();
    for i in 0..FILE_COUNT {
        let body = format!("body {i} {}", "x".repeat(i));
        std::fs::write(root.join(format!("payload-{i}.bin")), &body).unwrap();
        expected_hashes.push(yadorilink_local_storage::hash_block_bytes(body.as_bytes()));
    }

    let missing_at_commit: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let fired = Arc::new(AtomicBool::new(false));
    let _hook_slot = hold_scan_hook_slot();
    {
        let missing_at_commit = missing_at_commit.clone();
        let fired = fired.clone();
        let store = store.clone();
        let expected_hashes = expected_hashes.clone();
        scan_test_hooks::set_post_index_only_commit_hook(Some(Arc::new(move |gid: &str| {
            if gid != "group-1" {
                return;
            }
            fired.store(true, Ordering::SeqCst);
            let absent: Vec<String> = expected_hashes
                .iter()
                .filter(|hash| {
                    !yadorilink_local_storage::BlockStore::exists(store.as_ref(), hash)
                        .unwrap_or(false)
                })
                .cloned()
                .collect();
            *missing_at_commit.lock().unwrap_or_else(|p| p.into_inner()) = absent;
        })));
    }
    let scanned = proc.scan_existing_files("group-1", &root);
    scan_test_hooks::set_post_index_only_commit_hook(None);
    let records = scanned.expect("the scan must succeed");
    assert_eq!(records.len(), FILE_COUNT);

    assert!(fired.load(Ordering::SeqCst), "sanity: the index-only commit seam must have fired");
    let missing = missing_at_commit.lock().unwrap_or_else(|p| p.into_inner()).clone();
    assert!(
        missing.is_empty(),
        "{} of {FILE_COUNT} blocks were still only staged at the instant their rows became \
         durable; a crash there leaves a committed record referencing content this device \
         does not have: {missing:?}",
        missing.len()
    );
}

/// The other direction of the same invariant: when the bulk flush
/// cannot make blocks durable, the scan must commit NOTHING rather than
/// fall through to rows describing content that was never stored.
#[test]
fn a_scan_whose_bulk_flush_fails_commits_nothing() {
    let (proc, state, store, _store_dir, root_dir) = processor_with_counting_store();
    let root = canonical_root(&root_dir);

    for i in 0..8 {
        std::fs::write(root.join(format!("doomed-{i}.txt")), format!("content {i}")).unwrap();
    }
    store.fail_every_batch();

    let result = proc.scan_existing_files("group-1", &root);
    assert!(result.is_err(), "a scan that cannot make its blocks durable must fail");
    assert_eq!(
        store.batch_sizes().len(),
        1,
        "sanity: the scan must have attempted exactly one bulk flush"
    );
    assert!(
        state.file_index_repository().list_files("group-1").unwrap().is_empty(),
        "no row may be indexed when the blocks behind it never became durable"
    );
}

/// batch-processing changes (executor half): a `Paths` flush
/// indexes every listed path and returns the resulting records,
/// exactly as individual `process_event` calls would.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn process_flush_paths_indexes_each_path_and_returns_records() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    std::fs::write(root.join("a.txt"), b"aaa").unwrap();
    std::fs::write(root.join("b.txt"), b"bbb").unwrap();

    let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![
        (root.join("a.txt"), FsChangeKind::CreatedOrModified, 0),
        (root.join("b.txt"), FsChangeKind::CreatedOrModified, 0),
    ]);
    let outcome = proc.process_flush("group-1", &root, flush).await.unwrap();

    let mut paths: Vec<&str> = outcome.records.iter().map(|r| r.path.as_str()).collect();
    paths.sort();
    assert_eq!(paths, vec!["a.txt", "b.txt"]);
    assert_eq!(state.file_index_repository().list_files("group-1").unwrap().len(), 2);
}

/// A file still being written when its capture reads it -- a `git clone`
/// streaming its pack into the sync folder, a download, a log. The
/// capture used to build the record from two different looks at the
/// file: blocks from the read that reached EOF, size and mtime from a
/// later `stat`. When the file grew in between, the record claimed a
/// size its blocks did not add up to; storing its version then failed,
/// the error was only logged, and the caller carried on as if the path
/// had been captured.
///
/// Whatever the capture does with such a file, it must describe ONE
/// look at it: either a record whose size is exactly the bytes it
/// chunked, or a retry-later outcome that leaves the path journaled
/// dirty so the edit is re-driven. An error is not an acceptable
/// answer, and neither is a silent no-op.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_that_grows_while_it_is_read_is_captured_from_one_consistent_look_or_retried() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    adopt_root(&state, group, &root);
    let path = root.join("tmp_pack_growing");
    // Several fixed-size blocks, so the read spans more than one block.
    std::fs::write(&path, vec![0x11u8; 300 * 1024]).unwrap();

    let grow = path.clone();
    arm_content_read_race_hook(path.clone(), move || {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new().append(true).open(&grow).unwrap();
        file.write_all(&[0x22u8; 4096]).unwrap();
        file.sync_all().unwrap();
        false // one-shot: the writer finishes after this append
    });

    let event = FsChangeEvent { path: path.clone(), kind: FsChangeKind::CreatedOrModified };
    let outcome = proc.process_event(group, &root, &event).await;
    disarm_content_read_race_hook(&path);

    match outcome {
        Ok(LocalChangeOutcome::FileChanged(record)) => {
            let chunked: u64 = record.blocks.iter().map(|b| u64::from(b.size)).sum();
            assert_eq!(
                record.size, chunked,
                "a captured record must describe the bytes that were actually chunked"
            );
        }
        Ok(LocalChangeOutcome::None) | Ok(LocalChangeOutcome::FilesChanged(_)) => {
            panic!("a file that changed while it was read must not resolve to a no-op")
        }
        Ok(LocalChangeOutcome::RetryLater) => {
            assert!(
                state.dirty_path_repository().is_path_dirty(group, "tmp_pack_growing").unwrap(),
                "a capture that gives up on a file that changed while it was read must leave \
                 the path journaled dirty, or nothing re-drives the edit"
            );
            assert!(
                state
                    .file_index_repository()
                    .get_file(group, "tmp_pack_growing")
                    .unwrap()
                    .is_none(),
                "a capture that gives up must not have indexed anything"
            );
        }
        Err(error) => panic!(
            "a file that changed while it was read must be captured consistently or deferred, \
             never fail the capture: {error}"
        ),
    }

    // Once the writer is done, the next look captures the whole file.
    let record = expect_file_changed(proc.process_event(group, &root, &event).await.unwrap());
    let on_disk = std::fs::metadata(&path).unwrap().len();
    assert_eq!(record.size, on_disk, "the settled capture must describe the finished file");
    let chunked: u64 = record.blocks.iter().map(|b| u64::from(b.size)).sum();
    assert_eq!(record.size, chunked);
}

/// Regression test for the write-then-rename TOCTOU race: a debounced
/// `CreatedOrModified` event for a path can begin processing (this
/// module's own lstat guard, in `build_record_for_created_or_modified`,
/// confirms the path exists) and then have that exact path renamed out
/// from under it before the chunk attempt's own `fs::metadata`/
/// `File::open` runs -- exactly what an ordinary write-to-a-sibling-
/// temp-path-then-rename save does (including the benchmark's own
/// large-file writer, `yadorilink-bench`'s `l1.rs::write_seeded_file_
/// with_digest`, which writes to a `*.bench-write-tmp` sibling and
/// renames it onto the real name once fully written), whenever the
/// debounce accumulator's per-path quiet period happens to elapse for
/// the temp path's own "modified" events right as the writer finishes
/// and renames it away.
///
/// `arm_race_after_lstat_hook`/`fire_race_after_lstat_hook` make this
/// fully deterministic -- no sleep, no real wall-clock race, no
/// flakiness -- by renaming the temp path away at the exact instant
/// (right after this function's own lstat guard has just confirmed it
/// exists) production code has no other synchronization point to hook
/// into.
///
/// This only needs to race the *first* attempt: `process_event_with_
/// ignore_at` already re-derives a path's effective kind from a fresh
/// `symlink_metadata` call on every attempt (see its own doc comment,
/// "the watcher is a trigger to re-examine a path, not a source of
/// truth"), so once the path is truly gone a retry recovers cleanly on
/// its own -- the residual gap this test and fix close is narrower:
/// the single, unavoidable TOCTOU window *within* one attempt, between
/// that outer re-check and this function's own later chunk step, where
/// production code has no re-check at all.
///
/// Before the fix: the resulting `NotFound` surfaces as the identical
/// `StorageError::Io(_)` shape a genuine block-store fault would, so
/// `is_retriable_block_store_error` treats it as retriable -- the
/// first attempt fails, sleeps a full `LOCAL_INDEX_RETRY_BACKOFF`, and
/// only then recovers via the retry's own fresh re-check above. After
/// the fix: `is_source_path_vanished_error` re-stats the path, finds
/// it genuinely gone, and classifies it immediately, resolving as a
/// clean no-op on the very first attempt with no retry and no backoff
/// sleep at all -- the differentiating assertion below is exactly that
/// elapsed-time gap. Its counterpart,
/// `a_block_store_not_found_while_the_source_file_still_exists_stays_
/// dirty`, pins the other side of that same re-stat: the identical
/// error shape with the source file still present must NOT be
/// classified this way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn source_path_renamed_away_between_lstat_and_chunk_resolves_cleanly() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);

    let tmp_path = root.join("payload.bench-write-tmp");
    let final_path = root.join("payload.bin");
    std::fs::write(&tmp_path, vec![0x7Au8; 4096]).unwrap();

    let tmp_for_hook = tmp_path.clone();
    arm_race_after_lstat_hook(tmp_path.clone(), move || {
        std::fs::rename(&tmp_for_hook, &final_path).unwrap();
        false // one-shot: only the first attempt needs to race
    });

    let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![(
        tmp_path,
        FsChangeKind::CreatedOrModified,
        0,
    )]);
    let started = std::time::Instant::now();
    let outcome = proc.process_flush("group-1", &root, flush).await.unwrap();
    let elapsed = started.elapsed();

    assert!(
        outcome.records.is_empty(),
        "a source path that vanished mid-attempt must not produce a spurious record"
    );
    assert!(
        state.dirty_path_repository().list_dirty_paths("group-1").unwrap().is_empty(),
        "a source path proven to have vanished (renamed away), not merely faulting, must \
         resolve as a clean no-op"
    );
    assert!(
        state
            .file_index_repository()
            .get_file("group-1", "payload.bench-write-tmp")
            .unwrap()
            .is_none(),
        "the transient temp-file path must never be indexed as a real synced file"
    );
    assert!(
        elapsed < LOCAL_INDEX_RETRY_BACKOFF,
        "a vanished source path must resolve on the very first attempt, with no retry \
         backoff sleep at all -- took {elapsed:?}, which is at or beyond one \
         LOCAL_INDEX_RETRY_BACKOFF ({LOCAL_INDEX_RETRY_BACKOFF:?}), the signature of falling \
         through to the generic retriable-block-store-error path instead of being \
         classified as a vanished source path on the first attempt"
    );
}

/// The other half of `is_source_path_vanished_error`'s verdict, and
/// the one that actually needs a test: a `NotFound` raised by the
/// BLOCK STORE while the source file is still sitting on disk,
/// unchanged and unindexed, must never be mistaken for a vanished
/// source path.
///
/// The two are indistinguishable from the error value alone -- the
/// chunker reads the source file through the same
/// `StorageError::Io(#[from] std::io::Error)` blanket the block store
/// raises its own filesystem faults through, and neither carries a
/// path. This test drives the block-store side of that ambiguity
/// through real production code rather than a hand-built error:
/// headroom enforcement on (as `DaemonState::enable_disk_headroom_
/// enforcement` turns it on for the real daemon) plus a block-store
/// root that has been removed out from under the store (a deleted
/// store directory, or an unmounted volume hosting it). A file at or
/// above `CDC_SIZE_THRESHOLD` takes `SegmentBlockStore::commit_batch`,
/// whose free-space preflight stats that now-missing root BEFORE any
/// `create_dir_all` could recreate it -- so the block store really
/// does hand back `Storage(Io(NotFound))` here, with the source file
/// untouched.
///
/// The assertion that matters is the surviving `local_dirty_paths`
/// row. Classifying this as a vanished source path resolves it as
/// `LocalChangeOutcome::None`, which `process_flush` treats as a clean
/// no-op and CLEARS the journal row -- silently and permanently
/// dropping an already-detected local edit whose bytes are still on
/// disk, with nothing left to re-drive it. Keeping it on the
/// retriable-block-store-error path instead leaves the row journaled
/// dirty, so the startup rescan re-drives the file once the store is
/// back.
///
/// Deliberately pays for the full `MAX_LOCAL_INDEX_RETRIES` schedule
/// (a real block-store fault SHOULD be retried), so this is one of the
/// slower tests in this module -- it runs in parallel with its
/// neighbours and the durability property it pins is worth it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_block_store_not_found_while_the_source_file_still_exists_stays_dirty() {
    let (proc, state, store, _store_dir, root_dir) = processor_with_counting_store();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);

    // At or above `CDC_SIZE_THRESHOLD`, so the chunk attempt takes the
    // bulk-ingest batch path this double's `fail_every_batch_with_not_found`
    // targets.
    let source = root.join("big.bin");
    let size = yadorilink_local_storage::CDC_SIZE_THRESHOLD as usize + 1;
    std::fs::write(&source, vec![0xABu8; size]).unwrap();

    store.fail_every_batch_with_not_found();

    let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![(
        source.clone(),
        FsChangeKind::CreatedOrModified,
        0,
    )]);
    let outcome = proc.process_flush("group-1", &root, flush).await.unwrap();

    assert!(
        source.exists(),
        "test precondition: the SOURCE file must still be on disk -- the only thing that \
         went missing is the block store"
    );
    assert!(
        outcome.records.is_empty(),
        "a block-store fault must not produce a record for content it never durably stored"
    );
    assert_eq!(
        state.dirty_path_repository().list_dirty_paths("group-1").unwrap().len(),
        1,
        "a block-store NotFound is a durability fault, not a vanished source path: the \
         file's dirty-journal row must SURVIVE so the startup rescan re-drives it. An empty \
         journal here means the edit was silently and permanently dropped while its bytes \
         were still sitting on disk -- the signature of classifying by error shape alone \
         instead of re-stating the source path"
    );
    assert!(
        state.file_index_repository().get_file("group-1", "big.bin").unwrap().is_none(),
        "nothing may be indexed when the blocks were never durably stored"
    );
}

/// Stage-1 dirty-journal batching regression: a single `DebounceFlush::
/// Paths` batch mixing successful and failing paths must clear ONLY the
/// paths that actually succeeded from the dirty journal, even though all
/// three were batch-journaled together up front
/// (`record_dirty_paths_batch`) and the successes are cleared through
/// `clear_dirty_paths_conditional_batch` rather than one
/// `clear_dirty_path` call per path.
///
/// The mixed outcome is produced by a test double that refuses any
/// bulk flush over a mebibyte, so the split depends only on the size
/// of what each path asks the store to commit -- deterministic,
/// identical on every retry, and the same on every machine.
///
/// Two earlier versions of this test got that wrong in instructive
/// ways. The first deleted the store root and relied on the removed
/// loose-file backend creating a block's shard directory before
/// running its own headroom check -- a detail that was never the thing
/// being tested and no longer exists. The second used the real store's
/// free-space headroom gate, set relative to the volume's available
/// bytes; that gate's threshold moves with free space, so the test
/// passed and then failed on the same code when unrelated scratch was
/// deleted between runs. A discriminator for a test has to be a
/// property of the test, not of the machine.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mixed_outcome_batch_clears_only_the_successfully_processed_paths() {
    let (proc, state, store, _store_dir, root_dir) = processor_with_counting_store();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);

    let small_a = root.join("a.txt");
    let small_b = root.join("b.txt");
    std::fs::write(&small_a, b"aaa").unwrap();
    std::fs::write(&small_b, b"bbb").unwrap();

    let big = root.join("big.bin");
    let size = yadorilink_local_storage::CDC_SIZE_THRESHOLD as usize + 1;
    std::fs::write(&big, vec![0xABu8; size]).unwrap();

    // Any flush carrying more than a mebibyte is refused. The big
    // file's blocks cannot be committed; a 3-byte file's trivially
    // can.
    store.refuse_batches_larger_than(1024 * 1024);

    // `big` is processed first, deliberately: it has to be the one that
    // meets the refusal.
    let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![
        (big, FsChangeKind::CreatedOrModified, 0),
        (small_a, FsChangeKind::CreatedOrModified, 0),
        (small_b, FsChangeKind::CreatedOrModified, 0),
    ]);
    let outcome = proc.process_flush("group-1", &root, flush).await.unwrap();

    let mut succeeded: Vec<&str> = outcome.records.iter().map(|r| r.path.as_str()).collect();
    succeeded.sort();
    assert_eq!(
        succeeded,
        vec!["a.txt", "b.txt"],
        "the two small files must still succeed even though the batch also contained a \
         failing path"
    );

    let dirty = state.dirty_path_repository().list_dirty_paths("group-1").unwrap();
    assert_eq!(
        dirty.len(),
        1,
        "only the failing path may remain journaled once the batch's successes are cleared -- \
         a bulk unconditional clear here would have wrongly swept the failure's row too"
    );
    assert_eq!(dirty[0].path, "big.bin");
}

/// Authoritative-mutation group commit: a batch of N independent path
/// mutations (each its own file, no relation to the others) is signed as one
/// bounded multi-op delta, one op per path, on ONE linear head. Also pins the
/// ordinary success path: every path's dirty-journal row clears once its batch
/// actually commits.
#[tokio::test]
async fn batched_authoritative_commit_signs_one_multi_op_delta() {
    let (proc, state, _policy_healthy, _store_dir, root_dir) = processor_with_toggleable_policy();
    state.set_local_change_auth_provider(Arc::new(|_group_id| Ok(())));
    let root = canonical_root(&root_dir);
    let group = "group-1";
    adopt_root(&state, group, &root);

    const N: usize = 16;
    let mut paths = Vec::with_capacity(N);
    for i in 0..N {
        let p = root.join(format!("f-{i:02}.txt"));
        std::fs::write(&p, format!("content-{i}")).unwrap();
        paths.push((p, FsChangeKind::CreatedOrModified, 0));
    }
    let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(paths);
    let outcome = proc.process_flush(group, &root, flush).await.unwrap();
    assert_eq!(outcome.records.len(), N, "every path in the batch must be committed and reported");
    assert!(
        state.dirty_path_repository().list_dirty_paths(group).unwrap().is_empty(),
        "every successfully batch-committed path's dirty-journal row must clear"
    );
    // `commit_local_mutations_batch`'s Upsert arm is the production hot
    // path for exactly this shape of local edit -- an ordinary,
    // non-symlink create/modify flush. Its `stamp_hydrated_after_local_
    // emission_in_tx` call is what earns `Present` here; deleting that
    // call would leave every one of these rows on the schema's own
    // `Remote` default despite genuinely matching disk.
    for i in 0..N {
        let path = format!("f-{i:02}.txt");
        assert_eq!(
            state
                .materialization_state_repository()
                .get_materialization_state(group, &path)
                .unwrap(),
            Some(MaterializationState::Present),
            "a batch-committed local edit must be stamped Hydrated, not left on the \
             schema's own Placeholder default"
        );
    }

    let heads = crate::test_support::native_group_heads(&state, group);
    assert_eq!(
        heads.len(),
        1,
        "a batch of independent path mutations must chain onto ONE linear head, not fork"
    );

    // A bulk capture signs the batch as ONE multi-op delta (the paths are
    // unrelated), one op per path, chained onto its predecessor.
    let deltas = crate::test_support::native_deltas(&state, group);
    assert_eq!(deltas.len(), 1, "a batch of independent paths is one delta");
    let delta = &deltas[0];
    assert_eq!(delta.prev, None);
    let signed_paths: std::collections::BTreeSet<_> =
        delta.ops.iter().map(|op| op.path.as_str().to_owned()).collect();
    let expected: std::collections::BTreeSet<_> = (0..N).map(|i| format!("f-{i:02}.txt")).collect();
    assert_eq!(delta.ops.len(), N, "one op per path of the batch");
    assert_eq!(signed_paths, expected, "every path of the batch is in the delta");
}

/// If the shared batch commit itself fails (standing in for a crash
/// between preparing every mutation and the transaction that would
/// commit them), NOTHING may be committed — every mutation's
/// dirty-journal row must survive untouched for a normal re-drive, not
/// a partial subset.
#[tokio::test]
async fn batch_commit_failure_leaves_nothing_committed_and_every_dirty_row_survives() {
    use ed25519_dalek::SigningKey;

    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let state = Arc::new(TestReplica::open_in_memory().unwrap());
    state.set_local_change_auth_provider(Arc::new(|_group_id| Ok(())));
    let lease = Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests());
    let emitter =
        Arc::new(LocalAuthorKey::for_tests("device-a", SigningKey::from_bytes(&[9u8; 32])));
    let proc = LocalChangeProcessor::new(state.clone(), store, "device-a".into(), lease.clone())
        .with_change_emitter(emitter);
    let root_dir = tempfile::tempdir().unwrap();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    adopt_root(&state, group, &root);

    let ignore_set = EffectiveIgnoreSet::from_user_patterns("");
    let mut pending = Vec::new();
    for i in 0..3 {
        let name = format!("f-{i}.txt");
        let p = root.join(&name);
        std::fs::write(&p, format!("content-{i}")).unwrap();
        // Mirrors the flush's own batch-journal-before-processing step
        // (normally done by `process_flush_with_ignore`, bypassed here
        // since this test calls `process_event_with_ignore_at`
        // directly to control the exact timing against `lease.
        // begin_stopping()` below).
        state
            .dirty_path_repository()
            .record_dirty_path(
                group,
                &name,
                dirty_kind_str(FsChangeKind::CreatedOrModified),
                0,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        let outcome = proc
            .process_event_with_ignore_at(
                group,
                &root,
                &FsChangeEvent { path: p, kind: FsChangeKind::CreatedOrModified },
                &ignore_set,
                Some(0),
                Some(&mut pending),
            )
            .await
            .unwrap();
        assert!(
            matches!(outcome, EventOutcome::Deferred),
            "test precondition: must defer into the batch"
        );
    }
    assert_eq!(pending.len(), 3);

    // Simulate the link/process stopping between preparation and
    // commit -- `begin_operation` (which `flush_pending_batch` needs
    // for its own permit) now fails for every subsequent caller.
    lease.begin_stopping();

    let resolved = proc.flush_pending_batch(group, &root, &mut pending).await;
    let resolved = resolved.unwrap_or_default();
    assert!(resolved.is_empty(), "no mutation may resolve as committed once admission is revoked");

    for i in 0..3 {
        let path = format!("f-{i}.txt");
        assert!(
            state.file_index_repository().get_file(group, &path).unwrap().is_none(),
            "no row may exist for a mutation whose batch commit never ran"
        );
        assert!(
            state.dirty_path_repository().is_path_dirty(group, &path).unwrap(),
            "every mutation's dirty-journal row must survive a commit that never ran"
        );
    }
}

/// A concurrent peer materialization superseding a path's index row
/// between this path's preparation (Phase A) and its batch's validation
/// (Phase B) must exclude that mutation from the batch entirely, not
/// silently commit stale bytes over the peer's own update.
#[tokio::test]
async fn a_peer_mutation_between_preparation_and_validation_excludes_the_stale_mutation() {
    let (proc, state, _policy_healthy, _store_dir, root_dir) = processor_with_toggleable_policy();
    state.set_local_change_auth_provider(Arc::new(|_group_id| Ok(())));
    let root = canonical_root(&root_dir);
    let group = "group-1";
    adopt_root(&state, group, &root);

    let path = root.join("doc.txt");
    std::fs::write(&path, b"local-v1").unwrap();

    // Mirrors the flush's own batch-journal-before-processing step
    // (normally done by `process_flush_with_ignore`, bypassed here
    // since this test calls `process_event_with_ignore_at` directly to
    // control the exact timing of the peer write below).
    state
        .dirty_path_repository()
        .record_dirty_path(
            group,
            "doc.txt",
            dirty_kind_str(FsChangeKind::CreatedOrModified),
            0,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    let ignore_set = EffectiveIgnoreSet::from_user_patterns("");
    let mut pending = Vec::new();
    let outcome = proc
        .process_event_with_ignore_at(
            group,
            &root,
            &FsChangeEvent { path: path.clone(), kind: FsChangeKind::CreatedOrModified },
            &ignore_set,
            Some(0),
            Some(&mut pending),
        )
        .await
        .unwrap();
    assert!(matches!(outcome, EventOutcome::Deferred));
    assert_eq!(pending.len(), 1);

    // A concurrent peer materialization commits its own row for this
    // path while this device's mutation sat prepared but not yet
    // committed -- nothing was indexed for it before (preparation only
    // reads/chunks, it never writes); native seeing this peer write
    // arrive is enough to make Phase B's revalidation observe a change.
    let peer_record = FileRecord {
        path: "doc.txt".to_string(),
        size: 999,
        mtime_unix_nanos: 123_456_789,
        blocks: vec![],
        deleted: false,
    };
    state
        .file_index_repository()
        .upsert_file_with_origin(
            group,
            &peer_record,
            "device-b",
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    // Native sees the same peer write arrive.
    {
        use yadorilink_daemon::test_support::remote_admission_fixture as peer;
        peer::admit_remote_superseding_put(
            &state,
            group,
            "device-b",
            "doc.txt",
            yadorilink_replica_domain::ids::VersionHash([9; 32]),
        );
    }

    let resolved = proc.flush_pending_batch(group, &root, &mut pending).await.unwrap();
    assert!(
        resolved.is_empty(),
        "a prepared mutation must not commit once the index row it was based on has changed"
    );

    let current = state.file_index_repository().get_file(group, "doc.txt").unwrap().unwrap();
    assert_eq!(
        current.size, 999,
        "the peer's own write must survive; the stale local mutation must not overwrite it"
    );
    assert!(state.dirty_path_repository().is_path_dirty(group, "doc.txt").unwrap());
}

/// A peer's signed `Put` of `path`, admitted into native state only -- the way
/// admission leaves it until reconciliation projects it: `files` is never
/// written. Returns the change's hash.
fn admit_peer_put_only_into_the_dag(
    state: &ReplicaCoordinator,
    group: &str,
    path: &str,
    parents: Vec<yadorilink_replica_domain::ids::DeltaHash>,
    max_parent_lamport: u64,
    size: u64,
) -> yadorilink_replica_domain::ids::DeltaHash {
    use yadorilink_replica_domain::file::{FileMeta, FileVersion, VersionBlock};

    let version = FileVersion::new(
        Vec::<VersionBlock>::new(),
        size,
        FileMeta {
            mtime_unix_nanos: 1,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    let _ = max_parent_lamport;
    state
        .database()
        .write(|conn| yadorilink_sync_sqlite::dag_store::put_file_version(conn, group, &version))
        .unwrap();
    let basis = if parents.is_empty() {
        yadorilink_daemon::test_support::remote_admission_fixture::Basis::Nothing
    } else {
        yadorilink_daemon::test_support::remote_admission_fixture::Basis::CurrentHeads
    };
    yadorilink_daemon::test_support::remote_admission_fixture::admit_remote_ops(
        state,
        group,
        "device-b",
        &[Op::Put { path: SyncPath(path.to_string()), version: version.version_hash }],
        basis,
    );
    // What names the peer's head under native is its provenance: the hash of
    // the delta that put it.
    let provenances = crate::test_support::native_path_head_provenances(state, group, path);
    assert_eq!(
        provenances.len(),
        1,
        "sanity: the peer's write must be the live head before the local write is emitted"
    );
    yadorilink_replica_domain::ids::DeltaHash(provenances[0])
}

/// Asserts `local` did not claim `peer` as its causal past: both are live
/// heads of `path`, so conflict resolution keeps both contents.
fn assert_concurrent_live_heads(
    state: &ReplicaCoordinator,
    group: &str,
    path: &str,
    peer: &yadorilink_replica_domain::ids::DeltaHash,
    local: &yadorilink_replica_domain::ids::DeltaHash,
) {
    let heads = crate::test_support::native_path_head_provenances(state, group, path);
    assert!(heads.contains(&peer.0), "the peer's version must stay a live head of {path}");
    assert!(heads.contains(&local.0), "the local write must be a live head of {path}");
}

/// The batched route's rule when the path already has a row -- but only the
/// `version_seq = 0` scaffold reconciliation writes before it tries to place
/// a peer's version. The scaffold stays when placement is retried (the
/// peer's blocks are unavailable, or the disk changed under the fetch), and
/// it records no content: this device has still never shown any version of
/// the path. A local create written in that window must stay concurrent
/// with the peer's create, exactly as with no row at all.
#[tokio::test]
async fn a_local_create_over_a_placement_scaffold_is_not_a_descendant_of_the_peer_create() {
    use std::sync::atomic::Ordering;

    let (proc, state, policy_healthy, _store_dir, root_dir) = processor_with_toggleable_policy();
    policy_healthy.store(true, Ordering::SeqCst);
    state.set_local_change_auth_provider(Arc::new(|_group_id| Ok(())));
    let root = canonical_root(&root_dir);
    let group = "group-1";
    adopt_root(&state, group, &root);
    let ignore_set = EffectiveIgnoreSet::from_user_patterns("");

    // A peer's create is admitted, and reconciliation scaffolds the path
    // before its placement is retried.
    let r_hash = admit_peer_put_only_into_the_dag(&state, group, "new.txt", vec![], 0, 0);
    state.file_index_repository().ensure_bootstrap_row_for_metadata(group, "new.txt").unwrap();
    assert!(
        !state.file_index_repository().has_real_current_row(group, "new.txt").unwrap(),
        "sanity: the scaffold records no content"
    );

    // The user creates the path meanwhile.
    let path = root.join("new.txt");
    std::fs::write(&path, b"created locally").unwrap();
    state
        .dirty_path_repository()
        .record_dirty_path(
            group,
            "new.txt",
            dirty_kind_str(FsChangeKind::CreatedOrModified),
            0,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    let mut pending = Vec::new();
    let outcome = proc
        .process_event_with_ignore_at(
            group,
            &root,
            &FsChangeEvent { path: path.clone(), kind: FsChangeKind::CreatedOrModified },
            &ignore_set,
            Some(0),
            Some(&mut pending),
        )
        .await
        .unwrap();
    assert!(matches!(outcome, EventOutcome::Deferred));
    let resolved = proc.flush_pending_batch(group, &root, &mut pending).await.unwrap();
    assert_eq!(resolved.len(), 1, "the local create must commit, not be dropped");
    // The local write's head is the one at the path that is not the peer's.
    let l_hash = yadorilink_replica_domain::ids::DeltaHash(
        crate::test_support::native_path_head_provenances(&state, group, "new.txt")
            .into_iter()
            .find(|provenance| *provenance != r_hash.0)
            .expect("the local create is a head beside the peer's"),
    );

    assert_concurrent_live_heads(&state, group, "new.txt", &r_hash, &l_hash);
}

/// The window between capture and emission. A local create of a path this
/// device has never placed is captured; only then is a peer's create of the
/// same path admitted; then the captured create is emitted. It has no recorded
/// basis, so emission falls back to the current frontier, which now holds the
/// peer's create. The local create must not claim it as its causal past:
/// the peer's content would be superseded and no conflict copy derived.
#[tokio::test]
async fn a_peer_create_admitted_between_capture_and_emit_of_a_new_path_is_not_its_parent() {
    use std::sync::atomic::Ordering;

    let (proc, state, policy_healthy, _store_dir, root_dir) = processor_with_toggleable_policy();
    policy_healthy.store(true, Ordering::SeqCst);
    state.set_local_change_auth_provider(Arc::new(|_group_id| Ok(())));
    let root = canonical_root(&root_dir);
    let group = "group-1";
    adopt_root(&state, group, &root);
    let ignore_set = EffectiveIgnoreSet::from_user_patterns("");

    let path = root.join("new.txt");
    std::fs::write(&path, b"created locally").unwrap();
    state
        .dirty_path_repository()
        .record_dirty_path(
            group,
            "new.txt",
            dirty_kind_str(FsChangeKind::CreatedOrModified),
            0,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    let mut pending = Vec::new();
    let outcome = proc
        .process_event_with_ignore_at(
            group,
            &root,
            &FsChangeEvent { path: path.clone(), kind: FsChangeKind::CreatedOrModified },
            &ignore_set,
            Some(0),
            Some(&mut pending),
        )
        .await
        .unwrap();
    assert!(matches!(outcome, EventOutcome::Deferred));
    assert_eq!(pending.len(), 1, "the create must be captured but uncommitted");

    // The peer's create is admitted after capture, before emission.
    let r_hash = admit_peer_put_only_into_the_dag(&state, group, "new.txt", vec![], 0, 0);

    let resolved = proc.flush_pending_batch(group, &root, &mut pending).await.unwrap();
    assert_eq!(resolved.len(), 1, "the local create must still commit, not be dropped");
    let l_hash = yadorilink_replica_domain::ids::DeltaHash(
        crate::test_support::native_path_head_provenances(&state, group, "new.txt")
            .into_iter()
            .find(|provenance| *provenance != r_hash.0)
            .expect("the local create is a head beside the peer's"),
    );

    assert_concurrent_live_heads(&state, group, "new.txt", &r_hash, &l_hash);
}

/// The unbatched route's half of the rule above. A file captured straight
/// from disk and committed on its own -- a symlink, or a path the link
/// captures because a peer's change for it is about to be applied -- signs
/// through its own commit, not the batch. A peer's create of the same new
/// path, already admitted, must not become its parent there either.
#[tokio::test]
async fn an_unbatched_local_create_is_not_a_descendant_of_an_admitted_peer_create() {
    use std::sync::atomic::Ordering;

    let (proc, state, policy_healthy, _store_dir, root_dir) = processor_with_toggleable_policy();
    policy_healthy.store(true, Ordering::SeqCst);
    state.set_local_change_auth_provider(Arc::new(|_group_id| Ok(())));
    let root = canonical_root(&root_dir);
    let group = "group-1";
    adopt_root(&state, group, &root);

    let path = root.join("new.txt");
    std::fs::write(&path, b"created locally").unwrap();
    let r_hash = admit_peer_put_only_into_the_dag(&state, group, "new.txt", vec![], 0, 0);

    expect_file_changed(
        proc.process_event(
            group,
            &root,
            &FsChangeEvent { path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap(),
    );
    // The local write's head is the one at the path that is not the peer's.
    let l_hash = yadorilink_replica_domain::ids::DeltaHash(
        crate::test_support::native_path_head_provenances(&state, group, "new.txt")
            .into_iter()
            .find(|provenance| *provenance != r_hash.0)
            .expect("the local create is a head beside the peer's"),
    );

    assert_concurrent_live_heads(&state, group, "new.txt", &r_hash, &l_hash);
}

/// A raw external write to the same path (an editor, not this daemon)
/// between preparation and validation must exclude the stale mutation
/// even though the INDEX row never changed — only the disk fingerprint
/// has. Mirrors `peer_session::PeerSyncSession::hydrate_inner`'s own
/// `disk_race_fingerprint` re-check before its physical write.
#[tokio::test]
async fn a_raw_disk_write_between_preparation_and_validation_excludes_the_stale_mutation() {
    let (proc, state, _policy_healthy, _store_dir, root_dir) = processor_with_toggleable_policy();
    state.set_local_change_auth_provider(Arc::new(|_group_id| Ok(())));
    let root = canonical_root(&root_dir);
    let group = "group-1";
    adopt_root(&state, group, &root);

    let path = root.join("doc.txt");
    std::fs::write(&path, b"local-v1").unwrap();

    // Mirrors the flush's own batch-journal-before-processing step
    // (normally done by `process_flush_with_ignore`, bypassed here
    // since this test calls `process_event_with_ignore_at` directly to
    // control the exact timing of the disk rewrite below).
    state
        .dirty_path_repository()
        .record_dirty_path(
            group,
            "doc.txt",
            dirty_kind_str(FsChangeKind::CreatedOrModified),
            0,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    let ignore_set = EffectiveIgnoreSet::from_user_patterns("");
    let mut pending = Vec::new();
    let outcome = proc
        .process_event_with_ignore_at(
            group,
            &root,
            &FsChangeEvent { path: path.clone(), kind: FsChangeKind::CreatedOrModified },
            &ignore_set,
            Some(0),
            Some(&mut pending),
        )
        .await
        .unwrap();
    assert!(matches!(outcome, EventOutcome::Deferred));

    // A different size guarantees `disk_race_fingerprint` observes a
    // change regardless of filesystem mtime granularity.
    std::fs::write(&path, b"externally rewritten while this mutation was pending").unwrap();

    let resolved = proc.flush_pending_batch(group, &root, &mut pending).await.unwrap();
    assert!(
        resolved.is_empty(),
        "a prepared mutation must not author stale bytes once the on-disk file has changed \
         since preparation"
    );
    assert!(
        state.file_index_repository().get_file(group, "doc.txt").unwrap().is_none(),
        "nothing may be indexed for content that was never durably authored"
    );
    assert!(
        state.sqlite().dag_lookup_materialized_generation(group, "doc.txt").unwrap().is_none(),
        "mandatory race regression A: a path excluded by prepare-vs-commit \
         revalidation must publish no actual-state proof, not a proof for the \
         stale content it almost authored"
    );
    assert!(state.dirty_path_repository().is_path_dirty(group, "doc.txt").unwrap());
}

/// Two overlapping-path batches (prepared in opposite path order, so
/// neither happens to already match `flush_pending_batch`'s own
/// lexicographic acquisition order) run concurrently must never
/// deadlock — `flush_pending_batch` sorts its own lock acquisition
/// regardless of preparation order, so both converge on the same
/// acquisition order and can only ever wait in line, never cycle.
#[tokio::test]
async fn concurrent_overlapping_batches_never_deadlock_regardless_of_preparation_order() {
    let (proc, state, _policy_healthy, _store_dir, root_dir) = processor_with_toggleable_policy();
    state.set_local_change_auth_provider(Arc::new(|_group_id| Ok(())));
    let root = canonical_root(&root_dir);
    let group = "group-1";
    adopt_root(&state, group, &root);

    let path_a = root.join("a.txt");
    let path_b = root.join("b.txt");
    std::fs::write(&path_a, b"aaa").unwrap();
    std::fs::write(&path_b, b"bbb").unwrap();
    let ignore_set = EffectiveIgnoreSet::from_user_patterns("");

    let mut batch1 = Vec::new();
    for p in [&path_a, &path_b] {
        proc.process_event_with_ignore_at(
            group,
            &root,
            &FsChangeEvent { path: (*p).clone(), kind: FsChangeKind::CreatedOrModified },
            &ignore_set,
            Some(0),
            Some(&mut batch1),
        )
        .await
        .unwrap();
    }
    let mut batch2 = Vec::new();
    for p in [&path_b, &path_a] {
        proc.process_event_with_ignore_at(
            group,
            &root,
            &FsChangeEvent { path: (*p).clone(), kind: FsChangeKind::CreatedOrModified },
            &ignore_set,
            Some(0),
            Some(&mut batch2),
        )
        .await
        .unwrap();
    }

    let (r1, r2) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(
            proc.flush_pending_batch(group, &root, &mut batch1),
            proc.flush_pending_batch(group, &root, &mut batch2),
        )
    })
    .await
    .expect("two concurrent overlapping batches must not deadlock");
    r1.unwrap();
    r2.unwrap();
}

/// More paths in one flush than `AUTHORITATIVE_COMMIT_BATCH_SIZE` must
/// still all commit correctly, across however many bounded batch
/// commits that takes — bounding the batch size must never drop or
/// duplicate a path.
#[tokio::test]
async fn more_than_one_authoritative_batch_worth_of_paths_all_commit_correctly() {
    let (proc, state, _policy_healthy, _store_dir, root_dir) = processor_with_toggleable_policy();
    state.set_local_change_auth_provider(Arc::new(|_group_id| Ok(())));
    let root = canonical_root(&root_dir);
    let group = "group-1";
    adopt_root(&state, group, &root);

    const N: usize = 40; // more than 2x AUTHORITATIVE_COMMIT_BATCH_SIZE
    let mut paths = Vec::with_capacity(N);
    for i in 0..N {
        let p = root.join(format!("f-{i:03}.txt"));
        std::fs::write(&p, format!("content-{i}")).unwrap();
        paths.push((p, FsChangeKind::CreatedOrModified, 0));
    }
    let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(paths);
    let outcome = proc.process_flush(group, &root, flush).await.unwrap();
    assert_eq!(
        outcome.records.len(),
        N,
        "batching internally into bounded groups must not drop or duplicate any path"
    );
    assert!(state.dirty_path_repository().list_dirty_paths(group).unwrap().is_empty());
    for i in 0..N {
        assert!(state
            .file_index_repository()
            .get_file(group, &format!("f-{i:03}.txt"))
            .unwrap()
            .is_some());
    }
}

/// A batch mixing creates/modifies AND deletes must commit both
/// `PreparedLocalMutation` variants together, in one shared
/// transaction — `commit_local_mutations_batch`'s `Delete` arm is
/// otherwise never exercised by this module's other Stage-2 batching
/// tests, which are create/modify-only.
#[tokio::test]
async fn a_batch_mixing_creates_and_deletes_commits_both_variants_together() {
    let (proc, state, _policy_healthy, _store_dir, root_dir) = processor_with_toggleable_policy();
    state.set_local_change_auth_provider(Arc::new(|_group_id| Ok(())));
    let root = canonical_root(&root_dir);
    let group = "group-1";
    adopt_root(&state, group, &root);

    // Two pre-existing files, indexed via their own ordinary flush
    // first, then one is deleted and the other modified in the SAME
    // later flush, alongside a brand-new third file -- a create, a
    // modify, and a delete, all in one batch.
    let to_delete = root.join("to-delete.txt");
    let to_modify = root.join("to-modify.txt");
    std::fs::write(&to_delete, b"gone-soon").unwrap();
    std::fs::write(&to_modify, b"v1").unwrap();
    let setup_flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![
        (to_delete.clone(), FsChangeKind::CreatedOrModified, 0),
        (to_modify.clone(), FsChangeKind::CreatedOrModified, 0),
    ]);
    let setup_outcome = proc.process_flush(group, &root, setup_flush).await.unwrap();
    assert_eq!(setup_outcome.records.len(), 2);

    std::fs::remove_file(&to_delete).unwrap();
    std::fs::write(&to_modify, b"v2-modified").unwrap();
    let to_create = root.join("to-create.txt");
    std::fs::write(&to_create, b"brand-new").unwrap();

    let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![
        (to_delete, FsChangeKind::ObservedRemoval, 1),
        (to_modify, FsChangeKind::CreatedOrModified, 1),
        (to_create, FsChangeKind::CreatedOrModified, 1),
    ]);
    let outcome = proc.process_flush(group, &root, flush).await.unwrap();
    assert_eq!(outcome.records.len(), 3, "the create, the modify, and the delete must all commit");
    assert!(state.dirty_path_repository().list_dirty_paths(group).unwrap().is_empty());

    assert!(
        state.file_index_repository().get_file(group, "to-delete.txt").unwrap().unwrap().deleted,
        "the batched delete must tombstone the row"
    );
    let modified = state.file_index_repository().get_file(group, "to-modify.txt").unwrap().unwrap();
    assert!(!modified.deleted);
    assert_eq!(modified.size, "v2-modified".len() as u64);
    assert!(state.file_index_repository().get_file(group, "to-create.txt").unwrap().is_some());

    // Every mutation authored its own signed Change (3 more on top of
    // the setup flush's 1), still chained onto one linear head.
    let heads = crate::test_support::native_group_heads(&state, group);
    assert_eq!(heads.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn process_flush_paths_skips_ignored_files_and_ignore_config_file() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let ignore_set = EffectiveIgnoreSet::from_user_patterns("*.tmp\n");
    std::fs::write(root.join("keep.txt"), b"kept").unwrap();
    std::fs::write(root.join("scratch.tmp"), b"ignored").unwrap();
    std::fs::write(root.join(".yadorilinkignore"), b"*.tmp\n").unwrap();

    let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![
        (root.join("keep.txt"), FsChangeKind::CreatedOrModified, 0),
        (root.join("scratch.tmp"), FsChangeKind::CreatedOrModified, 0),
        (root.join(".yadorilinkignore"), FsChangeKind::CreatedOrModified, 0),
    ]);
    let outcome =
        proc.process_flush_with_ignore("group-1", &root, flush, &ignore_set, true).await.unwrap();

    assert_eq!(outcome.records.len(), 1);
    assert_eq!(outcome.records[0].path, "keep.txt");
    assert!(state.file_index_repository().get_file("group-1", "scratch.tmp").unwrap().is_none());
    assert!(state
        .file_index_repository()
        .get_file("group-1", ".yadorilinkignore")
        .unwrap()
        .is_none());
}

/// A `RescanRequired` flush runs a full reconciliation scan instead of
/// per-path processing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn process_flush_burst_fallback_runs_full_scan() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    // `RescanRequired` now goes through `verified_root_of_established_
    // link` (`VerifiedRoot::verify`), not the one-time-scan `verified_
    // root` (`VerifiedRoot::open`, which could adopt lazily) -- a real
    // link always adopts its root during the initial scan, before any
    // live flush (including a `RescanRequired` one) can ever reach this
    // path, so this fixture must model that ordering too.
    adopt_root(&state, "group-1", &root);
    std::fs::write(root.join("a.txt"), b"aaa").unwrap();
    std::fs::write(root.join("b.txt"), b"bbb").unwrap();
    std::fs::write(root.join("c.txt"), b"ccc").unwrap();

    let outcome = proc
        .process_flush(
            "group-1",
            &root,
            yadorilink_filesystem_sync::debounce::DebounceFlush::RescanRequired,
        )
        .await
        .unwrap();

    let mut paths: Vec<&str> = outcome.records.iter().map(|r| r.path.as_str()).collect();
    paths.sort();
    assert_eq!(paths, vec!["a.txt", "b.txt", "c.txt"]);
    assert_eq!(state.file_index_repository().list_files("group-1").unwrap().len(), 3);
}

/// `process_flush_with_ignore`'s `RescanRequired` arm must forward its
/// caller-supplied `emit_tombstones` gate to the scan, not silently
/// re-harden it to `true`. Every other test exercising the gate goes
/// through `scan_existing_files_with_ignore_gated[_for_established_link]`
/// directly; this is the only one that drives it through the actual
/// public entry point real callers use (see `yadorilink-daemon`'s
/// executor task), so nothing else would catch a future refactor that
/// re-hardcodes `emit_tombstones: true` at this arm.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn process_flush_rescan_required_forwards_a_false_emit_tombstones_gate() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let file_path = root.join("report.txt");
    std::fs::write(&file_path, b"version one").unwrap();
    proc.process_flush(
        "group-1",
        &root,
        yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![(
            file_path.clone(),
            FsChangeKind::CreatedOrModified,
            0,
        )]),
    )
    .await
    .unwrap();
    assert!(state.file_index_repository().get_file("group-1", "report.txt").unwrap().is_some());

    // Removed "offline" (no daemon in between); a plain RescanRequired
    // scan with the gate left on would tombstone this immediately.
    std::fs::remove_file(&file_path).unwrap();
    let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();
    let outcome = proc
        .process_flush_with_ignore(
            "group-1",
            &root,
            yadorilink_filesystem_sync::debounce::DebounceFlush::RescanRequired,
            &ignore_set,
            false,
        )
        .await
        .unwrap();

    assert!(
        !outcome.records.iter().any(|r| r.path == "report.txt" && r.deleted),
        "a false emit_tombstones gate must suppress the RescanRequired scan's missing-file \
         tombstone -- if this ever fails, the RescanRequired arm has stopped forwarding its \
         caller-supplied gate: {:?}",
        outcome.records
    );
    let indexed = state.file_index_repository().get_file("group-1", "report.txt").unwrap().unwrap();
    assert!(!indexed.deleted, "the index row itself must not have been tombstoned either");
}

/// self-echo
/// suppression still applies per-path when processing a `Paths`
/// flush — a path whose content already matches what's indexed
/// (as if a peer-applied write's own resulting event landed in this
/// debounce window) produces no record, exactly as an immediate
/// single-event `process_event` call would.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn process_flush_paths_applies_self_echo_suppression_per_path() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let file_path = root.join("synced.bin");
    std::fs::write(&file_path, b"peer-applied content").unwrap();

    // Index it first (simulating `peer_session::materialize` having
    // already written this exact content before its own triggered
    // watcher event ever reaches the debounce flush).
    let first_flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![(
        file_path.clone(),
        FsChangeKind::CreatedOrModified,
        0,
    )]);
    let first = proc.process_flush("group-1", &root, first_flush).await.unwrap();
    assert_eq!(first.records.len(), 1);

    // A second flush for the same, unchanged path — as if the
    // materialize-triggered watcher event arrived in its own later
    // window — must be suppressed, not re-indexed or re-broadcast.
    let second_flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![(
        file_path,
        FsChangeKind::CreatedOrModified,
        0,
    )]);
    let second = proc.process_flush("group-1", &root, second_flush).await.unwrap();
    assert!(second.records.is_empty(), "unchanged content must not be re-indexed");
}

/// the
/// placeholder/hydrating skip still applies when processing a `Paths`
/// flush, exactly as `process_event` does directly — a placeholder's
/// own on-disk representation is never chunked as if it were real
/// content, even when reached via the debounce/flush path.
#[tokio::test]
async fn process_flush_paths_skips_placeholders_exactly_like_process_event() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    let file_path = root.join("placeholder.bin");

    state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &FileRecord {
                path: "placeholder.bin".into(),
                size: 4_000_000,
                mtime_unix_nanos: 0,
                blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                    hash: vec![0xEE; 32],
                    offset: 0,
                    size: 4_000_000,
                }],
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .materialization_state_repository()
        .set_materialization_state(
            "group-1",
            "placeholder.bin",
            MaterializationState::Remote,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![(
        file_path,
        FsChangeKind::CreatedOrModified,
        0,
    )]);
    let outcome = proc.process_flush("group-1", &root, flush).await.unwrap();

    assert!(outcome.records.is_empty(), "a placeholder's own write must not be indexed");
    assert_eq!(
        state.sqlite().dag_list_versions("group-1", "placeholder.bin").unwrap().len(),
        1,
        "no spurious local version bump"
    );
}

/// an overflow signal (as a real
/// watcher would set on a dropped event, simulated here by setting
/// the flag directly — see `watcher::watch_folder_with_capacity`'s
/// own tests for proof the flag is set correctly under a genuine
/// full channel) reaches the debouncer and, once flushed through
/// `process_flush`'s `RescanRequired` handling, produces a fully
/// correct index — including files whose individual creation events
/// were never tracked at all, because the whole point of this
/// recovery path is not needing them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watcher_overflow_recovers_to_a_fully_correct_index_via_full_rescan() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    // See `process_flush_burst_fallback_runs_full_scan`'s identical
    // comment: `RescanRequired` now re-verifies an already-adopted
    // root rather than adopting lazily.
    adopt_root(&state, "group-1", &root);
    let proc = Arc::new(proc);

    // These files exist on disk, but no event for any of them is
    // ever sent into the debouncer — standing in for what a real
    // overflow drops.
    const FILE_COUNT: usize = 25;
    for i in 0..FILE_COUNT {
        std::fs::write(root.join(format!("dropped-{i}.bin")), format!("content {i}")).unwrap();
    }

    let (_events_tx, events_rx) = tokio::sync::mpsc::channel(16);
    let (flush_tx, mut flush_rx) = tokio::sync::mpsc::channel(4);
    let overflowed = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let config = yadorilink_filesystem_sync::debounce::DebounceConfig {
        quiet_period: std::time::Duration::from_millis(20),
        max_flush_interval: std::time::Duration::from_millis(100),
        burst_threshold: 1000,
    };
    let (_flush_requests_tx, flush_requests_rx) = tokio::sync::mpsc::channel(1);
    let (_flush_all_requests_tx, flush_all_requests_rx) = tokio::sync::mpsc::channel(1);
    tokio::spawn(yadorilink_filesystem_sync::debounce::run_debouncer(
        config,
        events_rx,
        flush_tx,
        overflowed,
        flush_requests_rx,
        flush_all_requests_rx,
    ));

    let flush = tokio::time::timeout(std::time::Duration::from_secs(2), flush_rx.recv())
        .await
        .expect("overflow never produced a flush")
        .unwrap();
    assert_eq!(flush, yadorilink_filesystem_sync::debounce::DebounceFlush::RescanRequired);

    let outcome = proc.process_flush("group-1", &root, flush).await.unwrap();
    assert_eq!(outcome.records.len(), FILE_COUNT, "the full rescan must discover every file");
    assert_eq!(state.file_index_repository().list_files("group-1").unwrap().len(), FILE_COUNT);
    for i in [0, FILE_COUNT / 2, FILE_COUNT - 1] {
        let record =
            state.file_index_repository().get_file("group-1", &format!("dropped-{i}.bin")).unwrap();
        assert!(record.is_some(), "file dropped-{i}.bin is missing from the recovered index");
    }
}

/// a
/// rename whose watcher event is missed entirely (the scenario a
/// dropped/overflowed event stream produces, or simply a device that
/// was offline while the rename happened) must be fully recovered by
/// the next full rescan — the old path tombstoned, the new path
/// indexed as live, and the old path never resurrected by a later
/// scan (idempotency: nothing about a stable, already-tombstoned
/// path should look "new" to a subsequent rescan).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scan_existing_files_recovers_a_dropped_rename_without_resurrecting_the_old_path() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);

    let old_path = root.join("original.txt");
    std::fs::write(&old_path, b"content").unwrap();
    let scanned = proc.scan_existing_files("group-1", &root).unwrap();
    assert_eq!(scanned.len(), 1);
    assert!(
        !state
            .file_index_repository()
            .get_file("group-1", "original.txt")
            .unwrap()
            .unwrap()
            .deleted
    );

    // Simulate a rename whose watcher event never arrived (dropped by
    // an overflow, or the device was offline) — from the index's
    // point of view, `original.txt` just vanished and `renamed.txt`
    // appeared, with no event ever processed for either.
    std::fs::rename(&old_path, root.join("renamed.txt")).unwrap();

    let recovered = proc.scan_existing_files("group-1", &root).unwrap();
    let old_record = recovered.iter().find(|r| r.path == "original.txt");
    let new_record = recovered.iter().find(|r| r.path == "renamed.txt");
    assert!(old_record.is_some_and(|r| r.deleted), "old path must be tombstoned: {recovered:?}");
    assert!(
        new_record.is_some_and(|r| !r.deleted),
        "new path must be indexed as live: {recovered:?}"
    );
    assert!(
        state.file_index_repository().get_file("group-1", "original.txt").unwrap().unwrap().deleted,
        "tombstone must actually be persisted to the index, not just returned"
    );

    // A further rescan (nothing changed on disk since) must not
    // resurrect the now-stable tombstone — the old path shouldn't
    // even appear in the returned records again, since nothing about
    // it changed.
    let second_scan = proc.scan_existing_files("group-1", &root).unwrap();
    assert!(
        second_scan.iter().all(|r| r.path != "original.txt"),
        "a stable tombstone must not be re-emitted/re-bumped by a later rescan: {second_scan:?}"
    );
    assert!(
        state.file_index_repository().get_file("group-1", "original.txt").unwrap().unwrap().deleted
    );
}

/// The add-only reconcile
/// (`reconcile_added_files`) indexes only a disk file with no existing
/// index row — an already-indexed file whose on-disk content changed,
/// and an indexed file missing from disk, are both left byte-identical
/// (no re-version, no tombstone). This is the property that makes it
/// safe to run unconditionally on a frequent periodic schedule, unlike
/// `scan_existing_files` (which does re-version/tombstone those two
/// cases, and is documented — `watcher.rs`'s module doc — as unsafe to
/// run that often against a possibly-mid-conflict-resolution index).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconcile_added_files_only_indexes_disk_files_with_no_existing_row() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);

    // (a) current: already indexed, on-disk content unchanged.
    std::fs::write(root.join("current.txt"), b"unchanged").unwrap();
    // (b) size-changed-on-disk: indexed once, then its disk content
    // changes size *after* indexing, without going through `scan_
    // existing_files` again (mirroring a watcher-missed edit).
    std::fs::write(root.join("changed.txt"), b"original").unwrap();
    // (c) indexed-but-disk-missing: indexed once, then deleted from
    // disk directly (mirroring a watcher-missed delete).
    std::fs::write(root.join("missing.txt"), b"will be deleted").unwrap();

    let initial = proc.scan_existing_files("group-1", &root).unwrap();
    assert_eq!(initial.len(), 3);
    let versions_of = |path: &str| state.sqlite().dag_list_versions("group-1", path).unwrap().len();
    let current_versions_before = versions_of("current.txt");
    let changed_versions_before = versions_of("changed.txt");
    let missing_versions_before = versions_of("missing.txt");

    // Now make (b) and (c) diverge from the index without dispatching
    // any event for them, and add (d): a brand-new file the index has
    // never seen.
    std::fs::write(root.join("changed.txt"), b"a longer, different body").unwrap();
    std::fs::remove_file(root.join("missing.txt")).unwrap();
    std::fs::write(root.join("new.txt"), b"never indexed before").unwrap();

    let added = proc.reconcile_added_files("group-1", &root).unwrap();
    assert_eq!(
        added.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
        vec!["new.txt"],
        "the add-only reconcile must emit a record only for the genuinely new file: {added:?}"
    );
    assert!(!added[0].deleted);

    // (a)/(b)/(c) must be byte-identical in the index to their
    // pre-reconcile state -- no re-version, no tombstone.
    let current_after =
        state.file_index_repository().get_file("group-1", "current.txt").unwrap().unwrap();
    assert_eq!(versions_of("current.txt"), current_versions_before);
    assert!(!current_after.deleted);

    let changed_after =
        state.file_index_repository().get_file("group-1", "changed.txt").unwrap().unwrap();
    assert_eq!(
        versions_of("changed.txt"),
        changed_versions_before,
        "a size-changed-on-disk file must not be re-versioned by the add-only reconcile"
    );
    assert!(!changed_after.deleted);

    let missing_after =
        state.file_index_repository().get_file("group-1", "missing.txt").unwrap().unwrap();
    assert_eq!(
        versions_of("missing.txt"),
        missing_versions_before,
        "a disk-missing indexed file must not be tombstoned by the add-only reconcile"
    );
    assert!(!missing_after.deleted, "the add-only reconcile must never tombstone an existing row");

    // The new file is actually persisted to the index, not just
    // returned -- and a second add-only pass is idempotent (nothing
    // new to add, and still no mutation of the other three rows).
    assert!(state.file_index_repository().get_file("group-1", "new.txt").unwrap().is_some());
    let second = proc.reconcile_added_files("group-1", &root).unwrap();
    assert!(
        second.is_empty(),
        "a second add-only pass with nothing new must emit nothing: {second:?}"
    );
}

/// The add-only backstop runs every ~90 s over the whole folder; with nothing new on
/// disk it must not pull the index's rows (block lists and all) into memory each tick.
/// It asks only which paths the index has, and still indexes a genuinely new file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_add_only_backstop_does_not_load_the_rows_it_leaves_alone() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    for i in 0..30 {
        std::fs::write(root.join(format!("f{i}.txt")), format!("body {i}")).unwrap();
    }
    assert_eq!(proc.scan_existing_files("group-1", &root).unwrap().len(), 30);

    let before = state.full_rows_listed();
    assert!(proc.reconcile_added_files("group-1", &root).unwrap().is_empty());
    assert_eq!(
        state.full_rows_listed(),
        before,
        "an add-only pass over an unchanged folder loaded full index rows"
    );

    std::fs::write(root.join("new.txt"), b"new").unwrap();
    let added = proc.reconcile_added_files("group-1", &root).unwrap();
    assert_eq!(added.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(), vec!["new.txt"]);
}

/// once the accumulator's internal
/// delivery queue is forced past capacity by a backlog
/// (see `debounce`'s own `executor_backlog_trigger_...` test for the
/// queue-merge mechanism in isolation), every file still ends up
/// correctly indexed end to end -- via the merged `Paths` batch the
/// queue collapses into now (no watcher overflow occurs in this
/// scenario, so no information was ever lost; see `push_ready`'s own
/// doc comment for why this no longer falls back to a full rescan).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn executor_backlog_recovers_to_a_fully_correct_index() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    // Unlike the full-rescan-fallback scenarios (which never call
    // `adopt_root`), this test now genuinely exercises PER-PATH
    // capture (see `push_ready`'s own doc comment on why a mere
    // backlog no longer falls back to a full rescan), and per-path
    // capture needs the group's policy actually adopted to author
    // anything at all.
    adopt_root(&state, "group-1", &root);
    let proc = Arc::new(proc);

    const FILE_COUNT: usize = 30;
    for i in 0..FILE_COUNT {
        std::fs::write(root.join(format!("obj-{i}.bin")), format!("content {i}")).unwrap();
    }

    let (events_tx, events_rx) = tokio::sync::mpsc::channel(256);
    // Never drained: forces the internal ready_queue to merge into a
    // single Paths batch once it exceeds DEFAULT_EXECUTOR_CHANNEL_CAPACITY
    // (no watcher overflow here, so the merge stays Paths, not RescanRequired).
    let (flush_tx, mut flush_rx) = tokio::sync::mpsc::channel(1);
    let config = yadorilink_filesystem_sync::debounce::DebounceConfig {
        quiet_period: std::time::Duration::from_millis(15),
        max_flush_interval: std::time::Duration::from_millis(60),
        burst_threshold: 1000,
    };
    let (_flush_requests_tx, flush_requests_rx) = tokio::sync::mpsc::channel(1);
    let (_flush_all_requests_tx, flush_all_requests_rx) = tokio::sync::mpsc::channel(1);
    tokio::spawn(yadorilink_filesystem_sync::debounce::run_debouncer(
        config,
        events_rx,
        flush_tx,
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
        flush_requests_rx,
        flush_all_requests_rx,
    ));

    // Many separate, well-spaced single-path windows — each one is a
    // *real* file (so a non-fallback flush would also reconstruct
    // correctly), but there are enough of them, undrained, that the
    // delivery queue must eventually merge. Every one of the
    // `FILE_COUNT` files gets its own event -- unlike the old
    // full-rescan-fallback version of this test, nothing here is
    // "unknown"; the whole point of the merge (see `push_ready`'s own
    // doc comment) is that a backlog of fully-known changes must
    // still deliver every one of them, not silently rely on a
    // directory walk to discover files this accumulator was never
    // even told about. The gap between sends needs real headroom
    // above quiet_period (15ms): on a slower/more contended CI
    // runner (observed on windows-latest at the old 25ms gap), a
    // slow-to-be-polled debouncer task can let several sends queue up
    // and then process them back-to-back, merging windows that were
    // meant to stay separate and never reaching the merge this test
    // means to exercise (same root cause as, and fixed the same way
    // as, debounce.rs's sibling test).
    for i in 0..FILE_COUNT {
        events_tx
            .send(FsChangeEvent {
                path: root.join(format!("obj-{i}.bin")),
                kind: FsChangeKind::CreatedOrModified,
            })
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }

    // Now drain everything and process each flush through the same
    // executor logic the daemon's flush-processing task (`link_runtime::tasks`)
    // uses. The gap between flushes is
    // bounded by max_flush_interval (60ms) under normal scheduling,
    // but this per-recv timeout needs real headroom above that on a
    // slow/contended CI runner (observed needing more than 500ms on
    // this suite's first real Windows run) -- it only ends the loop
    // once flushes genuinely stop arriving, so a generous bound here
    // doesn't weaken what the test verifies, just how patiently it
    // waits for a real signal.
    let mut total_records = Vec::new();
    while let Ok(Some(flush)) =
        tokio::time::timeout(std::time::Duration::from_secs(3), flush_rx.recv()).await
    {
        let outcome = proc.process_flush("group-1", &root, flush).await.unwrap();
        total_records.extend(outcome.records);
    }

    // Whether via individually-tracked paths or a merged backlog
    // batch, every file must end up correctly indexed — no permanent
    // gaps from the merge.
    assert_eq!(state.file_index_repository().list_files("group-1").unwrap().len(), FILE_COUNT);
    for i in [0, FILE_COUNT / 2, FILE_COUNT - 1] {
        assert!(
            state
                .file_index_repository()
                .get_file("group-1", &format!("obj-{i}.bin"))
                .unwrap()
                .is_some(),
            "file obj-{i}.bin is missing from the recovered index"
        );
    }
}

/// a file below the size threshold is chunked with the fixed-size
/// chunker — the automatic size-based decision picks fixed for small
/// files with no per-folder configuration involved.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn small_file_uses_fixed_size_chunking() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let file_path = root.join("hello.txt");
    std::fs::write(&file_path, b"hello world").unwrap();

    let record = expect_file_changed(
        proc.process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap(),
    );

    // The temp directory is bound, not a temporary: the store keeps its
    // index open in that directory for as long as it lives, so a
    // `TempDir` dropped at the end of the constructing expression would
    // delete the store out from under itself.
    let throwaway_dir = tempfile::tempdir().unwrap();
    let expected = yadorilink_local_storage::chunk_file(
        &SegmentBlockStore::new(throwaway_dir.path()).unwrap(),
        &file_path,
    )
    .unwrap();
    assert_eq!(record.blocks.len(), expected.len());
    assert_eq!(record.blocks[0].size, expected[0].size, "must match chunk_file's fixed sizing");
}

/// a file at or above the size threshold is
/// automatically chunked with CDC — verified by comparing against
/// `chunk_file_content_defined`'s direct output (deterministic for the
/// same content/parameters), and confirming it differs from what
/// fixed-size chunking would have produced for the same content.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_file_uses_content_defined_chunking() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);

    // Deterministic pseudo-random content, at the size threshold —
    // real CDC boundary-finding depends on actual byte entropy.
    use rand::{RngExt, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(11);
    let content: Vec<u8> =
        (0..yadorilink_local_storage::CDC_SIZE_THRESHOLD as usize).map(|_| rng.random()).collect();
    let file_path = root.join("big.bin");
    std::fs::write(&file_path, &content).unwrap();

    let record = expect_file_changed(
        proc.process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap(),
    );

    // Bound, not a temporary -- see the sibling test above for why.
    let throwaway_dir = tempfile::tempdir().unwrap();
    let throwaway_store = SegmentBlockStore::new(throwaway_dir.path()).unwrap();
    let expected_cdc =
        yadorilink_local_storage::chunk_file_content_defined(&throwaway_store, &file_path).unwrap();
    let expected_fixed =
        yadorilink_local_storage::chunk_file(&throwaway_store, &file_path).unwrap();

    assert_eq!(record.blocks, expected_cdc, "must match chunk_file_content_defined's output");
    assert_ne!(
        record.blocks, expected_fixed,
        "CDC output must differ from what fixed-size chunking would have produced"
    );
}

/// Crash-safety property: `flush_durable`'s `staged ->
/// durable` boundary structurally gates the `durable -> authoritative`
/// half too -- a source capture must not publish a `FileRecord` for
/// blocks that are not yet durable. Deterministic via `SegmentBlockStore::
/// install_durability_barrier_hook_for_tests`, which fires exactly
/// once `commit_batch` has finished all of a batch's durability work
/// but before it returns to its caller (`chunk_file_content_defined`,
/// still inside `build_record_for_created_or_modified`'s own
/// `block_in_place`) -- pausing there and observing no indexed
/// `FileRecord` yet, then releasing and observing one appear only
/// afterward, is a real ordering proof, not a timing-sensitive guess.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flush_durable_gates_authoritative_publication_deterministically() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let state = Arc::new(TestReplica::open_in_memory().unwrap());
    let root_dir = tempfile::tempdir().unwrap();
    let proc = LocalChangeProcessor::new(
        state.clone(),
        store.clone(),
        "device-a".into(),
        std::sync::Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
    );
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);

    use rand::{RngExt, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(21);
    let content: Vec<u8> =
        (0..yadorilink_local_storage::CDC_SIZE_THRESHOLD as usize).map(|_| rng.random()).collect();
    let file_path = root.join("gated.bin");
    std::fs::write(&file_path, &content).unwrap();

    let reached_barrier = Arc::new(Latch::new());
    let release_barrier = Arc::new(Latch::new());
    {
        let reached_barrier = reached_barrier.clone();
        let release_barrier = release_barrier.clone();
        store.install_durability_barrier_hook_for_tests(move || {
            reached_barrier.raise();
            release_barrier.wait();
        });
    }

    let capture_task = tokio::spawn(async move {
        expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        )
    });

    assert!(
        reached_barrier.wait_timeout(std::time::Duration::from_secs(20)),
        "capture never reached the bulk-ingest barrier within 20s"
    );

    // The batch's blocks are already durable on disk at this exact
    // point (that's when the hook fires) -- but nothing has published
    // a FileRecord referencing them yet, because `commit_batch` has
    // not returned to `build_record_for_created_or_modified`, which
    // has not returned to `process_event`, which is what actually
    // calls `upsert_file`. If this assertion ever fails, it means
    // some future change let authoritative publication race ahead of
    // (rather than strictly follow) the durability barrier.
    assert!(
        state.file_index_repository().get_file("group-1", "gated.bin").unwrap().is_none(),
        "no FileRecord may exist while flush_durable is still blocked mid-batch"
    );

    release_barrier.raise();
    let record = capture_task.await.unwrap();

    let published =
        state.file_index_repository().get_file("group-1", "gated.bin").unwrap().unwrap();
    assert_eq!(
        published.blocks, record.blocks,
        "the FileRecord becomes visible only after flush_durable released, and matches what \
         process_event returned"
    );
}

// --- Symlink pruning and cycle safety ---

/// a symlink inside the folder is recorded as a symlink
/// record — correct raw target text, no content blocks, and
/// `record_kind = Symlink` in the index (not folded into `FileRecord`
/// — see `types::RecordKind`'s doc comment).
#[cfg(unix)]
#[tokio::test]
async fn symlink_inside_folder_is_recorded_as_a_symlink_with_no_blocks() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    std::fs::write(root.join("real.txt"), b"target content").unwrap();
    let link_path = root.join("link.txt");
    std::os::unix::fs::symlink("real.txt", &link_path).unwrap();

    let record = expect_file_changed(
        proc.process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: link_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap(),
    );

    assert_eq!(record.path, "link.txt");
    assert!(record.blocks.is_empty(), "a symlink record must carry no content blocks");
    assert_eq!(
        state.file_index_repository().get_record_kind("group-1", "link.txt").unwrap(),
        Some(yadorilink_replica_domain::file::RecordKind::Symlink)
    );
    assert_eq!(
        state.file_index_repository().get_symlink_target("group-1", "link.txt").unwrap(),
        Some(b"real.txt".to_vec())
    );
    assert!(!state.file_index_repository().get_symlink_out_of_root("group-1", "link.txt").unwrap());
    // The target file itself must still be indexed normally and
    // separately — the symlink never dereferences into it.
    let target_record = state.file_index_repository().get_file("group-1", "real.txt").unwrap();
    assert!(target_record.is_none(), "target wasn't scanned in this single-event test");
}

/// A symlink target containing a byte that is not valid UTF-8 (real and
/// legal on Unix — a symlink target has no UTF-8 requirement) is
/// captured byte-exactly, not lossily. Not constructible portably on
/// Windows (its paths are UTF-16, so there is no equivalent way to hand
/// `std::os::unix::fs::symlink` an arbitrary invalid byte sequence);
/// `change::non_utf8_symlink_target_round_trips_byte_exactly` and
/// `fs_identity`'s own Windows-side tests cover the encoding and the
/// unpaired-surrogate case respectively, so this Unix-only test is not
/// this crate's only coverage of the byte-exactness property, just the
/// one exercised through a real on-disk symlink and the local capture
/// path.
#[cfg(unix)]
#[tokio::test]
async fn symlink_with_non_utf8_target_is_captured_byte_exactly() {
    use std::os::unix::ffi::OsStrExt;

    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let raw_target = std::ffi::OsStr::from_bytes(b"/tmp/\xffbroken-utf8/target");
    assert!(
        raw_target.to_str().is_none(),
        "fixture must actually be invalid UTF-8 (Path::to_string_lossy would replace it)"
    );
    let link_path = root.join("link.txt");
    std::os::unix::fs::symlink(raw_target, &link_path).unwrap();

    expect_file_changed(
        proc.process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: link_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap(),
    );

    assert_eq!(
        state.file_index_repository().get_symlink_target("group-1", "link.txt").unwrap(),
        Some(raw_target.as_bytes().to_vec()),
        "the captured target must be the exact on-disk bytes, not a lossy UTF-8 conversion"
    );
}

/// `scan_existing_files` classifies a pre-existing
/// symlink the same way a live watcher event does.
#[cfg(unix)]
#[test]
fn scan_existing_files_records_a_symlink_with_correct_target_text() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    std::fs::write(root.join("real.txt"), b"target content").unwrap();
    std::os::unix::fs::symlink("real.txt", root.join("link.txt")).unwrap();

    let records = proc.scan_existing_files("group-1", &root).unwrap();
    let link_record = records.iter().find(|r| r.path == "link.txt").unwrap();
    assert!(link_record.blocks.is_empty());
    assert_eq!(
        state.file_index_repository().get_record_kind("group-1", "link.txt").unwrap(),
        Some(yadorilink_replica_domain::file::RecordKind::Symlink)
    );
    assert_eq!(
        state.file_index_repository().get_symlink_target("group-1", "link.txt").unwrap(),
        Some(b"real.txt".to_vec())
    );

    // The regular file target is indexed too, as its own unrelated
    // record — proves the symlink and its target are two independent
    // entries, not one dereferenced into the other.
    let target_record = records.iter().find(|r| r.path == "real.txt").unwrap();
    assert!(!target_record.blocks.is_empty());
}

/// a symlinked directory's contents never appear as
/// separate scanned records — only the symlink itself is enumerated,
/// as a single leaf entry, never descended into as a subtree.
#[cfg(unix)]
#[test]
fn symlinked_directory_contents_never_appear_as_separate_scanned_records() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    std::fs::create_dir_all(root.join("real_dir")).unwrap();
    std::fs::write(root.join("real_dir/secret.txt"), b"must not leak").unwrap();
    std::os::unix::fs::symlink("real_dir", root.join("link_dir")).unwrap();

    let records = proc.scan_existing_files("group-1", &root).unwrap();
    let paths: Vec<&str> = records.iter().map(|r| r.path.as_str()).collect();

    assert!(paths.contains(&"link_dir"), "the symlink itself must be recorded: {paths:?}");
    assert!(
        !paths.iter().any(|p| p.starts_with("link_dir/")),
        "nothing inside the symlinked directory may be enumerated via the link: {paths:?}"
    );
    assert_eq!(
        state.file_index_repository().get_record_kind("group-1", "link_dir").unwrap(),
        Some(yadorilink_replica_domain::file::RecordKind::Symlink)
    );
    // The real directory's own (non-symlinked) path is scanned
    // normally and independently.
    assert!(paths.contains(&"real_dir/secret.txt"));
}

/// the same "never descend into a symlinked directory"
/// guarantee holds for the watcher's directory-registration path, not
/// just the scanner — a `CreatedOrModified` event for a freshly
/// created symlink-to-directory must not cause the watcher to start
/// watching (and thus later report file events for) anything inside
/// the target.
#[cfg(unix)]
#[tokio::test]
async fn watcher_never_registers_watches_inside_a_symlinked_directory() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join("real_dir")).unwrap();
    let mut watcher = yadorilink_filesystem_sync::watcher::watch_folder(&root).unwrap();

    std::os::unix::fs::symlink(root.join("real_dir"), root.join("link_dir")).unwrap();
    // The very first event received isn't necessarily this one:
    // macOS FSEvents' watch stream can have a small replay window
    // covering moments just before it starts, so the `real_dir`
    // creation above (right before watch_folder) can legitimately
    // surface here too (observed reproducing in real CI) -- loop
    // past anything unrelated, same tolerance the leak-check below
    // already applies to this same FSEvents quirk.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut saw_link_dir = false;
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let event = tokio::time::timeout(remaining, watcher.events.recv())
            .await
            .expect("timed out waiting for the symlink-creation event")
            .expect("watcher channel closed");
        if event.path.file_name().and_then(|n| n.to_str()) == Some("link_dir") {
            saw_link_dir = true;
            break;
        }
    }
    assert!(saw_link_dir, "the symlink creation itself must still be reported");

    // A file written *through* the symlinked directory into its real
    // target must never surface as a watched event *under the link's
    // own path* — proof no recursive watch was registered on the
    // target via the link. Checked as "strictly inside link_dir"
    // (`link_dir/<something>`), not merely "mentions link_dir"
    // anywhere: macOS FSEvents can legitimately emit more than one
    // coalesced notification for the link's own creation (a known,
    // pre-existing source of flakiness this crate's other comments
    // already call out), which would be a false positive for a
    // cruder substring check but says nothing about a leak.
    std::fs::write(root.join("real_dir/new_file.txt"), b"leak?").unwrap();
    let link_dir_path = root.join("link_dir");
    let mut leaked = None;
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(800);
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match tokio::time::timeout(remaining, watcher.events.recv()).await {
            Ok(Some(ev)) => {
                if ev.path.starts_with(&link_dir_path) && ev.path != link_dir_path {
                    leaked = Some(ev);
                    break;
                }
                // Some other, unrelated event (e.g. a duplicate
                // notification about `link_dir`'s own creation, or the
                // legitimate `real_dir/new_file.txt` event reached via
                // its real, directly-watched path) — keep draining.
            }
            _ => break,
        }
    }
    assert!(
        leaked.is_none(),
        "the watcher must never report an event reached only via the symlinked directory: {leaked:?}"
    );
}

/// a symlink with an absolute target is flagged.
#[cfg(unix)]
#[tokio::test]
async fn absolute_target_symlink_is_flagged() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let link_path = root.join("abs_link");
    std::os::unix::fs::symlink("/etc/passwd", &link_path).unwrap();

    expect_file_changed(
        proc.process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: link_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap(),
    );

    assert!(state.file_index_repository().get_symlink_out_of_root("group-1", "abs_link").unwrap());
    assert_eq!(
        state.file_index_repository().get_symlink_target("group-1", "abs_link").unwrap(),
        Some(b"/etc/passwd".to_vec()),
        "the raw target text is still recorded and synced, never rewritten"
    );
}

/// a relative symlink target that syntactically resolves
/// outside the linked folder's root (via `..`) is flagged too, without
/// ever dereferencing the target (the target need not even exist).
#[cfg(unix)]
#[tokio::test]
async fn out_of_root_relative_target_symlink_is_flagged() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    std::fs::create_dir_all(root.join("subdir")).unwrap();
    let link_path = root.join("subdir/escape_link");
    // Climbs above `root` itself: subdir/../.. -> above root.
    std::os::unix::fs::symlink("../../outside/nonexistent", &link_path).unwrap();

    expect_file_changed(
        proc.process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: link_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap(),
    );

    assert!(state
        .file_index_repository()
        .get_symlink_out_of_root("group-1", "subdir/escape_link")
        .unwrap());
}

/// a relative target that stays inside the folder root
/// (even via a `..` that doesn't actually escape) is NOT flagged.
#[cfg(unix)]
#[tokio::test]
async fn in_root_relative_target_symlink_is_not_flagged() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    std::fs::create_dir_all(root.join("subdir")).unwrap();
    std::fs::write(root.join("sibling.txt"), b"data").unwrap();
    let link_path = root.join("subdir/in_root_link");
    // subdir/../sibling.txt -> root/sibling.txt: still inside root.
    std::os::unix::fs::symlink("../sibling.txt", &link_path).unwrap();

    expect_file_changed(
        proc.process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: link_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap(),
    );

    assert!(!state
        .file_index_repository()
        .get_symlink_out_of_root("group-1", "subdir/in_root_link")
        .unwrap());
}

/// a self-referential symlinked-directory cycle (`a -> a`)
/// must not hang or recurse when scanned — proven with a real
/// wall-clock timeout around the scan (run on a background thread,
/// since `scan_existing_files` is synchronous) so a genuine infinite
/// loop fails the test loudly instead of hanging the suite forever.
/// This is expected to pass structurally, not by luck: the rule means
/// the scanner never descends into ANY symlinked directory, cyclic or
/// not, so there is no recursive call into the cycle to bound in the
/// first place — this test exists to confirm that reasoning against
/// real filesystem behavior rather than trusting it blindly.
#[cfg(unix)]
#[test]
fn self_referential_symlinked_directory_cycle_does_not_hang_or_recurse() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    std::fs::create_dir_all(root.join("cyc")).unwrap();
    // cyc/a -> cyc/a (a symlink whose own path is its target).
    std::os::unix::fs::symlink(root.join("cyc/a"), root.join("cyc/a")).unwrap();
    std::fs::write(root.join("ordinary.txt"), b"unrelated").unwrap();

    let (tx, rx) = std::sync::mpsc::channel();
    let proc = Arc::new(proc);
    let proc_clone = proc.clone();
    let root_clone = root.clone();
    std::thread::spawn(move || {
        let result = proc_clone.scan_existing_files("group-1", &root_clone);
        let _ = tx.send(result);
    });

    let result = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("scan_existing_files hung on a self-referential symlink cycle");
    let records = result.unwrap();

    let paths: Vec<&str> = records.iter().map(|r| r.path.as_str()).collect();
    assert!(paths.contains(&"cyc/a"), "the cyclic symlink itself must still be recorded");
    assert!(paths.contains(&"ordinary.txt"));
    assert_eq!(
        state.file_index_repository().get_record_kind("group-1", "cyc/a").unwrap(),
        Some(yadorilink_replica_domain::file::RecordKind::Symlink)
    );
}

/// a two-hop symlinked-directory cycle (`a/b -> a`, i.e. a
/// directory containing a symlink back to one of its own ancestors)
/// also must not hang or recurse.
#[cfg(unix)]
#[test]
fn ancestor_referencing_symlinked_directory_cycle_does_not_hang_or_recurse() {
    let (proc, _state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    std::fs::create_dir_all(root.join("a")).unwrap();
    // a/b -> a (points back up at its own parent).
    std::os::unix::fs::symlink(root.join("a"), root.join("a/b")).unwrap();

    let (tx, rx) = std::sync::mpsc::channel();
    let proc = Arc::new(proc);
    let proc_clone = proc.clone();
    let root_clone = root.clone();
    std::thread::spawn(move || {
        let result = proc_clone.scan_existing_files("group-1", &root_clone);
        let _ = tx.send(result);
    });

    let result = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("scan_existing_files hung on an ancestor-referencing symlink cycle");
    let records = result.unwrap();
    let paths: Vec<&str> = records.iter().map(|r| r.path.as_str()).collect();
    assert!(paths.contains(&"a/b"));
    assert!(!paths.iter().any(|p| p.starts_with("a/b/")), "must never descend through the cycle");
}

/// `normalize_syntactic`/`symlink_target_is_out_of_root`
/// never touch the filesystem — proven by pointing at a target that
/// does not exist at all (`read_link`-based classification must not
/// require or attempt to resolve it).
#[cfg(unix)]
#[tokio::test]
async fn symlink_classification_does_not_require_the_target_to_exist() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let link_path = root.join("dangling_link");
    std::os::unix::fs::symlink("this/path/does/not/exist.txt", &link_path).unwrap();

    let record = expect_file_changed(
        proc.process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: link_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap(),
    );

    assert!(record.blocks.is_empty());
    assert_eq!(
        state.file_index_repository().get_symlink_target("group-1", "dangling_link").unwrap(),
        Some(b"this/path/does/not/exist.txt".to_vec())
    );
    assert!(!state
        .file_index_repository()
        .get_symlink_out_of_root("group-1", "dangling_link")
        .unwrap());
}

/// Builds a change-emitting processor whose local-emission auth provider is
/// driven by the returned flag: `false` (the initial value) makes the
/// provider report the group's policy as stale (`Err(PolicyUnavailable)`),
/// and flipping it to `true` makes the provider report the group as
/// authorized again — the exact transition the daemon's provider
/// undergoes when a failed policy snapshot is later superseded by a valid
/// one. The `TempDir`s are returned so the caller keeps them alive.
fn processor_with_toggleable_policy() -> (
    LocalChangeProcessor,
    Arc<TestReplica>,
    Arc<std::sync::atomic::AtomicBool>,
    tempfile::TempDir,
    tempfile::TempDir,
) {
    use ed25519_dalek::SigningKey;
    use std::sync::atomic::Ordering;
    use yadorilink_replica_domain::local_op::PolicyUnavailable;

    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let state = Arc::new(TestReplica::open_in_memory().unwrap());

    let policy_healthy = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let policy_healthy = policy_healthy.clone();
        state.set_local_change_auth_provider(Arc::new(move |_group_id| {
            if policy_healthy.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(PolicyUnavailable)
            }
        }));
    }

    let emitter =
        Arc::new(LocalAuthorKey::for_tests("device-a", SigningKey::from_bytes(&[7u8; 32])));
    let proc = LocalChangeProcessor::new(
        state.clone(),
        store,
        "device-a".into(),
        std::sync::Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
    )
    .with_change_emitter(emitter);
    let root_dir = tempfile::tempdir().unwrap();
    (proc, state, policy_healthy, store_dir, root_dir)
}

/// While a group's policy is stale the auth provider returns
/// `Err(PolicyUnavailable)`, and a local edit must then produce NO native
/// delta — appending a placeholder-auth delta here would create a local
/// head every valid-policy peer rejects, stranding an un-replicable
/// branch. The edit must not be lost either: the path stays in the durable
/// dirty-path journal so a later re-drive can emit it once policy heals.
#[tokio::test]
async fn stale_policy_withholds_the_dag_change_but_keeps_the_path_journaled_dirty() {
    let (proc, state, _policy_healthy, _store_dir, root_dir) = processor_with_toggleable_policy();
    let root = canonical_root(&root_dir);
    let file_path = root.join("note.txt");
    std::fs::write(&file_path, b"hello").unwrap();

    let group = "group-1";
    let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![(
        file_path,
        FsChangeKind::CreatedOrModified,
        1_000,
    )]);
    let outcome = proc.process_flush(group, &root, flush).await.unwrap();

    // No record is announced and — crucially — the group's history is still
    // empty: no placeholder-auth change entered native state.
    assert!(outcome.records.is_empty(), "a stale-policy edit must not announce a record");
    assert!(
        crate::test_support::native_group_heads(&state, group).is_empty(),
        "no placeholder-auth change may enter native state while policy is stale"
    );
    // The edit is not lost: it remains journaled dirty for re-drive.
    assert!(state.dirty_path_repository().is_path_dirty(group, "note.txt").unwrap());
    assert!(state
        .dirty_path_repository()
        .list_dirty_paths(group)
        .unwrap()
        .iter()
        .any(|d| d.path == "note.txt"));
}

/// The coordination plane's netmap push carries a `policyInvalidGroupIds`
/// list naming groups whose stored policy state is malformed or corrupt
/// on the coordination plane's side (see the coordination worker's
/// netmap-computation and policy-distribution modules, which isolate
/// such a group out of the push rather than trust it). The daemon's
/// netmap client has no field for that list at all, so nothing ever
/// marks a group named there stale -- unlike the whole-policy-portion
/// failure this module's `stale_policy_withholds_...` test above covers,
/// a per-group `policyInvalidGroupIds` entry reaches this emission layer
/// only through the local-emission auth provider. In the daemon the
/// unified group-policy resolver funnels a coordinator-flagged group
/// through `mark_group_policy_stale` and reports it `Withhold`, so the
/// provider returns `Err(PolicyUnavailable)` for exactly that group while
/// healthy groups keep getting a real stamp. The group-aware provider
/// installed below stands in for that resolver at this layer.
#[tokio::test]
async fn policy_invalid_group_id_stops_local_dag_emission_for_that_group() {
    let (proc, state, _policy_healthy, _store_dir, root_dir) = processor_with_toggleable_policy();
    // Only the coordinator-flagged group withholds; every other group
    // still resolves to a real stamp. This is what the daemon's resolver
    // does once `policyInvalidGroupIds` is consumed.
    state.set_local_change_auth_provider(std::sync::Arc::new(|group_id| {
        if group_id == "policy-invalid-group" {
            Err(yadorilink_replica_domain::local_op::PolicyUnavailable)
        } else {
            Ok(())
        }
    }));

    let root = canonical_root(&root_dir);
    let file_path = root.join("note.txt");
    std::fs::write(&file_path, b"hello").unwrap();

    let group = "policy-invalid-group";
    let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![(
        file_path,
        FsChangeKind::CreatedOrModified,
        1_000,
    )]);
    let outcome = proc.process_flush(group, &root, flush).await.unwrap();

    assert!(
        outcome.records.is_empty(),
        "a local edit in a group the coordination plane flagged policy-invalid must be \
         withheld, not committed to native state like a healthy group's edit"
    );
    assert!(
        crate::test_support::native_group_heads(&state, group).is_empty(),
        "no change may enter native state for a policy-invalid group; the daemon funnels \
         `policyInvalidGroupIds` through the same withholding staleness gate"
    );
}

/// A restart re-drive that fully clears the dirty journal must leave a
/// second, immediately-following re-drive a true no-op: no records
/// produced, no journal rows re-appear, and no duplicate native head. This
/// pins `redrive_dirty_journal`'s empty-journal short-circuit against
/// Stage-1's batched journal/clear path specifically, since a batching
/// bug that left a stray row behind (or resurrected one) would only
/// show up on this second call, not the first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redriving_an_already_cleared_dirty_journal_twice_in_a_row_is_a_no_op() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    adopt_root(&state, group, &root);

    std::fs::write(root.join("a.txt"), b"aaa").unwrap();
    std::fs::write(root.join("b.txt"), b"bbb").unwrap();
    let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![
        (root.join("a.txt"), FsChangeKind::CreatedOrModified, 0),
        (root.join("b.txt"), FsChangeKind::CreatedOrModified, 0),
    ]);
    proc.process_flush(group, &root, flush).await.unwrap();
    assert!(
        state.dirty_path_repository().list_dirty_paths(group).unwrap().is_empty(),
        "both paths must have succeeded and cleared their journal rows"
    );
    let heads_after_flush = crate::test_support::native_group_heads(&state, group);

    let first_redrive = proc.redrive_dirty_journal(group, &root).await.unwrap();
    assert!(
        first_redrive.records.is_empty(),
        "an already-empty journal must produce no records on re-drive"
    );

    let second_redrive = proc.redrive_dirty_journal(group, &root).await.unwrap();
    assert!(
        second_redrive.records.is_empty(),
        "a second, immediately-following re-drive must remain a no-op"
    );
    assert!(state.dirty_path_repository().list_dirty_paths(group).unwrap().is_empty());
    assert_eq!(
        crate::test_support::native_group_heads(&state, group),
        heads_after_flush,
        "re-driving an empty journal twice must never move the native head"
    );
}

/// Once the policy heals — the provider flips from `Err(PolicyUnavailable)`
/// to `Ok(auth)` — re-driving the dirty journal emits the previously
/// withheld edit as a real, non-placeholder-auth change and clears the
/// journal row, so the deferred edit replicates normally.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn healed_policy_reemits_the_withheld_edit_with_real_auth_and_clears_the_journal() {
    use std::sync::atomic::Ordering;

    let (proc, state, policy_healthy, _store_dir, root_dir) = processor_with_toggleable_policy();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    adopt_root(&state, group, &root);
    let file_path = root.join("note.txt");
    std::fs::write(&file_path, b"hello").unwrap();

    let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![(
        file_path,
        FsChangeKind::CreatedOrModified,
        1_000,
    )]);
    // Stale phase: withheld, journaled dirty (asserted in full by the test
    // above; here it is only the precondition for the re-drive).
    proc.process_flush(group, &root, flush).await.unwrap();
    assert!(crate::test_support::native_group_heads(&state, group).is_empty());
    assert!(state.dirty_path_repository().is_path_dirty(group, "note.txt").unwrap());

    // Policy heals; the backstop re-drive re-emits the withheld edit.
    policy_healthy.store(true, Ordering::SeqCst);
    let redriven = proc.redrive_dirty_journal(group, &root).await.unwrap();
    assert_eq!(redriven.records.len(), 1, "the healed re-drive emits the withheld edit");

    let heads = crate::test_support::native_group_heads(&state, group);
    assert_eq!(heads.len(), 1, "exactly one change now heads the group");
    assert_eq!(
        crate::test_support::native_deltas(&state, group).len(),
        1,
        "the emitted delta is stored"
    );
    // The journal row is cleared on the successful re-emission.
    assert!(!state.dirty_path_repository().is_path_dirty(group, "note.txt").unwrap());
    assert!(state.dirty_path_repository().list_dirty_paths(group).unwrap().is_empty());
}

/// While the group's policy stays unavailable, re-driving the dirty
/// journal must not take up the withheld paths at all: each would only be
/// re-read and refused again, and the periodic backstop would repeat that
/// for every withheld path on every tick (a large directory tree captured
/// before its policy arrives puts thousands of rows in the journal). The
/// rows stay journaled, and once the policy arrives the next re-drive
/// captures every one of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redrive_leaves_withheld_paths_untouched_until_the_policy_arrives() {
    use std::sync::atomic::Ordering;

    const WITHHELD: usize = 40;
    let (proc, state, policy_healthy, _store_dir, root_dir) = processor_with_toggleable_policy();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    adopt_root(&state, group, &root);
    let paths: Vec<_> = (0..WITHHELD)
        .map(|i| {
            let path = root.join(format!("f{i}.txt"));
            std::fs::write(&path, format!("content {i}")).unwrap();
            (path, FsChangeKind::CreatedOrModified, 1_000 + i as i64)
        })
        .collect();
    proc.process_flush(
        group,
        &root,
        yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(paths),
    )
    .await
    .unwrap();
    assert_eq!(state.dirty_path_repository().list_dirty_paths(group).unwrap().len(), WITHHELD);

    let journaled_before = state.journaled_dirty_batch_entries();
    for _ in 0..3 {
        let outcome = proc.redrive_dirty_journal(group, &root).await.unwrap();
        assert!(outcome.records.is_empty(), "nothing can be emitted without a policy");
    }
    assert_eq!(
        state.journaled_dirty_batch_entries() - journaled_before,
        0,
        "a re-drive without a policy must not re-process any withheld path"
    );
    assert_eq!(
        state.dirty_path_repository().list_dirty_paths(group).unwrap().len(),
        WITHHELD,
        "every withheld path stays journaled"
    );
    assert!(crate::test_support::native_group_heads(&state, group).is_empty());

    policy_healthy.store(true, Ordering::SeqCst);
    let redriven = proc.redrive_dirty_journal(group, &root).await.unwrap();
    assert_eq!(redriven.records.len(), WITHHELD, "the policy's arrival captures every path");
    assert!(state.dirty_path_repository().list_dirty_paths(group).unwrap().is_empty());
}

/// A restart reconciliation scan that detects an offline edit while the
/// group's policy is stale must NOT fall back to a delta-silent index write.
/// The historical fallback wrote the batch through the non-emitting
/// `upsert_files_batch`, advancing the local index to match disk — so a
/// later rescan saw no disk-vs-index diff and the change never entered the
/// native state, and (unlike the live `process_flush` path) nothing was journaled
/// dirty to re-drive it either. The edit was stranded outside native state
/// forever. The scan must instead withhold the index write, leave the
/// index unadvanced, and journal the path dirty, so the dirty-journal
/// re-drive re-emits the change and the native head advances once policy
/// heals. This test fails on the old silent fallback (the native head never
/// advances past the pre-edit head).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_policy_scan_withholds_index_write_then_reemits_offline_edit_once_healed() {
    use std::sync::atomic::Ordering;

    let (proc, state, policy_healthy, _store_dir, root_dir) = processor_with_toggleable_policy();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    adopt_root(&state, group, &root);
    let file_path = root.join("report.txt");

    // A healthy-policy live edit establishes the group's first native history.
    policy_healthy.store(true, Ordering::SeqCst);
    std::fs::write(&file_path, b"version one").unwrap();
    expect_file_changed(
        proc.process_event(
            group,
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap(),
    );
    let heads_before = crate::test_support::native_group_heads(&state, group);
    assert_eq!(heads_before.len(), 1, "sanity: the live edit established one native head");

    // Policy goes stale; the file is edited offline (daemon "stopped").
    policy_healthy.store(false, Ordering::SeqCst);
    std::fs::write(&file_path, b"version two, edited offline while policy was stale").unwrap();

    // The restart scan detects the offline edit, but policy is stale: it
    // must withhold both the native delta and the index write and journal the
    // path dirty. The old silent fallback wrote the index here.
    let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();
    let scan_records = proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
    assert!(
        scan_records.is_empty(),
        "a stale-policy scan must announce nothing — no record ever entered native state"
    );
    assert_eq!(
        crate::test_support::native_group_heads(&state, group),
        heads_before,
        "no change may enter native state while policy is stale"
    );
    // The index must NOT have advanced to the offline content: advancing it
    // is exactly what poisoned re-derivation in the old silent fallback.
    let indexed = state.file_index_repository().get_file(group, "report.txt").unwrap().unwrap();
    assert_eq!(
        indexed.size,
        b"version one".len() as u64,
        "the scan must not silently advance the index while policy is stale"
    );
    // The withheld edit is journaled dirty for the re-drive.
    assert!(
        state.dirty_path_repository().is_path_dirty(group, "report.txt").unwrap(),
        "the policy-withheld offline edit must be journaled dirty for re-drive"
    );

    // Policy heals; the dirty-journal re-drive re-emits the withheld edit.
    policy_healthy.store(true, Ordering::SeqCst);
    let redriven = proc.redrive_dirty_journal(group, &root).await.unwrap();
    assert_eq!(
        redriven.records.len(),
        1,
        "the healed re-drive emits the previously withheld offline edit"
    );

    let heads_after = crate::test_support::native_group_heads(&state, group);
    assert_ne!(
        heads_after, heads_before,
        "the offline edit must advance the native head once policy heals; the silent fallback \
         left it stranded outside native state forever"
    );
    let indexed = state.file_index_repository().get_file(group, "report.txt").unwrap().unwrap();
    assert_eq!(
        indexed.size,
        b"version two, edited offline while policy was stale".len() as u64,
        "the re-drive reconciles the index to the offline content"
    );
    assert!(
        !state.dirty_path_repository().is_path_dirty(group, "report.txt").unwrap(),
        "the journal row is cleared on the successful re-emission"
    );
}

/// The invariant the fingerprint retirement replaced a narrower assertion
/// with: a first-ever import whose full scan is policy-withheld on chunk
/// zero recovers through the dirty-journal re-drive, and every path it
/// recovers ends up with a usable actual-state generation -- the proof
/// `Present` now rests on -- rather than merely existing in the index.
///
/// This is the shape the small-folder startup race produced: the scan
/// withholds, the re-drive commits per file, and the convergence
/// criterion's fourth condition waits on evidence for each row. Asserting
/// the generation rather than a fingerprint asserts the thing the system
/// actually reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_withheld_first_import_leaves_every_path_with_a_usable_generation() {
    use std::sync::atomic::Ordering;

    let (proc, state, policy_healthy, _store_dir, root_dir) = processor_with_toggleable_policy();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    adopt_root(&state, group, &root);

    let names = ["a.txt", "b.txt", "c.txt"];
    for name in names {
        std::fs::write(root.join(name), format!("content of {name}").as_bytes()).unwrap();
    }

    let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();
    let scanned = proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
    assert!(
        scanned.is_empty(),
        "chunk zero is withheld, so the first import commits nothing: {scanned:?}"
    );

    policy_healthy.store(true, Ordering::SeqCst);
    let redriven = proc.redrive_dirty_journal(group, &root).await.unwrap();
    assert_eq!(
        redriven.records.len(),
        names.len(),
        "the healed re-drive re-emits every withheld path"
    );

    // Guard against the vacuous pass: zero live rows trivially has zero
    // paths missing a proof.
    let indexed = state.file_index_repository().list_files(group).unwrap();
    let live: Vec<_> = indexed.iter().filter(|record| !record.deleted).collect();
    assert_eq!(live.len(), names.len(), "every file is indexed after the re-drive");

    let unproven: Vec<&str> = live
        .iter()
        .filter(|record| {
            state
                .sqlite()
                .dag_lookup_materialized_generation(group, &record.path)
                .unwrap()
                .is_none()
        })
        .map(|record| record.path.as_str())
        .collect();
    assert!(
        unproven.is_empty(),
        "every path the re-drive committed must carry a usable actual-state generation; \
         these carry none: {unproven:?}"
    );

    // The journal is a terminal state, not a standing retry.
    assert!(
        state.dirty_path_repository().list_dirty_paths(group).unwrap().is_empty(),
        "the dirty journal must be drained once every path has been re-emitted"
    );
}

/// Builds a processor with change-history emission wired against a
/// plain, always-succeeding local-change auth (unlike
/// `processor_with_toggleable_policy`'s stale/healed toggle) — plus
/// direct access to the underlying `ReplicaCoordinator` and `LocalAuthorKey`
/// so a test can inspect native heads.
fn processor_with_emitter() -> (
    LocalChangeProcessor,
    Arc<TestReplica>,
    Arc<LocalAuthorKey>,
    tempfile::TempDir,
    tempfile::TempDir,
) {
    use ed25519_dalek::SigningKey;

    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let state = Arc::new(TestReplica::open_in_memory().unwrap());
    let emitter =
        Arc::new(LocalAuthorKey::for_tests("device-a", SigningKey::from_bytes(&[5u8; 32])));
    let proc = LocalChangeProcessor::new(
        state.clone(),
        store,
        "device-a".into(),
        std::sync::Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
    )
    .with_change_emitter(emitter.clone());
    let root_dir = tempfile::tempdir().unwrap();
    (proc, state, emitter, store_dir, root_dir)
}

/// Local-origin proof regression: a disk change between the content read and the final
/// pre-commit revalidation must suppress the proof entirely (never a
/// hard failure of the capture itself -- see `fresh_actual_state_
/// identity_if_unraced`'s own doc comment). Exercises the exact
/// helper `process_event_with_ignore_at`'s single-immediate commit
/// path calls, directly and deterministically -- no wall-clock race,
/// no real concurrent writer, just the two fingerprint states that
/// helper actually compares.
#[test]
fn closed_disk_observation_if_unraced_suppresses_on_a_fingerprint_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f.bin");
    std::fs::write(&path, b"v1").unwrap();
    let fingerprint_before_read = disk_race_fingerprint(&path);
    assert!(fingerprint_before_read.is_some(), "sanity: a real file must fingerprint");

    // Matching fingerprint: identity IS observed.
    assert!(
        closed_disk_observation_if_unraced(&path, fingerprint_before_read).is_some(),
        "an unchanged file between the two observations must still produce an identity"
    );

    // A write between "before read" and "final revalidation" changes
    // the fingerprint (size, at minimum) -- the helper must suppress,
    // not merely warn.
    std::fs::write(&path, b"v2, raced in").unwrap();
    assert!(
        closed_disk_observation_if_unraced(&path, fingerprint_before_read).is_none(),
        "a disk fingerprint mismatch between the pre-read and pre-commit observations must \
         suppress the identity entirely -- publishing a proof here would attest to content \
         that was never actually read/hashed for this commit"
    );

    // No file at all (e.g. deleted in the same window): also
    // suppressed, not a panic/error.
    std::fs::remove_file(&path).unwrap();
    assert!(closed_disk_observation_if_unraced(&path, fingerprint_before_read).is_none());

    // A `None` "before" fingerprint (the read itself raced a delete)
    // must never be treated as "nothing to compare against, so
    // trust it" -- always suppressed.
    assert!(closed_disk_observation_if_unraced(&path, None).is_none());
}

/// Local-origin zero-work regression. Without `file_index.rs`'s
/// `adopt_local_capture_actual_state` call (reverting it turns this test
/// red), a local capture would write no `path_materialized_generations`
/// row for its own freshly-authored content, so
/// `dag_zero_work_settlement_if_already_current`'s
/// `lookup_materialized_generation` call would always return `None`, and
/// the ordinary reconcile path (`materialize_dag_content_head`) would be
/// the only way this device's own already-correct file could ever settle
/// its projection obligation.
///
/// Asserted: local capture publishes a usable exact
/// actual-state proof in the SAME transaction as the native state/index
/// commit. This test asserts the durable state directly -- never a
/// wall-clock/call-count proxy -- via the exact three preconditions
/// `dag_zero_work_settlement_if_already_current` itself checks:
/// (1) a projection obligation exists for the path (the universal
/// admission invariant), (2)
/// `dag_lookup_materialized_generation` returns `Some` (the proof is
/// USABLE right now, not merely present-but-stale against the
/// mutation fence), and (3) that row's `resolved_path_state_hash`
/// equals what `dag_desired_resolved_path_state_hash` independently
/// derives for the group's own current native-resolved state --
/// precisely the equality `dag_zero_work_settlement_if_already_
/// current` gates a real settlement on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_capture_of_new_content_publishes_a_usable_exact_actual_state_proof() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    adopt_root(&state, group, &root);
    let file_path = root.join("report.txt");

    std::fs::write(&file_path, b"locally authored content").unwrap();
    expect_file_changed(
        proc.process_event(
            group,
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap(),
    );

    // (1) Admission still bumps this path's obligation exactly as it
    // would for ANY admitted change -- local admission is not
    // special-cased -- and the SAME transaction then settles it
    // against the exact proof published below, which is the only thing
    // that entitles it to. Creation is still universal; what changed is
    // that the close no longer waits for a Convergence Engine wake to
    // re-derive a conclusion this transaction already proved and wrote
    // down.
    //
    // That admission is not special-cased is asserted where it is still
    // observable: `local_emission_without_a_publishable_proof_leaves_
    // its_obligation_open` drives this same emission path with no proof
    // to settle against and finds the obligation open.
    assert!(
        state.sqlite().dag_lookup_projection_obligation(group, "report.txt").unwrap().is_none(),
        "a local emission that published a usable exact proof must leave no obligation \
         behind: the proof already establishes the desired state this change asked for, so \
         an open obligation here is a Convergence Engine wake with nothing to do"
    );

    // (2) The proof this fix publishes must be immediately usable --
    // not merely present, which `lookup_materialized_generation`'s own
    // fail-closed contract (its `published_under_mutation_generation`
    // CAS against the live fence) would refuse to return at all if
    // this fix's fence-then-write ordering were wrong.
    let basis = state.sqlite().dag_lookup_materialized_generation(group, "report.txt").unwrap();
    let basis = basis.expect(
        "GREEN behavior missing: local capture of new content must publish a USABLE exact \
         actual-state proof in the same transaction as its native state/index commit -- if this is \
         None, either the fix regressed to not publishing at all, or it published under a \
         stale/mismatched mutation-fence epoch",
    );
    assert_eq!(
        basis.object_kind,
        yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind::RegularFile
    );
    assert!(basis.version.is_some(), "a present object's proof must carry its version hash");
    assert!(
        basis.filesystem_identity.is_some(),
        "a present object's proof must carry a strong FileIdentity"
    );

    // (3) The exact equality `dag_zero_work_settlement_if_already_
    // current` gates a real settlement on: the published proof's
    // resolved_path_state_hash must equal what the group's own
    // CURRENT native-resolved desired state independently derives --
    // computed here via the same production hash builder
    // (`native_desired_projected_path_state_hash`), not re-derived by
    // this test's own logic, so this assertion fails if either side
    // of that real equality check ever drifts.
    let desired_hash =
        state.sqlite().native_desired_projected_path_state_hash(group, "report.txt").unwrap();
    assert_eq!(
        basis.resolved_path_state_hash, desired_hash,
        "the published proof's resolved_path_state_hash must match the group's own current \
         desired-state hash -- this exact equality is what \
         dag_zero_work_settlement_if_already_current gates a real zero-work close on, so a \
         mismatch here means the Convergence Engine would still fall through to the \
         ordinary (non-zero-work) reconcile path despite this fix"
    );
}

/// Local-origin proof regression: a locally observed deletion must publish an exact `Absent`
/// proof in the same transaction as its tombstone admission, so a
/// peer's own reconcile of this now-deleted path can zero-work close
/// (recognize "already absent") without a redundant remove syscall --
/// the same GREEN behavior as content capture, but for
/// `MaterializedObjectKind::Absent` rather than `RegularFile`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_capture_of_a_deletion_publishes_a_usable_exact_absent_proof() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    adopt_root(&state, group, &root);
    let file_path = root.join("report.txt");

    std::fs::write(&file_path, b"locally authored content").unwrap();
    expect_file_changed(
        proc.process_event(
            group,
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap(),
    );

    std::fs::remove_file(&file_path).unwrap();
    let tombstone = expect_file_changed(
        proc.process_event(
            group,
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::ObservedRemoval },
        )
        .await
        .unwrap(),
    );
    assert!(tombstone.deleted, "sanity: the deletion must have been admitted as a tombstone");

    // Exactly as for content capture
    // (`local_capture_of_new_content_publishes_a_usable_exact_actual_state_proof`):
    // admission opens the path's obligation and the same transaction closes
    // it against the exact Absent proof, the resolved desired state.
    let obligation = state.sqlite().dag_lookup_projection_obligation(group, "report.txt").unwrap();
    assert!(
        obligation.is_none(),
        "a locally observed deletion that published a usable exact Absent proof must leave \
         no obligation behind: {obligation:?}"
    );

    let basis = state.sqlite().dag_lookup_materialized_generation(group, "report.txt").unwrap();
    let basis = basis.expect(
        "GREEN behavior missing: a locally observed deletion must publish a USABLE exact \
         Absent proof in the same transaction as its tombstone admission",
    );
    assert_eq!(
        basis.object_kind,
        yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind::Absent,
        "a locally observed deletion's proof must describe absence, not a stale present kind"
    );
    assert!(basis.version.is_none(), "an absent object's proof must carry no version hash");
    assert!(
        basis.filesystem_identity.is_none(),
        "an absent object's proof must carry no filesystem identity"
    );

    let desired_hash =
        state.sqlite().native_desired_projected_path_state_hash(group, "report.txt").unwrap();
    assert_eq!(
        basis.resolved_path_state_hash, desired_hash,
        "the published Absent proof's resolved_path_state_hash must match the group's own \
         current desired-state hash for absence -- this exact equality is what \
         dag_zero_work_settlement_if_already_current gates a real zero-work close on"
    );
}

/// Local-origin proof regression: a second local edit's own captured proof must fully
/// supersede the first's, never leave the first's stale
/// `resolved_path_state_hash` sitting around able to authorize
/// zero-work settlement of content it no longer describes. Only
/// covers correctness from the point the second edit is OBSERVED by
/// local capture (an ordinary second `process_event` call) --
/// nothing here claims pre-watcher linearizability against the
/// external write itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_local_capture_supersedes_the_first_captures_stale_proof() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    adopt_root(&state, group, &root);
    let file_path = root.join("report.txt");

    std::fs::write(&file_path, b"version one").unwrap();
    expect_file_changed(
        proc.process_event(
            group,
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap(),
    );
    let basis_v1 = state
        .sqlite()
        .dag_lookup_materialized_generation(group, "report.txt")
        .unwrap()
        .expect("sanity: v1's own capture must publish a usable proof");

    // A second, genuinely different local edit -- observed by local
    // capture exactly like the first, an ordinary second event, not a
    // race this test needs to simulate specially.
    std::fs::write(&file_path, b"version two, a real second edit").unwrap();
    expect_file_changed(
        proc.process_event(
            group,
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap(),
    );
    let basis_v2 = state
        .sqlite()
        .dag_lookup_materialized_generation(group, "report.txt")
        .unwrap()
        .expect("v2's own capture must also publish a usable proof");

    assert_ne!(
        basis_v2.version, basis_v1.version,
        "the second capture's proof must carry v2's own version hash, not v1's"
    );
    assert_ne!(
        basis_v2.resolved_path_state_hash, basis_v1.resolved_path_state_hash,
        "v1's stale resolved_path_state_hash must not still be the row's live value after \
         v2's own capture published its own -- a stale hash surviving here could let a \
         leftover v1 proof wrongly authorize zero-work settlement of v2's obligation"
    );

    // v1's own hash, independently recomputed, must no longer match
    // ANYTHING the live row now describes -- confirms this isn't just
    // "a different row exists somewhere," but that the ONE row
    // `dag_lookup_materialized_generation` returns for this path is
    // unambiguously v2's, not v1's under a still-live guise.
    let v1_hash_recomputed =
        yadorilink_sync_sqlite::materialized_generation::compute_resolved_path_state_hash(
            group,
            "report.txt",
            yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind::RegularFile,
            basis_v1.version.as_ref(),
        );
    assert_ne!(
        basis_v2.resolved_path_state_hash, v1_hash_recomputed,
        "v2's live proof must not happen to match v1's own content hash recomputed fresh -- \
         confirms this test's two versions are genuinely distinct content, not a false \
         positive from picking two edits that happen to hash the same"
    );
}

/// Batch-path counterpart to `local_capture_of_new_content_publishes_a_
/// usable_exact_actual_state_proof`: the SAME GREEN behavior must hold
/// through `commit_local_mutations_batch` (a `Paths` flush with more
/// than one non-symlink file, the shape a real debounced multi-file
/// save/import batches into), not just the single-immediate commit --
/// section 10's own requirement that each successfully-revalidated
/// batched mutation gets its own exact proof inputs, and a path
/// excluded by revalidation gets none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn batched_local_capture_of_new_content_publishes_usable_exact_actual_state_proofs() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    adopt_root(&state, group, &root);
    std::fs::write(root.join("a.txt"), b"aaa content").unwrap();
    std::fs::write(root.join("b.txt"), b"bbb content").unwrap();

    let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![
        (root.join("a.txt"), FsChangeKind::CreatedOrModified, 0),
        (root.join("b.txt"), FsChangeKind::CreatedOrModified, 0),
    ]);
    let outcome = proc.process_flush(group, &root, flush).await.unwrap();
    assert_eq!(outcome.records.len(), 2, "sanity: both files must have been captured");

    for path in ["a.txt", "b.txt"] {
        let basis = state
            .sqlite()
            .dag_lookup_materialized_generation(group, path)
            .unwrap()
            .unwrap_or_else(|| panic!("batched capture of {path} must publish a usable proof"));
        assert_eq!(
            basis.object_kind,
            yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind::RegularFile
        );
        let desired_hash =
            state.sqlite().native_desired_projected_path_state_hash(group, path).unwrap();
        assert_eq!(
            basis.resolved_path_state_hash, desired_hash,
            "{path}'s batched proof must satisfy the same zero-work equality as the \
             single-immediate path"
        );
    }
}

/// Reproduces the restart gap in native state: a file edited
/// while the daemon isn't running is picked up by the startup disk-vs-
/// index reconciliation scan (`scan_existing_files_with_ignore`), which
/// updates the local index through the same delta-emitting path a live
/// `process_event` call uses. Were the scan to update only the local index,
/// nothing later would backfill the missing delta: the on-disk file and the
/// local index would both show the new content, but the native head a peer
/// negotiates against would never move.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offline_edit_after_existing_dag_history_must_append_new_head_on_restart() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    // As `offline_delete_after_existing_dag_history_must_append_delete_
    // change` documents: the later offline edit leaves the index and
    // disk disagreeing on the same path, indistinguishable from an
    // unmounted volume unless the folder's identity was established
    // first, as a real link's would have been.
    adopt_root(&state, group, &root);
    let file_path = root.join("report.txt");

    // A live edit while the daemon is running establishes the group's
    // first native history, exactly as a normal local save does.
    std::fs::write(&file_path, b"version one").unwrap();
    expect_file_changed(
        proc.process_event(
            group,
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap(),
    );
    let heads_before = crate::test_support::native_group_heads(&state, group);
    assert_eq!(heads_before.len(), 1, "sanity: the live edit established one native head");

    // The daemon is "stopped": the file is edited directly on disk, with
    // no processor call observing the edit as it happens.
    std::fs::write(&file_path, b"version two, edited while the daemon was stopped").unwrap();

    // The daemon "restarts": its startup scan reconciles the index
    // against disk (the real path every linked folder's restart runs),
    // then re-runs the idempotent initial import, mirroring
    // `yadorilink-daemon`'s restart sequence exactly.
    let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();
    let scan_records = proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
    assert!(!scan_records.is_empty(), "sanity: the restart scan must notice the offline edit");

    // The local index reflects the offline edit...
    let indexed = state.file_index_repository().get_file(group, "report.txt").unwrap().unwrap();
    assert_eq!(
        indexed.size,
        b"version two, edited while the daemon was stopped".len() as u64,
        "sanity: the local index was reconciled to the offline edit"
    );

    // ...but native state must have advanced past the
    // pre-restart head too, so a peer that only negotiates via native heads
    // (never a legacy full-index sync) can still learn about the
    // offline edit.
    let heads_after = crate::test_support::native_group_heads(&state, group);
    assert_ne!(
        heads_after, heads_before,
        "an offline edit picked up by the restart scan must append a new native delta, not \
         just update the local index"
    );
}

/// Same restart gap as `offline_edit_after_existing_dag_history_must_
/// append_new_head_on_restart`, for an offline deletion: the startup
/// scan tombstones the local index row for a file removed while the
/// daemon wasn't running, but that tombstone never becomes a `Delete`
/// change in the group's native state.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offline_delete_after_existing_dag_history_must_append_delete_change() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    let file_path = root.join("report.txt");
    // Deleting the group's only file leaves an empty root, which is
    // indistinguishable from an unmounted volume unless the folder's
    // identity was established first — as a real link's would have been.
    adopt_root(&state, group, &root);

    std::fs::write(&file_path, b"version one").unwrap();
    expect_file_changed(
        proc.process_event(
            group,
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap(),
    );
    let heads_before = crate::test_support::native_group_heads(&state, group);
    assert_eq!(heads_before.len(), 1, "sanity: one native head after the initial live edit");

    // The daemon is "stopped"; the file is deleted directly on disk.
    std::fs::remove_file(&file_path).unwrap();

    // Restart: scan + re-run the idempotent import, exactly as above.
    let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();
    let scan_records = proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
    assert!(
        scan_records.iter().any(|r| r.path == "report.txt" && r.deleted),
        "sanity: the restart scan must tombstone the offline delete"
    );

    let indexed = state.file_index_repository().get_file(group, "report.txt").unwrap().unwrap();
    assert!(indexed.deleted, "sanity: the local index reflects the offline delete");

    let heads_after = crate::test_support::native_group_heads(&state, group);
    assert_ne!(
        heads_after, heads_before,
        "an offline delete picked up by the restart scan must append a Delete change to \
         native state, not just tombstone the local index row"
    );
}

/// The restart scan now routes an offline edit through the same
/// delta-emitting path a live edit uses, so the change reaches the group's
/// history at scan time rather than updating the index only. Re-running
/// the reconciliation must therefore be idempotent: neither a second scan
/// of the unchanged file nor the dirty-journal redrive
/// (`redrive_dirty_journal`, the daemon's restart backstop) may append a
/// duplicate head or clear the already-emitted change. The native head must
/// stay advanced past the pre-edit head and remain a single head — the
/// redrive must never silently leave the group's history stuck, nor fork
/// or drop the change it just emitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dirty_journal_redrive_must_not_clear_a_change_missing_from_dag() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    // See `offline_edit_after_existing_dag_history_must_append_new_head_
    // on_restart`'s identical adoption for why: the offline edit below
    // leaves the index and disk disagreeing, indistinguishable from an
    // unmounted volume unless the folder's identity was established
    // first.
    adopt_root(&state, group, &root);
    let file_path = root.join("report.txt");

    std::fs::write(&file_path, b"version one").unwrap();
    expect_file_changed(
        proc.process_event(
            group,
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap(),
    );
    let heads_before = crate::test_support::native_group_heads(&state, group);

    // Offline edit picked up by the restart scan, exactly as the
    // append-on-restart test above: the scan now routes the change through
    // the same delta-emitting path a live edit uses, so it appends the
    // change to the group's history at scan time. The re-run initial
    // import is a no-op once real history exists.
    std::fs::write(&file_path, b"version two, edited while the daemon was stopped").unwrap();
    let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();
    proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();

    let heads_after_scan = crate::test_support::native_group_heads(&state, group);
    assert_ne!(
        heads_after_scan, heads_before,
        "the restart scan must append the offline edit to native state at scan time, exactly \
         as the append-on-restart test proves"
    );
    assert_eq!(
        heads_after_scan.len(),
        1,
        "the offline edit must advance to a single new head, not fork the group's history"
    );

    // Re-running the reconciliation must be idempotent. A second scan of
    // the (now unchanged) on-disk file finds nothing to emit, so it must
    // not append a duplicate head for the already-committed change.
    proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
    assert_eq!(
        crate::test_support::native_group_heads(&state, group),
        heads_after_scan,
        "re-running the scan on an already-emitted change must not append a duplicate head"
    );

    // The dirty-journal redrive must likewise neither clear the
    // already-emitted change (reverting the native head to before the edit)
    // nor re-append it as a duplicate — it must leave the emitted change
    // intact.
    proc.redrive_dirty_journal(group, &root).await.unwrap();

    let heads_final = crate::test_support::native_group_heads(&state, group);
    assert_eq!(
        heads_final, heads_after_scan,
        "the dirty-journal redrive must leave the already-emitted change intact — neither \
         clearing it nor appending a duplicate head"
    );
    assert_ne!(
        heads_final, heads_before,
        "the redrive must never silently leave the group's history stuck at the pre-edit head"
    );
}

/// Walks the linear chain of changes from `head` back to (but excluding)
/// `stop`, tip-first. Asserts every step has exactly one parent, i.e. the
/// chain is linear — the shape a chunked reconciliation must produce so a
/// crash can resume from the last committed chunk and native state never forks.
fn linear_chain_back_to(
    state: &ReplicaCoordinator,
    head: yadorilink_replica_domain::ids::DeltaHash,
    stop: &yadorilink_replica_domain::ids::DeltaHash,
) -> Vec<yadorilink_replica_domain::signed_delta::NativeDelta> {
    let by_hash: std::collections::HashMap<[u8; 32], _> =
        crate::test_support::native_deltas(state, GROUP_FOR_CHAINS)
            .into_iter()
            .map(|delta| (delta.delta_hash().0, delta))
            .collect();
    let mut chain = Vec::new();
    let mut cur = head;
    while &cur != stop {
        let delta = by_hash.get(&cur.0).expect("the delta is stored").clone();
        match delta.prev {
            Some(prev) => cur = prev,
            None => {
                chain.push(delta);
                break;
            }
        }
        chain.push(delta);
    }
    chain
}

const GROUP_FOR_CHAINS: &str = "group-1";

// Only called by the #[cfg(unix)] symlink/exec-bit atomicity tests below.
#[cfg(unix)]
fn version_hash_for_path(
    delta: &yadorilink_replica_domain::signed_delta::NativeDelta,
    path: &str,
) -> yadorilink_replica_domain::ids::VersionHash {
    delta
        .ops
        .iter()
        .find(|op| op.path.as_str() == path)
        .and_then(|op| op.put.as_ref())
        .map(|put| put.version)
        .unwrap_or_else(|| panic!("no put op for {path} in delta"))
}

/// A symlink picked up by the delta-emitting startup scan must land its index
/// metadata columns (record kind / target / out-of-root) in the SAME
/// committed state as the `FileVersion` the
/// emitted change carries — no separate post-commit setter that a crash
/// could tear from the emit. The old code applied those columns via
/// `set_record_kind`/`set_symlink_*` AFTER the emit committed, so a crash
/// in between left native state saying "symlink -> target" while the index row
/// still showed the old (or default) columns. This asserts consistency
/// immediately after the single emitting scan call, with no setter run.
#[cfg(unix)]
#[test]
fn scan_emits_symlink_metadata_atomically_with_its_file_version() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();

    // Establish native history so the scan takes the emitting path.
    std::fs::write(root.join("seed.txt"), b"seed").unwrap();
    proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
    let heads_before = crate::test_support::native_group_heads(&state, group);

    // Offline: a new symlink whose raw target escapes the root.
    std::os::unix::fs::symlink("../outside", root.join("link")).unwrap();
    let scanned = proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
    assert!(scanned.iter().any(|r| r.path == "link"), "sanity: the scan noticed the symlink");

    // Index metadata columns are correct right after the single emitting
    // scan call — no post-commit setter was needed.
    assert_eq!(
        state.file_index_repository().get_record_kind(group, "link").unwrap(),
        Some(RecordKind::Symlink)
    );
    assert_eq!(
        state.file_index_repository().get_symlink_target(group, "link").unwrap(),
        Some(b"../outside".to_vec())
    );
    assert!(state.file_index_repository().get_symlink_out_of_root(group, "link").unwrap());
    assert_eq!(state.file_index_repository().get_unix_mode(group, "link").unwrap(), None);

    // ...and the `FileVersion` the emitted delta references agrees
    // exactly (same single committed state, not a later reconciliation).
    let heads_after = crate::test_support::native_group_heads(&state, group);
    assert_ne!(heads_after, heads_before, "the symlink must have emitted a change");
    let chain = linear_chain_back_to(&state, heads_after[0], &heads_before[0]);
    let vh = version_hash_for_path(&chain[chain.len() - 1], "link");
    let version = state.sqlite().dag_get_file_version(group, &vh).unwrap().unwrap();
    assert_eq!(version.meta.record_kind, RecordKind::Symlink);
    assert_eq!(version.meta.symlink_target.as_deref(), Some(b"../outside".as_slice()));
    assert_eq!(version.meta.unix_mode, None);
    // The two views are one and the same commit — the whole point of FIX A.
    assert_eq!(
        state.file_index_repository().get_record_kind(group, "link").unwrap(),
        Some(version.meta.record_kind),
    );
    assert_eq!(
        state.file_index_repository().get_symlink_target(group, "link").unwrap(),
        version.meta.symlink_target
    );
}

/// Exec-bit counterpart of the symlink case above: an executable regular
/// file picked up by the emitting scan must have its `unix_mode` index column set
/// in the same commit as the change's `FileVersion` — not by a separate
/// `set_unix_mode` after the commit.
#[cfg(unix)]
#[test]
fn scan_emits_unix_mode_atomically_with_its_file_version() {
    use std::os::unix::fs::PermissionsExt;

    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();

    std::fs::write(root.join("seed.txt"), b"seed").unwrap();
    proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
    let heads_before = crate::test_support::native_group_heads(&state, group);

    // Offline: a new executable script.
    let script = root.join("run.sh");
    std::fs::write(&script, b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();

    assert_eq!(
        state.file_index_repository().get_unix_mode(group, "run.sh").unwrap(),
        Some(0o755),
        "exec bit set right after the emit"
    );
    assert_eq!(
        state.file_index_repository().get_record_kind(group, "run.sh").unwrap(),
        Some(RecordKind::File)
    );
    assert_eq!(state.file_index_repository().get_symlink_target(group, "run.sh").unwrap(), None);

    let heads_after = crate::test_support::native_group_heads(&state, group);
    let chain = linear_chain_back_to(&state, heads_after[0], &heads_before[0]);
    let vh = version_hash_for_path(&chain[chain.len() - 1], "run.sh");
    let version = state.sqlite().dag_get_file_version(group, &vh).unwrap().unwrap();
    assert_eq!(
        version.meta.unix_mode,
        Some(0o755),
        "the emitted FileVersion carries the exec bit too"
    );
    assert_eq!(
        state.file_index_repository().get_unix_mode(group, "run.sh").unwrap(),
        version.meta.unix_mode
    );
}

/// A metadata-semantics defect worth recording: the
/// startup reconciliation scan used to emit `Vec::new()` for every
/// record it re-authored, regardless of whether that path already
/// carried real xattrs -- so an OFFLINE exec-bit-only change (content
/// untouched) to a file that separately already had a replicated
/// xattr silently wiped that attribute the moment the scan picked up
/// the exec-bit divergence, in both the index and the emitted
/// `FileVersion`. This proves the fix: the xattr must survive an
/// unrelated offline metadata change discovered by the same scan.
#[cfg(target_os = "linux")]
#[test]
fn scan_preserves_existing_xattrs_across_an_unrelated_offline_exec_bit_change() {
    use std::os::unix::fs::PermissionsExt;

    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();

    let script = root.join("run.sh");
    std::fs::write(&script, b"#!/bin/sh\n").unwrap();
    yadorilink_local_storage::apply_xattrs(
        &script,
        &[("user.yadorilink-test".to_string(), b"keep-me".to_vec())],
    )
    .unwrap();
    proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
    assert_eq!(
        state.file_index_repository().get_xattrs(group, "run.sh").unwrap(),
        vec![("user.yadorilink-test".to_string(), b"keep-me".to_vec())],
        "precondition: the xattr is indexed after the first scan"
    );

    // Offline: only the exec bit changes; the xattr is untouched.
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();

    assert_eq!(
        state.file_index_repository().get_unix_mode(group, "run.sh").unwrap(),
        Some(0o755),
        "the offline exec-bit change was picked up"
    );
    assert_eq!(
        state.file_index_repository().get_xattrs(group, "run.sh").unwrap(),
        vec![("user.yadorilink-test".to_string(), b"keep-me".to_vec())],
        "an unrelated offline metadata change must never erase an already-indexed xattr"
    );
}

/// An offline metadata-only change (mode or xattrs, content
/// untouched) still re-versions the path: the `FileVersion` hash
/// covers `unix_mode` and xattrs, so the scan that discovers a bare
/// `chmod` emits a real change carrying a NEW version.
///
/// RED before this fix: the scan's `already_current` metadata-only
/// branch pushed its record straight into the commit without ever
/// observing the path's disk identity, so the emitting commit had no
/// actual-state evidence to write a proof from. The path kept the
/// proof its PREVIOUS commit wrote, which names the PREVIOUS
/// version. Proof and native state then permanently name two different
/// versions for content that was correct on disk the whole time,
/// `dag_zero_work_settlement_if_already_current` can never close the
/// path's projection obligation, and on a device with no peer that
/// obligation never closes by any other route either.
///
/// The oracle is deliberately the version native state itself resolves
/// this path to -- read back out of the change the scan emitted --
/// never the version the proof happens to carry. Checking a proof
/// against itself passes no matter how wrong the proof is.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_offline_metadata_only_change_publishes_a_proof_for_the_version_it_emits() {
    use std::os::unix::fs::PermissionsExt;

    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();
    adopt_root(&state, group, &root);

    // A live capture establishes the group's first history, its index
    // row, and its first actual-state proof -- all correct.
    let script = root.join("run.sh");
    std::fs::write(&script, b"#!/bin/sh\necho hello\n").unwrap();
    expect_file_changed(
        proc.process_event(
            group,
            &root,
            &FsChangeEvent { path: script.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap(),
    );
    let heads_before = crate::test_support::native_group_heads(&state, group);
    assert_eq!(heads_before.len(), 1, "sanity: the live capture established one head");
    let version_before = version_hash_for_path(
        &linear_chain_back_to(
            &state,
            heads_before[0],
            &yadorilink_replica_domain::ids::DeltaHash([0; 32]),
        )[0],
        "run.sh",
    );

    // Offline: the exec bit changes, the bytes do not. Size and mtime
    // are untouched, so the scan's `already_current` content gate
    // holds and this lands in the metadata-only branch.
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();

    let heads_after = crate::test_support::native_group_heads(&state, group);
    assert_ne!(
        heads_after, heads_before,
        "sanity: the scan must have emitted a change for the offline mode change -- without \
         one there is no second version and nothing for this test to catch"
    );
    let chain = linear_chain_back_to(&state, heads_after[0], &heads_before[0]);
    let emitted_version = version_hash_for_path(&chain[chain.len() - 1], "run.sh");
    assert_ne!(
        emitted_version, version_before,
        "sanity: a mode-only change must produce a genuinely different version hash, or \
         there is no disagreement to detect"
    );

    // The proof must describe the version the scan just emitted.
    let basis = state.sqlite().dag_lookup_materialized_generation(group, "run.sh").unwrap().expect(
        "the commit that emitted this path's new version must publish a usable \
             actual-state proof for it -- a present proof naming a superseded version, or \
             none at all, leaves this path unable to settle",
    );
    assert_eq!(
        basis.version,
        Some(emitted_version),
        "the proof must name the version the emitting commit carried, not the version it \
         superseded"
    );

    // The exact equality `dag_zero_work_settlement_if_already_current`
    // gates a zero-work close on, computed against the native-resolved
    // version rather than the proof's own.
    let desired_hash =
        state.sqlite().native_desired_projected_path_state_hash(group, "run.sh").unwrap();
    assert_eq!(
        basis.resolved_path_state_hash, desired_hash,
        "the proof's resolved_path_state_hash must equal the desired-state hash of the \
         version native state resolves this path to; while they differ the path's projection \
         obligation cannot close and, with no peer, never will"
    );
}

/// The first scan of a not-yet-native-backed link must persist each row
/// AND the metadata it just observed for that row in one transaction.
///
/// RED before this fix: the scan wrote every `FileRecord` in one batch
/// transaction and only then stamped `unix_mode`/xattrs/symlink
/// columns, one setter call per path. Between that commit and the last
/// setter there was a durable, observable state -- rows present, most
/// of their metadata absent -- and a restart landing there is not
/// exotic. The rows are what every "has the scan finished" check a
/// caller has looks at, so the daemon reads the index as complete and
/// carries on.
///
/// The damage is not a lost exec bit; the next scan re-observes it.
/// It is that the next scan re-observes it as a CHANGE: on-disk mode
/// against an indexed `NULL` reads exactly like an offline `chmod`,
/// so the scan authors a metadata-only version for content nobody
/// touched, once per path the setter loop never reached. On a
/// 100-file folder that was 96 of them.
///
/// Observed from the streaming scan's own per-chunk commit callback,
/// which fires at the first instant that chunk's rows are durable --
/// what a restart at the worst possible moment would come back to --
/// which is the only point from which "a row never exists without its
/// metadata" can be checked at all without killing a process
/// mid-scan.
///
/// The same scan now also authors the history for what it observed, in
/// that same transaction, rather than writing rows for a separate
/// initial import to convert later. So the closing half of this test
/// asks the stronger question the first version could only approach
/// through the import: after the scan, there is nothing left for the
/// import to bind, and a rescan of an untouched folder authors
/// nothing.
/// What one bulk local-emission transaction actually leaves for the
/// Convergence Engine, counted rather than reasoned about.
///
/// The scan authors the change, publishes an EXACT actual-state proof
/// for each path, and commits all of it in one transaction. If that
/// proof is already sufficient to establish the state the same change
/// asked for, nothing should remain runnable. Three numbers decide it:
/// obligations bumped by the emission, exact proofs adopted alongside
/// it, and obligations still claimable the instant it commits.
#[test]
fn one_bulk_local_emission_leaves_no_runnable_obligations() {
    const GROUP: &str = "group-local-emission-obligations";

    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();

    // Well under RECONCILE_CHUNK_OP_LIMIT, so the whole scan is ONE
    // change in ONE transaction -- the unit the question is about.
    const FILE_COUNT: usize = 12;
    for i in 0..FILE_COUNT {
        std::fs::write(root.join(format!("p{i:02}.txt")), format!("content {i}")).unwrap();
    }

    let records = proc.scan_existing_files_with_ignore(GROUP, &root, &ignore_set).unwrap();
    assert_eq!(records.len(), FILE_COUNT, "sanity: the scan must have authored every path");
    assert_eq!(
        crate::test_support::native_group_heads(&state, GROUP).len(),
        1,
        "sanity: one bulk emission must leave exactly one head"
    );

    let mut bumped = 0usize;
    let mut exact_proofs = 0usize;
    for record in &records {
        if state.sqlite().dag_lookup_projection_obligation(GROUP, &record.path).unwrap().is_some() {
            bumped += 1;
        }
        if state.sqlite().dag_lookup_materialized_generation(GROUP, &record.path).unwrap().is_some()
        {
            exact_proofs += 1;
        }
    }
    // Claimed with the same primitive the engine's own tick uses, at
    // the instant after commit -- this is literally the work the engine
    // wakes up to find.
    let runnable = state
        .sqlite()
        .dag_claim_runnable_obligations(now_unix_nanos(), u32::MAX, u32::MAX)
        .unwrap();
    let runnable_here: Vec<&str> =
        runnable.iter().filter(|o| o.group_id == GROUP).map(|o| o.path.as_str()).collect();

    assert_eq!(
        exact_proofs, FILE_COUNT,
        "the emission must publish an exact actual-state proof for every path it authored; \
         without that this measurement says nothing"
    );
    assert_eq!(
        runnable_here.len(),
        0,
        "one bulk local emission published {exact_proofs} exact proofs for {FILE_COUNT} paths \
         and still left {} obligations runnable ({bumped} bumped). Every one of those is work \
         the Convergence Engine must wake for, claim and re-derive, to conclude what this \
         transaction already proved. Remaining: {runnable_here:?}",
        runnable_here.len()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn a_first_scan_commits_each_row_together_with_the_metadata_it_observed() {
    use std::os::unix::fs::PermissionsExt;

    const ATOMIC_GROUP: &str = "group-first-scan-atomicity";

    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();

    // Enough paths that a per-path setter loop could not plausibly be
    // mistaken for atomic, with metadata that differs per path so a
    // stale or defaulted column cannot accidentally read as correct.
    for i in 0..20 {
        let path = root.join(format!("file{i:02}.sh"));
        std::fs::write(&path, format!("#!/bin/sh\necho {i}\n")).unwrap();
        let mode = if i % 2 == 0 { 0o755 } else { 0o644 };
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    yadorilink_local_storage::apply_xattrs(
        &root.join("file00.sh"),
        &[("user.yadorilink-test".to_string(), b"observed".to_vec())],
    )
    .unwrap();

    // What the index holds at the exact instant this chunk's rows
    // become durable, read from the scan's own per-chunk commit
    // callback.
    type Observed = Vec<(String, Option<u32>, Vec<(String, Vec<u8>)>)>;
    let at_commit: Arc<Mutex<Observed>> = Arc::new(Mutex::new(Vec::new()));
    {
        let at_commit = at_commit.clone();
        let state = state.clone();
        let mut on_chunk_committed = move |_records: &[FileRecord]| {
            let repo = state.file_index_repository();
            let mut seen = Vec::new();
            for i in 0..20 {
                let path = format!("file{i:02}.sh");
                seen.push((
                    path.clone(),
                    repo.get_unix_mode(ATOMIC_GROUP, &path).unwrap(),
                    repo.get_xattrs(ATOMIC_GROUP, &path).unwrap(),
                ));
            }
            *at_commit.lock().unwrap_or_else(|p| p.into_inner()) = seen;
            Ok(())
        };
        proc.scan_existing_files_with_ignore_streaming(
            ATOMIC_GROUP,
            &root,
            &ignore_set,
            &mut on_chunk_committed,
        )
        .expect("the first scan of a fresh link must succeed");
    }

    let observed = at_commit.lock().unwrap_or_else(|p| p.into_inner()).clone();
    assert_eq!(
        observed.len(),
        20,
        "sanity: the per-chunk commit callback must have fired with every path's row \
         already durable"
    );
    for (i, (path, unix_mode, xattrs)) in observed.iter().enumerate() {
        let expected_mode = if i % 2 == 0 { 0o755 } else { 0o644 };
        assert_eq!(
            *unix_mode,
            Some(expected_mode),
            "{path}: the mode this scan observed must already be committed at the instant \
             its row is durable -- a restart here comes back to a row whose mode never \
             landed, and the next scan reads that as an offline chmod and authors a \
             version for content nobody touched"
        );
        let expected_xattrs: Vec<(String, Vec<u8>)> = if i == 0 {
            vec![("user.yadorilink-test".to_string(), b"observed".to_vec())]
        } else {
            Vec::new()
        };
        assert_eq!(
            *xattrs, expected_xattrs,
            "{path}: xattrs must land in the same transaction as the row, for the same \
             reason the mode must"
        );
    }

    // The scan authored its own history: the rows, their metadata, the
    // signed change describing them and its versions all landed in the
    // transactions above, rather than the rows landing now and their
    // history being reconstructed from a second look at the same disk
    // later.
    let heads_after_scan = crate::test_support::native_group_heads(&state, ATOMIC_GROUP);
    assert_eq!(
        heads_after_scan.len(),
        1,
        "the first scan of a fresh link must itself put what it observed into history, \
         converging on one head"
    );

    proc.scan_existing_files_with_ignore(ATOMIC_GROUP, &root, &ignore_set).unwrap();
    assert_eq!(
        crate::test_support::native_group_heads(&state, ATOMIC_GROUP),
        heads_after_scan,
        "a rescan of an untouched folder must author nothing: every mode and xattr the \
         first scan observed is already in the index, so there is no divergence to \
         mistake for an offline metadata change"
    );
}

/// The same atomicity property on the one branch that still writes
/// rows without authoring history: a device with no signing key, and
/// therefore no change emitter, which indexes locally and emits
/// nothing. Its rows must carry the metadata this scan observed from
/// the instant they are durable, for exactly the reason the emitting
/// branch's must -- a restart that comes back to rows with no mode
/// reads the next scan's re-observation as an offline `chmod`.
#[cfg(target_os = "linux")]
#[test]
fn a_scan_with_no_emitter_still_commits_each_row_with_the_metadata_it_observed() {
    use std::os::unix::fs::PermissionsExt;

    const NO_EMITTER_GROUP: &str = "group-first-scan-atomicity-no-emitter";

    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let state = Arc::new(TestReplica::open_in_memory().unwrap());
    let root_dir = tempfile::tempdir().unwrap();
    let root = root_dir.path().canonicalize().unwrap();
    // No `with_change_emitter`: this is the unregistered-device shape.
    let proc = LocalChangeProcessor::new(
        state.clone(),
        store,
        "device-a".into(),
        std::sync::Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
    );
    let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();

    for i in 0..4 {
        let path = root.join(format!("file{i:02}.sh"));
        std::fs::write(&path, format!("#!/bin/sh\necho {i}\n")).unwrap();
        let mode = if i % 2 == 0 { 0o755 } else { 0o644 };
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// `(path, unix_mode)` as each index-only commit recorded it.
    type ModesAtCommit = Vec<(String, Option<u32>)>;
    let at_commit: Arc<Mutex<ModesAtCommit>> = Arc::new(Mutex::new(Vec::new()));
    let _hook_slot = hold_scan_hook_slot();
    {
        let at_commit = at_commit.clone();
        let state = state.clone();
        scan_test_hooks::set_post_index_only_commit_hook(Some(Arc::new(move |gid: &str| {
            if gid != NO_EMITTER_GROUP {
                return;
            }
            let repo = state.file_index_repository();
            let seen = (0..4)
                .map(|i| {
                    let path = format!("file{i:02}.sh");
                    let mode = repo.get_unix_mode(NO_EMITTER_GROUP, &path).unwrap();
                    (path, mode)
                })
                .collect();
            *at_commit.lock().unwrap_or_else(|p| p.into_inner()) = seen;
        })));
    }
    let scanned = proc.scan_existing_files_with_ignore(NO_EMITTER_GROUP, &root, &ignore_set);
    scan_test_hooks::set_post_index_only_commit_hook(None);
    scanned.expect("a scan with no emitter must still succeed");

    assert!(
        crate::test_support::native_group_heads(&state, NO_EMITTER_GROUP).is_empty(),
        "sanity: with no emitter this scan must have taken the index-only branch, which is \
         the one this test is about"
    );
    let observed = at_commit.lock().unwrap_or_else(|p| p.into_inner()).clone();
    assert_eq!(observed.len(), 4, "sanity: the index-only commit seam must have fired");
    for (i, (path, unix_mode)) in observed.iter().enumerate() {
        let expected_mode = if i % 2 == 0 { 0o755 } else { 0o644 };
        assert_eq!(
            *unix_mode,
            Some(expected_mode),
            "{path}: the mode this scan observed must already be committed at the instant \
             its row is durable"
        );
    }
}

/// Op-count cap: a bulk offline diff of more than
/// `RECONCILE_CHUNK_OP_LIMIT` (1024) paths, picked up by one restart scan,
/// must be emitted as MULTIPLE chained changes each within the op-count
/// bound — never one oversized change that no peer could decode
/// (`change::MAX_OPS`) and no wire message could carry.
#[test]
fn two_concurrent_full_reconcile_requests_author_one_change_per_path() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let proc = Arc::new(proc);
    let root = canonical_root(&root_dir);
    const GROUP: &str = "concurrent-reconcile";
    let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();

    const FILE_COUNT: usize = 8;
    for i in 0..FILE_COUNT {
        std::fs::write(root.join(format!("f{i}.txt")), format!("body {i}")).unwrap();
    }

    // Pin the first pass in the exact window the two passes used to
    // share: after it has read `existing_by_path` (still empty) and
    // before it has committed anything. Only the FIRST pass is held --
    // the coalesced rerun must be free to run to completion.
    let _hook_slot = hold_scan_hook_slot();
    let first_snapshotted = Arc::new(Latch::new());
    let release_first = Arc::new(Latch::new());
    {
        let first_snapshotted = first_snapshotted.clone();
        let release_first = release_first.clone();
        let fired = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        scan_test_hooks::set_post_snapshot_hook(Some(Arc::new(move |gid: &str| {
            if gid != GROUP || fired.fetch_add(1, Ordering::SeqCst) != 0 {
                return;
            }
            first_snapshotted.raise();
            release_first.wait();
        })));
    }

    let first = std::thread::spawn({
        let proc = proc.clone();
        let root = root.clone();
        let ignore_set = ignore_set.clone();
        move || proc.scan_existing_files_with_ignore(GROUP, &root, &ignore_set)
    });
    assert!(
        first_snapshotted.wait_timeout(std::time::Duration::from_secs(30)),
        "the first pass never reached its post-snapshot seam"
    );

    // The second full reconcile request, arriving while the first pass
    // is holding a snapshot that is already stale. This is the request
    // that used to walk the same folder against the same empty index
    // and author every path a second time.
    let second = proc.scan_existing_files_with_ignore(GROUP, &root, &ignore_set);
    release_first.raise();
    let first = first.join().expect("the first pass must not panic");
    scan_test_hooks::set_post_snapshot_hook(None);
    first.expect("the first pass must succeed");
    second.expect("the second request must succeed");

    assert_eq!(
        state.file_index_repository().list_files(GROUP).unwrap().len(),
        FILE_COUNT,
        "every file must be indexed"
    );

    // Counted in the history, which is where a duplicate actually
    // costs something: walk the whole authored chain and tally how
    // many signed changes name each path. Two concurrent passes used
    // to give every path two -- byte-identical versions every peer has
    // to fetch, verify and keep forever.
    let heads = crate::test_support::native_group_heads(&state, GROUP);
    assert_eq!(heads.len(), 1, "sanity: the reconciles must converge on one head");
    let mut authorings: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for delta in crate::test_support::native_deltas(&state, GROUP) {
        for op in &delta.ops {
            if op.put.is_some() {
                *authorings.entry(op.path.as_str().to_string()).or_default() += 1;
            }
        }
    }

    let duplicated: Vec<_> =
        authorings.iter().filter(|(_, &n)| n != 1).map(|(p, n)| format!("{p}={n}")).collect();
    assert!(
        duplicated.is_empty(),
        "every path must be authored by exactly one change; these were authored more than \
         once: {duplicated:?}"
    );
    assert_eq!(authorings.len(), FILE_COUNT, "every path must be authored at least once");
}

/// A live index row for an inadmissible path -- which a build predating
/// this rule's local-authoring half could genuinely have written -- must
/// not stop a full reconciliation scan from committing everything else.
///
/// The first fix here skipped such a path in the scan walk BEFORE
/// `seen_paths.insert`, so an existing row for it looked absent from
/// disk to the tombstone pass, which has no inadmissible check of its
/// own. That produced `Op::Delete { path: "CON.txt" }` inside an
/// ordinary chunk, which `validate_no_reserved_paths` then refused --
/// failing the whole chunk and reproducing, by a different route, the
/// exact "one refused path stops its neighbours" defect the fix exists
/// to close. It fires even while the file is still present on disk.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_historical_inadmissible_row_does_not_fail_a_reconciliation_chunk() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    adopt_root(&state, group, &root);
    let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();

    // The row a pre-rule build could have left behind: live, current,
    // and naming a path admission now refuses permanently.
    state
        .file_index_repository()
        .upsert_file(
            group,
            &FileRecord {
                path: "CON.txt".to_string(),
                size: 4,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    std::fs::write(root.join("ordinary.txt"), b"an ordinary file").unwrap();

    proc.scan_existing_files_with_ignore(group, &root, &ignore_set)
        .expect("a historical inadmissible row must not fail the scan");

    assert!(
        state
            .file_index_repository()
            .get_file(group, "ordinary.txt")
            .unwrap()
            .is_some_and(|record| !record.deleted),
        "the ordinary file must still be captured despite a historical inadmissible row \
         sharing its reconciliation chunk"
    );
    assert!(
        state.file_index_repository().get_file(group, "CON.txt").unwrap().is_some(),
        "the row is left untouched rather than tombstoned -- local capture proposes no \
         further op for it, and cleaning up any legacy published history for such a path \
         is a separate migration problem this does not attempt"
    );

    // The same must hold with the file PRESENT on disk. The scan walk
    // skips it before `seen_paths.insert`, so it looks absent to the
    // tombstone pass either way -- this half fails for the same reason
    // even though nothing was ever deleted.
    std::fs::write(root.join("CON.txt"), b"back").unwrap();
    std::fs::write(root.join("second.txt"), b"another ordinary file").unwrap();
    proc.scan_existing_files_with_ignore(group, &root, &ignore_set)
        .expect("an inadmissible file present on disk must not fail the scan either");
    assert!(
        state
            .file_index_repository()
            .get_file(group, "second.txt")
            .unwrap()
            .is_some_and(|record| !record.deleted),
        "a second ordinary file must be captured with the inadmissible file present too"
    );
    assert_eq!(
        std::fs::read(root.join("CON.txt")).unwrap(),
        b"back",
        "the user's own file is never touched by any of this"
    );
}

/// RED->GREEN regression: one locally-created filename that admission
/// refuses permanently must not stop every OTHER file in the same
/// debounce batch from syncing.
///
/// The bug this pins, observed directly on this tree via
/// `windows_path_hazard_conflict`'s three sentinel failures: local
/// capture commits a debounce batch as ONE signed change, so the
/// emission's `validate_no_reserved_paths` refusing a single path failed
/// the whole batch. `flush_pending_batch` then journaled every path in
/// it dirty, and the backstop re-drove the identical failing batch every
/// 5s forever:
///
/// ```text
/// WARN failed to commit a batched group of local mutations; left journaled
///      dirty for re-drive error=path "CON.txt" has a component that is not
///      portable to every platform this group may sync to batch_len=2
/// ```
///
/// `batch_len=2` is the whole defect: the other entry was an ordinary
/// file that merely shared a debounce window. So a POSIX user creating
/// `CON.txt` -- an ordinary, legal filename on their own machine --
/// silently stopped that folder syncing anything at all. Not a
/// Windows-only concern: nothing in the refusal is gated on
/// `cfg!(windows)`, by design, so every platform refuses it.
///
/// To see this go RED, delete the
/// `skip_reason_for_inadmissible_wire_path` guard in
/// `process_event_with_ignore_at`: `ordinary.txt` then never reaches the
/// index, because `CON.txt` shares its batch.
///
/// Asserted on the index rather than on the returned records, because
/// the durable state is what matters -- a peer syncs from the index and
/// native state, not from this call's return value.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_inadmissible_local_name_does_not_block_its_batch_mates() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    adopt_root(&state, group, &root);

    // Both written before either is captured, so they land in ONE
    // debounce flush -- exactly the shape that made a single refused
    // path fatal to its neighbours.
    std::fs::write(root.join("CON.txt"), b"reserved device basename").unwrap();
    std::fs::write(root.join("ordinary.txt"), b"a perfectly ordinary file").unwrap();

    let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![
        (root.join("CON.txt"), FsChangeKind::CreatedOrModified, 0),
        (root.join("ordinary.txt"), FsChangeKind::CreatedOrModified, 0),
    ]);
    proc.process_flush(group, &root, flush)
        .await
        .expect("a batch containing an inadmissible name must not fail the flush itself");

    assert!(
        state
            .file_index_repository()
            .get_file(group, "ordinary.txt")
            .unwrap()
            .is_some_and(|record| !record.deleted),
        "the ordinary file shared a batch with an inadmissible name and must still have \
         been captured -- this is the whole bug: one refused path took its batch mates \
         down with it, forever"
    );

    // And the inadmissible name itself is skipped, never admitted -- the
    // same end state the emission's own refusal was always going to
    // enforce, reached without collateral damage.
    assert!(
        state.file_index_repository().get_file(group, "CON.txt").unwrap().is_none(),
        "a name admission refuses permanently must never enter the local index"
    );
    // The user's file is untouched on disk: not synced is not deleted.
    assert_eq!(
        std::fs::read(root.join("CON.txt")).unwrap(),
        b"reserved device basename",
        "skipping a name for sync must never modify the user's own file"
    );

    // Nothing is left journaled dirty for a backstop to re-drive
    // forever -- the re-drive loop is half of what made the original bug
    // permanent rather than momentary.
    assert!(
        state.dirty_path_repository().list_dirty_paths(group).unwrap().is_empty(),
        "neither path may be left journaled dirty: {:?}",
        state.dirty_path_repository().list_dirty_paths(group).unwrap()
    );
}

#[test]
fn bulk_offline_reconcile_chunks_by_op_count_into_a_chain() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();

    let n = RECONCILE_CHUNK_OP_LIMIT + 3;
    for i in 0..n {
        std::fs::write(root.join(format!("f{i}")), b"a").unwrap();
    }
    // Seed history from the initial index, then take it offline.
    proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
    let heads_before = crate::test_support::native_group_heads(&state, group);
    assert_eq!(heads_before.len(), 1, "sanity: import converged on one head");

    // Offline-modify every file (different size => re-versioned by the scan).
    for i in 0..n {
        std::fs::write(root.join(format!("f{i}")), b"abc").unwrap();
    }
    proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();

    let heads_after = crate::test_support::native_group_heads(&state, group);
    assert_eq!(heads_after.len(), 1, "the chunk chain must converge on a single head");
    let chain = linear_chain_back_to(&state, heads_after[0], &heads_before[0]);
    assert!(
        chain.len() >= 2,
        "{n} changed paths must split into >= 2 chained changes, got {}",
        chain.len()
    );
    let mut total_ops = 0usize;
    for change in &chain {
        assert!(
            change.ops.len() <= RECONCILE_CHUNK_OP_LIMIT,
            "every chunk must stay within the op-count bound"
        );
        let bytes: usize = change.to_wire_bytes().len();
        assert!(bytes <= RECONCILE_CHUNK_BYTE_LIMIT, "every chunk must stay within the byte bound");
        total_ops += change.ops.len();
    }
    assert_eq!(total_ops, n, "the chain's ops must cover every changed path exactly once");
}

/// `process_flush_with_ignore`'s `RescanRequired` arm must not withhold
/// every peer announcement until the WHOLE scan's `Vec<FileRecord>` is
/// returned, since `reconcile_disk_with_ignore`'s own chunk loop
/// (proven by `bulk_offline_reconcile_chunks_by_op_count_into_a_chain`
/// above) already commits each chunk durably to native state as it goes --
/// on a 15,000-file scan that would mean over a minute of zero
/// peer-visible progress while the source device's own index/native state
/// advances the entire time. Proves the streaming sibling
/// surfaces each durably-committed chunk via `on_chunk_committed`
/// DURING the scan (multiple callback invocations, each with a proper
/// subset of the total), not only once at the very end. Confirmed
/// genuinely RED by temporarily removing the `cb(chunk_records)` call
/// in `reconcile_disk_with_ignore`'s chunk loop: `sizes.len()` becomes
/// `0` even though the scan still completes and returns the same
/// records.
#[test]
fn streaming_reconciliation_surfaces_each_durable_chunk_before_the_whole_scan_returns() {
    let (proc, _state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();

    let n = RECONCILE_CHUNK_OP_LIMIT + 3;
    for i in 0..n {
        std::fs::write(root.join(format!("f{i}")), b"a").unwrap();
    }
    proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();

    // Offline-modify every file so the second scan's diff is non-empty
    // and routes through the chunked change-emission path (the same
    // setup `bulk_offline_reconcile_chunks_by_op_count_into_a_chain`
    // uses, just observed through the streaming API instead).
    for i in 0..n {
        std::fs::write(root.join(format!("f{i}")), b"abc").unwrap();
    }

    let observed_chunk_sizes = std::cell::RefCell::new(Vec::<usize>::new());
    let mut on_chunk = |records: &[FileRecord]| {
        observed_chunk_sizes.borrow_mut().push(records.len());
        Ok(())
    };
    let records = proc
        .scan_existing_files_with_ignore_streaming(group, &root, &ignore_set, &mut on_chunk)
        .unwrap();

    let sizes = observed_chunk_sizes.into_inner();
    assert!(
        sizes.len() >= 2,
        "{n} changed paths must stream as >= 2 chunk callbacks, got {}",
        sizes.len()
    );
    assert_eq!(
        sizes.iter().sum::<usize>(),
        n,
        "streamed chunk sizes must cover every changed path exactly once, with no overlap \
         or gap"
    );
    assert_eq!(
        records.len(),
        n,
        "the final aggregate return value must stay byte-identical to the non-streaming path"
    );
}

/// Byte cap: a diff of FEWER than the op-count
/// limit but with long paths that exceed `RECONCILE_CHUNK_BYTE_LIMIT` must
/// still split into multiple chained changes — proving the split is driven
/// by encoded size, not op count alone (op count alone would leave a single
/// multi-hundred-KiB change no wire message could deliver).
#[test]
fn bulk_offline_reconcile_chunks_by_encoded_bytes_into_a_chain() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();

    std::fs::create_dir(root.join("d")).unwrap();
    // ~289 bytes/op * 1000 ops ~= 282 KiB > 256 KiB, yet 1000 < 1024 ops,
    // so only the byte cap can split this.
    let n = 1000usize;
    assert!(n < RECONCILE_CHUNK_OP_LIMIT, "this test must stay under the op-count cap");
    let name = |i: usize| format!("d/{:0>250}", i);
    for i in 0..n {
        std::fs::write(root.join(name(i)), b"a").unwrap();
    }
    proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
    let heads_before = crate::test_support::native_group_heads(&state, group);

    for i in 0..n {
        std::fs::write(root.join(name(i)), b"abc").unwrap();
    }
    proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();

    let heads_after = crate::test_support::native_group_heads(&state, group);
    let chain = linear_chain_back_to(&state, heads_after[0], &heads_before[0]);
    assert!(
        chain.len() >= 2,
        "a >256 KiB diff of {n} (< op-count-cap) paths must split by bytes into >= 2 changes, \
         got {}",
        chain.len()
    );
    let mut total_ops = 0usize;
    for change in &chain {
        let bytes: usize = change.to_wire_bytes().len();
        assert!(
            bytes <= RECONCILE_CHUNK_BYTE_LIMIT,
            "every chunk must stay within the byte bound, got {bytes}"
        );
        assert!(change.ops.len() <= RECONCILE_CHUNK_OP_LIMIT);
        total_ops += change.ops.len();
    }
    assert_eq!(total_ops, n, "the chain's ops must cover every changed path exactly once");
}

/// The startup/offline full-reconcile scan must decide "already current"
/// on the same basis as the per-file path (`build_record_for_created_or_
/// modified`): size *and* mtime, not size alone. An offline edit that
/// preserves the byte length but changes the file's bytes (and its
/// mtime) — a flag flip, a same-length hash/uuid swap, an in-place binary
/// or DB edit — must be detected and re-indexed on restart, not skipped.
/// A size-only gate leaves the index pinned to the stale version while
/// disk holds new bytes: silent divergence that only heals if a peer
/// happens to re-advertise the path, with a silent-data-loss tail if a
/// later remote edit overwrites the un-indexed local edit.
#[test]
fn startup_scan_detects_same_size_edit_with_changed_mtime() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    let file_path = root.join("edge-case.bin");

    std::fs::write(&file_path, vec![b'A'; 20]).unwrap();
    let first_scan = proc.scan_existing_files("group-1", &root).unwrap();
    assert_eq!(first_scan.len(), 1, "sanity: the initial scan indexes the file");
    let indexed_v1 =
        state.file_index_repository().get_file("group-1", "edge-case.bin").unwrap().unwrap();

    // Same length (20 bytes), different bytes, and a distinctly newer
    // mtime — forced explicitly so the test never depends on filesystem
    // timestamp granularity happening to advance between the two writes.
    std::fs::write(&file_path, vec![b'B'; 20]).unwrap();
    let new_mtime = std::time::UNIX_EPOCH
        + std::time::Duration::from_nanos(indexed_v1.mtime_unix_nanos as u64)
        + std::time::Duration::from_secs(2);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&file_path)
        .unwrap()
        .set_modified(new_mtime)
        .unwrap();

    let rescan = proc.scan_existing_files("group-1", &root).unwrap();
    assert!(
        rescan.iter().any(|r| r.path == "edge-case.bin" && !r.deleted),
        "a same-size offline edit whose mtime changed must be detected by the restart scan, \
         not short-circuited as already-current: {rescan:?}"
    );

    let indexed_v2 =
        state.file_index_repository().get_file("group-1", "edge-case.bin").unwrap().unwrap();
    assert_ne!(
        indexed_v2.blocks, indexed_v1.blocks,
        "the re-index must capture the new on-disk content, not keep the stale blocks"
    );
    assert_eq!(
        state.sqlite().dag_list_versions("group-1", "edge-case.bin").unwrap().len(),
        2,
        "the detected offline edit must advance the file's version"
    );
}

/// DI-3 tail closed on the startup/offline full-reconcile path too: an
/// offline edit that preserves BOTH the byte length AND the mtime
/// (`touch -r`, an archive extraction that restores timestamps, an
/// in-place same-length overwrite) must still be detected on restart.
/// The `already_current` stat gate now verifies the on-disk bytes
/// against the indexed block hashes before short-circuiting, so a
/// same-size same-mtime content change is re-indexed rather than left
/// pinned at the stale version — the same content-verified identity
/// test the per-file/watcher path applies.
#[test]
fn startup_scan_detects_same_size_and_mtime_edit() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    let file_path = root.join("edge-case.bin");

    std::fs::write(&file_path, vec![b'A'; 20]).unwrap();
    let first_scan = proc.scan_existing_files("group-1", &root).unwrap();
    assert_eq!(first_scan.len(), 1, "sanity: the initial scan indexes the file");
    let indexed_v1 =
        state.file_index_repository().get_file("group-1", "edge-case.bin").unwrap().unwrap();

    // Same length (20 bytes), different bytes, and mtime forced back to
    // exactly the indexed instant — size AND mtime both match, so only
    // a content comparison can distinguish this from an unchanged file.
    std::fs::write(&file_path, vec![b'B'; 20]).unwrap();
    let original_mtime =
        std::time::UNIX_EPOCH + std::time::Duration::from_nanos(indexed_v1.mtime_unix_nanos as u64);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&file_path)
        .unwrap()
        .set_modified(original_mtime)
        .unwrap();

    let rescan = proc.scan_existing_files("group-1", &root).unwrap();
    assert!(
        rescan.iter().any(|r| r.path == "edge-case.bin" && !r.deleted),
        "a same-size, same-mtime offline edit must be detected by the restart scan, \
         not short-circuited as already-current: {rescan:?}"
    );

    let indexed_v2 =
        state.file_index_repository().get_file("group-1", "edge-case.bin").unwrap().unwrap();
    assert_ne!(
        indexed_v2.blocks, indexed_v1.blocks,
        "the re-index must capture the new on-disk content, not keep the stale blocks"
    );
    assert_eq!(
        state.sqlite().dag_list_versions("group-1", "edge-case.bin").unwrap().len(),
        2,
        "the detected offline edit must advance the file's version"
    );
}

/// Teeth for the content-verifying fast-path: a genuinely unchanged
/// file (same bytes, same size, same mtime) must NOT be re-emitted as a
/// change on a repeat scan. The content check must confirm the no-op,
/// never manufacture spurious churn that would bump the version vector
/// and re-broadcast an identical file on every restart.
#[test]
fn startup_scan_leaves_unchanged_file_untouched() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    let file_path = root.join("steady.bin");
    std::fs::write(&file_path, vec![b'Z'; 4096]).unwrap();

    let first_scan = proc.scan_existing_files("group-1", &root).unwrap();
    assert_eq!(first_scan.len(), 1, "sanity: the initial scan indexes the file");
    let indexed_v1 =
        state.file_index_repository().get_file("group-1", "steady.bin").unwrap().unwrap();

    // No change at all — the file's bytes, size, and mtime are exactly
    // as indexed, so a second scan must treat it as a no-op.
    let rescan = proc.scan_existing_files("group-1", &root).unwrap();
    assert!(
        rescan.iter().all(|r| r.path != "steady.bin"),
        "an unchanged file must not be re-emitted by a repeat scan: {rescan:?}"
    );
    let indexed_v2 =
        state.file_index_repository().get_file("group-1", "steady.bin").unwrap().unwrap();
    assert_eq!(
        state.sqlite().dag_list_versions("group-1", "steady.bin").unwrap().len(),
        1,
        "an unchanged file's version must not advance across scans"
    );
    assert_eq!(indexed_v2.blocks, indexed_v1.blocks, "unchanged blocks stay identical");
}

/// A single un-walkable subtree must not disable offline-delete
/// tombstoning for the *entire* scan. Tombstone suppression is
/// fail-safe (never tombstone a path whose directory we could not read),
/// but that suppression must be scoped to the failed subtree: a
/// confirmed deletion under a cleanly-walked subtree must still be
/// tombstoned even when an unrelated subtree errored, otherwise a
/// persistently-erroring directory defers a real deletion indefinitely
/// and a peer that evicted the file can re-hydrate it.
#[test]
#[cfg(unix)]
fn tombstone_suppression_is_scoped_to_the_failed_subtree() {
    use std::os::unix::fs::PermissionsExt;
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);

    std::fs::create_dir(root.join("clean")).unwrap();
    std::fs::create_dir(root.join("broken")).unwrap();
    std::fs::write(root.join("clean/keep.txt"), b"in the clean subtree").unwrap();
    std::fs::write(root.join("broken/other.txt"), b"in the broken subtree").unwrap();
    proc.scan_existing_files("group-1", &root).unwrap();

    // Offline delete of a file under the CLEAN subtree.
    std::fs::remove_file(root.join("clean/keep.txt")).unwrap();

    // Make the OTHER subtree un-walkable so the scan hits a walk error
    // there — and only there.
    std::fs::set_permissions(root.join("broken"), std::fs::Permissions::from_mode(0o000)).unwrap();

    let records = proc.scan_existing_files("group-1", &root).unwrap();

    // Restore permissions immediately so TempDir cleanup can remove it.
    std::fs::set_permissions(root.join("broken"), std::fs::Permissions::from_mode(0o755)).unwrap();

    assert!(
        records.iter().any(|r| r.path == "clean/keep.txt" && r.deleted),
        "a confirmed deletion under a cleanly-walked subtree must still be tombstoned even \
         when an unrelated subtree failed to walk: {records:?}"
    );
    let clean_indexed =
        state.file_index_repository().get_file("group-1", "clean/keep.txt").unwrap().unwrap();
    assert!(clean_indexed.deleted, "the clean-subtree tombstone must be persisted");

    // Fail-safe: the file under the un-walkable subtree must NOT be
    // tombstoned — its absence could not be confirmed this pass.
    let broken_indexed =
        state.file_index_repository().get_file("group-1", "broken/other.txt").unwrap().unwrap();
    assert!(
        !broken_indexed.deleted,
        "a path under the failed subtree must never be tombstoned — absence unconfirmed"
    );
}

// --- One live link per group: the dominant harm --------------------------

/// THE ANCHOR TEST. The index is group-scoped and path-relative while this
/// scan is root-scoped and authoritative, so with two live roots on one
/// group, root A's scan finds root B's indexed paths absent from its own
/// `seen_paths` and tombstones them -- signed changes that ride the
/// native state to EVERY device. That is silent, group-wide, cross-device loss
/// of the user's own data.
///
/// Asserts on the emitted RECORDS, not merely that the call is `Err`: an
/// `Err` returned AFTER the tombstones were pushed is still group-wide loss.
/// The scan must not reach the tombstone loop at all.
///
/// BOTH ROOTS ARE MARKED WITH THE SAME TOKEN, AND THAT IS THE POINT. An
/// earlier version of this test left root B unmarked, which made it a FALSE
/// ANCHOR: an unmarked B sends `VerifiedRoot::open` down the adoption path,
/// whose token write trips `set_link_root_token_for_group`'s fan-out assert
/// -- so the refusal came from the WRITER, and disabling the entire
/// read-side gate left this test PASSING. It named the gate and tested
/// something else. (Measured: with `ensure_unambiguous_group_on_conn`'s
/// `paths.len() > 1` forced to `false`, `1 passed; 0 failed`.)
///
/// Two rows carrying ONE token is also the realistic already-duplicated
/// state rather than a contrivance: it is exactly what the pre-fix
/// by-`group_id` token writer manufactured, stamping both rows on any
/// database that already had two links. In it, `open` finds a marker whose
/// token matches what is persisted and returns `Ok` WITHOUT WRITING -- so no
/// writer assert can fire, and the read-side gate is the only thing standing
/// between the user and the tombstones. Measured with the gate disabled:
/// `SCAN SUCCEEDED, tombstoned = ["only-in-a.txt"]`.
#[test]
fn a_full_scan_of_an_ambiguous_group_emits_zero_tombstones() {
    let (processor, state, _store_dir, root_a) = processor();
    let root_b = tempfile::tempdir().unwrap();
    let group = "group-1";

    state.link_repository().add_link(&root_a.path().to_string_lossy(), group).unwrap();

    // Two files live under root A and are indexed for the group.
    std::fs::write(root_a.path().join("shared.txt"), b"hello").unwrap();
    std::fs::write(root_a.path().join("only-in-a.txt"), b"world").unwrap();
    let scanned = processor.scan_existing_files(group, root_a.path()).unwrap();
    assert_eq!(scanned.len(), 2, "the healthy scan must index both files");
    assert!(scanned.iter().all(|r| !r.deleted));

    // Root B holds ONE of the group's files -- the realistic shape, since a
    // second root gets populated by hydration from a peer or by the user
    // copying some of the folder in.
    std::fs::write(root_b.path().join("shared.txt"), b"hello").unwrap();

    // Both roots marked with the group's ONE persisted token: the
    // already-duplicated database. Every identity check now PASSES for
    // either root -- which is precisely why sharing a token is the damage
    // and not the safety. Nothing after this writes a token, so the writer's
    // fan-out assert is out of the picture and only the gate is left.
    //
    // Read while the group is still healthy: once it is ambiguous this
    // resolver refuses, exactly as it should.
    let token = state
        .link_repository()
        .link_root_token_for_group(group)
        .unwrap()
        .expect("root A's scan above must have adopted it");
    yadorilink_root_authority::root_identity::write_root_marker_for_test(
        root_b.path(),
        group,
        &token,
    );

    // Now the user is in the two-live-roots state -- reachable today, and
    // the state this fix must make safe rather than merely prevent.
    state
        .link_repository()
        .force_second_live_link_for_test(&root_b.path().to_string_lossy(), group)
        .unwrap();

    // B's ROW carries the same token too. Without this, B's row token is
    // NULL and the token resolver -- a first-row-wins `ORDER BY local_path`
    // -- returns `None` whenever B happens to sort first, sending `open`
    // down its backfill WRITE and back into the writer's fan-out assert.
    // That would make this test's verdict depend on tempdir naming: the gate
    // on one run, the writer on the next. Both rows, one token, is also the
    // honest shape of the state the pre-fix writer produced.
    state
        .link_repository()
        .set_link_root_token_for_path_for_test(&root_b.path().to_string_lossy(), &token)
        .unwrap();

    // Scan root B, NOT root A. This direction is the whole bug: B's scan is
    // root-scoped and authoritative, but the index it reconciles against is
    // group-scoped, so A's `only-in-a.txt` is "indexed for this group but
    // absent from the root I just walked" -> tombstone -> signed change ->
    // every device. Scanning A instead would be vacuous: A's own file is
    // present under A, so that scan emits no tombstone whether or not the
    // fix exists.
    let result = processor.scan_existing_files(group, root_b.path());

    let err = match result {
        Err(e) => e,
        Ok(records) => {
            let tombstoned: Vec<_> =
                records.iter().filter(|r| r.deleted).map(|r| r.path.clone()).collect();
            panic!(
                "a scan of an ambiguous group must refuse, not pick a root. SCAN SUCCEEDED, \
                 tombstoned = {tombstoned:?} -- each of those is a signed deletion bound for \
                 every device"
            );
        }
    };
    assert!(
        matches!(err, LocalCaptureError::SyncCore(SyncSqliteError::AmbiguousLink { .. })),
        "got {err:?}"
    );

    // And the index is untouched: nothing was tombstoned on the way out.
    let indexed = state.file_index_repository().list_files(group).unwrap();
    assert!(
        indexed.iter().all(|r| !r.deleted),
        "no indexed file may be tombstoned by a scan of an ambiguous group, got {indexed:?}"
    );
}

/// The original anchor's state, kept as its own case now that the anchor
/// above has moved to the token-sharing one: an UNMARKED second root, where
/// the refusal comes from the token writer's fan-out assert on the adoption
/// path rather than from the read-side gate. Defence in depth, and labelled
/// as such -- it is not evidence about the gate.
#[test]
fn a_full_scan_of_an_ambiguous_group_with_an_unadopted_second_root_emits_zero_tombstones() {
    let (processor, state, _store_dir, root_a) = processor();
    let root_b = tempfile::tempdir().unwrap();
    let group = "group-1";

    state.link_repository().add_link(&root_a.path().to_string_lossy(), group).unwrap();
    std::fs::write(root_a.path().join("shared.txt"), b"hello").unwrap();
    std::fs::write(root_a.path().join("only-in-a.txt"), b"world").unwrap();
    processor.scan_existing_files(group, root_a.path()).unwrap();

    // One of the group's files is present under B, so B is "corroborated"
    // and the marker check would ADOPT it: `IndexedFilesAllMissing` only
    // fires when NOT ONE indexed file is present.
    std::fs::write(root_b.path().join("shared.txt"), b"hello").unwrap();
    state
        .link_repository()
        .force_second_live_link_for_test(&root_b.path().to_string_lossy(), group)
        .unwrap();

    let err = processor
        .scan_existing_files(group, root_b.path())
        .expect_err("a scan of an ambiguous group must refuse, not pick a root");
    assert!(
        matches!(err, LocalCaptureError::SyncCore(SyncSqliteError::AmbiguousLink { .. })),
        "got {err:?}"
    );

    let indexed = state.file_index_repository().list_files(group).unwrap();
    assert!(
        indexed.iter().all(|r| !r.deleted),
        "no indexed file may be tombstoned by a scan of an ambiguous group, got {indexed:?}"
    );
}

/// The fix's own remedy must not destroy data. `DELETE FROM files` is only
/// ever keyed by path, so unlinking B leaves B's rows in the GROUP's index;
/// A's next scan is root-scoped and authoritative and would read every one
/// of them as deleted and tombstone them to every device. Obeying the error
/// message ("unlink the other one") would then delete the files the message
/// told the user to save.
///
/// Measured before this flag existed: the survivor's scan emitted
/// `["only-in-b.txt"]`.
#[test]
fn the_survivors_first_post_recovery_scan_emits_no_tombstones() {
    let (processor, state, _store_dir, root_a) = processor();
    let root_b = tempfile::tempdir().unwrap();
    let group = "group-1";

    state.link_repository().add_link(&root_a.path().to_string_lossy(), group).unwrap();
    std::fs::write(root_a.path().join("in-a.txt"), b"aaa").unwrap();
    processor.scan_existing_files(group, root_a.path()).unwrap();

    // A path that only ever existed under B, indexed for the group -- the
    // shape a second root produces by hydrating from a peer.
    state
        .link_repository()
        .force_second_live_link_for_test(&root_b.path().to_string_lossy(), group)
        .unwrap();
    state
        .file_index_repository()
        .upsert_file(
            group,
            &FileRecord {
                path: "only-in-b.txt".into(),
                size: 3,
                mtime_unix_nanos: 1,
                blocks: vec![],
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    // Recovery, exactly as `SyncSqliteError::AmbiguousLink` instructs, plus the
    // additive-scan flag the daemon's unlink handler arms on the survivor.
    state.link_repository().remove_link(&root_b.path().to_string_lossy()).unwrap();
    state
        .link_repository()
        .set_suppress_tombstones(&root_a.path().to_string_lossy(), true)
        .unwrap();

    let ignore_set = EffectiveIgnoreSet::load_for_link_root(root_a.path()).unwrap();
    let emit_tombstones = !state.link_repository().suppress_tombstones_for_group(group).unwrap();
    let out = processor
        .scan_existing_files_with_ignore_gated(group, root_a.path(), &ignore_set, emit_tombstones)
        .unwrap();

    let tombstoned: Vec<_> = out.iter().filter(|r| r.deleted).map(|r| r.path.clone()).collect();
    assert!(
        tombstoned.is_empty(),
        "the survivor's first scan after recovery must delete nothing -- these paths can \
         still hydrate from a peer that holds them, got {tombstoned:?}"
    );
    let still_live =
        state.file_index_repository().get_file(group, "only-in-b.txt").unwrap().unwrap();
    assert!(!still_live.deleted, "the departed root's file must not be tombstoned");
}

/// A canonical wire path must have one separator spelling on every
/// platform. A literal Unix backslash therefore cannot be represented:
/// preserving it would make `a\b.txt` and `a/b.txt` distinct native paths
/// that address the same file when received on Windows.
#[cfg(unix)]
#[test]
fn wire_relative_string_refuses_a_literal_backslash_on_unix() {
    let root = tempfile::tempdir().unwrap();
    let literal_backslash_path = root.path().join("a\\b.txt");
    assert_eq!(
        path_to_wire_relative_string(literal_backslash_path.strip_prefix(root.path()).unwrap()),
        None,
    );

    let nested_path = root.path().join("a").join("b.txt");
    assert_eq!(
        path_to_wire_relative_string(nested_path.strip_prefix(root.path()).unwrap()).as_deref(),
        Some("a/b.txt"),
    );
}

/// The second collision hazard:
/// `to_string_lossy()` silently substitutes `�` for invalid UTF-8,
/// which can fold two DIFFERENT non-UTF-8 names onto the identical
/// wire path string. `path_to_wire_relative_string` must refuse
/// (`None`) rather than silently substitute.
#[cfg(unix)]
#[test]
fn wire_relative_string_refuses_non_utf8_names_instead_of_silently_substituting() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    // Two DIFFERENT invalid-UTF-8 byte sequences that `to_string_
    // lossy()` would both render as the single-character placeholder
    // "�", making them indistinguishable as wire path strings.
    let name_a = OsStr::from_bytes(b"caf\xE9.txt"); // Latin-1 "café.txt"
    let name_b = OsStr::from_bytes(b"caf\xE8.txt"); // Latin-1 "cafè.txt" (different byte)

    assert_eq!(
        path_to_wire_relative_string(Path::new(name_a)),
        None,
        "a non-UTF-8 name must be refused, not silently substituted"
    );
    assert_eq!(path_to_wire_relative_string(Path::new(name_b)), None);
}

/// Integration-level proof through the actual scan path: a real
/// on-disk file whose name is not valid UTF-8 must be skipped by
/// `scan_existing_files`, not silently indexed under a lossy,
/// potentially-colliding substitute name.
#[cfg(unix)]
#[test]
fn scan_existing_files_skips_a_non_utf8_named_file_rather_than_indexing_it_lossily() {
    use std::os::unix::ffi::OsStrExt;

    let (proc, _state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    let non_utf8_name = std::ffi::OsStr::from_bytes(b"caf\xE9.txt");
    // Some filesystems (notably macOS's APFS) enforce valid UTF-8 at
    // the filesystem level and refuse to create a non-UTF-8-named
    // entry outright -- skip on a host where that's the case, rather
    // than asserting a scenario this filesystem cannot even produce.
    // The pure `wire_relative_string_refuses_non_utf8_names_instead_
    // of_silently_substituting` test above still exercises the actual
    // fix on every platform regardless.
    if std::fs::write(root.join(non_utf8_name), b"content").is_err() {
        eprintln!("skipping: this filesystem refuses to create a non-UTF-8-named file");
        return;
    }
    std::fs::write(root.join("ordinary.txt"), b"ordinary content").unwrap();

    let records = proc.scan_existing_files("group-1", &root).unwrap();
    let paths: Vec<&str> = records.iter().map(|r| r.path.as_str()).collect();

    assert_eq!(
        paths,
        vec!["ordinary.txt"],
        "the non-UTF-8-named file must be skipped, never indexed under a lossily \
         substituted (and potentially colliding) name"
    );
}

/// The capture classifies a path with `lstat` and then opens it to read
/// its bytes. If the regular file is swapped for a symlink in between,
/// the open must not follow it: the bytes of whatever the link points at
/// (a file outside the sync root) would be captured as this path's
/// content and replicated to every peer.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_symlink_swapped_in_after_lstat_is_not_followed_by_the_capture() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    adopt_root(&state, group, &root);
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("id_ed25519");
    std::fs::write(&secret, b"PRIVATE KEY MATERIAL OUTSIDE THE ROOT").unwrap();
    let path = root.join("notes.txt");
    std::fs::write(&path, b"ordinary notes").unwrap();

    let swap = path.clone();
    arm_race_after_lstat_hook(path.clone(), move || {
        std::fs::remove_file(&swap).unwrap();
        std::os::unix::fs::symlink(&secret, &swap).unwrap();
        false
    });
    let event = FsChangeEvent { path: path.clone(), kind: FsChangeKind::CreatedOrModified };
    let outcome = proc.process_event(group, &root, &event).await.unwrap();

    if let Some(row) = state.file_index_repository().get_file(group, "notes.txt").unwrap() {
        assert_ne!(
            row.size, 37,
            "the capture followed a swapped-in symlink and indexed an out-of-root file's bytes"
        );
    }
    assert!(
        matches!(outcome, LocalChangeOutcome::RetryLater),
        "a path swapped under the capture must be left for a later pass"
    );
}

#[path = "directory_capture_tests.rs"]
mod directory_capture;

#[path = "recursive_capture_tests.rs"]
mod recursive_capture;

/// A file whose block list cannot travel in one replication item can never be
/// synced: peers would admit its head and never receive its version. Capture
/// refuses it explicitly, writes nothing, and leaves the path unsettled so a
/// later pass (after the file shrinks) can pick it up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_with_too_many_blocks_to_sync_is_refused_and_nothing_is_written() {
    struct RestoreLimit;
    impl Drop for RestoreLimit {
        fn drop(&mut self) {
            record_builder::override_syncable_block_limit(usize::MAX);
        }
    }
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let file_path = root.join("huge.bin");
    // 4 blocks at the default 128 KiB block size.
    std::fs::write(&file_path, vec![b'x'; 4 * 128 * 1024]).unwrap();

    let _restore = RestoreLimit;
    record_builder::override_syncable_block_limit(3);
    let event = FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified };
    let outcome = proc.process_event("group-1", &root, &event).await.unwrap();

    assert_eq!(outcome, LocalChangeOutcome::RetryLater);
    assert!(state.get_file("group-1", "huge.bin").unwrap().is_none(), "no index row");
    assert!(
        state.sqlite().dag_list_versions("group-1", "huge.bin").unwrap().is_empty(),
        "no version was authored"
    );

    // Within the limit the very same file is captured: the refusal is the limit's doing.
    record_builder::override_syncable_block_limit(4);
    let outcome = proc.process_event("group-1", &root, &event).await.unwrap();
    expect_file_changed(outcome);
}

/// A scan reads a path without its lock and commits later, so a path
/// another writer holds at commit time -- above all a write of a newer
/// version, whose row is already ahead of disk -- is not authored from
/// what the scan read: it is captured again under the lock once the
/// writer lets it go. A path whose disk moved on since the read is
/// captured again too, instead of authoring the bytes that are gone.
mod scan_commit_lock {
    use super::*;
    use tokio::sync::OwnedMutexGuard;

    const GROUP: &str = "scan-commit-lock";

    type Held = Arc<Mutex<Vec<OwnedMutexGuard<()>>>>;

    struct Fixture {
        proc: LocalChangeProcessor,
        state: Arc<TestReplica>,
        root: std::path::PathBuf,
        _store_dir: tempfile::TempDir,
        _root_dir: tempfile::TempDir,
    }

    fn fixture() -> Fixture {
        let (proc, state, _emitter, _store_dir, _root_dir) = processor_with_emitter();
        let root = canonical_root(&_root_dir);
        adopt_root(&state, GROUP, &root);
        Fixture { proc, state, root, _store_dir, _root_dir }
    }

    impl Fixture {
        async fn capture(&self, rel: &str) {
            self.proc
                .process_event(
                    GROUP,
                    &self.root,
                    &FsChangeEvent {
                        path: self.root.join(rel),
                        kind: FsChangeKind::CreatedOrModified,
                    },
                )
                .await
                .unwrap();
        }

        fn scan(&self) -> Vec<String> {
            let records = tokio::task::block_in_place(|| {
                self.proc.scan_existing_files(GROUP, &self.root).unwrap()
            });
            records.into_iter().map(|record| record.path).collect()
        }

        fn versions(&self, rel: &str) -> usize {
            self.state.sqlite().dag_list_versions(GROUP, rel).unwrap().len()
        }

        fn dirty(&self, rel: &str) -> bool {
            self.state.dirty_path_repository().is_path_dirty(GROUP, rel).unwrap()
        }

        fn indexed_size(&self, rel: &str) -> u64 {
            self.state.file_index_repository().get_file(GROUP, rel).unwrap().unwrap().size
        }

        async fn until_dirty(&self, rel: &str) {
            for _ in 0..500 {
                if self.dirty(rel) {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            panic!("{rel} was never journaled for another capture");
        }

        async fn redrive(&self) {
            self.proc.redrive_dirty_journal(GROUP, &self.root).await.unwrap();
        }

        /// While the scan runs, holds the lock of every path in `busy`
        /// from the moment the scan is about to commit it.
        fn hold_while_committing(&self, busy: &'static [&'static str]) -> Held {
            let held: Held = Arc::default();
            let (state, slot) = (Arc::clone(&self.state), Arc::clone(&held));
            scan_test_hooks::set_pre_upsert_commit_recheck_hook(Some(Arc::new(
                move |group: &str, path: &str| {
                    if group == GROUP && busy.contains(&path) {
                        let guard = state.path_lock(GROUP, path).try_lock_owned().unwrap();
                        slot.lock().unwrap().push(guard);
                    }
                },
            )));
            held
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(
        clippy::await_holding_lock,
        reason = "the scan-hook slot guard serializes the tests sharing the process-wide \
                  scan hook; holding it across awaits is the point"
    )]
    async fn a_path_written_while_the_scan_commits_is_captured_once_the_writer_releases_it() {
        let _hook_slot = hold_scan_hook_slot();
        let f = fixture();
        std::fs::write(f.root.join("a.txt"), b"one").unwrap();
        f.capture("a.txt").await;
        assert_eq!(f.versions("a.txt"), 1);
        std::fs::write(f.root.join("a.txt"), b"edited offline").unwrap();

        let held = f.hold_while_committing(&["a.txt"]);
        let scanned = f.scan();
        scan_test_hooks::set_pre_upsert_commit_recheck_hook(None);

        assert!(!scanned.contains(&"a.txt".to_string()), "authored under a held lock: {scanned:?}");
        assert_eq!(f.versions("a.txt"), 1, "nothing authored while another writer holds it");
        assert!(!f.dirty("a.txt"), "not journaled while the writer still holds the path");

        held.lock().unwrap().clear();
        f.until_dirty("a.txt").await;
        f.redrive().await;

        assert!(!f.dirty("a.txt"));
        assert_eq!(f.versions("a.txt"), 2, "the edit is captured exactly once");
        assert_eq!(f.indexed_size("a.txt"), b"edited offline".len() as u64);
        assert!(f.scan().is_empty(), "a later scan finds nothing left to author");
        assert_eq!(f.versions("a.txt"), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(
        clippy::await_holding_lock,
        reason = "the scan-hook slot guard serializes the tests sharing the process-wide \
                  scan hook; holding it across awaits is the point"
    )]
    async fn a_file_changed_between_the_scan_read_and_its_commit_is_captured_again() {
        let _hook_slot = hold_scan_hook_slot();
        let f = fixture();
        std::fs::write(f.root.join("a.txt"), b"one").unwrap();
        f.capture("a.txt").await;
        std::fs::write(f.root.join("a.txt"), b"read by the scan").unwrap();

        let root = f.root.clone();
        scan_test_hooks::set_pre_upsert_commit_recheck_hook(Some(Arc::new(
            move |group: &str, path: &str| {
                if group == GROUP && path == "a.txt" {
                    std::fs::write(root.join("a.txt"), b"saved again before the commit").unwrap();
                }
            },
        )));
        let scanned = f.scan();
        scan_test_hooks::set_pre_upsert_commit_recheck_hook(None);

        assert!(!scanned.contains(&"a.txt".to_string()), "authored stale bytes: {scanned:?}");
        assert_eq!(f.versions("a.txt"), 1);
        assert!(f.dirty("a.txt"), "journaled for another capture");

        f.redrive().await;

        assert!(!f.dirty("a.txt"));
        assert_eq!(f.versions("a.txt"), 2, "only what is on disk is authored, once");
        assert_eq!(f.indexed_size("a.txt"), b"saved again before the commit".len() as u64);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(
        clippy::await_holding_lock,
        reason = "the scan-hook slot guard serializes the tests sharing the process-wide \
                  scan hook; holding it across awaits is the point"
    )]
    async fn a_scan_commits_the_paths_it_can_lock_and_captures_the_others_later() {
        let _hook_slot = hold_scan_hook_slot();
        let f = fixture();
        let names = ["a.txt", "b.txt", "c.txt", "d.txt"];
        for name in names {
            std::fs::write(f.root.join(name), name.as_bytes()).unwrap();
        }

        let held = f.hold_while_committing(&["b.txt", "d.txt"]);
        let mut scanned = f.scan();
        scan_test_hooks::set_pre_upsert_commit_recheck_hook(None);
        scanned.sort();

        assert_eq!(scanned, ["a.txt", "c.txt"], "only the paths it could lock are authored");
        assert_eq!((f.versions("b.txt"), f.versions("d.txt")), (0, 0));

        held.lock().unwrap().clear();
        f.until_dirty("b.txt").await;
        f.until_dirty("d.txt").await;
        f.redrive().await;

        for name in names {
            assert_eq!(f.versions(name), 1, "{name} is authored exactly once");
            assert!(!f.dirty(name));
        }
        assert!(f.scan().is_empty());
    }

    /// The lock registry folds names, so an offline case-only rename puts
    /// the new name's upsert and the old name's delete under one lock in
    /// one commit. The commit holds it once for both, and both land.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(
        clippy::await_holding_lock,
        reason = "the scan-hook slot guard serializes the tests sharing the process-wide \
                  scan hook; holding it across awaits is the point"
    )]
    async fn an_offline_case_only_rename_commits_its_write_and_its_delete_together() {
        let _hook_slot = hold_scan_hook_slot();
        let f = fixture();
        std::fs::write(f.root.join("Report.txt"), b"quarterly").unwrap();
        f.capture("Report.txt").await;
        std::fs::rename(f.root.join("Report.txt"), f.root.join("report.txt")).unwrap();

        let mut scanned = f.scan();
        scanned.sort();

        assert_eq!(scanned, ["Report.txt", "report.txt"], "the write and the delete commit");
        let row = |rel: &str| f.state.file_index_repository().get_file(GROUP, rel).unwrap();
        assert!(row("Report.txt").is_some_and(|row| row.deleted), "the old name is deleted");
        assert!(row("report.txt").is_some_and(|row| !row.deleted), "the new name is live");
        assert!(!f.dirty("Report.txt") && !f.dirty("report.txt"));
    }

    /// However many scans find a path's lock busy, one waiter is queued to
    /// journal it, and it journals it once when the lock frees.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(
        clippy::await_holding_lock,
        reason = "the scan-hook slot guard serializes the tests sharing the process-wide \
                  scan hook; holding it across awaits is the point"
    )]
    async fn repeated_scans_of_a_busy_path_queue_one_journal_write() {
        let _hook_slot = hold_scan_hook_slot();
        let f = fixture();
        std::fs::write(f.root.join("a.txt"), b"one").unwrap();
        f.capture("a.txt").await;
        std::fs::write(f.root.join("a.txt"), b"edited offline").unwrap();

        let writer = f.state.path_lock(GROUP, "a.txt").try_lock_owned().unwrap();
        for _ in 0..3 {
            assert!(f.scan().is_empty());
            assert_eq!(f.proc.deferred_journal_waiter_count(), 1);
        }
        drop(writer);
        f.until_dirty("a.txt").await;
        for _ in 0..500 {
            if f.proc.deferred_journal_waiter_count() == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(f.proc.deferred_journal_waiter_count(), 0, "the waiter unregisters");
        let journaled = f.state.dirty_path_repository().list_dirty_paths(GROUP).unwrap();
        assert_eq!(journaled.len(), 1);
        assert_eq!(journaled[0].attempts, 1, "journaled once, not once per scan");
    }
}

/// A nested mount (simulated via the device-boundary test seam) is never
/// indexed: the walk neither descends into it nor captures the mountpoint.
#[test]
fn the_scan_walk_does_not_descend_across_a_device_boundary() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    std::fs::create_dir_all(root.join("media")).unwrap();
    std::fs::write(root.join("media/mounted.txt"), b"on another device").unwrap();
    std::fs::write(root.join("local.txt"), b"ours").unwrap();
    yadorilink_filesystem_sync::device_boundary::seam::mark_foreign(&root.join("media"));

    let records = proc.scan_existing_files("group-1", &root).unwrap();

    assert!(records.iter().any(|r| r.path == "local.txt"), "control: {records:?}");
    assert!(
        !records.iter().any(|r| r.path == "media" || r.path.starts_with("media/")),
        "nothing across the device boundary may be indexed: {records:?}"
    );
}

/// Rows indexed beneath a directory that is now on another device are not
/// delete evidence (the walk no longer sees them), so the scan must not
/// tombstone them. The control proves the same missing row IS tombstoned
/// on the root's own device.
#[test]
fn rows_under_a_device_boundary_are_not_tombstoned() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    std::fs::create_dir_all(root.join("media")).unwrap();
    std::fs::create_dir_all(root.join("plain")).unwrap();
    index_hydrated_missing_file(&state, "group-1", "media/old.txt");
    index_hydrated_missing_file(&state, "group-1", "plain/old.txt");
    yadorilink_filesystem_sync::device_boundary::seam::mark_foreign(&root.join("media"));

    let records = proc.scan_existing_files("group-1", &root).unwrap();

    assert!(
        records.iter().any(|r| r.path == "plain/old.txt" && r.deleted),
        "control: a missing row on the root's device is still a real deletion: {records:?}"
    );
    assert!(
        !records.iter().any(|r| r.path == "media/old.txt"),
        "a row under a device boundary must not be tombstoned: {records:?}"
    );
    let row = state.file_index_repository().get_file("group-1", "media/old.txt").unwrap().unwrap();
    assert!(!row.deleted);
}

/// Live events beneath a device boundary author nothing either.
#[tokio::test]
async fn live_events_under_a_device_boundary_are_ignored() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    std::fs::create_dir_all(root.join("mnt")).unwrap();
    std::fs::write(root.join("mnt/f.txt"), b"x").unwrap();
    yadorilink_filesystem_sync::device_boundary::seam::mark_foreign(&root.join("mnt"));

    proc.process_event(
        "group-1",
        &root,
        &FsChangeEvent { path: root.join("mnt/f.txt"), kind: FsChangeKind::CreatedOrModified },
    )
    .await
    .unwrap();

    assert!(state.file_index_repository().get_file("group-1", "mnt/f.txt").unwrap().is_none());
}

/// Rows an older build indexed under a path that has since been unmounted
/// (an empty mountpoint on the root's device) cannot be told from a real
/// deletion. A link with no recorded volume identity adopts the current one
/// in its first safe full scan and authors no deletes in that scan; the next
/// scan deletes normally.
#[test]
fn legacy_rows_adopt_the_volume_identity_without_deleting_anything() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root_without_volume_identity(&state, "group-1", &root);
    std::fs::create_dir_all(root.join("media")).unwrap();
    std::fs::create_dir_all(root.join("plain")).unwrap();
    // Indexed while `media` was a mount; now unmounted, so it is empty.
    index_hydrated_missing_file(&state, "group-1", "media/old.txt");
    index_hydrated_missing_file(&state, "group-1", "plain/old.txt");
    assert_eq!(
        state.link_repository().capture_volume_identity_for_group("group-1").unwrap(),
        Some(None)
    );

    let records = proc.scan_existing_files("group-1", &root).unwrap();

    assert!(!records.iter().any(|r| r.deleted), "the adopting scan deletes nothing: {records:?}");
    let adopted = state.link_repository().capture_volume_identity_for_group("group-1").unwrap();
    assert_eq!(
        adopted,
        Some(yadorilink_filesystem_sync::device_boundary::root_volume_identity(&root).ok())
    );
    for path in ["media/old.txt", "plain/old.txt"] {
        assert!(!state.file_index_repository().get_file("group-1", path).unwrap().unwrap().deleted);
    }

    // Control: with the identity recorded, a real deletion is tombstoned.
    let records = proc.scan_existing_files("group-1", &root).unwrap();
    assert!(records.iter().any(|r| r.path == "plain/old.txt" && r.deleted), "{records:?}");
}

/// A link with no recorded volume whose root's volume cannot be observed is not
/// started: the first capture would otherwise record whatever is mounted there.
/// Nothing is captured, deleted or recorded; once the volume reads, the same
/// scan proceeds normally.
#[test]
fn an_unobservable_volume_before_the_first_record_starts_nothing() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root_without_volume_identity(&state, "group-1", &root);
    std::fs::write(root.join("new.txt"), b"new").unwrap();
    index_hydrated_missing_file(&state, "group-1", "old.txt");
    yadorilink_filesystem_sync::device_boundary::seam::set_root_identity(&root, None);

    let scanned = proc.scan_existing_files("group-1", &root);

    yadorilink_filesystem_sync::device_boundary::seam::clear_root_identity(&root);
    assert!(scanned.is_err(), "no scan without an observable volume: {scanned:?}");
    assert!(state.file_index_repository().get_file("group-1", "new.txt").unwrap().is_none());
    assert!(
        !state.file_index_repository().get_file("group-1", "old.txt").unwrap().unwrap().deleted
    );
    assert_eq!(
        state.link_repository().capture_volume_identity_for_group("group-1").unwrap(),
        Some(None)
    );

    let records = proc.scan_existing_files("group-1", &root).unwrap();
    assert!(records.iter().any(|r| r.path == "new.txt" && !r.deleted), "{records:?}");
}

/// A root that is no longer on the recorded volume (swapped volume, or an
/// unmounted root leaving an empty mountpoint) is refused outright: neither a
/// scan nor a live event captures or tombstones anything under it, and it is
/// never re-adopted.
#[tokio::test]
async fn a_changed_root_volume_stops_all_tombstoning() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let recorded = state.link_repository().capture_volume_identity_for_group("group-1").unwrap();
    index_hydrated_missing_file(&state, "group-1", "docs/a.txt");
    index_hydrated_missing_file(&state, "group-1", "docs/b.txt");
    yadorilink_filesystem_sync::device_boundary::seam::set_root_identity(
        &root,
        Some("unix:424242"),
    );

    let scanned = proc.scan_existing_files("group-1", &root);
    let event = proc
        .process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: root.join("docs/b.txt"), kind: FsChangeKind::ObservedRemoval },
        )
        .await;

    yadorilink_filesystem_sync::device_boundary::seam::clear_root_identity(&root);
    assert!(scanned.is_err(), "a scan of a root off its volume is refused: {scanned:?}");
    assert!(event.is_err(), "a live event under a root off its volume is refused: {event:?}");
    for path in ["docs/a.txt", "docs/b.txt"] {
        assert!(!state.file_index_repository().get_file("group-1", path).unwrap().unwrap().deleted);
    }
    assert_eq!(
        state.link_repository().capture_volume_identity_for_group("group-1").unwrap(),
        recorded,
        "a mismatch must not be adopted as the new identity"
    );

    // Back on the recorded volume, the same absence is a real deletion.
    let records = proc.scan_existing_files("group-1", &root).unwrap();
    assert!(records.iter().any(|r| r.path == "docs/a.txt" && r.deleted), "{records:?}");
}

/// A platform that cannot observe a file's unix mode and replicated attributes
/// (Windows; macOS for attributes) inherits them from the path's semantic
/// predecessor and never captures their absence as a removal.
const RECEIVED_MODE: u32 = 0o644;

fn received_xattrs() -> Vec<(String, Vec<u8>)> {
    vec![("user.origin".to_string(), b"linux".to_vec())]
}

/// A peer-materialized file whose row records `RECEIVED_MODE` and attributes
/// the capturing platform cannot read.
async fn received_file_on_a_platform_that_reads_no_metadata() -> (
    LocalChangeProcessor,
    Arc<TestReplica>,
    std::path::PathBuf,
    tempfile::TempDir,
    tempfile::TempDir,
    Arc<CountingBlockStore>,
) {
    let (proc, state, store, store_dir, root_dir) = processor_with_counting_store();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let content = b"received bytes\n";
    let scratch = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(scratch.path(), content).unwrap();
    let blocks = yadorilink_local_storage::chunk_file(store.as_ref(), scratch.path()).unwrap();
    let file_path = root.join("received.bin");
    const PEER_AUTHORED_MTIME: i64 = 1_600_000_000_000_000_000;
    yadorilink_local_storage::reconstruct_file(
        store.as_ref(),
        &file_path,
        &blocks,
        PEER_AUTHORED_MTIME,
    )
    .unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &FileRecord {
                path: "received.bin".to_string(),
                size: content.len() as u64,
                mtime_unix_nanos: PEER_AUTHORED_MTIME,
                blocks,
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    state
        .file_index_repository()
        .set_unix_mode("group-1", "received.bin", Some(RECEIVED_MODE), &permit)
        .unwrap();
    state
        .file_index_repository()
        .set_xattrs("group-1", "received.bin", &received_xattrs(), &permit)
        .unwrap();
    proc.simulate_unobservable_modes();
    (proc, state, file_path, store_dir, root_dir, store)
}

#[tokio::test]
async fn a_noop_capture_where_no_metadata_is_readable_keeps_the_recorded_mode_and_attributes() {
    let (proc, state, file_path, _s, _r, _store) =
        received_file_on_a_platform_that_reads_no_metadata().await;
    let root = file_path.parent().unwrap().to_path_buf();
    let versions = state.sqlite().dag_list_versions("group-1", "received.bin").unwrap().len();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let outcome = proc
        .process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();
    assert!(matches!(outcome, LocalChangeOutcome::None), "no metadata read is no edit");
    proc.scan_existing_files("group-1", &root).unwrap();

    assert_eq!(
        state.sqlite().dag_list_versions("group-1", "received.bin").unwrap().len(),
        versions
    );
    assert_eq!(
        state.file_index_repository().get_unix_mode("group-1", "received.bin").unwrap(),
        Some(RECEIVED_MODE)
    );
}

#[tokio::test]
async fn a_content_edit_where_no_metadata_is_readable_inherits_the_mode_and_attributes() {
    let (proc, state, file_path, _s, _r, _store) =
        received_file_on_a_platform_that_reads_no_metadata().await;
    let root = file_path.parent().unwrap().to_path_buf();
    std::fs::write(&file_path, b"edited here, where mode and attributes are unreadable\n").unwrap();
    let outcome = proc
        .process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();
    expect_file_changed(outcome);

    assert_eq!(
        state.file_index_repository().get_unix_mode("group-1", "received.bin").unwrap(),
        Some(RECEIVED_MODE),
        "the edited version must keep the predecessor's mode, not drop it"
    );
    assert_eq!(
        state.file_index_repository().get_xattrs("group-1", "received.bin").unwrap(),
        received_xattrs(),
        "the edited version must keep the predecessor's attributes, not drop them"
    );
}

#[tokio::test]
async fn a_new_file_where_no_metadata_is_readable_has_no_mode_and_no_attributes() {
    let (proc, state, file_path, _s, _r, _store) =
        received_file_on_a_platform_that_reads_no_metadata().await;
    let root = file_path.parent().unwrap().to_path_buf();
    let fresh = root.join("made-here.bin");
    std::fs::write(&fresh, b"made here\n").unwrap();
    let outcome = proc
        .process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: fresh.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();
    expect_file_changed(outcome);

    assert_eq!(
        state.file_index_repository().get_unix_mode("group-1", "made-here.bin").unwrap(),
        None
    );
    assert!(state
        .file_index_repository()
        .get_xattrs("group-1", "made-here.bin")
        .unwrap()
        .is_empty());
}

/// A streaming consumer that reports failure must stop the rescan: the scan
/// returns the consumer error instead of committing the rest of the tree
/// into chunks nobody will announce.
#[test]
fn streaming_reconciliation_stops_when_the_chunk_consumer_fails() {
    let (proc, _state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();

    let n = RECONCILE_CHUNK_OP_LIMIT * 3;
    for i in 0..n {
        std::fs::write(root.join(format!("f{i}")), b"a").unwrap();
    }
    let mut calls = 0usize;
    let mut failing = |_records: &[FileRecord]| -> Result<(), LocalCaptureError> {
        calls += 1;
        Err(LocalCaptureError::StreamingConsumerClosed)
    };
    let result =
        proc.scan_existing_files_with_ignore_streaming(group, &root, &ignore_set, &mut failing);
    assert!(
        matches!(result, Err(LocalCaptureError::StreamingConsumerClosed)),
        "a failed consumer must fail the scan, got {result:?}"
    );
    assert_eq!(calls, 1, "the scan must stop at the first failed hand-off");
}

/// What a finished scan leaves behind, in a form comparable across schedules:
/// per-path content (size and block hashes; mtime-dependent version ids and
/// signed transaction ids are deliberately left out), how often each path was
/// authored across the whole native history, and whether any op deleted.
#[derive(Debug, PartialEq, Eq)]
struct ScanOutcome {
    content: std::collections::BTreeMap<String, (u64, Vec<Vec<u8>>)>,
    authored_per_path: std::collections::BTreeMap<String, usize>,
    deletes: usize,
    heads: usize,
    dirty_rows: usize,
}

fn scan_outcome(state: &TestReplica, group: &str) -> ScanOutcome {
    use crate::ports::LocalMutationStore as _;
    let content = state
        .list_files(group)
        .unwrap()
        .into_iter()
        .filter(|r| !r.deleted)
        .map(|r| (r.path, (r.size, r.blocks.into_iter().map(|b| b.hash).collect())))
        .collect();
    let mut authored_per_path = std::collections::BTreeMap::new();
    let mut deletes = 0;
    for delta in crate::test_support::native_deltas(state, group) {
        for op in &delta.ops {
            if op.put.is_some() {
                *authored_per_path.entry(op.path.0.clone()).or_insert(0) += 1;
            } else {
                deletes += 1;
            }
        }
    }
    ScanOutcome {
        content,
        authored_per_path,
        deletes,
        heads: crate::test_support::native_group_heads(state, group).len(),
        dirty_rows: state.list_dirty_paths(group).unwrap().len(),
    }
}

/// How the interrupted streaming run ends after its chunk is durable.
#[derive(Clone, Copy, Debug)]
enum ConsumerFault {
    /// The callback returns an error.
    Error,
    /// The callback aborts (a panic stands in for the process dying between
    /// the chunk commit and the callback's result).
    Abort,
}

/// What "restart" means between the interrupted run and its retry.
#[derive(Clone, Copy, Debug)]
enum Restart {
    /// The same processor and in-memory replica carry on.
    SameHandles,
    /// The index lives in a file; every handle is dropped, the file is
    /// reopened, and a fresh processor retries.
    ReopenFile,
}

/// A processor over a replica opened at `index_dir/index.db` (created on
/// first open, reloaded on a later one) and a block store in `store_dir`.
fn file_backed_processor(
    index_dir: &Path,
    store_dir: &Path,
) -> (LocalChangeProcessor, Arc<TestReplica>) {
    use ed25519_dalek::SigningKey;
    let store = Arc::new(SegmentBlockStore::new(store_dir).unwrap());
    let state = Arc::new(TestReplica::open_file_backed(index_dir).unwrap());
    let emitter =
        Arc::new(LocalAuthorKey::for_tests("device-a", SigningKey::from_bytes(&[5u8; 32])));
    let proc = LocalChangeProcessor::new(
        state.clone(),
        store,
        "device-a".into(),
        std::sync::Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
    )
    .with_change_emitter(emitter);
    (proc, state)
}

/// Runs one streaming scan over `n` fresh tiny files whose consumer fails on
/// its `fail_on`-th callback (1-based; `None` never fails), then re-runs the
/// scan with a healthy consumer until it completes (the "restart"). The
/// callback must never see a chunk the index does not hold yet, a failing
/// callback must stop any further chunk from committing, and the retry must
/// hand over exactly the paths the interrupted run did not. With
/// `Restart::ReopenFile` the stored index is closed for real in between and
/// must hold exactly the committed chunks when it is reopened.
fn interrupted_streaming_scan(
    n: usize,
    fail_on: Option<usize>,
    fault: ConsumerFault,
    restart: Restart,
) -> ScanOutcome {
    use crate::ports::LocalMutationStore as _;
    let index_dir = tempfile::tempdir().unwrap();
    let store_dir = tempfile::tempdir().unwrap();
    let root_dir = tempfile::tempdir().unwrap();
    // The in-memory fixture owns its own store dir; keep it alive.
    let mut _in_memory_store_dir = None;
    let (mut proc, mut state) = match restart {
        Restart::SameHandles => {
            let (proc, state, _emitter, kept_store_dir, _root_dir) = processor_with_emitter();
            _in_memory_store_dir = Some(kept_store_dir);
            (proc, state)
        }
        Restart::ReopenFile => file_backed_processor(index_dir.path(), store_dir.path()),
    };
    let root = canonical_root(&root_dir);
    let group = "group-1";
    let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();
    for i in 0..n {
        std::fs::write(root.join(format!("f{i:05}")), format!("body {i}")).unwrap();
    }
    let chunks = n.div_ceil(RECONCILE_CHUNK_OP_LIMIT);

    let first_run_paths = std::sync::Mutex::new(std::collections::BTreeSet::<String>::new());
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let first = {
        let observer = state.clone();
        let mut consumer = |records: &[FileRecord]| -> Result<(), LocalCaptureError> {
            let call = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            let indexed: std::collections::BTreeSet<String> =
                observer.list_files(group).unwrap().into_iter().map(|r| r.path).collect();
            let mut seen = first_run_paths.lock().unwrap();
            for record in records {
                assert!(
                    indexed.contains(&record.path),
                    "{} handed over before it was committed",
                    record.path
                );
                assert!(seen.insert(record.path.clone()), "{} handed over twice", record.path);
            }
            if Some(call) == fail_on {
                match fault {
                    ConsumerFault::Error => return Err(LocalCaptureError::StreamingConsumerClosed),
                    ConsumerFault::Abort => {
                        drop(seen);
                        panic!("injected abort between a chunk commit and its callback result");
                    }
                }
            }
            Ok(())
        };
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            proc.scan_existing_files_with_ignore_streaming(group, &root, &ignore_set, &mut consumer)
        }))
    };
    let first_run_paths = first_run_paths.into_inner().unwrap_or_else(|p| p.into_inner());
    let calls = calls.load(std::sync::atomic::Ordering::SeqCst);
    match fail_on {
        None => {
            first.unwrap().unwrap();
            assert_eq!(first_run_paths.len(), n, "every path handed over once");
        }
        Some(k) => {
            match (fault, first) {
                (ConsumerFault::Error, Ok(result)) => assert!(
                    matches!(result, Err(LocalCaptureError::StreamingConsumerClosed)),
                    "the failed consumer must fail the scan, got {:?}",
                    result.as_ref().map(Vec::len)
                ),
                (ConsumerFault::Abort, Err(_)) => {}
                (fault, other) => panic!("{fault:?} ended the scan as {:?}", other.is_ok()),
            }
            assert_eq!(calls, k, "no callback after the failed one");
            let committed = crate::test_support::native_deltas(&state, group).len();
            assert_eq!(committed, k, "a failed hand-off must stop later chunks from committing");
            if k < chunks {
                assert!(first_run_paths.len() < n, "the interrupted run must not have finished");
            }

            if let Restart::ReopenFile = restart {
                // Every handle goes: the processor and the replica must be
                // the last owners of the database before it is reopened.
                drop(proc);
                let owned = Arc::try_unwrap(state)
                    .unwrap_or_else(|_| panic!("a replica handle outlived the processor"));
                drop(owned);
                let (reopened_proc, reopened_state) =
                    file_backed_processor(index_dir.path(), store_dir.path());
                proc = reopened_proc;
                state = reopened_state;
                assert_eq!(
                    crate::test_support::native_deltas(&state, group).len(),
                    k,
                    "the reopened index lost or gained a committed chunk"
                );
                let indexed: std::collections::BTreeSet<String> =
                    state.list_files(group).unwrap().into_iter().map(|r| r.path).collect();
                assert_eq!(
                    indexed, first_run_paths,
                    "the reopened index must hold exactly the chunks the callback saw"
                );
            }

            // Restart: only what the interrupted run did not commit is left.
            let mut retry_paths = Vec::new();
            let mut healthy = |records: &[FileRecord]| -> Result<(), LocalCaptureError> {
                retry_paths.extend(records.iter().map(|r| r.path.clone()));
                Ok(())
            };
            proc.scan_existing_files_with_ignore_streaming(group, &root, &ignore_set, &mut healthy)
                .unwrap();
            for path in &retry_paths {
                assert!(!first_run_paths.contains(path), "{path} was authored again on restart");
            }
            assert_eq!(retry_paths.len() + first_run_paths.len(), n, "every path handed over once");
        }
    }
    let outcome = scan_outcome(&state, group);
    // A further scan of unchanged bytes authors nothing.
    let heads = crate::test_support::native_group_heads(&state, group);
    let deltas = crate::test_support::native_deltas(&state, group).len();
    proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
    assert_eq!(
        crate::test_support::native_group_heads(&state, group),
        heads,
        "an idempotent rescan moved the head"
    );
    assert_eq!(
        crate::test_support::native_deltas(&state, group).len(),
        deltas,
        "an idempotent rescan authored a change"
    );
    outcome
}

/// A scan interrupted by a failing chunk consumer (after the chunk is
/// durable) and then re-run is observationally the uninterrupted scan: same
/// content, every path authored exactly once, no tombstone, one head, no
/// dirty rows left behind. Covers a consumer error and a crash-like abort
/// between the chunk commit and the callback result, at the first, a middle
/// and the last callback, with the same live handles and with a real close
/// and reopen of the file-backed index and a fresh processor.
#[test]
fn an_interrupted_streaming_scan_is_equivalent_to_an_uninterrupted_one_after_a_retry() {
    let n = RECONCILE_CHUNK_OP_LIMIT * 2 + 5;
    let chunks = n.div_ceil(RECONCILE_CHUNK_OP_LIMIT);
    assert_eq!(chunks, 3, "the fixture must span first, middle and last chunk");
    let reference = interrupted_streaming_scan(n, None, ConsumerFault::Error, Restart::SameHandles);
    assert_eq!(reference.content.len(), n);
    assert!(reference.authored_per_path.values().all(|&c| c == 1));
    assert_eq!(reference.deletes, 0);
    assert_eq!(reference.heads, 1);
    assert_eq!(reference.dirty_rows, 0);
    let reference_on_disk =
        interrupted_streaming_scan(n, None, ConsumerFault::Error, Restart::ReopenFile);
    assert_eq!(reference_on_disk, reference, "a file-backed uninterrupted scan differs");
    for restart in [Restart::SameHandles, Restart::ReopenFile] {
        for fault in [ConsumerFault::Error, ConsumerFault::Abort] {
            for fail_on in 1..=chunks {
                let outcome = interrupted_streaming_scan(n, Some(fail_on), fault, restart);
                assert_eq!(
                    outcome, reference,
                    "{fault:?} on callback {fail_on} of {chunks}, restart {restart:?}"
                );
            }
        }
    }
}

/// A write that lands after a batched capture has read and bracketed a file,
/// but before the batch commits, must not be committed over as if it were the
/// content that was read. The prepared mutation carries the content read
/// BEFORE the write; the commit's revalidation has to compare the disk
/// against the state from before that read. Taken after the read, the
/// fingerprint described the already-rewritten file, the stale record was
/// committed with a proof that the rewritten bytes were the daemon's own
/// write, and the proof then made every later capture of the path dismiss the
/// rewrite as "an older version's untouched bytes": the edit was lost for good
/// (monkey_chaos: the base file's content differed per device while every
/// device agreed on the DAG).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_between_a_batched_capture_and_its_commit_is_not_lost() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    adopt_root(&state, group, &root);
    let path = root.join("a.txt");
    // Same length on purpose: only the content, mtime and ctime tell them apart.
    std::fs::write(&path, b"version one!!").unwrap();

    let rewrite = path.clone();
    arm_post_capture_race_hook(path.clone(), move || {
        // Let the clock tick so the rewrite is visible to any mtime comparison.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&rewrite, b"version two!!").unwrap();
        false // one-shot
    });
    let flush = || {
        yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![(
            path.clone(),
            FsChangeKind::CreatedOrModified,
            0,
        )])
    };
    proc.process_flush(group, &root, flush()).await.unwrap();
    disarm_post_capture_race_hook(&path);

    // Whatever the first flush did, the path must end up describing the bytes
    // on disk once it is re-driven.
    proc.process_flush(group, &root, flush()).await.unwrap();
    let on_disk = std::fs::read(&path).unwrap();
    assert_eq!(on_disk, b"version two!!");
    let row = state.file_index_repository().get_file(group, "a.txt").unwrap().unwrap();
    let indexed_hash = row.blocks.first().map(|b| hex::encode(&b.hash));
    let expected = yadorilink_local_storage::hash_block_bytes(&on_disk);
    assert_eq!(
        indexed_hash,
        Some(expected),
        "the index must describe the rewritten file, not the content read before the rewrite"
    );
}

/// The identity a batch commit publishes as `Present` evidence is observed
/// after the prepared-fingerprint check; a write landing between that check
/// and the observation must be caught by a closing re-check, not vouched for
/// as the bytes of the (stale) record being committed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_between_the_batch_fingerprint_check_and_the_identity_observation_is_not_lost() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    adopt_root(&state, group, &root);
    let path = root.join("b.txt");
    std::fs::write(&path, b"version one!!").unwrap();

    let ignore_set = EffectiveIgnoreSet::from_user_patterns("");
    let mut pending = Vec::new();
    let outcome = proc
        .process_event_with_ignore_at(
            group,
            &root,
            &FsChangeEvent { path: path.clone(), kind: FsChangeKind::CreatedOrModified },
            &ignore_set,
            Some(0),
            Some(&mut pending),
        )
        .await
        .unwrap();
    assert!(matches!(outcome, EventOutcome::Deferred));

    let rewrite = path.clone();
    arm_post_identity_race_hook(path.clone(), move || {
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&rewrite, b"version two!!").unwrap();
        false
    });
    let resolved = proc.flush_pending_batch(group, &root, &mut pending).await.unwrap();
    disarm_post_identity_race_hook(&path);
    assert!(resolved.is_empty(), "a mutation whose file changed during commit must be excluded");

    proc.process_flush(
        group,
        &root,
        yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![(
            path.clone(),
            FsChangeKind::CreatedOrModified,
            0,
        )]),
    )
    .await
    .unwrap();
    let row = state.file_index_repository().get_file(group, "b.txt").unwrap().unwrap();
    assert_eq!(
        row.blocks.first().map(|b| hex::encode(&b.hash)),
        Some(yadorilink_local_storage::hash_block_bytes(b"version two!!")),
        "the re-driven capture must index the rewritten file"
    );
}

/// A batched delete whose prepared fingerprint is that of a sibling the path
/// folds to (the exact name was what was observed absent) must not publish
/// `Absent` once the exact name exists again with an identical fingerprint.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_batched_delete_is_dropped_when_the_exact_name_exists_at_commit() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    let group = "group-1";
    adopt_root(&state, group, &root);
    let path = root.join("c.txt");
    std::fs::write(&path, b"version one!!").unwrap();
    let event = FsChangeEvent { path: path.clone(), kind: FsChangeKind::CreatedOrModified };
    expect_file_changed(proc.process_event(group, &root, &event).await.unwrap());

    std::fs::remove_file(&path).unwrap();
    let ignore_set = EffectiveIgnoreSet::from_user_patterns("");
    let mut pending = Vec::new();
    let outcome = proc
        .process_event_with_ignore_at(
            group,
            &root,
            &FsChangeEvent { path: path.clone(), kind: FsChangeKind::ObservedRemoval },
            &ignore_set,
            Some(0),
            Some(&mut pending),
        )
        .await
        .unwrap();
    assert!(matches!(outcome, EventOutcome::Deferred), "test precondition: delete is batched");

    // The exact name comes back, and the prepared fingerprint is the one a
    // sibling at this name would have shown.
    std::fs::write(&path, b"version two!!").unwrap();
    pending[0].disk_fingerprint_at_prepare = disk_race_fingerprint(&path);
    let resolved = proc.flush_pending_batch(group, &root, &mut pending).await.unwrap();
    assert!(resolved.is_empty(), "a delete must not commit while the exact name exists");
    assert!(
        !state.file_index_repository().get_file(group, "c.txt").unwrap().unwrap().deleted,
        "the row must stay live"
    );
}

/// A debounced flush that lands while a
/// safe stop has the lease paused is refused before it journals anything, so
/// after the pause is lifted (a `busy` safe stop) the edit is neither indexed
/// nor in the dirty journal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flush_during_a_safe_stop_pause_keeps_the_edit_after_the_pause_lifts() {
    use ed25519_dalek::SigningKey;
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let state = Arc::new(TestReplica::open_in_memory().unwrap());
    state.set_local_change_auth_provider(Arc::new(|_group_id| Ok(())));
    let lease = Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests());
    let emitter =
        Arc::new(LocalAuthorKey::for_tests("device-a", SigningKey::from_bytes(&[9u8; 32])));
    let proc = LocalChangeProcessor::new(state.clone(), store, "device-a".into(), lease.clone())
        .with_change_emitter(emitter);
    let root_dir = tempfile::tempdir().unwrap();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let p = root.join("edited.txt");
    std::fs::write(&p, b"user edit").unwrap();

    lease.begin_quiesce();
    let flush = yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![(
        p.clone(),
        FsChangeKind::CreatedOrModified,
        0,
    )]);
    let result = proc.process_flush("group-1", &root, flush).await;
    lease.end_quiesce();

    let dirty = state.dirty_path_repository().list_dirty_paths("group-1").unwrap();
    let indexed = state.file_index_repository().get_file("group-1", "edited.txt").unwrap();
    eprintln!(
        "flush result is_err={} dirty={dirty:?} indexed={}",
        result.is_err(),
        indexed.is_some()
    );
    assert!(
        indexed.is_some() || !dirty.is_empty(),
        "the edit made during the pause is remembered somewhere after the pause is lifted"
    );

    // The periodic redrive of the dirty journal then captures it, once the pause is lifted.
    proc.redrive_dirty_journal("group-1", &root).await.unwrap();
    let indexed = state.file_index_repository().get_file("group-1", "edited.txt").unwrap();
    assert!(indexed.is_some(), "the redrive captures the edit made during the pause");
    assert!(
        state.dirty_path_repository().list_dirty_paths("group-1").unwrap().is_empty(),
        "and clears its journal row"
    );
}

/// A pause that is lifted again must not look like a link being torn down: only a stopping
/// lease refuses the journal, and a stop (permanent) keeps its old behaviour.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_permanent_stop_still_refuses_and_a_pause_only_defers() {
    let lease = yadorilink_root_authority::root_commit::RootLease::for_tests();
    lease.begin_quiesce();
    assert!(matches!(
        lease.begin_operation(),
        Err(yadorilink_root_authority::RootAuthorityError::Quiescing(_))
    ));
    assert!(!lease.is_stopping());
    assert!(lease.begin_journal_operation().is_ok(), "journaling is admitted during a pause");
    lease.begin_stopping();
    assert!(lease.is_stopping());
    assert!(lease.begin_journal_operation().is_err(), "a stop refuses the journal too");
    assert!(matches!(
        lease.begin_operation(),
        Err(yadorilink_root_authority::RootAuthorityError::NotFound(_))
    ));
}

/// A full rescan journals nothing of its own, so a chunk that a safe-stop pause refuses must be
/// reported as paused (the caller repeats the rescan); repeated after the pause, it finds the
/// edit and the delete that the refused pass missed. A permanent stop is not reported as paused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rescan_refused_by_a_pause_reports_it_and_the_repeat_captures_everything() {
    use ed25519_dalek::SigningKey;
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let state = Arc::new(TestReplica::open_in_memory().unwrap());
    state.set_local_change_auth_provider(Arc::new(|_group_id| Ok(())));
    let lease = Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests());
    let emitter =
        Arc::new(LocalAuthorKey::for_tests("device-a", SigningKey::from_bytes(&[9u8; 32])));
    let proc = LocalChangeProcessor::new(state.clone(), store, "device-a".into(), lease.clone())
        .with_change_emitter(emitter);
    let root_dir = tempfile::tempdir().unwrap();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    std::fs::write(root.join("gone.txt"), b"to be deleted").unwrap();
    std::fs::write(root.join("kept.txt"), b"v1").unwrap();
    let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();
    proc.scan_existing_files_with_ignore("group-1", &root, &ignore_set).unwrap();

    // Changes the watcher never reported (it overflowed): only a rescan can find them.
    std::fs::remove_file(root.join("gone.txt")).unwrap();
    std::fs::write(root.join("kept.txt"), b"v2 edited").unwrap();

    async fn rescan(
        proc: &LocalChangeProcessor,
        root: &Path,
        ignore_set: &EffectiveIgnoreSet,
    ) -> Result<FlushOutcome, crate::LocalCaptureError> {
        proc.process_flush_with_ignore_streaming(
            "group-1",
            root,
            yadorilink_filesystem_sync::debounce::DebounceFlush::RescanRequired,
            ignore_set,
            true,
            &mut |_| Ok(()),
        )
        .await
    }

    lease.begin_quiesce();
    let paused = rescan(&proc, &root, &ignore_set).await;
    assert!(matches!(paused, Err(crate::LocalCaptureError::Paused)), "{paused:?}");

    lease.end_quiesce();
    let records = rescan(&proc, &root, &ignore_set).await.unwrap().records;
    assert!(records.iter().any(|r| r.path == "kept.txt" && !r.deleted), "{records:?}");
    assert!(records.iter().any(|r| r.path == "gone.txt" && r.deleted), "{records:?}");

    // A permanent stop is a different refusal.
    lease.begin_stopping();
    let stopped = rescan(&proc, &root, &ignore_set).await;
    assert!(!matches!(stopped, Err(crate::LocalCaptureError::Paused)));
}

/// Counts WARN events on the thread that installs it.
#[cfg(unix)]
struct WarnCounter(Arc<std::sync::atomic::AtomicUsize>);

#[cfg(unix)]
impl tracing::Subscriber for WarnCounter {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        if *event.metadata().level() == tracing::Level::WARN {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

/// A file that stays unreadable across several flush passes is warned about once per path/reason
/// (by the unreadable-file ledger), not on every re-drive; recovering and failing again, or
/// failing for a different reason, warns again.
#[cfg(unix)]
#[tokio::test]
async fn a_file_that_stays_unreadable_warns_once_across_flush_passes() {
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let warns = Arc::new(AtomicUsize::new(0));
    let _guard = tracing::subscriber::set_default(WarnCounter(Arc::clone(&warns)));
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    let Some(bad) = make_unreadable(&root, "bad.txt", b"secret") else { return };
    let flush = || {
        yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![(
            bad.clone(),
            FsChangeKind::CreatedOrModified,
            0,
        )])
    };

    for _ in 0..3 {
        proc.process_flush("group-1", &root, flush()).await.unwrap();
    }
    assert_eq!(warns.load(Ordering::SeqCst), 1, "three passes over one unreadable path: one WARN");
    assert_eq!(proc.unreadable_ledger().needing_user("group-1").len(), 1);

    // Readable again: the report clears and nothing is logged.
    make_readable(&bad);
    proc.process_flush("group-1", &root, flush()).await.unwrap();
    assert!(proc.unreadable_ledger().needing_user("group-1").is_empty());
    assert_eq!(warns.load(Ordering::SeqCst), 1);

    // Unreadable again after recovering: a new failure, so it warns again (once).
    std::fs::write(&bad, b"changed").unwrap();
    std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o000)).unwrap();
    for _ in 0..2 {
        proc.process_flush("group-1", &root, flush()).await.unwrap();
    }
    assert_eq!(warns.load(Ordering::SeqCst), 2);
}
