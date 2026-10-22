#![cfg(test)]
//! The open of a file's write (intent, row, in-flight state, held clear and
//! fence bump), queued with the run's other files and committed in one batch
//! transaction: when it flushes, what one item's failure or lost root does to
//! the others, what a dropped waiter leaves behind, and what the disk and the
//! path lock look like while a file waits for its batch.
//!
//! The window tests run the real batch transaction against a real database;
//! only the files' tasks (and the guards they hold) are stood in for by the
//! test. The run tests drive the real receive path.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
use yadorilink_root_authority::root_commit::{OwnedPermitCheck, RootCommitPermit, RootLease};
use yadorilink_root_authority::sync_root_lock::SyncRootLock;

use super::completion_window::CompletionWindow;
use super::completion_window::Participant;
use super::growing_file_projection_tests::{Harness, GROUP};
use super::receive_window_concurrency_tests::{
    names, pin_concurrency, publish, put, reconcile, run_workload_full, snapshot, source,
};
use crate::replica_coordinator::{OwnedContentWriteOpen, ReplicaCoordinator};
use yadorilink_peer_session::PeerSessionError;

fn valid_check() -> OwnedPermitCheck {
    RootCommitPermit::for_tests().owned_check()
}

fn record(path: &str, seed: u8) -> FileRecord {
    FileRecord {
        path: path.to_owned(),
        size: 5,
        mtime_unix_nanos: 1,
        blocks: vec![BlockInfo { hash: vec![seed; 32], offset: 0, size: 5 }],
        deleted: false,
    }
}

fn open_item(
    path: &str,
    seed: u8,
    lane_check: OwnedPermitCheck,
    row_check: OwnedPermitCheck,
) -> OwnedContentWriteOpen {
    let record = record(path, seed);
    OwnedContentWriteOpen {
        group_id: GROUP.to_owned(),
        intent_target_hash: yadorilink_local_storage::intent_target_hash(&record.blocks),
        record,
        origin_device_id: "device-peer".to_owned(),
        authoring: None,
        meta: crate::replica_coordinator::plain_file_columns(),
        now: 1,
        lane_check,
        row_check,
        gate: None,
        gate_fired: std::sync::atomic::AtomicBool::new(false),
    }
}

fn valid_item(path: &str, seed: u8) -> OwnedContentWriteOpen {
    open_item(path, seed, valid_check(), valid_check())
}

/// A root whose identity can be swapped, to stand for a link that lost it.
struct ClaimedRoot {
    lease: Arc<RootLease>,
    dir: tempfile::TempDir,
}

impl ClaimedRoot {
    fn new(state: &ReplicaCoordinator) -> Self {
        let dir = tempfile::tempdir().unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(dir.path(), GROUP, state)
            .unwrap();
        let lock = SyncRootLock::acquire(dir.path()).unwrap();
        Self { lease: Arc::new(RootLease::new(lock, GROUP.to_owned(), 0)), dir }
    }

    fn swap(&self) {
        let lock_path = self
            .dir
            .path()
            .join(yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME);
        std::fs::remove_file(&lock_path).unwrap();
        std::fs::File::create(&lock_path).unwrap();
    }
}

/// Everything the open of `path` writes: the intent, the row, the in-flight
/// state, and the fence.
fn opened(state: &ReplicaCoordinator, path: &str) -> bool {
    state.has_materialization_intent(GROUP, path).unwrap()
        && state.get_file(GROUP, path).unwrap().is_some()
        && state.get_materialization_state(GROUP, path).unwrap()
            == Some(yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE)
}

/// Nothing of the open: no intent, no row, no state.
fn untouched(state: &ReplicaCoordinator, path: &str) -> bool {
    !state.has_materialization_intent(GROUP, path).unwrap()
        && state.get_file(GROUP, path).unwrap().is_none()
        && state.get_materialization_state(GROUP, path).unwrap().is_none()
}

fn batch_sizes(state: &ReplicaCoordinator) -> Vec<usize> {
    state.test_observers.open_batch_sizes.lock().unwrap().clone()
}

/// A trigger that refuses the LAST statement of one path's open (the fence
/// bump), after the intent, the row and the state were written: only the
/// item's savepoint takes those back.
fn refuse_late_in_open(state: &ReplicaCoordinator, path: &str) {
    state
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            conn.execute_batch(&format!(
                "CREATE TRIGGER refuse_open BEFORE INSERT ON path_actual_mutation_fences \
                 WHEN NEW.path = '{path}' BEGIN SELECT RAISE(ABORT, 'refused'); END;"
            ))?;
            Ok(())
        })
        .unwrap();
}

// ---------------------------------------------------------------------
// The window on its own
// ---------------------------------------------------------------------

#[tokio::test]
async fn a_lone_file_opens_at_once_however_long_the_deadline() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let window = CompletionWindow::new(8, Duration::from_secs(10));
    let a = window.join();

    let started = Instant::now();
    let fence =
        tokio::time::timeout(Duration::from_secs(3), a.submit_open(&state, valid_item("a.txt", 1)))
            .await
            .expect("a lone file waited for its batch")
            .unwrap();

    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(fence > 0, "the fence value comes back as a value");
    assert!(opened(&state, "a.txt"));
    assert_eq!(batch_sizes(&state), vec![1]);
}

#[tokio::test]
async fn the_files_of_a_window_open_in_one_transaction_once_every_participant_queued() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let window = CompletionWindow::new(8, Duration::from_secs(10));
    let (a, b, c) = (window.join(), window.join(), window.join());

    let (a_fence, b_fence, c_fence) = tokio::join!(
        a.submit_open(&state, valid_item("a.txt", 1)),
        b.submit_open(&state, valid_item("b.txt", 2)),
        async {
            // The third file arrives later: the others wait for it.
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(batch_sizes(&state).is_empty(), "flushed before every participant queued");
            c.submit_open(&state, valid_item("c.txt", 3)).await
        },
    );

    let fences = [a_fence.unwrap(), b_fence.unwrap(), c_fence.unwrap()];
    assert!(
        fences.iter().all(|fence| *fence > 0),
        "every item gets its own fence value: {fences:?}"
    );
    assert_eq!(batch_sizes(&state), vec![3], "three files, one open transaction");
    for path in ["a.txt", "b.txt", "c.txt"] {
        assert!(opened(&state, path), "{path}");
    }
}

#[tokio::test]
async fn a_queue_that_reaches_its_cap_flushes_without_waiting_for_the_rest() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let window = CompletionWindow::new(2, Duration::from_secs(10));
    let (a, b, _straggler) = (window.join(), window.join(), window.join());

    let started = Instant::now();
    let (a_fence, b_fence) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            a.submit_open(&state, valid_item("a.txt", 1)),
            b.submit_open(&state, valid_item("b.txt", 2)),
        )
    })
    .await
    .expect("a full queue waited for a straggler");
    a_fence.unwrap();
    b_fence.unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(batch_sizes(&state), vec![2]);
}

#[tokio::test]
async fn the_deadline_flushes_a_queue_whose_participants_have_not_all_arrived() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let window = CompletionWindow::new(8, Duration::from_millis(50));
    let (a, _straggler) = (window.join(), window.join());

    let started = Instant::now();
    tokio::time::timeout(Duration::from_secs(5), a.submit_open(&state, valid_item("a.txt", 1)))
        .await
        .expect("the deadline never flushed")
        .unwrap();
    assert!(started.elapsed() >= Duration::from_millis(40), "flushed before the deadline");
    assert_eq!(batch_sizes(&state), vec![1]);
}

/// One item whose statements are refused does not abort the others, and
/// leaves nothing of itself: the same state a refused single open leaves.
#[tokio::test]
async fn a_refused_item_leaves_the_others_of_its_batch_opened() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    refuse_late_in_open(&state, "b.txt");
    let window = CompletionWindow::new(8, Duration::from_secs(10));
    let (a, b, c) = (window.join(), window.join(), window.join());

    let (a_out, b_out, c_out) = tokio::join!(
        a.submit_open(&state, valid_item("a.txt", 1)),
        b.submit_open(&state, valid_item("b.txt", 2)),
        c.submit_open(&state, valid_item("c.txt", 3)),
    );

    assert!(a_out.is_ok() && c_out.is_ok());
    assert!(b_out.is_err(), "the refused item reports its own error");
    assert!(opened(&state, "a.txt") && opened(&state, "c.txt"));
    assert!(untouched(&state, "b.txt"), "the refused item's savepoint rolled back");
    assert_eq!(batch_sizes(&state), vec![3]);
}

/// A lane permit whose root is no longer this link's aborts the whole
/// transaction: nothing of any item is written, and every waiter errors.
#[tokio::test]
async fn a_lost_lane_root_aborts_the_whole_batch() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root = ClaimedRoot::new(&state);
    let operation = root.lease.begin_operation().unwrap();
    let lost = operation.permit().owned_check();
    root.swap();
    let window = CompletionWindow::new(8, Duration::from_secs(10));
    let (a, b) = (window.join(), window.join());

    let (a_out, b_out) = tokio::join!(
        a.submit_open(&state, valid_item("a.txt", 1)),
        b.submit_open(&state, open_item("b.txt", 2, lost, valid_check())),
    );

    assert!(a_out.is_err() && b_out.is_err(), "a lost root fails the batch");
    assert!(untouched(&state, "a.txt") && untouched(&state, "b.txt"));
}

/// The row's own fresh permit is checked per item too.
#[tokio::test]
async fn a_lost_row_root_aborts_the_whole_batch() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root = ClaimedRoot::new(&state);
    let operation = root.lease.begin_operation().unwrap();
    let lost = operation.permit().owned_check();
    root.swap();
    let window = CompletionWindow::new(8, Duration::from_secs(10));
    let (a, b) = (window.join(), window.join());

    let (a_out, b_out) = tokio::join!(
        a.submit_open(&state, valid_item("a.txt", 1)),
        b.submit_open(&state, open_item("b.txt", 2, valid_check(), lost)),
    );

    assert!(a_out.is_err() && b_out.is_err());
    assert!(untouched(&state, "a.txt") && untouched(&state, "b.txt"));
}

/// The root checks run even when an item's own statements failed: an item
/// that is refused AND whose root was lost still aborts the whole batch,
/// instead of being isolated as an ordinary refusal.
#[tokio::test]
async fn a_lost_root_aborts_the_batch_even_when_the_items_own_statements_failed() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    refuse_late_in_open(&state, "b.txt");
    let root = ClaimedRoot::new(&state);
    let operation = root.lease.begin_operation().unwrap();
    let lost = operation.permit().owned_check();
    root.swap();
    let window = CompletionWindow::new(8, Duration::from_secs(10));
    let (a, b) = (window.join(), window.join());

    let (a_out, b_out) = tokio::join!(
        a.submit_open(&state, valid_item("a.txt", 1)),
        b.submit_open(&state, open_item("b.txt", 2, lost, valid_check())),
    );

    assert!(a_out.is_err(), "the lost root must reach the first item's outcome too: {a_out:?}");
    assert!(b_out.is_err());
    assert!(untouched(&state, "a.txt"), "an item of the aborted transaction survived");
}

/// A waiter dropped before its batch was taken leaves nothing: the next flush
/// discards its item, and the others of the queue open without it.
#[tokio::test]
async fn a_dropped_waiter_with_its_item_still_queued_commits_nothing() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let window = CompletionWindow::new(8, Duration::from_secs(10));
    let (a, b, c) = (window.join(), window.join(), window.join());

    // `a` queues its item and is dropped while the others have not arrived.
    let dropped = tokio::time::timeout(
        Duration::from_millis(100),
        a.submit_open(&state, valid_item("a.txt", 1)),
    )
    .await;
    assert!(dropped.is_err(), "a queue that others can still join was flushed early");
    drop(a);

    let (b_out, c_out) = tokio::join!(
        b.submit_open(&state, valid_item("b.txt", 2)),
        c.submit_open(&state, valid_item("c.txt", 3)),
    );

    b_out.unwrap();
    c_out.unwrap();
    assert!(untouched(&state, "a.txt"), "an item whose waiter was dropped was committed");
    assert!(opened(&state, "b.txt") && opened(&state, "c.txt"));
    assert_eq!(batch_sizes(&state), vec![2]);
}

// ---------------------------------------------------------------------
// Dropped while the batch commits: the guards of every item stay
// ---------------------------------------------------------------------

fn lease() -> Arc<RootLease> {
    Arc::new(RootLease::for_tests())
}

fn drained_within_blocking(lease: &Arc<RootLease>, wait: Duration) -> bool {
    lease.begin_stopping();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
    runtime.block_on(async { tokio::time::timeout(wait, lease.wait_drained()).await.is_ok() })
}

async fn drained_within(lease: &Arc<RootLease>, wait: Duration) -> bool {
    lease.begin_stopping();
    tokio::time::timeout(wait, lease.wait_drained()).await.is_ok()
}

/// A file future's frames while its open is queued: its path lock, its root
/// operation, and the participant that queues the item.
async fn wait_for_open(
    state: &Arc<ReplicaCoordinator>,
    lease: Arc<RootLease>,
    path_lock: Arc<tokio::sync::Mutex<()>>,
    participant: Participant,
    item: OwnedContentWriteOpen,
) -> Result<i64, PeerSessionError> {
    let _path = path_lock.lock_owned().await;
    let _operation = lease.begin_operation().unwrap();
    participant.submit_open(state, item).await
}

/// A run dropped while its open batch commits keeps every waiter's guards (its
/// path lock and its operation) until the commit is decided, and the batch
/// still lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_run_dropped_while_its_open_batch_commits_keeps_every_waiters_guards() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let (entered_tx, release_rx) = (Mutex::new(entered_tx), Mutex::new(release_rx));
    *state.test_observers.open_batch_gate.lock().unwrap() = Some(Arc::new(move || {
        let _ = entered_tx.lock().unwrap().send(());
        let _ = release_rx.lock().unwrap().recv();
    }));
    let window = CompletionWindow::new(8, Duration::from_secs(10));
    let (lease_a, lease_b) = (lease(), lease());
    let (path_a, path_b) = (state.path_lock(GROUP, "a.txt"), state.path_lock(GROUP, "b.txt"));
    let (participant_a, participant_b) = (window.join(), window.join());

    let task = tokio::spawn({
        let (state, lease_a, lease_b) = (state.clone(), lease_a.clone(), lease_b.clone());
        let (path_a, path_b) = (path_a.clone(), path_b.clone());
        async move {
            let _ = tokio::join!(
                wait_for_open(&state, lease_a, path_a, participant_a, valid_item("a.txt", 1)),
                wait_for_open(&state, lease_b, path_b, participant_b, valid_item("b.txt", 2)),
            );
        }
    });
    tokio::task::spawn_blocking(move || entered_rx.recv().unwrap()).await.unwrap();
    let (a, b, pa, pb) = (lease_a.clone(), lease_b.clone(), path_a.clone(), path_b.clone());
    let probe = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        assert!(!drained_within_blocking(&a, Duration::from_millis(50)), "operation a released");
        assert!(!drained_within_blocking(&b, Duration::from_millis(50)), "operation b released");
        assert!(pa.try_lock().is_err(), "path lock a released while its batch committed");
        assert!(pb.try_lock().is_err(), "path lock b released while its batch committed");
        release_tx.send(()).unwrap();
    });
    task.abort();
    let _ = task.await;
    probe.join().unwrap();
    *state.test_observers.open_batch_gate.lock().unwrap() = None;

    assert!(drained_within(&lease_a, Duration::from_secs(2)).await);
    assert!(drained_within(&lease_b, Duration::from_secs(2)).await);
    assert!(path_a.try_lock().is_ok() && path_b.try_lock().is_ok(), "a path lock leaked");
    assert!(opened(&state, "a.txt") && opened(&state, "b.txt"), "the batch must land");
}

// ---------------------------------------------------------------------
// The receive path
// ---------------------------------------------------------------------

const BATCH: u8 = 1;
const PER_FILE: u8 = 2;

fn use_open(h: &Harness, mode: u8, max_latency_ms: u64) {
    h.convergence.batch_open_override.store(mode, Ordering::Relaxed);
    h.convergence.completion_max_latency_override_ms.store(max_latency_ms, Ordering::Relaxed);
}

fn spawn_reconcile(
    h: &Harness,
    files: &[String],
) -> tokio::task::JoinHandle<Option<super::ProjectionAttempt>> {
    let (convergence, files) = (h.convergence.clone(), files.to_vec());
    tokio::spawn(async move {
        convergence
            .reconcile_paths_directly(
                &super::receive_window_concurrency_tests::driver(),
                GROUP,
                files.into_iter().collect(),
            )
            .await
            .unwrap()
    })
}

/// Eight files of one run are opened by far fewer transactions than files,
/// and are then written and closed as before; with the knob off each opens by
/// itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_files_of_a_run_open_in_one_transaction() {
    let h = Harness::new(false);
    pin_concurrency(&h, 8);
    use_open(&h, BATCH, 10_000);
    let files = names("o", 8);
    let contents = super::receive_window_concurrency_tests::publish_new_files(&h, &files).await;

    let attempt = reconcile(&h, &files).await;

    for name in &files {
        assert!(attempt.is_settled(name), "{name}: {:?}", attempt.retry);
        assert_eq!(&std::fs::read(h.path(name)).unwrap(), &contents[name]);
    }
    assert_eq!(batch_sizes(&h.state), vec![8], "eight files, one open transaction");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_the_knob_off_every_file_opens_by_itself() {
    let h = Harness::new(false);
    pin_concurrency(&h, 8);
    use_open(&h, PER_FILE, 10_000);
    let files = names("p", 4);
    super::receive_window_concurrency_tests::publish_new_files(&h, &files).await;

    let attempt = reconcile(&h, &files).await;

    assert!(files.iter().all(|name| attempt.is_settled(name)));
    assert!(batch_sizes(&h.state).is_empty(), "no batched open transaction ran");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lone_file_in_a_run_opens_without_waiting() {
    let h = Harness::new(false);
    pin_concurrency(&h, 8);
    use_open(&h, BATCH, 20_000);
    let files = names("l", 1);
    super::receive_window_concurrency_tests::publish_new_files(&h, &files).await;

    let attempt = tokio::time::timeout(Duration::from_secs(10), reconcile(&h, &files))
        .await
        .expect("a lone file waited for a batch");

    assert!(attempt.is_settled(&files[0]));
    assert_eq!(batch_sizes(&h.state), vec![1]);
}

/// One file whose open is refused leaves the state a refused per-file open
/// leaves, and the others of its batch are written.
async fn refused_open_state(mode: u8) -> (BTreeMap<String, String>, Vec<usize>) {
    let h = Harness::new(false);
    pin_concurrency(&h, 4);
    use_open(&h, mode, 10_000);
    let files = names("r", 4);
    super::receive_window_concurrency_tests::publish_new_files(&h, &files).await;
    refuse_late_in_open(&h.state, &files[1]);

    let attempt = reconcile(&h, &files).await;

    assert!(attempt.retry.contains(&files[1]), "{:?}", attempt.retry);
    for name in [&files[0], &files[2], &files[3]] {
        assert!(attempt.is_settled(name), "{name}: {:?}", attempt.retry);
    }
    assert!(!h.state.has_materialization_intent(GROUP, &files[1]).unwrap());
    assert!(std::fs::read(h.path(&files[1])).is_err(), "no byte of the refused file");
    (snapshot(&h, &files), batch_sizes(&h.state))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_open_leaves_the_state_a_refused_per_file_open_leaves() {
    let (per_file_state, per_file_sizes) = refused_open_state(PER_FILE).await;
    let (batched_state, batched_sizes) = refused_open_state(BATCH).await;

    assert!(per_file_sizes.is_empty());
    assert_eq!(batched_sizes, vec![4]);
    assert_eq!(batched_state, per_file_state);
}

/// The gap between a file's queueing its open and the batch's commit: the row
/// has not moved and not a byte is written, so there is nothing a scan could
/// capture; the path lock is held; a user edit made meanwhile is never
/// overwritten and is captured afterwards as an ordinary local edit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_wait_for_the_open_batch_changes_nothing_and_keeps_every_path_locked() {
    let h = Arc::new(Harness::new(false));
    pin_concurrency(&h, 3);
    use_open(&h, BATCH, 30_000);
    let files = names("g", 3);
    let mut ops = Vec::new();
    for (i, name) in files.iter().enumerate() {
        // This device's own version first, then the peer's newer one over it.
        std::fs::write(h.path(name), format!("own version {i}")).unwrap();
        assert!(matches!(
            h.capture(name).await,
            yadorilink_local_capture::LocalChangeOutcome::FileChanged(_)
        ));
        let content = format!("peer's newer version {i}").into_bytes();
        ops.push(put(name, source(&h, &format!("n{i}"), &content).await));
    }
    publish(&h, &ops);
    let own_rows: Vec<_> =
        files.iter().map(|name| h.state.get_file(GROUP, name).unwrap().unwrap().blocks).collect();

    let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let (entered_tx, release_rx) = (Mutex::new(entered_tx), Mutex::new(release_rx));
    *h.state.test_observers.open_batch_gate.lock().unwrap() = Some(Arc::new(move || {
        let _ = entered_tx.lock().unwrap().send(());
        let _ = release_rx.lock().unwrap().recv();
    }));
    let task = spawn_reconcile(&h, &files);
    tokio::task::spawn_blocking(move || {
        entered_rx.recv_timeout(Duration::from_secs(30)).expect("the open batch never committed")
    })
    .await
    .unwrap();

    // In the wait: the disk and the rows are as they were, every lock is held.
    for (i, name) in files.iter().enumerate() {
        assert_eq!(
            std::fs::read(h.path(name)).unwrap(),
            format!("own version {i}").into_bytes(),
            "{name}: a byte was written before its open was decided"
        );
        assert!(!h.state.has_materialization_intent(GROUP, name).unwrap(), "{name}");
        assert_eq!(h.state.get_file(GROUP, name).unwrap().unwrap().blocks, own_rows[i], "{name}");
        assert!(h.state.path_lock(GROUP, name).try_lock().is_err(), "{name}: lock not held");
    }
    // A user edit lands in the wait, and a scan runs: nothing is authored.
    let edited = &files[0];
    std::fs::write(h.path(edited), b"the user's edit in the wait").unwrap();
    let scan_authored: Vec<String> =
        h.scan().into_iter().map(|r| r.path).filter(|p| files.contains(p)).collect();
    assert!(scan_authored.is_empty(), "a scan authored a locked path: {scan_authored:?}");

    release_tx.send(()).unwrap();
    let attempt = task.await.unwrap().expect("the attempt runs");

    assert_eq!(
        std::fs::read(h.path(edited)).unwrap(),
        b"the user's edit in the wait".to_vec(),
        "the user's edit was overwritten"
    );
    assert!(!attempt.is_settled(edited), "the edited file must be left for the next pass");
    for name in &files[1..] {
        assert!(attempt.is_settled(name), "{name}: {:?}", attempt.retry);
    }
    assert!(matches!(
        h.capture(edited).await,
        yadorilink_local_capture::LocalChangeOutcome::FileChanged(_)
    ));
    assert!(files.iter().all(|name| h.state.path_lock(GROUP, name).try_lock().is_ok()));
}

/// A run dropped while its open batch is committing: the batch lands on its
/// own (the job fence holds the files' guards until it has), no byte was
/// written, every lock is free afterwards, and startup repair and the next
/// pass finish every file.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_run_dropped_while_its_open_batch_commits_is_recoverable() {
    let h = Arc::new(Harness::new(false));
    pin_concurrency(&h, 3);
    use_open(&h, BATCH, 30_000);
    let files = names("d", 3);
    let contents = super::receive_window_concurrency_tests::publish_new_files(&h, &files).await;
    let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let (entered_tx, release_rx) = (Mutex::new(entered_tx), Mutex::new(release_rx));
    *h.state.test_observers.open_batch_gate.lock().unwrap() = Some(Arc::new(move || {
        let _ = entered_tx.lock().unwrap().send(());
        let _ = release_rx.lock().unwrap().recv();
    }));
    let task = spawn_reconcile(&h, &files);
    tokio::task::spawn_blocking(move || {
        entered_rx.recv_timeout(Duration::from_secs(30)).expect("the open batch never committed")
    })
    .await
    .unwrap();
    for name in &files {
        assert!(h.state.path_lock(GROUP, name).try_lock().is_err(), "{name}: lock not held");
    }

    let releaser = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        release_tx.send(()).unwrap();
    });
    task.abort();
    let _ = task.await;
    releaser.join().unwrap();
    *h.state.test_observers.open_batch_gate.lock().unwrap() = None;

    assert_eq!(batch_sizes(&h.state), vec![3], "the batch landed on its own");
    for name in &files {
        assert!(opened(&h.state, name), "{name}");
        assert!(std::fs::read(h.path(name)).is_err(), "{name}: bytes after a dropped run");
        assert!(h.state.path_lock(GROUP, name).try_lock().is_ok(), "{name}: the lock leaked");
    }
    let report =
        yadorilink_filesystem_sync::materialization_repair::repair_interrupted_materializations(
            h.state.as_ref(),
            &*h.convergence.store,
            &h.path(""),
            GROUP,
            yadorilink_filesystem_sync::materialization_repair::RepairMode::Startup,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    assert!(report.offline_deleted.is_empty(), "an interrupted open is not an offline delete");
    let attempt = reconcile(&h, &files).await;
    for name in &files {
        assert!(attempt.is_settled(name), "{name}: {:?}", attempt.retry);
        assert_eq!(&std::fs::read(h.path(name)).unwrap(), &contents[name]);
    }
}

/// The same seeded workload (new, changed, deleted, moved and colliding names,
/// one file whose blocks are nowhere) ends in the same state with a batched
/// open and with an open per file, and the batched run opens in fewer
/// transactions than files.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_batched_open_pass_ends_in_the_state_of_a_per_file_open_pass() {
    let (per_file_state, per_file_disk, _, _) = run_workload_full(8, 0, PER_FILE, 0).await;
    let (batched_state, batched_disk, batched_max, _) = run_workload_full(8, 0, BATCH, 0).await;

    assert!(batched_max >= 2, "the workload never overlapped two writes");
    assert_eq!(batched_disk, per_file_disk);
    assert_eq!(batched_state, per_file_state);
}

/// The open batch is committed on the blocking pool like the others, with the
/// knob on or off, to the same end state.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_inline_open_batch_ends_in_the_state_of_an_offloaded_one() {
    let (inline_state, inline_disk, _, _) = run_workload_full(8, 0, BATCH, 2).await;
    let (offloaded_state, offloaded_disk, _, _) = run_workload_full(8, 0, BATCH, 1).await;

    assert_eq!(offloaded_disk, inline_disk);
    assert_eq!(offloaded_state, inline_state);
}

/// The collectors' flush cap is its own knob: with 32 files in flight and a
/// cap of 16, no batch carries more than 16 items and every file completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_flush_cap_is_independent_of_the_write_concurrency() {
    let h = Harness::new(false);
    pin_concurrency(&h, 32);
    h.convergence.collector_flush_cap_override.store(16, Ordering::Relaxed);
    use_open(&h, BATCH, 10_000);
    let files = names("c", 32);
    let contents = super::receive_window_concurrency_tests::publish_new_files(&h, &files).await;

    let attempt = reconcile(&h, &files).await;

    for name in &files {
        assert!(attempt.is_settled(name), "{name}: {:?}", attempt.retry);
        assert_eq!(&std::fs::read(h.path(name)).unwrap(), &contents[name]);
    }
    let sizes = batch_sizes(&h.state);
    assert_eq!(sizes.iter().sum::<usize>(), 32, "{sizes:?}");
    assert!(sizes.iter().all(|&n| n <= 16), "a batch exceeded the cap: {sizes:?}");
}
