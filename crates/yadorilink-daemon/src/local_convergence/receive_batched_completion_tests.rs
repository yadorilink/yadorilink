#![cfg(test)]
//! The files of a concurrent run close in batches, and everything a file's
//! own close guaranteed still holds: nothing is reported before its bytes are
//! durable, a refused or failed file leaves its state for the next pass and
//! the others commit, and a local edit made while a file waits for its batch
//! is never authored over, lost, or proven as the received version.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use yadorilink_local_capture::LocalChangeOutcome;
use yadorilink_replica_domain::session_state::MaterializationState;

use super::growing_file_projection_tests::{Harness, GROUP};
use super::receive_window_concurrency_tests::{
    arm, names, pin_concurrency, publish, put, reconcile, run_workload_with, source,
};
use super::{OverlapProbe, ProbeSeam};

const BATCH: u8 = 1;
const PER_FILE: u8 = 2;

fn use_completion(h: &Harness, mode: u8, max_latency_ms: u64) {
    h.convergence.batch_completion_override.store(mode, Ordering::Relaxed);
    h.convergence.completion_max_latency_override_ms.store(max_latency_ms, Ordering::Relaxed);
}

fn batch_sizes(h: &Harness) -> Vec<usize> {
    h.state.test_observers.close_batch_sizes.lock().unwrap().clone()
}

fn proven(h: &Harness, path: &str) -> bool {
    h.state
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            yadorilink_sync_sqlite::materialized_generation::lookup_materialized_generation(
                conn, GROUP, path,
            )
        })
        .unwrap()
        .is_some()
}

fn hydrated(h: &Harness, path: &str) -> bool {
    h.state.get_materialization_state(GROUP, path).unwrap() == Some(MaterializationState::Present)
}

fn intent_open(h: &Harness, path: &str) -> bool {
    h.state.has_materialization_intent(GROUP, path).unwrap()
}

/// Committed as the received version: proof, `Present`, no intent.
fn closed(h: &Harness, path: &str) -> bool {
    proven(h, path) && hydrated(h, path) && !intent_open(h, path)
}

/// Where a crash after the directory sync leaves a file: in flight, the intent
/// open, nothing proven.
fn in_flight(h: &Harness, path: &str) -> bool {
    !proven(h, path)
        && !hydrated(h, path)
        && intent_open(h, path)
        && h.state.get_materialization_state(GROUP, path).unwrap()
            == Some(yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE)
}

fn repair(
    h: &Harness,
) -> yadorilink_filesystem_sync::materialization_repair::MaterializationRepairReport {
    yadorilink_filesystem_sync::materialization_repair::repair_interrupted_materializations(
        h.state.as_ref(),
        &*h.convergence.store,
        &h.path(""),
        GROUP,
        yadorilink_filesystem_sync::materialization_repair::RepairMode::Startup,
        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
    )
    .unwrap()
}

async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let waited = std::time::Instant::now();
    while !done() {
        assert!(waited.elapsed() < Duration::from_secs(30), "{what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn publish_new(h: &Harness, files: &[String]) -> BTreeMap<String, Vec<u8>> {
    super::receive_window_concurrency_tests::publish_new_files(h, files).await
}

/// Eight files of one run are written at the same time and closed by far fewer
/// transactions than files; with the knob off each closes by itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_files_of_a_run_are_closed_in_one_transaction() {
    let h = Harness::new(false);
    pin_concurrency(&h, 8);
    use_completion(&h, BATCH, 10_000);
    let files = names("b", 8);
    let contents = publish_new(&h, &files).await;
    // Every file is renamed into place before any of them reaches its close.
    let probe = OverlapProbe::new(ProbeSeam::BeforeCommit, 8, 10_000);
    arm(&h, &probe);

    let attempt = reconcile(&h, &files).await;

    assert!(probe.max_in_flight() >= 8, "{:?}", probe.events());
    for name in &files {
        assert!(attempt.is_settled(name), "{name}: {:?}", attempt.retry);
        assert_eq!(&std::fs::read(h.path(name)).unwrap(), &contents[name]);
        assert!(closed(&h, name), "{name}");
    }
    assert_eq!(batch_sizes(&h), vec![8], "eight files, one close transaction");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_the_knob_off_every_file_closes_by_itself() {
    let h = Harness::new(false);
    pin_concurrency(&h, 8);
    use_completion(&h, PER_FILE, 10_000);
    let files = names("p", 4);
    publish_new(&h, &files).await;

    let attempt = reconcile(&h, &files).await;

    assert!(files.iter().all(|name| attempt.is_settled(name) && closed(&h, name)));
    assert!(batch_sizes(&h).is_empty(), "no batched transaction ran");
}

/// A lone file never waits for a batch to fill, however long the deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lone_file_in_a_run_closes_without_waiting() {
    let h = Harness::new(false);
    pin_concurrency(&h, 8);
    use_completion(&h, BATCH, 20_000);
    let files = names("l", 1);
    publish_new(&h, &files).await;

    let started = std::time::Instant::now();
    let attempt = tokio::time::timeout(Duration::from_secs(10), reconcile(&h, &files))
        .await
        .expect("a lone file waited for a batch");

    assert!(attempt.is_settled(&files[0]) && closed(&h, &files[0]));
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(batch_sizes(&h), vec![1]);
}

/// One file whose fence moved after its write is refused; the others of its
/// batch commit, and the refused file is left for the next pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_refused_file_leaves_the_others_of_its_batch_committed() {
    let h = Arc::new(Harness::new(false));
    pin_concurrency(&h, 4);
    use_completion(&h, BATCH, 10_000);
    let files = names("r", 4);
    publish_new(&h, &files).await;
    let probe = OverlapProbe::new(ProbeSeam::BeforeCommit, 1, 30_000);
    probe.hold_until_released();
    arm(&h, &probe);
    let task = {
        let (convergence, files) = (h.convergence.clone(), files.clone());
        tokio::spawn(async move {
            convergence
                .reconcile_paths_directly(
                    &super::receive_window_concurrency_tests::driver(),
                    GROUP,
                    files.into_iter().collect(),
                )
                .await
        })
    };
    until("all four writes reached the seam", || probe.in_flight() == 4).await;
    // A capture, or any other mutator, moves one path's fence after its write.
    h.state.dag_bump_mutation_fence(GROUP, &files[1], "local_capture").unwrap();
    probe.release();
    let attempt = task.await.unwrap().unwrap().expect("the attempt runs");

    assert!(attempt.retry.contains(&files[1]), "{:?}", attempt.retry);
    assert!(in_flight(&h, &files[1]), "the refused file keeps its intent and its row in flight");
    for name in [&files[0], &files[2], &files[3]] {
        assert!(attempt.is_settled(name), "{name}");
        assert!(closed(&h, name), "{name}");
    }
    assert_eq!(batch_sizes(&h), vec![4]);
}

/// What the committing task blocks on, with every file of the batch renamed
/// into place and none of them committed.
struct Gate {
    state: Mutex<(bool, bool)>,
    changed: Condvar,
}

impl Gate {
    fn arm(h: &Harness) -> Arc<Self> {
        let gate = Arc::new(Self { state: Mutex::new((false, false)), changed: Condvar::new() });
        let at_gate = gate.clone();
        *h.state.test_observers.close_batch_gate.lock().unwrap() = Some(Arc::new(move || {
            let mut state = at_gate.state.lock().unwrap();
            state.0 = true;
            at_gate.changed.notify_all();
            while !state.1 {
                let (next, timeout) =
                    at_gate.changed.wait_timeout(state, Duration::from_secs(30)).unwrap();
                state = next;
                assert!(!timeout.timed_out(), "the gate was never opened");
            }
        }));
        gate
    }

    fn reached(&self) -> bool {
        self.state.lock().unwrap().0
    }

    fn open(&self) {
        self.state.lock().unwrap().1 = true;
        self.changed.notify_all();
    }
}

/// The gap between a file's rename and its close: the row is in flight over
/// the received bytes, and only the path lock keeps a capture out.
struct Gap {
    release: Box<dyn Fn() + Send>,
}

async fn hold_the_gap(
    h: &Harness,
    mode: u8,
    files: &[String],
) -> (Gap, tokio::task::JoinHandle<Option<super::ProjectionAttempt>>) {
    let release: Box<dyn Fn() + Send>;
    if mode == BATCH {
        let gate = Gate::arm(h);
        release = {
            let gate = gate.clone();
            Box::new(move || gate.open())
        };
        let task = spawn_reconcile(h, files);
        until("the batch reached its transaction", || gate.reached()).await;
        return (Gap { release }, task);
    }
    // One close per file: the seam just before it.
    let probe = OverlapProbe::new(ProbeSeam::BeforeCommit, 1, 30_000);
    probe.hold_until_released();
    arm(h, &probe);
    let task = spawn_reconcile(h, files);
    until("every write reached its close", || probe.in_flight() == files.len()).await;
    release = Box::new(move || probe.release());
    (Gap { release }, task)
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

/// What a gap leaves behind, for comparing the two ways of closing.
#[derive(Debug, PartialEq)]
struct GapOutcome {
    scan_authored: Vec<String>,
    locks_held_in_gap: Vec<bool>,
    settled: Vec<String>,
    edited_capture_after: String,
    local_head_after_edit: bool,
    edited_disk_after: Vec<u8>,
    others_capture_after: Vec<String>,
}

async fn run_the_gap(mode: u8) -> GapOutcome {
    let h = Arc::new(Harness::new(false));
    pin_concurrency(&h, 3);
    use_completion(&h, mode, 30_000);
    let files = names("g", 3);
    let mut ops = Vec::new();
    for (i, name) in files.iter().enumerate() {
        // This device's own version first, then the peer's newer one over it,
        // so an authored scan would be authoring over a newer version.
        std::fs::write(h.path(name), format!("own version {i}")).unwrap();
        assert!(matches!(h.capture(name).await, LocalChangeOutcome::FileChanged(_)));
        let content = format!("peer's newer version {i}").into_bytes();
        ops.push(put(name, source(&h, &format!("n{i}"), &content).await));
    }
    publish(&h, &ops);

    let (gap, task) = hold_the_gap(&h, mode, &files).await;

    // Every file holds the received bytes on disk and nothing is committed.
    for (i, name) in files.iter().enumerate() {
        assert_eq!(
            std::fs::read(h.path(name)).unwrap(),
            format!("peer's newer version {i}").into_bytes()
        );
        assert!(in_flight(&h, name), "{name} is committed before its close");
    }
    let locks_held_in_gap: Vec<bool> =
        files.iter().map(|name| h.state.path_lock(GROUP, name).try_lock().is_err()).collect();
    // A user edit lands in the gap, and a scan runs.
    let edited = &files[0];
    std::fs::write(h.path(edited), b"the user's edit in the gap").unwrap();
    let scan_authored: Vec<String> =
        h.scan().into_iter().map(|r| r.path).filter(|p| files.contains(p)).collect();
    (gap.release)();
    let attempt = task.await.unwrap().expect("the attempt runs");
    let settled: Vec<String> = files.iter().filter(|n| attempt.is_settled(n)).cloned().collect();

    // The edit is still on disk and is captured as an ordinary local edit.
    let edited_capture_after = format!("{:?}", std::mem::discriminant(&h.capture(edited).await));
    h.redrive().await;
    let local_head_after_edit = h
        .native_heads(edited)
        .iter()
        .any(|head| head.dot.author.device.0 == super::growing_file_projection_tests::LOCAL_DEVICE);
    let mut others_capture_after = Vec::new();
    for name in &files[1..] {
        others_capture_after.push(format!("{:?}", h.capture(name).await));
        assert_eq!(h.native_heads(name).len(), 1, "{name}: no local head beside the peer's");
    }
    let free: Vec<bool> =
        files.iter().map(|name| h.state.path_lock(GROUP, name).try_lock().is_ok()).collect();
    assert!(free.iter().all(|free| *free), "a path lock outlived the pass");
    GapOutcome {
        scan_authored,
        locks_held_in_gap,
        settled,
        edited_capture_after,
        local_head_after_edit,
        edited_disk_after: std::fs::read(h.path(edited)).unwrap(),
        others_capture_after,
    }
}

/// The lock a file took before it wrote is held until its close has been
/// committed: a scan in the gap authors nothing, and a local edit made in the
/// gap is captured afterwards as a normal edit, exactly as with a close per
/// file.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_scan_and_a_local_edit_in_the_gap_before_the_batch_commit_are_handled_as_before() {
    let per_file = run_the_gap(PER_FILE).await;
    let batched = run_the_gap(BATCH).await;

    assert!(batched.locks_held_in_gap.iter().all(|held| *held), "{batched:?}");
    assert!(batched.scan_authored.is_empty(), "a scan authored a path in the gap: {batched:?}");
    assert_eq!(batched.edited_disk_after, b"the user's edit in the gap".to_vec());
    assert!(batched.local_head_after_edit, "the edit was never authored: {batched:?}");
    // The one difference: the file edited in the gap is not settled by the batch,
    // which re-checks the disk when it commits; closing per file has no gap to
    // re-check and settles it. Everything else is the same.
    assert_eq!(batched.settled, vec!["g01.txt".to_string(), "g02.txt".to_string()]);
    assert_eq!(
        GapOutcome { settled: Vec::new(), ..batched },
        GapOutcome { settled: Vec::new(), ..per_file }
    );
}

/// A run dropped while its files are queued: nothing of them is committed,
/// each file is where a crash after its directory sync leaves it, and the
/// locks are free for the next pass, which finishes every file.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_run_dropped_with_files_queued_commits_none_of_them_and_is_recoverable() {
    let h = Arc::new(Harness::new(false));
    pin_concurrency(&h, 3);
    use_completion(&h, BATCH, 60_000);
    let files = names("d", 3);
    let contents = publish_new(&h, &files).await;
    // The third file never reaches its close, so the other two wait for it.
    *h.convergence.completion_straggler.lock().unwrap() = Some(files[2].clone());
    let task = spawn_reconcile(&h, &files);
    until("two files renamed and queued", || {
        files[..2]
            .iter()
            .all(|name| std::fs::read(h.path(name)).ok().as_ref() == Some(&contents[name]))
    })
    .await;
    // Let them reach the queue.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(batch_sizes(&h).is_empty(), "nothing may commit while a sibling can still arrive");
    for name in &files[..2] {
        assert!(h.state.path_lock(GROUP, name).try_lock().is_err(), "{name} lost its lock early");
    }

    task.abort();
    let _ = task.await;

    assert!(batch_sizes(&h).is_empty(), "a dropped run committed something");
    for name in &files[..2] {
        assert!(in_flight(&h, name), "{name}");
        assert!(h.state.path_lock(GROUP, name).try_lock().is_ok(), "{name}: the lock leaked");
    }
    *h.convergence.completion_straggler.lock().unwrap() = None;
    // Startup repair finishes the interrupted writes, then the next pass.
    let report = repair(&h);
    assert!(report.reconstructed.is_empty(), "the bytes already match: nothing to rebuild");
    assert!(report.offline_deleted.is_empty(), "an interrupted write is not an offline delete");
    let attempt = reconcile(&h, &files).await;
    for name in &files {
        assert!(attempt.is_settled(name), "{name}: {:?}", attempt.retry);
        assert!(closed(&h, name), "{name}");
        assert_eq!(&std::fs::read(h.path(name)).unwrap(), &contents[name]);
    }
}

/// The end state of a generated workload (new, changed, deleted, moved and
/// colliding names, and one file whose blocks are nowhere) is the same with a
/// close per file and with batched closes, and the batched run closes its
/// files in fewer transactions than files.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_batched_pass_ends_in_the_state_of_a_per_file_pass() {
    let (serial_state, serial_disk, _, serial_sizes) = run_workload_with(1, PER_FILE).await;
    let (per_file_state, per_file_disk, _, per_file_sizes) = run_workload_with(8, PER_FILE).await;
    let (batched_state, batched_disk, batched_max, batched_sizes) =
        run_workload_with(8, BATCH).await;

    assert!(serial_sizes.is_empty() && per_file_sizes.is_empty());
    assert!(batched_max >= 2, "the workload never overlapped two writes");
    assert_eq!(batched_disk, per_file_disk);
    assert_eq!(batched_state, per_file_state);
    assert_eq!(batched_disk, serial_disk);
    assert_eq!(batched_state, serial_state);
    let closed_in_batches: usize = batched_sizes.iter().sum();
    assert!(closed_in_batches > 0, "nothing was closed in a batch");
    assert!(
        batched_sizes.len() < closed_in_batches,
        "{closed_in_batches} files closed in {} transactions",
        batched_sizes.len()
    );
}

/// Three files renamed into place, peer version newer than this device's own;
/// the batch is held just before its transaction.
async fn held_batch(
) -> (Arc<Harness>, Vec<String>, Gap, tokio::task::JoinHandle<Option<super::ProjectionAttempt>>) {
    let h = Arc::new(Harness::new(false));
    pin_concurrency(&h, 3);
    use_completion(&h, BATCH, 30_000);
    let files = names("e", 3);
    let mut ops = Vec::new();
    for (i, name) in files.iter().enumerate() {
        std::fs::write(h.path(name), format!("own version {i}")).unwrap();
        assert!(matches!(h.capture(name).await, LocalChangeOutcome::FileChanged(_)));
        let content = format!("peer's newer version {i}").into_bytes();
        ops.push(put(name, source(&h, &format!("n{i}"), &content).await));
    }
    publish(&h, &ops);
    let (gap, task) = hold_the_gap(&h, BATCH, &files).await;
    (h, files, gap, task)
}

/// A user writes the file directly (no lock needed) while it waits for its
/// batch. Nothing may then be proven for the received bytes: the committed
/// state must say the file is not exact, and the edit must survive to be
/// authored.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_direct_edit_while_a_file_waits_for_its_batch_is_not_proven_as_the_received_version() {
    let (h, files, gap, task) = held_batch().await;
    let edited = &files[0];
    std::fs::write(h.path(edited), b"V3 written straight to the disk").unwrap();
    (gap.release)();
    let attempt = task.await.unwrap().expect("the attempt runs");

    // Inspected before any capture or redrive.
    assert!(!hydrated(&h, edited), "Hydrated although the disk holds the user's bytes");
    assert!(!proven(&h, edited), "an exact proof for bytes that are not on disk");
    assert!(intent_open(&h, edited), "the intent must stay open");
    assert!(attempt.retry.contains(edited), "the file must stay retryable: {:?}", attempt.retry);
    for name in &files[1..] {
        assert!(attempt.is_settled(name) && closed(&h, name), "{name}");
    }
    assert_eq!(std::fs::read(h.path(edited)).unwrap(), b"V3 written straight to the disk");

    // The edit is authored as a local edit afterwards, never lost.
    h.redrive().await;
    let _ = h.capture(edited).await;
    h.redrive().await;
    assert!(
        h.native_heads(edited)
            .iter()
            .any(|head| head.dot.author.device.0
                == super::growing_file_projection_tests::LOCAL_DEVICE),
        "the user's edit was never authored"
    );
    assert_eq!(std::fs::read(h.path(edited)).unwrap(), b"V3 written straight to the disk");
}

/// An edit after the batch committed is an ordinary local edit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_edit_after_the_batch_commit_is_captured_normally() {
    let (h, files, gap, task) = held_batch().await;
    (gap.release)();
    let attempt = task.await.unwrap().expect("the attempt runs");
    assert!(files.iter().all(|n| attempt.is_settled(n) && closed(&h, n)));

    let edited = &files[0];
    std::fs::write(h.path(edited), b"edit after the commit").unwrap();
    assert!(matches!(h.capture(edited).await, LocalChangeOutcome::FileChanged(_)));
    assert_eq!(std::fs::read(h.path(edited)).unwrap(), b"edit after the commit");
    for name in &files[1..] {
        assert!(matches!(h.capture(name).await, LocalChangeOutcome::None), "{name}");
    }
}

/// The user overwrites the file after the exact verification and before the
/// file is queued (the seam between them): the identity the verification
/// vouched for no longer matches, so the batch must refuse the file.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_overwrite_between_the_verification_and_the_queue_is_not_proven() {
    let h = Arc::new(Harness::new(false));
    pin_concurrency(&h, 3);
    use_completion(&h, BATCH, 30_000);
    let files = names("v", 3);
    publish_new(&h, &files).await;
    let probe = OverlapProbe::new(ProbeSeam::BeforeCommit, 1, 30_000);
    probe.hold_until_released();
    arm(&h, &probe);
    let task = spawn_reconcile(&h, &files);
    until("every write reached the seam", || probe.in_flight() == 3).await;
    let edited = &files[0];
    std::fs::write(h.path(edited), b"overwritten after the verification").unwrap();
    probe.release();
    let attempt = task.await.unwrap().expect("the attempt runs");

    assert!(!hydrated(&h, edited) && !proven(&h, edited), "proven for bytes that are not on disk");
    assert!(intent_open(&h, edited));
    assert!(attempt.retry.contains(edited), "{:?}", attempt.retry);
    for name in &files[1..] {
        assert!(attempt.is_settled(name) && closed(&h, name), "{name}");
    }
}

/// The user deletes the received file after its bytes were placed and before
/// its batch committed. The close refuses the file (the disk is no longer the
/// verified object), and the watcher's removal event is only processed once
/// the path lock is released. That delete must still be indexed, and the
/// file must not come back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delete_while_a_file_waits_for_its_batch_is_indexed_and_the_file_stays_gone() {
    let (h, files, gap, task) = held_batch().await;
    let deleted = &files[0];
    std::fs::remove_file(h.path(deleted)).unwrap();
    (gap.release)();
    let attempt = task.await.unwrap().expect("the attempt runs");
    for name in &files[1..] {
        assert!(attempt.is_settled(name) && closed(&h, name), "{name}");
    }
    assert!(
        attempt.is_settled(deleted) && !attempt.retry.contains(deleted),
        "the received write was completed, so nothing is left to retry (and write back)"
    );

    let outcome = h.observe_removal(deleted).await;
    h.redrive().await;

    assert!(
        h.state.get_file(GROUP, deleted).unwrap().is_some_and(|row| row.deleted),
        "the user's delete was dropped ({outcome:?}): the index still holds the file live \
         although it is gone from disk"
    );
    assert!(
        h.native_heads(deleted).is_empty(),
        "the delete reached the legacy index only: the received version is still a live head"
    );
    assert!(!h.path(deleted).exists(), "the deleted file came back");
}
