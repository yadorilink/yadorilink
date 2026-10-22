#![cfg(test)]
//! The completion window on its own: when it flushes, what one item's
//! failure does to the others, and what it never commits.
//!
//! Rows are opened with the real pre-write transaction and closed through the
//! real window and batch transaction; only the files' tasks are stood in for
//! by the test.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use yadorilink_replica_domain::file::{BlockInfo, FileRecord, RecordKind};
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_root_authority::root_commit::{OwnedPermitCheck, RootCommitPermit, RootLease};
use yadorilink_root_authority::sync_root_lock::SyncRootLock;
use yadorilink_sync_sqlite::exact_materialized_commit::ExactMaterializedState;

use super::completion_window::CompletionWindow;
use crate::replica_coordinator::{ContentWriteClose, ContentWriteCloseItem, ReplicaCoordinator};

pub(super) const GROUP: &str = "window-group";

/// A row opened for a content write, as the lane leaves it before the bytes
/// are written: in flight, intent open, fence bumped.
pub(super) struct Opened {
    path: String,
    generation: i64,
    version: VersionHash,
}

pub(super) async fn open_row(state: &ReplicaCoordinator, path: &str, seed: u8) -> Opened {
    let record = FileRecord {
        path: path.to_owned(),
        size: 5,
        mtime_unix_nanos: 1,
        blocks: vec![BlockInfo { hash: vec![seed; 32], offset: 0, size: 5 }],
        deleted: false,
    };
    let permit = RootCommitPermit::for_tests();
    let lease = Arc::new(RootLease::for_tests());
    let (generation, intent) = state
        .open_content_write(
            GROUP,
            &record,
            "device-peer",
            None,
            &crate::replica_coordinator::plain_file_columns(),
            &|| Ok(lease.clone()),
            &permit,
        )
        .await
        .unwrap();
    drop(intent);
    let version = state
        .file_index_repository()
        .canonical_current_row(GROUP, path)
        .unwrap()
        .expect("the row was just opened")
        .version_hash();
    Opened { path: path.to_owned(), generation, version }
}

pub(super) fn item(opened: &Opened, root_check: OwnedPermitCheck) -> ContentWriteCloseItem {
    ContentWriteCloseItem {
        group_id: GROUP.to_owned(),
        path: opened.path.clone(),
        exact_state: ExactMaterializedState::Object {
            kind: RecordKind::File,
            version: opened.version,
            identity: Box::new(None),
        },
        expected_mutation_generation: opened.generation,
        expected_version: opened.version,
        claim: None,
        root_check,
        disk_check: Box::new(|| true),
        intent: yadorilink_sync_sqlite::IntentDisposition::Clear,
    }
}

pub(super) fn valid_check() -> OwnedPermitCheck {
    RootCommitPermit::for_tests().owned_check()
}

fn proven(state: &ReplicaCoordinator, path: &str) -> bool {
    state
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            yadorilink_sync_sqlite::materialized_generation::lookup_materialized_generation(
                conn, GROUP, path,
            )
        })
        .unwrap()
        .is_some()
}

fn hydrated(state: &ReplicaCoordinator, path: &str) -> bool {
    state.get_materialization_state(GROUP, path).unwrap() == Some(MaterializationState::Present)
}

fn intent_open(state: &ReplicaCoordinator, path: &str) -> bool {
    state.has_materialization_intent(GROUP, path).unwrap()
}

pub(super) fn committed(state: &ReplicaCoordinator, path: &str) -> bool {
    proven(state, path) && hydrated(state, path) && !intent_open(state, path)
}

/// Nothing of the close landed: in flight, intent open, no proof.
pub(super) fn untouched(state: &ReplicaCoordinator, path: &str) -> bool {
    !proven(state, path)
        && !hydrated(state, path)
        && intent_open(state, path)
        && state.get_materialization_state(GROUP, path).unwrap()
            == Some(yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE)
}

fn batch_sizes(state: &ReplicaCoordinator) -> Vec<usize> {
    state.test_observers.close_batch_sizes.lock().unwrap().clone()
}

pub(super) fn published() -> ContentWriteClose {
    ContentWriteClose::Published { obligation: None }
}

#[tokio::test]
async fn a_lone_file_commits_at_once_however_long_the_deadline() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let a = open_row(&state, "a.txt", 1).await;
    let window = CompletionWindow::new(8, Duration::from_secs(10));
    let _participant = window.join();

    let started = Instant::now();
    let outcome = tokio::time::timeout(
        Duration::from_secs(3),
        window.submit(&state, item(&a, valid_check())),
    )
    .await
    .expect("a lone file must not wait for a batch to fill")
    .unwrap();

    assert_eq!(outcome, published());
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(committed(&state, "a.txt"));
    assert_eq!(batch_sizes(&state), vec![1]);
}

#[tokio::test]
async fn a_queued_item_is_committed_at_the_deadline_while_a_sibling_is_still_running() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let a = open_row(&state, "a.txt", 1).await;
    let window = CompletionWindow::new(8, Duration::from_millis(150));
    let _a = window.join();
    // A sibling that is still writing and never queues here.
    let _straggler = window.join();

    let started = Instant::now();
    let outcome = tokio::time::timeout(
        Duration::from_secs(5),
        window.submit(&state, item(&a, valid_check())),
    )
    .await
    .expect("the deadline must flush the queue")
    .unwrap();

    assert_eq!(outcome, published());
    assert!(
        started.elapsed() >= Duration::from_millis(120),
        "committed before the deadline although a sibling could still arrive: {:?}",
        started.elapsed()
    );
    assert_eq!(batch_sizes(&state), vec![1]);
}

#[tokio::test]
async fn a_full_queue_is_committed_without_waiting_for_the_deadline() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let (a, b) = (open_row(&state, "a.txt", 1).await, open_row(&state, "b.txt", 2).await);
    let window = CompletionWindow::new(2, Duration::from_secs(10));
    let (_a, _b, _straggler) = (window.join(), window.join(), window.join());

    let (ra, rb) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(
            window.submit(&state, item(&a, valid_check())),
            window.submit(&state, item(&b, valid_check()))
        )
    })
    .await
    .expect("a queue as long as the window's limit must flush");

    assert_eq!((ra.unwrap(), rb.unwrap()), (published(), published()));
    assert_eq!(batch_sizes(&state), vec![2]);
}

#[tokio::test]
async fn a_sibling_that_finishes_without_queueing_releases_the_queue() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let a = open_row(&state, "a.txt", 1).await;
    let window = CompletionWindow::new(8, Duration::from_secs(10));
    let _a = window.join();
    let sibling = window.join();

    let (outcome, ()) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(window.submit(&state, item(&a, valid_check())), async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(sibling);
        })
    })
    .await
    .expect("the sibling leaving must let the queue flush");

    assert_eq!(outcome.unwrap(), published());
}

/// One item's refusal is that item's outcome; the rest of the batch commits.
#[tokio::test]
async fn an_item_whose_fence_moved_is_refused_and_the_others_commit() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let (a, b, c) = (
        open_row(&state, "a.txt", 1).await,
        open_row(&state, "b.txt", 2).await,
        open_row(&state, "c.txt", 3).await,
    );
    // A mutator moved b's fence after its write.
    state.dag_bump_mutation_fence(GROUP, "b.txt", "local_capture").unwrap();
    let window = CompletionWindow::new(3, Duration::from_secs(10));
    let (_a, _b, _c) = (window.join(), window.join(), window.join());

    let (ra, rb, rc) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(
            window.submit(&state, item(&a, valid_check())),
            window.submit(&state, item(&b, valid_check())),
            window.submit(&state, item(&c, valid_check()))
        )
    })
    .await
    .unwrap();

    assert_eq!(ra.unwrap(), published());
    assert_eq!(rb.unwrap(), ContentWriteClose::Refused);
    assert_eq!(rc.unwrap(), published());
    assert!(committed(&state, "a.txt") && committed(&state, "c.txt"));
    assert!(untouched(&state, "b.txt"), "a refused item leaves its row and intent as they were");
    assert_eq!(batch_sizes(&state), vec![3], "one transaction for all three");
}

struct ClaimedRoot {
    lease: Arc<RootLease>,
    dir: tempfile::TempDir,
}

fn claimed_root(state: &ReplicaCoordinator) -> ClaimedRoot {
    let dir = tempfile::tempdir().unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(dir.path(), GROUP, state).unwrap();
    let lock = SyncRootLock::acquire(dir.path()).unwrap();
    ClaimedRoot { lease: Arc::new(RootLease::new(lock, GROUP.to_owned(), 0)), dir }
}

/// Each item is checked against its own root permit, inside the batch
/// transaction. A root that is no longer this link's fails the whole
/// transaction, even for an item whose own check came first and passed: none
/// of the batch may commit for a root that is not owned any more.
#[tokio::test]
async fn a_root_lost_between_two_items_checks_fails_the_whole_batch() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    // Before any row exists: opening a root checks the files the group knows.
    let root = claimed_root(&state);
    let (a, b) = (open_row(&state, "a.txt", 1).await, open_row(&state, "b.txt", 2).await);
    let operation = root.lease.begin_operation().unwrap();
    let doomed = operation.permit().owned_check();
    // The root is replaced under the file that holds this permit.
    let lock_path =
        root.dir.path().join(yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME);
    std::fs::remove_file(&lock_path).unwrap();
    std::fs::File::create(&lock_path).unwrap();
    let window = CompletionWindow::new(2, Duration::from_secs(10));
    let (_a, _b) = (window.join(), window.join());

    // a's check comes first and passes; b's fails.
    let (ra, rb) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(
            window.submit(&state, item(&a, valid_check())),
            window.submit(&state, item(&b, doomed))
        )
    })
    .await
    .unwrap();

    assert!(ra.is_err() && rb.is_err(), "every waiter gets the error");
    assert!(untouched(&state, "a.txt"), "a committed for a root that is no longer owned");
    assert!(untouched(&state, "b.txt"));
}

/// The root check runs for an item whose own statements fail too: a root lost
/// under it fails the whole batch, and the item before it does not commit.
#[tokio::test]
async fn a_root_lost_under_an_item_whose_statements_fail_still_fails_the_whole_batch() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root = claimed_root(&state);
    let (a, b) = (open_row(&state, "a.txt", 1).await, open_row(&state, "b.txt", 2).await);
    let operation = root.lease.begin_operation().unwrap();
    let doomed = operation.permit().owned_check();
    let lock_path =
        root.dir.path().join(yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME);
    std::fs::remove_file(&lock_path).unwrap();
    std::fs::File::create(&lock_path).unwrap();
    // b's close statements fail (its intent cannot be cleared).
    state
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER poison_b BEFORE DELETE ON materialization_intents \
                 WHEN OLD.path = 'b.txt' BEGIN SELECT RAISE(ABORT, 'poisoned'); END;",
            )?;
            Ok(())
        })
        .unwrap();
    let window = CompletionWindow::new(2, Duration::from_secs(10));
    let (_a, _b) = (window.join(), window.join());

    let (ra, rb) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(
            window.submit(&state, item(&a, valid_check())),
            window.submit(&state, item(&b, doomed))
        )
    })
    .await
    .unwrap();

    assert!(ra.is_err() && rb.is_err(), "every waiter gets the error");
    assert!(untouched(&state, "a.txt"), "a committed although the root was lost");
}

/// A waiter that is gone has released its path lock with the rest of its
/// guards: committing its item would prove bytes nothing protects any more.
#[tokio::test]
async fn an_item_whose_waiter_was_dropped_is_not_committed_by_a_survivor() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let (a, b) = (open_row(&state, "a.txt", 1).await, open_row(&state, "b.txt", 2).await);
    let window = CompletionWindow::new(8, Duration::from_secs(10));
    let participant_a = window.join();
    let _b = window.join();
    // a's file queues, and its task is dropped before anything flushes.
    let dropped = tokio::time::timeout(
        Duration::from_millis(60),
        window.submit(&state, item(&a, valid_check())),
    )
    .await;
    assert!(dropped.is_err(), "a is still waiting for b when it is dropped");
    drop(participant_a);
    assert!(batch_sizes(&state).is_empty(), "nothing was flushed yet");

    let outcome = tokio::time::timeout(
        Duration::from_secs(3),
        window.submit(&state, item(&b, valid_check())),
    )
    .await
    .unwrap();

    assert_eq!(outcome.unwrap(), published());
    assert!(committed(&state, "b.txt"));
    assert!(
        untouched(&state, "a.txt"),
        "the dropped waiter's item was committed without its file holding anything"
    );
    assert_eq!(batch_sizes(&state), vec![1]);
}

/// The whole window dropped with items queued: nothing of them commits, and
/// every file is where a crash after its directory sync leaves it.
#[tokio::test]
async fn items_queued_when_the_window_is_dropped_stay_uncommitted() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let (a, b) = (open_row(&state, "a.txt", 1).await, open_row(&state, "b.txt", 2).await);
    let window = CompletionWindow::new(8, Duration::from_secs(10));
    let (_a, _b, _straggler) = (window.join(), window.join(), window.join());

    let both = tokio::time::timeout(Duration::from_millis(80), async {
        tokio::join!(
            window.submit(&state, item(&a, valid_check())),
            window.submit(&state, item(&b, valid_check()))
        )
    })
    .await;
    assert!(both.is_err(), "the straggler keeps the queue waiting");

    assert!(untouched(&state, "a.txt") && untouched(&state, "b.txt"));
    assert!(batch_sizes(&state).is_empty());
}

/// The transaction fails after every item was written and before it commits,
/// as a crash in its middle would: all of it goes, every file gets an error,
/// and each is left re-drivable.
#[tokio::test]
async fn a_transaction_that_fails_before_it_commits_leaves_every_item_as_it_was() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let (a, b) = (open_row(&state, "a.txt", 1).await, open_row(&state, "b.txt", 2).await);
    state.test_observers.close_batch_fails_before_commit.store(true, Ordering::SeqCst);
    let window = CompletionWindow::new(2, Duration::from_secs(10));
    let (_a, _b) = (window.join(), window.join());

    let (ra, rb) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(
            window.submit(&state, item(&a, valid_check())),
            window.submit(&state, item(&b, valid_check()))
        )
    })
    .await
    .unwrap();

    assert!(ra.is_err() && rb.is_err());
    assert!(untouched(&state, "a.txt") && untouched(&state, "b.txt"));
}

/// An identity that cannot show an in-place rewrite (no change-time token)
/// proves nothing about the bytes: they are compared, and only then.
#[test]
fn an_identity_that_cannot_see_a_rewrite_defers_to_the_bytes() {
    use super::completion_window::verified_bytes_still_on_disk as holds;
    // Same length, mtime restored: the identity is equal, the bytes are not.
    assert!(!holds(true, false, || false));
    assert!(holds(true, false, || true));
    // A visible rewrite needs no byte comparison, and a changed identity
    // never holds.
    assert!(holds(true, true, || panic!("bytes read although the identity shows rewrites")));
    assert!(!holds(false, true, || true));
    assert!(!holds(false, false, || true));
}
