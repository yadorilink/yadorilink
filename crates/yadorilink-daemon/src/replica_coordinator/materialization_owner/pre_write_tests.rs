//! The pre-write half of a received content write (`open_content_write`):
//! the intent, the row, the in-flight state, the hold clear and the fence
//! bump either all become durable together, before any disk mutation, or
//! none of them does.

use std::sync::Arc;

use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
use yadorilink_root_authority::root_commit::{RootCommitPermit, RootLease};
use yadorilink_root_authority::sync_root_lock::SyncRootLock;

use crate::replica_coordinator::ReplicaCoordinator;

const GROUP: &str = "group-1";
const PATH: &str = "received.bin";

fn record() -> FileRecord {
    FileRecord {
        path: PATH.to_owned(),
        size: 5,
        mtime_unix_nanos: 1,
        blocks: vec![BlockInfo { hash: vec![0xAB; 32], offset: 0, size: 5 }],
        deleted: false,
    }
}

/// The fence row as stored, without creating one.
fn fence(state: &ReplicaCoordinator) -> Option<i64> {
    use rusqlite::OptionalExtension as _;
    state
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            Ok(conn
                .query_row(
                    "SELECT mutation_generation FROM path_actual_mutation_fences \
                     WHERE group_id = ?1 AND path = ?2",
                    [GROUP, PATH],
                    |r| r.get(0),
                )
                .optional()?)
        })
        .unwrap()
}

/// Nothing of the pre-write transaction is durable.
fn assert_nothing_committed(state: &ReplicaCoordinator, context: &str) {
    assert!(!state.has_materialization_intent(GROUP, PATH).unwrap(), "{context}: no intent");
    assert!(state.get_file(GROUP, PATH).unwrap().is_none(), "{context}: no row");
    assert_eq!(state.get_materialization_state(GROUP, PATH).unwrap(), None, "{context}: no state");
    assert_eq!(fence(state), None, "{context}: the fence was not bumped");
}

/// A root claimed by a lease. [`ClaimedRoot::swap`] then pulls the root's
/// lock out from under it, so every permit taken from that lease, before or
/// after, fails to re-verify.
struct ClaimedRoot {
    lease: Arc<RootLease>,
    dir: tempfile::TempDir,
}

impl ClaimedRoot {
    fn swap(&self) {
        let lock_path = self
            .dir
            .path()
            .join(yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME);
        std::fs::remove_file(&lock_path).unwrap();
        std::fs::File::create(&lock_path).unwrap();
    }
}

fn claimed_root(state: &ReplicaCoordinator) -> ClaimedRoot {
    let dir = tempfile::tempdir().unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(dir.path(), GROUP, state).unwrap();
    let lock = SyncRootLock::acquire(dir.path()).unwrap();
    ClaimedRoot { lease: Arc::new(RootLease::new(lock, GROUP.to_owned(), 0)), dir }
}

fn always_valid_lease() -> Arc<RootLease> {
    Arc::new(RootLease::for_tests())
}

#[tokio::test]
async fn the_pre_write_steps_land_together_and_bump_the_fence_before_any_write() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let record = record();
    let permit = RootCommitPermit::for_tests();
    let lease = always_valid_lease();

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

    // Durable before the lane creates its temp file: what a crash at that
    // point leaves is an interrupted write repair rebuilds, never a row with
    // no file and no intent.
    assert!(state.has_materialization_intent(GROUP, PATH).unwrap());
    assert!(state.get_file(GROUP, PATH).unwrap().is_some_and(|row| !row.deleted));
    assert_eq!(
        state.get_materialization_state(GROUP, PATH).unwrap(),
        Some(yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE)
    );
    assert_eq!(
        fence(&state),
        Some(generation),
        "the fence the proof will CAS on is bumped in the same commit"
    );
    drop(intent);
}

/// The last step, the fence bump, refuses a frozen group. Everything the
/// steps before it wrote must go with it: an intent or a row left behind by
/// a write that never started is state nothing asked for.
#[tokio::test]
async fn a_refused_pre_write_step_leaves_no_intent_row_state_or_fence() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    crate::test_support::freeze_group(&state, GROUP);
    let record = record();
    let permit = RootCommitPermit::for_tests();
    let lease = always_valid_lease();

    let opened = state
        .open_content_write(
            GROUP,
            &record,
            "device-peer",
            None,
            &crate::replica_coordinator::plain_file_columns(),
            &|| Ok(lease.clone()),
            &permit,
        )
        .await;

    assert!(opened.is_err(), "a frozen group refuses the write");
    assert_nothing_committed(&state, "frozen group");
}

/// The lane's own permit is re-verified inside the transaction: a root
/// that stopped being this link's commits nothing.
#[tokio::test]
async fn the_pre_write_transaction_reverifies_the_lane_permit() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = claimed_root(&state);
    let operation = root.lease.begin_operation().unwrap();
    let permit = operation.permit();
    root.swap();
    let record = record();
    let lease = always_valid_lease();

    let opened = state
        .open_content_write(
            GROUP,
            &record,
            "device-peer",
            None,
            &crate::replica_coordinator::plain_file_columns(),
            &|| Ok(lease.clone()),
            &permit,
        )
        .await;

    assert!(opened.is_err(), "a lane permit whose root no longer verifies must be refused");
    assert_nothing_committed(&state, "lane permit");
}

/// The row is committed under a root operation begun for it at the moment
/// of the commit: a link that stopped owning its root after the lane began
/// commits no row, and leaves no intent behind either.
#[tokio::test]
async fn the_pre_write_transaction_reverifies_the_row_authority() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = claimed_root(&state);
    root.swap();
    let record = record();
    let permit = RootCommitPermit::for_tests();

    let opened = state
        .open_content_write(
            GROUP,
            &record,
            "device-peer",
            None,
            &crate::replica_coordinator::plain_file_columns(),
            &|| Ok(root.lease.clone()),
            &permit,
        )
        .await;

    assert!(opened.is_err(), "a row authority whose root no longer verifies must be refused");
    assert_nothing_committed(&state, "row authority");
}
