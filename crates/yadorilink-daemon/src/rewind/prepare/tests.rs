use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::file::BlockInfo;
use yadorilink_replica_domain::rewind::{RewindFailureKind, RewindRun, RewindRunState};

use super::super::{preview_rewind, RewindExecuteRequest};
use super::{prepare_rewind, RewindPrepareError};
use crate::change_policy::{GroupPolicyState, WriterRole};
use crate::daemon_state::DaemonState;
use crate::replica_coordinator::ReplicaCoordinator;

const GROUP: &str = "group-rewind";
const ME: &str = "device-a";
const TARGET: i64 = 500;

fn block_of(bytes: &[u8]) -> BlockInfo {
    BlockInfo { hash: Sha256::digest(bytes).to_vec(), offset: 0, size: bytes.len() as u32 }
}

/// Writes `path`'s new `current` row (superseding the previous one) whose
/// content is `blocks`, admitted at `at`, with one live head holding that
/// content: the namespace the row shows, settled.
fn write_current(state: &DaemonState, path: &str, seq: i64, blocks: &[BlockInfo], at: i64) {
    write_current_row(state, path, seq, blocks, at);
    let version = state
        .replica_coordinator
        .file_index_repository()
        .get_version(GROUP, path, seq)
        .unwrap()
        .unwrap()
        .version_hash;
    let database = state.replica_coordinator.database();
    let conn = database.pool_for_test().get().unwrap();
    conn.execute("DELETE FROM native_heads WHERE group_id = ?1 AND path = ?2", [GROUP, path])
        .unwrap();
    conn.execute(
        "INSERT INTO native_heads (group_id, path, author, incarnation, seq, version, provenance) \
         VALUES (?1, ?2, 'device-peer', ?3, ?4, ?5, ?6)",
        rusqlite::params![
            GROUP,
            path,
            [0u8; 16].as_slice(),
            seq,
            version.0.as_slice(),
            [0u8; 32].as_slice()
        ],
    )
    .unwrap();
}

/// [`write_current`] without the head: a row the namespace does not back.
fn write_current_row(state: &DaemonState, path: &str, seq: i64, blocks: &[BlockInfo], at: i64) {
    let size: u64 = blocks.iter().map(|b| b.size as u64).sum();
    let database = state.replica_coordinator.database();
    let conn = database.pool_for_test().get().unwrap();
    conn.execute(
        "UPDATE files SET state = 'superseded' \
         WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
        rusqlite::params![GROUP, path],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO files (group_id, path, version_seq, state, deleted, size, \
                            mtime_unix_nanos, blocks_json, admitted_at_unix_nanos) \
         VALUES (?1, ?2, ?3, 'current', 0, ?4, 0, ?5, ?6)",
        rusqlite::params![
            GROUP,
            path,
            seq,
            size as i64,
            serde_json::to_string(blocks).unwrap(),
            at
        ],
    )
    .unwrap();
}

fn store_locally(state: &DaemonState, bytes: &[u8]) {
    let block = block_of(bytes);
    state.block_store.put(bytes).unwrap();
    state.replica_coordinator.record_block_provenance(GROUP, &[block.hash]).unwrap();
}

/// What a mutation would touch: every `files` row and every native head.
fn namespace_snapshot(state: &DaemonState) -> (Vec<(String, i64, String, i64)>, i64) {
    let database = state.replica_coordinator.database();
    let conn = database.pool_for_test().get().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT path, version_seq, state, deleted FROM files WHERE group_id = ?1 \
             ORDER BY path, version_seq",
        )
        .unwrap();
    let rows = stmt
        .query_map([GROUP], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let heads: i64 = conn.query_row("SELECT count(*) FROM native_heads", [], |r| r.get(0)).unwrap();
    (rows, heads)
}

/// A linked group of which this device is a writer, alongside `others`.
/// `doc.txt` held "old" at T and holds "new" now: one Replace, whose
/// historical content is the block of "old".
fn linked_state(others: &[&str]) -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let state = DaemonState::build(
        ME.into(),
        Arc::new(ReplicaCoordinator::open_in_memory().unwrap()),
        store,
    );
    // The free-space check reads the real volume: pin the reserve so a full host disk does not
    // refuse every preparation. `a_low_free_space_reading_refuses_before_a_run_is_recorded`
    // pins the opposite.
    state.block_store.set_headroom_override_bytes(Some(0));
    write_current(&state, "doc.txt", 1, &[block_of(b"old")], 100);
    write_current(&state, "doc.txt", 2, &[block_of(b"new")], 900);
    state.replica_coordinator.link_repository().add_link("/rewind/root", GROUP).unwrap();
    let mut members = vec![(ME, WriterRole::Editor)];
    members.extend(others.iter().map(|other| (*other, WriterRole::Editor)));
    state
        .authority
        .install_test_group_policy(GROUP, GroupPolicyState::with_members_for_tests(&members));
    state
}

async fn approved(state: &Arc<DaemonState>) -> RewindExecuteRequest {
    let preview = preview_rewind(state.clone(), GROUP.into(), TARGET, false).await.unwrap();
    assert_eq!(preview.counts.replace, 1, "fixture: one path to restore");
    RewindExecuteRequest {
        group_id: GROUP.into(),
        target_unix_nanos: TARGET,
        plan_id: preview.plan_id,
    }
}

fn run(state: &DaemonState, run_id: &str) -> RewindRun {
    state.replica_coordinator.rewind_run_repository().get_run(run_id).unwrap().unwrap()
}

fn latest(state: &DaemonState) -> Option<RewindRun> {
    state.replica_coordinator.rewind_run_repository().latest_run(GROUP).unwrap()
}

#[tokio::test]
async fn a_low_free_space_reading_refuses_before_a_run_is_recorded() {
    let state = linked_state(&[]);
    let request = approved(&state).await;
    // A reserve no volume can satisfy stands for a genuinely low free-space reading.
    state.block_store.set_headroom_override_bytes(Some(u64::MAX / 2));

    let refused = prepare_rewind(state.clone(), request).await.err();

    assert!(
        matches!(refused, Some(RewindPrepareError::InsufficientSpace { .. })),
        "got {refused:?}"
    );
    assert!(latest(&state).is_none(), "nothing is recorded for a refused preparation");
}

#[tokio::test]
async fn content_already_held_is_prefetched_and_nothing_changes() {
    let state = linked_state(&[]);
    store_locally(&state, b"old");
    let request = approved(&state).await;
    let before = namespace_snapshot(&state);

    let prepared = prepare_rewind(state.clone(), request.clone()).await.unwrap();

    assert_eq!(prepared.plan().plan_id(), request.plan_id, "acts on the approved plan");
    assert_eq!(run(&state, prepared.run_id()).state, RewindRunState::Prefetched);
    assert_eq!(namespace_snapshot(&state), before, "preparation changes nothing");
    assert!(state.replica_coordinator.retention_paused(GROUP), "the plan's rows are held");
    assert!(state.is_write_safe_point(), "no write activity is held while prepared");

    // Dropped without being executed: settled as interrupted, pause released.
    let run_id = prepared.run_id().to_string();
    drop(prepared);
    let ended = run(&state, &run_id);
    assert_eq!(ended.state, RewindRunState::Failed);
    assert_eq!(ended.failure_kind, Some(RewindFailureKind::Interrupted));
    assert!(!state.replica_coordinator.retention_paused(GROUP), "the pause is released on drop");
}

/// The only device that could hold the content is this one, and it does
/// not: the content is unavailable, the whole rewind is refused, and
/// nothing changes.
#[tokio::test]
async fn content_no_holder_has_is_unavailable_and_changes_nothing() {
    let state = linked_state(&[]);
    let request = approved(&state).await;
    let before = namespace_snapshot(&state);

    let error = prepare_rewind(state.clone(), request).await.err().expect("must not prepare");

    let RewindPrepareError::ContentUnavailable { run_id, files } = &error else {
        panic!("expected content unavailable, got {error:?}");
    };
    assert_eq!(*files, 1);
    assert_eq!(error.to_string(), "1 files unavailable; rewind cannot start");
    let ended = run(&state, run_id);
    assert_eq!(ended.state, RewindRunState::Failed);
    assert_eq!(ended.failure_kind, Some(RewindFailureKind::ContentUnavailable));
    assert_eq!(ended.unavailable_files, 1);
    assert_eq!(namespace_snapshot(&state), before, "zero mutations");
    assert!(!state.replica_coordinator.retention_paused(GROUP));
}

/// Another member could hold the content but is not connected: that is
/// never evidence the content is gone. Transient, nothing changes.
#[tokio::test]
async fn an_offline_holder_makes_the_failure_transient_and_changes_nothing() {
    let state = linked_state(&["device-b"]);
    let request = approved(&state).await;
    let before = namespace_snapshot(&state);

    let error = prepare_rewind(state.clone(), request).await.err().expect("must not prepare");

    let RewindPrepareError::Transient { run_id, offline } = &error else {
        panic!("expected transient, got {error:?}");
    };
    assert_eq!(offline, &["device-b".to_string()]);
    // The person is told which device to bring back, not just "devices".
    assert_eq!(
        error.to_string(),
        "Rewind could not be prepared: device-b is offline. Retry when it is available."
    );
    let ended = run(&state, run_id);
    assert_eq!(ended.failure_kind, Some(RewindFailureKind::Transient));
    assert_eq!(ended.offline_devices, vec!["device-b".to_string()], "kept for status");
    assert_eq!(ended.message(), error.to_string());
    assert_eq!(ended.unavailable_files, 0);
    assert_eq!(namespace_snapshot(&state), before, "zero mutations");
}

/// Provenance alone is not "held": the bytes must be in the store and read
/// back intact. With nobody else able to supply them, the content is
/// unavailable.
#[tokio::test]
async fn provenance_without_the_bytes_is_not_counted_as_held() {
    let state = linked_state(&[]);
    // Provenance for the right hash, but the store does not hold its bytes.
    state.replica_coordinator.record_block_provenance(GROUP, &[block_of(b"old").hash]).unwrap();
    let request = approved(&state).await;
    assert!(matches!(
        prepare_rewind(state.clone(), request).await,
        Err(RewindPrepareError::ContentUnavailable { files: 1, .. })
    ));
}

#[tokio::test]
async fn a_second_preparation_of_the_same_group_is_refused() {
    let state = linked_state(&[]);
    store_locally(&state, b"old");
    let request = approved(&state).await;
    let first = prepare_rewind(state.clone(), request.clone()).await.unwrap();
    assert_eq!(
        prepare_rewind(state.clone(), request.clone()).await.err(),
        Some(RewindPrepareError::RunActive)
    );
    drop(first);
    assert!(prepare_rewind(state, request).await.is_ok(), "the next run may start once it ended");
}

#[tokio::test]
async fn a_viewer_is_refused_before_anything_is_recorded() {
    let state = linked_state(&[]);
    state.authority.install_test_group_policy(
        GROUP,
        GroupPolicyState::with_members_for_tests(&[(ME, WriterRole::Viewer)]),
    );
    let request = approved(&state).await;
    assert_eq!(
        prepare_rewind(state.clone(), request).await.err(),
        Some(RewindPrepareError::NotAuthorized)
    );
    assert_eq!(latest(&state), None);
    assert!(!state.replica_coordinator.retention_paused(GROUP));
}

/// Polls the prepare future until its run is recorded and fetching, then
/// returns it still pending.
async fn until_preparing(
    state: &Arc<DaemonState>,
    prepare: &mut std::pin::Pin<
        Box<impl std::future::Future<Output = Result<super::PreparedRewind, RewindPrepareError>>>,
    >,
) {
    let recorded = async {
        loop {
            if latest(state).is_some_and(|run| run.state == RewindRunState::Planned) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    };
    tokio::select! {
        outcome = prepare.as_mut() => panic!("finished before it could be interrupted: {:?}", outcome.err()),
        _ = recorded => {}
    }
}

/// A crash while content is being gathered leaves a `planned` row behind;
/// the next start settles it as interrupted from the row alone.
#[tokio::test]
async fn a_crash_while_gathering_content_is_settled_as_interrupted_on_restart() {
    // An offline holder keeps the preparation re-asking long enough to be
    // caught mid-way.
    let state = linked_state(&["device-b"]);
    let request = approved(&state).await;
    let before = namespace_snapshot(&state);
    state.install_test_root_commit_authority(GROUP);
    let mut prepare = Box::pin(prepare_rewind(state.clone(), request));
    until_preparing(&state, &mut prepare).await;
    // Gathering content holds no lock that a change of the folder needs.
    assert!(state.is_write_safe_point(), "no write activity is held");
    assert_eq!(
        state.root_lease_for(GROUP).unwrap().active_operations(),
        0,
        "no root operation is held"
    );
    assert!(
        state
            .replica_coordinator
            .path_lock_registry()
            .path_lock(GROUP, "doc.txt")
            .try_lock()
            .is_ok(),
        "the restored path's lock is free"
    );

    // The process dies: nothing of the preparation runs any further, no
    // destructor included.
    std::mem::forget(prepare);
    let run_id = latest(&state).unwrap().run_id;
    assert_eq!(run(&state, &run_id).state, RewindRunState::Planned);

    let settled = state.replica_coordinator.rewind_run_repository().interrupt_unfinished_runs();
    assert_eq!(settled.unwrap(), 1);
    let ended = run(&state, &run_id);
    assert_eq!(ended.state, RewindRunState::Failed);
    assert_eq!(ended.failure_kind, Some(RewindFailureKind::Interrupted));
    assert_eq!(namespace_snapshot(&state), before, "zero mutations");
}

/// Abandoning a preparation mid-way (its caller gives up) ends the run and
/// releases the retention pause.
#[tokio::test]
async fn abandoning_a_preparation_ends_the_run_and_releases_retention() {
    let state = linked_state(&["device-b"]);
    let request = approved(&state).await;
    let mut prepare = Box::pin(prepare_rewind(state.clone(), request));
    until_preparing(&state, &mut prepare).await;
    assert!(state.replica_coordinator.retention_paused(GROUP));

    drop(prepare);

    let ended = latest(&state).unwrap();
    assert_eq!(ended.state, RewindRunState::Failed);
    assert_eq!(ended.failure_kind, Some(RewindFailureKind::Interrupted));
    assert!(!state.replica_coordinator.retention_paused(GROUP), "the pause is released on drop");
}

/// While a rewind is prepared, retention expiry leaves the group's rows
/// alone; once it ends, expiry proceeds.
#[tokio::test]
async fn retention_expiry_waits_while_a_rewind_is_prepared() {
    let state = linked_state(&[]);
    store_locally(&state, b"old");
    // Twelve more superseded versions of another path, all old enough and
    // beyond the count bound: expiry would remove the oldest.
    for seq in 1..=12 {
        write_current(&state, "churn.txt", seq, &[], 50);
    }
    write_current(&state, "churn.txt", 13, &[], 60);
    let request = approved(&state).await;
    let prepared = prepare_rewind(state.clone(), request).await.unwrap();

    let far_future = i64::MAX / 2;
    let expired = state
        .replica_coordinator
        .expire_superseded_and_trashed_versions(GROUP, far_future)
        .unwrap();
    assert_eq!(expired, 0, "nothing expires while the rewind holds the group");

    drop(prepared);
    let expired = state
        .replica_coordinator
        .expire_superseded_and_trashed_versions(GROUP, far_future)
        .unwrap();
    assert!(expired > 0, "expiry proceeds once the rewind ended");
}

/// An unfinished row no live run owns (its settling write failed) does not
/// keep the group blocked: the next preparation settles it as interrupted
/// and starts.
#[tokio::test]
async fn an_orphaned_unfinished_row_is_settled_instead_of_blocking_the_group() {
    let state = linked_state(&[]);
    store_locally(&state, b"old");
    let request = approved(&state).await;
    let runs = state.replica_coordinator.rewind_run_repository();
    runs.begin_run("orphan", GROUP, TARGET, &request.plan_id, 1).unwrap();

    let prepared = prepare_rewind(state.clone(), request).await.unwrap();

    let orphan = run(&state, "orphan");
    assert_eq!(orphan.state, RewindRunState::Failed);
    assert_eq!(orphan.failure_kind, Some(RewindFailureKind::Interrupted));
    assert_eq!(run(&state, prepared.run_id()).state, RewindRunState::Prefetched);
}

/// A path whose live head holds other content than its row (a change
/// admitted here, not yet in the folder) would stop the run at its chunk
/// with the same plan id: refused before anything is recorded or fetched.
#[tokio::test]
async fn a_path_with_an_unprojected_head_is_refused_before_anything_is_recorded() {
    let state = linked_state(&[]);
    store_locally(&state, b"old");
    let request = approved(&state).await;
    let database = state.replica_coordinator.database();
    database
        .pool_for_test()
        .get()
        .unwrap()
        .execute(
            "UPDATE native_heads SET version = ?1 WHERE group_id = ?2 AND path = 'doc.txt'",
            rusqlite::params![[9u8; 32].as_slice(), GROUP],
        )
        .unwrap();

    let error = prepare_rewind(state.clone(), request).await.err().expect("must not start");

    assert_eq!(error, RewindPrepareError::FolderSettling { path: "doc.txt".into() });
    assert_eq!(
        error.to_string(),
        "The folder changed; wait for sync to settle, then preview again."
    );
    assert_eq!(latest(&state), None, "nothing recorded");
    assert!(!state.replica_coordinator.retention_paused(GROUP));
}
