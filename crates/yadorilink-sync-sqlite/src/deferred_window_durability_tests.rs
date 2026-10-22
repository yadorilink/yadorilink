//! Durability audit of the deferred receive flush and of the grouped temp-name
//! commit: what a crash leaves in the database file, taken as an
//! image of the database and its write-ahead log at the very step, and opened
//! the way a restart opens it.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use yadorilink_local_storage::TempFileLedger;
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_sqlite_runtime::SyncDatabase;

use crate::exact_materialized_commit::{
    commit_internal_materialized_state_with_intent, ExactMaterializedState,
};
use crate::{IntentDisposition, MaterializationTempLedger, SyncSqliteError, TempReleaseQueue};

fn open(path: &Path) -> Arc<SyncDatabase> {
    Arc::new(
        SyncDatabase::open(path, |conn| {
            crate::replica_tables::init_for_tests(conn)
                .map_err(|e| yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string()))
        })
        .unwrap(),
    )
}

/// The database file as a crash leaves it: the main file, the log and the
/// shared-memory index copied byte for byte while the live handle is still open
/// and nothing was checkpointed or closed.
fn crash_image(live: &Path, into: &Path) -> PathBuf {
    let image = into.join("image.db");
    for suffix in ["", "-wal", "-shm"] {
        let from = PathBuf::from(format!("{}{suffix}", live.display()));
        if from.exists() {
            std::fs::copy(&from, PathBuf::from(format!("{}{suffix}", image.display()))).unwrap();
        }
    }
    image
}

fn seed_waiting_intent(database: &SyncDatabase) -> i64 {
    database
        .write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, \
                 deleted, state, version_seq, materialization_state) \
                 VALUES ('g', 'p', 0, 0, '[]', 0, 'current', 1, 'remote')",
                [],
            )?;
            conn.execute(
                "INSERT INTO materialization_intents \
                 (group_id, path, target_version_hash, created_at_unix_nanos) \
                 VALUES ('g', 'p', ?1, 0)",
                [&[9u8; 32][..]],
            )?;
            let tx = conn.transaction()?;
            let fence =
                crate::materialized_generation::bump_mutation_fence(&tx, "g", "p", "test", 0)?;
            commit_internal_materialized_state_with_intent(
                &tx,
                "g",
                "p",
                &ExactMaterializedState::Object {
                    kind: RecordKind::Symlink,
                    version: VersionHash([4u8; 32]),
                    identity: Box::new(None),
                },
                fence,
                None,
                0,
                IntentDisposition::FlushPending { mutation_generation: fence },
            )?;
            tx.commit()?;
            Ok(fence)
        })
        .unwrap()
}

fn waits(database: &SyncDatabase, fence: i64) -> bool {
    database
        .read::<_, SyncSqliteError>(|conn| {
            let marker: Option<i64> = conn
                .query_row(
                    "SELECT mutation_generation FROM materialization_intents \
                     WHERE group_id = 'g' AND path = 'p' AND kind = 'write'",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(None);
            let state: String = conn.query_row(
                "SELECT materialization_state FROM files WHERE group_id = 'g' AND path = 'p'",
                [],
                |r| r.get(0),
            )?;
            Ok(marker == Some(fence)
                && state == "present"
                && crate::flush_pending_proof_identity(conn, "g", "p")?.is_some())
        })
        .unwrap()
}

/// A deferred close is one transaction: the proof, `Present` and the marked,
/// still-open intent are all in the log or none of them is. A restart from the
/// log alone, from a checkpointed file, and from a clean reopen all see the
/// same waiting state, and clearing it after the restart works.
#[test]
fn a_flush_pending_close_survives_every_way_the_database_is_reopened() {
    let dir = tempfile::tempdir().unwrap();
    let live = dir.path().join("live.db");
    let database = open(&live);
    let fence = seed_waiting_intent(&database);
    assert!(waits(&database, fence));

    // Crash with the commit only in the write-ahead log.
    let image = crash_image(&live, tempfile::tempdir().unwrap().keep().as_path());
    let recovered = open(&image);
    assert!(waits(&recovered, fence), "recovered from the log alone");

    // After a checkpoint into the main file, and a clean close and reopen.
    database.checkpoint_truncate().unwrap();
    let checkpointed = crash_image(&live, tempfile::tempdir().unwrap().keep().as_path());
    assert!(waits(&open(&checkpointed), fence), "checkpointed image");
    drop(database);
    let reopened = open(&live);
    assert!(waits(&reopened, fence), "clean reopen");

    // The barrier that follows the restart clears exactly the marked intent.
    let cleared = reopened
        .write::<_, SyncSqliteError>(|conn| {
            let tx = conn.transaction()?;
            let cleared = crate::clear_flush_pending_in_tx(&tx, "g", "p", fence)?;
            tx.commit()?;
            Ok(cleared)
        })
        .unwrap();
    assert!(cleared);
    assert!(!waits(&reopened, fence));
}

/// A torn transaction cannot be seen: an image whose log lost its tail (the
/// close was not yet fully written) shows the intent without a marker or the
/// whole close, never a marker without its proof.
#[test]
fn a_log_cut_inside_the_close_shows_no_half_of_it() {
    let dir = tempfile::tempdir().unwrap();
    let live = dir.path().join("live.db");
    let database = open(&live);
    // Hold the log: nothing is checkpointed while the handle lives.
    let before = std::fs::metadata(format!("{}-wal", live.display())).map(|m| m.len()).unwrap_or(0);
    let fence = seed_waiting_intent(&database);
    let image_dir = tempfile::tempdir().unwrap();
    let image = crash_image(&live, image_dir.path());
    let wal = PathBuf::from(format!("{}-wal", image.display()));
    let full = std::fs::metadata(&wal).unwrap().len();
    assert!(full > before, "the close is in the log");
    // Cut the log in the middle of the frames the close wrote.
    std::fs::OpenOptions::new().write(true).open(&wal).unwrap().set_len(full - 4096).unwrap();
    let torn = open(&image);
    let half = torn
        .read::<_, SyncSqliteError>(|conn| {
            let marked: i64 = conn.query_row(
                "SELECT COUNT(*) FROM materialization_intents \
                 WHERE mutation_generation IS NOT NULL",
                [],
                |r| r.get(0),
            )?;
            let proofs: i64 =
                conn.query_row("SELECT COUNT(*) FROM path_materialized_generations", [], |r| {
                    r.get(0)
                })?;
            let present: i64 = conn.query_row(
                "SELECT COUNT(*) FROM files WHERE materialization_state = 'present'",
                [],
                |r| r.get(0),
            )?;
            Ok((marked, proofs, present))
        })
        .unwrap();
    assert!(
        half.0 == 0 || half == (1, 1, 1),
        "a marker is never seen without its proof and Present: {half:?}"
    );
    assert_eq!(waits(&torn, fence), half == (1, 1, 1));
}

fn ledger(database: &Arc<SyncDatabase>, group: &str) -> MaterializationTempLedger {
    MaterializationTempLedger::new(database.clone(), group, Arc::new(TempReleaseQueue::default()))
}

/// The name is in the database file before `record` returns, so before the
/// temp file can be created: an image taken the instant it returns (no file
/// exists yet) lists it, for its own group only.
#[test]
fn a_recorded_name_is_durable_before_its_file_can_exist() {
    let dir = tempfile::tempdir().unwrap();
    let live = dir.path().join("live.db");
    let database = open(&live);
    let (a, b) = (ledger(&database, "a"), ledger(&database, "b"));
    let ours = Path::new("/r/.yadorilink-tmp.ours");
    let theirs = Path::new("/r/.yadorilink-tmp.theirs");
    a.record(ours).unwrap();
    b.record(theirs).unwrap();
    assert!(!ours.exists(), "no file was created");

    let image = crash_image(&live, tempfile::tempdir().unwrap().keep().as_path());
    let recovered = open(&image);
    assert_eq!(ledger(&recovered, "a").list().unwrap(), vec![ours.display().to_string()]);
    assert_eq!(ledger(&recovered, "b").list().unwrap(), vec![theirs.display().to_string()]);
}

/// A group commit that fails reports the failure to every writer in the group,
/// records none of them, and loses no queued release: the next commit that
/// works deletes the released rows too.
#[test]
fn a_failed_group_commit_records_nobody_and_keeps_the_queued_releases() {
    let database = crate::replica_tables::open_for_tests();
    let queue = Arc::new(TempReleaseQueue::default());
    let ledger = MaterializationTempLedger::new(database.clone(), "g", queue);
    let old = Path::new("/r/.yadorilink-tmp.old");
    ledger.record(old).unwrap();
    ledger.release(old);
    database
        .write::<_, SyncSqliteError>(|conn| {
            conn.execute_batch(
                "ALTER TABLE materialization_tmp_files RENAME TO materialization_tmp_files_away",
            )?;
            Ok(())
        })
        .unwrap();

    let failures: Vec<bool> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|n| {
                let ledger = &ledger;
                scope.spawn(move || {
                    ledger.record(Path::new(&format!("/r/.yadorilink-tmp.new{n}"))).is_err()
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(failures, vec![true; 4], "no writer is told its name is durable");

    database
        .write::<_, SyncSqliteError>(|conn| {
            conn.execute_batch(
                "ALTER TABLE materialization_tmp_files_away RENAME TO materialization_tmp_files",
            )?;
            Ok(())
        })
        .unwrap();
    let kept = Path::new("/r/.yadorilink-tmp.kept");
    ledger.record(kept).unwrap();
    assert_eq!(
        ledger.list().unwrap(),
        vec![kept.display().to_string()],
        "nothing of the failed group was recorded, and the queued release was applied"
    );
}
