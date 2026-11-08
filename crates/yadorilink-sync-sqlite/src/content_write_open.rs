//! The open half of an eager content write, as statements inside the
//! caller's transaction.
//!
//! Open the intent, persist the row, mark it in flight, clear any hazard hold
//! and bump the path's mutation fence, in that order. The caller commits (and
//! re-verifies its root permits) in the same transaction.

use rusqlite::Transaction;
use yadorilink_replica_domain::file::FileRecord;

use crate::error::SyncSqliteError;
use crate::file_index::FileIndexRepository;
use crate::{MaterializationIntentRepository, MaterializationStateRepository};

/// One content write's open, borrowing its inputs.
pub struct OpenWriteRequest<'a> {
    pub group_id: &'a str,
    pub record: &'a FileRecord,
    pub origin_device_id: &'a str,
    pub authoring: Option<&'a yadorilink_replica_domain::native_plan::NativeRowIdentity>,
    /// The version's metadata columns, written onto the row this open
    /// inserts and onto no earlier one.
    pub meta: &'a yadorilink_replica_domain::session_state::LocalFileMetaColumns,
    /// The intent's target: the hash of the record's block list.
    pub intent_target_hash: &'a [u8],
    /// The materialization state that marks a row whose bytes are not yet on
    /// disk.
    pub in_flight_state: yadorilink_replica_domain::session_state::MaterializationState,
    pub now_unix_nanos: i64,
    /// The temp file the write will publish, named before the open so a crash after it can finish
    /// the write from that file.
    pub tmp_path: Option<&'a str>,
    /// What the write says about the version its row replaces.
    pub retention: crate::retention::Retention<'a>,
}

/// Runs the open statements of one write and returns the mutation fence value
/// the write's proof will CAS on. Each step that fails leaves the caller's
/// transaction (or savepoint) to roll the earlier ones back.
pub fn open_content_write_in_tx(
    tx: &Transaction<'_>,
    request: &OpenWriteRequest<'_>,
) -> Result<i64, SyncSqliteError> {
    let OpenWriteRequest {
        group_id,
        record,
        origin_device_id,
        authoring,
        meta,
        intent_target_hash,
        in_flight_state,
        now_unix_nanos,
        tmp_path,
        retention,
    } = *request;
    MaterializationIntentRepository::begin_materialization_intent_in_tx(
        tx,
        group_id,
        &record.path,
        intent_target_hash,
        now_unix_nanos,
    )?;
    crate::materialization_intent_repository::set_write_intent_tmp_path_in_tx(
        tx,
        group_id,
        &record.path,
        tmp_path,
    )?;
    FileIndexRepository::upsert_file_with_origin_and_authoring_in_tx(
        tx,
        group_id,
        record,
        origin_device_id,
        authoring,
        Some(meta),
        retention,
    )?;
    // Explicitly the in-flight state, NOT `Present`: the intent is what makes
    // the row-before-file ordering safe across a crash, and the bytes are
    // still nowhere at this point.
    MaterializationStateRepository::set_materialization_state_in_tx(
        tx,
        group_id,
        &record.path,
        in_flight_state,
    )?;
    MaterializationStateRepository::clear_held_in_tx(tx, group_id, &record.path)?;
    crate::materialized_generation::bump_mutation_fence(
        tx,
        group_id,
        &record.path,
        "eager_content_write",
        now_unix_nanos,
    )
}

/// Prepares an in-place write of `path` that has no row to commit (an on-demand hydration), in
/// the caller's transaction: opens the write intent for `target_version_hash` (phase
/// `prepared`) and bumps the path's mutation fence, and returns the bumped fence.
pub fn open_write_and_bump_fence_in_tx(
    tx: &Transaction<'_>,
    group_id: &str,
    path: &str,
    target_version_hash: &[u8],
    mutation_kind: &str,
    now_unix_nanos: i64,
) -> Result<i64, SyncSqliteError> {
    MaterializationIntentRepository::begin_materialization_intent_in_tx(
        tx,
        group_id,
        path,
        target_version_hash,
        now_unix_nanos,
    )?;
    crate::materialized_generation::bump_mutation_fence(
        tx,
        group_id,
        path,
        mutation_kind,
        now_unix_nanos,
    )
}

/// One open of a write with no block content (a symlink, an explicit directory), borrowing its
/// inputs.
pub struct OpenSingleObjectRequest<'a> {
    pub group_id: &'a str,
    pub record: &'a FileRecord,
    pub origin_device_id: &'a str,
    pub authoring: Option<&'a yadorilink_replica_domain::native_plan::NativeRowIdentity>,
    pub meta: &'a yadorilink_replica_domain::session_state::LocalFileMetaColumns,
    /// The intent's target: the hash of the object's own bytes (the link target, or empty for a
    /// directory).
    pub intent_target_hash: &'a [u8],
    pub in_flight_state: yadorilink_replica_domain::session_state::MaterializationState,
    /// The label recorded with the fence bump.
    pub fence_reason: &'a str,
    pub now_unix_nanos: i64,
    pub retention: crate::retention::Retention<'a>,
}

/// The open statements of a single-object write, in the caller's transaction: open the intent,
/// upsert the row unless this exact authored version is already current (a policy-skipped link
/// retried on a backoff would otherwise add a version row per retry), mark the row in flight and
/// bump the path's mutation fence. Returns the fence value the write's proof will CAS on.
pub fn open_single_object_write_in_tx(
    tx: &Transaction<'_>,
    request: &OpenSingleObjectRequest<'_>,
) -> Result<i64, SyncSqliteError> {
    let OpenSingleObjectRequest {
        group_id,
        record,
        origin_device_id,
        authoring,
        meta,
        intent_target_hash,
        in_flight_state,
        fence_reason,
        now_unix_nanos,
        retention,
    } = *request;
    MaterializationIntentRepository::begin_materialization_intent_in_tx(
        tx,
        group_id,
        &record.path,
        intent_target_hash,
        now_unix_nanos,
    )?;
    let already_current = match authoring {
        Some(identity) => {
            crate::file_index::row_authoring_in_tx(tx, group_id, &record.path)?.as_ref()
                == Some(identity)
        }
        None => false,
    };
    if !already_current {
        FileIndexRepository::upsert_file_with_origin_and_authoring_in_tx(
            tx,
            group_id,
            record,
            origin_device_id,
            authoring,
            Some(meta),
            retention,
        )?;
    }
    // The row carries the previous version's state forward, and its proof dies with the bump
    // below: an existing `Present` link would otherwise still read `Present` with nothing
    // vouching for it.
    MaterializationStateRepository::set_materialization_state_in_tx(
        tx,
        group_id,
        &record.path,
        in_flight_state,
    )?;
    crate::materialized_generation::bump_mutation_fence(
        tx,
        group_id,
        &record.path,
        fence_reason,
        now_unix_nanos,
    )
}

/// Prepares a tombstone delete of `path` in the caller's transaction: opens its delete intent
/// (the live row is left as it is) and bumps the path's mutation fence, and returns the bumped
/// fence.
pub fn open_delete_and_bump_fence_in_tx(
    tx: &Transaction<'_>,
    group_id: &str,
    path: &str,
    now_unix_nanos: i64,
) -> Result<i64, SyncSqliteError> {
    crate::materialization_intent_repository::begin_delete_intent_in_tx(
        tx,
        group_id,
        path,
        now_unix_nanos,
    )?;
    crate::materialized_generation::bump_mutation_fence(
        tx,
        group_id,
        path,
        "tombstone_delete",
        now_unix_nanos,
    )
}

/// Prepares an eviction of `path` to a placeholder in the caller's transaction: marks the row
/// `Evicting` and bumps the path's mutation fence for the placeholder write, and returns the
/// bumped fence. No committed state has the row `Evicting` over an unbumped fence.
pub fn open_eviction_in_tx(
    tx: &Transaction<'_>,
    group_id: &str,
    path: &str,
    now_unix_nanos: i64,
) -> Result<i64, SyncSqliteError> {
    MaterializationStateRepository::set_materialization_state_in_tx(
        tx,
        group_id,
        path,
        yadorilink_replica_domain::session_state::MaterializationState::Evicting,
    )?;
    crate::materialized_generation::bump_mutation_fence(
        tx,
        group_id,
        path,
        "eviction_to_placeholder",
        now_unix_nanos,
    )
}

/// Opens several content writes in the caller's one transaction, each as its
/// own unit.
///
/// Every request runs the statements of [`open_content_write_in_tx`], in
/// that order, against its own path, under its own savepoint. Once every
/// request has run, `verify(index)` runs for each request in order, which is
/// where the caller checks that request's own root permits (the lane's and the
/// fresh one of the row's operation); it runs whatever the statements did, after
/// the last of them and before the caller commits, so a caller whose requests
/// share a root authority need verify it only once.
///
/// A failing `verify` means a root is no longer this link's, which no item's
/// commit may outlive: it fails the whole call, so the transaction rolls back
/// and every request keeps its pre-open state. A transient lock inside a request's statements is not that
/// request's verdict either: it fails the whole call, which the writer
/// retries. Any other failure of a request's statements rolls that request
/// back to its savepoint (so no intent, row, state or fence change of it
/// survives) and is its outcome; the others in the batch are unaffected and
/// commit with the transaction.
pub fn open_content_writes_in_tx(
    tx: &Transaction<'_>,
    requests: &[OpenWriteRequest<'_>],
    mut verify: impl FnMut(usize) -> Result<(), SyncSqliteError>,
) -> Result<Vec<Result<i64, SyncSqliteError>>, SyncSqliteError> {
    let mut outcomes = Vec::with_capacity(requests.len());
    for request in requests {
        tx.execute_batch("SAVEPOINT open_content_write")?;
        let outcome = open_content_write_in_tx(tx, request);
        let outcome = match outcome {
            Err(error) if yadorilink_sqlite_runtime::SqlOperationError::is_locked(&error) => {
                return Err(error);
            }
            other => other,
        };
        if outcome.is_err() {
            tx.execute_batch("ROLLBACK TO open_content_write")?;
        }
        tx.execute_batch("RELEASE open_content_write")?;
        outcomes.push(outcome);
    }
    // Whatever the statements did, a lost root fails the whole call. Checked once every statement
    // has run, right before the caller commits: a failure rolls back every item either way, and
    // a check after the last statement is at least as late as one after each item's own.
    for index in 0..requests.len() {
        verify(index)?;
    }
    Ok(outcomes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use yadorilink_replica_domain::file::BlockInfo;

    fn record(path: &str) -> FileRecord {
        FileRecord {
            path: path.to_owned(),
            size: 5,
            mtime_unix_nanos: 1,
            blocks: vec![BlockInfo { hash: vec![7; 32], offset: 0, size: 5 }],
            deleted: false,
        }
    }

    fn file_meta() -> &'static yadorilink_replica_domain::session_state::LocalFileMetaColumns {
        static META: std::sync::OnceLock<
            yadorilink_replica_domain::session_state::LocalFileMetaColumns,
        > = std::sync::OnceLock::new();
        META.get_or_init(|| yadorilink_replica_domain::session_state::LocalFileMetaColumns {
            record_kind: yadorilink_replica_domain::file::RecordKind::File,
            symlink_target: None,
            symlink_out_of_root: false,
            exec: false,
        })
    }

    fn request<'a>(record: &'a FileRecord, hash: &'a [u8]) -> OpenWriteRequest<'a> {
        OpenWriteRequest {
            group_id: "g",
            record,
            origin_device_id: "dev",
            authoring: None,
            meta: file_meta(),
            intent_target_hash: hash,
            in_flight_state:
                yadorilink_replica_domain::session_state::MaterializationState::Hydrating,
            now_unix_nanos: 1,
            tmp_path: None,
            retention: crate::retention::Retention::OwnEdit,
        }
    }

    /// The temp a write names is written with its intent and replaced by the next open of the
    /// path, which names none: a pointer never outlives the open it was written for.
    #[test]
    fn the_intent_names_its_temp_until_the_next_open() {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::init_replica_schema(&conn).unwrap();
        let a = record("a.txt");
        let hash = vec![9u8; 32];
        let named = |conn: &Connection| -> Option<String> {
            conn.query_row(
                "SELECT tmp_path FROM materialization_intents WHERE kind = 'write'",
                [],
                |r| r.get(0),
            )
            .unwrap()
        };
        let tx = conn.transaction().unwrap();
        let mut first = request(&a, &hash);
        first.tmp_path = Some("/r/.yadorilink-tmp.00");
        open_content_write_in_tx(&tx, &first).unwrap();
        tx.commit().unwrap();
        assert_eq!(named(&conn).as_deref(), Some("/r/.yadorilink-tmp.00"));
        let tx = conn.transaction().unwrap();
        open_content_write_in_tx(&tx, &request(&a, &hash)).unwrap();
        tx.commit().unwrap();
        assert_eq!(named(&conn), None);
    }

    /// A repair re-opens the intent to finish the write from its temp: the open does not drop the
    /// name, so a crash in the middle of the finish can still find the temp.
    #[test]
    fn a_repair_open_keeps_the_temp_the_intent_names() {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::init_replica_schema(&conn).unwrap();
        let a = record("a.txt");
        let hash = vec![9u8; 32];
        let tx = conn.transaction().unwrap();
        let mut first = request(&a, &hash);
        first.tmp_path = Some("/r/.yadorilink-tmp.00");
        open_content_write_in_tx(&tx, &first).unwrap();
        tx.commit().unwrap();
        let tx = conn.transaction().unwrap();
        open_write_and_bump_fence_in_tx(&tx, "g", "a.txt", &hash, "repair_reconstruct", 2).unwrap();
        tx.commit().unwrap();
        let named: Option<String> = conn
            .query_row(
                "SELECT tmp_path FROM materialization_intents WHERE kind = 'write'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(named.as_deref(), Some("/r/.yadorilink-tmp.00"));
    }

    /// A statement of the second item fails with SQLITE_LOCKED: that is not
    /// the item's verdict. The whole call fails (so the writer's retry re-runs
    /// the transaction) and nothing of the first item survives it; once the
    /// lock clears, the same batch commits.
    #[test]
    fn a_transient_lock_inside_an_item_fails_the_whole_open_batch() {
        // Shared-cache in-memory database, as the daemon's tests use: a second
        // connection with an unfinished read of the fence table makes the first
        // one's insert into it fail with SQLITE_LOCKED.
        let uri = "file:open_batch_lock?mode=memory&cache=shared";
        let flags = rusqlite::OpenFlags::default() | rusqlite::OpenFlags::SQLITE_OPEN_URI;
        let mut conn = Connection::open_with_flags(uri, flags).unwrap();
        crate::init_replica_schema(&conn).unwrap();
        conn.execute(
            "INSERT INTO path_actual_mutation_fences (group_id, path, mutation_generation, last_mutation_kind, \
             last_mutation_at) VALUES ('other', 'seed', 1, 'x', 1)",
            [],
        )
        .unwrap();
        let reader = Connection::open_with_flags(uri, flags).unwrap();
        let mut hold = reader.prepare("SELECT path FROM path_actual_mutation_fences").unwrap();
        let mut rows = hold.query([]).unwrap();
        assert!(rows.next().unwrap().is_some(), "the reader holds the table mid-read");
        let (a, b) = (record("a.txt"), record("b.txt"));
        let hash = vec![9u8; 32];
        let requests = [request(&a, &hash), request(&b, &hash)];

        let tx = conn.transaction().unwrap();
        let failed = open_content_writes_in_tx(&tx, &requests, |_| Ok(()));
        assert!(
            failed.as_ref().is_err_and(yadorilink_sqlite_runtime::SqlOperationError::is_locked),
            "a transient lock must fail the whole call: {failed:?}"
        );
        drop(tx);
        let intents: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM materialization_intents WHERE kind = 'write'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(intents, 0, "the rolled-back transaction left an item behind");

        drop(rows);
        drop(hold);
        let tx = conn.transaction().unwrap();
        let outcomes = open_content_writes_in_tx(&tx, &requests, |_| Ok(())).unwrap();
        assert!(outcomes.iter().all(Result::is_ok));
        tx.commit().unwrap();
    }

    /// Preparing a write is one transaction: the intent (phase `prepared`) and the fence bump
    /// are committed together, or neither is. There is no committed state with an open intent
    /// and no bumped fence, or the reverse.
    #[test]
    fn the_intent_and_the_fence_bump_commit_together_or_not_at_all() {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::init_replica_schema(&conn).unwrap();
        let a = record("a.txt");
        let hash = vec![9u8; 32];
        let counts = |conn: &Connection| -> (i64, i64) {
            let intents = conn
                .query_row(
                    "SELECT COUNT(*) FROM materialization_intents \
                     WHERE kind = 'write' AND phase = 'prepared'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            let fences = conn
                .query_row("SELECT COUNT(*) FROM path_actual_mutation_fences", [], |r| r.get(0))
                .unwrap();
            (intents, fences)
        };

        let tx = conn.transaction().unwrap();
        open_content_writes_in_tx(&tx, &[request(&a, &hash)], |_| Ok(())).unwrap();
        drop(tx);
        assert_eq!(counts(&conn), (0, 0), "a rolled-back open leaves neither");

        let tx = conn.transaction().unwrap();
        open_content_writes_in_tx(&tx, &[request(&a, &hash)], |_| Ok(())).unwrap();
        tx.commit().unwrap();
        assert_eq!(counts(&conn), (1, 1), "a committed open leaves both");
    }

    /// A single-object open is one transaction: the intent, the in-flight row and the fence bump
    /// commit together or not at all, and a version already current is not upserted again.
    #[test]
    fn a_single_object_open_commits_intent_row_and_fence_together() {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::init_replica_schema(&conn).unwrap();
        let record = record("l");
        let hash = vec![5u8; 32];
        let count = |conn: &Connection| -> (i64, i64, i64) {
            let one = |sql: &str| conn.query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap();
            (
                one("SELECT COUNT(*) FROM materialization_intents WHERE phase = 'prepared'"),
                one("SELECT COUNT(*) FROM files"),
                one("SELECT COUNT(*) FROM path_actual_mutation_fences"),
            )
        };
        let request = |record| OpenSingleObjectRequest {
            group_id: "g",
            record,
            origin_device_id: "dev",
            authoring: None,
            meta: file_meta(),
            intent_target_hash: &hash,
            in_flight_state:
                yadorilink_replica_domain::session_state::MaterializationState::Hydrating,
            fence_reason: "test",
            now_unix_nanos: 1,
            retention: crate::retention::Retention::OwnEdit,
        };

        let tx = conn.transaction().unwrap();
        open_single_object_write_in_tx(&tx, &request(&record)).unwrap();
        drop(tx);
        assert_eq!(count(&conn), (0, 0, 0), "a rolled-back open leaves nothing");

        let tx = conn.transaction().unwrap();
        let fence = open_single_object_write_in_tx(&tx, &request(&record)).unwrap();
        tx.commit().unwrap();
        assert_eq!(fence, 1);
        assert_eq!(count(&conn), (1, 1, 1), "a committed open leaves all three");
    }

    /// An eviction's open is one transaction: the `Evicting` mark and the fence bump commit
    /// together or not at all, so no committed state has the row `Evicting` over an unbumped
    /// fence.
    #[test]
    fn an_eviction_open_commits_the_evicting_mark_and_the_fence_bump_together() {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::init_replica_schema(&conn).unwrap();
        let record = record("e");
        let tx = conn.transaction().unwrap();
        FileIndexRepository::upsert_file_with_origin_and_authoring_in_tx(
            &tx,
            "g",
            &record,
            "dev",
            None,
            Some(file_meta()),
            crate::retention::Retention::OwnEdit,
        )
        .unwrap();
        tx.commit().unwrap();
        let state = |conn: &Connection| -> (String, i64) {
            let state = conn
                .query_row(
                    "SELECT materialization_state FROM files WHERE group_id = 'g' AND path = 'e' \
                     AND state = 'current'",
                    [],
                    |r| r.get::<_, String>(0),
                )
                .unwrap();
            let fences = conn
                .query_row("SELECT COUNT(*) FROM path_actual_mutation_fences", [], |r| r.get(0))
                .unwrap();
            (state, fences)
        };
        let before = state(&conn);
        assert_ne!(before.0, "evicting");

        let tx = conn.transaction().unwrap();
        open_eviction_in_tx(&tx, "g", "e", 1).unwrap();
        drop(tx);
        assert_eq!(state(&conn), before, "a rolled-back open leaves neither");

        let tx = conn.transaction().unwrap();
        let fence = open_eviction_in_tx(&tx, "g", "e", 1).unwrap();
        tx.commit().unwrap();
        assert_eq!(fence, 1);
        assert_eq!(state(&conn), ("evicting".to_owned(), before.1 + 1));
    }

    /// The roots are checked after every item's statements have run and before the caller
    /// commits, and a failure then rolls back every item, not only the one that failed.
    #[test]
    fn roots_are_verified_after_the_last_statement_and_a_failure_rolls_back_every_item() {
        let conn = Connection::open_in_memory().unwrap();
        crate::init_replica_schema(&conn).unwrap();
        let (a, b) = (record("a.txt"), record("b.txt"));
        let hash = vec![9u8; 32];
        let requests = [request(&a, &hash), request(&b, &hash)];
        let intents = |tx: &Transaction<'_>| -> i64 {
            tx.query_row(
                "SELECT COUNT(*) FROM materialization_intents WHERE kind = 'write'",
                [],
                |r| r.get(0),
            )
            .unwrap()
        };

        let mut conn = conn;
        let tx = conn.transaction().unwrap();
        let mut seen_at_verify = Vec::new();
        let failed = open_content_writes_in_tx(&tx, &requests, |index| {
            seen_at_verify.push(intents(&tx));
            if index == 1 {
                Err(SyncSqliteError::CorruptState("root lost".into()))
            } else {
                Ok(())
            }
        });
        assert!(failed.is_err(), "a lost root fails the whole call");
        assert_eq!(seen_at_verify, vec![2, 2], "both items had run before the first check");
        drop(tx);
        let tx = conn.transaction().unwrap();
        assert_eq!(intents(&tx), 0, "the first item must not survive its sibling's lost root");
    }

    /// Measurement, not a test: the CPU cost of each statement group of one open, per file, over
    /// a growing table (10,000 files in batches of 32, in memory, so no fsync is in it). Run with
    /// `--ignored --nocapture`, release profile.
    #[test]
    #[ignore = "measurement"]
    fn open_cost_per_step_over_10000_files() {
        use std::time::{Duration, Instant};
        let mut conn = Connection::open_in_memory().unwrap();
        crate::init_replica_schema(&conn).unwrap();
        let hash = vec![9u8; 32];
        let mut totals = [Duration::ZERO; 7];
        let (batches, per_batch) = (312usize, 32usize);
        let started = Instant::now();
        for batch in 0..batches {
            let records: Vec<FileRecord> = (0..per_batch)
                .map(|i| {
                    let n = batch * per_batch + i;
                    record(&format!("d{:03}/f{:05}.bin", n / 100, n))
                })
                .collect();
            let tx = conn.transaction().unwrap();
            for r in &records {
                let t0 = Instant::now();
                tx.execute_batch("SAVEPOINT open_content_write").unwrap();
                let t1 = Instant::now();
                MaterializationIntentRepository::begin_materialization_intent_in_tx(
                    &tx, "g", &r.path, &hash, 1,
                )
                .unwrap();
                let t2 = Instant::now();
                crate::materialization_intent_repository::set_write_intent_tmp_path_in_tx(
                    &tx,
                    "g",
                    &r.path,
                    Some("/r/.yadorilink-tmp.00"),
                )
                .unwrap();
                let t3 = Instant::now();
                FileIndexRepository::upsert_file_with_origin_and_authoring_in_tx(
                    &tx,
                    "g",
                    r,
                    "dev",
                    None,
                    Some(file_meta()),
                    crate::retention::Retention::OwnEdit,
                )
                .unwrap();
                let t4 = Instant::now();
                MaterializationStateRepository::set_materialization_state_in_tx(
                    &tx,
                    "g",
                    &r.path,
                    yadorilink_replica_domain::session_state::MaterializationState::Hydrating,
                )
                .unwrap();
                MaterializationStateRepository::clear_held_in_tx(&tx, "g", &r.path).unwrap();
                let t5 = Instant::now();
                crate::materialized_generation::bump_mutation_fence(
                    &tx,
                    "g",
                    &r.path,
                    "eager_content_write",
                    1,
                )
                .unwrap();
                let t6 = Instant::now();
                tx.execute_batch("RELEASE open_content_write").unwrap();
                let t7 = Instant::now();
                for (slot, d) in totals.iter_mut().zip([
                    t1 - t0,
                    t2 - t1,
                    t3 - t2,
                    t4 - t3,
                    t5 - t4,
                    t6 - t5,
                    t7 - t6,
                ]) {
                    *slot += d;
                }
            }
            let c0 = Instant::now();
            tx.commit().unwrap();
            let _ = c0;
        }
        let files = (batches * per_batch) as f64;
        let names = [
            "SAVEPOINT",
            "begin intent",
            "set tmp path",
            "upsert file",
            "set state + clear held",
            "bump fence",
            "RELEASE",
        ];
        println!("whole run {:?} for {} files", started.elapsed(), files);
        for (name, total) in names.iter().zip(totals) {
            println!("{:>24}: {:7.1} us per file", name, total.as_secs_f64() * 1e6 / files);
        }
    }

    /// Measurement, not a test: the wall time of the production batch open (32 files in one
    /// `write_immediate`) on a file-backed database with `synchronous = FULL`, as the daemon runs,
    /// with the connection's `wal_autocheckpoint` left alone and switched off. Run with
    /// `--ignored --nocapture`, release profile; `YL_BENCH_DB_DIR` picks the disk.
    #[test]
    #[ignore = "measurement"]
    fn open_batch_wall_on_a_file_backed_database() {
        use std::time::{Duration, Instant};
        let dir = match std::env::var_os("YL_BENCH_DB_DIR") {
            Some(dir) => std::path::PathBuf::from(dir),
            None => std::env::temp_dir(),
        };
        let hash = vec![9u8; 32];
        for (label, setup) in [
            ("default (autocheckpoint 1000 pages)", ""),
            ("wal_autocheckpoint = 0", "PRAGMA wal_autocheckpoint = 0"),
        ] {
            let path = dir.join(format!("open-batch-{}-{}.db", std::process::id(), label.len()));
            let db = yadorilink_sqlite_runtime::SyncDatabase::open(path.clone(), |conn| {
                crate::replica_tables::init_for_tests(conn).map_err(|e| {
                    yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string())
                })
            })
            .unwrap();
            if !setup.is_empty() {
                db.write_immediate::<_, SyncSqliteError>(|tx| {
                    tx.execute_batch(setup)?;
                    Ok(())
                })
                .unwrap();
            }
            let mut times: Vec<Duration> = Vec::new();
            for batch in 0..312usize {
                let records: Vec<FileRecord> = (0..32)
                    .map(|i| {
                        let n = batch * 32 + i;
                        record(&format!("d{:03}/f{:05}.bin", n / 100, n))
                    })
                    .collect();
                let requests: Vec<OpenWriteRequest<'_>> =
                    records.iter().map(|r| request(r, &hash)).collect();
                let started = Instant::now();
                db.write_immediate::<_, SyncSqliteError>(|tx| {
                    open_content_writes_in_tx(tx, &requests, |_| Ok(()))
                })
                .unwrap();
                times.push(started.elapsed());
            }
            let sum: Duration = times.iter().sum();
            times.sort();
            let at = |q: f64| times[((times.len() - 1) as f64 * q) as usize];
            println!(
                "{label}: total {:?}, mean {:?}, p50 {:?}, p90 {:?}, p99 {:?}, max {:?}",
                sum,
                sum / times.len() as u32,
                at(0.5),
                at(0.9),
                at(0.99),
                times[times.len() - 1]
            );
            drop(db);
            for suffix in ["", "-wal", "-shm"] {
                let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
            }
        }
    }
}
