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
        retention,
    } = *request;
    MaterializationIntentRepository::begin_materialization_intent_in_tx(
        tx,
        group_id,
        &record.path,
        intent_target_hash,
        now_unix_nanos,
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
            retention: crate::retention::Retention::OwnEdit,
        }
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
}
