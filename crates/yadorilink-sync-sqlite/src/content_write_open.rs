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
/// that order, against its own path, under its own savepoint. Then
/// `verify(index)` runs for that request, which is where the caller checks
/// that request's own root permits (the lane's and the fresh one of the row's
/// operation); it runs whatever the statements did.
///
/// A failing `verify` means a root is no longer this link's, which no item's
/// commit may outlive: it fails the whole call before that item's savepoint
/// is released, so the transaction rolls back and every request keeps its
/// pre-open state. A transient lock inside a request's statements is not that
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
    for (index, request) in requests.iter().enumerate() {
        tx.execute_batch("SAVEPOINT open_content_write")?;
        let outcome = open_content_write_in_tx(tx, request);
        // Whatever the statements did, a lost root fails the whole call.
        verify(index)?;
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
            unix_mode: None,
            xattrs: Vec::new(),
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
}
