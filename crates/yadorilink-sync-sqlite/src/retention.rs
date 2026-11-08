//! What a supersede must be shown before it may stop a version being current.
//!
//! A version's bytes are kept by the block store, and the store no longer receives a copy of every
//! version that is captured or received. So a row that a **sync** makes stop being current must
//! come with a [`RetentionProof`] for the version it replaces: either the version's bytes are in
//! the store (verified), or this device never had them. The transaction that flips the row checks
//! the proof against the row it actually finds, so a proof made for a row the path has since moved
//! on from is refused, and a caller that has no proof cannot call the write at all.
//!
//! A device's own edit is the exception the owner decided on: the version an edit replaces is not
//! guaranteed ([`Retention::OwnEdit`]).

use std::collections::HashMap;

use rusqlite::Transaction;
use yadorilink_replica_domain::file::BlockInfo;
use yadorilink_replica_domain::ids::VersionHash;

use crate::error::SyncSqliteError;

/// The row a proof is about: the exact row, not only its content. A path that goes from version A to
/// B and back to an identical A has the same content hash twice and a different `version_seq`, and
/// a row that eviction has turned `Remote` is no longer the row that was `Present`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupersededRow {
    pub version_seq: i64,
    pub version_hash: VersionHash,
    pub materialization_state: String,
}

/// Why the bytes of the version being replaced are accounted for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetentionProof {
    /// Every block of the version is in the block store, verified, with the group's provenance.
    InStore(SupersededRow),
    /// This device never held the bytes of the version (a placeholder, a row committed without its
    /// content, a version evicted after a custody confirmation): nothing of it is here to keep.
    NoLocalBytes(SupersededRow),
    /// Keeping the version was given up: the disk has no room for the bytes that keeping it would
    /// add, and nothing protects the version (no pin, no lease). The supersede then retains no row
    /// for it and records the gap instead (see [`crate::history_freed`]). Only the version being
    /// replaced is given up; no other version and no byte is removed.
    Skipped { row: SupersededRow, reason: SkipReason },
}

/// Why keeping a version was given up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// The volume's free space is at or below its headroom once the ingest is counted.
    LowSpace,
}

impl RetentionProof {
    fn row(&self) -> &SupersededRow {
        match self {
            RetentionProof::InStore(row)
            | RetentionProof::NoLocalBytes(row)
            | RetentionProof::Skipped { row, .. } => row,
        }
    }
}

/// What the supersede does with the row it replaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Supersede {
    /// The replaced row stays as history (`superseded` or `trashed`).
    Retain,
    /// The replaced row is not kept; the gap is recorded in the same transaction.
    GiveUp(SkipReason),
}

/// The proofs for the paths one write replaces, by path.
#[derive(Debug, Default, Clone)]
pub struct RetentionProofs {
    by_path: HashMap<String, RetentionProof>,
}

impl RetentionProofs {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, path: impl Into<String>, proof: RetentionProof) {
        self.by_path.insert(path.into(), proof);
    }

    fn get(&self, path: &str) -> Option<&RetentionProof> {
        self.by_path.get(path)
    }
}

/// What a write that replaces the current row of a path says about the replaced version.
#[derive(Debug, Clone, Copy)]
pub enum Retention<'a> {
    /// This device's own act replaces the version (an edit, a delete, a restore or a rewind the
    /// user asked for): it is not guaranteed (the owner's decision), so nothing is asked for.
    OwnEdit,
    /// The link keeps its content in the block store and nowhere else (a provider link: the
    /// operating system's provider fetches from the store), so the replaced version's bytes stay in
    /// the store as long as its row is retained, and there is no file of the daemon's to read them
    /// from. Nothing is asked for.
    StoreBacked,
    /// A sync replaces the version: every replaced row that holds bytes needs its proof.
    Proofs(&'a RetentionProofs),
}

/// The current row of `path` as a proof describes it, and whether the version has bytes to keep (a
/// live regular file with at least one block). `None` when the path has no current row, or only a
/// bootstrap scaffold.
pub fn current_row_for_retention(
    tx: &rusqlite::Connection,
    group_id: &str,
    path: &str,
) -> Result<Option<(SupersededRow, bool, Vec<BlockInfo>)>, SyncSqliteError> {
    use rusqlite::OptionalExtension;
    let row = tx
        .prepare_cached(
            "SELECT version_seq, size, mtime_unix_nanos, blocks_json, deleted, record_kind, \
                    symlink_target, exec, materialization_state \
             FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
        )?
        .query_row(rusqlite::params![group_id, path], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, u64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<Vec<u8>>>(6)?,
                r.get::<_, i64>(7)?,
                r.get::<_, String>(8)?,
            ))
        })
        .optional()?;
    let Some((version_seq, size, mtime, blocks_json, deleted, kind, symlink_target, exec, state)) =
        row
    else {
        return Ok(None);
    };
    // A scaffold is not a genuine version.
    if version_seq == 0 {
        return Ok(None);
    }
    let record = crate::file_index::version_record(
        path.to_string(),
        version_seq,
        size,
        mtime,
        &blocks_json,
        deleted,
        "current",
        None,
        &kind,
        symlink_target,
        exec,
    )?;
    let holds_bytes = deleted == 0
        && record.record_kind == yadorilink_replica_domain::file::RecordKind::File
        && !record.blocks.is_empty();
    let key = SupersededRow {
        version_seq,
        version_hash: record.version_hash,
        materialization_state: state,
    };
    Ok(Some((key, holds_bytes, record.blocks)))
}

impl crate::file_index::FileIndexRepository {
    /// [`current_row_for_retention`] for a caller that is about to make a proof, outside any
    /// transaction of its own: the row as it stands now. The write that uses the proof reads the
    /// row again inside its transaction and refuses the proof if the row has moved on.
    pub fn current_row_for_retention(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<(SupersededRow, bool, Vec<BlockInfo>)>, SyncSqliteError> {
        self.database()
            .read::<_, SyncSqliteError>(|conn| current_row_for_retention(conn, group_id, path))
    }
}

/// Refuses a write that would make the current row of `path` stop being current without the proof
/// its kind of write needs. `new_blocks` is the block list of the version being written.
///
/// A write that keeps the same block list keeps the bytes: the new row is the version that holds
/// them, and it is proved when it in turn is replaced.
///
/// A `Skipped` proof is honoured only while the version is still unprotected: a pin or a lease
/// that appeared after the proof was made is read here, inside the transaction, and discards the
/// proof like any other change of the row (the caller makes a new one, and a protected version is
/// kept, never skipped).
pub(crate) fn check_before_supersede(
    tx: &Transaction<'_>,
    group_id: &str,
    path: &str,
    new_blocks: &[BlockInfo],
    retention: Retention<'_>,
) -> Result<Supersede, SyncSqliteError> {
    let Retention::Proofs(proofs) = retention else { return Ok(Supersede::Retain) };
    // `OwnEdit` and `StoreBacked` ask for nothing (see their documentation).
    let Some((row, holds_bytes, old_blocks)) = current_row_for_retention(tx, group_id, path)?
    else {
        return Ok(Supersede::Retain);
    };
    if !holds_bytes || old_blocks == new_blocks {
        return Ok(Supersede::Retain);
    }
    let stale = || SyncSqliteError::RetentionProofStale {
        group_id: group_id.to_string(),
        path: path.to_string(),
    };
    match proofs.get(path) {
        None => Err(SyncSqliteError::RetentionProofMissing {
            group_id: group_id.to_string(),
            path: path.to_string(),
        }),
        Some(proof) if proof.row() != &row => Err(stale()),
        Some(RetentionProof::Skipped { reason, .. }) => {
            if version_is_protected(tx, group_id, path)? {
                Err(stale())
            } else {
                Ok(Supersede::GiveUp(*reason))
            }
        }
        Some(_) => Ok(Supersede::Retain),
    }
}

/// Whether the versions of `path` are protected from being given up: the path (or a folder above
/// it) is pinned, or an active handoff lease names a version of it. The same question the
/// capture side asks (`must_keep_in_store`), answered from the index so it can be read inside the
/// transaction that supersedes the row.
fn version_is_protected(
    tx: &Transaction<'_>,
    group_id: &str,
    path: &str,
) -> Result<bool, SyncSqliteError> {
    if crate::retention_rules::read_rules(tx, group_id)?.is_kept(path) {
        return Ok(true);
    }
    let now_unix_seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0);
    let leases: Vec<String> = tx
        .prepare_cached(
            "SELECT pinned_versions_json FROM handoff_leases \
             WHERE group_id = ?1 AND state IN ('provisional', 'confirmed') \
               AND expires_at_unix > ?2",
        )?
        .query_map(rusqlite::params![group_id, now_unix_seconds], |r| r.get::<_, String>(0))?
        .collect::<Result<_, _>>()?;
    for json in leases {
        let versions: Vec<crate::handoff_lease::PinnedVersion> = serde_json::from_str(&json)?;
        if versions.iter().any(|(leased_path, _)| leased_path == path) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use yadorilink_replica_domain::file::{BlockInfo, FileRecord};

    use super::*;
    use crate::file_index::upsert_file_in_tx;
    use yadorilink_sqlite_runtime::SyncDatabase;

    const GROUP: &str = "g";

    fn db() -> Arc<SyncDatabase> {
        crate::replica_tables::open_for_tests()
    }

    fn block(tag: u8) -> BlockInfo {
        BlockInfo { hash: vec![tag; 32], offset: 0, size: 4 }
    }

    fn file(path: &str, tag: u8) -> FileRecord {
        FileRecord {
            path: path.into(),
            size: 4,
            mtime_unix_nanos: i64::from(tag),
            blocks: vec![block(tag)],
            deleted: false,
        }
    }

    fn tombstone(path: &str) -> FileRecord {
        FileRecord {
            path: path.into(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: Vec::new(),
            deleted: true,
        }
    }

    fn write(
        db: &SyncDatabase,
        record: &FileRecord,
        retention: Retention<'_>,
    ) -> Result<(), SyncSqliteError> {
        db.write_immediate::<_, SyncSqliteError>(|tx| {
            upsert_file_in_tx(tx, GROUP, record, "dev", retention)
        })
    }

    fn current_row(db: &SyncDatabase, path: &str) -> (SupersededRow, bool) {
        // The same read the write does, through a write transaction of its own.
        let mut found = None;
        db.write_immediate::<_, SyncSqliteError>(|tx| {
            found = current_row_for_retention(tx, GROUP, path)?.map(|(row, holds, _)| (row, holds));
            Ok(())
        })
        .unwrap();
        found.expect("the path has a current row")
    }

    fn rows(db: &SyncDatabase, path: &str) -> i64 {
        db.read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM files WHERE group_id = ?1 AND path = ?2",
                rusqlite::params![GROUP, path],
                |row| row.get(0),
            )?)
        })
        .unwrap()
    }

    fn in_store(db: &SyncDatabase, path: &str) -> RetentionProofs {
        let (row, _) = current_row(db, path);
        let mut proofs = RetentionProofs::new();
        proofs.insert(path, RetentionProof::InStore(row));
        proofs
    }

    #[test]
    fn a_sync_replacing_a_file_with_bytes_needs_a_proof_and_without_one_nothing_is_written() {
        let db = db();
        write(&db, &file("a", 1), Retention::OwnEdit).unwrap();
        let none = RetentionProofs::new();

        let refused = write(&db, &file("a", 2), Retention::Proofs(&none));

        assert!(
            matches!(refused, Err(SyncSqliteError::RetentionProofMissing { .. })),
            "{refused:?}"
        );
        assert_eq!(rows(&db, "a"), 1, "the refused write changed nothing");
    }

    #[test]
    fn a_proof_for_the_current_row_lets_the_replacement_through() {
        let db = db();
        write(&db, &file("a", 1), Retention::OwnEdit).unwrap();
        let proofs = in_store(&db, "a");

        write(&db, &file("a", 2), Retention::Proofs(&proofs)).unwrap();

        assert_eq!(rows(&db, "a"), 2);
    }

    #[test]
    fn a_proof_that_says_nothing_of_the_version_was_held_here_is_accepted_too() {
        let db = db();
        write(&db, &file("a", 1), Retention::OwnEdit).unwrap();
        let (row, _) = current_row(&db, "a");
        let mut proofs = RetentionProofs::new();
        proofs.insert("a", RetentionProof::NoLocalBytes(row));

        write(&db, &file("a", 2), Retention::Proofs(&proofs)).unwrap();
    }

    /// The path went from version A to B and back to an identical A while the proof was being
    /// made: the content hash is the same twice and the row is not.
    #[test]
    fn a_proof_made_for_an_earlier_row_with_the_same_content_is_stale() {
        let db = db();
        write(&db, &file("a", 1), Retention::OwnEdit).unwrap();
        let proofs = in_store(&db, "a");
        write(&db, &file("a", 2), Retention::OwnEdit).unwrap();
        write(&db, &file("a", 1), Retention::OwnEdit).unwrap();

        let refused = write(&db, &file("a", 3), Retention::Proofs(&proofs));

        assert!(matches!(refused, Err(SyncSqliteError::RetentionProofStale { .. })), "{refused:?}");
        assert_eq!(rows(&db, "a"), 3);
    }

    /// Eviction turned the row `Remote` between the proof and the write.
    #[test]
    fn a_proof_made_while_the_row_was_present_is_stale_once_it_is_no_longer() {
        let db = db();
        write(&db, &file("a", 1), Retention::OwnEdit).unwrap();
        let (row, _) = current_row(&db, "a");
        let mut proofs = RetentionProofs::new();
        proofs.insert("a", RetentionProof::InStore(row.clone()));
        let other_state = if row.materialization_state == "remote" { "present" } else { "remote" };
        db.write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute(
                "UPDATE files SET materialization_state = ?2 \
                 WHERE group_id = ?1 AND path = 'a' AND state = 'current'",
                rusqlite::params![GROUP, other_state],
            )?;
            Ok(())
        })
        .unwrap();

        let refused = write(&db, &file("a", 2), Retention::Proofs(&proofs));

        assert!(matches!(refused, Err(SyncSqliteError::RetentionProofStale { .. })), "{refused:?}");
    }

    #[test]
    fn a_replacement_that_keeps_the_same_blocks_keeps_the_bytes_and_needs_no_proof() {
        let db = db();
        write(&db, &file("a", 1), Retention::OwnEdit).unwrap();
        let mut again = file("a", 1);
        again.mtime_unix_nanos = 99;
        let none = RetentionProofs::new();

        write(&db, &again, Retention::Proofs(&none)).unwrap();
    }

    #[test]
    fn replacing_a_tombstone_or_an_empty_file_needs_no_proof() {
        let db = db();
        write(&db, &tombstone("gone"), Retention::OwnEdit).unwrap();
        write(&db, &file("empty", 0), Retention::OwnEdit).unwrap();
        let mut empty_again = file("empty", 0);
        empty_again.blocks.clear();
        empty_again.size = 0;
        write(&db, &empty_again, Retention::OwnEdit).unwrap();
        let none = RetentionProofs::new();

        write(&db, &file("gone", 5), Retention::Proofs(&none)).unwrap();
        write(&db, &file("empty", 6), Retention::Proofs(&none)).unwrap();
    }

    #[test]
    fn a_new_path_needs_no_proof() {
        let db = db();
        let none = RetentionProofs::new();

        write(&db, &file("brand-new", 1), Retention::Proofs(&none)).unwrap();
    }

    #[test]
    fn an_own_edit_and_a_store_backed_link_ask_for_nothing() {
        let db = db();
        write(&db, &file("a", 1), Retention::OwnEdit).unwrap();

        write(&db, &file("a", 2), Retention::OwnEdit).unwrap();
        write(&db, &file("a", 3), Retention::StoreBacked).unwrap();

        assert_eq!(rows(&db, "a"), 3);
    }

    fn skipped(db: &SyncDatabase, path: &str) -> RetentionProofs {
        let (row, _) = current_row(db, path);
        let mut proofs = RetentionProofs::new();
        proofs.insert(path, RetentionProof::Skipped { row, reason: SkipReason::LowSpace });
        proofs
    }

    fn versions(db: &SyncDatabase, path: &str) -> Vec<(i64, String)> {
        db.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT version_seq, state FROM files WHERE group_id = ?1 AND path = ?2 \
                 ORDER BY version_seq",
            )?;
            let rows = stmt
                .query_map(rusqlite::params![GROUP, path], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .unwrap()
    }

    fn freed(db: &SyncDatabase, path: &str) -> Vec<crate::history_freed::FreedSpan> {
        db.read::<_, SyncSqliteError>(|conn| {
            Ok(crate::history_freed::spans_by_path(conn, GROUP)?.remove(path).unwrap_or_default())
        })
        .unwrap()
    }

    /// Three versions, the second of which a skipped supersede replaces.
    fn history_with_a_skipped_second_version(db: &SyncDatabase) {
        write(db, &file("a", 1), Retention::OwnEdit).unwrap();
        write(db, &file("a", 2), Retention::OwnEdit).unwrap();
        let proofs = skipped(db, "a");
        write(db, &file("a", 3), Retention::Proofs(&proofs)).unwrap();
    }

    #[test]
    fn a_skipped_version_leaves_no_row_but_one_record_and_no_other_version_goes() {
        let db = db();

        history_with_a_skipped_second_version(&db);

        // Version 1 stays; version 2 is not kept; version 3 is current (numbered after 2).
        assert_eq!(
            versions(&db, "a"),
            vec![(1, "superseded".to_string()), (3, "current".to_string())]
        );
        let spans = freed(&db, "a");
        assert_eq!(spans.len(), 1, "one event, one row: {spans:?}");
        let span = &spans[0];
        assert_eq!(span.reason, crate::history_freed::FreedReason::LowSpace);
        assert_eq!((span.from_seq, span.to_seq), (2, 3));
        assert!(span.covers_seq(2) && !span.covers_seq(1) && !span.covers_seq(3));
    }

    #[test]
    fn rewind_and_restore_inside_a_skipped_span_say_the_disk_was_nearly_full() {
        use yadorilink_replica_domain::rewind::{RewindPathAction, RewindUnavailableReason};
        let db = db();
        history_with_a_skipped_second_version(&db);
        let span = freed(&db, "a").remove(0);
        let inside = span.from_unix_nanos.unwrap();

        let plan = db
            .read::<_, SyncSqliteError>(|conn| {
                crate::rewind_plan::compute_rewind_plan(conn, GROUP, inside, &|_| false)
            })
            .unwrap();
        let action = plan.entries.iter().find(|e| e.path == "a").unwrap().action.clone();

        assert_eq!(
            action,
            RewindPathAction::Unavailable { reason: RewindUnavailableReason::NotKeptLowSpace }
        );
        let covering = db
            .read::<_, SyncSqliteError>(|conn| {
                crate::history_freed::span_covering_seq(conn, GROUP, "a", 2)
            })
            .unwrap()
            .expect("version 2 was given up");
        assert_eq!(covering.reason.words(), "the disk was nearly full");
    }

    #[test]
    fn a_pin_or_a_lease_taken_after_the_proof_discards_a_skipped_proof() {
        let db = db();
        write(&db, &file("a", 1), Retention::OwnEdit).unwrap();
        write(&db, &file("b", 1), Retention::OwnEdit).unwrap();
        write(&db, &file("dir/c", 1), Retention::OwnEdit).unwrap();
        let (a, b, c) = (skipped(&db, "a"), skipped(&db, "b"), skipped(&db, "dir/c"));
        db.write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute(
                "INSERT INTO retention_rules (group_id, path, rule, generation, set_at_unix_nanos) VALUES (?1, 'a', 'keep', 1, 0)",
                [GROUP],
            )?;
            tx.execute(
                "INSERT INTO retention_rules (group_id, path, rule, generation, set_at_unix_nanos) VALUES (?1, 'dir', 'keep', 1, 0)",
                [GROUP],
            )?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            tx.execute(
                "INSERT INTO handoff_leases (lease_id, group_id, root_digest, state, \
                 pinned_versions_json, created_at_unix, expires_at_unix) \
                 VALUES ('l', ?1, zeroblob(32), 'confirmed', '[[\"b\",1]]', ?2, ?3)",
                rusqlite::params![GROUP, now, now + 3600],
            )?;
            Ok(())
        })
        .unwrap();

        for (path, proofs) in [("a", &a), ("b", &b), ("dir/c", &c)] {
            let refused = write(&db, &file(path, 2), Retention::Proofs(proofs));
            assert!(
                matches!(refused, Err(SyncSqliteError::RetentionProofStale { .. })),
                "{path}: {refused:?}"
            );
            assert_eq!(rows(&db, path), 1, "{path}: nothing was written");
            assert!(freed(&db, path).is_empty(), "{path}: nothing was recorded");
        }
    }

    #[test]
    fn a_skipped_proof_for_a_row_the_path_moved_on_from_is_stale() {
        let db = db();
        write(&db, &file("a", 1), Retention::OwnEdit).unwrap();
        let proofs = skipped(&db, "a");
        write(&db, &file("a", 2), Retention::OwnEdit).unwrap();

        let refused = write(&db, &file("a", 3), Retention::Proofs(&proofs));

        assert!(matches!(refused, Err(SyncSqliteError::RetentionProofStale { .. })), "{refused:?}");
        assert!(freed(&db, "a").is_empty());
    }

    #[test]
    fn a_skipped_replacement_by_a_deletion_keeps_the_deletion_current() {
        let db = db();
        write(&db, &file("a", 1), Retention::OwnEdit).unwrap();
        let proofs = skipped(&db, "a");

        write(&db, &tombstone("a"), Retention::Proofs(&proofs)).unwrap();

        assert_eq!(versions(&db, "a"), vec![(2, "current".to_string())]);
        assert_eq!(freed(&db, "a").len(), 1);
    }

    #[test]
    fn low_space_events_are_counted_by_when_they_were_recorded() {
        let db = db();
        history_with_a_skipped_second_version(&db);
        let count = |since: i64| {
            db.read::<_, SyncSqliteError>(|conn| {
                crate::history_freed::count_low_space_since(conn, GROUP, since)
            })
            .unwrap()
        };
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
                as i64;

        assert_eq!(count(now - 86_400), 1);
        assert_eq!(
            count(now + 3_600),
            0,
            "an event recorded earlier than the window is not counted"
        );
    }

    #[test]
    fn history_names_a_block_only_while_an_older_version_holds_it() {
        use yadorilink_replica_domain::file::VersionBlock;
        use yadorilink_replica_domain::ids::BlockHash;
        let db = db();
        let repository = crate::file_index::FileIndexRepository::new(db.clone());
        let blocks = |tag: u8| vec![VersionBlock { hash: BlockHash(vec![tag; 32]), size: 4 }];
        write(&db, &file("a", 1), Retention::OwnEdit).unwrap();
        assert!(
            !repository.history_names_any_block(GROUP, "a", &blocks(1)).unwrap(),
            "the current version is not history"
        );

        write(&db, &file("a", 2), Retention::OwnEdit).unwrap();

        assert!(repository.history_names_any_block(GROUP, "a", &blocks(1)).unwrap());
        assert!(!repository.history_names_any_block(GROUP, "a", &blocks(2)).unwrap());
        assert!(!repository.history_names_any_block(GROUP, "other", &blocks(1)).unwrap());
    }

    #[test]
    fn kept_history_counts_blocks_only_older_versions_name_once() {
        let db = db();
        let repository = crate::file_index::FileIndexRepository::new(db.clone());
        // Versions 1 and 2 are history; version 3 is current and names version 2's block again.
        write(&db, &file("a", 1), Retention::OwnEdit).unwrap();
        write(&db, &file("a", 2), Retention::OwnEdit).unwrap();
        write(&db, &file("a", 3), Retention::OwnEdit).unwrap();
        let mut again = file("a", 2);
        again.mtime_unix_nanos = 9;
        write(&db, &again, Retention::OwnEdit).unwrap();
        write(&db, &file("b", 7), Retention::OwnEdit).unwrap();

        // History: a@1 (block 1, only history), a@2 (block 2, now current), a@3 (block 3, only
        // history). Only blocks 1 and 3 are history-only: 2 versions, 2 x 4 bytes.
        assert_eq!(repository.kept_history_usage(&|_| true).unwrap(), (8, 2));

        // A version kept without its bytes (this device never held them) takes no space: with
        // block 1 absent from the store only version 3's block 3 is held history.
        let block_one = vec![1u8; 32];
        assert_eq!(repository.kept_history_usage(&|hash| hash != block_one).unwrap(), (4, 1));
        assert_eq!(repository.kept_history_usage(&|_| false).unwrap(), (0, 0));
    }
}
