#![cfg(test)]

//! A block list that cannot be read back is refused when a row is written, and one that was
//! damaged afterwards is found by the audit.

use super::*;
use yadorilink_replica_domain::file::BlockInfo;

const GROUP: &str = "g";

fn db() -> Arc<SyncDatabase> {
    crate::replica_tables::open_for_tests()
}

fn block(size: u32, offset: u64) -> BlockInfo {
    BlockInfo { hash: vec![7; 32], offset, size }
}

fn record(path: &str, size: u64, blocks: Vec<BlockInfo>) -> FileRecord {
    FileRecord { path: path.into(), size, mtime_unix_nanos: 1, blocks, deleted: false }
}

fn upsert(db: &SyncDatabase, record: &FileRecord) -> Result<(), SyncSqliteError> {
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        upsert_file_in_tx(tx, GROUP, record, "device-a", crate::retention::Retention::OwnEdit)
    })
}

fn paths(damaged: &[DamagedRow]) -> Vec<&str> {
    damaged.iter().map(|d| d.path.as_str()).collect()
}

fn damaged_row(db: &SyncDatabase, path: &str) -> DamagedRow {
    DamagedRow { rowid: rowid_of(db, path), group_id: GROUP.into(), path: path.into() }
}

fn rowid_of(db: &SyncDatabase, path: &str) -> i64 {
    db.read::<_, SyncSqliteError>(|conn| {
        Ok(conn.query_row(
            "SELECT rowid FROM files WHERE path = ?1 AND state = 'current'",
            [path],
            |r| r.get(0),
        )?)
    })
    .unwrap()
}

fn rows(db: &SyncDatabase) -> i64 {
    db.read::<_, SyncSqliteError>(|conn| {
        Ok(conn.query_row("SELECT COUNT(*) FROM files", [], |r| r.get(0))?)
    })
    .unwrap()
}

fn damage(db: &SyncDatabase, path: &str, blocks_json: &str) {
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "UPDATE files SET blocks_json = ?1 WHERE path = ?2",
            rusqlite::params![blocks_json, path],
        )?;
        Ok(())
    })
    .unwrap();
}

#[test]
fn a_block_list_that_does_not_add_up_is_refused_and_leaves_no_row() {
    let db = db();
    // Sizes of 4 and 4 for a file of 10 bytes.
    let short = record("short", 10, vec![block(4, 0), block(4, 4)]);
    let zero = record("zero", 4, vec![block(4, 0), block(0, 4)]);
    for refused in [&short, &zero] {
        let error = upsert(&db, refused).unwrap_err();
        assert!(matches!(error, SyncSqliteError::InvalidInput(_)), "{error}");
    }
    assert_eq!(rows(&db), 0, "a refused write stores nothing");
}

#[test]
fn a_block_list_that_adds_up_and_an_empty_one_are_stored() {
    let db = db();
    upsert(&db, &record("file", 8, vec![block(4, 0), block(4, 4)])).unwrap();
    // A symlink or directory carries no blocks whatever its size says.
    upsert(&db, &record("link", 12, Vec::new())).unwrap();
    assert_eq!(rows(&db), 2);
}

#[test]
fn the_audit_finds_every_damaged_live_row_and_pages_through_the_table() {
    let db = db();
    let files = FileIndexRepository::new(db.clone());
    for name in ["a", "b", "c", "d"] {
        upsert(&db, &record(name, 4, vec![block(4, 0)])).unwrap();
    }
    damage(&db, "b", "[{\"hash\"");
    // Valid JSON that no longer adds up to the file's size.
    damage(&db, "d", &serde_json::to_string(&vec![block(3, 0)]).unwrap());

    let first = files.audit_live_block_lists(0, 2).unwrap();
    assert_eq!(paths(&first.damaged), ["b"]);
    let cursor = first.next_rowid.expect("more rows follow a full step");
    let second = files.audit_live_block_lists(cursor, 2).unwrap();
    assert_eq!(paths(&second.damaged), ["d"]);
    // A step that fills its limit cannot tell it read the last row; the next one finds out.
    let third = files.audit_live_block_lists(second.next_rowid.unwrap(), 2).unwrap();
    assert!(third.damaged.is_empty());
    assert_eq!(third.next_rowid, None, "the table's end was reached");
}

#[test]
fn a_damaged_row_reads_as_repaired_once_it_is_valid_or_no_longer_live() {
    let db = db();
    let files = FileIndexRepository::new(db.clone());
    upsert(&db, &record("a", 4, vec![block(4, 0)])).unwrap();
    assert!(!files.live_block_list_damaged(&damaged_row(&db, "a")).unwrap());
    damage(&db, "a", "not json");
    assert!(files.live_block_list_damaged(&damaged_row(&db, "a")).unwrap());
    // A row that is not live is not a damaged one.
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute("UPDATE files SET deleted = 1 WHERE path = 'a'", [])?;
        Ok(())
    })
    .unwrap();
    assert!(!files.live_block_list_damaged(&damaged_row(&db, "a")).unwrap());
    assert!(files.audit_live_block_lists(0, 10).unwrap().damaged.is_empty());
    // Repaired in place.
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute("UPDATE files SET deleted = 0 WHERE path = 'a'", [])?;
        Ok(())
    })
    .unwrap();
    damage(&db, "a", &serde_json::to_string(&vec![block(4, 0)]).unwrap());
    assert!(!files.live_block_list_damaged(&damaged_row(&db, "a")).unwrap());
}

fn tombstone(path: &str) -> FileRecord {
    FileRecord {
        path: path.into(),
        size: 4,
        mtime_unix_nanos: 2,
        blocks: Vec::new(),
        deleted: true,
    }
}

/// The ways out of a damaged row stay open: deleting it, and writing a correct record over it.
#[test]
fn a_damaged_row_can_be_deleted_and_overwritten() {
    let not_json = "[{\"hash\"".to_string();
    // Valid JSON that no longer adds up to the file's size of 4.
    let does_not_add_up = serde_json::to_string(&vec![block(3, 0)]).unwrap();
    for damage_with in [not_json, does_not_add_up] {
        let db = db();
        let files = FileIndexRepository::new(db.clone());
        upsert(&db, &record("a", 4, vec![block(4, 0)])).unwrap();
        upsert(&db, &record("b", 4, vec![block(4, 0)])).unwrap();
        damage(&db, "a", &damage_with);
        damage(&db, "b", &damage_with);
        let (old_a, old_b) = (damaged_row(&db, "a"), damaged_row(&db, "b"));
        assert!(files.live_block_list_damaged(&old_a).unwrap(), "{damage_with}");
        assert!(files.live_block_list_damaged(&old_b).unwrap(), "{damage_with}");

        // Deleted: the tombstone is written although the row it replaces is damaged.
        upsert(&db, &tombstone("a")).unwrap();
        assert!(!files.live_block_list_damaged(&old_a).unwrap());
        // Overwritten with the right content.
        upsert(&db, &record("b", 4, vec![block(4, 0)])).unwrap();
        assert!(!files.live_block_list_damaged(&old_b).unwrap());
        assert!(!files.live_block_list_damaged(&damaged_row(&db, "b")).unwrap());
        assert!(files.audit_live_block_lists(0, 10).unwrap().damaged.is_empty());
    }
}

#[test]
fn a_value_the_database_cannot_hand_back_as_text_is_damage_and_does_not_stop_the_walk() {
    let db = db();
    let files = FileIndexRepository::new(db.clone());
    for name in ["a", "b", "c"] {
        upsert(&db, &record(name, 4, vec![block(4, 0)])).unwrap();
    }
    db.write::<_, SyncSqliteError>(|conn| {
        // Invalid UTF-8 in "b", a blob in "a".
        conn.execute(
            "UPDATE files SET blocks_json = CAST(X'5B7BFF' AS TEXT) WHERE path = 'b'",
            [],
        )?;
        conn.execute("UPDATE files SET blocks_json = X'5B5D' WHERE path = 'a'", [])?;
        Ok(())
    })
    .unwrap();
    let audit = files.audit_live_block_lists(0, 10).unwrap();
    assert_eq!(paths(&audit.damaged), ["a", "b"], "the rows after a damaged one are still read");
    assert!(files.live_block_list_damaged(&damaged_row(&db, "b")).unwrap());
}

fn identity() -> yadorilink_replica_domain::native_plan::NativeRowIdentity {
    use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
    use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, SyncPath};
    use yadorilink_replica_domain::native_state::{DeltaHash, Dot};
    yadorilink_replica_domain::native_plan::NativeRowIdentity {
        source_path: SyncPath("x".into()),
        dot: Dot {
            author: AuthorId {
                device: DeviceId("device-a".into()),
                incarnation: IncarnationId([1; 16]),
            },
            seq: AuthorSeq(1),
        },
        provenance: DeltaHash([1; 32]),
    }
}

#[test]
fn rows_inserted_for_new_paths_are_checked_like_any_other_write() {
    let db = db();
    let bad = record("bad", 10, vec![block(4, 0)]);
    let good = record("good", 4, vec![block(4, 0)]);
    let (meta, identity) = (
        LocalFileMetaColumns {
            record_kind: yadorilink_replica_domain::file::RecordKind::File,
            symlink_target: None,
            symlink_out_of_root: false,
            exec: false,
        },
        identity(),
    );
    let row =
        |record| crate::new_path_rows::NewPathRow { record, meta: &meta, identity: &identity };
    let error = db
        .write_immediate::<_, SyncSqliteError>(|tx| {
            crate::new_path_rows::insert_hydrated_rows(
                tx,
                GROUP,
                "device-a",
                &[row(&good), row(&bad)],
            )
        })
        .unwrap_err();
    assert!(matches!(error, SyncSqliteError::InvalidInput(_)), "{error}");
    assert_eq!(rows(&db), 0, "the batch is refused whole");
}

#[test]
fn a_rowid_that_now_holds_another_row_is_not_the_damaged_one() {
    let db = db();
    let files = FileIndexRepository::new(db.clone());
    upsert(&db, &record("a", 4, vec![block(4, 0)])).unwrap();
    damage(&db, "a", "not json");
    let recorded = damaged_row(&db, "a");
    assert!(files.live_block_list_damaged(&recorded).unwrap());
    // The same rowid, now another path (as when SQLite reuses the rowid of a deleted row) and
    // another group.
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute("UPDATE files SET path = 'z' WHERE path = 'a'", [])?;
        Ok(())
    })
    .unwrap();
    assert!(!files.live_block_list_damaged(&recorded).unwrap());
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute("UPDATE files SET path = 'a', group_id = 'other' WHERE path = 'z'", [])?;
        Ok(())
    })
    .unwrap();
    assert!(!files.live_block_list_damaged(&recorded).unwrap());
}
