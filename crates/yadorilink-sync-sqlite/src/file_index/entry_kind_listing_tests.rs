#![cfg(test)]

//! The trash and conflict listings carry each row's own kind, so a surface
//! can show a directory as a directory.

use super::*;

const GROUP: &str = "g";

fn open_full_test_db() -> Arc<SyncDatabase> {
    Arc::new(
        SyncDatabase::open_in_memory(|conn| {
            crate::replica_tables::init_for_tests(conn).map_err(|e| {
                yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string())
            })?;
            crate::materialized_generation::init_materialized_generation_schema(conn).map_err(
                |e| yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string()),
            )?;
            yadorilink_sqlite_runtime::init_schema(conn)
        })
        .expect("open in-memory db"),
    )
}

fn insert(
    db: &SyncDatabase,
    path: &str,
    version_seq: i64,
    state: &str,
    deleted: bool,
    kind: RecordKind,
) {
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
             version_seq, state, record_kind) VALUES (?1, ?2, 0, 0, '[]', ?3, ?4, ?5, ?6)",
            rusqlite::params![GROUP, path, deleted as i64, version_seq, state, kind.as_db_str()],
        )?;
        Ok(())
    })
    .unwrap();
}

#[test]
fn trashed_rows_carry_the_kind_of_the_trashed_version() {
    let db = open_full_test_db();
    insert(&db, "album", 1, "trashed", false, RecordKind::Directory);
    insert(&db, "album", 2, "current", true, RecordKind::File);
    insert(&db, "notes.txt", 1, "trashed", false, RecordKind::File);
    insert(&db, "notes.txt", 2, "current", true, RecordKind::File);

    let mut kinds: Vec<(String, RecordKind)> = FileIndexRepository::new(db)
        .list_trashed(GROUP)
        .unwrap()
        .into_iter()
        .map(|t| (t.path, t.record_kind))
        .collect();
    kinds.sort_by(|a, b| a.0.cmp(&b.0));

    assert_eq!(
        kinds,
        [("album".to_string(), RecordKind::Directory), ("notes.txt".into(), RecordKind::File)]
    );
}

#[test]
fn live_conflict_copies_carry_their_kind() {
    let db = open_full_test_db();
    insert(
        &db,
        "album (conflicted copy, 2026-01-01-000000, device-b)",
        1,
        "current",
        false,
        RecordKind::Directory,
    );
    insert(
        &db,
        "latest (conflicted copy, 2026-01-01-000000, device-b)",
        1,
        "current",
        false,
        RecordKind::Symlink,
    );

    let mut kinds: Vec<(String, RecordKind)> = FileIndexRepository::new(db)
        .list_live_conflict_copies(GROUP)
        .unwrap()
        .into_iter()
        .map(|c| (c.path, c.record_kind))
        .collect();
    kinds.sort_by(|a, b| a.0.cmp(&b.0));

    assert_eq!(
        kinds,
        [
            (
                "album (conflicted copy, 2026-01-01-000000, device-b)".to_string(),
                RecordKind::Directory
            ),
            ("latest (conflicted copy, 2026-01-01-000000, device-b)".into(), RecordKind::Symlink),
        ]
    );
}

#[test]
fn current_entries_are_the_live_current_rows_with_their_kind_in_path_order() {
    let db = open_full_test_db();
    insert(&db, "b", 1, "current", false, RecordKind::File);
    insert(&db, "a", 1, "current", false, RecordKind::Directory);
    insert(&db, "gone", 1, "current", true, RecordKind::File);
    insert(&db, "old", 1, "trashed", false, RecordKind::File);

    let entries = FileIndexRepository::new(db).list_current_entries(GROUP).unwrap();

    let listed: Vec<(&str, RecordKind)> =
        entries.iter().map(|e| (e.path.as_str(), e.kind)).collect();
    assert_eq!(listed, [("a", RecordKind::Directory), ("b", RecordKind::File)]);
}
