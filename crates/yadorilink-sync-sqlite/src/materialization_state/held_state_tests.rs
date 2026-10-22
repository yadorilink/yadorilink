#![cfg(test)]

use super::*;

/// Full schema: the replica tables first, then
/// `yadorilink_sqlite_runtime::init_schema` (the real `files` table).
fn open_full_test_db() -> Arc<SyncDatabase> {
    Arc::new(
        SyncDatabase::open_in_memory(|conn| {
            crate::replica_tables::init_for_tests(conn).map_err(|e| {
                yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string())
            })?;
            yadorilink_sqlite_runtime::init_schema(conn)
        })
        .expect("open in-memory db"),
    )
}

fn seed_file_row(conn: &rusqlite::Connection, group_id: &str, path: &str) {
    conn.execute(
        "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json) \
         VALUES (?1, ?2, 0, 0, '[]')",
        rusqlite::params![group_id, path],
    )
    .unwrap();
}

/// Only currently-held paths in the requested group are listed -- an
/// unheld path, and a held path from a DIFFERENT group, must not leak
/// in.
#[test]
fn lists_only_currently_held_paths_in_the_requested_group() {
    let db = open_full_test_db();
    db.write::<_, SyncSqliteError>(|conn| {
        seed_file_row(conn, "group-1", "held.txt");
        seed_file_row(conn, "group-1", "not-held.txt");
        seed_file_row(conn, "group-2", "held-in-other-group.txt");
        Ok(())
    })
    .unwrap();
    let repo = MaterializationStateRepository::new(db);
    repo.set_held("group-1", "held.txt", "case_collision", 1000).unwrap();
    repo.set_held("group-2", "held-in-other-group.txt", "case_collision", 1000).unwrap();

    assert_eq!(repo.list_held_paths("group-1").unwrap(), vec!["held.txt".to_string()]);
}

/// Once a hold is cleared, the path must disappear from the listing --
/// otherwise a sweep built on this method would keep re-visiting a path
/// that no longer needs it.
#[test]
fn a_cleared_hold_disappears_from_the_listing() {
    let db = open_full_test_db();
    db.write::<_, SyncSqliteError>(|conn| {
        seed_file_row(conn, "group-1", "was-held.txt");
        Ok(())
    })
    .unwrap();
    let repo = MaterializationStateRepository::new(db);
    repo.set_held("group-1", "was-held.txt", "case_collision", 1000).unwrap();
    assert_eq!(repo.list_held_paths("group-1").unwrap(), vec!["was-held.txt".to_string()]);

    repo.clear_held("group-1", "was-held.txt").unwrap();

    assert!(repo.list_held_paths("group-1").unwrap().is_empty());
}

/// A keyed hold's key is readable while it stands and goes with it: a
/// cleared hold, and a hold re-set for a reason recorded without a key,
/// must not leave a stale key behind for a later hold to be compared
/// against.
#[test]
fn a_hold_key_lives_and_dies_with_its_hold() {
    let db = open_full_test_db();
    db.write::<_, SyncSqliteError>(|conn| {
        seed_file_row(conn, "group-1", "write-only.txt");
        Ok(())
    })
    .unwrap();
    let repo = MaterializationStateRepository::new(db);
    assert_eq!(repo.get_held_key("group-1", "write-only.txt").unwrap(), None);

    repo.set_held_with_key("group-1", "write-only.txt", "metadata_unprovable", 1000, Some("k1"))
        .unwrap();
    assert_eq!(repo.get_held_key("group-1", "write-only.txt").unwrap().as_deref(), Some("k1"));
    assert_eq!(
        repo.get_held_state("group-1", "write-only.txt").unwrap().map(|held| held.reason),
        Some("metadata_unprovable".to_string())
    );

    repo.set_held("group-1", "write-only.txt", "case_collision", 2000).unwrap();
    assert_eq!(
        repo.get_held_key("group-1", "write-only.txt").unwrap(),
        None,
        "a hold recorded without a key must not inherit the previous hold's"
    );

    repo.set_held_with_key("group-1", "write-only.txt", "metadata_unprovable", 3000, Some("k2"))
        .unwrap();
    repo.clear_held("group-1", "write-only.txt").unwrap();
    assert_eq!(repo.get_held_key("group-1", "write-only.txt").unwrap(), None);
}
