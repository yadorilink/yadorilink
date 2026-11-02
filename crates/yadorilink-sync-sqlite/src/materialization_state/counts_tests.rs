#![cfg(test)]

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

fn seed(db: &SyncDatabase, path: &str, record_kind: RecordKind, state: MaterializationState) {
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, \
             deleted, record_kind, materialization_state) \
             VALUES (?1, ?2, 0, 0, '[]', 0, ?3, ?4)",
            rusqlite::params![GROUP, path, record_kind.as_db_str(), state.as_db_str()],
        )?;
        Ok(())
    })
    .unwrap();
}

/// `yadorilink status` summarizes files by materialization state. A
/// directory has no content to hydrate or evict, so counting it would
/// inflate the file totals; a symlink keeps being counted, since it has a
/// materialization state of its own that durability health reads.
#[test]
fn materialization_counts_do_not_count_directories() {
    let db = open_full_test_db();
    seed(&db, "a.txt", RecordKind::File, MaterializationState::Present);
    seed(&db, "b.txt", RecordKind::File, MaterializationState::Remote);
    seed(&db, "link", RecordKind::Symlink, MaterializationState::Present);
    seed(&db, "album", RecordKind::Directory, MaterializationState::Present);
    seed(&db, "empty", RecordKind::Directory, MaterializationState::Remote);

    let counts = MaterializationStateRepository::new(db).materialization_counts(GROUP).unwrap();

    assert_eq!((counts.hydrated, counts.placeholder, counts.hydrating), (2, 1, 0));
}

/// A directory reads as the least materialized state of the files below it.
#[test]
fn a_directory_takes_the_least_materialized_state_below_it() {
    let db = open_full_test_db();
    seed(&db, "album", RecordKind::Directory, MaterializationState::Remote);
    seed(&db, "album/a.jpg", RecordKind::File, MaterializationState::Present);
    seed(&db, "empty", RecordKind::Directory, MaterializationState::Remote);
    let materialization = MaterializationStateRepository::new(db.clone());
    let state =
        |prefix: &str| materialization.directory_materialization_state(GROUP, prefix).unwrap();
    assert_eq!(state("album"), MaterializationState::Present);
    assert_eq!(state("empty"), MaterializationState::Present, "nothing to fetch");
    seed(&db, "album/sub/b.jpg", RecordKind::File, MaterializationState::Remote);
    assert_eq!(state("album"), MaterializationState::Remote);
    assert_eq!(state(""), MaterializationState::Remote);
    seed(&db, "album/c.jpg", RecordKind::File, MaterializationState::Hydrating);
    assert_eq!(state("album"), MaterializationState::Hydrating);
}

/// An evicting file is not a fetch: it is counted apart from `hydrating`, which is a request
/// signal for content.
#[test]
fn evicting_files_are_not_counted_as_hydrating() {
    let db = open_full_test_db();
    seed(&db, "a.txt", RecordKind::File, MaterializationState::Hydrating);
    seed(&db, "b.txt", RecordKind::File, MaterializationState::Evicting);
    seed(&db, "c.txt", RecordKind::File, MaterializationState::Evicting);

    let counts = MaterializationStateRepository::new(db).materialization_counts(GROUP).unwrap();

    assert_eq!((counts.hydrating, counts.evicting), (1, 2));
}

fn seed_blocks(db: &SyncDatabase, path: &str, kind: RecordKind, blocks_json: &str) {
    seed(db, path, kind, MaterializationState::Remote);
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "UPDATE files SET blocks_json = ?2 WHERE group_id = ?3 AND path = ?1",
            rusqlite::params![path, blocks_json, GROUP],
        )?;
        Ok(())
    })
    .unwrap();
}

/// The placeholders' block hashes are the union over regular-file placeholders; hydrated files and
/// directories contribute nothing, and anything the list cannot vouch for answers `None`.
#[test]
fn placeholder_block_hashes_fail_closed() {
    let db = open_full_test_db();
    let repo = MaterializationStateRepository::new(db.clone());
    assert_eq!(repo.placeholder_block_hashes(GROUP, 8).unwrap(), Some(HashSet::new()));

    let block = |byte: u8| format!(r#"{{"hash":{:?},"offset":0,"size":1}}"#, vec![byte; 2]);
    seed_blocks(&db, "a", RecordKind::File, &format!("[{}]", block(1)));
    seed_blocks(&db, "b", RecordKind::File, &format!("[{},{}]", block(1), block(2)));
    seed(&db, "done", RecordKind::File, MaterializationState::Present);
    seed(&db, "dir", RecordKind::Directory, MaterializationState::Remote);
    let expected: HashSet<Vec<u8>> = [vec![1u8; 2], vec![2u8; 2]].into_iter().collect();
    assert_eq!(repo.placeholder_block_hashes(GROUP, 2).unwrap(), Some(expected));
    assert_eq!(repo.placeholder_block_hashes(GROUP, 1).unwrap(), None, "over the budget");

    seed(&db, "link", RecordKind::Symlink, MaterializationState::Remote);
    assert_eq!(repo.placeholder_block_hashes(GROUP, 8).unwrap(), None, "not a regular file");
}

/// A folder's size is the content bytes of its live regular files; the online-only part is the
/// files held only as placeholders. Directories and symlinks add no bytes.
#[test]
fn materialization_counts_sum_content_and_online_only_bytes() {
    let db = open_full_test_db();
    let seed_sized = |path: &str, kind: RecordKind, state: MaterializationState, size: i64| {
        db.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, \
                 deleted, record_kind, materialization_state) \
                 VALUES (?1, ?2, ?3, 0, '[]', 0, ?4, ?5)",
                rusqlite::params![GROUP, path, size, kind.as_db_str(), state.as_db_str()],
            )?;
            Ok(())
        })
        .unwrap();
    };
    seed_sized("a", RecordKind::File, MaterializationState::Present, 100);
    seed_sized("b", RecordKind::File, MaterializationState::Remote, 40);
    seed_sized("c", RecordKind::File, MaterializationState::Remote, 2);
    seed_sized("l", RecordKind::Symlink, MaterializationState::Present, 9);
    seed_sized("d", RecordKind::Directory, MaterializationState::Present, 4096);

    let counts = MaterializationStateRepository::new(db).materialization_counts(GROUP).unwrap();

    assert_eq!(counts.total_bytes, 142);
    assert_eq!(counts.online_only_bytes, 42);
}

/// `Status` lists held files with one statement: live held rows only, in path order.
#[test]
fn held_states_are_listed_in_one_statement_for_live_held_rows_only() {
    let db = open_full_test_db();
    seed(&db, "b.txt", RecordKind::File, MaterializationState::Present);
    seed(&db, "a.txt", RecordKind::File, MaterializationState::Present);
    seed(&db, "c.txt", RecordKind::File, MaterializationState::Present);
    seed(&db, "gone.txt", RecordKind::File, MaterializationState::Present);
    let repo = MaterializationStateRepository::new(db.clone());
    repo.set_held(GROUP, "b.txt", "case_collision", 7).unwrap();
    repo.set_held(GROUP, "a.txt", "invalid_name", 5).unwrap();
    repo.set_held(GROUP, "gone.txt", "invalid_name", 9).unwrap();
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute("UPDATE files SET deleted = 1 WHERE path = 'gone.txt'", [])?;
        Ok(())
    })
    .unwrap();
    let held = repo.list_held_states(GROUP).unwrap();
    assert_eq!(
        held.iter()
            .map(|(p, h)| (p.as_str(), h.reason.as_str(), h.since_unix_nanos))
            .collect::<Vec<_>>(),
        [("a.txt", "invalid_name", 5), ("b.txt", "case_collision", 7)]
    );
}

/// `Status` no longer decodes every row's block list, so a corrupt one must still fail it closed
/// (and a symlink count is one statement).
#[test]
fn a_corrupt_stored_block_list_fails_the_status_read_closed() {
    let db = open_full_test_db();
    seed(&db, "ok.txt", RecordKind::File, MaterializationState::Present);
    seed(&db, "link", RecordKind::Symlink, MaterializationState::Present);
    let files = crate::file_index::FileIndexRepository::new(db.clone());
    files.verify_live_block_lists(GROUP).unwrap();
    assert_eq!(files.count_live_symlinks(GROUP).unwrap(), 1);
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute("UPDATE files SET blocks_json = '[{\"hash\"' WHERE path = 'ok.txt'", [])?;
        Ok(())
    })
    .unwrap();
    let error = files.verify_live_block_lists(GROUP).unwrap_err().to_string();
    assert!(error.contains("ok.txt"), "{error}");
    // A deleted row's list is not a live one.
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute("UPDATE files SET deleted = 1 WHERE path = 'ok.txt'", [])?;
        Ok(())
    })
    .unwrap();
    files.verify_live_block_lists(GROUP).unwrap();
}
