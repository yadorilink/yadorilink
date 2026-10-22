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
