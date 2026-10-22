#![cfg(test)]

//! The repair pass re-drives through an ordinary fetch only the rows that
//! admit they are owed bytes. In an on-demand folder a `placeholder` row is
//! Remote, its steady state, so a restart leaves it Remote; only a fetch
//! that was abandoned mid-way is owed its bytes. In an eager folder every
//! placeholder is owed its bytes.

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

fn link(db: &SyncDatabase, policy: &str) {
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "INSERT INTO links (local_path, group_id, materialization_policy) \
             VALUES ('/tmp/repair', ?1, ?2)",
            rusqlite::params![GROUP, policy],
        )?;
        Ok(())
    })
    .unwrap();
}

fn insert(db: &SyncDatabase, path: &str, state: MaterializationState) {
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
             version_seq, state, record_kind, materialization_state) \
             VALUES (?1, ?2, 1, 0, '[]', 0, 1, 'current', 'file', ?3)",
            rusqlite::params![GROUP, path, state.as_db_str()],
        )?;
        Ok(())
    })
    .unwrap();
}

fn seed_every_state(db: &SyncDatabase) {
    insert(db, "present.bin", MaterializationState::Present);
    insert(db, "remote.bin", MaterializationState::Remote);
    insert(db, "abandoned.bin", MaterializationState::Hydrating);
}

#[test]
fn an_on_demand_folder_owes_bytes_only_to_an_abandoned_fetch() {
    let db = open_full_test_db();
    link(&db, "on_demand");
    seed_every_state(&db);

    let candidates =
        MaterializationStateRepository::new(db).list_materialization_repair_candidates(GROUP);

    assert_eq!(candidates.unwrap(), ["abandoned.bin"]);
}

#[test]
fn an_eager_folder_owes_bytes_to_every_placeholder_and_an_abandoned_fetch() {
    let db = open_full_test_db();
    link(&db, "eager");
    seed_every_state(&db);

    let candidates =
        MaterializationStateRepository::new(db).list_materialization_repair_candidates(GROUP);

    assert_eq!(candidates.unwrap(), ["abandoned.bin", "remote.bin"]);
}
