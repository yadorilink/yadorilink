#![cfg(test)]

use std::sync::Arc;

use yadorilink_sqlite_runtime::DatabaseError;

use super::*;

/// Minimal stand-in for the tables these reads need -- not this
/// crate's real schema (this layer doesn't move schema ownership, only
/// reads), just enough shape for these tests to exercise real SQL.
fn test_schema(conn: &Connection) -> Result<(), DatabaseError> {
    conn.execute_batch(
        "CREATE TABLE file_versions (group_id TEXT NOT NULL, version_hash BLOB NOT NULL, encoded BLOB NOT NULL);
         CREATE TABLE group_block_provenance (group_id TEXT NOT NULL, block_hash BLOB NOT NULL);
         CREATE TABLE files (
             group_id TEXT NOT NULL, path TEXT NOT NULL, version_seq INTEGER NOT NULL,
             size INTEGER NOT NULL, mtime_unix_nanos INTEGER NOT NULL, blocks_json TEXT NOT NULL,
             deleted INTEGER NOT NULL, state TEXT NOT NULL, origin_device_id TEXT,
             record_kind TEXT NOT NULL, symlink_target BLOB, unix_mode INTEGER NOT NULL,
             xattrs_json TEXT NOT NULL DEFAULT '[]',
             -- Present in the real schema; the canonical current-row
             -- read returns them alongside the content columns so a
             -- guard can compare the version and materialization state
             -- from one incarnation of the row, and so a producer can
             -- take the whole payload -- origin and out-of-root flag
             -- included -- from one statement.
             materialization_state TEXT,
             symlink_out_of_root INTEGER NOT NULL DEFAULT 0
         );",
    )?;
    Ok(())
}

fn open_test_store() -> SqliteSyncStore {
    let database = Arc::new(SyncDatabase::open_in_memory(test_schema).expect("open in-memory db"));
    SqliteSyncStore::new(database)
}

fn insert_block_provenance(
    store: &SqliteSyncStore,
    group: &FolderGroupId,
    block_hashes: &[Vec<u8>],
) {
    store
        .database
        .write::<_, SyncSqliteError>(|conn| {
            for h in block_hashes {
                conn.execute(
                    "INSERT INTO group_block_provenance (group_id, block_hash) VALUES (?1, ?2)",
                    rusqlite::params![group.as_str(), h],
                )?;
            }
            Ok(())
        })
        .expect("insert block provenance");
}

#[test]
fn list_versions_orders_newest_first_and_preserves_metadata() {
    let store = open_test_store();
    store
        .database
        .write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "INSERT INTO files (group_id, path, version_seq, size, mtime_unix_nanos, \
                 blocks_json, deleted, state, origin_device_id, record_kind, symlink_target, unix_mode) \
                 VALUES ('group-1', 'a.txt', 1, 10, 100, '[]', 0, 'superseded', 'device-a', 'file', NULL, 0)",
                [],
            )?;
            conn.execute(
                "INSERT INTO files (group_id, path, version_seq, size, mtime_unix_nanos, \
                 blocks_json, deleted, state, origin_device_id, record_kind, symlink_target, unix_mode) \
                 VALUES ('group-1', 'a.txt', 2, 20, 200, '[]', 0, 'current', 'device-b', 'file', NULL, 1)",
                [],
            )?;
            Ok(())
        })
        .expect("insert version rows");

    let versions =
        store.list_versions(&FolderGroupId("group-1".into()), "a.txt").expect("list_versions");
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].version_seq, 2, "newest (highest version_seq) must come first");
    assert_eq!(versions[0].state, RetainedVersionState::Current);
    assert_eq!(versions[0].origin_device_id.as_deref(), Some("device-b"));
    assert_eq!(versions[0].unix_mode, Some(1));
    assert_eq!(versions[1].version_seq, 1);
    assert_eq!(versions[1].state, RetainedVersionState::Superseded);
}

#[test]
fn get_current_version_record_distinguishes_missing_from_corrupt() {
    let store = open_test_store();
    let group = FolderGroupId("group-1".into());
    assert!(
        store.get_current_version_record(&group, "missing.txt").expect("query").is_none(),
        "no row at all must read as None, not an error"
    );

    store
        .database
        .write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "INSERT INTO files (group_id, path, version_seq, size, mtime_unix_nanos, \
                 blocks_json, deleted, state, origin_device_id, record_kind, symlink_target, unix_mode) \
                 VALUES ('group-1', 'corrupt.txt', 1, 1, 1, 'not-json', 0, 'current', NULL, 'file', NULL, 0)",
                [],
            )?;
            Ok(())
        })
        .expect("insert corrupt row");
    let result = store.get_current_version_record(&group, "corrupt.txt");
    assert!(
        result.is_err(),
        "an unparseable blocks_json column must fail closed, not default to empty"
    );
}

/// `group_has_block_provenance_batch` must return exactly the
/// subset of queried hashes that actually have a recorded row for this
/// group -- not every hash ever recorded (would falsely dedup blocks
/// this call wasn't even asked about) and not a hash recorded under a
/// DIFFERENT group (provenance is group-scoped by design: a block
/// physically present because a different sync group already holds it
/// must not be trusted as available for THIS group without this
/// group's own independent fetch).
#[test]
fn group_has_block_provenance_batch_returns_exactly_the_recorded_subset_for_this_group() {
    let store = open_test_store();
    let group = FolderGroupId("group-1".into());
    let other_group = FolderGroupId("group-2".into());
    let h1 = vec![1u8; 32];
    let h2 = vec![2u8; 32];
    let h3 = vec![3u8; 32];

    insert_block_provenance(&store, &group, std::slice::from_ref(&h1));
    insert_block_provenance(&store, &other_group, std::slice::from_ref(&h2));
    // h3 is never recorded anywhere.

    let found = store
        .group_has_block_provenance_batch(&group, &[h1.clone(), h2.clone(), h3.clone()])
        .expect("batch query");
    assert_eq!(
        found,
        std::collections::HashSet::from([h1]),
        "only h1 (recorded under THIS group) may come back -- h2's provenance is under a \
         different group and must not leak across the group boundary, and h3 was never \
         recorded at all"
    );
}

/// A batch larger than SQLite's bound-parameter limit (32766 by default)
/// still answers, and answers exactly.
#[test]
fn group_has_block_provenance_batch_answers_beyond_the_parameter_limit() {
    let store = open_test_store();
    let group = FolderGroupId("group-1".into());
    let hashes: Vec<Vec<u8>> = (0u32..40_000)
        .map(|i| {
            let mut hash = vec![0u8; 32];
            hash[..4].copy_from_slice(&i.to_be_bytes());
            hash
        })
        .collect();
    let recorded: Vec<Vec<u8>> = hashes.iter().step_by(1000).cloned().collect();
    insert_block_provenance(&store, &group, &recorded);

    let found = store.group_has_block_provenance_batch(&group, &hashes).expect("batch query");
    assert_eq!(found, recorded.into_iter().collect::<std::collections::HashSet<_>>());
}

/// An empty query must not touch the database at all (SQLite's own
/// `IN ()` is invalid syntax) and must return an empty set, not an
/// error -- the common case at the tail of a mostly-already-deduped
/// batch where every remaining hash's presence still needs checking.
#[test]
fn group_has_block_provenance_batch_with_empty_input_returns_empty_without_querying() {
    let store = open_test_store();
    let group = FolderGroupId("group-1".into());
    let found = store.group_has_block_provenance_batch(&group, &[]).expect("empty batch query");
    assert!(found.is_empty());
}

/// The batched form must agree with the single-hash form for every
/// hash it's asked about -- this is a narrow performance change, not a
/// semantic one, and this pins that equivalence directly rather than
/// trusting the two implementations to stay in sync by inspection.
#[test]
fn group_has_block_provenance_batch_agrees_with_the_single_hash_form() {
    let store = open_test_store();
    let group = FolderGroupId("group-1".into());
    let recorded = vec![9u8; 32];
    let not_recorded = vec![10u8; 32];
    insert_block_provenance(&store, &group, std::slice::from_ref(&recorded));

    let batch = store
        .group_has_block_provenance_batch(&group, &[recorded.clone(), not_recorded.clone()])
        .expect("batch query");

    assert_eq!(
        batch.contains(&recorded),
        store.group_has_block_provenance(&group, &recorded).expect("single query")
    );
    assert_eq!(
        batch.contains(&not_recorded),
        store.group_has_block_provenance(&group, &not_recorded).expect("single query")
    );
}
