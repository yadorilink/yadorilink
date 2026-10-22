#![cfg(test)]

use std::sync::Arc;

use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sqlite_runtime::DatabaseError;

use super::*;

/// Minimal stand-in for the tables `init_schema`'s authoring-identity
/// triggers reference (see `yadorilink-sqlite-runtime`'s own
/// `SyncDatabase::open` test module for the identical pattern) -- these
/// tests only ever touch `local_dirty_paths`, so the stub tables are
/// never populated, just present.
fn schema_init(conn: &rusqlite::Connection) -> Result<(), DatabaseError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS admitted_changes (group_id TEXT NOT NULL, change_hash BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS group_history_bases (group_id TEXT NOT NULL, history_base BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS history_base_path_heads (group_id TEXT NOT NULL, base_hash BLOB NOT NULL, change_hash BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS history_base_carried_authors (group_id TEXT NOT NULL, base_hash BLOB NOT NULL, change_hash BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS native_authoring_witness (group_id TEXT NOT NULL, identity BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS published_evidence (change_hash BLOB NOT NULL, checkpoint_hash BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS authorization_checkpoints (checkpoint_hash BLOB NOT NULL, group_id TEXT NOT NULL);",
    )?;
    yadorilink_sqlite_runtime::init_schema(conn)
}

fn open_test_repo() -> DirtyPathRepository {
    let database = Arc::new(SyncDatabase::open_in_memory(schema_init).expect("open in-memory db"));
    DirtyPathRepository::new(database)
}

fn permit() -> RootCommitPermit<'static> {
    RootCommitPermit::for_tests()
}

#[test]
fn batch_journal_commits_all_paths_together() {
    let repo = open_test_repo();
    let entries = vec![
        ("a.txt".to_string(), "created_or_modified".to_string(), 100),
        ("b.txt".to_string(), "created_or_modified".to_string(), 101),
        ("c.txt".to_string(), "removed".to_string(), 102),
    ];
    repo.record_dirty_paths_batch("g1", &entries, &permit()).expect("batch journal");

    let mut rows = repo.list_dirty_paths("g1").expect("list");
    rows.sort_by(|a, b| a.path.cmp(&b.path));
    assert_eq!(rows.len(), 3, "every path in the batch must be journaled");
    assert_eq!(rows[0].path, "a.txt");
    assert_eq!(rows[0].observed_at_unix_nanos, 100);
    assert_eq!(rows[1].path, "b.txt");
    assert_eq!(rows[2].path, "c.txt");
    assert_eq!(rows[2].change_kind, "removed");
}

/// A batch-journaled row that is never cleared (standing in for a crash
/// between the journal commit and the per-path index+delta commit) stays
/// fully re-drivable -- exactly what `redrive_dirty_journal` reads from
/// on the next startup.
#[test]
fn an_unprocessed_batch_journaled_path_remains_fully_re_drivable() {
    let repo = open_test_repo();
    let entries = vec![
        ("a.txt".to_string(), "created_or_modified".to_string(), 100),
        ("b.txt".to_string(), "created_or_modified".to_string(), 101),
    ];
    repo.record_dirty_paths_batch("g1", &entries, &permit()).expect("batch journal");

    // No `clear_dirty_paths_conditional_batch` call follows -- standing
    // in for a crash before either path's processing step commits.
    let rows = repo.list_dirty_paths("g1").expect("list");
    assert_eq!(rows.len(), 2, "an unprocessed batch must leave every row re-drivable");
}

/// The conditional batch-clear must never erase a row a newer event has
/// since superseded. `a.txt` is journaled at `observed_at=100`, then a
/// fresh event for the SAME path arrives and re-journals it at
/// `observed_at=200` (e.g. a rapid edit racing in while the first
/// event's processing attempt was still in flight) before the first
/// attempt's conditional clear (still keyed on the stale `observed_at=
/// 100`) runs.
#[test]
fn a_newer_same_path_observation_survives_an_older_conditional_batch_clear() {
    let repo = open_test_repo();
    repo.record_dirty_path("g1", "a.txt", "created_or_modified", 100, &permit())
        .expect("initial journal");
    repo.record_dirty_path("g1", "a.txt", "created_or_modified", 200, &permit())
        .expect("superseding journal");

    // The stale attempt's conditional clear, keyed on the observation it
    // actually processed (100), must be a no-op now that the row reads
    // 200.
    repo.clear_dirty_paths_conditional_batch("g1", &[("a.txt".to_string(), 100)], &permit())
        .expect("conditional clear");

    let rows = repo.list_dirty_paths("g1").expect("list");
    assert_eq!(rows.len(), 1, "the newer observation must survive the stale clear");
    assert_eq!(rows[0].observed_at_unix_nanos, 200);

    // The current attempt's own conditional clear, keyed on the
    // observation it actually processed (200), does clear it.
    repo.clear_dirty_paths_conditional_batch("g1", &[("a.txt".to_string(), 200)], &permit())
        .expect("conditional clear");
    assert!(repo.list_dirty_paths("g1").expect("list").is_empty());
}

#[test]
fn conditional_batch_clear_only_removes_the_exact_observations_named() {
    let repo = open_test_repo();
    let entries = vec![
        ("a.txt".to_string(), "created_or_modified".to_string(), 100),
        ("b.txt".to_string(), "created_or_modified".to_string(), 101),
        ("c.txt".to_string(), "created_or_modified".to_string(), 102),
    ];
    repo.record_dirty_paths_batch("g1", &entries, &permit()).expect("batch journal");

    // Only a.txt and c.txt succeeded; b.txt's processing failed and must
    // stay journaled.
    repo.clear_dirty_paths_conditional_batch(
        "g1",
        &[("a.txt".to_string(), 100), ("c.txt".to_string(), 102)],
        &permit(),
    )
    .expect("conditional clear");

    let rows = repo.list_dirty_paths("g1").expect("list");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].path, "b.txt");
}
