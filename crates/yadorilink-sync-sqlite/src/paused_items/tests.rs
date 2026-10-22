#![cfg(test)]

use std::sync::Arc;

use yadorilink_sqlite_runtime::{DatabaseError, SyncDatabase};

use super::*;

fn schema_init(conn: &rusqlite::Connection) -> Result<(), DatabaseError> {
    crate::projection_obligations::init_projection_obligations_schema(conn)
        .map_err(|e| DatabaseError::CorruptSchema(e.to_string()))
}

fn in_memory() -> Arc<SyncDatabase> {
    Arc::new(SyncDatabase::open_in_memory(schema_init).expect("open in-memory db"))
}

#[test]
fn an_item_covers_itself_and_its_subtree_but_not_a_sibling_sharing_its_prefix() {
    let paused = vec!["dir".to_string(), "notes.txt".to_string()];
    assert!(path_is_covered(&paused, "dir"));
    assert!(path_is_covered(&paused, "dir/a.txt"));
    assert!(path_is_covered(&paused, "dir/sub/b.txt"));
    assert!(path_is_covered(&paused, "notes.txt"));
    assert!(!path_is_covered(&paused, "dir2/a.txt"));
    assert!(!path_is_covered(&paused, "dir.txt"));
    assert!(!path_is_covered(&paused, "notes.txt.bak"));
    assert!(!path_is_covered(&paused, "other/dir/a.txt"));
    assert!(path_is_covered(&[String::new()], "anything/at/all.txt"), "the root covers all");
    assert!(!path_is_covered(&[], "dir/a.txt"));
}

/// The claim query and local capture must agree on what a pause covers, or
/// one side of a paused item would sync while the other is held.
#[test]
fn the_sql_rule_agrees_with_the_rust_rule() {
    let database = in_memory();
    let repo = PausedItemRepository::new(database.clone());
    let items = ["dir", "notes.txt", "a/b"];
    for item in items {
        repo.pause("g", item).unwrap();
    }
    repo.pause("other-group", "").unwrap();
    let paused = repo.list("g").unwrap();
    let candidates = [
        "dir",
        "dir/x",
        "dir/y/z",
        "dir2",
        "dir2/x",
        "dir.txt",
        "notes.txt",
        "notes.txt/x",
        "notes.txt2",
        "a",
        "a/b",
        "a/b/c",
        "a/bc",
        "b",
        "",
    ];
    for candidate in candidates {
        let sql_says: bool = database
            .read::<_, SyncSqliteError>(|conn| {
                Ok(conn.query_row(
                    &format!("SELECT {}", covered_by_paused_item_sql("'g'", "?1")),
                    [candidate],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(sql_says, path_is_covered(&paused, candidate), "disagreement on {candidate:?}");
    }
}

/// "Paused until resumed" survives a daemon restart.
#[test]
fn a_pause_survives_reopening_the_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("index.db");
    {
        let database = Arc::new(SyncDatabase::open(&path, schema_init).unwrap());
        PausedItemRepository::new(database).pause("g", "dir").unwrap();
    }
    let database = Arc::new(SyncDatabase::open(&path, schema_init).unwrap());
    let repo = PausedItemRepository::new(database);
    assert_eq!(repo.list("g").unwrap(), vec!["dir".to_string()]);
    assert!(repo.resume("g", "dir").unwrap(), "resume reports that the item was paused");
    assert!(repo.list("g").unwrap().is_empty());
    assert!(!repo.resume("g", "dir").unwrap(), "resuming an unpaused item is a no-op");
}

/// A covered obligation is not claimed while paused, and resume hands it
/// straight back to the scheduler even if it had been deferred.
#[test]
fn a_paused_items_obligations_are_withheld_from_the_claim_until_resume() {
    let database = in_memory();
    let repo = PausedItemRepository::new(database.clone());
    let claimed_paths = |now: i64| -> Vec<String> {
        let mut paths: Vec<String> = database
            .read::<_, SyncSqliteError>(|conn| {
                crate::projection_obligations::claim_runnable_obligations(conn, now, 100, 100)
            })
            .unwrap()
            .into_iter()
            .map(|o| o.path)
            .collect();
        paths.sort();
        paths
    };
    database
        .write::<_, SyncSqliteError>(|conn| {
            crate::projection_obligations::bump_projection_obligations_for_touched_paths(
                conn,
                "g",
                &["dir/a.txt", "outside.txt"],
                1,
            )?;
            // As if the scheduler had deferred it after the pause landed.
            conn.execute(
                "UPDATE projection_obligations SET next_attempt_at = 1000000 \
                  WHERE path = 'dir/a.txt'",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    repo.pause("g", "dir").unwrap();
    assert_eq!(
        claimed_paths(i64::MAX),
        vec!["outside.txt".to_string()],
        "a covered obligation is not claimed however long it has been runnable"
    );

    repo.resume("g", "dir").unwrap();
    assert_eq!(
        claimed_paths(10),
        vec!["dir/a.txt".to_string(), "outside.txt".to_string()],
        "resume makes the covered obligation runnable now, not after its deferral"
    );
}
