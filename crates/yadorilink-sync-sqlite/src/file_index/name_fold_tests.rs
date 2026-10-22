#![cfg(test)]

//! The name-collision keys stored with each `files` row and the lookups that
//! read them.

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

fn plan(db: &SyncDatabase, sql: &str) -> String {
    db.read::<_, SyncSqliteError>(|conn| {
        let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?;
        let rows = stmt.query_map(rusqlite::params![GROUP, "k", "p"], |r| r.get::<_, String>(3))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?.join(" | "))
    })
    .unwrap()
}

#[test]
fn both_lookups_are_index_searches_not_scans() {
    let db = open_full_test_db();
    let case = plan(&db, NAME_FOLD_MATCHES_SQL_CASE);
    assert!(case.contains("USING INDEX files_case_fold_key"), "{case}");
    assert!(!case.contains("SCAN"), "{case}");
    let canonical = plan(&db, NAME_FOLD_MATCHES_SQL_CANONICAL);
    assert!(canonical.contains("USING INDEX files_canonical_fold_key"), "{canonical}");
    assert!(!canonical.contains("SCAN"), "{canonical}");
}

fn record(path: &str, mtime: i64) -> FileRecord {
    FileRecord {
        path: path.to_string(),
        size: 0,
        mtime_unix_nanos: mtime,
        blocks: vec![],
        deleted: false,
    }
}

/// Every row, in any state, carries exactly the folds of its own path.
fn assert_every_row_carries_its_path_folds(db: &SyncDatabase) {
    let rows: Vec<(String, String, String)> = db
        .read::<_, SyncSqliteError>(|conn| {
            let mut stmt =
                conn.prepare("SELECT path, case_fold_key, canonical_fold_key FROM files")?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
        .unwrap();
    assert!(!rows.is_empty());
    for (path, case_key, canonical_key) in rows {
        let (want_case, want_canonical) = name_fold_keys(&path);
        assert_eq!(case_key, want_case, "case key of {path:?}");
        assert_eq!(canonical_key, want_canonical, "canonical key of {path:?}");
        assert!(!case_key.is_empty() && !canonical_key.is_empty(), "{path:?}");
    }
}

/// A new path, a new version of it and both metadata scaffolds
/// each write the keys of the path they leave current, with the shared
/// functions: not an empty default, and not a lowercase.
#[test]
fn every_writer_that_sets_a_path_stores_its_folds() {
    let db = open_full_test_db();
    let repo = FileIndexRepository::new(db.clone());
    let permit = RootCommitPermit::for_tests();
    repo.upsert_file(GROUP, &record("Docs/Stra\u{df}e.TXT", 1), &permit).unwrap();
    repo.upsert_file(GROUP, &record("Docs/Stra\u{df}e.TXT", 2), &permit).unwrap();
    repo.ensure_bootstrap_row_for_metadata(GROUP, "Scaffold/\u{3a3}.txt").unwrap();
    db.write::<_, SyncSqliteError>(|conn| {
        let tx = conn.unchecked_transaction()?;
        ensure_bootstrap_row_for_metadata_in_tx(&tx, GROUP, "Tx/Caf\u{e9}.txt")?;
        tx.commit()?;
        Ok(())
    })
    .unwrap();
    assert_every_row_carries_its_path_folds(&db);
    // The keys are the shared folds, not plain lowercase: `ß` folds to `ss`.
    let (case_key, _) = name_fold_keys("Docs/Stra\u{df}e.TXT");
    assert_eq!(case_key, "docs/strasse.txt");
}

/// A lookup matches the stored fold exactly, leaves out the probe's own path,
/// other groups, tombstones and superseded versions.
#[test]
fn a_lookup_matches_live_current_rows_of_the_group_other_than_the_path_itself() {
    let db = open_full_test_db();
    let repo = FileIndexRepository::new(db.clone());
    let permit = RootCommitPermit::for_tests();
    repo.upsert_file(GROUP, &record("a/Readme.md", 1), &permit).unwrap();
    repo.upsert_file(GROUP, &record("a/README.md", 1), &permit).unwrap();
    repo.upsert_file("other", &record("a/readme.MD", 1), &permit).unwrap();
    let mut gone = record("a/ReadMe.md", 1);
    gone.deleted = true;
    repo.upsert_file(GROUP, &gone, &permit).unwrap();
    let (case_key, _) = name_fold_keys("a/readme.md");
    let found = |path: &str| repo.name_fold_matches(GROUP, NameFoldKey::Case, &case_key, path);
    assert_eq!(found("a/readme.md").unwrap(), ["a/README.md", "a/Readme.md"]);
    // The path itself never matches itself.
    assert_eq!(found("a/Readme.md").unwrap(), ["a/README.md"]);
}

/// Pins the stored keys for a fixed corpus. The keys live in the database, so
/// a dependency upgrade that changes folding would leave existing rows
/// holding keys the new code never computes.
#[test]
fn stored_name_keys_match_the_pinned_corpus() {
    let corpus: &[(&str, &str, &str)] = &[
        ("Docs/ReadMe.TXT", "docs/readme.txt", "docs/readme.txt"),
        ("Docs/Stra\u{df}e.TXT", "docs/strasse.txt", "docs/strasse.txt"),
        ("Docs/\u{130}stanbul.txt", "docs/i\u{307}stanbul.txt", "docs/i\u{307}stanbul.txt"),
        ("Docs/ANKARA\u{131}.txt", "docs/ankara\u{131}.txt", "docs/ankara\u{131}.txt"),
        (
            "Docs/\u{39f}\u{394}\u{39f}\u{3a3}",
            "docs/\u{3bf}\u{3b4}\u{3bf}\u{3c3}",
            "docs/\u{3bf}\u{3b4}\u{3bf}\u{3c3}",
        ),
        (
            "Docs/\u{3bf}\u{3b4}\u{3bf}\u{3c2}",
            "docs/\u{3bf}\u{3b4}\u{3bf}\u{3c3}",
            "docs/\u{3bf}\u{3b4}\u{3bf}\u{3c3}",
        ),
        ("Docs/Caf\u{e9}.txt", "docs/caf\u{e9}.txt", "docs/caf\u{e9}.txt"),
        ("Docs/Cafe\u{301}.txt", "docs/cafe\u{301}.txt", "docs/caf\u{e9}.txt"),
        ("Docs/x\u{323}\u{307}.txt", "docs/x\u{323}\u{307}.txt", "docs/\u{1e8b}\u{323}.txt"),
        ("Docs/x\u{307}\u{323}.txt", "docs/x\u{307}\u{323}.txt", "docs/\u{1e8b}\u{323}.txt"),
        ("Docs/\u{1f600}Party.TXT", "docs/\u{1f600}party.txt", "docs/\u{1f600}party.txt"),
        (
            "\u{65e5}\u{672c}\u{8a9e}/\u{540d}\u{524d}.txt",
            "\u{65e5}\u{672c}\u{8a9e}/\u{540d}\u{524d}.txt",
            "\u{65e5}\u{672c}\u{8a9e}/\u{540d}\u{524d}.txt",
        ),
    ];
    for (path, case_key, canonical_key) in corpus {
        let (got_case, got_canonical) = name_fold_keys(path);
        assert_eq!(
            (got_case.as_str(), got_canonical.as_str()),
            (*case_key, *canonical_key),
            "folding changed: bump SCHEMA_VERSION so stored keys are rebuilt ({path:?})"
        );
    }
}
