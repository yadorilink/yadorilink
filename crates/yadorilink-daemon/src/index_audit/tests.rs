//! The audit's bookkeeping: what it records, what it keeps, what it lets go.

use std::sync::Arc;

use yadorilink_sync_sqlite::file_index::FileIndexRepository;
use yadorilink_sync_sqlite::SyncSqliteError;

use super::*;

const GROUP: &str = "g";

fn files_with(
    paths: &[&str],
) -> (FileIndexRepository, Arc<yadorilink_sqlite_runtime::SyncDatabase>) {
    let db = yadorilink_sync_sqlite::replica_tables::open_for_tests();
    let files = FileIndexRepository::new(db.clone());
    for path in paths {
        files.ensure_bootstrap_row_for_metadata(GROUP, path).unwrap();
    }
    (files, db)
}

fn set(db: &yadorilink_sqlite_runtime::SyncDatabase, path: &str, blocks_json: &str) {
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "UPDATE files SET blocks_json = ?1 WHERE path = ?2",
            rusqlite::params![blocks_json, path],
        )?;
        Ok(())
    })
    .unwrap();
}

fn audit_without_gap() -> IndexAudit {
    IndexAudit { state: Mutex::new(State::default()), step_gap: Duration::ZERO }
}

fn damaged(audit: &IndexAudit) -> Vec<String> {
    let state = audit.state.lock().unwrap();
    state.damaged.get(GROUP).map(|rows| rows.values().cloned().collect()).unwrap_or_default()
}

#[test]
fn the_first_pass_reads_to_the_end_of_the_table() {
    let (files, db) = files_with(&["a", "b", "c"]);
    set(&db, "c", "not json");
    let audit = audit_without_gap();
    let mut state = audit.state.lock().unwrap();
    audit.advance(&mut state, &files);
    assert_eq!(state.damaged.get(GROUP).unwrap().values().collect::<Vec<_>>(), ["c"]);
}

#[test]
fn damage_that_comes_after_the_first_pass_is_found_by_a_later_step() {
    let (files, db) = files_with(&["a", "b"]);
    let audit = audit_without_gap();
    audit.advance(&mut audit.state.lock().unwrap(), &files);
    assert!(damaged(&audit).is_empty());
    set(&db, "a", "[");
    audit.advance(&mut audit.state.lock().unwrap(), &files);
    assert_eq!(damaged(&audit), ["a"]);
}

#[test]
fn a_recorded_path_stays_until_it_reads_back_even_when_a_pass_does_not_meet_it() {
    let (files, db) = files_with(&["a", "b"]);
    set(&db, "a", "[");
    set(&db, "b", "[");
    let audit = audit_without_gap();
    audit.advance(&mut audit.state.lock().unwrap(), &files);
    assert_eq!(damaged(&audit), ["a", "b"]);
    // "a" is repaired; "b" is still damaged, so the folder is still marked.
    set(&db, "a", "[]");
    audit.advance(&mut audit.state.lock().unwrap(), &files);
    assert_eq!(damaged(&audit), ["b"]);
    set(&db, "b", "[]");
    audit.advance(&mut audit.state.lock().unwrap(), &files);
    assert!(damaged(&audit).is_empty());
}

#[test]
fn a_row_that_is_no_longer_live_is_let_go() {
    let (files, db) = files_with(&["a"]);
    set(&db, "a", "[");
    let audit = audit_without_gap();
    audit.advance(&mut audit.state.lock().unwrap(), &files);
    assert_eq!(damaged(&audit), ["a"]);
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute("UPDATE files SET deleted = 1 WHERE path = 'a'", [])?;
        Ok(())
    })
    .unwrap();
    audit.advance(&mut audit.state.lock().unwrap(), &files);
    assert!(damaged(&audit).is_empty());
}
