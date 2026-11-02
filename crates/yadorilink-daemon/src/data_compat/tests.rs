use rusqlite::Connection;
use yadorilink_local_storage::release_descriptor::StateSchema;

use super::{judge, EXIT_COMPATIBLE, EXIT_NEWER, EXIT_UNDETERMINED};

const TARGET: StateSchema = StateSchema { writes: 134, reads_from: 134 };

fn db_stamped(dir: &std::path::Path, version: i32) -> std::path::PathBuf {
    let path = dir.join("sync-state.sqlite3");
    let conn = Connection::open(&path).unwrap();
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    conn.execute_batch("CREATE TABLE files (id INTEGER PRIMARY KEY);").unwrap();
    conn.pragma_update(None, "user_version", version).unwrap();
    path
}

#[test]
fn no_data_and_data_of_this_generation_are_compatible_without_a_word() {
    let dir = tempfile::tempdir().unwrap();
    let none = judge(&dir.path().join("sync-state.sqlite3"), TARGET);
    assert_eq!((none.code, none.message.as_str()), (EXIT_COMPATIBLE, ""));
    let same = judge(&db_stamped(dir.path(), 134), TARGET);
    assert_eq!((same.code, same.message.as_str()), (EXIT_COMPATIBLE, ""));
}

#[test]
fn data_written_by_a_newer_build_is_a_refused_downgrade() {
    let dir = tempfile::tempdir().unwrap();
    let verdict = judge(&db_stamped(dir.path(), 135), TARGET);
    assert_eq!(verdict.code, EXIT_NEWER);
    assert!(verdict.message.contains("downgrading"), "{}", verdict.message);
    assert!(verdict.message.contains("135"), "{}", verdict.message);
}

#[test]
fn older_data_is_not_refused_but_warned_about() {
    let dir = tempfile::tempdir().unwrap();
    let verdict = judge(&db_stamped(dir.path(), 133), TARGET);
    assert_eq!(verdict.code, EXIT_COMPATIBLE);
    assert!(verdict.message.starts_with("warning:"), "{}", verdict.message);
}

#[test]
fn data_that_cannot_be_read_stops_the_installer_and_says_what_to_do() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sync-state.sqlite3");
    std::fs::write(&path, b"this is not a database, but it is long enough to look like a header..")
        .unwrap();
    let verdict = judge(&path, TARGET);
    assert_eq!(verdict.code, EXIT_UNDETERMINED);
    assert!(verdict.message.contains("Nothing was changed"), "{}", verdict.message);
    assert!(verdict.message.contains("start the daemon once and stop it cleanly"));
}
