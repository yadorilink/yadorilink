use std::path::Path;

use rusqlite::Connection;

use super::{read_state_stamp, StateStamp};

/// A database in WAL mode (as the daemon keeps it) stamped `version`, left open so its log is not
/// folded into the main file. The returned connection is the "daemon".
fn wal_db_with_pending_log(path: &Path, version: i32) -> Connection {
    let conn = Connection::open(path).unwrap();
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    conn.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
    conn.execute_batch("CREATE TABLE files (id INTEGER PRIMARY KEY);").unwrap();
    conn.pragma_update(None, "user_version", version).unwrap();
    conn
}

fn bytes(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

/// What a crash leaves: the main file and its log, no shared-memory index, in a directory of its
/// own.
fn crash_copy(db: &Path) -> (tempfile::TempDir, std::path::PathBuf) {
    let copy_dir = tempfile::tempdir().unwrap();
    let copy = copy_dir.path().join("sync-state.sqlite3");
    std::fs::copy(db, &copy).unwrap();
    let wal = db.with_file_name("sync-state.sqlite3-wal");
    std::fs::copy(&wal, copy_dir.path().join("sync-state.sqlite3-wal")).unwrap();
    (copy_dir, copy)
}

#[test]
fn no_file_is_fresh_and_nothing_is_created() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("sync-state.sqlite3");
    assert_eq!(read_state_stamp(&db), Ok(StateStamp::Fresh));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn a_directory_is_not_a_database() {
    let dir = tempfile::tempdir().unwrap();
    let err = read_state_stamp(dir.path()).unwrap_err();
    assert!(err.contains("not a regular file"), "{err}");
}

#[test]
fn a_database_after_a_clean_shutdown_reads_its_stamp_and_is_left_byte_identical() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("sync-state.sqlite3");
    {
        let conn = wal_db_with_pending_log(&db, 134);
        conn.pragma_update(None, "wal_autocheckpoint", 1000).unwrap();
        // Closing the last connection folds the log into the main file and removes -wal/-shm.
    }
    assert!(!dir.path().join("sync-state.sqlite3-wal").exists());
    assert!(!dir.path().join("sync-state.sqlite3-shm").exists());
    let before = bytes(&db);
    let listing = || {
        let mut names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    };
    let files_before = listing();
    assert_eq!(read_state_stamp(&db), Ok(StateStamp::Version(134)));
    assert_eq!(bytes(&db), before, "the main file is untouched");
    assert_eq!(listing(), files_before, "reading creates no file beside the database");
}

#[test]
fn a_stamp_committed_to_the_log_but_not_yet_checkpointed_is_seen() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("sync-state.sqlite3");
    let daemon = wal_db_with_pending_log(&db, 134);
    // The main file may still say 0; the stamp is in the log. Reading the file alone, or opening
    // it immutable, would say "fresh" and let an installer put an older reader over newer data.
    assert_eq!(read_state_stamp(&db), Ok(StateStamp::Version(134)));
    drop(daemon);
}

#[test]
fn a_crashed_daemons_log_is_recovered_in_memory_by_the_read() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("sync-state.sqlite3");
    let daemon = wal_db_with_pending_log(&db, 140);
    let (_keep, copy) = crash_copy(&db);
    drop(daemon);
    assert_eq!(read_state_stamp(&copy), Ok(StateStamp::Version(140)));
}

#[cfg(unix)]
#[test]
fn a_log_that_needs_recovery_in_a_directory_that_cannot_be_written_is_an_error_not_a_guess() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("sync-state.sqlite3");
    let daemon = wal_db_with_pending_log(&db, 140);
    let (keep, copy) = crash_copy(&db);
    drop(daemon);
    std::fs::set_permissions(keep.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
    let writable_anyway = std::fs::File::create(keep.path().join("probe")).is_ok();
    let result = read_state_stamp(&copy);
    std::fs::set_permissions(keep.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    if writable_anyway {
        return; // running as a user the permission does not bind (root)
    }
    let err = result.expect_err("the stamp cannot be proven here and must not be reported");
    assert!(err.contains("cannot read"), "{err}");
}

#[test]
fn a_negative_stamp_cannot_be_trusted() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("sync-state.sqlite3");
    {
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch("CREATE TABLE files (id INTEGER PRIMARY KEY);").unwrap();
        conn.pragma_update(None, "user_version", -1).unwrap();
    }
    let err = read_state_stamp(&db).unwrap_err();
    assert!(err.contains("not a valid"), "{err}");
}

#[test]
fn a_file_that_is_not_a_database_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("sync-state.sqlite3");
    std::fs::write(&db, b"this is not a database, but it is long enough to look like a header..")
        .unwrap();
    assert!(read_state_stamp(&db).is_err());
}

#[test]
fn tables_without_a_stamp_are_an_error_and_an_empty_zero_file_is_fresh() {
    let dir = tempfile::tempdir().unwrap();
    let empty = dir.path().join("empty.sqlite3");
    drop(Connection::open(&empty).unwrap());
    assert_eq!(read_state_stamp(&empty), Ok(StateStamp::Fresh));

    let unstamped = dir.path().join("unstamped.sqlite3");
    {
        let conn = Connection::open(&unstamped).unwrap();
        conn.execute_batch("CREATE TABLE files (id INTEGER PRIMARY KEY);").unwrap();
    }
    let err = read_state_stamp(&unstamped).unwrap_err();
    assert!(err.contains("no schema version stamp"), "{err}");
}

#[test]
fn a_database_a_writer_is_in_the_middle_of_changing_past_the_wait_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("sync-state.sqlite3");
    let conn = Connection::open(&db).unwrap();
    conn.execute_batch("CREATE TABLE files (id INTEGER PRIMARY KEY);").unwrap();
    conn.pragma_update(None, "user_version", 134).unwrap();
    // A rollback-journal writer mid-transaction: its journal exists, so the main file alone is not
    // the whole truth and the connection path decides (and waits, then gives up).
    conn.execute_batch("BEGIN EXCLUSIVE; INSERT INTO files VALUES (1);").unwrap();
    let err = read_state_stamp(&db).unwrap_err();
    assert!(err.contains("cannot read"), "{err}");
    conn.execute_batch("ROLLBACK;").unwrap();
    assert_eq!(read_state_stamp(&db), Ok(StateStamp::Version(134)));
}

#[test]
fn with_no_log_content_the_stamp_is_read_from_the_header_even_while_the_file_is_locked() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("sync-state.sqlite3");
    let conn = Connection::open(&db).unwrap();
    conn.execute_batch("CREATE TABLE files (id INTEGER PRIMARY KEY);").unwrap();
    conn.pragma_update(None, "user_version", 134).unwrap();
    conn.execute_batch("BEGIN EXCLUSIVE;").unwrap();
    assert_eq!(read_state_stamp(&db), Ok(StateStamp::Version(134)));
    conn.execute_batch("ROLLBACK;").unwrap();
}
