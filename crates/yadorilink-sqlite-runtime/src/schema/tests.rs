#![cfg(test)]

use rusqlite::Connection;

use super::*;

fn stub_dag_tables(conn: &Connection) -> Result<(), DatabaseError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS admitted_changes (group_id TEXT NOT NULL, change_hash BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS group_history_bases (group_id TEXT NOT NULL, history_base BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS history_base_path_heads (group_id TEXT NOT NULL, base_hash BLOB NOT NULL, change_hash BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS history_base_carried_authors (group_id TEXT NOT NULL, base_hash BLOB NOT NULL, change_hash BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS native_authoring_witness (group_id TEXT NOT NULL, identity BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS published_evidence (change_hash BLOB NOT NULL, checkpoint_hash BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS authorization_checkpoints (checkpoint_hash BLOB NOT NULL, group_id TEXT NOT NULL);",
    )?;
    Ok(())
}

/// The authoring-identity triggers reference `admitted_changes` and the
/// history-base tables -- this crate's own `init_schema` does not create
/// them (that is the caller's responsibility, sequenced before this call),
/// so it must fail cleanly, not panic or silently skip the triggers, when
/// they don't already exist.
#[test]
fn init_schema_fails_without_caller_supplied_dag_tables() {
    let conn = Connection::open_in_memory().expect("open");
    let result = init_schema(&conn);
    assert!(result.is_err(), "init_schema must fail when admitted_changes doesn't already exist");
}

/// When the caller has already created `admitted_changes` and the
/// history-base tables before calling `init_schema` (as `SyncDatabase::open`'s composed
/// `schema_init` closure does), the core schema -- including the
/// triggers that reference them -- succeeds.
#[test]
fn init_schema_succeeds_when_caller_supplied_dag_tables_already_exist() {
    let conn = Connection::open_in_memory().expect("open");
    stub_dag_tables(&conn).expect("stub dag tables");
    init_schema(&conn).expect("init_schema");
    assert!(table_exists(&conn, "files").unwrap());
}

/// `files.admitted_at_unix_nanos` lands on a fresh database and is
/// NULLable with no default -- both halves matter. The column's
/// presence is what Folder Rewind's read-only planning layer reads;
/// its NULLability is what lets an unstamped row be reported as
/// unanswerable instead of being coerced to a value that would read as
/// a confident (and wrong) answer.
#[test]
fn admitted_at_unix_nanos_is_present_and_nullable_with_no_default() {
    let conn = Connection::open_in_memory().expect("open");
    stub_dag_tables(&conn).expect("stub dag tables");
    init_schema(&conn).expect("init_schema");

    let mut stmt = conn.prepare("PRAGMA table_info(files)").unwrap();
    let mut rows = stmt.query([]).unwrap();
    let mut found = false;
    while let Some(row) = rows.next().unwrap() {
        if row.get::<_, String>(1).unwrap() == "admitted_at_unix_nanos" {
            found = true;
            assert_eq!(row.get::<_, i64>(3).unwrap(), 0, "must not be NOT NULL");
            assert_eq!(
                row.get::<_, Option<String>>(4).unwrap(),
                None,
                "must have no column default"
            );
        }
    }
    assert!(found, "the v26 migration must add files.admitted_at_unix_nanos");
}

/// Running `init_schema` twice in a row (schema already present) must
/// not fail -- the `CREATE TABLE IF NOT EXISTS` migrations are
/// idempotent, not just safe to run once.
#[test]
fn init_schema_is_idempotent() {
    let conn = Connection::open_in_memory().expect("open");
    stub_dag_tables(&conn).expect("stub dag tables");
    init_schema(&conn).expect("first init_schema");
    init_schema(&conn).expect("second init_schema");
}

/// The replica index's open sequence as its owner composes it: the
/// generation policy first, then the caller-supplied replica tables, this
/// crate's schema, and the version stamp (`init_schema` does not stamp).
fn replica_schema_init(conn: &Connection) -> Result<(), DatabaseError> {
    check_replica_schema_generation(conn)?;
    stub_dag_tables(conn)?;
    init_schema(conn)?;
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    Ok(())
}

/// A WAL-mode database file holding one table and one row, stamped
/// `version`. WAL mode up front, because the real open switches the
/// journal mode before the schema step runs, and the byte comparison below
/// is about what the schema step does.
fn stamped_database_file(dir: &tempfile::TempDir, version: i32) -> std::path::PathBuf {
    let path = dir.path().join("index.db");
    let conn = Connection::open(&path).expect("create database file");
    conn.pragma_update_and_check(None, "journal_mode", "WAL", |_row| Ok(())).unwrap();
    conn.execute_batch(
        "CREATE TABLE left_behind (id INTEGER PRIMARY KEY, note TEXT NOT NULL);
         INSERT INTO left_behind (note) VALUES ('written by another build');",
    )
    .unwrap();
    conn.pragma_update(None, "user_version", version).unwrap();
    drop(conn);
    path
}

/// Written relative to [`SCHEMA_VERSION`] so it holds on both sides of a
/// version bump. An older stamp is refused before a single statement runs
/// against the file: not migrated, not partially rewritten.
#[test]
fn a_database_stamped_below_the_supported_version_is_refused_and_left_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let path = stamped_database_file(&dir, SCHEMA_VERSION - 1);
    let before = std::fs::read(&path).unwrap();

    let result = crate::SyncDatabase::open(&path, replica_schema_init);

    assert!(result.is_err(), "a database stamped below the supported version must be refused");
    drop(result);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "a refused database must be left byte-identical"
    );
}

#[test]
fn a_database_stamped_above_the_supported_version_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = stamped_database_file(&dir, SCHEMA_VERSION + 1);

    let result = crate::SyncDatabase::open(&path, replica_schema_init);

    assert!(
        matches!(result, Err(DatabaseError::UnsupportedSchemaDowngrade { .. })),
        "a database stamped above the supported version must be refused"
    );
}

/// The case `check_schema_version_supported` alone cannot see, and which
/// accepting `user_version == 0` unconditionally used to admit.
#[test]
fn an_unstamped_database_with_tables_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = stamped_database_file(&dir, 0);

    let result = crate::SyncDatabase::open(&path, replica_schema_init);

    assert!(
        result.is_err(),
        "a database holding tables but no version stamp must be refused: this build cannot \
         establish what shape it is in"
    );
}

#[test]
fn a_fresh_database_is_created_at_the_supported_version() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("index.db");

    let database = crate::SyncDatabase::open(&path, replica_schema_init).expect("fresh open");
    drop(database);

    let conn = Connection::open(&path).unwrap();
    let version: i32 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
    assert_eq!(version, SCHEMA_VERSION);
}

/// The other half: a genuinely brand-new file still opens.
#[test]
fn a_brand_new_database_passes_the_replica_generation_check() {
    let conn = Connection::open_in_memory().expect("open");

    check_replica_schema_generation(&conn)
        .expect("an empty database at user_version 0 is a first run, not a stale one");
}
