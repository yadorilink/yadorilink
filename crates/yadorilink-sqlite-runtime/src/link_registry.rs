//! A read-only look at the link registry of a database no daemon is running on.
//!
//! The uninstaller must know which folders the stopped daemon was syncing before it deletes
//! anything. This opens the database read-only (nothing is created, stamped, migrated or
//! checkpointed by this process), and reports only what it can prove: a file that is not this
//! build's schema, a missing `links` table or any read error is an error, never "no links".

use std::path::Path;

use rusqlite::{Connection, OpenFlags};

use crate::schema::{table_exists, SCHEMA_VERSION};

/// How long a locked database is waited for before the registry counts as unreadable.
const LOCKED_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// One registered link, as the removal check needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredLink {
    /// The folder, or a provider link's synthetic locator.
    pub local_path: String,
    /// `none` for a plain directory, otherwise the provider kind.
    pub provider_kind: String,
    /// The link was orphaned (its folder is no longer synced, its files remain).
    pub orphaned: bool,
}

/// Every link row of the sync-state database at `db_path`, orphaned ones included.
///
/// `Ok(None)` when there is no database file at all (nothing was ever registered here).
///
/// # Errors
/// A message saying why the registry could not be read: unreadable or locked file, a schema that
/// is not exactly this build's, or a missing table.
pub fn read_link_registry(db_path: &Path) -> Result<Option<Vec<RegisteredLink>>, String> {
    // Follows a symlink alias, as the daemon does for its database path.
    match std::fs::metadata(db_path) {
        Ok(m) if m.is_file() => {}
        Ok(_) => return Err(format!("{} is not a regular file", db_path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot examine {}: {e}", db_path.display())),
    }
    let fail = |what: &str, e: &dyn std::fmt::Display| {
        format!("cannot read {} ({what}: {e})", db_path.display())
    };
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| fail("open", &e))?;
    conn.busy_timeout(LOCKED_WAIT).map_err(|e| fail("busy timeout", &e))?;
    let version: i32 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(|e| fail("schema version", &e))?;
    if version != SCHEMA_VERSION {
        return Err(format!(
            "{} has schema version {version}, which is not this build's {SCHEMA_VERSION}",
            db_path.display()
        ));
    }
    if !table_exists(&conn, "links").map_err(|e| fail("tables", &e))? {
        return Err(format!("{} has no link table", db_path.display()));
    }
    let mut stmt = conn
        .prepare("SELECT local_path, provider_kind, orphaned FROM links ORDER BY local_path")
        .map_err(|e| fail("links", &e))?;
    let rows = stmt
        .query_map([], |r| {
            Ok(RegisteredLink {
                local_path: r.get(0)?,
                provider_kind: r.get(1)?,
                orphaned: r.get::<_, i64>(2)? != 0,
            })
        })
        .map_err(|e| fail("links", &e))?;
    rows.collect::<Result<Vec<_>, _>>().map(Some).map_err(|e| fail("links", &e))
}

/// Writes a registry the way the daemon's schema defines it, for tests of readers.
///
/// # Panics
/// On any SQLite error.
#[cfg(any(test, feature = "test-support"))]
pub fn write_registry_for_test(db_path: &Path, links: &[(&str, &str, bool)]) {
    let conn = Connection::open(db_path).unwrap();
    // The tables the owning crate supplies before the core schema (see `schema/tests.rs`).
    conn.execute_batch(
        "CREATE TABLE admitted_changes (group_id TEXT NOT NULL, change_hash BLOB NOT NULL);
         CREATE TABLE group_history_bases (group_id TEXT NOT NULL, history_base BLOB NOT NULL);
         CREATE TABLE history_base_path_heads (group_id TEXT NOT NULL, base_hash BLOB NOT NULL, change_hash BLOB NOT NULL);
         CREATE TABLE history_base_carried_authors (group_id TEXT NOT NULL, base_hash BLOB NOT NULL, change_hash BLOB NOT NULL);
         CREATE TABLE native_authoring_witness (group_id TEXT NOT NULL, identity BLOB NOT NULL);
         CREATE TABLE published_evidence (change_hash BLOB NOT NULL, checkpoint_hash BLOB NOT NULL);
         CREATE TABLE authorization_checkpoints (checkpoint_hash BLOB NOT NULL, group_id TEXT NOT NULL);",
    )
    .unwrap();
    crate::init_schema(&conn).unwrap();
    for (path, kind, orphaned) in links {
        conn.execute(
            "INSERT INTO links (local_path, group_id, orphaned, provider_kind) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![path, format!("g-{path}"), i64::from(*orphaned), kind],
        )
        .unwrap();
    }
    conn.pragma_update(None, "user_version", SCHEMA_VERSION).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_is_no_registry_and_an_existing_one_lists_every_link() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("s.sqlite3");
        assert_eq!(read_link_registry(&db), Ok(None));
        write_registry_for_test(&db, &[("/a", "none", false), ("/b", "none", true)]);
        let links = read_link_registry(&db).unwrap().unwrap();
        assert_eq!(links.len(), 2);
        assert!(links[1].orphaned && links[0].local_path == "/a");
    }

    #[test]
    fn a_database_locked_by_another_connection_is_an_error_not_empty() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("s.sqlite3");
        write_registry_for_test(&db, &[("/a", "none", false)]);
        let holder = Connection::open(&db).unwrap();
        holder.execute_batch("BEGIN EXCLUSIVE").unwrap();
        assert!(read_link_registry(&db).is_err());
        holder.execute_batch("ROLLBACK").unwrap();
        assert!(read_link_registry(&db).unwrap().is_some());
    }

    #[test]
    fn garbage_a_foreign_schema_and_a_directory_are_errors_not_empty() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("s.sqlite3");
        std::fs::write(&db, b"this is not sqlite at all, just text padding padding").unwrap();
        assert!(read_link_registry(&db).is_err());
        std::fs::remove_file(&db).unwrap();
        let conn = Connection::open(&db).unwrap();
        conn.execute("CREATE TABLE links (local_path TEXT)", []).unwrap();
        conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1).unwrap();
        drop(conn);
        assert!(read_link_registry(&db).unwrap_err().contains("schema version"));
        std::fs::remove_file(&db).unwrap();
        std::fs::create_dir(&db).unwrap();
        assert!(read_link_registry(&db).is_err());
    }
}
