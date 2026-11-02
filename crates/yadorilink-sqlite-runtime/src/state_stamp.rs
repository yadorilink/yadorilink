//! A read-only look at the schema version stamped on the sync-state database.
//!
//! An installer must know, before it replaces the programs, whether the data they would be given
//! was written by a newer build. The database is the only record of that, and nothing is created,
//! stamped, migrated or checkpointed by this process:
//!
//! * With no write-ahead log content (no `-wal`, or an empty one, and no rollback journal) the
//!   main file holds every committed byte, so the stamp is read from its header (offset 60) and
//!   no SQLite connection is opened. A SQLite connection would create an empty `-wal` and `-shm`
//!   beside the file (the check may run as another user than the one that owns the data).
//! * Otherwise the file is opened read-only through SQLite and `PRAGMA user_version` is read
//!   through the connection, so a version committed to the log and not yet folded into the main
//!   file is seen (a crashed daemon's log is recovered in memory; that can create the `-shm`).
//!
//! The file is never opened `immutable`: that would ignore the log and could report the version
//! from before a migration.
//!
//! Anything it cannot prove is an error, never "compatible".

use std::path::Path;

use rusqlite::{Connection, OpenFlags};

/// How long a locked database is waited for before the stamp counts as unreadable.
const LOCKED_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// What the database file at a path says about its schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateStamp {
    /// No file, or a file with no tables and no stamp: nothing was ever written here.
    Fresh,
    /// The schema version the data was written with (always above zero).
    Version(u32),
}

/// Reads the schema stamp of the sync-state database at `db_path`.
///
/// # Errors
/// A message saying why the stamp could not be established: the path is not a regular file, the
/// file cannot be opened read-only (a write-ahead log that needs recovery in a directory that
/// cannot be written, a lock held past the wait, a file that is not a database), or it has tables
/// but no stamp.
pub fn read_state_stamp(db_path: &Path) -> Result<StateStamp, String> {
    // Follows a symlink alias, as the daemon does for its database path.
    match std::fs::metadata(db_path) {
        Ok(m) if m.is_file() => {}
        Ok(_) => return Err(format!("{} is not a regular file", db_path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(StateStamp::Fresh),
        Err(e) => return Err(format!("cannot examine {}: {e}", db_path.display())),
    }
    let fail = |what: &str, e: &dyn std::fmt::Display| {
        format!("cannot read {} ({what}: {e})", db_path.display())
    };
    if !has_pending_log(db_path) {
        if let Some(version) = header_user_version(db_path) {
            if version != 0 {
                return stamp_from(version, db_path);
            }
            // A zero stamp is "fresh" only with no tables: that needs a query.
        }
    }
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| fail("open read-only", &e))?;
    conn.busy_timeout(LOCKED_WAIT).map_err(|e| fail("busy timeout", &e))?;
    let version: i32 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(|e| fail("schema version", &e))?;
    if version != 0 {
        return stamp_from(version, db_path);
    }
    let tables: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' \
             AND name NOT LIKE 'sqlite_%' AND name <> 'writer_generation'",
            [],
            |r| r.get(0),
        )
        .map_err(|e| fail("tables", &e))?;
    if tables > 0 {
        return Err(format!("{} has tables but no schema version stamp", db_path.display()));
    }
    Ok(StateStamp::Fresh)
}

/// A negative stamp is not one any build writes: it cannot be compared with anything.
fn stamp_from(version: i32, db_path: &Path) -> Result<StateStamp, String> {
    u32::try_from(version).map(StateStamp::Version).map_err(|_| {
        format!(
            "{} has a schema version stamp ({version}) that is not a valid version",
            db_path.display()
        )
    })
}

/// Whether a write-ahead log with content, or a rollback journal, sits beside the database.
fn has_pending_log(db_path: &Path) -> bool {
    let beside = |suffix: &str| {
        let mut name = db_path.as_os_str().to_owned();
        name.push(suffix);
        std::path::PathBuf::from(name)
    };
    let wal = std::fs::metadata(beside("-wal")).map(|m| m.len() > 0).unwrap_or(false);
    wal || beside("-journal").exists()
}

/// `user_version` from the 100-byte header of a SQLite file (a big-endian 32-bit integer at offset
/// 60), `None` when the file is not one or cannot be read (the connection path then says why).
fn header_user_version(db_path: &Path) -> Option<i32> {
    use std::io::Read as _;
    let mut header = [0u8; 100];
    std::fs::File::open(db_path).ok()?.read_exact(&mut header).ok()?;
    header
        .starts_with(b"SQLite format 3\0")
        .then(|| i32::from_be_bytes([header[60], header[61], header[62], header[63]]))
}

#[cfg(test)]
mod tests;
