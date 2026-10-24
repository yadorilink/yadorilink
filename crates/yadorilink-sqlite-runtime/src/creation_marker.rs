//! A durable "this database was created here" marker, kept beside the
//! database file.
//!
//! Opening a SQLite path that does not exist silently creates an empty
//! database. For a database that is the durable record of what other,
//! separately stored data is still referenced, that silent creation turns
//! loss of the file (a disk fault, an incomplete restore) into "nothing is
//! referenced any more". The marker lets the owner tell the two apart: a
//! database that is missing while its marker exists was lost, not new, and
//! must not be recreated empty.

use std::io::Write;
use std::path::{Path, PathBuf};

/// A missing database that must not be recreated empty.
#[derive(Debug, thiserror::Error)]
pub enum LostDatabaseError {
    #[error(
        "the database {db} is missing but its creation marker {marker} exists, so it was lost \
         rather than never created; refusing to start with an empty replacement. Restore the \
         database from a backup; to deliberately start over, delete the marker and the data it \
         guards"
    )]
    MarkerWithoutDatabase { db: PathBuf, marker: PathBuf },

    #[error(
        "the database {db} is missing but {evidence}; refusing to start with an empty \
         replacement. Restore the database from a backup; to deliberately start over, remove \
         that data first"
    )]
    OtherDataWithoutDatabase { db: PathBuf, evidence: String },

    #[error("could not check the creation marker for {db}: {source}")]
    Io {
        db: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Where the creation marker for the database at `db_path` lives.
pub fn creation_marker_path(db_path: &Path) -> PathBuf {
    let mut name = db_path.as_os_str().to_owned();
    name.push(".created");
    PathBuf::from(name)
}

/// Fails closed when the database at `db_path` is missing yet was created
/// before (its marker exists) or `other_data` says data that only the
/// database can account for survives. `other_data` is a description of that
/// evidence, supplied by the caller that knows what else lives beside the
/// database. An existing database always passes.
pub fn refuse_lost_database(
    db_path: &Path,
    other_data: Option<&str>,
) -> Result<(), LostDatabaseError> {
    let io = |source| LostDatabaseError::Io { db: db_path.to_owned(), source };
    if db_path.try_exists().map_err(io)? {
        return Ok(());
    }
    let marker = creation_marker_path(db_path);
    if marker.try_exists().map_err(io)? {
        return Err(LostDatabaseError::MarkerWithoutDatabase { db: db_path.to_owned(), marker });
    }
    if let Some(evidence) = other_data {
        return Err(LostDatabaseError::OtherDataWithoutDatabase {
            db: db_path.to_owned(),
            evidence: evidence.to_owned(),
        });
    }
    Ok(())
}

/// Records, durably, that the database at `db_path` exists. Idempotent;
/// call once the database has opened successfully.
pub fn record_database_created(db_path: &Path) -> std::io::Result<()> {
    let marker = creation_marker_path(db_path);
    if marker.try_exists()? {
        return Ok(());
    }
    // Written and flushed under a name of its own, then published by a durable
    // move that refuses an occupied name: the marker is never seen half
    // written, and it is on disk when this returns.
    let staged = marker.with_extension(format!("tmp.{}", std::process::id()));
    let written = (|| -> std::io::Result<()> {
        let mut file = std::fs::File::create(&staged)?;
        file.write_all(b"yadorilink database creation marker\n")?;
        yadorilink_fs_platform::flush::sync_file(&file)
    })();
    if let Err(error) = written {
        let _ = std::fs::remove_file(&staged);
        return Err(error);
    }
    match yadorilink_fs_platform::durable_dir::publish_durably(
        &staged,
        &marker,
        yadorilink_fs_platform::durable_dir::Replace::No,
    ) {
        Ok(()) => Ok(()),
        // Another writer recorded it first.
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_database_with_its_marker_is_refused_but_a_new_one_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.sqlite3");

        refuse_lost_database(&db, None).expect("nothing exists: a fresh install");

        record_database_created(&db).unwrap();
        std::fs::write(&db, b"").unwrap();
        refuse_lost_database(&db, None).expect("database and marker both present");

        std::fs::remove_file(&db).unwrap();
        let err = refuse_lost_database(&db, None).unwrap_err();
        assert!(matches!(err, LostDatabaseError::MarkerWithoutDatabase { .. }), "{err}");
    }

    #[test]
    fn other_data_without_a_database_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.sqlite3");
        let err = refuse_lost_database(&db, Some("the block store holds data")).unwrap_err();
        assert!(matches!(err, LostDatabaseError::OtherDataWithoutDatabase { .. }), "{err}");
        std::fs::write(&db, b"").unwrap();
        refuse_lost_database(&db, Some("the block store holds data")).expect("db exists");
    }
}
