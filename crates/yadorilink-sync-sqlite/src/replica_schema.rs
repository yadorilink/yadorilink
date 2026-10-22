//! The replica index database's schema init, as the replica open calls it.
//!
//! [`init_replica_schema`] creates the replica schema
//! (`replica_tables::init`) and stamps its version.

use rusqlite::Connection;

use yadorilink_sqlite_runtime::DatabaseError;

use crate::error::SyncSqliteError;

/// Why the replica schema init failed: a step owned by the SQLite runtime
/// (the generation policy, the core tables) or one owned by this crate.
/// Kept apart so the caller can report each exactly as it did when it
/// sequenced the steps itself.
#[derive(Debug)]
pub enum ReplicaSchemaError {
    Database(DatabaseError),
    Store(SyncSqliteError),
}

impl From<DatabaseError> for ReplicaSchemaError {
    fn from(err: DatabaseError) -> Self {
        Self::Database(err)
    }
}

impl From<SyncSqliteError> for ReplicaSchemaError {
    fn from(err: SyncSqliteError) -> Self {
        Self::Store(err)
    }
}

impl std::fmt::Display for ReplicaSchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(err) => err.fmt(f),
            Self::Store(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for ReplicaSchemaError {}

/// Creates or checks the replica index schema on a freshly opened
/// connection, before anything else runs against it.
///
/// The generation check comes first: once any table exists, "has this
/// database any tables?" can no longer tell a brand-new file from one an
/// un-stamping build wrote. A database stamped with any other schema
/// version other than this build's is refused there; a fresh one is created
/// and stamped once every table exists.
///
/// The tables and the stamp commit in one transaction: a crash part-way
/// leaves either nothing (the next open creates the schema afresh) or the
/// whole stamped schema, never tables without a stamp, which the
/// generation check would refuse on every later open.
pub fn init_replica_schema(conn: &Connection) -> Result<(), ReplicaSchemaError> {
    yadorilink_sqlite_runtime::check_replica_schema_generation(conn)?;
    let tx = conn.unchecked_transaction().map_err(DatabaseError::from)?;
    crate::replica_tables::init(&tx)?;
    tx.pragma_update(None, "user_version", yadorilink_sqlite_runtime::SCHEMA_VERSION)
        .map_err(DatabaseError::from)?;
    tx.commit().map_err(DatabaseError::from)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tables(conn: &Connection) -> i64 {
        conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .unwrap()
    }

    fn user_version(conn: &Connection) -> i32 {
        conn.pragma_query_value(None, "user_version", |row| row.get(0)).unwrap()
    }

    /// An init that fails part-way leaves no table behind and no stamp, so
    /// the next open creates the schema afresh instead of refusing a
    /// database with tables but no stamp.
    #[test]
    fn a_failed_init_leaves_no_unstamped_tables() {
        let conn = Connection::open_in_memory().unwrap();
        // A view where the schema creates a table and then indexes it: the
        // index creation fails after many tables were created.
        conn.execute_batch("CREATE VIEW handoff_leases AS SELECT 1 AS group_id").unwrap();
        assert!(init_replica_schema(&conn).is_err());
        assert_eq!(tables(&conn), 0, "the tables created before the failure are rolled back");
        assert_eq!(user_version(&conn), 0);

        conn.execute_batch("DROP VIEW handoff_leases").unwrap();
        init_replica_schema(&conn).expect("the next init creates the schema");
        assert!(tables(&conn) > 0);
        assert_eq!(user_version(&conn), yadorilink_sqlite_runtime::SCHEMA_VERSION);
        init_replica_schema(&conn).expect("and a stamped database opens again");
    }
}
