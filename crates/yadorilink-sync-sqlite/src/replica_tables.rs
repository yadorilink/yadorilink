//! The complete replica schema: the content-version store, the native
//! causal-state tables (heads, frontier, delta log, publication evidence,
//! checkpoints, placements), the projection and local-capture tables, the
//! SQLite runtime's core tables and the verified-possession tables. It runs
//! no startup repair pass.
//!
//! [`init`] neither checks nor stamps `user_version`; the replica open
//! ([`crate::init_replica_schema`]) does that.

use rusqlite::Connection;

use crate::replica_schema::ReplicaSchemaError;

/// Creates the replica schema on `conn`.
///
/// Order: the content-version and projection tables first, then the native
/// tables, then the SQLite runtime's core tables.
pub fn init(conn: &Connection) -> Result<(), ReplicaSchemaError> {
    crate::dag_store::init_dag_tables(conn)?;
    crate::author_incarnation::init_schema(conn)?;
    // Native causal-state tables: see native_store.rs's module doc.
    crate::native_store::init_native_tables(conn)?;
    // Remote admission: the delta log and hold queue (native_admission.rs).
    crate::native_admission::init_admission_tables(conn)?;
    // Publication: per-delta authorization evidence (native_publication.rs).
    crate::native_publication::init_native_publication_tables(conn)?;
    // Sealing: per-checkpoint seal evidence (native_checkpoint_authorization.rs).
    crate::native_checkpoint_authorization::init_native_checkpoint_authorization_tables(conn)?;
    crate::native_recursive_operation::init_tables(conn)?;
    crate::remote_custody_lease::init_tables(conn)?;
    crate::remote_custody_hold::init_tables(conn)?;
    yadorilink_sqlite_runtime::init_schema(conn)?;
    Ok(())
}

/// [`init`] with the store's error type, for tests that build their own
/// connection the way the replica schema init does.
#[cfg(any(test, feature = "test-support"))]
pub fn init_for_tests(conn: &Connection) -> Result<(), crate::SyncSqliteError> {
    init(conn).map_err(|error| match error {
        ReplicaSchemaError::Store(error) => error,
        ReplicaSchemaError::Database(error) => {
            crate::SyncSqliteError::CorruptState(error.to_string())
        }
    })
}

/// An in-memory database with the replica schema, for tests of the
/// code paths that read it. It is never stamped (`user_version` stays 0), so
/// no replica open accepts it as its own.
#[cfg(any(test, feature = "test-support"))]
pub fn open_for_tests() -> std::sync::Arc<yadorilink_sqlite_runtime::SyncDatabase> {
    let database = yadorilink_sqlite_runtime::SyncDatabase::open_in_memory(|conn| {
        init(conn).map_err(|err| match err {
            ReplicaSchemaError::Database(err) => err,
            ReplicaSchemaError::Store(err) => {
                yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(err.to_string())
            }
        })
    })
    .expect("open the replica schema test database");
    std::sync::Arc::new(database)
}
