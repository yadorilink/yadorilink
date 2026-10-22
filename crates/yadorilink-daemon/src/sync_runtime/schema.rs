//! Maps the replica schema init's errors onto the error type
//! `SyncDatabase::open` takes. The init itself is composed by
//! `yadorilink_sync_sqlite::init_replica_schema`; a store-side failure is
//! reported through this crate's `SyncError`, as it always has been.

use yadorilink_sync_sqlite::ReplicaSchemaError;

use crate::sync_error::SyncError;

pub fn map_replica_schema_error(
    err: ReplicaSchemaError,
) -> yadorilink_sqlite_runtime::DatabaseError {
    match err {
        ReplicaSchemaError::Database(err) => err,
        ReplicaSchemaError::Store(err) => yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(
            SyncError::from(err).to_string(),
        ),
    }
}
