//! Errors this crate's own constructors (`SyncDatabase::open`/
//! `open_in_memory`, schema bootstrap) can raise directly.
//! `SyncDatabase::read`/`write`/`write_immediate` do NOT use this type --
//! they are generic over the caller's own error type via
//! [`SqlOperationError`], so a caller (e.g.

#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("connection pool error: {0}")]
    Pool(#[from] r2d2::Error),

    #[error("unsupported database schema version {on_disk_version} (this build supports {supported_version})")]
    UnsupportedSchemaDowngrade { on_disk_version: i32, supported_version: i32 },

    #[error("corrupt database schema: {0}")]
    CorruptSchema(String),
}

/// The bound `SyncDatabase::read`/`write`/`write_immediate` require of a
/// caller's own error type: it must be constructible from the two error
/// kinds a connection checkout or SQL statement can raise, and must be
/// able to tell [`crate::retry_on_database_locked`] whether a given value
/// represents a transient `SQLITE_LOCKED`/`SQLITE_BUSY` condition (the
/// only thing that's retried) versus a genuine, unretryable failure.
pub trait SqlOperationError: From<rusqlite::Error> + From<r2d2::Error> {
    fn is_locked(&self) -> bool;
}

impl SqlOperationError for DatabaseError {
    fn is_locked(&self) -> bool {
        matches!(
            self,
            DatabaseError::Sqlite(rusqlite::Error::SqliteFailure(e, _))
                if matches!(
                    e.code,
                    rusqlite::ErrorCode::DatabaseLocked | rusqlite::ErrorCode::DatabaseBusy
                )
        )
    }
}
