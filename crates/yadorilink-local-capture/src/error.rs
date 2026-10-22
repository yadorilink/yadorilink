//! This crate's own error type, following the exact shape
//! `yadorilink-peer-session::error::PeerSessionError` established in Phase
//! 7D-6 (`crates/yadorilink-peer-session/src/error.rs`): a thiserror-based
//! enum with only the variants this module's own code paths actually need,
//! not a blind copy of a lower-level crate's full variant list. A single
//! transparent wrapping variant is therefore everything this crate's own
//! public API (`LocalChangeProcessor`'s methods) needs.
#[derive(Debug, thiserror::Error)]
pub enum LocalCaptureError {
    #[error(transparent)]
    SyncCore(#[from] yadorilink_sync_sqlite::SyncSqliteError),
    /// The streaming consumer of a full rescan's committed chunks went away,
    /// so the rescan stopped rather than keep committing unannounced chunks.
    #[error("the rescan's chunk consumer is no longer running")]
    StreamingConsumerClosed,
    /// The link is paused for a safe stop and refused this work. Nothing was lost by the
    /// refusal itself, but the pass that hit it is incomplete: the caller must run it again
    /// once the pause lifts (a full rescan has no journal rows of its own to fall back on).
    #[error("the link is paused for a safe stop; this pass must be repeated once it resumes")]
    Paused,
}

/// Routes every conversion through `SyncSqliteError`'s own `From` impl
/// rather than wrapping the source type directly, so its special-casing
/// (e.g. the `Storage(StorageError::DiskPressure { .. })` shape
/// `is_retriable_block_store_error`'s classification depends on) is
/// preserved byte-for-byte — this crate's own `?`-propagation sites are the
/// same ones `local_change.rs` always had, just converting to the narrower
/// `SyncSqliteError` instead of a wider error type.
impl From<std::io::Error> for LocalCaptureError {
    fn from(err: std::io::Error) -> Self {
        LocalCaptureError::SyncCore(yadorilink_sync_sqlite::SyncSqliteError::from(err))
    }
}

impl From<yadorilink_local_storage::StorageError> for LocalCaptureError {
    fn from(err: yadorilink_local_storage::StorageError) -> Self {
        LocalCaptureError::SyncCore(yadorilink_sync_sqlite::SyncSqliteError::from(err))
    }
}

impl From<yadorilink_root_authority::RootAuthorityError> for LocalCaptureError {
    fn from(err: yadorilink_root_authority::RootAuthorityError) -> Self {
        if matches!(err, yadorilink_root_authority::RootAuthorityError::Quiescing(_)) {
            return LocalCaptureError::Paused;
        }
        LocalCaptureError::SyncCore(yadorilink_sync_sqlite::SyncSqliteError::from(err))
    }
}
