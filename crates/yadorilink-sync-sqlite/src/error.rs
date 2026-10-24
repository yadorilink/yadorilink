//! This crate's own error type -- used for every `SyncDatabase::read`/
//! `write`/`write_immediate` call this crate makes (satisfying
//! `yadorilink_sqlite_runtime::SqlOperationError`), and returned by every
//! public method.

#[derive(Debug, thiserror::Error)]
pub enum SyncSqliteError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("connection pool error: {0}")]
    Pool(#[from] r2d2::Error),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("corrupt state: {0}")]
    CorruptState(String),

    /// The link at `local_path` belongs to a different group than the caller expected. Nothing
    /// was changed.
    #[error("the folder at {local_path} belongs to a different group than expected")]
    GroupMismatch { local_path: String },

    /// `file_index`'s `blocks_json` encode/decode.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// A caller supplied an argument that is structurally invalid for the
    /// operation -- rejected up front, before any state is written.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// A closure was refused: it does not verify, was signed by another device,
    /// or does not belong to the state it is offered with. Nothing was stored.
    #[error("closure refused: {0}")]
    ClosureRefused(String),

    /// An I/O failure surfaced while satisfying a
    /// [`yadorilink_root_authority::root_commit::RootCommitPermit::verify`]
    /// re-check inside a write transaction (see
    /// `materialization_job_repository`'s intent-journal writes). Not
    /// produced by this crate's own SQL paths, which fail through
    /// `SyncSqliteError::Sqlite` instead.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A path names a component reserved for transaction artefacts
    /// somewhere it must not: a peer delta naming one before
    /// admission, a collision detected at artefact creation, or one found
    /// unexpectedly at startup. Fail-closed and carries the exact path --
    /// the offending path is never admitted, materialized or deleted.
    #[error("path {0:?} names a reserved artefact component and cannot be used here")]
    ReservedNamespaceCollision(String),

    /// A path component would not survive a Windows peer's own path
    /// normalization (Windows silently drops a trailing `.` or ` ` from a
    /// path component in most Win32 APIs). Fail-closed: the offending path
    /// is never admitted, materialized, or trusted as faithfully
    /// represented on disk.
    #[error(
        "path {0:?} has a component that is not portable to every platform this group may sync \
         to (Windows silently strips a trailing '.' or ' ') and cannot be used here"
    )]
    NonPortablePath(String),

    /// A local authoring of a path held by a held-path hold (see
    /// `crate::held_path`): the object on disk there belongs to no
    /// row this device placed, so it is not an edit of the row the index
    /// holds; the reconciliation pass decides what it is.
    #[error(
        "{group_id}/{path} is held pending reconciliation of its disk state; a local change to \
         it cannot be authored until it is"
    )]
    PathAwaitingHeldPathReconciliation { group_id: String, path: String },

    /// A local authoring of a path under an item the user paused (see
    /// `crate::paused_items`). Checked inside the authoring transaction, so
    /// a capture that passed its earlier pause check before the pause landed
    /// still authors nothing. Nothing is written; the edit stays on disk and
    /// is captured when the item is resumed.
    #[error("{group_id}/{path} is under a paused item; a local change to it is not authored")]
    PathPaused { group_id: String, path: String },

    /// A delta, write, delete, rename or replace refused because a rebootstrap has frozen the
    /// group (see `crate::native_rebootstrap::group_frozen`). Nothing was written. Not a fault of the
    /// delta: a local edit is captured again, and a remote delta is delivered again, once the
    /// rebootstrap has finished or been discarded.
    #[error("group {group_id} is frozen by a rebootstrap")]
    GroupFrozen { group_id: String },

    /// A local write whose row no longer shows what the writer was shown
    /// when the write was captured: another head replaced it in between.
    /// Nothing was written. Authoring it anyway would supersede a version
    /// the writer never saw, so the write is captured again against the
    /// row as it stands now.
    #[error(
        "{group_id}/{path} changed between the capture of a local write and its commit; the \
         write was not authored and must be captured again"
    )]
    LocalWriteCaptureStale { group_id: String, path: String },

    /// A local authoring refused by an authoring rule
    /// ([`yadorilink_replica_domain::author::AuthoringRefusal`]). Nothing was
    /// signed or written. Kept structured so the caller can react to the
    /// refusals that need it: `StaleAuthor` and `OwnAuthorAhead` rotate the
    /// incarnation and author again.
    #[error("local authoring refused: {refusal:?}")]
    AuthoringRefused { refusal: yadorilink_replica_domain::author::AuthoringRefusal },

    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),

    /// A chunking/content-addressing failure surfaced while classifying a
    /// retained preimage.
    #[error("chunking error: {0}")]
    Chunking(String),

    /// A block-store failure not otherwise covered above -- `captured_
    /// authoring`'s own boundary with
    /// `yadorilink_local_storage::BlockStore`.
    #[error("storage error: {0}")]
    Storage(#[from] yadorilink_local_storage::StorageError),

    /// A folder group has more than one live link on this device --
    /// refused rather than resolved, since guessing which root is the real
    /// one risks tombstoning the other's files group-wide.
    #[error(
        "folder group {group_id} is linked to {} folders on this device ({}); sync is stopped \
         for this folder group until exactly one remains",
        local_paths.len(),
        local_paths.join(", ")
    )]
    AmbiguousLink { group_id: String, local_paths: Vec<String> },

    /// A filesystem root was asked of a provider-backed group: it has no directory and never yields a
    /// path.
    #[error("group {0} is a provider-backed root: it has no filesystem path")]
    NotFilesystemRoot(String),

    /// A change-emitting write's `local_emission_auth` pre-check: the
    /// group's policy has not loaded this run, so the write withheld its
    /// emission rather than stamp a placeholder-auth change.
    #[error("no verified policy is currently loaded for this group")]
    PolicyUnavailable,
}

impl From<yadorilink_replica_domain::local_op::PolicyUnavailable> for SyncSqliteError {
    fn from(_: yadorilink_replica_domain::local_op::PolicyUnavailable) -> Self {
        SyncSqliteError::PolicyUnavailable
    }
}

impl From<yadorilink_replica_domain::codec::ChangeError> for SyncSqliteError {
    fn from(error: yadorilink_replica_domain::codec::ChangeError) -> Self {
        SyncSqliteError::CorruptState(error.to_string())
    }
}

impl From<yadorilink_root_authority::RootAuthorityError> for SyncSqliteError {
    fn from(err: yadorilink_root_authority::RootAuthorityError) -> Self {
        use yadorilink_root_authority::RootAuthorityError as E;
        // Captured before the match below moves `err` -- `AmbiguousLink`'s
        // arm has no dedicated SyncSqliteError variant yet, so it falls
        // back to CorruptState carrying this crate's own formatted message
        // rather than reconstructing the group_id/local_paths fields.
        match err {
            E::Io(e) => SyncSqliteError::Io(e),
            E::NotFound(msg) => SyncSqliteError::NotFound(msg),
            E::CorruptState(msg) => SyncSqliteError::CorruptState(msg),
            E::ReservedNamespaceCollision(msg) => SyncSqliteError::ReservedNamespaceCollision(msg),
            // No dedicated variant -- `CorruptState` is the closest existing shape (a
            // fail-closed condition the caller cannot repair by retrying).
            E::RootIdentityMismatch(msg) => SyncSqliteError::CorruptState(msg),
            // Kept an `Io`, as a lost sidecar always was here: callers re-verify the permit.
            E::OwnershipLost(msg) => SyncSqliteError::Io(std::io::Error::other(msg)),
            // A pause that will lift: an I/O-shaped failure to retry, deliberately not
            // `NotFound`, which callers may read as "nothing there".
            E::Quiescing(msg) => SyncSqliteError::Io(std::io::Error::other(msg)),
            // Fenced out or refused at open: an `Io`-shaped refusal, like a lost sidecar.
            E::StaleWriter(msg) | E::WriterLeaseHeld(msg) => {
                SyncSqliteError::Io(std::io::Error::other(msg))
            }
            // Lossless, not flattened to a message string: `link.rs` gives
            // `AmbiguousLink` a real sync-sqlite call site with the same "callers match on the
            // structured variant, not the message" requirement
            // `SyncError::AmbiguousLink`'s own doc comment already documents
            // for its round trip through `RootAuthorityError`.
            E::AmbiguousLink { group_id, local_paths } => {
                SyncSqliteError::AmbiguousLink { group_id, local_paths }
            }
        }
    }
}

/// `ReplicaEngineError` has no `Io`/`InvalidInput`-shaped variant of its
/// own distinct from `Storage`, so `Storage` collapses to
/// `SyncSqliteError::CorruptState` here too: a replica-engine "storage"
/// failure reaching this crate is always a decode/consistency problem on
/// data this crate itself owns reading, never a live I/O failure (those
/// already surface as `SyncSqliteError::Io`/`Sqlite` directly).
impl From<yadorilink_replica_engine::error::ReplicaEngineError> for SyncSqliteError {
    fn from(error: yadorilink_replica_engine::error::ReplicaEngineError) -> Self {
        use yadorilink_replica_engine::error::ReplicaEngineError as E;
        match error {
            E::CorruptState(msg) => SyncSqliteError::CorruptState(msg),
            E::InvalidInput(msg) => SyncSqliteError::InvalidInput(msg),
            E::Storage(msg) => SyncSqliteError::CorruptState(msg),
        }
    }
}

impl yadorilink_sqlite_runtime::SqlOperationError for SyncSqliteError {
    fn is_locked(&self) -> bool {
        matches!(
            self,
            SyncSqliteError::Sqlite(rusqlite::Error::SqliteFailure(e, _))
                if matches!(
                    e.code,
                    rusqlite::ErrorCode::DatabaseLocked | rusqlite::ErrorCode::DatabaseBusy
                )
        )
    }
}
