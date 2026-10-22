//! Every variant here mirrors one `SyncError` variant `peer_session.rs`
//! actually constructed or matched on, same message text, so error
//! reporting stays byte-identical for anything wrapping the message
//! string.

#[derive(Debug, thiserror::Error)]
pub enum PeerSessionError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("corrupt local state: {0}")]
    CorruptState(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("hydration of {0:?} timed out or failed: no reachable peer holds all required blocks")]
    HydrationFailed(String),

    #[error(
        "materialization target {0:?} resolved outside its sync root (symlinked path component?)"
    )]
    PathEscapesRoot(String),

    #[error("path {0:?} names a reserved artefact component and cannot be used here")]
    ReservedNamespaceCollision(String),

    #[error(
        "path {0:?} has a component that is not portable to every platform this group may sync \
         to (Windows silently strips a trailing '.' or ' ') and cannot be used here"
    )]
    NonPortablePath(String),

    #[error("disk pressure on {volume}: {available_bytes} bytes available, {headroom_bytes} required for {path}")]
    DiskPressure { path: String, volume: String, available_bytes: u64, headroom_bytes: u64 },

    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("transport error: {0}")]
    Transport(#[from] yadorilink_transport::TransportError),

    // No `#[from]` -- `StorageError::DiskPressure` special-cases into
    // `Self::DiskPressure` below (matches `SyncError`'s own reasoning: a
    // caller matching on `PeerSessionError` alone, without reaching into
    // the wrapped `StorageError`, can still tell disk pressure apart from
    // every other storage error).
    #[error("storage error: {0}")]
    Storage(yadorilink_local_storage::StorageError),

    #[error("root authority error: {0}")]
    RootAuthority(#[from] yadorilink_root_authority::RootAuthorityError),

    #[error("replica engine error: {0}")]
    ReplicaEngine(#[from] yadorilink_replica_engine::error::ReplicaEngineError),

    #[error("decode error: {0}")]
    Decode(#[from] yadorilink_replica_domain::codec::ChangeError),

    /// A write this device just performed cannot be proven to hold its
    /// desired version's replicated extended attributes exactly --
    /// either a strict on-disk reread confirmed a real mismatch, or this
    /// backend cannot even attempt the comparison (see
    /// `yadorilink_local_storage::verify_replicated_xattrs_exact`'s own
    /// two `Err` cases). Never constructed via `#[from]`: every call
    /// site gating `SettlementEvidence::ExactObject` on this maps BOTH
    /// of that function's outcomes (a confirmed `Ok(false)` mismatch,
    /// and every `Err`) to this one variant on purpose, since both mean
    /// exactly the same thing to a caller deciding whether to settle --
    /// leave the obligation outstanding for retry, never let it publish
    /// a false exactness proof.
    #[error("replicated extended attributes for {0:?} could not be confirmed to exactly match the desired version")]
    ReplicatedXattrsNotExact(String),

    /// A write this device just performed cannot be proven to hold its
    /// desired version's claimed object kind (`RecordKind::File`/
    /// `Symlink`/`Directory`) -- either nothing exists at the target path
    /// at all, or what exists there is a different kind of object
    /// entirely. Never constructed via `#[from]`: every call site gating
    /// `SettlementEvidence::ExactObject` on this treats it exactly like
    /// `ReplicatedXattrsNotExact` -- leave the obligation outstanding for
    /// retry, never let it publish a false exactness proof.
    #[error(
        "physical object kind at {0:?} does not match the desired version's claimed record kind"
    )]
    PhysicalKindMismatch(String),

    /// The file already at this path denies its owner read access, so the
    /// replicated metadata the desired version names can be neither
    /// confirmed nor applied to it. Raised before anything is mutated (no
    /// fence bump, no write). The caller holds the path
    /// ([`crate::hazard::HELD_REASON_METADATA_UNPROVABLE`]) instead of
    /// retrying it or replacing the file.
    #[error(
        "the existing file at {0:?} is not readable by its owner, so its replicated metadata \
         cannot be confirmed or applied"
    )]
    MetadataUnprovable(String),
}

impl From<yadorilink_local_storage::StorageError> for PeerSessionError {
    fn from(error: yadorilink_local_storage::StorageError) -> Self {
        match error {
            yadorilink_local_storage::StorageError::DiskPressure {
                path,
                volume,
                available_bytes,
                headroom_bytes,
            } => PeerSessionError::DiskPressure {
                path: path.display().to_string(),
                volume: volume.display().to_string(),
                available_bytes,
                headroom_bytes,
            },
            yadorilink_local_storage::StorageError::PathEscapesRoot(path) => {
                PeerSessionError::PathEscapesRoot(path)
            }
            other => PeerSessionError::Storage(other),
        }
    }
}
