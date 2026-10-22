//! Callers convert via `From` at the crate boundary, same pattern as
//! `yadorilink-sqlite-runtime`'s `DatabaseError` /
//! `yadorilink-sync-sqlite`'s `SyncSqliteError`.

use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum RootAuthorityError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("not found: {0}")]
    NotFound(String),

    /// The link's root lease is paused for a safe stop and will resume if that stop gives up.
    /// Unlike a stopping lease (`NotFound`), this refusal is temporary: the caller must keep the
    /// work (journal it, or leave it queued) and try again, never treat it as "nothing to do".
    #[error("{0}")]
    Quiescing(String),

    #[error("corrupt state: {0}")]
    CorruptState(String),

    /// A path component names a reserved on-disk artefact component (a
    /// staging/tombstone name this engine reserves for its own
    /// atomic-commit machinery) and cannot be used for ordinary content.
    #[error("path {0:?} names a reserved artefact component and cannot be used here")]
    ReservedNamespaceCollision(String),

    /// This link's folder does not verify against its previously-adopted
    /// root identity -- see `root_identity`'s module doc for why an
    /// existence check alone cannot detect this. Never resolved to a more
    /// specific variant: the message is the whole diagnosis.
    #[error("{0}")]
    RootIdentityMismatch(String),

    /// The sync-root lock sidecar is gone, replaced, or can no longer be
    /// re-observed: this process can no longer prove it owns the root. Terminal
    /// for the link -- never retried, never repaired by recreating the sidecar;
    /// only a relink or a daemon restart acquires a fresh lock.
    #[error("{0}")]
    OwnershipLost(String),

    /// A group has more than one live link -- `root_identity`'s
    /// `ensure_single_root` gate refuses before any constructor touches
    /// disk or the index. }` after this crate's
    /// `RootVerificationStatePort` implementation for `SyncState`
    /// round-trips through this variant and back, so the conversion must
    /// be lossless in both directions.
    #[error(
        "folder group {group_id} is linked to {} folders on this device ({}); sync is stopped \
         for this folder group until exactly one remains. Decide which folder is this group's \
         sync root and run `yadorilink unlink` on the other(s) — unlinking removes a folder from \
         sync and does not delete any files from it. Any file that exists only in a folder you \
         unlink will be copied into the folder you keep if another device still has it; if no \
         other device has it, copy it into the folder you keep yourself, or a later scan will \
         delete it everywhere.",
        local_paths.len(),
        local_paths.join(", ")
    )]
    AmbiguousLink { group_id: String, local_paths: Vec<String> },
}

impl RootAuthorityError {
    pub fn not_found(message: impl fmt::Display) -> Self {
        Self::NotFound(message.to_string())
    }

    pub fn corrupt_state(message: impl fmt::Display) -> Self {
        Self::CorruptState(message.to_string())
    }
}
