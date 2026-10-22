//! The block-serving authorization boundary a session needs from replica
//! state, as its own narrow port. `PeerSyncSession` needs exactly this one
//! operation from replica state; the daemon's `ReplicaCoordinator`
//! implements it.

use crate::error::PeerSessionError;

/// [`BlockServeAuthorizationPort::authorize_block_serve`]'s verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockServeAuthorization {
    /// Referenced (by the live record or native state/retained-version
    /// fallback) and provenance-verified -- the request may proceed to
    /// dispatch/serve. `declared_size` is the block's own size from the
    /// live `FileRecord`'s block list when it's referenced there, `None`
    /// when the reference was only established via native state/retained-
    /// version path.
    Allowed { declared_size: Option<u32> },
    /// Not referenced by the requested file's live record, native heads, or
    /// retained versions.
    NotReferenced,
    /// Referenced, but this peer has no verified provenance for the group.
    NoProvenance,
}

/// The block-serving authorization boundary for an incoming peer
/// `BlockRequest`, as one semantic operation instead of the four raw
/// reads a session used to assemble it from (`published_file_at_path`/
/// `published_group_file_version_references_block` for the reference
/// check, `group_has_block_provenance` for the provenance check,
/// `get_file` for the declared size). Preserves every existing semantic
/// exactly:
///
/// - the reference check reads the PUBLISHED view only -- never the raw
///   materialized-index pair, and deliberately never
///   `group_retained_version_references_block` (folding that in would
///   reopen an evidence-free serving path).
/// - the provenance check runs only once the reference check has passed,
///   so the common unreferenced-request case costs one fewer read.
/// - the declared size is read from the LIVE record (`get_file`), not the
///   published one, and only once the request is authorized; it's `None`
///   when the live record is deleted or no longer lists the hash, and the
///   caller falls back to a pessimistic estimate in that case.
pub trait BlockServeAuthorizationPort: Send + Sync {
    fn authorize_block_serve(
        &self,
        group_id: &str,
        path: &str,
        block_hash: &[u8],
    ) -> Result<BlockServeAuthorization, PeerSessionError>;
}
