//! The capture-level intent vocabulary: the `Op`s a local scan or event
//! produces (`Put`, `Delete`, `Move`) and the size limits of an op list.
//!
//! An `Op` is intent, not replicated state. `Move` is a rename hint that a
//! native delta cannot express (a delta carries one op per path), so it exists
//! only on the capture side, where it is lowered to a remove at the source
//! plus a put at the destination. The canonical encoding below only sizes
//! and orders op lists; it is not a wire format.

use ed25519_dalek::VerifyingKey;

use crate::codec::{put_str, ChangeError};
use crate::ids::{SyncPath, VersionHash};
use crate::limits::{MAX_PATH_BYTES, MAX_PATH_SEGMENTS};
use crate::reserved_paths::{IGNORE_FILE_NAME, ROOT_MARKER_FILE_NAME};

/// One captured operation. `Move` is a rename *hint*, not a distinct identity
/// operation: it is semantically exactly `Delete { from }` plus
/// `Put { to, version }`. It exists only so a rename can be recognized as one
/// (for UX and transfer-avoidance) rather than as an unrelated delete and put.
///
/// `Create` and `Update` collapse into one `Put`: the distinction is entirely
/// derivable from the state the op is authored against (absent: a create,
/// present: an update).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Op {
    Put { path: SyncPath, version: VersionHash },
    Delete { path: SyncPath },
    Move { from: SyncPath, to: SyncPath, version: VersionHash },
}

impl Op {
    /// Stable per-variant discriminant used both in the canonical encoding
    /// and as the secondary key of the canonical op ordering.
    pub fn discriminant(&self) -> u8 {
        match self {
            Op::Put { .. } => 0,
            Op::Delete { .. } => 1,
            Op::Move { .. } => 2,
        }
    }
}

/// Signals that a group's authorization context cannot be produced right
/// now. An installed authorization provider returns this when the group is
/// *stale* — its most recent policy snapshot failed verification, so its
/// verified state was dropped from the trusted set and inbound change
/// admission for the group fails closed until a valid snapshot restores it.
/// Each engine crate's own error type (e.g. `SyncError::PolicyUnavailable`)
/// converts from this via a local `From` impl.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PolicyUnavailable;

// --- Op list encoding -------------------------------------------------------

/// Appends one op's canonical encoding — exactly the bytes a change's
/// signed encoding carries for it.
pub fn encode_op(buf: &mut Vec<u8>, op: &Op) {
    encode_op_into(buf, op);
}

fn encode_op_into(buf: &mut Vec<u8>, op: &Op) {
    buf.push(op.discriminant());
    match op {
        Op::Put { path, version } => {
            put_str(buf, path.as_str());
            buf.extend_from_slice(&version.0);
        }
        Op::Delete { path } => {
            put_str(buf, path.as_str());
        }
        Op::Move { from, to, version } => {
            put_str(buf, from.as_str());
            put_str(buf, to.as_str());
            buf.extend_from_slice(&version.0);
        }
    }
}

/// The canonical encoded byte length of one op, mirroring [`encode_op_into`].
/// The single source of truth for per-op sizing: callers that bound a
/// change's encoded size before emitting it (the initial import and the
/// startup reconcile) share this so their byte accounting can never drift
/// from what `encode_op_into` writes.
pub fn encoded_op_len(op: &Op) -> usize {
    match op {
        Op::Delete { path } => 1 + 4 + path.as_str().len(),
        Op::Put { path, .. } => 1 + 4 + path.as_str().len() + 32,
        Op::Move { from, to, .. } => 1 + 4 + from.as_str().len() + 4 + to.as_str().len() + 32,
    }
}

/// Max canonical op-bytes packed into a single locally emitted change — shared
/// by the initial import and the startup reconcile, the two paths that convert
/// a bulk offline diff into a chain of changes. A change cannot be wire-split,
/// so it must fit in one delivered message, and every peer-protocol message
/// lane bounds its frame size (the service lane's `MAX_SERVICE_MESSAGE_BYTES`
/// is 1 MiB). 256 KiB stays well under that — leaving
/// ample room for the change's fixed header, parents, and signature, plus
/// everything else sharing that same ceiling — while a pathological run of
/// very long paths is split into a chain rather than forming one change no
/// wire message could ever carry.
pub const MAX_CHANGE_OP_BYTES: usize = 256 * 1024;

/// Upper bound on how many operations a single synthesized initial-import or
/// reconciliation change carries. A very large existing index (or a bulk
/// offline diff found by the startup reconcile) converts into a chain of
/// changes, each no bigger than this, so an individual change stays
/// comfortably small for storage while the chain as a whole still captures
/// the entire diff. Chosen to keep changes small without producing an
/// excessive number of them for a typical folder. This op-count cap alone
/// does NOT bound a change's encoded size — long paths can make a
/// `IMPORT_BATCH_OP_LIMIT`-op change several MiB — so both callers
/// additionally cap each change by canonical encoded byte size
/// ([`MAX_CHANGE_OP_BYTES`]); the two bounds apply together. Shared here
/// (rather than defined once by whichever crate owns initial import) because
/// `yadorilink-local-capture`'s own startup-reconcile chunking
/// (`RECONCILE_CHUNK_OP_LIMIT`) must match it exactly, and that crate sits
/// below `yadorilink-daemon` (which owns `dag_import`'s initial-import logic)
/// in the dependency graph, so it cannot import the constant from there.
pub const IMPORT_BATCH_OP_LIMIT: usize = 1024;

/// Rejects an op path that could escape the group root or is otherwise unsafe
/// to hand to the filesystem: empty, absolute (POSIX root, a drive letter, or
/// a UNC/backslash root), a `.`/`..`/empty segment, a NUL byte, or exceeding
/// the path length/segment bounds. Paths are the `/`-separated group-relative
/// form the index uses; `\` is treated as a separator too, so a
/// Windows-style `a\..\b` traversal is caught rather than hidden inside one
/// `/`-segment.
pub(crate) fn validate_path(path: &str) -> Result<(), ChangeError> {
    if path.is_empty() {
        return Err(ChangeError::Malformed("empty path".into()));
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(ChangeError::Malformed(format!("path exceeds {MAX_PATH_BYTES} bytes")));
    }
    if path.contains('\0') {
        return Err(ChangeError::Malformed("path contains a NUL byte".into()));
    }
    if path.contains('\\') {
        return Err(ChangeError::Malformed(
            "path contains a backslash; canonical wire paths use '/' separators only".into(),
        ));
    }
    if path.starts_with('/') {
        return Err(ChangeError::Malformed("absolute path".into()));
    }
    let is_sep = |c: char| c == '/' || c == '\\';
    let first_segment = path.split(is_sep).next().unwrap_or(path);
    if first_segment == ROOT_MARKER_FILE_NAME || first_segment == IGNORE_FILE_NAME {
        return Err(ChangeError::Malformed(
            "path targets a reserved sync-root control file".into(),
        ));
    }
    // A drive-qualified first segment such as "C:" or "C:foo".
    if first_segment.len() >= 2 && first_segment.as_bytes()[1] == b':' {
        return Err(ChangeError::Malformed("drive-qualified (absolute) path".into()));
    }
    let segments: Vec<&str> = path.split(is_sep).collect();
    if segments.len() > MAX_PATH_SEGMENTS {
        return Err(ChangeError::Malformed(format!("path exceeds {MAX_PATH_SEGMENTS} segments")));
    }
    for seg in segments {
        if seg.is_empty() {
            return Err(ChangeError::Malformed("empty path segment".into()));
        }
        if seg == "." || seg == ".." {
            return Err(ChangeError::Malformed("path contains a '.' or '..' segment".into()));
        }
    }
    Ok(())
}

/// Reconstructs an Ed25519 verifying key from its 32 raw bytes.
pub fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey, ChangeError> {
    let array: [u8; 32] = bytes.try_into().map_err(|_| ChangeError::InvalidKey)?;
    VerifyingKey::from_bytes(&array).map_err(|_| ChangeError::InvalidKey)
}
