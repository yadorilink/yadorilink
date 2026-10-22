//! Signed grouping for one recursive filesystem mutation split across
//! several changes.
//!
//! A recursive delete (`rm -rf a/`) or a directory rename (`a/ -> b/`) is,
//! logically, a finite set of point operations on the explicit entries the
//! mutating device observed under the directory. That set can be far larger
//! than one change may carry, so it is authored as a run of changes — the
//! operation's *parts*. Everything that later has to treat the operation as
//! one unit (restoring a deleted folder from the trash is the motivating
//! case) must be able to name the whole set exactly, and must never have to
//! guess it from author sequence adjacency, timestamps or a shared path
//! prefix: those heuristics either merge two unrelated operations or split
//! one, and they cannot tell a missing part from an operation that simply
//! had fewer parts.
//!
//! So every part is signed with the operation's identity and shape (the
//! `RecursivePart` a delta carries):
//!
//! * `operation_id` — author-chosen, random, never all zero (a delta carrying
//!   the all-zero id does not decode). Two operations are the same operation
//!   only when they share the author *and* the id, so one device can never
//!   claim, poison or complete another device's operation by reusing its id.
//! * `part_index` / `part_count` — this part's position and the total, so a
//!   reader can tell a complete operation from one with parts still missing.
//!   Parts of one operation must agree on the total: a part that claims another
//!   one than a recorded part is refused at admission.
//!
//! Nothing else about the operation is signed: its kind and scope are not part
//! of the contract, only the grouping above.

use crate::ids::{DeviceId, SyncPath};

/// The identity an author gives one recursive operation. 16 random bytes;
/// all-zero is reserved so an unset id cannot pass for a real one.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecursiveOperationId(pub [u8; 16]);

impl RecursiveOperationId {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl std::fmt::Debug for RecursiveOperationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RecursiveOperationId({})", hex::encode(self.0))
    }
}

/// A recursive operation's full name: its author and the id the author
/// gave it. Two parts belong to one operation exactly when their references
/// are equal.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct RecursiveOperationRef {
    pub author: DeviceId,
    pub operation_id: RecursiveOperationId,
}

/// What a recursive operation did, as the local write-through of its
/// mutations needs it (a directory rename moves a copy's source along with its
/// directory). Authoring-side only: the kind is not signed or carried on the
/// wire.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RecursiveOperationKind {
    /// A recursive delete of `root` and the explicit entries observed under it.
    RmTree { root: SyncPath },
    /// A rename of the directory `from` to `to`.
    RenameTree { from: SyncPath, to: SyncPath },
}

/// `ancestor == path`, or `ancestor` is a proper `/`-segment ancestor of
/// `path`. A plain string prefix is not enough: `a` is not an ancestor of
/// `ab`.
pub fn is_ancestor_or_self(ancestor: &str, path: &str) -> bool {
    path == ancestor
        || (path.len() > ancestor.len()
            && path.starts_with(ancestor)
            && path.as_bytes()[ancestor.len()] == b'/')
}

#[cfg(test)]
mod tests;
