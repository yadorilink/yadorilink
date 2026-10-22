//! The *desired*-side half of the resolved-state comparison
//! `materialized_generation` relies on: what native state requires at one
//! path, as the `(MaterializedObjectKind, Option<VersionHash>)` pair that
//! `compute_resolved_path_state_hash` hashes.

use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::ids::VersionHash;

use crate::materialized_generation::{compute_resolved_path_state_hash, MaterializedObjectKind};

fn map_record_kind(kind: RecordKind) -> MaterializedObjectKind {
    match kind {
        RecordKind::File => MaterializedObjectKind::RegularFile,
        RecordKind::Directory => MaterializedObjectKind::Directory,
        RecordKind::Symlink => MaterializedObjectKind::Symlink,
    }
}

/// What the namespace projection places at one path on the path's own
/// account.
///
/// A filesystem is not per path: a File `a` cannot be materialized while
/// `a/x` lives, and a deleted directory that still holds a live child is
/// still a directory. This is the per-path answer with that tree constraint
/// applied by the native namespace projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesiredPathState {
    /// Nothing is required at the path.
    Absent,
    /// A File or Symlink version stays at its own path.
    Entry { kind: RecordKind, version: VersionHash },
    /// A replicated Directory entry lives at the path.
    ExplicitDirectory { version: VersionHash },
    /// A directory required only to hold live descendants. When the path's
    /// own winner is a File or Symlink, that content is relocated to its
    /// conflict-copy sibling and is not part of this path's state.
    StructuralDirectory,
}

impl DesiredPathState {
    /// The materialized-generation kind and version this state is proven
    /// by.
    #[must_use]
    pub fn object_kind_and_version(&self) -> (MaterializedObjectKind, Option<VersionHash>) {
        match *self {
            Self::Absent => (MaterializedObjectKind::Absent, None),
            Self::Entry { kind, version } => (map_record_kind(kind), Some(version)),
            Self::ExplicitDirectory { version } => {
                (MaterializedObjectKind::Directory, Some(version))
            }
            Self::StructuralDirectory => (MaterializedObjectKind::StructuralDirectory, None),
        }
    }

    /// The `resolved_path_state_hash` a generation proving this state at
    /// `path` carries.
    #[must_use]
    pub fn resolved_path_state_hash(&self, group_id: &str, path: &str) -> [u8; 32] {
        let (kind, version) = self.object_kind_and_version();
        compute_resolved_path_state_hash(group_id, path, kind, version.as_ref())
    }
}
