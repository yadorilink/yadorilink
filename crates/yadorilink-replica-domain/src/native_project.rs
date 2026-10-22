//! The semantic projection of a native tree: what each path shows, as a pure
//! function of the replicated head state.
//!
//! [`project_path`] takes the live heads at one path, the kind of each head's
//! version (a lookup that may fail while a version record trails its head) and
//! one derived fact about the subtree, [`has_live_descendant`]. It returns
//! [`Projection::Settled`], [`Projection::Absent`] or [`Projection::Pending`].
//! It reads no disk, no index and no local table; the module has no
//! dependency that could. Two replicas holding the same admitted deltas
//! project every path identically, whatever order the deltas arrived in and
//! whatever their disks hold.
//!
//! # Contested paths
//!
//! A path is contested when
//!
//! * it holds file-like heads (file, symlink) of two or more distinct
//!   versions, or
//! * it holds a file-like head and the path has to be a directory: a
//!   directory head lives there, or a live head exists strictly below it.
//!
//! A contested path projects `Pending`. A contest ends when the author of a
//! losing head moves that head to its copy path with an ordinary delta (see
//! [`crate::native_fork`]); until then `Pending` is a statement about the
//! replicated state, not about any disk: what a device's files show for a
//! pending path is a materializer decision and never an input here.
//!
//! Two directory heads of distinct versions are not a contest: directory
//! metadata is decided by [`crate::native_state::win_key`] alone.
//!
//! A path whose head kinds cannot all be resolved (a version record has not
//! arrived) is `Pending` as well: the projection fails closed instead of
//! guessing a kind.
//!
//! [`has_live_descendant`]: project_path

use std::collections::{BTreeMap, BTreeSet};

use crate::file::RecordKind;
use crate::ids::{SyncPath, VersionHash};
use crate::native_state::{win_key, Dot, LiveHead, PathHeads, WinKey};

/// How a directory at a path came to be.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DirectoryNode {
    /// A directory head lives at the path; the highest version decides its
    /// metadata.
    Explicit { version: VersionHash },
    /// Only live descendants require the directory.
    Structural,
}

/// What a settled path shows.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Settled {
    /// One file-like version. `representative` is the head standing for it
    /// (the one with the largest provenance among the heads of that version,
    /// a function of the heads alone).
    Entry { kind: RecordKind, version: VersionHash, representative: Dot },
    /// A directory: explicit when a directory head lives at the path (the
    /// highest version decides its metadata), structural when only live
    /// descendants require it.
    Directory(DirectoryNode),
}

/// Why a path cannot be settled yet.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PendingReason {
    /// Two or more distinct file-like versions hold the path.
    DistinctVersions,
    /// A file-like head holds a path that has to be a directory.
    DirectoryRequired,
    /// The kind of this head's version is not known yet.
    UnknownKind { version: VersionHash },
}

/// The projection of one path.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Projection {
    Settled(Settled),
    Absent,
    Pending(PendingReason),
}

/// Projects one path from its live heads.
///
/// `kind_of` answers the record kind of a version, or `None` while the record
/// is missing. `has_live_descendant` is true when some live head exists
/// strictly below the path.
pub fn project_path(
    heads: impl IntoIterator<Item = LiveHead>,
    kind_of: impl Fn(&VersionHash) -> Option<RecordKind>,
    has_live_descendant: bool,
) -> Projection {
    let mut best_directory: Option<WinKey> = None;
    let mut file_like: Vec<(LiveHead, RecordKind)> = Vec::new();
    let mut unknown: Option<VersionHash> = None;

    for head in heads {
        match kind_of(&head.payload.version) {
            None => {
                // The smallest unresolved version, so the reason does not
                // depend on iteration order.
                unknown =
                    Some(unknown.map_or(head.payload.version, |v| v.min(head.payload.version)));
            }
            Some(RecordKind::Directory) => {
                let key = win_key(true, head.payload.version);
                best_directory = best_directory.max(Some(key));
            }
            Some(kind) => file_like.push((head, kind)),
        }
    }
    if let Some(version) = unknown {
        return Projection::Pending(PendingReason::UnknownKind { version });
    }

    if !file_like.is_empty() {
        if best_directory.is_some() || has_live_descendant {
            return Projection::Pending(PendingReason::DirectoryRequired);
        }
        let first = file_like[0].0.payload.version;
        if file_like.iter().any(|(head, _)| head.payload.version != first) {
            return Projection::Pending(PendingReason::DistinctVersions);
        }
        let (winner, kind) = file_like
            .into_iter()
            .max_by_key(|(head, _)| head.payload.provenance)
            .expect("file_like is not empty");
        return Projection::Settled(Settled::Entry {
            kind,
            version: winner.payload.version,
            representative: winner.dot,
        });
    }

    if let Some(WinKey { version, .. }) = best_directory {
        return Projection::Settled(Settled::Directory(DirectoryNode::Explicit { version }));
    }
    if has_live_descendant {
        return Projection::Settled(Settled::Directory(DirectoryNode::Structural));
    }
    Projection::Absent
}

/// Whether some key of `heads` lies strictly below `path`.
fn has_descendant(heads: &BTreeMap<SyncPath, PathHeads>, path: &str) -> bool {
    // Every path below `path` sorts at or after `path/`, and the first key at
    // or after it is below `path` exactly when any is.
    let lower = SyncPath(format!("{path}/"));
    heads
        .range(lower..)
        .next()
        .is_some_and(|(key, _)| key.as_str().starts_with(&format!("{path}/")))
}

/// The projection of a whole tree: every path that holds a head, or that a
/// live descendant requires as a directory, mapped to its projection.
/// `Absent` paths are omitted.
pub fn project_tree(
    heads_by_path: &BTreeMap<SyncPath, PathHeads>,
    kind_of: impl Fn(&VersionHash) -> Option<RecordKind>,
) -> BTreeMap<SyncPath, Projection> {
    let mut candidates: BTreeSet<String> = BTreeSet::new();
    for path in heads_by_path.keys() {
        let mut current = path.as_str();
        candidates.insert(current.to_owned());
        while let Some((parent, _)) = current.rsplit_once('/') {
            if !candidates.insert(parent.to_owned()) {
                break;
            }
            current = parent;
        }
    }
    let mut out = BTreeMap::new();
    for path in candidates {
        let key = SyncPath(path);
        let live = heads_by_path.get(&key).into_iter().flat_map(|heads| {
            heads
                .iter()
                .map(|(dot, payload)| LiveHead { dot: dot.clone(), payload: payload.clone() })
        });
        let projection = project_path(live, &kind_of, has_descendant(heads_by_path, key.as_str()));
        if projection != Projection::Absent {
            out.insert(key, projection);
        }
    }
    out
}

/// The paths of `tree` strictly below a `Pending` path. A materializer does
/// not create or delete anything there until the contest above is resolved.
pub fn blocked_by_pending(tree: &BTreeMap<SyncPath, Projection>) -> BTreeSet<SyncPath> {
    let pending: Vec<&SyncPath> = tree
        .iter()
        .filter(|(_, projection)| matches!(projection, Projection::Pending(_)))
        .map(|(path, _)| path)
        .collect();
    tree.keys()
        .filter(|path| {
            pending.iter().any(|ancestor| {
                path.as_str().len() > ancestor.as_str().len()
                    && path.as_str().starts_with(ancestor.as_str())
                    && path.as_str().as_bytes()[ancestor.as_str().len()] == b'/'
            })
        })
        .cloned()
        .collect()
}

/// One contested path of a tree.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Contest {
    pub path: SyncPath,
    pub reason: PendingReason,
}

/// Every pending path of the tree, in path order (the contest detector).
pub fn contests(tree: &BTreeMap<SyncPath, Projection>) -> Vec<Contest> {
    tree.iter()
        .filter_map(|(path, projection)| match projection {
            Projection::Pending(reason) => {
                Some(Contest { path: path.clone(), reason: reason.clone() })
            }
            _ => None,
        })
        .collect()
}

/// Whether `head` is a loser its author has to move: it is file-like and either the path needs a
/// directory (a directory head or a live descendant), or another version of
/// larger [`WinKey`] holds the path.
///
/// This is the one predicate behind both the contest detector and the fork
/// builder, a function of the semantic state only.
pub fn loses(
    head: &LiveHead,
    kind_of: impl Fn(&VersionHash) -> Option<RecordKind>,
    heads_at_path: &PathHeads,
    has_live_descendant: bool,
) -> Option<bool> {
    let kind = kind_of(&head.payload.version)?;
    if kind == RecordKind::Directory {
        return Some(false);
    }
    if has_live_descendant {
        return Some(true);
    }
    let mut max = win_key(false, head.payload.version);
    for payload in heads_at_path.values() {
        let other = kind_of(&payload.version)?;
        max = max.max(win_key(other == RecordKind::Directory, payload.version));
    }
    Some(win_key(false, head.payload.version) < max)
}

#[cfg(test)]
mod tests;
