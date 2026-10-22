//! What a path settles to once the author of each losing head has moved it:
//! the highest version keeps the name, and every other distinct version stands
//! at [`copy_path`] of the path and that version.
//!
//! This is a pure function of a path's live heads, for the oracles and model
//! checks that ask what a converged replica must show. Production does not
//! decide anything with it: the projection of a path is
//! `yadorilink_replica_domain::native_project`, and a contested path is
//! resolved by the losing author's own delta
//! (`yadorilink_replica_domain::native_fork`).

use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_domain::native_fork::copy_path;

/// One live head of a single path `P`.
#[derive(Clone, Debug)]
pub struct PathHead {
    /// The delta that wrote the head (its provenance); breaks a tie between
    /// heads of one version.
    pub change_hash: [u8; 32],
    pub rank: u64,
    pub device_id: String,
    pub naming_device_id: String,
    /// The content this head lands at `P`, or `None` when this head removes
    /// `P`.
    pub content: Option<PathHeadContent>,
}

#[derive(Clone, Debug)]
pub struct PathHeadContent {
    /// Content address of the file version.
    pub version_hash: [u8; 32],
    pub mtime_unix_nanos: i64,
}

/// A losing version standing at its copy path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictCopy {
    /// Index into the `heads` slice passed to `resolve_path_heads`.
    pub head: usize,
    /// `copy_path(P, version)`.
    pub path: String,
}

/// The settled outcome of one path from its live heads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathResolution {
    /// Every live head removes the path.
    Absent,
    /// The path holds `winner`'s content; each other distinct version stands at
    /// its copy path.
    Present { winner: usize, conflict_copies: Vec<ConflictCopy> },
}

/// Settles `heads`, the live heads of `path`. Order does not matter. Heads of
/// one version are one piece of content: they make no copy between them.
pub fn resolve_path_heads(path: &str, heads: &[PathHead]) -> PathResolution {
    let content_heads: Vec<usize> =
        heads.iter().enumerate().filter(|(_, h)| h.content.is_some()).map(|(i, _)| i).collect();
    let key = |i: usize| {
        (heads[i].content.as_ref().expect("a content head").version_hash, heads[i].change_hash)
    };
    let Some(&winner) = content_heads.iter().max_by_key(|&&i| key(i)) else {
        return PathResolution::Absent;
    };
    let winner_version = key(winner).0;
    let mut reps: std::collections::BTreeMap<[u8; 32], usize> = std::collections::BTreeMap::new();
    for &i in &content_heads {
        let version = key(i).0;
        if version == winner_version {
            continue;
        }
        let rep = reps.entry(version).or_insert(i);
        if key(*rep) < key(i) {
            *rep = i;
        }
    }
    let conflict_copies = reps
        .iter()
        .map(|(version, &head)| ConflictCopy {
            head,
            path: copy_path(path, &VersionHash(*version)),
        })
        .collect();
    PathResolution::Present { winner, conflict_copies }
}

#[cfg(test)]
mod tests;
