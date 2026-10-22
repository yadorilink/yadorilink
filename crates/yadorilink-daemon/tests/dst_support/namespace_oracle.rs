//! Directory-aware oracles: the checks every earlier oracle in this harness
//! is structurally blind to, because each of them walks regular files only
//! (`oracle.rs`'s `walk_recursive`, `directory_conflict_matrix.rs`'s
//! `recursive_snapshot`, `collision_matrix.rs`'s snapshot). Under those, a
//! peer left holding an empty `linux/` after `rm -rf linux/` elsewhere, a
//! path that is a directory on one device and a file on the other, and a
//! File `a` silently dropped because `a/x` needed `a` to be a directory all
//! read GREEN.
//!
//! The model checked against: files, directories and symlinks are
//! path-scoped replicated entries (explicit state `E`, one set of live heads
//! per path); a directory needed only to hold surviving descendants is a
//! *structural* container derived from `E`, never replicated; deleting a
//! directory never deletes a concurrently surviving descendant; and the
//! desired physical tree is a pure function `project(E)`.
//!
//! * **Projection oracles** (pure, over explicit state `E` and the tree
//!   `project(E)`, the tree a converged replica shows):
//!   [`check_projection`] re-derives `NeedsDirectory` independently of
//!   `project` and compares the directory set, explicit-vs-structural
//!   labelling, tree well-formedness, and data preservation on shape
//!   conflicts (every live content version is placed somewhere, nothing
//!   is invented). [`check_projection_purity`] checks that `project` is a
//!   function of the head *sets*: head order, tombstone-only paths and
//!   repetition must not change the tree.
//! * **Disk oracles** (over a kind-aware walk of a real root,
//!   [`disk_tree`]): [`check_disk_against_projection`] compares one
//!   device's physical tree to the projection — kind mismatches, missing
//!   directories, and directories the engine is responsible for left behind
//!   with nothing tracked or untracked inside (the `rm -rf` leftover). A
//!   directory the projection does not want but that still holds content
//!   no replica knows about is *retained* (the engine never deletes
//!   content it does not track); one the engine has no origin for is
//!   *unowned* and kept whatever it holds (an empty directory is not
//!   proof the engine made it). Both are returned for inspection, not
//!   violations.
//!   [`check_retained_claims`] holds the product's own "retained" reports
//!   to that split in both directions.
//!   [`check_trees_converge`] is the kind-aware cross-device convergence
//!   check.
//!
//! Deliberately free of the simulator and of any daemon type: it is
//! included both as `dst_support::namespace_oracle` (turmoil builds) and by
//! plain integration tests through `#[path]`, so the real-stack matrices can
//! assert the same directory invariants as the DST sweep.

#![allow(dead_code)] // each includer uses a different subset

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use sha2::{Digest, Sha256};
use yadorilink_fs_platform::reserved_namespace::is_reserved_component;
use yadorilink_replica_domain::conflict::is_conflict_copy_of;
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME;
use yadorilink_replica_engine::conflict::PathHead;
use yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME;

/// The per-device sync-root identity marker. Device-local by design, so it
/// is never part of a replicated or projected tree.
pub const ROOT_IDENTITY_MARKER: &str = ROOT_MARKER_FILE_NAME;

/// True for a name the engine keeps for itself under a sync root (the
/// identity marker, the root-lock sidecar, in-flight temp files, the
/// reserved namespace): never user content, never replicated, so never part
/// of a compared tree.
pub fn is_engine_private_name(name: &std::ffi::OsStr) -> bool {
    name == ROOT_IDENTITY_MARKER
        || name == SYNC_ROOT_LOCK_FILE_NAME
        || name.to_string_lossy().contains(".yadorilink-tmp.")
        || is_reserved_component(name)
}

// ---------------------------------------------------------------------------
// Violations
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NamespaceViolationKind {
    /// The projection's directory set differs from `NeedsDirectory`
    /// re-derived from `E`: a directory that no explicit head and no live
    /// descendant justifies, or a required one that is missing.
    NeedsDirectoryClosure,
    /// A projected directory is labelled explicit without a live Directory
    /// head (structural promoted to replicated), or structural while
    /// one exists, or carries a version that is not one of its heads.
    ExplicitnessMislabel,
    /// The projection is not a tree a filesystem can hold: a node whose
    /// parent is not a directory, a leaf at a path that must be a
    /// directory, or a placement that contradicts its own path.
    MalformedTree,
    /// A live content version of `E` appears nowhere in the projection:
    /// data lost to a shape conflict (File `a` against a live `a/x`).
    ShapeConflictLoss,
    /// A projected leaf names content that no live head of its source path
    /// holds.
    InventedEntry,
    /// `project` gave different trees for inputs that differ only in what
    /// a pure function of the explicit state must ignore.
    ProjectionImpure,
    /// `project` refused an input every version kind of which is known.
    ProjectionFailed,
    /// Disk holds a different kind of object than the tree requires (a
    /// file where a directory must be, or the reverse), or two devices
    /// disagree on the kind at a path.
    KindMismatch,
    /// The tree requires a node that is absent on disk.
    MissingNode,
    /// A directory survives on disk that the tree does not want and that
    /// holds no untracked content either: the `rm -rf` leftover.
    LeftoverDirectory,
    /// A directory is reported retained but holds no content the
    /// replicated state does not know about.
    RetainedMisclassified,
    /// A directory is kept only because untracked content sits below it
    /// (D4: `ENOTEMPTY` is retained, `.DS_Store` included), but the
    /// product does not report it as retained.
    RetainedUnreported,
    /// A leaf holds different bytes (or symlink target) than its version.
    ContentMismatch,
    /// Two devices' trees differ (in presence or content) at a path.
    TreeDivergence,
}

impl NamespaceViolationKind {
    /// Stable name, for bundles and failure signatures.
    pub fn label(self) -> &'static str {
        match self {
            Self::NeedsDirectoryClosure => "NeedsDirectoryClosure",
            Self::ExplicitnessMislabel => "ExplicitnessMislabel",
            Self::MalformedTree => "MalformedTree",
            Self::ShapeConflictLoss => "ShapeConflictLoss",
            Self::InventedEntry => "InventedEntry",
            Self::ProjectionImpure => "ProjectionImpure",
            Self::ProjectionFailed => "ProjectionFailed",
            Self::KindMismatch => "KindMismatch",
            Self::MissingNode => "MissingNode",
            Self::LeftoverDirectory => "LeftoverDirectory",
            Self::RetainedMisclassified => "RetainedMisclassified",
            Self::RetainedUnreported => "RetainedUnreported",
            Self::ContentMismatch => "ContentMismatch",
            Self::TreeDivergence => "TreeDivergence",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceViolation {
    pub kind: NamespaceViolationKind,
    pub path: String,
    pub devices: Vec<usize>,
    pub detail: String,
}

impl std::fmt::Display for NamespaceViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:?}] {} (devices {:?}): {}", self.kind, self.path, self.devices, self.detail)
    }
}

fn violation(
    kind: NamespaceViolationKind,
    path: &str,
    devices: Vec<usize>,
    detail: impl Into<String>,
) -> NamespaceViolation {
    NamespaceViolation { kind, path: path.to_string(), devices, detail: detail.into() }
}

// ---------------------------------------------------------------------------
// Explicit state
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// The settled tree: what a converged replica shows
// ---------------------------------------------------------------------------

/// How a directory in the settled tree came to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryNode {
    /// A Directory head lives at the path; `version_hash` is its winning version.
    Explicit { version_hash: [u8; 32] },
    /// Only live descendants require the directory.
    Structural,
}

/// Where a leaf sits relative to the path that owns it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    /// At its own path.
    AtPath,
    /// At `copy_path(source, version)`: the loser of a contest, which its
    /// author moved there.
    ConflictCopy,
}

/// A File or Symlink version in the tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlacedEntry {
    pub kind: RecordKind,
    pub version_hash: [u8; 32],
    /// The path the content was written at, before any author moved it.
    pub source: String,
    pub placement: Placement,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PhysicalNode {
    Directory(DirectoryNode),
    Entry(PlacedEntry),
}

impl PhysicalNode {
    pub fn is_directory(&self) -> bool {
        matches!(self, Self::Directory(_))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NamespaceProjection {
    nodes: BTreeMap<String, PhysicalNode>,
}

impl NamespaceProjection {
    pub fn nodes(&self) -> &BTreeMap<String, PhysicalNode> {
        &self.nodes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionError {
    Undecidable { path: String, version_hash: [u8; 32] },
}

impl std::fmt::Display for ProjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self::Undecidable { path, version_hash } = self;
        write!(f, "the kind of version {} at {path:?} is unknown", short_hex(version_hash))
    }
}

/// The tree a replica converges to from the explicit state `heads`: contested
/// paths are resolved the way the product resolves them (the author of each
/// losing head moves it to `copy_path(path, version)`, round after round,
/// until nothing is contested), then every path is projected. A function of
/// the head sets alone.
pub fn project(
    heads: &ExplicitHeads,
    kind_of: impl Fn(&[u8; 32]) -> Option<RecordKind>,
) -> Result<NamespaceProjection, ProjectionError> {
    use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
    use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, SyncPath, VersionHash};
    use yadorilink_replica_domain::native_fork::copy_path;
    use yadorilink_replica_domain::native_project::{
        contests, loses, project_tree, DirectoryNode as Dir, Projection, Settled,
    };
    use yadorilink_replica_domain::native_state::{
        DeltaHash, Dot, HeadPayload, LiveHead, PathHeads,
    };

    for (path, path_heads) in heads {
        for version in path_heads.iter().filter_map(version_of) {
            if kind_of(&version).is_none() {
                return Err(ProjectionError::Undecidable {
                    path: path.clone(),
                    version_hash: version,
                });
            }
        }
    }
    let kind = |v: &VersionHash| kind_of(&v.0);
    let mut seqs: BTreeMap<String, u64> = BTreeMap::new();
    let mut world: BTreeMap<SyncPath, PathHeads> = BTreeMap::new();
    let mut origin: BTreeMap<String, String> = BTreeMap::new();
    let mut put = |world: &mut BTreeMap<SyncPath, PathHeads>,
                   path: &str,
                   device: &str,
                   version: [u8; 32],
                   provenance: [u8; 32]| {
        let seq = seqs.entry(device.to_owned()).or_insert(0);
        *seq += 1;
        let dot = Dot {
            author: AuthorId {
                device: DeviceId(device.to_owned()),
                incarnation: IncarnationId([1; 16]),
            },
            seq: AuthorSeq(*seq),
        };
        world.entry(SyncPath(path.to_owned())).or_default().insert(
            dot,
            HeadPayload { version: VersionHash(version), provenance: DeltaHash(provenance) },
        );
    };
    for (path, path_heads) in heads {
        for head in path_heads {
            if let Some(content) = &head.content {
                put(&mut world, path, &head.device_id, content.version_hash, head.change_hash);
            }
        }
    }
    for _round in 0..16 {
        let tree = project_tree(&world, kind);
        let pending = contests(&tree);
        if pending.is_empty() {
            break;
        }
        let mut moved = false;
        for contest in pending {
            let path = contest.path.clone();
            let has_descendant = world
                .range(SyncPath(format!("{}/", path.as_str()))..)
                .next()
                .is_some_and(|(key, _)| key.as_str().starts_with(&format!("{}/", path.as_str())));
            let Some(at_path) = world.get(&path).cloned() else { continue };
            for (dot, payload) in &at_path {
                let live = LiveHead { dot: dot.clone(), payload: payload.clone() };
                if loses(&live, kind, &at_path, has_descendant) != Some(true) {
                    continue;
                }
                world.get_mut(&path).expect("present").remove(dot);
                let copy = copy_path(path.as_str(), &payload.version);
                let source =
                    origin.get(path.as_str()).cloned().unwrap_or_else(|| path.as_str().to_owned());
                origin.insert(copy.clone(), source);
                put(
                    &mut world,
                    &copy,
                    &dot.author.device.0,
                    payload.version.0,
                    payload.provenance.0,
                );
                moved = true;
            }
            world.retain(|_, heads| !heads.is_empty());
        }
        if !moved {
            break;
        }
    }
    let tree = project_tree(&world, kind);
    let mut nodes = BTreeMap::new();
    for (path, projection) in tree {
        let Projection::Settled(settled) = projection else { continue };
        let node = match settled {
            Settled::Directory(Dir::Explicit { version }) => {
                PhysicalNode::Directory(DirectoryNode::Explicit { version_hash: version.0 })
            }
            Settled::Directory(Dir::Structural) => {
                PhysicalNode::Directory(DirectoryNode::Structural)
            }
            Settled::Entry { kind, version, .. } => {
                let source = origin.get(path.as_str()).cloned();
                PhysicalNode::Entry(PlacedEntry {
                    kind,
                    version_hash: version.0,
                    placement: if source.is_some() {
                        Placement::ConflictCopy
                    } else {
                        Placement::AtPath
                    },
                    source: source.unwrap_or_else(|| path.as_str().to_owned()),
                })
            }
        };
        nodes.insert(path.as_str().to_owned(), node);
    }
    Ok(NamespaceProjection { nodes })
}

/// Explicit replicated state `E` as `project` takes it: per path, its live
/// heads (content and removing heads alike).
pub type ExplicitHeads = BTreeMap<String, Vec<PathHead>>;

/// A projected tree's nodes (`NamespaceProjection::nodes()`), taken as a
/// plain map so a test can hand an oracle a deliberately broken tree.
pub type ProjectedTree = BTreeMap<String, PhysicalNode>;

/// Proper ancestors of `path`, nearest first.
pub fn proper_ancestors(path: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(parent_of(path), |p| parent_of(p))
}

pub fn parent_of(path: &str) -> Option<&str> {
    path.rsplit_once('/').map(|(parent, _)| parent)
}

fn version_of(head: &PathHead) -> Option<[u8; 32]> {
    head.content.as_ref().map(|c| c.version_hash)
}

/// `NeedsDirectory`, derived straight from `E` and never through
/// `project`: `p` holds a live Directory head, or `p` is a proper ancestor
/// of a path holding any live content head. A content head is live
/// whatever else is concurrent at its path, because a concurrent tombstone
/// loses to content, so "has a content head" is the whole test.
pub fn reference_needs_directory(
    heads: &ExplicitHeads,
    kind_of: &impl Fn(&[u8; 32]) -> Option<RecordKind>,
) -> BTreeSet<String> {
    let mut needs = BTreeSet::new();
    for (path, path_heads) in heads {
        let versions: Vec<[u8; 32]> = path_heads.iter().filter_map(version_of).collect();
        if versions.is_empty() {
            continue;
        }
        if versions.iter().any(|v| kind_of(v) == Some(RecordKind::Directory)) {
            needs.insert(path.clone());
        }
        needs.extend(proper_ancestors(path).map(str::to_string));
    }
    needs
}

// ---------------------------------------------------------------------------
// Projection oracles
// ---------------------------------------------------------------------------

/// Checks `projection` against `E` with rules re-derived here, not borrowed
/// from `project`:
///
/// * the directory set is exactly [`reference_needs_directory`];
/// * a directory is explicit iff its path has a live Directory head, and
///   then carries one of those heads' versions;
/// * every node's parent is a directory, and no leaf sits at a path that
///   must be a directory;
/// * a leaf is `AtPath` iff it sits at its own source path, and a copy
///   (`ConflictCopy`) is a sibling of its source;
/// * every live File/Symlink version of every path is placed somewhere
///   (no data loss on a shape conflict), and every placed leaf is a live
///   version of its source path (nothing invented).
pub fn check_projection(
    heads: &ExplicitHeads,
    kind_of: &impl Fn(&[u8; 32]) -> Option<RecordKind>,
    nodes: &ProjectedTree,
) -> Vec<NamespaceViolation> {
    use NamespaceViolationKind as K;
    let mut out = Vec::new();
    let needs = reference_needs_directory(heads, kind_of);

    let projected_dirs: BTreeSet<&String> =
        nodes.iter().filter(|(_, n)| n.is_directory()).map(|(p, _)| p).collect();
    for path in &needs {
        if !projected_dirs.contains(path) {
            out.push(violation(
                K::NeedsDirectoryClosure,
                path,
                vec![],
                format!("NeedsDirectory holds but the projection has {:?}", nodes.get(path)),
            ));
        }
    }
    for path in &projected_dirs {
        if !needs.contains(*path) {
            out.push(violation(
                K::NeedsDirectoryClosure,
                path,
                vec![],
                "projected directory with neither a live Directory head nor a live descendant",
            ));
        }
    }

    for (path, node) in nodes {
        if let Some(parent) = parent_of(path) {
            if !matches!(nodes.get(parent), Some(PhysicalNode::Directory(_))) {
                out.push(violation(
                    K::MalformedTree,
                    path,
                    vec![],
                    format!("parent {parent:?} is {:?}, not a directory", nodes.get(parent)),
                ));
            }
        }
        let path_heads = heads.get(path).map(Vec::as_slice).unwrap_or(&[]);
        let directory_versions: Vec<[u8; 32]> = path_heads
            .iter()
            .filter_map(version_of)
            .filter(|v| kind_of(v) == Some(RecordKind::Directory))
            .collect();
        match node {
            PhysicalNode::Directory(DirectoryNode::Explicit { version_hash }) => {
                if !directory_versions.contains(version_hash) {
                    out.push(violation(
                        K::ExplicitnessMislabel,
                        path,
                        vec![],
                        "explicit directory whose version is not a live Directory head here",
                    ));
                }
            }
            PhysicalNode::Directory(DirectoryNode::Structural) => {
                if !directory_versions.is_empty() {
                    out.push(violation(
                        K::ExplicitnessMislabel,
                        path,
                        vec![],
                        "structural directory at a path with a live Directory head",
                    ));
                }
            }
            PhysicalNode::Entry(entry) => {
                check_placed_entry(heads, kind_of, &needs, path, entry, &mut out);
            }
        }
    }

    // No loss: every live leaf version of every path is held by a node of
    // its own source, or by an entry a change authored at one of that
    // path's conflict-copy names holding the same bytes (the projection
    // does not copy such a loser twice).
    let holds = |path: &str, version: &[u8; 32]| {
        nodes.iter().any(|(at, node)| match node {
            PhysicalNode::Entry(e) if e.version_hash == *version => {
                e.source == path
                    || (e.placement == Placement::AtPath && is_conflict_copy_of(at, path))
            }
            _ => false,
        })
    };
    for (path, path_heads) in heads {
        for version in path_heads.iter().filter_map(version_of) {
            match kind_of(&version) {
                Some(RecordKind::Directory) | None => {}
                Some(_) if holds(path, &version) => {}
                Some(kind) => out.push(violation(
                    K::ShapeConflictLoss,
                    path,
                    vec![],
                    format!("live {kind:?} version {} is placed nowhere", short_hex(&version)),
                )),
            }
        }
    }
    out
}

fn check_placed_entry(
    heads: &ExplicitHeads,
    kind_of: &impl Fn(&[u8; 32]) -> Option<RecordKind>,
    needs: &BTreeSet<String>,
    path: &str,
    entry: &PlacedEntry,
    out: &mut Vec<NamespaceViolation>,
) {
    use NamespaceViolationKind as K;
    if needs.contains(path) {
        out.push(violation(
            K::MalformedTree,
            path,
            vec![],
            format!("{:?} leaf at a path that must be a directory", entry.kind),
        ));
    }
    let at_own_path = entry.source == path;
    match entry.placement {
        Placement::AtPath if !at_own_path => out.push(violation(
            K::MalformedTree,
            path,
            vec![],
            format!("AtPath leaf whose source is {:?}", entry.source),
        )),
        Placement::ConflictCopy if at_own_path || parent_of(path) != parent_of(&entry.source) => {
            out.push(violation(
                K::MalformedTree,
                path,
                vec![],
                format!(
                    "{:?} copy is not a sibling of its source {:?}",
                    entry.placement, entry.source
                ),
            ))
        }
        _ => {}
    }
    let source_versions: Vec<[u8; 32]> =
        heads.get(&entry.source).into_iter().flatten().filter_map(version_of).collect();
    if !source_versions.contains(&entry.version_hash) {
        out.push(violation(
            K::InventedEntry,
            path,
            vec![],
            format!(
                "leaf version {} is not a live head of its source {:?}",
                short_hex(&entry.version_hash),
                entry.source
            ),
        ));
    } else if kind_of(&entry.version_hash) != Some(entry.kind) {
        out.push(violation(
            K::MalformedTree,
            path,
            vec![],
            format!("leaf labelled {:?} for a version of another kind", entry.kind),
        ));
    }
}

/// Checks that `project` is a function of `E` alone: the same tree for the same head *sets*
/// in another order, with an extra path that holds only tombstones, and
/// on a second call. Each deviation is one [`NamespaceViolationKind::
/// ProjectionImpure`] naming what was perturbed.
pub fn check_projection_purity(
    heads: &ExplicitHeads,
    kind_of: &impl Fn(&[u8; 32]) -> Option<RecordKind>,
) -> Vec<NamespaceViolation> {
    use NamespaceViolationKind as K;
    let base = match project(heads, kind_of) {
        Ok(tree) => tree.nodes().clone(),
        Err(error) => {
            return vec![violation(K::ProjectionFailed, "", vec![], error.to_string())];
        }
    };
    let mut perturbations: Vec<(&str, ExplicitHeads)> = Vec::new();

    let mut reversed = heads.clone();
    reversed.values_mut().for_each(|h| h.reverse());
    perturbations.push(("heads reversed per path", reversed));

    let mut rotated = heads.clone();
    rotated.values_mut().filter(|h| !h.is_empty()).for_each(|h| h.rotate_left(1));
    perturbations.push(("heads rotated per path", rotated));

    let mut with_tombstone_path = heads.clone();
    if let Some(template) = heads.values().flatten().next() {
        let mut tombstone = template.clone();
        tombstone.content = None;
        with_tombstone_path.insert(unused_path(heads), vec![tombstone]);
        perturbations.push(("an extra tombstone-only path", with_tombstone_path));
    }

    perturbations.push(("a second call", heads.clone()));

    let mut out = Vec::new();
    for (what, perturbed) in perturbations {
        match project(&perturbed, kind_of) {
            Ok(tree) if *tree.nodes() == base => {}
            Ok(tree) => out.push(violation(
                K::ProjectionImpure,
                "",
                vec![],
                format!("{what} changed the tree: {base:?} vs {:?}", tree.nodes()),
            )),
            Err(error) => {
                out.push(violation(K::ProjectionImpure, "", vec![], format!("{what}: {error}")))
            }
        }
    }
    out
}

fn unused_path(heads: &ExplicitHeads) -> String {
    (0..).map(|n| format!("zz-tombstone-only-{n}")).find(|p| !heads.contains_key(p)).unwrap()
}

fn short_hex(bytes: &[u8; 32]) -> String {
    bytes[..4].iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Disk trees
// ---------------------------------------------------------------------------

/// One object on disk, as `lstat` sees it. Symlinks are never followed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DiskNode {
    /// `mode` is the permission bits (`st_mode & 0o7777`; 0 where the
    /// platform has none): a directory's `unix_mode` is replicated state
    /// (D1), so two devices holding `d` at 0755 and 0700 have not
    /// converged.
    Directory {
        mode: u32,
    },
    File {
        sha256: String,
    },
    Symlink {
        target: String,
    },
    /// A socket, fifo, device node: nothing this engine replicates.
    Other,
}

impl DiskNode {
    pub fn is_directory(&self) -> bool {
        matches!(self, DiskNode::Directory { .. })
    }

    /// A directory with the mode `create_dir` gives one here and now (the
    /// process umask applied), for expected trees in tests whose
    /// directories nobody chmods.
    pub fn fresh_directory() -> DiskNode {
        static MODE: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
        let mode = *MODE.get_or_init(|| {
            let probe = tempfile::tempdir().expect("probe dir");
            let dir = probe.path().join("d");
            std::fs::create_dir(&dir).expect("probe mkdir");
            directory_mode(&std::fs::symlink_metadata(&dir).expect("probe lstat"))
        });
        DiskNode::Directory { mode }
    }

    pub fn kind_label(&self) -> &'static str {
        match self {
            DiskNode::Directory { .. } => "directory",
            DiskNode::File { .. } => "file",
            DiskNode::Symlink { .. } => "symlink",
            DiskNode::Other => "other",
        }
    }
}

/// A root's physical tree: every object under it keyed by its
/// forward-slash root-relative path. Unlike every older snapshot helper in
/// this harness, directories are entries in their own right, so an empty
/// directory is visible.
pub type DiskTree = BTreeMap<String, DiskNode>;

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// Walks `root` with `lstat` semantics. The root itself is not an entry;
/// engine-private names ([`is_engine_private_name`]) are skipped with
/// everything under them. Unreadable objects are skipped, as
/// in every other walk here (a race with a live writer is not an oracle
/// finding).
pub fn disk_tree(root: &Path) -> DiskTree {
    let mut out = DiskTree::new();
    walk(root, root, &mut out);
    out
}

fn walk(root: &Path, dir: &Path, out: &mut DiskTree) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        if is_engine_private_name(&entry.file_name()) {
            continue;
        }
        let path = entry.path();
        let Ok(rel) = path.strip_prefix(root) else { continue };
        let rel = rel.to_string_lossy().replace('\\', "/");
        let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
        let file_type = meta.file_type();
        let node = if file_type.is_symlink() {
            let Ok(target) = std::fs::read_link(&path) else { continue };
            DiskNode::Symlink { target: target.to_string_lossy().into_owned() }
        } else if file_type.is_dir() {
            walk(root, &path, out);
            DiskNode::Directory { mode: directory_mode(&meta) }
        } else if file_type.is_file() {
            let Ok(bytes) = std::fs::read(&path) else { continue };
            DiskNode::File { sha256: sha256_hex(&bytes) }
        } else {
            DiskNode::Other
        };
        out.insert(rel, node);
    }
}

#[cfg(unix)]
fn directory_mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn directory_mode(_meta: &std::fs::Metadata) -> u32 {
    0
}

/// What a projected leaf's version must look like on disk. `None` from
/// the caller's lookup means "check the kind only".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedLeaf {
    FileSha256(String),
    SymlinkTarget(String),
}

/// The disk directories the projection does not want, split three ways.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtraDirectories {
    /// The engine is responsible for it, and untracked content sits
    /// somewhere below: deleting it would fail with `ENOTEMPTY`, so it is
    /// kept and must be reported retained (D4).
    pub retained: BTreeSet<String>,
    /// No origin the engine could act on (a user directory not captured
    /// yet, a structural directory whose provenance was lost and is now
    /// `OriginUnknown`, an ignored directory): kept whatever it holds, and
    /// itself untracked content for its ancestors (D6).
    pub unowned: BTreeSet<String>,
    /// The engine is responsible for it and nothing untracked is below:
    /// it must be gone.
    pub leftover: BTreeSet<String>,
}

/// Splits the directories on disk that `nodes` has no node for.
///
/// `engine_owned(path)` is the caller's record that the engine is
/// responsible for the directory at `path`: it replicated it, created it
/// as a container, or holds its structural origin. Emptiness alone is no
/// such evidence, since the engine may not delete an empty directory it
/// cannot tell apart from a user's.
///
/// Untracked content is any non-directory object the projection does not
/// know about (OS junk included: `.DS_Store` gets no exception) and any
/// unowned directory. An owned directory with untracked content below is
/// retained, without any is leftover; an unowned one is unowned.
pub fn classify_extra_directories(
    disk: &DiskTree,
    nodes: &ProjectedTree,
    engine_owned: &dyn Fn(&str) -> bool,
) -> ExtraDirectories {
    let mut out = ExtraDirectories::default();
    let mut untracked: Vec<&String> = Vec::new();
    for (path, node) in disk {
        if nodes.contains_key(path) {
            continue; // wanted, or a kind mismatch the caller reports
        }
        if !node.is_directory() {
            untracked.push(path);
        } else if !engine_owned(path) {
            out.unowned.insert(path.clone());
            untracked.push(path);
        }
    }
    for (path, node) in disk {
        if !node.is_directory() || nodes.contains_key(path) || out.unowned.contains(path) {
            continue;
        }
        let holds_untracked = untracked
            .iter()
            .any(|leaf| leaf.len() > path.len() + 1 && leaf.starts_with(&format!("{path}/")));
        if holds_untracked {
            out.retained.insert(path.clone());
        } else {
            out.leftover.insert(path.clone());
        }
    }
    out
}

/// Compares device `device`'s physical tree to `projection`:
///
/// * every projected node is on disk with the right kind (and, where
///   `expected_leaf` names it, the right bytes or target);
/// * every directory on disk the projection does not want is retained or
///   unowned (see [`classify_extra_directories`], both returned) or a
///   [`NamespaceViolationKind::LeftoverDirectory`].
///
/// Untracked leaves themselves are not violations here: whether a stray
/// file is data loss, corruption or user content is the file oracles'
/// question.
pub fn check_disk_against_projection(
    device: usize,
    disk: &DiskTree,
    nodes: &ProjectedTree,
    engine_owned: &dyn Fn(&str) -> bool,
    expected_leaf: impl Fn(&PlacedEntry) -> Option<ExpectedLeaf>,
) -> (Vec<NamespaceViolation>, ExtraDirectories) {
    use NamespaceViolationKind as K;
    let mut out = Vec::new();
    for (path, node) in nodes {
        let on_disk = disk.get(path);
        match (node, on_disk) {
            (_, None) => out.push(violation(
                K::MissingNode,
                path,
                vec![device],
                format!("projection wants {node:?}, disk has nothing"),
            )),
            (PhysicalNode::Directory(_), Some(DiskNode::Directory { .. })) => {}
            (PhysicalNode::Directory(_), Some(other)) => out.push(violation(
                K::KindMismatch,
                path,
                vec![device],
                format!("projection wants a directory, disk has a {}", other.kind_label()),
            )),
            (PhysicalNode::Entry(entry), Some(found)) => {
                let kind_ok = matches!(
                    (entry.kind, found),
                    (RecordKind::File, DiskNode::File { .. })
                        | (RecordKind::Symlink, DiskNode::Symlink { .. })
                );
                if !kind_ok {
                    out.push(violation(
                        K::KindMismatch,
                        path,
                        vec![device],
                        format!(
                            "projection wants a {:?}, disk has a {}",
                            entry.kind,
                            found.kind_label()
                        ),
                    ));
                    continue;
                }
                let content_ok = match (expected_leaf(entry), found) {
                    (None, _) => true,
                    (Some(ExpectedLeaf::FileSha256(want)), DiskNode::File { sha256 }) => {
                        *sha256 == want
                    }
                    (Some(ExpectedLeaf::SymlinkTarget(want)), DiskNode::Symlink { target }) => {
                        *target == want
                    }
                    (Some(_), _) => false,
                };
                if !content_ok {
                    out.push(violation(
                        K::ContentMismatch,
                        path,
                        vec![device],
                        format!("{found:?} is not version {}", short_hex(&entry.version_hash)),
                    ));
                }
            }
        }
    }
    let extra = classify_extra_directories(disk, nodes, engine_owned);
    for path in &extra.leftover {
        out.push(violation(
            K::LeftoverDirectory,
            path,
            vec![device],
            "engine-owned directory on disk that the projection does not want, with nothing \
             untracked inside",
        ));
    }
    (out, extra)
}

/// Checks the product's own "retained (local untracked content)" claims
/// against the disk, both ways:
///
/// * a claimed directory must be retained: it exists, the projection does
///   not want it (a wanted directory is simply present), and untracked
///   content sits below it ([`NamespaceViolationKind::RetainedMisclassified`]);
/// * a retained directory must be claimed: a product that silently keeps
///   an `ENOTEMPTY` directory hides it from the user
///   ([`NamespaceViolationKind::RetainedUnreported`]).
///
/// An unowned directory may be claimed or not: the engine never tried to
/// remove it, so whether it says so is not decided here.
pub fn check_retained_claims(
    device: usize,
    claimed: &BTreeSet<String>,
    disk: &DiskTree,
    nodes: &ProjectedTree,
    engine_owned: &dyn Fn(&str) -> bool,
) -> Vec<NamespaceViolation> {
    let actual = classify_extra_directories(disk, nodes, engine_owned);
    let misclaimed = claimed
        .iter()
        .filter(|path| !actual.retained.contains(*path) && !actual.unowned.contains(*path))
        .map(|path| {
            violation(
                NamespaceViolationKind::RetainedMisclassified,
                path,
                vec![device],
                format!(
                    "reported retained, but disk has {:?} and projection has {:?}",
                    disk.get(path),
                    nodes.get(path)
                ),
            )
        });
    let unreported = actual.retained.iter().filter(|path| !claimed.contains(*path)).map(|path| {
        violation(
            NamespaceViolationKind::RetainedUnreported,
            path,
            vec![device],
            "kept because untracked content sits below it, but not reported retained",
        )
    });
    misclaimed.chain(unreported).collect()
}

/// Kind-aware convergence: every device's tree must equal the first's,
/// directories included. A path whose object differs in kind is a
/// [`NamespaceViolationKind::KindMismatch`]; any other difference
/// (present on one side only, different bytes) is a
/// [`NamespaceViolationKind::TreeDivergence`].
pub fn check_trees_converge(trees: &[(usize, DiskTree)]) -> Vec<NamespaceViolation> {
    use NamespaceViolationKind as K;
    let Some(((reference_device, reference), rest)) = trees.split_first() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (device, tree) in rest {
        let paths: BTreeSet<&String> = reference.keys().chain(tree.keys()).collect();
        for path in paths {
            let (a, b) = (reference.get(path), tree.get(path));
            if a == b {
                continue;
            }
            let kind = match (a, b) {
                (Some(x), Some(y)) if x.kind_label() != y.kind_label() => K::KindMismatch,
                _ => K::TreeDivergence,
            };
            out.push(violation(
                kind,
                path,
                vec![*reference_device, *device],
                format!("device {reference_device} has {a:?}, device {device} has {b:?}"),
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_replica_engine::conflict::PathHeadContent;

    const FILE_1: [u8; 32] = [0x11; 32];
    const FILE_2: [u8; 32] = [0x12; 32];
    const DIR_1: [u8; 32] = [0xD1; 32];
    const LINK_1: [u8; 32] = [0x51; 32];

    fn kind_of(v: &[u8; 32]) -> Option<RecordKind> {
        match *v {
            FILE_1 | FILE_2 => Some(RecordKind::File),
            DIR_1 => Some(RecordKind::Directory),
            LINK_1 => Some(RecordKind::Symlink),
            _ => None,
        }
    }

    fn head(change: u8, lamport: u64, content: Option<[u8; 32]>) -> PathHead {
        let mut change_hash = [0u8; 32];
        change_hash[0] = change;
        PathHead {
            change_hash,
            rank: lamport,
            device_id: format!("dev-{change}"),
            naming_device_id: format!("dev-{change}"),
            content: content
                .map(|version_hash| PathHeadContent { version_hash, mtime_unix_nanos: 0 }),
        }
    }

    fn state(entries: Vec<(&str, Vec<PathHead>)>) -> ExplicitHeads {
        entries.into_iter().map(|(p, h)| (p.to_string(), h)).collect()
    }

    fn kinds(violations: &[NamespaceViolation]) -> BTreeSet<NamespaceViolationKind> {
        violations.iter().map(|v| v.kind).collect()
    }

    /// The shape-conflict state (File `a` against a live `a/x`, Symlink `l`
    /// against `l/y`) plus a deleted explicit directory with a surviving
    /// child: every oracle must accept `project`'s
    /// answer for it.
    fn shape_conflict_state() -> ExplicitHeads {
        state(vec![
            ("a", vec![head(1, 1, Some(FILE_1))]),
            ("a/x", vec![head(2, 1, Some(FILE_2))]),
            ("d", vec![head(3, 2, None)]),
            ("d/keep", vec![head(4, 1, Some(FILE_1))]),
            ("e", vec![head(5, 1, Some(DIR_1))]),
            ("l", vec![head(6, 1, Some(LINK_1))]),
            ("l/y", vec![head(7, 1, Some(FILE_2))]),
        ])
    }

    #[test]
    fn project_passes_every_projection_oracle_on_shape_conflicts() {
        let heads = shape_conflict_state();
        let tree = project(&heads, kind_of).unwrap();
        let violations = check_projection(&heads, &kind_of, tree.nodes());
        assert!(violations.is_empty(), "{violations:#?}");
        assert!(check_projection_purity(&heads, &kind_of).is_empty());
        assert_eq!(
            reference_needs_directory(&heads, &kind_of),
            ["a", "d", "e", "l"].into_iter().map(String::from).collect()
        );
    }

    /// The oracles hold `project` to rules derived independently; they must
    /// not object to anything `project` really produces. Exhaustive over a
    /// three-deep chain with up to two concurrent heads of every kind per
    /// path, so a false positive cannot hide behind a hand-picked state.
    #[test]
    fn projection_oracles_accept_every_real_projection_of_a_small_tree() {
        type Choice = &'static [Option<[u8; 32]>];
        const CHOICES: [Choice; 10] = [
            &[],
            &[None],
            &[Some(FILE_1)],
            &[Some(FILE_2)],
            &[Some(DIR_1)],
            &[Some(LINK_1)],
            &[Some(FILE_1), Some(FILE_2)],
            &[Some(FILE_1), Some(DIR_1)],
            &[Some(DIR_1), None],
            &[Some(LINK_1), None],
        ];
        let paths = ["a", "a/x", "a/x/y"];
        let mut checked = 0;
        for i in 0..CHOICES.len().pow(paths.len() as u32) {
            let mut heads = ExplicitHeads::new();
            let mut rest = i;
            for (p, path) in paths.iter().enumerate() {
                let choice = CHOICES[rest % CHOICES.len()];
                rest /= CHOICES.len();
                if choice.is_empty() {
                    continue;
                }
                let path_heads = choice
                    .iter()
                    .enumerate()
                    .map(|(h, content)| head((p * 4 + h) as u8 + 1, 1 + h as u64, *content))
                    .collect();
                heads.insert(path.to_string(), path_heads);
            }
            let tree = project(&heads, kind_of).unwrap();
            let violations = check_projection(&heads, &kind_of, tree.nodes());
            assert!(violations.is_empty(), "state {i}: {heads:?}\n{violations:#?}");
            let impure = check_projection_purity(&heads, &kind_of);
            assert!(impure.is_empty(), "state {i}: {impure:#?}");
            checked += 1;
        }
        assert_eq!(checked, 1000);
    }

    #[test]
    fn dropping_a_relocated_file_is_a_shape_conflict_loss() {
        let heads = shape_conflict_state();
        let mut nodes = project(&heads, kind_of).unwrap().nodes().clone();
        let relocated = nodes
            .iter()
            .find(|(_, n)| {
                matches!(n, PhysicalNode::Entry(e) if e.placement == Placement::ConflictCopy && e.source == "a")
            })
            .map(|(p, _)| p.clone())
            .expect("File a is relocated beside directory a");
        nodes.remove(&relocated);
        assert!(kinds(&check_projection(&heads, &kind_of, &nodes))
            .contains(&NamespaceViolationKind::ShapeConflictLoss));
    }

    #[test]
    fn a_file_winning_over_its_live_descendant_is_malformed() {
        // The pre-projection per-path answer: File `a` at `a` while `a/x`
        // lives. Closure and tree shape must both object.
        let heads = shape_conflict_state();
        let mut nodes = project(&heads, kind_of).unwrap().nodes().clone();
        nodes.insert(
            "a".into(),
            PhysicalNode::Entry(PlacedEntry {
                kind: RecordKind::File,
                version_hash: FILE_1,
                source: "a".into(),
                placement: Placement::AtPath,
            }),
        );
        let found = kinds(&check_projection(&heads, &kind_of, &nodes));
        assert!(found.contains(&NamespaceViolationKind::NeedsDirectoryClosure), "{found:?}");
        assert!(found.contains(&NamespaceViolationKind::MalformedTree), "{found:?}");
    }

    #[test]
    fn a_structural_directory_labelled_explicit_is_caught() {
        let heads = shape_conflict_state();
        let mut nodes = project(&heads, kind_of).unwrap().nodes().clone();
        nodes.insert(
            "d".into(),
            PhysicalNode::Directory(DirectoryNode::Explicit { version_hash: DIR_1 }),
        );
        assert!(kinds(&check_projection(&heads, &kind_of, &nodes))
            .contains(&NamespaceViolationKind::ExplicitnessMislabel));
    }

    #[test]
    fn a_directory_nothing_justifies_is_a_closure_violation() {
        let heads = shape_conflict_state();
        let mut nodes = project(&heads, kind_of).unwrap().nodes().clone();
        nodes.insert("ghost".into(), PhysicalNode::Directory(DirectoryNode::Structural));
        assert!(kinds(&check_projection(&heads, &kind_of, &nodes))
            .contains(&NamespaceViolationKind::NeedsDirectoryClosure));
    }

    #[test]
    fn an_invented_leaf_is_caught() {
        let heads = shape_conflict_state();
        let mut nodes = project(&heads, kind_of).unwrap().nodes().clone();
        nodes.insert(
            "d/keep".into(),
            PhysicalNode::Entry(PlacedEntry {
                kind: RecordKind::File,
                version_hash: FILE_2,
                source: "d/keep".into(),
                placement: Placement::AtPath,
            }),
        );
        assert!(kinds(&check_projection(&heads, &kind_of, &nodes))
            .contains(&NamespaceViolationKind::InventedEntry));
    }

    fn dir() -> DiskNode {
        DiskNode::Directory { mode: 0o755 }
    }

    fn owned(_: &str) -> bool {
        true
    }

    fn file(bytes: &[u8]) -> DiskNode {
        DiskNode::File { sha256: sha256_hex(bytes) }
    }

    fn disk(entries: Vec<(&str, DiskNode)>) -> DiskTree {
        entries.into_iter().map(|(p, n)| (p.to_string(), n)).collect()
    }

    /// `rm -rf linux/` on a peer: the projection has nothing under
    /// `linux`, this device still holds the empty directory.
    #[test]
    fn an_empty_directory_left_after_rm_rf_is_leftover() {
        let heads = state(vec![("linux/Makefile", vec![head(1, 2, None)])]);
        let tree = project(&heads, kind_of).unwrap();
        let (violations, retained) = check_disk_against_projection(
            0,
            &disk(vec![("linux", dir()), ("linux/arch", dir())]),
            tree.nodes(),
            &owned,
            |_| None,
        );
        assert!(retained.retained.is_empty() && retained.unowned.is_empty());
        let leftovers: BTreeSet<&str> = violations
            .iter()
            .filter(|v| v.kind == NamespaceViolationKind::LeftoverDirectory)
            .map(|v| v.path.as_str())
            .collect();
        assert_eq!(leftovers, BTreeSet::from(["linux", "linux/arch"]));
    }

    /// Untracked content (OS junk included) keeps its directory and
    /// every ancestor, and none of that is a violation.
    #[test]
    fn a_directory_holding_untracked_content_is_retained_not_leftover() {
        let tree = project(&ExplicitHeads::new(), kind_of).unwrap();
        let on_disk = disk(vec![
            ("linux", dir()),
            ("linux/arch", dir()),
            ("linux/arch/.DS_Store", file(b"junk")),
            ("empty", dir()),
        ]);
        let (violations, extra) =
            check_disk_against_projection(0, &on_disk, tree.nodes(), &owned, |_| None);
        assert_eq!(extra.retained, BTreeSet::from(["linux".to_string(), "linux/arch".to_string()]));
        assert_eq!(violations.len(), 1, "{violations:#?}");
        assert_eq!(violations[0].kind, NamespaceViolationKind::LeftoverDirectory);
        assert_eq!(violations[0].path, "empty");

        let claims = BTreeSet::from(["linux".to_string(), "empty".to_string()]);
        let found = check_retained_claims(0, &claims, &on_disk, tree.nodes(), &owned);
        let found: Vec<(NamespaceViolationKind, &str)> =
            found.iter().map(|v| (v.kind, v.path.as_str())).collect();
        assert_eq!(
            found,
            vec![
                (NamespaceViolationKind::RetainedMisclassified, "empty"),
                (NamespaceViolationKind::RetainedUnreported, "linux/arch"),
            ]
        );
    }

    /// D4=A: a directory kept by `ENOTEMPTY` must be reported retained. A
    /// product that keeps `a/` because of an untracked `.DS_Store` and
    /// says nothing is caught, not passed by an empty claim set.
    #[test]
    fn a_silently_retained_directory_is_unreported() {
        let tree = project(&ExplicitHeads::new(), kind_of).unwrap();
        let on_disk = disk(vec![("a", dir()), ("a/.DS_Store", file(b"junk"))]);
        let found = check_retained_claims(0, &BTreeSet::new(), &on_disk, tree.nodes(), &owned);
        assert_eq!(kinds(&found), BTreeSet::from([NamespaceViolationKind::RetainedUnreported]));
        assert_eq!(found[0].path, "a");
        let claims = BTreeSet::from(["a".to_string()]);
        assert!(check_retained_claims(0, &claims, &on_disk, tree.nodes(), &owned).is_empty());
    }

    /// D6: B lost `linux/`'s structural provenance (`OriginUnknown`), then
    /// A deleted the last file under it. The engine may not delete the now
    /// empty `linux/` on emptiness alone, so the oracle must not demand
    /// it; only a directory the engine is responsible for is a leftover.
    #[test]
    fn an_empty_directory_of_unknown_origin_is_kept_not_leftover() {
        let heads = state(vec![("linux/Makefile", vec![head(1, 2, None)])]);
        let tree = project(&heads, kind_of).unwrap();
        let on_disk = disk(vec![("linux", dir()), ("linux/arch", dir())]);

        let (violations, extra) =
            check_disk_against_projection(0, &on_disk, tree.nodes(), &|_| false, |_| None);
        assert!(violations.is_empty(), "{violations:#?}");
        assert_eq!(extra.unowned, BTreeSet::from(["linux".to_string(), "linux/arch".to_string()]));

        // The engine made `linux/arch` but has no origin for `linux`: the
        // child must go, the parent stays.
        let (violations, extra) = check_disk_against_projection(
            0,
            &on_disk,
            tree.nodes(),
            &|p| p == "linux/arch",
            |_| None,
        );
        assert_eq!(kinds(&violations), BTreeSet::from([NamespaceViolationKind::LeftoverDirectory]));
        assert_eq!(violations[0].path, "linux/arch");
        assert_eq!(extra.unowned, BTreeSet::from(["linux".to_string()]));

        // The reverse: an unowned (say, ignored) empty directory under an
        // owned one keeps the owned one alive as retained, not leftover.
        let (violations, extra) =
            check_disk_against_projection(0, &on_disk, tree.nodes(), &|p| p == "linux", |_| None);
        assert!(violations.is_empty(), "{violations:#?}");
        assert_eq!(extra.retained, BTreeSet::from(["linux".to_string()]));
        assert_eq!(extra.unowned, BTreeSet::from(["linux/arch".to_string()]));
    }

    #[test]
    fn disk_matching_the_projection_passes_and_kind_errors_are_named() {
        let heads = shape_conflict_state();
        let tree = project(&heads, kind_of).unwrap();
        let expected = |e: &PlacedEntry| match e.version_hash {
            FILE_1 => Some(ExpectedLeaf::FileSha256(sha256_hex(b"one"))),
            FILE_2 => Some(ExpectedLeaf::FileSha256(sha256_hex(b"two"))),
            LINK_1 => Some(ExpectedLeaf::SymlinkTarget("target".into())),
            _ => None,
        };
        let mut good: DiskTree = tree
            .nodes()
            .iter()
            .map(|(p, n)| {
                let node = match n {
                    PhysicalNode::Directory(_) => dir(),
                    PhysicalNode::Entry(e) => match expected(e).unwrap() {
                        ExpectedLeaf::FileSha256(h) => DiskNode::File { sha256: h },
                        ExpectedLeaf::SymlinkTarget(t) => DiskNode::Symlink { target: t },
                    },
                };
                (p.clone(), node)
            })
            .collect();
        let (violations, extra) =
            check_disk_against_projection(1, &good, tree.nodes(), &owned, expected);
        assert!(violations.is_empty() && extra == ExtraDirectories::default(), "{violations:#?}");

        // Per-path winner materialized over the structural directory.
        good.insert("a".into(), file(b"one"));
        let (violations, _) =
            check_disk_against_projection(1, &good, tree.nodes(), &owned, expected);
        assert!(kinds(&violations).contains(&NamespaceViolationKind::KindMismatch));

        good.insert("a".into(), dir());
        good.insert("d/keep".into(), file(b"two"));
        let (violations, _) =
            check_disk_against_projection(1, &good, tree.nodes(), &owned, expected);
        assert_eq!(kinds(&violations), BTreeSet::from([NamespaceViolationKind::ContentMismatch]));

        good.remove("d/keep");
        let (violations, _) =
            check_disk_against_projection(1, &good, tree.nodes(), &owned, expected);
        assert_eq!(kinds(&violations), BTreeSet::from([NamespaceViolationKind::MissingNode]));
    }

    #[test]
    fn trees_that_differ_only_by_an_empty_directory_do_not_converge() {
        let a = disk(vec![("f", file(b"x"))]);
        let b = disk(vec![("f", file(b"x")), ("linux", dir())]);
        let found = check_trees_converge(&[(0, a.clone()), (1, b)]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, NamespaceViolationKind::TreeDivergence);
        assert_eq!(found[0].path, "linux");

        let c = disk(vec![("f", dir())]);
        let found = check_trees_converge(&[(0, a.clone()), (2, c)]);
        assert_eq!(kinds(&found), BTreeSet::from([NamespaceViolationKind::KindMismatch]));
        assert!(check_trees_converge(&[(0, a.clone()), (1, a)]).is_empty());
    }

    /// D1: a directory's mode is replicated state. `d` at 0755 on one
    /// device and 0700 on the other has not converged.
    #[test]
    fn trees_that_differ_only_by_a_directory_mode_do_not_converge() {
        let a = disk(vec![("d", DiskNode::Directory { mode: 0o755 })]);
        let b = disk(vec![("d", DiskNode::Directory { mode: 0o700 })]);
        let found = check_trees_converge(&[(0, a), (1, b)]);
        assert_eq!(kinds(&found), BTreeSet::from([NamespaceViolationKind::TreeDivergence]));
        assert_eq!(found[0].path, "d");
    }

    #[test]
    fn disk_tree_sees_empty_directories_and_does_not_follow_symlinks() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("a/empty")).unwrap();
        std::fs::write(root.path().join("a/f"), b"bytes").unwrap();
        std::fs::write(root.path().join(ROOT_IDENTITY_MARKER), b"id").unwrap();
        std::fs::write(root.path().join(SYNC_ROOT_LOCK_FILE_NAME), b"lock").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("a", root.path().join("link")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(root.path().join("a/empty"), perms).unwrap();
        }
        let tree = disk_tree(root.path());
        assert_eq!(tree.get("a"), Some(&DiskNode::fresh_directory()));
        #[cfg(unix)]
        assert_eq!(tree.get("a/empty"), Some(&DiskNode::Directory { mode: 0o700 }));
        assert_eq!(tree.get("a/f"), Some(&file(b"bytes")));
        assert!(!tree.contains_key(ROOT_IDENTITY_MARKER));
        assert!(!tree.contains_key(SYNC_ROOT_LOCK_FILE_NAME));
        #[cfg(unix)]
        {
            assert_eq!(tree.get("link"), Some(&DiskNode::Symlink { target: "a".into() }));
            assert!(!tree.contains_key("link/f"), "symlink must not be followed");
        }
    }
}
