//! Native's desired tree: what the materializer has to make true on disk,
//! as a pure function of `NativeState`'s live heads and the version store's
//! record kinds, and of nothing else.
//!
//! Every path is its own entry. A path whose heads are uncontested projects
//! to a node; a contested path (two versions, a file where a directory is
//! required, or a version record that has not arrived) projects `Pending` and
//! has no node: the materializer leaves it and everything below it alone
//! until the loser's author renames its head. Nothing is recorded while
//! planning, so a plan is a read.
//!
//! The per-path answer has the shape of [`crate::desired_state`]'s
//! `DesiredPathState`.

use std::collections::{BTreeSet, HashMap};

use rusqlite::Connection;

use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::ids::{FolderGroupId, SyncPath, VersionHash};
use yadorilink_replica_domain::native_plan::{
    NativeDesiredNode, NativeLevelPlan, NativeLocatedHead, NativePlannedNode,
};
use yadorilink_replica_domain::native_project::{
    project_path, DirectoryNode as ProjectedDirectory, Projection, Settled,
};
use yadorilink_replica_domain::native_state::{
    resolve_winner, Dot, HeadPayload, LiveHead, PathHeads,
};

use crate::desired_state::DesiredPathState;
use crate::error::SyncSqliteError;
use crate::native_store::{native_has_descendant_head, native_heads_at, native_heads_at_level};

/// The kind of every version among `heads`; a version whose record has not
/// arrived is `None`, and its path projects `Pending`.
fn lookup_kinds<'a>(
    conn: &Connection,
    group_id: &str,
    heads: impl IntoIterator<Item = &'a PathHeads>,
) -> Result<HashMap<VersionHash, Option<RecordKind>>, SyncSqliteError> {
    let mut kinds = HashMap::new();
    for path_heads in heads {
        for payload in path_heads.values() {
            if kinds.contains_key(&payload.version) {
                continue;
            }
            let kind = crate::dag_store::get_file_version(conn, group_id, &payload.version)?
                .map(|version| version.meta.record_kind);
            kinds.insert(payload.version, kind);
        }
    }
    Ok(kinds)
}

fn located(source: &SyncPath, dot: &Dot, payload: &HeadPayload) -> NativeLocatedHead {
    NativeLocatedHead {
        source_path: source.clone(),
        head: LiveHead { dot: dot.clone(), payload: payload.clone() },
    }
}

/// The best-ranked Directory head among `heads` -- the one whose metadata
/// an explicit directory carries.
fn best_directory_head(
    path: &SyncPath,
    heads: &PathHeads,
    kinds: &HashMap<VersionHash, Option<RecordKind>>,
) -> Option<NativeLocatedHead> {
    let live: Vec<LiveHead> = heads
        .iter()
        .filter(|(_, payload)| kinds.get(&payload.version) == Some(&Some(RecordKind::Directory)))
        .map(|(dot, payload)| LiveHead { dot: dot.clone(), payload: payload.clone() })
        .collect();
    resolve_winner(live.iter())
        .map(|head| NativeLocatedHead { source_path: path.clone(), head: head.clone() })
}

/// What a path projects to.
enum Planned {
    Absent,
    Node(NativePlannedNode),
    Contested,
}

fn plan_one(
    sync: &SyncPath,
    path_heads: &PathHeads,
    kinds: &HashMap<VersionHash, Option<RecordKind>>,
    has_descendant: bool,
) -> Result<Planned, SyncSqliteError> {
    let live = path_heads
        .iter()
        .map(|(dot, payload)| LiveHead { dot: dot.clone(), payload: payload.clone() });
    let projection =
        project_path(live, |version| kinds.get(version).copied().flatten(), has_descendant);
    let path = sync.as_str();
    Ok(match projection {
        Projection::Absent => Planned::Absent,
        Projection::Pending(_) => Planned::Contested,
        Projection::Settled(Settled::Directory(ProjectedDirectory::Structural)) => {
            Planned::Node(NativePlannedNode::StructuralDirectory)
        }
        Projection::Settled(Settled::Directory(ProjectedDirectory::Explicit { .. })) => {
            let head = best_directory_head(sync, path_heads, kinds).ok_or_else(|| {
                SyncSqliteError::CorruptState(format!(
                    "explicit directory at {path:?} without a directory head"
                ))
            })?;
            Planned::Node(NativePlannedNode::ExplicitDirectory { head })
        }
        Projection::Settled(Settled::Entry { kind, representative, .. }) => {
            let payload = path_heads.get(&representative).ok_or_else(|| {
                SyncSqliteError::CorruptState(format!("winner of {path:?} is not one of its heads"))
            })?;
            Planned::Node(NativePlannedNode::Entry {
                head: located(sync, &representative, payload),
                kind,
            })
        }
    })
}

fn contested_error(path: &str) -> SyncSqliteError {
    SyncSqliteError::NotFound(format!("{path} is contested or its version record is missing"))
}

/// What `path` is required to be, with the exact head each requirement
/// stands for. Fails closed (`NotFound`) for a contested path, and for one
/// whose version record has not arrived; never turns either into `Absent`.
pub fn native_plan_path(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<NativeDesiredNode, SyncSqliteError> {
    let group = FolderGroupId(group_id.to_owned());
    let sync = SyncPath(path.to_owned());
    let heads = native_heads_at(conn, &group, &sync)?;
    let path_heads: PathHeads = heads.into_iter().map(|h| (h.dot, h.payload)).collect();
    let kinds = lookup_kinds(conn, group_id, [&path_heads])?;
    let descendant = native_has_descendant_head(conn, &group, &sync)?;
    Ok(match plan_one(&sync, &path_heads, &kinds, descendant)? {
        Planned::Absent => NativeDesiredNode::Absent,
        Planned::Contested => return Err(contested_error(path)),
        Planned::Node(NativePlannedNode::StructuralDirectory) => {
            NativeDesiredNode::StructuralDirectory
        }
        Planned::Node(NativePlannedNode::ExplicitDirectory { head }) => {
            NativeDesiredNode::ExplicitDirectory { head }
        }
        Planned::Node(NativePlannedNode::Entry { head, kind }) => {
            NativeDesiredNode::Entry { head, kind }
        }
    })
}

/// What `path` is required to be given `heads`, the kinds of their versions,
/// and that the path has no live descendant: for a caller that holds those
/// facts from the install that wrote the heads; every other caller reads them
/// through [`native_desired_path_state`].
pub(crate) fn desired_path_state_of_unplaced_heads(
    path: &str,
    heads: Vec<LiveHead>,
    kinds: &HashMap<VersionHash, RecordKind>,
) -> Result<DesiredPathState, SyncSqliteError> {
    let sync = SyncPath(path.to_owned());
    let path_heads: PathHeads = heads.into_iter().map(|h| (h.dot, h.payload)).collect();
    let kinds: HashMap<VersionHash, Option<RecordKind>> =
        kinds.iter().map(|(version, kind)| (*version, Some(*kind))).collect();
    Ok(match plan_one(&sync, &path_heads, &kinds, false)? {
        Planned::Absent => DesiredPathState::Absent,
        Planned::Contested => return Err(contested_error(path)),
        Planned::Node(node) => desired_of_planned(node),
    })
}

fn desired_of_planned(node: NativePlannedNode) -> DesiredPathState {
    match node {
        NativePlannedNode::StructuralDirectory => DesiredPathState::StructuralDirectory,
        NativePlannedNode::ExplicitDirectory { head } => {
            DesiredPathState::ExplicitDirectory { version: head.version() }
        }
        NativePlannedNode::Entry { head, kind } => {
            DesiredPathState::Entry { kind, version: head.version() }
        }
    }
}

fn desired_of_node(node: NativeDesiredNode) -> DesiredPathState {
    match node {
        NativeDesiredNode::Absent => DesiredPathState::Absent,
        NativeDesiredNode::StructuralDirectory => DesiredPathState::StructuralDirectory,
        NativeDesiredNode::ExplicitDirectory { head } => {
            DesiredPathState::ExplicitDirectory { version: head.version() }
        }
        NativeDesiredNode::Entry { head, kind } => {
            DesiredPathState::Entry { kind, version: head.version() }
        }
    }
}

/// What `path` is required to be, as the state the materialization proof
/// records. The per-path counterpart of [`native_desired_level_projection`].
pub fn native_desired_path_state(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<DesiredPathState, SyncSqliteError> {
    Ok(desired_of_node(native_plan_path(conn, group_id, path)?))
}

/// `resolved_path_state_hash` of [`native_desired_path_state`].
pub fn native_desired_projected_path_state_hash(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<[u8; 32], SyncSqliteError> {
    Ok(native_desired_path_state(conn, group_id, path)?.resolved_path_state_hash(group_id, path))
}

/// One directory level of the desired tree with every node's exact head:
/// every node whose parent is `parent` (`""` for the root), and the paths of
/// the level that are contested.
pub fn native_plan_level(
    conn: &Connection,
    group_id: &str,
    parent: &str,
) -> Result<NativeLevelPlan, SyncSqliteError> {
    let group = FolderGroupId(group_id.to_owned());
    let (children, with_descendant) = native_heads_at_level(conn, &group, parent)?;
    let kinds = lookup_kinds(conn, group_id, children.values())?;
    let candidates: BTreeSet<&str> = children
        .keys()
        .map(SyncPath::as_str)
        .chain(with_descendant.iter().map(String::as_str))
        .collect();
    let mut plan = NativeLevelPlan::default();
    let empty = PathHeads::new();
    for candidate in candidates {
        let sync = SyncPath(candidate.to_owned());
        let heads = children.get(&sync).unwrap_or(&empty);
        match plan_one(&sync, heads, &kinds, with_descendant.contains(candidate))? {
            Planned::Absent => {}
            Planned::Contested => {
                plan.contested.insert(sync);
            }
            Planned::Node(node) => {
                plan.nodes.insert(sync, node);
            }
        }
    }
    Ok(plan)
}

/// The nodes of `parent`'s level plan at `names`, computed from those names'
/// own heads and live descendants and not from the whole level.
pub fn native_plan_nodes(
    conn: &Connection,
    group_id: &str,
    parent: &str,
    names: &BTreeSet<String>,
) -> Result<NativeLevelPlan, SyncSqliteError> {
    let group = FolderGroupId(group_id.to_owned());
    let mut plan = NativeLevelPlan::default();
    for name in names {
        if name.rsplit_once('/').map_or("", |(p, _)| p) != parent {
            continue;
        }
        let sync = SyncPath(name.clone());
        let heads = native_heads_at(conn, &group, &sync)?;
        let path_heads: PathHeads = heads.into_iter().map(|h| (h.dot, h.payload)).collect();
        let kinds = lookup_kinds(conn, group_id, [&path_heads])?;
        let descendant = native_has_descendant_head(conn, &group, &sync)?;
        match plan_one(&sync, &path_heads, &kinds, descendant)? {
            Planned::Absent => {}
            Planned::Contested => {
                plan.contested.insert(sync);
            }
            Planned::Node(node) => {
                plan.nodes.insert(sync, node);
            }
        }
    }
    Ok(plan)
}

/// The node [`native_plan_level`] of `path`'s parent puts at `path`, or `None`
/// when it puts nothing there. A contested path is not "nothing": it fails
/// closed (`NotFound`).
pub fn native_plan_node(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<Option<NativePlannedNode>, SyncSqliteError> {
    let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
    let mut plan = native_plan_nodes(conn, group_id, parent, &BTreeSet::from([path.to_owned()]))?;
    if plan.contested.contains(&SyncPath(path.to_owned())) {
        return Err(contested_error(path));
    }
    Ok(plan.nodes.remove(&SyncPath(path.to_owned())))
}

/// Arms the projection obligation of every path `delta` touched, once
/// `delta` has been installed into `NativeState`. `local` marks a delta
/// this device authored (its own edit is not a desired state it has yet to
/// place).
pub(crate) fn arm_projection_for_delta(
    conn: &Connection,
    group_id: &str,
    delta: &yadorilink_replica_domain::signed_delta::NativeDelta,
    local: bool,
) -> Result<
    std::collections::BTreeMap<String, crate::projection_obligations::ArmedObligation>,
    SyncSqliteError,
> {
    let paths: BTreeSet<&str> = delta.ops.iter().map(|op| op.path.as_str()).collect();
    let paths: Vec<&str> = paths.into_iter().collect();
    // A delta this device authored is not a desired state it has yet to place: its obligations
    // are written `Local` by the bump itself.
    let origin = if local {
        crate::projection_obligations::ObligationOrigin::Local
    } else {
        crate::projection_obligations::ObligationOrigin::Remote
    };
    let armed = crate::projection_obligations::bump_projection_obligations_with_origin(
        conn,
        group_id,
        &paths,
        crate::dag_store::now_unix_nanos(),
        origin,
    )?;
    crate::native_contest_candidates::note(conn, group_id, &paths)?;
    Ok(armed)
}

/// A version's metadata just became locally resolvable: every path whose
/// native live head names it was undecidable until now and has to be
/// materialized without waiting for another event. A no-op where the
/// native tables do not exist (a store that never held native state).
pub fn arm_projection_for_arrived_version(
    conn: &Connection,
    group_id: &str,
    version: &VersionHash,
) -> Result<(), SyncSqliteError> {
    let present: i64 = conn
        .prepare_cached(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' \
             AND name IN ('native_heads', 'projection_obligations')",
        )?
        .query_row([], |row| row.get(0))?;
    if present < 2 {
        return Ok(());
    }
    // `DISTINCT path` tempts the planner into walking the group's whole primary
    // key (already in path order) instead of the version index: a scan of every
    // head of the group for each version that arrives.
    let mut stmt = conn.prepare_cached(
        "SELECT DISTINCT path FROM native_heads INDEXED BY idx_native_heads_version \
         WHERE group_id = ?1 AND version = ?2",
    )?;
    let paths: Vec<String> = stmt
        .query_map(rusqlite::params![group_id, &version.0[..]], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    if paths.is_empty() {
        return Ok(());
    }
    let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
    crate::native_contest_candidates::note(conn, group_id, &refs)?;
    crate::projection_obligations::bump_projection_obligations_for_touched_paths(
        conn,
        group_id,
        &refs,
        crate::dag_store::now_unix_nanos(),
    )
}

/// [`arm_projection_for_arrived_version`] for several versions that just arrived together: the
/// paths whose heads name any of them are found in a few statements, and each version bumps
/// the paths naming it exactly as arming it alone does (a path naming two of the versions is
/// bumped once per version).
pub fn arm_projection_for_arrived_versions(
    conn: &Connection,
    group_id: &str,
    versions: &[VersionHash],
) -> Result<(), SyncSqliteError> {
    if versions.is_empty() {
        return Ok(());
    }
    let present: i64 = conn
        .prepare_cached(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' \
             AND name IN ('native_heads', 'projection_obligations')",
        )?
        .query_row([], |row| row.get(0))?;
    if present < 2 {
        return Ok(());
    }
    let mut paths_of: std::collections::HashMap<[u8; 32], Vec<String>> =
        std::collections::HashMap::new();
    for chunk in versions.chunks(crate::store::PATHS_PER_QUERY) {
        let marks = vec!["?"; chunk.len()].join(",");
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT DISTINCT version, path FROM native_heads INDEXED BY idx_native_heads_version \
             WHERE group_id = ?1 AND version IN ({marks})"
        ))?;
        let params = std::iter::once(rusqlite::types::Value::from(group_id.to_owned()))
            .chain(chunk.iter().map(|v| rusqlite::types::Value::from(v.0.to_vec())));
        let mut rows = stmt.query(rusqlite::params_from_iter(params))?;
        while let Some(row) = rows.next()? {
            let version: Vec<u8> = row.get(0)?;
            let path: String = row.get(1)?;
            let key: [u8; 32] = version.as_slice().try_into().map_err(|_| {
                SyncSqliteError::CorruptState("a native head names a malformed version".into())
            })?;
            paths_of.entry(key).or_default().push(path);
        }
    }
    let now = crate::dag_store::now_unix_nanos();
    for version in versions {
        let Some(paths) = paths_of.get_mut(&version.0) else { continue };
        paths.sort();
        let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
        crate::native_contest_candidates::note(conn, group_id, &refs)?;
        crate::projection_obligations::bump_projection_obligations_for_touched_paths(
            conn, group_id, &refs, now,
        )?;
    }
    Ok(())
}

/// Arms every path whose live heads differ between `before` and `after`,
/// for a state installed wholesale (a join with a remote state) rather
/// than as one delta.
pub fn arm_projection_for_state_change(
    conn: &Connection,
    group_id: &str,
    before: &yadorilink_replica_domain::native_state::NativeState,
    after: &yadorilink_replica_domain::native_state::NativeState,
) -> Result<(), SyncSqliteError> {
    // The install may also have closed authors: every contest is worth a look.
    crate::native_contest_candidates::reset_attempts(conn, group_id)?;
    let paths: BTreeSet<&SyncPath> = before.heads.keys().chain(after.heads.keys()).collect();
    let changed: Vec<&str> = paths
        .into_iter()
        .filter(|path| before.heads.get(*path) != after.heads.get(*path))
        .map(SyncPath::as_str)
        .collect();
    if changed.is_empty() {
        return Ok(());
    }
    crate::native_contest_candidates::note(conn, group_id, &changed)?;
    crate::projection_obligations::bump_projection_obligations_for_touched_paths(
        conn,
        group_id,
        &changed,
        crate::dag_store::now_unix_nanos(),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests;

/// The source paths whose planned entry has no live row: see
/// `FileIndexRepository::native_plan_gap_paths`.
pub fn native_plan_gap_paths(
    conn: &Connection,
    group_id: &str,
) -> Result<BTreeSet<String>, SyncSqliteError> {
    let mut parents = BTreeSet::new();
    {
        let mut stmt =
            conn.prepare("SELECT DISTINCT path FROM native_heads WHERE group_id = ?1")?;
        let rows = stmt.query_map([group_id], |row| row.get::<_, String>(0))?;
        for path in rows {
            let path = path?;
            parents.insert(
                path.rsplit_once('/').map_or(String::new(), |(parent, _)| parent.to_owned()),
            );
        }
    }
    let mut gaps = BTreeSet::new();
    for parent in parents {
        let plan = native_plan_level(conn, group_id, &parent)?;
        for (physical, node) in &plan.nodes {
            let (NativePlannedNode::Entry { head, .. }
            | NativePlannedNode::ExplicitDirectory { head }) = node
            else {
                continue;
            };
            let row = crate::store::read_canonical_current_row(conn, group_id, physical.as_str())?;
            if row.is_none_or(|row| row.snapshot.deleted) {
                gaps.insert(head.source_path.as_str().to_owned());
            }
        }
    }
    Ok(gaps)
}
