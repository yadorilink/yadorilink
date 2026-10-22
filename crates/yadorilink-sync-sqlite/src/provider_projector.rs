//! The projector of a provider root: the ONLY consumer of its group's projection obligations,
//! for the initial build of the namespace and for every later peer edit.
//!
//! A provider root has no directory, so nothing else can project it: the engine lanes refuse it
//! (`ensure_unambiguous_group`), the link runtime never starts for it, and the engine's claim
//! skips its group (`claim_runnable_obligations`). One batch is ONE transaction of up to
//! [`BATCH`] obligations: it writes the current `files` row of each obligation's desired node
//! (the plan, with its stable names and the identity of the head the row shows) and completes
//! the obligation. The commit-time reconcile of that same transaction maintains the structural
//! directories, item liveness and the change events, and the content fence is derived
//! (a changed published item has published != current), so rows, events and fence commit
//! together. A crash loses at most the open batch; the unfinished obligations are the cursor.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use rusqlite::OptionalExtension;
use yadorilink_replica_domain::file::{FileRecord, RecordKind};
use yadorilink_replica_domain::ids::{FolderGroupId, SyncPath};
use yadorilink_replica_domain::native_plan::{NativePlannedNode, NativeRowIdentity};

use crate::error::SyncSqliteError;
use crate::provider_write::{block_infos, meta_columns};

impl crate::provider::ProviderRepository {
    /// One projector batch of the group in ONE immediate transaction (see the module doc).
    pub fn project_batch(&self, group_id: &str, limit: usize) -> Result<usize, SyncSqliteError> {
        self.database_for_write()
            .write_immediate::<_, SyncSqliteError>(|tx| project_batch_in_tx(tx, group_id, limit))
    }

    /// How many obligations of the group are open.
    pub fn open_obligations(&self, group_id: &str) -> Result<u64, SyncSqliteError> {
        self.database_for_write()
            .read::<_, SyncSqliteError>(|conn| pending_obligations(conn, group_id))
    }

    /// The initial-build verification; `None` means the namespace is queryable.
    pub fn verify_namespace(&self, group_id: &str) -> Result<Option<NotReady>, SyncSqliteError> {
        self.database_for_write()
            .write_immediate::<_, SyncSqliteError>(|tx| verify_namespace_in_tx(tx, group_id))
    }
}

/// Obligations projected by one transaction (a knob of the caller; the kernel measured 5 000).
pub const BATCH: usize = 5_000;

/// How many obligations of `group_id` are still open.
pub fn pending_obligations(
    conn: &rusqlite::Connection,
    group_id: &str,
) -> Result<u64, SyncSqliteError> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM projection_obligations WHERE group_id = ?1",
        [group_id],
        |r| r.get::<_, i64>(0),
    )? as u64)
}

/// Projects up to `limit` pending obligations of the group in the caller's transaction and
/// returns how many were completed.
pub fn project_batch_in_tx(
    tx: &rusqlite::Transaction<'_>,
    group_id: &str,
    limit: usize,
) -> Result<usize, SyncSqliteError> {
    let pending: Vec<(String, i64)> = {
        let mut stmt = tx.prepare(
            "SELECT path, invalidation_generation FROM projection_obligations \
             WHERE group_id = ?1 ORDER BY path LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(rusqlite::params![group_id, limit as i64], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?;
        rows
    };
    if pending.is_empty() {
        return Ok(0);
    }
    let mut by_parent: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for (path, _) in &pending {
        let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
        by_parent.entry(parent).or_default().insert(path.clone());
    }
    for (parent, names) in &by_parent {
        let plan = crate::native_desired_state::native_plan_nodes(tx, group_id, parent, names)?;
        // The level plan is indexed ONCE by the source path each node stands for, so applying a
        // batch visits every node once (a flat level of 100k names would otherwise cost one
        // pass over the whole plan per name).
        let mut by_source: HashMap<&str, Vec<(&SyncPath, &NativePlannedNode)>> = HashMap::new();
        let mut structural: HashSet<&str> = HashSet::new();
        for (physical, node) in &plan.nodes {
            match node {
                NativePlannedNode::Entry { head, .. }
                | NativePlannedNode::ExplicitDirectory { head } => {
                    by_source.entry(head.source_path.as_str()).or_default().push((physical, node));
                }
                NativePlannedNode::StructuralDirectory => {
                    structural.insert(physical.as_str());
                }
            }
        }
        for name in names {
            let nodes = by_source.get(name.as_str()).map_or(&[][..], Vec::as_slice);
            project_path(tx, group_id, name, nodes, structural.contains(name.as_str()))?;
        }
    }
    for (path, generation) in &pending {
        // Completed only if nothing re-armed it meanwhile (the generation is the fence).
        tx.execute(
            "DELETE FROM projection_obligations \
             WHERE group_id = ?1 AND path = ?2 AND invalidation_generation = ?3",
            rusqlite::params![group_id, path, generation],
        )?;
    }
    Ok(pending.len())
}

/// Writes the row the plan gives for `source`, and tombstones the row at `source` when the plan
/// holds nothing there any more.
///
/// A tombstone here is PROJECTION, never a semantic delete: it writes only the group's own rows
/// (the same way any projected row is written) and authors no change and no tombstone head for
/// peers.
fn project_path(
    tx: &rusqlite::Transaction<'_>,
    group_id: &str,
    source: &str,
    nodes: &[(&SyncPath, &NativePlannedNode)],
    structural: bool,
) -> Result<(), SyncSqliteError> {
    let mut holds_source_path = false;
    for (physical, node) in nodes {
        let (NativePlannedNode::Entry { head, .. } | NativePlannedNode::ExplicitDirectory { head }) =
            node
        else {
            continue;
        };
        if physical.as_str() == source {
            holds_source_path = true;
        }
        write_row(tx, group_id, physical.as_str(), head)?;
    }
    if !holds_source_path {
        let was_row = tombstone_if_live(tx, group_id, source)?;
        // An explicit directory whose head left while descendants remain becomes a structural
        // one: the old explicit row is retired, the folder item stays, and its generation
        // advances with an event, so a token of the explicit directory is stale.
        if was_row && structural {
            yadorilink_sqlite_runtime::note_item_replaced(tx, group_id, source)?;
        }
    }
    Ok(())
}

fn write_row(
    tx: &rusqlite::Transaction<'_>,
    group_id: &str,
    physical: &str,
    head: &yadorilink_replica_domain::native_plan::NativeLocatedHead,
) -> Result<(), SyncSqliteError> {
    let identity = NativeRowIdentity::of(head);
    // Already showing exactly this head: nothing to write.
    let shown: Option<Option<Vec<u8>>> = tx
        .query_row(
            "SELECT native_authoring_identity FROM files \
             WHERE group_id = ?1 AND path = ?2 AND state = 'current' AND deleted = 0",
            rusqlite::params![group_id, physical],
            |r| r.get(0),
        )
        .optional()?;
    if shown.flatten().as_deref() == Some(identity.to_bytes().as_slice()) {
        return Ok(());
    }
    // The path shows another head (or is revived within this transaction) while the OS knows an
    // item there: that item is replaced, and its earlier tokens must not pass any gate.
    yadorilink_sqlite_runtime::note_item_replaced(tx, group_id, physical)?;
    let hash = head.version();
    let version = crate::dag_store::get_file_version(tx, group_id, &hash)?.ok_or_else(|| {
        SyncSqliteError::CorruptState(format!(
            "the version of {physical} that a head names is not in the version store"
        ))
    })?;
    let record = FileRecord {
        path: physical.to_owned(),
        size: version.size,
        mtime_unix_nanos: version.meta.mtime_unix_nanos,
        blocks: block_infos(&version),
        deleted: false,
    };
    // The row's version is derived from its record AND its meta columns, so the check that the
    // row shows the head it cites runs after both are written (as the authoring path does).
    crate::file_index::upsert_file_with_authoring_in_tx(
        tx,
        group_id,
        &record,
        "",
        Some(&identity),
    )?;
    crate::file_index::apply_local_meta_columns_in_tx(
        tx,
        group_id,
        physical,
        &meta_columns(&version),
    )?;
    crate::file_index::require_row_shows_native_head(tx, group_id, physical, Some(&identity))?;
    debug_assert!(matches!(
        version.meta.record_kind,
        RecordKind::File | RecordKind::Directory | RecordKind::Symlink
    ));
    Ok(())
}

fn tombstone_if_live(
    tx: &rusqlite::Transaction<'_>,
    group_id: &str,
    path: &str,
) -> Result<bool, SyncSqliteError> {
    let live: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM files WHERE group_id = ?1 AND path = ?2 \
         AND state = 'current' AND deleted = 0)",
        rusqlite::params![group_id, path],
        |r| r.get(0),
    )?;
    if live {
        // A path deleted and shown again inside this transaction is a replacement: the item's
        // generation moves now (silently; `write_row` tells the OS if the path comes back).
        tx.execute(
            "UPDATE provider_items SET generation = generation + 1 \
             WHERE group_id = ?1 AND path = ?2 AND live = 1",
            rusqlite::params![group_id, path],
        )?;
        let tombstone = FileRecord {
            path: path.to_owned(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: Vec::new(),
            deleted: true,
        };
        crate::file_index::upsert_file_with_authoring_in_tx(tx, group_id, &tombstone, "", None)?;
    }
    Ok(live)
}

/// Why a namespace is not ready.
#[derive(Debug, PartialEq, Eq)]
pub enum NotReady {
    /// The namespace was not installed yet: an empty namespace is not "queryable".
    NotInstalled,
    OpenObligations(u64),
    Gaps(usize),
    /// The listing of a folder disagrees with the plan: (parent, listed, planned).
    ChildCount(String, usize, usize),
}

/// The verification of the INITIAL build: no open obligation, no planned entry
/// without a row, and for EVERY parent the children the listing finds (rows plus structural
/// directories of any depth) equal the plan level's node count. Runs in a write transaction
/// because planning records placements.
pub fn verify_namespace_in_tx(
    tx: &rusqlite::Transaction<'_>,
    group_id: &str,
) -> Result<Option<NotReady>, SyncSqliteError> {
    let installed: bool = tx.query_row(
        "SELECT COALESCE((SELECT install_done FROM provider_roots WHERE group_id = ?1), 0)",
        [group_id],
        |r| r.get(0),
    )?;
    if !installed {
        return Ok(Some(NotReady::NotInstalled));
    }
    let open = pending_obligations(tx, group_id)?;
    if open > 0 {
        return Ok(Some(NotReady::OpenObligations(open)));
    }
    let gaps = crate::native_desired_state::native_plan_gap_paths(tx, group_id)?.len();
    if gaps > 0 {
        return Ok(Some(NotReady::Gaps(gaps)));
    }
    // Every parent of the plan: the ancestors of every head path, and the root.
    let mut parents: BTreeSet<String> = BTreeSet::from([String::new()]);
    {
        let mut stmt = tx.prepare("SELECT DISTINCT path FROM native_heads WHERE group_id = ?1")?;
        let rows = stmt.query_map([group_id], |r| r.get::<_, String>(0))?;
        for path in rows {
            let mut at = path?;
            while let Some((parent, _)) = at.rsplit_once('/') {
                if !parents.insert(parent.to_owned()) {
                    break;
                }
                at = parent.to_owned();
            }
        }
    }
    let _ = FolderGroupId(group_id.to_owned());
    for parent in parents {
        let planned =
            crate::native_desired_state::native_plan_level(tx, group_id, &parent)?.nodes.len();
        let listed = count_children(tx, group_id, &parent)?;
        if listed != planned {
            return Ok(Some(NotReady::ChildCount(parent, listed, planned)));
        }
    }
    Ok(None)
}

/// How many children the listing of `parent` finds: the rows with that parent plus the
/// structural directories with that parent that have no row.
pub fn count_children(
    conn: &rusqlite::Connection,
    group_id: &str,
    parent: &str,
) -> Result<usize, SyncSqliteError> {
    let rows: i64 = conn.query_row(
        "SELECT COUNT(*) FROM files WHERE group_id = ?1 AND state = 'current' AND deleted = 0 \
         AND version_seq > 0 AND rtrim(rtrim(path, replace(path, '/', '')), '/') = ?2",
        rusqlite::params![group_id, parent],
        |r| r.get(0),
    )?;
    let structural: i64 = conn.query_row(
        "SELECT COUNT(*) FROM provider_dirs d WHERE d.group_id = ?1 AND d.parent_path = ?2 \
         AND NOT EXISTS (SELECT 1 FROM files f WHERE f.group_id = d.group_id AND f.path = d.path \
                         AND f.state = 'current' AND f.deleted = 0 AND f.version_seq > 0)",
        rusqlite::params![group_id, parent],
        |r| r.get(0),
    )?;
    Ok((rows + structural) as usize)
}
