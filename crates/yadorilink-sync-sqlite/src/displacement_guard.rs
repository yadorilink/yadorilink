//! The displacement guard: replacing or removing the on-disk content of a path
//! must not lose a version the replicated state still holds elsewhere.
//!
//! When the loser of a contest is renamed to its copy path, the original path
//! is asked to show the winner (or a directory, or nothing) while the copy path
//! is asked to show the loser. Applying the original first, on a device whose
//! disk holds the loser there, would destroy the only copy of it. The guard
//! therefore asks, before a path's materialized content is replaced or removed,
//! where else that version is live and whether each of those paths already holds
//! it on disk (a `Present` row of exactly that version, which the caller then checks
//! against the disk).

use rusqlite::Connection;

use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::ids::{FolderGroupId, VersionHash};
use yadorilink_replica_domain::session_state::MaterializationState;

use crate::error::SyncSqliteError;

/// What the guard finds for one path about to give up its content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DisplacementGuard {
    /// Nothing is at stake: the row shows no file, shows the planned version,
    /// or shows a version that is live nowhere else in the group.
    Clear,
    /// The displaced version is live elsewhere and some of those paths do not
    /// hold it yet. The path waits for them.
    Wait,
    /// The displaced version is live elsewhere and every one of those paths
    /// has it recorded as present. The path may give up its content once the
    /// disk is seen to hold it at each of them, on a platform that can make
    /// that durable.
    Guarded(Vec<String>),
}

/// The guard for `path`, which is about to show `planned` (`None` for a
/// directory or nothing). `folds_onto_path` says of another path whether this volume folds it
/// onto `path` (a pure name test, taking no connection): such a path can never be on disk while `path` is, so waiting for it to hold
/// the version would wait for the very removal that is being decided (a case-only rename),
/// and it is not a place the content lives on.
pub fn displacement_guard(
    conn: &Connection,
    group_id: &str,
    path: &str,
    planned: Option<&VersionHash>,
    folds_onto_path: &dyn Fn(&str) -> bool,
) -> Result<DisplacementGuard, SyncSqliteError> {
    // What the disk at `path` may hold: the version the row shows, and the
    // version of the last materialization proof even when its fence has moved
    // (a write that moved the row and then failed leaves the older bytes on
    // disk, and only the proof still names them). Neither is trusted to be
    // alone: each version that lives on at another path must be safe there.
    let mut displaced: Vec<VersionHash> = Vec::new();
    if let Some(row) = crate::store::read_canonical_current_row(conn, group_id, path)? {
        if !row.snapshot.deleted
            && matches!(row.snapshot.record_kind, RecordKind::File | RecordKind::Symlink)
            && row.materialization_state == Some(MaterializationState::Present)
        {
            displaced.push(row.version_hash());
        }
    }
    if let Some(proof) = crate::materialized_generation::lookup_materialized_generation_diagnostic(
        conn, group_id, path,
    )? {
        if let Some(version) = proof.version {
            if matches!(
                proof.object_kind,
                crate::materialized_generation::MaterializedObjectKind::RegularFile
                    | crate::materialized_generation::MaterializedObjectKind::Symlink
            ) && !displaced.contains(&version)
            {
                displaced.push(version);
            }
        }
    }
    displaced.retain(|version| planned != Some(version));
    let group = FolderGroupId(group_id.to_owned());
    let mut holders: Vec<String> = Vec::new();
    for version in &displaced {
        let elsewhere: Vec<String> =
            crate::native_store::native_paths_with_version(conn, &group, version)?
                .into_iter()
                .filter(|other| other != path)
                .collect::<Vec<_>>()
                .into_iter()
                .filter(|other| {
                    !(folds_onto_path(other) && plan_shows_version(conn, group_id, other, version))
                })
                .collect();
        if elsewhere.is_empty() {
            continue;
        }
        let refs: Vec<&str> = elsewhere.iter().map(String::as_str).collect();
        let rows = crate::store::read_canonical_current_rows(conn, group_id, &refs)?;
        let holds = |other: &String| {
            rows.get(other).is_some_and(|other_row| {
                !other_row.snapshot.deleted
                    && other_row.materialization_state == Some(MaterializationState::Present)
                    && other_row.version_hash() == *version
            })
        };
        if !elsewhere.iter().all(holds) {
            return Ok(DisplacementGuard::Wait);
        }
        holders.extend(elsewhere);
    }
    holders.sort();
    holders.dedup();
    Ok(if holders.is_empty() {
        DisplacementGuard::Clear
    } else {
        DisplacementGuard::Guarded(holders)
    })
}

/// Whether native's plan puts exactly `version` as a plain entry at `path`, read on the
/// guard's own connection.
fn plan_shows_version(
    conn: &Connection,
    group_id: &str,
    path: &str,
    version: &VersionHash,
) -> bool {
    use yadorilink_replica_domain::native_plan::NativePlannedNode;
    matches!(
        crate::native_desired_state::native_plan_node(conn, group_id, path),
        Ok(Some(NativePlannedNode::Entry { head, .. })) if head.version() == *version
    )
}

/// Whether `path` is the copy of content that a materialization proof of the
/// group names at another path: the fork of a hydrated loser, whose bytes are
/// already on this device at the path it left. Writing them at the copy path is
/// a local copy that needs no fetch, whatever the folder's on-demand policy; and
/// the original path waits for it. Only copy-named paths are asked, so the proof
/// table is scanned for them alone.
pub fn version_present_elsewhere(
    conn: &Connection,
    group_id: &str,
    path: &str,
    version: &VersionHash,
) -> Result<bool, SyncSqliteError> {
    if !yadorilink_replica_domain::conflict::is_conflict_copy_path(path) {
        return Ok(false);
    }
    Ok(conn
        .prepare_cached(
            "SELECT 1 FROM path_materialized_generations \
             WHERE group_id = ?1 AND version_hash = ?2 AND path <> ?3 \
               AND object_kind IN ('regular_file', 'symlink') LIMIT 1",
        )?
        .exists(rusqlite::params![group_id, &version.0[..], path])?)
}

/// Whether a destructive step (replacing or removing a path whose content
/// lives on elsewhere) may be made durable under `root`: the volume must offer
/// durable namespace changes (`DurableNamespace::open` trusts it). Where it does
/// not (Windows until its gate is open, a volume the probe rejects), the
/// conflict is resolved semantically and the local file update waits.
pub fn destructive_step_durable(root: &std::path::Path) -> bool {
    #[cfg(any(test, feature = "test-support"))]
    if FORCED_ROOTS.lock().unwrap_or_else(|p| p.into_inner()).contains(root) {
        return false;
    }
    crate::native_rebootstrap_recovery::directory_durability_available(root)
}

#[cfg(any(test, feature = "test-support"))]
static FORCED_ROOTS: std::sync::Mutex<std::collections::BTreeSet<std::path::PathBuf>> =
    std::sync::Mutex::new(std::collections::BTreeSet::new());

/// Test seam: makes `root` stand in for a platform that cannot make a
/// directory entry durable. Per root, so tests running side by side do not see
/// each other's setting.
#[cfg(any(test, feature = "test-support"))]
pub fn set_force_no_directory_durability(root: &std::path::Path, forced: bool) {
    let mut roots = FORCED_ROOTS.lock().unwrap_or_else(|p| p.into_inner());
    if forced {
        roots.insert(root.to_path_buf());
    } else {
        roots.remove(root);
    }
}
