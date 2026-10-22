//! The evidence and settlement of brand-new paths, from what authoring already holds.
//!
//! After a capture authors a put at a path nothing else named, the commit publishes the proof of
//! what it observed on disk and tries to close the path's obligation against it. For such a path
//! every fact that takes is in hand from the transaction's own writes: the install returned the
//! heads it left at the path, the arming returned the obligation it left, and the version the head
//! names is the one being committed. This module publishes the proofs of a chunk of such paths in
//! batches (one statement per chunk for the fences, for the proofs and for the closes) from those
//! facts, instead of reading each back per path.
//!
//! The facts a head set alone cannot give are absent here by the caller's check (see
//! [`open_namespace_paths`] and [`crate::new_path_rows::brand_new_paths`]): no head at an ancestor
//! or a descendant, and nothing recording a placement, stable name or kept copy for the path. A
//! path for which any of that is not known to hold takes the per-path settlement, which reads it.

use std::collections::{HashMap, HashSet};

use rusqlite::Connection;

use yadorilink_fs_platform::fs_identity::FileIdentity;
use yadorilink_replica_domain::file::{FileVersion, RecordKind};
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_domain::native_plan::NativeRowIdentity;
use yadorilink_replica_domain::native_state::LiveHead;

use crate::error::SyncSqliteError;
use crate::materialized_generation::{MaterializedObjectKind, ObservedPresent};
use crate::native_store::PathHeadsMap;
use crate::projection_obligations::{ArmedObligation, ExactClose};
use crate::store::PATHS_PER_QUERY;

/// The paths of `paths` with no native head at any ancestor and none below them. Read before
/// authoring puts the paths' heads: authoring writes only the heads at the group's own paths, which
/// are unrelated to each other, so what it leaves at an ancestor or below a path is what it found.
pub(crate) fn open_namespace_paths(
    conn: &Connection,
    group_id: &str,
    paths: &[&str],
) -> Result<HashSet<String>, SyncSqliteError> {
    let mut ancestors: HashSet<&str> = HashSet::new();
    for path in paths {
        let mut ancestor = *path;
        while let Some((parent, _)) = ancestor.rsplit_once('/') {
            ancestors.insert(parent);
            ancestor = parent;
        }
    }
    let ancestors: Vec<&str> = ancestors.into_iter().collect();
    let mut with_heads: HashSet<String> = HashSet::new();
    for chunk in ancestors.chunks(PATHS_PER_QUERY) {
        let marks = vec!["?"; chunk.len()].join(",");
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT DISTINCT path FROM native_heads WHERE group_id = ?1 AND path IN ({marks})"
        ))?;
        let params = std::iter::once(group_id).chain(chunk.iter().copied());
        let mut rows = stmt.query(rusqlite::params_from_iter(params))?;
        while let Some(row) = rows.next()? {
            with_heads.insert(row.get(0)?);
        }
    }
    let mut below: HashSet<String> = HashSet::new();
    for chunk in paths.chunks(PATHS_PER_QUERY) {
        let values: Vec<String> = (0..chunk.len()).map(|i| format!("(?{})", 2 + i)).collect();
        let mut stmt = conn.prepare_cached(&format!(
            "WITH v(path) AS (VALUES {}) SELECT v.path FROM v WHERE EXISTS ( \
               SELECT 1 FROM native_heads h WHERE h.group_id = ?1 \
                 AND h.path > v.path || '/' AND h.path < v.path || '0')",
            values.join(", ")
        ))?;
        let params = std::iter::once(group_id).chain(chunk.iter().copied());
        let mut rows = stmt.query(rusqlite::params_from_iter(params))?;
        while let Some(row) = rows.next()? {
            below.insert(row.get(0)?);
        }
    }
    Ok(paths
        .iter()
        .filter(|path| {
            let mut ancestor = **path;
            while let Some((parent, _)) = ancestor.rsplit_once('/') {
                if with_heads.contains(parent) {
                    return false;
                }
                ancestor = parent;
            }
            !below.contains(**path)
        })
        .map(|path| (*path).to_owned())
        .collect())
}

/// What the commit holds about one new path it has just authored, written, and observed on disk.
pub(crate) struct NewPathProof<'a> {
    pub path: &'a str,
    pub version: &'a FileVersion,
    pub filesystem_identity: &'a FileIdentity,
    heads: Vec<LiveHead>,
    obligation: ArmedObligation,
}

impl<'a> NewPathProof<'a> {
    /// The proof's facts, when what the install and the arming left at `path` is exactly the one
    /// head the put wrote, naming the content being committed, and an obligation was armed for
    /// the path. `None` sends the path to the per-path settlement.
    pub(crate) fn new(
        path: &'a str,
        version: &'a FileVersion,
        filesystem_identity: &'a FileIdentity,
        identity: &NativeRowIdentity,
        installed: Option<&PathHeadsMap>,
        obligation: Option<&ArmedObligation>,
    ) -> Option<Self> {
        let installed = installed?;
        let (dot, payload) = match (installed.len(), installed.iter().next()) {
            (1, Some(head)) => head,
            _ => return None,
        };
        if *dot != identity.dot
            || payload.provenance != identity.provenance
            || payload.version != version.version_hash
            || version.meta.record_kind != RecordKind::File
        {
            return None;
        }
        Some(Self {
            path,
            version,
            filesystem_identity,
            heads: vec![LiveHead { dot: dot.clone(), payload: payload.clone() }],
            obligation: obligation?.clone(),
        })
    }

    fn basis(&self) -> crate::materialization_basis::ReflectedHeads {
        let provenances: Vec<[u8; 32]> =
            self.heads.iter().map(|head| head.payload.provenance.0).collect();
        crate::materialization_basis::of_unplaced_heads(&provenances)
    }
}

/// Publishes the proof of every path of `proofs` and closes the obligations those proofs settle:
/// the fences are bumped first, each proof is written under the epoch its own bump returned, and
/// an obligation is closed only through the exact-proof check on its generation and incarnation,
/// as the per-path close does.
pub(crate) fn publish_and_settle(
    tx: &Connection,
    group_id: &str,
    proofs: &[NewPathProof<'_>],
    now_unix_nanos: i64,
) -> Result<(), SyncSqliteError> {
    if proofs.is_empty() {
        return Ok(());
    }
    #[cfg(test)]
    crate::new_path_rows::tests_support::PROOFS_BATCHED.with(|n| n.set(n.get() + proofs.len()));
    let observed: Vec<ObservedPresent<'_>> = proofs
        .iter()
        .map(|proof| ObservedPresent {
            path: proof.path,
            object_kind: MaterializedObjectKind::RegularFile,
            version: &proof.version.version_hash,
            filesystem_identity: proof.filesystem_identity,
            basis: proof.basis(),
        })
        .collect();
    crate::materialized_generation::adopt_observed_present_generations_batch(
        tx,
        group_id,
        &observed,
        now_unix_nanos,
    )?;
    #[cfg(test)]
    if !crate::new_path_rows::tests_support::CROSS_CHECK_OFF.with(|flag| flag.get()) {
        cross_check_against_the_database(tx, group_id, proofs)?;
    }

    let mut closes = Vec::with_capacity(proofs.len());
    for proof in proofs {
        let kinds: HashMap<VersionHash, RecordKind> =
            HashMap::from([(proof.version.version_hash, proof.version.meta.record_kind)]);
        let desired = match crate::native_desired_state::desired_path_state_of_unplaced_heads(
            proof.path,
            proof.heads.clone(),
            &kinds,
        ) {
            Ok(desired) => desired,
            // Contested: nothing is owed yet.
            Err(SyncSqliteError::NotFound(_)) => continue,
            Err(error) => return Err(error),
        };
        // The directory the path has to be is the engine's to place.
        if let crate::desired_state::DesiredPathState::StructuralDirectory = desired {
            continue;
        }
        closes.push(ExactClose {
            path: proof.path,
            claimed_invalidation_generation: proof.obligation.invalidation_generation,
            claimed_obligation_incarnation: proof.obligation.obligation_incarnation,
            desired_resolved_path_state_hash: desired
                .resolved_path_state_hash(group_id, proof.path),
        });
    }
    crate::projection_obligations::complete_obligations_if_exact_proofs_current(
        tx, group_id, &closes,
    )?;
    Ok(())
}

/// Checks, against the database, every fact [`publish_and_settle`] took from memory: the heads at
/// the path (and none above or below it), the basis the proof recorded, and that nothing records a
/// placement, stable name or kept copy for it. Read-only, so it cannot hide a write the batched
/// settlement leaves out.
#[cfg(test)]
fn cross_check_against_the_database(
    tx: &Connection,
    group_id: &str,
    proofs: &[NewPathProof<'_>],
) -> Result<(), SyncSqliteError> {
    let group = yadorilink_replica_domain::ids::FolderGroupId(group_id.to_owned());
    for proof in proofs {
        let sync = yadorilink_replica_domain::ids::SyncPath(proof.path.to_owned());
        let stored = crate::native_store::native_heads_at(tx, &group, &sync)?;
        assert_eq!(stored, proof.heads, "the install left other heads at {}", proof.path);
        assert!(
            !crate::native_store::native_has_descendant_head(tx, &group, &sync)?,
            "{} has a descendant head",
            proof.path
        );
        let mut ancestor = proof.path;
        while let Some((parent, _)) = ancestor.rsplit_once('/') {
            let sync = yadorilink_replica_domain::ids::SyncPath(parent.to_owned());
            assert!(
                crate::native_store::native_heads_at(tx, &group, &sync)?.is_empty(),
                "{parent} has a head above {}",
                proof.path
            );
            ancestor = parent;
        }
        let recorded = crate::materialization_basis::record(tx, group_id, proof.path)?;
        assert_eq!(recorded, proof.basis(), "the basis of {} is not the one read", proof.path);
        let kind = crate::dag_store::get_file_version(tx, group_id, &proof.version.version_hash)?
            .map(|version| version.meta.record_kind);
        assert_eq!(kind, Some(proof.version.meta.record_kind));
    }
    Ok(())
}
