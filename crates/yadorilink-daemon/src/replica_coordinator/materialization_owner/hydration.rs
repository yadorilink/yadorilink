//! Owner operations for hydration: the one version-bound guard every hydration attempt holds
//! (`HydrationAttempt`) and the judgement of what an attempt found at its path when it started
//! (`admit_hydration_start`).
//!
//! The guard is armed by the entry CAS to `Hydrating`, bound to the attempt's version, and
//! reverts the row on drop unless the attempt published. The lane keeps every fetch, check and
//! physical write between these steps. Which lane runs (the on-access hydration, the background
//! convergence rehydration) changes how it fetches and writes, not what the guard guarantees.

use yadorilink_filesystem_sync::materialization_execution::MaterializationExecutionError;
use yadorilink_fs_platform::fs_identity::FileIdentity;
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_root_authority::root_commit::RootCommitPermit;

use yadorilink_sync_sqlite::exact_materialized_commit::{
    ExactMaterializedState, ExpectedAuthoring, InternalMaterializedCommit,
};

use super::super::ReplicaCoordinator;
use crate::sync_error::SyncError;

/// One hydration attempt's `Hydrating` window: reverts the row to the state the attempt found on
/// drop unless `commit_exact_file` published (or `complete` ran first).
///
/// Every fallible step between marking a row `Hydrating` and committing it used to leave the row
/// stuck at `Hydrating` on any error with no independent recovery, so every exit path is covered
/// by this one mechanism: the drop. The revert target is always the entry state. The physical
/// write's fence bump retires the proof a `Present` entry stood on, but `Present` without a
/// usable proof is a legitimate state (an object no proof vouches for), which hydration's
/// admission handles by evidence.
///
/// The revert is bound to BOTH the expected state (`Hydrating`) AND this attempt's own version,
/// not a blind write: a state-only CAS cannot tell "this row is still the version this attempt
/// started with" apart from "a newer version became current mid-attempt and also landed in
/// `Hydrating`" (a peer's concurrent update superseding the row). It only ever reverts the exact
/// version this attempt was hydrating.
pub(crate) struct HydrationAttempt<'a> {
    coordinator: &'a ReplicaCoordinator,
    group_id: &'a str,
    path: &'a str,
    /// This attempt's own version, captured before it set `Hydrating`.
    version: VersionHash,
    /// What an abandoned attempt puts the row back to: the state it found, so an attempt that
    /// changes nothing leaves nothing changed.
    revert_to: MaterializationState,
    committed: bool,
}

impl ReplicaCoordinator {
    /// Entry step of every hydration: CAS the row from `entry_state` to `Hydrating`, bound to
    /// this attempt's version (tx). `None` when the row moved (the lane fails the attempt);
    /// otherwise the guard that reverts the row to `entry_state` (or `Remote` when it had none)
    /// on drop.
    pub(crate) fn begin_hydration<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        entry_state: Option<MaterializationState>,
        version: VersionHash,
    ) -> Result<Option<HydrationAttempt<'a>>, SyncError> {
        if !self
            .materialization_state_repository()
            .transition_materialization_state_if_same_version(
                group_id,
                path,
                entry_state,
                Some(&version),
                MaterializationState::Hydrating,
            )?
        {
            return Ok(None);
        }
        Ok(Some(HydrationAttempt {
            coordinator: self,
            group_id,
            path,
            version,
            revert_to: entry_state.unwrap_or(MaterializationState::Remote),
            committed: false,
        }))
    }
}

impl<'a> HydrationAttempt<'a> {
    /// Bumps this path's mutation fence for the physical write (tx): from that point the
    /// standing proof is stale. The revert target stays the entry state: `Present` makes no
    /// claim that the object equals any version, so an object left under a `Present` row after a
    /// failed attempt needs no demotion, and a path that was empty stays `Remote`. Returns the
    /// value the commit must still find.
    pub(crate) fn begin_physical_write(&mut self) -> Result<i64, PeerSessionError> {
        self.coordinator.dag_bump_mutation_fence(self.group_id, self.path, "hydration_write")
    }

    /// Settle: publish this attempt's version with `identity` under `mutation_generation`, stamp
    /// `Present` and clear any intent, in one commit (tx) that still expects `Hydrating` with
    /// this attempt's version. The group heads are derived inside the commit's own transaction.
    /// Disarms the revert only when it published; any other outcome leaves the guard armed.
    pub(crate) fn commit_exact_file(
        &mut self,
        identity: FileIdentity,
        mutation_generation: i64,
        permit: &RootCommitPermit<'_>,
    ) -> Result<InternalMaterializedCommit, SyncError> {
        let outcome = self
            .coordinator
            .materialization_state_repository()
            .commit_internal_materialized_state_if_fence_current(
                self.group_id,
                self.path,
                &ExactMaterializedState::Object {
                    kind: yadorilink_replica_domain::file::RecordKind::File,
                    version: self.version,
                    identity: Box::new(Some(identity)),
                },
                mutation_generation,
                Some(ExpectedAuthoring {
                    state: MaterializationState::Hydrating,
                    expected_version: Some(&self.version),
                }),
                permit,
            )?;
        if matches!(outcome, InternalMaterializedCommit::Published(_)) {
            self.committed = true;
        }
        Ok(outcome)
    }

    /// Disarms the revert: the attempt published, or found the path already complete.
    pub(crate) fn complete(&mut self) {
        self.committed = true;
    }

    #[cfg(test)]
    pub(crate) fn armed_for_tests(
        coordinator: &'a ReplicaCoordinator,
        group_id: &'a str,
        path: &'a str,
        version: VersionHash,
        revert_to: MaterializationState,
    ) -> Self {
        Self { coordinator, group_id, path, version, revert_to, committed: false }
    }
}

impl Drop for HydrationAttempt<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        // Best-effort on error: this already runs during unwind from a `?` elsewhere in the
        // lane, so a second failure here has nowhere better to go than a log line.
        if let Err(error) = self
            .coordinator
            .materialization_state_repository()
            .transition_materialization_state_if_same_version(
                self.group_id,
                self.path,
                Some(MaterializationState::Hydrating),
                Some(&self.version),
                self.revert_to,
            )
        {
            tracing::warn!(
                group_id = self.group_id,
                path = self.path,
                %error,
                "failed to revert an aborted hydration's materialization state; row may be \
                 stuck at Hydrating"
            );
        }
    }
}

impl ReplicaCoordinator {
    /// The proof heal for a `Present` row whose bytes,
    /// identity, mode and xattrs the lane verified against `version`:
    /// re-publish the proof for `version` with `identity` under the live
    /// fence (tx), guarded on the row still being `Present` with
    /// `version`. `permit` is verified inside that tx,
    /// before the publish, so a lost root fails the heal with nothing
    /// published; a superseded row writes nothing and answers `false`.
    ///
    /// The errors keep the port's type, exactly as the lane saw them
    /// through `MaterializationExecutionPort` before.
    pub(crate) fn reprove_hydrated_file(
        &self,
        group_id: &str,
        path: &str,
        version: &VersionHash,
        identity: FileIdentity,
        permit: &RootCommitPermit<'_>,
    ) -> Result<bool, MaterializationExecutionError> {
        let exact = ExactMaterializedState::Object {
            kind: yadorilink_replica_domain::file::RecordKind::File,
            version: *version,
            identity: Box::new(Some(identity)),
        };
        let guard = Some(ExpectedAuthoring {
            state: MaterializationState::Present,
            expected_version: Some(version),
        });
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        let published = self
            .database
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                yadorilink_sync_sqlite::exact_materialized_commit::reprove_verified_hydrated_state(
                    tx, group_id, path, &exact, guard, now, permit,
                )
            })
            .map_err(SyncError::from)?;
        Ok(published.is_some())
    }
}

impl ReplicaCoordinator {
    /// Settle half of a live version restore, after the lane's physical
    /// write: mark the journal entry disk-committed (tx), observe what is
    /// now at `out_path` (`None` for the one arm that writes nothing, or
    /// when it cannot be observed), then commit the restore under the
    /// fence value the write went out under (tx). Returns the commit's
    /// outcome for the lane to map.
    ///
    /// `permit` comes from the one `LinkOperation` the lane holds for the
    /// whole restore, and both transactions verify it before they write
    /// so a root lost after the physical write marks nothing and
    /// publishes nothing, leaving the journal entry for recovery.
    pub(crate) fn settle_restore_write(
        &self,
        operation_id: &str,
        out_path: &std::path::Path,
        wrote_under_mutation_generation: i64,
        // False when the write could not confirm every exact-required field
        // it set (its replicated xattrs): the restore is still committed,
        // but with no observed identity, so no exact proof is published
        // and the row does not claim to hold the content.
        exact_claimable: bool,
        permit: &yadorilink_root_authority::root_commit::RootCommitPermit<'_>,
    ) -> Result<yadorilink_replica_domain::session_state::RestoreCommitOutcome, SyncError> {
        self.restore_operation_repository().mark_restore_disk_committed(operation_id, permit)?;
        // Observed after the disk write, so the proof describes what a
        // reader would now find.
        let restored_identity =
            if exact_claimable { FileIdentity::observe_path(out_path).ok() } else { None };
        Ok(self.restore_operation_repository().commit_restore_operation(
            operation_id,
            restored_identity.as_ref(),
            Some(wrote_under_mutation_generation),
            permit,
        )?)
    }
}

#[cfg(test)]
mod convergence_guard_tests;

impl ReplicaCoordinator {
    /// Whether a hydration attempt may replace what it found at `out_path`
    /// when it started, `lstat` (`None`: nothing there). When it may not,
    /// the path is journalled dirty for local capture before this returns
    /// `false`, and the attempt must fail without touching it.
    ///
    /// Shared by both hydration lanes. The baseline each attempt re-checks
    /// before its write only proves the file did not change DURING the
    /// attempt. It says nothing about what the file was when the attempt
    /// started: an edit written into the path before that, and not yet
    /// journalled by the watcher, would be sampled as the baseline itself,
    /// found unchanged, and replaced. So the starting point is judged
    /// against what this device knows it put there.
    ///
    /// Nothing on disk passes (a `Remote` row has no object), except where a
    /// native provider recorded an identity for an object that is no longer
    /// there: that was removed locally, and hydrating would put the file
    /// back and undo the delete before local capture has turned it into a
    /// tombstone. A regular file passes when it is a native provider's
    /// untouched placeholder (Windows only), when it is this device's own
    /// write, untouched since the proof that vouches for it was published
    /// (an older version's bytes under a newer row), or when it is already
    /// exactly the version the row names: bytes, mode and replicated xattrs,
    /// under a disk identity unchanged from `lstat` across the comparison.
    /// The last is the recovery for an attempt interrupted between its
    /// rename and its commit; refusing it would refuse on every attempt. The
    /// metadata has to match too, or a mode or xattr change made locally to
    /// that leftover would be reverted by the attempt's own metadata apply.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit_hydration_start(
        &self,
        group_id: &str,
        path: &str,
        out_path: &std::path::Path,
        lstat: Option<&std::fs::Metadata>,
        record: &yadorilink_replica_domain::file::FileRecord,
        unix_mode: Option<u32>,
        xattrs: &[(String, Vec<u8>)],
        permit: &RootCommitPermit<'_>,
    ) -> Result<bool, SyncError> {
        let generation =
            self.materialization_state_repository().get_placeholder_generation(group_id, path)?;
        let may_replace = match lstat {
            None => generation.is_none(),
            Some(lstat) if !lstat.is_file() => false,
            Some(lstat) => {
                yadorilink_local_capture::local_change::cfapi_placeholder_untouched(
                    self,
                    out_path,
                    lstat,
                    Some(record),
                    generation.as_ref(),
                ) || self
                    .disk_is_untouched_proven_write_at(group_id, path, out_path)
                    .unwrap_or(false)
                    || (yadorilink_local_storage::disk_bytes_match_indexed_blocks(
                        out_path,
                        &record.blocks,
                    )? && yadorilink_local_storage::unix_mode_already_matches_disk(
                        out_path, unix_mode,
                    )? && matches!(
                        yadorilink_local_storage::verify_replicated_xattrs_exact(out_path, xattrs),
                        Ok(true)
                    ) && crate::hydration::disk_identity(out_path)?
                        == Some(crate::hydration::disk_identity_of(lstat)))
            }
        };
        if !may_replace {
            self.journal_uncaptured_local_edit(group_id, path, lstat.is_some(), permit)?;
        }
        Ok(may_replace)
    }

    /// Records `path` in the dirty journal as holding a local change local
    /// capture has not taken yet, unless it is already there. `present`
    /// says whether something is on disk at the path now.
    pub(crate) fn journal_uncaptured_local_edit(
        &self,
        group_id: &str,
        path: &str,
        present: bool,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncError> {
        let dirty = self.dirty_path_repository();
        if !dirty.is_path_dirty(group_id, path)? {
            let observed_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as i64)
                .unwrap_or(0);
            let kind = if present { "created_or_modified" } else { "removed" };
            dirty.record_dirty_path(group_id, path, kind, observed_at, permit)?;
        }
        Ok(())
    }
}
