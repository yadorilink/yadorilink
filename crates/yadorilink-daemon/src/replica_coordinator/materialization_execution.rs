//! `impl yadorilink_filesystem_sync::materialization_execution::
//! MaterializationExecutionPort for ReplicaCoordinator`, built on the
//! generic `MaterializationIntentGuard`.

use std::path::Path;
use std::sync::Arc;

use crate::sync_error::SyncError;
use yadorilink_filesystem_sync::block_liveness::BlockPhysicalDeletionGuard;
use yadorilink_filesystem_sync::materialization_execution::{
    EvictionEligibilitySnapshot as ExecEvictionEligibilitySnapshot,
    EvictionRevalidationSnapshot as ExecEvictionRevalidationSnapshot,
    MaterializationExecutionError, MaterializationExecutionPort, MaterializationIntentKind,
    OpenMaterializationIntent, RepairRowSnapshot as ExecRepairRowSnapshot,
};
use yadorilink_local_storage::{BlockReclamationStore, GcReport};
use yadorilink_replica_domain::file::{FileRecord, RecordKind};
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_replica_domain::session_state::{RestoreCommitOutcome, RestoreOperation};
use yadorilink_replica_engine::custody::VerifiedCustody;
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_root_authority::root_identity::VerifiedRoot;

use super::ReplicaCoordinator;

/// `yadorilink-filesystem-sync` names its exact-state values through
/// `yadorilink-peer-session`'s port types; the persistence layer has its
/// own, structurally identical one. The conversion belongs here, at the
/// adapter boundary that already exists to join the two.
fn expected_authoring_from(
    guard: yadorilink_peer_session::ports::ExpectedAuthoring<'_>,
) -> yadorilink_sync_sqlite::exact_materialized_commit::ExpectedAuthoring<'_> {
    yadorilink_sync_sqlite::exact_materialized_commit::ExpectedAuthoring {
        state: guard.state,
        expected_version: guard.expected_version,
    }
}

/// `None` for a structural directory: this commit stamps a row as holding
/// what it proves, and a structural directory is no row's entry.
fn exact_materialized_state_from(
    state: yadorilink_peer_session::ports::ExactActualState,
) -> Option<yadorilink_sync_sqlite::exact_materialized_commit::ExactMaterializedState> {
    match state {
        yadorilink_peer_session::ports::ExactActualState::Object { kind, version, identity } => {
            Some(
                yadorilink_sync_sqlite::exact_materialized_commit::ExactMaterializedState::Object {
                    kind,
                    version,
                    identity,
                },
            )
        }
        yadorilink_peer_session::ports::ExactActualState::Absent => {
            Some(yadorilink_sync_sqlite::exact_materialized_commit::ExactMaterializedState::Absent)
        }
        yadorilink_peer_session::ports::ExactActualState::StructuralDirectory { .. } => None,
    }
}

impl MaterializationExecutionPort for ReplicaCoordinator {
    fn record_temp_file(
        &self,
        group_id: &str,
        tmp_path: &Path,
    ) -> Result<(), MaterializationExecutionError> {
        use yadorilink_local_storage::TempFileLedger;
        self.temp_ledger(group_id).record(tmp_path).map_err(|error| {
            MaterializationExecutionError::from(SyncError::CorruptState(error.to_string()))
        })
    }

    fn release_temp_file(&self, group_id: &str, tmp_path: &Path) {
        use yadorilink_local_storage::TempFileLedger;
        self.temp_ledger(group_id).release(tmp_path);
    }

    fn record_stranded_directory(
        &self,
        group_id: &str,
        dir_path: &Path,
    ) -> Result<(), MaterializationExecutionError> {
        use yadorilink_local_storage::TempFileLedger;
        self.temp_ledger(group_id).strand(dir_path).map_err(|error| {
            MaterializationExecutionError::from(SyncError::CorruptState(error.to_string()))
        })
    }

    fn get_file(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<FileRecord>, MaterializationExecutionError> {
        Ok(self.file_index_repository().get_file(group_id, path).map_err(SyncError::from)?)
    }

    fn windows_symlink_opt_in_for_group(
        &self,
        group_id: &str,
    ) -> Result<bool, MaterializationExecutionError> {
        Ok(self
            .link_repository()
            .windows_symlink_opt_in_for_group(group_id)
            .map_err(SyncError::from)?)
    }

    fn list_materialization_states(
        &self,
        group_id: &str,
    ) -> Result<
        std::collections::HashMap<String, MaterializationState>,
        MaterializationExecutionError,
    > {
        Ok(self
            .materialization_state_repository()
            .list_materialization_states(group_id)
            .map_err(SyncError::from)?)
    }

    fn materialization_intent_kind(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<MaterializationIntentKind>, MaterializationExecutionError> {
        Ok(ReplicaCoordinator::materialization_intent_kind(self, group_id, path)
            .map_err(SyncError::from)?)
    }

    fn list_materialization_intent_paths(
        &self,
        group_id: &str,
    ) -> Result<std::collections::HashSet<String>, MaterializationExecutionError> {
        Ok(self
            .materialization_intent_repository()
            .list_materialization_intent_paths(group_id)
            .map_err(SyncError::from)?)
    }

    fn has_unsettled_projection_obligation(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, MaterializationExecutionError> {
        // Excludes a LOCAL-origin obligation: it can only be produced by
        // this device's own local emission, whose bytes were already
        // observed on this device's own disk before the change was ever
        // admitted, so it never represents content not yet placed -- see
        // `yadorilink_sync_sqlite::projection_obligations::
        // ObligationOrigin`'s own doc comment.
        Ok(self
            .sqlite()
            .dag_lookup_projection_obligation(group_id, path)
            .map_err(SyncError::from)?
            .is_some_and(|obligation| {
                obligation.origin
                    == yadorilink_sync_sqlite::projection_obligations::ObligationOrigin::Remote
            }))
    }

    fn clear_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), MaterializationExecutionError> {
        Ok(self
            .materialization_intent_repository()
            .clear_materialization_intent(group_id, path, permit)
            .map_err(SyncError::from)?)
    }

    fn record_dirty_path(
        &self,
        group_id: &str,
        path: &str,
        change_kind: &str,
        observed_at_unix_nanos: i64,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), MaterializationExecutionError> {
        Ok(self
            .dirty_path_repository()
            .record_dirty_path(group_id, path, change_kind, observed_at_unix_nanos, permit)
            .map_err(SyncError::from)?)
    }

    fn commit_recovered_materialized_state(
        &self,
        group_id: &str,
        path: &str,
        state: yadorilink_peer_session::ports::ExactActualState,
        expected: yadorilink_peer_session::ports::ExpectedAuthoring<'_>,
        permit: &RootCommitPermit,
    ) -> Result<bool, MaterializationExecutionError> {
        self.commit_recovered_state(group_id, path, state, expected, permit)
    }

    fn settled_file_paths(
        &self,
        group_id: &str,
        paths: &[&str],
    ) -> Result<std::collections::HashSet<String>, MaterializationExecutionError> {
        Ok(self.sqlite().settled_file_paths(group_id, paths).map_err(SyncError::from)?)
    }

    fn has_usable_materialized_generation(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, MaterializationExecutionError> {
        Ok(self
            .sqlite()
            .dag_usable_proof_names_current_version(group_id, path)
            .map_err(SyncError::from)?)
    }

    fn disk_is_untouched_proven_write(
        &self,
        group_id: &str,
        path: &str,
        out_path: &Path,
    ) -> Result<bool, MaterializationExecutionError> {
        Ok(ReplicaCoordinator::disk_is_untouched_proven_write_at(self, group_id, path, out_path)
            .unwrap_or(false))
    }

    fn get_recorded_placeholder_identity(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<
        Option<(yadorilink_local_storage::PlaceholderDiskIdentity, String)>,
        MaterializationExecutionError,
    > {
        Ok(self
            .materialization_state_repository()
            .get_recorded_placeholder_identity(group_id, path)
            .map_err(SyncError::from)?
            .map(|recorded| (recorded.identity, recorded.provider_kind)))
    }

    #[cfg(windows)]
    fn dehydrate_windows_placeholder(
        &self,
        path: &str,
        out_path: &Path,
        expected_generation: u64,
    ) -> Result<(), MaterializationExecutionError> {
        // Test-only bypass: a `--lib` unit test (`gc::tests::eviction_without_
        // remote_lease_never_reaches_physical_reclaim`) that seeds a real `Present` row via direct index writes
        // (no actual `cfapi-host.exe` ever ran to create a real CfAPI
        // placeholder object underneath it) has no live pipe to dial here --
        // unlike `get_recorded_placeholder_identity`'s "no recorded identity"
        // check just above this call site (a plain SQL read, and a REAL
        // precondition these tests must still seed via `record_placeholder_
        // generation` to reach this call at all), the actual native RPC
        // needs `cfapi-host.exe` running, real Windows CfAPI infrastructure
        // no unit test process provides. Exactly the same shape as
        // `create_or_defer_placeholder`'s own `test_force_deferred_
        // placeholder_is_armed_for` seam (`yadorilink-local-storage`'s
        // `materialize_write.rs`): a path-scoped flag lets a specific test
        // drive this exact Windows-only branch without a real provider,
        // while every OTHER path (and every non-test build) still dials the
        // real pipe. Compiled out entirely outside `cfg(test)` -- unlike
        // several other seams in this crate, nothing outside this crate's
        // own unit tests needs this one, so plain `cfg(test)` (rather than
        // `any(test, feature = "test-support")`) is deliberate: it keeps
        // this function's only caller (`gc.rs`/`hydration.rs`'s own
        // `#[cfg(test)] mod tests`) compiled into the exact same build unit
        // as the function itself, so it is never a `dead_code` warning in
        // the SEPARATE plain-lib artifact `test-support` alone would also
        // activate (via this crate's own dev-dependency self-reference)
        // but that never turns `cfg(test)` on for that artifact's callers.
        #[cfg(test)]
        if test_windows_dehydrate_confirmed_without_cfapi_host_is_armed_for(out_path) {
            let _ = expected_generation;
            return Ok(());
        }
        let absolute_path = out_path.to_string_lossy().to_string();
        crate::placeholder_dehydrate_windows::dehydrate_via_cfapi_host_blocking(
            &absolute_path,
            expected_generation,
        )
        .map_err(|e| {
            // `Io`/`Timeout`: the round trip to `cfapi-host` did not
            // complete, so whether `CfDehydratePlaceholder` itself ran
            // (and possibly succeeded) before the failure is genuinely
            // unknown -- `dehydrate_server` performs the real call BEFORE
            // writing its response. `Rejected`: a coherent
            // `DehydrateResponse` was received, so `cfapi-host`'s own
            // logic ran to completion and its answer is trusted. See
            // `MaterializationExecutionError::EvictionOutcomeAmbiguous`'s
            // own doc comment for why the caller must handle these two
            // differently.
            match e {
                crate::placeholder_dehydrate_windows::DehydrateError::Io(_)
                | crate::placeholder_dehydrate_windows::DehydrateError::Timeout => {
                    MaterializationExecutionError::EvictionOutcomeAmbiguous(format!(
                        "{path}: native Windows dehydrate outcome unconfirmed: {e}"
                    ))
                }
                crate::placeholder_dehydrate_windows::DehydrateError::Rejected(_) => {
                    MaterializationExecutionError::EvictionRejected(format!(
                        "{path}: native Windows dehydrate failed: {e}"
                    ))
                }
            }
        })
    }

    fn list_held_paths(
        &self,
        group_id: &str,
    ) -> Result<
        Vec<yadorilink_replica_domain::session_state::HeldPath>,
        MaterializationExecutionError,
    > {
        Ok(self
            .held_path_repository()
            .list_for_reconciliation(group_id)
            .map_err(SyncError::from)?)
    }

    fn begin_held_path_disk_write(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), MaterializationExecutionError> {
        ReplicaCoordinator::begin_path_disk_write(self, group_id, path, "held_path_reconcile")
    }

    fn release_held_path(
        &self,
        group_id: &str,
        path: &str,
        generation: i64,
    ) -> Result<bool, MaterializationExecutionError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        Ok(self
            .held_path_repository()
            .release(group_id, path, generation, now)
            .map_err(SyncError::from)?)
    }

    fn path_lock(&self, group_id: &str, path: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.path_lock_registry().path_lock(group_id, path)
    }

    fn record_structural_directory_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), MaterializationExecutionError> {
        Ok(ReplicaCoordinator::record_structural_directory_intent(self, group_id, path)
            .map_err(SyncError::from)?)
    }

    fn complete_structural_directory_origin(
        &self,
        group_id: &str,
        path: &str,
        identity: &yadorilink_fs_platform::fs_identity::FileIdentity,
    ) -> Result<(), MaterializationExecutionError> {
        Ok(ReplicaCoordinator::complete_structural_directory_origin(self, group_id, path, identity)
            .map_err(SyncError::from)?)
    }

    fn abandon_structural_directory_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), MaterializationExecutionError> {
        Ok(ReplicaCoordinator::abandon_structural_directory_intent(self, group_id, path)
            .map_err(SyncError::from)?)
    }

    fn resolve_interrupted_structural_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), MaterializationExecutionError> {
        Ok(ReplicaCoordinator::resolve_interrupted_structural_intent(self, group_id, path)
            .map_err(SyncError::from)?)
    }

    fn index_has_live_descendant(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, MaterializationExecutionError> {
        Ok(self
            .held_path_repository()
            .has_live_descendant_row(group_id, path)
            .map_err(SyncError::from)?)
    }

    fn is_structural_directory(
        &self,
        group_id: &str,
        path: &str,
        sync_root: &Path,
        observed: &yadorilink_fs_platform::fs_identity::FileIdentity,
    ) -> Result<bool, MaterializationExecutionError> {
        Ok(ReplicaCoordinator::structural_origin_status(
            self,
            group_id,
            path,
            sync_root,
            Some(observed),
        )
        .map_err(SyncError::from)?
            == yadorilink_sync_sqlite::structural_origin::StructuralOriginStatus::Structural)
    }

    fn adopt_as_structural_directory(
        &self,
        group_id: &str,
        path: &str,
        identity: &yadorilink_fs_platform::fs_identity::FileIdentity,
    ) -> Result<(), MaterializationExecutionError> {
        Ok(ReplicaCoordinator::adopt_as_structural_directory(self, group_id, path, identity)
            .map_err(SyncError::from)?)
    }

    fn retain_directory_with_untracked_content(
        &self,
        group_id: &str,
        path: &str,
        removable: Option<&yadorilink_fs_platform::fs_identity::FileIdentity>,
    ) -> Result<(), MaterializationExecutionError> {
        Ok(ReplicaCoordinator::keep_retained_directory(
            self,
            group_id,
            path,
            yadorilink_sync_sqlite::structural_origin::RETAINED_UNTRACKED_CONTENT,
            removable,
        )
        .map_err(SyncError::from)?)
    }

    fn forget_removed_directory(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), MaterializationExecutionError> {
        Ok(ReplicaCoordinator::forget_removed_directory(self, group_id, path)
            .map_err(SyncError::from)?)
    }

    fn list_restore_operations(
        &self,
        group_id: &str,
    ) -> Result<Vec<RestoreOperation>, MaterializationExecutionError> {
        Ok(self
            .restore_operation_repository()
            .list_restore_operations(group_id)
            .map_err(SyncError::from)?)
    }

    fn commit_restore_operation(
        &self,
        operation_id: &str,
        identity: Option<&yadorilink_fs_platform::fs_identity::FileIdentity>,
        wrote_under_mutation_generation: Option<i64>,
        permit: &RootCommitPermit,
    ) -> Result<RestoreCommitOutcome, MaterializationExecutionError> {
        Ok(self
            .restore_operation_repository()
            .commit_restore_operation(
                operation_id,
                identity,
                wrote_under_mutation_generation,
                permit,
            )
            .map_err(SyncError::from)?)
    }

    fn discard_restore_operation(
        &self,
        operation_id: &str,
    ) -> Result<(), MaterializationExecutionError> {
        Ok(self
            .restore_operation_repository()
            .discard_restore_operation(operation_id)
            .map_err(SyncError::from)?)
    }

    fn verify_root(
        &self,
        root: &Path,
        group_id: &str,
    ) -> Result<VerifiedRoot, MaterializationExecutionError> {
        Ok(VerifiedRoot::verify(root, group_id, self)?)
    }

    fn open_root(
        &self,
        root: &Path,
        group_id: &str,
    ) -> Result<VerifiedRoot, MaterializationExecutionError> {
        Ok(VerifiedRoot::open(root, group_id, self)?)
    }

    fn open_materialization_intent_guard<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        target_version_hash: &[u8],
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<Box<dyn OpenMaterializationIntent + Send + 'a>, MaterializationExecutionError> {
        let guard = crate::materialization_intent::MaterializationIntentGuard::open(
            self,
            group_id,
            path,
            target_version_hash,
            permit,
        )
        .map_err(SyncError::from)?;
        Ok(Box::new(guard))
    }

    fn eviction_eligibility_snapshot(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<ExecEvictionEligibilitySnapshot, MaterializationExecutionError> {
        Ok(ExecEvictionEligibilitySnapshot {
            current_version: self
                .sqlite()
                .dag_get_current_version_record(group_id, path)
                .map_err(SyncError::from)?,
            record_kind: self
                .file_index_repository()
                .get_record_kind(group_id, path)
                .map_err(SyncError::from)?,
        })
    }

    fn eviction_revalidation_snapshot(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<ExecEvictionRevalidationSnapshot, MaterializationExecutionError> {
        Ok(ExecEvictionRevalidationSnapshot {
            current_version: self
                .sqlite()
                .dag_get_current_version_record(group_id, path)
                .map_err(SyncError::from)?,
            materialization_state: self
                .materialization_state_repository()
                .get_materialization_state(group_id, path)
                .map_err(SyncError::from)?,
            path_dirty: self
                .dirty_path_repository()
                .is_path_dirty(group_id, path)
                .map_err(SyncError::from)?,
            pinned: self
                .pinned_item_repository()
                .retention(group_id, path)
                .map_err(SyncError::from)?
                .policy
                == yadorilink_sync_sqlite::RetentionPolicy::Pinned,
        })
    }

    fn flush_pending_proof_identity(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<
        Option<Option<yadorilink_fs_platform::fs_identity::FileIdentity>>,
        MaterializationExecutionError,
    > {
        Ok(self
            .database
            .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                yadorilink_sync_sqlite::flush_pending_proof_identity(conn, group_id, path)
            })
            .map_err(SyncError::from)?)
    }

    fn repair_row_snapshot(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<ExecRepairRowSnapshot, MaterializationExecutionError> {
        // ONE statement for every field. This used to take the version,
        // authoring and state from the canonical read and then go back to
        // the database twice more, for the kind and the record -- three
        // read transactions, no isolation spanning them, and a struct
        // called a snapshot that could hold the version and authoring of
        // one incarnation of the row beside the blocks and kind of
        // another. Repair then compared a guard built from the first
        // against bytes chosen by the second.
        //
        // The path lock does not close this: native admission does not take
        // it, so a supersession can land while a live repair pass is
        // between reads.
        //
        // Nothing had to be added to the canonical read to fix this: it
        // already returned the kind, the block list and the symlink
        // target in the same statement.
        let Some(canonical) = self
            .database
            .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                yadorilink_sync_sqlite::read_canonical_current_row(conn, group_id, path)
            })
            .map_err(SyncError::from)?
        else {
            return Ok(ExecRepairRowSnapshot::default());
        };
        let current_version = canonical.version_hash();
        let snapshot = canonical.snapshot;
        Ok(ExecRepairRowSnapshot {
            materialization_state: canonical.materialization_state,
            record_kind: Some(snapshot.record_kind),
            symlink_target: snapshot.symlink_target.clone(),
            file: Some(FileRecord {
                path: path.to_string(),
                size: snapshot.size,
                mtime_unix_nanos: snapshot.mtime_unix_nanos,
                blocks: snapshot.blocks,
                deleted: snapshot.deleted,
            }),
            current_version: Some(current_version),
            unix_mode: snapshot.unix_mode,
            xattrs: snapshot.xattrs,
        })
    }

    fn reclaim_verified_cached_blocks(
        &self,
        deletion_guard: &BlockPhysicalDeletionGuard<'_>,
        custody: VerifiedCustody<'_>,
        siblings: Vec<VerifiedCustody<'_>>,
        store: &dyn BlockReclamationStore,
    ) -> Result<GcReport, MaterializationExecutionError> {
        Ok(self
            .reclaim_cached_blocks(deletion_guard, custody, &siblings, store)
            .map_err(SyncError::from)?)
    }

    fn remote_siblings_sharing_blocks(
        &self,
        group_id: &str,
        path: &str,
        blocks: &[yadorilink_replica_domain::file::VersionBlock],
    ) -> Result<
        Vec<(String, String, yadorilink_replica_domain::file::FileVersion)>,
        MaterializationExecutionError,
    > {
        let rows = self
            .materialization_state_repository()
            .remote_rows_sharing_blocks(group_id, path, blocks)
            .map_err(SyncError::from)?;
        let mut out = Vec::with_capacity(rows.len());
        for (row_group, row_path) in rows {
            // A full replica is the durable holder of its group: its placeholders keep their
            // blocks whatever custody says, exactly as `is_local_full_replica` decides for the
            // evicting file itself.
            if matches!(
                self.link_repository().materialization_policy_for_group(&row_group),
                Ok(Some(yadorilink_replica_domain::session_state::MaterializationPolicy::Eager))
            ) {
                continue;
            }
            if let Some(current) = self
                .sqlite()
                .dag_get_current_version_record(&row_group, &row_path)
                .map_err(SyncError::from)?
            {
                if !current.deleted {
                    out.push((row_group, row_path, current.to_file_version()));
                }
            }
        }
        Ok(out)
    }

    fn dag_bump_mutation_fence(
        &self,
        group_id: &str,
        path: &str,
        mutation_kind: &str,
    ) -> Result<i64, MaterializationExecutionError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        self.database
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                yadorilink_sync_sqlite::materialized_generation::bump_mutation_fence(
                    tx,
                    group_id,
                    path,
                    mutation_kind,
                    now,
                )
            })
            .map_err(|error| match error {
                // A frozen group is refused for this path alone: a sweep goes
                // on with the others instead of failing the group.
                yadorilink_sync_sqlite::SyncSqliteError::GroupFrozen { .. } => {
                    MaterializationExecutionError::Io(std::io::Error::other(error.to_string()))
                }
                other => SyncError::from(other).into(),
            })
    }

    fn open_eviction(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<Result<i64, MaterializationExecutionError>, MaterializationExecutionError> {
        ReplicaCoordinator::open_eviction(self, group_id, path, permit)
    }

    fn settle_eviction(
        &self,
        group_id: &str,
        path: &str,
        placeholder: yadorilink_local_storage::PlaceholderIdentityToRecord,
        permit: &RootCommitPermit<'_>,
    ) -> Result<bool, MaterializationExecutionError> {
        ReplicaCoordinator::settle_eviction(self, group_id, path, placeholder, permit)
    }

    fn abandon_eviction(
        &self,
        group_id: &str,
        path: &str,
        version: &yadorilink_replica_domain::ids::VersionHash,
        abandoned: yadorilink_filesystem_sync::materialization_execution::AbandonedEviction,
        permit: &RootCommitPermit<'_>,
    ) -> Result<bool, MaterializationExecutionError> {
        ReplicaCoordinator::abandon_eviction(self, group_id, path, version, abandoned, permit)
    }

    fn record_placeholder_identity(
        &self,
        group_id: &str,
        path: &str,
        outcome: yadorilink_local_storage::PlaceholderIdentityToRecord,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), MaterializationExecutionError> {
        Ok(ReplicaCoordinator::record_placeholder_identity(self, group_id, path, outcome, permit)?)
    }

    fn open_repair_quarantine<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        target_version_hash: &[u8],
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<Box<dyn OpenMaterializationIntent + Send + 'a>, MaterializationExecutionError> {
        ReplicaCoordinator::open_repair_quarantine(
            self,
            group_id,
            path,
            target_version_hash,
            permit,
        )
    }

    fn open_repair_object_rebuild<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        kind: RecordKind,
        target_version_hash: &[u8],
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<(i64, Box<dyn OpenMaterializationIntent + Send + 'a>), MaterializationExecutionError>
    {
        ReplicaCoordinator::open_repair_object_rebuild(
            self,
            group_id,
            path,
            kind,
            target_version_hash,
            permit,
        )
    }

    fn settle_repair_object_rebuild(
        &self,
        group_id: &str,
        path: &str,
        kind: RecordKind,
        out_path: &Path,
        version: yadorilink_replica_domain::ids::VersionHash,
        row_state: Option<MaterializationState>,
        mutation_generation: i64,
        permit: &RootCommitPermit<'_>,
    ) -> Result<bool, MaterializationExecutionError> {
        ReplicaCoordinator::settle_repair_object_rebuild(
            self,
            group_id,
            path,
            kind,
            out_path,
            version,
            row_state,
            mutation_generation,
            permit,
        )
    }

    fn preserve_divergent_restore(
        &self,
        operation_id: &str,
        group_id: &str,
        path: &str,
        change_kind: &str,
        observed_at_unix_nanos: i64,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), MaterializationExecutionError> {
        ReplicaCoordinator::preserve_divergent_restore(
            self,
            operation_id,
            group_id,
            path,
            change_kind,
            observed_at_unix_nanos,
            permit,
        )
    }

    fn open_repair_placeholder_demotion(
        &self,
        group_id: &str,
        path: &str,
        row_state: MaterializationState,
        version: Option<&yadorilink_replica_domain::ids::VersionHash>,
        permit: &RootCommitPermit<'_>,
    ) -> Result<bool, MaterializationExecutionError> {
        ReplicaCoordinator::open_repair_placeholder_demotion(
            self, group_id, path, row_state, version, permit,
        )
    }

    fn settle_repair_reconstruct(
        &self,
        group_id: &str,
        path: &str,
        out_path: &Path,
        row_state: MaterializationState,
        version: Option<yadorilink_replica_domain::ids::VersionHash>,
        mutation_generation: i64,
        permit: &RootCommitPermit<'_>,
    ) -> bool {
        ReplicaCoordinator::settle_repair_reconstruct(
            self,
            group_id,
            path,
            out_path,
            row_state,
            version,
            mutation_generation,
            permit,
        )
    }
}

/// Test-only failure-injection flag consulted by `dehydrate_windows_
/// placeholder`'s `#[cfg(windows)]` impl above: when armed for a path,
/// that call skips the real `cfapi-host.exe` pipe round trip and reports
/// dehydration confirmed. See that call site's own doc comment for why a
/// plain `--lib` unit test needs this (no real Windows CfAPI provider
/// process runs in a `cargo test` process).
///
/// Path-keyed, not a single global flag -- same reasoning as
/// `yadorilink_local_storage::materialize_write`'s identical
/// `TEST_FORCE_DEFERRED_PLACEHOLDER_PATHS`: several `#[tokio::test]`
/// functions in this crate can be mid-flight at once, each evicting its
/// own path, and a blanket flag would let one test's bypass silently
/// swallow an unrelated test's real (non-bypassed) call.
///
/// `#[cfg(windows)]`: the only reader is inside `dehydrate_windows_
/// placeholder`'s own `#[cfg(windows)]` body, so on every other target
/// this static would otherwise be written (by the arming function below)
/// but never read -- a `dead_code` warning under `-D warnings`. The
/// arming function itself stays defined on every platform (its callers,
/// `gc.rs`/`hydration.rs`'s own unit tests, are not themselves
/// `#[cfg(windows)]`-gated); its body is simply a no-op on a target where
/// there is no Windows dehydrate path to bypass in the first place.
#[cfg(all(windows, test))]
static TEST_WINDOWS_DEHYDRATE_CONFIRMED_PATHS: std::sync::Mutex<
    Option<std::collections::HashSet<std::path::PathBuf>>,
> = std::sync::Mutex::new(None);

#[cfg(all(windows, test))]
fn test_windows_dehydrate_confirmed_without_cfapi_host_is_armed_for(path: &Path) -> bool {
    TEST_WINDOWS_DEHYDRATE_CONFIRMED_PATHS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .is_some_and(|paths| paths.contains(path))
}

/// Test-only: arms (or disarms) the bypass above for one exact path --
/// see [`TEST_WINDOWS_DEHYDRATE_CONFIRMED_PATHS`]'s own doc comment. Call
/// after seeding a `Present` row this test intends to `evict_file` on a
/// build targeting Windows, once a placeholder identity has also been
/// recorded for it (`record_placeholder_generation`) -- the real
/// precondition `dehydrate_windows_placeholder`'s own doc comment
/// documents, which this bypass does NOT substitute for.
#[cfg(all(windows, test))]
pub(crate) fn set_test_windows_dehydrate_confirmed_for_path(path: &Path, armed: bool) {
    let mut guard =
        TEST_WINDOWS_DEHYDRATE_CONFIRMED_PATHS.lock().unwrap_or_else(|p| p.into_inner());
    let paths = guard.get_or_insert_with(std::collections::HashSet::new);
    if armed {
        paths.insert(path.to_path_buf());
    } else {
        paths.remove(path);
    }
}

/// Non-Windows stand-in for the above: there is no native Windows
/// dehydrate path to bypass on this target at all, so arming this is a
/// no-op. Exists so `gc.rs`/`hydration.rs`'s own unit tests (which run,
/// and must compile, on every target) can call this unconditionally
/// rather than needing their own `#[cfg(windows)]` branch around the call.
#[cfg(all(not(windows), test))]
pub(crate) fn set_test_windows_dehydrate_confirmed_for_path(path: &Path, armed: bool) {
    let _ = (path, armed);
}

#[cfg(test)]
mod tests;

impl ReplicaCoordinator {
    /// The recovery commit behind [`MaterializationExecutionPort::commit_recovered_materialized_state`]
    /// and [`Self::finish_matching_in_flight_write`]: one guarded transaction that publishes the
    /// proof of the version the caller compared the bytes on disk against, sets the row
    /// `Present` and clears the intent, or writes nothing when the row has moved.
    fn commit_recovered_state(
        &self,
        group_id: &str,
        path: &str,
        state: yadorilink_peer_session::ports::ExactActualState,
        expected: yadorilink_peer_session::ports::ExpectedAuthoring<'_>,
        permit: &RootCommitPermit,
    ) -> Result<bool, MaterializationExecutionError> {
        let exact = exact_materialized_state_from(state).ok_or_else(|| {
            SyncError::from(yadorilink_sync_sqlite::SyncSqliteError::InvalidInput(format!(
                "{group_id}/{path}: a structural directory is no entry a row can be recovered to"
            )))
        })?;
        let guard = expected_authoring_from(expected);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        let outcome = self
            .database
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                let outcome =
                    yadorilink_sync_sqlite::exact_materialized_commit::commit_recovered_materialized_state(
                        tx, group_id, path, &exact, guard, now,
                    )?;
                permit.verify()?;
                Ok(outcome)
            })
            .map_err(SyncError::from)?;
        Ok(matches!(
            outcome,
            yadorilink_sync_sqlite::exact_materialized_commit::RecoveredMaterializedCommit::Published(_)
        ))
    }

    /// Settles a regular file whose bytes on disk are the `version` of its row, when an earlier
    /// attempt left the row in flight: the attempt renamed the bytes in and was refused at its
    /// commit (another mutator advanced the fence), so the row is still `Hydrating` with its
    /// intent open and no proof. One guarded recovery commit finishes it, the way the repair
    /// sweep finishes a write whose bytes are already right. A row in any other state is
    /// already settled as far as this is concerned. `false`, with nothing written, when the
    /// commit was refused because the row moved.
    pub(crate) fn finish_matching_in_flight_write(
        &self,
        group_id: &str,
        path: &str,
        version: &yadorilink_replica_domain::ids::VersionHash,
        identity: Option<yadorilink_fs_platform::fs_identity::FileIdentity>,
        permit: &RootCommitPermit,
    ) -> Result<bool, MaterializationExecutionError> {
        let in_flight = self
            .materialization_state_repository()
            .get_materialization_state(group_id, path)
            .map_err(SyncError::from)?
            == Some(yadorilink_replica_domain::session_state::MaterializationState::Hydrating);
        if !in_flight {
            return Ok(true);
        }
        self.commit_recovered_state(
            group_id,
            path,
            yadorilink_peer_session::ports::ExactActualState::Object {
                kind: yadorilink_replica_domain::file::RecordKind::File,
                version: *version,
                identity: Box::new(identity),
            },
            yadorilink_peer_session::ports::ExpectedAuthoring {
                state: yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE,
                expected_version: Some(version),
            },
            permit,
        )
    }
}
