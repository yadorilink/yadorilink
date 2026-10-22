//! `impl LocalMutationStore for ReplicaCoordinator`.
//!
//! `yadorilink-local-capture::LocalChangeProcessor` needs a concrete
//! `Arc<dyn LocalMutationStore>` so it can mutually exclude local capture
//! against anything else touching the same path (via `path_lock`), and
//! `ReplicaCoordinator` is this trait's sole implementor.
//! `ReplicaCoordinator::path_lock_registry()` (see its `from_database` doc
//! comment) is the only per-path lock registry in the process, so
//! `path_lock` below trivially serializes against every other caller
//! reached through `ReplicaCoordinator`, local capture included.
//!
//! `ReplicaCoordinator` also already implements `RootVerificationStatePort`,
//! which `verify_root`/`open_root` below need to pass to
//! `VerifiedRoot::verify`/`VerifiedRoot::open`.
//!
//! Every method below is a thin delegation to this struct's own existing
//! accessors. Legal under the orphan rule because the trait is foreign
//! (`yadorilink-local-capture`) but `ReplicaCoordinator` is local to this
//! crate.
//!
//! Three are not thin: capture's directory operations
//! (`commit_captured_directory`, `commit_directory_removal`,
//! `commit_directory_rename`) choose between the emitting and index-only
//! writes, and build a removal's point deletes and their Absent evidence,
//! here on the owner side, so the capture lane names what it captured and
//! composes none of the raw primitives itself.
//!
//! The authoring bodies of `commit_local_mutations_batch`,
//! `commit_captured_directory`, `commit_directory_removal`,
//! `commit_directory_rename` and `commit_write_through_deletion` live in
//! [`super::local_commit`], each signing a native delta as the
//! replica's current author.
//!
//! `build_change_processor` (`link_runtime/startup.rs`) is this port's one
//! production call site (`LinkRuntimeDependencies::replica_coordinator`).

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use yadorilink_local_capture::ports::{LocalChangeEmission, LocalMutationStore};
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::session_state::{
    DirtyPath, LocalFileMetaColumns, MaterializationState, PreparedLocalMutation,
};
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sync_sqlite::dag_store::LocalAuthorKey;
use yadorilink_sync_sqlite::SyncSqliteError;

use super::ReplicaCoordinator;

use super::local_commit;

impl LocalMutationStore for ReplicaCoordinator {
    fn path_lock(&self, group_id: &str, path: &str) -> Arc<tokio::sync::Mutex<()>> {
        ReplicaCoordinator::path_lock_registry(self).path_lock(group_id, path)
    }

    fn get_file(&self, group_id: &str, path: &str) -> Result<Option<FileRecord>, SyncSqliteError> {
        self.file_index_repository().get_file(group_id, path)
    }

    fn canonical_current_row(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<yadorilink_sync_sqlite::CanonicalCurrentRow>, SyncSqliteError> {
        self.file_index_repository().canonical_current_row(group_id, path)
    }

    fn native_capture_witness(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<yadorilink_replica_domain::native_state::NativeCaptureWitness, SyncSqliteError>
    {
        self.file_index_repository().native_capture_witness(group_id, path)
    }

    fn native_capture_witnesses(
        &self,
        group_id: &str,
    ) -> Result<
        std::collections::HashMap<
            String,
            yadorilink_replica_domain::native_state::NativeCaptureWitness,
        >,
        SyncSqliteError,
    > {
        self.file_index_repository().native_capture_witnesses(group_id)
    }

    fn native_capture_is_fresh(
        &self,
        group_id: &str,
        witness: &yadorilink_replica_domain::native_state::NativeCaptureWitness,
    ) -> Result<bool, SyncSqliteError> {
        self.file_index_repository().native_capture_is_fresh(group_id, witness)
    }

    fn list_materialization_states(
        &self,
        group_id: &str,
    ) -> Result<HashMap<String, MaterializationState>, SyncSqliteError> {
        self.materialization_state_repository().list_materialization_states(group_id)
    }

    fn capture_volume_identity(
        &self,
        group_id: &str,
    ) -> Result<Option<Option<String>>, SyncSqliteError> {
        self.link_repository().capture_volume_identity_for_group(group_id)
    }

    fn adopt_capture_volume_identity(
        &self,
        group_id: &str,
        identity: &str,
    ) -> Result<(), SyncSqliteError> {
        self.link_repository().set_capture_volume_identity_for_group(group_id, identity)
    }

    fn get_materialization_state(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<MaterializationState>, SyncSqliteError> {
        self.materialization_state_repository().get_materialization_state(group_id, path)
    }

    fn list_placeholder_generations(
        &self,
        group_id: &str,
    ) -> Result<
        HashMap<String, yadorilink_sync_sqlite::RecordedPlaceholderGeneration>,
        SyncSqliteError,
    > {
        self.materialization_state_repository().list_placeholder_generations(group_id)
    }

    fn get_placeholder_generation(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<yadorilink_sync_sqlite::RecordedPlaceholderGeneration>, SyncSqliteError>
    {
        self.materialization_state_repository().get_placeholder_generation(group_id, path)
    }

    /// Delegates to `crate::placeholder_inspect_windows`, the only
    /// module in this crate allowed to make a real `CfGetPlaceholderInfo`
    /// call -- see that module's own doc comment for why this daemon
    /// process, not `yadorilink-cfapi-host.exe`, makes the call directly.
    /// The `#[cfg(not(windows))]` arm is unreachable in practice:
    /// `local_change.rs`'s dirty-detection verdict only ever calls this
    /// method from its own `#[cfg(windows)]` branch, so this body exists
    /// solely to keep the trait implementable (and this crate compiling)
    /// on every other platform.
    fn inspect_windows_placeholder(
        &self,
        path: &Path,
        expected_generation: u64,
    ) -> yadorilink_local_capture::ports::PlaceholderStatus {
        #[cfg(windows)]
        {
            crate::placeholder_inspect_windows::inspect_placeholder(path, expected_generation)
        }
        #[cfg(not(windows))]
        {
            let _ = (path, expected_generation);
            unreachable!(
                "inspect_windows_placeholder is only ever called from local_change.rs's own \
                 #[cfg(windows)] branch"
            )
        }
    }

    fn has_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        self.materialization_intent_repository().has_materialization_intent(group_id, path)
    }

    fn materialization_intent_target(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<Vec<u8>>, SyncSqliteError> {
        self.materialization_intent_repository().materialization_intent_target(group_id, path)
    }

    fn pre_image_content_targets(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Vec<Vec<u8>>, SyncSqliteError> {
        self.database().read::<_, SyncSqliteError>(|conn| {
            yadorilink_sync_sqlite::materialized_generation::pre_image_content_targets(
                conn, group_id, path,
            )
        })
    }

    fn paused_items(&self, group_id: &str) -> Result<Vec<String>, SyncSqliteError> {
        self.paused_item_repository().list(group_id)
    }

    fn held_path_names(&self, group_id: &str) -> Result<Vec<String>, SyncSqliteError> {
        self.held_path_repository().held_paths(group_id)
    }

    /// A frozen group is paused as a whole for local capture, except while its rebootstrap runs
    /// the one final capture pass: that pass is what folds the user's edits into the plan.
    fn group_frozen(&self, group_id: &str) -> Result<bool, SyncSqliteError> {
        Ok(self.held_path_repository().group_frozen(group_id)?
            && self.capture_authority(group_id).is_none())
    }

    fn hold_unauthorable_local_edit(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), SyncSqliteError> {
        self.held_path_repository().hold_unauthorable_local_edit(group_id, path)
    }

    fn wake_install_reconciliation(&self) {
        self.notify_held_path();
    }

    fn has_unsettled_projection_obligation(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        // While a REMOTE-origin projection obligation exists for this path,
        // an absent local file must not yet be interpreted as an offline
        // user deletion -- any row at all (pending or the parked
        // `ignore_blocked`) means the path is still being placed locally.
        // A `Local`-origin row is excluded from this veto: it can only be
        // produced by this device's own local emission, whose bytes were
        // already observed on this device's own disk before the change was
        // ever admitted, so it never represents content not yet placed --
        // see `yadorilink_sync_sqlite::projection_obligations::
        // ObligationOrigin`'s own doc comment.
        Ok(self.sqlite().dag_lookup_projection_obligation(group_id, path)?.is_some_and(
            |obligation| {
                obligation.origin
                    == yadorilink_sync_sqlite::projection_obligations::ObligationOrigin::Remote
            },
        ))
    }

    fn is_held(&self, group_id: &str, path: &str) -> Result<bool, SyncSqliteError> {
        Ok(self
            .materialization_state_repository()
            .get_held_state(group_id, path)?
            .is_some_and(|held| held.keeps_the_name_empty()))
    }

    fn structural_directory_origin(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<yadorilink_sync_sqlite::structural_origin::StructuralDirectoryOrigin, SyncSqliteError>
    {
        self.sqlite().dag_structural_directory_origin(group_id, path)
    }

    fn retained_directory(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<yadorilink_sync_sqlite::structural_origin::RetainedDirectory, SyncSqliteError> {
        self.sqlite().retained_directory(group_id, path)
    }

    fn materialized_directory_identity(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<yadorilink_fs_platform::fs_identity::FileIdentity>, SyncSqliteError> {
        self.sqlite().dag_materialized_directory_identity(group_id, path)
    }

    fn birth_time_granularity(
        &self,
        sync_root: &std::path::Path,
    ) -> yadorilink_fs_platform::fs_identity::TimestampGranularity {
        super::peer_replica_state::cached_birth_time_granularity(sync_root)
    }

    fn disk_is_untouched_proven_write(
        &self,
        group_id: &str,
        path: &str,
        sync_root: &std::path::Path,
        out_path: &std::path::Path,
    ) -> Result<bool, SyncSqliteError> {
        self.sqlite().disk_is_untouched_proven_write_at(
            group_id,
            path,
            out_path,
            super::peer_replica_state::cached_birth_time_granularity(sync_root),
        )
    }

    fn commit_local_mutations_batch(
        &self,
        group_id: &str,
        mutations: &[PreparedLocalMutation],
        evidence: &[Option<yadorilink_sync_sqlite::file_index::LocalCaptureActualStateEvidence>],
        origin_device_id: &str,
        emission: LocalChangeEmission<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.local_policy_head(group_id).map_err(SyncSqliteError::from)?;
        let capture = self.capture_authority(group_id);
        self.with_local_author(emission.author, |author| {
            local_commit::commit_local_mutations_batch(
                self.file_index_repository(),
                group_id,
                mutations,
                evidence,
                origin_device_id,
                author,
                capture.as_deref(),
                emission.permit,
            )
        })
    }

    fn commit_captured_directory(
        &self,
        group_id: &str,
        directory: &yadorilink_local_capture::ports::CapturedDirectory,
        origin_device_id: &str,
        emitter: Option<&LocalAuthorKey>,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        let Some(emitter) = emitter else {
            let observed = directory.identity.map(|filesystem_identity| {
                yadorilink_sync_sqlite::file_index::ImportedActualState {
                    filesystem_identity,
                    record_kind: yadorilink_replica_domain::file::RecordKind::Directory,
                    version_hash: directory.version.version_hash,
                }
            });
            return self.file_index_repository().upsert_files_batch(
                group_id,
                std::slice::from_ref(&directory.record),
                origin_device_id,
                &[Some(directory.meta.clone())],
                &[observed],
                permit,
            );
        };
        self.local_policy_head(group_id).map_err(SyncSqliteError::from)?;
        let capture = self.capture_authority(group_id);
        self.with_local_author(emitter, |author| {
            local_commit::commit_captured_directory(
                self.file_index_repository(),
                group_id,
                &directory.record,
                &directory.op,
                &directory.version,
                &directory.meta,
                directory.identity.as_ref(),
                origin_device_id,
                author,
                capture.as_deref(),
                permit,
            )
        })
    }

    fn commit_directory_removal(
        &self,
        group_id: &str,
        root: &str,
        tombstones: &[PreparedLocalMutation],
        origin_device_id: &str,
        observed_at_unix_nanos: i64,
        emitter: Option<&LocalAuthorKey>,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        let Some(emitter) = emitter else {
            for tombstone in tombstones {
                self.file_index_repository().mark_deleted_at(
                    group_id,
                    &tombstone.record().path,
                    origin_device_id,
                    observed_at_unix_nanos,
                    permit,
                )?;
            }
            return Ok(());
        };
        self.local_policy_head(group_id).map_err(SyncSqliteError::from)?;
        let capture = self.capture_authority(group_id);
        self.with_local_author(emitter, |author| {
            local_commit::commit_directory_removal(
                self.file_index_repository(),
                group_id,
                root,
                tombstones,
                origin_device_id,
                author,
                capture.as_deref(),
                permit,
            )
        })
    }

    fn commit_directory_rename(
        &self,
        group_id: &str,
        from: &str,
        to: &str,
        mutations: &[PreparedLocalMutation],
        evidence: &[Option<yadorilink_sync_sqlite::file_index::LocalCaptureActualStateEvidence>],
        origin_device_id: &str,
        emission: LocalChangeEmission<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.local_policy_head(group_id).map_err(SyncSqliteError::from)?;
        let capture = self.capture_authority(group_id);
        self.with_local_author(emission.author, |author| {
            local_commit::commit_directory_rename(
                self.file_index_repository(),
                group_id,
                from,
                to,
                mutations,
                evidence,
                origin_device_id,
                author,
                capture.as_deref(),
                emission.permit,
            )
        })
    }

    fn has_live_descendant_row(&self, group_id: &str, path: &str) -> Result<bool, SyncSqliteError> {
        self.file_index_repository().has_live_descendant_row(group_id, path)
    }

    fn follow_renamed_structural_directory(
        &self,
        group_id: &str,
        to_path: &str,
        identity: &yadorilink_fs_platform::fs_identity::FileIdentity,
        birth_time_granularity: yadorilink_fs_platform::fs_identity::TimestampGranularity,
    ) -> Result<Option<String>, SyncSqliteError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        self.sqlite().dag_rekey_structural_origin(
            group_id,
            to_path,
            identity,
            birth_time_granularity,
            now,
        )
    }

    fn upsert_files_batch(
        &self,
        group_id: &str,
        records: &[FileRecord],
        origin_device_id: &str,
        metas: &[Option<LocalFileMetaColumns>],
        observed: &[Option<yadorilink_sync_sqlite::file_index::ImportedActualState>],
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.file_index_repository().upsert_files_batch(
            group_id,
            records,
            origin_device_id,
            metas,
            observed,
            permit,
        )
    }

    fn mark_deleted_at(
        &self,
        group_id: &str,
        path: &str,
        device_id: &str,
        observed_at_unix_nanos: i64,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.file_index_repository().mark_deleted_at(
            group_id,
            path,
            device_id,
            observed_at_unix_nanos,
            permit,
        )
    }

    fn remove_file(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<bool, SyncSqliteError> {
        self.file_index_repository().remove_file(group_id, path, permit)
    }

    fn record_group_block_provenance(
        &self,
        group_id: &str,
        block_hashes: &[Vec<u8>],
    ) -> Result<(), SyncSqliteError> {
        self.record_block_provenance(group_id, block_hashes)
    }

    fn record_dirty_path(
        &self,
        group_id: &str,
        path: &str,
        change_kind: &str,
        observed_at_unix_nanos: i64,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.dirty_path_repository().record_dirty_path(
            group_id,
            path,
            change_kind,
            observed_at_unix_nanos,
            permit,
        )
    }

    fn record_dirty_paths_batch(
        &self,
        group_id: &str,
        entries: &[(String, String, i64)],
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.dirty_path_repository().record_dirty_paths_batch(group_id, entries, permit)
    }

    fn mark_dirty_path_attempt(
        &self,
        group_id: &str,
        path: &str,
        last_error: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.dirty_path_repository().mark_dirty_path_attempt(group_id, path, last_error, permit)
    }

    fn clear_dirty_paths_conditional_batch(
        &self,
        group_id: &str,
        entries: &[(String, i64)],
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.dirty_path_repository().clear_dirty_paths_conditional_batch(group_id, entries, permit)
    }

    fn local_emission_available(&self, group_id: &str) -> bool {
        self.local_policy_head(group_id).is_ok()
    }

    fn list_dirty_paths(&self, group_id: &str) -> Result<Vec<DirtyPath>, SyncSqliteError> {
        self.dirty_path_repository().list_dirty_paths(group_id)
    }

    fn list_files(&self, group_id: &str) -> Result<Vec<FileRecord>, SyncSqliteError> {
        self.file_index_repository().list_files(group_id)
    }

    fn list_files_with_kind(
        &self,
        group_id: &str,
    ) -> Result<Vec<(FileRecord, yadorilink_replica_domain::file::RecordKind)>, SyncSqliteError>
    {
        self.file_index_repository().list_files_with_kind(group_id)
    }

    fn list_indexed_paths_with_kind(
        &self,
        group_id: &str,
    ) -> Result<Vec<(String, yadorilink_replica_domain::file::RecordKind)>, SyncSqliteError> {
        self.file_index_repository().list_indexed_paths_with_kind(group_id)
    }

    fn verify_root(
        &self,
        root: &Path,
        group_id: &str,
    ) -> Result<yadorilink_root_authority::root_identity::VerifiedRoot, SyncSqliteError> {
        yadorilink_root_authority::root_identity::VerifiedRoot::verify(root, group_id, self)
            .map_err(SyncSqliteError::from)
    }

    fn open_root(
        &self,
        root: &Path,
        group_id: &str,
    ) -> Result<yadorilink_root_authority::root_identity::VerifiedRoot, SyncSqliteError> {
        yadorilink_root_authority::root_identity::VerifiedRoot::open(root, group_id, self)
            .map_err(SyncSqliteError::from)
    }
}

#[cfg(test)]
mod tests;
