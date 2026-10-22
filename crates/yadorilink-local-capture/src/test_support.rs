//! `TestReplica` -- a thin, crate-local wrapper around
//! `yadorilink_daemon::replica_coordinator::ReplicaCoordinator` that this
//! crate's own `#[cfg(test)]` code (in `local_change.rs` and
//! `ports/local_mutation.rs`) uses to build a real, database-backed
//! `LocalMutationStore` fixture. Why a wrapper, not `ReplicaCoordinator`
//! directly: `LocalMutationStore` is defined in *this* crate. Coercing
//! `Arc<ReplicaCoordinator>` straight to `Arc<dyn LocalMutationStore>`
//! from inside this crate's own `#[cfg(test)]` code does not compile --
//! rustc reports "there are multiple different versions of crate
//! `yadorilink_local_capture` in the dependency graph". This crate's own
//! `--lib` test target is a SEPARATE compilation from the plain library
//! artifact `yadorilink-daemon` (a dev dependency here) links against for
//! its own `impl LocalMutationStore for ReplicaCoordinator`
//! (`yadorilink-daemon/src/replica_coordinator/ local_mutation.rs`) -- so
//! that impl and this crate's own test code disagree about which
//! `LocalMutationStore` trait (from which compilation) they mean, even
//! though the source is identical. `TestReplica` sidesteps the problem: it
//! is a type local to *this* crate's own compilation (test or not), so
//! `impl LocalMutationStore for TestReplica` is an ordinary,
//! single-compilation-unit impl with no cross-crate identity mismatch. It
//! `Deref`s to `ReplicaCoordinator` for every accessor this crate's tests
//! call directly (`link_repository()`, `file_index_repository()`,
//! `sqlite()`, etc. -- all real `pub fn`s on `ReplicaCoordinator`,
//! callable across the crate boundary with no trait-identity issue since
//! they return concrete `yadorilink-sync-sqlite` types, not a
//! `yadorilink-local-capture` trait object), and its `LocalMutationStore`
//! impl body is a verbatim copy of `ReplicaCoordinator`'s own
//! (`yadorilink-daemon/src/replica_coordinator/ local_mutation.rs`),
//! delegating to those same accessors.
//! `local_change_auth_provider`/`local_emission_auth` are NOT reached via
//! `ReplicaCoordinator`: that pair is `pub(crate)` to `yadorilink-daemon`
//! (not visible here), so `TestReplica` keeps its own copy of the same
//! trivial "call the configured provider, or fall back to
//! `ChangeAuth::PLACEHOLDER`" logic, backed by its own field. Its own
//! `set_local_change_auth_provider` inherent method shadows
//! `ReplicaCoordinator`'s (Rust always prefers an inherent method over a
//! `Deref` target's), so `state.set_local_change_auth_provider(..)` in
//! this crate's tests configures *this* copy, which is what
//! `TestReplica`'s own `LocalMutationStore::upsert_file_emitting_change`/
//! `upsert_files_batch_emitting_change`/`mark_deleted_emitting_change`
//! actually consult.

use std::sync::{Arc, Mutex};

use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::ids::DeltaHash;
use yadorilink_replica_domain::local_op::PolicyUnavailable;
use yadorilink_replica_domain::session_state::{
    DirtyPath, LocalFileMetaColumns, MaterializationState, PreparedLocalMutation,
};
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sync_sqlite::dag_store::LocalAuthorKey;
use yadorilink_sync_sqlite::SyncSqliteError;

use crate::ports::LocalMutationStore;

// SEAM-LOCAL, as the daemon's port impl has it: the authoring bodies below
// route through the same seam module, so this fixture follows the switch
// with the production impl.
use yadorilink_daemon::replica_coordinator::local_commit;

type LocalChangeAuthProvider =
    dyn Fn(&str) -> Result<(), PolicyUnavailable> + Send + Sync + 'static;

/// The tip of every author's delta chain: the group's causal frontier, one
/// entry per author that has written.
pub(crate) fn native_group_heads(state: &ReplicaCoordinator, group_id: &str) -> Vec<DeltaHash> {
    let group = yadorilink_replica_domain::ids::FolderGroupId(group_id.to_owned());
    state
        .database()
        .read::<_, SyncSqliteError>(|conn| {
            yadorilink_sync_sqlite::native_store::load_frontier(conn, &group)
        })
        .unwrap()
        .values()
        .map(|entry| entry.tip)
        .collect()
}

/// Every native delta in the group, by author and sequence.
pub(crate) fn native_deltas(
    state: &ReplicaCoordinator,
    group_id: &str,
) -> Vec<yadorilink_replica_domain::signed_delta::NativeDelta> {
    let bodies: Vec<Vec<u8>> = state
        .database()
        .read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT encoded_delta FROM native_delta_bodies WHERE group_id = ?1 \
                 ORDER BY author, incarnation, seq",
            )?;
            let rows = stmt.query_map([group_id], |row| row.get::<_, Vec<u8>>(0))?;
            let bodies = rows.collect::<Result<Vec<_>, _>>()?;
            Ok(bodies)
        })
        .unwrap();
    bodies
        .iter()
        .map(|body| {
            yadorilink_replica_domain::signed_delta::NativeDelta::from_wire_bytes(body).unwrap()
        })
        .collect()
}

/// The provenance of every live native head at `path`.
pub(crate) fn native_path_head_provenances(
    state: &ReplicaCoordinator,
    group_id: &str,
    path: &str,
) -> Vec<[u8; 32]> {
    state
        .database()
        .read::<_, SyncSqliteError>(|conn| {
            yadorilink_sync_sqlite::native_store::native_heads_at(
                conn,
                &yadorilink_replica_domain::ids::FolderGroupId(group_id.to_owned()),
                &yadorilink_replica_domain::ids::SyncPath(path.to_owned()),
            )
        })
        .unwrap()
        .into_iter()
        .map(|head| head.payload.provenance.0)
        .collect()
}

pub(crate) struct TestReplica {
    inner: Arc<ReplicaCoordinator>,
    local_change_auth_provider: Mutex<Option<Arc<LocalChangeAuthProvider>>>,
    /// How many paths `record_dirty_paths_batch` has journaled -- every
    /// path a flush (or a dirty-journal re-drive) takes up is journaled
    /// there first, so a test can count re-processed paths.
    journaled_dirty_batch_entries: std::sync::atomic::AtomicUsize,
    /// How many full index records `list_files_with_kind` has handed out: the
    /// decoded rows (block lists included) a reconcile pass pulled in.
    full_rows_listed: std::sync::atomic::AtomicUsize,
    /// `inspect_windows_placeholder` is a live `CfGetPlaceholderInfo`
    /// call in production (`yadorilink-daemon::placeholder_inspect_windows`,
    /// Windows-only) -- nothing this crate's own `#[cfg(test)]` code can
    /// exercise against a real placeholder, on any platform. Configurable
    /// via `set_windows_placeholder_inspect_result` so a test can pin
    /// exactly the verdict `local_change.rs`'s Windows dirty-detection
    /// branch should see; defaults to `Unknown`, matching this whole
    /// mechanism's own fail-closed contract for a scenario nothing has set
    /// up an expectation for.
    windows_placeholder_inspect_result: Mutex<crate::ports::PlaceholderStatus>,
}

impl TestReplica {
    pub(crate) fn open_in_memory() -> Result<Self, yadorilink_sqlite_runtime::DatabaseError> {
        Ok(Self {
            inner: Arc::new(ReplicaCoordinator::open_in_memory()?),
            local_change_auth_provider: Mutex::new(None),
            journaled_dirty_batch_entries: std::sync::atomic::AtomicUsize::new(0),
            full_rows_listed: std::sync::atomic::AtomicUsize::new(0),
            windows_placeholder_inspect_result: Mutex::new(
                crate::ports::PlaceholderStatus::Unknown,
            ),
        })
    }

    /// A replica whose index lives in a file under `dir`, for tests whose subject is
    /// what survives in the stored index rather than in memory.
    pub(crate) fn open_file_backed(
        dir: &std::path::Path,
    ) -> Result<Self, yadorilink_sqlite_runtime::DatabaseError> {
        Ok(Self {
            inner: Arc::new(ReplicaCoordinator::open(dir.join("index.db"))?),
            local_change_auth_provider: Mutex::new(None),
            journaled_dirty_batch_entries: std::sync::atomic::AtomicUsize::new(0),
            full_rows_listed: std::sync::atomic::AtomicUsize::new(0),
            windows_placeholder_inspect_result: Mutex::new(
                crate::ports::PlaceholderStatus::Unknown,
            ),
        })
    }

    /// Configures the verdict `LocalMutationStore::inspect_windows_placeholder`
    /// returns for every subsequent call on this `TestReplica`, regardless
    /// of `path`/`expected_generation` -- coarse (not per-path), matching
    /// this fixture's one-scenario-per-test usage. Its only caller
    /// (`local_change.rs`'s `cfapi_placeholder_untouched_windows_tests`)
    /// is itself `#[cfg(all(test, windows))]`, so this has no caller at
    /// all on a non-Windows build -- not dead code, just untriggered on
    /// this platform.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn set_windows_placeholder_inspect_result(
        &self,
        result: crate::ports::PlaceholderStatus,
    ) {
        *self.windows_placeholder_inspect_result.lock().unwrap_or_else(|p| p.into_inner()) = result;
    }

    /// The replica's author handle for `author`'s device and
    /// key (minted on first use, as the daemon opens it): the tests build
    /// their handles `without_incarnation`, which authoring
    /// refuses.
    fn author(&self, author: &LocalAuthorKey) -> Result<Arc<LocalAuthorKey>, SyncSqliteError> {
        self.inner
            .open_local_author(author.device_id(), author.signing_key().clone())
            .map_err(|error| SyncSqliteError::CorruptState(error.to_string()))
    }

    /// The wrapped `ReplicaCoordinator` directly -- for callers that
    /// take a concrete `&ReplicaCoordinator`.
    pub(crate) fn coordinator(&self) -> &ReplicaCoordinator {
        &self.inner
    }

    pub(crate) fn set_local_change_auth_provider(&self, provider: Arc<LocalChangeAuthProvider>) {
        *self.local_change_auth_provider.lock().unwrap_or_else(|p| p.into_inner()) = Some(provider);
    }

    /// Full index records listed so far (see the field).
    pub(crate) fn full_rows_listed(&self) -> usize {
        self.full_rows_listed.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Paths journaled through `record_dirty_paths_batch` so far.
    pub(crate) fn journaled_dirty_batch_entries(&self) -> usize {
        self.journaled_dirty_batch_entries.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn local_emission_auth(&self, group_id: &str) -> Result<(), PolicyUnavailable> {
        match self.local_change_auth_provider.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            Some(provider) => provider(group_id),
            None => Ok(()),
        }
    }
}

impl std::ops::Deref for TestReplica {
    type Target = ReplicaCoordinator;
    fn deref(&self) -> &ReplicaCoordinator {
        &self.inner
    }
}

impl LocalMutationStore for TestReplica {
    fn path_lock(&self, group_id: &str, path: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.path_lock_registry().path_lock(group_id, path)
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
    ) -> Result<std::collections::HashMap<String, MaterializationState>, SyncSqliteError> {
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
        std::collections::HashMap<String, yadorilink_sync_sqlite::RecordedPlaceholderGeneration>,
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

    fn inspect_windows_placeholder(
        &self,
        path: &std::path::Path,
        expected_generation: u64,
    ) -> crate::ports::PlaceholderStatus {
        let _ = (path, expected_generation);
        *self.windows_placeholder_inspect_result.lock().unwrap_or_else(|p| p.into_inner())
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

    fn group_frozen(&self, group_id: &str) -> Result<bool, SyncSqliteError> {
        self.held_path_repository().group_frozen(group_id)
    }

    fn hold_unauthorable_local_edit(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), SyncSqliteError> {
        self.held_path_repository().hold_unauthorable_local_edit(group_id, path)
    }

    fn wake_install_reconciliation(&self) {}

    fn has_unsettled_projection_obligation(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        // Kept a verbatim copy of `ReplicaCoordinator`'s own impl.
        Ok(self.sqlite().dag_lookup_projection_obligation(group_id, path)?.is_some_and(
            |obligation| {
                obligation.origin
                    == yadorilink_sync_sqlite::projection_obligations::ObligationOrigin::Remote
            },
        ))
    }

    fn is_held(&self, group_id: &str, path: &str) -> Result<bool, SyncSqliteError> {
        // Kept a verbatim copy of `ReplicaCoordinator`'s own impl.
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
        yadorilink_fs_platform::fs_capabilities::probe_birth_time_granularity(sync_root)
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
            yadorilink_fs_platform::fs_capabilities::probe_birth_time_granularity(sync_root),
        )
    }

    fn commit_local_mutations_batch(
        &self,
        group_id: &str,
        mutations: &[PreparedLocalMutation],
        evidence: &[Option<yadorilink_sync_sqlite::file_index::LocalCaptureActualStateEvidence>],
        origin_device_id: &str,
        emission: crate::ports::LocalChangeEmission<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.local_emission_auth(group_id).map_err(SyncSqliteError::from)?;
        local_commit::commit_local_mutations_batch(
            self.file_index_repository(),
            group_id,
            mutations,
            evidence,
            origin_device_id,
            &*self.author(emission.author)?,
            None,
            emission.permit,
        )
    }

    fn commit_captured_directory(
        &self,
        group_id: &str,
        directory: &crate::ports::CapturedDirectory,
        origin_device_id: &str,
        emitter: Option<&LocalAuthorKey>,
        permit: &RootCommitPermit,
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
        self.local_emission_auth(group_id).map_err(SyncSqliteError::from)?;
        local_commit::commit_captured_directory(
            self.file_index_repository(),
            group_id,
            &directory.record,
            &directory.op,
            &directory.version,
            &directory.meta,
            directory.identity.as_ref(),
            origin_device_id,
            &*self.author(emitter)?,
            None,
            permit,
        )
    }

    fn commit_directory_removal(
        &self,
        group_id: &str,
        root: &str,
        tombstones: &[PreparedLocalMutation],
        origin_device_id: &str,
        observed_at_unix_nanos: i64,
        emitter: Option<&LocalAuthorKey>,
        permit: &RootCommitPermit,
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
        self.local_emission_auth(group_id).map_err(SyncSqliteError::from)?;
        local_commit::commit_directory_removal(
            self.file_index_repository(),
            group_id,
            root,
            tombstones,
            origin_device_id,
            &*self.author(emitter)?,
            None,
            permit,
        )
    }

    fn commit_directory_rename(
        &self,
        group_id: &str,
        from: &str,
        to: &str,
        mutations: &[PreparedLocalMutation],
        evidence: &[Option<yadorilink_sync_sqlite::file_index::LocalCaptureActualStateEvidence>],
        origin_device_id: &str,
        emission: crate::ports::LocalChangeEmission<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.local_emission_auth(group_id).map_err(SyncSqliteError::from)?;
        local_commit::commit_directory_rename(
            self.file_index_repository(),
            group_id,
            from,
            to,
            mutations,
            evidence,
            origin_device_id,
            &*self.author(emission.author)?,
            None,
            emission.permit,
        )
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
        permit: &RootCommitPermit,
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
        permit: &RootCommitPermit,
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
        permit: &RootCommitPermit,
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
        permit: &RootCommitPermit,
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
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        self.journaled_dirty_batch_entries
            .fetch_add(entries.len(), std::sync::atomic::Ordering::SeqCst);
        self.dirty_path_repository().record_dirty_paths_batch(group_id, entries, permit)
    }

    fn mark_dirty_path_attempt(
        &self,
        group_id: &str,
        path: &str,
        last_error: &str,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        self.dirty_path_repository().mark_dirty_path_attempt(group_id, path, last_error, permit)
    }

    fn clear_dirty_paths_conditional_batch(
        &self,
        group_id: &str,
        entries: &[(String, i64)],
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        self.dirty_path_repository().clear_dirty_paths_conditional_batch(group_id, entries, permit)
    }

    fn local_emission_available(&self, group_id: &str) -> bool {
        self.local_emission_auth(group_id).is_ok()
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
        let rows = self.file_index_repository().list_files_with_kind(group_id)?;
        self.full_rows_listed.fetch_add(rows.len(), std::sync::atomic::Ordering::SeqCst);
        Ok(rows)
    }

    fn list_indexed_paths_with_kind(
        &self,
        group_id: &str,
    ) -> Result<Vec<(String, yadorilink_replica_domain::file::RecordKind)>, SyncSqliteError> {
        self.file_index_repository().list_indexed_paths_with_kind(group_id)
    }

    fn verify_root(
        &self,
        root: &std::path::Path,
        group_id: &str,
    ) -> Result<yadorilink_root_authority::root_identity::VerifiedRoot, SyncSqliteError> {
        yadorilink_root_authority::root_identity::VerifiedRoot::verify(
            root,
            group_id,
            self.inner.as_ref(),
        )
        .map_err(SyncSqliteError::from)
    }

    fn open_root(
        &self,
        root: &std::path::Path,
        group_id: &str,
    ) -> Result<yadorilink_root_authority::root_identity::VerifiedRoot, SyncSqliteError> {
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            root,
            group_id,
            self.inner.as_ref(),
        )
        .map_err(SyncSqliteError::from)
    }
}

#[cfg(test)]
mod structural_origin_port_tests {
    use super::*;
    use yadorilink_fs_platform::fs_identity::{FileIdentity, TimestampGranularity};
    use yadorilink_sync_sqlite::structural_origin::{
        StructuralDirectoryOrigin, StructuralOriginCompletion, StructuralOriginStatus,
    };

    /// Capture reads the ledger the materializer writes: an intent is
    /// visible while the `mkdir` is in flight, and afterwards the
    /// directory reads as structural by its identity.
    #[test]
    fn capture_sees_the_structural_origin_the_materializer_recorded() {
        let replica = TestReplica::open_in_memory().unwrap();
        let store: &dyn LocalMutationStore = &replica;
        assert_eq!(
            store.structural_directory_origin("g", "a").unwrap(),
            StructuralDirectoryOrigin::None
        );

        replica.sqlite().dag_record_structural_intent("g", "a", 1).unwrap();
        assert_eq!(
            store.structural_directory_origin("g", "a").unwrap(),
            StructuralDirectoryOrigin::IntentPending
        );

        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("a");
        std::fs::create_dir(&dir).unwrap();
        let identity = FileIdentity::observe_path(&dir).unwrap();
        assert_eq!(
            replica.sqlite().dag_complete_structural_origin("g", "a", &identity, 2).unwrap(),
            StructuralOriginCompletion::Recorded
        );
        assert_eq!(
            store
                .structural_directory_origin("g", "a")
                .unwrap()
                .status(Some(&identity), TimestampGranularity::Fine),
            StructuralOriginStatus::Structural
        );
    }
}
