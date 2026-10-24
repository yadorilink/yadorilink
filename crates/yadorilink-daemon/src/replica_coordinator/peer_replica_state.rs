//! The replica-state operations the local convergence executor drives.
//!
//! Most methods here are thin delegates onto `ReplicaCoordinator`'s own
//! repository accessors (`file_index_repository()`,
//! `materialization_state_repository()`,
//! `sqlite()`, etc.), translating each accessor's own error type into
//! `PeerSessionError` via `SyncError`. `open_materialization_intent_guard`
//! is the one method whose body is more than a straight accessor call: it
//! constructs and boxes a
//! [`crate::materialization_intent::MaterializationIntentGuard`].

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use crate::sync_error::SyncError;
use yadorilink_peer_session::ports::{BlockServeAuthorization, CurrentRowSnapshot};
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::file::{FileRecord, FileVersion, RecordKind};
use yadorilink_replica_domain::session_state::{
    CurrentVersionRecord, HeldState, LinkGate, MaterializationPolicy, MaterializationState,
};
use yadorilink_root_authority::root_commit::RootCommitPermit;

use yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind;

use super::ReplicaCoordinator;

/// The birth-time granularity of `sync_root`'s volume, from the one per-volume cache in
/// `yadorilink-fs-platform` (a measurement that could not be made is never kept there).
pub(in crate::replica_coordinator) fn cached_birth_time_granularity(
    sync_root: &Path,
) -> yadorilink_fs_platform::fs_identity::TimestampGranularity {
    yadorilink_fs_platform::fs_capabilities::cached_probe_birth_time_granularity(sync_root)
}

impl ReplicaCoordinator {
    /// Acquires the per-`(group_id, path)` lock serializing this peer
    /// reconciliation against a concurrent local save of the same path.
    pub fn path_lock(&self, group_id: &str, path: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.path_lock_registry().path_lock(group_id, path)
    }

    /// Whether `group_id`'s folder link currently accepts peer-applied
    /// writes at all (paused/orphaned/live) — checked before reconciling any
    /// file for the group.
    pub fn link_gate_for_group(&self, group_id: &str) -> Result<LinkGate, PeerSessionError> {
        self.link_repository()
            .link_gate_for_group(group_id)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// [`Self::link_gate_for_group`] for a caller that works on a directory: `None` for a provider
    /// root, which has no directory (its content lives with the OS, so there is nothing to
    /// project, repair or retire into). A caller treats `None` as "nothing to do", never as an
    /// error.
    pub fn directory_link_gate_for_group(
        &self,
        group_id: &str,
    ) -> Result<Option<LinkGate>, PeerSessionError> {
        match self.link_repository().link_gate_for_group(group_id) {
            Ok(gate) => Ok(Some(gate)),
            Err(yadorilink_sync_sqlite::SyncSqliteError::NotFilesystemRoot(_)) => Ok(None),
            Err(error) => Err(PeerSessionError::from(SyncError::from(error))),
        }
    }

    /// The group's configured on-demand-sync materialization policy, used to
    /// decide whether an incoming file should be hydrated eagerly or left a
    /// placeholder.
    pub fn materialization_policy_for_group(
        &self,
        group_id: &str,
    ) -> Result<Option<MaterializationPolicy>, PeerSessionError> {
        // A provider root never materializes into a directory, eager or not: the OS owns the
        // local copy. For every decision made here its policy is OnDemand; whether an Eager
        // root also asks the OS to download is the Eager driver's business, not this one's.
        // A declaration that cannot be read counts as a provider root (fail closed).
        if !matches!(
            self.provider_repository().declaration_for_group(group_id),
            Ok(yadorilink_sync_sqlite::provider::ProviderDeclaration::Plain)
        ) {
            return Ok(Some(MaterializationPolicy::OnDemand));
        }
        self.link_repository()
            .materialization_policy_for_group(group_id)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// Whether this device has opted a group into materializing peer
    /// symlinks as real Windows symlinks (vs. placeholder files).
    pub fn windows_symlink_opt_in_for_group(
        &self,
        group_id: &str,
    ) -> Result<bool, PeerSessionError> {
        self.link_repository()
            .windows_symlink_opt_in_for_group(group_id)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// The current row for `(group_id, path)`, read before deciding whether
    /// an incoming peer version supersedes it.
    pub fn get_file(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<FileRecord>, PeerSessionError> {
        self.file_index_repository()
            .get_file(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// Batched form of `get_file` for reconciling many incoming paths from
    /// one peer message without one query per path.
    pub fn get_files_by_paths(
        &self,
        group_id: &str,
        paths: &[String],
    ) -> Result<HashMap<String, FileRecord>, PeerSessionError> {
        self.file_index_repository()
            .get_files_by_paths(group_id, paths)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// Whether `(group_id, path)` has a genuine current row this device
    /// actually indexed, as opposed to no row or only the bootstrap
    /// scaffold — distinguishes "never seen this path" from "seen it, it's
    /// a tombstone" while applying incoming wire metadata.
    pub fn has_real_current_row(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, PeerSessionError> {
        self.file_index_repository()
            .has_real_current_row(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// Drops the bootstrap scaffold of `path`, if that is all the path has as its current row.
    pub fn retire_bootstrap_scaffold(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<bool, PeerSessionError> {
        self.file_index_repository()
            .retire_bootstrap_scaffold(group_id, path, permit)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// The payload producer for every caller that has to read its
    /// payload out of this device's own index: every
    /// materialization-relevant column of `path`'s current row, from ONE
    /// statement -- see [`CurrentRowSnapshot`] for why such a caller may
    /// not assemble this out of the single-column accessors below.
    /// `None` when the path has no current row at all.
    pub fn current_row_snapshot(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<CurrentRowSnapshot>, PeerSessionError> {
        let row = self
            .file_index_repository()
            .canonical_current_row(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)?;
        // After the row is captured, before it is returned: the caller
        // leaves holding this incarnation while the database has already
        // moved to the next one. A producer that reads once is therefore
        // unaffected, and one that reads again gets the newer row and
        // stitches -- which is the difference under test. Firing before
        // the read would simply hand the caller the newer row, coherent
        // and proving nothing.
        #[cfg(test)]
        self.test_observers.fire_armed_supersession(group_id, path);
        Ok(row.map(|row| {
            let snapshot = row.snapshot;
            CurrentRowSnapshot {
                path: path.to_string(),
                record: FileRecord {
                    path: path.to_string(),
                    size: snapshot.size,
                    mtime_unix_nanos: snapshot.mtime_unix_nanos,
                    blocks: snapshot.blocks,
                    deleted: snapshot.deleted,
                },
                record_kind: snapshot.record_kind,
                symlink_target: snapshot.symlink_target,
                symlink_out_of_root: row.symlink_out_of_root,
                unix_mode: snapshot.unix_mode,
                xattrs: snapshot.xattrs,
                origin_device_id: row.origin_device_id,
                materialization_state: row.materialization_state,
            }
        }))
    }

    pub fn get_record_kind(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<RecordKind>, PeerSessionError> {
        self.file_index_repository()
            .get_record_kind(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    pub fn get_symlink_target(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<Vec<u8>>, PeerSessionError> {
        self.file_index_repository()
            .get_symlink_target(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    pub fn get_symlink_out_of_root(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, PeerSessionError> {
        self.file_index_repository()
            .get_symlink_out_of_root(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    pub fn get_unix_mode(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<u32>, PeerSessionError> {
        self.file_index_repository()
            .get_unix_mode(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// The replicated extended attributes currently recorded for `path`
    /// -- sorted by name, already filtered to the capture-side
    /// allow-list. See `FileMeta::xattrs`'s own doc comment.
    pub fn get_xattrs(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Vec<(String, Vec<u8>)>, PeerSessionError> {
        self.file_index_repository()
            .get_xattrs(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// The device that produced `path`'s current content, consulted when
    /// deciding whether an incoming record actually changes anything.
    pub fn get_origin_device_id(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<String>, PeerSessionError> {
        self.file_index_repository()
            .get_origin_device_id(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// The native head the current row at `path` shows, if any.
    pub fn row_authoring(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<yadorilink_replica_domain::native_plan::NativeRowIdentity>, PeerSessionError>
    {
        self.file_index_repository()
            .row_authoring(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    pub fn get_materialization_state(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<MaterializationState>, PeerSessionError> {
        self.materialization_state_repository()
            .get_materialization_state(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    pub fn set_materialization_state(
        &self,
        group_id: &str,
        path: &str,
        state: MaterializationState,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError> {
        self.materialization_state_repository()
            .set_materialization_state(group_id, path, state, permit)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    pub fn clear_held(&self, group_id: &str, path: &str) -> Result<(), PeerSessionError> {
        self.materialization_state_repository()
            .clear_held(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    pub(in crate::replica_coordinator) fn set_held(
        &self,
        group_id: &str,
        path: &str,
        reason: &str,
        since_unix_nanos: i64,
    ) -> Result<(), PeerSessionError> {
        self.materialization_state_repository()
            .set_held(group_id, path, reason, since_unix_nanos)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    pub fn has_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, PeerSessionError> {
        self.materialization_intent_repository()
            .has_materialization_intent(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// Paths whose index row already admits it has no bytes — reconcile's
    /// on-demand-sync repair audit re-drives exactly these through an
    /// ordinary peer fetch.
    pub fn list_materialization_repair_candidates(
        &self,
        group_id: &str,
    ) -> Result<Vec<String>, PeerSessionError> {
        self.materialization_state_repository()
            .list_materialization_repair_candidates(group_id)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// Wakes the Convergence Engine's scheduler loop promptly after
    /// enqueuing a pending job, instead of waiting for its fallback poll.
    pub fn notify_materialization_wake(&self) {
        self.materialization_wake().notify_materialization_wake()
    }

    pub fn is_path_dirty(&self, group_id: &str, path: &str) -> Result<bool, PeerSessionError> {
        self.dirty_path_repository()
            .is_path_dirty(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// Commits a peer-originated version onto the index, recording the
    /// sending peer as origin. The plain (non-authoring) form, used when no
    /// verified native delta accompanies the write.
    pub fn upsert_file_with_origin(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError> {
        self.file_index_repository()
            .upsert_file_with_origin(group_id, record, origin_device_id, permit)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)?;
        // After the row has landed: the supersession is inside this
        // materialization's own window, not before it started.
        #[cfg(test)]
        self.test_observers.fire_armed_upsert_supersession(group_id, &record.path);
        Ok(())
    }

    /// [`Self::upsert_file_with_origin`] plus the identity the row is
    /// produced under: the NativeState head it shows, or none. `meta` is the
    /// version's metadata columns, written onto the row this call inserts
    /// and never onto the row it supersedes; with none they are carried
    /// forward.
    pub fn upsert_file_with_origin_and_authoring(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        authoring: Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity>,
        meta: Option<&yadorilink_replica_domain::session_state::LocalFileMetaColumns>,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError> {
        self.file_index_repository()
            .upsert_file_with_origin_and_authoring(
                group_id,
                record,
                origin_device_id,
                authoring,
                meta,
                permit,
            )
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)?;
        #[cfg(test)]
        self.test_observers.fire_armed_upsert_supersession(group_id, &record.path);
        Ok(())
    }

    /// Erases `path`'s index row entirely -- not a tombstone, nothing
    /// published as a replicated fact. For a path this device's index
    /// tracks with NO admitted delta ever having touched it (a pure local
    /// artifact, e.g. an ephemeral conflict-copy materialized before a
    /// durable carrier existed for it): the schema's `files_require_
    /// authoring_identity_on_*` triggers require every 'current' row to
    /// carry a verified native authoring identity once the group has ANY
    /// native history, so upserting a tombstone here (which `materialize_
    /// tombstone` would, via `upsert_file_with_origin`) is rejected outright
    /// -- there is no head to attribute it to, and there never was one.
    /// Erasing the row instead of asserting a tombstone fact is correct
    /// specifically because nothing about this path was ever a replicated
    /// fact to begin with. See `yadorilink_sync_sqlite::file_index::
    /// FileIndexRepository::remove_file`'s own doc comment (its existing
    /// use is the ignore sweep) for the identical "erasure,
    /// not a tombstone" semantics reused here.
    pub fn erase_local_only_file(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError> {
        self.file_index_repository()
            .remove_file(group_id, path, permit)
            .map(|_removed| ())
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// Batched form of [`group_has_block_provenance`](Self::group_has_block_provenance)
    /// — one query for many hashes instead of one query per hash. Returns
    /// the SUBSET of `block_hashes` that have recorded provenance for
    /// `group_id`; a hash absent from the returned set has none (same
    /// meaning as that hash's own single-hash call returning `false`).
    /// `ensure_blocks_present`'s dedup path uses this instead of looping
    /// the single-hash form once per block.
    pub fn group_has_block_provenance_batch(
        &self,
        group_id: &str,
        block_hashes: &[Vec<u8>],
    ) -> Result<std::collections::HashSet<Vec<u8>>, PeerSessionError> {
        self.sqlite()
            .dag_group_has_block_provenance_batch(group_id, block_hashes)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// Records blocks this device actually obtained through the group during
    /// reconciliation (never called for peer-claimed-only metadata).
    pub fn record_group_block_provenance(
        &self,
        group_id: &str,
        block_hashes: &[Vec<u8>],
    ) -> Result<(), PeerSessionError> {
        #[cfg(test)]
        if self
            .test_observers
            .record_group_block_provenance_fails
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            // Before the batch is noted, and before the write: the
            // blocks this is about are already durably fetched, and it
            // is recording them that fails.
            return Err(PeerSessionError::CorruptState(
                "injected record_group_block_provenance failure".to_string(),
            ));
        }
        #[cfg(test)]
        self.test_observers.note_provenance_batch(block_hashes);
        self.record_block_provenance(group_id, block_hashes)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// Records that `peer_device_id` EXPLICITLY, definitively refused a
    /// fetch of `path` AT `version_hash` for lack of verified provenance on
    /// that exact version -- deliberately distinct both from a transient
    /// miss (`NotFound`/`TimedOut`/`Busy`) and from any OTHER `Rejected`
    /// reason, neither of which must ever call this. This is the evidence
    /// `DurabilityFacts::known_unobtainable_required_content` needs to
    /// positively confirm no currently-authorized peer can serve the exact
    /// CURRENT version's content, rather than inferring it from
    /// connectivity/timing alone or conflating it with a since-superseded
    /// version's refusals (why this is keyed by `version_hash`, not just
    /// `path`).
    pub fn record_block_fetch_refusal(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &str,
        peer_device_id: &str,
        reason: &str,
        refused_at_unix_nanos: i64,
    ) -> Result<(), PeerSessionError> {
        self.materialization_state_repository()
            .record_block_fetch_refusal(
                group_id,
                path,
                version_hash,
                peer_device_id,
                reason,
                refused_at_unix_nanos,
            )
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// Deletes any refusal previously recorded for `peer_device_id` against
    /// `path` at `version_hash` -- called on a SUCCESSFUL fetch, so a peer
    /// that once refused a version but has since obtained it can never be
    /// read as still refusing it.
    pub fn clear_block_fetch_refusal(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &str,
        peer_device_id: &str,
    ) -> Result<(), PeerSessionError> {
        #[cfg(test)]
        self.test_observers.note_clear_block_fetch_refusal(
            group_id,
            path,
            version_hash,
            peer_device_id,
        );
        self.materialization_state_repository()
            .clear_block_fetch_refusal(group_id, path, version_hash, peer_device_id)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// The group's authenticated author frontier: where each author's chain
    /// stands. It moves exactly when a causal fact is admitted, never when a
    /// physical placement changes.
    pub fn native_author_frontier(
        &self,
        group_id: &str,
    ) -> Result<yadorilink_replica_domain::native_frontier::NativeAuthorFrontier, PeerSessionError>
    {
        self.database()
            .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                yadorilink_sync_sqlite::native_store::load_frontier(
                    conn,
                    &yadorilink_replica_domain::ids::FolderGroupId(group_id.to_owned()),
                )
            })
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// Paths that hold a live native head on their own account: an entry some
    /// delta authored at that very name, as opposed to a name only a placement
    /// gives out.
    pub fn native_head_paths(&self, group_id: &str) -> Result<HashSet<String>, PeerSessionError> {
        self.database()
            .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                let mut stmt =
                    conn.prepare("SELECT DISTINCT path FROM native_heads WHERE group_id = ?1")?;
                let paths = stmt.query_map([group_id], |row| row.get::<_, String>(0))?;
                Ok(paths.collect::<Result<HashSet<_>, _>>()?)
            })
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    pub fn dag_get_file_version(
        &self,
        group_id: &str,
        hash: &yadorilink_replica_domain::ids::VersionHash,
    ) -> Result<Option<FileVersion>, PeerSessionError> {
        self.sqlite()
            .dag_get_file_version(group_id, hash)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// Whether `head` is the head local capture last authored for `path`:
    /// authored by reading this device's own disk, not in order to change it.
    /// See `yadorilink_sync_sqlite::local_capture_provenance`.
    pub fn is_local_capture_head(
        &self,
        group_id: &str,
        path: &str,
        head: &crate::local_convergence::types::Head,
    ) -> Result<bool, PeerSessionError> {
        self.database()
            .read(|conn| {
                yadorilink_sync_sqlite::local_capture_provenance::is_native_local_capture(
                    conn,
                    group_id,
                    path,
                    &head.identity,
                )
            })
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// Durably bumps `(group_id, path)`'s
    /// filesystem-side mutation fence (independent of the native-side
    /// `invalidation_generation`) and returns the new value. A single
    /// atomic statement, never a read followed by a write, so two
    /// concurrent callers always receive two distinct values -- this is a
    /// staleness detector, never a mutual-exclusion primitive; callers MUST
    /// still hold this path's own lock for the mutation itself.
    ///
    /// Call this from inside the SAME path-lock critical section as the
    /// physical mutation it fences, before the first mutating syscall, and
    /// only once the decision to mutate has actually been made.
    /// `mutation_kind` is a short diagnostic label (e.g. `"materialize"`,
    /// `"retire"`); it plays no role in any correctness check.
    pub fn dag_bump_mutation_fence(
        &self,
        group_id: &str,
        path: &str,
        mutation_kind: &str,
    ) -> Result<i64, PeerSessionError> {
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
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// Reads `(group_id, path)`'s current mutation-fence value WITHOUT
    /// bumping it (creating it at generation 0 first if absent), for a
    /// content-identical verification that changes no bytes (decision 3d:
    /// "verification snapshots, it does not bump"). The observation of
    /// disk and this call MUST happen as one atomic step under the path's
    /// lock.
    pub fn dag_snapshot_mutation_fence(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<i64, PeerSessionError> {
        self.database
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                yadorilink_sync_sqlite::materialized_generation::snapshot_mutation_fence(
                    tx, group_id, path,
                )
            })
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// CAS-publish for a real physical mutation or a content-identical
    /// verification's evidence (decision 3e): writes the actual-state
    /// generation for `(group_id, path)` only if its CURRENT mutation-fence
    /// value still equals `expected_mutation_generation` -- the epoch the
    /// caller captured via [`Self::dag_bump_mutation_fence`]/
    /// [`Self::dag_snapshot_mutation_fence`] before it acted. Returns
    /// `Ok(false)` (not an error) when the CAS fails -- some other mutator
    /// has already bumped the fence since, so this attempt's evidence is
    /// stale and must not be published as current.
    pub fn dag_publish_materialized_generation_if_fence_current(
        &self,
        group_id: &str,
        path: &str,
        state: yadorilink_peer_session::ports::ExactActualState,
        expected_mutation_generation: i64,
        permit: &RootCommitPermit,
    ) -> Result<bool, PeerSessionError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        let (sync_kind, version, filesystem_identity) = match state {
            yadorilink_peer_session::ports::ExactActualState::Object {
                kind,
                version,
                identity,
            } => {
                let sync_kind = match kind {
                    RecordKind::File => MaterializedObjectKind::RegularFile,
                    RecordKind::Directory => MaterializedObjectKind::Directory,
                    RecordKind::Symlink => MaterializedObjectKind::Symlink,
                };
                (sync_kind, Some(version), *identity)
            }
            yadorilink_peer_session::ports::ExactActualState::Absent => {
                (MaterializedObjectKind::Absent, None, None)
            }
            yadorilink_peer_session::ports::ExactActualState::StructuralDirectory { identity } => {
                (MaterializedObjectKind::StructuralDirectory, None, *identity)
            }
        };
        let published = self
            .database
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                // The fence alone is not enough for a proof that names a
                // version. A native-side supersession moves the row's version
                // without touching the mutation fence -- that is stated
                // outright on `ExpectedAuthoring::expected_version`, and it
                // is why every lane that captures its version in an earlier
                // transaction than its commit passes that guard. This entry
                // point had no equivalent, so evidence built against one
                // version could be published verbatim after the row had left
                // it, leaving a durable proof naming a version the row no
                // longer has.
                //
                // Checked here, inside the publishing transaction, against
                // the one canonical read. A mismatch is `Ok(None)`, not an
                // error: it is the same outcome as losing the fence CAS, and
                // every caller already treats that as "re-resolve later"
                // rather than as a failure.
                //
                // The kind is checked with it. `ExactActualState::Object`
                // carries `kind` and `version` as independent fields, so
                // a version-only check would accept
                // `{kind: Symlink, version: <a File's V1>}` and write a
                // durable proof describing an object no `FileVersion`
                // could ever be. Every current producer builds both from
                // one payload, so there is no known route that reaches
                // this -- which is the argument for closing it while that
                // is still true, not for leaving it open.
                let live =
                    yadorilink_sync_sqlite::read_canonical_current_row(tx, group_id, path)?;
                let describes_the_row = match version.as_ref() {
                    Some(version) => live.as_ref().is_some_and(|row| {
                        row.version_hash() == *version
                            && matches!(
                                (row.snapshot.record_kind, sync_kind),
                                (RecordKind::File, MaterializedObjectKind::RegularFile)
                                    | (RecordKind::Directory, MaterializedObjectKind::Directory)
                                    | (RecordKind::Symlink, MaterializedObjectKind::Symlink)
                            )
                    }),
                    // `Absent` names no version, and that is exactly why
                    // it needs checking rather than waving through: with
                    // no version to compare, a version-only guard skipped
                    // it entirely, so a stale `Absent` could be published
                    // over a path a native-side recreation had brought back.
                    // A supersession moves the row without moving the
                    // fence, so the fence CAS sees nothing wrong.
                    //
                    // Exact absence means the row is gone or is a
                    // tombstone. A live, non-deleted row is the claim's
                    // direct contradiction. A structural directory is the
                    // same claim about the row: no entry of the path's own
                    // is held there, only the container its descendants
                    // need.
                    None => live.as_ref().is_none_or(|row| row.snapshot.deleted),
                };
                if !describes_the_row {
                    return Ok(None);
                }
                yadorilink_sync_sqlite::materialized_generation::publish_materialized_generation_if_fence_current(
                    tx,
                    group_id,
                    path,
                    sync_kind,
                    version.as_ref(),
                    filesystem_identity.as_ref(),
                    expected_mutation_generation,
                    now,
                )
                .and_then(|published| {
                    // Inside the publishing transaction, for the same reason
                    // the internal commit does it there: the physical delete
                    // this proof is about ran earlier, under a root that may
                    // since have been swapped. An absence published under a
                    // root this device no longer owns describes a path that
                    // may well exist under the root that replaced it.
                    permit.verify()?;
                    Ok(published)
                })
            })
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)?;
        Ok(published.is_some())
    }

    /// Everything an internal physical mutation proved, committed as one
    /// durable step: the versioned generation published under
    /// `expected_mutation_generation`, the row stamped `Present`, and the
    /// materialization intent cleared.
    ///
    /// For a writer that controls when the mutation happens -- it bumped
    /// the fence to `expected_mutation_generation` before its first
    /// mutating syscall and is now recording what it did. Use this rather
    /// than publishing and stamping separately: the three writes are only
    /// meaningful together, and any subset is a state nothing can read
    /// correctly. See `yadorilink_sync_sqlite::exact_materialized_commit`
    /// for the full reasoning.
    ///
    /// `false` means the commit was refused, so nothing at all was
    /// written -- the intent above all, since it is the only record that a
    /// write was ever in flight. It covers two refusals this `bool` does
    /// not distinguish: the fence had moved past
    /// `expected_mutation_generation`, or `expected_authoring` no longer
    /// held (the row's state or version had been
    /// superseded). Not an error: the caller must re-drive its work either
    /// way.
    ///
    /// Deliberately NOT the external-adoption path, which mints a fresh
    /// epoch of its own. Routing an internal mutator through that advances
    /// the fence past the epoch the caller is about to be judged on, so
    /// the caller's own settlement evidence can never win. That path is
    /// now reachable only from inside the local-capture upserts that admit
    /// an external change in the same transaction, so an internal mutator
    /// can no longer pick it up by mistake.
    ///
    /// `expected_authoring`, when supplied, must also still hold: the row
    /// must be in that state and, when named, derive that version. A writer
    /// whose attempt was bound to one version passes it so the
    /// re-check and the commit are one step -- otherwise a supersession
    /// landing in between would let it stamp `Present` for a version it
    /// never materialized.
    ///
    /// The permit is re-verified inside the commit's own transaction, the
    /// way this operation's two sibling surfaces already do it. A caller
    /// on this lane checks the root before its write, but the write is a
    /// block fetch and a file publish away from this commit -- the widest
    /// such gap of the three -- and an admission-time check cannot close
    /// the unlink-and-recreate window across it (see
    /// `LinkOperation::reverify`). Publishing a proof about bytes under a
    /// root this device no longer owns is exactly what that window costs.
    ///
    /// The causal basis is always derived inside the commit's own
    /// transaction, and is deliberately not a parameter here. Every writer
    /// on this lane reconstructs whatever the path currently resolves to,
    /// so the group's heads at commit time are its honest basis; reading
    /// them at the call site would cost a second round-trip for the same
    /// answer, and accepting them as an argument would let a writer name a
    /// frontier it did not resolve. The lane that genuinely realizes one
    /// specific winner -- the projected-upsert batch finalizer -- names its
    /// own basis by calling the sync-sqlite commit directly.
    pub fn commit_internal_materialized_state_if_fence_current(
        &self,
        group_id: &str,
        path: &str,
        state: yadorilink_peer_session::ports::ExactActualState,
        expected_mutation_generation: i64,
        expected_authoring: Option<yadorilink_peer_session::ports::ExpectedAuthoring<'_>>,
        permit: &RootCommitPermit,
    ) -> Result<bool, PeerSessionError> {
        let guard = expected_authoring.map(|g| {
            yadorilink_sync_sqlite::exact_materialized_commit::ExpectedAuthoring {
                state: g.state,
                expected_version: g.expected_version,
            }
        });
        let exact = match state {
            yadorilink_peer_session::ports::ExactActualState::Object {
                kind,
                version,
                identity,
            } => {
                yadorilink_sync_sqlite::exact_materialized_commit::ExactMaterializedState::Object {
                    kind,
                    version,
                    identity,
                }
            }
            yadorilink_peer_session::ports::ExactActualState::Absent => {
                yadorilink_sync_sqlite::exact_materialized_commit::ExactMaterializedState::Absent
            }
            // This commit stamps the row as holding what it proves; a
            // structural directory is no row's entry.
            yadorilink_peer_session::ports::ExactActualState::StructuralDirectory { .. } => {
                return Err(PeerSessionError::from(SyncError::from(
                    yadorilink_sync_sqlite::SyncSqliteError::InvalidInput(format!(
                        "{group_id}/{path}: a structural directory is committed by publication, \
                         not as a row's materialized state"
                    )),
                )));
            }
        };
        // Through the repository rather than straight at the database, so
        // this commit runs the permit re-verification inside its own
        // transaction -- the same path `MaterializationExecutionPort`'s
        // identically-named method already takes.
        let outcome = self
            .materialization_state_repository()
            .commit_internal_materialized_state_if_fence_current(
                group_id,
                path,
                &exact,
                expected_mutation_generation,
                guard,
                permit,
            )
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)?;
        match outcome {
            yadorilink_sync_sqlite::exact_materialized_commit::InternalMaterializedCommit::Published(_) => Ok(true),
            yadorilink_sync_sqlite::exact_materialized_commit::InternalMaterializedCommit::FenceLost {
                live_mutation_generation,
            } => {
                tracing::warn!(
                    group_id,
                    path,
                    expected_mutation_generation,
                    ?live_mutation_generation,
                    "another mutator advanced this path's fence between its write and this \
                     commit; leaving the materialization intent open so the work is retried \
                     rather than closed unproven"
                );
                Ok(false)
            }
            yadorilink_sync_sqlite::exact_materialized_commit::InternalMaterializedCommit::AuthoringSuperseded => {
                tracing::warn!(
                    group_id,
                    path,
                    "this path was superseded while its write was in flight; the bytes just \
                     written are stale for whatever version is current now, so nothing was \
                     recorded"
                );
                Ok(false)
            }
        }
    }

    /// Whether `(group_id, path)` has a usable `path_materialized_generations`
    /// record at all -- exactly the fence-checked point lookup
    /// [`Self::dag_zero_work_settlement_if_already_current`] performs before
    /// anything else, and whose absence makes that method return `None`
    /// unconditionally.
    ///
    /// Exposed separately so a caller can ask the cheap question FIRST. The
    /// settlement check's own inputs (a path's resolved native heads) cost an
    /// ancestry walk to compute, and on a device that has materialized
    /// nothing for a path yet -- every path on a replica catching up to a
    /// bulk import -- that walk is provably wasted: the O(1) lookup that
    /// follows it can only answer "no". `false` here is therefore never a
    /// weaker answer than running the full check, it is the same answer
    /// reached without paying for it.
    ///
    /// Advisory in the safe direction only. A record appearing between this
    /// call and a later one merely means the caller does the ordinary work it
    /// would have done anyway -- which is what `None` from the settlement
    /// check already means -- never that a needed write is skipped.
    pub fn dag_has_usable_materialized_generation(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, PeerSessionError> {
        Ok(self
            .sqlite()
            .dag_lookup_materialized_generation(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)?
            .is_some())
    }

    /// Whether the proof standing for `(group_id, path)` is a proof about
    /// the version the ROW currently names -- the whole of what a
    /// `Present` stamp claims, rather than the existence of some proof.
    ///
    /// Deliberately a different question from
    /// [`Self::dag_has_usable_materialized_generation`], which is the
    /// advisory pre-check for zero-work settlement. That one compares the
    /// proof against a DESIRED resolution the caller derives itself and
    /// must not additionally demand a projected row: the whole case it
    /// serves is a path whose disk is already correct before anything
    /// projected it. This one is for a caller asking about the row it is
    /// holding -- is this path's claim to be materialized true right now
    /// -- and the answer has to account for the row having moved on. A
    /// proof is published for one version; an admission supersedes the row
    /// without touching the mutation fence, so the old proof stays usable
    /// while describing content the path no longer wants.
    pub fn dag_usable_proof_names_current_version(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, PeerSessionError> {
        self.sqlite()
            .dag_usable_proof_names_current_version(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// Opens the durable write intent of one in-place hydration, before the
    /// path's mutation fence is bumped, so a crash after the bump leaves the
    /// old bytes readable as the pre-image of an unfinished write.
    pub(crate) fn open_hydration_write_intent<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        target: &[u8],
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<crate::materialization_intent::MaterializationIntentGuard<'a>, SyncError> {
        Ok(crate::materialization_intent::MaterializationIntentGuard::open(
            self, group_id, path, target, permit,
        )?)
    }

    /// Records, inside the caller's open write transaction, the blocks it has
    /// just stored from a recovered version, so they are served like any
    /// other block this device holds through the group.
    pub(crate) fn record_recovered_block_provenance_in_tx(
        conn: &rusqlite::Connection,
        group_id: &str,
        block_hashes: &[Vec<u8>],
    ) -> Result<(), yadorilink_sync_sqlite::SyncSqliteError> {
        yadorilink_sync_sqlite::dag_store::record_group_block_provenance(
            conn,
            group_id,
            block_hashes,
        )
    }

    /// Whether a usable proof names the version this path's row holds now:
    /// the read-only question status and listing lanes ask, answered here so
    /// they do not reach for the raw proof lookup themselves.
    pub(crate) fn local_copy_names_current_version(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncError> {
        Ok(self.sqlite().dag_usable_proof_names_current_version(group_id, path)?)
    }

    /// `SqliteSyncStore::disk_is_untouched_proven_write_at`
    /// for a path under this group's live root. Fail-closed: a group with no
    /// live link, or any error, is `false`.
    pub fn disk_is_untouched_proven_write_at(
        &self,
        group_id: &str,
        path: &str,
        out_path: &Path,
    ) -> Result<bool, PeerSessionError> {
        let sync_root = match self
            .link_repository()
            .link_gate_for_group(group_id)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)?
        {
            LinkGate::Live { local_path, .. } | LinkGate::Paused { local_path } => {
                std::path::PathBuf::from(local_path)
            }
            LinkGate::NoLiveLink => return Ok(false),
        };
        self.sqlite()
            .disk_is_untouched_proven_write_at(
                group_id,
                path,
                out_path,
                cached_birth_time_granularity(&sync_root),
            )
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// The zero-work-close pre-check: without any block fetch or disk
    /// write, determines whether `path` already, verifiably, holds the
    /// state `resolution`/`winner_version_hash` describes -- a usable
    /// `path_materialized_generations` record (fail-closed against the
    /// filesystem-side mutation fence, same as every other reader of that
    /// table) whose content matches the desired hash for this resolution,
    /// AND whose recorded filesystem identity re-verifies against live
    /// disk right now. `Some((state, mutation_generation))` authorizes
    /// skipping physical work for THIS decision only -- it is not itself a
    /// completion, never republishes, and never refreshes the record; the
    /// caller must still close via the same compound completion a real
    /// materialization would use, re-establishing currency at the actual
    /// moment of close. `None` means "not confirmable, do the real work"
    /// and must never be treated as an error or a proof of anything.
    ///
    /// The disk revalidation's birth-time-granularity input is expected to
    /// come from a per-group cache the implementation maintains, populated
    /// by one real probe the first time any path in that group is checked
    /// and reused for the rest of the process's lifetime -- never a fixed
    /// `Coarse` assumption. A fixed `Coarse` assumption was tried and
    /// rejected: on a filesystem that does not expose `generation_or_usn`
    /// (unprivileged `FS_IOC_GETVERSION` is commonly unavailable, and never
    /// available on overlayfs), `Coarse` treats even a perfectly matching
    /// birth time as `Ambiguous`, so this check could never confirm
    /// anything at all on such a filesystem, not merely miss an
    /// optimization on it. A per-call probe was also rejected: it performs
    /// its own file creation/deletion, which is itself physical work and
    /// would defeat the "zero work" guarantee this check exists to
    /// provide -- amortizing it to once per group keeps the steady-state
    /// cost at zero.
    pub fn dag_zero_work_settlement_if_already_current(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<(yadorilink_peer_session::ports::ExactActualState, i64)>, PeerSessionError>
    {
        // What the namespace requires at the path, not only its own heads:
        // a proof that `a` holds File `a` says nothing once a live `a/x`
        // needs `a` to be a directory. Heads and descendants are read in
        // one transaction. Under native authority the requirement is
        // native's own; a path native cannot decide yet (a live version this
        // replica does not hold) is never confirmed current.
        let desired_hash =
            match self.sqlite().native_desired_projected_path_state_hash(group_id, path) {
                Ok(hash) => hash,
                Err(yadorilink_sync_sqlite::SyncSqliteError::NotFound(_)) => return Ok(None),
                Err(error) => return Err(PeerSessionError::from(SyncError::from(error))),
            };
        let Some(basis) = self
            .sqlite()
            .dag_lookup_materialized_generation(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)?
        else {
            return Ok(None);
        };
        if basis.resolved_path_state_hash != desired_hash {
            return Ok(None);
        }
        let sync_root = match self
            .link_repository()
            .link_gate_for_group(group_id)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)?
        {
            LinkGate::Live { local_path, .. } | LinkGate::Paused { local_path } => {
                std::path::PathBuf::from(local_path)
            }
            LinkGate::NoLiveLink => return Ok(None),
        };
        let out_path = sync_root.join(path);
        let granularity = cached_birth_time_granularity(&sync_root);
        let revalidation =
            yadorilink_sync_sqlite::materialized_generation::revalidate_identity_against_disk(
                &basis,
                &out_path,
                granularity,
            );
        if revalidation
            != yadorilink_sync_sqlite::materialized_generation::IdentityRevalidation::Confirmed
        {
            return Ok(None);
        }
        let exact_state = match basis.object_kind {
            // A structural directory is no replicated entry, so there is no
            // exact state of one to settle an obligation against: do the
            // real work.
            MaterializedObjectKind::StructuralDirectory => return Ok(None),
            MaterializedObjectKind::Absent => {
                yadorilink_peer_session::ports::ExactActualState::Absent
            }
            MaterializedObjectKind::RegularFile => {
                yadorilink_peer_session::ports::ExactActualState::Object {
                    kind: RecordKind::File,
                    version: basis.version.ok_or_else(|| {
                        PeerSessionError::from(SyncError::from(
                            yadorilink_sync_sqlite::SyncSqliteError::CorruptState(
                                "a non-Absent materialized generation must carry a version".into(),
                            ),
                        ))
                    })?,
                    identity: Box::new(basis.filesystem_identity),
                }
            }
            MaterializedObjectKind::Directory => {
                yadorilink_peer_session::ports::ExactActualState::Object {
                    kind: RecordKind::Directory,
                    version: basis.version.ok_or_else(|| {
                        PeerSessionError::from(SyncError::from(
                            yadorilink_sync_sqlite::SyncSqliteError::CorruptState(
                                "a non-Absent materialized generation must carry a version".into(),
                            ),
                        ))
                    })?,
                    identity: Box::new(basis.filesystem_identity),
                }
            }
            MaterializedObjectKind::Symlink => {
                yadorilink_peer_session::ports::ExactActualState::Object {
                    kind: RecordKind::Symlink,
                    version: basis.version.ok_or_else(|| {
                        PeerSessionError::from(SyncError::from(
                            yadorilink_sync_sqlite::SyncSqliteError::CorruptState(
                                "a non-Absent materialized generation must carry a version".into(),
                            ),
                        ))
                    })?,
                    identity: Box::new(basis.filesystem_identity),
                }
            }
        };
        let mutation_generation = self.dag_snapshot_mutation_fence(group_id, path)?;
        Ok(Some((exact_state, mutation_generation)))
    }

    /// The settlement of explicit directory `path` when settling it again
    /// could change nothing, with the version it settles, else `None`.
    ///
    /// Everything [`crate::local_convergence`]'s directory settle writes is
    /// already so: the recorded proof is for `head`'s version and is the one
    /// the plan requires here now (re-read, descendants included; its fence
    /// is current and the live directory still has the recorded identity and
    /// mode), and the row is `head`'s, live, not held and `Present`. The
    /// fence is read before the proof and once more last, and must not have
    /// moved, so a write that began while the rest was read is not mistaken
    /// for a settled directory. A new head, a delete, a
    /// rename, a contest, a write in flight or an edit on disk each fails one
    /// of these. The caller still owes the name-hazard check.
    pub(crate) fn settled_explicit_directory(
        &self,
        group_id: &str,
        path: &str,
        head: &yadorilink_replica_domain::native_plan::NativeLocatedHead,
    ) -> Result<
        Option<(yadorilink_peer_session::ports::ExactActualState, i64, FileVersion)>,
        PeerSessionError,
    > {
        // The fence brackets every read below: a write that begins in between
        // moves it, and the proof read before it began no longer stands.
        let fence_before = self.dag_snapshot_mutation_fence(group_id, path)?;
        let Some((exact, mutation_generation)) =
            self.dag_zero_work_settlement_if_already_current(group_id, path)?
        else {
            return Ok(None);
        };
        if mutation_generation != fence_before {
            return Ok(None);
        }
        let version = head.version();
        let yadorilink_peer_session::ports::ExactActualState::Object {
            kind: RecordKind::Directory,
            version: proven,
            ..
        } = &exact
        else {
            return Ok(None);
        };
        if *proven != version {
            return Ok(None);
        }
        let Some(current) = self.get_current_version_record(group_id, path)? else {
            return Ok(None);
        };
        let current_version = current.to_file_version();
        if current.deleted
            || current_version.version_hash != version
            || self.row_authoring(group_id, path)?
                != Some(yadorilink_replica_domain::native_plan::NativeRowIdentity::of(head))
            || self.get_held_state(group_id, path)?.is_some()
            || self.get_materialization_state(group_id, path)?
                != Some(MaterializationState::Present)
            || self.dag_snapshot_mutation_fence(group_id, path)? != mutation_generation
        {
            return Ok(None);
        }
        Ok(Some((exact, mutation_generation, current_version)))
    }

    /// Opens the single sanctioned materialization-intent seam for
    /// `(group_id, path)` before a peer-driven materialize commits a fresh
    /// `Present` row and writes the file's bytes. See
    /// [`crate::materialization::MaterializationIntentGuard::open`]. Added
    /// as a narrow delegate (rather than exposing `&SyncState` itself)
    /// because `MaterializationIntentGuard<'a>` borrows a concrete
    /// `&'a SyncState`.
    pub(in crate::replica_coordinator) fn open_materialization_intent_guard<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        target_version_hash: &[u8],
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<
        Box<dyn yadorilink_peer_session::ports::OpenMaterializationIntent + Send + 'a>,
        PeerSessionError,
    > {
        let guard = crate::materialization_intent::MaterializationIntentGuard::open(
            self,
            group_id,
            path,
            target_version_hash,
            permit,
        )
        .map_err(SyncError::from)
        .map_err(PeerSessionError::from)?;
        Ok(Box::new(guard))
    }

    /// After every upsert in `finished_upserts` has had its temp file
    /// published to its final path (and every delete in `deletes` has had
    /// its `out_path` removed from disk), commits ALL of the following in
    /// ONE transaction: each finished upsert's fingerprint + intent-clear,
    /// and each delete's tombstone row + held-state clear. The row
    /// and intent were committed before the publish, so a crash in between is
    /// resolved by repair.
    ///
    /// Each upsert carries its OWN causal basis, captured at its own
    /// revalidation -- never re-read here, and no longer one basis shared
    /// by the batch. Re-deriving it at finalize time would attribute these
    /// physical writes to whatever resolution is current at commit; a
    /// shared one attributes every write in the batch to whatever the
    /// group frontier happened to be when the first of them started.
    ///
    /// Returns the upsert paths whose proof actually landed. A candidate
    /// the finalizer refused -- a lost fence, a row superseded while the
    /// batch was writing -- published nothing and must not be reported as
    /// settled either: its evidence names a version the path has left,
    /// and handing that to the engine lets it be published from there
    /// instead.
    pub fn finalize_projected_mutations_batch(
        &self,
        group_id: &str,
        finished_upserts: &[yadorilink_peer_session::ports::FinishedProjectedUpsert],
        deletes: &[yadorilink_peer_session::ports::PreparedProjectedDelete],
        permit: &RootCommitPermit<'_>,
    ) -> Result<std::collections::HashSet<String>, PeerSessionError> {
        #[cfg(test)]
        if self
            .test_observers
            .finalize_projected_mutations_batch_fails
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(PeerSessionError::CorruptState(
                "injected finalize_projected_mutations_batch failure".to_string(),
            ));
        }
        if finished_upserts.is_empty() && deletes.is_empty() {
            return Ok(std::collections::HashSet::new());
        }
        self.database()
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                let mut published_paths = std::collections::HashSet::new();
                for u in finished_upserts {
                    // This is an INTERNAL mutator publishing its own proof,
                    // not an external change being adopted. The distinction
                    // is the whole bug this replaced: the adoption API bumps
                    // the mutation fence itself ("external-actual-state-
                    // adopted"), so routing this write through it advanced
                    // the fence from `N` to `N+1` and the obligation's own
                    // settlement evidence -- which CASes on `N` -- could
                    // then never win. Every successfully observed write
                    // defeated its own publication, so the healthier the
                    // filesystem, the more reliably the path was
                    // re-materialized forever.
                    //
                    // One primitive commits all three of the proof, the
                    // `Present` stamp and the intent clear, under exactly
                    // the epoch this write produced and only while the row
                    // is still the one that was written for. Each of those
                    // three alone is a state nothing can read correctly,
                    // which is why they are no longer a publish here and a
                    // conditional clear there.
                    let outcome = yadorilink_sync_sqlite::exact_materialized_commit::commit_internal_materialized_state_if_fence_current(
                        tx,
                        group_id,
                        &u.rel_path,
                        &yadorilink_sync_sqlite::exact_materialized_commit::ExactMaterializedState::Object {
                            kind: u.kind,
                            version: u.version_hash,
                            identity: Box::new(u.observed_identity),
                        },
                        u.mutation_generation,
                        Some(yadorilink_sync_sqlite::exact_materialized_commit::ExpectedAuthoring {
                            state: u.expected_state,
                            expected_version: Some(&u.version_hash),
                        }),
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_nanos() as i64)
                            .unwrap_or(0),
                    )?;
                    match outcome {
                        yadorilink_sync_sqlite::exact_materialized_commit::InternalMaterializedCommit::Published(_) => {
                            published_paths.insert(u.rel_path.clone());
                        }
                        // Nothing was written, the intent included. Clearing
                        // it after a lost guard would leave the row claiming
                        // materialization with no exact proof and nothing
                        // recording that a write was ever in flight --
                        // exactly the unprovable-claim state, manufactured on
                        // the recovery side this time. The obligation is
                        // retried instead of closed unproven.
                        yadorilink_sync_sqlite::exact_materialized_commit::InternalMaterializedCommit::FenceLost {
                            live_mutation_generation,
                        } => {
                            tracing::warn!(
                                group_id,
                                path = %u.rel_path,
                                expected_mutation_generation = u.mutation_generation,
                                ?live_mutation_generation,
                                "another mutator advanced this path's fence between its write and \
                                 this publish; leaving the materialization intent open so the \
                                 obligation is retried rather than closed unproven"
                            );
                        }
                        yadorilink_sync_sqlite::exact_materialized_commit::InternalMaterializedCommit::AuthoringSuperseded => {
                            tracing::warn!(
                                group_id,
                                path = %u.rel_path,
                                "this path was superseded while its batch was writing; the bytes \
                                 on disk are for a version it has moved off, so nothing is \
                                 published and the intent stays open for the re-drive"
                            );
                        }
                    }
                }
                for d in deletes {
                    yadorilink_sync_sqlite::MaterializationStateRepository::clear_held_in_tx(
                        tx, group_id, &d.rel_path,
                    )?;
                    yadorilink_sync_sqlite::file_index::upsert_file_in_tx(
                        tx,
                        group_id,
                        &d.record,
                        &d.origin_device_id,
                    )?;
                }
                permit.verify()?;
                Ok(published_paths)
            })
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// Re-verifies an already-established root's identity, requiring the
    /// persisted root-identity token. See
    /// [`crate::root_identity::VerifiedRoot::verify`]. Added as a narrow
    /// delegate for the same reason as `open_materialization_intent_guard`
    /// above: `VerifiedRoot::verify` takes a concrete `&SyncState`, which a
    /// trait object can't produce.
    /// Fails closed if `root`'s on-disk identity no longer matches the
    /// group's stored marker (a replaced/swapped mountpoint). The verified
    /// identity value itself is never used by any production caller --
    /// every call site only needs the pass/fail outcome -- so this
    /// deliberately returns `()`, not the verified-root value.
    pub fn verify_root(&self, root: &Path, group_id: &str) -> Result<(), PeerSessionError> {
        yadorilink_root_authority::root_identity::VerifiedRoot::verify(root, group_id, self)
            .map(|_| ())
            .map_err(PeerSessionError::from)
    }

    /// Every currently indexed file row for `group_id`. Not for the
    /// per-file filename-hazard check, which is [`Self::name_fold_matches`].
    pub fn list_files(&self, group_id: &str) -> Result<Vec<FileRecord>, PeerSessionError> {
        self.file_index_repository()
            .list_files(group_id)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// The live rows that could be conflict copies (see
    /// `FileIndexRepository::list_live_conflict_copy_candidates`).
    pub fn list_live_conflict_copy_candidates(
        &self,
        group_id: &str,
    ) -> Result<Vec<FileRecord>, PeerSessionError> {
        self.file_index_repository()
            .list_live_conflict_copy_candidates(group_id)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// Whether the single live head at `destination` descends, through its own author's
    /// removals, from a delta that removed `removed`'s exact head and put `destination`
    /// in the same delta: the verified shape of a move of `removed.source_path` onto
    /// `destination`. Anything missing, concurrent or unrecognised answers `false`.
    pub fn native_head_descends_from_move_of(
        &self,
        group_id: &str,
        removed: &yadorilink_replica_domain::native_plan::NativeRowIdentity,
        destination: &str,
    ) -> Result<bool, PeerSessionError> {
        use yadorilink_replica_domain::ids::{FolderGroupId, SyncPath};
        use yadorilink_replica_domain::native_state::DeltaHash;
        use yadorilink_replica_domain::signed_delta::NativeDelta;
        let group = FolderGroupId(group_id.to_owned());
        let destination = SyncPath(destination.to_owned());
        self.database()
            .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                let heads = yadorilink_sync_sqlite::native_store::native_heads_at(
                    conn,
                    &group,
                    &destination,
                )?;
                let [head] = heads.as_slice() else { return Ok(false) };
                let mut dot = head.dot.clone();
                let mut provenance: DeltaHash = head.payload.provenance;
                // A delta chain is finite; a repeated dot would be a cycle and answers `false`.
                let mut seen = std::collections::HashSet::new();
                while seen.insert(dot.clone()) {
                    let Some(body) = yadorilink_sync_sqlite::native_store::fetch_delta_body(
                        conn,
                        &group,
                        &dot.author,
                        dot.seq,
                    )?
                    else {
                        return Ok(false);
                    };
                    let Ok(delta) = NativeDelta::from_wire_bytes(&body) else {
                        return Ok(false);
                    };
                    if delta.delta_hash() != provenance {
                        return Ok(false);
                    }
                    let Some(put_op) =
                        delta.ops.iter().find(|op| op.path == destination && op.put.is_some())
                    else {
                        return Ok(false);
                    };
                    let moved_here = delta.ops.iter().any(|op| {
                        op.path == removed.source_path
                            && op
                                .removes
                                .iter()
                                .any(|r| r.dot == removed.dot && r.provenance == removed.provenance)
                    });
                    if moved_here {
                        return Ok(true);
                    }
                    // An edit of the destination: follow the one head it replaced.
                    let [previous] = put_op.removes.as_slice() else { return Ok(false) };
                    dot = previous.dot.clone();
                    provenance = previous.provenance;
                }
                Ok(false)
            })
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// Whether any native head is recorded at exactly `path` in `group_id`.
    pub fn native_path_has_heads(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, PeerSessionError> {
        self.database()
            .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                Ok(!yadorilink_sync_sqlite::native_store::native_heads_at(
                    conn,
                    &yadorilink_replica_domain::ids::FolderGroupId(group_id.to_owned()),
                    &yadorilink_replica_domain::ids::SyncPath(path.to_owned()),
                )?
                .is_empty())
            })
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// The live indexed paths of `group_id`, other than `path`, whose stored
    /// name key equals `folded` (see [`yadorilink_sync_sqlite::file_index::
    /// NameFoldKey`]). An index lookup, for the per-file hazard check.
    pub fn name_fold_matches(
        &self,
        group_id: &str,
        key: yadorilink_sync_sqlite::file_index::NameFoldKey,
        folded: &str,
        path: &str,
    ) -> Result<Vec<String>, PeerSessionError> {
        self.file_index_repository()
            .name_fold_matches(group_id, key, folded, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// The atomic-write-identity read for `(group_id, path)`'s current row,
    /// used to answer a peer's durability-handoff query with an identity
    /// that can't tear across a concurrent metadata/content transition. See
    /// [`crate::index::SyncState::get_current_version_record`].
    pub fn get_current_version_record(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<CurrentVersionRecord>, PeerSessionError> {
        self.sqlite()
            .dag_get_current_version_record(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// The current held-state row for `(group_id, path)`, if any.
    pub fn get_held_state(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<HeldState>, PeerSessionError> {
        self.materialization_state_repository()
            .get_held_state(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// The full row (blocks/size/mtime/deleted/origin/
    /// authoring identity) plus every metadata column, in ONE
    /// transaction -- for a peer-projection candidate whose content
    /// already matches what's on disk and in the index, but whose row/
    /// metadata/authoring/origin still needs updating, in one
    /// `writer_gate` acquisition.
    pub fn apply_projected_row_atomic(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        authoring: Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity>,
        meta: &yadorilink_replica_domain::session_state::LocalFileMetaColumns,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError> {
        #[cfg(test)]
        self.test_observers.note_apply_projected_row_atomic();
        self.file_index_repository()
            .apply_projected_row_with_authoring_atomic(
                group_id,
                record,
                origin_device_id,
                authoring,
                meta,
                permit,
            )
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)
    }
}

impl yadorilink_peer_session::ports::BlockServeAuthorizationPort for ReplicaCoordinator {
    fn authorize_block_serve(
        &self,
        group_id: &str,
        path: &str,
        block_hash: &[u8],
    ) -> Result<BlockServeAuthorization, PeerSessionError> {
        let referenced = self
            .published_group_file_version_references_block(group_id, block_hash)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)?;
        if !referenced {
            return Ok(BlockServeAuthorization::NotReferenced);
        }
        let has_provenance = self
            .sqlite()
            .dag_group_has_block_provenance(group_id, block_hash)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)?;
        if !has_provenance {
            return Ok(BlockServeAuthorization::NoProvenance);
        }
        let declared_size = self
            .file_index_repository()
            .get_file(group_id, path)
            .map_err(SyncError::from)
            .map_err(PeerSessionError::from)?
            .filter(|record| !record.deleted)
            .and_then(|record| record.blocks.iter().find(|b| b.hash == block_hash).map(|b| b.size));
        Ok(BlockServeAuthorization::Allowed { declared_size })
    }
}

#[cfg(test)]
mod tests;
