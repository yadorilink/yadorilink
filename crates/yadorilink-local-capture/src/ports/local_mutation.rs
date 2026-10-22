//! The capability surface `LocalChangeProcessor` (`local_change.rs`) needs
//! from a replica-state type: committing a detected local edit (upsert or
//! delete) as a delta-emitting index write, plus the dirty-path journal that
//! survives a crash between detection and that commit. Every method below
//! is called by `local_change.rs` today via `self.state.<method>`,
//! surveyed directly from that file. Three additions beyond that original
//! survey: `list_files`, used by the two production
//! `scan_existing_files`/reconcile call sites; and
//! `verify_root`/`open_root`, added because
//! `VerifiedRoot::verify`/`VerifiedRoot::open` need a concrete
//! replica-state reference that a trait object can't produce, so the port
//! grows a delegate that performs the concrete call internally instead of
//! exposing the concrete type.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_replica_domain::session_state::{
    DirtyPath, LocalFileMetaColumns, PreparedLocalMutation,
};
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sync_sqlite::dag_store::LocalAuthorKey;
use yadorilink_sync_sqlite::structural_origin::StructuralDirectoryOrigin;
use yadorilink_sync_sqlite::SyncSqliteError;

#[derive(Clone, Copy)]
pub struct LocalChangeEmission<'a> {
    pub author: &'a LocalAuthorKey,
    pub permit: &'a RootCommitPermit<'a>,
}

/// One explicit directory as capture found it: the entry to commit and,
/// when the directory on disk is still the one the verdict was taken on
/// with the mode being authored, its identity.
pub struct CapturedDirectory {
    pub record: FileRecord,
    pub op: yadorilink_replica_domain::local_op::Op,
    pub version: yadorilink_replica_domain::file::FileVersion,
    pub meta: LocalFileMetaColumns,
    pub identity: Option<yadorilink_fs_platform::fs_identity::FileIdentity>,
}

/// The answer of [`LocalMutationStore::inspect_windows_placeholder`]: whether
/// the OS still reports the Cloud Files placeholder at a path as the exact,
/// untouched object the daemon recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaceholderStatus {
    /// The on-disk object is still exactly the recorded placeholder: safe to
    /// hydrate over or evict back to a placeholder without losing anything.
    Untouched,
    /// The OS's own signal (not this process's stat heuristics) says the
    /// object has been written to, replaced, or otherwise materialized since
    /// it was recorded: a real local change, never silently overwritten.
    Dirty,
    /// Could not determine which of the above is true (the object is gone,
    /// the identity does not decode, the OS call failed). Fails closed: every
    /// caller treats this exactly like `Dirty`, never like `Untouched`.
    Unknown,
}

/// Capability surface `LocalChangeProcessor` needs to turn a detected local
/// filesystem event into a committed index row plus native delta, and to
/// journal the attempt durably across the read/blockify/put/index+delta step
/// so a crash or block-store fault cannot silently drop the edit.
pub trait LocalMutationStore: Send + Sync {
    /// Acquires the per-`(group_id, path)` lock serializing this local
    /// capture against a concurrent peer reconciliation of the same path.
    fn path_lock(&self, group_id: &str, path: &str) -> Arc<tokio::sync::Mutex<()>>;

    /// The current row for `path`, read before deciding whether a detected
    /// filesystem event actually represents new content.
    fn get_file(&self, group_id: &str, path: &str) -> Result<Option<FileRecord>, SyncSqliteError>;

    /// Every column of `path`'s current row -- content, metadata columns,
    /// authoring identity -- read as ONE statement (see
    /// [`yadorilink_sync_sqlite::CanonicalCurrentRow`]). `None` when the
    /// path has no current row.
    ///
    /// The authoring identity is a precise "has anything committed a new
    /// version of this row since I last looked" signal -- every commit
    /// (this device's own or a peer's) stamps a fresh, distinct hash, even
    /// when the new version's `FileRecord` fields (size/mtime/blocks) happen
    /// to coincide with the old one (a metadata-only change, or content
    /// that happens to hash the same). Batched-commit revalidation
    /// (`flush_pending_batch`) compares it alongside the `FileRecord`, and
    /// both come from this one read so they cannot describe different
    /// incarnations of the row. Every other caller that compares more than
    /// one indexed column against disk (exec bit + xattrs, record kind +
    /// symlink target) reads them here for the same reason.
    fn canonical_current_row(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<yadorilink_sync_sqlite::CanonicalCurrentRow>, SyncSqliteError>;

    /// Native's own capture witness for `path` -- read alongside
    /// [`canonical_current_row`](Self::canonical_current_row), never
    /// derived from it. A prepared mutation carries it, and the commit
    /// refuses the mutation when native no longer shows it.
    fn native_capture_witness(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<yadorilink_replica_domain::native_state::NativeCaptureWitness, SyncSqliteError>;

    /// [`native_capture_witness`](Self::native_capture_witness) for every
    /// path native knows in the group, from one read (for a whole-index
    /// snapshot). A path missing from the result has no head: use
    /// `yadorilink_sync_sqlite::native_capture::absent_native_witness`.
    fn native_capture_witnesses(
        &self,
        group_id: &str,
    ) -> Result<
        std::collections::HashMap<
            String,
            yadorilink_replica_domain::native_state::NativeCaptureWitness,
        >,
        SyncSqliteError,
    >;

    /// Whether native still shows `witness` at its physical path: native's
    /// staleness verdict, the one that decides whether a prepared local
    /// mutation may still be committed.
    fn native_capture_is_fresh(
        &self,
        group_id: &str,
        witness: &yadorilink_replica_domain::native_state::NativeCaptureWitness,
    ) -> Result<bool, SyncSqliteError>;

    /// Bulk materialization-state lookup for a whole group — used by
    /// `scan_existing_files` so deciding whether an on-disk entry is a
    /// never-chunk placeholder costs one query for the whole scan.
    fn list_materialization_states(
        &self,
        group_id: &str,
    ) -> Result<HashMap<String, MaterializationState>, SyncSqliteError>;

    /// The volume identity persisted for `group_id`'s live link: `None` when
    /// the group has no link row, `Some(None)` for a link not yet adopted.
    fn capture_volume_identity(
        &self,
        group_id: &str,
    ) -> Result<Option<Option<String>>, SyncSqliteError>;

    /// Persists the volume identity of `group_id`'s live link (first adoption
    /// only; a changed volume is never followed automatically).
    fn adopt_capture_volume_identity(
        &self,
        group_id: &str,
        identity: &str,
    ) -> Result<(), SyncSqliteError>;

    fn get_materialization_state(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<MaterializationState>, SyncSqliteError>;

    fn has_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError>;

    /// The live intent's target content hash for `(group_id, path)`, if a
    /// `materialize()` write is in flight right now -- the durable
    /// projection fence a detected filesystem event is checked against
    /// before it is ever treated as a genuine local edit.
    ///
    /// THE INVARIANT THIS BACKS: content a remote projection wrote to this
    /// device's own filesystem must never, by itself, cause a new local
    /// Change to be authored for it. `materialize()` already opens this
    /// intent durably (`MaterializationIntentGuard`, opened before its
    /// temp-write-then-rename begins) for an unrelated reason -- crash
    /// recovery disambiguating an interrupted write from a genuine offline
    /// deletion. It happens to already be exactly the fence this needs: a
    /// durable `expected_projection(path, target_version_hash)`, opened
    /// before the write that could echo back through the watcher begins,
    /// so this reuses it rather than inventing a second, parallel piece of
    /// state that would need to stay in sync with the first.
    ///
    /// `local_change.rs`'s caller compares this target against the SAME
    /// freshly-chunked blocks it already computed for the event
    /// (`intent_target_hash(&blocks)`), not merely against whether an
    /// intent exists at all: presence alone cannot tell an echo of THIS
    /// materialize apart from a genuine local edit racing it toward a
    /// DIFFERENT target, and the latter must always still be captured (see
    /// that call site's own doc comment for the full worked example this
    /// guards).
    fn materialization_intent_target(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<Vec<u8>>, SyncSqliteError>;

    /// The content targets of what this daemon's own writes may have left
    /// on disk at `path` while a write of other content is open over it: the
    /// version it was last proven to hold, even if that proof has been
    /// invalidated since, and every earlier write the open intent replaced
    /// before it was proven. Capture never authors bytes equal to one of
    /// these while such a write is open (see `yadorilink_sync_sqlite::
    /// materialized_generation::pre_image_content_targets`).
    fn pre_image_content_targets(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Vec<Vec<u8>>, SyncSqliteError>;

    /// Whether `(group_id, path)` still has an unsettled, REMOTE-origin
    /// `projection_obligations` row -- distinct from
    /// `has_materialization_intent` above, which only covers the narrower
    /// window a `MaterializationIntentGuard` protects (a `materialize()`
    /// call already in flight). A path can have a durably-committed,
    /// non-deleted index row with an obligation that has not yet settled at
    /// all -- no intent has ever been opened for it, but it is just as much
    /// "we know about this file and are still placing it locally" as an
    /// in-flight intent is: the startup reconciliation scan's own
    /// `has_materialization_intent` check alone is not enough to protect
    /// this state; a newly-arrived native delta whose obligation is still
    /// unsettled when a restart's scan runs was silently tombstoned before
    /// this check existed. While a REMOTE-origin obligation exists for a
    /// path, an absent local file must not yet be interpreted as an
    /// offline user deletion.
    ///
    /// Deliberately excludes a LOCAL-origin obligation: one can only be
    /// produced by this device's own local emission, whose bytes were
    /// already observed on this device's own disk before the change was
    /// ever admitted (that observation IS what produced the change) -- so
    /// it never represents content not yet placed, and its presence must
    /// never withhold a genuine, later offline deletion of that same path.
    fn has_unsettled_projection_obligation(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError>;

    /// The items of `group_id` the user paused (see
    /// `yadorilink_sync_sqlite::paused_items`). A local change to a path one
    /// of them covers is not authored while the pause lasts; the edit stays
    /// on disk, and resuming the item captures it.
    fn paused_items(&self, group_id: &str) -> Result<Vec<String>, SyncSqliteError>;

    /// The held paths of `group_id` whose disk has not yet been reconciled
    /// (see `yadorilink_sync_sqlite::held_path`). Whatever is on
    /// disk under one of them belongs to no row this device placed, so no
    /// local change to it -- edit or deletion -- is authored until the
    /// reconciliation pass has released it.
    fn held_path_names(&self, group_id: &str) -> Result<Vec<String>, SyncSqliteError>;

    /// Whether a rebootstrap freezes `group_id` (see
    /// `yadorilink_sync_sqlite::native_rebootstrap::group_frozen`). Nothing is authored
    /// for a frozen group: its disk edits stay as they are, and the scan that follows the
    /// freeze captures them.
    fn group_frozen(&self, group_id: &str) -> Result<bool, SyncSqliteError>;

    /// Holds `path` for a local edit that cannot be authored there because
    /// this replica's own bucket at the path is full of versions it was not
    /// shown (see `yadorilink_sync_sqlite::held_path::
    /// HeldPathRepository::hold_unauthorable_local_edit`). The
    /// reconciliation that preserves the edit as a conflict copy and places
    /// the path's current value runs once woken
    /// ([`Self::wake_install_reconciliation`]).
    fn hold_unauthorable_local_edit(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), SyncSqliteError>;

    /// Wakes the reconciliation of held paths now. The pass skips a path
    /// whose lock is held, so a caller that held a path wakes it after
    /// releasing that path's lock.
    fn wake_install_reconciliation(&self);

    /// Whether `(group_id, path)`'s current row is hazard-held right now
    /// (`held_reason` set -- a case-fold/reserved-name/other on-disk-name
    /// collision `hold_record` recorded, per that function's own doc
    /// comment). A held row is `Remote`, has nothing written under
    /// this exact name, and opens no materialization intent -- by design,
    /// per `hold_record`'s own fix -- so neither `has_materialization_
    /// intent` nor (once `HazardHeld` settlement deletes the path's
    /// projection-obligation row) `has_unsettled_projection_obligation`
    /// protects it from being misread as an offline deletion. A held path
    /// is emphatically not deleted: it is this device's own, deliberate,
    /// per-device refusal to materialize under a name that collides with
    /// something else, and it stays valid and present on every other peer.
    ///
    /// Only holds that keep the name empty count
    /// (`HeldState::keeps_the_name_empty`). A metadata-unprovable hold is
    /// recorded against a file that was on disk, so when that file goes
    /// missing it is a real deletion and must propagate.
    fn is_held(&self, group_id: &str, path: &str) -> Result<bool, SyncSqliteError>;

    /// What the structural-directory ledger holds for `path`: nothing, a
    /// structural `mkdir` in flight, or the identity of a directory this
    /// device created (or kept) only to hold replicated descendants.
    ///
    /// Capture must never author such a directory as an explicit one -- it
    /// is derived state, not something a user made. Only the ledger can
    /// tell the two apart; nothing observable on disk can. Compare the
    /// record against the directory actually there with
    /// [`StructuralDirectoryOrigin::status`]: a directory with no matching
    /// record is `OriginUnknown`, which is kept and authored as nothing,
    /// never guessed to be either kind; a structural directory whose own
    /// metadata (its mode) changed since it was recorded is
    /// `StructuralMetadataChanged`, which D5 promotes to an explicit
    /// directory with the observed mode.
    fn structural_directory_origin(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<StructuralDirectoryOrigin, SyncSqliteError>;

    /// The retained-directory record for `path`: a directory whose entry
    /// is deleted, kept on disk because it is not empty (see
    /// `yadorilink_sync_sqlite::structural_origin::record_retained_directory`).
    /// It is local state, not something a user made, and capture never
    /// authors it back.
    fn retained_directory(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<yadorilink_sync_sqlite::structural_origin::RetainedDirectory, SyncSqliteError>;

    /// The identity of the directory this device last published as
    /// materialized for the explicit Directory entry at `path` (read
    /// without the fence check), if the last publication for the path was
    /// one and recorded an identity. It stays after the entry's deletion is
    /// settled as retained, which publishes nothing, so it tells the
    /// directory the deleted entry described from one put there since.
    fn materialized_directory_identity(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<yadorilink_fs_platform::fs_identity::FileIdentity>, SyncSqliteError>;

    /// The birth-time granularity of the volume holding `sync_root`, which
    /// decides whether an identity comparison of a directory against its
    /// structural-origin record is conclusive.
    fn birth_time_granularity(
        &self,
        sync_root: &Path,
    ) -> yadorilink_fs_platform::fs_identity::TimestampGranularity;

    /// Whether the regular file at `out_path` is, untouched, what a usable
    /// proof says this device wrote at `path` -- whichever version the row
    /// now names. A `Present` row says only that an object exists, so an
    /// older version's bytes can stand under a newer row; those bytes are
    /// the daemon's own write, not an edit, and must not be authored over the
    /// newer version. Fail-closed: any doubt is `false`, which leaves the
    /// file to the ordinary comparison against the row.
    fn disk_is_untouched_proven_write(
        &self,
        group_id: &str,
        path: &str,
        sync_root: &Path,
        out_path: &Path,
    ) -> Result<bool, SyncSqliteError>;

    /// Bulk placeholder-identity lookup for a whole group -- used by
    /// `scan_existing_files` for the same reason as
    /// `list_materialization_states`: one query for the whole scan instead
    /// of one per file. Only paths whose row is currently `Remote`
    /// AND carries a recorded identity appear here -- see
    /// `MaterializationStateRepository::list_placeholder_generations`'s own
    /// doc comment for why the state gate matters.
    fn list_placeholder_generations(
        &self,
        group_id: &str,
    ) -> Result<
        HashMap<String, yadorilink_sync_sqlite::RecordedPlaceholderGeneration>,
        SyncSqliteError,
    >;

    fn get_placeholder_generation(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<yadorilink_sync_sqlite::RecordedPlaceholderGeneration>, SyncSqliteError>;

    /// The ONLY way `local_change.rs`'s Windows dirty-detection
    /// verdict may be `Untouched` -- a live query against the real CfAPI
    /// placeholder at `path`, asking whether its OS-tracked
    /// `CF_PLACEHOLDER_STATE_IN_SYNC` bit is set AND its current
    /// `FileIdentity` still decodes to exactly `expected_generation`.
    /// Never a local heuristic (no size/mtime comparison anywhere in this
    /// call): any failure to confirm both -- the path isn't a real
    /// placeholder, the identity doesn't decode, the API call itself
    /// fails -- must come back as
    /// [`PlaceholderStatus::Unknown`],
    /// which every caller treats exactly like `Dirty` (fail-closed).
    ///
    /// `path` is the absolute on-disk path, not a `group_id`/relative-path
    /// pair like every other method on this trait -- this is a live OS
    /// call (`CreateFileW`+`CfGetPlaceholderInfo`), not an index query, so
    /// it needs the same real filesystem path `local_change.rs` already
    /// has in hand from its own `lstat`, not a re-resolution through the
    /// index.
    fn inspect_windows_placeholder(
        &self,
        path: &Path,
        expected_generation: u64,
    ) -> PlaceholderStatus;

    /// Commits a bounded batch of already-prepared, already-revalidated
    /// local mutations in one transaction — the batched counterpart to
    /// [`Self::upsert_file_emitting_change`]/[`Self::mark_deleted_emitting_change`].
    /// See `yadorilink_sync_sqlite::file_index::FileIndexRepository::
    /// commit_local_mutations_batch`'s own doc for the correctness
    /// preconditions the caller must have already established (disk/index
    /// revalidation, path locks held for the whole call) before reaching
    /// this method — this trait cannot enforce either. `evidence`, when
    /// non-empty, must be aligned 1:1 with `mutations` — see that same
    /// method's own doc comment and
    /// `yadorilink_sync_sqlite::file_index::LocalCaptureActualStateEvidence`'s
    /// doc comment.
    fn commit_local_mutations_batch(
        &self,
        group_id: &str,
        mutations: &[PreparedLocalMutation],
        evidence: &[Option<yadorilink_sync_sqlite::file_index::LocalCaptureActualStateEvidence>],
        origin_device_id: &str,
        emission: LocalChangeEmission<'_>,
    ) -> Result<(), SyncSqliteError>;

    /// Commits the capture of one explicit directory: its entry `directory`
    /// describes, with the observed identity as its actual-state proof when
    /// the directory is still the one the verdict was taken on. With an
    /// emitter it is authored as a signed change; without one it is an
    /// index write only. Committed on its own rather than in a flush batch
    /// (a directory's stat moves whenever an entry inside it changes, which
    /// would fail the batch's revalidation for no change to its version).
    fn commit_captured_directory(
        &self,
        group_id: &str,
        directory: &CapturedDirectory,
        origin_device_id: &str,
        emitter: Option<&LocalAuthorKey>,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    /// Commits the removal of the directory `root`: a point delete of each
    /// of `tombstones` (the explicit entries this device observed there,
    /// deepest first, each re-verified absent and locked by the caller,
    /// each carrying the change its row showed at capture).
    /// With an emitter they are one signed recursive delete rooted at
    /// `root`, cut into parts, each path adopting its Absent evidence (see
    /// `yadorilink_sync_sqlite::file_index::FileIndexRepository::
    /// commit_recursive_operation`); without one, index tombstones observed
    /// at `observed_at_unix_nanos`. The same caller preconditions as
    /// [`Self::commit_local_mutations_batch`] apply.
    // One argument per fact the removal needs; a params struct would only
    // rename them.
    #[allow(clippy::too_many_arguments)]
    fn commit_directory_removal(
        &self,
        group_id: &str,
        root: &str,
        tombstones: &[PreparedLocalMutation],
        origin_device_id: &str,
        observed_at_unix_nanos: i64,
        emitter: Option<&LocalAuthorKey>,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    /// Commits the rename of the directory `from` to `to` as one signed
    /// recursive rename: `mutations` are each moved entry's delete at its
    /// old path and put at its new one, already prepared and revalidated,
    /// with `evidence` aligned 1:1. The same caller preconditions as
    /// [`Self::commit_local_mutations_batch`] apply.
    // One argument per fact the rename needs; a params struct would only
    // rename them.
    #[allow(clippy::too_many_arguments)]
    fn commit_directory_rename(
        &self,
        group_id: &str,
        from: &str,
        to: &str,
        mutations: &[PreparedLocalMutation],
        evidence: &[Option<yadorilink_sync_sqlite::file_index::LocalCaptureActualStateEvidence>],
        origin_device_id: &str,
        emission: LocalChangeEmission<'_>,
    ) -> Result<(), SyncSqliteError>;

    /// Whether any live current row lies strictly below `path`: whether
    /// the index holds entries in a directory at `path`.
    fn has_live_descendant_row(&self, group_id: &str, path: &str) -> Result<bool, SyncSqliteError>;

    /// Follows a structural directory a rename moved to `to_path`: when the
    /// ledger records the object `identity` names as structural under
    /// another path, its record (and those below it) moves to `to_path`,
    /// and the path it moved from is returned. A renamed container stays a
    /// container; it is never promoted by being renamed. See
    /// `yadorilink_sync_sqlite::structural_origin::rekey_structural_origin`.
    fn follow_renamed_structural_directory(
        &self,
        group_id: &str,
        to_path: &str,
        identity: &yadorilink_fs_platform::fs_identity::FileIdentity,
        birth_time_granularity: yadorilink_fs_platform::fs_identity::TimestampGranularity,
    ) -> Result<Option<String>, SyncSqliteError>;

    /// Batch upsert for an initial folder scan, one transaction per chunk —
    /// `scan_existing_files`'s bulk-write path. `metas` carries each
    /// record's scan-observed metadata columns (empty, or aligned 1:1 with
    /// `records`) and is written in the same transaction as the row, so no
    /// restart can observe a row whose metadata has not landed yet.
    ///
    /// `observed` (same alignment) is what the scan saw on disk for each
    /// path: the exact version it derived for those bytes, the object's
    /// kind, and the identity it observed. A path with one gets its
    /// actual-state generation and its `Present` stamp in the same
    /// transaction; a path without one gets neither -- and has whatever
    /// proof its previous version left behind retired, since `Present` is
    /// carried forward by the row upsert and is exactly the claim that
    /// proof supports.
    fn upsert_files_batch(
        &self,
        group_id: &str,
        records: &[FileRecord],
        origin_device_id: &str,
        metas: &[Option<LocalFileMetaColumns>],
        observed: &[Option<yadorilink_sync_sqlite::file_index::ImportedActualState>],
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    /// Tombstones a path with "now" as the observed time — the plain local
    /// delete path when no debounce-recorded observation time applies.
    fn mark_deleted_at(
        &self,
        group_id: &str,
        path: &str,
        device_id: &str,
        observed_at_unix_nanos: i64,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    fn remove_file(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<bool, SyncSqliteError>;

    /// Records blocks this device actually obtained by reading them off
    /// local disk during capture (as opposed to receiving them from a peer).
    fn record_group_block_provenance(
        &self,
        group_id: &str,
        block_hashes: &[Vec<u8>],
    ) -> Result<(), SyncSqliteError>;

    /// Journals `path` as a detected-but-not-yet-processed local edit,
    /// before the read/blockify/put/index+delta step runs, so a crash or fault
    /// mid-processing cannot drop the edit.
    fn record_dirty_path(
        &self,
        group_id: &str,
        path: &str,
        change_kind: &str,
        observed_at_unix_nanos: i64,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    /// Journals every `(path, change_kind, observed_at_unix_nanos)` in
    /// `entries` in one durable transaction, before any of their
    /// block-store/index work runs -- the batched form of
    /// [`Self::record_dirty_path`], letting a whole debounce-flush batch
    /// share one commit instead of paying one per path.
    fn record_dirty_paths_batch(
        &self,
        group_id: &str,
        entries: &[(String, String, i64)],
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    /// Records that a processing attempt for `path` failed, leaving the
    /// dirty row in place for retry.
    fn mark_dirty_path_attempt(
        &self,
        group_id: &str,
        path: &str,
        last_error: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    /// Clears every `(path, observed_at_unix_nanos)` in `entries` from the
    /// dirty journal in one durable transaction, but only the exact
    /// observation each entry names -- the batched, conditional form of
    /// `DirtyPathRepository::clear_dirty_path`. See the concrete `DirtyPathRepository`
    /// method of the same name for why the condition matters: it must never
    /// erase a newer, not-yet-processed event for the same path.
    fn clear_dirty_paths_conditional_batch(
        &self,
        group_id: &str,
        entries: &[(String, i64)],
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    /// Whether a change-emitting write for `group_id` would currently pass
    /// its policy precondition -- `false` exactly when every emitting
    /// method above would refuse with `SyncSqliteError::PolicyUnavailable`.
    /// A read of the same gate, never an authorization decision of its own:
    /// the dirty-journal re-drive asks it so it does not re-process every
    /// withheld path only to have each one refused again.
    fn local_emission_available(&self, group_id: &str) -> bool;

    /// Every currently journaled dirty path for `group_id`, oldest-first —
    /// the startup rescan worklist that re-drives edits a crash interrupted.
    fn list_dirty_paths(&self, group_id: &str) -> Result<Vec<DirtyPath>, SyncSqliteError>;

    /// Every currently indexed file row for `group_id` — the baseline a
    /// disk-vs-index reconcile diffs against.
    fn list_files(&self, group_id: &str) -> Result<Vec<FileRecord>, SyncSqliteError>;

    /// [`Self::list_files`] with each row's record kind: whether a row is a
    /// directory decides which ignore patterns cover it and what a vanished
    /// directory's removal deletes.
    fn list_files_with_kind(
        &self,
        group_id: &str,
    ) -> Result<Vec<(FileRecord, yadorilink_replica_domain::file::RecordKind)>, SyncSqliteError>;

    /// Every current row's path and kind -- the rows [`Self::list_files_with_kind`]
    /// lists, tombstones included, without decoding their content. For a pass that
    /// only needs to know which paths the index already has.
    fn list_indexed_paths_with_kind(
        &self,
        group_id: &str,
    ) -> Result<Vec<(String, yadorilink_replica_domain::file::RecordKind)>, SyncSqliteError>;

    /// Re-verifies an already-established root's identity, requiring the
    /// persisted root-identity token rather than silently adopting an
    /// unmarked-but-corroborated root. See
    /// [`yadorilink_root_authority::root_identity::VerifiedRoot::verify`].
    fn verify_root(
        &self,
        root: &Path,
        group_id: &str,
    ) -> Result<yadorilink_root_authority::root_identity::VerifiedRoot, SyncSqliteError>;

    /// Establishes a root's identity for the one-time initial scan, which
    /// may silently adopt an unmarked-but-corroborated root. See
    /// [`yadorilink_root_authority::root_identity::VerifiedRoot::open`].
    fn open_root(
        &self,
        root: &Path,
        group_id: &str,
    ) -> Result<yadorilink_root_authority::root_identity::VerifiedRoot, SyncSqliteError>;
}

#[cfg(test)]
mod tests;
