//! The capability surface `evict_file`'s function family
//! (`materialization_eviction.rs`) and `repair_interrupted_materializations`/
//! `reconcile_restore_operations`/`quarantine_dirty_disk_file`'s
//! (`materialization_repair.rs`) need from whatever concrete state backs
//! them. Covers exactly the method surface a direct grep of every
//! `state.<method>(` call across those two files' production code finds,
//! plus
//! one semantic operation (`reclaim_verified_cached_blocks`) whose
//! custody/pin/materialization-state revalidation is owned by the concrete
//! state (`ReplicaCoordinator::reclaim_cached_blocks` in
//! `yadorilink-daemon`), since it reads across repositories this crate
//! cannot name.
//!
//! `impl MaterializationExecutionPort for ReplicaCoordinator` stays in
//! `yadorilink-daemon` (orphan rule -- `ReplicaCoordinator` is
//! daemon-local), mirroring `LocalMutationStore`'s own precedent exactly: the trait *definition* crosses the crate line,
//! the impl does not.

use std::path::Path;
use std::sync::Arc;

use yadorilink_local_storage::{BlockReclamationStore, GcReport, PlaceholderDiskIdentity};
use yadorilink_replica_domain::file::{FileRecord, RecordKind};
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_replica_engine::custody::VerifiedCustody;
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_root_authority::root_identity::VerifiedRoot;

use crate::block_liveness::BlockPhysicalDeletionGuard;
use yadorilink_replica_domain::session_state::{RestoreCommitOutcome, RestoreOperation};

/// What an open materialization intent is for, as the materialization owner
/// classifies it ([`MaterializationExecutionPort::materialization_intent_kind`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterializationIntentKind {
    /// A write of content to the path is in flight. A missing file under
    /// it is an interrupted write, and repair may rebuild it.
    Materialize,
    /// A removal of the path is in flight (a tombstone delete). A missing
    /// file under it is where the delete was heading: repair must not
    /// rebuild it, and leaves the path to the outstanding delete.
    Delete,
}

/// What an eviction that failed after it opened (the row `Evicting`, the
/// fence bumped) knows about the path, which decides the state
/// [`MaterializationExecutionPort::abandon_eviction`] leaves the row in.
#[derive(Debug, Clone)]
pub enum AbandonedEviction {
    /// The placeholder write did not happen, and the lane re-verified under
    /// the path lock that the file is still the one it revalidated before
    /// the open (same disk identity, bytes matching the evicted version's
    /// blocks), and observed its `identity`. The row goes back to
    /// `Present` with a proof of that version published under the live
    /// fence.
    Intact { identity: yadorilink_fs_platform::fs_identity::FileIdentity },
    /// The placeholder write did not happen, but the file no longer
    /// verifies (a local edit or removal landed during the attempt) or
    /// could not be observed. The row goes back to `Present` without a
    /// proof: an edit is the watcher's and the dirty-path journal's to
    /// capture, and the repair sweep re-proves bytes that do match.
    NotWritten,
    /// The placeholder may be on disk: the native dehydrate's outcome is
    /// unknown ([`MaterializationExecutionError::EvictionOutcomeAmbiguous`]),
    /// or the placeholder was written and the settle failed. The row goes
    /// to `Remote`, the resolution the startup reset gives a stale
    /// `Evicting` row, which is safe whether or not the write landed.
    PlaceholderMayExist,
}

/// An open, durably-recorded materialization intent for one path, returned
/// by [`MaterializationExecutionPort::open_materialization_intent_guard`].
/// Opaque here (the concrete guard is `yadorilink-daemon`'s own
/// `MaterializationIntentGuard<'_>`, which borrows a concrete
/// `&ReplicaCoordinator` a trait object can't name) -- the only operation
/// any caller ever performs on one is clearing it once the write it guards
/// is durable. Dropping without calling `clear` is itself meaningful: the
/// intent stays recorded, so the next repair pass treats a missing file at
/// this path as a crash to recover, not an offline delete. Mirrors
/// `yadorilink-peer-session::ports::OpenMaterializationIntent` exactly --
/// `MaterializationIntentGuard` implements one marker trait per consumer
/// crate, since neither can depend on the other.
pub trait OpenMaterializationIntent: Send {
    fn clear(self: Box<Self>) -> Result<(), MaterializationExecutionError>;
}

/// The unconditional, pre-lock reads `evict_file` performs to decide
/// whether a path is even a candidate for eviction at all -- the atomic
/// current-version snapshot and the record's kind. Grouped into one
/// semantic read because `evict_file` always performs both together, with
/// no intervening mutation between them.
#[derive(Debug, Clone)]
pub struct EvictionEligibilitySnapshot {
    pub current_version: Option<yadorilink_replica_domain::session_state::CurrentVersionRecord>,
    pub record_kind: Option<RecordKind>,
}

/// The reads `evict_file` re-performs *after* acquiring the per-path lock,
/// to re-verify nothing raced the eligibility check above before the
/// placeholder write commits -- this IS the "permit/lease re-verification
/// point" this module's behavioral invariants require stay pinned to this
/// precise point in the control flow.
#[derive(Debug, Clone)]
pub struct EvictionRevalidationSnapshot {
    pub current_version: Option<yadorilink_replica_domain::session_state::CurrentVersionRecord>,
    pub materialization_state: Option<MaterializationState>,
    pub path_dirty: bool,
    /// The user asked for the path to be kept on this device. Read here, under the same lock
    /// as the rest, so a pin set before the commit point is never overtaken by an eviction.
    pub pinned: bool,
}

/// The reads `repair_interrupted_materializations_inner`'s per-path loop
/// re-performs under the path lock, before deciding whether a `Present`
/// row is a genuine interrupted-materialization candidate.
#[derive(Debug, Clone, Default)]
pub struct RepairRowSnapshot {
    pub materialization_state: Option<MaterializationState>,
    pub record_kind: Option<RecordKind>,
    pub file: Option<FileRecord>,
    /// The raw symlink target the same row records, for a caller
    /// verifying a symlink by kind -- carried rather than read separately,
    /// so it comes from the same statement as `current_version`.
    pub symlink_target: Option<Vec<u8>>,
    /// The version the current row names. Carried on the snapshot rather
    /// than fetched where it is used: every proof this repair pass
    /// publishes has to name it, and this snapshot is already the one
    /// consolidated read the per-path loop performs under the path lock.
    /// A separate accessor would add a read to every row of a sweep that
    /// runs at whole-replica scale.
    pub current_version: Option<yadorilink_replica_domain::ids::VersionHash>,
    /// The mode and the replicated xattrs this row records, from that
    /// same statement.
    ///
    /// Carried, not fetched where they are applied. Every repair arm
    /// that writes a file follows it with a real `chmod` and
    /// `fsetxattr`, and both fields are hashed into `current_version` --
    /// so re-reading them after the bytes are down applies one
    /// incarnation's metadata under another incarnation's proof, and the
    /// exactness gate cannot catch it, because it verifies against the
    /// same row that supplied the wrong value.
    pub unix_mode: Option<u32>,
    pub xattrs: Vec<(String, Vec<u8>)>,
}

/// This crate's own error type for the materialization/eviction/repair
/// filesystem-execution path -- `yadorilink-daemon`'s `SyncError` cannot be
/// reused here without a forbidden dependency edge back onto that crate
/// (this crate is a dependency OF `yadorilink-daemon`, not the reverse).
/// Every variant mirrors one `SyncError` variant the `evict_file` family
/// (`materialization_eviction.rs`/`materialization_repair.rs`) actually
/// constructs or matches on, same message text, so error reporting stays
/// byte-identical for anything wrapping the message string -- same shape as
/// `yadorilink-peer-session`'s `PeerSessionError`. `yadorilink-daemon`'s own
/// `impl From<SyncError> for MaterializationExecutionError` bridges
/// `SyncError` -> this type at the port boundary (used inside `impl
/// MaterializationExecutionPort for ReplicaCoordinator`'s own `?`-sites);
/// `impl From<MaterializationExecutionError> for SyncError` (in
/// `yadorilink-daemon`, since `SyncError` is the foreign type from this
/// crate's perspective) bridges the other direction for any caller of the
/// `evict_file` family that still needs a plain `SyncError`.
#[derive(Debug, thiserror::Error)]
pub enum MaterializationExecutionError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("corrupt local state: {0}")]
    CorruptState(String),

    #[error("eviction of {0:?} was rejected")]
    EvictionRejected(String),

    /// A reconstruct wrote the bytes and mode, but the replicated extended
    /// attributes it set could not be confirmed, so it has no exact proof.
    /// Path-local and retriable, like any other failed reconstruct.
    #[error("replicated extended attributes not proven: {0}")]
    ReplicatedXattrsNotProven(String),

    /// A `dehydrate_windows_placeholder` call's outcome could not be
    /// determined. Not every returned error means dehydration did NOT
    /// happen: `dehydrate_server`
    /// performs the real `CfDehydratePlaceholder` call BEFORE writing its
    /// response, so a transport-level failure (timeout, a dropped pipe,
    /// the response never arriving) can happen AFTER the native dehydrate
    /// already succeeded server-side -- the daemon genuinely cannot tell
    /// the two apart from a bare I/O error or timeout. Unlike
    /// `EvictionRejected` (a coherent response was received, so the
    /// server's own logic ran to completion and its answer is trusted),
    /// this variant must NOT be treated as "the file is still fully
    /// materialized" -- `evict_file` must not roll the row back to
    /// `Present`. It resolves the row to `Remote` instead
    /// ([`AbandonedEviction::PlaceholderMayExist`]), the resolution
    /// `reset_stale_evicting`'s startup recovery gives a
    /// stale `Evicting` row, which is safe regardless of which of the two
    /// real outcomes actually happened (see that function's own doc
    /// comment; Windows eviction never mints a fresh identity,
    /// which is exactly what makes resolving to `Remote` safe in
    /// both cases).
    #[error("eviction outcome for {0:?} could not be confirmed")]
    EvictionOutcomeAmbiguous(String),

    /// The group's policy has not loaded this run, so a change-emitting
    /// write withheld its emission rather than stamp a placeholder-auth
    /// change. See `yadorilink_replica_domain::local_op::PolicyUnavailable`.
    #[error("no verified policy is currently loaded for this group")]
    PolicyUnavailable,

    #[error(
        "materialization target {0:?} resolved outside its sync root (symlinked path component?)"
    )]
    PathEscapesRoot(String),

    #[error("disk pressure on {volume}: {available_bytes} bytes available, {headroom_bytes} required for {path}")]
    DiskPressure { path: String, volume: String, available_bytes: u64, headroom_bytes: u64 },

    // No `#[from]` -- `StorageError::DiskPressure`/`PathEscapesRoot` special-case
    // into the two variants above instead of being buried in this generic
    // variant, so a caller matching on `MaterializationExecutionError` alone
    // can still tell them apart without reaching into the wrapped
    // `StorageError`. Mirrors `SyncError`/`PeerSessionError`'s own identical
    // reasoning.
    #[error("storage error: {0}")]
    Storage(yadorilink_local_storage::StorageError),

    #[error("root authority error: {0}")]
    RootAuthority(#[from] yadorilink_root_authority::RootAuthorityError),
}

impl MaterializationExecutionError {
    /// Whether this failure belongs to the one path an operation was
    /// working on (its file could not be read, written, renamed or
    /// observed; it was busy, rejected, missing, or escaped the root), so a
    /// sweep over many paths may record it and go on to the next. Anything
    /// else -- a database or invariant failure (`CorruptState`, which is
    /// also what a SQLite error arrives as), a lost root or permit, a
    /// group-wide policy gap, volume-wide disk pressure -- is not, and
    /// aborts the sweep.
    ///
    /// `Io` and `NotFound` do not say by themselves whether the cause was
    /// the path or the group, so group-wide causes are caught where they
    /// can be told apart: every eviction re-verifies the root before it
    /// touches anything and the repair sweep verifies it before its first
    /// path (a missing link or root token, a missing marker, an unmounted
    /// or replaced root all fail as `RootAuthority`), and both sweeps
    /// re-verify their permit before continuing past a path-local failure,
    /// because an owner transaction reports a lost root as `Io`.
    pub fn is_path_local(&self) -> bool {
        use yadorilink_local_storage::StorageError as S;
        match self {
            Self::Io(_)
            | Self::NotFound(_)
            | Self::EvictionRejected(_)
            | Self::ReplicatedXattrsNotProven(_)
            | Self::EvictionOutcomeAmbiguous(_)
            | Self::PathEscapesRoot(_) => true,
            Self::Storage(storage) => {
                matches!(storage, S::Io(_) | S::InvalidPath(_) | S::PathEscapesRoot(_))
            }
            Self::CorruptState(_)
            | Self::PolicyUnavailable
            | Self::DiskPressure { .. }
            | Self::RootAuthority(_) => false,
        }
    }
}

impl From<yadorilink_local_storage::StorageError> for MaterializationExecutionError {
    fn from(error: yadorilink_local_storage::StorageError) -> Self {
        match error {
            yadorilink_local_storage::StorageError::DiskPressure {
                path,
                volume,
                available_bytes,
                headroom_bytes,
            } => MaterializationExecutionError::DiskPressure {
                path: path.display().to_string(),
                volume: volume.display().to_string(),
                available_bytes,
                headroom_bytes,
            },
            yadorilink_local_storage::StorageError::PathEscapesRoot(path) => {
                MaterializationExecutionError::PathEscapesRoot(path)
            }
            other => MaterializationExecutionError::Storage(other),
        }
    }
}

/// The structural-directory ledger of one group, as the materializer's
/// `mkdir` helper (`yadorilink_local_storage::
/// create_dir_all_never_through_a_symlink`) records into it: every
/// directory created for a descendant goes through the owner's two-phase
/// origin protocol on `port`.
pub struct GroupStructuralLedger<'a> {
    port: &'a dyn MaterializationExecutionPort,
    group_id: &'a str,
    names: GroupTempLedger<'a>,
}

impl<'a> GroupStructuralLedger<'a> {
    pub fn new(port: &'a dyn MaterializationExecutionPort, group_id: &'a str) -> Self {
        Self { port, group_id, names: GroupTempLedger::new(port, group_id) }
    }
}

fn ledger_error(error: MaterializationExecutionError) -> yadorilink_local_storage::StorageError {
    yadorilink_local_storage::StorageError::Io(std::io::Error::other(format!(
        "structural-directory ledger: {error}"
    )))
}

impl yadorilink_local_storage::StructuralDirectoryLedger for GroupStructuralLedger<'_> {
    fn names(&self) -> &dyn yadorilink_local_storage::TempFileLedger {
        &self.names
    }

    fn record_intent(&self, rel_path: &str) -> Result<(), yadorilink_local_storage::StorageError> {
        self.port.record_structural_directory_intent(self.group_id, rel_path).map_err(ledger_error)
    }

    fn complete(
        &self,
        rel_path: &str,
        identity: &yadorilink_fs_platform::fs_identity::FileIdentity,
    ) -> Result<(), yadorilink_local_storage::StorageError> {
        self.port
            .complete_structural_directory_origin(self.group_id, rel_path, identity)
            .map_err(ledger_error)
    }

    fn abandon(&self, rel_path: &str) -> Result<(), yadorilink_local_storage::StorageError> {
        self.port.abandon_structural_directory_intent(self.group_id, rel_path).map_err(ledger_error)
    }

    fn interrupted(&self, rel_path: &str) -> Result<(), yadorilink_local_storage::StorageError> {
        self.port
            .resolve_interrupted_structural_intent(self.group_id, rel_path)
            .map_err(ledger_error)
    }
}

/// The temp-file ledger of one group, over the port: a writer in
/// `yadorilink-local-storage` records the temp file it will create through it.
pub struct GroupTempLedger<'a> {
    port: &'a dyn MaterializationExecutionPort,
    group_id: &'a str,
}

impl<'a> GroupTempLedger<'a> {
    pub fn new(port: &'a dyn MaterializationExecutionPort, group_id: &'a str) -> Self {
        Self { port, group_id }
    }
}

impl yadorilink_local_storage::TempFileLedger for GroupTempLedger<'_> {
    fn record(
        &self,
        tmp_path: &std::path::Path,
    ) -> Result<(), yadorilink_local_storage::StorageError> {
        self.port.record_temp_file(self.group_id, tmp_path).map_err(|error| {
            yadorilink_local_storage::StorageError::Io(std::io::Error::other(format!(
                "temp file ledger: {error}"
            )))
        })
    }

    fn release(&self, tmp_path: &std::path::Path) {
        self.port.release_temp_file(self.group_id, tmp_path);
    }

    fn strand(
        &self,
        dir_path: &std::path::Path,
    ) -> Result<(), yadorilink_local_storage::StorageError> {
        self.port.record_stranded_directory(self.group_id, dir_path).map_err(|error| {
            yadorilink_local_storage::StorageError::Io(std::io::Error::other(format!(
                "stranded directory ledger: {error}"
            )))
        })
    }
}

pub trait MaterializationExecutionPort: Send + Sync {
    /// Durably records the temp file a writer is about to create (see
    /// `yadorilink_local_storage::TempFileLedger`).
    fn record_temp_file(
        &self,
        group_id: &str,
        tmp_path: &Path,
    ) -> Result<(), MaterializationExecutionError>;

    /// Forgets a recorded temp file once it is renamed away or removed.
    fn release_temp_file(&self, group_id: &str, tmp_path: &Path);

    /// Records a directory a durable removal moved aside and could not put
    /// back, so status can report it (see
    /// `yadorilink_local_storage::TempFileLedger::strand`).
    fn record_stranded_directory(
        &self,
        group_id: &str,
        dir_path: &Path,
    ) -> Result<(), MaterializationExecutionError>;

    fn get_file(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<FileRecord>, MaterializationExecutionError>;

    /// Whether `group_id`'s link has opted in to writing real Windows
    /// symlinks -- see `yadorilink-peer-session`'s identically-named
    /// method (the live materialize path's own policy source) for the
    /// full reasoning. Repair's symlink-recovery path must respect the
    /// same policy the live path does, or it could write a real symlink
    /// on a Windows link that has explicitly opted out.
    fn windows_symlink_opt_in_for_group(
        &self,
        group_id: &str,
    ) -> Result<bool, MaterializationExecutionError>;

    /// Every file's materialization state for a group, in one query.
    fn list_materialization_states(
        &self,
        group_id: &str,
    ) -> Result<
        std::collections::HashMap<String, MaterializationState>,
        MaterializationExecutionError,
    >;

    /// What the intent open on `path` is for, if one is open: the
    /// materialization owner's classification of its target. Repair acts
    /// on the kind, never on the raw target.
    fn materialization_intent_kind(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<MaterializationIntentKind>, MaterializationExecutionError>;

    /// Whether the write open on `path` recorded that its bytes were renamed
    /// into place, durably, and nothing has proven or moved it since. A path
    /// that is missing then was removed or moved by the user after the write
    /// placed it; with the intent alone it cannot be told from a write that
    /// crashed before the rename.
    fn write_landed_unproven(
        &self,
        _group_id: &str,
        _path: &str,
    ) -> Result<bool, MaterializationExecutionError> {
        Ok(false)
    }

    /// For a path whose write intent waits for the batch flush of a received
    /// file (the write's proof was published, its file may not have reached
    /// stable storage): the identity that proof recorded for the file. `None`
    /// when the path has no such intent, or the proof it waits for no longer
    /// stands; `Some(None)` when the proof records no identity. A repair that
    /// finds the file torn may rebuild it in place only if it is still the
    /// very object the proof describes.
    fn flush_pending_proof_identity(
        &self,
        _group_id: &str,
        _path: &str,
    ) -> Result<
        Option<Option<yadorilink_fs_platform::fs_identity::FileIdentity>>,
        MaterializationExecutionError,
    > {
        Ok(None)
    }

    /// Whether `path` currently has a REMOTE-origin row in the projection-
    /// obligation worklist (any state, including the parked
    /// `ignore_blocked` state) -- a live, per-path, always-authoritative
    /// read; never cached or snapshotted. A LOCAL-origin row (this
    /// device's own local emission, whose bytes were already observed on
    /// this device's own disk before the change was admitted) is
    /// deliberately excluded: it never represents content not yet placed.
    ///
    /// While a REMOTE-origin projection obligation exists for a path, an
    /// absent local file must not yet be interpreted as an offline user
    /// deletion: the Convergence Engine still considers this path's
    /// desired state unsettled (freshly admitted, mid-materialize-retry,
    /// or otherwise not yet placed -- see this method's own callers for
    /// the "not yet settled, not settled-but-wrong" scope this signal
    /// covers, and does not). This is a SEPARATE signal from `materialization_intent_kind`/
    /// `list_materialization_intent_paths`: an intent exists only for the
    /// narrow window of one in-flight physical write, while an obligation
    /// can be outstanding long before any write is ever attempted (or
    /// after one that keeps retrying) -- repair must check both, not
    /// either alone, before concluding a missing-with-no-intent path was
    /// genuinely deleted.
    ///
    /// Deliberately per-path, not a whole-pass snapshot the way
    /// `list_materialization_intent_paths` is: that shape trades staleness
    /// risk for cost on the (very common) `outstanding_intents` case,
    /// which is fine there -- see that method's own doc comment -- because
    /// its worst case is merely deferring a moot cleanup by one pass. This
    /// method instead gates the tombstone-vs-reconstruct DECISION itself, on
    /// only the rare rows that are already `Present`-but-disk-mismatched,
    /// where a stale miss could let a real, still-unsettled path fall
    /// through to be wrongly resolved. On that small a candidate set, one
    /// extra authoritative read per row costs nothing worth trading
    /// correctness for.
    fn has_unsettled_projection_obligation(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, MaterializationExecutionError>;

    /// Every path in `group_id` that currently carries a materialization
    /// intent, as one read.
    ///
    /// The intent journal is empty in steady state -- an intent exists only
    /// between a materialize opening one and the same materialize clearing it,
    /// or after a crash in that window. A sweep over the whole group therefore
    /// wants to know the (tiny) set ONCE rather than asking, or blindly
    /// writing, per path: see `materialization_repair`'s own use of this.
    fn list_materialization_intent_paths(
        &self,
        group_id: &str,
    ) -> Result<std::collections::HashSet<String>, MaterializationExecutionError>;

    /// Clears the durable materialization-write-in-progress intent once the
    /// write + rename + fsync has completed for `(group_id, path)`.
    fn clear_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit,
    ) -> Result<(), MaterializationExecutionError>;

    fn record_dirty_path(
        &self,
        group_id: &str,
        path: &str,
        change_kind: &str,
        observed_at_unix_nanos: i64,
        permit: &RootCommitPermit,
    ) -> Result<(), MaterializationExecutionError>;

    /// Of `paths`, the settled regular files: `Present`, with a usable proof
    /// naming the version the row names now (what
    /// [`Self::has_usable_materialized_generation`] answers for one path), read
    /// for all of them at once. A path in doubt is left out.
    fn settled_file_paths(
        &self,
        group_id: &str,
        paths: &[&str],
    ) -> Result<std::collections::HashSet<String>, MaterializationExecutionError>;

    /// Whether `(group_id, path)`'s standing proof is a proof about the
    /// version the row currently names -- the whole of what
    /// `MaterializationState::Present` claims exists, not just its
    /// presence. Fail-closed: a generation published under a superseded
    /// mutation fence is NOT usable, nor is one that names a version the
    /// path has moved off, nor a versionless one, nor no generation at
    /// all -- and this cannot tell those apart on purpose.
    fn has_usable_materialized_generation(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, MaterializationExecutionError>;

    /// Whether the regular file at `out_path` is, untouched, what a usable
    /// proof says this device wrote at `path` -- whichever version the row
    /// now names. `Present` says only that an object exists; this is the
    /// evidence that separates an older version's bytes still standing under
    /// a newer row from an edit. Fail-closed: any doubt is `false`.
    fn disk_is_untouched_proven_write(
        &self,
        group_id: &str,
        path: &str,
        out_path: &Path,
    ) -> Result<bool, MaterializationExecutionError>;

    /// The recovery lane's own commit, for a path this pass has verified
    /// byte for byte and now has to FINISH: publish the proof, promote the
    /// row, and clear the intent, in ONE transaction, with the guard
    /// re-evaluated inside it against the live row.
    ///
    /// Distinct from both sibling commits, which the repair lane now
    /// reaches only through owner operations (the internal commit and the
    /// re-proving call in `yadorilink-daemon`'s `materialization_owner`),
    /// and the gap between them is why it exists. The internal commit is
    /// anchored on an epoch its caller bumped before its own write;
    /// recovery mutated nothing and owns no such epoch. The re-proving
    /// call is fence-free but deliberately leaves `materialization_state`
    /// alone, which is right for a row already `Present` and not enough
    /// for one still in the transient state an interrupted
    /// materialization left.
    ///
    /// `false` means the row was superseded between the caller's
    /// verification and this commit; nothing was written, the intent
    /// included.
    fn commit_recovered_materialized_state(
        &self,
        group_id: &str,
        path: &str,
        state: yadorilink_peer_session::ports::ExactActualState,
        expected: yadorilink_peer_session::ports::ExpectedAuthoring<'_>,
        permit: &RootCommitPermit,
    ) -> Result<bool, MaterializationExecutionError>;

    /// The identity currently recorded on `(group_id, path)`'s row,
    /// regardless of its current `materialization_state` -- unlike
    /// `MaterializationStateRepository::record_placeholder_generation`'s
    /// read counterpart in
    /// `MaterializationStateRepository::get_placeholder_generation` (gated to
    /// `materialization_state = 'placeholder'`, so it deliberately returns
    /// nothing once a row has hydrated), no production call site clears
    /// `placeholder_dev`/`placeholder_ino`/`placeholder_provider_kind` on the
    /// `Remote` -> `Present` transition -- they are simply left in
    /// place until an explicit clear ([`Self::record_placeholder_identity`]'s
    /// `Clear` arm).
    /// The Windows eviction path relies on exactly that: it reads a
    /// `Present` file's still-recorded generation here as the expected
    /// identity to pass into the native dehydrate call -- an extra
    /// defense-in-depth check on top of the disk-content revalidation
    /// `evict_file` already performs, not a substitute for it.
    fn get_recorded_placeholder_identity(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<(PlaceholderDiskIdentity, String)>, MaterializationExecutionError>;

    /// Asks the real Windows CfAPI provider process
    /// (`yadorilink-cfapi-host.exe`) to natively dehydrate the placeholder
    /// at `out_path` (an absolute path), blocking until it confirms
    /// success or failure. `expected_generation`: the generation
    /// [`Self::get_recorded_placeholder_identity`] returned for this row,
    /// passed through as a defense-in-depth ABA guard (see
    /// `crates/yadorilink-shell-ext-windows/src/cfapi.rs::dehydrate_placeholder`'s own doc
    /// comment). The guard is mandatory: eviction refuses a row with no
    /// recorded identity before reaching this call. `materialization_eviction::
    /// evict_to_placeholder`'s Windows arm gates the `Remote`
    /// transition and block reclamation on this call's success; its
    /// non-Windows arm never calls it at all.
    ///
    /// An implementor MUST return
    /// [`MaterializationExecutionError::EvictionOutcomeAmbiguous`], never
    /// [`MaterializationExecutionError::EvictionRejected`], for any
    /// failure mode that cannot positively rule out the native dehydrate
    /// having actually succeeded (a transport timeout, a dropped
    /// connection, a response that never arrived) -- see that variant's
    /// own doc comment for why `evict_file`'s caller handles the two
    /// differently.
    ///
    /// The default implementation (used by every platform except Windows,
    /// where nothing calls this) fails closed with `EvictionRejected` --
    /// there is no real provider to ask at all, so there is no ambiguity:
    /// dehydration definitely did not happen.
    fn dehydrate_windows_placeholder(
        &self,
        _path: &str,
        _out_path: &Path,
        _expected_generation: u64,
    ) -> Result<(), MaterializationExecutionError> {
        Err(MaterializationExecutionError::EvictionRejected(
            "native Windows placeholder dehydration is not supported on this platform".to_string(),
        ))
    }

    /// Every held path of `group_id` whose disk has not yet been
    /// reconciled. See `crate::held_path_reconcile`.
    fn list_held_paths(
        &self,
        group_id: &str,
    ) -> Result<
        Vec<yadorilink_replica_domain::session_state::HeldPath>,
        MaterializationExecutionError,
    >;

    /// Announces that the reconciliation of a held path is about to change
    /// what is on disk under it (remove, move aside, or place a
    /// placeholder), invalidating any proof or in-flight writer that read
    /// the path before. Called once, before the first such change.
    fn begin_held_path_disk_write(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), MaterializationExecutionError>;

    /// Releases a held path at `generation` once its disk agrees with the
    /// installed row read at that generation, and in the same transaction
    /// schedules the installed row's projection when it is live. Returns
    /// whether it was released: `false` when an install renewed the hold
    /// since, which leaves it held.
    fn release_held_path(
        &self,
        group_id: &str,
        path: &str,
        generation: i64,
    ) -> Result<bool, MaterializationExecutionError>;

    /// Phase 1 of a structural `mkdir` of `path` (a directory this device
    /// is about to create only to hold a descendant): records the intent
    /// and moves the path's mutation fence, durably, before the syscall.
    /// See `yadorilink_sync_sqlite::structural_origin`.
    fn record_structural_directory_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), MaterializationExecutionError>;

    /// Phase 2 of a structural `mkdir` that created the directory: binds
    /// the pending intent to the identity observed on it. Records nothing
    /// (and says nothing) when the intent is gone or the fence moved; the
    /// directory is then `OriginUnknown`, which keeps it and authors
    /// nothing.
    fn complete_structural_directory_origin(
        &self,
        group_id: &str,
        path: &str,
        identity: &yadorilink_fs_platform::fs_identity::FileIdentity,
    ) -> Result<(), MaterializationExecutionError>;

    /// Phase 2 of a structural `mkdir` that did not create the directory
    /// (`EEXIST`, or any failure): drops the pending intent, claiming
    /// nothing.
    fn abandon_structural_directory_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), MaterializationExecutionError>;

    /// A `mkdir` writer leaving with its intent unsettled: resolves that one
    /// intent as startup recovery would.
    fn resolve_interrupted_structural_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), MaterializationExecutionError>;

    /// Whether a live current index row of `group_id` lies strictly below
    /// `path`: whether the rows the index holds need `path` as a directory.
    /// The held-path reconciliation's view of the namespace, since
    /// an installed base's rows are what its disk has to match.
    fn index_has_live_descendant(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, MaterializationExecutionError>;

    /// Whether `observed`, the directory now at `path`, is one this device
    /// created (or adopted) only to hold descendants, per the
    /// structural-origin ledger: the one kind of directory it may remove
    /// once nothing needs it and it is empty.
    fn is_structural_directory(
        &self,
        group_id: &str,
        path: &str,
        sync_root: &Path,
        observed: &yadorilink_fs_platform::fs_identity::FileIdentity,
    ) -> Result<bool, MaterializationExecutionError>;

    /// Records the directory now at `path` (`identity`) as structural: its
    /// explicit entry is gone while live descendants keep it on disk, so it
    /// goes with the last of them instead of staying as a directory of
    /// unknown origin.
    fn adopt_as_structural_directory(
        &self,
        group_id: &str,
        path: &str,
        identity: &yadorilink_fs_platform::fs_identity::FileIdentity,
    ) -> Result<(), MaterializationExecutionError>;

    /// Records that the directory at `path` stays on disk, settled, because
    /// it holds content this device does not replicate (D4: nothing
    /// untracked is ever deleted). `removable` is the identity of the
    /// directory this device placed there, which may go once it is empty;
    /// `None` keeps whatever is there for good.
    fn retain_directory_with_untracked_content(
        &self,
        group_id: &str,
        path: &str,
        removable: Option<&yadorilink_fs_platform::fs_identity::FileIdentity>,
    ) -> Result<(), MaterializationExecutionError>;

    /// Settles a directory removed from disk: nothing is structural or
    /// retained at `path` any more.
    fn forget_removed_directory(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), MaterializationExecutionError>;

    /// Acquires the per-`(group_id, path)` lock so a materialization write
    /// cannot race a concurrent local capture or peer reconciliation of the
    /// same path.
    fn path_lock(&self, group_id: &str, path: &str) -> Arc<tokio::sync::Mutex<()>>;

    /// Every open crash-safe restore-journal entry for `group_id`.
    fn list_restore_operations(
        &self,
        group_id: &str,
    ) -> Result<Vec<RestoreOperation>, MaterializationExecutionError>;

    /// Atomically publishes the exact journaled restore version and removes
    /// its recovery marker, verifying `permit` inside that transaction.
    fn commit_restore_operation(
        &self,
        operation_id: &str,
        identity: Option<&yadorilink_fs_platform::fs_identity::FileIdentity>,
        wrote_under_mutation_generation: Option<i64>,
        permit: &RootCommitPermit,
    ) -> Result<RestoreCommitOutcome, MaterializationExecutionError>;

    /// Drops a restore-journal entry that recovery determined no longer
    /// needs replaying.
    fn discard_restore_operation(
        &self,
        operation_id: &str,
    ) -> Result<(), MaterializationExecutionError>;

    /// Re-verifies an already-established root's identity, requiring the
    /// persisted root-identity token. Added as a narrow delegate because
    /// `VerifiedRoot::verify` needs `&dyn RootVerificationStatePort`, and a
    /// caller holding only `&dyn MaterializationExecutionPort` cannot
    /// produce one -- Rust does not let a trait object be treated as a
    /// different trait object its own trait was never declared to imply.
    fn verify_root(
        &self,
        root: &Path,
        group_id: &str,
    ) -> Result<VerifiedRoot, MaterializationExecutionError>;

    /// Establishes a root's identity, which may silently adopt an
    /// unmarked-but-corroborated root. Added as a narrow delegate for the
    /// same reason as `verify_root` above.
    fn open_root(
        &self,
        root: &Path,
        group_id: &str,
    ) -> Result<VerifiedRoot, MaterializationExecutionError>;

    /// Opens the single sanctioned materialization-intent seam for
    /// `(group_id, path)`. Added as a narrow delegate (rather than exposing
    /// `&ReplicaCoordinator` itself) because the concrete guard borrows a
    /// concrete `&'a ReplicaCoordinator`, which a trait object can't
    /// produce; the implementation runs inside `impl
    /// MaterializationExecutionPort for ReplicaCoordinator`, where `self`
    /// already is that concrete `&ReplicaCoordinator`.
    fn open_materialization_intent_guard<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        target_version_hash: &[u8],
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<Box<dyn OpenMaterializationIntent + Send + 'a>, MaterializationExecutionError>;

    /// Semantic-operation read replacing `evict_file`'s three unconditional
    /// pre-lock CRUD reads with one snapshot-shaped call. See
    /// [`EvictionEligibilitySnapshot`]'s own doc comment.
    fn eviction_eligibility_snapshot(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<EvictionEligibilitySnapshot, MaterializationExecutionError>;

    /// Semantic-operation read replacing the four-CRUD-call re-verification
    /// `evict_file` performs immediately after acquiring the per-path lock
    /// -- the "permit/lease re-verification point". See
    /// [`EvictionRevalidationSnapshot`]'s own doc comment.
    fn eviction_revalidation_snapshot(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<EvictionRevalidationSnapshot, MaterializationExecutionError>;

    /// Semantic-operation read replacing the three-CRUD-call re-check
    /// `repair_interrupted_materializations_inner`'s per-path loop performs
    /// under the path lock. See [`RepairRowSnapshot`]'s own doc comment.
    fn repair_row_snapshot(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<RepairRowSnapshot, MaterializationExecutionError>;

    /// Reclaims the cached blocks of a path whose eviction custody was
    /// verified, under the exclusive physical-deletion guard. The
    /// implementor revalidates the custody's exact version, the pin and
    /// materialization state, and the custody confirmation itself before
    /// freeing any block no other indexed row still references.
    ///
    /// `siblings` are other placeholders sharing blocks with the path, whose own exact-version
    /// custody was verified too: the blocks only they still reference are freed with this one.
    /// A sibling that no longer qualifies by then stays a reference.
    fn reclaim_verified_cached_blocks(
        &self,
        deletion_guard: &BlockPhysicalDeletionGuard<'_>,
        custody: VerifiedCustody<'_>,
        siblings: Vec<VerifiedCustody<'_>>,
        store: &dyn BlockReclamationStore,
    ) -> Result<GcReport, MaterializationExecutionError>;

    /// The other current placeholder rows `(group, path, exact version)` that share a block with
    /// `blocks`. Their retained blocks are the only thing that can keep an eviction's blocks
    /// alive once the last hydrated referrer is gone.
    fn remote_siblings_sharing_blocks(
        &self,
        group_id: &str,
        path: &str,
        blocks: &[yadorilink_replica_domain::file::VersionBlock],
    ) -> Result<
        Vec<(String, String, yadorilink_replica_domain::file::FileVersion)>,
        MaterializationExecutionError,
    >;

    /// Bumps `path`'s filesystem-side mutation fence, invalidating any
    /// actual-state proof
    /// `path_materialized_generations` may hold for it. `evict_file` has no
    /// native-frontier proof of its own to publish under (it is a pure
    /// disk-state transition, hydrated content -> placeholder), so it only
    /// ever calls this, never a publish -- same treatment as on-demand
    /// hydration (`ReplicaCoordinator::dag_bump_mutation_fence` in
    /// `yadorilink-daemon`). Must be called inside
    /// `path`'s lock, before the first mutating syscall.
    fn dag_bump_mutation_fence(
        &self,
        group_id: &str,
        path: &str,
        mutation_kind: &str,
    ) -> Result<i64, MaterializationExecutionError>;

    /// Open half of `evict_file`'s placeholder write, after its
    /// revalidation: marks the row `Evicting` (its own transaction; an
    /// error here fails the eviction with nothing else touched), then bumps
    /// the fence for the placeholder write (its own transaction). The
    /// bump's result is returned inside: the caller chains it into the
    /// placeholder write and treats its failure as that write's, closing
    /// the row with [`abandon_eviction`](Self::abandon_eviction).
    fn open_eviction(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit,
    ) -> Result<Result<i64, MaterializationExecutionError>, MaterializationExecutionError>;

    /// Settle half of `evict_file`'s placeholder write: moves the row
    /// `Evicting` -> `Remote` only if it is still `Evicting`
    /// (`false`, with nothing else written, when it is not), then records
    /// the identity the placeholder write reported. Two transactions.
    fn settle_eviction(
        &self,
        group_id: &str,
        path: &str,
        placeholder: yadorilink_local_storage::PlaceholderIdentityToRecord,
        permit: &RootCommitPermit,
    ) -> Result<bool, MaterializationExecutionError>;

    /// Close half of an eviction that failed after
    /// [`open_eviction`](Self::open_eviction) returned, so the row does
    /// not stay `Evicting` until the next daemon start. Acts only while
    /// the row is still `Evicting` (`false`, with nothing written, when it
    /// is not), and moves it to the state `abandoned` names -- or to
    /// `Remote` when the row no longer names `version`, the version
    /// the eviction revalidated, since that row's content was never on
    /// disk. One transaction, with the permit verified inside it: under a
    /// lost root nothing is written and the row is left for the startup
    /// reset.
    fn abandon_eviction(
        &self,
        group_id: &str,
        path: &str,
        version: &yadorilink_replica_domain::ids::VersionHash,
        abandoned: AbandonedEviction,
        permit: &RootCommitPermit,
    ) -> Result<bool, MaterializationExecutionError>;

    /// Records the identity a placeholder write reported for
    /// `(group_id, path)`: overwrite, record only if absent (a concurrent
    /// winner's value is kept), or clear. One transaction for whichever
    /// arm applies.
    fn record_placeholder_identity(
        &self,
        group_id: &str,
        path: &str,
        outcome: yadorilink_local_storage::PlaceholderIdentityToRecord,
        permit: &RootCommitPermit,
    ) -> Result<(), MaterializationExecutionError>;

    /// First step of the repair sweep's placeholder demotion, before the
    /// placeholder write: moves the row to `Remote` only while it is
    /// still in `row_state` and, when named, `version`
    /// (one transaction). `false` means the row moved off what the lane
    /// read, and the lane must write nothing for it: not the placeholder
    /// it would size for the version it read, not its identity, and not
    /// the intent clear.
    fn open_repair_placeholder_demotion(
        &self,
        group_id: &str,
        path: &str,
        row_state: MaterializationState,
        version: Option<&yadorilink_replica_domain::ids::VersionHash>,
        permit: &RootCommitPermit,
    ) -> Result<bool, MaterializationExecutionError>;

    /// Open half of the repair sweep's quarantine of divergent on-disk
    /// bytes: opens the intent naming the content the path will be rebuilt
    /// to, then bumps the fence for the quarantine rename. Two
    /// transactions, in that order. The caller holds the returned intent
    /// across the rename and drops it uncleared.
    fn open_repair_quarantine<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        target_version_hash: &[u8],
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<Box<dyn OpenMaterializationIntent + Send + 'a>, MaterializationExecutionError>;

    /// Settle half of the repair sweep's journaled reconstruct of a regular
    /// file written under `mutation_generation`: publishes the proof for
    /// `version` with the identity now at `out_path`, guarded on the row
    /// still being in `row_state` with `version`; when
    /// nothing was published (no version, no identity, a failed or refused
    /// commit), demotes that same row to `Hydrating`, leaving the intent
    /// open so the next repair pass finds a candidate to prove. Logs every
    /// failure and returns none; `true` means the proof was published.
    // Mirrors the lane's own inputs one for one; a params struct would
    // exist only to carry them across this one call.
    #[allow(clippy::too_many_arguments)]
    fn settle_repair_reconstruct(
        &self,
        group_id: &str,
        path: &str,
        out_path: &Path,
        row_state: MaterializationState,
        version: Option<yadorilink_replica_domain::ids::VersionHash>,
        mutation_generation: i64,
        permit: &RootCommitPermit,
    ) -> bool;

    /// Open half of the repair sweep's journaled rebuild of a single
    /// object with no block content (a symlink, an explicit directory):
    /// bumps the fence for the rebuild, then opens the intent naming
    /// `target_version_hash`. Two transactions, in that order. Returns the
    /// fence value to publish under and the intent, which the caller drops
    /// uncleared once the object is written.
    fn open_repair_object_rebuild<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        kind: RecordKind,
        target_version_hash: &[u8],
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<(i64, Box<dyn OpenMaterializationIntent + Send + 'a>), MaterializationExecutionError>;

    /// Settle half of the repair sweep's journaled rebuild of a `kind`
    /// object: publishes the proof for `version` with the identity observable at
    /// `out_path` under `mutation_generation`, guarded on the row still
    /// being in `row_state` with `version` when a state was
    /// found. `false` when the fence was lost or the row superseded.
    // Mirrors the lane's own inputs one for one, like
    // `settle_repair_reconstruct`.
    #[allow(clippy::too_many_arguments)]
    fn settle_repair_object_rebuild(
        &self,
        group_id: &str,
        path: &str,
        kind: RecordKind,
        out_path: &Path,
        version: yadorilink_replica_domain::ids::VersionHash,
        row_state: Option<MaterializationState>,
        mutation_generation: i64,
        permit: &RootCommitPermit,
    ) -> Result<bool, MaterializationExecutionError>;

    /// Restore-journal recovery's preservation of bytes neither side of an
    /// interrupted restore explains: journals `path` as dirty with
    /// `change_kind` and `observed_at_unix_nanos`, then discards the
    /// journal entry. Two transactions, in that order.
    fn preserve_divergent_restore(
        &self,
        operation_id: &str,
        group_id: &str,
        path: &str,
        change_kind: &str,
        observed_at_unix_nanos: i64,
        permit: &RootCommitPermit,
    ) -> Result<(), MaterializationExecutionError>;
}
