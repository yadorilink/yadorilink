//! Full and reconcile scans: the initial `scan_existing_files*` entry
//! points, the add-only backstop, and the disk-vs-index reconciliation
//! pass (`reconcile_disk_pass`) with its per-path `PreparedMutation`.

use std::path::Path;

use crate::error::LocalCaptureError;
use crate::scan_block_staging::ScanBlockStaging;
use yadorilink_filesystem_sync::watcher::FsChangeKind;
use yadorilink_fs_platform::fs_identity::{disk_race_fingerprint_of_at, metadata_mtime_matches};
use yadorilink_fs_platform::ignore_patterns::EffectiveIgnoreSet;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::file::{FileRecord, RecordKind};
use yadorilink_replica_domain::ids::SyncPath;
use yadorilink_replica_domain::local_op::{encoded_op_len, Op};
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_replica_domain::session_state::{LocalFileMetaColumns, PreparedLocalMutation};
use yadorilink_root_authority::root_identity::VerifiedRoot;
use yadorilink_sync_sqlite::file_index::ImportedActualState;
use yadorilink_sync_sqlite::SyncSqliteError;

use super::directory_capture::{directory_entry, DirectoryVerdict};
use super::dirty_journal::dirty_kind_str;
use super::disk_observation::{
    closed_disk_observation_if_unraced, disk_bytes_match_indexed_blocks_off_worker,
    error_means_absent, run_capture_pass_off_worker, try_exact_leaf_exists_as_directory,
    try_exact_leaf_exists_as_file_or_symlink, DiskObservation,
};
use super::path_policy::{
    is_excluded_from_sync, path_to_wire_relative_string, skip_reason_for_inadmissible_wire_path,
};
use super::record_builder::{metadata_columns_for, SymlinkClassification};
#[cfg(test)]
use super::scan_test_hooks;
use super::Predecessor;
use super::{now_unix_nanos, LocalChangeOutcome, LocalChangeProcessor};

/// Whether the file's bytes still match `existing`'s indexed blocks. An
/// unreadable file is not current: the capture that follows reads it again
/// and reports the failure through [`unreadable_file`].
fn indexed_bytes_match(
    path: &Path,
    existing: &FileRecord,
    size: u64,
) -> Result<bool, yadorilink_local_storage::StorageError> {
    match disk_bytes_match_indexed_blocks_off_worker(path, &existing.blocks, size) {
        Err(yadorilink_local_storage::StorageError::SourceRead(_)) => Ok(false),
        other => other,
    }
}

/// True when `rel_path` (a root-relative index path, `/`-separated) sits
/// under any of the `failed_prefixes` a partial scan collected — the
/// root-relative directories the walk could not read. Matching is on whole
/// path components (`Path::starts_with`), so `foo` matches `foo/bar` but not
/// `foobar`; an empty prefix (the walk root itself failed) matches every
/// path. Used to scope offline-delete tombstone suppression to the failed
/// subtree(s) only, never tombstoning a path whose directory was unreadable.
pub(super) fn path_is_within_failed_subtree(rel_path: &str, failed_prefixes: &[String]) -> bool {
    let candidate = Path::new(rel_path);
    failed_prefixes.iter().any(|prefix| candidate.starts_with(Path::new(prefix)))
}

/// A caller-supplied per-chunk-commit observer, which returns `Err` when its
/// consumer is gone so the scan stops instead of committing chunks nobody
/// will announce, threaded through a full
/// disk scan's batched writes. Factored out (clippy type_complexity).
pub(super) type OnChunkCommitted<'a> =
    Option<&'a mut dyn FnMut(&[FileRecord]) -> Result<(), LocalCaptureError>>;

/// `OnChunkCommitted` with the borrow and the trait object's own lifetime
/// kept apart. `&mut dyn Trait` is invariant in the object lifetime, so the
/// single-lifetime form above cannot be reborrowed for a shorter span --
/// which is exactly what the single-flight wrapper has to do to hand the
/// same callback to a pass and then to its coalesced rerun.
pub(super) type ChunkCommittedSink<'cb, 'obj> =
    Option<&'cb mut (dyn FnMut(&[FileRecord]) -> Result<(), LocalCaptureError> + 'obj)>;

/// Everything one path contributes to a reconciliation scan's commit,
/// derived from ONE bracketed observation of that path.
///
/// The reconciliation scan reaches its commit from several branches — a
/// new or content-changed file, a file whose content is unchanged but
/// whose mode or xattrs diverged offline, a path that vanished — and every
/// one of them has to supply the same five things. Before this type they
/// each supplied whichever subset they happened to know about, into
/// separate path-keyed side tables that were recombined just before the
/// commit. A branch that forgot one of them did not fail to compile and
/// did not fail any assertion at the commit: it simply committed a change
/// with a piece missing.
///
/// That is not hypothetical. The metadata-only branch pushed a record and
/// a mode, and no actual-state evidence — so the commit that emitted its
/// new `FileVersion` wrote no proof, and the path kept the proof its
/// previous commit had written, naming a version native state had already
/// superseded. Nothing could close that path's projection obligation
/// afterwards, and on a device with no peer nothing ever would.
///
/// Making it one value removes the category: a branch cannot reach the
/// commit having produced part of a mutation, because there is no way to
/// express part of one. The two shapes a path can have -- an object that
/// is there, and an object that is gone -- are the two variants, so the
/// pieces only one of them has (a version, metadata columns, a disk
/// observation) are not `Option` fields every branch has to remember to
/// fill, and the other shape cannot carry them at all.
///
/// The one deliberate `Option` is the observation: a bracket that could
/// not vouch for the path yields no proof rather than a wrong one. It is
/// an observation and not evidence, because evidence is what a commit may
/// publish and this is not yet that -- see [`DiskObservation`] for the
/// window between preparing a mutation and committing it, which the
/// bracket does not span.
#[allow(
    clippy::large_enum_variant,
    reason = "boxing the present-path variant would trade a per-path heap allocation for a \
              saving that does not exist: a scan's `prepared` vector is dominated by present \
              paths, and the single struct this enum replaced was the large shape for every \
              entry, tombstones included. So this is already strictly smaller than what it \
              replaced, and the suggested box would make the common case slower on exactly \
              the scans (a whole folder, a bulk offline diff) where this vector is largest"
)]
pub(super) enum PreparedMutation {
    /// A path that is present on disk: its record, the `Op::Put`
    /// describing it, the exact `FileVersion` that op references, the
    /// index metadata columns to write in the same transaction (so the
    /// row's kind/target/mode/xattrs can never lag the version the change
    /// carries), and the disk observation all of it was derived from.
    Upsert {
        record: FileRecord,
        op: Op,
        version: FileVersion,
        meta: LocalFileMetaColumns,
        observation: Option<DiskObservation>,
    },
    /// A path that is gone: an index tombstone and the `Op::Delete` that
    /// records it. There is no object left to describe, so there is
    /// nothing observed to carry -- absence is established instead by the
    /// pre-commit re-check that runs under the path's own lock, held
    /// through the commit, and it is that re-check which supplies this
    /// mutation's `Absent` evidence.
    Delete { record: FileRecord, op: Op },
}

/// Whether disk still holds the bytes a scan read, given whether the path's
/// identity is unchanged since the read and whether that identity would
/// show an in-place rewrite that kept the length and restored the
/// modification time. When it would not (see
/// `FileIdentity::in_place_rewrite_visible`), an unchanged identity proves
/// nothing about the bytes, so they are compared themselves.
fn scanned_bytes_still_on_disk(
    identity_unchanged: bool,
    rewrite_visible: bool,
    bytes_match: impl FnOnce() -> bool,
) -> bool {
    identity_unchanged && (rewrite_visible || bytes_match())
}

#[cfg(test)]
mod scanned_bytes_still_on_disk_tests {
    use super::scanned_bytes_still_on_disk;

    #[test]
    fn an_identity_that_cannot_see_a_rewrite_defers_to_the_bytes() {
        assert!(!scanned_bytes_still_on_disk(true, false, || false));
        assert!(scanned_bytes_still_on_disk(true, false, || true));
    }

    #[test]
    fn an_identity_that_sees_rewrites_is_enough_and_the_bytes_are_not_read() {
        assert!(scanned_bytes_still_on_disk(true, true, || panic!("bytes read")));
        assert!(!scanned_bytes_still_on_disk(false, true, || panic!("bytes read")));
        assert!(!scanned_bytes_still_on_disk(false, false, || panic!("bytes read")));
    }
}

/// The path locks one commit holds through its write.
///
/// The lock registry folds names, so two names in one commit can share a
/// lock -- an offline case-only rename deletes `Report.txt` and writes
/// `report.txt` -- and tokio's mutex is not re-entrant: a second
/// `try_lock` of a lock this commit already holds would fail against the
/// commit itself and withhold half of the rename. A lock already held here
/// is simply held. Every other acquisition is a `try_lock`, so holding
/// several never waits on another holder.
#[derive(Default)]
pub(super) struct CommitPathLocks(Vec<tokio::sync::OwnedMutexGuard<()>>);

impl CommitPathLocks {
    /// Holds `lock` until this value drops; `false` when another holder
    /// has it.
    pub(super) fn try_hold(&mut self, lock: std::sync::Arc<tokio::sync::Mutex<()>>) -> bool {
        if self
            .0
            .iter()
            .any(|held| std::sync::Arc::ptr_eq(tokio::sync::OwnedMutexGuard::mutex(held), &lock))
        {
            return true;
        }
        match lock.try_lock_owned() {
            Ok(guard) => {
                self.0.push(guard);
                true
            }
            Err(_) => false,
        }
    }
}

impl PreparedMutation {
    /// The mutation for a path that is gone.
    fn tombstone(record: FileRecord) -> Self {
        let op = Op::Delete { path: SyncPath(record.path.clone()) };
        Self::Delete { record, op }
    }

    fn record(&self) -> &FileRecord {
        match self {
            Self::Upsert { record, .. } | Self::Delete { record, .. } => record,
        }
    }

    fn op(&self) -> &Op {
        match self {
            Self::Upsert { op, .. } | Self::Delete { op, .. } => op,
        }
    }

    /// The index metadata columns for this mutation, aligned with the
    /// commit's `metas` parameter: `None` for a tombstone, whose row has
    /// no kind/target/mode/xattrs to state.
    fn meta(&self) -> Option<LocalFileMetaColumns> {
        match self {
            Self::Upsert { meta, .. } => Some(meta.clone()),
            Self::Delete { .. } => None,
        }
    }
}

/// Takes the tombstones of directories removed offline out of `prepared`,
/// keyed by the topmost gone directory each was in: a path whose parent
/// is gone from disk belongs to the topmost gone ancestor, and an explicit
/// Directory row gone from disk under a present parent is that directory
/// itself. Everything else is returned in order.
fn split_offline_directory_removals(
    root: &Path,
    snapshot: &ReconcileSnapshot,
    prepared: Vec<PreparedMutation>,
) -> (std::collections::BTreeMap<String, Vec<OfflineRemovalCandidate>>, Vec<PreparedMutation>) {
    let mut removed: std::collections::BTreeMap<String, Vec<OfflineRemovalCandidate>> =
        std::collections::BTreeMap::new();
    let mut rest = Vec::with_capacity(prepared.len());
    for mutation in prepared {
        if let PreparedMutation::Delete { record, .. } = &mutation {
            let mut topmost_gone = None;
            let mut current = record.path.as_str();
            while let Some((parent, _)) = current.rsplit_once('/') {
                if std::fs::symlink_metadata(root.join(parent)).is_ok() {
                    break;
                }
                topmost_gone = Some(parent);
                current = parent;
            }
            let directory = topmost_gone
                .or_else(|| snapshot.is_directory(&record.path).then_some(record.path.as_str()));
            if let Some(directory) = directory {
                removed.entry(directory.to_string()).or_default().push(OfflineRemovalCandidate {
                    record: record.clone(),
                    native_witness: snapshot.native_witness(&record.path),
                });
                continue;
            }
        }
        rest.push(mutation);
    }
    (removed, rest)
}

/// Sleeps for the delay `diagnostics::set_snapshot_delay_ms` set
/// at the point a reconciliation pass has read the index but committed
/// nothing. A measurement seam for one specific question — "can two
/// reconciliation passes for one group overlap, and which callers are
/// they?" — which cannot be answered on a small folder otherwise: the
/// overlap window in production is however long the pass takes, and on a
/// 100-file folder that is milliseconds, while the periodic backstop that
/// races it only ticks every 90s. Widening the window is the only way to
/// make a timer-driven race land on demand instead of only on a folder
/// large enough to scan for minutes. Read fresh on every call, not cached:
/// a repro wants to arm this for one pass. Unset (every production
/// process) is one relaxed load and no sleep.
pub(super) fn diagnostic_post_snapshot_delay() {
    let ms = crate::diagnostics::snapshot_delay_ms();
    if ms == 0 {
        return;
    }
    tracing::warn!(delay_ms = ms, "diagnostic: holding a reconciliation pass after its snapshot");
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

/// One reconciliation pass's identity in the log.
///
/// Exists because "two scans of the same folder ran at once" is invisible
/// in an ordinary log: both passes emit the same per-path lines from
/// different threads, and the only trace left behind is in the committed
/// history (two signed changes per path, in adjacent chunks). A pass-scoped
/// id with a begin and an end line makes the overlap directly observable —
/// two `begin`s for one group with no `end` between them IS the bug.
///
/// `Drop` rather than an explicit end call: the pass has many `?` exits,
/// and an end line that only fires on the success path would make a pass
/// that aborted mid-way look like one that never finished.
pub(super) struct ReconcilePassTrace {
    scan_id: u64,
    caller: &'static str,
    group_id: String,
    mode: &'static str,
    started: std::time::Instant,
    prepared: usize,
    committed: usize,
}

impl ReconcilePassTrace {
    fn begin(caller: &'static str, group_id: &str, mode: ReconcileMode) -> Self {
        static NEXT_SCAN_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let scan_id = NEXT_SCAN_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mode = if mode.is_full() { "full" } else { "add_only" };
        tracing::info!(
            scan_id,
            caller,
            group_id,
            mode,
            "RECONCILE_PASS begin: reconciliation pass started"
        );
        Self {
            scan_id,
            caller,
            group_id: group_id.to_string(),
            mode,
            started: std::time::Instant::now(),
            prepared: 0,
            committed: 0,
        }
    }

    fn record_counts(&mut self, prepared: usize, committed: usize) {
        self.prepared = prepared;
        self.committed = committed;
    }
}

impl Drop for ReconcilePassTrace {
    fn drop(&mut self) {
        tracing::info!(
            scan_id = self.scan_id,
            caller = self.caller,
            group_id = %self.group_id,
            mode = self.mode,
            elapsed_ms = self.started.elapsed().as_millis() as u64,
            prepared = self.prepared,
            committed = self.committed,
            "RECONCILE_PASS end: reconciliation pass finished"
        );
    }
}

/// The whole-index snapshot one reconciliation pass judges disk against:
/// read once, before the walk, and consulted by every later phase. Two
/// passes holding the same stale snapshot is the failure `reconcile_gate`
/// exists to close, so a pass never refreshes it midway.
struct ReconcileSnapshot {
    existing_by_path: std::collections::HashMap<String, FileRecord>,
    /// Each row's kind: whether a directory-only ignore pattern covers a
    /// row cannot be asked of a path that is gone from disk.
    kind_by_path: std::collections::HashMap<String, RecordKind>,
    /// What native showed at each path it knows, read BEFORE the rows above
    /// so a head landing in between makes a commit stale rather than
    /// unseen. A path missing here was absent to native.
    native_witness_by_path: std::collections::HashMap<
        String,
        yadorilink_replica_domain::native_state::NativeCaptureWitness,
    >,
    materialization_by_path: std::collections::HashMap<String, MaterializationState>,
    placeholder_generation_by_path:
        std::collections::HashMap<String, yadorilink_sync_sqlite::RecordedPlaceholderGeneration>,
}

impl ReconcileSnapshot {
    fn native_witness(
        &self,
        path: &str,
    ) -> yadorilink_replica_domain::native_state::NativeCaptureWitness {
        self.native_witness_by_path
            .get(path)
            .cloned()
            .unwrap_or_else(|| yadorilink_sync_sqlite::native_capture::absent_native_witness(path))
    }

    fn is_directory(&self, path: &str) -> bool {
        self.kind_by_path.get(path) == Some(&RecordKind::Directory)
    }
}

/// One path a folder removal found gone: the tombstone record and what
/// native showed at it in the pass's snapshot.
struct OfflineRemovalCandidate {
    record: FileRecord,
    native_witness: yadorilink_replica_domain::native_state::NativeCaptureWitness,
}

/// What a pass's walk established: the mutations it prepared, in walk
/// order, and how far its inventory of disk can be trusted when the
/// tombstone phase reads a path's absence from `seen_paths` as a deletion.
struct ReconcileWalk {
    prepared: Vec<PreparedMutation>,
    seen_paths: std::collections::HashSet<String>,
    /// `false` when a walk error could not be attributed to a subtree, which
    /// suppresses tombstoning for the whole pass.
    scan_complete: bool,
    /// Root-relative prefixes of the subtrees the walk could not read; no
    /// path under one is tombstoned.
    failed_prefixes: Vec<String>,
}

/// Max ops in a single reconciliation-emitted change. Matches the initial
/// import's [`yadorilink_replica_domain::local_op::IMPORT_BATCH_OP_LIMIT`] so a
/// bulk offline diff converts into a chain of same-sized changes whichever
/// path (import or reconcile) first observes it, and stays far under the
/// change decoder's hard [`yadorilink_replica_domain::limits::MAX_OPS`]
/// (65536) per-change ceiling.
pub(super) const RECONCILE_CHUNK_OP_LIMIT: usize =
    yadorilink_replica_domain::local_op::IMPORT_BATCH_OP_LIMIT;

/// Max canonical op-bytes in a single reconciliation-emitted change. A change
/// cannot be wire-split, so one change must fit in one delivered
/// `ChangeBatch` message, and every peer-protocol message lane bounds its
/// frame size (the service lane's `MAX_SERVICE_MESSAGE_BYTES` is 1 MiB).
/// 256 KiB stays well under that (leaving room for the
/// change's fixed header, parents, and signature, and letting several changes
/// still share one batch message) while a pathological run of long paths — up
/// to `RECONCILE_CHUNK_OP_LIMIT` * ~4 KiB ≈ 4 MiB if bounded by op-count
/// alone — is instead split by this byte cap. At least one op is always taken
/// per chunk, so a single over-cap op (never possible: one op is at most a
/// 4 KiB-ish path plus 37 bytes) could not wedge the loop. Shares
/// [`yadorilink_replica_domain::local_op::MAX_CHANGE_OP_BYTES`] with the initial import so the two
/// byte bounds can never drift.
pub(super) const RECONCILE_CHUNK_BYTE_LIMIT: usize =
    yadorilink_replica_domain::local_op::MAX_CHANGE_OP_BYTES;

/// How much of a disk-vs-index reconciliation scan is allowed to mutate
/// the index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReconcileMode {
    /// The full startup / burst-fallback reconciliation: index new files,
    /// re-version files whose on-disk content changed, drop now-ignored
    /// rows, and tombstone indexed files no longer on disk.
    Full { emit_tombstones: bool },
    /// Add-only: index *only* files present on disk with no existing index
    /// row. Never re-versions a file that already has a row and never
    /// tombstones a row whose path isn't on disk. This is the sole
    /// disk-reconcile shape safe to run on a frequent, unconditional
    /// schedule (the periodic backstop for OS-watcher event loss): a
    /// file with no index row has never been broadcast and so cannot
    /// collide with a
    /// concurrent mid-conflict resolution the way re-versioning or
    /// tombstoning an already-known path can (the hazard `watcher.rs`'s
    /// module doc documents as "found unsafe").
    AddOnly,
}

/// Whether the link root is still the volume the index was built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CaptureAuthority {
    /// The persisted identity equals the root's current one (or the group has
    /// no link row to record one on): absence on disk is delete evidence.
    Confirmed,
    /// A link created by an older build, with no identity recorded yet. The
    /// current identity is adopted by the first safe full scan, which authors
    /// no deletes; nothing is inferred about earlier history.
    Unrecorded(String),
    /// The root is on another volume than the one recorded, on one only the
    /// user can confirm, or its volume cannot be observed. Nothing under it
    /// may be tombstoned.
    Refused,
}

impl ReconcileMode {
    fn is_full(self) -> bool {
        matches!(self, Self::Full { .. })
    }

    fn is_add_only(self) -> bool {
        matches!(self, Self::AddOnly)
    }

    fn emits_tombstones(self) -> bool {
        matches!(self, Self::Full { emit_tombstones: true })
    }
}

impl LocalChangeProcessor {
    /// The single place the reconciliation scan builds a mutation for a
    /// path that is still present, whatever branch discovered it.
    ///
    /// Every input is one observation's worth of the same path:
    /// `record` (its content, from the index or a fresh chunking),
    /// `classification`/`unix_mode`/`xattrs` (its metadata as just read
    /// from disk), and `observation` (`Some` only when the fingerprint
    /// bracketing all of the above still matched at the end — see
    /// [`closed_disk_observation_if_unraced`]).
    ///
    /// The version and the metadata columns are derived here from those
    /// same values, so the proof the commit writes from `observation` is a
    /// proof about the exact `FileVersion` the commit emits. Deriving
    /// either one a second time somewhere closer to the commit — re-reading
    /// the xattrs, re-deriving the version from the index row — is what
    /// makes a proof and a live head two answers to one question instead of
    /// one answer recorded twice.
    pub(super) fn prepare_present_mutation(
        &self,
        record: FileRecord,
        classification: Option<SymlinkClassification>,
        unix_mode: Option<u32>,
        xattrs: Vec<(String, Vec<u8>)>,
        observation: Option<DiskObservation>,
    ) -> PreparedMutation {
        let symlink_target = classification.as_ref().map(|c| c.target.clone());
        let (op, version) = self.content_op(&record, unix_mode, symlink_target, xattrs.clone());
        // A symlink carries neither an exec bit nor xattrs, matching what
        // `content_op` just put in the version's own `FileMeta`.
        let exec_for_meta = if classification.is_some() { None } else { Some(unix_mode) };
        let meta = metadata_columns_for(&classification, exec_for_meta, xattrs);
        PreparedMutation::Upsert { record, op, version, meta, observation }
    }

    /// Indexes every pre-existing file under `root` that isn't already
    /// indexed (`sync-engine` spec's "Initial Full Sync" requirement).
    /// Necessary because a filesystem watcher, by nature, only reports
    /// changes from the moment it starts — files already present when a
    /// folder is linked (or created while the daemon wasn't running)
    /// would otherwise never enter the index at all. Call once, before
    /// starting the live watch on `root`.
    ///
    /// Skips files whose size already matches an existing, non-deleted
    /// index entry, so restarting the daemon doesn't spuriously bump every
    /// unchanged file's version vector on every scan.
    ///
    /// The existing index and
    /// materialization states are bulk-loaded once up front (rather than
    /// one `get_file`/`get_materialization_state` query per walked entry),
    /// and every newly-indexed or changed record is committed in a single
    /// transaction at the end — so a folder with a very large number of
    /// pre-existing files (e.g. a git repository's `.git/objects/`) scans
    /// in a bounded number of SQLite round trips rather than one per file.
    pub fn scan_existing_files(
        &self,
        group_id: &str,
        root: &Path,
    ) -> Result<Vec<FileRecord>, LocalCaptureError> {
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(root)?;
        self.scan_existing_files_with_ignore(group_id, root, &ignore_set)
    }

    pub fn scan_existing_files_with_ignore(
        &self,
        group_id: &str,
        root: &Path,
        ignore_set: &EffectiveIgnoreSet,
    ) -> Result<Vec<FileRecord>, LocalCaptureError> {
        let root = self.verified_root(group_id, root)?;
        self.reconcile_disk_with_ignore(
            group_id,
            &root,
            ignore_set,
            ReconcileMode::Full { emit_tombstones: true },
            None,
            "scan_existing_files_with_ignore",
        )
    }

    /// Streaming sibling of `scan_existing_files_with_ignore`: identical
    /// scan/commit behavior and return value, but `on_chunk_committed` is
    /// called once per reconciliation chunk right after that chunk's own
    /// durable commit -- see `reconcile_disk_with_ignore`'s own doc for the
    /// exact guarantee (never before a commit, never for a withheld chunk).
    pub fn scan_existing_files_with_ignore_streaming(
        &self,
        group_id: &str,
        root: &Path,
        ignore_set: &EffectiveIgnoreSet,
        on_chunk_committed: &mut dyn FnMut(&[FileRecord]) -> Result<(), LocalCaptureError>,
    ) -> Result<Vec<FileRecord>, LocalCaptureError> {
        let root = self.verified_root(group_id, root)?;
        self.reconcile_disk_with_ignore(
            group_id,
            &root,
            ignore_set,
            ReconcileMode::Full { emit_tombstones: true },
            Some(on_chunk_committed),
            "scan_existing_files_with_ignore_streaming",
        )
    }

    /// Same as `scan_existing_files_with_ignore`, but lets the caller suppress
    /// this pass's missing-file tombstone emission via `emit_tombstones`.
    ///
    /// The startup crash-vs-offline-delete disambiguation depends on the
    /// interrupted-materialization repair pass having run first: repair is what
    /// distinguishes a crash-mid-materialize (missing target, blocks present
    /// locally, an open materialization intent -> reconstruct) from an offline
    /// user delete (missing target, no intent -> tombstone). When that repair
    /// pass ERRORED for this group on this boot, its disambiguation input is
    /// unavailable, so a `Present`-but-missing file cannot be safely told apart
    /// from a genuine deletion. Passing `emit_tombstones = false` then defers
    /// ALL of this scan's delete emission to a later boot on which repair
    /// succeeds — fail-closed: never emit a delete when a crash cannot be told
    /// from a delete. A path is still indexed/updated as usual; only the
    /// missing-file tombstone step is withheld.
    ///
    /// `emit_tombstones = true` reproduces `scan_existing_files_with_ignore`
    /// exactly.
    pub fn scan_existing_files_with_ignore_gated(
        &self,
        group_id: &str,
        root: &Path,
        ignore_set: &EffectiveIgnoreSet,
        emit_tombstones: bool,
    ) -> Result<Vec<FileRecord>, LocalCaptureError> {
        let root = self.verified_root(group_id, root)?;
        self.reconcile_disk_with_ignore(
            group_id,
            &root,
            ignore_set,
            ReconcileMode::Full { emit_tombstones },
            None,
            "scan_existing_files_with_ignore_gated",
        )
    }

    /// The full reconciliation scan `DebounceFlush::RescanRequired` drives
    /// from the LIVE flush loop -- a watcher-channel/OS overflow, or
    /// simply editing this link's own `.yadorilinkignore`, both ordinary
    /// triggers requiring no crash -- once this link's startup barrier has
    /// already resolved. Unlike `scan_existing_files_with_ignore[_gated/
    /// _streaming]` above (the one-time initial scan
    /// `yadorilink-daemon::link_manager::start_link_watch` runs exactly
    /// once, before the live watch begins), this runs repeatedly for the
    /// rest of an established link's lifetime, concurrently with peer
    /// apply, on-demand hydration, and the periodic repair sweep.
    ///
    /// Two independent things the three functions above get structurally
    /// right for the one-time initial scan, and this one must get right
    /// for the live, repeating case instead:
    ///
    /// - `verified_root_of_established_link`, not `verified_root`: `open`
    ///   (what `verified_root` uses) can silently ADOPT an unmarked-but-
    ///   corroborated root and does not check `sync_root_lock`'s live
    ///   ownership registry -- correct ONLY for the one-time scan that
    ///   runs before the watch starts. See that method's own doc comment
    ///   for the sidecar-unlink-and-recreate race this closes for every
    ///   OTHER already-established-link caller; this one used to be the
    ///   sole exception.
    /// - `emit_tombstones` is a caller-supplied parameter here, not
    ///   hardcoded `true`: a live rescan must respect the identical
    ///   fail-closed gates the startup scan itself was gated on (this
    ///   boot's materialization-repair success, ANDed with the two-live-
    ///   roots recovery flag) -- omitting them here silently defeated
    ///   both for the entire live lifetime of every link, deterministically,
    ///   no race required. The caller is responsible for re-reading the
    ///   live recovery flag fresh for each call (not reusing a value
    ///   frozen at link-start), since that flag can be armed or cleared at
    ///   any point during an established link's life -- see
    ///   `yadorilink-daemon`'s executor task for how it combines the two.
    pub fn scan_existing_files_with_ignore_gated_for_established_link(
        &self,
        group_id: &str,
        root: &Path,
        ignore_set: &EffectiveIgnoreSet,
        emit_tombstones: bool,
        on_chunk_committed: OnChunkCommitted<'_>,
    ) -> Result<Vec<FileRecord>, LocalCaptureError> {
        let root = self.verified_root_of_established_link(group_id, root)?;
        self.reconcile_disk_with_ignore(
            group_id,
            &root,
            ignore_set,
            ReconcileMode::Full { emit_tombstones },
            on_chunk_committed,
            "scan_existing_files_with_ignore_gated_for_established_link",
        )
    }

    /// Establishes this link's root identity for a caller that has only a path.
    ///
    /// Every public reconcile entry point funnels through here, so verification
    /// is unconditional: there is no entry point that scans an unverified root,
    /// and `reconcile_disk_with_ignore`'s `&VerifiedRoot` parameter is what
    /// makes that structural rather than a convention a new entry point could
    /// quietly break.
    ///
    /// Uses [`VerifiedRoot::open`], which can silently ADOPT an unmarked-but-
    /// corroborated root and does not check the in-process
    /// `sync_root_lock::HELD_ROOT_IDENTITIES` registry — appropriate ONLY for
    /// the one-time "initial full sync" (`scan_existing_files*`) that
    /// `yadorilink-daemon`'s `LinkRuntimeController::start` runs exactly once,
    /// after it has already acquired this root's `SyncRootLock`, before the
    /// live watch and the periodic backstop begin. A caller that runs
    /// repeatedly for the lifetime of an established watch must use
    /// [`Self::verified_root_of_established_link`] instead — see that
    /// method's own doc for why `open` is the wrong primitive once a link is
    /// already running.
    pub(super) fn verified_root(
        &self,
        group_id: &str,
        root: &Path,
    ) -> Result<VerifiedRoot, LocalCaptureError> {
        Ok(self.state.open_root(root, group_id)?)
    }

    /// Re-verifies this link's root identity for a caller that runs
    /// repeatedly against an already-established, already-watched link —
    /// the live event handler (`process_event*`) and the periodic add-only
    /// backstop (`reconcile_added_files*`), both of which run for as long as
    /// `yadorilink-daemon`'s `LinkRuntimeController::start` holds this root's
    /// `SyncRootLock`.
    ///
    /// Uses [`VerifiedRoot::verify`], not `open`: `open` can silently ADOPT
    /// an unmarked-but-corroborated root (the correct behavior for the
    /// one-time initial scan, wrong here) and — the gap this method closes —
    /// does not check `sync_root_lock::verify_registered_root_ownership`.
    /// Without that check, the sidecar-unlink-and-recreate race
    /// `SyncRootLock::verify_still_owns`'s own doc describes (a live holder's
    /// OS lock survives its own sidecar being unlinked out from under it; a
    /// second process can then create-and-lock a brand-new object at the
    /// same pathname, and both processes correctly believe they exclusively
    /// own the root) goes undetected by every call that funnels through
    /// `open` instead — closed for eviction/materialization by
    /// `VerifiedRoot::verify`'s own wiring, but previously open here: the
    /// live watcher and periodic backstop kept authoring local changes,
    /// updating the index and emitting tombstones against a root whose
    /// exclusive ownership this process had actually lost.
    pub(super) fn verified_root_of_established_link(
        &self,
        group_id: &str,
        root: &Path,
    ) -> Result<VerifiedRoot, LocalCaptureError> {
        Ok(self.state.verify_root(root, group_id)?)
    }

    /// The add-only disk reconcile the periodic backstop runs. Walks
    /// `root` and returns/indexes a `FileRecord` only for a regular file
    /// or symlink that is present on disk but has **no** existing index
    /// row — recovering a local write whose OS filesystem-watcher event
    /// was never delivered (e.g. it fell into an FSEvents stream-recreate
    /// blind window, see `watcher.rs`'s module doc). It
    /// never re-versions an already-indexed file whose on-disk content
    /// changed and never tombstones an indexed file missing from disk (both
    /// of which `scan_existing_files_with_ignore` does): those mutate an
    /// already-known path and are unsafe to run this often (they can
    /// re-derive or false-delete a file mid-conflict-resolution between two
    /// devices). Indexing a file that has no row yet is byte-for-byte what a
    /// live create event would have done, so it carries none of that hazard.
    pub fn reconcile_added_files_with_ignore(
        &self,
        group_id: &str,
        root: &Path,
        ignore_set: &EffectiveIgnoreSet,
    ) -> Result<Vec<FileRecord>, LocalCaptureError> {
        // Root identity is still verified, even though this scope cannot
        // tombstone and so cannot cause the loss that motivates the check. The
        // converse hazard is what makes it worth paying for here: an add-only
        // walk of a *wrong* filesystem indexes that volume's files as new
        // members of this group and pushes them to every device. That is not
        // silent loss, but it is silent pollution, and this is a periodic
        // backstop — it would land repeatedly and unattended.
        //
        // `verified_root_of_established_link`, not `verified_root`: this is
        // the recurring backstop for an already-running watch, not the
        // one-time initial scan — see that method's own doc.
        let root = self.verified_root_of_established_link(group_id, root)?;
        self.reconcile_disk_with_ignore(
            group_id,
            &root,
            ignore_set,
            ReconcileMode::AddOnly,
            None,
            "reconcile_added_files_with_ignore",
        )
    }

    /// Like `reconcile_added_files_with_ignore`, but loads `root`'s ignore
    /// set itself — the periodic backstop's own convenience entry point,
    /// mirroring `scan_existing_files`'s relationship to `scan_existing_
    /// files_with_ignore`.
    pub fn reconcile_added_files(
        &self,
        group_id: &str,
        root: &Path,
    ) -> Result<Vec<FileRecord>, LocalCaptureError> {
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(root)?;
        self.reconcile_added_files_with_ignore(group_id, root, &ignore_set)
    }

    /// The final check before a scan authors content it read at `path`:
    /// `true` when it is safe to author now, with the path's lock held in
    /// `locks` through the commit; `false` when it is not, with the path
    /// already left to be captured again (or, for an unfinished write's
    /// pre-image, to that write's retry).
    ///
    /// A write of a path holds its lock from the transaction that moves the
    /// row to the version it writes until those bytes are proven, so while
    /// it is held the row can be ahead of disk: bytes the scan read then are
    /// the version being replaced, and authoring them would put that older
    /// content over the newer version. Native's witness cannot tell -- it
    /// saw the row already at the newer version. So the upsert commits only
    /// under the lock and only while disk is still exactly what the scan
    /// read: the rule a debounced flush commits under. A path whose lock is
    /// busy is journaled once the holder releases it; one that changed since
    /// the read is journaled now, under its lock. Bytes that are the
    /// pre-image of a write still open over the path (one that failed after
    /// moving the row) are not authored either, and not journaled: that
    /// write's retry owns the path.
    fn recheck_scanned_upsert(
        &self,
        group_id: &str,
        root: &Path,
        record: &FileRecord,
        version: &FileVersion,
        observation: Option<DiskObservation>,
        locks: &mut CommitPathLocks,
    ) -> Result<bool, LocalCaptureError> {
        let path = record.path.as_str();
        #[cfg(test)]
        scan_test_hooks::fire_pre_upsert_commit_recheck(group_id, path);
        if !locks.try_hold(self.state.path_lock(group_id, path)) {
            tracing::info!(
                group_id,
                path,
                "a path the scan read is being written; capturing it again once the write \
                 releases it"
            );
            self.journal_uncaptured_once_unlocked(group_id, path);
            return Ok(false);
        }
        let disk_path = root.join(path);
        let still_as_read = observation.is_some_and(|observation| {
            scanned_bytes_still_on_disk(
                observation.identity_if_still_current(&disk_path).is_some(),
                version.meta.record_kind != RecordKind::File
                    || yadorilink_fs_platform::fs_identity::FileIdentity::in_place_rewrite_visible(
                        &disk_path,
                    ),
                || {
                    yadorilink_local_storage::disk_bytes_match_indexed_blocks(
                        &disk_path,
                        &record.blocks,
                    )
                    .unwrap_or(false)
                },
            )
        });
        if !still_as_read {
            tracing::info!(
                group_id,
                path,
                "a path changed on disk after the scan read it; capturing it again instead of \
                 authoring what the scan read"
            );
            self.journal_uncaptured_local_edit(group_id, path, now_unix_nanos())?;
            return Ok(false);
        }
        // Not journaled: the open write's own retry owns the path, and a
        // capture of these bytes would find nothing to author either.
        if self.authors_pre_image_of_open_write(group_id, record, version)? {
            return Ok(false);
        }
        Ok(true)
    }

    /// See [`CaptureAuthority`]. Never updates a recorded identity: following a
    /// changed volume would legitimise the empty mountpoint it leaves behind.
    pub(super) fn capture_authority(
        &self,
        group_id: &str,
        root: &Path,
    ) -> Result<CaptureAuthority, LocalCaptureError> {
        let Some(stored) = self.state.capture_volume_identity(group_id)? else {
            return Ok(CaptureAuthority::Confirmed);
        };
        use yadorilink_filesystem_sync::device_boundary::{root_volume_identity, VolumeMatch};
        let Ok(current) = root_volume_identity(root) else {
            return Ok(CaptureAuthority::Refused);
        };
        Ok(match (VolumeMatch::of(stored.as_deref(), &current), stored) {
            (VolumeMatch::Same, Some(_)) => CaptureAuthority::Confirmed,
            (VolumeMatch::Same, None) => CaptureAuthority::Unrecorded(current),
            (VolumeMatch::Other | VolumeMatch::Unconfirmed, _) => CaptureAuthority::Refused,
        })
    }

    /// The single choke point every disk reconcile passes through, and the
    /// reason it takes a [`VerifiedRoot`] rather than a `&Path`.
    ///
    /// A scan is *authoritative*: a path it does not find on disk becomes a
    /// tombstone that propagates to every device. That is only sound if the
    /// directory walked is genuinely this link's folder, which an existence
    /// check cannot establish — an unmounted volume leaves its mountpoint
    /// behind as an empty directory that passes every such check, and the scan
    /// then reads a whole folder as deleted. `VerifiedRoot` is the proof that
    /// the check ran, carried in the type rather than repeated at each call
    /// site, so a future entry point cannot reintroduce the gap by forgetting
    /// it: there is no way to hand this function a root without having verified
    /// one first. It also arrives already canonical, which subsumes the bare
    /// `root.canonicalize()?` this used to open with — the walked entries must
    /// relativize against the same resolution `process_event` performs
    /// internally, or `strip_prefix` silently fails for every entry (the same
    /// class of mismatch that function's own doc comment warns about for OS
    /// watchers).
    /// `on_chunk_committed`, when present, is called synchronously once per
    /// reconciliation chunk immediately after that chunk's own durable
    /// commit succeeds (right where `committed.extend_from_slice` already
    /// runs below) -- never before, and never for a chunk withheld by
    /// `PolicyUnavailable`. This lets a caller (see `scan_existing_files_
    /// with_ignore_streaming`) observe already-durable progress before the
    /// whole scan returns, without this function's own return contract
    /// changing at all: every existing caller passes `None` and sees
    /// byte-identical behavior. A full reconciliation already commits in
    /// bounded chunks (this loop's own doc comment above); without the
    /// callback nothing would surface that progress until this function
    /// returned -- for a 15k-file scan, withholding peer visibility for the
    /// whole scan's length (tens of seconds) even though most of the work
    /// was already durable far earlier.
    /// A `try_lock_owned` + fresh disk/veto re-check for ONE tombstone
    /// candidate, immediately before it is trusted -- shared by both the
    /// candidacy filter in `reconcile_disk_with_ignore`'s main loop and
    /// the final pre-commit re-verification right before each chunk
    /// actually writes. `Ok(true)` means safe to tombstone THIS
    /// instant, with the path's lock held in `locks`, which must stay held
    /// until the write this check is protecting actually lands (a caller
    /// that drops it immediately closes nothing -- see the call sites' own
    /// comments).
    /// `Ok(false)` means not safe right now (contended, protected, or the
    /// path exists again) -- skip this candidate for this pass.
    pub(super) fn recheck_tombstone_candidate(
        &self,
        group_id: &str,
        root: &Path,
        path: &str,
        locks: &mut CommitPathLocks,
    ) -> Result<bool, LocalCaptureError> {
        // `try_lock`, never a blocking `lock`: mirrors
        // `materialization_repair.rs`'s own established pattern for the
        // identical shape of problem (a synchronous sweep racing an async
        // mutator that holds this same lock) -- contention itself is the
        // answer, not something to wait out. If a real mutator is
        // actively working on this exact path right now, that alone
        // proves the "genuinely missing, nothing in progress"
        // precondition for a tombstone does not hold.
        if !locks.try_hold(self.state.path_lock(group_id, path)) {
            return Ok(false);
        }
        // Exact-name, not `std::fs::symlink_metadata(...).is_ok()`: on a
        // case- or Unicode-normalization-insensitive filesystem (macOS,
        // Windows), a direct path lookup resolves to whatever sibling
        // happens to case/normalization-fold to the same name, wrongly
        // reporting "still exists" for a path that is, under its OWN
        // exact spelling, genuinely gone -- the identical case-fold
        // hazard this whole investigation is about, just in the disk
        // check instead of the index. Also mirrors the walk's own
        // `is_file() || is_symlink()` admission predicate, not a bare
        // existence check: a directory (or fifo/socket/device) now
        // occupying this exact name is not "the file still exists" any
        // more than it was during the walk itself, which would have
        // skipped it the same way.
        // A failed look (EIO, EACCES, a stale network handle, ...) is no evidence of
        // absence: only a genuinely missing name counts. Defer; the next pass retries.
        match try_exact_leaf_exists_as_file_or_symlink(root, path) {
            Ok(false) => {}
            Ok(true) => return Ok(false),
            Err(error) if error_means_absent(&error) => {}
            Err(error) => {
                tracing::warn!(
                    group_id,
                    path,
                    %error,
                    "offline-tombstone candidate deferred: its directory could not be listed"
                );
                return Ok(false);
            }
        }
        // Under (or at) a directory now on another device: the walk does not
        // cross it, so absence here is not delete evidence.
        if yadorilink_filesystem_sync::device_boundary::path_crosses_device_boundary(root, path) {
            return Ok(false);
        }
        if self.capture_authority(group_id, root)? != CaptureAuthority::Confirmed {
            return Ok(false);
        }
        // Absence is delete evidence only for a `Present` object (see
        // `prepare_offline_tombstones`). Read under the lock held above, so a
        // row that became `Remote`, `Hydrating` or `Evicting` since the
        // candidate was accepted is no longer one.
        if self.state.get_materialization_state(group_id, path)?
            != Some(MaterializationState::Present)
        {
            return Ok(false);
        }

        // An explicit Directory row is present while a directory stands at
        // its exact name. The walk skips directories, so without this every
        // settled Directory would read as an offline deletion here and be
        // signed as a group-wide Delete. A directory at a File or Symlink
        // row's name is still that row's deletion, as above.
        let directory_present = match try_exact_leaf_exists_as_directory(root, path) {
            Ok(present) => present,
            Err(error) if error_means_absent(&error) => false,
            Err(error) => {
                tracing::warn!(
                    group_id,
                    path,
                    %error,
                    "offline-tombstone candidate deferred: its directory could not be listed"
                );
                return Ok(false);
            }
        };
        if directory_present
            && self.state.canonical_current_row(group_id, path)?.is_some_and(|row| {
                !row.snapshot.deleted && row.snapshot.record_kind == RecordKind::Directory
            })
        {
            return Ok(false);
        }
        if self.state.has_materialization_intent(group_id, path)?
            || self.state.has_unsettled_projection_obligation(group_id, path)?
            || (self.state.is_held(group_id, path)?
                && self.state.get_materialization_state(group_id, path)?
                    != Some(MaterializationState::Present))
        {
            return Ok(false);
        }
        Ok(true)
    }

    /// Runs ONE reconciliation pass for this group at a time, performing at
    /// most one coalesced rerun for whatever was requested while it ran.
    ///
    /// See `reconcile_gate`'s module doc for the failure this closes. In
    /// short: two passes used to be able to snapshot the same index and
    /// both author the same paths, so every path acquired a second signed
    /// change carrying a byte-identical version. Serializing is not enough
    /// on its own -- the second pass must also take a FRESH snapshot, which
    /// it does by being a genuinely new pass here rather than the stale one
    /// that was already prepared.
    ///
    /// A coalesced caller gets `Ok(vec![])`: the reconcile it asked for
    /// does happen, in the rerun, and that rerun's own caller announces
    /// its records. The link's startup scan is in practice never the
    /// coalesced one -- it is the first reconcile a group ever runs, long
    /// before the 90-second backstop's first tick.
    pub(super) fn reconcile_disk_with_ignore(
        &self,
        group_id: &str,
        root: &VerifiedRoot,
        ignore_set: &EffectiveIgnoreSet,
        mode: ReconcileMode,
        on_chunk_committed: OnChunkCommitted<'_>,
        caller: &'static str,
    ) -> Result<Vec<FileRecord>, LocalCaptureError> {
        let Some(_pass) = self.reconcile_gate.try_enter(group_id, mode) else {
            tracing::info!(
                caller,
                group_id,
                mode = if mode.is_full() { "full" } else { "add_only" },
                "RECONCILE_PASS coalesced: a pass for this group is already running; this \
                 request will be served by its rerun rather than by a second concurrent pass"
            );
            return Ok(Vec::new());
        };
        let mut on_chunk_committed = on_chunk_committed;
        let mut records = self.reconcile_disk_pass(
            group_id,
            root,
            ignore_set,
            mode,
            on_chunk_committed.as_deref_mut(),
            caller,
        )?;
        if let Some(rerun_mode) = self.reconcile_gate.take_rerun(group_id) {
            // Reloaded rather than reused: an ignore-pattern edit is itself
            // one of the things that requests a rescan, so a rerun carrying
            // the pattern set this call was entered with could answer that
            // request against exactly the rules it was asked to stop using.
            // A reload failure falls back to the caller's set -- a rerun
            // with slightly stale patterns is still strictly better than no
            // rerun.
            let reloaded = EffectiveIgnoreSet::load_for_link_root(root.path()).ok();
            let rerun_ignore_set = reloaded.as_ref().unwrap_or(ignore_set);
            records.extend(self.reconcile_disk_pass(
                group_id,
                root,
                rerun_ignore_set,
                rerun_mode,
                // Moved, not reborrowed: this is the sink's last use.
                on_chunk_committed,
                "coalesced_rerun",
            )?);
        }
        Ok(records)
    }

    /// One reconciliation pass, as its lifecycle phases in order: read the
    /// index snapshot ([`ReconcileSnapshot`]), drop rows that became
    /// ignored, walk disk and prepare every present-path mutation
    /// ([`Self::walk_and_prepare`], which returns only once every block it
    /// staged is durable), add offline-deletion tombstones
    /// ([`Self::prepare_offline_tombstones`]), then commit -- chunked into
    /// signed changes when this processor can author history
    /// ([`Self::commit_prepared_with_history`]), index-only otherwise
    /// ([`Self::commit_prepared_index_only`]).
    // Two lifetimes, not `OnChunkCommitted<'_>`: `&mut dyn Trait` is
    // invariant in the trait object's own lifetime, so a single elided
    // lifetime would pin the callback borrow to the caller's whole
    // lifetime and make the two reborrows the coalescing wrapper needs
    // (one per pass) impossible to express.
    pub(super) fn reconcile_disk_pass<'cb, 'obj: 'cb>(
        &self,
        group_id: &str,
        root: &VerifiedRoot,
        ignore_set: &EffectiveIgnoreSet,
        mode: ReconcileMode,
        on_chunk_committed: ChunkCommittedSink<'cb, 'obj>,
        caller: &'static str,
    ) -> Result<Vec<FileRecord>, LocalCaptureError> {
        // Identifies this pass in the log for its whole life, so two passes
        // that overlap are legible as two passes rather than as one
        // confusing interleaving. Paired with the matching line
        // `ReconcilePassTrace` emits on drop, which fires on every exit
        // path this function has, `?` returns and panics included.
        let mut trace = ReconcilePassTrace::begin(caller, group_id, mode);
        let root = root.path();

        let snapshot = self.load_reconcile_snapshot(group_id, mode)?;

        // Test-only seam: fires right after the whole-index snapshot
        // (`existing_by_path`) has been read but before any record derived from
        // it is committed below. It lets a test deterministically inject a
        // concurrent peer change for a scanned path into exactly the
        // snapshot-vs-commit window this scan's missing per-path locking used to
        // leave open, to prove the group startup barrier closes it. Compiled out
        // entirely in non-test builds.
        #[cfg(test)]
        scan_test_hooks::fire_post_snapshot(group_id);

        // Diagnostic-only, and placed HERE rather than at this function's
        // entry on purpose: the failure being reproduced is two passes
        // holding the same stale `existing_by_path`, so the delay has to
        // sit after this pass has taken its snapshot and before it commits
        // anything. A delay before the snapshot would let the second pass
        // finish and the first one then re-read a populated index -- which
        // is the non-failing ordering, and would make the repro say the
        // opposite of the truth. Unset in every production process.
        diagnostic_post_snapshot_delay();

        // Whether this scan can author history for what it observes.
        //
        // Deliberately NOT "does this group already have a head". A first
        // scan of a freshly linked, populated folder used to take an
        // index-only path here and leave the authoring to the separate
        // initial import that runs afterwards -- which meant the rows and
        // the changes describing them came from two different looks at the
        // same disk, minutes apart on a large folder. The import had to
        // re-open, re-read and re-hash every file just to establish that
        // the version it was about to sign still described what was on
        // disk, and when it could not, the path entered history with no
        // actual-state proof at all.
        //
        // With emission on, this scan commits the row, the metadata, the
        // signed change, its `FileVersion` and the actual-state proof in
        // ONE transaction per chunk, all projected from the one bracketed
        // observation that produced them. The initial import stays where
        // it is, but only as the recovery path it is now the only caller
        // of: a legacy database holding current rows that were never
        // authored. A group with no emitter at all (an unregistered
        // device) still takes the index-only branch below, exactly as
        // before.
        let can_author_history = self.change_emitter.is_some();

        // Becoming ignored is not a deletion. Drop this device's local
        // index row so future sync work no longer considers the path,
        // but do not emit a tombstone and do not touch the on-disk file.
        // This mutates an existing index row, so it is a
        // `Full`-scope-only step — the add-only backstop never removes
        // or re-versions a known path.
        if mode.is_full() {
            self.remove_now_ignored_rows(group_id, &snapshot, ignore_set)?;
        }

        self.unreadable.begin_pass(group_id);
        let mut walk = self.walk_and_prepare(group_id, root, ignore_set, mode, &snapshot)?;
        if mode.is_full() && walk.scan_complete {
            self.unreadable.settle_full_pass(group_id, |path| {
                path_is_within_failed_subtree(path, &walk.failed_prefixes)
            });
        } else {
            self.unreadable.probe_standing(group_id, root);
        }

        // the walk above only ever adds/updates files that still
        // exist on disk — it never notices a file that vanished (deleted,
        // or renamed away, since the watcher classifies a rename-source
        // as `CreatedOrModified`, see `watcher.rs`). Without this, a
        // missed removal propagates to peers as a live file forever, and
        // even the "full reconciliation" this function IS the recovery
        // path for can't fix it. Tombstone any indexed, not-already-
        // deleted file whose path wasn't observed in this walk.
        // Tombstoning increments an existing row's version, so it is
        // `Full`-scope only — the add-only backstop never deletes a
        // known path (a file missing from disk this pass might be
        // mid-materialization or mid-conflict-resolution; only the
        // deliberate full reconciliation is allowed to tombstone).
        // `emit_tombstones` is `false` when the interrupted-materialization
        // repair pass that must run before this scan ERRORED for this group on
        // this boot: without repair's crash-vs-offline-delete disambiguation, a
        // `Present`-but-missing file cannot be safely told apart from a
        // genuine deletion, so ALL delete emission is deferred to a later boot
        // on which repair succeeds. Fail-closed: never emit a delete when a
        // crash cannot be told from a delete. See
        // `scan_existing_files_with_ignore_gated`.
        if mode.is_full() && walk.scan_complete {
            // Absence is delete evidence only on the volume the index was
            // built from (see `CaptureAuthority`). Adoption of a first
            // identity needs a scan that read the whole tree, whether or not
            // this scan may emit deletes, and emits none itself.
            match self.capture_authority(group_id, root)? {
                CaptureAuthority::Confirmed => {
                    if mode.emits_tombstones() {
                        self.prepare_offline_tombstones(
                            group_id, root, ignore_set, &snapshot, &mut walk,
                        )?;
                    }
                }
                CaptureAuthority::Unrecorded(current) => {
                    if walk.failed_prefixes.is_empty() {
                        self.state.adopt_capture_volume_identity(group_id, &current)?;
                    }
                }
                CaptureAuthority::Refused => {
                    if mode.emits_tombstones() {
                        tracing::warn!(
                            group_id,
                            "the sync root is not on the volume its index was built from; \
                             no deletions are authored under it"
                        );
                    }
                }
            }
        }

        // A paused item's changes -- edits and offline deletions alike --
        // stay unauthored on disk until it is resumed (see `paused_items`).
        let paused = self.paused_items(group_id)?;
        if !paused.is_empty() {
            let mut kept = Vec::with_capacity(walk.prepared.len());
            for mutation in walk.prepared.drain(..) {
                if !yadorilink_sync_sqlite::paused_items::path_is_covered(
                    &paused,
                    &mutation.record().path,
                ) {
                    kept.push(mutation);
                }
            }
            walk.prepared = kept;
        }

        let prepared = walk.prepared;
        // Route the reconciliation's detected changes through the same
        // change-emission path a live `process_event` uses, so an offline
        // edit or delete picked up only by this startup scan advances the
        // group's native state — not merely the local index — closing
        // the gap where a peer would otherwise never learn of it -- and so a first scan's rows enter history in
        // the same transaction that writes them (see `can_author_history`).
        // An empty record set emits nothing, so re-running the scan never
        // appends a duplicate head. A scan is always this device's own local
        // content — same origin as `process_event`'s single-file write path.
        if can_author_history && !prepared.is_empty() {
            // A folder removed while nothing watched is still one recursive
            // operation, so it can be restored as the unit it was removed
            // as; only what is left is chunked into ordinary changes.
            let (removed_directories, prepared) =
                split_offline_directory_removals(root, &snapshot, prepared);
            let mut on_chunk_committed = on_chunk_committed;
            let mut records = self.commit_offline_directory_removals(
                group_id,
                root,
                removed_directories,
                on_chunk_committed.as_deref_mut(),
            )?;
            if !prepared.is_empty() {
                records.extend(self.commit_prepared_with_history(
                    group_id,
                    root,
                    &snapshot,
                    &prepared,
                    on_chunk_committed,
                    &mut trace,
                )?);
            }
            Ok(records)
        } else {
            self.commit_prepared_index_only(group_id, root, &prepared, &mut trace)
        }
    }

    /// Reads the whole-index snapshot a pass judges disk against. Every
    /// later phase consults this one read; none re-reads the index rows.
    fn load_reconcile_snapshot(
        &self,
        group_id: &str,
        mode: ReconcileMode,
    ) -> Result<ReconcileSnapshot, LocalCaptureError> {
        let mut existing_by_path = std::collections::HashMap::new();
        let mut kind_by_path = std::collections::HashMap::new();
        let native_witness_by_path = self.state.native_capture_witnesses(group_id)?;
        if mode.is_add_only() {
            // The add-only backstop asks only whether the index has a path: it
            // never re-versions, tombstones or un-ignores a known one, so the
            // rows' content (block lists decoded for every file of the folder, on
            // every tick) is not read at all.
            for (path, kind) in self.state.list_indexed_paths_with_kind(group_id)? {
                kind_by_path.insert(path, kind);
            }
        } else {
            for (record, kind) in self.state.list_files_with_kind(group_id)? {
                kind_by_path.insert(record.path.clone(), kind);
                existing_by_path.insert(record.path.clone(), record);
            }
        }
        let materialization_by_path = self.state.list_materialization_states(group_id)?;
        let placeholder_generation_by_path = self.state.list_placeholder_generations(group_id)?;
        Ok(ReconcileSnapshot {
            existing_by_path,
            kind_by_path,
            native_witness_by_path,
            materialization_by_path,
            placeholder_generation_by_path,
        })
    }

    /// `Full`-scope only: drops the index row of every snapshot path the
    /// current ignore set now excludes (see the call site).
    fn remove_now_ignored_rows(
        &self,
        group_id: &str,
        snapshot: &ReconcileSnapshot,
        ignore_set: &EffectiveIgnoreSet,
    ) -> Result<(), LocalCaptureError> {
        let ignored_existing_paths: Vec<String> = snapshot
            .existing_by_path
            .keys()
            .filter(|path| {
                is_excluded_from_sync(Path::new(path), snapshot.is_directory(path), ignore_set)
            })
            .cloned()
            .collect();
        for path in &ignored_existing_paths {
            // The rows of a group a rebootstrap freezes stay; a later full scan drops
            // them once the freeze is over.
            if self.state.group_frozen(group_id)? {
                continue;
            }
            self.state.remove_file(group_id, path, &self.begin_operation()?.permit())?;
        }
        Ok(())
    }

    /// The `io::Error` of a failed read of the user's own file, when `error` is that and not a
    /// fault of our own stores.
    ///
    /// Decided by the error's type alone: every operation on the source file (the open, its
    /// `fstat`, `readlink`, each read of its bytes) reports `StorageError::SourceRead`, and
    /// `StorageError::Io` is only ever the block store's or another of our own stores, so it
    /// never counts as the file's, whatever the file looks like at that moment. Out-of-space and
    /// quota failures are never the file's either.
    pub(super) fn file_read_failure(error: &LocalCaptureError) -> Option<&std::io::Error> {
        use yadorilink_sync_sqlite::SyncSqliteError;
        let LocalCaptureError::SyncCore(SyncSqliteError::Storage(
            yadorilink_local_storage::StorageError::SourceRead(io),
        )) = error
        else {
            return None;
        };
        if matches!(
            io.kind(),
            std::io::ErrorKind::StorageFull
                | std::io::ErrorKind::QuotaExceeded
                | std::io::ErrorKind::OutOfMemory
        ) {
            return None;
        }
        Some(io)
    }

    /// Records that `rel_path` (a file, or a directory the walk could not read) could not be
    /// read. A path that keeps failing is logged when it first fails, when the reason changes and
    /// when it turns into something the person has to fix; later passes stay quiet.
    pub(super) fn note_unreadable(&self, group_id: &str, rel_path: &str, error: &std::io::Error) {
        let reason = crate::unreadable::UnreadableReason::from_io(error.kind());
        let recorded =
            self.unreadable.record_failure(group_id, rel_path, reason, std::time::Instant::now());
        if recorded.worth_logging {
            tracing::warn!(
                group_id,
                path = %rel_path,
                reason = reason.code(),
                needs_user = recorded.class == crate::unreadable::UnreadableClass::NeedsUser,
                error = %error,
                "could not read a path; it is skipped and deletions under it are suppressed \
                 until it can be read"
            );
        }
    }

    /// A directory the walk cannot list is reported like an unreadable file (the walk root itself
    /// is not a path inside the folder).
    fn note_unreadable_walk_entry(&self, group_id: &str, rel: &str, error: &walkdir::Error) {
        if let Some(io) = error.io_error().filter(|_| !rel.is_empty()) {
            self.note_unreadable(group_id, rel, io);
        }
    }

    /// One unreadable source file must not abort the whole scan: its path joins
    /// the failed prefixes, so no deletion is inferred under it, and the failure is
    /// reported. Any other error (block store, database, out of space) is returned
    /// and still aborts.
    pub(super) fn unreadable_file(
        &self,
        group_id: &str,
        rel_path: &str,
        error: LocalCaptureError,
        failed_prefixes: &mut Vec<String>,
    ) -> Result<(), LocalCaptureError> {
        let Some(io) = Self::file_read_failure(&error) else {
            return Err(error);
        };
        self.note_unreadable(group_id, rel_path, io);
        failed_prefixes.push(rel_path.to_owned());
        Ok(())
    }

    /// Walks disk under `root` and prepares a mutation for every present
    /// path that is new or changed, recording what the walk saw and where
    /// its inventory is incomplete for the tombstone phase.
    ///
    /// Owns the pass's cross-file block pool and returns only after
    /// draining it: no mutation this returns can be committed while a block
    /// it references is still only staged.
    #[allow(
        clippy::excessive_nesting,
        reason = "the already-current branch's mode/xattr divergence check sits inside the \
                  per-entry walk loop, next to the lstat that opens the observation bracket \
                  its evidence argument depends on; hoisting it out would separate that \
                  argument from the bracket it reasons about"
    )]
    fn walk_and_prepare(
        &self,
        group_id: &str,
        root: &Path,
        ignore_set: &EffectiveIgnoreSet,
        mode: ReconcileMode,
        snapshot: &ReconcileSnapshot,
    ) -> Result<ReconcileWalk, LocalCaptureError> {
        let ReconcileSnapshot {
            existing_by_path,
            materialization_by_path,
            placeholder_generation_by_path,
            ..
        } = snapshot;
        // Every path this scan will commit, in walk order, each already
        // carrying its record, op, version, metadata columns and
        // actual-state evidence. Built branch by branch below; nothing
        // downstream re-derives any part of a mutation, so no branch can
        // reach the commit having produced only some of one. See
        // `PreparedMutation`'s own doc comment.
        let mut prepared: Vec<PreparedMutation> = Vec::new();
        // This scan's cross-file block pool. Every file the walk below
        // chunks stages its blocks here instead of committing them one file
        // at a time, and the pool flushes on its own bounds — so the
        // durability barriers a batch can share are shared even when each
        // individual file is a single block. Drained (and asserted empty)
        // after the walk, before anything in `prepared` can commit; see
        // `scan_block_staging`'s module doc for the invariant that split
        // creates and who holds which half of it.
        let mut staging = ScanBlockStaging::new(self.store.as_ref(), self.state.as_ref(), group_id);
        let mut seen_paths = std::collections::HashSet::new();
        // `follow_links(false)` is walkdir's default, but stated
        // explicitly here — verified (not assumed) that this default is
        // what makes a symlinked directory get enumerated as a single
        // leaf entry rather than descended into; see
        // `watcher::register_non_ignored_directories` for the one place
        // that default alone was NOT sufficient (an explicitly-given walk
        // root that is itself a symlink is still descended into even with
        // `follow_links(false)` — a walkdir quirk that doesn't apply here
        // since `root` is always canonicalized above, but is guarded
        // there defensively regardless).
        let walker = walkdir::WalkDir::new(root)
            .follow_links(false)
            .same_file_system(true)
            .into_iter()
            .filter_entry(|entry| {
                if entry.depth() == 0 {
                    return true;
                }
                // Never index across a device (mount) boundary; see
                // `device_boundary`. Unmounting must not read as deletion.
                if entry.file_type().is_dir()
                    && yadorilink_filesystem_sync::device_boundary::is_foreign_device_dir(
                        root,
                        entry.path(),
                    )
                {
                    // The walk prunes the whole subtree, so this fires once per scan.
                    tracing::warn!(
                        path = %entry.path().display(),
                        "skipping directory on another device (mount, btrfs subvolume or ZFS dataset); its contents are not synced"
                    );
                    return false;
                }
                let Ok(rel_path) = entry.path().strip_prefix(root) else { return false };
                !is_excluded_from_sync(rel_path, entry.file_type().is_dir(), ignore_set)
            });
        // A walk error means `seen_paths` is not an authoritative inventory
        // *for the subtree that failed* — a file's absence from `seen_paths`
        // there might just mean we could not read its directory, not that it
        // was deleted, so absence must not be converted into a tombstone
        // under that subtree. But it says nothing about cleanly-walked
        // subtrees, so suppression is scoped per-failed-prefix rather than
        // disabling tombstoning for the whole scan: one persistently-erroring
        // directory must not indefinitely defer a real deletion elsewhere
        // (which a peer that evicted the file could then re-hydrate). Each
        // failed directory's root-relative prefix is collected here and
        // consulted in the tombstone loop below. If an error carries no path
        // at all (it cannot be attributed to a subtree), fall back to the
        // conservative whole-scan suppression via `scan_complete`.
        let mut scan_complete = true;
        let mut failed_prefixes: Vec<String> = Vec::new();
        for entry in walker {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    match error
                        .path()
                        .and_then(|p| p.strip_prefix(root).ok())
                        .and_then(path_to_wire_relative_string)
                    {
                        Some(rel) => {
                            // The root-relative directory (or entry) walkdir
                            // could not read. An empty prefix means the walk
                            // root itself failed, which `starts_with("")`
                            // matches for every path — i.e. the whole tree is
                            // suppressed, the correct outcome when the root is
                            // unreadable.
                            self.note_unreadable_walk_entry(group_id, &rel, &error);
                            failed_prefixes.push(rel);
                        }
                        None => {
                            // No attributable (or losslessly representable)
                            // path — cannot scope the suppression, so fail
                            // safe for the entire pass.
                            scan_complete = false;
                        }
                    }
                    tracing::warn!(
                        group_id,
                        root = %root.display(),
                        error = %error,
                        "filesystem scan was partial; tombstone reconciliation is \
                         suppressed for the affected subtree"
                    );
                    continue;
                }
            };
            // a symlink (whatever it points to) is admitted
            // here as its own leaf entry — `entry.file_type` reflects
            // lstat metadata (never follows) since `follow_links(false)`
            // is in effect, so a symlink to a directory shows up here as
            // `is_symlink == true`, `is_dir == false`, and walkdir
            // never descends into it to enumerate its contents. Anything
            // that's neither a regular file nor a symlink (a directory,
            // or something exotic) is skipped, same as before.
            let file_type = entry.file_type();
            if file_type.is_dir() && entry.depth() > 0 {
                self.prepare_directory(
                    group_id,
                    root,
                    entry.path(),
                    mode,
                    snapshot,
                    &mut prepared,
                )?;
                continue;
            }
            if !file_type.is_file() && !file_type.is_symlink() {
                continue;
            }
            let path = entry.path();
            let Ok(rel_path) = path.strip_prefix(root) else { continue };
            // A name that cannot be represented losslessly as this
            // crate's UTF-8 wire path (see `path_to_wire_relative_string`'s
            // own doc comment) is skipped outright, exactly like an
            // unsupported file type just above — better than silently
            // colliding it with some other file via lossy conversion.
            let Some(rel_path) = path_to_wire_relative_string(rel_path) else { continue };
            if is_excluded_from_sync(Path::new(&rel_path), false, ignore_set) {
                continue;
            }
            // A name native admission will refuse permanently is skipped here,
            // for the same reason and in the same shape as the lossy-wire-
            // path skip just above: it can never become a change, so
            // carrying it further can only fail -- and because a scan chunk
            // commits as ONE change, failing takes every other path in the
            // chunk with it. Checked after the ignore filter, so an ignored
            // subtree neither pays for this nor warns about files it was
            // never going to sync. See
            // `skip_reason_for_inadmissible_wire_path`.
            if let Some(reason) = skip_reason_for_inadmissible_wire_path(&rel_path) {
                tracing::warn!(
                    group_id,
                    path = %rel_path,
                    reason,
                    "skipping a local file whose name can never enter this group's change \
                     history; it stays on disk untouched but is not synced"
                );
                continue;
            }

            seen_paths.insert(rel_path.clone());

            // In add-only scope a path the index already has is left entirely
            // alone (see below); the snapshot then holds only its kind.
            if mode.is_add_only() && snapshot.kind_by_path.contains_key(&rel_path) {
                continue;
            }
            let existing = existing_by_path.get(&rel_path).cloned();

            // In add-only scope, a path that already has an index row is
            // left entirely untouched — no re-hash, no re-version, no
            // exec-bit update. The backstop only recovers files the
            // index has never seen (whose live watcher event was lost);
            // anything already indexed is the live watcher's /
            // conflict-resolution's business, and re-deriving it here is
            // exactly the unsafe re-versioning `watcher.rs`'s module doc
            // warns about.
            // ONE `lstat` opens this path's observation bracket and is the
            // only metadata any branch below judges it on: the size and
            // mtime the already-current gate compares, the mode the
            // emitted version and index row carry, and the fingerprint
            // `closed_disk_observation_if_unraced` re-checks at the end
            // all come from this single look at the file. Reading them
            // from separate stats is what lets a `chmod` land between two
            // observations and be recorded by neither.
            //
            // `symlink_metadata` rather than `entry.metadata()` for the
            // same reason the walk sets `follow_links(false)`: a symlink is
            // captured as itself, never as whatever it points at.
            let entry_metadata = std::fs::symlink_metadata(path).ok();
            let fingerprint_before =
                entry_metadata.as_ref().map(|meta| disk_race_fingerprint_of_at(meta, path));
            // "Already current" must be judged on the *same* basis as the
            // per-file path (`build_record_for_created_or_modified`'s fast
            // path): the cheap size+mtime stat gate first (via the shared
            // `metadata_mtime_matches` helper), then a content verification
            // before the no-op is trusted. A size-only gate is strictly
            // weaker than both that path and the live watcher (which
            // re-hashes on Modify): an offline edit that preserves the byte
            // length but changes the bytes (a flag flip, a same-length
            // hash/uuid swap, an in-place binary/DB edit) would be skipped
            // here, pinning the index at the stale version while disk holds
            // new bytes.
            //
            // Closing the tail: an edit that preserves BOTH size and mtime
            // (`touch -r`, archive extraction that restores timestamps, an
            // in-place same-length overwrite) is invisible to any stat-only
            // check, so a regular file that passes the size+mtime gate is
            // additionally verified against its indexed block hashes with
            // `disk_bytes_match_indexed_blocks` — the same content check the
            // per-file fast path now applies. That verifier reads the file
            // once, comparing each indexed block's SHA-256 in sequence and
            // early-exiting on the first mismatch, without re-chunking or
            // writing any block to the store. When the bytes differ (or any
            // size/mtime mismatch), the path falls through to
            // `build_record_for_created_or_modified` below, which re-chunks
            // and re-versions. Symlinks carry no blocks (their identity is
            // the target text, checked in `build_symlink_record`), so they
            // are never "already current" on a stat: a same-length retarget
            // inside one timestamp tick leaves size and mtime alone, and
            // that path reads the target and compares it. The read cost is bounded: it lands only on files
            // that already matched size+mtime, only on the infrequent full
            // startup/burst-fallback scan — the high-frequency `AddOnly`
            // backstop never reaches this path for an already-indexed file
            // (it `continue`s above at `existing.is_some()`).
            //
            // Bounded in total work is not the same as bounded per hold,
            // though. The daemon runs the *initial* scan inside its own
            // `spawn_blocking`, but the disk-reconcile backstop reaches
            // this same loop by awaiting `reconcile_added_files_from_disk`
            // straight from a runtime task — so on that route every large
            // already-current file would re-read and re-hash itself with a
            // worker core held. `disk_bytes_match_indexed_blocks_off_
            // worker` hands the core off for exactly those files and leaves
            // small ones inline, so this per-file loop pays no handoff for
            // the files that do not need one.
            let already_current = match (&existing, &entry_metadata) {
                (Some(existing), Some(metadata)) => {
                    !existing.deleted
                        && existing.size == metadata.len()
                        && file_type.is_file()
                        && metadata_mtime_matches(metadata, existing.mtime_unix_nanos)
                        && indexed_bytes_match(path, existing, metadata.len())?
                }
                _ => false,
            };
            if already_current {
                // content (size) is
                // unchanged, but this file's exec bit may never have been
                // captured at all (it predates this change and the
                // `unix_mode` column defaults to `false`), or may have been
                // chmod-only-changed since the last scan with no live
                // watcher running to catch it via
                // `build_record_for_created_or_modified`'s own fast path.
                // Reuse the `Metadata` already fetched above for the size
                // comparison — no extra syscall — rather than falling
                // through to that function's full machinery for what is,
                // by definition here, an unchanged-content file. Symlinks
                // carry no exec bit, so this only
                // applies to a genuine regular file.
                if file_type.is_file() {
                    if let (Some(existing), Some(metadata)) = (&existing, &entry_metadata) {
                        let predecessor = Predecessor::of_row(
                            self.state.canonical_current_row(group_id, &rel_path)?.as_ref(),
                        );
                        let on_disk_unix_mode = self.captured_unix_mode(metadata, &predecessor);
                        let indexed_unix_mode = predecessor.unix_mode;
                        let indexed_xattrs = predecessor.xattrs.clone();
                        // Same reasoning as the exec-bit check just
                        // above, for extended attributes: an
                        // offline `setxattr`-only edit changes neither
                        // size, mtime, content, nor unix_mode, so it must
                        // be checked here too or a re-scan can never
                        // discover it.
                        let on_disk_xattrs = self.captured_xattrs(path, &predecessor);
                        // A differing mode or xattr set is a local edit only if
                        // someone made it: the daemon's own untouched write of
                        // an older version still carries that version's
                        // metadata, and authoring it would put it over the
                        // newer version.
                        if (on_disk_unix_mode != indexed_unix_mode
                            || on_disk_xattrs != indexed_xattrs)
                            && !self
                                .state
                                .disk_is_untouched_proven_write(group_id, &rel_path, root, path)?
                        {
                            // A mode or xattr change is still a change:
                            // the version hash covers both, so this emits
                            // a genuinely new `FileVersion` for the path
                            // and native state's answer for it moves. That
                            // makes this branch's proof obligation
                            // identical to the content branch's -- the
                            // commit has to publish evidence describing
                            // the version it is about to emit, or the
                            // path's previous proof is left naming a
                            // version that no longer resolves and its
                            // projection obligation can never close.
                            //
                            // The evidence is safe to publish here for the
                            // same reason it is safe on the content
                            // branch, and only for that reason: one
                            // bracket covers the whole derivation. It
                            // opened at `fingerprint_before` above, before
                            // the exact indexed-block content verification
                            // `already_current` required; the mode came
                            // from the same `lstat` that opened it; the
                            // xattrs were read inside it; and
                            // `closed_disk_observation_if_unraced`
                            // closes it by re-stating the fingerprint
                            // around its own identity observation.
                            // Anything that touched this path at any point
                            // in that window -- including a `chmod` or
                            // `setxattr`, which move ctime -- fails the
                            // closing check and yields no evidence.
                            //
                            // Observing identity here WITHOUT that bracket
                            // would be the stale-content bug in a new
                            // place: a valid identity for an object whose
                            // bytes were replaced since they were verified
                            // is precisely a proof that the path already
                            // holds content it does not hold.
                            let observation =
                                closed_disk_observation_if_unraced(path, fingerprint_before);
                            prepared.push(self.prepare_present_mutation(
                                existing.clone(),
                                // Reached only when `file_type.is_file()`,
                                // so never a symlink.
                                None,
                                on_disk_unix_mode,
                                on_disk_xattrs,
                                observation,
                            ));
                        }
                    }
                }
                continue;
            }

            let materialization_state = materialization_by_path.get(&rel_path).copied();
            let placeholder_generation = placeholder_generation_by_path.get(&rel_path).cloned();
            let (outcome, classification, unix_mode) = match self
                .build_record_for_created_or_modified(
                    group_id,
                    root,
                    rel_path.clone(),
                    path,
                    existing,
                    materialization_state,
                    placeholder_generation,
                    Some(&mut staging),
                ) {
                Ok(built) => built,
                Err(error) => {
                    self.unreadable_file(group_id, &rel_path, error, &mut failed_prefixes)?;
                    continue;
                }
            };
            if outcome == LocalChangeOutcome::RetryLater {
                // Changed while it was read: nothing to prepare from this
                // pass. It is already in `seen_paths`, so it is never read
                // as a deletion; journal it so the edit is re-driven and a
                // remote change for it waits until it is captured.
                self.journal_uncaptured_local_edit(group_id, &rel_path, now_unix_nanos())?;
                continue;
            }
            if let LocalChangeOutcome::FileChanged(record) = outcome {
                if record.deleted {
                    prepared.push(PreparedMutation::tombstone(record));
                    continue;
                }
                // Read inside this path's bracket, before the identity
                // observation that closes it, so the xattrs the emitted
                // version carries and the identity that vouches for it
                // describe one look at the file. A fresh open, not the
                // handle `build_record_for_created_or_modified` chunked
                // through above -- a weaker same-bytes guarantee than the
                // content read itself, but xattrs are best-effort
                // metadata, never content integrity. Never scanned for a
                // symlink, matching `unix_mode`'s own `None` there.
                let xattrs = if classification.is_none() {
                    let row = self.state.canonical_current_row(group_id, &rel_path)?;
                    self.captured_xattrs(path, &Predecessor::of_row(row.as_ref()))
                } else {
                    Vec::new()
                };
                // Closes the bracket this path's `lstat` opened, covering
                // the content read, the metadata reads and everything
                // between them.
                let observation = closed_disk_observation_if_unraced(path, fingerprint_before);
                prepared.push(self.prepare_present_mutation(
                    record,
                    classification,
                    unix_mode.flatten(),
                    xattrs,
                    observation,
                ));
            }
        }

        // THE ORDERING POINT. The walk is over, so no further block can be
        // staged; this drains what is left in the pool and does not return
        // until `put_prepared_batch` has. Every commit this function makes
        // -- the delta-authoring chunk loop and the index-only branch alike
        // -- happens strictly below this line, so no `FileRecord` and no
        // native delta can become authoritative while any block it references
        // is still only staged. That is the same crash invariant the
        // per-file commit gave for free, re-established at the one place
        // that can see both ends of it.
        //
        // A failure here propagates before anything commits, which is the
        // fail-closed direction: the scan is abandoned, the index is left
        // unadvanced, and the next scan re-derives the identical diff from
        // disk and re-stages it.
        //
        // Off the worker core for the same reason the per-file capture
        // passes are (see `run_capture_pass_off_worker`): this is up to a
        // full pool's worth of real `fsync`-backed commits, and the
        // add-only backstop reaches this loop straight from a runtime task
        // rather than from the initial scan's `spawn_blocking`. The
        // mid-walk flushes already run inside that guard, since they fire
        // from inside the capture pass itself; this trailing one would not
        // have.
        run_capture_pass_off_worker(|| staging.flush())?;
        debug_assert!(
            !staging.has_staged_blocks(),
            "no block may remain staged once the scan starts committing"
        );
        let (block_flushes, blocks_flushed, bytes_flushed) = staging.flushed_totals();
        if blocks_flushed > 0 {
            tracing::debug!(
                group_id,
                block_flushes,
                blocks_flushed,
                bytes_flushed,
                "reconciliation scan committed its captured blocks as cross-file bulk batches"
            );
        }

        Ok(ReconcileWalk { prepared, seen_paths, scan_complete, failed_prefixes })
    }

    /// The walk's step for a directory: prepares its explicit entry when
    /// [`Self::directory_verdict`] says to author it. Its absence from
    /// `seen_paths` is harmless: an explicit Directory row whose directory
    /// is on disk is kept out of the tombstone phase by
    /// [`Self::recheck_tombstone_candidate`], and a File row whose name a
    /// directory now holds is still that file's deletion.
    fn prepare_directory(
        &self,
        group_id: &str,
        root: &Path,
        path: &Path,
        mode: ReconcileMode,
        snapshot: &ReconcileSnapshot,
        prepared: &mut Vec<PreparedMutation>,
    ) -> Result<(), LocalCaptureError> {
        let Ok(rel_path) = path.strip_prefix(root) else { return Ok(()) };
        let Some(rel_path) = path_to_wire_relative_string(rel_path) else { return Ok(()) };
        if skip_reason_for_inadmissible_wire_path(&rel_path).is_some() {
            return Ok(());
        }
        // Same scope rule as a file's: the add-only backstop only captures
        // a path the index has never seen.
        if mode.is_add_only() && snapshot.kind_by_path.contains_key(&rel_path) {
            return Ok(());
        }
        let Ok(lstat) = std::fs::symlink_metadata(path) else { return Ok(()) };
        let fingerprint_before = Some(disk_race_fingerprint_of_at(&lstat, path));
        let DirectoryVerdict::Author { unix_mode } =
            self.directory_verdict(group_id, root, &rel_path, &lstat)?
        else {
            return Ok(());
        };
        let (record, op, version, meta) = directory_entry(&rel_path, unix_mode);
        let observation = closed_disk_observation_if_unraced(path, fingerprint_before);
        prepared.push(PreparedMutation::Upsert { record, op, version, meta, observation });
        Ok(())
    }

    /// Whether a directory entry the walk prepared is still one to author,
    /// asked again under the path's lock immediately before its chunk
    /// commits: the walk read the ledger and the index without it, and in
    /// between the materializer may have begun placing an entry there or
    /// recorded the directory as structural. `true` keeps the lock, in
    /// `locks`, until the commit lands.
    fn recheck_directory_upsert(
        &self,
        group_id: &str,
        root: &Path,
        path: &str,
        unix_mode: Option<u32>,
        locks: &mut CommitPathLocks,
    ) -> Result<bool, LocalCaptureError> {
        if !locks.try_hold(self.state.path_lock(group_id, path)) {
            return Ok(false);
        }
        let Ok(lstat) = std::fs::symlink_metadata(root.join(path)) else { return Ok(false) };
        Ok(matches!(
            self.directory_verdict(group_id, root, path, &lstat)?,
            DirectoryVerdict::Author { unix_mode: now } if now == unix_mode
        ))
    }

    /// Appends a tombstone to `walk.prepared` for every snapshot path the
    /// walk did not see and that no veto protects. Callers run this only
    /// for a tombstone-emitting mode over a walk with an attributable
    /// inventory (see the call site).
    fn prepare_offline_tombstones(
        &self,
        group_id: &str,
        root: &Path,
        ignore_set: &EffectiveIgnoreSet,
        snapshot: &ReconcileSnapshot,
        walk: &mut ReconcileWalk,
    ) -> Result<(), LocalCaptureError> {
        let ReconcileWalk { prepared, seen_paths, failed_prefixes, .. } = walk;
        // Read once, and only if some path is missing at all.
        let mut materialization_states = None;
        for (path, existing) in &snapshot.existing_by_path {
            if existing.deleted || seen_paths.contains(path) {
                continue;
            }
            if is_excluded_from_sync(Path::new(path), snapshot.is_directory(path), ignore_set) {
                continue;
            }
            // A path admission refuses permanently is never tombstoned
            // either, and this is not symmetry for its own sake.
            //
            // A live row for such a path can genuinely exist: a build
            // predating this rule's local-authoring half could have
            // written one. The scan walk above skips the path, so it is
            // absent from `seen_paths` and looks deleted here -- which
            // would emit `Op::Delete` for it, and
            // `validate_no_reserved_paths` refuses a Delete exactly as it
            // refuses a Put, failing this whole chunk and taking every
            // unrelated path in it down. That is the same defect this
            // rule's other half exists to close, reached by another
            // route, and it fires even while the file is still on disk.
            //
            // So local capture proposes no new Put or Delete for such a
            // path and leaves the row untouched locally. It can no longer
            // fail its neighbours, which is what this closes.
            //
            // Deliberately NOT claimed: that the path is "not synced".
            // If a build predating this rule already got a change for it
            // Published, that history exists and this does not remove it
            // -- local capture simply stops proposing anything further.
            // Cleaning up a legacy published inadmissible row is a
            // separate problem: it would need admission to accept a
            // Delete for a path it otherwise refuses, a wire-visible rule
            // change every peer must agree on, and a migration story for
            // history that already contains one. Neither is attempted
            // here.
            if skip_reason_for_inadmissible_wire_path(path).is_some() {
                continue;
            }
            // Fail-safe, per-subtree: never tombstone a path that lives
            // under a directory this pass could not walk — its absence
            // from `seen_paths` may be an unread directory, not a real
            // deletion. `Path::starts_with` matches on whole path
            // components, so the prefix `broken` suppresses `broken/x`
            // but never `broken-sibling/x`. Paths under cleanly-walked
            // subtrees are still tombstoned normally.
            if path_is_within_failed_subtree(path, failed_prefixes) {
                continue;
            }
            // Test-only seam: fires here, right at this path's
            // candidacy check, before any of the (potentially stale --
            // `seen_paths` was captured earlier, by the walk) checks
            // below run. Lets a test pause the scan for one targeted
            // path, inject a concurrent mutator's completed
            // transition, then resume and confirm neither the checks
            // below nor the fresh re-check further down are fooled by
            // it. Compiled out entirely in non-test builds.
            #[cfg(test)]
            scan_test_hooks::fire_pre_tombstone_recheck(group_id, path);
            // A path's absence is delete evidence only for a `Present`
            // object. A `Remote` row has no local object, a `Hydrating` one
            // is producing it and an `Evicting` one is removing it: nothing
            // missing from the user tree says anything about any of them,
            // however unprotected the path otherwise looks. The authoritative
            // twin of this check runs under the path lock in
            // `recheck_tombstone_candidate`.
            let states = match &materialization_states {
                Some(states) => states,
                None => {
                    materialization_states.insert(self.state.list_materialization_states(group_id)?)
                }
            };
            if states.get(path) != Some(&MaterializationState::Present) {
                continue;
            }
            // Never tombstone a path with an open materialization intent: a
            // crash interrupted its write (the file is missing precisely
            // because the rename never completed), and the durable intent
            // is the signal that the interrupted-materialization repair
            // pass must reconstruct it from the locally-present blocks — not
            // that the user deleted it. Absent this check, a crash
            // mid-eager-materialize whose repair could not run (or errored)
            // this boot would be misread here as an offline deletion and a
            // `Delete` propagated group-wide, silently destroying a fully
            // reconstructable file. Fail-closed: an errored intent lookup
            // propagates via `?` rather than falling through to a tombstone.
            if self.state.has_materialization_intent(group_id, path)? {
                continue;
            }
            // An open intent alone is not enough. A path can have a
            // durably-committed, non-deleted index row whose REMOTE-
            // origin projection obligation is still unsettled (right
            // after a native delta was admitted from a peer, before
            // `materialize()` itself has ever run) -- no intent has
            // ever been opened for it, but it is exactly as "not yet
            // known to be deleted" as an in-flight intent is. Without
            // this check, a restart landing between native delta
            // admission and the obligation's first successful
            // materialize reads this as an offline deletion and
            // tombstones a file the device never even finished
            // receiving once. Same fail-closed contract as the intent
            // check above: an errored lookup propagates via `?`.
            //
            // Deliberately does NOT veto on a LOCAL-origin obligation:
            // one exists only after this device's own local emission,
            // whose bytes were already on this device's own disk
            // before the change was admitted (that observation is what
            // produced the change) -- it can never represent content
            // this device is still waiting to receive, so its presence
            // must never block a genuine, later offline deletion of
            // that same path. See `yadorilink_sync_sqlite::
            // projection_obligations::ObligationOrigin`'s own doc
            // comment for why the obligation table now distinguishes
            // this, and `has_unsettled_projection_obligation`'s own
            // contract for how the distinction is applied.
            if self.state.has_unsettled_projection_obligation(group_id, path)? {
                continue;
            }
            // A hazard-held path is not deleted: `hold_record` demotes
            // it to `Remote`, writes nothing under this exact
            // name, and opens no materialization intent, ALL by
            // design (see that fix's own doc comment) -- so neither
            // check above protects it. `HazardHeld` settlement also
            // deletes the path's projection-obligation row, so the
            // check just above stops protecting it too, the instant
            // the hazard engine settles. Without this, a case-fold
            // collision or reserved-name hazard on this device alone
            // would look, to this scan, exactly like every peer having
            // deleted a file that is perfectly valid on all of them --
            // and this scan would propagate a real, signed, group-wide
            // `Delete` for it. Fail-closed, same contract as the two
            // checks above: an errored lookup propagates via `?`.
            //
            // Narrowed to `is_held && state != Hydrated`, not
            // `is_held` alone: `held_reason` and `materialization_
            // state` are independently-cleared columns
            // (`clear_held`/`set_materialization_state`/`transition_
            // materialization_state_if_same_version` are all
            // separate calls, not one atomic operation), so a stale
            // `held_reason` left behind on a row that a LATER,
            // successful materialize genuinely wrote real content for
            // and stamped `Present` must not suppress its real
            // deletion forever -- that row's own actual, current
            // state already proves it is not the "nothing on disk
            // under this name" shape this whole check exists to
            // protect.
            if self.state.is_held(group_id, path)?
                && self.state.get_materialization_state(group_id, path)?
                    != Some(MaterializationState::Present)
            {
                continue;
            }
            // Closes a real TOCTOU window, not a theoretical one: this
            // scan is a plain synchronous `fn`, so it structurally
            // cannot hold the async per-path lock every real mutator
            // (hydrate, materialize, materialization_repair) takes for
            // its whole operation -- and the four checks above (this
            // one plus the three vetoes) are four independent,
            // non-atomic reads on a pooled connection, each reading
            // whatever happens to be true at that instant. A
            // completed held-to-materialize transition (open intent,
            // write the real content, clear the intent/held state) can
            // land entirely between `seen_paths`' capture (the walk,
            // already finished by this point in the loop) and this
            // path reaching its candidacy check here -- every one of
            // the checks above would then read exactly the "genuinely
            // missing, fully unprotected" shape a real offline
            // deletion has, even though the file now genuinely exists.
            //
            // A cheap PRE-filter, not the authoritative check: this
            // guard is dropped at the end of this loop iteration, long
            // before the actual native write for this candidate happens
            // (the chunked commit loop further down, potentially many
            // paths and real elapsed time later, itself unlocked). A
            // mutator that completes a held-to-materialize transition
            // (or any other legitimate materialization) AFTER this
            // check but BEFORE this exact candidate's own chunk
            // commits would still get tombstoned if this were the only
            // check -- see the chunked commit loop's own final,
            // guard-held-through-commit re-verification for the
            // ACTUAL protection. Kept here anyway (not merely a
            // 3-veto check with no lock) so an already-doomed
            // candidate is discarded early rather than carried all the
            // way to the commit loop only to be filtered there.
            if !self.recheck_tombstone_candidate(
                group_id,
                root,
                path,
                &mut CommitPathLocks::default(),
            )? {
                continue;
            }
            tracing::info!(
                group_id,
                path,
                "startup reconciliation scan is tombstoning a locally-missing path (no open \
                 intent, no unsettled projection obligation) as an offline deletion"
            );
            let mut tombstone = existing.clone();
            tombstone.deleted = true;
            prepared.push(PreparedMutation::tombstone(tombstone));
        }
        Ok(())
    }

    /// Commits each directory found removed offline as one recursive delete
    /// (a recursive `RmTree` rooted at the topmost gone
    /// directory) over its tombstone candidates, each re-verified under its
    /// path lock held through the commit exactly as
    /// [`Self::commit_prepared_with_history`] does. A directory the policy
    /// withholds is journaled dirty, as a withheld chunk is.
    fn commit_offline_directory_removals(
        &self,
        group_id: &str,
        root: &Path,
        removed_directories: std::collections::BTreeMap<String, Vec<OfflineRemovalCandidate>>,
        mut on_chunk_committed: ChunkCommittedSink<'_, '_>,
    ) -> Result<Vec<FileRecord>, LocalCaptureError> {
        let emitter = self.change_emitter.as_ref().expect("emitter present");
        let mut committed = Vec::new();
        for (directory, candidates) in removed_directories {
            let mut locks = CommitPathLocks::default();
            let mut kept: Vec<FileRecord> = Vec::with_capacity(candidates.len());
            let mut witnesses = Vec::with_capacity(candidates.len());
            for OfflineRemovalCandidate { record, native_witness } in candidates {
                #[cfg(test)]
                scan_test_hooks::fire_pre_chunk_commit_recheck(group_id, &record.path);
                let recheck = match self.recheck_tombstone_candidate(
                    group_id,
                    root,
                    &record.path,
                    &mut locks,
                )? {
                    true => {
                        // The delete acts on the row the pass read, so it
                        // goes ahead only while native still shows what it
                        // showed when the pass read it: a head another
                        // author landed since -- even one with identical
                        // size, mtime and blocks -- is a version this
                        // removal never saw, and must not enter its basis.
                        self.state
                            .native_capture_is_fresh(group_id, &native_witness)?
                            .then_some(native_witness)
                    }
                    false => None,
                };
                match recheck {
                    Some(witness) => {
                        kept.push(record);
                        witnesses.push(witness);
                    }
                    None => {
                        tracing::info!(
                            group_id,
                            path = %record.path,
                            "an offline folder removal's pre-commit re-check found this path no \
                             longer eligible for a tombstone; withholding it"
                        );
                    }
                }
            }
            if kept.is_empty() {
                continue;
            }
            // Deepest first, as `rm -rf` removes them.
            let mut tombstones: Vec<PreparedLocalMutation> = kept
                .iter()
                .zip(witnesses)
                .map(|(record, native_witness)| PreparedLocalMutation::Delete {
                    record: record.clone(),
                    op: Op::Delete { path: SyncPath(record.path.clone()) },
                    native_witness: Some(native_witness),
                })
                .collect();
            tombstones.sort_by(|a, b| b.record().path.cmp(&a.record().path));
            kept.sort_by(|a, b| b.path.cmp(&a.path));
            let result = self.state.commit_directory_removal(
                group_id,
                &directory,
                &tombstones,
                &self.device_id,
                now_unix_nanos(),
                Some(&**emitter),
                &self.begin_operation()?.permit(),
            );
            drop(locks);
            match result {
                Ok(_) => {
                    if let Some(ref mut cb) = on_chunk_committed {
                        cb(&kept)?;
                    }
                    committed.extend(kept);
                }
                Err(SyncSqliteError::PolicyUnavailable) => {
                    let observed = now_unix_nanos();
                    for record in &kept {
                        if let Err(e) = self.state.record_dirty_path(
                            group_id,
                            &record.path,
                            dirty_kind_str(FsChangeKind::ObservedRemoval),
                            observed,
                            &self.begin_journal_operation()?.permit(),
                        ) {
                            tracing::warn!(
                                error = %e,
                                path = %record.path,
                                group_id,
                                "failed to journal a policy-withheld offline folder removal; a \
                                 later full rescan re-derives it from the unadvanced index"
                            );
                        }
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(committed)
    }

    /// Commits `prepared` as a chain of op- and byte-bounded signed changes,
    /// re-verifying each tombstone candidate under its path lock held
    /// through its chunk's commit. A chunk the policy withholds stops the
    /// chain, and it and everything after it are journaled dirty instead.
    ///
    /// Two lifetimes for the sink for the same reason
    /// [`Self::reconcile_disk_pass`] has them.
    fn commit_prepared_with_history<'cb, 'obj: 'cb>(
        &self,
        group_id: &str,
        root: &Path,
        snapshot: &ReconcileSnapshot,
        prepared: &[PreparedMutation],
        mut on_chunk_committed: ChunkCommittedSink<'cb, 'obj>,
        trace: &mut ReconcilePassTrace,
    ) -> Result<Vec<FileRecord>, LocalCaptureError> {
        // Present only when the caller's `can_author_history` already
        // required it.
        let emitter = self.change_emitter.as_ref().expect("emitter present");
        // A bulk offline diff (e.g. deleting or renaming 100k files while
        // the daemon was stopped) would otherwise become a single change
        // with 100k ops — which no peer can decode (over `change::MAX_OPS`)
        // and no wire message can carry (over the transport's control
        // frame size cap), stranding that head permanently
        // un-propagatable. Split it into
        // op-count- and byte-bounded chunks, each committed as its own
        // change. Because `dag_store::emit_local_change` takes the group's
        // current heads as parents and each chunk commits before the next
        // runs, the chunks form a single linear chain converging on one
        // head. A crash mid-way leaves the already-committed chunks durable;
        // the remaining disk-vs-index diff is re-derived and re-emitted
        // (chaining onto the last committed chunk) by the next scan.
        let mut committed: Vec<FileRecord> = Vec::new();
        let mut withheld_from: Option<usize> = None;
        let mut start = 0usize;
        while start < prepared.len() {
            let mut end = start;
            let mut chunk_bytes = 0usize;
            while end < prepared.len() {
                let op_bytes = encoded_op_len(prepared[end].op());
                // Always take at least one op (`end == start`), so a single
                // over-cap op could never wedge the loop; otherwise stop at
                // either bound.
                if end > start
                    && (end - start >= RECONCILE_CHUNK_OP_LIMIT
                        || chunk_bytes + op_bytes > RECONCILE_CHUNK_BYTE_LIMIT)
                {
                    break;
                }
                chunk_bytes += op_bytes;
                end += 1;
            }
            // The FINAL, load-bearing re-verification -- not the
            // candidacy-time one further up, which drops its guard as
            // soon as that loop iteration ends, long before this
            // point. Held through the commit call just below: for
            // each tombstone candidate in THIS chunk, re-take its lock
            // and re-run every check one more time, right here,
            // immediately before the write that actually deletes it.
            // A mutator that completes a legitimate materialization
            // after the candidacy-time check but before this exact
            // moment -- the window the candidacy-time check alone
            // cannot close, since nothing serializes between the two
            // -- is caught here instead. Content upserts take their lock
            // here too, and re-check that disk is still what the scan
            // read (see the arm below). The proof their observation
            // would publish is decided in the pass below, after every
            // candidate in this chunk has been settled -- so it sits as
            // close to the commit as anything in this loop can.
            //
            // Every lock this loop takes is a `try_lock`: it never waits
            // while holding the locks already taken for this chunk, so it
            // cannot close a lock-order cycle with any other holder, and a
            // busy lock only defers its path (to
            // `journal_uncaptured_once_unlocked`, whose waiter holds no
            // other lock).
            let mut kept_indices: Vec<usize> = Vec::with_capacity(end - start);
            let mut kept_locks = CommitPathLocks::default();
            let mut chunk_actual_state: std::collections::HashMap<
                String,
                yadorilink_sync_sqlite::file_index::LocalCaptureActualStateEvidence,
            > = std::collections::HashMap::new();
            for (i, mutation) in prepared.iter().enumerate().take(end).skip(start) {
                match mutation {
                    PreparedMutation::Upsert { record, meta, .. }
                        if meta.record_kind == RecordKind::Directory =>
                    {
                        match self.recheck_directory_upsert(
                            group_id,
                            root,
                            &record.path,
                            meta.unix_mode,
                            &mut kept_locks,
                        )? {
                            true => {
                                kept_indices.push(i);
                            }
                            false => {
                                tracing::info!(
                                    group_id,
                                    path = %record.path,
                                    "a directory the scan was about to author is no longer \
                                     one to author; withholding it from this chunk's commit"
                                );
                            }
                        }
                    }
                    PreparedMutation::Upsert { record, version, observation, .. } => {
                        if self.recheck_scanned_upsert(
                            group_id,
                            root,
                            record,
                            version,
                            *observation,
                            &mut kept_locks,
                        )? {
                            kept_indices.push(i);
                        }
                    }
                    PreparedMutation::Delete { record, .. } => {
                        // Test-only seam: fires once per tombstone
                        // candidate, right before this final
                        // re-verification -- distinct from the
                        // candidacy-time hook above, so a test can
                        // inject a race specifically in THIS window
                        // (after candidacy, before commit) without
                        // also needing to race the earlier one.
                        // Compiled out entirely in non-test builds.
                        #[cfg(test)]
                        scan_test_hooks::fire_pre_chunk_commit_recheck(group_id, &record.path);
                        match self.recheck_tombstone_candidate(
                            group_id,
                            root,
                            &record.path,
                            &mut kept_locks,
                        )? {
                            true => {
                                kept_indices.push(i);
                                // That re-check IS this mutation's
                                // absence observation: it confirmed,
                                // under this path's own lock, held
                                // from here through the commit below,
                                // that nothing exists under this exact
                                // name. Absence is a first-class
                                // materialized generation, so a
                                // deletion publishes a proof exactly
                                // like a present file does -- in the
                                // same transaction as the `Delete`
                                // change, from the same observation
                                // that authorized emitting it. Without
                                // it the path's own deletion leaves
                                // its actual-state record still naming
                                // the content that used to be there,
                                // and the obligation the deletion
                                // opens has nothing to close against.
                                chunk_actual_state.insert(
                                    record.path.clone(),
                                    yadorilink_sync_sqlite::file_index::
                                        LocalCaptureActualStateEvidence::Absent,
                                );
                            }
                            false => {
                                tracing::info!(
                                    group_id,
                                    path = %record.path,
                                    "live reconciliation scan's final pre-commit re-check \
                                     found this path no longer eligible for an \
                                     offline-deletion tombstone; withholding it from this \
                                     chunk's commit"
                                );
                            }
                        }
                    }
                }
            }
            // Every part of this chunk's commit is projected out of
            // the same `PreparedMutation`s, so a record, the op that
            // describes it, the version that op references, the
            // metadata columns and the evidence its proof is written
            // from cannot disagree about which path they belong to.
            let chunk_records: Vec<FileRecord> =
                kept_indices.iter().map(|&i| prepared[i].record().clone()).collect();
            // One local mutation per kept record, each authored as its own
            // change over the head its row showed when the scan read it
            // (the snapshot): a row that shows another head by the commit
            // is refused (`LocalWriteCaptureStale`) and captured again.
            let chunk_mutations: Vec<PreparedLocalMutation> = kept_indices
                .iter()
                .map(|&i| {
                    let path = &prepared[i].record().path;
                    match &prepared[i] {
                        PreparedMutation::Upsert { record, op, version, meta, .. } => {
                            PreparedLocalMutation::Upsert {
                                record: record.clone(),
                                op: op.clone(),
                                version: version.clone(),
                                meta: Some(meta.clone()),
                                native_witness: Some(snapshot.native_witness(path)),
                            }
                        }
                        PreparedMutation::Delete { record, op } => PreparedLocalMutation::Delete {
                            record: record.clone(),
                            op: op.clone(),
                            native_witness: Some(snapshot.native_witness(path)),
                        },
                    }
                })
                .collect();
            if chunk_records.is_empty() {
                // Every candidate in this chunk was withheld by the
                // re-check above (or the chunk was entirely
                // tombstones, all now stale) -- nothing left to
                // commit. `kept_locks` drops here, releasing every
                // lock this iteration took.
                start = end;
                continue;
            }
            // The LAST thing before the commit, deliberately: each
            // present path's observation bracket closed when its
            // mutation was prepared, and that can be a whole chunk's
            // worth of other paths' work ago -- reading, hashing and
            // re-verifying files, taking locks, and anything the
            // tombstone re-checks above did. Nothing in that window
            // re-examined the file, so the observation speaks for the
            // moment it closed and not for this one.
            //
            // Re-verifying it here is what turns it into evidence, and
            // only a re-verification that still describes disk exactly
            // -- metadata token included, so an in-place overwrite that
            // kept the inode, the length and the mtime is caught too --
            // does. Anything else yields no evidence: the row and the
            // change still commit (they describe the content this scan
            // genuinely read), the path simply is not vouched for as
            // already materialized, and the next scan re-derives it.
            //
            // This cannot be made to span the commit itself. An
            // external writer takes no lock of this daemon's, so the
            // boundary here is the one every observe-then-commit design
            // in this codebase has: the proof is exact relative to the
            // latest state this device durably observed and adopted --
            // which is why `revalidate_identity_against_disk` re-checks
            // the same token again at the moment a proof is actually
            // used.
            for &i in &kept_indices {
                if let PreparedMutation::Upsert { record, observation, .. } = &prepared[i] {
                    let Some(observation) = observation else { continue };
                    if let Some(evidence) =
                        observation.into_evidence_if_still_current(&root.join(&record.path))
                    {
                        chunk_actual_state.insert(record.path.clone(), evidence);
                    }
                }
            }
            // `RootCommitPermit::verify` is called by `upsert_files_
            // batch_emitting_change` itself, immediately before its own
            // commit -- not just once at this whole scan's entry
            // (`root`'s caller already produced a `VerifiedRoot` before
            // this function was reached): a scan chunks into
            // potentially many sequential commits (see this loop's own
            // doc above), each separated by real elapsed time, during
            // which root ownership/lifecycle can change. This used to
            // be a standalone `sync_root_lock::verify_registered_root_
            // ownership(root)?` call here; that check is now folded
            // into the permit's own `verify`, alongside the daemon's
            // lifecycle-fence check the standalone call never covered.
            let chunk_evidence: Vec<_> = chunk_mutations
                .iter()
                .map(|mutation| chunk_actual_state.get(&mutation.record().path).cloned())
                .collect();
            let commit_result = self.state.commit_local_mutations_batch(
                group_id,
                &chunk_mutations,
                &chunk_evidence,
                &self.device_id,
                crate::ports::LocalChangeEmission {
                    author: emitter,
                    permit: &self.begin_operation()?.permit(),
                },
            );
            // Every re-verified tombstone candidate's lock is held all
            // the way through the commit call above -- dropped only
            // now, after it durably lands (or fails). This is what
            // actually closes the window: nothing else can complete a
            // materialization for any of these exact paths while this
            // commit is in flight.
            drop(kept_locks);
            match commit_result {
                Ok(_) => {
                    committed.extend_from_slice(&chunk_records);
                    if let Some(ref mut cb) = on_chunk_committed {
                        cb(&chunk_records)?;
                    }
                }
                // The group's policy is stale or has not loaded yet this
                // run, so the emit withheld this chunk rather than stamp a
                // placeholder-auth change every valid-policy peer would
                // reject (see `upsert_file_emitting_change`). Any earlier
                // chunks already committed are real emitted changes and
                // stand; do NOT fall back to a delta-silent index write for
                // the rest. Journal this chunk and the remaining tail dirty
                // (below) so the dirty-journal re-drive re-emits them — with
                // a real authorization stamp — once policy heals, leaving
                // the index unadvanced for them so a later full rescan can
                // still re-derive the same diff.
                //
                // A row that no longer shows what the scan read (a remote
                // change or another capture landed on it since) is the same
                // case for the rest of the chain: nothing of this chunk was
                // written, and the dirty journal captures it again.
                Err(SyncSqliteError::PolicyUnavailable)
                | Err(SyncSqliteError::LocalWriteCaptureStale { .. }) => {
                    withheld_from = Some(start);
                    break;
                }
                Err(e) => return Err(e.into()),
            }
            start = end;
        }

        if let Some(from) = withheld_from {
            let observed = now_unix_nanos();
            for mutation in &prepared[from..] {
                let record = mutation.record();
                let kind = if record.deleted {
                    FsChangeKind::ObservedRemoval
                } else {
                    FsChangeKind::CreatedOrModified
                };
                if let Err(e) = self.state.record_dirty_path(
                    group_id,
                    &record.path,
                    dirty_kind_str(kind),
                    observed,
                    &self.begin_journal_operation()?.permit(),
                ) {
                    tracing::warn!(
                        error = %e,
                        path = %record.path,
                        group_id,
                        "failed to journal a policy-withheld offline change; a later \
                         full rescan re-derives it from the unadvanced index"
                    );
                }
            }
            trace.record_counts(prepared.len(), committed.len());
            // Broadcast only the chunks that durably entered native state; the
            // withheld tail re-emits via the dirty journal.
            return Ok(committed);
        }
        trace.record_counts(prepared.len(), committed.len());
        Ok(committed)
    }

    /// Commits `prepared` to the index alone, rows and metadata columns in
    /// one transaction, for a processor with no change emitter.
    fn commit_prepared_index_only(
        &self,
        group_id: &str,
        root: &Path,
        prepared: &[PreparedMutation],
        trace: &mut ReconcilePassTrace,
    ) -> Result<Vec<FileRecord>, LocalCaptureError> {
        // No emitter at all: an unregistered device, which has no
        // signing key to author a delta with. An index-only write is
        // not a silent divergence here, because there is no native state to
        // diverge from and never will be until this device registers.
        //
        // The metadata columns still go in the SAME transaction as the
        // rows, even though there is no change here to keep them atomic
        // with. They used to be applied afterwards, one setter call per
        // path, which left a durable window: rows written, most of their
        // modes not. A restart in that window is not exotic -- the rows
        // are already there, so every "has the scan finished" check a
        // caller has says yes, and the daemon carries on. The next boot's
        // scan then compared each real on-disk mode against the missing
        // one, concluded the path had changed while the daemon was down,
        // and authored a metadata-only version for content nobody had
        // touched. On a 100-file folder that was 96 spurious versions,
        // one per path the setter loop had not reached.
        //
        // Same permit re-check as the delta-authoring branch above,
        // immediately before this scan's commit (see that branch's
        // own comment).
        let records: Vec<FileRecord> =
            prepared.iter().map(|mutation| mutation.record().clone()).collect();
        let metas: Vec<Option<LocalFileMetaColumns>> =
            prepared.iter().map(PreparedMutation::meta).collect();
        // Observed now, from the bytes this scan just read, and written
        // in the same transaction as the row: the proof and the
        // `Present` it earns cannot come apart across a crash.
        //
        // The version travels with the identity rather than being
        // re-derived at the commit boundary. This scan already computed
        // the exact `FileVersion` for these bytes when it prepared the
        // mutation, and a proof that named a separately-recomputed
        // version would be a second answer to a question that already
        // has one.
        let observed: Vec<Option<ImportedActualState>> = prepared
            .iter()
            .map(|mutation| match mutation {
                PreparedMutation::Upsert { record, version, observation, .. } => {
                    // The version comes from the scan, so the identity
                    // has to come from the same moment the scan read
                    // those bytes -- not from a fresh look taken now.
                    // A bare re-observation here would pair this
                    // path's ALREADY-COMPUTED version with whatever is
                    // on disk at commit time, so an external write
                    // landing in between publishes a proof asserting
                    // the old version is present, carrying an identity
                    // that describes the new one. Nothing downstream
                    // could catch it: identity revalidation compares
                    // against exactly that identity, and agrees.
                    //
                    // So the observation the scan closed over travels
                    // with the mutation, and this asks it whether it
                    // still describes disk. No answer means no proof
                    // for this path, and the next scan re-derives it.
                    observation
                        .as_ref()
                        .and_then(|observation| {
                            observation.identity_if_still_current(&root.join(&record.path))
                        })
                        .map(|filesystem_identity| ImportedActualState {
                            filesystem_identity,
                            record_kind: version.meta.record_kind,
                            version_hash: version.version_hash,
                        })
                }
                PreparedMutation::Delete { .. } => None,
            })
            .collect();
        self.state.upsert_files_batch(
            group_id,
            &records,
            &self.device_id,
            &metas,
            &observed,
            &self.begin_operation()?.permit(),
        )?;
        // Test-only seam: fires at the first instant these rows are
        // durable -- exactly what a restart here would come back to.
        // Compiled out entirely in non-test builds.
        #[cfg(test)]
        scan_test_hooks::fire_post_index_only_commit(group_id);
        trace.record_counts(prepared.len(), records.len());
        Ok(records)
    }
}
