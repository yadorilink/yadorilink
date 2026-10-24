//! `FileRecord` construction for a created/modified path: chunking, the
//! placeholder fast path, symlink classification, and the version /
//! metadata-column derivation a change is emitted from.

use std::path::{Path, PathBuf};

use crate::error::LocalCaptureError;
use crate::scan_block_staging::ScanBlockStaging;
use yadorilink_fs_platform::fs_identity::{
    disk_race_fingerprint_of_handle, metadata_mtime_matches,
};
use yadorilink_local_storage::{chunk_open_file, CDC_SIZE_THRESHOLD};
use yadorilink_replica_domain::file::{FileMeta, FileVersion, VersionBlock};
use yadorilink_replica_domain::file::{FileRecord, RecordKind};
use yadorilink_replica_domain::ids::{BlockHash, SyncPath};
use yadorilink_replica_domain::limits::MAX_SYNCABLE_BLOCKS;
use yadorilink_replica_domain::local_op::Op;
use yadorilink_replica_domain::session_state::LocalFileMetaColumns;
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_sync_sqlite::SyncSqliteError;

use super::disk_observation::{
    cfapi_placeholder_untouched, disk_bytes_match_indexed_blocks_off_worker,
    run_capture_pass_off_worker,
};
use super::{LocalChangeOutcome, LocalChangeProcessor, Predecessor};

/// [`build_record_for_created_or_modified`]'s Unix-mode-to-persist output:
/// the outer `None` means nothing to persist (a symlink, or nothing
/// changed); the inner `Option<u32>` is `unix_mode_from_metadata`'s own
/// value (itself `None` on a platform with no Unix permission-bits model).
pub(super) type PendingUnixModeUpdate = Option<Option<u32>>;

/// The `FileRecord` a `get_file` read would return for one current-row
/// read, so a caller that also needs the row's other columns reads them
/// from the same incarnation.
pub(super) fn record_of_row(
    path: &str,
    row: Option<yadorilink_sync_sqlite::CanonicalCurrentRow>,
) -> Option<FileRecord> {
    row.map(|row| FileRecord {
        path: path.to_string(),
        size: row.snapshot.size,
        mtime_unix_nanos: row.snapshot.mtime_unix_nanos,
        blocks: row.snapshot.blocks,
        deleted: row.snapshot.deleted,
    })
}

/// Extra classification produced when `build_record_for_created_or_modified`
/// determines a path is a symlink — carried
/// alongside, not inside, the `FileRecord` it returns. Like
/// `types::RecordKind` itself (see its doc comment), this is index-local
/// metadata carried in the row's own metadata columns rather than a
/// `FileRecord` field, so every existing `FileRecord {.. }` construction
/// site keeps compiling unchanged. Both the live single-event path and the
/// reconciliation scan fold it into the path's `LocalFileMetaColumns` (see
/// [`metadata_columns_for`]), so it lands in the same transaction as the
/// row rather than after it.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct SymlinkClassification {
    /// The raw, unresolved target bytes exactly as returned by
    /// `std::fs::read_link` — never dereferenced. Platform-native bytes, not
    /// a lossy UTF-8 conversion of them — see `fs_identity::target_to_bytes`
    /// (which this is built with) and `change::FileMeta::symlink_target`'s
    /// doc for why: a symlink target is not required to be valid UTF-8, and
    /// converting it lossily would make the restored symlink a different
    /// symlink from the one that was captured.
    pub(super) target: Vec<u8>,
    /// `true` when the target is an absolute path, or —
    /// resolved syntactically (never touching the filesystem) against the
    /// symlink's own parent directory — lands outside the linked folder's
    /// root.
    pub(super) out_of_root: bool,
}

/// Builds the local index metadata columns for a created/modified record from
/// the same inputs [`LocalChangeProcessor::content_op`] uses to build the
/// record's `FileVersion`, so the two are guaranteed to agree: a symlink's
/// classification produces `RecordKind::Symlink` + its target / out-of-root
/// flag (and no exec bit); a regular file produces `RecordKind::File` + its
/// exec bit (and a cleared symlink target/flag). Threading the result into the
/// emitting transaction (rather than applying it via post-commit setters) is
/// what makes the index row's metadata atomic with the emitted change's
/// `FileVersion`.
pub(super) fn metadata_columns_for(
    classification: &Option<SymlinkClassification>,
    unix_mode: Option<Option<u32>>,
    xattrs: Vec<(String, Vec<u8>)>,
) -> LocalFileMetaColumns {
    match classification {
        Some(c) => LocalFileMetaColumns {
            record_kind: RecordKind::Symlink,
            symlink_target: Some(c.target.clone()),
            symlink_out_of_root: c.out_of_root,
            unix_mode: None,
            // A symlink is not scanned for xattrs either, for the
            // identical reason `unix_mode` is `None` here -- matches
            // `single_pass_capture.rs`'s own symlink branch.
            xattrs: Vec::new(),
        },
        None => LocalFileMetaColumns {
            record_kind: RecordKind::File,
            symlink_target: None,
            symlink_out_of_root: false,
            unix_mode: unix_mode.flatten(),
            xattrs,
        },
    }
}

/// A failed operation on the user's own file (open, `fstat`, `readlink`), typed as the source's
/// so nothing downstream has to guess its origin from the error's shape.
fn source_read_error(error: std::io::Error) -> LocalCaptureError {
    LocalCaptureError::SyncCore(SyncSqliteError::Storage(
        yadorilink_local_storage::StorageError::SourceRead(error),
    ))
}

/// Whether the failed chunk attempt for `path` failed *because `path`
/// itself no longer exists* — as opposed to because the block store it was
/// writing into faulted. Both questions are asked of the same error type,
/// and that is precisely the trap this function exists to avoid walking
/// into.
///
/// The error shape alone is NECESSARY BUT NOT SUFFICIENT, and it is worth
/// being blunt about why, because the shape check reads like it ought to be
/// enough. `chunk_file`, `chunk_file_content_defined_with_callback`, and
/// `chunk_file_fixed_with_callback` (`yadorilink-local-storage`'s
/// `chunker.rs`) read the source file via a bare `?` on `fs::metadata`/
/// `fs::File::open`, so a source-path `NotFound` arrives here as
/// `Storage(Io(NotFound))`. But `StorageError::Io` is a blanket
/// `#[from] std::io::Error` over EVERY filesystem call the block store
/// itself makes, and the block store has its own real `NotFound` paths —
/// e.g. `SegmentBlockStore::commit_batch` runs its free-space preflight
/// (`check_headroom` -> `free_space::classify_volume`, which stats the
/// block-store root) BEFORE any `create_dir_all` could recreate anything,
/// so a block-store root that has been deleted or whose volume was
/// unmounted also surfaces as `Storage(Io(NotFound))`; so does a
/// concurrent removal racing `commit_block_staged`'s
/// `exists()`-then-`fs::read` of an already-present block file. The error
/// value carries no path, so the two fault domains are genuinely
/// indistinguishable from the error alone — which is exactly why
/// `is_retriable_block_store_error` above does not try.
///
/// Getting that wrong is not a cosmetic misclassification. A `true` verdict
/// makes the caller return `LocalChangeOutcome::None`, and `process_flush`
/// treats `None` as a clean no-op: it CLEARS the durable
/// `local_dirty_paths` journal row for this path. For a genuinely vanished
/// source path that is right (there is nothing left to index, and the
/// rename's own watcher event queues a fresh `CreatedOrModified` for the
/// final name — see `watcher.rs`'s `RenameMode::To`/`Both` handling). For a
/// block-store fault it is a silent, permanent loss of an already-detected
/// local edit: the file is still sitting on disk, changed, with nothing
/// left to re-drive it — the exact split-brain the retry/journal machinery
/// in `process_flush` exists to prevent.
///
/// So the verdict is taken from the PATH, not from the error: the
/// `NotFound` shape only gets us as far as "one of the two files involved
/// went missing", and the `symlink_metadata` re-stat below decides which
/// one. `symlink_metadata`, not `metadata`, so a dangling symlink — whose
/// target is missing but which is itself very much still there, and is
/// handled by `build_symlink_record`, not by chunking — is never misread as
/// a vanished path.
///
/// The re-stat can of course race in its turn, and both directions of that
/// race are safe. If `path` came back between the chunk attempt and this
/// stat (a write-then-rename that has already put a NEW file at the same
/// name), the stat succeeds, this returns `false`, and the error falls
/// through to `is_retriable_block_store_error`'s bounded retry — which
/// re-derives everything from a fresh lstat and indexes whatever is
/// actually there now. A stat that fails for any reason OTHER than
/// `NotFound` likewise returns `false` and falls through to the retry
/// path. Both are the conservative direction: the worst case is some
/// wasted retries, never a dropped edit.
///
/// FUTURE READER: do not "simplify" this back into a pure match on the
/// error shape. That form looks equivalent, compiles, passes the
/// happy-path rename test, and silently drops local edits whenever the
/// block store is the thing that is missing. See
/// `a_block_store_not_found_while_the_source_file_still_exists_stays_dirty`
/// for the regression test that pins this down.
pub(super) fn is_source_path_vanished_error(e: &LocalCaptureError, path: &Path) -> bool {
    let kind = match e {
        LocalCaptureError::SyncCore(SyncSqliteError::Storage(
            yadorilink_local_storage::StorageError::Io(io_err),
        )) => Some(io_err.kind()),
        LocalCaptureError::SyncCore(SyncSqliteError::Storage(
            yadorilink_local_storage::StorageError::SourceRead(io_err),
        )) => Some(io_err.kind()),
        _ => None,
    };
    if kind != Some(std::io::ErrorKind::NotFound) {
        return false;
    }
    // The shape is only half the verdict — confirm against `path` itself.
    matches!(
        std::fs::symlink_metadata(path),
        Err(stat_err) if stat_err.kind() == std::io::ErrorKind::NotFound
    )
}

/// The outcome of a capture pass whose path was replaced by another object
/// between its `lstat` and its open: nothing captured, left for a later
/// pass, which classifies the path afresh.
fn replaced_while_opening(group_id: &str, rel_path: &str) -> LocalChangeOutcome {
    tracing::info!(
        group_id,
        path = %rel_path,
        "a file was replaced by another object while it was being opened; nothing captured \
         from this pass, left for a later one"
    );
    LocalChangeOutcome::RetryLater
}

/// Opens `path` for reading only if it is still the regular file `lstat`
/// classified: `None` if it has since become a symlink (never followed) or
/// another object. Other open errors are returned as they are.
///
/// Errors here, and from the `fstat`s of the handle, are filesystem calls
/// on the source file and surface as the top-level `Io` variant, which
/// the flush's in-place retry deliberately does not retry
/// (`is_retriable_block_store_error` retries block-store faults only). A
/// path that fails this way stays journaled dirty and is re-driven by the
/// next flush or the backstop. (A read fault during chunking still comes
/// back through the chunker as a block-store-shaped error and is retried;
/// that split predates this function.)
fn open_classified_regular_file(
    path: &Path,
    lstat: &std::fs::Metadata,
) -> Result<Option<std::fs::File>, LocalCaptureError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Ok(None),
            Err(e) => return Err(source_read_error(e)),
        };
        let opened = file.metadata().map_err(source_read_error)?;
        if (opened.dev(), opened.ino()) != (lstat.dev(), lstat.ino()) {
            return Ok(None);
        }
        Ok(Some(file))
    }
    #[cfg(not(unix))]
    {
        let _ = lstat;
        let file = std::fs::File::open(path).map_err(source_read_error)?;
        if !file.metadata().map_err(source_read_error)?.is_file() {
            return Ok(None);
        }
        Ok(Some(file))
    }
}

/// Test-only synchronization seam backing `fire_race_after_lstat_hook`
/// below: a global, path-keyed table (not a thread-local — the chunk
/// attempt this races against runs inside `tokio::task::block_in_place`
/// under a multi-thread runtime, which is free to resume the calling task
/// on a different OS worker thread than whichever one armed the hook) so a
/// test can deterministically inject a filesystem mutation (e.g. a rename)
/// at exactly the point between `build_record_for_created_or_modified`'s
/// own lstat guard and its later chunk attempt where production code has
/// no synchronization point to hook into otherwise, without resorting to a
/// real, flaky wall-clock race. Keyed by the exact `path` a test arms so
/// concurrently-running unrelated tests (every other test in this module
/// that also exercises this same function, via its own distinct temp
/// directory) can never consume each other's armed hook. The hook closure
/// returns whether it should stay armed for a later attempt on the same
/// path (`true`) or be consumed (`false`) — every current use is one-shot
/// (a real-world race only ever fires once, and `process_event_with_
/// ignore_at`'s own fresh per-attempt existence re-check already recovers
/// a retry on its own once the path is truly gone — see that function's
/// doc comment), but a future test targeting a different window could
/// still want the hook to keep firing.
#[cfg(test)]
pub(super) static RACE_AFTER_LSTAT_HOOKS: std::sync::OnceLock<RaceAfterLstatHookMap> =
    std::sync::OnceLock::new();

/// Per-path armed test hooks for [`RACE_AFTER_LSTAT_HOOKS`]. Factored out
/// (clippy type_complexity).
#[cfg(test)]
pub(super) type RaceAfterLstatHookMap =
    std::sync::Mutex<std::collections::HashMap<PathBuf, Box<dyn FnMut() -> bool + Send>>>;

#[cfg(test)]
pub(super) fn arm_race_after_lstat_hook(path: PathBuf, f: impl FnMut() -> bool + Send + 'static) {
    let map = RACE_AFTER_LSTAT_HOOKS
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    map.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(path, Box::new(f));
}

#[cfg(test)]
pub(super) fn fire_race_after_lstat_hook(path: &Path) {
    let Some(map) = RACE_AFTER_LSTAT_HOOKS.get() else { return };
    let mut guard = map.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let keep_armed = match guard.get_mut(path) {
        Some(f) => f(),
        None => return,
    };
    if !keep_armed {
        guard.remove(path);
    }
}

/// Per-path armed hooks fired once a capture pass has read a file's
/// content, before it takes the observation (size, mtime) its record is
/// built from -- the window in which a program still writing the file
/// (a `git clone`'s pack being streamed to disk, a download, a log)
/// changes it under the capture. Same shape as [`RACE_AFTER_LSTAT_HOOKS`]
/// (path-keyed, global because the pass runs off the calling task's
/// worker), but reachable from other crates' test builds too: the
/// daemon's projection tests drive a real capture through its own flush
/// handle and need the identical deterministic race.
#[cfg(any(test, feature = "test-support"))]
static CONTENT_READ_RACE_HOOKS: std::sync::OnceLock<ContentReadRaceHookMap> =
    std::sync::OnceLock::new();

#[cfg(any(test, feature = "test-support"))]
type ContentReadRaceHookMap =
    std::sync::Mutex<std::collections::HashMap<PathBuf, Box<dyn FnMut() -> bool + Send>>>;

/// Arms a hook for `path` that runs after a capture pass has read that
/// file's content and before the pass observes the file's size and mtime.
/// The closure returns whether it stays armed for the next pass.
#[cfg(any(test, feature = "test-support"))]
pub fn arm_content_read_race_hook(path: PathBuf, f: impl FnMut() -> bool + Send + 'static) {
    let map = CONTENT_READ_RACE_HOOKS
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    map.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(path, Box::new(f));
}

/// Disarms whatever hook is armed for `path`.
#[cfg(any(test, feature = "test-support"))]
pub fn disarm_content_read_race_hook(path: &Path) {
    if let Some(map) = CONTENT_READ_RACE_HOOKS.get() {
        map.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(path);
    }
}

/// Hooks that run after a capture has built a path's record and before the
/// record is committed or queued for a batched commit -- the window in which
/// a writer can change the file after the capture's own bracket closed.
#[cfg(any(test, feature = "test-support"))]
static POST_CAPTURE_RACE_HOOKS: std::sync::OnceLock<ContentReadRaceHookMap> =
    std::sync::OnceLock::new();

/// Arms a hook for `path` that runs once a capture of that file has built
/// its record. The closure returns whether it stays armed for the next pass.
#[cfg(any(test, feature = "test-support"))]
pub fn arm_post_capture_race_hook(path: PathBuf, f: impl FnMut() -> bool + Send + 'static) {
    let map = POST_CAPTURE_RACE_HOOKS
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    map.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(path, Box::new(f));
}

/// Disarms whatever post-capture hook is armed for `path`.
#[cfg(any(test, feature = "test-support"))]
pub fn disarm_post_capture_race_hook(path: &Path) {
    if let Some(map) = POST_CAPTURE_RACE_HOOKS.get() {
        map.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(path);
    }
}

#[cfg(any(test, feature = "test-support"))]
pub(super) fn fire_post_capture_race_hook(path: &Path) {
    let Some(map) = POST_CAPTURE_RACE_HOOKS.get() else { return };
    let mut guard = map.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let keep_armed = match guard.get_mut(path) {
        Some(f) => f(),
        None => return,
    };
    if !keep_armed {
        guard.remove(path);
    }
}

/// Hooks that run inside a batch commit's revalidation, after the identity
/// of a kept path has been observed and before the fingerprint re-check that
/// closes that observation.
#[cfg(any(test, feature = "test-support"))]
static POST_IDENTITY_RACE_HOOKS: std::sync::OnceLock<ContentReadRaceHookMap> =
    std::sync::OnceLock::new();

/// Arms a one-shot-or-repeating hook (the closure returns whether it stays
/// armed) for `path`, run between a batch commit's identity observation and
/// the re-check that closes it.
#[cfg(any(test, feature = "test-support"))]
pub fn arm_post_identity_race_hook(path: PathBuf, f: impl FnMut() -> bool + Send + 'static) {
    let map = POST_IDENTITY_RACE_HOOKS
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    map.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(path, Box::new(f));
}

/// Disarms whatever post-identity hook is armed for `path`.
#[cfg(any(test, feature = "test-support"))]
pub fn disarm_post_identity_race_hook(path: &Path) {
    if let Some(map) = POST_IDENTITY_RACE_HOOKS.get() {
        map.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(path);
    }
}

#[cfg(any(test, feature = "test-support"))]
pub(super) fn fire_post_identity_race_hook(path: &Path) {
    let Some(map) = POST_IDENTITY_RACE_HOOKS.get() else { return };
    let mut guard = map.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let keep_armed = match guard.get_mut(path) {
        Some(f) => f(),
        None => return,
    };
    if !keep_armed {
        guard.remove(path);
    }
}

#[cfg(any(test, feature = "test-support"))]
fn fire_content_read_race_hook(path: &Path) {
    let Some(map) = CONTENT_READ_RACE_HOOKS.get() else { return };
    let mut guard = map.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let keep_armed = match guard.get_mut(path) {
        Some(f) => f(),
        None => return,
    };
    if !keep_armed {
        guard.remove(path);
    }
}

/// Whether a file of `block_count` blocks is too large to sync, logging the
/// refusal. A file whose block list could not travel in one replication item
/// can never be synced: peers would admit its head and never receive its
/// version. It is refused before anything is indexed or authored and the path
/// is left unsettled, so it is picked up again once it shrinks.
fn refuse_unsyncable(group_id: &str, rel_path: &str, block_count: usize) -> bool {
    let limit = syncable_block_limit();
    if block_count <= limit {
        return false;
    }
    tracing::error!(
        group_id,
        path = %rel_path,
        blocks = block_count,
        max_blocks = limit,
        "file too large to sync (block list exceeds the limit); nothing captured, the path \
         stays unsynced"
    );
    true
}

/// The most blocks a captured file may have and still be synced.
fn syncable_block_limit() -> usize {
    #[cfg(test)]
    {
        let overridden = SYNCABLE_BLOCK_LIMIT_OVERRIDE.load(std::sync::atomic::Ordering::SeqCst);
        if overridden != usize::MAX {
            return overridden;
        }
    }
    MAX_SYNCABLE_BLOCKS
}

/// Lowers the syncable block limit for a test, so a file of a few blocks
/// stands in for one of a hundred thousand. `usize::MAX` restores the real
/// limit. Process-global: a test that sets it must restore it.
#[cfg(test)]
static SYNCABLE_BLOCK_LIMIT_OVERRIDE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(usize::MAX);

#[cfg(test)]
pub(super) fn override_syncable_block_limit(limit: usize) {
    SYNCABLE_BLOCK_LIMIT_OVERRIDE.store(limit, std::sync::atomic::Ordering::SeqCst);
}

/// path-string analysis only — never dereferences `raw_target`
/// (no `canonicalize`, no `metadata`, no filesystem read of the target at
/// all) to decide whether it escapes `root`. `link_path` is the symlink's
/// own absolute path (used only for its parent directory, to resolve a
/// relative target); `raw_target` is exactly what `std::fs::read_link`
/// returned. Returns `true` if the target is absolute, or if — resolved
/// syntactically against the symlink's parent — it lands outside `root`.
pub(super) fn symlink_target_is_out_of_root(
    root: &Path,
    link_path: &Path,
    raw_target: &Path,
) -> bool {
    if raw_target.is_absolute() {
        return true;
    }
    let parent = link_path.parent().unwrap_or(link_path);
    let joined = parent.join(raw_target);
    let normalized = normalize_syntactic(&joined);
    !normalized.starts_with(root)
}

/// Syntactic (non-filesystem-touching) `.`/`..` normalization — NOT
/// `Path::canonicalize`, which resolves symlinks and touches the
/// filesystem (dereferencing the
/// target is the one thing this check must not do). A `..` that has
/// nothing left to pop (already at the start of an absolute path) is kept
/// literally rather than dropped, so the caller's `starts_with(root)`
/// check conservatively treats it as escaping rather than silently
/// accepting it.
pub(super) fn normalize_syntactic(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

impl LocalChangeProcessor {
    /// Builds the content version op for a created/updated record, together
    /// with the full [`FileVersion`] it references. The version hash covers the
    /// file's block list, size, and the metadata in scope at the write site
    /// (mtime, exec bit, and symlink target/kind when the record is a symlink).
    /// The op carries only the hash; the returned version carries the block
    /// list a receiver needs to materialize it, and is persisted alongside the
    /// emitted change.
    pub(super) fn content_op(
        &self,
        record: &FileRecord,
        unix_mode: Option<u32>,
        symlink_target: Option<Vec<u8>>,
        xattrs: Vec<(String, Vec<u8>)>,
    ) -> (Op, FileVersion) {
        // The chunker's real per-block sizes are in scope here, so the version
        // carries each block's exact length; a receiver rebuilds offsets from
        // them and validates each fetched block against its declared size.
        let blocks = record
            .blocks
            .iter()
            .map(|b| VersionBlock { hash: BlockHash(b.hash.clone()), size: b.size })
            .collect();
        let record_kind =
            if symlink_target.is_some() { RecordKind::Symlink } else { RecordKind::File };
        let meta = FileMeta {
            mtime_unix_nanos: record.mtime_unix_nanos,
            unix_mode,
            symlink_target,
            record_kind,
            xattrs,
        };
        let version = FileVersion::new(blocks, record.size, meta);
        let version_hash = version.version_hash;
        let path = SyncPath(record.path.clone());
        let op = Op::Put { path, version: version_hash };
        (op, version)
    }

    /// Whether the object at `path` is a native provider's placeholder that
    /// the provider itself reports untouched. Only a `Remote` row can have
    /// one; where no provider exists this is always `false`.
    fn is_untouched_provider_placeholder(
        &self,
        materialization_state: Option<MaterializationState>,
        path: &Path,
        lstat: &std::fs::Metadata,
        existing: Option<&FileRecord>,
        placeholder_generation: Option<&yadorilink_sync_sqlite::RecordedPlaceholderGeneration>,
    ) -> bool {
        materialization_state == Some(MaterializationState::Remote)
            && cfapi_placeholder_untouched(
                self.state.as_ref(),
                path,
                lstat,
                existing,
                placeholder_generation,
            )
    }

    /// Whether the regular file at `path` is, untouched, what a usable proof
    /// says this device wrote at `rel_path` -- whichever version the row now
    /// names. `Present` says only that an object exists, so an older
    /// version's bytes can stand under a newer row; they are the daemon's
    /// own write, not an edit, and authoring them would put the older
    /// version over the newer one. Asked only after the cheap
    /// size/mtime/content fast path has found the file differs from the row.
    fn is_untouched_proven_write(
        &self,
        existing: Option<&FileRecord>,
        group_id: &str,
        rel_path: &str,
        root: &Path,
        path: &Path,
    ) -> Result<bool, LocalCaptureError> {
        if existing.is_none_or(|existing| existing.deleted) {
            return Ok(false);
        }
        Ok(self.state.disk_is_untouched_proven_write(group_id, rel_path, root, path)?)
    }

    /// Builds the `FileRecord` for a `CreatedOrModified` event without
    /// writing it to the index — shared by `process_event` (which writes
    /// immediately, one file at a time) and `scan_existing_files` (which
    /// batches writes via `upsert_files_batch`, batch-processing changes
    /// ). `existing` and `materialization_state` are supplied by
    /// the caller rather than looked up here, so a bulk-loading caller
    /// (`scan_existing_files`) never issues a per-file query for them.
    ///
    /// The third element of the returned tuple
    /// (see [`PendingUnixModeUpdate`]) is the Unix permission bits to
    /// persist, when this call determined a value needs capturing. Returned
    /// rather than applied directly here, mirroring `SymlinkClassification`:
    /// the caller folds both into the path's `LocalFileMetaColumns` (see
    /// [`metadata_columns_for`]), so they land in the same transaction as
    /// the row itself, which may not exist yet at this point.
    /// `materialization_state` and `placeholder_generation` are two
    /// separate, independently-`None`-able lookups (a row can have a
    /// materialization state with no recorded identity, e.g. right after
    /// this build's own migration) -- bundling them into one struct would
    /// obscure that rather than clarify it, so this stays a plain argument
    /// list at 8 rather than introducing a parameter object.
    #[allow(clippy::too_many_arguments)]
    #[allow(
        clippy::too_many_lines,
        reason = "one file's complete capture decision, written as a single top-to-bottom \
                  ladder: each early return is a different reason the file is not an edit, and \
                  splitting the ladder would separate them from the ordering that makes the \
                  expensive chunking the last resort"
    )]
    #[allow(
        clippy::excessive_nesting,
        reason = "the nested arms are the fast-path ladder for an \
                  apparently-unchanged file: size and mtime match, then \
                  unix_mode, then replicated xattrs, each level only \
                  reachable when every coarser check already matched. \
                  Flattening it would either re-read metadata per check or \
                  lose the ordering that makes the expensive xattr open the \
                  last resort"
    )]
    pub(super) fn build_record_for_created_or_modified(
        &self,
        group_id: &str,
        root: &Path,
        rel_path: String,
        path: &Path,
        existing: Option<FileRecord>,
        materialization_state: Option<MaterializationState>,
        placeholder_generation: Option<yadorilink_sync_sqlite::RecordedPlaceholderGeneration>,
        // `Some` only on the reconciliation-scan route, which is the only
        // caller that has more than one file to pool blocks across. `None`
        // is a single live watcher event, whose content is chunked and
        // durably committed here exactly as it always was.
        staging: Option<&mut ScanBlockStaging<'_>>,
    ) -> Result<
        (LocalChangeOutcome, Option<SymlinkClassification>, PendingUnixModeUpdate),
        LocalCaptureError,
    > {
        // Zero-field `phase T_*` marker: a timestamp anchor for offline
        // timing analysis of captured logs.
        tracing::trace!(
            "phase T_capture_start: local capture entry (build_record_for_created_or_modified)"
        );
        // Nothing under a symlinked component is this folder's to capture.
        //
        // One check for both callers — the full scan and a single watcher
        // event — because it is the same invariant and splitting it is how it
        // was half-held before: the walker already refused to descend, and
        // the per-path route did not, so a directory symlink inside a sync
        // root let this function read a file living outside it and publish
        // those bytes to every peer. Measured, not theorised.
        //
        // The final component may itself be a symlink; that is a file this
        // folder contains and it is captured *as* a symlink further down.
        // What is refused is walking through one.
        if yadorilink_local_storage::resolve_read_path_without_traversal(
            root,
            std::path::Path::new(&rel_path),
        )
        .is_err()
        {
            tracing::warn!(
                group_id,
                path = %rel_path,
                "refusing to capture through a symlinked path component"
            );
            return Ok((LocalChangeOutcome::None, None, None));
        }

        // classify via an lstat-equivalent check first —
        // `symlink_metadata` never follows the final path component,
        // unlike `Path::is_file`/`std::fs::metadata` (used further below,
        // now only reached once a symlink has already been ruled out
        // here, so those later calls are safe to leave following-by-
        // default: at that point `path` is confirmed to be a genuine
        // regular file, not a symlink, so stat and lstat agree anyway).
        let Ok(lstat) = std::fs::symlink_metadata(path) else {
            return Ok((LocalChangeOutcome::None, None, None)); // already gone again
        };

        // Test-only synchronization seam: deterministically reproduces the
        // TOCTOU race this function's own chunk attempt further below can
        // hit against a write-then-rename save landing between this lstat
        // (which just proved `path` exists) and the chunker's later
        // `fs::metadata`/`File::open` on the same `path` — see
        // `is_source_path_vanished_error`'s doc comment for the full
        // explanation. No effect outside `#[cfg(test)]` builds.
        #[cfg(test)]
        fire_race_after_lstat_hook(path);

        if lstat.file_type().is_symlink() {
            let (outcome, classification) =
                self.build_symlink_record(group_id, root, rel_path, path, existing, &lstat)?;
            return Ok((outcome, classification, None));
        }

        if !lstat.is_file() {
            return Ok((LocalChangeOutcome::None, None, None)); // directory event, or exotic entry
        }

        // A native provider's placeholder (Windows CfAPI) is not the file's
        // content: chunking it would index wrong block hashes, and reading it
        // could hydrate it. Only a placeholder this device created and the
        // provider itself reports untouched is skipped. Where no provider
        // exists nothing is ever taken as untouched: whatever stands at the
        // path is user bytes, and falls through to the ordinary edit path.
        if self.is_untouched_provider_placeholder(
            materialization_state,
            path,
            &lstat,
            existing.as_ref(),
            placeholder_generation.as_ref(),
        ) {
            return Ok((LocalChangeOutcome::None, None, None));
        }

        // a size+mtime fast-path, checked before
        // any chunking. A filesystem watcher routinely reports a
        // `CreatedOrModified` event for a file whose bytes never actually
        // changed — this device's own self-echo (see the block-hash
        // comparison further down, which already resolves this case to
        // `None`, just after paying for a full read+chunk+hash first), an
        // editor's atomic rewrite that restores identical content, or a
        // backup/sync tool that bumps mtime without touching bytes. When
        // both `size` *and* `mtime` match a non-deleted index entry, that
        // is only "probably unchanged": a `stat` is orders of magnitude
        // cheaper than reading and chunking the whole file, but it is not,
        // on its own, a correctness guarantee.
        //
        // For data integrity we must not trust the stat verdict blindly.
        // A content edit that preserves BOTH byte length and mtime — an
        // in-place same-length overwrite, or any writer that restores the
        // mtime via `utimes`/`touch -r` after editing — would otherwise be
        // silently missed here, pinning the index (and every peer) at the
        // stale version while disk holds new bytes. So before taking the
        // no-op path, verify the on-disk bytes against the indexed block
        // hashes with `disk_bytes_match_indexed_blocks`: it streams the
        // file comparing each indexed block's SHA-256 in sequence and
        // early-exits on the first mismatch, without re-chunking (no
        // content-defined boundary search) and without writing any block to
        // the store — much cheaper than the full chunk path, and it runs
        // only for files that already passed the cheap size+mtime gate.
        // Cheaper is not cheap, though: for a large file it is still a full
        // sequential read plus a SHA-256 per indexed block, and this fast
        // path sits on the live `process_event` route, awaited directly on
        // a tokio worker with nothing above it offloading anything. Hence
        // `disk_bytes_match_indexed_blocks_off_worker` rather than the bare
        // verifier — identical verdict, but a large file's pass no longer
        // runs with a worker core held for its duration. If
        // the bytes differ, this whole fast-path is skipped and the edit
        // falls through to the full chunk-and-compare path below, which
        // re-versions the record and emits the change.
        if let Some(existing) = &existing {
            if !existing.deleted {
                if let Ok(metadata) = std::fs::metadata(path) {
                    let current_mtime_matches =
                        metadata_mtime_matches(&metadata, existing.mtime_unix_nanos);
                    if existing.size == metadata.len()
                        && current_mtime_matches
                        && disk_bytes_match_indexed_blocks_off_worker(
                            path,
                            &existing.blocks,
                            metadata.len(),
                        )?
                    {
                        // size, mtime, AND content are all verified
                        // identical here — but that still isn't the whole
                        // "nothing changed" story: a `chmod` (owner-exec bit
                        // toggle) touches none of them, so compare the exec
                        // bit too, off the same `Metadata` already fetched
                        // above (no extra syscall), before trusting this
                        // fast path's no-op conclusion. When only the exec
                        // bit differs, this
                        // is exactly the "metadata-only change" shape
                        // `try_apply_metadata_only_update` (`peer_session.
                        // rs`) already applies on the receiving side for a
                        // peer's advertised bit — mirrored here for local
                        // capture: bump the version (broadcast-worthy)
                        // without re-chunking.
                        let predecessor = Predecessor::of_row(
                            self.state.canonical_current_row(group_id, &rel_path)?.as_ref(),
                        );
                        let on_disk_unix_mode = self.captured_unix_mode(&metadata, &predecessor);
                        let (indexed_unix_mode, indexed_xattrs) =
                            (predecessor.unix_mode, predecessor.xattrs.clone());
                        // Same reasoning as the exec bit just above, for
                        // extended attributes: a `setxattr`-only
                        // edit touches none of size/mtime/content/unix_mode
                        // either, so it must be checked here too, or it is
                        // silently and permanently dropped -- never
                        // captured, never emitted, and a peer's next sync
                        // would overwrite this device's real xattr edit
                        // with the stale indexed value.
                        let on_disk_xattrs = self.captured_xattrs(path, &predecessor);
                        if on_disk_unix_mode == indexed_unix_mode
                            && on_disk_xattrs == indexed_xattrs
                        {
                            // size, mtime, exec bit, AND xattrs all
                            // unchanged — preserve the existing no-op
                            // behavior exactly.
                            return Ok((LocalChangeOutcome::None, None, None));
                        }
                        // A row that records no mode (a version from a platform with
                        // no permission bits) says nothing the file's own mode can
                        // diverge from, and the daemon's write of that version gives
                        // the file the platform's default one. While a write of
                        // exactly this content is open, that is the write's own
                        // echo, not a chmod: the unfinished write (its proof is not
                        // recorded yet, so `is_untouched_proven_write` cannot say so)
                        // must not be authored back as a local edit.
                        if indexed_unix_mode.is_none()
                            && on_disk_xattrs == indexed_xattrs
                            && self
                                .state
                                .materialization_intent_target(group_id, &rel_path)?
                                .is_some_and(|target| {
                                    target
                                        == yadorilink_local_storage::intent_target_hash(
                                            &existing.blocks,
                                        )
                                })
                        {
                            return Ok((LocalChangeOutcome::None, None, None));
                        }
                        // A mode or xattr set that differs from the row is a
                        // local edit only if someone made it. The daemon's own
                        // untouched write of an older version still carries
                        // that version's metadata, and authoring it would put
                        // the older mode over the newer version.
                        if self.is_untouched_proven_write(
                            Some(existing),
                            group_id,
                            &rel_path,
                            root,
                            path,
                        )? {
                            return Ok((LocalChangeOutcome::None, None, None));
                        }
                        let record = existing.clone();
                        return Ok((
                            LocalChangeOutcome::FileChanged(record),
                            None,
                            Some(on_disk_unix_mode),
                        ));
                    }
                }
            }
        }

        // An older version's bytes under a newer row are the daemon's own
        // untouched write, not an edit (see `is_untouched_proven_write`).
        if self.is_untouched_proven_write(existing.as_ref(), group_id, &rel_path, root, path)? {
            return Ok((LocalChangeOutcome::None, None, None));
        }

        // Offloaded, not a bare synchronous call — for a large
        // (CDC-eligible) file this scan (chunk + hash + a real
        // `fsync`-backed `store.put` per block) runs long enough (13-20s
        // for 1 GiB, confirmed via timing diagnostics) that running it
        // in place on a tokio worker would occupy that worker for the
        // whole span, exactly the class of bug `reconstruct_file_off_
        // runtime` (peer_session.rs) already fixed on the receive side.
        // Via `run_capture_pass_off_worker`, NOT a bare
        // `tokio::task::block_in_place`. Same primitive underneath, and
        // for the same reason (a scoped closure needs no `Send + 'static`
        // ownership transfer, so it fits `self` being a plain
        // `&LocalChangeProcessor` at both call sites with zero refactor of
        // `self`/`store` access) — but the bare form
        // was a latent panic. `block_in_place` panics unless a
        // multi-threaded runtime is current, so the bare call would have
        // panicked outright had this path ever been reached from a
        // current-thread runtime — which it can be: this whole function is
        // reachable from the synchronous `scan_existing_files` public API.
        // See that helper's own doc comment for the guard and for the
        // bound it buys.
        //
        // `diagnostics::set_force_fixed_chunking`
        // routes a file that would normally take the CDC branch (`use_cdc`)
        // through `chunk_file_fixed_with_callback` instead of content-
        // defined chunking -- same hash-once/bulk-commit pipeline, only the
        // boundary-selection algorithm differs.
        // Isolates whether `fastcdc`'s own rolling-hash cost, specifically,
        // is what dominates `capture -> chunk EOF` (found to be 73-86% of
        // `T_detect` for a real 1 GiB transfer). Not a production
        // chunking-policy change -- `use_cdc`'s own decision is untouched
        // when this env var is unset (every existing caller/test).
        let force_fixed_requested = crate::diagnostics::force_fixed_chunking();
        // Read before `staging` is moved into the closure below; decides
        // who records this file's group block provenance further down.
        let staged_blocks = staging.is_some();
        // ONE LOOK AT THE FILE. The record built below -- blocks, size,
        // mtime, mode -- must describe a single state of the file, and a
        // file can be written while it is read (a `git clone` streaming a
        // pack, a download, a log). So the content is read through one
        // handle, bracketed by two `fstat`s of that same handle: the size
        // and metadata come from the handle whose bytes were chunked, never
        // from a separate `stat` of the path taken at some other moment.
        // If the bracket shows the file changed during the read, or the
        // bytes read do not add up to the size it ended at, there is no
        // consistent record to build from this pass: nothing is indexed,
        // and the caller leaves the path journaled dirty for a later pass
        // (`LocalChangeOutcome::RetryLater`). The write that moved the file
        // also produces its own watcher event, which drives that pass.
        //
        // The handle must also be the object `lstat` classified above: the
        // path can be swapped for a symlink in between, and following it
        // would capture whatever it points at -- possibly a file outside
        // the root -- as this path's content. Such a pass is left for a
        // later one, which classifies the path afresh.
        let chunk_result = run_capture_pass_off_worker(|| -> Result<_, LocalCaptureError> {
            let Some(file) = open_classified_regular_file(path, &lstat)? else {
                return Ok(None);
            };
            let before = file.metadata().map_err(source_read_error)?;
            let fingerprint_before = disk_race_fingerprint_of_handle(&before, &file);
            // Chunking algorithm is chosen automatically from file size:
            // files at or above the size threshold use content-defined
            // chunking (so an internal edit re-transfers only the affected
            // region), and everything below uses the original fixed-size
            // chunker. Self-echo suppression below just compares whatever
            // this device's chunker produced against what's indexed, so it
            // needs no algorithm-awareness either way.
            let use_cdc = before.len() >= CDC_SIZE_THRESHOLD;
            let force_fixed = use_cdc && force_fixed_requested;
            let blocks = match staging {
                // A reconciliation scan: hash here, hand every block to the
                // scan's cross-file pool, and let the scan flush. The
                // blocks this returns are NOT durable yet — see
                // `scan_block_staging`'s module doc for who owns making
                // them so, and for why a per-file commit cannot be the
                // answer on a folder of small files.
                Some(staging) => yadorilink_local_storage::hash_open_file_blocks(
                    &file,
                    use_cdc && !force_fixed,
                    |block, prepared| staging.stage(&block.hash, prepared),
                )?,
                // A single live watcher event: one file is the whole batch
                // there, so there is nothing to pool across and the
                // existing per-file producers stay exactly as they were.
                None if force_fixed => {
                    yadorilink_local_storage::chunk_open_file_fixed_with_callback(
                        self.store.as_ref(),
                        &file,
                        |_, _: std::sync::Arc<[u8]>| {},
                    )?
                }
                None if use_cdc => {
                    yadorilink_local_storage::chunk_open_file_content_defined_with_callback(
                        self.store.as_ref(),
                        &file,
                        |_, _: std::sync::Arc<[u8]>| {},
                    )?
                }
                None => chunk_open_file(self.store.as_ref(), &file)?,
            };
            #[cfg(any(test, feature = "test-support"))]
            fire_content_read_race_hook(path);
            let after = file.metadata().map_err(source_read_error)?;
            let fingerprint_after = disk_race_fingerprint_of_handle(&after, &file);
            Ok(Some((blocks, before, after, fingerprint_before == fingerprint_after)))
        });
        let (blocks, before, after, unchanged) = match chunk_result {
            Ok(Some(read)) => read,
            Ok(None) => return Ok((replaced_while_opening(group_id, &rel_path), None, None)),
            // The lstat above already confirmed `path` existed when this
            // attempt started, but a write-then-rename save pattern (write
            // to a sibling temp path, then `fs::rename` onto the final
            // name — used by both ordinary atomic-save editors and this
            // benchmark's own large-file writer) can complete its rename
            // in the narrow window between that lstat and the chunker's
            // own `fs::metadata`/`File::open` a few lines later —
            // especially for a large file, where the debounce
            // accumulator's per-path quiet period can legitimately elapse
            // for the temp path's own "modified" events just as the
            // writer finishes and renames it away. When `path` is proven
            // GONE (see `is_source_path_vanished_error`: the `NotFound`
            // error shape alone does NOT prove that — it re-stats `path`
            // itself, because a block-store fault produces the identical
            // error shape and must stay on the retry/journal path), this
            // is the exact same benign, expected race the lstat guard
            // above already treats as "already gone again" rather than an
            // error, so extend that same verdict here. Falling through to
            // `is_retriable_block_store_error` instead would waste up to
            // `MAX_LOCAL_INDEX_RETRIES` retries against a path that can
            // never come back, or — worse — occasionally "succeed" against
            // a since-fully-rewritten file, indexing a spurious record
            // under what was only ever a transient rename artifact. The
            // rename's own watcher event independently queues a fresh
            // `CreatedOrModified` for the file's real final name (see
            // `watcher.rs`'s `RenameMode::To`/`Both` handling), so nothing
            // is silently dropped here.
            Err(e) if is_source_path_vanished_error(&e, path) => {
                return Ok((LocalChangeOutcome::None, None, None));
            }
            Err(e) => return Err(e),
        };
        let chunked_len: u64 = blocks.iter().map(|block| u64::from(block.size)).sum();
        if !unchanged || chunked_len != after.len() {
            tracing::info!(
                group_id,
                path = %rel_path,
                size_before = before.len(),
                size_after = after.len(),
                chunked_len,
                "a file changed while it was being read; nothing captured from this pass, \
                 left for a later one"
            );
            return Ok((LocalChangeOutcome::RetryLater, None, None));
        }
        if refuse_unsyncable(group_id, &rel_path, blocks.len()) {
            return Ok((LocalChangeOutcome::RetryLater, None, None));
        }
        // Chunking has read these bytes from this group's local filesystem,
        // hashed them, and durably put them in the shared physical store.
        // Record that fact separately from peer-controlled metadata so block
        // serving cannot infer group ownership from a FileVersion reference.
        //
        // Only on the per-file route. On the scan route these blocks are
        // not durable yet -- they are staged, and provenance for a staged
        // block would claim this device holds content it might still lose
        // -- so `ScanBlockStaging::flush` records it there instead, per
        // batch, immediately after that batch is durable and still well
        // before anything referencing it can commit.
        if !staged_blocks {
            let block_hashes: Vec<Vec<u8>> =
                blocks.iter().map(|block| block.hash.clone()).collect();
            self.state.record_group_block_provenance(group_id, &block_hashes)?;
        }

        // Content-addressed dedup, applied here as self-echo suppression:
        // applying a peer's update writes the file to disk
        // (`peer_session::materialize`), which — with no special-casing —
        // this *same* watcher would otherwise see as a brand-new local
        // edit, increment the version for, and rebroadcast, which the
        // peer's own watcher then does right back, forever, racing into
        // spurious conflicts. If the
        // freshly chunked content hashes to exactly the blocks already
        // indexed, nothing actually changed — regardless of *why* the fs
        // event fired — so there is nothing to re-index.
        //
        // THE PROJECTION FENCE, checked before any of the plain-index
        // comparison below. `existing` (the plain `files` index row this
        // module reads) is not guaranteed to already reflect a `materialize()`
        // call that is still in flight for this exact path -- and while it
        // does not, the comparison below sees the OLD indexed blocks against
        // the NEW on-disk content and reads that as a genuine local edit.
        // That is exactly the loop this whole block's own opening comment
        // describes, closing on the ordinary (already-settled) case but not
        // this one: a peer's projection getting authored right back as if a
        // human had just typed it, which the peer's own watcher then does
        // right back, forever.
        //
        // `materialize()` already opens a durable
        // `MaterializationIntentGuard` (`materialization_intents`, this
        // group_id+path's live `target_version_hash`) before its
        // temp-write-then-rename begins, for an unrelated reason -- crash
        // recovery telling an interrupted write apart from a genuine offline
        // deletion. It is already exactly the fence this needs: a durable
        // "this path is being projected toward this exact content" fact,
        // opened before the write that could echo back through the watcher
        // begins. Reused here rather than inventing a second, parallel piece
        // of state that would need to stay in sync with the first (a
        // suppress-next-event flag, an ignore table, etc.).
        //
        // Deliberately gated on the TARGET matching, not merely on an intent
        // being open at all: presence alone would just as happily suppress a
        // genuine local edit racing a DIFFERENT target. Worked example this
        // guards -- projection is writing content A; the instant after (or
        // even during) that write, a human edits the same path to content B;
        // the watcher's event lands while the intent for A is still open.
        // Content on disk is now B, so `intent_target_hash(&blocks)` (B's
        // hash) does NOT match the open intent's target (A) -- this branch
        // does not fire, and B falls through to the ordinary comparison
        // below, which correctly sees B diverge from the indexed content and
        // captures it as a real edit. Only an event whose on-disk content
        // hashes to EXACTLY the target a live intent for this path is
        // projecting is treated as that projection's own echo.
        //
        // CONTENT MATCHING THE INTENT IS NOT, BY ITSELF, PROOF THIS IS AN
        // ECHO -- the same lesson the exec-bit/xattr check just below this
        // block exists to teach about the plain `existing.blocks == blocks`
        // comparison applies here too, for an identical reason. A real
        // metadata-only edit (chmod, an xattr change) can land on a path
        // while materialize's OWN intent for that path's CONTENT is still
        // open (its content write already landed; its own
        // `apply_unix_mode`/`apply_xattrs` calls, or simply an unrelated
        // human edit racing the still-open intent, haven't run yet) --
        // returning unconditionally here on content alone would silently
        // swallow that edit, exactly the failure class the check below was
        // added to close for the *plain-index* comparison, reintroduced
        // here for the *intent* comparison instead. The predicate this
        // fence actually needs is "observed disk state IS EXACTLY the state
        // this materialization intends to project" -- content alone is
        // necessary but not sufficient.
        //
        // So: suppress only when mode AND xattrs ALSO already agree with
        // what's indexed for this path RIGHT NOW -- fetched fresh here, not
        // from `existing` (a snapshot taken before this function's own
        // chunking read, which is exactly the kind of stale reference this
        // whole mechanism exists to stop relying on). If they don't yet
        // agree, this falls through to the ordinary comparison below,
        // which -- content already matching -- resolves it exactly as an
        // ordinary metadata-only edit would: captured if it's a genuine
        // divergence from what materialize intends, silently absorbed once
        // materialize's own trailing metadata syscalls catch the index up.
        if let Some(intent_target) =
            self.state.materialization_intent_target(group_id, &rel_path)?
        {
            if intent_target == yadorilink_local_storage::intent_target_hash(&blocks) {
                if let Ok(metadata) = std::fs::metadata(path) {
                    let indexed_row = self.state.canonical_current_row(group_id, &rel_path)?;
                    let has_row = indexed_row.is_some();
                    let predecessor = Predecessor::of_row(indexed_row.as_ref());
                    let on_disk_unix_mode = self.captured_unix_mode(&metadata, &predecessor);
                    let (indexed_unix_mode, indexed_xattrs) =
                        (predecessor.unix_mode, predecessor.xattrs.clone());
                    let on_disk_xattrs = self.captured_xattrs(path, &predecessor);
                    // A row that records no mode has none for the disk to diverge from
                    // while the write that owns the intent is still open. (No row at
                    // all is a different thing: nothing says what the file should be.)
                    if (on_disk_unix_mode == indexed_unix_mode
                        || (has_row && indexed_unix_mode.is_none()))
                        && on_disk_xattrs == indexed_xattrs
                    {
                        return Ok((LocalChangeOutcome::None, None, None));
                    }
                }
            } else if self.is_pre_image_of_open_write(group_id, &rel_path, &blocks)? {
                return Ok((LocalChangeOutcome::None, None, None));
            }
        }

        // But — same lesson as the size+mtime fast path above — matching
        // CONTENT still is not the whole "nothing changed" story: a
        // chmod-only edit changes neither bytes nor (on every POSIX
        // platform) mtime, so it can reach this content-only comparison
        // (e.g. via the same-size-in-place-overwrite path, or any other
        // route that skips the fast path above) with its content hash
        // still matching what's indexed, yet its exec bit genuinely
        // diverged from what's indexed. Unconditionally returning `None`
        // here — as this check used to, with no exec-bit comparison at
        // all — silently and permanently dropped that divergence: never
        // captured, never emitted, and the next materialize on a peer
        // would eventually overwrite this device's real exec-bit edit
        // with the stale indexed value. Compare the exec bit too, off a
        // fresh `stat`, before trusting the content match's "no-op"
        // verdict — mirroring the fast path's own exec-bit check exactly.
        if let Some(existing) = &existing {
            if !existing.deleted && existing.blocks == blocks {
                if let Ok(metadata) = std::fs::metadata(path) {
                    let predecessor = Predecessor::of_row(
                        self.state.canonical_current_row(group_id, &rel_path)?.as_ref(),
                    );
                    let on_disk_unix_mode = self.captured_unix_mode(&metadata, &predecessor);
                    let (indexed_unix_mode, indexed_xattrs) =
                        (predecessor.unix_mode, predecessor.xattrs.clone());
                    // Same reasoning as the exec-bit check just above, for
                    // extended attributes -- see the size+mtime
                    // fast path's own identical comment for the full
                    // rationale.
                    let on_disk_xattrs = self.captured_xattrs(path, &predecessor);
                    if on_disk_unix_mode != indexed_unix_mode || on_disk_xattrs != indexed_xattrs {
                        // Content is genuinely unchanged (so no re-chunk,
                        // no re-versioned block list), but the exec bit is
                        // a real, local, user-initiated divergence — bump
                        // the version and emit it, the same
                        // "metadata-only change" shape the fast path
                        // above already applies.
                        return Ok((
                            LocalChangeOutcome::FileChanged(existing.clone()),
                            None,
                            Some(on_disk_unix_mode),
                        ));
                    }
                }
                return Ok((LocalChangeOutcome::None, None, None));
            }
        }

        // The same look the blocks came from -- see the bracket above.
        let metadata = after;
        let mtime_unix_nanos = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        // content genuinely changed
        // (or this is a brand-new file), reached below the fast path above
        // — capture the exec bit here too, off the same `Metadata` already
        // fetched for `mtime_unix_nanos`, so a brand-new executable file's
        // exec bit is indexed from its first appearance rather than only
        // discoverable later via a subsequent metadata-only update.
        let predecessor =
            Predecessor::of_row(self.state.canonical_current_row(group_id, &rel_path)?.as_ref());
        let unix_mode = self.captured_unix_mode(&metadata, &predecessor);

        let record = FileRecord {
            path: rel_path,
            size: chunked_len,
            mtime_unix_nanos,
            blocks,
            deleted: false,
        };
        Ok((LocalChangeOutcome::FileChanged(record), None, Some(unix_mode)))
    }

    /// Builds a symlink leaf record: the target's raw text
    /// and the out-of-root/absolute flag, never dereferencing the target
    /// to decide either. No content is read or chunked — a symlink record
    /// carries no blocks.
    pub(super) fn build_symlink_record(
        &self,
        group_id: &str,
        root: &Path,
        rel_path: String,
        path: &Path,
        existing: Option<FileRecord>,
        lstat: &std::fs::Metadata,
    ) -> Result<(LocalChangeOutcome, Option<SymlinkClassification>), LocalCaptureError> {
        // `read_link` reads the raw target without dereferencing it —
        // safe, unlike `metadata`/`canonicalize`, which is exactly the
        // dereference that is forbidden. `target_to_bytes` is the same raw,
        // platform-native byte conversion `fs_identity`'s own symlink-target
        // digest uses (never a lossy UTF-8 conversion) — see `change::
        // FileMeta::symlink_target`'s doc for why a symlink's captured
        // target must be these exact bytes.
        let raw_target = std::fs::read_link(path).map_err(source_read_error)?;
        let target_bytes = yadorilink_fs_platform::fs_identity::target_to_bytes(&raw_target);
        let out_of_root = symlink_target_is_out_of_root(root, path, &raw_target);
        // `size` is derived from the same buffer as the target, not a
        // separately obtained stat length, so the two can never disagree —
        // consistent by construction rather than by a cross-check.
        let size = target_bytes.len() as u64;
        let mtime_unix_nanos = lstat
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);

        // Self-echo/no-op suppression, mirroring the regular-file
        // fast-path above: a redundant watcher event (or an unchanged
        // rescan) for a symlink whose target hasn't actually changed must
        // not bump the version vector every time it fires. `size` alone
        // can't disambiguate two different targets of the same length, so
        // the actual stored target bytes are checked too — a lookup bounded
        // to symlink paths only, not every scanned file.
        if let Some(existing) = &existing {
            if !existing.deleted && existing.size == size {
                let previous = self.state.canonical_current_row(group_id, &rel_path)?;
                let previously_symlink = previous.as_ref().map(|row| row.snapshot.record_kind)
                    == Some(RecordKind::Symlink);
                let previous_target = previous.and_then(|row| row.snapshot.symlink_target);
                if previously_symlink && previous_target.as_deref() == Some(target_bytes.as_slice())
                {
                    return Ok((LocalChangeOutcome::None, None));
                }
            }
        }

        let record = FileRecord {
            path: rel_path,
            size,
            mtime_unix_nanos,
            blocks: Vec::new(),
            deleted: false,
        };
        let classification = SymlinkClassification { target: target_bytes, out_of_root };
        Ok((LocalChangeOutcome::FileChanged(record), Some(classification)))
    }
}
