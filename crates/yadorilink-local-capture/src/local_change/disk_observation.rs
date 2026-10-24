//! Filesystem race observation for local capture: the stat fingerprint
//! that brackets a read, the closed `DiskObservation` a commit may derive
//! actual-state evidence from, the untouched-placeholder verdict, and the
//! off-worker re-verification of on-disk bytes against indexed blocks.

use std::path::Path;

use yadorilink_fs_platform::fs_identity::{
    disk_race_fingerprint_or_stat_observed, DiskRaceFingerprint, FileIdentity,
};
use yadorilink_local_storage::CDC_SIZE_THRESHOLD;
use yadorilink_replica_domain::file::FileRecord;

/// Whether `error`, from looking a path up, says nothing answers to that
/// name. Only a missing name or a missing parent directory does. Any other
/// error (a directory this process may not search, an I/O error, a stale
/// network handle) says the path could not be observed, which is no evidence
/// that it is gone: reading it as a deletion would author a delete, and
/// propagate it, for a file that still exists.
pub(super) fn error_means_absent(error: &std::io::Error) -> bool {
    matches!(error.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory)
}

/// Whether `path` is observably absent right now, as opposed to merely
/// unreadable.
pub(super) fn is_confirmed_absent(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_err_and(|error| error_means_absent(&error))
}

/// What re-sampling a path against its prepare-time fingerprint found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PrepareMatch {
    /// The disk no longer matches (or could not be observed): exclude and re-drive.
    Changed,
    /// Equal on a fingerprint that includes the change time/USN (always, on Unix).
    Strict,
    /// Equal, but only on size and write time because this volume cannot answer the change
    /// time/USN query (Windows). That cannot show a same-size rewrite with a restored mtime, so
    /// the caller verifies the bytes and publishes no actual-state proof.
    Degraded,
}

/// Whether the disk at `path` still matches what a mutation was prepared
/// against. Two failed observations are not "unchanged": a path that was
/// absent at prepare must still be confirmed absent, not just unreadable.
///
/// The prepare sample is `disk_race_fingerprint_or_stat`; this sample comes from one query, so
/// the verdict and its degraded flag cannot disagree. A degraded sample equals a prepare sample
/// only if that one was degraded too (a readable change time/USN is part of the strict value).
pub(super) fn prepare_match(path: &Path, at_prepare: &Option<DiskRaceFingerprint>) -> PrepareMatch {
    match (disk_race_fingerprint_or_stat_observed(path), at_prepare) {
        (None, None) => {
            if is_confirmed_absent(path) {
                PrepareMatch::Strict
            } else {
                PrepareMatch::Changed
            }
        }
        (Some((current, degraded)), Some(prepared)) if current == *prepared => {
            if degraded {
                warn_degraded_capture_once();
                PrepareMatch::Degraded
            } else {
                PrepareMatch::Strict
            }
        }
        _ => PrepareMatch::Changed,
    }
}

/// Said once per process: capture is running on a volume that cannot prove file stability.
fn warn_degraded_capture_once() {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::warn!(
            "this volume cannot prove file stability (change time/USN unreadable): local capture \
             verifies file bytes before committing and publishes no actual-state proof"
        );
    }
}

/// One path's closed disk observation: what the scan saw at the moment its
/// observation bracket closed, carried forward as the single thing a later
/// commit may derive an actual-state proof from.
///
/// Deliberately NOT a `FileIdentity` the commit could publish directly.
/// An identity answers "is this the same object", and there is a real
/// shape of change it cannot see: an in-place overwrite keeps the inode,
/// the length and (if the writer restores it) the mtime, so every field
/// `FileIdentity::compare` consults still agrees while the bytes the proof
/// vouches for are gone. A bracket only speaks for the window it spans,
/// and the commit carrying a prepared mutation happens later -- unlocked,
/// with other paths' work in between -- so an observation that was sound
/// when it closed is not evidence about the moment of the commit.
///
/// The token that closes that gap is already inside the observation:
/// `FileIdentity::metadata_fingerprint` digests the tracked metadata
/// subset, which on Unix includes ctime. Every write to a file moves
/// ctime, and no userspace API can put it back -- unlike mtime, which
/// `utimensat` restores freely. So an observation still describing the
/// CURRENT disk state is exactly one whose re-observation is identical
/// field for field, fingerprint included.
///
/// [`Self::into_evidence_if_still_current`] is the only way to get
/// evidence out of this type, so a commit cannot publish a proof from an
/// observation it never re-verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DiskObservation {
    pub(super) identity: FileIdentity,
}

impl DiskObservation {
    /// Turns this observation into publishable actual-state evidence, but
    /// ONLY if re-observing `path` right now yields the identical
    /// observation -- same object by every field, and the same metadata
    /// token (see the type's own doc for why the token, not just the
    /// object identity, is what makes this a statement about content).
    ///
    /// Full structural equality rather than `FileIdentity::compare`, on
    /// purpose. `compare` answers a deliberately weaker question ("same
    /// object, possibly mutated") and is three-valued, needing a volume's
    /// birth-time granularity to resolve; two observations taken moments
    /// apart on one device need neither. Anything that differs at all --
    /// including a field this crate has no opinion about -- means the
    /// observation no longer describes disk, and the fail-closed answer
    /// is no proof.
    pub(super) fn into_evidence_if_still_current(
        self,
        path: &Path,
    ) -> Option<yadorilink_sync_sqlite::file_index::LocalCaptureActualStateEvidence> {
        self.identity_if_still_current(path).map(|filesystem_identity| {
            yadorilink_sync_sqlite::file_index::LocalCaptureActualStateEvidence::Present {
                filesystem_identity,
            }
        })
    }

    /// The same gate, for a caller that publishes its proof directly
    /// rather than through `LocalCaptureActualStateEvidence` -- the
    /// no-emitter scan, which has no change to attach evidence to and
    /// hands the commit an `ImportedActualState` instead.
    ///
    /// Returns the identity THIS observation closed over, never the
    /// re-observation: the two are equal or there is no answer, and
    /// returning the original keeps it the same value the version beside
    /// it was derived from.
    pub(super) fn identity_if_still_current(self, path: &Path) -> Option<FileIdentity> {
        let observed = FileIdentity::observe_path(path).ok()?;
        (observed == self.identity).then_some(self.identity)
    }
}

/// The closed disk observation for `path`, but ONLY if a fresh fingerprint that includes the
/// change time/USN still matches `fingerprint_before_read`
/// (a fingerprint captured before this path's own content was read) --
/// `None` for either a fingerprint mismatch (something touched this path
/// during the read/prepare window) or a failed observation. `None` here
/// always means "publish no actual-state proof for this commit," never a
/// hard failure of the capture itself. Where the volume cannot answer the change time/USN query
/// the closing sample is stat-only, which is no proof of unchanged bytes, so the answer is
/// always `None` there (a proof is never published from a degraded sample).
///
/// The identity is observed INSIDE the bracket and the fingerprint
/// re-check closes it afterwards, not the other way around: a check
/// followed by an observation leaves the observation itself outside the
/// window the check vouches for, which is precisely the kind of
/// unbracketed look this whole mechanism exists to refuse. Same syscall
/// count either way.
pub(super) fn closed_disk_observation_if_unraced(
    path: &Path,
    fingerprint_before_read: Option<DiskRaceFingerprint>,
) -> Option<DiskObservation> {
    fingerprint_before_read?;
    let identity = FileIdentity::observe_path(path).ok()?;
    let (closing, degraded) = disk_race_fingerprint_or_stat_observed(path)?;
    if degraded || Some(closing) != fingerprint_before_read {
        return None;
    }
    Some(DiskObservation { identity })
}

/// Whether the CfAPI placeholder at `path` is still untouched. On Windows, this is the ONLY signal permitted to produce
/// `true` -- a live query against the real CfAPI placeholder at `path`
/// (`LocalMutationStore::inspect_windows_placeholder`, which in
/// production calls `CfGetPlaceholderInfo`/`CfGetPlaceholderStateFromFileInfo`
/// via `yadorilink-daemon::placeholder_inspect_windows`). No size/mtime
/// comparison anywhere in this function -- the fallback this replaced
/// (plain `lstat.len() == record.size && mtime matches`) is exactly the
/// heuristic this whole mechanism exists to stop relying on (see this
/// module's own top-level doc and the `#[cfg(unix)]` overload above for
/// the residual gap a size/mtime-only check always had: an in-place edit
/// that happens to land on the same size and mtime was invisible to it).
///
/// Two independent fail-closed gates, either of which alone forces
/// `false` (never silently treated as untouched):
/// - No `placeholder_generation` recorded at all, or its `provider_kind`
///   isn't [`yadorilink_local_storage::WINDOWS_CFAPI_GENERATION_PROVIDER_KIND`]
///   (a legacy non-CfAPI row, or one this build's `record_placeholder_generation`
///   call site hasn't reached yet) -- there is nothing to compare against,
///   so this cannot possibly be proven untouched.
/// - `inspect_windows_placeholder` returns anything other than
///   [`crate::ports::PlaceholderStatus::Untouched`]
///   -- `Dirty` is an honest "this was locally written since creation",
///   and `Unknown` (the path isn't a real placeholder, the identity
///   doesn't decode, the API call itself failed) is deliberately treated
///   exactly like `Dirty`, never like a confirmed match.
#[cfg(windows)]
pub fn cfapi_placeholder_untouched(
    store: &dyn crate::ports::LocalMutationStore,
    path: &Path,
    _lstat: &std::fs::Metadata,
    _existing: Option<&FileRecord>,
    placeholder_generation: Option<&yadorilink_sync_sqlite::RecordedPlaceholderGeneration>,
) -> bool {
    let Some(recorded) = placeholder_generation else {
        return false;
    };
    if recorded.provider_kind != yadorilink_local_storage::WINDOWS_CFAPI_GENERATION_PROVIDER_KIND {
        return false;
    }
    // `dev` is always `0` (an unused sentinel) for this provider kind;
    // `ino` carries the actual `u64` generation -- see
    // `WINDOWS_CFAPI_GENERATION_PROVIDER_KIND`'s own doc comment for why
    // this reuses `PlaceholderDiskIdentity`'s two-`u64` shape.
    let expected_generation = recorded.identity.ino;
    matches!(
        store.inspect_windows_placeholder(path, expected_generation),
        crate::ports::PlaceholderStatus::Untouched
    )
}

/// Where no native provider exists, no object is ever a provider
/// placeholder: whatever is at a path is user bytes, so nothing is taken as
/// untouched on this platform's say-so.
#[cfg(not(windows))]
pub fn cfapi_placeholder_untouched(
    _store: &dyn crate::ports::LocalMutationStore,
    _path: &Path,
    _lstat: &std::fs::Metadata,
    _existing: Option<&FileRecord>,
    _placeholder_generation: Option<&yadorilink_sync_sqlite::RecordedPlaceholderGeneration>,
) -> bool {
    false
}

/// Whether `path` (root-relative) exists on disk RIGHT NOW as a regular
/// file or symlink, under its OWN exact spelling -- checked by directory-
/// listing the parent and matching the leaf name byte-for-byte, never by
/// resolving the full path directly (`std::fs::symlink_metadata`/
/// `exists`). A direct resolution succeeds on a case- or Unicode-
/// normalization-insensitive filesystem (macOS, Windows) for ANY sibling
/// that happens to fold to the same name, wrongly reporting "still
/// exists" for a path that, under its own exact name, is genuinely gone
/// -- the same case-fold hazard this whole investigation is about, just
/// surfacing in a disk check instead of an index one. Mirrors the main
/// reconciliation walk's own `entry.file_type()` admission predicate too
/// (`is_file() || is_symlink()`, from `lstat`, never following a
/// symlink): a directory (or fifo/socket/device) now occupying this exact
/// name is not "the file still exists" any more than it was during the
/// walk itself, which would have skipped it the same way -- an indexed
/// file silently replaced offline by one of those must still be
/// tombstoned, not permanently spared because *something* now answers to
/// its name.
pub(super) fn exact_leaf_exists_as_file_or_symlink(root: &Path, path: &str) -> bool {
    try_exact_leaf_exists_as_file_or_symlink(root, path).unwrap_or(false)
}

/// [`exact_leaf_exists_as_file_or_symlink`], but a failed look (a directory
/// cannot be listed, an entry cannot be read) is an error, not "absent".
pub(super) fn try_exact_leaf_exists_as_file_or_symlink(
    root: &Path,
    path: &str,
) -> std::io::Result<bool> {
    Ok(exact_entry_type(root, path)?.is_some_and(|ft| ft.is_file() || ft.is_symlink()))
}

/// Whether a real directory (lstat, never followed) answers to `path` under its exact
/// spelling. The directory counterpart of [`exact_leaf_exists_as_file_or_symlink`], for an
/// explicit Directory row: the walk never admits a directory, so the directory itself is the
/// only evidence that such a row is still present.
pub(super) fn exact_leaf_exists_as_directory(root: &Path, path: &str) -> bool {
    try_exact_leaf_exists_as_directory(root, path).unwrap_or(false)
}

/// [`exact_leaf_exists_as_directory`], but a failed look is an error, not "absent": only a
/// successful listing that has no such directory is evidence of absence (a case-only
/// directory rename leaves the lookup answering to the new spelling).
pub(super) fn try_exact_leaf_exists_as_directory(root: &Path, path: &str) -> std::io::Result<bool> {
    Ok(exact_entry_type(root, path)?.is_some_and(|ft| ft.is_dir()))
}

/// Whether nothing answers to `path` under its exact spelling, EVERY component included: a
/// leaf that survives under a renamed ancestor (`Photos/a.jpg` after `Photos` became
/// `photos`) is not that path. An unreadable directory is not an absence.
pub(super) fn is_exact_path_confirmed_absent(root: &Path, path: &str) -> bool {
    match std::fs::symlink_metadata(root.join(path)) {
        Err(error) => error_means_absent(&error),
        Ok(_) => matches!(exact_entry_type(root, path), Ok(None)),
    }
}

/// The type of the entry `path` names under its exact spelling, found by listing each
/// directory on the way and matching the name byte-for-byte: never by resolving the full
/// path, which a case- or normalization-insensitive volume answers for any folded sibling.
/// `None` when some component has no entry of that exact name.
fn exact_entry_type(root: &Path, path: &str) -> std::io::Result<Option<std::fs::FileType>> {
    let mut dir = root.to_path_buf();
    let mut components = path.split('/').filter(|c| !c.is_empty()).peekable();
    if components.peek().is_none() {
        return Ok(None);
    }
    while let Some(name) = components.next() {
        let mut found = None;
        let mut listed_name = None;
        let is_leaf = components.peek().is_none();
        // An ancestor is matched leniently across Unicode forms (a volume that stores names
        // decomposed lists it so) only when no entry has the exact bytes: presence is what an
        // ancestor can prove, and erring toward "present" never authors a delete. Case and
        // the leaf stay exact.
        let mut lenient = None;
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            if entry.file_name() == name {
                found = Some(entry.file_type()?);
                listed_name = Some(entry.file_name());
                lenient = None;
                break;
            }
            if !is_leaf
                && lenient.is_none()
                && same_name_up_to_unicode_form(&entry.file_name(), name)
                && volume_answers_through(&dir, name, &entry.file_name())
            {
                lenient = Some((entry.file_type()?, entry.file_name()));
            }
        }
        if let Some((file_type, listed)) = lenient {
            found = Some(file_type);
            listed_name = Some(listed);
        }
        let Some(file_type) = found else { return Ok(None) };
        if components.peek().is_none() {
            return Ok(Some(file_type));
        }
        if file_type.is_symlink() {
            // A path through a link is not one this exact walk can vouch for either way.
            return Err(std::io::Error::other("a symlink stands in the path"));
        }
        if !file_type.is_dir() {
            return Ok(None);
        }
        dir.push(listed_name.unwrap_or_else(|| name.into()));
    }
    Ok(None)
}

/// Whether the exact spelling `name` resolves, in `dir`, to the very entry listed as `listed`:
/// only a volume that folds the Unicode forms answers one through the other, while one that
/// tells them apart (Linux, NTFS) has a different directory there, not this ancestor. The
/// same file identity is what proves it; a name that resolves to some other entry (a case
/// match on a case-folding volume) does not. Platforms without a stable identity here (NTFS
/// keeps the forms apart) never take the lenient match.
#[cfg(unix)]
fn volume_answers_through(dir: &Path, name: &str, listed: &std::ffi::OsStr) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (std::fs::symlink_metadata(dir.join(name)), std::fs::symlink_metadata(dir.join(listed))) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

#[cfg(not(unix))]
fn volume_answers_through(_dir: &Path, _name: &str, _listed: &std::ffi::OsStr) -> bool {
    false
}

fn same_name_up_to_unicode_form(listed: &std::ffi::OsStr, name: &str) -> bool {
    listed.to_str().is_some_and(|listed| {
        yadorilink_fs_platform::canonical_fold::nfc(listed)
            == yadorilink_fs_platform::canonical_fold::nfc(name)
    })
}

/// Runs one of this module's long synchronous capture passes — a
/// whole-file chunk-and-hash, or a whole-file re-verify against the
/// indexed block hashes — without leaving it holding the tokio worker core
/// it was called on. The bound this establishes is on the CORE, not on
/// `f`. On a multi-threaded runtime `block_in_place` moves this worker's
/// core, and every task already queued on it, to a replacement thread
/// *before* `f` starts; the calling thread becomes an ordinary blocking
/// thread for the duration. So no worker core is held for longer than that
/// one handoff, however long `f` itself runs — which matters because these
/// passes are not measured in milliseconds. Chunking, hashing and durably
/// committing a 1 GiB file measures 13-20s; re-verifying one against its
/// indexed hashes is a full sequential read plus a SHA-256 per block. A
/// held core, meanwhile, can't service anything else queued on it --
/// including this device's own QUIC endpoint driver, which has to run
/// promptly enough to send ACKs and keepalives before the QUIC stack's own
/// loss-detection and peer idle timeout react to the silence -- and it is
/// time-to-schedule, not poll turnaround, that decides whether they go out
/// in time. `spawn_blocking` wants a `Send + 'static` closure and an
/// `.await` to join it, and there is no `.await` to be had here without
/// turning that whole public API async. A scoped closure needs neither.
/// The runtime guard mirrors `peer_session::record_materialized_
/// fingerprint_off_runtime`, `daemon_state::run_blocking_sweep_offloaded`
/// and `gc::run_sweep_with_grace_cutoff`, and it is load-bearing rather
/// than defensive: `block_in_place` PANICS unless a multi-threaded runtime
/// is current, and these call sites are genuinely reached from a
/// current-thread runtime and from no runtime at all. Where there is no
/// multi-threaded worker to hand off to there is also no worker pool to
/// starve, so the plain synchronous call is already the right answer
/// there, not a degraded one. Nesting costs nothing and needs no guarding
/// of its own: tokio only hands off a core this thread actually holds, so
/// reaching here from a thread that has none — a `spawn_blocking` thread
/// (how the daemon runs the whole initial scan), or a thread whose core an
/// outer offload already took (the daemon's flush task wraps all of
/// `process_flush_with_ignore` in its own `block_in_place`) — simply runs
/// `f` in place.
pub(super) fn run_capture_pass_off_worker<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}

/// At or above this size, a "is the on-disk content still exactly what is
/// indexed" re-verification is handed off the calling worker's core by
/// [`disk_bytes_match_indexed_blocks_off_worker`] instead of running in
/// place. Below it the read-and-hash pass is short enough that the handoff
/// would cost more than it saves — and `reconcile_disk_with_ignore` runs
/// this verification once per already-current file across a whole tree, so
/// a per-file handoff there is not free.
///
/// Shares the chunker's own large-file threshold rather than inventing a
/// second notion of "big file": a file large enough to be worth
/// content-defined chunking is exactly a file large enough that a full
/// re-read plus per-block SHA-256 is worth getting off a worker.
pub(super) const OFF_WORKER_VERIFY_MIN_BYTES: u64 = CDC_SIZE_THRESHOLD;

/// [`yadorilink_local_storage::disk_bytes_match_indexed_blocks`], off the
/// calling tokio worker's core when `size` says the pass is big enough to
/// be worth the handoff — see [`run_capture_pass_off_worker`] for the bound
/// that buys and [`OFF_WORKER_VERIFY_MIN_BYTES`] for the cutoff.
///
/// Identical verdict either way: this only decides which thread the
/// (unchanged) read-and-compare runs on, never what it concludes.
///
/// The comparison only ever touches the user's own file (never the block store), so every I/O
/// failure it reports is the source's and comes back as `StorageError::SourceRead`.
pub(super) fn disk_bytes_match_indexed_blocks_off_worker(
    path: &Path,
    blocks: &[yadorilink_replica_domain::file::BlockInfo],
    size: u64,
) -> Result<bool, yadorilink_local_storage::StorageError> {
    use yadorilink_local_storage::StorageError;
    let source_only = |result: Result<bool, StorageError>| match result {
        Err(StorageError::Io(error)) => Err(StorageError::SourceRead(error)),
        other => other,
    };
    if size < OFF_WORKER_VERIFY_MIN_BYTES {
        return source_only(yadorilink_local_storage::disk_bytes_match_indexed_blocks(
            path, blocks,
        ));
    }
    source_only(run_capture_pass_off_worker(|| {
        yadorilink_local_storage::disk_bytes_match_indexed_blocks(path, blocks)
    }))
}

#[cfg(test)]
mod exact_path_tests {
    use super::*;

    /// After `Photos` becomes `photos`, nothing answers to `Photos/a.jpg` under its exact
    /// spelling, whether or not the volume folds (where it does, a plain lookup still answers).
    #[test]
    fn a_leaf_under_a_renamed_ancestor_is_not_the_old_path() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("Photos")).unwrap();
        std::fs::write(root.join("Photos/a.jpg"), b"x").unwrap();
        assert!(!is_exact_path_confirmed_absent(root, "Photos/a.jpg"));
        assert!(try_exact_leaf_exists_as_file_or_symlink(root, "Photos/a.jpg").unwrap());
        assert!(try_exact_leaf_exists_as_directory(root, "Photos").unwrap());

        std::fs::rename(root.join("Photos"), root.join("photos")).unwrap();
        assert!(is_exact_path_confirmed_absent(root, "Photos/a.jpg"));
        assert!(is_exact_path_confirmed_absent(root, "Photos"));
        assert!(!try_exact_leaf_exists_as_file_or_symlink(root, "Photos/a.jpg").unwrap());
        assert!(!try_exact_leaf_exists_as_directory(root, "Photos").unwrap());
        assert!(!is_exact_path_confirmed_absent(root, "photos/a.jpg"));
        assert!(try_exact_leaf_exists_as_directory(root, "photos").unwrap());
    }

    /// An ancestor listed in another Unicode form than the wire path's is still that ancestor:
    /// a delete must never be authored for a file that is there.
    #[test]
    fn an_ancestor_in_another_unicode_form_is_not_an_absence() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("Caf\u{e9}")).unwrap();
        std::fs::write(root.join("Caf\u{e9}/a.jpg"), b"x").unwrap();
        // A volume that tells the forms apart has two distinct paths here, and the
        // decomposed one really is absent.
        if std::fs::symlink_metadata(root.join("Cafe\u{301}/a.jpg")).is_err() {
            return;
        }
        assert!(!is_exact_path_confirmed_absent(root, "Cafe\u{301}/a.jpg"));
        assert!(try_exact_leaf_exists_as_file_or_symlink(root, "Cafe\u{301}/a.jpg").unwrap());
    }

    /// Where both Unicode forms of an ancestor exist (a volume that keeps them apart), the
    /// exact one is the ancestor, whichever is listed first.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_exact_ancestor_wins_over_another_unicode_form() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for name in ["Caf\u{e9}", "Cafe\u{301}"] {
            std::fs::create_dir_all(root.join(name)).unwrap();
        }
        // A temp volume that folds the forms made one directory, not two.
        if std::fs::read_dir(root).unwrap().count() != 2 {
            return;
        }
        std::fs::write(root.join("Cafe\u{301}/only-here.jpg"), b"x").unwrap();
        assert!(!is_exact_path_confirmed_absent(root, "Cafe\u{301}/only-here.jpg"));
        assert!(is_exact_path_confirmed_absent(root, "Caf\u{e9}/only-here.jpg"));
    }

    /// A form-sensitive volume whose only entry is the other form's directory has no such
    /// ancestor: the path is absent, not withheld behind a different directory.
    #[cfg(target_os = "linux")]
    #[test]
    fn another_unicode_form_alone_is_not_the_ancestor_on_a_form_sensitive_volume() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("Caf\u{e9}")).unwrap();
        std::fs::write(root.join("Caf\u{e9}/a.jpg"), b"x").unwrap();
        if std::fs::symlink_metadata(root.join("Cafe\u{301}")).is_ok() {
            return;
        }
        assert!(is_exact_path_confirmed_absent(root, "Cafe\u{301}/a.jpg"));
        assert!(!try_exact_leaf_exists_as_file_or_symlink(root, "Cafe\u{301}/a.jpg").unwrap());
    }

    /// An unlistable directory is no evidence of absence.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_directory_is_not_an_absence() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("d")).unwrap();
        std::fs::write(root.join("d/a"), b"x").unwrap();
        std::fs::set_permissions(root.join("d"), std::fs::Permissions::from_mode(0o000)).unwrap();
        let readable = std::fs::read_dir(root.join("d")).is_ok(); // root user ignores modes
        let absent = is_exact_path_confirmed_absent(root, "d/a");
        let leaf = try_exact_leaf_exists_as_directory(root, "d/a");
        std::fs::set_permissions(root.join("d"), std::fs::Permissions::from_mode(0o755)).unwrap();
        if !readable {
            assert!(!absent);
            assert!(leaf.is_err());
        }
    }
}
