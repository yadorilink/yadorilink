//! Filesystem write primitives for materializing content from block
//! storage: write-target/delete-target symlink-escape verification, atomic
//! temp-then-rename file reconstruction, sparse placeholder writes, and
//! the owner-exec bit.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::content_ports::BlockContentStore;
use crate::error::StorageError;
use crate::fs_ops::{durable_namespace_beside, remove_path, rename_path, LedgerNames};
use crate::LocallyHashedBlock;
use yadorilink_fs_platform::durable_dir::{NsError, Replace};
use yadorilink_replica_domain::file::BlockInfo;

/// How much of a reconstructed file's durability the writer pays for itself.
///
/// `Full` (the default everywhere) flushes the temp file before the rename and
/// the parent directories after it. `DeferredToBatch` is for content that is
/// already durable elsewhere (a block just received into the segment store):
/// the writer neither flushes the file nor the directories, keeps the temp
/// name's ledger record, and the caller owes one [`flush_received_files`] for
/// the batch before it forgets that the write was in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Durability {
    #[default]
    Full,
    DeferredToBatch,
    /// For content that is NOT durable elsewhere (a block kept in memory for a single-pass
    /// receive): the writer flushes the file's data before it can be renamed into place, so a cut
    /// after the rename cannot leave a torn file that nothing could rebuild; the directory flush
    /// and the temp name's ledger record are deferred to the batch exactly as for
    /// `DeferredToBatch`.
    FileFlushedNamesDeferred,
}

/// Prefix of every temp name. Kept as the legacy marker so the reserved
/// namespace keeps such a name out of indexing, and so a leftover from an
/// older build (`<name>.yadorilink-tmp.<pid>.<n>`) is recognised by the same
/// predicate.
const TMP_PREFIX: &str = ".yadorilink-tmp.";

/// Attempts at finding an unused temp name before giving up. A random
/// 128-bit name colliding is not a chance event, so a second collision already
/// means something is planting names.
const MAX_TMP_NAME_ATTEMPTS: usize = 8;

/// A fresh temp path beside `path`: a fixed-length name of 128 random bits that
/// does not depend on `path`'s own name, so it can neither be predicted nor
/// outgrow the filesystem's component limit.
pub fn random_tmp_path(path: &Path) -> PathBuf {
    let mut bits = [0u8; 16];
    rand::fill(&mut bits[..]);
    path.with_file_name(format!("{TMP_PREFIX}{}", hex::encode(bits)))
}

/// Records a new temp name in `ledger` and creates the object there with
/// `create`, which must fail rather than reuse anything already at the name
/// (`create_new`, `symlink`).
///
/// A name the ledger already holds, or one something already occupies, belongs
/// to someone else: it is never created over, removed or released, and a new
/// name is tried instead, a bounded number of times. Any other failure ends
/// the attempt, releasing only the record this call made.
fn create_recorded_tmp<T>(
    out_path: &Path,
    ledger: &dyn TempFileLedger,
    mut next_name: impl FnMut(&Path) -> PathBuf,
    mut create: impl FnMut(&Path) -> std::io::Result<T>,
) -> Result<(PathBuf, T), StorageError> {
    let mut preassigned = ledger.preassigned_name();
    for _ in 0..MAX_TMP_NAME_ATTEMPTS {
        let tmp_path = preassigned.take().unwrap_or_else(|| next_name(out_path));
        match ledger.record(&tmp_path) {
            Ok(()) => {}
            Err(StorageError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
        match create(&tmp_path) {
            Ok(created) => return Ok((tmp_path, created)),
            Err(e) => {
                // Nothing was created by this call, so only the record is ours.
                ledger.release(&tmp_path);
                if e.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(e.into());
                }
            }
        }
    }
    Err(StorageError::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!("no unused temp name found beside {out_path:?}"),
    )))
}

/// Creates a new regular file at `path`, never following a symlink at the
/// name and never reusing an existing object.
fn create_new_file(path: &Path) -> std::io::Result<fs::File> {
    create_new_file_with(path, false)
}

/// [`create_new_file`] that can also be read, for a file that is read back after it is written.
fn create_new_file_read_write(path: &Path) -> std::io::Result<fs::File> {
    create_new_file_with(path, true)
}

fn create_new_file_with(path: &Path, read: bool) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(read).write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NOFOLLOW);
    #[cfg(windows)]
    // FILE_FLAG_OPEN_REPARSE_POINT: a reparse point at the name is opened as
    // itself, not followed (and `create_new` already refuses an existing name).
    std::os::windows::fs::OpenOptionsExt::custom_flags(&mut options, 0x0020_0000);
    options.open(path)
}

/// Where a writer records, durably, the temp file it is about to create.
///
/// A temp file exists between its `create` and the `rename` that publishes it
/// (or the `remove` that discards it). A crash in that span leaves it on disk,
/// and the only honest way to find it again is for something durable to have
/// named it first: [`Self::record`] runs BEFORE the file is created and must
/// not return until the name is durable; [`Self::release`] runs AFTER the file
/// has been renamed away or removed. A row left behind by a crash is what the
/// recovery at the next start works from, so nothing ever has to guess from a
/// file name that a stray file is ours.
pub trait TempFileLedger: Send + Sync {
    fn record(&self, tmp_path: &Path) -> Result<(), StorageError>;
    /// Best effort: a row that outlives its file only names a path that no
    /// longer exists, which recovery clears without touching anything.
    fn release(&self, tmp_path: &Path);
    /// Records that the directory at `dir_path` was moved aside by a durable
    /// removal and could not be put back, so it stands there with its
    /// contents and the user has to be told. The directory is on
    /// disk either way, but an unreported one is a silent one, so a failure to
    /// record it is an error for the caller.
    fn strand(&self, dir_path: &Path) -> Result<(), StorageError>;
    /// A temp name chosen in advance (and already named by the write's intent), which the next
    /// temp created through this ledger takes as its first candidate. Taken once.
    fn preassigned_name(&self) -> Option<PathBuf> {
        None
    }
}

/// For writers with no recovery to speak of (a one-shot copy outside any
/// linked folder, tests).
pub struct NoTempLedger;

impl TempFileLedger for NoTempLedger {
    fn record(&self, _tmp_path: &Path) -> Result<(), StorageError> {
        Ok(())
    }
    fn release(&self, _tmp_path: &Path) {}
    fn strand(&self, _dir_path: &Path) -> Result<(), StorageError> {
        Ok(())
    }
}

/// Removes a temp file that will not be published and releases its record,
/// in that order: the record outlives the file, never the reverse. A removal
/// that fails (other than the file already being gone) keeps the record, so
/// the next link start retries it.
pub fn discard_temp_file(tmp_path: &Path, ledger: &dyn TempFileLedger) {
    match remove_path(tmp_path) {
        Ok(()) => release_once_gone_is_durable(tmp_path, ledger),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ledger.release(tmp_path),
        Err(_) => {}
    }
}

/// Releases the record of a temp file that was just removed or renamed away,
/// but only once its disappearance is durable: after a power failure the name
/// could otherwise come back with no record left to find it by. A directory
/// sync that fails keeps the record.
fn release_once_gone_is_durable(tmp_path: &Path, ledger: &dyn TempFileLedger) {
    // Windows has no documented durability for an unlink (the no-op sync below is not one):
    // the record stays until a recovery sees the path absent.
    if cfg!(unix) && sync_parent_directory(tmp_path).is_ok() {
        ledger.release(tmp_path);
    }
}

/// Defense-in-depth: creates `out_path`'s parent directory (if needed) then
/// canonicalizes it and confirms it still `starts_with` `sync_root`'s own
/// canonical form, before any caller writes through `out_path`. A purely
/// lexical `..`/absolute-path rejection on the caller's side cannot detect
/// a **symlink** at an intermediate path component already present on
/// disk (planted by a local actor, or a TOCTOU race), which the plain
/// `create`/`rename` calls in `reconstruct_file`/`write_placeholder` below
/// would otherwise follow right out of the sync root. This closes that
/// specific gap for the common case (a symlinked *directory* component);
/// it does not fully eliminate every TOCTOU window (e.g. a symlink
/// swapped in between this check and the write) — known "Low / TOCTOU"
/// severity residual: exploiting even this residual window requires a
/// locally pre-planted symlink or a racing local actor, not something a
/// remote peer can create on its own.
///
/// Self-contained (canonicalizes `sync_root` itself on every call) —
/// callers that invoke this on a hot, concurrency-sensitive path for the
/// same `sync_root` repeatedly should prefer
/// `verify_write_target_within_canonical_root` with a `sync_root`
/// canonicalized once up front.
pub fn verify_write_target_within_root(
    out_path: &Path,
    sync_root: &Path,
    ledger: &dyn StructuralDirectoryLedger,
) -> Result<(), StorageError> {
    // The root itself, not a directory inside it: the one creation this
    // module makes outside [`create_dir_all_never_through_a_symlink`].
    fs::create_dir_all(sync_root)?;
    let canonical_root = fs::canonicalize(sync_root)?;
    verify_write_target_within_canonical_root(out_path, &canonical_root, ledger)
}

/// Resolves a root-relative path for *reading*, refusing if any component of
/// it is a symlink.
///
/// The read-side counterpart of [`verify_write_target_within_root`], and it
/// exists because the two directions disagreed. A write was already refused
/// when a component resolved outside the root; a read was not, so a directory
/// symlink planted inside a sync root let the capture path read a file that
/// lives outside it — and, being a capture, replicate those bytes to every
/// peer in the group. Measured, not theorised.
///
/// The rule is deliberately about *traversal*, not about where the target
/// lands:
///
/// ```text
///   root/real-dir/...     resolved
///   root/link             resolved, as the symlink itself
///   root/link/anything    never
/// ```
///
/// A link whose target is inside the root is refused too. Following it would
/// give the same bytes two logical paths — `real/file` and `alias/file` —
/// and this replica model uses a path as a semantic identity: duplicate
/// Changes, ambiguous renames and deletes, ambiguous conflict copies, and
/// cycles all follow from allowing one object two names.
///
/// A symlink is a synchronised filesystem object, not an edge the tree walk
/// may cross.
pub fn resolve_read_path_without_traversal(
    root: &Path,
    relative: &Path,
) -> Result<PathBuf, StorageError> {
    let mut resolved = root.to_path_buf();
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        resolved.push(component);
        // The final component may itself be a symlink: that is a file this
        // folder legitimately contains, and it is synchronised as a symlink.
        // What it must never be is walked *through*, which is what having a
        // further component after it would mean.
        let is_intermediate = components.peek().is_some();
        match fs::symlink_metadata(&resolved) {
            Ok(metadata) if metadata.file_type().is_symlink() && is_intermediate => {
                return Err(StorageError::PathEscapesRoot(resolved.display().to_string()));
            }
            // A component that does not exist cannot be a symlink being
            // traversed, and its absence is the caller's business, not this
            // function's.
            _ => {}
        }
    }
    Ok(resolved)
}

/// Like `verify_write_target_within_root`, but takes an already-canonical
/// `canonical_root` (resolved once by the caller) instead of re-resolving
/// it on every call — see that function's doc comment for why this
/// matters on a hot path.
pub fn verify_write_target_within_canonical_root(
    out_path: &Path,
    canonical_root: &Path,
    ledger: &dyn StructuralDirectoryLedger,
) -> Result<(), StorageError> {
    let parent = out_path.parent().unwrap_or(out_path);
    create_dir_all_never_through_a_symlink(parent, canonical_root, out_path, ledger)?;
    let canonical_parent = fs::canonicalize(parent)?;
    if !canonical_parent.starts_with(canonical_root) {
        return Err(StorageError::PathEscapesRoot(out_path.display().to_string()));
    }
    Ok(())
}

/// Where the materializer records the directories it creates only to hold
/// descendants (structural directories), so that nothing later mistakes
/// one for a directory a user made.
///
/// A directory's filesystem identity exists only after it is created, but
/// the claim that this device created it has to be durable before, or a
/// crash in between leaves a directory nothing says this device made --
/// which capture would read as a user's `mkdir`. So each creation in
/// [`create_dir_all_never_through_a_symlink`] is bracketed:
///
/// 1. [`Self::record_intent`] before the `mkdir` (durable before the
///    syscall);
/// 2. [`Self::complete`] after a `mkdir` that created the directory, with
///    the identity observed on it;
/// 3. [`Self::abandon`] when the `mkdir` found the name taken (`EEXIST`,
///    a user or another writer got there first) or failed: nothing is
///    claimed for what is there;
/// 4. [`Self::interrupted`] when the writer leaves with neither of those
///    done (the ledger itself failed, or a panic is unwinding): the intent is
///    resolved as recovery would resolve it, so a running process never leaves
///    one pending.
///
/// `rel_path` is the directory's path relative to the sync root, with `/`
/// separators -- the same form every replicated path has. An
/// implementation is bound to one group; it is the owner of the
/// structural-origin ledger for that group's root.
pub trait StructuralDirectoryLedger {
    /// Where the Stage names of the directories this writer creates are
    /// recorded, so a crash between the Stage directory and its publication
    /// leaves a record to clean it by, never a name to guess from. A ledger
    /// with no recovery to speak of keeps the default.
    fn names(&self) -> &dyn TempFileLedger {
        &NoTempLedger
    }
    fn record_intent(&self, rel_path: &str) -> Result<(), StorageError>;
    fn complete(
        &self,
        rel_path: &str,
        identity: &yadorilink_fs_platform::fs_identity::FileIdentity,
    ) -> Result<(), StorageError>;
    fn abandon(&self, rel_path: &str) -> Result<(), StorageError>;
    fn interrupted(&self, rel_path: &str) -> Result<(), StorageError>;
}

/// What [`create_explicit_directory`] found or did at its path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExplicitDirectoryCreation {
    /// This call created the directory.
    Created,
    /// A directory was already there; it is left as it is.
    AlreadyDirectory,
}

/// Creates `out_path` as a directory that is itself a replicated entry (an
/// explicit Directory version), inside `canonical_root`.
///
/// Its missing ancestors are structural -- they exist only to hold it --
/// and are created through [`create_dir_all_never_through_a_symlink`],
/// which records them in `ledger`. `out_path` itself is not structural and
/// is not recorded there: what records it is the materialized proof its
/// caller publishes for the version.
///
/// A directory already at `out_path` is kept (its mode is the caller's to
/// apply). Anything else there -- a file, a symlink -- is refused with
/// [`std::io::ErrorKind::AlreadyExists`] and left untouched.
pub fn create_explicit_directory(
    out_path: &Path,
    canonical_root: &Path,
    ledger: &dyn StructuralDirectoryLedger,
) -> Result<ExplicitDirectoryCreation, StorageError> {
    verify_write_target_within_canonical_root(out_path, canonical_root, ledger)?;
    match make_directory(out_path, ledger) {
        Ok(()) => Ok(ExplicitDirectoryCreation::Created),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            match fs::symlink_metadata(out_path) {
                Ok(meta) if meta.is_dir() => Ok(ExplicitDirectoryCreation::AlreadyDirectory),
                Ok(_) => Err(StorageError::Io(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!(
                        "{} is occupied by an object that is not a directory",
                        out_path.display()
                    ),
                ))),
                Err(e) => Err(e.into()),
            }
        }
        Err(e) => Err(e.into()),
    }
}

/// One directory, created empty at `path`: a Stage directory published by a
/// durable move where the volume offers it, so the name is on disk before the
/// caller reports it, and a plain `mkdir` followed by a best-effort parent sync
/// where it does not.
fn make_directory(path: &Path, ledger: &dyn StructuralDirectoryLedger) -> std::io::Result<()> {
    if let Some(ns) = durable_namespace_beside(path)? {
        return ns.create_dir(path, &LedgerNames(ledger.names())).map_err(std::io::Error::from);
    }
    fs::create_dir(path)?;
    if let Err(error) = sync_parent_directory(path) {
        tracing::warn!(
            path = %path.display(),
            error = %error,
            "directory was created but its parent directory could not be synced"
        );
    }
    Ok(())
}

/// Creates every missing directory component of `target` (`out_path`'s
/// parent) WITHOUT ever creating anything by walking through an
/// already-existing symlink -- unlike plain `fs::create_dir_all`, which
/// happily follows one. A symlink planted at an intermediate component
/// inside an already-adopted sync root (e.g. `escape -> /outside`) would
/// otherwise let `create_dir_all(parent)` create real directories on the
/// far side of that symlink, entirely outside the sync root, before any
/// `canonicalize`+`starts_with` check ever ran.
///
/// The fix: find the deepest ALREADY-EXISTING ancestor of `target` first
/// (never itself created by this call), canonicalize just that ancestor,
/// and refuse immediately if it has already escaped `canonical_root` --
/// this is the only place a pre-existing symlink can be hiding, since
/// everything below it, if any, is about to be created by this
/// function itself. Every directory this function creates from there
/// down is freshly made by `fs::create_dir` one level at a time, so it is
/// by construction a plain directory, never a symlink. A residual TOCTOU
/// window remains between the existing-ancestor check and the first
/// `create_dir` -- the same documented "Low / TOCTOU" class of residual
/// `verify_write_target_within_root`'s own doc comment already accepts.
pub fn create_dir_all_never_through_a_symlink(
    target: &Path,
    canonical_root: &Path,
    out_path_for_errors: &Path,
    ledger: &dyn StructuralDirectoryLedger,
) -> Result<(), StorageError> {
    let mut existing_ancestor = target;
    let mut to_create = Vec::new();
    loop {
        match fs::symlink_metadata(existing_ancestor) {
            Ok(meta) if meta.is_dir() => break,
            Ok(_) => {
                // Exists but is not a directory (a file, or -- the case
                // this function exists to catch -- a symlink). Whether
                // it's actually an escape or just a legitimately-adopted
                // non-directory in the way, refuse rather than create
                // anything through or over it.
                return Err(StorageError::PathEscapesRoot(
                    out_path_for_errors.display().to_string(),
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let Some(parent) = existing_ancestor.parent() else {
                    // Walked all the way to a filesystem root with
                    // nothing found -- `canonical_root` itself must be an
                    // ancestor of `target` for this to ever be reached
                    // legitimately; if it isn't, there's nothing safe to
                    // create.
                    return Err(StorageError::PathEscapesRoot(
                        out_path_for_errors.display().to_string(),
                    ));
                };
                to_create.push(existing_ancestor);
                existing_ancestor = parent;
            }
            Err(e) => return Err(e.into()),
        }
    }
    let canonical_existing_ancestor = fs::canonicalize(existing_ancestor)?;
    if !canonical_existing_ancestor.starts_with(canonical_root) {
        return Err(StorageError::PathEscapesRoot(out_path_for_errors.display().to_string()));
    }
    // Every directory below the existing ancestor is created here, so its
    // root-relative name is the ancestor's plus the components walked.
    let ancestor_rel = canonical_existing_ancestor
        .strip_prefix(canonical_root)
        .map_err(|_| StorageError::PathEscapesRoot(out_path_for_errors.display().to_string()))?
        .to_path_buf();
    // `to_create` was pushed shallowest-last (closest to `target` first);
    // create shallowest-first so each `create_dir` call's own parent
    // already exists.
    for dir in to_create.into_iter().rev() {
        let tail = dir.strip_prefix(existing_ancestor).map_err(|_| {
            StorageError::PathEscapesRoot(out_path_for_errors.display().to_string())
        })?;
        let rel_path = wire_relative_path(&ancestor_rel.join(tail))?;
        create_structural_directory(dir, &rel_path, ledger)?;
    }
    Ok(())
}

/// A structural intent this writer has recorded and not yet settled. If the
/// writer leaves while it is still armed -- a settling call that failed, or a
/// panic unwinding past the `mkdir` -- the ledger resolves the intent, so
/// nothing is left for a periodic sweep to guess about.
struct OpenStructuralIntent<'a> {
    ledger: &'a dyn StructuralDirectoryLedger,
    rel_path: &'a str,
    armed: bool,
}

impl OpenStructuralIntent<'_> {
    /// Disarms on a settling call that succeeded; passes its result through.
    fn settle(&mut self, settled: Result<(), StorageError>) -> Result<(), StorageError> {
        if settled.is_ok() {
            self.armed = false;
        }
        settled
    }
}

impl Drop for OpenStructuralIntent<'_> {
    fn drop(&mut self) {
        if self.armed {
            // Best effort, and never a second panic out of a drop: whatever
            // this cannot resolve, startup and the next link start do.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = self.ledger.interrupted(self.rel_path);
            }));
        }
    }
}

/// One structural `mkdir`, bracketed by `ledger`: the intent is durable
/// before the syscall, the identity recorded after it. A name found taken
/// (`EEXIST`: a user, or another writer, created it since the walk above
/// looked) is abandoned without a claim, and is then accepted only if it
/// is a real directory. Any other failure abandons the intent too, so a
/// failed `mkdir` leaves nothing pending; a failure to abandon or complete
/// resolves the intent through [`StructuralDirectoryLedger::interrupted`].
///
/// The identity is observed by name right after the `mkdir`: neither macOS
/// nor Linux has a `mkdir` that returns a descriptor of the directory it
/// made. A directory another process swaps in at the same name within that
/// gap (removing the new one and making its own) is recorded as structural
/// in its place. What that can cost is bounded: a structural directory is
/// only ever pruned with a non-recursive `rmdir`, so at most that
/// replacement is removed later, and only while it is empty -- never a file
/// or anything inside a directory. Making the directory under a private
/// name and renaming it into place is no better: a plain directory rename
/// replaces an empty directory already at the target, and a crash between
/// the two leaves the privately named directory in the sync root.
/// [`make_directory`] does it anyway where the volume offers durable moves: the
/// move refuses an occupied target, and the Stage name is in the temp-file
/// ledger before the directory exists, so a crash leaves a record to clean it by.
fn create_structural_directory(
    dir: &Path,
    rel_path: &str,
    ledger: &dyn StructuralDirectoryLedger,
) -> Result<(), StorageError> {
    ledger.record_intent(rel_path)?;
    let mut open = OpenStructuralIntent { ledger, rel_path, armed: true };
    match make_directory(dir, ledger) {
        Ok(()) => {
            let identity =
                match yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(dir) {
                    Ok(identity) => identity,
                    Err(e) => {
                        // Created, but its identity cannot be read: nothing to
                        // bind the claim to, so none is made.
                        let _ = open.settle(ledger.abandon(rel_path));
                        return Err(e.into());
                    }
                };
            open.settle(ledger.complete(rel_path, &identity))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            open.settle(ledger.abandon(rel_path))?;
            match fs::symlink_metadata(dir) {
                Ok(meta) if meta.is_dir() => Ok(()),
                _ => Err(StorageError::PathEscapesRoot(dir.display().to_string())),
            }
        }
        Err(e) => {
            let _ = open.settle(ledger.abandon(rel_path));
            Err(e.into())
        }
    }
}

/// `relative` as a replicated path: its normal components joined with `/`.
fn wire_relative_path(relative: &Path) -> Result<String, StorageError> {
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            std::path::Component::Normal(part) => parts.push(part.to_str().ok_or_else(|| {
                StorageError::InvalidPath(format!("{} is not valid UTF-8", relative.display()))
            })?),
            std::path::Component::CurDir => {}
            _ => {
                return Err(StorageError::InvalidPath(format!(
                    "{} is not a plain relative path",
                    relative.display()
                )))
            }
        }
    }
    Ok(parts.join("/"))
}

/// The write primitives below never create a directory: inside a sync
/// root every directory is created by
/// [`create_dir_all_never_through_a_symlink`], which records the ones it
/// makes for descendants, and their callers run it first (through
/// [`verify_write_target_within_root`] or its canonical-root form). A
/// missing parent here means the caller skipped that step, or something
/// removed the directory since; either way it fails rather than creating an
/// unrecorded directory.
fn require_parent_directory(out_path: &Path) -> Result<(), StorageError> {
    let Some(parent) = out_path.parent().filter(|parent| !parent.as_os_str().is_empty()) else {
        return Ok(());
    };
    if fs::metadata(parent).is_ok_and(|meta| meta.is_dir()) {
        return Ok(());
    }
    Err(StorageError::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!(
            "{} has no parent directory; verify the write target (which creates it) first",
            out_path.display()
        ),
    )))
}

/// Like `verify_write_target_within_root`, but for a caller about to
/// DELETE `out_path` rather than write it. Two differences from the write
/// version, both because a delete target that isn't there needs no
/// escape-checking machinery at all: this never creates `sync_root` or
/// `out_path`'s parent as a side effect, and a missing `sync_root` or
/// parent is treated as "nothing to verify, proceed" rather than an error
/// — the delete itself (`remove_file`) already tolerates a missing target.
pub fn verify_delete_target_within_root(
    out_path: &Path,
    sync_root: &Path,
) -> Result<(), StorageError> {
    let canonical_root = match fs::canonicalize(sync_root) {
        Ok(root) => root,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(StorageError::from(e)),
    };
    verify_delete_target_within_canonical_root(out_path, &canonical_root)
}

/// Like `verify_delete_target_within_root`, but takes an already-canonical
/// `canonical_root` — see `verify_write_target_within_canonical_root`'s doc
/// comment for why this matters on a hot path.
pub fn verify_delete_target_within_canonical_root(
    out_path: &Path,
    canonical_root: &Path,
) -> Result<(), StorageError> {
    let parent = out_path.parent().unwrap_or(out_path);
    let canonical_parent = match fs::canonicalize(parent) {
        Ok(parent) => parent,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(StorageError::from(e)),
    };
    if !canonical_parent.starts_with(canonical_root) {
        return Err(StorageError::PathEscapesRoot(out_path.display().to_string()));
    }
    Ok(())
}

/// Best-effort: stamps `file`'s modified-time to `mtime_unix_nanos`, unless
/// it is negative (the "no authoritative mtime to stamp" sentinel, e.g. a
/// purely local write with no wire-carried authored time). Shared by
/// `write_placeholder` and `reconstruct_file` so every materialization write
/// — sparse placeholder or real content alike — stamps the on-disk mtime the
/// same way.
///
/// A `set_times` failure here (some filesystems/platforms don't support
/// setting mtime at all, or only at coarser precision) is silently
/// ignored, not propagated -- this is `mtime`'s retained-only treatment
/// (see `SettlementEvidence::ExactObject`'s own doc comment for the full
/// target-projection-contract model this and every other metadata field
/// follows): `mtime_unix_nanos` stays authoritative in the LOGICAL
/// version (`version_hash`) regardless of whether this stamp lands, and
/// nothing downstream currently strict-verifies disk mtime against it,
/// so a failed stamp never blocks completion. It is not, however,
/// unimportant when it succeeds: `reconstruct_file`'s own doc comment
/// below explains a real, separate mechanism (`local_change.rs`'s
/// self-echo-suppression fast path) that this stamp landing correctly
/// makes cheaper -- a failure just means that one fast path doesn't
/// fire for this file, falling through to the slower but still-correct
/// content-hash comparison a few steps further down the same function,
/// not that anything becomes wrong.
fn stamp_mtime(file: &fs::File, mtime_unix_nanos: i64) {
    if mtime_unix_nanos >= 0 {
        let mtime = std::time::SystemTime::UNIX_EPOCH
            + std::time::Duration::from_nanos(mtime_unix_nanos as u64);
        let times = fs::FileTimes::new().set_modified(mtime);
        let _ = file.set_times(times);
    }
}

/// [`stamp_mtime`]'s path-based counterpart, for a caller (a metadata-
/// only fast path that never opens its own fresh `File` handle the way
/// `reconstruct_file`/`write_placeholder` do mid-write) that only has
/// `path` to work with. Best-effort in exactly the same way: a
/// `set_times` failure is silently ignored, never propagated -- see
/// `stamp_mtime`'s own doc comment for the target-projection-contract
/// reasoning (mtime is retained-only, not exact-required, on every
/// target today). Only the leading `File::open` can fail here, and that
/// failure IS propagated: a metadata-only fast path only ever calls this
/// after already confirming the path exists, so an open failure at this
/// point is a genuine anomaly, not an expected "this target can't do
/// this" outcome.
///
/// The handle is opened for exactly what setting times needs. On Unix a
/// read-only descriptor suffices (`futimens` checks ownership, not the open
/// mode), and asking for write access would refuse a read-only file. On
/// Windows `SetFileTime` needs `FILE_WRITE_ATTRIBUTES` on the handle, which a
/// read-only open does not carry, so the stamp would always be refused there.
pub fn stamp_mtime_at_path(path: &Path, mtime_unix_nanos: i64) -> Result<(), StorageError> {
    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
        fs::OpenOptions::new().access_mode(FILE_WRITE_ATTRIBUTES).open(path)?
    };
    #[cfg(not(windows))]
    let file = fs::File::open(path)?;
    stamp_mtime(&file, mtime_unix_nanos);
    Ok(())
}

/// Whether `path`'s on-disk mtime already equals `desired_mtime_unix_
/// nanos` -- a pure, read-only comparison with no side effects, the
/// mtime counterpart of `unix_mode_already_matches_disk`/`xattrs_
/// already_match_disk`. Exists so a caller that must bump a physical-
/// mutation fence before its first real mutating syscall (never after)
/// can decide whether attempting `stamp_mtime_at_path` would actually
/// change anything, before committing to either it or a fence bump --
/// this is purely a fence-bump-correctness concern, NOT a completion
/// gate: mtime stays retained-only (see `SettlementEvidence::
/// ExactObject`'s own doc comment), so this function's result never
/// blocks `ExactObject` from being constructed, only decides whether the
/// stamp attempt below it needs a preceding bump.
///
/// A negative `desired_mtime_unix_nanos` (the "no authoritative mtime to
/// stamp" sentinel `stamp_mtime` itself also honors) trivially matches:
/// there is nothing to compare against, the same "not applicable, so
/// nothing to enforce" treatment `unix_mode_already_matches_disk` gives
/// `unix_mode: None`. A pre-1970 on-disk mtime (which a non-negative
/// desired value can never equal) is treated as a mismatch rather than
/// an error -- letting the caller attempt (and, being best-effort,
/// harmlessly fail or succeed at) a real stamp rather than surfacing a
/// hard error for what is, at most, a stale/unusual timestamp already on
/// disk.
pub fn mtime_already_matches_disk(
    path: &Path,
    desired_mtime_unix_nanos: i64,
) -> Result<bool, StorageError> {
    if desired_mtime_unix_nanos < 0 {
        return Ok(true);
    }
    let modified = fs::metadata(path)?.modified()?;
    let actual_nanos = match modified.duration_since(std::time::SystemTime::UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i64,
        Err(_) => return Ok(false),
    };
    Ok(actual_nanos == desired_mtime_unix_nanos)
}

/// Reconstructs a file at `out_path` from `blocks`, reading each block's
/// content from `store` in order and concatenating.
///
/// `mtime_unix_nanos` is the mtime this materialized content is (or is
/// about to be) indexed under — pass a negative value only when no such
/// value exists yet (e.g. a low-level test with no index row). Stamping the
/// on-disk file to match the indexed value here, the same way
/// `write_placeholder` already stamps a placeholder's mtime, is
/// correctness-critical: `yadorilink-local-capture`'s local-change fast
/// path (`local_change.rs::metadata_mtime_matches`) treats "on-disk mtime
/// equals the indexed mtime" as its signal that a file is unchanged since
/// last indexed. Before this stamp existed, a materialized (peer-received)
/// file's on-disk mtime was whatever wall-clock time this write happened to
/// land at — never equal to the wire-carried authored mtime the index
/// recorded for it — so that fast path could never fire for a materialized
/// file, and a later genuine local edit fell all the way through to the
/// content-only self-echo comparison a few steps further down that same
/// function.
pub fn reconstruct_file(
    store: &dyn BlockContentStore,
    out_path: &Path,
    blocks: &[BlockInfo],
    mtime_unix_nanos: i64,
) -> Result<(), StorageError> {
    reconstruct_file_in(store, out_path, blocks, mtime_unix_nanos, &NoTempLedger)
}

/// [`reconstruct_file`] with its temp file recorded in `ledger`.
pub fn reconstruct_file_in(
    store: &dyn BlockContentStore,
    out_path: &Path,
    blocks: &[BlockInfo],
    mtime_unix_nanos: i64,
    ledger: &dyn TempFileLedger,
) -> Result<(), StorageError> {
    // What this call may replace is what stands at the path as it starts: a save that lands during
    // the assembly or at the rename is kept (see `persist_reconstructed_file_checked`).
    let expected = TargetExpectation::observe(out_path)?;
    let tmp_path = reconstruct_file_to_temp_in(store, out_path, blocks, mtime_unix_nanos, ledger)?;
    let published = persist_reconstructed_file_checked(
        &tmp_path,
        out_path,
        ledger,
        Durability::Full,
        None,
        expected,
    );
    // A refusal leaves the temp to the caller; this caller has no use for it and keeps no handle
    // on its name, so it goes here.
    if matches!(published, Err(StorageError::TargetChanged(_))) {
        discard_temp_file(&tmp_path, ledger);
    }
    published
}

/// The "assemble" half of [`reconstruct_file`]: reads `blocks` from `store`
/// and writes them, concatenated, into a fresh, durably-fsynced temp file
/// near `out_path` (same directory, so a later rename can be atomic on the
/// same filesystem) -- WITHOUT touching `out_path` itself at all. Returns
/// the temp file's path.
///
/// Split out (receiver-side materialization batching) so a caller
/// that needs to defer the final publish -- e.g. to batch several paths'
/// SQLite commits together before any of them become visible on disk --
/// can do the slow part (this function: network-fetch-bound block reads)
/// without holding that path's lock, then take the lock only for the fast
/// [`persist_reconstructed_file`] half. Callers with no such need should
/// keep calling [`reconstruct_file`], which does both steps exactly as
/// before -- this split changes no behavior for them.
///
/// On any failure (a block-store read error mid-loop, a short write), the
/// temp file is removed so an interrupted assemble leaves the directory as
/// it found it -- the caller never receives a `tmp_path` for a file that
/// only partially exists.
pub fn reconstruct_file_to_temp(
    store: &dyn BlockContentStore,
    out_path: &Path,
    blocks: &[BlockInfo],
    mtime_unix_nanos: i64,
) -> Result<PathBuf, StorageError> {
    reconstruct_file_to_temp_in(store, out_path, blocks, mtime_unix_nanos, &NoTempLedger)
}

/// [`reconstruct_file_to_temp`] with the temp file recorded in `ledger`
/// before it is created. The caller owns the record from here on: it ends
/// in [`persist_reconstructed_file_in`] or [`discard_temp_file`].
pub fn reconstruct_file_to_temp_in(
    store: &dyn BlockContentStore,
    out_path: &Path,
    blocks: &[BlockInfo],
    mtime_unix_nanos: i64,
    ledger: &dyn TempFileLedger,
) -> Result<PathBuf, StorageError> {
    reconstruct_file_to_temp_observed(store, out_path, blocks, mtime_unix_nanos, ledger, &|_| {})
}

/// [`reconstruct_file_to_temp_in`] that reports each block's size once it was written.
pub fn reconstruct_file_to_temp_observed(
    store: &dyn BlockContentStore,
    out_path: &Path,
    blocks: &[BlockInfo],
    mtime_unix_nanos: i64,
    ledger: &dyn TempFileLedger,
    written: &dyn Fn(u64),
) -> Result<PathBuf, StorageError> {
    reconstruct_file_to_temp_observed_durable(
        store,
        out_path,
        blocks,
        mtime_unix_nanos,
        ledger,
        written,
        Durability::Full,
    )
}

/// [`reconstruct_file_to_temp_observed`] with the temp file's own flush chosen.
/// `DeferredToBatch` leaves the finished temp file unflushed.
pub fn reconstruct_file_to_temp_observed_durable(
    store: &dyn BlockContentStore,
    out_path: &Path,
    blocks: &[BlockInfo],
    mtime_unix_nanos: i64,
    ledger: &dyn TempFileLedger,
    written: &dyn Fn(u64),
    durability: Durability,
) -> Result<PathBuf, StorageError> {
    reconstruct_file_to_named_temp_with(
        store,
        out_path,
        blocks,
        mtime_unix_nanos,
        ledger,
        written,
        durability,
        random_tmp_path,
    )
}

/// [`reconstruct_file_to_temp_observed`] with the source of temp names given
/// (tests make names collide).
#[cfg(test)]
fn reconstruct_file_to_named_temp(
    store: &dyn BlockContentStore,
    out_path: &Path,
    blocks: &[BlockInfo],
    mtime_unix_nanos: i64,
    ledger: &dyn TempFileLedger,
    written: &dyn Fn(u64),
    next_name: impl FnMut(&Path) -> PathBuf,
) -> Result<PathBuf, StorageError> {
    reconstruct_file_to_named_temp_with(
        store,
        out_path,
        blocks,
        mtime_unix_nanos,
        ledger,
        written,
        Durability::Full,
        next_name,
    )
}

#[allow(clippy::too_many_arguments)]
fn reconstruct_file_to_named_temp_with(
    store: &dyn BlockContentStore,
    out_path: &Path,
    blocks: &[BlockInfo],
    mtime_unix_nanos: i64,
    ledger: &dyn TempFileLedger,
    written: &dyn Fn(u64),
    durability: Durability,
    next_name: impl FnMut(&Path) -> PathBuf,
) -> Result<PathBuf, StorageError> {
    require_parent_directory(out_path)?;
    // The name is durable before the file exists.
    let (tmp_path, mut out) = create_recorded_tmp(out_path, ledger, next_name, create_new_file)?;
    // Removes the temp file on every way out but success, a panic included.
    struct RemoveUnlessKept<'a>(PathBuf, bool, &'a dyn TempFileLedger);
    impl Drop for RemoveUnlessKept<'_> {
        fn drop(&mut self) {
            if !self.1 {
                discard_temp_file(&self.0, self.2);
            }
        }
    }
    let mut cleanup = RemoveUnlessKept(tmp_path.clone(), false, ledger);
    let mut assemble = move || -> Result<(), StorageError> {
        // Straight-line and synchronous, so the guard covers exactly these
        // reads and nothing else.
        let _reads = crate::io_diag::attribute_reads(crate::io_diag::ReadReason::Reconstruct);
        for block in blocks {
            let hash_hex = hex::encode(&block.hash);
            let data = store.get(&hash_hex)?;
            std::io::Write::write_all(&mut out, &data)?;
            written(data.len() as u64);
        }
        // Receiver-side phase markers (see hydration.rs's own `phase T_recv_*`
        // markers for the daemon-level points either side of this function).
        // This function is shared with the version-restore materialization
        // path, not only on-demand hydration -- a phase-log reader
        // interested specifically in a bulk-transfer receiver run should
        // anchor these against `T_recv_materialize_start`, which only the
        // hydration path emits.
        tracing::debug!("phase T_recv_write_done: final-file write complete (all blocks written to the temp file)");
        // Stamp the mtime before the final `sync_all`/rename below, so a
        // reader that observes the renamed-into-place file always also
        // observes its final mtime — no window where the file is visible
        // under its real name with a stale (creation-time) mtime.
        stamp_mtime(&out, mtime_unix_nanos);
        // Closing a file only releases the handle; it does not make its data
        // durable across power loss. Persist the complete temp before the
        // rename can publish it under the user-visible path.
        if durability != Durability::DeferredToBatch {
            crate::io_diag::time(crate::io_diag::Op::FileFsync, 0, || {
                yadorilink_fs_platform::flush::sync_file(&out)
            })?;
        }
        tracing::debug!("phase T_recv_fsync_done: final-file fsync complete");
        Ok(())
        // `out` is dropped (closed) here, before the rename below.
    };
    assemble()?;
    cleanup.1 = true;
    Ok(tmp_path)
}

/// A temp file a crash left, opened and read back against the version's blocks: recovery
/// finishes a write from it only through this handle.
///
/// The file is opened without following a symlink, must be a regular file with one name only (a
/// second hard link would let someone else write the bytes that were verified, or have their own
/// file's metadata changed), and is verified through the handle it keeps. Stamping, flushing and
/// the last check before the rename all go through that handle; the rename is allowed only while
/// the name still leads to the verified object.
pub struct VerifiedTemp {
    path: PathBuf,
    file: fs::File,
}

impl VerifiedTemp {
    /// `None` unless the file at `path` holds exactly the bytes `blocks` describe: its length is
    /// the record's size and every block range hashes to the block.
    pub fn open(path: &Path, blocks: &[BlockInfo]) -> Option<Self> {
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NOFOLLOW);
        let file = options.open(path).ok()?;
        let temp = Self { path: path.to_path_buf(), file };
        let meta = temp.file.metadata().ok()?;
        let expected: u64 = blocks.iter().map(|block| u64::from(block.size)).sum();
        if !meta.is_file() || meta.len() != expected || !temp.is_still_at_its_path() {
            return None;
        }
        let matches = blocks.iter().all(|block| {
            let mut data = vec![0u8; block.size as usize];
            read_exact_at(&temp.file, &mut data, block.offset).is_ok()
                && LocallyHashedBlock::from_bytes(data).hash().as_bytes()
                    == hex::encode(&block.hash).as_bytes()
        });
        matches.then_some(temp)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Stamps the modification time and flushes the data, both through the verified handle (the
    /// crash may have come before either).
    pub fn prepare_for_publish(&self, mtime_unix_nanos: i64) -> Result<(), StorageError> {
        stamp_mtime(&self.file, mtime_unix_nanos);
        yadorilink_fs_platform::flush::sync_file(&self.file)?;
        Ok(())
    }

    /// Whether the name still leads to the object this handle verified, and that object has one
    /// name only. `false` where the platform gives no object identity.
    pub fn is_still_at_its_path(&self) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let (Ok(handle), Ok(named)) = (self.file.metadata(), fs::symlink_metadata(&self.path))
            else {
                return false;
            };
            named.is_file()
                && (handle.dev(), handle.ino()) == (named.dev(), named.ino())
                && handle.nlink() == 1
        }
        #[cfg(not(unix))]
        {
            false
        }
    }
}

/// A temp file beside its target that a large received file is written into while it arrives: each
/// verified block is written at its offset, in any order, and the file is then flushed and read back
/// against the record before anything can rename it into place.
///
/// The name is recorded in the temp ledger before the file exists, as for every temp. The file is
/// removed, and its ledger record released, when the last holder drops it without having called
/// [`StagedFile::keep`]: write jobs on the blocking pool hold a clone, so the discard runs only after
/// the last of them has finished, never under a write still in flight.
pub struct StagedFile {
    tmp_path: PathBuf,
    file: fs::File,
    ledger: std::sync::Arc<dyn TempFileLedger>,
    kept: std::sync::atomic::AtomicBool,
    /// Data flushes issued before the final one (see [`StagedFile::flush_data`]).
    data_flushes: AtomicU64,
}

impl StagedFile {
    /// Creates the temp beside `out_path` (never reusing a name), sized to `size`.
    pub fn create(
        out_path: &Path,
        size: u64,
        ledger: std::sync::Arc<dyn TempFileLedger>,
    ) -> Result<Self, StorageError> {
        require_parent_directory(out_path)?;
        let (tmp_path, file) = create_recorded_tmp(
            out_path,
            ledger.as_ref(),
            random_tmp_path,
            create_new_file_read_write,
        )?;
        let staged = Self {
            tmp_path,
            file,
            ledger,
            kept: std::sync::atomic::AtomicBool::new(false),
            data_flushes: AtomicU64::new(0),
        };
        // On a failure the drop below removes the temp and releases its record.
        staged.file.set_len(size)?;
        Ok(staged)
    }

    pub fn tmp_path(&self) -> &Path {
        &self.tmp_path
    }

    /// Writes `data` at `offset`.
    pub fn write_at(&self, offset: u64, data: &[u8]) -> std::io::Result<()> {
        write_all_at(&self.file, data, offset)
    }

    /// Flushes the data written so far, while later blocks are still being written. A large file's
    /// dirty pages would otherwise all be waiting for one flush at the end; flushing as it fills
    /// overlaps the disk with the network. A failure here is the file's failure: the caller must
    /// not treat the final flush's success as covering it.
    pub fn flush_data(&self) -> std::io::Result<()> {
        self.data_flushes.fetch_add(1, Ordering::Relaxed);
        crate::io_diag::time(crate::io_diag::Op::SinkStepFlush, 0, || {
            crate::io_diag::time(crate::io_diag::Op::FileFsync, 0, || {
                yadorilink_fs_platform::flush::sync_data(&self.file)
            })
        })
    }

    /// How many data flushes [`StagedFile::flush_data`] has issued.
    pub fn data_flushes(&self) -> u64 {
        self.data_flushes.load(Ordering::Relaxed)
    }

    /// Reads `len` bytes at `offset`.
    fn read_at(&self, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        read_exact_at(&self.file, &mut buf, offset)?;
        Ok(buf)
    }

    /// Completes the file: stamps its modification time, flushes its data, and reads every block
    /// range back, checking it against the record's hash. The written bytes, not the arrived ones,
    /// are what is verified, before they can be renamed in.
    pub fn finish(&self, blocks: &[BlockInfo], mtime_unix_nanos: i64) -> Result<(), StorageError> {
        stamp_mtime(&self.file, mtime_unix_nanos);
        crate::io_diag::time(crate::io_diag::Op::FileFsync, 0, || {
            yadorilink_fs_platform::flush::sync_file(&self.file)
        })?;
        let expected: u64 = blocks.iter().map(|block| u64::from(block.size)).sum();
        if self.file.metadata()?.len() != expected {
            return Err(StorageError::Io(std::io::Error::other(
                "the staged file's length is not the record's size",
            )));
        }
        for block in blocks {
            let data = crate::io_diag::time(
                crate::io_diag::Op::SinkReadbackRead,
                u64::from(block.size),
                || self.read_at(block.offset, block.size as usize),
            )?;
            let digest_matches = crate::io_diag::time(
                crate::io_diag::Op::SinkReadbackHash,
                u64::from(block.size),
                || {
                    LocallyHashedBlock::from_bytes(data).hash().as_bytes()
                        == hex::encode(&block.hash).as_bytes()
                },
            );
            if !digest_matches {
                return Err(StorageError::Io(std::io::Error::other(
                    "a block read back from the staged file does not hash to the record",
                )));
            }
        }
        // What was verified is the object this handle writes: its name must still lead to it, or
        // the rename would publish whatever else stands at the name.
        #[cfg(unix)]
        if !self.is_still_at_its_path() {
            return Err(StorageError::Io(std::io::Error::other(
                "the staged file's name no longer leads to the file that was verified",
            )));
        }
        Ok(())
    }

    /// Whether the bytes at `block`'s range hash to the block (the written bytes are read back,
    /// not trusted). A short or unreadable range is a mismatch.
    pub fn block_matches(&self, block: &BlockInfo) -> bool {
        let Ok(data) = self.read_at(block.offset, block.size as usize) else { return false };
        LocallyHashedBlock::from_bytes(data).hash().as_bytes()
            == hex::encode(&block.hash).as_bytes()
    }

    /// Whether the name this temp was created under still leads to the file this handle writes: a
    /// temp kept for a later attempt may have been removed or replaced meanwhile, and a handle on
    /// an unlinked file must never be renamed into place by its old path. `false` where the
    /// platform gives no object identity.
    pub fn is_still_at_its_path(&self) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let (Ok(handle), Ok(named)) =
                (self.file.metadata(), fs::symlink_metadata(&self.tmp_path))
            else {
                return false;
            };
            // One name only: a second hard link would expose the bytes written through this
            // handle under another name.
            named.is_file()
                && (handle.dev(), handle.ino()) == (named.dev(), named.ino())
                && handle.nlink() == 1
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    /// The identity of the file this handle writes, which is what [`StagedFile::finish`] verified;
    /// the name is renamed into place only while it still leads to this object.
    pub fn object_key(&self) -> Option<crate::received_flush::ObjectKey> {
        crate::received_flush::key_of(&self.file)
    }

    /// Whether removing the temp's name removes this handle's file (or nothing). A name that now
    /// leads to another object is somebody else's file and is left alone.
    fn name_is_ours_to_remove(&self) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            match (self.file.metadata(), fs::symlink_metadata(&self.tmp_path)) {
                (Ok(handle), Ok(named)) => {
                    (handle.dev(), handle.ino()) == (named.dev(), named.ino())
                }
                _ => true,
            }
        }
        #[cfg(not(unix))]
        {
            true
        }
    }

    /// The file is complete and its owner will rename or discard it: the drop no longer removes it.
    /// Returns its path and the ledger it is recorded in.
    pub fn keep(&self) -> (PathBuf, std::sync::Arc<dyn TempFileLedger>) {
        self.kept.store(true, Ordering::SeqCst);
        (self.tmp_path.clone(), self.ledger.clone())
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        if self.kept.load(Ordering::SeqCst) {
            return;
        }
        if self.name_is_ours_to_remove() {
            discard_temp_file(&self.tmp_path, self.ledger.as_ref());
        } else {
            // The name now leads to another object. It is left alone, and its record is
            // released so that recovery, which removes whatever stands at a recorded temp name,
            // never takes it. (Between the check and a removal by name there is the window every
            // path-based removal has; the name is a 128-bit random one in the reserved namespace.)
            // Released only once the replacement is durable (as for a removal), so a rolled-back
            // rename cannot bring our own file back under a name nothing records.
            release_once_gone_is_durable(&self.tmp_path, self.ledger.as_ref());
        }
    }
}

#[cfg(unix)]
fn write_all_at(file: &fs::File, data: &[u8], offset: u64) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::write_all_at(file, data, offset)
}

#[cfg(unix)]
fn read_exact_at(file: &fs::File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::read_exact_at(file, buf, offset)
}

#[cfg(windows)]
fn write_all_at(file: &fs::File, mut data: &[u8], mut offset: u64) -> std::io::Result<()> {
    while !data.is_empty() {
        let n = std::os::windows::fs::FileExt::seek_write(file, data, offset)?;
        if n == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        data = &data[n..];
        offset += n as u64;
    }
    Ok(())
}

#[cfg(windows)]
fn read_exact_at(file: &fs::File, mut buf: &mut [u8], mut offset: u64) -> std::io::Result<()> {
    while !buf.is_empty() {
        let n = std::os::windows::fs::FileExt::seek_read(file, buf, offset)?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        let rest = buf;
        buf = &mut rest[n..];
        offset += n as u64;
    }
    Ok(())
}

/// The unchecked spellings of the publish, for tests of the publish itself: each observes what
/// stands at the target as it is called and publishes through
/// [`persist_reconstructed_file_checked`]. Product code names the expectation it classified.
#[cfg(test)]
pub(crate) fn persist_reconstructed_file(
    tmp_path: &Path,
    out_path: &Path,
) -> Result<(), StorageError> {
    persist_reconstructed_file_in(tmp_path, out_path, &NoTempLedger)
}

#[cfg(test)]
pub(crate) fn persist_reconstructed_file_in(
    tmp_path: &Path,
    out_path: &Path,
    ledger: &dyn TempFileLedger,
) -> Result<(), StorageError> {
    persist_reconstructed_file_durable(tmp_path, out_path, ledger, Durability::Full, None)
}

#[cfg(test)]
pub(crate) fn persist_reconstructed_file_durable(
    tmp_path: &Path,
    out_path: &Path,
    ledger: &dyn TempFileLedger,
    durability: Durability,
    exec: Option<bool>,
) -> Result<(), StorageError> {
    let expected = TargetExpectation::observe(out_path)?;
    persist_reconstructed_file_checked(tmp_path, out_path, ledger, durability, exec, expected)
}

/// What stood at a write's target when the writer decided to replace it (or to write where
/// nothing stands).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "one short-lived value per write; Copy keeps it simple"
)]
pub enum TargetExpectation {
    /// Nothing: the publish must not replace anything that has appeared since.
    Absent,
    /// This object, unmodified: the publish replaces it only while the target is still exactly
    /// this object (same identity, size and modification time).
    Object(ObjectStamp),
}

/// One observation of an object, for telling later whether it is the same object, unmodified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectStamp {
    identity: yadorilink_fs_platform::fs_identity::FileIdentity,
    modified: Option<std::time::SystemTime>,
}

impl ObjectStamp {
    fn observe(path: &Path) -> std::io::Result<Self> {
        let identity = yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(path)?;
        let modified = fs::symlink_metadata(path)?.modified().ok();
        Ok(Self { identity, modified })
    }

    /// The same object with the same content: identity, size and modification time. The change
    /// time is left out on purpose: moving the object between names changes it, and the
    /// verification of an exchanged-out object must not refuse for that.
    fn unmodified_since(&self, earlier: &Self) -> bool {
        let (a, b) = (&self.identity, &earlier.identity);
        a.volume_identity == b.volume_identity
            && a.object_id == b.object_id
            && a.object_kind == b.object_kind
            && a.generation_or_usn == b.generation_or_usn
            && a.birth_or_creation_time == b.birth_or_creation_time
            && a.observed_size == b.observed_size
            && self.modified == earlier.modified
            && self.modified.is_some()
    }
}

impl TargetExpectation {
    /// Observes `path` now (never following a terminal symlink).
    pub fn observe(path: &Path) -> std::io::Result<Self> {
        match fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::Absent),
            Err(e) => Err(e),
            Ok(_) => ObjectStamp::observe(path).map(Self::Object),
        }
    }

    /// Whether the object at `path` now is what was expected there.
    fn holds_at(self, path: &Path) -> bool {
        match (self, Self::observe(path)) {
            (Self::Absent, Ok(Self::Absent)) => true,
            (Self::Object(expected), Ok(Self::Object(now))) => now.unmodified_since(&expected),
            _ => false,
        }
    }
}

/// [`persist_reconstructed_file_durable`] for a write that decided, earlier, what it may replace:
/// the target is checked against `expected` immediately before the rename, in the same step. A
/// target that is no longer what was decided on is left untouched (the temp stays for the caller
/// and [`StorageError::TargetChanged`] is returned): bytes a user saved meanwhile are never
/// replaced. `Absent` also publishes without replacing, so a name created between the check and
/// the rename is kept as well; a replaced `Object` is checked, then renamed over, with no
/// syscall between that the filesystem could interleave a save into other than the rename's own.
pub fn persist_reconstructed_file_checked(
    tmp_path: &Path,
    out_path: &Path,
    ledger: &dyn TempFileLedger,
    durability: Durability,
    exec: Option<bool>,
    expected: TargetExpectation,
) -> Result<(), StorageError> {
    let keep_temp =
        matches!(durability, Durability::DeferredToBatch | Durability::FileFlushedNamesDeferred);
    persist_reconstructed_file_inner(
        tmp_path, out_path, ledger, durability, exec, expected, keep_temp,
    )
}

/// [`persist_reconstructed_file_checked`] for a temp the caller did not make and may not have
/// another copy of (one a crashed write left, finished from after it was read back): whatever
/// fails, the temp stays where it is. Only a success moves it.
pub fn persist_borrowed_temp_checked(
    tmp_path: &Path,
    out_path: &Path,
    ledger: &dyn TempFileLedger,
    exec: Option<bool>,
    expected: TargetExpectation,
) -> Result<(), StorageError> {
    persist_reconstructed_file_inner(
        tmp_path,
        out_path,
        ledger,
        Durability::Full,
        exec,
        expected,
        true,
    )
}

fn persist_reconstructed_file_inner(
    tmp_path: &Path,
    out_path: &Path,
    ledger: &dyn TempFileLedger,
    durability: Durability,
    exec: Option<bool>,
    expected: TargetExpectation,
    keep_temp: bool,
) -> Result<(), StorageError> {
    #[cfg(not(unix))]
    let _ = exec;
    // With `keep_temp` a failed publish leaves the temp (and its ledger record) to the caller.
    // In the deferred modes the caller may have recorded the temp's flushed name as a witness
    // that the name was renamed, and a witness must be withdrawn BEFORE its temp is removed; a
    // borrowed temp may be the only copy of its bytes. A caller that cannot tell the difference
    // removes the temp itself.
    let discard = |tmp: &Path| {
        if !keep_temp {
            discard_temp_file(tmp, ledger);
        }
    };
    // What the person set on the file being replaced (ACL, own attributes, permission bits) moves to the
    // new file; if it cannot be read, nothing is replaced.
    #[cfg(unix)]
    if let Err(error) = crate::replace_keep::carry_over(out_path, tmp_path) {
        discard(tmp_path);
        return Err(error.into());
    }
    // The carry-over drops every execute bit (they come from the replicated flag), so the flag
    // is applied after it.
    #[cfg(unix)]
    if let Some(exec) = exec {
        if let Err(error) = apply_exec(tmp_path, exec) {
            discard(tmp_path);
            return Err(error);
        }
    }
    let namespace = match durable_namespace_beside(out_path) {
        Ok(namespace) => namespace,
        Err(error) => {
            discard(tmp_path);
            return Err(error.into());
        }
    };
    // The decision is re-checked after everything slow, inside the move, immediately before
    // the rename, and a changed target leaves the temp and the target as they are (the temp
    // may be the only copy of the bytes).
    publish_checked(tmp_path, out_path, ledger, durability, namespace, expected, keep_temp)
}

/// The publish of [`persist_reconstructed_file_checked`]: renames `tmp_path` to `out_path` only
/// while the target is still what `expected` says. `Absent` never replaces anything (an atomic
/// no-replace rename), so a name created at any moment is kept; a replaced `Object` is re-checked
/// inside the move, after the volume and directory handling, the instant before the rename. A
/// rename cannot compare what it replaces, so where the file system has an atomic exchange the
/// replaced object is not checked and then renamed over: the two names are exchanged, the
/// captured object is verified, and the exchange is undone if it is not the expected one (see
/// `DurableNamespace::replace_if_unchanged`), so no save is ever replaced. Only where there is no
/// exchange does the few-instruction window between check and rename remain. Every refusal
/// returns [`StorageError::TargetChanged`] with the temp untouched; any other failure discards the
/// temp as the unchecked publish does.
fn publish_checked(
    tmp_path: &Path,
    out_path: &Path,
    ledger: &dyn TempFileLedger,
    durability: Durability,
    namespace: Option<yadorilink_fs_platform::durable_dir::DurableNamespace>,
    expected: TargetExpectation,
    keep_temp: bool,
) -> Result<(), StorageError> {
    let changed = || StorageError::TargetChanged(out_path.to_path_buf());
    let deferred =
        matches!(durability, Durability::DeferredToBatch | Durability::FileFlushedNamesDeferred);
    let fail = |error: StorageError| {
        if !keep_temp {
            discard_temp_file(tmp_path, ledger);
        }
        error
    };
    if let Some(ns) = namespace {
        // Only a Unix volume defers the flush; elsewhere the move is the full one.
        let flush = !(cfg!(unix) && deferred);
        let moved = crate::io_diag::time(crate::io_diag::Op::Rename, 0, || match expected {
            TargetExpectation::Absent => {
                ns.move_if(tmp_path, out_path, Replace::No, flush, &|| expected.holds_at(out_path))
            }
            TargetExpectation::Object(_) => {
                ns.replace_if_unchanged(tmp_path, out_path, flush, &|captured| {
                    expected.holds_at(captured)
                })
            }
        });
        return match moved {
            Ok(()) => {
                if flush {
                    ledger.release(tmp_path);
                    note_directory_sync_inside_the_move(out_path);
                }
                Ok(())
            }
            Err(NsError::Refused | NsError::AlreadyExists) => Err(changed()),
            // A simulated crash leaves the temp and its record as they are.
            Err(error) if error.is_simulated_crash() => Err(StorageError::Io(error.into())),
            Err(error) => Err(fail(StorageError::Io(error.into()))),
        };
    }
    // No durable move on this volume: the plain rename. An absent target still never replaces
    // (where the platform has an atomic no-replace rename); a replaced object is checked just
    // before the rename.
    let moved = crate::io_diag::time(crate::io_diag::Op::Rename, 0, || match expected {
        TargetExpectation::Absent => match rename_no_replace(tmp_path, out_path) {
            // No atomic no-replace rename on this platform or volume: absence is checked just
            // before the rename (the window of the object case, without a durable move).
            Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
                if expected.holds_at(out_path) {
                    rename_path(tmp_path, out_path)
                } else {
                    Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
                }
            }
            other => other,
        },
        TargetExpectation::Object(_) => {
            match yadorilink_fs_platform::durable_dir::swap_in_if(
                tmp_path,
                out_path,
                &|captured| expected.holds_at(captured),
            )? {
                yadorilink_fs_platform::durable_dir::SwapIn::Replaced => Ok(()),
                yadorilink_fs_platform::durable_dir::SwapIn::Refused => {
                    Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
                }
                yadorilink_fs_platform::durable_dir::SwapIn::Unsupported => {
                    if expected.holds_at(out_path) {
                        rename_path(tmp_path, out_path)
                    } else {
                        Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
                    }
                }
            }
        }
    });
    match moved {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(changed()),
        Err(e) => return Err(fail(StorageError::Io(e))),
    }
    if let Err(e) = sync_parent_directory(out_path) {
        return Err(fail(e));
    }
    ledger.release(tmp_path);
    Ok(())
}

/// The directory sync of a durable move on Unix happens inside it and is timed
/// with the rename; the counters still say that one was issued.
fn note_directory_sync_inside_the_move(out_path: &Path) {
    #[cfg(unix)]
    if let Some(parent) = out_path.parent() {
        let parent = if parent.as_os_str().is_empty() { Path::new(".") } else { parent };
        crate::io_diag::note_dir_fsync(parent);
        crate::io_diag::time(crate::io_diag::Op::DirFsync, 0, || ());
    }
    #[cfg(not(unix))]
    let _ = out_path;
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), StorageError> {
    if let Some(parent) = path.parent() {
        // A bare file name has the current directory as its parent.
        let parent = if parent.as_os_str().is_empty() { Path::new(".") } else { parent };
        crate::io_diag::note_dir_fsync(parent);
        crate::io_diag::time(crate::io_diag::Op::DirFsync, 0, || {
            yadorilink_fs_platform::flush::sync_directory(&fs::File::open(parent)?)
        })?;
    }
    Ok(())
}

// Windows has no documented directory flush to rely on, and none is issued:
// what makes a Windows namespace change durable is the write-through move of
// `durable_dir`, used wherever the volume offers it. This is the plain-rename
// fallback's parent sync, and it is nothing there.
#[cfg(windows)]
fn sync_parent_directory(_path: &Path) -> Result<(), StorageError> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn sync_parent_directory(_path: &Path) -> Result<(), StorageError> {
    Ok(())
}

/// The `(dev, ino)`-shaped token a native provider's placeholder is recorded
/// under. On Windows the `dev` half is always `0` (an unused sentinel) and
/// `ino` carries the opaque CfAPI generation; see
/// [`WINDOWS_CFAPI_GENERATION_PROVIDER_KIND`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaceholderDiskIdentity {
    pub dev: u64,
    pub ino: u64,
}

/// The `provider_kind` string the Windows CfAPI generation-identity
/// scheme persists alongside a `PlaceholderDiskIdentity` -- reusing this
/// same two-`u64`-column shape even though the real value is a single
/// opaque `u64` generation token, not a `(dev, ino)` pair: `dev` is always
/// `0` (an unused sentinel) and `ino` carries the generation. See
/// `yadorilink-daemon`'s `placeholder_inspect_windows` module (the real
/// CfAPI-backed reader of this value) and `crates/yadorilink-shell-ext-windows/src/cfapi.rs`'s
/// `encode_generation_identity` (the writer, over on the CfAPI side of the
/// process boundary) for the wire format this token is stored in as a
/// placeholder's actual `FileIdentity` on disk -- unrelated to how it's
/// persisted here in the daemon's own index.
pub const WINDOWS_CFAPI_GENERATION_PROVIDER_KIND: &str = "windows-cfapi-generation";

impl PlaceholderDiskIdentity {
    /// Extracts the identity from an already-fetched [`fs::Metadata`].
    /// `None` on non-Unix builds.
    #[cfg(unix)]
    pub fn from_metadata(metadata: &fs::Metadata) -> Option<Self> {
        use std::os::unix::fs::MetadataExt;
        Some(Self { dev: metadata.dev(), ino: metadata.ino() })
    }

    #[cfg(not(unix))]
    pub fn from_metadata(_metadata: &fs::Metadata) -> Option<Self> {
        None
    }
}

/// What a provider-object creation call site must persist once
/// [`create_or_defer_placeholder`] returns, and HOW:
///
/// - `RecordIfAbsent`: Windows. Creation is deferred to a second process
///   (`cfapi-host.exe`) polling on its own schedule, so a concurrent
///   `ListFolderFilesRequest` backfill (`ensure_windows_placeholder_
///   generation`) can mint and persist its OWN generation for the same path
///   first and hand it to that process before this call's persist runs. An
///   unconditional overwrite would then silently orphan the generation
///   already in use on disk, so only-if-absent keeps whichever value won.
/// - `RecordOverwrite`: an object this call (or the caller's own
///   dehydration) positively identifies, persisted unconditionally.
/// - `Clear`: nothing is on disk for this path and nothing will be created
///   for it, so any recorded identity is withdrawn. This is the whole
///   outcome on a platform without a native provider: a `Remote` row has no
///   local object there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaceholderIdentityToRecord {
    RecordOverwrite { identity: PlaceholderDiskIdentity, provider_kind: &'static str },
    RecordIfAbsent { identity: PlaceholderDiskIdentity, provider_kind: &'static str },
    Clear,
}

impl PlaceholderIdentityToRecord {
    /// Whether the real provider object this outcome describes is deferred
    /// to a separate, out-of-process step (Windows's `cfapi-host.exe`, on
    /// its own ~30s poll) rather than already on disk right now.
    ///
    /// A caller must not clear a materialization intent that is protecting
    /// this exact path, or settle an outcome that completes this path's
    /// projection obligation, while this is `true`: doing so removes a
    /// protection for a path that genuinely has nothing under its own name
    /// yet, before `cfapi-host.exe` has had a chance to create it.
    pub fn is_deferred_to_a_separate_process(&self) -> bool {
        matches!(self, Self::RecordIfAbsent { .. })
    }

    /// Whether this outcome leaves a provider object on disk that the caller
    /// should now give the row's mode and attributes. Never true where no
    /// native provider exists.
    pub fn placed_an_object(&self) -> bool {
        matches!(self, Self::RecordOverwrite { .. })
    }
}

/// The one sanctioned entry point for making a path's `Remote` row
/// projectable by a native provider.
///
/// A `Remote` row has no local object in the user tree. Where a native
/// provider exists (Windows CfAPI) the object is created later by that
/// provider's own process, so this writes NOTHING to disk and mints a fresh
/// generation tagged [`WINDOWS_CFAPI_GENERATION_PROVIDER_KIND`] for the
/// caller to persist; `cfapi-host.exe`'s poll reads it back through
/// `ListFolderFilesRequest`. Nowhere else is a stand-in object written: on
/// a platform without a native provider this is [`PlaceholderIdentityToRecord::Clear`]
/// and the path stays empty.
pub fn create_or_defer_placeholder(out_path: &Path) -> PlaceholderIdentityToRecord {
    #[cfg(any(test, feature = "test-support"))]
    let deferred = test_force_deferred_placeholder_is_armed_for(out_path);
    #[cfg(not(any(test, feature = "test-support")))]
    let deferred = false;
    let _ = out_path;
    #[cfg(any(test, feature = "test-support"))]
    let native_provider_exists =
        cfg!(windows) && !TEST_NATIVE_PROVIDER_ABSENT.load(std::sync::atomic::Ordering::Relaxed);
    #[cfg(not(any(test, feature = "test-support")))]
    let native_provider_exists = cfg!(windows);
    if deferred || native_provider_exists {
        return PlaceholderIdentityToRecord::RecordIfAbsent {
            identity: PlaceholderDiskIdentity {
                dev: 0,
                ino: mint_windows_placeholder_generation(),
            },
            provider_kind: WINDOWS_CFAPI_GENERATION_PROVIDER_KIND,
        };
    }
    PlaceholderIdentityToRecord::Clear
}

/// Test-only: declares that this process runs without a native provider
/// (on Windows, no `cfapi-host.exe`), so [`create_or_defer_placeholder`]
/// answers [`PlaceholderIdentityToRecord::Clear`] as it does on any platform
/// without one. A pure-Rust harness has no host to create the deferred
/// object, and a `Remote` row whose placeholder never appears can neither be
/// hydrated (a recorded identity with nothing on disk means "removed
/// locally") nor receive its content. A per-path force
/// ([`set_test_force_deferred_placeholder_for_path`]) still wins.
#[cfg(any(test, feature = "test-support"))]
static TEST_NATIVE_PROVIDER_ABSENT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(any(test, feature = "test-support"))]
pub fn set_test_native_provider_absent(absent: bool) {
    TEST_NATIVE_PROVIDER_ABSENT.store(absent, std::sync::atomic::Ordering::Relaxed);
}

/// Test-only failure-injection flag, consumed by [`create_or_defer_placeholder`]
/// itself: when armed for a path, forces the Windows-deferred
/// (`RecordIfAbsent`) outcome regardless of the actual host platform, so a
/// test on any platform can drive every caller's deferred branch.
/// Path-keyed, deliberately NOT a process-wide flag: a single test binary
/// runs unrelated tests concurrently, and a blanket flag armed by one
/// scenario would hijack another's call.
#[cfg(any(test, feature = "test-support"))]
static TEST_FORCE_DEFERRED_PLACEHOLDER_PATHS: std::sync::Mutex<
    Option<std::collections::HashSet<std::path::PathBuf>>,
> = std::sync::Mutex::new(None);

#[cfg(any(test, feature = "test-support"))]
fn test_force_deferred_placeholder_is_armed_for(path: &Path) -> bool {
    TEST_FORCE_DEFERRED_PLACEHOLDER_PATHS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .is_some_and(|paths| paths.contains(path))
}

/// Test-only: arms (or disarms) the failure-injection flag above for one
/// exact path.
#[cfg(any(test, feature = "test-support"))]
pub fn set_test_force_deferred_placeholder_for_path(path: &Path, armed: bool) {
    let mut guard = TEST_FORCE_DEFERRED_PLACEHOLDER_PATHS.lock().unwrap_or_else(|p| p.into_inner());
    let paths = guard.get_or_insert_with(std::collections::HashSet::new);
    if armed {
        paths.insert(path.to_path_buf());
    } else {
        paths.remove(path);
    }
}

/// Renames `from` to `to` without ever replacing an existing `to`: it fails
/// with `AlreadyExists` instead. The rename is atomic and moves exactly the
/// object that has the name `from` at that instant, so a caller that detaches
/// an object to examine it cannot destroy a file already standing at `to`, and
/// cannot take a replacement of `from` for the object it meant. Uses
/// `RENAME_EXCL` (macOS), `RENAME_NOREPLACE` (Linux) or `MoveFileExW` without
/// the replace flag (Windows). Where no atomic no-replace move exists (another
/// platform, or a volume without the flag) it FAILS CLOSED with
/// `Unsupported`: there is deliberately no check-then-rename or link-then-
/// unlink fallback, since either can destroy an object it never looked at.
pub fn rename_no_replace(from: &Path, to: &Path) -> std::io::Result<()> {
    #[cfg(any(test, feature = "test-support"))]
    if TEST_NO_ATOMIC_RENAME.with(std::cell::Cell::get) {
        return Err(std::io::Error::from(std::io::ErrorKind::Unsupported));
    }
    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    {
        use std::os::unix::ffi::OsStrExt;
        let c_from = std::ffi::CString::new(from.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        let c_to = std::ffi::CString::new(to.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        loop {
            #[cfg(target_vendor = "apple")]
            // SAFETY: both pointers are valid NUL-terminated strings for the call.
            let rc = unsafe { libc::renamex_np(c_from.as_ptr(), c_to.as_ptr(), libc::RENAME_EXCL) };
            #[cfg(target_os = "linux")]
            // SAFETY: both pointers are valid NUL-terminated strings for the call.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    libc::AT_FDCWD,
                    c_from.as_ptr(),
                    libc::AT_FDCWD,
                    c_to.as_ptr(),
                    libc::RENAME_NOREPLACE,
                ) as libc::c_int
            };
            if rc == 0 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EINVAL | libc::ENOSYS | libc::ENOTSUP) => {
                    return Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
                }
                _ => return Err(error),
            }
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::MoveFileExW;
        let wide = |p: &Path| -> Vec<u16> { p.as_os_str().encode_wide().chain(Some(0)).collect() };
        let (f, t) = (
            wide(&yadorilink_fs_platform::long_path::for_win32(from)),
            wide(&yadorilink_fs_platform::long_path::for_win32(to)),
        );
        // SAFETY: both are NUL-terminated wide strings that outlive the call;
        // flags 0 means no replace of an existing destination.
        if unsafe { MoveFileExW(f.as_ptr(), t.as_ptr(), 0) } != 0 {
            return Ok(());
        }
        Err(std::io::Error::last_os_error())
    }
    #[cfg(not(any(target_vendor = "apple", target_os = "linux", windows)))]
    {
        let _ = (from, to);
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
}

// Test-only: makes `rename_no_replace` behave as on a volume without an atomic
// no-replace move, for this thread.
#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static TEST_NO_ATOMIC_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Arms (or disarms) the condition described on `TEST_NO_ATOMIC_RENAME`.
#[cfg(any(test, feature = "test-support"))]
pub fn set_test_no_atomic_rename(armed: bool) {
    TEST_NO_ATOMIC_RENAME.with(|c| c.set(armed));
}

/// Makes the directory entries of `path`'s parent durable.
pub fn sync_parent_dir(path: &Path) -> Result<(), StorageError> {
    sync_parent_directory(path)
}

/// Removes the regular file at `out_path` so that its row can be `Remote`:
/// eviction on a platform without a native provider leaves NO object in the
/// user tree. A file that is already gone is not an error. The removal is
/// made durable by syncing the parent directory; a failure of that sync is
/// logged, not returned, because the visible state has already changed and
/// the caller must advance its index state to match it.
pub fn remove_evicted_object(out_path: &Path) -> Result<(), StorageError> {
    match remove_path(out_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if let Err(error) = sync_parent_directory(out_path) {
        tracing::warn!(
            path = %out_path.display(),
            error = %error,
            "an evicted object was removed but its parent directory could not be synced"
        );
    }
    Ok(())
}

/// Mints a fresh Windows CfAPI placeholder generation: a process-lifetime
/// monotonic counter seeded from wall-clock time, so two placeholders
/// minted back-to-back (even at the same path, e.g. an evict immediately
/// followed by a re-create) never collide regardless of clock resolution.
/// The single shared mint site for every Windows generation-minting caller
/// in the daemon process -- both this module's [`create_or_defer_placeholder`]
/// and `yadorilink-daemon`'s `LinkFlushHandle::ensure_windows_placeholder_
/// generation` (the `ListFolderFilesRequest`-driven lazy backfill for
/// placeholders that predate this call, or that this call's own persist
/// raced with) call this same counter, since both run in the one daemon
/// process. Uniqueness only needs to hold per-path over time, not globally
/// across paths -- a live CfAPI generation comparison is always scoped to
/// one path -- so a shared counter across unrelated paths is harmless.
///
/// Deliberately NOT `#[cfg(windows)]`-gated: it's pure counter logic with no
/// platform API, and `yadorilink-daemon`'s caller invokes it unconditionally
/// (dead code on non-Windows, never compiled out).
pub fn mint_windows_placeholder_generation() -> u64 {
    static COUNTER: std::sync::OnceLock<AtomicU64> = std::sync::OnceLock::new();
    let counter = COUNTER.get_or_init(|| {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1);
        AtomicU64::new(seed)
    });
    counter.fetch_add(1, Ordering::Relaxed)
}

/// Every execute bit of a mode, whichever class holds it.
#[cfg(unix)]
const EXEC_BITS: u32 = 0o111;

/// Whether a file with this permission word is executable: its owner's `x` bit is set. (Group and
/// other `x` bits are not what the flag means; clearing the flag clears them with the owner's.)
#[cfg(unix)]
pub fn exec_from_mode(mode: u32) -> bool {
    mode & 0o100 != 0
}

/// The mode of `current` once the execute flag is `exec`. Execute set: the owner always gets `x` (so the
/// result is representable even on a `0200` or `0000` file), group and other get it where that class has `r`.
/// Execute cleared: every `x` goes. No other bit changes, except that a content change drops
/// setuid/setgid (`clear_special`), as a write to the file would.
#[cfg(unix)]
pub fn mode_with_exec(current: u32, exec: bool, clear_special: bool) -> u32 {
    let mut mode = current;
    if exec {
        mode |= 0o100;
        if mode & 0o040 != 0 {
            mode |= 0o010;
        }
        if mode & 0o004 != 0 {
            mode |= 0o001;
        }
    } else {
        mode &= !EXEC_BITS;
    }
    if clear_special {
        mode &= !0o6000;
    }
    mode
}

/// Whether [`apply_exec`] would need to perform a real `set_permissions` syscall for `path` given the
/// desired execute flag -- a pure, read-only comparison against what disk currently holds, with no side
/// effects. `true` means calling `apply_exec` right now would be a genuine no-op. Exists so a caller that
/// must bump a physical-mutation fence before its first real mutating syscall (never after) can decide
/// whether it needs to bump at all. It shares [`mode_with_exec`] with `apply_exec`, so the two cannot
/// disagree about what "right" means.
#[cfg(unix)]
pub fn exec_already_matches_disk(path: &Path, exec: bool) -> Result<bool, StorageError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)?.permissions().mode();
    Ok(exec_from_mode(mode) == exec)
}

/// Execute is not applied off Unix, so there is never a mutation to fence.
#[cfg(not(unix))]
pub fn exec_already_matches_disk(_path: &Path, _exec: bool) -> Result<bool, StorageError> {
    Ok(true)
}

/// Gives a regular file the execute state `exec` (see [`mode_with_exec`]) and leaves every other
/// permission bit as it is. A no-op when the file already is right (no syscall, so no ctime movement), and
/// on any non-Unix platform.
#[cfg(unix)]
pub fn apply_exec(path: &Path, exec: bool) -> Result<(), StorageError> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::metadata(path)?;
    let mode = metadata.permissions().mode();
    if exec_from_mode(mode) == exec {
        return Ok(());
    }
    let mut perms = metadata.permissions();
    perms.set_mode(mode_with_exec(mode, exec, false));
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
pub fn apply_exec(_path: &Path, _exec: bool) -> Result<(), StorageError> {
    Ok(())
}

/// Applies a materialized regular file's replicated metadata: the execute flag, the only part of the
/// permission model that is replicated.
pub fn apply_file_metadata(path: &Path, exec: bool) -> Result<(), StorageError> {
    apply_exec(path, exec)
}

/// Materializes a symlink record at `out_path`, pointing at `target` (the
/// record's raw, unresolved target bytes — never lossily converted, and a
/// symlink target is never dereferenced by this crate; see `fs_identity::
/// bytes_to_target`, this function's inverse) using the same atomic
/// temp-path-then-rename pattern `reconstruct_file`/`write_placeholder`
/// already use: a fresh random temp name
/// is picked, `std::os::unix::fs::symlink` creates the link there,
/// and `fs::rename` atomically swaps it into place — a torn/partial
/// symlink is never observable at `out_path`, matching the guarantee
/// regular-file materialization already gives.
#[cfg(unix)]
pub fn materialize_symlink(out_path: &Path, target: &[u8]) -> Result<(), StorageError> {
    let expected = TargetExpectation::observe(out_path)?;
    materialize_symlink_in(out_path, target, &NoTempLedger, expected)
}

/// [`materialize_symlink`] with its temp link recorded in `ledger`, replacing only what
/// `expected` says stands at `out_path` (see [`persist_reconstructed_file_checked`]): a changed
/// target is [`StorageError::TargetChanged`], with the target untouched and the temp link removed.
#[cfg(unix)]
pub fn materialize_symlink_in(
    out_path: &Path,
    target: &[u8],
    ledger: &dyn TempFileLedger,
    expected: TargetExpectation,
) -> Result<(), StorageError> {
    require_parent_directory(out_path)?;
    let link_target = yadorilink_fs_platform::fs_identity::bytes_to_target(target);
    let (tmp_path, ()) = create_recorded_tmp(out_path, ledger, random_tmp_path, |tmp| {
        std::os::unix::fs::symlink(&link_target, tmp)
    })?;
    let namespace = match durable_namespace_beside(out_path) {
        Ok(namespace) => namespace,
        Err(error) => {
            discard_temp_file(&tmp_path, ledger);
            return Err(error.into());
        }
    };
    let published =
        publish_checked(&tmp_path, out_path, ledger, Durability::Full, namespace, expected, false);
    if matches!(published, Err(StorageError::TargetChanged(_))) {
        discard_temp_file(&tmp_path, ledger);
    }
    published
}

/// Windows per-link opt-in symlink materialization: the default Windows
/// policy is skip-with-visible-status (the record is tracked and synced,
/// but nothing is written to disk), and this function is only ever reached
/// once a link has explicitly opted in. It attempts a real
/// `CreateSymbolicLinkW` via `std::os::windows::fs`, using the same atomic
/// temp-path-then-rename pattern as `materialize_symlink`. Creating a
/// Windows symlink requires `SeCreateSymbolicLinkPrivilege` or Developer
/// Mode; when that precondition isn't met the OS call fails, which is
/// surfaced here as a clear, actionable `StorageError::Io` — never a
/// silent no-op or a panic — since an opted-in link that can't actually
/// materialize symlinks on this machine should be loud about it, unlike
/// the default (non-opt-in) skip policy, which is silent by design.
///
/// Windows symlinks are typed (file vs. directory) at creation time; since
/// a target is never dereferenced for *classification* purposes elsewhere
/// in this crate, this does a best-effort *local* check instead: if
/// `target`, resolved relative to `out_path`'s parent, currently exists
/// locally as a directory, a directory symlink is created; otherwise
/// (doesn't exist yet, resolves elsewhere, or any I/O error reading it)
/// this defaults to a file symlink, the more common case.
///
/// Not exercised by this crate's own test suite (no Windows CI/dev machine
/// available at the time this was written) — reviewed carefully against
/// the documented `std::os::windows::fs` API shape, but treat as
/// unverified until run on real Windows.
#[cfg(windows)]
pub fn materialize_symlink_windows(out_path: &Path, target: &[u8]) -> Result<(), StorageError> {
    let expected = TargetExpectation::observe(out_path)?;
    materialize_symlink_windows_in(out_path, target, &NoTempLedger, expected)
}

/// [`materialize_symlink_windows`] with its temp link recorded in `ledger`.
#[cfg(windows)]
pub fn materialize_symlink_windows_in(
    out_path: &Path,
    target: &[u8],
    ledger: &dyn TempFileLedger,
    expected: TargetExpectation,
) -> Result<(), StorageError> {
    // `target` is `target_to_bytes`'s own little-endian UTF-16 output (see
    // `fs_identity::bytes_to_target`'s doc) for any target this crate itself
    // ever captured; a malformed byte string has nothing well-formed to
    // materialize.
    let Some(target) = yadorilink_fs_platform::fs_identity::bytes_to_target(target) else {
        return Err(StorageError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "symlink target for {out_path:?} is not a valid UTF-16LE byte string; cannot \
                 materialize"
            ),
        )));
    };
    require_parent_directory(out_path)?;
    let target_hint = out_path.parent().unwrap_or(out_path).join(&target);
    let is_dir = fs::metadata(&target_hint).map(|m| m.is_dir()).unwrap_or(false);
    let created = create_recorded_tmp(out_path, ledger, random_tmp_path, |tmp| {
        if is_dir {
            std::os::windows::fs::symlink_dir(&target, tmp)
        } else {
            std::os::windows::fs::symlink_file(&target, tmp)
        }
    });
    let tmp_path = match created {
        Ok((tmp_path, ())) => tmp_path,
        Err(StorageError::Io(e)) => {
            return Err(StorageError::from(std::io::Error::new(
                e.kind(),
                format!(
                    "failed to create Windows symlink at {out_path:?} (target {target:?}): {e}. \
                     Creating symlinks on Windows requires SeCreateSymbolicLinkPrivilege \
                     or Developer Mode to be enabled for the running user."
                ),
            )));
        }
        Err(e) => return Err(e),
    };
    let namespace = match durable_namespace_beside(out_path) {
        Ok(namespace) => namespace,
        Err(error) => {
            discard_temp_file(&tmp_path, ledger);
            return Err(error.into());
        }
    };
    let published =
        publish_checked(&tmp_path, out_path, ledger, Durability::Full, namespace, expected, false);
    if matches!(published, Err(StorageError::TargetChanged(_))) {
        discard_temp_file(&tmp_path, ledger);
    }
    published
}

#[cfg(test)]
mod tests;

#[cfg(all(test, unix))]
mod read_traversal_tests {
    use super::*;

    fn root_with_link() -> (tempfile::TempDir, tempfile::TempDir) {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("victim.txt"), b"outside").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("link")).unwrap();
        (root, outside)
    }

    #[test]
    fn a_path_through_a_symlinked_component_is_refused() {
        let (root, _outside) = root_with_link();
        assert!(matches!(
            resolve_read_path_without_traversal(root.path(), Path::new("link/victim.txt")),
            Err(StorageError::PathEscapesRoot(_))
        ));
    }

    /// The symlink itself is an ordinary member of the folder — it is
    /// synchronised, as a symlink. Only walking *through* it is refused.
    #[test]
    fn the_symlink_itself_resolves() {
        let (root, _outside) = root_with_link();
        assert_eq!(
            resolve_read_path_without_traversal(root.path(), Path::new("link")).unwrap(),
            root.path().join("link")
        );
    }

    /// A link pointing back inside the root is refused too. Following it
    /// would give one object two logical paths, and a path is a semantic
    /// identity here.
    #[test]
    fn a_link_whose_target_is_inside_the_root_is_refused_as_well() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("real")).unwrap();
        std::fs::write(root.path().join("real/file.txt"), b"x").unwrap();
        std::os::unix::fs::symlink(root.path().join("real"), root.path().join("alias")).unwrap();
        assert!(
            resolve_read_path_without_traversal(root.path(), Path::new("real/file.txt")).is_ok()
        );
        assert!(matches!(
            resolve_read_path_without_traversal(root.path(), Path::new("alias/file.txt")),
            Err(StorageError::PathEscapesRoot(_))
        ));
    }

    #[test]
    fn an_ordinary_nested_path_resolves() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("a/b")).unwrap();
        std::fs::write(root.path().join("a/b/c.txt"), b"x").unwrap();
        assert_eq!(
            resolve_read_path_without_traversal(root.path(), Path::new("a/b/c.txt")).unwrap(),
            root.path().join("a/b/c.txt")
        );
    }

    /// A delete must not reach through a symlinked component either.
    ///
    /// This is the twin of the write-side check, and it was already correct —
    /// it canonicalises the target's parent and refuses when that lands
    /// outside the root. It had no test. Stated here rather than as a
    /// two-device scenario because that scenario cannot isolate it: the two
    /// devices legitimately disagree about whether the component is a
    /// directory or a symlink, and the delete stalls on that rather than on
    /// the defence.
    #[test]
    fn a_delete_through_a_symlinked_component_is_refused() {
        let (root, outside) = root_with_link();
        let victim = outside.path().join("victim.txt");
        assert!(matches!(
            verify_delete_target_within_root(&root.path().join("link/victim.txt"), root.path()),
            Err(StorageError::PathEscapesRoot(_))
        ));
        assert!(victim.exists(), "the check itself must not touch the target");
    }

    /// And a delete inside the root is still allowed, so the rule above
    /// cannot have been implemented as "refuse every delete".
    #[test]
    fn an_ordinary_delete_inside_the_root_is_allowed() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("a")).unwrap();
        std::fs::write(root.path().join("a/file.txt"), b"x").unwrap();
        assert!(
            verify_delete_target_within_root(&root.path().join("a/file.txt"), root.path()).is_ok()
        );
    }

    /// A path whose components do not exist yet is not a traversal; whether
    /// it is there is the caller's question.
    #[test]
    fn a_missing_path_is_not_a_traversal() {
        let root = tempfile::tempdir().unwrap();
        assert!(
            resolve_read_path_without_traversal(root.path(), Path::new("nope/none.txt")).is_ok()
        );
    }
}
