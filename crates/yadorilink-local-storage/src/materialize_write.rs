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
use yadorilink_fs_platform::durable_dir::Replace;
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
fn random_tmp_path(path: &Path) -> PathBuf {
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
    for _ in 0..MAX_TMP_NAME_ATTEMPTS {
        let tmp_path = next_name(out_path);
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
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
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
    let tmp_path = reconstruct_file_to_temp_in(store, out_path, blocks, mtime_unix_nanos, ledger)?;
    persist_reconstructed_file_in(&tmp_path, out_path, ledger)
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
        if durability == Durability::Full {
            crate::io_diag::time(crate::io_diag::Op::FileFsync, 0, || out.sync_all())?;
        }
        tracing::debug!("phase T_recv_fsync_done: final-file fsync complete");
        Ok(())
        // `out` is dropped (closed) here, before the rename below.
    };
    assemble()?;
    cleanup.1 = true;
    Ok(tmp_path)
}

/// The "publish" half of [`reconstruct_file`]: atomically renames an
/// already-assembled temp file (from [`reconstruct_file_to_temp`]) into
/// place at `out_path`, then syncs the parent directory. Fast (one rename,
/// one directory fsync) and does no network/block-store I/O -- the
/// intended boundary for a caller that wants to hold a path's lock across
/// only this short step, not the slower assemble step above.
///
/// On any failure, removes `tmp_path` so an interrupted publish leaves the
/// directory as it found it. `tmp_path` must not be reused after this
/// returns, whether it succeeds or fails.
pub fn persist_reconstructed_file(tmp_path: &Path, out_path: &Path) -> Result<(), StorageError> {
    persist_reconstructed_file_in(tmp_path, out_path, &NoTempLedger)
}

/// [`persist_reconstructed_file`] for a temp file recorded in `ledger`: the
/// record is released once the temp file is renamed away or removed.
pub fn persist_reconstructed_file_in(
    tmp_path: &Path,
    out_path: &Path,
    ledger: &dyn TempFileLedger,
) -> Result<(), StorageError> {
    persist_reconstructed_file_durable(tmp_path, out_path, ledger, Durability::Full)
}

/// [`persist_reconstructed_file_in`] with the directory flush chosen.
/// `DeferredToBatch` renames and returns: no parent flush, and the temp name's
/// ledger record is kept (the caller releases it after
/// [`flush_received_files`]). Only a Unix volume with durable moves defers; any
/// other publish is the full one, and the record is then already released --
/// releasing it again is harmless.
pub fn persist_reconstructed_file_durable(
    tmp_path: &Path,
    out_path: &Path,
    ledger: &dyn TempFileLedger,
    durability: Durability,
) -> Result<(), StorageError> {
    let namespace = match durable_namespace_beside(out_path) {
        Ok(namespace) => namespace,
        Err(error) => {
            discard_temp_file(tmp_path, ledger);
            return Err(error.into());
        }
    };
    #[cfg(unix)]
    if let (Some(ns), Durability::DeferredToBatch) = (&namespace, durability) {
        let published = crate::io_diag::time(crate::io_diag::Op::Rename, 0, || {
            ns.publish_without_flush(tmp_path, out_path, Replace::Yes, &LedgerNames(ledger))
        });
        return published.map_err(|error| StorageError::Io(error.into()));
    }
    if let Some(ns) = namespace {
        // The temp file is flushed; a durable move publishes it and removes the
        // temp name, and the record is released once that name is gone.
        let published = crate::io_diag::time(crate::io_diag::Op::Rename, 0, || {
            ns.publish(tmp_path, out_path, Replace::Yes, &LedgerNames(ledger))
        });
        note_directory_sync_inside_the_move(out_path);
        return published.map_err(|error| StorageError::Io(error.into()));
    }
    let publish = || -> Result<(), StorageError> {
        crate::io_diag::time(crate::io_diag::Op::Rename, 0, || rename_path(tmp_path, out_path))?;
        tracing::debug!("phase T_recv_rename_done: temp-file-to-final-path rename complete");
        sync_parent_directory(out_path)?;
        // On Unix this is a real parent-directory fsync (see `sync_parent_
        // directory`'s own doc comment); on non-Unix it is a documented
        // no-op, so this line still fires there but measures nothing real
        // -- a phase-log reader on a non-Unix capture should read this
        // span as "step skipped," not "step free."
        tracing::debug!(
            "phase T_recv_dir_fsync_done: parent-directory fsync complete (or skipped, non-Unix)"
        );
        Ok(())
    };
    if let Err(e) = publish() {
        discard_temp_file(tmp_path, ledger);
        return Err(e);
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
            fs::File::open(parent)?.sync_all()
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

/// Whether [`apply_unix_mode`] would need to perform a real
/// `set_permissions` syscall for `path` given the desired `unix_mode` -- a
/// pure, read-only comparison against what disk currently holds, with no
/// side effects. `true` means calling `apply_unix_mode` right now would be
/// a genuine no-op; `false` means it would actually change something.
/// Exists so a caller that must bump a physical-mutation fence before its
/// first real mutating syscall (never after) can decide whether it needs
/// to bump at all, before committing to either `apply_unix_mode` or a
/// fence bump.
#[cfg(unix)]
pub fn unix_mode_already_matches_disk(
    path: &Path,
    unix_mode: Option<u32>,
) -> Result<bool, StorageError> {
    use std::os::unix::fs::PermissionsExt;
    const PERMISSION_BITS: u32 = 0o777;
    let Some(unix_mode) = unix_mode else {
        return Ok(true);
    };
    let metadata = fs::metadata(path)?;
    let mode = metadata.permissions().mode();
    Ok((mode & PERMISSION_BITS) == (unix_mode & PERMISSION_BITS))
}

/// See the `#[cfg(unix)]` `unix_mode_already_matches_disk` above --
/// `apply_unix_mode` is already a no-op off Unix, so it never needs a
/// fence bump either.
///
/// Target projection contract (see `SettlementEvidence::ExactObject`'s
/// own doc comment for the full model): `unix_mode` is retained-only on
/// a non-Unix target, not exact-required. This function's own `Ok(true)`
/// is that retained-only status expressed as "no mutation needed," which
/// is also, deliberately, exactly what an exact-required field reports
/// once it genuinely already matches -- a caller cannot tell "nothing to
/// verify here" from "verified and it matches" from this return value
/// alone, and does not need to: either way, this field never blocks
/// `ExactObject` completion on this platform.
#[cfg(not(unix))]
pub fn unix_mode_already_matches_disk(
    _path: &Path,
    _unix_mode: Option<u32>,
) -> Result<bool, StorageError> {
    Ok(true)
}

/// Whether [`apply_xattrs`] would need to perform any real
/// `fsetxattr`/`fremovexattr` syscall for `path` given the desired
/// `xattrs` -- the xattr counterpart of `unix_mode_already_matches_disk`,
/// for the same reason. Reuses `chunker::read_replicated_xattrs`, the same
/// read side `apply_xattrs` itself is the write-side counterpart to, so
/// the two can never disagree about which names/values are "replicated"
/// ones.
#[cfg(target_os = "linux")]
pub fn xattrs_already_match_disk(
    path: &Path,
    xattrs: &[(String, Vec<u8>)],
) -> Result<bool, StorageError> {
    // A file whose mode denies its owner read access cannot be compared.
    // "Not known to match" sends the caller down its mutating path, which is
    // always safe here; failing hard would stop every later step for a
    // file that is merely unreadable.
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let mut current = crate::chunker::read_replicated_xattrs(&file);
    let mut desired = xattrs.to_vec();
    current.sort();
    desired.sort();
    Ok(current == desired)
}

/// See the `#[cfg(target_os = "linux")]` `xattrs_already_match_disk` above
/// -- `apply_xattrs` is already a no-op off Linux, so it never needs a
/// fence bump either.
#[cfg(not(target_os = "linux"))]
pub fn xattrs_already_match_disk(
    _path: &Path,
    _xattrs: &[(String, Vec<u8>)],
) -> Result<bool, StorageError> {
    Ok(true)
}

/// The `ExactObject` proof gate: whether `path`'s on-disk replicated
/// extended attributes exactly equal `desired`, verified strictly. This
/// is NOT `xattrs_already_match_disk` -- that function exists only to
/// choose snapshot-vs-bump before any mutation and reuses
/// `read_replicated_xattrs`'s best-effort reader, which silently folds a
/// real enumeration/read failure into "no attributes" (fine for deciding
/// whether a mutating syscall is needed, since falling through to
/// actually attempt the syscalls is always safe). An `ExactObject`
/// completion proof has no such fallback available: publishing it means
/// claiming disk demonstrably holds this exact desired version, and
/// `FileVersion`'s content-addressed identity bakes replicated xattr
/// bytes directly into `version_hash` (see `FileVersion::compute_hash`)
/// -- so a caller that cannot actually confirm the attributes match must
/// never be allowed to read that failure as a match.
///
/// Returns `Ok(true)`/`Ok(false)` for a confirmed match/mismatch, and
/// `Err` when this backend cannot even attempt the comparison -- a real
/// I/O failure enumerating or reading an attribute (this Linux arm
/// only; the non-Linux arm below has no replicated-xattr backend to
/// fail reading from in the first place, and always settles as
/// retained-only -- see its own doc comment). Every caller gating
/// `SettlementEvidence::ExactObject` on this Linux arm's `Err` must
/// treat it exactly like `Ok(false)`: leave the obligation outstanding
/// for retry, never propagate it as a hard failure of the write itself
/// (the content and any other metadata this call's caller already
/// applied are still genuinely on disk).
///
/// `path` is opened with ordinary, symlink-following semantics -- correct
/// (and required, to still catch a genuine stale attribute) for a
/// `RecordKind::File` whose `desired` may legitimately be empty, but
/// wrong for a symlink or directory path, which `FileMeta::xattrs`'s own
/// doc says is never scanned at all (always an empty `desired`) and
/// which may not even have a followable target (a dangling symlink is
/// perfectly valid). Callers must only invoke this for `RecordKind::
/// File`; skip it entirely for every other kind rather than passing an
/// empty `desired` and relying on this function to no-op.
#[cfg(target_os = "linux")]
pub fn verify_replicated_xattrs_exact(
    path: &Path,
    desired: &[(String, Vec<u8>)],
) -> Result<bool, StorageError> {
    let file = fs::File::open(path)?;
    replicated_xattrs_exactly_match(&file, desired)
}

/// The comparison `verify_replicated_xattrs_exact` makes once it holds
/// the file open, split out so a test can hand it a descriptor whose
/// attribute listing succeeds but whose attribute read is refused -- a
/// state the path-based entry point cannot reach, since it opens the
/// file read-only and a file its caller cannot read never gets that far.
#[cfg(target_os = "linux")]
fn replicated_xattrs_exactly_match(
    file: &fs::File,
    desired: &[(String, Vec<u8>)],
) -> Result<bool, StorageError> {
    let mut current = crate::chunker::read_replicated_xattrs_strict(file)?;
    let mut desired = desired.to_vec();
    current.sort();
    desired.sort();
    Ok(current == desired)
}

/// Off Linux, replicated-xattr support does not exist at all (see
/// `apply_xattrs`'s own non-Linux stub, which never writes anything).
///
/// Design decision (target projection contract, see `SettlementEvidence::
/// ExactObject`'s own doc comment for the full model): a version's
/// `xattrs` stay part of its authoritative logical identity
/// (`VersionHash`) everywhere, but whether they are a REQUIRED-exact
/// projection field or a RETAINED-only one (present in the logical
/// version, but this target is never asked to physically reproduce it)
/// is target-specific. On a backend with no replicated-xattr support at
/// all, xattrs are always retained-only -- exactly the same "this
/// target cannot represent it, so completion does not wait on it"
/// treatment `unix_mode_already_matches_disk`'s own non-Unix arm already
/// gives `unix_mode`. An earlier version of this function treated a
/// nonempty desired set as permanently unrepresentable and refused to
/// ever settle -- correct under the OLD "ExactObject means literal
/// field-for-field equality" model, but wrong under this one: it left a
/// path with any replicated attribute permanently un-completable on any
/// non-Linux target, for a field this target was never expected to
/// physically reproduce in the first place.
#[cfg(not(target_os = "linux"))]
pub fn verify_replicated_xattrs_exact(
    _path: &Path,
    _desired: &[(String, Vec<u8>)],
) -> Result<bool, StorageError> {
    Ok(true)
}

/// Sets the replicated permission bits (`REPLICATED_MODE_MASK`,
/// owner/group/other read-write-execute) on an already-materialized file.
/// `None` -- the authoring version carries no Unix permission info, i.e. it
/// was authored on a platform with no Unix mode model -- is a deliberate
/// no-op: this device does not fabricate a mode for a peer that never had
/// one, it leaves whatever mode the write already produced (the process's
/// own umask-derived default). Only the low 9 permission bits are ever
/// touched; any higher bits (file type, setuid/setgid/sticky) already on
/// disk are preserved untouched. A no-op on any non-Unix platform (Windows
/// has no equivalent permission-bits model, so this must be silent there,
/// not an error).
/// Applies a materialized regular file's replicated metadata: extended
/// attributes first, permission bits second. The order is the contract.
/// Setting or listing attributes needs access the target mode may not
/// grant (`apply_xattrs` opens the file for reading, and a `user.*`
/// attribute can only be written by someone who may write the file), so a
/// replicated mode such as `0o200` or `0o444` applied first would make the
/// attribute step fail with a permission error. The freshly written file
/// still carries the mode it was created with until the last step here.
pub fn apply_file_metadata(
    path: &Path,
    unix_mode: Option<u32>,
    xattrs: &[(String, Vec<u8>)],
) -> Result<(), StorageError> {
    apply_xattrs(path, xattrs)?;
    apply_unix_mode(path, unix_mode)
}

/// Evidence from one write attempt that a path's replicated extended
/// attributes were set and then strictly re-read as exactly the desired set
/// ([`verify_replicated_xattrs_exact`]) BEFORE that attempt applied the
/// final mode. Only [`apply_file_metadata_verified`] constructs it.
///
/// It exists for the case a later re-read cannot cover: a replicated mode
/// that revokes the owner's read permission (`0o200`) makes the attributes
/// unreadable once the mode lands, although changing the mode does not
/// change them. A caller that just wrote the file may use this in place of
/// a re-read. A caller proving disk state it did not just write must still
/// re-read with [`verify_replicated_xattrs_exact`], and an unreadable file
/// is then correctly "not provable".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XattrsConfirmedInAttempt {
    path: PathBuf,
    xattrs: Vec<(String, Vec<u8>)>,
}

impl XattrsConfirmedInAttempt {
    fn new(path: &Path, xattrs: &[(String, Vec<u8>)]) -> Self {
        let mut xattrs = xattrs.to_vec();
        xattrs.sort();
        Self { path: path.to_path_buf(), xattrs }
    }

    /// Whether this confirmation is about `path` holding exactly `xattrs`.
    /// A caller must check this before relying on it, so a confirmation
    /// can never be spent on a different path or a different version.
    pub fn covers(&self, path: &Path, xattrs: &[(String, Vec<u8>)]) -> bool {
        let mut desired = xattrs.to_vec();
        desired.sort();
        self.path == path && self.xattrs == desired
    }
}

/// Why [`apply_file_metadata_verified`] could not confirm the attributes.
#[derive(Debug)]
pub enum XattrsNotConfirmed {
    /// Read back, and not the desired set.
    Mismatch,
    /// Could not be set or read back, e.g. a file whose current mode already
    /// denies the owner read access.
    Unreadable(StorageError),
}

/// What [`apply_file_metadata_verified`] established about one attempt.
#[derive(Debug)]
#[must_use = "the attribute confirmation is the ExactObject evidence; dropping it loses the proof"]
pub struct AppliedFileMetadata {
    xattrs: Result<XattrsConfirmedInAttempt, XattrsNotConfirmed>,
}

impl AppliedFileMetadata {
    pub fn into_xattrs(self) -> Result<XattrsConfirmedInAttempt, XattrsNotConfirmed> {
        self.xattrs
    }
}

/// Where the replicated-xattr half of an exact-object proof comes from, for
/// every writer that publishes one (local convergence, access hydration,
/// materialization repair), so they all accept exactly the same evidence.
///
/// A path this attempt just wrote carries the attempt's own strict check,
/// taken before the final mode was applied ([`apply_file_metadata_verified`]).
/// A path whose disk state this attempt did not write is re-proved from disk,
/// and on Linux an unreadable file then cannot be proved -- which is the
/// correct answer, not something to accept as exact.
#[derive(Debug)]
pub enum XattrEvidence {
    /// This attempt set the attributes and strictly re-read them.
    ConfirmedInAttempt(XattrsConfirmedInAttempt),
    /// This attempt set the attributes but could not confirm them.
    NotConfirmedInAttempt(XattrsNotConfirmed),
    /// Nothing was written in this attempt; prove what disk holds now.
    ReproveFromDisk,
}

impl From<AppliedFileMetadata> for XattrEvidence {
    fn from(applied: AppliedFileMetadata) -> Self {
        match applied.into_xattrs() {
            Ok(confirmed) => Self::ConfirmedInAttempt(confirmed),
            Err(reason) => Self::NotConfirmedInAttempt(reason),
        }
    }
}

/// Why [`XattrEvidence::prove`] refused to back an exact claim.
#[derive(Debug)]
pub enum XattrProofRefused {
    /// An in-attempt confirmation for a different path or attribute set.
    ConfirmationDoesNotCover,
    /// This attempt set the attributes but could not confirm them.
    NotConfirmedInAttempt,
    /// Re-read from disk, and not the desired set.
    DiskMismatch,
    /// Re-read from disk failed (e.g. an owner-unreadable file).
    DiskUnreadable(StorageError),
}

impl XattrEvidence {
    /// Whether this evidence proves `out_path` holds exactly `desired`. An
    /// in-attempt confirmation counts only for the path and set it was taken
    /// for; `ReproveFromDisk` re-reads strictly and never treats a failed
    /// read as a match.
    pub fn prove(
        &self,
        out_path: &Path,
        desired: &[(String, Vec<u8>)],
    ) -> Result<(), XattrProofRefused> {
        match self {
            Self::ConfirmedInAttempt(confirmed) if confirmed.covers(out_path, desired) => Ok(()),
            Self::ConfirmedInAttempt(_) => Err(XattrProofRefused::ConfirmationDoesNotCover),
            Self::NotConfirmedInAttempt(_) => Err(XattrProofRefused::NotConfirmedInAttempt),
            Self::ReproveFromDisk => match verify_replicated_xattrs_exact(out_path, desired) {
                Ok(true) => Ok(()),
                Ok(false) => Err(XattrProofRefused::DiskMismatch),
                Err(error) => Err(XattrProofRefused::DiskUnreadable(error)),
            },
        }
    }
}

/// [`apply_file_metadata`] for a caller that will claim the result as an
/// exact object: sets the attributes, strictly re-reads them while the file
/// still has the mode it was written with, applies the final mode, and
/// returns what the re-read established. Order:
///
/// 1. apply the replicated extended attributes
/// 2. strictly verify them
/// 3. apply the final permission bits
///
/// A permission error setting the attributes (a file already carrying an
/// owner-unreadable mode) is reported as [`XattrsNotConfirmed::Unreadable`],
/// not as a hard error, so the caller leaves the path unproven instead of
/// failing everything around it. Any other error is returned as is.
pub fn apply_file_metadata_verified(
    path: &Path,
    unix_mode: Option<u32>,
    xattrs: &[(String, Vec<u8>)],
) -> Result<AppliedFileMetadata, StorageError> {
    let confirmation = match apply_xattrs(path, xattrs) {
        Ok(()) => match verify_replicated_xattrs_exact(path, xattrs) {
            Ok(true) => Ok(XattrsConfirmedInAttempt::new(path, xattrs)),
            Ok(false) => Err(XattrsNotConfirmed::Mismatch),
            Err(error) => Err(XattrsNotConfirmed::Unreadable(error)),
        },
        Err(StorageError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(XattrsNotConfirmed::Unreadable(StorageError::Io(error)))
        }
        Err(error) => return Err(error),
    };
    apply_unix_mode(path, unix_mode)?;
    Ok(AppliedFileMetadata { xattrs: confirmation })
}

#[cfg(unix)]
pub fn apply_unix_mode(path: &Path, unix_mode: Option<u32>) -> Result<(), StorageError> {
    use std::os::unix::fs::PermissionsExt;
    const PERMISSION_BITS: u32 = 0o777;
    let Some(unix_mode) = unix_mode else {
        return Ok(());
    };
    let metadata = fs::metadata(path)?;
    let mut perms = metadata.permissions();
    let mode = perms.mode();
    let new_mode = (mode & !PERMISSION_BITS) | (unix_mode & PERMISSION_BITS);
    if new_mode != mode {
        perms.set_mode(new_mode);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

/// See the `#[cfg(unix)]` `apply_unix_mode` above — the no-op
/// Windows/other-platform counterpart needed for cross-platform parity.
/// `unix_mode` is retained-only, not exact-required, on a non-Unix
/// target -- see `unix_mode_already_matches_disk`'s own non-Unix arm and
/// `SettlementEvidence::ExactObject`'s doc comment for the full model.
#[cfg(not(unix))]
pub fn apply_unix_mode(_path: &Path, _unix_mode: Option<u32>) -> Result<(), StorageError> {
    Ok(())
}

/// Sets an already-materialized regular file's replicated extended
/// attributes to exactly `xattrs` — the
/// write-side counterpart to `chunker::read_replicated_xattrs`. Scoped to
/// the same `user.*` allow-list the read side captures under: only names
/// in that namespace are ever set or removed here, so an attribute this
/// device's capture path was never allowed to read is never touched by
/// materialization either, mirroring `apply_unix_mode`'s "only the bits we
/// replicate" discipline. An attribute already on disk under `user.*` but
/// absent from `xattrs` is removed (a fresh temp-then-rename target
/// normally carries none, but this keeps a re-materialized path from
/// accumulating stale attributes from an earlier, different version at the
/// same path). Best-effort: a failure to set or remove one attribute (e.g.
/// a filesystem with no xattr support) is silently skipped, matching
/// `read_replicated_xattrs`'s own "no attributes" fallback rather than
/// failing the whole materialization over metadata that was never
/// content-integrity-critical to begin with.
#[cfg(target_os = "linux")]
const LINUX_ALLOWED_XATTR_PREFIX: &str = "user.";

/// Whether `name` is inside the one extended-attribute namespace this
/// sync tool ever replicates on Linux -- the single predicate
/// `apply_xattrs` uses on BOTH its set and remove sides, so the two can
/// never disagree about which names are "replicated" ones. Factored out
/// so it is directly unit-testable without needing a real filesystem or
/// real syscalls at all (setting a genuinely privileged namespace like
/// `trusted.*`/`security.*` to prove a filter caught it would require
/// root in the first place, which would prove nothing about this
/// specific code path).
#[cfg(target_os = "linux")]
fn is_replicated_xattr_name(name: &str) -> bool {
    name.starts_with(LINUX_ALLOWED_XATTR_PREFIX)
}

#[cfg(target_os = "linux")]
pub fn apply_xattrs(path: &Path, xattrs: &[(String, Vec<u8>)]) -> Result<(), StorageError> {
    use std::os::unix::io::AsRawFd;

    let file = fs::File::open(path)?;
    let fd = file.as_raw_fd();

    let existing = crate::chunker::list_xattr_names_for_apply(fd)
        .into_iter()
        .filter(|name| is_replicated_xattr_name(name));
    for name in existing {
        if !xattrs.iter().any(|(n, _)| n == &name) {
            if let Ok(c_name) = std::ffi::CString::new(name) {
                unsafe { libc::fremovexattr(fd, c_name.as_ptr()) };
            }
        }
    }
    // Defense in depth, independent of `FileMeta::decode`'s own
    // allow-list rejection: this is the last point before a real
    // `fsetxattr` syscall, so a non-allow-listed name must never reach
    // it regardless of how it got here (a future caller that builds
    // `xattrs` some other way, a decode check that regresses). Silently
    // dropped, not an error -- exactly how every other best-effort
    // outcome in this function is already handled.
    for (name, value) in xattrs.iter().filter(|(name, _)| is_replicated_xattr_name(name)) {
        if let Ok(c_name) = std::ffi::CString::new(name.as_str()) {
            unsafe {
                libc::fsetxattr(
                    fd,
                    c_name.as_ptr(),
                    value.as_ptr() as *const libc::c_void,
                    value.len(),
                    0,
                )
            };
        }
    }
    Ok(())
}

/// See the `#[cfg(target_os = "linux")]` `apply_xattrs` above — every other
/// platform's read side (`read_replicated_xattrs`) never captures anything,
/// so there is nothing this device would ever need to write back; kept as
/// an explicit no-op for cross-platform parity rather than `#[cfg]`-hiding
/// the call sites.
#[cfg(not(target_os = "linux"))]
pub fn apply_xattrs(_path: &Path, _xattrs: &[(String, Vec<u8>)]) -> Result<(), StorageError> {
    Ok(())
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
    materialize_symlink_in(out_path, target, &NoTempLedger)
}

/// [`materialize_symlink`] with its temp link recorded in `ledger`.
#[cfg(unix)]
pub fn materialize_symlink_in(
    out_path: &Path,
    target: &[u8],
    ledger: &dyn TempFileLedger,
) -> Result<(), StorageError> {
    require_parent_directory(out_path)?;
    let link_target = yadorilink_fs_platform::fs_identity::bytes_to_target(target);
    let (tmp_path, ()) = create_recorded_tmp(out_path, ledger, random_tmp_path, |tmp| {
        std::os::unix::fs::symlink(&link_target, tmp)
    })?;
    if let Some(ns) = durable_namespace_beside(out_path)? {
        // Published by a durable move: the link is not reported as present
        // before its name is on disk.
        return ns
            .publish(&tmp_path, out_path, Replace::Yes, &LedgerNames(ledger))
            .map_err(|error| StorageError::Io(error.into()));
    }
    match rename_path(&tmp_path, out_path) {
        Ok(()) => {
            // The same directory holds the new name and the gone temp name.
            // The link is published only once that entry is durable: a failed
            // flush is an error, not a link the caller may record as present
            // (the temp record stays, to be cleaned by the ledger's sweep).
            sync_parent_directory(out_path)?;
            ledger.release(&tmp_path);
            Ok(())
        }
        Err(e) => {
            discard_temp_file(&tmp_path, ledger);
            Err(e.into())
        }
    }
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
    materialize_symlink_windows_in(out_path, target, &NoTempLedger)
}

/// [`materialize_symlink_windows`] with its temp link recorded in `ledger`.
#[cfg(windows)]
pub fn materialize_symlink_windows_in(
    out_path: &Path,
    target: &[u8],
    ledger: &dyn TempFileLedger,
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
    if let Some(ns) = namespace {
        return ns
            .publish(&tmp_path, out_path, Replace::Yes, &LedgerNames(ledger))
            .map_err(|error| StorageError::Io(error.into()));
    }
    if let Err(e) = rename_path(&tmp_path, out_path) {
        discard_temp_file(&tmp_path, ledger);
        return Err(e.into());
    }
    release_once_gone_is_durable(&tmp_path, ledger);
    Ok(())
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
