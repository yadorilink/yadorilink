//! The one place that changes the namespace durably.
//!
//! Every namespace change the product's correctness depends on is expressed as
//! a [`DurableNamespace::durable_move`]: a rename that is on disk when it
//! returns. Windows has exactly one documented primitive for that,
//! `MoveFileExW(MOVEFILE_WRITE_THROUGH)` on one volume: it "does not return
//! until the file is actually moved on the disk". Only the moved entry itself
//! is claimed durable by it: not an earlier `mkdir`, not other entries of the
//! same directory, not a replace that is half done. The shapes below are
//! built from that and nothing else:
//!
//! * create: a reserved Stage name beside the target, content flushed, then a
//!   no-replace move onto the target;
//! * replace: the same, with a replacing move (the visible path is never
//!   unlinked first);
//! * mkdir: an empty Stage directory, then a no-replace move; a missing chain
//!   of ancestors is built one published level at a time;
//! * delete / rmdir: a move of the object to a reserved Discard name beside it
//!   (the commit point), then a non-critical physical removal that is always
//!   non-recursive.
//!
//! Unix uses the same shapes with `rename` plus an `fsync` of the parent
//! directories as the durable move, so the steps above and their tests are
//! identical on every platform.
//!
//! Stage and Discard names are never recognised by their shape alone. The
//! caller records the name in a [`NameLedger`] before the object exists, and
//! the removal of leftovers works from that record.
//!
//! Windows is gated twice: [`WINDOWS_DIRECTORY_DURABILITY_VALIDATED`] (a
//! reviewed decision) and a per-volume probe that must see these shapes work on
//! the volume. [`DurableNamespace::open`] checks both and is the only way to
//! get a handle.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::fs_capabilities::Capability;
use crate::reserved_namespace::{artefact_component_name, ArtefactKind};

mod judged_remove;
#[cfg(any(test, feature = "test-support"))]
pub mod model;
mod probe;
mod raw;
#[cfg(any(test, feature = "test-support"))]
pub mod trace;
#[cfg(not(any(test, feature = "test-support")))]
mod trace;

#[cfg(test)]
mod tests;

pub use judged_remove::{judge_open_file, remove_file_judged, JudgedRemoveError};
#[cfg(windows)]
pub use probe::local_volume_file_system;
pub use probe::probe_directory_durability;
pub use probe::{is_no_guid_path, require_volume_guid_path, NoVolumeGuidPath};
pub use raw::{durable_flush_directory, rename_no_replace_durable};

/// The one-line switch for Windows. While `false`, [`DurableNamespace::open`]
/// refuses every Windows volume. It is `true` now that the conditions in the
/// design have been met and the owner has approved; which Windows volumes
/// qualify is still the per-volume probe's decision.
pub(crate) const WINDOWS_DIRECTORY_DURABILITY_VALIDATED: bool = true;

/// Whether this platform offers durable namespace changes at all: Unix always,
/// Windows only once its gate is open. Which volumes qualify is
/// [`DurableNamespace::open`]'s answer; this is the platform-wide part of it,
/// for the places that cannot name a directory yet.
pub const fn platform_offers_durable_namespace() -> bool {
    cfg!(unix) || (cfg!(windows) && WINDOWS_DIRECTORY_DURABILITY_VALIDATED)
}

/// Whether the local bytes held on `dirs` may be deleted: every volume must pass `is_durable`. A
/// directory that cannot be named (`None`) is an unknown volume and fails closed. Deleting
/// bytes depends on the volume that holds *them*, so the callers name the block store's
/// directory (and the sync root where the working-tree copy is deleted too).
pub fn all_volumes_durable(
    is_durable: impl Fn(Option<&Path>) -> bool,
    dirs: &[Option<&Path>],
) -> bool {
    dirs.iter().all(|dir| is_durable(*dir))
}

/// The production verdict for [`all_volumes_durable`]: Unix as before; Windows only when
/// [`DurableNamespace::open`] (the global gate and the volume's probe) accepts the directory.
pub fn volume_offers_durable_namespace(dir: Option<&Path>) -> bool {
    if !cfg!(windows) {
        return platform_offers_durable_namespace();
    }
    dir.is_some_and(|dir| DurableNamespace::open(dir).is_ok())
}

/// Whether a move may replace an existing target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replace {
    No,
    Yes,
}

/// Why [`DurableNamespace::open`] refused a directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnavailableReason {
    /// Windows, and [`WINDOWS_DIRECTORY_DURABILITY_VALIDATED`] is `false`.
    GateClosed,
    /// The volume's probe saw the shapes fail, or the volume is not one the
    /// shapes are meant for.
    Unsupported,
    /// The probe could not run.
    Unknown,
    /// The volume has a DOS path but no volume GUID path ([`NoVolumeGuidPath`]): it cannot be
    /// told from another volume later, so it is refused rather than matched by drive letter.
    VolumeWithoutGuidPath,
}

/// A failpoint of the namespace operations: the operation stops there as a
/// process killed at that point would, leaving the file system as it is. Armed
/// per thread by [`arm_failpoint`] (test builds only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(any(test, feature = "test-support")), allow(dead_code))]
pub enum NsFailpoint {
    /// The Stage object is complete (content flushed) and not yet moved.
    AfterStage,
    /// Right before a durable move.
    BeforeMove,
    /// Right after a durable move returned.
    AfterMove,
    /// A discard is committed; the physical removal is skipped.
    AfterDiscardBeforeUnlink,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NsError {
    /// Not a volume this contract holds on: the caller fails closed.
    #[error("durable namespace changes are unavailable here: {0:?}")]
    Unavailable(UnavailableReason),
    /// A no-replace move found its target occupied.
    #[error("the target already exists")]
    AlreadyExists,
    #[error("the source does not exist")]
    NotFound,
    /// A directory about to be discarded has children. A discard never
    /// removes a non-empty directory.
    #[error("the directory is not empty")]
    NotEmpty,
    /// The entry is gone but the sync that makes its absence durable failed
    /// (non-Windows removal). The caller decides whether that is fatal.
    #[error("removed, but not made durable: {0}")]
    NotDurable(io::Error),
    /// A sharing violation, access denial or lock (antivirus, indexer): never
    /// treated as success, and not retried here.
    #[error("the entry is in use: {0}")]
    Busy(io::Error),
    /// The move would cross volumes; it is not turned into a copy and delete.
    #[error("the move would cross volumes")]
    CrossVolume,
    #[error(transparent)]
    Io(io::Error),
    /// An armed [`NsFailpoint`] fired.
    #[cfg(any(test, feature = "test-support"))]
    #[error("failpoint {0:?}")]
    Crashed(NsFailpoint),
}

impl NsError {
    fn from_io(error: io::Error) -> Self {
        use io::ErrorKind as K;
        match error.kind() {
            K::AlreadyExists => return Self::AlreadyExists,
            K::NotFound => return Self::NotFound,
            K::DirectoryNotEmpty => return Self::NotEmpty,
            K::ResourceBusy => return Self::Busy(error),
            _ => {}
        }
        #[cfg(windows)]
        match error.raw_os_error() {
            // ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS
            Some(183 | 80) => return Self::AlreadyExists,
            // ERROR_NOT_SAME_DEVICE
            Some(17) => return Self::CrossVolume,
            // ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION
            Some(5 | 32 | 33) => return Self::Busy(error),
            _ => {}
        }
        #[cfg(unix)]
        match error.raw_os_error() {
            Some(libc::EXDEV) => return Self::CrossVolume,
            Some(libc::EEXIST) => return Self::AlreadyExists,
            Some(libc::EBUSY | libc::ETXTBSY) => return Self::Busy(error),
            _ => {}
        }
        Self::Io(error)
    }
}

impl From<NsError> for io::Error {
    fn from(error: NsError) -> Self {
        match error {
            NsError::Io(error) | NsError::Busy(error) | NsError::NotDurable(error) => error,
            NsError::AlreadyExists => io::Error::from(io::ErrorKind::AlreadyExists),
            NsError::NotFound => io::Error::from(io::ErrorKind::NotFound),
            NsError::NotEmpty => io::Error::from(io::ErrorKind::DirectoryNotEmpty),
            other => io::Error::other(other.to_string()),
        }
    }
}

/// The durable record of the names the product is about to create. `record`
/// runs BEFORE the object exists and must not return until the name is durable;
/// `release` runs after the name is gone for good. A record left behind by a
/// crash is what the next start works from: nothing ever guesses from a name
/// that a stray entry is ours.
pub trait NameLedger {
    fn record(&self, path: &Path) -> io::Result<()>;
    /// Best effort: a record that outlives its object only names a path that
    /// no longer exists.
    fn release(&self, path: &Path);
}

/// For writers with no recovery to speak of (small private files whose
/// leftover is harmless, tests).
pub struct NoLedger;

impl NameLedger for NoLedger {
    fn record(&self, _path: &Path) -> io::Result<()> {
        Ok(())
    }
    fn release(&self, _path: &Path) {}
}

/// Why a discarded object is still beside its former path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetainReason {
    /// The physical removal failed; the ledger record stays and the next
    /// recovery retries it.
    RemovalFailed,
    /// A directory turned out to have children and its former path is occupied
    /// by another object, so it could be neither removed nor put back. It stays
    /// under the Discard name and the user must be told.
    OriginalOccupied,
}

/// What became of a discarded object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscardOutcome {
    /// Physically removed.
    Removed,
    /// A directory with children was put back under its former name.
    Restored,
    /// Still under its Discard name at the given path.
    Retained { path: PathBuf, reason: RetainReason },
}

impl DiscardOutcome {
    /// For a caller about to record the path absent. Moved away from the path is not the same
    /// as logically removed: only `Removed`, or `RemovalFailed` whose leftover the caller's
    /// ledger holds (recovery is guaranteed to finish it), is `Ok`. A directory put back, or
    /// an object left under a Discard name beside an occupied path, is an error that names the
    /// leftover. A caller with no ledger must clean up `RemovalFailed` itself (see
    /// [`remove_file_durably`]) and treat a failed cleanup as an error.
    pub fn removed(&self) -> io::Result<()> {
        match self {
            Self::Removed | Self::Retained { reason: RetainReason::RemovalFailed, .. } => Ok(()),
            Self::Restored => {
                Err(io::Error::new(io::ErrorKind::ResourceBusy, "an object occupies the path"))
            }
            Self::Retained { path, reason: RetainReason::OriginalOccupied } => Err(io::Error::new(
                io::ErrorKind::ResourceBusy,
                format!("an object occupies the path; the displaced one is at {}", path.display()),
            )),
        }
    }
}

/// An object moved to its Discard name: the removal is committed.
#[derive(Debug)]
pub struct Discarded {
    path: PathBuf,
    original: PathBuf,
}

impl Discarded {
    /// Where the object is now.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The physical removal. Non-critical (a failure keeps the ledger record
    /// for the next recovery) and always non-recursive: a directory with a
    /// child is never deleted but put back by a durable no-replace move, and if
    /// its former path is occupied meanwhile it is left under the Discard name
    /// ([`RetainReason::OriginalOccupied`]), never replacing the other object.
    pub fn finish(self, ns: &DurableNamespace, ledger: &dyn NameLedger) -> DiscardOutcome {
        if hit(NsFailpoint::AfterDiscardBeforeUnlink).is_err() {
            return self.retained(RetainReason::RemovalFailed);
        }
        match remove_and_release(&self.path, ledger) {
            Ok(()) => DiscardOutcome::Removed,
            Err(error) if is_directory_not_empty(&error) => self.put_back(ns, ledger),
            Err(_) => self.retained(RetainReason::RemovalFailed),
        }
    }

    fn retained(self, reason: RetainReason) -> DiscardOutcome {
        DiscardOutcome::Retained { path: self.path, reason }
    }

    fn put_back(self, ns: &DurableNamespace, ledger: &dyn NameLedger) -> DiscardOutcome {
        match ns.durable_move(&self.path, &self.original, Replace::No) {
            Ok(()) => {
                ledger.release(&self.path);
                DiscardOutcome::Restored
            }
            Err(NsError::AlreadyExists) => self.retained(RetainReason::OriginalOccupied),
            Err(_) => self.retained(RetainReason::RemovalFailed),
        }
    }
}

fn is_directory_not_empty(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::DirectoryNotEmpty {
        return true;
    }
    // POSIX lets `rmdir` answer EEXIST for a non-empty directory.
    #[cfg(unix)]
    if error.raw_os_error() == Some(libc::EEXIST) {
        return true;
    }
    false
}

/// A directory on a volume where the shapes in the module documentation have
/// been seen to work. The only way to change the namespace durably.
#[derive(Debug, Clone, Copy)]
pub struct DurableNamespace {
    /// The volume the handle was validated for; every move stays on it.
    volume: Option<u64>,
}

impl DurableNamespace {
    /// The handle for the volume `dir` lives on: Windows requires
    /// [`WINDOWS_DIRECTORY_DURABILITY_VALIDATED`] and a probe verdict of
    /// `Supported`; Unix requires the probe verdict only. The verdict is cached
    /// per volume (an `Unknown` is not).
    pub fn open(dir: &Path) -> Result<Self, NsError> {
        if cfg!(windows) && !WINDOWS_DIRECTORY_DURABILITY_VALIDATED {
            return Err(NsError::Unavailable(UnavailableReason::GateClosed));
        }
        if let Err(e) = probe::volume_key(dir) {
            if probe::is_no_guid_path(&e) {
                return Err(NsError::Unavailable(UnavailableReason::VolumeWithoutGuidPath));
            }
        }
        Self::from_verdict(probe::cached_verdict(dir), dir)
    }

    /// The handle for `dir` given its volume's probe verdict: only `Supported` opens.
    fn from_verdict(verdict: Capability, dir: &Path) -> Result<Self, NsError> {
        match verdict {
            Capability::Supported => {
                Ok(Self { volume: Some(probe::volume_key(dir).map_err(NsError::Io)?) })
            }
            Capability::Unsupported => Err(NsError::Unavailable(UnavailableReason::Unsupported)),
            Capability::Unknown => Err(NsError::Unavailable(UnavailableReason::Unknown)),
        }
    }

    /// [`Self::open`] for a writer that keeps its pre-validation behaviour (a plain
    /// rename, no durability claim) only while the global Windows gate is closed:
    /// `Ok(None)` is that, and nothing else. A volume the probe judged
    /// `Unsupported` or `Unknown` is an error the caller must propagate, so once
    /// the gate opens no writer can fall back to a plain rename on a volume that
    /// was refused. This is the only fallback the writers may take.
    pub fn open_unless_gate_closed(dir: &Path) -> Result<Option<Self>, NsError> {
        Self::only_a_closed_gate_may_fall_back(Self::open(dir))
    }

    fn only_a_closed_gate_may_fall_back(
        opened: Result<Self, NsError>,
    ) -> Result<Option<Self>, NsError> {
        match opened {
            Ok(ns) => Ok(Some(ns)),
            Err(NsError::Unavailable(UnavailableReason::GateClosed)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// A handle without the gate or the probe, for the probe itself and for
    /// tests of the shapes on a platform whose gate is closed.
    #[cfg(any(test, feature = "test-support"))]
    pub fn unchecked_for_tests() -> Self {
        Self { volume: None }
    }

    pub(crate) fn unchecked() -> Self {
        Self { volume: None }
    }

    /// Moves `from` to `to`; on return the move is on disk. This is the only
    /// primitive the rest is made of. Windows: `MoveFileExW` with write-through
    /// and no copy fallback. Unix: the (no-replace) rename and an `fsync` of
    /// both parent directories. A Unix directory sync that fails after the
    /// rename reports an error although the entry moved; the caller treats the
    /// move as not done.
    ///
    /// A parent directory that is a link is followed to the directory it names
    /// (a sync root may be given by a link); the volume check below judges the
    /// directory it leads to. The moved entry itself may be a link: it is
    /// moved, never followed.
    pub fn durable_move(&self, from: &Path, to: &Path, replace: Replace) -> Result<(), NsError> {
        let (from_parent, to_parent) = (parent_of(from)?, parent_of(to)?);
        self.require_validated_volume(&[from_parent, to_parent])?;
        #[cfg(unix)]
        let handles = ops::open_parents(from_parent, to_parent)?;
        hit(NsFailpoint::BeforeMove)?;
        ops::move_entry(from, to, replace).map_err(NsError::from_io)?;
        #[cfg(unix)]
        ops::sync_handles(&handles, from_parent, to_parent)?;
        hit(NsFailpoint::AfterMove)
    }

    /// Creates `target` with the content `write` produces: a Stage file beside
    /// it (named in `ledger` first), flushed, then published by
    /// [`Self::durable_move`]. The visible path is never half written.
    pub fn create_file(
        &self,
        target: &Path,
        replace: Replace,
        ledger: &dyn NameLedger,
        write: impl FnOnce(&mut fs::File) -> io::Result<()>,
    ) -> Result<(), NsError> {
        let stage = self.stage_path(target)?;
        ledger.record(&stage).map_err(NsError::Io)?;
        let staged = (|| -> io::Result<()> {
            let mut file = ops::create_file(&stage)?;
            write(&mut file)?;
            ops::sync_file(&file, &stage)
        })();
        if let Err(error) = staged {
            abandon(&stage, ledger);
            return Err(NsError::from_io(error));
        }
        self.publish_staged(&stage, target, replace, ledger)
    }

    /// Publishes an object the caller staged at [`Self::stage_path`] itself
    /// (created with its own permissions, written and flushed, and recorded in
    /// `ledger` before it existed): a file or an empty directory. The record
    /// is released here once the stage name is gone; a failed publish removes
    /// the stage.
    pub fn publish(
        &self,
        staged: &Path,
        target: &Path,
        replace: Replace,
        ledger: &dyn NameLedger,
    ) -> Result<(), NsError> {
        self.publish_staged(staged, target, replace, ledger)
    }

    /// [`Self::publish`] without the directory flush: the rename only. The caller
    /// owes the flush of both parents before it relies on the name, and keeps
    /// the stage record in its ledger until then (it is NOT released here: a
    /// crash before the flush may bring the stage name back). A failed rename
    /// removes the stage, as [`Self::publish`] does.
    #[cfg(unix)]
    pub fn publish_without_flush(
        &self,
        staged: &Path,
        target: &Path,
        replace: Replace,
        ledger: &dyn NameLedger,
    ) -> Result<(), NsError> {
        let (from_parent, to_parent) = (parent_of(staged)?, parent_of(target)?);
        self.require_validated_volume(&[from_parent, to_parent])?;
        let moved = hit(NsFailpoint::BeforeMove)
            .and_then(|()| ops::move_entry(staged, target, replace).map_err(NsError::from_io));
        if let Err(error) = moved {
            if !is_crash(&error) {
                abandon(staged, ledger);
            }
            return Err(error);
        }
        Ok(())
    }

    /// Creates the empty directory `target`: a Stage directory, then a
    /// no-replace move. An existing `target` is `AlreadyExists`.
    pub fn create_dir(&self, target: &Path, ledger: &dyn NameLedger) -> Result<(), NsError> {
        let stage = self.stage_path(target)?;
        ledger.record(&stage).map_err(NsError::Io)?;
        if let Err(error) = ops::mkdir(&stage) {
            abandon(&stage, ledger);
            return Err(NsError::from_io(error));
        }
        self.publish_staged(&stage, target, Replace::No, ledger)
    }

    /// Creates every missing ancestor of `target`, shallowest first, then
    /// `target`, each as its own published directory. The first ancestor that
    /// exists is trusted as it is, a link to a directory included (a sync root,
    /// a profile directory); a non-directory in the way is refused.
    pub fn create_dir_all(&self, target: &Path, ledger: &dyn NameLedger) -> Result<(), NsError> {
        let mut missing = Vec::new();
        let mut current = target;
        loop {
            // `metadata` follows a link: the first ancestor that exists is trusted
            // as it is, a sync root given by a link included.
            match fs::metadata(current) {
                Ok(meta) if meta.is_dir() => break,
                Ok(_) => return Err(NsError::AlreadyExists),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    missing.push(current);
                    current = parent_of(current)?;
                }
                Err(e) => return Err(NsError::from_io(e)),
            }
        }
        for dir in missing.into_iter().rev() {
            match self.create_dir(dir, ledger) {
                Ok(()) => {}
                // Another creator won the race; fine if it made a directory.
                Err(NsError::AlreadyExists) if dir.is_dir() => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Commits the removal of `target`: the Discard name is recorded in
    /// `ledger`, then `target` is moved to it. A directory with children is
    /// refused ([`NsError::NotEmpty`]). The physical removal is
    /// [`Discarded::finish`].
    pub fn discard(&self, target: &Path, ledger: &dyn NameLedger) -> Result<Discarded, NsError> {
        let meta = fs::symlink_metadata(target).map_err(NsError::from_io)?;
        if meta.is_dir() && fs::read_dir(target).map_err(NsError::from_io)?.next().is_some() {
            return Err(NsError::NotEmpty);
        }
        let path = reserved_sibling(target, ArtefactKind::Discard)?;
        ledger.record(&path).map_err(NsError::Io)?;
        if let Err(error) = self.durable_move(target, &path, Replace::No) {
            // A name that never came to exist has nothing to recover.
            if !is_crash(&error) && fs::symlink_metadata(&path).is_err() {
                ledger.release(&path);
            }
            return Err(error);
        }
        Ok(Discarded { path, original: target.to_path_buf() })
    }

    /// The handle was validated for one volume; a move on any other has not
    /// been probed, whatever the OS would accept.
    fn require_validated_volume(&self, dirs: &[&Path]) -> Result<(), NsError> {
        let Some(volume) = self.volume else { return Ok(()) };
        for dir in dirs {
            if probe::volume_key(dir).map_err(NsError::from_io)? != volume {
                return Err(NsError::CrossVolume);
            }
        }
        Ok(())
    }

    /// Removes the file or link at `target`; on return the removal is durable.
    /// A directory is refused ([`NsError::Io`], `IsADirectory`).
    ///
    /// Windows: [`Self::discard`] and [`Discarded::finish`], the move being the
    /// commit point (`ledger` names the Discard name). Elsewhere a plain unlink
    /// followed by a sync of the parent is already durable and keeps its
    /// single ledger-free step; the invariant is the same.
    pub fn remove_file(
        &self,
        target: &Path,
        ledger: &dyn NameLedger,
    ) -> Result<DiscardOutcome, NsError> {
        match is_directory(target)? {
            Some(true) => Err(NsError::Io(io::Error::from(io::ErrorKind::IsADirectory))),
            // Where nothing is, a non-Windows removal still has the parent sync
            // to do, which makes the absence durable for a caller about to
            // record it; on Windows there is nothing to make durable.
            None if cfg!(windows) => Err(NsError::NotFound),
            _ => self.remove_object(target, ledger, Kind::File),
        }
    }

    /// Removes the empty directory at `target` with one non-recursive step; on
    /// return the removal is durable. A directory with children is
    /// [`NsError::NotEmpty`] and stays as it is; on Windows one that gains a
    /// child while it is being moved aside is put back
    /// ([`DiscardOutcome::Restored`]) and never replaces what took its place
    /// ([`RetainReason::OriginalOccupied`]). Anything but a directory is
    /// refused.
    pub fn remove_empty_dir(
        &self,
        target: &Path,
        ledger: &dyn NameLedger,
    ) -> Result<DiscardOutcome, NsError> {
        match is_directory(target)? {
            Some(true) => self.remove_object(target, ledger, Kind::EmptyDirectory),
            Some(false) => Err(NsError::Io(io::Error::from(io::ErrorKind::NotADirectory))),
            None => Err(NsError::NotFound),
        }
    }

    /// Removes the object at `target`, which the caller saw to be of `kind`.
    /// Whatever has taken its place since is not removed: the kind is
    /// enforced by the removal itself (Unix) or checked on the moved object and
    /// put back (Windows), never trusted from the earlier look.
    fn remove_object(
        &self,
        target: &Path,
        ledger: &dyn NameLedger,
        kind: Kind,
    ) -> Result<DiscardOutcome, NsError> {
        run_before_remove_hook();
        #[cfg(windows)]
        {
            let discarded = self.discard(target, ledger)?;
            let moved_is_dir = is_directory(discarded.path())?;
            if moved_is_dir != Some(kind == Kind::EmptyDirectory) {
                // Another kind of object was moved: a failed put-back is no removal either,
                // so it is reported as the displaced object it is, never as `RemovalFailed`.
                return Ok(match discarded.put_back(self, ledger) {
                    DiscardOutcome::Retained { path, .. } => {
                        DiscardOutcome::Retained { path, reason: RetainReason::OriginalOccupied }
                    }
                    other => other,
                });
            }
            Ok(discarded.finish(self, ledger))
        }
        #[cfg(not(windows))]
        {
            let _ = ledger;
            self.require_validated_volume(&[parent_of(target)?])?;
            let removed = match kind {
                Kind::File => ops::remove_file(target),
                Kind::EmptyDirectory => ops::remove_dir(target),
            };
            match removed {
                Ok(()) => {}
                // Already gone: the parent sync below still makes that durable,
                // which is what a caller about to record the absence needs.
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) if is_directory_not_empty(&error) => return Err(NsError::NotEmpty),
                Err(error) => return Err(NsError::from_io(error)),
            }
            ops::sync_parent_after_removal(target).map_err(NsError::NotDurable)?;
            Ok(DiscardOutcome::Removed)
        }
    }

    /// A fresh reserved Stage name beside `target`.
    pub fn stage_path(&self, target: &Path) -> Result<PathBuf, NsError> {
        reserved_sibling(target, ArtefactKind::Stage)
    }

    fn publish_staged(
        &self,
        stage: &Path,
        target: &Path,
        replace: Replace,
        ledger: &dyn NameLedger,
    ) -> Result<(), NsError> {
        hit(NsFailpoint::AfterStage)?;
        if let Err(error) = self.durable_move(stage, target, replace) {
            if !is_crash(&error) {
                abandon(stage, ledger);
            }
            return Err(error);
        }
        ledger.release(stage);
        Ok(())
    }
}

/// Publishes `staged`, a file the caller created beside `target`, wrote and
/// flushed, as `target`, and returns once that is durable. This is for the small
/// private files (a credential, a device identity, a consent record) whose
/// writers keep their own temporary name and have no ledger to recover from.
///
/// Where the volume offers durable moves (see [`DurableNamespace::open`]) the
/// publish is [`DurableNamespace::publish`]; otherwise it is what such writers
/// always did: a replacing rename, or a hard link that refuses an occupied
/// name, followed by a sync of the directory where the platform has one. An
/// occupied `target` with [`Replace::No`] is `AlreadyExists` either way, and a
/// failed publish removes `staged`.
pub fn publish_durably(staged: &Path, target: &Path, replace: Replace) -> io::Result<()> {
    match DurableNamespace::open_unless_gate_closed(directory_of(target)) {
        Ok(Some(ns)) => {
            return ns.publish(staged, target, replace, &NoLedger).map_err(io::Error::from)
        }
        Ok(None) => {}
        Err(error) => {
            // A refused volume: nothing is published, and the staged file does not outlive it.
            let _ = fs::remove_file(staged);
            return Err(error.into());
        }
    }
    publish_without_a_durable_move(staged, target, replace)
}

fn publish_without_a_durable_move(
    staged: &Path,
    target: &Path,
    replace: Replace,
) -> io::Result<()> {
    let published = match replace {
        Replace::Yes => fs::rename(staged, target),
        // An atomic no-replace move, as the durable publish makes: no hard link, so a volume
        // without them (FAT, exFAT) publishes too, and a staged directory can be published.
        Replace::No => raw::move_entry(staged, target, Replace::No),
    };
    // As with a durable publish, `staged` does not outlive a failed one.
    match published.and_then(|()| sync_directory_if_any(target)) {
        Ok(()) => Ok(()),
        Err(error) => {
            // The staged object is a file or an empty directory.
            match fs::symlink_metadata(staged) {
                Ok(meta) if meta.is_dir() => {
                    let _ = fs::remove_dir(staged);
                }
                Ok(_) => {
                    let _ = fs::remove_file(staged);
                }
                Err(_) => {}
            }
            Err(error)
        }
    }
}

/// Creates `path` and every missing ancestor, each as its own published directory where the
/// volume offers durable moves (the first ancestor that exists is trusted as it is), otherwise
/// with a plain `create_dir_all` (only while the Windows gate is closed). For the parents of the
/// private records whose loss changes what a restart concludes.
///
/// Policy for a directory that already exists: it is trusted as it is and nothing about it is
/// flushed. Only what this call creates is made durable, so a parent that an earlier call
/// created is durable already (every creation of such a parent goes through here), and one that
/// predates the product (a profile folder) is not the product's to prove.
pub fn create_dir_all_durably(path: &Path) -> io::Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    let (path, existing) = absolute_with_existing_ancestor(path)?;
    if let Some(existing) = existing {
        if let Some(ns) = DurableNamespace::open_unless_gate_closed(&existing)? {
            return ns.create_dir_all(&path, &NoLedger).map_err(io::Error::from);
        }
    }
    fs::create_dir_all(&path)
}

/// `path` resolved against the current directory, and the nearest ancestor of it that exists.
/// A relative path (a config directory given as `state/config`) has no existing ancestor among
/// its own relative spellings, which would silently turn the durable creation into a plain one.
fn absolute_with_existing_ancestor(path: &Path) -> io::Result<(PathBuf, Option<PathBuf>)> {
    let path = std::path::absolute(path)?;
    let existing = path.ancestors().find(|dir| dir.is_dir()).map(Path::to_path_buf);
    Ok((path, existing))
}

#[cfg(test)]
mod relative_path_tests {
    use super::*;

    #[test]
    fn a_relative_path_finds_its_existing_ancestor_in_the_current_directory() {
        let name = format!("yl-rel-{}", std::process::id());
        let relative = Path::new(&name).join("config").join("deeper");
        let (absolute, existing) = absolute_with_existing_ancestor(&relative).unwrap();
        assert_eq!(absolute, std::env::current_dir().unwrap().join(&relative));
        assert_eq!(existing, Some(std::env::current_dir().unwrap()));

        create_dir_all_durably(&relative).unwrap();
        assert!(relative.is_dir());
        let _ = fs::remove_dir_all(&name);
    }
}

/// Moves `from` to `to` and returns once that is durable, for a caller that
/// owns neither name's content beyond the move (a user file or directory kept
/// under another name): [`DurableNamespace::durable_move`] where the volume
/// offers durable moves, otherwise the plain move (never replacing, with
/// [`Replace::No`]) and a sync of the directory where the platform has one.
/// Unlike [`publish_durably`], a failed move leaves `from` where it was.
pub fn move_durably(from: &Path, to: &Path, replace: Replace) -> io::Result<()> {
    if let Some(ns) = DurableNamespace::open_unless_gate_closed(directory_of(to))? {
        return ns.durable_move(from, to, replace).map_err(io::Error::from);
    }
    raw::move_entry(from, to, replace)?;
    sync_directory_if_any(to)
}

/// Removes the file or link at `target` (already gone is fine) and returns once
/// that is durable: [`DurableNamespace::remove_file`] where the volume offers
/// durable moves, otherwise an unlink followed by a sync of the directory where
/// the platform has one. For the same small private files as [`publish_durably`].
pub fn remove_file_durably(target: &Path) -> io::Result<()> {
    if let Some(ns) = DurableNamespace::open_unless_gate_closed(directory_of(target))? {
        return remove_file_with(&ns, target);
    }
    match fs::remove_file(target) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    sync_directory_if_any(target)
}

/// [`remove_file_durably`] on a volume that offers durable moves.
fn remove_file_with(ns: &DurableNamespace, target: &Path) -> io::Result<()> {
    match ns.remove_file(target, &NoLedger) {
        Ok(outcome) => {
            outcome.removed()?;
            // No ledger, so no recovery will ever finish a leftover: remove it now or say so.
            if let DiscardOutcome::Retained { path, .. } = &outcome {
                fs::remove_file(path)?;
            }
            Ok(())
        }
        Err(NsError::NotFound) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// The directory sync a writer without durable moves can still do: Unix only,
/// and a directory that is gone has nothing to sync.
fn sync_directory_if_any(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    match raw::DirHandle::open(directory_of(path)) {
        Ok(handle) => handle.sync()?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Removes a Stage object that will not be published, then releases its record
/// (the record outlives the object, never the reverse). A failed removal keeps
/// the record for recovery.
fn abandon(stage: &Path, ledger: &dyn NameLedger) {
    match remove_and_release(stage, ledger) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => ledger.release(stage),
        _ => {}
    }
}

/// Removes `path` (never recursively) and releases its record once the name's
/// disappearance is durable: on Unix after a sync of the parent, which a
/// failure keeps the record for. Windows documents no durability for an unlink,
/// so the record is NOT released on that unproven boundary: a power loss could
/// bring the name back with no record naming it. The next recovery reads the
/// record, finds the path absent (and drops the record) or present (and
/// removes it again, non-recursively).
fn remove_and_release(path: &Path, ledger: &dyn NameLedger) -> io::Result<()> {
    remove_and_release_with(path, ledger, cfg!(unix))
}

fn remove_and_release_with(
    path: &Path,
    ledger: &dyn NameLedger,
    unlink_is_durable: bool,
) -> io::Result<()> {
    ops::remove(path)?;
    ops::sync_parent_after_removal(path)?;
    if unlink_is_durable {
        ledger.release(path);
    }
    Ok(())
}

/// What a removal is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    File,
    EmptyDirectory,
}

/// Whether `target` is a directory (a link is not followed); `None` if nothing
/// is there.
fn is_directory(target: &Path) -> Result<Option<bool>, NsError> {
    match fs::symlink_metadata(target) {
        Ok(meta) => Ok(Some(meta.is_dir())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(NsError::from_io(error)),
    }
}

/// The directory a bare file name or a path lives in (`.` for a bare name).
fn directory_of(path: &Path) -> &Path {
    path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."))
}

/// The directory `path` lives in (`.` for a bare file name); a path with no
/// parent at all, such as a root, is an error.
fn parent_of(path: &Path) -> Result<&Path, NsError> {
    match path.parent() {
        Some(parent) if parent.as_os_str().is_empty() => Ok(Path::new(".")),
        Some(parent) => Ok(parent),
        None => Err(NsError::Io(io::Error::new(io::ErrorKind::InvalidInput, "no parent"))),
    }
}

static NAME_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A fresh reserved name of `kind` in the same directory as `target`.
fn reserved_sibling(target: &Path, kind: ArtefactKind) -> Result<PathBuf, NsError> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let id = format!(
        "{}-{}-{}",
        std::process::id(),
        nanos,
        NAME_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let name = artefact_component_name(kind, &id)
        .map_err(|e| NsError::Io(io::Error::new(io::ErrorKind::InvalidInput, e)))?;
    Ok(parent_of(target)?.join(name))
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static ARMED: std::cell::Cell<Option<NsFailpoint>> = const { std::cell::Cell::new(None) };
    /// Non-zero while the probe runs: its own steps neither fire a failpoint
    /// nor show up in the trace of the operation that triggered it.
    static QUIET: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Runs `f` with failpoints and the trace silenced (see `QUIET`).
#[cfg(any(test, feature = "test-support"))]
fn quiet<T>(f: impl FnOnce() -> T) -> T {
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            QUIET.with(|q| q.set(q.get() - 1));
        }
    }
    QUIET.with(|q| q.set(q.get() + 1));
    let _restore = Restore;
    f()
}

#[cfg(not(any(test, feature = "test-support")))]
fn quiet<T>(f: impl FnOnce() -> T) -> T {
    f()
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn is_quiet() -> bool {
    QUIET.with(|q| q.get() > 0)
}

/// Arms `failpoint` for this thread: the next time an operation reaches it, the
/// operation stops with [`NsError::Crashed`] (or, for
/// [`NsFailpoint::AfterDiscardBeforeUnlink`], skips the removal) and the
/// failpoint disarms.
#[cfg(any(test, feature = "test-support"))]
pub fn arm_failpoint(failpoint: NsFailpoint) {
    ARMED.with(|armed| armed.set(Some(failpoint)));
}

/// Test seam: runs `f` once, on this thread, right before the next
/// `remove_file` / `remove_empty_dir` acts on the path its caller just judged
/// (the window in which another process can swap the object).
#[cfg(any(test, feature = "test-support"))]
pub fn before_next_remove_object(f: impl FnOnce() + 'static) {
    BEFORE_REMOVE.with(|hook| *hook.borrow_mut() = Some(Box::new(f)));
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static BEFORE_REMOVE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(any(test, feature = "test-support"))]
fn run_before_remove_hook() {
    if let Some(f) = BEFORE_REMOVE.with(|hook| hook.borrow_mut().take()) {
        f();
    }
}

#[cfg(not(any(test, feature = "test-support")))]
fn run_before_remove_hook() {}

#[cfg(any(test, feature = "test-support"))]
pub fn disarm_failpoint() {
    ARMED.with(|armed| armed.set(None));
}

#[cfg(any(test, feature = "test-support"))]
fn hit(failpoint: NsFailpoint) -> Result<(), NsError> {
    if !is_quiet() && ARMED.with(|armed| armed.get()) == Some(failpoint) {
        disarm_failpoint();
        return Err(NsError::Crashed(failpoint));
    }
    Ok(())
}

#[cfg(not(any(test, feature = "test-support")))]
fn hit(_failpoint: NsFailpoint) -> Result<(), NsError> {
    Ok(())
}

#[cfg(any(test, feature = "test-support"))]
fn is_crash(error: &NsError) -> bool {
    matches!(error, NsError::Crashed(_))
}

#[cfg(not(any(test, feature = "test-support")))]
fn is_crash(_error: &NsError) -> bool {
    false
}

/// Every file system change of the operations above goes through here, so the
/// model in [`model`] sees exactly the steps that were taken.
mod ops {
    use super::*;

    pub(super) fn create_file(path: &Path) -> io::Result<fs::File> {
        let file = fs::OpenOptions::new().write(true).create_new(true).open(path)?;
        trace::emit(|| trace::Event::Create { path: path.into(), dir: false });
        Ok(file)
    }

    pub(super) fn mkdir(path: &Path) -> io::Result<()> {
        fs::create_dir(path)?;
        trace::emit(|| trace::Event::Create { path: path.into(), dir: true });
        Ok(())
    }

    pub(super) fn sync_file(file: &fs::File, path: &Path) -> io::Result<()> {
        file.sync_all()?;
        trace::emit(|| trace::Event::FlushFile { path: path.into() });
        Ok(())
    }

    pub(super) fn move_entry(from: &Path, to: &Path, replace: Replace) -> io::Result<()> {
        super::raw::move_entry(from, to, replace)?;
        trace::emit(|| trace::Event::Move {
            from: from.into(),
            to: to.into(),
            write_through: true,
        });
        Ok(())
    }

    /// Removes a file or a link; a directory is refused by the system call.
    pub(super) fn remove_file(path: &Path) -> io::Result<()> {
        remove_non_directory(path)?;
        trace::emit(|| trace::Event::Remove { path: path.into() });
        Ok(())
    }

    /// Removes a directory that is empty; anything else is refused by the
    /// system call.
    pub(super) fn remove_dir(path: &Path) -> io::Result<()> {
        fs::remove_dir(path)?;
        trace::emit(|| trace::Event::Remove { path: path.into() });
        Ok(())
    }

    /// Removes a file, a link or an empty directory, whichever is there. Never
    /// recursive.
    pub(super) fn remove(path: &Path) -> io::Result<()> {
        if fs::symlink_metadata(path)?.is_dir() {
            remove_dir(path)
        } else {
            remove_file(path)
        }
    }

    fn remove_non_directory(path: &Path) -> io::Result<()> {
        let removed = fs::remove_file(path);
        // A directory link needs `remove_dir` on Windows.
        #[cfg(windows)]
        if removed.is_err() && fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
        {
            return fs::remove_dir(path);
        }
        removed
    }

    #[cfg(unix)]
    pub(super) fn open_parents(
        from_parent: &Path,
        to_parent: &Path,
    ) -> Result<Vec<super::raw::DirHandle>, NsError> {
        let mut handles = vec![super::raw::DirHandle::open(to_parent).map_err(NsError::from_io)?];
        if from_parent != to_parent {
            handles.push(super::raw::DirHandle::open(from_parent).map_err(NsError::from_io)?);
        }
        Ok(handles)
    }

    #[cfg(unix)]
    pub(super) fn sync_handles(
        handles: &[super::raw::DirHandle],
        from_parent: &Path,
        to_parent: &Path,
    ) -> Result<(), NsError> {
        let dirs = [to_parent, from_parent];
        for (handle, dir) in handles.iter().zip(dirs) {
            handle.sync().map_err(NsError::from_io)?;
            trace::emit(|| trace::Event::FlushDir { dir: dir.into() });
        }
        Ok(())
    }

    /// After a physical removal: Unix syncs the parent so the record is only
    /// released once the name is really gone; Windows has no such contract and
    /// the record is released as soon as the removal returned.
    pub(super) fn sync_parent_after_removal(path: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            let parent = super::directory_of(path);
            match super::raw::DirHandle::open(parent) {
                Ok(handle) => handle.sync()?,
                // The directory is gone too: nothing is left in it to make durable.
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(error),
            }
            trace::emit(|| trace::Event::FlushDir { dir: parent.into() });
        }
        #[cfg(not(unix))]
        let _ = path;
        Ok(())
    }
}
