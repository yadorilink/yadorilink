//! The crate's single boundary for the filesystem primitives that publish
//! or remove objects: removing a path, atomically replacing a path,
//! publishing a path only if it is absent, and making a directory's own
//! entries durable.
//!
//! These live here rather than inside whichever module happened to need
//! them first so that an audit of "where does this crate unlink, rename,
//! or issue a directory barrier?" has exactly one place to look. Moved out
//! of the deleted loose-file block backend, unchanged.

use std::fs;
use std::path::Path;

use yadorilink_fs_platform::durable_dir::{DurableNamespace, NameLedger, NsError};

use crate::error::StorageError;
use crate::materialize_write::TempFileLedger;

/// The handle for durable namespace changes beside `path`. `Ok(None)` means only
/// that the global Windows gate is still closed: callers then keep the plain
/// rename they always had, with no durability claim beyond it. A volume the
/// probe refused (`Unsupported`, `Unknown`) is an `Err` the caller propagates
/// with the visible target left unchanged; it is never turned into that plain
/// path.
pub(crate) fn durable_namespace_beside(
    path: &Path,
) -> Result<Option<DurableNamespace>, std::io::Error> {
    // The writers' own tests run the durable shapes on every platform, Windows
    // included, where the gate is closed; the gate and the probe are tested
    // where they live.
    #[cfg(any(test, feature = "test-support"))]
    {
        let _ = path;
        if let Some(reason) = TEST_REFUSAL.with(std::cell::Cell::get) {
            return Err(NsError::Unavailable(reason, Default::default()).into());
        }
        Ok(Some(DurableNamespace::unchecked_for_tests()))
    }
    #[cfg(not(any(test, feature = "test-support")))]
    durable_namespace_checked(path)
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static TEST_REFUSAL: std::cell::Cell<Option<yadorilink_fs_platform::durable_dir::UnavailableReason>> =
        const { std::cell::Cell::new(None) };
}

/// Test seam: for this thread, `DurableNamespace::open` refuses every directory with `reason`
/// (a ReFS, exFAT or SMB volume, or a probe that could not run).
#[cfg(test)]
pub(crate) fn set_test_namespace_refusal(
    reason: Option<yadorilink_fs_platform::durable_dir::UnavailableReason>,
) {
    TEST_REFUSAL.with(|cell| cell.set(reason));
}

#[cfg(not(any(test, feature = "test-support")))]
fn durable_namespace_checked(path: &Path) -> Result<Option<DurableNamespace>, std::io::Error> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    DurableNamespace::open_unless_gate_closed(dir).map_err(std::io::Error::from)
}

/// A [`TempFileLedger`] as the [`NameLedger`] a durable operation records its
/// Stage and Discard names in.
pub(crate) struct LedgerNames<'a>(pub &'a dyn TempFileLedger);

impl NameLedger for LedgerNames<'_> {
    fn record(&self, path: &Path) -> std::io::Result<()> {
        self.0.record(path).map_err(|error| match error {
            StorageError::Io(error) => error,
            other => std::io::Error::other(other.to_string()),
        })
    }

    fn release(&self, path: &Path) {
        self.0.release(path);
    }
}

/// Single crate-wide boundary for removing a filesystem object. Block-store
/// segment retirement and materialization cleanup both pass through here so
/// audits see every physical removal at one capability seam.
pub(crate) fn remove_path(path: &Path) -> std::io::Result<()> {
    let removed = fs::remove_file(path);
    // A Windows directory symlink (a Stage temp made by `symlink_dir`) is removed as a directory.
    #[cfg(windows)]
    if removed.is_err()
        && fs::symlink_metadata(path)
            .is_ok_and(|m| std::os::windows::fs::FileTypeExt::is_symlink_dir(&m.file_type()))
    {
        return fs::remove_dir(path);
    }
    removed
}

/// What [`remove_empty_dir`] found at its path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmptyDirectoryRemoval {
    /// The directory was empty and is gone.
    Removed,
    /// Nothing was at the path.
    Absent,
    /// The directory still holds entries. Nothing was removed.
    NotEmpty,
    /// Something other than a directory is at the path (a symlink to a
    /// directory included). Nothing was removed.
    NotADirectory,
    /// The directory gained a child while it was being moved aside to be
    /// removed, and something else took its name before it could be put back.
    /// Nothing was deleted: the directory and its child stand under the reserved
    /// name at this path, and the user has to be told.
    Stranded(std::path::PathBuf),
}

/// Removes the directory at `path` only if it is empty: one non-recursive
/// removal. The only way this crate removes a directory. There is no
/// recursive counterpart on purpose: a directory's contents are removed
/// entry by entry by whoever knows each one (a replicated delete), and
/// anything left is something this device does not know about -- a
/// user's untracked file, an ignored `.git`, an OS's `.DS_Store` -- which
/// is never deleted on anyone's behalf.
pub fn remove_empty_dir(path: &Path) -> Result<EmptyDirectoryRemoval, StorageError> {
    remove_empty_dir_in(path, &crate::materialize_write::NoTempLedger)
}

/// [`remove_empty_dir`] with the Discard name a durable removal may need
/// recorded in `ledger` first.
pub fn remove_empty_dir_in(
    path: &Path,
    ledger: &dyn TempFileLedger,
) -> Result<EmptyDirectoryRemoval, StorageError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return Ok(EmptyDirectoryRemoval::NotADirectory),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(EmptyDirectoryRemoval::Absent)
        }
        Err(e) => return Err(e.into()),
    }
    if let Some(ns) = durable_namespace_beside(path)? {
        return durable_remove_empty_dir(&ns, path, ledger);
    }
    match fs::remove_dir(path) {
        Ok(()) => {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                if let Err(error) = sync_directory(parent) {
                    tracing::warn!(
                        path = %path.display(),
                        error = %error,
                        "directory was removed but its parent directory could not be synced"
                    );
                }
            }
            Ok(EmptyDirectoryRemoval::Removed)
        }
        Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
            Ok(EmptyDirectoryRemoval::NotEmpty)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(EmptyDirectoryRemoval::Absent),
        // Replaced by something that is not a directory since the check
        // above (`ENOTDIR`): not ours to remove.
        Err(e) if e.kind() == std::io::ErrorKind::NotADirectory => {
            Ok(EmptyDirectoryRemoval::NotADirectory)
        }
        Err(e) => Err(e.into()),
    }
}

/// A directory that gained a child while it was being removed and whose name
/// was taken meanwhile stays under its reserved name. Nothing is deleted; the
/// ledger is told so the user can be (an error log alone leaves no state to
/// report).
/// Whether the directory moved aside still holds an entry, or cannot be read
/// to tell (then it is not claimed to be gone).
pub(crate) fn holds_entries_or_unreadable(aside: &Path) -> bool {
    fs::read_dir(aside).map_or(true, |mut entries| entries.next().is_some())
}

pub(crate) fn stranded(
    path: &Path,
    aside: std::path::PathBuf,
    ledger: &dyn TempFileLedger,
) -> Result<EmptyDirectoryRemoval, StorageError> {
    tracing::error!(
        path = %path.display(),
        aside = %aside.display(),
        "a directory gained a child while it was being removed and something else now \
         stands at its name; it was not put back and nothing was deleted: it stays \
         under a reserved name beside it and needs the user's attention"
    );
    ledger.strand(&aside)?;
    Ok(EmptyDirectoryRemoval::Stranded(aside))
}

fn durable_remove_empty_dir(
    ns: &DurableNamespace,
    path: &Path,
    ledger: &dyn TempFileLedger,
) -> Result<EmptyDirectoryRemoval, StorageError> {
    use yadorilink_fs_platform::durable_dir::{DiscardOutcome, RetainReason};
    match ns.remove_empty_dir(path, &LedgerNames(ledger)) {
        Ok(DiscardOutcome::Removed) => Ok(EmptyDirectoryRemoval::Removed),
        // Moved aside, which is the removal; the record stays and the next start
        // finishes it. But a directory that gained a child and could not be put
        // back (for a reason other than its name being taken) is as stranded as
        // one whose name was: it still holds that child.
        Ok(DiscardOutcome::Retained { path: aside, reason: RetainReason::RemovalFailed }) => {
            if holds_entries_or_unreadable(&aside) {
                stranded(path, aside, ledger)
            } else {
                Ok(EmptyDirectoryRemoval::Removed)
            }
        }
        // A child appeared meanwhile: put back, untouched.
        Ok(DiscardOutcome::Restored) => Ok(EmptyDirectoryRemoval::NotEmpty),
        Ok(DiscardOutcome::Retained { path: aside, reason: RetainReason::OriginalOccupied }) => {
            stranded(path, aside, ledger)
        }
        // Gone, but the sync that makes it durable failed: the visible state has
        // changed and the caller advances its index state to match; a
        // resurrected empty directory costs nothing.
        Err(NsError::NotDurable(error)) => {
            tracing::warn!(
                path = %path.display(),
                error = %error,
                "directory was removed but its parent directory could not be synced"
            );
            Ok(EmptyDirectoryRemoval::Removed)
        }
        Err(NsError::NotEmpty) => Ok(EmptyDirectoryRemoval::NotEmpty),
        Err(NsError::NotFound) => Ok(EmptyDirectoryRemoval::Absent),
        Err(NsError::Io(e)) if e.kind() == std::io::ErrorKind::NotADirectory => {
            Ok(EmptyDirectoryRemoval::NotADirectory)
        }
        Err(error) => Err(StorageError::Io(error.into())),
    }
}

/// Single crate-wide boundary for atomically replacing a filesystem path.
/// Callers remain responsible for their operation-specific durability and
/// containment checks.
pub(crate) fn rename_path(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

/// Makes `path`'s own directory entries durable. A file that has been
/// written and fsynced is still unreachable after a crash until the
/// directory entry naming it has itself reached disk, so every path that
/// creates a file it will later claim to be durable owes one of these.
#[cfg(unix)]
pub(crate) fn sync_directory(path: &Path) -> Result<(), StorageError> {
    yadorilink_fs_platform::flush::sync_directory(&fs::File::open(path)?)?;
    Ok(())
}

// Windows documents no directory flush, and none is issued: what makes a
// Windows namespace change durable is the write-through move of `durable_dir`.
// The syncs that remain after an unlink are for the non-critical removals
// (a retired or orphan segment), whose resurrection the store already handles.
#[cfg(windows)]
pub(crate) fn sync_directory(_path: &Path) -> Result<(), StorageError> {
    Ok(())
}

/// Removes the file or link at `path` and returns once the removal is durable:
/// the caller records the path as absent next. A path that is already gone is
/// fine. `ledger` names the Discard name where the volume's durable shape needs
/// one (Windows); a volume without durable moves keeps a plain unlink followed
/// by a sync of the parent where the platform has one.
pub fn remove_durably(path: &Path, ledger: &dyn TempFileLedger) -> Result<(), StorageError> {
    if let Some(ns) = durable_namespace_beside(path)? {
        return match ns.remove_file(path, &LedgerNames(ledger)) {
            Ok(outcome) => outcome.removed().map_err(StorageError::Io),
            Err(NsError::NotFound) => Ok(()),
            Err(error) => Err(StorageError::Io(error.into())),
        };
    }
    match remove_path(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    match crate::materialize_write::sync_parent_dir(path) {
        // The directory is gone too: nothing is left in it to make durable.
        Err(StorageError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// Moves `from` to `to` without replacing anything at `to` (`AlreadyExists`
/// otherwise) and returns once the move is durable: a durable move where the
/// volume offers one, otherwise the no-replace rename followed by a sync of
/// `to`'s directory where the platform has one.
pub fn move_no_replace_durably(from: &Path, to: &Path) -> std::io::Result<()> {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(ns) = durable_namespace_beside(to)? {
        return ns
            .durable_move(from, to, yadorilink_fs_platform::durable_dir::Replace::No)
            .map_err(std::io::Error::from);
    }
    yadorilink_fs_platform::durable_dir::move_durably(
        from,
        to,
        yadorilink_fs_platform::durable_dir::Replace::No,
    )
}

/// Creates `path` and every missing ancestor, each as its own published
/// directory where the volume offers durable moves (the first ancestor that
/// exists is trusted as it is), otherwise with a plain `create_dir_all`.
pub(crate) fn create_dir_all_durably(path: &Path) -> Result<(), StorageError> {
    // A relative path has no existing ancestor among its own relative spellings (the current
    // directory is never one of them), which would silently turn this into a plain mkdir.
    let path = std::path::absolute(path)?;
    let existing = path.ancestors().find(|dir| dir.is_dir());
    let ns = match existing {
        Some(dir) => durable_namespace_beside(&dir.join("x"))?,
        None => None,
    };
    match ns {
        Some(ns) => ns
            .create_dir_all(&path, &yadorilink_fs_platform::durable_dir::NoLedger)
            .map_err(|error| StorageError::Io(error.into())),
        None => fs::create_dir_all(&path).map_err(StorageError::from),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::materialize_write::NoTempLedger;
    use yadorilink_fs_platform::durable_dir::before_next_remove_object;

    /// `Ok` is what the caller records as an absent path; a directory that took the file's place
    /// in the window must not be reported removed (Windows put-back answers `Ok(Restored)`).
    #[test]
    fn remove_durably_does_not_report_a_file_swapped_for_a_directory_removed() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("f");
        std::fs::write(&target, b"x").unwrap();
        let swapped = target.clone();
        before_next_remove_object(move || {
            std::fs::remove_file(&swapped).unwrap();
            std::fs::create_dir(&swapped).unwrap();
        });
        let result = remove_durably(&target, &NoTempLedger);
        assert!(target.is_dir());
        assert!(result.is_err(), "reported removed while an object occupies the path");
    }
}
