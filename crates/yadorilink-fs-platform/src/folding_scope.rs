//! The scope inside which what a directory folds (case, Unicode normalization)
//! cannot have changed.
//!
//! What a volume folds is learned by a real probe (see
//! `yadorilink_peer_session::hazard::probed_folding`), which costs several
//! directory-lock round trips in the kernel. The answer is a property of the
//! directory it was taken on, so it may be reused for as long as the directory
//! is observably the same one on the same mounted filesystem with the same
//! folding switches. [`FoldingScope::of`] names exactly that, in a handful of
//! cheap calls, and is `None` whenever it cannot name it with certainty: such a
//! directory is probed afresh every time, which is the fail-closed default.
//!
//! What the scope covers:
//!
//! * Linux: the unique mount id of the mount the directory is on (never reused
//!   within a boot, so another filesystem, a bind mount or a remount at the same
//!   path is another scope), the directory's own inode (a replaced directory is
//!   another scope) and its per-directory case-fold flag (`FS_CASEFOLD_FL`,
//!   which ext4 and f2fs can switch on an empty directory). A filesystem
//!   without inode flags (FUSE, network mounts) and a kernel without a unique
//!   mount id (before 6.8) have no scope.
//! * macOS: the volume UUID, the device number and the directory's inode. A
//!   volume without a UUID has no scope.
//! * Everywhere else (Windows, whose folding is per directory and can be
//!   switched by `fsutil`): no scope.

use std::io;
use std::path::Path;

/// Opaque; two observations of the same directory in the same folding state are
/// equal, and an observation that differs may fold differently.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FoldingScope(String);

impl FoldingScope {
    /// The scope of `dir`, or `None` when it cannot be named with certainty.
    pub fn of(dir: &Path) -> Option<Self> {
        observe(dir).ok().flatten().map(Self)
    }

    /// A scope from its parts, for callers that name scopes themselves (tests).
    pub fn from_parts(parts: &str) -> Self {
        Self(parts.to_owned())
    }
}

#[cfg(target_os = "linux")]
fn observe(dir: &Path) -> io::Result<Option<String>> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    const STATX_MNT_ID_UNIQUE: u32 = 0x4000;
    const FS_CASEFOLD_FL: libc::c_long = 0x4000_0000;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(dir)?;
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    // SAFETY: the fd is open, the path is the empty string `AT_EMPTY_PATH`
    // asks for, and `stx` is a valid out-pointer.
    let rc = unsafe {
        libc::statx(
            file.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            STATX_MNT_ID_UNIQUE | libc::STATX_INO,
            &mut stx,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if stx.stx_mask & STATX_MNT_ID_UNIQUE == 0 || stx.stx_mask & libc::STATX_INO == 0 {
        return Ok(None);
    }
    let mut flags: libc::c_long = 0;
    // SAFETY: `flags` is the `long` FS_IOC_GETFLAGS fills in.
    let rc = unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_GETFLAGS as _, &mut flags) };
    if rc != 0 {
        let error = io::Error::last_os_error();
        // A filesystem without inode flags (FUSE, network mounts) says nothing
        // about whether its folding can change: no scope, so it is probed afresh.
        return match error.raw_os_error() {
            Some(libc::ENOTTY | libc::EOPNOTSUPP | libc::ENOSYS | libc::EINVAL) => Ok(None),
            _ => Err(error),
        };
    }
    Ok(Some(format!(
        "linux:{}:{}:{}:{}:{}:{}",
        stx.stx_dev_major,
        stx.stx_dev_minor,
        stx.stx_mnt_id,
        stx.stx_ino,
        flags & FS_CASEFOLD_FL != 0,
        flags
    )))
}

#[cfg(target_vendor = "apple")]
fn observe(dir: &Path) -> io::Result<Option<String>> {
    use std::os::unix::fs::MetadataExt;

    use crate::volume_identity::StableVolumeId;

    let meta = std::fs::metadata(dir)?;
    if !meta.is_dir() {
        return Ok(None);
    }
    let StableVolumeId::Uuid(uuid) = StableVolumeId::observe(dir)? else {
        return Ok(None);
    };
    Ok(Some(format!("apple:{uuid}:{}:{}", meta.dev(), meta.ino())))
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn observe(_: &Path) -> io::Result<Option<String>> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    #[test]
    fn a_directory_is_in_the_same_scope_every_time_and_another_directory_is_not() {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let Some(scope) = FoldingScope::of(a.path()) else {
            return; // a kernel or volume that names no scope
        };
        assert_eq!(FoldingScope::of(a.path()), Some(scope.clone()));
        assert_ne!(FoldingScope::of(b.path()), Some(scope));
    }

    #[test]
    fn a_directory_that_cannot_be_observed_has_no_scope() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(FoldingScope::of(&dir.path().join("missing")), None);
        let file = dir.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        assert_eq!(FoldingScope::of(&file), None);
    }
}
