//! Proof that no program holds a file open for writing.
//!
//! A program that opened a file before it was renamed keeps writing the same object through
//! its handle, and no check by name or by content can fence it: a write can land after any
//! check and before an unlink. The only safe unlink of such an object is one taken while the
//! operating system itself guarantees no writer exists. Where it offers no such guarantee the
//! object must be kept, not unlinked.
//!
//! The object must be one nothing can newly open: a private name inside the root that no
//! program uses, with no other hard link. Then the writers are exactly those that already hold
//! it, and the set can only shrink.
//!
//! - Linux: a write lease (`F_SETLEASE`, `F_WRLCK`) is granted only if no other open file
//!   description exists for the file, and keeps anything from opening it while held. It needs
//!   a local filesystem that supports leases and a file the process owns; otherwise it is
//!   refused and no exclusion is claimed.
//! - Windows: a handle opened without `FILE_SHARE_WRITE` fails while another handle has write
//!   access, and refuses later write opens. A handle that was opened sharing delete is needed
//!   for the unlink that follows.
//! - Other platforms (macOS has no such primitive): no exclusion is claimed.

use std::fs::File;
use std::io;
use std::path::Path;

/// An open file and whether the operating system guarantees no other handle can write to it
/// for as long as this value lives.
#[derive(Debug)]
pub struct WriteExclusion {
    pub file: File,
    pub excludes_writers: bool,
    /// Whether the exclusion is a Linux lease that can be broken.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    lease: bool,
}

impl WriteExclusion {
    /// A stand-in for a platform that grants the exclusion, for tests of the callers.
    pub fn assumed(file: File) -> Self {
        Self { file, excludes_writers: true, lease: false }
    }

    /// Whether the exclusion is still in force. A Linux lease can be broken (a program opened the
    /// object, and the holder did not give the lease up in time); a Windows share mode cannot.
    pub fn still_excludes_writers(&self) -> io::Result<bool> {
        if !self.excludes_writers {
            return Ok(false);
        }
        #[cfg(target_os = "linux")]
        if self.lease {
            use std::os::fd::AsRawFd;
            // SAFETY: `fcntl` on a descriptor `self.file` owns, with no argument.
            let kind = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GETLEASE) };
            if kind < 0 {
                return Err(io::Error::last_os_error());
            }
            return Ok(kind == libc::F_WRLCK);
        }
        Ok(true)
    }
}

/// Opens the regular file at `path` for reading, claiming exclusion where the platform can
/// prove it. A refusal of the exclusion is not an error: the file is returned with
/// `excludes_writers == false`.
pub fn open_excluding_writers(path: &Path) -> io::Result<WriteExclusion> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_SHARE_READ | FILE_SHARE_DELETE: no FILE_SHARE_WRITE.
        match std::fs::OpenOptions::new().read(true).share_mode(1 | 4).open(path) {
            Ok(file) => return Ok(WriteExclusion { file, excludes_writers: true, lease: false }),
            // ERROR_SHARING_VIOLATION: another handle has write access.
            Err(e) if e.raw_os_error() == Some(32) => {}
            Err(e) => return Err(e),
        }
        Ok(WriteExclusion { file: File::open(path)?, excludes_writers: false, lease: false })
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let excludes_writers = lease_if_sole_name(&file)?;
        Ok(WriteExclusion { file, excludes_writers, lease: excludes_writers })
    }
    #[cfg(not(any(unix, windows)))]
    {
        Ok(WriteExclusion { file: File::open(path)?, excludes_writers: false, lease: false })
    }
}

#[cfg(target_os = "linux")]
fn lease_if_sole_name(file: &File) -> io::Result<bool> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    // A second name for the object could be opened by a program while the lease is held,
    // which would signal this process: no lease is taken then.
    if file.metadata()?.nlink() != 1 {
        return Ok(false);
    }
    ignore_lease_break_signal();
    // SAFETY: `fcntl` on a descriptor `file` owns, with an integer argument only.
    let granted = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLEASE, libc::F_WRLCK) } == 0;
    Ok(granted && file.metadata()?.nlink() == 1)
}

/// A lease break signals the holder with `SIGIO`, whose default action ends the process. A
/// program opening the object (it is held for the length of one read of the file) must not be
/// able to do that: the signal is ignored unless the process already handles it. The opener
/// simply waits for the lease to go, and [`WriteExclusion::still_excludes_writers`] reports the
/// break.
#[cfg(target_os = "linux")]
fn ignore_lease_break_signal() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: querying the current disposition (null new action), then installing
        // `SIG_IGN` only if it is the default; both calls take pointers to local structs.
        unsafe {
            let mut current: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(libc::SIGIO, std::ptr::null(), &mut current) == 0
                && current.sa_sigaction == libc::SIG_DFL
            {
                libc::signal(libc::SIGIO, libc::SIG_IGN);
            }
        }
    });
}

#[cfg(all(unix, not(target_os = "linux")))]
fn lease_if_sole_name(_file: &File) -> io::Result<bool> {
    Ok(false)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn a_file_with_another_writer_is_never_claimed_exclusive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"x").unwrap();
        let _writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        assert!(!open_excluding_writers(&path).unwrap().excludes_writers);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_file_nobody_else_holds_is_claimed_exclusive_on_linux() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"x").unwrap();
        assert!(open_excluding_writers(&path).unwrap().excludes_writers);
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn a_writer_blocks_the_exclusion_and_its_absence_grants_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"x").unwrap();
        {
            let _writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            assert!(!open_excluding_writers(&path).unwrap().excludes_writers);
        }
        let held = open_excluding_writers(&path).unwrap();
        assert!(held.excludes_writers);
        // Nobody can open it for writing while it is held.
        assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());
    }
}
