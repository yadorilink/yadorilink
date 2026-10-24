//! The one place a file or directory flush is issued.
//!
//! Every `fsync`, `F_FULLFSYNC` and `FlushFileBuffers` of the product goes
//! through here, so the counters see every flush, including the directory syncs
//! made inside a durable move. `.github/checks/check-flush-choke-point.py`
//! fails on a flush call anywhere else.
//!
//! The counters are compiled out without `test-support`; operation-count tests
//! read them as a delta around the work they measure.

use std::fs::File;
use std::io;

/// What a flush makes durable: the data of a file, or the entries of a directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    File,
    Directory,
}

/// Flushes issued so far in this process.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlushCounts {
    pub file_flushes: u64,
    pub directory_syncs: u64,
}

#[cfg(any(test, feature = "test-support"))]
static FILE_FLUSHES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(any(test, feature = "test-support"))]
static DIRECTORY_SYNCS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The counters now. Subtract an earlier reading to measure a stretch of work.
#[cfg(any(test, feature = "test-support"))]
pub fn counts() -> FlushCounts {
    use std::sync::atomic::Ordering::Relaxed;
    FlushCounts {
        file_flushes: FILE_FLUSHES.load(Relaxed),
        directory_syncs: DIRECTORY_SYNCS.load(Relaxed),
    }
}

fn count(target: Target) {
    #[cfg(any(test, feature = "test-support"))]
    match target {
        Target::File => &FILE_FLUSHES,
        Target::Directory => &DIRECTORY_SYNCS,
    }
    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    #[cfg(not(any(test, feature = "test-support")))]
    let _ = target;
}

/// The strongest flush the platform offers for `file` (`F_FULLFSYNC` on macOS,
/// `fsync` elsewhere, `FlushFileBuffers` on Windows): `sync_all`.
pub fn sync(file: &File, target: Target) -> io::Result<()> {
    count(target);
    file.sync_all()
}

/// [`sync`] of a file.
pub fn sync_file(file: &File) -> io::Result<()> {
    sync(file, Target::File)
}

/// Opens the existing regular file at `path` so that [`sync_file`] can flush it, without
/// changing it. Windows' `FlushFileBuffers` needs write access to the handle, so a plain
/// read-only `File::open` there fails every flush with "access denied" even though nothing is
/// wrong with the file; elsewhere a read-only descriptor flushes. A file that cannot be opened
/// for writing (read-only attribute, another handle that denies write sharing) is an `Err`:
/// callers treat that as "not confirmed durable".
pub fn open_for_flush(path: &std::path::Path) -> io::Result<File> {
    #[cfg(windows)]
    {
        std::fs::OpenOptions::new().read(true).write(true).open(path)
    }
    #[cfg(not(windows))]
    {
        File::open(path)
    }
}

/// [`sync`] of an open directory.
pub fn sync_directory(dir: &File) -> io::Result<()> {
    sync(dir, Target::Directory)
}

/// Plain `fsync(2)`, which on macOS does not flush the drive's write cache.
/// Only for a caller that follows it with its own full flush.
#[cfg(unix)]
pub fn fsync_plain(file: &File, target: Target) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    count(target);
    // SAFETY: the descriptor is open for the duration of the call.
    if unsafe { libc::fsync(file.as_raw_fd()) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `F_FULLFSYNC`, reporting the raw `fcntl` error (the capability probes
/// classify it).
#[cfg(target_vendor = "apple")]
pub fn full_fsync(file: &File, target: Target) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    count(target);
    loop {
        // SAFETY: the descriptor is open for the duration of the call.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error);
        }
    }
}

/// `fdatasync(2)` of a file where the platform has it, else [`sync_file`]:
/// the data and the metadata needed to read it back, not every timestamp.
pub fn sync_data(file: &File) -> io::Result<()> {
    count(Target::File);
    file.sync_data()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An existing file can be flushed through the handle `open_for_flush` gives, on every
    /// platform. On Windows a read-only `File::open` handle cannot (`FlushFileBuffers` needs
    /// write access), which is the failure this helper exists to avoid.
    #[test]
    fn an_existing_file_flushes_through_open_for_flush() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("existing");
        std::fs::write(&path, b"bytes").unwrap();
        let file = open_for_flush(&path).unwrap();
        sync_file(&file).expect("the flush of an existing file succeeds");
        assert_eq!(std::fs::read(&path).unwrap(), b"bytes", "opening for flush changes nothing");
    }

    #[cfg(windows)]
    #[test]
    fn a_plain_read_only_handle_cannot_flush_on_windows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("existing");
        std::fs::write(&path, b"bytes").unwrap();
        let error = sync_file(&File::open(&path).unwrap()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
    }

    #[test]
    fn a_missing_file_is_an_error_not_a_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        assert!(open_for_flush(&dir.path().join("absent")).is_err());
    }
}
