//! Handing a file to the engine for a provider write without a second full copy.
//!
//! The write path reads its bytes from a file in the fixed `ingest/` directory. A host process
//! that already has the file (a picked photo or video in its own temporary directory, a scan, a
//! file it exported) puts it there with [`stage_upload`] instead of copying it itself:
//!
//! * **Move**: the file is renamed into `ingest/`. Nothing is copied and nothing is written; the
//!   caller's path no longer exists. When the file cannot be moved (another volume, other hard
//!   links, another owner) the bytes are copied and the source is removed afterwards.
//! * **Clone**: a copy-on-write clone where the file system has one (APFS `clonefile`, a Linux
//!   reflink), else a copy. The source stays.
//! * **Copy**: the bytes are streamed into a private partial name and renamed when complete. The
//!   free space for the copy is checked BEFORE the first byte is read.
//!
//! Whichever way it got there, the staged file is flushed (the file, then the directory) before
//! this returns, so a caller that deletes its own source on success never loses the only copy,
//! and its SHA-256 and size are returned for the write request that names it. The ingest read
//! (`provider_ingest`) still verifies size and digest; nothing here is trusted by it.
//!
//! A staged file is removed by [`discard_staged`] when the caller abandons the write, by the
//! write itself once it commits, and by the ingest sweep when nobody claims it.

use std::path::{Path, PathBuf};

use crate::provider_ingest::IngestError;

/// How the file reaches `ingest/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageMode {
    /// Rename; a copy plus removing the source only where a rename cannot work.
    Move,
    /// A copy-on-write clone where there is one, else a copy. The source stays.
    Clone,
    /// A streamed copy. The source stays.
    Copy,
}

/// What is handed over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageSource {
    /// A file by path. It must be a regular file, not reached through a final symlink.
    Path(PathBuf),
    /// An open descriptor of a regular file. The engine duplicates it and never closes the
    /// caller's: the caller always keeps ownership. A descriptor cannot be moved, so
    /// [`StageMode::Move`] clones or copies it and leaves the file where it is.
    Descriptor(i32),
}

/// How the staged file was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagedHow {
    /// Renamed: no bytes were copied and the source is gone.
    Moved,
    /// Cloned: no bytes were copied (they are shared until one side changes).
    Cloned,
    /// Copied.
    Copied,
}

/// A file staged in `ingest/`, ready to be named by a write request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedUpload {
    /// The name in `ingest/`, for `ProviderContentSource.ingest_name`.
    pub ingest_name: String,
    pub size: u64,
    /// SHA-256 of the whole file.
    pub sha256: [u8; 32],
    pub how: StagedHow,
}

/// Whether `name` could have been issued by [`new_name`]: the only names [`discard_staged`] removes.
pub(crate) fn is_staged_name(name: &str) -> bool {
    name.starts_with("up-") && crate::provider_ingest::valid_ingest_name(name)
}

/// Removes a staged file that no write will use. Missing is fine (idempotent). Only a name this
/// module issued is accepted, so the call cannot be used to remove anything else in `ingest/`.
pub(crate) fn discard_staged(ingest_dir: &Path, name: &str) -> Result<(), IngestError> {
    if !is_staged_name(name) {
        return Err(IngestError::Rejected("not the name of a staged upload".into()));
    }
    match std::fs::remove_file(ingest_dir.join(name)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(IngestError::Store(e.to_string())),
    }
}

#[cfg(unix)]
pub(crate) use unix::stage_upload;

#[cfg(not(unix))]
pub(crate) fn stage_upload(
    _ingest_dir: &Path,
    _name: &str,
    _source: &StageSource,
    _mode: StageMode,
    _reserve: &dyn Fn(u64) -> Result<(), IngestError>,
) -> Result<StagedUpload, IngestError> {
    Err(IngestError::Rejected("staging an upload needs a Unix host".into()))
}

#[cfg(unix)]
mod unix {
    use std::ffi::CString;
    use std::fs::File;
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
    use std::path::Path;

    use sha2::{Digest, Sha256};

    use super::{StageMode, StageSource, StagedHow, StagedUpload};
    use crate::provider_ingest::IngestError;

    const BUFFER: usize = 1 << 20;

    fn io_error(error: &std::io::Error) -> IngestError {
        if error.raw_os_error() == Some(libc::ENOSPC) {
            IngestError::LowDisk(error.to_string())
        } else {
            IngestError::Store(error.to_string())
        }
    }

    /// The caller's file, opened once: every later step uses this descriptor, so the file that
    /// is staged is the file that was checked.
    fn open_source(source: &StageSource) -> Result<File, IngestError> {
        match source {
            StageSource::Path(path) => {
                let c_path = CString::new(path.as_os_str().as_encoded_bytes())
                    .map_err(|_| IngestError::Rejected("the path has a NUL".into()))?;
                // SAFETY: `c_path` is a valid NUL-terminated string.
                let fd = unsafe {
                    libc::open(
                        c_path.as_ptr(),
                        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    let error = std::io::Error::last_os_error();
                    return Err(if error.kind() == std::io::ErrorKind::NotFound {
                        IngestError::Unstable("the file to upload is missing".into())
                    } else {
                        IngestError::Rejected(format!(
                            "the file to upload cannot be opened: {error}"
                        ))
                    });
                }
                // SAFETY: `fd` was just returned by a successful `open` and is owned by nobody else.
                Ok(unsafe { File::from_raw_fd(fd) })
            }
            StageSource::Descriptor(fd) => {
                // SAFETY: `F_DUPFD_CLOEXEC` on any integer is memory safe; a bad one fails with EBADF.
                let duplicate = unsafe { libc::fcntl(*fd, libc::F_DUPFD_CLOEXEC, 0) };
                if duplicate < 0 {
                    return Err(IngestError::Rejected(format!(
                        "the descriptor cannot be used: {}",
                        std::io::Error::last_os_error()
                    )));
                }
                // SAFETY: `duplicate` is a fresh descriptor this call owns.
                Ok(unsafe { File::from_raw_fd(duplicate) })
            }
        }
    }

    /// SHA-256 and length of the whole file, read through `file` without moving its cursor.
    fn digest(file: &File) -> std::io::Result<([u8; 32], u64)> {
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; BUFFER];
        let mut offset = 0u64;
        loop {
            match file.read_at(&mut buffer, offset) {
                Ok(0) => break,
                Ok(n) => {
                    hasher.update(&buffer[..n]);
                    offset += n as u64;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok((hasher.finalize().into(), offset))
    }

    fn sync_directory(dir: &Path) -> Result<(), IngestError> {
        let directory = File::open(dir).map_err(|e| io_error(&e))?;
        yadorilink_fs_platform::flush::sync_directory(&directory).map_err(|e| io_error(&e))
    }

    #[cfg(target_vendor = "apple")]
    fn clone_into(source: &File, dir: &File, name: &str) -> std::io::Result<()> {
        let c_name = CString::new(name)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in name"))?;
        // SAFETY: both descriptors are open for the call and `c_name` is NUL terminated.
        let result =
            unsafe { libc::fclonefileat(source.as_raw_fd(), dir.as_raw_fd(), c_name.as_ptr(), 0) };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    #[cfg(target_os = "linux")]
    fn clone_into(source: &File, dir: &File, name: &str) -> std::io::Result<()> {
        let c_name = CString::new(name)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in name"))?;
        // SAFETY: `dir` is an open directory descriptor and `c_name` is NUL terminated.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` was just returned by a successful `openat` and is owned by nobody else.
        let destination = unsafe { File::from_raw_fd(fd) };
        // SAFETY: both descriptors are open for the call.
        let result =
            unsafe { libc::ioctl(destination.as_raw_fd(), libc::FICLONE, source.as_raw_fd()) };
        if result == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        drop(destination);
        // SAFETY: as above; removes only the name just created.
        unsafe { libc::unlinkat(dir.as_raw_fd(), c_name.as_ptr(), 0) };
        Err(error)
    }

    #[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
    fn clone_into(_source: &File, _dir: &File, _name: &str) -> std::io::Result<()> {
        Err(std::io::Error::from_raw_os_error(libc::ENOTSUP))
    }

    /// Streams `source` into a private partial name and renames it to `name` once it is complete
    /// and flushed. The digest is computed over the bytes written.
    fn copy_into(
        source: &File,
        size: u64,
        ingest_dir: &Path,
        name: &str,
        reserve: &dyn Fn(u64) -> Result<(), IngestError>,
    ) -> Result<([u8; 32], u64), IngestError> {
        // Before the first byte is read: a copy that cannot fit is refused now.
        reserve(size)?;
        let partial = ingest_dir.join(format!(".{name}.part"));
        let result = (|| {
            let mut destination = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC)
                .open(&partial)
                .map_err(|e| io_error(&e))?;
            let mut hasher = Sha256::new();
            let mut buffer = vec![0u8; BUFFER];
            let mut offset = 0u64;
            loop {
                match source.read_at(&mut buffer, offset) {
                    Ok(0) => break,
                    Ok(n) => {
                        hasher.update(&buffer[..n]);
                        destination.write_all(&buffer[..n]).map_err(|e| io_error(&e))?;
                        offset += n as u64;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(IngestError::Unstable(e.to_string())),
                }
            }
            yadorilink_fs_platform::flush::sync_file(&destination).map_err(|e| io_error(&e))?;
            drop(destination);
            std::fs::rename(&partial, ingest_dir.join(name)).map_err(|e| io_error(&e))?;
            Ok((hasher.finalize().into(), offset))
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&partial);
        }
        result
    }

    pub(crate) fn stage_upload(
        ingest_dir: &Path,
        name: &str,
        source: &StageSource,
        mode: StageMode,
        reserve: &dyn Fn(u64) -> Result<(), IngestError>,
    ) -> Result<StagedUpload, IngestError> {
        if !super::is_staged_name(name) {
            return Err(IngestError::Rejected("not a name for a staged upload".into()));
        }
        let file = open_source(source)?;
        let before = file.metadata().map_err(|e| io_error(&e))?;
        if !before.is_file() {
            return Err(IngestError::Rejected("the file to upload is not a regular file".into()));
        }
        let destination = ingest_dir.join(name);
        // SAFETY: `geteuid` has no preconditions.
        let me = unsafe { libc::geteuid() };

        let mut how = None;
        // A rename keeps the owner and the links, and the ingest read refuses a file that is not
        // ours or has other links: those are copied instead.
        if let (StageMode::Move, StageSource::Path(path)) = (mode, source) {
            if before.nlink() == 1 && before.uid() == me {
                match std::fs::rename(path, &destination) {
                    Ok(()) => {
                        // What was renamed must be what was opened and checked.
                        let moved = std::fs::symlink_metadata(&destination);
                        if moved.is_ok_and(|m| (m.dev(), m.ino()) == (before.dev(), before.ino())) {
                            how = Some(StagedHow::Moved);
                        } else {
                            let _ = std::fs::remove_file(&destination);
                            return Err(IngestError::Unstable(
                                "the file to upload was replaced while it was moved".into(),
                            ));
                        }
                    }
                    // Another volume: fall through to the copy.
                    Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {}
                    Err(e) => return Err(io_error(&e)),
                }
            }
        }
        if how.is_none() && matches!(mode, StageMode::Move | StageMode::Clone) {
            let directory = File::open(ingest_dir).map_err(|e| io_error(&e))?;
            if clone_into(&file, &directory, name).is_ok() {
                how = Some(StagedHow::Cloned);
            }
        }

        // Undoes the staging: a moved file goes back to where it was, anything else is removed.
        let rollback = |how: StagedHow| match (how, source) {
            (StagedHow::Moved, StageSource::Path(path)) => {
                let _ = std::fs::rename(&destination, path);
            }
            _ => {
                let _ = std::fs::remove_file(&destination);
            }
        };
        let (sha256, size, how) = match how {
            Some(how) => {
                // The bytes were not written by this call: read them once for the digest.
                match digest(&file) {
                    Ok((sha256, size)) => (sha256, size, how),
                    Err(e) => {
                        rollback(how);
                        return Err(io_error(&e));
                    }
                }
            }
            None => {
                let (sha256, size) = copy_into(&file, before.len(), ingest_dir, name, reserve)?;
                (sha256, size, StagedHow::Copied)
            }
        };
        let after = file.metadata().map_err(|e| io_error(&e))?;
        if size != before.len()
            || (after.len(), after.mtime(), after.mtime_nsec())
                != (before.len(), before.mtime(), before.mtime_nsec())
        {
            rollback(how);
            return Err(IngestError::Unstable(
                "the file to upload changed while it was staged".into(),
            ));
        }
        // Durable before this returns: a caller that removes its own copy relies on it.
        let staged = File::open(&destination).map_err(|e| io_error(&e))?;
        yadorilink_fs_platform::flush::sync_file(&staged).map_err(|e| io_error(&e))?;
        sync_directory(ingest_dir)?;
        // A move ends with the source gone, however the staged file came to be.
        if let (StageMode::Move, StageSource::Path(path)) = (mode, source) {
            if how != StagedHow::Moved {
                let _ = std::fs::remove_file(path);
            }
        }
        Ok(StagedUpload { ingest_name: name.to_owned(), size, sha256, how })
    }
}

#[cfg(test)]
mod tests;
