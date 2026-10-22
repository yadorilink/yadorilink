//! The platform primitives under [`super::DurableNamespace`]. Nothing outside
//! `durable_dir` may call these (the CI guard enforces it); the two measurement
//! entry points at the bottom are public only with the `evidence` feature.

use std::io;
use std::path::Path;

use super::Replace;

/// A name moved from `from` to `to`.
///
/// Windows: `MoveFileExW(MOVEFILE_WRITE_THROUGH [| MOVEFILE_REPLACE_EXISTING])`
/// and never `MOVEFILE_COPY_ALLOWED`, so a move across volumes fails instead of
/// turning into a copy and delete. Unix: `rename`, or the no-replace variant
/// (`renameat2(RENAME_NOREPLACE)` / `renamex_np(RENAME_EXCL)`), which fails
/// closed with `Unsupported` where the file system lacks it. The Unix move is
/// not durable by itself; [`super::DurableNamespace::durable_move`] adds the
/// parent directory syncs.
pub(super) fn move_entry(from: &Path, to: &Path, replace: Replace) -> io::Result<()> {
    #[cfg(windows)]
    {
        windows_move(from, to, replace)
    }
    #[cfg(unix)]
    {
        unix_move(from, to, replace)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (from, to, replace);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// The `MoveFileExW` flags of a move: write-through, replacing only when asked
/// to, and never `MOVEFILE_COPY_ALLOWED`, so a move across volumes fails
/// instead of becoming a copy and a delete.
#[cfg(any(windows, test))]
pub(crate) fn windows_move_flags(replace: Replace) -> u32 {
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    match replace {
        Replace::No => MOVEFILE_WRITE_THROUGH,
        Replace::Yes => MOVEFILE_WRITE_THROUGH | MOVEFILE_REPLACE_EXISTING,
    }
}

#[cfg(windows)]
fn windows_move(from: &Path, to: &Path, replace: Replace) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::MoveFileExW;
    let wide = |p: &Path| -> io::Result<Vec<u16>> {
        let wide: Vec<u16> = p.as_os_str().encode_wide().collect();
        if wide.contains(&0) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"));
        }
        Ok(wide.into_iter().chain(Some(0)).collect())
    };
    let (from, to) =
        (wide(&crate::long_path::for_win32(from))?, wide(&crate::long_path::for_win32(to))?);
    let flags = windows_move_flags(replace);
    // A replacing move onto a name that another handle has open (a concurrent reader, a virus
    // scanner, the search indexer) is refused with ACCESS_DENIED / SHARING_VIOLATION, even when
    // that handle shares DELETE; the refusal ends with the handle. Retry for a bounded time, then
    // fail closed with the last error. A no-replace move has no such target and is not retried.
    let mut delay = REPLACE_RETRY_FIRST_DELAY;
    for attempt in 0..=REPLACE_RETRY_LIMIT {
        // SAFETY: both buffers are NUL-terminated and outlive the call.
        if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), flags) } != 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        let busy = matches!(
            error.raw_os_error().map(|code| code as u32),
            Some(ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION)
        );
        if replace == Replace::No || !busy || attempt == REPLACE_RETRY_LIMIT {
            return Err(error);
        }
        std::thread::sleep(delay);
        delay = (delay * 2).min(REPLACE_RETRY_MAX_DELAY);
    }
    unreachable!("the last attempt returns")
}

#[cfg(windows)]
const ERROR_ACCESS_DENIED: u32 = 5;
#[cfg(windows)]
const ERROR_SHARING_VIOLATION: u32 = 32;
/// Retries of a refused replacing move: 1, 2, 4, ... 50 ms, about 0.4 seconds in all. The wait
/// blocks the calling thread like the write-through move itself does, so it stays short.
#[cfg(windows)]
const REPLACE_RETRY_LIMIT: u32 = 12;
#[cfg(windows)]
const REPLACE_RETRY_FIRST_DELAY: std::time::Duration = std::time::Duration::from_millis(1);
#[cfg(windows)]
const REPLACE_RETRY_MAX_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

#[cfg(unix)]
fn unix_move(from: &Path, to: &Path, replace: Replace) -> io::Result<()> {
    if replace == Replace::Yes {
        return std::fs::rename(from, to);
    }
    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    {
        use std::os::unix::ffi::OsStrExt;
        let c = |p: &Path| {
            std::ffi::CString::new(p.as_os_str().as_bytes())
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
        };
        let (c_from, c_to) = (c(from)?, c(to)?);
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
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EINVAL | libc::ENOSYS | libc::ENOTSUP) => {
                    return Err(io::Error::from(io::ErrorKind::Unsupported))
                }
                _ => return Err(error),
            }
        }
    }
    #[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
    {
        let _ = (from, to);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// An open directory whose entries [`DirHandle::sync`] makes durable. Unix
/// only: the directory sync is no part of the Windows contract.
#[cfg(unix)]
pub(super) struct DirHandle(std::fs::File);

#[cfg(unix)]
impl DirHandle {
    /// `O_DIRECTORY`: a link to a directory is followed.
    pub(super) fn open(dir: &Path) -> io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY).open(dir).map(Self)
    }

    pub(super) fn sync(&self) -> io::Result<()> {
        self.0.sync_all()
    }
}

/// Flushes the directory entries of `dir`; a link is refused rather than
/// followed. Not part of the correctness contract: kept so the evidence runs
/// can record what the platform does with it.
///
/// Unix: `fsync` of a directory descriptor. Windows: `FlushFileBuffers` on a
/// handle opened with `GENERIC_WRITE` and `FILE_FLAG_BACKUP_SEMANTICS`.
pub fn durable_flush_directory(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        DirHandle::open(dir)?.sync()
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Foundation::GENERIC_WRITE;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        if std::fs::symlink_metadata(dir)?.file_type().is_symlink() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "a link is not followed"));
        }
        let handle = std::fs::OpenOptions::new()
            .access_mode(GENERIC_WRITE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(dir)?;
        // BACKUP_SEMANTICS also opens a regular file; Unix refuses one.
        if !handle.metadata()?.is_dir() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a directory"));
        }
        handle.sync_all()
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = dir;
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// The write-through no-replace move on its own, for the evidence runs.
/// Windows only; elsewhere `Unsupported`.
pub fn rename_no_replace_durable(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        windows_move(from, to, Replace::No)
    }
    #[cfg(not(windows))]
    {
        let _ = (from, to);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}
