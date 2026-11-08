//! The platform primitives under [`super::DurableNamespace`]. Nothing outside
//! `durable_dir` may call these (the CI guard enforces it); the two measurement
//! entry points at the bottom are public only with the `evidence` feature.

use std::io;
use std::path::Path;

use super::Replace;

/// A name moved from `from` to `to`.
///
/// Windows: a rename on a handle held open on `from` (see [`windows_move`]), followed by a
/// flush of the parent directories; it never copies, so a move across volumes fails. Unix:
/// `rename`, or the no-replace variant (`renameat2(RENAME_NOREPLACE)` /
/// `renamex_np(RENAME_EXCL)`), which fails closed with `Unsupported` where the file system
/// lacks it. The Unix move is not durable by itself; [`super::DurableNamespace::durable_move`]
/// adds the parent directory syncs.
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

/// The error of a move that DID happen and whose parent-directory flush then failed. The entry
/// stands under its new name; a caller that undoes a move on failure must not treat this as
/// "nothing moved" (see [`moved_but_not_flushed`]).
#[cfg(any(windows, test))]
#[derive(Debug)]
pub(crate) struct MovedButNotFlushed(pub(crate) io::Error);

#[cfg(any(windows, test))]
impl std::fmt::Display for MovedButNotFlushed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the entry was moved but the directory flush failed: {}", self.0)
    }
}

#[cfg(any(windows, test))]
impl std::error::Error for MovedButNotFlushed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Whether `error` says the move happened and only the flush failed.
#[cfg(any(windows, test))]
pub(crate) fn moved_but_not_flushed(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|inner| inner.is::<MovedButNotFlushed>())
}

/// The `FileRenameInfoEx` flags of a move: POSIX semantics always (a target another handle has
/// open is replaced instead of refused), replacing only when asked to. A replacing move also
/// ignores the read-only mark of the target, which the replace-then-restore of the caller
/// otherwise cannot clear on a reparse point.
#[cfg(any(windows, test))]
pub(crate) fn windows_rename_flags(replace: Replace) -> u32 {
    const FILE_RENAME_FLAG_REPLACE_IF_EXISTS: u32 = 0x1;
    const FILE_RENAME_FLAG_POSIX_SEMANTICS: u32 = 0x2;
    const FILE_RENAME_FLAG_IGNORE_READONLY_ATTRIBUTE: u32 = 0x40;
    match replace {
        Replace::No => FILE_RENAME_FLAG_POSIX_SEMANTICS,
        Replace::Yes => {
            FILE_RENAME_FLAG_POSIX_SEMANTICS
                | FILE_RENAME_FLAG_REPLACE_IF_EXISTS
                | FILE_RENAME_FLAG_IGNORE_READONLY_ATTRIBUTE
        }
    }
}

/// The move on Windows. `from` is opened once, with a share mode that denies delete and rename
/// to everyone else, and the rename is made ON that handle: the name cannot be swapped (a
/// junction, another file) between the open and the rename, and the staged file's attributes
/// and ACL are carried over while it is held. The target is named by full path: the API
/// refuses a parent-directory handle (error 87), so `to`'s parent stays a path lookup.
///
/// A rename on a handle has no write-through flag, so both parent directories are flushed
/// afterwards (opened with `GENERIC_WRITE` and backup semantics, which a directory flush
/// needs, and opened BEFORE the rename so an unopenable directory fails while nothing has moved);
/// a failed flush is a failed move, as on Unix. The flushed directories are the ones the paths led
/// to when they were opened: an ancestor swapped between that and the rename is not detected.
#[cfg(windows)]
fn windows_move(from: &Path, to: &Path, replace: Replace) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FileRenameInfoEx, SetFileInformationByHandle, DELETE,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_RENAME_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA,
        OPEN_EXISTING, SYNCHRONIZE,
    };
    let wide_of = |p: &Path| -> io::Result<Vec<u16>> {
        let wide: Vec<u16> = p.as_os_str().encode_wide().collect();
        if wide.contains(&0) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"));
        }
        Ok(wide)
    };
    let wide = |p: &Path| wide_of(&crate::long_path::for_win32(p));
    let open = |path: &[u16], access: u32, share: u32, flags: u32| -> io::Result<OwnedHandle> {
        let nul: Vec<u16> = path.iter().copied().chain(Some(0)).collect();
        // SAFETY: `nul` is NUL-terminated and outlives the call; no security attributes or template.
        let handle = unsafe {
            CreateFileW(
                nul.as_ptr(),
                access,
                share,
                std::ptr::null(),
                OPEN_EXISTING,
                flags,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a valid handle we own.
        Ok(unsafe { OwnedHandle::from_raw_handle(handle as _) })
    };
    // A relative path (a bare file name lives in the current directory) is made absolute first:
    // the rename names its target by full path, and a bare name has no parent to open.
    let (from, to) = (std::path::absolute(from)?, std::path::absolute(to)?);
    let (from_w, to_w) = (wide(&from)?, wide(&to)?);
    // The parent directories are opened (for the flush after the rename) before anything moves: a
    // directory this process may not open for writing fails the move while nothing has changed.
    let parent_paths = {
        let mut parents = vec![
            crate::long_path::for_win32(&from).parent().map(Path::to_path_buf),
            crate::long_path::for_win32(&to).parent().map(Path::to_path_buf),
        ];
        parents.dedup();
        parents
    };
    let mut parent_dirs: Vec<std::fs::File> = Vec::new();
    for parent in parent_paths.into_iter().flatten() {
        parent_dirs.push(std::fs::File::from(open(
            &wide_of(&parent)?,
            // What a flush needs, and nothing more: GENERIC_WRITE also asks for attribute and
            // extended-attribute writes, which a volume root refuses.
            FILE_WRITE_DATA | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_BACKUP_SEMANTICS,
        )?));
    }
    // No share-delete: while this handle lives nobody can rename or delete the name. A reparse
    // point is opened as the link itself (moved, never followed). Another handle on the staged
    // file that does not share delete (a virus scanner reading it) refuses the open for as long as
    // it lives: retried for a bounded time, then the last error.
    let mut delay = REPLACE_RETRY_FIRST_DELAY;
    let mut attempt = 0;
    let held = loop {
        match open(
            &from_w,
            DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
        ) {
            Ok(held) => break held,
            Err(error)
                if attempt < REPLACE_RETRY_LIMIT
                    && matches!(
                        error.raw_os_error().map(|code| code as u32),
                        Some(ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION)
                    ) =>
            {
                attempt += 1;
                std::thread::sleep(delay);
                delay = (delay * 2).min(REPLACE_RETRY_MAX_DELAY);
            }
            Err(error) => return Err(error),
        }
    };
    // What the replaced file's owner set on it travels to the staged file first (see `windows_keep`).
    let (from_nul, to_nul): (Vec<u16>, Vec<u16>) = (
        from_w.iter().copied().chain(Some(0)).collect(),
        to_w.iter().copied().chain(Some(0)).collect(),
    );
    let kept = if replace == Replace::Yes {
        super::windows_keep::Kept::prepare(&from_nul, &to_nul)?
    } else {
        None
    };
    // FILE_RENAME_INFO: flags, RootDirectory (null), FileNameLength, FileName. The name is
    // followed by a NUL, which `FileNameLength` does not count: Windows converts the name to its
    // NT form from the NUL-terminated string, so a name that runs to the end of the buffer was
    // read on into whatever followed it (the file was published under a name with garbage
    // characters after it, or refused as an invalid name, depending on that memory). The offsets
    // are the structure's own, and the buffer is built in 8-byte units so it is aligned for it.
    let name_offset = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let length_offset = std::mem::offset_of!(FILE_RENAME_INFO, FileNameLength);
    let bytes = (name_offset + (to_w.len() + 1) * 2).next_multiple_of(8);
    let mut info = vec![0u64; bytes / 8];
    {
        // SAFETY: `info` is `bytes` long (a whole number of u64s) and is not otherwise used here.
        let raw = unsafe { std::slice::from_raw_parts_mut(info.as_mut_ptr().cast::<u8>(), bytes) };
        raw[0..4].copy_from_slice(&windows_rename_flags(replace).to_ne_bytes());
        raw[length_offset..length_offset + 4]
            .copy_from_slice(&((to_w.len() * 2) as u32).to_ne_bytes());
        for (i, unit) in to_w.iter().enumerate() {
            raw[name_offset + i * 2..name_offset + i * 2 + 2].copy_from_slice(&unit.to_ne_bytes());
        }
    }
    // A target held open by a handle that does not share delete (a C `fopen`, a .NET
    // `FileShare.Read`, a scanner or backup tool) refuses the rename even with POSIX semantics:
    // retried for a bounded time while `held` keeps the name, then the last error.
    let mut delay = REPLACE_RETRY_FIRST_DELAY;
    let mut attempt = 0;
    loop {
        // SAFETY: `info` is a FILE_RENAME_INFO of the stated length; `held` is a valid handle.
        let renamed = unsafe {
            SetFileInformationByHandle(
                held.as_raw_handle() as _,
                FileRenameInfoEx,
                info.as_ptr().cast(),
                bytes as u32,
            )
        };
        if renamed != 0 {
            break;
        }
        let error = io::Error::last_os_error();
        let refused_by_a_holder = matches!(
            error.raw_os_error().map(|code| code as u32),
            Some(ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION)
        );
        if refused_by_a_holder && attempt < REPLACE_RETRY_LIMIT {
            attempt += 1;
            std::thread::sleep(delay);
            delay = (delay * 2).min(REPLACE_RETRY_MAX_DELAY);
            continue;
        }
        if let Some(kept) = &kept {
            kept.undo();
        }
        return Err(error);
    }
    drop(held);
    // Past this point the entry has moved: a failure is a failed flush, never an undo, and says
    // so (a caller that undoes a failed move must not undo this one).
    for dir in &parent_dirs {
        crate::flush::sync_directory(dir)
            .map_err(|error| io::Error::new(error.kind(), MovedButNotFlushed(error)))?;
    }
    Ok(())
}

#[cfg(windows)]
const ERROR_ACCESS_DENIED: u32 = 5;
#[cfg(windows)]
const ERROR_SHARING_VIOLATION: u32 = 32;
/// Retries of a refused open of the source of a move, or of a `ReplaceFileW`: 1, 2, 4, ... 50 ms,
/// about 0.4 seconds in all. The wait blocks the calling thread, so it stays short.
#[cfg(windows)]
const REPLACE_RETRY_LIMIT: u32 = 12;
#[cfg(windows)]
const REPLACE_RETRY_FIRST_DELAY: std::time::Duration = std::time::Duration::from_millis(1);
#[cfg(windows)]
const REPLACE_RETRY_MAX_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

/// `ReplaceFileW`: makes `staged` the file named `target` and moves what was named `target`
/// to `backup`, the object itself (identity, size and times unchanged). Whatever the name led
/// to at that moment is the one captured under `backup`, so a caller can check it afterwards;
/// `NotFound` when `target` does not exist (nothing moved). Unlike an exchange there is a short
/// moment in which `target` names nothing. `ReplaceFileW` merges the replaced file's attributes
/// and ACL onto the replacement itself, but refuses a read-only replaced file, so the caller
/// clears that mark first and puts the person's marks back. Refused with a sharing violation
/// while another handle has `target` open without delete sharing; retried for a bounded time
/// like the replacing move.
#[cfg(windows)]
pub(super) fn replace_file_capturing(
    staged: &Path,
    target: &Path,
    backup: &Path,
) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{ReplaceFileW, REPLACEFILE_WRITE_THROUGH};
    let wide = |p: &Path| -> io::Result<Vec<u16>> {
        let wide: Vec<u16> = crate::long_path::for_win32(p).as_os_str().encode_wide().collect();
        if wide.contains(&0) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"));
        }
        Ok(wide.into_iter().chain(Some(0)).collect())
    };
    let (staged, target, backup) = (wide(staged)?, wide(target)?, wide(backup)?);
    let mut delay = REPLACE_RETRY_FIRST_DELAY;
    for attempt in 0..=REPLACE_RETRY_LIMIT {
        // SAFETY: all three buffers are NUL-terminated and outlive the call; the optional
        // arguments are null.
        let replaced = unsafe {
            ReplaceFileW(
                target.as_ptr(),
                staged.as_ptr(),
                backup.as_ptr(),
                REPLACEFILE_WRITE_THROUGH,
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if replaced != 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        let busy = matches!(
            error.raw_os_error().map(|code| code as u32),
            Some(ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION)
        );
        if !busy || attempt == REPLACE_RETRY_LIMIT {
            return Err(error);
        }
        std::thread::sleep(delay);
        delay = (delay * 2).min(REPLACE_RETRY_MAX_DELAY);
    }
    unreachable!("the last attempt returns")
}

/// The file attributes of `path` (read-only, hidden, system, ...), `None` if they cannot be read.
#[cfg(windows)]
pub(super) fn attributes(path: &Path) -> Option<u32> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{GetFileAttributesW, INVALID_FILE_ATTRIBUTES};
    let wide: Vec<u16> =
        crate::long_path::for_win32(path).as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: NUL-terminated and outlives the call.
    let attributes = unsafe { GetFileAttributesW(wide.as_ptr()) };
    (attributes != INVALID_FILE_ATTRIBUTES).then_some(attributes)
}

/// Sets the file attributes of `path`; best effort, for putting a person's marks back.
#[cfg(windows)]
pub(super) fn set_attributes(path: &Path, attributes: u32) {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::SetFileAttributesW;
    let wide: Vec<u16> =
        crate::long_path::for_win32(path).as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: NUL-terminated and outlives the call.
    unsafe { SetFileAttributesW(wide.as_ptr(), attributes) };
}

/// Whether `path` is under a registered Cloud Files sync root: `Some(false)` when the platform
/// says it is not under one, `None` when the question could not be answered. About 70 microseconds
/// on a measured machine, and it answers the same with the provider gone.
#[cfg(windows)]
pub(super) fn under_sync_root(path: &Path) -> Option<bool> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::CloudFilters::{
        CfGetSyncRootInfoByPath, CF_SYNC_ROOT_BASIC_INFO, CF_SYNC_ROOT_INFO_BASIC,
    };
    /// `ERROR_CLOUD_FILE_NOT_UNDER_SYNC_ROOT`, as an `HRESULT`.
    const NOT_UNDER_SYNC_ROOT: i32 = 0x8007_0186_u32 as i32;
    let wide: Vec<u16> =
        crate::long_path::for_win32(path).as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: an all-zero basic info is a valid value of this plain struct.
    let mut info: CF_SYNC_ROOT_BASIC_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: NUL-terminated path and a buffer of the stated size, both outliving the call.
    let result = unsafe {
        CfGetSyncRootInfoByPath(
            wide.as_ptr(),
            CF_SYNC_ROOT_INFO_BASIC,
            std::ptr::addr_of_mut!(info).cast(),
            std::mem::size_of::<CF_SYNC_ROOT_BASIC_INFO>() as u32,
            std::ptr::null_mut(),
        )
    };
    match result {
        0 => Some(true),
        NOT_UNDER_SYNC_ROOT => Some(false),
        _ => None,
    }
}

/// Whether no provider is connected to the sync root `path` is under: `Some(true)` when the
/// platform reports the root's provider as disconnected (never connected since the machine
/// started, ended, or terminated), `Some(false)` when one is connected, `None` when the path is
/// not under a sync root or the question could not be answered. This is the platform's own
/// statement and does not depend on the root's population policy, which decides whether a name
/// request in the root is refused without a provider (it is not on an ALWAYS_FULL root).
#[cfg(windows)]
pub(super) fn provider_disconnected(path: &Path) -> Option<bool> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::CloudFilters::{
        CfGetSyncRootInfoByPath, CF_PROVIDER_STATUS_DISCONNECTED, CF_PROVIDER_STATUS_ERROR,
        CF_PROVIDER_STATUS_TERMINATED, CF_SYNC_ROOT_INFO_STANDARD, CF_SYNC_ROOT_STANDARD_INFO,
    };
    let wide: Vec<u16> =
        crate::long_path::for_win32(path).as_os_str().encode_wide().chain(Some(0)).collect();
    // Room for the variable-length identity behind the fixed part (a provider may register one of
    // up to 64 KiB), 8-byte aligned.
    const IDENTITY_ROOM: usize = 64 * 1024 + 256;
    let mut buffer =
        vec![0u64; (std::mem::size_of::<CF_SYNC_ROOT_STANDARD_INFO>() + IDENTITY_ROOM).div_ceil(8)];
    // SAFETY: NUL-terminated path and a buffer of the stated size, both outliving the call.
    let result = unsafe {
        CfGetSyncRootInfoByPath(
            wide.as_ptr(),
            CF_SYNC_ROOT_INFO_STANDARD,
            buffer.as_mut_ptr().cast(),
            (buffer.len() * 8) as u32,
            std::ptr::null_mut(),
        )
    };
    if result != 0 {
        return None;
    }
    // SAFETY: the call succeeded, so at least the fixed part was written (8-byte aligned).
    let info = unsafe { &*buffer.as_ptr().cast::<CF_SYNC_ROOT_STANDARD_INFO>() };
    Some(matches!(
        info.ProviderStatus,
        CF_PROVIDER_STATUS_DISCONNECTED | CF_PROVIDER_STATUS_TERMINATED | CF_PROVIDER_STATUS_ERROR
    ))
}

/// The replaced file was renamed to the backup name and the replacement could not be moved.
#[cfg(windows)]
pub(super) const ERROR_UNABLE_TO_MOVE_REPLACEMENT_2: u32 = 1177;

/// Swaps two existing directory entries in one step, relative to open directories: afterwards
/// `name_a` in `dir_a` names what `name_b` in `dir_b` named and the other way round, and no
/// observer ever sees either name missing. `Ok(false)` where the platform or file system has no
/// such call (the caller falls back to a checked rename); `NotFound` when either name is missing.
///
/// Unix: `renameat2(RENAME_EXCHANGE)` / `renameatx_np(RENAME_SWAP)`. Not durable by itself.
#[cfg(unix)]
pub(super) fn exchange_at(
    dir_a: &DirHandle,
    name_a: &std::ffi::OsStr,
    dir_b: &DirHandle,
    name_b: &std::ffi::OsStr,
) -> io::Result<bool> {
    #[cfg(any(target_vendor = "apple", target_os = "linux"))]
    {
        let (c_a, c_b) = (c_name(name_a)?, c_name(name_b)?);
        loop {
            #[cfg(target_vendor = "apple")]
            // SAFETY: both names are valid NUL-terminated strings and both descriptors are open.
            let rc = unsafe {
                libc::renameatx_np(
                    dir_a.fd(),
                    c_a.as_ptr(),
                    dir_b.fd(),
                    c_b.as_ptr(),
                    libc::RENAME_SWAP,
                )
            };
            #[cfg(target_os = "linux")]
            // SAFETY: as above.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    dir_a.fd(),
                    c_a.as_ptr(),
                    dir_b.fd(),
                    c_b.as_ptr(),
                    libc::RENAME_EXCHANGE,
                ) as libc::c_int
            };
            if rc == 0 {
                return Ok(true);
            }
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::EINTR) => continue,
                // The file system or kernel lacks the flag.
                Some(libc::EINVAL | libc::ENOSYS | libc::ENOTSUP) => return Ok(false),
                _ => return Err(error),
            }
        }
    }
    #[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
    {
        let _ = (dir_a, name_a, dir_b, name_b);
        Ok(false)
    }
}

/// Removes the non-directory entry `name` of `dir` (`unlinkat`).
#[cfg(unix)]
pub(super) fn remove_file_at(dir: &DirHandle, name: &std::ffi::OsStr) -> io::Result<()> {
    let c = c_name(name)?;
    // SAFETY: a valid NUL-terminated name and an open descriptor.
    if unsafe { libc::unlinkat(dir.fd(), c.as_ptr(), 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// The path-named Unix move: both parents are opened and the rename is made relative to those
/// descriptors ([`move_entry_at`]), so a parent component swapped after the open cannot redirect it.
#[cfg(unix)]
fn unix_move(from: &Path, to: &Path, replace: Replace) -> io::Result<()> {
    let (from_name, to_name) = (entry_name(from)?, entry_name(to)?);
    let from_dir = DirHandle::open(super::directory_of(from))?;
    let to_dir = DirHandle::open(super::directory_of(to))?;
    move_entry_at(&from_dir, from_name, &to_dir, to_name, replace)
}

/// The last component of `path`, the name a descriptor-relative call takes.
///
/// A path that ends in a separator or in `/.` is refused: `Path::file_name` would strip that
/// syntax, and with it the requirement that the entry be a directory.
#[cfg(unix)]
pub(super) fn entry_name(path: &Path) -> io::Result<&std::ffi::OsStr> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    if bytes.ends_with(b"/") || bytes.ends_with(b"/.") || bytes == b"." {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    path.file_name().ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))
}

#[cfg(unix)]
fn c_name(name: &std::ffi::OsStr) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(name.as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

/// A name moved from `from_name` in `from_dir` to `to_name` in `to_dir`, relative to the open
/// directories: the directories renamed in are exactly the ones the caller holds (and flushes).
/// `Replace::No` is `renameat2(RENAME_NOREPLACE)` / `renameatx_np(RENAME_EXCL)` and fails closed
/// with `Unsupported` where the file system lacks it.
#[cfg(unix)]
pub(super) fn move_entry_at(
    from_dir: &DirHandle,
    from_name: &std::ffi::OsStr,
    to_dir: &DirHandle,
    to_name: &std::ffi::OsStr,
    replace: Replace,
) -> io::Result<()> {
    let (c_from, c_to) = (c_name(from_name)?, c_name(to_name)?);
    let (from_fd, to_fd) = (from_dir.fd(), to_dir.fd());
    loop {
        let rc = if replace == Replace::Yes {
            // SAFETY: both names are valid NUL-terminated strings and both descriptors are open.
            unsafe { libc::renameat(from_fd, c_from.as_ptr(), to_fd, c_to.as_ptr()) }
        } else {
            #[cfg(target_vendor = "apple")]
            // SAFETY: as above.
            let rc = unsafe {
                libc::renameatx_np(
                    from_fd,
                    c_from.as_ptr(),
                    to_fd,
                    c_to.as_ptr(),
                    libc::RENAME_EXCL,
                )
            };
            #[cfg(target_os = "linux")]
            // SAFETY: as above.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    from_fd,
                    c_from.as_ptr(),
                    to_fd,
                    c_to.as_ptr(),
                    libc::RENAME_NOREPLACE,
                ) as libc::c_int
            };
            #[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
            let rc = {
                let _ = (&c_from, &c_to, from_fd, to_fd);
                return Err(io::Error::from(io::ErrorKind::Unsupported));
            };
            rc
        };
        if rc == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => continue,
            // The file system lacks the no-replace variant. EINVAL is also what a directory moved
            // into itself answers, so the system's own error stays attached as the cause.
            Some(libc::EINVAL | libc::ENOSYS | libc::ENOTSUP) if replace == Replace::No => {
                return Err(io::Error::new(io::ErrorKind::Unsupported, error))
            }
            _ => return Err(error),
        }
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
        crate::flush::sync_directory(&self.0)
    }

    pub(super) fn fd(&self) -> std::os::fd::RawFd {
        std::os::fd::AsRawFd::as_raw_fd(&self.0)
    }

    /// Whether `path` (a link followed, as [`Self::open`] does) names the very directory this
    /// handle is open on.
    pub(super) fn is_directory_at(&self, path: &Path) -> io::Result<bool> {
        use std::os::unix::fs::MetadataExt;
        let held = self.0.metadata()?;
        let named = std::fs::metadata(path)?;
        Ok(held.dev() == named.dev() && held.ino() == named.ino())
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
        crate::flush::sync_directory(&handle)
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
