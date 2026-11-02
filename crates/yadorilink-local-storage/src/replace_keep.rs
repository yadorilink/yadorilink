//! What overwriting a synchronised file keeps of the file it replaces, on Unix.
//!
//! A received file is written to a new temporary file and renamed over the old one, so the new inode starts
//! with the default mode, no ACL and no extended attributes. Only the execute bit is replicated; everything
//! else the person set on the file stays theirs. [`carry_over`] runs just before the rename and copies from
//! the old file to the new one, in this order:
//!
//! 1. the ACL (Linux: the access ACL, stored as the `system.posix_acl_access` attribute; macOS: the extended
//!    ACL) -- first, because on Linux setting an ACL rewrites the group permission bits from its mask;
//! 2. the extended attributes the person owns (Linux: `user.*`; macOS: every attribute except the ones the
//!    system or a download sets about where the old bytes came from -- quarantine, provenance, the resource
//!    fork, Spotlight metadata);
//! 3. the permission bits, last, without setuid, setgid and the execute bits (a content change drops the
//!    first two; the execute bits come from the replicated flag, which the caller applies as for any
//!    received file). The owner always keeps read access, so a file the person made unreadable (0000) is
//!    still completed by the receive.
//!
//! The old file's metadata that cannot be read stops the replace with an error: publishing without it would
//! silently drop what the person set. Attributes the file system does not support are skipped.

use std::ffi::{CStr, CString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

/// An attribute name that is never carried over (macOS): where the old bytes came from, or derived data.
#[cfg(target_vendor = "apple")]
fn is_origin_attribute(name: &[u8]) -> bool {
    matches!(
        name,
        b"com.apple.quarantine"
            | b"com.apple.provenance"
            | b"com.apple.ResourceFork"
            | b"com.apple.lastuseddate#PS"
    ) || name.starts_with(b"com.apple.metadata:kMDItem")
        || name.starts_with(b"com.apple.metadata:_kMDItem")
}

/// Whether an attribute is the person's to keep on this platform.
fn is_kept_attribute(name: &[u8]) -> bool {
    #[cfg(target_os = "linux")]
    {
        name.starts_with(b"user.")
    }
    #[cfg(target_vendor = "apple")]
    {
        !is_origin_attribute(name)
    }
    #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
    {
        let _ = name;
        false
    }
}

fn c_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

/// The attribute is not there (macOS says `ENOATTR`, Linux `ENODATA`).
fn attribute_absent(error: &io::Error) -> bool {
    #[cfg(target_vendor = "apple")]
    {
        error.raw_os_error() == Some(libc::ENOATTR)
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        error.raw_os_error() == Some(libc::ENODATA)
    }
}

fn not_supported(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::ENOTSUP | libc::ENOSYS | libc::ENODATA))
}

#[cfg(target_os = "linux")]
mod sys {
    use super::*;
    pub fn list(path: &CStr, buf: *mut libc::c_char, len: usize) -> isize {
        // SAFETY: valid NUL-terminated path; `buf` is null with len 0 or points at `len` bytes.
        unsafe { libc::llistxattr(path.as_ptr(), buf, len) }
    }
    pub fn get(path: &CStr, name: &CStr, buf: *mut libc::c_void, len: usize) -> isize {
        // SAFETY: as above.
        unsafe { libc::lgetxattr(path.as_ptr(), name.as_ptr(), buf, len) }
    }
    pub fn set(path: &CStr, name: &CStr, value: &[u8]) -> i32 {
        // SAFETY: as above; `value` is a valid slice.
        unsafe {
            libc::lsetxattr(path.as_ptr(), name.as_ptr(), value.as_ptr().cast(), value.len(), 0)
        }
    }
}

#[cfg(target_vendor = "apple")]
mod sys {
    use super::*;
    pub fn list(path: &CStr, buf: *mut libc::c_char, len: usize) -> isize {
        // SAFETY: valid NUL-terminated path; `buf` is null with len 0 or points at `len` bytes.
        unsafe { libc::listxattr(path.as_ptr(), buf, len, libc::XATTR_NOFOLLOW) }
    }
    pub fn get(path: &CStr, name: &CStr, buf: *mut libc::c_void, len: usize) -> isize {
        // SAFETY: as above.
        unsafe { libc::getxattr(path.as_ptr(), name.as_ptr(), buf, len, 0, libc::XATTR_NOFOLLOW) }
    }
    pub fn set(path: &CStr, name: &CStr, value: &[u8]) -> i32 {
        // SAFETY: as above; `value` is a valid slice.
        unsafe {
            libc::setxattr(
                path.as_ptr(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
                libc::XATTR_NOFOLLOW,
            )
        }
    }
}

const ACL_ATTRIBUTE: &[u8] = b"system.posix_acl_access";

/// One value of an attribute, read again when it grew between the size query and the read.
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn read_value(path: &CStr, name: &CStr) -> io::Result<Option<Vec<u8>>> {
    loop {
        let size = sys::get(path, name, std::ptr::null_mut(), 0);
        if size < 0 {
            let error = io::Error::last_os_error();
            return if attribute_absent(&error) { Ok(None) } else { Err(error) };
        }
        let mut value = vec![0u8; size as usize];
        let got =
            sys::get(path, name, value.as_mut_ptr().cast(), value.len().max(1).min(value.len()));
        if got < 0 {
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                _ if attribute_absent(&error) => return Ok(None),
                Some(libc::ERANGE) => continue,
                _ => return Err(error),
            }
        }
        if got as usize != value.len() {
            // Changed between the two calls: ask again.
            if got as usize > value.len() {
                continue;
            }
            value.truncate(got as usize);
        }
        return Ok(Some(value));
    }
}

/// The attributes of `path` worth carrying as (name, value), the access ACL first. Every attribute name is
/// bytes: a name need not be UTF-8.
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn read_attributes(path: &Path) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let c = c_path(path)?;
    let mut listed = None;
    for _ in 0..8 {
        let size = sys::list(&c, std::ptr::null_mut(), 0);
        if size < 0 {
            let error = io::Error::last_os_error();
            return if not_supported(&error) { Ok(Vec::new()) } else { Err(error) };
        }
        let mut buffer = vec![0u8; size as usize];
        if size == 0 {
            listed = Some(buffer);
            break;
        }
        let got = sys::list(&c, buffer.as_mut_ptr().cast(), buffer.len());
        if got >= 0 {
            buffer.truncate(got as usize);
            listed = Some(buffer);
            break;
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ERANGE) {
            return Err(error);
        }
    }
    // Attributes that keep changing under the read are not guessed at: the replace stops.
    let names = listed.ok_or_else(|| io::Error::from(io::ErrorKind::Interrupted))?;
    let mut out = Vec::new();
    for raw in names.split(|b| *b == 0).filter(|n| !n.is_empty()) {
        let acl = cfg!(target_os = "linux") && raw == ACL_ATTRIBUTE;
        if !acl && !is_kept_attribute(raw) {
            continue;
        }
        let cname = CString::new(raw).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        if let Some(value) = read_value(&c, &cname)? {
            out.push((raw.to_vec(), value));
        }
    }
    // The ACL first: setting it rewrites the group bits, which the mode step then settles.
    out.sort_by_key(|(name, _)| name != ACL_ATTRIBUTE);
    Ok(out)
}

/// Writes `attributes` to `path`. On Linux a staged file that inherited an access ACL from its directory
/// but whose replaced file had none loses it: the new file must not be more open than the old one was.
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn write_attributes(path: &Path, attributes: &[(Vec<u8>, Vec<u8>)]) -> io::Result<()> {
    let c = c_path(path)?;
    #[cfg(target_os = "linux")]
    if !attributes.iter().any(|(name, _)| name == ACL_ATTRIBUTE) {
        let name = CString::new(ACL_ATTRIBUTE).expect("no NUL");
        // SAFETY: valid NUL-terminated path and name.
        if unsafe { libc::lremovexattr(c.as_ptr(), name.as_ptr()) } != 0 {
            let error = io::Error::last_os_error();
            if !not_supported(&error) {
                return Err(error);
            }
        }
    }
    for (name, value) in attributes {
        let cname = CString::new(name.as_slice())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        if sys::set(&c, &cname, value) != 0 {
            let error = io::Error::last_os_error();
            if not_supported(&error) {
                continue;
            }
            return Err(error);
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn read_attributes(_path: &Path) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    Ok(Vec::new())
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn write_attributes(_path: &Path, _attributes: &[(Vec<u8>, Vec<u8>)]) -> io::Result<()> {
    Ok(())
}

#[cfg(target_vendor = "apple")]
mod acl {
    use super::*;
    use std::ffi::c_void;
    const ACL_TYPE_EXTENDED: i32 = 0x100;
    extern "C" {
        fn acl_get_file(path: *const libc::c_char, kind: i32) -> *mut c_void;
        fn acl_set_file(path: *const libc::c_char, kind: i32, acl: *mut c_void) -> i32;
        fn acl_free(obj: *mut c_void) -> i32;
        fn acl_init(count: i32) -> *mut c_void;
    }
    pub struct Acl(*mut c_void);
    impl Drop for Acl {
        fn drop(&mut self) {
            // SAFETY: allocated by `acl_get_file`.
            unsafe { acl_free(self.0) };
        }
    }
    pub fn read(path: &Path) -> io::Result<Option<Acl>> {
        let c = c_path(path)?;
        // SAFETY: valid NUL-terminated path.
        let acl = unsafe { acl_get_file(c.as_ptr(), ACL_TYPE_EXTENDED) };
        if acl.is_null() {
            let error = io::Error::last_os_error();
            return match error.raw_os_error() {
                Some(libc::ENOENT) | Some(libc::ENOTSUP) | Some(libc::EINVAL) | None | Some(0) => {
                    Ok(None)
                }
                _ => Err(error),
            };
        }
        Ok(Some(Acl(acl)))
    }
    /// An ACL with no entries: sets "no ACL" on a staged file that inherited one.
    pub fn empty() -> io::Result<Acl> {
        // SAFETY: plain allocation.
        let acl = unsafe { acl_init(0) };
        if acl.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Acl(acl))
        }
    }
    pub fn write(path: &Path, acl: &Acl) -> io::Result<()> {
        let c = c_path(path)?;
        // SAFETY: valid path and ACL.
        if unsafe { acl_set_file(c.as_ptr(), ACL_TYPE_EXTENDED, acl.0) } != 0 {
            let error = io::Error::last_os_error();
            return if not_supported(&error) { Ok(()) } else { Err(error) };
        }
        Ok(())
    }
}

/// Carries the old file's ACL, owner attributes and permission bits to `new` (see the module comment). A
/// missing `old`, or one that is not a regular file, has nothing to carry.
pub(crate) fn carry_over(old: &Path, new: &Path) -> io::Result<()> {
    let metadata = match std::fs::symlink_metadata(old) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() {
        return Ok(());
    }
    let attributes = read_attributes(old)?;
    #[cfg(target_vendor = "apple")]
    let acl = acl::read(old)?;
    write_attributes(new, &attributes)?;
    #[cfg(target_vendor = "apple")]
    match &acl {
        Some(acl) => acl::write(new, acl)?,
        None => {
            if acl::read(new)?.is_some() {
                acl::write(new, &acl::empty()?)?;
            }
        }
    }
    // No execute bit is copied: the replicated flag decides them (see `apply_exec`). The owner keeps read
    // access so the received file can still be opened to finish its receive.
    let wanted = (metadata.mode() & 0o1666) | 0o400;
    let current = std::fs::symlink_metadata(new)?.permissions().mode() & 0o7777;
    if current != wanted {
        std::fs::set_permissions(new, std::fs::Permissions::from_mode(wanted))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
