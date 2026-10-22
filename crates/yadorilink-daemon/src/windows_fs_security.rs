#![cfg(windows)]

//! Windows file-security primitives for the provider write path: who the current user is, who
//! owns a file or directory, and how a directory is made private to that user.
//!
//! The Unix daemon relies on mode `0700` and `geteuid`; the Windows equivalents are a protected
//! DACL naming only the current user and a comparison of the owner SID of an open handle with the
//! SIDs of this process's token. Nothing here follows a path through a reparse point: directories
//! and files are opened with `FILE_FLAG_OPEN_REPARSE_POINT`.

use std::ffi::c_void;
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, GENERIC_READ, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetLengthSid, GetSecurityDescriptorDacl, GetTokenInformation, TokenOwner, TokenUser,
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    SECURITY_ATTRIBUTES, TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use yadorilink_ipc_proto::pipe_peer::sids_match;

fn wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    yadorilink_fs_platform::long_path::for_win32(path)
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// The SIDs this process creates objects under: its token's user and its token's default owner
/// (the user, or `Administrators` in an elevated token). A file belongs to "the current user"
/// when its owner is either.
pub(crate) struct ProcessSids {
    user: Vec<u8>,
    owner: Vec<u8>,
}

impl ProcessSids {
    pub(crate) fn current() -> std::io::Result<Self> {
        let mut token: HANDLE = null_mut();
        // SAFETY: plain Win32 call; `token` is closed on every path below.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let user = token_sid(token, TokenUser);
        let owner = token_sid(token, TokenOwner);
        // SAFETY: `token` was opened above and is not used again.
        unsafe { CloseHandle(token) };
        Ok(Self { user: user?, owner: owner? })
    }

    /// Whether `sid` names the current user (or the token's default owner).
    pub(crate) fn is_current(&self, sid: &[u8]) -> bool {
        sids_match(&self.user, sid) || sids_match(&self.owner, sid)
    }

    /// The user SID in `S-1-5-...` form, for a security descriptor.
    fn user_string(&self) -> std::io::Result<String> {
        let mut text: *mut u16 = null_mut();
        // SAFETY: `user` is a well-formed SID copied out of the token.
        if unsafe { ConvertSidToStringSidW(self.user.as_ptr().cast_mut().cast(), &mut text) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: on success `text` is a NUL-terminated wide string that this call owns.
        let value = unsafe {
            let mut len = 0usize;
            while *text.add(len) != 0 {
                len += 1;
            }
            let value = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
            LocalFree(text.cast());
            value
        };
        Ok(value)
    }
}

fn token_sid(token: HANDLE, class: i32) -> std::io::Result<Vec<u8>> {
    let mut len = 0u32;
    // SAFETY: the first call only asks for the required size.
    unsafe { GetTokenInformation(token, class, null_mut(), 0, &mut len) };
    if len == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut buffer = vec![0u8; len as usize];
    // SAFETY: `buffer` has the size the first call reported.
    if unsafe { GetTokenInformation(token, class, buffer.as_mut_ptr().cast(), len, &mut len) } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: both token classes start with a pointer to a SID that lives inside `buffer`
    // (`TOKEN_USER` and `TOKEN_OWNER` have a SID pointer as their first field).
    let sid = if class == TokenUser {
        unsafe { buffer.as_ptr().cast::<TOKEN_USER>().read_unaligned().User.Sid }
    } else {
        unsafe { buffer.as_ptr().cast::<TOKEN_OWNER>().read_unaligned().Owner }
    };
    // SAFETY: `sid` points at a SID inside `buffer`, which is still alive.
    let sid_len = unsafe { GetLengthSid(sid) } as usize;
    // SAFETY: as above; the bytes are copied out before `buffer` is dropped.
    Ok(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), sid_len) }.to_vec())
}

/// The owner SID of an open handle.
pub(crate) fn owner_sid_of_handle(handle: HANDLE) -> std::io::Result<Vec<u8>> {
    let mut owner: *mut c_void = null_mut();
    let mut descriptor: *mut c_void = null_mut();
    // SAFETY: `handle` is an open handle with READ_CONTROL; the out-pointers are valid.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }
    // SAFETY: `owner` points into `descriptor`, which is alive until the `LocalFree` below.
    let sid = unsafe {
        let len = GetLengthSid(owner) as usize;
        std::slice::from_raw_parts(owner.cast::<u8>(), len).to_vec()
    };
    // SAFETY: `descriptor` was allocated by `GetSecurityInfo` for this call.
    unsafe { LocalFree(descriptor) };
    Ok(sid)
}

/// A security descriptor allowing only the current user, inherited by what is created below.
struct PrivateDescriptor {
    descriptor: *mut c_void,
}

impl PrivateDescriptor {
    fn new(sids: &ProcessSids) -> std::io::Result<Self> {
        let sddl: Vec<u16> = format!("D:P(A;OICI;FA;;;{})", sids.user_string()?)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut descriptor = null_mut();
        // SAFETY: `sddl` is NUL-terminated; on success `descriptor` is owned by this value.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { descriptor })
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.descriptor,
            bInheritHandle: 0,
        }
    }
}

impl Drop for PrivateDescriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
        unsafe { LocalFree(self.descriptor) };
    }
}

/// Creates `dir` and every missing ancestor below the first existing one, each with a protected
/// DACL that names only the current user.
pub(crate) fn create_private_dir_all(dir: &Path) -> std::io::Result<()> {
    let descriptor = PrivateDescriptor::new(&ProcessSids::current()?)?;
    let mut missing = Vec::new();
    let mut cursor = Some(dir);
    while let Some(path) = cursor {
        match std::fs::symlink_metadata(path) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(path);
                cursor = path.parent();
            }
            Err(error) => return Err(error),
        }
    }
    for path in missing.into_iter().rev() {
        let attributes = descriptor.attributes();
        // SAFETY: `path` is NUL-terminated wide text; `attributes` outlives the call.
        if unsafe { CreateDirectoryW(wide(path).as_ptr(), &attributes) } == 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        }
    }
    Ok(())
}

/// Replaces the DACL of `path` with one naming only the current user (protected, so nothing is
/// inherited): the Windows counterpart of tightening a directory to mode `0700`.
pub(crate) fn restrict_to_current_user(path: &Path) -> std::io::Result<()> {
    let descriptor = PrivateDescriptor::new(&ProcessSids::current()?)?;
    let mut present = 0;
    let mut dacl = null_mut();
    let mut defaulted = 0;
    // SAFETY: `descriptor` is a valid self-relative descriptor; out-pointers are valid.
    if unsafe {
        GetSecurityDescriptorDacl(descriptor.descriptor, &mut present, &mut dacl, &mut defaulted)
    } == 0
        || present == 0
    {
        return Err(std::io::Error::other("the private descriptor has no DACL"));
    }
    let name = wide(path);
    // SAFETY: `name` is NUL-terminated; `dacl` points into `descriptor`, alive across the call.
    let status = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr().cast_mut(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

/// Whether the directory `path` (opened without following a reparse point) is owned by the
/// current user.
pub(crate) fn directory_owned_by_current_user(path: &Path) -> std::io::Result<bool> {
    let name = wide(path);
    // SAFETY: `name` is NUL-terminated; the handle is closed below.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            READ_CONTROL | GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle as isize == -1 {
        return Err(std::io::Error::last_os_error());
    }
    let owner = owner_sid_of_handle(handle);
    // SAFETY: `handle` was opened above and is not used again.
    unsafe { CloseHandle(handle) };
    Ok(ProcessSids::current()?.is_current(&owner?))
}
