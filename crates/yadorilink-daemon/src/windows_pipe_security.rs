#![cfg(windows)]

use std::ffi::c_void;
use std::ptr::{null_mut, NonNull};

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenOwner, SECURITY_ATTRIBUTES, TOKEN_OWNER, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub struct PipeSecurityAttributes {
    security_descriptor: *mut c_void,
    attrs: SECURITY_ATTRIBUTES,
}

impl PipeSecurityAttributes {
    pub fn new_current_user_and_system_only() -> std::io::Result<Self> {
        let current_user_sid = current_user_sid_string()?;
        let sddl = widestr(&format!("D:P(A;;GA;;;SY)(A;;GA;;;{current_user_sid})"));
        let mut security_descriptor = null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut security_descriptor,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security_descriptor,
            bInheritHandle: 0,
        };
        Ok(Self { security_descriptor, attrs })
    }

    pub fn as_mut_ptr(&mut self) -> *mut c_void {
        (&mut self.attrs as *mut SECURITY_ATTRIBUTES).cast()
    }
}

impl Drop for PipeSecurityAttributes {
    fn drop(&mut self) {
        if !self.security_descriptor.is_null() {
            unsafe {
                LocalFree(self.security_descriptor);
            }
        }
    }
}

fn widestr(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn current_user_sid_string() -> std::io::Result<String> {
    let mut token: HANDLE = null_mut();
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let sid = unsafe { current_user_sid_string_from_token(token) };
    unsafe {
        CloseHandle(token);
    }
    sid
}

unsafe fn current_user_sid_string_from_token(token: HANDLE) -> std::io::Result<String> {
    let mut len = 0u32;
    let _ = GetTokenInformation(token, TokenOwner, null_mut(), 0, &mut len);
    if len == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut buffer = vec![0u8; len as usize];
    let ok =
        GetTokenInformation(token, TokenOwner, buffer.as_mut_ptr().cast::<c_void>(), len, &mut len);
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let owner = buffer.as_ptr().cast::<TOKEN_OWNER>().read_unaligned();
    let mut sid_string = null_mut();
    let ok = ConvertSidToStringSidW(owner.Owner, &mut sid_string);
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let sid_string = NonNull::new(sid_string)
        .ok_or_else(|| std::io::Error::other("ConvertSidToStringSidW returned null"))?;
    let mut chars = 0usize;
    while *sid_string.as_ptr().add(chars) != 0 {
        chars += 1;
    }
    let sid = String::from_utf16_lossy(std::slice::from_raw_parts(sid_string.as_ptr(), chars));
    LocalFree(sid_string.as_ptr().cast::<c_void>());
    Ok(sid)
}
