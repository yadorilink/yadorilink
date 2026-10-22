//! The daemon-process side of Windows CfAPI dirty detection --
//! `local_change.rs`'s ONLY way to prove a `Remote`-state path is
//! still untouched on Windows (see `ports::LocalMutationStore::
//! inspect_windows_placeholder`'s own doc for the exact contract this
//! module fulfils).
//!
//! # Why this calls `CfGetPlaceholderInfo` from the DAEMON process, not
//! `yadorilink-cfapi-host.exe`
//!
//! `crates/yadorilink-shell-ext-windows/src/cfapi.rs`'s `fetch_data_callback` and this
//! module's own `inspect_placeholder` both end up calling into the Cloud
//! Filter API against the same on-disk placeholders, but from two
//! DIFFERENT OS processes. The filter driver refuses ordinary file
//! operations -- even a read-only attribute query -- against a
//! placeholder under a sync root with NO connected provider at all. It does not follow (and this
//! module does not assume) that the connection must belong to the SAME
//! process making the query: in production, `yadorilink-cfapi-host.exe`
//! is ALWAYS the connected provider for every registered root, so a
//! read-only query from a second process (this daemon) against a
//! placeholder under one of those already-connected roots is the bet this
//! module makes, instead of standing up a second cross-process RPC
//! surface (`daemon -> cfapi-host`) just to run this one read.
//!
//! This cross-process assumption is not exercised by this module's own
//! (non-Windows) tests. If it is wrong on real hardware, every `CfGetPlaceholderInfo`
//! call here would simply fail -- which this module already maps to
//! `PlaceholderStatus::Unknown`, the same fail-closed outcome as every
//! other failure mode it handles, so Windows dirty detection would
//! degrade to "always capture" (safe, if suboptimal) rather than produce
//! a wrong answer. Only in that failure case does the cross-process RPC
//! design (`cfapi-host` as a second named-pipe server, `daemon` as its
//! client) become worth the added complexity.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Storage::CloudFilters::{
    CfGetPlaceholderInfo, CfGetPlaceholderStateFromFileInfo, CF_PLACEHOLDER_BASIC_INFO,
    CF_PLACEHOLDER_INFO_BASIC, CF_PLACEHOLDER_STATE_INVALID, CF_PLACEHOLDER_STATE_IN_SYNC,
    CF_PLACEHOLDER_STATE_PLACEHOLDER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FileAttributeTagInfo, GetFileInformationByHandleEx, FILE_ATTRIBUTE_TAG_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};

use yadorilink_local_capture::ports::PlaceholderStatus;

/// The generation-identity wire format `crates/yadorilink-shell-ext-windows/src/cfapi.rs`'s
/// `encode_generation_identity` writes as a placeholder's `FileIdentity`,
/// and this function decodes: 1 version-tag byte (`1`, "generation-token
/// v1") followed by an 8-byte little-endian `u64`. Self-describing on
/// purpose -- a bare, untagged 8-byte timestamp (an older format) has no
/// way to be told apart from a filename-derived identity; both are
/// uniformly "not this format" here, since this project ships
/// pre-release with no compatibility burden (no migration path needed for
/// placeholders an earlier build created). Any blob that isn't exactly 9
/// bytes starting with tag `1` decodes to `None` -- a caller must treat
/// that as "not a generation this process minted", never guess a value
/// from it.
fn decode_generation_identity(bytes: &[u8]) -> Option<u64> {
    const VERSION_TAG: u8 = 1;
    if bytes.len() != 9 || bytes[0] != VERSION_TAG {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[1..9]);
    Some(u64::from_le_bytes(buf))
}

fn to_wide(path: &Path) -> Vec<u16> {
    yadorilink_fs_platform::long_path::for_win32(path)
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Opens `path` for a read-only placeholder-metadata query: `FILE_READ_
/// ATTRIBUTES` only (no `GENERIC_READ`/`GENERIC_WRITE`) -- this call never
/// reads or writes the placeholder's actual content, only asks the
/// filter driver about its identity/in-sync state, so it asks for
/// nothing more than that. `FILE_FLAG_OPEN_REPARSE_POINT` is required:
/// without it, `CreateFileW` on a dehydrated placeholder would itself
/// trigger hydration.
fn open_reparse_handle_read_attributes(
    path: &Path,
) -> Option<windows_sys::Win32::Foundation::HANDLE> {
    let wide = to_wide(path);
    // SAFETY: `wide` is a valid NUL-terminated UTF-16 buffer for the
    // duration of this call.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle.is_null() || handle as isize == -1 {
        return None;
    }
    Some(handle)
}

/// Reads back the `FileIdentity` bytes the placeholder at `handle`
/// currently carries, via `CfGetPlaceholderInfo(CF_PLACEHOLDER_INFO_
/// BASIC)`. `None` on any failure. Holds no `CfConnectSyncRoot`
/// connection of its own (see this module's top-level doc for why).
fn read_placeholder_identity(handle: windows_sys::Win32::Foundation::HANDLE) -> Option<Vec<u8>> {
    const IDENTITY_HEADROOM: usize = 64;
    let mut buf = vec![0u8; std::mem::size_of::<CF_PLACEHOLDER_BASIC_INFO>() + IDENTITY_HEADROOM];
    let mut returned: u32 = 0;
    // SAFETY: `handle` is a valid, open handle; `buf` is sized to hold at
    // least a full `CF_PLACEHOLDER_BASIC_INFO` plus headroom for the
    // trailing identity bytes.
    let hr = unsafe {
        CfGetPlaceholderInfo(
            handle,
            CF_PLACEHOLDER_INFO_BASIC,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            &mut returned,
        )
    };
    if hr < 0 {
        return None;
    }
    // SAFETY: `buf` was just populated by the call above, which reported
    // success, so at least `size_of::<CF_PLACEHOLDER_BASIC_INFO>()` bytes
    // are valid; `read_unaligned` does not require the buffer to be
    // aligned for the struct type.
    let info: CF_PLACEHOLDER_BASIC_INFO =
        unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const CF_PLACEHOLDER_BASIC_INFO) };
    let identity_offset = std::mem::offset_of!(CF_PLACEHOLDER_BASIC_INFO, FileIdentity);
    let len = info.FileIdentityLength as usize;
    if identity_offset.checked_add(len)? > buf.len() {
        return None;
    }
    Some(buf[identity_offset..identity_offset + len].to_vec())
}

/// The real implementation behind `LocalMutationStore::
/// inspect_windows_placeholder` on Windows. Every early-return is
/// `Unknown`, never `Untouched` -- see this crate's own port trait doc
/// comment for why that's the only sound default when this process
/// cannot positively confirm both the identity match and the in-sync
/// bit.
///
/// Reads identity BEFORE state (reading state first, then identity,
/// would let a local write landing between those two reads clear
/// `CF_PLACEHOLDER_STATE_IN_SYNC` while leaving the (still-matching)
/// identity in place, and this function would still report `Untouched`
/// using the now-stale, pre-write state it sampled first). Neither read is atomic with the other -- only an oplock or
/// equivalent OS-level synchronization could close this window
/// completely, which is out of scope here -- but sampling the state LAST,
/// immediately before the final decision, narrows it to the smallest
/// practical span: a write racing strictly between the state read and
/// this function's return, rather than one racing across the entire
/// identity-then-state sequence.
pub fn inspect_placeholder(path: &Path, expected_generation: u64) -> PlaceholderStatus {
    let Some(handle) = open_reparse_handle_read_attributes(path) else {
        return PlaceholderStatus::Unknown;
    };
    let close = || unsafe {
        CloseHandle(handle);
    };

    let identity = read_placeholder_identity(handle);
    let decoded = match identity {
        Some(bytes) => decode_generation_identity(&bytes),
        None => None,
    };
    if decoded != Some(expected_generation) {
        // ABA guard: a placeholder deleted and replaced by an unrelated
        // one at the same path (this process's index still expects the
        // OLD generation) must not report `Untouched` for a stale
        // expectation -- checked before state so a mismatched identity
        // never even reaches the in-sync decision below.
        close();
        return PlaceholderStatus::Unknown;
    }

    let mut attr_tag: FILE_ATTRIBUTE_TAG_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: `handle` is a valid, open handle to `path`; `attr_tag` is
    // correctly sized for `FileAttributeTagInfo`.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            &mut attr_tag as *mut _ as *mut c_void,
            std::mem::size_of_val(&attr_tag) as u32,
        )
    };
    if ok == 0 {
        close();
        return PlaceholderStatus::Unknown;
    }
    // SAFETY: `attr_tag` was just populated by the call above.
    let state = unsafe {
        CfGetPlaceholderStateFromFileInfo(
            &attr_tag as *const _ as *const c_void,
            FileAttributeTagInfo,
        )
    };
    close();
    if state == CF_PLACEHOLDER_STATE_INVALID || state & CF_PLACEHOLDER_STATE_PLACEHOLDER == 0 {
        // No longer a real placeholder at all (hydrated in place by
        // something other than this process's own hydrate path, or
        // replaced outright). Cannot confirm it is still the one this
        // process's index expects.
        return PlaceholderStatus::Unknown;
    }
    if state & CF_PLACEHOLDER_STATE_IN_SYNC != 0 {
        PlaceholderStatus::Untouched
    } else {
        PlaceholderStatus::Dirty
    }
}

#[cfg(test)]
mod tests;
