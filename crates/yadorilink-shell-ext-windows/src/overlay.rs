//! The four overlay states from `shell-integration` spec ("Sync Status
//! Icon Overlay" + on-demand-sync's "online-only" addition), each its own
//! COM class — Explorer's icon-overlay system only ever asks a given
//! identifier instance "does this ONE overlay apply to this file", so a
//! single identifier can't switch icons based on state; four registered
//! `CLSID`s (one per visual state) is the standard pattern every
//! shell-icon-overlay client (OneDrive, Dropbox, Nextcloud) uses.
//!
//! Icon files are placeholders (`shell32.dll`'s built-in icons) for early development — real custom overlay artwork is follow-up polish,
//! and must match the OS's native icon sizing guidelines.

use windows::core::{implement, w, Result, GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::S_FALSE;
use windows::Win32::UI::Shell::{IShellIconOverlayIdentifier, IShellIconOverlayIdentifier_Impl};

use crate::ipc_client;
use yadorilink_ipc_proto::shellipc::ShellBadge;

// Placeholder namespace-derived GUIDs — a real release
// MUST generate fixed, completely unique GUIDs here; the
// registry association is by GUID, so changing these breaks upgrades.
pub const CLSID_SYNCED: GUID = GUID::from_u128(0x8f3a1c00_1e6b_4b7a_9d2e_1a2b3c4d5e01);
pub const CLSID_SYNCING: GUID = GUID::from_u128(0x8f3a1c00_1e6b_4b7a_9d2e_1a2b3c4d5e02);
pub const CLSID_ERROR: GUID = GUID::from_u128(0x8f3a1c00_1e6b_4b7a_9d2e_1a2b3c4d5e03);
pub const CLSID_ONLINE_ONLY: GUID = GUID::from_u128(0x8f3a1c00_1e6b_4b7a_9d2e_1a2b3c4d5e04);

pub fn is_known_clsid(clsid: GUID) -> bool {
    matches!(clsid, CLSID_SYNCED | CLSID_SYNCING | CLSID_ERROR | CLSID_ONLINE_ONLY)
}

/// Converts a Windows path (as Explorer hands it to `IsMemberOf`, UTF-16
/// via `PCWSTR`) to a Rust `String`, or `None` if it's not valid UTF-16 /
/// null — matches the ipc_client's fail-soft contract: an unparseable
/// path just means "not a member of this overlay" rather than a panic.
fn path_from_pcwstr(path: PCWSTR) -> Option<String> {
    if path.is_null() {
        return None;
    }
    // Safety: Explorer guarantees a null-terminated UTF-16 string for the
    // lifetime of this call, per the documented `IsMemberOf` contract.
    unsafe { path.to_string().ok() }
}

fn is_member_of(path: &PCWSTR, want: ShellBadge) -> Result<()> {
    let Some(path) = path_from_pcwstr(*path) else {
        return Err(windows::core::Error::from(S_FALSE));
    };
    if ipc_client::query_badge(&path) == want {
        Ok(())
    } else {
        Err(windows::core::Error::from(S_FALSE))
    }
}

fn get_overlay_info(
    icon_file: PWSTR,
    cch_max: i32,
    index: *mut i32,
    flags: *mut u32,
    icon_index: i32,
) -> Result<()> {
    let icon_dll = w!(r"C:\Windows\System32\shell32.dll");
    // Safety: `icon_dll` is a `'static` wide-string literal from `w!`.
    let icon_wide: Vec<u16> =
        unsafe { icon_dll.as_wide() }.iter().copied().chain(std::iter::once(0)).collect();
    if icon_wide.len() > cch_max as usize {
        return Err(windows::core::Error::from(S_FALSE));
    }
    unsafe {
        std::ptr::copy_nonoverlapping(icon_wide.as_ptr(), icon_file.0, icon_wide.len());
        *index = icon_index;
        // ISIOI_ICONFILE (0x00000001) | ISIOI_ICONINDEX (0x00000002)
        *flags = 0x00000001 | 0x00000002;
    }
    Ok(())
}

#[implement(IShellIconOverlayIdentifier)]
pub struct SyncedOverlay;

impl SyncedOverlay {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SyncedOverlay {
    fn default() -> Self {
        Self::new()
    }
}

impl IShellIconOverlayIdentifier_Impl for SyncedOverlay_Impl {
    fn IsMemberOf(&self, pwszpath: &PCWSTR, _dwattrib: u32) -> Result<()> {
        is_member_of(pwszpath, ShellBadge::Synced)
    }
    fn GetOverlayInfo(
        &self,
        pwsziconfile: PWSTR,
        cchmax: i32,
        pindex: *mut i32,
        pdwflags: *mut u32,
    ) -> Result<()> {
        get_overlay_info(pwsziconfile, cchmax, pindex, pdwflags, 46)
    }
    fn GetPriority(&self) -> Result<i32> {
        Ok(0)
    }
}

#[implement(IShellIconOverlayIdentifier)]
pub struct SyncingOverlay;

impl SyncingOverlay {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SyncingOverlay {
    fn default() -> Self {
        Self::new()
    }
}

impl IShellIconOverlayIdentifier_Impl for SyncingOverlay_Impl {
    fn IsMemberOf(&self, pwszpath: &PCWSTR, _dwattrib: u32) -> Result<()> {
        is_member_of(pwszpath, ShellBadge::Syncing)
    }
    fn GetOverlayInfo(
        &self,
        pwsziconfile: PWSTR,
        cchmax: i32,
        pindex: *mut i32,
        pdwflags: *mut u32,
    ) -> Result<()> {
        get_overlay_info(pwsziconfile, cchmax, pindex, pdwflags, 238)
    }
    fn GetPriority(&self) -> Result<i32> {
        Ok(1)
    }
}

#[implement(IShellIconOverlayIdentifier)]
pub struct ErrorOverlay;

impl ErrorOverlay {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ErrorOverlay {
    fn default() -> Self {
        Self::new()
    }
}

impl IShellIconOverlayIdentifier_Impl for ErrorOverlay_Impl {
    fn IsMemberOf(&self, pwszpath: &PCWSTR, _dwattrib: u32) -> Result<()> {
        is_member_of(pwszpath, ShellBadge::Error)
    }
    fn GetOverlayInfo(
        &self,
        pwsziconfile: PWSTR,
        cchmax: i32,
        pindex: *mut i32,
        pdwflags: *mut u32,
    ) -> Result<()> {
        get_overlay_info(pwsziconfile, cchmax, pindex, pdwflags, 109)
    }
    fn GetPriority(&self) -> Result<i32> {
        Ok(2)
    }
}

/// on-demand-sync's "online-only" overlay: drawn when the daemon's badge for the path is
/// `OnlineOnly`. The daemon decides it; this shell never derives it.
#[implement(IShellIconOverlayIdentifier)]
pub struct OnlineOnlyOverlay;

impl OnlineOnlyOverlay {
    pub fn new() -> Self {
        Self
    }
}

impl Default for OnlineOnlyOverlay {
    fn default() -> Self {
        Self::new()
    }
}

impl IShellIconOverlayIdentifier_Impl for OnlineOnlyOverlay_Impl {
    fn IsMemberOf(&self, pwszpath: &PCWSTR, _dwattrib: u32) -> Result<()> {
        is_member_of(pwszpath, ShellBadge::OnlineOnly)
    }
    fn GetOverlayInfo(
        &self,
        pwsziconfile: PWSTR,
        cchmax: i32,
        pindex: *mut i32,
        pdwflags: *mut u32,
    ) -> Result<()> {
        get_overlay_info(pwsziconfile, cchmax, pindex, pdwflags, 172)
    }
    fn GetPriority(&self) -> Result<i32> {
        Ok(3)
    }
}
