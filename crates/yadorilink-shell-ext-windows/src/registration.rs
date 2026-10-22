//! COM registration for the four overlay
//! identifier CLSIDs, driven by `regsvr32.exe` calling `DllRegisterServer`
//! / `DllUnregisterServer` (the standard COM DLL registration contract —
//! no separate installer script is needed beyond `regsvr32`, though a
//! thin wrapper script is still useful for end users; see the repo's
//! `windows/install.ps1`).
//!
//! Registers under `HKEY_LOCAL_MACHINE\SOFTWARE\Classes` (system-wide,
//! all users) rather than `HKEY_CURRENT_USER` — `ShellIconOverlayIdentifiers`
//! is itself only ever read from `HKEY_LOCAL_MACHINE`, so per-user CLSID
//! registration wouldn't be visible to Explorer's overlay system anyway.
//! This means `regsvr32` must run elevated.

use windows::core::{Result, GUID};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{
    RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_WRITE,
    REG_OPTION_NON_VOLATILE, REG_SZ,
};

struct OverlaySlot {
    clsid: GUID,
    /// Registry key name under `ShellIconOverlayIdentifiers` — Windows
    /// only exposes a small number of overlay slots system-wide (commonly
    /// documented as 15 total, several reserved by the OS/cloud-provider
    /// API itself), so real deployments should expect to compete for a
    /// slot with other sync clients, same as OneDrive/Dropbox/Nextcloud
    /// do; nothing yadorilink-side can force a slot to be granted.
    name: &'static str,
}

const SLOTS: &[OverlaySlot] = &[
    OverlaySlot { clsid: crate::overlay::CLSID_SYNCED, name: "YadoriLinkSynced" },
    OverlaySlot { clsid: crate::overlay::CLSID_SYNCING, name: "YadoriLinkSyncing" },
    OverlaySlot { clsid: crate::overlay::CLSID_ERROR, name: "YadoriLinkError" },
    OverlaySlot { clsid: crate::overlay::CLSID_ONLINE_ONLY, name: "YadoriLinkOnlineOnly" },
];

fn guid_to_registry_string(guid: GUID) -> String {
    format!("{{{guid:?}}}")
}

fn dll_path() -> Result<String> {
    let mut buf = [0u16; 512];
    let len = unsafe {
        windows::Win32::System::LibraryLoader::GetModuleFileNameW(
            windows::Win32::Foundation::HMODULE(hmodule() as *mut _),
            &mut buf,
        )
    };
    if len == 0 {
        return Err(windows::core::Error::from_win32());
    }
    Ok(String::from_utf16_lossy(&buf[..len as usize]))
}

/// The DLL's own module handle — obtained once at load time via
/// `DllMain`, since `GetModuleFileNameW(NULL,...)` would return the
/// *host process's* (Explorer's, or regsvr32.exe's) path, not this DLL's.
///
/// A real bug found via manual verification on the Windows VM: `hmodule`
/// and `set_hmodule` each originally declared their own function-local
/// `static HMODULE`, which are two *entirely separate* static items
/// despite the identical name — Rust does not unify same-named
/// function-local statics across functions. `set_hmodule` was writing to
/// one, `hmodule` was always reading the other's untouched `0`
/// initializer, so `dll_path` always resolved to
/// `GetModuleFileNameW(NULL,...)`'s "current process" fallback — i.e.
/// regsvr32.exe's own path, not the shell extension DLL's. Registration
/// "succeeded" (the registry keys were written) but pointed
/// `InprocServer32` at regsvr32.exe, so Explorer could never actually
/// load the overlay identifiers — explaining why no overlay badge
/// appeared despite `DllRegisterServer` reporting success. Fixed by using
/// one shared, module-level static instead of two independent ones.
static HMODULE: std::sync::atomic::AtomicIsize = std::sync::atomic::AtomicIsize::new(0);

fn hmodule() -> isize {
    HMODULE.load(std::sync::atomic::Ordering::Relaxed)
}

fn set_hmodule(h: isize) {
    HMODULE.store(h, std::sync::atomic::Ordering::Relaxed);
}

/// # Safety
/// Standard `DllMain` contract — called by the OS loader.
#[no_mangle]
unsafe extern "system" fn DllMain(
    hinstance: windows::Win32::Foundation::HMODULE,
    fdw_reason: u32,
    _reserved: *mut core::ffi::c_void,
) -> windows::Win32::Foundation::BOOL {
    const DLL_PROCESS_ATTACH: u32 = 1;
    if fdw_reason == DLL_PROCESS_ATTACH {
        set_hmodule(hinstance.0 as isize);
    }
    windows::Win32::Foundation::BOOL(1)
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn set_string_value(key: HKEY, name: Option<&str>, value: &str) -> Result<()> {
    let wide_name = name.map(wide);
    let wide_value = wide(value);
    let value_bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(wide_value.as_ptr() as *const u8, wide_value.len() * 2)
    };
    // `PCWSTR::null` (a true NULL pointer, not a pointer to an empty
    // buffer) signals "the key's default value" to `RegSetValueExW` — a
    // dangling `Vec::new.as_ptr` would not be a valid null-terminated
    // string to hand the Win32 API.
    let name_ptr = match &wide_name {
        Some(w) => windows::core::PCWSTR::from_raw(w.as_ptr()),
        None => windows::core::PCWSTR::null(),
    };
    unsafe { RegSetValueExW(key, name_ptr, 0, REG_SZ, Some(value_bytes)).ok() }
}

fn create_key(parent: HKEY, subkey: &str) -> Result<HKEY> {
    let mut hkey = HKEY::default();
    let wide_subkey = wide(subkey);
    unsafe {
        let status = RegCreateKeyExW(
            parent,
            windows::core::PCWSTR::from_raw(wide_subkey.as_ptr()),
            0,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        );
        if status != ERROR_SUCCESS {
            return Err(windows::core::Error::from_win32());
        }
    }
    Ok(hkey)
}

/// Registered as a per-file-type context menu
/// handler (`*\shellex\ContextMenuHandlers`, i.e. applies to every file
/// regardless of extension) rather than a folder-specific one, since a
/// linked folder can contain any file type and every entry needs the
/// state-dependent actions the daemon offers.
const CONTEXT_MENU_NAME: &str = "YadoriLink";

pub fn register_all() -> Result<()> {
    let dll_path = dll_path()?;
    for slot in SLOTS {
        let clsid_str = guid_to_registry_string(slot.clsid);

        // HKLM\SOFTWARE\Classes\CLSID\{guid}\InprocServer32
        let clsid_key =
            create_key(HKEY_LOCAL_MACHINE, &format!("SOFTWARE\\Classes\\CLSID\\{clsid_str}"))?;
        set_string_value(clsid_key, None, "yadorilink overlay identifier")?;
        let inproc_key = create_key(
            HKEY_LOCAL_MACHINE,
            &format!("SOFTWARE\\Classes\\CLSID\\{clsid_str}\\InprocServer32"),
        )?;
        set_string_value(inproc_key, None, &dll_path)?;
        set_string_value(inproc_key, Some("ThreadingModel"), "Apartment")?;

        // HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\<name>
        let overlay_key = create_key(
            HKEY_LOCAL_MACHINE,
            &format!(
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers\\{}",
                slot.name
            ),
        )?;
        set_string_value(overlay_key, None, &clsid_str)?;
    }

    let ctx_clsid_str = guid_to_registry_string(crate::context_menu::CLSID_CONTEXT_MENU);
    let ctx_clsid_key =
        create_key(HKEY_LOCAL_MACHINE, &format!("SOFTWARE\\Classes\\CLSID\\{ctx_clsid_str}"))?;
    set_string_value(ctx_clsid_key, None, "yadorilink context menu handler")?;
    let ctx_inproc_key = create_key(
        HKEY_LOCAL_MACHINE,
        &format!("SOFTWARE\\Classes\\CLSID\\{ctx_clsid_str}\\InprocServer32"),
    )?;
    set_string_value(ctx_inproc_key, None, &dll_path)?;
    set_string_value(ctx_inproc_key, Some("ThreadingModel"), "Apartment")?;
    let ctx_handler_key = create_key(
        HKEY_LOCAL_MACHINE,
        &format!("SOFTWARE\\Classes\\*\\shellex\\ContextMenuHandlers\\{CONTEXT_MENU_NAME}"),
    )?;
    set_string_value(ctx_handler_key, None, &ctx_clsid_str)?;

    Ok(())
}

pub fn unregister_all() -> Result<()> {
    for slot in SLOTS {
        let clsid_str = guid_to_registry_string(slot.clsid);
        unsafe {
            let _ = RegDeleteTreeW(
                HKEY_LOCAL_MACHINE,
                windows::core::PCWSTR::from_raw(
                    wide(&format!("SOFTWARE\\Classes\\CLSID\\{clsid_str}")).as_ptr(),
                ),
            );
            let _ = RegDeleteTreeW(
                HKEY_LOCAL_MACHINE,
                windows::core::PCWSTR::from_raw(
                    wide(&format!(
                        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers\\{}",
                        slot.name
                    ))
                    .as_ptr(),
                ),
            );
        }
    }

    let ctx_clsid_str = guid_to_registry_string(crate::context_menu::CLSID_CONTEXT_MENU);
    unsafe {
        let _ = RegDeleteTreeW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR::from_raw(
                wide(&format!("SOFTWARE\\Classes\\CLSID\\{ctx_clsid_str}")).as_ptr(),
            ),
        );
        let _ = RegDeleteTreeW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR::from_raw(
                wide(&format!(
                    "SOFTWARE\\Classes\\*\\shellex\\ContextMenuHandlers\\{CONTEXT_MENU_NAME}"
                ))
                .as_ptr(),
            ),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    /// Manual diagnostic only — modifies real `HKEY_LOCAL_MACHINE` state on
    /// whatever machine runs it, so `#[ignore]`d rather than run by default
    /// (e.g. under `cargo test --workspace` or CI). Run explicitly with
    /// `cargo test -- --ignored` on a disposable Windows machine when
    /// registration behavior needs to be inspected directly rather than
    /// through `regsvr32`'s silent-by-default error reporting.
    #[test]
    #[ignore]
    fn debug_register_all() {
        let result = super::register_all();
        println!("register_all() result: {:?}", result);
        if let Err(e) = &result {
            println!("Error code: {:?}, message: {}", e.code(), e.message());
        }
        let _ = super::unregister_all();
    }
}
