//! A classic `IContextMenu` handler (shows
//! under Explorer's "Show more options" on Windows 11's default menu,
//! or as a primary entry pre-11/with the classic-menu policy) exposing
//! the actions the daemon says apply to the selected path (`menu_model`), calling
//! `ipc_client::send_context_action` for the same daemon operations the CLI exposes.
//! Registered per-file-type as `*\shellex\ContextMenuHandlers`.

use std::sync::Mutex;

use crate::menu_model::{menu_entries, status_deep_link, MenuEntry, MenuFacts};
use windows::core::{implement, w, Error, Result, GUID, HRESULT, PCWSTR, PSTR};
use windows::Win32::Foundation::MAX_PATH;
use windows::Win32::System::Com::{IDataObject, DVASPECT_CONTENT, FORMATETC, TYMED_HGLOBAL};
use windows::Win32::UI::Shell::{
    DragFinish, DragQueryFileW, IContextMenu, IContextMenu_Impl, IShellExtInit, IShellExtInit_Impl,
    ShellExecuteW, CMINVOKECOMMANDINFO, HDROP,
};
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, InsertMenuW, HMENU, MF_BYPOSITION, MF_SEPARATOR, MF_STRING, SW_SHOWNORMAL,
};

pub const CLSID_CONTEXT_MENU: GUID = GUID::from_u128(0x8f3a1c00_1e6b_4b7a_9d2e_1a2b3c4d5e10);

fn query_context_menu_result(command_count: u32) -> Result<()> {
    if command_count == 0 {
        Ok(())
    } else {
        // IContextMenu::QueryContextMenu reports the number of command IDs
        // consumed as MAKE_HRESULT(SEVERITY_SUCCESS, FACILITY_NULL, count).
        // windows-rs' generated trait shape is Result<>, so the only way
        // to preserve a non-S_OK success HRESULT through the COM vtable shim
        // is to carry that HRESULT in the Error slot.
        Err(Error::from_hresult(HRESULT(command_count as i32)))
    }
}

#[implement(IShellExtInit, IContextMenu)]
pub struct ContextMenuHandler {
    file_path: Mutex<Option<String>>,
    /// The entries `QueryContextMenu` added, in command-offset order.
    entries: Mutex<Vec<MenuEntry>>,
}

impl ContextMenuHandler {
    pub fn new() -> Self {
        Self { file_path: Mutex::new(None), entries: Mutex::new(Vec::new()) }
    }
}

impl Default for ContextMenuHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl IShellExtInit_Impl for ContextMenuHandler_Impl {
    fn Initialize(
        &self,
        _pidlfolder: *const windows::Win32::UI::Shell::Common::ITEMIDLIST,
        pdtobj: Option<&IDataObject>,
        _hkeyprogid: windows::Win32::System::Registry::HKEY,
    ) -> Result<()> {
        let Some(data_object) = pdtobj else { return Ok(()) };
        let format = FORMATETC {
            cfFormat: 15, // CF_HDROP
            ptd: std::ptr::null_mut(),
            dwAspect: DVASPECT_CONTENT.0,
            lindex: -1,
            tymed: TYMED_HGLOBAL.0 as u32,
        };
        unsafe {
            let Ok(medium) = data_object.GetData(&format) else { return Ok(()) };
            let hdrop = HDROP(medium.u.hGlobal.0);
            let mut buf = [0u16; MAX_PATH as usize];
            let len = DragQueryFileW(hdrop, 0, Some(&mut buf));
            if len > 0 {
                *self.file_path.lock().unwrap() =
                    Some(String::from_utf16_lossy(&buf[..len as usize]));
            }
            DragFinish(hdrop);
        }
        Ok(())
    }
}

impl IContextMenu_Impl for ContextMenuHandler_Impl {
    fn QueryContextMenu(
        &self,
        hmenu: HMENU,
        indexmenu: u32,
        idcmdfirst: u32,
        _idcmdlast: u32,
        uflags: u32,
    ) -> Result<()> {
        // CMF_DEFAULTONLY (0x0001) — Explorer is asking only for the
        // default double-click action, which this handler doesn't
        // provide; contribute nothing.
        if uflags & 0x0001 != 0 {
            return query_context_menu_result(0);
        }
        let Some(path) = self.file_path.lock().unwrap().clone() else {
            return query_context_menu_result(0);
        };
        // The daemon decides what applies; an unreachable daemon or an untracked path offers
        // nothing.
        let facts = crate::ipc_client::query_status(&path).as_ref().map(MenuFacts::from);
        let entries = menu_entries(facts);
        if entries.is_empty() {
            self.entries.lock().unwrap().clear();
            return query_context_menu_result(0);
        }
        unsafe {
            let _ = InsertMenuW(hmenu, indexmenu, MF_SEPARATOR | MF_BYPOSITION, 0, PCWSTR::null());
            for (offset, entry) in entries.iter().enumerate() {
                let wide: Vec<u16> =
                    entry.label().encode_utf16().chain(std::iter::once(0)).collect();
                let _ = AppendMenuW(
                    hmenu,
                    MF_STRING,
                    (idcmdfirst + offset as u32) as usize,
                    PCWSTR::from_raw(wide.as_ptr()),
                );
            }
        }
        let command_count = entries.len() as u32;
        *self.entries.lock().unwrap() = entries;
        query_context_menu_result(command_count)
    }

    fn InvokeCommand(&self, pici: *const CMINVOKECOMMANDINFO) -> Result<()> {
        let Some(path) = self.file_path.lock().unwrap().clone() else { return Ok(()) };
        unsafe {
            let info = &*pici;
            // `lpVerb` is either an integer command offset (low-order
            // word, when the high-order word is zero) or a string verb —
            // this handler only ever registers integer offsets.
            if (info.lpVerb.0 as usize) > 0xFFFF {
                return Ok(());
            }
            let cmd_offset = info.lpVerb.0 as usize;
            let entry = self.entries.lock().unwrap().get(cmd_offset).copied();
            match entry {
                Some(MenuEntry::ViewStatus) => open_status(&path),
                Some(entry) => {
                    if let Some(action) = entry.daemon_action() {
                        // Fire-and-forget: Explorer's context menu invocation is not the place
                        // to block on IPC or show a result dialog (fail-soft contract).
                        let _ = crate::ipc_client::send_context_action(&path, action);
                    }
                }
                None => {}
            }
        }
        Ok(())
    }

    fn GetCommandString(
        &self,
        _idcmd: usize,
        _uflags: u32,
        _preserved: *const u32,
        _pszname: PSTR,
        _cchmax: u32,
    ) -> Result<()> {
        Ok(())
    }
}

/// Opens the app at `path` through the registered `yadorilink://` handler (never a binary found
/// on PATH). Fail-soft: no handler registered simply opens nothing.
fn open_status(path: &str) {
    let link: Vec<u16> = status_deep_link(path).encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let _ = ShellExecuteW(
            None,
            w!("open"),
            PCWSTR::from_raw(link.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        );
    }
}
