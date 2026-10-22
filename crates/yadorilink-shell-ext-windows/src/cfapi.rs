//! Windows Cloud Filter API (cfapi) integration.
//! Runs inside the `yadorilink-cfapi-host` binary (see Cargo.toml's
//! `[[bin]]` doc comment for why this is a separate process from the
//! `yadorilink_shell_ext` COM DLL), not the shell extension DLL itself.
//!
//! Scope/known limitations, stated up front rather than discovered late:
//! - MVP hydrates whole files only (no byte-range
//!   hydration), so the sync root's `Hydration` policy is `FULL` and the
//!   fetch-data callback always serves the entire file regardless of the
//!   OS-requested range.
//! - Nested directories under an OnDemand folder are ordinary
//!   (non-placeholder) directories, not lazily-populated placeholder
//!   directories — `CfCreatePlaceholders` is only used for files. This
//!   matches the design's file-level (not directory-listing-level)
//!   on-demand scope. This process never creates them: the daemon does,
//!   before it records the placeholder this process places, and records
//!   each one it makes only to hold a descendant, so local capture never
//!   mistakes it for a directory a user made. A placeholder whose parent
//!   is not placed yet is skipped and placed on a later poll.
//! - A placeholder's `FileIdentity` blob carries only the relative path
//!   as an opaque marker, not real block/version state: `CfCreatePlaceholders`
//!   documents `FileIdentity` as *mandatory for files* (confirmed the hard
//!   way — a null/empty identity fails with
//!   `ERROR_CLOUD_FILE_INVALID_REQUEST`, 0x8007017C, verified against real
//!   cfapi on a Windows 11 VM), so it can't be omitted; the daemon remains
//!   the sole source of truth for block/version state, looked up by path
//!   over shell-IPC in the fetch callback rather than decoded from this
//!   blob, avoiding a second, potentially-stale copy of that state.
//! - `hydration::hydrate` (the daemon-side function this ultimately
//!   drives, over shell-IPC's `HydrateRequest`) writes a placeholder's
//!   real content by reconstructing to a temp file and rename-replacing
//!   the target (`yadorilink_sync_core::chunker::reconstruct_file`) — this
//!   was written and tested against the platform-neutral placeholder
//!   representation on a non-Windows dev machine, not against
//!   a real cfapi reparse-point placeholder. A rename-replace over a file
//!   with an in-flight `CF_CALLBACK_TYPE_FETCH_DATA` callback is expected
//!   to work (the placeholder's reparse point and sparse ranges are
//!   simply replaced by an ordinary, fully-present file, which is a
//!   documented-valid way for a provider to "finish" a placeholder), but
//!   this specific interaction has NOT been exercised against a live
//!   Explorer file-open on real hardware.

use std::collections::HashMap;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use windows::core::{Result as WinResult, GUID, PCWSTR};
use windows::Win32::Foundation::{NTSTATUS, STATUS_SUCCESS, STATUS_UNSUCCESSFUL};
use windows::Win32::Storage::CloudFilters::{
    CfConnectSyncRoot, CfCreatePlaceholders, CfDisconnectSyncRoot, CfExecute,
    CfGetSyncRootInfoByPath, CfRegisterSyncRoot, CfUnregisterSyncRoot, CF_CALLBACK_INFO,
    CF_CALLBACK_PARAMETERS, CF_CALLBACK_REGISTRATION, CF_CALLBACK_TYPE_CANCEL_FETCH_DATA,
    CF_CALLBACK_TYPE_FETCH_DATA, CF_CALLBACK_TYPE_NONE, CF_CONNECT_FLAG_NONE, CF_CREATE_FLAG_NONE,
    CF_HARDLINK_POLICY_NONE, CF_HYDRATION_POLICY, CF_HYDRATION_POLICY_FULL,
    CF_HYDRATION_POLICY_MODIFIER_NONE, CF_INSYNC_POLICY_TRACK_ALL, CF_OPERATION_INFO,
    CF_OPERATION_PARAMETERS, CF_OPERATION_PARAMETERS_0, CF_OPERATION_PARAMETERS_0_6,
    CF_OPERATION_TRANSFER_DATA_FLAG_NONE, CF_OPERATION_TYPE_TRANSFER_DATA,
    CF_PLACEHOLDER_CREATE_FLAG_DISABLE_ON_DEMAND_POPULATION,
    CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC, CF_PLACEHOLDER_CREATE_INFO,
    CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT, CF_POPULATION_POLICY,
    CF_POPULATION_POLICY_ALWAYS_FULL, CF_POPULATION_POLICY_MODIFIER_NONE,
    CF_POPULATION_POLICY_PARTIAL, CF_REGISTER_FLAG_NONE, CF_REGISTER_FLAG_UPDATE, CF_SYNC_POLICIES,
    CF_SYNC_REGISTRATION, CF_SYNC_ROOT_INFO_STANDARD, CF_SYNC_ROOT_STANDARD_INFO,
};
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_BASIC_INFO,
};
use yadorilink_fs_platform::durable_dir::{move_durably, NameLedger, Replace};
use yadorilink_fs_platform::reserved_namespace::{artefact_component_name, ArtefactKind};

use crate::windowed_fetch;

/// Fixed provider identity. Namespace-derived, like the
/// overlay CLSIDs in `overlay.rs` — a real release would hand-pick and
/// never regenerate this, since `CfRegisterSyncRoot` ties a sync root's
/// registration to this GUID.
const PROVIDER_ID: GUID = GUID::from_u128(0x8f3a1c00_1e6b_4b7a_9d2e_1a2b3c4d5e20);
const PROVIDER_NAME: &str = "yadorilink";
const PROVIDER_VERSION: &str = env!("CARGO_PKG_VERSION");

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A connected sync root: where it is, and, for a provider root, the root id the daemon declared.
#[derive(Clone)]
struct ConnectedRoot {
    path: PathBuf,
    provider_root: Option<Vec<u8>>,
}

/// connection key (`CF_CONNECTION_KEY.0`) -> the connected root, so the fetch-data callback (a
/// bare `extern "system" fn` with no way to receive a closure environment) can resolve
/// `CF_CALLBACK_INFO::NormalizedPath` (relative to the sync root) back to an absolute path or a
/// provider root. Also indexed the other way (`KEYS_BY_ROOT`) so `disconnect`/`unregister` can
/// look up a root's connection key by path — needed because `CfUnregisterSyncRoot` documents
/// failing with `ERROR_CLOUD_FILE_INVALID_REQUEST` if a provider is still connected (confirmed
/// the hard way against real cfapi), so unregistering this process's own connection must
/// disconnect it first.
static ROOTS_BY_CONNECTION: Mutex<Option<HashMap<i64, ConnectedRoot>>> = Mutex::new(None);
static KEYS_BY_ROOT: Mutex<Option<HashMap<PathBuf, i64>>> = Mutex::new(None);

fn register_root(key: i64, local_path: &Path, provider_root: Option<Vec<u8>>) {
    ROOTS_BY_CONNECTION
        .lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .insert(key, ConnectedRoot { path: local_path.to_path_buf(), provider_root });
    KEYS_BY_ROOT
        .lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .insert(local_path.to_path_buf(), key);
}

fn connected_root(key: i64) -> Option<ConnectedRoot> {
    ROOTS_BY_CONNECTION.lock().unwrap().as_ref()?.get(&key).cloned()
}

fn root_for_connection(key: i64) -> Option<PathBuf> {
    connected_root(key).map(|root| root.path)
}

fn take_key_for_root(local_path: &Path) -> Option<i64> {
    let key = KEYS_BY_ROOT.lock().unwrap().as_mut()?.remove(local_path)?;
    ROOTS_BY_CONNECTION.lock().unwrap().as_mut().map(|m| m.remove(&key));
    Some(key)
}

/// Whether this process holds a connection for the sync root at `local_path`.
pub fn is_connected(local_path: &Path) -> bool {
    KEYS_BY_ROOT.lock().unwrap().as_ref().is_some_and(|keys| keys.contains_key(local_path))
}

/// Converts Unix nanoseconds since the epoch (`FileRecord::mtime_unix_nanos`)
/// to a Windows `FILETIME`-style tick count (100ns intervals since
/// 1601-01-01), as `FILE_BASIC_INFO`'s fields expect.
fn unix_nanos_to_filetime_ticks(unix_nanos: i64) -> i64 {
    const UNIX_EPOCH_IN_FILETIME_TICKS: i64 = 116_444_736_000_000_000;
    unix_nanos / 100 + UNIX_EPOCH_IN_FILETIME_TICKS
}

/// Diagnostics only (debug builds): `YADORILINK_CFAPI_HYDRATION_POLICY=partial|progressive` selects
/// another hydration policy for an experiment; release builds and the default are always `FULL`.
fn experiment_hydration_policy(
) -> windows::Win32::Storage::CloudFilters::CF_HYDRATION_POLICY_PRIMARY {
    use windows::Win32::Storage::CloudFilters::{
        CF_HYDRATION_POLICY_PARTIAL, CF_HYDRATION_POLICY_PROGRESSIVE,
    };
    if cfg!(debug_assertions) {
        match std::env::var("YADORILINK_CFAPI_HYDRATION_POLICY").as_deref() {
            Ok("partial") => return CF_HYDRATION_POLICY_PARTIAL,
            Ok("progressive") => return CF_HYDRATION_POLICY_PROGRESSIVE,
            _ => {}
        }
    }
    CF_HYDRATION_POLICY_FULL
}

/// Registers `local_path` as a Cloud Filter API sync root and
/// connects it, wiring up the `CF_CALLBACK_TYPE_FETCH_DATA` handler.
/// Idempotent-ish: `CfRegisterSyncRoot` itself tolerates
/// re-registering the same root (it's meant to be called on every
/// provider startup, not just the first time — this is the documented
/// pattern, not a workaround).
///
/// Hydration policy is `FULL` (whole-file only — no partial/byte-range
/// hydration in this MVP) and population policy is `PARTIAL` (the
/// provider, not the OS, controls
/// which files are placeholders vs. fully present, which is exactly the
/// OnDemand model).
pub fn register_and_connect(local_path: &Path) -> WinResult<()> {
    register_and_connect_root(local_path, None)
}

/// Registers and connects the sync root of a provider root. The root id is stored in the
/// registration as the sync root identity, so the registration itself says which declared root it
/// serves.
pub fn register_and_connect_provider(root_id: &[u8], local_path: &Path) -> WinResult<()> {
    register_and_connect_root(local_path, Some(root_id))
}

fn register_and_connect_root(local_path: &Path, provider_root: Option<&[u8]>) -> WinResult<()> {
    let path_wide = wide(&local_path.to_string_lossy());
    let provider_name_wide = wide(PROVIDER_NAME);
    let provider_version_wide = wide(PROVIDER_VERSION);

    let registration = CF_SYNC_REGISTRATION {
        StructSize: std::mem::size_of::<CF_SYNC_REGISTRATION>() as u32,
        ProviderName: PCWSTR::from_raw(provider_name_wide.as_ptr()),
        ProviderVersion: PCWSTR::from_raw(provider_version_wide.as_ptr()),
        SyncRootIdentity: provider_root.map_or(std::ptr::null(), |id| id.as_ptr().cast()),
        SyncRootIdentityLength: provider_root.map_or(0, |id| id.len() as u32),
        FileIdentity: std::ptr::null(),
        FileIdentityLength: 0,
        ProviderId: PROVIDER_ID,
    };

    let policies = CF_SYNC_POLICIES {
        StructSize: std::mem::size_of::<CF_SYNC_POLICIES>() as u32,
        Hydration: CF_HYDRATION_POLICY {
            Primary: experiment_hydration_policy(),
            Modifier: CF_HYDRATION_POLICY_MODIFIER_NONE,
        },
        Population: CF_POPULATION_POLICY {
            // A provider root is populated by the host itself (every folder is created fully
            // populated), so the operating system never waits for a population callback.
            Primary: if provider_root.is_some() {
                CF_POPULATION_POLICY_ALWAYS_FULL
            } else {
                CF_POPULATION_POLICY_PARTIAL
            },
            Modifier: CF_POPULATION_POLICY_MODIFIER_NONE,
        },
        InSync: CF_INSYNC_POLICY_TRACK_ALL,
        HardLink: CF_HARDLINK_POLICY_NONE,
        PlaceholderManagement: CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT,
    };

    // A root registered by an earlier run of this host (or by the previous version of the
    // registration) is updated in place; a new one is registered.
    unsafe {
        if CfRegisterSyncRoot(
            PCWSTR::from_raw(path_wide.as_ptr()),
            &registration,
            &policies,
            CF_REGISTER_FLAG_UPDATE,
        )
        .is_err()
        {
            CfRegisterSyncRoot(
                PCWSTR::from_raw(path_wide.as_ptr()),
                &registration,
                &policies,
                CF_REGISTER_FLAG_NONE,
            )?;
        }
    }

    // Sentinel-terminated array: a `CF_CALLBACK_TYPE_NONE` entry marks the
    // end, per the documented `CfConnectSyncRoot` contract.
    let callbacks = [
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_FETCH_DATA,
            Callback: Some(fetch_data_callback),
        },
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_CANCEL_FETCH_DATA,
            Callback: Some(cancel_fetch_data_callback),
        },
        CF_CALLBACK_REGISTRATION { Type: CF_CALLBACK_TYPE_NONE, Callback: None },
    ];

    let key = unsafe {
        CfConnectSyncRoot(
            PCWSTR::from_raw(path_wide.as_ptr()),
            callbacks.as_ptr(),
            None,
            CF_CONNECT_FLAG_NONE,
        )?
    };
    register_root(key.0, local_path, provider_root.map(<[u8]>::to_vec));
    Ok(())
}

/// Disconnects this process's `CfConnectSyncRoot` connection for
/// `local_path`, if one was made via `register_and_connect` earlier in
/// this same process. A no-op (returns `Ok()`) if this process never
/// connected to that root — connections are per-process, so there is
/// nothing for *this* process to disconnect in that case.
pub fn disconnect(local_path: &Path) -> WinResult<()> {
    let Some(key) = take_key_for_root(local_path) else { return Ok(()) };
    unsafe { CfDisconnectSyncRoot(windows::Win32::Storage::CloudFilters::CF_CONNECTION_KEY(key)) }
}

/// Unregisters a sync root (the uninstall path).
///
/// `CfUnregisterSyncRoot` is documented to fail with
/// `ERROR_CLOUD_FILE_INVALID_REQUEST` if a sync provider is still
/// connected to the root (confirmed against real cfapi on a Windows 11
/// VM) — this disconnects first if *this process* holds a connection for
/// `local_path`. It does NOT reach into another process's connection:
/// the real long-lived `yadorilink-cfapi-host` process holds the actual
/// production connection, so callers driving the uninstall flow (like
/// `install.ps1`) must stop that process/its Scheduled Task before
/// calling this, not after — a connection is tied to process lifetime,
/// so stopping the process itself also tears down its connection.
pub fn unregister(local_path: &Path) -> WinResult<()> {
    let _ = disconnect(local_path);
    let path_wide = wide(&local_path.to_string_lossy());
    unsafe { CfUnregisterSyncRoot(PCWSTR::from_raw(path_wide.as_ptr())) }
}

/// The identity this host stored when it registered the sync root of `path`. `Ok(None)`: `path`
/// is not under a sync root. A root of another provider is an error: it is not this host's to touch.
pub fn registered_root_identity(path: &Path) -> Result<Option<Vec<u8>>, String> {
    const IDENTITY_ROOM: usize = 1024;
    let path_wide = wide(&path.to_string_lossy());
    let header = std::mem::size_of::<CF_SYNC_ROOT_STANDARD_INFO>();
    // 8-byte aligned storage for the variable length structure.
    let mut buffer = vec![0u64; (header + IDENTITY_ROOM).div_ceil(8)];
    let result = unsafe {
        CfGetSyncRootInfoByPath(
            PCWSTR::from_raw(path_wide.as_ptr()),
            CF_SYNC_ROOT_INFO_STANDARD,
            buffer.as_mut_ptr().cast(),
            (buffer.len() * 8) as u32,
            None,
        )
    };
    match result {
        Ok(()) => {}
        Err(e) if e.code() == windows::core::HRESULT(0x8007_0186_u32 as i32) => return Ok(None),
        Err(e) => return Err(format!("{e:?}")),
    }
    let info = unsafe { &*buffer.as_ptr().cast::<CF_SYNC_ROOT_STANDARD_INFO>() };
    let name_len = info.ProviderName.iter().position(|&c| c == 0).unwrap_or(0);
    if String::from_utf16_lossy(&info.ProviderName[..name_len]) != PROVIDER_NAME {
        return Err("registered by another provider".into());
    }
    let length = info.SyncRootIdentityLength as usize;
    if length > IDENTITY_ROOM {
        return Err("the sync root identity is longer than expected".into());
    }
    let identity = unsafe {
        std::slice::from_raw_parts(std::ptr::addr_of!(info.SyncRootIdentity).cast::<u8>(), length)
    };
    Ok(Some(identity.to_vec()))
}

/// Encodes `generation` -- a `u64` the DAEMON mints and persists -- as the
/// generation-token identity blob: 1 version-tag byte (`1`) followed by the 8-byte
/// little-endian `u64`. Only the round-trip tests of [`decode_generation_identity`] build one
/// now (this host no longer creates generation-identity placeholders; provider items carry an
/// item identity), but the daemon's reader still has to recognise the format.
#[cfg(test)]
fn encode_generation_identity(generation: u64) -> [u8; 9] {
    const VERSION_TAG: u8 = 1;
    let mut buf = [0u8; 9];
    buf[0] = VERSION_TAG;
    buf[1..9].copy_from_slice(&generation.to_le_bytes());
    buf
}

/// Reads a generation-token identity blob. Duplicated from
/// `yadorilink_daemon::placeholder_inspect_windows::decode_generation_identity`
/// rather than shared (this crate must not depend on `yadorilink-daemon` --
/// see `windows_pipe_security.rs`'s own doc comment for the same
/// reasoning); kept byte-for-byte identical to that copy since both decode
/// the same wire format this module's own test encoder
/// defines.
fn decode_generation_identity(bytes: &[u8]) -> Option<u64> {
    const VERSION_TAG: u8 = 1;
    if bytes.len() != 9 || bytes[0] != VERSION_TAG {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[1..9]);
    Some(u64::from_le_bytes(buf))
}

/// The tag of the identity blob of a provider item's placeholder (see [`decode_generation_identity`]
/// for the other tag): the tag byte, then the item id exactly as the daemon issued it.
const ITEM_IDENTITY_TAG: u8 = 2;
/// The longest item id this host accepts in an identity blob.
const MAX_ITEM_ID_BYTES: usize = 64;

/// The `FileIdentity` blob of the placeholder of provider item `item_id`.
pub fn encode_item_identity(item_id: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(1 + item_id.len());
    blob.push(ITEM_IDENTITY_TAG);
    blob.extend_from_slice(item_id);
    blob
}

/// The item id inside an identity blob, or `None` when the blob is not a provider item's.
pub fn decode_item_identity(bytes: &[u8]) -> Option<&[u8]> {
    match bytes.split_first() {
        Some((&ITEM_IDENTITY_TAG, item_id))
            if !item_id.is_empty() && item_id.len() <= MAX_ITEM_ID_BYTES =>
        {
            Some(item_id)
        }
        _ => None,
    }
}

/// Native Windows eviction. First verifies the placeholder
/// currently at `path` still carries exactly the `expected` generation (an ABA guard against dehydrating a placeholder that
/// was deleted and replaced by an unrelated one at the same path since the
/// daemon last read its index -- same defense-in-depth reasoning as
/// `placeholder_inspect_windows::inspect_placeholder`'s own identity
/// check), then calls `CfDehydratePlaceholder` to discard the placeholder's
/// local content while leaving the placeholder object (and its identity)
/// in place. This is the Windows counterpart to `write_placeholder` on
/// Unix, except the real on-disk dehydration happens HERE, synchronously,
/// in THIS process (the one actually connected to the sync root) --
/// unlike placeholder CREATION, which is deferred to a future
/// `sync_placeholders` poll, eviction cannot be fire-and-forget: the
/// caller (`dehydrate_server`) only reports success back to the daemon
/// once this function has actually confirmed the dehydrate call
/// succeeded, and the daemon gates block reclamation on that confirmation.
/// Runs in `yadorilink-cfapi-host.exe`.
///
/// Uses `windows-sys` rather than the `windows` crate the rest of this
/// file uses -- see `Cargo.toml`'s doc comment on the `windows-sys`
/// dependency for why: `CfGetPlaceholderInfo`/`CfDehydratePlaceholder`
/// have never been called through the `windows` crate anywhere in this
/// codebase, but the SAME `windows-sys` incantations this function reuses
/// (open a `FILE_FLAG_OPEN_REPARSE_POINT` handle, `CfGetPlaceholderInfo`
/// with a headroom buffer, raw HRESULT checks) are already proven working
/// against real cfapi on a Windows 11 VM in `yadorilink-daemon::
/// placeholder_inspect_windows`.
pub fn dehydrate_placeholder(path: &Path, expected: u64) -> Result<(), String> {
    use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Storage::CloudFilters::{
        CfDehydratePlaceholder, CfGetPlaceholderInfo, CF_DEHYDRATE_FLAG_NONE,
        CF_PLACEHOLDER_BASIC_INFO, CF_PLACEHOLDER_INFO_BASIC,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    let wide_path = wide(&yadorilink_fs_platform::long_path::for_win32(path).to_string_lossy());
    // SAFETY: `wide_path` is a valid NUL-terminated UTF-16 buffer for the
    // duration of this call. `GENERIC_READ | GENERIC_WRITE`: dehydrating
    // mutates the placeholder's population state, unlike a read-only
    // identity/in-sync query (which only needs `FILE_READ_ATTRIBUTES`, see
    // `placeholder_inspect_windows::open_reparse_handle_read_attributes`).
    // `FILE_FLAG_OPEN_REPARSE_POINT` so opening an already-partially-
    // dehydrated placeholder never itself triggers a hydration.
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle.is_null() || handle as isize == -1 {
        return Err(format!(
            "CreateFileW failed opening {} for dehydration: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    let close = || unsafe {
        CloseHandle(handle);
    };

    const IDENTITY_HEADROOM: usize = 64;
    let mut buf = vec![0u8; std::mem::size_of::<CF_PLACEHOLDER_BASIC_INFO>() + IDENTITY_HEADROOM];
    let mut returned: u32 = 0;
    // SAFETY: `handle` is a valid, open handle; `buf` is sized to hold
    // at least a full `CF_PLACEHOLDER_BASIC_INFO` plus headroom for
    // the trailing identity bytes -- mirrors `placeholder_inspect_
    // windows::read_placeholder_identity` exactly.
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
        close();
        return Err(format!(
            "CfGetPlaceholderInfo failed for {} before dehydrate: HRESULT {hr:#x}",
            path.display()
        ));
    }
    // SAFETY: the call above reported success, so at least
    // `size_of::<CF_PLACEHOLDER_BASIC_INFO>()` bytes of `buf` are
    // valid; `read_unaligned` does not require alignment.
    let info: CF_PLACEHOLDER_BASIC_INFO =
        unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const CF_PLACEHOLDER_BASIC_INFO) };
    let identity_offset = std::mem::offset_of!(CF_PLACEHOLDER_BASIC_INFO, FileIdentity);
    let len = info.FileIdentityLength as usize;
    let decoded = identity_offset
        .checked_add(len)
        .filter(|&end| end <= buf.len())
        .and_then(|_| decode_generation_identity(&buf[identity_offset..identity_offset + len]));
    if decoded != Some(expected) {
        close();
        return Err(format!(
            "{} identity mismatch before dehydrate: expected generation {expected}, found {decoded:?}",
            path.display()
        ));
    }

    // SAFETY: `handle` is a valid, open, writable handle to the
    // placeholder at `path`. `StartingOffset: 0, Length: i64::MAX`
    // dehydrates the entire file -- this MVP's `Hydration: FULL` policy
    // (module doc) means there is never a partial range to preserve.
    let hr = unsafe {
        CfDehydratePlaceholder(handle, 0, i64::MAX, CF_DEHYDRATE_FLAG_NONE, std::ptr::null_mut())
    };
    close();
    if hr < 0 {
        return Err(format!(
            "CfDehydratePlaceholder failed for {}: HRESULT {hr:#x}",
            path.display()
        ));
    }
    Ok(())
}

/// Creates the placeholder of a provider item named `name` below the existing directory
/// `parent_dir`. The identity blob is the item's tag and id (see [`encode_item_identity`]). A
/// directory is created as fully populated (this host fills its children itself), so the
/// operating system never asks for a population callback this host does not serve.
///
/// `CfCreatePlaceholders` has no write-through flag, so the placeholder is made under a Stage
/// name beside `name` and moved to `name` by the durable no-replace move (verified:
/// the placeholder keeps its identity, size and
/// dehydrated state across that move and a directory placeholder still takes children, but the
/// rename clears the in-sync bit, which is set again right after).
///
/// The Stage path is recorded in `ledger` (durably) BEFORE the placeholder exists, and the
/// record is dropped only once the name is gone for good (after the move). A crash anywhere in
/// between leaves a record, and the next walk's recovery ([`crate::stage_ledger`]) retires
/// exactly the recorded path: nothing is ever concluded from a name's shape. A name that is
/// taken fails the move; the Stage placeholder is then removed, and its record is kept (an
/// unlink is not proven durable) for the recovery to drop once it finds the path absent. A
/// crash (or a failed mark) between the move and the in-sync mark leaves a placeholder the next
/// walk marks in sync.
pub fn create_item_placeholder(
    ledger: &dyn NameLedger,
    parent_dir: &Path,
    name: &str,
    item_id: &[u8],
    size: u64,
    mtime_unix_nanos: i64,
    directory: bool,
) -> Result<(), String> {
    let stage = stage_name();
    let (from, to) = (parent_dir.join(&stage), parent_dir.join(name));
    ledger.record(&from).map_err(|error| format!("recording the Stage placeholder: {error}"))?;
    stage_failpoint(StageStep::Recorded)?;
    create_item_placeholder_at(parent_dir, &stage, item_id, size, mtime_unix_nanos, directory)
        .map_err(|error| format!("CfCreatePlaceholders: {error}"))?;
    stage_failpoint(StageStep::Created)?;
    if let Err(error) = move_durably(&from, &to, Replace::No) {
        // Best effort, non-recursive; the record stays for the recovery either way.
        let _ = if directory { std::fs::remove_dir(&from) } else { std::fs::remove_file(&from) };
        return Err(format!("publishing the placeholder as {name:?}: {error}"));
    }
    stage_failpoint(StageStep::Moved)?;
    // The Stage name is gone by the durable move.
    ledger.release(&from);
    // The move cleared the in-sync bit (E8). The name is the user's to use by now, so a failure to
    // set the bit again removes nothing: the create has failed, and the next walk finds the
    // placeholder of this item at its name and marks it.
    crate::provider_namespace::mark_in_sync(&to)
        .map_err(|error| format!("marking the new placeholder {name:?} in sync: {error}"))
}

/// A step of [`create_item_placeholder`] after which a test stops it as a killed process would.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum StageStep {
    Recorded,
    Created,
    Moved,
}

#[cfg(test)]
thread_local! {
    pub(crate) static STAGE_FAILPOINT: std::cell::Cell<Option<StageStep>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn stage_failpoint(point: StageStep) -> Result<(), String> {
    if STAGE_FAILPOINT.with(|armed| armed.get()) == Some(point) {
        return Err(format!("killed at {point:?}"));
    }
    Ok(())
}
#[cfg(not(test))]
fn stage_failpoint(_: StageStep) -> Result<(), String> {
    Ok(())
}

/// A fresh reserved Stage name: unique across restarts of this process and within it.
fn stage_name() -> String {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let id = format!(
        "{}-{nanos}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    artefact_component_name(ArtefactKind::Stage, &id).expect("a numeric id is a valid artefact id")
}

/// The placeholder of a provider item created directly under `name` (no Stage step).
pub(crate) fn create_item_placeholder_at(
    parent_dir: &Path,
    name: &str,
    item_id: &[u8],
    size: u64,
    mtime_unix_nanos: i64,
    directory: bool,
) -> WinResult<()> {
    let identity = encode_item_identity(item_id);
    create_placeholder_entry(parent_dir, name, size, mtime_unix_nanos, &identity, directory)
}

fn create_placeholder_entry(
    base_dir: &Path,
    file_name: &str,
    size: u64,
    mtime_unix_nanos: i64,
    file_identity: &[u8],
    directory: bool,
) -> WinResult<()> {
    // The base directory can be deep in the user's tree; a path past MAX_PATH takes the verbatim
    // spelling (`for_win32` leaves a short one alone).
    let base_dir_wide =
        wide(&yadorilink_fs_platform::long_path::for_win32(base_dir).to_string_lossy());
    let file_name_wide = wide(file_name);
    let ticks = unix_nanos_to_filetime_ticks(mtime_unix_nanos);

    // `FileIdentity` is documented as a *mandatory* field for files (not
    // directories) in `CfCreatePlaceholders` — a null/empty identity fails
    // with `ERROR_CLOUD_FILE_INVALID_REQUEST` (0x8007017C), confirmed
    // against real cfapi on a Windows 11 VM. The fetch-data callback still
    // resolves hydration data by looking up the path via shell-IPC (not by
    // decoding this blob) — this is not duplicated block/version state,
    // just enough of an opaque identity to satisfy the API contract AND
    // let `yadorilink-daemon`'s Windows dirty-detection reader
    // (`placeholder_inspect_windows::inspect_placeholder`) confirm a
    // placeholder is still the exact one the daemon expects.
    let mut entries = [CF_PLACEHOLDER_CREATE_INFO {
        RelativeFileName: PCWSTR::from_raw(file_name_wide.as_ptr()),
        FsMetadata: windows::Win32::Storage::CloudFilters::CF_FS_METADATA {
            BasicInfo: FILE_BASIC_INFO {
                CreationTime: ticks,
                LastAccessTime: ticks,
                LastWriteTime: ticks,
                ChangeTime: ticks,
                FileAttributes: if directory {
                    FILE_ATTRIBUTE_DIRECTORY.0
                } else {
                    FILE_ATTRIBUTE_NORMAL.0
                },
            },
            FileSize: if directory { 0 } else { size as i64 },
        },
        FileIdentity: file_identity.as_ptr() as *const c_void,
        FileIdentityLength: file_identity.len() as u32,
        // MARK_IN_SYNC (not ported: `ALWAYS_FULL`): a freshly created
        // placeholder is, by definition, untouched by any local writer --
        // "in sync" tracks local-modification state, orthogonal to
        // population/hydration state (`Population: PARTIAL`, set on this
        // sync root's own registration above, already governs whether
        // content is present; `MARK_IN_SYNC` at creation is honored on
        // its own -- `InSync: CF_INSYNC_POLICY_TRACK_ALL`, also already
        // set on that registration, instead governs which *subsequent*
        // filesystem changes clear the in-sync bit, not whether it's
        // honored at creation time). Deliberately does NOT also port
        // `CF_PLACEHOLDER_CREATE_FLAG_ALWAYS_FULL` from the dead
        // backend: that flag existed there specifically to compensate for
        // having NO `FETCH_DATA` callback registered (an ordinary local
        // write into an unpopulated placeholder byte range otherwise
        // times out waiting for a fetch that would never come) -- this
        // module already registers a real one (`fetch_data_callback`
        // above), so lazy population must stay genuinely lazy; forcing
        // `ALWAYS_FULL` here would defeat the whole point of On-Demand.
        //
        // UNVERIFIED against real hardware (flagged honestly, matching
        // this module's own doc-comment convention): `MARK_IN_SYNC`
        // combined with `Population: PARTIAL` and a real `FETCH_DATA`
        // callback has not been exercised on a live Windows machine in
        // this codebase yet -- only the dead backend's OWN combination
        // (`MARK_IN_SYNC | ALWAYS_FULL`, no fetch callback) was
        // empirically confirmed working.
        Flags: if directory {
            CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC
                | CF_PLACEHOLDER_CREATE_FLAG_DISABLE_ON_DEMAND_POPULATION
        } else {
            CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC
        },
        Result: windows::Win32::Foundation::S_OK,
        CreateUsn: 0,
    }];

    unsafe {
        CfCreatePlaceholders(
            PCWSTR::from_raw(base_dir_wide.as_ptr()),
            &mut entries,
            CF_CREATE_FLAG_NONE,
            None,
        )?;
    }
    entries[0].Result.ok()
}

/// The `CF_CALLBACK_TYPE_FETCH_DATA` handler: invoked by the
/// Cloud Filter driver, on an OS threadpool thread, whenever an
/// application's read reaches a dehydrated range of a placeholder under
/// one of this process's connected sync roots. Must always end by calling
/// `CfExecute(..., CF_OPERATION_TYPE_TRANSFER_DATA,...)` — that call is
/// what unblocks the application's blocked `ReadFile`, whether hydration
/// succeeded or not (: a bounded failure, never a hang).
unsafe extern "system" fn fetch_data_callback(
    callback_info: *const CF_CALLBACK_INFO,
    callback_parameters: *const CF_CALLBACK_PARAMETERS,
) {
    let info = &*callback_info;
    let params = &*callback_parameters;
    trace_fetch_entry(info, params);
    // Safety: `CF_CALLBACK_TYPE_FETCH_DATA` guarantees the `FetchData` union arm is the active
    // one, per the documented callback contract.
    let fetch = params.Anonymous.FetchData;

    let identity: &[u8] = if info.FileIdentity.is_null() || info.FileIdentityLength == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(info.FileIdentity.cast::<u8>(), info.FileIdentityLength as usize)
    };
    if let Some(item_id) = decode_item_identity(identity) {
        fetch_provider_item(info, fetch.RequiredFileOffset, fetch.RequiredLength, item_id);
        return;
    }

    let full_path = root_for_connection(info.ConnectionKey.0).map(|root| {
        let normalized = info.NormalizedPath.to_string().unwrap_or_default();
        let relative = normalized.trim_start_matches(['\\', '/']);
        root.join(relative)
    });

    let path_str = full_path.as_ref().and_then(|p| p.to_str().map(str::to_string));

    // Whole-file hydration only (module doc): request the daemon hydrate
    // the entire file, then serve the entire (now-real) file content back
    // to cfapi regardless of the specific offset/length the OS callback
    // asked for, since our sync policy only ever requests full files.
    let ok = path_str.as_deref().map(crate::ipc_client::hydrate).unwrap_or(false);

    let (buffer, status): (Vec<u8>, NTSTATUS) = if ok {
        match path_str.as_deref().map(std::fs::read) {
            Some(Ok(bytes)) => (bytes, STATUS_SUCCESS),
            _ => (Vec::new(), STATUS_UNSUCCESSFUL),
        }
    } else {
        (Vec::new(), STATUS_UNSUCCESSFUL)
    };

    let length = if status == STATUS_SUCCESS { buffer.len() as i64 } else { fetch.RequiredLength };
    let _ = transfer_data(info, status, &buffer, 0, length);
}

/// Diagnostics only: when `YADORILINK_CFAPI_TRACE` names a file, appends one line per callback
/// entry (before any daemon call) with the requested range and the requesting process id.
unsafe fn trace_fetch_entry(info: &CF_CALLBACK_INFO, params: &CF_CALLBACK_PARAMETERS) {
    use std::io::Write;
    let Some(path) = std::env::var_os("YADORILINK_CFAPI_TRACE") else { return };
    let fetch = params.Anonymous.FetchData;
    let line = format!(
        "fetch_entry t={:?} pid={} offset={} length={} identity_len={}\n",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default(),
        info.ProcessInfo.as_ref().map_or(0, |p| p.ProcessId),
        fetch.RequiredFileOffset,
        fetch.RequiredLength,
        info.FileIdentityLength,
    );
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(line.as_bytes());
    }
}

/// One `CfExecute(TRANSFER_DATA)` call: hands `buffer` to the operating system as the bytes
/// `[offset, offset + length)` of the file with `status`. With a failure status and an empty
/// buffer it fails the pending range instead, which is what unblocks the reader. Best effort: if
/// this itself fails there is nothing further a callback can do to unblock the caller; the
/// driver's own recall timeout becomes the last resort.
unsafe fn transfer_data(
    info: &CF_CALLBACK_INFO,
    status: NTSTATUS,
    buffer: &[u8],
    offset: i64,
    length: i64,
) -> bool {
    let op_info = CF_OPERATION_INFO {
        StructSize: std::mem::size_of::<CF_OPERATION_INFO>() as u32,
        Type: CF_OPERATION_TYPE_TRANSFER_DATA,
        ConnectionKey: info.ConnectionKey,
        TransferKey: info.TransferKey,
        CorrelationVector: std::ptr::null(),
        SyncStatus: std::ptr::null(),
        RequestKey: info.RequestKey,
    };
    let mut op_params = CF_OPERATION_PARAMETERS {
        ParamSize: std::mem::size_of::<CF_OPERATION_PARAMETERS>() as u32,
        Anonymous: CF_OPERATION_PARAMETERS_0 {
            TransferData: CF_OPERATION_PARAMETERS_0_6 {
                Flags: CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
                CompletionStatus: status,
                Buffer: if buffer.is_empty() {
                    std::ptr::null()
                } else {
                    buffer.as_ptr() as *const c_void
                },
                Offset: offset,
                Length: length,
            },
        },
    };
    let delivered = CfExecute(&op_info, &mut op_params).is_ok();
    #[cfg(test)]
    if status == STATUS_SUCCESS {
        TRANSFERS.lock().unwrap().push((std::time::Instant::now(), offset, length, delivered));
    }
    delivered
}

/// The bytes of one chunk of a fetch: a multiple of the 4 KiB the driver requires of every
/// chunk but the last.
const FETCH_CHUNK: usize = 1 << 20;
/// The granularity the driver requires of every transferred range but one that ends at the end
/// of the file.
const TRANSFER_ALIGNMENT: u64 = 4096;

/// The byte window `[start, end)` that serves a fetch of `required_length` bytes at
/// `required_offset` in a file of `size` bytes: the required range widened to the transfer
/// alignment and clamped to the file. `None` when the range lies outside the file or is empty (a
/// request the driver cannot have made), which fails the callback instead of sending anything.
fn fetch_window(required_offset: i64, required_length: i64, size: u64) -> Option<(u64, u64)> {
    let offset = u64::try_from(required_offset).ok()?;
    let length = u64::try_from(required_length).ok().filter(|length| *length > 0)?;
    if offset >= size {
        return None;
    }
    let end = offset.saturating_add(length).min(size);
    let start = offset / TRANSFER_ALIGNMENT * TRANSFER_ALIGNMENT;
    let aligned_end = end.div_ceil(TRANSFER_ALIGNMENT).saturating_mul(TRANSFER_ALIGNMENT).min(size);
    Some((start, aligned_end))
}

/// Where the window `[start, end)` sits in the handoff file the daemon named, as `(position of
/// `start` in the file, the length the file must have)`, given what was asked (`target`, `None`
/// for the current whole file). A ranged answer must be exactly the window asked for and only to
/// a ranged request; a whole-file answer (to a whole request, or from a daemon that predates
/// ranged requests, which leaves `ranged` unset) is the whole file and the window is cut from it.
/// An answer for another version than the one asked for is refused: a window of another version
/// or another range is never handed to the operating system.
fn served_layout(
    response: &yadorilink_ipc_proto::shellipc::MaterializeToTempResponse,
    target: Option<&crate::provider_client::FetchTarget>,
    start: u64,
    end: u64,
    placeholder_size: u64,
) -> Result<(u64, u64), String> {
    if target.is_some_and(|t| response.version_hash.as_slice() != t.version.as_slice()) {
        return Err(
            "the item changed since the placeholder was shown; the window is dropped".into()
        );
    }
    if response.size != placeholder_size {
        return Err(format!(
            "the daemon's version is {} bytes, the placeholder is {placeholder_size}",
            response.size
        ));
    }
    if response.ranged {
        if target.and_then(|t| t.range).is_none() {
            return Err("the daemon served a window that was not asked for".into());
        }
        if response.range_offset != start || response.range_length != end - start {
            return Err(format!(
                "the daemon served {}+{}, not the window {start}+{}",
                response.range_offset,
                response.range_length,
                end - start
            ));
        }
        Ok((0, end - start))
    } else {
        Ok((start, response.size))
    }
}

/// A fetch being served, so the driver's cancel for it can reach the loop that serves it.
struct ActiveFetch {
    id: u64,
    connection: i64,
    transfer: i64,
    /// The first byte not delivered yet, and the end of what was asked for.
    next: Arc<AtomicU64>,
    /// The first byte the reader needs, which can lie inside the first aligned window.
    required_start: i64,
    end: i64,
    cancelled: Arc<AtomicBool>,
}

static ACTIVE_FETCHES: Mutex<Vec<ActiveFetch>> = Mutex::new(Vec::new());

/// Registers a fetch for the time it is served; dropping it unregisters it.
struct ActiveGuard(u64);

impl ActiveGuard {
    fn new(
        info: &CF_CALLBACK_INFO,
        next: &Arc<AtomicU64>,
        required_start: i64,
        end: i64,
    ) -> (Self, Arc<AtomicBool>) {
        static IDS: AtomicU64 = AtomicU64::new(1);
        let id = IDS.fetch_add(1, Ordering::Relaxed);
        let cancelled = Arc::new(AtomicBool::new(false));
        ACTIVE_FETCHES.lock().unwrap().push(ActiveFetch {
            id,
            connection: info.ConnectionKey.0,
            transfer: info.TransferKey,
            next: next.clone(),
            required_start,
            end,
            cancelled: cancelled.clone(),
        });
        (Self(id), cancelled)
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        ACTIVE_FETCHES.lock().unwrap_or_else(|p| p.into_inner()).retain(|f| f.id != self.0);
    }
}

/// Marks the fetches of the file `transfer` on `connection` cancelled when the cancelled range
/// covers everything they still have to deliver. A cancel of only a part of it is another
/// reader's, and the rest of the range is still wanted.
fn cancel_fetches(connection: i64, transfer: i64, offset: i64, length: i64) {
    let cancelled_end = offset.saturating_add(length);
    for fetch in ACTIVE_FETCHES.lock().unwrap().iter() {
        let next = (fetch.next.load(Ordering::Relaxed) as i64).max(fetch.required_start);
        if fetch.connection == connection
            && fetch.transfer == transfer
            && offset <= next
            && cancelled_end >= fetch.end
        {
            fetch.cancelled.store(true, Ordering::Relaxed);
        }
    }
}

/// The `CF_CALLBACK_TYPE_CANCEL_FETCH_DATA` handler: the reader that needed a range is gone (it
/// closed the file or its request timed out). Windows already being served stop at the next
/// window.
unsafe extern "system" fn cancel_fetch_data_callback(
    callback_info: *const CF_CALLBACK_INFO,
    callback_parameters: *const CF_CALLBACK_PARAMETERS,
) {
    let info = &*callback_info;
    // Safety: `CF_CALLBACK_TYPE_CANCEL_FETCH_DATA` guarantees the `Cancel` arm is the active one,
    // with its `FetchData` range.
    let range = (*callback_parameters).Anonymous.Cancel.Anonymous.FetchData;
    cancel_fetches(info.ConnectionKey.0, info.TransferKey, range.FileOffset, range.Length);
}

/// What serving one range of a provider item needs: where it is asked from and delivered to.
struct ProviderFetch<'a> {
    info: &'a CF_CALLBACK_INFO,
    root: &'a [u8],
    item: &'a [u8],
    placeholder_size: u64,
    cancelled: &'a AtomicBool,
    next: &'a AtomicU64,
}

impl windowed_fetch::Window for ProviderFetch<'_> {
    fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    /// Asks the daemon for the window `[start, end)` of the version the placeholder stands for:
    /// the daemon fetches and verifies only the blocks that cover it and names the window in its
    /// handoff directory; this reads that file and hands it to the operating system with
    /// `TRANSFER_DATA`, then removes it. A daemon that answers with the whole file is cut at the
    /// window and serves the rest of the range from the same file.
    fn serve(
        &mut self,
        target: Option<crate::provider_client::FetchTarget>,
        start: u64,
        end: u64,
        range_end: u64,
    ) -> Result<windowed_fetch::Served, String> {
        use std::io::{Read, Seek};

        let request_id = next_request_id();
        let response = crate::provider_client::materialize_within(
            crate::provider_client::MATERIALIZE_TIMEOUT,
            self.cancelled,
            self.root,
            self.item,
            &request_id,
            target,
        )
        .ok_or("the daemon did not answer the materialization")?;
        if !response.ok {
            return Err(format!(
                "the daemon refused the materialization (failure {}): {}",
                response.failure, response.error
            ));
        }
        let name = response.handoff_name.clone();
        if name.is_empty() || name.contains(['\\', '/', ':']) || name == ".." {
            return Err("the daemon named a handoff file that is not a plain name".into());
        }
        let path = crate::host_paths::handoff_dir().join(&name);
        let result = (|| -> Result<windowed_fetch::Served, String> {
            let (position, file_len) =
                served_layout(&response, target.as_ref(), start, end, self.placeholder_size)?;
            let mut file =
                std::fs::File::open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let size = file.metadata().map_err(|e| e.to_string())?.len();
            if size != file_len {
                return Err(format!(
                    "the handoff file is {size} bytes, the daemon said {file_len}"
                ));
            }
            file.seek(std::io::SeekFrom::Start(position)).map_err(|e| e.to_string())?;
            // A window is exactly what was asked; the whole file serves the rest of the range.
            let stop = if response.ranged { end } else { range_end };
            let mut at = start;
            let mut buffer = vec![0u8; FETCH_CHUNK];
            while at < stop {
                if self.cancelled.load(Ordering::Relaxed) {
                    return Err("the request was cancelled".into());
                }
                let wanted = ((stop - at) as usize).min(buffer.len());
                file.read_exact(&mut buffer[..wanted]).map_err(|e| e.to_string())?;
                // Safety: `info` is the callback's own, valid for the whole callback.
                if !unsafe {
                    transfer_data(
                        self.info,
                        STATUS_SUCCESS,
                        &buffer[..wanted],
                        at as i64,
                        wanted as i64,
                    )
                } {
                    return Err("the operating system did not take the bytes".into());
                }
                at += wanted as u64;
                self.next.store(at, Ordering::Relaxed);
            }
            Ok(windowed_fetch::Served { next: stop, whole_version: !response.ranged })
        })();
        remove_handoff(&name);
        result
    }

    /// The operating system holds every byte of the version: asks the daemon for the whole
    /// version so that it records the handoff that "present" depends on. Nothing waits for it, and
    /// a failure leaves the item not present, which is the safe side.
    fn complete(&mut self, version: [u8; 32]) {
        record_whole_version(
            self.root.to_vec(),
            self.item.to_vec(),
            version,
            self.placeholder_size,
        );
    }
}

/// Removes the handoff file `name` the daemon named once its bytes are taken or not wanted.
fn remove_handoff(name: &str) {
    let _ = std::fs::remove_file(crate::host_paths::handoff_dir().join(name));
}

/// Whether `response` is the daemon recording the whole version asked for: ok, and of exactly
/// that version and size. Anything else records nothing the host can rely on.
fn records_whole_version(
    response: &yadorilink_ipc_proto::shellipc::MaterializeToTempResponse,
    version: &[u8; 32],
    size: u64,
) -> bool {
    response.ok && response.version_hash.as_slice() == version.as_slice() && response.size == size
}

fn record_whole_version(root: Vec<u8>, item: Vec<u8>, version: [u8; 32], size: u64) {
    use yadorilink_ipc_proto::shellipc::MaterializeFailure;
    /// A transient failure (the daemon busy or restarting) is tried again a few times; one that
    /// cannot change (the version moved, the item is gone) is not.
    const ATTEMPTS: usize = 4;
    std::thread::spawn(move || {
        for attempt in 1..=ATTEMPTS {
            let request_id = next_request_id();
            let target = crate::provider_client::FetchTarget { version, range: None };
            let response = crate::provider_client::materialize_within(
                crate::provider_client::RECORD_TIMEOUT,
                &AtomicBool::new(false),
                &root,
                &item,
                &request_id,
                Some(target),
            );
            // The operating system already holds these bytes: the daemon's copy is not needed.
            if let Some(r) = response.as_ref().filter(|r| r.ok) {
                let name = &r.handoff_name;
                if !name.is_empty() && !name.contains(['\\', '/', ':']) && name != ".." {
                    remove_handoff(name);
                }
            }
            let settled = match &response {
                Some(r) if r.ok => {
                    let recorded = records_whole_version(r, &version, size);
                    if !recorded {
                        eprintln!("yadorilink-cfapi-host: the daemon answered another version");
                    }
                    recorded
                }
                Some(r) => {
                    eprintln!(
                        "yadorilink-cfapi-host: the whole version was not recorded (failure {})",
                        r.failure
                    );
                    r.failure == MaterializeFailure::VersionOutOfDate as i32
                        || r.failure == MaterializeFailure::NotFound as i32
                }
                None => {
                    eprintln!("yadorilink-cfapi-host: the daemon did not record the whole version");
                    false
                }
            };
            if settled {
                return;
            }
            if attempt < ATTEMPTS {
                std::thread::sleep(std::time::Duration::from_secs(5 * attempt as u64));
            }
        }
    });
}

/// Serves a fetch of a provider item: the range the driver asked for, whole files included,
/// window by window (see `windowed_fetch`). Serving a window makes nothing present: the item is
/// only reported materialized once the operating system holds the whole file and the daemon
/// recorded its handoff. Any failure fails the pending range, so the reader gets an error and
/// never a hang or partial bytes.
unsafe fn fetch_provider_item(
    info: &CF_CALLBACK_INFO,
    required_offset: i64,
    required_length: i64,
    item_id: &[u8],
) {
    #[cfg(test)]
    FETCHES.lock().unwrap().push((required_offset, required_length));

    // The absolute offset of the next byte to hand over, and the end of what was asked for.
    let next = Arc::new(AtomicU64::new(required_offset.max(0) as u64));
    let asked_end: i64 = required_offset.saturating_add(required_length);
    let (_active, cancelled) = ActiveGuard::new(info, &next, required_offset.max(0), asked_end);
    let served = (|| -> Result<(), String> {
        let root = connected_root(info.ConnectionKey.0)
            .and_then(|root| root.provider_root)
            .ok_or("the sync root is not a provider root")?;
        let placeholder_size =
            u64::try_from(info.FileSize).map_err(|_| "the placeholder has no size".to_string())?;
        let (start, end) = fetch_window(required_offset, required_length, placeholder_size)
            .ok_or("the requested range lies outside the file")?;
        // The version the placeholder stands for. Not known (a walk that has not completed yet):
        // the whole current file, as before ranged requests; its size is checked against the
        // placeholder's.
        let version = crate::provider_client::shown_version(&root, item_id);
        crate::provider_client::note_fetch_activity(&root, item_id);
        next.store(start, Ordering::Relaxed);
        let mut at = start;
        let mut io = ProviderFetch {
            info,
            root: &root,
            item: item_id,
            placeholder_size,
            cancelled: &cancelled,
            next: &next,
        };
        let result = windowed_fetch::serve_range(&mut io, version, placeholder_size, &mut at, end);
        next.store(at, Ordering::Relaxed);
        result
    })();
    if let Err(reason) = served {
        eprintln!("yadorilink-cfapi-host: fetch failed: {reason}");
        // Fail what was not delivered, so the reader's call returns instead of waiting.
        let delivered = next.load(Ordering::Relaxed) as i64;
        // The failed range is a valid transfer range too: aligned, and not past the file.
        let alignment = TRANSFER_ALIGNMENT as i64;
        let asked_end =
            (asked_end.saturating_add(alignment - 1) / alignment * alignment).min(info.FileSize);
        let remaining = asked_end - delivered;
        let (start, length) =
            if remaining > 0 { (delivered, remaining) } else { (required_offset, required_length) };
        transfer_data(info, STATUS_UNSUCCESSFUL, &[], start, length);
    }
}

/// A request id that is unique within this process and across restarts of it.
fn next_request_id() -> Vec<u8> {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    let mut id = Vec::with_capacity(16);
    id.extend_from_slice(&started.to_be_bytes());
    id.extend_from_slice(&COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed).to_be_bytes());
    id
}

#[cfg(test)]
mod fetch_tests;

/// Test-only: the windows the driver asked this host to fetch, in order.
#[cfg(test)]
static FETCHES: Mutex<Vec<(i64, i64)>> = Mutex::new(Vec::new());

/// Test-only: every successful-status `TRANSFER_DATA` this host made: when, where, how long, and
/// whether the operating system took it.
#[cfg(test)]
static TRANSFERS: Mutex<Vec<(std::time::Instant, i64, i64, bool)>> = Mutex::new(Vec::new());

#[cfg(test)]
mod tests {
    use super::{decode_generation_identity, fetch_window, served_layout};
    use crate::provider_client::FetchTarget;

    fn answer(
        version: [u8; 32],
        size: u64,
        ranged: Option<(u64, u64)>,
    ) -> yadorilink_ipc_proto::shellipc::MaterializeToTempResponse {
        yadorilink_ipc_proto::shellipc::MaterializeToTempResponse {
            ok: true,
            version_hash: version.to_vec(),
            size,
            ranged: ranged.is_some(),
            range_offset: ranged.map_or(0, |r| r.0),
            range_length: ranged.map_or(0, |r| r.1),
            ..Default::default()
        }
    }

    fn ranged(version: [u8; 32], start: u64, end: u64) -> FetchTarget {
        FetchTarget { version, range: Some((start, end - start)) }
    }

    /// A 4 KiB open of a 1 GiB file asks for one 4 KiB window, and a ranged answer for exactly
    /// that window of exactly that version is served from the start of the handoff file.
    #[test]
    fn a_small_open_of_a_huge_file_is_one_small_ranged_window() {
        const GIB: u64 = 1 << 30;
        let (start, end) = fetch_window(512 << 20, 4096, GIB).unwrap();
        assert_eq!((start, end - start), (512 << 20, 4096));
        let version = [5u8; 32];
        let reply = answer(version, GIB, Some((start, 4096)));
        let target = ranged(version, start, end);
        assert_eq!(served_layout(&reply, Some(&target), start, end, GIB), Ok((0, 4096)));
    }

    /// A window of another version, of another range, of another file size, or one that was not
    /// asked for is dropped.
    #[test]
    fn a_window_of_another_version_or_range_is_refused() {
        let version = [5u8; 32];
        let (start, end, size) = (4096, 8192, 1 << 20);
        let target = ranged(version, start, end);
        let check = |reply: &_| served_layout(reply, Some(&target), start, end, size);
        assert!(check(&answer(version, size, Some((start, 4096)))).is_ok());
        assert!(check(&answer([6; 32], size, Some((start, 4096)))).is_err());
        let mut unnamed = answer(version, size, Some((start, 4096)));
        unnamed.version_hash.clear();
        assert!(check(&unnamed).is_err());
        assert!(check(&answer(version, size, Some((0, 4096)))).is_err());
        assert!(check(&answer(version, size, Some((start, 8192)))).is_err());
        assert!(check(&answer(version, size + 1, Some((start, 4096)))).is_err());
        // A window to a request for the whole version was not asked for.
        let whole = FetchTarget { version, range: None };
        let reply = answer(version, size, Some((start, 4096)));
        assert!(served_layout(&reply, Some(&whole), start, end, size).is_err());
    }

    /// A daemon that predates ranged requests answers with the whole file and `ranged` unset:
    /// the window is cut from it at its own offset, and only if it is the same version. The
    /// same goes for a whole-version request and for one without a known version.
    #[test]
    fn a_whole_file_answer_is_cut_from_the_file() {
        let version = [5u8; 32];
        let (start, end, size) = (4096, 8192, 1 << 20);
        let reply = answer(version, size, None);
        let target = ranged(version, start, end);
        assert_eq!(served_layout(&reply, Some(&target), start, end, size), Ok((start, size)));
        let whole = FetchTarget { version, range: None };
        assert_eq!(served_layout(&reply, Some(&whole), 0, size, size), Ok((0, size)));
        assert_eq!(served_layout(&reply, None, start, end, size), Ok((start, size)));
        let other = answer([6; 32], size, None);
        assert!(served_layout(&other, Some(&target), start, end, size).is_err());
    }

    #[test]
    fn a_fetch_window_is_the_required_range_widened_to_the_transfer_alignment() {
        // The whole file (what a full-hydration open asks for).
        assert_eq!(fetch_window(0, 10_000, 10_000), Some((0, 10_000)));
        // A range inside the file starts on a 4 KiB boundary and ends on one.
        assert_eq!(fetch_window(5_000, 100, 1_000_000), Some((4_096, 8_192)));
        assert_eq!(fetch_window(4_096, 4_096, 1_000_000), Some((4_096, 8_192)));
        // The end of the file is not rounded past the file.
        assert_eq!(fetch_window(8_192, 1 << 40, 10_000), Some((8_192, 10_000)));
        assert_eq!(fetch_window(9_999, 1, 10_000), Some((8_192, 10_000)));
        // Nothing the driver can legitimately ask for is accepted outside the file.
        assert_eq!(fetch_window(10_000, 1, 10_000), None);
        assert_eq!(fetch_window(-1, 10, 10_000), None);
        assert_eq!(fetch_window(0, 0, 10_000), None);
        assert_eq!(fetch_window(0, -5, 10_000), None);
        assert_eq!(fetch_window(i64::MAX - 1, i64::MAX, 1 << 60), None);
    }

    /// A cancel stops a fetch only when it covers everything the fetch still has to deliver, and
    /// bytes that were only fetched to align the transfer do not count: a reader of 5000..5100
    /// cancelling that range cancels the fetch although its window starts at 4096; a cancel of
    /// another reader's part of a larger range does not.
    #[test]
    fn a_cancel_covers_what_is_still_required() {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        use std::sync::Arc;
        let fetch = |id, required_start: i64, next: u64, end: i64| {
            let cancelled = Arc::new(AtomicBool::new(false));
            super::ACTIVE_FETCHES.lock().unwrap().push(super::ActiveFetch {
                id,
                connection: 9_001,
                transfer: 9_002,
                next: Arc::new(AtomicU64::new(next)),
                required_start,
                end,
                cancelled: cancelled.clone(),
            });
            cancelled
        };
        let unaligned = fetch(9_101, 5000, 4096, 5100);
        let whole = fetch(9_102, 0, 100 << 20, 1 << 30);
        let tail = fetch(9_103, 0, 100 << 20, 1 << 30);
        // Another file's cancel, or a cancel of a part, changes nothing.
        super::cancel_fetches(9_001, 1, 0, i64::MAX);
        super::cancel_fetches(9_001, 9_002, 5000, 50);
        assert!(!unaligned.load(Ordering::Relaxed) && !whole.load(Ordering::Relaxed));
        // The reader's own range, and everything left of a large one.
        super::cancel_fetches(9_001, 9_002, 0, 500 << 20);
        assert!(!whole.load(Ordering::Relaxed));
        super::cancel_fetches(9_001, 9_002, 5000, 100);
        assert!(unaligned.load(Ordering::Relaxed));
        super::cancel_fetches(9_001, 9_002, 100 << 20, (1 << 30) - (100 << 20));
        assert!(whole.load(Ordering::Relaxed) && tail.load(Ordering::Relaxed));
        super::ACTIVE_FETCHES.lock().unwrap().retain(|f| !(9_101..=9_103).contains(&f.id));
    }

    /// The daemon's answer to the whole-version record counts only for the version and size
    /// asked for.
    #[test]
    fn a_record_of_another_version_or_size_is_not_a_record() {
        let reply = |ok, version: [u8; 32], size| {
            let mut r = answer(version, size, None);
            r.ok = ok;
            r
        };
        let v = [5u8; 32];
        assert!(super::records_whole_version(&reply(true, v, 100), &v, 100));
        assert!(!super::records_whole_version(&reply(true, [6; 32], 100), &v, 100));
        assert!(!super::records_whole_version(&reply(true, v, 101), &v, 100));
        assert!(!super::records_whole_version(&reply(false, v, 100), &v, 100));
        let mut unnamed = reply(true, v, 100);
        unnamed.version_hash.clear();
        assert!(!super::records_whole_version(&unnamed, &v, 100));
    }

    #[test]
    fn decode_generation_identity_round_trips_through_encode() {
        for generation in [0u64, 1, 42, u64::MAX] {
            let encoded = super::encode_generation_identity(generation);
            assert_eq!(decode_generation_identity(&encoded), Some(generation));
        }
    }

    #[test]
    fn decode_generation_identity_rejects_wrong_length() {
        assert_eq!(decode_generation_identity(&[1u8; 8]), None);
        assert_eq!(decode_generation_identity(&[1u8; 10]), None);
        assert_eq!(decode_generation_identity(&[]), None);
    }

    #[test]
    fn decode_generation_identity_rejects_wrong_version_tag() {
        let mut bytes = vec![0u8];
        bytes.extend_from_slice(&42u64.to_le_bytes());
        assert_eq!(decode_generation_identity(&bytes), None);
    }

    /// Decision record: what the Cloud Files APIs take for a path past
    /// MAX_PATH. Verified on Windows 11 build 26300: `CfRegisterSyncRoot`, `CfConnectSyncRoot`,
    /// `CfCreatePlaceholders` and `CfUnregisterSyncRoot` accept both the plain and the verbatim
    /// (`\\?\`) spelling of a 300-character path. The sync root itself is registered with the
    /// plain path, because that is what the shell shows and records for the root (it is short by
    /// construction, a folder under the user's profile); the base directory of a placeholder
    /// creation, which can be deep in a user's tree, goes through `for_win32`.
    #[test]
    #[ignore = "real Cloud Files state; run on a Windows machine"]
    fn cloud_files_apis_take_paths_past_max_path_in_either_spelling() {
        let base = std::env::temp_dir().join(format!("yl-long-{}", std::process::id()));
        let mut long = base.clone();
        while long.to_string_lossy().len() < 300 {
            long.push("a-long-directory-segment");
        }
        let verbatim = yadorilink_fs_platform::long_path::for_win32(&long);
        assert!(verbatim.to_string_lossy().starts_with(r"\\?\"), "not past MAX_PATH");
        std::fs::create_dir_all(&verbatim).unwrap();
        for path in [&long, &verbatim] {
            super::register_and_connect(path).expect("register and connect");
            super::create_item_placeholder_at(path, "x.txt", b"i", 1, 0, false)
                .expect("create in the directory");
            super::create_item_placeholder(
                &yadorilink_fs_platform::durable_dir::NoLedger,
                path,
                "y.txt",
                b"j",
                1,
                0,
                false,
            )
            .expect("create and publish in the directory");
            for name in ["x.txt", "y.txt"] {
                std::fs::remove_file(verbatim.join(name)).unwrap();
            }
            super::unregister(path).expect("unregister");
        }
        let _ = std::fs::remove_dir_all(yadorilink_fs_platform::long_path::for_win32(&base));
    }

    /// Manual diagnostic only (matches `registration.rs`'s
    /// `debug_register_all` pattern): exercises the real
    /// `CfRegisterSyncRoot`/`CfConnectSyncRoot`/`CfCreatePlaceholders`/
    /// `CfUnregisterSyncRoot` calls against a real directory on whatever
    /// machine runs it, independent of the daemon or CLI (no
    /// coordination-plane login needed) — the narrowest possible
    /// real-cfapi-runtime check. `#[ignore]`d since it
    /// touches real OS state; run explicitly with `cargo test --release
    /// -- --ignored cfapi_smoke_test` on a disposable Windows machine.
    #[test]
    #[ignore]
    fn cfapi_smoke_test() {
        let dir = std::env::temp_dir().join("yadorilink-cfapi-smoke-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test dir");

        let reg = super::register_and_connect(&dir);
        println!("register_and_connect: {:?}", reg);
        reg.expect("CfRegisterSyncRoot/CfConnectSyncRoot should succeed");

        let now_nanos =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
                as i64;
        let create =
            super::create_item_placeholder_at(&dir, "hello.txt", b"item", 11, now_nanos, false);
        println!("create_item_placeholder_at: {:?}", create);
        create.expect("CfCreatePlaceholders should succeed");

        let placeholder_path = dir.join("hello.txt");
        let attrs = unsafe {
            windows::Win32::Storage::FileSystem::GetFileAttributesW(
                windows::core::PCWSTR::from_raw(
                    super::wide(&placeholder_path.to_string_lossy()).as_ptr(),
                ),
            )
        };
        println!("placeholder file attributes: {attrs:#x}");
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        assert!(
            attrs != u32::MAX && attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0,
            "expected the created placeholder to have FILE_ATTRIBUTE_REPARSE_POINT set, got {attrs:#x}"
        );

        let unreg = super::unregister(&dir);
        println!("unregister: {:?}", unreg);
        unreg.expect("CfUnregisterSyncRoot should succeed");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
