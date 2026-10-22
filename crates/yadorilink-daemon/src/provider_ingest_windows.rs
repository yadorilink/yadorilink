#![cfg(windows)]

//! The Windows reader of a provider write's private copy (see `provider_ingest` for the contract).
//!
//! The guarantees are the Unix ones, expressed with Windows primitives instead of POSIX ones:
//!
//! * the name is a single plain component: the shared alphabet (no separator, no `..`, no `:`
//!   drive or stream syntax) minus what Windows treats specially (reserved device names with or
//!   without an extension, a trailing dot);
//! * the copy lives in the fixed ingest directory, which is private to the current user (a
//!   protected DACL, set when the temp root is prepared). The file is opened by its path with
//!   `CreateFileW(FILE_FLAG_OPEN_REPARSE_POINT)`, so a reparse point is opened as itself and then
//!   refused, never followed; the handle's final path must be exactly the ingest directory plus
//!   the name, which also refuses a directory that was swapped for a junction;
//! * the open handle must be a disk file, not a directory or a reparse point, with one link
//!   (`FileStandardInfo.NumberOfLinks`), owned by the current user, of exactly the declared size;
//! * its bytes are chunked through that SAME handle while a SHA-256 is computed over them; the
//!   identity (volume serial plus 128-bit file id, size, write time, change time) must be the same
//!   after the read, and the digest must equal the declared one.
//!
//! The file is opened for reading with `FILE_SHARE_READ` only, so nobody can write to it, rename
//! it or delete it while it is being read.

use std::ffi::c_void;
use std::os::windows::io::FromRawHandle;
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::Arc;

use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FileBasicInfo, FileIdInfo, FileStandardInfo, GetFileInformationByHandleEx,
    GetFileType, GetFinalPathNameByHandleW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_BASIC_INFO, FILE_ID_INFO, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
    FILE_STANDARD_INFO, FILE_TYPE_DISK, OPEN_EXISTING, READ_CONTROL, VOLUME_NAME_DOS,
};
use yadorilink_local_storage::BlockContentStore;
use yadorilink_replica_domain::file::BlockInfo;
use yadorilink_replica_domain::limits::MAX_SYNCABLE_BLOCKS;

use crate::provider_ingest::{storage_error, valid_ingest_name, IngestError, Ingested};
use crate::windows_fs_security::{owner_sid_of_handle, ProcessSids};

const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// Whether `name` is usable as a Windows file name: the shared alphabet, and neither a reserved
/// device name (`CON`, `NUL`, `COM1`, ..., also with an extension) nor ending in a dot.
fn valid_windows_name(name: &str) -> bool {
    if !valid_ingest_name(name) || name.ends_with('.') {
        return false;
    }
    let stem = name.split('.').next().unwrap_or(name).to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
        || ["COM", "LPT"].iter().any(|prefix| {
            stem.strip_prefix(prefix).is_some_and(|digit| matches!(digit.as_bytes(), [b'0'..=b'9']))
        });
    !reserved
}

/// What identifies the open file at one moment.
#[derive(Debug, PartialEq, Eq)]
struct Identity {
    volume_serial: u64,
    file_id: [u8; 16],
    size: i64,
    last_write: i64,
    change: i64,
}

/// Everything read from the handle that the checks need.
struct Observed {
    identity: Identity,
    attributes: u32,
    links: u32,
    delete_pending: bool,
}

/// An owned handle, closed on drop unless it was turned into a `File`.
struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle was returned by a successful `CreateFileW` and is closed once.
        unsafe { CloseHandle(self.0) };
    }
}

fn query<T>(handle: HANDLE, class: i32) -> std::io::Result<T> {
    // SAFETY: every structure queried here is plain data for which all-zero is a valid value.
    let mut value: T = unsafe { std::mem::zeroed() };
    // SAFETY: `value` is a plain-data out-structure of the class's size.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            class,
            (&mut value as *mut T).cast::<c_void>(),
            std::mem::size_of::<T>() as u32,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(value)
}

fn observe(handle: HANDLE) -> std::io::Result<Observed> {
    let id: FILE_ID_INFO = query(handle, FileIdInfo)?;
    let standard: FILE_STANDARD_INFO = query(handle, FileStandardInfo)?;
    let basic: FILE_BASIC_INFO = query(handle, FileBasicInfo)?;
    Ok(Observed {
        identity: Identity {
            volume_serial: id.VolumeSerialNumber,
            file_id: id.FileId.Identifier,
            size: standard.EndOfFile,
            last_write: basic.LastWriteTime,
            change: basic.ChangeTime,
        },
        attributes: basic.FileAttributes,
        links: standard.NumberOfLinks,
        delete_pending: standard.DeletePending != 0,
    })
}

/// The final path of an open handle, in `\\?\C:\...` form.
fn final_path(handle: HANDLE) -> std::io::Result<String> {
    let mut buffer = vec![0u16; 1024];
    loop {
        // SAFETY: `buffer` is writable for `buffer.len()` UTF-16 units.
        let len = unsafe {
            GetFinalPathNameByHandleW(
                handle,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        } as usize;
        if len == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if len < buffer.len() {
            return Ok(String::from_utf16_lossy(&buffer[..len]));
        }
        buffer.resize(len + 1, 0);
    }
}

/// `\\?\C:\a\b` and `C:\a\b` name the same place; compare without the verbatim prefix and without
/// regard to case (NTFS names are case-insensitive).
fn same_location(a: &str, b: &str) -> bool {
    let plain = |text: &str| text.strip_prefix(r"\\?\").unwrap_or(text).to_lowercase();
    plain(a) == plain(b)
}

/// Reads and stores the copy `name` of `ingest_dir`.
pub(crate) fn ingest(
    ingest_dir: &Path,
    name: &str,
    declared_size: u64,
    declared_sha256: &[u8],
    store: &dyn BlockContentStore,
) -> Result<Ingested, IngestError> {
    if !valid_windows_name(name) {
        return Err(IngestError::Rejected("the ingest name is not a plain file name".into()));
    }
    let declared: [u8; 32] = declared_sha256
        .try_into()
        .map_err(|_| IngestError::Rejected("the content digest is not 32 bytes".into()))?;
    let me = ProcessSids::current().map_err(|e| {
        IngestError::Unstable(format!("the current user cannot be determined: {e}"))
    })?;

    // The ingest directory itself must be a plain directory; its resolved path is what the copy
    // must end up exactly below.
    let directory_meta = std::fs::symlink_metadata(ingest_dir).map_err(|e| {
        IngestError::Unstable(format!("the ingest directory cannot be inspected: {e}"))
    })?;
    {
        use std::os::windows::fs::MetadataExt;
        if directory_meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || !directory_meta.is_dir()
        {
            return Err(IngestError::Rejected(
                "the ingest directory is not a plain directory".into(),
            ));
        }
    }
    let directory = std::fs::canonicalize(ingest_dir).map_err(|e| {
        IngestError::Unstable(format!("the ingest directory cannot be resolved: {e}"))
    })?;
    let path = directory.join(name);
    let wide: Vec<u16> = {
        use std::os::windows::ffi::OsStrExt;
        yadorilink_fs_platform::long_path::for_win32(&path)
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    };
    // Reparse points are opened as themselves (and refused below), never followed. Read-only
    // sharing: while this handle is open nobody can write to, rename or delete the copy.
    // SAFETY: `wide` is NUL-terminated.
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_SHARE_READ,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if raw as isize == -1 {
        let error = std::io::Error::last_os_error();
        return Err(match error.kind() {
            std::io::ErrorKind::NotFound => {
                IngestError::Unstable("the ingest file is missing".into())
            }
            // Held open for writing or deleting by someone else: the extension copies again.
            _ if error.raw_os_error() == Some(32) => {
                IngestError::Unstable("the ingest file is in use".into())
            }
            _ => IngestError::Rejected(format!("the ingest file cannot be opened: {error}")),
        });
    }
    let guard = Handle(raw);

    // SAFETY: `raw` is an open handle.
    if unsafe { GetFileType(raw) } != FILE_TYPE_DISK {
        return Err(IngestError::Rejected("the ingest file is not a regular file".into()));
    }
    let located = final_path(raw).map_err(|e| IngestError::Unstable(e.to_string()))?;
    if !same_location(&located, &path.to_string_lossy()) {
        return Err(IngestError::Rejected(
            "the ingest file is not inside the ingest directory".into(),
        ));
    }
    let before = observe(raw).map_err(|e| IngestError::Unstable(e.to_string()))?;
    if before.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(IngestError::Rejected("the ingest file is a reparse point".into()));
    }
    if before.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Err(IngestError::Rejected("the ingest file is not a regular file".into()));
    }
    if before.delete_pending {
        return Err(IngestError::Unstable("the ingest file is being deleted".into()));
    }
    if before.links != 1 {
        return Err(IngestError::Rejected("the ingest file has other hard links".into()));
    }
    let owner = owner_sid_of_handle(raw).map_err(|e| IngestError::Unstable(e.to_string()))?;
    if !me.is_current(&owner) {
        return Err(IngestError::Rejected("the ingest file belongs to another user".into()));
    }
    let size = u64::try_from(before.identity.size).unwrap_or(u64::MAX);
    if size != declared_size {
        return Err(IngestError::Rejected(format!(
            "the ingest file is {size} bytes, the request says {declared_size}"
        )));
    }

    // From here the SAME handle is read: it becomes the `File` the chunker takes.
    std::mem::forget(guard);
    // SAFETY: `raw` is a valid, owned file handle that nothing else will close.
    let file = unsafe { std::fs::File::from_raw_handle(raw) };

    let mut hasher = Sha256::new();
    let use_cdc = size >= yadorilink_local_storage::CDC_SIZE_THRESHOLD;
    let on_block = |_: &BlockInfo, bytes: Arc<[u8]>| hasher.update(&bytes[..]);
    let blocks = if use_cdc {
        yadorilink_local_storage::chunk_open_file_content_defined_with_callback(
            store, &file, on_block,
        )
    } else {
        yadorilink_local_storage::chunk_open_file_fixed_with_callback(store, &file, on_block)
    }
    .map_err(storage_error)?;

    let after = observe(raw).map_err(|e| IngestError::Unstable(e.to_string()))?;
    let read: u64 = blocks.iter().map(|b| u64::from(b.size)).sum();
    if before.identity != after.identity || read != size {
        return Err(IngestError::Unstable("the ingest file changed while it was read".into()));
    }
    if blocks.len() > MAX_SYNCABLE_BLOCKS {
        return Err(IngestError::TooLarge);
    }
    let sha256: [u8; 32] = hasher.finalize().into();
    if sha256 != declared {
        return Err(IngestError::Unstable(
            "the ingested bytes do not match the declared digest".into(),
        ));
    }
    Ok(Ingested { blocks, size: read })
}

#[cfg(test)]
mod tests;
