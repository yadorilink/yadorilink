//! Reading the bytes of a provider write.
//!
//! The extension puts a private copy of the OS-supplied file in the daemon's fixed `ingest/`
//! directory and sends only its NAME, its size and its SHA-256. The daemon reads it like this:
//!
//! * the name is one component of a restricted alphabet that does not start with `.` (a copy in
//!   progress is invisible), and it is opened RELATIVE to the ingest directory (`openat` with
//!   `O_NOFOLLOW | O_NONBLOCK`), so no path from the request is ever joined or resolved;
//! * the open file must be a regular file, with one link, owned by the daemon's user, of exactly
//!   the declared size;
//! * its bytes are chunked by the ordinary streaming chunker (never the whole file in memory)
//!   while a SHA-256 is computed over the same bytes; the digest must equal the declared one, and
//!   the file's identity (size, mtime, ctime, inode) must be unchanged after the read, else the
//!   copy changed while it was read;
//! * blocks go to the block store; the caller records their provenance for the group.
//!
//! Hashes of blocks are computed by the daemon; the declared digest is checked, never trusted.

#[cfg(unix)]
use std::sync::Arc;

#[cfg(unix)]
use sha2::{Digest, Sha256};
#[cfg(not(windows))]
use yadorilink_local_storage::BlockContentStore;
use yadorilink_replica_domain::file::BlockInfo;
#[cfg(unix)]
use yadorilink_replica_domain::limits::MAX_SYNCABLE_BLOCKS;

/// Why a copy could not be ingested; each maps to one failure code of the wire.
#[derive(Debug)]
pub(crate) enum IngestError {
    /// Not a usable copy (bad name, not a regular file, wrong owner, extra links, wrong size or
    /// digest shape).
    Rejected(String),
    /// Missing, or changed while it was read: the extension re-copies and sends again.
    Unstable(String),
    /// More blocks than a version may have.
    TooLarge,
    /// The block store ran out of space.
    LowDisk(String),
    /// Anything else the store reported.
    Store(String),
}

/// What was read: the blocks (stored) and the exact size. The digest was verified, not kept.
#[derive(Debug, Clone)]
pub(crate) struct Ingested {
    pub(crate) blocks: Vec<BlockInfo>,
    pub(crate) size: u64,
}

/// The longest ingest name.
const MAX_NAME_BYTES: usize = 128;

/// Whether `name` is a single plain component: `[A-Za-z0-9][A-Za-z0-9._-]*`, at most 128 bytes.
pub(crate) fn valid_ingest_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_NAME_BYTES
        && bytes[0].is_ascii_alphanumeric()
        && bytes.iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && name != ".."
}

pub(crate) fn storage_error(error: yadorilink_local_storage::StorageError) -> IngestError {
    use yadorilink_local_storage::StorageError;
    match &error {
        StorageError::DiskPressure { .. } => IngestError::LowDisk(error.to_string()),
        StorageError::Io(io) if io.raw_os_error() == Some(libc_enospc()) => {
            IngestError::LowDisk(error.to_string())
        }
        _ => IngestError::Store(error.to_string()),
    }
}

#[cfg(unix)]
fn libc_enospc() -> i32 {
    libc::ENOSPC
}

/// `ERROR_DISK_FULL`.
#[cfg(windows)]
fn libc_enospc() -> i32 {
    112
}

#[cfg(not(any(unix, windows)))]
fn libc_enospc() -> i32 {
    -1
}

/// Reads and stores the copy `name` of `ingest_dir`.
#[cfg(unix)]
pub(crate) fn ingest(
    ingest_dir: &std::path::Path,
    name: &str,
    declared_size: u64,
    declared_sha256: &[u8],
    store: &dyn BlockContentStore,
) -> Result<Ingested, IngestError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;

    if !valid_ingest_name(name) {
        return Err(IngestError::Rejected("the ingest name is not a plain file name".into()));
    }
    let declared: [u8; 32] = declared_sha256
        .try_into()
        .map_err(|_| IngestError::Rejected("the content digest is not 32 bytes".into()))?;
    let dir = std::fs::File::open(ingest_dir).map_err(|e| {
        IngestError::Unstable(format!("the ingest directory cannot be opened: {e}"))
    })?;
    let c_name = std::ffi::CString::new(name)
        .map_err(|_| IngestError::Rejected("the ingest name has a NUL".into()))?;
    // Relative to the directory fd, never following a final symlink, never blocking on a fifo.
    // SAFETY: `c_name` is a valid NUL-terminated string and `dir` a live directory fd.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c_name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        return Err(if error.kind() == std::io::ErrorKind::NotFound {
            IngestError::Unstable("the ingest file is missing".into())
        } else {
            // ELOOP: a symlink; anything else: not a copy we may read.
            IngestError::Rejected(format!("the ingest file cannot be opened: {error}"))
        });
    }
    // SAFETY: `fd` was just returned by a successful `openat` and is owned by nobody else.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let before = file.metadata().map_err(|e| IngestError::Unstable(e.to_string()))?;
    // SAFETY: `geteuid` has no preconditions.
    let me = unsafe { libc::geteuid() };
    if !before.is_file() {
        return Err(IngestError::Rejected("the ingest file is not a regular file".into()));
    }
    if before.nlink() != 1 {
        return Err(IngestError::Rejected("the ingest file has other hard links".into()));
    }
    if before.uid() != me {
        return Err(IngestError::Rejected("the ingest file belongs to another user".into()));
    }
    if before.len() != declared_size {
        return Err(IngestError::Rejected(format!(
            "the ingest file is {} bytes, the request says {declared_size}",
            before.len()
        )));
    }

    let mut hasher = Sha256::new();
    let use_cdc = before.len() >= yadorilink_local_storage::CDC_SIZE_THRESHOLD;
    let on_block = |_: &BlockInfo, bytes: Arc<[u8]>| hasher.update(&bytes[..]);
    let blocks = if use_cdc {
        yadorilink_local_storage::chunk_open_file_content_defined_with_callback(
            store, &file, on_block,
        )
    } else {
        yadorilink_local_storage::chunk_open_file_fixed_with_callback(store, &file, on_block)
    }
    .map_err(storage_error)?;

    let after = file.metadata().map_err(|e| IngestError::Unstable(e.to_string()))?;
    let read: u64 = blocks.iter().map(|b| u64::from(b.size)).sum();
    let identity = |m: &std::fs::Metadata| {
        (m.len(), m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec(), m.ino(), m.dev())
    };
    if identity(&before) != identity(&after) || read != before.len() {
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

#[cfg(windows)]
pub(crate) use crate::provider_ingest_windows::ingest;

#[cfg(not(any(unix, windows)))]
pub(crate) fn ingest(
    _ingest_dir: &std::path::Path,
    _name: &str,
    _declared_size: u64,
    _declared_sha256: &[u8],
    _store: &dyn BlockContentStore,
) -> Result<Ingested, IngestError> {
    Err(IngestError::Rejected("provider writes need a Unix daemon".into()))
}

#[cfg(all(test, unix))]
mod tests;
