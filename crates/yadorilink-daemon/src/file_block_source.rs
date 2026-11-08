//! Reads a block for a peer from the user's own file, verified, when the block store does not
//! hold it (see `yadorilink_peer_session::ports::BlockFileSourcePort`).
//!
//! The file is a source only while the record says it is the version the block belongs to and the
//! bytes agree: the current row of the path is present and lists the hash, the file is a regular
//! file of the recorded length, and the range hashes to the requested hash. Anything else is
//! either "not a source right now" (the file is busy, or would have to be recalled from a
//! provider to be read) or "the file is no longer that version" (it was edited or removed since
//! the record), in which case the path is put back in front of capture.

use std::path::Path;
use std::sync::Arc;

use yadorilink_peer_session::ports::{BlockFileSourcePort, FileBlockRead};
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::file::BlockInfo;
use yadorilink_replica_domain::session_state::{LinkGate, MaterializationState};

use crate::replica_coordinator::ReplicaCoordinator;
use crate::sync_error::SyncError;
use yadorilink_peer_session::peer_session::RootCommitAuthorityProvider;

/// The journal's label for a path that may have been edited or created since its record.
pub(crate) const MODIFIED: &str = "created_or_modified";
/// The journal's label for a path observed to be gone.
pub(crate) const REMOVED: &str = "removed";

/// The block-reading seam of a daemon's sessions.
pub(crate) struct FileBlockSource {
    coordinator: Arc<ReplicaCoordinator>,
    /// Where the lease that admits a journal write comes from.
    root_authority: Arc<dyn RootCommitAuthorityProvider>,
}

impl FileBlockSource {
    pub(crate) fn new(
        coordinator: Arc<ReplicaCoordinator>,
        root_authority: Arc<dyn RootCommitAuthorityProvider>,
    ) -> Self {
        Self { coordinator, root_authority }
    }

    /// Puts `path` back in front of capture because the file no longer matches its record.
    ///
    /// Every failure writes a mark, strictly newer than whatever the path's journal row holds, so
    /// that capture, which deletes the row only up to the value it started from, can never remove
    /// the mark of an edit it has not read. Writing fewer marks would need to know when capture
    /// started on the path; nothing says so (a redrive writes the stored value back unchanged), and
    /// a mark skipped while capture is between its last read of the file and its delete is an edit
    /// that is never captured if its watcher event was missed. The cost is one small write per
    /// failed request, and it stops by itself: once capture has captured the new version the record
    /// no longer lists the old block, and a request for it is not a source and writes nothing.
    fn mark_changed(&self, group_id: &str, path: &str, kind: &str) {
        let Some(lease) = self.root_authority.root_lease_for(group_id) else { return };
        let _ = mark_for_capture(&self.coordinator, &lease, group_id, path, kind);
    }
}

/// Journals `path` as `kind` (`created_or_modified` or `removed`), strictly newer than whatever
/// the path's row holds (see [`FileBlockSource::mark_changed`]), so the next capture pass reads it.
pub(crate) fn mark_for_capture(
    coordinator: &ReplicaCoordinator,
    lease: &yadorilink_root_authority::root_commit::RootLease,
    group_id: &str,
    path: &str,
    kind: &str,
) -> bool {
    let repository = coordinator.dirty_path_repository();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);
    let held = repository.dirty_path_observed_at(group_id, path).unwrap_or(None);
    let observed_at = held.map_or(now, |held| now.max(held + 1));
    let Ok(operation) = lease.begin_journal_operation() else { return false };
    if let Err(error) =
        repository.record_dirty_path(group_id, path, kind, observed_at, &operation.permit())
    {
        tracing::debug!(%error, group_id, path, "could not journal a file that no longer matches its record");
        return false;
    }
    true
}

impl BlockFileSourcePort for FileBlockSource {
    fn read_block(
        &self,
        group_id: &str,
        path: &str,
        hash: &[u8],
    ) -> Result<FileBlockRead, PeerSessionError> {
        if !crate::receive_diag::enabled() {
            return self.read_block_from_file(group_id, path, hash);
        }
        let started = std::time::Instant::now();
        let read = self.read_block_from_file(group_id, path, hash);
        let (found, bytes) = match &read {
            Ok(FileBlockRead::Found(data)) => (true, data.len() as u64),
            _ => (false, 0),
        };
        crate::receive_diag::record_file_serve(found, bytes, started.elapsed().as_nanos() as u64);
        read
    }
}

impl FileBlockSource {
    fn read_block_from_file(
        &self,
        group_id: &str,
        path: &str,
        hash: &[u8],
    ) -> Result<FileBlockRead, PeerSessionError> {
        let coordinator = &self.coordinator;
        let sync =
            |e: yadorilink_sync_sqlite::SyncSqliteError| PeerSessionError::from(SyncError::from(e));
        let Some(record) =
            coordinator.file_index_repository().get_file_shared(group_id, path).map_err(sync)?
        else {
            return Ok(FileBlockRead::Absent);
        };
        if record.deleted {
            return Ok(FileBlockRead::Absent);
        }
        let Some(block) = record.blocks.iter().find(|block| block.hash == hash) else {
            return Ok(FileBlockRead::Absent);
        };
        // A placeholder, or a file being made or removed, is not a source.
        let present = coordinator
            .materialization_state_repository()
            .get_materialization_state(group_id, path)
            .map_err(sync)?;
        if present != Some(MaterializationState::Present) {
            return Ok(FileBlockRead::Absent);
        }
        let LinkGate::Live { local_path, .. } = coordinator.link_gate_for_group(group_id)? else {
            return Ok(FileBlockRead::Absent);
        };
        let Ok(resolved) = yadorilink_local_storage::resolve_read_path_without_traversal(
            Path::new(&local_path),
            Path::new(path),
        ) else {
            return Ok(FileBlockRead::Absent);
        };
        let file = match open_source(&resolved) {
            Opened::File(file) => file,
            Opened::Unavailable(_) => return Ok(FileBlockRead::Absent),
            Opened::Gone => {
                self.mark_changed(group_id, path, REMOVED);
                return Ok(FileBlockRead::Changed);
            }
        };
        let Ok(metadata) = file.metadata() else { return Ok(FileBlockRead::Absent) };
        if !metadata.is_file() || metadata.len() != record.size {
            self.mark_changed(group_id, path, MODIFIED);
            return Ok(FileBlockRead::Changed);
        }
        match read_verified(&file, block, hash) {
            Ok(Some(data)) => Ok(FileBlockRead::Found(data)),
            Ok(None) => {
                self.mark_changed(group_id, path, MODIFIED);
                Ok(FileBlockRead::Changed)
            }
            Err(error) => Err(PeerSessionError::Io(error)),
        }
    }
}

/// Reads the range of `block` and returns it when it hashes to `hash`; `None` when the file no
/// longer holds those bytes (short, or different).
fn read_verified(
    file: &std::fs::File,
    block: &BlockInfo,
    hash: &[u8],
) -> std::io::Result<Option<Vec<u8>>> {
    let mut data = vec![0u8; block.size as usize];
    match read_exact_at(file, &mut data, block.offset) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    // Hashed in place: the bytes are only checked here, not kept as a store block, so no copy of them is made.
    let digest = yadorilink_local_storage::hash_block_bytes(&data);
    Ok((digest.as_bytes() == hex::encode(hash).as_bytes()).then_some(data))
}

pub(crate) enum Opened {
    File(std::fs::File),
    /// The file cannot be read as a source right now. Carries the operating system's refusal
    /// when there was one (a busy or provider-owned file has none).
    Unavailable(Option<std::io::ErrorKind>),
    /// There is no such file.
    Gone,
}

#[cfg(unix)]
fn read_exact_at(file: &std::fs::File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::read_exact_at(file, buf, offset)
}

#[cfg(windows)]
fn read_exact_at(file: &std::fs::File, mut buf: &mut [u8], mut offset: u64) -> std::io::Result<()> {
    while !buf.is_empty() {
        let n = std::os::windows::fs::FileExt::seek_read(file, buf, offset)?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf = &mut buf[n..];
        offset += n as u64;
    }
    Ok(())
}

/// Opens the file for reading without following a symlink, and refuses a file that is not fully
/// present on this device (a macOS dataless file would be downloaded by reading it).
#[cfg(unix)]
pub(crate) fn open_source(path: &Path) -> Opened {
    use std::os::unix::fs::OpenOptionsExt;
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Opened::Gone,
        Err(error) => return Opened::Unavailable(Some(error.kind())),
    };
    // apple-cfg: macos-only the desktop daemon's serving path; the iOS host wires its own sessions
    #[cfg(target_os = "macos")]
    {
        use std::os::macos::fs::MetadataExt;
        // SF_DATALESS: the data is not on this device; a read would ask the provider for it.
        const SF_DATALESS: u32 = 0x4000_0000;
        match file.metadata() {
            Ok(metadata) if metadata.st_flags() & SF_DATALESS == 0 => {}
            _ => return Opened::Unavailable(None),
        }
    }
    Opened::File(file)
}

/// Opens the file once, for data, in a way that cannot recall it (`FILE_FLAG_OPEN_NO_RECALL`),
/// sharing it with every other opener so an editor, a rename or a delete is never blocked, and
/// then reads the attributes from that same handle: a reparse point of any kind, an offline file
/// or a file that would be recalled on access is not a source, whichever provider owns it.
#[cfg(windows)]
pub(crate) fn open_source(path: &Path) -> Opened {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const FILE_SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;
    const FILE_FLAG_OPEN_NO_RECALL: u32 = 0x0010_0000;
    // Open a symlink or other reparse point itself, not what it leads to, so that the attributes
    // read below are the link's and it is refused.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_ATTRIBUTE_OFFLINE: u32 = 0x0000_1000;
    const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
    const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_ALL)
        .custom_flags(FILE_FLAG_OPEN_NO_RECALL | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Opened::Gone,
        // A sharing violation or an access refusal: the file is busy, not changed.
        Err(error) => return Opened::Unavailable(Some(error.kind())),
    };
    let not_a_source = FILE_ATTRIBUTE_REPARSE_POINT
        | FILE_ATTRIBUTE_OFFLINE
        | FILE_ATTRIBUTE_RECALL_ON_OPEN
        | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
    match file.metadata() {
        Ok(metadata) if metadata.file_attributes() & not_a_source == 0 => Opened::File(file),
        _ => Opened::Unavailable(None),
    }
}

#[cfg(test)]
mod tests;
