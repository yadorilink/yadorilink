//! Damage and time-travel helpers for tests in *other* crates.
//!
//! These take a store **root directory** rather than a handle, because the
//! tests that need them (daemon integration tests, CLI tests) are driving
//! a live daemon that already owns the only handle on that root -- and one
//! root gets one handle, by design. Reaching the same bytes and the same
//! index rows through a second, read-mostly connection is exactly what
//! external corruption and clock drift look like to the store, which is
//! what these are modelling.
//!
//! Every function here is a test seam. Nothing in a shipping binary calls
//! any of them; they are ordinary `pub` items (rather than `#[cfg(test)]`)
//! only because `cfg(test)` does not cross a crate boundary.

use std::path::Path;
use std::time::SystemTime;

use rusqlite::{Connection, OptionalExtension};

use crate::error::StorageError;
use crate::segment_store::format::{RAW_HASH_LEN, RECORD_HEADER_LEN};
use crate::segment_store::segment::{segment_id_from_file_name, segment_path, SEGMENTS_DIR};

/// Opens a second connection on a store's index. WAL mode lets this
/// coexist with the live handle's own connections; `busy_timeout` covers
/// the moment a group commit happens to hold the write lock.
fn open_index(root: &Path) -> Result<Connection, StorageError> {
    let conn = Connection::open(root.join("index.sqlite3"))
        .map_err(|e| StorageError::Index(e.to_string()))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|e| StorageError::Index(e.to_string()))?;
    Ok(conn)
}

fn raw(hash_hex: &str) -> Result<[u8; RAW_HASH_LEN], StorageError> {
    let mut out = [0u8; RAW_HASH_LEN];
    hex::decode_to_slice(hash_hex, &mut out)?;
    Ok(out)
}

/// Where one block's payload sits: `(segment_id, payload_offset, length)`.
fn locate(root: &Path, hash_hex: &str) -> Result<Option<(u64, u64, u32)>, StorageError> {
    let conn = open_index(root)?;
    conn.query_row(
        "SELECT segment_id, record_offset, payload_len FROM blocks WHERE hash = ?1",
        [&raw(hash_hex)?[..]],
        |row| {
            Ok((
                row.get::<_, i64>(0)? as u64,
                row.get::<_, i64>(1)? as u64 + RECORD_HEADER_LEN as u64,
                row.get::<_, i64>(2)? as u32,
            ))
        },
    )
    .optional()
    .map_err(|e| StorageError::Index(e.to_string()))
}

/// Backdates one block's recorded ingest time, so a GC grace-window test
/// does not have to wait out a real grace window.
///
/// The segment store records ingest time in its index rather than reading
/// a file's mtime, so this is the equivalent of the mtime backdating a
/// file-per-block store needed -- and a more faithful one, since a
/// compaction that rewrites a block preserves its recorded ingest time
/// where an mtime would be reset by the copy.
pub fn backdate_block(root: &Path, hash_hex: &str, when: SystemTime) -> Result<(), StorageError> {
    let nanos = when
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos().min(i64::MAX as u128) as i64)
        .unwrap_or(0);
    let conn = open_index(root)?;
    let changed = conn
        .execute(
            "UPDATE blocks SET added_at = ?2 WHERE hash = ?1",
            rusqlite::params![&raw(hash_hex)?[..], nanos],
        )
        .map_err(|e| StorageError::Index(e.to_string()))?;
    if changed == 0 {
        return Err(StorageError::NotFound(hash_hex.to_string()));
    }
    Ok(())
}

/// Overwrites the start of one block's stored payload, modelling bit rot
/// or a torn write. The record framing is left intact, so what the store
/// meets is precisely the case its content verification exists for: a
/// record it can find and parse whose bytes are not the block they claim
/// to be.
pub fn corrupt_block_payload(
    root: &Path,
    hash_hex: &str,
    replacement: &[u8],
) -> Result<(), StorageError> {
    use std::io::{Seek, SeekFrom, Write};
    let (segment_id, payload_offset, length) =
        locate(root, hash_hex)?.ok_or_else(|| StorageError::NotFound(hash_hex.to_string()))?;
    let mut file = std::fs::OpenOptions::new().write(true).open(segment_path(root, segment_id))?;
    file.seek(SeekFrom::Start(payload_offset))?;
    let take = replacement.len().min(length as usize);
    if take == 0 {
        return Err(StorageError::InvalidPath(
            "replacement bytes must overlap the stored payload".into(),
        ));
    }
    file.write_all(&replacement[..take])?;
    file.sync_data()?;
    Ok(())
}

/// Flips every bit of one payload byte -- the smallest damage that still
/// breaks the content hash.
pub fn flip_one_payload_bit(root: &Path, hash_hex: &str) -> Result<(), StorageError> {
    use std::io::{Read, Seek, SeekFrom, Write};
    let (segment_id, payload_offset, _) =
        locate(root, hash_hex)?.ok_or_else(|| StorageError::NotFound(hash_hex.to_string()))?;
    let mut file =
        std::fs::OpenOptions::new().read(true).write(true).open(segment_path(root, segment_id))?;
    file.seek(SeekFrom::Start(payload_offset))?;
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte)?;
    byte[0] ^= 0x01;
    file.seek(SeekFrom::Start(payload_offset))?;
    file.write_all(&byte)?;
    file.sync_data()?;
    Ok(())
}

/// Every segment id present on disk, oldest first.
pub fn segment_ids_on_disk(root: &Path) -> Result<Vec<u64>, StorageError> {
    let mut ids = Vec::new();
    let entries = match std::fs::read_dir(root.join(SEGMENTS_DIR)) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ids),
        Err(e) => return Err(StorageError::Io(e)),
    };
    for entry in entries {
        let entry = entry?;
        if let Some(id) = entry.file_name().to_str().and_then(segment_id_from_file_name) {
            ids.push(id);
        }
    }
    ids.sort_unstable();
    Ok(ids)
}

/// Cuts a segment file down to `len` bytes, modelling a lost tail.
pub fn truncate_segment(root: &Path, segment_id: u64, len: u64) -> Result<(), StorageError> {
    let file = std::fs::OpenOptions::new().write(true).open(segment_path(root, segment_id))?;
    file.set_len(len)?;
    file.sync_data()?;
    Ok(())
}

/// Appends `bytes` past a segment's end without touching the index,
/// modelling a group that was appended (and even fsynced) but whose
/// transaction never committed.
pub fn append_uncommitted_bytes(
    root: &Path,
    segment_id: u64,
    bytes: &[u8],
) -> Result<(), StorageError> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new().append(true).open(segment_path(root, segment_id))?;
    file.write_all(bytes)?;
    file.sync_data()?;
    Ok(())
}

/// Deletes one segment file outright, modelling a lost file.
pub fn delete_segment(root: &Path, segment_id: u64) -> Result<(), StorageError> {
    crate::fs_ops::remove_path(&segment_path(root, segment_id))?;
    Ok(())
}

/// What the index records for one segment: `(state, durable_end,
/// live_blocks)`.
pub fn segment_row(
    root: &Path,
    segment_id: u64,
) -> Result<Option<(String, u64, u64)>, StorageError> {
    let conn = open_index(root)?;
    conn.query_row(
        "SELECT state, durable_end, live_blocks FROM segments WHERE segment_id = ?1",
        [segment_id as i64],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? as u64,
                row.get::<_, i64>(2)? as u64,
            ))
        },
    )
    .optional()
    .map_err(|e| StorageError::Index(e.to_string()))
}

/// Every hash the index maps, in key order. Lets a test assert what a
/// reopened store believes it holds without going through the store's own
/// read path.
pub fn indexed_hashes(root: &Path) -> Result<Vec<String>, StorageError> {
    let conn = open_index(root)?;
    let mut stmt = conn
        .prepare("SELECT hash FROM blocks ORDER BY hash")
        .map_err(|e| StorageError::Index(e.to_string()))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .map_err(|e| StorageError::Index(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::Index(e.to_string()))?;
    Ok(rows.into_iter().map(hex::encode).collect())
}
