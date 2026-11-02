//! Builds an offer's manifest by chunking the source path into Track
//! Send's own `SegmentBlockStore` (see [`crate::session::SendService::new`]) --
//! reusing `yadorilink_local_storage::chunker::chunk_file` exactly as the
//! sync engine does for its own captures, just against a wholly separate
//! store root (see `store.rs`'s own doc comment for why: dedup and crash-
//! durable commits for free, with zero visibility to the sync engine's
//! native-state-driven GC liveness sweep).
//!
//! Chunking a file freezes its offered content at offer time: once
//! `build_outbound_manifest` returns, every chunk is durably content-
//! addressed in the local store, so a later pull never re-reads (or can be
//! confused by an edit to) the original source path.

use std::path::{Path, PathBuf};

use yadorilink_ipc_proto::send::{SendFileEntry, SendManifest};
#[cfg(test)]
use yadorilink_local_storage::DEFAULT_BLOCK_SIZE;
use yadorilink_local_storage::{
    block_size_for, chunk_file, hash_block_bytes, BlockContentStore, ContentHash,
    LocallyHashedBlock, StorageError,
};

use crate::error::{Result, SendError};

/// A "store" that only hashes: building a manifest against it measures what a source holds now
/// without writing a single block, for a check that must leave no content behind (a retry that
/// finds the source changed sends nothing, so it must not keep the new content either).
pub(crate) struct HashOnlyStore;

impl BlockContentStore for HashOnlyStore {
    fn put(&self, data: &[u8]) -> std::result::Result<ContentHash, StorageError> {
        Ok(hash_block_bytes(data))
    }
    fn put_prepared(&self, _: &LocallyHashedBlock) -> std::result::Result<(), StorageError> {
        Ok(())
    }
    fn put_prepared_batch(
        &self,
        _: &[LocallyHashedBlock],
    ) -> std::result::Result<(), StorageError> {
        Ok(())
    }
    fn get(&self, hash: &str) -> std::result::Result<Vec<u8>, StorageError> {
        Err(StorageError::NotFound(hash.to_string()))
    }
    fn present_blocks(
        &self,
        hashes: &[ContentHash],
    ) -> std::result::Result<Vec<bool>, StorageError> {
        Ok(vec![false; hashes.len()])
    }
}

/// Walks `source_path`: a single regular file becomes one entry named by
/// its own file name; a directory becomes one entry per regular file found
/// by a recursive walk, named by its path relative to `source_path` with
/// forward slashes (never the platform separator, so a manifest built on
/// Windows and received on macOS/Linux names files identically).
///
/// Symlinks are skipped rather than followed or sent as symlinks -- v1
/// scope is plain file content, matching a one-shot Taildrop/Resilio-style
/// send; nothing downstream (the manifest, the wire protocol,
/// `reconstruct_file`) has a symlink representation to skip past.
fn collect_files(source_path: &Path) -> Result<Vec<(String, PathBuf)>> {
    let metadata = std::fs::symlink_metadata(source_path)?;
    if metadata.is_file() {
        let name = source_path
            .file_name()
            .ok_or_else(|| {
                SendError::Protocol(format!("{}: has no file name", source_path.display()))
            })?
            .to_string_lossy()
            .into_owned();
        return Ok(vec![(name, source_path.to_path_buf())]);
    }
    if !metadata.is_dir() {
        // Symlink, device file, etc. -- neither a file nor a directory
        // this walk knows how to represent.
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(source_path).follow_links(false).sort_by_file_name() {
        let entry = entry.map_err(std::io::Error::from)?;
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(source_path)
            .expect("walkdir yields paths under its own root");
        // Forward slashes on every platform -- see this function's own
        // doc comment.
        let relative_str = relative
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        out.push((relative_str, entry.path().to_path_buf()));
    }
    Ok(out)
}

/// The sources of one offer, in their stored form: a lone source is its plain path (exactly what
/// older stores hold); several are a JSON array, which no absolute path can look like.
pub fn encode_sources(sources: &[PathBuf]) -> String {
    match sources {
        [only] => only.to_string_lossy().into_owned(),
        many => serde_json::to_string(
            &many.iter().map(|p| p.to_string_lossy().into_owned()).collect::<Vec<_>>(),
        )
        .expect("a list of strings always serializes"),
    }
}

/// Inverse of [`encode_sources`].
pub fn decode_sources(stored: &str) -> Vec<PathBuf> {
    if stored.starts_with('[') {
        if let Ok(list) = serde_json::from_str::<Vec<String>>(stored) {
            return list.into_iter().map(PathBuf::from).collect();
        }
    }
    vec![PathBuf::from(stored)]
}

/// `name`, or `stem (n).ext` for the first `n >= 2` that no earlier top-level name took
/// (compared case-insensitively, since the receiver's filesystem may fold case).
fn unique_top_name(name: &str, taken: &mut std::collections::HashSet<String>) -> String {
    let mut candidate = name.to_string();
    let mut n = 2;
    while !taken.insert(candidate.to_lowercase()) {
        candidate = match name.rsplit_once('.') {
            Some((stem, ext)) if !stem.is_empty() => format!("{stem} ({n}).{ext}"),
            _ => format!("{name} ({n})"),
        };
        n += 1;
    }
    candidate
}

/// Walks every source. One source is named as [`collect_files`] names it. With several, each
/// source is a top-level item of the offer: a file is its own basename and a folder's files sit
/// under the folder's basename; two sources with the same basename get distinct names.
fn collect_sources(sources: &[PathBuf]) -> Result<Vec<(String, PathBuf)>> {
    if let [only] = sources {
        return collect_files(only);
    }
    let mut taken = std::collections::HashSet::new();
    let mut out = Vec::new();
    for source in sources {
        let top = source
            .file_name()
            .ok_or_else(|| SendError::Protocol(format!("{}: has no file name", source.display())))?
            .to_string_lossy()
            .into_owned();
        let top = unique_top_name(&top, &mut taken);
        let is_dir = std::fs::symlink_metadata(source)?.is_dir();
        for (relative, absolute) in collect_files(source)? {
            out.push((if is_dir { format!("{top}/{relative}") } else { top.clone() }, absolute));
        }
    }
    Ok(out)
}

/// The files an offer of `source_path` would carry, as (relative path, size), without chunking
/// or storing anything: what a recipient is shown before agreeing to receive.
pub fn list_offered_files(source_path: &Path) -> Result<Vec<(String, u64)>> {
    list_offered_files_multi(&[source_path.to_path_buf()])
}

/// [`list_offered_files`] for an offer of several sources.
pub fn list_offered_files_multi(sources: &[PathBuf]) -> Result<Vec<(String, u64)>> {
    collect_sources(sources)?
        .into_iter()
        .map(|(relative, absolute)| Ok((relative, std::fs::metadata(&absolute)?.len())))
        .collect()
}

/// Chunks every file under `source_path` into `store`, returning a
/// manifest describing the offer -- `total_size` mirrors
/// `manifest.total_size` for a caller that just needs the number without
/// decoding.
pub fn build_outbound_manifest(
    store: &dyn BlockContentStore,
    source_path: &Path,
    transfer_id: &str,
) -> Result<(SendManifest, u64)> {
    build_outbound_manifest_multi(store, &[source_path.to_path_buf()], transfer_id)
}

/// [`build_outbound_manifest`] for an offer of several sources (see [`collect_sources`]).
pub fn build_outbound_manifest_multi(
    store: &dyn BlockContentStore,
    sources: &[PathBuf],
    transfer_id: &str,
) -> Result<(SendManifest, u64)> {
    let files = collect_sources(sources)?;
    if files.is_empty() {
        return Err(SendError::EmptyManifest(encode_sources(sources)));
    }
    let mut entries = Vec::with_capacity(files.len());
    let mut total_size: u64 = 0;
    for (relative_path, absolute_path) in files {
        let size = std::fs::metadata(&absolute_path)?.len();
        let blocks = chunk_file(store, &absolute_path)?;
        let chunk_hashes = blocks.into_iter().map(|b| b.hash).collect::<Vec<_>>();
        let chunk_size = block_size_for(size) as u32;
        total_size += size;
        entries.push(SendFileEntry { relative_path, size, chunk_size, chunk_hashes });
    }
    let offered_at_unix_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i64;
    Ok((
        SendManifest {
            transfer_id: transfer_id.to_string(),
            files: entries,
            total_size,
            offered_at_unix_nanos,
            link_id: String::new(),
        },
        total_size,
    ))
}

/// The offered name as `a/b/c`, refusing anything that is not a plain relative path: empty,
/// absolute, a drive or UNC prefix, a backslash, or any `.` / `..` / empty component.
fn validated_relative_path(name: &str) -> std::result::Result<&str, String> {
    let bad = name.is_empty()
        || name.contains('\\')
        || name.contains('\0')
        || name.split('/').any(|part| part.is_empty() || part == "." || part == "..")
        || name.split('/').next().is_some_and(|first| first.contains(':'));
    if bad {
        return Err(format!("{name:?}: not a plain relative path"));
    }
    Ok(name)
}

/// Length of a chunk hash (SHA-256).
const CHUNK_HASH_LEN: usize = 32;

/// Checks an offered manifest is internally consistent before it is stored,
/// so nothing downstream sizes an allocation from a claim the sender made up:
/// every file's `chunk_size` is within `1..=MAX_BLOCK_SIZE_BYTES`, its hash
/// count is exactly `ceil(size / chunk_size)` with every hash a SHA-256
/// digest, and `total_size` is the sum of the file sizes. The reason names
/// the first inconsistency.
pub fn validate_offered_manifest(manifest: &SendManifest) -> std::result::Result<(), String> {
    let max_chunk = yadorilink_replica_domain::limits::MAX_BLOCK_SIZE_BYTES;
    let mut total: u64 = 0;
    let mut seen = std::collections::HashSet::new();
    let mut dirs = std::collections::HashSet::new();
    for entry in &manifest.files {
        let name = &entry.relative_path;
        let normal = validated_relative_path(name)?;
        if !seen.insert(normal.to_lowercase()) {
            return Err(format!("{name}: offered more than once"));
        }
        for (i, _) in normal.match_indices('/') {
            dirs.insert(normal[..i].to_lowercase());
        }
        if entry.chunk_size == 0 || entry.chunk_size > max_chunk {
            return Err(format!(
                "{name}: chunk size {} is outside 1..={max_chunk}",
                entry.chunk_size
            ));
        }
        let expected_chunks = entry.size.div_ceil(u64::from(entry.chunk_size));
        if entry.chunk_hashes.len() as u64 != expected_chunks {
            return Err(format!(
                "{name}: {} chunk hashes for {} bytes in chunks of {}, expected {expected_chunks}",
                entry.chunk_hashes.len(),
                entry.size,
                entry.chunk_size
            ));
        }
        if entry.chunk_hashes.iter().any(|hash| hash.len() != CHUNK_HASH_LEN) {
            return Err(format!("{name}: a chunk hash is not {CHUNK_HASH_LEN} bytes"));
        }
        total = total
            .checked_add(entry.size)
            .ok_or_else(|| "the file sizes overflow the total".to_string())?;
    }
    if let Some(clash) = seen.iter().find(|name| dirs.contains(*name)) {
        return Err(format!("{clash}: offered as both a file and a folder"));
    }
    if total != manifest.total_size {
        return Err(format!(
            "total size {} does not match the files' {total} bytes",
            manifest.total_size
        ));
    }
    Ok(())
}

/// The byte size of chunk `chunk_index` within `entry` -- every chunk is
/// `entry.chunk_size` bytes except the last, which is whatever remains.
/// Matches `chunk_file`'s own fixed-size splitting exactly (a short final
/// read), so a value computed here always agrees with what the sender's
/// local store actually holds under that chunk's hash.
pub fn chunk_byte_size(entry: &SendFileEntry, chunk_index: usize) -> Result<u32> {
    let num_chunks = entry.chunk_hashes.len();
    if chunk_index >= num_chunks {
        return Err(SendError::Protocol(format!(
            "chunk index {chunk_index} out of range for {} chunks",
            num_chunks
        )));
    }
    if chunk_index + 1 < num_chunks {
        return Ok(entry.chunk_size);
    }
    let full_chunks = (num_chunks as u64 - 1).saturating_mul(u64::from(entry.chunk_size));
    u32::try_from(entry.size.saturating_sub(full_chunks)).map_err(|_| {
        SendError::Protocol(format!("final chunk of {} bytes does not fit a chunk", entry.size))
    })
}

#[cfg(test)]
mod tests;
