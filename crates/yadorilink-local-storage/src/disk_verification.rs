//! Pure disk-content verification and headroom-preflight helpers: no SQL,
//! no port dependency, just filesystem reads/hashing and the free-space
//! classification this crate already owns.

use std::path::Path;

use sha2::{Digest, Sha256};
use yadorilink_replica_domain::file::BlockInfo;

use crate::free_space;
use crate::StorageError;

/// Preflight check before a hydration fetch or a materialize-to-temp-and-
/// rename write begins, scoped to the volume hosting `root`. Returns
/// `Ok(())` when the write may proceed, or `StorageError::DiskPressure` --
/// never partially writing anything, since this is checked *before* any
/// temp file is created -- when completing a write of `additional_bytes`
/// more would breach the configured headroom.
///
/// `headroom_override_bytes`: `None` uses the default `default headroom`
/// formula; `Some(_)` is an explicit override, both resolved the same way
/// the block-store preflight resolves it. Callers that haven't opted into
/// disk-pressure enforcement at all should not call this at all rather
/// than passing a sentinel.
pub fn check_disk_headroom(
    root: &Path,
    target_path: &Path,
    additional_bytes: u64,
    headroom_override_bytes: Option<u64>,
) -> Result<(), StorageError> {
    let space = free_space::classify_volume(root, headroom_override_bytes)?;
    if space.would_breach(additional_bytes) {
        return Err(StorageError::DiskPressure {
            path: target_path.to_path_buf(),
            volume: root.to_path_buf(),
            available_bytes: space.available_bytes,
            headroom_bytes: space.headroom_bytes,
        });
    }
    Ok(())
}

/// A stable content-derived identifier for a materialization intent's
/// target: SHA-256 over the record's block-hash sequence.
pub fn intent_target_hash(blocks: &[BlockInfo]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for block in blocks {
        hasher.update(&block.hash);
    }
    hasher.finalize().to_vec()
}

/// [`intent_target_hash`]'s counterpart for a materialization intent whose
/// target is not a block list at all -- a symlink's raw target bytes.
/// SHA-256 over the bytes directly, matching `intent_target_hash`'s own
/// "stable content-derived identifier" shape.
pub fn intent_target_hash_for_bytes(target: &[u8]) -> Vec<u8> {
    Sha256::digest(target).to_vec()
}

/// The three distinct ways a path's on-disk content can relate to a set of
/// indexed blocks. Collapsing `PresentButDifferent` and `Absent` into one
/// `false` is what let a pre-materialize guard misread "this path's parent
/// directory was renamed and the local pipeline hasn't caught up yet" as
/// "an unauthored local edit is on disk", declining a legitimate
/// fast-forward materialize forever -- callers must not silently
/// re-collapse this distinction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskContentComparison {
    /// The file exists and every indexed block's bytes match, with no
    /// trailing content beyond the last block.
    Matched,
    /// A file exists at the path, but its bytes diverge from the indexed
    /// blocks (a different hash, a short read, or trailing bytes past the
    /// last indexed block).
    PresentButDifferent,
    /// Nothing exists at the path at all.
    Absent,
}

/// Compares a path's on-disk bytes against a set of indexed blocks,
/// distinguishing "content differs" from "nothing is there" -- see
/// [`DiskContentComparison`]'s doc for why that distinction matters. Reads
/// the file once, streaming each block's SHA-256 in sequence and
/// early-exiting on the first mismatch.
pub fn disk_content_comparison(
    path: &Path,
    blocks: &[BlockInfo],
) -> Result<DiskContentComparison, StorageError> {
    disk_content_comparison_observed(path, blocks, &|_| {})
}

/// [`disk_content_comparison`] that reports, after each block whose hash MATCHED, that block's
/// size. A block that does not match, or is short, is never reported, so the reported total can
/// only reach the file's size when every block verified.
pub fn disk_content_comparison_observed(
    path: &Path,
    blocks: &[BlockInfo],
    verified: &dyn Fn(u64),
) -> Result<DiskContentComparison, StorageError> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(DiskContentComparison::Absent);
        }
        Err(e) => return Err(e.into()),
    };
    file_content_comparison_observed(&mut file, blocks, verified)
}

/// [`disk_content_comparison`] for an already open file, read from its current offset: the
/// bytes are those of the object the handle names, whatever its path has become since.
pub fn file_content_comparison(
    file: &mut std::fs::File,
    blocks: &[BlockInfo],
) -> Result<DiskContentComparison, StorageError> {
    file_content_comparison_observed(file, blocks, &|_| {})
}

fn file_content_comparison_observed(
    file: &mut std::fs::File,
    blocks: &[BlockInfo],
    verified: &dyn Fn(u64),
) -> Result<DiskContentComparison, StorageError> {
    use std::io::Read;

    for block in blocks {
        let mut bytes = vec![0u8; block.size as usize];
        if let Err(error) = file.read_exact(&mut bytes) {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                return Ok(DiskContentComparison::PresentButDifferent);
            }
            return Err(error.into());
        }
        if Sha256::digest(&bytes).as_slice() != block.hash.as_slice() {
            return Ok(DiskContentComparison::PresentButDifferent);
        }
        verified(block.size as u64);
    }
    let mut trailing = [0u8; 1];
    Ok(if file.read(&mut trailing)? == 0 {
        DiskContentComparison::Matched
    } else {
        DiskContentComparison::PresentButDifferent
    })
}

/// Whether a path's on-disk bytes exactly match a set of indexed blocks --
/// a thin wrapper over [`disk_content_comparison`] for the (common) callers
/// that only need "is this already current", where `PresentButDifferent`
/// and `Absent` are equally "no, it isn't" and nothing downstream needs to
/// tell them apart.
///
/// **Do not use this for a "may I overwrite this path" decision.** That
/// question needs [`disk_content_comparison`] directly: overwriting
/// `PresentButDifferent` bytes destroys an unauthored local edit
/// permanently, while a path that is `Absent` may legitimately be safe to
/// write into.
pub fn disk_bytes_match_indexed_blocks(
    path: &Path,
    blocks: &[BlockInfo],
) -> Result<bool, StorageError> {
    Ok(matches!(disk_content_comparison(path, blocks)?, DiskContentComparison::Matched))
}

/// What one exact object is supposed to be, chosen by the kind its own
/// version declares -- the input to [`disk_matches_expected_object`].
#[derive(Debug, Clone, Copy)]
pub enum ExpectedObject<'a> {
    /// A regular file holding exactly these blocks, in order, with
    /// nothing past the last one.
    File { blocks: &'a [BlockInfo] },
    /// A symlink whose raw target bytes are exactly these.
    Symlink { target: Option<&'a [u8]> },
    /// A directory. Nothing below it is this check's business: the paths
    /// inside are their own index rows with their own proofs.
    Directory,
}

/// Verifies that `path` holds exactly the object `expected` describes,
/// with the comparison chosen by kind rather than assumed.
///
/// [`disk_content_comparison`] answers one question -- "does this regular
/// file hold these bytes" -- and answers it by `File::open`, which follows
/// symlinks and cannot read a directory at all. Asking it about a symlink
/// compares the TARGET's bytes against the link's (empty) block list, so a
/// correctly restored link to a non-empty file reads as different and a
/// correctly restored dangling link reads as absent. Asking it about a
/// directory returns an I/O error from the read. Every one of those is a
/// wrong answer about a path that is exactly right, and a caller that
/// treats "not verified" as "must redo the work" acts on it.
///
/// Fail-closed throughout: anything that cannot be positively confirmed is
/// [`DiskContentComparison::PresentButDifferent`], and only a genuine
/// "nothing is there" is [`DiskContentComparison::Absent`]. The kind check
/// is `symlink_metadata`, never `metadata`, so a symlink is never mistaken
/// for whatever it points at.
pub fn disk_matches_expected_object(
    path: &Path,
    expected: ExpectedObject<'_>,
) -> Result<DiskContentComparison, StorageError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(DiskContentComparison::Absent);
        }
        Err(e) => return Err(e.into()),
    };
    match expected {
        ExpectedObject::File { blocks } => {
            if !metadata.is_file() {
                return Ok(DiskContentComparison::PresentButDifferent);
            }
            disk_content_comparison(path, blocks)
        }
        ExpectedObject::Symlink { target } => {
            if !metadata.is_symlink() {
                return Ok(DiskContentComparison::PresentButDifferent);
            }
            // A version with no recorded target says nothing about what
            // the link should point at, so nothing on disk can confirm
            // it -- not even a link that happens to exist.
            let Some(target) = target else {
                return Ok(DiskContentComparison::PresentButDifferent);
            };
            let actual = match std::fs::read_link(path) {
                Ok(actual) => actual,
                // The link is there (`symlink_metadata` succeeded) but its
                // target cannot be read: unconfirmed, not absent.
                Err(_) => return Ok(DiskContentComparison::PresentButDifferent),
            };
            // `target_to_bytes` is this workspace's one definition of what
            // a symlink target's captured bytes ARE -- the same conversion
            // local capture used to record the value being compared
            // against, and the same one `bytes_to_target` inverts to write
            // the link. Comparing through anything else here would be a
            // second, independently-lossy encoding of one thing.
            Ok(if yadorilink_fs_platform::fs_identity::target_to_bytes(&actual) == target {
                DiskContentComparison::Matched
            } else {
                DiskContentComparison::PresentButDifferent
            })
        }
        ExpectedObject::Directory => Ok(if metadata.is_dir() {
            DiskContentComparison::Matched
        } else {
            DiskContentComparison::PresentButDifferent
        }),
    }
}

/// The blind spot [`disk_matches_expected_object`] exists to close: exact
/// verification used to be `disk_content_comparison` everywhere, which is a
/// regular-file question wearing a general name. Restore recovery asked it
/// about symlinks and directories, and got a wrong answer for a path that
/// was exactly right -- then quarantined the user's correctly restored file
/// on the strength of it.
#[cfg(test)]
mod expected_object_tests;
