#![cfg(test)]

//! A version too large for one replication item can never be delivered, so it
//! is refused wherever a version is validated, decoded or stored.

use super::*;
use crate::limits::MAX_ENCODED_VERSION_BYTES;

fn file_meta() -> FileMeta {
    FileMeta {
        mtime_unix_nanos: 1,
        unix_mode: None,
        symlink_target: None,
        record_kind: RecordKind::File,
        xattrs: Vec::new(),
    }
}

/// A well-formed regular-file version (block sizes sum to the total, every
/// block non-empty) whose block list alone needs more than the limit.
fn oversized_version() -> FileVersion {
    let count = MAX_ENCODED_VERSION_BYTES / VERSION_BLOCK_ENCODED_BYTES + 1;
    let blocks: Vec<_> = (0..count)
        .map(|i| VersionBlock { hash: BlockHash(vec![(i % 251) as u8; 32]), size: 1 })
        .collect();
    FileVersion::new(blocks, count as u64, file_meta())
}

#[test]
fn an_oversized_version_passes_the_block_count_bound_but_is_refused_by_validation() {
    let version = oversized_version();
    assert!(version.blocks.len() <= MAX_BLOCKS, "the existing bound alone does not catch it");
    assert!(version.encoded_len() > MAX_ENCODED_VERSION_BYTES);
    assert!(matches!(version.verify_hash(), Err(ChangeError::VersionTooLarge { .. })));
}

#[test]
fn a_received_oversized_version_is_refused_at_decode() {
    let encoded = oversized_version().canonical_encoding();
    assert!(matches!(
        FileVersion::from_canonical_encoding(&encoded),
        Err(ChangeError::VersionTooLarge { .. })
    ));
}

#[test]
fn a_version_at_the_limit_is_accepted() {
    let count = (MAX_ENCODED_VERSION_BYTES - 1024) / VERSION_BLOCK_ENCODED_BYTES;
    let blocks: Vec<_> = (0..count)
        .map(|i| VersionBlock { hash: BlockHash(vec![(i % 251) as u8; 32]), size: 1 })
        .collect();
    let version = FileVersion::new(blocks, count as u64, file_meta());
    assert!(version.encoded_len() <= MAX_ENCODED_VERSION_BYTES);
    version.verify_hash().unwrap();
}
