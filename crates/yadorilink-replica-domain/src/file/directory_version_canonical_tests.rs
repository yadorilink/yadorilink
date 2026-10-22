#![cfg(test)]

//! A directory version's identity is its kind plus its replicated
//! permission bits. The size and mtime a filesystem reports for a
//! directory are observations of its children (entry-table size, last
//! child change), not state of the directory itself, so they must never
//! reach `version_hash`: otherwise every child change re-authors the
//! parent, and two devices that `mkdir` the same name concurrently mint
//! two versions and a spurious conflict copy of an empty directory.

use super::*;

fn directory_meta(mtime_unix_nanos: i64, unix_mode: Option<u32>) -> FileMeta {
    FileMeta {
        mtime_unix_nanos,
        unix_mode,
        symlink_target: None,
        record_kind: RecordKind::Directory,
        xattrs: Vec::new(),
    }
}

fn directory_row(size: u64, mtime_unix_nanos: i64, unix_mode: Option<u32>) -> FileVersion {
    FileVersion::from_index_row(
        Vec::new(),
        size,
        mtime_unix_nanos,
        RecordKind::Directory,
        unix_mode,
        None,
        Vec::new(),
    )
}

#[test]
fn directory_version_with_nonzero_size_is_malformed() {
    let version = FileVersion::new(Vec::new(), 4096, directory_meta(0, Some(0o755)));
    let err = version.verify_hash().unwrap_err();
    assert!(matches!(err, ChangeError::Malformed(_)), "got {err:?}");

    // The same bytes arriving from a peer are refused at decode too.
    let err = FileVersion::from_canonical_encoding(&version.canonical_encoding()).unwrap_err();
    assert!(matches!(err, ChangeError::Malformed(_)), "got {err:?}");
}

#[test]
fn directory_version_with_nonzero_mtime_is_malformed() {
    let version =
        FileVersion::new(Vec::new(), 0, directory_meta(1_700_000_000_123_456_789, Some(0o755)));
    let err = version.verify_hash().unwrap_err();
    assert!(matches!(err, ChangeError::Malformed(_)), "got {err:?}");

    let err = FileVersion::from_canonical_encoding(&version.canonical_encoding()).unwrap_err();
    assert!(matches!(err, ChangeError::Malformed(_)), "got {err:?}");
}

#[test]
fn directory_versions_differing_only_in_observed_size_and_mtime_hash_equal() {
    // What two devices' index rows for the same freshly made directory
    // plausibly hold: APFS reports 64/96-byte sizes, ext4 4096, and each
    // device observed its own mtime.
    let on_mac = directory_row(96, 1_700_000_000_000_000_001, Some(0o755));
    let on_linux = directory_row(4096, 1_700_000_123_000_000_000, Some(0o755));
    assert_eq!(on_mac.version_hash, on_linux.version_hash);
    assert_eq!(on_mac.size, 0);
    assert_eq!(on_mac.meta.mtime_unix_nanos, 0);
    on_mac.verify_hash().unwrap();
    on_linux.verify_hash().unwrap();
    assert_eq!(FileVersion::from_canonical_encoding(&on_mac.canonical_encoding()).unwrap(), on_mac);
}

#[test]
fn the_directory_constructor_is_the_canonical_row_version() {
    let canonical = FileVersion::directory(Some(0o755));
    canonical.verify_hash().unwrap();
    assert_eq!(canonical, directory_row(4096, 1_700_000_000_000_000_001, Some(0o755)));
}

/// `unix_mode` stays part of a directory's identity, exactly as for a
/// file: a `chmod` is an explicit change, and a device with no Unix mode
/// model (`None`) authors a distinct version, never a fabricated mode.
#[test]
fn directory_unix_mode_remains_part_of_its_identity() {
    let private = directory_row(0, 0, Some(0o700));
    let shared = directory_row(0, 0, Some(0o755));
    let no_mode = directory_row(0, 0, None);
    assert_ne!(private.version_hash, shared.version_hash);
    assert_ne!(shared.version_hash, no_mode.version_hash);
    no_mode.verify_hash().unwrap();
}

/// The canonicalization is directory-only: a regular file and a symlink
/// keep size and mtime in their identity, byte for byte as before.
#[test]
fn file_and_symlink_version_hashes_are_unchanged() {
    let file = FileVersion::from_index_row(
        vec![BlockInfo { hash: vec![0xAB; 32], offset: 0, size: 5 }],
        5,
        1_700_000_000_000_000_001,
        RecordKind::File,
        Some(0o644),
        None,
        vec![("user.tag".to_string(), b"v".to_vec())],
    );
    let symlink = FileVersion::from_index_row(
        Vec::new(),
        11,
        1_700_000_000_000_000_002,
        RecordKind::Symlink,
        None,
        Some(b"../target.txt".to_vec()),
        Vec::new(),
    );
    let empty_file = FileVersion::from_index_row(
        Vec::new(),
        0,
        1_700_000_000_000_000_003,
        RecordKind::File,
        None,
        None,
        Vec::new(),
    );
    assert_eq!(hex::encode(file.version_hash.0), FILE_GOLDEN);
    assert_eq!(hex::encode(symlink.version_hash.0), SYMLINK_GOLDEN);
    assert_eq!(hex::encode(empty_file.version_hash.0), EMPTY_FILE_GOLDEN);
}

const FILE_GOLDEN: &str = "cb2132993d85b504636f1e48645a3ff6b1c635c9aed2f5cb87533971b8dc91bc";
const SYMLINK_GOLDEN: &str = "5f5db1b79a55588d8264de670fc8f0c36064d883e40ea28c0dc4cef44f616957";
const EMPTY_FILE_GOLDEN: &str = "c10ddbaf561f091cfe250d0f83e0f7d41ebcd6c281a1d408a7260a92c5cd08ec";

/// A directory's index row can still hold the blocks of the file that
/// stood at its path before it (a path deleted as a file and made again as
/// a directory). They describe no content of the directory, and a version
/// minted from the row with them is malformed: a seal that carries it is
/// refused as an invalid snapshot, and keeps being refused. The row mints
/// the canonical directory version instead.
#[test]
fn a_directory_row_holding_a_former_files_blocks_mints_the_canonical_version() {
    let leftover = vec![BlockInfo { hash: vec![0xab; 32], offset: 0, size: 4096 }];
    let version = FileVersion::from_index_row(
        leftover,
        4096,
        1_700_000_000_000_000_000,
        RecordKind::Directory,
        Some(0o755),
        None,
        Vec::new(),
    );
    version.verify_hash().expect("a version minted from a directory row is well formed");
    assert_eq!(version, directory_row(0, 0, Some(0o755)));
}
