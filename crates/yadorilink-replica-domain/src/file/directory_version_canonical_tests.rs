#![cfg(test)]

//! A directory version's identity is its kind alone: its mode is not replicated. The size and mtime a filesystem reports for a
//! directory are observations of its children (entry-table size, last
//! child change), not state of the directory itself, so they must never
//! reach `version_hash`: otherwise every child change re-authors the
//! parent, and two devices that `mkdir` the same name concurrently mint
//! two versions and a spurious conflict copy of an empty directory.

use super::*;

fn directory_meta(mtime_unix_nanos: i64) -> FileMeta {
    FileMeta {
        mtime_unix_nanos,
        exec: false,
        symlink_target: None,
        record_kind: RecordKind::Directory,
    }
}

fn directory_row(size: u64, mtime_unix_nanos: i64) -> FileVersion {
    FileVersion::from_index_row(
        Vec::new(),
        size,
        mtime_unix_nanos,
        RecordKind::Directory,
        false,
        None,
    )
}

#[test]
fn directory_version_with_nonzero_size_is_malformed() {
    let version = FileVersion::new(Vec::new(), 4096, directory_meta(0));
    let err = version.verify_hash().unwrap_err();
    assert!(matches!(err, ChangeError::Malformed(_)), "got {err:?}");

    // The same bytes arriving from a peer are refused at decode too.
    let err = FileVersion::from_canonical_encoding(&version.canonical_encoding()).unwrap_err();
    assert!(matches!(err, ChangeError::Malformed(_)), "got {err:?}");
}

#[test]
fn directory_version_with_nonzero_mtime_is_malformed() {
    let version = FileVersion::new(Vec::new(), 0, directory_meta(1_700_000_000_123_456_789));
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
    let on_mac = directory_row(96, 1_700_000_000_000_000_001);
    let on_linux = directory_row(4096, 1_700_000_123_000_000_000);
    assert_eq!(on_mac.version_hash, on_linux.version_hash);
    assert_eq!(on_mac.size, 0);
    assert_eq!(on_mac.meta.mtime_unix_nanos, 0);
    on_mac.verify_hash().unwrap();
    on_linux.verify_hash().unwrap();
    assert_eq!(FileVersion::from_canonical_encoding(&on_mac.canonical_encoding()).unwrap(), on_mac);
}

#[test]
fn the_directory_constructor_is_the_canonical_row_version() {
    let canonical = FileVersion::directory();
    canonical.verify_hash().unwrap();
    assert_eq!(canonical, directory_row(4096, 1_700_000_000_000_000_001));
}

/// An executable flag on a row that names a directory is not part of the directory's identity:
/// the row mints the one canonical directory version.
#[test]
fn a_directory_rows_exec_flag_never_reaches_its_identity() {
    let marked = FileVersion::from_index_row(Vec::new(), 0, 0, RecordKind::Directory, true, None);
    assert_eq!(marked, FileVersion::directory());
    marked.verify_hash().unwrap();
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
        true,
        None,
    );
    let symlink = FileVersion::from_index_row(
        Vec::new(),
        11,
        1_700_000_000_000_000_002,
        RecordKind::Symlink,
        false,
        Some(b"../target.txt".to_vec()),
    );
    let empty_file = FileVersion::from_index_row(
        Vec::new(),
        0,
        1_700_000_000_000_000_003,
        RecordKind::File,
        false,
        None,
    );
    assert_eq!(hex::encode(file.version_hash.0), FILE_GOLDEN);
    assert_eq!(hex::encode(symlink.version_hash.0), SYMLINK_GOLDEN);
    assert_eq!(hex::encode(empty_file.version_hash.0), EMPTY_FILE_GOLDEN);
}

const FILE_GOLDEN: &str = "44a1ac8af8e6474e5aaa68951853769f82ec886fe27dc16c9ce51da8bf808592";
const SYMLINK_GOLDEN: &str = "9d5fff465ba51627c812b95f18e90ba4814b8cd58b583b8299452ae72b8ca70b";
const EMPTY_FILE_GOLDEN: &str = "d95949b1269052d2e4ca68d70ca1f956dc29a5101cb64284f1750e96a646e59c";

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
        false,
        None,
    );
    version.verify_hash().expect("a version minted from a directory row is well formed");
    assert_eq!(version, directory_row(0, 0));
}
