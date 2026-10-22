#![cfg(test)]

use super::*;
use yadorilink_local_storage::SegmentBlockStore;

fn store(dir: &std::path::Path) -> SegmentBlockStore {
    SegmentBlockStore::new(dir).unwrap()
}

#[test]
fn a_single_file_becomes_one_entry_named_by_its_own_basename() {
    let block_dir = tempfile::tempdir().unwrap();
    let store = store(block_dir.path());
    let source_dir = tempfile::tempdir().unwrap();
    let path = source_dir.path().join("hello.txt");
    std::fs::write(&path, b"hello world").unwrap();

    let (manifest, total) = build_outbound_manifest(&store, &path, "t1").unwrap();
    assert_eq!(total, 11);
    assert_eq!(manifest.files.len(), 1);
    assert_eq!(manifest.files[0].relative_path, "hello.txt");
    assert_eq!(manifest.files[0].size, 11);
    assert_eq!(manifest.files[0].chunk_hashes.len(), 1);
}

#[test]
fn a_directory_becomes_one_entry_per_file_with_forward_slash_relative_paths() {
    let block_dir = tempfile::tempdir().unwrap();
    let store = store(block_dir.path());
    let source_dir = tempfile::tempdir().unwrap();
    std::fs::write(source_dir.path().join("root.txt"), b"r").unwrap();
    std::fs::create_dir(source_dir.path().join("sub")).unwrap();
    std::fs::write(source_dir.path().join("sub").join("nested.txt"), b"n").unwrap();

    let (manifest, total) = build_outbound_manifest(&store, source_dir.path(), "t1").unwrap();
    assert_eq!(total, 2);
    let mut names: Vec<_> = manifest.files.iter().map(|f| f.relative_path.clone()).collect();
    names.sort();
    assert_eq!(names, vec!["root.txt".to_string(), "sub/nested.txt".to_string()]);
}

#[test]
fn an_empty_directory_is_rejected_rather_than_offering_nothing() {
    let block_dir = tempfile::tempdir().unwrap();
    let store = store(block_dir.path());
    let source_dir = tempfile::tempdir().unwrap();

    let error = build_outbound_manifest(&store, source_dir.path(), "t1").unwrap_err();
    assert!(matches!(error, SendError::EmptyManifest(_)));
}

#[test]
fn chunk_byte_size_matches_a_real_multi_chunk_split() {
    let block_dir = tempfile::tempdir().unwrap();
    let store = store(block_dir.path());
    let source_dir = tempfile::tempdir().unwrap();
    let path = source_dir.path().join("big.bin");
    // Three full 128 KiB chunks plus a short final one.
    let content = vec![7u8; DEFAULT_BLOCK_SIZE * 3 + 12345];
    std::fs::write(&path, &content).unwrap();

    let (manifest, _total) = build_outbound_manifest(&store, &path, "t1").unwrap();
    let entry = &manifest.files[0];
    assert_eq!(entry.chunk_hashes.len(), 4);
    for i in 0..3 {
        assert_eq!(chunk_byte_size(entry, i).unwrap(), DEFAULT_BLOCK_SIZE as u32);
    }
    assert_eq!(chunk_byte_size(entry, 3).unwrap(), 12345);
    assert!(chunk_byte_size(entry, 4).is_err());
}
