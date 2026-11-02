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

#[test]
fn listing_what_an_offer_carries_names_and_sizes_without_storing_anything() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("d")).unwrap();
    std::fs::write(dir.path().join("a.txt"), b"12345").unwrap();
    std::fs::write(dir.path().join("d/b.txt"), b"xy").unwrap();
    let mut listed = list_offered_files(dir.path()).unwrap();
    listed.sort();
    assert_eq!(listed, vec![("a.txt".to_string(), 5), ("d/b.txt".to_string(), 2)]);
    // One file lists as itself.
    assert_eq!(
        list_offered_files(&dir.path().join("a.txt")).unwrap(),
        vec![("a.txt".to_string(), 5)]
    );
    assert!(list_offered_files(&dir.path().join("missing")).is_err());
}

fn entry(name: &str) -> SendFileEntry {
    SendFileEntry {
        relative_path: name.to_string(),
        size: 0,
        chunk_size: 1,
        chunk_hashes: Vec::new(),
    }
}

fn manifest_of(names: &[&str]) -> SendManifest {
    SendManifest {
        transfer_id: "t".into(),
        files: names.iter().map(|n| entry(n)).collect(),
        total_size: 0,
        offered_at_unix_nanos: 0,
        ..Default::default()
    }
}

#[test]
fn several_sources_are_named_by_basename_and_folders_keep_their_name() {
    let block_dir = tempfile::tempdir().unwrap();
    let store = store(block_dir.path());
    let src = tempfile::tempdir().unwrap();
    let file = src.path().join("a.txt");
    std::fs::write(&file, b"aaa").unwrap();
    let folder = src.path().join("photos");
    std::fs::create_dir_all(folder.join("sub")).unwrap();
    std::fs::write(folder.join("x.jpg"), b"x").unwrap();
    std::fs::write(folder.join("sub").join("y.jpg"), b"yy").unwrap();

    let sources = vec![file, folder];
    let (manifest, total) = build_outbound_manifest_multi(&store, &sources, "t").unwrap();
    assert_eq!(total, 6);
    let mut names: Vec<_> = manifest.files.iter().map(|f| f.relative_path.clone()).collect();
    names.sort();
    assert_eq!(names, ["a.txt", "photos/sub/y.jpg", "photos/x.jpg"]);
    let listed = list_offered_files_multi(&sources).unwrap();
    assert_eq!(listed.iter().map(|(_, s)| s).sum::<u64>(), 6);
    assert_eq!(listed.len(), 3);
    validate_offered_manifest(&manifest).unwrap();
}

#[test]
fn sources_with_the_same_basename_get_distinct_names() {
    let block_dir = tempfile::tempdir().unwrap();
    let store = store(block_dir.path());
    let src = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(src.path().join("one")).unwrap();
    std::fs::create_dir_all(src.path().join("two")).unwrap();
    let a = src.path().join("one").join("report.txt");
    let b = src.path().join("two").join("Report.txt");
    std::fs::write(&a, b"1").unwrap();
    std::fs::write(&b, b"2").unwrap();

    let (manifest, _) = build_outbound_manifest_multi(&store, &[a, b], "t").unwrap();
    let names: Vec<_> = manifest.files.iter().map(|f| f.relative_path.as_str()).collect();
    assert_eq!(names, ["report.txt", "Report (2).txt"]);
}

#[test]
fn sources_round_trip_through_their_stored_form() {
    let one = vec![PathBuf::from("/a/b")];
    assert_eq!(encode_sources(&one), "/a/b");
    assert_eq!(decode_sources("/a/b"), one);
    let many = vec![PathBuf::from("/a/b"), PathBuf::from("/c [d]/e")];
    assert_eq!(decode_sources(&encode_sources(&many)), many);
}

#[test]
fn an_offered_name_that_escapes_or_is_not_relative_is_refused() {
    for bad in [
        "../x",
        "a/../../x",
        "/etc/passwd",
        "C:/x",
        "C:x",
        "\\\\host\\share",
        "a\\b",
        "",
        "a//b",
        "./a",
        "a/.",
    ] {
        let error = validate_offered_manifest(&manifest_of(&[bad])).unwrap_err();
        assert!(error.contains("not a plain relative path"), "{bad:?}: {error}");
    }
}

#[test]
fn duplicate_offered_names_are_refused_even_when_only_the_case_differs() {
    assert!(validate_offered_manifest(&manifest_of(&["a.txt", "a.txt"])).is_err());
    assert!(validate_offered_manifest(&manifest_of(&["a.txt", "A.TXT"])).is_err());
    assert!(validate_offered_manifest(&manifest_of(&["d", "d/x"])).is_err());
    validate_offered_manifest(&manifest_of(&["a.txt", "a (2).txt", "d/x"])).unwrap();
}
