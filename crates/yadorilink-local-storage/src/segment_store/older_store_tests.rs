#![cfg(test)]
//! A block store written by the previous build is refused as it stands: nothing is read from it,
//! repaired, quarantined, deleted or stamped, so the build that wrote it can still open it.

use super::*;

/// The files of a directory, with their contents, sorted: what "left exactly as it was" compares.
fn snapshot(root: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, base, out);
            } else {
                let name = path.strip_prefix(base).unwrap().to_string_lossy().into_owned();
                out.push((name, std::fs::read(&path).unwrap_or_default()));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

/// A segment file of the previous layout: its header declares layout v1, followed by some bytes
/// that stand for records.
fn write_previous_layout_segment(root: &Path, segment_id: u64) {
    let mut bytes = format::encode_segment_header(segment_id).to_vec();
    bytes[4..6].copy_from_slice(&(format::SEGMENT_FORMAT_VERSION - 1).to_le_bytes());
    bytes.extend_from_slice(&[0xAB; 300]);
    std::fs::create_dir_all(root.join(segment::SEGMENTS_DIR)).unwrap();
    std::fs::write(segment::segment_path(root, segment_id), bytes).unwrap();
}

fn refused(root: &Path) -> String {
    match SegmentBlockStore::new(root) {
        Err(error) => error.to_string(),
        Ok(_) => panic!("a store of the previous layout must not open"),
    }
}

fn assert_the_advice(message: &str) {
    for needed in [
        "pre-release builds do not migrate",
        "re-import the folder",
        "yadorilink preserved list",
        "yadorilink preserved restore <item-id>",
        "yadorilink preserved discard <item-id> --yes",
    ] {
        assert!(message.contains(needed), "the refusal lacks {needed:?}: {message}");
    }
}

/// The index was lost or replaced by an empty one while the previous build's segments are there:
/// recovery must not take them for orphans and delete them.
#[test]
fn segments_of_the_previous_layout_are_not_orphans_to_delete_under_a_new_index() {
    let dir = tempfile::tempdir().unwrap();
    write_previous_layout_segment(dir.path(), 1);
    write_previous_layout_segment(dir.path(), 2);
    // An existing but empty index, as a replacement for a lost one would be.
    drop(BlockIndex::open(&dir.path().join(INDEX_FILE)).unwrap());
    let before = snapshot(dir.path());

    let message = refused(dir.path());

    assert_the_advice(&message);
    assert!(message.contains("segment layout v1"), "{message}");
    assert_eq!(snapshot(dir.path()), before, "nothing was deleted, truncated or stamped");
    assert!(!dir.path().join(FORMAT_MARKER_FILE).exists(), "no marker was written");
}

/// A previous-layout store whose marker file is missing: it is refused without the marker being
/// written, so the previous build can still open it.
#[test]
fn a_previous_layout_store_without_its_marker_is_refused_and_no_marker_is_written() {
    let dir = tempfile::tempdir().unwrap();
    {
        // A store as the previous build left it: an index stamped with the previous version, its
        // segment of the previous layout, and no marker.
        drop(BlockIndex::open(&dir.path().join(INDEX_FILE)).unwrap());
        let conn = rusqlite::Connection::open(dir.path().join(INDEX_FILE)).unwrap();
        conn.execute(
            "UPDATE store_meta SET value = ?1 WHERE key = 'format_version'",
            [(index::STORE_FORMAT_VERSION - 1).to_string()],
        )
        .unwrap();
    }
    write_previous_layout_segment(dir.path(), 1);
    let _ = std::fs::remove_file(dir.path().join(FORMAT_MARKER_FILE));
    let before = snapshot(dir.path());

    let message = refused(dir.path());

    assert_the_advice(&message);
    assert_eq!(snapshot(dir.path()), before, "the store is left exactly as it was");
    assert!(!dir.path().join(FORMAT_MARKER_FILE).exists(), "no marker was written");
}

/// The previous build's marker names the previous format version.
#[test]
fn a_marker_of_the_previous_format_version_is_refused_with_the_advice() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(segment::SEGMENTS_DIR)).unwrap();
    std::fs::write(
        dir.path().join(FORMAT_MARKER_FILE),
        format!("yadorilink-block-store\nformat_version={}\n", index::STORE_FORMAT_VERSION - 1),
    )
    .unwrap();
    let before = snapshot(dir.path());

    let message = refused(dir.path());

    assert_the_advice(&message);
    assert_eq!(snapshot(dir.path()), before);
}

/// A segment file that is not a segment at all (foreign bytes, or too short to have a header) is
/// not a reason to refuse: only a segment declaring another layout is.
#[test]
fn a_file_that_is_not_a_segment_is_not_taken_for_one_of_another_layout() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(segment::SEGMENTS_DIR)).unwrap();
    std::fs::write(segment::segment_path(dir.path(), 1), [0u8; 4]).unwrap();
    std::fs::write(segment::segment_path(dir.path(), 2), vec![0x5A; 200]).unwrap();

    refuse_a_store_of_another_layout(dir.path()).expect("neither file declares another layout");
}
