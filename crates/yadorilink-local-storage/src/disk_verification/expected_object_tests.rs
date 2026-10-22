#![cfg(test)]

use super::*;

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().expect("temp dir")
}

/// A correctly restored symlink, verified the old way: `File::open`
/// follows it, reads the TARGET's bytes, and compares them against the
/// link's own (empty) block list -- so a link to any non-empty file
/// reads as content that differs.
#[cfg(unix)]
#[test]
fn a_correct_symlink_verifies_as_itself_not_as_its_target() {
    let dir = tmp();
    let target = dir.path().join("target.txt");
    std::fs::write(&target, b"the target's own bytes").unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let target_bytes = yadorilink_fs_platform::fs_identity::target_to_bytes(target.as_path());
    assert_eq!(
        disk_matches_expected_object(
            &link,
            ExpectedObject::Symlink { target: Some(&target_bytes) }
        )
        .unwrap(),
        DiskContentComparison::Matched
    );

    // What the old check answered about the same, correct link.
    assert_eq!(
        disk_content_comparison(&link, &[]).unwrap(),
        DiskContentComparison::PresentButDifferent,
        "the regular-file comparison follows the link and judges the target's bytes"
    );
}

/// A dangling symlink is still a symlink, and still exactly right if
/// its target text matches. The old check reported it as `Absent`,
/// because opening it fails with `NotFound`.
#[cfg(unix)]
#[test]
fn a_dangling_symlink_with_the_right_target_still_verifies() {
    let dir = tmp();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink("nowhere/at/all", &link).unwrap();

    assert_eq!(
        disk_matches_expected_object(
            &link,
            ExpectedObject::Symlink { target: Some(b"nowhere/at/all") }
        )
        .unwrap(),
        DiskContentComparison::Matched
    );
    assert_eq!(
        disk_content_comparison(&link, &[]).unwrap(),
        DiskContentComparison::Absent,
        "the regular-file comparison cannot open it and reports nothing is there"
    );
}

#[cfg(unix)]
#[test]
fn a_symlink_pointing_somewhere_else_does_not_verify() {
    let dir = tmp();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink("somewhere/else", &link).unwrap();

    assert_eq!(
        disk_matches_expected_object(
            &link,
            ExpectedObject::Symlink { target: Some(b"nowhere/at/all") }
        )
        .unwrap(),
        DiskContentComparison::PresentButDifferent
    );
}

/// A version that records no target says nothing about what the link
/// should point at, so nothing on disk can confirm it.
#[cfg(unix)]
#[test]
fn a_symlink_version_with_no_recorded_target_can_never_verify() {
    let dir = tmp();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink("anywhere", &link).unwrap();

    assert_eq!(
        disk_matches_expected_object(&link, ExpectedObject::Symlink { target: None }).unwrap(),
        DiskContentComparison::PresentButDifferent
    );
}

/// A directory verifies as a directory. The old check did not merely
/// answer wrongly here -- reading a directory is an I/O error, which
/// propagated out of the whole recovery pass.
#[test]
fn a_directory_verifies_by_kind() {
    let dir = tmp();
    let nested = dir.path().join("nested");
    std::fs::create_dir(&nested).unwrap();

    assert_eq!(
        disk_matches_expected_object(&nested, ExpectedObject::Directory).unwrap(),
        DiskContentComparison::Matched
    );
    assert_eq!(
        disk_matches_expected_object(&dir.path().join("gone"), ExpectedObject::Directory).unwrap(),
        DiskContentComparison::Absent
    );
}

/// Kind mismatches fail closed in every direction, so nothing can
/// verify by being the right bytes in the wrong shape.
#[test]
fn a_regular_file_where_a_directory_is_expected_does_not_verify() {
    let dir = tmp();
    let file = dir.path().join("f");
    std::fs::write(&file, b"").unwrap();

    assert_eq!(
        disk_matches_expected_object(&file, ExpectedObject::Directory).unwrap(),
        DiskContentComparison::PresentButDifferent
    );
}

#[cfg(unix)]
#[test]
fn a_symlink_where_a_regular_file_is_expected_does_not_verify() {
    let dir = tmp();
    let target = dir.path().join("target.txt");
    std::fs::write(&target, b"").unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    assert_eq!(
        disk_matches_expected_object(&link, ExpectedObject::File { blocks: &[] }).unwrap(),
        DiskContentComparison::PresentButDifferent,
        "an empty target would otherwise make the followed link verify as the file"
    );
}

/// The regular-file case still does exactly what it always did.
#[test]
fn a_regular_file_still_verifies_by_its_blocks() {
    use sha2::Digest;
    let dir = tmp();
    let file = dir.path().join("f");
    std::fs::write(&file, b"contents").unwrap();
    let blocks = vec![BlockInfo {
        hash: sha2::Sha256::digest(b"contents").to_vec(),
        offset: 0,
        size: b"contents".len() as u32,
    }];

    assert_eq!(
        disk_matches_expected_object(&file, ExpectedObject::File { blocks: &blocks }).unwrap(),
        DiskContentComparison::Matched
    );
    std::fs::write(&file, b"contents!").unwrap();
    assert_eq!(
        disk_matches_expected_object(&file, ExpectedObject::File { blocks: &blocks }).unwrap(),
        DiskContentComparison::PresentButDifferent
    );
}
