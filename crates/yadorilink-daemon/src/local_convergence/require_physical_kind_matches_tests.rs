#![cfg(test)]

use super::types::require_physical_kind_matches;
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::file::RecordKind;

#[test]
fn accepts_a_regular_file_claimed_as_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f.txt");
    std::fs::write(&path, b"content").unwrap();
    require_physical_kind_matches("f.txt", &path, RecordKind::File).unwrap();
}

#[test]
fn accepts_a_real_directory_claimed_as_directory() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("d");
    std::fs::create_dir(&path).unwrap();
    require_physical_kind_matches("d", &path, RecordKind::Directory).unwrap();
}

#[cfg(unix)]
#[test]
fn accepts_a_dangling_symlink_claimed_as_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("link");
    std::os::unix::fs::symlink("nowhere", &path).unwrap();
    require_physical_kind_matches("link", &path, RecordKind::Symlink).unwrap();
}

/// Regression: a hand-crafted, validly-signed `Directory` version must
/// never settle as
/// `ExactObject` when `materialize()` (which has no directory-
/// specific physical branch) actually created a regular file (the
/// ordinary reconstruct path's `File::create`). Confirmed genuinely
/// RED by temporarily short-circuiting this function to always
/// return `Ok(())`: this exact mismatch went undetected.
#[test]
fn rejects_a_regular_file_claimed_as_directory() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f.txt");
    std::fs::write(&path, b"content").unwrap();
    let err = require_physical_kind_matches("f.txt", &path, RecordKind::Directory).unwrap_err();
    assert!(matches!(err, PeerSessionError::PhysicalKindMismatch(_)), "got {err:?}");
}

#[test]
fn rejects_a_missing_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nothing-here");
    let err = require_physical_kind_matches("nothing-here", &path, RecordKind::File).unwrap_err();
    assert!(matches!(err, PeerSessionError::PhysicalKindMismatch(_)), "got {err:?}");
}
