#![cfg(test)]

use super::*;
use std::path::Path;
use yadorilink_fs_platform::fs_identity::FileIdentity;

fn observed(path: &Path) -> DiskObservation {
    DiskObservation { identity: FileIdentity::observe_path(path).expect("observe") }
}

#[test]
fn an_observation_still_describing_disk_yields_the_identity_it_closed_over() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f.bin");
    std::fs::write(&path, b"scanned bytes").unwrap();
    let observation = observed(&path);

    assert_eq!(
        observation.identity_if_still_current(&path),
        Some(observation.identity),
        "an unchanged path must yield the identity the scan closed over -- the same value \
         the version beside it was derived from, not a second look that merely agrees"
    );
}

/// The race itself. The version is already fixed by the time this runs,
/// so the only correct answer for a path whose bytes have moved on is
/// no evidence at all.
#[test]
fn an_observation_whose_bytes_changed_since_the_scan_yields_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f.bin");
    std::fs::write(&path, b"scanned bytes").unwrap();
    let observation = observed(&path);

    // An external writer, between the scan's read and the commit.
    std::fs::write(&path, b"different bytes entirely").unwrap();

    assert_eq!(
        observation.identity_if_still_current(&path),
        None,
        "these bytes are not the ones the scan derived its version from; pairing them \
         would publish a proof for a version that is no longer on disk"
    );
    // And the bare re-observation a caller might reach for instead
    // succeeds happily, which is exactly why the gate has to exist.
    assert!(
        FileIdentity::observe_path(&path).is_ok(),
        "the unguarded look this gate replaces cannot tell the difference"
    );
}

/// An in-place overwrite that preserves length and restores mtime is
/// the shape an object-identity comparison cannot see -- same inode,
/// same size, same mtime. The metadata token moves anyway, because
/// ctime does and no userspace API can put it back.
#[test]
fn an_in_place_same_length_overwrite_is_still_caught() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f.bin");
    std::fs::write(&path, b"aaaaaaaa").unwrap();
    let observation = observed(&path);
    let before = std::fs::metadata(&path).unwrap().modified().unwrap();

    // Same length, written in place, mtime restored afterwards --
    // everything a writer can put back, put back.
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new().write(true).truncate(false).open(&path).unwrap();
        file.write_all(b"bbbbbbbb").unwrap();
        file.sync_all().unwrap();
        file.set_modified(before).unwrap();
    }

    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        8,
        "sanity: the overwrite must have preserved the length"
    );
    assert_eq!(
        observation.identity_if_still_current(&path),
        None,
        "the metadata token moves on every write even when length and mtime do not"
    );
}
