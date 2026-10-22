#![cfg(test)]

//! `observably_absent_by_exact_name` compares names out of directory
//! listings, so none of these depend on the host volume folding case or
//! normalization: they run identically on every CI host.

use std::ffi::OsString;
use std::io;
use std::path::Path;

use super::{exact_name_absent_with, observably_absent_by_exact_name};

#[test]
fn an_entry_under_exactly_the_name_is_not_absent() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    std::fs::write(root.path().join("docs/report.txt"), b"x").unwrap();
    assert!(!observably_absent_by_exact_name(root.path(), "docs/report.txt", true));
}

#[test]
fn a_leaf_differing_only_in_case_is_absent() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("Photo.jpg"), b"x").unwrap();
    assert!(observably_absent_by_exact_name(root.path(), "photo.jpg", true));
}

/// The collision is in the parent, not the leaf: listing only the leaf's
/// parent would resolve `Docs` to the physical `docs` on a folding volume
/// and find `report.txt` there.
#[test]
fn an_ancestor_differing_only_in_case_is_absent() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("docs")).unwrap();
    std::fs::write(root.path().join("docs/report.txt"), b"x").unwrap();
    assert!(observably_absent_by_exact_name(root.path(), "Docs/report.txt", true));
}

/// A canonically-equivalent spelling may be this name's own stored form
/// (HFS+ decomposes every name it stores), so it is not an absence.
#[test]
fn a_canonically_equivalent_entry_is_not_absent() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("Cafe\u{301}.jpg"), b"x").unwrap();
    assert!(!observably_absent_by_exact_name(root.path(), "Caf\u{e9}.jpg", true));
}

#[test]
fn a_canonically_equivalent_entry_differing_in_case_is_absent() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("cafe\u{301}.jpg"), b"x").unwrap();
    assert!(observably_absent_by_exact_name(root.path(), "Caf\u{e9}.jpg", true));
}

#[test]
fn a_component_that_is_not_a_directory_is_not_absent() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("docs"), b"x").unwrap();
    assert!(!observably_absent_by_exact_name(root.path(), "docs/report.txt", true));
}

/// APFS-like (normalization-sensitive): a sibling differing only by NFC vs
/// NFD is a distinct file, so a redelivered tombstone for the other
/// spelling is absent and must not retry forever.
#[test]
fn a_normalization_sibling_is_absent_on_a_normalization_sensitive_volume() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("Cafe\u{301}.jpg"), b"x").unwrap();
    assert!(observably_absent_by_exact_name(root.path(), "Caf\u{e9}.jpg", false));
    assert!(!observably_absent_by_exact_name(root.path(), "Cafe\u{301}.jpg", false));
}

/// HFS+-like (normalization-insensitive): the same sibling may be this
/// name's own stored form, so it stays present.
#[test]
fn a_normalization_sibling_is_present_on_a_normalization_insensitive_volume() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("Cafe\u{301}.jpg"), b"x").unwrap();
    assert!(!observably_absent_by_exact_name(root.path(), "Caf\u{e9}.jpg", true));
}

#[test]
fn a_missing_root_is_not_absent() {
    let root = tempfile::tempdir().unwrap();
    assert!(!observably_absent_by_exact_name(&root.path().join("gone"), "report.txt", true));
}

#[test]
fn an_unreadable_directory_is_not_absent() {
    let absent = exact_name_absent_with(Path::new("/root"), "report.txt", true, |_| {
        Err::<std::vec::IntoIter<io::Result<OsString>>, _>(io::Error::from(
            io::ErrorKind::PermissionDenied,
        ))
    });
    assert!(!absent);
}

#[test]
fn an_unreadable_entry_is_not_absent() {
    let absent = exact_name_absent_with(Path::new("/root"), "report.txt", true, |_| {
        Ok(vec![Ok(OsString::from("other.txt")), Err(io::Error::from(io::ErrorKind::Other))]
            .into_iter())
    });
    assert!(!absent);
}

/// An unreadable deeper directory is not excused by the ancestors having
/// matched.
#[test]
fn an_unreadable_directory_below_a_matched_ancestor_is_not_absent() {
    let absent = exact_name_absent_with(Path::new("/root"), "docs/report.txt", true, |dir| {
        if dir == Path::new("/root") {
            Ok(vec![Ok(OsString::from("docs"))].into_iter())
        } else {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        }
    });
    assert!(!absent);
}
