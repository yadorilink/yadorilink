#![cfg(test)]

use super::*;

fn meta(record_kind: RecordKind, symlink_target: Option<Vec<u8>>) -> FileMeta {
    FileMeta {
        mtime_unix_nanos: 0,
        unix_mode: None,
        symlink_target,
        record_kind,
        xattrs: Vec::new(),
    }
}

#[test]
fn a_symlink_with_a_recorded_target_is_valid() {
    FileVersion::new(vec![], 0, meta(RecordKind::Symlink, Some(b"target".to_vec())))
        .verify_hash()
        .unwrap();
}

#[test]
fn a_file_and_a_directory_with_no_target_are_valid() {
    FileVersion::new(vec![], 0, meta(RecordKind::File, None)).verify_hash().unwrap();
    FileVersion::new(vec![], 0, meta(RecordKind::Directory, None)).verify_hash().unwrap();
}

/// Regression: a hand-crafted, validly-signed `Symlink` version with
/// no recorded target must be rejected at the wire-decode/admission
/// boundary, not only handled defensively much further downstream by
/// the local materialize path (a policy skip, not a rejection). Confirmed genuinely RED by
/// temporarily removing this specific check from `validate_structure`
/// (leaving the symmetric `File`/`Directory` checks in place): this
/// version verified successfully instead of being rejected.
#[test]
fn a_symlink_with_no_recorded_target_is_rejected() {
    let err =
        FileVersion::new(vec![], 0, meta(RecordKind::Symlink, None)).verify_hash().unwrap_err();
    assert!(matches!(err, ChangeError::Malformed(_)), "got {err:?}");
}

/// The symmetric case the review specifically asked not to skip: a
/// `File`/`Directory` version claiming a symlink target it can never
/// use is exactly as malformed as a targetless symlink, even though
/// no real capture path produces this today.
#[test]
fn a_file_or_directory_with_a_symlink_target_is_rejected() {
    let err = FileVersion::new(vec![], 0, meta(RecordKind::File, Some(b"target".to_vec())))
        .verify_hash()
        .unwrap_err();
    assert!(matches!(err, ChangeError::Malformed(_)), "got {err:?}");

    let err = FileVersion::new(vec![], 0, meta(RecordKind::Directory, Some(b"target".to_vec())))
        .verify_hash()
        .unwrap_err();
    assert!(matches!(err, ChangeError::Malformed(_)), "got {err:?}");
}

/// Regression: `FileMeta::xattrs`'s own doc comment says a symlink or
/// directory is "not scanned" for xattrs, and decode enforces it -- a
/// hand-crafted Symlink/Directory version carrying nonempty `xattrs`
/// would otherwise bake them into `version_hash` while no completion
/// proof for that path ever verifies, applies, or even looks at them
/// for those kinds.
/// Confirmed genuinely RED by temporarily removing this specific
/// check from `validate_structure` (leaving every other check in
/// place): both versions below verified successfully instead of
/// being rejected.
#[test]
fn a_symlink_or_directory_with_nonempty_xattrs_is_rejected() {
    let xattrs = vec![("user.a".to_string(), b"1".to_vec())];

    let mut symlink_meta = meta(RecordKind::Symlink, Some(b"target".to_vec()));
    symlink_meta.xattrs = xattrs.clone();
    let err = FileVersion::new(vec![], 0, symlink_meta).verify_hash().unwrap_err();
    assert!(matches!(err, ChangeError::Malformed(_)), "got {err:?}");

    let mut directory_meta = meta(RecordKind::Directory, None);
    directory_meta.xattrs = xattrs;
    let err = FileVersion::new(vec![], 0, directory_meta).verify_hash().unwrap_err();
    assert!(matches!(err, ChangeError::Malformed(_)), "got {err:?}");
}
