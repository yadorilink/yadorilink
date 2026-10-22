#![cfg(test)]

use super::*;

/// Hand-builds a canonical `FileMeta` encoding directly (rather than
/// going through `FileMeta`'s own encoder, which cannot be asked to
/// produce an invalid xattr name in the first place) -- `record_kind`
/// (`RecordKind::File` = 0), no unix mode, a fixed mtime, no symlink
/// target, then the xattr list exactly as `FileMeta::decode` expects
/// it: a `u32` count followed by `(name, value)` length-prefixed
/// pairs.
fn encode_file_meta_bytes_with_xattrs(xattrs: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0u8);
    buf.push(0u8);
    put_i64(&mut buf, 0);
    buf.push(0u8);
    put_u32(&mut buf, xattrs.len() as u32);
    for (name, value) in xattrs {
        put_len_bytes(&mut buf, name.as_bytes());
        put_len_bytes(&mut buf, value);
    }
    buf
}

#[test]
fn decode_accepts_an_allow_listed_xattr_name() {
    let bytes = encode_file_meta_bytes_with_xattrs(&[("user.a", b"1")]);
    let meta = FileMeta::decode(&mut Reader::new(&bytes)).unwrap();
    assert_eq!(meta.xattrs, vec![("user.a".to_string(), b"1".to_vec())]);
}

/// Regression: this device's own capture paths and every platform's
/// apply-side filter in `yadorilink-local-storage::chunker` restrict
/// xattr replication to the `user.` namespace, and decode must enforce
/// the same allow-list so a hand-crafted `FileVersion` from a fully
/// authorized-but-untrusted peer cannot carry a security-relevant name
/// (`security.*`/`system.*`/`trusted.*` on Linux) straight through
/// decode and on into `apply_xattrs`. Confirmed genuinely RED by
/// temporarily removing the allow-list check from `decode`: this call
/// succeeded instead of being rejected.
#[test]
fn decode_rejects_a_non_allow_listed_xattr_name() {
    let bytes = encode_file_meta_bytes_with_xattrs(&[("security.selinux", b"x")]);
    let err = FileMeta::decode(&mut Reader::new(&bytes)).unwrap_err();
    assert!(matches!(err, ChangeError::Encoding(_)), "got {err:?}");
}

/// A mixed list where only the second entry is outside the allow-list
/// must still be rejected -- the check must not be skippable by
/// hiding a bad name behind a good one earlier in sort order.
#[test]
fn decode_rejects_a_non_allow_listed_xattr_name_mixed_with_an_allowed_one() {
    let bytes = encode_file_meta_bytes_with_xattrs(&[("user.a", b"1"), ("z.trusted", b"x")]);
    let err = FileMeta::decode(&mut Reader::new(&bytes)).unwrap_err();
    assert!(matches!(err, ChangeError::Encoding(_)), "got {err:?}");
}
