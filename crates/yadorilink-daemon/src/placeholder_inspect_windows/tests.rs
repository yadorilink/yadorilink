#![cfg(test)]

use super::decode_generation_identity;

#[test]
fn decodes_a_well_formed_v1_token() {
    let mut bytes = vec![1u8];
    bytes.extend_from_slice(&42u64.to_le_bytes());
    assert_eq!(decode_generation_identity(&bytes), Some(42));
}

#[test]
fn rejects_wrong_length() {
    assert_eq!(decode_generation_identity(&[1u8; 8]), None);
    assert_eq!(decode_generation_identity(&[1u8; 10]), None);
    assert_eq!(decode_generation_identity(&[]), None);
}

#[test]
fn rejects_wrong_version_tag() {
    let mut bytes = vec![0u8];
    bytes.extend_from_slice(&42u64.to_le_bytes());
    assert_eq!(decode_generation_identity(&bytes), None);
}

#[test]
fn rejects_a_legacy_filename_derived_blob_even_at_the_right_length() {
    // A legacy identity was the placeholder's own filename as raw
    // bytes -- this happens to be 9 bytes for some filenames, so
    // length alone is not enough to accept it; the version tag must
    // also match.
    let legacy = b"file.ext\0"; // 9 bytes, first byte 'f' (0x66) != 1
    assert_eq!(decode_generation_identity(legacy), None);
}
