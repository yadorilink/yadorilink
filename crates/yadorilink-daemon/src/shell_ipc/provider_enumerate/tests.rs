#![cfg(test)]

use super::*;

/// A cursor is valid only for the root and the folder that issued it: another root, another folder
/// or another kind of cursor is refused, and nothing is misread.
#[test]
fn a_page_token_is_bound_to_its_root_its_scope_and_its_kind() {
    let token = encode_token(CHILDREN_TAG, 7, b"root-a", b"folder", b"last/path");
    assert_eq!(
        decode_token(CHILDREN_TAG, &token, b"root-a", b"folder"),
        Some((7, b"last/path".to_vec()))
    );
    assert!(decode_token(CHILDREN_TAG, &token, b"root-b", b"folder").is_none(), "another root");
    assert!(decode_token(CHILDREN_TAG, &token, b"root-a", b"other").is_none(), "another folder");
    assert!(decode_token(WORKING_SET_TAG, &token, b"root-a", b"folder").is_none(), "another kind");
    assert!(decode_token(CHILDREN_TAG, &token[..5], b"root-a", b"folder").is_none(), "truncated");
    assert!(decode_token(CHILDREN_TAG, b"", b"root-a", b"folder").is_none());
}
