#![cfg(test)]

use super::{block_data_matches, BlockInfo};
use sha2::{Digest, Sha256};

fn block_for(data: &[u8]) -> BlockInfo {
    BlockInfo { hash: Sha256::digest(data).to_vec(), offset: 0, size: data.len() as u32 }
}

#[test]
fn matching_data_is_accepted() {
    let data = b"real block content";
    assert!(block_data_matches(&block_for(data), data));
}

#[test]
fn wrong_content_with_the_same_length_is_rejected() {
    let real = b"aaaaaaaaaaaaaaaaaaaa";
    let junk = b"bbbbbbbbbbbbbbbbbbbb";
    assert_eq!(real.len(), junk.len());
    assert!(!block_data_matches(&block_for(real), junk));
}

#[test]
fn truncated_data_is_rejected() {
    let full = b"real block content";
    let expected = block_for(full);
    assert!(!block_data_matches(&expected, &full[..full.len() - 1]));
}

#[test]
fn empty_response_for_a_nonempty_block_is_rejected() {
    let expected = block_for(b"real block content");
    assert!(!block_data_matches(&expected, &[]));
}
