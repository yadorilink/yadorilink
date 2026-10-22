#![cfg(test)]

use super::*;

/// The two halves must be exact inverses: one runs on what this device
/// emits, the other on what it accepts from a peer.
#[tokio::test]
async fn a_length_prefixed_message_round_trips() {
    let (mut a, mut b) = tokio::io::duplex(4096);
    write_length_prefixed(&mut a, b"header bytes").await.unwrap();
    let read = read_length_prefixed(&mut b, MAX_BLOCK_STREAM_HEADER_BYTES).await.unwrap();
    assert_eq!(read, b"header bytes");
}

/// The bound is enforced on the declared length, not after reading the
/// body: a peer that announces a huge frame must be refused while it
/// has only spent four bytes.
#[tokio::test]
async fn an_oversized_declared_length_is_refused_before_allocating() {
    let (mut a, mut b) = tokio::io::duplex(4096);
    a.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
    let error = read_length_prefixed(&mut b, MAX_BLOCK_STREAM_HEADER_BYTES).await.unwrap_err();
    assert!(matches!(error, TransportError::MessageTooLarge(_, _)));
}
