#![cfg(test)]

use super::*;

#[test]
fn garbage_bytes_fail_to_decode() {
    let codec = ProtobufPeerWireCodec;
    // Not a valid varint tag for the first field -- prost must reject
    // this, not panic or silently produce an empty message.
    let garbage = vec![0xFFu8; 4];

    assert!(matches!(codec.decode_block_request_header(&garbage), Err(WireError::Decode(_))));
    assert!(matches!(codec.decode_block_response_header(&garbage), Err(WireError::Decode(_))));
}
