#![cfg(test)]

use super::*;

/// One block request, one bidirectional stream: the header's round trip
/// is what pins its encoding.
#[test]
fn a_block_request_header_round_trips() {
    let frame = BlockRequestHeaderFrame {
        folder_group_id: "g1".to_string(),
        file_path: "a.bin".to_string(),
        block_hash: vec![7u8; 32],
    };
    let bytes = ProtobufPeerWireCodec.encode_block_request_header(frame.clone()).unwrap();
    assert_eq!(ProtobufPeerWireCodec.decode_block_request_header(&bytes).unwrap(), frame);
}

#[test]
fn every_block_response_outcome_round_trips() {
    let outcomes = [
        BlockResponseOutcomeFrame::Found {
            size: 3,
            hash: vec![1u8; 32],
            compression: proto::Compression::Zstd as i32,
        },
        BlockResponseOutcomeFrame::DontHave,
        BlockResponseOutcomeFrame::Busy { retry_after_ms: 150, queue_depth: 4 },
        BlockResponseOutcomeFrame::Rejected { reason: "not authorized".to_string() },
    ];
    for outcome in outcomes {
        let frame = BlockResponseHeaderFrame { outcome };
        let bytes = ProtobufPeerWireCodec.encode_block_response_header(frame.clone()).unwrap();
        assert_eq!(ProtobufPeerWireCodec.decode_block_response_header(&bytes).unwrap(), frame);
    }
}

/// Under exact-generation ALPN a same-generation peer's
/// `BlockResponseHeader` always sets exactly one `outcome`; an absent
/// oneof is malformed for this generation and must be rejected at
/// decode time, never treated as `DontHave`.
#[test]
fn an_absent_block_response_outcome_is_a_decode_error() {
    let bytes = proto::BlockResponseHeader { outcome: None }.encode_to_vec();
    assert!(matches!(
        ProtobufPeerWireCodec.decode_block_response_header(&bytes),
        Err(WireError::Decode(_))
    ));
}
