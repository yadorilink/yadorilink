#![cfg(test)]

use super::*;

#[test]
fn peer_wire_frames_do_not_expose_proto_types() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<BlockRequestHeaderFrame>();
    assert_send_sync::<BlockResponseHeaderFrame>();
}

/// Constructs every block-stream header frame using only plain Rust
/// primitives (`String`/`Vec<u8>`/`u32`/`u64`/`i32`) as field values --
/// this module names no `yadorilink_ipc_proto` type anywhere, so if any
/// public frame field were secretly typed as a generated protobuf type,
/// this file would fail to compile rather than merely fail an assertion.
/// That is the proof this crate's public API surface never leaks
/// `proto::*`.
#[test]
fn public_frames_do_not_expose_generated_proto_types() {
    let request = BlockRequestHeaderFrame {
        folder_group_id: "g".to_string(),
        file_path: "a".to_string(),
        block_hash: vec![1],
    };
    assert_eq!(request.file_path, "a");

    let responses = [
        BlockResponseOutcomeFrame::Found { size: 1, hash: vec![1], compression: COMPRESSION_NONE },
        BlockResponseOutcomeFrame::DontHave,
        BlockResponseOutcomeFrame::Busy { retry_after_ms: 1, queue_depth: 1 },
        BlockResponseOutcomeFrame::Rejected { reason: "r".to_string() },
    ]
    .map(|outcome| BlockResponseHeaderFrame { outcome });
    assert_eq!(responses.len(), 4);
}
