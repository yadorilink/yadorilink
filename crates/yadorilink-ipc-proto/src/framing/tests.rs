#![cfg(test)]

use super::*;
use crate::daemonctl::DaemonControlRequest;

#[tokio::test]
async fn oversized_frame_is_rejected_before_body_allocation() {
    let (mut client, mut server) = tokio::io::duplex(64);
    tokio::spawn(async move {
        client.write_all(&FRAME_MAGIC).await.unwrap();
        client.write_all(&(MAX_FRAME_LEN + 1).to_be_bytes()).await.unwrap();
    });

    let err = read_message::<DaemonControlRequest>(&mut server).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

/// The write side enforces the same limit the read side does, before
/// putting anything on the wire -- so an oversized message fails where
/// it can still be diagnosed and replaced, not at a reader that has
/// lost all context about what the frame was.
#[tokio::test]
async fn an_oversized_frame_is_refused_by_the_writer_with_the_stream_untouched() {
    use crate::daemonctl::{daemon_control_response::Payload, DaemonControlResponse};
    let (mut client, mut server) = tokio::io::duplex(64);
    let oversized = DaemonControlResponse {
        daemon_protocol_version: 0,
        payload: Some(Payload::Error("x".repeat(MAX_FRAME_LEN as usize + 1))),
    };

    let err = write_message(&mut client, &oversized).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("oversized frame"), "{err}");

    // Nothing reached the stream, so the connection is still usable for
    // a smaller reply rather than being left mid-frame.
    let small = DaemonControlResponse {
        daemon_protocol_version: 7,
        payload: Some(Payload::Error("too large".to_string())),
    };
    write_message(&mut client, &small).await.unwrap();
    let read = read_message::<DaemonControlResponse>(&mut server).await.unwrap().unwrap();
    assert_eq!(read.daemon_protocol_version, 7);
}

#[tokio::test]
async fn pre_marker_frame_is_rejected_instead_of_decoded_compatibly() {
    let (mut client, mut server) = tokio::io::duplex(64);
    tokio::spawn(async move {
        // Historical framing started directly with the four-byte body
        // length. Pad enough bytes for the current reader's magic read;
        // the mismatch must fail before any protobuf decode is attempted.
        client.write_all(&0u32.to_be_bytes()).await.unwrap();
        client.write_all(&[0u8; 4]).await.unwrap();
    });

    let err = read_message::<DaemonControlRequest>(&mut server).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("unsupported YadoriLink framing generation"));
}
