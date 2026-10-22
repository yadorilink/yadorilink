#![cfg(test)]

use super::*;

fn body_of(frame: &[u8]) -> &[u8] {
    &frame[4..]
}

#[test]
fn a_hello_round_trips() {
    let frame = encode_hello("shared-folder").unwrap();
    assert_eq!(decode_hello(body_of(&frame)).unwrap(), "shared-folder");
}

fn hello_body_at_version(version: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&version.to_be_bytes());
    body.extend_from_slice(&1u16.to_be_bytes());
    body.push(b'g');
    body
}

/// Written relative to [`PROTOCOL_VERSION`] so it holds on both sides of a
/// version bump: an older peer is refused at the handshake, never parsed.
#[test]
fn a_hello_from_an_older_protocol_version_is_refused() {
    let body = hello_body_at_version(PROTOCOL_VERSION - 1);

    assert_eq!(
        decode_hello(&body),
        Err(WireError::UnsupportedVersion { theirs: PROTOCOL_VERSION - 1, ours: PROTOCOL_VERSION })
    );
}

#[test]
fn a_hello_from_a_newer_protocol_version_is_refused() {
    let body = hello_body_at_version(PROTOCOL_VERSION + 1);

    assert_eq!(
        decode_hello(&body),
        Err(WireError::UnsupportedVersion { theirs: PROTOCOL_VERSION + 1, ours: PROTOCOL_VERSION })
    );
}

#[test]
fn a_hello_declaring_more_group_bytes_than_it_carries_is_rejected() {
    let mut body = Vec::new();
    body.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    body.extend_from_slice(&511u16.to_be_bytes());

    assert!(matches!(decode_hello(&body), Err(WireError::Truncated { .. })));
}

#[test]
fn an_oversized_group_id_is_rejected() {
    assert!(matches!(
        encode_hello(&"g".repeat(MAX_GROUP_BYTES + 1)),
        Err(WireError::GroupTooLong { .. })
    ));
}

#[test]
fn a_group_id_that_is_not_utf8_is_rejected() {
    let mut body = Vec::new();
    body.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0xFF, 0xFE]);

    assert_eq!(decode_hello(&body), Err(WireError::MalformedGroupId));
}

/// Rolling-upgrade contract: the hello has no additive extension point. A peer at this version
/// that appends anything (what a newer build adding a hello field would do without bumping the
/// version) is refused, never read as the part this build recognises.
#[test]
fn a_hello_with_extra_bytes_at_the_current_version_is_refused() {
    let mut body = hello_body_at_version(PROTOCOL_VERSION);
    body.extend_from_slice(&[0xAB, 0xCD]);

    assert_eq!(decode_hello(&body), Err(WireError::TrailingBytes(2)));
}
