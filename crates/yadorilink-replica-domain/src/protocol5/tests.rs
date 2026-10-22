use super::*;
use crate::authorization_checkpoint::MerkleProof;
use crate::ids::VersionHash;
use crate::native_protocol::NATIVE_PROTOCOL_GENERATION;
use crate::signed_delta::{DeltaOp, DeltaPut};

fn author(device: &str, incarnation: u8) -> AuthorId {
    AuthorId { device: DeviceId(device.into()), incarnation: IncarnationId([incarnation; 16]) }
}

fn sample_delta_bytes() -> Vec<u8> {
    let mut delta = NativeDelta {
        recursive_part: None,
        group_id: FolderGroupId("g1".into()),
        author: author("device-a", 1),
        seq: AuthorSeq(2),
        prev: None,
        ops: vec![DeltaOp {
            path: crate::ids::SyncPath("x".into()),
            removes: vec![],
            put: Some(DeltaPut { version: VersionHash([5u8; 32]) }),
        }],
        signature: [0u8; 64],
    };
    delta.signature = [3u8; 64];
    delta.to_wire_bytes()
}

fn sample_proof() -> MerkleProof {
    MerkleProof { leaf_index: 0, leaf_count: 1, siblings: vec![] }
}

fn sample_delta_batch_entry() -> DeltaBatchEntry {
    DeltaBatchEntry {
        encoded_delta: sample_delta_bytes(),
        checkpoint_hash: [4u8; 32],
        checkpoint_encoded: vec![1, 2, 3, 4],
        checkpoint_signature: [5u8; 64],
        author_signing_public_key: [6u8; 32],
        proof_encoded: encode_proof(&sample_proof()),
        versions: Vec::new(),
    }
}

fn request_id(seed: u8) -> RequestId {
    RequestId([seed; 16])
}

fn sample_truncation() -> RefusalReason {
    RefusalReason::HistoryTruncated { checkpoint_id: [0xC1; 32], frontier_root: [0xF2; 32] }
}

fn all_sample_messages() -> Vec<Message> {
    vec![
        Message::SummaryRequest { request_id: request_id(1), group_id: FolderGroupId("g1".into()) },
        Message::SummaryResponse {
            request_id: request_id(2),
            group_id: FolderGroupId("g1".into()),
            namespace_root: [1u8; 32],
            author_state_root: [2u8; 32],
        },
        Message::FrontierDiffRequest {
            request_id: request_id(3),
            group_id: FolderGroupId("g1".into()),
            since: vec![FrontierEntry { author: author("d1", 1), seq: AuthorSeq(4), tip: None }],
        },
        Message::FrontierDiffResponse {
            request_id: request_id(4),
            entries: vec![FrontierEntry {
                author: author("d2", 1),
                seq: AuthorSeq(5),
                tip: Some(DeltaHash([7u8; 32])),
            }],
        },
        Message::DeltaBatch {
            group_id: FolderGroupId("g1".into()),
            entries: vec![sample_delta_batch_entry()],
        },
        Message::Refused { request_id: request_id(5), reason: RefusalReason::Overloaded },
        Message::Refused { request_id: request_id(8), reason: sample_truncation() },
        Message::RecoveryRequest { request_id: request_id(6), group_id: FolderGroupId("g".into()) },
        Message::RecoveryChunk {
            request_id: request_id(7),
            group_id: FolderGroupId("g".into()),
            index: 1,
            count: 3,
            bytes: vec![9; 64],
        },
    ]
}

#[test]
fn every_message_kind_round_trips() {
    for message in all_sample_messages() {
        let bytes = encode_message(&message).expect("encodes");
        let decoded = decode_message(&bytes).expect("decodes");
        assert_eq!(message, decoded, "round-trip mismatch for {message:?}");
    }
}

#[test]
fn empty_bytes_is_a_clean_error() {
    assert!(decode_message(&[]).is_err());
}

#[test]
fn bad_domain_tag_is_rejected() {
    let mut bytes = encode_message(&all_sample_messages()[0]).unwrap();
    bytes[0] ^= 0xFF;
    assert_eq!(decode_message(&bytes), Err(ProtocolError::BadEnvelopeTag));
}

#[test]
fn wrong_generation_byte_is_rejected() {
    let mut bytes = encode_message(&all_sample_messages()[0]).unwrap();
    bytes[NATIVE_TAG_PREFIX_LEN] ^= 0xFF;
    assert_eq!(decode_message(&bytes), Err(ProtocolError::BadEnvelopeTag));
}

#[test]
fn unsupported_protocol_version_fails_closed() {
    let mut bytes = encode_message(&all_sample_messages()[0]).unwrap();
    bytes[8] = 6;
    assert_eq!(
        decode_message(&bytes),
        Err(ProtocolError::UnsupportedProtocolVersion { theirs: 6 })
    );
}

#[test]
fn unknown_message_kind_fails_closed() {
    let mut bytes = encode_message(&all_sample_messages()[0]).unwrap();
    bytes[9] = 200;
    assert_eq!(decode_message(&bytes), Err(ProtocolError::UnknownMessageKind(200)));
}

#[test]
fn trailing_bytes_are_rejected() {
    let mut bytes = encode_message(&all_sample_messages()[0]).unwrap();
    bytes.push(0);
    assert!(decode_message(&bytes).is_err());
}

#[test]
fn declared_length_over_bound_is_rejected_before_use() {
    assert_eq!(
        accept_declared_length((MAX_MESSAGE_BYTES + 1) as u32),
        Err(ProtocolError::MessageTooLarge {
            declared: MAX_MESSAGE_BYTES + 1,
            max: MAX_MESSAGE_BYTES
        })
    );
    assert_eq!(accept_declared_length(MAX_MESSAGE_BYTES as u32), Ok(MAX_MESSAGE_BYTES));
}

#[test]
fn oversized_message_is_rejected_by_decode_before_parsing() {
    let oversized = vec![0u8; MAX_MESSAGE_BYTES + 1];
    assert!(matches!(decode_message(&oversized), Err(ProtocolError::MessageTooLarge { .. })));
}

#[test]
fn batch_count_over_bound_is_rejected_before_allocating() {
    let mut buf = Vec::new();
    buf.extend_from_slice(PROTOCOL5_ENVELOPE_TAG);
    buf.push(PROTOCOL5_VERSION);
    buf.push(MessageKind::DeltaBatch as u8);
    put_str(&mut buf, "g1");
    // A count far beyond MAX_BATCH_ITEMS, with far too few remaining
    // bytes to actually hold that many entries -- must be rejected by
    // the count check, not by attempting to allocate or read them.
    put_u32(&mut buf, u32::MAX);
    let err = decode_message(&buf).unwrap_err();
    assert!(matches!(err, ProtocolError::CountExceedsBound { .. } | ProtocolError::Malformed(_)));
}

#[test]
fn oversized_item_length_prefix_is_rejected_before_allocating() {
    let mut buf = Vec::new();
    buf.extend_from_slice(PROTOCOL5_ENVELOPE_TAG);
    buf.push(PROTOCOL5_VERSION);
    buf.push(MessageKind::DeltaBatch as u8);
    put_str(&mut buf, "g1");
    put_u32(&mut buf, 1);
    put_u32(&mut buf, (MAX_BATCH_ITEM_BYTES + 1) as u32);
    // Padding enough for the entry-count check only; a correct
    // implementation must reject the length prefix itself before trying to
    // read that many bytes.
    buf.extend_from_slice(&[0u8; 256]);
    let err = decode_message(&buf).unwrap_err();
    assert_eq!(
        err,
        ProtocolError::ItemTooLarge {
            declared: MAX_BATCH_ITEM_BYTES + 1,
            max: MAX_BATCH_ITEM_BYTES
        }
    );
}

#[test]
fn truncation_at_every_prefix_length_never_panics() {
    for message in all_sample_messages() {
        let bytes = encode_message(&message).expect("encodes");
        for cut in 0..bytes.len() {
            let _ = decode_message(&bytes[..cut]);
        }
    }
}

#[test]
fn byte_flips_never_panic() {
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
            z ^ (z >> 31)
        }
    }
    let mut rng = Rng(0xDEC0DE);
    for message in all_sample_messages() {
        let original = encode_message(&message).expect("encodes");
        for _ in 0..200 {
            let mut mutated = original.clone();
            if mutated.is_empty() {
                continue;
            }
            let idx = (rng.next() as usize) % mutated.len();
            mutated[idx] ^= (rng.next() as u8).max(1);
            let _ = decode_message(&mutated);
        }
    }
}

#[test]
fn delta_batch_entry_identity_matches_the_encoded_deltas_own_hash() {
    let entry = sample_delta_batch_entry();
    let delta = NativeDelta::from_wire_bytes(&entry.encoded_delta).unwrap();
    assert_eq!(delta_batch_entry_identity(&entry).unwrap(), delta.delta_hash());
}

/// The mapping test/spec: asserts the exact class table the user
/// specified, entirely via same-crate labels — see the module doc's
/// boundary note. This must never import `yadorilink_sync_substrate`.
#[test]
fn message_class_mapping_matches_the_specified_table() {
    assert_eq!(MessageKind::SummaryRequest.class(), MessageClass::Reconciliation);
    assert_eq!(MessageKind::SummaryResponse.class(), MessageClass::Reconciliation);
    assert_eq!(MessageKind::FrontierDiffRequest.class(), MessageClass::Reconciliation);
    assert_eq!(MessageKind::FrontierDiffResponse.class(), MessageClass::Reconciliation);
    assert_eq!(MessageKind::DeltaBatch.class(), MessageClass::History);
    // Content -> Block: protocol 5 defines no content-carrying MessageKind
    // at all (see MessageClass::Block's own doc) -- the existing Block
    // transport is reused unchanged, not re-specified here.
}

#[test]
fn a_recovery_chunk_outside_its_count_is_refused() {
    for (index, count) in [(0u32, 0u32), (3, 3), (0, MAX_RECOVERY_CHUNKS + 1)] {
        let mut bytes = encode_message(&Message::RecoveryChunk {
            request_id: request_id(1),
            group_id: FolderGroupId("g".into()),
            index: 0,
            count: 1,
            bytes: vec![1],
        })
        .unwrap();
        // index and count follow the envelope (10), the request id (16) and
        // the group string (4 + 1).
        let at = 10 + 16 + 4 + 1;
        bytes[at..at + 4].copy_from_slice(&index.to_be_bytes());
        bytes[at + 4..at + 8].copy_from_slice(&count.to_be_bytes());
        assert!(decode_message(&bytes).is_err(), "chunk {index} of {count} must not decode");
    }
}

#[test]
fn a_recovery_chunk_over_the_chunk_bound_is_refused() {
    let message = Message::RecoveryChunk {
        request_id: request_id(1),
        group_id: FolderGroupId("g".into()),
        index: 0,
        count: 1,
        bytes: vec![0; MAX_RECOVERY_CHUNK_BYTES + 1],
    };
    let bytes = encode_message(&message).unwrap();
    assert!(decode_message(&bytes).is_err());
}

/// The exact bytes of a history-truncated refusal: tag and generation, version,
/// kind, request id, reason byte, then the retained checkpoint id and frontier root.
#[test]
fn a_history_truncated_refusal_has_a_golden_encoding() {
    let message = Message::Refused { request_id: request_id(9), reason: sample_truncation() };
    let mut expected = Vec::new();
    expected.extend_from_slice(b"YLNKp5e");
    expected.push(NATIVE_PROTOCOL_GENERATION);
    expected.push(5); // protocol version
    expected.push(6); // Refused
    expected.extend_from_slice(&[9u8; 16]);
    expected.push(5); // HistoryTruncated
    expected.extend_from_slice(&[0xC1; 32]);
    expected.extend_from_slice(&[0xF2; 32]);
    assert_eq!(encode_message(&message).unwrap(), expected);
    assert_eq!(decode_message(&expected).unwrap(), message);
}

/// The envelope carries the one native protocol generation, and an envelope of
/// the previous generation is refused as a bad tag.
#[test]
fn the_envelope_carries_the_native_protocol_generation() {
    assert_eq!(PROTOCOL5_ENVELOPE_TAG[7], NATIVE_PROTOCOL_GENERATION);
    let mut old = encode_message(&Message::Refused {
        request_id: request_id(1),
        reason: RefusalReason::NotFound,
    })
    .unwrap();
    old[7] = NATIVE_PROTOCOL_GENERATION - 1;
    assert_eq!(decode_message(&old), Err(ProtocolError::BadEnvelopeTag));
}

#[test]
fn a_truncated_history_refusal_cut_short_is_malformed_not_a_panic() {
    let bytes = encode_message(&Message::Refused {
        request_id: request_id(2),
        reason: sample_truncation(),
    })
    .unwrap();
    for len in 0..bytes.len() {
        assert!(decode_message(&bytes[..len]).is_err(), "prefix of {len} bytes decoded");
    }
}
