//! The wire form of a native recovery bundle: a [`NativeBootstrap`] without
//! index rows (see [`crate::native_bootstrap::build_native_recovery_bundle`]).
//!
//! Every length prefix is bounded before it can size an allocation, and the
//! decoder never trusts a count: a hostile bundle fails to decode, it does not
//! allocate. Nothing here judges the bundle; verification is
//! [`crate::native_bootstrap::verify_native_bootstrap`]'s.

use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::author_closure::SignedAuthorClosure;
use yadorilink_replica_domain::codec::{
    put_len_bytes, put_str, put_u32, put_u64, ChangeError, Reader,
};
use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, SyncPath};
use yadorilink_replica_domain::native_checkpoint::NativeCheckpoint;
use yadorilink_replica_domain::native_checkpoint_seal::NativeCheckpointSealEvidence;
use yadorilink_replica_domain::native_frontier::{AuthorState, NativeAuthorFrontierEntry};
use yadorilink_replica_domain::native_protocol::native_domain_tag;
use yadorilink_replica_domain::native_state::{DeltaHash, Dot};

use crate::native_bootstrap::{
    BootstrapAuthorState, BootstrapDelta, BootstrapHead, NativeBootstrap,
};

/// Domain tag; the last byte is the generation.
const TAG: &[u8; 8] = &native_domain_tag(b"YLNKrcv");

/// Fixed-size pieces of the layout, named so the per-entry minimums below read
/// as the encoder's own arithmetic.
const LEN_PREFIX: usize = 4;
const INCARNATION_LEN: usize = 16;
const SEQ_LEN: usize = 8;
const HASH_LEN: usize = 32;
/// An author: a length-prefixed device (possibly empty) and an incarnation.
const AUTHOR_MIN: usize = LEN_PREFIX + INCARNATION_LEN;

/// The fewest bytes one entry of each collection can encode to. A count is
/// refused when the remaining bytes cannot hold that many entries of at least
/// this size, so each must be the true minimum, never an over-estimate: a valid
/// bundle of the smallest entries would otherwise be refused.
const HEAD_MIN: usize = LEN_PREFIX + AUTHOR_MIN + SEQ_LEN + HASH_LEN;
const DELTA_MIN: usize = LEN_PREFIX + HASH_LEN + LEN_PREFIX + LEN_PREFIX + HASH_LEN + LEN_PREFIX;
/// An author and its state flag: the shortest state (closed before the first
/// delta) carries no entry.
const AUTHOR_STATE_MIN: usize = AUTHOR_MIN + 1;
const FILE_VERSION_MIN: usize = LEN_PREFIX;
const CLOSURE_MIN: usize = LEN_PREFIX;

/// The flag of an author's state: open at an entry, closed at a cutoff entry, or
/// closed before its first delta (no entry follows).
const STATE_OPEN: u8 = 0;
const STATE_CLOSED: u8 = 1;
const STATE_CLOSED_EMPTY: u8 = 2;

/// The most of each collection one bundle may carry.
pub const MAX_ENTRIES: usize = 1 << 22;

fn put_author(buf: &mut Vec<u8>, author: &AuthorId) {
    put_str(buf, author.device.as_str());
    buf.extend_from_slice(&author.incarnation.0);
}

fn read_author(r: &mut Reader<'_>) -> Result<AuthorId, ChangeError> {
    let device = DeviceId(r.string()?);
    let incarnation = IncarnationId(r.array16()?);
    Ok(AuthorId { device, incarnation })
}

fn read_seq(r: &mut Reader<'_>) -> Result<AuthorSeq, ChangeError> {
    let seq = AuthorSeq(r.u64()?);
    if !(AuthorSeq::FIRST..=AuthorSeq::MAX).contains(&seq) {
        return Err(ChangeError::Encoding(format!("sequence {seq} is out of range")));
    }
    Ok(seq)
}

/// The bundle's canonical bytes.
pub fn encode_recovery_bundle(bundle: &NativeBootstrap) -> Result<Vec<u8>, ChangeError> {
    let seal = bundle
        .seal
        .as_ref()
        .ok_or_else(|| ChangeError::Malformed("a recovery bundle needs its seal".into()))?;
    let mut out = Vec::new();
    out.extend_from_slice(TAG);
    put_len_bytes(&mut out, &bundle.checkpoint.to_wire_bytes());
    put_str(&mut out, seal.sealer.as_str());
    put_len_bytes(&mut out, &seal.evidence);

    put_u32(&mut out, bundle.heads.len() as u32);
    for head in &bundle.heads {
        put_str(&mut out, head.path.as_str());
        put_author(&mut out, &head.dot.author);
        put_u64(&mut out, head.dot.seq.get());
        out.extend_from_slice(&head.provenance.0);
    }
    put_u32(&mut out, bundle.deltas.len() as u32);
    for delta in &bundle.deltas {
        put_len_bytes(&mut out, &delta.delta_wire);
        out.extend_from_slice(&delta.checkpoint_hash);
        put_len_bytes(&mut out, &delta.checkpoint_encoded);
        put_len_bytes(&mut out, &delta.checkpoint_signature);
        out.extend_from_slice(&delta.author_signing_public_key);
        put_len_bytes(&mut out, &delta.merkle_proof_encoded);
    }
    put_u32(&mut out, bundle.authors.len() as u32);
    for author in &bundle.authors {
        put_author(&mut out, &author.author);
        let (flag, entry) = match &author.state {
            AuthorState::Open(entry) => (STATE_OPEN, Some(entry)),
            AuthorState::Closed { frontier: Some(entry) } => (STATE_CLOSED, Some(entry)),
            AuthorState::Closed { frontier: None } => (STATE_CLOSED_EMPTY, None),
        };
        out.push(flag);
        if let Some(entry) = entry {
            put_u64(&mut out, entry.seq.get());
            out.extend_from_slice(&entry.tip.0);
        }
    }
    // One canonical byte string per set of closures: by author, then by identity.
    let mut closures: Vec<&SignedAuthorClosure> = bundle.closures.iter().collect();
    closures.sort_by_key(|closure| (closure.closure.author.clone(), closure.closure_hash()));
    put_u32(&mut out, closures.len() as u32);
    for closure in closures {
        put_len_bytes(&mut out, &closure.to_wire_bytes());
    }
    put_u32(&mut out, bundle.file_versions.len() as u32);
    for version in &bundle.file_versions {
        put_len_bytes(&mut out, version);
    }
    Ok(out)
}

/// The exact inverse of [`encode_recovery_bundle`]; anything else, trailing
/// bytes included, is refused.
pub fn decode_recovery_bundle(bytes: &[u8]) -> Result<NativeBootstrap, ChangeError> {
    let mut r = Reader::new(bytes);
    if r.take(8)? != TAG {
        return Err(ChangeError::Encoding("not a native recovery bundle".into()));
    }
    let checkpoint = NativeCheckpoint::from_wire_bytes(&r.len_bytes()?)?;
    let sealer = DeviceId(r.string()?);
    let evidence = r.len_bytes()?;
    let seal = NativeCheckpointSealEvidence { sealer, evidence };

    let count = r.bounded_count(HEAD_MIN, MAX_ENTRIES)?;
    let mut heads = Vec::with_capacity(count);
    for _ in 0..count {
        let path = SyncPath(r.string()?);
        let author = read_author(&mut r)?;
        let seq = read_seq(&mut r)?;
        heads.push(BootstrapHead {
            path,
            dot: Dot { author, seq },
            provenance: DeltaHash(r.array32()?),
        });
    }
    let count = r.bounded_count(DELTA_MIN, MAX_ENTRIES)?;
    let mut deltas = Vec::with_capacity(count);
    for _ in 0..count {
        deltas.push(BootstrapDelta {
            delta_wire: r.len_bytes()?,
            checkpoint_hash: r.array32()?,
            checkpoint_encoded: r.len_bytes()?,
            checkpoint_signature: r.len_bytes()?,
            author_signing_public_key: r.array32()?,
            merkle_proof_encoded: r.len_bytes()?,
        });
    }
    let count = r.bounded_count(AUTHOR_STATE_MIN, MAX_ENTRIES)?;
    let mut authors: Vec<BootstrapAuthorState> = Vec::with_capacity(count);
    for _ in 0..count {
        let author = read_author(&mut r)?;
        let flag = r.u8()?;
        let state = match flag {
            STATE_CLOSED_EMPTY => AuthorState::Closed { frontier: None },
            STATE_OPEN | STATE_CLOSED => {
                let seq = read_seq(&mut r)?;
                let tip = DeltaHash(r.array32()?);
                let entry = NativeAuthorFrontierEntry { seq, tip };
                if flag == STATE_OPEN {
                    AuthorState::Open(entry)
                } else {
                    AuthorState::Closed { frontier: Some(entry) }
                }
            }
            other => {
                return Err(ChangeError::Encoding(format!("unknown author-state flag {other}")))
            }
        };
        // One canonical byte string per set of author states: strictly
        // ascending by author, so a duplicate or a reordering is not a bundle.
        if authors.last().is_some_and(|last| last.author >= author) {
            return Err(ChangeError::Encoding(
                "authors are not in strictly ascending order".into(),
            ));
        }
        authors.push(BootstrapAuthorState { author, state });
    }
    let count = r.bounded_count(CLOSURE_MIN, MAX_ENTRIES)?;
    let mut closures: Vec<SignedAuthorClosure> = Vec::with_capacity(count);
    for _ in 0..count {
        let closure = SignedAuthorClosure::from_wire_bytes(&r.len_bytes()?)?;
        if closures.last().is_some_and(|last| {
            (&last.closure.author, last.closure_hash())
                >= (&closure.closure.author, closure.closure_hash())
        }) {
            return Err(ChangeError::Encoding(
                "closures are not in strictly ascending order".into(),
            ));
        }
        closures.push(closure);
    }
    let count = r.bounded_count(FILE_VERSION_MIN, MAX_ENTRIES)?;
    let mut file_versions = Vec::with_capacity(count);
    for _ in 0..count {
        file_versions.push(r.len_bytes()?);
    }
    r.expect_end()?;
    Ok(NativeBootstrap {
        checkpoint,
        seal: Some(seal),
        heads,
        deltas,
        authors,
        closures,
        file_versions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_replica_domain::native_protocol::NATIVE_PROTOCOL_GENERATION;

    fn bundle() -> NativeBootstrap {
        let author =
            AuthorId { device: DeviceId("device-a".into()), incarnation: IncarnationId([3; 16]) };
        let mut checkpoint = NativeCheckpoint::new(
            yadorilink_replica_domain::ids::FolderGroupId("g".into()),
            yadorilink_replica_domain::native_checkpoint::NamespaceRoot([1; 32]),
            yadorilink_replica_domain::native_checkpoint::AuthorStateRoot([2; 32]),
        );
        checkpoint.sign(&ed25519_dalek::SigningKey::from_bytes(&[9; 32]));
        NativeBootstrap {
            checkpoint,
            seal: Some(NativeCheckpointSealEvidence {
                sealer: DeviceId("device-a".into()),
                evidence: vec![1, 2, 3],
            }),
            heads: vec![BootstrapHead {
                path: SyncPath("a/b".into()),
                dot: Dot { author: author.clone(), seq: AuthorSeq(2) },
                provenance: DeltaHash([4; 32]),
            }],
            deltas: vec![BootstrapDelta {
                delta_wire: vec![5; 7],
                checkpoint_hash: [6; 32],
                checkpoint_encoded: vec![7; 5],
                checkpoint_signature: vec![8; 64],
                author_signing_public_key: [9; 32],
                merkle_proof_encoded: vec![10; 3],
            }],
            authors: vec![
                BootstrapAuthorState {
                    author: author.clone(),
                    state: AuthorState::Open(NativeAuthorFrontierEntry {
                        seq: AuthorSeq(2),
                        tip: DeltaHash([4; 32]),
                    }),
                },
                BootstrapAuthorState {
                    author: AuthorId {
                        device: DeviceId("device-b".into()),
                        incarnation: IncarnationId([4; 16]),
                    },
                    state: AuthorState::Closed {
                        frontier: Some(NativeAuthorFrontierEntry {
                            seq: AuthorSeq(1),
                            tip: DeltaHash([5; 32]),
                        }),
                    },
                },
                BootstrapAuthorState {
                    author: AuthorId {
                        device: DeviceId("device-c".into()),
                        incarnation: IncarnationId([5; 16]),
                    },
                    state: AuthorState::Closed { frontier: None },
                },
            ],
            closures: vec![closure_of_e()],
            file_versions: vec![vec![11; 9]],
        }
    }

    /// The closure the bundle carries for its closed author `e`.
    fn closure_of_e() -> SignedAuthorClosure {
        yadorilink_replica_domain::author_closure::AuthorClosure {
            group_id: yadorilink_replica_domain::ids::FolderGroupId("g".into()),
            author: AuthorId { device: DeviceId("e".into()), incarnation: IncarnationId([5; 16]) },
            cutoff: Some(NativeAuthorFrontierEntry { seq: AuthorSeq(6), tip: DeltaHash([7; 32]) }),
        }
        .sign(&ed25519_dalek::SigningKey::from_bytes(&[9; 32]), vec![1, 2, 3])
    }

    #[test]
    fn closures_must_be_in_strictly_ascending_order() {
        let first = closure_of_e();
        let mut second = first.clone();
        second.closure.author.incarnation = IncarnationId([6; 16]);
        let with = |closures: Vec<SignedAuthorClosure>| {
            let mut b = empty_bundle();
            b.closures = closures;
            encode_recovery_bundle(&b).unwrap()
        };
        assert!(decode_recovery_bundle(&with(vec![first.clone(), second.clone()])).is_ok());
        // The encoder writes the canonical order whatever order it is given.
        assert_eq!(
            with(vec![second.clone(), first.clone()]),
            with(vec![first.clone(), second.clone()])
        );
        // A duplicate is not a bundle.
        assert!(decode_recovery_bundle(&with(vec![first.clone(), first.clone()])).is_err());
        // Bytes that are not a closure are refused.
        let mut bytes = with(vec![first.clone()]);
        let at = bytes.len() - 3 * 4 - first.to_wire_bytes().len() + 1;
        bytes[at] ^= 0xff;
        assert!(decode_recovery_bundle(&bytes).is_err());
    }

    #[test]
    fn a_bundle_round_trips() {
        let bundle = bundle();
        let bytes = encode_recovery_bundle(&bundle).unwrap();
        assert_eq!(decode_recovery_bundle(&bytes).unwrap(), bundle);
    }

    /// A bundle whose every collection is empty.
    fn empty_bundle() -> NativeBootstrap {
        let mut b = bundle();
        b.heads.clear();
        b.deltas.clear();
        b.authors.clear();
        b.closures.clear();
        b.file_versions.clear();
        b
    }

    fn smallest_head() -> BootstrapHead {
        BootstrapHead {
            path: SyncPath(String::new()),
            dot: Dot {
                author: AuthorId {
                    device: DeviceId(String::new()),
                    incarnation: IncarnationId([0; 16]),
                },
                seq: AuthorSeq(1),
            },
            provenance: DeltaHash([0; 32]),
        }
    }

    /// The smallest author state: closed before the first delta, no entry.
    fn smallest_author_state() -> BootstrapAuthorState {
        BootstrapAuthorState {
            author: smallest_head().dot.author,
            state: AuthorState::Closed { frontier: None },
        }
    }

    fn smallest_delta() -> BootstrapDelta {
        BootstrapDelta {
            delta_wire: Vec::new(),
            checkpoint_hash: [0; 32],
            checkpoint_encoded: Vec::new(),
            checkpoint_signature: Vec::new(),
            author_signing_public_key: [0; 32],
            merkle_proof_encoded: Vec::new(),
        }
    }

    fn encoded_len(b: &NativeBootstrap) -> usize {
        encode_recovery_bundle(b).unwrap().len()
    }

    #[test]
    fn each_minimum_entry_size_is_the_size_of_the_smallest_encoded_entry() {
        let base = encoded_len(&empty_bundle());
        let grew = |f: &dyn Fn(&mut NativeBootstrap)| {
            let mut b = empty_bundle();
            f(&mut b);
            encoded_len(&b) - base
        };
        assert_eq!(grew(&|b| b.heads.push(smallest_head())), HEAD_MIN);
        assert_eq!(grew(&|b| b.deltas.push(smallest_delta())), DELTA_MIN);
        assert_eq!(grew(&|b| b.authors.push(smallest_author_state())), AUTHOR_STATE_MIN);
        assert_eq!(grew(&|b| b.file_versions.push(Vec::new())), FILE_VERSION_MIN);
    }

    #[test]
    fn a_bundle_of_only_the_smallest_entries_of_one_collection_round_trips() {
        // Each collection alone, so nothing larger follows it to make room for
        // an over-estimated minimum entry size.
        let fills: [fn(&mut NativeBootstrap); 4] = [
            |b| b.heads.push(smallest_head()),
            |b| b.deltas.push(smallest_delta()),
            |b| {
                // Authors are strictly ascending, so each is distinct.
                let mut state = smallest_author_state();
                state.author.incarnation = IncarnationId([b.authors.len() as u8; 16]);
                b.authors.push(state);
            },
            |b| b.file_versions.push(Vec::new()),
        ];
        for (which, fill) in fills.iter().enumerate() {
            let mut b = empty_bundle();
            for _ in 0..5 {
                fill(&mut b);
            }
            let bytes = encode_recovery_bundle(&b).unwrap();
            assert_eq!(decode_recovery_bundle(&bytes).unwrap(), b, "collection {which}");
        }
    }

    #[test]
    fn a_bundle_with_rows_or_no_seal_is_not_encoded() {
        let mut unsealed = bundle();
        unsealed.seal = None;
        assert!(encode_recovery_bundle(&unsealed).is_err());
    }

    #[test]
    fn every_truncation_and_trailing_byte_is_refused() {
        let bytes = encode_recovery_bundle(&bundle()).unwrap();
        for cut in 0..bytes.len() {
            assert!(decode_recovery_bundle(&bytes[..cut]).is_err(), "truncated at {cut}");
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(decode_recovery_bundle(&longer).is_err());
        let mut tagless = bytes;
        tagless[0] ^= 0xff;
        assert!(decode_recovery_bundle(&tagless).is_err());
    }

    #[test]
    fn a_hostile_count_does_not_allocate() {
        let mut bytes = encode_recovery_bundle(&bundle()).unwrap();
        // The head count follows the tag, the checkpoint and the seal.
        let offset =
            8 + 4 + bundle().checkpoint.to_wire_bytes().len() + 4 + "device-a".len() + 4 + 3;
        bytes[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_recovery_bundle(&bytes).is_err());
    }

    #[test]
    fn the_bundle_generation_is_pinned_and_another_one_is_refused() {
        assert_eq!(&TAG[..7], b"YLNKrcv");
        assert_eq!(TAG[7], NATIVE_PROTOCOL_GENERATION);
        let mut bytes = encode_recovery_bundle(&bundle()).unwrap();
        assert_eq!(&bytes[..8], TAG);
        bytes[7] = NATIVE_PROTOCOL_GENERATION - 1;
        assert!(decode_recovery_bundle(&bytes).is_err(), "the previous generation is refused");
    }

    /// Every native object (delta wire, header and body encodings, checkpoint,
    /// seal evidence, bundle, protocol-5 envelope) carries the one protocol
    /// generation in its domain tag: a bump moves them all together.
    #[test]
    fn delta_and_bundle_use_the_single_protocol_generation() {
        use yadorilink_replica_domain::native_checkpoint::NATIVE_CHECKPOINT_DOMAIN_TAG;
        use yadorilink_replica_domain::native_checkpoint_seal::{
            NATIVE_CHECKPOINT_SEAL_LEAF_TAG, NATIVE_CHECKPOINT_SEAL_PROOF_TAG,
        };
        use yadorilink_replica_domain::protocol5::PROTOCOL5_ENVELOPE_TAG;
        use yadorilink_replica_domain::signed_delta::{
            NATIVE_DELTA_BODY_DOMAIN_TAG, NATIVE_DELTA_DOMAIN_TAG, NATIVE_DELTA_HEADER_DOMAIN_TAG,
        };
        for (name, tag) in [
            ("delta wire", NATIVE_DELTA_DOMAIN_TAG),
            ("delta header", NATIVE_DELTA_HEADER_DOMAIN_TAG),
            ("delta body", NATIVE_DELTA_BODY_DOMAIN_TAG),
            ("checkpoint", NATIVE_CHECKPOINT_DOMAIN_TAG),
            ("seal leaf", NATIVE_CHECKPOINT_SEAL_LEAF_TAG),
            ("seal proof", NATIVE_CHECKPOINT_SEAL_PROOF_TAG),
            ("bundle", TAG),
            ("protocol-5 envelope", PROTOCOL5_ENVELOPE_TAG),
        ] {
            assert_eq!(tag[7], NATIVE_PROTOCOL_GENERATION, "{name}");
        }
    }

    /// The author-state section, byte for byte, built here without the encoder:
    /// the count, then each author with its state flag and, unless it was closed
    /// before its first delta, its entry.
    #[test]
    fn the_author_state_section_is_laid_out_as_pinned() {
        let mut b = empty_bundle();
        b.authors = vec![
            BootstrapAuthorState {
                author: AuthorId {
                    device: DeviceId("d".into()),
                    incarnation: IncarnationId([1; 16]),
                },
                state: AuthorState::Open(NativeAuthorFrontierEntry {
                    seq: AuthorSeq(2),
                    tip: DeltaHash([3; 32]),
                }),
            },
            BootstrapAuthorState {
                author: AuthorId {
                    device: DeviceId("e".into()),
                    incarnation: IncarnationId([5; 16]),
                },
                state: AuthorState::Closed {
                    frontier: Some(NativeAuthorFrontierEntry {
                        seq: AuthorSeq(6),
                        tip: DeltaHash([7; 32]),
                    }),
                },
            },
            BootstrapAuthorState {
                author: AuthorId {
                    device: DeviceId("f".into()),
                    incarnation: IncarnationId([9; 16]),
                },
                state: AuthorState::Closed { frontier: None },
            },
        ];
        let mut expected = Vec::new();
        expected.extend_from_slice(&3u32.to_be_bytes());
        expected.extend_from_slice(&1u32.to_be_bytes());
        expected.extend_from_slice(b"d");
        expected.extend_from_slice(&[1; 16]);
        expected.push(0);
        expected.extend_from_slice(&2u64.to_be_bytes());
        expected.extend_from_slice(&[3; 32]);
        expected.extend_from_slice(&1u32.to_be_bytes());
        expected.extend_from_slice(b"e");
        expected.extend_from_slice(&[5; 16]);
        expected.push(1);
        expected.extend_from_slice(&6u64.to_be_bytes());
        expected.extend_from_slice(&[7; 32]);
        expected.extend_from_slice(&1u32.to_be_bytes());
        expected.extend_from_slice(b"f");
        expected.extend_from_slice(&[9; 16]);
        expected.push(2);

        let bytes = encode_recovery_bundle(&b).unwrap();
        let without = encode_recovery_bundle(&empty_bundle()).unwrap();
        // The empty bundle holds a zero author count where this one holds the section.
        let at = without.len() - 4 * 2 - 4;
        assert_eq!(&without[at..at + 4], &0u32.to_be_bytes());
        assert_eq!(&bytes[at..at + expected.len()], expected.as_slice());
        assert_eq!(decode_recovery_bundle(&bytes).unwrap(), b);
    }

    #[test]
    fn an_author_state_with_an_unknown_flag_is_refused() {
        let mut b = empty_bundle();
        b.authors = vec![smallest_author_state()];
        let mut bytes = encode_recovery_bundle(&b).unwrap();
        // The flag is the last byte of the section, before the two empty counts
        // that close the bundle.
        let at = bytes.len() - 4 * 2 - 1;
        assert_eq!(bytes[at], STATE_CLOSED_EMPTY);
        bytes[at] = 9;
        assert!(decode_recovery_bundle(&bytes).is_err());
    }

    #[test]
    fn authors_must_be_in_strictly_ascending_order() {
        let state = |incarnation: u8| {
            let mut state = smallest_author_state();
            state.author.incarnation = IncarnationId([incarnation; 16]);
            state
        };
        let with = |states: Vec<BootstrapAuthorState>| {
            let mut b = empty_bundle();
            b.authors = states;
            encode_recovery_bundle(&b).unwrap()
        };
        assert!(decode_recovery_bundle(&with(vec![state(1), state(2)])).is_ok());
        assert!(decode_recovery_bundle(&with(vec![state(2), state(1)])).is_err(), "disorder");
        assert!(decode_recovery_bundle(&with(vec![state(1), state(1)])).is_err(), "duplicate");
    }
}
