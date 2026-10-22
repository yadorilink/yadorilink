//! `NativeDelta`: the signed wire object that carries one native-causal-state
//! mutation (`native_state::PathEdit`, generalized to remove by
//! `(dot, provenance)` rather than by dot alone) between replicas.
//!
//! This module is the pure domain type only (encode/hash/sign/verify).
//! Deliberately **not** done here:
//!
//! * Context-gated admission (hold a removal naming an unobserved dot; drop a
//!   removal whose provenance does not match the live head) — that is remote
//!   admission's job, not a domain-type concern.
//! * A Merkle-batch authorization scheme — production already has
//!   `AuthorizationCheckpoint` (see `authorization_checkpoint.rs`), and
//!   publish-time authorization integrates with that directly.
//!
//! # Encoding
//!
//! The encoding splits a header from a body: the header commits to a SHA-256 digest of the body,
//! so the delta's identity ([`NativeDelta::delta_hash`]) is the hash of the
//! header alone, and the signature covers the header (which transitively
//! commits to the body).
//!
//! ```text
//! header  = NATIVE_DELTA_HEADER_DOMAIN_TAG
//!           str(group_id) str(author) u64(seq) prev[0|1 + 32] body_digest[32]
//! body    = u32(|ops|) op*
//! op      = str(path) u32(|removes|) headref* u8(put?) [version[32]]
//! headref = str(author) u64(seq) provenance[32]
//! wire    = NATIVE_DELTA_DOMAIN_TAG header signature[64] body
//! ```
//!
//! A leading domain tag with a trailing generation byte prevents this
//! encoding from ever colliding with another wire type or being silently
//! reinterpreted across a future generation, There is no
//! compatibility path: a generation mismatch is refused outright, never
//! reinterpreted.
//!
//! A [`HeadRef`] names the head it supersedes by `(dot, provenance)`, not just
//! `dot`: `provenance` is the [`native_state::DeltaHash`] the target head's
//! `provenance` must match. This is the identity a receiver checks at
//! admission time (P4a) — out of scope here, but the field exists in this
//! slice's wire format because it is part of the delta's signed content, not
//! an admission-layer add-on. A landed head's own `provenance` is *not*
//! carried on the wire: it is derived by the receiver
//! as this delta's own `delta_hash()` once computed, so [`DeltaPut`] carries
//! only `version`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::author::{AuthorId, IncarnationId};
use crate::codec::{put_str, put_u32, put_u64, ChangeError, Reader};
use crate::ids::{AuthorSeq, DeviceId, FolderGroupId, SyncPath, VersionHash};
use crate::limits::MAX_OPS;
use crate::native_protocol::{check_native_tag, native_domain_tag};
use crate::native_state::{DeltaHash, Dot};

pub(crate) fn decode_author_id(r: &mut Reader<'_>) -> Result<AuthorId, ChangeError> {
    let device = DeviceId(r.string()?);
    let incarnation = IncarnationId(r.take(16)?.try_into().expect("take(16) yields 16 bytes"));
    let author = AuthorId { device, incarnation };
    author.validate()?;
    Ok(author)
}

/// Domain tag for a [`NativeDelta`]'s full wire encoding (header, signature,
/// body). Trailing byte is [`crate::native_protocol::NATIVE_PROTOCOL_GENERATION`]; there is no
/// migration ladder — see the module doc.
pub const NATIVE_DELTA_DOMAIN_TAG: &[u8; 8] = &native_domain_tag(b"YLNKndl");

/// Domain tag for the header encoding alone (what is hashed for
/// [`NativeDelta::delta_hash`] and signed), distinct from the full wire tag
/// so a header byte string can never be mistaken for a full delta.
pub const NATIVE_DELTA_HEADER_DOMAIN_TAG: &[u8; 8] = &native_domain_tag(b"YLNKndH");

/// Domain tag mixed into the body digest, distinct from the header tag so a
/// body byte string can never be mistaken for a header.
pub const NATIVE_DELTA_BODY_DOMAIN_TAG: &[u8; 8] = &native_domain_tag(b"YLNKndB");

/// The most heads one `DeltaOp` may name for removal at one path. Generous
/// relative to the live width seen in practice; an
/// untrusted-input ceiling, not a real-world capacity estimate (matches
/// `limits.rs`'s own reasoning for its bounds).
pub const MAX_REMOVES_PER_OP: usize = 64;

/// A head named inside an op by its exact identity: the dot that created it and
/// the header hash of the delta that did so (the head's provenance). The path is
/// the naming op's path; [`HeadId`] is the same identity with the path spelled
/// out. A reference to a dot the receiver has not observed yet, or whose
/// provenance does not match the live head's, is an admission-layer concern -
/// this type only carries the signed claim.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HeadRef {
    pub dot: Dot,
    pub provenance: DeltaHash,
}

/// Content landed at a path by one `DeltaOp`. `provenance` is deliberately
/// absent here — see the module doc — the receiver sets it to this delta's
/// own `delta_hash()`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DeltaPut {
    pub version: VersionHash,
}

/// One path's edit within a delta: the heads it supersedes there, and what
/// (if anything) it lands.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DeltaOp {
    pub path: SyncPath,
    pub removes: Vec<HeadRef>,
    pub put: Option<DeltaPut>,
}

/// One signed native-causal-state mutation. `prev` is the author's own
/// previous delta's header hash (`None` exactly for the author's first
/// delta in this group) — the author's chain link.
/// Names the recursive operation (a folder delete or directory rename) a
/// delta is one part of: every part of one operation carries the same id and
/// count, and its own index. The operation is keyed by `(author, id)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RecursivePart {
    pub operation_id: crate::recursive_operation::RecursiveOperationId,
    pub part_index: u32,
    pub part_count: u32,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NativeDelta {
    pub group_id: FolderGroupId,
    pub author: AuthorId,
    pub seq: AuthorSeq,
    pub prev: Option<DeltaHash>,
    pub ops: Vec<DeltaOp>,
    /// The recursive operation this delta is a part of, if it is one.
    pub recursive_part: Option<RecursivePart>,
    /// Ed25519 by the author's device key over [`Self::unsigned_header_encoding`].
    pub signature: [u8; 64],
}

impl NativeDelta {
    /// The delta's dot: `(author, seq)`.
    pub fn dot(&self) -> Dot {
        Dot { author: self.author.clone(), seq: self.seq }
    }

    fn body_encoding(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_u32(&mut buf, self.ops.len() as u32);
        for op in &self.ops {
            put_str(&mut buf, op.path.as_str());
            put_u32(&mut buf, op.removes.len() as u32);
            for removal in &op.removes {
                removal.dot.author.encode_into(&mut buf);
                put_u64(&mut buf, removal.dot.seq.get());
                buf.extend_from_slice(&removal.provenance.0);
            }
            match &op.put {
                None => buf.push(0),
                Some(put) => {
                    buf.push(1);
                    buf.extend_from_slice(&put.version.0);
                }
            }
        }
        buf
    }

    /// SHA-256 over [`NATIVE_DELTA_BODY_DOMAIN_TAG`] and the encoded ops.
    pub fn body_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(NATIVE_DELTA_BODY_DOMAIN_TAG);
        hasher.update(self.body_encoding());
        hasher.finalize().into()
    }

    /// The header this delta signs, without the signature.
    pub fn unsigned_header_encoding(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(NATIVE_DELTA_HEADER_DOMAIN_TAG);
        put_str(&mut buf, self.group_id.as_str());
        self.author.encode_into(&mut buf);
        put_u64(&mut buf, self.seq.get());
        match self.prev {
            None => buf.push(0),
            Some(prev) => {
                buf.push(1);
                buf.extend_from_slice(&prev.0);
            }
        }
        match &self.recursive_part {
            None => buf.push(0),
            Some(part) => {
                buf.push(1);
                buf.extend_from_slice(&part.operation_id.0);
                put_u32(&mut buf, part.part_index);
                put_u32(&mut buf, part.part_count);
            }
        }
        buf.extend_from_slice(&self.body_digest());
        buf
    }

    /// SHA-256 of [`Self::unsigned_header_encoding`] — this delta's identity
    /// and the head [`DeltaPut`] provenance a receiver derives for anything
    /// it lands.
    pub fn delta_hash(&self) -> DeltaHash {
        DeltaHash(Sha256::digest(self.unsigned_header_encoding()).into())
    }

    /// Signs the header encoding, overwriting `signature`.
    pub fn sign(&mut self, signing_key: &SigningKey) {
        let sig = signing_key.sign(&self.unsigned_header_encoding());
        self.signature = sig.to_bytes();
    }

    /// Verifies the signature against the author's public signing key.
    pub fn verify_signature(&self, public_key: &VerifyingKey) -> Result<(), ChangeError> {
        let sig = Signature::from_bytes(&self.signature);
        public_key
            .verify(&self.unsigned_header_encoding(), &sig)
            .map_err(|_| ChangeError::BadSignature)
    }

    /// Full wire bytes: domain tag, header, signature, body.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let body = self.body_encoding();
        let mut buf = Vec::with_capacity(8 + 128 + body.len());
        buf.extend_from_slice(NATIVE_DELTA_DOMAIN_TAG);
        buf.extend_from_slice(&self.unsigned_header_encoding());
        buf.extend_from_slice(&self.signature);
        buf.extend_from_slice(&body);
        buf
    }

    /// Decodes and structurally validates wire bytes: domain tag, header
    /// shape, and that the body matches the digest the header commits to.
    /// The signature is not checked here — that needs the author's key
    /// ([`Self::verify_signature`]).
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ChangeError> {
        let mut r = Reader::new(bytes);
        check_native_tag(r.take(8)?, NATIVE_DELTA_DOMAIN_TAG, "native delta")?;
        let header = HeaderFields::decode(&mut r)?;
        let signature: [u8; 64] = r
            .take(64)?
            .try_into()
            .map_err(|_| ChangeError::Encoding("signature must be 64 bytes".into()))?;
        let body_start = bytes.len() - r.remaining();
        let ops = decode_ops(&mut r)?;
        r.expect_end()?;

        let mut hasher = Sha256::new();
        hasher.update(NATIVE_DELTA_BODY_DOMAIN_TAG);
        hasher.update(&bytes[body_start..]);
        let body_digest: [u8; 32] = hasher.finalize().into();
        if body_digest != header.body_digest {
            return Err(ChangeError::HashMismatch);
        }

        Ok(NativeDelta {
            group_id: header.group_id,
            author: header.author,
            seq: header.seq,
            prev: header.prev,
            ops,
            recursive_part: header.recursive_part,
            signature,
        })
    }
}

struct HeaderFields {
    group_id: FolderGroupId,
    author: AuthorId,
    seq: AuthorSeq,
    prev: Option<DeltaHash>,
    recursive_part: Option<RecursivePart>,
    body_digest: [u8; 32],
}

impl HeaderFields {
    fn decode(r: &mut Reader<'_>) -> Result<Self, ChangeError> {
        check_native_tag(r.take(8)?, NATIVE_DELTA_HEADER_DOMAIN_TAG, "native delta header")?;
        let group_id = FolderGroupId(r.string()?);
        let author = decode_author_id(r)?;
        let seq = AuthorSeq(r.u64()?);
        if seq > AuthorSeq::MAX {
            return Err(ChangeError::Encoding(format!(
                "delta carries author sequence {seq}, which exceeds the highest storable position \
                 {}",
                AuthorSeq::MAX
            )));
        }
        if seq < AuthorSeq::FIRST {
            return Err(ChangeError::Encoding(format!(
                "delta carries author sequence {seq}, below the lowest legitimate position {}",
                AuthorSeq::FIRST
            )));
        }
        let prev = match r.u8()? {
            0 => None,
            1 => Some(DeltaHash(r.array32()?)),
            other => {
                return Err(ChangeError::Encoding(format!(
                    "unknown prev-presence discriminant {other}"
                )))
            }
        };
        let recursive_part = match r.u8()? {
            0 => None,
            1 => {
                let operation_id = crate::recursive_operation::RecursiveOperationId(r.array16()?);
                if operation_id.0 == [0u8; 16] {
                    return Err(ChangeError::Encoding(
                        "recursive operation id is the reserved all-zero value".into(),
                    ));
                }
                let part_index = r.u32()?;
                let part_count = r.u32()?;
                if part_count == 0 || part_index >= part_count {
                    return Err(ChangeError::Encoding(format!(
                        "recursive part {part_index} of {part_count} is out of range"
                    )));
                }
                Some(RecursivePart { operation_id, part_index, part_count })
            }
            other => {
                return Err(ChangeError::Encoding(format!(
                    "unknown recursive-part discriminant {other}"
                )))
            }
        };
        let body_digest = r.array32()?;
        Ok(Self { group_id, author, seq, prev, recursive_part, body_digest })
    }
}

fn decode_head_ref(r: &mut Reader<'_>, what: &str) -> Result<HeadRef, ChangeError> {
    let author = decode_author_id(r)?;
    let seq = AuthorSeq(r.u64()?);
    if !(AuthorSeq::FIRST..=AuthorSeq::MAX).contains(&seq) {
        return Err(ChangeError::Encoding(format!(
            "{what} names author sequence {seq}, outside the legitimate range [{}, {}]",
            AuthorSeq::FIRST,
            AuthorSeq::MAX
        )));
    }
    let provenance = DeltaHash(r.array32()?);
    Ok(HeadRef { dot: Dot { author, seq }, provenance })
}

fn decode_ops(r: &mut Reader<'_>) -> Result<Vec<DeltaOp>, ChangeError> {
    let op_count = r.bounded_count(4, MAX_OPS)?;
    if op_count == 0 {
        return Err(ChangeError::Malformed("delta carries no ops".into()));
    }
    let mut ops = Vec::with_capacity(op_count);
    let mut seen_paths = std::collections::BTreeSet::new();
    for _ in 0..op_count {
        let path_str = r.string()?;
        crate::local_op::validate_path(&path_str)?;
        // Two ops at the same path would be merged downstream (installation
        // keys ops by path), letting a sender split what one op may carry
        // into several that add up to something no single op could.
        if !seen_paths.insert(path_str.clone()) {
            return Err(ChangeError::Malformed(format!(
                "delta names path {path_str:?} in more than one op"
            )));
        }
        let path = SyncPath(path_str);
        let removes_count = r.bounded_count(60, MAX_REMOVES_PER_OP)?;
        let mut removes = Vec::with_capacity(removes_count);
        for _ in 0..removes_count {
            removes.push(decode_head_ref(r, "removal")?);
        }
        let put = match r.u8()? {
            0 => None,
            1 => Some(DeltaPut { version: VersionHash(r.array32()?) }),
            other => {
                return Err(ChangeError::Encoding(format!(
                    "unknown put-presence discriminant {other}"
                )))
            }
        };
        ops.push(DeltaOp { path, removes, put });
    }
    Ok(ops)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_protocol::NATIVE_PROTOCOL_GENERATION;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn author_id(device: &str, incarnation: u8) -> AuthorId {
        AuthorId { device: DeviceId(device.into()), incarnation: IncarnationId([incarnation; 16]) }
    }

    fn sample() -> NativeDelta {
        let mut delta = NativeDelta {
            recursive_part: None,
            group_id: FolderGroupId("g1".into()),
            author: author_id("device-a", 1),
            seq: AuthorSeq(2),
            prev: Some(DeltaHash([9u8; 32])),
            ops: vec![DeltaOp {
                path: SyncPath("x".into()),
                removes: vec![HeadRef {
                    dot: Dot { author: author_id("device-b", 1), seq: AuthorSeq(1) },
                    provenance: DeltaHash([1u8; 32]),
                }],
                put: Some(DeltaPut { version: VersionHash([5u8; 32]) }),
            }],
            signature: [0u8; 64],
        };
        delta.sign(&signing_key());
        delta
    }

    #[test]
    fn decode_rejects_a_zero_delta_seq() {
        let mut delta = sample();
        delta.seq = AuthorSeq(0);
        delta.sign(&signing_key());
        let bytes = delta.to_wire_bytes();
        assert!(
            NativeDelta::from_wire_bytes(&bytes).is_err(),
            "seq=0 must be rejected at decode, not merely handled deeper in the pipeline"
        );
    }

    #[test]
    fn decode_rejects_a_removal_naming_a_zero_seq_dot() {
        let mut delta = sample();
        delta.ops[0].removes[0].dot.seq = AuthorSeq(0);
        delta.sign(&signing_key());
        let bytes = delta.to_wire_bytes();
        assert!(
            NativeDelta::from_wire_bytes(&bytes).is_err(),
            "a removal naming seq=0 must be rejected at decode"
        );
    }

    #[test]
    fn decode_rejects_every_structurally_invalid_path_shape_validate_path_rejects() {
        let bad_paths =
            ["", "/absolute", "../escape", "a/../b", "a//b", "a\\b", "a\0b", ".yadorilink-root"];
        for bad in bad_paths {
            let mut delta = sample();
            delta.ops[0].path = SyncPath(bad.into());
            delta.sign(&signing_key());
            let bytes = delta.to_wire_bytes();
            assert!(
                NativeDelta::from_wire_bytes(&bytes).is_err(),
                "path {bad:?} must be rejected at decode via validate_path"
            );
        }
    }

    #[test]
    fn decode_accepts_an_ordinary_valid_path() {
        let delta = sample();
        let bytes = delta.to_wire_bytes();
        assert!(NativeDelta::from_wire_bytes(&bytes).is_ok());
    }

    #[test]
    fn decode_rejects_a_delta_with_no_ops() {
        let mut delta = sample();
        delta.ops.clear();
        delta.sign(&signing_key());
        let bytes = delta.to_wire_bytes();
        assert!(
            NativeDelta::from_wire_bytes(&bytes).is_err(),
            "a delta with zero ops must be rejected at decode: no genuine no-op/keepalive use case \
             was found for NativeDelta, and NativeState::author already refuses an empty local edit \
             the same way (AuthorError::Empty)"
        );
    }

    #[test]
    fn decode_rejects_two_ops_naming_the_same_path() {
        let mut delta = sample();
        let second = delta.ops[0].clone();
        delta.ops.push(second);
        delta.sign(&signing_key());
        let bytes = delta.to_wire_bytes();
        assert!(
            NativeDelta::from_wire_bytes(&bytes).is_err(),
            "two ops at the same path would be merged downstream by path -- must be rejected at decode"
        );
    }

    #[test]
    fn decode_accepts_ops_at_genuinely_different_paths() {
        let mut delta = sample();
        let mut second = delta.ops[0].clone();
        second.path = SyncPath("y".into());
        delta.ops.push(second);
        delta.sign(&signing_key());
        let bytes = delta.to_wire_bytes();
        assert!(NativeDelta::from_wire_bytes(&bytes).is_ok());
    }

    #[test]
    fn wire_round_trips() {
        let delta = sample();
        let bytes = delta.to_wire_bytes();
        let decoded = NativeDelta::from_wire_bytes(&bytes).unwrap();
        assert_eq!(decoded, delta);
        assert_eq!(decoded.delta_hash(), delta.delta_hash());
    }

    #[test]
    fn delta_encoding_has_no_rank_field() {
        let mut delta = sample();
        delta.ops[0].removes.clear();
        // ops count, path, removes count, put flag, version.
        let expected = 4 + (4 + 1) + 4 + 1 + 32;
        assert_eq!(delta.body_encoding().len(), expected);
    }

    #[test]
    fn signature_verifies_against_the_signing_key() {
        let delta = sample();
        let public_key = signing_key().verifying_key();
        delta.verify_signature(&public_key).unwrap();
    }

    #[test]
    fn tampered_body_is_refused_before_signature_check() {
        let delta = sample();
        let mut bytes = delta.to_wire_bytes();
        // Flip the last byte of `put.version`, so the count/shape prefixes all
        // still parse and only the digest check catches the tamper.
        let target = bytes.len() - 1;
        bytes[target] ^= 0xff;
        let err = NativeDelta::from_wire_bytes(&bytes).unwrap_err();
        assert_eq!(err, ChangeError::HashMismatch);
    }

    #[test]
    fn wrong_key_fails_signature_verification() {
        let delta = sample();
        let other_key = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        assert_eq!(delta.verify_signature(&other_key), Err(ChangeError::BadSignature));
    }

    #[test]
    fn foreign_generation_tag_is_refused() {
        let delta = sample();
        let mut bytes = delta.to_wire_bytes();
        bytes[7] = 0xff; // corrupt the generation byte of the domain tag
        let err = NativeDelta::from_wire_bytes(&bytes).unwrap_err();
        assert_eq!(
            err,
            ChangeError::UnsupportedGeneration { theirs: 0xff, ours: NATIVE_PROTOCOL_GENERATION }
        );
    }

    fn resigned(mut delta: NativeDelta) -> NativeDelta {
        delta.sign(&signing_key());
        delta
    }

    #[test]
    fn the_previous_delta_generation_is_refused_outright() {
        let delta = sample();
        let mut bytes = delta.to_wire_bytes();
        bytes[7] = NATIVE_PROTOCOL_GENERATION - 1;
        let err = NativeDelta::from_wire_bytes(&bytes).unwrap_err();
        assert_eq!(
            err,
            ChangeError::UnsupportedGeneration {
                theirs: NATIVE_PROTOCOL_GENERATION - 1,
                ours: NATIVE_PROTOCOL_GENERATION
            }
        );
    }

    #[test]
    fn the_previous_header_generation_is_refused_outright() {
        let mut bytes = sample().to_wire_bytes();
        // The header's own domain tag follows the wire tag.
        assert_eq!(&bytes[8..15], &NATIVE_DELTA_HEADER_DOMAIN_TAG[..7]);
        bytes[15] = NATIVE_PROTOCOL_GENERATION - 1;
        let err = NativeDelta::from_wire_bytes(&bytes).unwrap_err();
        assert_eq!(
            err,
            ChangeError::UnsupportedGeneration {
                theirs: NATIVE_PROTOCOL_GENERATION - 1,
                ours: NATIVE_PROTOCOL_GENERATION
            }
        );
    }

    /// A body digest taken under the previous body tag is not the digest of the
    /// same ops now, and a delta whose header commits to it is refused.
    #[test]
    fn a_header_committing_to_a_digest_under_the_previous_body_tag_is_refused() {
        let delta = resigned(sample());
        let mut previous = Sha256::new();
        previous.update(b"YLNKndB");
        previous.update([NATIVE_PROTOCOL_GENERATION - 1]);
        previous.update(delta.body_encoding());
        let previous: [u8; 32] = previous.finalize().into();
        assert_ne!(previous, delta.body_digest());

        let bytes = delta.to_wire_bytes();
        let current = delta.body_digest();
        let at = bytes.windows(32).position(|window| window == current).expect("in the header");
        let mut stale = bytes.clone();
        stale[at..at + 32].copy_from_slice(&previous);
        assert!(NativeDelta::from_wire_bytes(&stale).is_err());
    }

    /// The canonical body of one fixed delta, byte for byte. A change to how any field is encoded changes these bytes, which
    /// must come with a new generation tag.
    #[test]
    fn the_body_encoding_and_digest_are_pinned() {
        let delta = sample();
        assert_eq!(
            hex::encode(delta.body_encoding()),
            concat!(
                "00000001000000017800000001000000086465766963652d6201010101010101",
                "0101010101010101010000000000000001010101010101010101010101010101",
                "0101010101010101010101010101010101010505050505050505050505050505",
                "050505050505050505050505050505050505"
            )
        );
        assert_eq!(
            hex::encode(delta.body_digest()),
            "9a3e5b9be4a47869b19b0ac4e59c9b9db5d1c55ae00a3d619b5cd43e51b7ee43"
        );
    }

    fn part(index: u32, count: u32) -> RecursivePart {
        RecursivePart {
            operation_id: crate::recursive_operation::RecursiveOperationId([4u8; 16]),
            part_index: index,
            part_count: count,
        }
    }

    #[test]
    fn a_recursive_part_round_trips_and_is_covered_by_the_delta_identity() {
        let mut delta = sample();
        delta.recursive_part = Some(part(1, 3));
        delta.sign(&signing_key());
        let decoded = NativeDelta::from_wire_bytes(&delta.to_wire_bytes()).unwrap();
        assert_eq!(decoded, delta);
        decoded.verify_signature(&signing_key().verifying_key()).unwrap();

        let mut other_index = delta.clone();
        other_index.recursive_part = Some(part(2, 3));
        let mut untagged = delta.clone();
        untagged.recursive_part = None;
        assert_ne!(other_index.delta_hash(), delta.delta_hash());
        assert_ne!(untagged.delta_hash(), delta.delta_hash());
    }

    #[test]
    fn a_recursive_part_outside_its_count_is_refused() {
        for bad in [part(3, 3), part(0, 0)] {
            let mut delta = sample();
            delta.recursive_part = Some(bad);
            delta.sign(&signing_key());
            assert!(
                NativeDelta::from_wire_bytes(&delta.to_wire_bytes()).is_err(),
                "{bad:?} must not decode"
            );
        }
    }

    /// The all-zero id is reserved so an unset id cannot pass for a real one.
    #[test]
    fn a_recursive_part_with_the_reserved_zero_operation_id_is_refused() {
        let mut delta = sample();
        delta.recursive_part = Some(RecursivePart {
            operation_id: crate::recursive_operation::RecursiveOperationId([0u8; 16]),
            part_index: 0,
            part_count: 1,
        });
        delta.sign(&signing_key());
        assert!(NativeDelta::from_wire_bytes(&delta.to_wire_bytes()).is_err());
    }

    #[test]
    fn dot_reflects_author_and_seq() {
        let delta = sample();
        assert_eq!(delta.dot(), Dot { author: author_id("device-a", 1), seq: AuthorSeq(2) });
    }
}
