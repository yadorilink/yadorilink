#![cfg(test)]

use ed25519_dalek::SigningKey;

use super::*;
use crate::author::{AuthorId, IncarnationId};
use crate::authorization_checkpoint::{
    build_merkle_proof, canonical_signing_bytes, fingerprint_signing_key, merkle_root,
    sign_checkpoint,
};
use crate::ids::{AuthorSeq, DeviceId, FolderGroupId, SyncPath, VersionHash};
use crate::signed_delta::DeltaPut;

const GROUP: &str = "g";
const DEVICE: &str = "device-A";

fn author_key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

fn authority() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn signed_delta(group: &str, device: &str) -> NativeDelta {
    let mut d = NativeDelta {
        recursive_part: None,
        group_id: FolderGroupId(group.into()),
        author: AuthorId { device: DeviceId(device.into()), incarnation: IncarnationId([1u8; 16]) },
        seq: AuthorSeq(1),
        prev: None,
        ops: vec![crate::signed_delta::DeltaOp {
            path: SyncPath("a.txt".into()),
            removes: Vec::new(),
            put: Some(DeltaPut { version: VersionHash([1u8; 32]) }),
        }],
        signature: [0u8; 64],
    };
    d.sign(&author_key());
    d
}

/// Everything an honest sender would produce for `delta`.
struct Carried {
    encoded_delta: Vec<u8>,
    checkpoint_hash: [u8; 32],
    checkpoint_encoded: Vec<u8>,
    signature: [u8; 64],
    author_public_key: [u8; 32],
    proof: MerkleProof,
}

impl Carried {
    fn as_input(&self) -> ProofCarryingDelta<'_> {
        ProofCarryingDelta {
            encoded_delta: &self.encoded_delta,
            checkpoint_hash: &self.checkpoint_hash,
            checkpoint_encoded: &self.checkpoint_encoded,
            checkpoint_signature: &self.signature,
            author_signing_public_key: &self.author_public_key,
            proof: &self.proof,
        }
    }
}

fn carry(delta: &NativeDelta, checkpoint_group: &str, checkpoint_device: &str) -> Carried {
    let leaves = vec![delta.delta_hash().0];
    let checkpoint = AuthorizationCheckpoint {
        group_id: checkpoint_group.to_string(),
        device_id: checkpoint_device.to_string(),
        signing_key_fingerprint: fingerprint_signing_key(&author_key().verifying_key()),
        merkle_root: merkle_root(&leaves),
        leaf_count: 1,
        checkpoint_seq: 1,
        signer_key_id: fingerprint_signing_key(&authority().verifying_key()),
        policy_epoch: 0,
        policy_seq: 1,
        policy_head: [0u8; 32],
        issued_at_unix: 1,
    };
    let signature = sign_checkpoint(&checkpoint, &authority());
    let checkpoint_encoded = canonical_signing_bytes(&checkpoint);
    Carried {
        encoded_delta: delta.to_wire_bytes(),
        checkpoint_hash: crate::authorization_checkpoint::checkpoint_hash(
            &checkpoint_encoded,
            &signature,
        ),
        checkpoint_encoded,
        signature,
        author_public_key: author_key().verifying_key().to_bytes(),
        proof: build_merkle_proof(&leaves, 0),
    }
}

fn honest() -> Carried {
    carry(&signed_delta(GROUP, DEVICE), GROUP, DEVICE)
}

fn resolve_real(key_id: &[u8; 32], _head: &[u8; 32]) -> Option<ed25519_dalek::VerifyingKey> {
    let authority = authority().verifying_key();
    (*key_id == fingerprint_signing_key(&authority)).then_some(authority)
}

fn verify(carried: &Carried) -> Result<VerifiedDelta, DeltaProofVerificationError> {
    verify_proof_carrying_delta(&carried.as_input(), GROUP, resolve_real)
}

#[test]
fn an_honest_proof_carrying_delta_verifies() {
    let carried = honest();
    let verified = verify(&carried).expect("honest input must verify");
    assert_eq!(verified.delta_hash, verified.delta.delta_hash());
    assert_eq!(verified.checkpoint.checkpoint_seq, 1);
}

/// No parameter here names who delivered the delta, so acceptance cannot
/// depend on delivery order: verifying the identical bytes twice, as two
/// different receive paths (or a re-delivery) would, gives the identical
/// answer.
#[test]
fn the_same_bytes_verify_identically_however_they_arrived() {
    let carried = honest();
    let first = verify(&carried).unwrap();
    let second = verify(&carried).unwrap();
    assert_eq!(first.delta_hash, second.delta_hash);
    assert_eq!(first.checkpoint, second.checkpoint);
}

#[test]
fn a_delta_for_another_group_is_refused() {
    let carried = carry(&signed_delta("other", DEVICE), "other", DEVICE);
    assert!(matches!(
        verify_proof_carrying_delta(&carried.as_input(), GROUP, resolve_real),
        Err(DeltaProofVerificationError::GroupMismatch { .. })
    ));
}

#[test]
fn a_checkpoint_naming_another_group_than_the_delta_is_refused() {
    let delta = signed_delta(GROUP, DEVICE);
    let carried = carry(&delta, "other", DEVICE);
    assert!(matches!(
        verify(&carried),
        Err(DeltaProofVerificationError::CheckpointGroupMismatch { .. })
    ));
}

#[test]
fn a_checkpoint_naming_another_device_than_the_author_is_refused() {
    let delta = signed_delta(GROUP, DEVICE);
    let carried = carry(&delta, GROUP, "device-Z");
    assert!(matches!(
        verify(&carried),
        Err(DeltaProofVerificationError::CheckpointDeviceMismatch { .. })
    ));
}

/// The envelope is bound to its hash before it is decoded any further, so
/// no decode ever runs on bytes nothing has vouched for.
#[test]
fn an_envelope_that_does_not_match_its_claimed_hash_is_refused_before_decoding() {
    let mut carried = honest();
    carried.checkpoint_hash[0] ^= 0xFF;
    assert!(matches!(verify(&carried), Err(DeltaProofVerificationError::CheckpointHashMismatch)));

    let mut carried = honest();
    carried.checkpoint_encoded.push(0);
    assert!(matches!(verify(&carried), Err(DeltaProofVerificationError::CheckpointHashMismatch)));
}

#[test]
fn a_delta_signed_by_a_different_key_than_the_checkpoint_vouches_for_is_refused() {
    let mut carried = honest();
    carried.author_public_key = SigningKey::from_bytes(&[3u8; 32]).verifying_key().to_bytes();
    assert!(matches!(verify(&carried), Err(DeltaProofVerificationError::BadDeltaSignature(_))));
}

/// The fixed invariant: a delta legitimately published before a revoke
/// stays valid regardless of when it arrives, but a checkpoint whose
/// signer key the verifier's OWN policy chain no longer recognizes (the
/// key was rotated/revoked by `policy_head`) is refused -- modeled here by
/// `resolve_authority_key` returning `None`, exactly as
/// `verify_change_admission`'s own doc explains a stale/rotated-out key
/// resolves.
#[test]
fn a_checkpoint_signed_by_a_key_the_policy_chain_no_longer_recognizes_is_refused() {
    let carried = honest();
    assert!(matches!(
        verify_proof_carrying_delta(&carried.as_input(), GROUP, |_, _| None),
        Err(DeltaProofVerificationError::NotAdmissible(
            CheckpointAdmissionError::UnknownOrInvalidSignerKey
        ))
    ));
}

#[test]
fn a_proof_for_a_different_delta_is_refused() {
    let mut carried = honest();
    let other = carry(&signed_delta(GROUP, DEVICE), GROUP, DEVICE);
    carried.proof = build_merkle_proof(&[[0xAB; 32], other.checkpoint_hash], 0);
    assert!(matches!(verify(&carried), Err(DeltaProofVerificationError::NotAdmissible(_))));
}

#[test]
fn undecodable_delta_bytes_are_refused() {
    let mut carried = honest();
    carried.encoded_delta = vec![0u8; 4];
    assert!(matches!(verify(&carried), Err(DeltaProofVerificationError::UndecodableDelta(_))));
}
