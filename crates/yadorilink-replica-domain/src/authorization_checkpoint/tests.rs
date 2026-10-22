#![cfg(test)]

use super::*;
use ed25519_dalek::SigningKey;
use std::sync::atomic::{AtomicU8, Ordering as AtomicOrdering};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn decode_checkpoint_round_trips_canonical_signing_bytes() {
    let checkpoint = AuthorizationCheckpoint {
        group_id: "group-1".to_string(),
        device_id: "device-A".to_string(),
        signing_key_fingerprint: [1u8; 32],
        merkle_root: [2u8; 32],
        leaf_count: 7,
        checkpoint_seq: 42,
        signer_key_id: [3u8; 32],
        policy_epoch: 5,
        policy_seq: 9,
        policy_head: [4u8; 32],
        issued_at_unix: 1_700_000_000,
    };
    let encoded = canonical_signing_bytes(&checkpoint);
    let decoded = decode_checkpoint(&encoded).unwrap();
    assert_eq!(decoded, checkpoint);
}

#[test]
fn decode_checkpoint_rejects_a_bad_domain_tag() {
    let bytes = vec![0u8; 100];
    assert_eq!(decode_checkpoint(&bytes), Err(CheckpointDecodeError::BadDomainTag));
}

#[test]
fn decode_checkpoint_rejects_truncated_bytes() {
    let checkpoint = AuthorizationCheckpoint {
        group_id: "g".to_string(),
        device_id: "d".to_string(),
        signing_key_fingerprint: [0u8; 32],
        merkle_root: [0u8; 32],
        leaf_count: 1,
        checkpoint_seq: 1,
        signer_key_id: [0u8; 32],
        policy_epoch: 0,
        policy_seq: 1,
        policy_head: [0u8; 32],
        issued_at_unix: 1,
    };
    let mut encoded = canonical_signing_bytes(&checkpoint);
    encoded.truncate(encoded.len() - 1);
    assert_eq!(decode_checkpoint(&encoded), Err(CheckpointDecodeError::Truncated));
}

#[test]
fn decode_checkpoint_rejects_trailing_bytes() {
    let checkpoint = AuthorizationCheckpoint {
        group_id: "g".to_string(),
        device_id: "d".to_string(),
        signing_key_fingerprint: [0u8; 32],
        merkle_root: [0u8; 32],
        leaf_count: 1,
        checkpoint_seq: 1,
        signer_key_id: [0u8; 32],
        policy_epoch: 0,
        policy_seq: 1,
        policy_head: [0u8; 32],
        issued_at_unix: 1,
    };
    let mut encoded = canonical_signing_bytes(&checkpoint);
    encoded.push(0xFF);
    assert_eq!(decode_checkpoint(&encoded), Err(CheckpointDecodeError::TrailingBytes));
}

/// Cross-implementation golden vector for `canonical_signing_bytes` AND
/// the resulting Ed25519 signature -- the actual contract the coordination
/// Worker's TypeScript `checkpoint.ts::canonicalSigningBytes`/`signDecision`
/// must reproduce bit-for-bit. See
/// the coordination service for
/// the TS side of this SAME vector; a mismatch on either the byte
/// layout or the signature means Rust's `verify_change_admission`
/// would reject every checkpoint the Worker ever issues.
///
/// Ed25519 signing is deterministic (RFC 8032 -- no random nonce), so
/// the SAME 32-byte seed signing the SAME message bytes must produce
/// the SAME signature in any correct implementation, Web Crypto
/// included; this is what makes a hardcoded golden signature a valid
/// cross-language check rather than merely a self-consistency one.
#[test]
fn checkpoint_signing_golden_vector() {
    let seed = [1u8; 32];
    let authority_sk = SigningKey::from_bytes(&seed);

    let checkpoint = AuthorizationCheckpoint {
        group_id: "g".to_string(),
        device_id: "d".to_string(),
        signing_key_fingerprint: [0u8; 32],
        merkle_root: [0u8; 32],
        leaf_count: 1,
        checkpoint_seq: 1,
        signer_key_id: [0u8; 32],
        policy_epoch: 0,
        policy_seq: 1,
        policy_head: [0u8; 32],
        issued_at_unix: 1,
    };

    let bytes = canonical_signing_bytes(&checkpoint);
    let expected_bytes = concat!(
        "796c63686b707431", // "ylchkpt1"
        "0000000000000001",
        "67", // len=1, "g"
        "0000000000000001",
        "64",                                                               // len=1, "d"
        "0000000000000000000000000000000000000000000000000000000000000000", // fingerprint (32)
        "0000000000000000000000000000000000000000000000000000000000000000", // merkle_root (32)
        "0000000000000001",                                                 // leaf_count=1
        "0000000000000001",                                                 // checkpoint_seq=1
        "0000000000000000000000000000000000000000000000000000000000000000", // signer_key_id (32)
        "0000000000000000",                                                 // policy_epoch=0
        "0000000000000001",                                                 // policy_seq=1
        "0000000000000000000000000000000000000000000000000000000000000000", // policy_head (32)
        "0000000000000001",                                                 // issued_at_unix=1
    );
    assert_eq!(
        hex(&bytes),
        expected_bytes,
        "canonical_signing_bytes must stay byte-identical to the cross-implementation \
         golden vector in the coordination service"
    );

    let signature = sign_checkpoint(&checkpoint, &authority_sk);
    let expected_signature = "\
        d783b2ca3cd02733df18294570524bc1ed5b4f8ebfed87858306dfd867a3675\
        364b4d3dc7a312b2f62a7ee0e34ef00e6a85c4fc35cac7eb927298e1c9e4ed2\
        01";
    assert_eq!(
        hex(&signature),
        expected_signature.replace(['\n', ' '], ""),
        "the seed [1u8; 32] signing this exact message must produce this exact \
         signature -- Ed25519 is deterministic, so ANY correct implementation \
         (Web Crypto included) signing the same bytes with the same seed must \
         match. If this fails, either canonical_signing_bytes changed (caught by \
         the assertion above already) or ed25519_dalek's signing changed -- \
         either way, treat as a break, never update this constant to match."
    );
}

fn next_seed() -> [u8; 32] {
    static COUNTER: AtomicU8 = AtomicU8::new(1);
    let n = COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
    let mut seed = [0u8; 32];
    seed[0] = n;
    seed[31] = n.wrapping_mul(31).wrapping_add(7);
    seed
}

fn keypair() -> (SigningKey, VerifyingKey) {
    let sk = SigningKey::from_bytes(&next_seed());
    let vk = sk.verifying_key();
    (sk, vk)
}

fn device_keypair() -> (SigningKey, VerifyingKey) {
    keypair()
}

fn change_hash(tag: u8) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0] = tag;
    h
}

fn base_checkpoint(
    fp: [u8; 32],
    signer_key_id: [u8; 32],
    root: [u8; 32],
    leaf_count: usize,
) -> AuthorizationCheckpoint {
    AuthorizationCheckpoint {
        group_id: "group-1".to_string(),
        device_id: "device-A".to_string(),
        signing_key_fingerprint: fp,
        merkle_root: root,
        leaf_count: leaf_count as u64,
        checkpoint_seq: 1,
        signer_key_id,
        policy_epoch: 3,
        policy_seq: 7,
        policy_head: [9u8; 32],
        issued_at_unix: 1_000,
    }
}

/// A resolver that recognizes exactly one (signer_key_id, key) pair as
/// valid at any policy_head -- stands in for a real verified policy
/// chain lookup in these unit tests, which don't exercise chain
/// verification itself (that's `change_policy.rs`'s job).
fn single_key_resolver(
    known_key_id: [u8; 32],
    known_key: VerifyingKey,
) -> impl FnOnce(&[u8; 32], &[u8; 32]) -> Option<VerifyingKey> {
    move |key_id, _policy_head| (*key_id == known_key_id).then_some(known_key)
}

#[test]
fn a_change_included_in_a_signed_checkpoints_batch_is_admitted() {
    let (authority_sk, authority_vk) = keypair();
    let key_id = fingerprint_signing_key(&authority_vk);
    let (_, device_vk) = device_keypair();
    let fp = fingerprint_signing_key(&device_vk);
    let hashes = vec![change_hash(1), change_hash(2), change_hash(3)];
    let root = merkle_root(&hashes);
    let checkpoint = base_checkpoint(fp, key_id, root, hashes.len());
    let sig = sign_checkpoint(&checkpoint, &authority_sk);
    let proof = build_merkle_proof(&hashes, 1);

    let result = verify_change_admission(
        "group-1",
        "device-A",
        &device_vk,
        hashes[1],
        &proof,
        &checkpoint,
        &sig,
        single_key_resolver(key_id, authority_vk),
    );
    assert_eq!(result, Ok(()));
}

#[test]
fn every_change_in_an_odd_sized_batch_verifies() {
    // Exercises the odd-level duplication padding rule for all
    // positions, including the duplicated final leaf.
    let (authority_sk, authority_vk) = keypair();
    let key_id = fingerprint_signing_key(&authority_vk);
    let (_, device_vk) = device_keypair();
    let fp = fingerprint_signing_key(&device_vk);
    let hashes: Vec<[u8; 32]> = (1..=5).map(change_hash).collect();
    let root = merkle_root(&hashes);
    let checkpoint = base_checkpoint(fp, key_id, root, hashes.len());
    let sig = sign_checkpoint(&checkpoint, &authority_sk);

    for (i, h) in hashes.iter().enumerate() {
        let proof = build_merkle_proof(&hashes, i);
        let result = verify_change_admission(
            "group-1",
            "device-A",
            &device_vk,
            *h,
            &proof,
            &checkpoint,
            &sig,
            single_key_resolver(key_id, authority_vk),
        );
        assert_eq!(result, Ok(()), "leaf {i} failed to verify");
    }
}

#[test]
fn a_change_never_included_in_any_checkpointed_batch_cannot_be_admitted() {
    // There is no field an author can set to make an uncheckpointed
    // Change admissible. Constructing ANY proof for a hash that was
    // never in the authority's batch fails to reconstruct the signed
    // root.
    let (authority_sk, authority_vk) = keypair();
    let key_id = fingerprint_signing_key(&authority_vk);
    let (_, device_vk) = device_keypair();
    let fp = fingerprint_signing_key(&device_vk);
    let hashes = vec![change_hash(1), change_hash(2)];
    let root = merkle_root(&hashes);
    let checkpoint = base_checkpoint(fp, key_id, root, hashes.len());
    let sig = sign_checkpoint(&checkpoint, &authority_sk);

    // Attacker reuses a real proof shape but substitutes a Change hash
    // the authority never saw (e.g. authored after revocation, never
    // submitted for checkpointing).
    let forged_change = change_hash(99);
    let proof = build_merkle_proof(&hashes, 0);
    let result = verify_change_admission(
        "group-1",
        "device-A",
        &device_vk,
        forged_change,
        &proof,
        &checkpoint,
        &sig,
        single_key_resolver(key_id, authority_vk),
    );
    assert_eq!(result, Err(CheckpointAdmissionError::MerkleProofDoesNotMatchCheckpoint));
}

#[test]
fn a_tampered_merkle_root_fails_signature_verification() {
    let (authority_sk, authority_vk) = keypair();
    let key_id = fingerprint_signing_key(&authority_vk);
    let (_, device_vk) = device_keypair();
    let fp = fingerprint_signing_key(&device_vk);
    let hashes = vec![change_hash(1), change_hash(2)];
    let root = merkle_root(&hashes);
    let checkpoint = base_checkpoint(fp, key_id, root, hashes.len());
    let sig = sign_checkpoint(&checkpoint, &authority_sk);

    // A relay (or anyone) tries to splice in a different batch's root
    // under an already-issued signature.
    let mut tampered = checkpoint.clone();
    tampered.merkle_root = merkle_root(&[change_hash(1), change_hash(99)]);
    let proof = build_merkle_proof(&[change_hash(1), change_hash(99)], 1);

    let result = verify_change_admission(
        "group-1",
        "device-A",
        &device_vk,
        change_hash(99),
        &proof,
        &tampered,
        &sig,
        single_key_resolver(key_id, authority_vk),
    );
    assert_eq!(result, Err(CheckpointAdmissionError::BadCheckpointSignature));
}

#[test]
fn a_checkpoint_for_a_different_group_does_not_admit_this_change() {
    let (authority_sk, authority_vk) = keypair();
    let key_id = fingerprint_signing_key(&authority_vk);
    let (_, device_vk) = device_keypair();
    let fp = fingerprint_signing_key(&device_vk);
    let hashes = vec![change_hash(1)];
    let root = merkle_root(&hashes);
    let checkpoint = base_checkpoint(fp, key_id, root, hashes.len());
    let sig = sign_checkpoint(&checkpoint, &authority_sk);
    let proof = build_merkle_proof(&hashes, 0);

    let result = verify_change_admission(
        "group-2",
        "device-A",
        &device_vk,
        hashes[0],
        &proof,
        &checkpoint,
        &sig,
        single_key_resolver(key_id, authority_vk),
    );
    assert_eq!(result, Err(CheckpointAdmissionError::GroupMismatch));
}

#[test]
fn a_checkpoint_issued_to_a_different_device_does_not_admit_this_change() {
    let (authority_sk, authority_vk) = keypair();
    let key_id = fingerprint_signing_key(&authority_vk);
    let (_, device_vk) = device_keypair();
    let fp = fingerprint_signing_key(&device_vk);
    let hashes = vec![change_hash(1)];
    let root = merkle_root(&hashes);
    let checkpoint = base_checkpoint(fp, key_id, root, hashes.len());
    let sig = sign_checkpoint(&checkpoint, &authority_sk);
    let proof = build_merkle_proof(&hashes, 0);

    let result = verify_change_admission(
        "group-1",
        "device-B",
        &device_vk,
        hashes[0],
        &proof,
        &checkpoint,
        &sig,
        single_key_resolver(key_id, authority_vk),
    );
    assert_eq!(result, Err(CheckpointAdmissionError::DeviceMismatch));
}

#[test]
fn a_rotated_signing_key_invalidates_a_checkpoint_issued_to_the_old_key() {
    let (authority_sk, authority_vk) = keypair();
    let key_id = fingerprint_signing_key(&authority_vk);
    let (_, old_device_vk) = device_keypair();
    let old_fp = fingerprint_signing_key(&old_device_vk);
    let hashes = vec![change_hash(1)];
    let root = merkle_root(&hashes);
    let checkpoint = base_checkpoint(old_fp, key_id, root, hashes.len());
    let sig = sign_checkpoint(&checkpoint, &authority_sk);
    let proof = build_merkle_proof(&hashes, 0);

    let (_, new_device_vk) = device_keypair();
    let result = verify_change_admission(
        "group-1",
        "device-A",
        &new_device_vk,
        hashes[0],
        &proof,
        &checkpoint,
        &sig,
        single_key_resolver(key_id, authority_vk),
    );
    assert_eq!(result, Err(CheckpointAdmissionError::SigningKeyFingerprintMismatch));
}

#[test]
fn a_carried_key_that_does_not_hash_to_the_checkpoints_fingerprint_is_rejected() {
    // Proves the self-contained-verification binding: a
    // receiver with NO local pin for this device at all must still
    // reject a mismatched carried key, purely from the checkpoint's
    // own signed fingerprint.
    let (authority_sk, authority_vk) = keypair();
    let key_id = fingerprint_signing_key(&authority_vk);
    let (_, real_device_vk) = device_keypair();
    let real_fp = fingerprint_signing_key(&real_device_vk);
    let hashes = vec![change_hash(1)];
    let root = merkle_root(&hashes);
    let checkpoint = base_checkpoint(real_fp, key_id, root, hashes.len());
    let sig = sign_checkpoint(&checkpoint, &authority_sk);
    let proof = build_merkle_proof(&hashes, 0);

    // An attacker substitutes a DIFFERENT public key alongside the
    // same checkpoint/proof, hoping the verifier has no pinned key to
    // catch the swap.
    let (_, attacker_vk) = device_keypair();
    let result = verify_change_admission(
        "group-1",
        "device-A",
        &attacker_vk,
        hashes[0],
        &proof,
        &checkpoint,
        &sig,
        single_key_resolver(key_id, authority_vk),
    );
    assert_eq!(result, Err(CheckpointAdmissionError::SigningKeyFingerprintMismatch));
}

#[test]
fn an_authority_signature_from_the_wrong_key_never_verifies() {
    let (_, authority_vk) = keypair();
    let key_id = fingerprint_signing_key(&authority_vk);
    let (wrong_sk, _) = keypair();
    let (_, device_vk) = device_keypair();
    let fp = fingerprint_signing_key(&device_vk);
    let hashes = vec![change_hash(1)];
    let root = merkle_root(&hashes);
    let checkpoint = base_checkpoint(fp, key_id, root, hashes.len());
    let forged_sig = sign_checkpoint(&checkpoint, &wrong_sk);
    let proof = build_merkle_proof(&hashes, 0);

    let result = verify_change_admission(
        "group-1",
        "device-A",
        &device_vk,
        hashes[0],
        &proof,
        &checkpoint,
        &forged_sig,
        single_key_resolver(key_id, authority_vk),
    );
    assert_eq!(result, Err(CheckpointAdmissionError::BadCheckpointSignature));
}

#[test]
fn a_signer_key_id_the_resolver_does_not_recognize_is_rejected() {
    // The resolver stands in for a verified policy chain lookup; if
    // it says "I have never seen this key as this group's authority
    // key," verification must not fall back to trusting the
    // signature anyway.
    let (authority_sk, authority_vk) = keypair();
    let key_id = fingerprint_signing_key(&authority_vk);
    let (_, device_vk) = device_keypair();
    let fp = fingerprint_signing_key(&device_vk);
    let hashes = vec![change_hash(1)];
    let root = merkle_root(&hashes);
    let checkpoint = base_checkpoint(fp, key_id, root, hashes.len());
    let sig = sign_checkpoint(&checkpoint, &authority_sk);
    let proof = build_merkle_proof(&hashes, 0);

    let result = verify_change_admission(
        "group-1",
        "device-A",
        &device_vk,
        hashes[0],
        &proof,
        &checkpoint,
        &sig,
        |_key_id, _policy_head| None, // "never heard of this key"
    );
    assert_eq!(result, Err(CheckpointAdmissionError::UnknownOrInvalidSignerKey));
}

#[test]
fn a_claimed_signer_key_id_that_does_not_match_the_actual_signing_key_is_rejected() {
    // signer_key_id names key A, the resolver's chain says key A is
    // legitimately the authority key at this policy_head (so
    // UnknownOrInvalidSignerKey does NOT fire) -- but the signature
    // was actually produced by a different key B. This must still
    // fail signature verification, not silently succeed because "a
    // real key was named."
    let (authority_sk_a, authority_vk_a) = keypair();
    let (authority_sk_b, _authority_vk_b) = keypair();
    let key_id_a = fingerprint_signing_key(&authority_vk_a);
    let (_, device_vk) = device_keypair();
    let fp = fingerprint_signing_key(&device_vk);
    let hashes = vec![change_hash(1)];
    let root = merkle_root(&hashes);
    let mut checkpoint = base_checkpoint(fp, key_id_a, root, hashes.len());
    checkpoint.signer_key_id = key_id_a; // claims key A signed this
    let sig = sign_checkpoint(&checkpoint, &authority_sk_b); // but B actually did
    let proof = build_merkle_proof(&hashes, 0);

    let result = verify_change_admission(
        "group-1",
        "device-A",
        &device_vk,
        hashes[0],
        &proof,
        &checkpoint,
        &sig,
        single_key_resolver(key_id_a, authority_vk_a),
    );
    assert_eq!(result, Err(CheckpointAdmissionError::BadCheckpointSignature));
    let _ = authority_sk_a; // used only to prove key A's own signature would have differed
}

#[test]
fn a_proof_built_against_a_different_leaf_count_than_the_checkpoint_committed_to_is_rejected() {
    // Demonstrates the exact ambiguity leaf_count closes: a real
    // 3-leaf batch [a,b,c] pads internally to [a,b,c,c] and produces
    // the SAME root as an actual, distinct 4-leaf batch [a,b,c,c].
    // Without leaf_count in the checkpoint, a proof built against
    // the 4-leaf interpretation would incorrectly verify against a
    // checkpoint that only ever authorized the 3-leaf batch.
    let (authority_sk, authority_vk) = keypair();
    let key_id = fingerprint_signing_key(&authority_vk);
    let (_, device_vk) = device_keypair();
    let fp = fingerprint_signing_key(&device_vk);
    let hashes_3 = vec![change_hash(1), change_hash(2), change_hash(3)];
    let hashes_4 = vec![change_hash(1), change_hash(2), change_hash(3), change_hash(3)];
    assert_eq!(
        merkle_root(&hashes_3),
        merkle_root(&hashes_4),
        "test setup: the padding collision this test exercises must actually exist"
    );

    let checkpoint_for_3 = base_checkpoint(fp, key_id, merkle_root(&hashes_3), hashes_3.len());
    let sig = sign_checkpoint(&checkpoint_for_3, &authority_sk);

    // Proof built against the 4-leaf interpretation for the
    // duplicated leaf at index 3.
    let proof_from_4 = build_merkle_proof(&hashes_4, 3);
    let result = verify_change_admission(
        "group-1",
        "device-A",
        &device_vk,
        hashes_4[3],
        &proof_from_4,
        &checkpoint_for_3,
        &sig,
        single_key_resolver(key_id, authority_vk),
    );
    assert_eq!(result, Err(CheckpointAdmissionError::LeafCountMismatch));
}

#[test]
fn a_leaf_index_at_or_past_leaf_count_is_rejected() {
    let (authority_sk, authority_vk) = keypair();
    let key_id = fingerprint_signing_key(&authority_vk);
    let (_, device_vk) = device_keypair();
    let fp = fingerprint_signing_key(&device_vk);
    let hashes = vec![change_hash(1), change_hash(2)];
    let root = merkle_root(&hashes);
    let checkpoint = base_checkpoint(fp, key_id, root, hashes.len());
    let sig = sign_checkpoint(&checkpoint, &authority_sk);

    let mut proof = build_merkle_proof(&hashes, 1);
    proof.leaf_index = 2; // out of range for leaf_count = 2

    let result = verify_change_admission(
        "group-1",
        "device-A",
        &device_vk,
        hashes[1],
        &proof,
        &checkpoint,
        &sig,
        single_key_resolver(key_id, authority_vk),
    );
    assert_eq!(result, Err(CheckpointAdmissionError::LeafIndexOutOfRange));
}

#[test]
fn a_proof_with_the_wrong_number_of_siblings_for_its_leaf_count_is_rejected() {
    let (authority_sk, authority_vk) = keypair();
    let key_id = fingerprint_signing_key(&authority_vk);
    let (_, device_vk) = device_keypair();
    let fp = fingerprint_signing_key(&device_vk);
    let hashes: Vec<[u8; 32]> = (1..=5).map(change_hash).collect(); // depth 3
    let root = merkle_root(&hashes);
    let checkpoint = base_checkpoint(fp, key_id, root, hashes.len());
    let sig = sign_checkpoint(&checkpoint, &authority_sk);

    let mut proof = build_merkle_proof(&hashes, 0);
    proof.siblings.pop(); // truncate: now inconsistent with leaf_count=5's depth

    let result = verify_change_admission(
        "group-1",
        "device-A",
        &device_vk,
        hashes[0],
        &proof,
        &checkpoint,
        &sig,
        single_key_resolver(key_id, authority_vk),
    );
    assert_eq!(result, Err(CheckpointAdmissionError::ProofDepthMismatch));
}

#[test]
fn revocation_after_a_checkpoint_was_issued_does_not_retroactively_invalidate_it() {
    // Once the authority has signed a checkpoint (meaning it checked
    // writer status at THAT moment and found the device current),
    // every Change it covers is admissible forever afterward,
    // including after a later revocation -- because a LATER
    // revocation cannot un-sign an already-issued checkpoint. What a
    // later revocation actually prevents is the authority issuing the
    // NEXT checkpoint -- see the linearization
    // contract that makes this precise, and
    // `checkpoint_issuance_linearization` below for why a naive
    // read-then-sign issuance protocol does NOT give you this
    // property for free.
    let (authority_sk, authority_vk) = keypair();
    let key_id = fingerprint_signing_key(&authority_vk);
    let (_, device_vk) = device_keypair();
    let fp = fingerprint_signing_key(&device_vk);
    let hashes = vec![change_hash(1)];
    let root = merkle_root(&hashes);
    let checkpoint = base_checkpoint(fp, key_id, root, hashes.len());
    let sig = sign_checkpoint(&checkpoint, &authority_sk);
    let proof = build_merkle_proof(&hashes, 0);

    let result = verify_change_admission(
        "group-1",
        "device-A",
        &device_vk,
        hashes[0],
        &proof,
        &checkpoint,
        &sig,
        single_key_resolver(key_id, authority_vk),
    );
    assert_eq!(result, Ok(()));
}

#[test]
fn checkpoint_hash_changes_if_either_the_checkpoint_or_the_signature_changes() {
    let (authority_sk, authority_vk) = keypair();
    let key_id = fingerprint_signing_key(&authority_vk);
    let (_, device_vk) = device_keypair();
    let fp = fingerprint_signing_key(&device_vk);
    let checkpoint = base_checkpoint(fp, key_id, [1u8; 32], 1);
    let sig = sign_checkpoint(&checkpoint, &authority_sk);
    let encoded = canonical_signing_bytes(&checkpoint);
    let h1 = checkpoint_hash(&encoded, &sig);

    let mut other = checkpoint.clone();
    other.checkpoint_seq = 2;
    let sig2 = sign_checkpoint(&other, &authority_sk);
    let encoded2 = canonical_signing_bytes(&other);
    let h2 = checkpoint_hash(&encoded2, &sig2);
    assert_ne!(h1, h2);

    let mut forged_sig = sig;
    forged_sig[0] ^= 1;
    let h3 = checkpoint_hash(&encoded, &forged_sig);
    assert_ne!(h1, h3);
}

/// Every proof of one batch, the way a batch flush needs them.
fn all_proofs(hashes: &[[u8; 32]]) -> Vec<MerkleProof> {
    build_merkle_proofs(hashes)
}

fn hashes_for_proofs(count: usize) -> Vec<[u8; 32]> {
    (0..count as u64)
        .map(|i| {
            let mut hash = [0u8; 32];
            hash[..8].copy_from_slice(&i.to_be_bytes());
            hash
        })
        .collect()
}

fn counted<T>(work: impl FnOnce() -> T) -> (T, u64) {
    hash_count::reset();
    let value = work();
    (value, hash_count::get())
}

#[test]
fn building_every_proof_of_a_batch_costs_a_linear_number_of_hashes() {
    let small = hashes_for_proofs(1024);
    let large = hashes_for_proofs(2048);
    let (_, small_hashes) = counted(|| all_proofs(&small));
    let (_, large_hashes) = counted(|| all_proofs(&large));
    assert!(small_hashes <= 4 * 1024, "{small_hashes} hashes for 1024 leaves");
    assert!(large_hashes <= 4 * 2048, "{large_hashes} hashes for 2048 leaves");
    assert!(
        large_hashes * 2 <= small_hashes * 5,
        "doubling the batch took {small_hashes} -> {large_hashes} hashes"
    );
}

#[test]
fn verifying_every_proof_of_a_batch_costs_n_log_n_hashes() {
    let (authority_sk, authority_vk) = keypair();
    let key_id = fingerprint_signing_key(&authority_vk);
    let (_, device_vk) = device_keypair();
    let fp = fingerprint_signing_key(&device_vk);
    let hashes = hashes_for_proofs(2048);
    let checkpoint = base_checkpoint(fp, key_id, merkle_root(&hashes), hashes.len());
    let sig = sign_checkpoint(&checkpoint, &authority_sk);
    let proofs = all_proofs(&hashes);

    let ((), spent) = counted(|| {
        for (hash, proof) in hashes.iter().zip(&proofs) {
            verify_change_admission(
                "group-1",
                "device-A",
                &device_vk,
                *hash,
                proof,
                &checkpoint,
                &sig,
                single_key_resolver(key_id, authority_vk),
            )
            .unwrap();
        }
    });
    // One leaf hash plus one node hash per level for each leaf.
    assert!(spent <= 2048 * (1 + 11), "{spent} hashes verifying 2048 proofs");
}

#[test]
fn batch_proofs_equal_the_single_leaf_proofs_and_verify_for_every_batch_size() {
    // Every size up to 64 (all odd/even level shapes, the single-leaf batch),
    // then a deterministic spread of larger sizes.
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut sizes: Vec<usize> = (1..=64).collect();
    for _ in 0..24 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        sizes.push(65 + (state >> 33) as usize % 236);
    }
    for count in sizes {
        let hashes = hashes_for_proofs(count);
        let root = merkle_root(&hashes);
        let proofs = build_merkle_proofs(&hashes);
        assert_eq!(proofs.len(), count);
        for (index, proof) in proofs.iter().enumerate() {
            assert_eq!(proof, &build_merkle_proof(&hashes, index), "n={count} leaf {index}");
            assert_eq!(recompute_root_from_proof(&hashes[index], proof), root);
        }
    }
}

#[test]
fn the_batch_split_of_admission_gives_the_single_leaf_verdict_for_valid_and_invalid_inputs() {
    let (authority_sk, authority_vk) = keypair();
    let key_id = fingerprint_signing_key(&authority_vk);
    let (_, device_vk) = device_keypair();
    let fp = fingerprint_signing_key(&device_vk);
    let hashes = hashes_for_proofs(7);
    let checkpoint = base_checkpoint(fp, key_id, merkle_root(&hashes), hashes.len());
    let signature = sign_checkpoint(&checkpoint, &authority_sk);
    let mut bad_signature = signature;
    bad_signature[0] ^= 1;
    let mut wrong_root = checkpoint.clone();
    wrong_root.merkle_root[0] ^= 1;
    let mut wrong_count = checkpoint.clone();
    wrong_count.leaf_count += 1;
    let proofs = build_merkle_proofs(&hashes);
    let mut short = proofs[3].clone();
    short.siblings.pop();
    let mut moved = proofs[3].clone();
    moved.leaf_index = 4;

    let cases = [
        (&checkpoint, &signature, "group-1", hashes[3], &proofs[3]),
        (&checkpoint, &bad_signature, "group-1", hashes[3], &proofs[3]),
        (&checkpoint, &signature, "other-group", hashes[3], &proofs[3]),
        (&checkpoint, &signature, "group-1", hashes[2], &proofs[3]),
        (&checkpoint, &signature, "group-1", hashes[3], &short),
        (&checkpoint, &signature, "group-1", hashes[3], &moved),
        (&wrong_root, &signature, "group-1", hashes[3], &proofs[3]),
        (&wrong_count, &signature, "group-1", hashes[3], &proofs[3]),
    ];
    for (n, (checkpoint, signature, group, hash, proof)) in cases.into_iter().enumerate() {
        let single = verify_change_admission(
            group,
            "device-A",
            &device_vk,
            hash,
            proof,
            checkpoint,
            signature,
            single_key_resolver(key_id, authority_vk),
        );
        let batch = verify_checkpoint_authorization(
            group,
            "device-A",
            &device_vk,
            checkpoint,
            signature,
            single_key_resolver(key_id, authority_vk),
        )
        .and_then(|()| verify_change_inclusion(hash, proof, checkpoint));
        assert_eq!(batch, single, "case {n}");
        assert_eq!(single.is_ok(), n == 0, "case {n}: {single:?}");
    }
}
