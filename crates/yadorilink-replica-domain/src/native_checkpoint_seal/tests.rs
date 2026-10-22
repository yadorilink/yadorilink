use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;

use super::*;
use crate::authorization_checkpoint::{
    build_merkle_proof, fingerprint_signing_key, merkle_root, sign_checkpoint,
};
use crate::native_checkpoint::{AuthorStateRoot, NamespaceRoot};
use crate::native_protocol::NATIVE_PROTOCOL_GENERATION;

const GROUP: &str = "group-native-seal";

fn authority() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn sealer_key() -> SigningKey {
    SigningKey::from_bytes(&[13; 32])
}

fn checkpoint(seed: u8) -> NativeCheckpoint {
    let mut checkpoint = NativeCheckpoint::new(
        crate::ids::FolderGroupId(GROUP.into()),
        NamespaceRoot([seed; 32]),
        AuthorStateRoot([seed.wrapping_add(1); 32]),
    );
    checkpoint.sign(&sealer_key());
    checkpoint
}

/// A policy whose authority key is `authority()` at every head in `heads`,
/// and under which each `(device, fingerprint)` in `capable` is
/// a writer at the listed policy seqs.
#[derive(Default)]
struct FakePolicy {
    heads: Vec<[u8; 32]>,
    capable: BTreeMap<(String, [u8; 32]), Vec<u64>>,
}

impl FakePolicy {
    fn granting(device: &str, key: &SigningKey, seqs: &[u64]) -> Self {
        let mut policy = Self { heads: vec![[1; 32], [0; 32]], ..Self::default() };
        policy.capable.insert(
            (device.to_owned(), fingerprint_signing_key(&key.verifying_key())),
            seqs.to_vec(),
        );
        policy
    }
}

impl NativeSealPolicy for FakePolicy {
    fn resolve_authority_key(
        &self,
        signer_key_id: &[u8; 32],
        policy_head: &[u8; 32],
    ) -> Option<VerifyingKey> {
        let key = authority().verifying_key();
        (self.heads.contains(policy_head) && fingerprint_signing_key(&key) == *signer_key_id)
            .then_some(key)
    }

    fn writer_at_policy_point(
        &self,
        device: &str,
        signing_key_fingerprint: &[u8; 32],
        point: &SealPolicyPoint,
    ) -> bool {
        self.capable
            .get(&(device.to_owned(), *signing_key_fingerprint))
            .is_some_and(|seqs| seqs.contains(&point.seq))
    }
}

#[allow(clippy::too_many_arguments)]
fn evidence(
    group: &str,
    device: &str,
    key: &SigningKey,
    checkpoint: &NativeCheckpoint,
    signer: &SigningKey,
    seq: u64,
    head: [u8; 32],
) -> NativeCheckpointSealEvidence {
    let leaf = native_checkpoint_seal_leaf(group, checkpoint);
    let authority_checkpoint = AuthorizationCheckpoint {
        group_id: group.to_owned(),
        device_id: device.to_owned(),
        signing_key_fingerprint: fingerprint_signing_key(&key.verifying_key()),
        merkle_root: merkle_root(&[leaf]),
        leaf_count: 1,
        checkpoint_seq: 1,
        signer_key_id: fingerprint_signing_key(&authority().verifying_key()),
        policy_epoch: 0,
        policy_seq: seq,
        policy_head: head,
        issued_at_unix: 0,
    };
    NativeCheckpointSealProof {
        authority_checkpoint_signature: sign_checkpoint(&authority_checkpoint, signer),
        authority_checkpoint,
        sealer_public_key: key.verifying_key().to_bytes(),
        merkle_proof: build_merkle_proof(&[leaf], 0),
    }
    .into_evidence()
}

fn genuine() -> NativeCheckpointSealEvidence {
    evidence(GROUP, "sealer", &sealer_key(), &checkpoint(1), &authority(), 1, [1; 32])
}

#[test]
fn a_seal_authorized_at_its_policy_point_verifies() {
    let policy = FakePolicy::granting("sealer", &sealer_key(), &[1]);
    let verified =
        verify_native_checkpoint_seal_authorization(GROUP, &checkpoint(1), &genuine(), &policy)
            .unwrap();
    assert_eq!(verified.sealer, DeviceId("sealer".into()));
    assert_eq!(verified.policy_point.seq, 1);
    assert_eq!(verified.sealer_public_key, sealer_key().verifying_key().to_bytes());
}

#[test]
fn the_proof_encoding_round_trips_and_refuses_truncation_or_trailing_bytes() {
    let bytes = genuine().evidence;
    let proof = NativeCheckpointSealProof::decode(&bytes).unwrap();
    assert_eq!(proof.encode(), bytes);

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        NativeCheckpointSealProof::decode(&trailing),
        Err(NativeCheckpointSealDecodeError::Malformed(_))
    ));
    assert!(matches!(
        NativeCheckpointSealProof::decode(&bytes[..bytes.len() - 1]),
        Err(NativeCheckpointSealDecodeError::Malformed(_))
    ));
}

#[test]
fn another_generation_of_seal_evidence_is_refused_by_name() {
    let mut bytes = genuine().evidence;
    bytes[7] = 0;
    assert_eq!(
        NativeCheckpointSealProof::decode(&bytes),
        Err(NativeCheckpointSealDecodeError::UnsupportedGeneration {
            theirs: 0,
            ours: NATIVE_PROTOCOL_GENERATION
        })
    );
    let policy = FakePolicy::granting("sealer", &sealer_key(), &[1]);
    let evidence =
        NativeCheckpointSealEvidence { sealer: DeviceId("sealer".into()), evidence: bytes };
    assert_eq!(
        verify_native_checkpoint_seal_authorization(GROUP, &checkpoint(1), &evidence, &policy),
        Err(NativeCheckpointSealRefusal::EvidenceMissing)
    );
}

#[test]
fn malformed_seal_evidence_is_refused() {
    let policy = FakePolicy::granting("sealer", &sealer_key(), &[1]);
    for bytes in [Vec::new(), vec![0u8; 4]] {
        let evidence =
            NativeCheckpointSealEvidence { sealer: DeviceId("sealer".into()), evidence: bytes };
        assert_eq!(
            verify_native_checkpoint_seal_authorization(GROUP, &checkpoint(1), &evidence, &policy),
            Err(NativeCheckpointSealRefusal::EvidenceMissing)
        );
    }
}

/// Evidence is bound to one specific checkpoint and one group: moved to
/// any other checkpoint or group, it is refused as missing (the leaf no
/// longer matches).
#[test]
fn evidence_for_another_checkpoint_or_group_is_refused() {
    let policy = FakePolicy::granting("sealer", &sealer_key(), &[1]);
    let evidence = genuine();
    assert_eq!(
        verify_native_checkpoint_seal_authorization(GROUP, &checkpoint(2), &evidence, &policy),
        Err(NativeCheckpointSealRefusal::EvidenceMissing)
    );
    assert_eq!(
        verify_native_checkpoint_seal_authorization(
            "another-group",
            &checkpoint(1),
            &evidence,
            &policy
        ),
        Err(NativeCheckpointSealRefusal::EvidenceMissing)
    );
}

/// A sealer that was not a writer at the
/// checkpoint's policy point is refused, even though the authority's
/// signature is genuine: never granted, revoked at that point, or granted
/// under another key.
#[test]
fn a_sealer_that_was_not_a_writer_at_the_sealed_point_is_refused() {
    let refused =
        NativeCheckpointSealRefusal::SignerNotAuthorized { sealer: DeviceId("sealer".into()) };
    for policy in [
        FakePolicy::granting("someone-else", &sealer_key(), &[1]),
        FakePolicy::granting("sealer", &sealer_key(), &[2, 3]),
        FakePolicy::granting("sealer", &SigningKey::from_bytes(&[14; 32]), &[1]),
    ] {
        assert_eq!(
            verify_native_checkpoint_seal_authorization(GROUP, &checkpoint(1), &genuine(), &policy),
            Err(refused.clone())
        );
    }
}

/// A sealer revoked after it sealed still verifies: the evidence is judged
/// at the policy point it was issued at, not against current membership --
///
#[test]
fn a_sealer_revoked_after_sealing_still_verifies() {
    // The policy only grants at seq 1: a later revoke (which would show up
    // as the policy no longer granting at, say, seq 5) does not retroact
    // onto evidence pinned to seq 1.
    let policy = FakePolicy::granting("sealer", &sealer_key(), &[1]);
    verify_native_checkpoint_seal_authorization(GROUP, &checkpoint(1), &genuine(), &policy)
        .unwrap();
}
