use ed25519_dalek::SigningKey;

use super::*;
use crate::author::{AuthorId, IncarnationId};
use crate::authorization_checkpoint::{
    canonical_signing_bytes, fingerprint_signing_key, merkle_root, sign_checkpoint,
    AuthorizationCheckpoint,
};
use crate::ids::DeviceId;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn author(name: &str) -> AuthorId {
    AuthorId { device: DeviceId(name.into()), incarnation: IncarnationId([1; 16]) }
}

fn entry(seq: u64, tip: u8) -> NativeAuthorFrontierEntry {
    NativeAuthorFrontierEntry { seq: AuthorSeq(seq), tip: DeltaHash([tip; 32]) }
}

/// The authority's checkpoint for `device` holding `device_key`, as the
/// authorization a closure carries.
fn authorization(device: &str, device_key: &SigningKey) -> Vec<u8> {
    let authority = key(200);
    let checkpoint = AuthorizationCheckpoint {
        group_id: "g".into(),
        device_id: device.into(),
        signing_key_fingerprint: fingerprint_signing_key(&device_key.verifying_key()),
        merkle_root: merkle_root(&[[9; 32]]),
        leaf_count: 1,
        checkpoint_seq: 1,
        signer_key_id: fingerprint_signing_key(&authority.verifying_key()),
        policy_epoch: 0,
        policy_seq: 1,
        policy_head: [0; 32],
        issued_at_unix: 0,
    };
    let mut bytes = canonical_signing_bytes(&checkpoint);
    bytes.extend_from_slice(&sign_checkpoint(&checkpoint, &authority));
    bytes
}

fn resolver(id: &[u8; 32], _head: &[u8; 32]) -> Option<VerifyingKey> {
    let authority = key(200).verifying_key();
    (*id == fingerprint_signing_key(&authority)).then_some(authority)
}

fn closure(name: &str, cutoff: Option<NativeAuthorFrontierEntry>) -> AuthorClosure {
    AuthorClosure { group_id: FolderGroupId("g".into()), author: author(name), cutoff }
}

fn signed(
    name: &str,
    signer_seed: u8,
    cutoff: Option<NativeAuthorFrontierEntry>,
) -> SignedAuthorClosure {
    let signer = key(signer_seed);
    closure(name, cutoff).sign(&signer, authorization(name, &signer))
}

#[test]
fn a_closure_signed_by_its_own_device_verifies_and_round_trips() {
    for cutoff in [None, Some(entry(5, 7))] {
        let own = signed("device-a", 1, cutoff);
        own.verify("g", resolver).expect("verifies");
        let decoded = SignedAuthorClosure::from_wire_bytes(&own.to_wire_bytes()).unwrap();
        assert_eq!(decoded, own);
        assert_eq!(decoded.closure_hash(), own.closure_hash());
    }
}

#[test]
fn a_closure_signed_by_another_device_does_not_verify() {
    // Device B signs a closure of device A's incarnation with B's own key and
    // B's own authorization.
    let forged =
        closure("device-a", Some(entry(2, 1))).sign(&key(2), authorization("device-b", &key(2)));
    assert!(matches!(forged.verify("g", resolver), Err(ClosureError::NotAuthorized(_))));
    // And with A's authorization attached, the key is still not A's.
    let mut borrowed = forged.clone();
    borrowed.authorization = authorization("device-a", &key(1));
    assert!(matches!(borrowed.verify("g", resolver), Err(ClosureError::NotAuthorized(_))));
}

#[test]
fn tampering_any_signed_field_breaks_the_signature() {
    let own = signed("device-a", 1, Some(entry(5, 7)));
    let mut moved = own.clone();
    moved.closure.cutoff = Some(entry(6, 7));
    assert_eq!(moved.verify("g", resolver), Err(ClosureError::BadSignature));
    let mut other_author = own.clone();
    other_author.closure.author = author("device-b");
    assert_eq!(other_author.verify("g", resolver), Err(ClosureError::BadSignature));
    assert!(matches!(own.verify("other", resolver), Err(ClosureError::GroupMismatch { .. })));
}

#[test]
fn a_closure_without_authorization_is_refused() {
    let mut own = signed("device-a", 1, None);
    own.authorization.clear();
    assert_eq!(own.verify("g", resolver), Err(ClosureError::NoAuthorization));
}

#[test]
fn lower_sequence_wins_and_none_is_the_lowest() {
    let (none, low, high) = (None, Some(entry(2, 1)), Some(entry(5, 1)));
    assert_eq!(join_cutoffs(none.as_ref(), low.as_ref()), ClosureJoin::Lower);
    assert_eq!(join_cutoffs(low.as_ref(), none.as_ref()), ClosureJoin::Higher);
    assert_eq!(join_cutoffs(low.as_ref(), high.as_ref()), ClosureJoin::Lower);
    assert_eq!(join_cutoffs(high.as_ref(), low.as_ref()), ClosureJoin::Higher);
    assert_eq!(join_cutoffs(none.as_ref(), none.as_ref()), ClosureJoin::Identical);
    assert_eq!(join_cutoffs(low.as_ref(), low.as_ref()), ClosureJoin::Identical);
    let other_tip = Some(entry(2, 9));
    assert_eq!(join_cutoffs(low.as_ref(), other_tip.as_ref()), ClosureJoin::Fork);
}

#[test]
fn a_foreign_generation_or_tag_is_refused() {
    let mut bytes = signed("device-a", 1, None).to_wire_bytes();
    bytes[7] = bytes[7].wrapping_add(1);
    assert!(matches!(
        SignedAuthorClosure::from_wire_bytes(&bytes),
        Err(ChangeError::UnsupportedGeneration { .. })
    ));
    bytes[0] = b'X';
    assert!(SignedAuthorClosure::from_wire_bytes(&bytes).is_err());
}
