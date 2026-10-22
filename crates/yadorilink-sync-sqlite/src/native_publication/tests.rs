#![cfg(test)]

use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use yadorilink_replica_domain::author::IncarnationId;
use yadorilink_replica_domain::ids::DeviceId;

use super::*;

fn conn() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    native_store::init_native_tables(&c).unwrap();
    crate::native_admission::init_admission_tables(&c).unwrap();
    init_native_publication_tables(&c).unwrap();
    c
}

fn group() -> FolderGroupId {
    FolderGroupId("g1".into())
}

fn author(name: &str) -> AuthorId {
    AuthorId { device: DeviceId(name.into()), incarnation: IncarnationId([1u8; 16]) }
}

fn hash(byte: u8) -> DeltaHash {
    DeltaHash([byte; 32])
}

const CHECKPOINT_HASH: [u8; 32] = [0xAA; 32];

fn attach_one(conn: &Connection, delta_hash: DeltaHash, proof: &[u8]) {
    attach_authorization_evidence(
        conn,
        &CHECKPOINT_HASH,
        "g1",
        "device-a",
        1,
        b"encoded",
        b"0123456789012345678901234567890123456789012345678901234567890a",
        &[7u8; 32],
        &[(delta_hash, proof.to_vec())],
    )
    .unwrap();
}

#[test]
fn an_unattached_delta_is_not_published() {
    let c = conn();
    assert!(!is_published(&c, &hash(1)).unwrap());
    assert!(evidence_for(&c, &hash(1)).unwrap().is_none());
}

#[test]
fn attaching_evidence_makes_a_delta_published_and_readable() {
    let c = conn();
    attach_one(&c, hash(1), b"proof-bytes");
    assert!(is_published(&c, &hash(1)).unwrap());
    let (checkpoint_hash, proof) = evidence_for(&c, &hash(1)).unwrap().unwrap();
    assert_eq!(checkpoint_hash, CHECKPOINT_HASH);
    assert_eq!(proof, b"proof-bytes");

    let (encoded, signature, author_key) =
        checkpoint_envelope(&c, &CHECKPOINT_HASH).unwrap().unwrap();
    assert_eq!(encoded, b"encoded");
    assert_eq!(signature, b"0123456789012345678901234567890123456789012345678901234567890a");
    assert_eq!(author_key, [7u8; 32]);
}

#[test]
fn re_attaching_the_identical_evidence_is_a_no_op() {
    let c = conn();
    attach_one(&c, hash(1), b"proof-bytes");
    attach_one(&c, hash(1), b"proof-bytes");
    assert!(is_published(&c, &hash(1)).unwrap());
}

#[test]
fn attaching_a_different_checkpoint_payload_under_the_same_hash_is_refused() {
    let c = conn();
    attach_one(&c, hash(1), b"proof-bytes");
    let err = attach_authorization_evidence(
        &c,
        &CHECKPOINT_HASH,
        "g1",
        "device-a",
        1,
        b"DIFFERENT",
        b"0123456789012345678901234567890123456789012345678901234567890a",
        &[7u8; 32],
        &[(hash(2), b"another-proof".to_vec())],
    );
    assert!(matches!(err, Err(SyncSqliteError::CorruptState(_))));
    // The mismatched call must not have attached the second delta either.
    assert!(!is_published(&c, &hash(2)).unwrap());
}

#[test]
fn attaching_different_evidence_under_an_already_published_delta_hash_is_refused() {
    let c = conn();
    attach_one(&c, hash(1), b"proof-bytes");
    let err = attach_delta_evidence(&c, &hash(1), &CHECKPOINT_HASH, b"a-different-proof");
    assert!(matches!(err, Err(SyncSqliteError::CorruptState(_))));
}

#[test]
fn a_pending_evidence_entry_can_be_taken_exactly_once() {
    let c = conn();
    store_checkpoint(&c, &CHECKPOINT_HASH, "g1", "device-a", 1, b"encoded", b"sig", &[7u8; 32])
        .unwrap();
    record_pending_evidence(&c, &hash(1), &CHECKPOINT_HASH, b"proof-bytes").unwrap();

    let (checkpoint_hash, proof) = take_pending_evidence(&c, &hash(1)).unwrap().unwrap();
    assert_eq!(checkpoint_hash, CHECKPOINT_HASH);
    assert_eq!(proof, b"proof-bytes");

    // Taken -- gone now.
    assert!(take_pending_evidence(&c, &hash(1)).unwrap().is_none());
}

#[test]
fn pending_native_deltas_for_author_lists_installed_but_unpublished_deltas_only() {
    let c = conn();
    let a = author("a");
    let key_a = SigningKey::from_bytes(&[1u8; 32]);

    let mut d1 = yadorilink_replica_domain::signed_delta::NativeDelta {
        recursive_part: None,
        group_id: group(),
        author: a.clone(),
        seq: yadorilink_replica_domain::ids::AuthorSeq(1),
        prev: None,
        ops: vec![yadorilink_replica_domain::signed_delta::DeltaOp {
            path: yadorilink_replica_domain::ids::SyncPath("x".into()),
            removes: Vec::new(),
            put: Some(yadorilink_replica_domain::signed_delta::DeltaPut {
                version: yadorilink_replica_domain::ids::VersionHash([1u8; 32]),
            }),
        }],
        signature: [0u8; 64],
    };
    d1.sign(&key_a);
    let d1_hash = d1.delta_hash();
    native_store::install_verified_delta(&c, &group(), &d1, &key_a.verifying_key()).unwrap();

    // Not yet published.
    let pending = pending_native_deltas_for_author(&c, &group(), &a).unwrap();
    assert_eq!(pending, vec![(yadorilink_replica_domain::ids::AuthorSeq(1), d1_hash)]);

    // Publish it -- no longer pending.
    attach_one(&c, d1_hash, b"proof-bytes");
    assert!(pending_native_deltas_for_author(&c, &group(), &a).unwrap().is_empty());
}
