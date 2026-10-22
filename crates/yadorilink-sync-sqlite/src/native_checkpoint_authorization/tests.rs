use std::collections::BTreeMap;

use ed25519_dalek::{SigningKey, VerifyingKey};
use rusqlite::Connection;

use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::authorization_checkpoint::{
    build_merkle_proof, fingerprint_signing_key, merkle_root, sign_checkpoint,
    AuthorizationCheckpoint,
};
use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, FolderGroupId};
use yadorilink_replica_domain::native_checkpoint::{
    AuthorStateRoot, NamespaceRoot, NativeCheckpoint,
};
use yadorilink_replica_domain::native_checkpoint_seal::SealPolicyPoint;
use yadorilink_replica_domain::native_checkpoint_seal::{
    native_checkpoint_seal_leaf, NativeCheckpointSealProof, NativeSealPolicy,
};
use yadorilink_replica_domain::native_frontier::{
    author_state_root, AuthorState, NativeAuthorFrontier, NativeAuthorFrontierEntry,
    NativeAuthorStates,
};
use yadorilink_replica_domain::native_state::DeltaHash;

use super::*;
use crate::native_checkpoint_frontier::CheckpointCoverage;
use crate::native_store::{self, as_array32};

const GROUP: &str = "group-checkpoint-auth";

fn conn() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    native_store::init_native_tables(&c).unwrap();
    init_native_checkpoint_authorization_tables(&c).unwrap();
    c
}

fn group() -> FolderGroupId {
    FolderGroupId(GROUP.into())
}

fn author(name: &str) -> AuthorId {
    AuthorId { device: DeviceId(name.into()), incarnation: IncarnationId([1u8; 16]) }
}

fn frontier(entries: &[(&str, u64)]) -> NativeAuthorFrontier {
    entries
        .iter()
        .map(|(name, seq)| {
            (
                author(name),
                NativeAuthorFrontierEntry { seq: AuthorSeq(*seq), tip: DeltaHash([1u8; 32]) },
            )
        })
        .collect()
}

fn authority() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn sealer_key() -> SigningKey {
    SigningKey::from_bytes(&[13; 32])
}

/// The states of a frontier in which every author is open (no closed authors
/// in these tests).
fn open_states(frontier: &NativeAuthorFrontier) -> NativeAuthorStates {
    frontier.iter().map(|(author, entry)| (author.clone(), AuthorState::Open(*entry))).collect()
}

/// A checkpoint whose `author_state_root` is exactly the root of `frontier`'s
/// open states, so it corroborates against that frontier for snapshot purposes.
fn checkpoint_for(frontier: &NativeAuthorFrontier, salt: u8) -> NativeCheckpoint {
    let mut checkpoint = NativeCheckpoint::new(
        group(),
        NamespaceRoot([salt; 32]),
        AuthorStateRoot(author_state_root(&open_states(frontier))),
    );
    checkpoint.sign(&sealer_key());
    checkpoint
}

#[derive(Default)]
struct FakePolicy {
    heads: Vec<[u8; 32]>,
    capable: BTreeMap<(String, [u8; 32]), Vec<u64>>,
}

impl FakePolicy {
    fn granting_all(device: &str, key: &SigningKey) -> Self {
        let mut policy = Self { heads: vec![[1; 32]], ..Self::default() };
        policy
            .capable
            .insert((device.to_owned(), fingerprint_signing_key(&key.verifying_key())), vec![1]);
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

fn evidence_for(
    checkpoint: &NativeCheckpoint,
) -> yadorilink_replica_domain::native_checkpoint_seal::NativeCheckpointSealEvidence {
    let leaf = native_checkpoint_seal_leaf(GROUP, checkpoint);
    let authority_checkpoint = AuthorizationCheckpoint {
        group_id: GROUP.to_owned(),
        device_id: "sealer".to_owned(),
        signing_key_fingerprint: fingerprint_signing_key(&sealer_key().verifying_key()),
        merkle_root: merkle_root(&[leaf]),
        leaf_count: 1,
        checkpoint_seq: 1,
        signer_key_id: fingerprint_signing_key(&authority().verifying_key()),
        policy_epoch: 0,
        policy_seq: 1,
        policy_head: [1; 32],
        issued_at_unix: 0,
    };
    NativeCheckpointSealProof {
        authority_checkpoint_signature: sign_checkpoint(&authority_checkpoint, &authority()),
        authority_checkpoint,
        sealer_public_key: sealer_key().verifying_key().to_bytes(),
        merkle_proof: build_merkle_proof(&[leaf], 0),
    }
    .into_evidence()
}

fn coverage_of(frontier: &NativeAuthorFrontier) -> CheckpointCoverage {
    CheckpointCoverage { states: open_states(frontier) }
}

fn install(c: &Connection, checkpoint: &NativeCheckpoint, frontier: &NativeAuthorFrontier) {
    let policy = FakePolicy::granting_all("sealer", &sealer_key());
    install_authorized_checkpoint(
        c,
        &group(),
        checkpoint,
        &evidence_for(checkpoint),
        &policy,
        &coverage_of(frontier),
    )
    .unwrap();
}

fn installed_checkpoint_hashes(c: &Connection) -> Vec<[u8; 32]> {
    let mut stmt =
        c.prepare("SELECT checkpoint_hash FROM native_checkpoints WHERE group_id = ?1").unwrap();
    let rows: Vec<Vec<u8>> =
        stmt.query_map([GROUP], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect();
    rows.into_iter().map(|b| as_array32(&b).unwrap()).collect()
}

#[test]
fn unauthorized_evidence_is_refused_and_nothing_installs() {
    let c = conn();
    let f = frontier(&[("a", 1)]);
    let checkpoint = checkpoint_for(&f, 1);
    let wrong_policy = FakePolicy::default(); // grants nothing
    let err = install_authorized_checkpoint(
        &c,
        &group(),
        &checkpoint,
        &evidence_for(&checkpoint),
        &wrong_policy,
        &coverage_of(&f),
    )
    .unwrap_err();
    assert!(matches!(err, SyncSqliteError::InvalidInput(_)));
    assert!(installed_checkpoint_hashes(&c).is_empty());
}

#[test]
fn authorized_checkpoint_installs() {
    let c = conn();
    let f = frontier(&[("a", 1)]);
    let checkpoint = checkpoint_for(&f, 1);
    install(&c, &checkpoint, &f);
    assert_eq!(installed_checkpoint_hashes(&c), vec![checkpoint.checkpoint_hash().0]);
}

#[test]
fn seal_evidence_survives_alongside_the_checkpoint_and_is_fetchable() {
    let c = conn();
    let f = frontier(&[("a", 1)]);
    let checkpoint = checkpoint_for(&f, 1);
    let evidence = evidence_for(&checkpoint);
    install(&c, &checkpoint, &f);

    let fetched = fetch_checkpoint_seal_evidence(&c, &group(), &checkpoint.checkpoint_hash().0)
        .unwrap()
        .expect("evidence must be persisted alongside the checkpoint it authorized");
    assert_eq!(
        fetched, evidence,
        "the exact evidence originally verified must be recoverable later"
    );
}

#[test]
fn fetching_evidence_for_an_unknown_checkpoint_is_none_not_an_error() {
    let c = conn();
    assert_eq!(fetch_checkpoint_seal_evidence(&c, &group(), &[7u8; 32]).unwrap(), None);
}

/// Simulates a crash after the checkpoint body is written but while its seal
/// evidence is: everything `install_authorized_checkpoint` had written so far
/// rolls back, so a checkpoint is never installed without its evidence.
#[test]
fn a_crash_while_storing_the_evidence_leaves_nothing_installed() {
    let c = conn();
    let f = frontier(&[("a", 1)]);
    let checkpoint = checkpoint_for(&f, 1);

    c.execute_batch(
        "CREATE TEMP TRIGGER evidence_failpoint BEFORE INSERT ON main.native_checkpoint_seal_evidence \
         BEGIN SELECT RAISE(ABORT, 'injected crash'); END;",
    )
    .unwrap();

    let policy = FakePolicy::granting_all("sealer", &sealer_key());
    let err = install_authorized_checkpoint(
        &c,
        &group(),
        &checkpoint,
        &evidence_for(&checkpoint),
        &policy,
        &coverage_of(&f),
    )
    .unwrap_err();
    assert!(err.to_string().contains("injected crash"), "{err}");
    assert!(installed_checkpoint_hashes(&c).is_empty());

    c.execute_batch("DROP TRIGGER evidence_failpoint;").unwrap();
    install(&c, &checkpoint, &f);
    assert_eq!(installed_checkpoint_hashes(&c), vec![checkpoint.checkpoint_hash().0]);
}
