//! DST-style fault scenarios that do not need a real network:
//! publish-time-authorization timing, driven through real production code,
//! seeded and swept over several interleavings per scenario.
//!
//! The network-dependent scenarios (partition/heal, restart-with-a-held-
//! delta, reorder/duplicate delivery over a real wire) live in
//! `yadorilink-daemon`'s `native_dst_network_scenarios.rs`. This file covers
//! what is naturally storage-layer: revoke timing.
//!
//! This project has a heavy, purpose-built turmoil-based DST harness
//! (`yadorilink-daemon/tests/dst_turmoil_substrate_case.rs`). Building an
//! equivalent here is explicitly out of scope --
//! these scenarios are DST-*style* (deterministic, seeded, reproducible)
//! but driven directly against the real, already-hardened storage APIs,
//! not through a simulated network/clock.

use ed25519_dalek::{SigningKey, VerifyingKey};
use rusqlite::Connection;

use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::authorization_checkpoint::{
    build_merkle_proof, canonical_signing_bytes, checkpoint_hash as compute_checkpoint_hash,
    fingerprint_signing_key, merkle_root, sign_checkpoint, AuthorizationCheckpoint,
};
use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, FolderGroupId, SyncPath, VersionHash};
use yadorilink_replica_domain::signed_delta::{DeltaOp, DeltaPut, NativeDelta};

use yadorilink_sync_sqlite::native_admission::{self, NativeAdmission};
use yadorilink_sync_sqlite::native_publication;
use yadorilink_sync_sqlite::native_store;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
}

fn group() -> FolderGroupId {
    FolderGroupId("g-dst-storage".into())
}

fn author(index: u8) -> AuthorId {
    AuthorId {
        device: DeviceId(format!("dst-author-{index}")),
        incarnation: IncarnationId([1u8; 16]),
    }
}

fn signing_key(index: u8) -> SigningKey {
    SigningKey::from_bytes(&[50 + index; 32])
}

fn authority_key() -> SigningKey {
    SigningKey::from_bytes(&[210u8; 32])
}

fn conn() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    yadorilink_sync_sqlite::replica_tables::init(&c).unwrap();
    native_store::init_native_tables(&c).unwrap();
    native_admission::init_admission_tables(&c).unwrap();
    native_publication::init_native_publication_tables(&c).unwrap();
    yadorilink_sync_sqlite::native_checkpoint_authorization::init_native_checkpoint_authorization_tables(&c).unwrap();
    c
}

struct Bundle {
    encoded_delta: Vec<u8>,
    checkpoint_hash: [u8; 32],
    checkpoint_encoded: Vec<u8>,
    checkpoint_signature: [u8; 64],
    author_public_key: [u8; 32],
    proof_encoded: Vec<u8>,
}

fn bundle_for(delta: &NativeDelta, author_signing_key: &SigningKey, device_id: &str) -> Bundle {
    let leaves = vec![delta.delta_hash().0];
    let checkpoint = AuthorizationCheckpoint {
        group_id: group().0,
        device_id: device_id.to_string(),
        signing_key_fingerprint: fingerprint_signing_key(&author_signing_key.verifying_key()),
        merkle_root: merkle_root(&leaves),
        leaf_count: 1,
        checkpoint_seq: 1,
        signer_key_id: fingerprint_signing_key(&authority_key().verifying_key()),
        policy_epoch: 0,
        policy_seq: 1,
        policy_head: [0u8; 32],
        issued_at_unix: 1,
    };
    let signature = sign_checkpoint(&checkpoint, &authority_key());
    let checkpoint_encoded = canonical_signing_bytes(&checkpoint);
    Bundle {
        encoded_delta: delta.to_wire_bytes(),
        checkpoint_hash: compute_checkpoint_hash(&checkpoint_encoded, &signature),
        checkpoint_encoded,
        checkpoint_signature: signature,
        author_public_key: author_signing_key.verifying_key().to_bytes(),
        proof_encoded: yadorilink_replica_domain::protocol5::encode_proof(&build_merkle_proof(
            &leaves, 0,
        )),
    }
}

/// Scenario 5: author revoke-before-publish vs. revoke-after-late-delivery,
/// swept over several randomized "when does the revoke happen relative to
/// delivery" interleavings. This is the earlier fix's exact fixed invariant
/// (a delta published while its author was a legitimate writer stays valid
/// however late it arrives), confirmed under a DST-style sweep of the
/// live-key-table state at delivery time rather than one fixed ordering.
#[test]
fn scenario_5_revoke_timing_sweep() {
    for seed in 0..40u64 {
        let mut rng = Rng(seed);
        let c = conn();
        let a = author(0);
        let key_a = signing_key(0);
        let delta = {
            let mut d = NativeDelta {
                recursive_part: None,
                group_id: group(),
                author: a.clone(),
                seq: AuthorSeq(1),
                prev: None,
                ops: vec![DeltaOp {
                    path: SyncPath("x".into()),
                    removes: vec![],
                    put: Some(DeltaPut { version: VersionHash([1u8; 32]) }),
                }],
                signature: [0u8; 64],
            };
            d.sign(&key_a);
            d
        };
        let bundle = bundle_for(&delta, &key_a, a.device.as_str());
        let proof = yadorilink_replica_domain::authorization_checkpoint::decode_merkle_proof(
            &bundle.proof_encoded,
        )
        .unwrap();

        // Randomized: whether the author is ALREADY revoked (absent from
        // the live key table) at the moment this late delta is delivered.
        // Per the fixed invariant, this must never matter -- publish-time
        // authorization already proved legitimacy via the carried,
        // checkpoint-bound key, not a live lookup.
        let already_revoked = rng.below(2) == 0;
        let key_for: &dyn Fn(&AuthorId) -> Option<VerifyingKey> = if already_revoked {
            &|_: &AuthorId| None
        } else {
            &|candidate: &AuthorId| {
                (*candidate == author(0)).then(|| signing_key(0).verifying_key())
            }
        };
        let resolve_authority = |key_id: &[u8; 32], _head: &[u8; 32]| {
            (*key_id == fingerprint_signing_key(&authority_key().verifying_key()))
                .then(|| authority_key().verifying_key())
        };

        let outcome = native_admission::admit_published_native_delta(
            &c,
            &group(),
            &bundle.encoded_delta,
            &bundle.checkpoint_hash,
            &bundle.checkpoint_encoded,
            &bundle.checkpoint_signature,
            &bundle.author_public_key,
            &proof,
            key_for,
            resolve_authority,
        )
        .expect("admission call itself does not error");
        assert!(
            matches!(outcome, NativeAdmission::Admitted { .. }),
            "seed {seed}: a legitimately published delta must admit whether or not its author is revoked from the live key table by delivery time (got {outcome:?})"
        );
    }
}
