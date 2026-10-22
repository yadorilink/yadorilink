//! The batched obligation close and proof publication of new paths mean what the per-path ones
//! mean: a close succeeds exactly when the single close would, and a proof is published under the
//! epoch its own fence bump minted.

use std::collections::BTreeSet;

use rusqlite::Connection;
use tempfile::TempDir;

use yadorilink_fs_platform::fs_identity::FileIdentity;
use yadorilink_replica_domain::ids::VersionHash;

use crate::materialized_generation::{
    adopt_observed_present_generations_batch, bump_mutation_fence,
    compute_resolved_path_state_hash, lookup_materialized_generation, MaterializedObjectKind,
    ObservedPresent,
};
use crate::projection_obligations::{
    bump_projection_obligations_for_touched_paths, complete_obligation_if_exact_proof_current,
    complete_obligations_if_exact_proofs_current, lookup_projection_obligation, ExactClose,
};

const GROUP: &str = "g";

/// What differs between a close that must succeed and one of the ways it must not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    /// Everything holds.
    Exact,
    /// Another writer bumped the path's fence after the proof was published.
    StaleFence,
    /// The desired state is another version than the proof shows (a winner that differs).
    DesiredDiffers,
    /// The obligation was bumped again after the claim was read.
    StaleGeneration,
    /// The claim names another row lifetime of the obligation.
    StaleIncarnation,
    /// The path has an obligation and no proof at all.
    NoProof,
}

const CASES: [Case; 6] = [
    Case::Exact,
    Case::StaleFence,
    Case::DesiredDiffers,
    Case::StaleGeneration,
    Case::StaleIncarnation,
    Case::NoProof,
];

struct Claim {
    path: String,
    generation: i64,
    incarnation: i64,
    desired: [u8; 32],
    case: Case,
}

fn version() -> VersionHash {
    VersionHash([5; 32])
}

fn identity() -> (TempDir, FileIdentity) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f");
    std::fs::write(&path, b"x").unwrap();
    let identity = FileIdentity::observe_path(&path).unwrap();
    (dir, identity)
}

/// A replica holding, for each path of `cases`, the obligation and proof its case describes, and
/// the claim a close would make.
fn replica(cases: &[Case]) -> (Connection, Vec<Claim>) {
    let conn = Connection::open_in_memory().unwrap();
    crate::replica_tables::init(&conn).unwrap();
    let (_dir, file) = identity();
    let paths: Vec<String> = (0..cases.len()).map(|i| format!("p/f{i}")).collect();
    let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
    bump_projection_obligations_for_touched_paths(&conn, GROUP, &refs, 1).unwrap();
    let proof_version = version();
    let observed: Vec<ObservedPresent<'_>> = paths
        .iter()
        .zip(cases)
        .filter(|(_, case)| **case != Case::NoProof)
        .map(|(path, _)| ObservedPresent {
            path,
            object_kind: MaterializedObjectKind::RegularFile,
            version: &proof_version,
            filesystem_identity: &file,
            basis: crate::materialization_basis::ReflectedHeads::of(&[[1; 32]], &[]),
        })
        .collect();
    adopt_observed_present_generations_batch(&conn, GROUP, &observed, 2).unwrap();
    let mut claims = Vec::new();
    for (path, case) in paths.iter().zip(cases) {
        let obligation = lookup_projection_obligation(&conn, GROUP, path).unwrap().unwrap();
        let proof_hash = compute_resolved_path_state_hash(
            GROUP,
            path,
            MaterializedObjectKind::RegularFile,
            Some(&version()),
        );
        let other_hash = compute_resolved_path_state_hash(
            GROUP,
            path,
            MaterializedObjectKind::RegularFile,
            Some(&VersionHash([6; 32])),
        );
        let mut claim = Claim {
            path: path.clone(),
            generation: obligation.invalidation_generation,
            incarnation: obligation.obligation_incarnation,
            desired: proof_hash,
            case: *case,
        };
        match case {
            Case::StaleFence => {
                bump_mutation_fence(&conn, GROUP, path, "materialize", 3).unwrap();
            }
            Case::DesiredDiffers => claim.desired = other_hash,
            Case::StaleGeneration => {
                bump_projection_obligations_for_touched_paths(&conn, GROUP, &[path], 3).unwrap();
            }
            Case::StaleIncarnation => claim.incarnation += 1000,
            Case::Exact | Case::NoProof => {}
        }
        claims.push(claim);
    }
    (conn, claims)
}

fn remaining(conn: &Connection) -> BTreeSet<String> {
    conn.prepare("SELECT path FROM projection_obligations")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// For every mix of cases, closing the claims in one statement closes the paths that closing them
/// one at a time closes, and only those: a stale fence, a desired state that differs from the
/// proof, a bumped obligation, another incarnation and a missing proof each leave it pending.
#[test]
fn the_batched_close_closes_what_the_single_close_closes() {
    let mut closed_somewhere = 0;
    let mut left_somewhere = 0;
    for seed in 0..60u64 {
        let mut state = seed.wrapping_mul(2862933555777941757).wrapping_add(3037000493);
        let cases: Vec<Case> = (0..9)
            .map(|_| {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                CASES[((state >> 33) % CASES.len() as u64) as usize]
            })
            .collect();
        let (batched, claims) = replica(&cases);
        let (single, _) = replica(&cases);
        let closes: Vec<ExactClose<'_>> = claims
            .iter()
            .map(|c| ExactClose {
                path: &c.path,
                claimed_invalidation_generation: c.generation,
                claimed_obligation_incarnation: c.incarnation,
                desired_resolved_path_state_hash: c.desired,
            })
            .collect();
        let closed =
            complete_obligations_if_exact_proofs_current(&batched, GROUP, &closes).unwrap();
        let mut closed_singly = BTreeSet::new();
        for claim in &claims {
            if complete_obligation_if_exact_proof_current(
                &single,
                GROUP,
                &claim.path,
                claim.generation,
                claim.incarnation,
                &claim.desired,
            )
            .unwrap()
            {
                closed_singly.insert(claim.path.clone());
            }
        }
        assert_eq!(closed.iter().cloned().collect::<BTreeSet<_>>(), closed_singly, "{cases:?}");
        assert_eq!(remaining(&batched), remaining(&single), "{cases:?}");
        for claim in &claims {
            let closes_it = claim.case == Case::Exact;
            assert_eq!(closed_singly.contains(&claim.path), closes_it, "{:?}", claim.case);
        }
        closed_somewhere += closed.len();
        left_somewhere += claims.len() - closed.len();
    }
    assert!(closed_somewhere > 20 && left_somewhere > 100);
}

/// Each proof of a batch is published under the epoch its own fence bump returned, which is the
/// path's live fence afterwards, and a path whose fence already moved is published above it.
#[test]
fn a_batched_proof_is_published_under_the_epoch_of_its_own_bump() {
    let conn = Connection::open_in_memory().unwrap();
    crate::replica_tables::init(&conn).unwrap();
    let (_dir, file) = identity();
    // One path has been mutated twice already.
    bump_mutation_fence(&conn, GROUP, "b", "materialize", 1).unwrap();
    bump_mutation_fence(&conn, GROUP, "b", "materialize", 1).unwrap();
    let version = version();
    let observed: Vec<ObservedPresent<'_>> = ["a", "b", "c"]
        .iter()
        .map(|path| ObservedPresent {
            path,
            object_kind: MaterializedObjectKind::RegularFile,
            version: &version,
            filesystem_identity: &file,
            basis: crate::materialization_basis::ReflectedHeads::of(&[[1; 32]], &[]),
        })
        .collect();
    adopt_observed_present_generations_batch(&conn, GROUP, &observed, 9).unwrap();
    for (path, epoch) in [("a", 1), ("b", 3), ("c", 1)] {
        let fence: i64 = conn
            .query_row(
                "SELECT mutation_generation FROM path_actual_mutation_fences \
                 WHERE group_id = ?1 AND path = ?2",
                rusqlite::params![GROUP, path],
                |r| r.get(0),
            )
            .unwrap();
        let published: i64 = conn
            .query_row(
                "SELECT published_under_mutation_generation FROM path_materialized_generations \
                 WHERE group_id = ?1 AND path = ?2",
                rusqlite::params![GROUP, path],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!((fence, published), (epoch, epoch), "{path}");
        assert!(lookup_materialized_generation(&conn, GROUP, path).unwrap().is_some());
    }
}

/// Two proofs for one path in a batch are refused: they would be published under one bump.
#[test]
fn a_batch_names_each_path_once() {
    let conn = Connection::open_in_memory().unwrap();
    crate::replica_tables::init(&conn).unwrap();
    let (_dir, file) = identity();
    let version = version();
    let observed: Vec<ObservedPresent<'_>> = ["a", "a"]
        .iter()
        .map(|path| ObservedPresent {
            path,
            object_kind: MaterializedObjectKind::RegularFile,
            version: &version,
            filesystem_identity: &file,
            basis: crate::materialization_basis::ReflectedHeads::of(&[], &[]),
        })
        .collect();
    assert!(adopt_observed_present_generations_batch(&conn, GROUP, &observed, 1).is_err());
}
