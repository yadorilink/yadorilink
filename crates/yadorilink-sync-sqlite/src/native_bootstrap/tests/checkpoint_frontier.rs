//! The author states a checkpoint covers are persisted with the checkpoint's
//! adoption: after a join the rows equal the states the bundle carried, the root
//! the rows build is the root the sealer signed, and a failure while adopting
//! leaves nothing behind.

use yadorilink_replica_domain::native_checkpoint::NativeCheckpoint;
use yadorilink_replica_domain::native_frontier::{
    frontier_of_states, AuthorState, NativeAuthorFrontier,
};

use super::*;
use crate::native_checkpoint_frontier::{
    adopt_verified_checkpoint, checkpoint_coverage, checkpoint_frontier, CheckpointCoverage,
};

fn frontier_of(bundle: &NativeBootstrap) -> NativeAuthorFrontier {
    frontier_of_states(&bundle.author_states().unwrap())
}

fn count(c: &Connection, table: &str) -> i64 {
    c.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0)).unwrap()
}

fn evidence_of(bundle: &NativeBootstrap) -> NativeCheckpointSealEvidence {
    bundle.seal.clone().unwrap()
}

fn sealed_coverage(bundle: &NativeBootstrap) -> CheckpointCoverage {
    CheckpointCoverage { states: bundle.author_states().unwrap() }
}

fn assert_root_matches(coverage: &CheckpointCoverage, checkpoint: &NativeCheckpoint) {
    assert_eq!(coverage.recomputed_root(), checkpoint.author_state_root.0, "author-state root");
}

#[test]
fn a_join_persists_the_frontier_the_checkpoint_covers() {
    let (source, _a, _b) = source();
    let bundle = built(&source);
    let hash = bundle.checkpoint.checkpoint_hash().0;

    let fresh = conn();
    join_bundle(bundle.clone(), &fresh).unwrap();

    let stored = checkpoint_frontier(&fresh, &group(), &hash).unwrap();
    assert_eq!(stored, frontier_of(&bundle));
    assert!(!stored.is_empty());
    let coverage = checkpoint_coverage(&fresh, &group(), &hash).unwrap();
    assert_root_matches(&coverage, &bundle.checkpoint);
}

#[test]
fn a_closed_author_keeps_its_real_frontier_row_and_is_marked_closed_in_it() {
    let (source, a, _b) = source();
    close_author(&source, &group(), &a);
    let bundle = built(&source);
    let hash = bundle.checkpoint.checkpoint_hash().0;

    let fresh = conn();
    join_bundle(bundle.clone(), &fresh).unwrap();

    let coverage = checkpoint_coverage(&fresh, &group(), &hash).unwrap();
    assert!(coverage.frontier().contains_key(&a), "the closed author's real row stays");
    assert_eq!(coverage.frontier(), frontier_of(&bundle));
    assert!(matches!(coverage.states[&a], AuthorState::Closed { frontier: Some(_) }));
    assert_eq!(coverage.states, bundle.author_states().unwrap());
    assert_root_matches(&coverage, &bundle.checkpoint);
}

/// An author closed before its first delta has a row with no entry, and reads
/// back as exactly that.
#[test]
fn an_author_closed_before_its_first_delta_is_stored_without_an_entry() {
    let (source, _a, _b) = source();
    let never_seen = author("device-d");
    close_author(&source, &group(), &never_seen);
    let bundle = built(&source);
    let hash = bundle.checkpoint.checkpoint_hash().0;

    let fresh = conn();
    join_bundle(bundle.clone(), &fresh).unwrap();

    let coverage = checkpoint_coverage(&fresh, &group(), &hash).unwrap();
    assert_eq!(coverage.states[&never_seen], AuthorState::Closed { frontier: None });
    assert!(!coverage.frontier().contains_key(&never_seen));
    assert_root_matches(&coverage, &bundle.checkpoint);
}

/// A failure while the checkpoint is being adopted (here, while its frontier rows
/// are written) rolls back the whole adoption: no checkpoint row, no evidence, no
/// frontier row.
#[test]
fn a_failure_while_adopting_leaves_nothing_behind() {
    let (source, _a, _b) = source();
    let bundle = built(&source);
    let coverage = sealed_coverage(&bundle);

    let target = conn();
    target
        .execute_batch(
            "CREATE TEMP TRIGGER frontier_failpoint BEFORE INSERT ON main.native_checkpoint_frontier \
             BEGIN SELECT RAISE(ABORT, 'injected crash'); END;",
        )
        .unwrap();
    let error = adopt_verified_checkpoint(
        &target,
        &group(),
        &bundle.checkpoint,
        &evidence_of(&bundle),
        &sealer_key().verifying_key(),
        &coverage,
    )
    .unwrap_err();
    assert!(error.to_string().contains("injected crash"), "{error}");
    for table in
        ["native_checkpoints", "native_checkpoint_seal_evidence", "native_checkpoint_frontier"]
    {
        assert_eq!(count(&target, table), 0, "{table}");
    }

    target.execute_batch("DROP TRIGGER frontier_failpoint").unwrap();
    adopt_verified_checkpoint(
        &target,
        &group(),
        &bundle.checkpoint,
        &evidence_of(&bundle),
        &sealer_key().verifying_key(),
        &coverage,
    )
    .unwrap();
    assert_eq!(count(&target, "native_checkpoint_frontier") as usize, coverage.states.len());
}

#[test]
fn states_that_do_not_build_the_signed_root_are_refused_and_nothing_is_written() {
    let (source, a, _b) = source();
    let bundle = built(&source);
    let mut coverage = sealed_coverage(&bundle);
    let AuthorState::Open(entry) = coverage.states.get_mut(&a).unwrap() else {
        panic!("a is open")
    };
    entry.seq = AuthorSeq(99);

    let target = conn();
    let result = adopt_verified_checkpoint(
        &target,
        &group(),
        &bundle.checkpoint,
        &evidence_of(&bundle),
        &sealer_key().verifying_key(),
        &coverage,
    );
    assert!(result.is_err(), "states that are not the sealed ones are refused");
    for table in
        ["native_checkpoints", "native_checkpoint_seal_evidence", "native_checkpoint_frontier"]
    {
        assert_eq!(count(&target, table), 0, "{table}");
    }
}

#[test]
fn adopting_the_same_checkpoint_twice_keeps_one_set_of_rows() {
    let (source, _a, _b) = source();
    let bundle = built(&source);
    let coverage = sealed_coverage(&bundle);
    let target = conn();
    for _ in 0..2 {
        adopt_verified_checkpoint(
            &target,
            &group(),
            &bundle.checkpoint,
            &evidence_of(&bundle),
            &sealer_key().verifying_key(),
            &coverage,
        )
        .unwrap();
    }
    assert_eq!(count(&target, "native_checkpoints"), 1);
    assert_eq!(count(&target, "native_checkpoint_frontier") as usize, coverage.states.len());
}

#[test]
fn a_join_sets_the_history_floor_to_the_checkpoint_it_joined_from() {
    use crate::native_history_floor::{history_floor, retained_frontier, verify_history_floor};
    let (source, _a, _b) = source();
    let bundle = built(&source);
    let hash = bundle.checkpoint.checkpoint_hash().0;

    let fresh = conn();
    join_bundle(bundle.clone(), &fresh).unwrap();

    assert_eq!(history_floor(&fresh, &group()).unwrap().unwrap().checkpoint_id, hash);
    assert_eq!(retained_frontier(&fresh, &group()).unwrap(), frontier_of(&bundle));
    verify_history_floor(&fresh, &group()).unwrap();
    // The sealer itself adopted nothing: it has no floor of its own until it names one.
    assert!(history_floor(&source, &group()).unwrap().is_none());
}
