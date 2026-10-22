#![cfg(test)]

use super::*;
use crate::materialization_intent::MaterializationIntentGuard;

/// End-to-end proof that `MaterializationIntentGuard` opens and clears
/// a real, durable intent against a `ReplicaCoordinator`-backed
/// `MaterializationIntentRepository` -- not merely that the trait bound
/// type-checks.
#[test]
fn guard_opens_and_clears_against_replica_coordinator() {
    let coordinator = ReplicaCoordinator::open_in_memory().unwrap();
    let permit = RootCommitPermit::for_tests();

    assert!(!coordinator
        .materialization_intent_repository()
        .has_materialization_intent("group-1", "a.bin")
        .unwrap());

    let guard = MaterializationIntentGuard::open(
        &coordinator,
        "group-1",
        "a.bin",
        b"target-version-hash",
        &permit,
    )
    .unwrap();
    assert!(coordinator
        .materialization_intent_repository()
        .has_materialization_intent("group-1", "a.bin")
        .unwrap());

    guard.clear().unwrap();
    assert!(!coordinator
        .materialization_intent_repository()
        .has_materialization_intent("group-1", "a.bin")
        .unwrap());
}
