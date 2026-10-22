#![cfg(test)]

use super::*;

/// Proves a real `Arc<ReplicaCoordinator>` unsize-coerces to `Arc<dyn
/// LocalMutationStore>` and dispatches correctly -- mirrors
/// `yadorilink-local-capture`'s own
/// `arc_test_replica_coerces_to_port_trait`.
#[test]
fn arc_replica_coordinator_coerces_to_local_mutation_store() {
    let coordinator: Arc<ReplicaCoordinator> =
        Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let port: Arc<dyn LocalMutationStore> = coordinator;

    let _lock = port.path_lock("group-a", "path/a.txt");
    assert_eq!(port.get_file("group-a", "path/a.txt").unwrap(), None);
}

/// A lock taken through `LocalMutationStore::path_lock` and a lock taken
/// through the coordinator's own `path_lock_registry()` for the
/// identical `(group_id, path)` must be the literal same `Arc`, or the
/// two do not actually serialize against each other. `ReplicaCoordinator`
/// owns the only `PathLockRegistry` in the process
/// (`crate::sync_runtime::path_locks::PathLockRegistry` -- see
/// `ReplicaCoordinator::from_database`'s own doc comment), so this just
/// proves `LocalMutationStore::path_lock` actually resolves through that
/// registry rather than, say, a fresh one constructed per call.
#[test]
fn path_lock_is_shared_across_the_coordinators_own_accessors() {
    let coordinator = ReplicaCoordinator::open_in_memory().unwrap();

    let via_trait = LocalMutationStore::path_lock(&coordinator, "group-a", "path/a.txt");
    let via_registry = coordinator.path_lock_registry().path_lock("group-a", "path/a.txt");

    assert!(
        Arc::ptr_eq(&via_trait, &via_registry),
        "ReplicaCoordinator's LocalMutationStore::path_lock must resolve through its own \
         path_lock_registry(), or local capture and anything reached through \
         ReplicaCoordinator no longer mutually exclude on the same path"
    );
}
