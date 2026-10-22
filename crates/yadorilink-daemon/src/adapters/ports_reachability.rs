#![cfg(test)]

//! Proof that `yadorilink-daemon` composes every capability port: each
//! port trait is nameable from this crate, and constructible as
//! `Arc<dyn Trait>` from a real production type this crate already
//! holds (`ReplicaCoordinator`, this crate's `BlockStorePortsAdapter`
//! wrapping its actual `BlockStore` instance type).
//! No consumer switches to holding these traits yet -- this only
//! establishes the composition seam is real and compiles, which is what
//! activating the ports requires before any consumer migration can
//! follow.

use std::sync::Arc;

use crate::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_capture::ports::LocalMutationStore;
use yadorilink_local_storage::{BlockContentStore, BlockReclamationStore};

use crate::adapters::block_store_ports::BlockStorePortsAdapter;

#[test]
fn every_capability_port_is_constructible_from_daemon_types() {
    let coordinator: Arc<ReplicaCoordinator> =
        Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let _local_mutation: Arc<dyn LocalMutationStore> = coordinator;

    // The daemon's actual `block_store` type is already type-erased to
    // `Arc<dyn BlockStore + Send + Sync>`, which needs
    // `BlockStorePortsAdapter` (not a direct coercion -- see that
    // module's doc comment) to reach these two ports.
    let dir = tempfile::tempdir().unwrap();
    let block_store: Arc<dyn yadorilink_local_storage::BlockStore + Send + Sync> =
        Arc::new(yadorilink_local_storage::SegmentBlockStore::new(dir.path()).unwrap());
    let _block_content: Arc<dyn BlockContentStore> =
        Arc::new(BlockStorePortsAdapter::new(block_store.clone()));
    let _block_reclamation: Arc<dyn BlockReclamationStore> =
        Arc::new(BlockStorePortsAdapter::new(block_store));
}
