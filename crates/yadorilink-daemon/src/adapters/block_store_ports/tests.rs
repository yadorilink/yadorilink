#![cfg(test)]

use super::*;

/// Proves the adapter above lets `DaemonState::block_store`'s actual
/// type, `Arc<dyn BlockStore + Send + Sync>`, reach both port traits
/// after all -- the case direct unsize coercion can't handle (see this
/// module's doc comment) -- and that calls through the coerced port
/// handles still dispatch to the real underlying store.
#[test]
fn erased_dyn_block_store_reaches_both_port_traits_via_adapter() {
    let dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn BlockStore + Send + Sync> =
        Arc::new(yadorilink_local_storage::SegmentBlockStore::new(dir.path()).unwrap());

    let content: Arc<dyn BlockContentStore> = Arc::new(BlockStorePortsAdapter::new(store.clone()));
    let hash = content.put(b"adapter proof").unwrap();
    assert_eq!(content.get(&hash).unwrap(), b"adapter proof");
    assert_eq!(content.present_blocks(std::slice::from_ref(&hash)).unwrap(), vec![true]);

    let reclamation: Arc<dyn BlockReclamationStore> = Arc::new(BlockStorePortsAdapter::new(store));
    let live = HashSet::new();
    // `grace_cutoff` at the Unix epoch means every block's mtime is
    // newer than the cutoff, so `SegmentBlockStore::sweep`'s grace-period
    // check skips it as "too new to reclaim" regardless of `live` --
    // this proves dispatch reached the real `sweep` through the adapter
    // (a hash it stored survives an unrelated GC pass), not
    // `blocks_deleted` bookkeeping, which counts dry-run candidates
    // whether or not `dry_run` is set (only the physical delete is what
    // `dry_run` actually gates).
    let report = reclamation.sweep(&live, SystemTime::UNIX_EPOCH, true).unwrap();
    assert_eq!(report.blocks_deleted, 0, "grace period must protect a freshly written block");
}
