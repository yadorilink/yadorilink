//! Wraps `DaemonState::block_store` (`Arc<dyn BlockStore + Send + Sync>`)
//! so it can be handed to code that only wants
//! `yadorilink_local_storage::{BlockContentStore, BlockReclamationStore}`.
//! `yadorilink-local-storage`'s `content_ports` module blanket-implements
//! both port traits for every `BlockStore` implementor, including `dyn
//! BlockStore` itself, so a concrete, still-Sized `BlockStore` implementor
//! (e.g. a freshly constructed `SegmentBlockStore`) unsize-coerces
//! straight to `Arc<dyn BlockContentStore>`/`Arc<dyn
//! BlockReclamationStore>` with no wrapper needed.
//! `DaemonState::block_store` isn't that, though -- it's already
//! type-erased to `Arc<dyn BlockStore + Send + Sync>` by the time any
//! composition site sees it, and Rust's `Unsize` coercion for trait
//! objects only covers a declared supertrait relationship (dyn upcasting),
//! not a relationship established solely through a blanket impl. So
//! `Arc<dyn BlockStore> -> Arc<dyn BlockContentStore>` does not typecheck
//! even though `dyn BlockStore + Send + Sync` genuinely implements
//! `BlockContentStore` (see `yadorilink-local-storage`'s `content_ports`
//! module doc and its
//! `erased_dyn_block_store_needs_an_adapter_not_a_coercion` test for the
//! confirmed negative case this adapter exists to work around). Hydration, GC,
//! provider writes and peer sessions all construct one of these.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::SystemTime;

use yadorilink_local_storage::{
    BlockContentStore, BlockReclamationStore, BlockStore, ContentHash, GcReport,
    LocallyHashedBlock, StorageError,
};

/// Adapts an already-erased `Arc<dyn BlockStore + Send + Sync>` to
/// `BlockContentStore`/`BlockReclamationStore` by forwarding each port
/// method to the wrapped store.
pub struct BlockStorePortsAdapter(Arc<dyn BlockStore + Send + Sync>);

impl BlockStorePortsAdapter {
    pub fn new(store: Arc<dyn BlockStore + Send + Sync>) -> Self {
        Self(store)
    }
}

impl BlockContentStore for BlockStorePortsAdapter {
    fn put(&self, data: &[u8]) -> Result<ContentHash, StorageError> {
        self.0.put(data)
    }

    fn put_prepared(&self, prepared: &LocallyHashedBlock) -> Result<(), StorageError> {
        self.0.put_prepared(prepared)
    }

    fn put_prepared_batch(&self, prepared: &[LocallyHashedBlock]) -> Result<(), StorageError> {
        self.0.put_prepared_batch(prepared)
    }

    fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        self.0.get(hash)
    }

    fn present_blocks(&self, hashes: &[ContentHash]) -> Result<Vec<bool>, StorageError> {
        self.0.present_blocks(hashes)
    }
}

impl BlockReclamationStore for BlockStorePortsAdapter {
    fn storage_root(&self) -> Option<&std::path::Path> {
        self.0.storage_root()
    }

    fn sweep(
        &self,
        live: &HashSet<ContentHash>,
        grace_cutoff: SystemTime,
        dry_run: bool,
    ) -> Result<GcReport, StorageError> {
        self.0.sweep(live, grace_cutoff, dry_run)
    }

    fn reclaim_cached_blocks(&self, hashes: &[ContentHash]) -> Result<GcReport, StorageError> {
        self.0.reclaim_cached_blocks(hashes)
    }
}

#[cfg(test)]
mod tests;
