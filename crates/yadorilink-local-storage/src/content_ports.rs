//! `BlockStore` itself exposes twelve methods (`put`, `get`,
//! `get_unchecked`, `delete`, `exists`, `list_by_prefix`, `usage`,
//! `sweep`, `reclaim_cached_blocks`, `present_blocks`,
//! `set_headroom_enforced`, `set_headroom_override_bytes`, `free_space`).
//! The rest are unused from this crate today: - `get_unchecked`, `delete`,
//! `exists`, `list_by_prefix`, and `usage` are exercised only by this
//! crate's own tests (a `CountingBlockStore` test double in
//! `local_change.rs`, and assertions against a real `SegmentBlockStore` in
//! `block_deletion.rs`/`materialization.rs`), never by production call
//! sites. - `free_space` is never called through `BlockStore` at all here
//! — `link_preflight.rs` and `materialization.rs` call
//! `yadorilink_local_storage::free_space::classify_volume`, a free
//! function in a different module, not the trait method. -
//! `set_headroom_enforced`/`set_headroom_override_bytes` are never
//! forwarded to a `BlockStore` from this crate either. `peer_session.rs`
//! has its own same-named methods on `PeerSyncSession` (an `AtomicBool`
//! and a `Mutex<Option<u64>>` it owns directly), consulted by
//! `preflight_disk_headroom`, which calls the free-function
//! `check_disk_headroom` — not `self.store`. So this module defines two
//! traits, not the four-trait split a generic sketch might suggest,
//! because only two clusters of `BlockStore` methods are actually
//! load-bearing here: - [`BlockContentStore`] — the content-addressed
//! read/write hot path: `chunker.rs`'s
//! `chunk_file`/`chunk_file_content_defined` and
//! `single_pass_capture.rs`'s single-pass chunking both call `put` while
//! writing new blocks; `chunker.rs`'s `reconstruct_file` and
//! `peer_session.rs`'s block-request handling call `get`;
//! `peer_session.rs`'s hydration presence check and `materialization.rs`'s
//! local-reconstruct-without-a-peer decision both call `present_blocks` to
//! batch-check which blocks are already local. - [`BlockReclamationStore`]
//! — GC/eviction, each reached only behind a guard proving no in-flight
//! materialization write can read the block: `sweep` (mark-and-sweep GC,
//! via filesystem-sync's `block_deletion::sweep_globally_unreferenced_blocks`)
//! and `reclaim_cached_blocks` (on-demand-sync cache eviction of a specific
//! hash set once custody is confirmed elsewhere, via the daemon's
//! `ReplicaCoordinator::reclaim_cached_blocks`). Same scaffolding discipline as
//! `peer_replica_state.rs`/
//! `local_mutation.rs`/`materialization_state.rs`: these traits are thin,
//! same-signature delegates (kept in `StorageError`, `BlockStore`'s own
//! error type, rather than converted to `SyncError`, since a delegate that
//! changes its error type wouldn't be same-signature). No consumer is
//! migrated to use them yet — `chunker.rs`, `single_pass_capture.rs`,
//! `peer_session.rs`, `materialization.rs`, and `block_deletion.rs` are
//! untouched and still take `&dyn BlockStore`/`Arc<dyn BlockStore>`
//! directly. A later commit swaps each consumer's parameter/field type to
//! `&dyn Trait`/`Arc<dyn Trait>` one at a time. Blanket-implemented for
//! every `BlockStore` (`+ ?Sized`, so the impl also covers `dyn
//! BlockStore` itself as a type, and a concrete `BlockStore` implementor
//! unsize-coerces straight to `Arc<dyn BlockContentStore>`/`Arc<dyn
//! BlockReclamationStore>` with no adapter type) rather than implemented
//! directly for one concrete type, unlike the `SyncState`-only adapters in
//! this module's siblings: `BlockStore` is a foreign trait with several
//! implementations already in play (`SegmentBlockStore`, in-memory test
//! doubles, `CountingBlockStore`), and there's no orphan-rule obstacle to
//! a blanket impl here since both new traits are local to this crate. That
//! direct coercion needs a *concrete, still-Sized* `BlockStore`
//! implementor at the call site, though (proven in this module's `tests`
//! below) — it does NOT extend to an already-erased `Arc<dyn BlockStore +
//! Send + Sync>`, which is what `yadorilink-daemon`'s
//! `DaemonState::block_store` actually holds. Rust's `Unsize` coercion for
//! trait objects only applies to a declared supertrait relationship (dyn
//! upcasting); `BlockContentStore` and `BlockReclamationStore` are not
//! supertraits of `BlockStore`, they're connected only through this
//! module's blanket impl, so `Arc<dyn BlockStore> -> Arc<dyn
//! BlockContentStore>` does not typecheck even though `dyn BlockStore +
//! Send + Sync` genuinely implements `BlockContentStore`. A daemon-side
//! adapter that wraps the already-erased `Arc<dyn BlockStore + Send +
//! Sync>` and forwards each port method is required for that case — see
//! `yadorilink-daemon`'s `adapters::block_store_ports` module.

use std::collections::HashSet;
use std::time::SystemTime;

use crate::{BlockStore, ContentHash, GcReport, LocallyHashedBlock, StorageError};

/// Content-addressed read/write for the sync/materialization hot path.
/// Every method here is called from this crate today — see this module's
/// doc comment for the exact call sites.
pub trait BlockContentStore: Send + Sync {
    /// Stores a freshly chunked block, called once per block from both of
    /// `chunker.rs`'s chunking strategies and both of
    /// `single_pass_capture.rs`'s single-pass branches while a file is
    /// captured.
    fn put(&self, data: &[u8]) -> Result<ContentHash, StorageError>;

    /// See `BlockStore::put_prepared`'s own doc comment — same contract,
    /// forwarded through this port for `chunker.rs`'s `&dyn
    /// BlockContentStore` callers.
    fn put_prepared(&self, prepared: &LocallyHashedBlock) -> Result<(), StorageError>;

    /// See `BlockStore::put_prepared_batch`'s own doc comment — same
    /// contract, forwarded through this port for `chunker.rs`'s `&dyn
    /// BlockContentStore` callers.
    fn put_prepared_batch(&self, prepared: &[LocallyHashedBlock]) -> Result<(), StorageError>;

    /// Reads a block back by hash, called from `chunker.rs::reconstruct_file`
    /// while assembling a file from its index-recorded blocks, and from
    /// `peer_session.rs` while serving a block a peer requested.
    fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError>;

    /// Batch presence check, called from `peer_session.rs` before a
    /// hydration fetch (deciding which of a file's blocks still need a
    /// peer round-trip) and from `materialization.rs` before a repair
    /// reconstruct (deciding whether every block is already local, so the
    /// reconstruct needs no peer at all).
    fn present_blocks(&self, hashes: &[ContentHash]) -> Result<Vec<bool>, StorageError>;
}

impl<T: BlockStore + ?Sized> BlockContentStore for T {
    fn put(&self, data: &[u8]) -> Result<ContentHash, StorageError> {
        BlockStore::put(self, data)
    }

    fn put_prepared(&self, prepared: &LocallyHashedBlock) -> Result<(), StorageError> {
        BlockStore::put_prepared(self, prepared)
    }

    fn put_prepared_batch(&self, prepared: &[LocallyHashedBlock]) -> Result<(), StorageError> {
        BlockStore::put_prepared_batch(self, prepared)
    }

    fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        BlockStore::get(self, hash)
    }

    fn present_blocks(&self, hashes: &[ContentHash]) -> Result<Vec<bool>, StorageError> {
        BlockStore::present_blocks(self, hashes)
    }
}

/// GC/eviction. Physical deletion is reached only through the guarded
/// owners named on each method; the eviction path reaches these through
/// them rather than calling a `BlockStore` directly.
pub trait BlockReclamationStore: Send + Sync {
    /// See [`BlockStore::storage_root`].
    fn storage_root(&self) -> Option<&std::path::Path>;

    /// Mark-and-sweep GC, called from filesystem-sync's
    /// `block_deletion::sweep_globally_unreferenced_blocks`, which requires
    /// a `BlockPhysicalDeletionGuard` before delegating here.
    fn sweep(
        &self,
        live: &HashSet<ContentHash>,
        grace_cutoff: SystemTime,
        dry_run: bool,
    ) -> Result<GcReport, StorageError>;

    /// Deletes a specific, already-decided set of cached blocks, called
    /// from the daemon's `ReplicaCoordinator::reclaim_cached_blocks` only
    /// after it has revalidated custody confirmation, pin status, and
    /// materialization state under the deletion guard — this method itself
    /// makes no liveness decision, per `BlockStore::reclaim_cached_blocks`'s
    /// own contract.
    fn reclaim_cached_blocks(&self, hashes: &[ContentHash]) -> Result<GcReport, StorageError>;
}

impl<T: BlockStore + ?Sized> BlockReclamationStore for T {
    fn storage_root(&self) -> Option<&std::path::Path> {
        BlockStore::storage_root(self)
    }

    fn sweep(
        &self,
        live: &HashSet<ContentHash>,
        grace_cutoff: SystemTime,
        dry_run: bool,
    ) -> Result<GcReport, StorageError> {
        BlockStore::sweep(self, live, grace_cutoff, dry_run)
    }

    fn reclaim_cached_blocks(&self, hashes: &[ContentHash]) -> Result<GcReport, StorageError> {
        BlockStore::reclaim_cached_blocks(self, hashes)
    }
}

#[cfg(test)]
mod tests;
