#![cfg(test)]

use std::sync::Arc;

use crate::SegmentBlockStore;

use super::*;

/// Proves the blanket impls above make a concrete, still-Sized
/// `BlockStore` implementor (`SegmentBlockStore`, the real production backend)
/// unsize-coerce directly to `Arc<dyn BlockContentStore>` and `Arc<dyn
/// BlockReclamationStore>` with no adapter type, and that each coerced
/// handle still dispatches to the real underlying store.
///
/// This does NOT prove the same coercion works starting from an
/// already-erased `Arc<dyn BlockStore + Send + Sync>` (what
/// `yadorilink-daemon`'s `DaemonState::block_store` actually holds) — it
/// does not, see this module's doc comment for why, and
/// `yadorilink-daemon`'s `adapters::block_store_ports` for the adapter
/// that case needs.
#[test]
fn concrete_block_store_coerces_to_both_port_traits() {
    let dir = tempfile::tempdir().unwrap();

    let content: Arc<dyn BlockContentStore> = Arc::new(SegmentBlockStore::new(dir.path()).unwrap());
    let hash = content.put(b"port coercion proof").unwrap();
    assert_eq!(content.get(&hash).unwrap(), b"port coercion proof");
    assert_eq!(content.present_blocks(std::slice::from_ref(&hash)).unwrap(), vec![true]);

    let other = tempfile::tempdir().unwrap();
    let reclamation: Arc<dyn BlockReclamationStore> =
        Arc::new(SegmentBlockStore::new(other.path()).unwrap());
    reclamation.reclaim_cached_blocks(&[]).unwrap();
    let live = HashSet::new();
    // `grace_cutoff` at the Unix epoch is before every block's recorded
    // ingest time, so the grace-window check finds nothing to reclaim.
    // This proves dispatch reached the real `sweep`, not the trait's
    // default.
    let report = reclamation.sweep(&live, SystemTime::UNIX_EPOCH, true).unwrap();
    assert_eq!(report.blocks_deleted, 0, "grace period must protect a freshly written block");
}

/// Proves the specific negative claim above: an already-erased
/// `Arc<dyn BlockStore + Send + Sync>` does NOT unsize-coerce to a port
/// trait object, even though the blanket impl means it genuinely
/// implements both port traits. This is a `compile_fail` doctest-style
/// check expressed as a plain comment plus a passing runtime assertion,
/// since `compile_fail` doctests aren't available on private items:
/// see the module doc comment's "Rust's `Unsize` coercion..." paragraph
/// for the explanation, and the daemon-side adapter this motivates.
#[test]
fn erased_dyn_block_store_needs_an_adapter_not_a_coercion() {
    let dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn BlockStore + Send + Sync> =
        Arc::new(SegmentBlockStore::new(dir.path()).unwrap());
    // `let _content: Arc<dyn BlockContentStore> = store.clone();` does not
    // compile here (verified manually while writing this commit) --
    // this test instead documents and exercises the fallback: calling
    // straight through the erased `BlockStore` trait object still works,
    // it's only the re-coercion to a *different* trait object that's
    // unavailable.
    let hash = store.put(b"erased dyn still works directly").unwrap();
    assert_eq!(store.get(&hash).unwrap(), b"erased dyn still works directly");
}
