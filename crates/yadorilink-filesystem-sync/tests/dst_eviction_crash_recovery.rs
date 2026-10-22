//! Fault-injection DST scenario for the `Evicting` crash
//! window `materialization_eviction::evict_file` opens between setting
//! `MaterializationState::Evicting` and its final `Remote` commit --
//! the same window the native Windows dehydrate RPC widens (a real
//! cross-process round trip sits inside it, not just a local disk
//! write).
//!
//! Same shape and same reasoning as the sibling
//! `dst_materialization_crash_recovery.rs` for the `Present` crash
//! window: plain synchronous functions, no `tokio`/simulator scheduling to
//! simulate, so the fault is injected by directly constructing the
//! on-disk-and-index state a crash would leave behind, then asserting the
//! real recovery path (`MaterializationStateRepository::reset_stale_
//! evicting_to_placeholder`, the exact call `yadorilink-daemon`'s own
//! startup wiring makes) self-heals it. Many seeded variations, covering
//! both crash sub-cases plus block count/size, not one fixed scenario.
//!
//! # Scope, stated honestly (a review finding on this file's first
//! version)
//!
//! What this DOES prove, by actually running the real functions: (a)
//! `reset_stale_evicting` correctly resets a stale
//! `Evicting` row to `Remote` regardless of which of the two disk
//! sub-cases a crash left behind, and touches only that row (never more
//! than the one seeded); (b) the row's indexed blocks remain individually
//! present and reconstructable in the block store afterward.
//!
//! What this does NOT prove, and an earlier version of this doc comment
//! overclaimed: that `evict_file`'s real ordering (`Evicting` -> native
//! dehydrate/placeholder confirmation -> `Remote` commit -> block
//! reclamation, strictly in that order) is itself what keeps blocks safe
//! across a REAL interrupted eviction. Nothing in this test's flow ever
//! calls `evict_file` or anything capable of reclaiming a block at all --
//! `reset_stale_evicting` is pure SQL with no block-store
//! access (see its own implementation), and `reconstruct_file` only reads
//! from the block store this test itself seeded and never touched. This
//! test would still pass with `reset_stale_evicting`
//! deleted entirely (only the separate `reset_count`/`state_after`
//! assertions would then fail) -- it is a regression test for the reset
//! function and block reconstructability, not an end-to-end proof that
//! real eviction never reclaims a block before its `Remote` commit.
//! That stronger property is verified by direct code inspection of
//! `materialization_eviction.rs::evict_file`'s own control flow (block
//! reclamation is textually and provably unreachable before the
//! `Remote` transition succeeds) -- not by a randomized execution
//! here. Exercising it end-to-end would need a fault-injection seam
//! threaded through `evict_file` itself (pausing it mid-attempt) and a
//! reclaim-spy block store, which this file does not claim to provide.

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::{
    reconstruct_file, BlockStore, PlaceholderDiskIdentity, SegmentBlockStore,
    WINDOWS_CFAPI_GENERATION_PROVIDER_KIND,
};
use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_root_authority::root_commit::RootCommitPermit;

const GROUP_ID: &str = "dst-eviction-crash-group";
const PATH: &str = "evicting.bin";
const VARIATIONS: u64 = 200;

/// Which of the two real crash sub-cases `reset_stale_evicting_to_
/// placeholder`'s own doc comment names this seed simulates.
enum CrashLanding {
    /// The object's removal had already landed on disk before the crash --
    /// nothing stands at the path, indexed blocks untouched in the block
    /// store. The Windows equivalent (a real CfAPI placeholder
    /// post-dehydrate) cannot be reproduced without a real Windows sync
    /// root -- see this file's own top-level doc comment's "Scope" section on
    /// what this test does and doesn't exercise -- but
    /// `reset_stale_evicting` is pure SQL with no filesystem access at all
    /// (verified by reading its own implementation), so the disk shape
    /// genuinely does not matter to what THIS sub-case is proving.
    AfterRemoval,
    /// The crash landed strictly BEFORE the removal/dehydrate call -- disk
    /// still holds the file's full original content, unrelated to whatever
    /// the (stale) `Evicting` row claims.
    BeforeRemoval,
}

fn run_scenario(seed: u64) -> Result<(), String> {
    let mut rng = StdRng::seed_from_u64(seed);
    let root_dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let root = root_dir.path().canonicalize().map_err(|e| e.to_string())?;
    let store_dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let store = SegmentBlockStore::new(store_dir.path()).map_err(|e| e.to_string())?;
    let state = ReplicaCoordinator::open_in_memory().map_err(|e| e.to_string())?;
    state
        .link_repository()
        .add_link(&root.to_string_lossy(), GROUP_ID)
        .map_err(|e| e.to_string())?;
    yadorilink_root_authority::root_identity::VerifiedRoot::open(&root, GROUP_ID, &state)
        .map_err(|e| e.to_string())?;

    let num_blocks = rng.random_range(1..=3u32);
    let mut blocks = Vec::with_capacity(num_blocks as usize);
    let mut expected_content = Vec::new();
    let mut offset = 0u64;
    for _ in 0..num_blocks {
        let size = rng.random_range(4..40u32);
        let data: Vec<u8> = (0..size).map(|_| rng.random()).collect();
        let hash_hex = store.put(&data).map_err(|e| e.to_string())?;
        let hash = hex::decode(&hash_hex).map_err(|e| e.to_string())?;
        blocks.push(BlockInfo { hash, offset, size });
        offset += u64::from(size);
        expected_content.extend_from_slice(&data);
    }

    let record = FileRecord {
        path: PATH.to_string(),
        size: expected_content.len() as u64,
        mtime_unix_nanos: 0,
        blocks: blocks.clone(),
        deleted: false,
    };
    let permit = RootCommitPermit::for_tests();
    state
        .file_index_repository()
        .upsert_file(GROUP_ID, &record, &permit)
        .map_err(|e| e.to_string())?;

    // A Windows placeholder identity, recorded BEFORE eviction starts --
    // matching the real precondition the Windows eviction path
    // depends on: a `Present` row being evicted already carries the
    // generation its placeholder object was created under (eviction never
    // mints a fresh one; see `materialization_eviction::evict_to_
    // placeholder`'s own doc comment). `reset_stale_evicting_to_
    // placeholder` only ever touches the `materialization_state` column
    // (verified by reading its own implementation) -- this identity must
    // survive the crash and reset completely untouched.
    let identity = PlaceholderDiskIdentity { dev: 0, ino: seed.wrapping_add(1) };
    state
        .materialization_state_repository()
        .record_placeholder_generation(
            GROUP_ID,
            PATH,
            identity,
            WINDOWS_CFAPI_GENERATION_PROVIDER_KIND,
            &permit,
        )
        .map_err(|e| e.to_string())?;

    // The crash: `evict_file` already committed the transient `Evicting`
    // state (the FIRST write it makes, per its own doc comment: "Index
    // update happens before the disk write") before the process died --
    // matching real eviction's actual ordering, not an arbitrary choice.
    state
        .materialization_state_repository()
        .set_materialization_state(GROUP_ID, PATH, MaterializationState::Evicting, &permit)
        .map_err(|e| e.to_string())?;

    let landing =
        if rng.random_bool(0.5) { CrashLanding::AfterRemoval } else { CrashLanding::BeforeRemoval };
    match landing {
        CrashLanding::AfterRemoval => {
            // The real removal, not a hand-rolled stand-in -- an honest
            // reproduction of the disk a genuine post-removal crash leaves:
            // nothing at the path.
            yadorilink_local_storage::remove_evicted_object(&root.join(PATH))
                .map_err(|e| e.to_string())?;
        }
        CrashLanding::BeforeRemoval => {
            // The real content is still fully on disk -- the crash landed
            // before any removal/dehydrate call ever touched it.
            std::fs::write(root.join(PATH), &expected_content).map_err(|e| e.to_string())?;
        }
    }

    // The real recovery path -- exactly what `yadorilink-daemon::app::run`'s
    // startup wiring calls (see `crates/yadorilink-daemon/src/app.rs`'s
    // own "Recover any file left permanently stuck `Evicting`" section).
    let reset_count = state
        .materialization_state_repository()
        .reset_stale_transients(&[], &[])
        .map_err(|e| format!("seed {seed}: reset_stale_transients failed: {e}"))?
        .1;
    if reset_count != 1 {
        return Err(format!("seed {seed}: expected exactly 1 row reset, got {reset_count}"));
    }

    let state_after = state
        .materialization_state_repository()
        .get_materialization_state(GROUP_ID, PATH)
        .map_err(|e| e.to_string())?;
    if state_after != Some(MaterializationState::Remote) {
        return Err(format!(
            "seed {seed}: row must land on Remote after reset, got {state_after:?}"
        ));
    }

    let identity_after = state
        .materialization_state_repository()
        .get_recorded_placeholder_identity(GROUP_ID, PATH)
        .map_err(|e| e.to_string())?
        .map(|recorded| recorded.identity);
    if identity_after != Some(identity) {
        return Err(format!(
            "seed {seed}: the placeholder identity recorded before the crash must survive \
             reset_stale_evicting untouched -- expected {identity:?}, got \
             {identity_after:?}"
        ));
    }

    // Every block this scenario indexed is still individually present and
    // reconstructable in the block store after the reset -- see this
    // file's own top-level "Scope" doc comment for exactly what this
    // does and does not prove: nothing here could have reclaimed a
    // block regardless of what `reset_stale_evicting`
    // did, so this is a regression check on block reconstructability
    // and the reset function's own correctness, not an end-to-end proof
    // that real eviction's reclaim ordering is what kept them safe.
    reconstruct_file(&store, &root.join(PATH), &blocks, 0)
        .map_err(|e| format!("seed {seed}: reconstruct_file failed after repair: {e}"))?;
    let on_disk = std::fs::read(root.join(PATH)).map_err(|e| e.to_string())?;
    if on_disk != expected_content {
        return Err(format!(
            "seed {seed}: reconstructed content doesn't match the original -- a block this \
             test itself seeded went missing from the block store"
        ));
    }

    Ok(())
}

/// Many seeded variations (block count/sizes, which of the two crash
/// sub-cases landed) of "eviction was interrupted by a crash between its
/// `Evicting` commit and its final `Remote` commit" -- `reset_stale_
/// evicting_to_placeholder` must correctly resolve the row to
/// `Remote` (touching only the one seeded row) and every indexed
/// block must remain reconstructable afterward. See this file's own
/// top-level "Scope" doc comment for what this test does and does not
/// prove.
#[test]
fn eviction_self_heals_after_a_simulated_crash_with_no_data_loss() {
    for seed in 0..VARIATIONS {
        run_scenario(seed).unwrap_or_else(|e| panic!("{e}"));
    }
}
