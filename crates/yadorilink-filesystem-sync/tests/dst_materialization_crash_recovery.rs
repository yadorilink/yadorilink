//! Fault-injection DST scenario: simulates a process crash during
//! materialization and verifies the real recovery path
//! (`materialization::repair_interrupted_materializations` +
//! `remove_recorded_temp_files`) self-heals without data loss or leftover
//! garbage.
//!
//! Scope note: unlike the watcher (`SimulatedFolderWatchSource`) and
//! peer-network (simulated socket) boundaries, this scenario is
//! deliberately **not** built on a `MaterializeIo` trait abstraction or a
//! simulated runtime. The materialization write path
//! (`chunker::reconstruct_file`) and its recovery path
//! (`repair_interrupted_materializations`, `remove_recorded_temp_files`)
//! are both plain, synchronous functions with no `tokio`/async
//! involvement at all -- there is no scheduling to simulate. Rather than
//! intercepting `reconstruct_file`'s own I/O calls (which would mean
//! threading a new abstraction through `chunker.rs`, a shared,
//! sync-protocol-critical file, for a benefit this scenario doesn't
//! need), the fault is injected the way a real crash actually manifests:
//! by directly constructing the *on-disk and index state* a crash would
//! leave behind (an index row already marked `Present` -- matching
//! `peer_session.rs::materialize`'s real ordering, where the index is
//! updated as part of the same operation as the disk write -- but the
//! file itself missing or a stale temp file left over), then asserting
//! the real repair functions recover it. This is still seeded and run
//! across many variations (block count/sizes, whether a stale temp file
//! is also present), matching this harness's "many variations, not one
//! scenario" shape (see `dst_watcher_debounce.rs`) -- it just doesn't
//! need a simulator to get there.

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_filesystem_sync::materialization_repair::{
    repair_interrupted_materializations, RepairMode,
};
use yadorilink_local_storage::{BlockStore, SegmentBlockStore};
use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_root_authority::root_commit::RootCommitPermit;

const GROUP_ID: &str = "dst-repair-group";
const PATH: &str = "recovered.bin";
const VARIATIONS: u64 = 200;

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
    // Claim the root while the index is still empty, the way linking a folder
    // does. This scenario's whole shape -- index a file, simulate a crash that
    // loses the bytes, then repair -- is byte-for-byte the unmounted-volume
    // signature (indexed files, none of them on disk, no marker), so without an
    // adopted root the repair below correctly refuses to touch the folder and
    // the crash is never actually exercised.
    yadorilink_root_authority::root_identity::VerifiedRoot::open(&root, GROUP_ID, &state)
        .map_err(|e| e.to_string())?;

    // Real content, chunked into a random number of real blocks, each
    // durably stored for real in a real SegmentBlockStore -- the block store
    // itself is assumed unaffected by the simulated crash (a separate
    // durability concern; materialize's crash-safety is specifically
    // about the disk-write-then-index-update sequence, not block
    // storage).
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
        blocks,
        deleted: false,
    };
    state
        .file_index_repository()
        .upsert_file(GROUP_ID, &record, &RootCommitPermit::for_tests())
        .map_err(|e| e.to_string())?;
    // The crash: the index already reflects this file as Hydrated (the
    // real materialize updates the index as part of the same
    // operation as the disk write -- see in conflict.rs and
    // peer_session.rs), but the actual bytes never made it to `root`
    // because the process died first. Deliberately never call
    // reconstruct_file at all here -- that's the point.
    state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP_ID,
            PATH,
            MaterializationState::Present,
            &RootCommitPermit::for_tests(),
        )
        .map_err(|e| e.to_string())?;
    // A genuine crash mid-materialize leaves the durable materialization intent
    // in place (it is written before the temp-write-then-rename and cleared only
    // after it completes). Its presence is what tells startup repair this is a
    // crash to recover, not a file the user deleted while the daemon was stopped
    // (which would carry no intent). Seed it here to model the real crash state.
    state
        .materialization_intent_repository()
        .begin_materialization_intent(GROUP_ID, PATH, &[0u8; 32], &RootCommitPermit::for_tests())
        .map_err(|e| e.to_string())?;

    // About half the seeds also leave a temp file, the shape a crash *during*
    // reconstruct_file's write (rather than before it started) leaves behind.
    // The writer recorded it before creating it, which is what recovery uses.
    let left_stale_temp = rng.random_bool(0.5);
    if left_stale_temp {
        let tmp_name =
            format!("{PATH}.yadorilink-tmp.{}.{}", std::process::id(), rng.random::<u32>());
        let tmp = root.join(&tmp_name);
        yadorilink_local_storage::TempFileLedger::record(&state.temp_ledger(GROUP_ID), &tmp)
            .map_err(|e| e.to_string())?;
        std::fs::write(&tmp, b"partial garbage from an interrupted write")
            .map_err(|e| e.to_string())?;
    }

    // The real recovery path -- exactly what yadorilink-daemon's startup
    // wiring and its periodic MATERIALIZATION_REPAIR_INTERVAL sweep call.
    let report = repair_interrupted_materializations(
        &state,
        &store,
        &root,
        GROUP_ID,
        RepairMode::Startup,
        &RootCommitPermit::for_tests(),
    )
    .map_err(|e| format!("seed {seed}: repair_interrupted_materializations failed: {e}"))?;
    let removed_temps =
        state.remove_recorded_temp_files(GROUP_ID, &root).map_err(|e| e.to_string())?;

    let on_disk = std::fs::read(root.join(PATH)).map_err(|e| {
        format!("seed {seed}: not repaired (report: {report:?}, stale_temp_present={left_stale_temp}): {e}")
    })?;
    if on_disk != expected_content {
        return Err(format!(
            "seed {seed}: repaired content doesn't match what was originally chunked (report: {report:?})"
        ));
    }

    let leftover: Vec<_> = std::fs::read_dir(&root)
        .map_err(|e| e.to_string())?
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains(".yadorilink-tmp."))
        .collect();
    if !leftover.is_empty() {
        return Err(format!(
            "seed {seed}: stale temp file(s) remained after remove_recorded_temp_files: {leftover:?} \
             (it reported removing: {removed_temps:?})"
        ));
    }
    Ok(())
}

/// Many seeded variations (block count/sizes, presence of a leftover
/// temp file) of "materialization was interrupted by a crash after the
/// index was updated but before/during the disk write" -- all must
/// self-heal via the real repair path with no data loss and no leftover
/// garbage.
#[test]
fn materialization_self_heals_after_a_simulated_crash() {
    for seed in 0..VARIATIONS {
        run_scenario(seed).unwrap_or_else(|e| panic!("{e}"));
    }
}
