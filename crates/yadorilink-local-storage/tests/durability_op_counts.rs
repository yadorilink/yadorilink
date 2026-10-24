//! Operation-count guard for the receive path's durability work.
//!
//! Counts the durable operations a fixed synthetic workload issues (file flushes,
//! directory flushes, renames, block-store durability groups) and compares them
//! with `.github/checks/perf-baseline.json`. Counts do not depend on the machine
//! or its load, so this catches an added or dropped flush without timing anything.
//!
//! The counters are process-global, so this file holds exactly one test and owns its
//! process. To change a number on purpose, follow the header of
//! `.github/checks/check-perf-baseline.py`.
#![cfg(unix)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use yadorilink_fs_platform::flush::{self, FlushCounts};
use yadorilink_local_storage::io_diag::{self, Op};
use yadorilink_local_storage::{
    flush_received_files, persist_reconstructed_file_durable,
    reconstruct_file_to_temp_observed_durable, BlockStore, Durability, LocallyHashedBlock,
    NoTempLedger, ReceivedFlushMode, ReceivedFlushOutcome, SegmentBlockStore,
};

const BASELINE: &str = include_str!("../../../.github/checks/perf-baseline.json");

type Counts = BTreeMap<&'static str, u64>;

/// Counters of the phase since `before`. `file_flushes` and `directory_syncs` count at the
/// platform layer's one flush choke point (every flush, including those inside a durable
/// move); `file_fsync` and `dir_fsync` are the counters the receive path reports, so a flush
/// added below the reporting is still seen.
fn counts(ops: &[(&'static str, Op)], before: FlushCounts) -> Counts {
    let mut seen: Counts = ops.iter().map(|(n, op)| (*n, io_diag::stat(*op).calls)).collect();
    let now = flush::counts();
    seen.insert("file_flushes", now.file_flushes - before.file_flushes);
    seen.insert("directory_syncs", now.directory_syncs - before.directory_syncs);
    seen
}

/// Differences between what was observed and what the baseline records, for the
/// counters the baseline names. Empty when they agree.
fn differences(phase: &str, observed: &Counts, expected: &serde_json::Value) -> Vec<String> {
    observed
        .iter()
        .filter_map(|(name, seen)| {
            let want = expected[name].as_u64().unwrap_or_else(|| panic!("{phase}.{name} missing"));
            (*seen != want).then(|| format!("{phase}.{name}: observed {seen}, baseline {want}"))
        })
        .collect()
}

fn layout(root: &Path, files: usize, directories: usize) -> Vec<PathBuf> {
    (0..directories).for_each(|d| std::fs::create_dir_all(root.join(format!("d{d}"))).unwrap());
    (0..files)
        .map(|i| root.join(format!("d{}", i % directories)).join(format!("f{i}.bin")))
        .collect()
}

fn publish_all(
    store: &SegmentBlockStore,
    targets: &[PathBuf],
    durability: Durability,
    extra_flush_per_file: bool,
) {
    for target in targets {
        let tmp = reconstruct_file_to_temp_observed_durable(
            store,
            target,
            &[],
            1,
            &NoTempLedger,
            &|_| {},
            durability,
        )
        .unwrap();
        persist_reconstructed_file_durable(&tmp, target, &NoTempLedger, durability).unwrap();
        if extra_flush_per_file {
            // The defect the guard exists for: one more flush per received file.
            io_diag::time(Op::DirFsync, 0, || {
                flush::sync_directory(&std::fs::File::open(target.parent().unwrap()).unwrap())
            })
            .unwrap();
        }
    }
}

/// Runs the fixed workload and returns the counts per phase.
fn observe(extra_flush_per_file: bool) -> BTreeMap<&'static str, Counts> {
    let doc: serde_json::Value = serde_json::from_str(BASELINE).unwrap();
    let w = &doc["storage_workload"];
    let (files, dirs, blocks) = (
        w["files"].as_u64().unwrap() as usize,
        w["directories"].as_u64().unwrap() as usize,
        w["blocks_in_batch"].as_u64().unwrap() as usize,
    );
    let tmp = tempfile::tempdir().unwrap();
    let store =
        SegmentBlockStore::new(tmp.path().join("blocks")).unwrap().with_volume_verdict(|_| true);
    let publish_ops =
        [("file_fsync", Op::FileFsync), ("dir_fsync", Op::DirFsync), ("rename", Op::Rename)];
    let mut seen = BTreeMap::new();

    io_diag::reset();
    let before = flush::counts();
    let targets = layout(&tmp.path().join("each"), files, dirs);
    publish_all(&store, &targets, Durability::Full, extra_flush_per_file);
    seen.insert("publish_each", counts(&publish_ops, before));

    io_diag::reset();
    let before = flush::counts();
    let targets = layout(&tmp.path().join("deferred"), files, dirs);
    publish_all(&store, &targets, Durability::DeferredToBatch, extra_flush_per_file);
    let flushed = flush_received_files(&targets, ReceivedFlushMode::FullFsyncEach, 4);
    assert!(flushed.iter().all(|o| matches!(o, ReceivedFlushOutcome::Flushed)));
    seen.insert("publish_deferred_then_flush", counts(&publish_ops, before));

    io_diag::reset();
    let before = flush::counts();
    let batch: Vec<_> = (0..blocks)
        .map(|i| {
            LocallyHashedBlock::from_bytes(format!("guard-block-{i:04}").repeat(64).into_bytes())
        })
        .collect();
    store.put_prepared_batch(&batch).unwrap();
    seen.insert(
        "block_batch",
        counts(&[("group_commit", Op::GroupCommit), ("segment_fsync", Op::SegmentFsync)], before),
    );
    seen
}

#[test]
fn durable_operation_counts_match_the_recorded_baseline() {
    io_diag::set_enabled(true);
    let doc: serde_json::Value = serde_json::from_str(BASELINE).unwrap();
    let w = &doc["storage_workload"];
    let compare = |seen: &BTreeMap<&'static str, Counts>| -> Vec<String> {
        seen.iter().flat_map(|(phase, counts)| differences(phase, counts, &w[phase])).collect()
    };

    let honest = compare(&observe(false));
    assert!(
        honest.is_empty(),
        "the durable operation counts moved: {honest:#?}\nIf this is intended, follow the update \
         procedure in .github/checks/check-perf-baseline.py (a recorded reason is required)."
    );

    // The guard must notice one extra directory flush per file.
    let mutated = compare(&observe(true));
    assert!(
        mutated.iter().any(|d| d.contains("dir_fsync")),
        "an extra flush per file went unnoticed: {mutated:#?}"
    );
    io_diag::set_enabled(false);
}
