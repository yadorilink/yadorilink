//! Deterministic simulation testing (DST) harness skeleton: runs the real
//! watcher-boundary/debounce/local-change-indexing code (unmodified in
//! its logic) under a simulated, seed-controlled scheduler,
//! substituting `watcher::SimulatedFolderWatchSource` for a real OS
//! watcher (see that type's doc comment for why the watcher specifically
//! needs a manual substitute while everything downstream of it does
//! not).
//!
//! Only compiled/run when built with `RUSTFLAGS="--cfg turmoil"` (the whole
//! point is exercising a simulated scheduler) — a plain `cargo test` never
//! builds this file at all. How the simulation is constructed is
//! `dst_support::sim`'s business, not this file's: nothing below names a
//! simulator.
//!
//! It needs no simulated network at all — it proves seeding, virtual time,
//! task spawning and the oracle, and nothing else.
//!
//! `run_many_seeded_variations_in_parallel` is this skeleton's actual
//! scenario: it doesn't stop at "one seed, one scenario" but drives many
//! independently-seeded simulated runs concurrently across OS threads,
//! each fully isolated (its own simulated runtime) and fully reproducible
//! from its own seed — the intended day-to-day shape of this harness, not
//! just a smoke test of the plumbing.

#![cfg(turmoil)]

mod dst_support;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_filesystem_sync::debounce::{self, DebounceConfig};
use yadorilink_filesystem_sync::watcher::{
    FolderWatchSource, FsChangeEvent, FsChangeKind, SimulatedFolderWatchSource,
};
use yadorilink_local_capture::LocalChangeProcessor;
use yadorilink_local_storage::SegmentBlockStore;

use dst_support::{check_no_silent_data_loss, format_violations, WriteOracle};

const GROUP_ID: &str = "dst-group";
const DEVICE_ID: &str = "dst-device";
const OPS_PER_RUN: usize = 15;
/// Default seed count for a plain `cargo test` run — deliberately larger
/// than a quick smoke check now that each run is known-cheap (~ms) and
/// the point of a chaos/DST-style test is exploring many interleavings,
/// not confirming the plumbing works once. Override with `DST_VARIATIONS`
/// for a per-PR-sized fast run or a much larger soak-run/nightly sweep.
const PARALLEL_VARIATIONS: usize = 500;

/// One simulated run's observable history: what happened, in order, at
/// which point on the *simulated* clock. This is the artifact the
/// determinism test compares, and it is deliberately a trace rather than a
/// pass/fail — two runs that both satisfy the oracle can still have
/// explored different interleavings, and a substrate that claims seeded
/// determinism has to be held to the stronger statement.
type Trace = Arc<Mutex<Vec<String>>>;

fn run_scenario(seed: u64) -> Result<(), String> {
    run_scenario_traced(seed, Arc::new(Mutex::new(Vec::new())))
}

fn run_scenario_traced(seed: u64, trace: Trace) -> Result<(), String> {
    dst_support::sim::run_scenario(seed, move || scenario_body(seed, trace))
}

async fn scenario_body(seed: u64, trace: Trace) -> Result<(), String> {
    // Read once, at the start of simulated time, so every entry below is an
    // offset from the run's own origin rather than from whatever the
    // substrate's epoch happens to be.
    let started_at = tokio::time::Instant::now();
    let root_dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    // Canonicalize up front, matching what the real `watch_folder`
    // does to `root` internally (see watcher.rs's own tests for the
    // same note) -- macOS's tempdir lives under a `/var` path that's
    // itself a symlink to `/private/var`, so path-prefix stripping
    // during indexing would otherwise silently mismatch.
    let root: PathBuf = root_dir.path().canonicalize().map_err(|e| format!("canonicalize: {e}"))?;
    let store_dir = tempfile::tempdir().map_err(|e| format!("store tempdir: {e}"))?;
    let store = Arc::new(
        SegmentBlockStore::new(store_dir.path()).map_err(|e| format!("block store: {e}"))?,
    );
    let sync_state =
        Arc::new(ReplicaCoordinator::open_in_memory().map_err(|e| format!("sync state: {e}"))?);
    dst_support::link::link_and_start(&sync_state, &root, GROUP_ID)
        .map_err(|e| format!("link_and_start: {e}"))?;
    let processor = LocalChangeProcessor::new(
        sync_state.clone(),
        store.clone(),
        DEVICE_ID.to_string(),
        Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
    );

    let (watch_source, events_tx) = SimulatedFolderWatchSource::new(64);
    let ignore_set =
        Arc::new(yadorilink_fs_platform::ignore_patterns::EffectiveIgnoreSet::defaults_only());
    let watcher = watch_source.watch(&root, ignore_set).map_err(|e| format!("watch: {e}"))?;
    let (events_rx, overflowed, _guard) = watcher.split();

    let (flush_tx, mut flush_rx) =
        tokio::sync::mpsc::channel(debounce::DEFAULT_EXECUTOR_CHANNEL_CAPACITY);
    let (_flush_request_tx, flush_request_rx) = tokio::sync::mpsc::channel(4);
    let (_flush_all_request_tx, flush_all_request_rx) = tokio::sync::mpsc::channel(4);

    tokio::spawn(debounce::run_debouncer(
        DebounceConfig::default(),
        events_rx,
        flush_tx,
        overflowed,
        flush_request_rx,
        flush_all_request_rx,
    ));

    let executor_processor = processor;
    let executor_root = root.clone();
    let executor_trace = trace.clone();
    let executor = tokio::spawn(async move {
        while let Some(flush) = flush_rx.recv().await {
            // Recorded before the flush is consumed: the debouncer decided
            // both this batch's contents and the moment it fired, so those
            // two together are where a scheduler difference between two
            // runs of one seed would first become visible.
            record(&executor_trace, started_at, describe_flush(&flush));
            if let Err(e) = executor_processor.process_flush(GROUP_ID, &executor_root, flush).await
            {
                tracing::warn!(error = %e, "dst scenario: process_flush failed");
            }
        }
    });

    let mut rng = StdRng::seed_from_u64(seed);
    let oracle = WriteOracle::new();
    let candidate_names: Vec<String> = (0..6).map(|i| format!("dst-{i:02}.bin")).collect();

    for round in 0..OPS_PER_RUN {
        let name = &candidate_names[rng.random_range(0..candidate_names.len())];
        let path = root.join(name);
        let content = format!("seed {seed} round {round} name {name}");
        std::fs::write(&path, content.as_bytes()).map_err(|e| format!("write: {e}"))?;
        oracle.record_write(name, content.as_bytes());

        // The scenario controls exactly when the synthetic watcher event
        // is delivered relative to the real write above -- a randomized
        // simulated delay here is what makes different seeds actually
        // explore different debounce-window interleavings, unlike a real
        // OS watcher whose timing this process doesn't control.
        let delay_ms = rng.random_range(0..40);
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        record(&trace, started_at, format!("event round={round} name={name}"));
        events_tx
            .send(FsChangeEvent { path, kind: FsChangeKind::CreatedOrModified })
            .await
            .map_err(|_| "events channel closed early".to_string())?;
    }

    // Give the last window's own quiet period/max-flush-interval room to
    // fire under simulated time (fast-forwarded, not a real wall-clock
    // wait) before checking the index.
    tokio::time::sleep(DebounceConfig::default().max_flush_interval + Duration::from_millis(200))
        .await;
    drop(events_tx);
    let _ = executor.await;

    record(&trace, started_at, "settled".to_string());

    let violations = check_no_silent_data_loss(&oracle, &sync_state, GROUP_ID, &root);
    if !violations.is_empty() {
        return Err(format_violations(seed, &violations));
    }
    Ok(())
}

/// Appends one entry stamped with the *simulated* clock. Real elapsed time
/// is deliberately absent: it differs run to run on any substrate and would
/// make every trace comparison fail for reasons that say nothing about
/// scheduling.
fn record(trace: &Trace, started_at: tokio::time::Instant, what: String) {
    let at = tokio::time::Instant::now().duration_since(started_at);
    trace.lock().unwrap_or_else(|p| p.into_inner()).push(format!("{:>9}us {what}", at.as_micros()));
}

/// The flush's own contents, ordered, so the comparison sees *which* paths
/// the debouncer batched together and not merely how many.
fn describe_flush(flush: &debounce::DebounceFlush) -> String {
    match flush {
        debounce::DebounceFlush::Paths(entries) => {
            let mut names: Vec<String> = entries
                .iter()
                .map(|(path, kind, _observed_at)| {
                    let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
                    format!("{}:{kind:?}", name.unwrap_or_else(|| "<none>".to_string()))
                })
                .collect();
            // The accumulator's iteration order is its own business and is
            // not part of what this test pins; the *set* batched into one
            // window is.
            names.sort();
            format!("flush [{}]", names.join(" "))
        }
        other => format!("flush {other:?}"),
    }
}

/// The harness's actual day-to-day shape: not one seed, but many
/// independently-seeded runs driven concurrently, each fully isolated
/// and fully reproducible on its own. A failure reports its seed so it
/// can be re-run in isolation (`DST_SEED=<seed> cargo test...
/// single_seed_smoke`, or `run_scenario(seed)` directly) to reproduce.
///
/// `DST_VARIATIONS` overrides how many seeds this run explores (default
/// `PARALLEL_VARIATIONS`) — a small fixed count is enough for a fast
/// per-PR check, a much larger one (thousands) for a soak-run/nightly
/// sweep; each simulated run
/// costs low-single-digit milliseconds since simulated time is
/// fast-forwarded, so scaling this up is cheap. Bounded to
/// `available_parallelism` concurrent OS threads (a shared work queue,
/// not one real thread per seed) so a large `DST_VARIATIONS` doesn't
/// spawn thousands of real threads at once.
#[test]
fn run_many_seeded_variations_in_parallel() {
    let base_seed: u64 =
        std::env::var("DST_BASE_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(0xD57_0000);
    let variations: u64 = std::env::var("DST_VARIATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(PARALLEL_VARIATIONS as u64);
    let worker_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(usize::try_from(variations).unwrap_or(usize::MAX).max(1));

    let next_index = AtomicU64::new(0);
    let failures: Mutex<Vec<String>> = Mutex::new(Vec::new());

    std::thread::scope(|scope| {
        for _ in 0..worker_count {
            scope.spawn(|| loop {
                let i = next_index.fetch_add(1, Ordering::Relaxed);
                if i >= variations {
                    break;
                }
                let seed = base_seed.wrapping_add(i);
                if let Err(err) = run_scenario(seed) {
                    failures
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .push(format!("seed {seed}: {err}"));
                }
            });
        }
    });

    let failures = failures.into_inner().unwrap_or_else(|p| p.into_inner());
    assert!(
        failures.is_empty(),
        "{}/{variations} DST variations failed:\n{}\n(reproduce one with DST_SEED=<seed> cargo test ... single_seed_smoke, or call run_scenario(seed) directly)",
        failures.len(),
        failures.join("\n")
    );
}

/// Single-seed entry point for reproducing a specific failure reported by
/// `run_many_seeded_variations_in_parallel` above.
#[test]
fn single_seed_smoke() {
    let seed: u64 = std::env::var("DST_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(1);
    run_scenario(seed).unwrap_or_else(|e| panic!("seed {seed} failed: {e}"));
}

fn trace_of(seed: u64) -> Vec<String> {
    let trace: Trace = Arc::new(Mutex::new(Vec::new()));
    run_scenario_traced(seed, trace.clone())
        .unwrap_or_else(|e| panic!("seed {seed} failed while tracing: {e}"));
    let collected = trace.lock().unwrap_or_else(|p| p.into_inner()).clone();
    // A trace of events alone would still be seed-varying and still compare
    // equal to itself, so both determinism tests below would pass while
    // pinning nothing about the code under test. The debouncer has to have
    // actually fired.
    assert!(
        collected.iter().any(|entry| entry.contains("flush ")),
        "seed {seed} produced a trace with no flush in it, so it pins nothing about the \
         debouncer:\n{}",
        collected.join("\n")
    );
    collected
}

/// The property that makes this a *deterministic* simulation rather than a
/// randomized one: a seed names an execution, not just a distribution.
///
/// A green oracle does not establish this. Two runs can both satisfy the
/// no-silent-data-loss invariant while having batched entirely different
/// events into entirely different debounce windows, and a substrate that
/// did that would reproduce no failure it ever reported. So the comparison
/// is over the observable history — which events fired, at which point on
/// the simulated clock, and which paths the debouncer grouped into each
/// flush.
#[test]
fn the_same_seed_reproduces_the_same_history() {
    const SEED: u64 = 0xD57_D37;
    let first = trace_of(SEED);
    let second = trace_of(SEED);
    assert_eq!(
        first, second,
        "the same seed produced two different histories, so no failure this harness reports \
         could be reproduced from its seed"
    );
}

/// The other half of the same property, and the reason the seed loop is
/// worth running at all: distinct seeds must actually reach distinct
/// executions. A substrate that was perfectly reproducible but ignored the
/// seed would pass the test above while exploring one interleaving 500
/// times.
#[test]
fn different_seeds_reach_different_histories() {
    let traces: Vec<Vec<String>> = (0..8).map(|i| trace_of(0xD57_D37 + i)).collect();
    let distinct: std::collections::HashSet<&Vec<String>> = traces.iter().collect();
    assert!(
        distinct.len() > 1,
        "8 different seeds all produced the identical history, so the seed is not reaching the \
         scheduler:\n{}",
        traces[0].join("\n")
    );
}
