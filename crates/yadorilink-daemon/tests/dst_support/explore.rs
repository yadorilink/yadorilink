//! Unattended exploration: seeded random walks over fault sequences at the
//! capture boundary, a bounded budget, automatic minimization of a failing
//! seed, and a written triage report that needs no one to reproduce.
//!
//! # The walk
//!
//! A walk is a list of [`Act`]s drawn from a seed alone: file operations,
//! holding and releasing the debounce window, writes and deletes the watcher
//! never reports, clock jumps, the index refusing the journal and healing, a
//! process restart (memory gone, the index file reopened) and a recovery
//! (rescan and re-drive). It runs on the real capture pipeline
//! ([`Device`]), the same one `risk_matrix_gate` and `boundary_gate` use.
//!
//! # The oracle
//!
//! The disk is the truth and shares no code with the pipeline. When the walk
//! lost nothing (no unreported change, no restart, no refused flush), the index
//! must equal the disk as it stands. When it lost something, the product's
//! recovery runs first (heal the journal, rescan, re-drive) and then the index
//! must equal the disk, and a second recovery must change nothing. "Equal"
//! means:
//!
//! * every file on the disk is live in the index with the hash its bytes give
//!   (no loss of data the pipeline was handed or could find);
//! * every live indexed file is on the disk (no resurrected delete);
//! * no live indexed path was never touched by the walk (no phantom or
//!   conflict-copy explosion).
//!
//! # Budget, minimization, report
//!
//! [`explore`] walks seeds from a start seed until a wall-clock budget or a
//! seed count runs out. Each failing seed is minimized with a delta-debugging
//! pass (chunks, then single acts) and written as JSON (`failures/seed-N.json`)
//! plus the same acts as Rust source (`failures/seed-N.rs`), with a one-line
//! replay command, into `report.md`. Replaying a JSON file
//! (`cargo dst-explore --replay <file>`) re-runs exactly that minimized walk
//! and fails if it still fails. A file dropped into `tests/dst_corpus/explore/`
//! is replayed by every run of `dst_explore` and must then pass: that is how a
//! fixed failure becomes a regression test.

#![cfg(turmoil)]
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use serde::{Deserialize, Serialize};
use yadorilink_filesystem_sync::debounce::DebounceFlush;
use yadorilink_filesystem_sync::watcher::FsChangeKind;
use yadorilink_local_storage::{BlockStore, SegmentBlockStore};

use super::boundary_device::{Defect, Device, GROUP};
use super::case_ir::{DiskFault, Fault, Op, SimNanos};
use super::directory_model::ExplicitModel;
use super::fault_schedule::{run_schedule, ScheduledInjectors};
use super::fault_sqlite::JournalFault;
use super::fs_events::{coalesce, WatchEvent};

/// The names a walk touches. Flat on purpose: a directory is a different
/// record kind and not what this walk explores.
pub const NAMES: [&str; 4] = ["a", "b", "c", "d"];

/// Clock targets: the epoch, the past, the present, the far future.
const CLOCKS: [i64; 4] =
    [0, 1_600_000_000_000_000_000, 1_700_000_000_000_000_000, 4_000_000_000_000_000_000];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Act {
    Write {
        path: String,
        content: u64,
    },
    Delete {
        path: String,
    },
    Rename {
        from: String,
        to: String,
    },
    /// Hold watcher events (the debounce window stays open).
    Pause,
    /// Deliver what was held.
    Retry,
    /// A write the watcher never reports.
    SilentWrite {
        path: String,
        content: u64,
    },
    /// A delete the watcher never reports.
    SilentDelete {
        path: String,
    },
    /// A write whose requester gave up: the edit is handed to the journal
    /// (which the index may refuse) instead of being flushed.
    HandOffWrite {
        path: String,
        content: u64,
    },
    /// The same for a delete.
    HandOffDelete {
        path: String,
    },
    Clock {
        to_unix_nanos: i64,
    },
    /// The index starts refusing the journal's writes.
    JournalFail,
    JournalHeal,
    /// The process restarts: held events and in-memory retries are gone.
    Restart,
    /// The product's recovery: rescan, then re-drive the journal.
    Recover,
}

impl Act {
    /// The act as Rust source, for a regression test written by hand.
    pub fn to_rust(&self) -> String {
        match self {
            Act::Write { path, content } => {
                format!("Act::Write {{ path: {path:?}.into(), content: {content} }}")
            }
            Act::Delete { path } => format!("Act::Delete {{ path: {path:?}.into() }}"),
            Act::Rename { from, to } => {
                format!("Act::Rename {{ from: {from:?}.into(), to: {to:?}.into() }}")
            }
            Act::Pause => "Act::Pause".into(),
            Act::Retry => "Act::Retry".into(),
            Act::SilentWrite { path, content } => {
                format!("Act::SilentWrite {{ path: {path:?}.into(), content: {content} }}")
            }
            Act::SilentDelete { path } => format!("Act::SilentDelete {{ path: {path:?}.into() }}"),
            Act::HandOffWrite { path, content } => {
                format!("Act::HandOffWrite {{ path: {path:?}.into(), content: {content} }}")
            }
            Act::HandOffDelete { path } => {
                format!("Act::HandOffDelete {{ path: {path:?}.into() }}")
            }
            Act::Clock { to_unix_nanos } => {
                format!("Act::Clock {{ to_unix_nanos: {to_unix_nanos} }}")
            }
            Act::JournalFail => "Act::JournalFail".into(),
            Act::JournalHeal => "Act::JournalHeal".into(),
            Act::Restart => "Act::Restart".into(),
            Act::Recover => "Act::Recover".into(),
        }
    }

    /// Whether the act can leave the pipeline owing something only a rescan
    /// finds: a change no event reported, or events a restart dropped.
    fn needs_rescan(&self) -> bool {
        matches!(self, Act::SilentWrite { .. } | Act::SilentDelete { .. } | Act::Restart)
    }

    /// Whether the act can leave the journal owing an edit that its re-drive
    /// (and nothing else) must commit.
    fn owes_journal(&self) -> bool {
        matches!(self, Act::HandOffWrite { .. } | Act::HandOffDelete { .. } | Act::JournalFail)
    }

    fn loses_events(&self) -> bool {
        self.needs_rescan() || self.owes_journal()
    }
}

fn write(path: &str, content: u64) -> Act {
    Act::Write { path: path.into(), content }
}

/// A walk of 6 to 18 acts, deterministic from `seed`. One walk in three is
/// "clean": it draws no act that loses events, so the pipeline has to be exactly
/// right with no rescan to fall back on. Without those the final recovery
/// would mask any defect in the plain delivery path.
pub fn generate(seed: u64) -> Vec<Act> {
    let mut rng = StdRng::seed_from_u64(seed ^ 0xE5_9101);
    let len = rng.random_range(6..=18);
    let clean = rng.random_range(0..3) == 0;
    let name = |rng: &mut StdRng| NAMES[rng.random_range(0..NAMES.len())];
    let mut acts = Vec::with_capacity(len);
    while acts.len() < len {
        let act = match rng.random_range(0..24) {
            0..=4 => write(name(&mut rng), rng.random_range(1..=3)),
            5 | 6 => Act::Delete { path: name(&mut rng).into() },
            7 | 8 => Act::Rename { from: name(&mut rng).into(), to: name(&mut rng).into() },
            9 => Act::Pause,
            10 => Act::Retry,
            11 => {
                Act::SilentWrite { path: name(&mut rng).into(), content: rng.random_range(1..=3) }
            }
            12 => Act::SilentDelete { path: name(&mut rng).into() },
            13 => Act::Clock { to_unix_nanos: CLOCKS[rng.random_range(0..CLOCKS.len())] },
            14 => Act::JournalFail,
            15 => Act::JournalHeal,
            16 => Act::Restart,
            17 | 18 => Act::Recover,
            19 | 20 => {
                Act::HandOffWrite { path: name(&mut rng).into(), content: rng.random_range(1..=3) }
            }
            21 | 22 => Act::HandOffDelete { path: name(&mut rng).into() },
            _ => write(name(&mut rng), rng.random_range(1..=3)),
        };
        if !(clean && act.loses_events()) {
            acts.push(act);
        }
    }
    acts
}

/// What a walk exercised, so a green run says what it covered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    pub acts: usize,
    pub skipped_ill_formed: usize,
    pub restarts: usize,
    pub recoveries: usize,
    pub clock_jumps: usize,
    pub journal_fail_windows: usize,
    pub refused_flushes: usize,
    pub refused_handoffs: usize,
    pub lost_events: usize,
}

fn disk_files(root: &Path) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(root)
        .expect("list root")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_file())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| !name.starts_with(".yadorilink"))
        .map(|name| {
            let bytes = std::fs::read(root.join(&name)).expect("read");
            (name, bytes)
        })
        .collect()
}

fn live_index(device: &Device) -> BTreeMap<String, String> {
    device.live_index()
}

fn expected_hashes(files: &BTreeMap<String, Vec<u8>>) -> BTreeMap<String, String> {
    let scratch = tempfile::tempdir().expect("scratch");
    let store = SegmentBlockStore::new(scratch.path()).expect("scratch store");
    files.iter().map(|(n, b)| (n.clone(), store.put(b).expect("hash"))).collect()
}

/// The oracle: the index against the disk.
fn judge(device: &Device, touched: &BTreeSet<String>) -> Result<(), String> {
    let (disk, index) = (disk_files(&device.root), live_index(device));
    let want = expected_hashes(&disk);
    let mut problems = Vec::new();
    for (path, hash) in &want {
        match index.get(path) {
            None => problems.push(format!("`{path}` is on disk but not live in the index")),
            Some(have) if have != hash => {
                problems.push(format!("`{path}` is indexed with other content than the disk's"));
            }
            Some(_) => {}
        }
    }
    for path in index.keys().filter(|p| !want.contains_key(*p)) {
        problems.push(format!("`{path}` is live in the index but gone from the disk"));
    }
    for path in index.keys().filter(|p| !touched.contains(*p)) {
        problems.push(format!("`{path}` is live in the index but the walk never touched it"));
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

async fn recover(device: &Device) -> Result<(), String> {
    device
        .processor
        .process_flush(GROUP, &device.root, DebounceFlush::RescanRequired)
        .await
        .map_err(|e| format!("rescan: {e}"))?;
    device
        .processor
        .redrive_dirty_journal(GROUP, &device.root)
        .await
        .map_err(|e| format!("redrive: {e}"))?;
    Ok(())
}

fn without_defect(defect: Defect, mut events: Vec<WatchEvent>) -> Vec<WatchEvent> {
    events.retain(|e| {
        !matches!(
            (defect, e.kind),
            (Defect::DropRemovals, FsChangeKind::ObservedRemoval)
                | (Defect::DropCreations, FsChangeKind::CreatedOrModified)
        )
    });
    events
}

/// Runs the walk on a fresh device and judges it. `defect` plants a pipeline
/// fault so a test can show the walk finds it.
pub async fn check(acts: &[Act], defect: Defect) -> Result<Stats, String> {
    let spec = vec![(SimNanos::ZERO, Fault::Disk(DiskFault::SqliteBusy))];
    let injectors = ScheduledInjectors::for_spec(&spec).map_err(|e| e.to_string())?;
    run_schedule(spec, injectors.clone()).await.map_err(|e| e.to_string())?;

    let db_dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let db = db_dir.path().join("index.db");
    let mut device = Device::over_file(&db);
    let fault = JournalFault::new(&db, &injectors);

    let mut model = ExplicitModel::default();
    let (mut paused, mut window): (bool, Vec<WatchEvent>) = (false, Vec::new());
    let mut touched = BTreeSet::new();
    let mut stats = Stats { acts: acts.len(), ..Stats::default() };
    let mut journal_failing = false;
    let mut lost = false;
    let mut owes_journal = false;

    for act in acts {
        match act {
            Act::Write { path, content } | Act::SilentWrite { path, content } => {
                let op = Op::Write { path: path.clone(), content_id: *content };
                if model.apply(&op).is_err() {
                    stats.skipped_ill_formed += 1;
                    continue;
                }
                touched.insert(path.clone());
                let events = device.apply_to_disk(&op);
                if matches!(act, Act::SilentWrite { .. }) {
                    stats.lost_events += 1;
                } else {
                    deliver(
                        &device,
                        defect,
                        events,
                        paused,
                        &mut window,
                        &mut stats,
                        journal_failing,
                        &mut lost,
                    )
                    .await;
                }
            }
            Act::Delete { path } | Act::SilentDelete { path } => {
                let op = Op::Delete { path: path.clone() };
                if model.apply(&op).is_err() {
                    stats.skipped_ill_formed += 1;
                    continue;
                }
                touched.insert(path.clone());
                let events = device.apply_to_disk(&op);
                if matches!(act, Act::SilentDelete { .. }) {
                    stats.lost_events += 1;
                } else {
                    deliver(
                        &device,
                        defect,
                        events,
                        paused,
                        &mut window,
                        &mut stats,
                        journal_failing,
                        &mut lost,
                    )
                    .await;
                }
            }
            Act::HandOffWrite { path, .. } | Act::HandOffDelete { path } => {
                let (op, kind) = match act {
                    Act::HandOffWrite { content, .. } => (
                        Op::Write { path: path.clone(), content_id: *content },
                        FsChangeKind::CreatedOrModified,
                    ),
                    _ => (Op::Delete { path: path.clone() }, FsChangeKind::ObservedRemoval),
                };
                if model.apply(&op).is_err() {
                    stats.skipped_ill_formed += 1;
                    continue;
                }
                touched.insert(path.clone());
                device.apply_to_disk(&op);
                let edit = [(device.root.join(path), kind, 2)];
                let result = device.processor.journal_handed_over_edits(GROUP, &device.root, &edit);
                if fault.observe(result).is_err() {
                    stats.refused_handoffs += 1;
                }
            }
            Act::Rename { from, to } => {
                let op = Op::Rename { from: from.clone(), to: to.clone() };
                if model.apply(&op).is_err() {
                    stats.skipped_ill_formed += 1;
                    continue;
                }
                touched.insert(from.clone());
                touched.insert(to.clone());
                let events = device.apply_to_disk(&op);
                deliver(
                    &device,
                    defect,
                    events,
                    paused,
                    &mut window,
                    &mut stats,
                    journal_failing,
                    &mut lost,
                )
                .await;
            }
            Act::Pause => paused = true,
            Act::Retry => {
                let events = coalesce(std::mem::take(&mut window));
                paused = false;
                deliver(
                    &device,
                    defect,
                    events,
                    false,
                    &mut window,
                    &mut stats,
                    journal_failing,
                    &mut lost,
                )
                .await;
            }
            Act::Clock { to_unix_nanos } => {
                stats.clock_jumps += 1;
                device.apply_clock_fault(&Fault::ClockJump {
                    device: 0,
                    to_unix_nanos: *to_unix_nanos,
                });
            }
            Act::JournalFail => {
                if !journal_failing {
                    stats.journal_fail_windows += 1;
                }
                fault.engage();
                journal_failing = true;
            }
            Act::JournalHeal => {
                fault.heal();
                journal_failing = false;
            }
            Act::Restart => {
                stats.restarts += 1;
                window.clear();
                paused = false;
                device.restart_over_file(&db);
            }
            Act::Recover => {
                stats.recoveries += 1;
                // A recovery that errors is the pipeline refusing; it is
                // retried by the final recovery after the journal heals.
                let _ = recover(&device).await;
            }
        }
        // Only an act that was carried out can leave anything owed: a skipped
        // (ill-formed) act must not enable a recovery that hides a defect.
        lost |= act.needs_rescan();
        owes_journal |= act.owes_journal();
    }

    // The walk ends: whatever is held is delivered (the debouncer fires), the
    // journal heals, and the product recovers if the walk lost anything.
    let events = coalesce(std::mem::take(&mut window));
    deliver(&device, defect, events, false, &mut window, &mut stats, journal_failing, &mut lost)
        .await;
    let rescans = lost || stats.refused_flushes > 0;
    if rescans {
        fault.heal();
        recover(&device).await.map_err(|e| format!("final recovery failed: {e}"))?;
    } else if owes_journal {
        // Only the journal owes something: its re-drive, and nothing else,
        // must commit it. A rescan here would hide a re-drive that gives up.
        fault.heal();
        device
            .processor
            .redrive_dirty_journal(GROUP, &device.root)
            .await
            .map_err(|e| format!("final redrive failed: {e}"))?;
    }
    judge(&device, &touched).map_err(|e| format!("{e} (after {stats:?})"))?;
    if rescans || owes_journal {
        let before = live_index(&device);
        recover(&device).await.map_err(|e| format!("second recovery failed: {e}"))?;
        if live_index(&device) != before {
            return Err("a second recovery changed the index: the state is not stable".into());
        }
    }
    Ok(stats)
}

#[allow(clippy::too_many_arguments)]
async fn deliver(
    device: &Device,
    defect: Defect,
    events: Vec<WatchEvent>,
    paused: bool,
    window: &mut Vec<WatchEvent>,
    stats: &mut Stats,
    _journal_failing: bool,
    lost: &mut bool,
) {
    let events = without_defect(defect, events);
    if paused {
        window.extend(events);
        return;
    }
    if device.try_flush_events(events).await.is_err() {
        // A refused flush: the daemon would retry; the walk treats the events
        // as lost and leaves them to the recovery.
        stats.refused_flushes += 1;
        *lost = true;
    }
}

/// Delta-debugging minimizer: drop chunks of halving size, then single acts,
/// until no removal still fails.
pub async fn shrink<F, Fut>(mut acts: Vec<Act>, mut still_fails: F) -> Vec<Act>
where
    F: FnMut(Vec<Act>) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let mut chunk = acts.len().div_ceil(2).max(1);
    loop {
        let mut removed_any = false;
        let mut start = 0;
        while start < acts.len() {
            let end = (start + chunk).min(acts.len());
            let mut candidate = acts.clone();
            candidate.drain(start..end);
            if still_fails(candidate.clone()).await {
                acts = candidate;
                removed_any = true;
            } else {
                start = end;
            }
        }
        if chunk == 1 && !removed_any {
            return acts;
        }
        chunk = if removed_any { chunk } else { (chunk / 2).max(1) };
    }
}

/// One failing seed, minimized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Failure {
    pub seed: u64,
    pub violation: String,
    pub original_len: usize,
    pub minimal: Vec<Act>,
}

/// A replayable walk, as stored in the corpus and in a failure file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Replay {
    pub seed: Option<u64>,
    pub acts: Vec<Act>,
    pub violation: Option<String>,
}

pub struct ExploreConfig {
    pub start_seed: u64,
    pub max_seeds: u64,
    pub budget: Duration,
    /// Stops after this many failures: each costs a minimization.
    pub max_failures: usize,
    pub defect: Defect,
}

pub struct Report {
    pub config_start: u64,
    pub seeds_run: u64,
    pub elapsed: Duration,
    pub coverage: Stats,
    pub failures: Vec<Failure>,
    pub budget_exhausted: bool,
}

/// Walks seeds `start_seed..` until the budget or `max_seeds` is spent;
/// minimizes each failure.
pub async fn explore(config: &ExploreConfig) -> Report {
    let started = Instant::now();
    let mut report = Report {
        config_start: config.start_seed,
        seeds_run: 0,
        elapsed: Duration::ZERO,
        coverage: Stats::default(),
        failures: Vec::new(),
        budget_exhausted: false,
    };
    for seed in config.start_seed..config.start_seed.saturating_add(config.max_seeds) {
        if started.elapsed() >= config.budget {
            report.budget_exhausted = true;
            break;
        }
        let acts = generate(seed);
        report.seeds_run += 1;
        match check(&acts, config.defect).await {
            Ok(stats) => {
                let c = &mut report.coverage;
                c.acts += stats.acts;
                c.skipped_ill_formed += stats.skipped_ill_formed;
                c.restarts += stats.restarts;
                c.recoveries += stats.recoveries;
                c.clock_jumps += stats.clock_jumps;
                c.journal_fail_windows += stats.journal_fail_windows;
                c.refused_flushes += stats.refused_flushes;
                c.refused_handoffs += stats.refused_handoffs;
                c.lost_events += stats.lost_events;
            }
            Err(violation) => {
                let defect = config.defect;
                let original_len = acts.len();
                let minimal =
                    shrink(
                        acts,
                        |candidate| async move { check(&candidate, defect).await.is_err() },
                    )
                    .await;
                let violation = check(&minimal, defect).await.err().unwrap_or(violation);
                report.failures.push(Failure { seed, violation, original_len, minimal });
                if report.failures.len() >= config.max_failures {
                    break;
                }
            }
        }
    }
    report.elapsed = started.elapsed();
    report
}

/// Writes `report.md` and one JSON and one Rust file per failure into `out`.
/// Returns the report path. `replay_prefix` is the command that replays a
/// file, e.g. `cargo dst-explore --replay`.
pub fn write_report(report: &Report, out: &Path, replay_prefix: &str) -> std::io::Result<PathBuf> {
    let failures_dir = out.join("failures");
    std::fs::create_dir_all(&failures_dir)?;
    let mut md = String::new();
    md.push_str("# DST exploration report\n\n");
    md.push_str(&format!(
        "- seeds run: {} (from seed {}), elapsed {:.1}s{}\n",
        report.seeds_run,
        report.config_start,
        report.elapsed.as_secs_f64(),
        if report.budget_exhausted { ", stopped by the time budget" } else { "" }
    ));
    let c = &report.coverage;
    md.push_str(&format!(
        "- coverage of passing walks: {} acts, {} restarts, {} recoveries, {} clock jumps, {} journal-refusal windows, {} refused flushes, {} refused journal hand-offs, {} lost events, {} ill-formed acts skipped\n",
        c.acts, c.restarts, c.recoveries, c.clock_jumps, c.journal_fail_windows, c.refused_flushes, c.refused_handoffs, c.lost_events, c.skipped_ill_formed
    ));
    md.push_str(&format!("- failures: {}\n\n", report.failures.len()));
    if report.failures.is_empty() {
        md.push_str("No walk violated an invariant in this budget.\n");
    }
    for failure in &report.failures {
        let json_name = format!("seed-{}.json", failure.seed);
        let json_path = failures_dir.join(&json_name);
        let replay = Replay {
            seed: Some(failure.seed),
            acts: failure.minimal.clone(),
            violation: Some(failure.violation.clone()),
        };
        std::fs::write(&json_path, serde_json::to_string_pretty(&replay).expect("json"))?;
        let rust: Vec<String> = failure.minimal.iter().map(Act::to_rust).collect();
        std::fs::write(
            failures_dir.join(format!("seed-{}.rs", failure.seed)),
            format!(
                "// Minimized from seed {} ({} acts down to {}).\n// Violation: {}\n\
                 #[test]\nfn explore_regression_seed_{}() {{\n    sim(|| async {{\n        \
                 let acts = vec![\n            {}\n        ];\n        \
                 check(&acts, Defect::None).await.expect(\"the walk still violates an invariant\");\n    }});\n}}\n",
                failure.seed,
                failure.original_len,
                failure.minimal.len(),
                failure.violation,
                failure.seed,
                rust.join(",\n            ")
            ),
        )?;
        md.push_str(&format!(
            "## Seed {}\n\n- violation: {}\n- minimized: {} acts (from {})\n- replay, from a checkout of the commit that ran (works on a downloaded artifact too): `{} <this report's directory>/failures/{}`\n- regression test: copy `failures/{}` into `crates/yadorilink-daemon/tests/dst_corpus/explore/` once fixed (it is replayed by every `dst_explore` run), or paste `seed-{}.rs`\n- acts:\n",
            failure.seed,
            failure.violation,
            failure.minimal.len(),
            failure.original_len,
            replay_prefix,
            json_name,
            json_name,
            failure.seed
        ));
        for act in &failure.minimal {
            md.push_str(&format!("  1. `{act:?}`\n"));
        }
        md.push('\n');
    }
    let path = out.join("report.md");
    std::fs::write(&path, md)?;
    Ok(path)
}

/// Every replay file under `dir` (the promoted regressions).
pub fn load_corpus(dir: &Path) -> Vec<(PathBuf, Replay)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return out };
    let mut paths: Vec<_> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
    paths.sort();
    for path in paths.into_iter().filter(|p| p.extension().is_some_and(|e| e == "json")) {
        let text = std::fs::read_to_string(&path).expect("read corpus file");
        let replay: Replay = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("{}: not a replay file: {e}", path.display()));
        out.push((path, replay));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sim<F: std::future::Future<Output = ()> + 'static>(f: impl FnOnce() -> F + 'static) {
        super::super::sim::block_on(1, f);
    }

    #[test]
    fn generation_is_deterministic_and_varied() {
        assert_eq!(generate(5), generate(5));
        assert_ne!(generate(5), generate(6));
        let all: Vec<Act> = (0..300).flat_map(generate).collect();
        for needle in [
            |a: &Act| matches!(a, Act::Restart),
            |a: &Act| matches!(a, Act::JournalFail),
            |a: &Act| matches!(a, Act::SilentDelete { .. }),
            |a: &Act| matches!(a, Act::Clock { .. }),
            |a: &Act| matches!(a, Act::Rename { .. }),
        ] {
            assert!(all.iter().any(needle), "a kind of act is never generated");
        }
    }

    /// The healthy pipeline passes a sweep of seeds, and the sweep reached
    /// the faults it claims to explore.
    #[test]
    fn the_healthy_pipeline_passes_and_the_walks_reach_the_faults() {
        sim(|| async {
            let report = explore(&ExploreConfig {
                start_seed: 0,
                max_seeds: smoke_seeds(),
                budget: Duration::from_secs(600),
                max_failures: 3,
                defect: Defect::None,
            })
            .await;
            assert!(
                report.failures.is_empty(),
                "{:?}",
                report
                    .failures
                    .iter()
                    .map(|f| (f.seed, &f.violation, &f.minimal))
                    .collect::<Vec<_>>()
            );
            let c = &report.coverage;
            assert!(c.restarts > 0 && c.recoveries > 0 && c.clock_jumps > 0, "{c:?}");
            assert!(c.journal_fail_windows > 0 && c.lost_events > 0, "{c:?}");
            assert!(c.refused_handoffs > 0, "no journal refusal ever fired: {c:?}");
        });
    }

    fn smoke_seeds() -> u64 {
        std::env::var("DST_EXPLORE_SMOKE_SEEDS").ok().and_then(|v| v.parse().ok()).unwrap_or(40)
    }

    /// A planted pipeline defect is found, minimized to the smallest walk that
    /// shows it, and reported with a replay file that fails the defective
    /// pipeline and passes the real one.
    #[test]
    fn a_planted_defect_is_found_minimized_and_reported() {
        sim(|| async {
            for (defect, minimal_len) in [(Defect::DropRemovals, 2), (Defect::DropCreations, 1)] {
                let report = explore(&ExploreConfig {
                    start_seed: 0,
                    max_seeds: 120,
                    budget: Duration::from_secs(600),
                    max_failures: 1,
                    defect,
                })
                .await;
                let failure =
                    report.failures.first().unwrap_or_else(|| panic!("{defect:?} unnoticed"));
                assert_eq!(failure.minimal.len(), minimal_len, "{defect:?}: {:?}", failure.minimal);
                assert!(check(&failure.minimal, defect).await.is_err());
                check(&failure.minimal, Defect::None)
                    .await
                    .expect("the real pipeline fails it too");

                let out = tempfile::tempdir().unwrap();
                let path = write_report(&report, out.path(), "cargo dst-explore --replay").unwrap();
                let md = std::fs::read_to_string(path).unwrap();
                assert!(
                    md.contains("`cargo dst-explore --replay <this report's directory>/failures/"),
                    "{md}"
                );
                assert!(md.contains(&format!("## Seed {}", failure.seed)));
                let corpus = load_corpus(&out.path().join("failures"));
                assert_eq!(corpus.len(), report.failures.len());
                assert_eq!(corpus[0].1.acts, failure.minimal);
                let rust = std::fs::read_to_string(
                    out.path().join("failures").join(format!("seed-{}.rs", failure.seed)),
                )
                .unwrap();
                assert!(rust.contains("explore_regression_seed_"));
            }
        });
    }

    /// The budget bounds the run.
    #[test]
    fn a_zero_budget_runs_no_walk() {
        sim(|| async {
            let report = explore(&ExploreConfig {
                start_seed: 0,
                max_seeds: 1000,
                budget: Duration::ZERO,
                max_failures: 1,
                defect: Defect::None,
            })
            .await;
            assert_eq!(report.seeds_run, 0);
            assert!(report.budget_exhausted);
        });
    }
}
