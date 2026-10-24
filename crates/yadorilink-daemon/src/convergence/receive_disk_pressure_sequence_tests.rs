#![cfg(test)]

//! An ordered fault sequence on the receive side: the volume is below its
//! headroom while files arrive, the engine tries again and again (and is
//! replaced partway), and then the space comes back. Nothing tells the engine
//! that it did: there is no new admission and no new watcher event. The files
//! must land by themselves.
//!
//! Safety invariants, each read from the disk and the obligation table and not
//! from the code that decides them:
//!
//! * while the pressure holds, a refused file is not written, no temp file is
//!   left, a file received before the pressure is untouched, and the
//!   obligation to place the refused file stays open;
//! * the wait before the next attempt never grows past a bound, so an
//!   obligation cannot be pushed out of reach by repeated refusals;
//! * once the space is back and the backoff has run its (bounded) course, every
//!   file lands with exactly the bytes its version names and its obligation
//!   settles.
//!
//! The fault is credited where the product asks the volume for its free space
//! (`free_space_probe`, called inside the real headroom preflight): a refusal
//! counts only if the product's own preflight ran under the pressure. A run in
//! which the pressure never reached the preflight fails
//! ([`a_pressure_that_never_reaches_the_preflight_fails_the_gate`]). The
//! sequence is a function of its seed alone: `DST_SEQUENCES=<n>` widens the
//! seed sweep for the weekly exploration.
//!
//! What this does not cover: a restart is the engine being replaced over the
//! same database and executor, not a new process; the real free-space query
//! (here replaced by the executor's test seam) is covered by the
//! `hydration` and `files_that_fit...` tests. The status surface is read here as the
//! daemon's Degraded state of the link (what `yadorilink status` and the status API
//! report): "Waiting for disk space" with the free and the kept-free bytes while the
//! pressure holds, cleared by the pass that gets through once the space is back. The
//! pressure is the executor's fake free space against an enforced headroom, not a
//! small real volume.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use yadorilink_sync_sqlite::projection_obligations::lookup_projection_obligation;

use super::engine::{drive_obligations_once_for_test, ConvergenceEngine};
use super::receive_cost_tests::{content_of, fixture, Fixture, GROUP};

const MIB: u64 = 1024 * 1024;

/// The longest the engine may defer a path after a refusal: the backoff cap
/// (30 s) with its jitter (+25%) and some slack.
const MAX_DEFERRAL_NANOS: i64 = 40_000_000_000;

/// The ordered sequence of one seed.
#[derive(Debug, Clone)]
struct Sequence {
    seed: u64,
    /// Files that arrive while the volume is full.
    files: usize,
    /// Engine passes that run under the pressure.
    pressured_passes: usize,
    /// The pass after which the engine is replaced, if any.
    restart_after: Option<usize>,
}

impl Sequence {
    fn from_seed(seed: u64) -> Self {
        // The two minimized rows `cargo dst-gate` always runs: the longest
        // stall (enough refusals for an unbounded backoff to show, the
        // engine replaced partway) and the shortest (one refusal).
        match seed {
            0 => {
                return Self { seed, files: 3, pressured_passes: 8, restart_after: Some(3) };
            }
            1 => {
                return Self { seed, files: 2, pressured_passes: 1, restart_after: None };
            }
            _ => {}
        }
        let mut rng = StdRng::seed_from_u64(seed);
        let pressured_passes = rng.random_range(1..=9);
        Self {
            seed,
            files: rng.random_range(2..=4),
            pressured_passes,
            restart_after: rng.random_bool(0.5).then(|| rng.random_range(0..pressured_passes)),
        }
    }
}

/// Whether the pressure is on, and how often the product's preflight ran
/// under it.
struct Pressure {
    on: AtomicBool,
    refusals: AtomicUsize,
}

fn install_pressure(f: &Fixture, pressure: &Arc<Pressure>) {
    f.executor.set_headroom_enforced_for_tests(true);
    f.executor.set_headroom_override_bytes_for_tests(Some(1 << 30));
    *f.executor.fake_available_bytes.lock().unwrap() = Some(u64::MAX / 2);
    let seen = pressure.clone();
    // Weak: the executor owns this callback, so a strong handle would be a cycle.
    let executor = Arc::downgrade(&f.executor);
    *f.executor.free_space_probe.lock().unwrap() = Some(Arc::new(move || {
        let Some(executor) = executor.upgrade() else { return };
        if seen.on.load(Ordering::SeqCst) {
            seen.refusals.fetch_add(1, Ordering::SeqCst);
            *executor.fake_available_bytes.lock().unwrap() = Some(MIB);
        } else {
            *executor.fake_available_bytes.lock().unwrap() = Some(u64::MAX / 2);
        }
    }));
}

fn temp_files(f: &Fixture) -> Vec<String> {
    std::fs::read_dir(&f.root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".yadorilink-tmp."))
        .collect()
}

fn obligation(
    f: &Fixture,
    name: &str,
) -> Option<yadorilink_sync_sqlite::projection_obligations::ProjectionObligation> {
    f.state
        .replica_coordinator
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            lookup_projection_obligation(conn, GROUP, name)
        })
        .unwrap()
}

/// Time passing: every deferral has run out.
fn let_backoff_elapse(f: &Fixture) {
    f.state
        .replica_coordinator
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            conn.execute("UPDATE projection_obligations SET next_attempt_at = 0", [])?;
            Ok(())
        })
        .unwrap();
}

fn now_nanos() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as i64
}

async fn pass(engine: &ConvergenceEngine) {
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        drive_obligations_once_for_test(engine, 128, 256),
    )
    .await
    .expect("one engine pass must not stall");
}

/// Runs one sequence; `Err` names the first invariant that broke.
async fn run(seq: &Sequence, window_opens: bool) -> Result<(), String> {
    let f = fixture(false).await;
    let mut engine = ConvergenceEngine::new(f.state.clone());
    let pressure = Arc::new(Pressure { on: AtomicBool::new(false), refusals: AtomicUsize::new(0) });
    install_pressure(&f, &pressure);

    // A file received before the volume filled up.
    let early = content_of(3000, seq.seed as u8);
    f.admit("early.bin", &f.content_version(&early, 1));
    for _ in 0..20 {
        pass(&engine).await;
        if f.read("early.bin").as_deref() == Some(early.as_slice()) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    if f.read("early.bin").as_deref() != Some(early.as_slice()) {
        return Err("the file received before the pressure never landed".into());
    }

    // The volume fills; files arrive.
    pressure.on.store(window_opens, Ordering::SeqCst);
    let mut wanted = Vec::new();
    for i in 0..seq.files {
        let name = format!("held-{i}.bin");
        let content = content_of(2000 + 500 * i, (seq.seed as u8).wrapping_add(i as u8 + 1));
        f.admit(&name, &f.content_version(&content, 10 + i as i64));
        wanted.push((name, content));
    }

    // Ordered: pressured passes, a replaced engine partway.
    for n in 0..seq.pressured_passes {
        let_backoff_elapse(&f);
        let refusals_before = pressure.refusals.load(Ordering::SeqCst);
        pass(&engine).await;
        let attempted = pressure.refusals.load(Ordering::SeqCst) - refusals_before;
        if attempted == 0 {
            return Err(format!("pass {n}: the engine never asked the volume for space"));
        }
        for (name, _) in &wanted {
            if f.read(name).is_some() {
                return Err(format!("pass {n}: {name} was written under pressure"));
            }
            let Some(row) = obligation(&f, name) else {
                return Err(format!("pass {n}: {name} lost its obligation"));
            };
            if row.state == "complete" || row.state == "settled" {
                return Err(format!("pass {n}: {name} was settled without being written"));
            }
            let wait = row.next_attempt_at - now_nanos();
            if wait > MAX_DEFERRAL_NANOS {
                return Err(format!(
                    "pass {n}: {name} is deferred {} s, beyond the bound",
                    wait / 1_000_000_000
                ));
            }
        }
        let leftovers = temp_files(&f);
        if !leftovers.is_empty() {
            return Err(format!("pass {n}: temp files left behind: {leftovers:?}"));
        }
        match f.state.degraded_link_info(&f.root.to_string_lossy()) {
            Some(info)
                if info.cause == crate::link_registry::DegradedCause::WaitingForDiskSpace
                    && info.reason.contains(&format!("{MIB} bytes free"))
                    && info.reason.contains(&format!("{} bytes must stay free", 1u64 << 30)) => {}
            other => {
                return Err(format!(
                    "pass {n}: the status does not say it waits for space: {other:?}"
                ));
            }
        }
        if f.read("early.bin").as_deref() != Some(early.as_slice()) {
            return Err(format!("pass {n}: the earlier file changed under pressure"));
        }
        if seq.restart_after == Some(n) {
            engine = ConvergenceEngine::new(f.state.clone());
        }
    }
    if pressure.refusals.load(Ordering::SeqCst) < seq.pressured_passes {
        return Err("fault never fired often enough".into());
    }

    // The space comes back. No admission, no event: only time.
    pressure.on.store(false, Ordering::SeqCst);
    let_backoff_elapse(&f);
    for _ in 0..10 {
        pass(&engine).await;
        if wanted.iter().all(|(n, c)| f.read(n).as_deref() == Some(c.as_slice())) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let_backoff_elapse(&f);
    }
    for (name, content) in &wanted {
        if f.read(name).as_deref() != Some(content.as_slice()) {
            return Err(format!("{name} never landed after the space came back"));
        }
    }
    let leftovers = temp_files(&f);
    if !leftovers.is_empty() {
        return Err(format!("temp files left after recovery: {leftovers:?}"));
    }
    if let Some(info) = f.state.degraded_link_info(&f.root.to_string_lossy()) {
        return Err(format!("the status still waits for space after recovery: {info:?}"));
    }
    for (name, _) in &wanted {
        let Some(row) = obligation(&f, name) else { continue };
        if row.state == "pending" || row.state == "claimed" {
            return Err(format!("{name} landed but its obligation is still {}", row.state));
        }
    }
    Ok(())
}

fn seeds() -> Vec<u64> {
    let count = std::env::var("DST_SEQUENCES").ok().and_then(|v| v.parse().ok()).unwrap_or(3);
    (0..count).collect()
}

/// Every seeded sequence ends with all files landed and every invariant held
/// on the way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn files_refused_under_disk_pressure_land_by_themselves_when_space_returns() {
    let mut failures = Vec::new();
    for seed in seeds() {
        let seq = Sequence::from_seed(seed);
        if let Err(why) = run(&seq, true).await {
            failures.push(format!("{seq:?}: {why}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The gate can fail: a sequence that names the pressure but whose window never
/// opens (so the preflight never ran under it) is reported, not passed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pressure_that_never_reaches_the_preflight_fails_the_gate() {
    let outcome = run(&Sequence::from_seed(0), false).await;
    assert!(
        matches!(&outcome, Err(why) if why.contains("never asked the volume")),
        "an unpressured run read as pressured: {outcome:?}"
    );
}

/// Space returning is enough, with no help: after one refusal the engine's own backoff
/// (not reset by the test) runs out within a few seconds, the file lands, and the status
/// stops saying it waits for space.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_resumes_on_its_own_backoff_once_space_returns() {
    let f = fixture(false).await;
    let engine = ConvergenceEngine::new(f.state.clone());
    let pressure = Arc::new(Pressure { on: AtomicBool::new(true), refusals: AtomicUsize::new(0) });
    install_pressure(&f, &pressure);
    let content = content_of(2500, 9);
    f.admit("held.bin", &f.content_version(&content, 1));
    pass(&engine).await;
    assert!(pressure.refusals.load(Ordering::SeqCst) > 0, "the preflight never saw the pressure");
    assert!(f.read("held.bin").is_none());
    assert!(f.state.degraded_link_info(&f.root.to_string_lossy()).is_some());

    pressure.on.store(false, Ordering::SeqCst);
    let started = std::time::Instant::now();
    while f.read("held.bin").as_deref() != Some(content.as_slice()) {
        assert!(started.elapsed() < std::time::Duration::from_secs(20), "never resumed");
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        pass(&engine).await;
    }
    assert!(f.state.degraded_link_info(&f.root.to_string_lossy()).is_none());
}
