#![cfg(test)]

//! A mechanism test, not a configuration test: a file received through the
//! real obligation engine and the real eager lane must move every receive-
//! budget instrument whose job is to see that work. An instrument that is
//! armed but wired to a path no receive takes would report zeros, and a run
//! reading zeros would look like a fast pipeline.

use super::receive_cost_tests::{content_of, fixture};
use crate::receive_diag;
use yadorilink_local_storage::io_diag::{self, Op};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receiving_files_through_the_engine_moves_the_budget_counters() {
    let _owner = crate::receive_diag::tests::GLOBAL_TEST_LOCK.lock().await;
    // On-disk replica database, so a commit really is a WAL commit.
    let f = fixture(true).await;
    let engine = crate::convergence::engine::ConvergenceEngine::new(f.state.clone());

    const FILES: u64 = 3;
    let block = yadorilink_local_storage::chunker::DEFAULT_BLOCK_SIZE;
    // Setup writes (blocks, admissions) happen before arming.
    for i in 0..FILES {
        let content = content_of(block + 1000, i as u8);
        let version = f.content_version(&content, 100 + i as i64);
        f.admit(&format!("budget-{i}.bin"), &version);
    }
    receive_diag::reset();
    io_diag::reset();
    // The counters below are per file; a batched open or close is counted by its own test.
    let executor = f.state.peers.local_convergence("device-peer").unwrap();
    executor.batch_completion_override.store(2, std::sync::atomic::Ordering::Relaxed);
    executor.batch_open_override.store(2, std::sync::atomic::Ordering::Relaxed);
    yadorilink_sqlite_runtime::writer_gate_stats::reset();
    receive_diag::set_enabled(true);
    io_diag::set_enabled(true);
    yadorilink_sqlite_runtime::writer_gate_stats::set_split_enabled(true);

    for _ in 0..50 {
        tokio::time::timeout(
            std::time::Duration::from_secs(20),
            crate::convergence::engine::drive_obligations_once_for_test(&engine, 128, 256),
        )
        .await
        .expect("one engine pass must not stall");
        if (0..FILES).all(|i| f.read(&format!("budget-{i}.bin")).is_some()) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    receive_diag::set_enabled(false);
    io_diag::set_enabled(false);
    yadorilink_sqlite_runtime::writer_gate_stats::set_split_enabled(false);

    for i in 0..FILES {
        assert!(f.read(&format!("budget-{i}.bin")).is_some(), "budget-{i}.bin was not received");
    }
    // Lower bounds: nothing else arms these, but the lib's other tests run in
    // this process and may add to them while they are armed.
    for op in [Op::FileFsync, Op::Rename] {
        assert!(io_diag::stat(op).calls >= FILES, "{op:?} must count each received file");
    }
    // The parent-directory sync exists only where the platform has one to do:
    // `sync_parent_directory` is a deliberate no-op off Unix, and the counters
    // must say so rather than pretend.
    #[cfg(unix)]
    {
        assert!(
            io_diag::stat(Op::DirFsync).calls >= FILES,
            "DirFsync must count each received file"
        );
        assert!(io_diag::distinct_parent_dirs() >= 1);
    }
    #[cfg(not(unix))]
    {
        assert_eq!(io_diag::stat(Op::DirFsync).calls, 0, "no directory sync off Unix");
        assert_eq!(io_diag::distinct_parent_dirs(), 0);
    }
    // The receive's own commits: the content-write open and close
    // transactions in the lanes, once per file each.
    let splits = yadorilink_sqlite_runtime::writer_gate_stats::split_site_stats();
    let lane_commits: Vec<_> = splits
        .iter()
        .filter(|s| {
            // `file!()` uses the host's separator, so normalise it.
            let site = s.site.replace('\\', "/");
            site.ends_with("materialization_owner/lanes.rs")
                || site.contains("materialization_owner/lanes.rs:")
        })
        .filter(|s| s.commit_calls >= FILES && s.commit_nanos > 0)
        .collect();
    assert!(
        lane_commits.len() >= 2,
        "open and close content-write sites must each record >= {FILES} timed commits: {splits:?}"
    );
    let locks = receive_diag::lock_site_stats();
    assert!(
        locks.iter().any(|s| {
            s.site.replace('\\', "/").contains("local_convergence/reconcile.rs")
                && s.acquisitions >= FILES
        }),
        "the materialize path-lock site must count each acquisition: {locks:?}"
    );
    receive_diag::reset();
}

/// Drives engine passes until `names` are all on disk.
async fn receive_until_on_disk(
    f: &super::receive_cost_tests::Fixture,
    engine: &crate::convergence::engine::ConvergenceEngine,
    names: &[String],
) {
    for _ in 0..50 {
        tokio::time::timeout(
            std::time::Duration::from_secs(20),
            crate::convergence::engine::drive_obligations_once_for_test(engine, 128, 256),
        )
        .await
        .expect("one engine pass must not stall");
        if names.iter().all(|name| f.read(name).is_some()) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("{names:?} were not received");
}

fn admit_files(f: &super::receive_cost_tests::Fixture, prefix: &str, count: u64) -> Vec<String> {
    let block = yadorilink_local_storage::chunker::DEFAULT_BLOCK_SIZE;
    (0..count)
        .map(|i| {
            let name = format!("{prefix}-{i}.bin");
            let content = content_of(block + 1000, i as u8);
            let version = f.content_version(&content, 100 + i as i64);
            f.admit(&name, &version);
            name
        })
        .collect()
}

/// The window timeline: each reconcile attempt of a receive is a window, with
/// its files, its wall time, its phases and the collectors' queue waits and
/// flush times, and a second attempt for the same group records the gap since
/// the first one ended. Armed, every number moves; this is the guard that the
/// instrument is wired to the path a receive takes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_window_timeline_moves_with_a_receive() {
    let _owner = crate::receive_diag::tests::GLOBAL_TEST_LOCK.lock().await;
    let f = fixture(true).await;
    let engine = crate::convergence::engine::ConvergenceEngine::new(f.state.clone());
    let first = admit_files(&f, "win-a", 3);
    receive_diag::reset();
    receive_diag::set_enabled(true);

    receive_until_on_disk(&f, &engine, &first).await;
    let after_first = receive_diag::window_stats();
    // A later attempt for the same group: the idle time between the two is
    // the gap.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let second = admit_files(&f, "win-b", 2);
    receive_until_on_disk(&f, &engine, &second).await;
    let stats = receive_diag::window_stats();
    receive_diag::set_enabled(false);

    assert!(after_first.windows >= 1, "no window recorded: {after_first:?}");
    assert!(stats.windows > after_first.windows, "{stats:?}");
    assert!(stats.files >= 5, "the windows must count the received files: {stats:?}");
    assert!(stats.wall_ns > 0, "{stats:?}");
    assert!(stats.plan_ns > 0, "plan time must move: {stats:?}");
    assert!(stats.fetch_ns <= stats.wall_ns, "fetch is part of the window: {stats:?}");
    assert!(stats.settle_ns > 0, "settle time must move: {stats:?}");
    assert!(stats.gaps >= 1, "a second attempt must record a gap: {stats:?}");
    assert!(stats.gap_ns > 0, "{stats:?}");
    // Batched collectors are on by default: each queue was waited in and each
    // batch committed.
    for (index, name) in ["open", "close"].iter().enumerate() {
        assert!(stats.queue_wait_ns[index] > 0, "{name} queue wait did not move: {stats:?}");
        assert!(stats.flush_ns[index] > 0, "{name} flush time did not move: {stats:?}");
    }
    receive_diag::reset();
}

/// Unarmed, nothing is recorded: the window timeline costs one relaxed load
/// per entry point and no clock read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_window_timeline_records_nothing_when_unarmed() {
    let _owner = crate::receive_diag::tests::GLOBAL_TEST_LOCK.lock().await;
    let f = fixture(false).await;
    let engine = crate::convergence::engine::ConvergenceEngine::new(f.state.clone());
    let names = admit_files(&f, "off", 2);
    receive_diag::reset();
    receive_diag::set_enabled(false);

    receive_until_on_disk(&f, &engine, &names).await;

    let stats = receive_diag::window_stats();
    assert_eq!(stats.windows, 0, "{stats:?}");
    assert_eq!(stats.wall_ns + stats.gap_ns + stats.plan_ns + stats.settle_ns, 0, "{stats:?}");
    assert!(receive_diag::window_begin("any-group").is_none());
    assert!(receive_diag::clock().is_none());
}

/// The last-attempt map of the gap measurement is bounded under group churn:
/// past the cap it forgets rather than grows, and a group evicted reports no
/// gap for its next attempt.
#[tokio::test]
async fn the_window_gap_map_is_bounded_under_group_churn() {
    let _owner = crate::receive_diag::tests::GLOBAL_TEST_LOCK.lock().await;
    receive_diag::reset();
    receive_diag::set_enabled(true);
    let phases = receive_diag::WindowPhases::default();
    for group in 0..(receive_diag::last_end_cap() * 2 + 10) {
        let start = receive_diag::window_begin(&format!("group-{group}")).unwrap();
        receive_diag::window_end(&format!("group-{group}"), start, 1, phases);
        assert!(receive_diag::last_end_len() <= receive_diag::last_end_cap());
    }
    // `group-0` was evicted long ago: no gap for it.
    let before = receive_diag::window_stats().gaps;
    let start = receive_diag::window_begin("group-0").unwrap();
    receive_diag::window_end("group-0", start, 1, phases);
    assert_eq!(receive_diag::window_stats().gaps, before, "an evicted group reported a gap");
    receive_diag::set_enabled(false);
    receive_diag::reset();
}

/// Set in the child process that runs the isolated receive-flush count.
#[cfg(unix)]
const ISOLATED_ENV: &str = "YADORILINK_ISOLATED_RECEIVE_FLUSH_COUNT";
#[cfg(unix)]
const ISOLATED_TEST: &str = "convergence::receive_budget_tests::receive_flush_counts_run";

/// Differences between observed flush counts and the baseline's `receive_engine_workload`.
fn flush_count_differences(observed: &[(&str, u64)], baseline: &serde_json::Value) -> Vec<String> {
    observed
        .iter()
        .filter_map(|(name, seen)| {
            let want = baseline[name].as_u64().unwrap_or_else(|| panic!("baseline.{name} missing"));
            (*seen != want).then(|| format!("{name}: observed {seen}, baseline {want}"))
        })
        .collect()
}

/// Files received through the real engine, and exact flush counts against the baseline. The
/// flush counters are process-global, and the lib's other tests share a process, so this body
/// only runs in the child process the test below starts for it alone.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_flush_counts_run() {
    if std::env::var_os(ISOLATED_ENV).is_none() {
        return;
    }
    let baseline = &super::receive_cost_tests::perf_baseline()["receive_engine_workload"];
    let files = baseline["files"].as_u64().unwrap();
    let f = super::receive_cost_tests::quiet_fixture(false).await;
    let engine = crate::convergence::engine::ConvergenceEngine::new(f.state.clone());
    let warm = admit_files(&f, "warm", 1);
    receive_until_on_disk(&f, &engine, &warm).await;
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    let names = admit_files(&f, "counted", files);
    io_diag::reset();
    io_diag::set_enabled(true);
    let flushes_before = yadorilink_fs_platform::flush::counts();
    receive_until_on_disk(&f, &engine, &names).await;
    // Let any trailing batch flush finish before reading.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    io_diag::set_enabled(false);
    let flushed = yadorilink_fs_platform::flush::counts();
    let observed = [
        ("file_fsync", io_diag::stat(Op::FileFsync).calls),
        ("dir_fsync", io_diag::stat(Op::DirFsync).calls),
        ("rename", io_diag::stat(Op::Rename).calls),
        ("file_flushes", flushed.file_flushes - flushes_before.file_flushes),
        ("directory_syncs", flushed.directory_syncs - flushes_before.directory_syncs),
    ];
    eprintln!("MEASURE receive flush counts: {observed:?}");
    let moved = flush_count_differences(&observed, baseline);
    assert!(
        moved.is_empty(),
        "the receive flush counts moved: {moved:#?}\nIf this is intended, follow the update \
         procedure in .github/checks/check-perf-baseline.py (a recorded reason is required)."
    );
}

/// Runs [`receive_flush_counts_run`] alone in its own process, so no other test's flushes
/// are counted with it.
#[cfg(unix)]
#[test]
fn receive_flush_counts_match_the_recorded_baseline_in_an_isolated_process() {
    if std::env::var_os(ISOLATED_ENV).is_some() {
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", ISOLATED_TEST, "--nocapture", "--test-threads=1"])
        .env(ISOLATED_ENV, "1")
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "isolated receive flush count failed:\n{text}");
    assert!(
        text.contains("MEASURE receive flush counts"),
        "the isolated test did not run:\n{text}"
    );
}

#[test]
fn the_flush_count_comparison_notices_one_extra_flush() {
    let baseline = serde_json::json!({ "file_fsync": 3, "dir_fsync": 3 });
    assert!(flush_count_differences(&[("file_fsync", 3), ("dir_fsync", 3)], &baseline).is_empty());
    let moved = flush_count_differences(&[("file_fsync", 3), ("dir_fsync", 4)], &baseline);
    assert_eq!(moved.len(), 1, "{moved:?}");
}
