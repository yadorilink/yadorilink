//! Regression coverage for the Convergence Engine scheduler: `run`'s own
//! loop used to sleep a
//! full tick interval (or wait on the coarse `MaterializationWake`
//! `Notify`) after every `run_once` call, REGARDLESS of whether that
//! call's own group-processing attempts left a large, immediately-runnable
//! backlog behind -- `MAX_PATHS_PER_RECONCILE_ATTEMPT` (32; see
//! `engine.rs`'s own doc comment on it) bounds one
//! ATTEMPT's worst-case latency, but nothing forced the scheduler to
//! actually rest once that attempt finished. `run_once`'s `RunOnceOutcome`/
//! `run`'s own `yield_now`-not-sleep decision is what this file exercises;
//! `run_once`'s live claim source is now `projection_obligations`, driven
//! through `process_group_via_obligations`, not the retired
//! `materialization_jobs` scheduler.
//!
//! **Scope note**: a fully hermetic, single-tick-precise test of
//! `process_group_via_obligations`'s own budget-selection boundary (e.g. "exactly one window of the
//! claimed jobs reach `Planning`, the rest are never touched at all")
//! would need either a real connected peer session constructed with no
//! concurrently-running background engine tick racing it, or a production
//! seam to inject a fake `candidate_sessions` result -- `DaemonState::new`
//! unconditionally starts `MaintenanceCoordinator` (which owns this exact
//! engine loop), and `DaemonState::build` (the maintenance-free
//! constructor) is `pub(crate)`, unreachable from this external
//! integration-test crate. This file's own tests are therefore built
//! around properties that stay deterministic even with that background
//! loop genuinely running alongside them -- a real, connected two-device
//! scenario, and a real, permanently-peerless one -- rather than
//! asserting exact per-tick job-table state.

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use support::{
    connect_two_daemons, daemon_status_summary, ensure_device_signing_key, real_entry_names,
    wait_until_with_context,
};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::convergence::engine::{run_once_for_test, ConvergenceEngine};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind, VersionBlock};
use yadorilink_replica_domain::ids::BlockHash;

const GROUP: &str = "scheduler-test-group";

/// A device, and a sync root that is ITS OWN DIRECTORY.
///
/// The block store gets a separate one. It used to be the same directory,
/// which made every device's own `FORMAT`, `segments` and `index.sqlite3*`
/// part of the folder under test: the scanner imported the store it was
/// writing into, `real_entry_names` counted those artifacts towards the
/// file total, and each device materialized the other's store files over
/// its own. Every other fixture in this suite already keeps the two apart
/// (`ondemand_adoption.rs`'s `setup_device`, for one).
fn new_device(device_id: &str) -> (Arc<DaemonState>, tempfile::TempDir, tempfile::TempDir) {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new(device_id.to_string(), sync_state, store);
    ensure_device_signing_key(&state);
    (state, tempfile::tempdir().unwrap(), store_dir)
}

/// Deterministic, no background-engine race possible: a device with NO
/// connected peer ever, for this group, takes the obligation-driven
/// scheduler's own "no candidate session shares this folder group" branch
/// every single tick -- both this test's own manual `run_once_for_test`
/// call and the background engine's automatic ticks agree on this outcome
/// regardless of interleaving, since neither can ever find a candidate
/// session. This is exactly the "zero progress" case the scheduler fix
/// must not treat as an immediate-backlog signal -- a permanently-
/// unreachable backlog must fall back to its ordinary per-path backoff/
/// retry timing, not spin the scheduler loop tight forever finding nothing
/// to do.
///
/// The backlog is seeded via a REAL DAG admission (a `Change` authored by
/// a device that is never registered as a peer session here, referencing
/// blocks this device never receives), not a direct legacy
/// `materialization_enqueue_pending` call -- `run_once` no longer reads
/// `materialization_jobs` at all post-cutover, so seeding that table alone
/// would make every claim empty and this assertion vacuously true instead
/// of genuinely exercising the "no candidate peer" durable-backoff path in
/// `process_group_via_obligations`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_progress_never_reports_an_immediate_backlog() {
    support::ensure_isolated_config_dir();
    let (state, root, _store_dir) = new_device("sched-lonely");
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    LinkRuntimeController::new(state.clone()).start(local_path, GROUP.to_string()).unwrap();

    let _key = SigningKey::from_bytes(&[7u8; 32]);
    for i in 0..20 {
        let path = format!("unreachable-{i:03}.txt");
        let version = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(vec![i as u8; 32]), size: 100 }],
            100,
            FileMeta {
                mtime_unix_nanos: i as i64,
                unix_mode: None,
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        );
        let _change = yadorilink_daemon::test_support::remote_admission_fixture::admit_remote(
            &state.replica_coordinator,
            GROUP,
            "sched-remote-ghost",
            vec![yadorilink_daemon::test_support::remote_admission_fixture::put(
                &path,
                version.version_hash,
                vec![],
            )],
            std::slice::from_ref(&version),
        );
    }

    // Several manual ticks, not just one -- proves this holds steadily,
    // not just on the very first call before anything has settled.
    let engine = ConvergenceEngine::new(state.clone());
    for _ in 0..5 {
        assert!(
            !run_once_for_test(&engine).await,
            "a permanently unreachable backlog (no connected peer) must never report an \
             immediate backlog -- there is nothing an immediate re-drive could accomplish"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Counts, per local device, the engine loop's iterations that ran a window of work and then
/// went straight into the next iteration instead of waiting (the loop logs
/// `engine loop draining an immediate backlog without waiting` for exactly those).
#[derive(Clone, Default)]
struct DrainRecorder(Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<Duration>>>>);

impl DrainRecorder {
    /// The own-work time of each iteration of `device` that drained without waiting.
    fn drained(&self, device: &str) -> Vec<Duration> {
        self.0.lock().unwrap().get(device).cloned().unwrap_or_default()
    }
}

#[derive(Default)]
struct DrainFields {
    device: Option<String>,
    wall_ms: Option<u64>,
    is_drain: bool,
}

impl tracing::field::Visit for DrainFields {
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        if field.name() == "run_once_wall_ms" {
            self.wall_ms = Some(value);
        }
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "local_device_id" => self.device = Some(format!("{value:?}").trim_matches('"').into()),
            "message" => {
                self.is_drain = format!("{value:?}")
                    == "engine loop draining an immediate backlog without waiting"
            }
            _ => {}
        }
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for DrainRecorder {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        let mut fields = DrainFields::default();
        event.record(&mut fields);
        if let (true, Some(device), Some(wall_ms)) =
            (fields.is_drain, fields.device, fields.wall_ms)
        {
            self.0.lock().unwrap().entry(device).or_default().push(Duration::from_millis(wall_ms));
        }
    }
}

/// Real two-device scenario: more small files than one attempt's budget
/// (`MAX_PATHS_PER_RECONCILE_ATTEMPT`, 32) land on A before B ever links,
/// so B's initial import enqueues more materialization jobs than one tick
/// can budget. Before the scheduler fix, `run`'s loop slept a full
/// `FALLBACK_POLL_INTERVAL` (1s, or however long until the next
/// `MaterializationWake` notify) after every `run_once` call regardless
/// of how much runnable backlog remained -- syncing N files older than
/// the budget cost at least `ceil(N / 32) - 1` extra full seconds of pure
/// sleep, on top of whatever real work each tick did. This asserts
/// convergence well under that old floor, proving the scheduler is
/// actually work-conserving now rather than merely happening to finish
/// eventually.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn more_files_than_the_attempt_budget_converge_without_artificial_per_tick_sleeps() {
    support::ensure_isolated_config_dir();
    use tracing_subscriber::layer::SubscriberExt;
    let drains = DrainRecorder::default();
    let _ = tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(drains.clone()).with(
            tracing_subscriber::filter::Targets::new()
                .with_target("yadorilink_daemon::convergence", tracing::Level::DEBUG),
        ),
    );
    const FILE_COUNT: usize = 96;
    // The old bug slept a full tick interval after every 32-file budget
    // window instead of draining the remaining backlog immediately:
    // `ceil(96/32) - 1 = 2` full seconds of dead sleep before any real work.
    // The windows' own work is not a constant (half a second each in a debug
    // build on a slow disk), so a wall-clock bound on the whole convergence
    // is a throughput threshold; what the bug changes is whether an
    // iteration that ran a window goes straight into the next one, so that
    // is what is asserted, from the loop's own record of it.
    const WINDOWS_THAT_MUST_DRAIN: usize = 2;

    let (state_a, root_a, _store_a) = new_device("sched-a");
    let (state_b, root_b, _store_b) = new_device("sched-b");

    for i in 0..FILE_COUNT {
        std::fs::write(root_a.path().join(format!("file-{i:03}.txt")), format!("content {i}"))
            .unwrap();
    }

    // A linked group with no policy is fail-closed: local emission is
    // withheld and only the dirty-journal backstop (5s) re-drives it.
    // `connect_two_daemons` installs the policy on the way past, which races
    // A's initial scan; losing that race cost a full backstop interval on
    // A's side before B had anything to fetch, which is not the scheduler
    // latency this test measures. Install it before either watch starts.
    for state in [&state_a, &state_b] {
        support::install_bootstrap_policy(state, &[GROUP.to_string()]);
    }

    let local_path_a = root_a.path().to_string_lossy().to_string();
    state_a.replica_coordinator.link_repository().add_link(&local_path_a, GROUP).unwrap();
    LinkRuntimeController::new(state_a.clone()).start(local_path_a, GROUP.to_string()).unwrap();
    let local_path_b = root_b.path().to_string_lossy().to_string();
    state_b.replica_coordinator.link_repository().add_link(&local_path_b, GROUP).unwrap();
    LinkRuntimeController::new(state_b.clone())
        .start(local_path_b.clone(), GROUP.to_string())
        .unwrap();

    let started = Instant::now();
    connect_two_daemons(
        &state_a,
        "sched-a",
        &state_b,
        "sched-b",
        std::slice::from_ref(&GROUP.to_string()),
    )
    .await;

    wait_until_with_context(
        || real_entry_names(root_b.path()).len() >= FILE_COUNT,
        Duration::from_secs(30),
        || {
            format!(
                "{FILE_COUNT} files never converged on B; B has {}; device A: {}; device B: {}",
                real_entry_names(root_b.path()).len(),
                daemon_status_summary(&state_a),
                daemon_status_summary(&state_b),
            )
        },
    )
    .await;
    let _ = started;
    // 96 files over a 32-file budget are three windows; each of the first two leaves runnable
    // backlog behind it and so must not wait for the next wake or poll. (The files appear on
    // disk during the third window, whose iteration is the one that legitimately waits.)
    let drained = drains.drained("sched-b");
    assert!(
        drained.len() >= WINDOWS_THAT_MUST_DRAIN,
        "{FILE_COUNT} files (over the 32-file attempt budget) converged, but only {} of the \
         first {WINDOWS_THAT_MUST_DRAIN} windows went straight into the next one (own work of \
         those that did: {drained:?}): the loop is waiting out a tick interval after budget \
         windows with backlog left, the regression the scheduler fix removed",
        drained.len(),
    );
}
