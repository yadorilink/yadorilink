#![cfg(test)]

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_root_authority::root_commit::RootLease;

use super::*;
use crate::replica_coordinator::ReplicaCoordinator;

struct Fixture {
    _dir: tempfile::TempDir,
    state: Arc<DaemonState>,
    db_path: std::path::PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("sync-state.sqlite3");
    let store = Arc::new(SegmentBlockStore::new(dir.path().join("blocks")).unwrap());
    let coordinator = Arc::new(ReplicaCoordinator::open(&db_path).unwrap());
    let state = DaemonState::new("device-a".into(), coordinator, store);
    Fixture { _dir: dir, state, db_path }
}

fn leases(n: usize) -> Leases {
    (0..n).map(|_| Arc::new(RootLease::for_tests())).collect()
}

const SECOND: Duration = Duration::from_secs(1);

fn wal_len(db_path: &std::path::Path) -> u64 {
    let wal = db_path.with_file_name("sync-state.sqlite3-wal");
    std::fs::metadata(wal).map(|m| m.len()).unwrap_or(0)
}

fn stopping(already: bool) -> SafeStopOutcome {
    SafeStopOutcome::Stopping { already_in_progress: already }
}

fn is_busy(outcome: &SafeStopOutcome, wanted: SafeStopBusy) -> bool {
    matches!(outcome, SafeStopOutcome::Busy { reason, retry_after, .. }
        if *reason == wanted && !retry_after.is_zero())
}

#[tokio::test]
async fn the_happy_path_pauses_links_checkpoints_and_begins_the_shutdown() {
    let f = fixture();
    // Something sits in the sync database's log before the stop.
    let database = f.state.replica_coordinator.database();
    database
        .write::<_, yadorilink_sqlite_runtime::DatabaseError>(|conn| {
            Ok(conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS probe (x INTEGER); INSERT INTO probe VALUES (1);",
            )?)
        })
        .unwrap();
    assert!(wal_len(&f.db_path) > 0, "precondition: the log holds the write");

    let links = leases(2);
    let mut shutdown = f.state.shutdown_tx.subscribe();
    let outcome = run(&f.state, 5 * SECOND, &NoHook, links.clone()).await;

    assert_eq!(outcome, stopping(false));
    assert!(shutdown.has_changed().unwrap() && *shutdown.borrow_and_update());
    assert_eq!(wal_len(&f.db_path), 0, "the log was folded into the database file");
    for lease in &links {
        assert!(lease.begin_operation().is_err(), "no new operation once the stop is committed");
    }
}

#[tokio::test]
async fn a_write_that_does_not_finish_is_busy_and_the_daemon_keeps_working() {
    let f = fixture();
    let links = leases(2);
    let held = links[0].begin_operation().unwrap();

    let outcome = run(&f.state, Duration::from_millis(150), &NoHook, links.clone()).await;

    assert!(is_busy(&outcome, SafeStopBusy::WritesInProgress), "{outcome:?}");
    assert!(!*f.state.shutdown_tx.borrow(), "a busy answer begins no shutdown");
    for lease in &links {
        let again = lease.begin_operation();
        assert!(again.is_ok(), "the pause is lifted again after a busy answer");
    }
    drop(held);

    // The retry succeeds once the write is done.
    let outcome = run(&f.state, 5 * SECOND, &NoHook, links).await;
    assert_eq!(outcome, stopping(false));
}

#[tokio::test]
async fn an_operation_that_finishes_in_time_lets_the_stop_through() {
    let f = fixture();
    let links = leases(1);
    let lease = links[0].clone();
    let finishing = tokio::spawn(async move {
        let op = lease.begin_operation().unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(op);
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let outcome = run(&f.state, 5 * SECOND, &NoHook, links).await;
    finishing.await.unwrap();
    assert_eq!(outcome, stopping(false));
}

#[tokio::test]
async fn repeated_requests_are_idempotent() {
    let f = fixture();
    let links = leases(1);
    assert_eq!(run(&f.state, 5 * SECOND, &NoHook, links.clone()).await, stopping(false));
    for _ in 0..3 {
        assert_eq!(run(&f.state, 5 * SECOND, &NoHook, links.clone()).await, stopping(true));
    }
}

#[tokio::test]
async fn concurrent_requests_commit_exactly_once() {
    let f = fixture();
    let links = leases(2);
    let results = futures_util::future::join_all(
        (0..6).map(|_| run(&f.state, 5 * SECOND, &NoHook, links.clone())),
    )
    .await;
    let first = results.iter().filter(|r| **r == stopping(false)).count();
    let repeats = results.iter().filter(|r| **r == stopping(true)).count();
    assert_eq!((first, repeats), (1, 5), "{results:?}");
}

#[tokio::test]
async fn a_daemon_that_is_already_shutting_down_answers_as_stopping() {
    let f = fixture();
    f.state.shutdown_tx.send_replace(true);
    assert_eq!(run(&f.state, 5 * SECOND, &NoHook, leases(1)).await, stopping(true));
}

struct FailAt(Step, AtomicU32);

impl StepHook for FailAt {
    fn after(&self, step: Step) -> Result<(), String> {
        if step == self.0 {
            self.1.fetch_add(1, Ordering::SeqCst);
            Err(format!("injected failure after {step:?}"))
        } else {
            Ok(())
        }
    }
}

#[tokio::test]
async fn a_failure_at_any_step_leaves_the_daemon_running_and_the_retry_works() {
    for step in [Step::Paused, Step::Drained, Step::Checkpointed] {
        let f = fixture();
        let links = leases(2);
        let hook = FailAt(step, AtomicU32::new(0));

        let outcome = run(&f.state, 5 * SECOND, &hook, links.clone()).await;

        assert_eq!(hook.1.load(Ordering::SeqCst), 1, "{step:?} was reached");
        assert!(matches!(outcome, SafeStopOutcome::Busy { .. }), "{step:?}: {outcome:?}");
        assert!(!*f.state.shutdown_tx.borrow(), "{step:?}: no shutdown begun");
        for lease in &links {
            assert!(lease.begin_operation().is_ok(), "{step:?}: links admit work again");
        }
        assert_eq!(
            run(&f.state, 5 * SECOND, &NoHook, links).await,
            stopping(false),
            "{step:?}: the retry succeeds"
        );
    }
}

#[tokio::test]
async fn a_checkpoint_that_cannot_finish_in_time_is_busy_not_a_forced_exit() {
    let f = fixture();
    let links = leases(1);
    // A long writer holds the database's writer gate, so the checkpoint cannot start.
    let database = f.state.replica_coordinator.database();
    let writer = tokio::task::spawn_blocking(move || {
        database
            .write::<_, yadorilink_sqlite_runtime::DatabaseError>(|_| {
                std::thread::sleep(Duration::from_millis(600));
                Ok(())
            })
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let outcome = run(&f.state, Duration::from_millis(200), &NoHook, links.clone()).await;

    assert!(is_busy(&outcome, SafeStopBusy::CheckpointFailed), "{outcome:?}");
    assert!(!*f.state.shutdown_tx.borrow(), "nothing was forced");
    assert!(links[0].begin_operation().is_ok());
    writer.await.unwrap();
    assert_eq!(run(&f.state, 5 * SECOND, &NoHook, links).await, stopping(false));
}

#[tokio::test]
async fn a_late_checkpoint_after_busy_coexists_with_normal_writes_and_a_retry_succeeds() {
    let f = fixture();
    let links = leases(1);
    let database = f.state.replica_coordinator.database();
    database
        .write::<_, yadorilink_sqlite_runtime::DatabaseError>(|conn| {
            Ok(conn.execute_batch("CREATE TABLE probe (x INTEGER);")?)
        })
        .unwrap();
    // A long writer holds the writer gate, so the stop's checkpoint queues behind it and the
    // stop gives up as busy while the checkpoint task is still pending.
    let holder = {
        let database = database.clone();
        tokio::task::spawn_blocking(move || {
            database
                .write::<_, yadorilink_sqlite_runtime::DatabaseError>(|conn| {
                    conn.execute("INSERT INTO probe VALUES (0)", [])?;
                    std::thread::sleep(Duration::from_millis(600));
                    Ok(())
                })
                .unwrap();
        })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;

    let outcome = run(&f.state, Duration::from_millis(200), &NoHook, links.clone()).await;
    assert!(is_busy(&outcome, SafeStopBusy::CheckpointFailed), "{outcome:?}");
    // The pause is lifted: a link operation is admitted again.
    assert!(links[0].begin_operation().is_ok(), "the pause is lifted after busy");
    assert!(!*f.state.shutdown_tx.borrow(), "nothing was forced");

    // Normal writes overlap the late checkpoint; every one of them completes.
    let writers: Vec<_> = (1..=20i64)
        .map(|i| {
            let database = database.clone();
            tokio::task::spawn_blocking(move || {
                database
                    .write::<_, yadorilink_sqlite_runtime::DatabaseError>(|conn| {
                        conn.execute("INSERT INTO probe VALUES (?1)", [i])?;
                        Ok(())
                    })
                    .unwrap();
            })
        })
        .collect();
    tokio::time::timeout(5 * SECOND, async {
        holder.await.unwrap();
        for writer in writers {
            writer.await.unwrap();
        }
    })
    .await
    .expect("the late checkpoint does not block writers forever");

    // No write was lost or corrupted.
    let (count, sum, integrity) = database
        .write::<_, yadorilink_sqlite_runtime::DatabaseError>(|conn| {
            let (count, sum): (i64, i64) =
                conn.query_row("SELECT COUNT(*), SUM(x) FROM probe", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;
            let integrity: String = conn.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
            Ok((count, sum, integrity))
        })
        .unwrap();
    assert_eq!((count, sum), (21, 210), "every write is present exactly once");
    assert_eq!(integrity, "ok");

    // A retried safe stop succeeds.
    assert_eq!(run(&f.state, 5 * SECOND, &NoHook, links).await, stopping(false));
}

#[tokio::test]
async fn a_second_request_that_cannot_get_its_turn_in_time_is_busy() {
    let f = fixture();
    let links = leases(1);
    let held = links[0].begin_operation().unwrap();
    // The first request waits for the held operation (longer than the second's whole deadline).
    let first = {
        let state = f.state.clone();
        let links = links.clone();
        tokio::spawn(async move { run(&state, 2 * SECOND, &NoHook, links).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let second = run(&f.state, Duration::from_millis(100), &NoHook, links.clone()).await;
    assert!(is_busy(&second, SafeStopBusy::AnotherRequestInProgress), "{second:?}");
    drop(held);
    assert_eq!(first.await.unwrap(), stopping(false));
}

#[tokio::test]
async fn a_cancelled_safe_stop_lifts_the_pause() {
    let f = fixture();
    let links = leases(1);
    let _held = links[0].begin_operation().unwrap(); // wait_drained never finishes
                                                     // The caller gives up (client disconnect / outer timeout) while the stop is waiting.
    let cancelled = tokio::time::timeout(
        Duration::from_millis(100),
        run(&f.state, 60 * SECOND, &NoHook, links.clone()),
    )
    .await;
    assert!(cancelled.is_err(), "precondition: the stop was still waiting and got dropped");
    assert!(
        links[0].begin_operation().is_ok(),
        "dropping the stop future must end the quiesce; the link is paused forever otherwise"
    );
}

fn start_is_refused_by_safe_stop(state: &Arc<DaemonState>, path: &str) -> bool {
    matches!(
        LinkRegistry::reserve_starting(&state.links, path.to_string()),
        Err(crate::error::DaemonError::SafeStopInProgress)
    )
}

/// Records whether a link start was refused at each step, and can fail the stop at one.
struct GateProbe {
    state: Arc<DaemonState>,
    refused_at_paused: AtomicU32,
    fail_at: Option<Step>,
}

impl StepHook for GateProbe {
    fn after(&self, step: Step) -> Result<(), String> {
        if step == Step::Paused && start_is_refused_by_safe_stop(&self.state, "/late-link") {
            self.refused_at_paused.fetch_add(1, Ordering::SeqCst);
        }
        if self.fail_at == Some(step) {
            return Err("injected".into());
        }
        Ok(())
    }
}

#[tokio::test]
async fn a_link_start_during_safe_stop_is_refused_and_succeeds_after_a_failed_stop() {
    let f = fixture();
    let probe = GateProbe {
        state: f.state.clone(),
        refused_at_paused: AtomicU32::new(0),
        fail_at: Some(Step::Drained),
    };
    let outcome = request_with(&f.state, 5 * SECOND, &probe).await;
    assert!(is_busy(&outcome, SafeStopBusy::WritesInProgress));
    assert_eq!(probe.refused_at_paused.load(Ordering::SeqCst), 1, "refused while stopping");
    let reservation = LinkRegistry::reserve_starting(&f.state.links, "/late-link".into());
    assert!(reservation.is_ok(), "the start is accepted once the stop has failed");
}

#[tokio::test]
async fn a_link_start_succeeds_again_after_a_cancelled_safe_stop() {
    let f = fixture();
    let links = leases(1);
    let _held = links[0].begin_operation().unwrap();
    // Registered link whose operation never ends: the stop waits, then is dropped.
    let state = f.state.clone();
    let cancelled = tokio::time::timeout(Duration::from_millis(100), async {
        let _gate = LinkRegistry::close_start_gate(&state.links);
        assert!(start_is_refused_by_safe_stop(&state, "/late-link"));
        std::future::pending::<()>().await
    })
    .await;
    assert!(cancelled.is_err());
    assert!(LinkRegistry::reserve_starting(&f.state.links, "/late-link".into()).is_ok());
}

/// Cancels a real in-flight `request` (not just the gate guard): a link operation is held, so
/// the stop sits at the drain step with the start gate closed and the lease paused.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_in_flight_request_reopens_the_start_gate_and_lifts_the_pause() {
    let f = fixture();
    f.state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]));
    let root = tempfile::tempdir().unwrap();
    let path = root.path().to_string_lossy().into_owned();
    f.state.replica_coordinator.link_repository().add_link(&path, "g-cancel").unwrap();
    crate::adapters::runtime::link_runtime_controller::LinkRuntimeController::new(f.state.clone())
        .start(path.clone(), "g-cancel".into())
        .unwrap();
    let lease = f.state.links.ready_root_leases().pop().expect("the link is ready");
    let held = lease.begin_operation().unwrap();

    let cancelled = tokio::time::timeout(
        Duration::from_millis(300),
        request_with(&f.state, 60 * SECOND, &NoHook),
    )
    .await;
    assert!(cancelled.is_err(), "precondition: the request was still draining and got dropped");

    assert!(
        LinkRegistry::reserve_starting(&f.state.links, "/late-link".into()).is_ok(),
        "dropping the request must reopen the start gate"
    );
    drop(held);
    assert!(lease.begin_operation().is_ok(), "dropping the request must lift the pause");
}

#[tokio::test]
async fn a_committed_safe_stop_keeps_link_starts_refused() {
    let f = fixture();
    let outcome = request(&f.state, 5 * SECOND).await;
    assert_eq!(outcome, stopping(false));
    assert!(start_is_refused_by_safe_stop(&f.state, "/late-link"));
}

#[tokio::test]
async fn a_link_still_starting_is_waited_out_before_the_leases_are_taken() {
    let f = fixture();
    let reservation = LinkRegistry::reserve_starting(&f.state.links, "/starting".into()).unwrap();
    let state = f.state.clone();
    let stop = tokio::spawn(async move { request(&state, 5 * SECOND).await });
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(!stop.is_finished(), "the stop must wait for the starting link");
    drop(reservation); // the start failed
    assert_eq!(stop.await.unwrap(), stopping(false));
}

#[tokio::test]
async fn a_stop_waiting_for_a_starting_link_gives_up_busy_and_reopens_the_gate() {
    let f = fixture();
    let _reservation = LinkRegistry::reserve_starting(&f.state.links, "/starting".into()).unwrap();
    let outcome = request(&f.state, Duration::from_millis(100)).await;
    assert!(is_busy(&outcome, SafeStopBusy::WritesInProgress));
    assert!(LinkRegistry::reserve_starting(&f.state.links, "/other".into()).is_ok());
}

#[tokio::test]
async fn an_already_stopping_daemon_answers_at_once_even_with_a_link_starting() {
    let f = fixture();
    let _starting = LinkRegistry::reserve_starting(&f.state.links, "/starting".into()).unwrap();
    f.state.shutdown_tx.send_replace(true);
    assert_eq!(request(&f.state, 5 * SECOND).await, stopping(true));
}

// The stop's reason is part of the commit: the shutdown signal never fires before it is recorded.

/// What a shutdown observer (the main task) could see at the instant the signal had fired.
struct AtSignal {
    state: Arc<DaemonState>,
    seen: std::sync::Mutex<Option<(bool, bool)>>,
}

impl StepHook for AtSignal {
    fn after(&self, step: Step) -> Result<(), String> {
        if step == Step::Committed {
            let signalled = *self.state.shutdown_tx.borrow();
            let restart = self.state.restart_on_exit.load(std::sync::atomic::Ordering::SeqCst);
            *self.seen.lock().unwrap() = Some((signalled, restart));
        }
        Ok(())
    }
}

fn restart_flag(state: &DaemonState) -> bool {
    state.restart_on_exit.load(std::sync::atomic::Ordering::SeqCst)
}

#[tokio::test]
async fn the_restart_reason_is_recorded_before_the_shutdown_signal_is_visible() {
    let f = fixture();
    let hook = AtSignal { state: f.state.clone(), seen: std::sync::Mutex::new(None) };
    let outcome = run_as(&f.state, 5 * SECOND, &hook, leases(1), StopIntent::Restart).await;
    assert_eq!(outcome, stopping(false));
    assert_eq!(
        *hook.seen.lock().unwrap(),
        Some((true, true)),
        "at the moment the signal is visible the restart reason already is"
    );
}

/// Looks at the restart reason at the point inside the commit that sits between recording it and
/// setting the shutdown signal.
struct AtRecorded {
    state: Arc<DaemonState>,
    restart_seen: std::sync::Mutex<Option<bool>>,
}

impl StepHook for AtRecorded {
    fn after(&self, step: Step) -> Result<(), String> {
        if step == Step::ReasonRecorded {
            *self.restart_seen.lock().unwrap() = Some(restart_flag(&self.state));
        }
        Ok(())
    }
}

#[tokio::test]
async fn the_restart_reason_is_recorded_before_the_signal_is_set() {
    // The commit runs under the shutdown channel's lock, so no observer can tell the order apart;
    // this pins it anyway: the hook between the two operations sees the reason already recorded
    // (a commit that set the signal first would show `false` here).
    let f = fixture();
    let hook = AtRecorded { state: f.state.clone(), restart_seen: std::sync::Mutex::new(None) };
    assert_eq!(
        run_as(&f.state, 5 * SECOND, &hook, leases(1), StopIntent::Restart).await,
        stopping(false)
    );
    assert_eq!(*hook.restart_seen.lock().unwrap(), Some(true));
}

/// Fires a stop from elsewhere (as the control socket or a signal does) at one step.
struct StopAt {
    state: Arc<DaemonState>,
    at: Step,
}

impl StepHook for StopAt {
    fn after(&self, step: Step) -> Result<(), String> {
        if step == self.at {
            self.state.shutdown_tx.send_replace(true);
        }
        Ok(())
    }
}

#[tokio::test]
async fn a_stop_from_elsewhere_during_the_drain_or_the_checkpoint_is_not_turned_into_a_restart() {
    for at in [Step::Paused, Step::Drained, Step::Checkpointed] {
        let f = fixture();
        let hook = StopAt { state: f.state.clone(), at };
        let outcome = run_as(&f.state, 5 * SECOND, &hook, leases(1), StopIntent::Restart).await;
        assert_eq!(outcome, stopping(true), "{at:?}");
        assert!(!restart_flag(&f.state), "{at:?}: somebody else's stop is not a restart");
    }
}

#[tokio::test]
async fn a_plain_stop_never_records_a_restart() {
    let f = fixture();
    let hook = AtSignal { state: f.state.clone(), seen: std::sync::Mutex::new(None) };
    assert_eq!(
        run_as(&f.state, 5 * SECOND, &hook, leases(1), StopIntent::Plain).await,
        stopping(false)
    );
    assert_eq!(*hook.seen.lock().unwrap(), Some((true, false)));
    assert!(!restart_flag(&f.state));
}

#[tokio::test]
async fn a_restart_request_that_does_not_commit_records_nothing() {
    // Busy: a write that does not finish.
    let f = fixture();
    let links = leases(1);
    let held = links[0].begin_operation().unwrap();
    let outcome =
        run_as(&f.state, Duration::from_millis(150), &NoHook, links.clone(), StopIntent::Restart)
            .await;
    assert!(is_busy(&outcome, SafeStopBusy::WritesInProgress));
    assert!(!restart_flag(&f.state));
    drop(held);

    // Another source already shut the daemon down.
    f.state.shutdown_tx.send_replace(true);
    let outcome = run_as(&f.state, 5 * SECOND, &NoHook, links, StopIntent::Restart).await;
    assert_eq!(outcome, stopping(true));
    assert!(!restart_flag(&f.state), "a stop somebody else began is not a restart");
}

#[tokio::test]
async fn a_restart_request_after_another_safe_stop_committed_records_nothing() {
    let f = fixture();
    assert_eq!(
        run_as(&f.state, 5 * SECOND, &NoHook, leases(1), StopIntent::Plain).await,
        stopping(false)
    );
    let outcome = run_as(&f.state, 5 * SECOND, &NoHook, leases(1), StopIntent::Restart).await;
    assert_eq!(outcome, stopping(true));
    assert!(!restart_flag(&f.state));
}

#[tokio::test]
async fn the_real_adapter_and_the_watch_end_in_a_restart_exit_for_the_watchs_own_stop() {
    use crate::adapters::runtime::runtime_control::DaemonLifecycleAdapter;
    use crate::application::ports::DaemonLifecyclePort;
    use crate::exe_replaced::{watch_with, Observation, ReplacedConfig, Target};

    let f = fixture();
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("daemon");
    std::fs::write(&exe, "v1").unwrap();
    let target = Target::new(exe.clone());
    let Observation::Present(baseline) = target.observe() else { panic!("present") };
    std::fs::write(&exe, "version-2").unwrap();

    let lifecycle: Arc<dyn DaemonLifecyclePort> =
        Arc::new(DaemonLifecycleAdapter::new(f.state.clone()));
    let mut main_task = f.state.shutdown_tx.subscribe();
    let config = ReplacedConfig {
        interval: Duration::from_millis(10),
        stop_deadline: 5 * SECOND,
        busy_backoff_cap: Duration::from_millis(50),
    };
    let watch = tokio::spawn(watch_with(
        config,
        lifecycle,
        baseline,
        f.state.shutdown_tx.subscribe(),
        move || target.observe(),
    ));
    tokio::time::timeout(5 * SECOND, main_task.changed()).await.unwrap().unwrap();
    // What the main task does the moment it sees the shutdown.
    assert!(restart_flag(&f.state), "the reason was there when the shutdown became visible");
    watch.await.unwrap();
}

#[tokio::test]
async fn the_real_adapter_leaves_a_stop_by_someone_else_as_a_plain_exit() {
    use crate::adapters::runtime::runtime_control::DaemonLifecycleAdapter;
    use crate::application::ports::DaemonLifecyclePort;

    let f = fixture();
    let adapter = DaemonLifecycleAdapter::new(f.state.clone());
    // `request_shutdown` only takes effect while somebody listens, as in the running daemon.
    let _listener = f.state.shutdown_tx.subscribe();
    adapter.request_shutdown();
    assert_eq!(adapter.request_safe_stop_to_restart(5 * SECOND).await, stopping(true));
    assert!(!restart_flag(&f.state));
}

#[tokio::test]
async fn a_shutdown_request_nobody_subscribed_to_yet_is_not_lost() {
    use crate::adapters::runtime::runtime_control::DaemonLifecycleAdapter;
    use crate::application::ports::DaemonLifecyclePort;
    let f = fixture();
    assert_eq!(f.state.shutdown_tx.receiver_count(), 0);
    DaemonLifecycleAdapter::new(f.state.clone()).request_shutdown();
    assert!(*f.state.shutdown_tx.borrow());
    assert!(*f.state.shutdown_tx.subscribe().borrow());
}
