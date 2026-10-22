#![cfg(test)]
//! Commits that run on the blocking pool while the file's task keeps
//! polling: what a dropped or panicking waiter may not break.
//!
//! The commit of a file's open and of the collectors' batches runs on another
//! thread. The frames that wait for it keep holding what the commit is about
//! (path lock, the lane's and the row's root operations, claim), and must keep
//! holding it until the commit has landed or rolled back, even when they are
//! dropped mid-commit. The root operations are the observable: a lease that
//! is stopping only drains once every operation admitted on it has dropped.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
use yadorilink_root_authority::root_commit::RootLease;

use super::completion_window::CompletionWindow;
use super::completion_window_tests::{committed, item, open_row, untouched, valid_check, GROUP};
use crate::replica_coordinator::ReplicaCoordinator;

fn lease() -> Arc<RootLease> {
    Arc::new(RootLease::for_tests())
}

async fn drained_within(lease: &Arc<RootLease>, wait: Duration) -> bool {
    lease.begin_stopping();
    tokio::time::timeout(wait, lease.wait_drained()).await.is_ok()
}

/// [`drained_within`] for a thread outside the runtime.
/// Stops the lease (later admissions refuse), which the tests do not mind.
fn drained_within_blocking(lease: &Arc<RootLease>, wait: Duration) -> bool {
    lease.begin_stopping();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
    runtime.block_on(async { tokio::time::timeout(wait, lease.wait_drained()).await.is_ok() })
}

/// A gate a commit parks in: `entered` fires when the commit reached it,
/// `release` lets it go on.
struct Gate {
    entered: std::sync::mpsc::Receiver<()>,
    release: std::sync::mpsc::Sender<()>,
}

fn gate() -> (Arc<dyn Fn() + Send + Sync>, Gate) {
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (entered_tx, release_rx) = (Mutex::new(entered_tx), Mutex::new(release_rx));
    let hook: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
        let _ = entered_tx.lock().unwrap().send(());
        let _ = release_rx.lock().unwrap().recv();
    });
    (hook, Gate { entered: entered_rx, release: release_tx })
}

fn record(path: &str) -> FileRecord {
    FileRecord {
        path: path.to_owned(),
        size: 5,
        mtime_unix_nanos: 1,
        blocks: vec![BlockInfo { hash: vec![7; 32], offset: 0, size: 5 }],
        deleted: false,
    }
}

fn set_open_gate(state: &ReplicaCoordinator, hook: Arc<dyn Fn() + Send + Sync>) {
    *state.test_observers.open_commit_gate.lock().unwrap() = Some(hook);
}

/// Runs `probe` on a thread of its own at +`after`, then lets the gate go.
/// The awaiting task is dropped meanwhile, so the thread that drops it is
/// stuck in its fence and cannot do this itself.
fn release_after(
    gate: Gate,
    after: Duration,
    probe: impl FnOnce() + Send + 'static,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        std::thread::sleep(after);
        probe();
        gate.release.send(()).unwrap();
    })
}

/// A dropped awaiting open keeps the path lock, the lane's operation and the
/// row's own operation until the commit it handed to the blocking pool has
/// landed; the commit lands although nobody awaits it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_open_keeps_both_operations_and_the_path_lock_until_the_commit_lands() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let (hook, gate) = gate();
    set_open_gate(&state, hook);
    let (lane_lease, row_lease) = (lease(), lease());
    let path_lock = state.path_lock(GROUP, "open.bin");

    let task = tokio::spawn({
        let (state, lane_lease, row_lease, path_lock) =
            (state.clone(), lane_lease.clone(), row_lease.clone(), path_lock.clone());
        async move {
            let _path = path_lock.lock_owned().await;
            let lane_operation = lane_lease.begin_operation().unwrap();
            let permit = lane_operation.permit();
            let record = record("open.bin");
            state
                .open_content_write(
                    GROUP,
                    &record,
                    "device-peer",
                    None,
                    &crate::replica_coordinator::plain_file_columns(),
                    &|| Ok(row_lease.clone()),
                    &permit,
                )
                .await
                .map(|(generation, _intent)| generation)
        }
    });
    let gate = tokio::task::spawn_blocking(move || {
        gate.entered.recv().unwrap();
        gate
    })
    .await
    .unwrap();
    let (lane, row, path) = (lane_lease.clone(), row_lease.clone(), path_lock.clone());
    let released = release_after(gate, Duration::from_millis(300), move || {
        assert!(
            !drained_within_blocking(&lane, Duration::from_millis(50)),
            "the lane's operation was released while its commit was still running"
        );
        assert!(
            !drained_within_blocking(&row, Duration::from_millis(50)),
            "the row's operation was released while its commit was still running"
        );
        assert!(
            path.try_lock().is_err(),
            "the path lock was released while its commit was still running"
        );
    });
    task.abort();
    let _ = task.await;
    released.join().unwrap();
    let _ = state.test_observers.open_commit_gate.lock().unwrap().take();

    // Everything is released now, and the commit landed on its own.
    assert!(drained_within(&lane_lease, Duration::from_secs(2)).await);
    assert!(drained_within(&row_lease, Duration::from_secs(2)).await);
    assert!(path_lock.try_lock().is_ok(), "the path lock leaked");
    assert!(state.has_materialization_intent(GROUP, "open.bin").unwrap());
    assert!(state.get_file(GROUP, "open.bin").unwrap().is_some());
}

/// The open's job needs nothing the dropping side holds: with the path lock
/// held by the thread that drops the awaiting future, the commit still
/// lands, and the lock is still held when it has.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_open_job_commits_while_the_dropper_holds_the_path_lock() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let (hook, gate) = gate();
    set_open_gate(&state, hook);
    let row_lease = lease();
    let permit_lease = lease();
    let task = tokio::spawn({
        let (state, row_lease, permit_lease) =
            (state.clone(), row_lease.clone(), permit_lease.clone());
        async move {
            let operation = permit_lease.begin_operation().unwrap();
            let permit = operation.permit();
            let record = record("dropper.bin");
            let _ = state
                .open_content_write(
                    GROUP,
                    &record,
                    "device-peer",
                    None,
                    &crate::replica_coordinator::plain_file_columns(),
                    &|| Ok(row_lease.clone()),
                    &permit,
                )
                .await;
        }
    });
    tokio::task::spawn_blocking({
        let entered = gate.entered;
        move || entered.recv().unwrap()
    })
    .await
    .unwrap();

    // The dropper's own lock, held while it drops the awaiting future.
    let dropper_lock = state.path_lock(GROUP, "dropper.bin");
    let held = dropper_lock.clone().lock_owned().await;
    let release = gate.release;
    let dropper = std::thread::spawn(move || task.abort());
    std::thread::sleep(Duration::from_millis(100));
    release.send(()).unwrap();
    dropper.join().unwrap();

    let mut committed = false;
    for _ in 0..300 {
        if state.has_materialization_intent(GROUP, "dropper.bin").unwrap() {
            committed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(dropper_lock.try_lock().is_err(), "the dropper's lock was taken from it");
    assert!(committed, "the job did not commit while the dropper held its lock");
    drop(held);
}

/// The knob: with the commit offloaded it runs on a thread other than the
/// polling one; with `0` it runs in the calling poll, as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_async_commit_knob_moves_the_open_commit_between_threads() {
    async fn thread_of_open(mode: u8) -> (std::thread::ThreadId, std::thread::ThreadId) {
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        state.test_observers.async_commit_override.store(mode, Ordering::Relaxed);
        let commit_thread: Arc<Mutex<Option<std::thread::ThreadId>>> = Arc::default();
        let hook: Arc<dyn Fn() + Send + Sync> = Arc::new({
            let commit_thread = commit_thread.clone();
            move || *commit_thread.lock().unwrap() = Some(std::thread::current().id())
        });
        set_open_gate(&state, hook);
        let row_lease = lease();
        let permit_lease = lease();
        let operation = permit_lease.begin_operation().unwrap();
        let permit = operation.permit();
        let record = record("knob.bin");
        let poller = std::thread::current().id();
        state
            .open_content_write(
                GROUP,
                &record,
                "device-peer",
                None,
                &crate::replica_coordinator::plain_file_columns(),
                &|| Ok(row_lease.clone()),
                &permit,
            )
            .await
            .unwrap();
        let committer = commit_thread.lock().unwrap().expect("the commit ran");
        (poller, committer)
    }

    let (poller, committer) = thread_of_open(1).await;
    assert_ne!(poller, committer, "the commit did not leave the polling thread");
    let (poller, committer) = thread_of_open(2).await;
    assert_eq!(poller, committer, "with the knob off the commit runs in the calling poll");
}

/// The files of a window keep running while a batch commit is blocked on the
/// blocking pool: a sibling future of the run advances during it. With the
/// commit inline in the poll it cannot.
async fn ticks_during_a_blocked_commit(async_commit: bool) -> usize {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let rows = [open_row(&state, "t0.txt", 1).await, open_row(&state, "t1.txt", 2).await];
    let ticks = Arc::new(AtomicUsize::new(0));
    let during: Arc<Mutex<Option<usize>>> = Arc::default();
    *state.test_observers.close_batch_gate.lock().unwrap() = Some(Arc::new({
        let (ticks, during) = (ticks.clone(), during.clone());
        move || {
            let before = ticks.load(Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(300));
            *during.lock().unwrap() = Some(ticks.load(Ordering::SeqCst) - before);
        }
    }));
    let window = CompletionWindow::with_steps(2, Duration::from_secs(10), true, true, async_commit);
    let (a, b, sibling) = (window.join(), window.join(), window.join());
    let _ = (&a, &b);
    let run = async {
        let first = window.submit(&state, item(&rows[0], valid_check()));
        let second = window.submit(&state, item(&rows[1], valid_check()));
        // The sibling queues nothing for a while: it is a file still reading
        // blocks, which a blocked commit must not stall. The two queued items
        // make the batch due at once (cap 2).
        let ticker = async {
            for _ in 0..60 {
                tokio::time::sleep(Duration::from_millis(10)).await;
                ticks.fetch_add(1, Ordering::SeqCst);
            }
            drop(sibling);
        };
        let (first, second, ()) = tokio::join!(first, second, ticker);
        first.unwrap();
        second.unwrap();
    };
    run.await;
    assert!(committed(&state, "t0.txt") && committed(&state, "t1.txt"));
    let delta = during.lock().unwrap().expect("the commit ran");
    delta
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocked_batch_commit_does_not_stall_the_siblings_of_its_window() {
    let delta = ticks_during_a_blocked_commit(true).await;
    assert!(delta >= 10, "the siblings advanced only {delta} times during a 300 ms commit");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_the_knob_off_a_blocked_batch_commit_stalls_the_poll_as_before() {
    let delta = ticks_during_a_blocked_commit(false).await;
    assert_eq!(delta, 0, "an inline commit runs in the poll, so nothing else advances");
}

/// Dropped after its batch was taken, a waiter keeps the guards of its item
/// until the batch's commit is decided: the two waiters' operations are
/// released only after the commit landed, and the commit still lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_run_dropped_while_its_batch_commits_keeps_every_waiters_guards_until_it_is_decided() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let rows = [open_row(&state, "d0.txt", 1).await, open_row(&state, "d1.txt", 2).await];
    let (hook, gate) = gate();
    *state.test_observers.close_batch_gate.lock().unwrap() = Some(hook);
    let window = CompletionWindow::new(8, Duration::from_secs(10));
    let (lease_a, lease_b) = (lease(), lease());
    let (participant_a, participant_b) = (window.join(), window.join());

    let task = tokio::spawn({
        let (state, window) = (state.clone(), window.clone());
        let (lease_a, lease_b) = (lease_a.clone(), lease_b.clone());
        let item_a = item(&rows[0], valid_check());
        let item_b = item(&rows[1], valid_check());
        async move {
            let waiter = |lease: Arc<RootLease>, participant, item| {
                let (state, window) = (state.clone(), window.clone());
                async move {
                    let _operation = lease.begin_operation().unwrap();
                    let _participant = participant;
                    window.submit(&state, item).await
                }
            };
            let _ = tokio::join!(
                waiter(lease_a, participant_a, item_a),
                waiter(lease_b, participant_b, item_b),
            );
        }
    });
    let gate = tokio::task::spawn_blocking(move || {
        gate.entered.recv().unwrap();
        gate
    })
    .await
    .unwrap();
    let (a, b) = (lease_a.clone(), lease_b.clone());
    let released = release_after(gate, Duration::from_millis(300), move || {
        assert!(
            !drained_within_blocking(&a, Duration::from_millis(50)),
            "a waiter's operation was released while its batch was committing"
        );
        assert!(
            !drained_within_blocking(&b, Duration::from_millis(50)),
            "a waiter's operation was released while its batch was committing"
        );
    });
    task.abort();
    let _ = task.await;
    released.join().unwrap();
    *state.test_observers.close_batch_gate.lock().unwrap() = None;

    assert!(drained_within(&lease_a, Duration::from_secs(2)).await);
    assert!(drained_within(&lease_b, Duration::from_secs(2)).await);
    assert!(committed(&state, "d0.txt") && committed(&state, "d1.txt"), "the batch must land");
}

/// A panic in the offloaded commit rolls the transaction back, fails every
/// waiter with an error (no hang), and leaves the window usable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panic_in_the_offloaded_flush_fails_the_waiters_and_commits_nothing() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let rows = [open_row(&state, "p0.txt", 1).await, open_row(&state, "p1.txt", 2).await];
    let armed = Arc::new(AtomicBool::new(true));
    *state.test_observers.close_batch_gate.lock().unwrap() = Some(Arc::new({
        let armed = armed.clone();
        move || {
            if armed.swap(false, Ordering::SeqCst) {
                panic!("injected panic inside the batch commit");
            }
        }
    }));
    let window = CompletionWindow::new(8, Duration::from_secs(10));
    let (a, b) = (window.join(), window.join());
    let (first, second) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            window.submit(&state, item(&rows[0], valid_check())),
            window.submit(&state, item(&rows[1], valid_check())),
        )
    })
    .await
    .expect("a waiter hung after the job panicked");
    assert!(first.is_err() && second.is_err(), "every waiter of a panicked batch errors");
    assert!(untouched(&state, "p0.txt") && untouched(&state, "p1.txt"));

    // The window still works: the same items commit on the next attempt.
    let (first, second) = tokio::join!(
        window.submit(&state, item(&rows[0], valid_check())),
        window.submit(&state, item(&rows[1], valid_check())),
    );
    first.unwrap();
    second.unwrap();
    assert!(committed(&state, "p0.txt") && committed(&state, "p1.txt"));
    drop((a, b));
}
