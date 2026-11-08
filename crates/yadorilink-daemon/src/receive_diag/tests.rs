use super::*;

/// This file's own lock sites: other tests running in the process while the
/// instrument is armed record theirs too.
fn own_sites() -> Vec<LockSiteStat> {
    lock_site_stats()
        .into_iter()
        .filter(|s| s.site.replace('\\', "/").contains("receive_diag/tests.rs"))
        .collect()
}

/// Serialises the tests that arm the process-global instruments, so one
/// cannot observe another's recordings or see it disarm mid-run.
pub(crate) static GLOBAL_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Every instrument is inert until armed; armed, each acquisition records
/// its wait and hold against the CALLER's source line; disarming stops it.
#[tokio::test]
async fn path_lock_recording_is_inert_until_armed_and_keyed_on_the_caller() {
    let _owner = GLOBAL_TEST_LOCK.lock().await;
    set_enabled(false);
    reset();
    let lock = tokio::sync::Mutex::new(());

    drop(lock_path(&lock).await);
    assert!(start().is_none(), "no clock read while unarmed");
    assert!(own_sites().is_empty(), "unarmed: nothing recorded");

    set_enabled(true);
    drop(lock_path(&lock).await);
    let held = lock_path(&lock).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    drop(held);
    set_enabled(false);
    drop(lock_path(&lock).await);

    let sites = own_sites();
    assert_eq!(sites.len(), 2, "two distinct call sites were armed: {sites:?}");
    assert_eq!(
        sites.iter().map(|s| s.acquisitions).sum::<u64>(),
        2,
        "the disarmed one is not counted"
    );
    let longest = &sites[0];
    assert!(longest.hold_nanos >= 20_000_000, "the 20ms hold is the longest: {longest:?}");
    assert!(longest.hold_max_nanos >= 20_000_000);
    reset();
}

/// A second task blocked on the lock shows up as wait time at ITS site, not
/// the holder's. No sleeps: the waiter is polled once, which starts its wait and finds the lock
/// held; the time the test then lets pass before releasing the holder is a lower bound the
/// recorded wait must cover (both read the same monotonic clock), whatever the timer granularity.
#[tokio::test]
async fn a_blocked_acquisition_records_its_wait_at_its_own_site() {
    use std::future::Future;
    let _owner = GLOBAL_TEST_LOCK.lock().await;
    reset();
    set_enabled(true);
    let lock = std::sync::Arc::new(tokio::sync::Mutex::new(()));
    let holder = lock.clone();
    let (held_tx, held_rx) = tokio::sync::oneshot::channel::<()>();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let hold = tokio::spawn(async move {
        let _g = holder.lock().await;
        held_tx.send(()).unwrap();
        release_rx.await.unwrap();
    });
    held_rx.await.unwrap();

    let waiter = lock_path(&lock);
    tokio::pin!(waiter);
    let blocked =
        std::future::poll_fn(|cx| std::task::Poll::Ready(waiter.as_mut().poll(cx).is_pending()))
            .await;
    assert!(blocked, "the holder has the lock");
    let blocked_since = std::time::Instant::now();
    // Let some real time pass while it is provably blocked, so the bound below is not empty.
    tokio::task::yield_now().await;
    let released_at = std::time::Instant::now();
    release_tx.send(()).unwrap();
    drop(waiter.await);
    hold.await.unwrap();
    set_enabled(false);

    let sites = own_sites();
    assert_eq!(sites.len(), 1, "{sites:?}");
    let observed_blocked = released_at.saturating_duration_since(blocked_since).as_nanos();
    assert!(
        sites[0].wait_nanos >= observed_blocked,
        "the wait covers the time it was seen blocked ({observed_blocked} ns): {:?}",
        sites[0]
    );
    assert_eq!(sites[0].acquisitions, 1);
    reset();
}

/// Informal overhead check; prints numbers, asserts nothing, run explicitly:
/// `cargo test -p yadorilink-daemon --lib receive_diag::tests::overhead -- --ignored --nocapture`.
///
/// Each primitive is timed bare, instrumented but disarmed, and armed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "measurement; run explicitly"]
async fn overhead_of_the_instrumented_primitives() {
    use std::hint::black_box;
    let _owner = GLOBAL_TEST_LOCK.lock().await;
    reset();
    let per = |d: Duration, n: u32| d.as_nanos() as f64 / f64::from(n);

    // A real syscall: rename a small file back and forth in a temp dir.
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    std::fs::write(&a, b"x").unwrap();
    const SYSCALLS: u32 = 20_000;
    let run_rename = |instrumented: bool| {
        let started = Instant::now();
        for i in 0..SYSCALLS {
            let (from, to) = if i % 2 == 0 { (&a, &b) } else { (&b, &a) };
            if instrumented {
                yadorilink_local_storage::io_diag::time(
                    yadorilink_local_storage::io_diag::Op::Rename,
                    0,
                    || std::fs::rename(from, to),
                )
                .unwrap();
            } else {
                std::fs::rename(black_box(from), to).unwrap();
            }
        }
        started.elapsed()
    };
    yadorilink_local_storage::io_diag::set_enabled(false);
    let bare = run_rename(false);
    let off = run_rename(true);
    yadorilink_local_storage::io_diag::set_enabled(true);
    let on = run_rename(true);
    yadorilink_local_storage::io_diag::set_enabled(false);
    println!(
        "rename ns/op: bare {:.0}, disarmed {:.0}, armed {:.0} ({:+.2}% vs bare)",
        per(bare, SYSCALLS),
        per(off, SYSCALLS),
        per(on, SYSCALLS),
        (per(on, SYSCALLS) / per(bare, SYSCALLS) - 1.0) * 100.0
    );

    // The path lock, uncontended: the cheapest thing it wraps.
    let lock = tokio::sync::Mutex::new(());
    const LOCKS: u32 = 200_000;
    let started = Instant::now();
    for _ in 0..LOCKS {
        drop(black_box(lock.lock().await));
    }
    let bare = started.elapsed();
    let started = Instant::now();
    for _ in 0..LOCKS {
        drop(black_box(lock_path(&lock).await));
    }
    let off = started.elapsed();
    set_enabled(true);
    let started = Instant::now();
    for _ in 0..LOCKS {
        drop(black_box(lock_path(&lock).await));
    }
    let on = started.elapsed();
    set_enabled(false);
    println!(
        "path lock ns/op (uncontended): bare {:.0}, disarmed {:.0}, armed {:.0} (armed adds {:.0} ns)",
        per(bare, LOCKS),
        per(off, LOCKS),
        per(on, LOCKS),
        per(on, LOCKS) - per(bare, LOCKS)
    );
    reset();
}

/// A settle run's stage steps add up to its wall time, are inert unarmed, and
/// a mark outside any run records nothing.
#[tokio::test]
async fn a_run_trace_partitions_the_run_wall_time_by_the_last_file_to_reach_each_stage() {
    let _owner = GLOBAL_TEST_LOCK.lock().await;
    set_enabled(false);
    reset();
    assert!(run_trace_begin().is_none(), "no trace unarmed");
    mark(Stage::Locked);

    set_enabled(true);
    mark(Stage::Locked); // outside any run: dropped
    let trace = run_trace_begin();
    run_trace_scope(trace.clone(), async {
        // Two files: the first reaches the lock quickly, the second late.
        mark(Stage::Started);
        mark(Stage::Started);
        mark(Stage::Locked);
        tokio::time::sleep(Duration::from_millis(30)).await;
        mark(Stage::Locked);
        tokio::time::sleep(Duration::from_millis(10)).await;
        mark(Stage::Closed);
    })
    .await;
    // Record into this test's own distributions: other tests' settle runs
    // (which do not take the lock) feed the process-global ones while armed.
    let step: [Dist; STAGES + 1] = std::array::from_fn(|_| Dist::new());
    let spread: [Dist; STAGES] = std::array::from_fn(|_| Dist::new());
    record_run(&trace.expect("armed"), &step, &spread);
    set_enabled(false);

    let lock = step[Stage::Locked as usize].total();
    let close = step[Stage::Closed as usize].total();
    let tail = step[STAGES].total();
    assert!(lock >= 30_000_000, "the late file's lock sets the lock step: {lock}");
    assert!((10_000_000..30_000_000).contains(&close), "close step: {close}");
    assert_eq!(step[STAGES].count(), 1);
    assert!(tail < 5_000_000, "nothing after the last stage: {tail}");
    assert!(spread[Stage::Locked as usize].total() >= 30_000_000, "first and last differ");
    reset();
}

/// The block-reuse counters are inert until armed, and armed they split the
/// planned blocks into store-held and fetched ones.
#[tokio::test]
async fn block_reuse_is_inert_until_armed_and_counts_held_and_fetched_blocks() {
    let _owner = GLOBAL_TEST_LOCK.lock().await;
    set_enabled(false);
    reset();
    record_block_planned(true, 100);
    record_block_fetched(100);
    assert_eq!(block_source_counts(), (0, 0, 0), "unarmed: nothing recorded");

    set_enabled(true);
    record_block_planned(true, 100);
    record_block_planned(false, 200);
    record_block_planned(false, 200);
    record_block_fetched(200);
    set_enabled(false);
    assert_eq!(block_source_counts(), (3, 1, 1));
    assert_eq!(DEDUP_STORE_BYTES.load(Ordering::Relaxed), 100);
    assert_eq!(DEDUP_BYTES.load(Ordering::Relaxed), 500);
    reset();
    assert_eq!(block_source_counts(), (0, 0, 0));
}
