use super::*;

/// The batch is a knob with a small default, and a build yields between batches while idle
/// polling stays slow.
#[test]
fn the_batch_is_a_knob_and_a_build_yields_between_batches() {
    assert_eq!(batch_from(None), 1_000);
    assert_eq!(batch_from(Some("250")), 250);
    assert_eq!(batch_from(Some(" 4000 ")), 4_000);
    for bad in ["0", "-3", "many", ""] {
        assert_eq!(batch_from(Some(bad)), 1_000, "{bad:?}");
    }
    assert_eq!(next_delay(&Tick { projected: 1_000, ..Tick::default() }), YIELD);
    assert_eq!(next_delay(&Tick::default()), POLL);
    assert!(YIELD < POLL);
    // A failed tick retries on the short interval (the loop does not wait for a write then).
    assert_eq!(next_delay(&Tick { failed: true, ..Tick::default() }), POLL);
}

/// A change nobody announced to the OS (such as a pin changing what it may do with an item) gets
/// the root's publication driver kicked, once per pass until it is announced.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unannounced_change_kicks_the_publication_driver() {
    use crate::provider_read_fault::declared_root;
    use std::sync::Mutex;
    let (coordinator, root) = declared_root();
    let store = Arc::new(
        yadorilink_local_storage::SegmentBlockStore::new(tempfile::tempdir().unwrap().keep())
            .unwrap(),
    );
    let state = DaemonState::new("device-a".into(), coordinator.clone(), store);
    let kicked = Mutex::new(Vec::<String>::new());
    let kick = |root: &str| kicked.lock().unwrap().push(root.to_owned());

    pass(&state, 10, kick).await.unwrap();
    assert!(kicked.lock().unwrap().is_empty(), "a quiet root was kicked");
    coordinator
        .database()
        .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
            tx.execute("UPDATE provider_roots SET change_seq = 1", [])?;
            Ok(())
        })
        .unwrap();
    pass(&state, 10, kick).await.unwrap();
    assert_eq!(*kicked.lock().unwrap(), vec![root.clone()]);
    coordinator.provider_repository().mark_announced(&root, 1).unwrap();
    pass(&state, 10, kick).await.unwrap();
    assert_eq!(kicked.lock().unwrap().len(), 1, "an announced change was kicked again");
}

/// A root listing that fails is reported as such (and projects nothing); the next pass that can
/// read resumes the work for the root.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_root_list_is_not_a_pass_over_zero_roots() {
    use crate::provider_read_fault::{declared_root, Fault};
    use std::sync::Mutex;
    let (coordinator, _root) = declared_root();
    let store = Arc::new(
        yadorilink_local_storage::SegmentBlockStore::new(tempfile::tempdir().unwrap().keep())
            .unwrap(),
    );
    let state = DaemonState::new("device-a".into(), coordinator.clone(), store);
    let kicked = Mutex::new(Vec::<String>::new());
    let kick = |root: &str| kicked.lock().unwrap().push(root.to_owned());

    let fault = Fault::inject(&coordinator, "links", "provider_kind");
    assert_eq!(pass(&state, 10, kick).await.unwrap(), Pass::RootsUnreadable);
    assert!(kicked.lock().unwrap().is_empty());
    fault.restore();

    assert!(matches!(pass(&state, 10, kick).await.unwrap(), Pass::Done { roots: 1, .. }));
}

/// One failed batch is retried on the short interval: the cause (a busy or briefly unreadable
/// database) can clear without any write, and the loop then must not fall into the idle wait for
/// a write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_batch_is_retried_promptly_not_on_the_idle_backstop() {
    use crate::provider_read_fault::{declared_root, Fault};
    let (coordinator, _root) = declared_root();
    let store = Arc::new(
        yadorilink_local_storage::SegmentBlockStore::new(tempfile::tempdir().unwrap().keep())
            .unwrap(),
    );
    let state = DaemonState::new("device-a".into(), coordinator.clone(), store);

    let fault = Fault::inject(&coordinator, "projection_obligations", "path");
    match pass(&state, 10, |_| {}).await.unwrap() {
        Pass::Done { delay, retry, .. } => {
            assert!(retry, "a failed batch was not marked for retry");
            assert_eq!(delay, POLL);
            assert!(delay < IDLE_BACKSTOP);
        }
        other => panic!("{other:?}"),
    }
    fault.restore();

    // The fault is gone and no write happened: the next pass works and finds nothing to retry.
    match pass(&state, 10, |_| {}).await.unwrap() {
        Pass::Done { retry, .. } => assert!(!retry),
        other => panic!("{other:?}"),
    }
}

/// After a failed tick the loop waits the short interval, not the idle backstop, even though no
/// write arrives; a quiet pass still waits for a write (or the backstop).
#[tokio::test(start_paused = true)]
async fn the_loop_retries_a_failed_pass_after_the_short_interval_without_a_write() {
    let (tx, mut writes) = tokio::sync::watch::channel(0u64);
    let _keep = &tx;
    let mut backoff = Backoff::new();
    let failed = Pass::Done { roots: 1, delay: POLL, retry: true };
    let started = tokio::time::Instant::now();
    wait_after(&failed, &mut writes, &mut backoff).await;
    assert_eq!(started.elapsed(), POLL, "a failed pass did not retry after the poll interval");

    let quiet = Pass::Done { roots: 1, delay: POLL, retry: false };
    let started = tokio::time::Instant::now();
    wait_after(&quiet, &mut writes, &mut backoff).await;
    assert_eq!(started.elapsed(), IDLE_BACKSTOP);

    // A write wakes a quiet wait at once.
    let waiting = tokio::spawn(async move {
        wait_after(&quiet, &mut writes, &mut backoff).await;
    });
    tokio::task::yield_now().await;
    tx.send_modify(|g| *g += 1);
    tokio::time::timeout(Duration::from_millis(1), waiting).await.unwrap().unwrap();
}

/// A fault that lasts costs a few wakeups a minute, not four a second: each consecutive failure
/// doubles the wait up to the idle backstop, and one pass that does not fail starts over. Holds for
/// a failed tick and for an unreadable root list alike.
#[tokio::test(start_paused = true)]
async fn a_lasting_fault_backs_off_to_the_idle_backstop_and_recovery_resets_it() {
    let (tx, mut writes) = tokio::sync::watch::channel(0u64);
    let _keep = &tx;
    let mut backoff = Backoff::new();
    let failed = Pass::Done { roots: 1, delay: POLL, retry: true };

    let mut waits = Vec::new();
    for outcome in [&failed, &Pass::RootsUnreadable, &failed, &Pass::RootsUnreadable] {
        let started = tokio::time::Instant::now();
        wait_after(outcome, &mut writes, &mut backoff).await;
        waits.push(started.elapsed());
    }
    assert_eq!(
        waits,
        [POLL, POLL * 2, POLL * 4, POLL * 8],
        "consecutive failures did not double the retry wait"
    );

    for _ in 0..10 {
        wait_after(&failed, &mut writes, &mut backoff).await;
    }
    let started = tokio::time::Instant::now();
    wait_after(&Pass::RootsUnreadable, &mut writes, &mut backoff).await;
    assert_eq!(started.elapsed(), IDLE_BACKSTOP, "the backoff grew past the idle backstop");

    // A pass that did not fail starts over.
    let quiet = Pass::Done { roots: 1, delay: POLL, retry: false };
    let mut quiet_writes = writes.clone();
    tx.send_modify(|g| *g += 1);
    wait_after(&quiet, &mut quiet_writes, &mut backoff).await;
    writes.borrow_and_update();
    let started = tokio::time::Instant::now();
    wait_after(&failed, &mut writes, &mut backoff).await;
    assert_eq!(started.elapsed(), POLL, "recovery did not reset the retry wait");
}

/// Recovery that arrives as a write ends a backed-off retry wait without waiting out the backoff,
/// but never sooner than the first retry delay, so a failing pass that itself writes cannot run
/// back to back.
#[tokio::test(start_paused = true)]
async fn a_write_ends_a_backed_off_retry_wait_within_the_first_retry_delay() {
    let (tx, mut writes) = tokio::sync::watch::channel(0u64);
    let mut backoff = Backoff::new();
    for _ in 0..8 {
        wait_after(&Pass::RootsUnreadable, &mut writes, &mut backoff).await;
    }
    let started = tokio::time::Instant::now();
    let waiting = tokio::spawn(async move {
        wait_after(&Pass::RootsUnreadable, &mut writes, &mut backoff).await;
    });
    tokio::task::yield_now().await;
    tx.send_modify(|g| *g += 1);
    waiting.await.unwrap();
    assert_eq!(started.elapsed(), POLL, "the write neither ended the wait nor respected the floor");
}

/// A closed write channel (its sender dropped) must not turn a retry wait into a busy loop.
#[tokio::test(start_paused = true)]
async fn a_closed_write_channel_does_not_turn_a_retry_wait_into_a_busy_loop() {
    let (tx, mut writes) = tokio::sync::watch::channel(0u64);
    drop(tx);
    let mut backoff = Backoff::new();
    let started = tokio::time::Instant::now();
    wait_after(&Pass::RootsUnreadable, &mut writes, &mut backoff).await;
    assert_eq!(started.elapsed(), POLL);
    let started = tokio::time::Instant::now();
    wait_after(&Pass::RootsUnreadable, &mut writes, &mut backoff).await;
    assert_eq!(started.elapsed(), POLL * 2, "the delay did not keep growing on a closed channel");
}

/// A build that is producing batches resets the retry delay: a fault after it starts again from
/// the first retry delay.
#[tokio::test(start_paused = true)]
async fn a_build_in_progress_resets_the_retry_delay() {
    let (tx, mut writes) = tokio::sync::watch::channel(0u64);
    let _keep = &tx;
    let mut backoff = Backoff::new();
    let failed = Pass::Done { roots: 1, delay: POLL, retry: true };
    for _ in 0..4 {
        wait_after(&failed, &mut writes, &mut backoff).await;
    }
    wait_after(&Pass::Done { roots: 1, delay: YIELD, retry: false }, &mut writes, &mut backoff)
        .await;
    let started = tokio::time::Instant::now();
    wait_after(&failed, &mut writes, &mut backoff).await;
    assert_eq!(started.elapsed(), POLL);
}
