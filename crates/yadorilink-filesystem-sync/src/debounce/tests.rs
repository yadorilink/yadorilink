#![cfg(test)]

use super::*;

/// Serializes every test that installs its own `tracing::subscriber::
/// set_default` -- `tracing`'s own global max-level cache is process-
/// wide, not thread-local, so two such tests genuinely running at the
/// same wall-clock time (`cargo test`'s default parallelism runs each
/// `#[test]` on its own OS thread) can race that shared cache and
/// cause a `tracing::warn!` call in one test's own debouncer task to be
/// silently filtered out for the whole run, not merely delayed --
/// confirmed empirically (isolated and `--test-threads=1` runs never
/// flake; concurrent runs did, consistently in the same test, even
/// after polling the log buffer for up to 5s found nothing). Every
/// other test in this module is unaffected and stays fully parallel.
static TRACING_TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn no_overflow() -> std::sync::Arc<std::sync::atomic::AtomicBool> {
    std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false))
}

/// A `flush_requests` receiver for tests that don't exercise
/// the targeted-flush
/// mechanism — the sender is simply dropped, so `run_debouncer` sees a
/// closed channel and stops polling it (see `flush_requests_open`).
fn no_flush_requests() -> mpsc::Receiver<FlushPathRequest> {
    let (_tx, rx) = mpsc::channel(1);
    rx
}

fn no_flush_all_requests() -> mpsc::Receiver<FlushAllRequest> {
    let (_tx, rx) = mpsc::channel(1);
    rx
}

fn short_config() -> DebounceConfig {
    DebounceConfig {
        quiet_period: Duration::from_millis(30),
        max_flush_interval: Duration::from_millis(150),
        burst_threshold: 5,
    }
}

/// Strips the per-path observed timestamp — most existing assertions
/// only care about which paths/kinds flushed, not the exact wall-clock
/// time attached to each.
fn expect_paths(flush: DebounceFlush) -> Vec<(PathBuf, FsChangeKind)> {
    match flush {
        DebounceFlush::Paths(paths) => {
            paths.into_iter().map(|(path, kind, _at)| (path, kind)).collect()
        }
        DebounceFlush::RescanRequired => panic!("expected Paths, got RescanRequired"),
    }
}

/// A single event flushes after the quiet period, with the expected
/// path and kind — the common case's latency floor.
#[tokio::test]
async fn single_event_flushes_after_the_quiet_period() {
    let (events_tx, events_rx) = mpsc::channel(16);
    let (flush_tx, mut flush_rx) = mpsc::channel(16);
    tokio::spawn(run_debouncer(
        short_config(),
        events_rx,
        flush_tx,
        no_overflow(),
        no_flush_requests(),
        no_flush_all_requests(),
    ));

    let started = Instant::now();
    events_tx
        .send(FsChangeEvent { path: "a.txt".into(), kind: FsChangeKind::CreatedOrModified })
        .await
        .unwrap();

    let flush = tokio::time::timeout(Duration::from_secs(2), flush_rx.recv())
        .await
        .expect("timed out waiting for flush")
        .unwrap();
    let elapsed = started.elapsed();

    let paths = expect_paths(flush);
    assert_eq!(paths, vec![(PathBuf::from("a.txt"), FsChangeKind::CreatedOrModified)]);
    assert!(elapsed >= Duration::from_millis(30), "flushed too early: {elapsed:?}");
    assert!(elapsed < Duration::from_millis(500), "flush latency too high: {elapsed:?}");
}

/// The targeted
/// "flush now" mechanism: a path with a pending, undispatched entry is
/// handed back (and removed) immediately, well before the normal quiet
/// period would otherwise flush it — and is never flushed a second
/// time once its window's timer does elapse.
#[tokio::test]
async fn flush_path_request_hands_back_and_removes_a_pending_entry_immediately() {
    let (events_tx, events_rx) = mpsc::channel(16);
    let (flush_tx, mut flush_rx) = mpsc::channel(16);
    let (flush_requests_tx, flush_requests_rx) = mpsc::channel(4);
    tokio::spawn(run_debouncer(
        short_config(),
        events_rx,
        flush_tx,
        no_overflow(),
        flush_requests_rx,
        no_flush_all_requests(),
    ));

    events_tx
        .send(FsChangeEvent { path: "a.txt".into(), kind: FsChangeKind::CreatedOrModified })
        .await
        .unwrap();
    // `send.await` only guarantees the event reached the channel
    // buffer, not that the spawned accumulator task has already polled
    // it into `pending` — give it a moment before racing a flush
    // request against it, well under the 30ms quiet period below.
    tokio::time::sleep(Duration::from_millis(10)).await;

    let started = Instant::now();
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    flush_requests_tx
        .send(FlushPathRequest {
            path: "a.txt".into(),
            mode: FlushMode::ExactPath,
            reply: reply_tx,
        })
        .await
        .unwrap();
    let found = tokio::time::timeout(Duration::from_secs(1), reply_rx)
        .await
        .expect("timed out waiting for the flush-request reply")
        .unwrap();
    let (found_path, found_kind, _found_at) = found.expect("expected a pending entry for a.txt");
    assert_eq!(found_path, PathBuf::from("a.txt"));
    assert_eq!(found_kind, FsChangeKind::CreatedOrModified);
    assert!(
        started.elapsed() < Duration::from_millis(20),
        "a targeted flush request must not wait for the normal quiet period: {:?}",
        started.elapsed()
    );

    // The normal window timer, still armed, must not re-deliver "a.txt"
    // now that it's been claimed by the targeted request above.
    let flush = tokio::time::timeout(Duration::from_millis(300), flush_rx.recv()).await;
    match flush {
        Ok(Some(DebounceFlush::Paths(paths))) => {
            assert!(paths.is_empty(), "already-claimed path must not be flushed again: {paths:?}")
        }
        Ok(Some(DebounceFlush::RescanRequired)) => panic!("unexpected burst fallback"),
        Ok(None) => panic!("accumulator task ended unexpectedly"),
        Err(_) => {} // no flush at all is also an acceptable outcome
    }

    // A second request for the same path now finds nothing pending.
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    flush_requests_tx
        .send(FlushPathRequest {
            path: "a.txt".into(),
            mode: FlushMode::ExactPath,
            reply: reply_tx,
        })
        .await
        .unwrap();
    let found_again =
        tokio::time::timeout(Duration::from_secs(1), reply_rx).await.unwrap().unwrap();
    assert_eq!(found_again, None);
}

/// The same targeted flush, but with **no** settle between the event
/// and the request — the event is still sitting unread in `events`
/// when the request arrives, which the `biased` `select!` services
/// first.
///
/// Before `drain_ready_events`, this replied `None`, and the test above
/// only passed because of its 10ms sleep. That `None` is not a delay,
/// it is data loss: `flush_pending_local_change_before_reconcile` reads
/// it as "no local edit here", admits the incoming remote change, and
/// materializes it over the local write on disk — after which
/// `process_flush` re-reads the path, sees the remote bytes already
/// matching the index, and suppresses the whole thing as a self-echo.
/// This is the unit-level form of the retired network-fault scenario's
/// `[NoLoss]` violation on seeds 3298840576/3298840578.
///
/// No sleep here on purpose: the guarantee under test is precisely
/// that a caller does not need one.
#[tokio::test]
async fn flush_path_request_sees_an_event_still_queued_when_it_arrives() {
    let (events_tx, events_rx) = mpsc::channel(16);
    let (flush_tx, _flush_rx) = mpsc::channel(16);
    let (flush_requests_tx, flush_requests_rx) = mpsc::channel(4);
    tokio::spawn(run_debouncer(
        short_config(),
        events_rx,
        flush_tx,
        no_overflow(),
        flush_requests_rx,
        no_flush_all_requests(),
    ));

    events_tx
        .send(FsChangeEvent { path: "a.txt".into(), kind: FsChangeKind::CreatedOrModified })
        .await
        .unwrap();
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    flush_requests_tx
        .send(FlushPathRequest {
            path: "a.txt".into(),
            mode: FlushMode::ExactPath,
            reply: reply_tx,
        })
        .await
        .unwrap();

    let found = tokio::time::timeout(Duration::from_secs(1), reply_rx)
        .await
        .expect("timed out waiting for the flush-request reply")
        .unwrap();
    let (found_path, found_kind, _at) = found.expect(
        "a flush request must see an event the watcher already delivered, even if the \
         accumulator has not polled it yet -- replying None here loses the local write",
    );
    assert_eq!(found_path, PathBuf::from("a.txt"));
    assert_eq!(found_kind, FsChangeKind::CreatedOrModified);
}

/// The `FlushAll` variant of the guarantee directly above.
#[tokio::test]
async fn flush_all_request_sees_events_still_queued_when_it_arrives() {
    let (events_tx, events_rx) = mpsc::channel(16);
    let (flush_tx, _flush_rx) = mpsc::channel(16);
    let (flush_all_tx, flush_all_rx) = mpsc::channel(4);
    tokio::spawn(run_debouncer(
        short_config(),
        events_rx,
        flush_tx,
        no_overflow(),
        no_flush_requests(),
        flush_all_rx,
    ));

    for name in ["a.txt", "b.txt"] {
        events_tx
            .send(FsChangeEvent { path: name.into(), kind: FsChangeKind::CreatedOrModified })
            .await
            .unwrap();
    }
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    flush_all_tx.send(FlushAllRequest { reply: reply_tx }).await.unwrap();

    let drained = tokio::time::timeout(Duration::from_secs(1), reply_rx)
        .await
        .expect("timed out waiting for the flush-all reply")
        .unwrap();
    let mut paths: Vec<_> = drained.into_iter().map(|(path, _, _)| path).collect();
    paths.sort();
    assert_eq!(paths, vec![PathBuf::from("a.txt"), PathBuf::from("b.txt")]);
}

/// `FlushMode::CaseFoldSibling` finds and removes a *different*
/// pending path in the same directory whose final component is
/// case-fold-equal to the requested one, leaving an exact-byte match
/// (there is none here) or an unrelated path (`b.txt`) untouched.
#[tokio::test]
async fn flush_case_fold_sibling_finds_a_differently_cased_pending_entry() {
    let (events_tx, events_rx) = mpsc::channel(16);
    let (flush_tx, _flush_rx) = mpsc::channel(16);
    let (flush_requests_tx, flush_requests_rx) = mpsc::channel(4);
    tokio::spawn(run_debouncer(
        short_config(),
        events_rx,
        flush_tx,
        no_overflow(),
        flush_requests_rx,
        no_flush_all_requests(),
    ));

    events_tx
        .send(FsChangeEvent { path: "Shared.bin".into(), kind: FsChangeKind::CreatedOrModified })
        .await
        .unwrap();
    events_tx
        .send(FsChangeEvent { path: "b.txt".into(), kind: FsChangeKind::CreatedOrModified })
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    flush_requests_tx
        .send(FlushPathRequest {
            path: "shared.bin".into(),
            mode: FlushMode::CaseFoldSibling,
            reply: reply_tx,
        })
        .await
        .unwrap();
    let found = tokio::time::timeout(Duration::from_secs(1), reply_rx).await.unwrap().unwrap();
    let (found_path, found_kind, _found_at) = found.expect("expected Shared.bin to be found");
    assert_eq!(found_path, PathBuf::from("Shared.bin"));
    assert_eq!(found_kind, FsChangeKind::CreatedOrModified);

    // A second request now finds nothing (already removed), and
    // `b.txt` was never a candidate to begin with.
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    flush_requests_tx
        .send(FlushPathRequest {
            path: "shared.bin".into(),
            mode: FlushMode::CaseFoldSibling,
            reply: reply_tx,
        })
        .await
        .unwrap();
    let found_again =
        tokio::time::timeout(Duration::from_secs(1), reply_rx).await.unwrap().unwrap();
    assert_eq!(found_again, None);
}

/// `FlushAllRequest`
/// drains every pending entry at once (not just one path), leaving the
/// accumulator empty and back in `Idle` afterward.
#[tokio::test]
async fn flush_all_request_drains_every_pending_entry_at_once() {
    let (events_tx, events_rx) = mpsc::channel(16);
    let (flush_tx, mut flush_rx) = mpsc::channel(16);
    let (_flush_requests_tx, flush_requests_rx) = mpsc::channel(4);
    let (flush_all_requests_tx, flush_all_requests_rx) = mpsc::channel(4);
    tokio::spawn(run_debouncer(
        short_config(),
        events_rx,
        flush_tx,
        no_overflow(),
        flush_requests_rx,
        flush_all_requests_rx,
    ));

    events_tx
        .send(FsChangeEvent { path: "a.txt".into(), kind: FsChangeKind::CreatedOrModified })
        .await
        .unwrap();
    events_tx
        .send(FsChangeEvent { path: "b.txt".into(), kind: FsChangeKind::ObservedRemoval })
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    let started = Instant::now();
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    flush_all_requests_tx.send(FlushAllRequest { reply: reply_tx }).await.unwrap();
    let mut drained =
        tokio::time::timeout(Duration::from_secs(1), reply_rx).await.unwrap().unwrap();
    drained.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        drained.into_iter().map(|(path, kind, _at)| (path, kind)).collect::<Vec<_>>(),
        vec![
            (PathBuf::from("a.txt"), FsChangeKind::CreatedOrModified),
            (PathBuf::from("b.txt"), FsChangeKind::ObservedRemoval),
        ]
    );
    assert!(
        started.elapsed() < Duration::from_millis(20),
        "a flush-all request must not wait for the normal quiet period: {:?}",
        started.elapsed()
    );

    // Everything already having been drained, the normal window timer
    // (still armed a moment ago) must not re-deliver either path.
    let flush = tokio::time::timeout(Duration::from_millis(300), flush_rx.recv()).await;
    match flush {
        Ok(Some(DebounceFlush::Paths(paths))) => {
            assert!(paths.is_empty(), "already-drained paths must not be flushed again: {paths:?}")
        }
        Ok(Some(DebounceFlush::RescanRequired)) => panic!("unexpected burst fallback"),
        Ok(None) => panic!("accumulator task ended unexpectedly"),
        Err(_) => {} // no flush at all is also an acceptable outcome
    }

    // A second flush-all request now finds nothing pending.
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    flush_all_requests_tx.send(FlushAllRequest { reply: reply_tx }).await.unwrap();
    let drained_again =
        tokio::time::timeout(Duration::from_secs(1), reply_rx).await.unwrap().unwrap();
    assert!(drained_again.is_empty());
}

/// Multiple events for the same path within one window coalesce into
/// one flush entry using the last-observed kind.
#[tokio::test]
async fn repeated_events_for_the_same_path_coalesce_to_the_latest_kind() {
    let (events_tx, events_rx) = mpsc::channel(16);
    let (flush_tx, mut flush_rx) = mpsc::channel(16);
    tokio::spawn(run_debouncer(
        short_config(),
        events_rx,
        flush_tx,
        no_overflow(),
        no_flush_requests(),
        no_flush_all_requests(),
    ));

    events_tx
        .send(FsChangeEvent { path: "a.txt".into(), kind: FsChangeKind::CreatedOrModified })
        .await
        .unwrap();
    events_tx
        .send(FsChangeEvent { path: "a.txt".into(), kind: FsChangeKind::CreatedOrModified })
        .await
        .unwrap();
    events_tx
        .send(FsChangeEvent { path: "a.txt".into(), kind: FsChangeKind::ObservedRemoval })
        .await
        .unwrap();

    let flush = tokio::time::timeout(Duration::from_secs(2), flush_rx.recv())
        .await
        .expect("timed out waiting for flush")
        .unwrap();
    let paths = expect_paths(flush);
    assert_eq!(paths, vec![(PathBuf::from("a.txt"), FsChangeKind::ObservedRemoval)]);
}

/// Events for different paths within one window all land in the same
/// flush.
#[tokio::test]
async fn multiple_distinct_paths_in_one_window_flush_together() {
    let (events_tx, events_rx) = mpsc::channel(16);
    let (flush_tx, mut flush_rx) = mpsc::channel(16);
    tokio::spawn(run_debouncer(
        short_config(),
        events_rx,
        flush_tx,
        no_overflow(),
        no_flush_requests(),
        no_flush_all_requests(),
    ));

    for name in ["a.txt", "b.txt", "c.txt"] {
        events_tx
            .send(FsChangeEvent { path: name.into(), kind: FsChangeKind::CreatedOrModified })
            .await
            .unwrap();
    }

    let flush = tokio::time::timeout(Duration::from_secs(2), flush_rx.recv())
        .await
        .expect("timed out waiting for flush")
        .unwrap();
    let mut paths = expect_paths(flush);
    paths.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        paths,
        vec![
            (PathBuf::from("a.txt"), FsChangeKind::CreatedOrModified),
            (PathBuf::from("b.txt"), FsChangeKind::CreatedOrModified),
            (PathBuf::from("c.txt"), FsChangeKind::CreatedOrModified),
        ]
    );
}

/// Events for the same path split across two separate windows (a
/// quiet period elapses between them) each get their own flush,
/// rather than being merged into one.
#[tokio::test]
async fn events_split_across_two_windows_flush_separately() {
    let (events_tx, events_rx) = mpsc::channel(16);
    let (flush_tx, mut flush_rx) = mpsc::channel(16);
    tokio::spawn(run_debouncer(
        short_config(),
        events_rx,
        flush_tx,
        no_overflow(),
        no_flush_requests(),
        no_flush_all_requests(),
    ));

    events_tx
        .send(FsChangeEvent { path: "a.txt".into(), kind: FsChangeKind::CreatedOrModified })
        .await
        .unwrap();
    let first =
        tokio::time::timeout(Duration::from_secs(2), flush_rx.recv()).await.unwrap().unwrap();
    assert_eq!(
        expect_paths(first),
        vec![(PathBuf::from("a.txt"), FsChangeKind::CreatedOrModified)]
    );

    events_tx
        .send(FsChangeEvent { path: "a.txt".into(), kind: FsChangeKind::ObservedRemoval })
        .await
        .unwrap();
    let second =
        tokio::time::timeout(Duration::from_secs(2), flush_rx.recv()).await.unwrap().unwrap();
    assert_eq!(expect_paths(second), vec![(PathBuf::from("a.txt"), FsChangeKind::ObservedRemoval)]);
}

/// A continuously-busy path (a new event arrives before every quiet
/// period elapses) still flushes at least once per `max_flush_interval`.
#[tokio::test]
async fn continuously_busy_path_flushes_at_max_interval() {
    let config = DebounceConfig {
        quiet_period: Duration::from_millis(500),
        max_flush_interval: Duration::from_millis(100),
        burst_threshold: 5,
    };
    let (events_tx, events_rx) = mpsc::channel(64);
    let (flush_tx, mut flush_rx) = mpsc::channel(16);
    tokio::spawn(run_debouncer(
        config,
        events_rx,
        flush_tx,
        no_overflow(),
        no_flush_requests(),
        no_flush_all_requests(),
    ));

    let keep_sending = tokio::spawn(async move {
        for _ in 0..20 {
            let _ = events_tx
                .send(FsChangeEvent {
                    path: "busy.txt".into(),
                    kind: FsChangeKind::CreatedOrModified,
                })
                .await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });

    // With a 500ms quiet period that never elapses (events every
    // 20ms) but a 100ms max_flush_interval, a flush must still arrive
    // well before the 500ms quiet-period would ever fire on its own.
    let flush = tokio::time::timeout(Duration::from_millis(400), flush_rx.recv())
        .await
        .expect("max_flush_interval did not force a flush in time")
        .unwrap();
    assert_eq!(
        expect_paths(flush),
        vec![(PathBuf::from("busy.txt"), FsChangeKind::CreatedOrModified)]
    );
    keep_sending.abort();
}

/// Exceeding the burst threshold within one window flushes early as a
/// sequence of bounded `Paths` batches — never `RescanRequired`, which
/// is reserved for genuine information loss (watcher overflow). A
/// confirmed, measured bug this replaces: converting a large but
/// fully-known burst into a full-rescan fallback traded a bounded cost
/// for an unbounded one and was observed stalling a real ~1k-file
/// rename/delete storm indefinitely.
#[tokio::test]
async fn exceeding_burst_threshold_flushes_early_as_bounded_batches() {
    // See `burst_threshold_of_one_flushes_on_the_first_event`'s own
    // comment on why a test that emits the same `tracing::warn!`
    // callsite the log-capturing tests below assert on must also be
    // serialized against them, even without installing its own
    // subscriber.
    let _tracing_guard = TRACING_TEST_MUTEX.lock().await;
    let (events_tx, events_rx) = mpsc::channel(64);
    let (flush_tx, mut flush_rx) = mpsc::channel(16);
    tokio::spawn(run_debouncer(
        short_config(),
        events_rx,
        flush_tx,
        no_overflow(),
        no_flush_requests(),
        no_flush_all_requests(),
    ));

    // short_config's burst_threshold is 5.
    for i in 0..10 {
        events_tx
            .send(FsChangeEvent {
                path: format!("file-{i}.txt").into(),
                kind: FsChangeKind::CreatedOrModified,
            })
            .await
            .unwrap();
    }

    let mut seen: Vec<PathBuf> = Vec::new();
    for _ in 0..2 {
        let flush = tokio::time::timeout(Duration::from_secs(2), flush_rx.recv())
            .await
            .expect("timed out waiting for flush")
            .unwrap();
        let paths = match flush {
            DebounceFlush::Paths(paths) => paths,
            DebounceFlush::RescanRequired => {
                panic!("a known 10-path burst must never fall back to a full rescan")
            }
        };
        assert_eq!(paths.len(), 5, "each early flush must be exactly one bounded batch");
        seen.extend(paths.into_iter().map(|(path, _, _)| path));
    }
    seen.sort();
    let expected: Vec<PathBuf> = (0..10).map(|i| PathBuf::from(format!("file-{i}.txt"))).collect();
    assert_eq!(seen, expected, "all 10 known paths must be delivered, none lost");
}

/// A `burst_threshold` of exactly 1 -- a real, publicly permitted
/// `DebounceConfig` value -- must flush on the very FIRST event of a
/// fresh window, not only from the second one onward. review
/// finding on the early-flush fix above: the threshold check lived
/// only in the `Accumulating` arm, so a length-1 map built fresh from
/// `Idle` never got checked at all until a quiet period/max-flush-
/// interval elapsed.
#[tokio::test]
async fn burst_threshold_of_one_flushes_on_the_first_event() {
    // Also serialized against the tracing-subscriber-installing tests
    // below, even though this test never installs one itself: this
    // test's own `accumulate_event` call emits the exact same
    // `tracing::warn!("burst_threshold_reached", ...)` line those
    // tests capture, and `tracing`'s per-callsite interest cache is
    // rebuilt globally (not per-thread) whenever a subscriber is
    // installed/dropped elsewhere in the process -- letting this run
    // concurrently with one of those tests could race that rebuild
    // and cause the OTHER test's own capture to silently miss the
    // line, not just this one (confirmed empirically: `--test-
    // threads=1` and fully-isolated single-test runs never flake).
    let _tracing_guard = TRACING_TEST_MUTEX.lock().await;
    let config = DebounceConfig {
        quiet_period: Duration::from_secs(30),
        max_flush_interval: Duration::from_secs(60),
        burst_threshold: 1,
    };
    let (events_tx, events_rx) = mpsc::channel(16);
    let (flush_tx, mut flush_rx) = mpsc::channel(16);
    tokio::spawn(run_debouncer(
        config,
        events_rx,
        flush_tx,
        no_overflow(),
        no_flush_requests(),
        no_flush_all_requests(),
    ));

    events_tx
        .send(FsChangeEvent { path: "a.txt".into(), kind: FsChangeKind::CreatedOrModified })
        .await
        .unwrap();

    // The quiet period/max_flush_interval are both far longer than
    // this timeout -- only the threshold-of-1 early flush can produce
    // a result this fast.
    let flush = tokio::time::timeout(Duration::from_millis(500), flush_rx.recv())
        .await
        .expect(
            "a burst_threshold of 1 must flush on the very first event, not wait for \
                 the quiet period",
        )
        .unwrap();
    assert_eq!(
        expect_paths(flush),
        vec![(PathBuf::from("a.txt"), FsChangeKind::CreatedOrModified)]
    );
}

/// A quiet folder (`Idle` state, no timer armed) doesn't spuriously
/// flush anything, and closing the events channel ends the debouncer
/// cleanly.
#[tokio::test]
async fn idle_debouncer_ends_cleanly_when_the_events_channel_closes() {
    let (events_tx, events_rx) = mpsc::channel(16);
    let (flush_tx, mut flush_rx) = mpsc::channel(16);
    let handle = tokio::spawn(run_debouncer(
        short_config(),
        events_rx,
        flush_tx,
        no_overflow(),
        no_flush_requests(),
        no_flush_all_requests(),
    ));

    drop(events_tx);
    handle.await.unwrap();
    assert!(flush_rx.recv().await.is_none());
}

/// An artificially slow
/// executor (here, a test task that only calls `flush_rx.recv` after
/// a deliberate delay) does not prevent the accumulator from
/// continuing to observe and accumulate new events during that delay —
/// the accumulator and executor are independently-scheduled tasks
/// connected only by the flush channel, not one blocking loop.
#[tokio::test]
async fn a_slow_executor_does_not_block_the_accumulator_from_observing_new_events() {
    // Capacity 1: the *first* flush fills the wire channel completely
    // and stays unread for a while — if delivery were a blocking
    // `.await` inside the same loop that reads `events`, this alone
    // would already stall the accumulator. A second and third window
    // must still complete and queue up correctly while the executor
    // (this test) isn't draining at all.
    let (events_tx, events_rx) = mpsc::channel(64);
    let (flush_tx, mut flush_rx) = mpsc::channel(1);
    tokio::spawn(run_debouncer(
        short_config(),
        events_rx,
        flush_tx,
        no_overflow(),
        no_flush_requests(),
        no_flush_all_requests(),
    ));

    for name in ["first.txt", "second.txt", "third.txt"] {
        events_tx
            .send(FsChangeEvent { path: name.into(), kind: FsChangeKind::CreatedOrModified })
            .await
            .unwrap();
        // Longer than the quiet period, so each becomes its own
        // completed window before the next event is sent.
        tokio::time::sleep(Duration::from_millis(60)).await;
    }

    // Only now does the "executor" start draining — proving all three
    // windows completed independently of any consumer activity, and
    // arrive in the order they were produced.
    for expected in ["first.txt", "second.txt", "third.txt"] {
        let flush = tokio::time::timeout(Duration::from_secs(2), flush_rx.recv())
            .await
            .expect("a queued flush never arrived")
            .unwrap();
        assert_eq!(
            expect_paths(flush),
            vec![(PathBuf::from(expected), FsChangeKind::CreatedOrModified)]
        );
    }
}

#[derive(Clone, Default)]
struct SharedLogBuf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for SharedLogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl SharedLogBuf {
    fn contains(&self, needle: &str) -> bool {
        String::from_utf8_lossy(&self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()))
            .contains(needle)
    }
}

/// Each of the three fallback
/// triggers logs a distinguishable reason. One `#[tokio::test]` (the
/// default current-thread flavor) keeps everything on one OS thread,
/// so a thread-local-default subscriber captures the debouncer task's
/// log output correctly.
#[tokio::test]
async fn burst_threshold_trigger_logs_a_distinguishable_reason() {
    let _tracing_guard = TRACING_TEST_MUTEX.lock().await;
    let buf = SharedLogBuf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer({
            let b = buf.clone();
            move || b.clone()
        })
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let (events_tx, events_rx) = mpsc::channel(64);
    let (flush_tx, mut flush_rx) = mpsc::channel(16);
    tokio::spawn(run_debouncer(
        short_config(),
        events_rx,
        flush_tx,
        no_overflow(),
        no_flush_requests(),
        no_flush_all_requests(),
    ));

    for i in 0..10 {
        events_tx
            .send(FsChangeEvent {
                path: format!("file-{i}.txt").into(),
                kind: FsChangeKind::CreatedOrModified,
            })
            .await
            .unwrap();
    }
    let flush =
        tokio::time::timeout(Duration::from_secs(2), flush_rx.recv()).await.unwrap().unwrap();
    assert!(
        matches!(flush, DebounceFlush::Paths(_)),
        "a known burst must flush as bounded Paths batches, not fall back to a rescan"
    );

    // Polls rather than checking once immediately: under CPU contention
    // (many tests running concurrently) the log write can lag behind
    // this task observing the flush, even though the `tracing::warn!`
    // call is causally before it -- same rationale, and same fix, as
    // `executor_backlog_trigger_logs_a_distinguishable_reason_and_merges_
    // the_queue`'s own identical polling loop below.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !buf.contains("burst_threshold_reached") && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        buf.contains("burst_threshold_reached"),
        "log did not mention the burst-threshold reason"
    );
}

#[tokio::test]
async fn watcher_overflow_trigger_logs_a_distinguishable_reason() {
    let _tracing_guard = TRACING_TEST_MUTEX.lock().await;
    let buf = SharedLogBuf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer({
            let b = buf.clone();
            move || b.clone()
        })
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let (_events_tx, events_rx) = mpsc::channel(16);
    let (flush_tx, mut flush_rx) = mpsc::channel(16);
    let overflowed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    tokio::spawn(run_debouncer(
        short_config(),
        events_rx,
        flush_tx,
        overflowed,
        no_flush_requests(),
        no_flush_all_requests(),
    ));

    let flush =
        tokio::time::timeout(Duration::from_secs(2), flush_rx.recv()).await.unwrap().unwrap();
    assert_eq!(flush, DebounceFlush::RescanRequired);

    assert!(
        buf.contains("watcher_channel_overflow"),
        "log did not mention the watcher-overflow reason"
    );
}

/// Once the delivery queue reaches capacity (executor never drains),
/// further completed windows merge into a single `Paths` entry instead
/// of growing the queue without bound -- bounding queue depth WITHOUT
/// discarding known paths (a confirmed, measured bug the merge
/// replaces: collapsing straight to `RescanRequired` here converted a
/// merely-slow executor into an unbounded full-tree rescan even though
/// every path that changed was already known). The merge is logged
/// with its own distinguishable reason.
#[tokio::test]
async fn executor_backlog_trigger_logs_a_distinguishable_reason_and_merges_the_queue() {
    let _tracing_guard = TRACING_TEST_MUTEX.lock().await;
    let buf = SharedLogBuf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer({
            let b = buf.clone();
            move || b.clone()
        })
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let (events_tx, events_rx) = mpsc::channel(256);
    // Never drained during the test — forces the internal ready_queue
    // (not the wire channel) to fill past DEFAULT_EXECUTOR_CHANNEL_CAPACITY.
    let (flush_tx, mut flush_rx) = mpsc::channel(1);
    tokio::spawn(run_debouncer(
        short_config(),
        events_rx,
        flush_tx,
        no_overflow(),
        no_flush_requests(),
        no_flush_all_requests(),
    ));

    // One window per file, well separated so each completes on its
    // own — enough windows to exceed DEFAULT_EXECUTOR_CHANNEL_CAPACITY
    // (8) while nothing reads flush_rx. The gap between sends needs
    // real headroom above quiet_period (30ms), not just a few ms: if
    // the spawned debouncer task is slow to get scheduled (a slower/
    // more contended CI runner -- observed failing on windows-latest
    // at the old 40ms gap), several sends can queue up in its mpsc
    // channel before it's polled again, and it then processes them
    // back-to-back with nearly-identical Instant::now reads, merging
    // what should have been separate windows into one and never
    // reaching the queue depth this test means to exercise.
    for i in 0..(DEFAULT_EXECUTOR_CHANNEL_CAPACITY + 4) {
        events_tx
            .send(FsChangeEvent {
                path: format!("file-{i}.txt").into(),
                kind: FsChangeKind::CreatedOrModified,
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    // The debouncer task runs independently of this test's own
    // progress -- under CPU contention (many tests running in
    // parallel, or a slower CI runner) it can lag behind having
    // actually reached the queue-depth-8 collapse by the moment the
    // send loop above returns, so this polls for the log rather than
    // checking exactly once immediately (which raced and failed
    // intermittently even locally under `cargo test`'s default
    // parallelism, not just in CI).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !buf.contains("executor_backlog") && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(buf.contains("executor_backlog"), "log did not mention the executor-backlog reason");

    // Now drain: the queue was merged, so what's left is a small,
    // bounded number of entries — not one per file — and every known
    // path (this scenario never overflowed the watcher channel, only
    // the delivery queue) must still be present, not discarded.
    let mut seen_entries = 0;
    let mut saw_rescan_required = false;
    let mut seen_paths: Vec<PathBuf> = Vec::new();
    while let Ok(Some(flush)) =
        tokio::time::timeout(Duration::from_millis(500), flush_rx.recv()).await
    {
        seen_entries += 1;
        match flush {
            DebounceFlush::RescanRequired => saw_rescan_required = true,
            DebounceFlush::Paths(paths) => {
                seen_paths.extend(paths.into_iter().map(|(path, _, _)| path));
            }
        }
        assert!(
            seen_entries <= DEFAULT_EXECUTOR_CHANNEL_CAPACITY + 1,
            "queue was not bounded/merged"
        );
    }
    assert!(
        !saw_rescan_required,
        "no watcher overflow occurred in this scenario -- every path was known, so the \
         merge must never fall back to a full rescan"
    );
    seen_paths.sort();
    seen_paths.dedup();
    let mut expected: Vec<PathBuf> = (0..(DEFAULT_EXECUTOR_CHANNEL_CAPACITY + 4))
        .map(|i| PathBuf::from(format!("file-{i}.txt")))
        .collect();
    expected.sort();
    assert_eq!(seen_paths, expected, "merging a backed-up queue must lose no known path");
}

// ---------------------------------------------------------------------------
// A requester that stops listening (its own timeout, or its task being dropped)
// before the accumulator answers must not take the pending edit with it: the
// accumulator hands entries over only when the reply is delivered, and keeps
// them otherwise. No test below sleeps to order events: a queued event is
// folded in by the accumulator before it answers a request.
// ---------------------------------------------------------------------------

fn created(path: &str) -> FsChangeEvent {
    FsChangeEvent { path: path.into(), kind: FsChangeKind::CreatedOrModified }
}

/// A request whose requester is already gone when the accumulator pops it.
fn abandoned_path_request(path: &str, mode: FlushMode) -> FlushPathRequest {
    let (reply, reply_rx) = tokio::sync::oneshot::channel();
    drop(reply_rx);
    FlushPathRequest { path: path.into(), mode, reply }
}

async fn ask_path(
    tx: &mpsc::Sender<FlushPathRequest>,
    path: &str,
    mode: FlushMode,
) -> Option<(PathBuf, FsChangeKind, i64)> {
    let (reply, reply_rx) = tokio::sync::oneshot::channel();
    tx.send(FlushPathRequest { path: path.into(), mode, reply }).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), reply_rx).await.unwrap().unwrap()
}

#[tokio::test]
async fn an_exact_path_reply_abandoned_before_it_is_sent_keeps_the_pending_edit() {
    let (events_tx, events_rx) = mpsc::channel(16);
    let (flush_tx, _flush_rx) = mpsc::channel(16);
    let (flush_requests_tx, flush_requests_rx) = mpsc::channel(4);
    tokio::spawn(run_debouncer(
        short_config(),
        events_rx,
        flush_tx,
        no_overflow(),
        flush_requests_rx,
        no_flush_all_requests(),
    ));
    events_tx.send(created("a.txt")).await.unwrap();
    flush_requests_tx.send(abandoned_path_request("a.txt", FlushMode::ExactPath)).await.unwrap();

    // The edit is still there for the next request ...
    let found = ask_path(&flush_requests_tx, "a.txt", FlushMode::ExactPath).await;
    assert_eq!(
        found.map(|(path, kind, _)| (path, kind)),
        Some(("a.txt".into(), FsChangeKind::CreatedOrModified))
    );
    // ... and, once that one claimed it, the window timer does not deliver it again.
    assert!(ask_path(&flush_requests_tx, "a.txt", FlushMode::ExactPath).await.is_none());
}

#[tokio::test]
async fn an_abandoned_reply_leaves_the_edit_to_the_window_timer_when_nobody_asks_again() {
    let (events_tx, events_rx) = mpsc::channel(16);
    let (flush_tx, mut flush_rx) = mpsc::channel(16);
    let (flush_requests_tx, flush_requests_rx) = mpsc::channel(4);
    tokio::spawn(run_debouncer(
        short_config(),
        events_rx,
        flush_tx,
        no_overflow(),
        flush_requests_rx,
        no_flush_all_requests(),
    ));
    events_tx.send(created("a.txt")).await.unwrap();
    flush_requests_tx.send(abandoned_path_request("a.txt", FlushMode::ExactPath)).await.unwrap();

    let flush = tokio::time::timeout(Duration::from_secs(5), flush_rx.recv())
        .await
        .expect("the edit must still reach the executor")
        .unwrap();
    assert_eq!(
        expect_paths(flush),
        vec![(PathBuf::from("a.txt"), FsChangeKind::CreatedOrModified)]
    );
}

#[tokio::test]
async fn a_case_fold_sibling_reply_abandoned_before_it_is_sent_keeps_the_pending_edit() {
    let (events_tx, events_rx) = mpsc::channel(16);
    let (flush_tx, _flush_rx) = mpsc::channel(16);
    let (flush_requests_tx, flush_requests_rx) = mpsc::channel(4);
    tokio::spawn(run_debouncer(
        short_config(),
        events_rx,
        flush_tx,
        no_overflow(),
        flush_requests_rx,
        no_flush_all_requests(),
    ));
    events_tx.send(created("Report.txt")).await.unwrap();
    events_tx.send(created("other.txt")).await.unwrap();
    flush_requests_tx
        .send(abandoned_path_request("report.txt", FlushMode::CaseFoldSibling))
        .await
        .unwrap();

    // The retried reconciliation still finds the local sibling, which has no
    // disk-authoritative fallback behind it.
    let found = ask_path(&flush_requests_tx, "report.txt", FlushMode::CaseFoldSibling).await;
    assert_eq!(found.map(|(path, _, _)| path), Some(PathBuf::from("Report.txt")));
}

#[tokio::test]
async fn a_flush_all_reply_abandoned_after_draining_several_paths_keeps_every_one() {
    let (events_tx, events_rx) = mpsc::channel(16);
    let (flush_tx, _flush_rx) = mpsc::channel(16);
    let (flush_all_tx, flush_all_rx) = mpsc::channel(4);
    tokio::spawn(run_debouncer(
        short_config(),
        events_rx,
        flush_tx,
        no_overflow(),
        no_flush_requests(),
        flush_all_rx,
    ));
    for path in ["a.txt", "b.txt", "c.txt"] {
        events_tx.send(created(path)).await.unwrap();
    }
    let (reply, reply_rx) = tokio::sync::oneshot::channel();
    drop(reply_rx);
    flush_all_tx.send(FlushAllRequest { reply }).await.unwrap();

    let (reply, reply_rx) = tokio::sync::oneshot::channel();
    flush_all_tx.send(FlushAllRequest { reply }).await.unwrap();
    let mut drained: Vec<PathBuf> = tokio::time::timeout(Duration::from_secs(5), reply_rx)
        .await
        .unwrap()
        .unwrap()
        .into_iter()
        .map(|(path, _, _)| path)
        .collect();
    drained.sort();
    assert_eq!(
        drained,
        vec![PathBuf::from("a.txt"), PathBuf::from("b.txt"), PathBuf::from("c.txt")]
    );
}

/// Controls: a delivered reply hands the entry over exactly once, and an
/// abandoned request for a path with nothing pending neither invents nor
/// disturbs anything.
#[tokio::test]
async fn controls_a_delivered_reply_is_handed_over_once_and_an_empty_abandoned_one_is_harmless() {
    let (events_tx, events_rx) = mpsc::channel(16);
    let (flush_tx, mut flush_rx) = mpsc::channel(16);
    let (flush_requests_tx, flush_requests_rx) = mpsc::channel(4);
    tokio::spawn(run_debouncer(
        short_config(),
        events_rx,
        flush_tx,
        no_overflow(),
        flush_requests_rx,
        no_flush_all_requests(),
    ));
    flush_requests_tx
        .send(abandoned_path_request("nothing.txt", FlushMode::ExactPath))
        .await
        .unwrap();
    events_tx.send(created("a.txt")).await.unwrap();
    assert!(ask_path(&flush_requests_tx, "a.txt", FlushMode::ExactPath).await.is_some());
    assert!(ask_path(&flush_requests_tx, "a.txt", FlushMode::ExactPath).await.is_none());
    // Claimed once by the request, so the timer has nothing left to deliver for it.
    assert!(tokio::time::timeout(Duration::from_millis(300), flush_rx.recv()).await.is_err());
}
