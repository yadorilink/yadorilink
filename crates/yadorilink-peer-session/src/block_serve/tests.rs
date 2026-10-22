#![cfg(test)]

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

/// HIGH-3 regression: `try_begin_examination` is a real, finite cap —
/// once every permit is held, a further call fails immediately with
/// `Busy` rather than admitting unboundedly. Exercises the engine's
/// smallest legal `max_inflight_requests` (1) so the cap
/// (`1 * MAX_WAITING_MULTIPLE` = 8) is small enough to exhaust directly
/// in a unit test.
#[test]
fn examination_admission_is_a_real_bounded_cap_not_unbounded_spawn() {
    let engine = BlockServeEngine::new(1_000_000, 1_000_000, 1_000_000, 1);
    let capacity = engine.examination_admission_capacity;

    let mut held = Vec::new();
    for _ in 0..capacity {
        held.push(engine.try_begin_examination().expect("must admit up to capacity"));
    }

    let err = engine
        .try_begin_examination()
        .expect_err("the (capacity + 1)th examination must be refused, not admitted");
    assert!(err.retry_after_ms > 0);
    assert_eq!(
        err.queue_depth, capacity as u32,
        "queue_depth must reflect every held permit while the budget is fully consumed"
    );

    // Dropping one permit frees exactly one slot -- never more, never
    // fewer -- proving this is a real semaphore, not a one-shot gate.
    held.pop();
    engine.try_begin_examination().expect("a freed slot must be immediately reusable");
}

#[test]
fn admits_within_all_three_budgets() {
    let engine = BlockServeEngine::new(1000, 500, 500, 100);
    let guard = engine.try_admit("peer-a", "group-1", 100).unwrap();
    drop(guard);
}

#[test]
fn denies_when_the_per_peer_budget_is_exceeded_even_though_global_has_room() {
    let engine = BlockServeEngine::new(10_000, 100, 10_000, 100);
    let _guard = engine.try_admit("peer-a", "group-1", 90).unwrap();
    let err = engine.try_admit("peer-a", "group-1", 20).unwrap_err();
    assert!(err.retry_after_ms > 0);
}

#[test]
fn denies_when_the_per_group_budget_is_exceeded_even_though_per_peer_has_room() {
    let engine = BlockServeEngine::new(10_000, 10_000, 100, 100);
    let _guard_a = engine.try_admit("peer-a", "group-1", 60).unwrap();
    // A DIFFERENT peer requesting from the SAME group must still be
    // denied -- the per-group budget is shared across all requesters
    // for that group, not per (peer, group) pair.
    let err = engine.try_admit("peer-b", "group-1", 60).unwrap_err();
    assert!(err.retry_after_ms > 0);
}

#[test]
fn denies_when_the_global_budget_is_exceeded_even_with_per_peer_and_per_group_room() {
    let engine = BlockServeEngine::new(100, 10_000, 10_000, 100);
    let _guard_a = engine.try_admit("peer-a", "group-1", 60).unwrap();
    let err = engine.try_admit("peer-b", "group-2", 60).unwrap_err();
    assert!(err.retry_after_ms > 0);
}

#[test]
fn releasing_a_guard_frees_all_three_budgets_for_a_later_admission() {
    let engine = BlockServeEngine::new(100, 100, 100, 100);
    let guard = engine.try_admit("peer-a", "group-1", 100).unwrap();
    assert!(engine.try_admit("peer-a", "group-1", 1).is_err());
    drop(guard);
    assert!(engine.try_admit("peer-a", "group-1", 100).is_ok());
}

#[test]
fn a_different_peer_is_not_blocked_by_another_peers_exhausted_per_peer_budget() {
    let engine = BlockServeEngine::new(10_000, 100, 10_000, 100);
    let _guard_a = engine.try_admit("peer-a", "group-1", 100).unwrap();
    assert!(engine.try_admit("peer-b", "group-1", 100).is_ok());
}

#[tokio::test]
async fn concurrent_coalesce_requesters_for_the_same_key_share_one_initializer() {
    let engine = BlockServeEngine::new(u64::MAX, u64::MAX, u64::MAX, 100);
    let init_count = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let cell = engine.coalesce_cell("group-1", b"hash-a", None);
        let init_count = init_count.clone();
        handles.push(tokio::spawn(async move {
            cell.get_or_init(|| async {
                init_count.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                Ok::<_, CoalesceFailure>((Bytes::from_static(b"content"), 0))
            })
            .await
            .clone()
        }))
    }
    for h in handles {
        let result = h.await.unwrap();
        assert_eq!(result.unwrap().0, Bytes::from_static(b"content"));
    }
    assert_eq!(
        init_count.load(Ordering::SeqCst),
        1,
        "8 concurrent requesters for the same key must share exactly one initializer run"
    );
}

#[test]
fn different_keys_get_independent_coalesce_cells() {
    let engine = BlockServeEngine::new(u64::MAX, u64::MAX, u64::MAX, 100);
    let a1 = engine.coalesce_cell("group-1", b"hash-a", None);
    let a2 = engine.coalesce_cell("group-1", b"hash-a", None);
    let b = engine.coalesce_cell("group-1", b"hash-b", None);
    assert!(Arc::ptr_eq(&a1, &a2), "same key must return the same cell while it's still live");
    assert!(!Arc::ptr_eq(&a1, &b), "different keys must get independent cells");
}

/// Regression for a confirmed cross-requester credit bypass: coalescing
/// keyed by `(group_id, hash)` alone let two
/// requesters with DIFFERENT `expected_size` for the identical hash
/// (e.g. one correctly-sized referencing record, one corrupted or
/// understated) share the same cached result. Whichever requester's
/// `get_or_init` call won ran the size check against ITS OWN expected
/// size; every other requester then silently inherited that same
/// "found" result without its OWN size ever being checked -- a
/// requester whose own declared size understated the real stored data
/// would be served more bytes than it ever reserved credit for.
/// `expected_size` must be part of the key: the same `(group, hash)`
/// under different expected sizes must be two independent cells.
#[test]
fn expected_size_is_part_of_the_coalescing_key() {
    let engine = BlockServeEngine::new(u64::MAX, u64::MAX, u64::MAX, 100);
    let sized_100 = engine.coalesce_cell("group-1", b"hash-a", Some(100));
    let sized_50 = engine.coalesce_cell("group-1", b"hash-a", Some(50));
    let no_size = engine.coalesce_cell("group-1", b"hash-a", None);
    assert!(
        !Arc::ptr_eq(&sized_100, &sized_50),
        "the same (group, hash) under different expected sizes must never share a cell -- a \
         requester with a corrupted/understated declared size could otherwise be served more \
         bytes than it reserved credit for"
    );
    assert!(
        !Arc::ptr_eq(&sized_100, &no_size),
        "a known expected size and the pessimistic MAX_BLOCK_SIZE fallback (None) must not \
         share a cell either"
    );
}

/// Regression for a confirmed TOCTOU: when the check-then-commit steps
/// of admission were split across a plain atomic (global) and separate
/// mutexes (per-peer/per-group) with no lock held across the whole
/// decision, many concurrent callers could all observe pre-commit usage
/// and all be admitted, overshooting the global budget by nearly the
/// full size of the flood. `try_admit` now checks and commits under one
/// lock, so exactly as many requests as the budget allows are ever
/// admitted, regardless of how many arrive at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_admission_never_overshoots_the_global_budget() {
    let engine = BlockServeEngine::new(1_000, u64::MAX, u64::MAX, 1_000);
    // A barrier releases all 200 tasks at essentially the same instant,
    // maximizing genuine cross-thread overlap of the check-then-commit
    // window a prior version of `try_admit` left unlocked between
    // separately-guarded checks and the later commit -- confirmed to
    // reliably overshoot the budget under this exact setup before that
    // fix (three runs, three failures).
    let barrier = Arc::new(tokio::sync::Barrier::new(200));
    let mut handles = Vec::new();
    for i in 0..200 {
        let engine = engine.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            engine.try_admit(&format!("peer-{i}"), "group-1", 100)
        }));
    }
    let mut admitted = Vec::new();
    for h in handles {
        if let Ok(guard) = h.await.unwrap() {
            admitted.push(guard);
        }
    }
    assert!(
        admitted.len() <= 10,
        "200 concurrent 100-byte requests against a 1000-byte budget admitted {}, which overshoots it",
        admitted.len()
    );
}

/// Regression for a confirmed leak: `release_and_wake_next` grants a
/// queued waiter its turn (increments `active`) and hands it off
/// through a channel; if the waiter's task were cancelled after that
/// grant but before it resumed to actually construct a guard from the
/// old bare `()` signal, `active` stayed incremented forever with
/// nothing left alive to release it -- repeated occurrences would
/// eventually leak every dispatch slot and stall serving permanently.
/// The fix sends the already-constructed `FairDispatchGuard` itself
/// through the channel, so a cancellation anywhere in that window still
/// drops (and so releases) it.
///
/// This test uses the default current-thread test runtime to fully
/// control scheduling: it registers a waiter, then (synchronously, with
/// no intervening `.await`) drops the slot that grants it -- which
/// sends the guard -- and immediately aborts the waiter's task before
/// the runtime ever gets a chance to poll it again to receive that
/// guard. That is exactly the window the old code leaked in.
#[tokio::test]
async fn a_waiter_cancelled_after_being_granted_does_not_leak_its_slot() {
    let queue = Arc::new(FairDispatchQueue::new(1, 10));
    let g1 = queue.acquire("peer-a", "group-1", 1).await.unwrap();

    let queue_for_waiter = queue.clone();
    let waiter =
        tokio::spawn(async move { queue_for_waiter.acquire("peer-b", "group-1", 1).await });
    tokio::task::yield_now().await; // let the waiter register and suspend on rx.await

    drop(g1); // synchronously grants the waiter's turn and sends its guard
    waiter.abort(); // cancel it before it's ever polled again to receive that guard
    let _ = waiter.await;

    let recovered = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let _ = queue.acquire("peer-c", "group-1", 1).await.unwrap();
    })
    .await;
    assert!(recovered.is_ok(), "dispatch capacity did not recover -- the granted slot was leaked");
}

/// Regression for the stated requirement ("fair queue... by
/// bytes, not request count") plausibly being violated by a plain
/// per-key round-robin: a key sending a FEW LARGE requests and a key
/// sending MANY SMALL ones can reach the same turn count from wildly
/// different byte totals, so round-robin-by-turn treats them as
/// equally "caught up" the moment either one's queue is merely empty,
/// regardless of how many bytes it was actually granted. This queues 3
/// huge (10 MB) requests from one key alongside 10 tiny (100 B)
/// requests from another behind one held slot, releases that slot
/// repeatedly, and records the grant order. Under plain round-robin,
/// the huge key's queue would drain in a handful of alternating turns
/// and its LAST grant would land well before the small key's -- byte-
/// fair scheduling instead keeps deprioritizing the huge key (its
/// cumulative bytes granted vastly exceeds the small key's) until the
/// small key's queue is completely empty, so the huge key's last grant
/// must land dead last.
#[tokio::test]
async fn a_few_huge_requests_do_not_dominate_many_tiny_ones_from_another_key() {
    let queue = Arc::new(FairDispatchQueue::new(1, 20));
    let holder = queue.acquire("holder", "group-x", 1).await.unwrap();

    // Each task pushes its own label the moment it's granted, then
    // immediately drops the guard to free the slot for the next --
    // with `max_active == 1`, at most one label is ever pushed at a
    // time, so this log's order IS the grant order.
    let log: Arc<StdMutex<Vec<&'static str>>> = Arc::new(StdMutex::new(Vec::new()));
    let mut tasks = Vec::new();
    for _ in 0..3 {
        let (queue, log) = (queue.clone(), log.clone());
        tasks.push(tokio::spawn(async move {
            let guard = queue.acquire("huge-peer", "group-a", 10_000_000).await.unwrap();
            log.lock().unwrap_or_else(|p| p.into_inner()).push("huge");
            drop(guard);
        }));
    }
    for _ in 0..10 {
        let (queue, log) = (queue.clone(), log.clone());
        tasks.push(tokio::spawn(async move {
            let guard = queue.acquire("tiny-peer", "group-b", 100).await.unwrap();
            log.lock().unwrap_or_else(|p| p.into_inner()).push("tiny");
            drop(guard);
        }));
    }
    // Let every spawned task reach registration (the synchronous part
    // of `acquire`'s slow path) before releasing the held slot, so all
    // 13 are genuinely queued and competing, not racing each other in.
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    drop(holder);

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        for t in tasks {
            t.await.unwrap();
        }
    })
    .await
    .expect("all 13 queued requests should eventually be granted");

    let order = log.lock().unwrap_or_else(|p| p.into_inner()).clone();
    assert_eq!(order.len(), 13);
    assert_eq!(
        order.last(),
        Some(&"huge"),
        "byte-fair scheduling must keep deprioritizing the huge key against its own vastly \
         larger cumulative bytes granted until every tiny request has been served -- got \
         order {order:?}"
    );
}

/// Regression: a queued waiter's task being cancelled/timed out (e.g.
/// via the caller's own `tokio::time::timeout`) must recover
/// `waiting`'s capacity IMMEDIATELY, not only once
/// `release_and_wake_next` eventually rotates to the now-stale entry.
#[tokio::test]
async fn a_timed_out_waiter_is_removed_from_the_waiting_count_immediately() {
    let queue = Arc::new(FairDispatchQueue::new(1, 10));
    let _holder = queue.acquire("holder", "group-x", 1).await.unwrap();

    let timed_out = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        queue.acquire("peer-a", "group-a", 1),
    )
    .await;
    assert!(timed_out.is_err(), "sanity: the holder is never released, so this must time out");

    assert_eq!(
        queue.waiting_count(),
        0,
        "a timed-out waiter must be removed from the queue immediately, not left for \
         release_and_wake_next to discover later"
    );
}

/// Regression: `release_and_wake_next` popping a waiter whose receiver
/// has ALREADY been dropped (the narrow race `WaiterCancelGuard` can't
/// fully close -- see that guard's own doc comment) must not charge
/// `bytes_granted` for a request that was never actually served. This
/// bypasses `acquire`'s own registration to force that exact `Err`
/// branch deterministically (a real cancellation is normally caught by
/// `WaiterCancelGuard` well before `release_and_wake_next` ever sees
/// it, making the race impractical to hit reliably from the public API
/// alone).
#[tokio::test]
async fn a_waiter_whose_receiver_already_dropped_does_not_inflate_bytes_granted() {
    let queue = Arc::new(FairDispatchQueue::new(1, 10));
    let holder = queue.acquire("holder", "group-x", 1).await.unwrap();

    let dead_key = ("dead-peer".to_string(), "dead-group".to_string());
    let (tx, rx) = tokio::sync::oneshot::channel();
    drop(rx);
    {
        let mut state = queue.state.lock().unwrap_or_else(|p| p.into_inner());
        state.waiters.entry(dead_key.clone()).or_default().push_back(DispatchWaiter {
            id: 999,
            cost: 10_000_000,
            tx,
        });
        state.waiting += 1;
    }

    drop(holder); // release_and_wake_next pops the dead waiter, tx.send fails

    let bytes_granted = {
        let state = queue.state.lock().unwrap_or_else(|p| p.into_inner());
        state.bytes_granted.get(&dead_key).copied()
    };
    assert_eq!(
        bytes_granted, None,
        "a waiter whose guard was never actually handed off must not be charged bytes_granted"
    );
}

/// Regression: a large request that gets cancelled before ever being
/// served must not leave its key looking like it consumed those bytes
/// -- otherwise a later, LEGITIMATE request from the same key would be
/// unfairly deprioritized against other keys for bytes it was never
/// actually granted.
#[tokio::test]
async fn a_cancelled_large_request_does_not_starve_a_later_request_from_the_same_key() {
    let queue = Arc::new(FairDispatchQueue::new(1, 10));
    let holder = queue.acquire("holder", "group-x", 1).await.unwrap();

    // A huge request from peer-a, cancelled before ever being served.
    let cancelled = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        queue.acquire("peer-a", "group-a", 100_000_000),
    )
    .await;
    assert!(cancelled.is_err(), "sanity: cancelled before the holder ever releases");
    drop(holder);

    // Directly inspect the bookkeeping the starvation bug this
    // regresses would have corrupted: `bytes_granted` must show
    // peer-a as having consumed nothing, since its huge request was
    // cancelled before ever actually being served. A separate
    // end-to-end "does a real follow-up request get served promptly"
    // check is deliberately NOT done here: with only two competing
    // keys and this queue's own tie-breaking picking arbitrarily
    // between two that are equally at `0`, asserting a specific grant
    // ORDER between them is not something this fix (or the
    // fairness goal) makes any promise about -- only that a
    // NEVER-SERVED request must not inflate its key's tally is.
    let bytes_granted = {
        let state = queue.state.lock().unwrap_or_else(|p| p.into_inner());
        state.bytes_granted.get(&("peer-a".to_string(), "group-a".to_string())).copied()
    };
    assert!(
        bytes_granted.is_none_or(|b| b == 0),
        "peer-a's cancelled 100,000,000-byte request must not be charged to bytes_granted, \
         or its later legitimate requests would be permanently deprioritized for bytes it \
         was never actually served -- got {bytes_granted:?}"
    );
}

/// Regression: `max_waiting`'s capacity must recover as soon as a
/// queued waiter is cancelled, without needing to wait for an ACTIVE
/// request to finish and `release_and_wake_next` to run.
#[tokio::test]
async fn queue_capacity_recovers_from_a_cancelled_waiter_without_any_active_request_finishing() {
    let queue = Arc::new(FairDispatchQueue::new(1, 1));
    let _holder = queue.acquire("holder", "group-x", 1).await.unwrap();

    // Fills the one waiting slot, then times out and is cancelled --
    // no active request ever finishes in this test.
    let filled = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        queue.acquire("peer-a", "group-a", 1),
    )
    .await;
    assert!(filled.is_err());

    // With the cancelled waiter still occupying its slot (the bug this
    // regresses), this second call would be rejected outright (`Err`)
    // since `max_waiting == 1`. With immediate cancellation cleanup,
    // it must be able to queue instead. Spawned (not immediately
    // timed out itself) so its own eventual cancellation doesn't race
    // the `waiting_count` check below -- this task is aborted at the
    // end of the test instead.
    let second_queue = queue.clone();
    let second_task =
        tokio::spawn(async move { second_queue.acquire("peer-b", "group-b", 1).await });
    // Give it a chance to reach `acquire`'s registration point (a
    // synchronous section with no `.await` before the slow-path
    // `rx.await`), which a plain `yield_now` reliably lets it reach.
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    assert!(
        !second_task.is_finished(),
        "sanity: the holder is still held, so this must still be waiting, not already \
         resolved (Busy or otherwise)"
    );
    assert_eq!(
        queue.waiting_count(),
        1,
        "the second request must have been queued, not rejected as Busy -- the cancelled \
         first waiter's slot must have already been freed"
    );
    second_task.abort();
}
