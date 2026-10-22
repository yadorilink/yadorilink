#![cfg(test)]

use super::*;
use std::time::Instant;

/// unlimited (`0`, the default) imposes no measurable delay —
/// a huge transfer completes in well under a millisecond of bucket
/// overhead, not gated by any sleep.
#[tokio::test]
async fn unlimited_bucket_imposes_no_measurable_delay() {
    let bucket = TokenBucket::unlimited();
    let start = Instant::now();
    for _ in 0..1000 {
        bucket.acquire(10 * 1024 * 1024).await; // 10 MiB, one thousand times
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(50),
        "unlimited bucket should impose no measurable delay, took {elapsed:?}"
    );
}

/// `current_rate_bytes_per_sec` reports real throughput
/// even on an *unlimited* bucket (no configured rate) — `status`
/// reporting shouldn't show `0` current rate just because nothing is
/// throttling.
#[tokio::test]
async fn current_rate_reflects_unlimited_transfers_too() {
    let bucket = TokenBucket::unlimited();
    assert_eq!(bucket.current_rate_bytes_per_sec(), 0, "no bytes transferred yet");
    bucket.acquire(1_000_000).await;
    let rate = bucket.current_rate_bytes_per_sec();
    assert!(rate > 0, "expected a nonzero measured rate after transferring bytes, got {rate}");
}

/// Regression test: a *single* `acquire` request larger than the
/// bucket's nominal one-second capacity (a real case — a whole block
/// payload can be tens of MB while a configured rate can be a few
/// KB/sec) must still eventually succeed instead of looping forever.
/// Before the `capacity = rate.max(bytes)` fix, `available` was capped
/// at `rate` and could never climb high enough to satisfy a request
/// bigger than that, so this exact scenario deadlocked permanently —
/// caught by an end-to-end `peer_session` integration test transferring
/// a real block under a throttled bucket, which hung indefinitely until
/// this fix.
#[tokio::test]
async fn a_single_request_larger_than_capacity_still_eventually_succeeds() {
    let bucket = TokenBucket::new(1000); // capacity 1000 bytes/sec
    let start = Instant::now();
    tokio::time::timeout(Duration::from_secs(10), bucket.acquire(5000))
        .await
        .expect("a request for 5x the nominal capacity must not deadlock");
    let elapsed = start.elapsed();
    // Starting available = capacity (1000), so ~4000 bytes' worth of
    // waiting is expected at 1000 bytes/sec: ~4 seconds.
    assert!(
        (Duration::from_secs(3)..Duration::from_secs(6)).contains(&elapsed),
        "expected roughly a 4s wait, took {elapsed:?}"
    );
}

/// a configured rate caps throughput — acquiring more bytes
/// than the bucket's capacity in one go forces a wait proportional to
/// the deficit at the configured rate.
#[tokio::test]
async fn configured_rate_caps_throughput_with_a_real_wait() {
    let bucket = TokenBucket::new(1000); // 1000 bytes/sec, capacity 1000 bytes
    let start = Instant::now();
    bucket.acquire(1000).await; // drains the initial full bucket instantly
    bucket.acquire(500).await; // must wait ~0.5s for refill
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(400),
        "expected a real wait for refill, took {elapsed:?}"
    );
    assert!(elapsed < Duration::from_secs(2), "wait was unexpectedly long: {elapsed:?}");
}

/// a rate change is picked up by a call already blocked
/// awaiting refill, not just newly-started calls — simulated by
/// draining the bucket, raising the rate significantly, and confirming
/// the next acquire finishes much sooner than the *original* rate would
/// have allowed.
#[tokio::test]
async fn rate_change_applies_without_reconstructing_the_bucket() {
    let bucket = Arc::new(TokenBucket::new(10)); // very slow: 10 bytes/sec
    bucket.acquire(10).await; // drain the initial bucket

    let waiter = {
        let bucket = bucket.clone();
        tokio::spawn(async move {
            let start = Instant::now();
            bucket.acquire(1000).await; // would take ~100s at the original rate
            start.elapsed()
        })
    };
    // Give the waiter a moment to start blocking, then raise the rate
    // by several orders of magnitude.
    tokio::time::sleep(Duration::from_millis(20)).await;
    bucket.set_rate_bytes_per_sec(1_000_000);

    let elapsed = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("rate increase should let the waiting acquire finish quickly")
        .unwrap();
    assert!(elapsed < Duration::from_secs(2), "took {elapsed:?} after a rate increase");
}

/// A `0` rate change mid-wait immediately unblocks any pending acquire
/// (the next loop iteration's rate re-read sees `0` and returns).
#[tokio::test]
async fn setting_rate_to_zero_mid_wait_unblocks_immediately() {
    let bucket = Arc::new(TokenBucket::new(1)); // effectively frozen
    bucket.acquire(1).await;

    let waiter = {
        let bucket = bucket.clone();
        tokio::spawn(async move { bucket.acquire(1_000_000).await })
    };
    tokio::time::sleep(Duration::from_millis(20)).await;
    bucket.set_rate_bytes_per_sec(0);

    tokio::time::timeout(Duration::from_secs(2), waiter)
        .await
        .expect("switching to unlimited mid-wait should unblock immediately")
        .unwrap();
}
