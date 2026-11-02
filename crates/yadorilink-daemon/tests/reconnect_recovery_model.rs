//! How long a mesh takes to come back when several pairs lose their session together, with the handshake
//! permit the `row14_strict_acceptance` harness uses (ONE at a time) and without it (the product: every peer is kept by
//! its own keeper, `peer_connectivity_runtime::peer_sessions`, and nothing there takes a shared permit).
//!
//! A model on paused time, no daemons and no load: each pair reconnects with the production schedule
//! (`BackoffConfig::RECONNECT`: 1 s doubling, 45 s cap; the nominal values here, without the jitter) and each attempt
//! either fails after `FAIL_AFTER` (a handshake that ran out of time on a loaded host) or succeeds after `OK_AFTER`.
//! The permit, when there is one, is held for the whole attempt, exactly as the harness holds it.
//!
//! What it shows (and what the test is about): five pairs cut together, each failing twice before it succeeds. With a single
//! permit the attempts are served one after the other and the mesh needs over 100 s, which is longer than
//! `row14_strict_acceptance`'s 90 s no-progress bound, without any defect in convergence. Without the permit the same
//! pairs are back in about half a minute.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::time::Instant;

/// A handshake that ran out of its time on a loaded host: the exact-generation handshake's bounded retry budget is
/// "about 11 s worst case" (`row14_strict_acceptance.rs`, `TEST_PAIR_READY_TIMEOUT`'s comment).
const FAIL_AFTER: Duration = Duration::from_secs(11);
/// A handshake that works, on a loaded host.
const OK_AFTER: Duration = Duration::from_secs(2);
const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(45);

fn nominal_backoff(attempt: u32) -> Duration {
    BACKOFF_INITIAL.saturating_mul(1u32 << attempt.min(20)).min(BACKOFF_MAX)
}

/// One pair's reconnect loop: wait the backoff, take the permit (if any) for the whole attempt, fail `failures` times,
/// then succeed. Returns when the pair is up.
async fn reconnect_pair(permit: Option<Arc<Semaphore>>, failures: u32) {
    let mut attempt = 0u32;
    loop {
        tokio::time::sleep(nominal_backoff(attempt)).await;
        let _held = match &permit {
            Some(p) => Some(p.acquire().await.unwrap()),
            None => None,
        };
        if attempt < failures {
            tokio::time::sleep(FAIL_AFTER).await;
            attempt += 1;
        } else {
            tokio::time::sleep(OK_AFTER).await;
            return;
        }
    }
}

/// Seconds until `pairs` pairs cut at the same instant are all back.
async fn mesh_recovery(pairs: usize, permits: Option<usize>, failures: u32) -> u64 {
    let permit = permits.map(|n| Arc::new(Semaphore::new(n)));
    let start = Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..pairs {
        tasks.push(tokio::spawn(reconnect_pair(permit.clone(), failures)));
    }
    for t in tasks {
        t.await.unwrap();
    }
    start.elapsed().as_secs()
}

#[tokio::test(start_paused = true)]
async fn five_pairs_cut_together_with_one_handshake_permit_take_longer_than_the_stall_bound() {
    // The harness (row14_strict_acceptance.rs): MAX_CONCURRENT_HANDSHAKES = 1.
    let serial = mesh_recovery(5, Some(1), 2).await;
    // No shared permit (the product's keepers are independent per peer).
    let parallel = mesh_recovery(5, None, 2).await;
    eprintln!(
        "5 pairs, 2 failed attempts each: one permit {serial} s, no shared permit {parallel} s"
    );
    assert!(serial > 100, "one permit: {serial} s");
    assert!(parallel < 40, "no shared permit: {parallel} s");
}

/// The permits `row14_strict_acceptance` uses (its `MAX_CONCURRENT_HANDSHAKES`; keep them equal): the mesh that lost one
/// device's five pairs, each failing twice, must be back inside 60 s, well under that test's 90 s no-progress bound.
const ROW14_PERMITS: usize = 3;

#[tokio::test(start_paused = true)]
async fn the_permits_row14_uses_bring_five_cut_pairs_back_inside_sixty_seconds() {
    let recovery = mesh_recovery(5, Some(ROW14_PERMITS), 2).await;
    eprintln!("5 pairs, 2 failed attempts each, {ROW14_PERMITS} permits: {recovery} s");
    assert!(recovery <= 60, "{ROW14_PERMITS} permits: {recovery} s");
}

#[tokio::test(start_paused = true)]
async fn the_permit_is_a_cost_only_when_attempts_fail() {
    // Healthy attempts (no failures): five handshakes of 2 s in a row are still quick.
    let serial_healthy = mesh_recovery(5, Some(1), 0).await;
    eprintln!("5 pairs, no failed attempt: one permit {serial_healthy} s");
    assert!(serial_healthy < 15, "one permit, healthy: {serial_healthy} s");
    // A few permits in between (a small, bounded parallelism) recover close to the unbounded case.
    for permits in [2usize, 3] {
        let t = mesh_recovery(5, Some(permits), 2).await;
        eprintln!("5 pairs, 2 failed attempts each: {permits} permits {t} s");
    }
    let two = mesh_recovery(5, Some(2), 2).await;
    let three = mesh_recovery(5, Some(3), 2).await;
    assert!(two >= three, "more permits never recover later ({two} s with 2, {three} s with 3)");
}
