//! Shared backoff schedule for the Convergence Engine.
//!
//! Both job-level retry (a whole `(group, path)` materialization job that
//! could not progress this attempt) and the per-block fetch retry inside
//! `hydration::BlockWorkQueue` want the same shape: fast on the first retry
//! (a single slow response is common and shouldn't be penalized much),
//! meaningfully spaced out on repeated failures, jittered so concurrent
//! waiters on the same peer don't resynchronize their retries back onto it
//! at once. Factoring it into one function here — rather than each retry
//! site keeping its own constants — is what lets a later cleanup fold
//! `BlockWorkQueue::mark_timed_out`'s own backoff into this one without
//! maintaining two schedules that drift apart.

use std::time::Duration;

const BACKOFF_BASE: Duration = Duration::from_secs(1);
const BACKOFF_CAP: Duration = Duration::from_secs(30);
const BACKOFF_JITTER_FRACTION: f64 = 0.25;

/// `attempt`'s backoff delay: `BACKOFF_BASE * 2^(attempt-1)` capped at
/// `BACKOFF_CAP`, +/-25% jitter — 1s/2s/4s/8s/16s/30s for `attempt` 1..=6,
/// then flat at 30s (jittered) for any further attempt. `attempt` is
/// 1-indexed (the count of consecutive failures so far, including this
/// one); `attempt == 0` is treated the same as `attempt == 1` (fast first
/// retry) rather than a zero delay, since a caller scheduling backoff has by
/// definition already failed at least once.
pub fn next_backoff(attempt: u32) -> Duration {
    let scale = 1u64 << attempt.saturating_sub(1).min(20);
    let backed_off = BACKOFF_BASE.saturating_mul(scale as u32).min(BACKOFF_CAP);
    let jitter = rand::random_range(-BACKOFF_JITTER_FRACTION..=BACKOFF_JITTER_FRACTION);
    backed_off.mul_f64((1.0 + jitter).max(0.0))
}

#[cfg(test)]
mod tests;
