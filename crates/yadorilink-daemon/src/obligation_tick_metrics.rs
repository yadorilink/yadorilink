//! Process-wide counter for the obligation engine's zero-work pre-check.
//!
//! `process_group_via_obligations` windows each tick's claimed paths down to
//! `MAX_PATHS_PER_RECONCILE_ATTEMPT` before running the zero-work pre-check
//! over them. Checking every claimed path instead (up to the claim limit)
//! multiplies per-tick resolution work with no throughput benefit, since at
//! most one window of paths can reach a real reconcile attempt in the same
//! tick. This counter is what lets a test observe that bound on the full
//! async engine, and it exists only in test builds: nothing in a release
//! build reads it.

use std::sync::atomic::{AtomicU64, Ordering};

static ZERO_WORK_ATTEMPTED: AtomicU64 = AtomicU64::new(0);

/// `n` paths handed to the zero-work pre-check in one tick.
pub(crate) fn record_zero_work_attempted(n: usize) {
    ZERO_WORK_ATTEMPTED.fetch_add(n as u64, Ordering::Relaxed);
}
