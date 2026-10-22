//! Daemon-wide GC coordination and last-run bookkeeping -- one instance
//! lives on `DaemonState`, shared by the idle scheduler and every
//! on-demand `gc`/`gc --dry-run` request, so both go through the exact
//! same mutual-exclusion and reporting state. Split out of `gc.rs` itself
//! (which owns the actual sweep logic and needs `DaemonState`) so this
//! narrow, self-contained runtime-state owner -- no `DaemonState`
//! dependency at all -- can be read (`RuntimeStatusQueryService`) without
//! pulling in the sweep module's own `DaemonState` coupling, matching
//! `peer_registry`/`link_registry`/`runtime_telemetry`/`durability_service`'s
//! own extraction precedent.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};

pub struct GcState {
    /// "only one sweep runs at a time daemon-wide" -- claimed via
    /// `compare_exchange` in `try_start` regardless of which trigger (idle
    /// scheduler vs. on-demand IPC request) is attempting it, so an
    /// on-demand trigger firing mid-idle-sweep never starts a second,
    /// concurrent sweep.
    running: AtomicBool,
    /// Unix seconds of the last *real* (non-dry-run) sweep's completion;
    /// `0` if none has ever completed since this daemon's block store was
    /// created.
    last_run_unix: AtomicI64,
    last_blocks_deleted: AtomicU64,
    last_bytes_reclaimed: AtomicU64,
    /// The most recently *computed* delete-set size: reset to `0`
    /// immediately after a real sweep (everything reclaimable as of that
    /// snapshot was just reclaimed), or left at the reported delete-set
    /// size after a `gc --dry-run` -- going stale as new writes/deletes
    /// happen until the next sweep/dry-run computes it again (this is
    /// disclosed dry-run behavior -- modulo the ordinary passage of time --
    /// not a bug). Backs `StatusResponse.gc_reclaimable_estimate_bytes`.
    reclaimable_estimate_bytes: AtomicU64,
}

impl Default for GcState {
    fn default() -> Self {
        Self::new()
    }
}

impl GcState {
    pub fn new() -> Self {
        Self {
            running: AtomicBool::new(false),
            last_run_unix: AtomicI64::new(0),
            last_blocks_deleted: AtomicU64::new(0),
            last_bytes_reclaimed: AtomicU64::new(0),
            reclaimable_estimate_bytes: AtomicU64::new(0),
        }
    }

    pub fn last_run_unix(&self) -> i64 {
        self.last_run_unix.load(Ordering::SeqCst)
    }

    pub fn last_blocks_deleted(&self) -> u64 {
        self.last_blocks_deleted.load(Ordering::SeqCst)
    }

    pub fn last_bytes_reclaimed(&self) -> u64 {
        self.last_bytes_reclaimed.load(Ordering::SeqCst)
    }

    pub fn reclaimable_estimate_bytes(&self) -> u64 {
        self.reclaimable_estimate_bytes.load(Ordering::SeqCst)
    }

    /// Records a completed `--dry-run` sweep: only the reclaimable-bytes
    /// estimate changes, since nothing was actually deleted.
    pub(crate) fn record_dry_run(&self, bytes_reclaimed: u64) {
        self.reclaimable_estimate_bytes.store(bytes_reclaimed, Ordering::SeqCst);
    }

    /// Records a completed real sweep -- also zeroes the reclaimable-bytes
    /// estimate, since everything reclaimable as of this snapshot was just
    /// reclaimed.
    pub(crate) fn record_real_sweep(
        &self,
        now_unix: i64,
        blocks_deleted: u64,
        bytes_reclaimed: u64,
    ) {
        self.last_run_unix.store(now_unix, Ordering::SeqCst);
        self.last_blocks_deleted.store(blocks_deleted, Ordering::SeqCst);
        self.last_bytes_reclaimed.store(bytes_reclaimed, Ordering::SeqCst);
        self.reclaimable_estimate_bytes.store(0, Ordering::SeqCst);
    }

    /// Atomically claims the "a sweep is running" flag and returns a guard
    /// that releases it on drop -- `Err(())` means another sweep (idle-
    /// triggered or on-demand) already holds it.
    pub(crate) fn try_start(&self) -> Result<GcRunGuard<'_>, ()> {
        if self.running.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            return Err(());
        }
        Ok(GcRunGuard { running: &self.running })
    }

    /// Test-only: forces the running flag on without going through
    /// `try_start`, to simulate "a sweep is already in flight" for a
    /// concurrency test.
    #[cfg(test)]
    pub(crate) fn mark_running_for_test(&self) {
        self.running.store(true, Ordering::SeqCst);
    }
}

/// RAII guard releasing `GcState`'s running flag on drop -- mirrors
/// `BroadcastGuard`/`WriteActivityGuard` (`daemon_state.rs`) so a sweep
/// that returns early via `?` (or, in principle, panics) still gets
/// counted back out, never wedging every future sweep attempt behind a
/// permanently-stuck flag.
pub(crate) struct GcRunGuard<'a> {
    running: &'a AtomicBool,
}

impl Drop for GcRunGuard<'_> {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
    }
}
