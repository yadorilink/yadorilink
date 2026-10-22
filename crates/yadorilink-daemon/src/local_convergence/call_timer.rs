//! Per-call timing for one reconcile pass.
//!
//! A [`ReconcileCallTimer`] is created once per `reconcile_group_paths` call
//! and threaded by reference through every function that call touches, so
//! every number it reports is scoped to THIS call, never a sibling's --
//! overlapping calls (e.g. the windowed reprojection backstop running
//! alongside an obligation tick) cannot contaminate each other the way a
//! global before/after counter diff does. Its internals are atomics only
//! because concurrent work WITHIN one call (block fetches, `spawn_blocking`
//! store/SQLite work) can run on different executor threads.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Saturating nanoseconds: a duration longer than 584 years clamps rather
/// than wrapping.
fn ns(d: Duration) -> u64 {
    d.as_nanos().min(u64::MAX as u128) as u64
}

fn ms_of(nanos: u64) -> u64 {
    nanos / 1_000_000
}

static NEXT_RECONCILE_ID: AtomicU64 = AtomicU64::new(0);

/// Per-invocation, call-local timing for one `reconcile_group_paths` call
/// (and the `try_commit_ordinary_batch`/`prepare_ordinary_projected_upsert`
/// work it drives). See this module's own doc comment.
pub struct ReconcileCallTimer {
    reconcile_id: u64,
    dag_resolution_ns: AtomicU64,
    ensure_blocks_present_ns: AtomicU64,
    provenance_flush_ns: AtomicU64,
    /// Writer-gate wait vs. actual SQLite transaction/fsync time, summed
    /// across every SQLite write this call's commit path made (provenance
    /// flush, `finalize_projected_
    /// mutations_batch`) -- see `add_sqlite_write`'s own doc comment for
    /// how the split is derived.
    writer_gate_wait_ns: AtomicU64,
    sqlite_transaction_ns: AtomicU64,
    ordinary_commit_ns: AtomicU64,
    blocks_fetched: AtomicU64,
    block_fetch_wait_ns: AtomicU64,
    store_put_ns: AtomicU64,
    /// The window timeline's phases (`receive_diag`): only written while the
    /// receive budget is armed.
    window_fetch_ns: AtomicU64,
    window_plan_ns: AtomicU64,
    window_settle_ns: AtomicU64,
    collector_wait_ns: [AtomicU64; 2],
    collector_flush_ns: [AtomicU64; 2],
}

impl ReconcileCallTimer {
    pub fn new() -> Self {
        Self {
            reconcile_id: NEXT_RECONCILE_ID.fetch_add(1, Ordering::Relaxed) + 1,
            dag_resolution_ns: AtomicU64::new(0),
            ensure_blocks_present_ns: AtomicU64::new(0),
            provenance_flush_ns: AtomicU64::new(0),
            writer_gate_wait_ns: AtomicU64::new(0),
            sqlite_transaction_ns: AtomicU64::new(0),
            ordinary_commit_ns: AtomicU64::new(0),
            blocks_fetched: AtomicU64::new(0),
            block_fetch_wait_ns: AtomicU64::new(0),
            store_put_ns: AtomicU64::new(0),
            window_fetch_ns: AtomicU64::new(0),
            window_plan_ns: AtomicU64::new(0),
            window_settle_ns: AtomicU64::new(0),
            collector_wait_ns: [const { AtomicU64::new(0) }; 2],
            collector_flush_ns: [const { AtomicU64::new(0) }; 2],
        }
    }

    /// The whole of the attempt's content-obtaining step (not just the wire
    /// waits [`Self::add_block_fetch_wait`] sums).
    pub fn add_window_fetch(&self, elapsed: Duration) {
        self.window_fetch_ns.fetch_add(ns(elapsed), Ordering::Relaxed);
    }
    /// Planning every level and building the work, up to the first settle.
    pub fn add_window_plan(&self, elapsed: Duration) {
        self.window_plan_ns.fetch_add(ns(elapsed), Ordering::Relaxed);
    }
    /// Settling the planned entries (the runs and the barriers), start to end.
    pub fn add_window_settle(&self, elapsed: Duration) {
        self.window_settle_ns.fetch_add(ns(elapsed), Ordering::Relaxed);
    }
    /// One run's collector times, as summed by its `CompletionWindow`.
    pub(crate) fn add_collectors(&self, waits: [u64; 2], flushes: [u64; 2]) {
        for index in 0..2 {
            self.collector_wait_ns[index].fetch_add(waits[index], Ordering::Relaxed);
            self.collector_flush_ns[index].fetch_add(flushes[index], Ordering::Relaxed);
        }
    }
    /// What this attempt spent per phase, for the window timeline.
    pub(crate) fn window_phases(&self) -> crate::receive_diag::WindowPhases {
        let load = |slot: &AtomicU64| Duration::from_nanos(slot.load(Ordering::Relaxed));
        crate::receive_diag::WindowPhases {
            fetch: load(&self.window_fetch_ns),
            plan: load(&self.window_plan_ns),
            settle: load(&self.window_settle_ns),
            queue_wait: std::array::from_fn(|index| load(&self.collector_wait_ns[index])),
            flush: std::array::from_fn(|index| load(&self.collector_flush_ns[index])),
        }
    }

    pub fn add_dag_resolution(&self, elapsed: Duration) {
        self.dag_resolution_ns.fetch_add(ns(elapsed), Ordering::Relaxed);
    }
    pub fn add_provenance_flush(&self, elapsed: Duration) {
        self.provenance_flush_ns.fetch_add(ns(elapsed), Ordering::Relaxed);
    }
    fn add_writer_gate_wait(&self, elapsed: Duration) {
        self.writer_gate_wait_ns.fetch_add(ns(elapsed), Ordering::Relaxed);
    }
    fn add_sqlite_transaction(&self, elapsed: Duration) {
        self.sqlite_transaction_ns.fetch_add(ns(elapsed), Ordering::Relaxed);
    }
    /// Records the writer_gate wait/hold split for ONE SQLite write this
    /// call made, from a narrow before/after diff of `yadorilink_sqlite_
    /// runtime::writer_gate_stats`'s own (process-wide, but here narrowly windowed
    /// around exactly one write, not this whole `reconcile_group_paths`
    /// call) gate-acquisition wait counter -- see the call site's own
    /// comment for why this narrow a window is trustworthy where the old
    /// whole-call-span diff was not: `total_elapsed` is this call's own
    /// wrap around exactly one `write`/`write_immediate`, and `gate_wait`
    /// is that SAME window's own delta of the global wait-time counter, so
    /// nothing from a sibling call's writer_gate wait can leak in unless
    /// another writer's wait genuinely straddles this narrow window --
    /// far less likely than straddling a whole multi-file reconcile call.
    /// `sqlite_transaction_ms` is then simply what is left: actual
    /// transaction/fsync work, never spent waiting for the gate.
    pub fn add_sqlite_write(&self, total_elapsed: Duration, gate_wait: Duration) {
        let sqlite_txn = total_elapsed.saturating_sub(gate_wait);
        self.add_writer_gate_wait(gate_wait);
        self.add_sqlite_transaction(sqlite_txn);
    }
    /// `elapsed` is the requester-observed `fetch_block_raw` round trip for
    /// ONE ATTEMPT at fetching a block (wire wait, from just before the
    /// request goes out to the response arriving) -- see `fetch_block_raw`'s
    /// own doc comment. Called on every attempt, including a block that
    /// needed a `NotFound`/`Busy` retry before succeeding, so this
    /// legitimately sums to more than `blocks_fetched * one RTT` for a
    /// call with any retries -- does NOT bump `blocks_fetched` itself, see
    /// [`Self::add_block_fetched`] for that (recorded once, at the block's
    /// own eventual success, not once per attempt).
    pub fn add_block_fetch_wait(&self, elapsed: Duration) {
        self.block_fetch_wait_ns.fetch_add(ns(elapsed), Ordering::Relaxed);
    }
    /// One block newly fetched and durably `store.put` by this call --
    /// call exactly once per block, at its success, not once per attempt
    /// (see [`Self::add_block_fetch_wait`] for the attempt-scoped wire-wait
    /// sum).
    pub fn add_block_fetched(&self) {
        self.blocks_fetched.fetch_add(1, Ordering::Relaxed);
    }
    /// `elapsed` is the whole `spawn_blocking` round trip for one block's
    /// `store.put`, timed from the async caller's side (not just the
    /// closure body) -- so this also captures `spawn_blocking` queueing
    /// time.
    pub fn add_store_put(&self, elapsed: Duration) {
        self.store_put_ns.fetch_add(ns(elapsed), Ordering::Relaxed);
    }

    /// Logs exactly one line for this call, unconditionally, at `info`
    /// (silent under the daemon's default filter). Not gated by an elapsed
    /// threshold: a benchmark run sums every call's phases, and a gate would
    /// drop the fast calls from that sum.
    pub fn finish(
        &self,
        group_id: &str,
        path_count: usize,
        settled_count: usize,
        retry_count: usize,
        outer_elapsed: Duration,
    ) {
        let outer_ms = outer_elapsed.as_millis() as u64;
        let dag_resolution_ms = ms_of(self.dag_resolution_ns.load(Ordering::Relaxed));
        let ensure_blocks_present_ms = ms_of(self.ensure_blocks_present_ns.load(Ordering::Relaxed));
        let provenance_flush_ms = ms_of(self.provenance_flush_ns.load(Ordering::Relaxed));
        let writer_gate_wait_ms = ms_of(self.writer_gate_wait_ns.load(Ordering::Relaxed));
        let sqlite_transaction_ms = ms_of(self.sqlite_transaction_ns.load(Ordering::Relaxed));
        let ordinary_commit_ms = ms_of(self.ordinary_commit_ns.load(Ordering::Relaxed));
        let blocks_fetched = self.blocks_fetched.load(Ordering::Relaxed);
        let block_fetch_wait_ms = ms_of(self.block_fetch_wait_ns.load(Ordering::Relaxed));
        let store_put_ms = ms_of(self.store_put_ns.load(Ordering::Relaxed));
        // `ordinary_commit_ms` already includes `provenance_flush_ms`
        // (`try_commit_ordinary_batch`'s own call is wrapped as one whole
        // span), so `unattributed_ms` is a useful "how much of this call is
        // NOT explained by any named component" signal, not a strict
        // partition.
        let attributed_ms = dag_resolution_ms + ensure_blocks_present_ms + ordinary_commit_ms;
        let unattributed_ms = outer_ms.saturating_sub(attributed_ms);
        tracing::info!(
            reconcile_id = self.reconcile_id,
            group_id,
            path_count,
            settled_count,
            retry_count,
            outer_ms,
            dag_resolution_ms,
            ensure_blocks_present_ms,
            provenance_flush_ms,
            writer_gate_wait_ms,
            sqlite_transaction_ms,
            ordinary_commit_ms,
            blocks_fetched,
            block_fetch_wait_ms,
            store_put_ms,
            unattributed_ms,
            "reconcile_group_paths call timing"
        );
    }
}

impl Default for ReconcileCallTimer {
    fn default() -> Self {
        Self::new()
    }
}
