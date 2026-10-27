//! Measurement-only "serial budget" for a bulk receive: where wall time goes
//! between a peer's change being claimed and the file being committed.
//!
//! Throughput says how fast a run was; it cannot say whether the time is in
//! the SQLite commits, in the durability syscalls, or in waiting for the
//! per-path lock, and those have different fixes. The pieces, all armed
//! together by `YADORILINK_DIAGNOSTIC_RECEIVE_BUDGET=1` and dumped by
//! [`emit_report`] at shutdown (and on SIGUSR1):
//!
//! - **path lock** wait and hold per acquisition site (this module);
//! - the SQLite body/commit split per write site
//!   (`yadorilink_sqlite_runtime::writer_gate_stats`), next to the existing
//!   per-site hold and gate-wait counters;
//! - file fsync, parent-directory fsync and rename counts and times, plus
//!   the number of distinct parent directories
//!   (`yadorilink_local_storage::io_diag`);
//! - the **window timeline**: per reconcile attempt, the files in the window,
//!   its wall duration, the time in each phase (block fetch, plan, settle run,
//!   and the collectors' queue waits and flush times), and the gap between
//!   the end of one attempt and the start of the next for the same group,
//!   aggregated into one `receive_budget windows` line;
//! - the **settle-run stages**: per settle run, when the first and the last
//!   file reached each step of the per-file sequence (lock, open, temp file,
//!   rename, close). The distance between the last arrivals of consecutive
//!   steps is the time the run waited for its slowest file to pass the step,
//!   so the steps add up to the run's wall time (`receive_budget
//!   settle_stages`), unlike the per-task sums above.
//!
//! **Off by default and inert.** Every entry point begins with one relaxed
//! load of [`ENABLED`]; unarmed, nothing allocates, locks or reads the
//! clock, and nothing here changes control flow, ordering or error handling
//! in either state. Armed, an acquisition costs two clock reads and one
//! uncontended mutex plus a map update (see the overhead test). Process-
//! global state, like `io_diag`, so a test arming it owns the process for
//! its duration.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use yadorilink_sqlite_runtime::diag_hist::Log2Hist;

static ENABLED: AtomicBool = AtomicBool::new(false);

/// Whether the receive budget is armed. One relaxed load.
#[inline(always)]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Arms or disarms recording process-wide.
pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
}

/// Zeroes everything this module records. Call between measured runs.
pub fn reset() {
    *LOCK_SITES.lock().unwrap_or_else(|p| p.into_inner()) = None;
    LOCK_WAIT_HIST.reset();
    LOCK_HOLD_HIST.reset();
    COMPLETION_BATCHES.store(0, Ordering::Relaxed);
    COMPLETION_ITEMS.store(0, Ordering::Relaxed);
    COMPLETION_ITEMS_HIST.reset();
    OPEN_BATCHES.store(0, Ordering::Relaxed);
    OPEN_ITEMS.store(0, Ordering::Relaxed);
    OPEN_ITEMS_HIST.reset();
    reset_windows();
    reset_stages();
}

// ---------------------------------------------------------------------
// Batched completions
// ---------------------------------------------------------------------

static COMPLETION_BATCHES: AtomicU64 = AtomicU64::new(0);
static COMPLETION_ITEMS: AtomicU64 = AtomicU64::new(0);
static COMPLETION_ITEMS_HIST: Log2Hist = Log2Hist::new();

/// One batched completion transaction that closed `items` files.
pub(crate) fn record_completion_batch(items: usize) {
    if !enabled() {
        return;
    }
    COMPLETION_BATCHES.fetch_add(1, Ordering::Relaxed);
    COMPLETION_ITEMS.fetch_add(items as u64, Ordering::Relaxed);
    COMPLETION_ITEMS_HIST.record(items as u64);
}

static OPEN_BATCHES: AtomicU64 = AtomicU64::new(0);
static OPEN_ITEMS: AtomicU64 = AtomicU64::new(0);
static OPEN_ITEMS_HIST: Log2Hist = Log2Hist::new();

/// One batched open transaction that opened `items` files' writes.
pub(crate) fn record_open_batch(items: usize) {
    if !enabled() {
        return;
    }
    OPEN_BATCHES.fetch_add(1, Ordering::Relaxed);
    OPEN_ITEMS.fetch_add(items as u64, Ordering::Relaxed);
    OPEN_ITEMS_HIST.record(items as u64);
}

// ---------------------------------------------------------------------
// Window timeline
// ---------------------------------------------------------------------

/// The collectors whose queue wait and flush time a window reports, in the
/// order of the arrays below.
pub(crate) const COLLECTOR_OPEN: usize = 0;
pub(crate) const COLLECTOR_CLOSE: usize = 1;
const COLLECTORS: usize = 2;

/// One metric over the windows of a run: how many, their sum, and a
/// histogram for the percentiles. Nanoseconds unless it counts files.
struct Dist {
    count: AtomicU64,
    total: AtomicU64,
    hist: Log2Hist,
}

impl Dist {
    const fn new() -> Self {
        Self { count: AtomicU64::new(0), total: AtomicU64::new(0), hist: Log2Hist::new() }
    }

    fn record(&self, value: u64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.total.fetch_add(value, Ordering::Relaxed);
        self.hist.record(value);
    }

    fn reset(&self) {
        self.count.store(0, Ordering::Relaxed);
        self.total.store(0, Ordering::Relaxed);
        self.hist.reset();
    }

    fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    fn mean(&self) -> u64 {
        self.total().checked_div(self.count()).unwrap_or(0)
    }
}

static W_WALL: Dist = Dist::new();
static W_FILES: Dist = Dist::new();
static W_GAP: Dist = Dist::new();
static W_FETCH: Dist = Dist::new();
static W_PLAN: Dist = Dist::new();
static W_SETTLE: Dist = Dist::new();
static W_WAIT: [Dist; COLLECTORS] = [const { Dist::new() }; COLLECTORS];
static W_FLUSH: [Dist; COLLECTORS] = [const { Dist::new() }; COLLECTORS];
/// The most groups whose last attempt end is remembered.
const LAST_END_CAP: usize = 1024;

/// When the last recorded attempt of each group ended.
static LAST_END: Mutex<Option<HashMap<String, Instant>>> = Mutex::new(None);

fn reset_windows() {
    for dist in [&W_WALL, &W_FILES, &W_GAP, &W_FETCH, &W_PLAN, &W_SETTLE] {
        dist.reset();
    }
    for dist in W_WAIT.iter().chain(W_FLUSH.iter()) {
        dist.reset();
    }
    *LAST_END.lock().unwrap_or_else(|p| p.into_inner()) = None;
}

/// Reads the clock only when armed: the start of a span a caller reports with
/// `elapsed()`.
#[inline]
pub(crate) fn clock() -> Option<Instant> {
    enabled().then(Instant::now)
}

/// An attempt that started while armed.
pub(crate) struct WindowStart {
    started: Instant,
    /// The time since the same group's previous recorded attempt ended.
    gap: Option<Duration>,
}

/// What an attempt spent per phase. The collector times are sums over the
/// window's files, so they can exceed the wall time (files wait together).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct WindowPhases {
    pub fetch: Duration,
    pub plan: Duration,
    pub settle: Duration,
    pub queue_wait: [Duration; COLLECTORS],
    pub flush: [Duration; COLLECTORS],
}

/// Starts a window for `group_id` when armed, and notes the gap since the
/// group's last attempt ended.
pub(crate) fn window_begin(group_id: &str) -> Option<WindowStart> {
    if !enabled() {
        return None;
    }
    let started = Instant::now();
    let gap = LAST_END
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .and_then(|ends| ends.get(group_id))
        .map(|ended| started.saturating_duration_since(*ended));
    Some(WindowStart { started, gap })
}

/// Records a finished window of `files` files.
pub(crate) fn window_end(group_id: &str, start: WindowStart, files: usize, phases: WindowPhases) {
    // A window that began while armed and ends after the instrument was disarmed (a receive still
    // finishing when its caller moved on) records nothing, so disarming really stops recording.
    if !enabled() {
        return;
    }
    let ended = Instant::now();
    W_WALL.record(nanos(ended.saturating_duration_since(start.started)));
    W_FILES.record(files as u64);
    if let Some(gap) = start.gap {
        W_GAP.record(nanos(gap));
    }
    W_FETCH.record(nanos(phases.fetch));
    W_PLAN.record(nanos(phases.plan));
    W_SETTLE.record(nanos(phases.settle));
    for index in 0..COLLECTORS {
        W_WAIT[index].record(nanos(phases.queue_wait[index]));
        W_FLUSH[index].record(nanos(phases.flush[index]));
    }
    let mut ends = LAST_END.lock().unwrap_or_else(|p| p.into_inner());
    let ends = ends.get_or_insert_with(HashMap::new);
    if ends.len() >= LAST_END_CAP && !ends.contains_key(group_id) {
        // Group churn: forget every end time rather than grow without bound;
        // the evicted groups simply report no gap for their next attempt.
        ends.clear();
    }
    ends.insert(group_id.to_owned(), ended);
}

/// How many groups' last attempt ends are remembered, for tests.
#[cfg(test)]
pub(crate) fn last_end_len() -> usize {
    LAST_END.lock().unwrap_or_else(|p| p.into_inner()).as_ref().map_or(0, HashMap::len)
}

/// The cap of [`last_end_len`], for tests.
#[cfg(test)]
pub(crate) const fn last_end_cap() -> usize {
    LAST_END_CAP
}

/// The totals of the window timeline, for tests.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct WindowStats {
    pub windows: u64,
    pub files: u64,
    pub wall_ns: u64,
    pub gaps: u64,
    pub gap_ns: u64,
    pub fetch_ns: u64,
    pub plan_ns: u64,
    pub settle_ns: u64,
    pub queue_wait_ns: [u64; COLLECTORS],
    pub flush_ns: [u64; COLLECTORS],
}

#[cfg(test)]
pub(crate) fn window_stats() -> WindowStats {
    WindowStats {
        windows: W_WALL.count(),
        files: W_FILES.total(),
        wall_ns: W_WALL.total(),
        gaps: W_GAP.count(),
        gap_ns: W_GAP.total(),
        fetch_ns: W_FETCH.total(),
        plan_ns: W_PLAN.total(),
        settle_ns: W_SETTLE.total(),
        queue_wait_ns: std::array::from_fn(|index| W_WAIT[index].total()),
        flush_ns: std::array::from_fn(|index| W_FLUSH[index].total()),
    }
}

// ---------------------------------------------------------------------
// Settle-run critical path
// ---------------------------------------------------------------------

/// The steps every file of a settle run passes through, in order.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Stage {
    /// Past the byte-budget wait, the file's future starts.
    Started = 0,
    /// The displacement guard has answered.
    Displaced,
    /// The directory-in-the-way checks have answered.
    DirChecked,
    /// The case-fold sibling's pending edit is flushed.
    Flushed,
    /// The path lock is held.
    Locked,
    /// About to queue the open of the write.
    ReadyToOpen,
    /// The open transaction has committed.
    Opened,
    /// The temp file is written (without its flush when the flush is deferred).
    TempWritten,
    /// The temp file is renamed into place.
    Renamed,
    /// Metadata applied and verified; about to queue the close.
    PreCommit,
    /// The close transaction has committed and the file's future ends.
    Closed,
}

const STAGES: usize = 11;
const STAGE_NAMES: [&str; STAGES] = [
    "start",
    "displace",
    "dircheck",
    "flush",
    "lock",
    "ready_open",
    "open",
    "temp",
    "rename",
    "precommit",
    "close",
];

/// When the first and the last file of one settle run reached each stage, as
/// nanoseconds since the run began. The distance between the last arrivals of
/// consecutive stages is the time the run was waiting for its slowest file to
/// pass that step, and these distances add up to the run's wall time.
pub(crate) struct RunTrace {
    begun: Instant,
    last: [AtomicU64; STAGES],
    first: [AtomicU64; STAGES],
}

tokio::task_local! {
    static RUN_TRACE: std::sync::Arc<RunTrace>;
}

static S_STEP: [Dist; STAGES + 1] = [const { Dist::new() }; STAGES + 1];
static S_SPREAD: [Dist; STAGES] = [const { Dist::new() }; STAGES];

fn reset_stages() {
    for dist in S_STEP.iter().chain(S_SPREAD.iter()) {
        dist.reset();
    }
}

/// Starts tracing one settle run when armed.
pub(crate) fn run_trace_begin() -> Option<std::sync::Arc<RunTrace>> {
    enabled().then(|| {
        std::sync::Arc::new(RunTrace {
            begun: Instant::now(),
            last: std::array::from_fn(|_| AtomicU64::new(0)),
            first: std::array::from_fn(|_| AtomicU64::new(u64::MAX)),
        })
    })
}

/// Runs `future` with `trace` as the run the [`mark`] calls inside it report to.
pub(crate) async fn run_trace_scope<F: std::future::Future>(
    trace: Option<std::sync::Arc<RunTrace>>,
    future: F,
) -> F::Output {
    match trace {
        Some(trace) => RUN_TRACE.scope(trace, future).await,
        None => future.await,
    }
}

/// Notes that a file of the current settle run reached `stage`.
#[inline]
pub(crate) fn mark(stage: Stage) {
    if !enabled() {
        return;
    }
    let _ = RUN_TRACE.try_with(|trace| {
        let at = nanos(trace.begun.elapsed());
        trace.last[stage as usize].fetch_max(at, Ordering::Relaxed);
        trace.first[stage as usize].fetch_min(at, Ordering::Relaxed);
    });
}

/// Closes a settle run's trace: records how long the run waited at each step.
pub(crate) fn run_trace_end(trace: Option<std::sync::Arc<RunTrace>>) {
    let Some(trace) = trace else { return };
    if !enabled() {
        return;
    }
    record_run(&trace, &S_STEP, &S_SPREAD);
}

/// Adds one finished run to the given stage distributions.
fn record_run(trace: &RunTrace, step: &[Dist; STAGES + 1], spread: &[Dist; STAGES]) {
    let ended = nanos(trace.begun.elapsed());
    let mut frontier = 0u64;
    for index in 0..STAGES {
        let last = trace.last[index].load(Ordering::Relaxed);
        let first = trace.first[index].load(Ordering::Relaxed);
        if first == u64::MAX {
            continue;
        }
        spread[index].record(last.saturating_sub(first));
        let reached = last.max(frontier);
        step[index].record(reached - frontier);
        frontier = reached;
    }
    step[STAGES].record(ended.saturating_sub(frontier));
}

fn emit_stages(occasion: &str) {
    let mut line = String::new();
    for index in 0..STAGES {
        line.push_str(&format!(
            " {}_ms={} {}_spread_ms={}",
            STAGE_NAMES[index],
            S_STEP[index].total() / 1_000_000,
            STAGE_NAMES[index],
            S_SPREAD[index].total() / 1_000_000
        ));
    }
    line.push_str(&format!(" tail_ms={}", S_STEP[STAGES].total() / 1_000_000));
    tracing::info!(occasion, runs = S_STEP[STAGES].count(), stages = %line, "receive_budget settle_stages");
}

// ---------------------------------------------------------------------
// Path lock wait and hold per acquisition site
// ---------------------------------------------------------------------

fn nanos(d: Duration) -> u64 {
    d.as_nanos().min(u128::from(u64::MAX)) as u64
}

/// Reads the clock only when armed.
#[inline]
fn start() -> Option<Instant> {
    enabled().then(Instant::now)
}

#[derive(Clone, Debug, Default)]
pub struct LockSiteStat {
    pub site: String,
    pub acquisitions: u64,
    pub wait_nanos: u128,
    pub wait_max_nanos: u64,
    pub hold_nanos: u128,
    pub hold_max_nanos: u64,
}

type LockSiteKey = (&'static str, u32);

static LOCK_SITES: Mutex<Option<HashMap<LockSiteKey, LockSiteStat>>> = Mutex::new(None);
static LOCK_WAIT_HIST: Log2Hist = Log2Hist::new();
static LOCK_HOLD_HIST: Log2Hist = Log2Hist::new();

fn with_lock_site(site: &'static std::panic::Location<'static>, f: impl FnOnce(&mut LockSiteStat)) {
    let mut guard = LOCK_SITES.lock().unwrap_or_else(|p| p.into_inner());
    let map = guard.get_or_insert_with(Default::default);
    f(map.entry((site.file(), site.line())).or_default());
}

/// A held path lock that, when armed, reports how long it was held.
pub struct TimedPathLock<'a> {
    guard: Option<tokio::sync::MutexGuard<'a, ()>>,
    site: &'static std::panic::Location<'static>,
    acquired: Option<Instant>,
}

impl Drop for TimedPathLock<'_> {
    fn drop(&mut self) {
        if let Some(acquired) = self.acquired {
            // Measure, release the lock, and only then do the bookkeeping,
            // so recording never lengthens the hold it reports.
            let held = nanos(acquired.elapsed());
            drop(self.guard.take());
            LOCK_HOLD_HIST.record(held);
            with_lock_site(self.site, |s| {
                s.hold_nanos += u128::from(held);
                s.hold_max_nanos = s.hold_max_nanos.max(held);
            });
        }
    }
}

/// Acquires a path lock, recording wait and hold time against the CALLER's
/// source line when armed. Unarmed, it is `lock.lock().await` plus one
/// relaxed load, and the guard is the same lock guard.
#[track_caller]
pub fn lock_path(
    lock: &tokio::sync::Mutex<()>,
) -> impl std::future::Future<Output = TimedPathLock<'_>> {
    let site = std::panic::Location::caller();
    async move {
        let wait_started = start();
        let guard = lock.lock().await;
        let acquired = wait_started.map(|started| {
            let acquired = Instant::now();
            let waited = nanos(acquired.saturating_duration_since(started));
            LOCK_WAIT_HIST.record(waited);
            with_lock_site(site, |s| {
                s.acquisitions += 1;
                s.wait_nanos += u128::from(waited);
                s.wait_max_nanos = s.wait_max_nanos.max(waited);
            });
            acquired
        });
        TimedPathLock { guard: Some(guard), site, acquired }
    }
}

/// Every site that acquired a path lock, longest total hold first.
pub fn lock_site_stats() -> Vec<LockSiteStat> {
    let guard = LOCK_SITES.lock().unwrap_or_else(|p| p.into_inner());
    let mut v: Vec<LockSiteStat> = guard
        .iter()
        .flatten()
        .map(|((file, line), stat)| LockSiteStat { site: format!("{file}:{line}"), ..stat.clone() })
        .collect();
    v.sort_by_key(|s| std::cmp::Reverse(s.hold_nanos));
    v
}

// ---------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------

fn ms(nanos: u128) -> u64 {
    (nanos / 1_000_000) as u64
}

fn us(nanos: u64) -> u64 {
    nanos / 1_000
}

/// The one `receive_budget windows` line: how many windows, how many files in
/// them, and for the wall time, the gap between attempts (`gaps` of them),
/// each phase and each collector's queue wait and flush time, the total in
/// milliseconds and the mean, p50 and p99 in microseconds (the percentiles are
/// power-of-two lower bounds). The collector waits are sums over the files of
/// a window, so they can exceed the wall time.
fn emit_windows(occasion: &str) {
    let ms_total = |dist: &Dist| dist.total() / 1_000_000;
    let us_mean = |dist: &Dist| dist.mean() / 1_000;
    let us_pct = |dist: &Dist, q: f64| dist.hist.percentile(q) / 1_000;
    tracing::info!(
        occasion,
        windows = W_WALL.count(),
        files_total = W_FILES.total(),
        files_mean = W_FILES.mean(),
        gaps = W_GAP.count(),
        wall_total_ms = ms_total(&W_WALL),
        wall_mean_us = us_mean(&W_WALL),
        wall_p50_us = us_pct(&W_WALL, 0.5),
        wall_p99_us = us_pct(&W_WALL, 0.99),
        gap_total_ms = ms_total(&W_GAP),
        gap_mean_us = us_mean(&W_GAP),
        gap_p50_us = us_pct(&W_GAP, 0.5),
        gap_p99_us = us_pct(&W_GAP, 0.99),
        fetch_total_ms = ms_total(&W_FETCH),
        fetch_mean_us = us_mean(&W_FETCH),
        fetch_p50_us = us_pct(&W_FETCH, 0.5),
        fetch_p99_us = us_pct(&W_FETCH, 0.99),
        plan_total_ms = ms_total(&W_PLAN),
        plan_mean_us = us_mean(&W_PLAN),
        plan_p50_us = us_pct(&W_PLAN, 0.5),
        plan_p99_us = us_pct(&W_PLAN, 0.99),
        settle_total_ms = ms_total(&W_SETTLE),
        settle_mean_us = us_mean(&W_SETTLE),
        settle_p50_us = us_pct(&W_SETTLE, 0.5),
        settle_p99_us = us_pct(&W_SETTLE, 0.99),
        wait_open_total_ms = ms_total(&W_WAIT[COLLECTOR_OPEN]),
        wait_open_mean_us = us_mean(&W_WAIT[COLLECTOR_OPEN]),
        wait_open_p50_us = us_pct(&W_WAIT[COLLECTOR_OPEN], 0.5),
        wait_open_p99_us = us_pct(&W_WAIT[COLLECTOR_OPEN], 0.99),
        wait_close_total_ms = ms_total(&W_WAIT[COLLECTOR_CLOSE]),
        wait_close_mean_us = us_mean(&W_WAIT[COLLECTOR_CLOSE]),
        wait_close_p50_us = us_pct(&W_WAIT[COLLECTOR_CLOSE], 0.5),
        wait_close_p99_us = us_pct(&W_WAIT[COLLECTOR_CLOSE], 0.99),
        flush_open_total_ms = ms_total(&W_FLUSH[COLLECTOR_OPEN]),
        flush_open_mean_us = us_mean(&W_FLUSH[COLLECTOR_OPEN]),
        flush_open_p50_us = us_pct(&W_FLUSH[COLLECTOR_OPEN], 0.5),
        flush_open_p99_us = us_pct(&W_FLUSH[COLLECTOR_OPEN], 0.99),
        flush_close_total_ms = ms_total(&W_FLUSH[COLLECTOR_CLOSE]),
        flush_close_mean_us = us_mean(&W_FLUSH[COLLECTOR_CLOSE]),
        flush_close_p50_us = us_pct(&W_FLUSH[COLLECTOR_CLOSE], 0.5),
        flush_close_p99_us = us_pct(&W_FLUSH[COLLECTOR_CLOSE], 0.99),
        "receive_budget windows"
    );
}

/// Writes the whole budget out as `receive_budget ...` lines, tagged with
/// `occasion`. Existing `io_diag` and `sqlite_diag` lines are unchanged;
/// these are new lines under a new prefix, one fact per line, `key=value`
/// fields, so a summariser can match on the leading words.
pub fn emit_report(occasion: &str) {
    for site in lock_site_stats() {
        tracing::info!(
            occasion,
            site = %site.site,
            acquisitions = site.acquisitions,
            wait_ms = ms(site.wait_nanos),
            wait_max_ms = site.wait_max_nanos / 1_000_000,
            hold_ms = ms(site.hold_nanos),
            hold_max_ms = site.hold_max_nanos / 1_000_000,
            "receive_budget path_lock"
        );
    }
    if LOCK_WAIT_HIST.count() > 0 {
        tracing::info!(
            occasion,
            wait_p50_us = us(LOCK_WAIT_HIST.percentile(0.5)),
            wait_p99_us = us(LOCK_WAIT_HIST.percentile(0.99)),
            hold_p50_us = us(LOCK_HOLD_HIST.percentile(0.5)),
            hold_p99_us = us(LOCK_HOLD_HIST.percentile(0.99)),
            "receive_budget path_lock percentiles"
        );
    }
    // Every write transaction by call site, whether it ran as a `write` closure
    // (autocommit statements) or a `write_immediate` transaction, and whether or not
    // the split below is armed. A nested write inside another write's closure is not a
    // transaction of its own and is not counted here, so the sum of the sites is the
    // daemon's `write_transactions` total and `unattributed` is zero.
    let (write_transactions, _) = yadorilink_sqlite_runtime::writer_gate_stats::stats();
    let mut attributed = 0u64;
    for (site, calls, held_micros) in
        yadorilink_sqlite_runtime::writer_gate_stats::hold_site_stats()
    {
        attributed += calls;
        tracing::info!(
            occasion,
            site = %site,
            write_tx = calls,
            held_ms = (held_micros / 1000) as u64,
            "receive_budget write_tx_site"
        );
    }
    let batches = COMPLETION_BATCHES.load(Ordering::Relaxed);
    if batches > 0 {
        // The batched site's transaction count is its `write_tx_site` line
        // (`exact_materialized_commit`'s caller in the coordinator); this line says how
        // many files each of those transactions closed.
        let items = COMPLETION_ITEMS.load(Ordering::Relaxed);
        tracing::info!(
            occasion,
            batches,
            items,
            items_per_batch_mean = items as f64 / batches as f64,
            items_per_batch_p50 = COMPLETION_ITEMS_HIST.percentile(0.5),
            items_per_batch_p99 = COMPLETION_ITEMS_HIST.percentile(0.99),
            "receive_budget completion_batch"
        );
    }
    let batches = OPEN_BATCHES.load(Ordering::Relaxed);
    if batches > 0 {
        // The batched site's transaction count is its `write_tx_site` line
        // (`lanes.rs`, `open_content_writes`); this line says how many files'
        // writes each of those transactions opened.
        let items = OPEN_ITEMS.load(Ordering::Relaxed);
        tracing::info!(
            occasion,
            batches,
            items,
            items_per_batch_mean = items as f64 / batches as f64,
            items_per_batch_p50 = OPEN_ITEMS_HIST.percentile(0.5),
            items_per_batch_p99 = OPEN_ITEMS_HIST.percentile(0.99),
            "receive_budget open_batch"
        );
    }
    if W_WALL.count() > 0 {
        emit_windows(occasion);
    }
    if S_STEP[STAGES].count() > 0 {
        emit_stages(occasion);
    }
    if write_transactions > 0 {
        tracing::info!(
            occasion,
            write_transactions,
            attributed,
            unattributed = write_transactions.saturating_sub(attributed),
            "receive_budget write_tx_total"
        );
    }
    for site in yadorilink_sqlite_runtime::writer_gate_stats::split_site_stats() {
        tracing::info!(
            occasion,
            site = %site.site,
            calls = site.calls,
            body_ms = ms(site.body_nanos),
            commit_calls = site.commit_calls,
            commit_ms = ms(site.commit_nanos),
            commit_max_ms = site.commit_max_nanos / 1_000_000,
            "receive_budget sqlite_split"
        );
    }
    let (body_p50, commit_p50) =
        yadorilink_sqlite_runtime::writer_gate_stats::split_percentile_nanos(0.5);
    let (body_p99, commit_p99) =
        yadorilink_sqlite_runtime::writer_gate_stats::split_percentile_nanos(0.99);
    if body_p99 > 0 || commit_p99 > 0 {
        tracing::info!(
            occasion,
            body_p50_us = us(body_p50),
            body_p99_us = us(body_p99),
            commit_p50_us = us(commit_p50),
            commit_p99_us = us(commit_p99),
            "receive_budget sqlite_split percentiles"
        );
    }
    {
        use yadorilink_local_storage::io_diag::{distinct_parent_dirs, stat, Op};
        let dir_fsyncs = stat(Op::DirFsync);
        if dir_fsyncs.calls > 0 {
            tracing::info!(
                occasion,
                renames = stat(Op::Rename).calls,
                dir_fsyncs = dir_fsyncs.calls,
                distinct_parent_dirs = distinct_parent_dirs(),
                saturated = yadorilink_local_storage::io_diag::parent_dirs_saturated(),
                "receive_budget dir_fsync_coalescing"
            );
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
