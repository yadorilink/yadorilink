//! The Convergence Engine's scheduler loop: claims every currently-runnable
//! `projection_obligations` row (bumped by native admission, not enqueued by the
//! peer session, which does not schedule anything) and
//! drives them to completion on its own schedule, using the SAME
//! `reconcile_local_materialization_audit` / `reconcile_group_paths` /
//! `materialize` machinery this codebase already had and already tests --
//! this engine only changes *when*, *from where*, and *off which claim
//! source* that machinery runs, not what it does internally.
//!
//! `projection_obligations` has no in-flight state at all: claiming
//! (`dag_claim_runnable_obligations`) is a plain read, never a claim-and-mark
//! transition, so unlike the retired job-table scheduler this needs no
//! stale-active-processing reclaim at startup or on a same-process failure
//! between claim and completion -- there is nothing to go stale in the
//! first place. Completion is one atomic (G, E, durable-proof) decision per
//! path (`complete_one_obligation`/`complete_zero_work_obligation`), and
//! retry/backoff (`dag_mark_obligation_attempt_failed`/`dag_defer_
//! obligation_without_penalty`) is obligation-native, not modeled on a
//! separate job-state machine.
//!
//! Every SQLite call this file makes is synchronous and blocks the calling
//! thread (`yadorilink-sqlite-runtime` has no async surface at all, by
//! design), and several of them are per-path loops over a claimed batch of up
//! to `MAX_JOBS_PER_TICK_PER_GROUP` rows. This is a `spawn_restarting` async
//! task, so every one of them goes through `run_blocking_sweep_offloaded` --
//! the crate's shared `block_in_place`-when-multi-threaded guard -- rather
//! than running on the worker that polls the tick. `pool.rs`'s own contract
//! states the requirement outright: an async caller must do the wrapping on
//! its own side, because the SQLite layer has no runtime to yield to.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use futures_util::stream::{FuturesUnordered, StreamExt};

use crate::daemon_state::{run_blocking_sweep_offloaded, DaemonState};

use super::backoff::next_backoff;

/// Upper bound on how many jobs a single tick claims — keeps one tick's
/// worth of work bounded even if a large batch just enqueued many paths at
/// once; the rest are picked up on the next tick (which the same
/// `notify_materialization_wake` call that triggered this one leaves armed
/// to fire again immediately, since nothing here waits on the notify before
/// the next unconditional poll).
const MAX_JOBS_PER_TICK: u32 = 256;

/// Per-group share of `MAX_JOBS_PER_TICK` a single claim call will take —
/// without this, a group that keeps admitting many paths could crowd every
/// other group's jobs out of the claim entirely (a plain `LIMIT` has no
/// per-group fairness). Deliberately
/// smaller than `MAX_JOBS_PER_TICK` so at least a couple of distinct groups
/// are always represented in one tick's claimed batch, but generous enough
/// (half of `MAX_JOBS_PER_TICK`) to comfortably cover a single heavy
/// group's realistic per-tick job count without throttling its own
/// legitimate churn.
const MAX_JOBS_PER_TICK_PER_GROUP: u32 = 128;

/// Fallback poll interval when no `materialization_wake` fires — the
/// no-better-signal case the design accounts for; the primary path is the
/// event-driven wake fired by `enqueue_pending`'s caller.
const FALLBACK_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// How many groups' audits run concurrently. Without this, `run_once`
/// processing groups one at a time meant one group with many slow, blocked
/// (sole-source-unreachable) attempts could hold up every other group's
/// otherwise-instant materialization for the whole tick — message
/// *intake* is kept unblocked separately, but the engine itself would still have its
/// own head-of-line blocking across groups without this. Kept small (not
/// unbounded) since each group audit can itself spend real wall-clock time
/// in a block fetch; a handful of groups stalled on unreachable sources
/// should not turn into an unbounded fan-out of blocked network attempts.
const MAX_CONCURRENT_GROUP_AUDITS: usize = 4;

/// Bounded per-attempt path budget: how many paths one candidate attempt is
/// asked to resolve. Capping it, and rotating which bounded subset gets the
/// attempt each tick, bounds a single call's worst case while still giving
/// every path its turn across a few ticks. Used by
/// `process_group_via_obligations`.
///
/// The window was 8 while an attempt fetched its paths' blocks serially, and
/// a large backlog accumulated into 40+ second calls with no intermediate
/// progress. Fetching now overlaps across paths and the settle is
/// concurrent, so a wider window no longer lengthens an attempt in
/// proportion. Measured on a 15,000-file receive: 8 -> 126 files/s,
/// 16 -> 177, 32 -> 229, 64 -> 255-280, at the price of a longer window wall
/// time (mean about 200 ms, tail past 500 ms at 64). 32 is the default: most
/// of the gain, with a bounded tail. It matches the receive write
/// concurrency and the prefetch budget, so the window is not the binding
/// limit by default.
const MAX_PATHS_PER_RECONCILE_ATTEMPT: usize = 32;

/// Largest window any override can select. A claim takes at most
/// `MAX_JOBS_PER_TICK_PER_GROUP` jobs per group; a window covering the whole
/// claim leaves no deferred work, so the engine sleeps until its fallback
/// poll after every window (measured: 128-path window = 92 files/s against
/// 255 at 64). Half the claim cap keeps deferred work on hand.
const MAX_RECONCILE_PATHS_OVERRIDE: usize = (MAX_JOBS_PER_TICK_PER_GROUP / 2) as usize;

const _: () = assert!(MAX_PATHS_PER_RECONCILE_ATTEMPT <= MAX_RECONCILE_PATHS_OVERRIDE);

/// `MAX_PATHS_PER_RECONCILE_ATTEMPT`, with a diagnostic override.
///
/// This window is what a receive-side measurement runs into once the block
/// store's commit pooling is working: a tiny-file corpus is one block per
/// file, so a reconciliation pass carrying at most N paths can pool at most
/// N blocks into one durability barrier. Measured at the default, 2001
/// received blocks took 253 barriers -- 7.909 blocks each, against a window
/// of 8. The pool was saturating its input, and the ceiling had moved out
/// of storage and into this constant.
///
/// Raising it is not obviously free, which is exactly why it is a knob to
/// sweep rather than a number to change: a bigger window means a longer
/// single attempt (this constant exists because attempts were accumulating
/// into 40+ second calls with no intermediate progress), a larger commit
/// transaction, and a coarser rotation, which is a fairness question as
/// much as a throughput one.
///
/// Read fresh per call rather than cached, matching
/// the block fetch concurrency's own seam: this runs once per group per tick,
/// nowhere near hot, and a sweep can then vary it run-to-run with no
/// rebuild. Invalid or absent falls back to the compiled default, so an
/// unset environment behaves exactly as before this existed.
///
/// An override is clamped to `MAX_RECONCILE_PATHS_OVERRIDE`.
///
/// The unit tests in this module deliberately keep using the `const`: they
/// pin the shipped default's behaviour, and should not start tracking
/// whatever a sweep happens to have exported.
fn max_paths_per_reconcile_attempt(tuning: &crate::engine_tuning::EngineTuning) -> usize {
    tuning.reconcile_paths_per_attempt
}

/// The parsing half of [`max_paths_per_reconcile_attempt`], split out so it
/// can be tested without touching the process environment.
///
/// That split is not stylistic. Other tests in this binary drive
/// `process_group_via_obligations`, which reads this window; a test that
/// set the real variable would be visible to whichever of them happened to
/// be running concurrently, and would make THEM flaky rather than failing
/// itself. A pure function has no such reach.
pub(crate) fn parse_reconcile_paths(raw: Option<&str>) -> usize {
    raw.and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .map_or(MAX_PATHS_PER_RECONCILE_ATTEMPT, |n| n.min(MAX_RECONCILE_PATHS_OVERRIDE))
}

fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// The Convergence Engine's own per-group rotation cursors, advanced only by
/// `process_group_via_obligations`, once per call for a group.
///
/// Both are keyed by `group_id` and hold an offset the caller always applies
/// modulo the current count, so a stale or out-of-range entry is harmless.
/// Neither is ever cleared: an entry survives link stop/start and a
/// panic-restart of the scheduler loop, and resets only with a new
/// `DaemonState`. That lifetime is why this is owned by [`ConvergenceEngine`]
/// and not by `run`: `spawn_restarting` rebuilds `run` on every panic, while
/// the engine itself is built once per `DaemonState` (in
/// `maintenance_coordinator::start`) and handed to every restart. The
/// `*_for_test` drivers take the engine too, so calls through one engine
/// instance share these cursors with each other; a test's own engine does
/// not share them with the background scheduler's.
///
/// Kept separate from `MaterializationRepairJob`'s peer rotation: the two run
/// on independent schedules (event-driven/~1s vs the 90s backstop) and
/// rotating them together would couple cadences that have no reason to be
/// coupled.
struct ObligationRotationCursors {
    /// group_id -> next candidate offset for this engine's per-group peer
    /// selection.
    peer: std::sync::Mutex<HashMap<String, usize>>,
    /// group_id -> next path-budget offset for this engine's per-call path cap
    /// (`MAX_PATHS_PER_RECONCILE_ATTEMPT`): a single candidate attempt handed
    /// the ENTIRE claimed batch for a group (up to
    /// `MAX_JOBS_PER_TICK_PER_GROUP`, 128) processes every path's blocks
    /// fully serially, and a large backlog of not-yet-referenced/
    /// genuinely-missing blocks can accumulate into a 40+ second single
    /// call with no visible progress. Rotating which bounded subset of
    /// `remaining` gets attempted each tick (this cursor) is what lets every
    /// path eventually get its turn without needing an unboundedly large
    /// single attempt.
    path_budget: std::sync::Mutex<HashMap<String, usize>>,
}

impl ObligationRotationCursors {
    fn new() -> Self {
        Self {
            peer: std::sync::Mutex::new(HashMap::new()),
            path_budget: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// The stored peer-rotation offset for `group_id` (0 if none yet), taken
    /// modulo `candidate_count`. Panics on a zero `candidate_count`, exactly
    /// like the inline `%` it replaces; the caller has already returned when
    /// there are no candidates.
    fn peer_start(&self, group_id: &str, candidate_count: usize) -> usize {
        let cursors = self.peer.lock().unwrap_or_else(|p| p.into_inner());
        cursors.get(group_id).copied().unwrap_or(0) % candidate_count
    }

    fn set_peer_next(&self, group_id: &str, next: usize) {
        let mut cursors = self.peer.lock().unwrap_or_else(|p| p.into_inner());
        cursors.insert(group_id.to_owned(), next);
    }

    /// The stored path-budget offset for `group_id` (0 if none yet), taken
    /// modulo `path_count` (treated as at least 1).
    fn path_budget_start(&self, group_id: &str, path_count: usize) -> usize {
        let cursors = self.path_budget.lock().unwrap_or_else(|p| p.into_inner());
        cursors.get(group_id).copied().unwrap_or(0) % path_count.max(1)
    }

    fn set_path_budget_next(&self, group_id: &str, next: usize) {
        let mut cursors = self.path_budget.lock().unwrap_or_else(|p| p.into_inner());
        cursors.insert(group_id.to_owned(), next);
    }
}

/// The Convergence Engine: the `DaemonState` its scheduler drives, plus the
/// engine's own cross-tick rotation cursors (see
/// [`ObligationRotationCursors`] for their lifetime). Built once per
/// `DaemonState` by `maintenance_coordinator::start`, before
/// `spawn_restarting`, so a panic-restart of `run` reuses the same engine and
/// its cursors.
pub struct ConvergenceEngine {
    state: Arc<DaemonState>,
    obligation_rotation: ObligationRotationCursors,
}

impl ConvergenceEngine {
    pub fn new(state: Arc<DaemonState>) -> Self {
        Self { state, obligation_rotation: ObligationRotationCursors::new() }
    }

    pub(crate) fn state(&self) -> &Arc<DaemonState> {
        &self.state
    }
}

/// Pure rotation math for `process_group_via_obligations`'s peer
/// selection, pulled out so it can be unit-tested directly without a real
/// multi-device harness (this pure core of peer failover is cheap to
/// verify in isolation). Returns the candidate indices to try this call, in order,
/// starting at `cursor % candidate_count` and wrapping around, capped at
/// `max_attempts` (or `candidate_count`, whichever is smaller). Returns an
/// empty `Vec` if there are no candidates at all.
fn rotation_indices(candidate_count: usize, cursor: usize, max_attempts: usize) -> Vec<usize> {
    if candidate_count == 0 {
        return Vec::new();
    }
    let start = cursor % candidate_count;
    let attempts = candidate_count.min(max_attempts);
    (0..attempts).map(|offset| (start + offset) % candidate_count).collect()
}

/// `rotation_indices` with an optional origin-first preference: the
/// candidate at `origin` (the peer that authored the changes triggering
/// this tick's budgeted jobs) is tried FIRST — it is the peer most likely
/// to actually hold the block content those jobs need, since every other
/// candidate may have admitted the change history without hydrating the
/// content yet — while the total attempt budget stays exactly
/// `max_attempts`. If the origin already sits inside this tick's rotation
/// window it is moved to the front; otherwise it is prepended and the
/// window's last slot is dropped to make room. The caller must NOT advance
/// the rotation cursor by the raw tried count afterwards — see
/// `process_group_via_obligations`'s cursor-advance comment for the
/// prefix-consumption rule that keeps a rotated-out-but-untried candidate
/// from being skipped.
fn origin_first_indices(
    candidate_count: usize,
    cursor: usize,
    max_attempts: usize,
    origin: Option<usize>,
) -> Vec<usize> {
    let mut indices = rotation_indices(candidate_count, cursor, max_attempts);
    let Some(origin) = origin else { return indices };
    if origin >= candidate_count || max_attempts == 0 {
        return indices;
    }
    match indices.iter().position(|&i| i == origin) {
        Some(pos) => {
            indices.remove(pos);
        }
        None => {
            // Not in the window — make room so the budget is unchanged.
            indices.pop();
        }
    }
    indices.insert(0, origin);
    indices
}

/// The author preferred as this tick's fetch origin: the device that
/// authored the largest share of the budgeted jobs' triggering changes
/// (deterministic tie-break: lexicographically smallest device id).
/// `None` when no author can be determined at all.
fn majority_author(authors: impl IntoIterator<Item = String>) -> Option<String> {
    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    for author in authors {
        *tally.entry(author).or_default() += 1;
    }
    tally.into_iter().max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0))).map(|(author, _)| author)
}

/// Resolves the origin-first fetch preference from the CURRENT desired-state
/// winner rather than a stored triggering change: `ClaimedObligation` carries
/// no `version_hash` at all (by
/// design -- desired state is always recomputed fresh, never carried from
/// claim time), so there is no historical "which change created this
/// obligation" to look up even heuristically. An obligation represents
/// current desired state, not "what invalidated it first," so deriving the
/// fetch-source preference from the path's current resolved winner is the
/// more accurate source anyway, not merely a workaround for the missing
/// field: `resolve_path_heads`'s own winner is exactly the author whose
/// content this attempt is actually trying to materialize, correct even
/// across a divergent-branch/conflict-copy resolution where "the change
/// that first bumped the obligation's generation" could name a losing
/// branch's author instead. `session` only needs to be ABLE to resolve native
/// state (`diagnostic_path_heads`'s own doc comment: "identical result
/// regardless of which peer session it's called through — this reads
/// purely local state"), so the caller may pass whichever session it
/// already has in hand rather than constructing a new one for this alone.
///
/// Resolves each path's heads directly rather than through a shared,
/// per-tick memo of `combined_heads` results. Such a memo was tried, and
/// removed: it only paid off while a single `combined_heads` call was
/// itself expensive, and resolving a path's live heads is now an indexed
/// lookup rather than an ancestry walk over the group's history.
fn origin_candidate_index_for_obligations<S>(
    local: &crate::local_convergence::LocalConvergenceExecutor,
    group_id: &str,
    budget: &BTreeSet<String>,
    candidates: &[(String, S)],
) -> Option<usize> {
    let authors =
        budget.iter().filter_map(|path| match local.native_planned_node(group_id, path).ok()? {
            Some(yadorilink_replica_domain::native_plan::NativePlannedNode::Entry {
                head, ..
            }) => Some(head.dot().author.device.0.clone()),
            _ => None,
        });
    let author = majority_author(authors)?;
    candidates.iter().position(|(device_id, _)| *device_id == author)
}

/// Runs the Convergence Engine's scheduler loop forever. Intended to be
/// spawned via `supervise::spawn_restarting` (never `spawn_logged`) — unlike
/// `DaemonState`'s other periodic tasks, a silent stop here does not just
/// skip one sweep, it stops all materialization for every group for the
/// rest of the daemon's life, which is a strictly worse failure mode.
///
/// No startup recovery step runs before the loop starts: `run_once`'s claim
/// (`dag_claim_runnable_obligations`) is a plain read, never a claim-and-mark
/// transition, so there is no in-flight state a crash could leave stale for
/// this to reclaim in the first place.
pub async fn run(engine: Arc<ConvergenceEngine>) {
    let state = &engine.state;
    // Diagnostic-only tick counter -- proves directly whether this loop is still iterating at all (as
    // opposed to inferring it from whether `run_once` happened to find any
    // claimable work) and which branch woke it each time.
    let mut tick: u64 = 0;
    loop {
        let tick_start = std::time::Instant::now();
        let outcome = run_once(&engine).await;
        let run_once_wall_ms = tick_start.elapsed().as_millis() as u64;
        tick += 1;
        // Work-conserving: an immediately-runnable backlog must not wait
        // out a full tick interval (or however long until the next
        // `Notify`) just because 8 paths already got their turn this
        // tick. `MaterializationWake` is a coarse "something changed"
        // signal, not a work-count -- draining is decided here, from
        // `run_once`'s own aggregated outcome, not from that signal.
        // `yield_now` (not a bare `continue`, and never a sleep) hands
        // the executor a chance to run other ready tasks between ticks
        // without giving up this loop's own turn for any real duration,
        // so a large healthy backlog drains as fast as each tick's own
        // real work allows, not throttled by an unrelated fixed interval.
        if outcome.immediate_backlog {
            tracing::debug!(
                local_device_id = %state.device_id,
                tick,
                run_once_wall_ms,
                "engine loop draining an immediate backlog without waiting"
            );
            tokio::task::yield_now().await;
            // Per-tick wall time at `debug`: the one engine-throughput number
            // a benchmark run needs, enabled only by an explicit filter.
            tracing::debug!(local_device_id = %state.device_id, tick, run_once_wall_ms, "convergence tick end");
            continue;
        }
        tracing::debug!(local_device_id = %state.device_id, tick, run_once_wall_ms, "engine loop about to wait for next wake");
        let select_started = std::time::Instant::now();
        tokio::select! {
            _ = state.replica_coordinator.materialization_wake().materialization_wake_notified() => {
                let select_ms = select_started.elapsed().as_millis() as u64;
                tracing::debug!(local_device_id = %state.device_id, tick, select_ms, "engine loop woken by wake_notified");
            }
            _ = tokio::time::sleep(FALLBACK_POLL_INTERVAL) => {
                let select_ms = select_started.elapsed().as_millis() as u64;
                tracing::debug!(local_device_id = %state.device_id, tick, select_ms, "engine loop woken by fallback poll");
            }
        }
        tracing::debug!(local_device_id = %state.device_id, tick, run_once_wall_ms, "convergence tick end");
    }
}

/// Whether `run`'s own scheduler loop should immediately drive another
/// `run_once` tick instead of sleeping/waiting on the wake `Notify` --
/// see `run`'s own doc comment for why "8 processed, sleep regardless of
/// what's left" was a real work-conserving-scheduler bug, not merely a
/// throughput tuning question.
struct RunOnceOutcome {
    immediate_backlog: bool,
}

/// One scheduler tick: claims every currently-runnable `projection_
/// obligations` row, groups by `group_id`, and drives up to
/// `MAX_CONCURRENT_GROUP_AUDITS` groups' worth of `process_group_via_
/// obligations` concurrently — one stalled group (e.g. every path waiting
/// on an unreachable sole source) must not hold up another group whose
/// obligations could complete instantly. `projection_obligations` is the
/// only claim source.
async fn run_once(engine: &ConvergenceEngine) -> RunOnceOutcome {
    let state = &engine.state;
    // Per-tick timing, as a `debug!`-level diagnostic (it fires on every
    // tick -- too noisy for `warn!`, but worth keeping at `debug!` since
    // it distinguishes "run_once is stuck inside an
    // already-started tick" from "ticks keep completing but claim returns
    // zero", the two fundamentally different ways obligations_claimed can
    // freeze for tens of seconds.
    let run_once_started = std::time::Instant::now();
    let now = now_unix_nanos();
    // One read claiming up to `MAX_JOBS_PER_TICK` rows -- see
    // `claim_runnable_obligations`'s own doc comment for why this needs no
    // stale-active-processing reclaim the way the legacy job claim did:
    // there is no in-flight state here to go stale in the first place.
    let claim_started = std::time::Instant::now();
    let runnable = match run_blocking_sweep_offloaded(|| {
        state.replica_coordinator.sqlite().dag_claim_runnable_obligations(
            now,
            MAX_JOBS_PER_TICK_PER_GROUP,
            MAX_JOBS_PER_TICK,
        )
    }) {
        Ok(obligations) => obligations,
        Err(e) => {
            tracing::warn!(error = %e, "convergence engine failed to claim runnable obligations");
            return RunOnceOutcome { immediate_backlog: false };
        }
    };
    tracing::debug!(
        claim_ms = claim_started.elapsed().as_millis() as u64,
        claimed_count = runnable.len(),
        "dag_claim_runnable_obligations returned"
    );
    if runnable.is_empty() {
        tracing::debug!(
            run_once_ms = run_once_started.elapsed().as_millis() as u64,
            "run_once returning (nothing runnable)"
        );
        return RunOnceOutcome { immediate_backlog: false };
    }
    // This tick's claim itself hit the global cap -- there may be MORE
    // runnable obligations this call never even fetched, regardless of how
    // any individual group's own attempt turns out. `process_group_via_
    // obligations`'s own `deferred_runnable` only ever reasons about the
    // batch it was actually handed, so this is the one signal that has to
    // be captured at this level instead.
    let claim_hit_cap = runnable.len() as u32 >= MAX_JOBS_PER_TICK;

    let mut obligations_by_group: HashMap<
        String,
        Vec<yadorilink_sync_sqlite::projection_obligations::ClaimedObligation>,
    > = HashMap::new();
    for obligation in runnable {
        obligations_by_group.entry(obligation.group_id.clone()).or_default().push(obligation);
    }
    // Diagnostic-only: visibility into exactly which (group, path) pairs
    // `claim_runnable_obligations` actually selected this tick -- without this, a path that silently
    // stops being claimed (rather than being completed/backed-off/deferred)
    // is invisible.
    for (group_id, obligations) in &obligations_by_group {
        tracing::debug!(
            local_device_id = %state.device_id,
            group_id = %group_id,
            claimed_count = obligations.len(),
            claimed_paths = ?obligations.iter().map(|o| o.path.as_str()).collect::<Vec<_>>(),
            "claimed obligations this tick"
        );
    }
    let mut group_ids: Vec<String> = obligations_by_group.keys().cloned().collect();
    group_ids.sort();

    let mut any_group_immediate_backlog = false;
    let mut next_idx = 0usize;
    let mut in_flight = FuturesUnordered::new();
    while next_idx < group_ids.len() && in_flight.len() < MAX_CONCURRENT_GROUP_AUDITS {
        let group_id = group_ids[next_idx].clone();
        let obligations = obligations_by_group.remove(&group_id).unwrap_or_default();
        in_flight.push(process_group_via_obligations(engine, group_id, obligations, None));
        next_idx += 1;
    }
    while let Some(outcome) = in_flight.next().await {
        if outcome.audit_healthy && outcome.deferred_runnable {
            any_group_immediate_backlog = true;
        }
        if next_idx < group_ids.len() {
            let group_id = group_ids[next_idx].clone();
            let obligations = obligations_by_group.remove(&group_id).unwrap_or_default();
            in_flight.push(process_group_via_obligations(engine, group_id, obligations, None));
            next_idx += 1;
        }
    }
    tracing::debug!(
        run_once_ms = run_once_started.elapsed().as_millis() as u64,
        "run_once returning (groups processed)"
    );
    RunOnceOutcome { immediate_backlog: any_group_immediate_backlog || claim_hit_cap }
}

/// Test-only: drives exactly one scheduler tick and reports whether `run`'s
/// own loop would immediately continue draining afterward (see
/// `RunOnceOutcome`'s own doc comment) -- `run_once` itself is private (this
/// whole module is `mod engine_impl`, not reachable from outside
/// `yadorilink-daemon::convergence` at all), so an external integration
/// test needs a minimal seam to drive the scheduler deterministically one
/// tick at a time rather than only through `run`'s own infinite loop. Only
/// the boolean an external caller can actually act on is exposed --
/// `RunOnceOutcome`/`ProcessGroupOutcome` stay private, matching this
/// crate's `test-support` feature's existing "expose the minimum a test
/// needs, not the internals" convention (see `Cargo.toml`'s own doc
/// comment on that feature).
#[cfg(any(test, feature = "test-support"))]
pub async fn run_once_for_test(engine: &ConvergenceEngine) -> bool {
    run_once(engine).await.immediate_backlog
}

/// Drives every claimed job in one group to a conclusion: rotating through
/// every currently-connected, group-sharing peer session in round-robin
/// order (a per-group `ObligationRotationCursors` cursor, advanced every call — the
/// same shape as `MaterializationRepairJob`'s own peer rotation,
/// but this engine's own, since the two run on independent schedules)
/// rather than always picking whichever session happens to be first in
/// `candidate_sessions`'s `HashMap` iteration order. A block a peer doesn't
/// have would otherwise be retried against that SAME unhelpful peer
/// indefinitely — `ensure_blocks_present`'s block fetch is scoped to the one
/// session the audit runs through, so which session gets picked directly
/// determines which peer's content is actually reachable this attempt.
///
/// Tries the next candidate only for whatever paths are still outstanding
/// after the previous one's attempt — a `Present`-branch content path is
/// finished the moment ANY candidate's clean audit shows it's no longer
/// unapplied; no need to keep trying further peers for paths already
/// resolved.
///
/// What one `process_group_via_obligations` call actually accomplished, for `run_once`'s
/// own work-conserving decision (see [`RunOnceOutcome`]): whether this
/// group's own audit mechanism was trustworthy at all this tick, and
/// whether this tick's claim for this group held more runnable jobs than
/// one attempt's budget could cover. Neither field alone answers "should
/// the scheduler keep draining without sleeping":
///
/// - `deferred_runnable` without `audit_healthy` means every candidate
///   this tick was unreachable, or every attempt raced a concurrent
///   admission/guard contention -- a systemic problem a DIFFERENT budget
///   window is unlikely to escape either, so immediately retrying would
///   just burn CPU re-hitting the same failure instead of the same dead
///   *paths* -- falling back to the ordinary wait/retry cadence is safer.
/// - `audit_healthy` without `deferred_runnable` means this group's
///   entire runnable backlog already fit inside this tick's budget --
///   nothing left to immediately drain FOR THIS GROUP (though another
///   group might still have its own backlog), regardless of whether this
///   specific window's content happened to resolve yet.
/// - `audit_healthy` WITH `deferred_runnable` is the case worth calling
///   out explicitly: even if every one of THIS window's budgeted paths
///   individually failed to resolve (still-fetching content, say), the
///   budget cursor always rotates forward regardless of outcome (see its
///   own comment below) -- so the NEXT tick's window is guaranteed to be
///   a genuinely different, not-yet-attempted set of paths, never a
///   repeat of this tick's own failure. Gating immediate continuation on
///   "did THIS window resolve something" (an earlier version of this
///   fix did) reintroduced exactly the bug this fix targets for a mixed
///   backlog: a healthy peer with some content ready and some not yet
///   fetched would sleep a full tick interval before ever reaching the
///   ready paths, just because they happened to land in a later window
///   than an unready one.
struct ProcessGroupOutcome {
    audit_healthy: bool,
    deferred_runnable: bool,
}

/// The test-only rendezvous at a claimed path's completion. It now lives
/// with the claims it rides on, because the eager content write closes its
/// obligation inside its own commit; see its own doc comment.
pub use crate::local_convergence::obligation_claims::BeforeCompletionHook;

/// Closes one path's claimed obligation against the evidence
/// `reconcile_paths_directly` just settled it with, publishing first for an
/// exact outcome and using the exact-outcome or non-exact-outcome
/// compound completion as appropriate. Any failure at any step (a lost
/// publish CAS race, a publish error, a lost completion CAS race) simply
/// leaves the obligation outstanding for a later claim to re-resolve from
/// scratch — never treated as this path's final word: a rejected
/// publication must not close its obligation.
///
/// Not reached for a path whose lane already decided its obligation in the
/// commit that published its proof (a received file's content write): the
/// caller skips those.
// Each parameter is independently meaningful obligation-completion context;
// grouping into a params struct is out of scope for a lint cleanup.
#[allow(clippy::too_many_arguments)]
async fn complete_one_obligation(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
    claimed_generation: i64,
    claimed_incarnation: i64,
    evidence: &crate::local_convergence::types::SettlementEvidence,
    hooks: Option<&Arc<BeforeCompletionHook>>,
) {
    use crate::local_convergence::types::SettlementEvidence;
    use yadorilink_sync_sqlite::projection_obligations::NonExactProofKind;

    if let Some((exact_state, expected_mutation_generation)) = evidence.as_exact_actual_state() {
        let group_id_owned = group_id.to_string();
        let path_owned = path.to_string();
        let exact_state_for_publish = exact_state.clone();
        // The proof is published after whatever physical work it is
        // about, so the root is re-verified inside the publishing
        // transaction rather than trusted from before that work.
        let lease = match state.local_convergence().root_lease_for(&group_id_owned) {
            Ok(lease) => lease,
            Err(error) => {
                tracing::warn!(
                    group_id,
                    path,
                    %error,
                    "no live root authority to publish this settlement under; leaving the \
                     obligation outstanding rather than publishing unverified"
                );
                return;
            }
        };
        let published = run_blocking_sweep_offloaded(|| {
            let operation = lease.begin_operation()?;
            state.replica_coordinator.dag_publish_materialized_generation_if_fence_current(
                &group_id_owned,
                &path_owned,
                exact_state_for_publish,
                expected_mutation_generation,
                &operation.permit(),
            )
        });
        match published {
            Ok(true) => {}
            Ok(false) => {
                tracing::debug!(
                    group_id,
                    path,
                    "obligation-driven publish CAS lost the race; leaving obligation outstanding \
                     for re-resolution"
                );
                return;
            }
            Err(e) => {
                tracing::warn!(
                    group_id,
                    path,
                    error = %e,
                    "obligation-driven publish failed; leaving obligation outstanding"
                );
                return;
            }
        }
        if let Some(hook) = hooks {
            hook.pause().await;
        }
        let (group_id_owned, path_owned) = (group_id.to_string(), path.to_string());
        let closed = run_blocking_sweep_offloaded(|| {
            state.replica_coordinator.complete_obligation_exact(
                &group_id_owned,
                &path_owned,
                claimed_generation,
                claimed_incarnation,
                &exact_state,
            )
        });
        match closed {
            Ok(true) => {
                note_obligation_completed(state, group_id);
                // Wake the hazard recheck: a copy this attempt just made durable
                // could be exactly the sibling change that clears some held
                // path's hazard.
                state.replica_coordinator.hazard_recheck_wake().mark_dirty(group_id);
            }
            Ok(false) => {
                tracing::debug!(
                    group_id,
                    path,
                    "obligation-driven completion CAS did not close; obligation left outstanding \
                     for re-resolution"
                );
            }
            Err(e) => tracing::warn!(
                group_id,
                path,
                error = %e,
                "obligation-driven completion failed; obligation left outstanding"
            ),
        }
    } else {
        let kind = match evidence {
            SettlementEvidence::PolicyRemote => NonExactProofKind::ContentNotOwed,
            SettlementEvidence::HazardHeld { .. } => NonExactProofKind::HazardHeld,
            SettlementEvidence::IgnoreExcluded => NonExactProofKind::IgnoreExcluded,
            SettlementEvidence::Retained { .. } => NonExactProofKind::RetainedDirectory,
            SettlementEvidence::ExactObject { .. }
            | SettlementEvidence::ExactAbsent { .. }
            | SettlementEvidence::StructuralDirectory { .. } => {
                unreachable!("as_exact_actual_state already handled every exact variant above")
            }
        };
        let (group_id_owned, path_owned) = (group_id.to_string(), path.to_string());
        let closed = run_blocking_sweep_offloaded(|| {
            state.replica_coordinator.complete_obligation_non_exact(
                &group_id_owned,
                &path_owned,
                claimed_generation,
                claimed_incarnation,
                kind,
            )
        });
        match closed {
            Ok(true) => {
                state.replica_coordinator.hazard_recheck_wake().mark_dirty(group_id);
            }
            Ok(false) => {
                tracing::debug!(
                    group_id,
                    path,
                    "obligation-driven non-exact completion CAS did not close; obligation left \
                     outstanding for re-resolution"
                );
            }
            Err(e) => tracing::warn!(
                group_id,
                path,
                error = %e,
                "obligation-driven non-exact completion failed; obligation left outstanding"
            ),
        }
    }
}

/// Closes one path's claimed obligation against zero-work-close evidence
/// (`PeerSyncSession::zero_work_settlement_for_path`) -- unlike
/// `complete_one_obligation`, this never publishes a new object: the
/// evidence already describes a proof row that is current right now (the
/// zero-work pre-check confirmed this itself, immediately before returning
/// it). The close is exactly the same compound exact-outcome completion
/// statement a real materialization would use, re-establishing currency at
/// the actual moment of close -- the pre-check's own read and disk
/// revalidation only ever authorized SKIPPING physical work, never the
/// close itself. On success the same transaction re-anchors that proof on
/// the current frontier, since the next local edit of the path is
/// parented on it (`ReplicaCoordinator::complete_zero_work_obligation`).
async fn complete_zero_work_obligation(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
    claimed_generation: i64,
    claimed_incarnation: i64,
    evidence: &crate::local_convergence::types::SettlementEvidence,
    hooks: Option<&Arc<BeforeCompletionHook>>,
) {
    let Some((exact_state, _mutation_generation)) = evidence.as_exact_actual_state() else {
        // The zero-work pre-check only ever produces exact evidence (see
        // its own doc comment) -- unreachable in practice, but fail safe
        // rather than panic if that ever changes.
        return;
    };
    if let Some(hook) = hooks {
        hook.pause().await;
    }
    let (group_id_owned, path_owned) = (group_id.to_string(), path.to_string());
    let closed = run_blocking_sweep_offloaded(|| {
        state.replica_coordinator.complete_zero_work_obligation(
            &group_id_owned,
            &path_owned,
            claimed_generation,
            claimed_incarnation,
            &exact_state,
        )
    });
    match closed {
        // Deliberately no retirement/hazard-recheck wake here, unlike
        // `complete_one_obligation`'s exact-outcome arm: a zero-work close
        // means the path already matched its desired state BEFORE this
        // attempt ran, so nothing physically changed just now for a
        // sibling to react to -- whatever originally wrote this content
        // already woke retirement/hazard at that time, through its own
        // (exact-outcome) completion.
        Ok(true) => note_obligation_completed(state, group_id),
        Ok(false) => tracing::debug!(
            group_id,
            path,
            "zero-work completion CAS did not close; obligation left outstanding for \
             re-resolution -- an independent mutator raced this decision"
        ),
        Err(e) => tracing::warn!(
            group_id,
            path,
            error = %e,
            "zero-work completion failed; obligation left outstanding"
        ),
    }
}

/// A [`yadorilink_peer_session::convergence_driver::ConvergenceDriver`] for
/// a group no peer shares right now: every block this device does not hold
/// simply did not arrive, so a pass through it materializes exactly what
/// local content allows.
struct LocalContentOnly {
    device_id: String,
}

impl yadorilink_peer_session::convergence_driver::ConvergenceDriver for LocalContentOnly {
    fn peer_device_id(&self) -> &str {
        &self.device_id
    }

    fn fetch_block<'a>(
        &'a self,
        _group_id: &'a str,
        _file_path: &'a str,
        _block: &'a yadorilink_replica_domain::file::BlockInfo,
        _timeout: Duration,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        yadorilink_peer_session::convergence_driver::FetchedBlock,
                        yadorilink_peer_session::PeerSessionError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async {
            Ok(yadorilink_peer_session::convergence_driver::FetchedBlock {
                outcome: yadorilink_peer_session::convergence_driver::BlockFetch::Missing,
                wire_wait: Duration::ZERO,
            })
        })
    }
}

/// The local folder of `group_id`'s live link. A link that is not live (terminal, lost
/// ownership) has none, so the disk-space wait is never touched for it.
fn live_link_path(state: &Arc<DaemonState>, group_id: &str) -> Option<String> {
    match state.replica_coordinator.link_gate_for_group(group_id) {
        Ok(yadorilink_replica_domain::session_state::LinkGate::Live { local_path, .. }) => {
            Some(local_path)
        }
        _ => None,
    }
}

/// Shows the folder as waiting for disk space while an attempt is refused for lack of it. The
/// wait ends on the real transitions, not on the next unrelated sync: an attempt that was not
/// refused and settled something (the refused write got through, or was superseded), and a path's
/// obligation completing ([`note_obligation_completed`]). Every clear is confirmed on the
/// volume, so one write at the edge never flaps the status.
pub(super) fn track_disk_space_wait(
    state: &Arc<DaemonState>,
    group_id: &str,
    attempt: &crate::local_convergence::types::ProjectionAttempt,
) {
    let Some(local_path) = live_link_path(state, group_id) else { return };
    if let Some(wait) = &attempt.disk_pressure {
        state.mark_link_waiting_for_disk_space(
            &local_path,
            crate::link_registry::waiting_for_disk_space_reason(
                &wait.volume,
                wait.available_bytes,
                wait.required_free_bytes,
            ),
        );
    } else if !attempt.settled.is_empty() {
        // Settling something is not proof the space is back: confirm on the volume. Paths still
        // in `retry` are retried for their own reasons; had they been refused for space, the
        // attempt would carry `disk_pressure`.
        state.clear_link_degraded_if_space_recovered(&local_path);
    }
}

/// A path's obligation closed: whatever was waiting for space to place it is over. Confirmed on
/// the volume like every other clear.
pub(super) fn note_obligation_completed(state: &Arc<DaemonState>, group_id: &str) {
    if let Some(local_path) = live_link_path(state, group_id) {
        state.clear_link_degraded_if_space_recovered(&local_path);
    }
}

/// Completes the obligation of every path `attempt` fully resolved and
/// removes those paths from `remaining`.
#[allow(clippy::too_many_arguments)]
async fn complete_settled_paths(
    state: &Arc<DaemonState>,
    group_id: &str,
    attempt: &crate::local_convergence::types::ProjectionAttempt,
    lane_claims: &crate::local_convergence::obligation_claims::ObligationClaims,
    claimed_generation: &BTreeMap<String, i64>,
    claimed_incarnation: &BTreeMap<String, i64>,
    hooks: Option<&Arc<BeforeCompletionHook>>,
    remaining: &mut BTreeSet<String>,
) {
    remaining.retain(|p| !attempt.path_fully_resolved(p));
    track_disk_space_wait(state, group_id, attempt);
    for (path, evidence) in attempt.settled_with_evidence() {
        // Already decided under its claim, in the same commit
        // as its proof: closed, or left open because the claim
        // had been overtaken. Completing it again could only
        // repeat that answer.
        if lane_claims.decided_in_lane(path) {
            continue;
        }
        // Settled is not done: a conflict copy derived from this
        // path that still needs another attempt has no
        // obligation of its own, so closing this one would leave
        // the copy with nothing to retry it.
        if !attempt.path_fully_resolved(path) {
            continue;
        }
        let Some(&claimed_g) = claimed_generation.get(path) else { continue };
        let Some(&claimed_i) = claimed_incarnation.get(path) else { continue };
        complete_one_obligation(state, group_id, path, claimed_g, claimed_i, evidence, hooks).await;
    }
}

/// A group no peer shares right now: materializes what local content
/// allows, then backs off every path still outstanding.
#[allow(clippy::too_many_arguments)]
async fn process_without_peers(
    state: &Arc<DaemonState>,
    group_id: &str,
    windowed_budget: BTreeSet<String>,
    lane_claims: &crate::local_convergence::obligation_claims::ObligationClaims,
    claimed_generation: &BTreeMap<String, i64>,
    claimed_incarnation: &BTreeMap<String, i64>,
    claimed_attempt: &BTreeMap<String, i64>,
    hooks: Option<&Arc<BeforeCompletionHook>>,
) {
    // No peer, but what a path needs may already be here: content this
    // device authored itself from history it holds (a folder rewind, a
    // version restore placed by projection), or blocks it kept. That is
    // materialized now, from local blocks only; it does not wait for a
    // peer that has nothing to add. Paths that do need a block from
    // elsewhere stay outstanding below.
    let mut remaining = windowed_budget;
    let local_only: Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver> =
        Arc::new(LocalContentOnly { device_id: state.device_id.clone() });
    match state
        .local_convergence()
        .reconcile_claimed_paths(&local_only, group_id, remaining.clone(), lane_claims)
        .await
    {
        Ok(Some(attempt)) => {
            complete_settled_paths(
                state,
                group_id,
                &attempt,
                lane_claims,
                claimed_generation,
                claimed_incarnation,
                hooks,
                &mut remaining,
            )
            .await;
        }
        Ok(None) => {}
        Err(e) => tracing::warn!(
            group_id = %group_id,
            error = %e,
            "local-content reconciliation failed for this group"
        ),
    }
    // Unlike a guard-contention/raced-read tick (see the no-penalty
    // defer below), "no peer shares this group right now" is a stable
    // condition, not a transient blip -- it stays true every tick until
    // one connects. Applying real, growing backoff (not the no-penalty
    // defer) keeps a permanently-offline group from being re-examined
    // at full speed forever.
    let now = now_unix_nanos();
    for path in &remaining {
        let Some(&claimed_g) = claimed_generation.get(path) else { continue };
        let Some(&claimed_i) = claimed_incarnation.get(path) else { continue };
        let attempt_count = claimed_attempt.get(path).copied().unwrap_or(0);
        let next_attempt_at =
            now + next_backoff((attempt_count as u32).saturating_add(1)).as_nanos() as i64;
        let path_owned = path.clone();
        let group_id_owned = group_id.to_string();
        let _ = run_blocking_sweep_offloaded(move || {
            state.replica_coordinator.sqlite().dag_mark_obligation_attempt_failed(
                &group_id_owned,
                &path_owned,
                claimed_g,
                claimed_i,
                next_attempt_at,
                now,
            )
        });
    }
}

/// Drives every currently-claimable `projection_obligations` row for one
/// group through `reconcile_paths_directly`, closing each path's
/// obligation via the atomic compound completion.
///
/// Per-group path-budget rotation, a persistent cross-tick peer-rotation
/// cursor, origin-first fetch preference, and generation-guarded retry/
/// backoff (`attempt_count`/`next_attempt_at`) are all ported below, using
/// their own dedicated cursors (`ObligationRotationCursors`, owned by
/// `ConvergenceEngine`), separate from the
/// materialization repair job's own peer-rotation cursors so neither
/// driver's rotation state perturbs the other.
///
/// The zero-work-close pre-check never requires a connected peer -- an
/// already-satisfied local projection must close with zero peers online --
/// but does not unconditionally construct the synthetic LOCAL session
/// (`DaemonState::local_retirement_session`) to get there: it prefers an
/// already-live candidate session when one exists, falling back to the
/// local session only when there are none. `local_retirement_session`'s
/// first-ever construction for a group re-validates this device's own
/// retained-history trust as a side effect (`NetmapChangeAuthenticator::
/// new`), which can transiently revoke every OTHER already-connected
/// session's authorization for this group if that validation briefly comes
/// back unavailable -- skipping the construction whenever a live candidate
/// already exists avoids ever triggering that side effect in the
/// overwhelmingly common case where it isn't needed at all. Only the paths
/// the pre-check cannot close need a real fetch, which is the point at
/// which "is any peer connected" first becomes a real question; "no peer
/// shares this group" is then treated as a stable condition (real, growing
/// backoff via `dag_mark_obligation_attempt_failed`, mirroring the legacy
/// job-based scheduler's own equivalent), distinct from a single tick's
/// guard-contention/raced read (the no-penalty defer further below).
#[allow(
    clippy::too_many_lines,
    reason = "single obligation-tick pipeline for one group, and the stages are ordered by \
              a dependency chain rather than composed: claim-token maps (generation / \
              incarnation / attempt) are built up front and threaded into every \
              completion-family call, the zero-work-close pre-check must run before any \
              peer-connectivity question is asked, and the per-tick cost-attribution \
              timing (the zero-work counter plus the slow-tick alarm) brackets \
              the whole body. Splitting it would either duplicate the claim tokens or \
              make the tick timer measure only a fragment of the tick."
)]
async fn process_group_via_obligations(
    engine: &ConvergenceEngine,
    group_id: String,
    claimed: Vec<yadorilink_sync_sqlite::projection_obligations::ClaimedObligation>,
    hooks: Option<&Arc<BeforeCompletionHook>>,
) -> ProcessGroupOutcome {
    let state = &engine.state;
    if claimed.is_empty() {
        return ProcessGroupOutcome { audit_healthy: false, deferred_runnable: false };
    }
    // Per-call start marker, at `debug!` (it fires on every claimed group every tick, too noisy for
    // production `warn!`). Pairs with the "slow obligation tick"
    // end-of-call `warn!` further below (that one stays `warn!`, since
    // it's threshold-gated): if this start marker appears without a
    // matching end marker for tens of seconds, this call is stuck
    // in-flight, not merely absent.
    tracing::debug!(
        group_id = %group_id,
        claimed_count = claimed.len(),
        claimed_paths = ?claimed.iter().map(|c| c.path.as_str()).collect::<Vec<_>>(),
        "process_group_via_obligations starting"
    );
    let claimed_generation: BTreeMap<String, i64> =
        claimed.iter().map(|c| (c.path.clone(), c.invalidation_generation)).collect();
    // Obligation row-incarnation (ABA guard): carried alongside
    // `claimed_generation` into every completion-family call below, exactly
    // like `invalidation_generation` itself -- see `ClaimedObligation`'s own
    // doc comment for why `G` alone is not a safe claim token on its own.
    let claimed_incarnation: BTreeMap<String, i64> =
        claimed.iter().map(|c| (c.path.clone(), c.obligation_incarnation)).collect();
    let claimed_attempt: BTreeMap<String, i64> =
        claimed.iter().map(|c| (c.path.clone(), c.attempt_count)).collect();
    // The same claims, carried into the attempt: a lane that closes a path's
    // obligation in the same transaction as its proof needs the token, and
    // the loop below must then skip that path.
    let lane_claims = crate::local_convergence::obligation_claims::ObligationClaims::new(
        claimed.iter().map(|c| (c.path.clone(), c.token())).collect(),
        hooks.cloned(),
    );
    // Per-tick cost attribution: feeds the slow-obligation-tick alarm
    // below. Throughput here is (paths resolved per tick) / (tick
    // duration), and only the first factor is visible from the outside -- it
    // is pinned at MAX_PATHS_PER_RECONCILE_ATTEMPT. Whether a slow catch-up is
    // "the window is small" or "each tick is expensive", and if the latter
    // WHICH half of the tick is expensive, is not otherwise observable.
    let tick_started = std::time::Instant::now();
    let claimed_count = claimed.len();

    // Per-group path-budget rotation (`MAX_PATHS_PER_RECONCILE_ATTEMPT`
    // windowing): a single
    // `reconcile_paths_directly` call handed this group's ENTIRE
    // still-outstanding budget would process every path's blocks fully
    // serially, and the claim call's own per-group/total limits bound how
    // much gets CLAIMED per tick, not how much one attempt is asked to
    // resolve in a single call. Chosen BEFORE the zero-work pre-check below
    // (not after, as an earlier version of this function did): a zero-work
    // resolution is itself a real per-path head resolution,
    // not a free operation, so pre-checking every one
    // of up to 128 claimed paths when at most `MAX_PATHS_PER_RECONCILE_
    // ATTEMPT` of them can ever reach a real reconcile attempt this tick
    // was an up-to-16x resolution amplification with no corresponding
    // throughput benefit -- the other claimed-but-unwindowed rows are a
    // plain read from `claim_runnable_obligations` (never marked in-flight
    // by claiming alone), so leaving them completely untouched this tick is
    // correct and costs nothing; they remain claimable on a future tick.
    let mut all_paths: Vec<String> = claimed_generation.keys().cloned().collect();
    all_paths.sort();
    let path_budget_start =
        engine.obligation_rotation.path_budget_start(&group_id, all_paths.len());
    let budget_indices = rotation_indices(
        all_paths.len(),
        path_budget_start,
        max_paths_per_reconcile_attempt(state.tuning()),
    );
    let windowed_paths: Vec<String> =
        budget_indices.iter().map(|&i| all_paths[i].clone()).collect();
    engine.obligation_rotation.set_path_budget_next(
        &group_id,
        (path_budget_start + budget_indices.len().max(1)) % all_paths.len().max(1),
    );
    let deferred_runnable = all_paths.len() > windowed_paths.len();
    let mut budget: BTreeSet<String> = windowed_paths.into_iter().collect();
    let windowed_len = budget.len();

    // Candidates are fetched up front so the "no peer" backoff further below
    // sees the same list, without a second and potentially different fetch.
    // A pure read: nothing here constructs a session.
    let mut candidates = crate::hydration::candidate_sessions(state, &group_id);
    candidates.sort_by(|a, b| a.0.cmp(&b.0));

    // The zero-work pre-check is decided from this device's own durable
    // state, so it runs on this device's own executor. It used to pick a
    // connected peer's session and fall back to a synthetic local one, which
    // was never an input to the decision — see
    // `ConvergenceRetirementService::reconcile_group` for the same change and
    // the authorization side effect the preference existed to avoid. A path
    // this confirms is closed immediately and removed from the budget handed
    // to the ordinary reconcile loop below — it never reaches
    // `reconcile_paths_directly`/`materialize` at all this tick.
    let zero_work = state.local_convergence();
    // Test-only: nothing in a release build can read the counter.
    #[cfg(test)]
    crate::obligation_tick_metrics::record_zero_work_attempted(budget.len());
    for path in budget.iter().cloned().collect::<Vec<_>>() {
        let zero_work = zero_work.clone();
        let group_id_for_check = group_id.clone();
        let path_for_check = path.clone();
        let settlement = run_blocking_sweep_offloaded(move || {
            zero_work.zero_work_settlement_for_path(&group_id_for_check, &path_for_check)
        });
        match settlement {
            Ok(Some(evidence)) => {
                if let (Some(&claimed_g), Some(&claimed_i)) =
                    (claimed_generation.get(&path), claimed_incarnation.get(&path))
                {
                    complete_zero_work_obligation(
                        state, &group_id, &path, claimed_g, claimed_i, &evidence, hooks,
                    )
                    .await;
                }
                budget.remove(&path);
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    group_id = %group_id,
                    path,
                    error = %e,
                    "zero-work-close pre-check failed; falling through to a real attempt"
                );
            }
        }
    }
    let precheck_elapsed = tick_started.elapsed();
    let precheck_closed = windowed_len.saturating_sub(budget.len());
    if budget.is_empty() {
        tracing::debug!(
            group_id = %group_id,
            claimed = claimed_count,
            windowed = windowed_len,
            precheck_closed,
            precheck_ms = precheck_elapsed.as_millis() as u64,
            "obligation tick closed entirely in the zero-work pre-check"
        );
        return ProcessGroupOutcome { audit_healthy: true, deferred_runnable };
    }
    let windowed_budget = budget;

    // Only now does whether any peer is connected actually matter -- every
    // path the zero-work pre-check couldn't already close needs a real
    // fetch/materialize attempt, which does need somewhere to fetch from.
    // Reuses the SAME `candidates` fetched at the top of this function
    // (a peer connecting/disconnecting in the brief window since is an
    // accepted race the rest of this scheduler already tolerates via its
    // own CAS-based completion, not something worth a second fetch here).
    if candidates.is_empty() {
        process_without_peers(
            state,
            &group_id,
            windowed_budget,
            &lane_claims,
            &claimed_generation,
            &claimed_incarnation,
            &claimed_attempt,
            hooks,
        )
        .await;
        return ProcessGroupOutcome { audit_healthy: false, deferred_runnable };
    }

    const MAX_PEERS_PER_TICK: usize = 2;
    // Persistent cross-tick peer-rotation cursor (`ObligationRotationCursors`
    // peer cursor): advancing by a fixed amount regardless of how many
    // candidates this call actually tried would re-try an early candidate
    // every tick while a later one is reached far less often.
    let peer_rotation_start = engine.obligation_rotation.peer_start(&group_id, candidates.len());
    // Origin-first fetch preference, resolved from the current desired-state
    // winner (see `origin_candidate_index_for_obligations`'s own doc
    // comment) rather than a stored triggering change — reuses
    // this device's own executor rather than constructing anything new.
    let origin_index = origin_candidate_index_for_obligations(
        &zero_work,
        &group_id,
        &windowed_budget,
        &candidates,
    );
    let rotation_window =
        rotation_indices(candidates.len(), peer_rotation_start, MAX_PEERS_PER_TICK);
    let indices = origin_first_indices(
        candidates.len(),
        peer_rotation_start,
        MAX_PEERS_PER_TICK,
        origin_index,
    );

    let mut remaining: BTreeSet<String> = windowed_budget;
    let mut any_trustworthy_audit = false;
    let mut tried = 0usize;

    for &candidate_index in &indices {
        if remaining.is_empty() {
            break;
        }
        tried += 1;
        let (_, session) = &candidates[candidate_index];
        let local = state.peers.local_convergence(&candidates[candidate_index].0);
        let attempt_result =
            match local {
                Some(local) => local
                    .reconcile_claimed_paths(
                        &(session.clone()
                            as std::sync::Arc<
                                dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver,
                            >),
                        &group_id,
                        remaining.clone(),
                        &lane_claims,
                    )
                    .await,
                None => Ok(None),
            };

        match attempt_result {
            // No group-wide `before == after` comparison gates publishing/
            // completing this attempt's settlements --
            // `unrelated_path_head_movement_must_not_discard_an_already_
            // settled_attempt` and
            // `same_path_admission_while_parked_is_independently_rejected_
            // by_generation_cas` together show that the
            // per-path completion CAS below (claimed generation/incarnation
            // plus the live mutation fence -- see `complete_one_obligation`)
            // already decides currency on its own, per path, regardless of
            // whether some OTHER path's admission moved the group's heads
            // in between. Gating the whole attempt on group-wide stability
            // would be actively harmful: a catch-up admitting unrelated
            // historical changes fast enough (~15/s) makes a stable
            // before/after window across an entire
            // `reconcile_paths_directly` call rare, so already-resolved
            // settlements would be repeatedly discarded for reasons
            // unconnected to the paths they targeted.
            Ok(Some(attempt)) => {
                any_trustworthy_audit = true;
                complete_settled_paths(
                    state,
                    &group_id,
                    &attempt,
                    &lane_claims,
                    &claimed_generation,
                    &claimed_incarnation,
                    hooks,
                    &mut remaining,
                )
                .await;
            }
            Ok(None) => {
                // Skipped: guard contention or the group's link gate is no
                // longer live. Leave `remaining` untouched.
            }
            Err(e) => {
                tracing::warn!(
                    group_id = %group_id,
                    error = %e,
                    "obligation-driven reconciliation failed for this group"
                );
            }
        }
    }

    {
        // Advance by how many of the ROTATION window's leading positions
        // were actually consumed, not by raw `tried`: with an origin-first
        // preference, raw `tried` can include an out-of-window origin
        // attempt (which must not move the rotation at all) or an in-window
        // origin tried out of position (which must not let the cursor skip
        // a window candidate that never got its own turn).
        let tried_set: BTreeSet<usize> = indices.iter().take(tried).copied().collect();
        let advance = rotation_window.iter().take_while(|i| tried_set.contains(i)).count();
        engine
            .obligation_rotation
            .set_peer_next(&group_id, (peer_rotation_start + advance) % candidates.len());
    }

    // Retry/backoff bookkeeping for every path still outstanding
    // (`remaining` never shrinks below what `path_fully_resolved` removed
    // above -- see that arm's own comment). A `HazardHeld`/`IgnoreExcluded`/
    // `PolicyRemote` settlement is never in `remaining` at all: it was
    // `is_settled`, so `path_fully_resolved` already dropped it, and its own
    // dedicated liveness mechanism (the hazard-recheck sweep, the ignore-set
    // refresh) — not this generic backoff — owns re-arming it later. Only a
    // genuine `RetryRequired` (or a path no candidate got to examine at all
    // this tick) ever reaches here.
    let backoff_now = now_unix_nanos();
    if !any_trustworthy_audit {
        // Nothing this tick was learned about ANY budgeted path — every
        // candidate was skipped (guard contention) or raced a concurrent
        // admission. A short, fixed, UNPENALIZED reschedule avoids a tight
        // busy-loop against a systemic condition without treating it as a
        // real per-path failure.
        let next_attempt_at = backoff_now + Duration::from_millis(200).as_nanos() as i64;
        for path in &remaining {
            let Some(&claimed_g) = claimed_generation.get(path) else { continue };
            let Some(&claimed_i) = claimed_incarnation.get(path) else { continue };
            let path_owned = path.clone();
            let group_id_owned = group_id.clone();
            let _ = run_blocking_sweep_offloaded(move || {
                state.replica_coordinator.sqlite().dag_defer_obligation_without_penalty(
                    &group_id_owned,
                    &path_owned,
                    claimed_g,
                    claimed_i,
                    next_attempt_at,
                    backoff_now,
                )
            });
        }
    } else {
        for path in &remaining {
            let Some(&claimed_g) = claimed_generation.get(path) else { continue };
            let Some(&claimed_i) = claimed_incarnation.get(path) else { continue };
            let attempt_count = claimed_attempt.get(path).copied().unwrap_or(0);
            let next_attempt_at = backoff_now
                + next_backoff((attempt_count as u32).saturating_add(1)).as_nanos() as i64;
            let path_owned = path.clone();
            let group_id_owned = group_id.clone();
            let _ = run_blocking_sweep_offloaded(move || {
                state.replica_coordinator.sqlite().dag_mark_obligation_attempt_failed(
                    &group_id_owned,
                    &path_owned,
                    claimed_g,
                    claimed_i,
                    next_attempt_at,
                    backoff_now,
                )
            });
        }
    }

    // Slow-tick alarm: `warn` only past a threshold, so a
    // healthy fast tick stays silent while a catch-up that is spending
    // seconds per 8 paths says so.
    let tick_elapsed = tick_started.elapsed();
    if tick_elapsed >= Duration::from_millis(250) {
        let waiting_for = state
            .replica_coordinator
            .link_gate_for_group(&group_id)
            .ok()
            .and_then(|gate| match gate {
                yadorilink_replica_domain::session_state::LinkGate::Live { local_path, .. } => {
                    state.degraded_link_info(&local_path)
                }
                _ => None,
            })
            .map(|info| info.reason);
        tracing::warn!(
            group_id = %group_id,
            degraded_reason = waiting_for.as_deref().unwrap_or(""),
            claimed = claimed_count,
            precheck_closed,
            precheck_ms = precheck_elapsed.as_millis() as u64,
            windowed = windowed_len,
            still_unresolved = remaining.len(),
            candidates_tried = tried,
            tick_ms = tick_elapsed.as_millis() as u64,
            "slow obligation tick"
        );
    }
    ProcessGroupOutcome { audit_healthy: any_trustworthy_audit, deferred_runnable }
}

/// Shared body for [`drive_obligations_once_for_test`] and
/// [`drive_obligations_once_for_test_with_hooks`]: claims every currently-
/// runnable `projection_obligations` row across all groups and drives each
/// group's claimed batch through [`process_group_via_obligations`],
/// forwarding `hooks` (`None` from the plain entrypoint) unchanged.
#[cfg(any(test, feature = "test-support"))]
async fn drive_obligations_once_for_test_inner(
    engine: &ConvergenceEngine,
    per_group_limit: u32,
    total_limit: u32,
    hooks: Option<&Arc<BeforeCompletionHook>>,
) -> bool {
    let state = &engine.state;
    let now = now_unix_nanos();
    let claimed = match run_blocking_sweep_offloaded(|| {
        state.replica_coordinator.sqlite().dag_claim_runnable_obligations(
            now,
            per_group_limit,
            total_limit,
        )
    }) {
        Ok(claimed) => claimed,
        Err(e) => {
            tracing::warn!(error = %e, "obligation-driven test entrypoint failed to claim");
            return false;
        }
    };
    let mut by_group: HashMap<
        String,
        Vec<yadorilink_sync_sqlite::projection_obligations::ClaimedObligation>,
    > = HashMap::new();
    for obligation in claimed {
        by_group.entry(obligation.group_id.clone()).or_default().push(obligation);
    }
    let mut any_healthy = false;
    for (group_id, group_claimed) in by_group {
        let outcome = process_group_via_obligations(engine, group_id, group_claimed, hooks).await;
        any_healthy = any_healthy || outcome.audit_healthy;
    }
    any_healthy
}

/// Test-only: claims every currently-runnable `projection_obligations` row
/// across all groups and drives each group's claimed batch through
/// [`process_group_via_obligations`] — the obligation-driven counterpart of
/// [`run_once_for_test`], for proving the obligation-driven claim path is
/// correct end-to-end before any cutover wires this claim source into the
/// live `run_once`
/// loop. Returns whether at least one group's audit was trustworthy this
/// call, which is enough for a focused test to assert real progress
/// happened without depending on `run_once`'s own work-conserving
/// `immediate_backlog` semantics (not meaningful here since nothing repeats
/// this call automatically).
#[cfg(any(test, feature = "test-support"))]
pub async fn drive_obligations_once_for_test(
    engine: &ConvergenceEngine,
    per_group_limit: u32,
    total_limit: u32,
) -> bool {
    drive_obligations_once_for_test_inner(engine, per_group_limit, total_limit, None).await
}

/// Identical to [`drive_obligations_once_for_test`], except every
/// completion decision this tick makes pauses at [`BeforeCompletionHook`]
/// immediately before its own completion CAS, letting a deterministic-
/// interleaving test land an independent mutation in between. Intended to
/// be spawned onto its own task (see [`BeforeCompletionHook`]'s own doc
/// comment) so the calling test can drive the interleaving from its own,
/// separate task while this one sits parked.
#[cfg(any(test, feature = "test-support"))]
pub async fn drive_obligations_once_for_test_with_hooks(
    engine: &ConvergenceEngine,
    per_group_limit: u32,
    total_limit: u32,
    hooks: &Arc<BeforeCompletionHook>,
) -> bool {
    drive_obligations_once_for_test_inner(engine, per_group_limit, total_limit, Some(hooks)).await
}

#[cfg(test)]
#[path = "engine/tests.rs"]
mod tests;
