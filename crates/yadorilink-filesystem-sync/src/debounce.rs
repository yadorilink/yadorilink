//! Coalesces raw filesystem events into windowed batches before they reach
//! `LocalChangeProcessor` (`yadorilink-local-capture::local_change`).
//! Deliberately knows nothing about indexing, chunking, or peers — it only
//! decides *when* a set of paths should be considered "one batch," leaving
//! the caller (typically `yadorilink-daemon::link_runtime`) to turn that
//! batch into actual work via a separate executor task, so this module
//! owns none of that I/O and stays cheaply unit-testable in isolation.
//! Lives here, not in `yadorilink-daemon`, despite being task-scheduling-
//! shaped rather than filesystem-execution-shaped: `DebounceFlush` (this
//! module's output type) is consumed directly by
//! `yadorilink-local-capture::local_change::process_flush` in production,
//! and `yadorilink-local-capture` sits *below* `yadorilink-daemon` in the
//! dependency graph (`yadorilink-daemon` depends on it, never the reverse)
//! — moving this module to `yadorilink-daemon` would need
//! `yadorilink-local-capture` to depend back on `yadorilink-daemon`, a
//! real cycle. `yadorilink-filesystem-sync` already owns this module's one
//! real dependency (`watcher::{FsChangeEvent, FsChangeKind}`) and already
//! sits below both `yadorilink-local-capture` and `yadorilink-daemon`, so
//! it is the natural common ancestor for a type both need.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::watcher::{FsChangeEvent, FsChangeKind};

/// Default quiet period: short, unlike Syncthing's multi-second default, so
/// a local edit reaches peers with minimal added latency.
pub const DEFAULT_QUIET_PERIOD: Duration = Duration::from_millis(300);
/// A continuously-busy folder still flushes at least this often, so a
/// long-running burst of activity doesn't delay every change indefinitely.
pub const DEFAULT_MAX_FLUSH_INTERVAL: Duration = Duration::from_secs(2);
/// Distinct paths changing within one window at or above this count
/// flushes the window early as its own bounded `Paths` batch (see
/// `accumulate_event`) instead of growing it further — never a switch to
/// the full-rescan fallback, which is reserved for genuine information
/// loss (see `DebounceFlush::RescanRequired`'s own doc comment).
pub const DEFAULT_BURST_THRESHOLD: usize = 500;
/// Default capacity of the channel connecting the accumulator to its
/// executor — small, since a flush is already a coalesced
/// unit of work; a handful of pending flushes is enough buffer that a
/// single slow flush never blocks the accumulator from continuing to
/// observe new events. What happens once even this
/// buffer is exhausted by a sustained backlog is hardened separately
/// (see `push_ready`).
pub const DEFAULT_EXECUTOR_CHANNEL_CAPACITY: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebounceConfig {
    pub quiet_period: Duration,
    pub max_flush_interval: Duration,
    pub burst_threshold: usize,
}

impl Default for DebounceConfig {
    fn default() -> Self {
        Self {
            quiet_period: DEFAULT_QUIET_PERIOD,
            max_flush_interval: DEFAULT_MAX_FLUSH_INTERVAL,
            burst_threshold: DEFAULT_BURST_THRESHOLD,
        }
    }
}

/// What one debounce window produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebounceFlush {
    /// Distinct paths that changed in this window, each with the last
    /// `FsChangeKind` observed for it (a path modified then removed
    /// within the window is reported as `Removed`, matching final
    /// on-disk state — ), and the wall-clock time (unix nanos)
    /// this accumulator last observed an event for that path — i.e. when
    /// the *raw* event was received here, not when this flush is finally
    /// dispatched (which can lag by up to `quiet_period`/
    /// `max_flush_interval`). `local_change.rs`'s `Removed` dispatch needs
    /// this real observed
    /// time for `SyncState::mark_deleted_at` — a tombstone stamped with
    /// dispatch time instead would be systematically later than a
    /// concurrent edit's own (never debounce-delayed) file mtime,
    /// regardless of which genuinely happened first.
    Paths(Vec<(PathBuf, FsChangeKind, i64)>),
    /// Precise per-path tracking was genuinely lost for whatever changed
    /// during this window — the caller should run a full reconciliation
    /// scan instead. Reserved for the one case that actually loses
    /// information: the watcher's own raw-event channel overflowed (see
    /// `overflowed` in `run_debouncer`'s own doc comment), so some change
    /// in this window is simply unknown to this accumulator. Crossing
    /// `burst_threshold` distinct KNOWN paths is NOT this case — see
    /// `Paths`'s own early-flush behavior above, which handles a large
    /// but fully-known burst (e.g. a bulk rename/delete) as a sequence of
    /// bounded `Paths` batches instead. Converting a large-but-known
    /// burst into a full-tree rescan would be a real cost: at
    /// ~100k-file scale, a full disk-vs-index content rescan costs
    /// roughly the ENTIRE tree's own content verification, not the size
    /// of what actually changed — and `watcher.rs`'s own doc comment
    /// already documents a full-rescan fallback like this one
    /// deterministically stalling convergence when it re-derives/
    /// re-versions files a concurrent peer write is racing.
    RescanRequired,
}

/// Same shape as this crate's
/// other private `now_unix_nanos` helpers (`index.rs`, `peer_session.rs`,
/// `yadorilink-daemon::link_manager`) — captures the wall-clock time a raw
/// event is received here, for `DebounceFlush::Paths`'s third tuple
/// element.
fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

enum State {
    Idle,
    Accumulating {
        pending: HashMap<PathBuf, (FsChangeKind, i64)>,
        window_started_at: Instant,
        last_event_at: Instant,
    },
    /// Precision was genuinely lost (watcher-channel overflow only — see
    /// `RescanRequired`'s own doc comment; a large but fully-known burst no
    /// longer reaches this state, see `accumulate_event`); further events
    /// are observed (to know when the burst subsides) but not tracked
    /// individually. `window_started_at` bounds this state's own worst-case
    /// dwell time by `max_flush_interval`, the same defense-in-depth
    /// `Accumulating` already has — a continuous trickle of further raw
    /// events (each resetting `last_event_at`) must not indefinitely delay
    /// the rescan this state exists to trigger.
    Bursting {
        window_started_at: Instant,
        last_event_at: Instant,
    },
}

/// Which entry `FlushPathRequest` should look for in `pending`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushMode {
    /// Look up `FlushPathRequest::path` itself, exactly.
    ExactPath,
    /// Look up a *different* pending entry that shares `path`'s parent
    /// directory and case-folded final path component (but not its exact
    /// bytes) — i.e. the other name a case-insensitive filesystem would
    /// treat as colliding with `path`. Only ever meaningful for a caller
    /// who already confirmed the target root is on a case-insensitive
    /// filesystem (`hazard::is_case_insensitive_filesystem`); this module
    /// doesn't know or care about filesystem case-sensitivity itself, it
    /// just does the lookup asked of it.
    CaseFoldSibling,
}

/// A targeted request to immediately hand back (and remove, so it is not
/// flushed a second time when its window's own timer later elapses) one
/// specific path's pending, undispatched entry, bypassing the normal
/// quiet-period/max-flush-interval timing entirely. This lets a caller
/// outside the accumulator (`yadorilink-daemon::link_manager`, on behalf of
/// `peer_session::PeerSyncSession::reconcile_one_file`) make sure a local
/// change still sitting in this accumulator is captured into the index
/// before a racing peer write or tombstone for the same path is
/// compared/applied — see `reconcile_one_file`'s call site for why this
/// must happen before, not after, that comparison.
pub struct FlushPathRequest {
    pub path: PathBuf,
    pub mode: FlushMode,
    /// `Some((found_path, kind, observed_at_unix_nanos))` if a matching
    /// entry was pending, undispatched (now removed from this
    /// accumulator's own state) — `found_path` is `path` itself for
    /// `FlushMode::ExactPath`, or the actual sibling key that matched for
    /// `FlushMode::CaseFoldSibling` (never byte-identical to `path` in
    /// that case). `None` if nothing matched — either because it had
    /// already been handed off to the executor (in which case the
    /// ordinary per-path index lock/version check the executor and
    /// `reconcile_one_file` both already go through is what serializes the
    /// two, the same as for any other already-dispatched change), or
    /// because no `FsChangeEvent` for it has ever reached this accumulator
    /// at all — a path can still be genuinely undiscovered by the watcher
    /// subsystem at this point — see `yadorilink-daemon::link_manager::
    /// LinkFlushHandle::capture_undiscovered_local_change`, the caller's
    /// fallback for this third case).
    ///
    /// The entry leaves the accumulator only once this reply is delivered: if the receiver
    /// is gone, the entry stays pending.
    pub reply: tokio::sync::oneshot::Sender<Option<(PathBuf, FsChangeKind, i64)>>,
}

/// A request to
/// immediately drain and hand back *every* currently-pending, undispatched
/// entry in this accumulator (not just one path), bypassing the normal
/// quiet-period/max-flush-interval timing entirely -- same rationale as
/// `FlushPathRequest`, but for "resuming a paused link must broadcast its
/// true current state, not whatever snapshot happened to already be
/// flushed into the index at that exact instant" rather than "reconciling
/// one specific incoming path." A local change made while a link was
/// paused is indexed immediately regardless of pause (`announce_local_
/// change`'s doc comment), but only once its own debounce window's quiet
/// period elapses -- resuming shortly after such a change (well within
/// that window) would otherwise broadcast a stale snapshot missing it,
/// with no second chance to send it until either another local change to
/// the same path, or the periodic full-index resync, happens to occur.
pub struct FlushAllRequest {
    /// Every entry that was pending, in no particular order; empty if
    /// nothing was pending (including while `Idle`/`Bursting`, where there
    /// is nothing per-path to drain).
    pub reply: tokio::sync::oneshot::Sender<Vec<(PathBuf, FsChangeKind, i64)>>,
}

async fn sleep_until_opt(deadline: Option<Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending().await,
    }
}

/// Runs the debounce accumulator:
/// reads raw events from `events`, and delivers completed window batches
/// to `flush_tx`. Returns once `events` closes (the watcher stopped) or
/// `flush_tx` closes (the executor side is gone). Does no I/O beyond
/// these two channels — see the module doc comment for why.
///
/// Delivery to `flush_tx` races against continuing to read `events`
/// A completed window joins an internal delivery queue
/// rather than being sent with a blocking `.await` directly in the same
/// `select!` as event intake, so a slow or backed-up executor (not
/// draining `flush_tx` quickly) never stalls this task's ability to keep
/// observing and accumulating new filesystem events for the *next*
/// window in the meantime. Per-link delivery order is still preserved —
/// the queue is drained strictly front-to-back, one send at a time.
///
/// `overflowed` is `watcher::FolderWatcher`'s overflow flag:
/// checked (and cleared) on every loop iteration. A set flag means the
/// watcher's own channel dropped at least one raw event since it was last
/// checked — precise per-path tracking is no longer trustworthy for
/// whatever window is in progress, so it's routed into the exact same
/// `Bursting` state and full-reconciliation recovery as an oversized
/// debounce burst, rather than a second, separate fallback
/// mechanism.
///
/// `flush_requests` is the
/// targeted "flush now" channel (`FlushPathRequest`'s doc comment) —
/// serviced with higher priority than continuing to accumulate new events,
/// so a caller waiting on the reply is never stuck behind an unrelated
/// burst of activity for other paths.
pub async fn run_debouncer(
    config: DebounceConfig,
    mut events: mpsc::Receiver<FsChangeEvent>,
    flush_tx: mpsc::Sender<DebounceFlush>,
    overflowed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    mut flush_requests: mpsc::Receiver<FlushPathRequest>,
    mut flush_all_requests: mpsc::Receiver<FlushAllRequest>,
) {
    let mut state = State::Idle;
    let mut ready_queue: std::collections::VecDeque<DebounceFlush> =
        std::collections::VecDeque::new();
    // Once the requester side is gone, stop polling `flush_requests`
    // entirely rather than let a closed channel's always-ready `None` spin
    // this loop — mirrors `ready_queue.is_empty`'s guard on the
    // `send_front` branch below.
    let mut flush_requests_open = true;
    let mut flush_all_requests_open = true;

    loop {
        if overflowed.swap(false, std::sync::atomic::Ordering::Relaxed) {
            // Each of the three fallback triggers logs a
            // distinguishable reason.
            tracing::warn!(
                reason = "watcher_channel_overflow",
                "filesystem watcher channel overflowed; falling back to full reconciliation"
            );
            let now = Instant::now();
            state = State::Bursting { window_started_at: now, last_event_at: now };
        }

        let deadline = match &state {
            State::Idle => None,
            State::Accumulating { window_started_at, last_event_at, .. } => Some(std::cmp::min(
                *last_event_at + config.quiet_period,
                *window_started_at + config.max_flush_interval,
            )),
            State::Bursting { window_started_at, last_event_at } => Some(std::cmp::min(
                *last_event_at + config.quiet_period,
                *window_started_at + config.max_flush_interval,
            )),
        };

        tokio::select! {
            biased;

            // Cancel-safe: only pops the front entry once it's actually
            // been sent; if this branch loses the race below, the queue
            // is untouched and the same entry is retried next iteration.
            result = send_front(&flush_tx, &ready_queue), if !ready_queue.is_empty() => {
                match result {
                    Ok(()) => { ready_queue.pop_front(); }
                    Err(()) => break, // executor side is gone
                }
            }

            // Serviced ahead of `events.recv` (see this fn's doc comment):
            // a targeted flush request should never be left waiting behind
            // a caller that's still busy generating unrelated events.
            maybe_request = flush_requests.recv(), if flush_requests_open => {
                let Some(request) = maybe_request else {
                    flush_requests_open = false;
                    continue;
                };
                drain_ready_events(&mut events, &mut state, &config, &mut ready_queue);
                match state {
                    State::Accumulating { mut pending, window_started_at, last_event_at } => {
                        let found = match request.mode {
                            FlushMode::ExactPath => pending
                                .remove(&request.path)
                                .map(|(kind, at)| (request.path.clone(), kind, at)),
                            FlushMode::CaseFoldSibling => {
                                let sibling = pending.keys().find(|candidate| {
                                    *candidate != &request.path
                                        && candidate.parent() == request.path.parent()
                                        && candidate.file_name().map(|n| n.to_string_lossy().to_lowercase())
                                            == request.path.file_name().map(|n| n.to_string_lossy().to_lowercase())
                                }).cloned();
                                sibling.and_then(|key| {
                                    pending.remove(&key).map(|(kind, at)| (key, kind, at))
                                })
                            }
                        };
                        // The entry leaves `pending` only once its reply is delivered. A
                        // requester that stopped listening (timed out, or was dropped) gets
                        // nothing, so `send` hands the value back and it returns to
                        // `pending` under the window's own timing, for the next request or
                        // the timer to flush.
                        if let Err(Some((key, kind, at))) = request.reply.send(found) {
                            pending.insert(key, (kind, at));
                        }
                        state = if pending.is_empty() {
                            State::Idle
                        } else {
                            State::Accumulating { pending, window_started_at, last_event_at }
                        };
                    }
                    other @ (State::Idle | State::Bursting { .. }) => {
                        state = other;
                        let _ = request.reply.send(None);
                    }
                }
            }

            maybe_request = flush_all_requests.recv(), if flush_all_requests_open => {
                let Some(request) = maybe_request else {
                    flush_all_requests_open = false;
                    continue;
                };
                drain_ready_events(&mut events, &mut state, &config, &mut ready_queue);
                match state {
                    State::Accumulating { pending, window_started_at, last_event_at } => {
                        let drained: Vec<_> = pending
                            .iter()
                            .map(|(path, (kind, at))| (path.clone(), *kind, *at))
                            .collect();
                        // Same rule as the targeted request: the batch is handed over only if
                        // its reply is delivered; otherwise the accumulator keeps all of it.
                        state = match request.reply.send(drained) {
                            Ok(()) => State::Idle,
                            Err(_) => State::Accumulating { pending, window_started_at, last_event_at },
                        };
                    }
                    other @ (State::Idle | State::Bursting { .. }) => {
                        state = other;
                        let _ = request.reply.send(Vec::new());
                    }
                }
            }

            maybe_event = events.recv() => {
                let Some(event) = maybe_event else { break };
                let (next_state, flush) = accumulate_event(state, event, &config);
                state = next_state;
                if let Some(flush) = flush {
                    push_ready(&mut ready_queue, flush);
                }
            }

            _ = sleep_until_opt(deadline) => {
                let flush = match state {
                    // No timer is armed while Idle (`deadline` is `None`, and
                    // `sleep_until_opt(None)` never completes), so this arm
                    // should be unreachable. Handle a spurious wake as a no-op
                    // — skip straight to the next loop iteration, leaving the
                    // state Idle — rather than panicking the debouncer task and
                    // taking down local change detection with it if a future
                    // refactor ever arms a deadline in this state.
                    State::Idle => continue,
                    State::Accumulating { pending, .. } => DebounceFlush::Paths(
                        pending.into_iter().map(|(path, (kind, at))| (path, kind, at)).collect(),
                    ),
                    State::Bursting { .. } => DebounceFlush::RescanRequired,
                };
                push_ready(&mut ready_queue, flush);
                state = State::Idle;
            }
        }
    }
}

/// Folds one filesystem event into the accumulator state — the single
/// definition shared by ordinary `events.recv()` intake and the
/// pre-reply drain in `drain_ready_events`, so a flush request can never
/// answer from a state built by a *different* accumulation rule than the
/// timer path uses.
///
/// Returns the flush to push onto the ready queue when this event fills
/// this window to `burst_threshold` — the caller is responsible for
/// actually queuing it (`push_ready`), since only the caller knows
/// whether it's mid-drain (`drain_ready_events`, which must not itself
/// touch `ready_queue`) or on the main event-intake path.
///
/// `burst_threshold` distinct paths in one window flushes early as an
/// ordinary bounded `Paths` batch rather than discarding per-path
/// tracking — a confirmed, measured bug this replaces: converting a
/// large but fully-known burst (e.g. a bulk rename/delete storm) into
/// `RescanRequired` traded a bounded, known cost (this window's own
/// path count) for an UNBOUNDED one (a full-tree disk-vs-index content
/// verification, roughly the size of the entire synced folder regardless
/// of how much of it actually changed) -- observed hanging a ~1k-file
/// folder's own 900-op storm for the full length of a 900s test timeout
/// with zero further progress. A sustained burst of N paths now costs
/// `ceil(N / burst_threshold)` bounded batches instead.
fn accumulate_event(
    state: State,
    event: FsChangeEvent,
    config: &DebounceConfig,
) -> (State, Option<DebounceFlush>) {
    let now = Instant::now();
    let observed_at = now_unix_nanos();
    let (mut pending, window_started_at) = match state {
        State::Idle => (HashMap::new(), now),
        State::Accumulating { pending, window_started_at, .. } => (pending, window_started_at),
        State::Bursting { window_started_at, .. } => {
            return (State::Bursting { window_started_at, last_event_at: now }, None);
        }
    };
    pending.insert(event.path, (event.kind, observed_at));
    // `>=`, not `>`, so a caller-configured `burst_threshold` of exactly 1
    // (a real, publicly permitted `DebounceConfig` value) flushes on this
    // very first event too, rather than only from the second one onward --
    // checked uniformly here for a window of any prior size (including
    // fresh-from-`Idle`), not only once already `Accumulating`.
    if pending.len() >= config.burst_threshold {
        tracing::warn!(
            reason = "burst_threshold_reached",
            burst_threshold = config.burst_threshold,
            "debounce window reached its known-path threshold; flushing early as a batch"
        );
        let flush = DebounceFlush::Paths(
            pending.into_iter().map(|(path, (kind, at))| (path, kind, at)).collect(),
        );
        (State::Idle, Some(flush))
    } else {
        (State::Accumulating { pending, window_started_at, last_event_at: now }, None)
    }
}

/// Folds every event the watcher has *already* delivered into this task's
/// channel into `state`, without waiting for any new one.
///
/// This runs before a flush request is answered, and it is what makes the
/// answer trustworthy. The `select!` above is `biased` with the flush-request
/// branch ahead of `events.recv()` — deliberately, so a targeted flush is
/// never stuck behind an unrelated burst — but that priority also means a
/// local write whose event is sitting *unread* in `events` is invisible to
/// the request, which then replies "nothing pending for that path".
///
/// The caller of that reply is
/// `PeerSyncSession::flush_pending_local_change_before_reconcile`, whose
/// entire job is to capture a local edit before an incoming remote change
/// is admitted and materialized over it. A false "nothing pending" there is
/// silent data loss, not a delay: the remote content overwrites the local
/// write on disk, and when the event finally is dequeued, `process_flush`
/// re-reads the path, finds the remote bytes already matching the index,
/// suppresses it as a self-echo, and the local write is never authored at
/// all. Measured as exactly this, on the retired network-fault scenario seeds
/// 3298840576/3298840578: every lost write was on the device driven through
/// the watcher/debounce path, and its round printed no flush line.
///
/// Scope, measured rather than assumed: draining here removes *one* window
/// — the event is in this channel but not yet polled — and no more. It is
/// **not** on its own sufficient to close the loss. With this drain in
/// place and the disk-authoritative fallback disabled, that scenario still
/// failed 1 run in 3, because a false-negative `None` is also reachable
/// when the entry was already dispatched to the executor and its
/// `process_flush` simply has not run yet. Nothing this accumulator can do
/// covers that case: the only reliable defense is the caller's
/// `link_manager::LinkFlushHandle::capture_undiscovered_local_change`
/// fallback, which reads the path off disk before the incoming change is
/// admitted, and which is what actually makes the scenario green.
///
/// This drain still earns its place — `flush_case_fold_sibling` has no
/// such fallback by deliberate design (see its doc comment), so for that
/// caller the accumulator's reply *is* the whole answer, and a stale one
/// is the artifact-free silent overwrite it exists to prevent.
fn drain_ready_events(
    events: &mut mpsc::Receiver<FsChangeEvent>,
    state: &mut State,
    config: &DebounceConfig,
    ready_queue: &mut std::collections::VecDeque<DebounceFlush>,
) {
    while let Ok(event) = events.try_recv() {
        let current = std::mem::replace(state, State::Idle);
        let (next_state, flush) = accumulate_event(current, event, config);
        *state = next_state;
        // A burst-threshold early flush can complete mid-drain (see
        // `accumulate_event`'s own doc comment) -- it must still reach the
        // executor via the ordinary ready queue, never be silently dropped
        // just because it happened while draining ahead of a flush request.
        if let Some(flush) = flush {
            push_ready(ready_queue, flush);
        }
    }
}

/// Pushes a completed window onto the delivery queue, merging every
/// currently-queued entry (plus this new one) into a single entry when the
/// executor has fallen far enough behind that the queue would otherwise
/// grow without bound — bounding queue DEPTH to 1 in that case, without
/// discarding known paths the way collapsing to `RescanRequired` used to
/// (a confirmed, measured bug — see `DebounceFlush::RescanRequired`'s own
/// doc comment). Every queued `Paths` batch folds into one deduplicated
/// map (a path touched by more than one queued batch keeps the latest
/// batch's kind/timestamp, the same "last observation wins" rule
/// `accumulate_event` already applies within a single window); only if a
/// `RescanRequired` is already queued does the merge stay
/// `RescanRequired` — that precision loss already happened and merging
/// cannot recover it, but merging still bounds queue depth for it too.
fn push_ready(queue: &mut std::collections::VecDeque<DebounceFlush>, flush: DebounceFlush) {
    if queue.len() >= DEFAULT_EXECUTOR_CHANNEL_CAPACITY {
        tracing::warn!(
            reason = "executor_backlog",
            queued = queue.len(),
            "executor has fallen behind the accumulator; merging queued flushes to bound memory"
        );
        let mut merged: HashMap<PathBuf, (FsChangeKind, i64)> = HashMap::new();
        let mut rescan_required = false;
        for queued in queue.drain(..).chain(std::iter::once(flush)) {
            match queued {
                DebounceFlush::Paths(paths) => {
                    for (path, kind, at) in paths {
                        merged.insert(path, (kind, at));
                    }
                }
                DebounceFlush::RescanRequired => rescan_required = true,
            }
        }
        if rescan_required {
            queue.push_back(DebounceFlush::RescanRequired);
        } else {
            queue.push_back(DebounceFlush::Paths(
                merged.into_iter().map(|(path, (kind, at))| (path, kind, at)).collect(),
            ));
        }
    } else {
        queue.push_back(flush);
    }
}

/// Sends a clone of the queue's front entry — cloning (rather than
/// popping first) is what makes the caller's `select!` branch cancel-safe:
/// if a competing branch wins the race, this future is simply dropped
/// mid-flight with the queue left untouched, ready to retry.
async fn send_front(
    flush_tx: &mpsc::Sender<DebounceFlush>,
    queue: &std::collections::VecDeque<DebounceFlush>,
) -> Result<(), ()> {
    let front = queue.front().cloned().expect("caller guards on !queue.is_empty()");
    // Zero-field `phase T_*` marker: a timestamp anchor for offline
    // timing analysis of captured logs.
    tracing::debug!("phase T_debounce: debounce dispatch to the flush consumer");
    let result = flush_tx.send(front).await.map_err(|_| ());
    // Kept at `debug!`: it fires on every dispatch, too noisy for
    // `warn!` on an active sync. `capacity()` after a successful send
    // reflects real occupancy regardless of this future's own
    // cancel-safety (a cancelled/re-raced future never reaches this line
    // at all).
    if result.is_ok() {
        tracing::debug!(remaining_capacity = flush_tx.capacity(), "debounce dispatch completed");
    }
    result
}

#[cfg(test)]
mod tests;
