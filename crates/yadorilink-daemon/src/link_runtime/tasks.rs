//! Three of the four per-link background tasks `LinkRuntimeFactory::build`
//! spawns: the debounce **accumulator** (raw filesystem events -> windowed
//! batches), the **executor** (batches -> chunk/index/broadcast, plus this
//! link's startup scan+redrive retry loop), and the periodic
//! dirty-journal-redrive backstop task. Each function here spawns exactly
//! one of those and returns its `JoinHandle` -- `LinkRuntimeFactory::build`
//! wires their shared inputs (channels, `Arc` clones) and collects the
//! handles into the `Vec<JoinHandle<()>>` a `LinkRuntime` is built from.
//!
//! The 4th task, the periodic live materialization-repair task, is
//! deliberately NOT here: it needs `DaemonState::root_lease_for` (through
//! `LinkRegistry`, not this module tree's own narrow
//! `LinkRuntimeDependencies` bundle), so the daemon's own `LinkRuntimeController` spawns it
//! directly and passes the resulting `JoinHandle` into
//! `LinkRuntimeFactory::build` -- see that function's own doc comment for
//! why. Keeping this whole module tree free of `DaemonState` is what keeps
//! it out of the `daemon_state`/`link_registry` dependency cycle (see this
//! crate's own architecture-boundary checks).
//!
//! Moved here from the daemon's own `LinkRuntimeController` as a pure relocation -- every task's
//! logic is byte-identical to before the move; only the closures'
//! previously-inline captures are now this module's function parameters.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::task::JoinHandle;
use yadorilink_filesystem_sync::debounce::{self, DebounceFlush};
use yadorilink_fs_platform::ignore_patterns::{is_ignore_file_relative_path, EffectiveIgnoreSet};
use yadorilink_local_capture::LocalChangeProcessor;
use yadorilink_root_authority::root_identity::RootVerificationStatePort;

use crate::link_runtime::dependencies::LinkRuntimeDependencies;
use crate::link_runtime::operations::capture_local_change::{
    announce_local_change, link_should_propagate,
};
use crate::link_runtime::startup::GroupStartupReadyGuard;

/// How often the live dirty-path-journal redrive pass runs for this link.
/// `record_dirty_path`/`redrive_dirty_journal` (`local_change.rs`) exist
/// precisely because a local edit's own index+delta write can fail
/// transiently (most commonly `SQLITE_BUSY`/`SQLITE_LOCKED` under real
/// concurrent load), leaving the edit journaled but never emitted as a
/// change -- before this, the ONLY consumer of that journal was the
/// one-shot startup rescan (`redrive_dirty_journal`'s own call site in this
/// module's own `spawn_executor_task`), so a failure that happened *during*
/// a live run (not at startup) sat un-synced for the rest of the run unless
/// the exact same path happened to be touched again. Confirmed as a real,
/// reproduced convergence gap (not merely a slowness one) on a contended
/// host: pre-writer-gate, a full mesh of paired sessions could push
/// `SQLITE_BUSY` past even a widened `retry_on_database_locked` (the
/// `SyncState` writer gate has since made that own-process shape
/// impossible, though other transient write failures remain), and nothing
/// during normal operation
/// ever looked at `local_dirty_paths` again afterward. Short relative to
/// `MATERIALIZATION_REPAIR_INTERVAL` (that one walks the whole linked
/// folder; this one is a single indexed query, a no-op read when nothing is
/// journaled) -- the whole point is closing this gap fast, not merely
/// eventually.
const DIRTY_JOURNAL_REDRIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// The debounce accumulator task: reads raw filesystem events off
/// `events_rx` and coalesces them into windowed batches sent on
/// `flush_tx`. Never touches `DaemonState` at all -- it only knows about
/// `yadorilink_filesystem_sync::debounce`'s own types.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_accumulator_task(
    events_rx: tokio::sync::mpsc::Receiver<yadorilink_filesystem_sync::watcher::FsChangeEvent>,
    overflowed: Arc<std::sync::atomic::AtomicBool>,
    watcher_guard: yadorilink_filesystem_sync::watcher::WatcherGuard,
    flush_tx: tokio::sync::mpsc::Sender<DebounceFlush>,
    flush_request_rx: tokio::sync::mpsc::Receiver<debounce::FlushPathRequest>,
    flush_all_request_rx: tokio::sync::mpsc::Receiver<debounce::FlushAllRequest>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // Kept alive for this task's whole lifetime — dropping it would
        // stop the underlying OS watch.
        let _watcher_guard = watcher_guard;
        debounce::run_debouncer(
            debounce::DebounceConfig::default(),
            events_rx,
            flush_tx,
            overflowed,
            flush_request_rx,
            flush_all_request_rx,
        )
        .await;
    })
}

/// Whether tombstone suppression may be cleared after checking (and, if
/// actually pending, running) duplicate-root recovery for this startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DuplicateRecoveryOutcome {
    /// Nothing was pending, or a pending set fully resolved: suppression
    /// may be cleared.
    Complete,
    /// A pending set still has unresolved paths: keep suppression armed.
    StillPending,
    /// The durable pending state could not be read at all: fail closed,
    /// keep suppression armed.
    UnknownFailClosed,
}

/// The duplicate-root recovery gate: `corroborate_and_resolve` (the
/// expensive per-live-row pass -- re-reading/re-hashing every live indexed
/// file against disk) must run ONLY when durable state says duplicate-root
/// recovery is actually pending for this group. An ordinary startup with
/// nothing pending must not pay for a full content pass over the linked
/// folder just to find out there is nothing to do.
///
/// Every real dependency is taken as an already-resolved value or an
/// injected closure precisely so a unit test can prove
/// `corroborate_and_resolve` is never invoked on the "not pending" path
/// without needing a real index or disk -- see `tests` below.
fn resolve_duplicate_recovery_gate<E: std::fmt::Display>(
    group_id: &str,
    pending: Result<bool, E>,
    corroborate_and_resolve: impl FnOnce(),
    recheck_pending: impl FnOnce() -> Result<bool, E>,
) -> DuplicateRecoveryOutcome {
    match pending {
        Ok(false) => DuplicateRecoveryOutcome::Complete,
        Ok(true) => {
            corroborate_and_resolve();
            match recheck_pending() {
                Ok(false) => DuplicateRecoveryOutcome::Complete,
                Ok(true) => DuplicateRecoveryOutcome::StillPending,
                Err(error) => {
                    tracing::warn!(
                        group_id = %group_id,
                        error = %error,
                        "could not re-check duplicate-recovery state after corroboration; \
                         keeping deletion suppression fail-closed"
                    );
                    DuplicateRecoveryOutcome::UnknownFailClosed
                }
            }
        }
        Err(error) => {
            tracing::warn!(
                group_id = %group_id,
                error = %error,
                "could not determine duplicate-recovery state; keeping deletion \
                 suppression fail-closed"
            );
            DuplicateRecoveryOutcome::UnknownFailClosed
        }
    }
}

/// The synchronous pass that runs immediately after a link's initial scan:
/// re-checks disk/index convergence for the duplicate-root recovery gate.
///
/// Extracted from `spawn_executor_task` so it can be handed to `spawn_blocking`
/// whole. Both halves are open-ended in exactly the way the scan that precedes
/// them is: `list_files` reads this group's entire index,
/// `indexed_path_is_corroborated` re-reads and re-hashes every live indexed
/// file against its recorded blocks (a full content pass over the linked
/// folder) -- but only when `resolve_duplicate_recovery_gate` determines
/// duplicate-root recovery is actually pending. Run inline on the executor
/// task, that holds the polling worker for its duration on every link start.
fn post_scan_convergence(
    deps: &Arc<LinkRuntimeDependencies>,
    local_path: &str,
    group_id: &str,
    root: &std::path::Path,
) {
    // A successful *additive* scan proves only that present
    // disk entries were indexed. It deliberately leaves live
    // rows originating at the departed duplicate root intact,
    // so it does not prove disk/index convergence. Keep the
    // deletion gate armed until every live indexed path is
    // present; otherwise the next authoritative scan would
    // tombstone precisely the rows recovery preserved.
    let outcome = resolve_duplicate_recovery_gate(
        group_id,
        deps.replica_coordinator.link_repository().duplicate_recovery_pending(group_id),
        || {
            if let Ok(rows) = deps.replica_coordinator.file_index_repository().list_files(group_id)
            {
                for row in rows.into_iter().filter(|row| !row.deleted) {
                    // A row that expects no object (`Remote`) has converged by
                    // definition: its absence is the correct disk state.
                    if matches!(
                        deps.replica_coordinator.indexed_path_expects_no_object(group_id, &row),
                        Ok(true)
                    ) || matches!(
                        deps.replica_coordinator.indexed_path_is_corroborated(root, group_id, &row),
                        Ok(true)
                    ) {
                        if let Err(error) = deps
                            .replica_coordinator
                            .link_repository()
                            .resolve_duplicate_recovery_path(group_id, &row.path)
                        {
                            tracing::warn!(group_id = %group_id, path = %row.path, error = %error, "could not persist duplicate-recovery path progress");
                        }
                    }
                }
            }
        },
        || deps.replica_coordinator.link_repository().duplicate_recovery_pending(group_id),
    );
    if outcome == DuplicateRecoveryOutcome::Complete {
        if let Err(e) =
            deps.replica_coordinator.link_repository().set_suppress_tombstones(local_path, false)
        {
            tracing::warn!(
                local_path = %local_path,
                error = %e,
                "could not clear this link's additive-scan flag after disk/index \
                 convergence; its deletions stay suppressed until this succeeds"
            );
        }
    }
}

/// One startup attempt for a link's group: the initial scan of the folder
/// and the re-drive of the durable dirty-path journal. `None` when both
/// completed, otherwise why one did not. Idempotent, so a failed attempt is
/// simply run again.
async fn startup_scan_and_redrive(
    deps: Arc<LinkRuntimeDependencies>,
    local_path: String,
    group_id: String,
    processor: Arc<LocalChangeProcessor>,
    root: PathBuf,
    ignore_set: Arc<EffectiveIgnoreSet>,
    emit_tombstones: bool,
) -> Option<String> {
    #[cfg(test)]
    if take_injected_startup_failure(&group_id) {
        return Some("injected startup failure".to_string());
    }
    // `scan_existing_files` walks the whole
    // linked folder and, for every not-already-current file, reads
    // and chunks it — synchronous `std::fs` I/O plus CPU-bound
    // hashing, run directly here would otherwise monopolize this
    // tokio worker thread for the whole initial scan (a large folder
    // or a few multi-GB files stall every other task — peer message
    // handling, heartbeats, control-socket responses — scheduled on
    // the same worker for the duration). `spawn_blocking` moves it
    // onto Tokio's dedicated blocking-thread pool instead; `processor`
    // is already `Arc`-wrapped, so cloning it into the 'static
    // closure is cheap.
    let scan_result = {
        let processor = processor.clone();
        let group_id = group_id.clone();
        let root = root.clone();
        let ignore_set = ignore_set.clone();
        // The initial scan chunks and
        // indexes every not-already-current file — a genuine
        // sync-critical write, held for the guard's whole duration
        // (including the `spawn_blocking` await) so an update install
        // never starts mid-scan.
        let _write_activity = deps.begin_write_activity();
        // Aborting this task (unlink) does not stop the blocking thread, which owns the
        // processor and with it the root lease; the hold is how `stop` learns it is over.
        let blocking_hold = processor.hold_blocking_work();
        {
            tokio::task::spawn_blocking(move || {
                #[cfg(test)]
                if let Some(probe) =
                    INITIAL_SCAN_PROBE.lock().unwrap_or_else(|p| p.into_inner()).clone()
                {
                    probe(&group_id);
                }
                let result = processor.scan_existing_files_with_ignore_gated(
                    &group_id,
                    &root,
                    ignore_set.as_ref(),
                    emit_tombstones,
                );
                // The processor (a clone of the lease) goes first, the hold last: once the
                // hold is gone nothing of this closure owns the root any more.
                drop(processor);
                drop(blocking_hold);
                result
            })
            .await
        }
    };
    let scan_failure: Option<String> = match scan_result {
        Ok(Ok(records)) => {
            // Offloaded for the same reason the scan above is -- see
            // `post_scan_convergence`'s own doc for what
            // runs in there. A panicking blocking task is folded into
            // the same startup-failure string the scan task's own
            // `JoinError` produces, so this link's bounded startup
            // retry can re-run it rather than wedging the group's gate.
            let history_failure = {
                let deps = deps.clone();
                let task_local_path = local_path.clone();
                let group_id = group_id.clone();
                let root = root.clone();
                match tokio::task::spawn_blocking(move || {
                    post_scan_convergence(&deps, &task_local_path, &group_id, &root)
                })
                .await
                {
                    Ok(()) => None,
                    Err(join_err) => {
                        tracing::warn!(
                            error = %join_err,
                            local_path = %local_path,
                            "post-scan convergence task panicked"
                        );
                        Some(format!("post-scan convergence task panicked: {join_err}"))
                    }
                }
            };
            // One batched broadcast for the whole initial scan
            // (batch processing) instead of one peer message per
            // pre-existing file.
            if history_failure.is_none() {
                // Same reason as the flush arms: a scan that resolves
                // dirty rows settles the barrier regardless of whether
                // it produced records to announce.
                deps.note_capture_settled(&group_id);
                announce_local_change(&deps, &local_path, &group_id, records).await;
            }
            history_failure
        }
        Ok(Err(e)) => {
            tracing::warn!(error = %e, local_path = %local_path, "failed to scan pre-existing files");
            Some(format!("initial scan failed: {e}"))
        }
        Err(join_err) => {
            tracing::warn!(error = %join_err, local_path = %local_path, "initial scan task panicked");
            Some(format!("initial scan task panicked: {join_err}"))
        }
    };

    // Startup rescan of the durable dirty-path journal. Any local edit that
    // was detected before a previous crash/restart — or left unprocessed by
    // a multi-second disk-full/EIO that outlived the in-flight retry — is
    // re-driven here, before the live watcher loop resumes, so a detected
    // edit is never silently lost across a restart. Runs after the initial
    // scan (whose own writes journal-and-clear the paths they touch), so an
    // edit already reconciled by the scan resolves to a no-op `None` and is
    // simply cleared. A redrive failure keeps the barrier closed (below),
    // so peer apply cannot race ahead of an un-redriven offline edit.
    let redrive_failure: Option<String> = {
        let _write_activity = deps.begin_write_activity();
        match processor.redrive_dirty_journal(&group_id, &root).await {
            Ok(outcome) => {
                deps.note_capture_settled(&group_id);
                if !outcome.records.is_empty() {
                    announce_local_change(&deps, &local_path, &group_id, outcome.records).await;
                }
                None
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    local_path = %local_path,
                    "failed to re-drive the dirty-path journal at startup"
                );
                Some(format!("dirty-journal redrive failed: {e}"))
            }
        }
    };
    scan_failure.or(redrive_failure)
}

/// Test-only: called on the blocking thread just before a link's initial scan, with its group
/// id; may block.
#[cfg(test)]
type InitialScanProbe = Arc<dyn Fn(&str) + Send + Sync>;
#[cfg(test)]
pub(crate) static INITIAL_SCAN_PROBE: std::sync::Mutex<Option<InitialScanProbe>> =
    std::sync::Mutex::new(None);

/// Test-only: how many more startup attempts of each group fail outright.
#[cfg(test)]
static INJECTED_STARTUP_FAILURES: std::sync::Mutex<Vec<(String, u32)>> =
    std::sync::Mutex::new(Vec::new());

/// Makes the next `attempts` startup attempts of `group_id` fail.
#[cfg(test)]
pub(crate) fn inject_startup_failures(group_id: &str, attempts: u32) {
    INJECTED_STARTUP_FAILURES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push((group_id.to_string(), attempts));
}

#[cfg(test)]
fn take_injected_startup_failure(group_id: &str) -> bool {
    let mut injected = INJECTED_STARTUP_FAILURES.lock().unwrap_or_else(|p| p.into_inner());
    match injected.iter_mut().find(|(group, remaining)| group == group_id && *remaining > 0) {
        Some((_, remaining)) => {
            *remaining -= 1;
            true
        }
        None => false,
    }
}

/// How long to wait before the startup attempt that follows `failures`
/// failed ones in a row, once the immediate attempts are spent: doubling from
/// a few seconds, capped at a minute.
fn startup_retry_delay(failures: u32) -> std::time::Duration {
    #[cfg(test)]
    const BASE: std::time::Duration = std::time::Duration::from_millis(50);
    #[cfg(not(test))]
    const BASE: std::time::Duration = std::time::Duration::from_secs(3);
    BASE.saturating_mul(1u32 << failures.saturating_sub(1).min(10))
        .min(std::time::Duration::from_secs(60))
}

/// The executor task: this link's startup scan+redrive retry loop (which
/// resolves `startup_ready_guard`), then the live flush loop that consumes
/// `flush_rx` for the rest of this link's lifetime.
#[allow(clippy::too_many_arguments)]
#[allow(
    clippy::too_many_lines,
    reason = "one spawned task body holding a link's whole executor lifetime: the bounded \
              startup scan+redrive retry loop and the live `flush_rx` loop that follows it \
              share the moved-in `startup_ready_guard` and the per-attempt \
              `StartupGeneration` re-arming, and the guard must be resolved exactly once on \
              the path between them. Hoisting either loop into its own fn would move that \
              single-owner guard across a boundary and break the fail-closed \
              settle-on-`Failed` sequencing the startup gate depends on."
)]
pub(crate) fn spawn_executor_task(
    executor_deps: Arc<LinkRuntimeDependencies>,
    executor_local_path: String,
    executor_group_id: String,
    executor_processor: Arc<LocalChangeProcessor>,
    executor_root: PathBuf,
    executor_ignore_set: Arc<EffectiveIgnoreSet>,
    // Withhold this boot's initial-scan tombstone emission when the startup
    // interrupted-materialization repair pass errored for this group (see
    // the daemon's own `LinkRuntimeController::start_gating_tombstones`). Fail-closed: a
    // crash-mid-materialize whose repair could not disambiguate it this
    // boot must not be tombstoned.
    executor_emit_tombstones: bool,
    // Armed by `LinkRuntimeFactory::build`'s caller before its fallible
    // setup and *moved* in here, so the window between opening this group's
    // startup generation and taking ownership of it is not merely small but
    // empty: there is no path on which the generation exists without the
    // guard covering it.
    startup_ready_guard: GroupStartupReadyGuard,
    mut flush_rx: tokio::sync::mpsc::Receiver<DebounceFlush>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut executor_ignore_set = executor_ignore_set;
        let executor_canonical_root =
            executor_root.canonicalize().unwrap_or_else(|_| executor_root.clone());
        // Resolves this group's startup barrier exactly once: `Ready` on the
        // normal path just before the live flush loop below, or `Failed` on any
        // path that does not complete — a caught scan/redrive error, a scan
        // task panic surfaced as `JoinError`, or an unwind/task-abort caught by
        // the guard's `Drop`. Peer apply for the group is then deferred
        // (fail-closed) rather than admitted over a half-built index. The guard
        // carries the current `StartupGeneration`, re-armed on each retry below.
        let mut startup_ready_guard = startup_ready_guard;
        // Bounded startup retry. A transient scan/redrive fault (a brief
        // disk-full/EIO, a panic in the blocking scan task) must not wedge peer
        // apply for the group forever behind a `Failed` gate that nothing
        // re-opens. On failure the executor supersedes its generation with a
        // fresh `begin_group_startup` and re-runs the idempotent
        // scan+redrive; only after exhausting the immediate attempts does it
        // settle on `Failed`, from which the live loop below keeps retrying
        // with backoff (and a relink/watcher restart also recovers).
        const STARTUP_MAX_ATTEMPTS: u32 = 3;
        let mut attempt: u32 = 1;
        let startup_outcome: Result<(), String> = loop {
            let startup_failure = startup_scan_and_redrive(
                executor_deps.clone(),
                executor_local_path.clone(),
                executor_group_id.clone(),
                executor_processor.clone(),
                executor_root.clone(),
                executor_ignore_set.clone(),
                executor_emit_tombstones,
            )
            .await;

            match startup_failure {
                None => break Ok(()),
                Some(reason) if attempt >= STARTUP_MAX_ATTEMPTS => break Err(reason),
                Some(reason) => {
                    tracing::warn!(
                        attempt,
                        max_attempts = STARTUP_MAX_ATTEMPTS,
                        local_path = %executor_local_path,
                        group_id = %executor_group_id,
                        reason = %reason,
                        "group startup did not complete; retrying with a fresh generation"
                    );
                    attempt += 1;
                    // Supersede the just-failed generation with a fresh one and
                    // re-run the idempotent scan+redrive. Re-arming the guard
                    // keeps its `Drop`/`mark_*` targeting the generation now in
                    // flight, so a panic mid-retry still fails the right one.
                    // Uses `replica_coordinator`'s `StartupReadinessRegistry`
                    // accessor, consistent with `GroupStartupReadyGuard::mark_ready`/
                    // `mark_failed` (`startup.rs`) and `link_runtime_controller.rs`'s
                    // own initial `begin_group_startup` call, which construct/resolve
                    // generations the same way. `replica_coordinator.startup_readiness()` and
                    // `sync_state.startup_readiness()` are provably the SAME live
                    // `Arc<StartupReadinessRegistry>` (see
                    // `ReplicaCoordinator::from_database`'s own doc comment and
                    // `replica_coordinator::local_mutation::tests::
                    // path_lock_is_shared_with_the_underlying_sync_state_registry`'s
                    // sibling proof for `PathLockRegistry`) -- mixing accessors here
                    // never orphans a generation.
                    let next_generation = executor_deps
                        .replica_coordinator
                        .startup_readiness()
                        .begin_group_startup(&executor_group_id);
                    startup_ready_guard.begin_generation(next_generation);
                }
            }
        };

        // Publish the startup outcome for this group's barrier. On success peer
        // apply proceeds against the up-to-date index; on exhausted retries it
        // stays fail-closed (`Failed`) until a relink/watcher restart supersedes
        // it. Either way local edits are untouched — they live in the index and
        // the dirty-path journal, so a `Failed` only defers peer apply. Resolving
        // here (rather than at end of scope) is also what orders the live flush
        // loop below *after* the barrier resolves: the flush loop and peer apply
        // then observe a fully-committed startup snapshot. The guard lives to end
        // of scope but is now defused, so its eventual `Drop` is a no-op.
        //
        // `Failed` is not final: the live loop below keeps trying the startup
        // attempt again, with a growing delay, for as long as this link runs
        // (`late_startup_retry`). A fault that outlasts the immediate attempts
        // (a disk that stays full for a while, a flaky network volume) is
        // otherwise a gate nothing re-opens until the user relinks.
        let mut late_startup_retry: Option<(tokio::time::Instant, u32)> = None;
        match startup_outcome {
            Ok(()) => startup_ready_guard.mark_ready(),
            Err(reason) => {
                tracing::error!(
                    local_path = %executor_local_path,
                    group_id = %executor_group_id,
                    attempts = STARTUP_MAX_ATTEMPTS,
                    reason = %reason,
                    "group startup failed after retries; deferring peer apply (fail-closed) for this group and retrying with backoff"
                );
                startup_ready_guard.mark_failed(reason);
                late_startup_retry =
                    Some((tokio::time::Instant::now() + startup_retry_delay(1), 1));
            }
        }
        // At `debug!` (it fires on every debounced flush -- too noisy for
        // `warn!` on an active sync): is the executor task
        // still alive and draining flushes, or stuck?
        let mut flushes_received: u64 = 0;
        let mut flushes_completed: u64 = 0;
        // Set when a streaming rescan stopped early because its announcer
        // died: chunks after the failure were never committed, so the next
        // iteration runs another full rescan to capture that tail.
        let mut rescan_retry = false;
        loop {
            let flush = if std::mem::take(&mut rescan_retry) {
                Some(DebounceFlush::RescanRequired)
            } else {
                match late_startup_retry {
                    None => flush_rx.recv().await,
                    Some((due, failures)) => {
                        tokio::select! {
                            flush = flush_rx.recv() => flush,
                            () = tokio::time::sleep_until(due) => {
                                let generation = executor_deps
                                    .replica_coordinator
                                    .startup_readiness()
                                    .begin_group_startup(&executor_group_id);
                                startup_ready_guard.begin_generation(generation);
                                match startup_scan_and_redrive(
                                    executor_deps.clone(),
                                    executor_local_path.clone(),
                                    executor_group_id.clone(),
                                    executor_processor.clone(),
                                    executor_root.clone(),
                                    executor_ignore_set.clone(),
                                    executor_emit_tombstones,
                                )
                                .await
                                {
                                    None => {
                                        tracing::info!(
                                            local_path = %executor_local_path,
                                            group_id = %executor_group_id,
                                            "group startup completed on a later attempt; peer apply \
                                             is admitted again"
                                        );
                                        startup_ready_guard.mark_ready();
                                        late_startup_retry = None;
                                    }
                                    Some(reason) => {
                                        startup_ready_guard.mark_failed(reason);
                                        late_startup_retry = Some((
                                            tokio::time::Instant::now()
                                                + startup_retry_delay(failures + 1),
                                            failures + 1,
                                        ));
                                    }
                                }
                                continue;
                            }
                        }
                    }
                }
            };
            let Some(flush) = flush else { break };
            flushes_received += 1;
            let flush_kind = if matches!(flush, DebounceFlush::RescanRequired) {
                "RescanRequired"
            } else {
                "Paths"
            };
            let start = std::time::Instant::now();
            tracing::debug!(
                flush_kind,
                flushes_received_total = flushes_received,
                flushes_completed_total = flushes_completed,
                "executor flush received"
            );
            let burst_fallback = matches!(flush, DebounceFlush::RescanRequired);
            let ignore_file_changed = flush_touches_ignore_file(&executor_canonical_root, &flush);
            if burst_fallback || ignore_file_changed {
                match EffectiveIgnoreSet::load_for_link_root(&executor_root) {
                    Ok(updated) => executor_ignore_set = Arc::new(updated),
                    Err(e) => tracing::warn!(
                        error = %e,
                        local_path = %executor_local_path,
                        "failed to reload ignore patterns; using the previous effective set"
                    ),
                }
            }
            let flush = if ignore_file_changed {
                tracing::info!(
                    local_path = %executor_local_path,
                    group_id = %executor_group_id,
                    "ignore patterns changed; running a full reconciliation scan"
                );
                DebounceFlush::RescanRequired
            } else {
                flush
            };
            if burst_fallback {
                // Every fallback trigger is logged, not silent. A large but
                // fully-known event burst no longer reaches `RescanRequired`
                // at all (see `debounce.rs`'s own doc comment) -- reaching
                // this arm now means precision was genuinely lost (a real
                // watcher-channel overflow, or the executor backlog merge
                // already having absorbed one).
                tracing::warn!(
                    local_path = %executor_local_path,
                    group_id = %executor_group_id,
                    "debounce reported a full reconciliation scan is required"
                );
            }
            // `process_flush` chunks every
            // touched file (or, for a `RescanRequired`, runs the same
            // full-scan chunking as above) directly on whatever worker
            // polls this future — same blocking-runtime hazard as the
            // initial scan. `process_flush` is `async` (it holds an async
            // per-path lock across the read-compare-write), so it can't be
            // moved into `spawn_blocking` as-is; `block_in_place` is
            // Tokio's documented bridge for exactly this "blocking work
            // interleaved with async code" case — it hands this worker's
            // other queued tasks off to another worker for the duration,
            // without requiring the future/closure to be `'static` (unlike
            // `spawn_blocking`, it can run in place, so no extra `Arc`
            // clones are needed here).
            // Every flush chunks/indexes
            // touched files (or runs a full reconciliation scan) — held
            // across the whole `block_in_place`/`block_on` call so an
            // update install never starts mid-flush.
            let _write_activity = executor_deps.begin_write_activity();
            // Freshly read for THIS flush, not reused from
            // `executor_emit_tombstones` (frozen once, at link-start,
            // before this link's startup scan even ran): the two-live-
            // roots recovery flag can be armed or cleared at any point
            // during an established link's live lifetime, and a value
            // captured before that would silently defeat this exact
            // protection the instant it goes stale in the dangerous
            // direction (armed after capture, cleared only at the next
            // daemon restart). `executor_emit_tombstones` itself is still
            // ANDed in as a lower bound -- this boot's startup materialization-
            // repair failure (if any) must keep suppressing this link's
            // tombstones for the rest of the boot, same as the startup
            // scan itself was gated. Computed unconditionally but only
            // actually consulted for `RescanRequired` -- see
            // `scan_existing_files_with_ignore_gated_for_established_link`'s
            // own doc comment for why a `Paths` flush never needs this.
            let live_emit_tombstones = executor_emit_tombstones
                && !executor_deps
                    .replica_coordinator
                    .link_repository()
                    .suppress_tombstones_for_group(&executor_group_id)
                    .unwrap_or_else(|e| {
                        tracing::error!(
                            group_id = %executor_group_id,
                            error = %e,
                            "cannot tell whether this group's live rescan must be additive; \
                             suppressing its deletions for this pass"
                        );
                        true
                    });
            if burst_fallback {
                // A `RescanRequired` full-reconciliation scan already commits
                // its detected changes to native state in durable, bounded chunks
                // as it walks (`reconcile_disk_with_ignore`'s own chunk
                // loop). Announcing only once the WHOLE scan returned would
                // withhold peer visibility for the scan's entire length (a
                // 15,000-file scan measured ~75s of zero peer-visible
                // progress) even though the source device's own index/native state
                // keeps advancing the whole time -- head-of-line blocking,
                // not a correctness issue. Streaming each durably-committed
                // chunk to `announce_local_change` as it lands avoids this
                // without changing what gets committed, in what
                // order, or when: only when each already-durable chunk
                // becomes peer-visible.
                let announce_deps = executor_deps.clone();
                let announce_local_path = executor_local_path.clone();
                let announce_group_id = executor_group_id.clone();
                let (chunk_tx, announce_task) = spawn_chunk_announcer(move |records| {
                    let deps = announce_deps.clone();
                    let local_path = announce_local_path.clone();
                    let group_id = announce_group_id.clone();
                    async move {
                        announce_local_change(&deps, &local_path, &group_id, records).await;
                    }
                });

                let flush_result = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(
                        executor_processor.process_flush_with_ignore_streaming(
                            &executor_group_id,
                            &executor_root,
                            flush,
                            executor_ignore_set.as_ref(),
                            live_emit_tombstones,
                            &mut |chunk_records| send_committed_chunk(&chunk_tx, chunk_records),
                        ),
                    )
                });
                // Closes the channel so `announce_task`'s `while let Some`
                // ends once every already-sent chunk is drained, then waits
                // for that draining to actually finish before this flush is
                // considered complete (so `flushes_completed_total`/the
                // completion log below stay accurate, and so a later flush's
                // own writes never race this one's still-in-flight
                // announcements).
                drop(chunk_tx);
                let announce_joined = announce_task.await;
                let announce_failed = announce_joined.is_err()
                    || matches!(
                        flush_result,
                        Err(yadorilink_local_capture::LocalCaptureError::StreamingConsumerClosed)
                    );
                if announce_failed {
                    tracing::error!(
                        error = ?announce_joined.as_ref().err(),
                        local_path = %executor_local_path,
                        group_id = %executor_group_id,
                        "the full-rescan announcement consumer died; re-announcing the \
                         group's committed state"
                    );
                    // Everything the scan committed is durable; the peer
                    // announce is group-level, so one fresh announce covers
                    // the chunks the dead consumer never delivered.
                    if link_should_propagate(
                        &executor_deps.replica_coordinator,
                        &executor_local_path,
                        &executor_group_id,
                    ) {
                        executor_deps.on_local_native_commit(&executor_group_id).await;
                    }
                    // The scan stopped at the failed hand-off, so later
                    // chunks were never committed. Wait out a short delay
                    // (a consumer that keeps dying must not spin) and rescan.
                    tokio::time::sleep(ANNOUNCE_FAILURE_RESCAN_DELAY).await;
                    rescan_retry = true;
                } else if matches!(
                    flush_result,
                    Err(yadorilink_local_capture::LocalCaptureError::Paused)
                ) {
                    // A safe stop paused this link mid-scan: chunks after the refusal were
                    // never committed, and a full rescan journals nothing of its own. Run it
                    // again once the pause has had time to lift.
                    tracing::warn!(
                        local_path = %executor_local_path,
                        "the full rescan was paused for a safe stop; repeating it after the pause"
                    );
                    wait_out_pause_then_rescan(&mut rescan_retry).await;
                }

                flushes_completed += 1;
                tracing::debug!(
                    flush_kind,
                    flushes_received_total = flushes_received,
                    flushes_completed_total = flushes_completed,
                    elapsed_ms = start.elapsed().as_millis() as u64,
                    ok = flush_result.is_ok() && !announce_failed,
                    records = flush_result.as_ref().map(|o| o.records.len()).unwrap_or(0),
                    "executor flush completed"
                );
                // `outcome.records` is deliberately NOT passed to
                // `announce_local_change` again here -- every record it
                // contains was already announced, per chunk, as
                // `on_chunk_committed` fired above. Doing so again would
                // double-announce the whole scan.
                if let Err(e) = flush_result {
                    tracing::warn!(error = %e, local_path = %executor_local_path, "failed to process a local-change batch")
                }
            } else {
                let flush_result = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(
                        executor_processor.process_flush_with_ignore(
                            &executor_group_id,
                            &executor_root,
                            flush,
                            executor_ignore_set.as_ref(),
                            live_emit_tombstones,
                        ),
                    )
                });
                flushes_completed += 1;
                tracing::debug!(
                    flush_kind,
                    flushes_received_total = flushes_received,
                    flushes_completed_total = flushes_completed,
                    elapsed_ms = start.elapsed().as_millis() as u64,
                    ok = flush_result.is_ok(),
                    records = flush_result.as_ref().map(|o| o.records.len()).unwrap_or(0),
                    "executor flush completed"
                );
                match flush_result {
                    Ok(outcome) => {
                        // Before the announce, and deliberately not inside it:
                        // a successful flush clears the dirty rows that ARE the
                        // capture barrier, and it can do that while authoring
                        // nothing. `announce_local_change` returns at
                        // `records.is_empty()`, so anything placed after it is
                        // skipped in exactly the case that strands a staged
                        // Change.
                        executor_deps.note_capture_settled(&executor_group_id);
                        announce_local_change(
                            &executor_deps,
                            &executor_local_path,
                            &executor_group_id,
                            outcome.records,
                        )
                        .await;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, local_path = %executor_local_path, "failed to process a local-change batch");
                        // A rescan forced by an ignore-file change journals nothing of its own
                        // either; if a safe-stop pause refused it, it must run again.
                        if ignore_file_changed
                            && matches!(e, yadorilink_local_capture::LocalCaptureError::Paused)
                        {
                            wait_out_pause_then_rescan(&mut rescan_retry).await;
                        }
                    }
                }
            }
        }
    })
}

/// Live backstop for `redrive_dirty_journal` -- see
/// `DIRTY_JOURNAL_REDRIVE_INTERVAL`'s doc comment for why this exists as
/// its own periodic task rather than relying on the startup-only rescan in
/// `spawn_executor_task` or a coincidental re-touch of the same path. Takes
/// its own `Arc<LocalChangeProcessor>` clone (cheap -- it only holds `Arc`
/// references) rather than sharing the executor task's: `redrive_dirty_
/// journal` ultimately calls the same `process_flush` the live watcher loop
/// uses, and is written to be idempotent/safe to call concurrently with it
/// (a path already resolved by the live loop is simply cleared as a
/// no-op), so this task needs no coordination with the watcher loop.
pub(crate) fn spawn_dirty_journal_task(
    dirty_journal_processor: Arc<LocalChangeProcessor>,
    dirty_journal_deps: Arc<LinkRuntimeDependencies>,
    dirty_journal_root: PathBuf,
    dirty_journal_local_path: String,
    dirty_journal_group_id: String,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(DIRTY_JOURNAL_REDRIVE_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let _write_activity = dirty_journal_deps.begin_write_activity();
            let redrive_result = dirty_journal_processor
                .redrive_dirty_journal(&dirty_journal_group_id, &dirty_journal_root)
                .await;
            match redrive_result {
                Ok(outcome) => {
                    dirty_journal_deps.note_capture_settled(&dirty_journal_group_id);
                    if !outcome.records.is_empty() {
                        announce_local_change(
                            &dirty_journal_deps,
                            &dirty_journal_local_path,
                            &dirty_journal_group_id,
                            outcome.records,
                        )
                        .await;
                    }
                }
                Err(e) => tracing::warn!(
                    error = %e,
                    local_path = %dirty_journal_local_path,
                    group_id = %dirty_journal_group_id,
                    "periodic live dirty-journal redrive failed"
                ),
            }
        }
    })
}

/// Moved here from the daemon's own `LinkRuntimeController` alongside `spawn_executor_task` --
/// its only caller -- as part of the same relocation: byte-identical
/// logic, `pub(crate)` only because the daemon's own `LinkRuntimeController`'s own test module
/// still exercises the live-watch path this feeds into, not because
/// anything outside this module tree calls it directly.
pub(crate) fn flush_touches_ignore_file(root: &std::path::Path, flush: &DebounceFlush) -> bool {
    match flush {
        DebounceFlush::Paths(paths) => paths.iter().any(|(path, _, _)| {
            path.strip_prefix(root).ok().is_some_and(is_ignore_file_relative_path)
        }),
        DebounceFlush::RescanRequired => false,
    }
}

/// Committed-but-not-yet-announced chunks a full rescan may buffer. Each
/// chunk is already bounded by the reconcile op/byte limits, so the memory
/// held by the queue is independent of tree size.
const ANNOUNCE_QUEUE_CAPACITY: usize = 2;

/// Pause before repeating a full rescan that a safe-stop pause refused. A pause that is still
/// in force refuses the repeat too, which then waits again.
const PAUSED_RESCAN_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

/// Waits out `PAUSED_RESCAN_DELAY`, then marks the next executor iteration to run a full rescan
/// again: a rescan refused by a safe-stop pause journals nothing of its own.
async fn wait_out_pause_then_rescan(rescan_retry: &mut bool) {
    tokio::time::sleep(PAUSED_RESCAN_DELAY).await;
    *rescan_retry = true;
}

/// Pause before the rescan that follows a dead announcer.
const ANNOUNCE_FAILURE_RESCAN_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

type CommittedChunkSender =
    std::sync::mpsc::SyncSender<Vec<yadorilink_replica_domain::file::FileRecord>>;

/// Starts the consumer that announces each durably committed chunk of a
/// streaming full rescan, in commit order. The queue is bounded, so a slow
/// consumer blocks the scan (backpressure) instead of letting it buffer the
/// whole tree. If the consumer dies its receiver is dropped, which makes
/// every later send fail (see `send_committed_chunk`).
fn spawn_chunk_announcer<F, Fut>(announce: F) -> (CommittedChunkSender, tokio::task::JoinHandle<()>)
where
    F: Fn(Vec<yadorilink_replica_domain::file::FileRecord>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::sync_channel(ANNOUNCE_QUEUE_CAPACITY);
    let handle = tokio::runtime::Handle::current();
    // A blocking-pool thread, not an async task: the scan callback blocks on
    // the queue from inside a runtime context, where tokio's own
    // `blocking_send` is not allowed.
    let task = tokio::task::spawn_blocking(move || {
        while let Ok(records) = rx.recv() {
            handle.block_on(announce(records));
        }
    });
    (tx, task)
}

/// Hands one committed chunk to the announcer, blocking while the queue is
/// full. One chunk is one durable commit (a removed directory's descendants
/// commit together), so the bound is on chunk count, not on any single commit. Fails closed when the consumer is gone so the scan stops.
fn send_committed_chunk(
    tx: &CommittedChunkSender,
    records: &[yadorilink_replica_domain::file::FileRecord],
) -> Result<(), yadorilink_local_capture::LocalCaptureError> {
    tx.send(records.to_vec())
        .map_err(|_| yadorilink_local_capture::LocalCaptureError::StreamingConsumerClosed)
}

#[cfg(test)]
mod tests;
