//! Starts/stops the background tasks that watch one linked folder
//! (watcher, chunking-and-indexing, broadcast to connected peers, and
//! shell-extension status push). Two tasks per link: a debounce
//! **accumulator** that only ever reads raw filesystem
//! events and coalesces them into windowed batches
//! (`yadorilink_filesystem_sync::debounce`), and an **executor** that consumes
//! those batches and does the actual chunk/index/broadcast work — kept
//! separate so a slow executor flush never blocks the accumulator from
//! continuing to observe new events.
//!
//! `LinkRuntimeController` is the single entry point every daemon caller
//! now goes through for starting, stopping, resuming, and sweeping a
//! link's runtime -- replacing the free functions this daemon used to
//! expose from its own now-removed link-manager module. A pure
//! relocation: every method's logic below is byte-identical to its former
//! free-function body, only the receiver changed from an explicit `state`
//! parameter to `&self`.
//!
//! `new`/`start`/`start_with_source`/`stop`/`resume` are `pub`, not
//! `pub(crate)`, purely so this crate's own external integration-test
//! binaries under `tests/` -- which compile as separate crates and so
//! never see `#[cfg(test)]`/`pub(crate)` items regardless of how they're
//! built -- can still drive a link's lifecycle directly, the same
//! external-reachability reason `ControlContext::from_state` is `pub`.
//! `start_gating_tombstones`/`run_retention_expiry_sweep`/
//! `run_disk_reconcile_backstop_sweep` stay `pub(crate)`: no external test
//! calls them today.

#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use yadorilink_filesystem_sync::watcher::FolderWatchSource;
#[cfg(feature = "process-model")]
use yadorilink_filesystem_sync::watcher::RealFolderWatchSource;

/// The watch source a link starts with: the OS watcher in the desktop daemon; none in the
/// embedded host, whose linked folders are owned by the operating system and change through
/// the provider channel.
fn default_watch_source(links: &Arc<LinkRegistry>) -> Arc<dyn FolderWatchSource> {
    #[cfg(feature = "process-model")]
    {
        let _ = links;
        Arc::new(RealFolderWatchSource)
    }
    #[cfg(not(feature = "process-model"))]
    {
        Arc::new(NoChangeSource { links: links.clone() })
    }
}

/// The watch source of the embedded build: an ordinary folder has no source of changes, so its
/// start fails (its startup gate stays failed, so peers' changes are deferred, not applied) and
/// the link is shown stopped with the reason.
#[cfg(not(feature = "process-model"))]
struct NoChangeSource {
    links: Arc<LinkRegistry>,
}

#[cfg(not(feature = "process-model"))]
impl FolderWatchSource for NoChangeSource {
    fn watch(
        &self,
        root: &std::path::Path,
        ignore_set: Arc<yadorilink_fs_platform::ignore_patterns::EffectiveIgnoreSet>,
    ) -> Result<
        yadorilink_filesystem_sync::watcher::FolderWatcher,
        yadorilink_filesystem_sync::watcher::WatcherError,
    > {
        self.links.mark_no_change_source(&root.to_string_lossy(), crate::daemon_state::now_unix());
        yadorilink_filesystem_sync::watcher::NoWatchSource.watch(root, ignore_set)
    }
}

/// Whether an ordinary folder link can have a source of changes in this build: only the desktop
/// build has an OS watcher. Elsewhere only provider folders can be linked.
#[must_use]
pub const fn ordinary_folder_links_supported() -> bool {
    cfg!(feature = "process-model")
}
#[cfg(test)]
use yadorilink_fs_platform::ignore_patterns::EffectiveIgnoreSet;

use crate::daemon_state::DaemonState;
use crate::error::DaemonError;
use crate::link_registry::LinkRegistry;
use crate::link_runtime::factory::LinkRuntimeFactory;
use crate::link_runtime::operations::capture_local_change::announce_local_change;
use crate::link_runtime::startup::GroupStartupReadyGuard;

/// How often each link's
/// background task re-runs `materialization::repair_interrupted_
/// materializations` during live operation, not just at daemon startup —
/// defense-in-depth against whatever bug might leave a `Present` index
/// record disagreeing with what's actually on disk (the direct fixes are
/// in `try_apply_metadata_only_update` and this module's debounce-batch
/// executor; this is a coarse, low-frequency safety net on top of those,
/// not a substitute for them). Same order of magnitude as
/// `yadorilink_peer_session::peer_session::DEFAULT_MAINTENANCE_RECONCILE_INTERVAL`
/// (90s) -- frequent enough to bound how long a divergence can persist,
/// infrequent enough that a full per-link disk scan is negligible
/// overhead against normal sync traffic.
const MATERIALIZATION_REPAIR_INTERVAL: std::time::Duration = std::time::Duration::from_secs(120);

pub struct LinkRuntimeController {
    state: Arc<DaemonState>,
}

impl LinkRuntimeController {
    pub fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }

    pub(crate) fn is_ready(&self, local_path: &str) -> bool {
        self.state.links.runtime(local_path).is_some()
    }

    pub fn start(&self, local_path: String, group_id: String) -> Result<(), DaemonError> {
        self.start_inner(local_path, group_id, default_watch_source(&self.state.links), true)
    }

    /// Same as `start`, but takes
    /// an explicit `FolderWatchSource` so a DST scenario can substitute a
    /// synthetic event source in place of the real OS filesystem watcher,
    /// while every other production code path below (debounce, indexing,
    /// broadcast, materialization) runs unchanged.
    pub fn start_with_source(
        &self,
        local_path: String,
        group_id: String,
        watcher_source: Arc<dyn FolderWatchSource>,
    ) -> Result<(), DaemonError> {
        self.start_inner(local_path, group_id, watcher_source, true)
    }

    /// Same as `start`, but lets the daemon's startup path suppress
    /// this link's initial-scan tombstone emission for this boot.
    ///
    /// Startup runs the interrupted-materialization repair pass for every link
    /// before restarting its watcher; that pass is what disambiguates a
    /// crash-mid-materialize (missing target, blocks present, an open
    /// materialization intent -> reconstruct) from an offline user delete (missing
    /// target, no intent -> tombstone). When repair ERRORED for this link's group,
    /// its disambiguation input is unavailable, so the initial reconcile scan must
    /// not classify a `Present`-but-missing file as a deletion. Passing
    /// `emit_tombstones = false` then defers this scan's delete emission to a later
    /// boot on which repair succeeds — fail-closed. See
    /// `LocalChangeProcessor::scan_existing_files_with_ignore_gated`.
    pub(crate) fn start_gating_tombstones(
        &self,
        local_path: String,
        group_id: String,
        emit_tombstones: bool,
    ) -> Result<(), DaemonError> {
        self.start_inner(
            local_path,
            group_id,
            default_watch_source(&self.state.links),
            emit_tombstones,
        )
    }

    fn start_inner(
        &self,
        local_path: String,
        group_id: String,
        watcher_source: Arc<dyn FolderWatchSource>,
        emit_tombstones: bool,
    ) -> Result<(), DaemonError> {
        let state = &self.state;
        let watcher_source: Arc<dyn FolderWatchSource> =
            Arc::new(WatchLimitReporter { inner: watcher_source, links: state.links.clone() });
        // Close this group's startup barrier and arm its fail-closed guard FIRST,
        // before any fallible step below. `app::run` calls this for every existing
        // link *before* it spawns the peer orchestrator, so a peer change arriving
        // later observes the barrier closed and waits (in its own apply path) until
        // the startup reconciliation has published its results, instead of racing
        // the scan's stale-snapshot batch commit. Per-group: this only gates this
        // group's peer apply, never an unrelated group's.
        //
        // The ordering is load-bearing, not stylistic. Every fallible step from
        // here on -- whether in this function or inside
        // `LinkRuntimeFactory::build`, below -- drops the guard and publishes
        // `Failed` for this generation. Returning early with NO gate registered
        // would instead leave the group *absent* from the registry, and an
        // absent gate reads as Ready (`wait_group_ready`) — so a failed watcher
        // bind (OS watch limit, unmounted root, permissions) would admit peer
        // changes into a folder this boot never scanned and let them overwrite
        // un-indexed local content. Do not add a fallible step above this pair.
        // Infallible (plain `Arc` clones), so deriving it up here -- before
        // the guard-arming pair below -- does not violate that pair's own
        // "no fallible work above it" rule. Every remaining step that touches
        // the per-link runtime module tree
        // (`link_runtime.rs`/`link_runtime/operations/*.rs`) threads this
        // narrow bundle instead of `state` from here on -- see
        // `LinkRuntimeDependencies`'s own doc for why.
        let deps = state.link_runtime_dependencies();

        let startup_generation =
            state.replica_coordinator.startup_readiness().begin_group_startup(&group_id);
        let startup_ready_guard =
            GroupStartupReadyGuard::new(deps.clone(), group_id.clone(), startup_generation);

        // Below the guard-arming pair above, per that block's own rule -- and
        // itself as early as every remaining fallible step below allows: see
        // `LinkSlotStartingGuard`'s own doc for the start-vs-stop zombie-
        // runtime race a `Starting` placeholder published this early closes.
        let link_slot_guard = LinkRegistry::reserve_starting(&state.links, local_path.clone())?;

        // Nothing touches a folder that is missing or off the volume recorded
        // for it -- not even the root lock's sidecar, which would otherwise be
        // created on the volume underneath an unmounted disk and leave this
        // runtime watching and locking the wrong directory once the disk is
        // back. The link waits instead; `follow_link_volumes` starts it when
        // the folder returns. Its startup gate stays Failed meanwhile, so peer
        // changes are deferred, not applied.
        if folder_volume(state, &local_path) != FolderVolume::Available {
            state.links.mark_awaiting_volume(&local_path);
            return Err(DaemonError::Config(format!(
                "linked folder {local_path} is missing or not on the volume it was recorded on \
                 (its disk may be unmounted or replaced); it is not touched until that volume \
                 is back"
            )));
        }

        // Periodic live repair pass — see MATERIALIZATION_REPAIR_INTERVAL's doc
        // comment. Spawned here, in `LinkRuntimeController`, rather than inside
        // `LinkRuntimeFactory::build`: this is the one per-link background task
        // that needs a full `Arc<DaemonState>` (`DaemonState::root_lease_for`,
        // which resolves through `LinkRegistry` — something the `link_runtime`
        // module tree's own narrow `LinkRuntimeDependencies` bundle deliberately
        // excludes), and keeping that module tree free of `DaemonState` is what
        // keeps it out of the `daemon_state`/`link_registry` dependency cycle
        // (see this crate's own architecture-boundary checks). Its own
        // logic/closure body is unchanged from before this task-set's
        // construction moved into `LinkRuntimeFactory::build`; only its call
        // site did. First tick is deliberately delayed a full interval, NOT
        // immediate -- `tokio::time::interval`'s own first tick fires
        // immediately (a well-known gotcha, see its docs), which would race
        // this same function's own startup repair pass (inside
        // `LinkRuntimeFactory::build`, right after acquiring this link's
        // `SyncRootLock`) that already just ran once for this link before
        // its watcher started -- a confirmed, reproduced bug: an
        // immediate first tick landed microseconds after a fresh restart,
        // grabbed a just-synced file's path lock before a live incoming
        // peer edit reached it, read the disk bytes as "diverged," and
        // quarantined them. `interval_at` with an explicit first deadline
        // is what actually delays it (plain `interval` does not, despite
        // what this comment used to claim).
        let repair_state = state.clone();
        let repair_root = PathBuf::from(&local_path);
        let repair_group_id = group_id.clone();
        let repair_handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval_at(
                tokio::time::Instant::now() + MATERIALIZATION_REPAIR_INTERVAL,
                MATERIALIZATION_REPAIR_INTERVAL,
            );
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // A base install's holds are reconciled by this pass: an install
            // wakes it early (the interval is the backstop), including one
            // that landed while the previous pass was running.
            let mut installs = repair_state.replica_coordinator.subscribe_held_path();
            loop {
                tokio::select! {
                    _ = ticker.tick() => {}
                    Ok(()) = installs.changed() => {}
                }
                let replica_coordinator = repair_state.replica_coordinator.clone();
                let block_store = repair_state.block_store.clone();
                let root = repair_root.clone();
                let group_id = repair_group_id.clone();
                let root_lease = match repair_state.root_lease_for(&group_id) {
                    Ok(lease) => lease,
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            local_path = %repair_root.display(),
                            "periodic live materialization repair: no live root lease for this link"
                        );
                        continue;
                    }
                };
                // Same spawn_blocking rationale as the initial scan in the
                // executor task: this walks the whole linked folder
                // synchronously. `root_op` is admitted INSIDE the
                // closure and held for the whole repair call, including the
                // disk walk/reconstruct work that precedes its own DB commits,
                // not just their `verify`.
                let lease_to_latch = root_lease.clone();
                let repair_result = tokio::task::spawn_blocking(move || {
                    crate::link_runtime::operations::repair_materialization::repair_interrupted_materializations(
                        &replica_coordinator,
                        &block_store,
                        &root_lease,
                        &root,
                        &group_id,
                        yadorilink_filesystem_sync::materialization_repair::RepairMode::Live,
                    )
                })
                .await;
                match repair_result {
                    Ok(Ok(report)) if report.is_empty() => {}
                    Ok(Ok(report)) => tracing::info!(
                        local_path = %repair_root.display(),
                        reconstructed = report.reconstructed.len(),
                        demoted_to_placeholder = report.demoted_to_placeholder.len(),
                        "periodic live repair found and fixed a materialization/disk divergence"
                    ),
                    // Terminal: the sidecar is gone. No retry, no recreation; only relink or a
                    // daemon restart acquires a fresh lock. This link's repair work ends here.
                    Ok(Err(crate::sync_error::SyncError::OwnershipLost(msg))) => {
                        // Latch: even if the sidecar becomes observable again, no operation is
                        // admitted until a relink or restart builds a fresh lease.
                        lease_to_latch.begin_stopping();
                        if repair_state.mark_link_ownership_lost(&repair_root.to_string_lossy()) {
                            tracing::error!(
                                local_path = %repair_root.display(),
                                reason = %msg,
                                "sync-root ownership lost; this folder stops syncing until it is re-linked or the daemon restarts"
                            );
                        }
                        break;
                    }
                    Ok(Err(e)) => tracing::warn!(
                        error = %e,
                        local_path = %repair_root.display(),
                        "periodic live materialization repair failed for linked folder"
                    ),
                    Err(join_err) => tracing::warn!(
                        error = %join_err,
                        local_path = %repair_root.display(),
                        "periodic live materialization repair task panicked"
                    ),
                }
            }
        });

        // Every remaining fallible step -- the per-group/per-link pre-checks,
        // acquiring the `SyncRootLock`/building the `RootLease`, startup
        // materialization/restore repair, binding the watcher, spawning the
        // accumulator/executor/dirty-journal background tasks, and constructing
        // the `LinkFlushHandle` -- lives in `LinkRuntimeFactory::build` now.
        // This function's own remaining job is just: derive `deps`, arm the two
        // guards above, spawn `repair_handle` (above), delegate to the factory,
        // and publish the result -- see `LinkRuntimeFactory`'s own doc for the
        // exact scope split.
        //
        // `repair_handle` is already running by this point (spawned above, so
        // it's covered by the same `Starting` slot every other in-flight setup
        // step is), unlike in the pre-factory version of this function, where
        // its spawn was the second-to-last statement -- reachable only once
        // every fallible step already succeeded. `build`'s own `?` can still
        // fail after that, so its `AbortHandle` is grabbed first and explicitly
        // aborted on that path: a dropped (not aborted) `JoinHandle` would
        // otherwise leave this infinite-loop task running forever, orphaned,
        // logging "no live root lease for this link" on every tick.
        let repair_abort_handle = repair_handle.abort_handle();

        // Fail-closed for a link whose policy is already `OnDemand` from a previous run: a plain
        // (direct-filesystem) root has no on-demand mechanism, so a row committed OnDemand must not
        // silently start watching and materializing anyway. Decided here, where the daemon state owns the
        // per-root capability; a provider root never reaches this runtime at all.
        match state
            .replica_coordinator
            .link_repository()
            .materialization_policy_for_group(&group_id)
        {
            Ok(Some(yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand))
                if !state.root_allows_on_demand(&group_id) =>
            {
                repair_abort_handle.abort();
                return Err(DaemonError::Config(format!(
                    "link {local_path} (group {group_id}) is configured OnDemand, but this root is not a \
                     ready provider folder; refusing to start it fail-closed -- migrate \
                     it to eager (full-copy) mode to resume syncing"
                )));
            }
            Ok(_) => {}
            Err(e) => {
                repair_abort_handle.abort();
                return Err(DaemonError::Config(format!(
                    "cannot verify materialization policy for group {group_id}: {e}"
                )));
            }
        }

        let runtime = match LinkRuntimeFactory::new(deps).build(
            local_path.clone(),
            group_id.clone(),
            watcher_source,
            emit_tombstones,
            startup_ready_guard,
            repair_handle,
        ) {
            Ok(runtime) => runtime,
            Err(e) => {
                repair_abort_handle.abort();
                return Err(e);
            }
        };

        // Published as a single atomic slot transition (`Starting` -> `Ready`)
        // only now that every fallible step above has succeeded -- see
        // `LinkRuntime`'s own doc for why this used to be (and no longer is)
        // three separate map inserts, and `LinkSlotStartingGuard`'s own doc
        // for why the slot was reserved as `Starting` back at this function's
        // very start rather than appearing from nothing right here.
        link_slot_guard.publish(Arc::new(runtime));
        state.links.clear_awaiting_volume(&local_path);
        // A fresh start holds a fresh lock: a previous OwnershipLost no longer applies.
        state.links.clear_ownership_lost(&local_path);
        // A rebootstrap the journal records is continued now that the folder is watched
        // again; for a group with none this reads the journal and returns.
        crate::native_rebootstrap::spawn_resume(state.clone(), group_id);
        Ok(())
    }

    /// `async`, and genuinely waits for every task to actually stop, rather than
    /// just requesting cancellation and returning immediately -- the difference
    /// matters because the root lock is released at the end of this function,
    /// and a lock released while a task is still running is not actually
    /// exclusive to anyone. `abort()` alone does not make that safe: the
    /// executor task's initial scan runs inside `tokio::task::spawn_blocking`
    /// (see `start`'s own comment on why), and a blocking closure
    /// already running on Tokio's blocking thread pool cannot be interrupted
    /// mid-execution by `abort()` -- it keeps running to completion regardless,
    /// still reading/chunking files and committing index/native state writes against
    /// this root. Without awaiting the handle afterward, `stop`
    /// used to return (and the caller could immediately re-link/hand the root
    /// to another process) while that scan was still physically running,
    /// letting the still-running old scan's batch commits land against a root
    /// a new owner had already started operating on. Awaiting each handle
    /// after `abort()` blocks until the task actually observes the
    /// cancellation at its own next await point -- for the executor task, that
    /// is precisely the `spawn_blocking` scan's own `.await`, so this
    /// necessarily waits for the scan closure to finish running, not merely
    /// for cancellation to be requested.
    ///
    /// Awaiting `tasks` alone is not sufficient, though (K15): a peer session's
    /// targeted flush (`LinkFlushHandle::flush_pending_local_change` and
    /// friends) and the disk-reconcile backstop sweep
    /// (`run_disk_reconcile_backstop_sweep`) both hold their own `Arc` clone of
    /// the flush handle, reachable independent of `link_runtimes`, and can be
    /// mid-commit when this function's map removal runs. `flush_handle.fence`
    /// (a `LinkOpFence`) closes that: `begin_stopping` is called BEFORE the
    /// task-abort loop below (so no new one of those operations is admitted
    /// from this point on), and `wait_drained` is called AFTER it (so any
    /// operation already admitted -- necessarily started before `begin_
    /// stopping`, since admission and the stopping flag are checked under the
    /// same atomic re-check in `LinkOpFence::try_begin` -- has genuinely
    /// finished) before `root_lock` is allowed to drop.
    pub async fn stop(&self, local_path: &str) {
        let state = &self.state;
        // Serializes concurrent `stop` calls for the SAME
        // `local_path` (the control socket spawns one task per connection, so
        // two overlapping `Unlink`s are a real shape, not hypothetical) -- see
        // `DaemonState::link_watch_stop_locks`'s own doc for the race this
        // closes: without it, a second concurrent call can find `link_runtimes`
        // already emptied by the first and skip waiting entirely, racing ahead
        // to drop the root lock while the first call's awaited scan is still
        // genuinely running. Held for this whole function, including every
        // await below.
        let per_link_lock = state.links.stop_lock(local_path);
        let _stop_guard = per_link_lock.lock().await;
        // A stopped link is not waiting for its volume (an unlink must not leave
        // it to be started again); the volume job's own stop re-marks it through
        // the refused start that follows.
        state.links.clear_awaiting_volume(local_path);

        // Waits out a `LinkSlot::Starting` entry rather than treating it as
        // absent -- see `LinkSlotStartingGuard`'s own doc for the zombie-
        // runtime race this closes. `notified.as_mut().enable()` before the
        // re-check is technically redundant here (`link_lifecycle_notify` is
        // woken via `notify_waiters`, which tokio's own docs guarantee a
        // `Notified` future observes as soon as it is constructed, not only
        // once polled/enabled -- see `LinkOpFence::wait_drained`'s identical,
        // corrected comment) but costs nothing and is kept for the same
        // future-proofing reason.
        //
        // A `Starting` entry is only ever PEEKED here, never removed: this
        // call does not own resolving it (the in-progress `start_inner`
        // call, via `LinkSlotStartingGuard`, does), and removing then
        // re-inserting it would open its own gap -- a concurrent `reserve`
        // for the same path could observe the map momentarily empty and
        // wrongly succeed, producing two live `Starting` reservations for one
        // path. Once this loop observes `Ready`, nothing else can change that
        // entry out from under it before the actual removal just below: `per_
        // link_lock` already serializes this against every other
        // `stop` call for this path, and `LinkSlotStartingGuard::
        // reserve` refuses to touch a path that already has ANY entry
        // (`Starting` or `Ready`), so no concurrent start can clobber a
        // `Ready` entry either.
        // The wait loop and the resolving removal both now live in
        // `LinkRegistry::wait_and_take_ready` itself -- see that method's own
        // doc for the exact same reasoning (a `Starting` entry is only ever
        // peeked, never removed and re-inserted, until it resolves) that used
        // to live here.
        let Some(runtime) = state.links.wait_and_take_ready(local_path).await else { return };
        // `link_runtimes` was the only place this `Arc` was ever
        // DURABLY cloned from, so removing it there leaves exactly one
        // strong reference in the steady state -- but a genuine, narrow
        // exception exists: `RootCommitAuthorityProvider::root_lease_for`
        // (`root_commit_authority.rs`) does `self.links.runtime(&local_
        // path).map(|runtime| runtime.root_lease().clone())` -- a bare,
        // unfenced PEEK at the same registry entry, entirely outside the
        // `begin_stopping`/`wait_drained` sequencing above. That peek's
        // own `Arc<LinkRuntime>` clone is dropped the instant the
        // closure returns (no `.await` inside `root_lease_for`, so
        // nothing can suspend mid-peek) -- but on a real multi-threaded
        // runtime, that whole synchronous peek can genuinely be
        // in-flight on a DIFFERENT OS thread at the exact instant this
        // function's own removal-then-unwrap runs on this one, which is
        // an ordinary, expected data race on the refcount, not a fence
        // bug (exercised by `topology_soak_lane.rs`'s `RestartNode` op
        // racing concurrent `hydrate`/`evict` calls). The window is microsecond-scale by
        // construction, so a few bounded, near-immediate retries let it
        // clear on its own almost every time, keeping this function on
        // its normal clean-shutdown path; only a genuinely persistent
        // failure (a real bug elsewhere holding the Arc across an await,
        // which retrying cannot fix) falls through to the same graceful
        // degraded fallback `app.rs::graceful_shutdown` uses for an
        // unexpectedly-shared Arc here -- log loudly, abort the tasks and
        // drain the lease in place (`LinkRuntime::drain_shared`) rather
        // than panic the whole link-stop caller over what is, in that case,
        // still a real anomaly worth knowing about but not worth taking the
        // daemon down for.
        //
        // Admission is closed before the first attempt, not after the last: a
        // holder that is mid-operation then finds `begin_operation` refusing
        // it, finishes sooner, and lets go of its `Arc` -- and if it never
        // does, nothing it starts from here on can commit.
        runtime.root_lease().begin_stopping();
        const MAX_UNWRAP_RETRIES: u32 = 20;
        const UNWRAP_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(5);
        let mut candidate = runtime;
        let mut attempt = 0;
        let runtime = loop {
            match Arc::try_unwrap(candidate) {
                Ok(runtime) => break runtime,
                Err(shared) if attempt < MAX_UNWRAP_RETRIES => {
                    attempt += 1;
                    tokio::time::sleep(UNWRAP_RETRY_BACKOFF).await;
                    candidate = shared;
                }
                Err(shared) => {
                    tracing::error!(
                        local_path,
                        refs = Arc::strong_count(&shared),
                        attempts = attempt,
                        "stop: Arc<LinkRuntime> still shared after removal from link_runtimes \
                         and every retry; draining it in place"
                    );
                    shared.drain_shared().await;
                    return;
                }
            }
        };

        // begin_stopping -> abort+await tasks -> wait_drained -> drop root_lock,
        // in that order -- see `LinkRuntime::shutdown`'s own doc for why.
        runtime.shutdown().await;
    }

    /// Links whose timed pause is over; see `LinkRepository::timed_pauses_due`.
    pub(crate) fn timed_pauses_due(
        &self,
        now_unix: i64,
        latest_plausible_unix: i64,
    ) -> Result<Vec<String>, crate::sync_error::SyncError> {
        Ok(self
            .state
            .replica_coordinator
            .link_repository()
            .timed_pauses_due(now_unix, latest_plausible_unix)?)
    }

    /// Resumes a paused link and re-raises the group's commit follow-up so
    /// connected peers catch up. Unpausing alone only lifts the gate on
    /// *future* propagation — any change indexed *while* paused was queued
    /// locally (guarantee: `SyncState` itself is the backlog) but never
    /// followed up, since `announce_local_change` only ever checks the pause
    /// flag once, at the moment each change is first processed. Resume must
    /// therefore re-raise that follow-up itself, not just flip the flag.
    /// Peers that are already fully caught up find nothing to transfer.
    pub async fn resume(&self, local_path: &str) -> Result<(), crate::sync_error::SyncError> {
        self.resume_expecting_group(local_path, None).await
    }

    /// [`Self::resume`] that acts only if the link at `local_path` belongs to
    /// `expected_group` (when given). The group is checked before anything is flushed, and
    /// again by the write that lifts the pause; a link of another group is
    /// `SyncError::GroupMismatch` with nothing changed.
    pub async fn resume_expecting_group(
        &self,
        local_path: &str,
        expected_group: Option<&str>,
    ) -> Result<(), crate::sync_error::SyncError> {
        let state = &self.state;
        let link = state
            .replica_coordinator
            .link_repository()
            .list_links()?
            .into_iter()
            .find(|l| l.key() == local_path)
            .ok_or_else(|| crate::sync_error::SyncError::NotFound(format!("link {local_path}")))?;
        if expected_group.is_some_and(|expected| expected != link.group_id) {
            return Err(crate::sync_error::SyncError::GroupMismatch(local_path.to_string()));
        }
        if link.orphaned {
            return Err(crate::sync_error::SyncError::InvalidInput(format!(
                "cannot resume orphaned link {local_path}: its coordination-side authorization is gone"
            )));
        }
        state.replica_coordinator.link_repository().ensure_unambiguous_group(&link.group_id)?;
        // Closes the gap this fn's own doc comment doesn't cover -- a change
        // still sitting undispatched in the debounce accumulator (not yet
        // even in `SyncState`) at the moment of resume isn't part of the
        // backlog the follow-up below can see at all. Force it into the
        // index first, so the follow-up reflects this link's true current
        // state rather than racing whatever quiet-period window that
        // change's own debounce window happened to still be in. Done before
        // the pause is lifted: a failed capture then leaves the link paused
        // (a timed pause stays retryable) instead of resumed without it.
        // A link replaced since the check above still gets this flush (capture only); the
        // write that lifts the pause then refuses on the group.
        if let Some(runtime) = state.links.runtime(local_path) {
            runtime.flush_pending_local_changes(&link.group_id).await.map_err(|error| {
                crate::sync_error::SyncError::InvalidInput(format!(
                    "cannot resume {local_path}: pending local changes could not be captured \
                     first: {error}"
                ))
            })?;
        }
        state.replica_coordinator.link_repository().set_paused_expecting_group(
            local_path,
            false,
            Some(&link.group_id),
        )?;
        let group_id = link.group_id;
        match state.replica_coordinator.link_repository().link_gate_for_group(&group_id)? {
            yadorilink_replica_domain::session_state::LinkGate::Live {
                local_path: live_path,
                ..
            } if live_path == local_path => {}
            _ => {
                return Err(crate::sync_error::SyncError::InvalidInput(format!(
                    "cannot resume {local_path}: it is not the group's single live link"
                )))
            }
        }
        state.on_local_native_commit(&group_id).await;
        Ok(())
    }

    /// Runs `SyncState::expire_superseded_
    /// and_trashed_versions` for every currently-registered link, applying the
    /// fixed built-in retention policy — a version exceeding both the built-in
    /// version-count and age bounds is swept. Bounded and synchronous (SQLite
    /// calls only, no network I/O), matching this module's other maintenance
    /// sweeps (e.g. `DaemonState`'s pending-broadcast-retry loop) which also run
    /// plain `SyncState` calls directly on the async runtime rather than via
    /// `spawn_blocking` — a link's superseded/trashed backlog is bounded by
    /// the built-in retention policy, so this is not expected to be a large or
    /// slow scan. Logs (rather than propagating) a per-link failure so one link's
    /// error never stops the sweep from covering the rest — matching
    /// `resume`'s and `announce_local_change`'s existing "log and
    /// continue" error-handling shape for background maintenance work.
    /// Re-checks free space for every currently-Degraded link whose
    /// backoff window has elapsed. Thin delegate to
    /// `DaemonState::recheck_degraded_links`, which already narrows to
    /// `links`/`governance_config` internally -- this method exists only
    /// so `DegradedLinkRecheckJob` can hold the same `Arc<LinkRuntimeController>`
    /// its sibling maintenance jobs use instead of a full `Arc<DaemonState>`.
    pub(crate) fn recheck_degraded_links(&self) {
        self.state.recheck_degraded_links();
    }

    pub(crate) fn run_retention_expiry_sweep(&self) {
        let state = &self.state;
        let links = match state.replica_coordinator.link_repository().list_links() {
            Ok(links) => links,
            Err(e) => {
                tracing::warn!(error = %e, "retention-expiry sweep: failed to list links");
                return;
            }
        };
        let now_unix_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        for link in links {
            match state
                .replica_coordinator
                .expire_superseded_and_trashed_versions(&link.group_id, now_unix_nanos)
            {
                Ok(expired_count) if expired_count > 0 => {
                    tracing::debug!(
                        group_id = %link.group_id,
                        local_path = %link.key(),
                        expired_count,
                        "retention-expiry sweep removed aged-out superseded/trashed versions"
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        group_id = %link.group_id,
                        local_path = %link.key(),
                        "retention-expiry sweep failed for this link"
                    );
                }
            }
        }
    }

    /// A periodic, filesystem-watcher-event-
    /// *independent* disk-authoritative reconcile — the eventual-consistency
    /// backstop for a local write whose OS watcher event never arrives at all
    /// (e.g. an FSEvents blind window opened by `watch` tearing down and
    /// recreating its entire event stream — see `watcher.rs`'s module doc).
    /// No
    /// watcher-triggered recovery (the registrar's own `reconcile_new_
    /// directory_subtree` safety net) can reach a loss like this one, since
    /// that safety net only ever walks a *newly-registered* directory — it
    /// never revisits the *already*-watched link root, or a directory whose
    /// own creation event was itself lost.
    ///
    /// Deliberately **add-only** (`LocalChangeProcessor::reconcile_added_
    /// files`): indexes a disk file with no existing index row, and nothing
    /// else — never re-versions an already-indexed file whose on-disk content
    /// changed, never tombstones an indexed file missing from disk. Those two
    /// operations mutate an already-known path and are the ones `watcher.rs`'s
    /// module doc documents as unsafe to run this often (they can re-derive or
    /// false-delete a file mid-conflict-resolution between two devices —
    /// reproduced deterministically against the registration-mutex-contention
    /// race that made this fallback necessary). A file with no index row has never
    /// been broadcast or adopted by a peer, so indexing it carries none of
    /// that hazard — it's byte-for-byte what a live create event would have
    /// done.
    ///
    /// Skips paused links entirely: a paused link intentionally
    /// does not propagate, and indexing+broadcasting from this sweep would
    /// violate that the same way a live local change would. A link paused
    /// during a watcher-event loss is still covered once it resumes:
    /// `resume`'s own broadcast re-emits `list_files`, and the next
    /// sweep tick after resume runs normally for it.
    ///
    /// Also skips an orphaned link — its coordination-side authorization is
    /// permanently gone, so there is nothing left to sync it against. In
    /// practice this link never has a `LinkFlushHandle` to begin with (its
    /// watcher is stopped the moment `EnrollmentRecoveryService::reconcile_once` marks it
    /// orphaned, and never restarted), so the check below is defense in depth,
    /// not the primary mechanism.
    ///
    /// Skips a link with no `LinkFlushHandle` yet registered (the brief window
    /// between `add_link` and `start` completing) rather than
    /// erroring — the next tick covers it once registration finishes.
    pub(crate) async fn run_disk_reconcile_backstop_sweep(&self) {
        let state = &self.state;
        // Infallible, same as `start_inner`'s own derivation --
        // everything below that touches the per-link runtime module tree goes
        // through this narrow bundle instead of `state` from here on.
        let deps = state.link_runtime_dependencies();
        let links = match state.replica_coordinator.link_repository().list_links() {
            Ok(links) => links,
            Err(e) => {
                tracing::warn!(error = %e, "disk-reconcile-backstop: failed to list links");
                return;
            }
        };
        // One task per link, so one link's whole-folder walk (arbitrarily
        // long: a stalled volume, a huge unindexed tree) never delays the
        // others' recovery. A pass that is still running when the next sweep
        // comes round is not stacked on: that link is skipped until it
        // finishes, and this sweep stops waiting for it after
        // `SWEEP_TIME_BUDGET` instead of holding every later tick behind it.
        let mut passes = Vec::new();
        for link in links {
            if link.paused || link.orphaned {
                continue;
            }
            let Some(folder) = link.folder_path() else { continue };
            let Some(runtime) = state.links.runtime(folder) else { continue };
            let Some(claim) = state.begin_backstop_pass(folder) else {
                tracing::debug!(
                    local_path = %link.key(),
                    "disk-reconcile-backstop: the previous pass for this link is still running"
                );
                continue;
            };
            let deps = deps.clone();
            passes.push(tokio::spawn(async move {
                let _claim = claim;
                sweep_one_link(deps, runtime, link).await;
            }));
        }
        let _ =
            tokio::time::timeout(SWEEP_TIME_BUDGET, futures_util::future::join_all(passes)).await;
    }
}

/// Where a link's folder stands relative to the volume recorded for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FolderVolume {
    /// The folder exists and is on its recorded volume (or none is recorded yet).
    Available,
    /// The folder is gone or on another volume: its disk is unmounted or replaced.
    Away,
    /// It cannot be told right now (the link table or the volume could not be
    /// read). Nothing is changed on this basis.
    Unknown,
}

/// Test-only override of [`folder_volume`] per folder: `None` defers to the
/// real check; the closure may block, as a hung network mount does.
#[cfg(test)]
pub(crate) type VolumeProbeHook = Arc<dyn Fn(&str) -> Option<FolderVolume> + Send + Sync>;
#[cfg(test)]
pub(crate) static VOLUME_PROBE_HOOK: std::sync::Mutex<Option<VolumeProbeHook>> =
    std::sync::Mutex::new(None);

/// The precondition for running a link at all (see `start_inner`). Blocking:
/// it stats the folder, which can hang on a dead network mount.
fn folder_volume(state: &DaemonState, local_path: &str) -> FolderVolume {
    #[cfg(test)]
    {
        let hook = VOLUME_PROBE_HOOK.lock().unwrap_or_else(|p| p.into_inner()).clone();
        if let Some(answer) = hook.and_then(|hook| hook(local_path)) {
            return answer;
        }
    }
    match std::fs::metadata(local_path) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return FolderVolume::Away,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return FolderVolume::Away,
        Err(_) => return FolderVolume::Unknown,
    }
    match state.replica_coordinator.folder_on_capture_volume(local_path) {
        Ok(true) => FolderVolume::Available,
        Ok(false) => FolderVolume::Away,
        Err(_) => FolderVolume::Unknown,
    }
}

/// How long the volume job waits for one folder's probe. A probe that takes
/// longer (a hung network mount) is left running and answers `Unknown`; the
/// folder is not probed again until it returns.
const VOLUME_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

impl LinkRuntimeController {
    /// The user's confirmation that the disk now mounted at `local_path` is its
    /// folder's disk: the volume the folder is on now is recorded as its own,
    /// and a link waiting for its volume starts with the folder as it is (what
    /// is missing from it is then a deletion). This is how a folder on a
    /// filesystem without a stable identity is used again after every remount,
    /// and how a folder moved to another disk is accepted. Only ever reached
    /// from an explicit user action. Refused for a volume that can never be
    /// confirmed on this system: recording it would confirm nothing.
    pub async fn readopt_volume(
        &self,
        local_path: &str,
    ) -> Result<(), crate::sync_error::SyncError> {
        use crate::sync_error::SyncError;
        use yadorilink_filesystem_sync::device_boundary::{root_volume_identity, VolumeMatch};
        let state = &self.state;
        let links = state.replica_coordinator.link_repository();
        let link = links
            .list_links()?
            .into_iter()
            .find(|l| !l.orphaned && l.folder_path() == Some(local_path))
            .ok_or_else(|| SyncError::NotFound(format!("linked folder {local_path}")))?;
        links.ensure_unambiguous_group(&link.group_id)?;
        let path = std::path::PathBuf::from(local_path);
        let probe = tokio::task::spawn_blocking(move || root_volume_identity(&path));
        let current = match tokio::time::timeout(VOLUME_PROBE_TIMEOUT, probe).await {
            Ok(Ok(observed)) => observed.map_err(SyncError::Io)?,
            _ => {
                return Err(SyncError::InvalidInput(format!(
                    "the disk at {local_path} did not answer; check that it is mounted and retry"
                )))
            }
        };
        if VolumeMatch::of(None, &current) == VolumeMatch::Unconfirmed {
            return Err(SyncError::InvalidInput(format!(
                "the disk at {local_path} has no identity this system can check, so it cannot be \
                 confirmed as this folder's disk. Use a disk formatted with ext4, btrfs, ZFS or \
                 xfs (Linux 6.5 or later), or run Linux 6.8 or later"
            )));
        }
        let previous = links.capture_volume_identity_for_path(local_path)?;
        if !links.confirm_capture_volume_identity(local_path, &link.group_id, &current)? {
            return Err(SyncError::NotFound(format!("linked folder {local_path}")));
        }
        tracing::info!(local_path, volume = %current, "the user confirmed the folder's disk");
        // A runtime that still runs on the disk it was started on (remounted
        // before the volume monitor noticed) starts again, so the confirmed
        // disk is scanned as it is.
        if previous.as_deref() != Some(current.as_str())
            && state.links.runtime(local_path).is_some()
        {
            self.stop(local_path).await;
            if let Err(e) = self.start(local_path.to_owned(), link.group_id.clone()) {
                tracing::warn!(error = %e, local_path, "linked folder failed to restart after its disk was confirmed");
                // A start refused for now (a safe stop under way) is picked up by the next
                // volume pass instead of leaving the stopped link unattended.
                self.wait_unless_started(local_path);
            }
        }
        self.follow_link_volumes().await;
        // The disk is confirmed, but the folder may still be refused for another
        // reason (another group's marker, a lock held): do not claim success.
        if state.links.runtime(local_path).is_none() {
            return Err(SyncError::FolderNotStarted { local_path: local_path.to_owned() });
        }
        Ok(())
    }

    /// Follows each linked folder's volume. A running link whose folder has
    /// left its volume (the disk was unmounted, failed or replaced) is stopped
    /// and left waiting, exactly as a start in that state is refused; a waiting
    /// link whose folder is back is started, and its startup scan converges
    /// with the folder as it is. Nothing was written into the folder and no
    /// deletion was authored while it was away, so that scan only sees what
    /// genuinely changed on the volume. A running link that lost its root
    /// lock (a brief outage between two passes can do that) is restarted once
    /// its folder is available: the fresh start takes the lock again, and a
    /// root another process really owns refuses it.
    ///
    /// Folders are probed concurrently, each bounded by
    /// [`VOLUME_PROBE_TIMEOUT`], so one hung mount does not hold up the rest.
    pub async fn follow_link_volumes(&self) {
        let state = &self.state;
        let links = match state.replica_coordinator.link_repository().list_links() {
            Ok(links) => links,
            Err(e) => {
                tracing::warn!(error = %e, "link volume check: failed to list links");
                return;
            }
        };
        let probes = links.into_iter().filter(|link| !link.orphaned).filter_map(|link| {
            let folder = link.folder_path()?.to_owned();
            let claim = LinkRegistry::begin_volume_probe(&state.links, &folder)?;
            let probe_state = state.clone();
            let probe_folder = folder.clone();
            Some(async move {
                let probe = tokio::task::spawn_blocking(move || {
                    let _claim = claim;
                    folder_volume(&probe_state, &probe_folder)
                });
                let volume = match tokio::time::timeout(VOLUME_PROBE_TIMEOUT, probe).await {
                    Ok(Ok(volume)) => volume,
                    _ => FolderVolume::Unknown,
                };
                (link.group_id, folder, volume)
            })
        });
        for (group_id, folder, volume) in futures_util::future::join_all(probes).await {
            let running = state.links.runtime(&folder).is_some();
            match volume {
                FolderVolume::Away if running => {
                    tracing::warn!(
                        local_path = %folder,
                        "linked folder left its volume; stopping it until the volume is back"
                    );
                    self.stop(&folder).await;
                    // Refused while the folder is away: leaves the link waiting
                    // with its startup gate Failed.
                    if self.start(folder.clone(), group_id).is_err() {
                        // Also covers a start refused before it reached that marking (a safe
                        // stop under way): the next pass picks the link up.
                        self.wait_unless_started(&folder);
                    }
                }
                FolderVolume::Available if running && state.links.is_ownership_lost(&folder) => {
                    tracing::info!(
                        local_path = %folder,
                        "linked folder lost its root lock and is available again; restarting it"
                    );
                    self.stop(&folder).await;
                    if let Err(e) = self.start(folder.clone(), group_id) {
                        tracing::warn!(error = %e, local_path = %folder, "linked folder failed to restart");
                        // The old runtime's root lock can outlive `stop` for a moment (a scan
                        // on the blocking pool still holds it), so this start may be refused
                        // as "in use". Leave the link waiting like one whose folder is away:
                        // the next pass starts it. Without this nothing ever would.
                        self.wait_unless_started(&folder);
                    }
                }
                FolderVolume::Available
                    if !running
                        && !state.links.has_entry(&folder)
                        && state.links.is_awaiting_volume(&folder) =>
                {
                    tracing::info!(local_path = %folder, "linked folder is back on its volume; starting it");
                    if let Err(e) = self.start(folder.clone(), group_id) {
                        tracing::warn!(error = %e, local_path = %folder, "linked folder is back but failed to start");
                    }
                }
                _ => {}
            }
        }
    }
}

impl LinkRuntimeController {
    /// Leaves a link waiting for the next pass after a refused restart, unless
    /// something else (a start that ran while `stop` was awaited) already holds
    /// its slot: marking that live link would close its peer apply for good.
    pub(crate) fn wait_unless_started(&self, folder: &str) {
        if !self.state.links.has_entry(folder) {
            self.state.links.mark_awaiting_volume(folder);
        }
    }
}

/// How long one backstop sweep waits for the per-link passes it started
/// before it returns and leaves the unfinished ones running.
#[cfg(not(test))]
const SWEEP_TIME_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);
#[cfg(test)]
const SWEEP_TIME_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);

/// Test-only: called at the start of each link's blocking reconcile with the
/// link's local path; may block.
#[cfg(test)]
type BackstopProbe = Arc<dyn Fn(&str) + Send + Sync>;
#[cfg(test)]
static BACKSTOP_PROBE: std::sync::Mutex<Option<BackstopProbe>> = std::sync::Mutex::new(None);

/// One link's backstop pass: the add-only reconcile, then the announcement of
/// whatever it recovered.
async fn sweep_one_link(
    deps: Arc<crate::link_runtime::dependencies::LinkRuntimeDependencies>,
    runtime: Arc<crate::link_runtime::LinkRuntime>,
    link: yadorilink_replica_domain::session_state::FolderLink,
) {
    // Held for this whole pass so `stop`'s
    // `wait_drained` genuinely waits for it -- see `RootLease`'s own
    // doc; this is the second of the two call sites (`LinkFlushHandle`'s
    // own methods are the other) that used to let a write land after
    // the root lock had already been handed to a new owner (K15).
    // `reconcile_added_files_from_disk` itself refuses admission (and
    // returns `None`) once `stop` has called
    // `begin_stopping` for this link.
    let _write_activity = deps.begin_write_activity();
    // `reconcile_added_files_from_disk` is synchronous and open-ended:
    // it loads the link's ignore set from disk, reads the group's whole
    // index out of SQLite, then `walkdir`s the entire link folder and,
    // for every path with no index row, reads/chunks/SHA-256s the file
    // and writes its blocks. That is exactly the work the *initial*
    // scan already offloads (`link_runtime/tasks.rs`'s `spawn_blocking`
    // around `scan_existing_files_with_ignore_gated`), and the case
    // this backstop exists for -- a watcher that never bound, or lost
    // its events -- is precisely the case where the whole folder is
    // unindexed, so a single pass can be arbitrarily long. It runs on the
    // blocking pool, so neither the worker that polls the sweep nor
    // another link's pass waits for it.
    let group_id = link.group_id.clone();
    #[cfg(test)]
    let probed_path = link.key().to_string();
    let reconciled = tokio::task::spawn_blocking(move || {
        #[cfg(test)]
        {
            let probe = BACKSTOP_PROBE.lock().unwrap_or_else(|p| p.into_inner()).clone();
            if let Some(probe) = probe {
                probe(&probed_path);
            }
        }
        runtime.reconcile_added_files_from_disk(&group_id)
    })
    .await;
    let reconciled = match reconciled {
        Ok(reconciled) => reconciled,
        Err(join_error) => {
            tracing::warn!(
                error = %join_error,
                local_path = %link.key(),
                "disk-reconcile-backstop pass panicked for this link"
            );
            return;
        }
    };
    let Some(result) = reconciled else {
        return;
    };
    match result {
        Ok(records) if !records.is_empty() => {
            tracing::info!(
                group_id = %link.group_id,
                local_path = %link.key(),
                count = records.len(),
                "disk-reconcile-backstop recovered file(s) never delivered by the local \
                 filesystem watcher"
            );
            announce_local_change(&deps, link.key(), &link.group_id, records).await;
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(
                error = %e,
                group_id = %link.group_id,
                local_path = %link.key(),
                "disk-reconcile-backstop failed for this link"
            );
        }
    }
}

#[cfg(test)]
mod tests;

/// Wraps a link's watch source so an exhausted OS watch limit is recorded
/// where `status` and `doctor` read it, instead of only reaching the log.
struct WatchLimitReporter {
    inner: Arc<dyn FolderWatchSource>,
    links: Arc<LinkRegistry>,
}

impl FolderWatchSource for WatchLimitReporter {
    fn watch(
        &self,
        root: &std::path::Path,
        ignore_set: Arc<yadorilink_fs_platform::ignore_patterns::EffectiveIgnoreSet>,
    ) -> Result<
        yadorilink_filesystem_sync::watcher::FolderWatcher,
        yadorilink_filesystem_sync::watcher::WatcherError,
    > {
        let key = root.to_string_lossy();
        match self.inner.watch(root, ignore_set) {
            Ok(watcher) => {
                self.links.track_watcher(&key, watcher.watch_limited_flag());
                Ok(watcher)
            }
            Err(err) => {
                if err.is_watch_limit() {
                    self.links.record_watch_limit_startup_failure(&key);
                } else {
                    self.links.clear_watch_limit(&key);
                }
                Err(err)
            }
        }
    }
}
