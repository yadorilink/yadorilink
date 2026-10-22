//! `LinkRuntimeFactory`: builds a fully-wired [`super::LinkRuntime`] for one
//! link -- every fallible step of what used to be
//! the daemon's own `LinkRuntimeController::start_inner`'s body, from the per-group
//! fail-closed pre-checks through spawning every background task
//! ([`super::tasks`]) and constructing the `LinkFlushHandle`.
//!
//! Deliberately does NOT touch the `LinkRegistry` `Starting` slot or
//! publish anything into it -- the daemon's own `LinkRuntimeController` still owns reserving that
//! slot (before calling [`LinkRuntimeFactory::build`]) and publishing the
//! runtime this returns (after it succeeds). See that module's own
//! `start_link_watch_inner` for why: the guard-arming pair
//! (`begin_group_startup` + `GroupStartupReadyGuard::new`) and the
//! `Starting` reservation must both happen before any fallible step
//! anywhere in the combined call chain, and the daemon's own `LinkRuntimeController` is what
//! constructs the guard and threads it in as `build`'s
//! `startup_ready_guard` parameter.
//!
//! `build` stays entirely free of `DaemonState`: the one background task
//! that needs it (the periodic live materialization-repair task, via
//! `DaemonState::root_lease_for`, which resolves through `LinkRegistry` --
//! not this module tree's own narrow `LinkRuntimeDependencies` bundle) is
//! spawned by the daemon's own `LinkRuntimeController` itself, which passes the resulting
//! `JoinHandle` in as `build`'s `repair_handle` parameter. Keeping this
//! whole module tree `DaemonState`-free is what keeps it out of the
//! `daemon_state`/`link_registry` dependency cycle (see this crate's own
//! architecture-boundary checks) -- every other step below reaches
//! `replica_coordinator`/`block_store` through `self.deps`, never through a
//! daemon-wide state handle.

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::task::JoinHandle;
use yadorilink_filesystem_sync::debounce;
use yadorilink_filesystem_sync::watcher::FolderWatchSource;
use yadorilink_fs_platform::ignore_patterns::EffectiveIgnoreSet;

use crate::error::DaemonError;
use crate::link_runtime::dependencies::LinkRuntimeDependencies;
use crate::link_runtime::startup::{build_change_processor, GroupStartupReadyGuard};
use crate::link_runtime::tasks;
use crate::link_runtime::LinkRuntime;

pub(crate) struct LinkRuntimeFactory {
    deps: Arc<LinkRuntimeDependencies>,
}

impl LinkRuntimeFactory {
    pub(crate) fn new(deps: Arc<LinkRuntimeDependencies>) -> Self {
        Self { deps }
    }

    /// Builds and returns a fully-wired `LinkRuntime` -- every fallible
    /// step of the old `start_link_watch_inner` body, from the
    /// per-group/per-link pre-checks through spawning every background
    /// task and constructing the `LinkFlushHandle`. Does NOT touch the
    /// `LinkRegistry` `Starting` slot or publish anything -- the caller
    /// still owns that (see this module's own doc comment).
    ///
    /// `repair_handle` is the periodic live materialization-repair task's
    /// already-spawned `JoinHandle` -- the daemon's own `LinkRuntimeController` spawns that one
    /// task itself (it needs a full `Arc<DaemonState>`, which this
    /// function deliberately never takes) and passes the handle straight
    /// through into the same task-set every other spawned task here joins.
    pub(crate) fn build(
        &self,
        local_path: String,
        group_id: String,
        watcher_source: Arc<dyn FolderWatchSource>,
        emit_tombstones: bool,
        startup_ready_guard: GroupStartupReadyGuard,
        repair_handle: JoinHandle<()>,
    ) -> Result<LinkRuntime, DaemonError> {
        let deps = &self.deps;

        // Below the guard-arming pair the daemon's own `LinkRuntimeController::start_inner`
        // already armed before calling this -- and itself as early as every
        // remaining fallible step below allows: this `?` drops the guard and
        // publishes `Failed` for this group's generation, which is exactly
        // the intended outcome -- the group refuses to sync, loudly, while
        // every other group on this device carries on.
        //
        // Checked here, up front, rather than left to the scan inside the
        // spawned executor task below: this refusal is deterministic, and
        // the executor's failure disposition RETRIES to
        // `STARTUP_MAX_ATTEMPTS`, which would turn one actionable error into
        // N identical log lines that no retry can fix.
        deps.replica_coordinator
            .link_repository()
            .ensure_unambiguous_group(&group_id)
            .map_err(crate::sync_error::SyncError::from)?;

        // A provider-backed root never enters the filesystem runtime (no watch, no scan, no
        // capture, no tombstones), ready or not, and a root with inconsistent provider state
        // is refused ("rebootstrap required"): only a plain root starts here.
        crate::provider_gate::require_filesystem_root(&deps.replica_coordinator, &group_id)
            .map_err(|e| DaemonError::Config(format!("link {local_path}: {e}")))?;

        // Sync-root single-instance ownership (hold and verify
        // ownership for each linked root). A conflict here
        // drops the guard and publishes `Failed` for this group, which is
        // the correct outcome -- a root already owned by another process
        // must not be watched at all, let alone scanned. Held in a local
        // binding, NOT registered into the registry yet: every remaining
        // step in this function is fallible (`?`), and an early return
        // must drop this and release the OS lock immediately so a retried
        // `start_link_watch` call for the same root is not blocked by this
        // same process's own abandoned attempt. It is moved into the
        // registry only by the caller's own
        // `link_slot_guard.publish(...)`, once this whole function has
        // already succeeded.
        let root_lock = yadorilink_root_authority::sync_root_lock::SyncRootLock::acquire(
            Path::new(&local_path),
        )?;
        // Monotonic per-attempt identifier -- not persisted, not compared
        // against anything; exists purely so a `RootLease` (and every log line
        // that includes it) can be told apart from a previous or subsequent
        // attempt for the same path within one process's lifetime.
        static NEXT_ROOT_LEASE_GENERATION: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(1);
        let root_lease = Arc::new(yadorilink_root_authority::root_commit::RootLease::new(
            root_lock,
            group_id.clone(),
            NEXT_ROOT_LEASE_GENERATION.fetch_add(1, Ordering::SeqCst),
        ));

        // Interrupted-materialization/restore-operation repair for THIS link,
        // now that its `SyncRootLock` is held and `root_lease` can admit real
        // `LinkOperation`s -- moved here (from a pre-`DaemonState`,
        // no-real-authority pass in `app::run`) so repair goes through the
        // exact same lease every other mutation for this link uses, instead of
        // a startup-only stand-in that could not actually exclude a concurrent
        // unlink/relink for the same path. Runs while this link's `LinkSlot` is
        // still `Starting` -- visible (so a racing `stop_link_watch` waits for
        // it via `LinkSlotStartingGuard`) but not yet serving anything.
        let stale_root_tmp = deps
            .replica_coordinator
            .remove_recorded_temp_files(&group_id, Path::new(&local_path))
            .map_err(crate::sync_error::SyncError::from)?;
        // Structural-directory intents a dead process left for this group
        // (startup keeps the ones whose root it could not look at).
        if let Err(error) =
            deps.replica_coordinator.resolve_structural_intents_at_link_start(&group_id)
        {
            tracing::warn!(%error, group_id = %group_id, "could not resolve structural-directory intents at link start");
        }
        if !stale_root_tmp.is_empty() {
            tracing::info!(
                count = stale_root_tmp.len(),
                local_path = %local_path,
                "removed stale temp files from linked folder on startup"
            );
        }
        {
            let report =
                crate::link_runtime::operations::repair_materialization::reconcile_restore_operations(
                    &deps.replica_coordinator,
                    &root_lease,
                    Path::new(&local_path),
                    &group_id,
                )?;
            if !report.committed.is_empty()
                || !report.discarded_unstarted.is_empty()
                || !report.preserved_divergent.is_empty()
            {
                tracing::info!(
                    local_path = %local_path,
                    committed = report.committed.len(),
                    discarded_unstarted = report.discarded_unstarted.len(),
                    preserved_divergent = report.preserved_divergent.len(),
                    "reconciled interrupted restore operations on startup"
                );
            }
        }
        // Fail-closed: a materialization-repair error for THIS link must not
        // abort every other link's startup (unlike the restore-reconciliation
        // `?` above, this is `repair_interrupted_materializations`'s
        // pre-existing soft-fail contract -- see `emit_tombstones`'s own doc
        // below for why a repair failure defers this boot's delete emission
        // instead of refusing to start the watch at all).
        let repair_succeeded = {
            match crate::link_runtime::operations::repair_materialization::repair_interrupted_materializations(
                &deps.replica_coordinator,
                &deps.block_store,
                &root_lease,
                Path::new(&local_path),
                &group_id,
                yadorilink_filesystem_sync::materialization_repair::RepairMode::Startup,
            ) {
                Ok(report) => {
                    if !report.is_empty() {
                        tracing::info!(
                            local_path = %local_path,
                            reconstructed = report.reconstructed.len(),
                            demoted_to_placeholder = report.demoted_to_placeholder.len(),
                            failed = report.failed.len(),
                            "repaired interrupted materializations found on startup"
                        );
                    }
                    // A path the pass could not finish defers this boot's
                    // delete emission exactly as a failed pass does; the
                    // pass only no longer stops at it.
                    report.failed.is_empty()
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        local_path = %local_path,
                        "failed to run startup materialization repair for linked folder; \
                         deferring this boot's initial-scan delete emission for it"
                    );
                    false
                }
            }
        };
        // The additive-scan window, read HERE rather than at the caller, and ANDed
        // with whatever the caller already decided.
        //
        // A recovery out of the two-live-roots state arms this flag on the surviving
        // link: the folder that was unlinked leaves its rows behind in this group's
        // index (`DELETE FROM files` is only ever keyed by path), and the scan below
        // is root-scoped and authoritative, so without this it reads every one of
        // them as deleted and tombstones them to every device -- the remedy
        // destroying the files it was meant to save.
        //
        // Every `start_link_watch*` variant reaches this line via
        // the daemon's own `LinkRuntimeController`'s own entry points.
        //
        // A failure to READ the flag suppresses too: "I could not tell" must never
        // resolve to "deleting is fine".
        let suppress_after_recovery = match deps
            .replica_coordinator
            .link_repository()
            .suppress_tombstones_for_group(&group_id)
        {
            Ok(suppress) => suppress,
            Err(e) => {
                tracing::error!(
                    group_id = %group_id,
                    error = %e,
                    "cannot tell whether this group's scan must be additive; suppressing its \
                     deletions for this run"
                );
                true
            }
        };
        let emit_tombstones = emit_tombstones && !suppress_after_recovery && repair_succeeded;

        // Bind the watcher *before* the initial scan below: `notify` starts
        // buffering OS-level events into its channel as soon as it's created,
        // so any file created mid-scan is still caught (see `scan_existing_files`'s
        // doc comment for why the scan is needed at all — a watcher alone only
        // reports changes from the moment it starts). The accumulator task
        // (spawned below) starts draining those events immediately, but the
        // executor task doesn't consume the flushes it produces until after
        // the scan below completes — matching the original ordering guarantee
        // even though accumulation and scanning now happen concurrently.
        let ignore_set = Arc::new(EffectiveIgnoreSet::load_for_link_root(Path::new(&local_path))?);
        let watcher = watcher_source
            .watch(Path::new(&local_path), ignore_set.clone())
            .map_err(crate::sync_error::SyncError::from)?;
        // `root_lease` (constructed above, right after acquiring this link's
        // `SyncRootLock`) backs both `processor`'s `RootCommitPermit`s and the
        // `LinkFlushHandle` this link's targeted-flush/backstop paths admit
        // through -- one lease per link, not two independently-stopped ones
        // that could disagree about whether this link is still live.
        let processor = Arc::new(build_change_processor(deps, &group_id, root_lease.clone())?);

        let root = PathBuf::from(&local_path);

        let (flush_tx, flush_rx) =
            tokio::sync::mpsc::channel(debounce::DEFAULT_EXECUTOR_CHANNEL_CAPACITY);
        // A small
        // channel is enough — a targeted flush request is a single in-flight
        // round trip per racing path, not a backlog like `flush_tx` above.
        let (flush_request_tx, flush_request_rx) = tokio::sync::mpsc::channel(4);
        // Same sizing
        // rationale as `flush_request_tx` above — a single in-flight round
        // trip per resume, not a backlog.
        let (flush_all_request_tx, flush_all_request_rx) = tokio::sync::mpsc::channel(4);

        let executor_handle = tasks::spawn_executor_task(
            deps.clone(),
            local_path.clone(),
            group_id.clone(),
            processor.clone(),
            root.clone(),
            ignore_set.clone(),
            emit_tombstones,
            startup_ready_guard,
            flush_rx,
        );

        let (events_rx, overflowed, watcher_guard) = watcher.split();
        let accumulator_handle = tasks::spawn_accumulator_task(
            events_rx,
            overflowed,
            watcher_guard,
            flush_tx,
            flush_request_rx,
            flush_all_request_rx,
        );

        // Built now, but not registered into the registry until the caller's
        // own `link_slot_guard.publish(...)` -- see that call's own comment
        // for why a peer session must never be able to observe a runtime for
        // this link without every one of its parts (tasks, flush handle,
        // root lock) simultaneously reachable.
        let flush_handle =
            Arc::new(crate::link_runtime::operations::capture_local_change::LinkFlushHandle::new(
                deps,
                flush_request_tx,
                flush_all_request_tx,
                processor.clone(),
                root.clone(),
                local_path.clone(),
                root_lease.clone(),
            ));

        // `repair_handle` (the periodic live materialization-repair task) was
        // already spawned by the caller before calling this function -- see
        // this function's own doc comment for why -- and is simply joined
        // into the same task-set as every task spawned here.

        // Live backstop for `redrive_dirty_journal` -- see
        // `tasks::DIRTY_JOURNAL_REDRIVE_INTERVAL`'s doc comment for why this
        // exists as its own periodic task rather than relying on the
        // startup-only rescan above or a coincidental re-touch of the same
        // path. A fresh `LocalChangeProcessor` clone (cheap -- it only holds
        // `Arc` references) rather than reusing the executor task's: see
        // `tasks::spawn_dirty_journal_task`'s own doc comment.
        let dirty_journal_handle = tasks::spawn_dirty_journal_task(
            processor.clone(),
            deps.clone(),
            root.clone(),
            local_path.clone(),
            group_id.clone(),
        );

        Ok(LinkRuntime::new(
            vec![accumulator_handle, executor_handle, repair_handle, dirty_journal_handle],
            flush_handle,
            root_lease,
        ))
    }
}
