//! `MaterializationRepairJob` -- relocated byte-identically from this
//! crate's former `daemon_state::spawn_materialization_repair_scheduler`.
//! Periodic, daemon-wide live repair pass: for every non-orphaned link's
//! group, backfills any change history a policy-withheld initial import
//! omitted, then asks one connected peer (round-robin across
//! this job's own `cursors`, so a slow/incomplete peer is never
//! selected forever) to reconcile this device's local materialization
//! audit against its own. Interval-only -- no startup-immediate run
//! (see the inventory's own "no new startup runs" constraint); this
//! job's sweep never ran at startup before this reorganization, and
//! still doesn't.
//!
//! Holds a full `Arc<DaemonState>` rather than a narrower bundle: its
//! real dependencies (`sync_state`, `peers`,
//! `backfill_missing_change_history`) span daemon-wide
//! coordination state broader than any existing narrow port, and
//! inventing a new bespoke port for one job's sake would be exactly the
//! kind of speculative abstraction this pass is meant to avoid --
//! mirrors `LinkRuntimeController::start_inner`'s own periodic
//! materialization-repair task, which for the identical reason
//! (`DaemonState::root_lease_for`) also keeps a full `Arc<DaemonState>`
//! instead of the narrower `LinkRuntimeDependencies` bundle the rest of
//! that module tree uses.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::daemon_state::DaemonState;

pub(crate) struct MaterializationRepairJob {
    state: Arc<DaemonState>,
    /// group_id -> next candidate offset for this job's per-group peer
    /// rotation, so a slow or incomplete peer is not selected forever.
    /// Advanced only by this job's own sweep. Lives as long as this job,
    /// which `spawn_materialization_repair_task` builds exactly once per
    /// `DaemonState` (outside `spawn_restarting`'s per-restart factory), so
    /// the rotation survives a panic-restart of the sweep loop and resets
    /// only when a new `DaemonState` is constructed -- the same lifetime it
    /// had as a `DaemonState` field.
    cursors: Mutex<HashMap<String, usize>>,
}

impl MaterializationRepairJob {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state, cursors: Mutex::new(HashMap::new()) }
    }

    /// Read fresh on every call (mirrors `PeerSyncSession`'s own
    /// `resync_handle` loop reading `maintenance_reconcile_interval()` fresh
    /// each time) rather than a `tokio::time::interval` fixed once at
    /// spawn time, so `set_materialization_repair_sweep_interval` takes
    /// effect on the very next sleep -- see
    /// `DaemonState::materialization_repair_sweep_interval`'s own doc for
    /// why a fixed-period interval would make that setter silently inert
    /// for an already-running daemon (every test call site).
    pub(crate) fn sweep_interval(&self) -> Duration {
        self.state.materialization_repair_sweep_interval()
    }

    pub(crate) async fn run_once(&self) {
        // Test-only panic-injection seam, proving the restart-supervision
        // fix this pairs with (`spawn_materialization_repair_task` below,
        // via `spawn_restarting`) actually recovers a real panic in this
        // exact call path -- not just exercising `spawn_restarting`'s own
        // already-tested generic mechanism in isolation. Compiled out
        // entirely in production; zero behavioral effect outside `#[cfg(test)]`.
        #[cfg(test)]
        {
            let flag = TEST_PANIC_ON_NEXT_RUN_ONCE.swap(false, std::sync::atomic::Ordering::SeqCst);
            if flag {
                panic!("materialization repair: test-injected panic");
            }
        }
        let state = &self.state;
        let groups: HashSet<String> = match state.replica_coordinator.link_repository().list_links()
        {
            // An orphaned link's coordination-side authorization is
            // confirmed gone, so there is no valid peer edge left to
            // request a repair from -- skip it the same way a paused
            // link's watcher already keeps it out of this set in
            // practice (no `LinkFlushHandle` to drive repair against).
            Ok(links) => {
                links.into_iter().filter(|link| !link.orphaned).map(|link| link.group_id).collect()
            }
            Err(e) => {
                tracing::warn!(error = %e, "materialization repair failed to list links");
                return;
            }
        };
        for group_id in groups {
            let candidates = state.peers.sessions_for_group(&group_id);
            if candidates.is_empty() {
                tracing::debug!(
                    local_device_id = %state.device_id,
                    group_id,
                    "materialization repair: no live peer sessions for this group this sweep"
                );
                continue;
            }
            let start = {
                let mut cursors = self.cursors.lock().unwrap_or_else(|p| p.into_inner());
                let cursor = cursors.entry(group_id.clone()).or_insert(0);
                let start = *cursor % candidates.len();
                *cursor = (start + 1) % candidates.len();
                start
            };
            // Full per-sweep
            // trace (ordered candidate list, cursor start, which peer got
            // asked, and that peer's own result) to distinguish real
            // round-robin starvation from genuinely unrepairable content --
            // see the tracked comment on `randomized_soak_converges_with_
            // no_leaks_or_stuck_state` in `topology_soak_lane.rs`.
            let ordered_candidates: Vec<&str> =
                candidates.iter().map(|(id, _)| id.as_str()).collect();
            tracing::debug!(
                local_device_id = %state.device_id,
                group_id,
                ?ordered_candidates,
                start,
                "materialization repair: sweep starting"
            );
            // Stopping at the first `Ok(_)` would starve peers, not just
            // be an efficiency choice -- `reconcile_local_materialization_audit`
            // returns `Ok(true)` for "the audit ran without an outer I/O
            // error", not "this device's materialization is now complete"
            // (a per-file `RetryRequired` is intentionally folded into
            // `Ok(())` inside `rematerialize_one_record`, since
            // re-candidacy is driven by `list_materialization_repair_
            // candidates`'s own DB state, not this return value). A
            // full-replica device could then ask the same first-in-list
            // peer every sweep and never try its other live peers, because
            // that first peer's audit reliably returns `Ok(_)` (itself only
            // partially materialized, so it has nothing to contribute).
            // Every live candidate is asked every sweep -- bounded by this
            // group's live session count, same as before -- so a peer that
            // actually holds the missing content is never starved out by
            // an earlier peer's no-op success.
            let mut any_ok = false;
            let mut last_error = None;
            for offset in 0..candidates.len() {
                let (peer_id, session) = &candidates[(start + offset) % candidates.len()];
                let result = match state.peers.local_convergence(peer_id) {
                    Some(local) => {
                        local
                            .reconcile_local_materialization_audit(&(session.clone() as std::sync::Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>), &group_id)
                            .await
                    }
                    None => Ok(false),
                };
                tracing::debug!(
                    local_device_id = %state.device_id,
                    group_id,
                    peer = %peer_id,
                    offset,
                    ok = result.is_ok(),
                    "materialization repair: peer attempt finished"
                );
                match result {
                    Ok(_) => any_ok = true,
                    Err(e) => {
                        tracing::warn!(
                            group_id,
                            peer = %peer_id,
                            error = %e,
                            "materialization repair peer failed; trying another peer"
                        );
                        last_error = Some(e);
                    }
                }
            }
            tracing::debug!(
                local_device_id = %state.device_id,
                group_id,
                any_ok,
                "materialization repair: sweep finished"
            );
            if !any_ok {
                if let Some(e) = last_error {
                    tracing::warn!(
                        group_id,
                        error = %e,
                        "materialization repair failed for every available peer"
                    );
                }
            }
        }
        // Paired with `TEST_PANIC_ON_NEXT_RUN_ONCE` above -- only reached on
        // a normal (non-panicking) completion, so a test can distinguish
        // "this call panicked" from "this call ran to completion" by
        // watching this counter rather than the panic itself.
        #[cfg(test)]
        TEST_RUN_ONCE_COMPLETIONS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
pub(crate) static TEST_PANIC_ON_NEXT_RUN_ONCE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
pub(crate) static TEST_RUN_ONCE_COMPLETIONS: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(0);

/// Spawns the periodic materialization-repair sweep as a restartable task
/// -- extracted from `maintenance_coordinator::run` into its own function
/// so the spawn wiring (specifically: does a panic in `run_once` actually
/// get recovered, not just logged-and-abandoned) is directly testable
/// without spinning up every other task that coordinator also spawns.
/// `spawn_restarting`, not `spawn_logged`: this job is the sole mechanism
/// that re-arms an OnDemand->Eager materialization-policy promotion (and
/// the hazard/ignore-recheck-adjacent repair-candidate class of work), so
/// an unhandled panic anywhere in `run_once`'s own call path must not
/// silently and permanently disable it for the rest of the process's life.
///
/// The job is built once, here, and shared into every restart's task (not
/// rebuilt inside the restart factory), so its peer-rotation `cursors`
/// keep their position across a panic-restart.
pub(crate) fn spawn_materialization_repair_task(
    state: Arc<DaemonState>,
) -> tokio::task::JoinHandle<()> {
    let materialization_repair_job = Arc::new(MaterializationRepairJob::new(state));
    crate::supervise::spawn_restarting(
        "daemon-state-materialization-repair",
        crate::supervise::BackoffConfig::MATERIALIZATION_REPAIR,
        move || {
            let materialization_repair_job = materialization_repair_job.clone();
            async move {
                loop {
                    tokio::time::sleep(materialization_repair_job.sweep_interval()).await;
                    materialization_repair_job.run_once().await;
                }
            }
        },
    )
}

#[cfg(test)]
mod tests;
