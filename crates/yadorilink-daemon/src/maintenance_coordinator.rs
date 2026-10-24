//! Owns spawning every one of this daemon's periodic background
//! maintenance tasks: the update-check scheduler, the pending-report retry
//! sweep, materialization repair, the Convergence Engine's own scheduler
//! loop, degraded-link recheck, retention expiry,
//! membership recovery, the disk-reconcile backstop, and the idle-triggered
//! GC scheduler.
//!
//! This module holds the SPAWNING CODE, kept out of `DaemonState::new`'s
//! own body -- `DaemonState::new` calls `start` as a single line. The
//! production composition root (`app::run`) builds the state with
//! `DaemonState::build` and calls `start` itself, so it controls exactly
//! when maintenance begins relative to the rest of its wiring.
//!
//! Most of these tasks are named job types under `crate::maintenance`,
//! each with a `run_once` method holding the sweep/check logic. This module's own remaining job is
//! exactly what its name says: construct each job (deriving its narrow
//! dependencies from `state`), then spawn a small loop per job that calls
//! `run_once` -- every loop-shape/interval/supervision-strategy choice
//! below (`spawn_logged` vs `spawn_restarting`, which jobs run once
//! immediately at startup, which don't) lives here; the sweep bodies live
//! in their own files.
//! No queue unification, no `ConvergenceWork` enum, no priority
//! scheduling, no dedup, no event-driven enqueue -- every task below keeps
//! its own independent spawn, own interval, own supervision strategy
//! (`spawn_logged` vs `spawn_restarting`), completely unchanged.

use std::sync::Arc;

use crate::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use crate::daemon_state::{
    DaemonState, RETENTION_EXPIRY_SWEEP_INTERVAL, ROLE_LOSS_RECONCILIATION_SWEEP_INTERVAL,
};
use crate::maintenance::degraded_link_recheck::DegradedLinkRecheckJob;
use crate::maintenance::disk_reconcile_backstop::DiskReconcileBackstopJob;
use crate::maintenance::durability_confirmation::DurabilityConfirmationJob;
use crate::maintenance::gc_idle::GcIdleJob;
use crate::maintenance::link_volume::LinkVolumeJob;
use crate::maintenance::pause_expiry::PauseExpiryJob;
use crate::maintenance::recovery::RecoveryJob;
use crate::maintenance::replacement_confirm::ReplacementConfirmJob;
use crate::maintenance::retention_expiry::RetentionExpiryJob;
#[cfg(not(test))]
#[cfg(feature = "process-model")]
use crate::maintenance::update_check::UpdateCheckJob;
use crate::supervise;

/// Spawns every periodic background maintenance task this daemon runs for
/// the rest of its life. Called once, synchronously, from
/// `DaemonState::new` right after `state` itself is fully constructed.
///
/// `application` is the daemon's shared `ApplicationServices`, or `None` to
/// build a private one (see below).
///
/// Returns the daemon's single [`RecoveryJob`], so the caller can schedule
/// the enrollment sweep (which must wait for the coordination-plane config)
/// through the same owner instead of building a second one.
pub(crate) fn start(
    state: &Arc<DaemonState>,
    application: Option<&crate::application::ApplicationServices>,
) -> Arc<RecoveryJob> {
    let controller = Arc::new(LinkRuntimeController::new(state.clone()));
    // The recovery workflows live in the application services. Production
    // (`app.rs`) passes the one instance it also hands the control socket,
    // so a sweep and a live command cannot diverge. `DaemonState::new` (the
    // test-compat wrapper, which has no control socket) passes `None` and
    // gets a private instance here.
    let owned;
    let application = match application {
        Some(application) => application,
        None => {
            owned = crate::adapters::build_application_services(state.clone());
            &*owned
        }
    };
    let recovery_job = Arc::new(RecoveryJob::new(application));
    // Periodic background update
    // checks with jitter, honoring `automatic_checks_enabled` (a
    // disabled policy just means this loop's iteration is a no-op,
    // not that the loop stops running — `yadorilink update check`
    // must still work regardless, per the spec's "Automatic checks
    // disabled" scenario). A failed check retries sooner
    // (`UPDATE_CHECK_RETRY`'s shorter, doubling backoff) than the
    // steady-state success interval (`UPDATE_CHECK_INTERVAL`).
    // The periodic update-check scheduler is the daemon's only startup
    // path that performs a real outbound HTTP request (`reqwest`, via
    // `UpdateManager::check_now`). The `UpdateManager` itself is
    // constructed regardless of whether this loop runs, so
    // `yadorilink update check` and control-socket requests work.
    // Unit tests construct many short-lived states in one process. Starting
    // a real, immediate HTTP check for each one both leaks work past the
    // test body and can overwrite the update-policy fixture another test
    // is asserting. Integration tests still compile this crate normally,
    // so production-like scheduler coverage remains available there.
    #[cfg(all(not(test), feature = "process-model"))]
    {
        let update_check_job = UpdateCheckJob::new(state.update_manager.clone());
        supervise::spawn_logged("daemon-state-update-check-scheduler", async move {
            let mut consecutive_failures: u32 = 0;
            loop {
                // Periodic update checks at daemon startup
                // and on an interval — the startup check runs first
                // (immediately, no delay), and every subsequent iteration
                // waits out the jittered steady-state interval, or a
                // shorter jittered backoff after a failure.
                match update_check_job.run_once().await {
                    None => {}
                    Some(Ok(_)) => consecutive_failures = 0,
                    Some(Err(e)) => {
                        consecutive_failures = consecutive_failures.saturating_add(1);
                        tracing::warn!(error = %e, consecutive_failures, "update check failed");
                    }
                }
                let delay = if consecutive_failures == 0 {
                    supervise::BackoffConfig::UPDATE_CHECK_INTERVAL.next(0)
                } else {
                    supervise::BackoffConfig::UPDATE_CHECK_RETRY.next(consecutive_failures - 1)
                };
                tokio::time::sleep(delay).await;
            }
        });
    }
    // The background queue-retry
    // sweep, spawned unconditionally like the other periodic tasks
    // below — it is a no-op (no network call at all) until the user
    // opts into `queue_retry_enabled` and configures an endpoint, so
    // spawning it for every `DaemonState` (including test call sites)
    // is inert, matching how the pending-broadcast-retry task below is
    // already spawned unconditionally. `reporting_retry::spawn_periodic`
    // now constructs its own `ReportingRetryJob` internally -- see that
    // module's own doc for why this stays a thin wrapper rather than
    // moving under `crate::maintenance`.
    crate::reporting_retry::spawn_periodic(state.clone());
    // Materialization repair: interval-only, no startup-immediate run
    // (see the inventory's own "no new startup runs" constraint) -- the
    // loop below still reads `sweep_interval()` fresh on every tick, not
    // a `tokio::time::interval` fixed at spawn time, so
    // `set_materialization_repair_sweep_interval` still takes effect on
    // the very next sleep, exactly as before this task moved the sweep
    // body into `MaterializationRepairJob::run_once`.
    // `spawn_restarting`, not `spawn_logged` -- this closes the same
    // structurally-identical asymmetry the Convergence Engine scheduler
    // loop just below is deliberately protected against: this job is the
    // SOLE mechanism that re-arms an OnDemand->Eager materialization-
    // policy promotion (and the hazard/ignore-recheck-adjacent
    // repair-candidate class of work) -- an unhandled panic anywhere in
    // `run_once`'s own synchronous call path (`list_links`,
    // `backfill_missing_change_history`,
    // `dag_reconcile_compatibility_applied_flag_for_group`,
    // `list_materialization_repair_candidates`, `get_files_by_paths`,
    // `file_info_for_record` -- none of which run inside the per-record
    // `tokio::spawn` in `rematerialize_local_records` that already
    // isolates individual-record panics from the caller) would otherwise
    // silently and permanently kill this one shared task for the rest of
    // the process's life, with only a single log line as evidence, until
    // an operator restarts the whole daemon. Extracted into
    // `materialization_repair::spawn_materialization_repair_task` so this
    // exact wiring (the panic recovers, not just "spawn_restarting works
    // in general") is directly testable -- see that function's own test.
    crate::maintenance::materialization_repair::spawn_materialization_repair_task(state.clone());
    // Durability confirmation sweep -- interval-only, same
    // fresh-read-each-tick shape as materialization repair above, so a
    // changed `DurabilityService` sweep interval takes effect on the very
    // next sleep. This is what turns `group_durability_status`'s `Protected`
    // into real peer-confirmed evidence instead of a local-only heuristic
    // -- see `durability_confirmation::DurabilityConfirmationJob`'s own
    // doc comment.
    {
        let durability_confirmation_job = DurabilityConfirmationJob::new(
            state.durability().clone(),
            state.authority.clone(),
            state.peers.clone(),
            state.peer_connectivity.clone(),
            state.replica_coordinator.clone(),
        );
        supervise::spawn_logged("daemon-state-durability-confirmation", async move {
            loop {
                tokio::time::sleep(durability_confirmation_job.sweep_interval()).await;
                durability_confirmation_job.run_once().await;
            }
        });
    }
    // The Convergence Engine's own scheduler loop: drives
    // `materialization_jobs` rows `handle_change_batch` enqueues, on its
    // own schedule, never under a `message_slots` permit. Like
    // materialization repair above (and unlike the still-`spawn_logged`
    // durability-confirmation/pending-broadcast-retry tasks), a silent
    // stop of this one loop halts all materialization for every group
    // for the rest of the daemon's life — `spawn_restarting` is used
    // deliberately so a panic/error here recovers instead of silently
    // wedging the daemon. Already isolated via `spawn_restarting`, with no
    // `run_once`/interval shape to extract it into.
    {
        // Built once, outside the restart factory, so the engine's own
        // rotation cursors survive a panic-restart and reset only with a
        // new `DaemonState` -- see `ConvergenceEngine`'s own doc comment.
        let convergence_engine =
            Arc::new(crate::convergence::engine::ConvergenceEngine::new(state.clone()));
        crate::supervise::spawn_restarting(
            "convergence-engine-scheduler",
            crate::supervise::BackoffConfig::CONVERGENCE_ENGINE,
            move || crate::convergence::engine::run(convergence_engine.clone()),
        );
    }
    // A dedicated, short-interval poll for every currently-Degraded
    // link whose backoff window has elapsed. The whole point of
    // `BackoffConfig::DEGRADED_LINK_RECHECK`'s 5s *initial* interval is
    // a link that degrades and recovers quickly getting checked again
    // promptly, so this must not be folded into a slower housekeeping
    // cadence.
    {
        let degraded_link_recheck_job = DegradedLinkRecheckJob::new(controller.clone());
        supervise::spawn_logged("daemon-state-degraded-link-recheck", async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                degraded_link_recheck_job.run_once();
            }
        });
    }
    // Follows each linked folder's volume: a link whose disk went away stops,
    // and starts again once the disk is back (a mount that finished after the
    // daemon started, a replugged drive). No startup run: `app::run` starts
    // every link itself, and a refused start is what this picks up.
    {
        let link_volume_job = LinkVolumeJob::new(controller.clone());
        supervise::spawn_logged("daemon-state-link-volume", async move {
            loop {
                tokio::time::sleep(crate::maintenance::link_volume::TICK).await;
                link_volume_job.run_once().await;
            }
        });
    }
    // Ends timed pauses whose deadline has passed. The first pass runs at once,
    // so a pause that ended while the daemon was down ends at startup.
    {
        let pause_expiry_job = PauseExpiryJob::new(controller.clone());
        supervise::spawn_logged("daemon-state-pause-expiry", async move {
            loop {
                pause_expiry_job.run_once().await;
                tokio::time::sleep(crate::maintenance::pause_expiry::TICK).await;
            }
        });
    }
    // Finishes a start over whose replacement the service called unconfirmed: once each folder
    // group is fully here as an eager replica (and its link finished startup), confirms it and
    // removes the record. The first pass runs at once, so a daemon restarted with a pending
    // record picks it up without waiting.
    {
        // Replaced devices are refused whether or not a confirmation is pending.
        let state = state.clone();
        supervise::spawn_logged("daemon-state-superseded-devices", async move {
            loop {
                // Tests that count their coordination stub's requests switch background jobs off.
                #[cfg(test)]
                let disabled = state
                    .membership_recovery_sweep_disabled_for_test
                    .load(std::sync::atomic::Ordering::SeqCst);
                #[cfg(not(test))]
                let disabled = false;
                if !disabled {
                    crate::maintenance::replacement_confirm::refresh_superseded_devices(&state)
                        .await;
                }
                tokio::time::sleep(
                    crate::maintenance::replacement_confirm::SUPERSESSION_REFRESH_INTERVAL,
                )
                .await;
            }
        });
    }
    {
        let replacement_confirm_job = ReplacementConfirmJob::for_daemon(state.clone());
        // With no record the job asks the service for the supersessions at once. A test that
        // counts the requests its coordination stub receives switches the background recovery
        // jobs off (`DaemonState::disable_membership_recovery_sweep_for_test`), so that request
        // is not counted against the one it is asserting on.
        #[cfg(test)]
        let confirm_state = state.clone();
        supervise::spawn_logged("daemon-state-replacement-confirm", async move {
            loop {
                #[cfg(test)]
                let disabled = confirm_state
                    .membership_recovery_sweep_disabled_for_test
                    .load(std::sync::atomic::Ordering::SeqCst);
                #[cfg(not(test))]
                let disabled = false;
                if !disabled {
                    replacement_confirm_job.run_once().await;
                }
                tokio::time::sleep(crate::maintenance::replacement_confirm::TICK).await;
            }
        });
    }
    // The retention-expiry sweep —
    // "scheduled periodically... and on daemon startup". Once
    // immediately (a daemon that was down for a while, or one whose
    // retention policy just changed, shouldn't wait a full interval
    // before its first sweep), then on a bounded interval. A
    // relatively long interval (unlike the 2s degraded-link recheck
    // above, which reacts to a transient, user-visible condition) is
    // appropriate here: retention expiry is a slow-moving housekeeping
    // concern — a version that's `RETENTION_EXPIRY_SWEEP_INTERVAL`
    // late to be swept is not a correctness problem, only a delayed
    // storage reclamation, and the actual space reclamation is
    // deferred to the block-store GC regardless (this sweep only
    // ever drops the *index* row). Both this startup call and the
    // spawned loop's own periodic call now go through the same
    // `RetentionExpiryJob::run_once`.
    let retention_expiry_job = RetentionExpiryJob::new(controller.clone());
    retention_expiry_job.run_once();
    {
        let retention_expiry_job = retention_expiry_job.clone();
        supervise::spawn_logged("daemon-state-retention-expiry-sweep", async move {
            loop {
                tokio::time::sleep(RETENTION_EXPIRY_SWEEP_INTERVAL).await;
                retention_expiry_job.run_once();
            }
        });
    }
    // Fix-saga: startup + periodic reconciliation of any membership-
    // related recovery journal left mid-flight by a crash or an
    // unconfirmable coordination-plane call — role-loss (this device's
    // own demote/unlink), unknown-scope, and ambiguous membership
    // operations were previously three independent supervised loops on
    // this same interval; collapsed into one so the number of periodic
    // sweep owners doesn't keep growing with every new recovery journal.
    // Unlike the retention sweep above, this one is async (each sub-sweep
    // makes coordination-plane HTTP calls), so "run once immediately, then
    // on an interval" is expressed as a single spawned loop that sweeps at
    // the top before its first sleep, rather than a separate blocking
    // call ahead of the spawn -- both that first, immediate sweep and
    // every later periodic one now go through the same
    // `RecoveryJob::run_membership_recovery_once`.
    {
        let recovery_job = recovery_job.clone();
        // Unit tests that plant a journal row and read it back switch this
        // sweep off (`DaemonState::disable_membership_recovery_sweep_for_test`)
        // so it cannot race the read.
        #[cfg(test)]
        let sweep_state = state.clone();
        supervise::spawn_logged("daemon-state-membership-recovery-sweep", async move {
            loop {
                #[cfg(test)]
                let disabled = sweep_state
                    .membership_recovery_sweep_disabled_for_test
                    .load(std::sync::atomic::Ordering::SeqCst);
                #[cfg(not(test))]
                let disabled = false;
                if !disabled {
                    recovery_job.run_membership_recovery_once().await;
                }
                tokio::time::sleep(ROLE_LOSS_RECONCILIATION_SWEEP_INTERVAL).await;
            }
        });
    }
    // Piggy-backs on the same cadence as
    // `PeerSyncSession`'s own periodic native-frontier maintenance
    // (`DEFAULT_MAINTENANCE_RECONCILE_INTERVAL`) rather than a new,
    // independent timer. Not run once immediately at startup the way the
    // retention sweep above is: `start_link_watch`'s own initial
    // `scan_existing_files` already indexes everything present on disk
    // at daemon start, so an immediate add-only pass here would find
    // nothing new; the first sweep only matters once a watcher has had
    // a chance to miss something.
    {
        let disk_reconcile_backstop_job = DiskReconcileBackstopJob::new(controller.clone());
        supervise::spawn_logged("daemon-state-disk-reconcile-backstop-sweep", async move {
            loop {
                tokio::time::sleep(
                    yadorilink_peer_session::peer_session::DEFAULT_MAINTENANCE_RECONCILE_INTERVAL,
                )
                .await;
                disk_reconcile_backstop_job.run_once().await;
            }
        });
    }
    // The idle-triggered GC scheduler, modeled on this same `spawn_logged`
    // periodic-task shape as every other sweep in this file.
    {
        let gc_idle_job = GcIdleJob::new(state.clone());
        supervise::spawn_logged("daemon-state-gc-idle-scheduler", async move {
            loop {
                tokio::time::sleep(crate::gc::GC_IDLE_POLL_INTERVAL).await;
                gc_idle_job.run_once().await;
            }
        });
    }
    recovery_job
}

/// Runs one role-loss reconciliation pass through the same service the
/// periodic recovery sweep uses -- for integration tests that need the real
/// production workflow deterministically, without racing that sweep's own
/// interval.
pub async fn run_role_loss_reconciliation_sweep(context: &crate::control_context::ControlContext) {
    context.application.replica_role.reconcile_role_loss().await;
}
