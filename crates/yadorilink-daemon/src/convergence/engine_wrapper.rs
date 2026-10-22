//! Runs the existing materialization engine together with its independent
//! maintenance loops (hazard and ignore rechecks).
//!
//! Keeping the loops in a wrapper leaves `engine.rs` free to evolve
//! independently. If either essential loop exits, this wrapper exits and
//! `DaemonState`'s existing `spawn_restarting` supervision restarts both.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use yadorilink_fs_platform::ignore_patterns::{is_ignore_file_relative_path, EffectiveIgnoreSet};

use crate::daemon_state::DaemonState;

pub use super::engine_impl::ConvergenceEngine;

/// The hazard re-check loop's backstop cadence, for its own `HazardRecheckWake`-driven events -- a correctness backstop
/// only, for a mark lost to a crash or a race with linking.
const HAZARD_RECHECK_BACKSTOP_INTERVAL: Duration = Duration::from_secs(30);
/// The ignore-recheck loop's own backstop cadence -- unlike the retirement
/// and hazard loops, this one is backstop-only, with no event-driven fast
/// path yet (see `run_ignore_recheck_loop`'s own doc comment for why that
/// is an acceptable, deliberate scope boundary for now). Matches
/// `HAZARD_RECHECK_BACKSTOP_INTERVAL` so an ignore-policy edit and a lifted
/// hazard hold carry the same worst-case re-arm latency.
const IGNORE_RECHECK_BACKSTOP_INTERVAL: Duration = Duration::from_secs(30);

/// See `engine_impl::run_once_for_test`'s own doc comment -- this is the
/// only way to drive the Convergence Engine's scheduler deterministically
/// one tick at a time from outside `yadorilink-daemon` at all, since
/// `engine_impl` (this module's own sibling, `mod engine_impl` -- not
/// `pub`) is otherwise unreachable from an external integration test.
#[cfg(any(test, feature = "test-support"))]
pub async fn run_once_for_test(engine: &ConvergenceEngine) -> bool {
    super::engine_impl::run_once_for_test(engine).await
}

/// See `engine_impl::drive_obligations_once_for_test`'s own doc comment --
/// the obligation-driven worker's counterpart of [`run_once_for_test`],
/// exposed the same way for the same reason.
#[cfg(any(test, feature = "test-support"))]
pub async fn drive_obligations_once_for_test(
    engine: &ConvergenceEngine,
    per_group_limit: u32,
    total_limit: u32,
) -> bool {
    super::engine_impl::drive_obligations_once_for_test(engine, per_group_limit, total_limit).await
}

/// See `engine_impl::BeforeCompletionHook`'s own doc comment -- re-exported
/// so a deterministic-interleaving test outside `yadorilink-daemon` can
/// construct one and drive it.
#[cfg(any(test, feature = "test-support"))]
pub use super::engine_impl::BeforeCompletionHook;

/// See `engine_impl::drive_obligations_once_for_test_with_hooks`'s own doc
/// comment -- exposed the same way as [`drive_obligations_once_for_test`].
#[cfg(any(test, feature = "test-support"))]
pub async fn drive_obligations_once_for_test_with_hooks(
    engine: &ConvergenceEngine,
    per_group_limit: u32,
    total_limit: u32,
    hooks: &Arc<BeforeCompletionHook>,
) -> bool {
    super::engine_impl::drive_obligations_once_for_test_with_hooks(
        engine,
        per_group_limit,
        total_limit,
        hooks,
    )
    .await
}

pub async fn run(engine: Arc<ConvergenceEngine>) {
    let state = engine.state().clone();
    // Each loop is spawned as its own task rather than raced directly via
    // `tokio::select!` on the bare futures: a loop that calls synchronous,
    // blocking `SyncState` methods, raced directly alongside the main
    // engine's future on the SAME task, would
    // let a slow synchronous call in this poll starve the engine's own tick
    // for as long as it runs (`select!` only gets to poll whichever branch
    // it currently has control in) -- exactly the kind of added per-tick
    // latency the row-14 stress scenario's stall detector is tuned to
    // catch. Spawning each onto its own task lets tokio schedule them on
    // genuinely separate worker threads.
    //
    // Explicit abort-and-await of the three survivors below, not a bare
    // `tokio::select!` on the four `JoinHandle`s alone, gives the "either
    // dies, all restart" semantics this wrapper's own doc comment
    // describes: a `JoinHandle` a `select!` branch drops only DETACHES its
    // task rather than cancelling it (it keeps running), so
    // `spawn_restarting`'s subsequent restart would otherwise leave the old
    // survivors running undetached alongside a brand new set of tasks --
    // duplicate materialization engines or maintenance loops, compounding on
    // every restart. This manual select-then-abort-and-await reproduces
    // `tokio::task::JoinSet`'s "aborts every remaining task and awaits their
    // completion" contract explicitly -- this function never returns while
    // any of the four tasks is still alive.
    let hazard_recheck_state = state.clone();
    let ignore_recheck_state = state;
    let mut engine_handle = tokio::spawn(super::engine_impl::run(engine));
    let mut hazard_recheck_handle = tokio::spawn(run_hazard_recheck_loop(hazard_recheck_state));
    let mut ignore_recheck_handle = tokio::spawn(run_ignore_recheck_loop(ignore_recheck_state));
    // Cancelling this future (an aborted supervisor) must stop all four
    // rather than detach them.
    let _stop_with_wrapper = [
        crate::supervise::AbortOnDrop(engine_handle.abort_handle()),
        crate::supervise::AbortOnDrop(hazard_recheck_handle.abort_handle()),
        crate::supervise::AbortOnDrop(ignore_recheck_handle.abort_handle()),
    ];
    tokio::select! {
        _ = &mut engine_handle => {}
        _ = &mut hazard_recheck_handle => {}
        _ = &mut ignore_recheck_handle => {}
    }
    for handle in [&mut engine_handle, &mut hazard_recheck_handle, &mut ignore_recheck_handle] {
        handle.abort();
        let _ = handle.await;
    }
}

/// Every currently linked, non-paused, non-orphaned group -- the backstop
/// pass's own candidate set, since (unlike an event-driven wake) it has no
/// narrower dirty set to go on.
async fn list_linked_groups_for_retirement(state: &Arc<DaemonState>) -> Option<BTreeSet<String>> {
    let replica_coordinator_for_links = state.replica_coordinator.clone();
    match tokio::task::spawn_blocking(move || {
        replica_coordinator_for_links.link_repository().list_links()
    })
    .await
    {
        Ok(Ok(links)) => Some(
            links
                .into_iter()
                .filter(|link| !link.paused && !link.orphaned)
                .map(|link| link.group_id)
                .collect(),
        ),
        Ok(Err(error)) => {
            tracing::warn!(%error, "ephemeral conflict-copy retire audit could not list links");
            None
        }
        Err(error) => {
            tracing::error!(
                %error,
                "ephemeral conflict-copy retire audit's list_links task panicked"
            );
            None
        }
    }
}

/// Re-evaluates every currently-`HazardHeld` path in a group whenever this
/// device's native frontier advances or a materialization job completes --
/// see `MaterializationStateRepository::list_held_paths`'s own doc comment
/// for why nothing else ever re-visits a held path once the sibling that
/// caused its hold changes. Structurally identical to
/// `run_ephemeral_conflict_copy_retire_loop`: event-driven via
/// `HazardRecheckWake`, with `HAZARD_RECHECK_BACKSTOP_INTERVAL` as a
/// correctness backstop only for a mark lost to a crash or a race with
/// linking. Uses a separate `GroupWake` instance
/// (`hazard_recheck_wake`), not the retirement loop's own, since `pending`/
/// `complete` are consumer-specific -- see that field's own doc comment.
async fn run_hazard_recheck_loop(state: Arc<DaemonState>) {
    loop {
        tokio::select! {
            _ = state.replica_coordinator.hazard_recheck_wake().wake_notified() => {
                let pending = state.replica_coordinator.hazard_recheck_wake().pending();
                run_hazard_recheck_pass(&state, pending).await;
            }
            _ = tokio::time::sleep(HAZARD_RECHECK_BACKSTOP_INTERVAL) => {
                if let Some(groups) = list_linked_groups_for_retirement(&state).await {
                    for group_id in &groups {
                        state.replica_coordinator.hazard_recheck_wake().mark_dirty(group_id);
                    }
                    let pending = state.replica_coordinator.hazard_recheck_wake().pending();
                    run_hazard_recheck_pass(&state, pending).await;
                }
            }
        }
    }
}

/// For each group in `pending` (group id -> the generation `GroupWake::
/// pending` reported for it), lists its currently-held paths and, if any,
/// re-resolves them directly against this device's current native heads via
/// `reconcile_paths_directly` -- the SAME entry point the Convergence
/// Engine's own per-job completion oracle uses. A held path's hazard status
/// follows only local native state and disk state, so this decision is not
/// peer-dependent at all. It still prefers an already-live candidate session
/// when one exists, because a peer is what makes content the recheck may need
/// obtainable; with none, the local executor runs the same pass and a path
/// waiting on content it cannot get stays held.
///
/// What it no longer does is manufacture a session to run local work through.
/// That used to trigger `NetmapChangeAuthenticator::new` ->
/// `validate_linked_history_best_effort`, which can transiently quarantine
/// every OTHER already-connected session's
/// authorization for this group if that validation is briefly unavailable.
/// This backstop pass runs on its own 30s timer, independent of peer-connect
/// timing, so it is realistic for it to be the first caller to need a
/// session for a group whose real peers already connected. A group whose
/// listing came back empty, or whose `reconcile_paths_directly` call
/// genuinely ran (`Some(_)`, regardless of what it found -- a still-
/// hazardous path is a correctly re-verified outcome, not a failure to
/// complete this generation), completes its generation. A listing failure
/// or a skipped attempt (`None`: guard contention, or the group is not
/// `LinkGate::Live` right now) leaves the group pending for the next wake
/// or backstop.
async fn run_hazard_recheck_pass(state: &Arc<DaemonState>, pending: BTreeMap<String, u64>) {
    for (group_id, generation) in pending {
        let replica_coordinator_for_list = state.replica_coordinator.clone();
        let local_for_list = state.local_convergence();
        let list_group_id = group_id.clone();
        let held_paths = match tokio::task::spawn_blocking(move || {
            let held = replica_coordinator_for_list
                .materialization_state_repository()
                .list_held_paths(&list_group_id)?;
            // A path held because its existing file is unreadable to its
            // owner is re-examined only once something it was held against
            // has changed: re-running it unchanged can only reach the same
            // hold again. A failed check keeps the path in the pass.
            Ok::<_, yadorilink_sync_sqlite::SyncSqliteError>(
                held.into_iter()
                    .filter(|path| {
                        !local_for_list
                            .metadata_unprovable_hold_unchanged(&list_group_id, path)
                            .unwrap_or_else(|error| {
                                tracing::debug!(
                                    %error,
                                    group_id = %list_group_id,
                                    path = %path,
                                    "could not tell whether a metadata hold is unchanged; \
                                     re-examining it"
                                );
                                false
                            })
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .await
        {
            Ok(Ok(paths)) => paths,
            Ok(Err(error)) => {
                tracing::warn!(%error, %group_id, "hazard recheck could not list held paths");
                continue;
            }
            Err(error) => {
                tracing::error!(%error, %group_id, "hazard recheck's list_held_paths task panicked");
                continue;
            }
        };
        if held_paths.is_empty() {
            state.replica_coordinator.hazard_recheck_wake().complete(&group_id, generation);
            continue;
        }
        let paths: std::collections::BTreeSet<String> = held_paths.into_iter().collect();
        let peer = crate::hydration::candidate_sessions(state, &group_id)
            .into_iter()
            .min_by(|a, b| a.0.cmp(&b.0))
            .map(|(_, session)| session);
        let outcome = match peer {
            Some(session) => match state.peers.local_convergence(
                yadorilink_peer_session::convergence_driver::ConvergenceDriver::peer_device_id(
                    session.as_ref(),
                ),
            ) {
                Some(local) => local
                    .reconcile_paths_directly(
                        &(session.clone()
                            as std::sync::Arc<
                                dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver,
                            >),
                        &group_id,
                        paths,
                    )
                    .await,
                None => Ok(None),
            },
            // No peer is connected. The re-check still runs: a hazard resolves
            // for purely local reasons -- the name that was in the way is gone,
            // the conflicting row was retired -- and this device needs nobody's
            // help to notice. What it cannot do alone is obtain content it does
            // not hold, and a path waiting on that stays held, which is what
            // being unable to reach anyone has always meant here.
            None => state.local_convergence().reconcile_paths(&group_id, paths).await,
        };
        match outcome {
            Ok(Some(_)) => {
                state.replica_coordinator.hazard_recheck_wake().complete(&group_id, generation);
            }
            // `None`: the audit guard was already held by another attempt,
            // or the group is not `LinkGate::Live` right now -- nothing was
            // actually re-verified, so this generation stays pending for
            // the next wake or backstop.
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%group_id, %error, "hazard recheck's direct reconciliation failed");
            }
        }
    }
}

/// Re-arms a `projection_obligations` row parked at `'ignore_blocked'`
/// (`complete_obligation_if_non_exact_proof_current`'s `IgnoreExcluded`
/// arm -- see that variant's own doc comment) once a periodic re-check
/// confirms the path is no longer locally ignored, closing the liveness
/// gap the `IGNORE_SET_REFRESH_INTERVAL` cache-TTL fix alone left open: a
/// live-reloading ignore-set cache only ever changes what a FUTURE
/// `is_locally_ignored` call sees, it does nothing for a path whose
/// obligation was already parked before the reload, since nothing else
/// ever calls `is_locally_ignored` for it again on its own.
///
/// Deliberately backstop-only for now, unlike the retirement/hazard loops
/// (no `GroupWake`-style event-driven fast path): the natural trigger
/// -- "the ignore-set cache for this group just reloaded from a changed
/// `.yadorilinkignore`" -- fires deep inside `yadorilink-peer-session`'s
/// `effective_ignore_set`, and wiring a cross-crate notification back into
/// this loop is a possible follow-up, not required to close the liveness
/// gap itself: the `IGNORE_RECHECK_BACKSTOP_INTERVAL` poll alone already
/// bounds worst-case re-arm latency, exactly the same tradeoff this
/// codebase already accepted for the hazard-recheck loop's own 30s
/// backstop.
///
/// Spawned for real from `run`, alongside the retirement and
/// hazard-recheck loops: `process_group_via_obligations` is the live
/// claim source, so an `'ignore_blocked'` row is a real, live
/// possibility, not merely a test-driven one.
async fn run_ignore_recheck_loop(state: Arc<DaemonState>) {
    loop {
        tokio::time::sleep(IGNORE_RECHECK_BACKSTOP_INTERVAL).await;
        if let Some(groups) = list_linked_groups_for_retirement(&state).await {
            for group_id in &groups {
                run_ignore_recheck_pass(&state, group_id).await;
            }
        }
    }
}

/// Lists `group_id`'s currently-`'ignore_blocked'` paths and re-checks
/// EACH ONE against the current, live ignore-policy verdict alone -- never
/// by attempting a reconcile/materialize. A path still matching the
/// current ignore set is left exactly where it is; a path that no longer
/// matches is re-armed back to `'pending'` immediately, then the ordinary
/// obligation claim cycle (a live candidate peer, not this sweep) produces
/// the real fetch/materialize/completion for it.
///
/// This deliberately does NOT drive a reconcile attempt the way the
/// hazard-recheck sweep does: gating re-arm on
/// `ProjectionAttempt::is_settled(path)` after running reconciliation
/// with no way to obtain content at all would stall permanently. A path whose content
/// requires an actual block fetch (anything but the trivial empty-content
/// case) could never `is_settled` on such a pass, so it could never
/// re-arm at all: an unignored file needing real content would stay
/// `'ignore_blocked'` forever, invisible to the production scheduler
/// (which only ever claims `'pending'` rows). Reproducing that needs a
/// `FileVersion` with a real (non-empty) block absent from the local store
/// -- `empty_version()` is trivially "materializable" with no blocks at
/// all and so never exercises the ChannelClosed path. This function has
/// no dependency on full settlement at all: whether a path is still ignored is a pure,
/// local, synchronous policy question that has nothing to do with whether
/// its content can currently be fetched.
///
/// This deliberately avoids `state.local_retirement_session` (a real
/// `PeerSyncSession`, previously used only for its
/// `is_path_locally_ignored` accessor): that session's own first-ever
/// construction for a group triggers `NetmapChangeAuthenticator::new` ->
/// `validate_linked_history_best_effort`, which can transiently quarantine
/// every OTHER already-connected session's authorization for this group if
/// that validation is not yet available (see
/// `process_group_via_obligations`'s doc comment). Whether a path is
/// locally ignored has nothing to do with peer/session state at all --
/// this pass loads the group's `EffectiveIgnoreSet` directly from its sync
/// root, the same source `PeerSyncSession::effective_ignore_set` reads
/// from, without ever constructing a session. Unlike that session-cached
/// accessor, this has no last-known-good fallback: a transient sync-root
/// resolution failure re-arms rather than leaving the path parked, which
/// is safe (the ordinary claim cycle re-evaluates ignore policy again
/// downstream) and strictly better than risking the quarantine side effect.
async fn run_ignore_recheck_pass(state: &Arc<DaemonState>, group_id: &str) {
    let replica_coordinator_for_list = state.replica_coordinator.clone();
    let list_group_id = group_id.to_string();
    let ignore_blocked_paths = match tokio::task::spawn_blocking(move || {
        replica_coordinator_for_list.sqlite().dag_list_ignore_blocked_paths(&list_group_id)
    })
    .await
    {
        Ok(Ok(paths)) => paths,
        Ok(Err(error)) => {
            tracing::warn!(%error, %group_id, "ignore recheck could not list ignore-blocked paths");
            return;
        }
        Err(error) => {
            tracing::error!(%error, %group_id, "ignore recheck's list_ignore_blocked_paths task panicked");
            return;
        }
    };
    if ignore_blocked_paths.is_empty() {
        return;
    }
    let sync_roots = crate::peer_orchestrator::sync_roots_for_groups(
        state,
        std::slice::from_ref(&group_id.to_string()),
    );
    let ignore_set = sync_roots.get(group_id).map(|root| {
        EffectiveIgnoreSet::load_for_link_root(root)
            .unwrap_or_else(|_| EffectiveIgnoreSet::defaults_only())
    });
    let mut any_rearmed = false;
    for path in &ignore_blocked_paths {
        // The same rule as `LocalConvergenceExecutor::is_locally_ignored`:
        // a directory-only pattern covers a path the namespace places a
        // directory at.
        let still_ignored = ignore_set.as_ref().is_some_and(|set| {
            is_ignore_file_relative_path(path)
                || set.is_ignored(path, false)
                || (set.is_ignored(path, true)
                    && matches!(
                        state.replica_coordinator.desired_path_state(group_id, path),
                        Ok(yadorilink_sync_sqlite::desired_state::DesiredPathState::ExplicitDirectory { .. }
                            | yadorilink_sync_sqlite::desired_state::DesiredPathState::StructuralDirectory)
                    ))
        });
        if still_ignored {
            continue;
        }
        let replica_coordinator_for_rearm = state.replica_coordinator.clone();
        let rearm_group_id = group_id.to_string();
        let rearm_path = path.clone();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        match tokio::task::spawn_blocking(move || {
            replica_coordinator_for_rearm.sqlite().dag_rearm_ignore_blocked_obligation(
                &rearm_group_id,
                &rearm_path,
                now,
            )
        })
        .await
        {
            Ok(Ok(rearmed)) => any_rearmed = any_rearmed || rearmed,
            Ok(Err(error)) => {
                tracing::warn!(%error, %group_id, path, "ignore recheck failed to re-arm a path");
            }
            Err(error) => {
                tracing::error!(%error, %group_id, path, "ignore recheck's re-arm task panicked");
            }
        }
    }
    if any_rearmed {
        state.replica_coordinator.materialization_wake().notify_materialization_wake();
    }
}

/// `run_hazard_recheck_pass`'s own regression coverage: proves a path
/// marked `HazardHeld` gets re-examined and un-held by the sweep alone,
/// with no fresh incoming record for that exact path -- the gap
/// `MaterializationStateRepository::list_held_paths`'s own doc comment
/// describes. Marks the path held via a direct `set_held` call rather than
/// through real case-fold/normalization hazard detection: those checks
/// probe the real tempdir's filesystem (`hazard::is_case_insensitive_
/// filesystem`/`is_normalization_insensitive_filesystem`), which is a
/// no-op on this crate's own Linux CI/dev tempdirs regardless of policy --
/// see `crate::convergence`'s own `hazard_reason_tests` for why those
/// tests skip outright there. A path this device's own `hazard_reason_for`
/// call (invoked fresh, inside `materialize`, every time
/// `reconcile_paths_directly` resolves it) finds NOT hazardous already
/// clears its own hold as a documented side effect of successful
/// reconciliation -- what nothing does today is ever CALL that
/// reconciliation for a held path with no new incoming record of its own,
/// which is exactly what this sweep exists to do.
#[cfg(test)]
#[path = "engine_wrapper/hazard_recheck_tests.rs"]
mod hazard_recheck_tests;

/// `run_ignore_recheck_pass`'s own regression coverage: proves the
/// liveness gap the `IGNORE_SET_REFRESH_INTERVAL` cache-TTL fix alone left
/// open (see `run_ignore_recheck_loop`'s own doc comment) is actually
/// closed -- a path parked `'ignore_blocked'` gets re-examined and re-armed
/// by the sweep alone, with no fresh incoming record for that exact path.
#[cfg(test)]
#[path = "engine_wrapper/ignore_recheck_tests.rs"]
mod ignore_recheck_tests;
