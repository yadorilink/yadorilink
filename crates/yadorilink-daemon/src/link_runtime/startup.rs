//! Per-group startup-readiness state and the local-change-processor
//! construction it gates: `GroupStartupReadyGuard` (the fail-closed RAII
//! barrier `LinkRuntimeFactory::build` arms before any fallible setup step,
//! and the spawned executor task in [`super::tasks`] resolves once its own
//! scan+redrive loop completes or exhausts its retries) and
//! `build_change_processor`/`open_group_author` (wiring a
//! link's `LocalChangeProcessor` with change-history emission once this
//! device has both a registered identity and a signing key).
//!
//! Moved here from the daemon's own `LinkRuntimeController` as a pure relocation -- every method's
//! logic is byte-identical to before the move.

use std::sync::Arc;

use crate::sync_error::SyncError;
use yadorilink_local_capture::LocalChangeProcessor;

use crate::link_runtime::dependencies::LinkRuntimeDependencies;

/// Builds a linked folder's local-change processor, wiring in native delta
/// emission when this device has both a registered identity and a signing
/// key.
///
/// Emission is left off only for a genuinely *unregistered* device (empty
/// `device_id`) -- a *registered* device with no signing key wired is a
/// fail-closed condition instead, not a legitimate no-emitter path; see
/// `open_group_author`'s own doc comment.
pub(crate) fn build_change_processor(
    deps: &Arc<LinkRuntimeDependencies>,
    group_id: &str,
    root_lease: Arc<yadorilink_root_authority::root_commit::RootLease>,
) -> Result<LocalChangeProcessor, SyncError> {
    let processor = LocalChangeProcessor::new(
        deps.replica_coordinator.clone(),
        Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
            deps.block_store.clone(),
        )),
        deps.device_id.clone(),
        root_lease,
    )
    .with_unreadable_ledger(deps.telemetry.unreadable_files_handle());
    // Emission needs a stable device id to attribute deltas to. A device
    // with no identity leaves emission off. A registered device with no signing
    // key is NOT handled here: `open_group_author` below fails
    // closed for that case instead of silently leaving emission off.
    if deps.device_id.is_empty() {
        return Ok(processor);
    }
    Ok(processor.with_change_emitter(open_group_author(deps, group_id)?))
}

pub(crate) fn open_group_author(
    deps: &Arc<LinkRuntimeDependencies>,
    group_id: &str,
) -> Result<Arc<yadorilink_sync_sqlite::dag_store::LocalAuthorKey>, SyncError> {
    // A *registered* device (non-empty `device_id`, checked by the caller)
    // with no signing key wired is a fail-closed condition, not a legitimate
    // no-emitter path: without a `LocalAuthorKey`, local edits get indexed but
    // never recorded as native deltas, so this device's own edits would never
    // reach a peer at all -- silent data loss
    // from the group's perspective, not merely "emission off." Only a
    // genuinely *unregistered* device (empty `device_id`, handled entirely by
    // `build_change_processor`'s own early return above) is exempt.
    let signing_key = deps.device_signing_key().ok_or_else(|| {
        SyncError::CorruptState(format!(
            "registered device {} has no signing key; refusing index-only sync",
            deps.device_id
        ))
    })?;
    // This replica's current author incarnation (opened with the sidecar
    // check when the signing key was wired; opened here otherwise).
    let emitter = deps
        .replica_coordinator
        .open_local_author(&deps.device_id, signing_key)
        .map_err(|error| {
            SyncError::CorruptState(format!(
                "registered device {} cannot open its author identity: {error}",
                deps.device_id
            ))
        })?;
    // What the plan names but the index does not hold is owed a projection, and
    // nothing persisted says so if the obligation was lost with the last run.
    // This is the one place the plan is compared with the index: every change
    // to the plan arms its paths in the same transaction, so within a run an
    // unmet entry always has its obligation, and no periodic pass looks again.
    if let Err(error) = deps.replica_coordinator.arm_native_plan_gaps(group_id) {
        tracing::warn!(group_id, %error, "could not arm planned entries that have no row");
    }
    Ok(emitter)
}

/// Resolves a group's startup-readiness barrier exactly once, fail-*closed*.
/// Mirrors `HydrationAttempt`: an explicit success call (`mark_ready`)
/// publishes the good state, while `Drop` on the unfinished path — an early
/// return, a panic that unwinds the executor, or a task abort — transitions the
/// group to `Failed` instead of Ready. A startup that does not complete
/// therefore DEFERS (fail-closed) peer apply for the group rather than opening
/// the gate over a half-built index, where an incoming peer change could
/// overwrite un-indexed local content or skip an offline edit the dirty-journal
/// redrive never got to re-apply. Recovery is a subsequent `begin_group_startup`
/// (relink / watcher restart / the executor's own bounded retry), which
/// supersedes the failure and re-runs startup.
///
/// The guard carries the `StartupGeneration` it owns, and every transition
/// routes through the generation-checked `SyncState` methods, so an aborted old
/// executor's late `Drop` can neither open nor fail a newer generation's gate.
pub(crate) struct GroupStartupReadyGuard {
    deps: Arc<LinkRuntimeDependencies>,
    group_id: String,
    generation: crate::sync_runtime::startup_readiness::StartupGeneration,
    resolved: bool,
}

impl GroupStartupReadyGuard {
    pub(crate) fn new(
        deps: Arc<LinkRuntimeDependencies>,
        group_id: String,
        generation: crate::sync_runtime::startup_readiness::StartupGeneration,
    ) -> Self {
        Self { deps, group_id, generation, resolved: false }
    }

    /// Success path: publish `Ready` for this generation and defuse the
    /// fail-closed `Drop`.
    pub(crate) fn mark_ready(&mut self) {
        self.deps
            .replica_coordinator
            .startup_readiness()
            .mark_group_ready(&self.group_id, self.generation);
        yadorilink_fs_platform::join_timeline::mark(
            &self.deps.device_id,
            &self.group_id,
            yadorilink_fs_platform::join_timeline::Milestone::LinkReady,
        );
        self.resolved = true;
    }

    /// Explicit failure path — a caught scan/redrive error, or a `JoinError`
    /// from a scan task that panicked inside `spawn_blocking` (which does NOT
    /// unwind this future). Publishes `Failed` for this generation and defuses
    /// the `Drop`.
    pub(crate) fn mark_failed(&mut self, reason: impl Into<String>) {
        self.deps.replica_coordinator.startup_readiness().mark_group_failed(
            &self.group_id,
            self.generation,
            reason,
        );
        self.resolved = true;
    }

    /// Re-arm for a retry: adopt the fresh generation returned by a new
    /// `begin_group_startup` so a subsequent `mark_*`/`Drop` targets the
    /// generation actually in flight.
    pub(crate) fn begin_generation(
        &mut self,
        generation: crate::sync_runtime::startup_readiness::StartupGeneration,
    ) {
        self.generation = generation;
        self.resolved = false;
    }
}

impl Drop for GroupStartupReadyGuard {
    fn drop(&mut self) {
        if !self.resolved {
            // Unwound before completing (panic / early return / task abort):
            // fail-closed. The generation check inside `mark_group_failed` makes
            // this a no-op when a newer startup has already superseded us.
            self.deps.replica_coordinator.startup_readiness().mark_group_failed(
                &self.group_id,
                self.generation,
                "startup task did not complete (panicked, aborted, or returned early)",
            );
        }
    }
}

#[cfg(test)]
mod tests;
