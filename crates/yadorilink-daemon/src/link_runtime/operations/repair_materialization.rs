//! Interrupted-materialization/restore-operation repair for one link,
//! admitted through its `RootLease`. Deduplicates a "begin a `LinkOperation`,
//! mint a permit, call the filesystem-sync repair function" ceremony that
//! would otherwise be written out three times: once for restore-operation
//! reconciliation and once for materialization repair at link-startup
//! (the daemon's own `LinkRuntimeController::start_inner`), and again for materialization
//! repair on the periodic live-repair task. All three share this module,
//! so a caller cannot forget to hold the operation across the repair call --
//! there is no other way to reach `materialization_repair::
//! repair_interrupted_materializations`/`reconcile_restore_operations` from
//! this crate.
//!
//! Deliberately does NOT bundle restore-operation reconciliation and
//! materialization repair into a single call: the two callers need
//! different failure handling (restore-operation reconciliation errors are
//! hard startup failures for this link; materialization-repair errors are
//! soft, deferring only this boot's tombstone emission -- see each
//! function's own return type and each call site's own handling).

use std::path::Path;
use std::sync::Arc;

use crate::sync_error::SyncError;
use yadorilink_filesystem_sync::materialization_repair::{
    MaterializationRepairReport, RepairMode, RestoreRecoveryReport,
};
use yadorilink_local_storage::BlockStore;
use yadorilink_root_authority::root_commit::RootLease;

use crate::replica_coordinator::ReplicaCoordinator;

/// Reconciles any restore operation this link's index still has an open
/// intent for. Admits its own `LinkOperation` from `root_lease`, held for
/// the whole call.
///
/// Takes `&Arc<ReplicaCoordinator>`: both free functions this delegates to
/// take `&dyn MaterializationExecutionPort`, which `ReplicaCoordinator`
/// implements, so it coerces here without any adapter.
pub(crate) fn reconcile_restore_operations(
    replica_coordinator: &Arc<ReplicaCoordinator>,
    root_lease: &Arc<RootLease>,
    root: &Path,
    group_id: &str,
) -> Result<RestoreRecoveryReport, SyncError> {
    let op = root_lease.begin_operation()?;
    // `reconcile_restore_operations` returns `yadorilink_filesystem_sync::
    // materialization_execution::MaterializationExecutionError`, mapped at
    // this one boundary via the same `impl From<MaterializationExecutionError>
    // for SyncError` bridge `hydration.rs::evict` already uses.
    yadorilink_filesystem_sync::materialization_repair::reconcile_restore_operations(
        replica_coordinator.as_ref(),
        root,
        group_id,
        &op.permit(),
    )
    .map_err(SyncError::from)
}

/// Repairs any `Present`-but-disk-inconsistent row this link's index has --
/// see `yadorilink_filesystem_sync::materialization_repair::
/// repair_interrupted_materializations`'s own doc for exactly what crash
/// window this closes. Admits its own `LinkOperation` from `root_lease`,
/// held across both the (potentially slow) disk walk/reconstruct work and
/// the commits it makes.
///
/// `repair_interrupted_materializations_inner`
/// (`yadorilink-filesystem-sync::materialization_repair`) calls
/// `state.path_lock(group_id, path)` against the same `&Arc<ReplicaCoordinator>`
/// passed in here. That has to be the identical registry
/// `yadorilink-local-capture::LocalChangeProcessor` locks the same path
/// through (via the `LocalMutationStore` port, `replica_coordinator/
/// local_mutation.rs`), or a repair walk and a concurrent local-capture
/// mutation for the same path would not actually mutually exclude. They do:
/// both call sites are handed the SAME `Arc<ReplicaCoordinator>` out of
/// `LinkRuntimeDependencies` (`link_runtime/dependencies.rs`), and that one
/// coordinator owns exactly one `PathLockRegistry`
/// (`ReplicaCoordinator::path_lock_registry()`), so there is only ever one
/// lock per path to take.
pub(crate) fn repair_interrupted_materializations(
    replica_coordinator: &Arc<ReplicaCoordinator>,
    block_store: &Arc<dyn BlockStore + Send + Sync>,
    root_lease: &Arc<RootLease>,
    root: &Path,
    group_id: &str,
    mode: RepairMode,
) -> Result<MaterializationRepairReport, SyncError> {
    let op = root_lease.begin_operation()?;
    // See `reconcile_restore_operations` above for the same error-type note.
    yadorilink_filesystem_sync::materialization_repair::repair_interrupted_materializations(
        replica_coordinator.as_ref(),
        &crate::adapters::block_store_ports::BlockStorePortsAdapter::new(block_store.clone()),
        root,
        group_id,
        mode,
        &op.permit(),
    )
    .map_err(SyncError::from)
}
