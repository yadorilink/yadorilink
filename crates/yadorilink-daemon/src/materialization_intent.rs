//! Unlike those registries, this one could not simply be given an
//! independent copy without also duplicating two marker-trait impls:
//! `yadorilink_peer_session::ports::OpenMaterializationIntent` and
//! `yadorilink_filesystem_sync::materialization_execution::
//! OpenMaterializationIntent` are each foreign traits owned by a different
//! crate, and Rust's orphan rule requires the `impl` to live in a crate
//! that owns either the trait or the type. Hoisting the guard type itself
//! to a lower shared crate (`yadorilink-replica-domain`, where other
//! plain-data types live) does not work here: a crate implementing both
//! foreign traits for the guard needs to depend on both trait owners,
//! which `yadorilink-replica-domain` cannot without inverting the very
//! dependency order that crate relies on (nothing above
//! `yadorilink-replica-domain` could still depend on it for its plain-data
//! types).

use yadorilink_root_authority::root_commit::RootCommitPermit;

use crate::sync_error::SyncError;

#[must_use = "an intent guard that is neither cleared nor deliberately dropped leaves a durable \
              materialization intent behind"]
pub struct MaterializationIntentGuard<'a> {
    state: &'a crate::replica_coordinator::ReplicaCoordinator,
    group_id: &'a str,
    path: &'a str,
    permit: &'a RootCommitPermit<'a>,
}

impl<'a> MaterializationIntentGuard<'a> {
    /// Opens (durably writes) the materialization intent for `(group_id,
    /// path)` targeting `target_version_hash`'s content. MUST be called
    /// before the bytes are written and before any `Present` row is
    /// committed for this path.
    pub fn open(
        state: &'a crate::replica_coordinator::ReplicaCoordinator,
        group_id: &'a str,
        path: &'a str,
        target_version_hash: &[u8],
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<Self, yadorilink_sync_sqlite::SyncSqliteError> {
        state.materialization_intent_repository().begin_materialization_intent(
            group_id,
            path,
            target_version_hash,
            permit,
        )?;
        Ok(Self::opened(state, group_id, path, permit))
    }

    /// The guard of an intent the caller has already committed for `(group_id,
    /// path)`, in a transaction of its own that also wrote other facts.
    pub(crate) fn opened(
        state: &'a crate::replica_coordinator::ReplicaCoordinator,
        group_id: &'a str,
        path: &'a str,
        permit: &'a RootCommitPermit<'a>,
    ) -> Self {
        Self { state, group_id, path, permit }
    }

    /// Clears the intent. Call ONLY after the temp-write-then-rename is
    /// durable, or when the write has been abandoned to a `Remote`.
    pub fn clear(self) -> Result<(), yadorilink_sync_sqlite::SyncSqliteError> {
        self.state.materialization_intent_repository().clear_materialization_intent(
            self.group_id,
            self.path,
            self.permit,
        )
    }
}

impl yadorilink_peer_session::ports::OpenMaterializationIntent for MaterializationIntentGuard<'_> {
    fn clear(self: Box<Self>) -> Result<(), yadorilink_peer_session::PeerSessionError> {
        MaterializationIntentGuard::clear(*self)
            .map_err(SyncError::from)
            .map_err(yadorilink_peer_session::PeerSessionError::from)
    }
}

impl yadorilink_filesystem_sync::materialization_execution::OpenMaterializationIntent
    for MaterializationIntentGuard<'_>
{
    fn clear(
        self: Box<Self>,
    ) -> Result<
        (),
        yadorilink_filesystem_sync::materialization_execution::MaterializationExecutionError,
    > {
        MaterializationIntentGuard::clear(*self).map_err(SyncError::from).map_err(Into::into)
    }
}
