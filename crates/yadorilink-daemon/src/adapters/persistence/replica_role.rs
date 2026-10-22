//! `DaemonState`-backed [`ReplicaRoleRepository`] -- wraps `DaemonState`
//! rather than raw `SyncState` for the same reason the membership repository
//! adapter does: `latch_group_durability_unknown` also updates
//! `DaemonState`'s own in-memory durability-status cache.

use std::sync::Arc;

use crate::sync_error::SyncError;
use yadorilink_replica_domain::session_state::FolderLink;
use yadorilink_replica_domain::session_state::MaterializationPolicy;

use crate::application::ports::ReplicaRoleRepository;
use crate::daemon_state::DaemonState;

pub(crate) struct SyncStateReplicaRoleRepository {
    state: Arc<DaemonState>,
}

impl SyncStateReplicaRoleRepository {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl ReplicaRoleRepository for SyncStateReplicaRoleRepository {
    fn list_links(&self) -> Result<Vec<FolderLink>, SyncError> {
        self.state.replica_coordinator.link_repository().list_links().map_err(SyncError::from)
    }

    fn live_link_key_for_group(&self, group_id: &str) -> Result<Option<String>, SyncError> {
        self.state
            .replica_coordinator
            .link_repository()
            .live_link_key_for_group(group_id)
            .map_err(SyncError::from)
    }

    fn recheck_digest_then_set_materialization_policy(
        &self,
        group_id: &str,
        local_path: &str,
        policy: MaterializationPolicy,
        expected_digest: [u8; 32],
    ) -> Result<bool, SyncError> {
        self.state
            .replica_coordinator
            .link_repository()
            .recheck_digest_then_set_materialization_policy(
                group_id,
                local_path,
                policy,
                expected_digest,
            )
            .map_err(SyncError::from)
    }

    fn recheck_digest_then_remove_link(
        &self,
        group_id: &str,
        local_path: &str,
        expected_digest: [u8; 32],
    ) -> Result<bool, SyncError> {
        let removed = self
            .state
            .replica_coordinator
            .link_repository()
            .recheck_digest_then_remove_link(group_id, local_path, expected_digest)
            .map_err(SyncError::from)?;
        if removed {
            self.state.durability().clear_custody_confirmation(group_id);
        }
        Ok(removed)
    }

    fn remove_link_expecting_group(
        &self,
        local_path: &str,
        group_id: &str,
    ) -> Result<(), SyncError> {
        self.state
            .replica_coordinator
            .link_repository()
            .remove_link_expecting_group(local_path, group_id)
            .map_err(SyncError::from)?;
        self.state.durability().clear_custody_confirmation(group_id);
        Ok(())
    }

    fn set_materialization_policy(
        &self,
        local_path: &str,
        policy: MaterializationPolicy,
    ) -> Result<(), SyncError> {
        self.state
            .replica_coordinator
            .link_repository()
            .set_materialization_policy(local_path, policy)
            .map_err(SyncError::from)
    }

    fn latch_group_durability_unknown(&self, group_id: &str) -> Result<(), SyncError> {
        self.state.latch_group_durability_unknown(group_id)
    }

    fn arm_duplicate_recovery_paths(&self, group_id: &str) -> Result<(), SyncError> {
        self.state
            .replica_coordinator
            .link_repository()
            .arm_duplicate_recovery_paths(group_id)
            .map_err(SyncError::from)
    }

    fn set_suppress_tombstones(&self, local_path: &str, suppress: bool) -> Result<(), SyncError> {
        self.state
            .replica_coordinator
            .link_repository()
            .set_suppress_tombstones(local_path, suppress)
            .map_err(SyncError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replica_coordinator::ReplicaCoordinator;
    use yadorilink_local_storage::SegmentBlockStore;

    /// The real removal checks the group inside its own transaction: a link of another
    /// group at the path stays, and nothing is reported removed.
    #[tokio::test]
    async fn removing_a_link_expecting_another_group_leaves_it_in_place() {
        let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
        let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let state = DaemonState::new("device-a".into(), sync_state, store);
        state.replica_coordinator.link_repository().add_link("/tmp/a", "group-2").unwrap();
        let repository = SyncStateReplicaRoleRepository::new(state.clone());

        let refused = repository.remove_link_expecting_group("/tmp/a", "group-1");
        assert!(matches!(refused, Err(SyncError::GroupMismatch(_))), "{refused:?}");
        assert_eq!(repository.list_links().unwrap().len(), 1);

        repository.remove_link_expecting_group("/tmp/a", "group-2").unwrap();
        assert!(repository.list_links().unwrap().is_empty());
    }
}
