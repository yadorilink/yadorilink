//! `DaemonState`-backed [`MembershipRepository`] -- wraps `DaemonState`
//! rather than raw `SyncState` directly (unlike the enrollment repository
//! adapter) because several of these journal writes also update
//! `DaemonState`'s own in-memory unknown-scope-marker cache
//! (`try_persist_membership_operation`/`settle_membership_operation`'s own
//! side effects) -- a caller going around `DaemonState` straight to
//! `SyncState` would silently desync that cache from the durable table.

use std::sync::Arc;

use crate::sync_error::SyncError;
use yadorilink_replica_domain::session_state::{
    FolderLink, MembershipCommitMode, MembershipDurabilityScope, MembershipOperationAction,
    MembershipOperationScan,
};

use crate::application::ports::MembershipRepository;
use crate::daemon_state::DaemonState;

pub(crate) struct SyncStateMembershipRepository {
    state: Arc<DaemonState>,
}

impl SyncStateMembershipRepository {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl MembershipRepository for SyncStateMembershipRepository {
    fn try_insert_operation(
        &self,
        operation_id: &str,
        action: MembershipOperationAction,
        commit_mode: MembershipCommitMode,
        removed_device_id: &str,
        group_ids: &[String],
        target_device_ids: &[String],
        lease_ids: &[Option<String>],
        durability_scope: MembershipDurabilityScope,
        latch_group_ids: &[String],
    ) -> Result<bool, String> {
        self.state.try_persist_membership_operation(
            operation_id,
            action,
            commit_mode,
            removed_device_id,
            group_ids,
            target_device_ids,
            lease_ids,
            yadorilink_replica_domain::session_state::MembershipOperationState::Prepared,
            durability_scope,
            latch_group_ids,
            None,
        )
    }

    fn settle_operation(&self, operation_id: &str) {
        self.state.settle_membership_operation(
            operation_id,
            yadorilink_replica_domain::session_state::MembershipOperationState::Completed,
        );
    }

    fn mark_ambiguous(&self, operation_id: &str, detail: &str) {
        self.state.mark_membership_operation_ambiguous(operation_id, detail);
    }

    fn mark_recovery_blocked(&self, operation_id: &str, detail: &str) {
        self.state.mark_membership_operation_recovery_blocked(operation_id, detail);
    }

    fn mark_local_settlement_pending(&self, operation_id: &str, detail: &str) {
        self.state.mark_membership_operation_local_settlement_pending(operation_id, detail);
    }

    fn discard_operation(&self, operation_id: &str) {
        self.state.discard_membership_operation(operation_id);
    }

    fn scan_open_operations(&self) -> Result<MembershipOperationScan, SyncError> {
        self.state
            .replica_coordinator
            .membership_operation_repository()
            .scan_open_membership_operations()
            .map_err(SyncError::from)
    }

    fn list_links(&self) -> Result<Vec<FolderLink>, SyncError> {
        self.state.replica_coordinator.link_repository().list_links().map_err(SyncError::from)
    }

    fn latch_group_durability_unknown(&self, group_id: &str) -> Result<(), SyncError> {
        self.state.latch_group_durability_unknown(group_id)
    }
}
