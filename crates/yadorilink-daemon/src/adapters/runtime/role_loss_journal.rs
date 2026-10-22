//! `DaemonState`-backed [`RoleLossJournal`].

use std::sync::Arc;

use yadorilink_replica_domain::session_state::{
    RoleLossAction, RoleLossOperation, RoleLossOperationState,
};

use crate::application::ports::RoleLossJournal;
use crate::daemon_state::{now_unix, DaemonState};

pub(crate) struct DaemonRoleLossJournal {
    state: Arc<DaemonState>,
}

impl DaemonRoleLossJournal {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl RoleLossJournal for DaemonRoleLossJournal {
    fn open_operation(
        &self,
        group_id: &str,
        target_device_id: &str,
        lease_id: &str,
        action: RoleLossAction,
        local_path: &str,
    ) -> Result<String, String> {
        self.state.open_role_loss_operation(
            group_id,
            target_device_id,
            lease_id,
            action,
            local_path,
        )
    }

    fn mark_worker_committed(&self, operation_id: &str, membership_generation: i64) {
        self.state.mark_role_loss_worker_committed(operation_id, membership_generation);
    }

    fn discard_operation(&self, operation_id: &str) {
        self.state.discard_role_loss_operation(operation_id);
    }

    fn settle_success(&self, operation_id: &str) {
        self.state.settle_role_loss_operation_success(operation_id);
    }

    fn get_operation(&self, operation_id: &str) -> Result<Option<RoleLossOperation>, String> {
        self.state
            .replica_coordinator
            .role_loss_operation_repository()
            .get_role_loss_operation(operation_id)
            .map_err(|e| e.to_string())
    }

    fn list_operations_in_states(
        &self,
        states: &[RoleLossOperationState],
    ) -> Result<Vec<RoleLossOperation>, String> {
        self.state
            .replica_coordinator
            .role_loss_operation_repository()
            .list_role_loss_operations_in_states(states)
            .map_err(|e| e.to_string())
    }

    fn advance_operation(
        &self,
        operation_id: &str,
        state: RoleLossOperationState,
    ) -> Result<(), String> {
        self.state
            .replica_coordinator
            .role_loss_operation_repository()
            .advance_role_loss_operation(operation_id, state, now_unix())
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn increment_attempts(&self, operation_id: &str) -> Result<i64, String> {
        self.state
            .replica_coordinator
            .role_loss_operation_repository()
            .increment_role_loss_operation_attempts(operation_id, now_unix())
            .map_err(|e| e.to_string())
    }

    fn delete_operation(&self, operation_id: &str) -> Result<(), String> {
        self.state
            .replica_coordinator
            .role_loss_operation_repository()
            .delete_role_loss_operation(operation_id)
            .map_err(|e| e.to_string())
    }
}
