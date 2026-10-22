//! `SyncState`-backed [`EnrollmentRepository`].

use std::sync::Arc;

use crate::sync_error::SyncError;
use yadorilink_replica_domain::session_state::{
    EnrollmentOperation, EnrollmentOperationScan, EnrollmentOperationState, FolderLink,
    PendingEnrollment, PendingEnrollmentScan,
};

use crate::application::ports::EnrollmentRepository;
use crate::replica_coordinator::ReplicaCoordinator;

pub(crate) struct SyncStateEnrollmentRepository {
    state: Arc<ReplicaCoordinator>,
}

impl SyncStateEnrollmentRepository {
    pub(crate) fn new(state: Arc<ReplicaCoordinator>) -> Self {
        Self { state }
    }
}

impl EnrollmentRepository for SyncStateEnrollmentRepository {
    fn try_insert_operation(&self, operation: &EnrollmentOperation) -> Result<bool, SyncError> {
        self.state
            .enrollment_repository()
            .try_insert_enrollment_operation(operation)
            .map_err(SyncError::from)
    }

    fn delete_operation(&self, operation_id: &str) -> Result<(), SyncError> {
        self.state
            .enrollment_repository()
            .delete_enrollment_operation(operation_id)
            .map_err(SyncError::from)
    }

    fn mark_prepared(
        &self,
        operation_id: &str,
        group_id: &str,
        now_unix: i64,
    ) -> Result<bool, SyncError> {
        self.state
            .enrollment_repository()
            .mark_enrollment_operation_prepared(operation_id, group_id, now_unix)
            .map_err(SyncError::from)
    }

    fn mark_state(
        &self,
        operation_id: &str,
        state: EnrollmentOperationState,
        error: Option<&str>,
        now_unix: i64,
    ) -> Result<bool, SyncError> {
        self.state
            .enrollment_repository()
            .mark_enrollment_operation_state(operation_id, state, error, now_unix)
            .map_err(SyncError::from)
    }

    fn list_links(&self) -> Result<Vec<FolderLink>, SyncError> {
        self.state.link_repository().list_links().map_err(SyncError::from)
    }

    fn creation_digest(&self, locator: &str) -> Result<Option<String>, SyncError> {
        self.state.link_repository().creation_digest(locator).map_err(SyncError::from)
    }

    fn scan_pending(&self) -> Result<PendingEnrollmentScan, SyncError> {
        self.state.enrollment_repository().scan_pending_enrollments().map_err(SyncError::from)
    }

    fn settle_activated(&self, operation_id: &str) -> Result<(), SyncError> {
        self.state
            .enrollment_repository()
            .remove_pending_enrollment(operation_id)
            .map_err(SyncError::from)
    }

    fn operation(&self, operation_id: &str) -> Result<Option<EnrollmentOperation>, SyncError> {
        self.state
            .enrollment_repository()
            .get_enrollment_operation(operation_id)
            .map_err(SyncError::from)
    }

    fn scan_open_operations(&self) -> Result<EnrollmentOperationScan, SyncError> {
        self.state
            .enrollment_repository()
            .scan_open_enrollment_operations()
            .map_err(SyncError::from)
    }

    fn settle_activated_and_close(&self, operation_id: &str) -> Result<(), SyncError> {
        self.state
            .enrollment_repository()
            .settle_activated_enrollment(operation_id)
            .map_err(SyncError::from)
    }

    fn move_marker_to_cancel_operation(
        &self,
        marker: &PendingEnrollment,
        now_unix: i64,
    ) -> Result<(), SyncError> {
        self.state
            .enrollment_repository()
            .move_pending_enrollment_to_cancel_operation(marker, now_unix)
            .map_err(SyncError::from)
    }

    fn increment_attempts(&self, operation_id: &str, now_unix: i64) -> Result<i64, SyncError> {
        self.state
            .enrollment_repository()
            .increment_enrollment_operation_attempts(operation_id, now_unix)
            .map_err(SyncError::from)
    }

    fn rollback_local_setup_to_cancel_pending(
        &self,
        local_path: &str,
        operation_id: &str,
        detail: &str,
        now_unix: i64,
    ) -> Result<bool, SyncError> {
        self.state
            .enrollment_repository()
            .rollback_local_setup_to_cancel_pending(local_path, operation_id, detail, now_unix)
            .map_err(SyncError::from)
    }
}
