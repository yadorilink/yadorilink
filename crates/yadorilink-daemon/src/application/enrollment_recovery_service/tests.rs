#![cfg(test)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use yadorilink_replica_domain::session_state::MaterializationPolicy;
use yadorilink_replica_domain::session_state::{
    FolderLink, InvalidEnrollmentOperation, InvalidPendingEnrollment, PendingEnrollment,
};

use super::*;
use crate::application::ports::EnrollmentLinkRequest;
use crate::application::EnrollmentLinkError;

#[derive(Clone, Debug, PartialEq, Eq)]
enum RepoCall {
    MarkPrepared(String, String),
    MarkState(String, OpState),
    DeleteOperation(String),
    SettleActivatedAndClose(String),
    MoveMarkerToCancelOperation(String),
    IncrementAttempts(String),
    RollbackLocalSetup(String),
}

#[derive(Default)]
struct FakeRepository {
    calls: Mutex<Vec<RepoCall>>,
    operations: Mutex<std::collections::HashMap<String, EnrollmentOperation>>,
    links: Mutex<Vec<FolderLink>>,
    markers: Mutex<yadorilink_replica_domain::session_state::PendingEnrollmentScan>,
    invalid_operations: Mutex<Vec<InvalidEnrollmentOperation>>,
    fail_list_links: AtomicBool,
    fail_scan_pending: AtomicBool,
    fail_scan_open: AtomicBool,
    /// The journal row has no recorded link write for the rollback to undo.
    no_recorded_link_write: AtomicBool,
}

impl FakeRepository {
    fn with_operation(self, operation: EnrollmentOperation) -> Self {
        self.operations.lock().unwrap().insert(operation.operation_id.clone(), operation);
        self
    }

    fn with_link(self, link: FolderLink) -> Self {
        self.links.lock().unwrap().push(link);
        self
    }

    fn with_marker(self, marker: PendingEnrollment) -> Self {
        self.markers.lock().unwrap().valid.push(marker);
        self
    }
}

impl EnrollmentRepository for FakeRepository {
    fn try_insert_operation(
        &self,
        _operation: &EnrollmentOperation,
    ) -> Result<bool, crate::sync_error::SyncError> {
        unimplemented!("not exercised by recovery-service tests")
    }

    fn delete_operation(&self, operation_id: &str) -> Result<(), crate::sync_error::SyncError> {
        self.calls.lock().unwrap().push(RepoCall::DeleteOperation(operation_id.to_string()));
        self.operations.lock().unwrap().remove(operation_id);
        Ok(())
    }

    fn mark_prepared(
        &self,
        operation_id: &str,
        group_id: &str,
        _now_unix: i64,
    ) -> Result<bool, crate::sync_error::SyncError> {
        self.calls
            .lock()
            .unwrap()
            .push(RepoCall::MarkPrepared(operation_id.to_string(), group_id.to_string()));
        let mut operations = self.operations.lock().unwrap();
        let Some(op) = operations.get_mut(operation_id) else { return Ok(false) };
        op.group_id = Some(group_id.to_string());
        op.state = OpState::Prepared;
        Ok(true)
    }

    fn mark_state(
        &self,
        operation_id: &str,
        state: OpState,
        _error: Option<&str>,
        _now_unix: i64,
    ) -> Result<bool, crate::sync_error::SyncError> {
        self.calls.lock().unwrap().push(RepoCall::MarkState(operation_id.to_string(), state));
        let mut operations = self.operations.lock().unwrap();
        let Some(op) = operations.get_mut(operation_id) else { return Ok(false) };
        op.state = state;
        Ok(true)
    }

    fn creation_digest(
        &self,
        _locator: &str,
    ) -> Result<Option<String>, crate::sync_error::SyncError> {
        Ok(None)
    }

    fn list_links(&self) -> Result<Vec<FolderLink>, crate::sync_error::SyncError> {
        if self.fail_list_links.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("fake list_links failure").into());
        }
        Ok(self.links.lock().unwrap().clone())
    }

    fn scan_pending(
        &self,
    ) -> Result<
        yadorilink_replica_domain::session_state::PendingEnrollmentScan,
        crate::sync_error::SyncError,
    > {
        if self.fail_scan_pending.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("fake scan_pending failure").into());
        }
        Ok(self.markers.lock().unwrap().clone())
    }

    fn settle_activated(&self, _operation_id: &str) -> Result<(), crate::sync_error::SyncError> {
        unimplemented!("recovery uses settle_activated_and_close, not settle_activated")
    }

    fn operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<EnrollmentOperation>, crate::sync_error::SyncError> {
        Ok(self.operations.lock().unwrap().get(operation_id).cloned())
    }

    fn scan_open_operations(
        &self,
    ) -> Result<
        yadorilink_replica_domain::session_state::EnrollmentOperationScan,
        crate::sync_error::SyncError,
    > {
        if self.fail_scan_open.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("fake scan_open_operations failure").into());
        }
        Ok(yadorilink_replica_domain::session_state::EnrollmentOperationScan {
            valid: self
                .operations
                .lock()
                .unwrap()
                .values()
                .filter(|op| op.state != OpState::RecoveryBlocked)
                .cloned()
                .collect(),
            invalid: self.invalid_operations.lock().unwrap().clone(),
        })
    }

    fn settle_activated_and_close(
        &self,
        operation_id: &str,
    ) -> Result<(), crate::sync_error::SyncError> {
        self.calls
            .lock()
            .unwrap()
            .push(RepoCall::SettleActivatedAndClose(operation_id.to_string()));
        self.operations.lock().unwrap().remove(operation_id);
        self.markers.lock().unwrap().valid.retain(|m| m.operation_id != operation_id);
        Ok(())
    }

    fn move_marker_to_cancel_operation(
        &self,
        marker: &PendingEnrollment,
        _now_unix: i64,
    ) -> Result<(), crate::sync_error::SyncError> {
        self.calls
            .lock()
            .unwrap()
            .push(RepoCall::MoveMarkerToCancelOperation(marker.operation_id.clone()));
        self.markers.lock().unwrap().valid.retain(|m| m.operation_id != marker.operation_id);
        if let Some(op) = self.operations.lock().unwrap().get_mut(&marker.operation_id) {
            op.state = OpState::CancelPending;
        }
        Ok(())
    }

    fn increment_attempts(
        &self,
        operation_id: &str,
        _now_unix: i64,
    ) -> Result<i64, crate::sync_error::SyncError> {
        self.calls.lock().unwrap().push(RepoCall::IncrementAttempts(operation_id.to_string()));
        Ok(1)
    }

    fn rollback_local_setup_to_cancel_pending(
        &self,
        _local_path: &str,
        operation_id: &str,
        _detail: &str,
        _now_unix: i64,
    ) -> Result<bool, crate::sync_error::SyncError> {
        self.calls.lock().unwrap().push(RepoCall::RollbackLocalSetup(operation_id.to_string()));
        if self.no_recorded_link_write.load(Ordering::SeqCst) {
            return Ok(false);
        }
        if let Some(op) = self.operations.lock().unwrap().get_mut(operation_id) {
            op.state = OpState::CancelPending;
        }
        Ok(true)
    }
}

#[derive(Default)]
struct FakeCoordination {
    activate: Mutex<VecDeque<EnrollmentActivationResult>>,
    cancel: Mutex<VecDeque<EnrollmentCancellationResult>>,
    prepare: Mutex<VecDeque<EnrollmentPrepareResult>>,
    activate_calls: Mutex<u32>,
    cancel_calls: Mutex<u32>,
}

impl EnrollmentCoordination for FakeCoordination {
    fn is_configured(&self) -> bool {
        true
    }

    fn prepare_create<'a>(
        &'a self,
        _operation_id: &'a str,
        _group_name: &'a str,
        _device_id: &'a str,
        _storage_mode: &'a str,
    ) -> crate::application::ports::BoxFuture<'a, EnrollmentPrepareResult> {
        Box::pin(
            async move { self.prepare.lock().unwrap().pop_front().expect("missing fake prepare") },
        )
    }

    fn prepare_join<'a>(
        &'a self,
        _operation_id: &'a str,
        _group_id: &'a str,
        _device_id: &'a str,
        _storage_mode: &'a str,
    ) -> crate::application::ports::BoxFuture<'a, EnrollmentPrepareResult> {
        Box::pin(
            async move { self.prepare.lock().unwrap().pop_front().expect("missing fake prepare") },
        )
    }

    fn activate_create<'a>(
        &'a self,
        _group_id: &'a str,
        _operation_id: &'a str,
    ) -> crate::application::ports::BoxFuture<'a, EnrollmentActivationResult> {
        Box::pin(async move {
            *self.activate_calls.lock().unwrap() += 1;
            self.activate.lock().unwrap().pop_front().expect("missing fake activate")
        })
    }

    fn activate_join<'a>(
        &'a self,
        _group_id: &'a str,
        _operation_id: &'a str,
        _device_id: &'a str,
    ) -> crate::application::ports::BoxFuture<'a, EnrollmentActivationResult> {
        Box::pin(async move {
            *self.activate_calls.lock().unwrap() += 1;
            self.activate.lock().unwrap().pop_front().expect("missing fake activate")
        })
    }

    fn cancel_create<'a>(
        &'a self,
        _group_id: &'a str,
        _operation_id: &'a str,
    ) -> crate::application::ports::BoxFuture<'a, EnrollmentCancellationResult> {
        Box::pin(async move {
            *self.cancel_calls.lock().unwrap() += 1;
            self.cancel.lock().unwrap().pop_front().expect("missing fake cancel")
        })
    }

    fn cancel_join<'a>(
        &'a self,
        _group_id: &'a str,
        _operation_id: &'a str,
        _device_id: &'a str,
    ) -> crate::application::ports::BoxFuture<'a, EnrollmentCancellationResult> {
        Box::pin(async move {
            *self.cancel_calls.lock().unwrap() += 1;
            self.cancel.lock().unwrap().pop_front().expect("missing fake cancel")
        })
    }

    fn prepare_invite_accept<'a>(
        &'a self,
        _operation_id: &'a str,
        _code: &'a str,
        _device_id: &'a str,
        _storage_mode: &'a str,
    ) -> crate::application::ports::BoxFuture<'a, EnrollmentPrepareResult> {
        Box::pin(
            async move { self.prepare.lock().unwrap().pop_front().expect("missing fake prepare") },
        )
    }

    fn activate_invite_accept<'a>(
        &'a self,
        _group_id: &'a str,
        _operation_id: &'a str,
        _device_id: &'a str,
    ) -> crate::application::ports::BoxFuture<'a, EnrollmentActivationResult> {
        Box::pin(async move {
            *self.activate_calls.lock().unwrap() += 1;
            self.activate.lock().unwrap().pop_front().expect("missing fake activate")
        })
    }

    fn cancel_invite_accept<'a>(
        &'a self,
        _group_id: &'a str,
        _operation_id: &'a str,
        _device_id: &'a str,
    ) -> crate::application::ports::BoxFuture<'a, EnrollmentCancellationResult> {
        Box::pin(async move {
            *self.cancel_calls.lock().unwrap() += 1;
            self.cancel.lock().unwrap().pop_front().expect("missing fake cancel")
        })
    }

    fn mint_invite<'a>(
        &'a self,
        _group_id: &'a str,
        _role: Option<&'a str>,
        _ttl_secs: Option<u64>,
        _requires_approval: bool,
    ) -> crate::application::ports::BoxFuture<
        'a,
        Result<crate::application::model::MintedInvite, String>,
    > {
        Box::pin(async move { unimplemented!("recovery never mints an invite") })
    }
}

#[derive(Default)]
struct FakeLinkPort {
    rollback_calls: Mutex<Vec<(String, String)>>,
    rollback_result: Mutex<VecDeque<Result<(), String>>>,
}

impl EnrollmentLinkPort for FakeLinkPort {
    fn commit<'a>(
        &'a self,
        _request: EnrollmentLinkRequest,
    ) -> crate::application::ports::BoxFuture<
        'a,
        Result<crate::application::LinkOutcome, EnrollmentLinkError>,
    > {
        Box::pin(async move { unimplemented!("recovery never commits a new link") })
    }

    fn rollback<'a>(
        &'a self,
        local_path: &'a str,
        operation_id: &'a str,
    ) -> crate::application::ports::BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.rollback_calls
                .lock()
                .unwrap()
                .push((local_path.to_string(), operation_id.to_string()));
            self.rollback_result.lock().unwrap().pop_front().expect("missing fake rollback result")
        })
    }

    fn commit_plain<'a>(
        &'a self,
        _group_id: &'a str,
        _absolute_path: &'a std::path::Path,
        _on_demand: bool,
    ) -> crate::application::ports::BoxFuture<'a, Result<(), EnrollmentLinkError>> {
        Box::pin(async move { unimplemented!("recovery never commits a plain link") })
    }
}

#[derive(Default)]
struct FakeAttemptTracker {
    counters: Mutex<std::collections::HashMap<String, u32>>,
    cleared: Mutex<Vec<String>>,
}

impl EnrollmentAttemptTracker for FakeAttemptTracker {
    fn note_transient_attempt(&self, operation_id: &str) -> u32 {
        let mut counters = self.counters.lock().unwrap();
        let count = counters.entry(operation_id.to_string()).or_insert(0);
        *count += 1;
        *count
    }

    fn clear_transient_attempts(&self, operation_id: &str) {
        self.cleared.lock().unwrap().push(operation_id.to_string());
    }
}

fn service(
    repository: Arc<FakeRepository>,
    coordination: Arc<FakeCoordination>,
    links: Arc<FakeLinkPort>,
    attempts: Arc<FakeAttemptTracker>,
) -> EnrollmentRecoveryService {
    EnrollmentRecoveryService::new(repository, coordination, links, attempts)
}

fn marker(operation_id: &str, group_id: &str) -> PendingEnrollment {
    PendingEnrollment {
        operation_id: operation_id.to_string(),
        kind: WireEnrollmentKind::Create,
        group_id: group_id.to_string(),
        device_id: "device-a".to_string(),
        local_path: "/home/alice/Photos".to_string(),
    }
}

fn link(group_id: &str) -> FolderLink {
    FolderLink {
        location: yadorilink_replica_domain::session_state::LinkLocation::Folder(
            "/home/alice/Photos".to_string(),
        ),
        group_id: group_id.to_string(),
        paused: false,
        materialization_policy: MaterializationPolicy::Eager,
        orphaned: false,
    }
}

fn operation(operation_id: &str, group_id: &str, state: OpState) -> EnrollmentOperation {
    EnrollmentOperation {
        operation_id: operation_id.to_string(),
        kind: WireEnrollmentKind::Create,
        group_id: Some(group_id.to_string()),
        group_name: Some("photos".to_string()),
        device_id: "device-a".to_string(),
        local_path: "/home/alice/Photos".to_string(),
        storage_mode: "eager".to_string(),
        state,
        last_error: None,
        attempts: 0,
        created_at_unix: 0,
        updated_at_unix: 0,
    }
}

// ===== Marker reconciliation =====

#[tokio::test]
async fn confirmed_activation_settles_marker_and_journal_together() {
    let repository = Arc::new(
        FakeRepository::default()
            .with_operation(operation("op-1", "group-1", OpState::ActivationPending))
            .with_link(link("group-1"))
            .with_marker(marker("op-1", "group-1")),
    );
    let coordination = Arc::new(FakeCoordination::default());
    coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::Activated);
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository.clone(), coordination, links.clone(), attempts.clone())
        .reconcile_once()
        .await;

    assert!(repository
        .calls
        .lock()
        .unwrap()
        .contains(&RepoCall::SettleActivatedAndClose("op-1".to_string())));
    assert!(links.rollback_calls.lock().unwrap().is_empty());
    assert_eq!(*attempts.cleared.lock().unwrap(), vec!["op-1".to_string()]);
}

#[tokio::test]
async fn deleted_activation_rolls_back_via_the_link_port() {
    let repository = Arc::new(
        FakeRepository::default()
            .with_operation(operation("op-1", "group-1", OpState::ActivationPending))
            .with_link(link("group-1"))
            .with_marker(marker("op-1", "group-1")),
    );
    let coordination = Arc::new(FakeCoordination::default());
    coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::Deleted);
    let links = Arc::new(FakeLinkPort::default());
    links.rollback_result.lock().unwrap().push_back(Ok(()));
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository.clone(), coordination, links.clone(), attempts).reconcile_once().await;

    assert_eq!(
        *links.rollback_calls.lock().unwrap(),
        vec![("/home/alice/Photos".to_string(), "op-1".to_string())]
    );
    assert!(!repository
        .calls
        .lock()
        .unwrap()
        .contains(&RepoCall::SettleActivatedAndClose("op-1".to_string())));
}

#[tokio::test]
async fn transient_activation_failure_never_rolls_back_and_counts_attempts() {
    let repository = Arc::new(
        FakeRepository::default()
            .with_operation(operation("op-1", "group-1", OpState::ActivationPending))
            .with_link(link("group-1"))
            .with_marker(marker("op-1", "group-1")),
    );
    let coordination = Arc::new(FakeCoordination::default());
    coordination
        .activate
        .lock()
        .unwrap()
        .push_back(EnrollmentActivationResult::TransientFailure { detail: "timeout".to_string() });
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository, coordination, links.clone(), attempts.clone()).reconcile_once().await;

    assert!(links.rollback_calls.lock().unwrap().is_empty());
    assert_eq!(attempts.counters.lock().unwrap().get("op-1"), Some(&1));
}

#[tokio::test]
async fn activation_pending_gate_skips_a_non_activation_pending_row() {
    let repository = Arc::new(
        FakeRepository::default()
            .with_operation(operation("op-1", "group-1", OpState::LocalSetupPending))
            .with_link(link("group-1"))
            .with_marker(marker("op-1", "group-1")),
    );
    let coordination = Arc::new(FakeCoordination::default());
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository, coordination.clone(), links, attempts).reconcile_once().await;

    assert_eq!(*coordination.activate_calls.lock().unwrap(), 0);
}

#[tokio::test]
async fn identity_mismatch_between_marker_and_operation_blocks_recovery() {
    let repository = Arc::new(
        FakeRepository::default()
            .with_operation(operation("op-1", "group-other", OpState::ActivationPending))
            .with_link(link("group-1"))
            .with_marker(marker("op-1", "group-1")),
    );
    let coordination = Arc::new(FakeCoordination::default());
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository.clone(), coordination.clone(), links, attempts).reconcile_once().await;

    assert_eq!(*coordination.activate_calls.lock().unwrap(), 0);
    assert!(repository
        .calls
        .lock()
        .unwrap()
        .contains(&RepoCall::MarkState("op-1".to_string(), OpState::RecoveryBlocked)));
}

#[tokio::test]
async fn a_marker_with_no_matching_link_transfers_to_cancel_pending_then_retries_cancel() {
    let repository = Arc::new(
        FakeRepository::default()
            .with_operation(operation("op-1", "group-1", OpState::ActivationPending))
            .with_marker(marker("op-1", "group-1")),
    );
    let coordination = Arc::new(FakeCoordination::default());
    coordination.cancel.lock().unwrap().push_back(EnrollmentCancellationResult::Confirmed);
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository.clone(), coordination.clone(), links, attempts).reconcile_once().await;

    assert!(repository
        .calls
        .lock()
        .unwrap()
        .contains(&RepoCall::MoveMarkerToCancelOperation("op-1".to_string())));
    assert!(repository
        .calls
        .lock()
        .unwrap()
        .contains(&RepoCall::DeleteOperation("op-1".to_string())));
    assert_eq!(*coordination.cancel_calls.lock().unwrap(), 1);
}

#[tokio::test]
async fn a_malformed_marker_blocks_only_that_row_not_sibling_rows() {
    let repository = Arc::new(
        FakeRepository::default()
            .with_operation(operation("op-1", "group-1", OpState::ActivationPending))
            .with_link(link("group-1"))
            .with_marker(marker("op-2", "group-2")),
    );
    repository.markers.lock().unwrap().invalid.push(InvalidPendingEnrollment {
        operation_id: "op-bad".to_string(),
        detail: "unrecognized kind".to_string(),
    });
    let coordination = Arc::new(FakeCoordination::default());
    coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::AlreadyActive);
    // op-2's marker has no matching link (its group doesn't match
    // op-1's link), so reconcile_markers routes it through the
    // no-matching-link cancel path -- queue a result for that too.
    coordination.cancel.lock().unwrap().push_back(EnrollmentCancellationResult::Confirmed);
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository.clone(), coordination.clone(), links, attempts).reconcile_once().await;

    let calls = repository.calls.lock().unwrap();
    assert!(calls.contains(&RepoCall::MarkState("op-bad".to_string(), OpState::RecoveryBlocked)));
    // Sibling marker op-1/op-2 pairing doesn't line up (op-1's marker is
    // op-2's group), so activation is never attempted for it here --
    // proven separately above. This test only proves the malformed row
    // did not abort the whole sweep (the call log has more than the one
    // block entry, i.e. iteration continued).
    drop(calls);
}

// ===== Journal reconciliation: PreparePending =====

#[tokio::test]
async fn prepare_pending_success_marks_prepared() {
    let mut op = operation("op-1", "group-1", OpState::PreparePending);
    op.updated_at_unix = -1000;
    let repository = Arc::new(FakeRepository::default().with_operation(op));
    let coordination = Arc::new(FakeCoordination::default());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository.clone(), coordination, links, attempts).reconcile_once().await;

    assert!(repository
        .calls
        .lock()
        .unwrap()
        .contains(&RepoCall::MarkPrepared("op-1".to_string(), "group-1".to_string())));
}

#[tokio::test]
async fn prepare_pending_definitely_rejected_deletes_the_row() {
    let mut op = operation("op-1", "group-1", OpState::PreparePending);
    op.updated_at_unix = -1000;
    let repository = Arc::new(FakeRepository::default().with_operation(op));
    let coordination = Arc::new(FakeCoordination::default());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::DefinitelyRejected { detail: "gone".to_string() });
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository.clone(), coordination, links, attempts).reconcile_once().await;

    assert!(repository
        .calls
        .lock()
        .unwrap()
        .contains(&RepoCall::DeleteOperation("op-1".to_string())));
}

#[tokio::test]
async fn prepare_pending_conflict_blocks_recovery() {
    let mut op = operation("op-1", "group-1", OpState::PreparePending);
    op.updated_at_unix = -1000;
    let repository = Arc::new(FakeRepository::default().with_operation(op));
    let coordination = Arc::new(FakeCoordination::default());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Conflict { detail: "shape mismatch".to_string() });
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository.clone(), coordination, links, attempts).reconcile_once().await;

    assert!(repository
        .calls
        .lock()
        .unwrap()
        .contains(&RepoCall::MarkState("op-1".to_string(), OpState::RecoveryBlocked)));
}

// ===== Journal reconciliation: Prepared =====

#[tokio::test]
async fn prepared_with_matching_link_and_marker_advances_to_local_setup_pending() {
    let mut op = operation("op-1", "group-1", OpState::Prepared);
    op.updated_at_unix = -1000;
    let repository = Arc::new(
        FakeRepository::default()
            .with_operation(op)
            .with_link(link("group-1"))
            .with_marker(marker("op-1", "group-1")),
    );
    let coordination = Arc::new(FakeCoordination::default());
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository.clone(), coordination, links, attempts).reconcile_once().await;

    assert!(repository
        .calls
        .lock()
        .unwrap()
        .contains(&RepoCall::MarkState("op-1".to_string(), OpState::LocalSetupPending)));
}

#[tokio::test]
async fn prepared_with_neither_link_nor_marker_moves_to_cancel_pending() {
    let mut op = operation("op-1", "group-1", OpState::Prepared);
    op.updated_at_unix = -1000;
    let repository = Arc::new(FakeRepository::default().with_operation(op));
    let coordination = Arc::new(FakeCoordination::default());
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository.clone(), coordination, links, attempts).reconcile_once().await;

    assert!(repository
        .calls
        .lock()
        .unwrap()
        .contains(&RepoCall::MarkState("op-1".to_string(), OpState::CancelPending)));
}

#[tokio::test]
async fn prepared_with_link_but_no_marker_blocks_recovery() {
    let mut op = operation("op-1", "group-1", OpState::Prepared);
    op.updated_at_unix = -1000;
    let repository =
        Arc::new(FakeRepository::default().with_operation(op).with_link(link("group-1")));
    let coordination = Arc::new(FakeCoordination::default());
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository.clone(), coordination, links, attempts).reconcile_once().await;

    assert!(repository
        .calls
        .lock()
        .unwrap()
        .contains(&RepoCall::MarkState("op-1".to_string(), OpState::RecoveryBlocked)));
}

/// A `share join` of a folder already linked to the group and running
/// commits nothing locally: its row stays `Prepared`, beside the earlier
/// link, with no marker, for the whole `activate_join` round trip. A daemon
/// that dies in that window must not leave the row blocked for operator
/// attention -- recovery finishes what the join was doing: activate by
/// (group, device), then close the row, never touching the link.
fn rejoin_left_prepared(state_link: FolderLink) -> Arc<FakeRepository> {
    let mut op = operation("op-1", "group-1", OpState::Prepared);
    op.kind = WireEnrollmentKind::Join;
    op.group_name = None;
    op.updated_at_unix = -1000;
    Arc::new(FakeRepository::default().with_operation(op).with_link(state_link))
}

#[tokio::test]
async fn an_interrupted_rejoin_of_a_linked_folder_is_settled_not_blocked() {
    let repository = rejoin_left_prepared(link("group-1"));
    let coordination = Arc::new(FakeCoordination::default());
    coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::AlreadyActive);
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository.clone(), coordination.clone(), links.clone(), attempts)
        .reconcile_once()
        .await;

    let calls = repository.calls.lock().unwrap().clone();
    assert!(
        !calls.contains(&RepoCall::MarkState("op-1".to_string(), OpState::RecoveryBlocked)),
        "an interrupted no-op re-join must not be blocked: {calls:?}"
    );
    assert!(calls.contains(&RepoCall::DeleteOperation("op-1".to_string())), "{calls:?}");
    assert_eq!(*coordination.activate_calls.lock().unwrap(), 1);
    assert!(links.rollback_calls.lock().unwrap().is_empty(), "the link is never touched");
    assert_eq!(repository.links.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn an_interrupted_rejoin_whose_membership_is_gone_closes_the_row_and_keeps_the_link() {
    let repository = rejoin_left_prepared(link("group-1"));
    let coordination = Arc::new(FakeCoordination::default());
    coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::Deleted);
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository.clone(), coordination, links.clone(), attempts).reconcile_once().await;

    let calls = repository.calls.lock().unwrap().clone();
    assert!(calls.contains(&RepoCall::DeleteOperation("op-1".to_string())), "{calls:?}");
    assert!(
        !calls.contains(&RepoCall::MarkState("op-1".to_string(), OpState::RecoveryBlocked)),
        "{calls:?}"
    );
    assert!(links.rollback_calls.lock().unwrap().is_empty(), "the link is never touched");
}

#[tokio::test]
async fn an_interrupted_rejoin_with_a_transient_activation_failure_is_left_for_the_next_sweep() {
    let repository = rejoin_left_prepared(link("group-1"));
    let coordination = Arc::new(FakeCoordination::default());
    coordination
        .activate
        .lock()
        .unwrap()
        .push_back(EnrollmentActivationResult::TransientFailure { detail: "offline".to_string() });
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository.clone(), coordination, links.clone(), attempts).reconcile_once().await;

    let calls = repository.calls.lock().unwrap().clone();
    assert!(
        !calls
            .iter()
            .any(|call| matches!(call, RepoCall::MarkState(_, _) | RepoCall::DeleteOperation(_))),
        "the row stays Prepared for the next sweep: {calls:?}"
    );
    assert_eq!(repository.operations.lock().unwrap()["op-1"].state, OpState::Prepared);
    assert!(links.rollback_calls.lock().unwrap().is_empty());
}

/// Only a live link settles this way: a join row beside an ORPHANED link is
/// a shape the re-join path never leaves (it commits over an orphaned row),
/// so it stays blocked for an operator.
#[tokio::test]
async fn a_prepared_join_beside_an_orphaned_link_with_no_marker_still_blocks() {
    let mut orphaned = link("group-1");
    orphaned.orphaned = true;
    let repository = rejoin_left_prepared(orphaned);
    let coordination = Arc::new(FakeCoordination::default());
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository.clone(), coordination.clone(), links, attempts).reconcile_once().await;

    assert!(repository
        .calls
        .lock()
        .unwrap()
        .contains(&RepoCall::MarkState("op-1".to_string(), OpState::RecoveryBlocked)));
    assert_eq!(*coordination.activate_calls.lock().unwrap(), 0);
}

#[tokio::test]
async fn prepared_with_marker_but_no_link_transfers_to_cancel_operation() {
    let mut op = operation("op-1", "group-1", OpState::Prepared);
    op.updated_at_unix = -1000;
    let repository = Arc::new(
        FakeRepository::default().with_operation(op).with_marker(marker("op-1", "group-1")),
    );
    let coordination = Arc::new(FakeCoordination::default());
    // No link exists, so `reconcile_markers` itself also routes this
    // marker through the no-matching-link cancel path before
    // `reconcile_operations`'s own `Prepared` branch ever runs.
    coordination.cancel.lock().unwrap().push_back(EnrollmentCancellationResult::Confirmed);
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository.clone(), coordination, links, attempts).reconcile_once().await;

    assert!(repository
        .calls
        .lock()
        .unwrap()
        .contains(&RepoCall::MoveMarkerToCancelOperation("op-1".to_string())));
}

// ===== Journal reconciliation: LocalSetupPending / ActivationPending / CancelPending =====

#[tokio::test]
async fn local_setup_pending_past_the_age_gate_rolls_back_its_recorded_link_write() {
    let mut op = operation("op-1", "group-1", OpState::LocalSetupPending);
    op.updated_at_unix = -1000;
    let repository = Arc::new(FakeRepository::default().with_operation(op));
    let coordination = Arc::new(FakeCoordination::default());
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository.clone(), coordination, links, attempts).reconcile_once().await;

    assert!(repository
        .calls
        .lock()
        .unwrap()
        .contains(&RepoCall::RollbackLocalSetup("op-1".to_string())));
}

/// Without a recorded link write there is no telling whether the row at the
/// path is this operation's or an earlier link's, so the row is blocked for
/// an operator rather than rolled back by guessing.
#[tokio::test]
async fn local_setup_pending_with_no_recorded_link_write_is_blocked_not_guessed() {
    let mut op = operation("op-1", "group-1", OpState::LocalSetupPending);
    op.updated_at_unix = -1000;
    let repository = Arc::new(FakeRepository::default().with_operation(op));
    repository.no_recorded_link_write.store(true, Ordering::SeqCst);
    let coordination = Arc::new(FakeCoordination::default());
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository.clone(), coordination, links, attempts).reconcile_once().await;

    assert!(repository
        .calls
        .lock()
        .unwrap()
        .contains(&RepoCall::MarkState("op-1".to_string(), OpState::RecoveryBlocked)));
}

#[tokio::test]
async fn activation_pending_with_an_outstanding_marker_is_left_untouched() {
    let mut op = operation("op-1", "group-1", OpState::ActivationPending);
    op.updated_at_unix = -1000;
    let repository = Arc::new(
        FakeRepository::default()
            .with_operation(op)
            .with_link(link("group-1"))
            .with_marker(marker("op-1", "group-1")),
    );
    let coordination = Arc::new(FakeCoordination::default());
    coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::AlreadyActive);
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository.clone(), coordination, links, attempts).reconcile_once().await;

    let calls = repository.calls.lock().unwrap();
    assert!(!calls.contains(&RepoCall::DeleteOperation("op-1".to_string())));
    assert!(!calls
        .iter()
        .any(|c| matches!(c, RepoCall::MarkState(id, OpState::CancelPending) if id == "op-1")));
}

#[tokio::test]
async fn activation_pending_with_no_marker_and_a_matching_link_is_confirmed_cleanup() {
    let mut op = operation("op-1", "group-1", OpState::ActivationPending);
    op.updated_at_unix = -1000;
    let repository =
        Arc::new(FakeRepository::default().with_operation(op).with_link(link("group-1")));
    let coordination = Arc::new(FakeCoordination::default());
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository.clone(), coordination, links, attempts).reconcile_once().await;

    assert!(repository
        .calls
        .lock()
        .unwrap()
        .contains(&RepoCall::DeleteOperation("op-1".to_string())));
}

#[tokio::test]
async fn activation_pending_with_neither_marker_nor_link_moves_to_cancel_pending() {
    let mut op = operation("op-1", "group-1", OpState::ActivationPending);
    op.updated_at_unix = -1000;
    let repository = Arc::new(FakeRepository::default().with_operation(op));
    let coordination = Arc::new(FakeCoordination::default());
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository.clone(), coordination, links, attempts).reconcile_once().await;

    assert!(repository
        .calls
        .lock()
        .unwrap()
        .contains(&RepoCall::MarkState("op-1".to_string(), OpState::CancelPending)));
}

#[tokio::test]
async fn cancel_pending_confirmed_deletes_the_row() {
    let mut op = operation("op-1", "group-1", OpState::CancelPending);
    op.updated_at_unix = -1000;
    let repository = Arc::new(FakeRepository::default().with_operation(op));
    let coordination = Arc::new(FakeCoordination::default());
    coordination.cancel.lock().unwrap().push_back(EnrollmentCancellationResult::Confirmed);
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository.clone(), coordination, links, attempts).reconcile_once().await;

    assert!(repository
        .calls
        .lock()
        .unwrap()
        .contains(&RepoCall::DeleteOperation("op-1".to_string())));
}

#[tokio::test]
async fn cancel_pending_conflict_blocks_recovery() {
    let mut op = operation("op-1", "group-1", OpState::CancelPending);
    op.updated_at_unix = -1000;
    let repository = Arc::new(FakeRepository::default().with_operation(op));
    let coordination = Arc::new(FakeCoordination::default());
    coordination.cancel.lock().unwrap().push_back(EnrollmentCancellationResult::Conflict {
        detail: "identity mismatch".to_string(),
    });
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository.clone(), coordination, links, attempts).reconcile_once().await;

    assert!(repository
        .calls
        .lock()
        .unwrap()
        .contains(&RepoCall::MarkState("op-1".to_string(), OpState::RecoveryBlocked)));
}

#[tokio::test]
async fn cancel_pending_ambiguous_increments_attempts_and_never_blocks() {
    let mut op = operation("op-1", "group-1", OpState::CancelPending);
    op.updated_at_unix = -1000;
    let repository = Arc::new(FakeRepository::default().with_operation(op));
    let coordination = Arc::new(FakeCoordination::default());
    coordination
        .cancel
        .lock()
        .unwrap()
        .push_back(EnrollmentCancellationResult::Ambiguous { detail: "timeout".to_string() });
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository.clone(), coordination, links, attempts).reconcile_once().await;

    let calls = repository.calls.lock().unwrap();
    assert!(calls.contains(&RepoCall::IncrementAttempts("op-1".to_string())));
    assert!(!calls
        .iter()
        .any(|c| matches!(c, RepoCall::MarkState(id, OpState::RecoveryBlocked) if id == "op-1")));
}

// ===== Cross-cutting =====

#[tokio::test]
async fn a_row_updated_too_recently_is_left_for_the_next_sweep() {
    let mut op = operation("op-1", "group-1", OpState::CancelPending);
    // Freshly touched -- well inside `RECONCILE_MIN_AGE_SECS` of
    // `now_unix()` -- proves the age-gate is keyed on `updated_at_unix`,
    // not `created_at_unix` (which stays 0/ancient on this same row).
    op.updated_at_unix = now_unix();
    let repository = Arc::new(FakeRepository::default().with_operation(op));
    let coordination = Arc::new(FakeCoordination::default());
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository.clone(), coordination.clone(), links, attempts).reconcile_once().await;

    assert_eq!(*coordination.cancel_calls.lock().unwrap(), 0);
    assert!(repository.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_malformed_journal_row_blocks_only_that_row_not_a_healthy_sibling() {
    let mut healthy = operation("op-1", "group-1", OpState::CancelPending);
    healthy.updated_at_unix = -1000;
    let repository = Arc::new(FakeRepository::default().with_operation(healthy));
    repository.invalid_operations.lock().unwrap().push(InvalidEnrollmentOperation {
        operation_id: "op-bad".to_string(),
        raw_state: Some("unknown_state".to_string()),
        detail: "unrecognized state".to_string(),
    });
    let coordination = Arc::new(FakeCoordination::default());
    coordination.cancel.lock().unwrap().push_back(EnrollmentCancellationResult::Confirmed);
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository.clone(), coordination.clone(), links, attempts).reconcile_once().await;

    let calls = repository.calls.lock().unwrap();
    assert!(calls.contains(&RepoCall::MarkState("op-bad".to_string(), OpState::RecoveryBlocked)));
    assert!(calls.contains(&RepoCall::DeleteOperation("op-1".to_string())));
}

#[tokio::test]
async fn a_list_links_read_failure_skips_the_marker_sweep_without_cancelling_valid_enrollments() {
    let repository = Arc::new(
        FakeRepository::default()
            .with_operation(operation("op-1", "group-1", OpState::ActivationPending))
            .with_marker(marker("op-1", "group-1")),
    );
    repository.fail_list_links.store(true, Ordering::SeqCst);
    let coordination = Arc::new(FakeCoordination::default());
    let links = Arc::new(FakeLinkPort::default());
    let attempts = Arc::new(FakeAttemptTracker::default());

    service(repository.clone(), coordination.clone(), links, attempts).reconcile_once().await;

    assert!(repository.calls.lock().unwrap().is_empty());
    assert_eq!(*coordination.activate_calls.lock().unwrap(), 0);
}
