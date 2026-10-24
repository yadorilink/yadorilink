#![cfg(test)]

use std::collections::HashMap;
use std::sync::Mutex;

use super::*;
use yadorilink_replica_domain::session_state::ProviderKind;

#[test]
fn enrollment_outcome_keeps_operation_identity_for_recovery() {
    let outcome = EnrollmentOutcome {
        operation_id: "operation-1".to_string(),
        group_id: "group-1".to_string(),
        local_path: PathBuf::from("/tmp/group-1"),
        awaiting_approval: false,
        already_linked: false,
    };

    assert_eq!(outcome.operation_id, "operation-1");
    assert_eq!(outcome.group_id, "group-1");
}

#[test]
fn enrollment_errors_keep_compensation_context_structured() {
    let error = EnrollmentError::CompensationPending {
        operation_id: "operation-1".to_string(),
        detail: "cancel will be retried".to_string(),
    };

    assert!(error.to_string().contains("operation-1"));
}

#[test]
fn activation_success_and_idempotent_retry_finalize() {
    assert_eq!(
        activation_disposition(&EnrollmentActivationResult::Activated),
        ActivationDisposition::Finalize
    );
    assert_eq!(
        activation_disposition(&EnrollmentActivationResult::AlreadyActive),
        ActivationDisposition::Finalize
    );
}

#[test]
fn confirmed_activation_rejection_rolls_back() {
    assert_eq!(
        activation_disposition(&EnrollmentActivationResult::Deleted),
        ActivationDisposition::RollBack
    );
}

#[test]
fn ambiguous_activation_never_rolls_back() {
    assert_eq!(
        activation_disposition(&EnrollmentActivationResult::TransientFailure {
            detail: "timeout".to_string()
        }),
        ActivationDisposition::LeaveForReconciliation
    );
}

// ===== Fakes =====

#[derive(Default)]
struct FakeEnrollmentRepository {
    operations: Mutex<HashMap<String, EnrollmentOperation>>,
    links: Mutex<Vec<yadorilink_replica_domain::session_state::FolderLink>>,
    digests: Mutex<HashMap<String, String>>,
    /// Display names of provider folders that already exist on the fake device.
    taken_names: Mutex<Vec<String>>,
    /// `list_links` calls so far, and the call number (1-based) from which it fails (0: never).
    list_links_calls: std::sync::atomic::AtomicUsize,
    fail_list_links_from: std::sync::atomic::AtomicUsize,
}

impl EnrollmentRepository for FakeEnrollmentRepository {
    fn try_insert_operation(
        &self,
        operation: &EnrollmentOperation,
    ) -> Result<bool, crate::sync_error::SyncError> {
        let mut operations = self.operations.lock().unwrap();
        if operations.contains_key(&operation.operation_id) {
            return Ok(false);
        }
        operations.insert(operation.operation_id.clone(), operation.clone());
        Ok(true)
    }

    fn delete_operation(&self, operation_id: &str) -> Result<(), crate::sync_error::SyncError> {
        self.operations.lock().unwrap().remove(operation_id);
        Ok(())
    }

    fn mark_prepared(
        &self,
        operation_id: &str,
        group_id: &str,
        now_unix: i64,
    ) -> Result<bool, crate::sync_error::SyncError> {
        let mut operations = self.operations.lock().unwrap();
        let Some(op) = operations.get_mut(operation_id) else { return Ok(false) };
        op.group_id = Some(group_id.to_string());
        op.state = EnrollmentOperationState::Prepared;
        op.updated_at_unix = now_unix;
        Ok(true)
    }

    fn mark_state(
        &self,
        operation_id: &str,
        state: EnrollmentOperationState,
        error: Option<&str>,
        now_unix: i64,
    ) -> Result<bool, crate::sync_error::SyncError> {
        let mut operations = self.operations.lock().unwrap();
        let Some(op) = operations.get_mut(operation_id) else { return Ok(false) };
        op.state = state;
        op.last_error = error.map(str::to_string);
        op.updated_at_unix = now_unix;
        Ok(true)
    }

    fn creation_digest(
        &self,
        locator: &str,
    ) -> Result<Option<String>, crate::sync_error::SyncError> {
        Ok(self.digests.lock().unwrap().get(locator).cloned())
    }

    fn list_links(
        &self,
    ) -> Result<
        Vec<yadorilink_replica_domain::session_state::FolderLink>,
        crate::sync_error::SyncError,
    > {
        let call = self.list_links_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        let from = self.fail_list_links_from.load(std::sync::atomic::Ordering::SeqCst);
        if from != 0 && call >= from {
            return Err(std::io::Error::other("fake list_links failure").into());
        }
        Ok(self.links.lock().unwrap().clone())
    }

    fn provider_display_name_taken(
        &self,
        display_name: &str,
    ) -> Result<bool, crate::sync_error::SyncError> {
        Ok(self.taken_names.lock().unwrap().iter().any(|n| n == display_name))
    }

    fn scan_pending(
        &self,
    ) -> Result<
        yadorilink_replica_domain::session_state::PendingEnrollmentScan,
        crate::sync_error::SyncError,
    > {
        Ok(yadorilink_replica_domain::session_state::PendingEnrollmentScan::default())
    }

    fn settle_activated(&self, _operation_id: &str) -> Result<(), crate::sync_error::SyncError> {
        Ok(())
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
        Ok(yadorilink_replica_domain::session_state::EnrollmentOperationScan {
            valid: self.operations.lock().unwrap().values().cloned().collect(),
            invalid: Vec::new(),
        })
    }

    fn settle_activated_and_close(
        &self,
        operation_id: &str,
    ) -> Result<(), crate::sync_error::SyncError> {
        self.operations.lock().unwrap().remove(operation_id);
        Ok(())
    }

    fn move_marker_to_cancel_operation(
        &self,
        _marker: &yadorilink_replica_domain::session_state::PendingEnrollment,
        _now_unix: i64,
    ) -> Result<(), crate::sync_error::SyncError> {
        Ok(())
    }

    fn increment_attempts(
        &self,
        _operation_id: &str,
        _now_unix: i64,
    ) -> Result<i64, crate::sync_error::SyncError> {
        Ok(1)
    }

    fn rollback_local_setup_to_cancel_pending(
        &self,
        _local_path: &str,
        operation_id: &str,
        detail: &str,
        now_unix: i64,
    ) -> Result<bool, crate::sync_error::SyncError> {
        let mut operations = self.operations.lock().unwrap();
        let Some(op) = operations.get_mut(operation_id) else { return Ok(false) };
        op.state = EnrollmentOperationState::CancelPending;
        op.last_error = Some(detail.to_string());
        op.updated_at_unix = now_unix;
        Ok(true)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum EnrollmentCall {
    PrepareCreate,
    PrepareJoin,
    PrepareInviteAccept,
    ActivateCreate,
    ActivateJoin,
    ActivateInviteAccept,
    CancelCreate,
    CancelJoin,
    CancelInviteAccept,
    MintInvite,
    LinkCommit,
    LinkRollback,
    LinkCommitPlain,
}

/// The arguments one `mint_invite` port call carried.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MintInviteArgs {
    group_id: String,
    role: Option<String>,
    ttl_secs: Option<u64>,
    requires_approval: bool,
}

#[derive(Default)]
struct FakeCoordination {
    calls: Mutex<Vec<EnrollmentCall>>,
    prepare: Mutex<std::collections::VecDeque<EnrollmentPrepareResult>>,
    activate: Mutex<std::collections::VecDeque<EnrollmentActivationResult>>,
    cancel: Mutex<std::collections::VecDeque<EnrollmentCancellationResult>>,
    mint: Mutex<std::collections::VecDeque<Result<MintedInvite, String>>>,
    /// One entry per mint call -- the approval flag is the whole point of
    /// the option, so a test must be able to prove it survived the trip
    /// through this port rather than merely that a mint happened.
    mint_args: Mutex<Vec<MintInviteArgs>>,
    configured: std::sync::atomic::AtomicBool,
}

impl FakeCoordination {
    fn configured() -> Self {
        let this = Self::default();
        this.configured.store(true, std::sync::atomic::Ordering::SeqCst);
        this
    }
}

impl EnrollmentCoordination for FakeCoordination {
    fn is_configured(&self) -> bool {
        self.configured.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn prepare_create<'a>(
        &'a self,
        _operation_id: &'a str,
        _group_name: &'a str,
        _device_id: &'a str,
        _storage_mode: &'a str,
    ) -> super::super::ports::BoxFuture<'a, EnrollmentPrepareResult> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(EnrollmentCall::PrepareCreate);
            self.prepare.lock().unwrap().pop_front().expect("missing fake prepare result")
        })
    }

    fn prepare_join<'a>(
        &'a self,
        _operation_id: &'a str,
        _group_id: &'a str,
        _device_id: &'a str,
        _storage_mode: &'a str,
    ) -> super::super::ports::BoxFuture<'a, EnrollmentPrepareResult> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(EnrollmentCall::PrepareJoin);
            self.prepare.lock().unwrap().pop_front().expect("missing fake prepare result")
        })
    }

    fn activate_create<'a>(
        &'a self,
        _group_id: &'a str,
        _operation_id: &'a str,
    ) -> super::super::ports::BoxFuture<'a, EnrollmentActivationResult> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(EnrollmentCall::ActivateCreate);
            self.activate.lock().unwrap().pop_front().expect("missing fake activate result")
        })
    }

    fn activate_join<'a>(
        &'a self,
        _group_id: &'a str,
        _operation_id: &'a str,
        _device_id: &'a str,
    ) -> super::super::ports::BoxFuture<'a, EnrollmentActivationResult> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(EnrollmentCall::ActivateJoin);
            self.activate.lock().unwrap().pop_front().expect("missing fake activate result")
        })
    }

    fn cancel_create<'a>(
        &'a self,
        _group_id: &'a str,
        _operation_id: &'a str,
    ) -> super::super::ports::BoxFuture<'a, EnrollmentCancellationResult> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(EnrollmentCall::CancelCreate);
            self.cancel.lock().unwrap().pop_front().expect("missing fake cancel result")
        })
    }

    fn cancel_join<'a>(
        &'a self,
        _group_id: &'a str,
        _operation_id: &'a str,
        _device_id: &'a str,
    ) -> super::super::ports::BoxFuture<'a, EnrollmentCancellationResult> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(EnrollmentCall::CancelJoin);
            self.cancel.lock().unwrap().pop_front().expect("missing fake cancel result")
        })
    }

    fn prepare_invite_accept<'a>(
        &'a self,
        _operation_id: &'a str,
        _code: &'a str,
        _device_id: &'a str,
        _storage_mode: &'a str,
    ) -> super::super::ports::BoxFuture<'a, EnrollmentPrepareResult> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(EnrollmentCall::PrepareInviteAccept);
            self.prepare.lock().unwrap().pop_front().expect("missing fake prepare result")
        })
    }

    fn activate_invite_accept<'a>(
        &'a self,
        _group_id: &'a str,
        _operation_id: &'a str,
        _device_id: &'a str,
    ) -> super::super::ports::BoxFuture<'a, EnrollmentActivationResult> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(EnrollmentCall::ActivateInviteAccept);
            self.activate.lock().unwrap().pop_front().expect("missing fake activate result")
        })
    }

    fn cancel_invite_accept<'a>(
        &'a self,
        _group_id: &'a str,
        _operation_id: &'a str,
        _device_id: &'a str,
    ) -> super::super::ports::BoxFuture<'a, EnrollmentCancellationResult> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(EnrollmentCall::CancelInviteAccept);
            self.cancel.lock().unwrap().pop_front().expect("missing fake cancel result")
        })
    }

    fn mint_invite<'a>(
        &'a self,
        group_id: &'a str,
        role: Option<&'a str>,
        ttl_secs: Option<u64>,
        requires_approval: bool,
    ) -> super::super::ports::BoxFuture<'a, Result<MintedInvite, String>> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(EnrollmentCall::MintInvite);
            self.mint_args.lock().unwrap().push(MintInviteArgs {
                group_id: group_id.to_string(),
                role: role.map(str::to_string),
                ttl_secs,
                requires_approval,
            });
            self.mint.lock().unwrap().pop_front().expect("missing fake mint result")
        })
    }
}

#[derive(Default)]
struct FakeLinkPort {
    calls: Mutex<Vec<EnrollmentCall>>,
    commit: Mutex<std::collections::VecDeque<Result<LinkOutcome, EnrollmentLinkError>>>,
    rollback: Mutex<std::collections::VecDeque<Result<(), String>>>,
    commit_plain: Mutex<std::collections::VecDeque<Result<(), EnrollmentLinkError>>>,
    /// What each commit asked for: (operation id, link key, provider target).
    requests: Mutex<Vec<(String, PathBuf, Option<super::super::ports::ProviderLinkTarget>)>>,
    /// What each plain commit asked for: (link key, provider target).
    plain_requests: Mutex<Vec<(PathBuf, Option<super::super::ports::ProviderLinkTarget>)>>,
}

impl EnrollmentLinkPort for FakeLinkPort {
    fn commit<'a>(
        &'a self,
        request: EnrollmentLinkRequest,
    ) -> super::super::ports::BoxFuture<'a, Result<LinkOutcome, EnrollmentLinkError>> {
        Box::pin(async move {
            self.requests.lock().unwrap().push((
                request.operation_id.clone(),
                request.absolute_path.clone(),
                request.provider.clone(),
            ));
            self.calls.lock().unwrap().push(EnrollmentCall::LinkCommit);
            self.commit.lock().unwrap().pop_front().expect("missing fake commit result")
        })
    }

    fn rollback<'a>(
        &'a self,
        _local_path: &'a str,
        _operation_id: &'a str,
    ) -> super::super::ports::BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(EnrollmentCall::LinkRollback);
            self.rollback.lock().unwrap().pop_front().expect("missing fake rollback result")
        })
    }

    fn commit_plain<'a>(
        &'a self,
        _group_id: &'a str,
        absolute_path: &'a std::path::Path,
        _on_demand: bool,
        provider: Option<super::super::ports::ProviderLinkTarget>,
    ) -> super::super::ports::BoxFuture<'a, Result<(), EnrollmentLinkError>> {
        Box::pin(async move {
            self.plain_requests.lock().unwrap().push((absolute_path.to_path_buf(), provider));
            self.calls.lock().unwrap().push(EnrollmentCall::LinkCommitPlain);
            self.commit_plain.lock().unwrap().pop_front().expect("missing fake commit_plain result")
        })
    }
}

fn service(
    repository: Arc<FakeEnrollmentRepository>,
    coordination: Arc<FakeCoordination>,
    links: Arc<FakeLinkPort>,
) -> EnrollmentService {
    // The adapter kind is pinned so these cases do not depend on the OS running them.
    EnrollmentService::new("device-a".to_string(), repository, coordination, links)
        .with_provider_kind(Some(ProviderKind::MacFileProvider))
}

fn create_command() -> CreateAndLinkCommand {
    CreateAndLinkCommand {
        group_name: "photos".to_string(),
        absolute_path: PathBuf::from("/home/alice/Photos"),
        on_demand: false,
        provider: None,
    }
}

/// A `Deleted` activation rolls back via the link port's own rollback
/// method, never `ReplicaRoleService::unlink`'s full-replica-handoff
/// gate -- proven here by the sequence: link commit, then activate,
/// then rollback, nothing else.
#[tokio::test]
async fn deleted_activation_rolls_back_via_the_link_port() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
    coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::Deleted);
    let links = Arc::new(FakeLinkPort::default());
    links.commit.lock().unwrap().push_back(Ok(LinkOutcome::Linked));
    links.rollback.lock().unwrap().push_back(Ok(()));

    let result = service(repository, coordination.clone(), links.clone())
        .create_and_link(create_command())
        .await;

    assert!(matches!(result, Err(EnrollmentError::ActivationRejected { .. })));
    assert_eq!(
        *links.calls.lock().unwrap(),
        vec![EnrollmentCall::LinkCommit, EnrollmentCall::LinkRollback]
    );
}

/// If the rollback itself fails, `CompensationPending` is returned so
/// the next reconciliation sweep retries -- never treated as done.
#[tokio::test]
async fn rollback_failure_reports_compensation_pending() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
    coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::Deleted);
    let links = Arc::new(FakeLinkPort::default());
    links.commit.lock().unwrap().push_back(Ok(LinkOutcome::Linked));
    links.rollback.lock().unwrap().push_back(Err("disk full".to_string()));

    let result = service(repository, coordination, links).create_and_link(create_command()).await;

    assert!(matches!(result, Err(EnrollmentError::CompensationPending { .. })));
}

/// `TransientFailure` never rolls back -- the link/marker/rollback port
/// is never called a second time.
#[tokio::test]
async fn transient_activation_failure_never_rolls_back() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
    coordination
        .activate
        .lock()
        .unwrap()
        .push_back(EnrollmentActivationResult::TransientFailure { detail: "503".to_string() });
    let links = Arc::new(FakeLinkPort::default());
    links.commit.lock().unwrap().push_back(Ok(LinkOutcome::Linked));

    let result =
        service(repository, coordination, links.clone()).create_and_link(create_command()).await;

    assert!(matches!(result, Err(EnrollmentError::ActivationAmbiguous { .. })));
    assert_eq!(*links.calls.lock().unwrap(), vec![EnrollmentCall::LinkCommit]);
}

/// Config missing is checked BEFORE the journal is even opened -- no
/// journal row exists afterward, and no coordination call is ever made.
#[tokio::test]
async fn missing_coordination_config_never_opens_a_journal_row() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::default()); // not configured
    let links = Arc::new(FakeLinkPort::default());

    let result = service(repository.clone(), coordination.clone(), links)
        .create_and_link(create_command())
        .await;

    assert!(matches!(result, Err(EnrollmentError::LocalIdentityUnavailable)));
    assert!(repository.operations.lock().unwrap().is_empty());
    assert!(coordination.calls.lock().unwrap().is_empty());
}

/// A local `link()` failure that reaches a durable `CancelPending`
/// state (the immediate cancel-with-retries also fails) leaves exactly
/// one journal row behind, in `CancelPending`.
#[tokio::test]
async fn link_failure_and_cancel_failure_leaves_a_cancel_pending_row() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
    for _ in 0..3 {
        coordination
            .cancel
            .lock()
            .unwrap()
            .push_back(EnrollmentCancellationResult::Ambiguous { detail: "5xx".to_string() });
    }
    let links = Arc::new(FakeLinkPort::default());
    links.commit.lock().unwrap().push_back(Err(EnrollmentLinkError::NotCommitted {
        detail: "simulated local link failure".to_string(),
        refusal: None,
    }));

    let result = service(repository.clone(), coordination.clone(), links)
        .create_and_link(create_command())
        .await;

    assert!(matches!(result, Err(EnrollmentError::CompensationPending { .. })));
    let operations = repository.operations.lock().unwrap();
    assert_eq!(operations.len(), 1, "expected one cancel-pending journal row");
    let (_, op) = operations.iter().next().unwrap();
    assert_eq!(op.group_id.as_deref(), Some("group-1"));
    assert_eq!(op.state, EnrollmentOperationState::CancelPending);
    assert_eq!(
        coordination
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| **c == EnrollmentCall::CancelCreate)
            .count(),
        3,
        "expected 3 cancel retries"
    );
}

/// `NotCommitted` goes through the existing compensation path and the
/// remote cancel DOES get called -- the counterpart to the
/// `CommitUncertain` test below, proving the two classifications route
/// to genuinely different behavior.
#[tokio::test]
async fn not_committed_link_failure_calls_remote_cancel_and_reaches_cancel_pending() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
    coordination.cancel.lock().unwrap().push_back(EnrollmentCancellationResult::Confirmed);
    let links = Arc::new(FakeLinkPort::default());
    links.commit.lock().unwrap().push_back(Err(EnrollmentLinkError::NotCommitted {
        detail: "preflight rejected, nothing committed".to_string(),
        refusal: None,
    }));

    let result =
        service(repository, coordination.clone(), links).create_and_link(create_command()).await;

    assert!(
        !matches!(result, Err(EnrollmentError::LocalLinkAmbiguous { .. })),
        "NotCommitted must never surface as LocalLinkAmbiguous: {result:?}"
    );
    assert_eq!(
        coordination
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| **c == EnrollmentCall::CancelCreate)
            .count(),
        1,
        "a NotCommitted failure must attempt remote cancellation"
    );
}

/// `CommitUncertain` must NEVER be treated as "definitely not
/// committed": it must not mark CancelPending, must not call remote
/// cancel, and must not delete the journal row.
#[tokio::test]
async fn commit_uncertain_link_failure_never_calls_remote_cancel() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
    let links = Arc::new(FakeLinkPort::default());
    links.commit.lock().unwrap().push_back(Err(EnrollmentLinkError::CommitUncertain {
        detail: "post-commit setup failed, and rolling back also failed".to_string(),
    }));

    let result = service(repository.clone(), coordination.clone(), links)
        .create_and_link(create_command())
        .await;

    let Err(EnrollmentError::LocalLinkAmbiguous { operation_id, .. }) = result else {
        panic!("expected LocalLinkAmbiguous, got {result:?}");
    };
    let operations = repository.operations.lock().unwrap();
    let row = operations.get(&operation_id).unwrap();
    assert_ne!(
        row.state,
        EnrollmentOperationState::CancelPending,
        "CommitUncertain must never mark CancelPending"
    );
    assert_ne!(
        row.state,
        EnrollmentOperationState::RecoveryBlocked,
        "CommitUncertain must never block/discard the journal row"
    );
    assert!(
        coordination.calls.lock().unwrap().iter().all(|c| *c != EnrollmentCall::CancelCreate),
        "CommitUncertain must never call remote cancel"
    );
}

/// A 409 on create prepare means this operation_id already names a
/// differently-shaped request -- the row must move to
/// `RecoveryBlocked`, never be treated as an ordinary rejection or
/// silently retried.
#[tokio::test]
async fn create_prepare_conflict_blocks_recovery() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Conflict { detail: "409".to_string() });
    let links = Arc::new(FakeLinkPort::default());

    let result =
        service(repository.clone(), coordination, links).create_and_link(create_command()).await;

    let Err(EnrollmentError::OperationConflict { operation_id, .. }) = result else {
        panic!("expected OperationConflict, got {result:?}");
    };
    let operations = repository.operations.lock().unwrap();
    assert_eq!(
        operations.get(&operation_id).unwrap().state,
        EnrollmentOperationState::RecoveryBlocked
    );
}

fn accept_invite_command() -> AcceptInviteCommand {
    AcceptInviteCommand {
        code: "invite-code-abc".to_string(),
        absolute_path: PathBuf::from("/home/bob/Shared"),
        on_demand: false,
        provider: None,
    }
}

fn provider_accept_command(display_name: &str, token: &str) -> AcceptInviteCommand {
    AcceptInviteCommand {
        code: "invite-code-abc".to_string(),
        absolute_path: PathBuf::new(),
        on_demand: true,
        provider: Some(ProviderCreation {
            display_name: display_name.to_string(),
            request_token: token.to_string(),
        }),
    }
}

/// An invite accepted as a provider folder redeems and activates like any invite, but links the
/// provider locator with a provider target (a joined group: not an empty owner) in on-demand mode,
/// with no journal row.
#[tokio::test]
async fn an_invite_accepted_as_a_provider_folder_links_the_provider_locator() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-7".to_string() });
    coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::Activated);
    let links = Arc::new(FakeLinkPort::default());
    links.commit_plain.lock().unwrap().push_back(Ok(()));

    let outcome = service(repository.clone(), coordination.clone(), links.clone())
        .accept_invite_and_link(provider_accept_command("Shared", "token-1"))
        .await
        .expect("accepted");

    assert_eq!(outcome.group_id, "group-7");
    assert_eq!(outcome.local_path, PathBuf::from("provider://token-1"));
    assert!(!outcome.awaiting_approval);
    let plain = links.plain_requests.lock().unwrap();
    assert_eq!(plain.len(), 1);
    assert_eq!(plain[0].0, PathBuf::from("provider://token-1"));
    let target = plain[0].1.as_ref().expect("a provider target");
    assert_eq!(target.display_name, "Shared");
    assert!(target.on_demand && !target.empty_owner);
    assert!(repository.operations.lock().unwrap().is_empty(), "an invite opens no journal row");
}

/// A name already used by a provider folder here is refused before the one-use invite is
/// redeemed; so is a platform without provider folders.
#[tokio::test]
async fn a_provider_invite_is_refused_before_redeeming_when_it_cannot_link() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    repository.taken_names.lock().unwrap().push("Shared".to_string());
    let coordination = Arc::new(FakeCoordination::configured());
    let links = Arc::new(FakeLinkPort::default());
    let svc = service(repository.clone(), coordination.clone(), links.clone());
    let taken = svc.accept_invite_and_link(provider_accept_command("Shared", "token-2")).await;
    assert!(matches!(taken, Err(EnrollmentError::PreparationRejected { .. })), "{taken:?}");
    let none = service(repository, coordination.clone(), links.clone())
        .with_provider_kind(None)
        .accept_invite_and_link(provider_accept_command("Other", "token-3"))
        .await;
    assert!(matches!(none, Err(EnrollmentError::PreparationRejected { .. })), "{none:?}");
    assert!(coordination.calls.lock().unwrap().is_empty(), "the invite was redeemed");
    assert!(links.calls.lock().unwrap().is_empty());
}

/// A retry after a crash between the link and the activation finds its own link: its name is not
/// a clash, the same locator is linked again and the invite activates.
#[tokio::test]
async fn a_provider_invite_retry_finds_its_own_link_and_activates() {
    use yadorilink_replica_domain::session_state::{
        FolderLink, LinkLocation, MaterializationPolicy,
    };
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let creation = ProviderCreation {
        display_name: "Shared".to_string(),
        request_token: "token-4".to_string(),
    };
    repository.links.lock().unwrap().push(FolderLink {
        location: LinkLocation::Provider {
            locator: creation.locator(),
            root_id: "root-1".to_string(),
        },
        group_id: "group-7".to_string(),
        paused: false,
        materialization_policy: MaterializationPolicy::OnDemand,
        orphaned: false,
    });
    repository.taken_names.lock().unwrap().push("Shared".to_string());
    repository
        .digests
        .lock()
        .unwrap()
        .insert(creation.locator(), creation_digest(&creation, "group-7", true, "invite"));
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-7".to_string() });
    coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::AlreadyActive);
    let links = Arc::new(FakeLinkPort::default());
    links.commit_plain.lock().unwrap().push_back(Ok(()));

    let outcome = service(repository, coordination, links)
        .accept_invite_and_link(provider_accept_command("Shared", "token-4"))
        .await
        .expect("the retry completes");
    assert_eq!(outcome.group_id, "group-7");
}

/// The same token with another request (here another group) is refused, never linked as the
/// earlier one.
#[tokio::test]
async fn a_provider_invite_token_is_bound_to_its_request() {
    use yadorilink_replica_domain::session_state::{
        FolderLink, LinkLocation, MaterializationPolicy,
    };
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let creation = ProviderCreation {
        display_name: "Shared".to_string(),
        request_token: "token-5".to_string(),
    };
    repository.links.lock().unwrap().push(FolderLink {
        location: LinkLocation::Provider {
            locator: creation.locator(),
            root_id: "root-1".to_string(),
        },
        group_id: "group-1".to_string(),
        paused: false,
        materialization_policy: MaterializationPolicy::OnDemand,
        orphaned: false,
    });
    repository
        .digests
        .lock()
        .unwrap()
        .insert(creation.locator(), creation_digest(&creation, "group-1", true, "invite"));
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-8".to_string() });
    coordination.cancel.lock().unwrap().push_back(EnrollmentCancellationResult::Confirmed);
    let links = Arc::new(FakeLinkPort::default());
    let result = service(repository, coordination.clone(), links.clone())
        .accept_invite_and_link(provider_accept_command("Shared", "token-5"))
        .await;
    assert!(matches!(result, Err(EnrollmentError::PreparationRejected { .. })), "{result:?}");
    assert!(links.calls.lock().unwrap().is_empty());
    // Only knowable with the group the invite named, so the redeemed acceptance is cancelled.
    assert_eq!(
        *coordination.calls.lock().unwrap(),
        vec![EnrollmentCall::PrepareInviteAccept, EnrollmentCall::CancelInviteAccept]
    );
}

/// A name that is empty or only whitespace never reaches the redemption.
#[tokio::test]
async fn a_blank_provider_name_is_refused_before_redeeming() {
    for name in ["", "   ", "\t"] {
        let coordination = Arc::new(FakeCoordination::configured());
        let links = Arc::new(FakeLinkPort::default());
        let result = service(
            Arc::new(FakeEnrollmentRepository::default()),
            coordination.clone(),
            links.clone(),
        )
        .accept_invite_and_link(provider_accept_command(name, "token-blank"))
        .await;
        assert!(matches!(result, Err(EnrollmentError::PreparationRejected { .. })), "{result:?}");
        assert!(coordination.calls.lock().unwrap().is_empty(), "{name:?} redeemed the invite");
        assert!(links.calls.lock().unwrap().is_empty());
    }
}

/// The token of an earlier link of this device with another request is refused before the
/// invite is redeemed whenever the earlier link already shows it (same group, other name).
#[tokio::test]
async fn a_token_bound_to_another_name_is_refused_before_redeeming() {
    use yadorilink_replica_domain::session_state::{
        FolderLink, LinkLocation, MaterializationPolicy,
    };
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let earlier = ProviderCreation {
        display_name: "Shared".to_string(),
        request_token: "token-6".to_string(),
    };
    repository.links.lock().unwrap().push(FolderLink {
        location: LinkLocation::Provider {
            locator: earlier.locator(),
            root_id: "root-1".to_string(),
        },
        group_id: "group-7".to_string(),
        paused: false,
        materialization_policy: MaterializationPolicy::OnDemand,
        orphaned: false,
    });
    repository
        .digests
        .lock()
        .unwrap()
        .insert(earlier.locator(), creation_digest(&earlier, "group-7", true, "invite"));
    let coordination = Arc::new(FakeCoordination::configured());
    let links = Arc::new(FakeLinkPort::default());
    let result = service(repository, coordination.clone(), links)
        .accept_invite_and_link(provider_accept_command("Renamed", "token-6"))
        .await;
    assert!(matches!(result, Err(EnrollmentError::PreparationRejected { .. })), "{result:?}");
    assert!(coordination.calls.lock().unwrap().is_empty(), "the invite was redeemed");
}

/// Every way a provider invite can end after the redemption, and what it leaves remotely: the
/// paths where nothing was committed locally cancel the pending acceptance; the paths where the
/// link may or does exist keep it for the retry or the owner.
#[tokio::test]
async fn every_path_after_the_redemption_compensates_or_keeps_by_what_is_committed() {
    use EnrollmentCall::{ActivateInviteAccept, CancelInviteAccept, LinkCommitPlain};
    let prepared = || EnrollmentPrepareResult::Prepared { group_id: "group-7".to_string() };
    let calls_of = |c: &Arc<FakeCoordination>, l: &Arc<FakeLinkPort>| {
        let mut calls = c.calls.lock().unwrap().clone();
        calls.extend(l.calls.lock().unwrap().iter().cloned());
        calls
    };

    // The target cannot be built (the link list cannot be read): nothing committed, cancelled.
    let repository = Arc::new(FakeEnrollmentRepository::default());
    // The first read (before the redemption) passes, the second (after it) fails.
    repository.fail_list_links_from.store(2, std::sync::atomic::Ordering::SeqCst);
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.prepare.lock().unwrap().push_back(prepared());
    coordination.cancel.lock().unwrap().push_back(EnrollmentCancellationResult::Confirmed);
    let links = Arc::new(FakeLinkPort::default());
    let result = service(repository, coordination.clone(), links.clone())
        .accept_invite_and_link(provider_accept_command("Shared", "token-a"))
        .await;
    assert!(matches!(result, Err(EnrollmentError::Persistence(_))), "{result:?}");
    assert_eq!(
        calls_of(&coordination, &links),
        vec![EnrollmentCall::PrepareInviteAccept, CancelInviteAccept]
    );

    // The link was refused before anything was committed: cancelled.
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.prepare.lock().unwrap().push_back(prepared());
    coordination.cancel.lock().unwrap().push_back(EnrollmentCancellationResult::Confirmed);
    let links = Arc::new(FakeLinkPort::default());
    links.commit_plain.lock().unwrap().push_back(Err(EnrollmentLinkError::NotCommitted {
        detail: "name taken".to_string(),
        refusal: None,
    }));
    let result =
        service(Arc::new(FakeEnrollmentRepository::default()), coordination.clone(), links.clone())
            .accept_invite_and_link(provider_accept_command("Shared", "token-b"))
            .await;
    assert!(matches!(result, Err(EnrollmentError::LocalLinkFailed { .. })), "{result:?}");
    assert_eq!(
        calls_of(&coordination, &links),
        vec![EnrollmentCall::PrepareInviteAccept, CancelInviteAccept, LinkCommitPlain]
    );

    // The link may be committed: kept (no cancel, no activation).
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.prepare.lock().unwrap().push_back(prepared());
    let links = Arc::new(FakeLinkPort::default());
    links
        .commit_plain
        .lock()
        .unwrap()
        .push_back(Err(EnrollmentLinkError::CommitUncertain { detail: "unknown".to_string() }));
    let result =
        service(Arc::new(FakeEnrollmentRepository::default()), coordination.clone(), links.clone())
            .accept_invite_and_link(provider_accept_command("Shared", "token-c"))
            .await;
    assert!(matches!(result, Err(EnrollmentError::LocalLinkAmbiguous { .. })), "{result:?}");
    assert!(!calls_of(&coordination, &links).contains(&CancelInviteAccept));

    // After the link committed, activation ends keep the link and never cancel it away.
    for activation in [
        EnrollmentActivationResult::Deleted,
        EnrollmentActivationResult::TransientFailure { detail: "offline".to_string() },
        EnrollmentActivationResult::AwaitingApproval,
    ] {
        let coordination = Arc::new(FakeCoordination::configured());
        coordination.prepare.lock().unwrap().push_back(prepared());
        coordination.activate.lock().unwrap().push_back(activation);
        let links = Arc::new(FakeLinkPort::default());
        links.commit_plain.lock().unwrap().push_back(Ok(()));
        let _ = service(
            Arc::new(FakeEnrollmentRepository::default()),
            coordination.clone(),
            links.clone(),
        )
        .accept_invite_and_link(provider_accept_command("Shared", "token-d"))
        .await;
        let calls = calls_of(&coordination, &links);
        assert!(calls.contains(&ActivateInviteAccept), "{calls:?}");
        assert!(!calls.contains(&CancelInviteAccept), "{calls:?}");
    }

    // Refusals of the redemption itself consumed nothing: no cancel, nothing linked.
    for refused in [
        EnrollmentPrepareResult::DefinitelyRejected { detail: "no".to_string() },
        EnrollmentPrepareResult::InviteRefused {
            reason: crate::application::model::InviteRefusal::Expired,
            detail: "expired".to_string(),
        },
        EnrollmentPrepareResult::Conflict { detail: "409".to_string() },
        EnrollmentPrepareResult::Ambiguous { detail: "timeout".to_string() },
    ] {
        let coordination = Arc::new(FakeCoordination::configured());
        coordination.prepare.lock().unwrap().push_back(refused);
        let links = Arc::new(FakeLinkPort::default());
        let result = service(
            Arc::new(FakeEnrollmentRepository::default()),
            coordination.clone(),
            links.clone(),
        )
        .accept_invite_and_link(provider_accept_command("Shared", "token-e"))
        .await;
        assert!(result.is_err());
        assert_eq!(*coordination.calls.lock().unwrap(), vec![EnrollmentCall::PrepareInviteAccept]);
        assert!(links.calls.lock().unwrap().is_empty());
    }
}

#[test]
fn invite_accept_operation_id_is_deterministic_and_scoped_to_both_inputs() {
    let a = invite_accept_operation_id("code-1", "device-a");
    let b = invite_accept_operation_id("code-1", "device-a");
    assert_eq!(a, b, "same (code, device) must always produce the same operation id");

    let different_device = invite_accept_operation_id("code-1", "device-b");
    assert_ne!(a, different_device, "a different device must produce a different id");

    let different_code = invite_accept_operation_id("code-2", "device-a");
    assert_ne!(a, different_code, "a different code must produce a different id");
}

#[tokio::test]
async fn accept_invite_happy_path_activates_and_returns_outcome() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-9".to_string() });
    coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::Activated);
    let links = Arc::new(FakeLinkPort::default());
    links.commit_plain.lock().unwrap().push_back(Ok(()));

    let result = service(repository, coordination.clone(), links.clone())
        .accept_invite_and_link(accept_invite_command())
        .await;

    let outcome = result.expect("expected a successful enrollment outcome");
    assert_eq!(outcome.group_id, "group-9");
    assert_eq!(outcome.local_path, PathBuf::from("/home/bob/Shared"));
    assert_eq!(
        *coordination.calls.lock().unwrap(),
        vec![EnrollmentCall::PrepareInviteAccept, EnrollmentCall::ActivateInviteAccept]
    );
    assert!(
        !outcome.awaiting_approval,
        "an ordinary invite acceptance is a completed membership, not a request"
    );
    assert_eq!(*links.calls.lock().unwrap(), vec![EnrollmentCall::LinkCommitPlain]);
}

/// An invite minted requiring the owner's approval parks the membership
/// instead of granting it. That is a success for this device -- nothing
/// failed, nothing is left to retry, and the local link stays -- but it
/// is NOT a membership, and the outcome has to say so or the command
/// that ran it reports a folder as joined when it will not sync until
/// someone else acts.
#[tokio::test]
async fn accept_invite_awaiting_approval_succeeds_but_is_not_reported_as_a_membership() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-9".to_string() });
    coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::AwaitingApproval);
    let links = Arc::new(FakeLinkPort::default());
    links.commit_plain.lock().unwrap().push_back(Ok(()));

    let outcome = service(repository, coordination.clone(), links.clone())
        .accept_invite_and_link(accept_invite_command())
        .await
        .expect("awaiting approval is a success, not an error: nothing failed here");

    assert!(outcome.awaiting_approval);
    assert_eq!(outcome.group_id, "group-9");
    assert_eq!(outcome.local_path, PathBuf::from("/home/bob/Shared"));
    // The local link is NOT rolled back and no cancel is sent: the
    // coordination-plane edge is legitimately parked, waiting on a
    // human, and both sides must survive until they decide.
    assert_eq!(
        *coordination.calls.lock().unwrap(),
        vec![EnrollmentCall::PrepareInviteAccept, EnrollmentCall::ActivateInviteAccept]
    );
    assert_eq!(*links.calls.lock().unwrap(), vec![EnrollmentCall::LinkCommitPlain]);
}

/// A definitely-rejected prepare (e.g. the invite is invalid/expired/
/// already used) must never attempt a local link commit at all --
/// unlike the same-account create/join paths, there is no durable
/// journal row to open or clean up here either.
#[tokio::test]
async fn accept_invite_rejected_prepare_never_touches_the_link_port() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.prepare.lock().unwrap().push_back(EnrollmentPrepareResult::DefinitelyRejected {
        detail: "invite is invalid or already used".to_string(),
    });
    let links = Arc::new(FakeLinkPort::default());

    let result = service(repository, coordination, links.clone())
        .accept_invite_and_link(accept_invite_command())
        .await;

    assert!(matches!(result, Err(EnrollmentError::PreparationRejected { .. })));
    assert!(links.calls.lock().unwrap().is_empty());
}

/// An invite the coordination plane names as expired or used reaches the caller
/// as that reason, with the link port untouched.
#[tokio::test]
async fn accept_invite_refused_invite_keeps_its_reason() {
    for reason in [InviteRefusal::Expired, InviteRefusal::AlreadyUsed] {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        let coordination = Arc::new(FakeCoordination::configured());
        coordination.prepare.lock().unwrap().push_back(EnrollmentPrepareResult::InviteRefused {
            reason,
            detail: "invite is invalid or already used".to_string(),
        });
        let links = Arc::new(FakeLinkPort::default());

        let result = service(repository, coordination, links.clone())
            .accept_invite_and_link(accept_invite_command())
            .await;

        assert!(
            matches!(&result, Err(EnrollmentError::InviteRefused { reason: got, .. }) if *got == reason),
            "{result:?}"
        );
        assert!(links.calls.lock().unwrap().is_empty());
    }
}

/// A local link failure compensates by cancelling the invite-accept
/// Pending edge -- best-effort, but always attempted (mirrors
/// `compensate_failed_join_link`'s reasoning, simplified since there is
/// no local partial-state classification to make: see
/// `accept_invite_and_link`'s own doc comment).
#[tokio::test]
async fn accept_invite_not_committed_link_failure_triggers_a_cancel() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-9".to_string() });
    coordination.cancel.lock().unwrap().push_back(EnrollmentCancellationResult::Confirmed);
    let links = Arc::new(FakeLinkPort::default());
    links.commit_plain.lock().unwrap().push_back(Err(EnrollmentLinkError::NotCommitted {
        detail: "disk full".to_string(),
        refusal: Some(LinkRefusal::DiskFull),
    }));

    let result = service(repository, coordination.clone(), links.clone())
        .accept_invite_and_link(accept_invite_command())
        .await;

    assert!(matches!(
        result,
        Err(EnrollmentError::LocalLinkFailed { refusal: Some(LinkRefusal::DiskFull), .. })
    ));
    assert_eq!(
        *coordination.calls.lock().unwrap(),
        vec![EnrollmentCall::PrepareInviteAccept, EnrollmentCall::CancelInviteAccept]
    );
}

/// A `CommitUncertain` classification (the local link may still be
/// live even though `commit_plain` is reporting failure) must NEVER
/// trigger the compensating cancel -- doing so would delete the
/// coordination-plane authorization for a group this device may
/// actually be actively linked to. Mirrors `commit`'s identical
/// same-account guarantee (see `classify_link_failure`'s own doc
/// comment and its 3 dedicated tests in enrollment_link.rs).
#[tokio::test]
async fn accept_invite_commit_uncertain_never_triggers_a_cancel() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-9".to_string() });
    let links = Arc::new(FakeLinkPort::default());
    links.commit_plain.lock().unwrap().push_back(Err(EnrollmentLinkError::CommitUncertain {
        detail: "watcher start failed and the rollback itself also failed".to_string(),
    }));

    let result = service(repository, coordination.clone(), links.clone())
        .accept_invite_and_link(accept_invite_command())
        .await;

    assert!(matches!(result, Err(EnrollmentError::LocalLinkAmbiguous { .. })));
    // Only PrepareInviteAccept ran -- no CancelInviteAccept, and no
    // ActivateInviteAccept either (this call returns before reaching
    // activate).
    assert_eq!(*coordination.calls.lock().unwrap(), vec![EnrollmentCall::PrepareInviteAccept]);
}

/// A confirmed-gone activation (the Pending row's TTL swept it before
/// activate ran) reports an error but does NOT roll back the local
/// link -- there is no marker for `commit_plain` to have written, so
/// there is nothing for a rollback to remove; the link is left in
/// place for the user to `unlink` or retry with a fresh invite (see
/// `accept_invite_and_link`'s own doc comment).
#[tokio::test]
async fn accept_invite_deleted_activation_leaves_the_link_in_place() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-9".to_string() });
    coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::Deleted);
    let links = Arc::new(FakeLinkPort::default());
    links.commit_plain.lock().unwrap().push_back(Ok(()));

    let result = service(repository, coordination, links.clone())
        .accept_invite_and_link(accept_invite_command())
        .await;

    assert!(matches!(result, Err(EnrollmentError::ActivationRejected { .. })));
    // Only the plain commit ran -- no rollback call exists on this path
    // at all (unlike `commit`'s `EnrollmentLinkPort::rollback`).
    assert_eq!(*links.calls.lock().unwrap(), vec![EnrollmentCall::LinkCommitPlain]);
}

#[tokio::test]
async fn accept_invite_missing_coordination_config_never_attempts_a_link() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::default()); // not configured
    let links = Arc::new(FakeLinkPort::default());

    let result = service(repository, coordination, links.clone())
        .accept_invite_and_link(accept_invite_command())
        .await;

    assert!(matches!(result, Err(EnrollmentError::LocalIdentityUnavailable)));
    assert!(links.calls.lock().unwrap().is_empty());
}

fn minted(role: &str, requires_approval: bool) -> MintedInvite {
    MintedInvite {
        code: "abc123".to_string(),
        invite_id: "invite-1".to_string(),
        group_id: "group-9".to_string(),
        role: role.to_string(),
        expires_at_unix: 1_800_000_000,
        requires_approval,
    }
}

#[tokio::test]
async fn mint_invite_happy_path_returns_the_coordination_plane_result() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.mint.lock().unwrap().push_back(Ok(minted("viewer", false)));
    let links = Arc::new(FakeLinkPort::default());

    let result = service(repository, coordination.clone(), links)
        .mint_invite("group-9", Some("viewer"), None, false)
        .await;

    let invite = result.expect("expected a minted invite");
    assert_eq!(invite.code, "abc123");
    assert_eq!(invite.group_id, "group-9");
    assert!(!invite.requires_approval);
    assert_eq!(*coordination.calls.lock().unwrap(), vec![EnrollmentCall::MintInvite]);
    assert_eq!(
        *coordination.mint_args.lock().unwrap(),
        vec![MintInviteArgs {
            group_id: "group-9".to_string(),
            role: Some("viewer".to_string()),
            ttl_secs: None,
            requires_approval: false,
        }],
    );
}

/// The approval flag must reach the coordination plane unchanged and
/// independently of the role -- an owner asking for an approval-gated
/// Editor invite must not silently get an ungated one.
#[tokio::test]
async fn mint_invite_forwards_the_approval_requirement_independently_of_the_role() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.mint.lock().unwrap().push_back(Ok(minted("editor", true)));
    let links = Arc::new(FakeLinkPort::default());

    let invite = service(repository, coordination.clone(), links)
        .mint_invite("group-9", Some("editor"), None, true)
        .await
        .expect("expected a minted invite");

    assert!(invite.requires_approval);
    assert_eq!(
        *coordination.mint_args.lock().unwrap(),
        vec![MintInviteArgs {
            group_id: "group-9".to_string(),
            role: Some("editor".to_string()),
            ttl_secs: None,
            requires_approval: true,
        }],
    );
}

/// What the caller reports is what the coordination plane recorded, not
/// what was requested: a plane that ignored the flag must not be
/// described as having honored it.
#[tokio::test]
async fn mint_invite_reports_the_coordination_planes_own_approval_answer() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.mint.lock().unwrap().push_back(Ok(minted("editor", false)));
    let links = Arc::new(FakeLinkPort::default());

    let invite = service(repository, coordination.clone(), links)
        .mint_invite("group-9", Some("editor"), None, true)
        .await
        .expect("expected a minted invite");

    assert!(!invite.requires_approval);
}

#[tokio::test]
async fn mint_invite_missing_coordination_config_fails_closed() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::default()); // not configured
    let links = Arc::new(FakeLinkPort::default());

    let result = service(repository, coordination.clone(), links)
        .mint_invite("group-9", None, None, true)
        .await;

    assert!(result.is_err());
    assert!(coordination.calls.lock().unwrap().is_empty());
}

// ===== A re-join of a folder already linked and running =====

fn join_command() -> JoinAndLinkCommand {
    JoinAndLinkCommand {
        group_id: "group-1".to_string(),
        group_name: "photos".to_string(),
        absolute_path: PathBuf::from("/home/alice/Photos"),
        on_demand: false,
        provider: None,
    }
}

/// Runs `join_and_link` with the link port reporting the folder already
/// linked and running, and activation answering `activation`.
async fn rejoin_with_activation(
    activation: EnrollmentActivationResult,
) -> (Result<EnrollmentOutcome, EnrollmentError>, Arc<FakeEnrollmentRepository>, Arc<FakeLinkPort>)
{
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
    coordination.activate.lock().unwrap().push_back(activation);
    let links = Arc::new(FakeLinkPort::default());
    links.commit.lock().unwrap().push_back(Ok(LinkOutcome::AlreadyLinked));

    let result = service(repository.clone(), coordination, links.clone())
        .join_and_link(join_command())
        .await;
    (result, repository, links)
}

/// A join whose prepare was ambiguous leaves its pending edge on the coordination plane under that
/// attempt's operation id, which only the SAME id may resume (a different one is a 409 "already has
/// a pending join operation"). Retrying the same join must therefore reuse the open journal row
/// rather than open a second one under a fresh id.
#[tokio::test]
async fn a_retried_join_reuses_the_open_journal_row_of_its_earlier_attempt() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    for _ in 0..2 {
        coordination.prepare.lock().unwrap().push_back(EnrollmentPrepareResult::Ambiguous {
            detail: "refresh returned HTTP 401".to_string(),
        });
    }
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
    coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::Activated);
    let links = Arc::new(FakeLinkPort::default());
    links.commit.lock().unwrap().push_back(Ok(LinkOutcome::Linked));
    let svc = service(repository.clone(), coordination, links);

    let mut ids = Vec::new();
    for _ in 0..2 {
        match svc.join_and_link(join_command()).await {
            Err(EnrollmentError::PreparationAmbiguous { operation_id, .. }) => {
                ids.push(operation_id)
            }
            other => panic!("expected an ambiguous prepare, got {other:?}"),
        }
    }
    assert_eq!(ids[0], ids[1], "the retry presented a new operation id");
    assert_eq!(repository.operations.lock().unwrap().len(), 1);

    let outcome = svc.join_and_link(join_command()).await.expect("the third attempt prepares");
    assert_eq!(outcome.operation_id, ids[0]);
}

/// A row past the prepare phase (a finished join awaiting journal cleanup) is not the same
/// in-flight request: a repeated join opens its own row and settles as the documented no-op.
#[tokio::test]
async fn a_repeated_join_ignores_a_row_past_its_prepare_phase() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let mut row = journal_row_for("unused", EnrollmentOperationState::ActivationPending);
    row.operation_id = "finished-op".to_string();
    row.kind = yadorilink_replica_domain::session_state::EnrollmentKind::Join;
    row.group_id = Some("group-1".to_string());
    row.group_name = None;
    row.local_path = "/home/alice/Photos".to_string();
    repository.operations.lock().unwrap().insert(row.operation_id.clone(), row);
    let (result, ..) = {
        let coordination = Arc::new(FakeCoordination::configured());
        coordination
            .prepare
            .lock()
            .unwrap()
            .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
        coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::AlreadyActive);
        let links = Arc::new(FakeLinkPort::default());
        links.commit.lock().unwrap().push_back(Ok(LinkOutcome::AlreadyLinked));
        (service(repository, coordination, links).join_and_link(join_command()).await,)
    };
    let outcome = result.expect("a no-op re-join succeeds");
    assert!(outcome.already_linked);
    assert_ne!(outcome.operation_id, "finished-op");
}

/// The earlier attempt's prepare actually landed (`Prepared`, no link yet): the retry resumes it
/// under the same id instead of colliding with its pending edge.
#[tokio::test]
async fn a_retried_join_resumes_a_prepared_row_of_its_earlier_attempt() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let mut row = journal_row_for("unused", EnrollmentOperationState::Prepared);
    row.operation_id = "earlier-op".to_string();
    row.kind = yadorilink_replica_domain::session_state::EnrollmentKind::Join;
    row.group_id = Some("group-1".to_string());
    row.group_name = None;
    row.local_path = "/home/alice/Photos".to_string();
    repository.operations.lock().unwrap().insert(row.operation_id.clone(), row);
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
    coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::Activated);
    let links = Arc::new(FakeLinkPort::default());
    links.commit.lock().unwrap().push_back(Ok(LinkOutcome::Linked));

    let outcome = service(repository.clone(), coordination, links)
        .join_and_link(join_command())
        .await
        .expect("the retry resumes the earlier row");
    assert_eq!(outcome.operation_id, "earlier-op");
}

/// The coordination plane has no membership to activate: the command fails,
/// its own journal row is closed, and the earlier link is left alone -- no
/// rollback, which would orphan a link this command never created.
#[tokio::test]
async fn a_rejoin_whose_membership_is_gone_closes_its_row_and_never_rolls_back_the_link() {
    let (result, repository, links) =
        rejoin_with_activation(EnrollmentActivationResult::Deleted).await;

    assert!(matches!(result, Err(EnrollmentError::ActivationRejected { .. })), "{result:?}");
    assert!(repository.operations.lock().unwrap().is_empty(), "the journal row is closed");
    assert_eq!(*links.calls.lock().unwrap(), vec![EnrollmentCall::LinkCommit]);
}

/// Activation could not be confirmed: the command reports it, the row moves
/// to `CancelPending` (cancelling only a Pending membership this prepare
/// created, never an Active one), and the earlier link is left alone.
#[tokio::test]
async fn a_rejoin_with_a_transient_activation_failure_moves_to_cancel_pending_and_keeps_the_link() {
    let (result, repository, links) =
        rejoin_with_activation(EnrollmentActivationResult::TransientFailure {
            detail: "offline".to_string(),
        })
        .await;

    assert!(matches!(result, Err(EnrollmentError::ActivationAmbiguous { .. })), "{result:?}");
    let operations = repository.operations.lock().unwrap();
    assert_eq!(operations.len(), 1);
    assert_eq!(operations.values().next().unwrap().state, EnrollmentOperationState::CancelPending);
    assert_eq!(*links.calls.lock().unwrap(), vec![EnrollmentCall::LinkCommit]);
}

/// The ordinary case: the membership is already Active, so the command is a
/// no-op reported as one.
#[tokio::test]
async fn a_rejoin_of_an_active_membership_is_reported_as_already_linked() {
    let (result, repository, links) =
        rejoin_with_activation(EnrollmentActivationResult::AlreadyActive).await;

    let outcome = result.expect("a no-op re-join succeeds");
    assert!(outcome.already_linked);
    assert!(!outcome.awaiting_approval);
    assert!(repository.operations.lock().unwrap().is_empty());
    assert_eq!(*links.calls.lock().unwrap(), vec![EnrollmentCall::LinkCommit]);
}

fn provider_create_command(display_name: &str, token: &str) -> CreateAndLinkCommand {
    CreateAndLinkCommand {
        group_name: "photos".to_string(),
        absolute_path: PathBuf::new(),
        on_demand: false,
        provider: Some(ProviderCreation {
            display_name: display_name.to_string(),
            request_token: token.to_string(),
        }),
    }
}

/// A provider folder is created through the SAME journaled saga: the link request carries the
/// synthetic locator and a provider target (an owner-created group is an empty one), and the journal
/// operation id is derived from the request token.
#[tokio::test]
async fn a_provider_creation_runs_the_journaled_saga_under_a_token_derived_operation() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
    coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::Activated);
    let links = Arc::new(FakeLinkPort::default());
    links.commit.lock().unwrap().push_back(Ok(LinkOutcome::Linked));

    let outcome = service(repository, coordination, links.clone())
        .create_and_link(provider_create_command("Photos", "token-1"))
        .await
        .expect("created");

    assert_eq!(outcome.local_path, PathBuf::from("provider://token-1"));
    assert_eq!(
        outcome.operation_id,
        provider_operation_id("token-1", &digest_of("Photos", "photos", "create"), "device-a")
    );
    let requests = links.requests.lock().unwrap();
    let (operation_id, key, target) = &requests[0];
    assert_eq!(
        *operation_id,
        provider_operation_id("token-1", &digest_of("Photos", "photos", "create"), "device-a")
    );
    assert_eq!(*key, PathBuf::from("provider://token-1"));
    let target = target.as_ref().expect("a provider target");
    assert_eq!(target.display_name, "Photos");
    assert_eq!(target.kind, ProviderKind::MacFileProvider);
    assert!(target.empty_owner, "an owner-created group has nothing to install");
}

/// The link carries the adapter kind of the host, and a host with no provider adapter refuses a
/// provider link before the journal opens or the coordination plane is called.
#[tokio::test]
async fn a_provider_link_follows_the_host_adapter_and_is_refused_without_one() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .prepare
        .lock()
        .unwrap()
        .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
    coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::Activated);
    let links = Arc::new(FakeLinkPort::default());
    links.commit.lock().unwrap().push_back(Ok(LinkOutcome::Linked));
    service(repository.clone(), coordination.clone(), links.clone())
        .with_provider_kind(Some(ProviderKind::WindowsCfapi))
        .create_and_link(provider_create_command("Photos", "token-win"))
        .await
        .expect("created");
    assert_eq!(
        links.requests.lock().unwrap()[0].2.as_ref().expect("a provider target").kind,
        ProviderKind::WindowsCfapi
    );

    let repository = Arc::new(FakeEnrollmentRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    let links = Arc::new(FakeLinkPort::default());
    let refused = service(repository.clone(), coordination.clone(), links.clone())
        .with_provider_kind(None)
        .create_and_link(provider_create_command("Photos", "token-none"))
        .await;
    assert!(matches!(refused, Err(EnrollmentError::PreparationRejected { .. })), "{refused:?}");
    assert!(repository.operations.lock().unwrap().is_empty(), "a journal row was opened");
    assert!(links.requests.lock().unwrap().is_empty());
}

/// A retry of a completed creation answers with the existing folder and touches nothing (no
/// prepare, no link); the same token with a different request is refused.
#[tokio::test]
async fn a_retried_token_is_idempotent_and_bound_to_its_request() {
    use yadorilink_replica_domain::session_state::{
        FolderLink, LinkLocation, MaterializationPolicy,
    };
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let creation = ProviderCreation {
        display_name: "Photos".to_string(),
        request_token: "token-9".to_string(),
    };
    repository.links.lock().unwrap().push(FolderLink {
        location: LinkLocation::Provider {
            locator: creation.locator(),
            root_id: "root-1".to_string(),
        },
        group_id: "group-1".to_string(),
        paused: false,
        materialization_policy: MaterializationPolicy::Eager,
        orphaned: false,
    });
    repository
        .digests
        .lock()
        .unwrap()
        .insert(creation.locator(), creation_digest(&creation, "photos", false, "create"));
    let coordination = Arc::new(FakeCoordination::configured());
    let links = Arc::new(FakeLinkPort::default());
    let svc = service(repository, coordination.clone(), links.clone());

    let again = svc
        .create_and_link(provider_create_command("Photos", "token-9"))
        .await
        .expect("a retry answers with the existing folder");
    assert!(again.already_linked);
    assert_eq!(again.group_id, "group-1");
    assert!(
        coordination.calls.lock().unwrap().is_empty(),
        "a retry reached the coordination plane"
    );
    assert!(links.calls.lock().unwrap().is_empty(), "a retry committed another link");

    let different = svc.create_and_link(provider_create_command("Other", "token-9")).await;
    assert!(matches!(different, Err(EnrollmentError::PreparationRejected { .. })), "{different:?}");
}

fn journal_row_for(token: &str, state: EnrollmentOperationState) -> EnrollmentOperation {
    EnrollmentOperation {
        operation_id: provider_operation_id(
            token,
            &digest_of("Photos", "photos", "create"),
            "device-a",
        ),
        kind: yadorilink_replica_domain::session_state::EnrollmentKind::Create,
        group_id: None,
        group_name: Some("photos".to_string()),
        device_id: "device-a".to_string(),
        local_path: format!("provider://{token}"),
        storage_mode: "eager".to_string(),
        state,
        last_error: None,
        attempts: 0,
        created_at_unix: 0,
        updated_at_unix: 0,
    }
}

/// A crash left the journal row of this token mid-prepare: the retry resumes THAT row (same
/// operation id, so the coordination plane answers the same prepare) instead of opening a second one;
/// a row further along is the recovery sweep's, and the retry says so instead of racing it.
#[tokio::test]
async fn a_retry_after_a_crash_resumes_the_journal_row_of_its_token() {
    for (state, resumes) in [
        (EnrollmentOperationState::PreparePending, true),
        (EnrollmentOperationState::Prepared, true),
        (EnrollmentOperationState::ActivationPending, false),
    ] {
        let repository = Arc::new(FakeEnrollmentRepository::default());
        repository.operations.lock().unwrap().insert(
            provider_operation_id("token-c", &digest_of("Photos", "photos", "create"), "device-a"),
            journal_row_for("token-c", state),
        );
        let coordination = Arc::new(FakeCoordination::configured());
        coordination
            .prepare
            .lock()
            .unwrap()
            .push_back(EnrollmentPrepareResult::Prepared { group_id: "group-1".to_string() });
        coordination.activate.lock().unwrap().push_back(EnrollmentActivationResult::Activated);
        let links = Arc::new(FakeLinkPort::default());
        links.commit.lock().unwrap().push_back(Ok(LinkOutcome::Linked));

        let result = service(repository.clone(), coordination.clone(), links.clone())
            .create_and_link(provider_create_command("Photos", "token-c"))
            .await;

        if resumes {
            let outcome = result.unwrap_or_else(|e| panic!("{state:?}: {e}"));
            assert_eq!(
                outcome.operation_id,
                provider_operation_id(
                    "token-c",
                    &digest_of("Photos", "photos", "create"),
                    "device-a"
                )
            );
            assert_eq!(
                repository.operations.lock().unwrap().len(),
                1,
                "{state:?}: a second row was opened"
            );
            assert_eq!(links.requests.lock().unwrap().len(), 1, "{state:?}");
        } else {
            assert!(
                matches!(result, Err(EnrollmentError::PreparationAmbiguous { .. })),
                "{state:?}: {result:?}"
            );
            assert!(
                links.requests.lock().unwrap().is_empty(),
                "{state:?}: raced the recovery sweep"
            );
            assert!(
                coordination.calls.lock().unwrap().is_empty(),
                "{state:?}: reached the coordination plane"
            );
        }
    }
}

/// The creation digest of a provider create request as the tests build it.
fn digest_of(display_name: &str, group: &str, kind: &str) -> String {
    let creation = ProviderCreation {
        display_name: display_name.to_string(),
        request_token: "unused".to_string(),
    };
    creation_digest(&creation, group, false, kind)
}

/// (review) A journal row left open on a token by a request with a different payload (here another display
/// name) is never resumed by a retry that changed the request: it is refused.
#[tokio::test]
async fn a_resume_with_a_changed_payload_is_refused() {
    let repository = Arc::new(FakeEnrollmentRepository::default());
    let original =
        provider_operation_id("token-d", &digest_of("Photos", "photos", "create"), "device-a");
    let mut row = journal_row_for("token-d", EnrollmentOperationState::Prepared);
    row.operation_id = original.clone();
    repository.operations.lock().unwrap().insert(original, row);
    let coordination = Arc::new(FakeCoordination::configured());
    let links = Arc::new(FakeLinkPort::default());

    let result = service(repository.clone(), coordination.clone(), links.clone())
        .create_and_link(provider_create_command("Other name", "token-d"))
        .await;

    assert!(matches!(result, Err(EnrollmentError::PreparationRejected { .. })), "{result:?}");
    assert!(coordination.calls.lock().unwrap().is_empty());
    assert!(links.requests.lock().unwrap().is_empty());
    assert_eq!(repository.operations.lock().unwrap().len(), 1, "a second row was opened");
}
