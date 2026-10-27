#![cfg(test)]

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use yadorilink_replica_domain::session_state::FolderLink;
use yadorilink_replica_domain::session_state::MaterializationPolicy;
use yadorilink_replica_domain::session_state::{
    RoleLossAction, RoleLossOperation, RoleLossOperationState,
};

use super::*;
use crate::application::model::RoleLossCompensationOutcome;
use crate::application::ports::BoxFuture;
use crate::application::ports::StorageModeWriteError;
use crate::handoff_proof::StrongHandoffProof;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Call {
    Latch(String),
    RemoveLink(String),
    SetPolicy(String),
    OpenOperation(String),
    MarkWorkerCommitted(String),
    DiscardOperation(String),
    SettleSuccess(String),
    Advance(String, RoleLossOperationState),
    DeleteOperation(String),
    StartWatch(String),
    StopWatch(String),
}

#[derive(Default)]
struct FakeRepository {
    calls: Mutex<Vec<Call>>,
    links: Mutex<Vec<FolderLink>>,
    recheck_policy_result: Mutex<VecDeque<Result<bool, crate::sync_error::SyncError>>>,
    recheck_remove_result: Mutex<VecDeque<Result<bool, crate::sync_error::SyncError>>>,
}

impl FakeRepository {
    fn with_link(self, link: FolderLink) -> Self {
        self.links.lock().unwrap().push(link);
        self
    }
}

impl ReplicaRoleRepository for FakeRepository {
    fn list_links(&self) -> Result<Vec<FolderLink>, crate::sync_error::SyncError> {
        Ok(self.links.lock().unwrap().clone())
    }

    fn live_link_key_for_group(
        &self,
        group_id: &str,
    ) -> Result<Option<String>, crate::sync_error::SyncError> {
        Ok(self
            .links
            .lock()
            .unwrap()
            .iter()
            .find(|l| l.group_id == group_id)
            .map(|l| l.key().to_string()))
    }

    fn recheck_digest_then_set_materialization_policy(
        &self,
        _group_id: &str,
        local_path: &str,
        _policy: MaterializationPolicy,
        _expected_digest: [u8; 32],
    ) -> Result<bool, crate::sync_error::SyncError> {
        self.calls.lock().unwrap().push(Call::SetPolicy(local_path.to_string()));
        self.recheck_policy_result.lock().unwrap().pop_front().unwrap_or(Ok(true))
    }

    fn recheck_digest_then_remove_link(
        &self,
        _group_id: &str,
        local_path: &str,
        _expected_digest: [u8; 32],
    ) -> Result<bool, crate::sync_error::SyncError> {
        self.calls.lock().unwrap().push(Call::RemoveLink(local_path.to_string()));
        self.recheck_remove_result.lock().unwrap().pop_front().unwrap_or(Ok(true))
    }

    fn remove_link_expecting_group(
        &self,
        local_path: &str,
        group_id: &str,
    ) -> Result<(), crate::sync_error::SyncError> {
        let belongs = self
            .links
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.key() == local_path && l.group_id == group_id);
        if !belongs {
            return Err(crate::sync_error::SyncError::GroupMismatch(local_path.to_string()));
        }
        self.calls.lock().unwrap().push(Call::RemoveLink(local_path.to_string()));
        Ok(())
    }

    fn set_materialization_policy(
        &self,
        local_path: &str,
        _policy: MaterializationPolicy,
    ) -> Result<(), crate::sync_error::SyncError> {
        self.calls.lock().unwrap().push(Call::SetPolicy(local_path.to_string()));
        Ok(())
    }

    fn latch_group_durability_unknown(
        &self,
        group_id: &str,
    ) -> Result<(), crate::sync_error::SyncError> {
        self.calls.lock().unwrap().push(Call::Latch(group_id.to_string()));
        Ok(())
    }

    fn arm_duplicate_recovery_paths(
        &self,
        _group_id: &str,
    ) -> Result<(), crate::sync_error::SyncError> {
        Ok(())
    }

    fn set_suppress_tombstones(
        &self,
        _local_path: &str,
        _suppress: bool,
    ) -> Result<(), crate::sync_error::SyncError> {
        Ok(())
    }
}

/// In-memory role-loss journal: `open_operation` inserts a real `Prepared`
/// row, so the service's own compensation and reconciliation workflows run
/// against rows exactly as they would against the durable journal.
#[derive(Default)]
struct FakeRoleLoss {
    calls: Mutex<Vec<Call>>,
    open_result: Mutex<VecDeque<Result<String, String>>>,
    rows: Mutex<BTreeMap<String, RoleLossOperation>>,
}

fn journal_row(
    operation_id: &str,
    target_device_id: &str,
    lease_id: &str,
    state: RoleLossOperationState,
) -> RoleLossOperation {
    RoleLossOperation {
        operation_id: operation_id.to_string(),
        group_id: "group-1".to_string(),
        source_device_id: "device-a".to_string(),
        target_device_id: target_device_id.to_string(),
        lease_id: lease_id.to_string(),
        worker_membership_generation: None,
        action: RoleLossAction::Demote,
        state,
        local_path: Some("/home/alice/Photos".to_string()),
        attempts: 0,
        created_at_unix: 0,
        updated_at_unix: 0,
    }
}

impl FakeRoleLoss {
    fn with_row(self, row: RoleLossOperation) -> Self {
        self.rows.lock().unwrap().insert(row.operation_id.clone(), row);
        self
    }

    fn row(&self, operation_id: &str) -> Option<RoleLossOperation> {
        self.rows.lock().unwrap().get(operation_id).cloned()
    }
}

impl RoleLossJournal for FakeRoleLoss {
    fn open_operation(
        &self,
        _group_id: &str,
        target_device_id: &str,
        lease_id: &str,
        _action: RoleLossAction,
        _local_path: &str,
    ) -> Result<String, String> {
        let result = self.open_result.lock().unwrap().pop_front().unwrap_or(Ok("op-1".to_string()));
        if let Ok(id) = &result {
            self.calls.lock().unwrap().push(Call::OpenOperation(id.clone()));
            self.rows.lock().unwrap().insert(
                id.clone(),
                journal_row(id, target_device_id, lease_id, RoleLossOperationState::Prepared),
            );
        }
        result
    }

    fn mark_worker_committed(&self, operation_id: &str, membership_generation: i64) {
        self.calls.lock().unwrap().push(Call::MarkWorkerCommitted(operation_id.to_string()));
        if let Some(row) = self.rows.lock().unwrap().get_mut(operation_id) {
            row.state = RoleLossOperationState::WorkerCommitted;
            row.worker_membership_generation = Some(membership_generation);
        }
    }

    fn discard_operation(&self, operation_id: &str) {
        self.calls.lock().unwrap().push(Call::DiscardOperation(operation_id.to_string()));
        self.rows.lock().unwrap().remove(operation_id);
    }

    fn settle_success(&self, operation_id: &str) {
        self.calls.lock().unwrap().push(Call::SettleSuccess(operation_id.to_string()));
        self.rows.lock().unwrap().remove(operation_id);
    }

    fn get_operation(&self, operation_id: &str) -> Result<Option<RoleLossOperation>, String> {
        Ok(self.row(operation_id))
    }

    fn list_operations_in_states(
        &self,
        states: &[RoleLossOperationState],
    ) -> Result<Vec<RoleLossOperation>, String> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .values()
            .filter(|row| states.contains(&row.state))
            .cloned()
            .collect())
    }

    fn advance_operation(
        &self,
        operation_id: &str,
        state: RoleLossOperationState,
    ) -> Result<(), String> {
        self.calls.lock().unwrap().push(Call::Advance(operation_id.to_string(), state));
        if let Some(row) = self.rows.lock().unwrap().get_mut(operation_id) {
            row.state = state;
        }
        Ok(())
    }

    fn increment_attempts(&self, operation_id: &str) -> Result<i64, String> {
        let mut rows = self.rows.lock().unwrap();
        let row = rows.get_mut(operation_id).ok_or_else(|| "no such row".to_string())?;
        row.attempts += 1;
        Ok(row.attempts)
    }

    fn delete_operation(&self, operation_id: &str) -> Result<(), String> {
        self.calls.lock().unwrap().push(Call::DeleteOperation(operation_id.to_string()));
        self.rows.lock().unwrap().remove(operation_id);
        Ok(())
    }
}

#[derive(Default)]
struct FakeReadiness {
    full_replica: AtomicBool,
    digest_and_peer: Mutex<DigestAndPeerResults>,
    lease: Mutex<VecDeque<Option<String>>>,
}

type DigestAndPeerResults = VecDeque<Option<([u8; 32], Option<String>)>>;

impl HandoffReadinessPort for FakeReadiness {
    fn is_local_full_replica(&self, _group_id: &str) -> bool {
        self.full_replica.load(Ordering::SeqCst)
    }

    fn full_replica_handoff_proof<'a>(
        &'a self,
        _group_id: &'a str,
    ) -> BoxFuture<'a, Option<StrongHandoffProof>> {
        Box::pin(async move {
            self.digest_and_peer
                .lock()
                .unwrap()
                .pop_front()
                .flatten()
                .map(|(digest, peer)| StrongHandoffProof::new(digest, peer, 0))
        })
    }

    fn obtain_handoff_lease_from_peer<'a>(
        &'a self,
        _group_id: &'a str,
        _target_peer_device_id: &'a str,
        _my_digest: [u8; 32],
    ) -> BoxFuture<'a, Option<String>> {
        Box::pin(async move { self.lease.lock().unwrap().pop_front().flatten() })
    }
}

#[derive(Default)]
struct FakeCoordination {
    configured: AtomicBool,
    commit_result: Mutex<VecDeque<RoleLossCommitOutcome>>,
    set_storage_mode_calls: Mutex<u32>,
    set_storage_mode_result: Mutex<VecDeque<Result<(), StorageModeWriteError>>>,
    compensate_calls: Mutex<Vec<String>>,
    compensate_result: Mutex<VecDeque<Result<RoleLossCompensationOutcome, String>>>,
}

impl FakeCoordination {
    fn configured() -> Self {
        let this = Self::default();
        this.configured.store(true, Ordering::SeqCst);
        this
    }
}

impl RoleLossCoordination for FakeCoordination {
    fn is_configured(&self) -> bool {
        self.configured.load(Ordering::SeqCst)
    }

    fn commit_handoff_role_loss<'a>(
        &'a self,
        _group_id: &'a str,
        _source_device_id: &'a str,
        _target_device_id: &'a str,
        _lease_id: Option<&'a str>,
        _action: &'a str,
        _operation_id: &'a str,
    ) -> BoxFuture<'a, RoleLossCommitOutcome> {
        Box::pin(async move {
            self.commit_result.lock().unwrap().pop_front().expect("missing fake commit result")
        })
    }

    fn set_storage_mode<'a>(
        &'a self,
        _group_id: &'a str,
        _device_id: &'a str,
        _mode: &'a str,
    ) -> BoxFuture<'a, Result<(), StorageModeWriteError>> {
        Box::pin(async move {
            *self.set_storage_mode_calls.lock().unwrap() += 1;
            self.set_storage_mode_result.lock().unwrap().pop_front().unwrap_or(Ok(()))
        })
    }

    fn compensate_handoff_role_loss<'a>(
        &'a self,
        _group_id: &'a str,
        _source_device_id: &'a str,
        _target_device_id: &'a str,
        lease_id: &'a str,
        _expected_membership_generation: Option<i64>,
    ) -> BoxFuture<'a, Result<RoleLossCompensationOutcome, String>> {
        Box::pin(async move {
            self.compensate_calls.lock().unwrap().push(lease_id.to_string());
            self.compensate_result
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Ok(RoleLossCompensationOutcome::Restored))
        })
    }
}

#[derive(Default)]
struct FakeRuntime {
    calls: Mutex<Vec<Call>>,
    start_result: Mutex<VecDeque<Result<(), String>>>,
    /// Runs once when a watch is stopped: where a test makes something else happen in the
    /// middle of an unlink.
    on_stop: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl LinkRuntimePort for FakeRuntime {
    fn start_link_watch(&self, local_path: String, _group_id: String) -> Result<(), String> {
        self.calls.lock().unwrap().push(Call::StartWatch(local_path));
        self.start_result.lock().unwrap().pop_front().unwrap_or(Ok(()))
    }

    fn stop_link_watch<'a>(&'a self, local_path: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(Call::StopWatch(local_path.to_string()));
            if let Some(hook) = self.on_stop.lock().unwrap().take() {
                hook();
            }
        })
    }
}

/// [`CustodyLeaseHandoffPort`] fake: answers `hand_off_leases` from a queue
/// (a missing answer is "handed off") and records what the service did with it.
#[derive(Default)]
struct FakeCustody {
    answers: Mutex<VecDeque<Result<(), String>>>,
    hand_offs: Mutex<Vec<String>>,
    /// Guards handed out and not yet dropped.
    open_guards: Arc<std::sync::atomic::AtomicUsize>,
    /// How many role-loss journal rows existed when the hand-off ran.
    journal_len_at_hand_off: Mutex<Vec<usize>>,
    journal: Mutex<Option<Arc<FakeRoleLoss>>>,
    /// Runs once during a hand-off: where a test makes something else happen while the
    /// unlink waits on the network.
    on_hand_off: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

struct OpenGuard(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for OpenGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl CustodyLeaseHandoffPort for FakeCustody {
    fn hand_off_leases<'a>(
        &'a self,
        group_id: &'a str,
    ) -> BoxFuture<'a, Result<Box<dyn Send>, String>> {
        Box::pin(async move {
            self.hand_offs.lock().unwrap().push(group_id.to_string());
            if let Some(hook) = self.on_hand_off.lock().unwrap().take() {
                hook();
            }
            if let Some(journal) = self.journal.lock().unwrap().as_ref() {
                self.journal_len_at_hand_off
                    .lock()
                    .unwrap()
                    .push(journal.calls.lock().unwrap().len());
            }
            self.answers.lock().unwrap().pop_front().unwrap_or(Ok(()))?;
            self.open_guards.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(OpenGuard(self.open_guards.clone())) as Box<dyn Send>)
        })
    }
}

const FAKE_LINK_PATH: &str = "/home/alice/Photos";

fn link(group_id: &str, policy: MaterializationPolicy) -> FolderLink {
    FolderLink {
        location: yadorilink_replica_domain::session_state::LinkLocation::Folder(
            FAKE_LINK_PATH.to_string(),
        ),
        group_id: group_id.to_string(),
        paused: false,
        materialization_policy: policy,
        orphaned: false,
    }
}

/// Fixed-answer [`OnDemandCapabilityPort`] fake -- defaults to
/// connected since none of this module's own unit tests exercise the
/// disconnected-gate rejection itself (that's covered by the daemon
/// integration tests in `tests/role_loss_saga.rs`/
/// `tests/storage_mode_orchestration.rs`).
struct FakeOnDemandCapability {
    connected: bool,
}

impl Default for FakeOnDemandCapability {
    fn default() -> Self {
        Self { connected: true }
    }
}

impl OnDemandCapabilityPort for FakeOnDemandCapability {
    fn allows_on_demand(&self, _group_id: &str) -> bool {
        self.connected
    }
}

#[allow(clippy::too_many_arguments)]
fn service(
    repository: Arc<FakeRepository>,
    role_loss: Arc<FakeRoleLoss>,
    readiness: Arc<FakeReadiness>,
    coordination: Arc<FakeCoordination>,
    runtime: Arc<FakeRuntime>,
) -> ReplicaRoleService {
    service_with_custody(
        repository,
        role_loss,
        readiness,
        coordination,
        runtime,
        Arc::new(FakeCustody::default()),
    )
}

#[allow(clippy::too_many_arguments)]
fn service_with_custody(
    repository: Arc<FakeRepository>,
    role_loss: Arc<FakeRoleLoss>,
    readiness: Arc<FakeReadiness>,
    coordination: Arc<FakeCoordination>,
    runtime: Arc<FakeRuntime>,
    custody: Arc<FakeCustody>,
) -> ReplicaRoleService {
    ReplicaRoleService::new(
        "device-a".to_string(),
        repository,
        role_loss,
        readiness,
        coordination,
        runtime,
        Arc::new(FakeOnDemandCapability::default()),
        custody,
    )
}

// ===== set_storage_mode =====

/// The production gate answers "not connected": a request to switch a
/// folder to on-demand is refused before any coordination write or local
/// policy flip, so no root ever runs on-demand without a provider.
#[tokio::test]
async fn on_demand_is_refused_while_the_on_demand_capability_is_not_connected() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
    );
    let coordination = Arc::new(FakeCoordination::configured());
    let svc = ReplicaRoleService::new(
        "device-a".to_string(),
        repository.clone(),
        Arc::new(FakeRoleLoss::default()),
        Arc::new(FakeReadiness::default()),
        coordination.clone(),
        Arc::new(FakeRuntime::default()),
        Arc::new(FakeOnDemandCapability { connected: false }),
        Arc::new(FakeCustody::default()),
    );

    let error = svc
        .set_storage_mode("group-1", true)
        .await
        .expect_err("on-demand must be refused while the pipeline is not connected");

    assert!(matches!(error, StorageModeError::OnDemandUnavailable), "got {error}");
    assert_eq!(*coordination.set_storage_mode_calls.lock().unwrap(), 0);
    assert!(repository
        .calls
        .lock()
        .unwrap()
        .iter()
        .all(|call| !matches!(call, Call::SetPolicy(_))));
}

#[tokio::test]
async fn promotion_writes_coordination_before_the_local_flip() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::OnDemand)),
    );
    let role_loss = Arc::new(FakeRoleLoss::default());
    let readiness = Arc::new(FakeReadiness::default());
    let coordination = Arc::new(FakeCoordination::configured());
    let runtime = Arc::new(FakeRuntime::default());

    let result = service(repository.clone(), role_loss, readiness, coordination.clone(), runtime)
        .set_storage_mode("group-1", false)
        .await;

    assert!(result.is_ok());
    assert_eq!(*coordination.set_storage_mode_calls.lock().unwrap(), 1);
    assert!(repository
        .calls
        .lock()
        .unwrap()
        .contains(&Call::SetPolicy("/home/alice/Photos".to_string())));
}

#[tokio::test]
async fn promotion_without_coordination_config_fails_closed() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::OnDemand)),
    );
    let role_loss = Arc::new(FakeRoleLoss::default());
    let readiness = Arc::new(FakeReadiness::default());
    let coordination = Arc::new(FakeCoordination::default());
    let runtime = Arc::new(FakeRuntime::default());

    let result = service(repository.clone(), role_loss, readiness, coordination, runtime)
        .set_storage_mode("group-1", false)
        .await;

    assert!(result.is_err());
    assert!(repository.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn demotion_of_a_vacuously_ready_empty_group_flips_locally_with_no_journal() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
    );
    let role_loss = Arc::new(FakeRoleLoss::default());
    let readiness = Arc::new(FakeReadiness::default());
    readiness.full_replica.store(true, Ordering::SeqCst);
    readiness.digest_and_peer.lock().unwrap().push_back(Some(([1u8; 32], None)));
    let coordination = Arc::new(FakeCoordination::configured());
    let runtime = Arc::new(FakeRuntime::default());

    let result = service(repository, role_loss.clone(), readiness, coordination, runtime)
        .set_storage_mode("group-1", true)
        .await;

    assert!(result.is_ok());
    assert!(role_loss.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn demotion_with_confirmed_peer_opens_journal_commits_then_settles() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
    );
    let role_loss = Arc::new(FakeRoleLoss::default());
    let readiness = Arc::new(FakeReadiness::default());
    readiness.full_replica.store(true, Ordering::SeqCst);
    readiness
        .digest_and_peer
        .lock()
        .unwrap()
        .push_back(Some(([1u8; 32], Some("device-b".to_string()))));
    readiness.lease.lock().unwrap().push_back(Some("lease-1".to_string()));
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.commit_result.lock().unwrap().push_back(RoleLossCommitOutcome::Committed(
        HandoffCommitResult {
            target_device_id: "device-b".to_string(),
            membership_generation: 3,
            lease_id: Some("lease-1".to_string()),
        },
    ));
    let runtime = Arc::new(FakeRuntime::default());

    let result = service(repository, role_loss.clone(), readiness, coordination, runtime)
        .set_storage_mode("group-1", true)
        .await;

    assert!(result.is_ok());
    let calls = role_loss.calls.lock().unwrap();
    assert!(calls.contains(&Call::OpenOperation("op-1".to_string())));
    assert!(calls.contains(&Call::MarkWorkerCommitted("op-1".to_string())));
    assert!(calls.contains(&Call::SettleSuccess("op-1".to_string())));
}

#[tokio::test]
async fn demotion_lease_unavailable_refuses_with_the_lease_failure_message() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
    );
    let role_loss = Arc::new(FakeRoleLoss::default());
    let readiness = Arc::new(FakeReadiness::default());
    readiness.full_replica.store(true, Ordering::SeqCst);
    readiness
        .digest_and_peer
        .lock()
        .unwrap()
        .push_back(Some(([1u8; 32], Some("device-b".to_string()))));
    readiness.lease.lock().unwrap().push_back(None);
    let coordination = Arc::new(FakeCoordination::configured());
    let runtime = Arc::new(FakeRuntime::default());

    let result = service(repository, role_loss, readiness, coordination, runtime)
        .set_storage_mode("group-1", true)
        .await;

    assert_eq!(result.unwrap_err().to_string(), demotion_handoff_lease_failure_message());
}

/// A role-loss commit refused for the Terms is the typed Terms refusal, not a generic
/// "could not confirm the peer": nothing was committed, so the journal row is discarded and the
/// local mode is untouched.
#[tokio::test]
async fn a_demotion_refused_for_the_terms_is_a_typed_terms_refusal() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
    );
    let role_loss = Arc::new(FakeRoleLoss::default());
    let readiness = Arc::new(FakeReadiness::default());
    readiness.full_replica.store(true, Ordering::SeqCst);
    readiness
        .digest_and_peer
        .lock()
        .unwrap()
        .push_back(Some(([1u8; 32], Some("device-b".to_string()))));
    readiness.lease.lock().unwrap().push_back(Some("lease-1".to_string()));
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .commit_result
        .lock()
        .unwrap()
        .push_back(RoleLossCommitOutcome::TermsConsentRequired("403".into()));
    let runtime = Arc::new(FakeRuntime::default());

    let result = service(repository.clone(), role_loss.clone(), readiness, coordination, runtime)
        .set_storage_mode("group-1", true)
        .await;

    assert!(matches!(result, Err(StorageModeError::TermsConsentRequired)), "{result:?}");
    assert!(role_loss.calls.lock().unwrap().contains(&Call::DiscardOperation("op-1".to_string())));
    assert!(repository.calls.lock().unwrap().is_empty(), "no local change");
}

#[tokio::test]
async fn an_unlink_refused_for_the_terms_is_a_typed_terms_refusal() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
    );
    let readiness = Arc::new(FakeReadiness::default());
    readiness
        .digest_and_peer
        .lock()
        .unwrap()
        .push_back(Some(([1u8; 32], Some("device-b".to_string()))));
    readiness.lease.lock().unwrap().push_back(Some("lease-1".to_string()));
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .commit_result
        .lock()
        .unwrap()
        .push_back(RoleLossCommitOutcome::TermsConsentRequired("403".into()));

    let result = service(
        repository,
        Arc::new(FakeRoleLoss::default()),
        readiness,
        coordination,
        Arc::new(FakeRuntime::default()),
    )
    .ensure_unlink_keeps_a_full_replica("/home/alice/Photos", false, "group-1")
    .await;

    assert_eq!(result.unwrap_err(), UnlinkError::TermsConsentRequired);
}

#[tokio::test]
async fn demotion_ambiguous_commit_compensates_and_refuses() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
    );
    let role_loss = Arc::new(FakeRoleLoss::default());
    let readiness = Arc::new(FakeReadiness::default());
    readiness.full_replica.store(true, Ordering::SeqCst);
    readiness
        .digest_and_peer
        .lock()
        .unwrap()
        .push_back(Some(([1u8; 32], Some("device-b".to_string()))));
    readiness.lease.lock().unwrap().push_back(Some("lease-1".to_string()));
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .commit_result
        .lock()
        .unwrap()
        .push_back(RoleLossCommitOutcome::Ambiguous("timeout".to_string()));
    let runtime = Arc::new(FakeRuntime::default());

    let result = service(repository, role_loss.clone(), readiness, coordination, runtime)
        .set_storage_mode("group-1", true)
        .await;

    assert!(result.is_err());
    assert!(role_loss
        .calls
        .lock()
        .unwrap()
        .contains(&Call::Advance("op-1".to_string(), RoleLossOperationState::Compensating)));
}

// ===== ensure_unlink_keeps_a_full_replica =====

#[tokio::test]
async fn last_full_replica_cannot_unlink() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
    );
    let role_loss = Arc::new(FakeRoleLoss::default());
    let readiness = Arc::new(FakeReadiness::default());
    readiness.digest_and_peer.lock().unwrap().push_back(None);
    let coordination = Arc::new(FakeCoordination::configured());
    let runtime = Arc::new(FakeRuntime::default());

    let result = service(repository, role_loss, readiness, coordination, runtime)
        .ensure_unlink_keeps_a_full_replica("/home/alice/Photos", false, "group-1")
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn forced_unlink_bypasses_the_gate_and_latches_durability_unknown() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
    );
    let role_loss = Arc::new(FakeRoleLoss::default());
    let readiness = Arc::new(FakeReadiness::default());
    readiness.digest_and_peer.lock().unwrap().push_back(None);
    let coordination = Arc::new(FakeCoordination::configured());
    let runtime = Arc::new(FakeRuntime::default());

    let commit = service(repository.clone(), role_loss, readiness, coordination, runtime)
        .ensure_unlink_keeps_a_full_replica("/home/alice/Photos", true, "group-1")
        .await
        .unwrap();

    assert_eq!(commit, UnlinkCommit::RemoveNormally);
    assert!(repository.calls.lock().unwrap().contains(&Call::Latch("group-1".to_string())));
}

#[tokio::test]
async fn on_demand_link_always_allowed_no_gate_touched() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::OnDemand)),
    );
    let role_loss = Arc::new(FakeRoleLoss::default());
    let readiness = Arc::new(FakeReadiness::default());
    let coordination = Arc::new(FakeCoordination::configured());
    let runtime = Arc::new(FakeRuntime::default());

    let commit = service(repository, role_loss, readiness, coordination, runtime)
        .ensure_unlink_keeps_a_full_replica("/home/alice/Photos", false, "group-1")
        .await
        .unwrap();

    assert_eq!(commit, UnlinkCommit::RemoveNormally);
}

#[tokio::test]
async fn ready_eager_unlink_removes_atomically_via_the_readiness_and_coordination_ports() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
    );
    let role_loss = Arc::new(FakeRoleLoss::default());
    let readiness = Arc::new(FakeReadiness::default());
    readiness
        .digest_and_peer
        .lock()
        .unwrap()
        .push_back(Some(([1u8; 32], Some("device-b".to_string()))));
    readiness.lease.lock().unwrap().push_back(Some("lease-1".to_string()));
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.commit_result.lock().unwrap().push_back(RoleLossCommitOutcome::Committed(
        HandoffCommitResult {
            target_device_id: "device-b".to_string(),
            membership_generation: 1,
            lease_id: Some("lease-1".to_string()),
        },
    ));
    let runtime = Arc::new(FakeRuntime::default());

    let commit = service(repository, role_loss.clone(), readiness, coordination, runtime)
        .ensure_unlink_keeps_a_full_replica("/home/alice/Photos", false, "group-1")
        .await
        .unwrap();

    assert!(matches!(commit, UnlinkCommit::AlreadyRemoved(Some(_))));
    assert!(role_loss.calls.lock().unwrap().contains(&Call::SettleSuccess("op-1".to_string())));
}

// ===== unlink =====

#[tokio::test]
async fn unlink_stops_the_watcher_and_removes_the_link_normally() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::OnDemand)),
    );
    let role_loss = Arc::new(FakeRoleLoss::default());
    let readiness = Arc::new(FakeReadiness::default());
    let coordination = Arc::new(FakeCoordination::configured());
    let runtime = Arc::new(FakeRuntime::default());

    let outcome = service(repository.clone(), role_loss, readiness, coordination, runtime.clone())
        .unlink("/home/alice/Photos", false, None)
        .await
        .unwrap();

    assert!(outcome.handoff.is_none());
    assert!(runtime
        .calls
        .lock()
        .unwrap()
        .contains(&Call::StopWatch("/home/alice/Photos".to_string())));
    assert!(repository
        .calls
        .lock()
        .unwrap()
        .contains(&Call::RemoveLink("/home/alice/Photos".to_string())));
}

// ===== role-loss recovery =====

#[tokio::test]
async fn compensation_without_coordination_config_keeps_the_row_for_a_later_sweep() {
    let role_loss = Arc::new(FakeRoleLoss::default().with_row(journal_row(
        "op-1",
        "device-b",
        "lease-1",
        RoleLossOperationState::WorkerCommitted,
    )));
    let coordination = Arc::new(FakeCoordination::default());

    let result = service(
        Arc::new(FakeRepository::default()),
        role_loss.clone(),
        Arc::new(FakeReadiness::default()),
        coordination.clone(),
        Arc::new(FakeRuntime::default()),
    )
    .compensate_role_loss_operation("op-1")
    .await;

    assert!(result.is_err());
    assert!(coordination.compensate_calls.lock().unwrap().is_empty());
    let row = role_loss.row("op-1").expect("an uncompensated row must never be dropped");
    assert_eq!(row.state, RoleLossOperationState::Compensating);
    assert_eq!(row.attempts, 1);
}

#[tokio::test]
async fn reconciliation_deletes_settled_rows_and_compensates_in_flight_ones() {
    let role_loss = Arc::new(
        FakeRoleLoss::default()
            .with_row(journal_row(
                "op-settled",
                "device-b",
                "lease-settled",
                RoleLossOperationState::LocalCommitted,
            ))
            .with_row(journal_row(
                "op-prepared",
                "device-b",
                "lease-prepared",
                RoleLossOperationState::Prepared,
            ))
            .with_row(journal_row(
                "op-unreachable",
                "device-b",
                "lease-unreachable",
                RoleLossOperationState::Compensating,
            )),
    );
    let coordination = Arc::new(FakeCoordination::configured());
    // Rows are visited in operation-id order: op-prepared, then
    // op-unreachable (op-settled needs no coordination call).
    coordination.compensate_result.lock().unwrap().extend([
        Ok(RoleLossCompensationOutcome::Restored),
        Err("coordination plane unavailable".to_string()),
    ]);

    service(
        Arc::new(FakeRepository::default()),
        role_loss.clone(),
        Arc::new(FakeReadiness::default()),
        coordination.clone(),
        Arc::new(FakeRuntime::default()),
    )
    .reconcile_role_loss()
    .await;

    assert_eq!(
        *coordination.compensate_calls.lock().unwrap(),
        vec!["lease-prepared".to_string(), "lease-unreachable".to_string()]
    );
    assert!(role_loss.row("op-settled").is_none());
    assert!(role_loss.row("op-prepared").is_none());
    let retained = role_loss.row("op-unreachable").expect("a failed revert must keep its row");
    assert_eq!(retained.state, RoleLossOperationState::Compensating);
    assert_eq!(retained.attempts, 1);
}

// ===== provider-backed folders keep the same coordination guards =====

fn provider_link(group_id: &str) -> FolderLink {
    FolderLink {
        location: yadorilink_replica_domain::session_state::LinkLocation::Provider {
            locator: "provider://token-1".to_string(),
            root_id: "abcdef01".repeat(4),
        },
        group_id: group_id.to_string(),
        paused: false,
        materialization_policy: MaterializationPolicy::Eager,
        orphaned: false,
    }
}

/// A provider folder is a link like any other for the durability guards: the last full replica
/// cannot be unlinked without `--force`, and a forced unlink latches the durability status.
#[tokio::test]
async fn the_last_full_provider_folder_cannot_be_unlinked_without_force() {
    let repository = Arc::new(FakeRepository::default().with_link(provider_link("group-1")));
    let readiness = Arc::new(FakeReadiness::default());
    readiness.digest_and_peer.lock().unwrap().push_back(None);
    readiness.digest_and_peer.lock().unwrap().push_back(None);
    let svc = service(
        repository.clone(),
        Arc::new(FakeRoleLoss::default()),
        readiness,
        Arc::new(FakeCoordination::configured()),
        Arc::new(FakeRuntime::default()),
    );

    let refused =
        svc.ensure_unlink_keeps_a_full_replica("provider://token-1", false, "group-1").await;
    assert!(refused.is_err(), "the last complete copy was unlinked without the guard");
    let forced = svc
        .ensure_unlink_keeps_a_full_replica("provider://token-1", true, "group-1")
        .await
        .unwrap();
    assert_eq!(forced, UnlinkCommit::RemoveNormally);
    assert!(repository.calls.lock().unwrap().contains(&Call::Latch("group-1".to_string())));
}

/// Demoting a provider folder to on-demand goes through the same handoff: with a confirmed peer
/// the coordination plane is written before the local flip, exactly as for a plain folder.
#[tokio::test]
async fn demoting_a_provider_folder_opens_the_role_loss_journal_like_any_other() {
    let repository = Arc::new(FakeRepository::default().with_link(provider_link("group-1")));
    let role_loss = Arc::new(FakeRoleLoss::default());
    let readiness = Arc::new(FakeReadiness::default());
    readiness.full_replica.store(true, Ordering::SeqCst);
    readiness
        .digest_and_peer
        .lock()
        .unwrap()
        .push_back(Some(([1u8; 32], Some("device-b".to_string()))));
    readiness.lease.lock().unwrap().push_back(Some("lease-1".to_string()));
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.commit_result.lock().unwrap().push_back(RoleLossCommitOutcome::Committed(
        HandoffCommitResult {
            target_device_id: "device-b".to_string(),
            membership_generation: 3,
            lease_id: Some("lease-1".to_string()),
        },
    ));
    let svc = service(
        repository,
        role_loss.clone(),
        readiness,
        coordination,
        Arc::new(FakeRuntime::default()),
    );

    assert!(svc.set_storage_mode("group-1", true).await.is_ok());
    let calls = role_loss.calls.lock().unwrap();
    assert!(
        calls.contains(&Call::OpenOperation("op-1".to_string())),
        "no journal for a provider folder"
    );
    assert!(calls.contains(&Call::MarkWorkerCommitted("op-1".to_string())));
    assert!(calls.contains(&Call::SettleSuccess("op-1".to_string())));
}

// ===== custody leases at role loss =====

type DemotionFixtures = (
    Arc<FakeRepository>,
    Arc<FakeRoleLoss>,
    Arc<FakeReadiness>,
    Arc<FakeCoordination>,
    Arc<FakeRuntime>,
);

fn confirmed_demotion_fixtures() -> DemotionFixtures {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
    );
    let readiness = Arc::new(FakeReadiness::default());
    readiness.full_replica.store(true, Ordering::SeqCst);
    readiness
        .digest_and_peer
        .lock()
        .unwrap()
        .push_back(Some(([1u8; 32], Some("device-b".to_string()))));
    readiness.lease.lock().unwrap().push_back(Some("lease-1".to_string()));
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.commit_result.lock().unwrap().push_back(RoleLossCommitOutcome::Committed(
        HandoffCommitResult {
            target_device_id: "device-b".to_string(),
            membership_generation: 3,
            lease_id: Some("lease-1".to_string()),
        },
    ));
    (
        repository,
        Arc::new(FakeRoleLoss::default()),
        readiness,
        coordination,
        Arc::new(FakeRuntime::default()),
    )
}

/// A demotion moves the custody leases first -- before any journal row or
/// coordination commit exists -- and keeps the group closed while it commits.
#[tokio::test]
async fn demotion_hands_the_custody_leases_off_before_anything_is_committed() {
    let (repository, role_loss, readiness, coordination, runtime) = confirmed_demotion_fixtures();
    let custody = Arc::new(FakeCustody::default());
    *custody.journal.lock().unwrap() = Some(role_loss.clone());

    let result = service_with_custody(
        repository.clone(),
        role_loss.clone(),
        readiness,
        coordination,
        runtime,
        custody.clone(),
    )
    .set_storage_mode("group-1", true)
    .await;

    assert!(result.is_ok());
    assert_eq!(*custody.hand_offs.lock().unwrap(), vec!["group-1".to_string()]);
    assert_eq!(*custody.journal_len_at_hand_off.lock().unwrap(), vec![0], "nothing journaled yet");
    assert!(repository.calls.lock().unwrap().contains(&Call::SetPolicy(FAKE_LINK_PATH.into())));
    assert_eq!(custody.open_guards.load(Ordering::SeqCst), 0, "the group reopens when done");
}

/// A lease that cannot move blocks the demotion: no journal row, no
/// coordination commit (an unqueued commit would panic the fake), no policy
/// flip, and the group is open again for the retry.
#[tokio::test]
async fn demotion_is_refused_and_recoverable_when_a_custody_lease_cannot_move() {
    let (repository, role_loss, readiness, _coordination, runtime) = confirmed_demotion_fixtures();
    let coordination = Arc::new(FakeCoordination::configured());
    let custody = Arc::new(FakeCustody::default());
    custody.answers.lock().unwrap().push_back(Err("1 custody lease(s) could not move".into()));

    let result = service_with_custody(
        repository.clone(),
        role_loss.clone(),
        readiness,
        coordination,
        runtime,
        custody.clone(),
    )
    .set_storage_mode("group-1", true)
    .await;

    assert_eq!(result.unwrap_err().to_string(), "1 custody lease(s) could not move");
    assert!(role_loss.calls.lock().unwrap().is_empty(), "no journal row");
    assert!(repository.calls.lock().unwrap().is_empty(), "no local change");
    assert_eq!(custody.open_guards.load(Ordering::SeqCst), 0, "nothing stays closed");
}

/// The leases are moved after the readiness gate but also when the coordination
/// commit then fails: nothing is lost by having moved them, and the group
/// reopens so the retry can start from scratch.
#[tokio::test]
async fn a_failed_demotion_after_the_hand_off_reopens_the_group() {
    let (repository, role_loss, readiness, _coordination, runtime) = confirmed_demotion_fixtures();
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .commit_result
        .lock()
        .unwrap()
        .push_back(RoleLossCommitOutcome::DefinitelyRejected("no".into()));
    let custody = Arc::new(FakeCustody::default());

    let result = service_with_custody(
        repository,
        role_loss,
        readiness,
        coordination,
        runtime,
        custody.clone(),
    )
    .set_storage_mode("group-1", true)
    .await;

    assert!(result.is_err());
    assert_eq!(custody.open_guards.load(Ordering::SeqCst), 0);
}

/// Unlinking an eager link hands the leases off first and refuses (no link
/// change) when one cannot move.
#[tokio::test]
async fn unlink_of_an_eager_link_is_refused_when_a_custody_lease_cannot_move() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
    );
    let custody = Arc::new(FakeCustody::default());
    custody.answers.lock().unwrap().push_back(Err("a lease cannot move".into()));
    let runtime = Arc::new(FakeRuntime::default());

    let result = service_with_custody(
        repository.clone(),
        Arc::new(FakeRoleLoss::default()),
        Arc::new(FakeReadiness::default()),
        Arc::new(FakeCoordination::configured()),
        runtime.clone(),
        custody.clone(),
    )
    .unlink(FAKE_LINK_PATH, false, None)
    .await;

    assert_eq!(result.err(), Some(UnlinkError::NotProtected("a lease cannot move".to_string())));
    assert!(repository.calls.lock().unwrap().is_empty());
    assert!(runtime.calls.lock().unwrap().is_empty(), "the watcher was not stopped");
}

/// A forced unlink goes ahead without the hand-off; nothing here touches the
/// leases it could not move (they stay with their requesters' releases).
#[tokio::test]
async fn forced_unlink_proceeds_without_the_hand_off() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
    );
    let readiness = Arc::new(FakeReadiness::default());
    readiness.digest_and_peer.lock().unwrap().push_back(None);
    let custody = Arc::new(FakeCustody::default());
    custody.answers.lock().unwrap().push_back(Err("a lease cannot move".into()));

    let result = service_with_custody(
        repository.clone(),
        Arc::new(FakeRoleLoss::default()),
        readiness,
        Arc::new(FakeCoordination::configured()),
        Arc::new(FakeRuntime::default()),
        custody.clone(),
    )
    .unlink(FAKE_LINK_PATH, true, None)
    .await;

    assert!(result.is_ok());
    assert!(repository.calls.lock().unwrap().contains(&Call::RemoveLink(FAKE_LINK_PATH.into())));
    assert_eq!(custody.hand_offs.lock().unwrap().len(), 1, "the hand-off was attempted");
    assert_eq!(custody.open_guards.load(Ordering::SeqCst), 0);
}

/// An on-demand link holds no leases: nothing to hand off.
#[tokio::test]
async fn unlink_of_an_on_demand_link_does_not_touch_the_custody_leases() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::OnDemand)),
    );
    let custody = Arc::new(FakeCustody::default());
    service_with_custody(
        repository,
        Arc::new(FakeRoleLoss::default()),
        Arc::new(FakeReadiness::default()),
        Arc::new(FakeCoordination::configured()),
        Arc::new(FakeRuntime::default()),
        custody.clone(),
    )
    .unlink(FAKE_LINK_PATH, false, None)
    .await
    .unwrap();
    assert!(custody.hand_offs.lock().unwrap().is_empty());
}

fn unlink_service(
    repository: Arc<FakeRepository>,
    runtime: Arc<FakeRuntime>,
) -> ReplicaRoleService {
    service_with_custody(
        repository,
        Arc::new(FakeRoleLoss::default()),
        Arc::new(FakeReadiness::default()),
        Arc::new(FakeCoordination::configured()),
        runtime,
        Arc::new(FakeCustody::default()),
    )
}

/// The wrong expected group is refused before anything is touched.
#[tokio::test]
async fn unlink_with_the_wrong_expected_group_changes_nothing() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::OnDemand)),
    );
    let runtime = Arc::new(FakeRuntime::default());

    let result = unlink_service(repository.clone(), runtime.clone())
        .unlink(FAKE_LINK_PATH, false, Some("group-2"))
        .await;

    assert_eq!(result.err(), Some(UnlinkError::GroupMismatch(FAKE_LINK_PATH.to_string())));
    assert!(repository.calls.lock().unwrap().is_empty());
    assert!(runtime.calls.lock().unwrap().is_empty());
}

/// The right expected group, and none at all, unlink.
#[tokio::test]
async fn unlink_with_the_matching_or_no_expected_group_removes_the_link() {
    for expected in [Some("group-1"), None] {
        let repository = Arc::new(
            FakeRepository::default().with_link(link("group-1", MaterializationPolicy::OnDemand)),
        );
        let result = unlink_service(repository.clone(), Arc::new(FakeRuntime::default()))
            .unlink(FAKE_LINK_PATH, false, expected)
            .await;
        assert!(result.is_ok(), "{expected:?}");
        assert!(repository
            .calls
            .lock()
            .unwrap()
            .contains(&Call::RemoveLink(FAKE_LINK_PATH.into())));
    }
}

/// The folder is replaced by another group's link after the check and before the
/// removal: the removal itself refuses, the replacement stays and its watch is running.
#[tokio::test]
async fn unlink_refuses_when_the_link_is_replaced_before_the_removal() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::OnDemand)),
    );
    let runtime = Arc::new(FakeRuntime::default());
    let replaced = repository.clone();
    *runtime.on_stop.lock().unwrap() = Some(Box::new(move || {
        *replaced.links.lock().unwrap() = vec![link("group-2", MaterializationPolicy::OnDemand)];
    }));

    let result = unlink_service(repository.clone(), runtime.clone())
        .unlink(FAKE_LINK_PATH, false, Some("group-1"))
        .await;

    assert_eq!(result.err(), Some(UnlinkError::GroupMismatch(FAKE_LINK_PATH.to_string())));
    assert!(!repository.calls.lock().unwrap().iter().any(|c| matches!(c, Call::RemoveLink(_))));
    assert_eq!(repository.links.lock().unwrap().len(), 1, "the replacement stays");
    assert!(
        runtime.calls.lock().unwrap().contains(&Call::StartWatch(FAKE_LINK_PATH.into())),
        "the replacement's watch was started again"
    );
}

/// The folder is linked again to another eager group while the custody hand-off waits:
/// nothing may run for that group (no lease, no role-loss commit, no removal), with or
/// without a confirming peer.
#[tokio::test]
async fn unlink_refuses_an_eager_link_replaced_during_the_custody_hand_off() {
    for peer in [None, Some("device-b".to_string())] {
        let repository = Arc::new(
            FakeRepository::default().with_link(link("group-1", MaterializationPolicy::Eager)),
        );
        let readiness = Arc::new(FakeReadiness::default());
        readiness.digest_and_peer.lock().unwrap().push_back(Some(([7u8; 32], peer.clone())));
        readiness.lease.lock().unwrap().push_back(Some("lease-1".into()));
        let role_loss = Arc::new(FakeRoleLoss::default());
        let custody = Arc::new(FakeCustody::default());
        let replaced = repository.clone();
        *custody.on_hand_off.lock().unwrap() = Some(Box::new(move || {
            *replaced.links.lock().unwrap() = vec![link("group-2", MaterializationPolicy::Eager)];
        }));

        let result = service_with_custody(
            repository.clone(),
            role_loss.clone(),
            readiness,
            Arc::new(FakeCoordination::configured()),
            Arc::new(FakeRuntime::default()),
            custody,
        )
        .unlink(FAKE_LINK_PATH, false, Some("group-1"))
        .await;

        assert_eq!(
            result.err(),
            Some(UnlinkError::GroupMismatch(FAKE_LINK_PATH.to_string())),
            "peer {peer:?}"
        );
        assert!(role_loss.calls.lock().unwrap().is_empty(), "no role-loss commit; peer {peer:?}");
        assert!(
            !repository.calls.lock().unwrap().iter().any(|c| matches!(c, Call::RemoveLink(_))),
            "the replacement stays; peer {peer:?}"
        );
        assert_eq!(repository.links.lock().unwrap().len(), 1);
    }
}

/// The custody hand-off never runs for a link of a group other than the checked one.
#[tokio::test]
async fn custody_hand_off_refuses_a_link_of_another_group() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-2", MaterializationPolicy::Eager)),
    );
    let custody = Arc::new(FakeCustody::default());
    let service = service_with_custody(
        repository,
        Arc::new(FakeRoleLoss::default()),
        Arc::new(FakeReadiness::default()),
        Arc::new(FakeCoordination::configured()),
        Arc::new(FakeRuntime::default()),
        custody.clone(),
    );

    let result = service.hand_off_custody_leases_for_unlink(FAKE_LINK_PATH, "group-1").await;

    assert!(matches!(result, Err(UnlinkError::GroupMismatch(_))));
    assert!(custody.hand_offs.lock().unwrap().is_empty(), "no lease was handed off");
}

#[tokio::test]
async fn promotion_terms_refusal_is_the_typed_error_and_changes_nothing_locally() {
    let repository = Arc::new(
        FakeRepository::default().with_link(link("group-1", MaterializationPolicy::OnDemand)),
    );
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .set_storage_mode_result
        .lock()
        .unwrap()
        .push_back(Err(StorageModeWriteError::TermsConsentRequired("403".into())));

    let result = service(
        repository.clone(),
        Arc::new(FakeRoleLoss::default()),
        Arc::new(FakeReadiness::default()),
        coordination,
        Arc::new(FakeRuntime::default()),
    )
    .set_storage_mode("group-1", false)
    .await;

    assert!(matches!(result, Err(StorageModeError::TermsConsentRequired)), "{result:?}");
    assert!(repository.calls.lock().unwrap().is_empty(), "no local change");
}
