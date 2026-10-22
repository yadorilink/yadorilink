#![cfg(test)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use crate::sync_error::SyncError;
use yadorilink_peer_session::peer_session::PeerHandoffTicketGrant;
use yadorilink_replica_domain::session_state::MaterializationPolicy;
use yadorilink_replica_domain::session_state::{
    FolderLink, InvalidMembershipOperation, MembershipOperationScan,
};

use super::*;
use crate::application::model::{
    HandoffCommitResult, MembershipCommitResult, MembershipOperationRecord,
    MembershipRemoteRequest, MembershipRemoteResult, MembershipRemoteStatus,
};
use crate::application::ports::BoxFuture;

#[derive(Clone, Debug, PartialEq, Eq)]
enum RepoCall {
    Settle(String),
    MarkAmbiguous(String),
    MarkRecoveryBlocked(String),
    MarkLocalSettlementPending(String),
    Discard(String),
    Latch(String),
}

#[derive(Default)]
struct FakeRepository {
    calls: Mutex<Vec<RepoCall>>,
    operations: Mutex<std::collections::HashMap<String, MembershipOperation>>,
    links: Mutex<Vec<FolderLink>>,
    invalid: Mutex<Vec<InvalidMembershipOperation>>,
    insert_result: Mutex<VecDeque<Result<bool, String>>>,
    fail_latch: AtomicBool,
}

impl FakeRepository {
    fn with_operation(self, op: MembershipOperation) -> Self {
        self.operations.lock().unwrap().insert(op.operation_id.clone(), op);
        self
    }

    fn with_link(self, link: FolderLink) -> Self {
        self.links.lock().unwrap().push(link);
        self
    }
}

impl MembershipRepository for FakeRepository {
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
        if let Some(result) = self.insert_result.lock().unwrap().pop_front() {
            if matches!(result, Ok(true)) {
                self.operations.lock().unwrap().insert(
                    operation_id.to_string(),
                    MembershipOperation {
                        operation_id: operation_id.to_string(),
                        action,
                        commit_mode,
                        removed_device_id: removed_device_id.to_string(),
                        group_ids: group_ids.to_vec(),
                        target_device_ids: target_device_ids.to_vec(),
                        lease_ids: lease_ids.to_vec(),
                        state: MembershipOperationState::Prepared,
                        durability_scope,
                        latch_group_ids: latch_group_ids.to_vec(),
                        last_error: None,
                        created_at_unix: now_unix(),
                        updated_at_unix: now_unix(),
                    },
                );
            }
            return result;
        }
        self.operations.lock().unwrap().insert(
            operation_id.to_string(),
            MembershipOperation {
                operation_id: operation_id.to_string(),
                action,
                commit_mode,
                removed_device_id: removed_device_id.to_string(),
                group_ids: group_ids.to_vec(),
                target_device_ids: target_device_ids.to_vec(),
                lease_ids: lease_ids.to_vec(),
                state: MembershipOperationState::Prepared,
                durability_scope,
                latch_group_ids: latch_group_ids.to_vec(),
                last_error: None,
                created_at_unix: now_unix(),
                updated_at_unix: now_unix(),
            },
        );
        Ok(true)
    }

    fn settle_operation(&self, operation_id: &str) {
        self.calls.lock().unwrap().push(RepoCall::Settle(operation_id.to_string()));
        self.operations.lock().unwrap().remove(operation_id);
    }

    fn mark_ambiguous(&self, operation_id: &str, _detail: &str) {
        self.calls.lock().unwrap().push(RepoCall::MarkAmbiguous(operation_id.to_string()));
        if let Some(op) = self.operations.lock().unwrap().get_mut(operation_id) {
            op.state = MembershipOperationState::Ambiguous;
        }
    }

    fn mark_recovery_blocked(&self, operation_id: &str, _detail: &str) {
        self.calls.lock().unwrap().push(RepoCall::MarkRecoveryBlocked(operation_id.to_string()));
        if let Some(op) = self.operations.lock().unwrap().get_mut(operation_id) {
            op.state = MembershipOperationState::RecoveryBlocked;
        }
    }

    fn mark_local_settlement_pending(&self, operation_id: &str, _detail: &str) {
        self.calls
            .lock()
            .unwrap()
            .push(RepoCall::MarkLocalSettlementPending(operation_id.to_string()));
        if let Some(op) = self.operations.lock().unwrap().get_mut(operation_id) {
            op.state = MembershipOperationState::LocalSettlementPending;
        }
    }

    fn discard_operation(&self, operation_id: &str) {
        self.calls.lock().unwrap().push(RepoCall::Discard(operation_id.to_string()));
        self.operations.lock().unwrap().remove(operation_id);
    }

    fn scan_open_operations(&self) -> Result<MembershipOperationScan, SyncError> {
        Ok(MembershipOperationScan {
            valid: self
                .operations
                .lock()
                .unwrap()
                .values()
                .filter(|op| op.state != MembershipOperationState::RecoveryBlocked)
                .cloned()
                .collect(),
            invalid: self.invalid.lock().unwrap().clone(),
        })
    }

    fn list_links(&self) -> Result<Vec<FolderLink>, SyncError> {
        Ok(self.links.lock().unwrap().clone())
    }

    fn latch_group_durability_unknown(&self, group_id: &str) -> Result<(), SyncError> {
        self.calls.lock().unwrap().push(RepoCall::Latch(group_id.to_string()));
        if self.fail_latch.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("fake latch failure").into());
        }
        Ok(())
    }
}

struct FakeCoordination {
    configured: AtomicBool,
    eager_groups: Mutex<VecDeque<Result<Vec<String>, String>>>,
    dispatch: Mutex<VecDeque<MembershipCommitOutcome>>,
    dispatch_calls: Mutex<u32>,
    query: Mutex<VecDeque<Result<MembershipOperationLookup, String>>>,
    resolve_edge_result: Mutex<ResolveEdgeResults>,
    /// What `fetch_edge_state` answers. `None` (the default) stands for
    /// the coordination plane that does not report edge state at all,
    /// which every pre-existing test here is exercising -- so those keep
    /// taking the conservative, ticket-requiring branch unchanged.
    edge_state: Mutex<Result<Option<String>, String>>,
    edge_state_calls: Mutex<u32>,
    audit_calls: Mutex<u32>,
}

type ResolveEdgeResults = VecDeque<Result<Option<(String, String)>, String>>;

impl Default for FakeCoordination {
    fn default() -> Self {
        Self {
            configured: AtomicBool::default(),
            eager_groups: Mutex::default(),
            dispatch: Mutex::default(),
            dispatch_calls: Mutex::default(),
            query: Mutex::default(),
            resolve_edge_result: Mutex::default(),
            edge_state: Mutex::new(Ok(None)),
            edge_state_calls: Mutex::default(),
            audit_calls: Mutex::default(),
        }
    }
}

impl FakeCoordination {
    fn configured() -> Self {
        let this = Self::default();
        this.configured.store(true, Ordering::SeqCst);
        this
    }

    fn with_edge_state(self, state: &str) -> Self {
        *self.edge_state.lock().unwrap() = Ok(Some(state.to_string()));
        self
    }
}

impl MembershipCoordination for FakeCoordination {
    fn is_configured(&self) -> bool {
        self.configured.load(Ordering::SeqCst)
    }

    fn fetch_eager_groups<'a>(
        &'a self,
        _device_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<String>, String>> {
        Box::pin(async move {
            self.eager_groups.lock().unwrap().pop_front().expect("missing fake eager groups")
        })
    }

    fn dispatch<'a>(
        &'a self,
        _command: &'a MembershipRemoteCommand,
        _operation_id: &'a str,
    ) -> BoxFuture<'a, MembershipCommitOutcome> {
        Box::pin(async move {
            *self.dispatch_calls.lock().unwrap() += 1;
            self.dispatch.lock().unwrap().pop_front().expect("missing fake dispatch outcome")
        })
    }

    fn query_operation<'a>(
        &'a self,
        _operation_id: &'a str,
    ) -> BoxFuture<'a, Result<MembershipOperationLookup, String>> {
        Box::pin(async move {
            self.query.lock().unwrap().pop_front().expect("missing fake query result")
        })
    }

    fn resolve_edge<'a>(
        &'a self,
        _edge_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<(String, String)>, String>> {
        Box::pin(async move {
            self.resolve_edge_result
                .lock()
                .unwrap()
                .pop_front()
                .expect("missing fake resolve result")
        })
    }

    fn fetch_edge_state<'a>(
        &'a self,
        _group_id: &'a str,
        _device_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<String>, String>> {
        Box::pin(async move {
            *self.edge_state_calls.lock().unwrap() += 1;
            self.edge_state.lock().unwrap().clone()
        })
    }

    fn record_force_override_audit<'a>(
        &'a self,
        _local_device_id: &'a str,
        _target_device_id: &'a str,
        _group_ids: &'a [String],
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            *self.audit_calls.lock().unwrap() += 1;
        })
    }
}

#[derive(Default)]
struct FakeTickets {
    grants: Mutex<VecDeque<Option<PeerHandoffTicketGrant>>>,
    released: Mutex<Vec<String>>,
    release_result: Mutex<VecDeque<Result<(), String>>>,
}

impl HandoffTicketPort for FakeTickets {
    fn obtain_ticket<'a>(
        &'a self,
        _group_id: &'a str,
        _device_id: &'a str,
    ) -> BoxFuture<'a, Option<PeerHandoffTicketGrant>> {
        Box::pin(async move { self.grants.lock().unwrap().pop_front().flatten() })
    }

    fn release_ticket<'a>(
        &'a self,
        group_id: &'a str,
        _device_id: &'a str,
        _target_device_id: &'a str,
        _lease_id: &'a str,
    ) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.released.lock().unwrap().push(group_id.to_string());
            self.release_result.lock().unwrap().pop_front().unwrap_or(Ok(()))
        })
    }
}

#[derive(Default)]
struct FakeReadiness {
    ready: Mutex<VecDeque<bool>>,
    /// Whether this device's own verified policy shows the target is not a
    /// member. Defaults to `false`: no verified evidence.
    verified_non_member: AtomicBool,
    /// Groups this device's own evidence (netmap role, direct summary ask)
    /// shows the target holding as an eager replica.
    eager_evidence: Mutex<Vec<String>>,
    /// Groups this device's netmap shows the target sharing at all.
    shared_with_target: Mutex<Vec<String>>,
}

impl ReplicaReadinessPort for FakeReadiness {
    fn another_full_replica_is_ready_excluding<'a>(
        &'a self,
        _group_id: &'a str,
        _excluded_device_id: &'a str,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move { self.ready.lock().unwrap().pop_front().unwrap_or(false) })
    }

    fn verified_policy_shows_non_member<'a>(
        &'a self,
        _group_id: &'a str,
        _device_id: &'a str,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move { self.verified_non_member.load(Ordering::SeqCst) })
    }

    fn groups_shared_with_peer<'a>(&'a self, _device_id: &'a str) -> BoxFuture<'a, Vec<String>> {
        Box::pin(async move { self.shared_with_target.lock().unwrap().clone() })
    }

    fn peer_eager_replica_groups<'a>(
        &'a self,
        _device_id: &'a str,
        candidate_group_ids: &'a [String],
    ) -> BoxFuture<'a, Vec<String>> {
        Box::pin(async move {
            let evidence = self.eager_evidence.lock().unwrap();
            candidate_group_ids.iter().filter(|g| evidence.contains(g)).cloned().collect()
        })
    }
}

fn service(
    repository: Arc<FakeRepository>,
    coordination: Arc<FakeCoordination>,
    tickets: Arc<FakeTickets>,
    readiness: Arc<FakeReadiness>,
) -> ReplicaMembershipService {
    ReplicaMembershipService::new(
        "device-a".to_string(),
        repository,
        coordination,
        tickets,
        readiness,
    )
}

fn grant(target: &str, lease: &str) -> Option<PeerHandoffTicketGrant> {
    Some(PeerHandoffTicketGrant {
        lease_id: Some(lease.to_string()),
        target_device_id: Some(target.to_string()),
        expires_at_unix: now_unix() + 60,
    })
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

fn old_operation(
    operation_id: &str,
    state: MembershipOperationState,
    durability_scope: MembershipDurabilityScope,
) -> MembershipOperation {
    MembershipOperation {
        operation_id: operation_id.to_string(),
        action: MembershipOperationAction::RemoveDevice,
        commit_mode: MembershipCommitMode::PlainRemoveDevice,
        removed_device_id: "device-b".to_string(),
        group_ids: Vec::new(),
        target_device_ids: Vec::new(),
        lease_ids: Vec::new(),
        state,
        durability_scope,
        latch_group_ids: Vec::new(),
        last_error: None,
        created_at_unix: now_unix() - 1000,
        updated_at_unix: now_unix() - 1000,
    }
}

// ===== change_membership =====

#[tokio::test]
async fn unconfigured_coordination_refuses_before_touching_the_journal() {
    let repository = Arc::new(FakeRepository::default());
    let coordination = Arc::new(FakeCoordination::default());
    let tickets = Arc::new(FakeTickets::default());
    let readiness = Arc::new(FakeReadiness::default());

    let result = service(repository, coordination, tickets, readiness)
        .remove_device(RemoveDeviceCommand { device_id: "device-b".to_string(), force: false })
        .await;

    assert!(matches!(result, Err(ReplicaMembershipError::LocalIdentityUnavailable)));
}

#[tokio::test]
async fn revoke_with_no_groups_at_risk_takes_the_plain_fast_path() {
    let repository = Arc::new(FakeRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.eager_groups.lock().unwrap().push_back(Ok(Vec::new()));
    coordination
        .dispatch
        .lock()
        .unwrap()
        .push_back(MembershipCommitOutcome::Committed(MembershipCommitResult::NONE));
    let tickets = Arc::new(FakeTickets::default());
    let readiness = Arc::new(FakeReadiness::default());

    let outcome = service(repository, coordination.clone(), tickets.clone(), readiness)
        .remove_device(RemoveDeviceCommand { device_id: "device-b".to_string(), force: false })
        .await
        .unwrap();

    assert!(outcome.handoffs.is_empty());
    assert!(outcome.forced_group_ids.is_empty());
    assert!(tickets.grants.lock().unwrap().is_empty());
}

#[tokio::test]
async fn ticket_bound_guarded_revoke_reports_the_real_membership_generation() {
    let repository = Arc::new(FakeRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.eager_groups.lock().unwrap().push_back(Ok(vec!["group-1".to_string()]));
    coordination.dispatch.lock().unwrap().push_back(MembershipCommitOutcome::Committed(
        MembershipCommitResult {
            handoff: Some(HandoffCommitResult {
                target_device_id: "device-c".to_string(),
                membership_generation: 7,
                lease_id: Some("lease-1".to_string()),
            }),
        },
    ));
    let tickets = Arc::new(FakeTickets::default());
    tickets.grants.lock().unwrap().push_back(grant("device-c", "lease-0"));
    let readiness = Arc::new(FakeReadiness::default());

    let outcome = service(repository, coordination, tickets, readiness)
        .revoke_device(RevokeDeviceCommand {
            group_id: "group-1".to_string(),
            device_id: "device-b".to_string(),
            force: false,
        })
        .await
        .unwrap();

    assert_eq!(outcome.handoffs.len(), 1);
    assert_eq!(outcome.handoffs[0].membership_generation, 7);
    assert_eq!(outcome.handoffs[0].lease_id, "lease-1");
}

#[tokio::test]
async fn unavailable_ticket_without_force_refuses_with_replica_not_ready() {
    let repository = Arc::new(FakeRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.eager_groups.lock().unwrap().push_back(Ok(vec!["group-1".to_string()]));
    let tickets = Arc::new(FakeTickets::default());
    tickets.grants.lock().unwrap().push_back(None);
    let readiness = Arc::new(FakeReadiness::default());

    let result = service(repository, coordination, tickets, readiness)
        .revoke_device(RevokeDeviceCommand {
            group_id: "group-1".to_string(),
            device_id: "device-b".to_string(),
            force: false,
        })
        .await;

    assert!(matches!(result, Err(ReplicaMembershipError::ReplicaNotReady { .. })));
}

/// Turning down a device that is waiting for the group owner's approval
/// is this same targeted revoke, and it must simply work.
///
/// Such a device has never been granted anything, so it is in no
/// netmap, so no peer session with it can exist and no handoff ticket
/// for it can ever be obtained. Treating its group as at risk anyway
/// made every deny fail with "another full replica is not ready" for a
/// device holding zero bytes, leaving `--force` -- and its data-loss
/// warning, describing data that does not exist -- as the only way
/// through. Note what this test withholds: the tickets port yields
/// nothing at all, and `force` is false.
#[tokio::test]
async fn revoking_a_device_awaiting_approval_needs_no_ticket_and_no_force() {
    let repository = Arc::new(FakeRepository::default());
    let coordination = Arc::new(FakeCoordination::configured().with_edge_state("pending_approval"));
    coordination
        .dispatch
        .lock()
        .unwrap()
        .push_back(MembershipCommitOutcome::Committed(MembershipCommitResult::NONE));
    let tickets = Arc::new(FakeTickets::default());
    let readiness = Arc::new(FakeReadiness::default());
    readiness.verified_non_member.store(true, Ordering::SeqCst);

    let outcome = service(repository.clone(), coordination.clone(), tickets.clone(), readiness)
        .revoke_device(RevokeDeviceCommand {
            group_id: "group-1".to_string(),
            device_id: "device-b".to_string(),
            force: false,
        })
        .await
        .expect("denying an approval request must not need a complete-copy handoff");

    // The plain fast path: no handoff, nothing forced, no ticket asked
    // for, and no `--force` audit record (there was no override).
    assert!(outcome.handoffs.is_empty());
    assert!(outcome.forced_group_ids.is_empty());
    assert!(outcome.unknown_scope_operation_id.is_none());
    assert_eq!(*coordination.audit_calls.lock().unwrap(), 0);
    assert!(!repository.calls.lock().unwrap().contains(&RepoCall::Latch("group-1".to_string())));
}

/// The relaxation above is decided on the target's CURRENT state, and
/// only ever on a positive non-active answer: an active member still
/// takes the ticket-bound path and is still refused without one, exactly
/// as before. Anything less than a positive answer (an unreadable
/// listing, an edge the listing does not carry, a coordination plane
/// that reports no state at all -- what `FakeCoordination::default`
/// stands for, and what every other test in this file uses) is covered
/// by `unavailable_ticket_without_force_refuses_with_replica_not_ready`
/// above.
#[tokio::test]
async fn revoking_an_active_member_still_requires_a_ticket() {
    let repository = Arc::new(FakeRepository::default());
    let coordination = Arc::new(FakeCoordination::configured().with_edge_state("active"));
    let tickets = Arc::new(FakeTickets::default());
    tickets.grants.lock().unwrap().push_back(None);
    let readiness = Arc::new(FakeReadiness::default());

    let result = service(repository, coordination.clone(), tickets, readiness)
        .revoke_device(RevokeDeviceCommand {
            group_id: "group-1".to_string(),
            device_id: "device-b".to_string(),
            force: false,
        })
        .await;

    assert!(matches!(result, Err(ReplicaMembershipError::ReplicaNotReady { .. })));
    assert_eq!(*coordination.edge_state_calls.lock().unwrap(), 1);
}

#[tokio::test]
async fn unavailable_ticket_with_force_latches_and_commits_plain() {
    let repository = Arc::new(FakeRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.eager_groups.lock().unwrap().push_back(Ok(vec!["group-1".to_string()]));
    coordination
        .dispatch
        .lock()
        .unwrap()
        .push_back(MembershipCommitOutcome::Committed(MembershipCommitResult::NONE));
    let tickets = Arc::new(FakeTickets::default());
    tickets.grants.lock().unwrap().push_back(None);
    let readiness = Arc::new(FakeReadiness::default());

    let outcome = service(repository.clone(), coordination.clone(), tickets, readiness)
        .revoke_device(RevokeDeviceCommand {
            group_id: "group-1".to_string(),
            device_id: "device-b".to_string(),
            force: true,
        })
        .await
        .unwrap();

    assert_eq!(outcome.forced_group_ids, vec!["group-1".to_string()]);
    assert_eq!(*coordination.audit_calls.lock().unwrap(), 1);
    assert!(repository.calls.lock().unwrap().contains(&RepoCall::Latch("group-1".to_string())));
}

#[tokio::test]
async fn definitely_rejected_ticket_bound_commit_releases_tickets_and_falls_through() {
    let repository = Arc::new(FakeRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.eager_groups.lock().unwrap().push_back(Ok(vec!["group-1".to_string()]));
    coordination
        .dispatch
        .lock()
        .unwrap()
        .push_back(MembershipCommitOutcome::DefinitelyRejected("gone".to_string()));
    coordination
        .dispatch
        .lock()
        .unwrap()
        .push_back(MembershipCommitOutcome::Committed(MembershipCommitResult::NONE));
    let tickets = Arc::new(FakeTickets::default());
    tickets.grants.lock().unwrap().push_back(grant("device-c", "lease-0"));
    let readiness = Arc::new(FakeReadiness::default());

    let outcome = service(repository, coordination, tickets.clone(), readiness)
        .revoke_device(RevokeDeviceCommand {
            group_id: "group-1".to_string(),
            device_id: "device-b".to_string(),
            force: true,
        })
        .await
        .unwrap();

    assert_eq!(tickets.released.lock().unwrap().len(), 1);
    assert_eq!(outcome.forced_group_ids, vec!["group-1".to_string()]);
}

#[tokio::test]
async fn ambiguous_ticket_bound_commit_never_releases_tickets_or_falls_through() {
    let repository = Arc::new(FakeRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.eager_groups.lock().unwrap().push_back(Ok(vec!["group-1".to_string()]));
    coordination
        .dispatch
        .lock()
        .unwrap()
        .push_back(MembershipCommitOutcome::Ambiguous("timeout".to_string()));
    let tickets = Arc::new(FakeTickets::default());
    tickets.grants.lock().unwrap().push_back(grant("device-c", "lease-0"));
    let readiness = Arc::new(FakeReadiness::default());

    let result = service(repository, coordination, tickets.clone(), readiness)
        .revoke_device(RevokeDeviceCommand {
            group_id: "group-1".to_string(),
            device_id: "device-b".to_string(),
            force: true,
        })
        .await;

    assert!(matches!(result, Err(ReplicaMembershipError::RecoveryPending { .. })));
    assert!(tickets.released.lock().unwrap().is_empty());
}

#[tokio::test]
async fn conflict_is_reported_and_never_falls_through() {
    let repository = Arc::new(FakeRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.eager_groups.lock().unwrap().push_back(Ok(vec!["group-1".to_string()]));
    coordination
        .dispatch
        .lock()
        .unwrap()
        .push_back(MembershipCommitOutcome::Conflict("shape mismatch".to_string()));
    let tickets = Arc::new(FakeTickets::default());
    tickets.grants.lock().unwrap().push_back(grant("device-c", "lease-0"));
    let readiness = Arc::new(FakeReadiness::default());

    let result = service(repository, coordination.clone(), tickets, readiness)
        .revoke_device(RevokeDeviceCommand {
            group_id: "group-1".to_string(),
            device_id: "device-b".to_string(),
            force: true,
        })
        .await;

    assert!(matches!(result, Err(ReplicaMembershipError::OperationConflict { .. })));
    assert_eq!(*coordination.dispatch_calls.lock().unwrap(), 1);
}

#[tokio::test]
async fn journal_write_failure_never_falls_through_to_the_coordination_plane() {
    let repository = Arc::new(FakeRepository::default());
    repository.insert_result.lock().unwrap().push_back(Err("disk full".to_string()));
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.eager_groups.lock().unwrap().push_back(Ok(vec!["group-1".to_string()]));
    let tickets = Arc::new(FakeTickets::default());
    tickets.grants.lock().unwrap().push_back(grant("device-c", "lease-0"));
    let readiness = Arc::new(FakeReadiness::default());

    let result = service(repository, coordination.clone(), tickets.clone(), readiness)
        .revoke_device(RevokeDeviceCommand {
            group_id: "group-1".to_string(),
            device_id: "device-b".to_string(),
            force: true,
        })
        .await;

    assert!(matches!(result, Err(ReplicaMembershipError::RecoveryJournalUnavailable { .. })));
    assert_eq!(*coordination.dispatch_calls.lock().unwrap(), 0);
    assert_eq!(tickets.released.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn unverified_scope_forced_removal_surfaces_the_unknown_scope_operation_id() {
    let repository = Arc::new(FakeRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.eager_groups.lock().unwrap().push_back(Err("enumerate failed".to_string()));
    coordination
        .dispatch
        .lock()
        .unwrap()
        .push_back(MembershipCommitOutcome::Committed(MembershipCommitResult::NONE));
    let tickets = Arc::new(FakeTickets::default());
    let readiness = Arc::new(FakeReadiness::default());

    let outcome = service(repository, coordination, tickets, readiness)
        .remove_device(RemoveDeviceCommand { device_id: "device-b".to_string(), force: true })
        .await
        .unwrap();

    assert!(outcome.unknown_scope_operation_id.is_some());
}

#[tokio::test]
async fn unverified_scope_without_force_refuses() {
    let repository = Arc::new(FakeRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.eager_groups.lock().unwrap().push_back(Err("enumerate failed".to_string()));
    let tickets = Arc::new(FakeTickets::default());
    let readiness = Arc::new(FakeReadiness::default());

    let result = service(repository, coordination, tickets, readiness)
        .remove_device(RemoveDeviceCommand { device_id: "device-b".to_string(), force: false })
        .await;

    assert!(matches!(result, Err(ReplicaMembershipError::ReplicaNotReady { .. })));
}

#[tokio::test]
async fn self_removal_uses_the_readiness_port_not_tickets() {
    let repository = Arc::new(FakeRepository::default().with_link(link("group-1")));
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.eager_groups.lock().unwrap().push_back(Ok(vec!["group-1".to_string()]));
    let tickets = Arc::new(FakeTickets::default());
    let readiness = Arc::new(FakeReadiness::default());
    readiness.ready.lock().unwrap().push_back(false);

    let result = service(repository, coordination, tickets.clone(), readiness)
        .remove_device(RemoveDeviceCommand { device_id: "device-a".to_string(), force: false })
        .await;

    assert!(matches!(result, Err(ReplicaMembershipError::ReplicaNotReady { .. })));
    assert!(tickets.grants.lock().unwrap().is_empty());
}

/// A coordination-plane claim that the target's edge is not active is only
/// advisory: when this device's own verified policy still lists the target
/// as a member, the ticket requirement stays. Without a ticket and without
/// `--force` the revoke is refused and nothing is sent.
#[tokio::test]
async fn non_active_edge_claim_is_ignored_when_verified_policy_lists_the_target() {
    let repository = Arc::new(FakeRepository::default());
    let coordination = Arc::new(FakeCoordination::configured().with_edge_state("pending_approval"));
    let tickets = Arc::new(FakeTickets::default());
    tickets.grants.lock().unwrap().push_back(None);
    let readiness = Arc::new(FakeReadiness::default());

    let result = service(repository, coordination.clone(), tickets, readiness)
        .revoke_device(RevokeDeviceCommand {
            group_id: "group-1".to_string(),
            device_id: "device-b".to_string(),
            force: false,
        })
        .await;

    assert!(matches!(result, Err(ReplicaMembershipError::ReplicaNotReady { .. })));
    assert_eq!(*coordination.dispatch_calls.lock().unwrap(), 0);
}

/// Self-removal checks every group this device stores as an eager full
/// replica, not only the groups the coordination plane reports: a server
/// answer that omits a locally eager group must not skip its readiness check.
#[tokio::test]
async fn self_removal_checks_locally_eager_groups_the_server_omits() {
    let repository = Arc::new(FakeRepository::default().with_link(link("group-1")));
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.eager_groups.lock().unwrap().push_back(Ok(Vec::new()));
    coordination
        .dispatch
        .lock()
        .unwrap()
        .push_back(MembershipCommitOutcome::Committed(MembershipCommitResult::NONE));
    let tickets = Arc::new(FakeTickets::default());
    let readiness = Arc::new(FakeReadiness::default());
    readiness.ready.lock().unwrap().push_back(false);

    let result = service(repository, coordination.clone(), tickets, readiness)
        .remove_device(RemoveDeviceCommand { device_id: "device-a".to_string(), force: false })
        .await;

    match result {
        Err(ReplicaMembershipError::ReplicaNotReady { group_ids }) => {
            assert_eq!(group_ids, vec!["group-1".to_string()]);
        }
        other => panic!("expected ReplicaNotReady, got {other:?}"),
    }
    assert_eq!(*coordination.dispatch_calls.lock().unwrap(), 0);
}

/// The union only adds groups this device really stores eagerly: an
/// on-demand or orphaned link is not at risk, so self-removal still commits.
#[tokio::test]
async fn self_removal_ignores_local_links_that_are_not_eager_replicas() {
    let mut on_demand = link("group-1");
    on_demand.materialization_policy = MaterializationPolicy::OnDemand;
    let mut orphaned = link("group-2");
    orphaned.orphaned = true;
    let repository = Arc::new(FakeRepository::default().with_link(on_demand).with_link(orphaned));
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.eager_groups.lock().unwrap().push_back(Ok(Vec::new()));
    coordination
        .dispatch
        .lock()
        .unwrap()
        .push_back(MembershipCommitOutcome::Committed(MembershipCommitResult::NONE));

    let outcome = service(
        repository,
        coordination,
        Arc::new(FakeTickets::default()),
        Arc::new(FakeReadiness::default()),
    )
    .remove_device(RemoveDeviceCommand { device_id: "device-a".to_string(), force: false })
    .await
    .unwrap();

    assert!(outcome.forced_group_ids.is_empty());
}

#[tokio::test]
async fn revoke_edge_resolves_then_runs_the_same_guarded_path() {
    let repository = Arc::new(FakeRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination
        .resolve_edge_result
        .lock()
        .unwrap()
        .push_back(Ok(Some(("group-1".to_string(), "device-b".to_string()))));
    coordination.eager_groups.lock().unwrap().push_back(Ok(vec!["group-1".to_string()]));
    coordination
        .dispatch
        .lock()
        .unwrap()
        .push_back(MembershipCommitOutcome::Committed(MembershipCommitResult::NONE));
    let tickets = Arc::new(FakeTickets::default());
    tickets.grants.lock().unwrap().push_back(None);
    let readiness = Arc::new(FakeReadiness::default());

    let result = service(repository, coordination, tickets, readiness)
        .revoke_edge("edge-1".to_string(), true)
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn revoke_edge_already_gone_reports_target_not_found() {
    let repository = Arc::new(FakeRepository::default());
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.resolve_edge_result.lock().unwrap().push_back(Ok(None));
    let tickets = Arc::new(FakeTickets::default());
    let readiness = Arc::new(FakeReadiness::default());

    let result = service(repository, coordination, tickets, readiness)
        .revoke_edge("edge-1".to_string(), true)
        .await;

    assert!(matches!(result, Err(ReplicaMembershipError::TargetNotFound)));
}

// ===== reconcile_unknown_scope =====

// ===== engine-side evidence for another device's removal =====

fn engine_sees_eager(readiness: &FakeReadiness, groups: &[&str]) {
    *readiness.eager_evidence.lock().unwrap() = groups.iter().map(|g| g.to_string()).collect();
}

/// The coordination plane's at-risk list is advisory: a device this engine's
/// own netmap/peer evidence shows holding a group eagerly is at risk even
/// when the server's list omits it, so the removal needs a ticket.
#[tokio::test]
async fn removing_another_device_counts_groups_the_engine_sees_it_hold() {
    let repository = Arc::new(FakeRepository::default().with_link(link("group-1")));
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.eager_groups.lock().unwrap().push_back(Ok(Vec::new()));
    coordination
        .dispatch
        .lock()
        .unwrap()
        .push_back(MembershipCommitOutcome::Committed(MembershipCommitResult::NONE));
    let tickets = Arc::new(FakeTickets::default());
    tickets.grants.lock().unwrap().push_back(None);
    let readiness = Arc::new(FakeReadiness::default());
    engine_sees_eager(&readiness, &["group-1"]);

    let result = service(repository, coordination.clone(), tickets, readiness)
        .remove_device(RemoveDeviceCommand { device_id: "device-b".to_string(), force: false })
        .await;

    match result {
        Err(ReplicaMembershipError::ReplicaNotReady { group_ids }) => {
            assert_eq!(group_ids, vec!["group-1".to_string()]);
        }
        other => panic!("expected ReplicaNotReady, got {other:?}"),
    }
    assert_eq!(*coordination.dispatch_calls.lock().unwrap(), 0);
}

/// A scoped revoke the server calls "not active" (and the verified policy
/// agrees) still needs a ticket when the engine's own evidence shows the
/// target holding that group.
#[tokio::test]
async fn engine_evidence_keeps_the_ticket_requirement_on_a_scoped_revoke() {
    let repository = Arc::new(FakeRepository::default());
    let coordination = Arc::new(FakeCoordination::configured().with_edge_state("pending_approval"));
    coordination
        .dispatch
        .lock()
        .unwrap()
        .push_back(MembershipCommitOutcome::Committed(MembershipCommitResult::NONE));
    let tickets = Arc::new(FakeTickets::default());
    tickets.grants.lock().unwrap().push_back(None);
    let readiness = Arc::new(FakeReadiness::default());
    readiness.verified_non_member.store(true, Ordering::SeqCst);
    engine_sees_eager(&readiness, &["group-1"]);

    let result = service(repository, coordination.clone(), tickets, readiness)
        .revoke_device(RevokeDeviceCommand {
            group_id: "group-1".to_string(),
            device_id: "device-b".to_string(),
            force: false,
        })
        .await;

    assert!(matches!(result, Err(ReplicaMembershipError::ReplicaNotReady { .. })));
    assert_eq!(*coordination.dispatch_calls.lock().unwrap(), 0);
}

/// Evidence about a group outside a scoped revoke does not widen it.
#[tokio::test]
async fn engine_evidence_outside_the_scoped_group_is_ignored() {
    let repository = Arc::new(FakeRepository::default());
    let coordination = Arc::new(FakeCoordination::configured().with_edge_state("pending_approval"));
    coordination
        .dispatch
        .lock()
        .unwrap()
        .push_back(MembershipCommitOutcome::Committed(MembershipCommitResult::NONE));
    let readiness = Arc::new(FakeReadiness::default());
    readiness.verified_non_member.store(true, Ordering::SeqCst);
    engine_sees_eager(&readiness, &["group-2"]);

    let outcome = service(repository, coordination, Arc::new(FakeTickets::default()), readiness)
        .revoke_device(RevokeDeviceCommand {
            group_id: "group-1".to_string(),
            device_id: "device-b".to_string(),
            force: false,
        })
        .await
        .unwrap();

    assert!(outcome.forced_group_ids.is_empty());
}

/// When the server cannot enumerate the target's groups, the journal row
/// for the unknown-scope removal already records the local eager links the
/// engine's netmap shows the target sharing, so the later latch does not
/// depend on the server's list alone.
#[tokio::test]
async fn unknown_scope_removal_records_local_eager_links_the_target_shares() {
    let mut on_demand = link("group-3");
    on_demand.materialization_policy = MaterializationPolicy::OnDemand;
    let repository = Arc::new(
        FakeRepository::default()
            .with_link(link("group-1"))
            .with_link(link("group-2"))
            .with_link(on_demand),
    );
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.eager_groups.lock().unwrap().push_back(Err("worker down".to_string()));
    coordination
        .dispatch
        .lock()
        .unwrap()
        .push_back(MembershipCommitOutcome::Committed(MembershipCommitResult::NONE));
    let readiness = Arc::new(FakeReadiness::default());
    *readiness.shared_with_target.lock().unwrap() =
        vec!["group-1".to_string(), "group-3".to_string(), "group-9".to_string()];

    service(repository.clone(), coordination, Arc::new(FakeTickets::default()), readiness)
        .remove_device(RemoveDeviceCommand { device_id: "device-b".to_string(), force: true })
        .await
        .unwrap();

    let operations = repository.operations.lock().unwrap();
    let row = operations.values().next().expect("unknown-scope row stays open");
    assert_eq!(row.durability_scope, MembershipDurabilityScope::Unknown);
    assert_eq!(row.latch_group_ids, vec!["group-1".to_string()]);
}

/// Reconciliation latches the server's affected list AND the groups the
/// engine recorded when the removal was issued.
#[tokio::test]
async fn unknown_scope_reconcile_latches_the_union_of_server_and_engine_groups() {
    let mut marker = old_operation(
        "op-1",
        MembershipOperationState::Prepared,
        MembershipDurabilityScope::Unknown,
    );
    marker.latch_group_ids = vec!["group-3".to_string()];
    let repository = Arc::new(FakeRepository::default().with_operation(marker.clone()));
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.query.lock().unwrap().push_back(Ok(MembershipOperationLookup::Found(Box::new(
        MembershipOperationRecord {
            status: MembershipRemoteStatus::Committed,
            action: "removeDevice".to_string(),
            removed_device_id: "device-b".to_string(),
            request_fingerprint: "fp".to_string(),
            request:
                super::super::membership_operation_identity::expected_membership_remote_request(
                    &marker,
                ),
            result: Some(MembershipRemoteResult {
                affected_group_ids: Some(vec!["group-1".to_string()]),
                target_device_id: None,
                membership_generation: None,
                lease_id: None,
            }),
            rejection_code: None,
            rejection_detail: None,
        },
    ))));

    service(
        repository.clone(),
        coordination,
        Arc::new(FakeTickets::default()),
        Arc::new(FakeReadiness::default()),
    )
    .reconcile_unknown_scope()
    .await;

    let calls = repository.calls.lock().unwrap();
    assert!(calls.contains(&RepoCall::Latch("group-1".to_string())));
    assert!(calls.contains(&RepoCall::Latch("group-3".to_string())));
    assert!(calls.contains(&RepoCall::Discard("op-1".to_string())));
}

#[tokio::test]
async fn unknown_scope_found_committed_latches_real_groups_and_discards() {
    let repository = Arc::new(FakeRepository::default().with_operation(old_operation(
        "op-1",
        MembershipOperationState::Prepared,
        MembershipDurabilityScope::Unknown,
    )));
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.query.lock().unwrap().push_back(Ok(MembershipOperationLookup::Found(Box::new(
        MembershipOperationRecord {
            status: MembershipRemoteStatus::Committed,
            action: "removeDevice".to_string(),
            removed_device_id: "device-b".to_string(),
            request_fingerprint: "fp".to_string(),
            request:
                super::super::membership_operation_identity::expected_membership_remote_request(
                    &old_operation(
                        "op-1",
                        MembershipOperationState::Prepared,
                        MembershipDurabilityScope::Unknown,
                    ),
                ),
            result: Some(MembershipRemoteResult {
                affected_group_ids: Some(vec!["group-1".to_string(), "group-2".to_string()]),
                target_device_id: None,
                membership_generation: None,
                lease_id: None,
            }),
            rejection_code: None,
            rejection_detail: None,
        },
    ))));
    let tickets = Arc::new(FakeTickets::default());
    let readiness = Arc::new(FakeReadiness::default());

    service(repository.clone(), coordination, tickets, readiness).reconcile_unknown_scope().await;

    let calls = repository.calls.lock().unwrap();
    assert!(calls.contains(&RepoCall::Latch("group-1".to_string())));
    assert!(calls.contains(&RepoCall::Latch("group-2".to_string())));
    assert!(calls.contains(&RepoCall::Discard("op-1".to_string())));
}

#[tokio::test]
async fn unknown_scope_not_found_resends_and_commits() {
    let repository = Arc::new(FakeRepository::default().with_operation(old_operation(
        "op-1",
        MembershipOperationState::Prepared,
        MembershipDurabilityScope::Unknown,
    )));
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.query.lock().unwrap().push_back(Ok(MembershipOperationLookup::NotFound));
    coordination
        .dispatch
        .lock()
        .unwrap()
        .push_back(MembershipCommitOutcome::Committed(MembershipCommitResult::NONE));
    let tickets = Arc::new(FakeTickets::default());
    let readiness = Arc::new(FakeReadiness::default());

    service(repository.clone(), coordination.clone(), tickets, readiness)
        .reconcile_unknown_scope()
        .await;

    assert_eq!(*coordination.dispatch_calls.lock().unwrap(), 1);
    // Committed-via-resend leaves the row for the NEXT sweep's
    // Found+Committed arm to resolve the real scope from -- never
    // settled/discarded here directly.
    assert!(!repository.calls.lock().unwrap().contains(&RepoCall::Discard("op-1".to_string())));
}

#[tokio::test]
async fn unknown_scope_row_too_young_is_left_for_the_next_sweep() {
    let mut op = old_operation(
        "op-1",
        MembershipOperationState::Prepared,
        MembershipDurabilityScope::Unknown,
    );
    op.created_at_unix = now_unix();
    let repository = Arc::new(FakeRepository::default().with_operation(op));
    let coordination = Arc::new(FakeCoordination::configured());
    let tickets = Arc::new(FakeTickets::default());
    let readiness = Arc::new(FakeReadiness::default());

    service(repository.clone(), coordination.clone(), tickets, readiness)
        .reconcile_unknown_scope()
        .await;

    assert_eq!(*coordination.dispatch_calls.lock().unwrap(), 0);
    assert!(repository.calls.lock().unwrap().is_empty());
}

// ===== reconcile_ambiguous =====

#[tokio::test]
async fn ambiguous_found_committed_settles() {
    let op = old_operation(
        "op-1",
        MembershipOperationState::Ambiguous,
        MembershipDurabilityScope::Known,
    );
    let repository = Arc::new(FakeRepository::default().with_operation(op.clone()));
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.query.lock().unwrap().push_back(Ok(MembershipOperationLookup::Found(
        Box::new(MembershipOperationRecord {
            status: MembershipRemoteStatus::Committed,
            action: "removeDevice".to_string(),
            removed_device_id: "device-b".to_string(),
            request_fingerprint: "fp".to_string(),
            request:
                super::super::membership_operation_identity::expected_membership_remote_request(
                    &op,
                ),
            result: None,
            rejection_code: None,
            rejection_detail: None,
        }),
    )));
    let tickets = Arc::new(FakeTickets::default());
    let readiness = Arc::new(FakeReadiness::default());

    service(repository.clone(), coordination, tickets, readiness).reconcile_ambiguous().await;

    assert!(repository.calls.lock().unwrap().contains(&RepoCall::Settle("op-1".to_string())));
}

#[tokio::test]
async fn ambiguous_found_definitely_rejected_releases_tickets_and_settles() {
    let mut op = old_operation(
        "op-1",
        MembershipOperationState::Ambiguous,
        MembershipDurabilityScope::Known,
    );
    op.commit_mode = MembershipCommitMode::GuardedRevoke;
    op.group_ids = vec!["group-1".to_string()];
    op.target_device_ids = vec!["device-c".to_string()];
    op.lease_ids = vec![Some("lease-1".to_string())];
    let repository = Arc::new(FakeRepository::default().with_operation(op.clone()));
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.query.lock().unwrap().push_back(Ok(MembershipOperationLookup::Found(
        Box::new(MembershipOperationRecord {
            status: MembershipRemoteStatus::DefinitelyRejected,
            action: "revoke".to_string(),
            removed_device_id: "device-b".to_string(),
            request_fingerprint: "fp".to_string(),
            request:
                super::super::membership_operation_identity::expected_membership_remote_request(
                    &op,
                ),
            result: None,
            rejection_code: None,
            rejection_detail: None,
        }),
    )));
    let tickets = Arc::new(FakeTickets::default());
    let readiness = Arc::new(FakeReadiness::default());

    service(repository.clone(), coordination, tickets.clone(), readiness)
        .reconcile_ambiguous()
        .await;

    assert_eq!(*tickets.released.lock().unwrap(), vec!["group-1".to_string()]);
    assert!(repository.calls.lock().unwrap().contains(&RepoCall::Settle("op-1".to_string())));
}

#[tokio::test]
async fn identity_mismatch_blocks_recovery_instead_of_settling() {
    let op = old_operation(
        "op-1",
        MembershipOperationState::Ambiguous,
        MembershipDurabilityScope::Known,
    );
    let repository = Arc::new(FakeRepository::default().with_operation(op.clone()));
    let coordination = Arc::new(FakeCoordination::configured());
    coordination.query.lock().unwrap().push_back(Ok(MembershipOperationLookup::Found(Box::new(
        MembershipOperationRecord {
            status: MembershipRemoteStatus::Committed,
            action: "removeDevice".to_string(),
            removed_device_id: "device-b".to_string(),
            request_fingerprint: "fp".to_string(),
            request: MembershipRemoteRequest {
                action: "revoke".to_string(),
                removed_device_id: "device-other".to_string(),
                mode: "guarded".to_string(),
                groups: Vec::new(),
            },
            result: None,
            rejection_code: None,
            rejection_detail: None,
        },
    ))));
    let tickets = Arc::new(FakeTickets::default());
    let readiness = Arc::new(FakeReadiness::default());

    service(repository.clone(), coordination, tickets, readiness).reconcile_ambiguous().await;

    assert!(repository
        .calls
        .lock()
        .unwrap()
        .contains(&RepoCall::MarkRecoveryBlocked("op-1".to_string())));
    assert!(!repository.calls.lock().unwrap().contains(&RepoCall::Settle("op-1".to_string())));
}

#[tokio::test]
async fn local_settlement_pending_retries_the_latch_without_a_remote_call() {
    let op = old_operation(
        "op-1",
        MembershipOperationState::LocalSettlementPending,
        MembershipDurabilityScope::Known,
    );
    let mut op = op;
    op.latch_group_ids = vec!["group-1".to_string()];
    let repository = Arc::new(FakeRepository::default().with_operation(op));
    let coordination = Arc::new(FakeCoordination::configured());
    let tickets = Arc::new(FakeTickets::default());
    let readiness = Arc::new(FakeReadiness::default());

    service(repository.clone(), coordination.clone(), tickets, readiness)
        .reconcile_ambiguous()
        .await;

    assert_eq!(*coordination.dispatch_calls.lock().unwrap(), 0);
    let calls = repository.calls.lock().unwrap();
    assert!(calls.contains(&RepoCall::Latch("group-1".to_string())));
    assert!(calls.contains(&RepoCall::Settle("op-1".to_string())));
}

#[tokio::test]
async fn a_malformed_row_is_recovery_blocked_and_never_resent() {
    let repository = Arc::new(FakeRepository::default());
    repository.invalid.lock().unwrap().push(InvalidMembershipOperation {
        operation_id: "op-bad".to_string(),
        raw_state: Some("unknown".to_string()),
        detail: "unrecognized state".to_string(),
    });
    let coordination = Arc::new(FakeCoordination::configured());
    let tickets = Arc::new(FakeTickets::default());
    let readiness = Arc::new(FakeReadiness::default());

    service(repository.clone(), coordination.clone(), tickets, readiness)
        .reconcile_ambiguous()
        .await;

    assert_eq!(*coordination.dispatch_calls.lock().unwrap(), 0);
    assert!(repository
        .calls
        .lock()
        .unwrap()
        .contains(&RepoCall::MarkRecoveryBlocked("op-bad".to_string())));
}
