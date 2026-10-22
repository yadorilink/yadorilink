#![cfg(test)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::Notify;
use yadorilink_replica_domain::session_state::EnrollmentKind;
use yadorilink_replica_domain::session_state::{
    EnrollmentOperation, EnrollmentOperationState, MembershipCommitMode, MembershipDurabilityScope,
    MembershipOperationAction, MembershipOperationState, RoleLossAction, RoleLossOperationParams,
};

use super::*;
use crate::coordination_client::{
    EnrollmentOperationRecord, EnrollmentRemoteRequest, EnrollmentRemoteStatus,
    MembershipOperationRecord, MembershipRemoteRequest, MembershipRemoteRequestGroup,
    MembershipRemoteStatus, RemoteEvidenceErrorCategory, RoleLossOperationRecord,
};

fn enrollment_key(operation_id: &str) -> RecoveryOperationKey {
    RecoveryOperationKey {
        domain: RecoveryDomain::Enrollment,
        operation_id: operation_id.to_string(),
    }
}
fn membership_key(operation_id: &str) -> RecoveryOperationKey {
    RecoveryOperationKey {
        domain: RecoveryDomain::Membership,
        operation_id: operation_id.to_string(),
    }
}
fn role_loss_key(operation_id: &str) -> RecoveryOperationKey {
    RecoveryOperationKey {
        domain: RecoveryDomain::RoleLoss,
        operation_id: operation_id.to_string(),
    }
}

fn insert_enrollment_op(state: &ReplicaCoordinator, operation_id: &str) {
    state
        .enrollment_repository()
        .try_insert_enrollment_operation(&EnrollmentOperation {
            operation_id: operation_id.to_string(),
            kind: EnrollmentKind::Create,
            group_id: Some("group-1".to_string()),
            group_name: Some("photos".to_string()),
            device_id: "device-a".to_string(),
            local_path: "/home/alice/Photos".to_string(),
            storage_mode: "eager".to_string(),
            state: EnrollmentOperationState::ActivationPending,
            last_error: None,
            attempts: 0,
            created_at_unix: 1,
            updated_at_unix: 1,
        })
        .unwrap();
}

fn insert_membership_op(state: &ReplicaCoordinator, operation_id: &str) {
    state
        .membership_operation_repository()
        .try_insert_membership_operation(
            operation_id,
            MembershipOperationAction::Revoke,
            MembershipCommitMode::PlainRevoke,
            "device-b",
            &["group-1".to_string()],
            &[],
            &[],
            MembershipOperationState::Prepared,
            MembershipDurabilityScope::Known,
            &[],
            None,
            1,
        )
        .unwrap();
}

fn insert_role_loss_op(state: &ReplicaCoordinator, operation_id: &str) {
    state
        .role_loss_operation_repository()
        .insert_role_loss_operation(
            operation_id,
            "group-1",
            RoleLossOperationParams {
                source_device_id: "device-c",
                target_device_id: "device-d",
                lease_id: "lease-fixture",
                action: RoleLossAction::Demote,
                local_path: Some("/home/alice/Photos"),
                now_unix: 1,
            },
        )
        .unwrap();
}

fn enrollment_found(status: EnrollmentRemoteStatus) -> RemoteEvidence<EnrollmentOperationRecord> {
    RemoteEvidence::Found(EnrollmentOperationRecord {
        status,
        request_fingerprint: "fp".to_string(),
        request: EnrollmentRemoteRequest::Create {
            group_name: "photos".to_string(),
            device_id: "device-a".to_string(),
            storage_mode: "eager".to_string(),
        },
        result_group_id: Some("group-1".to_string()),
    })
}

fn membership_found() -> RemoteEvidence<MembershipOperationRecord> {
    RemoteEvidence::Found(MembershipOperationRecord {
        status: MembershipRemoteStatus::Committed,
        action: "revoke".to_string(),
        removed_device_id: "device-b".to_string(),
        request_fingerprint: "fp".to_string(),
        request: MembershipRemoteRequest {
            action: "revoke".to_string(),
            removed_device_id: "device-b".to_string(),
            mode: "guarded".to_string(),
            groups: vec![MembershipRemoteRequestGroup {
                group_id: "group-1".to_string(),
                target_device_id: None,
                lease_id: None,
            }],
        },
        result: None,
        rejection_code: None,
        rejection_detail: None,
    })
}

fn role_loss_found() -> RemoteEvidence<RoleLossOperationRecord> {
    RemoteEvidence::Found(RoleLossOperationRecord {
        group_id: "group-1".to_string(),
        source_device_id: "device-c".to_string(),
        target_device_id: "device-d".to_string(),
        lease_id: None,
        action: "demote".to_string(),
        membership_generation: 4,
        committed_at_unix: 1,
    })
}

/// A [`RecoveryEvidenceSource`] entirely under test control: counts
/// every lookup call, and -- when armed with a barrier -- notifies a
/// waiting test task the instant a lookup begins, then blocks until
/// that task releases it. This is what lets a race test mutate the
/// database from a SEPARATE task while `diagnose_stable`'s own remote
/// lookup is still in flight, without adding any mutation capability
/// to the fake itself (it still only implements the 3 read-only
/// methods `RecoveryEvidenceSource` has).
struct FakeEvidenceSource {
    enrollment: RemoteEvidence<EnrollmentOperationRecord>,
    membership: RemoteEvidence<MembershipOperationRecord>,
    role_loss: RemoteEvidence<RoleLossOperationRecord>,
    lookup_count: Arc<AtomicUsize>,
    barrier: Option<(Arc<Notify>, Arc<Notify>)>,
}

impl FakeEvidenceSource {
    fn new(
        enrollment: RemoteEvidence<EnrollmentOperationRecord>,
        membership: RemoteEvidence<MembershipOperationRecord>,
        role_loss: RemoteEvidence<RoleLossOperationRecord>,
    ) -> (Self, Arc<AtomicUsize>) {
        let lookup_count = Arc::new(AtomicUsize::new(0));
        (
            Self {
                enrollment,
                membership,
                role_loss,
                lookup_count: lookup_count.clone(),
                barrier: None,
            },
            lookup_count,
        )
    }

    fn with_barrier(mut self, entered: Arc<Notify>, proceed: Arc<Notify>) -> Self {
        self.barrier = Some((entered, proceed));
        self
    }

    async fn record_and_wait(&self) {
        self.lookup_count.fetch_add(1, Ordering::SeqCst);
        if let Some((entered, proceed)) = &self.barrier {
            entered.notify_one();
            proceed.notified().await;
        }
    }
}

impl RecoveryEvidenceSource for FakeEvidenceSource {
    async fn lookup_enrollment(
        &self,
        _key: &RecoveryOperationKey,
    ) -> RemoteEvidence<EnrollmentOperationRecord> {
        self.record_and_wait().await;
        self.enrollment.clone()
    }

    async fn lookup_membership(
        &self,
        _key: &RecoveryOperationKey,
    ) -> RemoteEvidence<MembershipOperationRecord> {
        self.record_and_wait().await;
        self.membership.clone()
    }

    async fn lookup_role_loss(
        &self,
        _key: &RecoveryOperationKey,
    ) -> RemoteEvidence<RoleLossOperationRecord> {
        self.record_and_wait().await;
        self.role_loss.clone()
    }
}

fn no_barrier_source() -> (FakeEvidenceSource, Arc<AtomicUsize>) {
    FakeEvidenceSource::new(
        enrollment_found(EnrollmentRemoteStatus::Active),
        membership_found(),
        role_loss_found(),
    )
}

// ===== Stable path =====

#[tokio::test]
async fn enrollment_stable_path_diagnoses() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    insert_enrollment_op(&state, "op-1");
    let (source, count) = no_barrier_source();
    let key = enrollment_key("op-1");

    let outcome = diagnose_stable(&state, &source, &key).await.unwrap();
    let StableDiagnosisOutcome::Diagnosed { operation, diagnosis, .. } = outcome else {
        panic!("expected Diagnosed");
    };
    assert_eq!(operation.operation_id, "op-1");
    assert_eq!(operation.operation_id, diagnosis.key().operation_id);
    assert_eq!(operation.domain, diagnosis.key().domain);
    assert_eq!(diagnosis.key(), &key);
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn membership_stable_path_diagnoses() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    insert_membership_op(&state, "op-1");
    let (source, count) = no_barrier_source();
    let key = membership_key("op-1");

    let outcome = diagnose_stable(&state, &source, &key).await.unwrap();
    assert!(matches!(outcome, StableDiagnosisOutcome::Diagnosed { .. }));
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn role_loss_stable_path_diagnoses() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    insert_role_loss_op(&state, "op-1");
    let (source, count) = no_barrier_source();
    let key = role_loss_key("op-1");

    let outcome = diagnose_stable(&state, &source, &key).await.unwrap();
    assert!(matches!(outcome, StableDiagnosisOutcome::Diagnosed { .. }));
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn record_not_found_remote_evidence_still_diagnoses() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    insert_enrollment_op(&state, "op-1");
    let (source, _count) = FakeEvidenceSource::new(
        RemoteEvidence::RecordNotFound,
        membership_found(),
        role_loss_found(),
    );
    let key = enrollment_key("op-1");

    let outcome = diagnose_stable(&state, &source, &key).await.unwrap();
    assert!(matches!(outcome, StableDiagnosisOutcome::Diagnosed { .. }));
}

#[tokio::test]
async fn unavailable_remote_evidence_still_diagnoses() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    insert_enrollment_op(&state, "op-1");
    let (source, _count) = FakeEvidenceSource::new(
        RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::Network },
        membership_found(),
        role_loss_found(),
    );
    let key = enrollment_key("op-1");

    let outcome = diagnose_stable(&state, &source, &key).await.unwrap();
    assert!(matches!(outcome, StableDiagnosisOutcome::Diagnosed { .. }));
}

// ===== No remote lookup =====

#[tokio::test]
async fn operation_not_found_never_looks_up_remote() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let (source, count) = no_barrier_source();
    let key = enrollment_key("does-not-exist");

    let outcome = diagnose_stable(&state, &source, &key).await.unwrap();
    assert!(matches!(outcome, StableDiagnosisOutcome::OperationNotFound { .. }));
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn invalid_operation_never_looks_up_remote() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    // The mechanism under test -- `InvalidOperation` short-circuits
    // before any remote lookup -- is domain-agnostic, so membership
    // exercises it just as well as enrollment would.
    state.plant_malformed_membership_operation_for_test("op-bad").unwrap();
    let (source, count) = no_barrier_source();
    let key = membership_key("op-bad");

    let outcome = diagnose_stable(&state, &source, &key).await.unwrap();
    assert!(matches!(outcome, StableDiagnosisOutcome::InvalidOperation { .. }));
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

// A genuine SQLite read failure propagating as `Err` before any remote
// lookup runs is structurally guaranteed here: `diagnose_stable`'s
// first statement is `sync_state.recovery_local_snapshot(key)?`, and
// that `?` returns before `lookup_for_domain` is ever reached.

// ===== Snapshot race =====

/// Runs `diagnose_stable` on a background task, waits until its remote
/// lookup has actually started, runs `mutate` against the SAME
/// database from this task, then releases the lookup and returns the
/// outcome -- the shared harness every race test below uses.
async fn run_race(
    state: Arc<ReplicaCoordinator>,
    key: RecoveryOperationKey,
    source: FakeEvidenceSource,
    entered: Arc<Notify>,
    proceed: Arc<Notify>,
    mutate: impl FnOnce(&ReplicaCoordinator) + Send + 'static,
) -> StableDiagnosisOutcome {
    // The spawned task and `mutate` below both operate on the SAME
    // `Arc<ReplicaCoordinator>` (a plain clone, not a second instance
    // built against a shared database) -- `state` itself is the single
    // `ReplicaCoordinator` handle this module needs, rather than a
    // `SyncState` this helper would have to
    // separately bridge into a `ReplicaCoordinator` for `diagnose_stable`.
    let task_state = state.clone();
    let task_key = key.clone();
    let handle =
        tokio::spawn(async move { diagnose_stable(&task_state, &source, &task_key).await });
    entered.notified().await;
    mutate(&state);
    proceed.notify_one();
    handle.await.unwrap().unwrap()
}

fn barrier_source(
    enrollment: RemoteEvidence<EnrollmentOperationRecord>,
    membership: RemoteEvidence<MembershipOperationRecord>,
    role_loss: RemoteEvidence<RoleLossOperationRecord>,
) -> (FakeEvidenceSource, Arc<Notify>, Arc<Notify>, Arc<AtomicUsize>) {
    let (source, count) = FakeEvidenceSource::new(enrollment, membership, role_loss);
    let entered = Arc::new(Notify::new());
    let proceed = Arc::new(Notify::new());
    let source = source.with_barrier(entered.clone(), proceed.clone());
    (source, entered, proceed, count)
}

#[tokio::test]
async fn race_operation_state_change_is_detected() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    insert_enrollment_op(&state, "op-1");
    let (source, entered, proceed, count) = barrier_source(
        enrollment_found(EnrollmentRemoteStatus::Active),
        membership_found(),
        role_loss_found(),
    );
    let key = enrollment_key("op-1");

    let outcome = run_race(state.clone(), key, source, entered, proceed, |state| {
        state
            .enrollment_repository()
            .mark_enrollment_operation_state(
                "op-1",
                EnrollmentOperationState::CancelPending,
                None,
                2,
            )
            .unwrap();
    })
    .await;

    assert!(matches!(outcome, StableDiagnosisOutcome::LocalEvidenceChanged { .. }));
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// `state`/`updated_at_unix` are held FIXED (the same `now_unix` as the
/// original row) while `attempts` changes underneath -- proving the
/// comparison is a full evidence equality check, not a `state`/
/// `updated_at_unix`-only shortcut.
#[tokio::test]
async fn race_attempts_only_change_with_state_and_updated_at_held_fixed_is_detected() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    insert_enrollment_op(&state, "op-1");
    let (source, entered, proceed, _count) = barrier_source(
        enrollment_found(EnrollmentRemoteStatus::Active),
        membership_found(),
        role_loss_found(),
    );
    let key = enrollment_key("op-1");

    let outcome = run_race(state.clone(), key, source, entered, proceed, |state| {
        // Same `now_unix` (1) as the original row's own `updated_at_unix`
        // -- only `attempts` actually changes.
        state.enrollment_repository().increment_enrollment_operation_attempts("op-1", 1).unwrap();
    })
    .await;

    assert!(matches!(outcome, StableDiagnosisOutcome::LocalEvidenceChanged { .. }));
}

#[tokio::test]
async fn race_enrollment_link_change_is_detected() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    insert_enrollment_op(&state, "op-1");
    let (source, entered, proceed, _count) = barrier_source(
        enrollment_found(EnrollmentRemoteStatus::Active),
        membership_found(),
        role_loss_found(),
    );
    let key = enrollment_key("op-1");

    let outcome = run_race(state.clone(), key, source, entered, proceed, |state| {
        state.link_repository().add_link("/home/alice/Photos", "group-1").unwrap();
    })
    .await;

    assert!(matches!(outcome, StableDiagnosisOutcome::LocalEvidenceChanged { .. }));
}

#[tokio::test]
async fn race_enrollment_marker_change_is_detected() {
    use yadorilink_replica_domain::session_state::PendingEnrollment;

    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    insert_enrollment_op(&state, "op-1");
    let (source, entered, proceed, _count) = barrier_source(
        enrollment_found(EnrollmentRemoteStatus::Active),
        membership_found(),
        role_loss_found(),
    );
    let key = enrollment_key("op-1");

    let outcome = run_race(state.clone(), key, source, entered, proceed, |state| {
        state
            .enrollment_repository()
            .add_link_with_pending_enrollment(
                "/home/alice/Photos",
                "group-1",
                &PendingEnrollment {
                    operation_id: "op-1".to_string(),
                    kind: EnrollmentKind::Create,
                    group_id: "group-1".to_string(),
                    device_id: "device-a".to_string(),
                    local_path: "/home/alice/Photos".to_string(),
                },
            )
            .unwrap();
    })
    .await;

    assert!(matches!(outcome, StableDiagnosisOutcome::LocalEvidenceChanged { .. }));
}

#[tokio::test]
async fn race_membership_latch_change_is_detected() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    insert_membership_op(&state, "op-1");
    let (source, entered, proceed, _count) = barrier_source(
        enrollment_found(EnrollmentRemoteStatus::Active),
        membership_found(),
        role_loss_found(),
    );
    let key = membership_key("op-1");

    let outcome = run_race(state.clone(), key, source, entered, proceed, |state| {
        state.role_loss_operation_repository().latch_group_durability_unknown("group-1").unwrap();
    })
    .await;

    assert!(matches!(outcome, StableDiagnosisOutcome::LocalEvidenceChanged { .. }));
}

#[tokio::test]
async fn race_role_loss_link_change_is_detected() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    insert_role_loss_op(&state, "op-1");
    let (source, entered, proceed, _count) = barrier_source(
        enrollment_found(EnrollmentRemoteStatus::Active),
        membership_found(),
        role_loss_found(),
    );
    let key = role_loss_key("op-1");

    let outcome = run_race(state.clone(), key, source, entered, proceed, |state| {
        state.link_repository().add_link("/home/alice/Photos", "group-1").unwrap();
    })
    .await;

    assert!(matches!(outcome, StableDiagnosisOutcome::LocalEvidenceChanged { .. }));
}

#[tokio::test]
async fn race_operation_deleted_mid_lookup_is_detected() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    insert_role_loss_op(&state, "op-1");
    let (source, entered, proceed, _count) = barrier_source(
        enrollment_found(EnrollmentRemoteStatus::Active),
        membership_found(),
        role_loss_found(),
    );
    let key = role_loss_key("op-1");

    let outcome = run_race(state.clone(), key, source, entered, proceed, |state| {
        state.role_loss_operation_repository().delete_role_loss_operation("op-1").unwrap();
    })
    .await;

    assert!(matches!(
        outcome,
        StableDiagnosisOutcome::LocalEvidenceChanged {
            after: SnapshotAfterLookup::OperationNotFound,
            ..
        }
    ));
}

#[tokio::test]
async fn race_row_becomes_invalid_mid_lookup_is_detected() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    insert_membership_op(&state, "op-1");
    let (source, entered, proceed, _count) = barrier_source(
        enrollment_found(EnrollmentRemoteStatus::Active),
        membership_found(),
        role_loss_found(),
    );
    let key = membership_key("op-1");

    let outcome = run_race(state.clone(), key, source, entered, proceed, |state| {
        // `plant_malformed_membership_operation_for_test` is a plain
        // INSERT, not an upsert -- the original valid row must be
        // deleted first or this collides on `operation_id`'s own
        // PRIMARY KEY.
        state.membership_operation_repository().delete_membership_operation("op-1").unwrap();
        state.plant_malformed_membership_operation_for_test("op-1").unwrap();
    })
    .await;

    assert!(matches!(
        outcome,
        StableDiagnosisOutcome::LocalEvidenceChanged {
            after: SnapshotAfterLookup::InvalidOperation { .. },
            ..
        }
    ));
}

// ===== Read-only =====

#[tokio::test]
async fn stable_diagnosis_never_mutates_the_journal() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    insert_enrollment_op(&state, "op-1");
    let (source, _count) = no_barrier_source();
    let key = enrollment_key("op-1");

    let before = state.enrollment_repository().get_enrollment_operation("op-1").unwrap();
    let before_links = state.link_repository().list_links().unwrap();
    let before_markers = state.enrollment_repository().list_pending_enrollments().unwrap();

    let outcome = diagnose_stable(&state, &source, &key).await.unwrap();
    assert!(matches!(outcome, StableDiagnosisOutcome::Diagnosed { .. }));

    assert_eq!(before, state.enrollment_repository().get_enrollment_operation("op-1").unwrap());
    assert_eq!(before_links, state.link_repository().list_links().unwrap());
    assert_eq!(before_markers, state.enrollment_repository().list_pending_enrollments().unwrap());
}

// ===== Wire conversion =====

/// Every [`StableDiagnosisOutcome`] variant round-trips through its
/// protobuf encoding without loss -- covers all 4
/// `ShowRecoveryOperationResponse.result` oneof variants.
mod wire {
    use prost::Message;
    use yadorilink_ipc_proto::daemonctl::show_recovery_operation_response::Result as WireResult;
    use yadorilink_ipc_proto::daemonctl::ShowRecoveryOperationResponse;

    use crate::recovery_diagnosis::ipc::stable_diagnosis_outcome_to_proto;

    use super::*;

    fn round_trip(outcome: &StableDiagnosisOutcome) -> ShowRecoveryOperationResponse {
        let proto = stable_diagnosis_outcome_to_proto(outcome);
        let bytes = proto.encode_to_vec();
        ShowRecoveryOperationResponse::decode(bytes.as_slice()).unwrap()
    }

    #[tokio::test]
    async fn diagnosed_outcome_round_trips_and_carries_the_same_operation_and_recommendation() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        insert_enrollment_op(&state, "op-1");
        let (source, _count) = no_barrier_source();
        let key = enrollment_key("op-1");
        let outcome = diagnose_stable(&state, &source, &key).await.unwrap();

        let decoded = round_trip(&outcome);
        match decoded.result {
            Some(WireResult::Diagnosed(diagnosis)) => {
                let op = diagnosis.operation.unwrap();
                assert_eq!(op.operation_id, "op-1");
                assert_eq!(op.domain, "enrollment");
                assert!(!diagnosis.recommendation.is_empty());
                let remote = diagnosis.remote.unwrap();
                assert_eq!(remote.status, "active");
                let qualification = diagnosis.qualification.unwrap();
                assert!(qualification.link.is_some());
                assert!(qualification.pending_marker.is_some());
                assert_eq!(qualification.remote_identity.unwrap().status, "exact");
            }
            other => panic!("expected Diagnosed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn operation_not_found_outcome_round_trips() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        let (source, _count) = no_barrier_source();
        let key = enrollment_key("does-not-exist");
        let outcome = diagnose_stable(&state, &source, &key).await.unwrap();

        let decoded = round_trip(&outcome);
        match decoded.result {
            Some(WireResult::NotFound(not_found)) => {
                let key = not_found.key.unwrap();
                assert_eq!(key.domain, "enrollment");
                assert_eq!(key.operation_id, "does-not-exist");
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn invalid_operation_outcome_round_trips() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        state.plant_malformed_membership_operation_for_test("op-bad").unwrap();
        let (source, _count) = no_barrier_source();
        let key = membership_key("op-bad");
        let outcome = diagnose_stable(&state, &source, &key).await.unwrap();

        let decoded = round_trip(&outcome);
        match decoded.result {
            Some(WireResult::Invalid(invalid)) => {
                assert_eq!(invalid.operation_id.as_deref(), Some("op-bad"));
                assert_eq!(invalid.domain, "membership");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn local_evidence_changed_outcome_round_trips() {
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        insert_role_loss_op(&state, "op-1");
        let (source, entered, proceed, _count) = barrier_source(
            enrollment_found(EnrollmentRemoteStatus::Active),
            membership_found(),
            role_loss_found(),
        );
        let key = role_loss_key("op-1");

        let outcome = run_race(state.clone(), key, source, entered, proceed, |state| {
            state.role_loss_operation_repository().delete_role_loss_operation("op-1").unwrap();
        })
        .await;

        let decoded = round_trip(&outcome);
        match decoded.result {
            Some(WireResult::LocalEvidenceChanged(changed)) => {
                let key = changed.key.unwrap();
                assert_eq!(key.domain, "role-loss");
                assert_eq!(key.operation_id, "op-1");
                let after = changed.after.unwrap();
                assert_eq!(after.outcome, "operation_not_found");
            }
            other => panic!("expected LocalEvidenceChanged, got {other:?}"),
        }
    }
}
