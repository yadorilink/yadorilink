//! Table-driven coverage for the classifier
//! (`super::classifier`), on top of the identity-qualification tests
//! (`super::identity::tests`).

use crate::recovery::{LocalLinkEvidence, LocalObservation, PendingEnrollmentEvidence};
use yadorilink_replica_domain::session_state::{EnrollmentKind, MaterializationPolicy};
use yadorilink_replica_domain::session_state::{
    EnrollmentOperation, EnrollmentOperationState, MembershipCommitMode, MembershipDurabilityScope,
    MembershipOperation, MembershipOperationAction, MembershipOperationState, RoleLossAction,
    RoleLossOperation, RoleLossOperationState,
};

use super::*;
use crate::coordination_client::{
    EnrollmentOperationRecord, EnrollmentRemoteRequest, EnrollmentRemoteStatus,
    MembershipOperationRecord, MembershipRemoteResult, MembershipRemoteStatus,
    RemoteEvidenceErrorCategory, RoleLossOperationRecord,
};
use crate::recovery::{EnrollmentLocalEvidence, MembershipLocalEvidence, RoleLossLocalEvidence};
use crate::recovery_evidence::RemoteEvidence;

// ============================== Enrollment fixtures ==============================

fn enrollment_op(
    kind: EnrollmentKind,
    group_id: Option<&str>,
    group_name: Option<&str>,
    storage_mode: &str,
    state: EnrollmentOperationState,
) -> EnrollmentOperation {
    EnrollmentOperation {
        operation_id: "op-1".to_string(),
        kind,
        group_id: group_id.map(str::to_string),
        group_name: group_name.map(str::to_string),
        device_id: "device-a".to_string(),
        local_path: "/home/alice/Photos".to_string(),
        storage_mode: storage_mode.to_string(),
        state,
        last_error: None,
        attempts: 0,
        created_at_unix: 1,
        updated_at_unix: 1,
    }
}

fn live_link(group_id: &str) -> LocalObservation<LocalLinkEvidence> {
    LocalObservation::Found(LocalLinkEvidence {
        group_id: group_id.to_string(),
        local_path: "/home/alice/Photos".to_string(),
        materialization_policy: MaterializationPolicy::Eager,
        paused: false,
        orphaned: false,
        root_token_present: false,
    })
}

fn paused_link(group_id: &str) -> LocalObservation<LocalLinkEvidence> {
    LocalObservation::Found(LocalLinkEvidence {
        group_id: group_id.to_string(),
        local_path: "/home/alice/Photos".to_string(),
        materialization_policy: MaterializationPolicy::Eager,
        paused: true,
        orphaned: false,
        root_token_present: false,
    })
}

fn orphaned_link(group_id: &str) -> LocalObservation<LocalLinkEvidence> {
    LocalObservation::Found(LocalLinkEvidence {
        group_id: group_id.to_string(),
        local_path: "/home/alice/Photos".to_string(),
        materialization_policy: MaterializationPolicy::Eager,
        paused: false,
        orphaned: true,
        root_token_present: false,
    })
}

fn found_marker(
    kind: EnrollmentKind,
    group_id: &str,
) -> LocalObservation<PendingEnrollmentEvidence> {
    LocalObservation::Found(PendingEnrollmentEvidence {
        operation_id: "op-1".to_string(),
        kind,
        group_id: group_id.to_string(),
        device_id: "device-a".to_string(),
        local_path: "/home/alice/Photos".to_string(),
    })
}

fn enrollment_evidence(
    operation: EnrollmentOperation,
    link: LocalObservation<LocalLinkEvidence>,
    pending_marker: LocalObservation<PendingEnrollmentEvidence>,
) -> EnrollmentLocalEvidence {
    EnrollmentLocalEvidence { operation, link, pending_marker }
}

fn create_record(
    status: EnrollmentRemoteStatus,
    group_name: &str,
    result_group_id: Option<&str>,
) -> RemoteEvidence<EnrollmentOperationRecord> {
    RemoteEvidence::Found(EnrollmentOperationRecord {
        status,
        request_fingerprint: "fp".to_string(),
        request: EnrollmentRemoteRequest::Create {
            group_name: group_name.to_string(),
            device_id: "device-a".to_string(),
            storage_mode: "eager".to_string(),
        },
        result_group_id: result_group_id.map(str::to_string),
    })
}

fn join_record(
    status: EnrollmentRemoteStatus,
    group_id: &str,
    result_group_id: Option<&str>,
) -> RemoteEvidence<EnrollmentOperationRecord> {
    RemoteEvidence::Found(EnrollmentOperationRecord {
        status,
        request_fingerprint: "fp".to_string(),
        request: EnrollmentRemoteRequest::Join {
            group_id: group_id.to_string(),
            device_id: "device-a".to_string(),
            storage_mode: "eager".to_string(),
        },
        result_group_id: result_group_id.map(str::to_string),
    })
}

// ============================== Enrollment: API structure ==============================

#[test]
fn enrollment_recovery_blocked_wins_over_everything_else() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Create,
            Some("group-1"),
            Some("photos"),
            "eager",
            EnrollmentOperationState::RecoveryBlocked,
        ),
        live_link("group-DIFFERENT"),
        LocalObservation::Invalid { detail: "corrupt".to_string() },
    );
    let remote = create_record(EnrollmentRemoteStatus::Active, "photos", Some("group-1"));
    let diagnosis = diagnose_enrollment(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::ManualInvestigation);
    assert!(!diagnosis.automatic_recovery_safe());
    assert_eq!(diagnosis.reason_codes(), vec![RecoveryReasonCode::RecoveryBlocked]);
}

#[test]
fn enrollment_local_invalid_observation_is_manual_before_remote_is_even_considered() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Create,
            Some("group-1"),
            Some("photos"),
            "eager",
            EnrollmentOperationState::ActivationPending,
        ),
        LocalObservation::Invalid { detail: "bad link row".to_string() },
        found_marker(EnrollmentKind::Create, "group-1"),
    );
    let remote = create_record(EnrollmentRemoteStatus::Active, "photos", Some("group-1"));
    let diagnosis = diagnose_enrollment(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::ManualInvestigation);
    assert!(diagnosis.reason_codes().contains(&RecoveryReasonCode::LocalLinkInvalid));
}

#[test]
fn enrollment_local_identity_mismatch_is_conflict() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Create,
            Some("group-1"),
            Some("photos"),
            "eager",
            EnrollmentOperationState::ActivationPending,
        ),
        live_link("group-DIFFERENT"),
        found_marker(EnrollmentKind::Create, "group-1"),
    );
    let remote = create_record(EnrollmentRemoteStatus::Active, "photos", Some("group-1"));
    let diagnosis = diagnose_enrollment(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::Conflict);
    assert!(!diagnosis.automatic_recovery_safe());
    assert!(diagnosis.reason_codes().contains(&RecoveryReasonCode::LocalLinkIdentityMismatch));
}

// ============================== Enrollment: state matrix ==============================

#[test]
fn enrollment_prepare_pending_record_not_found_retries() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Create,
            None,
            Some("photos"),
            "eager",
            EnrollmentOperationState::PreparePending,
        ),
        LocalObservation::ConfirmedAbsent,
        LocalObservation::ConfirmedAbsent,
    );
    let diagnosis = diagnose_enrollment(&local, &RemoteEvidence::RecordNotFound);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::RetrySameRemoteRequest);
    assert!(diagnosis.automatic_recovery_safe());
}

#[test]
fn enrollment_prepare_pending_with_a_pre_existing_link_is_conflict() {
    // A Create row is `PreparePending` only before `group_id` resolves, so
    // a link existing at this local_path can never compare as `Exact`
    // against an unresolved `group_id` (B1's own identity check always
    // reports `GroupId` mismatch here) -- the general "local identity
    // mismatch -> Conflict" priority rule (see `classify_enrollment`'s own
    // step 4) catches this before the PreparePending-specific
    // "unexpected evidence" state-matrix branch is ever reached.
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Create,
            None,
            Some("photos"),
            "eager",
            EnrollmentOperationState::PreparePending,
        ),
        live_link("group-existing"),
        LocalObservation::ConfirmedAbsent,
    );
    let diagnosis = diagnose_enrollment(&local, &RemoteEvidence::RecordNotFound);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::Conflict);
    assert!(diagnosis.reason_codes().contains(&RecoveryReasonCode::LocalLinkIdentityMismatch));
}

#[test]
fn enrollment_prepare_pending_remote_active_is_conflict() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Create,
            None,
            Some("photos"),
            "eager",
            EnrollmentOperationState::PreparePending,
        ),
        LocalObservation::ConfirmedAbsent,
        LocalObservation::ConfirmedAbsent,
    );
    let remote = create_record(EnrollmentRemoteStatus::Active, "photos", Some("group-1"));
    let diagnosis = diagnose_enrollment(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::Conflict);
    assert!(diagnosis.reason_codes().contains(&RecoveryReasonCode::RemoteActiveBeforeLocalSetup));
}

#[test]
fn enrollment_prepared_exact_link_and_marker_waits() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Create,
            Some("group-1"),
            Some("photos"),
            "eager",
            EnrollmentOperationState::Prepared,
        ),
        live_link("group-1"),
        found_marker(EnrollmentKind::Create, "group-1"),
    );
    let remote = create_record(EnrollmentRemoteStatus::Prepared, "photos", Some("group-1"));
    let diagnosis = diagnose_enrollment(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::WaitForAutomaticRecovery);
}

/// Exact local evidence (link + marker) at `Prepared` must NOT authorize
/// automatic recovery if the remote side already reports `Active` --
/// activation landing before this row ever reached `LocalSetupPending` is
/// exactly the phantom-full-replica race that state exists to prevent, and
/// must stay a `Conflict` here too, consistent with every other branch in
/// this state matrix that treats an early remote `Active` the same way.
#[test]
fn enrollment_prepared_exact_link_and_marker_but_remote_already_active_is_conflict() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Create,
            Some("group-1"),
            Some("photos"),
            "eager",
            EnrollmentOperationState::Prepared,
        ),
        live_link("group-1"),
        found_marker(EnrollmentKind::Create, "group-1"),
    );
    let remote = create_record(EnrollmentRemoteStatus::Active, "photos", Some("group-1"));
    let diagnosis = diagnose_enrollment(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::Conflict);
    assert!(!diagnosis.automatic_recovery_safe());
    assert!(diagnosis.reason_codes().contains(&RecoveryReasonCode::RemoteActiveBeforeLocalSetup));
}

#[test]
fn enrollment_prepared_create_record_not_found_is_manual_not_retry() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Create,
            Some("group-1"),
            Some("photos"),
            "eager",
            EnrollmentOperationState::Prepared,
        ),
        LocalObservation::ConfirmedAbsent,
        LocalObservation::ConfirmedAbsent,
    );
    let diagnosis = diagnose_enrollment(&local, &RemoteEvidence::RecordNotFound);
    assert_eq!(
        diagnosis.recommendation(),
        RecoveryRecommendation::ManualInvestigation,
        "a Create row that already resolved a group_id must not resend under a fresh identity"
    );
}

#[test]
fn enrollment_prepared_join_record_not_found_retries() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Join,
            Some("group-1"),
            None,
            "eager",
            EnrollmentOperationState::Prepared,
        ),
        LocalObservation::ConfirmedAbsent,
        LocalObservation::ConfirmedAbsent,
    );
    let diagnosis = diagnose_enrollment(&local, &RemoteEvidence::RecordNotFound);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::RetrySameRemoteRequest);
}

#[test]
fn enrollment_local_setup_pending_never_recommends_activation() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Create,
            Some("group-1"),
            Some("photos"),
            "eager",
            EnrollmentOperationState::LocalSetupPending,
        ),
        live_link("group-1"),
        found_marker(EnrollmentKind::Create, "group-1"),
    );
    let remote = create_record(EnrollmentRemoteStatus::Prepared, "photos", Some("group-1"));
    let diagnosis = diagnose_enrollment(&local, &remote);
    assert_ne!(diagnosis.recommendation(), RecoveryRecommendation::RetryRemoteActivation);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::WaitForAutomaticRecovery);
}

#[test]
fn enrollment_activation_pending_exact_evidence_and_prepared_retries_activation() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Create,
            Some("group-1"),
            Some("photos"),
            "eager",
            EnrollmentOperationState::ActivationPending,
        ),
        live_link("group-1"),
        found_marker(EnrollmentKind::Create, "group-1"),
    );
    let remote = create_record(EnrollmentRemoteStatus::Prepared, "photos", Some("group-1"));
    let diagnosis = diagnose_enrollment(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::RetryRemoteActivation);
    assert!(diagnosis.automatic_recovery_safe());
}

#[test]
fn enrollment_activation_pending_marker_missing_with_prepared_is_manual() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Create,
            Some("group-1"),
            Some("photos"),
            "eager",
            EnrollmentOperationState::ActivationPending,
        ),
        live_link("group-1"),
        LocalObservation::ConfirmedAbsent,
    );
    let remote = create_record(EnrollmentRemoteStatus::Prepared, "photos", Some("group-1"));
    let diagnosis = diagnose_enrollment(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::ManualInvestigation);
    assert!(diagnosis.reason_codes().contains(&RecoveryReasonCode::LocalMarkerMissing));
}

#[test]
fn enrollment_activation_pending_marker_missing_but_remote_active_settles() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Create,
            Some("group-1"),
            Some("photos"),
            "eager",
            EnrollmentOperationState::ActivationPending,
        ),
        live_link("group-1"),
        LocalObservation::ConfirmedAbsent,
    );
    let remote = create_record(EnrollmentRemoteStatus::Active, "photos", Some("group-1"));
    let diagnosis = diagnose_enrollment(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::CompleteLocalSettlement);
}

#[test]
fn enrollment_activation_pending_remote_gone_waits_for_automatic_recovery() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Create,
            Some("group-1"),
            Some("photos"),
            "eager",
            EnrollmentOperationState::ActivationPending,
        ),
        live_link("group-1"),
        found_marker(EnrollmentKind::Create, "group-1"),
    );
    let diagnosis = diagnose_enrollment(&local, &RemoteEvidence::RecordNotFound);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::WaitForAutomaticRecovery);
    assert!(diagnosis.reason_codes().contains(&RecoveryReasonCode::RemoteAuthorizationGone));
}

#[test]
fn enrollment_cancel_pending_with_live_paused_link_is_conflict() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Create,
            Some("group-1"),
            Some("photos"),
            "eager",
            EnrollmentOperationState::CancelPending,
        ),
        paused_link("group-1"),
        LocalObservation::ConfirmedAbsent,
    );
    let diagnosis = diagnose_enrollment(&local, &RemoteEvidence::RecordNotFound);
    assert_eq!(
        diagnosis.recommendation(),
        RecoveryRecommendation::Conflict,
        "a paused link is still LIVE -- pausing is a reversible sync gate, not an unlink"
    );
}

#[test]
fn enrollment_cancel_pending_with_orphaned_link_can_cancel() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Create,
            Some("group-1"),
            Some("photos"),
            "eager",
            EnrollmentOperationState::CancelPending,
        ),
        orphaned_link("group-1"),
        LocalObservation::ConfirmedAbsent,
    );
    let remote = create_record(EnrollmentRemoteStatus::Prepared, "photos", Some("group-1"));
    let diagnosis = diagnose_enrollment(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::RetryRemoteCancellation);
}

#[test]
fn enrollment_cancel_pending_record_not_found_retries_cancellation_not_settle() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Create,
            Some("group-1"),
            Some("photos"),
            "eager",
            EnrollmentOperationState::CancelPending,
        ),
        LocalObservation::ConfirmedAbsent,
        LocalObservation::ConfirmedAbsent,
    );
    let diagnosis = diagnose_enrollment(&local, &RemoteEvidence::RecordNotFound);
    assert_eq!(
        diagnosis.recommendation(),
        RecoveryRecommendation::RetryRemoteCancellation,
        "a 404 alone must never be treated as proof cancellation already completed"
    );
}

// ============================== Enrollment: result-shape validation ==============================

#[test]
fn enrollment_join_prepared_missing_result_group_id_is_incomplete() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Join,
            Some("group-1"),
            None,
            "eager",
            EnrollmentOperationState::ActivationPending,
        ),
        live_link("group-1"),
        found_marker(EnrollmentKind::Join, "group-1"),
    );
    let remote = join_record(EnrollmentRemoteStatus::Prepared, "group-1", None);
    let diagnosis = diagnose_enrollment(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::ManualInvestigation);
    assert!(diagnosis.reason_codes().contains(&RecoveryReasonCode::RemoteResultIncomplete));
}

/// A remote record reporting `Prepared` with no `result_group_id` is
/// malformed regardless of the LOCAL row's own state -- even while still
/// `PreparePending` (before this device has recorded any group_id of its
/// own), since a `PreparePending` row can never advance without a real
/// group_id. An earlier version of this check exempted `PreparePending`,
/// which let `WaitForAutomaticRecovery` (a `automatic_recovery_safe: true`
/// verdict) through for a remote record automatic recovery could never
/// actually act on.
#[test]
fn enrollment_prepare_pending_remote_prepared_missing_result_group_id_is_manual() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Create,
            None,
            Some("photos"),
            "eager",
            EnrollmentOperationState::PreparePending,
        ),
        LocalObservation::ConfirmedAbsent,
        LocalObservation::ConfirmedAbsent,
    );
    let remote = create_record(EnrollmentRemoteStatus::Prepared, "photos", None);
    let diagnosis = diagnose_enrollment(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::ManualInvestigation);
    assert!(!diagnosis.automatic_recovery_safe());
    assert!(diagnosis.reason_codes().contains(&RecoveryReasonCode::RemoteResultIncomplete));
}

#[test]
fn enrollment_create_prepared_missing_result_group_id_is_manual() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Create,
            Some("group-1"),
            Some("photos"),
            "eager",
            EnrollmentOperationState::Prepared,
        ),
        LocalObservation::ConfirmedAbsent,
        LocalObservation::ConfirmedAbsent,
    );
    let remote = create_record(EnrollmentRemoteStatus::Prepared, "photos", None);
    let diagnosis = diagnose_enrollment(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::ManualInvestigation);
    assert!(diagnosis.reason_codes().contains(&RecoveryReasonCode::RemoteResultIncomplete));
}

#[test]
fn enrollment_active_missing_result_group_id_is_incomplete() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Create,
            Some("group-1"),
            Some("photos"),
            "eager",
            EnrollmentOperationState::ActivationPending,
        ),
        live_link("group-1"),
        found_marker(EnrollmentKind::Create, "group-1"),
    );
    let remote = create_record(EnrollmentRemoteStatus::Active, "photos", None);
    let diagnosis = diagnose_enrollment(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::ManualInvestigation);
    assert!(diagnosis.reason_codes().contains(&RecoveryReasonCode::RemoteResultIncomplete));
}

/// `Cancelled` with no `result_group_id` is a legitimate terminal outcome
/// (the Worker's own stale-preparing sweep / a cancel racing an in-flight
/// prepare produces exactly this shape via `settleOperation(...,
/// resultJson: null)`), NOT a malformed record -- it must never be
/// reported as `RemoteResultIncomplete`.
#[test]
fn enrollment_create_cancel_pending_remote_cancelled_with_no_result_settles() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Create,
            Some("group-1"),
            Some("photos"),
            "eager",
            EnrollmentOperationState::CancelPending,
        ),
        LocalObservation::ConfirmedAbsent,
        LocalObservation::ConfirmedAbsent,
    );
    let remote = create_record(EnrollmentRemoteStatus::Cancelled, "photos", None);
    let diagnosis = diagnose_enrollment(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::CompleteLocalSettlement);
    assert!(!diagnosis.reason_codes().contains(&RecoveryReasonCode::RemoteResultIncomplete));
}

#[test]
fn enrollment_join_cancel_pending_remote_cancelled_with_no_result_settles() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Join,
            Some("group-1"),
            None,
            "eager",
            EnrollmentOperationState::CancelPending,
        ),
        LocalObservation::ConfirmedAbsent,
        LocalObservation::ConfirmedAbsent,
    );
    let remote = join_record(EnrollmentRemoteStatus::Cancelled, "group-1", None);
    let diagnosis = diagnose_enrollment(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::CompleteLocalSettlement);
    assert!(!diagnosis.reason_codes().contains(&RecoveryReasonCode::RemoteResultIncomplete));
}

#[test]
fn enrollment_activation_pending_remote_cancelled_with_no_result_waits_for_automatic_recovery() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Create,
            Some("group-1"),
            Some("photos"),
            "eager",
            EnrollmentOperationState::ActivationPending,
        ),
        live_link("group-1"),
        found_marker(EnrollmentKind::Create, "group-1"),
    );
    let remote = create_record(EnrollmentRemoteStatus::Cancelled, "photos", None);
    let diagnosis = diagnose_enrollment(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::WaitForAutomaticRecovery);
    assert!(diagnosis.reason_codes().contains(&RecoveryReasonCode::RemoteAuthorizationGone));
    assert!(!diagnosis.reason_codes().contains(&RecoveryReasonCode::RemoteResultIncomplete));
}

#[test]
fn enrollment_prepare_pending_remote_cancelled_with_no_result_is_conflict_not_incomplete() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Create,
            None,
            Some("photos"),
            "eager",
            EnrollmentOperationState::PreparePending,
        ),
        LocalObservation::ConfirmedAbsent,
        LocalObservation::ConfirmedAbsent,
    );
    let remote = create_record(EnrollmentRemoteStatus::Cancelled, "photos", None);
    let diagnosis = diagnose_enrollment(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::Conflict);
    assert!(diagnosis.reason_codes().contains(&RecoveryReasonCode::RemoteResultConflict));
    assert!(!diagnosis.reason_codes().contains(&RecoveryReasonCode::RemoteResultIncomplete));
}

#[test]
fn enrollment_create_preparing_with_a_result_group_id_is_a_conflict() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Create,
            None,
            Some("photos"),
            "eager",
            EnrollmentOperationState::PreparePending,
        ),
        LocalObservation::ConfirmedAbsent,
        LocalObservation::ConfirmedAbsent,
    );
    let remote = create_record(EnrollmentRemoteStatus::Preparing, "photos", Some("group-1"));
    let diagnosis = diagnose_enrollment(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::ManualInvestigation);
    assert!(diagnosis.reason_codes().contains(&RecoveryReasonCode::RemoteResultConflict));
}

#[test]
fn enrollment_join_preparing_with_a_result_group_id_is_a_conflict() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Join,
            Some("group-1"),
            None,
            "eager",
            EnrollmentOperationState::Prepared,
        ),
        LocalObservation::ConfirmedAbsent,
        LocalObservation::ConfirmedAbsent,
    );
    let remote = join_record(EnrollmentRemoteStatus::Preparing, "group-1", Some("group-1"));
    let diagnosis = diagnose_enrollment(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::ManualInvestigation);
    assert!(diagnosis.reason_codes().contains(&RecoveryReasonCode::RemoteResultConflict));
}

// ============================== Membership fixtures ==============================

fn membership_op(
    action: MembershipOperationAction,
    commit_mode: MembershipCommitMode,
    group_ids: Vec<&str>,
    target_device_ids: Vec<&str>,
    lease_ids: Vec<Option<&str>>,
    state: MembershipOperationState,
    durability: (MembershipDurabilityScope, Vec<&str>),
) -> MembershipOperation {
    let (durability_scope, latch_group_ids) = durability;
    MembershipOperation {
        operation_id: "op-1".to_string(),
        action,
        commit_mode,
        removed_device_id: "device-b".to_string(),
        group_ids: group_ids.into_iter().map(str::to_string).collect(),
        target_device_ids: target_device_ids.into_iter().map(str::to_string).collect(),
        lease_ids: lease_ids.into_iter().map(|l| l.map(str::to_string)).collect(),
        state,
        durability_scope,
        latch_group_ids: latch_group_ids.into_iter().map(str::to_string).collect(),
        last_error: None,
        created_at_unix: 1,
        updated_at_unix: 1,
    }
}

fn membership_evidence(
    operation: MembershipOperation,
    present_durability_latches: Vec<&str>,
) -> MembershipLocalEvidence {
    MembershipLocalEvidence {
        operation,
        present_durability_latches: present_durability_latches
            .into_iter()
            .map(str::to_string)
            .collect(),
    }
}

fn membership_record_for(
    operation: &MembershipOperation,
    status: MembershipRemoteStatus,
    result: Option<MembershipRemoteResult>,
) -> RemoteEvidence<MembershipOperationRecord> {
    let request =
        crate::application::membership_operation_identity::expected_membership_remote_request(
            operation,
        );
    RemoteEvidence::Found(MembershipOperationRecord {
        status,
        action: request.action.clone(),
        removed_device_id: request.removed_device_id.clone(),
        request_fingerprint: "fp".to_string(),
        request,
        result,
        rejection_code: None,
        rejection_detail: None,
    })
}

fn membership_result(affected_group_ids: Option<Vec<&str>>) -> MembershipRemoteResult {
    MembershipRemoteResult {
        affected_group_ids: affected_group_ids
            .map(|ids| ids.into_iter().map(str::to_string).collect()),
        target_device_id: None,
        membership_generation: Some(4),
        lease_id: None,
    }
}

// ============================== Membership: state matrix ==============================

#[test]
fn membership_recovery_blocked_wins() {
    let local = membership_evidence(
        membership_op(
            MembershipOperationAction::Revoke,
            MembershipCommitMode::PlainRevoke,
            vec!["group-1"],
            vec![],
            vec![],
            MembershipOperationState::RecoveryBlocked,
            (MembershipDurabilityScope::Known, vec![]),
        ),
        vec![],
    );
    let diagnosis = diagnose_membership(&local, &RemoteEvidence::RecordNotFound);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::ManualInvestigation);
    assert_eq!(diagnosis.reason_codes(), vec![RecoveryReasonCode::RecoveryBlocked]);
}

#[test]
fn membership_prepared_record_not_found_retries() {
    let local = membership_evidence(
        membership_op(
            MembershipOperationAction::Revoke,
            MembershipCommitMode::PlainRevoke,
            vec!["group-1"],
            vec![],
            vec![],
            MembershipOperationState::Prepared,
            (MembershipDurabilityScope::Known, vec![]),
        ),
        vec![],
    );
    let diagnosis = diagnose_membership(&local, &RemoteEvidence::RecordNotFound);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::RetrySameRemoteRequest);
}

#[test]
fn membership_local_settlement_pending_known_scope_completes_even_when_remote_unavailable() {
    let operation = membership_op(
        MembershipOperationAction::Revoke,
        MembershipCommitMode::PlainRevoke,
        vec!["group-1"],
        vec![],
        vec![],
        MembershipOperationState::LocalSettlementPending,
        (MembershipDurabilityScope::Known, vec![]),
    );
    let local = membership_evidence(operation, vec![]);
    let remote = RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::Network };
    let diagnosis = diagnose_membership(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::CompleteLocalSettlement);
    assert!(diagnosis.automatic_recovery_safe());
}

#[test]
fn membership_local_settlement_pending_unknown_scope_waits_when_remote_unavailable() {
    let operation = membership_op(
        MembershipOperationAction::RemoveDevice,
        MembershipCommitMode::PlainRemoveDevice,
        vec![],
        vec![],
        vec![],
        MembershipOperationState::LocalSettlementPending,
        (MembershipDurabilityScope::Unknown, vec![]),
    );
    let local = membership_evidence(operation, vec![]);
    let remote = RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::Network };
    let diagnosis = diagnose_membership(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::WaitForRemoteEvidence);
    assert!(!diagnosis.automatic_recovery_safe());
}

#[test]
fn membership_committed_remove_device_missing_affected_groups_is_manual() {
    let operation = membership_op(
        MembershipOperationAction::RemoveDevice,
        MembershipCommitMode::PlainRemoveDevice,
        vec![],
        vec![],
        vec![],
        MembershipOperationState::Prepared,
        (MembershipDurabilityScope::Unknown, vec![]),
    );
    let local = membership_evidence(operation.clone(), vec![]);
    let remote = membership_record_for(&operation, MembershipRemoteStatus::Committed, None);
    let diagnosis = diagnose_membership(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::ManualInvestigation);
    assert!(diagnosis.reason_codes().contains(&RecoveryReasonCode::RemoteResultIncomplete));
}

#[test]
fn membership_committed_revoke_with_empty_result_is_allowed() {
    let operation = membership_op(
        MembershipOperationAction::Revoke,
        MembershipCommitMode::PlainRevoke,
        vec!["group-1"],
        vec![],
        vec![],
        MembershipOperationState::Prepared,
        (MembershipDurabilityScope::Known, vec![]),
    );
    let local = membership_evidence(operation.clone(), vec![]);
    let remote = membership_record_for(
        &operation,
        MembershipRemoteStatus::Committed,
        Some(membership_result(None)),
    );
    let diagnosis = diagnose_membership(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::CompleteLocalSettlement);
}

#[test]
fn membership_definitely_rejected_with_result_payload_is_manual() {
    let operation = membership_op(
        MembershipOperationAction::Revoke,
        MembershipCommitMode::PlainRevoke,
        vec!["group-1"],
        vec![],
        vec![],
        MembershipOperationState::Prepared,
        (MembershipDurabilityScope::Known, vec![]),
    );
    let local = membership_evidence(operation.clone(), vec![]);
    let remote = membership_record_for(
        &operation,
        MembershipRemoteStatus::DefinitelyRejected,
        Some(membership_result(None)),
    );
    let diagnosis = diagnose_membership(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::ManualInvestigation);
    assert!(diagnosis.reason_codes().contains(&RecoveryReasonCode::RemoteResultConflict));
}

#[test]
fn membership_missing_latch_still_completes_local_settlement() {
    let operation = membership_op(
        MembershipOperationAction::Revoke,
        MembershipCommitMode::PlainRevoke,
        vec!["group-1"],
        vec![],
        vec![],
        MembershipOperationState::LocalSettlementPending,
        (MembershipDurabilityScope::Known, vec!["group-2"]),
    );
    let local = membership_evidence(operation, vec![]);
    let diagnosis = diagnose_membership(&local, &RemoteEvidence::RecordNotFound);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::CompleteLocalSettlement);
    assert!(diagnosis.reason_codes().contains(&RecoveryReasonCode::DurabilityLatchMissing));
    assert!(diagnosis.automatic_recovery_safe());
}

#[test]
fn membership_completed_with_remote_committed_settles() {
    let operation = membership_op(
        MembershipOperationAction::Revoke,
        MembershipCommitMode::PlainRevoke,
        vec!["group-1"],
        vec![],
        vec![],
        MembershipOperationState::Completed,
        (MembershipDurabilityScope::Known, vec![]),
    );
    let local = membership_evidence(operation.clone(), vec![]);
    let remote = membership_record_for(
        &operation,
        MembershipRemoteStatus::Committed,
        Some(membership_result(None)),
    );
    let diagnosis = diagnose_membership(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::CompleteLocalSettlement);
}

#[test]
fn membership_completed_with_remote_rejected_is_conflict() {
    let operation = membership_op(
        MembershipOperationAction::Revoke,
        MembershipCommitMode::PlainRevoke,
        vec!["group-1"],
        vec![],
        vec![],
        MembershipOperationState::Completed,
        (MembershipDurabilityScope::Known, vec![]),
    );
    let local = membership_evidence(operation.clone(), vec![]);
    let remote =
        membership_record_for(&operation, MembershipRemoteStatus::DefinitelyRejected, None);
    let diagnosis = diagnose_membership(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::Conflict);
}

// ============================== Role loss fixtures ==============================

fn role_loss_op(
    action: RoleLossAction,
    local_path: Option<&str>,
    worker_membership_generation: Option<i64>,
    state: RoleLossOperationState,
) -> RoleLossOperation {
    RoleLossOperation {
        operation_id: "op-1".to_string(),
        group_id: "group-1".to_string(),
        source_device_id: "device-c".to_string(),
        target_device_id: "device-d".to_string(),
        lease_id: "lease-1".to_string(),
        worker_membership_generation,
        action,
        state,
        local_path: local_path.map(str::to_string),
        attempts: 0,
        created_at_unix: 1,
        updated_at_unix: 1,
    }
}

fn role_loss_evidence(
    operation: RoleLossOperation,
    link: LocalObservation<LocalLinkEvidence>,
) -> RoleLossLocalEvidence {
    RoleLossLocalEvidence { operation, link }
}

fn role_loss_record(action: &str, generation: i64) -> RemoteEvidence<RoleLossOperationRecord> {
    RemoteEvidence::Found(RoleLossOperationRecord {
        group_id: "group-1".to_string(),
        source_device_id: "device-c".to_string(),
        target_device_id: "device-d".to_string(),
        lease_id: Some("lease-1".to_string()),
        action: action.to_string(),
        membership_generation: generation,
        committed_at_unix: 1,
    })
}

// ============================== Role loss: state matrix ==============================

#[test]
fn role_loss_prepared_record_not_found_continues_compensation() {
    let local = role_loss_evidence(
        role_loss_op(
            RoleLossAction::Demote,
            Some("/home/alice/Photos"),
            None,
            RoleLossOperationState::Prepared,
        ),
        LocalObservation::ConfirmedAbsent,
    );
    let diagnosis = diagnose_role_loss(&local, &RemoteEvidence::RecordNotFound);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::ContinueAutomaticCompensation);
    assert!(diagnosis.automatic_recovery_safe());
    assert!(diagnosis.reason_codes().contains(&RecoveryReasonCode::LegacyRoleLossReceiptUncertain));
}

#[test]
fn role_loss_prepared_unavailable_continues_compensation() {
    let local = role_loss_evidence(
        role_loss_op(
            RoleLossAction::Demote,
            Some("/home/alice/Photos"),
            None,
            RoleLossOperationState::Prepared,
        ),
        LocalObservation::ConfirmedAbsent,
    );
    let remote = RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::Timeout };
    let diagnosis = diagnose_role_loss(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::ContinueAutomaticCompensation);
    assert!(diagnosis.automatic_recovery_safe());
}

#[test]
fn role_loss_worker_committed_with_mismatched_local_link_still_continues_compensation() {
    let local = role_loss_evidence(
        role_loss_op(
            RoleLossAction::Demote,
            Some("/home/alice/Photos"),
            None,
            RoleLossOperationState::WorkerCommitted,
        ),
        LocalObservation::Found(LocalLinkEvidence {
            group_id: "group-DIFFERENT".to_string(),
            local_path: "/home/alice/Photos".to_string(),
            materialization_policy: MaterializationPolicy::Eager,
            paused: false,
            orphaned: false,
            root_token_present: false,
        }),
    );
    let remote = role_loss_record("demote", 4);
    let diagnosis = diagnose_role_loss(&local, &remote);
    assert_eq!(
        diagnosis.recommendation(),
        RecoveryRecommendation::ContinueAutomaticCompensation,
        "local link mismatch must never gate role-loss's own safe-direction compensation"
    );
    assert!(diagnosis.reason_codes().contains(&RecoveryReasonCode::LocalLinkIdentityMismatch));
}

#[test]
fn role_loss_compensating_with_invalid_local_link_still_continues_compensation() {
    let local = role_loss_evidence(
        role_loss_op(
            RoleLossAction::Unlink,
            Some("/home/alice/Photos"),
            None,
            RoleLossOperationState::Compensating,
        ),
        LocalObservation::Invalid { detail: "corrupt row".to_string() },
    );
    let remote = role_loss_record("demote", 4);
    let diagnosis = diagnose_role_loss(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::ContinueAutomaticCompensation);
    assert!(diagnosis.reason_codes().contains(&RecoveryReasonCode::LocalLinkInvalid));
}

#[test]
fn role_loss_local_committed_with_remote_unavailable_still_settles() {
    let local = role_loss_evidence(
        role_loss_op(
            RoleLossAction::Demote,
            Some("/home/alice/Photos"),
            None,
            RoleLossOperationState::LocalCommitted,
        ),
        LocalObservation::ConfirmedAbsent,
    );
    let remote = RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::ServerError };
    let diagnosis = diagnose_role_loss(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::CompleteLocalSettlement);
}

#[test]
fn role_loss_completed_with_remote_found_exact_settles() {
    let local = role_loss_evidence(
        role_loss_op(
            RoleLossAction::Demote,
            Some("/home/alice/Photos"),
            Some(4),
            RoleLossOperationState::Completed,
        ),
        LocalObservation::ConfirmedAbsent,
    );
    let remote = role_loss_record("demote", 4);
    let diagnosis = diagnose_role_loss(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::CompleteLocalSettlement);
}

#[test]
fn role_loss_generation_mismatch_is_conflict() {
    let local = role_loss_evidence(
        role_loss_op(
            RoleLossAction::Demote,
            Some("/home/alice/Photos"),
            Some(4),
            RoleLossOperationState::WorkerCommitted,
        ),
        LocalObservation::ConfirmedAbsent,
    );
    let remote = role_loss_record("demote", 99);
    let diagnosis = diagnose_role_loss(&local, &remote);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::Conflict);
    assert!(diagnosis.reason_codes().contains(&RecoveryReasonCode::RemoteResultConflict));
    assert!(!diagnosis.automatic_recovery_safe());
}

#[test]
fn role_loss_revoke_action_is_always_manual() {
    let local = role_loss_evidence(
        role_loss_op(
            RoleLossAction::Revoke,
            Some("/home/alice/Photos"),
            None,
            RoleLossOperationState::Prepared,
        ),
        LocalObservation::ConfirmedAbsent,
    );
    let diagnosis = diagnose_role_loss(&local, &RemoteEvidence::RecordNotFound);
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::ManualInvestigation);
    assert_eq!(diagnosis.reason_codes(), vec![RecoveryReasonCode::UnsupportedRoleLossAction]);
    assert!(!diagnosis.automatic_recovery_safe());
}

#[test]
fn role_loss_remote_identity_mismatch_is_conflict() {
    let local = role_loss_evidence(
        role_loss_op(
            RoleLossAction::Demote,
            Some("/home/alice/Photos"),
            None,
            RoleLossOperationState::WorkerCommitted,
        ),
        LocalObservation::ConfirmedAbsent,
    );
    let mut record = match role_loss_record("demote", 4) {
        RemoteEvidence::Found(record) => record,
        _ => unreachable!(),
    };
    record.source_device_id = "device-DIFFERENT".to_string();
    let diagnosis = diagnose_role_loss(&local, &RemoteEvidence::Found(record));
    assert_eq!(diagnosis.recommendation(), RecoveryRecommendation::Conflict);
    assert!(diagnosis.reason_codes().contains(&RecoveryReasonCode::RemoteIdentityMismatch));
}

// ============================== Determinism ==============================

#[test]
fn reason_codes_are_sorted_and_deduplicated() {
    let local = enrollment_evidence(
        enrollment_op(
            EnrollmentKind::Create,
            None,
            Some("photos"),
            "eager",
            EnrollmentOperationState::PreparePending,
        ),
        live_link("group-existing"),
        found_marker(EnrollmentKind::Create, "group-existing"),
    );
    let diagnosis = diagnose_enrollment(&local, &RemoteEvidence::RecordNotFound);
    let mut sorted = diagnosis.reason_codes().to_vec();
    sorted.sort();
    sorted.dedup();
    assert_eq!(diagnosis.reason_codes(), sorted);
}

#[test]
fn the_same_input_always_produces_the_same_diagnosis() {
    let build = || {
        enrollment_evidence(
            enrollment_op(
                EnrollmentKind::Create,
                Some("group-1"),
                Some("photos"),
                "eager",
                EnrollmentOperationState::ActivationPending,
            ),
            live_link("group-1"),
            found_marker(EnrollmentKind::Create, "group-1"),
        )
    };
    let remote = create_record(EnrollmentRemoteStatus::Prepared, "photos", Some("group-1"));
    let first = diagnose_enrollment(&build(), &remote);
    let second = diagnose_enrollment(&build(), &remote);
    assert_eq!(first, second);
}

#[test]
fn recommendation_and_automatic_recovery_safe_never_disagree() {
    let cases: Vec<(EnrollmentLocalEvidence, RemoteEvidence<EnrollmentOperationRecord>)> = vec![
        (
            enrollment_evidence(
                enrollment_op(
                    EnrollmentKind::Create,
                    None,
                    Some("photos"),
                    "eager",
                    EnrollmentOperationState::PreparePending,
                ),
                LocalObservation::ConfirmedAbsent,
                LocalObservation::ConfirmedAbsent,
            ),
            RemoteEvidence::RecordNotFound,
        ),
        (
            enrollment_evidence(
                enrollment_op(
                    EnrollmentKind::Create,
                    Some("group-1"),
                    Some("photos"),
                    "eager",
                    EnrollmentOperationState::RecoveryBlocked,
                ),
                LocalObservation::ConfirmedAbsent,
                LocalObservation::ConfirmedAbsent,
            ),
            RemoteEvidence::RecordNotFound,
        ),
    ];
    for (local, remote) in cases {
        let diagnosis = diagnose_enrollment(&local, &remote);
        assert_eq!(
            diagnosis.automatic_recovery_safe(),
            diagnosis.recommendation().automatic_recovery_safe()
        );
    }
}
