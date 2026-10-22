#![cfg(test)]

use yadorilink_replica_domain::session_state::EnrollmentKind;
use yadorilink_replica_domain::session_state::{
    MembershipCommitMode, MembershipDurabilityScope, MembershipOperationAction,
    MembershipOperationState,
};

use super::*;
use crate::coordination_client::{
    EnrollmentRemoteStatus, MembershipRemoteRequest, MembershipRemoteRequestGroup,
    MembershipRemoteStatus, RemoteEvidenceErrorCategory,
};

fn enrollment_op(
    kind: EnrollmentKind,
    group_id: Option<&str>,
    group_name: Option<&str>,
    state: EnrollmentOperationState,
) -> EnrollmentOperation {
    EnrollmentOperation {
        operation_id: "op-1".to_string(),
        kind,
        group_id: group_id.map(str::to_string),
        group_name: group_name.map(str::to_string),
        device_id: "device-a".to_string(),
        local_path: "/home/alice/Photos".to_string(),
        storage_mode: "eager".to_string(),
        state,
        last_error: None,
        attempts: 0,
        created_at_unix: 1,
        updated_at_unix: 1,
    }
}

fn link_evidence(group_id: &str, local_path: &str) -> LocalLinkEvidence {
    LocalLinkEvidence {
        group_id: group_id.to_string(),
        local_path: local_path.to_string(),
        materialization_policy: MaterializationPolicy::Eager,
        paused: false,
        orphaned: false,
        root_token_present: false,
    }
}

fn marker_evidence(
    kind: EnrollmentKind,
    group_id: &str,
    device_id: &str,
    local_path: &str,
) -> PendingEnrollmentEvidence {
    PendingEnrollmentEvidence {
        operation_id: "op-1".to_string(),
        kind,
        group_id: group_id.to_string(),
        device_id: device_id.to_string(),
        local_path: local_path.to_string(),
    }
}

// ===== Enrollment: local link/marker identity =====

#[test]
fn enrollment_marker_kind_mismatch() {
    let operation = enrollment_op(
        EnrollmentKind::Create,
        Some("group-1"),
        None,
        EnrollmentOperationState::ActivationPending,
    );
    let marker = LocalObservation::Found(marker_evidence(
        EnrollmentKind::Join,
        "group-1",
        "device-a",
        "/home/alice/Photos",
    ));
    assert_eq!(
        qualify_enrollment_marker_identity(&operation, &marker),
        ObservationQualification::Mismatch { fields: vec![IdentityField::Kind] }
    );
}

#[test]
fn enrollment_marker_group_mismatch() {
    let operation = enrollment_op(
        EnrollmentKind::Create,
        Some("group-1"),
        None,
        EnrollmentOperationState::ActivationPending,
    );
    let marker = LocalObservation::Found(marker_evidence(
        EnrollmentKind::Create,
        "group-DIFFERENT",
        "device-a",
        "/home/alice/Photos",
    ));
    assert_eq!(
        qualify_enrollment_marker_identity(&operation, &marker),
        ObservationQualification::Mismatch { fields: vec![IdentityField::GroupId] }
    );
}

#[test]
fn enrollment_marker_device_mismatch() {
    let operation = enrollment_op(
        EnrollmentKind::Create,
        Some("group-1"),
        None,
        EnrollmentOperationState::ActivationPending,
    );
    let marker = LocalObservation::Found(marker_evidence(
        EnrollmentKind::Create,
        "group-1",
        "device-DIFFERENT",
        "/home/alice/Photos",
    ));
    assert_eq!(
        qualify_enrollment_marker_identity(&operation, &marker),
        ObservationQualification::Mismatch { fields: vec![IdentityField::DeviceId] }
    );
}

#[test]
fn enrollment_marker_path_mismatch() {
    let operation = enrollment_op(
        EnrollmentKind::Create,
        Some("group-1"),
        None,
        EnrollmentOperationState::ActivationPending,
    );
    let marker = LocalObservation::Found(marker_evidence(
        EnrollmentKind::Create,
        "group-1",
        "device-a",
        "/tmp/other",
    ));
    assert_eq!(
        qualify_enrollment_marker_identity(&operation, &marker),
        ObservationQualification::Mismatch { fields: vec![IdentityField::LocalPath] }
    );
}

#[test]
fn enrollment_link_group_mismatch() {
    let operation = enrollment_op(
        EnrollmentKind::Create,
        Some("group-1"),
        None,
        EnrollmentOperationState::ActivationPending,
    );
    let link = LocalObservation::Found(link_evidence("group-DIFFERENT", "/home/alice/Photos"));
    assert_eq!(
        qualify_enrollment_link_identity(&operation, &link),
        ObservationQualification::Mismatch { fields: vec![IdentityField::GroupId] }
    );
}

#[test]
fn enrollment_link_storage_mode_mismatch() {
    let operation = enrollment_op(
        EnrollmentKind::Create,
        Some("group-1"),
        None,
        EnrollmentOperationState::ActivationPending,
    );
    let mut link = link_evidence("group-1", "/home/alice/Photos");
    link.materialization_policy = MaterializationPolicy::OnDemand;
    assert_eq!(
        qualify_enrollment_link_identity(&operation, &LocalObservation::Found(link)),
        ObservationQualification::Mismatch { fields: vec![IdentityField::StorageMode] }
    );
}

#[test]
fn enrollment_group_id_none_with_path_occupied_is_mismatch_not_exact() {
    let operation = enrollment_op(
        EnrollmentKind::Create,
        None,
        Some("photos"),
        EnrollmentOperationState::PreparePending,
    );
    let link = LocalObservation::Found(link_evidence("group-existing", "/home/alice/Photos"));
    assert_eq!(
        qualify_enrollment_link_identity(&operation, &link),
        ObservationQualification::Mismatch { fields: vec![IdentityField::GroupId] },
        "an unresolved group_id must never be treated as matching any concrete group a link \
         names"
    );
}

#[test]
fn enrollment_observation_preservation() {
    let operation = enrollment_op(
        EnrollmentKind::Create,
        Some("group-1"),
        None,
        EnrollmentOperationState::ActivationPending,
    );
    assert_eq!(
        qualify_enrollment_link_identity(&operation, &LocalObservation::ConfirmedAbsent),
        ObservationQualification::ConfirmedAbsent
    );
    assert_eq!(
        qualify_enrollment_link_identity(
            &operation,
            &LocalObservation::Invalid { detail: "bad row".to_string() }
        ),
        ObservationQualification::Invalid { detail: "bad row".to_string() }
    );
    assert_eq!(
        qualify_enrollment_link_identity(
            &operation,
            &LocalObservation::Ambiguous { detail: "2 candidates".to_string() }
        ),
        ObservationQualification::Ambiguous { detail: "2 candidates".to_string() }
    );
}

#[test]
fn mismatch_fields_are_sorted_and_deduplicated() {
    // GroupId appears twice in source order (link group AND storage
    // mode both fail) -- Ord on IdentityField sorts LocalPath before
    // GroupId before StorageMode is NOT what's under test here; what
    // matters is the result contains each field once, in Ord order.
    let operation = enrollment_op(
        EnrollmentKind::Create,
        Some("group-1"),
        None,
        EnrollmentOperationState::ActivationPending,
    );
    let mut link = link_evidence("group-DIFFERENT", "/tmp/other");
    link.materialization_policy = MaterializationPolicy::OnDemand;
    let ObservationQualification::Mismatch { fields } =
        qualify_enrollment_link_identity(&operation, &LocalObservation::Found(link))
    else {
        panic!("expected Mismatch");
    };
    let mut sorted = fields.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(fields, sorted, "fields must already be sorted and deduplicated");
    assert_eq!(fields.len(), fields.iter().collect::<std::collections::HashSet<_>>().len());
}

// ===== Enrollment: remote identity =====

#[test]
fn enrollment_create_prepare_pending_group_name_mismatch() {
    let operation = enrollment_op(
        EnrollmentKind::Create,
        None,
        Some("photos"),
        EnrollmentOperationState::PreparePending,
    );
    let remote = RemoteEvidence::Found(EnrollmentOperationRecord {
        status: EnrollmentRemoteStatus::Preparing,
        request_fingerprint: "fp".to_string(),
        request: EnrollmentRemoteRequest::Create {
            group_name: "not-photos".to_string(),
            device_id: "device-a".to_string(),
            storage_mode: "eager".to_string(),
        },
        result_group_id: None,
    });
    assert_eq!(
        qualify_enrollment_remote_identity(&operation, &remote),
        RemoteIdentityQualification::Mismatch { fields: vec![IdentityField::GroupName] }
    );
}

/// `operation.storage_mode` on a Create row records the CALLER's own
/// requested LOCAL materialization mode -- a different concept from the
/// remote creator edge, which is always "eager". A Create row
/// legitimately requesting on-demand local materialization must still
/// compare as `Exact` against a well-formed ("eager") remote Create
/// request; `operation.storage_mode` must never be compared here at
/// all (it belongs in the LINK comparison instead -- see
/// `qualify_enrollment_link_identity`).
#[test]
fn enrollment_create_local_on_demand_storage_mode_is_not_compared_against_remote_identity() {
    let mut operation = enrollment_op(
        EnrollmentKind::Create,
        Some("group-1"),
        Some("photos"),
        EnrollmentOperationState::Prepared,
    );
    operation.storage_mode = "on-demand".to_string();
    let remote = RemoteEvidence::Found(EnrollmentOperationRecord {
        status: EnrollmentRemoteStatus::Prepared,
        request_fingerprint: "fp".to_string(),
        request: EnrollmentRemoteRequest::Create {
            group_name: "photos".to_string(),
            device_id: "device-a".to_string(),
            storage_mode: "eager".to_string(),
        },
        result_group_id: Some("group-1".to_string()),
    });
    assert_eq!(
        qualify_enrollment_remote_identity(&operation, &remote),
        RemoteIdentityQualification::Exact
    );
}

/// A remote Create request reporting "on-demand" is impossible (the
/// Worker constructs it as a fixed "eager" constant) and must be a
/// mismatch, regardless of what the LOCAL row's own `storage_mode`
/// (a different concept) happens to be.
#[test]
fn enrollment_create_remote_on_demand_is_a_mismatch_regardless_of_local_storage_mode() {
    let operation = enrollment_op(
        EnrollmentKind::Create,
        Some("group-1"),
        Some("photos"),
        EnrollmentOperationState::Prepared,
    );
    let remote = RemoteEvidence::Found(EnrollmentOperationRecord {
        status: EnrollmentRemoteStatus::Prepared,
        request_fingerprint: "fp".to_string(),
        request: EnrollmentRemoteRequest::Create {
            group_name: "photos".to_string(),
            device_id: "device-a".to_string(),
            storage_mode: "on-demand".to_string(),
        },
        result_group_id: Some("group-1".to_string()),
    });
    assert_eq!(
        qualify_enrollment_remote_identity(&operation, &remote),
        RemoteIdentityQualification::Mismatch { fields: vec![IdentityField::StorageMode] }
    );
}

/// Unlike Create, a Join legitimately carries "on-demand" -- the
/// storage-mode check for Create must not leak into the Join arm.
#[test]
fn enrollment_join_on_demand_matches_remote_on_demand() {
    let mut operation = enrollment_op(
        EnrollmentKind::Join,
        Some("group-1"),
        None,
        EnrollmentOperationState::ActivationPending,
    );
    operation.storage_mode = "on-demand".to_string();
    let remote = RemoteEvidence::Found(EnrollmentOperationRecord {
        status: EnrollmentRemoteStatus::Prepared,
        request_fingerprint: "fp".to_string(),
        request: EnrollmentRemoteRequest::Join {
            group_id: "group-1".to_string(),
            device_id: "device-a".to_string(),
            storage_mode: "on-demand".to_string(),
        },
        result_group_id: Some("group-1".to_string()),
    });
    assert_eq!(
        qualify_enrollment_remote_identity(&operation, &remote),
        RemoteIdentityQualification::Exact
    );
}

/// The normal, well-formed Create/eager path must remain Exact.
#[test]
fn enrollment_create_eager_normal_path_is_still_exact() {
    let operation = enrollment_op(
        EnrollmentKind::Create,
        Some("group-1"),
        Some("photos"),
        EnrollmentOperationState::Prepared,
    );
    let remote = RemoteEvidence::Found(EnrollmentOperationRecord {
        status: EnrollmentRemoteStatus::Prepared,
        request_fingerprint: "fp".to_string(),
        request: EnrollmentRemoteRequest::Create {
            group_name: "photos".to_string(),
            device_id: "device-a".to_string(),
            storage_mode: "eager".to_string(),
        },
        result_group_id: Some("group-1".to_string()),
    });
    assert_eq!(
        qualify_enrollment_remote_identity(&operation, &remote),
        RemoteIdentityQualification::Exact
    );
}

/// `mark_enrollment_operation_prepared` only ever sets `group_id` -- it
/// never clears `group_name` -- so the original request's name stays
/// available and comparable for the whole lifetime of a Create row,
/// not just while `PreparePending`. A remote record with the SAME
/// resulting group id but a DIFFERENT original create request (a
/// reused operation_id naming an unrelated group creation) must still
/// be caught here, not silently pass as Exact.
#[test]
fn enrollment_create_prepared_group_name_mismatch_is_still_caught() {
    let operation = enrollment_op(
        EnrollmentKind::Create,
        Some("group-1"),
        Some("photos"),
        EnrollmentOperationState::Prepared,
    );
    let remote = RemoteEvidence::Found(EnrollmentOperationRecord {
        status: EnrollmentRemoteStatus::Prepared,
        request_fingerprint: "fp".to_string(),
        request: EnrollmentRemoteRequest::Create {
            group_name: "not-photos".to_string(),
            device_id: "device-a".to_string(),
            storage_mode: "eager".to_string(),
        },
        result_group_id: Some("group-1".to_string()),
    });
    assert_eq!(
        qualify_enrollment_remote_identity(&operation, &remote),
        RemoteIdentityQualification::Mismatch { fields: vec![IdentityField::GroupName] }
    );
}

#[test]
fn enrollment_create_prepared_remote_result_group_mismatch() {
    let operation = enrollment_op(
        EnrollmentKind::Create,
        Some("group-1"),
        None,
        EnrollmentOperationState::Prepared,
    );
    let remote = RemoteEvidence::Found(EnrollmentOperationRecord {
        status: EnrollmentRemoteStatus::Prepared,
        request_fingerprint: "fp".to_string(),
        request: EnrollmentRemoteRequest::Create {
            group_name: "photos".to_string(),
            device_id: "device-a".to_string(),
            storage_mode: "eager".to_string(),
        },
        result_group_id: Some("group-DIFFERENT".to_string()),
    });
    assert_eq!(
        qualify_enrollment_remote_identity(&operation, &remote),
        RemoteIdentityQualification::Mismatch { fields: vec![IdentityField::ResultGroupId] }
    );
}

#[test]
fn enrollment_create_prepared_remote_result_group_missing_is_not_comparable() {
    let operation = enrollment_op(
        EnrollmentKind::Create,
        Some("group-1"),
        None,
        EnrollmentOperationState::Prepared,
    );
    let remote = RemoteEvidence::Found(EnrollmentOperationRecord {
        status: EnrollmentRemoteStatus::Prepared,
        request_fingerprint: "fp".to_string(),
        request: EnrollmentRemoteRequest::Create {
            group_name: "photos".to_string(),
            device_id: "device-a".to_string(),
            storage_mode: "eager".to_string(),
        },
        result_group_id: None,
    });
    assert_eq!(
        qualify_enrollment_remote_identity(&operation, &remote),
        RemoteIdentityQualification::NotComparable {
            reasons: vec![IdentityQualificationReason::MissingRemoteResultGroupId]
        }
    );
}

/// `Cancelled` with no `result_group_id` is a legitimate terminal
/// shape (see `classify_enrollment`'s own `enrollment_result_shape_issue`
/// for the full contract reasoning) -- unlike `Prepared`/`Active`, its
/// absence here must never be `NotComparable`; every other field still
/// agrees, so this is `Exact`.
#[test]
fn enrollment_create_cancelled_with_no_result_group_id_is_exact() {
    let operation = enrollment_op(
        EnrollmentKind::Create,
        Some("group-1"),
        Some("photos"),
        EnrollmentOperationState::CancelPending,
    );
    let remote = RemoteEvidence::Found(EnrollmentOperationRecord {
        status: EnrollmentRemoteStatus::Cancelled,
        request_fingerprint: "fp".to_string(),
        request: EnrollmentRemoteRequest::Create {
            group_name: "photos".to_string(),
            device_id: "device-a".to_string(),
            storage_mode: "eager".to_string(),
        },
        result_group_id: None,
    });
    assert_eq!(
        qualify_enrollment_remote_identity(&operation, &remote),
        RemoteIdentityQualification::Exact
    );
}

/// A device_id mismatch is definite evidence this is NOT the same
/// request -- it must survive even though the group comparison
/// separately cannot be made (`result_group_id` missing). Discarding it
/// in favor of `NotComparable` (an earlier version of this function
/// did) would hide a real mismatch from the classifier.
#[test]
fn enrollment_create_device_mismatch_survives_a_missing_result_group_id() {
    let operation = enrollment_op(
        EnrollmentKind::Create,
        Some("group-1"),
        None,
        EnrollmentOperationState::Prepared,
    );
    let remote = RemoteEvidence::Found(EnrollmentOperationRecord {
        status: EnrollmentRemoteStatus::Prepared,
        request_fingerprint: "fp".to_string(),
        request: EnrollmentRemoteRequest::Create {
            group_name: "photos".to_string(),
            device_id: "device-DIFFERENT".to_string(),
            storage_mode: "eager".to_string(),
        },
        result_group_id: None,
    });
    assert_eq!(
        qualify_enrollment_remote_identity(&operation, &remote),
        RemoteIdentityQualification::Mismatch { fields: vec![IdentityField::DeviceId] }
    );
}

/// Same as above, for the `PreparePending` branch (missing local
/// `group_name`).
#[test]
fn enrollment_create_storage_mode_mismatch_survives_a_missing_local_group_name() {
    let operation =
        enrollment_op(EnrollmentKind::Create, None, None, EnrollmentOperationState::PreparePending);
    let remote = RemoteEvidence::Found(EnrollmentOperationRecord {
        status: EnrollmentRemoteStatus::Preparing,
        request_fingerprint: "fp".to_string(),
        request: EnrollmentRemoteRequest::Create {
            group_name: "photos".to_string(),
            device_id: "device-a".to_string(),
            storage_mode: "on-demand".to_string(),
        },
        result_group_id: None,
    });
    assert_eq!(
        qualify_enrollment_remote_identity(&operation, &remote),
        RemoteIdentityQualification::Mismatch { fields: vec![IdentityField::StorageMode] }
    );
}

/// Same as above, for the `Join` branch (missing local `group_id` --
/// the defensive case that should be unreachable against a
/// strictly-decoded row, but must still not swallow a real mismatch).
#[test]
fn enrollment_join_device_mismatch_survives_a_missing_local_group_id() {
    let operation = enrollment_op(
        EnrollmentKind::Join,
        None,
        None,
        EnrollmentOperationState::ActivationPending,
    );
    let remote = RemoteEvidence::Found(EnrollmentOperationRecord {
        status: EnrollmentRemoteStatus::Prepared,
        request_fingerprint: "fp".to_string(),
        request: EnrollmentRemoteRequest::Join {
            group_id: "group-1".to_string(),
            device_id: "device-DIFFERENT".to_string(),
            storage_mode: "eager".to_string(),
        },
        result_group_id: None,
    });
    assert_eq!(
        qualify_enrollment_remote_identity(&operation, &remote),
        RemoteIdentityQualification::Mismatch { fields: vec![IdentityField::DeviceId] }
    );
}

#[test]
fn enrollment_join_request_group_mismatch() {
    let operation = enrollment_op(
        EnrollmentKind::Join,
        Some("group-1"),
        None,
        EnrollmentOperationState::ActivationPending,
    );
    let remote = RemoteEvidence::Found(EnrollmentOperationRecord {
        status: EnrollmentRemoteStatus::Prepared,
        request_fingerprint: "fp".to_string(),
        request: EnrollmentRemoteRequest::Join {
            group_id: "group-DIFFERENT".to_string(),
            device_id: "device-a".to_string(),
            storage_mode: "eager".to_string(),
        },
        result_group_id: None,
    });
    assert_eq!(
        qualify_enrollment_remote_identity(&operation, &remote),
        RemoteIdentityQualification::Mismatch { fields: vec![IdentityField::GroupId] }
    );
}

#[test]
fn enrollment_remote_request_kind_mismatch() {
    let operation = enrollment_op(
        EnrollmentKind::Create,
        Some("group-1"),
        None,
        EnrollmentOperationState::Prepared,
    );
    let remote = RemoteEvidence::Found(EnrollmentOperationRecord {
        status: EnrollmentRemoteStatus::Prepared,
        request_fingerprint: "fp".to_string(),
        request: EnrollmentRemoteRequest::Join {
            group_id: "group-1".to_string(),
            device_id: "device-a".to_string(),
            storage_mode: "eager".to_string(),
        },
        result_group_id: Some("group-1".to_string()),
    });
    assert_eq!(
        qualify_enrollment_remote_identity(&operation, &remote),
        RemoteIdentityQualification::Mismatch { fields: vec![IdentityField::Kind] }
    );
}

#[test]
fn enrollment_remote_record_not_found_is_not_evaluated() {
    let operation = enrollment_op(
        EnrollmentKind::Create,
        Some("group-1"),
        None,
        EnrollmentOperationState::Prepared,
    );
    assert_eq!(
        qualify_enrollment_remote_identity(&operation, &RemoteEvidence::RecordNotFound),
        RemoteIdentityQualification::NotEvaluated {
            reason: IdentityNotEvaluatedReason::RecordNotFound
        }
    );
}

#[test]
fn enrollment_remote_unavailable_is_not_evaluated() {
    let operation = enrollment_op(
        EnrollmentKind::Create,
        Some("group-1"),
        None,
        EnrollmentOperationState::Prepared,
    );
    assert_eq!(
        qualify_enrollment_remote_identity(
            &operation,
            &RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::Network }
        ),
        RemoteIdentityQualification::NotEvaluated {
            reason: IdentityNotEvaluatedReason::RemoteUnavailable
        }
    );
}

// ===== Membership =====

fn membership_op(
    commit_mode: MembershipCommitMode,
    group_ids: Vec<&str>,
    target_device_ids: Vec<&str>,
    lease_ids: Vec<Option<&str>>,
) -> MembershipOperation {
    MembershipOperation {
        operation_id: "op-1".to_string(),
        action: MembershipOperationAction::Revoke,
        commit_mode,
        removed_device_id: "device-b".to_string(),
        group_ids: group_ids.into_iter().map(str::to_string).collect(),
        target_device_ids: target_device_ids.into_iter().map(str::to_string).collect(),
        lease_ids: lease_ids.into_iter().map(|l| l.map(str::to_string)).collect(),
        state: MembershipOperationState::Prepared,
        durability_scope: MembershipDurabilityScope::Known,
        latch_group_ids: vec![],
        last_error: None,
        created_at_unix: 1,
        updated_at_unix: 1,
    }
}

#[test]
fn membership_all_four_commit_modes_produce_the_expected_canonical_request() {
    let plain_revoke =
        membership_op(MembershipCommitMode::PlainRevoke, vec!["group-1"], vec![], vec![]);
    assert_eq!(
        crate::application::membership_operation_identity::expected_membership_remote_request(
            &plain_revoke
        )
        .mode,
        "guarded"
    );

    let guarded_revoke = membership_op(
        MembershipCommitMode::GuardedRevoke,
        vec!["group-1"],
        vec!["device-c"],
        vec![Some("lease-1")],
    );
    assert_eq!(
        crate::application::membership_operation_identity::expected_membership_remote_request(
            &guarded_revoke
        )
        .mode,
        "guarded"
    );

    let plain_remove =
        membership_op(MembershipCommitMode::PlainRemoveDevice, vec![], vec![], vec![]);
    assert_eq!(
        crate::application::membership_operation_identity::expected_membership_remote_request(
            &plain_remove
        )
        .mode,
        "plain"
    );

    let handoff_remove = membership_op(
        MembershipCommitMode::HandoffRemoveDevice,
        vec!["group-1", "group-2"],
        vec!["device-c", "device-d"],
        vec![Some("lease-1"), Some("lease-2")],
    );
    assert_eq!(
        crate::application::membership_operation_identity::expected_membership_remote_request(
            &handoff_remove
        )
        .mode,
        "guarded"
    );
}

#[test]
fn membership_canonical_request_orders_groups_by_group_id() {
    let operation = membership_op(
        MembershipCommitMode::HandoffRemoveDevice,
        vec!["group-z", "group-a"],
        vec!["device-z", "device-a"],
        vec![Some("lease-z"), Some("lease-a")],
    );
    let request =
        crate::application::membership_operation_identity::expected_membership_remote_request(
            &operation,
        );
    assert_eq!(
        request.groups.iter().map(|g| g.group_id.as_str()).collect::<Vec<_>>(),
        vec!["group-a", "group-z"]
    );
}

fn membership_record(request: MembershipRemoteRequest) -> MembershipOperationRecord {
    MembershipOperationRecord {
        status: MembershipRemoteStatus::Committed,
        action: request.action.clone(),
        removed_device_id: request.removed_device_id.clone(),
        request_fingerprint: "fp".to_string(),
        request,
        result: None,
        rejection_code: None,
        rejection_detail: None,
    }
}

#[test]
fn membership_action_mismatch() {
    let operation =
        membership_op(MembershipCommitMode::PlainRevoke, vec!["group-1"], vec![], vec![]);
    let record = membership_record(MembershipRemoteRequest {
        action: "remove-device".to_string(),
        removed_device_id: "device-b".to_string(),
        mode: "guarded".to_string(),
        groups: vec![MembershipRemoteRequestGroup {
            group_id: "group-1".to_string(),
            target_device_id: None,
            lease_id: None,
        }],
    });
    assert_eq!(
        qualify_membership_remote_identity(&operation, &RemoteEvidence::Found(record)),
        RemoteIdentityQualification::Mismatch { fields: vec![IdentityField::Action] }
    );
}

#[test]
fn membership_removed_device_mismatch() {
    let operation =
        membership_op(MembershipCommitMode::PlainRevoke, vec!["group-1"], vec![], vec![]);
    let record = membership_record(MembershipRemoteRequest {
        action: "revoke".to_string(),
        removed_device_id: "device-DIFFERENT".to_string(),
        mode: "guarded".to_string(),
        groups: vec![MembershipRemoteRequestGroup {
            group_id: "group-1".to_string(),
            target_device_id: None,
            lease_id: None,
        }],
    });
    assert_eq!(
        qualify_membership_remote_identity(&operation, &RemoteEvidence::Found(record)),
        RemoteIdentityQualification::Mismatch { fields: vec![IdentityField::RemovedDeviceId] }
    );
}

#[test]
fn membership_mode_mismatch() {
    let operation =
        membership_op(MembershipCommitMode::PlainRevoke, vec!["group-1"], vec![], vec![]);
    let record = membership_record(MembershipRemoteRequest {
        action: "revoke".to_string(),
        removed_device_id: "device-b".to_string(),
        mode: "plain".to_string(),
        groups: vec![MembershipRemoteRequestGroup {
            group_id: "group-1".to_string(),
            target_device_id: None,
            lease_id: None,
        }],
    });
    assert_eq!(
        qualify_membership_remote_identity(&operation, &RemoteEvidence::Found(record)),
        RemoteIdentityQualification::Mismatch { fields: vec![IdentityField::CommitMode] }
    );
}

#[test]
fn membership_group_tuple_target_mismatch() {
    let operation = membership_op(
        MembershipCommitMode::GuardedRevoke,
        vec!["group-1"],
        vec!["device-c"],
        vec![Some("lease-1")],
    );
    let record = membership_record(MembershipRemoteRequest {
        action: "revoke".to_string(),
        removed_device_id: "device-b".to_string(),
        mode: "guarded".to_string(),
        groups: vec![MembershipRemoteRequestGroup {
            group_id: "group-1".to_string(),
            target_device_id: Some("device-DIFFERENT".to_string()),
            lease_id: Some("lease-1".to_string()),
        }],
    });
    assert_eq!(
        qualify_membership_remote_identity(&operation, &RemoteEvidence::Found(record)),
        RemoteIdentityQualification::Mismatch { fields: vec![IdentityField::GroupTuples] }
    );
}

#[test]
fn membership_group_tuple_lease_mismatch() {
    let operation = membership_op(
        MembershipCommitMode::GuardedRevoke,
        vec!["group-1"],
        vec!["device-c"],
        vec![Some("lease-1")],
    );
    let record = membership_record(MembershipRemoteRequest {
        action: "revoke".to_string(),
        removed_device_id: "device-b".to_string(),
        mode: "guarded".to_string(),
        groups: vec![MembershipRemoteRequestGroup {
            group_id: "group-1".to_string(),
            target_device_id: Some("device-c".to_string()),
            lease_id: Some("lease-DIFFERENT".to_string()),
        }],
    });
    assert_eq!(
        qualify_membership_remote_identity(&operation, &RemoteEvidence::Found(record)),
        RemoteIdentityQualification::Mismatch { fields: vec![IdentityField::GroupTuples] }
    );
}

#[test]
fn membership_fingerprint_match_alone_does_not_force_exact() {
    // `request_fingerprint` is never even read by this qualification --
    // only the canonical `request` fields are compared.
    let operation =
        membership_op(MembershipCommitMode::PlainRevoke, vec!["group-1"], vec![], vec![]);
    let mut record = membership_record(MembershipRemoteRequest {
        action: "revoke".to_string(),
        removed_device_id: "device-DIFFERENT".to_string(),
        mode: "guarded".to_string(),
        groups: vec![MembershipRemoteRequestGroup {
            group_id: "group-1".to_string(),
            target_device_id: None,
            lease_id: None,
        }],
    });
    record.request_fingerprint = "identical-fingerprint".to_string();
    assert_ne!(
        qualify_membership_remote_identity(&operation, &RemoteEvidence::Found(record)),
        RemoteIdentityQualification::Exact
    );
}

#[test]
fn membership_exact_match() {
    let operation = membership_op(
        MembershipCommitMode::GuardedRevoke,
        vec!["group-1"],
        vec!["device-c"],
        vec![Some("lease-1")],
    );
    let record = membership_record(
        crate::application::membership_operation_identity::expected_membership_remote_request(
            &operation,
        ),
    );
    assert_eq!(
        qualify_membership_remote_identity(&operation, &RemoteEvidence::Found(record)),
        RemoteIdentityQualification::Exact
    );
}

// ===== Role loss =====

fn role_loss_op(action: RoleLossAction, local_path: Option<&str>) -> RoleLossOperation {
    RoleLossOperation {
        operation_id: "op-1".to_string(),
        group_id: "group-1".to_string(),
        source_device_id: "device-c".to_string(),
        target_device_id: "device-d".to_string(),
        lease_id: "lease-1".to_string(),
        worker_membership_generation: None,
        action,
        state: yadorilink_replica_domain::session_state::RoleLossOperationState::WorkerCommitted,
        local_path: local_path.map(str::to_string),
        attempts: 0,
        created_at_unix: 1,
        updated_at_unix: 1,
    }
}

fn role_loss_record(action: &str) -> RoleLossOperationRecord {
    RoleLossOperationRecord {
        group_id: "group-1".to_string(),
        source_device_id: "device-c".to_string(),
        target_device_id: "device-d".to_string(),
        lease_id: Some("lease-1".to_string()),
        action: action.to_string(),
        membership_generation: 4,
        committed_at_unix: 1,
    }
}

#[test]
fn role_loss_demote_maps_to_wire_demote() {
    let operation = role_loss_op(RoleLossAction::Demote, Some("/home/alice/Photos"));
    let record = role_loss_record("demote");
    assert_eq!(
        qualify_role_loss_remote_identity(&operation, &RemoteEvidence::Found(record)),
        RemoteIdentityQualification::Exact
    );
}

#[test]
fn role_loss_unlink_maps_to_wire_demote() {
    let operation = role_loss_op(RoleLossAction::Unlink, Some("/home/alice/Photos"));
    let record = role_loss_record("demote");
    assert_eq!(
        qualify_role_loss_remote_identity(&operation, &RemoteEvidence::Found(record)),
        RemoteIdentityQualification::Exact
    );
}

#[test]
fn role_loss_revoke_maps_to_wire_revoke() {
    let operation = role_loss_op(RoleLossAction::Revoke, Some("/home/alice/Photos"));
    let record = role_loss_record("revoke");
    assert_eq!(
        qualify_role_loss_remote_identity(&operation, &RemoteEvidence::Found(record)),
        RemoteIdentityQualification::Exact
    );
}

#[test]
fn role_loss_group_mismatch() {
    let operation = role_loss_op(RoleLossAction::Demote, Some("/home/alice/Photos"));
    let mut record = role_loss_record("demote");
    record.group_id = "group-DIFFERENT".to_string();
    assert_eq!(
        qualify_role_loss_remote_identity(&operation, &RemoteEvidence::Found(record)),
        RemoteIdentityQualification::Mismatch { fields: vec![IdentityField::GroupId] }
    );
}

#[test]
fn role_loss_source_mismatch() {
    let operation = role_loss_op(RoleLossAction::Demote, Some("/home/alice/Photos"));
    let mut record = role_loss_record("demote");
    record.source_device_id = "device-DIFFERENT".to_string();
    assert_eq!(
        qualify_role_loss_remote_identity(&operation, &RemoteEvidence::Found(record)),
        RemoteIdentityQualification::Mismatch { fields: vec![IdentityField::SourceDeviceId] }
    );
}

#[test]
fn role_loss_target_mismatch() {
    let operation = role_loss_op(RoleLossAction::Demote, Some("/home/alice/Photos"));
    let mut record = role_loss_record("demote");
    record.target_device_id = "device-DIFFERENT".to_string();
    assert_eq!(
        qualify_role_loss_remote_identity(&operation, &RemoteEvidence::Found(record)),
        RemoteIdentityQualification::Mismatch { fields: vec![IdentityField::TargetDeviceId] }
    );
}

#[test]
fn role_loss_lease_mismatch() {
    let operation = role_loss_op(RoleLossAction::Demote, Some("/home/alice/Photos"));
    let mut record = role_loss_record("demote");
    record.lease_id = Some("lease-DIFFERENT".to_string());
    assert_eq!(
        qualify_role_loss_remote_identity(&operation, &RemoteEvidence::Found(record)),
        RemoteIdentityQualification::Mismatch { fields: vec![IdentityField::LeaseId] }
    );
}

#[test]
fn role_loss_local_link_policy_is_not_an_identity_mismatch() {
    let operation = role_loss_op(RoleLossAction::Demote, Some("/home/alice/Photos"));
    // Still eager (as if the local demotion has not happened yet) --
    // this must NOT be reported as a mismatch; it is a state question
    // for the classifier, not this qualification's.
    let link = link_evidence("group-1", "/home/alice/Photos");
    assert_eq!(link.materialization_policy, MaterializationPolicy::Eager);
    assert_eq!(
        qualify_role_loss_link_identity(&operation, &LocalObservation::Found(link)),
        ObservationQualification::Exact
    );
}

#[test]
fn role_loss_membership_generation_is_not_part_of_identity() {
    let mut operation = role_loss_op(RoleLossAction::Demote, Some("/home/alice/Photos"));
    operation.worker_membership_generation = Some(2);
    let mut record = role_loss_record("demote");
    record.membership_generation = 99;
    assert_eq!(
        qualify_role_loss_remote_identity(&operation, &RemoteEvidence::Found(record)),
        RemoteIdentityQualification::Exact,
        "membership_generation is an outcome, not a request identity field"
    );
}

#[test]
fn role_loss_link_group_mismatch() {
    let operation = role_loss_op(RoleLossAction::Demote, Some("/home/alice/Photos"));
    let link = LocalObservation::Found(link_evidence("group-DIFFERENT", "/home/alice/Photos"));
    assert_eq!(
        qualify_role_loss_link_identity(&operation, &link),
        ObservationQualification::Mismatch { fields: vec![IdentityField::GroupId] }
    );
}
