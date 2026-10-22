//! Compares a local recovery journal row against its own
//! related local evidence (a link, a pending-enrollment marker) and against
//! a remote lookup's record, producing a typed
//! [`super::model::ObservationQualification`]/
//! [`super::model::RemoteIdentityQualification`] rather than a bare bool or
//! a free-form mismatch string.
//!
//! This module does not decide a recommendation, does not judge whether an
//! observation is EXPECTED for the row's own state, and touches no
//! database or HTTP client -- every input is a value already produced by
//! [`crate::recovery_snapshot::RecoverySnapshotReader::recovery_local_snapshot`]
//! or [`crate::recovery_evidence`]. Whether a `ConfirmedAbsent`/`Mismatch`
//! result here should block automatic recovery is decided by the
//! classifier (`super::classifier`), layered on top.

use crate::recovery::{
    EnrollmentLocalEvidence, LocalLinkEvidence, LocalObservation, MembershipLocalEvidence,
    PendingEnrollmentEvidence, RoleLossLocalEvidence,
};
use yadorilink_replica_domain::session_state::MaterializationPolicy;
use yadorilink_replica_domain::session_state::{
    EnrollmentOperation, EnrollmentOperationState, MembershipOperation, RoleLossAction,
    RoleLossOperation,
};

use crate::coordination_client::{
    EnrollmentOperationRecord, EnrollmentRemoteRequest, EnrollmentRemoteStatus,
    MembershipOperationRecord, RoleLossOperationRecord,
};
use crate::recovery_evidence::RemoteEvidence;

use super::model::{
    EnrollmentEvidenceQualification, IdentityField, IdentityNotEvaluatedReason,
    IdentityQualificationReason, MembershipEvidenceQualification, ObservationQualification,
    RemoteIdentityQualification, RoleLossEvidenceQualification,
};

fn sorted_dedup(mut fields: Vec<IdentityField>) -> Vec<IdentityField> {
    fields.sort();
    fields.dedup();
    fields
}

fn observation_from_fields(fields: Vec<IdentityField>) -> ObservationQualification {
    let fields = sorted_dedup(fields);
    if fields.is_empty() {
        ObservationQualification::Exact
    } else {
        ObservationQualification::Mismatch { fields }
    }
}

fn remote_from_fields(fields: Vec<IdentityField>) -> RemoteIdentityQualification {
    let fields = sorted_dedup(fields);
    if fields.is_empty() {
        RemoteIdentityQualification::Exact
    } else {
        RemoteIdentityQualification::Mismatch { fields }
    }
}

// ===== Enrollment =====

/// `Some` for a validated `"eager"`/`"on-demand"` string (the only two
/// values `validate_enrollment_operation` -- run at journal decode time --
/// ever lets through); `None` would mean a row reached here with a shape
/// that decode should already have rejected.
fn enrollment_storage_mode_policy(storage_mode: &str) -> Option<MaterializationPolicy> {
    match storage_mode {
        "eager" => Some(MaterializationPolicy::Eager),
        "on-demand" => Some(MaterializationPolicy::OnDemand),
        _ => None,
    }
}

/// Compares `operation`'s own link identity against `link` -- deliberately
/// NOT filtered by `operation.group_id.is_some()`: a link existing at
/// `operation.local_path` while `group_id` is still unresolved is itself a
/// mismatch (an unresolved `group_id` cannot be "the same" as any concrete
/// group a link names), not a case to skip comparing.
fn qualify_enrollment_link_identity(
    operation: &EnrollmentOperation,
    link: &LocalObservation<LocalLinkEvidence>,
) -> ObservationQualification {
    let link = match link {
        LocalObservation::ConfirmedAbsent => return ObservationQualification::ConfirmedAbsent,
        LocalObservation::Invalid { detail } => {
            return ObservationQualification::Invalid { detail: detail.clone() };
        }
        LocalObservation::Ambiguous { detail } => {
            return ObservationQualification::Ambiguous { detail: detail.clone() };
        }
        LocalObservation::Found(link) => link,
    };

    let mut fields = Vec::new();
    if operation.local_path != link.local_path {
        fields.push(IdentityField::LocalPath);
    }
    match &operation.group_id {
        Some(group_id) if group_id == &link.group_id => {}
        _ => fields.push(IdentityField::GroupId),
    }
    match enrollment_storage_mode_policy(&operation.storage_mode) {
        Some(expected) if expected == link.materialization_policy => {}
        _ => fields.push(IdentityField::StorageMode),
    }
    observation_from_fields(fields)
}

/// Compares `operation`'s own identity against a `pending_enrollments`
/// marker. `marker.operation_id` is not itself compared: the query that
/// produced this observation (`observe_pending_enrollment`) is BY
/// `operation_id`, so it is structurally guaranteed to already match --
/// there is no [`IdentityField`] variant for it because a mismatch here
/// cannot occur without the snapshot layer itself being broken.
fn qualify_enrollment_marker_identity(
    operation: &EnrollmentOperation,
    marker: &LocalObservation<PendingEnrollmentEvidence>,
) -> ObservationQualification {
    let marker = match marker {
        LocalObservation::ConfirmedAbsent => return ObservationQualification::ConfirmedAbsent,
        LocalObservation::Invalid { detail } => {
            return ObservationQualification::Invalid { detail: detail.clone() };
        }
        LocalObservation::Ambiguous { detail } => {
            return ObservationQualification::Ambiguous { detail: detail.clone() };
        }
        LocalObservation::Found(marker) => marker,
    };

    debug_assert_eq!(
        operation.operation_id, marker.operation_id,
        "observe_pending_enrollment queries by operation_id; this marker cannot belong to a \
         different operation"
    );

    let mut fields = Vec::new();
    if operation.kind != marker.kind {
        fields.push(IdentityField::Kind);
    }
    match &operation.group_id {
        Some(group_id) if group_id == &marker.group_id => {}
        _ => fields.push(IdentityField::GroupId),
    }
    if operation.device_id != marker.device_id {
        fields.push(IdentityField::DeviceId);
    }
    if operation.local_path != marker.local_path {
        fields.push(IdentityField::LocalPath);
    }
    observation_from_fields(fields)
}

fn qualify_enrollment_remote_identity(
    operation: &EnrollmentOperation,
    remote: &RemoteEvidence<EnrollmentOperationRecord>,
) -> RemoteIdentityQualification {
    let record = match remote {
        RemoteEvidence::RecordNotFound => {
            return RemoteIdentityQualification::NotEvaluated {
                reason: IdentityNotEvaluatedReason::RecordNotFound,
            };
        }
        RemoteEvidence::Unavailable { .. } => {
            return RemoteIdentityQualification::NotEvaluated {
                reason: IdentityNotEvaluatedReason::RemoteUnavailable,
            };
        }
        RemoteEvidence::Found(record) => record,
    };

    match (&operation.kind, &record.request) {
        (
            yadorilink_replica_domain::session_state::EnrollmentKind::Create,
            EnrollmentRemoteRequest::Create { group_name, device_id, storage_mode },
        ) => {
            let mut fields = Vec::new();
            if device_id != &operation.device_id {
                fields.push(IdentityField::DeviceId);
            }
            // The remote CREATOR EDGE is always "eager" by construction
            // (see `EnrollmentRemoteRequest`'s own doc comment) -- checked
            // against the wire string directly, not through
            // `enrollment_storage_mode_policy`, since `record.request`'s
            // `storage_mode` is filled in as a fixed constant, not read off
            // the wire. This is NOT the same field as `operation.storage_mode`:
            // that records the CALLER's own requested LOCAL materialization
            // mode (`CreateAndLinkCommand::on_demand` -- see
            // `EnrollmentService::create_and_link`), which can legitimately
            // be "on-demand" even for a Create row. Comparing the two would
            // be comparing unrelated concepts, not an identity check --
            // `operation.storage_mode` belongs in the LINK comparison
            // (`qualify_enrollment_link_identity`, against
            // `link.materialization_policy`), not here.
            if storage_mode != "eager" {
                fields.push(IdentityField::StorageMode);
            }
            // `group_name` is compared regardless of state: `mark_enrollment_operation_prepared`
            // only ever sets `group_id`, it never clears `group_name` --
            // the original request's name stays available (and worth
            // checking) for the whole lifetime of a Create row, not just
            // while `PreparePending`. A missing field needed for a
            // comparison is reported as `NotComparable` ONLY if nothing
            // else already proved a mismatch -- `device_id`/`storage_mode`/
            // `group_name` disagreeing is itself definite evidence this is
            // NOT the same request, and must never be discarded just
            // because a later comparison separately couldn't be made. See
            // the analogous reasoning in the `Join` arm below.
            match operation.group_name.as_deref() {
                Some(local_group_name) => {
                    if group_name != local_group_name {
                        fields.push(IdentityField::GroupName);
                    }
                }
                None if fields.is_empty()
                    && operation.state == EnrollmentOperationState::PreparePending =>
                {
                    return RemoteIdentityQualification::NotComparable {
                        reasons: vec![IdentityQualificationReason::MissingLocalGroupName],
                    };
                }
                None => {}
            }
            // The RESULTING group id is compared whenever the remote
            // record actually carries one, regardless of `status` -- a
            // `Some` value is always comparable content. Its ABSENCE is
            // only `NotComparable` for `Prepared`/`Active`, which the
            // Worker's own contract guarantees always carry one; a
            // `Preparing` or `Cancelled` record legitimately has none (a
            // `Cancelled` record's own `settleOperation(..., resultJson:
            // null)` path is a normal terminal outcome, not a malformed
            // one -- see `enrollment_result_shape_issue`'s identical
            // reasoning on the classifier side), so there is simply
            // nothing more to compare there, not a missing-field error.
            match record.result_group_id.as_deref() {
                Some(result_group_id) => match operation.group_id.as_deref() {
                    Some(local_group_id) => {
                        if result_group_id != local_group_id {
                            fields.push(IdentityField::ResultGroupId);
                        }
                    }
                    None if fields.is_empty() => {
                        return RemoteIdentityQualification::NotComparable {
                            reasons: vec![IdentityQualificationReason::MissingLocalGroupId],
                        };
                    }
                    None => {}
                },
                None => {
                    let result_required = matches!(
                        record.status,
                        EnrollmentRemoteStatus::Prepared | EnrollmentRemoteStatus::Active
                    );
                    if result_required && fields.is_empty() {
                        return RemoteIdentityQualification::NotComparable {
                            reasons: vec![IdentityQualificationReason::MissingRemoteResultGroupId],
                        };
                    }
                }
            }
            remote_from_fields(fields)
        }
        (
            yadorilink_replica_domain::session_state::EnrollmentKind::Join,
            EnrollmentRemoteRequest::Join { group_id, device_id, storage_mode },
        ) => {
            let mut fields = Vec::new();
            if device_id != &operation.device_id {
                fields.push(IdentityField::DeviceId);
            }
            if storage_mode != &operation.storage_mode {
                fields.push(IdentityField::StorageMode);
            }
            // A Join row always has a group_id from the moment its journal
            // row is opened (see `EnrollmentOperation::group_id`'s own doc
            // comment) -- unreachable for a strictly-decoded row, kept
            // defensive rather than panicking. As above, a mismatch
            // already found in `device_id`/`storage_mode` must survive
            // even if this defensive case is somehow hit.
            match operation.group_id.as_deref() {
                Some(local_group_id) => {
                    if group_id != local_group_id {
                        fields.push(IdentityField::GroupId);
                    }
                    if let Some(result_group_id) = record.result_group_id.as_deref() {
                        if result_group_id != local_group_id {
                            fields.push(IdentityField::ResultGroupId);
                        }
                    }
                }
                None if fields.is_empty() => {
                    return RemoteIdentityQualification::NotComparable {
                        reasons: vec![IdentityQualificationReason::MissingLocalGroupId],
                    };
                }
                None => {}
            }
            remote_from_fields(fields)
        }
        // The remote request's own variant (Create/Join) disagrees with
        // the local journal row's `kind` -- this operation_id apparently
        // names a fundamentally different request on the coordination
        // plane than what this row was opened for.
        _ => RemoteIdentityQualification::Mismatch { fields: vec![IdentityField::Kind] },
    }
}

pub fn qualify_enrollment(
    local: &EnrollmentLocalEvidence,
    remote: &RemoteEvidence<EnrollmentOperationRecord>,
) -> EnrollmentEvidenceQualification {
    EnrollmentEvidenceQualification {
        link: qualify_enrollment_link_identity(&local.operation, &local.link),
        pending_marker: qualify_enrollment_marker_identity(&local.operation, &local.pending_marker),
        remote_identity: qualify_enrollment_remote_identity(&local.operation, remote),
    }
}

// ===== Membership =====

fn qualify_membership_remote_identity(
    operation: &MembershipOperation,
    remote: &RemoteEvidence<MembershipOperationRecord>,
) -> RemoteIdentityQualification {
    let record = match remote {
        RemoteEvidence::RecordNotFound => {
            return RemoteIdentityQualification::NotEvaluated {
                reason: IdentityNotEvaluatedReason::RecordNotFound,
            };
        }
        RemoteEvidence::Unavailable { .. } => {
            return RemoteIdentityQualification::NotEvaluated {
                reason: IdentityNotEvaluatedReason::RemoteUnavailable,
            };
        }
        RemoteEvidence::Found(record) => record,
    };

    let expected =
        crate::application::membership_operation_identity::expected_membership_remote_request(
            operation,
        );

    let mut fields = Vec::new();
    if record.request.action != expected.action {
        fields.push(IdentityField::Action);
    }
    if record.request.removed_device_id != expected.removed_device_id {
        fields.push(IdentityField::RemovedDeviceId);
    }
    if record.request.mode != expected.mode {
        fields.push(IdentityField::CommitMode);
    }
    if record.request.groups != expected.groups {
        fields.push(IdentityField::GroupTuples);
    }
    remote_from_fields(fields)
}

pub fn qualify_membership(
    local: &MembershipLocalEvidence,
    remote: &RemoteEvidence<MembershipOperationRecord>,
) -> MembershipEvidenceQualification {
    MembershipEvidenceQualification {
        remote_identity: qualify_membership_remote_identity(&local.operation, remote),
    }
}

// ===== Role loss =====

/// Every [`RoleLossAction`] variant maps to a wire string today; `None`
/// is unreachable but kept so a future action variant this build predates
/// fails closed (`NotComparable`) instead of silently miscomparing.
fn role_loss_wire_action(action: RoleLossAction) -> Option<&'static str> {
    match action {
        RoleLossAction::Demote | RoleLossAction::Unlink => Some("demote"),
        RoleLossAction::Revoke => Some("revoke"),
    }
}

/// Compares only identity fields -- `group_id`, and `local_path` when the
/// journal row records one. Deliberately excludes
/// `materialization_policy`/`orphaned`/`paused`: for role-loss those
/// describe whether the LOCAL demotion already happened, which is exactly
/// the state question the classifier answers, not an identity question.
fn qualify_role_loss_link_identity(
    operation: &RoleLossOperation,
    link: &LocalObservation<LocalLinkEvidence>,
) -> ObservationQualification {
    let link = match link {
        LocalObservation::ConfirmedAbsent => return ObservationQualification::ConfirmedAbsent,
        LocalObservation::Invalid { detail } => {
            return ObservationQualification::Invalid { detail: detail.clone() };
        }
        LocalObservation::Ambiguous { detail } => {
            return ObservationQualification::Ambiguous { detail: detail.clone() };
        }
        LocalObservation::Found(link) => link,
    };

    let mut fields = Vec::new();
    if link.group_id != operation.group_id {
        fields.push(IdentityField::GroupId);
    }
    if let Some(local_path) = &operation.local_path {
        if &link.local_path != local_path {
            fields.push(IdentityField::LocalPath);
        }
    }
    observation_from_fields(fields)
}

fn qualify_role_loss_remote_identity(
    operation: &RoleLossOperation,
    remote: &RemoteEvidence<RoleLossOperationRecord>,
) -> RemoteIdentityQualification {
    let record = match remote {
        RemoteEvidence::RecordNotFound => {
            return RemoteIdentityQualification::NotEvaluated {
                reason: IdentityNotEvaluatedReason::RecordNotFound,
            };
        }
        RemoteEvidence::Unavailable { .. } => {
            return RemoteIdentityQualification::NotEvaluated {
                reason: IdentityNotEvaluatedReason::RemoteUnavailable,
            };
        }
        RemoteEvidence::Found(record) => record,
    };

    let Some(expected_action) = role_loss_wire_action(operation.action) else {
        return RemoteIdentityQualification::NotComparable {
            reasons: vec![IdentityQualificationReason::UnsupportedLocalRoleLossAction],
        };
    };

    let mut fields = Vec::new();
    if record.group_id != operation.group_id {
        fields.push(IdentityField::GroupId);
    }
    if record.source_device_id != operation.source_device_id {
        fields.push(IdentityField::SourceDeviceId);
    }
    if record.target_device_id != operation.target_device_id {
        fields.push(IdentityField::TargetDeviceId);
    }
    if record.lease_id.as_deref() != Some(operation.lease_id.as_str()) {
        fields.push(IdentityField::LeaseId);
    }
    if record.action != expected_action {
        fields.push(IdentityField::Action);
    }
    remote_from_fields(fields)
}

pub fn qualify_role_loss(
    local: &RoleLossLocalEvidence,
    remote: &RemoteEvidence<RoleLossOperationRecord>,
) -> RoleLossEvidenceQualification {
    RoleLossEvidenceQualification {
        link: qualify_role_loss_link_identity(&local.operation, &local.link),
        remote_identity: qualify_role_loss_remote_identity(&local.operation, remote),
    }
}

#[cfg(test)]
mod tests;
