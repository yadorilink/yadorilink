//! Converts this module's Rust types into the
//! `daemon_control.proto` wire shapes for `yadorilink recovery show`.
//! Centralized here so `control_socket.rs` never contains a large
//! conversion match block directly -- every wire slug is produced either by
//! a type's own `as_str()` (mirroring
//! [`super::RecoveryReasonCode::as_str`]) or by an exhaustive match in this
//! file. `format!("{value:?}")` is never used for a wire value: a Debug
//! representation is not a stable contract.

use crate::recovery::{
    RecoveryOperationKey, RecoveryOperationSummary, RecoverySeverity, RecoverySnapshotRevision,
};
use yadorilink_ipc_proto::daemonctl::{
    show_recovery_operation_response, InvalidRecoveryOperation as InvalidRecoveryOperationProto,
    RecoveryDiagnosis as RecoveryDiagnosisProto,
    RecoveryEvidenceQualification as RecoveryEvidenceQualificationProto,
    RecoveryLocalEvidenceChanged as RecoveryLocalEvidenceChangedProto,
    RecoveryObservationQualification as RecoveryObservationQualificationProto,
    RecoveryOperation as RecoveryOperationProto, RecoveryOperationKey as RecoveryOperationKeyProto,
    RecoveryOperationNotFound as RecoveryOperationNotFoundProto,
    RecoveryRemoteIdentityQualification as RecoveryRemoteIdentityQualificationProto,
    RecoveryRemoteState as RecoveryRemoteStateProto,
    RecoverySnapshotAfterLookup as RecoverySnapshotAfterLookupProto,
    RecoverySnapshotRevision as RecoverySnapshotRevisionProto, ShowRecoveryOperationResponse,
};
use yadorilink_replica_domain::recovery::InvalidRecoveryOperation;

use crate::coordination_client::RemoteEvidenceErrorCategory;

use super::model::{
    IdentityField, IdentityNotEvaluatedReason, IdentityQualificationReason,
    ObservationQualification, RemoteIdentityQualification,
};
use super::service::{SnapshotAfterLookup, StableDiagnosisOutcome};
use super::{RecoveryDiagnosis, RecoveryEvidenceQualification, RecoveryRemoteState};

pub(crate) fn recovery_summary_to_proto(op: &RecoveryOperationSummary) -> RecoveryOperationProto {
    RecoveryOperationProto {
        operation_id: op.operation_id.clone(),
        domain: op.domain.as_str().to_string(),
        action: op.action.clone(),
        state: op.state.clone(),
        severity: match op.severity {
            RecoverySeverity::Pending => "pending",
            RecoverySeverity::Retrying => "retrying",
            RecoverySeverity::DurabilityUnknown => "durability-unknown",
            RecoverySeverity::Blocked => "blocked",
            // Never actually produced on a decoded summary -- see
            // `RecoverySeverity::Invalid`'s own doc comment.
            RecoverySeverity::Invalid => "invalid",
        }
        .to_string(),
        group_ids: op.group_ids.clone(),
        device_id: op.device_id.clone(),
        local_path: op.local_path.clone(),
        // Never negative: `attempts < 0` is decode-time corruption, isolated
        // into `RecoveryInventory::invalid` before a summary is ever built --
        // this conversion only ever receives an already-validated value, so
        // it must not silently repair one that somehow slipped through by
        // clamping to zero.
        attempts: op.attempts as u64,
        last_error: op.last_error.clone(),
        created_at_unix: op.created_at_unix,
        updated_at_unix: op.updated_at_unix,
    }
}

pub(crate) fn invalid_recovery_operation_to_proto(
    op: &InvalidRecoveryOperation,
) -> InvalidRecoveryOperationProto {
    InvalidRecoveryOperationProto {
        operation_id: op.operation_id.clone(),
        domain: op.domain.as_str().to_string(),
        raw_state: op.raw_state.clone(),
        detail: op.detail.clone(),
    }
}

fn operation_key_to_proto(key: &RecoveryOperationKey) -> RecoveryOperationKeyProto {
    RecoveryOperationKeyProto {
        domain: key.domain.as_str().to_string(),
        operation_id: key.operation_id.clone(),
    }
}

fn snapshot_revision_to_proto(
    revision: &RecoverySnapshotRevision,
) -> RecoverySnapshotRevisionProto {
    RecoverySnapshotRevisionProto {
        state: revision.state.clone(),
        updated_at_unix: revision.updated_at_unix,
        diagnostic_fingerprint: revision.full_evidence_fingerprint,
    }
}

fn snapshot_after_lookup_to_proto(after: &SnapshotAfterLookup) -> RecoverySnapshotAfterLookupProto {
    match after {
        SnapshotAfterLookup::Found { revision } => RecoverySnapshotAfterLookupProto {
            outcome: "found".to_string(),
            revision: Some(snapshot_revision_to_proto(revision)),
            raw_state: None,
            detail: None,
        },
        SnapshotAfterLookup::OperationNotFound => RecoverySnapshotAfterLookupProto {
            outcome: "operation_not_found".to_string(),
            revision: None,
            raw_state: None,
            detail: None,
        },
        SnapshotAfterLookup::InvalidOperation { raw_state, detail } => {
            RecoverySnapshotAfterLookupProto {
                outcome: "invalid_operation".to_string(),
                revision: None,
                raw_state: raw_state.clone(),
                detail: Some(detail.clone()),
            }
        }
    }
}

fn observation_qualification_to_proto(
    q: &ObservationQualification,
) -> RecoveryObservationQualificationProto {
    match q {
        ObservationQualification::ConfirmedAbsent => RecoveryObservationQualificationProto {
            status: "confirmed_absent".to_string(),
            mismatch_fields: vec![],
            detail: None,
        },
        ObservationQualification::Exact => RecoveryObservationQualificationProto {
            status: "exact".to_string(),
            mismatch_fields: vec![],
            detail: None,
        },
        ObservationQualification::Mismatch { fields } => RecoveryObservationQualificationProto {
            status: "mismatch".to_string(),
            mismatch_fields: fields
                .iter()
                .copied()
                .map(IdentityField::as_str)
                .map(str::to_string)
                .collect(),
            detail: None,
        },
        ObservationQualification::Invalid { detail } => RecoveryObservationQualificationProto {
            status: "invalid".to_string(),
            mismatch_fields: vec![],
            detail: Some(detail.clone()),
        },
        ObservationQualification::Ambiguous { detail } => RecoveryObservationQualificationProto {
            status: "ambiguous".to_string(),
            mismatch_fields: vec![],
            detail: Some(detail.clone()),
        },
    }
}

fn remote_identity_qualification_to_proto(
    q: &RemoteIdentityQualification,
) -> RecoveryRemoteIdentityQualificationProto {
    match q {
        RemoteIdentityQualification::Exact => RecoveryRemoteIdentityQualificationProto {
            status: "exact".to_string(),
            mismatch_fields: vec![],
            not_comparable_reasons: vec![],
            not_evaluated_reason: None,
        },
        RemoteIdentityQualification::Mismatch { fields } => {
            RecoveryRemoteIdentityQualificationProto {
                status: "mismatch".to_string(),
                mismatch_fields: fields
                    .iter()
                    .copied()
                    .map(IdentityField::as_str)
                    .map(str::to_string)
                    .collect(),
                not_comparable_reasons: vec![],
                not_evaluated_reason: None,
            }
        }
        RemoteIdentityQualification::NotComparable { reasons } => {
            RecoveryRemoteIdentityQualificationProto {
                status: "not_comparable".to_string(),
                mismatch_fields: vec![],
                not_comparable_reasons: reasons
                    .iter()
                    .copied()
                    .map(IdentityQualificationReason::as_str)
                    .map(str::to_string)
                    .collect(),
                not_evaluated_reason: None,
            }
        }
        RemoteIdentityQualification::NotEvaluated { reason } => {
            RecoveryRemoteIdentityQualificationProto {
                status: "not_evaluated".to_string(),
                mismatch_fields: vec![],
                not_comparable_reasons: vec![],
                not_evaluated_reason: Some(reason_not_evaluated_to_str(*reason).to_string()),
            }
        }
    }
}

fn reason_not_evaluated_to_str(reason: IdentityNotEvaluatedReason) -> &'static str {
    reason.as_str()
}

fn evidence_qualification_to_proto(
    q: &RecoveryEvidenceQualification,
) -> RecoveryEvidenceQualificationProto {
    match q {
        RecoveryEvidenceQualification::Enrollment(q) => RecoveryEvidenceQualificationProto {
            link: Some(observation_qualification_to_proto(&q.link)),
            pending_marker: Some(observation_qualification_to_proto(&q.pending_marker)),
            remote_identity: Some(remote_identity_qualification_to_proto(&q.remote_identity)),
        },
        RecoveryEvidenceQualification::Membership(q) => RecoveryEvidenceQualificationProto {
            link: None,
            pending_marker: None,
            remote_identity: Some(remote_identity_qualification_to_proto(&q.remote_identity)),
        },
        RecoveryEvidenceQualification::RoleLoss(q) => RecoveryEvidenceQualificationProto {
            link: Some(observation_qualification_to_proto(&q.link)),
            pending_marker: None,
            remote_identity: Some(remote_identity_qualification_to_proto(&q.remote_identity)),
        },
    }
}

fn unavailable_category_to_str(category: RemoteEvidenceErrorCategory) -> &'static str {
    match category {
        RemoteEvidenceErrorCategory::Network => "network",
        RemoteEvidenceErrorCategory::Timeout => "timeout",
        RemoteEvidenceErrorCategory::ServerError => "server_error",
        RemoteEvidenceErrorCategory::Unauthorized => "unauthorized",
        RemoteEvidenceErrorCategory::MalformedResponse => "malformed_response",
        RemoteEvidenceErrorCategory::Unsupported => "unsupported",
        RemoteEvidenceErrorCategory::Pending => "pending",
    }
}

fn remote_state_to_proto(remote: RecoveryRemoteState) -> RecoveryRemoteStateProto {
    use crate::coordination_client::{EnrollmentRemoteStatus, MembershipRemoteStatus};
    match remote {
        RecoveryRemoteState::Enrollment(status) => RecoveryRemoteStateProto {
            status: match status {
                EnrollmentRemoteStatus::Preparing => "preparing",
                EnrollmentRemoteStatus::Prepared => "prepared",
                EnrollmentRemoteStatus::Active => "active",
                EnrollmentRemoteStatus::Cancelled => "cancelled",
            }
            .to_string(),
            unavailable_category: None,
        },
        RecoveryRemoteState::Membership(status) => RecoveryRemoteStateProto {
            status: match status {
                MembershipRemoteStatus::Committed => "committed",
                MembershipRemoteStatus::DefinitelyRejected => "definitely_rejected",
            }
            .to_string(),
            unavailable_category: None,
        },
        RecoveryRemoteState::RoleLossCommitted => RecoveryRemoteStateProto {
            status: "role_loss_committed".to_string(),
            unavailable_category: None,
        },
        RecoveryRemoteState::RecordNotFound => RecoveryRemoteStateProto {
            status: "record_not_found".to_string(),
            unavailable_category: None,
        },
        RecoveryRemoteState::Unavailable { category } => RecoveryRemoteStateProto {
            status: "unavailable".to_string(),
            unavailable_category: Some(unavailable_category_to_str(category).to_string()),
        },
    }
}

/// `operation` is the caller-supplied [`RecoveryOperationSummary`] built
/// from the SAME stable snapshot the diagnosis itself was assembled from --
/// never re-derived here, so this conversion can never disagree with what
/// was actually diagnosed.
fn diagnosis_to_proto(
    operation: &RecoveryOperationSummary,
    diagnosis: &RecoveryDiagnosis,
    local_revision: &RecoverySnapshotRevision,
) -> RecoveryDiagnosisProto {
    RecoveryDiagnosisProto {
        operation: Some(recovery_summary_to_proto(operation)),
        remote: Some(remote_state_to_proto(diagnosis.remote_state())),
        recommendation: diagnosis.recommendation().as_str().to_string(),
        reason_codes: diagnosis.reason_codes().iter().map(|r| r.as_str().to_string()).collect(),
        automatic_recovery_safe: diagnosis.automatic_recovery_safe(),
        qualification: Some(evidence_qualification_to_proto(diagnosis.qualification())),
        local_revision: Some(snapshot_revision_to_proto(local_revision)),
    }
}

pub(crate) fn stable_diagnosis_outcome_to_proto(
    outcome: &StableDiagnosisOutcome,
) -> ShowRecoveryOperationResponse {
    use show_recovery_operation_response::Result as WireResult;
    let result = match outcome {
        StableDiagnosisOutcome::Diagnosed { operation, diagnosis, local_revision } => {
            WireResult::Diagnosed(diagnosis_to_proto(operation, diagnosis, local_revision))
        }
        StableDiagnosisOutcome::OperationNotFound { key } => {
            WireResult::NotFound(RecoveryOperationNotFoundProto {
                key: Some(operation_key_to_proto(key)),
            })
        }
        StableDiagnosisOutcome::InvalidOperation { key, raw_state, detail } => {
            WireResult::Invalid(InvalidRecoveryOperationProto {
                operation_id: Some(key.operation_id.clone()),
                domain: key.domain.as_str().to_string(),
                raw_state: raw_state.clone(),
                detail: detail.clone(),
            })
        }
        StableDiagnosisOutcome::LocalEvidenceChanged { key, before, after } => {
            WireResult::LocalEvidenceChanged(RecoveryLocalEvidenceChangedProto {
                key: Some(operation_key_to_proto(key)),
                before: Some(snapshot_revision_to_proto(before)),
                after: Some(snapshot_after_lookup_to_proto(after)),
            })
        }
    };
    ShowRecoveryOperationResponse { result: Some(result) }
}
