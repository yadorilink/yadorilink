//! How the engine's membership results are put on the wire types, shared by the control socket
//! and the embedded host so both refuse and answer a membership change the same way.

use yadorilink_ipc_proto::daemonctl::{
    ApplicationCommandError, ApplicationErrorCode, MembershipHandoffResult,
    ReplicaMembershipCommandOutcome,
};

pub(crate) fn membership_outcome_to_proto(
    outcome: crate::application::ReplicaMembershipOutcome,
) -> ReplicaMembershipCommandOutcome {
    ReplicaMembershipCommandOutcome {
        handoffs: outcome
            .handoffs
            .into_iter()
            .map(|handoff| MembershipHandoffResult {
                group_id: handoff.group_id,
                target_device_id: handoff.target_device_id,
                lease_id: handoff.lease_id,
                membership_generation: handoff.membership_generation,
            })
            .collect(),
        forced_group_ids: outcome.forced_group_ids,
        unknown_scope_operation_id: outcome.unknown_scope_operation_id.unwrap_or_default(),
    }
}

pub(crate) fn membership_error_to_proto(
    error: crate::application::ReplicaMembershipError,
) -> ApplicationCommandError {
    use crate::application::ReplicaMembershipError as Error;
    let (code, group_ids, operation_id) = match &error {
        Error::LocalIdentityUnavailable => {
            (ApplicationErrorCode::LocalIdentityUnavailable, Vec::new(), String::new())
        }
        Error::TargetNotFound => (ApplicationErrorCode::TargetNotFound, Vec::new(), String::new()),
        Error::ReplicaNotReady { group_ids } => {
            (ApplicationErrorCode::ReplicaNotReady, group_ids.clone(), String::new())
        }
        Error::TicketUnavailable { group_id } => {
            (ApplicationErrorCode::TicketUnavailable, vec![group_id.clone()], String::new())
        }
        Error::CoordinationRejected { .. } => {
            (ApplicationErrorCode::CoordinationRejected, Vec::new(), String::new())
        }
        Error::TermsConsentRequired { .. } => {
            (ApplicationErrorCode::TermsConsentRequired, Vec::new(), String::new())
        }
        Error::CoordinationAmbiguous { .. } => {
            (ApplicationErrorCode::CoordinationAmbiguous, Vec::new(), String::new())
        }
        Error::DurabilityLatchFailed { group_ids, .. } => {
            (ApplicationErrorCode::DurabilityLatchFailed, group_ids.clone(), String::new())
        }
        Error::RecoveryPending { operation_id, .. } => {
            (ApplicationErrorCode::RecoveryPending, Vec::new(), operation_id.clone())
        }
        Error::CoordinationTransport { .. } => {
            (ApplicationErrorCode::CoordinationTransport, Vec::new(), String::new())
        }
        Error::Persistence(_) => (ApplicationErrorCode::Persistence, Vec::new(), String::new()),
        Error::OperationConflict { operation_id, .. } => {
            (ApplicationErrorCode::OperationConflict, Vec::new(), operation_id.clone())
        }
        Error::RecoveryJournalUnavailable { operation_id, .. } => {
            (ApplicationErrorCode::RecoveryJournalUnavailable, Vec::new(), operation_id.clone())
        }
    };
    ApplicationCommandError {
        code: code as i32,
        message: error.to_string(),
        group_ids,
        operation_id,
        ..Default::default()
    }
}
