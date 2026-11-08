//! The `recovery` family of control verbs: each fn is the body of one `handle_request` arm.

use super::*;

/// `yadorilink recovery list`/`show`.
pub(super) async fn list_recovery_operations(
    context: &crate::control_context::ControlContext,
) -> RespPayload {
    match context.queries.recovery.list() {
        Ok(inv) => RespPayload::ListRecoveryOperations(ListRecoveryOperationsResponse {
            operations: inv
                .valid
                .iter()
                .map(crate::recovery_diagnosis::ipc::recovery_summary_to_proto)
                .collect(),
            invalid: inv
                .invalid
                .iter()
                .map(crate::recovery_diagnosis::ipc::invalid_recovery_operation_to_proto)
                .collect(),
        }),
        Err(e) => RespPayload::Error(e.to_string()),
    }
}

/// `show` returns a stable diagnosis (local
/// evidence + exactly one remote lookup + a pure recommendation),
/// not just the local journal row. `domain` is required and
/// unambiguous -- see `ShowRecoveryOperationRequest`'s own doc
/// comment in the proto file.
pub(super) async fn show_recovery_operation(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::ShowRecoveryOperationRequest,
) -> RespPayload {
    let Some(domain) = yadorilink_replica_domain::recovery::RecoveryDomain::try_from_str(&r.domain)
    else {
        return RespPayload::Error(format!(
            "unknown recovery domain {:?}; expected one of \"enrollment\", \
                     \"membership\", \"role-loss\"",
            r.domain
        ));
    };
    let key =
        crate::recovery::RecoveryOperationKey { domain, operation_id: r.operation_id.clone() };
    match context.queries.recovery.diagnose(&key).await {
        Ok(crate::queries::recovery::DiagnoseOutcome::Diagnosis(outcome)) => {
            RespPayload::ShowRecoveryOperation(
                crate::recovery_diagnosis::ipc::stable_diagnosis_outcome_to_proto(&outcome),
            )
        }
        Ok(crate::queries::recovery::DiagnoseOutcome::CoordinationNotConfigured) => {
            RespPayload::Error(
                "coordination-plane address/access token not configured on this device".to_string(),
            )
        }
        Err(e) => RespPayload::Error(e.to_string()),
    }
}
