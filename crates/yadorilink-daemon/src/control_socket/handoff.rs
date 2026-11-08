//! The `handoff` family of control verbs: each fn is the body of one `handle_request` arm.

use super::*;

/// Read-only pre-check for `yadorilink share set-storage-mode`: never
/// mutates anything, local or remote (see
/// `DaemonState::another_full_replica_is_ready`'s doc comment). The
/// authoritative, fail-closed re-check happens again in
/// `SetStorageMode` below, right before the local flip commits.
pub(super) async fn check_full_replica_handoff_ready(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::CheckFullReplicaHandoffReadyRequest,
) -> RespPayload {
    RespPayload::CheckFullReplicaHandoffReady(CheckFullReplicaHandoffReadyResponse {
        ready: context.queries.handoff_readiness.ready(&r.group_id).await,
    })
}

pub(super) async fn set_storage_mode(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::SetStorageModeRequest,
) -> RespPayload {
    let application = context.application.clone();
    match application.replica_role.set_storage_mode(&r.group_id, r.on_demand).await {
        // `root_digest` is this device's own locally-computed
        // durability-root digest at commit time -- never sent to or
        // read back from the coordination service (see
        // `HandoffCommitResult`'s doc comment), same as
        // `UnlinkResponse`'s construction above.
        Ok(handoff_result) => RespPayload::SetStorageMode(SetStorageModeResponse {
            handoff_result: handoff_result.map(|(hr, root_digest)| HandoffResult {
                target_device_id: hr.target_device_id,
                root_digest: root_digest.to_vec(),
                membership_generation: hr.membership_generation,
                lease_id: hr.lease_id.unwrap_or_default(),
            }),
        }),
        Err(StorageModeError::OnDemandUnavailable) => {
            refused(crate::provider_gate::ON_DEMAND_REFUSAL, NextStep::CreateProviderFolder)
        }
        Err(StorageModeError::Advised { message, step }) => refused(&message, step),
        Err(e @ StorageModeError::TermsConsentRequired) => terms_consent_response(e),
        Err(e @ StorageModeError::Failed(_)) => RespPayload::Error(e.to_string()),
    }
}

/// Read-only durability pre-check for `yadorilink share revoke`/
/// `yadorilink device remove`, run by the acting device's own daemon
/// BEFORE the CLI ever calls the coordination plane. See
/// `full_replica_handoff_not_ready_excluding`'s doc comment for the
/// empty-`group_id` "every affected group this daemon can see"
/// semantics and the "partial view, not a distributed proof" caveat.
pub(super) async fn check_full_replica_handoff_ready_excluding(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::CheckFullReplicaHandoffReadyExcludingRequest,
) -> RespPayload {
    match context
            .queries
            .handoff_readiness
            .not_ready_excluding(&r.group_id, &r.excluded_device_id)
            .await
        {
            Ok(not_ready_group_ids) => RespPayload::CheckFullReplicaHandoffReadyExcluding(
                CheckFullReplicaHandoffReadyExcludingResponse {
                    ready: not_ready_group_ids.is_empty(),
                    not_ready_group_ids,
                },
            ),
            Err(e) => RespPayload::Error(format!(
                "cannot verify complete-copy durability because the local link table could not be read: {e}"
            )),
        }
}

/// Durable post-force durability-status latch for the
/// CLI-orchestrated force paths (`durability_force.rs`'s revoke/
/// device-remove) -- see the request's proto doc comment. Persistence
/// failure is returned rather than acknowledging a latch that would
/// disappear on restart.
pub(super) async fn latch_group_durability_unknown(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::LatchGroupDurabilityUnknownRequest,
) -> RespPayload {
    match context.application.durability.latch_group_durability_unknown(&r.group_id) {
        Ok(()) => RespPayload::LatchGroupDurabilityUnknown(LatchGroupDurabilityUnknownResponse {}),
        Err(error) => RespPayload::Error(error.to_string()),
    }
}

/// Full-replica-handoff lease request (target-side) -- see the
/// request's proto doc comment and `DaemonState::request_handoff_
/// lease` for the local-check-then-coordination-plane-request-then-
/// local-record round trip this drives.
pub(super) async fn request_handoff_lease(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::RequestHandoffLeaseRequest,
) -> RespPayload {
    match context.application.handoff.request_lease(&r.group_id).await {
        Ok(grant) => RespPayload::RequestHandoffLease(RequestHandoffLeaseResponse {
            requested: true,
            lease_id: grant.lease_id,
            expires_at_unix: grant.expires_at_unix,
            not_requested_reason: String::new(),
        }),
        Err(refusal) => RespPayload::RequestHandoffLease(RequestHandoffLeaseResponse {
            requested: false,
            lease_id: String::new(),
            expires_at_unix: 0,
            not_requested_reason: match refusal {
                LeaseRefusal::ChangingRetry => "changing_retry".to_owned(),
                LeaseRefusal::Unspecified => String::new(),
            },
        }),
    }
}

/// Removed-device handoff-ticket request (operating-device-side) --
/// see the request's proto doc comment and `DaemonState::obtain_
/// handoff_ticket_from_device` for the peer round trip (offline/
/// unreachable, timeout, and "the device could not attest its own
/// roots" all collapse to `granted = false` here, matching that
/// method's own doc comment).
pub(super) async fn obtain_handoff_ticket(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::ObtainHandoffTicketRequest,
) -> RespPayload {
    match context.application.handoff.obtain_ticket(&r.group_id, &r.device_id).await {
        Some(grant) => RespPayload::ObtainHandoffTicket(ObtainHandoffTicketResponse {
            granted: true,
            lease_id: grant.lease_id,
            expires_at_unix: grant.expires_at_unix,
            target_device_id: grant.target_device_id,
        }),
        None => RespPayload::ObtainHandoffTicket(ObtainHandoffTicketResponse {
            granted: false,
            lease_id: String::new(),
            expires_at_unix: 0,
            target_device_id: String::new(),
        }),
    }
}

pub(super) async fn release_handoff_ticket(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::ReleaseHandoffTicketRequest,
) -> RespPayload {
    context
        .application
        .handoff
        .release_ticket(&r.group_id, &r.device_id, &r.target_device_id, &r.lease_id)
        .await;
    RespPayload::ReleaseHandoffTicket(ReleaseHandoffTicketResponse {})
}
