//! The `links` family of control verbs: each fn is the body of one `handle_request` arm.

use super::*;

pub(super) async fn link(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::LinkRequest,
) -> RespPayload {
    match enrollment_commands::require_risks_acknowledged(
        &context.application.link_lifecycle,
        &r.local_path,
        r.acknowledge_risks,
    )
    .await
    {
        Err(error) => link_failure_payload(&error),
        Ok(()) => match decode_link_command(r) {
            Err(message) => RespPayload::Error(message),
            Ok(command) => match context.application.link_lifecycle.link(command).await {
                Ok(_) => RespPayload::Link(LinkResponse {}),
                Err(e) => link_failure_payload(&e),
            },
        },
    }
}

/// Served by `serve_nas_admin` on its own connection before this
/// dispatch is reached; here only for exhaustiveness.
pub(super) async fn open_nas_admin(
    _context: &crate::control_context::ControlContext,
) -> RespPayload {
    RespPayload::Error("a management session is opened on its own connection".to_string())
}

pub(super) async fn link_preflight(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::LinkPreflightRequest,
) -> RespPayload {
    match super::link_preflight(context, &r.local_path).await {
        Ok(response) => RespPayload::LinkPreflight(response),
        Err(message) => RespPayload::Error(message),
    }
}

pub(super) async fn unlink(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::UnlinkRequest,
) -> RespPayload {
    let application = context.application.clone();
    match application
        .replica_role
        .unlink(&r.local_path, r.force, expected_group(&r.expected_group_id))
        .await
    {
        Ok(outcome) => RespPayload::Unlink(UnlinkResponse {
            handoff_result: outcome.handoff.map(|h| HandoffResult {
                target_device_id: h.target_device_id,
                root_digest: h.root_digest.to_vec(),
                membership_generation: h.membership_generation,
                lease_id: h.lease_id.unwrap_or_default(),
            }),
        }),
        Err(crate::application::UnlinkError::NotProtected(message)) => {
            RespPayload::CommandError(ApplicationCommandError {
                code: ApplicationErrorCode::NotProtected as i32,
                message,
                group_ids: Vec::new(),
                operation_id: String::new(),
                ..Default::default()
            })
        }
        Err(crate::application::UnlinkError::TermsConsentRequired) => {
            terms_consent_response(crate::application::UnlinkError::TermsConsentRequired)
        }
        Err(crate::application::UnlinkError::GroupMismatch(message)) => {
            group_mismatch_response(message)
        }
        Err(crate::application::UnlinkError::Other(message)) => RespPayload::Error(message),
    }
}

pub(super) async fn readopt_volume(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::ReadoptVolumeRequest,
) -> RespPayload {
    match context.application.pause_resume.readopt_volume(&r.local_path).await {
        Ok(()) => RespPayload::ReadoptVolume(ReadoptVolumeResponse {}),
        Err(e @ crate::sync_error::SyncError::FolderNotStarted { .. }) => {
            refused(&e.to_string(), NextStep::CheckLinkStatus)
        }
        Err(e) => RespPayload::Error(e.to_string()),
    }
}

pub(super) async fn mark_link_not_rejoined(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::MarkLinkNotRejoinedRequest,
) -> RespPayload {
    match context.application.link_lifecycle.mark_not_rejoined(&r.local_path).await {
        Ok(()) => RespPayload::MarkLinkNotRejoined(MarkLinkNotRejoinedResponse {}),
        Err(e) => RespPayload::Error(e.to_string()),
    }
}

pub(super) async fn list_links(context: &crate::control_context::ControlContext) -> RespPayload {
    match context.status_hub.list_links().await {
        Ok(links) => RespPayload::ListLinks(ListLinksResponse {
            links: links
                .into_iter()
                .map(encode_link_status)
                .map(|mut link| {
                    // The state and the action only: a listing has no peers to read
                    // availability or protection from.
                    link.product = Some(
                        yadorilink_product_view::ProductStatusSummary::for_folder(&link).to_wire(),
                    );
                    link
                })
                .collect(),
        }),
        Err(message) => RespPayload::Error(message),
    }
}

pub(super) async fn pause(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::PauseRequest,
) -> RespPayload {
    let duration = match yadorilink_ipc_proto::daemonctl::PauseDuration::try_from(r.duration) {
        Ok(WirePauseDuration::TwoHours) => PauseDuration::TwoHours,
        Ok(WirePauseDuration::EightHours) => PauseDuration::EightHours,
        Ok(WirePauseDuration::TwentyFourHours) => PauseDuration::TwentyFourHours,
        Ok(WirePauseDuration::Unspecified) | Err(_) => PauseDuration::UntilResumed,
    };
    match context.application.pause_resume.pause(
        &r.local_path,
        duration,
        expected_group(&r.expected_group_id),
    ) {
        Ok(()) => RespPayload::Pause(PauseResponse {}),
        Err(crate::sync_error::SyncError::GroupMismatch(path)) => group_mismatch_response(path),
        Err(e) => RespPayload::Error(e.to_string()),
    }
}

pub(super) async fn resume(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::ResumeRequest,
) -> RespPayload {
    match context
        .application
        .pause_resume
        .resume(&r.local_path, expected_group(&r.expected_group_id))
        .await
    {
        Ok(()) => RespPayload::Resume(ResumeResponse {}),
        Err(crate::sync_error::SyncError::GroupMismatch(path)) => group_mismatch_response(path),
        Err(e) => RespPayload::Error(e.to_string()),
    }
}

/// Drops a pending-enrollment marker once `share create`/`share
/// join` has confirmed its own activate call directly -- an
/// optimization over waiting for the next `pending_enrollment::
/// reconcile` sweep to notice the same thing. Always succeeds: a
/// marker that's already gone (this device's own sweep beat the
/// caller to it) is a no-op, matching `remove_pending_enrollment`'s
/// own idempotent delete.
pub(super) async fn remove_pending_enrollment(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::RemovePendingEnrollmentRequest,
) -> RespPayload {
    match context.application.enrollment_recovery.acknowledge_activation(&r.operation_id) {
        Ok(()) => RespPayload::RemovePendingEnrollment(RemovePendingEnrollmentResponse {}),
        Err(e) => RespPayload::Error(e.to_string()),
    }
}
