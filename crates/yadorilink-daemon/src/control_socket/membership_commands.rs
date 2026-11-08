//! The `membership_commands` family of control verbs: each fn is the body of one `handle_request` arm.

use super::*;
use crate::membership_wire::{membership_error_to_proto, membership_outcome_to_proto};

pub(super) async fn remove_device_command(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::RemoveDeviceCommandRequest,
) -> RespPayload {
    let application = context.application.clone();
    let result = application
        .membership
        .remove_device(crate::application::RemoveDeviceCommand {
            device_id: r.device_id,
            force: r.force,
        })
        .await;
    RespPayload::RemoveDeviceCommand(RemoveDeviceCommandResponse {
        result: Some(match result {
            Ok(outcome) => remove_device_command_response::Result::Outcome(
                membership_outcome_to_proto(outcome),
            ),
            Err(error) => {
                remove_device_command_response::Result::Error(membership_error_to_proto(error))
            }
        }),
    })
}

pub(super) async fn revoke_device_command(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::RevokeDeviceCommandRequest,
) -> RespPayload {
    let application = context.application.clone();
    let result = application
        .membership
        .revoke_device(crate::application::RevokeDeviceCommand {
            group_id: r.group_id,
            device_id: r.device_id,
            force: r.force,
        })
        .await;
    RespPayload::RevokeDeviceCommand(RevokeDeviceCommandResponse {
        result: Some(match result {
            Ok(outcome) => revoke_device_command_response::Result::Outcome(
                membership_outcome_to_proto(outcome),
            ),
            Err(error) => {
                revoke_device_command_response::Result::Error(membership_error_to_proto(error))
            }
        }),
    })
}

pub(super) async fn revoke_edge_command(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::RevokeEdgeCommandRequest,
) -> RespPayload {
    let application = context.application.clone();
    let result = application.membership.revoke_edge(r.edge_id, r.force).await;
    RespPayload::RevokeEdgeCommand(RevokeEdgeCommandResponse {
        result: Some(match result {
            Ok(outcome) => {
                revoke_edge_command_response::Result::Outcome(membership_outcome_to_proto(outcome))
            }
            Err(error) => {
                revoke_edge_command_response::Result::Error(membership_error_to_proto(error))
            }
        }),
    })
}

pub(super) async fn delete_group_command(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::DeleteGroupCommandRequest,
) -> RespPayload {
    let application = context.application.clone();
    let result = application
        .group_admin
        .delete_folder_group(&r.group_id, r.acknowledge_cross_account_members)
        .await;
    RespPayload::DeleteGroupCommand(DeleteGroupCommandResponse {
        result: Some(match result {
            Ok(()) => delete_group_command_response::Result::Ok(true),
            Err(error) => delete_group_command_response::Result::Error(error),
        }),
    })
}

pub(super) async fn create_and_link_command(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::CreateAndLinkCommandRequest,
) -> RespPayload {
    let result = enrollment_commands::create_and_link(
        &context.application,
        enrollment_commands::CreateShare {
            group_name: r.group_name,
            local_path: r.local_path,
            create_local_path_if_missing: r.create_local_path_if_missing,
            on_demand: r.on_demand,
            acknowledge_risks: r.acknowledge_risks,
            provider_display_name: r.provider_display_name,
            request_token: r.request_token,
        },
    )
    .await;
    RespPayload::CreateAndLinkCommand(CreateAndLinkCommandResponse {
        result: Some(match result {
            Ok(outcome) => create_and_link_command_response::Result::Outcome(
                enrollment_outcome_to_proto(context, outcome),
            ),
            Err(error) => {
                create_and_link_command_response::Result::Error(enrollment_error_to_proto(error))
            }
        }),
    })
}

pub(super) async fn join_and_link_command(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::JoinAndLinkCommandRequest,
) -> RespPayload {
    let result = enrollment_commands::join_and_link(
        &context.application,
        enrollment_commands::JoinGroup {
            group_id: r.group_id,
            group_name: r.group_name,
            local_path: r.local_path,
            on_demand: r.on_demand,
            acknowledge_risks: r.acknowledge_risks,
            provider_display_name: r.provider_display_name,
            request_token: r.request_token,
        },
    )
    .await;
    RespPayload::JoinAndLinkCommand(JoinAndLinkCommandResponse {
        result: Some(match result {
            Ok(outcome) => join_and_link_command_response::Result::Outcome(
                enrollment_outcome_to_proto(context, outcome),
            ),
            Err(error) => {
                join_and_link_command_response::Result::Error(enrollment_error_to_proto(error))
            }
        }),
    })
}

pub(super) async fn accept_invite_command(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::AcceptInviteCommandRequest,
) -> RespPayload {
    let result = enrollment_commands::accept_invite(
        &context.application,
        enrollment_commands::AcceptInvite {
            code: r.code,
            local_path: r.local_path,
            on_demand: r.on_demand,
            acknowledge_risks: r.acknowledge_risks,
            provider_display_name: r.provider_display_name,
            request_token: r.request_token,
        },
    )
    .await;
    RespPayload::AcceptInviteCommand(AcceptInviteCommandResponse {
        result: Some(match result {
            Ok(outcome) => accept_invite_command_response::Result::Outcome(
                enrollment_outcome_to_proto(context, outcome),
            ),
            Err(error) => {
                accept_invite_command_response::Result::Error(enrollment_error_to_proto(error))
            }
        }),
    })
}

pub(super) async fn mint_invite_command(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::MintInviteCommandRequest,
) -> RespPayload {
    let application = context.application.clone();
    let role = if r.role.is_empty() { None } else { Some(r.role.as_str()) };
    let ttl_secs = if r.ttl_secs == 0 { None } else { Some(r.ttl_secs) };
    let result =
        application.enrollment.mint_invite(&r.group_id, role, ttl_secs, r.requires_approval).await;
    RespPayload::MintInviteCommand(MintInviteCommandResponse {
        result: Some(match result {
            Ok(invite) => mint_invite_command_response::Result::Outcome(MintedInviteInfo {
                code: invite.code,
                invite_id: invite.invite_id,
                group_id: invite.group_id,
                role: invite.role,
                expires_at_unix: invite.expires_at_unix,
                // Echoed from the coordination plane's own response,
                // never from the request: what the caller renders must
                // describe the invite that exists.
                requires_approval: invite.requires_approval,
            }),
            Err(error) => {
                let code = match error {
                    crate::application::model::MintInviteError::TermsConsentRequired(_) => {
                        ApplicationErrorCode::TermsConsentRequired
                    }
                    crate::application::model::MintInviteError::Rejected(_) => {
                        ApplicationErrorCode::CoordinationRejected
                    }
                };
                mint_invite_command_response::Result::Error(ApplicationCommandError {
                    code: code as i32,
                    message: error.to_string(),
                    group_ids: Vec::new(),
                    operation_id: String::new(),
                    ..Default::default()
                })
            }
        }),
    })
}

/// The devices of this account and whether each is online.
pub(super) async fn list_account_devices(
    context: &crate::control_context::ControlContext,
) -> RespPayload {
    match context.queries.account_devices.list().await {
        Ok(devices) => RespPayload::ListAccountDevices(
            yadorilink_ipc_proto::daemonctl::ListAccountDevicesResponse {
                devices: devices
                    .into_iter()
                    .map(|d| yadorilink_ipc_proto::daemonctl::AccountDeviceInfo {
                        device_id: d.device_id,
                        device_name: d.device_name,
                        online: d.online,
                        is_this_device: d.is_this_device,
                    })
                    .collect(),
            },
        ),
        Err(message) => RespPayload::Error(message),
    }
}

/// The share edges of this account's folder groups, from the coordination plane.
pub(super) async fn list_share_edges(
    context: &crate::control_context::ControlContext,
) -> RespPayload {
    match context.queries.account_devices.list_share_edges().await {
        Ok(edges) => {
            RespPayload::ListShareEdges(yadorilink_ipc_proto::daemonctl::ListShareEdgesResponse {
                edges: edges
                    .into_iter()
                    .map(|e| yadorilink_ipc_proto::daemonctl::ShareEdgeInfo {
                        edge_id: e.edge_id,
                        group_id: e.group_id,
                        device_id: e.device_id,
                        state: e.state,
                    })
                    .collect(),
            })
        }
        Err(message) => RespPayload::Error(format!("could not list the folder members: {message}")),
    }
}
