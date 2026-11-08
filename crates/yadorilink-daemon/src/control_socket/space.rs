//! The `space` family of control verbs: each fn is the body of one `handle_request` arm.

use super::*;

/// The setting is a small local file; an unreadable one reads as Off.
pub(super) async fn get_space_management(
    context: &crate::control_context::ControlContext,
) -> RespPayload {
    let config =
        crate::space_management_config::SpaceManagementStore::new(context.config_dir.clone())
            .load_or_off();
    RespPayload::GetSpaceManagement(GetSpaceManagementResponse {
        settings: Some(space_settings_to_proto(&config)),
    })
}

pub(super) async fn set_space_management(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::SetSpaceManagementRequest,
) -> RespPayload {
    match r.settings {
        None => RespPayload::Error("no setting given".into()),
        Some(settings) => match crate::space_management_config::SpaceManagementStore::new(
            context.config_dir.clone(),
        )
        .set(settings.enabled)
        {
            Ok(config) => RespPayload::SetSpaceManagement(SetSpaceManagementResponse {
                settings: Some(space_settings_to_proto(&config)),
            }),
            Err(e) => RespPayload::Error(format!("could not save the setting: {e}")),
        },
    }
}

pub(super) async fn preview_space_reclaim(
    context: &crate::control_context::ControlContext,
) -> RespPayload {
    match context.auto_reclaim.preview().await {
        Some(scan) => RespPayload::PreviewSpaceReclaim(PreviewSpaceReclaimResponse {
            items: scan
                .entries
                .iter()
                .map(|e| SpaceReclaimPreviewItem {
                    group_id: e.group_id.clone(),
                    path: e.path.clone(),
                    verdict: e.verdict.to_wire() as i32,
                })
                .collect(),
            unreadable_roots: scan.unreadable_roots as u32,
        }),
        None => {
            RespPayload::Error("automatic space management is not available in this daemon".into())
        }
    }
}

pub(super) async fn limits_set(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::LimitsSetRequest,
) -> RespPayload {
    match context
        .application
        .governance
        .set_limits(r.upload_bytes_per_sec, r.download_bytes_per_sec)
    {
        Ok(limits) => RespPayload::LimitsSet(LimitsSetResponse {
            upload_bytes_per_sec: limits.upload_bytes_per_sec,
            download_bytes_per_sec: limits.download_bytes_per_sec,
        }),
        Err(e) => RespPayload::Error(e.to_string()),
    }
}

pub(super) async fn limits_show(context: &crate::control_context::ControlContext) -> RespPayload {
    let config = context.queries.governance.limits();
    RespPayload::LimitsShow(LimitsShowResponse {
        upload_bytes_per_sec: config.upload_limit_bytes_per_sec,
        download_bytes_per_sec: config.download_limit_bytes_per_sec,
    })
}
