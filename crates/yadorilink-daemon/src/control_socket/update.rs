//! The `update` family of control verbs: each fn is the body of one `handle_request` arm.

use super::*;

/// Dispatch into `context.application.update`/`context.queries.
/// update_status`; `update_ipc` only translates to/from the wire
/// types — mirrors `reporting_ipc`'s own dispatch pattern above.
pub(super) async fn update_status(context: &crate::control_context::ControlContext) -> RespPayload {
    RespPayload::UpdateStatus(crate::update_ipc::encode_update_status(
        context.queries.update_status.snapshot(),
    ))
}

pub(super) async fn update_check(context: &crate::control_context::ControlContext) -> RespPayload {
    context.application.update.check().await;
    RespPayload::UpdateCheck(crate::update_ipc::encode_check_response(
        context.queries.update_status.snapshot(),
    ))
}

pub(super) async fn update_version_check(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::UpdateVersionCheckRequest,
) -> RespPayload {
    match crate::update_ipc::decode_version_check(r) {
        Ok((kind, version)) => {
            let outcome = context.application.update.version_check(kind, version).await;
            RespPayload::UpdateVersionCheck(crate::update_ipc::encode_version_check_response(
                outcome,
            ))
        }
        Err(e) => RespPayload::Error(e),
    }
}

pub(super) async fn update_verified_entry(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::UpdateVerifiedEntryRequest,
) -> RespPayload {
    match crate::update_ipc::decode_verified_entry(r) {
        Ok((item, phase)) => {
            RespPayload::UpdateVerifiedEntry(crate::update_ipc::encode_verified_entry_response(
                context.queries.update_status.verified_entry(&item, phase).await,
            ))
        }
        Err(e) => RespPayload::Error(e),
    }
}

pub(super) async fn update_install(
    context: &crate::control_context::ControlContext,
) -> RespPayload {
    RespPayload::UpdateInstall(crate::update_ipc::encode_download_response(
        context.application.update.download_guidance(),
        context.application.update.download_page_url(),
    ))
}

pub(super) async fn update_config(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::UpdateConfigRequest,
) -> RespPayload {
    match context.application.update.config(crate::update_ipc::decode_config_request(r)) {
        Ok(policy) => RespPayload::UpdateConfig(crate::update_ipc::encode_config_response(policy)),
        Err(e) => RespPayload::Error(e),
    }
}
