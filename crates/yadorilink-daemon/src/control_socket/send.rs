//! The `send` family of control verbs: each fn is the body of one `handle_request` arm.

use super::*;

/// Track Send: `yadorilink send <source_path>... <target_device>`.
pub(super) async fn send_file(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::SendFileRequest,
) -> RespPayload {
    match context.application.send_transfer.send(&r.source_paths, &r.target_device).await {
        Ok(outcome) => RespPayload::SendFile(SendFileResponse {
            transfer_id: outcome.transfer_id,
            files_offered: outcome.files_offered,
            total_size: outcome.total_size,
        }),
        Err(e) => send_failure_payload(e),
    }
}

/// Cross-account one-shot Send links: create, redeem, cancel.
pub(super) async fn create_send_link(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::CreateSendLinkRequest,
) -> RespPayload {
    match context.application.send_transfer.create_link(r.ttl_seconds, &r.source_paths).await {
        Ok(link) => RespPayload::CreateSendLink(CreateSendLinkResponse {
            link_id: link.link_id,
            code: link.code,
            expires_at_unix: link.expires_at_unix,
        }),
        Err(e) => send_failure_payload(e),
    }
}

pub(super) async fn redeem_send_link(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::RedeemSendLinkRequest,
) -> RespPayload {
    match context
        .application
        .send_transfer
        .redeem_link(&r.code, &r.receiver_device_id, &r.destination_dir)
        .await
    {
        Ok((link_id, destination_dir)) => {
            RespPayload::RedeemSendLink(RedeemSendLinkResponse { link_id, destination_dir })
        }
        Err(e) => send_failure_payload(e),
    }
}

pub(super) async fn cancel_send_link(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::CancelSendLinkRequest,
) -> RespPayload {
    match context.application.send_transfer.cancel_link(&r.link_id).await {
        Ok(()) => RespPayload::CancelSendLink(CancelSendLinkResponse {}),
        Err(e) => send_failure_payload(e),
    }
}

pub(super) async fn preview_send_link(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::PreviewSendLinkRequest,
) -> RespPayload {
    match context.application.send_transfer.preview_link(&r.code).await {
        Ok(preview) => {
            RespPayload::PreviewSendLink(yadorilink_ipc_proto::daemonctl::PreviewSendLinkResponse {
                sender_name: preview.sender_name,
                files: preview
                    .files
                    .into_iter()
                    .map(|(name, size)| yadorilink_ipc_proto::daemonctl::SendLinkFile {
                        name,
                        size,
                    })
                    .collect(),
                expires_at_unix: preview.expires_at_unix,
            })
        }
        Err(e) => send_failure_payload(e),
    }
}

pub(super) async fn send_link_status(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::SendLinkStatusRequest,
) -> RespPayload {
    match context.application.send_transfer.link_status(&r.link_id).await {
        Ok(view) => RespPayload::SendLinkStatus(SendLinkStatusResponse {
            state: view.state as i32,
            receiver_device_name: view.receiver_device_name,
            transfer_id: view.transfer_id,
            failure: view.failure,
        }),
        Err(e) => send_failure_payload(e),
    }
}

/// Track Send: `yadorilink inbox`.
pub(super) async fn list_inbox(context: &crate::control_context::ControlContext) -> RespPayload {
    match context.queries.inbox.list() {
        Ok(transfers) => RespPayload::ListInbox(ListInboxResponse {
            transfers: transfers
                .into_iter()
                .map(crate::send_transfer::inbox_entry_to_proto)
                .collect(),
        }),
        Err(e) => RespPayload::Error(e),
    }
}

/// Track Send: the transfers this device sent.
pub(super) async fn list_sent_transfers(
    context: &crate::control_context::ControlContext,
) -> RespPayload {
    match context.queries.inbox.list_sent() {
        Ok(transfers) => RespPayload::ListSentTransfers(ListSentTransfersResponse {
            transfers: transfers
                .into_iter()
                .map(crate::send_transfer::sent_entry_to_proto)
                .collect(),
        }),
        Err(e) => RespPayload::Error(e),
    }
}

pub(super) async fn cancel_transfer(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::CancelTransferRequest,
) -> RespPayload {
    match context.application.send_transfer.cancel(&r.transfer_id) {
        Ok(()) => RespPayload::CancelTransfer(CancelTransferResponse {}),
        Err(e) => RespPayload::Error(e),
    }
}

pub(super) async fn retry_transfer(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::RetryTransferRequest,
) -> RespPayload {
    match context.application.send_transfer.retry(&r.transfer_id, r.direction()).await {
        Ok(crate::send_transfer::RetryOutcome::Received(outcome)) => {
            RespPayload::RetryTransfer(RetryTransferResponse {
                destination_dir: outcome.destination_dir.to_string_lossy().into_owned(),
                files_received: outcome.files_received,
                bytes_received: outcome.bytes_received,
                ..Default::default()
            })
        }
        Ok(crate::send_transfer::RetryOutcome::Offered(outcome)) => {
            RespPayload::RetryTransfer(RetryTransferResponse {
                offered: true,
                files_offered: outcome.files_offered,
                total_size: outcome.total_size,
                ..Default::default()
            })
        }
        Err(e) => RespPayload::Error(e),
    }
}

/// Track Send: `yadorilink receive <transfer_id> [--to <dir>]`.
pub(super) async fn receive_transfer(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::ReceiveTransferRequest,
) -> RespPayload {
    let destination_dir =
        if r.destination_dir.is_empty() { None } else { Some(r.destination_dir.as_str()) };
    match context.application.send_transfer.receive(&r.transfer_id, destination_dir).await {
        Ok(outcome) => RespPayload::ReceiveTransfer(ReceiveTransferResponse {
            destination_dir: outcome.destination_dir.to_string_lossy().into_owned(),
            files_received: outcome.files_received,
            bytes_received: outcome.bytes_received,
        }),
        Err(e) => send_failure_payload(e),
    }
}
