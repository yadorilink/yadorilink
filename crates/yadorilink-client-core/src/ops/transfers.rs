//! One-shot file transfers to and from another device on this account,
//! separate from linked-folder sync.

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
pub use yadorilink_ipc_proto::daemonctl::RetryDirection;
use yadorilink_ipc_proto::daemonctl::{
    CancelTransferRequest, InboxTransfer, ListInboxRequest, ListSentTransfersRequest,
    ReceiveTransferRequest, ReceiveTransferResponse, RetryTransferRequest, SendFileRequest,
    SendFileResponse, SentTransferEntry,
};

use crate::daemon::control;
use crate::error::CoreError;
use crate::ops::paths;

fn unexpected() -> CoreError {
    CoreError::Other("unexpected daemon response".into())
}

/// Offers a file or directory to another device on this account.
pub async fn send_file(
    source_path: String,
    target_device: String,
) -> Result<SendFileResponse, CoreError> {
    // The daemon's working directory is not the user's, so it must never see
    // a relative path.
    let source_path = paths::absolute_path(&source_path)?;
    let resp =
        control::send(ReqPayload::SendFile(SendFileRequest { source_path, target_device })).await?;
    let Some(RespPayload::SendFile(result)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(result)
}

/// Every transfer other devices have offered to this device, received or
/// not.
pub async fn list_inbox() -> Result<Vec<InboxTransfer>, CoreError> {
    let resp = control::send(ReqPayload::ListInbox(ListInboxRequest {})).await?;
    let Some(RespPayload::ListInbox(list)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(list.transfers)
}

/// The transfers this device sent: every one still going and the most recent finished ones.
pub async fn list_sent() -> Result<Vec<SentTransferEntry>, CoreError> {
    let resp = control::send(ReqPayload::ListSentTransfers(ListSentTransfersRequest {})).await?;
    let Some(RespPayload::ListSentTransfers(list)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(list.transfers)
}

/// Accepts an inbound transfer into `destination_dir`, or the daemon's
/// default inbox directory when `None`. Resumable.
pub async fn receive_transfer(
    transfer_id: String,
    destination_dir: Option<String>,
) -> Result<ReceiveTransferResponse, CoreError> {
    let destination_dir = match destination_dir {
        Some(dir) => paths::absolute_path(&dir)?,
        None => String::new(),
    };
    let resp = control::send(ReqPayload::ReceiveTransfer(ReceiveTransferRequest {
        transfer_id,
        destination_dir,
    }))
    .await?;
    let Some(RespPayload::ReceiveTransfer(result)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(result)
}

/// Stops a transfer by id, whichever side this device is on. Idempotent for one already canceled
/// or completed; a completed one is never undone.
pub async fn cancel_transfer(transfer_id: String) -> Result<(), CoreError> {
    let resp =
        control::send(ReqPayload::CancelTransfer(CancelTransferRequest { transfer_id })).await?;
    let Some(RespPayload::CancelTransfer(_)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(())
}

/// What a retry did.
pub enum Retried {
    /// A received transfer was resumed and finished.
    Received(ReceiveTransferResponse),
    /// A sent transfer was offered again.
    Offered(SendFileResponse),
}

/// Retries a transfer by id. A received transfer that failed or was canceled is resumed once the
/// daemon has re-validated the sender, the manifest and the destination. A sent transfer that was
/// canceled, declined or never answered is offered again once the daemon has checked the files are
/// unchanged and been granted a new authorization for the same device.
///
/// `direction` is which side the caller means; the daemon refuses a transfer on the other side
/// before doing anything, so a retry meant for one kind can never run the other.
pub async fn retry_transfer(
    transfer_id: String,
    direction: RetryDirection,
) -> Result<Retried, CoreError> {
    let resp = control::send(ReqPayload::RetryTransfer(RetryTransferRequest {
        transfer_id: transfer_id.clone(),
        direction: direction as i32,
    }))
    .await?;
    let Some(RespPayload::RetryTransfer(result)) = resp.payload else {
        return Err(unexpected());
    };
    if result.offered {
        return Ok(Retried::Offered(SendFileResponse {
            transfer_id,
            files_offered: result.files_offered,
            total_size: result.total_size,
        }));
    }
    Ok(Retried::Received(ReceiveTransferResponse {
        destination_dir: result.destination_dir,
        files_received: result.files_received,
        bytes_received: result.bytes_received,
    }))
}
