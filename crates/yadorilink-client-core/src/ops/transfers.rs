//! One-shot file transfers to and from another device on this account,
//! separate from linked-folder sync.

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
pub use yadorilink_ipc_proto::daemonctl::RetryDirection;
use yadorilink_ipc_proto::daemonctl::{
    CancelSendLinkRequest, CancelTransferRequest, CreateSendLinkRequest, CreateSendLinkResponse,
    InboxTransfer, ListInboxRequest, ListSentTransfersRequest, PreviewSendLinkRequest,
    PreviewSendLinkResponse, ReceiveTransferRequest, ReceiveTransferResponse,
    RedeemSendLinkRequest, RedeemSendLinkResponse, RetryTransferRequest, SendFileRequest,
    SendFileResponse, SendLinkStatusRequest, SendLinkStatusResponse, SentTransferEntry,
};

use crate::daemon::control;
use crate::error::CoreError;
use crate::ops::paths;

fn unexpected() -> CoreError {
    CoreError::Other("unexpected daemon response".into())
}

fn absolute_all(paths_in: &[String]) -> Result<Vec<String>, CoreError> {
    paths_in.iter().map(|path| paths::absolute_path(path)).collect()
}

/// Offers a file or directory to another device on this account.
pub async fn send_file(
    source_path: String,
    target_device: String,
) -> Result<SendFileResponse, CoreError> {
    send_files(vec![source_path], target_device).await
}

/// Offers several files and/or folders as one transfer to another device (or a `link:<id>`).
pub async fn send_files(
    source_paths: Vec<String>,
    target_device: String,
) -> Result<SendFileResponse, CoreError> {
    if source_paths.is_empty() {
        return Err(CoreError::Other("name at least one file or folder to send".into()));
    }
    // The daemon's working directory is not the user's, so it must never see
    // a relative path.
    let source_paths = absolute_all(&source_paths)?;
    let resp = control::send(ReqPayload::SendFile(SendFileRequest { source_paths, target_device }))
        .await?;
    let Some(RespPayload::SendFile(result)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(result)
}

/// Mints a one-use expiring Send link for a recipient on any account.
/// `ttl_seconds` 0 = the service default.
///
/// `source_paths` are the files and folders the link will carry, so the recipient can see their
/// names and sizes (all of them, with the total) before redeeming; empty shows nothing.
pub async fn create_send_link(
    ttl_seconds: u32,
    source_paths: Vec<String>,
) -> Result<CreateSendLinkResponse, CoreError> {
    let source_paths = absolute_all(&source_paths)?;
    let resp = control::send(ReqPayload::CreateSendLink(CreateSendLinkRequest {
        ttl_seconds,
        source_paths,
    }))
    .await?;
    let Some(RespPayload::CreateSendLink(result)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(result)
}

/// Who sends the link a code names and what it carries, without redeeming or consuming it.
/// Needs a sign-in; every link that is not open is refused alike.
pub async fn preview_send_link(code: String) -> Result<PreviewSendLinkResponse, CoreError> {
    let resp = control::send(ReqPayload::PreviewSendLink(PreviewSendLinkRequest { code })).await?;
    let Some(RespPayload::PreviewSendLink(result)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(result)
}

/// Redeems a Send link code with one of this account's devices (`None` = this device);
/// returns the link id and where the files will land. The engine receives the offer that arrives under the link into
/// `destination_dir` (absolute; `None` = a folder of its own choosing) without another step.
pub async fn redeem_send_link(
    code: String,
    receiver_device_id: Option<String>,
    destination_dir: Option<String>,
) -> Result<RedeemSendLinkResponse, CoreError> {
    let resp = control::send(ReqPayload::RedeemSendLink(RedeemSendLinkRequest {
        code,
        receiver_device_id: receiver_device_id.unwrap_or_default(),
        destination_dir: destination_dir.unwrap_or_default(),
    }))
    .await?;
    let Some(RespPayload::RedeemSendLink(result)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(result)
}

/// Cancels a Send link; a grant it already issued but nobody used is revoked with it.
pub async fn cancel_send_link(link_id: String) -> Result<(), CoreError> {
    let resp = control::send(ReqPayload::CancelSendLink(CancelSendLinkRequest { link_id })).await?;
    let Some(RespPayload::CancelSendLink(_)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(())
}

/// The sender's view of a Send link it created: waiting, redeemed, transferring, done, cancelled,
/// expired or interrupted.
pub async fn send_link_status(link_id: String) -> Result<SendLinkStatusResponse, CoreError> {
    let resp = control::send(ReqPayload::SendLinkStatus(SendLinkStatusRequest { link_id })).await?;
    let Some(RespPayload::SendLinkStatus(result)) = resp.payload else {
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
