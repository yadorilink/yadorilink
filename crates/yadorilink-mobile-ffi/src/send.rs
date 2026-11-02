//! Cross-account Send on the embedded engine: links (create, preview, redeem, cancel, status,
//! the sender's list), sending under a link, and the receiving side (inbox, receive, cancel).
//! Each method is one command of `yadorilink-embedded-host`; the records mirror the product's
//! types and every failure is the typed [`CallFailure`](crate::CallFailure) (`Refused` with
//! `SendLinksDisabled`, `SendLinkInvalid`, `SendLinkExpired`, `SendLinkAlreadyUsed`,
//! `SendLinkCancelled`, `SendPeerUnreachable`, `SendNoSpace`, `SendInterrupted`; signed out is
//! `Refused` with `LocalIdentityUnavailable`).
//!
//! Lifecycle. There is no background daemon: a transfer runs only while the engine runs, so the
//! app keeps the engine running (and the process in the foreground, or inside a
//! `beginBackgroundTask` window) while a transfer is going.
//!
//! - The sender serves its files while its engine runs. If the engine stops first, the recipient
//!   sees the transfer stop (`SendPeerUnreachable`, or `Stalled` in the failure) and the sender
//!   makes the send again under a new link.
//! - The recipient must have its engine running when the sender offers: an offer to a device
//!   that is not running is `SendPeerUnreachable` for the sender, who offers again once the
//!   recipient has the app open.
//! - `suspend` and `stop` end a receive in flight cleanly: it is recorded as failed with the
//!   `Interrupted` reason, and `receive_transfer` on it after `resume` fetches only what never
//!   arrived. A process killed without a stop is recorded the same way when the engine next
//!   starts.
//! - Cancelling a `receive_transfer` call does not stop the pull; `cancel_transfer` does (the
//!   transfer is then `Canceled`, and `receive_transfer` resumes it).

use std::time::SystemTime;

use yadorilink_embedded_host as host;
use yadorilink_embedded_host::dto;

use crate::{CallFailure, CancelHandle, MobileHost};

fn unexpected(command: &str, output: &host::CommandOutput) -> CallFailure {
    CallFailure::Failed { message: format!("{command} returned {output:?}") }
}

/// How long a Send link stays redeemable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SendLinkTtl {
    OneHour,
    OneDay,
    SevenDays,
}

impl From<SendLinkTtl> for dto::SendLinkTtl {
    fn from(ttl: SendLinkTtl) -> Self {
        match ttl {
            SendLinkTtl::OneHour => Self::OneHour,
            SendLinkTtl::OneDay => Self::OneDay,
            SendLinkTtl::SevenDays => Self::SevenDays,
        }
    }
}

/// A Send link just created. The code is shown once: the service keeps only its hash, and the
/// engine does not keep it either.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SendLink {
    pub link_id: String,
    /// What the sender hands to the recipient, on any account.
    pub code: String,
    pub expires_at: Option<SystemTime>,
}

impl From<dto::SendLink> for SendLink {
    fn from(link: dto::SendLink) -> Self {
        Self { link_id: link.link_id, code: link.code, expires_at: link.expires_at }
    }
}

/// A file of a link or a transfer.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SendFile {
    pub relative_path: String,
    pub size: u64,
}

impl From<dto::IncomingFile> for SendFile {
    fn from(file: dto::IncomingFile) -> Self {
        Self { relative_path: file.relative_path, size: file.size }
    }
}

/// What a signed-in holder of a code sees before redeeming it. Nothing was consumed.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SendLinkPreview {
    /// The name of the sender's device.
    pub sender_name: String,
    /// What the link carries; empty when the sender attached no list.
    pub files: Vec<SendFile>,
    pub total_size: u64,
    pub expires_at: Option<SystemTime>,
}

impl From<dto::SendLinkPreview> for SendLinkPreview {
    fn from(preview: dto::SendLinkPreview) -> Self {
        Self {
            sender_name: preview.sender_name,
            files: preview.files.into_iter().map(Into::into).collect(),
            total_size: preview.total_size,
            expires_at: preview.expires_at,
        }
    }
}

/// Where a Send link stands, for the sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SendLinkState {
    /// Created; nobody has redeemed it.
    Waiting,
    /// Redeemed: the recipient picked a device; nothing has been sent yet.
    Redeemed,
    /// The send was authorized and the transfer is going.
    Transferring,
    /// The recipient reported that it received everything.
    Done,
    Cancelled,
    Expired,
    /// The send was authorized but the transfer stopped before it finished. Create a new link
    /// to send again.
    Interrupted,
}

impl From<dto::SendLinkState> for SendLinkState {
    fn from(state: dto::SendLinkState) -> Self {
        match state {
            dto::SendLinkState::Waiting => Self::Waiting,
            dto::SendLinkState::Redeemed => Self::Redeemed,
            dto::SendLinkState::Transferring => Self::Transferring,
            dto::SendLinkState::Done => Self::Done,
            dto::SendLinkState::Cancelled => Self::Cancelled,
            dto::SendLinkState::Expired => Self::Expired,
            dto::SendLinkState::Interrupted => Self::Interrupted,
        }
    }
}

/// The sender's view of one Send link.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SendLinkStatus {
    pub link_id: String,
    pub state: SendLinkState,
    /// The name of the device the recipient picked, once redeemed.
    pub receiver_device_name: Option<String>,
    /// The transfer under this link, once a send started one; match it against
    /// `list_sent_transfers` for progress.
    pub transfer_id: Option<String>,
}

impl From<dto::SendLinkStatus> for SendLinkStatus {
    fn from(status: dto::SendLinkStatus) -> Self {
        Self {
            link_id: status.link_id,
            state: status.state.into(),
            receiver_device_name: status.receiver_device_name,
            transfer_id: status.transfer_id,
        }
    }
}

/// A link in the sender's list: the engine keeps the links it created across restarts.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SendLinkListing {
    pub status: SendLinkStatus,
    pub created_at: Option<SystemTime>,
    pub expires_at: Option<SystemTime>,
    /// How many files the link was created to carry.
    pub file_count: u32,
}

fn unix(secs: i64) -> Option<SystemTime> {
    u64::try_from(secs).ok().map(|s| SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(s))
}

impl From<host::SendLinkEntry> for SendLinkListing {
    fn from(entry: host::SendLinkEntry) -> Self {
        Self {
            status: entry.status.into(),
            created_at: unix(entry.created_at_unix),
            expires_at: unix(entry.expires_at_unix),
            file_count: entry.file_count,
        }
    }
}

/// A send under a link was offered; the engine serves it while it runs.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OfferedTransfer {
    pub transfer_id: String,
    pub files_offered: Vec<String>,
    pub total_size: u64,
}

impl From<dto::SentTransfer> for OfferedTransfer {
    fn from(sent: dto::SentTransfer) -> Self {
        Self {
            transfer_id: sent.transfer_id,
            files_offered: sent.files_offered,
            total_size: sent.total_size,
        }
    }
}

/// Why a transfer stopped.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum TransferFailure {
    /// The other device could not be reached.
    Unreachable,
    /// The receiving device declined the offer.
    Declined,
    /// The sending device canceled the transfer.
    SenderCanceled,
    /// The sending device does not hold the offer as accepted.
    NotAccepted,
    /// The other device refused for another reason.
    Rejected,
    /// What arrived did not match what was offered.
    VerificationFailed,
    /// This device could not store what arrived.
    LocalStorage,
    /// The receiver stopped reading what the sender was serving.
    Stalled,
    /// The transfer stopped without a clearer reason: the engine stopped or was suspended, or
    /// the process ended. `receive_transfer` resumes it.
    Interrupted,
    Other {
        raw: String,
    },
    /// This device had no room to store what arrived.
    NoSpace,
    /// This device's operating system refused to send to the local network (macOS Local Network
    /// privacy, a firewall, a VPN), so a device on the same network could not be reached.
    LocalNetworkBlocked,
    /// The sending device stopped sending and could not be reached again; ask for a new link.
    SenderGone,
    /// The receiving device canceled the transfer (the sender's view).
    ReceiverCanceled,
    /// The receiving device's receive failed or went quiet (the sender's view).
    ReceiverStopped,
}

impl From<dto::TransferFailure> for TransferFailure {
    fn from(failure: dto::TransferFailure) -> Self {
        use dto::TransferFailure as F;
        match failure {
            F::Unreachable => Self::Unreachable,
            F::Declined => Self::Declined,
            F::SenderCanceled => Self::SenderCanceled,
            F::NotAccepted => Self::NotAccepted,
            F::Rejected => Self::Rejected,
            F::VerificationFailed => Self::VerificationFailed,
            F::LocalStorage => Self::LocalStorage,
            F::Stalled => Self::Stalled,
            F::Interrupted => Self::Interrupted,
            F::Other { raw } => Self::Other { raw },
            F::NoSpace => Self::NoSpace,
            F::LocalNetworkBlocked => Self::LocalNetworkBlocked,
            F::SenderGone => Self::SenderGone,
            F::ReceiverCanceled => Self::ReceiverCanceled,
            F::ReceiverStopped => Self::ReceiverStopped,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum IncomingTransferStatus {
    Pending,
    InProgress,
    Completed,
    /// The receive stopped on an error, was interrupted, or the process ended during it.
    Failed,
    Canceled,
    Other {
        raw: String,
    },
}

impl From<dto::IncomingTransferStatus> for IncomingTransferStatus {
    fn from(status: dto::IncomingTransferStatus) -> Self {
        use dto::IncomingTransferStatus as S;
        match status {
            S::Pending => Self::Pending,
            S::InProgress => Self::InProgress,
            S::Completed => Self::Completed,
            S::Failed => Self::Failed,
            S::Canceled => Self::Canceled,
            S::Other { raw } => Self::Other { raw },
        }
    }
}

/// A transfer another device offered to this one.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct IncomingTransfer {
    pub transfer_id: String,
    pub sender_device_id: String,
    pub files: Vec<SendFile>,
    pub total_size: u64,
    pub offered_at: Option<SystemTime>,
    pub status: IncomingTransferStatus,
    pub failure: Option<TransferFailure>,
    /// Whether `receive_transfer` resumes it: it failed, was interrupted or was canceled.
    pub can_retry: bool,
    /// The Send link this offer arrived under, when this device redeemed that link: the engine
    /// then receives it by itself. `None` for any other offer.
    pub link_id: Option<String>,
    /// Bytes written so far while in progress; `total_size` once completed; 0 otherwise.
    pub received_bytes: u64,
    /// The folder the files are received into, once a receive chose one.
    pub destination_dir: Option<String>,
}

impl From<dto::IncomingTransfer> for IncomingTransfer {
    fn from(transfer: dto::IncomingTransfer) -> Self {
        Self {
            transfer_id: transfer.transfer_id,
            sender_device_id: transfer.sender_device_id,
            files: transfer.files.into_iter().map(Into::into).collect(),
            total_size: transfer.total_size,
            offered_at: transfer.offered_at,
            status: transfer.status.into(),
            failure: transfer.failure.map(Into::into),
            can_retry: transfer.can_retry,
            link_id: transfer.link_id,
            received_bytes: transfer.received_bytes,
            destination_dir: transfer.destination_dir,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum OutgoingTransferStatus {
    /// Not answered yet.
    Offered,
    /// The other device accepted it and may fetch it.
    Accepted,
    /// The other device reported that it received everything.
    Completed,
    Declined,
    Canceled,
    Other {
        raw: String,
    },
}

impl From<dto::OutgoingTransferStatus> for OutgoingTransferStatus {
    fn from(status: dto::OutgoingTransferStatus) -> Self {
        use dto::OutgoingTransferStatus as S;
        match status {
            S::Offered => Self::Offered,
            S::Accepted => Self::Accepted,
            S::Completed => Self::Completed,
            S::Declined => Self::Declined,
            S::Canceled => Self::Canceled,
            S::Other { raw } => Self::Other { raw },
        }
    }
}

/// A transfer this device sent.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OutgoingTransfer {
    pub transfer_id: String,
    pub target_device_id: String,
    pub files: Vec<SendFile>,
    pub total_size: u64,
    pub created_at: Option<SystemTime>,
    pub status: OutgoingTransferStatus,
    pub failure: Option<TransferFailure>,
}

impl From<dto::OutgoingTransfer> for OutgoingTransfer {
    fn from(transfer: dto::OutgoingTransfer) -> Self {
        Self {
            transfer_id: transfer.transfer_id,
            target_device_id: transfer.target_device_id,
            files: transfer.files.into_iter().map(Into::into).collect(),
            total_size: transfer.total_size,
            created_at: transfer.created_at,
            status: transfer.status.into(),
            failure: transfer.failure.map(Into::into),
        }
    }
}

/// A transfer received in full.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ReceivedTransfer {
    pub destination_dir: String,
    pub files_received: Vec<String>,
    pub bytes_received: u64,
}

impl From<dto::ReceivedTransfer> for ReceivedTransfer {
    fn from(received: dto::ReceivedTransfer) -> Self {
        Self {
            destination_dir: received.destination_dir,
            files_received: received.files_received,
            bytes_received: received.bytes_received,
        }
    }
}

/// Every command takes a cancel handle (one per call) and an optional deadline, as elsewhere.
/// Reads and `send_to_link` are aborted when cancelled; the rest keep running and the failure
/// says so (`still_running`).
#[uniffi::export]
impl MobileHost {
    /// Mints a one-use expiring Send link for the files and folders at `source_paths` (absolute
    /// paths the app can read; copy a picked file into the app's container first).
    ///
    /// # Errors
    /// `Refused` with `SendLinksDisabled`, `LocalIdentityUnavailable` (signed out) or
    /// `CoordinationTransport`; the other [`CallFailure`] cases.
    pub fn create_send_link(
        &self,
        ttl: SendLinkTtl,
        source_paths: Vec<String>,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<SendLink, CallFailure> {
        let command = host::Command::CreateSendLink { ttl: ttl.into(), source_paths };
        match self.run(command, cancel, deadline_ms)? {
            host::CommandOutput::SendLink(link) => Ok(link.into()),
            other => Err(unexpected("create_send_link", &other)),
        }
    }

    /// Who sends the link a code names and what it carries, without redeeming it. Read-only.
    ///
    /// # Errors
    /// As `create_send_link`; an unusable code is `Refused` with `SendLinkInvalid`.
    pub fn preview_send_link(
        &self,
        code: String,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<SendLinkPreview, CallFailure> {
        match self.run(host::Command::PreviewSendLink { code }, cancel, deadline_ms)? {
            host::CommandOutput::SendLinkPreview(preview) => Ok(preview.into()),
            other => Err(unexpected("preview_send_link", &other)),
        }
    }

    /// Redeems a code with this device and returns the link id. Redeeming is the one consent: the
    /// engine receives the sender's offer by itself into `receive_dir` (absolute; `None` = a folder
    /// of its own choosing) as soon as the sender sends, while the engine is running. The offer
    /// shows in `list_inbox` with `link_id` set, its status and `received_bytes` following the
    /// receive.
    ///
    /// # Errors
    /// As `preview_send_link`.
    pub fn redeem_send_link(
        &self,
        code: String,
        receive_dir: Option<String>,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<String, CallFailure> {
        let command =
            host::Command::RedeemSendLink { code, device_id: None, destination_dir: receive_dir };
        match self.run(command, cancel, deadline_ms)? {
            host::CommandOutput::SendLinkRedeemed(link_id) => Ok(link_id),
            other => Err(unexpected("redeem_send_link", &other)),
        }
    }

    /// Cancels a link this device created; a grant it issued but nobody used is revoked with it.
    ///
    /// # Errors
    /// As `preview_send_link`.
    pub fn cancel_send_link(
        &self,
        link_id: String,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<(), CallFailure> {
        match self.run(host::Command::CancelSendLink { link_id }, cancel, deadline_ms)? {
            host::CommandOutput::Done => Ok(()),
            other => Err(unexpected("cancel_send_link", &other)),
        }
    }

    /// The sender's view of one link. Read-only.
    ///
    /// # Errors
    /// As `preview_send_link`.
    pub fn send_link_status(
        &self,
        link_id: String,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<SendLinkStatus, CallFailure> {
        match self.run(host::Command::SendLinkStatus { link_id }, cancel, deadline_ms)? {
            host::CommandOutput::SendLinkStatus(status) => Ok(status.into()),
            other => Err(unexpected("send_link_status", &other)),
        }
    }

    /// The links this device created, newest first, each with its status. The engine keeps the
    /// list across restarts. Read-only.
    ///
    /// # Errors
    /// As `preview_send_link`.
    pub fn list_send_links(
        &self,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<Vec<SendLinkListing>, CallFailure> {
        match self.run(host::Command::ListSendLinks, cancel, deadline_ms)? {
            host::CommandOutput::SendLinks(links) => {
                Ok(links.into_iter().map(Into::into).collect())
            }
            other => Err(unexpected("list_send_links", &other)),
        }
    }

    /// Waits for the recipient to redeem the link (up to ten minutes), then offers the files at
    /// `source_paths` under it; the engine serves them while it runs, so keep it running until
    /// `send_link_status` says `Done`. Cancelling the call ends the wait.
    ///
    /// # Errors
    /// As `preview_send_link`, with `SendLinkAlreadyUsed`, `SendLinkCancelled`,
    /// `SendLinkExpired` and `SendPeerUnreachable`.
    pub fn send_to_link(
        &self,
        link_id: String,
        source_paths: Vec<String>,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<OfferedTransfer, CallFailure> {
        match self.run(host::Command::SendToLink { link_id, source_paths }, cancel, deadline_ms)? {
            host::CommandOutput::SendOffered(sent) => Ok(sent.into()),
            other => Err(unexpected("send_to_link", &other)),
        }
    }

    /// Every transfer other devices offered to this device. Read-only.
    ///
    /// # Errors
    /// The [`CallFailure`] cases.
    pub fn list_inbox(
        &self,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<Vec<IncomingTransfer>, CallFailure> {
        match self.run(host::Command::ListInbox, cancel, deadline_ms)? {
            host::CommandOutput::Inbox(transfers) => {
                Ok(transfers.into_iter().map(Into::into).collect())
            }
            other => Err(unexpected("list_inbox", &other)),
        }
    }

    /// The transfers this device sent. Read-only.
    ///
    /// # Errors
    /// The [`CallFailure`] cases.
    pub fn list_sent_transfers(
        &self,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<Vec<OutgoingTransfer>, CallFailure> {
        match self.run(host::Command::ListSentTransfers, cancel, deadline_ms)? {
            host::CommandOutput::SentTransfers(transfers) => {
                Ok(transfers.into_iter().map(Into::into).collect())
            }
            other => Err(unexpected("list_sent_transfers", &other)),
        }
    }

    /// Accepts an inbound transfer and pulls it into `destination_dir` (an absolute path; `None`
    /// is the engine's inbox directory). Resumable: a transfer that failed, was interrupted by a
    /// suspend or stop, or was cancelled fetches only what never arrived.
    ///
    /// # Errors
    /// `Refused` with `SendPeerUnreachable`, `SendNoSpace` or `SendInterrupted`; the other
    /// [`CallFailure`] cases.
    pub fn receive_transfer(
        &self,
        transfer_id: String,
        destination_dir: Option<String>,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<ReceivedTransfer, CallFailure> {
        let command = host::Command::ReceiveTransfer { transfer_id, destination_dir };
        match self.run(command, cancel, deadline_ms)? {
            host::CommandOutput::Received(received) => Ok(received.into()),
            other => Err(unexpected("receive_transfer", &other)),
        }
    }

    /// Stops a transfer by id, whichever side this device is on: a running receive ends and the
    /// transfer is marked cancelled. Idempotent.
    ///
    /// # Errors
    /// The [`CallFailure`] cases; an unknown transfer is `Failed`.
    pub fn cancel_transfer(
        &self,
        transfer_id: String,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<(), CallFailure> {
        match self.run(host::Command::CancelTransfer { transfer_id }, cancel, deadline_ms)? {
            host::CommandOutput::Done => Ok(()),
            other => Err(unexpected("cancel_transfer", &other)),
        }
    }
}
