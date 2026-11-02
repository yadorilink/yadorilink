//! The Send commands an app needs: cross-account Send links (create, preview, redeem, cancel,
//! status, the sender's list) and the transfers under them (send, inbox, receive, cancel).
//! Each runs the service function the desktop control socket's handler runs and refuses with the
//! same typed codes (`SendFailure`), and answers in the same wire shapes.
//!
//! Lifecycle: the embedded engine lives only while the host process does, so a transfer runs
//! only while the engine runs. The sender serves its files while its engine is up, and the
//! recipient pulls while its own is. A receive the engine's stop cuts off is recorded as
//! interrupted and resumes (only what never arrived is fetched again) the next time it is
//! received; a send whose serving stopped is made again under a new link.

use yadorilink_ipc_proto::daemonctl::{
    CreateSendLinkResponse, InboxTransfer, PreviewSendLinkResponse, ReceiveTransferResponse,
    SendFileResponse, SendLinkFile, SendLinkStatusResponse, SentTransferEntry,
};

use super::{CommandError, EngineCommands};
use crate::send_transfer::SendFailure;

impl From<SendFailure> for CommandError {
    fn from(failure: SendFailure) -> Self {
        match failure.code {
            Some(code) => Self::refused(code, failure.message, String::new()),
            None => Self::failed(failure.message),
        }
    }
}

/// One link of the sender's list.
#[derive(Debug, Clone, PartialEq)]
pub struct SentLink {
    pub link_id: String,
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
    /// How many files the link was created to carry.
    pub file_count: u32,
    pub status: SendLinkStatusResponse,
}

impl EngineCommands {
    /// Mints a one-use expiring Send link for the files and folders at `source_paths` (absolute
    /// paths); `ttl_seconds` 0 is the service default. The code is shown once.
    ///
    /// # Errors
    /// [`CommandError`]; the typed codes are the control socket's (`SendLinksDisabled` when the
    /// service has Send links off, `LocalIdentityUnavailable` signed out).
    pub async fn create_send_link(
        &self,
        ttl_seconds: u32,
        source_paths: &[String],
    ) -> Result<CreateSendLinkResponse, CommandError> {
        let link =
            self.context.application.send_transfer.create_link(ttl_seconds, source_paths).await?;
        Ok(CreateSendLinkResponse {
            link_id: link.link_id,
            code: link.code,
            expires_at_unix: link.expires_at_unix,
        })
    }

    /// Who sends the link `code` names and what it carries, without redeeming it.
    ///
    /// # Errors
    /// As [`Self::create_send_link`]; an unusable code is `SendLinkInvalid`.
    pub async fn preview_send_link(
        &self,
        code: &str,
    ) -> Result<PreviewSendLinkResponse, CommandError> {
        let preview = self.context.application.send_transfer.preview_link(code).await?;
        Ok(PreviewSendLinkResponse {
            sender_name: preview.sender_name,
            files: preview
                .files
                .into_iter()
                .map(|(name, size)| SendLinkFile { name, size })
                .collect(),
            expires_at_unix: preview.expires_at_unix,
        })
    }

    /// Redeems `code` with `device_id` (empty: this device) and returns the link id. The offer
    /// that arrives under the link is received into `destination_dir` (absolute; empty: a folder
    /// of the engine's own choosing) without another step.
    ///
    /// # Errors
    /// As [`Self::preview_send_link`].
    pub async fn redeem_send_link(
        &self,
        code: &str,
        device_id: &str,
        destination_dir: &str,
    ) -> Result<String, CommandError> {
        let (link_id, _) = self
            .context
            .application
            .send_transfer
            .redeem_link(code, device_id, destination_dir)
            .await?;
        Ok(link_id)
    }

    /// Cancels a link this device created.
    ///
    /// # Errors
    /// As [`Self::preview_send_link`].
    pub async fn cancel_send_link(&self, link_id: &str) -> Result<(), CommandError> {
        Ok(self.context.application.send_transfer.cancel_link(link_id).await?)
    }

    /// The sender's view of one link.
    ///
    /// # Errors
    /// As [`Self::preview_send_link`].
    pub async fn send_link_status(
        &self,
        link_id: &str,
    ) -> Result<SendLinkStatusResponse, CommandError> {
        let view = self.context.application.send_transfer.link_status(link_id).await?;
        Ok(status_to_proto(view))
    }

    /// The links this device created, newest first, each with its status. The list is kept
    /// across restarts; a link the service no longer knows is dropped from it.
    ///
    /// # Errors
    /// As [`Self::preview_send_link`].
    pub async fn list_send_links(&self) -> Result<Vec<SentLink>, CommandError> {
        let listed = self.context.application.send_transfer.list_links().await?;
        Ok(listed
            .into_iter()
            .map(|l| SentLink {
                link_id: l.link_id,
                created_at_unix: l.created_at_unix,
                expires_at_unix: l.expires_at_unix,
                file_count: l.file_count,
                status: status_to_proto(l.view),
            })
            .collect())
    }

    /// Waits for the recipient to redeem the link `link_id` (up to ten minutes), then offers
    /// the files at `source_paths` under it. The engine serves them to the recipient for as
    /// long as it runs.
    ///
    /// # Errors
    /// As [`Self::preview_send_link`], and `SendLinkAlreadyUsed`, `SendLinkCancelled` or
    /// `SendLinkExpired` for a link that cannot carry a send, `SendPeerUnreachable` when the
    /// recipient's device cannot be reached.
    pub async fn send_to_link(
        &self,
        link_id: &str,
        source_paths: &[String],
    ) -> Result<SendFileResponse, CommandError> {
        let outcome = self
            .context
            .application
            .send_transfer
            .send(source_paths, &format!("link:{link_id}"))
            .await?;
        Ok(SendFileResponse {
            transfer_id: outcome.transfer_id,
            files_offered: outcome.files_offered,
            total_size: outcome.total_size,
        })
    }

    /// Every transfer other devices offered to this device.
    ///
    /// # Errors
    /// [`CommandError`] when the Send service is not ready or its store cannot be read.
    pub fn list_inbox(&self) -> Result<Vec<InboxTransfer>, CommandError> {
        let entries = self.context.queries.inbox.list().map_err(CommandError::failed)?;
        Ok(entries.into_iter().map(crate::send_transfer::inbox_entry_to_proto).collect())
    }

    /// The transfers this device sent.
    ///
    /// # Errors
    /// As [`Self::list_inbox`].
    pub fn list_sent_transfers(&self) -> Result<Vec<SentTransferEntry>, CommandError> {
        let entries = self.context.queries.inbox.list_sent().map_err(CommandError::failed)?;
        Ok(entries.into_iter().map(crate::send_transfer::sent_entry_to_proto).collect())
    }

    /// Accepts an inbound transfer into `destination_dir` (absolute; `None`: the engine's inbox
    /// directory) and pulls it. Resumable: a transfer that failed, was interrupted or was
    /// cancelled picks up where it stopped.
    ///
    /// # Errors
    /// [`CommandError`]; `SendPeerUnreachable`, `SendNoSpace` and `SendInterrupted` are typed.
    pub async fn receive_transfer(
        &self,
        transfer_id: &str,
        destination_dir: Option<&str>,
    ) -> Result<ReceiveTransferResponse, CommandError> {
        let outcome =
            self.context.application.send_transfer.receive(transfer_id, destination_dir).await?;
        Ok(ReceiveTransferResponse {
            destination_dir: outcome.destination_dir.to_string_lossy().into_owned(),
            files_received: outcome.files_received,
            bytes_received: outcome.bytes_received,
        })
    }

    /// Stops a transfer by id, whichever side this device is on: a running receive ends and
    /// the transfer is marked cancelled (a later receive resumes it). Idempotent.
    ///
    /// # Errors
    /// [`CommandError`] for an unknown transfer.
    pub fn cancel_transfer(&self, transfer_id: &str) -> Result<(), CommandError> {
        self.context.application.send_transfer.cancel(transfer_id).map_err(CommandError::failed)
    }
}

fn status_to_proto(view: crate::send_transfer::LinkStatusView) -> SendLinkStatusResponse {
    SendLinkStatusResponse {
        state: view.state as i32,
        receiver_device_name: view.receiver_device_name,
        transfer_id: view.transfer_id,
    }
}
