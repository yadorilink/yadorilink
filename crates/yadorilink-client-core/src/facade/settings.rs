//! Send and receive, storage, limits, diagnostics, the daemon's lifecycle,
//! updates, and the account's own records.

use std::path::Path;

use super::ClientCore;
use crate::dto::{
    self, AccountDeletionRequest, AccountDeletionStatus, BandwidthLimits, DaemonStartOutcome,
    DiagnosticsCollectionMode, DiagnosticsExport, GcReport, IncomingTransfer, OutgoingTransfer,
    ReceivedTransfer, SentTransfer, SpaceManagement, SpaceReclaimPreview, UpdateConfig,
    UpdateDownloadGuidance, UpdateStatus,
};
use crate::error::{CoreError, DaemonUnavailableReason, DesktopError};
use crate::ops;
use crate::ops::diagnostics::BundleRequest;
use crate::ops::transfers::RetryDirection;

fn limits(up: u64, down: u64) -> BandwidthLimits {
    BandwidthLimits {
        upload_bytes_per_sec: (up > 0).then_some(up),
        download_bytes_per_sec: (down > 0).then_some(down),
    }
}

fn collection_mode(raw: &str) -> DiagnosticsCollectionMode {
    match raw {
        "daemon" => DiagnosticsCollectionMode::Daemon,
        "daemon-partial" => DiagnosticsCollectionMode::DaemonPartial,
        _ => DiagnosticsCollectionMode::OfflineFallback,
    }
}

/// Writes a diagnostics bundle to `destination`, creating its directory.
fn write_bundle(destination: &Path, bundle: &serde_json::Value) -> Result<(), CoreError> {
    let contents = serde_json::to_string_pretty(bundle)?;
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent).map_err(|e| CoreError::Io(e.to_string()))?;
    }
    std::fs::write(destination, contents).map_err(|e| CoreError::Io(e.to_string()))
}

impl ClientCore {
    // ---- send and receive --------------------------------------------------------

    /// # Errors
    /// Daemon failures.
    pub async fn send_to_device(
        &self,
        source_path: String,
        target_device_id: String,
    ) -> Result<SentTransfer, DesktopError> {
        Ok(dto::sent_transfer(ops::transfers::send_file(source_path, target_device_id).await?))
    }

    /// # Errors
    /// Daemon failures.
    pub async fn list_inbox(&self) -> Result<Vec<IncomingTransfer>, DesktopError> {
        Ok(ops::transfers::list_inbox().await?.iter().map(dto::incoming_transfer).collect())
    }

    /// # Errors
    /// Daemon failures.
    pub async fn receive_transfer(
        &self,
        transfer_id: String,
        destination_dir: Option<String>,
    ) -> Result<ReceivedTransfer, DesktopError> {
        let received = ops::transfers::receive_transfer(transfer_id, destination_dir).await?;
        Ok(dto::received_transfer(received))
    }

    /// The transfers this device sent: every one still going and the most recent finished ones,
    /// oldest first. Survives a restart; the history is bounded.
    ///
    /// # Errors
    /// Daemon failures.
    pub async fn list_sent_transfers(&self) -> Result<Vec<OutgoingTransfer>, DesktopError> {
        Ok(ops::transfers::list_sent().await?.iter().map(dto::outgoing_transfer).collect())
    }

    /// Stops a transfer by id, sent or received. Canceling one already canceled or completed
    /// succeeds, and a completed one is never undone.
    ///
    /// # Errors
    /// Daemon failures, including an unknown transfer id.
    pub async fn cancel_transfer(&self, transfer_id: String) -> Result<(), DesktopError> {
        Ok(ops::transfers::cancel_transfer(transfer_id).await?)
    }

    /// Resumes a failed or canceled received transfer after the daemon re-validates it.
    ///
    /// # Errors
    /// Daemon failures, including an unknown transfer id or one this device sent.
    pub async fn retry_transfer(
        &self,
        transfer_id: String,
    ) -> Result<ReceivedTransfer, DesktopError> {
        match ops::transfers::retry_transfer(transfer_id, RetryDirection::Received).await? {
            ops::transfers::Retried::Received(received) => Ok(dto::received_transfer(received)),
            ops::transfers::Retried::Offered(_) => Err(DesktopError::from_core(
                CoreError::Other("the daemon offered a transfer for a received-side retry".into()),
                false,
            )),
        }
    }

    /// Offers a sent transfer that was canceled, declined or never answered again. The daemon
    /// checks the offered files are unchanged and asks for a new authorization for the same
    /// device; it never reuses an old one, so a transfer whose files changed or whose device can
    /// no longer be authorized is refused and has to be sent again.
    ///
    /// # Errors
    /// Daemon failures, including an unknown transfer id or one this device received.
    pub async fn retry_sent_transfer(
        &self,
        transfer_id: String,
    ) -> Result<SentTransfer, DesktopError> {
        match ops::transfers::retry_transfer(transfer_id, RetryDirection::Sent).await? {
            ops::transfers::Retried::Offered(sent) => Ok(dto::sent_transfer(sent)),
            ops::transfers::Retried::Received(_) => Err(DesktopError::from_core(
                CoreError::Other("the daemon received a transfer for a sent-side retry".into()),
                false,
            )),
        }
    }

    // ---- storage and limits ----------------------------------------------------------

    /// # Errors
    /// Daemon failures, including a refusal while a sweep or sync is running.
    pub async fn run_gc(&self, dry_run: bool) -> Result<GcReport, DesktopError> {
        Ok(dto::gc_report(dry_run, &ops::storage::run_gc(dry_run).await?))
    }

    /// # Errors
    /// Daemon failures.
    pub async fn space_management(&self) -> Result<SpaceManagement, DesktopError> {
        Ok(dto::space_management(Some(&ops::storage::space_management().await?)))
    }

    /// Stores the setting and returns what was stored.
    ///
    /// # Errors
    /// Daemon failures.
    pub async fn set_space_management(
        &self,
        enabled: bool,
    ) -> Result<SpaceManagement, DesktopError> {
        Ok(dto::space_management(Some(&ops::storage::set_space_management(enabled).await?)))
    }

    /// What automatic space management would do now; nothing is removed.
    ///
    /// # Errors
    /// Daemon failures.
    pub async fn preview_space_reclaim(&self) -> Result<SpaceReclaimPreview, DesktopError> {
        Ok(dto::space_reclaim_preview(&ops::storage::preview_space_reclaim().await?))
    }

    /// # Errors
    /// Daemon failures.
    pub async fn bandwidth_limits(&self) -> Result<BandwidthLimits, DesktopError> {
        let current = ops::storage::bandwidth_limits().await?;
        Ok(limits(current.upload_bytes_per_sec, current.download_bytes_per_sec))
    }

    /// Sets both limits (`None` is unlimited) and returns what was applied.
    ///
    /// # Errors
    /// Daemon failures.
    pub async fn set_bandwidth_limits(
        &self,
        requested: BandwidthLimits,
    ) -> Result<BandwidthLimits, DesktopError> {
        let applied = ops::storage::set_bandwidth_limits(
            requested.upload_bytes_per_sec.unwrap_or(0),
            requested.download_bytes_per_sec.unwrap_or(0),
        )
        .await?;
        Ok(limits(applied.upload_bytes_per_sec, applied.download_bytes_per_sec))
    }

    // ---- diagnostics and the daemon -------------------------------------------------

    /// Writes a redacted diagnostics bundle to `destination_path`. Works when
    /// the daemon is down, with a limited bundle.
    ///
    /// # Errors
    /// A daemon failure other than being down, or the file write.
    pub async fn export_diagnostics(
        &self,
        destination_path: String,
    ) -> Result<DiagnosticsExport, DesktopError> {
        let collected = ops::diagnostics::collect_bundle(BundleRequest::Export).await?;
        write_bundle(Path::new(&destination_path), &collected.bundle)?;
        Ok(DiagnosticsExport {
            path: destination_path,
            collection_mode: collection_mode(&collected.collection_mode),
            redaction_count: u32::try_from(collected.redaction_count).unwrap_or(u32::MAX),
        })
    }

    /// Brings the daemon up with this core's launch strategy, unless it
    /// already answers.
    ///
    /// # Errors
    /// `DaemonUnavailable{NotRunning}` naming what was tried when it could
    /// not be brought up; `DaemonUnavailable{Unresponsive}`, launching
    /// nothing, when a daemon is running but does not answer.
    pub async fn start_daemon(&self) -> Result<DaemonStartOutcome, DesktopError> {
        match ops::daemon::start_daemon_with(&self.config().daemon_launch).await {
            Ok(ops::daemon::DaemonStartOutcome::AlreadyRunning) => {
                Ok(DaemonStartOutcome::AlreadyRunning)
            }
            Ok(ops::daemon::DaemonStartOutcome::Started) => Ok(DaemonStartOutcome::Started),
            Err(CoreError::Other(message)) => Err(DesktopError::DaemonUnavailable {
                message,
                reason: DaemonUnavailableReason::NotRunning,
            }),
            Err(other) => Err(other.into()),
        }
    }

    /// Asks the daemon to exit; under launchd it is started again, so this
    /// is also how the daemon is restarted.
    ///
    /// # Errors
    /// Daemon failures.
    pub async fn stop_daemon(&self) -> Result<(), DesktopError> {
        Ok(ops::daemon::stop_daemon().await?)
    }

    /// Asks the daemon to reach a safe point and exit with success: it stops taking new link
    /// operations, lets writes in flight finish, checkpoints its databases and begins to exit.
    /// `Busy` means it kept running (a write did not finish within `deadline_secs`, 30 by
    /// default, at most 300): retry after the hinted wait. Never kills anything; repeating the
    /// call is safe. Used before an updater replaces the app and before uninstall.
    ///
    /// # Errors
    /// The daemon is not running or does not answer.
    pub async fn request_safe_stop(
        &self,
        deadline_secs: Option<u32>,
    ) -> Result<crate::dto::SafeStopOutcome, DesktopError> {
        let deadline = deadline_secs.map(|s| std::time::Duration::from_secs(u64::from(s)));
        Ok(dto::safe_stop_outcome(&ops::daemon::request_safe_stop(deadline).await?))
    }

    /// Who the running daemon is and who owns its data area. Read-only.
    ///
    /// # Errors
    /// The daemon is not running or does not answer.
    pub async fn daemon_identity(&self) -> Result<crate::dto::DaemonIdentity, DesktopError> {
        Ok(dto::daemon_identity(&ops::daemon::identify().await?))
    }

    // ---- updates -------------------------------------------------------------------

    /// # Errors
    /// Daemon failures.
    pub async fn update_status(&self) -> Result<UpdateStatus, DesktopError> {
        Ok(dto::update_status(&ops::updates::update_status().await?))
    }

    /// # Errors
    /// Daemon failures.
    pub async fn check_for_updates(&self) -> Result<UpdateStatus, DesktopError> {
        let check = ops::updates::check_for_updates().await?;
        let status = check.status.ok_or_else(|| {
            DesktopError::from(CoreError::Other("the update check returned no status".into()))
        })?;
        Ok(dto::update_status(&status))
    }

    /// Where to get the new version: the official download page, or the
    /// package-manager command for a package-managed install. YadoriLink
    /// never downloads or installs an update itself.
    ///
    /// # Errors
    /// Daemon failures, and a daemon reply that claims anything but a manual
    /// download.
    pub async fn download_guidance(&self) -> Result<UpdateDownloadGuidance, DesktopError> {
        let reply = ops::updates::download_guidance().await?;
        dto::update_download_guidance(&reply)
            .map_err(|reason| DesktopError::from(CoreError::Other(reason)))
    }

    /// Turns the automatic check for a newer version on or off. This is the
    /// only update setting: updates are never installed automatically.
    ///
    /// # Errors
    /// Daemon failures.
    pub async fn set_automatic_update_checks(
        &self,
        enabled: bool,
    ) -> Result<UpdateConfig, DesktopError> {
        Ok(dto::update_config(&ops::updates::set_update_config(Some(enabled)).await?))
    }

    // ---- account -------------------------------------------------------------------

    /// # Errors
    /// Coordination failures.
    pub async fn account_deletion_status(&self) -> Result<AccountDeletionStatus, DesktopError> {
        Ok(dto::account_deletion_status(&ops::account::deletion_status().await?))
    }

    /// Asks for account deletion; nothing is deleted until it is confirmed
    /// with the returned token.
    ///
    /// # Errors
    /// Coordination failures.
    pub async fn request_account_deletion(&self) -> Result<AccountDeletionRequest, DesktopError> {
        let requested = ops::account::request_deletion().await?;
        Ok(AccountDeletionRequest { confirmation_token: requested.confirmation_token })
    }

    /// # Errors
    /// Coordination failures.
    pub async fn confirm_account_deletion(
        &self,
        confirmation_token: String,
    ) -> Result<AccountDeletionStatus, DesktopError> {
        let status = ops::account::confirm_deletion(confirmation_token).await?;
        Ok(dto::account_deletion_status(&status))
    }

    /// # Errors
    /// Coordination failures.
    pub async fn cancel_account_deletion(&self) -> Result<AccountDeletionStatus, DesktopError> {
        Ok(dto::account_deletion_status(&ops::account::cancel_deletion().await?))
    }

    /// The account's server-side records as pretty-printed JSON; the front
    /// end saves it where the person chooses.
    ///
    /// # Errors
    /// Coordination failures.
    pub async fn export_account_data(&self) -> Result<String, DesktopError> {
        Ok(ops::account::export_account_json().await?)
    }
}
