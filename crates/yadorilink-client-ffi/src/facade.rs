//! The exported `ClientCore`: one forwarding method per facade method, each
//! run on the client runtime through [`crate::bridge`]. Errors and docs are
//! those of `yadorilink_client_core::ClientCore`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use yadorilink_client_core as core;
use yadorilink_client_core::dto::*;
use yadorilink_client_core::DesktopError;

use crate::{bridge, guarded, runtime, AdminSession, LoginSession, NasAdminOpening, StatusWatch};

/// The client facade. Every async method runs on the client runtime.
#[derive(uniffi::Object)]
pub struct ClientCore {
    inner: Arc<core::ClientCore>,
}

#[uniffi::export]
impl ClientCore {
    /// Performs no I/O.
    #[uniffi::constructor]
    pub fn new(config: CoreConfig) -> Arc<Self> {
        Arc::new(ClientCore { inner: core::ClientCore::new(config) })
    }

    /// The engine API version this library speaks.
    pub fn engine_api_version(&self) -> u32 {
        self.inner.engine_api_version()
    }

    /// Sign-in, registration and linked-folder state; never fails. Should
    /// the call itself fail unexpectedly, it reads as signed out with the
    /// daemon's answer unknown.
    pub async fn account_status(&self) -> AccountStatus {
        let core = self.inner.clone();
        bridge(async move { Ok(core.account_status().await) }).await.unwrap_or_else(|_| {
            AccountStatus {
                sign_in: SignInState::SignedOut,
                client_id: None,
                this_device_id: None,
                device_registered: false,
                default_device_name: String::new(),
                has_linked_folders: None,
                start_over_pending: false,
            }
        })
    }

    /// A sign-in that has not started yet.
    pub fn new_login_session(&self, options: LoginOptions) -> Arc<LoginSession> {
        LoginSession::wrap(self.inner.new_login_session(options))
    }

    /// A sign-in of this installation for an action refused with
    /// `PermissionDenied(ReauthenticationRequired)`; read like a login session.
    pub fn new_reauthentication_session(&self, options: LoginOptions) -> Arc<LoginSession> {
        LoginSession::wrap(self.inner.new_reauthentication_session(options))
    }

    /// Starts the status poll loop on the client runtime. If the runtime
    /// cannot start, the watch ends at once.
    pub fn watch_status(&self, interval: Duration) -> Arc<StatusWatch> {
        let core = self.inner.clone();
        let start = move || match runtime() {
            Ok(runtime) => {
                let _entered = runtime.enter();
                core.watch_status(interval)
            }
            Err(_) => core.watch_status(interval),
        };
        let inner = guarded(
            || {
                Arc::new(core::session::StatusWatch::start(
                    Arc::new(|| Box::pin(async { unreachable_update() })),
                    interval,
                ))
            },
            start,
        );
        Arc::new(StatusWatch { inner })
    }

    // ---- session and identity ----
    /// Revokes this installation, then removes its credential.
    pub async fn sign_out(&self) -> Result<SignOutOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.sign_out().await }).await
    }
    pub async fn register_device(&self, name: String) -> Result<DeviceRegistration, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.register_device(name).await }).await
    }
    /// Starts over as a new device after a restored database, or continues one; see
    /// `ClientCore::start_over_as_new_device`.
    pub async fn start_over_as_new_device(
        &self,
        confirmed: bool,
        name: String,
    ) -> Result<StartOverProgress, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.start_over_as_new_device(confirmed, name).await }).await
    }

    /// Records the person's explicit acknowledgement of possible loss for a waiting replacement;
    /// see `ClientCore::acknowledge_possible_loss`.
    pub async fn acknowledge_possible_loss(&self) -> Result<bool, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.acknowledge_possible_loss().await }).await
    }

    // ---- status ----
    pub async fn status_snapshot(&self) -> Result<StatusSnapshot, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.status_snapshot().await }).await
    }
    pub async fn folder_detail(&self, local_path: String) -> Result<FolderDetail, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.folder_detail(local_path).await }).await
    }
    /// Other devices with access to each linked folder's group, by group id.
    pub async fn folder_peer_counts(&self) -> Result<HashMap<String, u32>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.folder_peer_counts().await }).await
    }

    // ---- conflicts and kept originals ----
    pub async fn resolve_conflict(
        &self,
        copy_path: String,
        choice: ConflictChoice,
    ) -> Result<String, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.resolve_conflict(copy_path, choice).await }).await
    }
    pub async fn list_retained_originals(&self) -> Result<Vec<RetainedOriginal>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.list_retained_originals().await }).await
    }
    pub async fn release_retained_originals(
        &self,
        group_id: String,
    ) -> Result<Vec<RetainedRelease>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.release_retained_originals(group_id).await }).await
    }

    // ---- folder control ----
    pub async fn pause_folder(
        &self,
        local_path: String,
        duration: PauseDuration,
        expected_group_id: Option<String>,
    ) -> Result<(), DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.pause_folder(local_path, duration, expected_group_id).await })
            .await
    }
    pub async fn resume_folder(
        &self,
        local_path: String,
        expected_group_id: Option<String>,
    ) -> Result<(), DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.resume_folder(local_path, expected_group_id).await }).await
    }
    pub async fn pause_all(&self, duration: PauseDuration) -> Result<(), DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.pause_all(duration).await }).await
    }
    pub async fn resume_all(&self) -> Result<(), DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.resume_all().await }).await
    }
    pub async fn unlink_folder(
        &self,
        local_path: String,
        force: bool,
        expected_group_id: Option<String>,
    ) -> Result<UnlinkOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.unlink_folder(local_path, force, expected_group_id).await }).await
    }
    pub async fn readopt_folder(&self, local_path: String) -> Result<(), DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.readopt_folder(local_path).await }).await
    }
    pub async fn set_storage_mode(
        &self,
        group_id: String,
        mode: FolderMode,
    ) -> Result<StorageModeOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.set_storage_mode(group_id, mode).await }).await
    }

    // ---- files ----
    pub async fn list_conflicts(
        &self,
        local_path: Option<String>,
    ) -> Result<Vec<ConflictSummary>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.list_conflicts(local_path).await }).await
    }
    pub async fn list_trash(
        &self,
        local_path: Option<String>,
    ) -> Result<Vec<TrashedFile>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.list_trash(local_path).await }).await
    }
    pub async fn restore_from_trash(&self, absolute_path: String) -> Result<(), DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.restore_from_trash(absolute_path).await }).await
    }
    pub async fn restore_trash_operation(
        &self,
        absolute_path: String,
    ) -> Result<FolderRestoreOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.restore_trash_operation(absolute_path).await }).await
    }
    // ---- folder rewind ----
    pub async fn rewind_preview(
        &self,
        group_id: String,
        at: std::time::SystemTime,
    ) -> Result<RewindPreview, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.rewind_preview(group_id, at).await }).await
    }
    pub async fn rewind_execute(
        &self,
        group_id: String,
        target_unix_nanos: i64,
        plan_id: Vec<u8>,
    ) -> Result<RewindStartOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.rewind_execute(group_id, target_unix_nanos, plan_id).await }).await
    }
    pub async fn rewind_latest(&self, group_id: String) -> Result<Option<RewindRun>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.rewind_latest(group_id).await }).await
    }
    pub async fn rewind_follow(
        &self,
        group_id: String,
        run_id: String,
    ) -> Result<RewindRun, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.rewind_follow(group_id, run_id).await }).await
    }
    pub async fn list_versions(
        &self,
        absolute_path: String,
    ) -> Result<Vec<FileVersion>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.list_versions(absolute_path).await }).await
    }
    pub async fn restore_version(
        &self,
        absolute_path: String,
        version_seq: Option<i64>,
    ) -> Result<(), DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.restore_version(absolute_path, version_seq).await }).await
    }
    pub async fn file_availability(
        &self,
        absolute_path: String,
    ) -> Result<FileAvailability, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.file_availability(absolute_path).await }).await
    }
    pub async fn file_retention(
        &self,
        absolute_path: String,
    ) -> Result<FileRetention, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.file_retention(absolute_path).await }).await
    }
    pub async fn pin_file(&self, absolute_path: String) -> Result<PinOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.pin_file(absolute_path).await }).await
    }
    pub async fn unpin_file(&self, absolute_path: String) -> Result<FileRetention, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.unpin_file(absolute_path).await }).await
    }
    pub async fn hydrate_file(&self, absolute_path: String) -> Result<(), DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.hydrate_file(absolute_path).await }).await
    }
    pub async fn evict_file(&self, absolute_path: String) -> Result<EvictOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.evict_file(absolute_path).await }).await
    }

    // ---- devices ----
    pub async fn list_folder_devices(&self) -> Result<Vec<DeviceSummary>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.list_folder_devices().await }).await
    }
    pub async fn list_account_devices(&self) -> Result<Vec<DeviceSummary>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.list_account_devices().await }).await
    }
    pub async fn remove_device(
        &self,
        device_id: String,
        force: bool,
    ) -> Result<MembershipOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.remove_device(device_id, force).await }).await
    }

    /// Opens a device's management page; see
    /// `yadorilink_client_core::ClientCore::open_nas_admin`.
    pub async fn open_nas_admin(&self, device_id: String) -> Result<NasAdminOpening, DesktopError> {
        let core = self.inner.clone();
        bridge(async move {
            Ok(match core.open_nas_admin(device_id).await? {
                core::ops::nas_admin::NasAdminOpen::Opened(session) => {
                    NasAdminOpening::Opened { session: Arc::new(AdminSession::wrap(session)) }
                }
                core::ops::nas_admin::NasAdminOpen::Failed(failure) => NasAdminOpening::Failed {
                    failure,
                    message: core::wording::nas_admin_failure_message(failure).to_string(),
                },
            })
        })
        .await
    }

    /// The sentence to show for `failure`, worded once in client-core.
    #[must_use]
    pub fn nas_admin_failure_message(&self, failure: core::wording::NasAdminFailure) -> String {
        core::wording::nas_admin_failure_message(failure).to_string()
    }

    // ---- send and receive ----
    pub async fn send_to_device(
        &self,
        source_path: String,
        target_device_id: String,
    ) -> Result<SentTransfer, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.send_to_device(source_path, target_device_id).await }).await
    }
    pub async fn list_inbox(&self) -> Result<Vec<IncomingTransfer>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.list_inbox().await }).await
    }
    pub async fn receive_transfer(
        &self,
        transfer_id: String,
        destination_dir: Option<String>,
    ) -> Result<ReceivedTransfer, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.receive_transfer(transfer_id, destination_dir).await }).await
    }

    pub async fn cancel_transfer(&self, transfer_id: String) -> Result<(), DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.cancel_transfer(transfer_id).await }).await
    }
    pub async fn retry_transfer(
        &self,
        transfer_id: String,
    ) -> Result<ReceivedTransfer, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.retry_transfer(transfer_id).await }).await
    }
    pub async fn list_sent_transfers(&self) -> Result<Vec<OutgoingTransfer>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.list_sent_transfers().await }).await
    }
    pub async fn retry_sent_transfer(
        &self,
        transfer_id: String,
    ) -> Result<SentTransfer, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.retry_sent_transfer(transfer_id).await }).await
    }

    // ---- storage, settings and the daemon ----
    pub async fn run_gc(&self, dry_run: bool) -> Result<GcReport, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.run_gc(dry_run).await }).await
    }
    pub async fn space_management(&self) -> Result<SpaceManagement, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.space_management().await }).await
    }
    pub async fn set_space_management(
        &self,
        enabled: bool,
    ) -> Result<SpaceManagement, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.set_space_management(enabled).await }).await
    }
    pub async fn preview_space_reclaim(&self) -> Result<SpaceReclaimPreview, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.preview_space_reclaim().await }).await
    }
    pub async fn bandwidth_limits(&self) -> Result<BandwidthLimits, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.bandwidth_limits().await }).await
    }
    pub async fn set_bandwidth_limits(
        &self,
        limits: BandwidthLimits,
    ) -> Result<BandwidthLimits, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.set_bandwidth_limits(limits).await }).await
    }
    pub async fn export_diagnostics(
        &self,
        destination_path: String,
    ) -> Result<DiagnosticsExport, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.export_diagnostics(destination_path).await }).await
    }
    pub async fn start_daemon(&self) -> Result<DaemonStartOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.start_daemon().await }).await
    }
    pub async fn stop_daemon(&self) -> Result<(), DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.stop_daemon().await }).await
    }

    pub async fn request_safe_stop(
        &self,
        deadline_secs: Option<u32>,
    ) -> Result<SafeStopOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.request_safe_stop(deadline_secs).await }).await
    }
    pub async fn daemon_identity(&self) -> Result<DaemonIdentity, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.daemon_identity().await }).await
    }

    // ---- updates ----
    pub async fn update_status(&self) -> Result<UpdateStatus, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.update_status().await }).await
    }
    pub async fn check_for_updates(&self) -> Result<UpdateStatus, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.check_for_updates().await }).await
    }
    pub async fn check_appcast_item(
        &self,
        item: AppcastItem,
        phase: AppcastItemPhase,
    ) -> Result<AppcastItemCheck, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.check_appcast_item(item, phase).await }).await
    }
    pub async fn download_guidance(&self) -> Result<UpdateDownloadGuidance, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.download_guidance().await }).await
    }
    pub async fn set_automatic_update_checks(
        &self,
        enabled: bool,
    ) -> Result<UpdateConfig, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.set_automatic_update_checks(enabled).await }).await
    }

    // ---- account ----
    pub async fn account_deletion_status(&self) -> Result<AccountDeletionStatus, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.account_deletion_status().await }).await
    }
    pub async fn account_deletion_impact(&self) -> Result<AccountDeletionImpact, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.account_deletion_impact().await }).await
    }
    pub async fn request_account_deletion(
        &self,
        acknowledge_impact: bool,
    ) -> Result<AccountDeletionRequest, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.request_account_deletion(acknowledge_impact).await }).await
    }
    pub async fn complete_account_deletion(&self) -> Result<SignOutOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.complete_account_deletion().await }).await
    }
    pub async fn confirm_account_deletion(
        &self,
        confirmation_token: String,
    ) -> Result<AccountDeletionStatus, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.confirm_account_deletion(confirmation_token).await }).await
    }
    pub async fn cancel_account_deletion(&self) -> Result<AccountDeletionStatus, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.cancel_account_deletion().await }).await
    }
    pub async fn export_account_data(&self) -> Result<String, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.export_account_data().await }).await
    }

    // ---- shares ----
    pub async fn list_owned_groups(&self) -> Result<Vec<GroupSummary>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.list_owned_groups().await }).await
    }
    pub async fn list_joinable_groups(&self) -> Result<Vec<GroupSummary>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.list_joinable_groups().await }).await
    }
    pub async fn list_members(&self, group_id: String) -> Result<Vec<MemberSummary>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.list_members(group_id).await }).await
    }
    pub async fn change_member_role(
        &self,
        group_id: String,
        device_id: String,
        role: AssignableRole,
    ) -> Result<(), DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.change_member_role(group_id, device_id, role).await }).await
    }
    pub async fn revoke_member(
        &self,
        group_id: String,
        device_id: String,
        force: bool,
    ) -> Result<MembershipOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.revoke_member(group_id, device_id, force).await }).await
    }
    pub async fn deny_request(
        &self,
        group_id: String,
        device_id: String,
    ) -> Result<MembershipOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.deny_request(group_id, device_id).await }).await
    }
    pub async fn approve_request(
        &self,
        group_id: String,
        device_id: String,
    ) -> Result<ApproveOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.approve_request(group_id, device_id).await }).await
    }
    pub async fn list_pending_approvals(
        &self,
    ) -> Result<Vec<PendingApprovalSummary>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.list_pending_approvals().await }).await
    }
    pub async fn list_shares(&self) -> Result<Vec<ShareSummary>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.list_shares().await }).await
    }
    pub async fn revoke_share_edge(
        &self,
        edge_id: String,
        force: bool,
    ) -> Result<RevokeEdgeOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.revoke_share_edge(edge_id, force).await }).await
    }
    pub async fn mint_invite(
        &self,
        group_id: String,
        role: Option<AssignableRole>,
        ttl: Option<Duration>,
        require_approval: bool,
    ) -> Result<InviteSummary, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.mint_invite(group_id, role, ttl, require_approval).await }).await
    }
    pub async fn list_invites(&self) -> Result<Vec<PendingInviteSummary>, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.list_invites().await }).await
    }
    pub async fn cancel_invite(&self, invite_id: String) -> Result<(), DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.cancel_invite(invite_id).await }).await
    }
    pub fn parse_invite_link(&self, input: String) -> Result<String, DesktopError> {
        self.inner.parse_invite_link(&input)
    }
    pub async fn accept_invite(
        &self,
        code_or_url: String,
        local_path: String,
        mode: FolderMode,
        acknowledge_risks: bool,
    ) -> Result<AcceptInviteOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.accept_invite(code_or_url, local_path, mode, acknowledge_risks).await }).await
    }

    pub async fn accept_invite_as_provider_folder(
        &self,
        code_or_url: String,
        display_name: String,
        mode: FolderMode,
    ) -> Result<ProviderInviteOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move {
            core.accept_invite_as_provider_folder(code_or_url, display_name, mode).await
        })
        .await
    }

    // ---- linking ----
    pub async fn run_preflight(&self, local_path: String) -> Result<PreflightResult, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.run_preflight(local_path).await }).await
    }
    pub async fn create_group_and_link(
        &self,
        group_name: String,
        local_path: String,
        mode: FolderMode,
        acknowledge_risks: bool,
    ) -> Result<LinkOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move {
            core.create_group_and_link(group_name, local_path, mode, acknowledge_risks).await
        })
        .await
    }
    /// Where the default "YadoriLink Folder" is created; performs no I/O.
    pub fn default_folder(&self) -> Result<DefaultFolder, DesktopError> {
        self.inner.default_folder()
    }
    /// Creates the default "YadoriLink Folder" and links it.
    pub async fn create_default_folder(
        &self,
        mode: FolderMode,
    ) -> Result<LinkOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.create_default_folder(mode).await }).await
    }
    pub async fn join_group_and_link(
        &self,
        group_id: String,
        group_name: String,
        local_path: String,
        mode: FolderMode,
        acknowledge_risks: bool,
    ) -> Result<LinkOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move {
            core.join_group_and_link(group_id, group_name, local_path, mode, acknowledge_risks)
                .await
        })
        .await
    }
    pub async fn create_provider_folder(
        &self,
        group_name: String,
        display_name: String,
        mode: FolderMode,
    ) -> Result<ProviderFolderOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.create_provider_folder(group_name, display_name, mode).await })
            .await
    }
    pub async fn join_provider_folder(
        &self,
        group_id: String,
        group_name: String,
        display_name: String,
        mode: FolderMode,
    ) -> Result<ProviderFolderOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move {
            core.join_provider_folder(group_id, group_name, display_name, mode).await
        })
        .await
    }
    pub async fn link_folder(
        &self,
        local_path: String,
        group_id: String,
        mode: FolderMode,
        acknowledge_risks: bool,
    ) -> Result<LinkOutcome, DesktopError> {
        let core = self.inner.clone();
        bridge(async move { core.link_folder(local_path, group_id, mode, acknowledge_risks).await })
            .await
    }
}

/// Never polled: a watch that could not start has no runtime to poll on.
fn unreachable_update() -> StatusUpdate {
    StatusUpdate::Unavailable {
        error: DesktopError::Internal {
            message: "the status watch could not start".into(),
            category: "runtime_unavailable".into(),
        },
    }
}
