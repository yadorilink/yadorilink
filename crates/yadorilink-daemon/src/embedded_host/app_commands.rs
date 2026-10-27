//! The application commands an app needs beyond linking a folder: shares, link lifecycle,
//! status, preserved items and space management. Each runs the service function the desktop
//! control socket's handler runs (the shared code is in `enrollment_commands` and
//! `status_report`; the rest are one port call), and refuses what the control socket refuses,
//! with the same typed reasons.

use yadorilink_ipc_proto::daemonctl::{ApplicationErrorCode, StatusResponse};

use super::{CommandError, EngineCommands};
use crate::enrollment_commands::{self, CreateShare as Create, JoinGroup as Join};
pub use crate::preserved_items::{PreservedItem, PreservedKind};

/// How long a pause lasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseFor {
    UntilResumed,
    ThirtyMinutes,
    OneHour,
    /// Until the next local midnight.
    UntilTomorrow,
}

impl From<PauseFor> for crate::pause_deadline::PauseDuration {
    fn from(duration: PauseFor) -> Self {
        match duration {
            PauseFor::UntilResumed => Self::UntilResumed,
            PauseFor::ThirtyMinutes => Self::ThirtyMinutes,
            PauseFor::OneHour => Self::OneHour,
            PauseFor::UntilTomorrow => Self::UntilTomorrow,
        }
    }
}

/// A provider folder to create or join: the name the OS shows and the app's retry identity. A
/// retry of the same token with the same request reaches the same folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderFolder {
    pub display_name: String,
    pub request_token: String,
}

/// Where a share's folder is: an ordinary folder (this build may have no change source for it)
/// or a provider folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareFolder {
    Ordinary { local_path: String, create_if_missing: bool },
    Provider(ProviderFolder),
}

impl ShareFolder {
    /// The ordinary folder's path and whether to create it, or the provider's name and token.
    fn parts(self) -> (String, bool, String, String) {
        match self {
            Self::Ordinary { local_path, create_if_missing } => {
                (local_path, create_if_missing, String::new(), String::new())
            }
            Self::Provider(p) => (String::new(), false, p.display_name, p.request_token),
        }
    }
}

/// Create a share (a folder group) and link a folder to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateShare {
    pub group_name: String,
    pub folder: ShareFolder,
    /// Keep content in the cloud and fetch it on open.
    pub on_demand: bool,
    /// The user saw the risks the folder's preflight found and confirmed. Without it, a folder
    /// with risks is refused.
    pub acknowledge_risks: bool,
}

/// Join a share of this account and link a folder to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinGroup {
    pub group_id: String,
    pub group_name: String,
    pub folder: ShareFolder,
    pub on_demand: bool,
    pub acknowledge_risks: bool,
}

/// Join a share by an invite another account minted, linking a folder to it. A build with no OS
/// watcher cannot capture an ordinary folder's edits and refuses an ordinary folder with
/// [`super::CommandErrorKind::NoChangeSource`] before the one-use invite is redeemed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinShare {
    pub invite_code: String,
    pub folder: ShareFolder,
    pub on_demand: bool,
    pub acknowledge_risks: bool,
}

/// What a share command did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareOutcome {
    pub operation_id: String,
    pub group_id: String,
    /// The link's identity key: the folder's path, or a provider folder's locator.
    pub link_key: String,
    /// The provider folder's root, for a provider folder.
    pub provider_root_id: Option<String>,
    /// The membership waits for the group owner's approval and grants nothing until then.
    pub awaiting_approval: bool,
    /// The folder was already linked to this group: nothing changed.
    pub already_linked: bool,
}

/// Re-adopt the provider folder of `group_id` that a start over marked as needing the person: it
/// is joined to its group again as this device, keeping its OS folder, its root and every file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadoptMarkedFolder {
    pub group_id: String,
}

/// What a re-adoption did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadoptOutcome {
    pub group_id: String,
    /// The folder's link key: its locator.
    pub link_key: String,
    pub provider_root_id: Option<String>,
    /// The folder was on-demand while a replacement the service called unconfirmed waits for
    /// this group, and is now a full replica (eager): the replacement is confirmed only for a
    /// group held that way and complete on this device.
    pub promoted_to_eager: bool,
}

/// Why a re-adoption was refused; nothing was changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadoptRefusal {
    /// This engine has no folder of the group.
    GroupUnknown,
    /// The folder of the group is not marked as needing the person (it already syncs).
    NotMarked,
    /// The folder of the group is an ordinary folder: only a provider folder is re-adopted.
    NotAProviderFolder,
    /// The engine still runs as the identity a start over retired (its status still reports
    /// `database_restored`): restart it first.
    RestartRequired,
}

/// Pause sync of one linked folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PauseLink {
    pub link_key: String,
    pub duration: PauseFor,
    /// Refuse, changing nothing, unless the link still belongs to this group.
    pub expected_group_id: Option<String>,
}

/// Resume sync of one linked folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeLink {
    pub link_key: String,
    pub expected_group_id: Option<String>,
}

/// Unlink a folder: stop syncing it and give up this device's place in its group, after the
/// custody checks (and hand-off) the desktop's unlink runs. `force` skips a refusal and risks
/// data loss.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlinkFolder {
    pub link_key: String,
    pub force: bool,
    pub expected_group_id: Option<String>,
}

/// The custody hand-off an unlink committed, when it needed one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffInfo {
    pub target_device_id: String,
    pub root_digest: [u8; 32],
    pub membership_generation: i64,
    pub lease_id: Option<String>,
}

/// What an unlink did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlinkOutcome {
    pub handoff: Option<HandoffInfo>,
}

/// One preserved item of a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreservedRef {
    pub group_id: String,
    pub item_id: String,
}

/// Why an operation on a preserved item was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreservedRefusal {
    NotFound,
    /// A rebootstrap of the group is running.
    Busy,
    /// This device may not author into the group now.
    NotAWriter,
    /// The item holds no version record.
    RecordUnavailable,
    /// The item holds the record but its bytes cannot be obtained.
    ContentUnavailable,
}

/// The automatic space management setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpaceManagement {
    pub enabled: bool,
}

/// How one connectivity check came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorStatus {
    Ok,
    Warn,
    Error,
}

/// One row of the connectivity doctor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorCheck {
    /// What was checked.
    pub name: String,
    pub status: DoctorStatus,
    /// What was found, and the fix when there is one.
    pub detail: String,
}

const LOCATOR_PREFIX: &str = "provider://";

fn failed(message: impl Into<String>) -> CommandError {
    CommandError::failed(message)
}

fn enrollment_failure(error: &crate::application::EnrollmentError) -> CommandError {
    let (code, operation_id) = enrollment_commands::enrollment_error_code(error);
    CommandError::refused(code, error.to_string(), operation_id)
}

impl EngineCommands {
    fn outcome(&self, outcome: crate::application::EnrollmentOutcome) -> ShareOutcome {
        let root = enrollment_commands::provider_root_id(&self.context.queries, &outcome);
        ShareOutcome {
            operation_id: outcome.operation_id,
            group_id: outcome.group_id,
            link_key: outcome.local_path.to_string_lossy().into_owned(),
            provider_root_id: (!root.is_empty()).then_some(root),
            awaiting_approval: outcome.awaiting_approval,
            already_linked: outcome.already_linked,
        }
    }

    /// Creates a share and links a folder to it.
    ///
    /// # Errors
    /// [`CommandError`], typed by [`super::CommandErrorKind::Refused`] for the refusals the control
    /// socket types (a provider folder on a platform with none, a folder's risks, a failed or
    /// ambiguous enrollment, ...).
    pub async fn create_share(&self, command: CreateShare) -> Result<ShareOutcome, CommandError> {
        let (local_path, create_local_path_if_missing, display_name, token) =
            command.folder.parts();
        self.require_change_source(&display_name)?;
        let result = enrollment_commands::create_and_link(
            &self.context.application,
            Create {
                group_name: command.group_name,
                local_path,
                create_local_path_if_missing,
                on_demand: command.on_demand,
                acknowledge_risks: command.acknowledge_risks,
                provider_display_name: display_name,
                request_token: token,
            },
        )
        .await;
        result.map(|o| self.outcome(o)).map_err(|e| enrollment_failure(&e))
    }

    /// Joins a share of this account and links a folder to it.
    ///
    /// # Errors
    /// As [`Self::create_share`].
    pub async fn join_group(&self, command: JoinGroup) -> Result<ShareOutcome, CommandError> {
        let (local_path, _, display_name, token) = command.folder.parts();
        self.require_change_source(&display_name)?;
        let result = enrollment_commands::join_and_link(
            &self.context.application,
            Join {
                group_id: command.group_id,
                group_name: command.group_name,
                local_path,
                on_demand: command.on_demand,
                acknowledge_risks: command.acknowledge_risks,
                provider_display_name: display_name,
                request_token: token,
            },
        )
        .await;
        result.map(|o| self.outcome(o)).map_err(|e| enrollment_failure(&e))
    }

    /// Joins a share by invite.
    ///
    /// # Errors
    /// [`super::CommandErrorKind::NoChangeSource`] on a build that cannot link an ordinary folder
    /// (nothing is redeemed); otherwise as [`Self::create_share`], with the invite's own
    /// refusals ([`ApplicationErrorCode::InviteExpired`], [`ApplicationErrorCode::InviteAlreadyUsed`]).
    pub async fn join_share(&self, command: JoinShare) -> Result<ShareOutcome, CommandError> {
        let (local_path, _, display_name, token) = command.folder.parts();
        self.require_change_source(&display_name)?;
        let result = enrollment_commands::accept_invite(
            &self.context.application,
            enrollment_commands::AcceptInvite {
                code: command.invite_code,
                local_path,
                on_demand: command.on_demand,
                acknowledge_risks: command.acknowledge_risks,
                provider_display_name: display_name,
                request_token: token,
            },
        )
        .await;
        result.map(|o| self.outcome(o)).map_err(|e| enrollment_failure(&e))
    }

    /// An ordinary folder has no change source in this build: refused before anything is
    /// created or redeemed. A provider folder (non-empty `provider_display_name`) needs none.
    fn require_change_source(&self, provider_display_name: &str) -> Result<(), CommandError> {
        if provider_display_name.is_empty() && !super::ordinary_folder_links_supported() {
            return Err(CommandError::no_change_source());
        }
        Ok(())
    }

    /// Re-adopts the folder a start over marked as needing the person into its group.
    ///
    /// The marked provider folder is joined to its group again as this device (the same
    /// prepare, link, activate saga a join runs, over the existing folder: no second provider
    /// folder, root or OS domain is created) and syncs again. When a replacement the service
    /// called unconfirmed waits for the group and the folder is on-demand, it is promoted to a
    /// full replica, the only way the replacement can be confirmed. Never deletes or rewrites a
    /// file. If the promotion fails after the folder was re-adopted, the error says so and
    /// calling again finishes the promotion.
    ///
    /// # Errors
    /// [`super::CommandErrorKind::Readopt`] for the refusals of [`ReadoptRefusal`];
    /// [`super::CommandErrorKind::Refused`] when the service does not take the device into the
    /// group (the group is gone or not accessible to this account), with the code a join has.
    pub async fn readopt_marked_folder(
        &self,
        command: ReadoptMarkedFolder,
    ) -> Result<ReadoptOutcome, CommandError> {
        let group_id = command.group_id;
        // The engine that has not restarted since a start over still is the retired identity.
        let restored =
            self.status()?.attention_reasons.iter().any(|r| r.starts_with("database_restored"));
        if restored {
            return Err(CommandError::readopt(
                ReadoptRefusal::RestartRequired,
                "the engine still runs as the retired device; restart it, then re-adopt the folder",
            ));
        }
        let links =
            self.context.queries.link_status.list_links().map_err(|e| failed(e.to_string()))?;
        let Some(link) = links.into_iter().find(|link| link.group_id == group_id) else {
            return Err(CommandError::readopt(
                ReadoptRefusal::GroupUnknown,
                format!("this device has no folder of group {group_id}"),
            ));
        };
        let Some((root_id, display_name)) = link.provider.clone() else {
            return Err(CommandError::readopt(
                ReadoptRefusal::NotAProviderFolder,
                format!("the folder of group {group_id} is an ordinary folder"),
            ));
        };
        let on_demand = link.materialization_policy != "eager";
        let promote = on_demand && self.replacement_waits_for(&group_id);
        if !link.orphaned {
            // Re-adopted before, its promotion failed: only that is left to do.
            if !promote {
                return Err(CommandError::readopt(
                    ReadoptRefusal::NotMarked,
                    format!("the folder of group {group_id} is not marked as needing action"),
                ));
            }
        } else {
            let token = link.local_path.strip_prefix(LOCATOR_PREFIX).unwrap_or_default().to_owned();
            enrollment_commands::join_and_link(
                &self.context.application,
                Join {
                    group_id: group_id.clone(),
                    group_name: display_name.clone(),
                    local_path: String::new(),
                    on_demand,
                    acknowledge_risks: true,
                    provider_display_name: display_name,
                    request_token: token,
                },
            )
            .await
            .map_err(|e| enrollment_failure(&e))?;
        }
        if promote {
            self.promote_to_eager(&group_id).await?;
        }
        Ok(ReadoptOutcome {
            group_id,
            link_key: link.local_path,
            provider_root_id: Some(root_id),
            promoted_to_eager: promote,
        })
    }

    /// Whether the replacement the service called unconfirmed names `group_id`.
    fn replacement_waits_for(&self, group_id: &str) -> bool {
        yadorilink_local_storage::replacement_unconfirmed::read(&self.config_dir)
            .ok()
            .flatten()
            .is_some_and(|record| record.unconfirmed_group_ids.iter().any(|g| g == group_id))
    }

    async fn promote_to_eager(&self, group_id: &str) -> Result<(), CommandError> {
        use crate::application::replica_role_service::StorageModeError;
        match self.context.application.replica_role.set_storage_mode(group_id, false).await {
            Ok(_) => Ok(()),
            Err(StorageModeError::TermsConsentRequired) => Err(CommandError::refused(
                ApplicationErrorCode::TermsConsentRequired,
                StorageModeError::TermsConsentRequired.to_string(),
                String::new(),
            )),
            Err(e) => Err(failed(format!(
                "the folder is re-adopted, but promoting it to a full replica failed ({e}); call again"
            ))),
        }
    }

    /// Pauses a linked folder.
    ///
    /// # Errors
    /// [`ApplicationErrorCode::GroupMismatch`] when the link no longer belongs to the expected
    /// group (nothing changed); otherwise the engine's message.
    pub fn pause_link(&self, command: PauseLink) -> Result<(), CommandError> {
        self.context
            .application
            .pause_resume
            .pause(&command.link_key, command.duration.into(), command.expected_group_id.as_deref())
            .map_err(link_failure)
    }

    /// Resumes a linked folder.
    ///
    /// # Errors
    /// As [`Self::pause_link`].
    pub async fn resume_link(&self, command: ResumeLink) -> Result<(), CommandError> {
        self.context
            .application
            .pause_resume
            .resume(&command.link_key, command.expected_group_id.as_deref())
            .await
            .map_err(link_failure)
    }

    /// Unlinks a folder.
    ///
    /// # Errors
    /// [`ApplicationErrorCode::NotProtected`] when unlinking would leave the group without a
    /// confirmed complete copy elsewhere and `force` is not set; [`ApplicationErrorCode::GroupMismatch`]
    /// when the link no longer belongs to the expected group; otherwise the engine's message.
    pub async fn unlink(&self, command: UnlinkFolder) -> Result<UnlinkOutcome, CommandError> {
        use crate::application::UnlinkError;
        match self
            .context
            .application
            .replica_role
            .unlink(&command.link_key, command.force, command.expected_group_id.as_deref())
            .await
        {
            Ok(outcome) => Ok(UnlinkOutcome {
                handoff: outcome.handoff.map(|h| HandoffInfo {
                    target_device_id: h.target_device_id,
                    root_digest: h.root_digest,
                    membership_generation: h.membership_generation,
                    lease_id: h.lease_id,
                }),
            }),
            Err(UnlinkError::NotProtected(message)) => Err(CommandError::refused(
                ApplicationErrorCode::NotProtected,
                message,
                String::new(),
            )),
            Err(error @ UnlinkError::TermsConsentRequired) => Err(CommandError::refused(
                ApplicationErrorCode::TermsConsentRequired,
                error.to_string(),
                String::new(),
            )),
            Err(UnlinkError::GroupMismatch(path)) => Err(group_mismatch(&path)),
            Err(UnlinkError::Other(message)) => Err(failed(message)),
        }
    }

    /// The engine's whole status, the same one the desktop `status` reports.
    ///
    /// # Errors
    /// [`CommandError`] when the runtime view cannot be read.
    pub fn status(&self) -> Result<StatusResponse, CommandError> {
        crate::status_report::build_status(&self.context, Some(&self.config_dir)).map_err(failed)
    }

    /// The connectivity doctor's rows.
    #[must_use]
    pub fn doctor(&self) -> Vec<DoctorCheck> {
        self.context
            .queries
            .diagnostics
            .connectivity_doctor()
            .into_iter()
            .map(|c| DoctorCheck {
                name: c.name.to_owned(),
                status: match c.status {
                    "ok" => DoctorStatus::Ok,
                    "warn" => DoctorStatus::Warn,
                    // A status this code does not know is never reported as fine.
                    _ => DoctorStatus::Error,
                },
                detail: c.detail,
            })
            .collect()
    }

    /// What a rebootstrap set aside.
    ///
    /// # Errors
    /// [`CommandError`] when the store cannot be read.
    pub async fn preserved_items(&self) -> Result<Vec<PreservedItem>, CommandError> {
        self.context.application.preserved.list().await.map_err(preserved_failure)
    }

    /// Restores a preserved version as one ordinary new write; the item stays.
    ///
    /// # Errors
    /// [`super::CommandErrorKind::Preserved`] for the item's own refusals.
    pub async fn restore_preserved(&self, item: PreservedRef) -> Result<(), CommandError> {
        self.context
            .application
            .preserved
            .restore(item.group_id, item.item_id)
            .await
            .map_err(preserved_failure)
    }

    /// Deletes a preserved item: the only operation that does.
    ///
    /// # Errors
    /// As [`Self::restore_preserved`].
    pub async fn discard_preserved(&self, item: PreservedRef) -> Result<(), CommandError> {
        self.context
            .application
            .preserved
            .discard(item.group_id, item.item_id)
            .await
            .map_err(preserved_failure)
    }

    /// The automatic space management setting; Off when it was never set or cannot be read.
    #[must_use]
    pub fn space_management(&self) -> SpaceManagement {
        let config = crate::space_management_config::SpaceManagementStore::new(&self.config_dir)
            .load_or_off();
        SpaceManagement { enabled: config.enabled }
    }

    /// Turns automatic space management on or off.
    ///
    /// # Errors
    /// [`CommandError`] when the setting cannot be saved.
    pub fn set_space_management(&self, enabled: bool) -> Result<SpaceManagement, CommandError> {
        crate::space_management_config::SpaceManagementStore::new(&self.config_dir)
            .set(enabled)
            .map(|config| SpaceManagement { enabled: config.enabled })
            .map_err(|e| failed(format!("could not save the setting: {e}")))
    }
}

fn group_mismatch(local_path: &str) -> CommandError {
    CommandError::refused(
        ApplicationErrorCode::GroupMismatch,
        format!("the folder at {local_path} now belongs to a different group"),
        String::new(),
    )
}

fn link_failure(error: crate::sync_error::SyncError) -> CommandError {
    match error {
        crate::sync_error::SyncError::GroupMismatch(path) => group_mismatch(&path),
        other => failed(other.to_string()),
    }
}

fn preserved_failure(error: crate::preserved_items::PreservedError) -> CommandError {
    use crate::preserved_items::PreservedError as Error;
    let refusal = match &error {
        Error::NotFound => PreservedRefusal::NotFound,
        Error::Busy => PreservedRefusal::Busy,
        Error::NotAWriter => PreservedRefusal::NotAWriter,
        Error::RecordUnavailable => PreservedRefusal::RecordUnavailable,
        Error::ContentUnavailable => PreservedRefusal::ContentUnavailable,
        Error::Failed(message) => return failed(message.clone()),
    };
    CommandError::preserved(refusal, error.to_string())
}
