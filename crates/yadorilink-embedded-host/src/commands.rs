//! The host's typed command calls, each with its own cancel handle and deadline.
//!
//! A call runs on the engine's runtime and the caller waits for it on its own thread, so a
//! call can be cancelled or can run out of time without any cooperation from the command.
//! What cancelling means depends on the command:
//!
//! - A read-only command is aborted: nothing it did needs undoing.
//! - A command that changes state keeps running to its end. Dropping it half-way would leave
//!   a half-done saga, so the call returns [`CallError::Cancelled`] or
//!   [`CallError::DeadlineExceeded`] with `still_running` set, and the caller finds the
//!   outcome by reading the state (for example [`Command::ListFolders`]). The engine stopping
//!   ends it like any other task.
//!
//! - A sign-in step is waited for as a read-only command: the wait is aborted and the step is
//!   delivered again by the next call that names the same `after` ([`PollSignIn`]), so nothing
//!   is lost.
//!
//! One [`CancelHandle`] belongs to one call.

use std::future::Future;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use tokio::task::AbortHandle;
pub use yadorilink_client_core::DesktopError;
pub use yadorilink_daemon::embedded_host::{
    ordinary_folder_links_supported, ApplyChange, ApplyResponse, CommandError, CommandErrorKind,
    CreateShare, DoctorCheck, DoctorStatus, HandoffInfo, JoinGroup, JoinShare, LinkFolder,
    LinkedFolder, PauseFor, PauseLink, PreservedItem, PreservedKind, PreservedRef,
    PreservedRefusal, ProviderFolder, ReadoptMarkedFolder, ReadoptOutcome, ReadoptRefusal,
    RestoreVersion, ResumeLink, ShareFolder, ShareOutcome, SpaceManagement, UnlinkFolder,
    UnlinkOutcome,
};
pub use yadorilink_daemon::embedded_host::{
    DeletedItem, DeletedItems, DeletedParent, HistoryEntryKind, HistoryVersionState, ItemHistory,
    ItemVersion, MAX_DELETED_ITEMS,
};
pub use yadorilink_daemon::embedded_host::{
    DeliveryItem, DeliveryReport, DeliveryState, ItemDelivery, StageMode, StageRefused,
    StageSource, StagedHow, StagedUpload, MAX_DELIVERY_ITEMS,
};

use crate::account::{
    AccountCommand, AccountCommands, AccountDeletionImpact, AccountDeletionRequest,
    AccountDeletionStatus, AccountStatus, DeviceRegistration, SignInCancellation, SignInId,
    SignInStep, SignOutOutcome,
};
use crate::HostError;

/// A command to the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    LinkFolder(LinkFolder),
    RestoreVersion(RestoreVersion),
    ListFolders,
    /// Creates a share and links a folder (or a provider folder) to it.
    CreateShare(CreateShare),
    /// Joins a share of this account and links a folder to it.
    JoinGroup(JoinGroup),
    /// Joins a share by invite.
    JoinShare(JoinShare),
    PauseLink(PauseLink),
    ResumeLink(ResumeLink),
    /// Re-adopts the provider folder a start over marked as needing the person into its group.
    ReadoptMarkedFolder(ReadoptMarkedFolder),
    /// Unlinks a folder after the custody checks (and hand-off) the desktop's unlink runs.
    Unlink(UnlinkFolder),
    /// The engine's status: overall state, attention items, folders, peers, transfers, storage.
    Status,
    /// The connectivity doctor's rows.
    Doctor,
    /// What a rebootstrap set aside.
    ListPreserved,
    /// Restores a preserved version as one ordinary new write.
    RestorePreserved(PreservedRef),
    /// Deletes a preserved item.
    DiscardPreserved(PreservedRef),
    /// The automatic space management setting.
    SpaceManagement,
    /// Recent file events across every linked folder, newest first (the Activity page).
    /// `limit` is clamped to 1..=500; `before_cursor` is the previous page's `next_cursor`.
    ListActivity {
        limit: u32,
        before_cursor: Option<i64>,
        filter: Option<yadorilink_client_core::dto::ActivityFilter>,
    },
    SetSpaceManagement {
        enabled: bool,
    },
    /// Mints a one-use expiring Send link for the files and folders at `source_paths`
    /// (absolute paths). The code is shown once.
    CreateSendLink {
        ttl: yadorilink_client_core::dto::SendLinkTtl,
        source_paths: Vec<String>,
    },
    /// Who sends the link a code names and what it carries; nothing is consumed.
    PreviewSendLink {
        code: String,
    },
    /// Redeems a code with this device (or `device_id`); answers the link id.
    RedeemSendLink {
        code: String,
        device_id: Option<String>,
        /// Absolute folder to receive the link's files into; `None` = the engine's own choice.
        destination_dir: Option<String>,
    },
    CancelSendLink {
        link_id: String,
    },
    SendLinkStatus {
        link_id: String,
    },
    /// The links this device created, newest first, each with its status.
    ListSendLinks,
    /// Waits for the recipient to redeem the link, then offers the files under it. Cancelling
    /// the call ends the wait (and an offer in flight, which a new send makes again).
    SendToLink {
        link_id: String,
        source_paths: Vec<String>,
    },
    /// Every transfer other devices offered to this device.
    ListInbox,
    /// The transfers this device sent.
    ListSentTransfers,
    /// Accepts an inbound transfer and pulls it, into `destination_dir` (absolute) or the
    /// engine's inbox. Resumable. Cancelling the call does not stop the pull: use
    /// [`Command::CancelTransfer`], or stop or suspend the engine, which records the receive as
    /// interrupted so that a later receive resumes it.
    ReceiveTransfer {
        transfer_id: String,
        destination_dir: Option<String>,
    },
    /// Stops a transfer by id; a running receive ends and the transfer is marked cancelled.
    CancelTransfer {
        transfer_id: String,
    },
    /// Sign-in, device registration, sign-out and account deletion.
    Account(AccountCommand),
    /// Puts a file into the engine's ingest directory for an [`Command::ApplyChange`] to name:
    /// moved or cloned where it can be, copied otherwise.
    StageUpload {
        source: StageSource,
        mode: StageMode,
    },
    /// Removes a staged file no change will use.
    DiscardStagedUpload {
        ingest_name: String,
    },
    /// One change to a provider folder: create, modify (new contents, rename, move) or delete.
    /// Idempotent by its operation identity: asking again with the same `(session_id,
    /// operation_seq)` returns the stored outcome. Cancelling the call does not stop it (see the
    /// module docs); ask again to learn the outcome.
    ApplyChange(Box<ApplyChange>),
    /// Whether the versions this device authored have reached a device that keeps a full
    /// replica. Read-only.
    VersionDelivery {
        items: Vec<DeliveryItem>,
    },
    /// The retained versions of one item of a provider folder. Read-only. A restore
    /// is an [`Command::ApplyChange`] whose request names `restore_from`.
    ListItemVersions {
        root_id: Vec<u8>,
        item_id: Vec<u8>,
    },
    /// The deleted files and folders of a provider folder that can still be brought back.
    /// Read-only.
    ListDeletedItems {
        root_id: Vec<u8>,
    },
}

impl Command {
    /// Whether the command only reads, so that cancelling it can abort it.
    fn read_only(&self) -> bool {
        match self {
            Self::ListFolders | Self::Status | Self::Doctor | Self::ListPreserved => true,
            Self::ListActivity { .. } => true,
            Self::SpaceManagement => true,
            Self::PreviewSendLink { .. }
            | Self::SendLinkStatus { .. }
            | Self::ListSendLinks
            | Self::ListInbox
            | Self::ListSentTransfers => true,
            // Waiting for a redeem and offering are safe to drop: the offer is crash-safe (its
            // blocks are written before it is recorded) and a new send makes it again.
            Self::SendToLink { .. } => true,
            Self::Account(account) => account.read_only(),
            Self::VersionDelivery { .. }
            | Self::ListItemVersions { .. }
            | Self::ListDeletedItems { .. } => true,
            Self::LinkFolder(_)
            | Self::RestoreVersion(_)
            | Self::CreateShare(_)
            | Self::JoinGroup(_)
            | Self::JoinShare(_)
            | Self::PauseLink(_)
            | Self::ResumeLink(_)
            | Self::ReadoptMarkedFolder(_)
            | Self::Unlink(_)
            | Self::RestorePreserved(_)
            | Self::DiscardPreserved(_)
            | Self::SetSpaceManagement { .. }
            | Self::CreateSendLink { .. }
            | Self::RedeemSendLink { .. }
            | Self::CancelSendLink { .. }
            | Self::ReceiveTransfer { .. }
            | Self::CancelTransfer { .. }
            | Self::StageUpload { .. }
            | Self::DiscardStagedUpload { .. }
            | Self::ApplyChange(_) => false,
        }
    }
}

/// What a command returned.
#[derive(Debug, Clone, PartialEq)]
pub enum CommandOutput {
    Linked,
    /// Whether a version was restored; false when there was no earlier version.
    Restored(bool),
    Folders(Vec<LinkedFolder>),
    /// A command that returns nothing finished.
    Done,
    Shared(ShareOutcome),
    Unlinked(UnlinkOutcome),
    Readopted(ReadoptOutcome),
    Status(Box<yadorilink_client_core::dto::StatusSnapshot>),
    Doctor(Vec<DoctorCheck>),
    Preserved(Vec<PreservedItem>),
    SpaceManagement(SpaceManagement),
    Account(Box<AccountStatus>),
    SignInBegun(SignInId),
    /// What `CancelCurrentSignIn` found.
    SignInCancellation(SignInCancellation),
    SignInOrigins(yadorilink_client_core::ops::auth::TrustedSignInOrigins),
    SignInStep(SignInStep),
    DeviceRegistered(DeviceRegistration),
    SignedOut(SignOutOutcome),
    /// How far a start over got.
    StartOver(yadorilink_client_core::dto::StartOverProgress),
    /// Whether an acknowledgement was recorded (`false`: no replacement was waiting).
    PossibleLossAcknowledged(bool),
    /// One page of the Activity list.
    Activity(yadorilink_client_core::dto::ActivityPage),
    /// The folder groups the account may join: `(group_id, name)` summaries.
    JoinableGroups(Vec<yadorilink_client_core::dto::GroupSummary>),
    /// The devices of one folder group.
    GroupDevices(Vec<yadorilink_client_core::dto::MemberSummary>),
    /// An ownership offer, as just created, cancelled or declined.
    PrimaryTransfer(yadorilink_client_core::dto::PrimaryTransferSummary),
    /// An accepted ownership offer: this account is now the folder's primary owner.
    PrimaryTransferAccepted(yadorilink_client_core::dto::PrimaryTransferAccepted),
    /// The pending ownership offers this account made or received.
    PrimaryTransfers(Vec<yadorilink_client_core::dto::PrimaryTransferSummary>),
    /// A Send link just created.
    SendLink(yadorilink_client_core::dto::SendLink),
    SendLinkPreview(yadorilink_client_core::dto::SendLinkPreview),
    /// The id of the link a redeem bound to a device.
    SendLinkRedeemed(String),
    SendLinkStatus(yadorilink_client_core::dto::SendLinkStatus),
    SendLinks(Vec<SendLinkEntry>),
    /// A send under a link was offered.
    SendOffered(yadorilink_client_core::dto::SentTransfer),
    Inbox(Vec<yadorilink_client_core::dto::IncomingTransfer>),
    SentTransfers(Vec<yadorilink_client_core::dto::OutgoingTransfer>),
    Received(yadorilink_client_core::dto::ReceivedTransfer),
    DeletionImpact(AccountDeletionImpact),
    DeletionRequested(AccountDeletionRequest),
    DeletionStatus(AccountDeletionStatus),
    /// The file was staged, or why it could not be.
    Staged(Result<StagedUpload, StageRefused>),
    /// The engine's answer to an apply: the outcome, or a typed refusal.
    Applied(Box<ApplyResponse>),
    Delivery(Box<DeliveryOutcome>),
    /// The retained versions of one item.
    ItemVersions(Box<HistoryOutcome<ItemHistory>>),
    /// The deleted items of a provider folder.
    DeletedItems(Box<HistoryOutcome<DeletedItems>>),
}

/// A history listing with the names of the devices that authored what it lists (by device id; a
/// name is missing when the account's device list could not be read).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryOutcome<T> {
    pub listing: T,
    pub device_names: std::collections::HashMap<String, String>,
}

/// One link of the sender's list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendLinkEntry {
    pub status: yadorilink_client_core::dto::SendLinkStatus,
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
    /// How many files the link was created to carry.
    pub file_count: u32,
}

/// Why a call did not return the command's output.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CallError {
    /// The host is not running an engine.
    #[error("{0}")]
    Host(String),
    /// The cancel handle was used before, by another call.
    #[error("the cancel handle already belongs to a call")]
    HandleUsed,
    /// The caller cancelled. `still_running`: the command changes state and was left to finish.
    #[error("the call was cancelled{}", if *.still_running { "; the command is still running" } else { "" })]
    Cancelled { still_running: bool },
    /// The deadline passed. `still_running` as for [`Self::Cancelled`].
    #[error("the call ran out of time{}", if *.still_running { "; the command is still running" } else { "" })]
    DeadlineExceeded { still_running: bool },
    /// The engine stopped before the command finished.
    #[error("the engine stopped before the command finished")]
    EngineStopped,
    /// The command ran and failed.
    #[error(transparent)]
    Failed(#[from] CommandError),
    /// An account command ran and failed; the error is the product's typed one.
    #[error(transparent)]
    Account(Box<DesktopError>),
}

/// How a command failed, before its call decides what that means for the caller.
pub(crate) enum Failure {
    Command(CommandError),
    Account(Box<DesktopError>),
}

impl From<CommandError> for Failure {
    fn from(error: CommandError) -> Self {
        Self::Command(error)
    }
}

impl From<DesktopError> for Failure {
    fn from(error: DesktopError) -> Self {
        Self::Account(Box::new(error))
    }
}

impl From<Failure> for CallError {
    fn from(failure: Failure) -> Self {
        match failure {
            Failure::Command(error) => Self::Failed(error),
            Failure::Account(error) => Self::Account(error),
        }
    }
}

impl From<HostError> for CallError {
    fn from(error: HostError) -> Self {
        Self::Host(error.to_string())
    }
}

type Outcome = Result<CommandOutput, Failure>;

#[derive(Default)]
struct SlotState {
    used: bool,
    cancelled: bool,
    finished: bool,
    outcome: Option<Outcome>,
}

#[derive(Default)]
struct Slot {
    state: Mutex<SlotState>,
    changed: Condvar,
}

impl Slot {
    fn lock(&self) -> std::sync::MutexGuard<'_, SlotState> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl CallOptions {
    /// Why a call that has not started its command must end now: its handle was used before or
    /// was cancelled, or its deadline (counted from `start`) has passed. Marks the handle used
    /// when it ends the call.
    fn check(&self, state: &mut SlotState, start: Instant) -> Option<CallError> {
        if state.used {
            return Some(CallError::HandleUsed);
        }
        let reason = if state.cancelled {
            CallError::Cancelled { still_running: false }
        } else if self.deadline.is_some_and(|deadline| start.elapsed() >= deadline) {
            CallError::DeadlineExceeded { still_running: false }
        } else {
            return None;
        };
        state.used = true;
        Some(reason)
    }

    /// [`Self::check`] without taking the handle.
    pub(crate) fn interrupted(&self, start: Instant) -> Option<CallError> {
        self.check(&mut self.cancel.0.lock(), start)
    }

    /// Takes the handle for a call about to start its command, atomically with the check.
    fn claim(&self, start: Instant) -> Result<(), CallError> {
        let mut state = self.cancel.0.lock();
        if let Some(reason) = self.check(&mut state, start) {
            return Err(reason);
        }
        state.used = true;
        Ok(())
    }
}

/// Cancels one call. Clone it to cancel from another thread.
#[derive(Clone, Default)]
pub struct CancelHandle(Arc<Slot>);

impl CancelHandle {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancels the call this handle belongs to, or the call it is given to later: such a call
    /// returns [`CallError::Cancelled`] without starting the command.
    pub fn cancel(&self) {
        self.0.lock().cancelled = true;
        self.0.changed.notify_all();
    }
}

/// How one call is bounded.
#[derive(Clone, Default)]
pub struct CallOptions {
    /// How long the call may take; unbounded when `None`.
    pub deadline: Option<Duration>,
    pub cancel: CancelHandle,
}

/// Ends the call when the task is dropped without having finished: the engine stopped.
struct Finish(Arc<Slot>);

impl Drop for Finish {
    fn drop(&mut self) {
        self.0.lock().finished = true;
        self.0.changed.notify_all();
    }
}

/// A command that has been handed to the engine's runtime and is waited for.
pub(crate) struct Submitted {
    slot: Arc<Slot>,
    abort: AbortHandle,
}

/// Hands `work` to `runtime` without waiting. The caller holds the host's lifecycle lock across
/// this, so a stop cannot begin between the engine handles `work` owns and its registration
/// as a task of the runtime the stop drops; `work` must own everything it takes from the
/// engine, so that dropping the task releases it.
pub(crate) fn submit<F>(
    runtime: &tokio::runtime::Handle,
    options: &CallOptions,
    start: Instant,
    work: F,
) -> Result<Submitted, CallError>
where
    F: Future<Output = Outcome> + Send + 'static,
{
    options.claim(start)?;
    let slot = options.cancel.0.clone();
    // Built here and moved into the task: a task dropped before its first poll still drops
    // this and ends the call. The slot is not held across the spawn, since that drop locks it.
    let finish = Finish(slot.clone());
    let task_slot = slot.clone();
    let abort = runtime
        .spawn(async move {
            let _finish = finish;
            let outcome = work.await;
            task_slot.lock().outcome = Some(outcome);
        })
        .abort_handle();
    Ok(Submitted { slot, abort })
}

impl Submitted {
    /// Waits for the command under `options`. Holds nothing of the engine.
    pub(crate) fn wait(
        self,
        options: &CallOptions,
        read_only: bool,
        start: Instant,
    ) -> Result<CommandOutput, CallError> {
        let Self { slot, abort } = self;
        let mut state = slot.lock();
        loop {
            if let Some(outcome) = state.outcome.take() {
                return outcome.map_err(CallError::from);
            }
            if state.finished {
                return Err(CallError::EngineStopped);
            }
            let abandon = |read_only: bool| {
                if read_only {
                    abort.abort();
                }
                !read_only
            };
            if state.cancelled {
                return Err(CallError::Cancelled { still_running: abandon(read_only) });
            }
            match options.deadline {
                None => {
                    state =
                        slot.changed.wait(state).unwrap_or_else(std::sync::PoisonError::into_inner);
                }
                Some(deadline) => {
                    let Some(left) = deadline.checked_sub(start.elapsed()).filter(|d| !d.is_zero())
                    else {
                        return Err(CallError::DeadlineExceeded {
                            still_running: abandon(read_only),
                        });
                    };
                    state = slot
                        .changed
                        .wait_timeout(state, left)
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .0;
                }
            }
        }
    }
}

/// Submits and waits, for a caller that holds no lock.
#[cfg(test)]
pub(crate) fn run<F>(
    runtime: &tokio::runtime::Handle,
    read_only: bool,
    options: &CallOptions,
    start: Instant,
    work: F,
) -> Result<CommandOutput, CallError>
where
    F: Future<Output = Outcome> + Send + 'static,
{
    submit(runtime, options, start, work)?.wait(options, read_only, start)
}

/// Whether `command` only reads, so that cancelling it can abort it.
pub(crate) fn is_read_only(command: &Command) -> bool {
    command.read_only()
}

/// Hands `command` to the engine; `commands` and `accounts` move into the task.
pub(crate) fn submit_command(
    runtime: &tokio::runtime::Handle,
    commands: yadorilink_daemon::embedded_host::EngineCommands,
    accounts: Arc<AccountCommands>,
    command: Command,
    options: &CallOptions,
    start: Instant,
) -> Result<Submitted, CallError> {
    submit(runtime, options, start, async move { run_command(&commands, &accounts, command).await })
}

async fn run_command(
    commands: &yadorilink_daemon::embedded_host::EngineCommands,
    accounts: &AccountCommands,
    command: Command,
) -> Outcome {
    // Every command counts as changing state unless it is one of the reads a shell polls: a poll
    // that counted would make the next status wait for a rebuild.
    let changes_state = !matches!(
        command,
        Command::Status
            | Command::ListFolders
            | Command::Doctor
            | Command::Account(AccountCommand::Status)
    );
    let outcome = run_command_inner(commands, accounts, command).await;
    if changes_state {
        commands.command_completed();
    }
    outcome
}

async fn run_command_inner(
    commands: &yadorilink_daemon::embedded_host::EngineCommands,
    accounts: &AccountCommands,
    command: Command,
) -> Outcome {
    Ok(match command {
        Command::LinkFolder(link) => {
            commands.link_folder(link).await.map(|()| CommandOutput::Linked)?
        }
        Command::RestoreVersion(restore) => {
            commands.restore_version(restore).await.map(CommandOutput::Restored)?
        }
        Command::ListFolders => {
            commands.linked_folders_snapshot().await.map(CommandOutput::Folders)?
        }
        Command::CreateShare(create) => {
            commands.create_share(create).await.map(CommandOutput::Shared)?
        }
        Command::JoinGroup(join) => commands.join_group(join).await.map(CommandOutput::Shared)?,
        Command::JoinShare(join) => commands.join_share(join).await.map(CommandOutput::Shared)?,
        Command::PauseLink(pause) => commands.pause_link(pause).map(|()| CommandOutput::Done)?,
        Command::ResumeLink(resume) => {
            commands.resume_link(resume).await.map(|()| CommandOutput::Done)?
        }
        Command::ReadoptMarkedFolder(readopt) => {
            commands.readopt_marked_folder(readopt).await.map(CommandOutput::Readopted)?
        }
        Command::Unlink(unlink) => commands.unlink(unlink).await.map(CommandOutput::Unlinked)?,
        Command::Status => status(commands, accounts).await?,
        Command::Doctor => CommandOutput::Doctor(commands.doctor()),
        Command::ListPreserved => commands.preserved_items().await.map(CommandOutput::Preserved)?,
        Command::RestorePreserved(item) => {
            commands.restore_preserved(item).await.map(|()| CommandOutput::Done)?
        }
        Command::DiscardPreserved(item) => {
            commands.discard_preserved(item).await.map(|()| CommandOutput::Done)?
        }
        Command::SpaceManagement => CommandOutput::SpaceManagement(commands.space_management()),
        Command::SetSpaceManagement { enabled } => {
            commands.set_space_management(enabled).map(CommandOutput::SpaceManagement)?
        }
        Command::ListActivity { limit, before_cursor, filter } => {
            let request = yadorilink_client_core::dto::activity_request(
                limit,
                before_cursor,
                filter.as_ref(),
            );
            let events = commands.list_activity(&request)?;
            // Names are best effort: signed out or offline, the events carry ids only.
            let names = if events.iter().any(|e| !e.origin_device_id.is_empty()) {
                accounts.device_names().await
            } else {
                std::collections::HashMap::new()
            };
            CommandOutput::Activity(yadorilink_client_core::dto::activity_page(
                limit.clamp(1, 500),
                &events,
                &names,
            ))
        }
        Command::CreateSendLink { ttl, source_paths } => {
            let link = commands.create_send_link(ttl.seconds(), &source_paths).await?;
            CommandOutput::SendLink(yadorilink_client_core::dto::send_link(link))
        }
        Command::PreviewSendLink { code } => {
            CommandOutput::SendLinkPreview(yadorilink_client_core::dto::send_link_preview(
                commands.preview_send_link(&code).await?,
            ))
        }
        Command::RedeemSendLink { code, device_id, destination_dir } => {
            CommandOutput::SendLinkRedeemed(
                commands
                    .redeem_send_link(
                        &code,
                        device_id.as_deref().unwrap_or_default(),
                        destination_dir.as_deref().unwrap_or_default(),
                    )
                    .await?,
            )
        }
        Command::CancelSendLink { link_id } => {
            commands.cancel_send_link(&link_id).await.map(|()| CommandOutput::Done)?
        }
        Command::SendLinkStatus { link_id } => {
            let status = commands.send_link_status(&link_id).await?;
            CommandOutput::SendLinkStatus(link_status(link_id, status)?)
        }
        Command::ListSendLinks => {
            let mut entries = Vec::new();
            for link in commands.list_send_links().await? {
                entries.push(SendLinkEntry {
                    status: link_status(link.link_id, link.status)?,
                    created_at_unix: link.created_at_unix,
                    expires_at_unix: link.expires_at_unix,
                    file_count: link.file_count,
                });
            }
            CommandOutput::SendLinks(entries)
        }
        Command::SendToLink { link_id, source_paths } => {
            CommandOutput::SendOffered(yadorilink_client_core::dto::sent_transfer(
                commands.send_to_link(&link_id, &source_paths).await?,
            ))
        }
        Command::ListInbox => inbox_output(&commands.list_inbox()?),
        Command::ListSentTransfers => CommandOutput::SentTransfers(
            commands
                .list_sent_transfers()?
                .iter()
                .map(yadorilink_client_core::dto::outgoing_transfer)
                .collect(),
        ),
        Command::ReceiveTransfer { transfer_id, destination_dir } => {
            CommandOutput::Received(yadorilink_client_core::dto::received_transfer(
                commands.receive_transfer(&transfer_id, destination_dir.as_deref()).await?,
            ))
        }
        Command::CancelTransfer { transfer_id } => {
            commands.cancel_transfer(&transfer_id).map(|()| CommandOutput::Done)?
        }
        Command::Account(AccountCommand::Status) => {
            CommandOutput::Account(Box::new(accounts.account_status_with(
                commands.linked_folders_snapshot().await.ok().map(|l| !l.is_empty()),
            )))
        }
        Command::Account(account) => accounts.run(commands, account).await?,
        Command::StageUpload { source, mode } => {
            CommandOutput::Staged(commands.stage_upload(source, mode).await)
        }
        Command::DiscardStagedUpload { ingest_name } => commands
            .discard_staged_upload(&ingest_name)
            .map(|()| CommandOutput::Done)
            .map_err(|refused| CommandError::failed(refused.message))?,
        Command::ApplyChange(change) => {
            CommandOutput::Applied(Box::new(commands.apply_change(*change).await))
        }
        Command::VersionDelivery { items } => {
            let report = commands.version_delivery(items).await?;
            // Names are best effort, and asked for only when some device confirmed.
            let confirmed = report
                .items
                .iter()
                .any(|entry| matches!(entry.state, DeliveryState::Delivered { .. }));
            let device_names =
                if confirmed { accounts.device_names().await } else { Default::default() };
            CommandOutput::Delivery(Box::new(DeliveryOutcome { report, device_names }))
        }
        Command::ListItemVersions { root_id, item_id } => {
            let listing = commands.list_item_versions(&root_id, &item_id)?;
            let named = listing.versions.iter().any(|v| v.origin_device_id.is_some());
            let device_names =
                if named { accounts.device_names().await } else { Default::default() };
            CommandOutput::ItemVersions(Box::new(HistoryOutcome { listing, device_names }))
        }
        Command::ListDeletedItems { root_id } => {
            let listing = commands.list_deleted_items(&root_id)?;
            let named = listing.items.iter().any(|v| v.origin_device_id.is_some());
            let device_names =
                if named { accounts.device_names().await } else { Default::default() };
            CommandOutput::DeletedItems(Box::new(HistoryOutcome { listing, device_names }))
        }
    })
}

/// How far the versions asked about have reached full replicas, with the names of the devices that
/// confirmed (by device id; a name is missing when the account's device list could not be read).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryOutcome {
    pub report: DeliveryReport,
    pub device_names: std::collections::HashMap<String, String>,
}

/// A link status in the product's type; a state this build does not know is a failure.
fn inbox_output(entries: &[yadorilink_ipc_proto::daemonctl::InboxTransfer]) -> CommandOutput {
    CommandOutput::Inbox(
        entries.iter().map(yadorilink_client_core::dto::incoming_transfer).collect(),
    )
}

fn link_status(
    link_id: String,
    status: yadorilink_ipc_proto::daemonctl::SendLinkStatusResponse,
) -> Result<yadorilink_client_core::dto::SendLinkStatus, CommandError> {
    yadorilink_client_core::dto::send_link_status(link_id, status).ok_or_else(|| {
        CommandError::failed("the Send link is in a state this version does not know")
    })
}

/// The status the desktop shows, from the engine's own: the engine's wire status and the account
/// state go through the client layer's one derivation of the product snapshot.
async fn status(
    commands: &yadorilink_daemon::embedded_host::EngineCommands,
    accounts: &AccountCommands,
) -> Result<CommandOutput, Failure> {
    let response = commands.status_snapshot().await?;
    let account = accounts.account_status_with(Some(!response.links.is_empty()));
    Ok(CommandOutput::Status(Box::new(yadorilink_client_core::dto::status_snapshot(
        &response,
        account,
        std::time::SystemTime::now(),
    ))))
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_inbox_output_carries_the_link_redeemed_receive_fields() {
        use yadorilink_ipc_proto::daemonctl::InboxTransfer;
        let entry = InboxTransfer {
            transfer_id: "t".into(),
            status: "in_progress".into(),
            total_size: 10,
            link_id: "link-1".into(),
            received_bytes: 4,
            destination_dir: "/recv/link-1".into(),
            ..Default::default()
        };
        let plain = InboxTransfer { transfer_id: "u".into(), ..Default::default() };
        let super::CommandOutput::Inbox(rows) = super::inbox_output(&[entry, plain]) else {
            panic!("an inbox")
        };
        assert_eq!(rows[0].link_id.as_deref(), Some("link-1"));
        assert_eq!(rows[0].received_bytes, 4);
        assert_eq!(rows[0].destination_dir.as_deref(), Some("/recv/link-1"));
        assert_eq!(rows[1].link_id, None);
        assert_eq!(rows[1].destination_dir, None);
    }

    use super::*;
    use crate::account::{BeginPairingSignIn, BeginSignIn, PollSignIn};

    /// Which commands only read, so that cancelling them aborts them. A command that changes
    /// state is never on this list: dropping it half-way would leave a half-done saga.
    #[test]
    fn only_commands_that_read_are_aborted_when_cancelled() {
        let id = SignInId(1);
        let item = PreservedRef { group_id: "g".into(), item_id: "i".into() };
        let reads = [
            Command::ListFolders,
            Command::Status,
            Command::Doctor,
            Command::ListPreserved,
            Command::SpaceManagement,
            Command::ListActivity { limit: 50, before_cursor: None, filter: None },
            Command::Account(AccountCommand::Status),
            Command::Account(AccountCommand::PollSignIn(PollSignIn { id, after: 0 })),
            Command::Account(AccountCommand::DeletionImpact),
            Command::Account(AccountCommand::ListJoinableGroups),
            Command::Account(AccountCommand::ListGroupDevices { group_id: String::new() }),
            Command::Account(AccountCommand::ListPrimaryTransfers),
            Command::Account(AccountCommand::DeletionStatus),
            Command::PreviewSendLink { code: String::new() },
            Command::SendLinkStatus { link_id: String::new() },
            Command::ListSendLinks,
            Command::ListInbox,
            Command::ListSentTransfers,
            Command::VersionDelivery { items: Vec::new() },
            Command::ListItemVersions { root_id: Vec::new(), item_id: Vec::new() },
            Command::ListDeletedItems { root_id: Vec::new() },
            // Waiting for a redeem and offering are safe to drop; see the variant.
            Command::SendToLink { link_id: String::new(), source_paths: Vec::new() },
        ];
        let changes = [
            Command::LinkFolder(LinkFolder {
                local_path: String::new(),
                group_id: String::new(),
                on_demand: false,
                acknowledge_risks: false,
            }),
            Command::RestoreVersion(RestoreVersion {
                group_id: String::new(),
                path: String::new(),
                version_seq: None,
            }),
            Command::CreateShare(CreateShare {
                group_name: String::new(),
                folder: ShareFolder::Provider(ProviderFolder {
                    display_name: String::new(),
                    request_token: String::new(),
                }),
                on_demand: false,
                acknowledge_risks: false,
            }),
            Command::JoinGroup(JoinGroup {
                group_id: String::new(),
                group_name: String::new(),
                folder: ShareFolder::Provider(ProviderFolder {
                    display_name: String::new(),
                    request_token: String::new(),
                }),
                on_demand: false,
                acknowledge_risks: false,
            }),
            Command::JoinShare(JoinShare {
                invite_code: String::new(),
                folder: ShareFolder::Provider(ProviderFolder {
                    display_name: String::new(),
                    request_token: String::new(),
                }),
                on_demand: false,
                acknowledge_risks: false,
            }),
            Command::PauseLink(PauseLink {
                link_key: String::new(),
                duration: PauseFor::UntilResumed,
                expected_group_id: None,
            }),
            Command::ResumeLink(ResumeLink { link_key: String::new(), expected_group_id: None }),
            Command::ReadoptMarkedFolder(ReadoptMarkedFolder { group_id: String::new() }),
            Command::Unlink(UnlinkFolder {
                link_key: String::new(),
                force: false,
                expected_group_id: None,
            }),
            Command::RestorePreserved(item.clone()),
            Command::DiscardPreserved(item),
            Command::SetSpaceManagement { enabled: true },
            Command::Account(AccountCommand::BeginSignIn(BeginSignIn::default())),
            Command::Account(AccountCommand::BeginPairingSignIn(BeginPairingSignIn {
                pairing_code: String::new(),
                overall_timeout: None,
            })),
            Command::Account(AccountCommand::CancelSignIn(id)),
            Command::Account(AccountCommand::CancelCurrentSignIn),
            Command::Account(AccountCommand::RegisterDevice { name: String::new() }),
            Command::Account(AccountCommand::SignOut),
            Command::Account(AccountCommand::StartOver {
                confirmed: false,
                device_name: String::new(),
            }),
            Command::Account(AccountCommand::AcknowledgePossibleLoss),
            Command::Account(AccountCommand::OfferPrimaryTransfer {
                group_id: String::new(),
                target_device_id: String::new(),
            }),
            Command::Account(AccountCommand::CancelPrimaryTransfer {
                group_id: String::new(),
                transfer_id: String::new(),
            }),
            Command::Account(AccountCommand::AcceptPrimaryTransfer {
                group_id: String::new(),
                transfer_id: String::new(),
            }),
            Command::Account(AccountCommand::DeclinePrimaryTransfer {
                group_id: String::new(),
                transfer_id: String::new(),
            }),
            Command::Account(AccountCommand::RequestDeletion { acknowledge_impact: false }),
            Command::Account(AccountCommand::ConfirmDeletion { confirmation_token: String::new() }),
            Command::Account(AccountCommand::CancelDeletion),
            Command::Account(AccountCommand::CompleteDeletion),
            Command::CreateSendLink {
                ttl: yadorilink_client_core::dto::SendLinkTtl::OneHour,
                source_paths: Vec::new(),
            },
            Command::RedeemSendLink { code: String::new(), device_id: None, destination_dir: None },
            Command::CancelSendLink { link_id: String::new() },
            Command::ReceiveTransfer { transfer_id: String::new(), destination_dir: None },
            Command::CancelTransfer { transfer_id: String::new() },
            // Writes change state: a cancelled call leaves them running and the caller replays
            // the same operation identity to learn the outcome.
            Command::StageUpload { source: StageSource::Descriptor(-1), mode: StageMode::Copy },
            Command::DiscardStagedUpload { ingest_name: String::new() },
            Command::ApplyChange(Box::default()),
        ];
        for command in &reads {
            assert!(is_read_only(command), "{command:?} only reads");
        }
        for command in &changes {
            assert!(!is_read_only(command), "{command:?} changes state");
        }
    }

    /// The runtime is gone before the task can run: the call ends with `EngineStopped` instead
    /// of waiting for ever (no deadline, no cancel).
    #[test]
    fn a_task_dropped_before_its_first_poll_ends_the_call() {
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let handle = runtime.handle().clone();
        drop(runtime);
        let (done, result) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let outcome = run(&handle, false, &CallOptions::default(), Instant::now(), async {
                Ok(CommandOutput::Linked)
            });
            let _ = done.send(outcome);
        });
        let outcome = result.recv_timeout(Duration::from_secs(10)).expect("the call did not hang");
        assert_eq!(outcome, Err(CallError::EngineStopped));
    }

    /// A current-thread runtime that never gets polled, then dropped with the task queued.
    #[test]
    fn a_queued_task_dropped_with_its_runtime_ends_the_call() {
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let handle = runtime.handle().clone();
        let (done, result) = std::sync::mpsc::channel();
        let caller = std::thread::spawn(move || {
            let outcome = run(&handle, false, &CallOptions::default(), Instant::now(), async {
                Ok(CommandOutput::Linked)
            });
            let _ = done.send(outcome);
        });
        // Let the call queue its task, then drop the runtime without ever running it.
        std::thread::sleep(Duration::from_millis(200));
        drop(runtime);
        let outcome = result.recv_timeout(Duration::from_secs(10)).expect("the call did not hang");
        caller.join().unwrap();
        assert_eq!(outcome, Err(CallError::EngineStopped));
    }
}
