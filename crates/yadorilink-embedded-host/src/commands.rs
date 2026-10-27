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
    ordinary_folder_links_supported, CommandError, CommandErrorKind, CreateShare, DoctorCheck,
    DoctorStatus, HandoffInfo, JoinGroup, JoinShare, LinkFolder, LinkedFolder, PauseFor, PauseLink,
    PreservedItem, PreservedKind, PreservedRef, PreservedRefusal, ProviderFolder,
    ReadoptMarkedFolder, ReadoptOutcome, ReadoptRefusal, RestoreVersion, ResumeLink, ShareFolder,
    ShareOutcome, SpaceManagement, UnlinkFolder, UnlinkOutcome,
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
    SetSpaceManagement {
        enabled: bool,
    },
    /// Sign-in, device registration, sign-out and account deletion.
    Account(AccountCommand),
}

impl Command {
    /// Whether the command only reads, so that cancelling it can abort it.
    fn read_only(&self) -> bool {
        match self {
            Self::ListFolders | Self::Status | Self::Doctor | Self::ListPreserved => true,
            Self::SpaceManagement => true,
            Self::Account(account) => account.read_only(),
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
            | Self::SetSpaceManagement { .. } => false,
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
    /// The folder groups the account may join: `(group_id, name)` summaries.
    JoinableGroups(Vec<yadorilink_client_core::dto::GroupSummary>),
    DeletionImpact(AccountDeletionImpact),
    DeletionRequested(AccountDeletionRequest),
    DeletionStatus(AccountDeletionStatus),
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
    Ok(match command {
        Command::LinkFolder(link) => {
            commands.link_folder(link).await.map(|()| CommandOutput::Linked)?
        }
        Command::RestoreVersion(restore) => {
            commands.restore_version(restore).await.map(CommandOutput::Restored)?
        }
        Command::ListFolders => commands.linked_folders().map(CommandOutput::Folders)?,
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
        Command::Status => status(commands, accounts)?,
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
        Command::Account(AccountCommand::Status) => CommandOutput::Account(Box::new(
            accounts.account_status_with(commands.linked_folders().ok().map(|l| !l.is_empty())),
        )),
        Command::Account(account) => accounts.run(commands, account).await?,
    })
}

/// The status the desktop shows, from the engine's own: the engine's wire status and the account
/// state go through the client layer's one derivation of the product snapshot.
fn status(
    commands: &yadorilink_daemon::embedded_host::EngineCommands,
    accounts: &AccountCommands,
) -> Result<CommandOutput, Failure> {
    let response = commands.status()?;
    let account = accounts.account_status_with(Some(!response.links.is_empty()));
    Ok(CommandOutput::Status(Box::new(yadorilink_client_core::dto::status_snapshot(
        &response,
        account,
        std::time::SystemTime::now(),
    ))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{BeginSignIn, PollSignIn};

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
            Command::Account(AccountCommand::Status),
            Command::Account(AccountCommand::PollSignIn(PollSignIn { id, after: 0 })),
            Command::Account(AccountCommand::DeletionImpact),
            Command::Account(AccountCommand::ListJoinableGroups),
            Command::Account(AccountCommand::DeletionStatus),
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
            Command::Account(AccountCommand::CancelSignIn(id)),
            Command::Account(AccountCommand::CancelCurrentSignIn),
            Command::Account(AccountCommand::RegisterDevice { name: String::new() }),
            Command::Account(AccountCommand::SignOut),
            Command::Account(AccountCommand::StartOver {
                confirmed: false,
                device_name: String::new(),
            }),
            Command::Account(AccountCommand::AcknowledgePossibleLoss),
            Command::Account(AccountCommand::RequestDeletion { acknowledge_impact: false }),
            Command::Account(AccountCommand::ConfirmDeletion { confirmation_token: String::new() }),
            Command::Account(AccountCommand::CancelDeletion),
            Command::Account(AccountCommand::CompleteDeletion),
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
