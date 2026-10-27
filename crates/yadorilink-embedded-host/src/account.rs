//! The account commands: sign-in (a device-code session the host polls and can cancel), device
//! registration, sign-out and the account-deletion lifecycle.
//!
//! They are the client layer's operations (`yadorilink-client-core`) over the engine's own state
//! directory, so the credential store, the device key and `device.json` are the engine's, never
//! the process environment's. They need no engine service; they run as commands so that they
//! share the call bounds (cancel handle, deadline) and end with the engine.
//!
//! After a sign-in and a device registration the running engine still holds the state it started
//! with (no credential, no device): the host suspends and resumes it (or stops and starts it) to
//! bring it up as the registered device.

#![allow(
    clippy::result_large_err,
    reason = "the product's own error type, as every client-core operation returns it; the host boxes it into the call's error"
)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use yadorilink_client_core::coordination::credential_store::CredentialSettings;
use yadorilink_client_core::coordination::http_client::require_auth_in;
pub use yadorilink_client_core::dto::{
    AccountDeletionImpact, AccountDeletionRequest, AccountDeletionStatus, AccountStatus,
    DeviceRegistration, LoginEvent, NotRejoined, SignOutOutcome, StartOverProgress,
    StartOverReport,
};
use yadorilink_client_core::dto::{LoginFlow, LoginOptions};
use yadorilink_client_core::session::{CancelOutcome, LoginSession};
use yadorilink_client_core::{ops, DesktopError};
use yadorilink_daemon::embedded_host::CredentialConfig;

use crate::commands::CommandOutput;

/// Identifies one sign-in the host started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignInId(pub u64);

/// Start a sign-in with the device-code flow: the user approves this device on another screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BeginSignIn {
    /// Ends the sign-in as failed when it has not finished in time; `None` waits as long as each
    /// step allows.
    pub overall_timeout: Option<Duration>,
    /// A step-up of the signed-in installation instead of an ordinary sign-in: for an action
    /// the engine refused with `PermissionDenied` and reason `ReauthenticationRequired`
    /// (account deletion). It keeps this installation's identity and device and needs a
    /// credential; the caller retries the refused action once the sign-in ends as `SignedIn`.
    /// An ordinary sign-in is refused while signed in, and a step-up while signed out.
    pub reauthenticate: bool,
}

/// Wait for the next step of a sign-in.
///
/// Events are numbered from 1. `after` is the number of the last event the caller has: the call
/// returns the event that follows it, waiting for it (as long as the call's deadline allows). A
/// call whose answer was lost is repeated with the same `after` and gets the same event, so a
/// step is never skipped by a timeout or a dropped answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollSignIn {
    pub id: SignInId,
    pub after: u64,
}

/// One step of a sign-in.
#[derive(Debug, Clone, PartialEq)]
pub struct SignInStep {
    /// This event's number; pass it as `after` to get the next.
    pub seq: u64,
    /// The last event of a sign-in is `SignedIn`, `Failed` or `Cancelled`.
    pub event: LoginEvent,
}

/// What cancelling the engine's current sign-in came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignInCancellation {
    /// The engine held no sign-in.
    NothingToCancel,
    /// This sign-in's flow has stopped and will store nothing; it ends as `Cancelled`, or keeps
    /// the `Failed` it already ended with (its overall timeout). Also the answer to a repeated
    /// cancel.
    Stopped(SignInId),
    /// This sign-in's flow had returned before the cancel: its own last event stands, `SignedIn`
    /// (its credential is stored) or `Failed`; read it with `PollSignIn`.
    AlreadyFinished(SignInId),
}

/// An account command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountCommand {
    /// Sign-in, registration and linked-folder state.
    Status,
    /// Starts a sign-in, ending the one that was running (it ends as `Cancelled`). The running
    /// one is stopped first, so by the time the new one starts it can no longer write the
    /// credential store.
    BeginSignIn(BeginSignIn),
    /// The next step of a sign-in.
    PollSignIn(PollSignIn),
    /// Cancels the sign-in `id` if it is the current one (any other id is already ended).
    /// When the call returns, that sign-in's flow has stopped: it is never polled again and
    /// a poll that was running has finished, so nothing of it is written to the credential
    /// store afterwards (see `LoginSession::cancel`). A flow that had already finished keeps
    /// its own last event, which the poll shows: `SignedIn` (its credential is stored) or
    /// `Failed`. Idempotent. The
    /// call is not aborted by its own cancel handle or deadline once started.
    CancelSignIn(SignInId),
    /// Cancels whatever sign-in this engine currently holds, with the same guarantee as
    /// [`Self::CancelSignIn`] and without its id: for a host whose `BeginSignIn` call ran out of
    /// time and so never learned the id. Safe when there is none
    /// ([`SignInCancellation::NothingToCancel`]).
    ///
    /// It is ordered with `BeginSignIn` (both take the engine's one sign-in slot), so it cancels
    /// a begin that has already started running, whether or not its answer was lost. A begin
    /// that was submitted but has not started running yet (the engine's runtime has not
    /// scheduled it) is not affected, and a caller that knows its begin was still running
    /// repeats this call after the begin's call has ended or once it learned the id.
    CancelCurrentSignIn,
    /// Registers this device on the account under `name`, once signed in.
    RegisterDevice {
        name: String,
    },
    /// Revokes this installation on the server, then removes its credential; the credential is
    /// kept whenever the revocation could not be confirmed.
    SignOut,
    /// Starts over as a new device after the replica database was refused as restored or copied
    /// (the status item `database_restored`), or continues a start over that is under way
    /// (`AccountStatus::start_over_pending`).
    ///
    /// With none under way, `confirmed` must be true (the caller showed the person what happens)
    /// and the engine must report the database as refused at that moment; otherwise the call is
    /// refused with nothing changed. It signs this installation out, retires the device key and
    /// `device.json` into `retired-devices/<device id>/` (kept, never deleted), and returns
    /// `SignInRequired`. After the person signs in again, the next call registers `device_name`
    /// as a new device and marks every linked folder as needing the person; its answer is
    /// `Finished`. Restart the engine (`suspend`, `resume`) after `Finished`, so it opens the
    /// database as the new device. Until it is restarted the engine still reports the database
    /// as refused, and a new start over (one with none under way) is refused with
    /// `Refused(StartOverRestartRequired)`, nothing changed; a continuation is not. No file the person synced is ever deleted or rewritten. A
    /// `Finished` whose report is not `complete` is run again.
    StartOver {
        confirmed: bool,
        device_name: String,
    },
    /// Records that the person acknowledged that changes made after the backup may be missing,
    /// which lets the engine confirm a replacement the service called unconfirmed once every
    /// folder is complete here. Only from an explicit user action. `false` when nothing waits.
    AcknowledgePossibleLoss,
    /// What deleting the account would do to other people's access and data custody.
    DeletionImpact,
    /// The origins the sign-in pages are served from, per purpose (see
    /// `ops::auth::trusted_sign_in_origins_in`).
    SignInOrigins,
    /// The folder groups this account owns and may join on this device (identity only: id and
    /// name). Read-only.
    ListJoinableGroups,
    /// Asks for account deletion; nothing is deleted until it is confirmed. Refused as
    /// `DurabilityBlocked` until `acknowledge_impact` when the impact is not empty.
    RequestDeletion {
        acknowledge_impact: bool,
    },
    /// Confirms a requested deletion with its one-time token, starting the grace period.
    ConfirmDeletion {
        confirmation_token: String,
    },
    /// Cancels a requested or confirmed deletion before the grace period ends.
    CancelDeletion,
    DeletionStatus,
    /// After the server finalized the deletion, removes this device's credential and key. Fails
    /// closed: while the account still exists nothing is removed.
    CompleteDeletion,
}

impl AccountCommand {
    /// Whether the command only reads, so that cancelling it can abort it. Waiting for a sign-in
    /// step is read-only: dropping it loses nothing, the step is delivered again.
    pub(crate) fn read_only(&self) -> bool {
        matches!(
            self,
            Self::Status
                | Self::PollSignIn(_)
                | Self::SignInOrigins
                | Self::DeletionImpact
                | Self::ListJoinableGroups
                | Self::DeletionStatus
        )
    }
}

/// How a sign-in session is built over a state directory.
pub(crate) type SignInFactory =
    Arc<dyn Fn(PathBuf, LoginOptions, bool) -> Arc<LoginSession> + Send + Sync>;

/// The factory the product uses: the client layer's sign-in over the directory, or its step-up
/// when the flag is set.
pub(crate) fn product_sign_in(settings: CredentialSettings) -> SignInFactory {
    Arc::new(move |dir, options, reauthenticate| {
        if reauthenticate {
            yadorilink_client_core::new_reauthentication_session_in(dir, settings.clone(), options)
        } else {
            yadorilink_client_core::new_login_session_in(dir, settings.clone(), options)
        }
    })
}

/// The client layer's credential settings for an engine's [`CredentialConfig`]: the host's
/// choice, not the environment's.
pub(crate) fn credential_settings(config: &CredentialConfig) -> CredentialSettings {
    CredentialSettings {
        backend: config.backend.clone(),
        key_mirror: config.key_mirror,
        auth_server_addr: config.auth_server_addr.clone(),
        coordination_addr: config.coordination_addr.clone(),
        host_name: config.host_name.clone(),
    }
}

/// The numbered last event of a sign-in, so that a lost answer can be asked for again.
struct Delivered {
    seq: u64,
    last: Option<LoginEvent>,
}

struct SignIn {
    session: Arc<LoginSession>,
    delivered: tokio::sync::Mutex<Delivered>,
}

/// The account commands of one engine. Its sign-in ends with the engine.
pub(crate) struct AccountCommands {
    config_dir: PathBuf,
    settings: CredentialSettings,
    sign_in_factory: SignInFactory,
    /// Shared by every engine of the host, so an id from before a restart is never issued again.
    next_id: Arc<AtomicU64>,
    /// The one sign-in that can be polled: beginning another ends this one.
    sign_in: Mutex<Option<(SignInId, Arc<SignIn>)>>,
    /// Held by every command that changes the device identity (start over, registration,
    /// sign-out), so that two of them never interleave their steps over the one key and journal.
    identity: tokio::sync::Mutex<()>,
    /// Set once a start over has finished on this engine. This engine still holds the identity it
    /// started with and keeps reporting the database as refused until the host restarts it, so a
    /// new start over without a journal would read that stale report as a fresh refusal and
    /// retire the identity just registered. Cleared by the restart (a new engine, a new value).
    restart_required: std::sync::atomic::AtomicBool,
}

impl AccountCommands {
    pub(crate) fn new(
        config_dir: PathBuf,
        settings: CredentialSettings,
        sign_in_factory: SignInFactory,
        next_id: Arc<AtomicU64>,
    ) -> Self {
        Self {
            config_dir,
            settings,
            sign_in_factory,
            next_id,
            sign_in: Mutex::new(None),
            identity: tokio::sync::Mutex::new(()),
            restart_required: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn current(&self) -> std::sync::MutexGuard<'_, Option<(SignInId, Arc<SignIn>)>> {
        self.sign_in.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn sign_in_of(&self, id: SignInId) -> Result<Arc<SignIn>, DesktopError> {
        match &*self.current() {
            Some((current, sign_in)) if *current == id => Ok(sign_in.clone()),
            _ => Err(DesktopError::InvalidInput {
                message: "this sign-in is not the current one (another was started, or the \
                          engine restarted)"
                    .to_owned(),
                field: Some("sign_in".to_owned()),
            }),
        }
    }

    /// `has_linked_folders` is the engine's answer, which only the caller has.
    pub(crate) fn account_status_with(&self, has_linked_folders: Option<bool>) -> AccountStatus {
        yadorilink_client_core::account_status_in(
            &self.config_dir,
            &self.settings,
            has_linked_folders,
        )
    }

    /// The start over over `ports`, one at a time with the other identity commands.
    ///
    /// Invariant: once a start over has finished, this engine starts no other until it has been
    /// restarted, because only a restart replaces its stale `database_restored` report (see
    /// `restart_required`). A continuation (a journal exists) is always allowed.
    ///
    /// # Errors
    /// `Refused(StartOverRestartRequired)` for a new start over on an engine that has not restarted since one
    /// finished; the operation's own errors otherwise.
    pub(crate) async fn start_over_with<P: ops::start_over::StartOverPorts>(
        &self,
        ports: &P,
        confirmed: bool,
        device_name: String,
    ) -> Result<StartOverProgress, DesktopError> {
        let _identity = self.identity.lock().await;
        if self.restart_required.load(Ordering::SeqCst)
            && !ops::start_over::pending_in(&self.config_dir)
        {
            return Err(yadorilink_client_core::error::CoreError::StartOverRefused(
                yadorilink_client_core::error::StartOverRefusal::RestartRequired,
            )
            .into());
        }
        let progress = ops::start_over::start_over(ports, confirmed, device_name).await?;
        let progress = yadorilink_client_core::dto::start_over_progress(progress);
        if matches!(&progress, StartOverProgress::Finished { report } if report.complete) {
            self.restart_required.store(true, Ordering::SeqCst);
        }
        Ok(progress)
    }

    pub(crate) async fn run(
        &self,
        commands: &yadorilink_daemon::embedded_host::EngineCommands,
        command: AccountCommand,
    ) -> Result<CommandOutput, DesktopError> {
        let dir = self.config_dir.as_path();
        let settings = &self.settings;
        Ok(match command {
            AccountCommand::Status => {
                CommandOutput::Account(Box::new(self.account_status_with(None)))
            }
            AccountCommand::BeginSignIn(begin) => {
                // The whole begin runs under the sign-in slot (nothing here awaits), so a
                // cancel of the current sign-in is ordered before or after it, never between.
                let mut slot = self.current();
                // The one that was running is stopped BEFORE the new one starts: it can no
                // longer write the credential store, so the new sign-in's precheck reads the
                // store as the old one left it.
                if let Some((_, previous)) = &*slot {
                    previous.session.cancel();
                }
                let session = (self.sign_in_factory)(
                    self.config_dir.clone(),
                    LoginOptions {
                        flow: LoginFlow::DeviceCode,
                        overall_timeout: begin.overall_timeout,
                    },
                    begin.reauthenticate,
                );
                session.begin()?;
                let id = SignInId(self.next_id.fetch_add(1, Ordering::SeqCst));
                let sign_in = Arc::new(SignIn {
                    session,
                    delivered: tokio::sync::Mutex::new(Delivered { seq: 0, last: None }),
                });
                *slot = Some((id, sign_in));
                CommandOutput::SignInBegun(id)
            }
            AccountCommand::PollSignIn(poll) => {
                let sign_in = self.sign_in_of(poll.id)?;
                let mut delivered = sign_in.delivered.lock().await;
                if let (true, Some(event)) = (delivered.seq > poll.after, &delivered.last) {
                    return Ok(CommandOutput::SignInStep(SignInStep {
                        seq: delivered.seq,
                        event: event.clone(),
                    }));
                }
                // Cancel-safe: a dropped wait loses no event, and the number only advances once
                // an event is in hand.
                let Some(event) = sign_in.session.next_event().await else {
                    return Err(DesktopError::InvalidInput {
                        message: "the sign-in has ended".to_owned(),
                        field: Some("sign_in".to_owned()),
                    });
                };
                delivered.seq += 1;
                delivered.last = Some(event.clone());
                CommandOutput::SignInStep(SignInStep { seq: delivered.seq, event })
            }
            AccountCommand::CancelSignIn(id) => {
                // A sign-in that is no longer the current one is already ended.
                if let Ok(sign_in) = self.sign_in_of(id) {
                    sign_in.session.cancel();
                }
                CommandOutput::Done
            }
            AccountCommand::CancelCurrentSignIn => {
                // Taken out of the slot's lock before cancelling: a cancel waits for a poll of
                // the flow, and nothing should wait on the slot meanwhile.
                let current = self.current().clone();
                CommandOutput::SignInCancellation(match current {
                    None => SignInCancellation::NothingToCancel,
                    Some((id, sign_in)) => match sign_in.session.cancel() {
                        CancelOutcome::Stopped => SignInCancellation::Stopped(id),
                        CancelOutcome::AlreadyFinished => SignInCancellation::AlreadyFinished(id),
                    },
                })
            }
            AccountCommand::StartOver { confirmed, device_name } => {
                let ports = crate::start_over::EmbeddedPorts { dir, settings, commands };
                CommandOutput::StartOver(
                    self.start_over_with(&ports, confirmed, device_name).await?,
                )
            }
            AccountCommand::AcknowledgePossibleLoss => CommandOutput::PossibleLossAcknowledged(
                ops::start_over::acknowledge_possible_loss_in(dir)?,
            ),
            AccountCommand::RegisterDevice { name } => {
                let _identity = self.identity.lock().await;
                let device_id = ops::devices::register_device_in(dir, settings, name).await?;
                CommandOutput::DeviceRegistered(DeviceRegistration { device_id })
            }
            AccountCommand::SignOut => {
                let _identity = self.identity.lock().await;
                let report = ops::auth::sign_out_in(dir, settings).await?;
                let kind = match report.kind {
                    ops::auth::SignOutKind::Revoked { grants_revoked } => {
                        yadorilink_client_core::dto::SignOutKind::Revoked { grants_revoked }
                    }
                    ops::auth::SignOutKind::AlreadyRevoked => {
                        yadorilink_client_core::dto::SignOutKind::AlreadyRevoked
                    }
                    ops::auth::SignOutKind::ConfirmedRevokedAfterRejection => {
                        yadorilink_client_core::dto::SignOutKind::ConfirmedRevokedAfterRejection
                    }
                };
                CommandOutput::SignedOut(SignOutOutcome {
                    kind,
                    key_cleanup_warning: report.key_cleanup_warning,
                })
            }
            AccountCommand::SignInOrigins => {
                CommandOutput::SignInOrigins(ops::auth::trusted_sign_in_origins_in(dir, settings)?)
            }
            AccountCommand::DeletionImpact => {
                let auth = require_auth_in(dir, settings).await?;
                CommandOutput::DeletionImpact(yadorilink_client_core::dto::account_deletion_impact(
                    &ops::account::deletion_impact_with(&auth).await?,
                ))
            }
            AccountCommand::ListJoinableGroups => {
                let auth = require_auth_in(dir, settings).await?;
                CommandOutput::JoinableGroups(
                    ops::shares::list_joinable_groups_with(&auth)
                        .await?
                        .into_iter()
                        .map(|g| yadorilink_client_core::dto::GroupSummary {
                            group_id: g.group_id,
                            name: g.name,
                        })
                        .collect(),
                )
            }
            AccountCommand::RequestDeletion { acknowledge_impact } => {
                let auth = require_auth_in(dir, settings).await?;
                let requested = ops::account::request_deletion_with(&auth, acknowledge_impact)
                    .await
                    .map_err(|e| DesktopError::from_core(e, true))?;
                CommandOutput::DeletionRequested(AccountDeletionRequest {
                    confirmation_token: requested.confirmation_token,
                })
            }
            AccountCommand::ConfirmDeletion { confirmation_token } => {
                let auth = require_auth_in(dir, settings).await?;
                CommandOutput::DeletionStatus(yadorilink_client_core::dto::account_deletion_status(
                    &ops::account::confirm_deletion_with(&auth, &confirmation_token).await?,
                ))
            }
            AccountCommand::CancelDeletion => {
                let auth = require_auth_in(dir, settings).await?;
                CommandOutput::DeletionStatus(yadorilink_client_core::dto::account_deletion_status(
                    &ops::account::cancel_deletion_with(&auth).await?,
                ))
            }
            AccountCommand::DeletionStatus => {
                let auth = require_auth_in(dir, settings).await?;
                CommandOutput::DeletionStatus(yadorilink_client_core::dto::account_deletion_status(
                    &ops::account::deletion_status_with(&auth).await?,
                ))
            }
            AccountCommand::CompleteDeletion => {
                let report = ops::auth::complete_account_deletion_in(dir, settings).await?;
                CommandOutput::SignedOut(SignOutOutcome {
                    kind: yadorilink_client_core::dto::SignOutKind::ConfirmedRevokedAfterRejection,
                    key_cleanup_warning: report.key_cleanup_warning,
                })
            }
        })
    }
}
