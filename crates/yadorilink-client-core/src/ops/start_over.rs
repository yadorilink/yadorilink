//! Starting over as a new device: the way out of a refused (`database_restored`) replica database.
//!
//! A restored or copied database must not author as the device it came from, because the old
//! device's author state may already be ahead of it elsewhere. The device has to become a new
//! device, and for the only copy of a folder group that cannot be done by removing the old device
//! (the service refuses to remove the last full replica) or by signing out (the old signing key
//! stays bound to the old device row). This operation retires the identity locally and takes the
//! machine through a registration as a new device, without touching a file on disk:
//!
//! * the replica database, block store and every synced folder stay where they are. The old
//!   device's history stays in the database as a prior author incarnation; the engine rotates to a
//!   new author when it opens the database as the new device. Files on disk are re-adopted by the
//!   new device's scan like any file already in a folder that is linked;
//! * the old installation is signed out (its authority is revoked) and the old device row is left
//!   on the account, signed out. It is not removed here: removing it is the account's decision
//!   (`device remove`), and a device row that holds data protection is not ours to drop;
//! * a new signing key replaces the old one, which is moved to `retired-devices/<device id>/` (it
//!   is kept, never deleted); then `device.json` goes there too. The key goes first, so a machine
//!   that is unregistered always holds the new key; registering is refused until the journal says
//!   the identity is retired;
//! * after the person signs in again, the machine registers as a new device, tells the coordination
//!   service that it replaces the retired device (a request proven with the new device's own
//!   signing key, and safe to send again), and joins each folder group it had linked, in the
//!   storage mode it had, at the same folder. When the service answers that the retired device
//!   was the only complete replica of some group, the replacement stays unconfirmed and status
//!   reports it (`replacement_unconfirmed`) instead of healthy. Those groups are joined as full
//!   replicas (an on-demand folder is promoted to eager), and the daemon confirms the replacement
//!   itself once their data is complete here.
//!
//! The steps are recorded in a journal (`identity-restart.json` in the state directory), written
//! before the first one, so an interrupted run continues from the record instead of from what the
//! machine looks like. The preconditions are checked when the operation starts, against the
//! daemon's own report: the database is refused as restored right now, and the caller confirmed.

use std::future::Future;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, StartOverRefusal};
use crate::ops::device_supersede::{SupersedeError, SupersedeResponse};

/// Said when the service wants a fresher sign-in before it lets a device be replaced.
const REAUTHENTICATION_MESSAGE: &str =
    "the service needs a fresh sign-in before it can mark the retired device as replaced; sign \
     out, sign in again, then run the start over again. Nothing on this machine was changed";
/// Said when the new device is still registered to an installation that was not signed out.
const INSTALLATION_NOT_SIGNED_OUT_MESSAGE: &str =
    "the new device was registered by an installation that is still signed in, so the service \
     will not hand it to this sign-in; sign out of that installation, sign in again, then run \
     the start over again. Nothing on this machine was changed";
/// Said when another device already replaced the retired one.
const ALREADY_REPLACED_MESSAGE: &str =
    "this device was already replaced by another device, so this machine cannot replace it as \
     well. Your files are kept; the start over stays open and nothing was removed";

/// The journal's file name in the state directory.
const JOURNAL: &str = "identity-restart.json";
/// Where retired identities are kept, one directory per retired device id.
pub(crate) const RETIRED_DIR: &str = "retired-devices";

/// What happened to one linked folder when the new device joined its group again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RejoinFailure {
    pub local_path: String,
    pub group_id: String,
    pub message: String,
}

/// The finished (or nearly finished) start over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartOverReport {
    pub retired_device_id: String,
    pub new_device_id: String,
    /// Folders the new device joined again, by local path.
    pub rejoined: Vec<String>,
    /// Folders that need the person (a provider folder, a group this account does not own).
    pub not_rejoined: Vec<RejoinFailure>,
    /// Every folder was handled; the journal is cleared. When false, running the operation again
    /// retries the folders in `not_rejoined` that failed.
    pub complete: bool,
}

/// How far a call to [`start_over`] got.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StartOverProgress {
    /// The old identity is retired and this machine is signed out. Sign in, then run the
    /// operation again to register and join the folders again.
    SignInRequired {
        retired_device_id: String,
    },
    Finished(StartOverReport),
}

/// One folder the machine had linked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkedFolder {
    pub local_path: String,
    pub group_id: String,
    pub on_demand: bool,
}

/// Why one folder was not joined again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RejoinError {
    /// Nothing to retry: a person has to do something else (accept an invite, link the provider
    /// folder).
    NeedsPerson(String),
    /// Trying again may help.
    Failed(String),
}

/// Everything the operation touches outside the state directory, so that its order and its
/// preconditions are testable without a daemon or a coordination service.
pub trait StartOverPorts: Send + Sync {
    fn state_dir(&self) -> Result<PathBuf, CoreError>;
    /// Whether the daemon reports the replica database as refused (restored or copied) right now.
    /// A daemon that cannot be asked is an error: the precondition is not assumed.
    fn database_restored(&self) -> impl Future<Output = Result<bool, CoreError>> + Send;
    /// This machine's registered device id, if `device.json` names one.
    fn registered_device_id(&self) -> Option<String>;
    /// The installation id (OAuth client id) of the credential this machine holds, if any.
    fn installation_id(&self) -> Result<Option<String>, CoreError>;
    /// Revokes this installation on the server and removes its credential.
    fn sign_out(&self) -> impl Future<Output = Result<(), CoreError>> + Send;
    /// Replaces the signing key with a new one, keeping the old at `retired_key`.
    fn replace_signing_key(&self, key: &Path, retired_key: &Path) -> Result<(), CoreError>;
    /// Whether this host joins a folder group again itself. A host that cannot (the embedded
    /// engine: its folders are provider folders, which are linked from the provider folder list)
    /// answers false: every linked folder is then marked as needing the person, never joined,
    /// and [`Self::joinable_group_names`], [`Self::rejoin`] and [`Self::promote_to_eager`] are
    /// not called.
    fn can_rejoin(&self) -> bool {
        true
    }
    fn restart_daemon_if_running(&self) -> impl Future<Output = Result<(), CoreError>> + Send;
    /// Starts the daemon when nothing answers: a restart can leave it down.
    fn ensure_daemon_running(&self) -> impl Future<Output = Result<(), CoreError>> + Send;
    fn register(&self, name: String) -> impl Future<Output = Result<String, CoreError>> + Send;
    /// Tells the service that `new_device_id` replaces `retired_device_id`, proven with the new
    /// device's signing key. Idempotent: sending it again after an interruption is safe.
    fn supersede(
        &self,
        retired_device_id: &str,
        new_device_id: &str,
    ) -> impl Future<Output = Result<SupersedeResponse, SupersedeError>> + Send;
    fn linked_folders(&self) -> impl Future<Output = Result<Vec<LinkedFolder>, CoreError>> + Send;
    /// The names of the folder groups this account owns, by group id.
    fn joinable_group_names(
        &self,
    ) -> impl Future<Output = Result<Vec<(String, String)>, CoreError>> + Send;
    fn rejoin(
        &self,
        folder: &LinkedFolder,
        group_name: &str,
    ) -> impl Future<Output = Result<(), CoreError>> + Send;
    /// Makes this device an eager (full replica) member of a group it has just joined again in
    /// on-demand mode. Only a promotion: it gives the device more data, never less, and the
    /// daemon applies it without a durability hand-off. Running it again is harmless.
    fn promote_to_eager(
        &self,
        folder: &LinkedFolder,
        group_name: &str,
    ) -> impl Future<Output = Result<(), CoreError>> + Send;
    /// Records, in the daemon's link state, that the folder was not joined again: it stops taking
    /// part in sync and stays visible as needing the person across restarts, until it is linked
    /// to its group again or unlinked. Its files are never touched. Running it again is harmless.
    fn mark_not_rejoined(
        &self,
        folder: &LinkedFolder,
    ) -> impl Future<Output = Result<(), CoreError>> + Send;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    retired_device_id: String,
    /// The installation that was signed in when the start over began: the only one the `Retiring`
    /// stage may sign out. A different installation found later is a sign-in made after the
    /// sign-out, and is never revoked.
    #[serde(default, skip_serializing_if = "RetiringInstallation::is_unrecorded")]
    retiring_installation: RetiringInstallation,
    stage: Stage,
    /// The folders already marked as needing the person, by local path. Recorded one by one so
    /// that a retry never marks a folder twice: the person may have linked it to its group again
    /// since, and the list of links cannot tell that from a folder not handled yet.
    #[serde(default)]
    marked: Vec<String>,
}

/// What the journal knows about the installation being retired. The wire form is the plain
/// optional string (`null` records that nothing was signed in); a journal written before the
/// field existed has no key at all, which is [`Self::Unrecorded`]: unlike `null`, it proves
/// nothing, so the `Retiring` stage refuses to continue from it instead of treating it as "no
/// installation to sign out".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum RetiringInstallation {
    #[default]
    Unrecorded,
    Recorded(Option<String>),
}

impl RetiringInstallation {
    fn is_unrecorded(&self) -> bool {
        matches!(self, Self::Unrecorded)
    }
}

impl Serialize for RetiringInstallation {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            // Never written (see `skip_serializing_if`); `null` would claim a proof it lacks.
            Self::Unrecorded => Err(serde::ser::Error::custom("unrecorded installation")),
            Self::Recorded(installation) => installation.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for RetiringInstallation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Option::<String>::deserialize(deserializer).map(Self::Recorded)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Stage {
    /// Written before the first step. Nothing irreversible has happened yet.
    Retiring,
    /// The old installation was signed out. A sign-in seen from here on is the new one and is
    /// never signed out again.
    SignedOut,
    /// The old identity is retired; the machine needs a sign-in and a new registration.
    Retired,
    /// The service recorded that the new device replaces the retired one. Added last: the stages
    /// before it keep their wire names, and a journal that predates it continues from `retired`
    /// by sending the (idempotent) claim.
    Superseded,
}

fn journal_path(dir: &Path) -> PathBuf {
    dir.join(JOURNAL)
}

fn read_journal(dir: &Path) -> Result<Option<Journal>, CoreError> {
    match std::fs::read_to_string(journal_path(dir)) {
        Ok(text) => serde_json::from_str(&text).map(Some).map_err(|e| {
            CoreError::Other(format!(
                "{} is unreadable ({e}); it records a start over that is under way and is not \
                 removed automatically",
                journal_path(dir).display()
            ))
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn write_journal(dir: &Path, journal: &Journal) -> Result<(), CoreError> {
    let staged = dir.join(format!(".{JOURNAL}.tmp-{}", std::process::id()));
    yadorilink_fs_platform::durable_dir::remove_file_durably(&staged)?;
    {
        // One handle for the write and the flush: a read-only handle cannot flush on Windows.
        let mut file = std::fs::File::create(&staged)?;
        std::io::Write::write_all(&mut file, &serde_json::to_vec_pretty(journal)?)?;
        yadorilink_fs_platform::flush::sync_file(&file)?;
    }
    yadorilink_fs_platform::durable_dir::publish_durably(
        &staged,
        &journal_path(dir),
        yadorilink_fs_platform::durable_dir::Replace::Yes,
    )?;
    Ok(())
}

fn clear_journal(dir: &Path) -> Result<(), CoreError> {
    // Durable before the caller reports the start over finished: a crash after this returns can
    // never bring the journal back.
    yadorilink_fs_platform::durable_dir::remove_file_durably(&journal_path(dir))?;
    Ok(())
}

/// Whether a start over has been begun and not finished on the machine whose state is in `dir`.
#[must_use]
pub fn pending_in(dir: &Path) -> bool {
    journal_path(dir).exists()
}

/// Refuses a registration while a start over is mid-way: from the journal's first record until the
/// old identity is fully retired, the signing key at hand is the one being retired, and a device
/// row registered with it would be bound to a key the next step takes away. An unreadable journal
/// refuses too (the error says so).
///
/// # Errors
/// [`CoreError::StartOverRefused`] with [`StartOverRefusal::InProgress`].
pub fn ensure_registration_allowed(dir: &Path) -> Result<(), CoreError> {
    match read_journal(dir)? {
        Some(Journal { stage: Stage::Retiring | Stage::SignedOut, .. }) => {
            Err(CoreError::StartOverRefused(StartOverRefusal::InProgress))
        }
        Some(Journal { stage: Stage::Retired | Stage::Superseded, .. }) | None => Ok(()),
    }
}

/// [`pending_in`] for this machine's state directory.
#[must_use]
pub fn pending() -> bool {
    crate::coordination::device_config::config_dir().is_ok_and(|dir| pending_in(&dir))
}

/// Records that the person acknowledged that changes made after the backup may be missing, which
/// lets the daemon confirm the replacement once every group is complete here. `Ok(false)` when no
/// replacement is waiting. Nothing this device holds can prove those groups complete, so the
/// daemon never confirms without it.
///
/// # Errors
/// The record could not be read or written.
pub fn acknowledge_possible_loss_in(dir: &Path) -> Result<bool, CoreError> {
    Ok(yadorilink_local_storage::replacement_unconfirmed::acknowledge_possible_loss(dir)?)
}

/// [`acknowledge_possible_loss_in`] for this machine's state directory.
///
/// # Errors
/// The record could not be read or written.
pub fn acknowledge_possible_loss() -> Result<bool, CoreError> {
    acknowledge_possible_loss_in(&crate::coordination::device_config::config_dir()?)
}

/// Starts over as a new device, or continues a start over that is under way.
///
/// With no start over under way, `confirmed` must be true and the daemon must report the database
/// as restored; otherwise the call is refused with nothing changed. When one is under way the
/// journal decides what is left to do, and `confirmed` is not asked again.
///
/// # Errors
/// [`CoreError::StartOverRefused`] for a missing confirmation or a database that is not refused as
/// restored; the daemon being unreachable, a sign-out that cannot be confirmed (the credential is
/// then kept and nothing else is changed) and any step's own failure otherwise.
pub async fn start_over<P: StartOverPorts>(
    ports: &P,
    confirmed: bool,
    device_name: String,
) -> Result<StartOverProgress, CoreError> {
    let dir = ports.state_dir()?;
    let journal = match read_journal(&dir)? {
        Some(journal) => journal,
        None => {
            if !confirmed {
                return Err(CoreError::StartOverRefused(StartOverRefusal::NotConfirmed));
            }
            if !ports.database_restored().await? {
                return Err(CoreError::StartOverRefused(StartOverRefusal::NotRestored));
            }
            let Some(retired_device_id) = ports.registered_device_id() else {
                return Err(CoreError::StartOverRefused(StartOverRefusal::NotRestored));
            };
            let retiring_installation = RetiringInstallation::Recorded(ports.installation_id()?);
            let journal = Journal {
                retired_device_id,
                retiring_installation,
                stage: Stage::Retiring,
                marked: Vec::new(),
            };
            write_journal(&dir, &journal)?;
            journal
        }
    };

    if journal.stage == Stage::Retiring {
        // Revocation first: it is the step that cannot be taken back, and the only one that needs
        // the old credential. A sign-out that cannot be confirmed leaves everything as it was.
        match &journal.retiring_installation {
            RetiringInstallation::Unrecorded => {
                // Written by a version that did not record the installation: which credential to
                // revoke cannot be proven, and a guess could skip the revocation or revoke a
                // later sign-in. Nothing is changed.
                return Err(CoreError::Other(format!(
                    "{} was written by an older version and does not record which installation \
                     this start over was retiring, so it cannot be continued safely; nothing \
                     was changed. Sign out the original installation yourself, then add \
                     `\"retiring_installation\": null` to the file to continue (or the \
                     installation id as a string to have it signed out)",
                    journal_path(&dir).display()
                )));
            }
            RetiringInstallation::Recorded(Some(installation))
                if ports.installation_id()?.as_ref() == Some(installation) =>
            {
                ports.sign_out().await?;
            }
            RetiringInstallation::Recorded(_) => {}
        }
        write_journal(
            &dir,
            &Journal {
                retired_device_id: journal.retired_device_id.clone(),
                retiring_installation: journal.retiring_installation.clone(),
                stage: Stage::SignedOut,
                marked: Vec::new(),
            },
        )?;
    }
    if !matches!(journal.stage, Stage::Retired | Stage::Superseded) {
        retire_identity(ports, &dir, &journal.retired_device_id).await?;
        write_journal(
            &dir,
            &Journal {
                retired_device_id: journal.retired_device_id.clone(),
                retiring_installation: journal.retiring_installation.clone(),
                stage: Stage::Retired,
                marked: Vec::new(),
            },
        )?;
    }

    if ports.installation_id()?.is_none() {
        return Ok(StartOverProgress::SignInRequired {
            retired_device_id: journal.retired_device_id,
        });
    }
    // A running daemon reads the credential only at startup. After a sign-out and a new
    // sign-in it would still authenticate as the previous installation, so a device
    // registered now would be refused every join. Restarting it first makes it adopt the
    // stored sign-in; if that cannot be confirmed, nothing has been sent to the service
    // yet and the start over stays where it is.
    ports.restart_daemon_if_running().await.map_err(|error| {
        error.with_context(
            |why| {
                format!(
                    "the running daemon could not be restarted to pick up the current sign-in, \
                     so nothing was registered or changed and the start over can be run again: \
                     {why}"
                )
            },
            None,
        )
    })?;
    let new_device_id = match ports.registered_device_id() {
        Some(id) if id != journal.retired_device_id => id,
        _ => ports.register(device_name).await?,
    };
    let journal = if journal.stage == Stage::Superseded {
        journal
    } else {
        supersede_retired(ports, &dir, &journal, &new_device_id).await?;
        // A resend after an interruption lands here again with the same answer.
        let journal = Journal { stage: Stage::Superseded, ..journal };
        write_journal(&dir, &journal)?;
        journal
    };
    ports.ensure_daemon_running().await?;
    let report = rejoin_all(ports, &dir, &journal, new_device_id).await?;
    if report.complete {
        clear_journal(&dir)?;
    }
    Ok(StartOverProgress::Finished(report))
}

/// Sends the supersede claim and keeps what status must keep showing until it is confirmed. Every
/// failure leaves the journal as it is, so running the operation again sends the same claim.
async fn supersede_retired<P: StartOverPorts>(
    ports: &P,
    dir: &Path,
    journal: &Journal,
    new_device_id: &str,
) -> Result<(), CoreError> {
    let response = match ports.supersede(&journal.retired_device_id, new_device_id).await {
        Ok(response) => response,
        Err(SupersedeError::ReauthenticationRequired) => {
            return Err(CoreError::Forbidden(REAUTHENTICATION_MESSAGE.to_owned()));
        }
        Err(SupersedeError::InstallationNotSignedOut) => {
            return Err(CoreError::Forbidden(INSTALLATION_NOT_SIGNED_OUT_MESSAGE.to_owned()));
        }
        Err(SupersedeError::AlreadyReplaced) => {
            return Err(CoreError::Other(ALREADY_REPLACED_MESSAGE.to_owned()));
        }
        Err(SupersedeError::Failed(error)) => return Err(error),
    };
    if response.old_device_id != journal.retired_device_id
        || response.new_device_id != new_device_id
    {
        return Err(CoreError::Other(
            "the service answered for a different pair of devices than the one asked about"
                .to_owned(),
        ));
    }
    if !response.is_confirmed() {
        // Durable before the journal says superseded: status must never read healthy for a
        // replacement the service called unconfirmed.
        yadorilink_local_storage::replacement_unconfirmed::write(
            dir,
            &yadorilink_local_storage::replacement_unconfirmed::Record {
                old_device_id: response.old_device_id,
                new_device_id: response.new_device_id,
                unconfirmed_group_ids: response.unconfirmed_group_ids,
                acknowledged_possible_loss: false,
            },
        )?;
    }
    Ok(())
}

/// Moves the old identity aside. Each step can be run again.
async fn retire_identity<P: StartOverPorts>(
    ports: &P,
    dir: &Path,
    retired_device_id: &str,
) -> Result<(), CoreError> {
    let retired_dir = dir.join(RETIRED_DIR).join(retired_device_id);
    yadorilink_fs_platform::durable_dir::create_dir_all_durably(&retired_dir)?;
    // The key first: from here on an unregistered machine always holds the new key, and while the
    // journal is short of `retired` a registration is refused anyway.
    ports.replace_signing_key(&dir.join("signing_key"), &retired_dir.join("signing_key"))?;
    // Only the identity that was retired is moved; a `device.json` naming another device belongs
    // to a registration made after this step and stays.
    if ports.registered_device_id().as_deref() == Some(retired_device_id) {
        yadorilink_fs_platform::durable_dir::publish_durably(
            &dir.join("device.json"),
            &retired_dir.join("device.json"),
            yadorilink_fs_platform::durable_dir::Replace::Yes,
        )?;
    }
    // The running daemon still holds the old identity, which it refuses to author with anyway;
    // the next registration restarts it. A restart that fails here changes nothing the person
    // must act on.
    let _ = ports.restart_daemon_if_running().await;
    Ok(())
}

async fn rejoin_all<P: StartOverPorts>(
    ports: &P,
    dir: &Path,
    journal: &Journal,
    new_device_id: String,
) -> Result<StartOverReport, CoreError> {
    let retired_device_id = journal.retired_device_id.as_str();
    // A folder is marked once per start over: on a retry one it marked may have been linked to its
    // group again since, and the list of links cannot tell that from a folder not handled yet.
    let mut marked = journal.marked.clone();
    let folders = ports.linked_folders().await?;
    // The groups the service named as solely covered by the retired device: this device must hold
    // them as a full replica before the replacement can be confirmed.
    let unconfirmed: Vec<String> = yadorilink_local_storage::replacement_unconfirmed::read(dir)?
        .map(|record| record.unconfirmed_group_ids)
        .unwrap_or_default();
    let can_rejoin = ports.can_rejoin();
    let names = if folders.is_empty() || !can_rejoin {
        Vec::new()
    } else {
        ports.joinable_group_names().await?
    };
    let mut report = StartOverReport {
        retired_device_id: retired_device_id.to_owned(),
        new_device_id,
        rejoined: Vec::new(),
        not_rejoined: Vec::new(),
        complete: true,
    };
    for folder in folders {
        let needs_person = if folder.local_path.starts_with("provider://") {
            Some("a provider folder is joined again from the provider folder list")
        } else if !can_rejoin {
            Some("this host does not join a folder again by itself; accept an invite to its group again, or unlink the folder")
        } else if !names.iter().any(|(id, _)| *id == folder.group_id) {
            Some(
                "this account does not own the folder group, so it cannot be joined again from \
                 here; accept a new invite to it",
            )
        } else {
            None
        };
        if let Some(message) = needs_person {
            if marked.contains(&folder.local_path) {
                continue;
            }
            // Persisted before the journal is cleared: the report alone is gone after a restart.
            // A mark that cannot be written keeps the journal, so running this again retries it.
            let message = match ports.mark_not_rejoined(&folder).await {
                Ok(()) => {
                    marked.push(folder.local_path.clone());
                    // Superseded by now, whatever stage this run started from.
                    write_journal(
                        dir,
                        &Journal {
                            stage: Stage::Superseded,
                            marked: marked.clone(),
                            ..journal.clone()
                        },
                    )?;
                    message.to_owned()
                }
                Err(error) => {
                    report.complete = false;
                    format!("{message}; it could not be marked as needing action: {error}")
                }
            };
            report.not_rejoined.push(RejoinFailure {
                local_path: folder.local_path,
                group_id: folder.group_id,
                message,
            });
            continue;
        }
        let Some((_, group_name)) = names.iter().find(|(id, _)| *id == folder.group_id) else {
            continue;
        };
        let joined = match ports.rejoin(&folder, group_name).await {
            Ok(()) if folder.on_demand && unconfirmed.contains(&folder.group_id) => {
                ports.promote_to_eager(&folder, group_name).await
            }
            other => other,
        };
        match joined {
            Ok(()) => report.rejoined.push(folder.local_path),
            Err(error) => {
                report.complete = false;
                report.not_rejoined.push(RejoinFailure {
                    local_path: folder.local_path,
                    group_id: folder.group_id,
                    message: error.to_string(),
                });
            }
        }
    }
    Ok(report)
}

/// The real machine: the control socket, the credential store and the coordination service.
/// `launch` is how every daemon restart and start of this start over brings the daemon up: the
/// host's choice (`CoreConfig::daemon_launch`), or `ops::daemon::default_launch()` for the CLI.
pub struct MachinePorts {
    pub launch: crate::dto::DaemonLaunch,
}

impl StartOverPorts for MachinePorts {
    fn state_dir(&self) -> Result<PathBuf, CoreError> {
        Ok(crate::coordination::device_config::config_dir()?)
    }

    async fn database_restored(&self) -> Result<bool, CoreError> {
        let status = crate::ops::folders::status().await?;
        Ok(status.attention_reasons.iter().any(|reason| reason.starts_with("database_restored")))
    }

    fn registered_device_id(&self) -> Option<String> {
        crate::ops::shares::own_device_id()
    }

    fn installation_id(&self) -> Result<Option<String>, CoreError> {
        Ok(crate::coordination::credential_store::installation()?
            .map(|credentials| credentials.client_id().to_owned()))
    }

    async fn sign_out(&self) -> Result<(), CoreError> {
        // The key-mirror cleanup warning is dropped on purpose: the retired identity is already
        // revoked, and the new device key is written over the same keyring entry right after.
        crate::ops::auth::sign_out().await.map(|_| ())
    }

    fn replace_signing_key(&self, key: &Path, retired_key: &Path) -> Result<(), CoreError> {
        yadorilink_transport::DeviceSigningKeyPair::replace_retiring(
            key,
            retired_key,
            crate::coordination::credential_store::key_mirror(),
        )
        .map(|_| ())
        .map_err(|e| CoreError::Other(e.to_string()))
    }

    async fn restart_daemon_if_running(&self) -> Result<(), CoreError> {
        crate::ops::daemon::restart_if_running_with(&self.launch).await
    }

    async fn ensure_daemon_running(&self) -> Result<(), CoreError> {
        crate::ops::daemon::start_daemon_with(&self.launch).await.map(|_| ())
    }

    async fn register(&self, name: String) -> Result<String, CoreError> {
        crate::ops::devices::register_device(name, &self.launch).await
    }

    async fn supersede(
        &self,
        retired_device_id: &str,
        new_device_id: &str,
    ) -> Result<SupersedeResponse, SupersedeError> {
        crate::ops::device_supersede::supersede_device(retired_device_id, new_device_id).await
    }

    async fn linked_folders(&self) -> Result<Vec<LinkedFolder>, CoreError> {
        Ok(crate::ops::links::list_links()
            .await?
            .into_iter()
            .map(|link| LinkedFolder {
                on_demand: link.materialization_policy != "eager",
                local_path: link.local_path,
                group_id: link.group_id,
            })
            .collect())
    }

    async fn joinable_group_names(&self) -> Result<Vec<(String, String)>, CoreError> {
        Ok(crate::ops::shares::list_joinable_groups()
            .await?
            .into_iter()
            .map(|group| (group.group_id, group.name))
            .collect())
    }

    async fn rejoin(&self, folder: &LinkedFolder, group_name: &str) -> Result<(), CoreError> {
        crate::ops::shares::join_resolved_with_outcome(
            folder.group_id.clone(),
            group_name.to_owned(),
            PathBuf::from(&folder.local_path),
            folder.on_demand,
            // The folder is already linked and holds this machine's own files.
            true,
        )
        .await
        .map(|_| ())
    }

    async fn promote_to_eager(
        &self,
        folder: &LinkedFolder,
        group_name: &str,
    ) -> Result<(), CoreError> {
        crate::ops::shares::set_storage_mode_resolved(folder.group_id.clone(), false, group_name)
            .await
            .map(|_| ())
    }

    async fn mark_not_rejoined(&self, folder: &LinkedFolder) -> Result<(), CoreError> {
        crate::ops::links::mark_not_rejoined(&folder.local_path).await
    }
}

#[cfg(test)]
mod tests;
