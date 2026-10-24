//! [`ClientCore`]: the product facade a desktop front end drives.
//!
//! Every method returns product types ([`crate::dto`]) and fails only with
//! [`DesktopError`]. The methods are thin: each calls the typed operation in
//! [`crate::ops`] and converts its result with the pure functions in
//! [`crate::dto`]. They need a Tokio runtime, and every future is `Send`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::coordination::credential_store;
use crate::dto::{
    self, AccountStatus, BrowserPurpose, CoreConfig, FolderDetail, LoginEvent, LoginFlow,
    LoginOptions, SignInState, StatusSnapshot, StatusUpdate,
};
use crate::error::{CoreError, DesktopError};
use crate::ops;
use crate::session::{LoginEventSink, LoginSession, StatusPollFn, StatusWatch};

mod folders;
mod rewind;
mod settings;
mod sharing;

/// The product facade. Holds only its configuration; every call reads the
/// current daemon and credential state.
pub struct ClientCore {
    config: CoreConfig,
}

/// The poll interval a front end uses unless it has a reason not to.
pub const DEFAULT_STATUS_INTERVAL: Duration = Duration::from_secs(2);

impl ClientCore {
    /// Performs no I/O.
    #[must_use]
    pub fn new(config: CoreConfig) -> Arc<Self> {
        Arc::new(ClientCore { config })
    }

    #[must_use]
    pub fn config(&self) -> &CoreConfig {
        &self.config
    }

    /// The engine API version this library speaks (the one the engine identity file pins). The
    /// running daemon's is `StatusSnapshot::engine_api_version`; a shell that finds them unequal
    /// has a mixed install.
    #[must_use]
    pub fn engine_api_version(&self) -> u32 {
        yadorilink_ipc_proto::PROVIDER_HOST_API_VERSION
    }

    // ---- session and identity ------------------------------------------------

    /// Sign-in, registration and linked-folder state, as a value: never fails.
    pub async fn account_status(&self) -> AccountStatus {
        account_status().await
    }

    /// A sign-in that has not started yet; see [`LoginSession`].
    #[must_use]
    pub fn new_login_session(&self, options: LoginOptions) -> Arc<LoginSession> {
        let device = options.flow == LoginFlow::DeviceCode;
        Arc::new(LoginSession::with_flow(
            options,
            Box::new(|| ops::auth::ensure_not_enrolled().map_err(DesktopError::from)),
            Box::new(move |sink| Box::pin(sign_in(device, sink))),
        ))
    }

    /// A sign-in of THIS installation, for an action the server refused with
    /// `PermissionDenied{ReauthenticationRequired}` (account deletion). Read
    /// and cancelled exactly like [`Self::new_login_session`]; it keeps the
    /// installation's identity and device, and a front end retries the refused
    /// action after `SignedIn`.
    #[must_use]
    pub fn new_reauthentication_session(&self, options: LoginOptions) -> Arc<LoginSession> {
        let device = options.flow == LoginFlow::DeviceCode;
        Arc::new(LoginSession::with_flow(
            options,
            Box::new(|| {
                if credential_store::installation()?.is_none() {
                    return Err(DesktopError::from(CoreError::NotLoggedIn));
                }
                Ok(())
            }),
            Box::new(move |sink| Box::pin(step_up(device, sink))),
        ))
    }

    /// Revokes this installation on the server, then removes its credential.
    ///
    /// # Errors
    /// The credential is kept, and the error says why, whenever the
    /// revocation could not be confirmed.
    pub async fn sign_out(&self) -> Result<dto::SignOutOutcome, DesktopError> {
        let report = ops::auth::sign_out().await?;
        let kind = match report.kind {
            ops::auth::SignOutKind::Revoked { grants_revoked } => {
                dto::SignOutKind::Revoked { grants_revoked }
            }
            ops::auth::SignOutKind::AlreadyRevoked => dto::SignOutKind::AlreadyRevoked,
            ops::auth::SignOutKind::ConfirmedRevokedAfterRejection => {
                dto::SignOutKind::ConfirmedRevokedAfterRejection
            }
        };
        Ok(dto::SignOutOutcome { kind, key_cleanup_warning: report.key_cleanup_warning })
    }

    /// # Errors
    /// `NotSignedIn` before sign-in; coordination failures otherwise.
    pub async fn register_device(
        &self,
        name: String,
    ) -> Result<dto::DeviceRegistration, DesktopError> {
        let device_id = ops::devices::register_device(name, &self.machine_ports().launch).await?;
        Ok(dto::DeviceRegistration { device_id })
    }

    /// The real machine, restarting and starting the daemon with this core's launch.
    fn machine_ports(&self) -> ops::start_over::MachinePorts {
        ops::start_over::MachinePorts { launch: self.config().daemon_launch.clone() }
    }

    /// Starts over as a new device after the replica database was restored or copied, or
    /// continues a start over that is under way: the way out of the `database_restored` attention
    /// item (its action is `ProductAction::StartOverAsNewDevice`).
    ///
    /// The first call needs `confirmed`: this computer becomes a new device, its old device stays
    /// on the account signed out, and its files are kept and joined again by the new device. It
    /// is refused, with nothing changed, unless the daemon reports the database as restored at
    /// that moment. It signs this computer out, retires the old identity and returns
    /// `SignInRequired`. After signing in, the next call registers `name` as a new device and
    /// joins every linked folder again in its storage mode; it needs no confirmation.
    ///
    /// # Errors
    /// `Refused { StartOverNotConfirmed | DatabaseNotRestored }` before anything changes;
    /// `DaemonUnavailable` when the condition cannot be checked; coordination failures otherwise.
    pub async fn start_over_as_new_device(
        &self,
        confirmed: bool,
        name: String,
    ) -> Result<dto::StartOverProgress, DesktopError> {
        let progress = ops::start_over::start_over(&self.machine_ports(), confirmed, name).await?;
        Ok(dto::start_over_progress(progress))
    }

    /// Records that the person acknowledged that changes made after the backup may be missing,
    /// which lets the daemon confirm a waiting replacement once every folder is complete here
    /// (the attention item `replacement_unconfirmed_acknowledgement_required`). Call it only
    /// from an explicit user action ("Acknowledge and finish"); nothing confirms on its own.
    /// `Ok(false)` when no replacement is waiting. Idempotent.
    ///
    /// # Errors
    /// The replacement record could not be read or written (nothing is acknowledged).
    pub async fn acknowledge_possible_loss(&self) -> Result<bool, DesktopError> {
        Ok(ops::start_over::acknowledge_possible_loss()?)
    }

    // ---- status ------------------------------------------------------------------

    /// # Errors
    /// `DaemonUnavailable` when the daemon cannot be asked.
    pub async fn status_snapshot(&self) -> Result<StatusSnapshot, DesktopError> {
        status_snapshot().await
    }

    /// Starts the status poll loop on the current runtime; see
    /// [`StatusWatch`].
    #[must_use]
    pub fn watch_status(&self, interval: Duration) -> Arc<StatusWatch> {
        let poll: StatusPollFn = Arc::new(|| {
            Box::pin(async {
                match status_snapshot().await {
                    Ok(snapshot) => StatusUpdate::Snapshot { snapshot },
                    Err(error) => StatusUpdate::Unavailable { error },
                }
            })
        });
        Arc::new(StatusWatch::start(poll, interval))
    }

    /// # Errors
    /// `InvalidInput{field: "local_path"}` when no folder is linked there.
    pub async fn folder_detail(&self, local_path: String) -> Result<FolderDetail, DesktopError> {
        let status = ops::folders::status().await?;
        dto::folder_detail(&status, &local_path).ok_or_else(|| {
            DesktopError::invalid_input(
                format!("no folder is linked at {local_path}"),
                "local_path",
            )
        })
    }

    /// Other devices with access to each linked folder's group, keyed by
    /// group id. One coordination call per distinct group.
    ///
    /// # Errors
    /// Daemon or coordination failures.
    pub async fn folder_peer_counts(&self) -> Result<HashMap<String, u32>, DesktopError> {
        let memberships = folder_memberships().await?;
        let counts = yadorilink_product_view::peer_counts(
            memberships.iter().map(|(group, members)| (group.as_str(), members.as_slice())),
            ops::shares::own_device_id().as_deref(),
        );
        Ok(counts
            .into_iter()
            .map(|(group, count)| (group, u32::try_from(count).unwrap_or(u32::MAX)))
            .collect())
    }
}

async fn account_status() -> AccountStatus {
    account_status_with(linked_folders().await)
}

/// Whether any folder is linked here; `None` when the daemon cannot say.
async fn linked_folders() -> Option<bool> {
    ops::links::list_links().await.ok().map(|links| !links.is_empty())
}

/// The account state, with the daemon's answer already in hand. No await:
/// the sign-in flow builds its result with this in the same step as its
/// credential write.
fn account_status_with(has_linked_folders: Option<bool>) -> AccountStatus {
    account_status_from(
        credential_store::installation(),
        ops::shares::own_device_id(),
        crate::coordination::device_config::config_dir()
            .is_ok_and(|dir| ops::start_over::pending_in(&dir)),
        has_linked_folders,
        desktop_device_name(),
    )
}

/// [`ClientCore::account_status`] for the state directory `dir`, for a host that names its
/// directory instead of leaving it to the environment. `has_linked_folders` is the host's own
/// answer (this layer does not ask a daemon).
#[must_use]
pub fn account_status_in(
    dir: &std::path::Path,
    settings: &credential_store::CredentialSettings,
    has_linked_folders: Option<bool>,
) -> AccountStatus {
    account_status_from(
        credential_store::installation_in(dir, settings),
        crate::coordination::device_config::load_in(dir).ok().map(|config| config.device_id),
        ops::start_over::pending_in(dir),
        has_linked_folders,
        // The host's own name for the machine; no environment or process is consulted.
        settings
            .host_name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .unwrap_or("My Device")
            .to_owned(),
    )
}

fn account_status_from(
    installation: Result<Option<yadorilink_fapi_client::store::Credentials>, CoreError>,
    this_device_id: Option<String>,
    start_over_pending: bool,
    has_linked_folders: Option<bool>,
    default_device_name: String,
) -> AccountStatus {
    let (sign_in, client_id) = match installation {
        Ok(Some(credentials)) => (SignInState::SignedIn, Some(credentials.client_id().to_owned())),
        Ok(None) => (SignInState::SignedOut, None),
        Err(e) => (SignInState::CredentialStoreUnusable { message: e.to_string() }, None),
    };
    AccountStatus {
        sign_in,
        client_id,
        device_registered: this_device_id.is_some(),
        this_device_id,
        default_device_name,
        has_linked_folders,
        start_over_pending,
    }
}

/// A prefill for the device-name field on the desktop: the machine's name from the environment
/// or the `hostname` command, else a generic one. An embedded host gives its own
/// (`CredentialSettings::host_name`).
fn desktop_device_name() -> String {
    for var in ["COMPUTERNAME", "HOSTNAME", "HOST"] {
        if let Ok(value) = std::env::var(var) {
            if !value.trim().is_empty() {
                return value.trim().to_owned();
            }
        }
    }
    if let Ok(output) = std::process::Command::new("hostname").output() {
        let name = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if output.status.success() && !name.is_empty() {
            return name;
        }
    }
    "My Device".to_owned()
}

/// The real sign-in flow: the client layer's enrolment and login, with each
/// step passed on as a product event.
///
/// Nothing is awaited after the login's credential write: the write and the
/// flow's completion happen in one poll, and the session's gate makes a cancel
/// wait for a poll in flight and forbid the next, so a flow that has written is
/// reported as signed in and a cancelled one writes nothing. The daemon is
/// therefore asked about linked folders before the login starts.
/// A sign-in over the state directory `dir`: the same flow as
/// [`ClientCore::new_login_session`], with the credential store and every record it writes in
/// that directory.
#[must_use]
pub fn new_login_session_in(
    dir: PathBuf,
    settings: credential_store::CredentialSettings,
    options: LoginOptions,
) -> Arc<LoginSession> {
    let device = options.flow == LoginFlow::DeviceCode;
    let precheck_dir = dir.clone();
    let precheck_settings = settings.clone();
    Arc::new(LoginSession::with_flow(
        options,
        Box::new(move || {
            ops::auth::ensure_not_enrolled_in(&precheck_dir, &precheck_settings)
                .map_err(DesktopError::from)
        }),
        Box::new(move |sink| {
            Box::pin(async move {
                ops::auth::login_in(&dir, &settings, device, |event| {
                    if let Some(event) = login_event(event) {
                        sink.send(event);
                    }
                })
                .await?;
                Ok(account_status_in(&dir, &settings, None))
            })
        }),
    ))
}

/// A step-up sign-in over the state directory `dir`: the same flow as
/// [`ClientCore::new_reauthentication_session`], with the credential store in that directory
/// and the host's settings.
#[must_use]
pub fn new_reauthentication_session_in(
    dir: PathBuf,
    settings: credential_store::CredentialSettings,
    options: LoginOptions,
) -> Arc<LoginSession> {
    let device = options.flow == LoginFlow::DeviceCode;
    let precheck_dir = dir.clone();
    let precheck_settings = settings.clone();
    Arc::new(LoginSession::with_flow(
        options,
        Box::new(move || {
            if credential_store::installation_in(&precheck_dir, &precheck_settings)?.is_none() {
                return Err(DesktopError::from(CoreError::NotLoggedIn));
            }
            Ok(())
        }),
        Box::new(move |sink| {
            Box::pin(async move {
                ops::auth::reauthenticate_in(&dir, &settings, device, |event| {
                    if let Some(event) = login_event(event) {
                        sink.send(event);
                    }
                })
                .await?;
                Ok(account_status_in(&dir, &settings, None))
            })
        }),
    ))
}

async fn sign_in(device: bool, sink: LoginEventSink) -> Result<AccountStatus, DesktopError> {
    let has_linked_folders = linked_folders().await;
    ops::auth::login(device, |event| {
        if let Some(event) = login_event(event) {
            sink.send(event);
        }
    })
    .await?;
    Ok(account_status_with(has_linked_folders))
}

/// The step-up sign-in: [`ops::auth::reauthenticate`] with each step passed on
/// as a product event.
async fn step_up(device: bool, sink: LoginEventSink) -> Result<AccountStatus, DesktopError> {
    let has_linked_folders = linked_folders().await;
    ops::auth::reauthenticate(device, |event| {
        if let Some(event) = login_event(event) {
            sink.send(event);
        }
    })
    .await?;
    Ok(account_status_with(has_linked_folders))
}

/// The product form of one sign-in step. The client layer's own `SignedIn`
/// is dropped: the session reports the terminal event itself.
fn login_event(event: ops::auth::LoginEvent) -> Option<LoginEvent> {
    use ops::auth::LoginEvent as Step;
    Some(match event {
        Step::Enrolling => LoginEvent::Enrolling,
        Step::OpenBrowser { url, purpose } => LoginEvent::OpenBrowser {
            url,
            purpose: match purpose {
                ops::auth::BrowserPurpose::ApproveDevice => BrowserPurpose::ApproveDevice,
                ops::auth::BrowserPurpose::SignIn => BrowserPurpose::SignIn,
            },
        },
        Step::WaitingForApproval { expires_in } => LoginEvent::WaitingForApproval { expires_in },
        Step::WaitingForAuthorization => LoginEvent::WaitingForAuthorization,
        // The link to open is the one with the code filled in when the server offered it; the
        // code is still shown so the person can check it against the page.
        Step::ShowDeviceCode { verification_uri, verification_uri_complete, user_code } => {
            LoginEvent::ShowDeviceCode {
                verification_uri: verification_uri_complete.unwrap_or(verification_uri),
                user_code,
            }
        }
        Step::SignedIn { .. } => return None,
    })
}

async fn status_snapshot() -> Result<StatusSnapshot, DesktopError> {
    let status = ops::folders::status().await?;
    let account = account_status_with(Some(!status.links.is_empty()));
    Ok(dto::status_snapshot(&status, account, SystemTime::now()))
}

/// Each linked folder group's member list, fetched once per group.
async fn folder_memberships(
) -> Result<Vec<(String, Vec<yadorilink_product_view::DeviceSummary>)>, CoreError> {
    let links = ops::links::list_links().await?;
    let mut out = Vec::new();
    for group_id in yadorilink_product_view::distinct_group_ids(&links) {
        let members = ops::shares::list_members_resolved(&group_id)
            .await?
            .into_iter()
            .map(|m| yadorilink_product_view::DeviceSummary {
                device_id: m.device_id,
                display_name: m.device_name,
                online: m.online,
                last_seen_unix: m.last_seen_unix,
                is_caller_account: m.is_caller_account,
            })
            .collect();
        out.push((group_id, members));
    }
    Ok(out)
}

/// A path a person picked, resolved the way the link preflight resolves it.
fn existing_directory(local_path: &str) -> Result<PathBuf, DesktopError> {
    std::fs::canonicalize(local_path).map_err(|_| {
        DesktopError::invalid_input(format!("no such directory: {local_path}"), "local_path")
    })
}

/// Names the argument an `InvalidInput` refusal is about.
fn about(field: &str) -> impl FnOnce(CoreError) -> DesktopError + '_ {
    move |error| match DesktopError::from(error) {
        DesktopError::InvalidInput { message, field: None } => {
            DesktopError::InvalidInput { message, field: Some(field.to_owned()) }
        }
        other => other,
    }
}

/// For the operations that accept a `force` override: a durability refusal
/// of a call without it offers the override.
fn offering_force(force: bool) -> impl FnOnce(CoreError) -> DesktopError {
    move |error| DesktopError::from_core(error, !force)
}

#[cfg(test)]
mod tests;
