//! What a client operation can fail with.
//!
//! [`CoreError`] is lossless: it keeps every category a front end needs to
//! choose an exit code, a banner or a retry, and carries the daemon's typed
//! command errors instead of flattening them to text. Each front end maps it
//! onto its own presentation (the command-line tool keeps its historical
//! messages and exit codes); nothing here decides how an error is shown.

use yadorilink_fapi_client::store::StoreError;
use yadorilink_ipc_proto::daemonctl::{ApplicationCommandError, ApplicationErrorCode};

/// Which coordination-plane limit a [`CoreError::LimitExceeded`] hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitKind {
    /// A per-account quota (`quota_exceeded`): remove something first, or
    /// ask an operator to raise the ceiling.
    Quota,
    /// An abuse budget (`rate_limited`): wait and retry. `retry_after_secs` is the service's own
    /// wait when it gave one.
    RateLimited { retry_after_secs: Option<u64> },
}

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// Nobody has signed in on this machine.
    #[error("not signed in")]
    NotLoggedIn,

    /// A credential store that exists and cannot be used. Deliberately not
    /// folded into [`CoreError::NotLoggedIn`]: signing in again would succeed
    /// and leave the damaged store in place, so the remedy is the store, and
    /// the store's own message names it.
    #[error("{0}")]
    CredentialStore(#[from] StoreError),

    /// The coordination plane (or the Authorization Server) refused this
    /// installation's session.
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    /// The coordination plane answered 401 `device_superseded`: this device was replaced by a
    /// newer one and can never sign in again. Unlike [`CoreError::AuthFailed`], signing in again
    /// on this installation does not help; the device has to be set up afresh or retired.
    #[error("this device was replaced by another device and can no longer sign in")]
    DeviceSuperseded,

    /// The Authorization Server refused to refresh this installation's session with
    /// `invalid_grant`. After a change of the Terms this is how it refuses every grant of an
    /// account without current consent; a revoked grant answers the same way. The stored
    /// sign-in is kept, and signing in again as this installation is the remedy.
    #[error("sign-in required (the Terms may have changed); sign in again to continue")]
    SignInRequired,

    /// The coordination plane answered 403 `terms_consent_required`: the account has not
    /// accepted the current Terms. Nothing about the installation or its device changes; signing
    /// in again (the browser shows the consent screen) is the remedy.
    #[error("the Terms must be accepted to continue; sign in again to review and accept them")]
    TermsConsentRequired { terms_version: Option<String> },

    /// A sign-in on this installation was made with a different account than the one this
    /// installation belongs to. Nothing was changed; sign in with the original account.
    #[error(
        "that sign-in is for a different account than the one this computer belongs to; sign in \
         with the original account"
    )]
    AccountMismatch,

    /// The service did not accept the pairing code of "add this device with a code": it was
    /// never issued, has expired (ten minutes) or was used already. The service answers all
    /// three alike, so this does too. Nothing was changed; a new code is made on the account's
    /// web page.
    #[error("The code is invalid, expired or already used: create a new code on the web page")]
    PairingCodeRefused,

    /// The coordination plane refused a primary-ownership transfer call with a typed reason
    /// (`primary_transfer_refused`), or answered 404 for the group or offer. Nothing changed.
    #[error("{0}")]
    PrimaryTransferRefused(PrimaryTransferRefusal),

    /// The coordination plane answered 403: the session is valid but not
    /// allowed to do this.
    #[error("{0}")]
    Forbidden(String),

    /// The coordination plane answered 403 `reauthentication_required`: the
    /// action needs a sign-in made in the last few minutes. Signing in again as
    /// this installation (see `ops::auth::reauthenticate`) and retrying is the
    /// remedy; nothing about the installation or its device changes.
    #[error("this needs a fresh sign-in; sign in again to continue")]
    ReauthenticationRequired,

    #[error("could not reach the coordination plane: {0}")]
    CoordinationPlaneUnreachable(String),

    /// A quota or rate limit was hit; user-actionable rather than an outage.
    #[error("{message}")]
    LimitExceeded { message: String, kind: LimitKind },

    #[error("the yadorilink daemon is not running")]
    DaemonNotRunning,

    /// The daemon's control socket did not accept, or a quick request got no
    /// answer, within its deadline: the daemon is running but wedged.
    #[error("yadorilink daemon is not responding")]
    DaemonUnresponsive,

    /// The daemon speaks a different control-protocol generation. Pre-release
    /// binaries are one release unit, so this is refused rather than decoded
    /// with protobuf's missing-field defaults.
    #[error(
        "client/daemon protocol version mismatch (client {client}, daemon {daemon}); run matching \
         YadoriLink binaries"
    )]
    DaemonProtocolMismatch { client: u32, daemon: u32 },

    /// This program and the running daemon do not come from the same release (or this program's
    /// own release descriptor is unusable), so a state-changing request was not sent. `message`
    /// names what differs and which updater fixes it; `daemon_api` is what the daemon reported.
    #[error("{message}")]
    EngineMismatch { message: String, detail: EngineMismatchDetail },

    /// The daemon answered the request with a plain error message.
    #[error("{0}")]
    DaemonRejected(String),

    /// Another owner (the app, or another install) manages the daemon of this data area, or the
    /// owner cannot be told. Nothing was started. Distinct from a failure: the person is told who
    /// to ask instead.
    #[error("{0}")]
    ManagedElsewhere(String),

    /// The daemon refused an application command with a typed error. This
    /// is the only form of every daemon command refusal, including a create
    /// or join whose activation could not be confirmed
    /// (`ApplicationErrorCode::ActivationAmbiguous`, which the daemon's
    /// reconciliation sweep resolves): match on `code`.
    #[error("{message}")]
    DaemonCommand {
        code: ApplicationErrorCode,
        message: String,
        group_ids: Vec<String>,
        operation_id: Option<String>,
        /// Set with `ApplicationErrorCode::UnsupportedDrive`.
        drive: Option<UnsupportedDrive>,
    },

    /// The operation would leave a folder group without a confirmed-ready
    /// full replica, and was refused before anything changed.
    #[error("{message}")]
    DurabilityBlocked { message: String, group_ids: Vec<String> },

    /// An argument was refused before any request was made.
    #[error("{0}")]
    InvalidInput(String),

    /// The state directory (or a path configured away from it) may not be used by this process;
    /// nothing was created. The desktop sees it as `Refused { StateDirUnusable }`.
    #[error("{0}")]
    StatePlacement(#[from] yadorilink_fs_platform::state_dir::StateDirError),

    /// Starting over as a new device was refused before anything changed.
    #[error("{0}")]
    StartOverRefused(StartOverRefusal),

    #[error("{0}")]
    Io(String),

    /// An argument value this layer refuses before any request. The text names the argument
    /// without a flag; a front end that spells it as an option does so from the argument.
    #[error("{0}")]
    InvalidArgument(InvalidArgument),

    #[error("{0}")]
    Other(String),

    /// An error whose own text is host-neutral, plus what the person can do next as a typed
    /// [`Hint`]. The text never names a command: each host words the hint for its own surface
    /// (the command line prints the command, a GUI offers its own action). `error` keeps its
    /// category: the command line's exit code is that of `error`, and so is the desktop reason,
    /// except that a daemon hint (`StartDaemon`, `WaitThenStartDaemon`, `StopThenStartDaemon`)
    /// reaches a desktop front end as `DaemonUnavailable { StartNeeded }`. Match a category with
    /// [`CoreError::into_unhinted`].
    #[error("{error}")]
    Hinted { error: Box<CoreError>, hint: Hint },
}

/// Why the coordination plane refused a primary-ownership transfer call. Typed by the plane's
/// `reason`, never matched by text; the text here is host-neutral diagnostic English.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimaryTransferRefusal {
    /// The caller's account is not the folder's primary owner.
    NotPrimary,
    /// The chosen device is not an active member of the folder.
    TargetNotMember,
    /// The chosen device belongs to the caller's own account: nothing to hand over.
    TargetSameAccount,
    /// The offer lapsed (offers last seven days).
    OfferExpired,
    /// The folder is being created, handed off or deleted right now.
    GroupNotActive,
    /// The offer was already settled or replaced, another offer is pending, the folder changed
    /// owner, or the folder kept changing while the call ran.
    Conflict,
    /// No such folder or offer, or the caller is not a party to it.
    NotFound,
}

impl PrimaryTransferRefusal {
    /// The refusal the plane's `reason` names; `None` for a reason this build does not know.
    #[must_use]
    pub fn from_reason(reason: &str) -> Option<Self> {
        Some(match reason {
            "not_primary" => Self::NotPrimary,
            "target_not_member" => Self::TargetNotMember,
            "target_same_account" => Self::TargetSameAccount,
            "offer_expired" => Self::OfferExpired,
            "group_not_active" => Self::GroupNotActive,
            "conflict" | "operation_conflict" => Self::Conflict,
            _ => return None,
        })
    }

    /// The plane's `reason` word (`not_found` for the 404 case).
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::NotPrimary => "not_primary",
            Self::TargetNotMember => "target_not_member",
            Self::TargetSameAccount => "target_same_account",
            Self::OfferExpired => "offer_expired",
            Self::GroupNotActive => "group_not_active",
            Self::Conflict => "conflict",
            Self::NotFound => "not_found",
        }
    }
}

impl std::fmt::Display for PrimaryTransferRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotPrimary => "only the folder's primary owner can do this",
            Self::TargetNotMember => "that device is not an active member of this folder",
            Self::TargetSameAccount => {
                "that device is on your own account: choose a device of another person"
            }
            Self::OfferExpired => "the ownership offer has expired",
            Self::GroupNotActive => {
                "the folder is being set up, handed off or removed right now; try again shortly"
            }
            Self::Conflict => {
                "an ownership offer is already pending, this one was already settled or replaced, or \
                 the folder changed while this ran; check the pending offers and try again"
            }
            Self::NotFound => "no such folder or ownership offer for this account",
        })
    }
}

/// An argument value refused before any request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidArgument {
    /// Not a storage mode (`eager` or `on-demand`).
    StorageMode(String),
    /// Not a role a role change may move a member to.
    Role(String),
}

impl InvalidArgument {
    /// The argument's name as a desktop field.
    #[must_use]
    pub fn field(&self) -> &'static str {
        match self {
            InvalidArgument::StorageMode(_) => "storage_mode",
            InvalidArgument::Role(_) => "role",
        }
    }
}

impl std::fmt::Display for InvalidArgument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidArgument::StorageMode(value) => {
                write!(f, "invalid storage mode {value:?} (expected eager or on-demand)")
            }
            InvalidArgument::Role(value) => {
                write!(f, "invalid role {value:?} (expected viewer, editor or owner)")
            }
        }
    }
}

/// What a person can do next about a failure, as an action rather than a command line. Hosts
/// map it to their own wording; client-core texts never spell a host's commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hint {
    /// The daemon is not running or did not answer: start it.
    StartDaemon,
    /// The old daemon is still exiting, so the new one cannot start yet: wait, then start it.
    WaitThenStartDaemon,
    /// The running daemon did not stop: stop it, then start it.
    StopThenStartDaemon,
    /// This installation is already enrolled: sign out first to enrol again, or remove the
    /// leftover sign-in of a removed data directory from this computer.
    AlreadyEnrolled,
    /// A sign-in did not arrive in time: start it again.
    SignInAgain,
    /// Signed in, but this computer is not registered as a device yet: register it.
    RegisterDevice,
    /// No folder group of that name is visible: create one or accept an invitation to one.
    CreateOrAcceptShare,
    /// No joinable folder group of that name: list what the account can join.
    ListJoinableShares,
    /// An unlink was refused to protect the group's data: it can be done anyway, accepting the
    /// risk of losing the only complete copy.
    ForceUnlink,
    /// A folder is still being set up: check its sync status.
    CheckLinkStatus,
    /// What is linked is uncertain: check the linked folders and the daemon log.
    CheckLinkList,
    /// A provider-folder item downloads when opened; keeping it on this device downloads it now.
    KeepItemOnDevice,
    /// A provider-folder item's local state is held by the operating system: see it there and
    /// see the folder's download progress.
    ShowProviderLocalState,
    /// Only a provider folder can be on-demand: create one.
    CreateProviderFolder,
    /// Submitting a report needs its type enabled in the reporting consent settings.
    EnableReportSubmission,
    /// A hand-off of the data area to the app was interrupted: finish it or roll it back.
    FinishOrRollBackHandoff,
    /// A storage-mode change was refused for now: try it again.
    RetryStorageModeChange,
    /// Another command-line install owns the data area: use that install and its own updater.
    UseOwningInstall,
}

impl Hint {
    /// The step a daemon refusal carries on the wire; an unset or unknown value is none.
    #[must_use]
    pub fn from_wire(next_step: i32) -> Option<Self> {
        use yadorilink_ipc_proto::daemonctl::NextStep;
        match NextStep::try_from(next_step).ok()? {
            NextStep::Unspecified => None,
            NextStep::CheckLinkStatus => Some(Hint::CheckLinkStatus),
            NextStep::CheckLinkList => Some(Hint::CheckLinkList),
            NextStep::KeepItemOnDevice => Some(Hint::KeepItemOnDevice),
            NextStep::ShowProviderLocalState => Some(Hint::ShowProviderLocalState),
            NextStep::CreateProviderFolder => Some(Hint::CreateProviderFolder),
            NextStep::EnableReportSubmission => Some(Hint::EnableReportSubmission),
            NextStep::RetryStorageModeChange => Some(Hint::RetryStorageModeChange),
        }
    }
}

impl CoreError {
    /// This error with the next step a host can offer.
    #[must_use]
    pub fn hinted(self, hint: Hint) -> Self {
        CoreError::Hinted { error: Box::new(self), hint }
    }

    /// This error without its hint, for a match on the category it wraps. A direct
    /// `match` on `CoreError::Other(..)` etc. does not see through [`CoreError::Hinted`].
    #[must_use]
    pub fn into_unhinted(self) -> Self {
        match self {
            CoreError::Hinted { error, .. } => error.into_unhinted(),
            other => other,
        }
    }

    /// This error with `context` put around its text as a plain failure, keeping the next step
    /// it carries (the inner hint goes outward; it is never spelled into the text and
    /// attached again). `fallback` is the hint when it carries none.
    #[must_use]
    pub fn with_context(
        self,
        context: impl FnOnce(&str) -> String,
        fallback: Option<Hint>,
    ) -> Self {
        let hint = self.hint().or(fallback);
        let wrapped = CoreError::Other(context(&self.to_string()));
        match hint {
            Some(hint) => wrapped.hinted(hint),
            None => wrapped,
        }
    }

    /// The next step attached to this error, if any.
    #[must_use]
    pub fn hint(&self) -> Option<Hint> {
        match self {
            CoreError::Hinted { hint, .. } => Some(*hint),
            _ => None,
        }
    }
}

/// Why starting over as a new device was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartOverRefusal {
    /// The caller did not confirm that this computer becomes a new device.
    NotConfirmed,
    /// The daemon does not report the replica database as restored or copied, so there is no
    /// identity to start over from. Nothing is changed.
    NotRestored,
    /// A start over is mid-way and the old signing key is not yet replaced: registering now would
    /// bind a new device to the key being retired. Finish the start over first.
    InProgress,
    /// A start over already finished on this engine, which still reports the database as
    /// refused because it has not been restarted since: starting over again now would retire the
    /// identity just registered. Restart the engine first. Nothing is changed.
    RestartRequired,
}

impl std::fmt::Display for StartOverRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConfirmed => f.write_str(
                "starting over makes this computer a new device: its old device stays on the \
                 account, signed out, and the files here are kept and synced again by the new \
                 device. Confirm to continue.",
            ),
            Self::NotRestored => f.write_str(
                "this computer's database is not reported as restored or copied, so there is \
                 nothing to start over from",
            ),
            Self::RestartRequired => f.write_str(
                "a start over already finished on this engine, which still shows the old state \
                 until it restarts: restart the engine (suspend and resume) before starting \
                 over again",
            ),
            Self::InProgress => f.write_str(
                "a start over as a new device is under way on this computer; finish it before \
                 registering",
            ),
        }
    }
}

impl CoreError {
    /// The typed form of a daemon application-command refusal. An error code
    /// this build does not know reads as `Unspecified` rather than failing.
    #[must_use]
    pub fn from_command_error(error: ApplicationCommandError) -> Self {
        // The Terms refusal is a sign-in, not a command failure: the same error the direct
        // coordination calls produce, so every front end words it once.
        if error.code == ApplicationErrorCode::TermsConsentRequired as i32 {
            return CoreError::TermsConsentRequired { terms_version: None };
        }
        CoreError::DaemonCommand {
            code: ApplicationErrorCode::try_from(error.code)
                .unwrap_or(ApplicationErrorCode::Unspecified),
            message: error.message,
            group_ids: error.group_ids,
            operation_id: (!error.operation_id.is_empty()).then_some(error.operation_id),
            drive: UnsupportedDrive::from_wire(error.drive_reason, error.file_system),
        }
    }

    /// Whether this is a daemon command refusal carrying `code`.
    #[must_use]
    pub fn is_command_error(&self, code: ApplicationErrorCode) -> bool {
        matches!(self, CoreError::DaemonCommand { code: actual, .. } if *actual == code)
    }
}

/// The credential manager's failures, classified.
///
/// `NotEnrolled` ("nobody has signed in here") and `Store` ("there is a
/// credential and it cannot be used") are kept apart because their remedies
/// are opposite. Everything a refresh can fail with lands under one of the two
/// remote categories rather than under `Other`.
impl From<yadorilink_fapi_client::Error> for CoreError {
    fn from(e: yadorilink_fapi_client::Error) -> Self {
        use yadorilink_fapi_client::Error as FapiError;
        match e {
            FapiError::NotEnrolled => CoreError::NotLoggedIn,
            FapiError::Store(store) => CoreError::CredentialStore(store),
            FapiError::Http(_) => CoreError::CoordinationPlaneUnreachable(e.to_string()),
            // A refused refresh is a refused session: the registration was
            // revoked, the refresh token was replayed and took the grant family
            // with it, or the clock is wrong. All three are answered by signing
            // in again, not by retrying.
            // A refresh the server refused with `invalid_grant` is its own case: the stored
            // sign-in is intact and the person is asked to sign in again.
            ref refused @ FapiError::Response { step: "refresh", .. }
                if refused.is_invalid_grant() =>
            {
                CoreError::SignInRequired
            }
            FapiError::Response { status: 400 | 401 | 403, .. } => {
                CoreError::AuthFailed(e.to_string())
            }
            // The abuse budget: wait (the service's own number when it gave one) and retry.
            FapiError::RateLimited { retry_after, .. } => CoreError::LimitExceeded {
                message: match retry_after {
                    Some(wait) => format!(
                        "Too many attempts from this network; wait {} seconds and try again",
                        wait.as_secs().max(1)
                    ),
                    None => "Too many attempts from this network; wait a minute and try again"
                        .to_owned(),
                },
                kind: LimitKind::RateLimited {
                    retry_after_secs: retry_after.map(|wait| wait.as_secs().max(1)),
                },
            },
            FapiError::Response { status: 429 | 500..=599, .. } => {
                CoreError::CoordinationPlaneUnreachable(e.to_string())
            }
            // The code the person was shown ran out before they approved it.
            FapiError::DeviceAuthorizationExpired => {
                CoreError::AuthFailed(format!("{e}; start the sign-in again"))
            }
            other => CoreError::Other(other.to_string()),
        }
    }
}

/// Daemon-connect failures are mapped to [`CoreError::DaemonNotRunning`] where the socket is
/// opened; any other I/O failure (a missing file, say) keeps its own message.
impl From<std::io::Error> for CoreError {
    fn from(e: std::io::Error) -> Self {
        CoreError::Io(e.to_string())
    }
}

impl From<serde_json::Error> for CoreError {
    fn from(e: serde_json::Error) -> Self {
        CoreError::Other(e.to_string())
    }
}

/// What differs between this app and the engine (daemon) it found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum EngineMismatchKind {
    /// The two speak different local control surface (engine API) versions.
    ApiVersion,
    /// The same engine API but different builds (release ids differ).
    Build,
    /// The app's own installation is unusable (its release descriptor is unreadable or mixes two
    /// builds), so no engine can be paired with it. The engine's data is still reported.
    AppInstallation,
}

/// Which side is behind. Only the engine API version is ordered; release ids are opaque, so a
/// differing build is `Unknown`. Never infer a direction from the release id or version text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum EngineMismatchDirection {
    /// The engine speaks an older engine API than the app: the engine needs updating.
    EngineOlder,
    /// The engine speaks a newer engine API than the app: the app needs updating.
    EngineNewer,
    Unknown,
}

/// The release descriptors of a mismatched pair. Public build facts only (versions and release
/// ids, no paths, no secrets). An empty release id means that side carries no engine identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineMismatchDetail {
    pub kind: EngineMismatchKind,
    pub direction: EngineMismatchDirection,
    pub app_version: String,
    pub engine_version: String,
    pub app_release_id: String,
    pub engine_release_id: String,
    pub app_api_version: u32,
    pub engine_api_version: u32,
}

/// Why the daemon could not be asked.
///
/// A shell built before a case existed cannot decode it (its bindings are generated from the
/// library it ships with and refuse a different one), so the pairing never arises with an older
/// shell. A shell that must degrade on a case it does not know reads it by what that case
/// asks: `EngineMismatch` as `ProtocolMismatch` (starting the engine again cannot help; the
/// remedy is an update), `StartNeeded` as `NotRunning` (the remedy is starting the engine).
/// Host code that switches on this enum needs an arm for each case before it adopts the
/// library that adds it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum DaemonUnavailableReason {
    NotRunning,
    /// Running but not answering in time: starting it again cannot help.
    Unresponsive,
    ProtocolMismatch {
        client_version: u32,
        daemon_version: u32,
    },
    /// The running engine does not come from the same release as this app (or the app's own
    /// installation is unusable); nothing was changed. Starting again cannot help: the app or the
    /// engine must be updated. Declared last so the other cases keep their wire order.
    EngineMismatch {
        kind: EngineMismatchKind,
        direction: EngineMismatchDirection,
        app_version: String,
        engine_version: String,
        app_release_id: String,
        engine_release_id: String,
        app_api_version: u32,
        engine_api_version: u32,
    },
    /// A start or restart of the engine was attempted and did not complete (a registration that
    /// could not restart it, a start that was not answered, a stop that did not finish). The host
    /// starts it its own way; `stop_first` says the old process must be stopped before. Declared
    /// last so the other cases keep their wire order.
    StartNeeded {
        stop_first: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum NetworkErrorKind {
    Unreachable,
    /// The service's abuse budget refused the request: wait, then retry. `retry_after_secs` is
    /// the service's own wait when it gave one; apps show it and never parse `message`.
    RateLimited {
        retry_after_secs: Option<u64>,
    },
    /// A create or join whose activation could not be confirmed; the daemon
    /// settles it on its own.
    ActivationPendingReconciliation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum PermissionDeniedReason {
    /// The coordination plane refused this installation's session; signing
    /// in again is the remedy.
    SessionRejected,
    /// The coordination plane reported that another device replaced this one; signing in again
    /// cannot restore it.
    DeviceSuperseded,
    /// The action needs a sign-in made in the last few minutes. Signing in
    /// again as this installation and retrying is the remedy.
    ReauthenticationRequired,
    Forbidden,
    QuotaExceeded,
    /// The credential store exists and cannot be used; signing in again
    /// would leave it damaged.
    CredentialStoreUnusable,
    /// The account has not accepted the current Terms (`403 terms_consent_required`). Sign in
    /// again as this installation (the step-up sign-in; the browser shows the consent screen);
    /// the installation, its device and its folders are kept and work again afterwards.
    TermsConsentRequired,
}

/// Why a drive cannot be synced into yet (`DesktopError::UnsupportedDrive`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum UnsupportedDriveReason {
    /// ReFS, including a Dev Drive.
    Refs,
    ExFat,
    /// FAT or FAT32.
    Fat,
    /// A network share or a removable drive.
    NotLocalFixed,
    /// Any other file system; the error's `file_system` names it.
    Other,
}

/// The drive of an unsupported-drive refusal: the machine reason and the file system's name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsupportedDrive {
    pub reason: UnsupportedDriveReason,
    pub file_system: String,
}

impl UnsupportedDrive {
    fn from_wire(reason: i32, file_system: String) -> Option<Self> {
        use yadorilink_ipc_proto::daemonctl::UnsupportedDriveReason as Wire;
        let reason = match Wire::try_from(reason).unwrap_or(Wire::Unspecified) {
            Wire::Unspecified => return None,
            Wire::Refs => UnsupportedDriveReason::Refs,
            Wire::Exfat => UnsupportedDriveReason::ExFat,
            Wire::Fat => UnsupportedDriveReason::Fat,
            Wire::NotLocalFixed => UnsupportedDriveReason::NotLocalFixed,
            Wire::Other => UnsupportedDriveReason::Other,
        };
        Some(Self { reason, file_system })
    }
}

/// What a daemon refusal of a link or an invite acceptance says, for a front
/// end to word in its own language.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum RefusalReason {
    /// The disk is full; nothing was linked.
    DiskFull,
    /// The folder is nested in, or around, another linked folder or the
    /// daemon's recovery area. No confirmation overrides this.
    PathNotAllowed,
    /// The system refused access to the folder (macOS privacy protection, a Windows
    /// ACL). Nothing was linked; allow access or pick another folder, then retry.
    AccessDenied,
    InviteExpired,
    /// Redeemed already, or cancelled.
    InviteAlreadyUsed,
    /// A file holds changes that are not recorded yet and the action would
    /// replace them. Nothing changed; try again once they are recorded.
    UnrecordedLocalChanges,
    /// The conflict copy is not one this action can resolve. Nothing changed.
    ConflictNotResolvable,
    /// This app may not keep its data where it is configured to (under AppData while packaged);
    /// nothing was created. The remedy is the configuration the message names.
    StateDirUnusable,
    /// Starting over as a new device needs the caller's confirmation. Nothing changed.
    StartOverNotConfirmed,
    /// The replica database is not reported as restored or copied, so there is no identity to
    /// start over from. Nothing changed.
    DatabaseNotRestored,
    /// A start over as a new device is mid-way; registering is refused until it is finished,
    /// because the signing key at hand is being retired. Nothing changed.
    StartOverInProgress,
    /// Another owner (the app, or another install) manages YadoriLink on this machine, or the
    /// owner cannot be told. Nothing was started; the message names who to use instead.
    ManagedElsewhere,
    /// The folder at the path now belongs to a different group than the caller named (it was
    /// unlinked and linked again, or replaced). Nothing changed; look the folder up again.
    GroupMismatch,
    /// A start over already finished on this embedded engine, which still reports the old state
    /// until the host restarts it; starting over again is refused until then. Nothing changed.
    StartOverRestartRequired,
    /// The send link is past its expiry. Only the link's sender can learn this (the service
    /// answers a redeemer's refusal alike for every cause; see `SendLinkInvalid`).
    SendLinkExpired,
    /// The send link was already used; a link works once. A sender learns this when sending
    /// under it.
    SendLinkAlreadyUsed,
    /// The sender cancelled the send link.
    SendLinkCancelled,
    /// The code is not accepted: mistyped, unknown, expired, used or cancelled. The service does
    /// not say which to someone redeeming, so a redeem refusal is always this one.
    SendLinkInvalid,
    /// The other device of a send could not be reached (when receiving: the sender's device).
    /// Trying again once it is online can succeed.
    SendPeerUnreachable,
    /// This device has no room for what is being received. Free space or pick another device.
    SendNoSpace,
    /// The send stopped part way: the connection was lost or it stopped without a clearer reason.
    SendInterrupted,
    /// The service has Send links switched off: none can be created, previewed or redeemed
    /// until it turns them on. Nothing was changed.
    SendLinksDisabled,
    /// This device's operating system refused to send to the local network (the macOS Local
    /// Network privacy setting, a firewall or a VPN), so a device on the same network could not
    /// be reached. A device reachable over the internet still can be; allowing the app in the
    /// system's local network settings fixes the rest.
    SendLocalNetworkBlocked,
    /// The pairing code of "add this device with a code" is not accepted: never issued, expired
    /// or already used (the service does not say which). Make a new code on the web page.
    /// Declared last so the other reasons keep their wire order.
    PairingCodeInvalid,
    /// Primary-ownership transfer refused by the service, one reason each (nothing changed): the
    /// caller is not the primary owner.
    PrimaryTransferNotPrimary,
    /// The chosen device is not an active member of the folder.
    PrimaryTransferTargetNotMember,
    /// The chosen device is on the caller's own account.
    PrimaryTransferTargetSameAccount,
    /// The offer lapsed.
    PrimaryTransferOfferExpired,
    /// The folder is being created, handed off or deleted.
    PrimaryTransferGroupNotActive,
    /// The offer was settled or replaced, or the folder changed owner or kept changing.
    PrimaryTransferConflict,
    /// No such folder or offer for this account.
    PrimaryTransferNotFound,
    /// The list of files in a Send link does not open with the link's code (altered, or sealed
    /// for another link), so it is not shown. The link itself is still valid and can be redeemed;
    /// say that the list could not be verified. Declared last so the other reasons keep their
    /// wire order.
    SendPreviewUnverified,
}

/// The one error a desktop front end sees. Eight cases, each with a typed
/// reason to branch on; `message` is diagnostic English for a details view
/// or tooltip, never primary copy.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "ffi", derive(uniffi::Error))]
pub enum DesktopError {
    #[error("{message}")]
    NotSignedIn { message: String },
    #[error("{message}")]
    DaemonUnavailable { message: String, reason: DaemonUnavailableReason },
    #[error("{message}")]
    Network { message: String, kind: NetworkErrorKind },
    #[error("{message}")]
    PermissionDenied { message: String, reason: PermissionDeniedReason },
    /// Refused because a folder group would be left without a confirmed
    /// complete copy. `can_force` says whether calling again with `force`
    /// is offered for this operation.
    #[error("{message}")]
    DurabilityBlocked {
        message: String,
        group_ids: Vec<String>,
        operation_id: Option<String>,
        can_force: bool,
    },
    #[error("{message}")]
    InvalidInput { message: String, field: Option<String> },
    #[error("{message}")]
    Internal { message: String, category: String },
    /// The daemon refused for a reason the person can act on; branch on
    /// `reason`. Declared last so the other cases keep their wire order.
    #[error("{message}")]
    Refused { message: String, reason: RefusalReason },
    /// A folder was refused because its drive cannot be synced into yet. `message` is the
    /// English sentence (command line, logs); a front end words `reason` (and `file_system` for
    /// `Other`) in its own language. Declared last, like `Refused`.
    #[error("{message}")]
    UnsupportedDrive { message: String, reason: UnsupportedDriveReason, file_system: String },
}

impl DesktopError {
    /// Maps a client error onto the desktop taxonomy. `can_force` is set by
    /// the few operations that accept a `force` override and were called
    /// without it; it only matters for a durability refusal.
    #[must_use]
    pub fn from_core(error: CoreError, can_force: bool) -> Self {
        let message = error.to_string();
        match error {
            CoreError::NotLoggedIn => DesktopError::NotSignedIn { message },
            CoreError::DaemonNotRunning => DesktopError::DaemonUnavailable {
                message: match crate::ops::daemon::startup_refusal() {
                    Some(refusal) => format!("{message}\n\n{refusal}"),
                    None => message,
                },
                reason: DaemonUnavailableReason::NotRunning,
            },
            CoreError::DaemonUnresponsive => DesktopError::DaemonUnavailable {
                message,
                reason: DaemonUnavailableReason::Unresponsive,
            },
            CoreError::DaemonProtocolMismatch { client, daemon } => {
                DesktopError::DaemonUnavailable {
                    message,
                    reason: DaemonUnavailableReason::ProtocolMismatch {
                        client_version: client,
                        daemon_version: daemon,
                    },
                }
            }
            CoreError::CoordinationPlaneUnreachable(_) => {
                DesktopError::Network { message, kind: NetworkErrorKind::Unreachable }
            }
            CoreError::LimitExceeded {
                kind: LimitKind::RateLimited { retry_after_secs }, ..
            } => DesktopError::Network {
                message,
                kind: NetworkErrorKind::RateLimited { retry_after_secs },
            },
            CoreError::LimitExceeded { kind: LimitKind::Quota, .. } => {
                denied(message, PermissionDeniedReason::QuotaExceeded)
            }
            CoreError::AuthFailed(_) | CoreError::SignInRequired | CoreError::AccountMismatch => {
                denied(message, PermissionDeniedReason::SessionRejected)
            }
            CoreError::TermsConsentRequired { .. } => {
                denied(message, PermissionDeniedReason::TermsConsentRequired)
            }
            CoreError::DeviceSuperseded => {
                denied(message, PermissionDeniedReason::DeviceSuperseded)
            }
            CoreError::Forbidden(_) => denied(message, PermissionDeniedReason::Forbidden),
            CoreError::ReauthenticationRequired => {
                denied(message, PermissionDeniedReason::ReauthenticationRequired)
            }
            CoreError::CredentialStore(_) => {
                denied(message, PermissionDeniedReason::CredentialStoreUnusable)
            }
            CoreError::DurabilityBlocked { group_ids, .. } => DesktopError::DurabilityBlocked {
                message,
                group_ids,
                operation_id: None,
                can_force,
            },
            CoreError::StatePlacement(_) => {
                DesktopError::Refused { message, reason: RefusalReason::StateDirUnusable }
            }
            CoreError::StartOverRefused(refusal) => DesktopError::Refused {
                message,
                reason: match refusal {
                    StartOverRefusal::NotConfirmed => RefusalReason::StartOverNotConfirmed,
                    StartOverRefusal::NotRestored => RefusalReason::DatabaseNotRestored,
                    StartOverRefusal::InProgress => RefusalReason::StartOverInProgress,
                    StartOverRefusal::RestartRequired => RefusalReason::StartOverRestartRequired,
                },
            },
            CoreError::PairingCodeRefused => {
                DesktopError::Refused { message, reason: RefusalReason::PairingCodeInvalid }
            }
            CoreError::PrimaryTransferRefused(refusal) => DesktopError::Refused {
                message,
                reason: match refusal {
                    PrimaryTransferRefusal::NotPrimary => RefusalReason::PrimaryTransferNotPrimary,
                    PrimaryTransferRefusal::TargetNotMember => {
                        RefusalReason::PrimaryTransferTargetNotMember
                    }
                    PrimaryTransferRefusal::TargetSameAccount => {
                        RefusalReason::PrimaryTransferTargetSameAccount
                    }
                    PrimaryTransferRefusal::OfferExpired => {
                        RefusalReason::PrimaryTransferOfferExpired
                    }
                    PrimaryTransferRefusal::GroupNotActive => {
                        RefusalReason::PrimaryTransferGroupNotActive
                    }
                    PrimaryTransferRefusal::Conflict => RefusalReason::PrimaryTransferConflict,
                    PrimaryTransferRefusal::NotFound => RefusalReason::PrimaryTransferNotFound,
                },
            },
            CoreError::InvalidInput(_) => DesktopError::InvalidInput { message, field: None },
            CoreError::InvalidArgument(argument) => {
                DesktopError::InvalidInput { message, field: Some(argument.field().to_owned()) }
            }
            CoreError::DaemonCommand { code, group_ids, operation_id, drive, .. } => {
                from_command(code, message, group_ids, operation_id, drive, can_force)
            }
            CoreError::EngineMismatch { detail, .. } => DesktopError::DaemonUnavailable {
                message,
                reason: DaemonUnavailableReason::EngineMismatch {
                    kind: detail.kind,
                    direction: detail.direction,
                    app_version: detail.app_version,
                    engine_version: detail.engine_version,
                    app_release_id: detail.app_release_id,
                    engine_release_id: detail.engine_release_id,
                    app_api_version: detail.app_api_version,
                    engine_api_version: detail.engine_api_version,
                },
            },
            CoreError::ManagedElsewhere(_) => {
                DesktopError::Refused { message, reason: RefusalReason::ManagedElsewhere }
            }
            CoreError::DaemonRejected(_) | CoreError::Io(_) | CoreError::Other(_) => {
                DesktopError::Internal { message, category: "cli_command_failed".to_owned() }
            }
            // The hint is the host's to word; a daemon hint is a typed reason a GUI maps to its
            // own start action, every other hint is already carried by the inner error's reason.
            CoreError::Hinted { error, hint } => match hint {
                Hint::StartDaemon | Hint::WaitThenStartDaemon | Hint::StopThenStartDaemon => {
                    DesktopError::DaemonUnavailable {
                        message,
                        reason: DaemonUnavailableReason::StartNeeded {
                            stop_first: hint == Hint::StopThenStartDaemon,
                        },
                    }
                }
                _ => DesktopError::from_core(*error, can_force),
            },
        }
    }

    /// An argument refused before any request, naming the argument.
    #[must_use]
    pub fn invalid_input(message: impl Into<String>, field: &str) -> Self {
        DesktopError::InvalidInput { message: message.into(), field: Some(field.to_owned()) }
    }

    /// Whether this is the daemon being unreachable.
    #[must_use]
    pub fn is_daemon_unavailable(&self) -> bool {
        matches!(self, DesktopError::DaemonUnavailable { .. })
    }
}

fn denied(message: String, reason: PermissionDeniedReason) -> DesktopError {
    DesktopError::PermissionDenied { message, reason }
}

/// A typed daemon command refusal, sorted by what a person can do about it.
fn from_command(
    code: ApplicationErrorCode,
    message: String,
    group_ids: Vec<String>,
    operation_id: Option<String>,
    drive: Option<UnsupportedDrive>,
    can_force: bool,
) -> DesktopError {
    use ApplicationErrorCode as Code;
    match code {
        Code::UnsupportedDrive => match drive {
            Some(UnsupportedDrive { reason, file_system }) => {
                DesktopError::UnsupportedDrive { message, reason, file_system }
            }
            // A daemon that named no reason is still a refused path.
            None => DesktopError::Refused { message, reason: RefusalReason::PathNotAllowed },
        },
        // The daemon has no local identity: this device was never registered,
        // and setup is where that is fixed.
        Code::LocalIdentityUnavailable => DesktopError::NotSignedIn { message },
        Code::CoordinationTransport | Code::CoordinationAmbiguous | Code::TicketUnavailable => {
            DesktopError::Network { message, kind: NetworkErrorKind::Unreachable }
        }
        Code::ActivationAmbiguous => DesktopError::Network {
            message,
            kind: NetworkErrorKind::ActivationPendingReconciliation,
        },
        Code::CoordinationRejected | Code::ActivationRejected | Code::PreparationRejected => {
            denied(message, PermissionDeniedReason::Forbidden)
        }
        Code::ReplicaNotReady | Code::DurabilityLatchFailed | Code::RecoveryPending => {
            DesktopError::DurabilityBlocked { message, group_ids, operation_id, can_force }
        }
        // The unlink gate: the group's last confirmed complete copy.
        Code::NotProtected => {
            DesktopError::DurabilityBlocked { message, group_ids, operation_id, can_force }
        }
        Code::DiskFull => DesktopError::Refused { message, reason: RefusalReason::DiskFull },
        Code::PathNotAllowed => {
            DesktopError::Refused { message, reason: RefusalReason::PathNotAllowed }
        }
        Code::AccessDenied => {
            DesktopError::Refused { message, reason: RefusalReason::AccessDenied }
        }
        Code::InviteExpired => {
            DesktopError::Refused { message, reason: RefusalReason::InviteExpired }
        }
        Code::InviteAlreadyUsed => {
            DesktopError::Refused { message, reason: RefusalReason::InviteAlreadyUsed }
        }
        Code::SendLinkExpired => {
            DesktopError::Refused { message, reason: RefusalReason::SendLinkExpired }
        }
        Code::SendLinkAlreadyUsed => {
            DesktopError::Refused { message, reason: RefusalReason::SendLinkAlreadyUsed }
        }
        Code::SendLinkCancelled => {
            DesktopError::Refused { message, reason: RefusalReason::SendLinkCancelled }
        }
        Code::SendLinkInvalid => {
            DesktopError::Refused { message, reason: RefusalReason::SendLinkInvalid }
        }
        Code::SendPeerUnreachable => {
            DesktopError::Refused { message, reason: RefusalReason::SendPeerUnreachable }
        }
        Code::SendNoSpace => DesktopError::Refused { message, reason: RefusalReason::SendNoSpace },
        Code::SendInterrupted => {
            DesktopError::Refused { message, reason: RefusalReason::SendInterrupted }
        }
        Code::SendLinksDisabled => {
            DesktopError::Refused { message, reason: RefusalReason::SendLinksDisabled }
        }
        Code::SendPreviewUnverified => {
            DesktopError::Refused { message, reason: RefusalReason::SendPreviewUnverified }
        }
        Code::SendLocalNetworkBlocked => {
            DesktopError::Refused { message, reason: RefusalReason::SendLocalNetworkBlocked }
        }
        Code::TermsConsentRequired => denied(message, PermissionDeniedReason::TermsConsentRequired),
        Code::TargetNotFound => DesktopError::InvalidInput { message, field: None },
        // Refused with nothing changed.
        Code::UnrecordedLocalChanges => {
            DesktopError::Refused { message, reason: RefusalReason::UnrecordedLocalChanges }
        }
        Code::ConflictNotResolvable => {
            DesktopError::Refused { message, reason: RefusalReason::ConflictNotResolvable }
        }
        Code::GroupMismatch => {
            DesktopError::Refused { message, reason: RefusalReason::GroupMismatch }
        }
        Code::Unspecified
        | Code::Persistence
        | Code::LocalLinkFailed
        | Code::CompensationPending
        | Code::OperationConflict
        | Code::RecoveryJournalUnavailable => {
            DesktopError::Internal { message, category: command_category(code) }
        }
    }
}

/// `daemon_command_<code>`, from the protocol's own name for the code.
fn command_category(code: ApplicationErrorCode) -> String {
    let name = code.as_str_name();
    let short = name.strip_prefix("APPLICATION_ERROR_CODE_").unwrap_or(name);
    format!("daemon_command_{}", short.to_ascii_lowercase())
}

impl From<CoreError> for DesktopError {
    fn from(error: CoreError) -> Self {
        DesktopError::from_core(error, false)
    }
}

#[cfg(test)]
mod tests;
