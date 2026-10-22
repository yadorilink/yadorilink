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
    /// An abuse budget (`rate_limited`): wait and retry.
    RateLimited,
}

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// Nobody has signed in on this machine.
    #[error("not logged in — run `yadorilink login`")]
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

    /// The coordination plane answered 403: the session is valid but not
    /// allowed to do this.
    #[error("{0}")]
    Forbidden(String),

    #[error("could not reach the coordination plane: {0}")]
    CoordinationPlaneUnreachable(String),

    /// A quota or rate limit was hit; user-actionable rather than an outage.
    #[error("{message}")]
    LimitExceeded { message: String, kind: LimitKind },

    #[error("yadorilink daemon is not running — run `yadorilink daemon start`")]
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

    #[error("{0}")]
    Other(String),
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
            Self::InProgress => f.write_str(
                "a start over as a new device is under way on this computer; finish it \
                 (`yadorilink device start-over`) before registering",
            ),
        }
    }
}

impl CoreError {
    /// The typed form of a daemon application-command refusal. An error code
    /// this build does not know reads as `Unspecified` rather than failing.
    #[must_use]
    pub fn from_command_error(error: ApplicationCommandError) -> Self {
        CoreError::DaemonCommand {
            code: ApplicationErrorCode::try_from(error.code)
                .unwrap_or(ApplicationErrorCode::Unspecified),
            message: error.message,
            group_ids: error.group_ids,
            operation_id: (!error.operation_id.is_empty()).then_some(error.operation_id),
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
            FapiError::Response { status: 400 | 401 | 403, .. } => {
                CoreError::AuthFailed(e.to_string())
            }
            FapiError::Response { status: 429 | 500..=599, .. } => {
                CoreError::CoordinationPlaneUnreachable(e.to_string())
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
/// A shell built before `EngineMismatch` existed cannot decode it (its bindings are generated
/// from the library it ships with and refuse a different one), so the pairing never arises with
/// an older shell. A shell that must degrade on a variant it does not know reads it as
/// `ProtocolMismatch`: starting the engine again cannot help and the remedy is an update, the
/// same as for a mismatch.
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum NetworkErrorKind {
    Unreachable,
    RateLimited,
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
    Forbidden,
    QuotaExceeded,
    /// The credential store exists and cannot be used; signing in again
    /// would leave it damaged.
    CredentialStoreUnusable,
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
            CoreError::LimitExceeded { kind: LimitKind::RateLimited, .. } => {
                DesktopError::Network { message, kind: NetworkErrorKind::RateLimited }
            }
            CoreError::LimitExceeded { kind: LimitKind::Quota, .. } => {
                denied(message, PermissionDeniedReason::QuotaExceeded)
            }
            CoreError::AuthFailed(_) => denied(message, PermissionDeniedReason::SessionRejected),
            CoreError::Forbidden(_) => denied(message, PermissionDeniedReason::Forbidden),
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
                },
            },
            CoreError::InvalidInput(_) => DesktopError::InvalidInput { message, field: None },
            CoreError::DaemonCommand { code, group_ids, operation_id, .. } => {
                from_command(code, message, group_ids, operation_id, can_force)
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
    can_force: bool,
) -> DesktopError {
    use ApplicationErrorCode as Code;
    match code {
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
        Code::InviteExpired => {
            DesktopError::Refused { message, reason: RefusalReason::InviteExpired }
        }
        Code::InviteAlreadyUsed => {
            DesktopError::Refused { message, reason: RefusalReason::InviteAlreadyUsed }
        }
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
