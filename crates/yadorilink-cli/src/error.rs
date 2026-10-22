//! CLI error taxonomy: distinct categories so the exit code and
//! message tell the user what kind of thing went wrong, not just that
//! something did.

use yadorilink_client_core::CoreError;
use yadorilink_ipc_proto::daemonctl::ApplicationErrorCode;

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("not logged in — run `yadorilink login`")]
    NotLoggedIn,

    // A credential store that exists and cannot be used. Deliberately NOT
    // folded into `NotLoggedIn`: that one means "nobody has signed in here"
    // and its remedy is to sign in, which on a damaged or wrongly-configured
    // store would succeed and leave the damage behind. This one's remedy is
    // the store, and the message the store produces already names it.
    #[error("{0}")]
    CredentialStore(#[from] yadorilink_fapi_client::store::StoreError),

    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("could not reach the YadoriLink server: {0}")]
    CoordinationPlaneUnreachable(String),

    // A per-account quota
    // (`quota_exceeded`) or abuse budget (`rate_limited`) was hit. Distinct
    // from a coordination-plane *outage* (which is not the caller's fault and
    // is retryable by waiting) -- this is user-actionable (remove a device,
    // wait out a retry hint, or ask an operator to raise a ceiling), so it
    // carries its own exit code and is not reported as a maintainer-facing bug.
    #[error("{0}")]
    LimitExceeded(String),

    #[error("yadorilink daemon is not running — run `yadorilink daemon start`, or `systemctl start <service>` where a system service runs it")]
    DaemonNotRunning,

    #[error("{0}")]
    Other(String),

    // This process may not keep its state where it is configured (a packaged app under
    // AppData); nothing was created. Its remedy is the configuration the message names.
    #[error("{0}")]
    StatePlacement(#[from] yadorilink_fs_platform::state_dir::StateDirError),

    // The user declined a confirmation (or none could be asked): nothing
    // failed, so it is neither reportable nor a bug.
    #[error("{0}")]
    Cancelled(String),

    // Distinct from the generic `DaemonNotRunning` — this fires
    // specifically when a *reporting* command needed the daemon (the
    // report queue, or `--submit`) and it wasn't reachable, so the
    // message can explain *why* (daemon-owned storage / the one network
    // path) rather than just "start the daemon" with no context for why
    // a reporting command in particular needs it when so many other
    // reporting commands don't.
    #[error("{0}")]
    ReportingDaemonRequired(String),

    // A create/join's activate call could not be confirmed one way or the
    // other (a transport error, timeout, or 5xx from the coordination
    // plane) — the plane may already have committed the activation even
    // though this process never saw a clean response. Distinct from every
    // other error category here: the caller (`commands::share`) has
    // deliberately left the just-committed local link AND its
    // pending-enrollment marker in place rather than rolling them back, so
    // the daemon's own reconciliation sweep can resolve it (finalize to
    // Active, or clean up once the plane confirms it never landed) instead
    // of this process guessing wrong and either stranding a phantom
    // coordination-side edge or deleting a link the plane already counts.
    #[error("{0}")]
    EnrollmentPendingReconciliation(String),

    // A rewind that did not run to completion, by the kind of thing the
    // person has to do next. Each kind has its own exit code, so a script can
    // tell "preview again" from "wait for a device" without reading text. The
    // message is the shared wording (replica domain), printed as given.
    #[error("{message}")]
    Rewind { exit: RewindExit, message: String },

    /// Another owner (the app, or another install) manages YadoriLink on this machine, or the
    /// owner cannot be told. Nothing was started or changed. Its own exit code, so a script can
    /// tell "ask the owner" from a failure.
    #[error("{0}")]
    ManagedElsewhere(String),

    /// `self-update` refused the target version: the live, verified channel manifest withdraws
    /// it, a kill switch or the minimum supported version excludes it, or the daemon could not
    /// supply a verified manifest (fail closed). Nothing was downloaded or changed.
    #[error("{0}")]
    UpdateRefused(String),
}

/// Exit code of [`CliError::ManagedElsewhere`].
pub const EXIT_MANAGED_ELSEWHERE: i32 = 19;

/// How a rewind ended without finishing. The exit code of each is listed in
/// `yadorilink --help`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewindExit {
    /// The folder changed since the preview; preview again.
    PlanStale,
    /// Some files cannot be restored; the rewind cannot start.
    Unavailable,
    /// A needed device did not answer; retry later.
    Transient,
    /// The folder changed before the first change was made.
    FolderChanged,
    /// Stopped after some changes were made; preview again.
    NeedsReplan,
    /// Not started for another reason (this device may not change the
    /// folder, a rewind is already running, not enough space, interrupted
    /// before any change).
    NotStarted,
    /// The person answered no; nothing was changed.
    Declined,
    /// Confirmation was needed and there is no terminal to ask on.
    NotConfirmable,
}

impl RewindExit {
    pub fn code(self) -> i32 {
        match self {
            RewindExit::PlanStale => 11,
            RewindExit::Unavailable => 12,
            RewindExit::Transient => 13,
            RewindExit::FolderChanged => 14,
            RewindExit::NeedsReplan => 15,
            RewindExit::NotStarted => 16,
            RewindExit::Declined => 17,
            RewindExit::NotConfirmable => 18,
        }
    }
}

impl CliError {
    /// Why the daemon is not running, when it refused to start over its data:
    /// printed under "daemon is not running", which alone sends the user to
    /// `daemon start`, which cannot help.
    #[must_use]
    pub fn daemon_refusal_detail(&self) -> Option<String> {
        let dir = yadorilink_client_core::coordination::device_config::config_dir().ok()?;
        self.daemon_refusal_detail_in(&dir)
    }

    fn daemon_refusal_detail_in(&self, config_dir: &std::path::Path) -> Option<String> {
        matches!(self, CliError::DaemonNotRunning)
            .then(|| yadorilink_local_storage::startup_refusal::read(config_dir))
            .flatten()
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::NotLoggedIn | CliError::AuthFailed(_) => 10,
            CliError::CredentialStore(_) => 9,
            CliError::CoordinationPlaneUnreachable(_) => 3,
            CliError::DaemonNotRunning => 4,
            CliError::Other(_) | CliError::Cancelled(_) | CliError::StatePlacement(_) => 1,
            CliError::ReportingDaemonRequired(_) => 6,
            CliError::LimitExceeded(_) => 7,
            CliError::EnrollmentPendingReconciliation(_) => 8,
            CliError::Rewind { exit, .. } => exit.code(),
            CliError::ManagedElsewhere(_) => EXIT_MANAGED_ELSEWHERE,
            CliError::UpdateRefused(_) => 4,
        }
    }

    /// Whether this failure is worth surfacing to local error reporting at
    /// all. Excludes the purely user-actionable categories (not logged in,
    /// bad credentials, daemon not started) where the next step is already
    /// obvious from the error message itself and a maintainer-facing
    /// report would add noise, not signal; includes categories more likely
    /// to indicate a real environment/connectivity/bug condition worth a
    /// maintainer seeing.
    pub fn is_reportable(&self) -> bool {
        matches!(
            self,
            CliError::CoordinationPlaneUnreachable(_)
                | CliError::Other(_)
                | CliError::EnrollmentPendingReconciliation(_)
                | CliError::CredentialStore(_)
        )
    }

    /// A coarse, stable category label for this error, used as the
    /// `error_category` field of a candidate created by
    /// `commands::report::handle_reportable_error` — never the raw
    /// message (that goes in `log_lines`, already redacted).
    pub fn report_category(&self) -> &'static str {
        match self {
            CliError::NotLoggedIn => "cli_not_logged_in",
            CliError::CredentialStore(_) => "cli_credential_store",
            CliError::AuthFailed(_) => "cli_auth_failed",
            CliError::CoordinationPlaneUnreachable(_) => "cli_coordination_plane_unreachable",
            CliError::DaemonNotRunning => "cli_daemon_not_running",
            CliError::Other(_) => "cli_command_failed",
            CliError::Cancelled(_) => "cli_cancelled",
            CliError::StatePlacement(_) => "cli_state_placement",
            CliError::ReportingDaemonRequired(_) => "cli_reporting_daemon_required",
            CliError::LimitExceeded(_) => "cli_limit_exceeded",
            CliError::EnrollmentPendingReconciliation(_) => "cli_enrollment_pending_reconciliation",
            CliError::Rewind { .. } => "cli_rewind",
            CliError::ManagedElsewhere(_) => "cli_managed_elsewhere",
            CliError::UpdateRefused(_) => "cli_update_refused",
        }
    }
}

/// The credential manager's failures, classified the one way
/// `yadorilink-client-core` classifies them, then mapped onto this CLI's
/// categories like every other client error.
impl From<yadorilink_fapi_client::Error> for CliError {
    fn from(e: yadorilink_fapi_client::Error) -> Self {
        CoreError::from(e).into()
    }
}

/// The client layer's errors, mapped onto the CLI's categories. Every message
/// and exit code is the one this command line produced before those
/// operations moved into the client layer; the typed categories the client
/// layer adds (a 403, a durability refusal, a typed daemon command error,
/// invalid input) keep printing the same text under the same exit code.
impl From<CoreError> for CliError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::NotLoggedIn => CliError::NotLoggedIn,
            CoreError::CredentialStore(store) => CliError::CredentialStore(store),
            CoreError::AuthFailed(message) => CliError::AuthFailed(message),
            CoreError::CoordinationPlaneUnreachable(message) => {
                CliError::CoordinationPlaneUnreachable(message)
            }
            CoreError::LimitExceeded { message, .. } => CliError::LimitExceeded(message),
            CoreError::DaemonNotRunning => CliError::DaemonNotRunning,
            CoreError::ManagedElsewhere(message) => CliError::ManagedElsewhere(message),
            e @ CoreError::DaemonUnresponsive => CliError::Other(e.to_string()),
            CoreError::DaemonProtocolMismatch { client, daemon } => CliError::Other(format!(
                "CLI/daemon protocol version mismatch (CLI {client}, daemon {daemon}); run \
                 matching YadoriLink CLI and daemon binaries"
            )),
            CoreError::EngineMismatch { message, .. } => CliError::Other(message),
            CoreError::DaemonCommand {
                code: ApplicationErrorCode::ActivationAmbiguous,
                message,
                ..
            } => CliError::EnrollmentPendingReconciliation(message),
            CoreError::DaemonCommand { code: ApplicationErrorCode::DiskFull, message, .. } => {
                CliError::Other(format!(
                    "there is not enough free disk space to do this; free some space and try \
                     again ({message})"
                ))
            }
            CoreError::DaemonCommand {
                code: ApplicationErrorCode::AccessDenied, message, ..
            } => CliError::Other(format!(
                "the system has not allowed YadoriLink to access this folder, so nothing was \
                     linked. On macOS, allow it in System Settings > Privacy & Security > Files \
                     and Folders (or Full Disk Access); on Windows, give your account access to \
                     the folder. Then run the command again, or choose another folder ({message})"
            )),
            CoreError::DaemonCommand { code: ApplicationErrorCode::InviteExpired, .. } => {
                CliError::Other(
                    "this invite has expired; ask the person who sent it for a new one".to_string(),
                )
            }
            CoreError::DaemonCommand { code: ApplicationErrorCode::InviteAlreadyUsed, .. } => {
                CliError::Other(
                    "this invite was already used or was cancelled; ask the person who sent it \
                     for a new one"
                        .to_string(),
                )
            }
            CoreError::StatePlacement(refusal) => CliError::StatePlacement(refusal),
            CoreError::StartOverRefused(refusal) => CliError::Other(refusal.to_string()),
            CoreError::Forbidden(message)
            | CoreError::DaemonRejected(message)
            | CoreError::DaemonCommand { message, .. }
            | CoreError::DurabilityBlocked { message, .. }
            | CoreError::InvalidInput(message)
            | CoreError::Io(message)
            | CoreError::Other(message) => CliError::Other(message),
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        // A missing file is not a missing daemon: the daemon socket's own
        // absence is mapped where it is opened (`client-core` `send`).
        if e.kind() == std::io::ErrorKind::ConnectionRefused {
            CliError::DaemonNotRunning
        } else {
            CliError::Other(e.to_string())
        }
    }
}

// Unrelated hotfix: `commands/diagnose.rs`'s `preview`/`export` (from a
// separately-committed "cli diagnostics fallback" change) use `?` on
// `serde_json::to_string_pretty`, which needs this conversion and was
// missing it, breaking `cargo build --workspace` for every crate
// downstream of `yadorilink-cli`. Minimal, same-shape fix as every other
// blanket conversion here.
impl From<serde_json::Error> for CliError {
    fn from(e: serde_json::Error) -> Self {
        CliError::Other(e.to_string())
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod refusal_detail_tests {
    use super::*;

    #[test]
    fn a_not_running_daemon_that_refused_its_data_says_why() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(CliError::DaemonNotRunning.daemon_refusal_detail_in(dir.path()), None);
        yadorilink_local_storage::startup_refusal::record(dir.path(), "reset steps").unwrap();
        assert_eq!(
            CliError::DaemonNotRunning.daemon_refusal_detail_in(dir.path()).as_deref(),
            Some("reset steps")
        );
        assert_eq!(CliError::Other("x".into()).daemon_refusal_detail_in(dir.path()), None);
    }
}
