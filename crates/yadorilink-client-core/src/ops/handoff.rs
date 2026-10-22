//! Releasing the data area from this command-line install to the desktop app.
//!
//! The engine (journal, state machine, roll-back) is `yadorilink_local_storage::handoff`; this is
//! its host for a real machine: the safe-stop request on the control socket, the daemon launcher
//! of this install, the OS service tools. It must run from the install being released, because
//! only that install's program is the same release as the daemon it stops.

use std::path::PathBuf;
use std::time::Duration;

use yadorilink_ipc_proto::daemonctl::request_safe_stop_response::Outcome as WireOutcome;
use yadorilink_local_storage::handoff::services::{OsServices, ServiceManager, SystemRunner};
use yadorilink_local_storage::handoff::{self, Context, Host, StopAnswer};
use yadorilink_local_storage::install_check::RunningInstall;
use yadorilink_local_storage::ownership::{self, Owner, OwnershipRecord, RecordState};
use yadorilink_local_storage::release_descriptor::{DescriptorProblem, ReleaseDescriptor};
use yadorilink_local_storage::service_registrations::Roots;

pub use yadorilink_local_storage::handoff::{
    HandoffError, Outcome, PreviousDaemon, Refused, Request,
};

use crate::dto::DaemonLaunch;
use crate::error::CoreError;

/// How long the daemon may take to reach a safe point.
const STOP_DEADLINE: Duration = Duration::from_secs(30);
/// How long to wait for the data-area lock once the daemon has begun to exit.
const LOCK_WAIT: Duration = Duration::from_secs(30);

/// The real machine behind the engine.
pub struct SystemHost {
    services: OsServices<SystemRunner>,
}

impl SystemHost {
    #[must_use]
    pub fn new() -> Self {
        Self { services: OsServices { runner: SystemRunner, uid: super::daemon::current_uid() } }
    }
}

impl Default for SystemHost {
    fn default() -> Self {
        Self::new()
    }
}

impl Host for SystemHost {
    fn services(&self) -> &dyn ServiceManager {
        &self.services
    }

    async fn safe_stop(&self, deadline: Duration) -> StopAnswer {
        match super::daemon::request_safe_stop(Some(deadline)).await {
            Ok(answer) => match answer.outcome {
                Some(WireOutcome::Stopping(_)) => StopAnswer::Stopping,
                Some(WireOutcome::Busy(busy)) => StopAnswer::Busy { detail: busy.detail },
                None => StopAnswer::Busy { detail: "the daemon gave no outcome".into() },
            },
            Err(CoreError::DaemonNotRunning) => StopAnswer::NotRunning,
            Err(e) => StopAnswer::Unresponsive(e.to_string()),
        }
    }

    async fn start_previous(&self, previous: &OwnershipRecord) -> Result<(), String> {
        let launch = previous_launch(previous)?;
        super::daemon::start_daemon_with(&launch).await.map(|_| ()).map_err(|e| e.to_string())
    }

    async fn identify(&self) -> Option<RunningInstall> {
        let identity = super::daemon::identify().await.ok()?;
        Some(RunningInstall {
            install_source: identity.install_source,
            install_root: identity.install_root,
            version: identity.version,
            release_id: identity.release_id,
            engine_api_version: identity.engine_api_version,
        })
    }

    fn local_descriptor(&self) -> Result<ReleaseDescriptor, DescriptorProblem> {
        crate::daemon::control::local_descriptor()
    }
}

/// How to start the previous installation's daemon: the executable in the directory the record
/// names (the install root is the directory of the daemon that wrote it), never the default
/// launch, which may pick the app's agent or a daemon beside a different CLI.
fn previous_launch(previous: &OwnershipRecord) -> Result<DaemonLaunch, String> {
    let name = if cfg!(windows) { "yadorilink-daemon.exe" } else { "yadorilink-daemon" };
    let binary = PathBuf::from(&previous.install_root).join(name);
    if binary.is_file() {
        Ok(DaemonLaunch::SpawnBinary { path: Some(binary.display().to_string()) })
    } else {
        Err(format!(
            "the previous daemon {} is gone; start the install you want with its own tools",
            binary.display()
        ))
    }
}

fn home() -> PathBuf {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(PathBuf::from)
        .unwrap_or_default()
}

/// The engine's context for this machine's data area.
///
/// # Errors
/// [`CoreError`] when the state directory may not be used by this process.
pub fn context() -> Result<Context, CoreError> {
    let config_dir = crate::coordination::device_config::config_dir()
        .map_err(|e| CoreError::Other(e.to_string()))?;
    let recorded = match ownership::read(&config_dir) {
        RecordState::Present(r) => Some(r.install_root),
        _ => None,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    Ok(Context {
        roots: Roots::detect(home(), recorded.as_deref()),
        config_dir,
        stop_deadline: STOP_DEADLINE,
        lock_wait: LOCK_WAIT,
        now,
    })
}

/// Whether the running program is a command-line install's (the only one that may release).
#[must_use]
pub fn running_from_cli_install() -> bool {
    std::env::current_exe().map_or(true, |exe| Owner::of_executable(&exe) == Owner::Cli)
}

/// Hands the data area to the app described by `request`, or finishes an open hand-off to it.
///
/// # Errors
/// [`HandoffError`].
pub async fn release(request: &Request) -> Result<Outcome, HandoffError> {
    let ctx = context().map_err(|e| HandoffError::Refused(Refused::Unusable(e.to_string())))?;
    handoff::release(&SystemHost::new(), &ctx, request).await
}

/// Undoes an open hand-off.
///
/// # Errors
/// [`HandoffError`].
pub async fn rollback() -> Result<Outcome, HandoffError> {
    let ctx = context().map_err(|e| HandoffError::Refused(Refused::Unusable(e.to_string())))?;
    handoff::rollback(&SystemHost::new(), &ctx).await
}

/// Verifies the app's daemon and closes the hand-off.
///
/// # Errors
/// [`HandoffError`].
pub async fn commit() -> Result<Outcome, HandoffError> {
    let ctx = context().map_err(|e| HandoffError::Refused(Refused::Unusable(e.to_string())))?;
    handoff::commit(&SystemHost::new(), &ctx).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_previous_daemon_is_the_one_in_the_recorded_install_root() {
        let dir = tempfile::tempdir().unwrap();
        let record = OwnershipRecord {
            owner: Owner::Cli,
            install_source: "script".into(),
            install_root: dir.path().display().to_string(),
            release_id: String::new(),
            written_at: 1,
        };
        assert!(previous_launch(&record).unwrap_err().contains("is gone"));
        let name = if cfg!(windows) { "yadorilink-daemon.exe" } else { "yadorilink-daemon" };
        std::fs::write(dir.path().join(name), b"d").unwrap();
        assert_eq!(
            previous_launch(&record).unwrap(),
            DaemonLaunch::SpawnBinary { path: Some(dir.path().join(name).display().to_string()) }
        );
    }
}
