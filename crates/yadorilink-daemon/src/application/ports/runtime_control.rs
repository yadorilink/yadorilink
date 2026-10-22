//! What the pause/resume, GC and shutdown control commands need from the
//! runtime -- daemon-wide operations that don't fit
//! `MaterializationPort`'s per-file shape (pause/resume act on a link as a
//! whole; GC and shutdown aren't scoped to a link at all).

use crate::pause_deadline::PauseDuration;
use crate::sync_error::SyncError;

use super::common::BoxFuture;

pub(crate) trait LinkPauseResumePort: Send + Sync {
    /// Pauses the link as a whole for `duration`. Pausing an already paused
    /// link replaces its deadline; [`Self::resume`] ends the pause and
    /// clears the deadline. With `expected_group`, the link at `local_path` must belong to
    /// that group, checked by the write itself; otherwise `SyncError::GroupMismatch` and
    /// nothing changes.
    fn pause(
        &self,
        local_path: &str,
        duration: PauseDuration,
        expected_group: Option<&str>,
    ) -> Result<(), SyncError>;

    /// `expected_group` as for [`Self::pause`].
    fn resume<'a>(
        &'a self,
        local_path: &'a str,
        expected_group: Option<&'a str>,
    ) -> BoxFuture<'a, Result<(), SyncError>>;

    /// The user confirms that the disk now mounted at the linked folder
    /// `local_path` is that folder's disk (see
    /// `LinkRuntimeController::readopt_volume`).
    fn readopt_volume<'a>(&'a self, local_path: &'a str) -> BoxFuture<'a, Result<(), SyncError>>;

    /// Pauses one file or folder of `group_id` (`rel_path` relative to the
    /// linked folder's root, empty for the root itself) until
    /// [`Self::resume_item`], durably: local edits under it are not sent to
    /// peers and remote changes under it are not written to disk, while
    /// both keep being recorded so nothing is lost.
    fn pause_item(&self, group_id: &str, rel_path: &str) -> Result<(), SyncError>;

    /// Ends a pause of `rel_path` and catches up everything it held: local
    /// edits made meanwhile are sent, remote changes admitted meanwhile are
    /// written to disk (as conflicts where both sides changed). Safe to
    /// repeat -- a retry after a failed catch-up runs the catch-up again.
    fn resume_item<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> BoxFuture<'a, Result<(), SyncError>>;
}

/// Application-owned mirror of `yadorilink_local_storage::GcReport` --
/// kept as a distinct type (not a re-export) so `application` never names
/// a local-storage crate type in a port signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GcCommandOutcome {
    pub(crate) blocks_deleted: u64,
    pub(crate) bytes_reclaimed: u64,
}

/// Application-owned mirror of the daemon's own `GcTriggerError` -- kept
/// distinct so `application` never names that GC implementation type
/// directly in a port signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GcCommandError {
    AlreadyRunning,
    SyncBurstInProgress,
    Failed(String),
}

impl std::fmt::Display for GcCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GcCommandError::AlreadyRunning => {
                write!(f, "a garbage-collection sweep is already in progress; try again shortly")
            }
            GcCommandError::SyncBurstInProgress => write!(
                f,
                "sync activity is in progress; garbage collection was skipped to avoid \
                 contention -- try again once idle, or wait for the next automatic sweep"
            ),
            GcCommandError::Failed(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for GcCommandError {}

pub(crate) trait GcPort: Send + Sync {
    fn run_sweep(&self, dry_run: bool) -> BoxFuture<'_, Result<GcCommandOutcome, GcCommandError>>;
}

/// Used when a safe-stop request names no deadline.
pub(crate) const SAFE_STOP_DEFAULT_DEADLINE: std::time::Duration =
    std::time::Duration::from_secs(30);
/// No safe-stop request may ask the daemon to wait longer than this.
pub(crate) const SAFE_STOP_MAX_DEADLINE: std::time::Duration = std::time::Duration::from_secs(300);

/// The deadline a request's `deadline_secs` means.
pub(crate) fn safe_stop_deadline(secs: u32) -> std::time::Duration {
    if secs == 0 {
        SAFE_STOP_DEFAULT_DEADLINE
    } else {
        std::time::Duration::from_secs(u64::from(secs)).min(SAFE_STOP_MAX_DEADLINE)
    }
}

/// How a safe-stop request ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SafeStopOutcome {
    /// The daemon is at a safe point with its databases checkpointed and has begun to exit.
    Stopping { already_in_progress: bool },
    /// The daemon did not stop and keeps running normally.
    Busy { reason: SafeStopBusy, detail: String, retry_after: std::time::Duration },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SafeStopBusy {
    WritesInProgress,
    CheckpointFailed,
    AnotherRequestInProgress,
}

pub(crate) trait DaemonLifecyclePort: Send + Sync {
    /// Brings the daemon to a safe point and begins its exit, or reports why it could not within
    /// `deadline` and keeps running. Idempotent: a repeat while stopping is answered as such.
    /// Never forces anything.
    fn request_safe_stop(&self, deadline: std::time::Duration) -> BoxFuture<'_, SafeStopOutcome>;

    /// Requests graceful shutdown -- fire-and-forget, matching
    /// `DaemonState.shutdown_tx`'s own "a send error just means every
    /// receiver is already gone" semantics.
    fn request_shutdown(&self);
}
