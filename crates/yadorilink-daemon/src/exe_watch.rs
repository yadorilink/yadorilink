//! Stops the daemon cleanly when the installation it runs from is deleted or replaced.
//!
//! An app bundle is removed or swapped as a whole by its updater or by the user, and the daemon of
//! the old bundle must not keep syncing from files that are gone. This polls the installation's
//! path (the bundle, or the executable outside a bundle) and, when it has been missing for several
//! polls in a row, asks the daemon to stop through the same safe-stop request a person or an
//! updater uses: nothing is killed, and a stop that cannot happen yet (`busy`) is simply asked
//! again at the next poll.
//!
//! Conservative on purpose. Only the filesystem's own "not found" counts as missing: a look that
//! fails for another reason (permissions, I/O) is unverifiable, never a stop and never a miss.
//! Replacement under the same name is not detected here by design; an updater asks for the safe
//! stop itself. A path that exists is never a reason to stop, whatever happened to what
//! is behind it: an atomic replace in place (a new file renamed over the old, or the old moved
//! aside and the new moved in) leaves the path missing for at most an instant, so a single poll
//! seeing it missing is not enough and several consecutive ones are required.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::application::ports::{DaemonLifecyclePort, SafeStopOutcome};

#[derive(Debug, Clone, Copy)]
pub struct ExeWatchConfig {
    /// Time between two looks at the path.
    pub interval: Duration,
    /// How many looks in a row must find it missing.
    pub misses_needed: u32,
    /// The deadline handed to the safe-stop request.
    pub stop_deadline: Duration,
    /// Each `busy` answer doubles the wait before the next request, up to this. A safe-stop
    /// attempt pauses the links while it waits, so repeating it at a fixed short interval
    /// would keep them paused most of the time.
    pub busy_backoff_cap: Duration,
}

impl Default for ExeWatchConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(15),
            misses_needed: 3,
            stop_deadline: Duration::from_secs(30),
            busy_backoff_cap: Duration::from_secs(300),
        }
    }
}

/// What one look at the installation's path found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathProbe {
    /// Something is at the path.
    Present,
    /// The filesystem answered that nothing is there.
    Missing,
    /// The look itself failed (permissions, I/O error): nothing is known about the path.
    Unverifiable,
}

/// Looks at `path`. A link is a path that exists even if its target does not: only the
/// installation's own name matters here. Only an authoritative "not there" is `Missing`; any
/// other failure to look says nothing about whether the installation is still installed.
fn probe_on_disk(path: &Path) -> PathProbe {
    match std::fs::symlink_metadata(path) {
        Ok(_) => PathProbe::Present,
        Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
            PathProbe::Missing
        }
        Err(_) => PathProbe::Unverifiable,
    }
}

/// Watches `path` until the daemon is stopping. Returns once a safe stop has been accepted.
pub(crate) async fn watch(
    path: PathBuf,
    config: ExeWatchConfig,
    lifecycle: Arc<dyn DaemonLifecyclePort>,
) {
    watch_with(path, config, lifecycle, probe_on_disk).await;
}

pub(crate) async fn watch_with(
    path: PathBuf,
    config: ExeWatchConfig,
    lifecycle: Arc<dyn DaemonLifecyclePort>,
    probe: impl Fn(&Path) -> PathProbe,
) {
    let mut misses = 0u32;
    let mut delay = config.interval;
    let mut unverifiable_reported = false;
    loop {
        tokio::time::sleep(delay).await;
        match probe(&path) {
            PathProbe::Present => {
                misses = 0;
                delay = config.interval;
                unverifiable_reported = false;
                continue;
            }
            PathProbe::Unverifiable => {
                // Fail safe: never a reason to stop, and it breaks a run of misses because
                // absence was not observed at this look. Keep looking at the normal pace.
                misses = 0;
                if !unverifiable_reported {
                    unverifiable_reported = true;
                    tracing::warn!(
                        path = %path.display(),
                        "cannot tell whether the installation this daemon runs from is still there; \
                         not stopping"
                    );
                }
                continue;
            }
            PathProbe::Missing => unverifiable_reported = false,
        }
        misses = misses.saturating_add(1);
        if misses < config.misses_needed {
            continue;
        }
        tracing::warn!(
            path = %path.display(),
            "the installation this daemon runs from is gone; stopping safely"
        );
        match lifecycle.request_safe_stop(config.stop_deadline).await {
            SafeStopOutcome::Stopping { .. } => return,
            SafeStopOutcome::Busy { reason, detail, .. } => {
                delay = (delay * 2).min(config.busy_backoff_cap).max(config.interval);
                tracing::warn!(
                    ?reason,
                    detail,
                    retry_in_secs = delay.as_secs(),
                    "safe stop is not possible yet; asking again later"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests;
