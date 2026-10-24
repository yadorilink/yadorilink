//! The daemon-level task that projects provider groups.
//!
//! A provider root has no directory, so no link runtime ever starts for it and the engine's lanes
//! refuse it. This task is the only consumer of its group's projection obligations: for the
//! initial build of the namespace and for every later peer edit it writes the rows (and, through
//! the commit-time reconcile of the same transaction, the structural directories, the change
//! events and the content fence), then kicks the publication driver for what became pending. When
//! the initial build is complete and verified it marks the namespace queryable, which is what lets
//! the host register the domain.
//!
//! It polls for open obligations at a short interval instead of being woken by the admission:
//! the idle cost is one indexed existence probe per root, and no admission seam needs to know
//! about this task.

use std::sync::Arc;
use std::time::Duration;

use yadorilink_sync_sqlite::provider::ProviderRoot;
use yadorilink_sync_sqlite::provider_projector::NotReady;

use crate::daemon_state::DaemonState;
use crate::provider_publication::PublicationDriver;

/// How often an idle projector looks for open obligations.
const POLL: Duration = Duration::from_millis(250);
/// The pause between two batches of a build, so the writer is free for receive commits and the other
/// roots between them (a batch holds the single writer for its whole transaction).
const YIELD: Duration = Duration::from_millis(20);
/// Obligations per transaction. A 5 000-row batch held the writer about 0.8 s on the slowest measured
/// host; 1 000 rows hold it about 0.16 s. The tuning's `provider_projector_batch` overrides it.
const DEFAULT_BATCH: usize = 1_000;

/// The batch size from the environment value, falling back to the default for anything that is not a
/// positive number.
pub(crate) fn batch_from(value: Option<&str>) -> usize {
    value.and_then(|v| v.trim().parse::<usize>().ok()).filter(|n| *n > 0).unwrap_or(DEFAULT_BATCH)
}

/// How long to wait before the next pass: a short yield while a build is still producing batches,
/// the poll interval once idle.
pub(crate) fn next_delay(tick: &Tick) -> Duration {
    if tick.projected > 0 {
        YIELD
    } else {
        POLL
    }
}

/// What one tick did for one root.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Tick {
    pub(crate) projected: usize,
    pub(crate) became_ready: bool,
}

/// One pass over one root: ONE batch (the caller yields between passes), then, for a root that is
/// not ready and has nothing open, the verification of the initial build.
pub(crate) fn tick_root(state: &DaemonState, root: &ProviderRoot, batch: usize) -> Tick {
    let repo = state.replica_coordinator.provider_repository();
    let mut tick = Tick::default();
    match repo.project_batch(&root.group_id, batch) {
        Ok(n) => tick.projected += n,
        Err(error) => {
            tracing::warn!(root = %root.root_id, %error, "the provider projector failed a batch");
            return tick;
        }
    }
    if !root.namespace_ready {
        match repo.verify_namespace(&root.group_id) {
            Ok(None) => match repo.set_namespace_ready(&root.root_id, true) {
                Ok(_) => tick.became_ready = true,
                Err(error) => tracing::warn!(%error, "could not mark the namespace ready"),
            },
            Ok(Some(NotReady::NotInstalled | NotReady::OpenObligations(_))) => {}
            Ok(Some(reason)) => {
                tracing::warn!(root = %root.root_id, ?reason, "the namespace does not verify yet");
            }
            Err(error) => tracing::warn!(%error, "the namespace verification failed"),
        }
    }
    tick
}

/// What one pass over the declared roots found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Pass {
    /// The roots could not be listed. Nothing was projected and nothing is known about the roots:
    /// the caller retries at the poll interval; this is never a pass over zero roots.
    RootsUnreadable,
    /// `roots` declared roots were ticked; wait `delay` before the next pass.
    Done { roots: usize, delay: Duration },
}

/// One pass over every declared root. `kick` is told which roots got work or became ready.
pub(crate) async fn pass(
    state: &Arc<DaemonState>,
    batch: usize,
    kick: impl Fn(&str),
) -> Result<Pass, tokio::task::JoinError> {
    let roots = match state.replica_coordinator.provider_repository().list_declared_roots() {
        Ok(roots) => roots,
        Err(error) => {
            tracing::warn!(%error, "the provider projector could not list the provider roots");
            return Ok(Pass::RootsUnreadable);
        }
    };
    let mut delay = POLL;
    let count = roots.len();
    for root in roots {
        let (worker_state, worker_root) = (state.clone(), root.clone());
        let tick =
            tokio::task::spawn_blocking(move || tick_root(&worker_state, &worker_root, batch))
                .await?;
        // A change nobody announced (a pin changed what the OS may do with an item) is signalled
        // by the publication driver like any other.
        let unannounced = matches!(
            state.replica_coordinator.provider_repository().unannounced_changes(&root.root_id),
            Ok(Some(_))
        );
        if tick.projected > 0 || tick.became_ready || unannounced {
            kick(&root.root_id);
        }
        delay = delay.min(next_delay(&tick));
    }
    Ok(Pass::Done { roots: count, delay })
}

/// Runs for the life of the daemon.
pub(crate) async fn run(
    state: Arc<DaemonState>,
    publication: Arc<PublicationDriver>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let batch = state.tuning().provider_projector_batch;
    loop {
        let delay = match pass(&state, batch, |root| publication.kick(root)).await? {
            Pass::Done { delay, .. } => delay,
            Pass::RootsUnreadable => POLL,
        };
        tokio::time::sleep(delay).await;
    }
}

#[cfg(test)]
mod tests;
