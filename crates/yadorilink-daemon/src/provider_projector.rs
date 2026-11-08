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
//! It is woken by writes to the replica database (obligations only ever appear through one), with a
//! slow backstop, and retries a failed pass with a growing delay; no admission seam needs to know
//! about this task.

use std::sync::Arc;
use std::time::Duration;

use yadorilink_sync_sqlite::provider::ProviderRoot;
use yadorilink_sync_sqlite::provider_projector::NotReady;

use crate::daemon_state::DaemonState;
use crate::provider_publication::PublicationDriver;

/// The first retry delay after a failed pass; each further consecutive failure doubles it up to
/// [`IDLE_BACKSTOP`] (see [`Backoff`]).
const POLL: Duration = Duration::from_millis(250);
/// How long an idle projector waits for a write before looking anyway. Obligations only appear
/// through writes to the replica database (the receive commit's triggers, a root declaration),
/// and every such write wakes the projector, so this is a safety net, not the latency.
const IDLE_BACKSTOP: Duration = Duration::from_secs(30);
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
    if tick.failed {
        // A failed batch or namespace check may clear without any write to wake the next wait.
        POLL
    } else if tick.projected > 0 {
        YIELD
    } else {
        POLL
    }
}

/// Spacing of retries while passes keep failing (a batch, the namespace check, or the root list):
/// the first retry waits [`POLL`], each further consecutive failure doubles the wait up to
/// [`IDLE_BACKSTOP`], and any pass that does not fail starts over. A fault that lasts (a root that
/// cannot be listed, a database that stays unreadable) therefore costs a few wakeups a minute, not
/// four a second. A write to the replica database ends a retry wait early, so recovery that
/// arrives as a write is not delayed by the backoff, but never sooner than [`POLL`] after the wait
/// began. A pass that fails and writes every time it runs therefore retries at that first rate
/// (no worse than before the backoff), and its delay still grows.
#[derive(Debug)]
pub(crate) struct Backoff(Duration);

impl Backoff {
    pub(crate) fn new() -> Self {
        Self(POLL)
    }

    /// The wait before the next retry; the one after it is twice as long, up to the backstop.
    fn next(&mut self) -> Duration {
        let wait = self.0;
        self.0 = (self.0 * 2).min(IDLE_BACKSTOP);
        wait
    }

    fn reset(&mut self) {
        self.0 = POLL;
    }
}

/// What one tick did for one root.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Tick {
    pub(crate) projected: usize,
    pub(crate) became_ready: bool,
    /// A batch, the namespace check or marking the namespace ready failed: look again soon even
    /// though no write may arrive.
    pub(crate) failed: bool,
}

/// One pass over one root: ONE batch (the caller yields between passes), then, for a root that is
/// not ready and has nothing open, the verification of the initial build.
pub(crate) fn tick_root(state: &DaemonState, root: &ProviderRoot, batch: usize) -> Tick {
    let repo = state.replica_coordinator.provider_repository();
    let mut tick = Tick::default();
    match state.replica_coordinator.provider_writes().project_batch(&root.group_id, batch) {
        Ok(n) => tick.projected += n,
        Err(error) => {
            tracing::warn!(root = %root.root_id, %error, "the provider projector failed a batch");
            tick.failed = true;
            return tick;
        }
    }
    if !root.namespace_ready {
        match repo.verify_namespace(&root.group_id) {
            Ok(None) => match state
                .replica_coordinator
                .provider_writes()
                .set_namespace_ready(&root.root_id, true)
            {
                Ok(_) => tick.became_ready = true,
                Err(error) => {
                    tracing::warn!(%error, "could not mark the namespace ready");
                    tick.failed = true;
                }
            },
            Ok(Some(NotReady::NotInstalled | NotReady::OpenObligations(_))) => {}
            Ok(Some(reason)) => {
                tracing::warn!(root = %root.root_id, ?reason, "the namespace does not verify yet");
            }
            Err(error) => {
                tracing::warn!(%error, "the namespace verification failed");
                tick.failed = true;
            }
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
    /// `retry`: a root's tick failed, so the next pass is due after `delay` whether or not a write
    /// arrives.
    Done { roots: usize, delay: Duration, retry: bool },
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
    let mut retry = false;
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
        retry |= tick.failed;
    }
    Ok(Pass::Done { roots: count, delay, retry })
}

/// A provider group has no link runtime to continue its recorded rebootstrap when the folder is
/// watched again, so the projector continues it once at start.
pub(crate) fn resume_recorded_rebootstraps(state: &Arc<DaemonState>) {
    if let Ok(roots) = state.replica_coordinator.provider_repository().list_declared_roots() {
        for root in roots {
            crate::native_rebootstrap::spawn_resume(state.clone(), root.group_id);
        }
    }
}

/// Runs for the life of the daemon.
pub(crate) async fn run(
    state: Arc<DaemonState>,
    publication: Arc<PublicationDriver>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let batch = state.tuning().provider_projector_batch;
    let mut writes = state.replica_coordinator.database().subscribe_data_changes();
    let mut backoff = Backoff::new();
    resume_recorded_rebootstraps(&state);
    loop {
        // Marked before the pass reads anything: a write that lands during the pass wakes the
        // next wait.
        writes.borrow_and_update();
        let outcome = pass(&state, batch, |root| publication.kick(root)).await?;
        wait_after(&outcome, &mut writes, &mut backoff).await;
    }
}

/// How the loop waits after a pass.
pub(crate) async fn wait_after(
    outcome: &Pass,
    writes: &mut tokio::sync::watch::Receiver<u64>,
    backoff: &mut Backoff,
) {
    match outcome {
        // A build is still producing batches: pace them, the writer is shared.
        Pass::Done { delay, .. } if *delay == YIELD => {
            backoff.reset();
            tokio::time::sleep(*delay).await;
        }
        // A tick failed or the roots could not be listed: the cause may clear without a write, so
        // look again after a growing delay, or at once when a write arrives.
        Pass::Done { retry: true, .. } | Pass::RootsUnreadable => {
            let started = tokio::time::Instant::now();
            let wait = backoff.next();
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                changed = writes.changed() => {
                    // A closed channel would return at once forever: keep the delay.
                    if changed.is_err() {
                        tokio::time::sleep(wait).await;
                    }
                }
            }
            // A write ends the wait early, but never sooner than the first retry delay: a failing
            // pass that itself writes would otherwise run back to back.
            tokio::time::sleep_until(started + POLL).await;
        }
        // Nothing open: wait for the next write instead of probing on a timer.
        Pass::Done { .. } => {
            backoff.reset();
            let _ = tokio::time::timeout(IDLE_BACKSTOP, writes.changed()).await;
        }
    }
}

#[cfg(test)]
mod tests;
