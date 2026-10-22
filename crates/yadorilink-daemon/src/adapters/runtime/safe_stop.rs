//! Safe stop: bring the daemon to a point where nothing is half written, then let it exit
//! through the ordinary graceful shutdown.
//!
//! The steps, in order, each bounded by one deadline:
//!
//! 1. Pause every link's root lease (`RootLease::begin_quiesce`): no new link operation is
//!    admitted. This is the same admission gate the final shutdown closes, held reversibly.
//! 2. Wait for the operations already admitted to finish (`RootLease::wait_drained`).
//! 3. Fold the sync database's and the block index's write-ahead logs into their main files.
//! 4. Commit: request the graceful shutdown that every other stop uses. From here the daemon
//!    exits with status 0 and its locks are released by the process ending.
//!
//! Before step 1 the link registry's start gate is closed and the starts already under way are
//! waited out, so no link can become Ready after the leases are taken. Both the gate and the
//! pause are RAII guards: any failure, timeout or cancellation of the request reopens them.
//!
//! If step 2 or 3 does not finish in time, the pause is lifted again and the answer is `Busy`
//! with a retry hint; the daemon keeps running as it was. Nothing is cut off or killed.
//! Concurrent requests are serialized, and a request after the commit is answered "already
//! stopping", so repeating the call is always safe.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::application::ports::{SafeStopBusy, SafeStopOutcome};
use crate::daemon_state::DaemonState;
use crate::link_registry::LinkRegistry;

/// What a busy answer tells the caller to wait before asking again.
const RETRY_AFTER: Duration = Duration::from_secs(5);

/// A point between two steps, where a test can make the stop fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    Paused,
    Drained,
    Checkpointed,
}

pub(crate) trait StepHook: Send + Sync {
    /// `Err` makes the stop give up at this point, as a failure there would.
    fn after(&self, step: Step) -> Result<(), String>;
}

struct NoHook;

impl StepHook for NoHook {
    fn after(&self, _step: Step) -> Result<(), String> {
        Ok(())
    }
}

pub(crate) async fn request(state: &Arc<DaemonState>, deadline: Duration) -> SafeStopOutcome {
    request_with(state, deadline, &NoHook).await
}

/// Pauses the links through the registry: closes the start gate so no link can begin starting,
/// waits out the starts already under way, and only then takes the leases. Every link that will
/// ever be Ready during this stop is therefore in the snapshot.
pub(crate) async fn request_with(
    state: &Arc<DaemonState>,
    deadline: Duration,
    hook: &dyn StepHook,
) -> SafeStopOutcome {
    if *state.shutdown_tx.borrow() {
        return SafeStopOutcome::Stopping { already_in_progress: true };
    }
    let started = Instant::now();
    let gate = LinkRegistry::close_start_gate(&state.links);
    if tokio::time::timeout(deadline, state.links.wait_no_starting()).await.is_err() {
        return busy(
            SafeStopBusy::WritesInProgress,
            "a link that is starting did not finish in time",
        );
    }
    let leases = state.links.ready_root_leases();
    let outcome = run(state, deadline.saturating_sub(started.elapsed()), hook, leases).await;
    if matches!(outcome, SafeStopOutcome::Stopping { already_in_progress: false }) {
        // Committed: the process is shutting down, and no link may start meanwhile.
        gate.keep_closed();
    }
    outcome
}

/// The leases of the links paused by a stop. Dropping it lifts the pause, so a stop that fails,
/// gives up or is cancelled never leaves a link paused; only [`Self::disarm`] keeps it.
struct QuiesceGuard(Leases);

impl QuiesceGuard {
    fn begin(leases: Leases) -> Self {
        for lease in &leases {
            lease.begin_quiesce();
        }
        Self(leases)
    }

    /// Keeps the pause: the ordinary graceful shutdown takes over from here.
    fn disarm(mut self) {
        self.0.clear();
    }
}

impl Drop for QuiesceGuard {
    fn drop(&mut self) {
        for lease in &self.0 {
            lease.end_quiesce();
        }
    }
}

fn busy(reason: SafeStopBusy, detail: impl Into<String>) -> SafeStopOutcome {
    SafeStopOutcome::Busy { reason, detail: detail.into(), retry_after: RETRY_AFTER }
}

type Leases = Vec<Arc<yadorilink_root_authority::root_commit::RootLease>>;

/// [`request`] over the given links' leases, with a hook between the steps.
pub(crate) async fn run(
    state: &Arc<DaemonState>,
    deadline: Duration,
    hook: &dyn StepHook,
    leases: Leases,
) -> SafeStopOutcome {
    let started = Instant::now();
    let remaining = || deadline.saturating_sub(started.elapsed());

    // A stop that is already under way (a plain shutdown, a signal, an earlier safe stop) needs
    // nothing more from this request.
    if *state.shutdown_tx.borrow() {
        return SafeStopOutcome::Stopping { already_in_progress: true };
    }
    let Ok(mut committed) =
        tokio::time::timeout(remaining(), state.safe_stop_committed.lock()).await
    else {
        return busy(
            SafeStopBusy::AnotherRequestInProgress,
            "another safe-stop request is still waiting for in-flight operations",
        );
    };
    if *committed || *state.shutdown_tx.borrow() {
        return SafeStopOutcome::Stopping { already_in_progress: true };
    }

    let paused = QuiesceGuard::begin(leases);
    if let Err(detail) = hook.after(Step::Paused) {
        return busy(SafeStopBusy::WritesInProgress, detail);
    }

    let drained = tokio::time::timeout(
        remaining(),
        futures_util::future::join_all(paused.0.iter().map(|lease| lease.wait_drained())),
    )
    .await;
    if drained.is_err() {
        return busy(
            SafeStopBusy::WritesInProgress,
            "a write in progress did not reach a safe point in time",
        );
    }
    if let Err(detail) = hook.after(Step::Drained) {
        return busy(SafeStopBusy::WritesInProgress, detail);
    }

    if let Err(detail) = checkpoint(state, remaining()).await {
        return busy(SafeStopBusy::CheckpointFailed, detail);
    }
    if let Err(detail) = hook.after(Step::Checkpointed) {
        return busy(SafeStopBusy::CheckpointFailed, detail);
    }

    // Past this point nothing can fail: the ordinary graceful shutdown takes over and closes
    // admission for good. The lease clones are released first so that shutdown owns each
    // link's runtime outright.
    paused.disarm();
    *committed = true;
    tracing::info!("safe stop: links are at a safe point and checkpointed; shutting down");
    // `send_replace`: the value must change even if no receiver is listening any more.
    state.shutdown_tx.send_replace(true);
    SafeStopOutcome::Stopping { already_in_progress: false }
}

/// Folds the write-ahead logs of the sync database and the block index into their main files.
pub(crate) async fn checkpoint(state: &Arc<DaemonState>, within: Duration) -> Result<(), String> {
    let database = state.replica_coordinator.database();
    let block_store = state.block_store.clone();
    let work = tokio::task::spawn_blocking(move || -> Result<(), String> {
        database.checkpoint_truncate().map_err(|e| format!("sync database: {e}"))?;
        block_store.checkpoint().map_err(|e| format!("block index: {e}"))
    });
    match tokio::time::timeout(within, work).await {
        Ok(Ok(result)) => result,
        Ok(Err(joined)) => Err(format!("checkpoint task failed: {joined}")),
        Err(_) => Err("the checkpoint did not finish in time".to_string()),
    }
}

#[cfg(test)]
mod tests;
