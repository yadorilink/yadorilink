//! `GcIdleJob` -- the idle-triggered GC scheduler's single tick.
//! Interval-only -- no startup-immediate run.
//!
//! Holds a full `Arc<DaemonState>`: `gc::maybe_run_idle_sweep` takes the
//! full state today (idle-duration tracking, the sync/block-store index,
//! `gc` scheduling state), and is not behind a narrower port.

use std::sync::Arc;

use crate::daemon_state::DaemonState;

pub(crate) struct GcIdleJob {
    state: Arc<DaemonState>,
}

impl GcIdleJob {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }

    pub(crate) async fn run_once(&self) {
        let state = &self.state;
        match crate::gc::maybe_run_idle_sweep(state, crate::gc::GC_IDLE_THRESHOLD).await {
            None => {}
            Some(Ok(report)) if report.blocks_deleted > 0 => {
                tracing::info!(
                    blocks_deleted = report.blocks_deleted,
                    bytes_reclaimed = report.bytes_reclaimed,
                    "idle-triggered GC sweep reclaimed blocks"
                );
            }
            Some(Ok(_)) => {}
            // Benign: either another sweep (on-demand or this same loop's
            // previous still-running iteration -- shouldn't happen given
            // the `.await` above, but the invariant holds either way) is
            // in flight, or activity resumed between the idle check and
            // the attempt.
            Some(Err(
                crate::gc::GcTriggerError::AlreadyRunning
                | crate::gc::GcTriggerError::SyncBurstInProgress,
            )) => {}
            Some(Err(e @ crate::gc::GcTriggerError::Failed(_))) => {
                tracing::warn!(error = %e, "idle-triggered GC sweep failed");
            }
        }
    }
}
