//! `DegradedLinkRecheckJob` -- a dedicated re-check of every
//! currently-Degraded link whose backoff window has elapsed. Kept on its
//! own task (see `maintenance_coordinator.rs`'s spawn site) rather than
//! folded into a slower housekeeping cadence: the whole point of a link
//! degrading and recovering quickly is getting checked again promptly.
//! It sleeps until the earliest re-check is due (and at least
//! [`MIN_GAP`] between runs), and while no link is degraded it waits for
//! one to be, instead of waking every few seconds to find nothing. Infallible -- no error path, matching
//! `DaemonState::recheck_degraded_links` itself.
//!
//! Holds `Arc<LinkRuntimeController>` rather than `Arc<DaemonState>`:
//! `recheck_degraded_links` is now exposed as
//! `LinkRuntimeController::recheck_degraded_links` (a thin delegate to
//! the same `DaemonState` method, since `links`/`governance_config`
//! aren't behind any narrower port), so this job holds the same
//! dependency its sibling maintenance jobs
//! (`RetentionExpiryJob`/`DiskReconcileBackstopJob`) already do rather
//! than a bespoke `Arc<DaemonState>`.

use std::sync::Arc;

use crate::adapters::runtime::link_runtime_controller::LinkRuntimeController;

pub(crate) struct DegradedLinkRecheckJob {
    controller: Arc<LinkRuntimeController>,
}

/// The least time between two runs: a link still under pressure is rescheduled further out each
/// time, and this keeps a due time in the past from turning into a hot loop.
pub(crate) const MIN_GAP: std::time::Duration = std::time::Duration::from_secs(2);

impl DegradedLinkRecheckJob {
    /// Returns when a re-check may be due (see
    /// [`LinkRuntimeController::wait_for_degraded_recheck`]).
    pub(crate) async fn wait_until_due(&self) {
        self.controller.wait_for_degraded_recheck(MIN_GAP).await;
    }

    pub(crate) fn new(controller: Arc<LinkRuntimeController>) -> Self {
        Self { controller }
    }

    pub(crate) fn run_once(&self) {
        self.controller.recheck_degraded_links();
    }
}
