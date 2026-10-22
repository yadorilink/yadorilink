//! `DegradedLinkRecheckJob` -- a dedicated, short-interval poll for every
//! currently-Degraded link whose backoff window has elapsed. Kept on its
//! own fast, fixed 2s poll (see `maintenance_coordinator.rs`'s own spawn
//! site) rather than folded into a slower housekeeping cadence: the
//! whole point of a link degrading and recovering quickly is getting
//! checked again promptly. Infallible -- no error path, matching
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

impl DegradedLinkRecheckJob {
    pub(crate) fn new(controller: Arc<LinkRuntimeController>) -> Self {
        Self { controller }
    }

    pub(crate) fn run_once(&self) {
        self.controller.recheck_degraded_links();
    }
}
