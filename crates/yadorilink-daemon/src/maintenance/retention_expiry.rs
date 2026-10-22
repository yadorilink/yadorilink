//! `RetentionExpiryJob` -- runs `LinkRuntimeController::run_retention_
//! expiry_sweep` for every currently-registered link. Sync and
//! blocking-offloaded (not `async`): the sweep itself is plain `SyncState`
//! SQLite calls, no network I/O, matching this crate's other
//! synchronous-on-the-async-runtime maintenance sweeps -- see
//! `run_blocking_sweep_offloaded`'s own doc for why it still needs
//! `block_in_place` on a multi-thread runtime despite being "just SQLite".
//!
//! Unifies what used to be two separate call sites doing the same work:
//! a blocking call ahead of the spawn (the startup-immediate run) and an
//! identical call inside the spawned loop (the periodic run). Both now
//! go through this one `run_once` -- see `maintenance_coordinator.rs`'s
//! own spawn site for where each is called from.
//!
//! Holds `Arc<LinkRuntimeController>` rather than `Arc<DaemonState>`:
//! this sweep already goes through the controller today (`run_retention_
//! expiry_sweep` is one of its methods), so this is the narrowest real
//! dependency, not a new port.

use std::sync::Arc;

use crate::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use crate::daemon_state::run_blocking_sweep_offloaded;

#[derive(Clone)]
pub(crate) struct RetentionExpiryJob {
    controller: Arc<LinkRuntimeController>,
}

impl RetentionExpiryJob {
    pub(crate) fn new(controller: Arc<LinkRuntimeController>) -> Self {
        Self { controller }
    }

    pub(crate) fn run_once(&self) {
        run_blocking_sweep_offloaded(|| self.controller.run_retention_expiry_sweep());
    }
}
