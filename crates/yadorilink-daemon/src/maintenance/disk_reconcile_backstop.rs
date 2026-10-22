//! `DiskReconcileBackstopJob` -- a periodic, filesystem-watcher-event-
//! *independent* disk-authoritative reconcile: the eventual-consistency
//! backstop for a local write whose OS watcher event never arrives at
//! all. See `LinkRuntimeController::run_disk_reconcile_backstop_sweep`'s
//! own doc for the full rationale (add-only, skips paused/orphaned
//! links) -- this
//! job is a thin wrapper, not a new implementation.
//!
//! Interval-only -- no startup-immediate run: `start_link_watch`'s own
//! initial `scan_existing_files` already indexes everything present on
//! disk at daemon start, so an immediate add-only pass here would find
//! nothing new; the first sweep only matters once a watcher has had a
//! chance to miss something.
//!
//! Holds `Arc<LinkRuntimeController>` rather than `Arc<DaemonState>`:
//! this sweep already goes through the controller today, matching
//! `RetentionExpiryJob`'s own reasoning.

use std::sync::Arc;

use crate::adapters::runtime::link_runtime_controller::LinkRuntimeController;

#[derive(Clone)]
pub(crate) struct DiskReconcileBackstopJob {
    controller: Arc<LinkRuntimeController>,
}

impl DiskReconcileBackstopJob {
    pub(crate) fn new(controller: Arc<LinkRuntimeController>) -> Self {
        Self { controller }
    }

    pub(crate) async fn run_once(&self) {
        self.controller.run_disk_reconcile_backstop_sweep().await;
    }
}
