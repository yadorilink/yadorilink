//! Owns this device's observability-facing runtime state: the
//! shell-integration status-push fan-out, which essential tasks are still
//! alive, and the bounded in-memory connection-trace/transfer-progress/
//! recent-error logs surfaced by `yadorilink status`/`connectivity-doctor`.
//! Every field here is transient (never persisted) -- a fresh process
//! starts with none of it and that is fine, since it all describes only
//! this run's own recent activity.
//!
//! Every field is private, reached only through this type's own methods --
//! `connection_traces`/`transfer_progress`/`recent_errors` were already
//! narrow, self-contained types (own their own locking, never leak a raw
//! guard) before this, so their methods below are thin forwards, not new
//! logic.

use std::collections::HashMap;
use std::sync::Mutex;

use tokio::sync::broadcast;
use yadorilink_ipc_proto::shellipc::StatusPush;

use crate::connection_trace::{
    AddressClass, AttemptOutcome, CandidateSource, ConnectionAttemptTrace, ConnectionTraceLog,
};
use crate::recent_errors::{RecentErrorLog, RecentErrorRecord};
use crate::transfer_progress::{
    ActiveTransferProgress, LinkProgressRollup, TransferProgressGuard, TransferProgressTracker,
};

/// One essential task's liveness, as returned by
/// [`RuntimeTelemetry::task_snapshot`].
pub struct TaskLivenessEntry {
    pub name: String,
    pub alive: bool,
}

pub struct RuntimeTelemetry {
    /// Fan-out for the shell-integration IPC: every connected
    /// shell-extension client subscribes and receives status pushes as
    /// local changes are indexed, instead of only ever answering queries.
    status_push_tx: broadcast::Sender<StatusPush>,
    /// name -> still running, for every essential task `main.rs`
    /// supervises together. Populated from the outside (`main.rs` sets
    /// this as it spawns/observes the exit of each task) since
    /// `DaemonState` doesn't own those tasks itself; read by the control
    /// socket's health handler.
    task_liveness: Mutex<HashMap<String, bool>>,
    /// Bounded history of recent connection attempts
    /// (`crate::connection_trace`), feeding both the raw trace listing and
    /// the connectivity-doctor summary.
    connection_traces: ConnectionTraceLog,
    /// Bounded, in-memory per-active-transfer progress state
    /// (`crate::transfer_progress`), updated as blocks land during
    /// hydration and torn down automatically once a transfer completes,
    /// fails, or times out (its RAII guard's `Drop`).
    transfer_progress: TransferProgressTracker,
    /// Bounded, in-memory recent sync-error ring buffer
    /// (`crate::recent_errors`), surfaced in `yadorilink status` so a
    /// stuck or failing sync is diagnosable without reading logs.
    recent_errors: RecentErrorLog,
    /// Files each link's scans could not read and that need the person. Written by the
    /// capture scans, read by status; rebuilt by the first scan after a restart.
    unreadable_files: std::sync::Arc<yadorilink_local_capture::unreadable::UnreadableFileLedger>,
    /// Delta admission outcomes and bytes/messages served to peers, for `/metrics`.
    replication: std::sync::Arc<crate::native_replication_driver::ReplicationCounters>,
}

impl RuntimeTelemetry {
    pub(crate) fn new(status_push_tx: broadcast::Sender<StatusPush>) -> Self {
        Self {
            status_push_tx,
            task_liveness: Mutex::new(HashMap::new()),
            connection_traces: crate::connection_trace::ConnectionTraceLog::new(),
            transfer_progress: crate::transfer_progress::TransferProgressTracker::new(),
            recent_errors: crate::recent_errors::RecentErrorLog::new(),
            unreadable_files: std::sync::Arc::default(),
            replication: std::sync::Arc::default(),
        }
    }

    pub fn replication_counters(
        &self,
    ) -> std::sync::Arc<crate::native_replication_driver::ReplicationCounters> {
        self.replication.clone()
    }

    /// Records whether essential task `name` is currently running.
    pub fn set_task_alive(&self, name: &str, alive: bool) {
        self.task_liveness
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(name.to_string(), alive);
    }

    /// `name`'s last-recorded liveness, or `default_if_unknown` if `main.rs`
    /// has never reported on it (e.g. a task that hasn't been spawned in
    /// this build/configuration at all).
    pub fn task_alive(&self, name: &str, default_if_unknown: bool) -> bool {
        self.task_liveness
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(name)
            .copied()
            .unwrap_or(default_if_unknown)
    }

    /// Every task's last-recorded liveness.
    pub fn task_snapshot(&self) -> Vec<TaskLivenessEntry> {
        self.task_liveness
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|(name, alive)| TaskLivenessEntry { name: name.clone(), alive: *alive })
            .collect()
    }

    /// The ledger the capture scans report unreadable files into.
    pub fn unreadable_files_handle(
        &self,
    ) -> std::sync::Arc<yadorilink_local_capture::unreadable::UnreadableFileLedger> {
        self.unreadable_files.clone()
    }

    /// `group_id`'s files that cannot be read and need the person.
    pub fn unreadable_files(
        &self,
        group_id: &str,
    ) -> Vec<yadorilink_local_capture::unreadable::UnreadableFile> {
        self.unreadable_files.needing_user(group_id)
    }

    /// Pushes a shell-integration status update to every currently
    /// subscribed shell-extension client -- a no-op (not an error) if none
    /// are connected yet.
    pub fn push_status(&self, push: StatusPush) {
        let _ = self.status_push_tx.send(push);
    }

    /// Subscribes to the shell-integration status-push fan-out.
    pub fn subscribe_status(&self) -> broadcast::Receiver<StatusPush> {
        self.status_push_tx.subscribe()
    }

    // --- connection_traces ------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub fn record_connection_attempt(
        &self,
        peer_device_id: impl Into<String>,
        candidate_source: CandidateSource,
        address_class: AddressClass,
        outcome: AttemptOutcome,
        latency_ms: u64,
        failure_category: impl Into<String>,
        selected: bool,
        authorized: Option<bool>,
    ) {
        self.connection_traces.record(
            peer_device_id,
            candidate_source,
            address_class,
            outcome,
            latency_ms,
            failure_category,
            selected,
            authorized,
        );
    }

    /// Most recent connection-attempt entries first, optionally filtered to
    /// one peer.
    pub fn recent_connection_attempts(
        &self,
        peer_device_id: Option<&str>,
    ) -> Vec<ConnectionAttemptTrace> {
        self.connection_traces.recent(peer_device_id)
    }

    // --- transfer_progress --------------------------------------------

    /// Registers a new active transfer and returns an RAII guard that
    /// removes it once dropped.
    pub fn begin_transfer(
        &self,
        group_id: impl Into<String>,
        path: impl Into<String>,
        bytes_total: u64,
        blocks_total: u64,
    ) -> TransferProgressGuard {
        self.transfer_progress.begin(group_id, path, bytes_total, blocks_total)
    }

    /// A cheap-clone handle to the tracker, for a caller that needs to pass
    /// it into a spawned worker/task rather than call through `&self` --
    /// still only reaches `TransferProgressTracker`'s own methods, never a
    /// raw lock.
    pub fn transfer_progress_handle(&self) -> TransferProgressTracker {
        self.transfer_progress.clone()
    }

    pub fn active_transfer_snapshot(&self) -> Vec<ActiveTransferProgress> {
        self.transfer_progress.snapshot()
    }

    /// Records one more successfully-fetched-and-stored block for the
    /// `(group_id, path)` transfer -- a no-op if that transfer's guard has
    /// already been dropped.
    pub fn record_transfer_block_done(
        &self,
        group_id: &str,
        path: &str,
        bytes: u64,
        peer_id: &str,
    ) {
        self.transfer_progress.record_block_done(group_id, path, bytes, peer_id);
    }

    pub fn active_transfer_count(&self) -> usize {
        self.transfer_progress.active_transfer_count()
    }

    pub fn transfer_bytes_total(&self) -> u64 {
        self.transfer_progress.transfer_bytes_total()
    }

    pub fn link_transfer_rollup(&self, group_id: &str) -> Option<LinkProgressRollup> {
        self.transfer_progress.link_rollup(group_id)
    }

    pub fn render_block_fetch_histogram(&self) -> String {
        self.transfer_progress.render_block_fetch_histogram()
    }

    // --- recent_errors --------------------------------------------------

    pub fn record_recent_error(&self, category: &'static str, coarse_context: impl Into<String>) {
        self.recent_errors.record(category, coarse_context);
    }

    pub fn recent_error_snapshot(&self) -> Vec<RecentErrorRecord> {
        self.recent_errors.recent()
    }

    pub fn recent_error_category_counts(&self) -> Vec<(&'static str, u64)> {
        self.recent_errors.category_counts()
    }

    /// A cheap-clone handle to the log, for a caller that needs to pass it
    /// into a spawned worker/task rather than call through `&self`.
    pub fn recent_errors_handle(&self) -> RecentErrorLog {
        self.recent_errors.clone()
    }
}
