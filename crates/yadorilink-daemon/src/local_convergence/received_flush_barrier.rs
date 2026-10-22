//! The batch barrier of a receive run that defers its per-file flush
//! (`YADORILINK_RECEIVE_DEFERRED_FSYNC`).
//!
//! Each received file was renamed into place unflushed and committed with its
//! write intent still open (marked as waiting for this barrier). Here the files
//! of the run are flushed together, and only then are the intents of the files
//! that reached stable storage cleared, in one transaction. A file whose flush
//! failed keeps its intent: startup repair finds the open intent and rebuilds
//! the file from the block store if its bytes are not the version's.

use std::sync::Arc;

use yadorilink_local_storage::{
    flush_received_objects, ReceivedFlushMode, ReceivedFlushOutcome, TempFileLedger,
};

use super::completion_window::PendingFlush;
use crate::replica_coordinator::ReplicaCoordinator;

/// Parallel flushes in one barrier.
const FLUSH_WORKERS: usize = 8;

/// What one barrier did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct BarrierReport {
    pub(crate) flushed: usize,
    /// Files that were no longer at their path; their intents stay open.
    pub(crate) gone: usize,
    /// Files whose flush failed; their intents stay open.
    pub(crate) failed: usize,
    /// Intents cleared.
    pub(crate) cleared: usize,
}

/// Flushes `pending` and clears the intents of the files that were flushed (or
/// are gone). Blocking.
pub(crate) fn run_flush_barrier(
    state: &Arc<ReplicaCoordinator>,
    pending: Vec<PendingFlush>,
    mode: ReceivedFlushMode,
) -> BarrierReport {
    let mut report = BarrierReport::default();
    if pending.is_empty() {
        return report;
    }
    let started = std::time::Instant::now();
    // A volume that went away leaves a bare mountpoint, where every file looks
    // gone and a flush reaches the wrong filesystem: only a root that still
    // proves to be the link's is flushed, and its files are cleared.
    let proven = |item: &PendingFlush| state.verify_root(&item.root, &item.group_id).is_ok();
    let (pending, unproven): (Vec<_>, Vec<_>) = pending.into_iter().partition(|item| proven(item));
    report.failed += unproven.len();
    if !unproven.is_empty() {
        tracing::warn!(
            files = unproven.len(),
            "a sync root could not be proven before the batch flush of its received files; \
             their writes stay in flight for startup repair"
        );
    }
    if pending.is_empty() {
        return report;
    }
    let files: Vec<_> = pending.iter().map(|p| p.out_path.clone()).collect();
    let keys: Vec<_> = pending.iter().map(|p| p.object).collect();
    let outcomes = flush_received_objects(&files, &keys, mode, FLUSH_WORKERS);
    let mut to_clear: Vec<(&str, &str, i64)> = Vec::new();
    for (item, outcome) in pending.iter().zip(&outcomes) {
        // Proven again after the flush: a root lost meanwhile flushed nothing of ours.
        let outcome = if proven(item) {
            outcome.clone()
        } else {
            ReceivedFlushOutcome::Failed("the sync root was lost during the flush".into())
        };
        match &outcome {
            ReceivedFlushOutcome::Flushed => {
                report.flushed += 1;
                // The temp name is gone for good once the directory is flushed.
                item.ledger.release(&item.tmp_path);
                if let Some(generation) = item.marked_under {
                    to_clear.push((&item.group_id, &item.path, generation));
                }
            }
            // The file is no longer at its path: it may have been moved, and then
            // neither its bytes nor its new directory were flushed by this
            // barrier. Absence is not durability, so the intent stays open and
            // startup repair settles the path.
            ReceivedFlushOutcome::Gone => report.gone += 1,
            ReceivedFlushOutcome::Failed(reason) => {
                report.failed += 1;
                tracing::warn!(
                    group_id = %item.group_id,
                    path = %item.path,
                    reason = %reason,
                    "the batch flush of a received file failed; its write stays in flight for \
                     startup repair"
                );
            }
        }
    }
    let flushed_in = started.elapsed();
    match state.clear_flush_pending_intents(&to_clear) {
        Ok(cleared) => report.cleared = cleared,
        Err(error) => tracing::warn!(
            error = %error,
            "could not clear the intents of the flushed received files; they stay open and \
             startup repair closes them"
        ),
    }
    // Logged under the call timer's target, which a measurement run already
    // enables, so the time to stable storage can be read next to the receive.
    tracing::info!(
        target: "yadorilink_daemon::local_convergence::call_timer",
        files = pending.len(),
        flushed = report.flushed,
        failed = report.failed,
        cleared = report.cleared,
        flush_ms = flushed_in.as_millis() as u64,
        total_ms = started.elapsed().as_millis() as u64,
        "receive flush barrier"
    );
    report
}
