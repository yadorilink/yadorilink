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

use yadorilink_peer_session::PeerSessionError;

use yadorilink_local_storage::{
    flush_received_objects, ReceivedFlushMode, ReceivedFlushOutcome, TempFileLedger,
};

use super::completion_window::{PendingFlush, TempFlushItem};
use crate::replica_coordinator::ReplicaCoordinator;
use crate::write_op::StepEvent;

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
    let data_flushed: Vec<_> = pending.iter().map(|p| p.data_flushed).collect();
    let outcomes = flush_received_objects(&files, &keys, &data_flushed, mode, FLUSH_WORKERS);
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
    // An injected failure before the clear leaves the intents open, as a failed clear does.
    let injected = to_clear.iter().find_map(|(_, path, _)| {
        crate::write_op::failpoint::hit(
            crate::write_op::failpoint::WriteOpFailpoint::BeforeBarrier2,
            path,
        )
        .err()
    });
    let cleared = match injected {
        Some(error) => Err(error.to_string()),
        None => state.clear_flush_pending_intents(&to_clear).map_err(|e| e.to_string()),
    };
    match cleared {
        Ok(cleared) => {
            report.cleared = cleared;
            if cleared == to_clear.len() {
                for (group_id, path, _) in &to_clear {
                    crate::write_op::trace::emit_at(group_id, path, StepEvent::Settled);
                }
            }
        }
        Err(error) => tracing::warn!(
            error = %error,
            "could not clear the intents of the flushed received files; they stay open and \
             startup repair closes them"
        ),
    }
    // A probe, not a fault: it runs whether or not the clear succeeded, and an injected failure
    // is discarded. A test reads `Armed::fired` and the intent state.
    for (_, path, _) in &to_clear {
        let _ = crate::write_op::failpoint::hit(
            crate::write_op::failpoint::WriteOpFailpoint::AfterBarrier2,
            path,
        );
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

/// Barrier 1 of a window: before any of these temps is renamed over its target, its data and
/// its directory entry reach stable storage, so that a cut after the rename leaves the old
/// name, the new complete file, or the durable temp, and never a state with no copy of the
/// content. The files are flushed together (the temps, then each distinct parent directory
/// once), and each answers for itself: a temp that could not be flushed, moved, or whose root
/// can no longer be proven gets an error and must not be renamed. Blocking.
pub(crate) fn run_temp_flush_barrier(
    state: &Arc<ReplicaCoordinator>,
    items: &[&TempFlushItem],
    mode: ReceivedFlushMode,
) -> Vec<Result<Option<yadorilink_local_storage::FlushedStamp>, PeerSessionError>> {
    #[cfg(all(test, unix))]
    test_hold::wait_while_held(items);
    let refused = |reason: String| PeerSessionError::HydrationFailed(reason);
    let proven = |item: &TempFlushItem| state.verify_root(&item.root, &item.group_id).is_ok();
    let mut results: Vec<Option<Result<_, PeerSessionError>>> = items
        .iter()
        .map(|item| {
            (!proven(item)).then(|| {
                Err(refused(format!(
                    "the sync root of {} could not be proven before the temp flush",
                    item.tmp_path.display()
                )))
            })
        })
        .collect();
    let live: Vec<usize> = (0..items.len()).filter(|i| results[*i].is_none()).collect();
    // The stamp is taken BEFORE the flush: a write that lands after it moves the stamp, so barrier 2
    // flushes the file again instead of trusting a stamp that already includes that write.
    let before: Vec<_> =
        live.iter().map(|i| yadorilink_local_storage::flushed_stamp(&items[*i].tmp_path)).collect();
    let started = std::time::Instant::now();
    // Temps whose data is not durable anywhere else are flushed with their directory; a temp
    // whose content is in the block store needs only its name flushed.
    let (full, name_only): (Vec<usize>, Vec<usize>) =
        live.iter().copied().partition(|i| !items[*i].name_only);
    let mut outcomes: std::collections::HashMap<usize, ReceivedFlushOutcome> =
        std::collections::HashMap::new();
    if !full.is_empty() {
        let files: Vec<_> = full.iter().map(|i| items[*i].tmp_path.clone()).collect();
        let keys: Vec<_> = full.iter().map(|i| items[*i].object).collect();
        let stamps: Vec<_> = full.iter().map(|i| items[*i].data_flushed).collect();
        for (slot, outcome) in
            full.iter().zip(flush_received_objects(&files, &keys, &stamps, mode, FLUSH_WORKERS))
        {
            outcomes.insert(*slot, outcome);
        }
    }
    if !name_only.is_empty() {
        let files: Vec<_> = name_only.iter().map(|i| items[*i].tmp_path.clone()).collect();
        for (slot, outcome) in name_only
            .iter()
            .zip(yadorilink_local_storage::flush_parent_directories(&files, mode, FLUSH_WORKERS))
        {
            outcomes.insert(*slot, outcome);
        }
    }
    for (slot, stamp_before) in live.iter().zip(before) {
        let item = items[*slot];
        let outcome = outcomes.remove(slot).expect("every live item was flushed");
        results[*slot] = Some(match outcome {
            // Proven again after the flush: a root lost meanwhile flushed nothing of ours.
            ReceivedFlushOutcome::Flushed
                if proven(item)
                    && (item.object.is_none()
                        || yadorilink_local_storage::object_key(&item.tmp_path) == item.object) =>
            {
                // A name-only temp's data was not flushed here, so it carries no stamp: barrier 2
                // must flush the file itself.
                Ok(if item.name_only { None } else { stamp_before })
            }
            ReceivedFlushOutcome::Flushed if proven(item) => {
                Err(refused("the temp was replaced while it was being flushed".into()))
            }
            ReceivedFlushOutcome::Flushed => {
                Err(refused("the sync root was lost during the temp flush".into()))
            }
            ReceivedFlushOutcome::Gone => {
                Err(refused(format!("the temp {} is gone", item.tmp_path.display())))
            }
            ReceivedFlushOutcome::Failed(reason) => Err(refused(reason)),
        });
    }
    tracing::info!(
        target: "yadorilink_daemon::local_convergence::call_timer",
        files = items.len(),
        flush_ms = started.elapsed().as_millis() as u64,
        "receive temp flush barrier"
    );
    results.into_iter().map(|r| r.expect("every item has an answer")).collect()
}

/// Test seam: holds the temp flushes of a root until released, to cancel a receive that waits.
#[cfg(all(test, unix))]
pub(crate) mod test_hold {
    use super::TempFlushItem;
    use std::sync::{Condvar, Mutex};

    /// (still held, batches that reached the flush) and the condition that releases it.
    type Gate = std::sync::Arc<(Mutex<(bool, usize)>, Condvar)>;

    static HELD: Mutex<Vec<(String, Gate)>> = Mutex::new(Vec::new());

    pub(crate) struct Hold(Gate, String);

    pub(crate) fn hold_temp_flushes_under(root: &str) -> Hold {
        let state = std::sync::Arc::new((Mutex::new((true, 0)), Condvar::new()));
        HELD.lock().unwrap().push((root.to_owned(), state.clone()));
        Hold(state, root.to_owned())
    }

    impl Hold {
        /// Number of batches that reached the flush and wait.
        pub(crate) fn entered(&self) -> usize {
            self.0 .0.lock().unwrap().1
        }
        pub(crate) fn release(&self) {
            self.0 .0.lock().unwrap().0 = false;
            self.0 .1.notify_all();
        }
    }

    impl Drop for Hold {
        fn drop(&mut self) {
            self.release();
            HELD.lock().unwrap().retain(|(root, _)| *root != self.1);
        }
    }

    pub(super) fn wait_while_held(items: &[&TempFlushItem]) {
        let state = {
            let held = HELD.lock().unwrap();
            held.iter()
                .find(|(root, _)| items.iter().any(|i| i.tmp_path.starts_with(root)))
                .map(|(_, state)| state.clone())
        };
        if let Some(state) = state {
            let mut guard = state.0.lock().unwrap();
            guard.1 += 1;
            while guard.0 {
                guard = state.1.wait(guard).unwrap();
            }
        }
    }
}
