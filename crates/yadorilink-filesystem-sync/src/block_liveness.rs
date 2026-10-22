use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
struct State {
    writers: usize,
    deleting: bool,
    /// Deletions blocked in [`BlockLivenessGate::begin_physical_deletion`]. While non-zero,
    /// fair writers yield, so overlapping writers cannot keep `writers` above zero forever.
    delete_waiters: usize,
}

/// How long a fair writer yields to a waiting deletion before admitting itself anyway.
const FAIR_WAIT: Duration = Duration::from_millis(250);

pub struct BlockLivenessGate {
    state: Mutex<State>,
    changed: Condvar,
    fair_wait: Duration,
    /// Test hook: times a fair writer entered the yield-to-a-waiting-deletion wait.
    #[cfg(test)]
    yields: std::sync::atomic::AtomicUsize,
}

impl Default for BlockLivenessGate {
    fn default() -> Self {
        Self::with_fair_wait(FAIR_WAIT)
    }
}

impl BlockLivenessGate {
    fn with_fair_wait(fair_wait: Duration) -> Self {
        Self {
            state: Mutex::default(),
            changed: Condvar::new(),
            fair_wait,
            #[cfg(test)]
            yields: Default::default(),
        }
    }

    /// Admits a writer. While a deletion is waiting for the admitted writers to finish, a new
    /// writer yields to it for up to `fair_wait`, so a steady stream of overlapping writers
    /// cannot starve the deletion. The yield is bounded because the gate cannot tell a fresh
    /// writer from one nested inside an admitted writer (or holding what one waits for): such a
    /// writer would otherwise deadlock behind the deletion that waits for its outer writer.
    /// After the bound it is admitted, which is always safe: only a running deletion excludes.
    pub fn begin_reference_write(&self) -> BlockReferenceWriteGuard<'_> {
        let deadline = Instant::now() + self.fair_wait;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if state.deleting || (state.delete_waiters != 0 && !remaining.is_zero()) {
                #[cfg(test)]
                if !state.deleting {
                    self.yields.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                let timeout = if state.deleting { None } else { Some(remaining) };
                state = match timeout {
                    Some(t) => {
                        self.changed.wait_timeout(state, t).unwrap_or_else(|e| e.into_inner()).0
                    }
                    None => self.changed.wait(state).unwrap_or_else(|e| e.into_inner()),
                };
            } else {
                break;
            }
        }
        state.writers += 1;
        BlockReferenceWriteGuard { gate: self }
    }

    /// Admits a writer without yielding to waiting deletions; it waits only for a deletion that
    /// is actually running. Never weakens exclusion: a writer is never admitted during one.
    ///
    /// Policy: fair writers yield to a waiting deletion for at most `FAIR_WAIT`, so a deletion
    /// drains an overlapping chain of fair writers only while their holds are short against that
    /// bound (measured with 4-16 permanently overlapping writers: a deletion waited ~8 ms for 5 ms
    /// holds and 20-60 ms for 50 ms holds); once a hold approaches the bound, staggered writers
    /// can still keep the gate occupied. Against a permanently overlapping chain of barging
    /// writers a deletion has no progress guarantee at all (the same measurement waited over 3 s
    /// in every configuration). Barging is therefore reserved for short, finite callers that may run nested inside an
    /// admitted writer, never for a continuous stream.
    pub fn begin_reference_write_barging(&self) -> BlockReferenceWriteGuard<'_> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        while state.deleting {
            state = self.changed.wait(state).unwrap_or_else(|e| e.into_inner());
        }
        state.writers += 1;
        BlockReferenceWriteGuard { gate: self }
    }

    pub fn begin_physical_deletion(&self) -> BlockPhysicalDeletionGuard<'_> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.delete_waiters += 1;
        while state.deleting || state.writers != 0 {
            state = self.changed.wait(state).unwrap_or_else(|e| e.into_inner());
        }
        state.delete_waiters -= 1;
        state.deleting = true;
        BlockPhysicalDeletionGuard { gate: self }
    }
}

impl BlockLivenessGate {
    /// [`Self::begin_physical_deletion`] that never waits: `None` while a reference write or
    /// another deletion is in progress. For a caller that holds something a writer may be
    /// waiting for, and so must not wait for the writers itself.
    pub fn try_begin_physical_deletion(&self) -> Option<BlockPhysicalDeletionGuard<'_>> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.deleting || state.writers != 0 {
            return None;
        }
        state.deleting = true;
        Some(BlockPhysicalDeletionGuard { gate: self })
    }
}

pub struct BlockReferenceWriteGuard<'a> {
    gate: &'a BlockLivenessGate,
}

impl Drop for BlockReferenceWriteGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock().unwrap_or_else(|e| e.into_inner());
        state.writers -= 1;
        if state.writers == 0 {
            self.gate.changed.notify_all();
        }
    }
}

pub struct BlockPhysicalDeletionGuard<'a> {
    gate: &'a BlockLivenessGate,
}

impl Drop for BlockPhysicalDeletionGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock().unwrap_or_else(|e| e.into_inner());
        state.deleting = false;
        self.gate.changed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicIsize, Ordering::SeqCst};
    use std::sync::{mpsc, Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    /// A writer nested inside an admitted writer must not deadlock behind a waiting deletion.
    #[test]
    fn a_nested_fair_writer_is_admitted_after_the_bounded_yield() {
        let gate = Arc::new(BlockLivenessGate::with_fair_wait(Duration::from_millis(20)));
        let outer = gate.begin_reference_write();
        let deleter = {
            let gate = gate.clone();
            thread::spawn(move || drop(gate.begin_physical_deletion()))
        };
        wait_for_delete_waiter(&gate);
        drop(gate.begin_reference_write());
        drop(outer);
        deleter.join().unwrap();
    }

    fn wait_for_delete_waiter(gate: &BlockLivenessGate) {
        while gate.state.lock().unwrap().delete_waiters == 0 {
            thread::yield_now();
        }
    }

    fn writer(gate: &BlockLivenessGate, n: usize) -> BlockReferenceWriteGuard<'_> {
        if n.is_multiple_of(2) {
            gate.begin_reference_write()
        } else {
            gate.begin_reference_write_barging()
        }
    }

    /// A new writer arriving while a deletion waits queues behind it, so overlapping writers
    /// cannot keep the deletion out forever.
    #[test]
    fn a_new_writer_queues_behind_a_waiting_deletion() {
        let gate = Arc::new(BlockLivenessGate::with_fair_wait(Duration::from_secs(30)));
        let first = gate.begin_reference_write();
        let order = Arc::new(Mutex::new(Vec::new()));
        let (done_tx, done_rx) = mpsc::channel();
        let deleter = {
            let (gate, order) = (gate.clone(), order.clone());
            thread::spawn(move || {
                let _deletion = gate.begin_physical_deletion();
                order.lock().unwrap().push("deletion");
                done_tx.send(()).unwrap();
            })
        };
        wait_for_delete_waiter(&gate);
        let (admitted_tx, admitted_rx) = mpsc::channel();
        let second = {
            let (gate, order) = (gate.clone(), order.clone());
            thread::spawn(move || {
                let _w = gate.begin_reference_write();
                order.lock().unwrap().push("writer");
                admitted_tx.send(()).unwrap();
            })
        };
        // Writer B is provably parked in the yield wait (not merely unscheduled) before A goes.
        let parked = Instant::now();
        while gate.yields.load(SeqCst) == 0 {
            assert!(parked.elapsed() < Duration::from_secs(10), "writer never yielded");
            thread::yield_now();
        }
        assert!(
            admitted_rx.try_recv().is_err(),
            "a new writer was admitted past a waiting deletion"
        );
        drop(first);
        done_rx.recv_timeout(Duration::from_secs(10)).expect("deletion starved");
        deleter.join().unwrap();
        admitted_rx.recv_timeout(Duration::from_secs(10)).expect("writer never admitted");
        second.join().unwrap();
        assert_eq!(*order.lock().unwrap(), ["deletion", "writer"], "deletion was overtaken");
    }

    /// A deletion never overlaps an admitted writer, under contention.
    #[test]
    fn a_deletion_never_overlaps_an_admitted_writer() {
        let gate = Arc::new(BlockLivenessGate::default());
        let inside = Arc::new(AtomicIsize::new(0));
        let start = Arc::new(Barrier::new(6));
        let handles: Vec<_> = (0..6_usize)
            .map(|i| {
                let (gate, inside, start) = (gate.clone(), inside.clone(), start.clone());
                thread::spawn(move || {
                    start.wait();
                    for n in 0..200 {
                        if i.is_multiple_of(3) {
                            let _d = gate.begin_physical_deletion();
                            assert_eq!(inside.fetch_sub(1000, SeqCst), 0, "deletion with writers");
                            thread::yield_now();
                            assert_eq!(inside.fetch_add(1000, SeqCst), -1000, "overlap");
                        } else {
                            let _w = writer(&gate, n);
                            assert!(inside.fetch_add(1, SeqCst) >= 0, "writer during deletion");
                            thread::yield_now();
                            inside.fetch_sub(1, SeqCst);
                        }
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    }

    /// A barging writer (one that may hold what an admitted writer waits for) is never blocked
    /// by a merely waiting deletion.
    #[test]
    fn a_barging_writer_is_admitted_past_a_waiting_deletion() {
        let gate = Arc::new(BlockLivenessGate::default());
        let first = gate.begin_reference_write();
        let deleter = {
            let gate = gate.clone();
            thread::spawn(move || drop(gate.begin_physical_deletion()))
        };
        wait_for_delete_waiter(&gate);
        drop(gate.begin_reference_write_barging());
        drop(first);
        deleter.join().unwrap();
    }

    #[test]
    fn a_non_waiting_deletion_is_refused_while_anything_else_is_in_progress() {
        let gate = BlockLivenessGate::default();
        let writer = gate.begin_reference_write();
        assert!(gate.try_begin_physical_deletion().is_none(), "deleted under a writer");
        drop(writer);

        let deletion = gate.try_begin_physical_deletion().expect("idle gate refused");
        assert!(gate.try_begin_physical_deletion().is_none(), "two deletions at once");
        drop(deletion);
        assert!(gate.try_begin_physical_deletion().is_some(), "the guard did not release");
    }
}
