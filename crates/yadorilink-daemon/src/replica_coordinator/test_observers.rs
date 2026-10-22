//! What a test can observe about, and impose on, a real
//! `ReplicaCoordinator` -- the four things `FakeReplicaState` used to
//! provide by standing in for it.
//!
//! Compiled under `#[cfg(test)]` only, so none of this exists in a
//! production build: not the fields, not the calls that touch them. It
//! lives on the real coordinator rather than on a double because the
//! subject under test is a `LocalConvergenceExecutor` driving real
//! storage, and a double that answers differently from the database is
//! how a test passes over the difference.
//!
//! The four are not interchangeable and none of them is expressible as
//! "assert the final state":
//!
//! - **Call counts.** The zero-write assertions are about work *not*
//!   done. A path that is already settled must perform no metadata
//!   apply and no projected-row write -- and a final-state check cannot tell "wrote nothing" apart from "wrote the
//!   same value again", which is precisely the regression these guard.
//! - **Batch shapes.** Recording one entry per call, holding that call's
//!   block hashes, is what makes "these hashes were written in ONE call"
//!   distinguishable from "these hashes were written in N calls". The
//!   resulting rows are identical either way.
//! - **Failure injection.** A batch commit's transaction has to be made
//!   to fail on demand to assert that the whole call errors rather than
//!   reporting some paths settled; nothing a test can do to real storage
//!   fails exactly that transaction and nothing else.
//! - **Deterministic interleave.** A supersession has to land *inside*
//!   another operation's read window. Racing it from a thread makes the
//!   test flaky; firing it from the read itself makes it exact.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

/// A supersession to apply from inside the next current-row read, so it
/// lands in the middle of a producer's read window.
pub(crate) struct ArmedSupersession {
    pub group_id: String,
    pub path: String,
    /// Applied by the test's own closure, so this module needs to know
    /// nothing about what a supersession consists of.
    pub apply: Box<dyn Fn() + Send + Sync>,
}

#[derive(Default)]
pub(crate) struct TestObservers {
    pub apply_projected_row_atomic_calls: AtomicUsize,
    /// One per metadata-unprovable hold decided, including one that
    /// re-confirms an existing hold: how many times a blocked path was
    /// actually re-examined, which the hold's final state cannot show.
    pub metadata_unprovable_holds: AtomicUsize,
    /// One entry per `record_group_block_provenance` call, holding that
    /// call's hashes -- the shape, not just the total.
    pub record_group_block_provenance_batches: Mutex<Vec<Vec<Vec<u8>>>>,
    /// `(group_id, path, version_hash_hex, peer_device_id)` per call.
    pub clear_block_fetch_refusal_calls: Mutex<Vec<(String, String, String, String)>>,
    pub finalize_projected_mutations_batch_fails: AtomicBool,
    /// Fails the owner's `abandon_eviction` as its transaction would on a
    /// database failure, before it reads or writes anything.
    pub abandon_eviction_fails: AtomicBool,
    /// Fails the provenance write itself, leaving the blocks it is about
    /// already durably fetched. The distinction is the point: a pass that
    /// cannot record what it obtained must fail rather than let the paths
    /// depending on that proof publish.
    pub record_group_block_provenance_fails: AtomicBool,
    /// Armed for the READ window: fires once the row has been captured
    /// and before it is returned.
    pub armed_supersession: Mutex<Option<ArmedSupersession>>,
    /// Armed for the WRITE window: fires once a materialization's own
    /// upsert has landed, so the row moves in the middle of that
    /// materialization rather than before it starts. A different race
    /// from the read one, and not reachable from the same hook: what it
    /// asserts is that what gets written is decided by the payload, with
    /// the row only ever a guard.
    pub armed_upsert_supersession: Mutex<Option<ArmedSupersession>>,
    /// The number of items of every batched close transaction that ran.
    pub close_batch_sizes: Mutex<Vec<usize>>,
    /// Fails a batched close transaction after every item has been
    /// written and before it commits, as a crash in the middle of it would:
    /// none of the batch may survive.
    pub close_batch_fails_before_commit: AtomicBool,
    /// Runs when a batched close is about to open its transaction, before
    /// anything is written: a test parks the committing task here with every
    /// file of the batch renamed into place and none of them committed.
    pub close_batch_gate: Mutex<Option<std::sync::Arc<dyn Fn() + Send + Sync>>>,
    /// Runs inside a content write's open transaction before its first
    /// statement (on whichever thread runs the commit): a test parks the
    /// commit here.
    pub open_commit_gate: Mutex<Option<std::sync::Arc<dyn Fn() + Send + Sync>>>,
    /// The number of items of every batched open transaction that ran.
    pub open_batch_sizes: Mutex<Vec<usize>>,
    /// Fails a batched open transaction after every item has been written and
    /// before it commits, as a crash in the middle of it would: none of the
    /// batch may survive.
    pub open_batch_fails_before_commit: AtomicBool,
    /// Runs when a batched open is about to open its transaction, before
    /// anything is written.
    pub open_batch_gate: Mutex<Option<std::sync::Arc<dyn Fn() + Send + Sync>>>,
    /// Overrides `YADORILINK_RECEIVE_ASYNC_COMMIT` for this coordinator:
    /// 0 = the environment, 1 = on, 2 = off.
    pub async_commit_override: std::sync::atomic::AtomicU8,
}

impl TestObservers {
    pub fn note_apply_projected_row_atomic(&self) {
        self.apply_projected_row_atomic_calls.fetch_add(1, Ordering::SeqCst);
    }

    pub fn note_metadata_unprovable_hold(&self) {
        self.metadata_unprovable_holds.fetch_add(1, Ordering::SeqCst);
    }

    pub fn note_provenance_batch(&self, block_hashes: &[Vec<u8>]) {
        self.lock(&self.record_group_block_provenance_batches).push(block_hashes.to_vec());
    }

    pub fn note_clear_block_fetch_refusal(
        &self,
        group_id: &str,
        path: &str,
        version_hash_hex: &str,
        peer_device_id: &str,
    ) {
        self.lock(&self.clear_block_fetch_refusal_calls).push((
            group_id.to_string(),
            path.to_string(),
            version_hash_hex.to_string(),
            peer_device_id.to_string(),
        ));
    }

    /// Fires at most once, and only for the armed path: a producer that
    /// reads the row once gets the supersession after its read, and one
    /// that reads twice gets it between them. That difference is the
    /// whole assertion.
    pub fn fire_armed_supersession(&self, group_id: &str, path: &str) {
        let armed = {
            let mut slot = self.lock(&self.armed_supersession);
            match slot.as_ref() {
                Some(a) if a.group_id == group_id && a.path == path => slot.take(),
                _ => None,
            }
        };
        if let Some(armed) = armed {
            (armed.apply)();
        }
    }

    /// The write-window counterpart of [`Self::fire_armed_supersession`],
    /// fired from the upserts a materialization performs. One-shot, so a
    /// lane that upserts twice still sees a single supersession -- which
    /// is what one concurrent writer would actually produce.
    pub fn fire_armed_upsert_supersession(&self, group_id: &str, path: &str) {
        let armed = {
            let mut slot = self.lock(&self.armed_upsert_supersession);
            match slot.as_ref() {
                Some(a) if a.group_id == group_id && a.path == path => slot.take(),
                _ => None,
            }
        };
        if let Some(armed) = armed {
            (armed.apply)();
        }
    }

    fn lock<'a, T>(&self, m: &'a Mutex<T>) -> std::sync::MutexGuard<'a, T> {
        m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
