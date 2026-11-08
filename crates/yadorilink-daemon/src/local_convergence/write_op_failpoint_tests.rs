#![cfg(test)]
//! Every [`WriteOpFailpoint`] of the eager receive lane is reachable: the write
//! fails at the armed transition, the received bytes are never lost, and the
//! same write succeeds once the fault is cleared. The matrix of
//! `safety_gate_fault_matrix.table` points at these tests.

use super::growing_file_projection_tests::{Harness, GROUP};
use super::receive_deferred_flush_tests::{
    closed, intent_open, startup, use_deferred, FULL_FLUSH_EACH,
};
use super::receive_window_concurrency_tests::{
    driver, names, pin_concurrency, publish_new_files, reconcile,
};
use crate::write_op::failpoint::{arm, WriteOpFailpoint};

async fn attempt(h: &Harness, files: &[String]) {
    // A faulted attempt may answer with the injected error: the test reads the effects.
    let _ = h
        .convergence
        .reconcile_paths_directly(&driver(), GROUP, files.iter().cloned().collect())
        .await;
}

/// A fault before the proof leaves the write open and the retry finishes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_stopped_at_each_transition_before_the_proof_is_finished_by_the_retry() {
    for (i, point) in [
        WriteOpFailpoint::AfterPrepare,
        WriteOpFailpoint::AfterStage,
        WriteOpFailpoint::BeforePublish,
        WriteOpFailpoint::AfterPublish,
        WriteOpFailpoint::AfterObserve,
        WriteOpFailpoint::BeforeProve,
    ]
    .into_iter()
    .enumerate()
    {
        let h = Harness::new(false);
        let files = names(&format!("fp{i}-"), 1);
        let contents = publish_new_files(&h, &files).await;
        let fault = arm(point, &files[0]);

        attempt(&h, &files).await;

        // The lane retries a failed step within the attempt, so a point can be hit repeatedly.
        assert!(fault.fired() >= 1, "{point:?} was reached");
        assert!(!closed(&h, &files[0]), "{point:?}: nothing is proven yet");
        fault.clear();
        attempt(&h, &files).await;
        assert!(closed(&h, &files[0]), "{point:?}: the retry finishes the write");
        assert_eq!(std::fs::read(h.path(&files[0])).unwrap(), contents[&files[0]]);
    }
}

/// A fault after the proof commit is reached with the write already closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fault_after_the_proof_finds_the_write_closed() {
    let h = Harness::new(false);
    let files = names("fp-after-prove-", 1);
    let contents = publish_new_files(&h, &files).await;
    let fault = arm(WriteOpFailpoint::AfterProve, &files[0]);

    attempt(&h, &files).await;

    assert_eq!(fault.fired(), 1);
    assert!(closed(&h, &files[0]));
    assert_eq!(std::fs::read(h.path(&files[0])).unwrap(), contents[&files[0]]);
}

/// A fault before barrier 2 clears nothing: the intent stays open for startup repair.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fault_before_barrier_two_keeps_the_intent_for_startup_repair() {
    let h = Harness::new(false);
    pin_concurrency(&h, 4);
    use_deferred(&h, FULL_FLUSH_EACH);
    let files = names("fp-barrier-before-", 1);
    let contents = publish_new_files(&h, &files).await;
    let fault = arm(WriteOpFailpoint::BeforeBarrier2, &files[0]);

    let settled = reconcile(&h, &files).await;
    h.convergence.drain_flush_barriers().await;

    assert!(settled.is_settled(&files[0]));
    assert_eq!(fault.fired(), 1);
    assert!(intent_open(&h, &files[0]), "the intent was not cleared");
    fault.clear();
    startup(&h);
    assert!(closed(&h, &files[0]), "startup repair closes it");
    assert_eq!(std::fs::read(h.path(&files[0])).unwrap(), contents[&files[0]]);
}

/// After barrier 2 the write is closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fault_after_barrier_two_finds_the_write_closed() {
    let h = Harness::new(false);
    pin_concurrency(&h, 4);
    use_deferred(&h, FULL_FLUSH_EACH);
    let files = names("fp-barrier-after-", 1);
    publish_new_files(&h, &files).await;
    let fault = arm(WriteOpFailpoint::AfterBarrier2, &files[0]);

    reconcile(&h, &files).await;
    h.convergence.drain_flush_barriers().await;

    assert_eq!(fault.fired(), 1);
    assert!(closed(&h, &files[0]));
}
