#![cfg(test)]

use super::{
    resolve_duplicate_recovery_gate, send_committed_chunk, spawn_chunk_announcer,
    wait_out_pause_then_rescan, DuplicateRecoveryOutcome, ANNOUNCE_QUEUE_CAPACITY,
    PAUSED_RESCAN_DELAY,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use yadorilink_local_capture::LocalCaptureError;
use yadorilink_replica_domain::file::FileRecord;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FakeError;

impl std::fmt::Display for FakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "fake error")
    }
}

// Ordinary startup: nothing pending. The expensive corroboration pass
// must never run -- proven directly (not via timing) by panicking if
// the closure is ever invoked, and `recheck_pending` must likewise
// never be consulted since there was nothing to recheck.
#[test]
fn no_recovery_pending_skips_corroboration_and_completes_immediately() {
    let outcome = resolve_duplicate_recovery_gate::<FakeError>(
        "group",
        Ok(false),
        || panic!("corroborate_and_resolve must not run when nothing is pending"),
        || panic!("recheck_pending must not run when nothing was pending to begin with"),
    );
    assert_eq!(outcome, DuplicateRecoveryOutcome::Complete);
}

// Armed recovery, fully resolved this pass: corroboration runs exactly
// once and, since the durable pending set is now empty, the gate
// reports Complete so suppression may clear.
#[test]
fn pending_recovery_runs_corroboration_once_and_completes_when_pending_clears() {
    let mut corroborate_calls = 0;
    let outcome = resolve_duplicate_recovery_gate(
        "group",
        Ok::<bool, FakeError>(true),
        || corroborate_calls += 1,
        || Ok(false),
    );
    assert_eq!(corroborate_calls, 1);
    assert_eq!(outcome, DuplicateRecoveryOutcome::Complete);
}

// Armed recovery, still unresolved after this pass (some paths were
// not corroborated): suppression must stay armed.
#[test]
fn pending_recovery_stays_pending_when_recheck_still_reports_pending() {
    let mut corroborate_calls = 0;
    let outcome = resolve_duplicate_recovery_gate(
        "group",
        Ok::<bool, FakeError>(true),
        || corroborate_calls += 1,
        || Ok(true),
    );
    assert_eq!(corroborate_calls, 1);
    assert_eq!(outcome, DuplicateRecoveryOutcome::StillPending);
}

// Corroboration ran, but the post-corroboration recheck itself could
// not be read: fail closed exactly like the initial-read failure does,
// not optimistically treated as resolved.
#[test]
fn unreadable_recheck_after_corroboration_fails_closed() {
    let mut corroborate_calls = 0;
    let outcome = resolve_duplicate_recovery_gate(
        "group",
        Ok::<bool, FakeError>(true),
        || corroborate_calls += 1,
        || Err(FakeError),
    );
    assert_eq!(corroborate_calls, 1, "corroboration must still run once pending was true");
    assert_eq!(outcome, DuplicateRecoveryOutcome::UnknownFailClosed);
}

// The durable pending state itself could not be read: fail closed.
// Corroboration must not run against an unknown state, and
// suppression must stay armed rather than being cleared optimistically.
#[test]
fn unreadable_pending_state_fails_closed_without_running_corroboration() {
    let outcome = resolve_duplicate_recovery_gate(
        "group",
        Err(FakeError),
        || panic!("corroborate_and_resolve must not run when pending state is unknown"),
        || -> Result<bool, FakeError> {
            panic!("recheck_pending must not run when the initial read already failed")
        },
    );
    assert_eq!(outcome, DuplicateRecoveryOutcome::UnknownFailClosed);
}

fn chunk(i: usize) -> Vec<FileRecord> {
    vec![FileRecord {
        path: format!("f{i}"),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: Vec::new(),
        deleted: false,
    }]
}

// A stalled consumer must apply backpressure: the producer (a blocking
// scan callback) can have at most the queue capacity plus the chunk being
// announced plus the one blocked in `send` outstanding, however many chunks
// the tree produces. Once the consumer resumes, every chunk is announced in
// commit order.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_announcer_bounds_the_committed_chunk_queue() {
    const TOTAL: usize = 200;
    let release = Arc::new(AtomicBool::new(false));
    let announced = Arc::new(Mutex::new(Vec::<String>::new()));
    let (tx, task) = {
        let release = release.clone();
        let announced = announced.clone();
        spawn_chunk_announcer(move |records| {
            let release = release.clone();
            let announced = announced.clone();
            async move {
                while !release.load(Ordering::SeqCst) {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                announced.lock().unwrap().push(records[0].path.clone());
            }
        })
    };
    let sent = Arc::new(AtomicUsize::new(0));
    let producer = {
        let sent = sent.clone();
        tokio::task::spawn_blocking(move || {
            for i in 0..TOTAL {
                send_committed_chunk(&tx, &chunk(i)).unwrap();
                sent.fetch_add(1, Ordering::SeqCst);
            }
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let outstanding = sent.load(Ordering::SeqCst);
    assert!(
        outstanding <= ANNOUNCE_QUEUE_CAPACITY + 1,
        "a stalled consumer must block the producer: {outstanding} chunks were accepted"
    );
    assert!(!producer.is_finished(), "the producer must be blocked on the full queue");

    release.store(true, Ordering::SeqCst);
    producer.await.unwrap();
    task.await.unwrap();
    let expected: Vec<String> = (0..TOTAL).map(|i| format!("f{i}")).collect();
    assert_eq!(*announced.lock().unwrap(), expected, "chunks must be announced in commit order");
}

// A dead consumer must surface to the producer as an error rather than being
// ignored, and the task's failure must be visible to the joiner.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dead_announcer_fails_the_producer_and_the_join() {
    let (tx, task) = spawn_chunk_announcer(|_records| async move {
        panic!("injected announce failure");
    });
    let result = tokio::task::spawn_blocking(move || {
        for i in 0..1000 {
            send_committed_chunk(&tx, &chunk(i))?;
        }
        Ok::<(), LocalCaptureError>(())
    })
    .await
    .unwrap();
    assert!(
        matches!(result, Err(LocalCaptureError::StreamingConsumerClosed)),
        "the producer must observe the dead consumer, got {result:?}"
    );
    assert!(task.await.is_err(), "the announcer panic must reach the joiner");
}

// A full rescan refused by a safe-stop pause journals nothing of its own, so the executor must
// wait out the pause and mark the next iteration as a rescan again.
#[tokio::test(start_paused = true)]
async fn a_paused_full_rescan_waits_then_marks_the_next_iteration_as_a_rescan() {
    let mut rescan_retry = false;
    let start = tokio::time::Instant::now();
    wait_out_pause_then_rescan(&mut rescan_retry).await;
    assert!(rescan_retry, "the refused rescan must be repeated");
    assert_eq!(start.elapsed(), PAUSED_RESCAN_DELAY);
    assert_eq!(PAUSED_RESCAN_DELAY, std::time::Duration::from_secs(5));
}
