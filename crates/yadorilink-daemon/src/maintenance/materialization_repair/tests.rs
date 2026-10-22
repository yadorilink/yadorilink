#![cfg(test)]

use super::*;
use std::sync::atomic::Ordering;

/// The regression this whole seam exists for: a panic inside
/// `run_once` must not silently and permanently kill materialization
/// repair for the rest of the process's life -- `spawn_restarting`
/// must recover it. Proven end to end through the REAL spawn wiring
/// (`spawn_materialization_repair_task`), not just by re-exercising
/// `spawn_restarting`'s own already-tested generic mechanism in
/// isolation: empirically verified RED by temporarily replacing this
/// file's `spawn_restarting` call with a bare, unsupervised
/// `tokio::spawn` (no restart mechanism at all) and confirming this
/// test then fails -- not `spawn_logged`, whose closure-per-call
/// signature does not even match `spawn_restarting`'s
/// factory-that-returns-a-future one, so it would not compile as a
/// drop-in swap here.
#[tokio::test]
async fn a_panic_in_run_once_is_recovered_not_left_permanently_dead() {
    let _guard = crate::test_support::CONFIG_ENV_MUTEX.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        yadorilink_local_storage::SegmentBlockStore::new(dir.path().join("blocks")).unwrap(),
    );
    let sync_state = Arc::new(
        crate::replica_coordinator::ReplicaCoordinator::open(dir.path().join("sync.sqlite3"))
            .unwrap(),
    );
    std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
    // `build`, not `new`: `new` also starts `MaintenanceCoordinator`,
    // which spawns its own independent materialization-repair task
    // (via the real, unmodified `spawn_restarting`) racing this test's
    // own `spawn_materialization_repair_task` call below for the same
    // panic-injection statics -- exactly the kind of confound that
    // would let this test pass even if `spawn_materialization_repair_task`
    // itself lost its restart supervision. `build` constructs `state`
    // with no background tasks, so the task started below is the only
    // one that can possibly recover the injected panic.
    let state = DaemonState::build("device-under-test".into(), sync_state, store);
    // Fast enough that the test doesn't sit through a real production
    // interval, without being so fast it races the panic injection
    // below (the very first sleep must still land after
    // `TEST_PANIC_ON_NEXT_RUN_ONCE` is set).
    state.set_materialization_repair_sweep_interval(std::time::Duration::from_millis(20));

    TEST_RUN_ONCE_COMPLETIONS.store(0, Ordering::SeqCst);
    TEST_PANIC_ON_NEXT_RUN_ONCE.store(true, Ordering::SeqCst);

    let _handle = spawn_materialization_repair_task(state.clone());

    // Bounded wait comfortably past MATERIALIZATION_REPAIR's own 1s
    // restart backoff plus the 20ms sweep interval: long enough for
    // "panic, restart-backoff, one real completion" to happen at least
    // once if (and only if) the restart supervision actually works.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    let recovered = loop {
        if TEST_RUN_ONCE_COMPLETIONS.load(Ordering::SeqCst) >= 1 {
            break true;
        }
        if tokio::time::Instant::now() >= deadline {
            break false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    assert!(
        recovered,
        "run_once never completed after its first (injected) panic -- spawn_restarting did \
         not recover it, exactly the silent-permanent-death bug this task's own restart \
         supervision exists to prevent"
    );
    // The panic must have genuinely happened (not been skipped by a
    // race) for this to be a real regression test rather than a
    // trivially-true one.
    assert!(
        !TEST_PANIC_ON_NEXT_RUN_ONCE.load(Ordering::SeqCst),
        "sanity: the injected panic flag must have been consumed by a real run_once call"
    );
}
