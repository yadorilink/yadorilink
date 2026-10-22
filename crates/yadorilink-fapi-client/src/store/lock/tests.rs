#![cfg(test)]

use super::*;

#[tokio::test]
async fn a_second_acquirer_waits_and_then_times_out_rather_than_proceeding() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("credentials.lock");

    let held = acquire(&path, Duration::from_secs(1)).await.expect("first acquire");

    let started = Instant::now();
    let err = acquire(&path, Duration::from_millis(200))
        .await
        .expect_err("the lock is held, so this must refuse rather than proceed");
    assert!(matches!(err, StoreError::LockTimeout { .. }), "got {err}");
    assert!(
        started.elapsed() >= Duration::from_millis(150),
        "it returned too fast to have actually waited: {:?}",
        started.elapsed()
    );

    drop(held);
    acquire(&path, Duration::from_millis(500)).await.expect("released");
}

#[test]
fn the_lock_file_survives_release_so_a_waiter_is_never_handed_a_private_copy() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("credentials.lock");
    let runtime =
        tokio::runtime::Builder::new_current_thread().enable_time().build().expect("runtime");
    let held = runtime.block_on(acquire(&path, Duration::from_secs(1))).expect("acquire");
    drop(held);
    assert!(path.exists(), "unlinking the lock file would make the next acquire vacuous");
}
