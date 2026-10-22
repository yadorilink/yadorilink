#![cfg(test)]

use super::*;

#[test]
fn for_tests_permit_always_verifies() {
    assert!(RootCommitPermit::for_tests().verify().is_ok());
}

#[test]
fn an_operation_admitted_before_stopping_is_not_refused_by_a_racing_begin_stopping() {
    let lease = RootLease::for_tests();
    let op = lease.begin_operation().unwrap();
    lease.begin_stopping();
    // The already-admitted operation's permit must still verify -- a
    // caller mid-operation when stop begins must be allowed to finish.
    assert!(op.permit().verify().is_ok());
}

#[test]
fn begin_operation_refuses_once_stopping_has_begun() {
    let lease = RootLease::for_tests();
    lease.begin_stopping();
    assert!(lease.begin_operation().is_err());
}

#[tokio::test]
async fn wait_drained_blocks_until_every_admitted_operation_drops() {
    let lease = RootLease::for_tests();
    let op = lease.begin_operation().unwrap();
    lease.begin_stopping();

    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), lease.wait_drained())
            .await
            .is_err(),
        "wait_drained must not resolve while an admitted LinkOperation is still held"
    );
    drop(op);
    tokio::time::timeout(std::time::Duration::from_secs(1), lease.wait_drained())
        .await
        .expect("wait_drained must resolve promptly once the LinkOperation drops");
}

#[test]
fn a_quiesced_lease_refuses_new_operations_until_the_pause_ends() {
    let lease = RootLease::for_tests();
    let held = lease.begin_operation().unwrap();
    lease.begin_quiesce();
    assert!(lease.begin_operation().is_err(), "a pause refuses new work");
    drop(held);
    lease.end_quiesce();
    assert!(lease.begin_operation().is_ok(), "ending the pause reopens admission");
}

#[test]
fn ending_a_pause_never_reopens_a_stopping_lease() {
    let lease = RootLease::for_tests();
    lease.begin_quiesce();
    lease.begin_stopping();
    lease.end_quiesce();
    assert!(lease.begin_operation().is_err());
}

#[tokio::test]
async fn a_quiesced_lease_drains_once_its_admitted_operation_finishes() {
    let lease = std::sync::Arc::new(RootLease::for_tests());
    let op_lease = lease.clone();
    let op = hold_admission(op_lease);
    lease.begin_quiesce();
    let waiter = tokio::spawn({
        let lease = lease.clone();
        async move { lease.wait_drained().await }
    });
    tokio::task::yield_now().await;
    assert!(!waiter.is_finished(), "an admitted operation holds the drain");
    drop(op);
    tokio::time::timeout(std::time::Duration::from_secs(5), waiter).await.unwrap().unwrap();
}

/// Holds one admission on `lease` for as long as the returned guard lives.
fn hold_admission(lease: std::sync::Arc<RootLease>) -> impl Drop {
    struct Held(std::sync::Arc<RootLease>);
    impl Drop for Held {
        fn drop(&mut self) {
            self.0.release();
        }
    }
    lease.active.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    Held(lease)
}
