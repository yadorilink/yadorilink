#![cfg(test)]

use super::*;

/// An expired network deadline must surface as an ordinary `Err`.
///
/// That is the whole mechanism by which the single-flight key gets
/// released: `SingleFlight::run` drops its `ReleaseOnDrop` guard when
/// the work future returns, so an error unwinds exactly like any other
/// failure and frees the pair. A deadline that instead logged and
/// returned `Ok` would leave the key claimed and change nothing.
#[tokio::test]
async fn an_expired_network_deadline_becomes_an_error() {
    let result: Result<(), SyncRuntimeError> =
        with_deadline("connect", std::time::Duration::from_millis(10), async {
            tokio::time::sleep(std::time::Duration::from_secs(3_600)).await;
            Ok::<(), SyncRuntimeError>(())
        })
        .await;

    match result {
        Err(SyncRuntimeError::NetworkTimeout { stage, .. }) => assert_eq!(stage, "connect"),
        other => panic!("an expired deadline must be an error, got {other:?}"),
    }
}

/// Work that finishes inside its deadline is untouched -- the deadline
/// must not perturb the ordinary path.
#[tokio::test]
async fn work_inside_its_deadline_passes_through_unchanged() {
    let result: Result<u8, SyncRuntimeError> =
        with_deadline("connect", std::time::Duration::from_secs(60), async {
            Ok::<u8, SyncRuntimeError>(7)
        })
        .await;
    assert_eq!(result.unwrap(), 7);
}
