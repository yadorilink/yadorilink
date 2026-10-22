#![cfg(test)]

use std::future::Future;
use std::pin::Pin;

use super::*;
use crate::link_runtime::dependencies::LinkRuntimeHostPort;

/// A `LinkRuntimeHostPort` that does nothing -- these tests only exercise
/// `GroupStartupReadyGuard`'s own `sync_state`-based ready/failed
/// bookkeeping, never the daemon-wide broadcast/write-activity/signing-key
/// operations the real host implementation reaches.
struct NoopHost;

impl LinkRuntimeHostPort for NoopHost {
    fn note_capture_settled(&self, _group_id: &str) {}

    fn on_local_native_commit<'a>(
        &'a self,
        _group_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }

    fn begin_write_activity(&self) -> Box<dyn Send + '_> {
        Box::new(())
    }

    fn device_signing_key(&self) -> Option<ed25519_dalek::SigningKey> {
        None
    }
}

fn test_deps() -> Arc<LinkRuntimeDependencies> {
    let block_store = Arc::new(
        yadorilink_local_storage::SegmentBlockStore::new(tempfile::tempdir().unwrap().keep())
            .unwrap(),
    );
    let replica_coordinator =
        Arc::new(crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap());
    Arc::new(LinkRuntimeDependencies {
        replica_coordinator,
        block_store,
        telemetry: Arc::new(crate::runtime_telemetry::RuntimeTelemetry::new(
            tokio::sync::broadcast::channel(16).0,
        )),
        device_id: "device-a".to_string(),
        host: Arc::new(NoopHost),
    })
}

/// A startup that unwinds/returns early before calling `mark_ready` (its
/// guard drops while unresolved) must transition the group to `Failed`, so
/// peer apply fail-closes — it must NOT be released as ready over the
/// half-built index. This is the core of the fail-open fix: a startup panic
/// can no longer open the gate.
#[tokio::test]
async fn startup_panic_must_not_release_peer_apply_as_ready() {
    let deps = test_deps();
    let generation = deps.replica_coordinator.startup_readiness().begin_group_startup("g");
    // Model a startup that panics / returns early before `mark_ready`: the
    // guard is dropped while still unresolved.
    {
        let _guard = GroupStartupReadyGuard::new(deps.clone(), "g".to_string(), generation);
    }
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        deps.replica_coordinator.wait_group_ready("g"),
    )
    .await
    .expect("wait must resolve, not hang");
    assert!(
        result.is_err(),
        "a startup that dropped its guard without completing must fail-close peer apply, \
         never open the gate as ready over a half-built index"
    );
}

/// Aborting the startup task (as `LinkRuntimeController::stop` does with
/// `handle.abort()`) drops its guard mid-startup, which must transition the
/// group to `Failed` (fail-closed) rather than leaving it wedged in
/// `Starting` or opening it as ready.
#[tokio::test]
async fn startup_task_abort_transitions_group_to_failed() {
    let deps = test_deps();
    let generation = deps.replica_coordinator.startup_readiness().begin_group_startup("g");

    let task_deps = deps.clone();
    let handle = tokio::spawn(async move {
        let _guard = GroupStartupReadyGuard::new(task_deps, "g".to_string(), generation);
        // Startup is "in progress": hold the guard across an await that
        // parks until the task is aborted.
        std::future::pending::<()>().await;
    });

    // Let the task reach the park point so its guard is actually constructed
    // and held across the await, then abort mid-startup.
    tokio::task::yield_now().await;
    handle.abort();
    let _ = handle.await;

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        deps.replica_coordinator.wait_group_ready("g"),
    )
    .await
    .expect("wait must resolve, not hang");
    assert!(
        result.is_err(),
        "aborting the startup task must transition the group to Failed (fail-closed), \
         not leave it wedged or open it as ready"
    );
}
