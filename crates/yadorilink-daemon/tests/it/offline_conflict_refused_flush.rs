//! Two devices edit the same file while one of them cannot get its change checkpointed, and the
//! connection to the coordination plane stays up the whole time.
//!
//! The refused device's change stays Pending (a Pending change is never sent to a peer). Every
//! trigger that flushes it again -- a reconnect to the plane, a policy change, a later local
//! commit -- is absent here, so only the daemon's own retry can publish it. Without that retry the
//! other device never learns the change, and which of the two ends up stuck depends on a version
//! hash, so both orders are run: one of them would hang forever without the retry. Both versions
//! must end up on both devices.

use crate::support;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::{register_with_fake, wait_until_with_context};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::peer_orchestrator;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;

const GROUP: &str = "refused-flush-group";
const FROM_A: &[u8] = b"the edit made on device A, a little longer";
const FROM_B: &[u8] = b"the edit made on B";

fn new_daemon(device_id: &str) -> Arc<DaemonState> {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(Box::leak(Box::new(store_dir)).path()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    support::fast_daemon_state(device_id.to_string(), sync_state, store)
}

fn link(state: &Arc<DaemonState>, root: &std::path::Path) {
    let local_path = root.to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    LinkRuntimeController::new(state.clone()).start(local_path, GROUP.to_string()).unwrap();
}

fn spawn_orchestrator(coordination_addr: String, device_id: String, state: Arc<DaemonState>) {
    let config = peer_orchestrator::OrchestratorConfig {
        coordination_addr,
        auth: yadorilink_fapi_client::test_support::offline_auth(),
        device_id: device_id.clone(),
    };
    tokio::spawn(async move {
        if let Err(error) = peer_orchestrator::run(config, state).await {
            eprintln!("peer orchestrator for {device_id} stopped: {error}");
        }
    });
}

/// The regular files at the top of `root` by name, ignoring reserved names.
fn files(root: &std::path::Path) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(root)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|t| t.is_file()))
        .filter(|entry| !entry.file_name().to_string_lossy().starts_with(".yadorilink"))
        .filter_map(|entry| {
            let bytes = std::fs::read(entry.path()).ok()?;
            Some((entry.file_name().to_string_lossy().into_owned(), bytes))
        })
        .collect()
}

async fn indexed_with_size(state: &DaemonState, path: &str, size: usize) -> bool {
    state
        .replica_coordinator
        .file_index_repository()
        .get_file(GROUP, path)
        .unwrap()
        .is_some_and(|record| record.size == size as u64 && !record.deleted)
}

async fn run(refused_device: &str) {
    let _ = tracing_subscriber::fmt::try_init();
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let a = new_daemon("device-a");
    let b = new_daemon("device-b");
    let root_a = tempfile::tempdir().unwrap();
    let root_b = tempfile::tempdir().unwrap();
    register_with_fake(&fake, &a, "device-a", &[GROUP]).await;
    register_with_fake(&fake, &b, "device-b", &[GROUP]).await;

    std::fs::write(root_a.path().join("shared.txt"), b"baseline").unwrap();
    link(&a, root_a.path());
    link(&b, root_b.path());
    spawn_orchestrator(fake.addr(), "device-a".into(), a.clone());
    spawn_orchestrator(fake.addr(), "device-b".into(), b.clone());
    support::advertise_substrate_between(&[&a, &b]).await;

    wait_until_with_context(
        || a.peers.has_session("device-b") && b.peers.has_session("device-a"),
        Duration::from_secs(60),
        || "the peer sessions did not connect".to_owned(),
    )
    .await;
    wait_until_with_context(
        || root_b.path().join("shared.txt").exists(),
        Duration::from_secs(30),
        || "the baseline never reached device B".to_owned(),
    )
    .await;

    // The plane refuses this device's checkpoint requests; no connection is touched.
    fake.refuse_checkpoints_from(refused_device);
    std::fs::write(root_a.path().join("shared.txt"), FROM_A).unwrap();
    std::fs::write(root_b.path().join("shared.txt"), FROM_B).unwrap();
    // Both edits are captured locally before the plane is allowed to answer.
    for _ in 0..300 {
        if indexed_with_size(&a, "shared.txt", FROM_A.len()).await
            && indexed_with_size(&b, "shared.txt", FROM_B.len()).await
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(indexed_with_size(&a, "shared.txt", FROM_A.len()).await, "A never indexed its edit");
    assert!(indexed_with_size(&b, "shared.txt", FROM_B.len()).await, "B never indexed its edit");

    // The refusal has really happened (the daemon asked and was turned away) before it is
    // lifted; otherwise the first request could simply arrive after the lift and pass.
    wait_until_with_context(
        || fake.checkpoint_refusals(refused_device) >= 1,
        Duration::from_secs(30),
        || format!("{refused_device} never asked for a checkpoint while it was refused"),
    )
    .await;
    fake.accept_checkpoints_from(refused_device);

    wait_until_with_context(
        || {
            let (on_a, on_b) = (files(root_a.path()), files(root_b.path()));
            let has = |m: &BTreeMap<String, Vec<u8>>, bytes: &[u8]| m.values().any(|v| v == bytes);
            on_a == on_b && has(&on_a, FROM_A) && has(&on_a, FROM_B)
        },
        Duration::from_secs(90),
        || {
            format!(
                "the devices did not end identical with both versions kept (refused: \
                 {refused_device})\nA: {:?}\nB: {:?}",
                files(root_a.path()).keys().collect::<Vec<_>>(),
                files(root_b.path()).keys().collect::<Vec<_>>()
            )
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_flush_on_device_a_is_retried_and_both_versions_end_on_both_devices() {
    run("device-a").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_flush_on_device_b_is_retried_and_both_versions_end_on_both_devices() {
    run("device-b").await;
}
