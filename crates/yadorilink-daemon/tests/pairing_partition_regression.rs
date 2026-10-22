//! What partitions two directly paired test devices, and what does not.
//!
//! `support::connect_two_daemons_with_link` hands back a `PairingLink`, and
//! closing it ends the two sessions. It is easy to read that as "the devices
//! are now disconnected", and a test that did would be building its
//! "isolated" divergence on devices that are still converging: changes travel
//! over each device's reconciliation stack, which the link knows nothing
//! about. `support::sever_reconciliation` is what partitions them.
//!
//! This pins both halves, plus the way back: closing the link alone still
//! converges, severing stops convergence, and pairing again restores it.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::{open_file_backed_replica_coordinator, TestAccount};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::SegmentBlockStore;

struct TestDevice {
    device_id: String,
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    _index_dir: tempfile::TempDir,
}

async fn setup_device(account: &TestAccount, name: &str) -> TestDevice {
    let device_id = support::register_device(account, name, [0u8; 32]).await;
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let (sync_state, index_dir) = open_file_backed_replica_coordinator();
    let state = DaemonState::new(device_id.clone(), Arc::new(sync_state), store);
    support::ensure_device_signing_key(&state);
    TestDevice {
        device_id,
        state,
        root: tempfile::tempdir().unwrap(),
        _store_dir: store_dir,
        _index_dir: index_dir,
    }
}

async fn start_watching(device: &TestDevice, group_id: &str) {
    let local_path = device.root.path().to_string_lossy().to_string();
    device.state.replica_coordinator.link_repository().add_link(&local_path, group_id).unwrap();
    LinkRuntimeController::new(device.state.clone())
        .start(local_path, group_id.to_string())
        .unwrap();
}

fn knows(device: &TestDevice, group_id: &str, path: &str) -> bool {
    !support::native_path_heads(&device.state, group_id, path).is_empty()
}

/// Writes `path` on `from` and waits until `from` itself has recorded it,
/// so a later "the peer never saw it" cannot mean "it was never captured".
async fn write_and_capture(from: &TestDevice, group_id: &str, path: &str) {
    std::fs::write(from.root.path().join(path), path.as_bytes()).unwrap();
    support::wait_until_progress(
        || usize::from(!knows(from, group_id, path)),
        Duration::from_secs(120),
        Duration::from_secs(240),
        || format!("{} never captured its own {path}", from.device_id),
    )
    .await;
}

async fn wait_known(device: &TestDevice, group_id: &str, path: &str, why: &str) {
    // One event, so there is no progress to see; the stall limit is the wait. It is long because
    // a busy machine makes the same convergence several times slower.
    support::wait_until_progress(
        || usize::from(!knows(device, group_id, path)),
        Duration::from_secs(120),
        Duration::from_secs(240),
        || {
            format!(
                "{} never learned {path}: {why}; {}",
                device.device_id,
                support::daemon_status_summary(&device.state)
            )
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closing_the_pairing_link_is_not_a_partition_but_severing_reconciliation_is() {
    let coordination_addr = support::start_coordination_server().await;
    let account = support::register_and_login(&coordination_addr, "partition@example.com").await;
    let a = setup_device(&account, "device-a").await;
    let b = setup_device(&account, "device-b").await;
    let group_id = support::create_folder_group(&account, "pairing-partition-group").await;
    start_watching(&a, &group_id).await;
    start_watching(&b, &group_id).await;
    let groups = std::slice::from_ref(&group_id);

    let (_handles, link) = support::connect_two_daemons_with_link(
        &a.state,
        &a.device_id,
        &b.state,
        &b.device_id,
        groups,
    )
    .await;
    write_and_capture(&a, &group_id, "before.txt").await;
    wait_known(&b, &group_id, "before.txt", "the pairing never converged at all").await;

    // Closing the link ends the sessions and nothing else.
    link.close();
    assert!(!link.is_open());
    write_and_capture(&a, &group_id, "after-close.txt").await;
    wait_known(
        &b,
        &group_id,
        "after-close.txt",
        "closing the pairing link must not partition reconciliation",
    )
    .await;

    // Severing is the partition: a change made now must not arrive.
    support::sever_reconciliation(&a.state, &b.state).await;
    write_and_capture(&a, &group_id, "during-partition.txt").await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(
        !knows(&b, &group_id, "during-partition.txt"),
        "a change made after sever_reconciliation reached the peer: the partition is not one"
    );

    // Pairing again is the way back.
    support::connect_two_daemons(&a.state, &a.device_id, &b.state, &b.device_id, groups).await;
    wait_known(&b, &group_id, "during-partition.txt", "re-pairing must restore convergence").await;
}
