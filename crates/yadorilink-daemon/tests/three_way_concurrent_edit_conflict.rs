//! Regression coverage for a multiway-conflict name/content mismatch bug:
//! when three or more devices concurrently edit the same path, a conflict-
//! copy's deterministic name must always match the content actually
//! materialized under it, and every device must independently converge on the
//! same (name, content) pairing.
//!
//! This is the deterministic, minimal reproduction that let the bug be root-
//! caused and fixed: the conflict-copy naming was attributing a copy's
//! identity to whichever peer session happened to process it, rather than the
//! content's true origin device.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::{open_file_backed_replica_coordinator, real_entry_names, wait_until_with_context};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::SegmentBlockStore;

struct TestDevice {
    device_id: String,
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    // File-backed WAL (production's concurrency model) instead of
    // open_in_memory's shared-cache backend — see open_file_backed_replica_coordinator's
    // doc comment. Held only to keep the backing temp file alive.
    _index_dir: tempfile::TempDir,
}

fn setup_device(name: &str) -> TestDevice {
    // No coordination plane is needed: `connect_two_daemons` pairs devices
    // directly and installs write authorization locally, so the device id is
    // just a unique string.
    let device_id = name.to_string();
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let (sync_state, index_dir) = open_file_backed_replica_coordinator();
    let state = DaemonState::new(device_id.clone(), Arc::new(sync_state), store);
    // Give the device a change-signing key before its link watch starts, so the
    // change-DAG emitter is wired and local edits actually propagate.
    support::ensure_device_signing_key(&state);
    TestDevice {
        device_id,
        state,
        root: tempfile::tempdir().unwrap(),
        _store_dir: store_dir,
        _index_dir: index_dir,
    }
}

fn start_watching(device: &TestDevice, group_id: &str) {
    let local_path = device.root.path().to_string_lossy().to_string();
    device.state.replica_coordinator.link_repository().add_link(&local_path, group_id).unwrap();
    LinkRuntimeController::new(device.state.clone())
        .start(local_path, group_id.to_string())
        .unwrap();
}

/// Pairs every device with every other over loopback (a full mesh), the direct-
/// transport stand-in for the coordination-driven peer connections the
/// orchestrator would establish for an authorized group.
async fn connect_mesh(devices: &[TestDevice], group_id: &str) {
    for i in 0..devices.len() {
        for j in (i + 1)..devices.len() {
            support::connect_two_daemons(
                &devices[i].state,
                &devices[i].device_id,
                &devices[j].state,
                &devices[j].device_id,
                std::slice::from_ref(&group_id.to_string()),
            )
            .await;
        }
    }
}

/// A device's real (non-artifact) entries, keyed by name, valued by content —
/// plain content (not a hash) so a failure's assertion message is directly
/// readable.
fn snapshot(root: &std::path::Path) -> std::collections::HashMap<String, String> {
    real_entry_names(root)
        .into_iter()
        .map(|name| {
            let content = std::fs::read_to_string(root.join(&name)).unwrap_or_default();
            (name, content)
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_devices_editing_the_same_new_file_simultaneously_never_mismatches_name_and_content()
{
    // The three-way conflict converges only once a winner replaces the loser's
    // original, which the closed Windows gate withholds.
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    support::ensure_isolated_config_dir();

    let devices: Vec<TestDevice> = (0..3).map(|i| setup_device(&format!("device-{i}"))).collect();
    let group_id = "three-way-conflict-group";
    for device in &devices {
        start_watching(device, group_id);
    }
    connect_mesh(&devices, group_id).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // All 3 devices independently create "shared.bin" with DISTINCT content,
    // issued back-to-back with no pause — a real stagger between writes would
    // give each write time to propagate and be adopted sequentially rather than
    // racing as a genuine concurrent conflict, so the zero-stagger timing here
    // is deliberate.
    for (i, device) in devices.iter().enumerate() {
        std::fs::write(device.root.path().join("shared.bin"), format!("content from device {i}"))
            .unwrap();
    }

    // Wait for genuine convergence: every device holds the identical
    // name→content map (three conflict-resolved entries), not merely equal
    // file-name sets — the latter is satisfied trivially before any content
    // propagates, when every device still holds only its own `shared.bin`.
    let devices_ref = &devices;
    wait_until_with_context(
        || {
            let reference = snapshot(devices_ref[0].root.path());
            reference.len() == 3
                && devices_ref[1..].iter().all(|d| snapshot(d.root.path()) == reference)
        },
        Duration::from_secs(60),
        || {
            devices_ref
                .iter()
                .enumerate()
                .map(|(i, d)| format!("device-{i}={:?}", real_entry_names(d.root.path())))
                .collect::<Vec<_>>()
                .join("; ")
        },
    )
    .await;

    let reference = snapshot(devices[0].root.path());
    for (i, device) in devices.iter().enumerate().skip(1) {
        let snap = snapshot(device.root.path());
        assert_eq!(
            snap, reference,
            "device-{i} diverged from device-0 — a conflict-copy name matching on both devices but \
             holding different content indicates the conflict resolver has regressed to attributing \
             a conflict copy's identity to the wrong origin device"
        );
    }
}
