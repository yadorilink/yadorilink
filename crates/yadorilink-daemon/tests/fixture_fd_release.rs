//! A test process must not accumulate file descriptors with the number of tests it runs.
//!
//! A paired daemon state references itself through its sessions and its peer session driver, so
//! it is not freed when a test lets go of it. Tests used to run out of descriptors for that reason,
//! which forced the consolidated test targets to be split. `isolated_daemon_state` now parks a guard
//! on the runtime that breaks those cycles when the test's runtime shuts down; this test builds
//! paired, watching daemons run after run and fails if the descriptor count grows with the runs.
//!
//! It is its own target because it measures a property of the whole process.
#![cfg(unix)]

mod support;

use std::sync::Arc;
use std::time::Duration;

use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::SegmentBlockStore;

const RUNS: usize = 8;
/// Descriptors one run may leave behind (a runtime's selector, say). A run that keeps its two
/// databases, block stores, watchers and sockets leaves about sixty.
const LEFT_PER_RUN: usize = 6;

fn open_descriptors() -> usize {
    std::fs::read_dir("/dev/fd").expect("list /dev/fd").count()
}

struct Device {
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    _store: tempfile::TempDir,
    _index: tempfile::TempDir,
}

fn device(name: &str) -> Device {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let (coordinator, index_dir) = support::open_file_backed_replica_coordinator();
    let state = yadorilink_daemon::test_support::isolated_daemon_state(
        name.to_string(),
        Arc::new(coordinator),
        store,
    );
    support::ensure_device_signing_key(&state);
    Device { state, root: tempfile::tempdir().unwrap(), _store: store_dir, _index: index_dir }
}

/// One test's worth of daemons: two paired devices watching one folder group.
async fn paired_devices() {
    let (a, b) = (device("fd-a"), device("fd-b"));
    let group = "fd-group".to_string();
    for d in [&a, &b] {
        let path = d.root.path().to_string_lossy().to_string();
        d.state.replica_coordinator.link_repository().add_link(&path, &group).unwrap();
        LinkRuntimeController::new(d.state.clone()).start(path, group.clone()).unwrap();
    }
    support::connect_two_daemons(&a.state, "fd-a", &b.state, "fd-b", std::slice::from_ref(&group))
        .await;
    std::fs::write(a.root.path().join("file.txt"), "content").unwrap();
    let arrived = b.root.path().join("file.txt");
    support::wait_until(|| arrived.exists(), Duration::from_secs(20)).await;
}

fn one_test() {
    let runtime =
        tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    runtime.block_on(paired_devices());
    // The end of a test: its runtime is dropped, and with it the guard parked on it.
    drop(runtime);
}

#[test]
fn descriptors_do_not_grow_with_the_number_of_tests_a_process_runs() {
    support::ensure_isolated_config_dir();
    // The first run opens what every later one reuses.
    one_test();
    let baseline = open_descriptors();
    for _ in 0..RUNS {
        one_test();
    }
    let after = open_descriptors();
    assert!(
        after <= baseline + RUNS * LEFT_PER_RUN,
        "{RUNS} further runs of a paired test left {} descriptors open ({baseline} -> {after}); a \
         daemon state must be released when its test's runtime ends (see \
         `test_support::isolated_daemon_state`)",
        after.saturating_sub(baseline)
    );
}
