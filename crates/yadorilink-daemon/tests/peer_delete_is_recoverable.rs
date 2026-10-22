//! A peer's delete is recoverable on this device too.
//!
//! Deleting a file locally moves this device's last live content to trash
//! rather than discarding it. Adopting a *peer's* tombstone has to do the same
//! thing — otherwise "someone else deleted it" is unrecoverable while "I
//! deleted it" is not, which is exactly backwards: the device that did not
//! make the decision is the one most likely to want it back.
//!
//! `control_socket.rs`'s trash round trip covers the local half. This is the
//! adopted half, which nothing else states.
//!
//! The second test here is the same adoption seen from a different angle: a
//! path this device is *holding* (indexed, but deliberately not written to
//! disk under a name this platform cannot take) must give up its held state
//! when the path is tombstoned. A `held_reason` left behind for a path with no
//! live record is an entry nothing will ever clear.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::wait_until_with_context;
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::session_state::VersionState;

const GROUP: &str = "peer-delete-trash-group";
const PATH: &str = "shared.txt";

struct TestDevice {
    device_id: String,
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    _index_dir: tempfile::TempDir,
}

impl TestDevice {
    fn path(&self, relative: &str) -> std::path::PathBuf {
        self.root.path().join(relative)
    }
}

fn setup_device(name: &str) -> TestDevice {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let (sync_state, index_dir) = support::open_file_backed_replica_coordinator();
    let state = DaemonState::new(name.to_string(), Arc::new(sync_state), store);
    support::ensure_device_signing_key(&state);
    TestDevice {
        device_id: name.to_string(),
        state,
        root: tempfile::tempdir().unwrap(),
        _store_dir: store_dir,
        _index_dir: index_dir,
    }
}

fn start_watching(device: &TestDevice) {
    let local_path = device.root.path().to_string_lossy().to_string();
    device.state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    LinkRuntimeController::new(device.state.clone()).start(local_path, GROUP.to_string()).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tombstone_adopted_from_a_peer_leaves_recoverable_trash() {
    let device_a = setup_device("device-a");
    let device_b = setup_device("device-b");

    start_watching(&device_a);
    start_watching(&device_b);
    support::connect_two_daemons(
        &device_a.state,
        &device_a.device_id,
        &device_b.state,
        &device_b.device_id,
        std::slice::from_ref(&GROUP.to_string()),
    )
    .await;

    let content = b"content device-a wrote and device-b deleted";
    std::fs::write(device_a.path(PATH), content).unwrap();
    wait_until_with_context(
        || device_b.path(PATH).exists(),
        Duration::from_secs(60),
        || "the file never reached the deleting device".into(),
    )
    .await;

    // The delete happens on the peer, so what device-a adopts is a tombstone
    // for content device-a itself authored — the case where losing the bytes
    // outright would be least recoverable.
    std::fs::remove_file(device_b.path(PATH)).unwrap();
    // The tombstone commit is the sync point: adoption removes the file first and only then
    // records the tombstone (so a file that could not be removed is never marked deleted).
    // Waiting for the file to vanish would race the index write.
    wait_until_with_context(
        || {
            device_a
                .state
                .replica_coordinator
                .file_index_repository()
                .get_file(GROUP, PATH)
                .unwrap()
                .is_some_and(|record| record.deleted)
        },
        Duration::from_secs(60),
        || "the peer's tombstone never reached the authoring device".into(),
    )
    .await;
    assert!(!device_a.path(PATH).exists(), "a tombstoned file must be absent from disk");

    let trashed =
        device_a.state.replica_coordinator.file_index_repository().list_trashed(GROUP).unwrap();
    assert_eq!(trashed.len(), 1, "the last live content must be listed under trash, not discarded");
    assert_eq!(trashed[0].path, PATH);
    assert_eq!(trashed[0].last_known_size, content.len() as u64);

    // Recoverable means the bytes are still reachable, not merely that a row
    // says "trashed": a trashed version with no block references is a
    // tombstone with extra steps.
    let versions =
        device_a.state.replica_coordinator.sqlite().dag_list_versions(GROUP, PATH).unwrap();
    let trashed_version = versions
        .iter()
        .find(|version| version.state == VersionState::Trashed)
        .expect("exactly one version must be in the trashed state");
    assert!(
        !trashed_version.blocks.is_empty(),
        "the trashed version's block references must survive"
    );
    assert_eq!(
        trashed_version.origin_device_id.as_deref(),
        Some("device-a"),
        "the trashed version still records who originally wrote it"
    );
}

/// A held path's held state clears when a peer's tombstone lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peers_tombstone_clears_a_held_paths_held_state() {
    let device_a = setup_device("device-a");
    let device_b = setup_device("device-b");

    start_watching(&device_a);
    start_watching(&device_b);
    support::connect_two_daemons(
        &device_a.state,
        &device_a.device_id,
        &device_b.state,
        &device_b.device_id,
        std::slice::from_ref(&GROUP.to_string()),
    )
    .await;

    std::fs::write(device_b.path("A.txt"), b"held on the other device").unwrap();
    wait_until_with_context(
        || {
            device_a
                .state
                .replica_coordinator
                .file_index_repository()
                .get_file(GROUP, "A.txt")
                .unwrap()
                .is_some()
        },
        Duration::from_secs(60),
        || "the file never reached the holding device".into(),
    )
    .await;

    // Set up device-local, as a real name-hazard detection would: held state
    // is this device's refusal to write under this name, not anything the
    // group knows about.
    device_a
        .state
        .replica_coordinator
        .materialization_state_repository()
        .set_held(GROUP, "A.txt", "case_collision", 1_000)
        .unwrap();
    assert!(
        device_a
            .state
            .replica_coordinator
            .materialization_state_repository()
            .get_held_state(GROUP, "A.txt")
            .unwrap()
            .is_some(),
        "the path really must be held before the tombstone arrives"
    );

    std::fs::remove_file(device_b.path("A.txt")).unwrap();
    wait_until_with_context(
        || {
            device_a
                .state
                .replica_coordinator
                .file_index_repository()
                .get_file(GROUP, "A.txt")
                .unwrap()
                .is_some_and(|record| record.deleted)
        },
        Duration::from_secs(60),
        || "the peer's tombstone never reached the holding device".into(),
    )
    .await;

    wait_until_with_context(
        || {
            device_a
                .state
                .replica_coordinator
                .materialization_state_repository()
                .get_held_state(GROUP, "A.txt")
                .unwrap()
                .is_none()
        },
        Duration::from_secs(30),
        || "a tombstoned path must not stay held".into(),
    )
    .await;
}
