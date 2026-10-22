//! Ignoring a path is local, and relaying is not.
//!
//! `.yadorilinkignore` says what this device projects onto its own disk. It
//! says nothing about what the group holds, and nothing about what this device
//! owes its other peers. A device in the middle of a chain that dropped an
//! ignored peer's Change instead of relaying it would silently partition the
//! group along one device's local preference — and the further peers would
//! have no way to tell that from the file simply not existing.
//!
//! ```text
//!   A ── B ── C          B ignores *.log; A and C do not
//!
//!   A publishes secret.log
//!     → B: not on disk, not in B's index      (ignore is a local decision)
//!        but the Change is in B's DAG         (so B can still relay it)
//!     → C: indexed, having arrived through B  (relaying really happened)
//! ```
//!
//! A and C are never connected to each other, so anything C holds came through
//! B. What is asserted on C is the Change reaching its index, not the file's
//! bytes: B does not hold blocks for a path it ignores — that is the whole
//! point of ignoring it — so content for C has to come from a device that
//! holds it, and demanding bytes here would be asserting block availability
//! through a device that legitimately has none.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::wait_until_with_context;
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::SegmentBlockStore;

const GROUP: &str = "ignored-relay-group";

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

    fn indexed(&self, path: &str) -> bool {
        self.state
            .replica_coordinator
            .file_index_repository()
            .get_file(GROUP, path)
            .ok()
            .flatten()
            .is_some_and(|record| !record.deleted)
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

async fn pair(a: &TestDevice, b: &TestDevice) {
    support::connect_two_daemons(
        &a.state,
        &a.device_id,
        &b.state,
        &b.device_id,
        std::slice::from_ref(&GROUP.to_string()),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_path_one_device_ignores_still_reaches_the_peers_behind_it() {
    let device_a = setup_device("device-a");
    let device_b = setup_device("device-b");
    let device_c = setup_device("device-c");

    // Written before the link starts so the pattern is in force from the
    // first scan — a file adopted first and ignored second is a different
    // property (`ignore_pattern_rescan.rs` states that one).
    std::fs::write(device_b.path(".yadorilinkignore"), "*.log\n").unwrap();

    start_watching(&device_a);
    start_watching(&device_b);
    start_watching(&device_c);
    // A chain, not a mesh: nothing connects A to C, so anything C holds came
    // through B.
    pair(&device_a, &device_b).await;
    pair(&device_b, &device_c).await;

    std::fs::write(device_a.path("secret.log"), b"a line device-b would rather not keep").unwrap();
    // An ordinary file alongside it, as the synchronization point: once this
    // has travelled the whole chain, the ignored file has had the same
    // opportunity, so its absence on B is a decision rather than a wait.
    std::fs::write(device_a.path("ordinary.txt"), b"plain").unwrap();

    wait_until_with_context(
        || device_c.indexed("secret.log") && device_c.indexed("ordinary.txt"),
        Duration::from_secs(60),
        || {
            format!(
                "the far end of the chain never received both files: secret.log={} ordinary.txt={}",
                device_c.indexed("secret.log"),
                device_c.indexed("ordinary.txt"),
            )
        },
    )
    .await;
    // Indexed is not yet on disk: a path enters the index before its content is projected, so
    // wait for the projection on both devices before reading it back.
    wait_until_with_context(
        || {
            device_b.path("ordinary.txt").exists()
                && std::fs::read(device_c.path("ordinary.txt")).is_ok_and(|bytes| bytes == b"plain")
        },
        Duration::from_secs(60),
        || {
            format!(
                "ordinary.txt was indexed but never projected: on b={} on c={:?}",
                device_b.path("ordinary.txt").exists(),
                std::fs::read(device_c.path("ordinary.txt")).map_err(|error| error.kind()),
            )
        },
    )
    .await;
    assert_eq!(
        std::fs::read(device_c.path("ordinary.txt")).unwrap(),
        b"plain",
        "the ordinary file's content must reach the far end intact"
    );
    assert!(
        device_b.path("ordinary.txt").exists(),
        "the relaying device must still project what it does not ignore"
    );
    assert!(
        !device_b.path("secret.log").exists(),
        "the ignored path must not be projected onto the ignoring device's disk"
    );
    assert!(
        !device_b.indexed("secret.log"),
        "the ignored path must not enter the ignoring device's index either"
    );

    // The relay half, stated on B directly as well as through C: ignoring a
    // path must not drop what authored it from this device. Without it, B
    // would be a hole in the group rather than a device with a local
    // preference.
    assert_relayed(&device_b, &device_c, "secret.log");
}

/// `path`, which `relay` ignores, still reaches `far_end` through it: the far
/// end's row names what authored it, and the relay still holds that authoring
/// (a DCF change, or the native head) although it projects nothing.
fn assert_relayed(relay: &TestDevice, far_end: &TestDevice, path: &str) {
    let heads_on = |device: &TestDevice| {
        device
            .state
            .replica_coordinator
            .database()
            .write(|conn| {
                yadorilink_sync_sqlite::native_store::native_heads_at(
                    conn,
                    &yadorilink_replica_domain::ids::FolderGroupId(GROUP.to_owned()),
                    &yadorilink_replica_domain::ids::SyncPath(path.to_owned()),
                )
            })
            .unwrap()
    };
    let (relayed, held) = (heads_on(far_end), heads_on(relay));
    assert!(!relayed.is_empty(), "the far end must hold a native head for the relayed {path}");
    assert_eq!(
        held.iter().map(|head| head.payload.provenance).collect::<Vec<_>>(),
        relayed.iter().map(|head| head.payload.provenance).collect::<Vec<_>>(),
        "{path}'s head must stay in the relaying device's native state"
    );
}

/// The same rule for an explicit directory: a directory-only pattern on B
/// (`build/`) keeps a peer's empty directory off B's disk and out of B's
/// index, while its Change is still relayed to C.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn incoming_explicit_directory_on_locally_ignored_path_follows_file_rule() {
    let device_a = setup_device("device-a");
    let device_b = setup_device("device-b");
    let device_c = setup_device("device-c");
    std::fs::write(device_b.path(".yadorilinkignore"), "build/\n").unwrap();

    start_watching(&device_a);
    start_watching(&device_b);
    start_watching(&device_c);
    pair(&device_a, &device_b).await;
    pair(&device_b, &device_c).await;

    std::fs::create_dir(device_a.path("build")).unwrap();
    std::fs::write(device_a.path("ordinary.txt"), b"plain").unwrap();

    wait_until_with_context(
        || device_c.indexed("build") && device_c.indexed("ordinary.txt"),
        Duration::from_secs(60),
        || {
            format!(
                "the far end never received both entries: build={} ordinary.txt={}",
                device_c.indexed("build"),
                device_c.indexed("ordinary.txt"),
            )
        },
    )
    .await;
    wait_until_with_context(
        || device_c.path("build").is_dir(),
        Duration::from_secs(30),
        || "the far end never materialized the explicit directory".to_string(),
    )
    .await;
    assert!(device_b.path("ordinary.txt").exists());
    assert!(
        !device_b.path("build").exists(),
        "the ignored directory must not be projected onto the ignoring device's disk"
    );
    assert!(!device_b.indexed("build"), "the ignored directory must stay out of B's index");
    assert_relayed(&device_b, &device_c, "build");
}
