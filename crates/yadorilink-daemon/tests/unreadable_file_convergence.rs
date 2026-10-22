//! An unreadable local file must neither be overwritten by a peer's same-name
//! file nor stop healthy files from converging (two real devices, end to end).
//!
//! Unix only: the files are made unreadable with mode 000. A user who can read
//! them anyway (root) cannot exercise the scenario, so the tests skip there.
#![cfg(unix)]

mod support;

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use support::wait_until;
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::SegmentBlockStore;

/// Makes `path` unreadable; restores read permission on drop so the temp dir can be removed.
struct Unreadable(PathBuf);

impl Unreadable {
    /// `None` when the file is still readable (running as root): the scenario cannot be set up.
    fn lock(path: PathBuf) -> Option<Self> {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let guard = Self(path);
        std::fs::File::open(&guard.0).is_err().then_some(guard)
    }
}

impl Drop for Unreadable {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o644));
    }
}

fn read_bytes_ignoring_mode(path: &Path) -> Vec<u8> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let bytes = std::fs::read(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000)).unwrap();
    bytes
}

struct Device {
    state: Arc<DaemonState>,
    id: String,
    root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    _index_dir: tempfile::TempDir,
}

async fn device(account: &support::TestAccount, name: &str, group_id: &str) -> Device {
    let id = support::register_device(account, name, [0u8; 32]).await;
    support::grant_access(account, group_id, &id).await;
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let (sync_state, index_dir) = support::open_file_backed_replica_coordinator();
    let sync_state = Arc::new(sync_state);
    let state = DaemonState::new(id.clone(), sync_state, store);
    support::ensure_device_signing_key(&state);
    Device {
        state,
        id,
        root: tempfile::tempdir().unwrap(),
        _store_dir: store_dir,
        _index_dir: index_dir,
    }
}

impl Device {
    fn path(&self, rel: &str) -> PathBuf {
        self.root.path().join(rel)
    }

    fn start(&self, group_id: &str) {
        let local_path = self.root.path().to_string_lossy().to_string();
        self.state.replica_coordinator.link_repository().add_link(&local_path, group_id).unwrap();
        LinkRuntimeController::new(self.state.clone())
            .start(local_path, group_id.to_string())
            .unwrap();
    }

    /// `Some(deleted)` when the device's index has a row for `rel`.
    fn row(&self, group_id: &str, rel: &str) -> Option<bool> {
        self.state
            .replica_coordinator
            .file_index_repository()
            .get_file(group_id, rel)
            .unwrap()
            .map(|record| record.deleted)
    }
}

/// Two devices over one folder; `prepare` runs on the roots before either link starts.
async fn two_devices(
    email: &str,
    prepare: impl FnOnce(&Device, &Device) -> bool,
) -> Option<(Device, Device, String)> {
    let coordination_addr = support::start_coordination_server().await;
    let account = support::register_and_login(&coordination_addr, email).await;
    let group_id = support::create_folder_group(&account, "unreadable-group").await;
    let a = device(&account, "device-a", &group_id).await;
    let b = device(&account, "device-b", &group_id).await;
    if !prepare(&a, &b) {
        return None;
    }
    a.start(&group_id);
    b.start(&group_id);
    support::connect_two_daemons(&a.state, &a.id, &b.state, &b.id, std::slice::from_ref(&group_id))
        .await;
    Some((a, b, group_id))
}

/// An unindexed unreadable local file and a same-name remote file: the local bytes survive and
/// the peer's version is not written over them, while healthy files still converge.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreadable_local_file_is_not_overwritten_by_a_same_name_remote_file() {
    let mut lock = None;
    let Some((a, b, group_id)) = two_devices("unreadable-same-name@example.com", |a, b| {
        std::fs::write(a.path("secret.txt"), b"private bytes on device a").unwrap();
        std::fs::write(a.path("healthy-a.txt"), b"healthy a").unwrap();
        std::fs::write(b.path("secret.txt"), b"the peer's version of the name").unwrap();
        std::fs::write(b.path("healthy-b.txt"), b"healthy b").unwrap();
        lock = Unreadable::lock(a.path("secret.txt"));
        lock.is_some()
    })
    .await
    else {
        eprintln!("skipped: the file is readable despite mode 000 (running as root)");
        return;
    };

    // Healthy files converge in both directions with the unreadable file present.
    wait_until(
        || a.path("healthy-b.txt").exists() && b.path("healthy-a.txt").exists(),
        Duration::from_secs(30),
    )
    .await;
    assert_eq!(std::fs::read(a.path("healthy-b.txt")).unwrap(), b"healthy b");
    assert_eq!(std::fs::read(b.path("healthy-a.txt")).unwrap(), b"healthy a");
    // The peer's same-name version had every chance to arrive.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let locked = lock.as_ref().unwrap();
    let mode = std::fs::metadata(&locked.0).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o000, "the unreadable file was neither replaced nor re-created");
    assert_eq!(
        read_bytes_ignoring_mode(&a.path("secret.txt")),
        b"private bytes on device a",
        "the local bytes are untouched"
    );
    assert_eq!(
        std::fs::read(b.path("secret.txt")).unwrap(),
        b"the peer's version of the name",
        "the peer's file is not replaced by anything"
    );
    assert_ne!(
        a.row(&group_id, "secret.txt"),
        Some(true),
        "the unreadable path is never inferred as deleted"
    );
    assert_ne!(
        b.row(&group_id, "secret.txt"),
        Some(true),
        "no deletion reaches the peer for the unreadable path"
    );
}

/// An unreadable file only on one device: it is skipped, healthy files converge both ways, and
/// the peer receives neither the file nor a deletion for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn healthy_files_converge_while_an_unreadable_file_sits_in_the_root() {
    let mut lock = None;
    let Some((a, b, group_id)) = two_devices("unreadable-converge@example.com", |a, b| {
        std::fs::write(a.path("locked.txt"), b"locked on device a").unwrap();
        std::fs::write(a.path("healthy-a.txt"), b"healthy a").unwrap();
        std::fs::write(b.path("healthy-b.txt"), b"healthy b").unwrap();
        lock = Unreadable::lock(a.path("locked.txt"));
        lock.is_some()
    })
    .await
    else {
        eprintln!("skipped: the file is readable despite mode 000 (running as root)");
        return;
    };

    wait_until(
        || a.path("healthy-b.txt").exists() && b.path("healthy-a.txt").exists(),
        Duration::from_secs(30),
    )
    .await;
    // A file made while the unreadable one is present also syncs, through the live watcher.
    std::fs::write(a.path("later.txt"), b"made later").unwrap();
    wait_until(|| b.path("later.txt").exists(), Duration::from_secs(30)).await;
    assert_eq!(std::fs::read(b.path("later.txt")).unwrap(), b"made later");

    assert!(!b.path("locked.txt").exists(), "an unreadable file is never sent");
    assert_eq!(a.row(&group_id, "locked.txt"), None, "it is skipped, not indexed");
    assert_eq!(b.row(&group_id, "locked.txt"), None, "no tombstone or empty version for it");
    assert_eq!(
        read_bytes_ignoring_mode(&a.path("locked.txt")),
        b"locked on device a",
        "the local bytes are untouched"
    );
    drop(lock);
}
