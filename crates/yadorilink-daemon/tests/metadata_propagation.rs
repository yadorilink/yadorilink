//! Metadata that is part of a file's identity, crossing between two devices.
//!
//! A `FileVersion`'s hash covers its metadata, not just its bytes, so a change
//! to permissions or extended attributes is a real version change and has to
//! reach a peer's *file* — not merely its index. And the reverse: such a
//! change must not rewrite content that did not change, which on a large file
//! is the difference between a metadata update and a full transfer.
//!
//! These invariants were previously covered only by peer-session
//! integration tests that were retired with the Change protocol.

#![cfg(target_os = "linux")]

mod support;

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::Arc;
use std::time::Duration;

use support::wait_until_with_context;
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::SegmentBlockStore;

const GROUP: &str = "metadata-propagation-group";
const XATTR: &str = "user.yadori_test";

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

/// Whether the filesystem under `path` keeps extended attributes at all.
///
/// tmpfs on some kernels does not, and a test that cannot set an xattr on its
/// own fixture is testing the filesystem rather than the sync. Skipping is
/// honest; asserting would be noise.
fn xattrs_supported(path: &std::path::Path) -> bool {
    set_xattr(path, b"probe").is_ok() && read_xattr(path).as_deref() == Some(b"probe".as_slice())
}

fn set_xattr(path: &std::path::Path, value: &[u8]) -> std::io::Result<()> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let c_name = std::ffi::CString::new(XATTR).unwrap();
    let rc = unsafe {
        libc::setxattr(c_path.as_ptr(), c_name.as_ptr(), value.as_ptr().cast(), value.len(), 0)
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn read_xattr(path: &std::path::Path) -> Option<Vec<u8>> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).ok()?;
    let c_name = std::ffi::CString::new(XATTR).ok()?;
    let mut buffer = vec![0u8; 256];
    let len = unsafe {
        libc::getxattr(c_path.as_ptr(), c_name.as_ptr(), buffer.as_mut_ptr().cast(), buffer.len())
    };
    if len < 0 {
        return None;
    }
    buffer.truncate(len as usize);
    Some(buffer)
}

/// The last observed state of both devices for a propagation failure: sessions, the file and its
/// xattr on both sides, and what each index holds for it. No file contents beyond the test's own
/// fixture bytes.
fn propagation_state(a: &TestDevice, b: &TestDevice) -> String {
    let side = |device: &TestDevice| {
        let path = device.path("tagged.txt");
        format!(
            "{}: {} file={:?} xattr={:?} indexed={:?}",
            device.device_id,
            support::daemon_status_summary(&device.state),
            std::fs::read(&path).ok(),
            read_xattr(&path),
            indexed_rows(device),
        )
    };
    format!("{}\n{}", side(a), side(b))
}

fn indexed_rows(device: &TestDevice) -> Vec<(String, i64, bool)> {
    let database = device.state.replica_coordinator.database();
    let conn = database.pool_for_test().get().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT path, version_seq, deleted FROM files \
             WHERE group_id = ?1 AND state = 'current' ORDER BY path",
        )
        .unwrap();
    let rows = stmt
        .query_map([GROUP], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    rows
}

/// An extended attribute set on one device reaches the peer's real file.
///
/// Asserted on the file, not the index: an xattr recorded in a version and
/// never applied to disk would leave two devices reporting agreement while
/// their files differ.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_xattr_set_on_one_device_reaches_the_peers_real_file() {
    let device_a = setup_device("device-a");
    let device_b = setup_device("device-b");

    std::fs::write(device_a.path("probe"), b"x").unwrap();
    if !xattrs_supported(&device_a.path("probe")) {
        eprintln!("skipping: this filesystem does not support user xattrs");
        return;
    }
    std::fs::remove_file(device_a.path("probe")).unwrap();

    start_watching(&device_a);
    start_watching(&device_b);
    pair(&device_a, &device_b).await;

    std::fs::write(device_a.path("tagged.txt"), b"content").unwrap();
    set_xattr(&device_a.path("tagged.txt"), b"hello").unwrap();

    // Two stages, each named in its failure: the file reaching the peer at all, then its xattr.
    // A busy machine only makes both slower, so a stage ends on lack of progress, not on a
    // short fixed deadline.
    let tagged = device_b.path("tagged.txt");
    support::wait_until_progress(
        || usize::from(!tagged.exists()),
        Duration::from_secs(120),
        Duration::from_secs(240),
        || {
            format!(
                "stage 1, the file never reached the peer:\n{}",
                propagation_state(&device_a, &device_b)
            )
        },
    )
    .await;
    support::wait_until_progress(
        || usize::from(read_xattr(&tagged).as_deref() != Some(b"hello".as_slice())),
        Duration::from_secs(120),
        Duration::from_secs(240),
        || {
            format!(
                "stage 2, the file arrived without its xattr:\n{}",
                propagation_state(&device_a, &device_b)
            )
        },
    )
    .await;
    assert_eq!(std::fs::read(device_b.path("tagged.txt")).unwrap(), b"content");
}

/// Changing only an xattr does not rewrite the content.
///
/// The version hash covers metadata, so this *is* a new version — but the
/// bytes are unchanged, and rewriting them would make a metadata edit cost a
/// full materialization.
///
/// Stated on the inode, not only on the bytes: a full rematerialization writes
/// a temporary file and renames it over the target, so the peer's file would
/// keep its content and change identity. Comparing content alone cannot tell
/// the metadata-only path from a rewrite that happened to produce the same
/// bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_xattr_only_change_does_not_disturb_the_content() {
    let device_a = setup_device("device-a");
    let device_b = setup_device("device-b");

    std::fs::write(device_a.path("probe"), b"x").unwrap();
    if !xattrs_supported(&device_a.path("probe")) {
        eprintln!("skipping: this filesystem does not support user xattrs");
        return;
    }
    std::fs::remove_file(device_a.path("probe")).unwrap();

    start_watching(&device_a);
    start_watching(&device_b);
    pair(&device_a, &device_b).await;

    let content = vec![0x5au8; 128 * 1024];
    std::fs::write(device_a.path("big.bin"), &content).unwrap();
    wait_until_with_context(
        || std::fs::read(device_b.path("big.bin")).map(|b| b == content).unwrap_or(false),
        Duration::from_secs(30),
        || "the content never reached the peer".into(),
    )
    .await;
    let inode_before = std::fs::metadata(device_b.path("big.bin")).unwrap().ino();

    set_xattr(&device_a.path("big.bin"), b"tagged").unwrap();
    wait_until_with_context(
        || read_xattr(&device_b.path("big.bin")).as_deref() == Some(b"tagged".as_slice()),
        Duration::from_secs(30),
        || "the xattr-only change never reached the peer".into(),
    )
    .await;
    assert_eq!(
        std::fs::read(device_b.path("big.bin")).unwrap(),
        content,
        "an xattr-only change must leave the content byte-identical"
    );
    assert_eq!(
        std::fs::metadata(device_b.path("big.bin")).unwrap().ino(),
        inode_before,
        "an xattr-only change rewrote the file instead of updating its metadata"
    );
}

/// Removing a symlink removes the link and never what it points at.
///
/// A tombstone for a symlink names the link. Following it to delete the target
/// would destroy a file the folder does not own — the same class of mistake as
/// walking through a symlinked directory component, on the delete side.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removing_a_symlink_never_removes_its_target() {
    let device_a = setup_device("device-a");
    let device_b = setup_device("device-b");

    start_watching(&device_a);
    start_watching(&device_b);
    pair(&device_a, &device_b).await;

    std::fs::write(device_a.path("target.txt"), b"keep me").unwrap();
    std::os::unix::fs::symlink("target.txt", device_a.path("alias")).unwrap();

    wait_until_with_context(
        || {
            std::fs::symlink_metadata(device_b.path("alias"))
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
        },
        Duration::from_secs(30),
        || "the symlink never reached the peer".into(),
    )
    .await;

    std::fs::remove_file(device_a.path("alias")).unwrap();

    wait_until_with_context(
        || std::fs::symlink_metadata(device_b.path("alias")).is_err(),
        Duration::from_secs(30),
        || "the symlink's removal never reached the peer".into(),
    )
    .await;
    assert!(device_b.path("target.txt").exists(), "removing the link removed what it pointed at");
    assert_eq!(std::fs::read(device_b.path("target.txt")).unwrap(), b"keep me");
}

/// A unix mode change reaches the peer's real file, and only the mode changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mode_only_change_reaches_the_peers_real_file_without_disturbing_content() {
    let device_a = setup_device("device-a");
    let device_b = setup_device("device-b");

    start_watching(&device_a);
    start_watching(&device_b);
    pair(&device_a, &device_b).await;

    std::fs::write(device_a.path("script.sh"), b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(device_a.path("script.sh"), std::fs::Permissions::from_mode(0o644))
        .unwrap();
    wait_until_with_context(
        || device_b.path("script.sh").exists(),
        Duration::from_secs(30),
        || "the file never reached the peer".into(),
    )
    .await;

    std::fs::set_permissions(device_a.path("script.sh"), std::fs::Permissions::from_mode(0o755))
        .unwrap();
    wait_until_with_context(
        || {
            std::fs::metadata(device_b.path("script.sh"))
                .map(|m| m.permissions().mode() & 0o100 != 0)
                .unwrap_or(false)
        },
        Duration::from_secs(30),
        || {
            format!(
                "the exec bit never reached the peer's real file: {:?}",
                std::fs::metadata(device_b.path("script.sh"))
                    .map(|m| m.permissions().mode() & 0o777)
            )
        },
    )
    .await;
    assert_eq!(std::fs::read(device_b.path("script.sh")).unwrap(), b"#!/bin/sh\n");
}
