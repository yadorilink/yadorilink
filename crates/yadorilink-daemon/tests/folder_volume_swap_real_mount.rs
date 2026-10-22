//! The folder's disk is really swapped: a different volume (a disk image) is
//! mounted at the folder's path, over the folder's own volume. Unlike
//! `folder_volume_outage.rs` nothing is overridden in-process: the volume the
//! daemon observes is the one the OS reports. Nothing may be written to the
//! swapped-in volume and no deletion may be authored for files that are only
//! missing because the volume is not the folder's. When the foreign volume is
//! unmounted the link converges on its own.
//!
//! macOS only (`hdiutil`); needs no privileges and no external drive.
#![cfg(target_os = "macos")]

mod support;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::topology::{
    restart_node, stand_up_topology_two_full_replicas_one_on_demand, TopologyNode,
};
use support::{register_with_fake, wait_until_with_context};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_replica_domain::session_state::MaterializationState;

/// A blank APFS disk image mounted at `at` for as long as the guard lives.
struct Mounted {
    at: PathBuf,
    /// The image's whole-disk device (`/dev/diskN`), which stays attached even
    /// when only its filesystem is unmounted.
    device: Option<String>,
    /// Set once detached, so cleanup never touches a device number the OS reused.
    detached: std::cell::Cell<bool>,
    _dir: tempfile::TempDir,
}

impl Mounted {
    fn attach(at: &Path) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("foreign.sparseimage");
        let made = Command::new("hdiutil")
            .args([
                "create", "-size", "20m", "-fs", "APFS", "-volname", "Foreign", "-type", "SPARSE",
            ])
            .arg(&image)
            .output()
            .unwrap();
        assert!(made.status.success(), "hdiutil create: {made:?}");
        let mut this = Mounted {
            at: at.to_path_buf(),
            device: None,
            detached: std::cell::Cell::new(false),
            _dir: dir,
        };
        let attached = Command::new("hdiutil")
            .args(["attach", "-nobrowse", "-mountpoint"])
            .arg(at)
            .arg(&image)
            .output()
            .unwrap();
        assert!(attached.status.success(), "hdiutil attach: {attached:?}");
        let device = String::from_utf8_lossy(&attached.stdout)
            .lines()
            .filter_map(|l| l.split_whitespace().next())
            .find(|d| d.starts_with("/dev/disk"))
            .map(str::to_owned);
        this.device = device;
        this
    }

    /// Unmount the image, retrying while the OS reports the volume busy (a
    /// background indexer or a just-finished scan can hold it for a moment).
    /// Every attempt's exit code and output is kept and printed on failure, and
    /// who still holds the volume is listed, so a busy mount is diagnosable.
    fn detach(&self) {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let mut backoff = Duration::from_millis(250);
        let mut log = String::new();
        let mut attempt = 0;
        while std::time::Instant::now() < deadline {
            attempt += 1;
            let force = attempt > 3;
            let mut cmd = Command::new("hdiutil");
            cmd.arg("detach");
            if force {
                cmd.arg("-force");
            }
            match cmd.arg(&self.at).output() {
                Ok(o) if o.status.success() => {
                    self.detached.set(true);
                    return;
                }
                Ok(o) => log.push_str(&format!(
                    "attempt {attempt} (force={force}): {} stdout={:?} stderr={:?}\n",
                    o.status,
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                )),
                Err(e) => log.push_str(&format!("attempt {attempt}: spawn failed: {e}\n")),
            }
            std::thread::sleep(backoff);
            backoff = (backoff * 2).min(Duration::from_secs(4));
        }
        let holders = Command::new("lsof")
            .arg("+D")
            .arg(&self.at)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        let last = Command::new("diskutil").args(["unmount", "force"]).arg(&self.at).output();
        if matches!(&last, Ok(o) if o.status.success()) {
            if self.eject_device() {
                self.detached.set(true);
            }
            return;
        }
        panic!(
            "could not detach {}\n{log}holders:\n{holders}\ndiskutil unmount force: {last:?}",
            self.at.display()
        );
    }
}

impl Mounted {
    fn eject_device(&self) -> bool {
        match &self.device {
            Some(device) => Command::new("hdiutil")
                .args(["detach", "-force"])
                .arg(device)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false),
            None => false,
        }
    }
}

impl Drop for Mounted {
    fn drop(&mut self) {
        if self.detached.get() {
            return;
        }
        let by_path = Command::new("hdiutil").args(["detach", "-force"]).arg(&self.at).output();
        if !matches!(&by_path, Ok(o) if o.status.success()) {
            self.eject_device();
        }
    }
}

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n != ".fseventsd" && n != ".Spotlight-V100" && n != ".Trashes")
        .collect();
    v.sort();
    v
}

async fn recorded_volume_present(node: &TopologyNode, group_id: &str) {
    wait_until_with_context(
        || {
            matches!(
                node.state
                    .replica_coordinator
                    .link_repository()
                    .capture_volume_identity_for_group(group_id),
                Ok(Some(Some(_)))
            )
        },
        Duration::from_secs(30),
        || "the folder never recorded the volume it is on".to_string(),
    )
    .await;
}

fn deleted_rows(node: &TopologyNode, group_id: &str) -> Vec<String> {
    node.state
        .replica_coordinator
        .file_index_repository()
        .list_files(group_id)
        .unwrap()
        .into_iter()
        .filter(|f| f.deleted)
        .map(|f| f.path)
        .collect()
}

fn has_live_row(node: &TopologyNode, group_id: &str, path: &str) -> bool {
    node.state
        .replica_coordinator
        .file_index_repository()
        .list_files(group_id)
        .map(|files| files.iter().any(|f| f.path == path && !f.deleted))
        .unwrap_or(false)
}

async fn wait_for_file(root: &Path, name: &str, contents: &[u8], why: &str) {
    let path = root.join(name);
    wait_until_with_context(
        || std::fs::read(&path).ok().as_deref() == Some(contents),
        Duration::from_secs(60),
        || format!("{why}: {} never held the expected contents", path.display()),
    )
    .await;
}

async fn follow_volumes(node: &TopologyNode) {
    LinkRuntimeController::new(node.state.clone()).follow_link_volumes().await;
}

/// A different volume is mounted over a running link's folder. A peer's new
/// file is not received into it, the files it lacks are not deleted anywhere,
/// and once it is unmounted the link catches up.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_volume_mounted_over_a_running_folder_receives_nothing_and_deletes_nothing() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "real-volume-swap-running-group";
    let (n, m, w, handles) =
        stand_up_topology_two_full_replicas_one_on_demand(&fake, group_id).await;
    let m_root = m.root.path().to_path_buf();

    std::fs::write(n.root.path().join("shared.bin"), b"before the swap").unwrap();
    wait_for_file(&m_root, "shared.bin", b"before the swap", "M never got N's file").await;
    recorded_volume_present(&m, group_id).await;

    let foreign = Mounted::attach(&m_root);
    let before = names(&m_root);
    assert!(!before.contains(&"shared.bin".to_string()), "fixture: the foreign volume is blank");

    std::fs::write(n.root.path().join("during.bin"), b"written during the swap").unwrap();
    wait_until_with_context(
        || has_live_row(&w, group_id, "during.bin"),
        Duration::from_secs(60),
        || "N's change never reached the other devices".to_string(),
    )
    .await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    follow_volumes(&m).await;
    let during = names(&m_root);
    let tombstones = (deleted_rows(&n, group_id), deleted_rows(&m, group_id));
    let materialized = m
        .state
        .replica_coordinator
        .materialization_state_repository()
        .get_materialization_state(group_id, "during.bin")
        .unwrap();

    foreign.detach();
    assert_eq!(during, before, "the foreign volume must be left exactly as it was");
    assert_ne!(materialized, Some(MaterializationState::Present));
    assert!(tombstones.0.is_empty(), "N: {:?}", tombstones.0);
    assert!(tombstones.1.is_empty(), "M: {:?}", tombstones.1);

    follow_volumes(&m).await;
    wait_for_file(&m_root, "during.bin", b"written during the swap", "M never caught up").await;
    assert_eq!(std::fs::read(m_root.join("shared.bin")).unwrap(), b"before the swap");
    assert_eq!(std::fs::read(n.root.path().join("shared.bin")).unwrap(), b"before the swap");
    assert!(deleted_rows(&n, group_id).is_empty());
    assert!(deleted_rows(&m, group_id).is_empty());

    handles.shutdown();
}

/// The daemon starts while a different volume is mounted at the folder's
/// path (startup repair and the first scans run against it). Nothing is
/// written to it and nothing is deleted; after it is unmounted the link
/// converges.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_daemon_started_over_a_foreign_volume_leaves_it_alone_and_converges_after() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "real-volume-swap-startup-group";
    let (n, m, w, mut handles) =
        stand_up_topology_two_full_replicas_one_on_demand(&fake, group_id).await;
    let m_root = m.root.path().to_path_buf();

    std::fs::write(n.root.path().join("shared.bin"), b"before the swap").unwrap();
    wait_for_file(&m_root, "shared.bin", b"before the swap", "M never got N's file").await;
    recorded_volume_present(&m, group_id).await;

    support::topology::shutdown_substrate(&m).await;
    handles.take_and_shutdown(&m.device_id).await;
    LinkRuntimeController::new(m.state.clone()).stop(&m_root.to_string_lossy()).await;
    let foreign = Mounted::attach(&m_root);
    let before = names(&m_root);

    let m = restart_node(m).await;
    register_with_fake(&fake, &m.state, &m.device_id, &[group_id]).await;
    let m_runtime = support::topology::spawn_orchestrator(fake.addr(), &m);
    support::topology::advertise_substrate_endpoints(&[&n, &m, &w]).await;
    handles.insert(m.device_id.clone(), m_runtime);
    wait_until_with_context(
        || support::topology::fully_connected(&n.state, &m.device_id),
        Duration::from_secs(60),
        || "N never reconnected to the restarted M".to_string(),
    )
    .await;

    std::fs::write(n.root.path().join("during.bin"), b"written during the swap").unwrap();
    tokio::time::sleep(Duration::from_secs(5)).await;
    follow_volumes(&m).await;
    let during = names(&m_root);
    let tombstones = (deleted_rows(&n, group_id), deleted_rows(&m, group_id));
    foreign.detach();

    assert_eq!(during, before, "the foreign volume must be left exactly as it was");
    assert!(tombstones.0.is_empty(), "N: {:?}", tombstones.0);
    assert!(tombstones.1.is_empty(), "M: {:?}", tombstones.1);

    follow_volumes(&m).await;
    wait_for_file(&m_root, "during.bin", b"written during the swap", "M never converged").await;
    assert_eq!(std::fs::read(m_root.join("shared.bin")).unwrap(), b"before the swap");
    assert!(deleted_rows(&n, group_id).is_empty());
    assert!(deleted_rows(&m, group_id).is_empty());

    handles.shutdown();
}
