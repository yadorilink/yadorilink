//! A full replica whose folder's disk goes away (unmounted, failed, replaced)
//! must not write into whatever is left at the folder's path, must not record
//! anything there as materialized, and must not author a deletion for files
//! that are only missing because the disk is gone. Once the disk is back, the
//! link resumes on its own and converges with what the other devices changed
//! meanwhile, still without deleting anything.
//!
//! The disk is simulated in-process: the folder's recorded volume is
//! overridden through `device_boundary::seam`, and an unmount is a rename of
//! the folder away with an empty directory left at its path (what an unmounted
//! volume leaves behind as its mountpoint).

mod support;

use std::path::{Path, PathBuf};
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::topology::{
    restart_node, stand_up_topology_two_full_replicas_one_on_demand, TopologyNode,
};
use support::{register_with_fake, wait_until_with_context};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_filesystem_sync::device_boundary::seam;
use yadorilink_replica_domain::session_state::MaterializationState;

/// Overrides the volume `root` reports, under both the spelling the link was
/// created with and its canonical form (the checks see either).
fn set_volume(root: &Path, identity: &str) {
    seam::set_root_identity(root, Some(identity));
    if let Ok(canonical) = root.canonicalize() {
        seam::set_root_identity(&canonical, Some(identity));
    }
}

fn clear_volume(root: &Path) {
    seam::clear_root_identity(root);
    if let Ok(canonical) = root.canonicalize() {
        seam::clear_root_identity(&canonical);
    }
}

/// What the folder's recorded volume is, once its first full scan adopted it.
async fn recorded_volume(node: &TopologyNode, group_id: &str) -> String {
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
    node.state
        .replica_coordinator
        .link_repository()
        .capture_volume_identity_for_group(group_id)
        .unwrap()
        .unwrap()
        .unwrap()
}

fn has_live_row(node: &TopologyNode, group_id: &str, path: &str) -> bool {
    node.state
        .replica_coordinator
        .file_index_repository()
        .list_files(group_id)
        .map(|files| files.iter().any(|f| f.path == path && !f.deleted))
        .unwrap_or(false)
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

fn materialization(
    node: &TopologyNode,
    group_id: &str,
    path: &str,
) -> Option<MaterializationState> {
    node.state
        .replica_coordinator
        .materialization_state_repository()
        .get_materialization_state(group_id, path)
        .unwrap()
}

/// What the link-volume job does on its tick.
async fn follow_volumes(node: &TopologyNode) {
    LinkRuntimeController::new(node.state.clone()).follow_link_volumes().await;
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

/// The disk under a running link is swapped for another one that carries a
/// copy of the folder (its marker included). Nothing the other devices write
/// meanwhile lands on it; once the folder's own disk is back the link picks up
/// what it missed.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_folder_on_another_volume_receives_nothing_and_catches_up_when_its_volume_returns() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "folder-volume-replaced-group";
    let (n, m, w, handles) =
        stand_up_topology_two_full_replicas_one_on_demand(&fake, group_id).await;
    let m_root = m.root.path().to_path_buf();

    std::fs::write(n.root.path().join("shared.bin"), b"before the outage").unwrap();
    wait_for_file(&m_root, "shared.bin", b"before the outage", "M never got N's file").await;
    recorded_volume(&m, group_id).await;

    // Before the link-volume job notices: every write re-checks the volume.
    set_volume(&m_root, "uuid:another-disk");

    std::fs::write(n.root.path().join("during.bin"), b"written during the outage").unwrap();
    // The change is out (the third device has it) and M has had time to act.
    wait_until_with_context(
        || has_live_row(&w, group_id, "during.bin"),
        Duration::from_secs(60),
        || "N's change never reached the other devices".to_string(),
    )
    .await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(
        !m_root.join("during.bin").exists(),
        "a folder off its recorded volume must not be written into"
    );
    assert_ne!(
        materialization(&m, group_id, "during.bin"),
        Some(MaterializationState::Present),
        "nothing may be recorded as materialized in a folder off its volume"
    );

    clear_volume(&m_root);
    follow_volumes(&m).await;
    wait_for_file(&m_root, "during.bin", b"written during the outage", "M never caught up").await;
    assert_eq!(std::fs::read(m_root.join("shared.bin")).unwrap(), b"before the outage");
    assert_eq!(std::fs::read(n.root.path().join("shared.bin")).unwrap(), b"before the outage");
    assert!(deleted_rows(&n, group_id).is_empty(), "N: {:?}", deleted_rows(&n, group_id));
    assert!(deleted_rows(&m, group_id).is_empty(), "M: {:?}", deleted_rows(&m, group_id));

    handles.shutdown();
}

/// The daemon starts while the folder's disk is unmounted, so the folder's
/// path is an empty directory on the volume underneath. Nothing is written
/// there (not even the folder's lock file), nothing is recorded as present
/// and nothing is deleted. When the disk is mounted again the link starts by
/// itself and converges.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_daemon_started_during_an_unmount_leaves_the_mountpoint_alone_and_converges_on_remount() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "folder-volume-unmounted-group";
    let (n, m, w, mut handles) =
        stand_up_topology_two_full_replicas_one_on_demand(&fake, group_id).await;
    let m_root = m.root.path().to_path_buf();

    std::fs::write(n.root.path().join("shared.bin"), b"before the outage").unwrap();
    wait_for_file(&m_root, "shared.bin", b"before the outage", "M never got N's file").await;
    recorded_volume(&m, group_id).await;

    // M goes down; its disk is unmounted, leaving the empty mountpoint on the
    // volume underneath.
    support::topology::shutdown_substrate(&m).await;
    handles.take_and_shutdown(&m.device_id).await;
    // The link stops before its folder moves: Windows refuses to rename a
    // directory that a watcher holds open, and a daemon that is down has no
    // watcher on it either.
    LinkRuntimeController::new(m.state.clone()).stop(&m_root.to_string_lossy()).await;
    let away: PathBuf = m_root.with_extension("unmounted");
    std::fs::rename(&m_root, &away).unwrap();
    std::fs::create_dir(&m_root).unwrap();
    set_volume(&m_root, "uuid:the-volume-underneath");

    // M comes back up with the disk still missing.
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

    std::fs::write(n.root.path().join("during.bin"), b"written during the outage").unwrap();
    tokio::time::sleep(Duration::from_secs(5)).await;
    follow_volumes(&m).await;
    let left_behind: Vec<_> = std::fs::read_dir(&m_root)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        left_behind.is_empty(),
        "nothing may be written onto the volume underneath an unmounted folder: {left_behind:?}"
    );
    assert_ne!(
        materialization(&m, group_id, "during.bin"),
        Some(MaterializationState::Present),
        "nothing may be recorded as materialized on the empty mountpoint"
    );
    assert!(deleted_rows(&n, group_id).is_empty(), "N: {:?}", deleted_rows(&n, group_id));
    assert!(deleted_rows(&m, group_id).is_empty(), "M: {:?}", deleted_rows(&m, group_id));

    // The disk is mounted again.
    std::fs::remove_dir(&m_root).unwrap();
    std::fs::rename(&away, &m_root).unwrap();
    clear_volume(&m_root);
    follow_volumes(&m).await;

    wait_for_file(&m_root, "during.bin", b"written during the outage", "M never converged").await;
    std::fs::write(n.root.path().join("after.bin"), b"after the outage").unwrap();
    wait_for_file(&m_root, "after.bin", b"after the outage", "M stopped syncing").await;
    assert_eq!(std::fs::read(m_root.join("shared.bin")).unwrap(), b"before the outage");
    assert_eq!(std::fs::read(n.root.path().join("shared.bin")).unwrap(), b"before the outage");
    assert!(deleted_rows(&n, group_id).is_empty(), "N: {:?}", deleted_rows(&n, group_id));
    assert!(deleted_rows(&m, group_id).is_empty(), "M: {:?}", deleted_rows(&m, group_id));

    handles.shutdown();
}

/// What the folder's own device reports about it.
async fn link_status(
    node: &TopologyNode,
    group_id: &str,
) -> yadorilink_ipc_proto::daemonctl::LinkStatus {
    support::control_socket_client::query_link_status(node.state.clone(), group_id).await
}

/// The folder's path as its link records it (what the user names).
fn link_path(node: &TopologyNode, group_id: &str) -> String {
    let paths = node
        .state
        .replica_coordinator
        .link_repository()
        .live_link_paths_for_group(group_id)
        .unwrap();
    assert_eq!(paths.len(), 1, "{paths:?}");
    paths.into_iter().next().unwrap()
}

/// Records `identity` as the folder's volume and makes its root report it, as
/// a folder linked on a disk without a stable identity does.
fn record_volume(node: &TopologyNode, group_id: &str, identity: &str) {
    node.state
        .replica_coordinator
        .link_repository()
        .set_capture_volume_identity_for_group(group_id, identity)
        .unwrap();
    set_volume(node.root.path(), identity);
}

/// The folder is on a disk whose filesystem has no stable identity (FAT,
/// exFAT), confirmed for one mount. After a remount a disk carrying a copy of
/// the folder (marker included, one file missing) is at its path: nothing
/// tells it from the folder's own disk, so nothing is written to it, nothing
/// is deleted, no device counts it as a copy, and the folder asks the user.
/// Once the user re-adopts the disk, the folder syncs with it as it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_remounted_disk_without_a_stable_identity_waits_for_the_user_to_readopt_it() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "folder-volume-unknown-group";
    let (n, m, w, handles) =
        stand_up_topology_two_full_replicas_one_on_demand(&fake, group_id).await;
    let m_root = m.root.path().to_path_buf();

    std::fs::write(n.root.path().join("shared.bin"), b"before the remount").unwrap();
    std::fs::write(n.root.path().join("kept.bin"), b"kept").unwrap();
    wait_for_file(&m_root, "shared.bin", b"before the remount", "M never got N's file").await;
    wait_for_file(&m_root, "kept.bin", b"kept", "M never got N's file").await;
    recorded_volume(&m, group_id).await;
    record_volume(&m, group_id, "unknown:boot-1:41");
    follow_volumes(&m).await;
    assert!(!link_status(&m, group_id).await.capture_volume_unconfirmed);

    // Remounted: another mount of a disk with no identity, holding a copy
    // that lacks one file.
    set_volume(&m_root, "unknown:boot-1:42");
    follow_volumes(&m).await;
    std::fs::remove_file(m_root.join("shared.bin")).unwrap();
    std::fs::write(n.root.path().join("during.bin"), b"written after the remount").unwrap();
    wait_until_with_context(
        || has_live_row(&w, group_id, "during.bin"),
        Duration::from_secs(60),
        || "N's change never reached the other devices".to_string(),
    )
    .await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    follow_volumes(&m).await;

    assert!(!m_root.join("during.bin").exists(), "an unconfirmed disk must not be written into");
    assert_ne!(materialization(&m, group_id, "during.bin"), Some(MaterializationState::Present));
    assert!(deleted_rows(&n, group_id).is_empty(), "N: {:?}", deleted_rows(&n, group_id));
    assert!(deleted_rows(&m, group_id).is_empty(), "M: {:?}", deleted_rows(&m, group_id));
    assert!(
        m.state.replica_coordinator.group_folder_off_capture_volume(group_id),
        "an unconfirmed disk must not count as a copy"
    );
    let status = link_status(&m, group_id).await;
    assert!(status.capture_volume_unconfirmed, "the folder must ask the user");
    assert!(!status.capture_volume_changed, "the disk is not simply away");

    // The user confirms the disk: it syncs as it is, the missing file being
    // a deletion now.
    LinkRuntimeController::new(m.state.clone())
        .readopt_volume(&link_path(&m, group_id))
        .await
        .expect("re-adopting a disk that can be confirmed");
    assert_eq!(recorded_volume(&m, group_id).await, "unknown:boot-1:42");
    assert!(!link_status(&m, group_id).await.capture_volume_unconfirmed);
    wait_for_file(&m_root, "during.bin", b"written after the remount", "M never caught up").await;
    wait_until_with_context(
        || !n.root.path().join("shared.bin").exists(),
        Duration::from_secs(60),
        || "the file missing from the confirmed disk was never deleted".to_string(),
    )
    .await;
    assert_eq!(std::fs::read(n.root.path().join("kept.bin")).unwrap(), b"kept");

    clear_volume(&m_root);
    handles.shutdown();
}

/// A disk whose filesystem has no stable identity, on a system that cannot
/// name the mount either: it matches nothing, not even itself, so the folder
/// never syncs there, and re-adopting it is refused rather than recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_disk_that_can_never_be_confirmed_is_never_accepted() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "folder-volume-unconfirmable-group";
    let (n, m, w, handles) =
        stand_up_topology_two_full_replicas_one_on_demand(&fake, group_id).await;
    let m_root = m.root.path().to_path_buf();

    std::fs::write(n.root.path().join("shared.bin"), b"before").unwrap();
    wait_for_file(&m_root, "shared.bin", b"before", "M never got N's file").await;
    recorded_volume(&m, group_id).await;
    record_volume(&m, group_id, "unknown");
    follow_volumes(&m).await;

    std::fs::write(n.root.path().join("during.bin"), b"after").unwrap();
    wait_until_with_context(
        || has_live_row(&w, group_id, "during.bin"),
        Duration::from_secs(60),
        || "N's change never reached the other devices".to_string(),
    )
    .await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(!m_root.join("during.bin").exists(), "an unconfirmable disk must not be written into");
    assert!(link_status(&m, group_id).await.capture_volume_unconfirmed);

    let refused =
        LinkRuntimeController::new(m.state.clone()).readopt_volume(&link_path(&m, group_id)).await;
    assert!(refused.is_err(), "{refused:?}");
    assert_eq!(recorded_volume(&m, group_id).await, "unknown");

    clear_volume(&m_root);
    handles.shutdown();
}
