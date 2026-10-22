//! A receiving device keeps, for the version a peer's change replaces, the
//! metadata that version was authored with: mode, record kind and symlink
//! target belong to the row of the version they describe. A peer's symlink
//! retarget reaches the disk without a conflict copy, and the receiver's
//! history rows equal the author's.

#![cfg(unix)]

mod support;

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::topology::{
    advertise_substrate_endpoints, fully_connected, link_eager, new_node, spawn_orchestrator,
    TopologyHandles,
};
use support::{register_with_fake, wait_until_with_context};
use yadorilink_daemon::change_policy::WriterRole;

const GROUP: &str = "symlink-replacement-group";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    Dir,
    File(String),
    Symlink(String),
}

fn tree(root: &Path) -> BTreeMap<String, Entry> {
    let mut out = BTreeMap::new();
    for name in ["links", "notes"] {
        let dir = root.join(name);
        out.insert(name.to_string(), Entry::Dir);
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            let rel = format!("{name}/{}", entry.file_name().to_string_lossy());
            let meta = std::fs::symlink_metadata(&path).unwrap();
            let node = if meta.file_type().is_symlink() {
                Entry::Symlink(std::fs::read_link(&path).unwrap().to_string_lossy().into_owned())
            } else if meta.is_dir() {
                Entry::Dir
            } else {
                Entry::File(std::fs::read_to_string(&path).unwrap())
            };
            out.insert(rel, node);
        }
    }
    out
}

fn ops_by(state: &yadorilink_daemon::daemon_state::DaemonState, device: &str) -> usize {
    support::native_deltas(state, GROUP)
        .iter()
        .filter(|delta| delta.author.device.as_str() == device)
        .map(|delta| delta.ops.len())
        .sum()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replaced_symlink_reaches_the_peers_disk_without_a_conflict() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let (a, b) = (new_node("symlink-a"), new_node("symlink-b"));
    for node in [&a, &b] {
        register_with_fake(&fake, &node.state, &node.device_id, &[GROUP]).await;
        fake.grant_role(&node.device_id, GROUP, WriterRole::Editor);
        link_eager(node, GROUP);
    }
    let mut handles = TopologyHandles::new();
    handles.insert(a.device_id.clone(), spawn_orchestrator(fake.addr(), &a));
    handles.insert(b.device_id.clone(), spawn_orchestrator(fake.addr(), &b));
    advertise_substrate_endpoints(&[&a, &b]).await;
    wait_until_with_context(
        || fully_connected(&a.state, &b.device_id) && fully_connected(&b.state, &a.device_id),
        Duration::from_secs(60),
        || "the two devices never connected".to_string(),
    )
    .await;

    let root = a.root.path();
    std::fs::create_dir_all(root.join("notes")).unwrap();
    std::fs::create_dir_all(root.join("links")).unwrap();
    std::fs::write(root.join("notes/a.txt"), "a").unwrap();
    std::fs::write(root.join("notes/b.txt"), "b").unwrap();
    std::os::unix::fs::symlink("../notes/a.txt", root.join("links/retargeted")).unwrap();
    std::os::unix::fs::symlink("../notes/a.txt", root.join("links/becomes-file")).unwrap();
    std::fs::write(root.join("links/becomes-link"), "a file for now").unwrap();
    let first = tree(root);
    wait_until_with_context(
        || tree(b.root.path()) == first,
        Duration::from_secs(60),
        || format!("the peer never got the links: {:?}", tree(b.root.path())),
    )
    .await;

    std::fs::remove_file(root.join("links/retargeted")).unwrap();
    std::os::unix::fs::symlink("../notes/b.txt", root.join("links/retargeted")).unwrap();
    std::fs::remove_file(root.join("links/becomes-file")).unwrap();
    std::fs::write(root.join("links/becomes-file"), "now a file").unwrap();
    std::fs::remove_file(root.join("links/becomes-link")).unwrap();
    std::os::unix::fs::symlink("../notes/b.txt", root.join("links/becomes-link")).unwrap();
    let second = tree(root);
    assert_eq!(second["links/retargeted"], Entry::Symlink("../notes/b.txt".into()));

    wait_until_with_context(
        || tree(b.root.path()) == second && tree(root) == second,
        Duration::from_secs(60),
        || format!("the peer has {:?}, the author {:?}", tree(b.root.path()), tree(root)),
    )
    .await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(tree(b.root.path()), second, "no conflict copy, no revert");
    assert_eq!(tree(root), second);
    assert_eq!(ops_by(&b.state, &b.device_id), 0, "the peer authored nothing of its own");
    handles.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_receivers_history_keeps_the_metadata_of_the_version_it_replaced() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let (a, b) = (new_node("history-a"), new_node("history-b"));
    for node in [&a, &b] {
        register_with_fake(&fake, &node.state, &node.device_id, &[GROUP]).await;
        fake.grant_role(&node.device_id, GROUP, WriterRole::Editor);
        link_eager(node, GROUP);
    }
    let mut handles = TopologyHandles::new();
    handles.insert(a.device_id.clone(), spawn_orchestrator(fake.addr(), &a));
    handles.insert(b.device_id.clone(), spawn_orchestrator(fake.addr(), &b));
    advertise_substrate_endpoints(&[&a, &b]).await;
    wait_until_with_context(
        || fully_connected(&a.state, &b.device_id) && fully_connected(&b.state, &a.device_id),
        Duration::from_secs(60),
        || "the two devices never connected".to_string(),
    )
    .await;
    use std::os::unix::fs::PermissionsExt;
    let root = a.root.path();
    std::fs::create_dir_all(root.join("notes")).unwrap();
    std::fs::write(root.join("notes/t.sh"), "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(root.join("notes/t.sh"), std::fs::Permissions::from_mode(0o755))
        .unwrap();
    let rows = |state: &yadorilink_daemon::daemon_state::DaemonState| -> Vec<(i64, i64)> {
        let database = state.replica_coordinator.database();
        let conn = database.pool_for_test().get().unwrap();
        let mut stmt = conn
            .prepare("SELECT version_seq, unix_mode FROM files WHERE group_id = ?1 AND path = 'notes/t.sh' ORDER BY version_seq")
            .unwrap();
        let rows = stmt
            .query_map([GROUP], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        rows
    };
    wait_until_with_context(
        || rows(&b.state).len() == 1,
        Duration::from_secs(60),
        || format!("{:?}", rows(&b.state)),
    )
    .await;
    std::fs::set_permissions(root.join("notes/t.sh"), std::fs::Permissions::from_mode(0o644))
        .unwrap();
    wait_until_with_context(
        || rows(&b.state).len() == 2 && rows(&a.state).len() == 2,
        Duration::from_secs(60),
        || format!("{:?}", rows(&b.state)),
    )
    .await;
    assert_eq!(rows(&a.state), vec![(1, 0o755), (2, 0o644)], "the author's history");
    assert_eq!(rows(&b.state), rows(&a.state), "the receiver's history after a mode-only change");
    // Content and mode change together: the receiver writes the new bytes, so
    // the metadata of the version it replaces must not move.
    // Staged next to the root and renamed in, so the capture sees the new
    // bytes and the new mode as one change.
    let stage = root.parent().unwrap().join("history-stage-t.sh");
    std::fs::write(&stage, "#!/bin/sh\necho new\n").unwrap();
    std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::rename(&stage, root.join("notes/t.sh")).unwrap();
    wait_until_with_context(
        || rows(&b.state).len() == 3 && rows(&a.state).len() == 3,
        Duration::from_secs(60),
        || format!("{:?}", rows(&b.state)),
    )
    .await;
    assert_eq!(rows(&a.state), vec![(1, 0o755), (2, 0o644), (3, 0o700)], "the author's history");
    assert_eq!(
        rows(&b.state),
        rows(&a.state),
        "the receiver's history after a content+mode change"
    );
    handles.shutdown();
}
