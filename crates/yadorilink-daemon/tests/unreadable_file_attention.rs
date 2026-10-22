//! A file the daemon cannot read becomes an attention item in `Status` (path and reason), the
//! rest of the folder keeps syncing, the item survives a daemon restart while the file stays
//! unreadable, and it clears by itself, with no restart, once the file reads again. The
//! unreadable file is never indexed, so nothing is deleted or emptied for it.
//!
//! Unix only: the file is made unreadable with mode 000. A user who can read it anyway (root)
//! cannot exercise the scenario, so the tests skip there. Windows and macOS refusal semantics
//! differ and are verified separately.
#![cfg(unix)]

mod support;

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::time::Duration;

use support::control_socket_client;
use support::fake_coordination::FakeCoordination;
use support::register_with_fake;
use support::topology::{link_eager, new_node, restart_node, spawn_orchestrator, TopologyNode};
use support::wait_until;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{StatusRequest, StatusResponse};

const GROUP: &str = "unreadable-attention-group";

fn set_mode(path: &PathBuf, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Restores read permission on drop so the temp dir can be removed.
struct Restore(PathBuf);
impl Drop for Restore {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o644));
    }
}

async fn status(node: &TopologyNode) -> StatusResponse {
    let handle = control_socket_client::start(node.state.clone()).await;
    let Some(RespPayload::Status(status)) =
        control_socket_client::send(&handle, ReqPayload::Status(StatusRequest {})).await.payload
    else {
        panic!("expected a status response");
    };
    status
}

/// `(path, reason)` of the group's unreadable files and the rollup's reason for it, as `Status`
/// reports them now.
async fn unreadable(node: &TopologyNode) -> (Vec<(String, String)>, bool) {
    let status = status(node).await;
    let listed = status
        .links
        .iter()
        .find(|l| l.group_id == GROUP)
        .map(|l| {
            assert_eq!(l.unreadable_file_count as usize, l.unreadable_files.len());
            l.unreadable_files.iter().map(|f| (f.path.clone(), f.reason.clone())).collect()
        })
        .unwrap_or_default();
    let in_rollup = status.attention_reasons.contains(&format!("unreadable_files:{GROUP}"));
    (listed, in_rollup)
}

async fn wait_for_unreadable(node: &TopologyNode, why: &str) {
    for _ in 0..300 {
        if unreadable(node).await.1 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{why}: no unreadable_files attention item appeared");
}

fn row(node: &TopologyNode, rel: &str) -> Option<bool> {
    node.state
        .replica_coordinator
        .file_index_repository()
        .get_file(GROUP, rel)
        .unwrap()
        .map(|r| r.deleted)
}

/// One device in a group it is authorized for, with a locked file and a healthy one in its folder.
/// `None` when the file stays readable despite mode 000 (running as root).
async fn locked_node(
    fake: &FakeCoordination,
) -> Option<(TopologyNode, tokio::runtime::Runtime, PathBuf, Restore)> {
    support::ensure_isolated_config_dir();
    fake.enable_signed_policy();
    let node = new_node("unreadable-attention");
    let locked = node.root.path().join("locked.txt");
    std::fs::write(&locked, b"private bytes").unwrap();
    std::fs::write(node.root.path().join("healthy.txt"), b"healthy").unwrap();
    set_mode(&locked, 0o000);
    let guard = Restore(locked.clone());
    if std::fs::File::open(&locked).is_ok() {
        eprintln!("skipped: the file is readable despite mode 000 (running as root)");
        return None;
    }
    register_with_fake(fake, &node.state, &node.device_id, &[GROUP]).await;
    link_eager(&node, GROUP);
    fake.set_full_replica(&node.device_id, GROUP, true);
    let orchestrator = spawn_orchestrator(fake.addr(), &node);
    Some((node, orchestrator, locked, guard))
}

/// The item names the path and the reason, the healthy file is indexed, and restoring the
/// permission clears the item with the file captured, all without a restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreadable_file_shows_up_and_clears_when_permission_is_restored() {
    let fake = FakeCoordination::start().await;
    let Some((node, orchestrator, locked, _guard)) = locked_node(&fake).await else { return };

    wait_for_unreadable(&node, "mode 000 file").await;
    let (listed, in_rollup) = unreadable(&node).await;
    assert!(in_rollup);
    assert_eq!(listed, [("locked.txt".to_owned(), "permission_denied".to_owned())]);
    wait_until(|| row(&node, "healthy.txt") == Some(false), Duration::from_secs(30)).await;
    assert_eq!(row(&node, "locked.txt"), None, "skipped: no row, tombstone or empty version");

    set_mode(&locked, 0o644);
    wait_until(|| row(&node, "locked.txt") == Some(false), Duration::from_secs(60)).await;
    let (listed, in_rollup) = unreadable(&node).await;
    assert!(listed.is_empty() && !in_rollup, "the item clears once the file reads again");
    assert_eq!(std::fs::read(&locked).unwrap(), b"private bytes");
    orchestrator.shutdown_background();
}

/// A daemon restart while the file stays unreadable brings the same item back (the startup scan
/// finds it again); the file is still not indexed and still untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_item_survives_a_daemon_restart_while_the_file_stays_unreadable() {
    let fake = FakeCoordination::start().await;
    let Some((node, orchestrator, locked, _guard)) = locked_node(&fake).await else { return };
    wait_for_unreadable(&node, "before the restart").await;
    wait_until(|| row(&node, "healthy.txt") == Some(false), Duration::from_secs(30)).await;

    orchestrator.shutdown_background();
    let node = restart_node(node).await;
    let orchestrator = spawn_orchestrator(fake.addr(), &node);
    wait_for_unreadable(&node, "after the restart").await;
    let (listed, _) = unreadable(&node).await;
    assert_eq!(listed, [("locked.txt".to_owned(), "permission_denied".to_owned())]);
    assert_eq!(row(&node, "locked.txt"), None);
    assert_eq!(row(&node, "healthy.txt"), Some(false));
    assert_eq!(std::fs::metadata(&locked).unwrap().permissions().mode() & 0o777, 0);
    orchestrator.shutdown_background();
}
