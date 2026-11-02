//! A linked folder the daemon's account cannot write (a NAS bind mount owned by another uid) is
//! called out in the status the CLI prints: the path, the daemon's uid/gid and the Linux/Docker
//! remedy. A writable folder carries no warning, and the warning goes away once the folder is
//! writable again.
#![cfg(target_os = "linux")]

use crate::support;

use std::os::unix::fs::PermissionsExt;

use support::fake_coordination::FakeCoordination;
use support::topology::stand_up_topology_two_full_replicas_one_on_demand_fast;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unwritable_linked_root_is_warned_about_in_status() {
    // root writes anywhere, so there is nothing to warn about.
    // SAFETY: geteuid cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "unwritable-root-group";
    let (n, _m, _w, handles) =
        stand_up_topology_two_full_replicas_one_on_demand_fast(&fake, group_id).await;
    let root = n.root.path().to_path_buf();

    let healthy =
        support::control_socket_client::query_link_status(n.state.clone(), group_id).await;
    assert_eq!(healthy.root_access_warning, "", "a writable root has no warning");

    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o555)).unwrap();
    let status = support::control_socket_client::query_link_status(n.state.clone(), group_id).await;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();

    let warning = status.root_access_warning;
    // SAFETY: geteuid/getegid cannot fail.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    assert!(warning.contains(&root.display().to_string()), "{warning}");
    assert!(warning.contains(&format!("uid {uid}, gid {gid}")), "{warning}");
    for hint in ["chown", "PUID", "PGID", "user:"] {
        assert!(warning.contains(hint), "{hint} missing: {warning}");
    }

    let healed = support::control_socket_client::query_link_status(n.state.clone(), group_id).await;
    assert_eq!(healed.root_access_warning, "", "the warning clears once the root is writable");

    handles.shutdown();
}
