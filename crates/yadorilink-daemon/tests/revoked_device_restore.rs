//! A device that was revoked at the coordination plane while it was down, then brought back from
//! an older backup, must not sync, serve blocks or write into any folder.
//!
//! Real daemon stacks (`DaemonState`, link runtimes, `peer_orchestrator`) over the in-process
//! coordination plane, whose revocation is what the real plane does: the device stops appearing
//! in every peer's netmap. The revoked device keeps everything an old image holds: its index
//! database, its signing key, and the last-known-good authorization of its peers. Peers that are
//! still members must refuse it on their own account, whether the plane is down when the image
//! comes back (the device runs on its stale authorization) or reachable (its netmap is empty).
//!
//! Two restores are driven: onto the machine the backup came from (the installation witness
//! refuses the older database, so the device cannot author) and onto another machine (nothing
//! refuses it, so the device authors with its old identity and its peers' refusal is the only
//! barrier).

mod support;

use std::path::Path;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::topology::{
    advertise_substrate_endpoints, link_eager, new_node, shutdown_substrate, spawn_orchestrator,
    start_stopped_node, start_stopped_node_refusing_links, stop_node, TopologyHandles,
    TopologyNode,
};
use support::{register_with_fake, wait_until_with_context};
use yadorilink_daemon::daemon_state::AuthorizationProvenance;

const GROUP: &str = "revoked-restore-group";

/// How long a refusal is watched for. A session or a file that was going to arrive would have done
/// so well inside this on a loopback mesh (the positive controls below converge in a few seconds).
const QUIET_PERIOD: Duration = Duration::from_secs(10);
const CONVERGE: Duration = Duration::from_secs(90);

static TEST_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// One witness directory for the whole test process, kept outside every node's data, as the
/// installation witness is kept outside a backup (see `database_restored.rs`).
fn use_witness_dir() {
    static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    let dir = DIR.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("YADORILINK_WITNESS_DIR", dir.path());
        dir
    });
    assert_eq!(std::env::var_os("YADORILINK_WITNESS_DIR").as_deref(), Some(dir.path().as_os_str()));
}

fn read(root: &Path, name: &str) -> Option<Vec<u8>> {
    std::fs::read(root.join(name)).ok()
}

async fn converged(what: &str, roots: &[&Path], name: &str, content: &[u8]) {
    wait_until_with_context(
        || roots.iter().all(|root| read(root, name).as_deref() == Some(content)),
        CONVERGE,
        || format!("{what}: {name} never reached every device"),
    )
    .await;
}

struct Mesh {
    fake: FakeCoordination,
    /// Stays a member throughout.
    member: TopologyNode,
    /// The second member, the control that sync keeps working for devices that are not revoked.
    control: TopologyNode,
    handles: TopologyHandles,
}

async fn mesh_with(revoked_id: &str) -> (Mesh, TopologyNode) {
    support::ensure_isolated_config_dir();
    use_witness_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let member = new_node("restore-member");
    let control = new_node("restore-control");
    let revoked = new_node(revoked_id);
    for node in [&member, &control, &revoked] {
        register_with_fake(&fake, &node.state, &node.device_id, &[GROUP]).await;
        link_eager(node, GROUP);
        fake.set_full_replica(&node.device_id, GROUP, true);
    }
    let mut handles = TopologyHandles::new();
    for node in [&member, &control, &revoked] {
        handles.insert(node.device_id.clone(), spawn_orchestrator(fake.addr(), node));
    }
    advertise_substrate_endpoints(&[&member, &control, &revoked]).await;
    wait_until_with_context(
        || {
            member.state.peers.has_session(&revoked.device_id)
                && member.state.peers.has_session(&control.device_id)
                && control.state.peers.has_session(&revoked.device_id)
        },
        Duration::from_secs(60),
        || "the three devices never formed a mesh".to_string(),
    )
    .await;
    (Mesh { fake, member, control, handles }, revoked)
}

/// Stops a device the way a power-off does, and returns it ready to be copied.
async fn power_off(mesh: &mut Mesh, node: TopologyNode) -> support::topology::StoppedNode {
    shutdown_substrate(&node).await;
    mesh.handles.take_and_shutdown(&node.device_id).await;
    stop_node(node).await
}

/// The whole sequence: back up, move on, revoke while down, restore the old image, reconnect
/// (offline first, then with the plane back), and check at every step that nothing crosses.
async fn revoked_device_restored(other_machine: bool) {
    let (mut mesh, revoked) =
        mesh_with(if other_machine { "restore-revoked-new-machine" } else { "restore-revoked" })
            .await;
    let revoked_id = revoked.device_id.clone();

    // Before the backup: one file everybody holds.
    std::fs::write(mesh.member.root.path().join("before-backup.txt"), b"one").unwrap();
    let roots = [mesh.member.root.path(), mesh.control.root.path(), revoked.root.path()];
    converged("before the backup", &roots, "before-backup.txt", b"one").await;

    // The backup is taken while the device is off.
    let stopped = power_off(&mut mesh, revoked).await;
    let image = stopped.database_image();

    // The device runs on, so its database moves past the backup.
    let revoked = start_stopped_node(stopped).await;
    mesh.handles.insert(revoked_id.clone(), spawn_orchestrator(mesh.fake.addr(), &revoked));
    advertise_substrate_endpoints(&[&mesh.member, &mesh.control, &revoked]).await;
    std::fs::write(revoked.root.path().join("after-backup.txt"), b"two").unwrap();
    let roots = [mesh.member.root.path(), mesh.control.root.path(), revoked.root.path()];
    converged("after the backup", &roots, "after-backup.txt", b"two").await;
    let mut stopped = power_off(&mut mesh, revoked).await;

    // Revoked at the plane while the device is down. The members go on without it.
    mesh.fake.remove_device(&revoked_id);
    std::fs::write(mesh.member.root.path().join("after-revoke.txt"), b"three").unwrap();
    let members = [mesh.member.root.path(), mesh.control.root.path()];
    converged("after the revocation (control)", &members, "after-revoke.txt", b"three").await;
    wait_until_with_context(
        || {
            !mesh.member.state.peers.has_session(&revoked_id)
                && !mesh.control.state.peers.has_session(&revoked_id)
        },
        Duration::from_secs(30),
        || "the members still hold a session to the revoked device".to_string(),
    )
    .await;

    // The old image comes back, the plane is unreachable when the device starts.
    stopped.restore_database_image(image.path(), other_machine);
    mesh.fake.shutdown();
    let revoked = if other_machine {
        start_stopped_node(stopped).await
    } else {
        // Restored in place, the daemon refuses to run the folder's link at all.
        start_stopped_node_refusing_links(stopped).await
    };
    mesh.handles.insert(revoked_id.clone(), spawn_orchestrator(mesh.fake.addr(), &revoked));
    advertise_substrate_endpoints(&[&mesh.member, &mesh.control, &revoked]).await;

    // Control: the restore really put an older, still-authorizing state back. Without it the
    // refusals below could be the side effect of a device that knows nobody.
    assert!(
        revoked.state.authority.authorization_provenance().is_offline_last_known_good(),
        "the restored device must be running on its stale authorization"
    );
    assert!(
        !revoked.state.authority.authorized_groups_for_peer(&mesh.member.device_id).is_empty(),
        "the stale authorization must still name the member, or the refusal proves nothing"
    );
    assert_eq!(
        read(revoked.root.path(), "after-revoke.txt"),
        None,
        "the revocation postdates the backup: the restored device cannot hold this file"
    );
    assert_eq!(
        revoked.state.local_author().is_some(),
        other_machine,
        "restored in place the device is refused authorship; on another machine it authors"
    );

    // An edit made on the restored device must not leave it, whether or not it can author.
    std::fs::write(revoked.root.path().join("stale-edit.txt"), b"stale").unwrap();
    assert_nothing_crosses(&mesh, &revoked, &revoked_id, "plane unreachable").await;

    // The plane comes back: the device reconnects and receives an empty netmap.
    mesh.fake.restart();
    wait_until_with_context(
        || {
            revoked.state.authority.authorization_provenance()
                == AuthorizationProvenance::LiveNetmap
        },
        Duration::from_secs(60),
        || "the restored device never applied a live netmap".to_string(),
    )
    .await;
    assert!(
        revoked.state.authority.authorized_groups_for_peer(&mesh.member.device_id).is_empty(),
        "once the plane answers, the revoked device authorizes nobody"
    );
    assert_nothing_crosses(&mesh, &revoked, &revoked_id, "plane reachable").await;

    // The members are unharmed: they still sync with each other.
    std::fs::write(mesh.control.root.path().join("members-only.txt"), b"four").unwrap();
    converged("members after the restore", &members, "members-only.txt", b"four").await;
    assert_eq!(read(revoked.root.path(), "members-only.txt"), None);

    mesh.handles.shutdown();
}

async fn assert_nothing_crosses(
    mesh: &Mesh,
    revoked: &TopologyNode,
    revoked_id: &str,
    phase: &str,
) {
    tokio::time::sleep(QUIET_PERIOD).await;
    for member in [&mesh.member, &mesh.control] {
        assert!(
            !member.state.peers.has_session(revoked_id),
            "{phase}: {} holds a session to the revoked device",
            member.device_id
        );
        assert_eq!(
            read(member.root.path(), "stale-edit.txt"),
            None,
            "{phase}: the revoked device's edit reached {}",
            member.device_id
        );
    }
    for member in [&mesh.member, &mesh.control] {
        assert!(
            !revoked.state.peers.has_session(&member.device_id),
            "{phase}: the revoked device holds a session to {}",
            member.device_id
        );
    }
    assert_eq!(
        read(revoked.root.path(), "after-revoke.txt"),
        None,
        "{phase}: a file written after the revocation reached the revoked device"
    );
    assert_eq!(
        read(revoked.root.path(), "stale-edit.txt").as_deref(),
        Some(b"stale" as &[u8]),
        "{phase}: the revoked device's own file is left alone"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn revoked_device_restored_in_place_never_syncs_or_writes() {
    let _guard = TEST_GUARD.lock().await;
    revoked_device_restored(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn revoked_device_restored_on_another_machine_never_syncs_or_writes() {
    let _guard = TEST_GUARD.lock().await;
    revoked_device_restored(true).await;
}
