//! Full-stack revocation tests: the in-process fake coordination plane plus
//! real `peer_orchestrator::run` daemons proving the revocation flow end to
//! end: coordination-plane netmap push → daemon netmap diff →
//! `PeerSyncSession::revoke_group` wiring → sync-engine re-validation. They
//! also guard the "coordination plane availability independence" invariant for
//! already-authorized, already-connected peers.
//!
//! Uses the full daemon stack (real `DaemonState` + `LinkRuntimeController::
//! start` + `peer_orchestrator::run`, discovering peers from the
//! fake's netmap) rather than the lighter-weight `connect_two_daemons` pairing,
//! since what's under test here is the daemon-level coordination wiring itself.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::{daemon_status_summary, register_with_fake, wait_until, wait_until_with_context};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::peer_orchestrator;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;

static TEST_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct TestDaemon {
    state: Arc<DaemonState>,
}

fn new_test_daemon(device_id: &str) -> TestDaemon {
    let store_dir = tempfile::tempdir().unwrap();
    // Leaked deliberately: the block store must outlive the test; the process
    // tears the temp dir down on exit.
    let store = Arc::new(SegmentBlockStore::new(Box::leak(Box::new(store_dir)).path()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new(device_id.to_string(), sync_state, store);
    TestDaemon { state }
}

fn link(state: &Arc<DaemonState>, root: &std::path::Path, group_id: &str) {
    let local_path = root.to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, group_id).unwrap();
    LinkRuntimeController::new(state.clone()).start(local_path, group_id.to_string()).unwrap();
}

fn spawn_orchestrator(coordination_addr: String, device_id: String, state: Arc<DaemonState>) {
    let config = peer_orchestrator::OrchestratorConfig {
        coordination_addr,
        auth: yadorilink_fapi_client::test_support::offline_auth(),
        device_id,
    };
    tokio::spawn(async move {
        let _ = peer_orchestrator::run(config, state).await;
    });
}

/// Two devices sharing *two* groups (`group-revoked`, so the tunnel is left up
/// once one edge is revoked, and `group-control`, so there's something still-
/// authorized to prove kept working) — access is revoked against
/// `group-revoked` for device A while a real sync session is up. Proves the
/// push lands and is diffed into `removed_group_edges`, the daemon calls
/// `session.revoke_group` so `shares_group` flips, a request for that group
/// issued after the flip is refused, and the tunnel plus the other shared
/// group keep working throughout — a narrow, not a whole-device, teardown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn share_revoke_mid_session_stops_serving_the_revoked_group_but_not_others() {
    let _test_guard = TEST_GUARD.lock().await;
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let device_a_id = "device-a-share-revoke";
    let device_b_id = "device-b-share-revoke";
    let group_revoked = "group-revoked";
    let group_control = "group-control";

    let daemon_a = new_test_daemon(device_a_id);
    let daemon_b = new_test_daemon(device_b_id);

    let root_a_revoked = tempfile::tempdir().unwrap();
    let root_a_control = tempfile::tempdir().unwrap();
    let root_b_revoked = tempfile::tempdir().unwrap();
    let root_b_control = tempfile::tempdir().unwrap();

    register_with_fake(&fake, &daemon_a.state, device_a_id, &[group_revoked, group_control]).await;
    register_with_fake(&fake, &daemon_b.state, device_b_id, &[group_revoked, group_control]).await;

    link(&daemon_a.state, root_a_revoked.path(), group_revoked);
    link(&daemon_a.state, root_a_control.path(), group_control);
    link(&daemon_b.state, root_b_revoked.path(), group_revoked);
    link(&daemon_b.state, root_b_control.path(), group_control);

    spawn_orchestrator(fake.addr(), device_a_id.to_string(), daemon_a.state.clone());
    spawn_orchestrator(fake.addr(), device_b_id.to_string(), daemon_b.state.clone());

    // The peer-session handshake waited on below does NOT imply the
    // reconciliation substrate is reachable -- different socket, different
    // ALPN, and these fixtures carry only the former. Without this, the
    // control group never converges either, so the test cannot tell "revoked
    // group stopped being served" from "nothing was ever served".
    support::advertise_substrate_between(&[&daemon_a.state, &daemon_b.state]).await;

    wait_until(|| daemon_a.state.peers.session(device_b_id).is_some(), Duration::from_secs(40))
        .await;

    // Sanity: both groups sync normally before any revocation.
    std::fs::write(root_b_revoked.path().join("before-revoke.txt"), b"synced pre-revoke").unwrap();
    wait_until(
        || root_a_revoked.path().join("before-revoke.txt").exists(),
        Duration::from_secs(40),
    )
    .await;
    std::fs::write(root_b_control.path().join("before-revoke.txt"), b"control pre-revoke").unwrap();
    wait_until(
        || root_a_control.path().join("before-revoke.txt").exists(),
        Duration::from_secs(40),
    )
    .await;

    // B's live session-to-A serves A's requests; its `shares_group` must flip.
    let session_b_to_a =
        daemon_b.state.peers.session(device_a_id).expect("B must have a live session to A by now");
    assert!(session_b_to_a.shares_group(group_revoked));
    assert!(session_b_to_a.shares_group(group_control));

    fake.revoke(device_a_id, group_revoked);

    // The push → netmap diff → `session.revoke_group` wiring flips
    // `shares_group` for the revoked group within the propagation bound.
    wait_until(|| !session_b_to_a.shares_group(group_revoked), Duration::from_secs(10)).await;
    assert!(
        session_b_to_a.shares_group(group_control),
        "revoking one group edge must not affect the other shared group's authorization"
    );

    // Mid-session re-validation: a request for the now-revoked group, issued
    // after propagation is confirmed, must be refused rather than served.
    std::fs::write(root_b_revoked.path().join("after-revoke.txt"), b"must not reach A").unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !root_a_revoked.path().join("after-revoke.txt").exists(),
        "a file written to the revoked group after propagation was confirmed must never reach \
         the now-unauthorized device"
    );

    // The still-authorized control group keeps syncing, and the tunnel stays up
    // on both sides — no whole-device teardown was triggered.
    std::fs::write(root_b_control.path().join("after-revoke.txt"), b"control keeps working")
        .unwrap();
    wait_until(|| root_a_control.path().join("after-revoke.txt").exists(), Duration::from_secs(40))
        .await;
    assert!(
        daemon_a
            .state
            .peer_connectivity
            .reachability(device_b_id)
            .map(|r| r.is_connected())
            .unwrap_or(false),
        "the tunnel must stay up for a group-edge-only revocation"
    );
    assert!(
        daemon_b
            .state
            .peer_connectivity
            .reachability(device_a_id)
            .map(|r| r.is_connected())
            .unwrap_or(false),
        "the tunnel must stay up for a group-edge-only revocation"
    );
}

/// `device remove` while the affected peer (device A) has never once subscribed
/// to the coordination plane: device B is removed entirely while A's daemon has
/// not started yet, so when A finally subscribes its very first netmap already
/// reflects B's removal and A never establishes a session to B. Device C is an
/// unrevoked control on the same group, proving A's connection logic works and
/// B's absence is specifically the removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn device_remove_while_peer_offline_is_reflected_on_its_next_subscribe() {
    let _test_guard = TEST_GUARD.lock().await;
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let device_a_id = "device-a-offline";
    let device_b_id = "device-b-removed";
    let device_c_id = "device-c-control";
    let group_id = "shared";

    let daemon_a = new_test_daemon(device_a_id);
    let daemon_c = new_test_daemon(device_c_id);
    let root_a = tempfile::tempdir().unwrap();
    let root_c = tempfile::tempdir().unwrap();

    register_with_fake(&fake, &daemon_a.state, device_a_id, &[group_id]).await;
    register_with_fake(&fake, &daemon_c.state, device_c_id, &[group_id]).await;
    // B is a member, then removed entirely before A's daemon ever subscribes.
    fake.register_device(device_b_id, [9u8; 32], "127.0.0.1:1".to_string(), &[group_id]);
    fake.remove_device(device_b_id);

    link(&daemon_a.state, root_a.path(), group_id);
    link(&daemon_c.state, root_c.path(), group_id);

    spawn_orchestrator(fake.addr(), device_a_id.to_string(), daemon_a.state.clone());
    spawn_orchestrator(fake.addr(), device_c_id.to_string(), daemon_c.state.clone());

    // A `PeerSyncSession` only ever forms over the iroh reconciliation
    // substrate now (`peer_connectivity_runtime/peer_sessions.rs`), which
    // resolves a peer's address from the substrate's own address
    // directory -- production carries that over the coordination plane's
    // netmap fan-out; this bare `spawn_orchestrator` fixture does not, so
    // without this call A and C never learn where each other's substrate
    // answers and the positive control below never connects at all. See
    // `share_revoke_mid_session...`'s own identical call earlier in this
    // file.
    support::advertise_substrate_between(&[&daemon_a.state, &daemon_c.state]).await;

    // Positive control: A connects normally to the still-authorized peer C.
    wait_until_with_context(
        || daemon_a.state.peers.has_session(device_c_id),
        Duration::from_secs(40),
        || {
            format!(
                "A never connected to still-authorized C\n  a: {}\n  c: {}",
                daemon_status_summary(&daemon_a.state),
                daemon_status_summary(&daemon_c.state),
            )
        },
    )
    .await;

    // A must never establish a session to the removed device.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !daemon_a.state.peers.has_session(device_b_id),
        "an offline device reconnecting after its peer was removed must never establish a \
         session to the removed device"
    );
    assert!(
        daemon_a.state.peer_connectivity.reachability(device_b_id).is_none(),
        "a removed device must never even appear as connecting/connected in peer status"
    );
}

// A coordination-plane-outage sync test used to live here too, testing the
// broader "Coordination Plane Availability Independence" invariant this
// file's revocation scenarios don't actually exercise. That invariant is
// not achievable for NEW content under checkpoint admission (checkpoint
// issuance requires a live coordination-plane round trip); the narrower, correct property
// ("Published Data Plane Survives Coordination Outage") now has its own
// dedicated, more thorough test in `chaos_coordination_unreachable.rs`
// (which also covers the outage-recovery half this one never did), so this
// file no longer duplicates it.
