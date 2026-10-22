//! Chaos test for "Published Data Plane Survives Coordination Outage" --
//! deliberately narrower than this file's old name/claim
//! ("Coordination Plane Availability Independence"). That broader claim is
//! not achievable under `AuthorizationCheckpoint` admission: a NEW Change
//! cannot become Published without
//! a live round-trip to the coordination plane (checkpoint issuance is the
//! SOLE writer-authorization gate, and it must check CURRENT writer status
//! live -- a cached/short-grace/current-key-only exemption of any kind would
//! reintroduce exactly the stale-authorization class of bug checkpoint
//! admission exists to close, under a different name). What genuinely survives
//! a coordination outage, and what this test proves end to end:
//!
//! ```text
//! transfer of already-Published Changes/blocks over the direct transport   yes
//! an already-established peer session                                     yes
//! a device authoring a NEW local edit                                     yes
//! that edit's local durability (indexed, DAG-admitted, Pending)            yes
//! that edit reaching the OTHER device while the outage lasts               no
//! automatic Pending -> Published + convergence once the plane recovers    yes
//! ```
//!
//! i.e. `edit -> Pending --(outage)--> Pending --(recovery)--> checkpoint ->
//! Published -> peer convergence`. A user's own editing is never blocked;
//! only this device's OWN new edits reaching a peer is deferred, and it
//! resumes automatically -- no manual republish, no lost edits, no silent
//! drop.
//!
//! This drives the real daemon stack (real `DaemonState` +
//! `LinkRuntimeController::start` + `peer_orchestrator::run`, discovering
//! its peer from the in-process fake coordination plane's netmap) rather than
//! the lighter-weight `connect_two_daemons` pairing, so the coordination-plane
//! outage is a genuine outage of the seam the orchestrator actually depends on:
//! taking the fake down aborts its listener (future reconnects fail) and closes
//! every live netmap WebSocket, exactly as a real plane vanishing would; and
//! `FakeCoordination::restart` brings it back up on the SAME address with its
//! device/policy registration intact (a coordination plane's registration
//! database is durable storage, unlike the in-memory connections an outage
//! actually drops -- see that method's own doc comment), modeling recovery
//! rather than a permanent outage.

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

/// Diagnostic-only: one device's index state for `path` -- distinguishes
/// "never arrived in the index at all" (delivery/DAG-admission never
/// reached it) from "indexed but not materialized" (e.g. stuck
/// `Hydrating`/`Remote`, or held) from "DAG head advanced, index says
/// live, but the bytes never landed on disk" (a materialization bug).
/// Mirrors `monkey_chaos.rs`'s `describe_index_state`.
fn describe_index_state(state: &DaemonState, group_id: &str, path: &str) -> String {
    let record = state.replica_coordinator.file_index_repository().get_file(group_id, path);
    let materialization = state
        .replica_coordinator
        .materialization_state_repository()
        .get_materialization_state(group_id, path);
    let held =
        state.replica_coordinator.materialization_state_repository().get_held_state(group_id, path);
    let heads = state
        .replica_coordinator
        .sqlite()
        .native_group_heads(group_id)
        .map(|hs| hs.iter().map(|h| h.to_hex()).collect::<Vec<_>>());
    format!(
        "record={record:?} materialization={materialization:?} held={held:?} \
         dag_group_heads={heads:?}"
    )
}

fn spawn_orchestrator(coordination_addr: String, device_id: String, state: Arc<DaemonState>) {
    let log_device_id = device_id.clone();
    let config = peer_orchestrator::OrchestratorConfig {
        coordination_addr,
        auth: yadorilink_fapi_client::test_support::offline_auth(),
        device_id,
    };
    tokio::spawn(async move {
        if let Err(error) = peer_orchestrator::run(config, state).await {
            eprintln!("peer orchestrator for {log_device_id} stopped: {error}");
        }
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn published_data_plane_survives_coordination_outage_and_pending_edits_converge_on_recovery()
{
    let _ = tracing_subscriber::fmt::try_init();
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let fake_host = fake.addr().trim_start_matches("http://").to_string();
    let device_a_id = "device-a";
    let device_b_id = "device-b";
    let group_id = "chaos-group";

    let daemon_a = new_test_daemon(device_a_id);
    let daemon_b = new_test_daemon(device_b_id);
    let root_a = tempfile::tempdir().unwrap();
    let root_b = tempfile::tempdir().unwrap();

    register_with_fake(&fake, &daemon_a.state, device_a_id, &[group_id]).await;
    register_with_fake(&fake, &daemon_b.state, device_b_id, &[group_id]).await;

    // Seed the healthy-sync probe before linking so the deterministic initial
    // scan captures it. Watcher behavior is exercised by the post-outage
    // writes below; this probe only establishes the pre-outage baseline.
    std::fs::write(root_a.path().join("before-outage.txt"), b"synced while healthy").unwrap();
    link(&daemon_a.state, root_a.path(), group_id);
    link(&daemon_b.state, root_b.path(), group_id);

    spawn_orchestrator(fake.addr(), device_a_id.to_string(), daemon_a.state.clone());
    spawn_orchestrator(fake.addr(), device_b_id.to_string(), daemon_b.state.clone());

    // The reconciliation substrate is the only plane that carries DAG
    // changes, and these fixtures do not propagate its addresses -- see
    // `support::topology::advertise_substrate_endpoints` for the two
    // test-side reasons. Without this the pre-outage baseline below can
    // never pass: both sessions come up, and nothing converges. It
    // survives `fake.restart()`.
    support::advertise_substrate_between(&[&daemon_a.state, &daemon_b.state]).await;

    // Establish both peer sessions before checking the healthy-sync probe.
    wait_until_with_context(
        || {
            daemon_a.state.peers.has_session(device_b_id)
                && daemon_b.state.peers.has_session(device_a_id)
        },
        Duration::from_secs(60),
        || {
            format!(
                "peer sessions did not connect\ndaemon-a: {}\ndaemon-b: {}",
                daemon_status_summary(&daemon_a.state),
                daemon_status_summary(&daemon_b.state)
            )
        },
    )
    .await;

    // Confirm an initial sync works *before* the outage.
    wait_until_with_context(
        || root_b.path().join("before-outage.txt").exists(),
        Duration::from_secs(30),
        || {
            format!(
                "initial sync failed\ndaemon-a: {}\ndaemon-b: {}\n  a/before-outage.txt: {}\n  \
                 b/before-outage.txt: {}",
                daemon_status_summary(&daemon_a.state),
                daemon_status_summary(&daemon_b.state),
                describe_index_state(&daemon_a.state, group_id, "before-outage.txt"),
                describe_index_state(&daemon_b.state, group_id, "before-outage.txt"),
            )
        },
    )
    .await;

    // Confirm the LIVE watcher -> debounce -> DAG-emit -> announce path also
    // works before the outage, not just the initial-scan path
    // `before-outage.txt` exercised above. Without this, a post-outage sync
    // failure below is ambiguous between "coordination unavailability broke
    // peer sync" (what this test exists to catch) and "the live watcher
    // pipeline has an unrelated bug" (this test's post-outage writes would
    // otherwise be the *first* time either device's live watcher is
    // exercised at all in this scenario) -- indistinguishable failure modes
    // without a working live-watcher baseline recorded first.
    std::fs::write(root_a.path().join("live-before-outage.txt"), b"live watcher works").unwrap();
    wait_until_with_context(
        || root_b.path().join("live-before-outage.txt").exists(),
        Duration::from_secs(30),
        || {
            format!(
                "pre-outage LIVE watcher sync failed (coordination plane is still up here -- \
                 this isolates a live-watcher-pipeline bug from a coordination-availability bug)\n\
                 daemon-a: {}\ndaemon-b: {}\ndaemon-a live-before-outage.txt: {}",
                daemon_status_summary(&daemon_a.state),
                daemon_status_summary(&daemon_b.state),
                describe_index_state(&daemon_a.state, group_id, "live-before-outage.txt"),
            )
        },
    )
    .await;

    // Simulate the coordination plane vanishing completely: abort its accept
    // loop (freeing the port, so every future reconnect fails immediately —
    // connection refused, not just slow) and drop every live netmap
    // subscription.
    fake.shutdown();
    wait_until(
        || {
            std::net::TcpStream::connect_timeout(
                &fake_host.parse().unwrap(),
                Duration::from_millis(200),
            )
            .is_err()
        },
        Duration::from_secs(5),
    )
    .await;

    // Step 3: already-Published content stays available on the direct
    // transport throughout the outage -- re-confirm both pre-outage probes
    // are still present with unchanged content on the peer that received
    // them, proving the outage did not roll back or evict anything already
    // synced (this is the data-plane guarantee this test's name actually
    // makes, unlike the new-edit guarantee below).
    assert_eq!(
        std::fs::read(root_b.path().join("before-outage.txt")).unwrap(),
        b"synced while healthy",
        "already-Published content must remain available through a coordination outage"
    );
    assert_eq!(
        std::fs::read(root_b.path().join("live-before-outage.txt")).unwrap(),
        b"live watcher works",
        "already-Published content must remain available through a coordination outage"
    );

    // Steps 4-5: both devices author a NEW local edit WHILE the plane is
    // down. Local authoring is never blocked (`replica_coordinator.rs`'s
    // `LocalPolicyHeadProvider` doc comment: local emission is unconditional
    // regardless of writer role OR coordination-plane reachability) -- both
    // edits land in each device's OWN index/DAG as ordinary Pending Changes.
    // What must NOT happen is either edit reaching the OTHER device: a
    // Pending Change has no checkpoint evidence, and `send_change_batch` can
    // only ever serve a Published one (see the checkpoint-evidence rules).
    std::fs::write(root_a.path().join("during-outage-from-a.txt"), b"a keeps editing").unwrap();
    std::fs::write(root_b.path().join("during-outage-from-b.txt"), b"b keeps editing").unwrap();

    wait_until_with_context(
        || {
            daemon_a
                .state
                .replica_coordinator
                .file_index_repository()
                .get_file(group_id, "during-outage-from-a.txt")
                .unwrap()
                .is_some()
        },
        Duration::from_secs(10),
        || {
            format!(
                "device A's own local edit made during the outage must still be indexed locally \
                 (local emission is unconditional) -- daemon-a: {}",
                describe_index_state(&daemon_a.state, group_id, "during-outage-from-a.txt"),
            )
        },
    )
    .await;
    wait_until_with_context(
        || {
            daemon_b
                .state
                .replica_coordinator
                .file_index_repository()
                .get_file(group_id, "during-outage-from-b.txt")
                .unwrap()
                .is_some()
        },
        Duration::from_secs(10),
        || {
            format!(
                "device B's own local edit made during the outage must still be indexed locally \
                 (local emission is unconditional) -- daemon-b: {}",
                describe_index_state(&daemon_b.state, group_id, "during-outage-from-b.txt"),
            )
        },
    )
    .await;

    // A generous settle window (matching scenario (a)'s in `viewer_editor_
    // authorization_end_to_end.rs`): long enough that any real cross-device
    // sync would have completed several times over if the checkpoint gate
    // were somehow bypassed.
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(
        !root_b.path().join("during-outage-from-a.txt").exists(),
        "an edit authored during a coordination outage must never reach the peer until the \
         outage recovers and this device's Pending Change gets checkpointed"
    );
    assert!(
        !root_a.path().join("during-outage-from-b.txt").exists(),
        "an edit authored during a coordination outage must never reach the peer until the \
         outage recovers and this device's Pending Change gets checkpointed"
    );

    // Step 6: the coordination plane recovers, on the SAME address, with
    // every device/policy registration from before the outage intact (see
    // `FakeCoordination::restart`'s own doc comment) -- exactly what a real
    // coordination-plane process restart looks like from a daemon's
    // perspective. Each daemon's own WS reconnect logic picks the netmap
    // subscription back up on its existing retry cadence; nothing in this
    // test needs to nudge it.
    fake.restart();

    // Steps 7-8: both Pending edits get checkpointed automatically (no
    // manual republish) and converge to both devices.
    wait_until_with_context(
        || root_b.path().join("during-outage-from-a.txt").exists(),
        Duration::from_secs(30),
        || {
            format!(
                "post-recovery A-to-B convergence failed\ndaemon-a: {}\ndaemon-b: {}\n\
                 daemon-a during-outage-from-a.txt: {}\ndaemon-b during-outage-from-a.txt: {}",
                daemon_status_summary(&daemon_a.state),
                daemon_status_summary(&daemon_b.state),
                describe_index_state(&daemon_a.state, group_id, "during-outage-from-a.txt"),
                describe_index_state(&daemon_b.state, group_id, "during-outage-from-a.txt"),
            )
        },
    )
    .await;
    wait_until_with_context(
        || root_a.path().join("during-outage-from-b.txt").exists(),
        Duration::from_secs(30),
        || {
            format!(
                "post-recovery B-to-A convergence failed\ndaemon-a: {}\ndaemon-b: {}\n\
                 daemon-a during-outage-from-b.txt: {}\ndaemon-b during-outage-from-b.txt: {}",
                daemon_status_summary(&daemon_a.state),
                daemon_status_summary(&daemon_b.state),
                describe_index_state(&daemon_a.state, group_id, "during-outage-from-b.txt"),
                describe_index_state(&daemon_b.state, group_id, "during-outage-from-b.txt"),
            )
        },
    )
    .await;

    assert_eq!(
        std::fs::read(root_b.path().join("during-outage-from-a.txt")).unwrap(),
        b"a keeps editing"
    );
    assert_eq!(
        std::fs::read(root_a.path().join("during-outage-from-b.txt")).unwrap(),
        b"b keeps editing"
    );

    // Step 9: no duplicate-Change/conflict-copy storm from the outage+
    // recovery cycle -- both devices edited DISTINCT paths (no genuine
    // content conflict is even possible here), so a conflict-copy sibling
    // file appearing at all would mean the recovery path spuriously forked
    // history rather than cleanly converging it.
    for entry in
        std::fs::read_dir(root_a.path()).unwrap().chain(std::fs::read_dir(root_b.path()).unwrap())
    {
        let name = entry.unwrap().file_name().to_string_lossy().to_string();
        assert!(
            !name.contains("(conflicted copy"),
            "the outage+recovery cycle must never fork a conflict copy for a path only one \
             device ever touched, got {name:?}"
        );
    }
}
