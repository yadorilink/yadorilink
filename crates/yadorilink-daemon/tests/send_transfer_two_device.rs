//! Track Send: real two-device send/receive over each daemon's own iroh
//! endpoint (Track Send's ALPN), and a real crash-recovery test for
//! `receive_transfer`'s resume logic.
//!
//! Deliberately does NOT call `link_eager`/`link_on_demand` on either
//! device, and registers both with the coordination fake with an EMPTY
//! group list -- proving Track Send needs no linked folder and no shared
//! folder group, per its own design constraint. `support::topology`'s
//! `new_node`/`FakeCoordination`/`spawn_orchestrator` are reused exactly as
//! every other real-transport daemon test uses them; this file adds
//! nothing to that harness beyond what Track Send itself needs
//! (`yadorilink_daemon::send_transfer::run`, started the same way
//! `app.rs` starts it in production, over each node's own isolated
//! config directory).

mod support;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::topology::{new_node, spawn_orchestrator, TopologyNode};
use support::{register_with_fake, wait_until_with_context};
use yadorilink_daemon::daemon_state::DaemonState;

/// Starts Track Send's own background service for `node`, over its own
/// fresh, isolated directory -- never `YADORILINK_CONFIG_DIR` (process-wide,
/// and shared by every node in a multi-node test process; see
/// `send_transfer::run`'s own doc comment for why it takes this as an
/// explicit parameter instead of reading that env var itself).
fn start_send_transfer(node: &TopologyNode) -> tempfile::TempDir {
    let config_dir = tempfile::tempdir().unwrap();
    let state = node.state.clone();
    let dir = config_dir.path().to_path_buf();
    tokio::spawn(async move {
        let _ = yadorilink_daemon::send_transfer::run(state, dir).await;
    });
    config_dir
}

async fn wait_for_send_service(state: &Arc<DaemonState>) {
    wait_until_with_context(
        || state.send_service().is_some(),
        Duration::from_secs(30),
        || "Track Send service never became ready".to_string(),
    )
    .await;
}

/// Pairs two nodes with the coordination fake using an EMPTY group list on
/// both sides and starts Track Send on both. Returns the `FakeCoordination`, the two orchestrator runtimes, and
/// both nodes' Track Send config-dir guards -- all of which must outlive
/// the calling test.
async fn stand_up_two_groupless_devices(
    a_name: &str,
    b_name: &str,
) -> (
    FakeCoordination,
    TopologyNode,
    TopologyNode,
    [tokio::runtime::Runtime; 2],
    [tempfile::TempDir; 2],
) {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;

    let a = new_node(a_name);
    let b = new_node(b_name);
    for node in [&a, &b] {
        // Empty group list: Track Send must work between two same-account
        // devices that share NO folder group at all.
        register_with_fake(&fake, &node.state, &node.device_id, &[]).await;
    }

    let runtimes = [spawn_orchestrator(fake.addr(), &a), spawn_orchestrator(fake.addr(), &b)];

    // Deliberately NOT `fully_connected`: two devices sharing no folder
    // group are never each other's sync peers, so no sync session ever
    // exists between them. That absence is the point: Track Send reaches
    // the receiver on its own ALPN, admitted by the grant the coordination
    // plane issues, with the receiver's iroh address taken from that grant.
    //
    // `wait_for_send_service` below is the readiness signal this scenario
    // needs: `send_transfer::run` publishes a `SendService` only once the
    // daemon's reconciliation stack -- and so its iroh endpoint -- exists.
    // The receiver's substrate address must also be on the plane before a
    // grant can carry it. The harness does not run the daemon's startup, so
    // each node's address report -- the production route by which a
    // device's iroh address reaches the plane -- is started here, and
    // `wait_for_substrate_address` waits for it to land.
    let send_dirs = [start_send_transfer(&a), start_send_transfer(&b)];
    wait_for_send_service(&a.state).await;
    wait_for_send_service(&b.state).await;
    for node in [&a, &b] {
        report_endpoint(&fake, node);
        wait_for_substrate_address(&fake, &node.device_id).await;
    }

    (fake, a, b, runtimes, send_dirs)
}

/// Runs `node`'s real address reporter against the fake: whatever its iroh
/// endpoint publishes (`local_substrate_reachability`) is reported to the
/// plane, exactly as the daemon's startup does in production.
fn report_endpoint(fake: &FakeCoordination, node: &TopologyNode) {
    tokio::spawn(yadorilink_daemon::peer_connectivity_runtime::report_own_address(
        fake.addr(),
        yadorilink_fapi_client::test_support::offline_auth(),
        node.device_id.clone(),
        node.state.peer_connectivity.local_substrate_reachability.clone(),
    ));
}

/// Waits until the coordination fake holds `device_id`'s iroh endpoint
/// address -- what a Track Send grant hands the other side to dial.
async fn wait_for_substrate_address(fake: &FakeCoordination, device_id: &str) {
    wait_until_with_context(
        || fake.substrate_reachability_of(device_id).is_some_and(|(direct, _)| !direct.is_empty()),
        Duration::from_secs(30),
        || format!("{device_id} never published an iroh address"),
    )
    .await;
}

fn shutdown_orchestrators(runtimes: [tokio::runtime::Runtime; 2]) {
    for runtime in runtimes {
        runtime.shutdown_background();
    }
}

/// The golden path: A sends a file to B, with no linked folder and no
/// shared group anywhere in the setup. B sees it in its inbox before
/// receiving, then `receive_transfer` materializes it with the exact
/// original bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_devices_send_and_receive_a_file_with_no_shared_group() {
    let (_fake, a, b, runtimes, _send_dirs) =
        stand_up_two_groupless_devices("send-a-sender", "send-b-receiver").await;

    let source_dir = tempfile::tempdir().unwrap();
    let source_path = source_dir.path().join("hello.txt");
    std::fs::write(&source_path, b"hello from device A, never synced through any folder").unwrap();

    let outcome = a
        .state
        .send_service()
        .unwrap()
        .offer_send(&source_path, &b.device_id)
        .await
        .expect("offer_send should succeed between two connected, groupless devices");
    assert_eq!(outcome.files_offered, vec!["hello.txt".to_string()]);

    let inbox = b.state.send_service().unwrap().list_inbox().unwrap();
    assert_eq!(inbox.len(), 1, "B's inbox should show the pending offer before receiving it");
    assert_eq!(inbox[0].transfer_id, outcome.transfer_id);
    assert_eq!(inbox[0].sender_device_id, a.device_id);
    assert_eq!(inbox[0].status, "pending");

    let dest_dir = tempfile::tempdir().unwrap();
    let receive_outcome = b
        .state
        .send_service()
        .unwrap()
        .receive_transfer(&outcome.transfer_id, Some(dest_dir.path()))
        .await
        .expect("receive_transfer should succeed");
    assert_eq!(receive_outcome.files_received, vec!["hello.txt".to_string()]);

    let received = std::fs::read(dest_dir.path().join("hello.txt")).unwrap();
    assert_eq!(received, b"hello from device A, never synced through any folder");

    let inbox_after = b.state.send_service().unwrap().list_inbox().unwrap();
    assert_eq!(inbox_after[0].status, "completed");

    shutdown_orchestrators(runtimes);
}

/// Real crash-recovery: a multi-chunk transfer is interrupted by aborting
/// the exact task driving `receive_transfer` the instant 3 of its chunks
/// are durably confirmed (not all of them) -- a real task abort, not a
/// simulated flag -- then `receive_transfer` is run again from scratch (a
/// fresh call, exactly what re-running `yadorilink receive <id>` after a
/// real process restart would do) and must resume from that partial state
/// and finish with byte-exact content.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn receive_resumes_after_a_simulated_crash_mid_transfer() {
    let (_fake, a, b, runtimes, _send_dirs) =
        stand_up_two_groupless_devices("send-a-sender-crash", "send-b-receiver-crash").await;

    // Comfortably more than one chunk at the default 128 KiB block size, so
    // there is genuine room for "some chunks landed, some didn't".
    let source_dir = tempfile::tempdir().unwrap();
    let source_path = source_dir.path().join("big.bin");
    let content: Vec<u8> = (0..900_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&source_path, &content).unwrap();

    let outcome =
        a.state.send_service().unwrap().offer_send(&source_path, &b.device_id).await.unwrap();

    let receiver = b.state.send_service().unwrap();
    let dest_dir = tempfile::tempdir().unwrap();
    let dest_path: PathBuf = dest_dir.path().to_path_buf();

    // ---- CRASH: abort receive_transfer once exactly 3 chunks have landed.
    let hit_three_chunks = receiver.test_abort_after_n_chunks(3);
    let crash_transfer_id = outcome.transfer_id.clone();
    let crash_receiver = receiver.clone();
    let in_flight = tokio::spawn(async move {
        crash_receiver.receive_transfer(&crash_transfer_id, Some(&dest_path)).await
    });
    tokio::time::timeout(Duration::from_secs(30), hit_three_chunks.notified())
        .await
        .expect("3 chunks should confirm well within 30s over a real loopback connection");
    in_flight.abort();
    let aborted_result = in_flight.await;
    assert!(aborted_result.is_err(), "the task must have been genuinely aborted, not raced");

    // The final materialized file must NOT exist yet -- the crash landed
    // before `reconstruct_file`'s atomic rename, or there would be nothing
    // left to resume.
    assert!(
        !dest_dir.path().join("big.bin").exists(),
        "a real crash mid-transfer must not have left a (necessarily incomplete) final file"
    );

    // ---- RESTART: a fresh call, exactly what re-running `yadorilink
    // receive <id>` does. No special "resume" API -- the same entry point.
    let final_outcome = receiver
        .receive_transfer(&outcome.transfer_id, Some(dest_dir.path()))
        .await
        .expect("receive_transfer must resume and complete after the simulated crash");
    assert_eq!(final_outcome.files_received, vec!["big.bin".to_string()]);

    let received = std::fs::read(dest_dir.path().join("big.bin")).unwrap();
    assert_eq!(received.len(), content.len());
    assert_eq!(received, content, "resumed transfer must produce byte-exact content");

    let inbox_after = receiver.list_inbox().unwrap();
    assert_eq!(inbox_after[0].status, "completed");

    shutdown_orchestrators(runtimes);
}
