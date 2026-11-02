//! A device removal waits on the coordination plane for seconds; the daemon must keep answering
//! its other control requests (status, the link list) while it waits. Runs on every platform,
//! over the platform's own control transport.

use crate::support;

use std::sync::Arc;
use std::time::Duration;

use support::control_socket_client as control;
use support::{
    connect_two_daemons, ensure_device_signing_key, open_file_backed_replica_coordinator,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    ListLinksRequest, RevokeDeviceCommandRequest, StatusRequest,
};
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::file::{BlockInfo, FileRecord};

const GROUP: &str = "revoke-reads-group";
/// How long the stand-in coordination plane takes to answer the audit record and the revoke.
const SLOW: Duration = Duration::from_secs(4);

struct Daemon {
    state: Arc<DaemonState>,
    _store_dir: tempfile::TempDir,
    _index_dir: tempfile::TempDir,
    root: tempfile::TempDir,
}

fn new_daemon(device_id: &str) -> Daemon {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let (sync_state, index_dir) = open_file_backed_replica_coordinator();
    let state = support::fast_daemon_state(device_id.to_string(), Arc::new(sync_state), store);
    ensure_device_signing_key(&state);
    let root = tempfile::tempdir().unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&root.path().to_string_lossy(), GROUP)
        .unwrap();
    Daemon { state, _store_dir: store_dir, _index_dir: index_dir, root }
}

/// Polls status and the link list over `socket` until `revoke` is done; returns the slowest
/// answer and how many reads were made. A failed read fails the test.
async fn poll_reads_until_finished<T>(
    socket: &control::ControlSocketHandle,
    revoke: &tokio::task::JoinHandle<T>,
) -> (Duration, usize) {
    let mut slowest = Duration::ZERO;
    let mut polls = 0;
    while !revoke.is_finished() {
        for payload in
            [ReqPayload::Status(StatusRequest {}), ReqPayload::ListLinks(ListLinksRequest {})]
        {
            let asked = std::time::Instant::now();
            let response = control::send(socket, payload).await;
            slowest = slowest.max(asked.elapsed());
            assert!(
                !matches!(response.payload, Some(RespPayload::Error(_))),
                "a read failed during the revoke: {:?}",
                response.payload
            );
            polls += 1;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    (slowest, polls)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reads_are_answered_while_a_revoke_waits_on_the_coordination_plane() {
    support::ensure_isolated_config_dir();
    let server = MockServer::start().await;
    for route in [format!("/shares/groups/{GROUP}/revoke"), "/audit/force-override".to_string()] {
        Mock::given(method("POST"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_delay(SLOW))
            .mount(&server)
            .await;
    }

    let a = new_daemon("device-a");
    let b = new_daemon("device-b"); // the operator, who removes device-a
    b.state.set_coordination_client_config(
        server.uri(),
        yadorilink_fapi_client::test_support::offline_auth(),
    );
    connect_two_daemons(&a.state, "device-a", &b.state, "device-b", &[GROUP.to_string()]).await;
    b.state.authority.set_peer_group_full_replica("device-a", GROUP, true);
    a.state.authority.set_peer_group_full_replica("device-b", GROUP, true);
    tokio::time::sleep(Duration::from_millis(500)).await; // let the session establish
    let socket = Arc::new(control::start(b.state.clone()).await);

    let revoke_socket = socket.clone();
    let revoke = tokio::spawn(async move {
        let started = std::time::Instant::now();
        let response = control::send(
            &revoke_socket,
            ReqPayload::RevokeDeviceCommand(RevokeDeviceCommandRequest {
                group_id: GROUP.to_string(),
                device_id: "device-a".to_string(),
                force: true,
            }),
        )
        .await;
        (response, started.elapsed())
    });

    let (slowest, polls) = poll_reads_until_finished(&socket, &revoke).await;
    let (response, took) = revoke.await.unwrap();
    println!("revoke took {took:?}; {polls} reads, slowest {slowest:?}; {:?}", response.payload);
    assert!(took >= SLOW, "the revoke did not wait on the coordination plane ({took:?})");
    assert!(slowest < Duration::from_secs(1), "a read waited {slowest:?} behind the revoke");
    let _ = a.root;
    let _ = b.root;
}

// --- the same, with a real handoff ticket and lease in the way ---

fn record_referencing(path: &str, hash_bytes: Vec<u8>, size: u64) -> FileRecord {
    FileRecord {
        path: path.to_string(),
        size,
        mtime_unix_nanos: 0,
        blocks: vec![BlockInfo { hash: hash_bytes, offset: 0, size: size as u32 }],
        deleted: false,
    }
}

fn far_future_expiry() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
        + 900
}

/// Wires device-a and device-b together exactly like `unlink_allowed_when_
/// another_replica_is_ready`, but symmetrically: device-b is ALSO marked a
/// full replica from device-a's point of view, so device-a's own target-side
/// readiness self-check (run when it answers device-b's `HandoffLeaseRequest`)
/// succeeds too. `configure_source_coordination` controls whether device-b
/// (the unlinking device) records coordination config at all -- setting it
/// `false` exercises the `(confirmed target, no source config)` fail-closed
/// arm. `configure_target_coordination` controls whether device-a gets a
/// coordination-plane config (and so whether it can ever grant a lease).
async fn unlink_setup(
    server: &MockServer,
    configure_source_coordination: bool,
    configure_target_coordination: bool,
) -> (Daemon, Daemon, Arc<control::ControlSocketHandle>) {
    support::ensure_isolated_config_dir();
    let a = new_daemon("device-a"); // complete copy: durably holds every block
    let b = new_daemon("device-b"); // eager device asking to unlink

    let content = b"the only file in this group";
    let hash = a.state.block_store.put(content).unwrap();
    b.state.block_store.put(content).unwrap();
    let bytes = hex::decode(hash.as_str()).unwrap();
    // Mirrors what `LocalChangeProcessor` does for a real local edit
    // (`record_group_block_provenance`'s doc comment): without this, the
    // real peer-to-peer readiness confirmation this file exercises refuses
    // the block as never having been obtained through the group.
    a.state
        .replica_coordinator
        .record_block_provenance(GROUP, std::slice::from_ref(&bytes))
        .unwrap();
    // Device-b needs the same provenance record as device-a: device-a's own
    // mandatory lease issuance re-verifies ITS OWN readiness by querying
    // device-b to confirm device-b durably holds this file, which requires
    // group block provenance on the ANSWERING side too.
    b.state
        .replica_coordinator
        .record_block_provenance(GROUP, std::slice::from_ref(&bytes))
        .unwrap();
    let record = record_referencing("only.bin", bytes, content.len() as u64);
    for daemon in [&a, &b] {
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        daemon
            .state
            .replica_coordinator
            .file_index_repository()
            .upsert_file(GROUP, &record, &permit)
            .unwrap();
        // `upsert_file` leaves a row `Remote`, which is what a row looks like
        // between its change being projected and its content being fetched.
        // Both devices here are meant to be holding the content -- they have
        // the blocks and the group provenance a few lines up -- so they have
        // to say so, and `Present` alone says nothing about which version the
        // object is: the proof is what a device's claim to hold the version
        // stands on.
        //
        // This used not to matter: the background custody check ran the
        // action-time proof, which asks the peer's BLOCK STORE. The
        // background check now asks the peer's index instead, and treats a
        // peer with the changes and unmaterialized rows as a peer that has
        // not taken custody yet -- deliberately, because that is exactly
        // what a device still doing its first sync looks like. The fixture
        // has to be specific about which of the two it is modelling.
        let on_disk = daemon.root.path().join(&record.path);
        std::fs::write(&on_disk, content).unwrap();
        yadorilink_daemon::test_support::seed_prior_cycle_proof(
            &daemon.state.replica_coordinator,
            GROUP,
            &record.path,
            &on_disk,
            &permit,
        );
    }

    // Must win the race against `connect_two_daemons`'s own coordination-
    // plane wiring below: `coordination_client_config` is a set-once
    // `OnceLock` (production semantics), so whichever caller sets it FIRST
    // wins for the rest of the process. This also matters for a `false`
    // flag here: `connect_two_daemons` would otherwise unconditionally wire
    // BOTH devices to its own fake regardless of what this test asked for,
    // silently defeating a deliberate no-config scenario too.
    if configure_source_coordination {
        b.state.set_coordination_client_config(
            server.uri(),
            yadorilink_fapi_client::test_support::offline_auth(),
        );
    }
    if configure_target_coordination {
        a.state.set_coordination_client_config(
            server.uri(),
            yadorilink_fapi_client::test_support::offline_auth(),
        );
    }

    connect_two_daemons(&a.state, "device-a", &b.state, "device-b", &[GROUP.to_string()]).await;
    b.state.authority.set_peer_group_full_replica("device-a", GROUP, true);
    a.state.authority.set_peer_group_full_replica("device-b", GROUP, true);
    tokio::time::sleep(Duration::from_millis(500)).await; // let the session establish

    let socket = Arc::new(control::start(b.state.clone()).await);
    (a, b, socket)
}

/// The unforced removal, which asks the removed device for a handoff ticket (it obtains a lease
/// from the remaining copy) and then commits through the coordination plane, keeps the operator
/// daemon's reads live for as long as it takes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reads_are_answered_while_a_ticket_bound_revoke_runs() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/handoff/lease")))
        .respond_with(ResponseTemplate::new(200).set_delay(SLOW).set_body_json(serde_json::json!({
            "leaseId": "lease-revoke-1",
            "expiresAt": far_future_expiry(),
            "ttlSeconds": 900,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/handoff/commit")))
        .respond_with(ResponseTemplate::new(200).set_delay(SLOW).set_body_json(serde_json::json!({
            "targetDeviceId": "device-b",
            "membershipGeneration": 1,
            "leaseId": "lease-revoke-1",
        })))
        .mount(&server)
        .await;

    let (_a, _b, socket) = unlink_setup(&server, true, true).await;
    let revoke_socket = socket.clone();
    let revoke = tokio::spawn(async move {
        let started = std::time::Instant::now();
        let response = control::send(
            &revoke_socket,
            ReqPayload::RevokeDeviceCommand(RevokeDeviceCommandRequest {
                group_id: GROUP.to_string(),
                device_id: "device-a".to_string(),
                force: false,
            }),
        )
        .await;
        (response, started.elapsed())
    });
    let (slowest, polls) = poll_reads_until_finished(&socket, &revoke).await;
    let (response, took) = revoke.await.unwrap();
    println!(
        "ticket revoke took {took:?}; {polls} reads, slowest {slowest:?}; {:?}",
        response.payload
    );
    assert!(slowest < Duration::from_secs(1), "a read waited {slowest:?} behind the revoke");
}
