//! The removed-device handoff-ticket flow (Stage C): lifts the cross-device
//! durability fail-closed gate for the online case by having the removed
//! device (B) attest and hand off ITS OWN roots, rather than the operating
//! device (X) trying (and being structurally unable) to attest them.
//!
//! Mirrors `unlink_and_removal_durability.rs`'s real-peer-session style:
//! `connect_two_daemons` wires actual loopback UDP sessions between
//! in-process `DaemonState`s, so these tests exercise the real
//! `HandoffTicketRequest`/`HandoffTicketGrant` wire exchange and the real
//! `HandoffLeaseRequest`/`HandoffLeaseGrant` exchange it reuses underneath
//! (Stage B, unchanged), not an injected confirmer.
#![cfg(unix)]

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::{
    connect_two_daemons, ensure_device_signing_key, ensure_isolated_config_dir,
    open_file_backed_replica_coordinator,
};
use tokio::net::UnixStream;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    DaemonControlRequest, DaemonControlResponse, ObtainHandoffTicketRequest,
};
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::file::{BlockInfo, FileRecord};

const GROUP: &str = "ticket-durability-group";

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
    let state = DaemonState::new(device_id.to_string(), Arc::new(sync_state), store);
    ensure_device_signing_key(&state);
    let root = tempfile::tempdir().unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&root.path().to_string_lossy(), GROUP)
        .unwrap();
    Daemon { state, _store_dir: store_dir, _index_dir: index_dir, root }
}

fn record_referencing(path: &str, _author: &str, hash_bytes: Vec<u8>, size: u64) -> FileRecord {
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

async fn send_over_socket(
    socket_path: &std::path::Path,
    payload: ReqPayload,
) -> DaemonControlResponse {
    let mut stream = UnixStream::connect(socket_path).await.unwrap();
    write_message(
        &mut stream,
        &DaemonControlRequest {
            payload: Some(payload),
            protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
        },
    )
    .await
    .unwrap();
    read_message::<DaemonControlResponse>(&mut stream).await.unwrap().unwrap()
}

/// Puts `content` in `daemon`'s block store and records `file_name` as one
/// of its current files, with a version vector authored by `author`. Every
/// daemon that is meant to durably hold the SAME version of a file must be
/// given the same `author` (regardless of which device's own id that is) so
/// each independently produces an identical version vector -- and so an
/// identical `change::VersionHash` -- matching `unlink_and_removal_
/// durability.rs`'s own `record_referencing` convention: whole-group
/// durability confirmation (`peer_holds_entire_group`) requires an exact
/// version-hash match, not merely equal content.
fn give_file(daemon: &Daemon, file_name: &str, content: &[u8], author: &str) {
    let hash = daemon.state.block_store.put(content).unwrap();
    let bytes = hex::decode(hash.as_str()).unwrap();
    // Mirrors what `LocalChangeProcessor` does for a real local edit
    // (`record_group_block_provenance`'s doc comment): without this, the
    // real peer-to-peer durability confirmation this file exercises
    // refuses the block as never having been obtained through the group.
    daemon
        .state
        .replica_coordinator
        .record_block_provenance(GROUP, std::slice::from_ref(&bytes))
        .unwrap();
    let record = record_referencing(file_name, author, bytes, content.len() as u64);
    daemon
        .state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
}

// --- happy path: B online, produces a real ticket ------------------------

/// Device-b (the device being removed) is online and can pin its own root
/// set at device-c (a confirmed peer holding everything b holds). Device-x
/// (the operating device) asks its own daemon, over the real control
/// socket, to obtain a ticket from device-b -- and gets `granted = true`
/// with a real lease id back, proving the ticket was actually requested
/// from b and a live lease actually obtained, not a local guess.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn ticket_granted_when_b_is_online_and_can_pin_its_own_roots_at_a_confirmed_peer() {
    ensure_isolated_config_dir();
    let b = new_daemon("device-b"); // the device being removed
    let c = new_daemon("device-c"); // a confirmed peer holding everything b holds
    let x = new_daemon("device-x"); // the operating device

    give_file(&b, "shared.bin", b"the only file device-b holds", "device-b");
    give_file(&c, "shared.bin", b"the only file device-b holds", "device-b");

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/handoff/lease")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "leaseId": "ticket-lease-1",
            "expiresAt": far_future_expiry(),
            "ttlSeconds": 900,
        })))
        .mount(&server)
        .await;

    // Must win the race against `connect_two_daemons`'s own coordination-
    // plane wiring below: `coordination_client_config` is a set-once
    // `OnceLock` (matching production semantics -- see its own doc
    // comment), so whichever caller sets it FIRST wins for the rest of the
    // process. This test needs device-c's config to be THIS wiremock
    // server (only it implements the handoff-lease endpoint this test
    // exercises), not `connect_two_daemons`'s own in-process checkpoint-
    // issuance fake.
    c.state.set_coordination_client_config(
        server.uri(),
        yadorilink_fapi_client::test_support::offline_auth(),
    );
    connect_two_daemons(&b.state, "device-b", &c.state, "device-c", &[GROUP.to_string()]).await;
    // Symmetric marking, matching `unlink_and_removal_durability.rs`'s
    // `unlink_setup`: device-c's own target-side readiness self-check (run
    // as part of `request_handoff_lease` when it answers device-b's
    // `HandoffLeaseRequest`) needs device-b marked as its own confirming
    // full replica too -- device-c's root set (just `shared.bin`) is a
    // subset of what device-b holds, so this is trivially satisfied.
    b.state.authority.set_peer_group_full_replica("device-c", GROUP, true);
    c.state.authority.set_peer_group_full_replica("device-b", GROUP, true);

    connect_two_daemons(&x.state, "device-x", &b.state, "device-b", &[GROUP.to_string()]).await;
    tokio::time::sleep(Duration::from_millis(500)).await; // let both sessions establish

    let socket_path = x.root.path().join("daemon.sock");
    let serve_path = socket_path.clone();
    let serve_state = x.state.clone();
    tokio::spawn(async move {
        let _ = yadorilink_daemon::control_socket::unix_transport::serve(
            &serve_path,
            std::sync::Arc::new(yadorilink_daemon::control_context::ControlContext::from_state(
                serve_state,
            )),
        )
        .await;
    });
    yadorilink_daemon::control_socket::unix_transport::wait_until_bound(&socket_path).await;

    let resp = send_over_socket(
        &socket_path,
        ReqPayload::ObtainHandoffTicket(ObtainHandoffTicketRequest {
            group_id: GROUP.to_string(),
            device_id: "device-b".to_string(),
        }),
    )
    .await;
    let Some(RespPayload::ObtainHandoffTicket(r)) = resp.payload else {
        panic!("wrong response variant: {:?}", resp.payload)
    };
    assert!(r.granted, "device-b is online and can pin its own roots at device-c; must be granted");
    assert_eq!(r.lease_id, "ticket-lease-1");
    // The ticket must name the confirming peer (device-c) alongside the
    // lease id -- this is what lets X present `(lease_id, target_device_id)`
    // together to a lease-guarded role-loss commit, atomically re-verified
    // at removal time rather than trusted from ticket-issue time alone.
    assert_eq!(r.target_device_id, "device-c");

    // INV-4: the only Worker call this flow makes (device-c's own
    // target-side Stage-B lease request) must carry no digest, path, or
    // version -- purely `(group_id, target_device_id)`, per
    // `coordination_client::request_handoff_lease`'s own contract.
    let requests = server.received_requests().await.unwrap();
    let lease_requests: Vec<_> =
        requests.iter().filter(|r| r.url.path().ends_with("/handoff/lease")).collect();
    assert_eq!(lease_requests.len(), 1, "device-c must have actually requested a Worker lease");
    let body: serde_json::Value = lease_requests[0].body_json().unwrap();
    let keys: Vec<&str> = body.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys, vec!["targetDeviceId"], "the Worker call must carry no content-derived field");
}

// --- B online but cannot pin its own roots --------------------------------

/// Device-b is online (a live session to device-x exists) but no other peer
/// confirms holding its whole root set -- b cannot pin/lease its own roots
/// this round, so the ticket must not be granted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ticket_not_granted_when_b_has_no_confirming_peer() {
    ensure_isolated_config_dir();
    let b = new_daemon("device-b");
    let x = new_daemon("device-x");

    give_file(&b, "solo.bin", b"only device-b has this", "device-b");

    connect_two_daemons(&x.state, "device-x", &b.state, "device-b", &[GROUP.to_string()]).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let grant = x.state.obtain_handoff_ticket_from_device(GROUP, "device-b").await;
    assert!(
        grant.is_none(),
        "no peer confirms holding device-b's whole root set, so no ticket can be granted"
    );
}

// --- the key trust boundary: B attests its OWN roots, not X's local view -

/// The scenario the whole design exists for: device-x's OWN local view of
/// the group would say "ready" (it only knows about the file device-c also
/// holds), but device-b additionally holds a version unique to itself
/// (`b_unique.bin`, which neither device-x nor device-c has). The ticket
/// decision must route through device-b's own attestation -- which
/// correctly declines, since device-c cannot confirm device-b's whole root
/// set -- never through device-x's (in this case wrong) self-view.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn b_attests_its_own_roots_and_x_never_self_attests() {
    ensure_isolated_config_dir();
    let x = new_daemon("device-x");
    let b = new_daemon("device-b"); // the device being removed
    let c = new_daemon("device-c"); // confirms the file x and c share, but not b's extra one

    let shared = b"a file all three devices hold";
    give_file(&x, "shared.bin", shared, "device-b");
    give_file(&b, "shared.bin", shared, "device-b");
    give_file(&c, "shared.bin", shared, "device-b");
    // A version unique to device-b -- neither device-x nor device-c ever
    // receives this file.
    give_file(&b, "b_unique.bin", b"only device-b ever holds this", "device-b");

    connect_two_daemons(&x.state, "device-x", &c.state, "device-c", &[GROUP.to_string()]).await;
    x.state.authority.set_peer_group_full_replica("device-c", GROUP, true);

    connect_two_daemons(&b.state, "device-b", &c.state, "device-c", &[GROUP.to_string()]).await;
    b.state.authority.set_peer_group_full_replica("device-c", GROUP, true);
    c.state.authority.set_peer_group_full_replica("device-b", GROUP, true);
    c.state.set_coordination_client_config(
        "http://127.0.0.1:1".to_string(),
        yadorilink_fapi_client::test_support::offline_auth(),
    );

    connect_two_daemons(&x.state, "device-x", &b.state, "device-b", &[GROUP.to_string()]).await;
    tokio::time::sleep(Duration::from_millis(600)).await; // let every session establish

    // Sanity check: device-x's OWN local view (only `shared.bin`) would
    // call itself ready, confirmed by device-c -- proving this is a
    // realistic case where a self-attesting X would have gotten it wrong.
    assert!(
        x.state.full_replica_handoff_proof(GROUP).await.is_some(),
        "sanity check: device-x's own (incomplete, missing b_unique.bin) root view must look ready"
    );

    // The real decision: device-b's own root set (`shared.bin` +
    // `b_unique.bin`) is NOT confirmed by device-c (missing `b_unique.bin`),
    // so device-b cannot pin/lease it -- the ticket must not be granted,
    // regardless of what device-x's own (wrong, for b's roots) view says.
    let grant = x.state.obtain_handoff_ticket_from_device(GROUP, "device-b").await;
    assert!(
        grant.is_none(),
        "device-b holds a version (b_unique.bin) no confirming peer has -- the ticket must route \
         through device-b's own attestation, which correctly declines, not through device-x's \
         local view, which would have wrongly said ready"
    );
}
