//! The Ready-handoff gate closing the count-vs-readiness gap on the
//! non-demote role-loss paths: `yadorilink unlink` (exercised end-to-end
//! over the real control socket, mirroring `control_socket.rs`'s own
//! integration style) and `DaemonState::another_full_replica_is_ready_excluding`
//! (the primitive behind the `share revoke`/`device remove` pre-check,
//! exercised the same way `full_replica_handoff_ready.rs` exercises its
//! non-excluding sibling — real peer-to-peer `VersionPresentQuery`s, not an
//! injected confirmer).
#![cfg(unix)]

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::{
    connect_two_daemons, ensure_device_signing_key, open_file_backed_replica_coordinator,
};
use tokio::net::UnixStream;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::durability_service::GroupDurabilityStatus;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    ApplicationErrorCode, DaemonControlRequest, DaemonControlResponse, ListLinksRequest,
    UnlinkRequest,
};
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
use yadorilink_replica_domain::session_state::RoleLossOperationState;

const GROUP: &str = "durability-group";

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

fn record_referencing(path: &str, hash_bytes: Vec<u8>, size: u64) -> FileRecord {
    FileRecord {
        path: path.to_string(),
        size,
        mtime_unix_nanos: 0,
        blocks: vec![BlockInfo { hash: hash_bytes, offset: 0, size: size as u32 }],
        deleted: false,
    }
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

// --- unlink: refused without a confirmed-ready replica, allowed with one ---

/// The eager device asking to unlink has a file, but no peer is connected at
/// all to confirm holding it -- the same "no other full replica" case
/// `set-storage-mode --mode on-demand` refuses, now closed for unlink too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unlink_refused_when_no_other_replica_is_ready() {
    support::ensure_isolated_config_dir();
    let b = new_daemon("device-b");
    let record = record_referencing("solo.bin", vec![1u8; 32], 4);
    b.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    let socket_path = b.root.path().join("daemon.sock");
    let serve_path = socket_path.clone();
    let serve_state = b.state.clone();
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

    let local_path = b.root.path().to_string_lossy().to_string();
    let resp = send_over_socket(
        &socket_path,
        ReqPayload::Unlink(UnlinkRequest {
            local_path: local_path.clone(),
            force: false,
            expected_group_id: String::new(),
        }),
    )
    .await;
    assert!(
        matches!(resp.payload, Some(RespPayload::CommandError(ref e)) if e.code() == ApplicationErrorCode::NotProtected && e.message.contains("no other complete copy")),
        "unlinking the last confirmed-ready replica must be refused, got {:?}",
        resp.payload
    );

    // Refused means the link must still be present.
    let resp = send_over_socket(&socket_path, ReqPayload::ListLinks(ListLinksRequest {})).await;
    let Some(RespPayload::ListLinks(list)) = resp.payload else { panic!("wrong response variant") };
    assert_eq!(list.links.len(), 1, "a refused unlink must leave the link in place");
}

/// Another full replica that durably holds every current file makes the
/// unlink allowed -- the real, live counterpart to the count-based unit
/// tests in `control_socket.rs`. A non-empty root set now also requires a
/// live lease from the confirmed target, so device-b records coordination
/// config and device-a grants a lease over the peer wire (`unlink_setup`'s
/// realistic ready state); the unlink then removes the link.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unlink_allowed_when_another_replica_is_ready() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/handoff/lease")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "leaseId": "lease-allowed-1",
            "expiresAt": far_future_expiry(),
            "ttlSeconds": 900,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/handoff/commit")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "targetDeviceId": "device-a",
            "membershipGeneration": 1,
            "leaseId": "lease-allowed-1",
        })))
        .mount(&server)
        .await;

    let (_a, b, socket_path) = unlink_setup(&server, true, true).await;

    let local_path = b.root.path().to_string_lossy().to_string();
    let resp = send_over_socket(
        &socket_path,
        ReqPayload::Unlink(UnlinkRequest {
            local_path,
            force: false,
            expected_group_id: String::new(),
        }),
    )
    .await;
    assert!(
        matches!(resp.payload, Some(RespPayload::Unlink(_))),
        "unlink should succeed once device-a is confirmed to durably hold the group, got {:?}",
        resp.payload
    );

    let resp = send_over_socket(&socket_path, ReqPayload::ListLinks(ListLinksRequest {})).await;
    let Some(RespPayload::ListLinks(list)) = resp.payload else { panic!("wrong response variant") };
    assert!(list.links.is_empty(), "a successful unlink must remove the link");
}

// --- another_full_replica_is_ready_excluding -------------------------------

/// The only replica confirmed ready IS the device about to be revoked/
/// removed -- excluding it from counting as its own handoff target must make
/// this false, even though the plain (non-excluding) check would say true.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exclude_target_readiness_false_when_only_ready_replica_is_the_excluded_device() {
    support::ensure_isolated_config_dir();
    let a = new_daemon("device-a"); // the device about to be revoked/removed
    let b = new_daemon("device-b"); // the device asking the question

    let content = b"file only device-a holds";
    let hash = a.state.block_store.put(content).unwrap();
    let bytes = hex::decode(hash.as_str()).unwrap();
    // Mirrors what `LocalChangeProcessor` does for a real local edit
    // (`record_group_block_provenance`'s doc comment): without this, the
    // real peer-to-peer readiness confirmation this file exercises refuses
    // the block as never having been obtained through the group.
    a.state
        .replica_coordinator
        .record_block_provenance(GROUP, std::slice::from_ref(&bytes))
        .unwrap();
    let record = record_referencing("held.bin", bytes, content.len() as u64);
    a.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    b.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    connect_two_daemons(&a.state, "device-a", &b.state, "device-b", &[GROUP.to_string()]).await;
    b.state.authority.set_peer_group_full_replica("device-a", GROUP, true);
    tokio::time::sleep(Duration::from_millis(500)).await; // let the session establish

    assert!(
        b.state.another_full_replica_is_ready(GROUP).await,
        "sanity check: the plain (non-excluding) query must see device-a as ready"
    );
    assert!(
        !b.state.another_full_replica_is_ready_excluding(GROUP, "device-a").await,
        "device-a is the only ready replica and is also the excluded target, so excluding it \
         must leave no confirmed handoff"
    );
}

/// With a second, distinct full replica also confirmed ready, excluding the
/// device being revoked/removed still finds a valid handoff target.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn exclude_target_readiness_true_when_a_different_replica_is_ready() {
    support::ensure_isolated_config_dir();
    let a = new_daemon("device-a"); // the device about to be revoked/removed
    let c = new_daemon("device-c"); // a different, ready complete copy
    let b = new_daemon("device-b"); // the device asking the question

    let content = b"file both device-a and device-c hold";
    let hash = b.state.block_store.put(content).unwrap();
    let bytes = hex::decode(hash.as_str()).unwrap();
    let record = record_referencing("shared.bin", bytes, content.len() as u64);
    for d in [&a, &b, &c] {
        d.state
            .replica_coordinator
            .file_index_repository()
            .upsert_file(
                GROUP,
                &record,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
    }
    // Give device-a and device-c the actual block too, since each must
    // independently confirm holding it when queried.
    let block_hash = record.blocks[0].hash.clone();
    a.state.block_store.put(content).unwrap();
    a.state
        .replica_coordinator
        .record_block_provenance(GROUP, std::slice::from_ref(&block_hash))
        .unwrap();
    c.state.block_store.put(content).unwrap();
    c.state.replica_coordinator.record_block_provenance(GROUP, &[block_hash]).unwrap();

    connect_two_daemons(&a.state, "device-a", &b.state, "device-b", &[GROUP.to_string()]).await;
    connect_two_daemons(&c.state, "device-c", &b.state, "device-b", &[GROUP.to_string()]).await;
    b.state.authority.set_peer_group_full_replica("device-a", GROUP, true);
    b.state.authority.set_peer_group_full_replica("device-c", GROUP, true);
    tokio::time::sleep(Duration::from_millis(500)).await; // let the sessions establish

    assert!(
        b.state.another_full_replica_is_ready_excluding(GROUP, "device-a").await,
        "device-c is a distinct, ready complete copy, so excluding device-a must still find a \
         valid handoff target"
    );
}

// --- unlink: the mandatory handoff lease (non-empty root set) -------------

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
) -> (Daemon, Daemon, std::path::PathBuf) {
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

    let socket_path = b.root.path().join("daemon.sock");
    let serve_path = socket_path.clone();
    let serve_state = b.state.clone();
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
    (a, b, socket_path)
}

/// Normal handoff: device-b obtains a live lease from the confirmed target
/// (device-a) over the peer wire, presents it to the role-loss commit, and
/// the unlink succeeds -- proving the lease was actually requested and
/// presented, not merely looked up best-effort.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unlink_obtains_and_presents_a_lease_from_the_confirmed_target() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/handoff/lease")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "leaseId": "lease-unlink-1",
            "expiresAt": far_future_expiry(),
            "ttlSeconds": 900,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/handoff/commit")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "targetDeviceId": "device-a",
            "membershipGeneration": 1,
            "leaseId": "lease-unlink-1",
        })))
        .mount(&server)
        .await;

    let (_a, b, socket_path) = unlink_setup(&server, true, true).await;

    let local_path = b.root.path().to_string_lossy().to_string();
    let resp = send_over_socket(
        &socket_path,
        ReqPayload::Unlink(UnlinkRequest {
            local_path,
            force: false,
            expected_group_id: String::new(),
        }),
    )
    .await;
    assert!(
        matches!(resp.payload, Some(RespPayload::Unlink(_))),
        "unlink must succeed once a live lease is obtained and presented, got {:?}",
        resp.payload
    );

    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests.iter().filter(|r| r.url.path().ends_with("/handoff/lease")).count(),
        1,
        "the source must actually request a lease from the confirmed target peer"
    );
    let commit_body: serde_json::Value = requests
        .iter()
        .find(|r| r.url.path().ends_with("/handoff/commit"))
        .unwrap()
        .body_json()
        .unwrap();
    assert_eq!(commit_body["leaseId"], "lease-unlink-1");
}

/// A successful Worker commit with an unreadable response is not a definite
/// unlink failure. Keep the journal (here observable after the immediate
/// compensation is deliberately rejected) so the periodic sweep can restore
/// Worker state instead of leaving Worker=on-demand/local=eager silently.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ambiguous_unlink_keeps_prepared_journal() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/handoff/lease")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "leaseId": "lease-unlink-ambiguous",
            "expiresAt": far_future_expiry(),
            "ttlSeconds": 900,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/handoff/commit")))
        .respond_with(ResponseTemplate::new(200).set_body_string("response lost after commit"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/storage-mode")))
        .respond_with(ResponseTemplate::new(503).set_body_string("retry later"))
        .mount(&server)
        .await;

    let (_a, b, socket_path) = unlink_setup(&server, true, true).await;
    let local_path = b.root.path().to_string_lossy().to_string();
    let resp = send_over_socket(
        &socket_path,
        ReqPayload::Unlink(UnlinkRequest {
            local_path,
            force: false,
            expected_group_id: String::new(),
        }),
    )
    .await;

    assert!(matches!(resp.payload, Some(RespPayload::CommandError(_))));
    let rows = b
        .state
        .replica_coordinator
        .role_loss_operation_repository()
        .list_role_loss_operations_in_states(&[
            RoleLossOperationState::Prepared,
            RoleLossOperationState::Compensating,
        ])
        .unwrap();
    assert_eq!(rows.len(), 1, "ambiguous unlink must retain its recovery journal");
    assert_eq!(rows[0].state, RoleLossOperationState::Compensating);

    let resp = send_over_socket(&socket_path, ReqPayload::ListLinks(ListLinksRequest {})).await;
    let Some(RespPayload::ListLinks(list)) = resp.payload else { panic!("wrong response variant") };
    assert_eq!(list.links.len(), 1, "ambiguous unlink must not remove the local link");
}

/// MANDATORY fail-closed, no `--force`: device-a has no coordination-plane
/// config, so it can never grant a lease. The unlink must be refused exactly
/// like an unconfirmed peer -- the role-loss commit is never attempted, and
/// the link stays in place.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unlink_refused_when_no_lease_obtainable_without_force() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/handoff/commit")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "targetDeviceId": "device-a",
            "membershipGeneration": 1,
            "leaseId": null,
        })))
        .mount(&server)
        .await;

    // Source has config; `configure_target_coordination = false`: device-a can
    // never grant a lease.
    let (_a, b, socket_path) = unlink_setup(&server, true, false).await;

    let local_path = b.root.path().to_string_lossy().to_string();
    let resp = send_over_socket(
        &socket_path,
        ReqPayload::Unlink(UnlinkRequest {
            local_path,
            force: false,
            expected_group_id: String::new(),
        }),
    )
    .await;
    assert!(
        matches!(resp.payload, Some(RespPayload::CommandError(_))),
        "a non-empty-root-set unlink with no obtainable lease and no --force must be refused, \
         got {:?}",
        resp.payload
    );

    let resp = send_over_socket(&socket_path, ReqPayload::ListLinks(ListLinksRequest {})).await;
    let Some(RespPayload::ListLinks(list)) = resp.payload else { panic!("wrong response variant") };
    assert_eq!(list.links.len(), 1, "a refused unlink must leave the link in place");

    let requests = server.received_requests().await.unwrap();
    assert!(
        !requests.iter().any(|r| r.url.path().ends_with("/handoff/commit")),
        "the role-loss commit must never even be attempted without a mandatory lease"
    );
}

/// `--force` still overrides the missing-lease refusal: the unlink proceeds
/// anyway, latching this device's own view of the group to
/// `Unknown` -- matching the pre-existing forced-unlink behavior
/// unchanged by the mandatory-lease requirement (which governs the
/// non-forced path only).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unlink_force_proceeds_without_a_lease_and_latches_durability_unknown() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/handoff/commit")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "targetDeviceId": "device-a",
            "membershipGeneration": 1,
            "leaseId": null,
        })))
        .mount(&server)
        .await;

    let (_a, b, socket_path) = unlink_setup(&server, true, false).await;
    // `Protected` requires a fresh peer-confirmed custody check
    // (`DurabilityConfirmationJob`'s sweep, normally run periodically in
    // the background) rather than this device's own local materialization
    // state alone -- force one round synchronously so the sanity check
    // below doesn't race the background sweep's own cadence.
    b.state.refresh_custody_confirmation(GROUP).await;
    assert_eq!(
        b.state.group_durability_status(GROUP),
        GroupDurabilityStatus::Protected,
        "sanity check: before the forced unlink, the group must not already read Unknown"
    );

    let local_path = b.root.path().to_string_lossy().to_string();
    let resp = send_over_socket(
        &socket_path,
        ReqPayload::Unlink(UnlinkRequest {
            local_path,
            force: true,
            expected_group_id: String::new(),
        }),
    )
    .await;
    assert!(
        matches!(resp.payload, Some(RespPayload::Unlink(_))),
        "a forced unlink must proceed even with no obtainable lease, got {:?}",
        resp.payload
    );
    assert_eq!(
        b.state.group_durability_status(GROUP),
        GroupDurabilityStatus::Unknown,
        "a forced unlink with no confirmed lease must latch this device's own view of the \
         group to Unknown"
    );

    let requests = server.received_requests().await.unwrap();
    assert!(
        !requests.iter().any(|r| r.url.path().ends_with("/handoff/commit")),
        "a forced unlink with no lease obtained never even attempts the role-loss commit"
    );
}

/// MANDATORY-lease fail-closed, the `(Some(target), None-config)` arm: the
/// UNLINKING device (device-b) has a confirmed ready target peer -- a
/// non-empty root set -- but NO coordination-plane config recorded. A
/// non-empty root set now mandates a live lease, unobtainable with no
/// config, so a non-forced unlink must be refused (not fall through to a
/// local-only link removal), leaving the link in place and never committing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unlink_refused_when_a_target_is_confirmed_but_this_device_has_no_config() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/handoff/commit")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "targetDeviceId": "device-a",
            "membershipGeneration": 1,
            "leaseId": null,
        })))
        .mount(&server)
        .await;

    // `configure_source_coordination = false`: device-b (the unlinking
    // device) records no coordination config, so the (confirmed target,
    // no source config) arm is exercised.
    let (_a, b, socket_path) = unlink_setup(&server, false, false).await;

    let local_path = b.root.path().to_string_lossy().to_string();
    let resp = send_over_socket(
        &socket_path,
        ReqPayload::Unlink(UnlinkRequest {
            local_path,
            force: false,
            expected_group_id: String::new(),
        }),
    )
    .await;
    assert!(
        matches!(resp.payload, Some(RespPayload::CommandError(_))),
        "an unlink with a confirmed target but no coordination config must fail closed \
         (non-empty root set mandates a lease that cannot be obtained here), got {:?}",
        resp.payload
    );

    let resp = send_over_socket(&socket_path, ReqPayload::ListLinks(ListLinksRequest {})).await;
    let Some(RespPayload::ListLinks(list)) = resp.payload else { panic!("wrong response variant") };
    assert_eq!(
        list.links.len(),
        1,
        "a fail-closed (no-config) unlink must leave the link in place"
    );

    let requests = server.received_requests().await.unwrap();
    assert!(
        !requests.iter().any(|r| r.url.path().ends_with("/handoff/commit")),
        "no role-loss commit may be attempted without coordination config or a lease"
    );
}

/// `--force` still overrides the missing-config refusal for the same
/// `(Some(target), None-config)` arm: a forced unlink proceeds and latches
/// `Unknown`, proving the new production fail-closed refusal does
/// not swallow the `--force` path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unlink_force_proceeds_without_config_and_latches_durability_unknown() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/handoff/commit")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "targetDeviceId": "device-a",
            "membershipGeneration": 1,
            "leaseId": null,
        })))
        .mount(&server)
        .await;

    let (_a, b, socket_path) = unlink_setup(&server, false, false).await;
    // See the identical comment in
    // `unlink_force_proceeds_without_a_lease_and_latches_durability_unknown`.
    b.state.refresh_custody_confirmation(GROUP).await;
    assert_eq!(
        b.state.group_durability_status(GROUP),
        GroupDurabilityStatus::Protected,
        "sanity check: before the forced unlink, the group must not already read Unknown"
    );

    let local_path = b.root.path().to_string_lossy().to_string();
    let resp = send_over_socket(
        &socket_path,
        ReqPayload::Unlink(UnlinkRequest {
            local_path,
            force: true,
            expected_group_id: String::new(),
        }),
    )
    .await;
    assert!(
        matches!(resp.payload, Some(RespPayload::Unlink(_))),
        "a forced unlink must proceed even with no coordination config, got {:?}",
        resp.payload
    );
    assert_eq!(
        b.state.group_durability_status(GROUP),
        GroupDurabilityStatus::Unknown,
        "a forced unlink with no config/lease must latch this device's view to Unknown"
    );

    let requests = server.received_requests().await.unwrap();
    assert!(
        !requests.iter().any(|r| r.url.path().ends_with("/handoff/commit")),
        "a forced unlink with no config never attempts the role-loss commit"
    );
}
