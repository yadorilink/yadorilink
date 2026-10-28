//! Daemon-orchestrated `yadorilink share set-storage-mode`: the daemon
//! (`control_socket::set_storage_mode`) is now the SOLE writer of the
//! coordination-plane storage-mode record for both directions -- the CLI no
//! longer makes a direct Worker call, and there is nothing left for it to
//! compensate. Exercised over the real control socket, mirroring
//! `unlink_and_removal_durability.rs`'s own integration style, against a
//! `wiremock` stand-in for the coordination service.
//!
//! Covers:
//!   - a DEMOTION writes the coordination plane exactly once, through the
//!     role-loss commit (`POST .../handoff/commit`), and never touches the
//!     plain `.../storage-mode` route -- the double-write this change fixes.
//!   - the demotion's ordering is Worker-commit-then-local-flip: a refused
//!     Worker commit leaves the local policy untouched (still Eager), which
//!     is the crash-safe direction (see `control_socket::set_storage_mode`'s
//!     doc comment).
//!   - a PROMOTION now writes the coordination plane itself
//!     (`POST .../storage-mode`) -- the write the CLI used to make directly,
//!     relocated here so it is not simply dropped -- with the same
//!     Worker-write-then-local-flip ordering and the same crash-safety
//!     property on a refused write.
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
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    DaemonControlRequest, DaemonControlResponse, SetStorageModeRequest,
};
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
use yadorilink_replica_domain::session_state::MaterializationPolicy;

const GROUP: &str = "storage-mode-group";

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

fn record_referencing(path_str: &str, hash_bytes: Vec<u8>, size: u64) -> FileRecord {
    FileRecord {
        path: path_str.to_string(),
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

/// Starts the real control socket for `daemon` and returns its path, letting
/// the request-handling loop the CLI actually talks to run this test's
/// requests, not a stand-in.
async fn serve(state: Arc<DaemonState>, root: &std::path::Path) -> std::path::PathBuf {
    let socket_path = root.join("daemon.sock");
    let serve_path = socket_path.clone();
    tokio::spawn(async move {
        let _ = yadorilink_daemon::control_socket::unix_transport::serve(
            &serve_path,
            std::sync::Arc::new(yadorilink_daemon::control_context::ControlContext::from_state(
                state,
            )),
        )
        .await;
    });
    yadorilink_daemon::control_socket::unix_transport::wait_until_bound(&socket_path).await;
    socket_path
}

fn policy_of(state: &DaemonState, group_id: &str) -> MaterializationPolicy {
    state
        .replica_coordinator
        .link_repository()
        .materialization_policy_for_group(group_id)
        .unwrap()
        .unwrap()
}

/// Counts requests the mock coordination plane received matching `method`
/// and a path ending in `suffix` (e.g. `"/storage-mode"` or
/// `"/handoff/commit"`) -- reading straight off `MockServer::received_requests`
/// rather than a per-mock `.expect(n)` so a single test can assert the exact
/// split across two different routes in one place.
async fn request_count(server: &MockServer, method_name: &str, suffix: &str) -> usize {
    server
        .received_requests()
        .await
        .expect("request recording must be enabled")
        .iter()
        .filter(|r| {
            r.method.as_str().eq_ignore_ascii_case(method_name) && r.url.path().ends_with(suffix)
        })
        .count()
}

// --- DEMOTION: exactly one Worker write, via the role-loss commit ---------

/// Sets up device-b as an eager full replica with device-a confirmed ready to
/// take over (mirrors `full_replica_handoff_ready.rs`'s own
/// `ready_when_another_replica_holds_every_file`), then points device-b's
/// coordination-plane config at a mock Worker before demoting. The mandatory
/// lease request is now also two-sided over the peer wire: device-a is
/// marked a full replica from device-b's point of view (so device-b's own
/// readiness check finds it) AND device-b is marked a full replica from
/// device-a's point of view (so device-a's own target-side readiness
/// self-check -- "does some other peer confirm I hold everything I hold" --
/// also succeeds when device-a answers device-b's `HandoffLeaseRequest`).
/// Whether device-a's own coordination-plane config is ALSO set (letting it
/// actually obtain a lease from the mocked Worker) is left to each caller via
/// `configure_target_coordination`, since the mandatory-fail-closed tests
/// deliberately leave it unset.
async fn demoting_setup(
    server: &MockServer,
    configure_target_coordination: bool,
) -> (Daemon, Daemon, std::path::PathBuf) {
    support::ensure_isolated_config_dir();
    let a = new_daemon("device-a"); // complete copy: durably holds every block
    let b = new_daemon("device-b"); // eager device asking to demote
                                    // Every test in this file exercises the demotion orchestration itself,
                                    // not the on-demand pipeline's own real-vs-fake state -- see
                                    // `role_loss_saga.rs`'s identical `demoting_setup` override for why a
                                    // daemon integration test needs this instead of the production probe
                                    // (unconditionally `false`) or a thread-local override.
    b.state.set_test_on_demand_allowed(true);

    let content = b"the file device-a confirms holding";
    let hash = a.state.block_store.put(content).unwrap();
    a.state
        .replica_coordinator
        .record_block_provenance(GROUP, &[hex::decode(hash.as_str()).unwrap()])
        .unwrap();
    b.state.block_store.put(content).unwrap();
    let bytes = hex::decode(hash.as_str()).unwrap();
    // Device-b is the confirmed-ready target's OWN peer: device-a's mandatory
    // lease issuance (`DaemonState::request_handoff_lease`) re-verifies ITS
    // OWN readiness by querying device-b to confirm device-b durably holds
    // this file (`peer_holds_entire_group` -> `holds_version_durably`, which
    // requires group block provenance on the ANSWERING side, not just the
    // asker's) -- without this, device-a's own readiness check fails and no
    // lease is ever issued, regardless of the mocked Worker endpoint below.
    b.state
        .replica_coordinator
        .record_block_provenance(GROUP, std::slice::from_ref(&bytes))
        .unwrap();
    let record = record_referencing("only.bin", bytes, content.len() as u64);
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

    // Must win the race against `connect_two_daemons`'s own coordination-
    // plane wiring below: `coordination_client_config` is a set-once
    // `OnceLock` (production semantics), so whichever caller sets it FIRST
    // wins for the rest of the process -- this test needs its devices
    // pointed at THIS `server`, not `connect_two_daemons`'s own in-process
    // checkpoint-issuance fake.
    b.state.set_coordination_client_config(
        server.uri(),
        yadorilink_fapi_client::test_support::offline_auth(),
    );
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

    let socket_path = serve(b.state.clone(), b.root.path()).await;
    (a, b, socket_path)
}

fn far_future_expiry() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
        + 900
}

/// Mounts the target-side (device-a) lease-issuance endpoint the mandatory
/// lease request now depends on: device-a's own `DaemonState::request_
/// handoff_lease` calls this exactly like the pre-existing target-side flow
/// always has (the already-atomic local verify+pin behind it is unchanged by
/// this), granting a real lease id device-b then presents to
/// `/handoff/commit`.
async fn mount_target_lease_issuance(server: &MockServer, lease_id: &str) {
    let lease_id = lease_id.to_string();
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/handoff/lease")))
        .respond_with(move |_req: &wiremock::Request| {
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "leaseId": lease_id,
                "expiresAt": far_future_expiry(),
                "ttlSeconds": 900,
            }))
        })
        .mount(server)
        .await;
}

/// A successful demotion obtains a live lease from the confirmed target
/// peer over the peer wire (mandatory for this non-empty root set), presents
/// it to the role-loss commit, and writes the coordination plane exactly
/// once (the role-loss commit) -- never touching the plain storage-mode
/// route at all. Also asserts the presented `leaseId` is the real one the
/// target obtained, i.e. the lease was actually requested from the peer and
/// presented, not fabricated or skipped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn demotion_writes_the_worker_exactly_once_via_role_loss_commit() {
    let server = MockServer::start().await;
    mount_target_lease_issuance(&server, "lease-from-device-a").await;
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/handoff/commit")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "targetDeviceId": "device-a",
            "membershipGeneration": 1,
            "leaseId": "lease-from-device-a",
        })))
        .mount(&server)
        .await;

    let (_a, b, socket_path) = demoting_setup(&server, true).await;

    let resp = send_over_socket(
        &socket_path,
        ReqPayload::SetStorageMode(SetStorageModeRequest {
            group_id: GROUP.to_string(),
            on_demand: true,
        }),
    )
    .await;
    assert!(
        matches!(resp.payload, Some(RespPayload::SetStorageMode(_))),
        "a ready demotion with a successful role-loss commit must succeed, got {:?}",
        resp.payload
    );
    assert_eq!(
        policy_of(&b.state, GROUP),
        MaterializationPolicy::OnDemand,
        "a successful demotion must flip the local policy to on-demand"
    );

    assert_eq!(
        request_count(&server, "POST", "/handoff/commit").await,
        1,
        "a demotion's single coordination-plane write must be the role-loss commit"
    );
    assert_eq!(
        request_count(&server, "POST", "/storage-mode").await,
        0,
        "a demotion must never call the plain storage-mode route -- that write belongs entirely \
         to the role-loss commit, so calling both would double-write storage_mode"
    );

    // The lease was actually requested from the peer (device-a's own Worker
    // lease-issuance endpoint was called) and the SAME lease id was
    // presented to the commit -- not fabricated, not skipped.
    assert_eq!(
        request_count(&server, "POST", "/handoff/lease").await,
        1,
        "the source must actually request a lease from the confirmed target peer"
    );
    let commit_requests = server.received_requests().await.unwrap();
    let commit_body: serde_json::Value = commit_requests
        .iter()
        .find(|r| r.url.path().ends_with("/handoff/commit"))
        .unwrap()
        .body_json()
        .unwrap();
    assert_eq!(commit_body["leaseId"], "lease-from-device-a");

    // INV-4: neither Worker call in this flow ever carries a digest, path, or
    // version identity -- only opaque ids/strings.
    for req in &commit_requests {
        let body: serde_json::Value = match req.body_json() {
            Ok(b) => b,
            Err(_) => continue,
        };
        let dump = body.to_string().to_lowercase();
        assert!(
            !dump.contains("digest")
                && !dump.contains("root_digest")
                && !dump.contains("rootdigest"),
            "no coordination-plane request may ever carry a durability-root digest: {dump}"
        );
    }
}

/// Ordering/crash-safety: when the Worker refuses the role-loss commit, the
/// local materialization policy must stay untouched (still Eager) -- proving
/// the commit happens BEFORE the local flip, not after. Committing the local
/// demotion first (or regardless of the commit's outcome) would let this
/// device release its only durable copy before the handoff is ever recorded
/// coordination-side. A live lease IS obtained first (mandatory), so this
/// exercises the commit-refused path specifically, not the lease-refused one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn demotion_refused_by_the_worker_leaves_local_policy_untouched() {
    let server = MockServer::start().await;
    mount_target_lease_issuance(&server, "lease-from-device-a").await;
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/handoff/commit")))
        .respond_with(ResponseTemplate::new(409).set_body_string("target is no longer eager"))
        .mount(&server)
        .await;

    let (_a, b, socket_path) = demoting_setup(&server, true).await;

    let resp = send_over_socket(
        &socket_path,
        ReqPayload::SetStorageMode(SetStorageModeRequest {
            group_id: GROUP.to_string(),
            on_demand: true,
        }),
    )
    .await;
    assert!(
        support::control_socket_client::refusal_message(&resp.payload).is_some(),
        "a refused role-loss commit must fail the demotion, got {:?}",
        resp.payload
    );
    assert_eq!(
        policy_of(&b.state, GROUP),
        MaterializationPolicy::Eager,
        "a refused Worker commit must leave this device's local policy untouched -- it must \
         still be the group's confirmed complete copy"
    );
    assert_eq!(
        request_count(&server, "POST", "/storage-mode").await,
        0,
        "a demotion must never call the plain storage-mode route, refused or not"
    );
}

/// MANDATORY-lease fail-closed: device-a (the confirmed target) has no
/// coordination-plane config recorded at all, so its own target-side
/// `request_handoff_lease` can never obtain a Worker-issued lease no matter
/// how the rest of the readiness check goes -- device-b's source-side
/// `obtain_handoff_lease_from_peer` gets back `granted = false` over the
/// real peer wire, and the demotion must refuse outright: no role-loss
/// commit is ever attempted (there is nothing to commit without a lease for
/// this non-empty root set), and the local policy stays untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn demotion_refused_when_the_target_cannot_grant_a_lease() {
    let server = MockServer::start().await;
    // Mounted only so the test can assert it is NEVER called -- the source
    // must not even attempt the commit without a lease.
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/handoff/commit")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "targetDeviceId": "device-a",
            "membershipGeneration": 1,
            "leaseId": null,
        })))
        .mount(&server)
        .await;

    // `configure_target_coordination = false`: device-a never gets a
    // coordination-plane config, so it can never grant a lease.
    let (_a, b, socket_path) = demoting_setup(&server, false).await;

    let resp = send_over_socket(
        &socket_path,
        ReqPayload::SetStorageMode(SetStorageModeRequest {
            group_id: GROUP.to_string(),
            on_demand: true,
        }),
    )
    .await;
    assert!(
        support::control_socket_client::refusal_message(&resp.payload).is_some(),
        "a non-empty-root-set demotion with no obtainable lease must be refused, got {:?}",
        resp.payload
    );
    assert_eq!(
        policy_of(&b.state, GROUP),
        MaterializationPolicy::Eager,
        "a refused (lease-less) demotion must leave the local policy untouched"
    );
    assert_eq!(
        request_count(&server, "POST", "/handoff/commit").await,
        0,
        "the role-loss commit must never even be attempted without a mandatory lease"
    );
}

/// MANDATORY-lease fail-closed, the `(Some(target), None-config)` arm: the
/// DEMOTING device (device-b) itself has a confirmed ready target peer -- a
/// non-empty root set -- but NO coordination-plane config recorded at all.
/// A non-empty root set now mandates a live lease, and with no config there
/// is no way to obtain or commit one, so the demotion must fail closed
/// rather than relinquish the role lease-less. This encodes the guarantee
/// for the arm that would otherwise fall through to a local-only policy flip.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn demotion_refused_when_a_target_is_confirmed_but_this_device_has_no_config() {
    support::ensure_isolated_config_dir();
    let server = MockServer::start().await;
    // Mounted only to assert it is NEVER called: with no config the daemon
    // cannot even reach the plane, and the role-loss commit is never
    // attempted regardless.
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/handoff/commit")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "targetDeviceId": "device-a",
            "membershipGeneration": 1,
            "leaseId": null,
        })))
        .mount(&server)
        .await;

    // Wire a confirmed ready peer for device-b exactly like `demoting_setup`,
    // but deliberately do NOT record any coordination-plane config on
    // device-b -- the (Some(target), None) arm under test.
    let a = new_daemon("device-a");
    let b = new_daemon("device-b");
    // Past the on-demand availability refusal, so the request reaches the lease arm under test.
    b.state.set_test_on_demand_allowed(true);
    let content = b"the file device-a confirms holding";
    let hash = a.state.block_store.put(content).unwrap();
    a.state
        .replica_coordinator
        .record_block_provenance(GROUP, &[hex::decode(hash.as_str()).unwrap()])
        .unwrap();
    let bytes = hex::decode(hash.as_str()).unwrap();
    let record = record_referencing("only.bin", bytes, content.len() as u64);
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
    tokio::time::sleep(Duration::from_millis(500)).await;
    let socket_path = serve(b.state.clone(), b.root.path()).await;

    let resp = send_over_socket(
        &socket_path,
        ReqPayload::SetStorageMode(SetStorageModeRequest {
            group_id: GROUP.to_string(),
            on_demand: true,
        }),
    )
    .await;
    assert!(
        support::control_socket_client::refusal_message(&resp.payload).is_some(),
        "a demotion with a confirmed target but no coordination config must fail closed \
         (non-empty root set mandates a lease that cannot be obtained here), got {:?}",
        resp.payload
    );
    assert_eq!(
        policy_of(&b.state, GROUP),
        MaterializationPolicy::Eager,
        "a fail-closed (no-config) demotion must leave the local policy untouched"
    );
    assert_eq!(
        request_count(&server, "POST", "/handoff/commit").await,
        0,
        "no role-loss commit may be attempted without coordination config or a lease"
    );
}

/// EMPTY root set: a group with no files at all is vacuously ready (no
/// confirming peer is ever named), so no lease is required and the demotion
/// proceeds exactly as before this change -- device-a is not even given a
/// chance to grant or refuse anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn demotion_of_an_empty_group_needs_no_lease() {
    support::ensure_isolated_config_dir();
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
    // No `/handoff/lease` mock at all -- a call to it would panic wiremock's
    // unmatched-request assertion, proving none is ever made.

    let b = new_daemon("device-b"); // starts Eager, with zero files in GROUP
    b.state.set_test_on_demand_allowed(true);
    b.state.set_coordination_client_config(
        server.uri(),
        yadorilink_fapi_client::test_support::offline_auth(),
    );
    let socket_path = serve(b.state.clone(), b.root.path()).await;

    let resp = send_over_socket(
        &socket_path,
        ReqPayload::SetStorageMode(SetStorageModeRequest {
            group_id: GROUP.to_string(),
            on_demand: true,
        }),
    )
    .await;
    assert!(
        matches!(resp.payload, Some(RespPayload::SetStorageMode(_))),
        "an empty group's demotion needs no lease and must succeed, got {:?}",
        resp.payload
    );
    assert_eq!(policy_of(&b.state, GROUP), MaterializationPolicy::OnDemand);
    assert_eq!(
        request_count(&server, "POST", "/handoff/commit").await,
        0,
        "an empty root set has no confirmed target peer to name, so no role-loss commit is \
         attempted at all -- matching this group's pre-existing vacuous-ready behavior"
    );
}

// --- PROMOTION: the daemon now writes the Worker itself -------------------

fn promoting_setup(server: &MockServer) -> Daemon {
    let b = new_daemon("device-b");
    b.state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy(
            &b.root.path().to_string_lossy(),
            MaterializationPolicy::OnDemand,
        )
        .unwrap();
    b.state.set_coordination_client_config(
        server.uri(),
        yadorilink_fapi_client::test_support::offline_auth(),
    );
    b
}

/// A promotion (on-demand -> eager) has no readiness hazard, but since the
/// CLI no longer writes the coordination-plane storage mode itself, this is
/// now the ONLY place that Worker write happens for a promotion -- the write
/// the CLI used to make directly must not simply be dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn promotion_writes_the_worker_storage_mode_route_itself() {
    support::ensure_isolated_config_dir();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/storage-mode")))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let b = promoting_setup(&server);
    let socket_path = serve(b.state.clone(), b.root.path()).await;

    let resp = send_over_socket(
        &socket_path,
        ReqPayload::SetStorageMode(SetStorageModeRequest {
            group_id: GROUP.to_string(),
            on_demand: false,
        }),
    )
    .await;
    assert!(
        matches!(resp.payload, Some(RespPayload::SetStorageMode(_))),
        "a promotion with a successful Worker write must succeed, got {:?}",
        resp.payload
    );
    assert_eq!(
        policy_of(&b.state, GROUP),
        MaterializationPolicy::Eager,
        "a successful promotion must flip the local policy to eager"
    );

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "expected exactly one Worker call for the promotion");
    let body: serde_json::Value = requests[0].body_json().unwrap();
    assert_eq!(body["deviceId"], "device-b");
    assert_eq!(body["storageMode"], "eager");
}

/// A promotion by a daemon with NO coordination-plane config recorded must
/// fail closed rather than silently skip the Worker write. Skipping it would
/// flip local policy to eager while the coordination plane stays on-demand --
/// a split that would NOT self-heal, since a re-run no-ops once the local
/// mode already matches the target. (This test runs against a real control
/// socket, so config is genuinely absent unless set; here it is never set.)
/// Unlike a demotion, a promotion has no ready-peer gate to
/// fail closed on its own, which is exactly why this direction needs the
/// explicit guard.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn promotion_without_coordination_config_fails_closed_and_leaves_local_untouched() {
    support::ensure_isolated_config_dir();
    // A server only so we can assert it is NEVER called; the daemon is given
    // no config pointing at it, so no request should ever reach it.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/storage-mode")))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let b = new_daemon("device-b");
    b.state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy(
            &b.root.path().to_string_lossy(),
            MaterializationPolicy::OnDemand,
        )
        .unwrap();
    // Deliberately do NOT call set_coordination_client_config: config is None.
    let socket_path = serve(b.state.clone(), b.root.path()).await;

    let resp = send_over_socket(
        &socket_path,
        ReqPayload::SetStorageMode(SetStorageModeRequest {
            group_id: GROUP.to_string(),
            on_demand: false,
        }),
    )
    .await;
    assert!(
        support::control_socket_client::refusal_message(&resp.payload).is_some(),
        "a promotion with no coordination-plane config must fail closed, got {:?}",
        resp.payload
    );
    assert_eq!(
        policy_of(&b.state, GROUP),
        MaterializationPolicy::OnDemand,
        "a failed-closed promotion must not silently flip local policy to eager"
    );
    assert_eq!(
        request_count(&server, "POST", "/storage-mode").await,
        0,
        "no Worker request should be made when the daemon has no coordination-plane config"
    );
}

/// Ordering/crash-safety: when the Worker refuses the promotion's
/// storage-mode write, the local policy must stay untouched (still
/// on-demand) -- the write happens BEFORE the local flip, and its failure
/// aborts before the flip runs. Unlike demotion, the reverse failure
/// direction here (Worker updated, local flip not yet run) would also be
/// safe -- promotion only ever ADDS a durable copy -- but this still proves
/// the actual ordering the daemon uses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn promotion_refused_by_the_worker_leaves_local_policy_untouched() {
    support::ensure_isolated_config_dir();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/storage-mode")))
        .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
        .mount(&server)
        .await;

    let b = promoting_setup(&server);
    let socket_path = serve(b.state.clone(), b.root.path()).await;

    let resp = send_over_socket(
        &socket_path,
        ReqPayload::SetStorageMode(SetStorageModeRequest {
            group_id: GROUP.to_string(),
            on_demand: false,
        }),
    )
    .await;
    assert!(
        support::control_socket_client::refusal_message(&resp.payload).is_some(),
        "a refused Worker storage-mode write must fail the promotion, got {:?}",
        resp.payload
    );
    assert_eq!(
        policy_of(&b.state, GROUP),
        MaterializationPolicy::OnDemand,
        "a refused Worker write must leave this device's local policy untouched"
    );
}
