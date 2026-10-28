//! Covers: - a demotion whose Worker-side commit succeeds but whose local
//! recheck-then-flip afterwards fails (a genuine digest-mismatch race,
//! forced deterministically by racing a concurrent local index write
//! against a deliberately delayed `/handoff/commit` response) is
//! compensated: the daemon reverts the Worker back to `eager`, ends in a
//! consistent state (no split), returns a "safely rolled back" error (not
//! a silent success), and leaves no journal row behind. - a successful
//! demotion still leaves no journal row behind (the normal success path is
//! unchanged, just with a row written-then-deleted around it). - a
//! `WorkerCommitted` journal row present when the reconciliation sweep
//! runs (the crash-between-Worker-commit-and-local-commit case) is
//! compensated and cleared. - a compensation attempt that cannot reach the
//! coordination plane leaves the row at `Compensating` rather than losing
//! it, and a subsequent sweep retries it (attempts accrue, the row
//! survives). - INV-4: the compensating Worker call carries only
//! `(group_id, device_id, storage_mode)` -- never a digest, path, or
//! version.
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
use yadorilink_daemon::control_context::ControlContext;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::maintenance_coordinator::run_role_loss_reconciliation_sweep;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    DaemonControlRequest, DaemonControlResponse, SetStorageModeRequest,
};
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
use yadorilink_replica_domain::session_state::MaterializationPolicy;
use yadorilink_replica_domain::session_state::{
    RoleLossAction, RoleLossOperationParams, RoleLossOperationState,
};

const GROUP: &str = "role-loss-saga-group";

struct Daemon {
    state: Arc<DaemonState>,
    _store_dir: tempfile::TempDir,
    index_dir: tempfile::TempDir,
    root: tempfile::TempDir,
}

impl Daemon {
    /// The on-disk path of this daemon's file-backed sync index -- matches
    /// `support::open_file_backed_replica_coordinator`'s own `dir.join("index.db")`.
    /// Used only by the fail-closed test, which opens an independent
    /// connection here to drop a table out from under an in-flight operation.
    fn index_db_path(&self) -> std::path::PathBuf {
        self.index_dir.path().join("index.db")
    }
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
    Daemon { state, _store_dir: store_dir, index_dir, root }
}

fn record_referencing(path_str: &str, _device: &str, hash_bytes: Vec<u8>, size: u64) -> FileRecord {
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

fn far_future_expiry() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
        + 900
}

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

/// Same shape as `storage_mode_orchestration.rs`'s own `demoting_setup`: wires
/// device-a as a confirmed-ready full-replica target and device-b as the
/// eager device about to demote, both sides of the mandatory peer-to-peer
/// lease request live.
async fn demoting_setup(server: &MockServer) -> (Daemon, Daemon, std::path::PathBuf) {
    support::ensure_isolated_config_dir();
    let a = new_daemon("device-a");
    let b = new_daemon("device-b");
    // Every test in this file exercises the demotion saga itself (journal
    // write/settle/compensate ordering) -- none of them are about the
    // on-demand pipeline's own real-vs-fake state, so unconditionally
    // connect the fake here rather than per test. See `DaemonState::
    // set_test_on_demand_allowed`'s own doc comment for why a
    // daemon integration test needs this instead of the production probe
    // (unconditionally `false`) or the free function's thread-local
    // a thread-local override (unreliable across this multi-threaded runtime).
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
    let record = record_referencing("only.bin", "device-b", bytes, content.len() as u64);
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
    // wins for the rest of the process -- this test needs both devices
    // pointed at THIS `server`, not `connect_two_daemons`'s own in-process
    // checkpoint-issuance fake.
    b.state.set_coordination_client_config(
        server.uri(),
        yadorilink_fapi_client::test_support::offline_auth(),
    );
    a.state.set_coordination_client_config(
        server.uri(),
        yadorilink_fapi_client::test_support::offline_auth(),
    );

    connect_two_daemons(&a.state, "device-a", &b.state, "device-b", &[GROUP.to_string()]).await;
    b.state.authority.set_peer_group_full_replica("device-a", GROUP, true);
    a.state.authority.set_peer_group_full_replica("device-b", GROUP, true);
    tokio::time::sleep(Duration::from_millis(500)).await;

    let socket_path = serve(b.state.clone(), b.root.path()).await;
    (a, b, socket_path)
}

/// Every role-loss-operation row currently recorded for `state`, in any
/// state -- the full journal-table dump this file's assertions read.
fn all_role_loss_operations(
    state: &DaemonState,
) -> Vec<yadorilink_replica_domain::session_state::RoleLossOperation> {
    state
        .replica_coordinator
        .role_loss_operation_repository()
        .list_role_loss_operations_in_states(&[
            RoleLossOperationState::Prepared,
            RoleLossOperationState::WorkerCommitted,
            RoleLossOperationState::LocalCommitted,
            RoleLossOperationState::Compensating,
            RoleLossOperationState::Completed,
        ])
        .unwrap()
}

// --- Normal success path: journal written then deleted ---------------------

/// A demotion that fully succeeds must behave identically to before this
/// journal existed -- and must leave no journal row behind once it does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn successful_demote_leaves_no_role_loss_operation_journal_row() {
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

    let (_a, b, socket_path) = demoting_setup(&server).await;

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
    assert_eq!(policy_of(&b.state, GROUP), MaterializationPolicy::OnDemand);
    assert!(
        all_role_loss_operations(&b.state).is_empty(),
        "a fully-successful demotion must leave no role-loss-operation journal row behind"
    );
}

// --- Fail-closed Prepared write: no journal -> no Worker commit ------------

/// FAIL-CLOSED: if the durable `Prepared` journal row cannot be persisted,
/// the daemon must NOT go on to commit the role loss on the Worker -- doing
/// so would reopen the exact split-state hole (Worker on-demand / local
/// eager, with no durable record to drive a retry) the journal exists to
/// close. Forces a genuine journal-insert storage error by dropping the
/// `role_loss_operations` table out from under device-b's file-backed index
/// (the same fault-injection trick `daemon_state.rs`'s handoff-lease tests
/// use), then asserts the role-loss commit is NEVER attempted and the local
/// policy stays Eager -- no split, just a clean refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn demote_fails_closed_when_the_prepared_journal_write_fails() {
    let server = MockServer::start().await;
    mount_target_lease_issuance(&server, "lease-from-device-a").await;
    // Mounted only so the test can assert it is NEVER called: without a
    // durable journal row, the commit must not even be attempted.
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/handoff/commit")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "targetDeviceId": "device-a",
            "membershipGeneration": 1,
            "leaseId": "lease-from-device-a",
        })))
        .mount(&server)
        .await;

    let (_a, b, socket_path) = demoting_setup(&server).await;

    // Drop the journal table via an independent connection to the same file,
    // so device-b's own `insert_role_loss_operation` -- which runs BEFORE the
    // Worker commit -- hits a genuine "no such table" storage error. `files`
    // and `links` are untouched, so everything up to the Prepared write still
    // behaves exactly as in the success path; only the journal insert fails.
    {
        let conn = rusqlite::Connection::open(b.index_db_path()).unwrap();
        conn.execute("DROP TABLE role_loss_operations", []).unwrap();
    }

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
        "a demotion whose durable journal write fails must be refused, got {:?}",
        resp.payload
    );
    assert_eq!(
        policy_of(&b.state, GROUP),
        MaterializationPolicy::Eager,
        "a fail-closed (no-journal) demotion must leave the local policy untouched -- no split"
    );
    assert_eq!(
        request_count(&server, "POST", "/handoff/commit").await,
        0,
        "the role-loss commit must NEVER be attempted without a durable journal row -- \
         committing on the Worker without it is the split the journal exists to prevent"
    );
    assert_eq!(
        request_count(&server, "POST", "/storage-mode").await,
        0,
        "nothing was committed on the Worker, so there is nothing to compensate either"
    );
}

// --- Post-Worker-commit local failure: compensated, not split --------------

/// A 2xx means the Worker committed, even when the response body is lost or
/// corrupted before the client can decode it. The daemon must not discard the
/// Prepared journal as if the transaction had definitely failed. This mock
/// returns an invalid success body, then makes the immediate compensation
/// fail so the retained row is directly observable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ambiguous_demote_keeps_prepared_journal() {
    let server = MockServer::start().await;
    mount_target_lease_issuance(&server, "lease-from-device-a").await;
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/handoff/commit")))
        .respond_with(ResponseTemplate::new(200).set_body_string("response lost after commit"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/handoff/compensate")))
        .respond_with(ResponseTemplate::new(503).set_body_string("retry compensation later"))
        .mount(&server)
        .await;

    let (_a, b, socket_path) = demoting_setup(&server).await;
    let resp = send_over_socket(
        &socket_path,
        ReqPayload::SetStorageMode(SetStorageModeRequest {
            group_id: GROUP.to_string(),
            on_demand: true,
        }),
    )
    .await;

    assert!(support::control_socket_client::refusal_message(&resp.payload).is_some());
    assert_eq!(policy_of(&b.state, GROUP), MaterializationPolicy::Eager);
    let rows = all_role_loss_operations(&b.state);
    assert_eq!(rows.len(), 1, "an ambiguous commit must retain its recovery journal");
    assert_eq!(rows[0].state, RoleLossOperationState::Compensating);
    assert!(
        request_count(&server, "POST", "/handoff/compensate").await >= 1,
        "an ambiguous commit should attempt an immediate safe revert"
    );
}

/// An explicit 4xx is the only protocol outcome that guarantees the Worker
/// rejected before committing. That terminal rejection may discard Prepared
/// without issuing a compensating eager write. 400, not 409: 409 CONFLICT is
/// its own distinct `RoleLossCommitOutcome::Conflict` outcome
/// (`coordination_client::commit_handoff_role_loss`'s own status-code
/// classification) -- an operation-id collision the daemon deliberately
/// leaves untouched for operator attention, not the definite-rejection path
/// this test means to exercise.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn definite_4xx_discards_prepared_journal() {
    let server = MockServer::start().await;
    mount_target_lease_issuance(&server, "lease-from-device-a").await;
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/handoff/commit")))
        .respond_with(ResponseTemplate::new(400).set_body_string("lease no longer valid"))
        .mount(&server)
        .await;

    let (_a, b, socket_path) = demoting_setup(&server).await;
    let resp = send_over_socket(
        &socket_path,
        ReqPayload::SetStorageMode(SetStorageModeRequest {
            group_id: GROUP.to_string(),
            on_demand: true,
        }),
    )
    .await;

    assert!(support::control_socket_client::refusal_message(&resp.payload).is_some());
    assert!(all_role_loss_operations(&b.state).is_empty());
    assert_eq!(request_count(&server, "POST", "/storage-mode").await, 0);
}

/// Forces the exact split-state hazard the journal exists to close: the
/// Worker-side role-loss commit succeeds, but this device's own durability
/// root set changes (a genuinely concurrent local write) before the atomic
/// local recheck-then-flip runs, so that recheck fails closed with a digest
/// mismatch (`Ok(false)`) -- *after* the Worker already committed the role
/// loss. Deterministic, not a flaky race: the mock `/handoff/commit`
/// response is deliberately delayed, giving a concurrent task a wide,
/// reliable window to land the conflicting local write while the commit is
/// still in flight.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn demote_local_failure_after_worker_commit_is_compensated_and_rolled_back() {
    let server = MockServer::start().await;
    mount_target_lease_issuance(&server, "lease-from-device-a").await;
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/handoff/commit")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "targetDeviceId": "device-a",
                    "membershipGeneration": 1,
                    "leaseId": "lease-from-device-a",
                }))
                .set_delay(Duration::from_millis(400)),
        )
        .mount(&server)
        .await;
    // The compensating revert: reverting device-b's storage mode back to
    // `eager` after the local recheck fails.
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/handoff/compensate")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"status": "restored"})),
        )
        .mount(&server)
        .await;

    let (_a, b, socket_path) = demoting_setup(&server).await;

    // Concurrently, while the (delayed) role-loss commit is in flight, land a
    // brand-new local file version for this group on device-b -- this moves
    // its durability-root digest out from under the readiness check that ran
    // moments earlier, so the atomic recheck-then-flip will find a mismatch.
    let racer_state = b.state.clone();
    let racer = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let record = record_referencing("concurrent-edit.bin", "device-b", vec![0xAB; 32], 4);
        racer_state
            .replica_coordinator
            .file_index_repository()
            .upsert_file(
                GROUP,
                &record,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
    });

    let resp = send_over_socket(
        &socket_path,
        ReqPayload::SetStorageMode(SetStorageModeRequest {
            group_id: GROUP.to_string(),
            on_demand: true,
        }),
    )
    .await;
    racer.await.unwrap();

    let Some(err_message) = support::control_socket_client::refusal_message(&resp.payload) else {
        panic!("a post-Worker-commit local failure must not report success");
    };
    assert!(
        err_message.contains("SAFELY ROLLED BACK") || err_message.contains("rolled back"),
        "the error must say the operation was safely rolled back, not silently swallowed: \
         {err_message}"
    );

    // Consistent end state: the Worker was reverted back to eager (visible
    // as the compensating `/storage-mode` call), and this device's own local
    // policy was never actually flipped away from eager either -- neither
    // side thinks this device gave up its full-replica role.
    assert_eq!(
        policy_of(&b.state, GROUP),
        MaterializationPolicy::Eager,
        "a compensated demotion must leave this device locally eager, matching the Worker \
         after the revert -- not a split state"
    );
    assert_eq!(
        request_count(&server, "POST", "/handoff/compensate").await,
        1,
        "exactly one compensating revert-to-eager call must have been made"
    );
    let storage_mode_requests = server.received_requests().await.unwrap();
    let revert_body: serde_json::Value = storage_mode_requests
        .iter()
        .find(|r| r.url.path().ends_with("/handoff/compensate"))
        .unwrap()
        .body_json()
        .unwrap();
    assert_eq!(revert_body["sourceDeviceId"], "device-b");
    assert_eq!(revert_body["targetDeviceId"], "device-a");
    assert_eq!(revert_body["leaseId"], "lease-from-device-a");
    assert_eq!(revert_body["expectedMembershipGeneration"], 1);
    // INV-4: the compensating call carries only ids/strings, never a digest.
    let dump = revert_body.to_string().to_lowercase();
    assert!(
        !dump.contains("digest") && !dump.contains("hash") && !dump.contains("path"),
        "the compensating Worker call must never carry a digest, hash, or path: {dump}"
    );

    assert!(
        all_role_loss_operations(&b.state).is_empty(),
        "a completed compensation must leave no role-loss-operation journal row behind"
    );
}

// --- Startup + periodic reconciliation sweep --------------------------------

/// Prepared is deliberately ambiguous: the request may never have arrived,
/// or the Worker may have committed before its response was lost. The safe
/// recovery for either case is the same idempotent eager write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prepared_reconcile_restores_worker_eager_after_response_loss() {
    support::ensure_isolated_config_dir();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/handoff/compensate")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"status": "restored"})),
        )
        .mount(&server)
        .await;

    let b = new_daemon("device-b");
    b.state.set_coordination_client_config(
        server.uri(),
        yadorilink_fapi_client::test_support::offline_auth(),
    );
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        as i64;
    b.state
        .replica_coordinator
        .role_loss_operation_repository()
        .insert_role_loss_operation(
            "op-ambiguous-prepared",
            GROUP,
            RoleLossOperationParams {
                source_device_id: "device-b",
                target_device_id: "device-a",
                lease_id: "lease-prepared",
                action: RoleLossAction::Demote,
                local_path: Some(&b.root.path().to_string_lossy()),
                now_unix: now,
            },
        )
        .unwrap();

    run_role_loss_reconciliation_sweep(&ControlContext::from_state(b.state.clone())).await;

    assert!(request_count(&server, "POST", "/handoff/compensate").await >= 1);
    assert!(all_role_loss_operations(&b.state).is_empty());
}

/// The crash-between-Worker-commit-and-local-commit case: a `WorkerCommitted`
/// journal row is already on disk (as if a previous process crashed right
/// after the Worker commit landed but before the local flip ran) when the
/// reconciliation sweep runs. The sweep must compensate it (revert the
/// Worker back to `eager`) and clear the row -- exactly the same outcome as
/// the inline compensation path, reached from a cold start instead of a live
/// request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_committed_row_found_at_startup_is_compensated_by_the_sweep() {
    support::ensure_isolated_config_dir();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/handoff/compensate")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"status": "restored"})),
        )
        .mount(&server)
        .await;

    let b = new_daemon("device-b");
    b.state.set_coordination_client_config(
        server.uri(),
        yadorilink_fapi_client::test_support::offline_auth(),
    );

    // Simulate the crash: a WorkerCommitted row sits in the journal with no
    // process left alive that remembers issuing it.
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        as i64;
    b.state
        .replica_coordinator
        .role_loss_operation_repository()
        .insert_role_loss_operation(
            "op-crash-1",
            GROUP,
            RoleLossOperationParams {
                source_device_id: "device-b",
                target_device_id: "device-a",
                lease_id: "lease-crash-1",
                action: RoleLossAction::Demote,
                local_path: Some(&b.root.path().to_string_lossy()),
                now_unix: now,
            },
        )
        .unwrap();
    b.state
        .replica_coordinator
        .role_loss_operation_repository()
        .advance_role_loss_operation("op-crash-1", RoleLossOperationState::WorkerCommitted, now)
        .unwrap();

    run_role_loss_reconciliation_sweep(&ControlContext::from_state(b.state.clone())).await;

    // Assert the end-state INVARIANT, not an exact call count: the auto-sweep
    // spawned by `DaemonState::new` (run-immediately-then-loop) can also fire
    // and compensate the same row, which is safe because reverting to eager is
    // idempotent -- so one-or-more `/storage-mode` reverts is correct, exactly
    // one is not guaranteed. What must hold deterministically is that the
    // Worker was reverted at least once and the row is gone.
    assert!(
        request_count(&server, "POST", "/handoff/compensate").await >= 1,
        "the sweep must compensate a leftover WorkerCommitted row by reverting the Worker at \
         least once"
    );
    assert!(
        all_role_loss_operations(&b.state).is_empty(),
        "a compensated WorkerCommitted row must be cleared once the sweep confirms the revert"
    );
}

/// If the compensating revert cannot reach the coordination plane, the row
/// must NOT be lost -- it stays `Compensating`, its attempt counter grows,
/// and the next sweep retries it (calling the Worker again).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compensation_unreachable_leaves_the_row_compensating_and_retries() {
    support::ensure_isolated_config_dir();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{GROUP}/handoff/compensate")))
        .respond_with(ResponseTemplate::new(503).set_body_string("coordination plane unavailable"))
        .mount(&server)
        .await;

    let b = new_daemon("device-b");
    b.state.set_coordination_client_config(
        server.uri(),
        yadorilink_fapi_client::test_support::offline_auth(),
    );

    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        as i64;
    b.state
        .replica_coordinator
        .role_loss_operation_repository()
        .insert_role_loss_operation(
            "op-crash-2",
            GROUP,
            RoleLossOperationParams {
                source_device_id: "device-b",
                target_device_id: "device-a",
                lease_id: "lease-crash-2",
                action: RoleLossAction::Demote,
                local_path: Some(&b.root.path().to_string_lossy()),
                now_unix: now,
            },
        )
        .unwrap();
    b.state
        .replica_coordinator
        .role_loss_operation_repository()
        .advance_role_loss_operation("op-crash-2", RoleLossOperationState::WorkerCommitted, now)
        .unwrap();

    run_role_loss_reconciliation_sweep(&ControlContext::from_state(b.state.clone())).await;
    let after_first = b
        .state
        .replica_coordinator
        .role_loss_operation_repository()
        .get_role_loss_operation("op-crash-2")
        .unwrap();
    let after_first = after_first.expect("an unreachable-compensation row must NOT be lost");
    assert_eq!(after_first.state, RoleLossOperationState::Compensating);
    // `>= 1`, not `== 1`: the auto-sweep spawned by `DaemonState::new` may also
    // have attempted a (failing) compensation, bumping the counter. The
    // invariant under test is that the row is never lost and its attempts only
    // ever grow -- it is retried, never abandoned -- not the exact count.
    assert!(
        after_first.attempts >= 1,
        "a failed compensation must record at least one attempt, got {}",
        after_first.attempts
    );

    // A second sweep must retry -- calling the Worker again, not giving up.
    run_role_loss_reconciliation_sweep(&ControlContext::from_state(b.state.clone())).await;
    let after_second = b
        .state
        .replica_coordinator
        .role_loss_operation_repository()
        .get_role_loss_operation("op-crash-2")
        .unwrap()
        .expect("the row must still survive a second failed compensation attempt");
    assert_eq!(after_second.state, RoleLossOperationState::Compensating);
    assert!(
        after_second.attempts > after_first.attempts,
        "each sweep must re-attempt and bump the attempt counter (never abandon the row): {} then \
         {}",
        after_first.attempts,
        after_second.attempts
    );
    assert!(
        request_count(&server, "POST", "/handoff/compensate").await >= 2,
        "each sweep must re-attempt the compensating Worker call, never abandoning the row"
    );
}
