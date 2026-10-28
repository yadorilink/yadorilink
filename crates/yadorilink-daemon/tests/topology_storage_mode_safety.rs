//! Safety-critical storage operations under faults, proven on
//! the real canonical N/M/W topology (real `peer_orchestrator`, real
//! transport, real control socket) composed with `storage_mode_
//! orchestration.rs`'s own established `wiremock` stand-in for
//! the coordination service. The role-level demotion/unlink handoff gate in `replica_role_service.rs`
//! is the real, CURRENTLY-SHIPPED backend-authoritative safety operation
//! ("Unsafe eviction/local-copy removal is backend-gated"). The PER-FILE
//! block-reclaim custody path (`P2pCustodyConfirmer::confirms_present`,
//! `materialization_eviction::evict_file`'s physical-deletion half) is
//! covered end to end by `custody_evict_e2e.rs` and at the unit level by
//! `gc.rs`'s own `eviction_without_custody_confirmation_never_reaches_physical_reclaim`.
//!
//! **Why compose two fakes, not one**: `FakeCoordination` (the netmap
//! WebSocket subscription) and the coordination service's plain HTTP API are
//! genuinely separate production boundaries --
//! `DaemonHandoffReadinessAdapter`'s own doc comment states readiness
//! confirmation and lease acquisition go over the real peer-to-peer
//! session, NEVER the coordination service's HTTP API, while the final
//! role-loss COMMIT (and a promotion's storage-mode write) genuinely does
//! go to the coordination service over HTTP (`HttpRoleLossCoordination`). No new
//! unified fake is introduced; both existing fakes are simply pointed at
//! the same real topology nodes.
//!
//! **Why M must genuinely PROMOTE itself to Eager first**: `fake.set_full_
//! replica` only publishes what OTHER peers believe about a device over
//! the netmap -- it does not touch that device's own LOCAL materialization
//! policy. The real responder-side check
//! (`yadorilink_replica_engine::engine::holds_version_durably`, answering
//! an incoming `VersionPresentQuery`) requires the RESPONDER's OWN local
//! retention policy to already be `Eager` -- an on-demand device's cache is
//! transient and must never be trusted to authorize a peer dropping its own
//! only copy, no matter what the coordination plane claims about it. So
//! before N can ever demote, M must have genuinely, locally promoted itself
//! -- driven here through M's own real control-socket `set_storage_mode`
//! request (never a direct DB write), exactly the "exercise production
//! daemon APIs" requirement.
//!
//! **The TOCTOU seam**: `DaemonState::request_handoff_lease` (the
//! confirmed TARGET's own handling of an incoming P2P `HandoffLeaseRequest`)
//! already computes `attested_digest` (this device's root-set digest)
//! BEFORE calling the coordination service's `/handoff/lease` route, then
//! re-derives `pinned_digest` via an atomic local pin AFTER that HTTP round
//! trip returns, and declines the lease if they differ -- a real,
//! already-existing production TOCTOU guard. `wiremock`'s own responder
//! closure for that route fires synchronously DURING the awaited HTTP call,
//! i.e. exactly inside that window -- the narrowest available test-only
//! hook to inject a genuine, real state change (a real `std::fs::write`)
//! between the safety read and the commit, with zero production code
//! touched.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::fake_coordination::HandoffRoute;
use support::topology::{stand_up_canonical_topology_with_m_http_coordination, TopologyNode};
use support::wait_until_with_context;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::SetStorageModeRequest;
use yadorilink_replica_domain::session_state::MaterializationPolicy;

/// A `tracing` writer that both prints (visible under `--nocapture`, same
/// as `with_test_writer()`) and appends into a shared, process-global
/// buffer -- letting `version_change_during_lease_issuance_refuses_the_
/// demotion` assert WHICH of two layered, independently-correct guards
/// actually caught its injected race: M's own target-side digest-mismatch
/// check inside `DaemonState::request_handoff_lease` (which never grants a
/// lease at all), versus N's separate source-side re-check inside
/// `DaemonState::obtain_handoff_lease_from_peer` (reached only if M
/// mistakenly granted one). Both paths converge on the SAME observable
/// local-lease-state/`  /release`-call-count signals the earlier
/// assertions already check, so distinguishing them needs the log line
/// each one emits at its own distinct call site -- a real review
/// finding: without this, a broken/missing target-side check could still
/// pass this test via the source-side backstop, silently proving the
/// wrong guard.
#[derive(Clone)]
struct CapturingWriter {
    buf: Arc<std::sync::Mutex<Vec<u8>>>,
}

impl std::io::Write for CapturingWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf.lock().unwrap_or_else(|p| p.into_inner()).extend_from_slice(data);
        eprint!("{}", String::from_utf8_lossy(data));
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

static LOG_CAPTURE: std::sync::OnceLock<Arc<std::sync::Mutex<Vec<u8>>>> =
    std::sync::OnceLock::new();

/// Installs the process-global tracing subscriber (once -- `try_init`
/// no-ops for whichever of this file's tests loses the race to call this
/// first) and returns the SAME shared capture buffer regardless of which
/// test actually performed the install, so every caller can read from it.
fn init_tracing() -> Arc<std::sync::Mutex<Vec<u8>>> {
    let buf = LOG_CAPTURE.get_or_init(|| Arc::new(std::sync::Mutex::new(Vec::new()))).clone();
    let writer_buf = buf.clone();
    // `yadorilink_daemon=info` is forced as a FLOOR, not merely a default:
    // `version_change_during_lease_issuance_refuses_the_demotion`'s own
    // proof (the captured log-line assertion, see `CapturingWriter`'s doc
    // comment) depends on M's `tracing::info!` event actually being
    // emitted -- a review finding that an ambient `RUST_LOG=warn`/
    // `error`/`off` in the environment (e.g. a CI default) would silently
    // filter that event out and fail the assertion for a reason that has
    // nothing to do with whether the real guard fired. `add_directive`
    // layers this floor on top of whatever `RUST_LOG` additionally asks
    // for, rather than replacing it, so a caller who wants MORE verbosity
    // (e.g. `RUST_LOG=trace`) still gets it.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(""))
        .add_directive("yadorilink_daemon=info".parse().unwrap());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(move || CapturingWriter { buf: writer_buf.clone() })
        .try_init();
    buf
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

/// Mounts a successful `/storage-mode` responder and drives M's own real
/// control-socket `set_storage_mode(on_demand: false)` request -- the
/// genuine production promotion path, never a direct policy write. Waits
/// for M's local policy to actually flip before returning, so every
/// caller can rely on `holds_version_durably`'s Eager-retention
/// precondition genuinely being met from here on.
async fn promote_to_eager_via_real_api(node: &TopologyNode, group_id: &str, server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{group_id}/storage-mode")))
        .respond_with(ResponseTemplate::new(204))
        .mount(server)
        .await;
    node.state.set_coordination_client_config(
        server.uri(),
        yadorilink_fapi_client::test_support::offline_auth(),
    );
    let handle = support::control_socket_client::start(node.state.clone()).await;
    let resp = support::control_socket_client::send(
        &handle,
        ReqPayload::SetStorageMode(SetStorageModeRequest {
            group_id: group_id.to_string(),
            on_demand: false,
        }),
    )
    .await;
    assert!(
        matches!(resp.payload, Some(RespPayload::SetStorageMode(_))),
        "the real promotion request must succeed, got {:?}",
        resp.payload
    );
    assert_eq!(
        policy_of(&node.state, group_id),
        MaterializationPolicy::Eager,
        "a successful promotion must flip local policy to Eager"
    );
}

/// A single `hydrate` attempt can genuinely race a still-settling fresh
/// convergence and return `HydrationFailed` transiently -- the same
/// documented, real-consumer-must-retry outcome
/// `topology_restart_convergence.rs`'s own established pattern retries
/// through.
#[allow(dead_code)]
async fn hydrate_with_retries(state: &Arc<DaemonState>, group_id: &str, path: &str) {
    let mut attempts = 0;
    loop {
        match yadorilink_daemon::hydration::hydrate(state, group_id, path).await {
            Ok(()) => return,
            Err(error) if attempts < 5 => {
                attempts += 1;
                tracing::warn!(%error, attempts, path, "hydration attempt failed, retrying");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(error) => panic!("hydration of {path} should eventually succeed: {error}"),
        }
    }
}

/// A safe demotion on the real canonical topology.
/// M genuinely promotes itself to Eager (real control-socket request), N
/// (the topology's own eager anchor) then demotes to on-demand once M is a
/// REAL, content-complete full replica -- proven via N's own real
/// `set_storage_mode` control-socket request, the real P2P
/// readiness/lease exchange with M, and a real (mocked) coordination service
/// role-loss commit. Asserts both the returned result AND the actual
/// resulting system state: N's local policy, the Worker's exact call
/// pattern (role-loss commit only, never the plain storage-mode route --
/// mirrors `storage_mode_orchestration.rs`'s own established assertion),
/// and that M is durably confirmed to hold the content (the real precondition
/// the demotion's own readiness gate required, re-derived independently
/// here rather than trusted from the operation's own success alone).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn safe_demotion_succeeds_when_a_real_peer_durably_holds_everything() {
    init_tracing();
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "topology-storage-safety-group";

    // M's own outbound coordination calls (its promotion, and the lease it
    // mints as the handoff target) are scripted and counted here; N stays on
    // `FakeCoordination`, which serves the stateful `authorization-checkpoint`
    // N needs to author content at all. See
    // `stand_up_canonical_topology_with_m_http_coordination`.
    let server = MockServer::start().await;
    let (n, m, _w, handles) =
        stand_up_canonical_topology_with_m_http_coordination(&fake, group_id, Some(&server.uri()))
            .await;

    promote_to_eager_via_real_api(&m, group_id, &server).await;

    // Real content, real convergence -- M is now genuinely Eager, so its
    // own real-time sync engine fetches this the same way N's would, no
    // manual hydrate needed. Nothing here is injected directly into
    // either device's index.
    let target_path = n.root.path().join("only.bin");
    std::fs::write(&target_path, b"the only file in this group").unwrap();
    wait_until_with_context(
        || {
            std::fs::read(m.root.path().join("only.bin")).ok().as_deref()
                == Some(b"the only file in this group" as &[u8])
        },
        Duration::from_secs(30),
        || "M (now Eager) never converged on N's content".to_string(),
    )
    .await;

    // M declares full-replica capability over the REAL coordination
    // channel -- the same public API `stand_up_canonical_topology` already
    // uses for N itself, not a raw DB mutation.
    fake.set_full_replica(&m.device_id, group_id, true);
    wait_until_with_context(
        || n.state.authority.peer_group_is_full_replica(&m.device_id, group_id),
        Duration::from_secs(30),
        || "N never saw M's complete-copy declaration propagate over the real netmap".to_string(),
    )
    .await;

    // The source side of the real handoff exchange: N's own role-loss
    // commit. M's own lease-issuance responder was already mounted by
    // `promote_to_eager_via_real_api` sharing this SAME server.
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{group_id}/handoff/lease")))
        .respond_with(move |_req: &wiremock::Request| {
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "leaseId": "lease-from-m",
                "expiresAt": far_future_expiry(),
                "ttlSeconds": 900,
            }))
        })
        .mount(&server)
        .await;
    // N's commit goes to `FakeCoordination`, not the wiremock: N must keep
    // the fake as its coordination plane for the stateful
    // `authorization-checkpoint` route, so the fake is where its role-loss
    // commit lands and is counted.
    fake.set_handoff_commit_response(
        group_id,
        200,
        serde_json::json!({
            "targetDeviceId": m.device_id,
            "membershipGeneration": 1,
            "leaseId": "lease-from-m",
        }),
    );

    // N is EAGER (not on-demand), but the demotion path's own
    // placeholder-pipeline-connected check gates on-demand readiness for
    // the DEVICE ASKING to become on-demand -- test-only override for the
    // (platform-native, out of scope here) on-demand pipeline probe,
    // matching `storage_mode_orchestration.rs`'s own established use of
    // this exact override for its own demoting device.
    n.state.set_test_on_demand_allowed(true);
    let handle = support::control_socket_client::start(n.state.clone()).await;
    let resp = support::control_socket_client::send(
        &handle,
        ReqPayload::SetStorageMode(SetStorageModeRequest {
            group_id: group_id.to_string(),
            on_demand: true,
        }),
    )
    .await;

    // 1. The operation's own result.
    assert!(
        matches!(resp.payload, Some(RespPayload::SetStorageMode(_))),
        "a ready demotion with a real confirmed peer and a successful role-loss commit must \
         succeed, got {:?}",
        resp.payload
    );

    // 2. The actual resulting system state -- never accepted on the
    // returned success alone.
    assert_eq!(
        policy_of(&n.state, group_id),
        MaterializationPolicy::OnDemand,
        "a successful demotion must flip N's local policy to on-demand"
    );
    assert_eq!(
        request_count(&server, "POST", "/handoff/lease").await,
        1,
        "N must have actually requested a lease from M over the real peer wire -- proof the \
         readiness gate was genuinely exercised, not bypassed"
    );
    let commit_body: serde_json::Value = fake
        .handoff_requests()
        .into_iter()
        .find(|r| r.route == HandoffRoute::Commit)
        .map(|r| serde_json::from_str(&r.body).expect("the commit body is JSON"))
        .expect("the role-loss commit must have been sent");
    assert_eq!(
        commit_body["targetDeviceId"], m.device_id,
        "the commit must name M -- the SAME peer that was actually confirmed ready -- as the \
         handoff target"
    );
    assert_eq!(
        commit_body["leaseId"], "lease-from-m",
        "the commit must present the SAME lease id M actually issued, not a fabricated or \
         mismatched one"
    );
    assert_eq!(
        fake.handoff_request_count(HandoffRoute::Commit),
        1,
        "a demotion's single coordination-plane write must be the role-loss commit"
    );
    assert_eq!(
        request_count(&server, "POST", "/storage-mode").await,
        1,
        "the only /storage-mode write in this whole scenario must be M's own earlier \
         promotion -- N's demotion must never call the plain storage-mode route"
    );
    assert!(
        std::fs::read(m.root.path().join("only.bin")).ok().as_deref()
            == Some(b"the only file in this group" as &[u8]),
        "M's own copy of the content must still be present and correct after the handoff -- \
         the demotion only changes N's role, never M's data"
    );

    handles.shutdown();
}

/// Exact-version race: M genuinely promotes to
/// Eager and holds the baseline content, then a NEW version lands on M --
/// injected via a REAL `std::fs::write` on M, executed synchronously
/// inside the mocked Worker's `/handoff/lease` responder closure, i.e.
/// genuinely BETWEEN `DaemonState::request_handoff_lease`'s pre-HTTP
/// `attested_digest` read and its post-HTTP atomic `pinned_digest`
/// re-check (see this file's own module doc comment for why this is the
/// real, already-existing TOCTOU guard and the narrowest available
/// injection point). The lease must be declined (digest mismatch), and
/// N's demotion must fail closed: local policy unchanged, and the Worker
/// must never receive a role-loss commit for a lease that was never
/// actually granted on a matching digest.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn version_change_during_lease_issuance_refuses_the_demotion() {
    let log_capture = init_tracing();
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "topology-storage-safety-race-group";

    // M on the wiremock (its promotion and the lease it mints, both scripted
    // and counted), N on `FakeCoordination` for the stateful
    // `authorization-checkpoint` it needs to author content. See
    // `stand_up_canonical_topology_with_m_http_coordination`.
    let server = MockServer::start().await;
    let (n, m, _w, handles) =
        stand_up_canonical_topology_with_m_http_coordination(&fake, group_id, Some(&server.uri()))
            .await;

    promote_to_eager_via_real_api(&m, group_id, &server).await;

    let target_path = n.root.path().join("only.bin");
    std::fs::write(&target_path, b"the only file in this group").unwrap();
    wait_until_with_context(
        || {
            std::fs::read(m.root.path().join("only.bin")).ok().as_deref()
                == Some(b"the only file in this group" as &[u8])
        },
        Duration::from_secs(30),
        || "M (now Eager) never converged on N's content".to_string(),
    )
    .await;

    fake.set_full_replica(&m.device_id, group_id, true);
    wait_until_with_context(
        || n.state.authority.peer_group_is_full_replica(&m.device_id, group_id),
        Duration::from_secs(30),
        || "N never saw M's complete-copy declaration propagate over the real netmap".to_string(),
    )
    .await;

    // THE RACE: this closure runs synchronously, on M's own coordination-
    // client call thread, DURING `request_handoff_lease`'s awaited HTTP
    // round trip -- after M already computed `attested_digest` from its
    // pre-race root set, but before the post-HTTP atomic re-check. A real
    // second file lands on M's real, watched (M is Eager) local folder
    // right here -- and this closure BLOCKS via a plain synchronous
    // spin-wait (`std::thread::sleep`, deliberately NOT `block_in_place` +
    // `block_on`: `wiremock`'s own request-handling task does not run on
    // this test's outer multi-threaded runtime -- an earlier version of
    // this closure hit "can call blocking only when running on the
    // multi-threaded runtime" there, and the resulting connection error
    // was silently misread as a successful digest-mismatch refusal, a
    // vacuous pass this test must not ship; `list_files` is a plain
    // synchronous DB call, so no runtime is needed to poll it at all)
    // until M's own real filesystem watcher has actually indexed the
    // write into the DAG, not merely written the bytes to disk. Bounded
    // well UNDER the P2P `HandoffLeaseRequest`'s own 10s timeout
    // (`peer_session.rs`'s `request_handoff_lease_from_peer`): a 30s
    // bound here could let N's OWN P2P request time out first, producing
    // the exact same "could not obtain a lease" refusal for the WRONG
    // reason (a timeout, not the digest-mismatch guard this test exists
    // to prove), silently passing regardless of which one actually fired.
    let m_root_for_race = m.root.path().to_path_buf();
    let m_state_for_race = m.state.clone();
    let race_group_id = group_id.to_string();
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{group_id}/handoff/lease")))
        .respond_with(move |_req: &wiremock::Request| {
            std::fs::write(
                m_root_for_race.join("race-version.bin"),
                b"a version M's peer never confirmed",
            )
            .unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                let indexed = m_state_for_race
                    .replica_coordinator
                    .file_index_repository()
                    .list_files(&race_group_id)
                    .map(|files| files.iter().any(|f| f.path == "race-version.bin" && !f.deleted))
                    .unwrap_or(false);
                if indexed {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "the race write was never indexed into M's own DAG within the 5s bound -- \
                     must stay well under the P2P handoff-lease request's own 10s timeout, or a \
                     timeout refusal could masquerade as the digest-mismatch refusal this test \
                     exists to prove"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "leaseId": "lease-from-m-mid-race",
                "expiresAt": far_future_expiry(),
                "ttlSeconds": 900,
            }))
        })
        .mount(&server)
        .await;
    // M's own best-effort release of the just-granted, now-mismatched
    // Worker lease -- mounted and asserted below so a genuinely reached
    // (not merely absent) release call, on the SAME lease id, is part of
    // the proof that the digest-mismatch path specifically ran, not some
    // other failure that never got this far.
    Mock::given(method("POST"))
        .and(path(format!("/shares/groups/{group_id}/handoff/lease/lease-from-m-mid-race/release")))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    // No commit mock is mounted here, deliberately. The commit is N's call,
    // and N's coordination plane is the fake, not this wiremock -- so a mock
    // here would record nothing no matter what N did, and an assertion
    // reading its count would be vacuous. The fake records every handoff
    // request before consulting any configured response, so leaving the
    // commit route unconfigured there still catches a wrongly-issued one;
    // that is what the assertion at the end of this test reads.
    // N deliberately stays on `FakeCoordination` (see the topology helper):
    // a `set_coordination_client_config` here would be a guaranteed no-op,
    // because `spawn_orchestrator` already claimed N's `OnceLock` with the
    // fake's address. So N's commit -- if the guard under test wrongly let
    // one through -- lands on the fake, and that is where it must be
    // counted. Counting it on the wiremock instead would be vacuous: zero
    // there is guaranteed whether or not N commits.

    n.state.set_test_on_demand_allowed(true);
    let handle = support::control_socket_client::start(n.state.clone()).await;
    let log_offset_before_demotion = log_capture.lock().unwrap_or_else(|p| p.into_inner()).len();
    let resp = support::control_socket_client::send(
        &handle,
        ReqPayload::SetStorageMode(SetStorageModeRequest {
            group_id: group_id.to_string(),
            on_demand: true,
        }),
    )
    .await;
    let captured_logs = {
        let buf = log_capture.lock().unwrap_or_else(|p| p.into_inner());
        String::from_utf8_lossy(&buf[log_offset_before_demotion..]).into_owned()
    };

    // 0. WHICH guard actually caught the race: this scenario's whole point
    // is M's own TARGET-side check (`DaemonState::request_handoff_lease`'s
    // `pinned_digest != attested_digest` branch, which never grants a
    // lease at all) -- not N's separate SOURCE-side re-check
    // (`obtain_handoff_lease_from_peer`'s `handoff_lease_grant_matches_
    // digest`, only reached if M had mistakenly granted one). Both
    // converge on the identical local-lease-state/`/release`-call
    // observables the assertions below check, so a broken/missing
    // target-side check could otherwise still pass this whole test via
    // the source-side backstop alone -- a real review finding this
    // log-line assertion closes.
    assert!(
        captured_logs.contains(
            "handoff lease request aborted: durability-root set changed between readiness \
             attestation and atomic pin"
        ),
        "M's own target-side digest-mismatch check must be the one that actually caught this \
         race (not N's separate source-side backstop) -- did not observe M's specific log line \
         in this demotion attempt's captured output:\n{captured_logs}"
    );

    // 1. The operation's own result: must be an error, never a success --
    // a version M's confirmed readiness never actually covered must not
    // silently authorize N to drop its own full-replica status. The exact
    // phrase (not just a loose "contains lease" check) distinguishes the
    // specific "could not obtain a lease" refusal from any other error
    // path that might also happen to mention "lease".
    let payload_debug = format!("{:?}", resp.payload);
    let Some(error_message) = support::control_socket_client::refusal_message(&resp.payload) else {
        panic!(
            "a version change mid-lease-issuance must refuse the demotion, got a non-error \
             response: {payload_debug}"
        );
    };
    assert!(
        error_message.contains("could not obtain the required handoff lease"),
        "the refusal must be the specific handoff-lease-failure message \
         (`demotion_handoff_lease_failure_message`), got: {error_message}"
    );

    // 2. The actual resulting system state.
    assert_eq!(
        policy_of(&n.state, group_id),
        MaterializationPolicy::Eager,
        "a refused demotion must leave N's local policy untouched (still Eager) -- the \
         crash-safe, TOCTOU-safe direction this whole gate exists to guarantee"
    );
    assert_eq!(
        fake.handoff_request_count(HandoffRoute::Commit),
        0,
        "the digest-mismatched lease must never reach a role-loss commit -- old-version \
         readiness must not authorize a commit that would cover the NEW version too. Counted \
         on the fake, the plane N actually uses: the fake records every handoff request \
         BEFORE consulting any configured response, so a wrongly-sent commit is caught here \
         even though this scenario never configures a commit response at all"
    );
    assert_eq!(
        request_count(&server, "POST", "/handoff/lease").await,
        1,
        "the lease WAS requested (proving the race actually landed inside the real \
         production call), it just correctly came back declined"
    );
    assert_eq!(
        request_count(&server, "POST", "/handoff/lease/lease-from-m-mid-race/release").await,
        1,
        "M must have actually reached the atomic pin (and thus the digest-mismatch check) and \
         then released the now-mismatched Worker lease -- proof this specifically is the \
         digest-mismatch path, not a failure that never got that far (e.g. a P2P timeout)"
    );
    let m_local_leases = m
        .state
        .replica_coordinator
        .handoff_lease_repository()
        .list_handoff_leases_for_group(group_id)
        .expect("M's own local lease repository must be readable");
    assert_eq!(
        m_local_leases.len(),
        1,
        "M's own local pin for this lease must have been recorded (the atomic pin genuinely ran)"
    );
    assert_eq!(
        m_local_leases[0].state,
        yadorilink_sync_sqlite::handoff_lease::HandoffLeaseState::Released,
        "M's own local pin must be Released (not left dangling as live-looking) after the \
         digest mismatch was caught"
    );

    handles.shutdown();
}
