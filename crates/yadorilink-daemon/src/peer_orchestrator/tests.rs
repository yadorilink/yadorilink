#![cfg(test)]

use super::*;
use crate::peer_connectivity_runtime::reachability_source_for_tests as reachability_source;
use crate::replica_coordinator::ReplicaCoordinator;
use std::sync::atomic::AtomicU32;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_peer_session::peer_session::PeerSyncSession;
use yadorilink_transport::DeviceSigningKeyPair;

/// A daemon drives Change convergence because it is a daemon, not because
/// something told it to.
///
/// Reconciliation used to be selected by an environment variable, with the
/// legacy `HeadsAnnounce`/`ChangeRequest`/`ChangeBatch` path as the
/// alternative. That path is gone, so "anything else, or unset" no longer
/// names a second way to converge — it names a daemon that cannot
/// converge at all, and does so silently, on the default configuration.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn convergence_starts_without_an_environment_variable_selecting_it() {
    let store_dir = tempfile::tempdir().unwrap();
    let db_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let coordinator = Arc::new(ReplicaCoordinator::open(db_dir.path().join("index.db")).unwrap());
    let state = TestState(DaemonState::new("device-under-test".into(), coordinator, store));
    state.set_device_signing_key(yadorilink_transport::DeviceSigningKeyPair::generate().signing);

    start_reconciliation_with(&state, yadorilink_sync_substrate::NetworkConfig::direct_only())
        .await;

    assert!(
        state.peer_session_driver().is_some(),
        "a daemon with no convergence driver installed cannot sync at all"
    );
}

/// Starting twice does not build a second stack.
///
/// The reconnect loop calls this on every pass so a start that failed
/// once is retried; a second endpoint and a second driver per reconnect
/// would be the cost of that if it were not idempotent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn starting_convergence_again_keeps_the_stack_already_running() {
    let store_dir = tempfile::tempdir().unwrap();
    let db_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let coordinator = Arc::new(ReplicaCoordinator::open(db_dir.path().join("index.db")).unwrap());
    let state = TestState(DaemonState::new("device-under-test".into(), coordinator, store));
    state.set_device_signing_key(yadorilink_transport::DeviceSigningKeyPair::generate().signing);

    let config = || yadorilink_sync_substrate::NetworkConfig::direct_only();
    start_reconciliation_with(&state, config()).await;
    let first = state.peer_session_driver().expect("a driver after the first start");
    start_reconciliation_with(&state, config()).await;
    let second = state.peer_session_driver().expect("a driver after the second start");

    assert!(
        Arc::ptr_eq(&first, &second),
        "a second start must keep the running stack rather than replace it"
    );
}

/// `session_transports_for` -- the gate `wait_for_session_transports`
/// polls before a session may be constructed -- answers `None` before
/// this device's own reconciliation stack exists, and `Some` once it
/// does.
///
/// This is the replacement for the old attach-after-construction race
/// this file used to close with `session_attach_lock` (see the deleted
/// `a_session_registered_before_the_stack_is_attached_when_it_arrives`/
/// `registration_racing_stack_startup_never_leaves_a_session_unattached`
/// tests in history): `SessionTransports` is a required `PeerSyncSession`
/// constructor parameter now, so there is no longer a "session exists,
/// transports attach later" state for a race to produce -- a session
/// simply cannot be constructed at all before this returns `Some`. What
/// is left to state is only that the gate itself flips at the right
/// moment.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_transports_for_is_none_before_a_stack_exists_and_some_after() {
    let store_dir = tempfile::tempdir().unwrap();
    let db_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let coordinator = Arc::new(ReplicaCoordinator::open(db_dir.path().join("index.db")).unwrap());
    let state = TestState(DaemonState::new("device-under-test".into(), coordinator, store));
    state.set_device_signing_key(yadorilink_transport::DeviceSigningKeyPair::generate().signing);

    assert!(
        state.session_transports_for("device-early").is_none(),
        "precondition: no reconciliation stack exists yet"
    );

    start_reconciliation_with(&state, yadorilink_sync_substrate::NetworkConfig::direct_only())
        .await;

    assert!(
        state.session_transports_for("device-early").is_some(),
        "a peer that connects once the stack exists must get real transports"
    );
}

/// Startup keeps retrying while there is no convergence driver, and stops
/// for good once there is one.
///
/// The retry lived in the coordination reconnect loop first, which was
/// wrong for a reason no bind failure was needed to see: that loop's body
/// returns only when the netmap stream ends, so a daemon whose first start
/// failed and whose coordination connection then stayed healthy would
/// never have retried. What the loop must do is bounded by its own
/// success, not by an unrelated stream's lifetime.
#[tokio::test(start_paused = true)]
async fn convergence_startup_retries_until_it_succeeds_and_then_stops() {
    let store_dir = tempfile::tempdir().unwrap();
    let db_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let coordinator = Arc::new(ReplicaCoordinator::open(db_dir.path().join("index.db")).unwrap());
    let state = TestState(DaemonState::new("device-under-test".into(), coordinator, store));
    state.set_device_signing_key(yadorilink_transport::DeviceSigningKeyPair::generate().signing);

    // Two failures, then a start that takes. Standing in for a transient
    // bind failure, which cannot be produced on demand.
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = attempts.clone();
    retry_until_started(&state, move |state| {
        let counted = counted.clone();
        let state = state.clone();
        Box::pin(async move {
            let attempt = counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if attempt >= 2 {
                start_reconciliation_with(
                    &state,
                    yadorilink_sync_substrate::NetworkConfig::direct_only(),
                )
                .await;
            }
        })
    })
    .await;

    assert_eq!(
        attempts.load(std::sync::atomic::Ordering::SeqCst),
        3,
        "the loop must stop on the attempt that succeeds, not keep going"
    );
    assert!(state.peer_session_driver().is_some());
}

#[test]
fn peer_key_pinning_detects_key_changes() {
    let mut pins = HashMap::new();

    assert!(matches!(
        verify_or_pin_peer_key(&mut pins, "device-a", &[1u8; 32]),
        PeerKeyDecision::NewlyPinned
    ));
    assert!(matches!(
        verify_or_pin_peer_key(&mut pins, "device-a", &[1u8; 32]),
        PeerKeyDecision::AlreadyPinned
    ));
    assert!(matches!(
        verify_or_pin_peer_key(&mut pins, "device-a", &[2u8; 32]),
        PeerKeyDecision::Mismatch
    ));
}

#[test]
fn policy_service_key_pin_decision_requires_tofu_or_rotation() {
    let endpoint = "https://coord.example";
    let mut pins = HashMap::new();

    let (key, decision) = policy_service_key_pin_decision(&pins, endpoint, [1u8; 32]).unwrap();
    assert_eq!(key, [1u8; 32]);
    assert_eq!(decision, PolicyServiceKeyPinDecision::NewPin);

    pins.insert(endpoint.to_string(), hex::encode([1u8; 32]));
    let (key, decision) = policy_service_key_pin_decision(&pins, endpoint, [1u8; 32]).unwrap();
    assert_eq!(key, [1u8; 32]);
    assert_eq!(decision, PolicyServiceKeyPinDecision::AlreadyPinned);

    let (key, decision) = policy_service_key_pin_decision(&pins, endpoint, [2u8; 32]).unwrap();
    assert_eq!(key, [1u8; 32]);
    assert_eq!(decision, PolicyServiceKeyPinDecision::RotationRequired);
}

/// `pin_peer_signing_key` is a thin wrapper around `verify_or_pin_peer_key`,
/// so its refuse-on-change behavior is the same generic pin/verify logic
/// `peer_key_pinning_detects_key_changes` above already exercises
/// directly; the persisting `NewlyPinned` path is covered there.
#[test]
fn device_key_pinning_refuses_a_changed_key() {
    let mut pins = HashMap::new();

    // Already-pinned matching key: accepted, no change.
    pins.insert("device-a".to_string(), hex::encode([7u8; 32]));
    assert!(!pin_peer_signing_key(std::path::Path::new("."), &mut pins, "device-a", &[7u8; 32])
        .unwrap());

    // Changed key: refused.
    assert!(
        pin_peer_signing_key(std::path::Path::new("."), &mut pins, "device-a", &[9u8; 32]).unwrap()
    );
}

/// Everything that is not a 32-byte Ed25519 key is one outcome:
/// unusable. There is no shape of netmap entry in which a peer without
/// a device key is admissible, because that key is what authenticates
/// its transport -- so absence is not a weaker form of presence, it is
/// an invalid entry.
#[test]
fn a_peer_without_a_usable_device_key_is_not_admissible() {
    use base64::Engine;
    let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);

    assert_eq!(decode_peer_signing_key(""), None, "empty");
    assert_eq!(decode_peer_signing_key("not base64!!"), None, "undecodable");
    assert_eq!(decode_peer_signing_key(&encode(&[1u8; 31])), None, "too short");
    assert_eq!(decode_peer_signing_key(&encode(&[1u8; 33])), None, "too long");
    assert_eq!(decode_peer_signing_key(&encode(&[1u8; 32])), Some([1u8; 32]));
}

/// The netmap WebSocket URL builder's loopback/scheme validation:
/// remote `http://` is refused, loopback `http://` maps to `ws://`, and
/// `https://` maps to `wss://`.
#[test]
fn ws_netmap_url_rejects_remote_http_and_accepts_loopback_and_https() {
    use super::ws_netmap::netmap_ws_url;

    assert!(netmap_ws_url("http://coordination.example", "device-1").is_err());
    assert_eq!(
        netmap_ws_url("http://127.0.0.1:8787", "device-1").unwrap(),
        "ws://127.0.0.1:8787/netmap/subscribe?deviceId=device-1"
    );
    assert_eq!(
        netmap_ws_url("https://coordination.example", "device-1").unwrap(),
        "wss://coordination.example/netmap/subscribe?deviceId=device-1"
    );
}

/// Regression test: an earlier version of `netmap_ws_url` hand-rolled
/// the host extraction by splitting on `:`, which silently mangled an
/// IPv6 loopback literal (`[::1]`) since the address itself contains
/// colons. Parsing with the `url` crate handles this correctly.
#[test]
fn ws_netmap_url_handles_an_ipv6_loopback_literal() {
    use super::ws_netmap::netmap_ws_url;

    assert_eq!(
        netmap_ws_url("http://[::1]:8787", "device-1").unwrap(),
        "ws://[::1]:8787/netmap/subscribe?deviceId=device-1"
    );
}

// --- peer_orchestrator tests -------------------------------
//
// `state.peers.sessions`/`state.peers.peer_statuses` are keyed on real
// `Arc<PeerSyncSession>`/`PeerChannel` types from other crates, so a
// couple of these tests build one real (but peer-less) `PeerChannel`
// against a candidate address that never answers — a lightweight "fake
// transport": `PeerChannel::connect` registers on the shared socket and
// spawns its actor without blocking on completing a handshake with a
// live peer, so no second device is needed.

fn test_state() -> TestState {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    TestState(DaemonState::new("local-device".into(), sync_state, store))
}

/// A test's state, freed when the test lets go of it.
///
/// Registering a session or starting convergence ties the state into a
/// reference cycle with itself (see
/// [`DaemonState::release_reference_cycles_for_tests`]), which would keep its
/// databases and their worker threads alive for the rest of the test binary.
struct TestState(Arc<DaemonState>);

impl std::ops::Deref for TestState {
    type Target = Arc<DaemonState>;

    fn deref(&self) -> &Arc<DaemonState> {
        &self.0
    }
}

impl Drop for TestState {
    fn drop(&mut self) {
        self.0.release_reference_cycles_for_tests();
    }
}

/// An orphaned link is never handed back as a sync root -- an incoming
/// peer change for its group must have nowhere local to land, the same
/// as if this device had no link for that group at all.
/// A group whose root cannot be named unambiguously must be OMITTED, not
/// resolved by chance. Before this, the `HashMap::insert` loop here took the
/// LAST matching row while `link_gate_for_group` -- consulted by the same
/// apply path -- took the FIRST: two components in one process disagreeing
/// about which folder is "the" root for one group, at the same moment.
/// Omitting it leaves the peer change undelivered (recoverable) rather than
/// applied against the wrong folder (not).
#[tokio::test]
async fn sync_roots_for_groups_omits_an_ambiguous_group() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link("/home/alice/Photos", "group-1").unwrap();
    state
        .replica_coordinator
        .link_repository()
        .force_second_live_link_for_test("/home/alice/PhotosCopy", "group-1")
        .unwrap();
    state.replica_coordinator.link_repository().add_link("/home/alice/Docs", "group-2").unwrap();

    let roots = sync_roots_for_groups(&state, &["group-1".to_string(), "group-2".to_string()]);

    assert!(
        !roots.contains_key("group-1"),
        "an ambiguous group must not resolve to either of its roots, got {roots:?}"
    );
    assert_eq!(
        roots.get("group-2"),
        Some(&PathBuf::from("/home/alice/Docs")),
        "an unrelated healthy group must still resolve -- the refusal is per-group"
    );
}

#[tokio::test]
async fn sync_roots_for_groups_excludes_an_orphaned_link() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link("/home/alice/Photos", "group-1").unwrap();
    state.replica_coordinator.link_repository().add_link("/home/alice/Docs", "group-2").unwrap();
    state.replica_coordinator.link_repository().mark_link_orphaned("/home/alice/Photos").unwrap();

    let roots = sync_roots_for_groups(&state, &["group-1".to_string(), "group-2".to_string()]);

    assert!(!roots.contains_key("group-1"), "an orphaned link's group must not resolve");
    assert_eq!(roots.get("group-2"), Some(&PathBuf::from("/home/alice/Docs")));
}

async fn fake_session(state: &Arc<DaemonState>) -> Arc<PeerSyncSession> {
    let (transports, _peer_transports) =
        crate::test_support::session_transports_pair("local-device", "device-b").await;
    let peer_store = Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
        state.block_store.clone(),
    ));
    let replica_engine = crate::replica_coordinator::engine_ports::build_peer_replica_engine(
        &state.replica_coordinator,
        peer_store.clone(),
    );
    PeerSyncSession::over_substrate(
        "local-device".into(),
        "device-b".into(),
        state.replica_coordinator.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine,
        peer_store,
        vec![],
        transports,
        PeerSyncSessionDeps::standalone(),
    )
}

#[tokio::test]
async fn authoritative_netmap_replaces_metadata_for_an_existing_session() {
    let state = test_state();
    let session = fake_session(&state).await;
    state.peers.register_session("device-b".into(), session.clone(), state.local_convergence());

    let initial_groups = HashSet::from(["group-1".to_string(), "group-2".to_string()]);
    apply_authoritative_peer_metadata(
        &state,
        "device-b",
        Some([7; 32]),
        &initial_groups,
        &initial_groups,
        &std::sync::Mutex::new(HashMap::new()),
    );
    assert!(session.shares_group("group-2"));
    assert!(state.authority.peer_is_writer("device-b", "group-2"));
    assert!(state.authority.peer_group_is_full_replica("device-b", "group-2"));

    let generation_before = state.authority.membership_generation();
    let demoted_groups = HashSet::from(["group-1".to_string()]);
    apply_authoritative_peer_metadata(
        &state,
        "device-b",
        None,
        &demoted_groups,
        &HashSet::new(),
        &std::sync::Mutex::new(HashMap::new()),
    );

    assert!(session.shares_group("group-1"));
    assert!(!session.shares_group("group-2"));
    assert!(state.authority.peer_is_writer("device-b", "group-1"));
    assert!(!state.authority.peer_is_writer("device-b", "group-2"));
    assert!(!state.authority.peer_group_is_full_replica("device-b", "group-1"));
    assert!(!state.authority.peer_group_is_full_replica("device-b", "group-2"));
    assert_eq!(state.authority.peer_signing_key("device-b"), None);
    assert!(state.authority.membership_generation() > generation_before);
}

/// A snapshot that repeats the groups a session already has must not wake the reconcile
/// loops (it arrives for every peer on every netmap push); a changed set must.
#[tokio::test]
async fn netmap_push_wakes_reconcile_only_when_the_groups_change() {
    let state = test_state();
    let session = fake_session(&state).await;
    state.peers.register_session("device-b".into(), session.clone(), state.local_convergence());
    let mut wake = state.native_replication.subscribe_wake_for_test();
    let apply = |groups: &[&str]| {
        let groups: HashSet<String> = groups.iter().map(|g| g.to_string()).collect();
        apply_authoritative_peer_metadata(
            &state,
            "device-b",
            Some([7; 32]),
            &groups,
            &groups,
            &std::sync::Mutex::new(HashMap::new()),
        );
    };

    apply(&["group-1"]);
    assert!(wake.has_changed().unwrap(), "a new group must wake");
    wake.borrow_and_update();

    apply(&["group-1"]);
    apply(&["group-1"]);
    assert!(!wake.has_changed().unwrap(), "an unchanged push must not wake");

    apply(&["group-1", "group-2"]);
    assert!(wake.has_changed().unwrap(), "a changed set must wake");
}

/// A netmap push carrying every field the plane always sends, so a
/// test can omit or corrupt exactly the one it is about.
///
/// `serviceSigningPublicKeyBase64`, `groupPolicyLogs` and
/// `policyInvalidGroupIds` are required, deliberately: defaulting them
/// would let a truncated push apply as "nothing changed". A fixture
/// that leaves them out therefore fails to deserialize for a reason
/// that has nothing to do with the test -- and, worse, a test asserting
/// only `is_err()` would go on passing even if the field it is really
/// about became optional. Passing `generation: None` omits
/// `snapshotGeneration` and nothing else.
fn netmap_push(generation: Option<&str>, peers: serde_json::Value) -> serde_json::Value {
    let mut push = serde_json::json!({
        "type": "netmap",
        "serviceSigningPublicKeyBase64": "AA==",
        "groupPolicyLogs": [],
        "policyInvalidGroupIds": [],
        "peers": peers,
    });
    if let Some(generation) = generation {
        push["snapshotGeneration"] = serde_json::Value::String(generation.to_string());
    }
    push
}

/// One peer row carrying every field the plane always sends.
/// `fullReplicaGroupIds` is as required as the rest, so a fixture that
/// spells a peer out by hand and omits it fails to deserialize for a
/// reason unrelated to what the test is about.
fn netmap_peer(device_id: &str, signing_public_key_base64: &str) -> serde_json::Value {
    serde_json::json!({
        "deviceId": device_id,
        "signingPublicKeyBase64": signing_public_key_base64,
        "endpoints": [],
        "sharedGroupIds": [],
        "fullReplicaGroupIds": [],
    })
}

#[test]
fn duplicate_device_ids_are_rejected_before_snapshot_application() {
    use super::ws_netmap::{AdmittedNetmapMessage, WsNetmapMessage};

    let generation = StdMutex::new(None);

    let duplicate: WsNetmapMessage = serde_json::from_value(netmap_push(
        Some("1"),
        serde_json::json!([netmap_peer("device-b", "AA=="), netmap_peer("device-b", "AQ=="),]),
    ))
    .unwrap();

    // This is the exact admission gate used by the receive loop. A
    // duplicate snapshot cannot reach the policy, diff, key-pin,
    // metadata, or session application phase below that gate.
    assert!(AdmittedNetmapMessage::admit(duplicate, &generation).is_err());
    assert_eq!(*generation.lock().unwrap(), None);

    let unique: WsNetmapMessage = serde_json::from_value(netmap_push(
        Some("1"),
        serde_json::json!([netmap_peer("device-b", "AA=="), netmap_peer("device-c", "AQ=="),]),
    ))
    .unwrap();
    assert!(AdmittedNetmapMessage::admit(unique, &generation).is_ok());
    assert_eq!(*generation.lock().unwrap(), Some(1));
}

#[test]
fn stale_or_replayed_netmap_generation_is_rejected_across_attempts() {
    use super::ws_netmap::{AdmittedNetmapMessage, NetmapAdmissionError, WsNetmapMessage};

    fn message(generation: &str) -> WsNetmapMessage {
        serde_json::from_value(netmap_push(Some(generation), serde_json::json!([]))).unwrap()
    }

    let last_generation = StdMutex::new(None);
    assert!(AdmittedNetmapMessage::admit(message("9"), &last_generation).is_ok());
    assert!(matches!(
        AdmittedNetmapMessage::admit(message("9"), &last_generation),
        Err(NetmapAdmissionError::StaleGeneration)
    ));
    assert!(matches!(
        AdmittedNetmapMessage::admit(message("8"), &last_generation),
        Err(NetmapAdmissionError::StaleGeneration)
    ));
    assert!(AdmittedNetmapMessage::admit(message("10"), &last_generation).is_ok());
    assert_eq!(*last_generation.lock().unwrap(), Some(10));
}

#[test]
fn missing_or_malformed_netmap_generation_fails_closed() {
    use super::ws_netmap::{AdmittedNetmapMessage, NetmapAdmissionError, WsNetmapMessage};

    // Well-formed in every respect except the generation, so this can
    // only be rejected for the absent `snapshotGeneration`.
    let missing =
        serde_json::from_value::<WsNetmapMessage>(netmap_push(None, serde_json::json!([])));
    assert!(
        missing.is_err(),
        "a push with no snapshotGeneration must not deserialize: every other required field \
         is present here, so nothing else can account for the rejection"
    );

    let malformed: WsNetmapMessage =
        serde_json::from_value(netmap_push(Some("not-a-generation"), serde_json::json!([])))
            .unwrap();
    let last_generation = StdMutex::new(None);
    assert!(matches!(
        AdmittedNetmapMessage::admit(malformed, &last_generation),
        Err(NetmapAdmissionError::InvalidGeneration)
    ));
    assert_eq!(*last_generation.lock().unwrap(), None);
}

/// A retired message family on the netmap subscription is dropped quietly.
///
/// The coordination plane used to push a peer-connection `rendezvous` signal
/// on this same socket, for the transport that has since been deleted. A
/// plane that has not been redeployed yet still pushes one, and a daemon
/// that reported it as a malformed message would report a routine, expected
/// frame as corruption -- and teach an operator to ignore the warning that
/// means the wire really is broken.
#[test]
fn a_retired_subscription_message_family_is_ignored_rather_than_called_malformed() {
    use super::ws_netmap::{classify_subscription_message, SubscriptionMessage, WsNetmapMessage};

    // The exact frame the retired route pushed.
    let rendezvous = serde_json::json!({
        "type": "rendezvous",
        "from": "device-a",
        "candidates": [{ "address": "127.0.0.1:41000", "priority": 1 }],
    });

    assert_eq!(
        classify_subscription_message(rendezvous.get("type").and_then(|t| t.as_str())),
        SubscriptionMessage::Unread,
        "a rendezvous frame must classify as a family this build does not read"
    );

    // And that classification is load-bearing rather than cosmetic: the
    // frame is not a netmap snapshot, so without it the snapshot decode is
    // what would see this frame, and it would fail.
    assert!(
        serde_json::from_value::<WsNetmapMessage>(rendezvous).is_err(),
        "a rendezvous frame does not decode as a netmap snapshot, which is why it must be \
         classified out before the snapshot decode reports it as malformed"
    );

    // The two families this build does read still route to their handlers.
    assert_eq!(classify_subscription_message(Some("netmap")), SubscriptionMessage::Netmap);
    assert_eq!(
        classify_subscription_message(Some("send_authorization")),
        SubscriptionMessage::SendAuthorization
    );
    assert_eq!(classify_subscription_message(None), SubscriptionMessage::Unread);
}

/// A session ending must remove the session from the registry.
///
/// And only the session: whether the peer is reachable is read from the iroh
/// endpoint's connections, which this transport's session ending says
/// nothing about.
#[tokio::test]
async fn session_end_removes_the_session_and_leaves_iroh_reachability_alone() {
    let state = test_state();
    let session = fake_session(&state).await;

    reachability_source::connected_directly(&state, "device-b");
    state.peers.register_session("device-b".into(), session.clone(), state.local_convergence());

    assert!(state.peers.has_session("device-b"));

    end_session(&state, "device-b");

    assert!(!state.peers.has_session("device-b"));
    assert_eq!(
        state.peer_connectivity.reachability("device-b"),
        Some(crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Direct)),
        "the legacy session ending does not decide the peer's reachability"
    );
}

// --- Netmap-diff-driven teardown integration tests -------------------

async fn fake_session_for(
    state: &Arc<DaemonState>,
    peer_device_id: &str,
    shared_group_ids: Vec<String>,
) -> Arc<PeerSyncSession> {
    let (transports, _peer_transports) =
        crate::test_support::session_transports_pair("local-device", peer_device_id).await;
    let peer_store = Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
        state.block_store.clone(),
    ));
    let replica_engine = crate::replica_coordinator::engine_ports::build_peer_replica_engine(
        &state.replica_coordinator,
        peer_store.clone(),
    );
    PeerSyncSession::over_substrate(
        "local-device".into(),
        peer_device_id.into(),
        state.replica_coordinator.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine,
        peer_store,
        shared_group_ids,
        transports,
        PeerSyncSessionDeps::standalone(),
    )
}

/// Registers a connected peer the way the session keeper would: a
/// session in the registry, reachability reported, and the peer's pinned
/// signing key recorded -- everything `teardown_peer`/`apply_netmap_diff`
/// act on. Returns the key revocation has to withdraw.
async fn register_fake_peer(
    state: &Arc<DaemonState>,
    peer_device_id: &str,
    shared_group_ids: Vec<String>,
) -> [u8; 32] {
    let session = fake_session_for(state, peer_device_id, shared_group_ids).await;
    reachability_source::connected_directly(state, peer_device_id);
    state.peers.register_session(peer_device_id.to_string(), session, state.local_convergence());
    let peer_public_key = DeviceSigningKeyPair::generate().public_bytes();
    state.record_peer_signing_key(peer_device_id, peer_public_key);
    peer_public_key
}

/// A whole-device removal (`diff.removed_devices`) withdraws the
/// device's authorization -- which is what revocation *is* with raw
/// public keys, there being no CA, CRL or OCSP to express it -- *and*
/// immediately drops the peer from `state.peers`. The second half
/// matters on its own: `hydration.rs`'s `candidate_sessions` reads that
/// map live, so removing it here is what makes a revoked device stop
/// being offered as a hydration candidate right away rather than once
/// its session times out on its own.
#[tokio::test]
async fn full_device_revocation_withdraws_authorization_and_drops_hydration_candidate() {
    let state = test_state();
    let peer_public_key = register_fake_peer(&state, "device-b", vec!["group-1".into()]).await;
    assert_eq!(state.authority.peer_signing_key("device-b"), Some(peer_public_key));

    let diff =
        NetmapDiff { removed_devices: vec!["device-b".to_string()], removed_group_edges: vec![] };
    apply_netmap_diff(&diff, &state);

    assert_eq!(
        state.authority.peer_signing_key("device-b"),
        None,
        "whole-device revocation must withdraw the device's key, so a fresh handshake from \
         it is refused rather than merely its current connection ended"
    );
    assert!(
        !state.peers.has_session("device-b"),
        "revoked device must be immediately gone from the peer registry, which hydration's \
         candidate_sessions reads live"
    );
    assert!(state.peer_connectivity.reachability("device-b").is_none());
}

/// A group-edge-only removal (the device is still present in
/// `removed_group_edges` but *not* in `removed_devices`, because it
/// still shares another group) must leave the device authorized and the
/// session up -- distinct from the whole-device case above, proving
/// `apply_netmap_diff` really does treat the two differently rather
/// than tearing down on any diff entry at all.
#[tokio::test]
async fn group_edge_revocation_leaves_the_device_authorized_and_the_session_up() {
    let state = test_state();
    let peer_public_key =
        register_fake_peer(&state, "device-b", vec!["group-1".into(), "group-2".into()]).await;

    let diff = NetmapDiff {
        removed_devices: vec![],
        removed_group_edges: vec![("device-b".to_string(), "group-2".to_string())],
    };
    apply_netmap_diff(&diff, &state);

    assert_eq!(
        state.authority.peer_signing_key("device-b"),
        Some(peer_public_key),
        "a device that still shares another group must stay authorized"
    );
    assert!(
        state.peers.has_session("device-b"),
        "a group-edge-only revocation must not remove the still-authorized session"
    );
}

/// This is the daemon-level wiring test proving the exact fix in
/// `apply_netmap_diff`'s `removed_group_edges` loop; the full
/// coordination-plane-to-daemon flow is exercised end-to-end in
/// `tests/revocation_end_to_end.rs`.
#[tokio::test]
async fn group_edge_revocation_calls_session_revoke_group() {
    let state = test_state();
    let _peer_public_key =
        register_fake_peer(&state, "device-b", vec!["group-1".into(), "group-2".into()]).await;
    let session = state.peers.session("device-b").unwrap();
    assert!(session.shares_group("group-1"));
    assert!(session.shares_group("group-2"));

    let diff = NetmapDiff {
        removed_devices: vec![],
        removed_group_edges: vec![("device-b".to_string(), "group-2".to_string())],
    };
    apply_netmap_diff(&diff, &state);

    assert!(
        !session.shares_group("group-2"),
        "group-edge revocation must call session.revoke_group so live re-validation \
         reflects it, not just leave the transport layer untouched"
    );
    assert!(session.shares_group("group-1"), "the remaining shared group must stay authorized");
}

#[tokio::test]
async fn pinned_peer_key_mismatch_tears_down_session_and_authorization() {
    let state = test_state();
    let peer_public_key = register_fake_peer(&state, "device-b", vec!["group-1".into()]).await;
    // The peer's own key, not an arbitrary one: `teardown_peer` revokes
    // whatever key the netmap currently records for the device, so a
    // fixture whose metadata disagreed with its registration would be
    // asserting against a key nothing ever authorized.
    apply_authoritative_peer_metadata(
        &state,
        "device-b",
        Some(peer_public_key),
        &HashSet::from(["group-1".to_string()]),
        &HashSet::from(["group-1".to_string()]),
        &std::sync::Mutex::new(HashMap::new()),
    );
    let mut pins = HashMap::new();
    assert!(matches!(
        verify_or_pin_peer_key(&mut pins, "device-b", &[1; 32]),
        PeerKeyDecision::NewlyPinned
    ));
    let decision = verify_or_pin_peer_key(&mut pins, "device-b", &[2; 32]);
    match decision {
        PeerKeyDecision::Mismatch => teardown_peer(&state, "device-b"),
        _ => panic!("changed pinned key must be rejected as a mismatch"),
    }

    assert!(!state.peers.has_session("device-b"));
    assert_eq!(state.authority.peer_signing_key("device-b"), None);
    assert!(!state.authority.peer_is_writer("device-b", "group-1"));
    assert!(!state.authority.peer_group_is_full_replica("device-b", "group-1"));
}

#[test]
fn diff_netmap_reused_from_transport_classifies_a_realistic_mixed_update() {
    // Exercises the exact type (`yadorilink_transport::NetmapSnapshot`)
    // and function `run_netmap_attempt` calls, from this crate's side
    // of the boundary — a lightweight regression guard against the
    // two crates' notion of a netmap snapshot drifting apart.
    let mut previous: NetmapSnapshot = HashMap::new();
    previous.insert("device-a".into(), HashSet::from(["group-1".to_string()]));
    previous
        .insert("device-b".into(), HashSet::from(["group-1".to_string(), "group-2".to_string()]));

    let mut current: NetmapSnapshot = HashMap::new();
    current.insert("device-b".into(), HashSet::from(["group-1".to_string()]));

    let diff = diff_netmap(&previous, &current);

    assert_eq!(diff.removed_devices, vec!["device-a".to_string()]);
    assert_eq!(diff.removed_group_edges, vec![("device-b".to_string(), "group-2".to_string())]);
}

/// Regression guard for the graceful-shutdown interaction: an earlier
/// version of `run` drove its reconnect loop through `supervise::spawn_restarting`,
/// which retries inside a second, independently `tokio::spawn`ed task — externally
/// aborting the task *running* `run` (as `main.rs`'s `JoinSet::shutdown` does)
/// only cancelled `run`'s `.await` on that task's `JoinHandle`, leaving the
/// retry loop running detached and reconnecting forever past the "shutdown".
/// This test would have failed under that design: it counts real connection
/// attempts against a listener that always fails the handshake immediately,
/// aborts `run`'s task once at least one attempt has happened, then asserts
/// the count stays flat.
#[tokio::test]
async fn run_task_stops_retrying_once_its_own_task_is_aborted() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accept_count = Arc::new(AtomicU32::new(0));
    {
        let accept_count = accept_count.clone();
        tokio::spawn(async move {
            // Every connection is closed immediately — every attempt
            // `run` makes fails fast and moves on to backoff.
            while let Ok((stream, _)) = listener.accept().await {
                accept_count.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
    }

    let state = test_state();
    let config = OrchestratorConfig {
        coordination_addr: format!("http://{addr}"),
        auth: yadorilink_fapi_client::test_support::offline_auth(),
        device_id: "local-device".into(),
    };

    let handle = tokio::spawn(run(config, Arc::clone(&state)));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while accept_count.load(Ordering::SeqCst) == 0 {
        assert!(tokio::time::Instant::now() < deadline, "run never attempted to connect");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    handle.abort();
    let count_at_abort = accept_count.load(Ordering::SeqCst);
    let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;

    // Backoff's initial delay is ~1s; a detached retry loop still
    // running would have made at least one more attempt within this window.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        accept_count.load(Ordering::SeqCst),
        count_at_abort,
        "a connection attempt happened after run's own task was aborted — the reconnect loop is still running detached"
    );
}

/// A long-lived stream that ends (the machine woke from sleep) must redial
/// quickly, however many outages came before; a stream that dies at once keeps
/// climbing the backoff.
#[test]
fn a_healthy_stream_resets_the_reconnect_backoff() {
    assert_eq!(attempt_after_stream(9, Duration::from_secs(3600)), 0);
    assert_eq!(attempt_after_stream(9, HEALTHY_STREAM), 0);
    assert_eq!(attempt_after_stream(3, Duration::from_secs(2)), 3);
}

/// The netmap connection carries TCP keepalive probes, so a connection that
/// died silently (sleep, Wi-Fi switch, IP change) errors instead of hanging.
#[tokio::test]
async fn netmap_connection_enables_tcp_keepalive() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stream = tokio::net::TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
    assert!(!socket2::SockRef::from(&stream).keepalive().unwrap());
    ws_netmap::enable_dead_peer_detection(&stream).unwrap();
    let sock = socket2::SockRef::from(&stream);
    assert!(sock.keepalive().unwrap());
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    assert_eq!(sock.tcp_keepalive_time().unwrap(), Duration::from_secs(30));
}

/// `reconnect_delay` is the pure function driving `run`'s inline backoff —
/// test its growth/cap behavior directly rather than through live networking.
/// ±25% jitter means exact values aren't checked, only that consecutive
/// attempts clearly grow and the schedule is eventually capped at
/// `BackoffConfig::RECONNECT.max`, preventing tight busy-retry loops
/// or unbounded growth.
#[test]
fn reconnect_delay_grows_then_caps_at_the_configured_max() {
    let d0 = reconnect_delay(0);
    let d1 = reconnect_delay(1);
    let d2 = reconnect_delay(2);
    assert!(
        d0 >= Duration::from_millis(500),
        "attempt 0 delay {d0:?} looks like a tight retry loop, not ~1s initial backoff"
    );
    assert!(d1 > d0, "attempt 1 delay {d1:?} did not grow past attempt 0's {d0:?}");
    assert!(d2 > d1, "attempt 2 delay {d2:?} did not grow past attempt 1's {d1:?}");

    let d_far = reconnect_delay(50);
    assert!(
        d_far <= BackoffConfig::RECONNECT.max,
        "a far-future attempt's delay {d_far:?} exceeded the configured cap {:?}",
        BackoffConfig::RECONNECT.max
    );
}

/// *starts* and *continues* in the first place.
#[tokio::test]
async fn run_resubscribes_repeatedly_after_a_simulated_drop() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accept_count = Arc::new(AtomicU32::new(0));
    {
        let accept_count = accept_count.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                accept_count.fetch_add(1, Ordering::SeqCst);
                drop(stream); // simulate the coordination server dropping the connection
            }
        });
    }

    let state = test_state();
    let config = OrchestratorConfig {
        coordination_addr: format!("http://{addr}"),
        auth: yadorilink_fapi_client::test_support::offline_auth(),
        device_id: "local-device".into(),
    };

    let handle = tokio::spawn(run(config, Arc::clone(&state)));

    let first_batch_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while accept_count.load(Ordering::SeqCst) == 0 {
        assert!(
            tokio::time::Instant::now() < first_batch_deadline,
            "run never attempted to connect at all"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let count_after_first_attempt = accept_count.load(Ordering::SeqCst);

    // Give the reconnect loop real time to sleep out its backoff and
    // come back for another try — proves this isn't a one-shot
    // "fail once and give up forever" path.
    //
    let second_batch_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while accept_count.load(Ordering::SeqCst) <= count_after_first_attempt {
        assert!(
            tokio::time::Instant::now() < second_batch_deadline,
            "run made {count_after_first_attempt} connection attempt(s) then stopped retrying — no re-subscription after a drop"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    handle.abort();
}

/// What a restart taken while the coordination plane is unreachable can
/// still admit.
///
/// The last-known-good peer authorization makes an already-authorized peer
/// dialable again after such a restart. On its own that is a connection that
/// cannot carry data: an introduced group with no verified policy resolves
/// to `Withhold`, so nothing is admitted for it until a netmap arrives --
/// which offline never does. These tests cover the other half: the signed
/// policy chains this device already verified are re-verified from disk at
/// startup, against the coordination service key it has pinned and the
/// rollback watermark it has persisted.
mod offline_group_policy {
    use super::*;
    use crate::change_policy::policy_signing::signed_writer_grant_log;
    use crate::daemon_state::GroupPolicyResolution;
    use ed25519_dalek::SigningKey;

    const ENDPOINT: &str = "https://coordination.test";
    const GROUP: &str = "group-1";
    const PEER: &str = "device-b";

    /// One device's durable state, outliving any single `DaemonState` built
    /// over it exactly as a real device's disk outlives its daemon process.
    struct Device {
        database: tempfile::TempDir,
        blocks: tempfile::TempDir,
    }

    impl Device {
        fn new() -> Self {
            Self { database: tempfile::tempdir().unwrap(), blocks: tempfile::tempdir().unwrap() }
        }

        fn start(&self) -> Arc<DaemonState> {
            let coordinator =
                Arc::new(ReplicaCoordinator::open(self.database.path().join("index.db")).unwrap());
            let blocks = Arc::new(SegmentBlockStore::new(self.blocks.path()).unwrap());
            DaemonState::new("device-a".into(), coordinator, blocks)
        }
    }

    fn authority() -> SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    /// Applies one netmap frame's policy through the real live path.
    ///
    /// The pin map is pre-seeded with this endpoint's key, so the decision is
    /// "already pinned" and nothing writes to the process-wide config
    /// directory; every other step -- verification, the rollback watermark,
    /// the stored chain, the trusted set -- is the production one.
    fn apply_live_policy_frame(
        state: &Arc<DaemonState>,
        authority: &SigningKey,
        logs: &[crate::change_policy::GroupPolicyLog],
    ) {
        let key = authority.verifying_key().to_bytes();
        let mut pins = HashMap::from([(ENDPOINT.to_string(), hex::encode(key))]);
        record_group_policy_states(state, ENDPOINT, &mut pins, &key, logs)
            .expect("the frame is well-formed");
    }

    fn writer_grant_log(authority: &SigningKey) -> crate::change_policy::GroupPolicyLog {
        signed_writer_grant_log(authority, GROUP, &[(PEER, [3u8; 32])])
    }

    /// The requirement: a group whose policy this device verified before the
    /// restart is verified again after it, with no plane to ask.
    #[tokio::test]
    async fn a_verified_group_policy_survives_a_restart_taken_offline() {
        let device = Device::new();
        let authority = authority();
        {
            let first = device.start();
            apply_live_policy_frame(&first, &authority, &[writer_grant_log(&authority)]);
            assert!(
                matches!(
                    first.authority.resolve_group_policy(GROUP, || true),
                    GroupPolicyResolution::Verified(_)
                ),
                "sanity check: the live frame verifies the group"
            );
        }

        let restarted = device.start();
        assert!(
            matches!(
                restarted.authority.resolve_group_policy(GROUP, || true),
                GroupPolicyResolution::Withhold
            ),
            "sanity check: a restarted daemon starts with nothing verified"
        );

        restore_group_policy_states_verified_by(&restarted, authority.verifying_key().to_bytes());

        match restarted.authority.resolve_group_policy(GROUP, || true) {
            GroupPolicyResolution::Verified(policy) => assert_eq!(
                policy
                    .current_writers()
                    .into_iter()
                    .map(|writer| writer.device_id)
                    .collect::<Vec<_>>(),
                vec![PEER.to_string()],
                "the restored policy must carry the writer set the plane granted"
            ),
            _ => panic!(
                "a group whose signed policy this device verified before the restart must be \
                 verified after it, or the rediscovered peer has nothing it may admit"
            ),
        }
    }

    /// The stored chain is bytes, not a decision: it is believed only
    /// because it verifies. Under a different service key it verifies
    /// against nothing and the group stays withheld.
    #[tokio::test]
    async fn a_stored_chain_is_not_restored_under_a_service_key_that_did_not_sign_it() {
        let device = Device::new();
        let authority = authority();
        {
            let first = device.start();
            apply_live_policy_frame(&first, &authority, &[writer_grant_log(&authority)]);
        }

        let restarted = device.start();
        let impostor = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        restore_group_policy_states_verified_by(&restarted, impostor.verifying_key().to_bytes());

        assert!(
            matches!(
                restarted.authority.resolve_group_policy(GROUP, || true),
                GroupPolicyResolution::Withhold
            ),
            "a chain that does not verify against the pinned service key must not be restored"
        );
    }

    /// A chain a live frame stopped trusting is not left on disk for the
    /// next restart to fall back on.
    #[tokio::test]
    async fn a_chain_whose_snapshot_failed_verification_is_not_restorable() {
        let device = Device::new();
        let authority = authority();
        {
            let first = device.start();
            apply_live_policy_frame(&first, &authority, &[writer_grant_log(&authority)]);

            // The same group, presented with a record whose signature has
            // been tampered with: the live path marks the group stale and
            // must drop the stored chain with it.
            let mut tampered = writer_grant_log(&authority);
            tampered.records[0].signature[0] ^= 0xff;
            apply_live_policy_frame(&first, &authority, &[tampered]);
            assert!(
                first.authority.is_group_policy_stale(GROUP),
                "sanity check: the tampered frame marks the group stale"
            );
        }

        let restarted = device.start();
        restore_group_policy_states_verified_by(&restarted, authority.verifying_key().to_bytes());

        assert!(
            matches!(
                restarted.authority.resolve_group_policy(GROUP, || true),
                GroupPolicyResolution::Withhold
            ),
            "a group this device stopped trusting must not come back trusted after a restart"
        );
    }

    /// A netmap frame on an established connection carries only the records
    /// after the base the daemon already holds, not the whole chain. A tail
    /// stored as if it were a chain is not one: a restart verifies from
    /// scratch, with no base to continue from, and would refuse it for
    /// starting at the wrong sequence. So the tail is merged onto what is
    /// stored before it is written.
    #[tokio::test]
    async fn a_forward_extension_is_stored_as_the_whole_chain_it_extends() {
        use crate::change_policy::policy_signing::grant_record;
        use crate::change_policy::WriterRole;

        let device = Device::new();
        let authority = authority();
        let second_peer = "device-c";
        {
            let first = device.start();
            let genesis = writer_grant_log(&authority);
            let genesis_head: [u8; 32] =
                genesis.records[0].record_hash.as_slice().try_into().unwrap();
            apply_live_policy_frame(&first, &authority, &[genesis]);

            // What the plane sends next on the SAME connection: record 2
            // alone, to be verified against the base already held.
            let extension = grant_record(
                &authority,
                GROUP,
                2,
                genesis_head,
                second_peer,
                [4u8; 32],
                WriterRole::Editor,
            );
            let head = extension.record_hash.clone();
            apply_live_policy_frame(
                &first,
                &authority,
                &[crate::change_policy::GroupPolicyLog {
                    group_id: GROUP.to_string(),
                    current_seq: 2,
                    current_epoch: 0,
                    policy_head: head,
                    records: vec![extension],
                }],
            );
        }

        let restarted = device.start();
        restore_group_policy_states_verified_by(&restarted, authority.verifying_key().to_bytes());

        match restarted.authority.resolve_group_policy(GROUP, || true) {
            GroupPolicyResolution::Verified(policy) => {
                let mut writers = policy
                    .current_writers()
                    .into_iter()
                    .map(|writer| writer.device_id)
                    .collect::<Vec<_>>();
                writers.sort();
                assert_eq!(
                    writers,
                    vec![PEER.to_string(), second_peer.to_string()],
                    "the restored chain must carry every grant, not just the last frame's"
                );
            }
            _ => panic!(
                "a chain extended frame by frame while online must still verify as a whole \
                 chain after a restart"
            ),
        }
    }

    /// Signing out leaves no policy to continue either.
    #[tokio::test]
    async fn signing_out_deletes_the_stored_policy_chains() {
        let device = Device::new();
        let authority = authority();
        {
            let first = device.start();
            apply_live_policy_frame(&first, &authority, &[writer_grant_log(&authority)]);
            first.forget_offline_peer_authorization();
            assert!(
                matches!(
                    first.authority.resolve_group_policy(GROUP, || true),
                    GroupPolicyResolution::Withhold
                ),
                "sanity check: the running daemon stops trusting the group immediately"
            );
        }

        let restarted = device.start();
        restore_group_policy_states_verified_by(&restarted, authority.verifying_key().to_bytes());

        assert!(
            matches!(
                restarted.authority.resolve_group_policy(GROUP, || true),
                GroupPolicyResolution::Withhold
            ),
            "nothing about a signed-out device's groups may survive on disk"
        );
    }
}

/// A checkpoint source that counts the requests it receives, so a test can
/// tell a flush that was attempted from one that never ran.
struct CountingSource {
    inner: crate::test_support::sync_stack_fixture::FixtureCheckpointSource,
    requests: Arc<std::sync::atomic::AtomicUsize>,
}

impl crate::checkpoint_source::CheckpointSource for CountingSource {
    fn request_authorization_checkpoint<'a>(
        &'a self,
        group_id: &'a str,
        device_id: &'a str,
        request_id: &'a str,
        merkle_root: [u8; 32],
        leaf_count: u64,
        purpose: crate::checkpoint_source::CheckpointPurpose,
    ) -> crate::checkpoint_source::CheckpointFuture<'a> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        self.inner.request_authorization_checkpoint(
            group_id,
            device_id,
            request_id,
            merkle_root,
            leaf_count,
            purpose,
        )
    }
}

fn pending_native_count(state: &DaemonState, group: &str) -> usize {
    state
        .replica_coordinator
        .database()
        .read(|conn| {
            yadorilink_sync_sqlite::native_publication::pending_native_deltas_for_device(
                conn,
                &yadorilink_replica_domain::ids::FolderGroupId(group.into()),
                &state.device_id,
            )
        })
        .unwrap()
        .len()
}

async fn wait_until_nothing_pending(state: &DaemonState, group: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while pending_native_count(state, group) > 0 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

const POLICY_ENDPOINT: &str = "https://coordination.test";

/// A batch whose checkpoint pins a policy head ahead of this device's verified
/// chain cannot be verified, and stays pending. The frame that brings the
/// chain forward is what makes it publishable, with no further local edit:
/// the first flush is attempted and refused, and a second one is started by
/// the frame itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_policy_frame_that_catches_up_publishes_the_batch_that_could_not_verify() {
    use crate::change_policy::policy_signing::signed_writer_grant_log;
    use crate::native_test_support::{author_delta, DEVICE, GROUP};
    use crate::test_support::sync_stack_fixture::{
        authority_key, device, link_folder, FixtureCheckpointSource,
    };

    let (state, _dir) = device(DEVICE, 9);
    let root = tempfile::tempdir().unwrap();
    let _canonical = link_folder(&state, root.path());

    let authority = authority_key();
    let service_key = authority.verifying_key().to_bytes();
    let own_key = state.device_signing_key().unwrap().verifying_key().to_bytes();
    let behind = signed_writer_grant_log(&authority, GROUP, &[(DEVICE, own_key)]);
    let ahead =
        signed_writer_grant_log(&authority, GROUP, &[(DEVICE, own_key), ("device-b", [3; 32])]);
    let mut pins = HashMap::from([(POLICY_ENDPOINT.to_string(), hex::encode(service_key))]);

    // Installed directly: a live frame would spawn a flush of its own that
    // could run after the delta below exists and publish it.
    let installed = crate::change_policy::verify_group_policy_log(&service_key, &behind).unwrap();
    state.authority.replace_group_policy_states(HashMap::from([(GROUP.to_string(), installed)]));
    author_delta(&state.replica_coordinator.database(), 1, "a.txt");
    let head: [u8; 32] = ahead.policy_head.as_slice().try_into().unwrap();
    let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    *state.test_seal_checkpoint_source.lock().unwrap() = Some(Arc::new(CountingSource {
        inner: FixtureCheckpointSource::for_device(&state).at_policy_point(2, head),
        requests: requests.clone(),
    }));

    state.flush_pending_native_checkpoint_for_group_for_test(GROUP).await;
    assert_eq!(requests.load(Ordering::SeqCst), 1, "the first flush was attempted");
    assert_eq!(
        pending_native_count(&state, GROUP),
        1,
        "the checkpoint names a head this device has not verified yet"
    );

    record_group_policy_states(&state, POLICY_ENDPOINT, &mut pins, &service_key, &[ahead]).unwrap();
    wait_until_nothing_pending(&state, GROUP).await;
    assert_eq!(pending_native_count(&state, GROUP), 0, "the frame publishes the batch");
    assert_eq!(requests.load(Ordering::SeqCst), 2, "by a second flush the frame started");
}

/// A device restarted with a batch still pending, whose plane connection comes
/// back, publishes it with no local edit. Two orders are possible and both
/// are proved: the restored policy chain is already verified when the
/// connection flush runs (the flush itself publishes), or it is not (the
/// flush finds no verified policy and does nothing, and the first live frame
/// carrying the chain, which advances it from nothing, starts the flush).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_batch_pending_across_a_restart_is_published_once_the_plane_is_back() {
    use crate::change_policy::policy_signing::signed_writer_grant_log;
    use crate::native_test_support::{author_delta, DEVICE, GROUP};
    use crate::test_support::sync_stack_fixture::{authority_key, FixtureCheckpointSource};

    let authority = authority_key();
    let service_key = authority.verifying_key().to_bytes();
    let own_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_bytes();
    let chain = signed_writer_grant_log(&authority, GROUP, &[(DEVICE, own_key)]);
    let head: [u8; 32] = chain.policy_head.as_slice().try_into().unwrap();

    for restored_before_connect in [true, false] {
        let database = tempfile::tempdir().unwrap();
        let blocks = tempfile::tempdir().unwrap();
        let folder = tempfile::tempdir().unwrap();
        let start = || {
            let coordinator =
                Arc::new(ReplicaCoordinator::open(database.path().join("sync.sqlite3")).unwrap());
            let store = Arc::new(SegmentBlockStore::new(blocks.path()).unwrap());
            let state = DaemonState::new(DEVICE.into(), coordinator, store);
            state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]));
            state
        };

        // Before the restart: the chain was verified and stored, the folder is
        // linked, and a local change was authored but never published.
        let first = start();
        let _linked = crate::test_support::sync_stack_fixture::link_folder(&first, folder.path());
        let mut pins = HashMap::from([(POLICY_ENDPOINT.to_string(), hex::encode(service_key))]);
        record_group_policy_states(
            &first,
            POLICY_ENDPOINT,
            &mut pins,
            &service_key,
            std::slice::from_ref(&chain),
        )
        .unwrap();
        author_delta(&first.replica_coordinator.database(), 1, "a.txt");
        first.stop_background_tasks_for_tests();
        first.release_reference_cycles_for_tests();
        drop(first);

        // After the restart.
        let second = start();
        assert_eq!(pending_native_count(&second, GROUP), 1, "the batch survived the restart");
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        *second.test_seal_checkpoint_source.lock().unwrap() = Some(Arc::new(CountingSource {
            inner: FixtureCheckpointSource::for_device(&second).at_policy_point(1, head),
            requests: requests.clone(),
        }));
        if restored_before_connect {
            restore_group_policy_states_verified_by(&second, service_key);
        }
        // What the reconnect hook runs for each linked group, awaited so
        // nothing is left to race the frame below.
        second.flush_pending_native_checkpoint_for_group_for_test(GROUP).await;
        if !restored_before_connect {
            assert_eq!(pending_native_count(&second, GROUP), 1, "no verified policy, no flush");
            assert_eq!(requests.load(Ordering::SeqCst), 0);
            // The first live frame carries the whole chain again.
            let mut pins = HashMap::from([(POLICY_ENDPOINT.to_string(), hex::encode(service_key))]);
            record_group_policy_states(
                &second,
                POLICY_ENDPOINT,
                &mut pins,
                &service_key,
                std::slice::from_ref(&chain),
            )
            .unwrap();
        }
        wait_until_nothing_pending(&second, GROUP).await;
        assert_eq!(
            pending_native_count(&second, GROUP),
            0,
            "published with no local edit (restored before connect: {restored_before_connect})"
        );
        assert!(requests.load(Ordering::SeqCst) >= 1);
        second.stop_background_tasks_for_tests();
        second.release_reference_cycles_for_tests();
    }
}

/// A netmap upgrade answered with the exact `403 terms_consent_required` body of the coordination
/// service: the attempt fails, the credential learns the block (status shows it), and nothing the
/// device knows is withdrawn (peers and authorization stay).
#[tokio::test]
async fn a_consent_refused_netmap_upgrade_is_remembered_and_withdraws_nothing() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let body = r#"{"error":"terms_consent_required","terms_version":"placeholder-v0","message":"m"}"#;
            let response = format!(
                "HTTP/1.1 403 Forbidden\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });

    let state = test_state();
    state.seed_netmap_peer_identity("device-b", Some([7u8; 32]));
    let config = OrchestratorConfig {
        coordination_addr: format!("http://{addr}"),
        auth: yadorilink_fapi_client::test_support::offline_auth(),
        device_id: "local-device".into(),
    };
    assert_eq!(config.auth.block(), None);
    let diff_state = NetmapDiffState::seeded_from_current_authorization(&state);

    let outcome = run_netmap_attempt(&config, &state, &diff_state).await;

    assert!(outcome.is_err(), "a refused upgrade is a failed attempt");
    assert_eq!(
        config.auth.block(),
        Some(yadorilink_fapi_client::CoordinationBlock::TermsConsentRequired {
            terms_version: Some("placeholder-v0".into())
        })
    );
    assert_eq!(state.authority.peer_signing_key("device-b"), Some([7u8; 32]));
}

/// While blocked the loop waits at least a minute between attempts, however fresh its backoff.
#[test]
fn a_blocked_coordination_service_is_retried_no_faster_than_once_a_minute() {
    for attempt in 0..4 {
        assert!(reconnect_delay_for(attempt, true) >= BLOCKED_RECONNECT_DELAY);
    }
    assert!(reconnect_delay_for(0, false) < BLOCKED_RECONNECT_DELAY);
}

/// The refusal's body may arrive after its headers; it is then not recognised (and must not clear
/// anything), but the 403 alone still slows the loop down.
#[tokio::test]
async fn a_forbidden_upgrade_with_a_late_body_is_not_misread_and_still_backs_off() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let body = r#"{"error":"terms_consent_required","terms_version":"v"}"#;
            let head = format!(
                "HTTP/1.1 403 Forbidden\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.flush().await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            let _ = stream.write_all(body.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });
    let state = test_state();
    let config = OrchestratorConfig {
        coordination_addr: format!("http://{addr}"),
        auth: yadorilink_fapi_client::test_support::offline_auth(),
        device_id: "local-device".into(),
    };
    let diff_state = NetmapDiffState::seeded_from_current_authorization(&state);
    // A block learned earlier from a complete refusal stays: the unread body clears nothing.
    config.auth.observe_status(403, br#"{"error":"terms_consent_required","terms_version":"v"}"#);
    let error = run_netmap_attempt(&config, &state, &diff_state).await.expect_err("refused");
    assert!(upgrade_was_forbidden(&error), "{error}");
    assert!(!upgrade_was_forbidden(&DaemonError::Config("x".into())));
    assert!(config.auth.block().is_some(), "an unreadable 403 body must not lift the block");
    // The loop's wiring: a forbidden upgrade or a block waits the full blocked delay, an ordinary
    // failure or a clean end does not.
    assert!(reconnect_delay_after(0, false, Some(&error)) >= BLOCKED_RECONNECT_DELAY);
    assert!(reconnect_delay_after(0, true, None) >= BLOCKED_RECONNECT_DELAY);
    assert!(reconnect_delay_after(0, false, None) < BLOCKED_RECONNECT_DELAY);
    assert!(
        reconnect_delay_after(0, false, Some(&DaemonError::Config("x".into())))
            < BLOCKED_RECONNECT_DELAY
    );
}
