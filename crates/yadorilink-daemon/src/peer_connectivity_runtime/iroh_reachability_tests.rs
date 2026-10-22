//! A peer's reachability, produced by real iroh connections.
//!
//! The status contract tests pin what each reachability MEANS; these pin that
//! the running endpoint produces it. Two devices bind their endpoints through
//! `PeerConnectivityRuntime::bind_endpoint` exactly as a daemon does, connect
//! over iroh, and each one's runtime is asked what it now says about the
//! other: connected directly, connected through a relay, unreachable because a
//! dial had nowhere to go, and gone again once the connection is.
//!
//! Nothing here touches the legacy QUIC transport, and nothing sets a
//! reachability by hand.

use std::sync::Arc;
use std::time::Duration;

use yadorilink_sync_substrate::testing::InProcessRelay;
use yadorilink_sync_substrate::NetworkConfig;

use crate::daemon_state::DaemonState;
use crate::peer_registry::{PeerReachability, UnreachableCategory};
use crate::route::RouteKind;
use crate::sync_adapter::sync_stack::SyncStack;
use crate::test_support::sync_stack_fixture::{device, pin};

const ALICE: &str = "device-alice";
const BOB: &str = "device-bob";

/// How long any single network step may take before it counts as "no answer".
const STEP: Duration = Duration::from_secs(10);

struct Pair {
    alice: Arc<DaemonState>,
    bob: Arc<DaemonState>,
    alice_stack: SyncStack,
    bob_stack: SyncStack,
    _dirs: (
        crate::test_support::sync_stack_fixture::ReleasingDir,
        crate::test_support::sync_stack_fixture::ReleasingDir,
    ),
}

/// Two devices that pin each other, with endpoints bound under `alice_config`
/// and `bob_config`. Neither has been told where the other answers yet.
async fn pair(alice_config: NetworkConfig, bob_config: NetworkConfig) -> Pair {
    let (alice, alice_dir) = device(ALICE, 11);
    let (bob, bob_dir) = device(BOB, 22);
    pin(&alice, BOB, 22);
    pin(&bob, ALICE, 11);
    let alice_stack =
        SyncStack::spawn(alice.clone(), alice_config).await.expect("alice's stack starts");
    let bob_stack = SyncStack::spawn(bob.clone(), bob_config).await.expect("bob's stack starts");
    Pair { alice, bob, alice_stack, bob_stack, _dirs: (alice_dir, bob_dir) }
}

/// Waits until `state` reports `expected` for `peer`, failing with what it
/// reported last.
async fn reads(state: &DaemonState, peer: &str, expected: Option<PeerReachability>) {
    let deadline = tokio::time::Instant::now() + STEP;
    loop {
        let now = state.peer_connectivity.reachability(peer);
        if now == expected {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{} still reads {peer} as {now:?}, expected {expected:?}",
            state.device_id
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_direct_iroh_connection_reads_connected_direct_on_both_sides_until_it_ends() {
    let pair = pair(NetworkConfig::direct_only(), NetworkConfig::direct_only()).await;
    assert_eq!(pair.bob.peer_connectivity.reachability(ALICE), None, "precondition");
    SyncStack::teach_each_other_for_tests(&pair.alice_stack, &pair.bob_stack);

    let link = tokio::time::timeout(STEP, pair.bob_stack.link_to(ALICE))
        .await
        .expect("bob's dial must not hang")
        .expect("bob reaches alice");

    let direct = Some(PeerReachability::Connected(RouteKind::Direct));
    reads(&pair.bob, ALICE, direct).await;
    reads(&pair.alice, BOB, direct).await;
    assert_eq!(pair.alice.peer_connectivity.connected_peer_count(), 1);

    // The dialling side goes away. Its own view ends with its endpoint; the
    // accepting side learns it from the connection closing.
    drop(link);
    pair.bob_stack.shutdown().await;
    reads(&pair.alice, BOB, None).await;
    reads(&pair.bob, ALICE, None).await;
    assert_eq!(pair.alice.peer_connectivity.connected_peer_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_carried_only_by_a_relay_reads_connected_relay() {
    let relay = InProcessRelay::start().await.expect("in-process relay starts");
    let pair = pair(relay.direct_or_relay(), relay.relay_only()).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while pair.alice_stack.local_address().relay_urls().next().is_none() {
        assert!(tokio::time::Instant::now() < deadline, "alice never registered with the relay");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    SyncStack::teach_each_other_for_tests(&pair.alice_stack, &pair.bob_stack);

    let _link = tokio::time::timeout(STEP, pair.bob_stack.link_to(ALICE))
        .await
        .expect("bob's dial must not hang")
        .expect("bob reaches alice through the relay");

    let relayed = Some(PeerReachability::Connected(RouteKind::Relay));
    reads(&pair.bob, ALICE, relayed).await;
    reads(&pair.alice, BOB, relayed).await;
    assert_eq!(pair.bob.peer_connectivity.connected_peer_count(), 1, "a relayed peer counts");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dial_with_no_address_for_the_peer_reads_unreachable_for_that_reason() {
    let pair = pair(NetworkConfig::direct_only(), NetworkConfig::direct_only()).await;
    // Pinned, but nobody has said where Alice answers.

    let dialled = tokio::time::timeout(STEP, pair.bob_stack.link_to(ALICE))
        .await
        .expect("bob's dial must not hang");
    assert!(dialled.is_err(), "precondition: there was nowhere to dial");

    reads(&pair.bob, ALICE, Some(PeerReachability::Unreachable(UnreachableCategory::NoCandidates)))
        .await;
    let _ = &pair.alice;
}
