//! A metered connection pauses peer traffic: the sessions close and stay closed, and come back
//! when the setting or the connection allows it.

use std::sync::Arc;
use std::time::Duration;

use yadorilink_sync_substrate::NetworkConfig;

use crate::network_policy::NetworkCost;
use crate::sync_adapter::driver::PeerSessionDriver;
use crate::sync_adapter::sync_stack::SyncStack;
use crate::test_support::sync_stack_fixture::{device, pin};

const ALICE: &str = "device-alice";
const BOB: &str = "device-bob";
const STEP: Duration = Duration::from_secs(20);

async fn within(mut check: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + STEP;
    while tokio::time::Instant::now() < deadline {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    check()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_metered_connection_pauses_the_sessions_until_it_is_allowed() {
    let (alice, _alice_dir) = device(ALICE, 11);
    let (bob, _bob_dir) = device(BOB, 22);
    pin(&alice, BOB, 22);
    pin(&bob, ALICE, 11);
    let alice_stack =
        Arc::new(SyncStack::spawn(alice.clone(), NetworkConfig::direct_only()).await.unwrap());
    let bob_stack =
        Arc::new(SyncStack::spawn(bob.clone(), NetworkConfig::direct_only()).await.unwrap());
    SyncStack::teach_each_other_for_tests(&alice_stack, &bob_stack);
    bob.install_peer_session_driver(PeerSessionDriver::start(bob.clone(), bob_stack));
    alice.install_peer_session_driver(PeerSessionDriver::start(alice.clone(), alice_stack));
    assert!(within(|| bob.peers.has_session(ALICE)).await, "setup: connected");

    bob.network_policy.report_cost(NetworkCost::Metered);
    assert!(within(|| !bob.peers.has_session(ALICE)).await, "metered: the session closes");
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(!bob.peers.has_session(ALICE), "and stays closed while the connection is metered");
    assert!(!bob.native_replication.is_attached(ALICE));

    bob.network_policy.set_sync_on_metered(true).unwrap();
    assert!(within(|| bob.peers.has_session(ALICE)).await, "allowed on metered: it returns");

    bob.network_policy.set_sync_on_metered(false).unwrap();
    assert!(within(|| !bob.peers.has_session(ALICE)).await, "paused again");
    bob.network_policy.report_cost(NetworkCost::Unmetered);
    assert!(within(|| bob.peers.has_session(ALICE)).await, "an unmetered connection: it returns");
}
