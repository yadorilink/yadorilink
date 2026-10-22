//! A peer that completes the transport but whose lane hello speaks another protocol version is
//! reachable-but-incompatible in the engine status model, never offline; a peer nobody can
//! connect to is still offline.

use std::sync::Arc;
use std::time::Duration;

use yadorilink_sync_protocol::PROTOCOL_VERSION;
use yadorilink_sync_substrate::{Lane, NetworkConfig};

use crate::peer_registry::PeerReachability;
use crate::sync_adapter::sync_stack::SyncStack;
use crate::test_support::sync_stack_fixture::{device, pin};

const STEP: Duration = Duration::from_secs(10);
const ALICE: &str = "device-alice";
const BOB: &str = "device-bob";

/// A raw lane hello claiming `version`.
fn hello_frame_at_version(version: u32) -> Vec<u8> {
    let mut body = version.to_be_bytes().to_vec();
    body.extend_from_slice(&1u16.to_be_bytes());
    body.push(b'g');
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    frame
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_on_another_protocol_version_is_incompatible_and_still_reachable() {
    for theirs in [PROTOCOL_VERSION + 1, PROTOCOL_VERSION - 1] {
        let (alice, _alice_dir) = device(ALICE, 11);
        let (bob, _bob_dir) = device(BOB, 22);
        pin(&alice, BOB, 22);
        pin(&bob, ALICE, 11);
        let alice_stack =
            Arc::new(SyncStack::spawn(alice.clone(), NetworkConfig::direct_only()).await.unwrap());
        let bob_stack =
            Arc::new(SyncStack::spawn(bob.clone(), NetworkConfig::direct_only()).await.unwrap());
        SyncStack::teach_each_other_for_tests(&alice_stack, &bob_stack);
        alice_stack.serve_peer_lanes();
        bob_stack.serve_peer_lanes();

        let link = tokio::time::timeout(STEP, bob_stack.link_to(ALICE))
            .await
            .expect("bob's dial must not hang")
            .expect("bob reaches alice");
        assert!(!alice.peer_connectivity.is_version_incompatible(BOB), "setup: compatible so far");

        let mut lane = link.open_lane(Lane::Service).await.expect("a lane opens");
        tokio::io::AsyncWriteExt::write_all(&mut lane, &hello_frame_at_version(theirs))
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::flush(&mut lane).await.unwrap();

        let deadline = tokio::time::Instant::now() + STEP;
        while !alice.peer_connectivity.is_version_incompatible(BOB) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "alice never reported bob (hello version {theirs}) as incompatible"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // The path a fresh connection uses is selected a moment after it opens, so for that
        // moment the peer reads "connecting"; it must reach "connected" and never "unreachable".
        let connected_by = tokio::time::Instant::now() + STEP;
        loop {
            match alice.peer_connectivity.reachability(BOB) {
                Some(PeerReachability::Connected(_)) => break,
                Some(PeerReachability::Unreachable(why)) => panic!(
                    "an incompatible peer is online: it must never read as unreachable ({why:?})"
                ),
                other => assert!(
                    tokio::time::Instant::now() < connected_by,
                    "alice never read bob as connected (last: {other:?})"
                ),
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreachable_peer_is_not_marked_incompatible() {
    let (alice, _dir) = device(ALICE, 11);
    pin(&alice, BOB, 22);
    alice.peer_connectivity.record_version_incompatible(BOB);
    assert!(!alice.peer_connectivity.is_version_incompatible(BOB), "no connection, no verdict");
}
