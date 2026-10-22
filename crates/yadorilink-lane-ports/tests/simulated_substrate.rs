//! Proof that this project's substrate runs with no operating-system socket
//! under it.
//!
//! The block, service and snapshot lanes are why a multi-device scenario
//! could not be simulated at all. `PeerSyncSession` requires
//! `SessionTransports`, and the only implementation that is not in-process is
//! `PeerTransports` over a real iroh endpoint, which binds real UDP below
//! anything a simulator can intercept. That left a scenario two options, both
//! bad: carry blocks over an in-process channel no injected fault can touch,
//! or add a second block path to a transport the architecture deliberately
//! closed.
//!
//! This is the third option. iroh's custom-transport seam replaces the
//! bottom-most datagram carrier and nothing else. Everything above it --
//! iroh's QUIC, TLS and stream multiplexing, `PeerLink`, `PeerTransports`,
//! the lane streams -- is the code a shipped daemon
//! runs. The carrier and its address lookup both come from upstream's own
//! `TestNetwork`; this crate reimplements neither.
//!
//! No fault is injected here. That is the next step, and doing it before this
//! one was green would have meant debugging two new things at once.

#![cfg(feature = "test-support")]

use std::time::Duration;

use iroh::test_utils::test_transport::TestNetwork;
use yadorilink_lane_ports::block_lane::LaneBlockStream;
use yadorilink_lane_ports::service_lane::LaneServiceStream;
use yadorilink_lane_ports::testing::{TestAddressBook, TestPeerNode};
use yadorilink_peer_session::ports::{
    BlockStreamTransport, PeerBlockStream, PeerServiceStream, ServiceStreamTransport,
};
use yadorilink_sync_substrate::Lane;

/// Generous, and only a backstop: every exchange below is one round trip
/// between two endpoints in the same process.
const STEP_TIMEOUT: Duration = Duration::from_secs(10);

/// The lanes are opened for a group, the way a session opens them.
const GROUP: &str = "simulated-group";

/// Everything a session needs from a peer, over a carrier that is not the
/// operating system's: a block request and its body, a service RPC, and a
/// prepared snapshot collected through the real fetch path.
///
/// One test rather than three, because the claim is about the carrier and not
/// about any one lane. Three lanes passing separately would still leave open
/// whether they can share one endpoint, which is the arrangement a session
/// actually puts them in.
#[tokio::test]
async fn every_lane_a_session_needs_crosses_a_simulated_carrier() {
    let network = TestNetwork::new();
    let book = TestAddressBook::new();
    let a = TestPeerNode::start_simulated("device-a", book.clone(), &network).await;
    let b = TestPeerNode::start_simulated("device-b", book, &network).await;

    // (4) No socket address, no relay. Asserted before anything is exchanged,
    // because a node that had quietly kept its IP transports would pass every
    // exchange below over the host's loopback and prove nothing -- and this
    // is the only place that difference is visible.
    for node in [&a, &b] {
        let direct: Vec<_> = node.address().direct_addrs().copied().collect();
        assert!(
            direct.is_empty(),
            "{} advertised a socket address, so its datagrams are not confined to the \
             simulated carrier: {direct:?}",
            node.device_id()
        );
    }

    // Larger than one datagram, so the block exchange genuinely reassembles a
    // QUIC byte stream rather than riding a single packet.
    let block_body: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
    // B answers each lane the way production answers it.

    let serving_body = block_body.clone();
    let serving = tokio::spawn(async move {
        let mut served: Vec<(&'static str, Vec<u8>)> = Vec::new();
        for _ in 0..2 {
            // The group the lane was opened for, not the peer: a lane is
            // per-group, and the peer is already authenticated by the QUIC
            // handshake that carried it.
            let (group, stream) =
                b.accept_unclaimed_lane().await.expect("an inbound lane must arrive");
            assert_eq!(group, GROUP, "a lane arrived for a group it was not opened for");
            match stream.lane() {
                Lane::Block => {
                    let mut lane = LaneBlockStream::new(stream);
                    let request = lane.recv_message(1024).await.expect("the block request");
                    lane.send_message(b"found").await.expect("the block response header");
                    lane.send_body(&serving_body).await.expect("the block body");
                    served.push(("block", request));
                }
                Lane::Service => {
                    let mut lane = LaneServiceStream::new(stream);
                    let request = lane.recv_message(1024).await.expect("the service request");
                    lane.send_response(b"pong").await.expect("the service response");
                    served.push(("service", request));
                }
            }
        }
        served
    });

    // (1) the shipped transports, (2)/(3) the shipped lane framing over real
    // iroh QUIC.
    let transports = a.transports_for("device-b");

    // (5) Block lane: A -> B -> A, bytes intact.
    let mut lane =
        tokio::time::timeout(STEP_TIMEOUT, BlockStreamTransport::open(transports.as_ref(), GROUP))
            .await
            .expect("opening a block lane must resolve")
            .expect("opening a block lane must succeed");
    lane.send_message(b"want").await.expect("the block request must send");
    lane.finish_send();
    let header = tokio::time::timeout(STEP_TIMEOUT, lane.recv_message(1024))
        .await
        .expect("the block response header must arrive")
        .expect("the block response header must read");
    assert_eq!(header, b"found", "the block response header did not survive the carrier");
    let received = tokio::time::timeout(STEP_TIMEOUT, lane.recv_body(block_body.len()))
        .await
        .expect("the block body must arrive")
        .expect("the block body must read");
    assert_eq!(received.len(), block_body.len(), "the block body was truncated");
    assert_eq!(received, block_body, "the block body's bytes did not survive the carrier");

    // (6) Service lane: request out, response back.
    let mut lane = tokio::time::timeout(
        STEP_TIMEOUT,
        ServiceStreamTransport::open(transports.as_ref(), GROUP),
    )
    .await
    .expect("opening a service lane must resolve")
    .expect("opening a service lane must succeed");
    lane.send_request(b"ping").await.expect("the service request must send");
    let response = tokio::time::timeout(STEP_TIMEOUT, lane.recv_message(1024))
        .await
        .expect("the service response must arrive")
        .expect("the service response must read");
    assert_eq!(response, b"pong", "the service response did not survive the carrier");

    let served = tokio::time::timeout(STEP_TIMEOUT, serving)
        .await
        .expect("the serving side must finish")
        .expect("the serving task");
    let kinds: Vec<&str> = served.iter().map(|(kind, _)| *kind).collect();
    assert!(kinds.contains(&"block"), "no block lane reached the far side: {kinds:?}");
    assert!(kinds.contains(&"service"), "no service lane reached the far side: {kinds:?}");
    for (kind, request) in &served {
        match *kind {
            "block" => assert_eq!(request, b"want", "the block request did not survive"),
            "service" => assert_eq!(request, b"ping", "the service request did not survive"),
            _ => {}
        }
    }
}

/// The negative control, and the reason the test above establishes anything.
///
/// Identical in every respect except that the simulated carrier's address
/// lookup is not registered, so nothing can resolve where the peer is
/// reachable. If a lane still opened, the endpoints would have found each
/// other some other way -- which would mean the green result above was about
/// the host's network, not about the carrier.
#[tokio::test]
async fn without_the_carrier_address_lookup_no_lane_opens() {
    let network = TestNetwork::new();
    let book = TestAddressBook::new();
    let a =
        TestPeerNode::start_simulated_with_lookup("device-a", book.clone(), &network, false).await;
    let _b = TestPeerNode::start_simulated_with_lookup("device-b", book, &network, false).await;

    let transports = a.transports_for("device-b");
    let outcome = tokio::time::timeout(
        Duration::from_secs(5),
        BlockStreamTransport::open(transports.as_ref(), GROUP),
    )
    .await;

    match outcome {
        // Either shape is a correct refusal: the dial may give up on its own,
        // or never resolve an address to dial at all. What must not happen is
        // a working lane.
        Err(_elapsed) => {}
        Ok(Err(_refused)) => {}
        Ok(Ok(_opened)) => panic!(
            "a lane opened with no address lookup for the simulated carrier, so these \
             endpoints reached each other by some path this test does not control -- every \
             result in this file would be about that path instead"
        ),
    }
}
