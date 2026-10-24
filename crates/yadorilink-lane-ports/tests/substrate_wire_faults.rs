//! One-way cuts, duplication and reordering on the simulated substrate.
//!
//! The symmetric partition is covered by `substrate_partition.rs`. These are
//! the wire faults it cannot express: a cut that stops one direction only, a
//! datagram delivered twice, and datagrams delivered out of order or late.
//! Each test shows the fault fired (a counter, or a request that did or did
//! not arrive) so a passing run cannot be a run in which nothing was
//! injected.

#![cfg(feature = "test-support")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use iroh::test_utils::test_transport::TestNetwork;
use yadorilink_lane_ports::block_lane::LaneBlockStream;
use yadorilink_lane_ports::sim_fault::{HoldPolicy, SimFaultController};
use yadorilink_lane_ports::testing::{TestAddressBook, TestPeerNode};
use yadorilink_peer_session::ports::{BlockStreamTransport, PeerBlockStream};
use yadorilink_sync_substrate::Lane;

const GROUP: &str = "wire-fault-group";
const HEALTHY_TIMEOUT: Duration = Duration::from_secs(20);
const CUT_TIMEOUT: Duration = Duration::from_secs(3);

struct Pair {
    a: Arc<TestPeerNode>,
    b: Arc<TestPeerNode>,
    a_id: iroh::EndpointId,
    b_id: iroh::EndpointId,
}

async fn pair(network: &TestNetwork, faults: &SimFaultController) -> Pair {
    let book = TestAddressBook::new();
    let (a, a_id) =
        TestPeerNode::start_simulated_with_faults("device-a", book.clone(), network, faults).await;
    let (b, b_id) =
        TestPeerNode::start_simulated_with_faults("device-b", book, network, faults).await;
    Pair { a, b, a_id, b_id }
}

/// Serves block lanes until aborted and counts the requests that arrived.
/// A request that arrives proves the requester-to-server direction carried.
fn serve(
    node: Arc<TestPeerNode>,
    body: Vec<u8>,
    arrived: Arc<AtomicUsize>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Some((_group, stream)) = node.accept_unclaimed_lane().await else { return };
            if stream.lane() != Lane::Block {
                continue;
            }
            let mut lane = LaneBlockStream::new(stream);
            let Ok(_request) = lane.recv_message(1024).await else { continue };
            arrived.fetch_add(1, Ordering::SeqCst);
            if lane.send_message(b"found").await.is_err() {
                continue;
            }
            let _ = lane.send_body(&body).await;
        }
    })
}

async fn round_trip(
    from: &Arc<TestPeerNode>,
    to_device: &str,
    expected: &[u8],
    budget: Duration,
) -> Option<Vec<u8>> {
    let transports = from.transports_for(to_device);
    let attempt = async {
        let mut lane = BlockStreamTransport::open(transports.as_ref(), GROUP).await.ok()?;
        lane.send_message(b"want").await.ok()?;
        lane.finish_send();
        if lane.recv_message(1024).await.ok()? != b"found" {
            return None;
        }
        lane.recv_body(expected.len()).await.ok()
    };
    tokio::time::timeout(budget, attempt).await.ok().flatten()
}

fn body(len: u32) -> Vec<u8> {
    (0..len).map(|i| ((i * 7) % 251) as u8).collect()
}

/// A->B cut: the request never arrives. B->A cut instead: the request
/// arrives and the answer does not. Healing one direction restores it.
#[tokio::test]
async fn a_one_way_cut_stops_exactly_one_direction() {
    let network = TestNetwork::new();
    let faults = SimFaultController::new();
    let p = pair(&network, &faults).await;
    let payload = body(4096);
    let arrived = Arc::new(AtomicUsize::new(0));
    let serving = serve(p.b.clone(), payload.clone(), arrived.clone());

    // Healthy first, so a later failure is the fault and not the setup.
    let got = round_trip(&p.a, "device-b", &payload, HEALTHY_TIMEOUT).await;
    assert_eq!(got.as_deref(), Some(payload.as_slice()), "the healthy lane must carry bytes");
    assert_eq!(arrived.load(Ordering::SeqCst), 1);

    // Reply direction cut: the request arrives, the answer cannot.
    faults.partition_one_way(p.b_id, p.a_id);
    let before = arrived.load(Ordering::SeqCst);
    let got = round_trip(&p.a, "device-b", &payload, CUT_TIMEOUT).await;
    assert!(got.is_none(), "an answer crossed the cut direction");
    assert!(
        arrived.load(Ordering::SeqCst) > before,
        "the request did not reach B although only B->A is cut: the cut is not one-way"
    );

    // Request direction cut: nothing reaches B.
    faults.heal_one_way(p.b_id, p.a_id);
    faults.partition_one_way(p.a_id, p.b_id);
    let before = arrived.load(Ordering::SeqCst);
    let got = round_trip(&p.a, "device-b", &payload, CUT_TIMEOUT).await;
    assert!(got.is_none(), "a lane completed although A cannot reach B");
    assert_eq!(arrived.load(Ordering::SeqCst), before, "a request crossed the cut direction");
    assert!(faults.dropped_datagrams() > 0, "no datagram was discarded: the fault did not fire");
    assert!(!faults.is_cut(p.b_id, p.a_id), "the reverse direction must stay open");

    faults.heal_one_way(p.a_id, p.b_id);
    // Healed: the same endpoints and network carry again.
    let got = round_trip(&p.a, "device-b", &payload, HEALTHY_TIMEOUT).await;
    assert_eq!(got.as_deref(), Some(payload.as_slice()), "the lane did not recover after heal");
    serving.abort();
}

/// Duplicated and reordered datagrams in both directions, over a body large
/// enough to span many datagrams: the bytes still arrive exactly once and
/// intact, and the counters show both faults fired.
#[tokio::test]
async fn duplicated_and_reordered_datagrams_still_deliver_exact_bytes() {
    for seed in 0..3u64 {
        let network = TestNetwork::new();
        let faults = SimFaultController::new();
        let p = pair(&network, &faults).await;
        faults.duplicate_datagrams(p.a_id, p.b_id, 2, seed);
        faults.duplicate_datagrams(p.b_id, p.a_id, 3, seed);
        let policy = HoldPolicy { every_nth: 3, release_after: 2, seed };
        faults.hold_inbound(p.a_id, policy);
        faults.hold_inbound(p.b_id, policy);

        let payload = body(256 * 1024);
        let arrived = Arc::new(AtomicUsize::new(0));
        let serving = serve(p.b.clone(), payload.clone(), arrived.clone());
        for round in 0..3 {
            let got = round_trip(&p.a, "device-b", &payload, HEALTHY_TIMEOUT).await;
            assert!(
                got.as_deref() == Some(payload.as_slice()),
                "seed {seed} round {round}: bytes changed or were lost under duplication and \
                 reordering"
            );
        }
        assert_eq!(arrived.load(Ordering::SeqCst), 3, "seed {seed}: a request was applied twice");
        assert!(faults.duplicated_datagrams() > 0, "seed {seed}: nothing was duplicated");
        assert!(faults.reordered_datagrams() > 0, "seed {seed}: nothing was reordered");
        serving.abort();
    }
}

/// The negative control for the counters: a controller told to do nothing
/// reports nothing.
#[tokio::test]
async fn an_idle_controller_duplicates_and_reorders_nothing() {
    let network = TestNetwork::new();
    let faults = SimFaultController::new();
    let p = pair(&network, &faults).await;
    let payload = body(64 * 1024);
    let arrived = Arc::new(AtomicUsize::new(0));
    let serving = serve(p.b.clone(), payload.clone(), arrived);
    let got = round_trip(&p.a, "device-b", &payload, HEALTHY_TIMEOUT).await;
    assert_eq!(got.as_deref(), Some(payload.as_slice()));
    assert_eq!(faults.duplicated_datagrams(), 0);
    assert_eq!(faults.reordered_datagrams(), 0);
    serving.abort();
}
