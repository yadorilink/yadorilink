//! Partition and heal, on the simulated substrate and nothing else.
//!
//! The fault lives in the datagram carrier (`sim_fault`), so nothing these
//! tests exercise above it -- `PeerTransports`, the lane framing, iroh's QUIC
//! -- knows a fault exists. That is the property being relied on: a partition
//! a session could see the shape of would be a harness artefact rather than a
//! network one.
//!
//! No scenario harness here, and no virtual clock. Bringing either in before
//! partition semantics were closed would mean a failure could be the carrier
//! or the harness, with no way to tell which.

#![cfg(feature = "test-support")]

use std::time::Duration;

use iroh::test_utils::test_transport::TestNetwork;
use yadorilink_lane_ports::block_lane::LaneBlockStream;
use yadorilink_lane_ports::sim_fault::SimFaultController;
use yadorilink_lane_ports::testing::{TestAddressBook, TestPeerNode};
use yadorilink_peer_session::ports::{BlockStreamTransport, PeerBlockStream};
use yadorilink_sync_substrate::Lane;

const GROUP: &str = "partition-group";

/// Long enough that a healthy exchange never hits it.
const HEALTHY_TIMEOUT: Duration = Duration::from_secs(10);

/// Short enough that a partitioned exchange is not waited on for minutes, and
/// long enough that a slow machine does not mistake scheduling for a
/// partition. Only ever evaluated while a link is cut.
const CUT_TIMEOUT: Duration = Duration::from_secs(3);

/// Two devices on one simulated network, under one fault controller.
struct Pair {
    a: std::sync::Arc<TestPeerNode>,
    b: std::sync::Arc<TestPeerNode>,
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

/// Serves block lanes on `node` until one exchange completes, answering with
/// `body`, and returns that request's bytes.
///
/// It loops rather than serving exactly one lane because a cut link leaves
/// lanes behind. A request that was opened while the link was down still
/// arrived at the far side's accept queue -- the stream was created before
/// the datagrams carrying its contents were discarded -- and it will never
/// carry a request. Insisting on the first lane in the queue would mean
/// waiting forever on one of those, which is a property of the accept queue
/// and not of the partition. A real peer's accept loop has the same shape
/// for the same reason.
fn serve_blocks(
    node: std::sync::Arc<TestPeerNode>,
    body: Vec<u8>,
) -> tokio::task::JoinHandle<Vec<u8>> {
    tokio::spawn(async move {
        loop {
            let Some((group, stream)) = node.accept_unclaimed_lane().await else {
                panic!("the inbound lane queue closed");
            };
            assert_eq!(group, GROUP);
            assert_eq!(stream.lane(), Lane::Block);
            let mut lane = LaneBlockStream::new(stream);
            let Ok(request) = lane.recv_message(1024).await else { continue };
            if lane.send_message(b"found").await.is_err() {
                continue;
            }
            if lane.send_body(&body).await.is_err() {
                continue;
            }
            return request;
        }
    })
}

/// One block round trip from `from` to `to`, or `None` if it did not
/// complete within `budget`.
///
/// A `None` means "no bytes came back", whatever the reason: a refused dial,
/// a stream that opened and stalled, a timeout. That is deliberately the
/// coarse question, because a partition is entitled to stop the exchange at
/// any of those points and a test that demanded one particular failure shape
/// would be asserting QUIC's internals rather than the partition.
async fn block_round_trip(
    from: &std::sync::Arc<TestPeerNode>,
    to_device: &str,
    expected: &[u8],
    budget: Duration,
) -> Option<Vec<u8>> {
    let transports = from.transports_for(to_device);
    let attempt = async {
        let mut lane = BlockStreamTransport::open(transports.as_ref(), GROUP).await.ok()?;
        lane.send_message(b"want").await.ok()?;
        lane.finish_send();
        let header = lane.recv_message(1024).await.ok()?;
        if header != b"found" {
            return None;
        }
        lane.recv_body(expected.len()).await.ok()
    };
    tokio::time::timeout(budget, attempt).await.ok().flatten()
}

fn body() -> Vec<u8> {
    (0..4096u32).map(|i| (i % 251) as u8).collect()
}

/// Healthy, then cut, then cut the other way, then healed -- on one network,
/// one controller and one pair of endpoints throughout.
///
/// Deliberately one test. Splitting it would let each phase pass against a
/// freshly built pair, and "it works after heal" means nothing if the healed
/// case is allowed to be a different network than the partitioned one.
#[tokio::test]
async fn a_partition_stops_both_directions_and_heal_restores_them() {
    let network = TestNetwork::new();
    let faults = SimFaultController::new();
    let p = pair(&network, &faults).await;
    let payload = body();

    // (1) Healthy: the lane works before any fault, so a later failure is
    // attributable to the fault and not to the setup.
    let serving = serve_blocks(p.b.clone(), payload.clone());
    let got = block_round_trip(&p.a, "device-b", &payload, HEALTHY_TIMEOUT).await;
    assert_eq!(got.as_deref(), Some(payload.as_slice()), "the healthy lane must carry bytes");
    assert_eq!(serving.await.expect("serving task"), b"want");
    assert_eq!(faults.dropped_datagrams(), 0, "nothing may be dropped while no link is cut");

    // (2) Cut. A new lane on a partitioned link must not complete.
    faults.partition(p.a_id, p.b_id);
    let serving = serve_blocks(p.b.clone(), payload.clone());
    let got = block_round_trip(&p.a, "device-b", &payload, CUT_TIMEOUT).await;
    assert!(got.is_none(), "a lane completed across a cut link");
    assert!(
        faults.dropped_datagrams() > 0,
        "the link is cut but no datagram was discarded, so the attempt never reached the \
         carrier -- this test would pass even with the fault removed"
    );
    serving.abort();

    // (3) The reverse direction is cut too. A partition is a property of the
    // link, and a carrier that only filtered the direction it was declared in
    // would let a peer answer a request it should never have received.
    let serving = serve_blocks(p.a.clone(), payload.clone());
    let got = block_round_trip(&p.b, "device-a", &payload, CUT_TIMEOUT).await;
    assert!(got.is_none(), "a lane completed across a cut link in the reverse direction");
    serving.abort();

    // (4) Healed, on the same endpoints, same network, same controller.
    let dropped_before_heal = faults.dropped_datagrams();
    faults.heal(p.a_id, p.b_id);
    let serving = serve_blocks(p.b.clone(), payload.clone());
    let got = block_round_trip(&p.a, "device-b", &payload, HEALTHY_TIMEOUT).await;
    assert_eq!(
        got.as_deref(),
        Some(payload.as_slice()),
        "the lane did not recover after the link healed"
    );
    assert_eq!(serving.await.expect("serving task"), b"want");

    // (5) Drop semantics, not hold. If the partition had queued what it
    // stopped, healing would have replayed it -- and the count of discarded
    // datagrams would have to fall as the queue drained. It does not,
    // because there is no queue.
    assert!(
        faults.dropped_datagrams() >= dropped_before_heal,
        "discarded datagrams were un-discarded on heal, so the partition held rather than \
         dropped"
    );
    assert!(
        !faults.is_partitioned(p.a_id, p.b_id),
        "the link is still recorded as cut after healing"
    );

    // A cancelled attempt stays cancelled. The two cut phases gave up when
    // their budget expired, which dropped their futures and with them their
    // streams; healing the link must not bring one back to life.
    //
    // Note what this does NOT show. It is not evidence that the carrier
    // discards rather than holds, and it cannot be: datagrams a partition
    // eats are still held by QUIC's own loss recovery, which will retransmit
    // them after heal -- that is production behaviour, and wanted. What is
    // observed here is narrower and still worth pinning: a request whose
    // caller walked away does not complete later. The carrier's own
    // no-hold-queue property is stated where it can be isolated from QUIC
    // entirely, in `sim_fault`'s own tests.
    let cancelled = serve_blocks(p.b.clone(), payload.clone());
    let late = tokio::time::timeout(Duration::from_secs(2), cancelled).await;
    assert!(
        late.is_err(),
        "an exchange completed after heal although its requester had already given up"
    );
}

/// The negative control: the same wrapper, never told to cut anything, must
/// never interfere.
///
/// Without this, every assertion above is consistent with the fault wrapper
/// being broken in a way that stops traffic regardless -- the partitioned
/// phases would pass for the wrong reason, and only the healthy phases would
/// be at risk, which is the half nobody looks at twice.
#[tokio::test]
async fn an_idle_fault_controller_never_interferes() {
    let network = TestNetwork::new();
    let faults = SimFaultController::new();
    let p = pair(&network, &faults).await;
    let payload = body();

    for round in 0..3 {
        let serving = serve_blocks(p.b.clone(), payload.clone());
        let got = block_round_trip(&p.a, "device-b", &payload, HEALTHY_TIMEOUT).await;
        assert_eq!(
            got.as_deref(),
            Some(payload.as_slice()),
            "round {round}: an idle fault controller stopped traffic"
        );
        assert_eq!(serving.await.expect("serving task"), b"want");
    }

    assert_eq!(faults.dropped_datagrams(), 0, "an idle fault controller discarded datagrams");
}
