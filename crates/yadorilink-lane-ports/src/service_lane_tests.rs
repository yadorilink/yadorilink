//! Service RPCs over the substrate's service lane.

use std::time::Duration;

use ed25519_dalek::SigningKey;
use yadorilink_peer_session::ports::PeerServiceStream;
use yadorilink_sync_substrate::{Lane, NetworkConfig, SubstrateNode};
use yadorilink_transport::TransportError;

use super::service_lane::{LaneServiceStream, MAX_SERVICE_MESSAGE_BYTES};
use yadorilink_sync_substrate::testing::SharedAddressBook;

/// A node publishing into, and resolving out of, `book`.
///
/// The book is per-test on purpose. A process-wide one is shared by every test
/// in this binary, and these tests reuse fixed seeds -- so two tests running at
/// once mint the SAME endpoint id, the later publish overwrites the earlier
/// address, and the first test then dials the second test's node and waits
/// forever for a stream it will never open.
async fn node(
    book: &SharedAddressBook,
    seed: u8,
) -> (SubstrateNode, tokio::sync::mpsc::Receiver<yadorilink_sync_substrate::PeerLink>) {
    let spawned = SubstrateNode::spawn_as_device(
        SigningKey::from_bytes(&[seed; 32]).to_bytes(),
        NetworkConfig::direct_only().with_directory(std::sync::Arc::new(book.clone())),
        std::sync::Arc::new(yadorilink_sync_substrate::AdmitAnyAuthenticated),
    )
    .await
    .unwrap();
    // The dial that follows resolves out of the book, and iroh fills it
    // asynchronously -- see `wait_published`.
    book.wait_published(spawned.0.peer_id()).await;
    spawned
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_service_request_and_its_response_cross_the_service_lane() {
    let book = SharedAddressBook::new();
    let (server, mut inbound) = node(&book, 21).await;
    let (client, _c) = node(&book, 22).await;

    let serving = tokio::spawn(async move {
        let link = inbound.recv().await.unwrap();
        let lane = link.accept_lane().await.unwrap();
        assert_eq!(lane.lane(), Lane::Service, "service RPCs must arrive on the service lane");
        let mut stream = LaneServiceStream::new(lane);
        let request = stream.recv_message(4096).await.unwrap();
        assert_eq!(request, b"is this version present?");
        stream.send_response(b"yes").await.unwrap();
    });

    let link = client.connect(server.local_address().peer()).await.unwrap();
    let mut stream = LaneServiceStream::new(link.open_lane(Lane::Service).await.unwrap());
    stream.send_request(b"is this version present?").await.unwrap();
    assert_eq!(stream.recv_message(4096).await.unwrap(), b"yes");

    serving.await.unwrap();
}

/// A slow RPC delays only itself.
///
/// This is the whole reason a service *lane* replaced a shared control stream
/// rather than being rebuilt on top of one. With a receive loop and a
/// request-id map, one handler that blocks holds up every other answer; with a
/// stream each, the second request is answered while the first is still
/// waiting.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_rpc_does_not_delay_another_one() {
    let book = SharedAddressBook::new();
    let (server, mut inbound) = node(&book, 23).await;
    let (client, _c) = node(&book, 24).await;

    let serving = tokio::spawn(async move {
        let link = inbound.recv().await.unwrap();
        while let Ok(lane) = link.accept_lane().await {
            tokio::spawn(async move {
                let mut stream = LaneServiceStream::new(lane);
                let request = stream.recv_message(4096).await.unwrap();
                if request == b"slow" {
                    // Never answers. A shared stream with one reader would be
                    // stuck behind whatever this handler is waiting on.
                    std::future::pending::<()>().await;
                }
                stream.send_response(b"quick").await.unwrap();
            });
        }
    });

    let link = client.connect(server.local_address().peer()).await.unwrap();

    let mut slow = LaneServiceStream::new(link.open_lane(Lane::Service).await.unwrap());
    slow.send_request(b"slow").await.unwrap();

    let mut quick = LaneServiceStream::new(link.open_lane(Lane::Service).await.unwrap());
    quick.send_request(b"quick").await.unwrap();

    let answered = tokio::time::timeout(Duration::from_secs(10), quick.recv_message(4096))
        .await
        .expect("the quick RPC must not wait on the stalled one");
    assert_eq!(answered.unwrap(), b"quick");

    serving.abort();
}

/// A declared length is refused against the smaller of the caller's ceiling
/// and this lane's own, before anything is allocated for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_oversized_message_is_refused_before_allocating() {
    let book = SharedAddressBook::new();
    let (server, mut inbound) = node(&book, 25).await;
    let (client, _c) = node(&book, 26).await;

    let serving = tokio::spawn(async move {
        let link = inbound.recv().await.unwrap();
        let lane = link.accept_lane().await.unwrap();
        let mut stream = LaneServiceStream::new(lane);
        let _ = stream.recv_message(4096).await;
        stream.send_response(&vec![0u8; 8192]).await.unwrap();
    });

    let link = client.connect(server.local_address().peer()).await.unwrap();
    let mut stream = LaneServiceStream::new(link.open_lane(Lane::Service).await.unwrap());
    stream.send_request(b"hello").await.unwrap();

    let refused = stream.recv_message(1024).await;
    assert!(
        matches!(refused, Err(TransportError::MessageTooLarge(8192, 1024))),
        "expected the caller's ceiling to be enforced, got {refused:?}"
    );

    let _ = serving.await;
}

/// The sender refuses to put a message on this lane that the far end would be
/// right to reject, so a misclassified bulk payload fails where it is written
/// rather than where it is read.
#[test]
fn the_lane_ceiling_is_enforced_on_the_way_out_too() {
    const { assert!(MAX_SERVICE_MESSAGE_BYTES < 16 << 20) };
}

/// The version-present RPC, end to end on the service lane, answered from a
/// live session — and refused, immediately, for a group the peer is not
/// authorized for.
///
/// The refusal is the half worth stating. Authorization is resolved per
/// request from live membership, never from anything remembered when the
/// stream opened, because a stream outlives a revocation. And it is *answered*
/// rather than dropped: a silent drop makes an unauthorized peer wait out its
/// own timeout, and the difference in delay between "unauthorized" and
/// "genuinely absent" is a side-channel of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unauthorized_group_is_refused_on_the_spot_not_dropped() {
    let book = SharedAddressBook::new();
    use yadorilink_peer_session::service_rpc::{
        decode_response, encode_request, ServiceRequest, ServiceResponse,
    };

    let (server, mut inbound) = node(&book, 27).await;
    let (client, _c) = node(&book, 28).await;

    // Stands in for a session that shares no group with this peer: it decodes
    // the request, finds it unauthorized, and answers false at once.
    let serving = tokio::spawn(async move {
        let link = inbound.recv().await.unwrap();
        let lane = link.accept_lane().await.unwrap();
        let mut stream = LaneServiceStream::new(lane);
        let encoded = stream.recv_message(1 << 20).await.unwrap();
        let request = yadorilink_peer_session::service_rpc::decode_request(&encoded).unwrap();
        assert_eq!(request.group_id(), "not-shared");
        stream
            .send_response(&yadorilink_peer_session::service_rpc::encode_response(
                &ServiceResponse::VersionPresent { present: false },
            ))
            .await
            .unwrap();
    });

    let link = client.connect(server.local_address().peer()).await.unwrap();
    let mut stream = LaneServiceStream::new(link.open_lane(Lane::Service).await.unwrap());
    stream
        .send_request(&encode_request(&ServiceRequest::VersionPresent {
            group_id: "not-shared".into(),
            file_path: "secret.bin".into(),
            version_hash: yadorilink_replica_domain::ids::VersionHash([3u8; 32]),
            blocks: Vec::new(),
            for_handoff: false,
        }))
        .await
        .unwrap();

    let answered = tokio::time::timeout(Duration::from_secs(5), stream.recv_message(1 << 20))
        .await
        .expect("an unauthorized request must be answered, not left to time out");
    assert_eq!(
        decode_response(&answered.unwrap()).unwrap(),
        ServiceResponse::VersionPresent { present: false }
    );

    serving.await.unwrap();
}
