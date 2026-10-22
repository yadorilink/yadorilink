//! One block exchange, end to end, on the substrate's block lane.
//!
//! What this pins is that the block protocol's own port is satisfied by a lane
//! stream — header then body, bounded reads, a direction that ends — so the
//! protocol above can move transport without changing.

use ed25519_dalek::SigningKey;
use yadorilink_peer_session::ports::PeerBlockStream;
use yadorilink_sync_substrate::{Lane, NetworkConfig, SubstrateNode};
use yadorilink_transport::TransportError;

use crate::block_lane::LaneBlockStream;
use yadorilink_sync_substrate::testing::SharedAddressBook;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_block_request_and_its_body_cross_the_block_lane() {
    let book = SharedAddressBook::new();
    let (server, mut inbound) = SubstrateNode::spawn_as_device(
        SigningKey::from_bytes(&[7u8; 32]).to_bytes(),
        NetworkConfig::direct_only().with_directory(std::sync::Arc::new(book.clone())),
        std::sync::Arc::new(yadorilink_sync_substrate::AdmitAnyAuthenticated),
    )
    .await
    .unwrap();
    let (client, _client_inbound) = SubstrateNode::spawn_as_device(
        SigningKey::from_bytes(&[8u8; 32]).to_bytes(),
        NetworkConfig::direct_only().with_directory(std::sync::Arc::new(book.clone())),
        std::sync::Arc::new(yadorilink_sync_substrate::AdmitAnyAuthenticated),
    )
    .await
    .unwrap();

    let body = vec![0xABu8; 64 * 1024];
    let expected = body.clone();
    let serving = tokio::spawn(async move {
        let link = inbound.recv().await.expect("a peer connects");
        let lane = link.accept_lane().await.expect("a lane is opened");
        assert_eq!(lane.lane(), Lane::Block, "block traffic must arrive on the block lane");
        let mut stream = LaneBlockStream::new(lane);

        let request = stream.recv_message(1024).await.expect("the request header arrives");
        assert_eq!(request, b"give me a block");
        stream.send_message(b"here it comes").await.unwrap();
        stream.send_body(&body).await.unwrap();
    });

    let link = client.connect(server.local_address().peer()).await.expect("the dial succeeds");
    let mut stream = LaneBlockStream::new(link.open_lane(Lane::Block).await.unwrap());
    stream.send_message(b"give me a block").await.unwrap();
    // The requester has nothing further to send once its header is out.
    stream.finish_send();

    let header = stream.recv_message(1024).await.expect("the response header arrives");
    assert_eq!(header, b"here it comes");
    let received = stream.recv_body(expected.len()).await.expect("the body arrives whole");
    assert_eq!(received, expected);

    serving.await.unwrap();
}

/// A header longer than the caller's ceiling is refused before it is
/// allocated for. The far end of this stream is a peer, so a declared length
/// is a claim, exactly as everywhere else this codebase reads from one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_header_larger_than_the_callers_ceiling_is_refused_before_allocating() {
    let book = SharedAddressBook::new();
    let (server, mut inbound) = SubstrateNode::spawn_as_device(
        SigningKey::from_bytes(&[9u8; 32]).to_bytes(),
        NetworkConfig::direct_only().with_directory(std::sync::Arc::new(book.clone())),
        std::sync::Arc::new(yadorilink_sync_substrate::AdmitAnyAuthenticated),
    )
    .await
    .unwrap();
    let (client, _client_inbound) = SubstrateNode::spawn_as_device(
        SigningKey::from_bytes(&[10u8; 32]).to_bytes(),
        NetworkConfig::direct_only().with_directory(std::sync::Arc::new(book.clone())),
        std::sync::Arc::new(yadorilink_sync_substrate::AdmitAnyAuthenticated),
    )
    .await
    .unwrap();

    let serving = tokio::spawn(async move {
        let link = inbound.recv().await.unwrap();
        let lane = link.accept_lane().await.unwrap();
        let mut stream = LaneBlockStream::new(lane);
        // Read the client's request first: replying and ending this task before
        // the client has finished writing resets the stream under its write.
        stream.recv_message(1024).await.unwrap();
        // Well-formed, and far larger than the reader below will accept.
        stream.send_message(&vec![0u8; 8192]).await.unwrap();
        stream.send_body(&[]).await.unwrap();
    });

    let link = client.connect(server.local_address().peer()).await.unwrap();
    let mut stream = LaneBlockStream::new(link.open_lane(Lane::Block).await.unwrap());
    stream.send_message(b"hello").await.unwrap();
    stream.finish_send();

    let refused = stream.recv_message(1024).await;
    assert!(
        matches!(refused, Err(TransportError::MessageTooLarge(8192, 1024))),
        "expected the declared length to be refused against the ceiling, got {refused:?}"
    );

    let _ = serving.await;
}
