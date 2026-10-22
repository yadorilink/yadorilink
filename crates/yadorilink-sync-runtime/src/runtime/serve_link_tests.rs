#![cfg(test)]

use std::time::Duration;

use yadorilink_sync_substrate::testing::SharedAddressBook;
use yadorilink_sync_substrate::{AdmitAnyAuthenticated, NetworkConfig};

use super::*;

async fn spawn_node(
    seed: u8,
    book: &SharedAddressBook,
) -> (SubstrateNode, tokio::sync::mpsc::Receiver<PeerLink>) {
    SubstrateNode::spawn(
        iroh::SecretKey::from_bytes(&[seed; 32]),
        NetworkConfig::direct_only().with_directory(Arc::new(book.clone())),
        Arc::new(AdmitAnyAuthenticated),
    )
    .await
    .expect("substrate starts")
}

/// A server runtime that reports the group of every lane stream it is handed,
/// and a link to it from a second node.
async fn serving_pair() -> (
    tokio::sync::mpsc::UnboundedReceiver<String>,
    PeerLink,
    (SubstrateNode, SyncRuntime, ServeHandle),
) {
    let book = SharedAddressBook::new();
    let (server_node, inbound) = spawn_node(1, &book).await;
    let (client_node, _client_inbound) = spawn_node(2, &book).await;
    let server = SyncRuntime::new(server_node);
    let (seen_tx, seen_rx) = tokio::sync::mpsc::unbounded_channel();
    server.when_lane_stream(Arc::new(move |_peer, group, _lane, _stream| {
        let seen_tx = seen_tx.clone();
        Box::pin(async move {
            let _ = seen_tx.send(group.0);
        })
    }));
    let handle = server.serve(inbound);
    let link = client_node.connect(server.peer_id()).await.expect("the client dials the server");
    (seen_rx, link, (client_node, server, handle))
}

async fn open_hello_lane(link: &PeerLink, group: &str) {
    let mut lane = link.open_lane(Lane::Service).await.expect("a lane opens");
    yadorilink_sync_protocol::session::open_lane(&mut lane, &GroupId(group.into()))
        .await
        .expect("the hello is written");
    // Keep the lane alive until the test ends.
    std::mem::forget(lane);
}

/// One stream with an unknown lane tag must not stop the connection's lane
/// serving: the next, well-formed stream is still handed to its hook.
#[tokio::test]
async fn a_stream_with_an_unknown_lane_tag_does_not_stop_later_streams_being_served() {
    let (mut seen, link, _keep) = serving_pair().await;

    let (mut send, _recv) = link.open_raw_stream_for_test().await.unwrap();
    send.write_all(&[0xEE]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    open_hello_lane(&link, "after-bad-tag").await;
    let group = tokio::time::timeout(Duration::from_secs(5), seen.recv())
        .await
        .expect("the later stream must still be served")
        .unwrap();
    assert_eq!(group, "after-bad-tag");
}

/// A stream that never sends its lane tag must not hold up accepting the
/// streams behind it.
#[tokio::test]
async fn a_stream_that_never_sends_its_tag_does_not_block_the_streams_behind_it() {
    let (mut seen, link, _keep) = serving_pair().await;

    // Opened and left silent; QUIC only announces a stream once it has data, so send
    // nothing but keep the handle alive.
    let (mut silent, _silent_recv) = link.open_raw_stream_for_test().await.unwrap();
    silent.write_all(&[]).await.unwrap();

    open_hello_lane(&link, "behind-the-silent-stream").await;
    let group = tokio::time::timeout(Duration::from_secs(5), seen.recv())
        .await
        .expect("a silent stream must not stall the accept loop")
        .unwrap();
    assert_eq!(group, "behind-the-silent-stream");
    drop(silent);
}

/// A raw hello frame claiming `version`, with a well-formed group.
fn hello_frame_at_version(version: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&version.to_be_bytes());
    body.extend_from_slice(&1u16.to_be_bytes());
    body.push(b'g');
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    frame
}

/// A peer whose lane hello names another protocol version has completed the transport, so it is
/// reachable; the runtime reports it as incompatible (with both versions) instead of only
/// logging and dropping the lane.
#[tokio::test]
async fn a_hello_from_another_protocol_version_is_reported_as_incompatible() {
    use yadorilink_sync_protocol::PROTOCOL_VERSION;

    for theirs in [PROTOCOL_VERSION + 1, PROTOCOL_VERSION - 1] {
        let (mut seen, link, (client_node, server, _handle)) = serving_pair().await;
        let (reported_tx, mut reported) = tokio::sync::mpsc::unbounded_channel();
        server.when_lane_incompatible(Arc::new(move |peer, theirs, ours| {
            let _ = reported_tx.send((peer, theirs, ours));
        }));

        let mut lane = link.open_lane(Lane::Service).await.expect("a lane opens");
        tokio::io::AsyncWriteExt::write_all(&mut lane, &hello_frame_at_version(theirs))
            .await
            .expect("the hello is written");
        tokio::io::AsyncWriteExt::flush(&mut lane).await.unwrap();

        let (peer, reported_theirs, reported_ours) =
            tokio::time::timeout(Duration::from_secs(5), reported.recv())
                .await
                .expect("the mismatch is reported")
                .unwrap();
        assert_eq!(peer, client_node.peer_id());
        assert_eq!((reported_theirs, reported_ours), (theirs, PROTOCOL_VERSION));
        // The lane itself is still refused: nothing is handed to the lane hook.
        assert!(seen.try_recv().is_err());
    }
}

/// A matching hello is not a mismatch.
#[tokio::test]
async fn a_matching_hello_is_not_reported_as_incompatible() {
    let (mut seen, link, (_client_node, server, _handle)) = serving_pair().await;
    let (reported_tx, mut reported) = tokio::sync::mpsc::unbounded_channel();
    server.when_lane_incompatible(Arc::new(move |peer, theirs, ours| {
        let _ = reported_tx.send((peer, theirs, ours));
    }));

    open_hello_lane(&link, "fine").await;
    tokio::time::timeout(Duration::from_secs(5), seen.recv()).await.unwrap().unwrap();
    assert!(reported.try_recv().is_err());
}
