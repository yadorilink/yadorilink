//! Track Send's ALPN beside the sync ALPN on one router.
//!
//! Real endpoints, real handshakes. What is pinned: each protocol is gated by
//! its own admission and delivered to its own queue, so being a sync peer does
//! not open Track Send, being a Track Send peer does not open sync, and a
//! connection made for one never reaches the other's handler.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use yadorilink_sync_substrate::testing::SharedAddressBook;
use yadorilink_sync_substrate::{
    AdmitNone, AdmitWhen, NetworkConfig, PeerAdmission, PeerId, PeerLink, SubstrateNode,
    TrackSendConnection,
};

const STEP: Duration = Duration::from_secs(10);

fn key(seed: u8) -> iroh::SecretKey {
    iroh::SecretKey::from_bytes(&[seed; 32])
}

fn peer_of(secret: &iroh::SecretKey) -> PeerId {
    PeerId::from_bytes(*secret.public().as_bytes())
}

fn only(peer: PeerId) -> Arc<dyn PeerAdmission> {
    AdmitWhen::new(move |candidate: &PeerId| *candidate == peer)
}

struct Node {
    node: SubstrateNode,
    sync_inbound: mpsc::Receiver<PeerLink>,
    send_inbound: mpsc::Receiver<TrackSendConnection>,
}

async fn spawn(
    secret: iroh::SecretKey,
    book: &SharedAddressBook,
    sync: Arc<dyn PeerAdmission>,
    send: Arc<dyn PeerAdmission>,
) -> Node {
    let (send_tx, send_inbound) = mpsc::channel(8);
    let (node, sync_inbound) = SubstrateNode::spawn(
        secret,
        NetworkConfig::direct_only()
            .with_directory(Arc::new(book.clone()))
            .with_track_send(send, send_tx),
        sync,
    )
    .await
    .expect("substrate starts");
    Node { node, sync_inbound, send_inbound }
}

/// Whether a Track Send connection from `dialer` to `target` carries bytes
/// both ways. Opening a stream succeeds against a peer that has already
/// refused us; only use shows the refusal.
async fn send_round_trips(
    dialer: &SubstrateNode,
    target: &SubstrateNode,
    target_inbound: &mut mpsc::Receiver<TrackSendConnection>,
) -> bool {
    let echo = async {
        let connection = target_inbound.recv().await?;
        let (mut writer, mut reader) = connection.accept_stream().await.ok()?;
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).await.ok()?;
        writer.write_all(&buf).await.ok()?;
        writer.finish().ok()?;
        writer.flushed(STEP).await;
        Some(())
    };
    let dial = async {
        let connection = dialer.connect_track_send(&target.local_address()).await.ok()?;
        let (mut writer, mut reader) = connection.open_stream().await.ok()?;
        writer.write_all(b"ping").await.ok()?;
        writer.finish().ok()?;
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).await.ok()?;
        Some(&buf == b"ping")
    };
    // The dial decides. The echo side runs alongside it and simply never
    // finishes when admission refused the connection it waits for.
    tokio::pin!(echo, dial);
    let deadline = tokio::time::sleep(STEP);
    tokio::pin!(deadline);
    let mut echo_running = true;
    loop {
        tokio::select! {
            answered = &mut dial => return answered == Some(true),
            _ = &mut echo, if echo_running => echo_running = false,
            () = &mut deadline => return false,
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_admitted_for_track_send_can_exchange_bytes_on_the_send_alpn() {
    let book = SharedAddressBook::new();
    let (a_key, b_key) = (key(41), key(42));
    let a_id = peer_of(&a_key);
    let a = spawn(a_key, &book, Arc::new(AdmitNone), Arc::new(AdmitNone)).await;
    let mut b = spawn(b_key, &book, Arc::new(AdmitNone), only(a_id)).await;

    assert!(
        send_round_trips(&a.node, &b.node, &mut b.send_inbound).await,
        "a peer the Track Send admission accepts must get a working connection"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sync_peer_is_refused_on_the_send_alpn_without_its_own_admission() {
    let book = SharedAddressBook::new();
    let (a_key, b_key) = (key(43), key(44));
    let a_id = peer_of(&a_key);
    let a = spawn(a_key, &book, Arc::new(AdmitNone), Arc::new(AdmitNone)).await;
    // B pins A for sync and admits nobody for Track Send.
    let mut b = spawn(b_key, &book, only(a_id), Arc::new(AdmitNone)).await;

    assert!(
        !send_round_trips(&a.node, &b.node, &mut b.send_inbound).await,
        "being a sync peer must not open Track Send"
    );
    assert!(b.send_inbound.try_recv().is_err(), "nothing reached the Track Send queue");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_track_send_peer_is_refused_on_the_sync_alpn_and_never_reaches_sync_lanes() {
    let book = SharedAddressBook::new();
    let (a_key, b_key) = (key(45), key(46));
    let (a_id, b_id) = (peer_of(&a_key), peer_of(&b_key));
    let a = spawn(a_key, &book, Arc::new(AdmitNone), Arc::new(AdmitNone)).await;
    // B admits A for Track Send only.
    let mut b = spawn(b_key, &book, Arc::new(AdmitNone), only(a_id)).await;

    // The send connection works and lands on the Track Send queue only.
    assert!(send_round_trips(&a.node, &b.node, &mut b.send_inbound).await);
    assert!(
        b.sync_inbound.try_recv().is_err(),
        "a Track Send connection must never be handed to the sync side"
    );

    // A sync dial from the same peer is refused: the Track Send admission is
    // never asked on the sync ALPN.
    let refused = async {
        let link = a.node.connect(b_id).await.ok()?;
        let mut lane = link.open_lane(yadorilink_sync_substrate::Lane::Service).await.ok()?;
        lane.write_all(b"ping").await.ok()?;
        let mut buf = [0u8; 4];
        lane.read_exact(&mut buf).await.ok()?;
        Some(())
    };
    assert!(
        matches!(tokio::time::timeout(STEP, refused).await, Ok(None)),
        "a peer admitted only for Track Send must not get a sync lane"
    );
    assert!(b.sync_inbound.try_recv().is_err(), "no sync link was ever delivered");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_node_without_track_send_does_not_answer_the_send_alpn() {
    let book = SharedAddressBook::new();
    let (a_key, b_key) = (key(47), key(48));
    let a_id = peer_of(&a_key);
    let a = spawn(a_key, &book, Arc::new(AdmitNone), Arc::new(AdmitNone)).await;
    let (b, _sync_inbound) = SubstrateNode::spawn(
        b_key,
        NetworkConfig::direct_only().with_directory(Arc::new(book.clone())),
        only(a_id),
    )
    .await
    .expect("substrate starts");

    let dialled = tokio::time::timeout(STEP, a.node.connect_track_send(&b.local_address())).await;
    assert!(
        matches!(dialled, Ok(Err(_))),
        "an ALPN the router never registered must not complete a handshake"
    );
}

/// Whether the stream `reader` belongs to sees its connection end within `STEP`,
/// rather than waiting on a peer that will never write.
async fn ends(reader: &mut yadorilink_sync_substrate::TrackSendReader) -> bool {
    let mut buf = [0u8; 1];
    matches!(tokio::time::timeout(STEP, reader.read_exact(&mut buf)).await, Ok(Err(_)))
}

#[tokio::test(flavor = "multi_thread")]
async fn closing_a_peer_ends_its_track_send_connections_in_both_directions() {
    let book = SharedAddressBook::new();
    let (a_key, b_key) = (key(49), key(50));
    let (a_id, b_id) = (peer_of(&a_key), peer_of(&b_key));
    let mut a = spawn(a_key, &book, Arc::new(AdmitNone), only(b_id)).await;
    let mut b = spawn(b_key, &book, Arc::new(AdmitNone), only(a_id)).await;

    // A dials B, and B dials A: each node holds one connection it dialled
    // and one it accepted, all to the same peer.
    let a_dialled = a.node.connect_track_send(&b.node.local_address()).await.expect("A dials");
    let b_dialled = b.node.connect_track_send(&a.node.local_address()).await.expect("B dials");
    let (mut a_writer, mut a_reader) = a_dialled.open_stream().await.expect("stream");
    a_writer.write_all(b"x").await.expect("written");
    let (mut b_writer, mut b_reader) = b_dialled.open_stream().await.expect("stream");
    b_writer.write_all(b"x").await.expect("written");
    let b_accepted = tokio::time::timeout(STEP, b.send_inbound.recv()).await.unwrap().unwrap();
    let a_accepted = tokio::time::timeout(STEP, a.send_inbound.recv()).await.unwrap().unwrap();
    let (_b_accepted_writer, _b_accepted_reader) = b_accepted.accept_stream().await.expect("B");
    let (_a_accepted_writer, _a_accepted_reader) = a_accepted.accept_stream().await.expect("A");

    // A drops B: both of A's connections to B end, whichever side dialled.
    assert_eq!(a.node.track_send_connections().close_to(&b_id), 2);
    assert!(ends(&mut a_reader).await, "the connection A dialled must be closed");
    assert!(ends(&mut b_reader).await, "the connection B dialled into A must be closed");

    // Closing a peer with nothing open is a no-op.
    assert_eq!(a.node.track_send_connections().close_to(&b_id), 0);
}
