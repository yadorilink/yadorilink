//! Shutting a node down does not wait on a peer that cannot be reached.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use yadorilink_sync_substrate::testing::SharedAddressBook;
use yadorilink_sync_substrate::{
    AdmitNone, AdmitWhen, NativeReplicationConnection, NetworkConfig, PeerAdmission, PeerId,
    SubstrateNode,
};

fn key(seed: u8) -> iroh::SecretKey {
    iroh::SecretKey::from_bytes(&[seed; 32])
}

fn peer_of(secret: &iroh::SecretKey) -> PeerId {
    PeerId::from_bytes(*secret.public().as_bytes())
}

async fn spawn_admitting(
    secret: iroh::SecretKey,
    book: &SharedAddressBook,
    replication: Arc<dyn PeerAdmission>,
) -> (SubstrateNode, mpsc::Receiver<NativeReplicationConnection>) {
    let (replication_tx, replication_inbound) = mpsc::channel(8);
    let (node, _sync_inbound) = SubstrateNode::spawn(
        secret,
        NetworkConfig::direct_only()
            .with_directory(Arc::new(book.clone()))
            .with_native_replication(replication, replication_tx),
        Arc::new(AdmitNone),
    )
    .await
    .expect("substrate starts");
    (node, replication_inbound)
}

async fn spawn(secret: iroh::SecretKey, book: &SharedAddressBook) -> SubstrateNode {
    spawn_admitting(secret, book, Arc::new(AdmitNone)).await.0
}

/// A dial to a peer that has gone away leaves the endpoint with traffic nobody acknowledges.
/// Closing the endpoint used to wait three seconds on it; the stop of a daemon whose peer is
/// offline took that long.
#[tokio::test(flavor = "multi_thread")]
async fn shutdown_with_a_dial_to_an_unreachable_peer_is_bounded() {
    let book = SharedAddressBook::new();
    let node = spawn(key(91), &book).await;
    let gone = spawn(key(92), &book).await;
    let gone_address = gone.local_address();
    gone.shutdown().await;

    let dialer = node.clone();
    let dial = tokio::spawn(async move { dialer.connect_native_replication(&gone_address).await });
    tokio::time::sleep(Duration::from_millis(500)).await;

    let started = std::time::Instant::now();
    node.shutdown().await;
    let took = started.elapsed();
    dial.abort();
    assert!(took < Duration::from_millis(2500), "shutdown took {took:?}");
}

/// The bound gives up only on peers that cannot be told. A reachable peer receives the close
/// frame, and sees its connection closed by the peer, well inside the bound.
#[tokio::test(flavor = "multi_thread")]
async fn a_reachable_peer_is_told_of_the_shutdown_within_the_bound() {
    let book = SharedAddressBook::new();
    let (a_key, b_key) = (key(95), key(96));
    let (a_id, b_id) = (peer_of(&a_key), peer_of(&b_key));
    let only = |peer: PeerId| -> Arc<dyn PeerAdmission> {
        AdmitWhen::new(move |candidate: &PeerId| *candidate == peer)
    };
    let (a, _a_inbound) = spawn_admitting(a_key, &book, only(b_id)).await;
    let (b, mut b_inbound) = spawn_admitting(b_key, &book, only(a_id)).await;

    let dialled = a.connect_native_replication(&b.local_address()).await.expect("A dials B");
    let (mut writer, _reader) = dialled.open_stream().await.expect("A opens a stream");
    writer.write_all(b"x").await.expect("A writes");
    let accepted =
        tokio::time::timeout(Duration::from_secs(10), b_inbound.recv()).await.unwrap().unwrap();

    a.shutdown().await;
    let deadline = std::time::Instant::now() + Duration::from_millis(1500);
    while !accepted.closed_by_peer() {
        assert!(std::time::Instant::now() < deadline, "B was not told that A shut down");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    b.shutdown().await;
}
