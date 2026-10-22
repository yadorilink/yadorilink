//! The gate between "authenticated" and "allowed to talk to us".
//!
//! Every test here dials a real endpoint over a real handshake. That is the
//! point: the refused peer is not malformed or unreachable, it is a
//! perfectly valid Ed25519 keyholder that completes the TLS handshake and
//! is turned away anyway, because holding a key was never the question.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use yadorilink_sync_substrate::testing::SharedAddressBook;
use yadorilink_sync_substrate::{
    AdmitNone, AdmitWhen, NetworkConfig, PeerId, PeerLink, SubstrateNode,
};

fn key(seed: u8) -> iroh::SecretKey {
    iroh::SecretKey::from_bytes(&[seed; 32])
}

fn peer_of(secret: &iroh::SecretKey) -> PeerId {
    PeerId::from_bytes(*secret.public().as_bytes())
}

async fn spawn(
    secret: iroh::SecretKey,
    book: &SharedAddressBook,
    admission: Arc<dyn yadorilink_sync_substrate::PeerAdmission>,
) -> (SubstrateNode, tokio::sync::mpsc::Receiver<PeerLink>) {
    SubstrateNode::spawn(
        secret,
        NetworkConfig::direct_only().with_directory(Arc::new(book.clone())),
        admission,
    )
    .await
    .expect("substrate starts")
}

/// Echo every stream on every link the node accepts, so that "was this
/// peer admitted?" has an observable answer on the wire.
fn serve_echo(mut inbound: tokio::sync::mpsc::Receiver<PeerLink>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(link) = inbound.recv().await {
            tokio::spawn(async move {
                while let Ok(lane) = link.accept_lane().await {
                    tokio::spawn(async move {
                        let (mut send, mut recv) = lane.split();
                        let _ = tokio::io::copy(&mut recv, &mut send).await;
                        let _ = send.finish();
                    });
                }
            });
        }
    })
}

/// Whether bytes actually cross, which is the only honest test of whether
/// a peer got in.
///
/// Neither `connect` nor `open_lane` can answer this. QUIC opens a stream
/// without consulting the far side, so both succeed against a peer that
/// has already refused us; the refusal only becomes visible on use. A test
/// built on either would pass against a gate that does nothing.
async fn can_round_trip(node: &SubstrateNode, peer: PeerId) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let attempt = async {
        let link = node.connect(peer).await.ok()?;
        let mut lane = link.open_lane(yadorilink_sync_substrate::Lane::Service).await.ok()?;
        lane.write_all(b"ping").await.ok()?;
        let mut echoed = [0u8; 4];
        lane.read_exact(&mut echoed).await.ok()?;
        Some(&echoed == b"ping")
    };
    // A refused peer fails fast; the timeout only bounds a hang that would
    // otherwise be reported as a stall rather than as this assertion.
    matches!(
        tokio::time::timeout(std::time::Duration::from_secs(10), attempt).await,
        Ok(Some(true))
    )
}

/// The base case, and the one that would quietly pass if the gate did
/// nothing at all -- so every other test here depends on this one being
/// separately true.
#[tokio::test(flavor = "multi_thread")]
async fn a_pinned_peer_is_admitted() {
    let book = SharedAddressBook::new();
    let (dialer_key, listener_key) = (key(11), key(12));
    let dialer_id = peer_of(&dialer_key);

    let (listener, inbound) =
        spawn(listener_key.clone(), &book, AdmitWhen::new(move |p: &PeerId| *p == dialer_id)).await;
    let _echo = serve_echo(inbound);
    let (dialer, _d) = spawn(dialer_key, &book, Arc::new(AdmitNone)).await;

    assert!(
        can_round_trip(&dialer, listener.peer_id()).await,
        "a peer the listener pinned was refused"
    );
}

/// The whole reason the gate exists.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_that_authenticates_but_is_not_pinned_gets_no_lane() {
    let book = SharedAddressBook::new();
    let (known_key, stranger_key, listener_key) = (key(21), key(22), key(23));
    let known_id = peer_of(&known_key);

    let (listener, mut inbound) =
        spawn(listener_key, &book, AdmitWhen::new(move |p: &PeerId| *p == known_id)).await;
    let (stranger, _s) = spawn(stranger_key, &book, Arc::new(AdmitNone)).await;

    assert!(
        !can_round_trip(&stranger, listener.peer_id()).await,
        "an unpinned device completed a handshake and was given a working lane"
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(500), inbound.recv()).await.is_err(),
        "a refused connection must never surface as an inbound link"
    );
}

/// Revocation, which is the property a startup snapshot would silently
/// lose: the peer here is admitted first, so the later refusal cannot be
/// explained by it having been unknown all along.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_revoked_after_spawn_stops_being_admitted() {
    let book = SharedAddressBook::new();
    let (dialer_key, listener_key) = (key(31), key(32));
    let dialer_id = peer_of(&dialer_key);
    let revoked = Arc::new(AtomicBool::new(false));

    let seen = revoked.clone();
    let (listener, inbound) = spawn(
        listener_key,
        &book,
        AdmitWhen::new(move |p: &PeerId| *p == dialer_id && !seen.load(Ordering::SeqCst)),
    )
    .await;
    let _echo = serve_echo(inbound);
    let (dialer, _d) = spawn(dialer_key, &book, Arc::new(AdmitNone)).await;

    assert!(can_round_trip(&dialer, listener.peer_id()).await, "admitted before revocation");

    revoked.store(true, Ordering::SeqCst);

    // A fresh connection, not the one already open. Cutting a live
    // connection is a separate obligation from refusing the next one, and
    // this test is only about the latter -- conflating them would let a
    // gate that never re-checks anything pass.
    assert!(
        !can_round_trip(&dialer, listener.peer_id()).await,
        "a revoked device was still admitted on a new connection"
    );
}

/// A node that names no peers talks to nobody -- including a peer that is
/// simultaneously willing to talk to it. Admission is each side's own
/// decision, not a negotiation.
#[tokio::test(flavor = "multi_thread")]
async fn admit_none_refuses_a_peer_that_would_admit_it_back() {
    let book = SharedAddressBook::new();
    let (dialer_key, listener_key) = (key(41), key(42));
    let dialer_id = peer_of(&dialer_key);

    let (listener, inbound) = spawn(listener_key, &book, Arc::new(AdmitNone)).await;
    let _echo = serve_echo(inbound);
    let (dialer, _d) =
        spawn(dialer_key, &book, AdmitWhen::new(move |p: &PeerId| *p == dialer_id)).await;

    assert!(
        !can_round_trip(&dialer, listener.peer_id()).await,
        "a node admitting nobody still handed out a lane"
    );
}
