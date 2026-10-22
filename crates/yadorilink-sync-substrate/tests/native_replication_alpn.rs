//! The native-replication protocol's ALPN beside the sync ALPN on one router.
//!
//! Mirrors `track_send_alpn.rs` exactly, for the native-replication protocol:
//! real endpoints, real handshakes. What is pinned: the native-replication
//! protocol is gated by its own admission and delivered to its own queue,
//! so being a sync peer does not open native-replication, being a native-replication
//! peer does not open sync, gate-off means byte-for-byte no answer at all,
//! and a native-replication connection's failure never touches the sync
//! connection to the same peer. This crate has zero workspace
//! dependencies, so these tests exchange plain bytes only -- protocol 5
//! decoding and native admission are exercised at the daemon layer, which
//! depends on both this crate and the domain/storage crates that live in.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use yadorilink_sync_substrate::testing::SharedAddressBook;
use yadorilink_sync_substrate::{
    AdmitNone, AdmitWhen, NativeReplicationConnection, NetworkConfig, PeerAdmission, PeerId,
    PeerLink, SubstrateNode,
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
    replication_inbound: mpsc::Receiver<NativeReplicationConnection>,
}

async fn spawn(
    secret: iroh::SecretKey,
    book: &SharedAddressBook,
    sync: Arc<dyn PeerAdmission>,
    replication: Arc<dyn PeerAdmission>,
) -> Node {
    let (replication_tx, replication_inbound) = mpsc::channel(8);
    let (node, sync_inbound) = SubstrateNode::spawn(
        secret,
        NetworkConfig::direct_only()
            .with_directory(Arc::new(book.clone()))
            .with_native_replication(replication, replication_tx),
        sync,
    )
    .await
    .expect("substrate starts");
    Node { node, sync_inbound, replication_inbound }
}

/// Whether a native-replication connection from `dialer` to `target` carries
/// bytes both ways. Opening a stream succeeds against a peer that has
/// already refused us; only use shows the refusal.
async fn replication_round_trips(
    dialer: &SubstrateNode,
    target: &SubstrateNode,
    target_inbound: &mut mpsc::Receiver<NativeReplicationConnection>,
) -> bool {
    let echo = async {
        let connection = target_inbound.recv().await?;
        let (mut writer, mut reader) = connection.accept_stream().await.ok()?;
        let bytes = reader.read_to_end(64).await.ok()?;
        writer.write_all(&bytes).await.ok()?;
        writer.finish().ok()?;
        Some(())
    };
    let dial = async {
        let connection = dialer.connect_native_replication(&target.local_address()).await.ok()?;
        let (mut writer, mut reader) = connection.open_stream().await.ok()?;
        writer.write_all(b"ping").await.ok()?;
        writer.finish().ok()?;
        let bytes = reader.read_to_end(64).await.ok()?;
        Some(bytes == b"ping")
    };
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
async fn a_peer_admitted_for_native_replication_can_exchange_bytes_on_its_own_alpn() {
    let book = SharedAddressBook::new();
    let (a_key, b_key) = (key(61), key(62));
    let a_id = peer_of(&a_key);
    let a = spawn(a_key, &book, Arc::new(AdmitNone), Arc::new(AdmitNone)).await;
    let mut b = spawn(b_key, &book, Arc::new(AdmitNone), only(a_id)).await;

    assert!(
        replication_round_trips(&a.node, &b.node, &mut b.replication_inbound).await,
        "a peer the native-replication admission accepts must get a working connection"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sync_peer_is_refused_on_the_native_replication_alpn_without_its_own_admission() {
    let book = SharedAddressBook::new();
    let (a_key, b_key) = (key(63), key(64));
    let a_id = peer_of(&a_key);
    let a = spawn(a_key, &book, Arc::new(AdmitNone), Arc::new(AdmitNone)).await;
    // B pins A for sync and admits nobody for native-replication.
    let mut b = spawn(b_key, &book, only(a_id), Arc::new(AdmitNone)).await;

    assert!(
        !replication_round_trips(&a.node, &b.node, &mut b.replication_inbound).await,
        "being a sync peer must not open the native-replication protocol"
    );
    assert!(
        b.replication_inbound.try_recv().is_err(),
        "nothing reached the native-replication queue"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_native_replication_peer_is_refused_on_the_sync_alpn_and_never_reaches_sync_lanes() {
    let book = SharedAddressBook::new();
    let (a_key, b_key) = (key(65), key(66));
    let (a_id, b_id) = (peer_of(&a_key), peer_of(&b_key));
    let a = spawn(a_key, &book, Arc::new(AdmitNone), Arc::new(AdmitNone)).await;
    // B admits A for native-replication only.
    let mut b = spawn(b_key, &book, Arc::new(AdmitNone), only(a_id)).await;

    assert!(replication_round_trips(&a.node, &b.node, &mut b.replication_inbound).await);
    assert!(
        b.sync_inbound.try_recv().is_err(),
        "a native-replication connection must never be handed to the sync side"
    );

    let refused = async {
        let link = a.node.connect(b_id).await.ok()?;
        let mut lane = link.open_lane(yadorilink_sync_substrate::Lane::Service).await.ok()?;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        lane.write_all(b"ping").await.ok()?;
        let mut buf = [0u8; 4];
        lane.read_exact(&mut buf).await.ok()?;
        Some(())
    };
    assert!(
        matches!(tokio::time::timeout(STEP, refused).await, Ok(None)),
        "a peer admitted only for native-replication must not get a sync lane"
    );
    assert!(b.sync_inbound.try_recv().is_err(), "no sync link was ever delivered");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_node_without_native_replication_configured_does_not_answer_its_alpn_at_all() {
    let book = SharedAddressBook::new();
    let (a_key, b_key) = (key(67), key(68));
    let a_id = peer_of(&a_key);
    let b_id = peer_of(&b_key);
    let a = spawn(a_key, &book, Arc::new(AdmitNone), Arc::new(AdmitNone)).await;
    // B is spawned with NO `with_native_replication` call at all -- the default,
    // gate-off configuration. Its sync behavior must be byte-for-byte
    // identical to any other node in this file.
    let (b, mut b_sync_inbound) = SubstrateNode::spawn(
        b_key,
        NetworkConfig::direct_only().with_directory(Arc::new(book.clone())),
        only(a_id),
    )
    .await
    .expect("substrate starts");

    let dialled =
        tokio::time::timeout(STEP, a.node.connect_native_replication(&b.local_address())).await;
    assert!(
        matches!(dialled, Ok(Err(_))),
        "an ALPN the router never registered must not complete a handshake"
    );

    // Ordinary sync still works perfectly for a node that never configured
    // native-replication at all -- the gate's absence is inert, not broken.
    let link = tokio::time::timeout(STEP, a.node.connect(b_id))
        .await
        .expect("connect completes")
        .expect("sync still works with native-replication unconfigured");
    drop(link);
    assert!(tokio::time::timeout(Duration::from_millis(200), b_sync_inbound.recv()).await.is_ok());
}

/// Whether the stream `reader` belongs to sees its connection end within
/// `STEP`, rather than waiting on a peer that will never write.
async fn ends(reader: &mut yadorilink_sync_substrate::NativeReplicationReader) -> bool {
    // A closed connection makes the pending read resolve one way or the
    // other (a read error, or a clean end-of-stream with no bytes) rather
    // than hang -- either counts as "ended" for this test's purpose.
    tokio::time::timeout(STEP, reader.read_to_end(64)).await.is_ok()
}

#[tokio::test(flavor = "multi_thread")]
async fn closing_a_peer_ends_its_native_replication_connections_in_both_directions() {
    let book = SharedAddressBook::new();
    let (a_key, b_key) = (key(69), key(70));
    let (a_id, b_id) = (peer_of(&a_key), peer_of(&b_key));
    let mut a = spawn(a_key, &book, Arc::new(AdmitNone), only(b_id)).await;
    let mut b = spawn(b_key, &book, Arc::new(AdmitNone), only(a_id)).await;

    let a_dialled =
        a.node.connect_native_replication(&b.node.local_address()).await.expect("A dials");
    let b_dialled =
        b.node.connect_native_replication(&a.node.local_address()).await.expect("B dials");
    let (mut a_writer, mut a_reader) = a_dialled.open_stream().await.expect("stream");
    a_writer.write_all(b"x").await.expect("written");
    let (mut b_writer, mut b_reader) = b_dialled.open_stream().await.expect("stream");
    b_writer.write_all(b"x").await.expect("written");
    let b_accepted =
        tokio::time::timeout(STEP, b.replication_inbound.recv()).await.unwrap().unwrap();
    let a_accepted =
        tokio::time::timeout(STEP, a.replication_inbound.recv()).await.unwrap().unwrap();
    let (_b_accepted_writer, _b_accepted_reader) = b_accepted.accept_stream().await.expect("B");
    let (_a_accepted_writer, _a_accepted_reader) = a_accepted.accept_stream().await.expect("A");

    assert_eq!(a.node.native_replication_connections().close_to(&b_id), 2);
    assert!(ends(&mut a_reader).await, "the connection A dialled must be closed");
    assert!(ends(&mut b_reader).await, "the connection B dialled into A must be closed");
    assert_eq!(a.node.native_replication_connections().close_to(&b_id), 0);
}

/// The core safety property: a malformed/broken native-replication connection
/// never touches the sync connection between the same two peers.
#[tokio::test(flavor = "multi_thread")]
async fn a_native_replication_failure_never_closes_the_sync_connection_to_the_same_peer() {
    let book = SharedAddressBook::new();
    let (a_key, b_key) = (key(71), key(72));
    let (a_id, b_id) = (peer_of(&a_key), peer_of(&b_key));
    let a = spawn(a_key, &book, only(b_id), only(b_id)).await;
    let mut b = spawn(b_key, &book, only(a_id), only(a_id)).await;

    // Establish a real sync link first.
    let link = tokio::time::timeout(STEP, a.node.connect(b_id))
        .await
        .expect("connect completes")
        .expect("sync link established");
    let mut lane =
        link.open_lane(yadorilink_sync_substrate::Lane::Service).await.expect("lane opens");

    // Open a native-replication connection, then abruptly slam it shut (as a
    // malformed peer or a crash would) with an error close code.
    let replication = a
        .node
        .connect_native_replication(&b.node.local_address())
        .await
        .expect("replication dials");
    let _accepted =
        tokio::time::timeout(STEP, b.replication_inbound.recv()).await.unwrap().unwrap();
    replication.close(2, b"malformed frame");

    // The sync lane, opened before the replication connection ever existed,
    // must still carry bytes afterward -- unaffected.
    use tokio::io::AsyncWriteExt;
    lane.write_all(b"ping").await.expect("sync lane still writable after replication closed");
    // (Best-effort liveness check only -- this test's real assertion is
    // that the write above did not error, i.e. the sync connection is
    // still open; a full round trip needs the peer side listening on this
    // exact lane, which is daemon-level plumbing outside this crate.)
    drop(lane);
}

/// ALPN isolation: repeated
/// shutdown/restart with an active native-replication connection leaks nothing.
///
/// `NativeReplicationConnections` holds only `Weak` handles by construction
/// (per this ALPN's own doc), so nothing here can literally "leak" a
/// strong reference the way an `Arc` cycle could -- but that argument was
/// never independently exercised. This test makes it so: `live_count`
/// (a non-mutating read, unlike `close_to` -- which actively closes and
/// removes every connection it counts, and so cannot be used to observe a
/// count without pre-empting whatever came after) is used across several
/// full shutdown/respawn cycles, each one leaving an open connection
/// behind at the moment of shutdown, to confirm the count is 1 right
/// before shutdown and independently 0 right after -- not just
/// architecturally reasoned, but counted, and counted by something that
/// cannot itself manufacture the result.
#[tokio::test(flavor = "multi_thread")]
async fn repeated_shutdown_with_an_open_native_replication_connection_leaves_nothing_behind() {
    let book = SharedAddressBook::new();
    let b_key = key(73);
    let b_id = peer_of(&b_key);

    for round in 0..6u8 {
        let a_key = key(80 + round);
        let a_id = peer_of(&a_key);
        let a = spawn(a_key, &book, Arc::new(AdmitNone), only(b_id)).await;
        let mut b = spawn(b_key.clone(), &book, Arc::new(AdmitNone), only(a_id)).await;

        // Establish a real, still-open native-replication connection in both
        // directions, then shut both nodes down WITHOUT closing it first
        // -- the scenario a real crash/restart looks like.
        let a_dialled =
            a.node.connect_native_replication(&b.node.local_address()).await.expect("A dials");
        let (mut a_writer, _a_reader) = a_dialled.open_stream().await.expect("A opens a stream");
        a_writer.write_all(b"x").await.expect("A writes");
        let _b_accepted = tokio::time::timeout(STEP, b.replication_inbound.recv())
            .await
            .expect("B accepts before shutdown")
            .expect("B accepts before shutdown");
        assert_eq!(
            a.node.native_replication_connections().live_count(&b_id),
            1,
            "round {round}: exactly the one connection just opened should be live before shutdown"
        );

        a.node.shutdown().await;
        b.node.shutdown().await;

        assert_eq!(
            a.node.native_replication_connections().live_count(&b_id),
            0,
            "round {round}: shutting the node down must drop its native-replication connections, not merely close them at the transport level"
        );
    }
}
