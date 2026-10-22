//! The relay harness itself.
//!
//! Everything the relay track asserts later rests on one claim: that a node
//! configured relay-only really is relayed, for the whole life of the
//! connection, without touching public infrastructure. If that claim is
//! wrong — if a direct path quietly appears partway through — then every
//! "over the relay" result above it is measuring something else.
//!
//! So this file gates the harness, not the protocol.

#![cfg(feature = "test-support")]

mod common;

use std::time::Duration;

use common::{round_trip, serve_echo};
use yadorilink_sync_substrate::testing::InProcessRelay;
use yadorilink_sync_substrate::{Carrier, Lane, NetworkConfig, PeerLink, SubstrateNode};

async fn spawn_with(
    config: NetworkConfig,
) -> (SubstrateNode, tokio::sync::mpsc::Receiver<PeerLink>) {
    SubstrateNode::spawn(
        iroh::SecretKey::generate(),
        config.with_directory(std::sync::Arc::new(shared_book())),
        std::sync::Arc::new(yadorilink_sync_substrate::AdmitAnyAuthenticated),
    )
    .await
    .expect("substrate starts")
}

/// Every node in this binary publishes into, and resolves out of, one book --
/// the stand-in for the coordination plane. Relay tests need it as much as
/// direct ones: a node is dialled by endpoint id, and the relay URL it can be
/// reached on is part of what the directory answers.
fn shared_book() -> yadorilink_sync_substrate::testing::SharedAddressBook {
    static BOOK: std::sync::OnceLock<yadorilink_sync_substrate::testing::SharedAddressBook> =
        std::sync::OnceLock::new();
    BOOK.get_or_init(yadorilink_sync_substrate::testing::SharedAddressBook::new).clone()
}

/// Waits for `node`'s address to include a relay, which is what a peer needs
/// in order to dial it through one.
///
/// A node registers with its home relay asynchronously after binding; dialling
/// before that has happened fails for a reason that has nothing to do with
/// what any of these tests are about.
async fn relay_address(node: &SubstrateNode) -> yadorilink_sync_substrate::PeerAddress {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let address = node.local_address();
        if address.relay_urls().next().is_some() {
            return address;
        }
        assert!(tokio::time::Instant::now() < deadline, "the node never registered with a relay");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A relay-only node reaches a peer, and does so over the relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_only_node_reaches_its_peer_through_the_relay() {
    let relay = InProcessRelay::start().await.expect("in-process relay starts");

    let (server, mut inbound) = spawn_with(relay.direct_or_relay()).await;
    let (client, _client_inbound) = spawn_with(relay.relay_only()).await;

    let server_address = relay_address(&server).await;
    let served = tokio::spawn(async move {
        let link = inbound.recv().await.expect("inbound link");
        serve_echo(link).await.ok();
    });

    let link = client.connect(server_address.peer()).await.expect("connect through the relay");
    let mut lane = link.open_lane(Lane::Service).await.expect("lane");
    round_trip(&mut lane, b"carried by the relay").await;

    assert_eq!(
        link.carrier(),
        Some(Carrier::Relay),
        "a node with no IP transport must be sending over the relay"
    );
    assert!(
        !link.has_direct_path(),
        "a node with no IP transport must not acquire a direct path at all"
    );

    served.abort();
}

/// The relay stays the carrier — it is not a path the connection drifts off.
///
/// Withholding a peer's direct addresses only controls the first attempt:
/// iroh hole-punches its way to a direct path, and a test that sampled the
/// carrier once at the start would then be measuring a direct connection for
/// most of its run. This keeps traffic flowing and re-checks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_relay_carrier_does_not_drift_to_direct_under_traffic() {
    let relay = InProcessRelay::start().await.expect("in-process relay starts");

    let (server, mut inbound) = spawn_with(relay.direct_or_relay()).await;
    let (client, _client_inbound) = spawn_with(relay.relay_only()).await;

    let server_address = relay_address(&server).await;
    let served = tokio::spawn(async move {
        let link = inbound.recv().await.expect("inbound link");
        serve_echo(link).await.ok();
    });

    let link = client.connect(server_address.peer()).await.expect("connect through the relay");
    for round in 0..20u8 {
        let mut lane = link.open_lane(Lane::Block).await.expect("lane");
        round_trip(&mut lane, &vec![round; 64 * 1024]).await;
        assert_eq!(
            link.carrier(),
            Some(Carrier::Relay),
            "the carrier changed to direct at round {round}"
        );
        assert!(!link.has_direct_path(), "a direct path opened at round {round}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    served.abort();
}

/// A node that *can* go direct does, when both ends have IP transports.
///
/// The contrast that makes the two tests above mean something: the same relay
/// configuration, with the client's IP transports left in place, ends up on a
/// direct path. Without this, "relayed" might just be what this harness always
/// produces.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_that_can_go_direct_does_not_stay_on_the_relay() {
    let relay = InProcessRelay::start().await.expect("in-process relay starts");

    let (server, mut inbound) = spawn_with(relay.direct_or_relay()).await;
    let (client, _client_inbound) = spawn_with(relay.direct_or_relay()).await;

    let server_address = relay_address(&server).await;
    let served = tokio::spawn(async move {
        let link = inbound.recv().await.expect("inbound link");
        serve_echo(link).await.ok();
    });

    let link = client.connect(server_address.peer()).await.expect("connect");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let mut lane = link.open_lane(Lane::Service).await.expect("lane");
        round_trip(&mut lane, b"looking for a direct path").await;
        if link.has_direct_path() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "two loopback nodes with IP transports never found a direct path"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    served.abort();
}

/// Gate: the witness reports a real relayed transfer as relayed.
///
/// The unit tests prove the accumulator's arithmetic; this proves it is wired
/// to something true. A relay-only node moves real bytes over a real relay, and
/// the witness has to say so -- because the number this gates is a competitive
/// benchmark that claims to measure a direct path, and a relayed transfer
/// reported as direct would be a false claim rather than a noisy one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relayed_transfer_is_not_reported_as_direct() {
    let relay = InProcessRelay::start().await.expect("in-process relay");
    let (server, mut inbound) = spawn_with(relay.relay_only()).await;
    let (client, _client_inbound) = spawn_with(relay.relay_only()).await;

    let server_addr = relay_address(&server).await;
    let server_task = tokio::spawn(async move {
        let link = inbound.recv().await.expect("inbound link");
        serve_echo(link).await.ok();
    });

    let link = client.connect(server_addr.peer()).await.expect("connect through the relay");
    // Subscribed before a single byte crosses, which is the whole point: a
    // witness that starts after the transfer cannot see what already moved.
    let watcher = link.watch_paths();

    let mut lane = link.open_lane(Lane::Service).await.expect("lane");
    round_trip(&mut lane, &vec![0xA5u8; 256 * 1024]).await;

    // The verdict is taken when the TRANSFER ends, with the connection still
    // up -- which is what a benchmark can actually do.
    let witness = watcher.finish().await;
    drop(lane);
    drop(link);
    server_task.abort();

    assert!(
        witness.relay_tx_bytes > 0,
        "a transfer that could only have gone over the relay must be counted there: {witness:?}"
    );
    assert!(
        !witness.is_direct_only(),
        "and must never be reported as a direct-path measurement: {witness:?}"
    );
    assert!(witness.rejection().is_some(), "with a reason a result record can carry");
}

/// Gate: a path that closes just as the transfer ends is still counted.
///
/// This is the boundary the first implementation got wrong. `finish()` aborted
/// the event pump, so a `Closed` event that iroh had already emitted but the
/// pump had not yet consumed was simply discarded -- and a relay whose close
/// event is dropped is also absent from the paths snapshot, so the verdict came
/// out "direct only". Not `Lagged` either: the events were delivered, we failed
/// to look at them, so nothing marked the result incomplete.
///
/// Here the relay path is closed deliberately, immediately before the verdict
/// is taken, with no sleep anywhere -- so the test fails whenever `finish()`
/// stops draining and starts discarding.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_path_closing_at_the_last_moment_is_not_lost() {
    let relay = InProcessRelay::start().await.expect("in-process relay");
    let (server, mut inbound) = spawn_with(relay.relay_only()).await;
    let (client, _client_inbound) = spawn_with(relay.relay_only()).await;

    let server_addr = relay_address(&server).await;
    let server_task = tokio::spawn(async move {
        let link = inbound.recv().await.expect("inbound link");
        serve_echo(link).await.ok();
    });

    let link = client.connect(server_addr.peer()).await.expect("connect through the relay");
    let watcher = link.watch_paths();

    let mut lane = link.open_lane(Lane::Service).await.expect("lane");
    round_trip(&mut lane, &vec![0x3Cu8; 128 * 1024]).await;

    // Tear the connection down so its paths close, then ask immediately. The
    // close events are in flight at exactly the moment the verdict is taken.
    drop(lane);
    server_task.abort();
    server.shutdown().await;

    let witness = watcher.finish().await;

    assert!(
        witness.relay_tx_bytes > 0 || witness.incomplete,
        "a relay that carried bytes must be counted even when its path closed at the \
         last moment -- or the run must be marked incomplete, never silently direct: {witness:?}"
    );
    // Taken AFTER the connection closed, which is the double-count boundary:
    // closing emits `Closed` for every still-open path and leaves those paths
    // in the list a snapshot reads. A payload of 128 KiB echoed both ways
    // cannot legitimately account for megabytes, so a doubled total shows up
    // here rather than as a plausible-looking number in a benchmark.
    assert!(
        witness.relay_tx_bytes < 4 * 1024 * 1024,
        "the transfer was 128 KiB each way; a total this large means paths were counted \
         more than once: {witness:?}"
    );
    assert!(
        !witness.is_direct_only(),
        "a relay-only transfer must never come out as a direct-path measurement: {witness:?}"
    );
    drop(link);
}
