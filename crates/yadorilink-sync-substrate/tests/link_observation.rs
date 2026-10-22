//! What a node reports about the connections it dials and accepts, and how a
//! connection's carrier is followed.
//!
//! The daemon shows a peer as connected, directly or through a relay, from
//! these reports alone. So each one is checked against a real endpoint: a
//! dial reports its start and its end exactly once, an accepted connection is
//! reported, and following a connection's carrier names the path that is
//! really carrying it and stops when the connection is gone.

#![cfg(feature = "test-support")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use yadorilink_sync_substrate::testing::{InProcessRelay, SharedAddressBook};
use yadorilink_sync_substrate::{
    AddressDirectory, Carrier, DialFailure, LinkEvent, LinkObserver, NetworkConfig, PeerId,
    PeerLink, SubstrateNode,
};

/// A report, reduced to what can be compared after the fact.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    Dialing(PeerId),
    Dialed(PeerId, Result<PeerId, DialFailure>),
    Accepted(PeerId),
}

fn recording() -> (LinkObserver, Arc<Mutex<Vec<Seen>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    let observer = LinkObserver::new(move |event| {
        let entry = match event {
            LinkEvent::Dialing(peer) => Seen::Dialing(peer),
            LinkEvent::Dialed(peer, outcome) => Seen::Dialed(peer, outcome.map(PeerLink::peer)),
            LinkEvent::Accepted(link) => Seen::Accepted(link.peer()),
        };
        sink.lock().unwrap().push(entry);
    });
    (observer, seen)
}

async fn spawn(
    config: NetworkConfig,
    book: &SharedAddressBook,
    observer: LinkObserver,
) -> (SubstrateNode, tokio::sync::mpsc::Receiver<PeerLink>) {
    SubstrateNode::spawn(
        iroh::SecretKey::generate(),
        config.with_directory(Arc::new(book.clone())).with_link_observer(observer),
        Arc::new(yadorilink_sync_substrate::AdmitAnyAuthenticated),
    )
    .await
    .expect("substrate starts")
}

/// Polls `condition` until it holds, failing with `what` after 10 s.
async fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(tokio::time::Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dial_is_reported_when_it_starts_and_when_it_connects_and_the_peer_reports_the_accept() {
    let book = SharedAddressBook::new();
    let (server_observer, server_seen) = recording();
    let (client_observer, client_seen) = recording();
    let (server, mut inbound) = spawn(NetworkConfig::direct_only(), &book, server_observer).await;
    let (client, _client_inbound) =
        spawn(NetworkConfig::direct_only(), &book, client_observer).await;
    book.wait_published(server.peer_id()).await;

    let link = client.connect(server.peer_id()).await.expect("connects directly");
    let _accepted = inbound.recv().await.expect("the server hands the link on");

    assert_eq!(
        *client_seen.lock().unwrap(),
        vec![Seen::Dialing(server.peer_id()), Seen::Dialed(server.peer_id(), Ok(server.peer_id()))],
        "one start and one end for one dial"
    );
    assert_eq!(*server_seen.lock().unwrap(), vec![Seen::Accepted(client.peer_id())]);
    drop(link);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dial_with_no_address_to_try_is_reported_as_such() {
    let book = SharedAddressBook::new();
    let (observer, seen) = recording();
    let (client, _inbound) = spawn(NetworkConfig::direct_only(), &book, observer).await;
    let nobody = PeerId::from_bytes(*iroh::SecretKey::generate().public().as_bytes());

    assert!(client.connect(nobody).await.is_err(), "nothing to dial");

    assert_eq!(
        *seen.lock().unwrap(),
        vec![Seen::Dialing(nobody), Seen::Dialed(nobody, Err(DialFailure::NoAddress))]
    );
}

/// A caller that gives up on a dial -- a deadline dropping its future --
/// still leaves the observer told that the dial ended. Otherwise the peer
/// would read as "connecting" for the life of the process.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dial_its_caller_abandons_is_still_reported_as_ended() {
    let book = SharedAddressBook::new();
    let (observer, seen) = recording();
    let (client, _inbound) = spawn(NetworkConfig::direct_only(), &book, observer).await;
    // An address that swallows datagrams: nothing listens on a port of a
    // documentation-range address, so the dial neither connects nor fails.
    let silent = PeerId::from_bytes(*iroh::SecretKey::generate().public().as_bytes());
    book.publish(silent, vec!["192.0.2.1:9".parse().unwrap()], vec![]);

    let abandoned = tokio::time::timeout(Duration::from_millis(300), client.connect(silent)).await;
    assert!(abandoned.is_err(), "precondition: the dial was still running when abandoned");

    assert_eq!(
        *seen.lock().unwrap(),
        vec![Seen::Dialing(silent), Seen::Dialed(silent, Err(DialFailure::NoResponse))]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_direct_link_reports_a_direct_carrier_and_stops_reporting_once_closed() {
    let book = SharedAddressBook::new();
    let (server, mut inbound) = spawn(NetworkConfig::direct_only(), &book, recording().0).await;
    let (client, _client_inbound) = spawn(NetworkConfig::direct_only(), &book, recording().0).await;
    book.wait_published(server.peer_id()).await;

    let link = client.connect(server.peer_id()).await.expect("connects directly");
    let _accepted = inbound.recv().await.expect("the server hands the link on");

    let mut changes = link.carrier_changes();
    assert_eq!(changes.next().await, Some(Some(Carrier::Direct)));

    link.close();
    let ended = tokio::time::timeout(Duration::from_secs(10), async {
        while changes.next().await.is_some() {}
    })
    .await;
    assert!(ended.is_ok(), "following a closed connection ends");
}

/// Following a connection does not keep it open: once every owner drops it,
/// it closes and the follower stops.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn following_a_link_does_not_keep_it_open() {
    let book = SharedAddressBook::new();
    let (server, mut inbound) = spawn(NetworkConfig::direct_only(), &book, recording().0).await;
    let (client, _client_inbound) = spawn(NetworkConfig::direct_only(), &book, recording().0).await;
    book.wait_published(server.peer_id()).await;

    let link = client.connect(server.peer_id()).await.expect("connects directly");
    let accepted = inbound.recv().await.expect("the server hands the link on");
    let mut changes = link.carrier_changes();
    assert_eq!(changes.next().await, Some(Some(Carrier::Direct)), "precondition");

    drop(link);
    eventually("the server sees the dropped connection close", || !accepted.is_alive()).await;
    let ended = tokio::time::timeout(Duration::from_secs(10), async {
        while changes.next().await.is_some() {}
    })
    .await;
    assert!(ended.is_ok(), "following a dropped connection ends");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relayed_link_reports_the_relay_as_its_carrier() {
    let relay = InProcessRelay::start().await.expect("in-process relay starts");
    let book = SharedAddressBook::new();
    let (server, mut inbound) = spawn(relay.direct_or_relay(), &book, recording().0).await;
    let (client, _client_inbound) = spawn(relay.relay_only(), &book, recording().0).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while book.resolve(server.peer_id()).is_none_or(|(_, relays)| relays.is_empty()) {
        assert!(tokio::time::Instant::now() < deadline, "the server never published a relay");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let link = client.connect(server.peer_id()).await.expect("connects through the relay");
    let _accepted = inbound.recv().await.expect("the server hands the link on");

    let mut changes = link.carrier_changes();
    assert_eq!(changes.next().await, Some(Some(Carrier::Relay)));
}
