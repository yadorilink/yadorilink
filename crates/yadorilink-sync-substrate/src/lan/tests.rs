//! The LAN lookup's authorization filter, at the lookup and at a real
//! endpoint.
//!
//! Multicast is not something a test host reliably delivers, so the mDNS
//! source is replaced by an address book one peer publishes into -- "what the
//! LAN would have announced". Everything in front of it, the filter and the
//! iroh endpoint that consumes its answers, is production code.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::*;
use crate::directory::DirectoryLookup;
use crate::testing::SharedAddressBook;
use crate::{AdmitAnyAuthenticated, AdmitNone, AdmitWhen, NetworkConfig, SubstrateNode};

/// What the LAN announced, and how often it was asked.
#[derive(Debug)]
struct Announced {
    lookup: DirectoryLookup,
    asked: AtomicUsize,
}

impl Announced {
    fn from(book: &SharedAddressBook) -> Arc<Self> {
        Arc::new(Self {
            lookup: DirectoryLookup::new(Arc::new(book.clone()), PeerId::from_bytes([0; 32])),
            asked: AtomicUsize::new(0),
        })
    }

    fn times_asked(&self) -> usize {
        self.asked.load(Ordering::SeqCst)
    }
}

impl AddressLookup for Announced {
    fn publish(&self, _data: &EndpointData) {}

    fn resolve(&self, endpoint_id: iroh::EndpointId) -> Option<BoxStream<Result<Item, Error>>> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        self.lookup.resolve(endpoint_id)
    }
}

/// A LAN on which `peer` has announced `addr`.
fn lan_announcing(peer: PeerId, addr: std::net::SocketAddr) -> Arc<Announced> {
    let book = SharedAddressBook::new();
    crate::directory::AddressDirectory::publish(&book, peer, vec![addr], Vec::new());
    Announced::from(&book)
}

fn endpoint(seed: u8) -> iroh::EndpointId {
    iroh::SecretKey::from_bytes(&[seed; 32]).public()
}

/// An endpoint the policy does not accept resolves to nothing, and the LAN
/// is not even asked about it -- an announcement is never a reason to talk to
/// the endpoint it names.
#[tokio::test]
async fn an_unauthorized_endpoint_never_resolves_from_the_lan() {
    let stranger = endpoint(3);
    let lan =
        lan_announcing(PeerId::from_bytes(*stranger.as_bytes()), "10.0.0.3:4433".parse().unwrap());
    let lookup = LanLookup::new(lan.clone(), Arc::new(AdmitNone));

    assert!(lookup.resolve(stranger).is_none(), "an unauthorized endpoint got a LAN address");
    assert_eq!(lan.times_asked(), 0, "the LAN was consulted for an unauthorized endpoint");
}

/// The policy is asked on every lookup, not once: a peer that stops being
/// authorized after it was discovered stops resolving at that moment.
#[tokio::test]
async fn a_peer_revoked_after_discovery_stops_resolving() {
    use n0_future::StreamExt as _;

    let peer = endpoint(4);
    let lan =
        lan_announcing(PeerId::from_bytes(*peer.as_bytes()), "10.0.0.4:4433".parse().unwrap());
    let authorized = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let policy = {
        let authorized = authorized.clone();
        AdmitWhen::new(move |_: &PeerId| authorized.load(Ordering::SeqCst))
    };
    let lookup = LanLookup::new(lan, policy);

    let item = lookup
        .resolve(peer)
        .expect("authorized")
        .next()
        .await
        .expect("an answer")
        .expect("not an error");
    assert_eq!(item.endpoint_id(), peer);

    authorized.store(false, Ordering::SeqCst);
    assert!(lookup.resolve(peer).is_none(), "a revoked peer still resolved from the LAN");
}

/// An answer about an endpoint other than the one asked for is dropped: the
/// filter judged the endpoint asked about, not that one.
#[tokio::test]
async fn an_answer_about_another_endpoint_is_dropped() {
    use n0_future::StreamExt as _;

    #[derive(Debug)]
    struct Misdirected(iroh::EndpointId);
    impl AddressLookup for Misdirected {
        fn publish(&self, _data: &EndpointData) {}
        fn resolve(&self, _asked: iroh::EndpointId) -> Option<BoxStream<Result<Item, Error>>> {
            let info = iroh::address_lookup::EndpointInfo::new(self.0)
                .with_ip_addrs(["10.0.0.9:4433".parse().unwrap()].into_iter().collect());
            let item = Item::new(info, "test", None);
            Some(Box::pin(n0_future::stream::once(Ok(item))))
        }
    }

    let lookup = LanLookup::new(Misdirected(endpoint(9)), Arc::new(AdmitAnyAuthenticated));
    let answers: Vec<_> = lookup.resolve(endpoint(5)).expect("authorized").collect().await;
    assert!(answers.is_empty(), "an answer naming another endpoint got through: {answers:?}");
}

/// The requirement this lookup exists for: the coordination directory knows
/// nothing (the plane is down), and an authorized peer on the same LAN is
/// still reached, directly, from what the LAN announced.
#[tokio::test]
async fn an_authorized_peer_is_reached_over_the_lan_while_the_directory_knows_nothing() {
    let bob_key = iroh::SecretKey::from_bytes(&[21; 32]);
    let bob_id = PeerId::from_bytes(*bob_key.public().as_bytes());
    // Bob publishes into what stands in for the LAN; Alice's coordination
    // directory is a different, empty book.
    let lan_book = SharedAddressBook::new();
    let (bob, mut bob_inbound) = SubstrateNode::spawn(
        bob_key,
        NetworkConfig::direct_only().with_directory(Arc::new(lan_book.clone())),
        Arc::new(AdmitAnyAuthenticated),
    )
    .await
    .expect("bob starts");
    lan_book.wait_published(bob_id).await;
    tokio::spawn(async move { while bob_inbound.recv().await.is_some() {} });

    let coordination_down = SharedAddressBook::new();
    let lan = Announced::from(&lan_book);
    let (alice, _alice_inbound) = SubstrateNode::spawn(
        iroh::SecretKey::from_bytes(&[22; 32]),
        NetworkConfig::direct_only()
            .with_directory(Arc::new(coordination_down))
            .with_lan_source_for_tests(lan.clone())
            .with_lan_peers(AdmitWhen::new(move |peer: &PeerId| *peer == bob_id)),
        Arc::new(AdmitNone),
    )
    .await
    .expect("alice starts");

    let link = tokio::time::timeout(Duration::from_secs(20), alice.connect(bob_id))
        .await
        .expect("the dial did not finish")
        .expect("an authorized peer on the LAN was not reached");
    assert_eq!(link.peer(), bob_id);
    assert!(lan.times_asked() > 0, "reached without asking the LAN: the test proves nothing");

    alice.shutdown().await;
    bob.shutdown().await;
}

/// The same LAN, the same announcement, a peer the policy does not accept:
/// the endpoint is given no address for it, so it is never dialled.
#[tokio::test]
async fn an_unauthorized_peer_announced_on_the_lan_is_never_dialled() {
    let bob_key = iroh::SecretKey::from_bytes(&[23; 32]);
    let bob_id = PeerId::from_bytes(*bob_key.public().as_bytes());
    let lan_book = SharedAddressBook::new();
    let (bob, mut bob_inbound) = SubstrateNode::spawn(
        bob_key,
        NetworkConfig::direct_only().with_directory(Arc::new(lan_book.clone())),
        Arc::new(AdmitAnyAuthenticated),
    )
    .await
    .expect("bob starts");
    lan_book.wait_published(bob_id).await;
    let reached = Arc::new(AtomicUsize::new(0));
    {
        let reached = reached.clone();
        tokio::spawn(async move {
            while bob_inbound.recv().await.is_some() {
                reached.fetch_add(1, Ordering::SeqCst);
            }
        });
    }

    let lan = Announced::from(&lan_book);
    let (alice, _alice_inbound) = SubstrateNode::spawn(
        iroh::SecretKey::from_bytes(&[24; 32]),
        NetworkConfig::direct_only()
            .with_directory(Arc::new(SharedAddressBook::new()))
            .with_lan_source_for_tests(lan.clone())
            .with_lan_peers(Arc::new(AdmitNone)),
        Arc::new(AdmitNone),
    )
    .await
    .expect("alice starts");

    let dialled = tokio::time::timeout(Duration::from_secs(20), alice.connect(bob_id)).await;
    assert!(
        !matches!(dialled, Ok(Ok(_))),
        "an unauthorized peer was reached from a LAN announcement"
    );
    assert_eq!(lan.times_asked(), 0, "the LAN was consulted for an unauthorized peer");
    assert_eq!(reached.load(Ordering::SeqCst), 0, "the unauthorized peer saw a connection");

    alice.shutdown().await;
    bob.shutdown().await;
}

/// Real mDNS, no scripted source: two endpoints on this host with no
/// directory at all find each other over multicast, each accepting only the
/// other.
///
/// Ignored by default because it needs a host that delivers multicast to
/// itself, which CI runners and sandboxes often do not. Run it by name with
/// `--ignored` on a developer machine.
#[tokio::test]
#[ignore = "needs a host that delivers local multicast"]
async fn two_authorized_endpoints_find_each_other_over_real_mdns() {
    let alice_key = iroh::SecretKey::from_bytes(&[31; 32]);
    let bob_key = iroh::SecretKey::from_bytes(&[32; 32]);
    let alice_id = PeerId::from_bytes(*alice_key.public().as_bytes());
    let bob_id = PeerId::from_bytes(*bob_key.public().as_bytes());
    let only = |peer: PeerId| AdmitWhen::new(move |candidate: &PeerId| *candidate == peer);

    let (bob, mut bob_inbound) = SubstrateNode::spawn(
        bob_key,
        NetworkConfig::direct_only().with_lan_discovery().with_lan_peers(only(alice_id)),
        only(alice_id),
    )
    .await
    .expect("bob starts");
    tokio::spawn(async move { while bob_inbound.recv().await.is_some() {} });
    let (alice, _alice_inbound) = SubstrateNode::spawn(
        alice_key,
        NetworkConfig::direct_only().with_lan_discovery().with_lan_peers(only(bob_id)),
        only(bob_id),
    )
    .await
    .expect("alice starts");

    let link = tokio::time::timeout(Duration::from_secs(30), alice.connect(bob_id))
        .await
        .expect("the dial did not finish")
        .expect("an authorized peer was not found over mDNS");
    assert_eq!(link.peer(), bob_id);

    alice.shutdown().await;
    bob.shutdown().await;
}
