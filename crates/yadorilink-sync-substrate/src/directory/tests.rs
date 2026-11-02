#![cfg(test)]

use super::*;
use iroh::address_lookup::AddressLookup as _;
use std::net::SocketAddr;
use std::sync::Mutex;

/// One recorded `publish` call: the peer, its direct addresses, its relays.
type Published = (PeerId, Vec<SocketAddr>, Vec<String>);

/// Records what was published and answers resolves from a fixed table.
#[derive(Debug, Default)]
struct Fake {
    published: Mutex<Vec<Published>>,
    answer: Mutex<Option<(Vec<SocketAddr>, Vec<String>)>>,
    /// When set, `changes` hands out a receiver of this channel.
    changes: Mutex<Option<tokio::sync::broadcast::Sender<()>>>,
}

impl AddressDirectory for Fake {
    fn publish(&self, peer: PeerId, direct: Vec<SocketAddr>, relays: Vec<String>) {
        self.published.lock().unwrap().push((peer, direct, relays));
    }
    fn resolve(&self, _peer: PeerId) -> Option<(Vec<SocketAddr>, Vec<String>)> {
        self.answer.lock().unwrap().clone()
    }
    fn changes(&self, _peer: PeerId) -> Option<ChangeStream> {
        let sender = self.changes.lock().unwrap().clone()?;
        let receiver = sender.subscribe();
        Some(Box::pin(n0_future::stream::unfold(receiver, |mut receiver| async move {
            receiver.recv().await.ok()?;
            Some(((), receiver))
        })))
    }
}

fn endpoint_id(seed: u8) -> iroh::EndpointId {
    iroh::SecretKey::from_bytes(&[seed; 32]).public()
}

/// Gate: a resolve answers with the substrate's own socket, and nothing
/// else.
///
/// The defect this closes had reconciliation dialling the legacy
/// peer-session socket, because the two transports shared one candidate
/// list and neither could tell which entry was its own. Nothing reaches
/// this lookup except what the directory holds for the substrate, so a
/// future change that reintroduced the shared list would have to come
/// through here to do it.
#[tokio::test]
async fn a_resolve_answers_with_the_substrate_socket_and_no_other() {
    use n0_future::StreamExt as _;

    let substrate: SocketAddr = "127.0.0.1:44444".parse().unwrap();
    let legacy: SocketAddr = "127.0.0.1:55555".parse().unwrap();

    let fake = Arc::new(Fake::default());
    *fake.answer.lock().unwrap() = Some((vec![substrate], Vec::new()));
    let lookup = DirectoryLookup::new(fake.clone(), PeerId::from_bytes([1u8; 32]));

    let id = endpoint_id(9);
    let mut stream = lookup.resolve(id).expect("the directory knows this endpoint");
    let item = stream.next().await.expect("one item").expect("not an error");

    let addrs: Vec<SocketAddr> = item
        .endpoint_info()
        .addrs()
        .filter_map(|a| match a {
            iroh::TransportAddr::Ip(socket) => Some(*socket),
            _ => None,
        })
        .collect();

    assert_eq!(addrs, vec![substrate], "reconciliation must resolve to the substrate socket");
    assert!(
        !addrs.contains(&legacy),
        "the legacy peer-session socket must never be a reconciliation destination"
    );
    assert_eq!(item.endpoint_id(), id);
}

/// Gate: an endpoint this directory knows nothing about resolves to
/// nothing, rather than to an empty answer iroh would treat as an address
/// set worth trying.
#[tokio::test]
async fn an_unknown_endpoint_resolves_to_nothing() {
    let fake = Arc::new(Fake::default());
    let lookup = DirectoryLookup::new(fake, PeerId::from_bytes([1u8; 32]));
    assert!(lookup.resolve(endpoint_id(3)).is_none());
}

/// Gate: publishing carries this endpoint's own identity.
///
/// `EndpointData` has addresses and no id, so the id has to come from
/// construction. Getting that wrong would publish this device's addresses
/// under someone else's name, which no later resolve could detect.
#[tokio::test]
async fn publishing_names_this_endpoint() {
    let fake = Arc::new(Fake::default());
    let local = PeerId::from_bytes([7u8; 32]);
    let lookup = DirectoryLookup::new(fake.clone(), local);

    let socket: SocketAddr = "127.0.0.1:44444".parse().unwrap();
    lookup.publish(&iroh::address_lookup::EndpointData::new(vec![iroh::TransportAddr::Ip(socket)]));

    let published = fake.published.lock().unwrap();
    assert_eq!(published.len(), 1);
    assert_eq!(published[0].0, local, "published under this endpoint's own identity");
    assert_eq!(published[0].1, vec![socket]);
}

mod hairpin {
    use super::super::{is_public, without_hairpin};
    use std::collections::HashSet;
    use std::net::{IpAddr, SocketAddr};

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn own(ip: &str) -> HashSet<IpAddr> {
        HashSet::from([ip.parse().unwrap()])
    }

    #[test]
    fn a_candidate_on_our_own_public_ip_is_dropped_when_the_lan_or_a_relay_remains() {
        let own = own("130.62.15.117");
        let public = addr("130.62.15.117:41939");
        let lan = addr("192.168.0.207:55519");
        let other = addr("203.0.113.9:5000");
        // The LAN address is another way in.
        assert_eq!(without_hairpin(vec![public, lan], false, &own), vec![lan]);
        // So is a relay.
        assert_eq!(without_hairpin(vec![public, other], true, &own), vec![other]);
        // Another device's own public address is never the hairpin.
        assert_eq!(without_hairpin(vec![other], false, &own), vec![other]);
    }

    #[test]
    fn the_only_way_in_is_kept_even_if_it_is_the_hairpin() {
        let own = own("130.62.15.117");
        let public = addr("130.62.15.117:41939");
        assert_eq!(without_hairpin(vec![public], false, &own), vec![public]);
        // Nothing known about our own public address: nothing to drop.
        assert_eq!(
            without_hairpin(vec![public, addr("192.168.0.2:1")], true, &HashSet::new()),
            vec![public, addr("192.168.0.2:1")]
        );
    }

    #[test]
    fn public_means_reachable_from_other_networks() {
        for ip in ["130.62.15.117", "2001:db8::1"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in
            ["192.168.0.1", "10.0.0.1", "127.0.0.1", "169.254.1.1", "fd00::1", "fe80::1", "::1"]
        {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
    }
}

/// A relay that only becomes known after the first lookup still reaches iroh, on the stream it
/// already holds: that is the only way a connection made before the relay was known can learn it.
#[tokio::test]
async fn a_relay_recorded_after_the_first_resolve_arrives_on_the_same_stream() {
    use n0_future::StreamExt as _;

    let lan: SocketAddr = "192.168.0.7:44444".parse().unwrap();
    let fake = Arc::new(Fake::default());
    *fake.answer.lock().unwrap() = Some((vec![lan], Vec::new()));
    let (tx, _keep) = tokio::sync::broadcast::channel(4);
    *fake.changes.lock().unwrap() = Some(tx.clone());
    let lookup = DirectoryLookup::new(fake.clone(), PeerId::from_bytes([1u8; 32]));

    let mut stream = lookup.resolve(endpoint_id(9)).expect("known");
    let first = stream.next().await.expect("item").expect("ok");
    assert_eq!(first.endpoint_info().relay_urls().count(), 0);

    *fake.answer.lock().unwrap() = Some((vec![lan], vec!["https://relay.example./".to_string()]));
    tx.send(()).unwrap();
    let second = stream.next().await.expect("item").expect("ok");
    assert_eq!(second.endpoint_info().relay_urls().count(), 1);
    assert!(stream.next().await.is_none(), "the lookup ends once it has delivered a relay");
}

/// A lookup that never sees a relay ends after its window, so iroh can start the next one (and
/// LAN discovery's with it) instead of holding this one open for ever.
#[tokio::test]
async fn a_lookup_waiting_for_a_relay_ends_after_its_window() {
    use n0_future::StreamExt as _;

    let lan: SocketAddr = "192.168.0.7:44444".parse().unwrap();
    let fake = Arc::new(Fake::default());
    *fake.answer.lock().unwrap() = Some((vec![lan], Vec::new()));
    let (tx, _keep) = tokio::sync::broadcast::channel(4);
    *fake.changes.lock().unwrap() = Some(tx);
    let lookup = DirectoryLookup::new(fake, PeerId::from_bytes([1u8; 32]))
        .with_live_window(std::time::Duration::from_millis(50));

    let mut stream = lookup.resolve(endpoint_id(9)).expect("known");
    assert!(stream.next().await.is_some(), "what is known now");
    let ended = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next()).await;
    assert!(matches!(ended, Ok(None)), "the stream must end by itself: {ended:?}");
}

/// A peer whose record already names a relay needs no waiting: the lookup is the old one-shot.
#[tokio::test]
async fn a_peer_with_a_relay_recorded_gets_a_lookup_that_ends_at_once() {
    use n0_future::StreamExt as _;

    let fake = Arc::new(Fake::default());
    *fake.answer.lock().unwrap() = Some((Vec::new(), vec!["https://relay.example./".to_string()]));
    let (tx, _keep) = tokio::sync::broadcast::channel(4);
    *fake.changes.lock().unwrap() = Some(tx);
    let lookup =
        DirectoryLookup::new(fake, PeerId::from_bytes([1u8; 32])).waiting_for_records(true);

    let mut stream = lookup.resolve(endpoint_id(9)).expect("known");
    assert!(stream.next().await.is_some());
    assert!(stream.next().await.is_none());
}

#[test]
fn only_a_parseable_relay_url_is_usable() {
    assert!(is_usable_relay_url("https://relay.example./"));
    assert!(!is_usable_relay_url("not a url"));
}

/// With LAN discovery keeping the dial waiting anyway, a peer nobody has recorded yet gets a
/// stream that yields once something is recorded; without it, the answer is still "nothing".
#[tokio::test]
async fn an_unknown_peer_waits_for_its_record_only_when_asked_to() {
    use n0_future::StreamExt as _;

    let fake = Arc::new(Fake::default());
    let (tx, _keep) = tokio::sync::broadcast::channel(4);
    *fake.changes.lock().unwrap() = Some(tx.clone());

    let not_waiting = DirectoryLookup::new(fake.clone(), PeerId::from_bytes([1u8; 32]));
    assert!(not_waiting.resolve(endpoint_id(4)).is_none());

    let waiting =
        DirectoryLookup::new(fake.clone(), PeerId::from_bytes([1u8; 32])).waiting_for_records(true);
    let mut stream = waiting.resolve(endpoint_id(4)).expect("a stream that waits");
    *fake.answer.lock().unwrap() = Some((Vec::new(), vec!["https://relay.example./".to_string()]));
    tx.send(()).unwrap();
    let item = stream.next().await.expect("item").expect("ok");
    assert_eq!(item.endpoint_info().relay_urls().count(), 1);
}
