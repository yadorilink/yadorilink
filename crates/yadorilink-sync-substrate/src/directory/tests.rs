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
}

impl AddressDirectory for Fake {
    fn publish(&self, peer: PeerId, direct: Vec<SocketAddr>, relays: Vec<String>) {
        self.published.lock().unwrap().push((peer, direct, relays));
    }
    fn resolve(&self, _peer: PeerId) -> Option<(Vec<SocketAddr>, Vec<String>)> {
        self.answer.lock().unwrap().clone()
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
