//! NAS management's ALPN on real endpoints and real handshakes.
//!
//! What is pinned: only a device the authorizer names can open a stream;
//! being a sync (folder-sharing) peer is not enough; a device that does not
//! answer the ALPN reads as "needs a newer version"; an absent service fails
//! closed with nothing offered in its place; withdrawing authority refuses
//! the next stream and the next connection; the stream carries HTTP and
//! WebSocket bytes untouched, directly and over a relay.

#![cfg(feature = "test-support")]

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use yadorilink_sync_substrate::testing::{InProcessRelay, SharedAddressBook};
use yadorilink_sync_substrate::{
    AdmitNone, AdmitWhen, NasAdminAuthorizer, NasAdminEndpoint, NasAdminError, NasAdminLimits,
    NasAdminService, NasAdminStream, NetworkConfig, PeerAddress, PeerAdmission, PeerId, PeerLink,
    SubstrateNode,
};

const STEP: Duration = Duration::from_secs(15);

fn key(seed: u8) -> iroh::SecretKey {
    iroh::SecretKey::from_bytes(&[seed; 32])
}

fn peer_of(secret: &iroh::SecretKey) -> PeerId {
    PeerId::from_bytes(*secret.public().as_bytes())
}

/// Stands in for "the devices on this device's own account", and records
/// every identity it was asked about.
#[derive(Debug, Default)]
struct Account {
    devices: Mutex<HashSet<PeerId>>,
    asked: Mutex<Vec<PeerId>>,
}

impl Account {
    fn with(devices: impl IntoIterator<Item = PeerId>) -> Arc<Self> {
        Arc::new(Self { devices: Mutex::new(devices.into_iter().collect()), ..Self::default() })
    }

    fn remove(&self, peer: &PeerId) {
        self.devices.lock().unwrap().remove(peer);
    }
}

impl NasAdminAuthorizer for Account {
    fn authorize(
        &self,
        peer: PeerId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        self.asked.lock().unwrap().push(peer);
        let allowed = self.devices.lock().unwrap().contains(&peer);
        Box::pin(async move { allowed })
    }
}

/// The management service, as a byte copy to a local test server. `None`
/// is a device whose service is not running.
struct Service {
    target: Option<SocketAddr>,
    delivered: AtomicUsize,
}

impl Service {
    fn at(target: Option<SocketAddr>) -> Arc<Self> {
        Arc::new(Self { target, delivered: AtomicUsize::new(0) })
    }
}

impl NasAdminEndpoint for Service {
    fn available(&self) -> bool {
        self.target.is_some()
    }

    fn deliver(&self, mut stream: NasAdminStream) {
        self.delivered.fetch_add(1, Ordering::SeqCst);
        let Some(target) = self.target else { return };
        tokio::spawn(async move {
            let Ok(mut tcp) = tokio::net::TcpStream::connect(target).await else { return };
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
        });
    }
}

struct Nas {
    node: SubstrateNode,
    _sync_inbound: mpsc::Receiver<PeerLink>,
}

async fn spawn_nas(
    secret: iroh::SecretKey,
    config: NetworkConfig,
    sync: Arc<dyn PeerAdmission>,
    account: Arc<Account>,
    service: Arc<Service>,
    limits: NasAdminLimits,
) -> Nas {
    let (tx, mut rx) = mpsc::channel(8);
    let (node, sync_inbound) =
        SubstrateNode::spawn(secret, config.with_nas_admin(account.clone(), tx), sync)
            .await
            .expect("substrate starts");
    let served = NasAdminService::new(account, service, limits);
    tokio::spawn(async move {
        while let Some(connection) = rx.recv().await {
            tokio::spawn(served.clone().serve(connection));
        }
    });
    Nas { node, _sync_inbound: sync_inbound }
}

/// Short re-authorization so a withdrawn device is noticed within a test.
fn limits() -> NasAdminLimits {
    NasAdminLimits { total: 8, per_device: 8, recheck: Duration::from_millis(300) }
}

async fn spawn_plain(secret: iroh::SecretKey, config: NetworkConfig) -> SubstrateNode {
    SubstrateNode::spawn(secret, config, Arc::new(AdmitNone)).await.expect("substrate starts").0
}

/// A minimal HTTP/1.1 server answering every request on a connection with a
/// body naming the request line, and keeping the connection alive.
async fn http_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(serve_http(tcp));
        }
    });
    addr
}

async fn serve_http(mut tcp: tokio::net::TcpStream) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        while let Some(end) = find(&buf, b"\r\n\r\n") {
            let request: Vec<u8> = buf.drain(..end + 4).collect();
            let text = String::from_utf8_lossy(&request);
            let body = format!("served {}", text.lines().next().unwrap_or(""));
            let response =
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len());
            if tcp.write_all(response.as_bytes()).await.is_err() {
                return;
            }
        }
        match tcp.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

/// A WebSocket server echoing every message.
async fn websocket_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else { return };
                while let Some(Ok(message)) = ws.next().await {
                    if message.is_close() || ws.send(message).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Sends `requests` on one stream, keep-alive, and returns everything read
/// back once every response has arrived.
async fn http_exchange(stream: &mut NasAdminStream, requests: &[&str]) -> String {
    let mut sent = String::new();
    for path in requests {
        sent.push_str(&format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n"));
    }
    stream.write_all(sent.as_bytes()).await.unwrap();
    let mut received = Vec::new();
    let mut chunk = [0u8; 1024];
    while requests
        .iter()
        .any(|path| find(&received, format!("served GET {path}").as_bytes()).is_none())
    {
        let n = tokio::time::timeout(STEP, stream.read(&mut chunk))
            .await
            .expect("response in time")
            .expect("read");
        assert!(n > 0, "stream ended before every response arrived");
        received.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8(received).unwrap()
}

async fn dial(
    from: &SubstrateNode,
    to: &SubstrateNode,
) -> Result<yadorilink_sync_substrate::NasAdminConnection, NasAdminError> {
    tokio::time::timeout(STEP, from.connect_nas_admin(&to.local_address()))
        .await
        .expect("dial settles in time")
}

async fn open(
    connection: &yadorilink_sync_substrate::NasAdminConnection,
) -> Result<NasAdminStream, NasAdminError> {
    tokio::time::timeout(STEP, connection.open_stream()).await.expect("open settles in time")
}

fn direct(book: &SharedAddressBook) -> NetworkConfig {
    NetworkConfig::direct_only().with_directory(Arc::new(book.clone()))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_on_the_same_account_gets_http_bytes_through_untouched() {
    let book = SharedAddressBook::new();
    let (nas_key, mac_key) = (key(101), key(102));
    let mac_id = peer_of(&mac_key);
    let account = Account::with([mac_id]);
    let service = Service::at(Some(http_server().await));
    let nas =
        spawn_nas(nas_key, direct(&book), Arc::new(AdmitNone), account.clone(), service, limits())
            .await;
    let mac = spawn_plain(mac_key, direct(&book)).await;

    let connection = dial(&mac, &nas.node).await.expect("a same-account device connects");
    let mut stream = open(&connection).await.expect("the service is ready");
    let received = http_exchange(&mut stream, &["/", "/api/status"]).await;
    assert!(received.starts_with("HTTP/1.1 200 OK\r\n"), "{received}");
    // A second stream on the same connection, as a browser's second TCP
    // connection would be.
    let mut second = open(&connection).await.expect("a second stream");
    http_exchange(&mut second, &["/api/links"]).await;

    let asked = account.asked.lock().unwrap().clone();
    assert!(
        !asked.is_empty() && asked.iter().all(|peer| *peer == mac_id),
        "the authorizer is asked about the identity the handshake proved, and only that"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_websocket_upgrade_and_its_frames_pass_both_ways() {
    let book = SharedAddressBook::new();
    let (nas_key, mac_key) = (key(103), key(104));
    let account = Account::with([peer_of(&mac_key)]);
    let service = Service::at(Some(websocket_server().await));
    let nas =
        spawn_nas(nas_key, direct(&book), Arc::new(AdmitNone), account, service, limits()).await;
    let mac = spawn_plain(mac_key, direct(&book)).await;

    let connection = dial(&mac, &nas.node).await.expect("connects");
    let stream = open(&connection).await.expect("ready");
    let (mut ws, _) = tokio_tungstenite::client_async("ws://127.0.0.1:1/events", stream)
        .await
        .expect("the upgrade handshake passes through");
    ws.send(Message::text("hello")).await.unwrap();
    assert_eq!(ws.next().await.unwrap().unwrap(), Message::text("hello"));
    ws.send(Message::binary(vec![0u8, 1, 2, 255])).await.unwrap();
    assert_eq!(ws.next().await.unwrap().unwrap(), Message::binary(vec![0u8, 1, 2, 255]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_stream_works_when_the_only_path_is_a_relay() {
    let relay = InProcessRelay::start().await.expect("in-process relay starts");
    let book = SharedAddressBook::new();
    let (nas_key, mac_key) = (key(105), key(106));
    let account = Account::with([peer_of(&mac_key)]);
    let service = Service::at(Some(http_server().await));
    let nas = spawn_nas(
        nas_key,
        relay.direct_or_relay().with_directory(Arc::new(book.clone())),
        Arc::new(AdmitNone),
        account,
        service,
        limits(),
    )
    .await;
    let mac = spawn_plain(mac_key, relay.relay_only().with_directory(Arc::new(book.clone()))).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let address = loop {
        let address = nas.node.local_address();
        if address.relay_urls().next().is_some() {
            break PeerAddress::new(address.peer())
                .with_relays(address.relay_urls().map(str::to_string));
        }
        assert!(tokio::time::Instant::now() < deadline, "never registered with the relay");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let connection = tokio::time::timeout(STEP, mac.connect_nas_admin(&address))
        .await
        .expect("dial in time")
        .expect("connects through the relay");
    let mut stream = open(&connection).await.expect("ready");
    http_exchange(&mut stream, &["/over-relay"]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_folder_sharing_peer_on_another_account_is_refused() {
    let book = SharedAddressBook::new();
    let (nas_key, peer_key) = (key(107), key(108));
    let peer_id = peer_of(&peer_key);
    // A sync peer of the NAS (it shares a folder), but not on its account.
    let sync_admission = AdmitWhen::new(move |candidate: &PeerId| *candidate == peer_id);
    let service = Service::at(Some(http_server().await));
    let nas = spawn_nas(
        nas_key,
        direct(&book),
        sync_admission,
        Account::with([]),
        service.clone(),
        limits(),
    )
    .await;
    let peer = spawn_plain(peer_key, direct(&book)).await;

    // The folder relationship is real: sync connects.
    tokio::time::timeout(STEP, peer.connect(nas.node.peer_id()))
        .await
        .expect("sync dial in time")
        .expect("a folder peer may sync");

    let refused = match dial(&peer, &nas.node).await {
        Ok(connection) => open(&connection).await.map(|_| ()),
        Err(err) => Err(err),
    };
    assert_eq!(refused, Err(NasAdminError::Unauthorized));
    assert_eq!(service.delivered.load(Ordering::SeqCst), 0, "nothing reached the service");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_the_account_does_not_list_is_refused() {
    let book = SharedAddressBook::new();
    let (nas_key, stranger_key) = (key(109), key(110));
    let service = Service::at(Some(http_server().await));
    let nas = spawn_nas(
        nas_key,
        direct(&book),
        Arc::new(AdmitNone),
        Account::with([peer_of(&key(111))]),
        service.clone(),
        limits(),
    )
    .await;
    let stranger = spawn_plain(stranger_key, direct(&book)).await;

    let refused = match dial(&stranger, &nas.node).await {
        Ok(connection) => open(&connection).await.map(|_| ()),
        Err(err) => Err(err),
    };
    assert_eq!(refused, Err(NasAdminError::Unauthorized));
    assert_eq!(service.delivered.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_that_does_not_answer_the_protocol_reads_as_needing_a_newer_version() {
    let book = SharedAddressBook::new();
    let (old_key, mac_key) = (key(112), key(113));
    // An older build: the node exists and answers sync, but not this ALPN.
    let old = spawn_plain(old_key, direct(&book)).await;
    let mac = spawn_plain(mac_key, direct(&book)).await;

    assert_eq!(dial(&mac, &old).await.err(), Some(NasAdminError::Unsupported));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_absent_service_fails_closed_and_nothing_is_offered_in_its_place() {
    let book = SharedAddressBook::new();
    let (nas_key, mac_key) = (key(114), key(115));
    let account = Account::with([peer_of(&mac_key)]);
    let service = Service::at(None);
    let nas =
        spawn_nas(nas_key, direct(&book), Arc::new(AdmitNone), account, service.clone(), limits())
            .await;
    let mac = spawn_plain(mac_key, direct(&book)).await;

    let connection = dial(&mac, &nas.node).await.expect("an authorized device connects");
    assert_eq!(open(&connection).await.err(), Some(NasAdminError::Unavailable));
    assert_eq!(service.delivered.load(Ordering::SeqCst), 0, "nothing was handed anywhere");
    // Asking again does not find something else answering instead.
    assert_eq!(open(&connection).await.err(), Some(NasAdminError::Unavailable));
}

#[tokio::test(flavor = "multi_thread")]
async fn withdrawing_authority_refuses_the_next_stream_and_the_next_connection() {
    let book = SharedAddressBook::new();
    let (nas_key, mac_key) = (key(116), key(117));
    let mac_id = peer_of(&mac_key);
    let account = Account::with([mac_id]);
    let service = Service::at(Some(http_server().await));
    let nas =
        spawn_nas(nas_key, direct(&book), Arc::new(AdmitNone), account.clone(), service, limits())
            .await;
    let mac = spawn_plain(mac_key, direct(&book)).await;

    let connection = dial(&mac, &nas.node).await.expect("connects");
    let mut stream = open(&connection).await.expect("ready while authorized");
    http_exchange(&mut stream, &["/before"]).await;

    account.remove(&mac_id);
    assert_eq!(open(&connection).await.err(), Some(NasAdminError::Unauthorized));
    let again = match dial(&mac, &nas.node).await {
        Ok(connection) => open(&connection).await.map(|_| ()),
        Err(err) => Err(err),
    };
    assert_eq!(again, Err(NasAdminError::Unauthorized));
}

#[tokio::test(flavor = "multi_thread")]
async fn shutting_the_device_down_ends_its_streams_and_new_dials_fail() {
    let book = SharedAddressBook::new();
    let (nas_key, mac_key) = (key(118), key(119));
    let account = Account::with([peer_of(&mac_key)]);
    let service = Service::at(Some(http_server().await));
    let nas =
        spawn_nas(nas_key, direct(&book), Arc::new(AdmitNone), account, service, limits()).await;
    let mac = spawn_plain(mac_key, direct(&book)).await;
    let address = nas.node.local_address();

    let connection = dial(&mac, &nas.node).await.expect("connects");
    let mut stream = open(&connection).await.expect("ready");
    nas.node.shutdown().await;

    let mut buf = [0u8; 16];
    let ended = tokio::time::timeout(STEP, stream.read(&mut buf)).await.expect("ends in time");
    assert!(matches!(ended, Ok(0) | Err(_)), "the stream ends with the device");
    assert!(open(&connection).await.is_err(), "no new stream on a closed connection");
    let redial = tokio::time::timeout(STEP, mac.connect_nas_admin(&address)).await;
    assert!(!matches!(redial, Ok(Ok(_))), "a stopped device cannot be dialled");
}

#[tokio::test(flavor = "multi_thread")]
async fn streams_beyond_the_bound_are_answered_busy() {
    let book = SharedAddressBook::new();
    let (nas_key, mac_key) = (key(120), key(121));
    let account = Account::with([peer_of(&mac_key)]);
    let service = Service::at(Some(http_server().await));
    let nas = spawn_nas(
        nas_key,
        direct(&book),
        Arc::new(AdmitNone),
        account,
        service,
        NasAdminLimits { total: 1, ..limits() },
    )
    .await;
    let mac = spawn_plain(mac_key, direct(&book)).await;

    let connection = dial(&mac, &nas.node).await.expect("connects");
    let held = open(&connection).await.expect("the one slot");
    assert_eq!(open(&connection).await.err(), Some(NasAdminError::Busy));
    drop(held);
    // The slot is released with the stream; give the drop a moment to land.
    let deadline = tokio::time::Instant::now() + STEP;
    loop {
        match open(&connection).await {
            Ok(_) => break,
            Err(NasAdminError::Busy) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(err) => panic!("expected the slot back, got {err:?}"),
        }
    }
}

/// A device removed from the account that never opens another stream still
/// loses the one it holds: the connection is re-authorized on its own.
#[tokio::test(flavor = "multi_thread")]
async fn withdrawing_authority_ends_a_held_stream_without_any_new_stream() {
    let book = SharedAddressBook::new();
    let (nas_key, mac_key) = (key(122), key(123));
    let mac_id = peer_of(&mac_key);
    let account = Account::with([mac_id]);
    let service = Service::at(Some(http_server().await));
    let nas =
        spawn_nas(nas_key, direct(&book), Arc::new(AdmitNone), account.clone(), service, limits())
            .await;
    let mac = spawn_plain(mac_key, direct(&book)).await;

    let connection = dial(&mac, &nas.node).await.expect("connects");
    let mut stream = open(&connection).await.expect("ready");
    http_exchange(&mut stream, &["/held"]).await;

    account.remove(&mac_id);
    let mut buf = [0u8; 16];
    let ended = tokio::time::timeout(STEP, stream.read(&mut buf))
        .await
        .expect("the held stream ends within the re-authorization period");
    assert!(matches!(ended, Ok(0) | Err(_)), "the held stream ends");
}

/// One device cannot take every slot: another device on the account still
/// gets one.
#[tokio::test(flavor = "multi_thread")]
async fn one_device_cannot_take_every_slot() {
    let book = SharedAddressBook::new();
    let (nas_key, mac_key, other_key) = (key(124), key(125), key(126));
    let account = Account::with([peer_of(&mac_key), peer_of(&other_key)]);
    let service = Service::at(Some(http_server().await));
    let nas = spawn_nas(
        nas_key,
        direct(&book),
        Arc::new(AdmitNone),
        account,
        service,
        NasAdminLimits { total: 4, per_device: 2, ..limits() },
    )
    .await;
    let mac = spawn_plain(mac_key, direct(&book)).await;
    let other = spawn_plain(other_key, direct(&book)).await;

    let connection = dial(&mac, &nas.node).await.expect("connects");
    let _first = open(&connection).await.expect("first slot");
    let _second = open(&connection).await.expect("second slot");
    assert_eq!(open(&connection).await.err(), Some(NasAdminError::Busy));
    let second_connection = dial(&mac, &nas.node).await.expect("connects again");
    assert_eq!(
        open(&second_connection).await.err(),
        Some(NasAdminError::Busy),
        "the cap is per device, not per connection"
    );

    let other_connection = dial(&other, &nas.node).await.expect("connects");
    open(&other_connection).await.expect("another device still gets a slot");
}
