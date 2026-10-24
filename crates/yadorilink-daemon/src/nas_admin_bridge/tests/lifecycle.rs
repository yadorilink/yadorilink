//! Failure and lifecycle scenarios of managing another device, end to end on
//! two real endpoints: the Mac side is the bridge session, the NAS side is
//! the management service with the daemon's own account authorizer, and a
//! browser is played by plain TCP and WebSocket clients on the session's
//! local address.
//!
//! After every scenario the same three things are checked: nothing accepts
//! on the session's old port, the NAS's backend has no connection left, and
//! the NAS's stream slots are all free again.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use yadorilink_sync_substrate::testing::{InProcessRelay, SharedAddressBook};
use yadorilink_sync_substrate::PeerAddress;

use super::*;
use crate::nas_admin::{AccountDevices, Dashboard};

const SLOTS: usize = 6;

/// What the NAS's management page is in these tests: counts live
/// connections, answers HTTP with the requested path (keep-alive aware) and
/// echoes a WebSocket.
struct Backend {
    addr: SocketAddr,
    live: Arc<AtomicUsize>,
}

struct Live(Arc<AtomicUsize>);

impl Live {
    fn new(count: &Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::SeqCst);
        Self(count.clone())
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn backend() -> Backend {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let live = Arc::new(AtomicUsize::new(0));
    let count = live.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let guard = Live::new(&count);
            tokio::spawn(async move {
                route(tcp).await;
                drop(guard);
            });
        }
    });
    Backend { addr, live }
}

async fn route(tcp: TcpStream) {
    let mut seen = [0u8; 2048];
    for _ in 0..500 {
        match tcp.peek(&mut seen).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                let head = String::from_utf8_lossy(&seen[..n]).to_ascii_lowercase();
                if head.contains("\r\n\r\n") {
                    if head.contains("upgrade: websocket") {
                        echo_websocket(tcp).await;
                    } else {
                        http_loop(tcp).await;
                    }
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
}

async fn http_loop(mut tcp: TcpStream) {
    let mut pending = Vec::new();
    loop {
        let end = loop {
            if let Some(at) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
            let mut chunk = [0u8; 1024];
            match tcp.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => pending.extend_from_slice(&chunk[..n]),
            }
        };
        let head = String::from_utf8_lossy(&pending[..end]).into_owned();
        pending.drain(..end);
        let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
        let body = format!("page:{path}");
        let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        if tcp.write_all(response.as_bytes()).await.is_err() {
            return;
        }
        if head.to_ascii_lowercase().contains("connection: close") {
            return;
        }
    }
}

/// One keep-alive request on an open browser connection; returns the body.
async fn get(tcp: &mut TcpStream, path: &str) -> String {
    let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    tcp.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    loop {
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..at]).to_ascii_lowercase();
            let length: usize = head
                .split("content-length: ")
                .nth(1)
                .and_then(|rest| rest.split("\r\n").next())
                .and_then(|n| n.trim().parse().ok())
                .expect("content-length");
            if buf.len() >= at + 4 + length {
                return String::from_utf8_lossy(&buf[at + 4..at + 4 + length]).into_owned();
            }
        }
        let mut chunk = [0u8; 1024];
        let n = tokio::time::timeout(STEP, tcp.read(&mut chunk))
            .await
            .expect("answer in time")
            .expect("read");
        assert_ne!(n, 0, "the connection ended before the answer: {buf:?}");
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// A new browser connection that gets its page: while slots released by
/// connections that just closed are still being returned, the NAS answers
/// busy and ends the connection without a page, so retry on a fresh one.
async fn connect_served(addr: SocketAddr, path: &str) -> TcpStream {
    let deadline = tokio::time::Instant::now() + STEP;
    loop {
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        if tcp.write_all(request.as_bytes()).await.is_ok() {
            let want = format!("page:{path}");
            let mut seen = Vec::new();
            let mut chunk = [0u8; 1024];
            let _ = tokio::time::timeout(Duration::from_millis(500), async {
                while !String::from_utf8_lossy(&seen).contains(&want) {
                    match tcp.read(&mut chunk).await {
                        Ok(n) if n > 0 => seen.extend_from_slice(&chunk[..n]),
                        _ => break,
                    }
                }
            })
            .await;
            if String::from_utf8_lossy(&seen).contains(&want) {
                return tcp;
            }
        }
        assert!(tokio::time::Instant::now() < deadline, "no slot ever served {path}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

type Socket = tokio_tungstenite::WebSocketStream<TcpStream>;

async fn websocket(addr: SocketAddr) -> Socket {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let (socket, _) =
        tokio_tungstenite::client_async(format!("ws://{addr}/socket"), tcp).await.unwrap();
    socket
}

async fn echo(socket: &mut Socket, text: &str) {
    socket.send(Message::text(text)).await.unwrap();
    let reply = tokio::time::timeout(STEP, socket.next()).await.expect("echo in time");
    assert_eq!(reply.unwrap().unwrap(), Message::text(text));
}

/// Waits for a WebSocket to end however it ends: close frame, error or EOF.
async fn socket_ends(socket: &mut Socket, within: Duration) {
    let end = tokio::time::timeout(within, async {
        loop {
            match socket.next().await {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return,
                Some(Ok(_)) => {}
            }
        }
    })
    .await;
    assert!(end.is_ok(), "the WebSocket did not end within {within:?}");
}

async fn tcp_ends(tcp: &mut TcpStream, within: Duration) {
    let end = tokio::time::timeout(within, async {
        let mut sink = [0u8; 512];
        while matches!(tcp.read(&mut sink).await, Ok(n) if n > 0) {}
    })
    .await;
    assert!(end.is_ok(), "the browser connection did not end within {within:?}");
}

/// The NAS side of a scenario: who the account lists, where the management
/// service goes, and its bounds. Cloneable so a restart reuses it.
#[derive(Clone)]
struct NasSide {
    listing: Arc<Mutex<HashSet<[u8; 32]>>>,
    endpoint: Arc<dyn NasAdminEndpoint>,
    periods: Option<(Duration, Duration)>,
    limits: NasAdminLimits,
}

impl NasSide {
    fn new(mac: &SubstrateNode, endpoint: Arc<dyn NasAdminEndpoint>) -> Self {
        Self {
            listing: Arc::new(Mutex::new(HashSet::from([*mac.peer_id().as_bytes()]))),
            endpoint,
            periods: Some((Duration::from_millis(300), Duration::from_millis(300))),
            limits: NasAdminLimits {
                total: SLOTS,
                per_device: SLOTS,
                recheck: Duration::from_millis(300),
            },
        }
    }

    fn forwarding(mac: &SubstrateNode, backend: &Backend) -> Self {
        Self::new(mac, Arc::new(Forward(Some(backend.addr))))
    }

    fn withdraw(&self, mac: &SubstrateNode) {
        self.listing.lock().unwrap().remove(mac.peer_id().as_bytes());
    }

    fn list(&self, mac: &SubstrateNode) {
        self.listing.lock().unwrap().insert(*mac.peer_id().as_bytes());
    }

    /// Starts (or restarts, with the same `seed`) the NAS endpoint.
    async fn spawn(&self, seed: [u8; 32], config: NetworkConfig) -> SubstrateNode {
        let listing = self.listing.clone();
        let mut devices = AccountDevices::new(Box::new(move || {
            let listing = listing.clone();
            Box::pin(async move { Ok(listing.lock().unwrap().clone()) })
        }));
        if let Some((fresh_for, retry_after)) = self.periods {
            devices = devices.with_periods(fresh_for, retry_after);
        }
        let authorizer: Arc<dyn NasAdminAuthorizer> = Arc::new(devices);
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let (node, _) = SubstrateNode::spawn_as_device(
            seed,
            config.with_nas_admin(authorizer.clone(), tx),
            Arc::new(AdmitNone),
        )
        .await
        .expect("substrate starts");
        let service = NasAdminService::new(authorizer, self.endpoint.clone(), self.limits);
        tokio::spawn(async move {
            while let Some(connection) = rx.recv().await {
                tokio::spawn(service.clone().serve(connection));
            }
        });
        node
    }
}

/// Every stream slot of the NAS answers again: `SLOTS` streams open at once
/// from a fresh connection, retrying while released slots are still being
/// returned.
async fn slots_are_free(mac: &SubstrateNode, nas: &SubstrateNode) {
    let deadline = tokio::time::Instant::now() + STEP;
    loop {
        let connection = mac.connect_nas_admin(&nas.local_address()).await.expect("dials");
        let mut held = Vec::new();
        let mut all = true;
        for _ in 0..SLOTS {
            match connection.open_stream().await {
                Ok(stream) => held.push(stream),
                Err(NasAdminError::Busy) => {
                    all = false;
                    break;
                }
                Err(other) => panic!("expected a free slot, got {other:?}"),
            }
        }
        drop(held);
        connection.close();
        if all {
            return;
        }
        assert!(tokio::time::Instant::now() < deadline, "management slots leaked");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The three checks after a scenario.
async fn nothing_is_left(
    old: SocketAddr,
    backend: &Backend,
    mac: &SubstrateNode,
    nas: &SubstrateNode,
) {
    assert!(!accepts(old).await, "a listener is still open on the old port {old}");
    let deadline = tokio::time::Instant::now() + STEP;
    while backend.live.load(Ordering::SeqCst) != 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the NAS still holds {} backend connections",
            backend.live.load(Ordering::SeqCst)
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    slots_are_free(mac, nas).await;
}

/// A session being served until told to stop.
struct Served {
    addr: SocketAddr,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl Served {
    fn start(session: BridgeSession) -> Self {
        let addr = session.local_addr();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(session.serve(async {
            let _ = stopped.await;
        }));
        Self { addr, stop, task }
    }

    async fn close(self) {
        let _ = self.stop.send(());
        ended(self.task).await;
    }
}

async fn open_to(mac: &SubstrateNode, nas: &SubstrateNode) -> Result<BridgeSession, OpenFailure> {
    open(mac, nas, quick()).await
}

/// The NAS daemon restarts while a page, a keep-alive connection and a
/// WebSocket are open. The session ends cleanly, nothing keeps listening,
/// and once the NAS is back (same identity, same account listing, no
/// reconfiguration) pressing Manage again works.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_nas_daemon_restart_ends_the_session_and_manage_works_again() {
    let backend = backend().await;
    let mac = mac().await;
    let side = NasSide::forwarding(&mac, &backend);
    let seed = fresh_seed();
    let nas = side.spawn(seed, NetworkConfig::direct_only()).await;

    let session = open_to(&mac, &nas).await.expect("available");
    let first = Served::start(session);
    let mut page = TcpStream::connect(first.addr).await.unwrap();
    assert_eq!(get(&mut page, "/before").await, "page:/before");
    let mut socket = websocket(first.addr).await;
    echo(&mut socket, "before").await;

    nas.shutdown().await;
    ended(first.task).await;
    assert!(!accepts(first.addr).await, "the old port must not accept after the NAS went down");
    socket_ends(&mut socket, STEP).await;
    tcp_ends(&mut page, STEP).await;
    assert_eq!(open_to(&mac, &nas).await.err(), Some(OpenFailure::Offline));

    // The NAS comes back. Nothing was reconfigured on either side.
    let nas = side.spawn(seed, NetworkConfig::direct_only()).await;
    let session = open_to(&mac, &nas).await.expect("manage works after the restart");
    let second = Served::start(session);
    let mut page = TcpStream::connect(second.addr).await.unwrap();
    assert_eq!(get(&mut page, "/after").await, "page:/after");
    let mut socket = websocket(second.addr).await;
    echo(&mut socket, "after").await;
    drop((page, socket));
    let (old, again) = (first.addr, second.addr);
    second.close().await;
    nothing_is_left(again, &backend, &mac, &nas).await;
    assert!(!accepts(old).await);
}

/// The same restart when the only path is the relay: the Mac reconnects
/// through it to the restarted NAS.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_only_session_reconnects_after_the_nas_restarts() {
    let relay = InProcessRelay::start().await.expect("in-process relay starts");
    let book = SharedAddressBook::new();
    let backend = backend().await;
    let mac = SubstrateNode::spawn_as_device(
        fresh_seed(),
        relay.relay_only().with_directory(Arc::new(book.clone())),
        Arc::new(AdmitNone),
    )
    .await
    .expect("substrate starts")
    .0;
    let side = NasSide::forwarding(&mac, &backend);
    let seed = fresh_seed();
    let config = || relay.direct_or_relay().with_directory(Arc::new(book.clone()));

    async fn via_relay(nas: &SubstrateNode) -> PeerAddress {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let address = nas.local_address();
            if address.relay_urls().next().is_some() {
                return PeerAddress::new(address.peer())
                    .with_relays(address.relay_urls().map(str::to_string));
            }
            assert!(tokio::time::Instant::now() < deadline, "never registered with the relay");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    let nas = side.spawn(seed, config()).await;
    let address = via_relay(&nas).await;
    let session = BridgeSession::open(mac.connect_nas_admin(&address), quick())
        .await
        .expect("available over the relay");
    let first = Served::start(session);
    let mut page = TcpStream::connect(first.addr).await.unwrap();
    assert_eq!(get(&mut page, "/relay").await, "page:/relay");
    let mut socket = websocket(first.addr).await;
    echo(&mut socket, "relay").await;

    nas.shutdown().await;
    ended(first.task).await;
    socket_ends(&mut socket, STEP).await;
    assert!(!accepts(first.addr).await);

    let nas = side.spawn(seed, config()).await;
    let address = via_relay(&nas).await;
    let session = BridgeSession::open(mac.connect_nas_admin(&address), quick())
        .await
        .expect("reconnects over the relay");
    let second = Served::start(session);
    let mut page = TcpStream::connect(second.addr).await.unwrap();
    assert_eq!(get(&mut page, "/relay-again").await, "page:/relay-again");
    drop(page);
    let again = second.addr;
    second.close().await;
    assert!(!accepts(first.addr).await);
    assert!(!accepts(again).await);
    let deadline = tokio::time::Instant::now() + STEP;
    while backend.live.load(Ordering::SeqCst) != 0 {
        assert!(tokio::time::Instant::now() < deadline, "backend connections leaked");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A session opened on the relay while a direct path is still being found:
/// the path moves under the open connection, and a keep-alive page and a
/// WebSocket keep answering across it without a redial.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_session_keeps_answering_while_the_path_moves_from_relay_to_direct() {
    let relay = InProcessRelay::start().await.expect("in-process relay starts");
    let book = SharedAddressBook::new();
    let backend = backend().await;
    let config = || relay.direct_or_relay().with_directory(Arc::new(book.clone()));
    let mac = SubstrateNode::spawn_as_device(fresh_seed(), config(), Arc::new(AdmitNone))
        .await
        .expect("substrate starts")
        .0;
    let side = NasSide::forwarding(&mac, &backend);
    let nas = side.spawn(fresh_seed(), config()).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let address = loop {
        let address = nas.local_address();
        if address.relay_urls().next().is_some() {
            // Only the relay is known: the first packets cannot go direct.
            break PeerAddress::new(address.peer())
                .with_relays(address.relay_urls().map(str::to_string));
        }
        assert!(tokio::time::Instant::now() < deadline, "never registered with the relay");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let session =
        BridgeSession::open(mac.connect_nas_admin(&address), quick()).await.expect("available");
    let served = Served::start(session);
    let mut page = TcpStream::connect(served.addr).await.unwrap();
    let mut socket = websocket(served.addr).await;
    let until = tokio::time::Instant::now() + Duration::from_secs(6);
    let mut round = 0;
    while tokio::time::Instant::now() < until {
        assert_eq!(get(&mut page, &format!("/r{round}")).await, format!("page:/r{round}"));
        echo(&mut socket, &format!("m{round}")).await;
        round += 1;
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(!served.task.is_finished(), "the session survived the path change");
    drop((page, socket));
    let addr = served.addr;
    served.close().await;
    nothing_is_left(addr, &backend, &mac, &nas).await;
}

/// A device removed from the account while its browser keeps a WebSocket
/// (and a kept-alive page) open and sends nothing new: the NAS closes the
/// device connection after the listing refreshes, the session ends, nothing
/// listens, and the next Manage is refused. Short periods stand in for the
/// real 30 s ones.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn losing_authorization_closes_an_idle_websocket_and_the_session() {
    let backend = backend().await;
    let mac = mac().await;
    let side = NasSide::forwarding(&mac, &backend);
    let nas = side.spawn(fresh_seed(), NetworkConfig::direct_only()).await;

    let session = open_to(&mac, &nas).await.expect("available");
    let served = Served::start(session);
    let mut page = TcpStream::connect(served.addr).await.unwrap();
    assert_eq!(get(&mut page, "/held").await, "page:/held");
    let mut socket = websocket(served.addr).await;
    echo(&mut socket, "while authorized").await;

    side.withdraw(&mac);
    let removed = tokio::time::Instant::now();
    socket_ends(&mut socket, Duration::from_secs(5)).await;
    tcp_ends(&mut page, Duration::from_secs(5)).await;
    ended(served.task).await;
    assert!(removed.elapsed() < Duration::from_secs(5));
    assert!(!accepts(served.addr).await);
    assert_eq!(open_to(&mac, &nas).await.err(), Some(OpenFailure::CouldNotOpen));

    // Restored on the account, Manage works again without anything else.
    side.list(&mac);
    let deadline = tokio::time::Instant::now() + STEP;
    let session = loop {
        match open_to(&mac, &nas).await {
            Ok(session) => break session,
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(failure) => panic!("not restored: {failure:?}"),
        }
    };
    let served_again = Served::start(session);
    let addr = served_again.addr;
    served_again.close().await;
    nothing_is_left(addr, &backend, &mac, &nas).await;
}

/// The same with the daemon's real periods (30 s listing, 30 s recheck): an
/// open WebSocket ends within 70 s of the device leaving the account.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn losing_authorization_closes_the_websocket_within_the_production_bound() {
    let backend = backend().await;
    let mac = mac().await;
    let mut side = NasSide::forwarding(&mac, &backend);
    side.periods = None;
    side.limits =
        NasAdminLimits { total: SLOTS, per_device: SLOTS, ..crate::nas_admin::production_limits() };
    let nas = side.spawn(fresh_seed(), NetworkConfig::direct_only()).await;

    let session = open_to(&mac, &nas).await.expect("available");
    let served = Served::start(session);
    let mut socket = websocket(served.addr).await;
    echo(&mut socket, "while authorized").await;

    side.withdraw(&mac);
    let removed = tokio::time::Instant::now();
    socket_ends(&mut socket, Duration::from_secs(70)).await;
    let took = removed.elapsed();
    eprintln!("the WebSocket ended {took:?} after the device left the account");
    ended(served.task).await;
    assert!(!accepts(served.addr).await);
    // The device is no longer admitted, so slots cannot be probed from it;
    // the NAS's backend connections are the leak check here.
    let deadline = tokio::time::Instant::now() + STEP;
    while backend.live.load(Ordering::SeqCst) != 0 {
        assert!(tokio::time::Instant::now() < deadline, "backend connections leaked");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A browser opens many connections at once (pages with keep-alive, a
/// WebSocket among them): every one is answered with its own content, none
/// starves another, and closing them all returns every slot on both ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn several_browser_connections_and_a_websocket_share_one_session() {
    let backend = backend().await;
    let mac = mac().await;
    let side = NasSide::forwarding(&mac, &backend);
    let nas = side.spawn(fresh_seed(), NetworkConfig::direct_only()).await;
    let session = open_to(&mac, &nas).await.expect("available");
    let served = Served::start(session);
    let addr = served.addr;

    let mut socket = websocket(addr).await;
    echo(&mut socket, "first").await;
    let browsers: Vec<_> = (0..SLOTS - 1)
        .map(|browser| {
            tokio::spawn(async move {
                let mut tcp = TcpStream::connect(addr).await.unwrap();
                for request in 0..5 {
                    let path = format!("/b{browser}/r{request}");
                    assert_eq!(get(&mut tcp, &path).await, format!("page:{path}"));
                    tokio::time::sleep(Duration::from_millis(30)).await;
                }
                tcp
            })
        })
        .collect();
    echo(&mut socket, "while pages load").await;
    let mut open_pages = Vec::new();
    for browser in browsers {
        open_pages.push(browser.await.unwrap());
    }
    echo(&mut socket, "after pages").await;
    assert_eq!(backend.live.load(Ordering::SeqCst), SLOTS, "one backend connection per browser");

    drop((open_pages, socket));
    served.close().await;
    nothing_is_left(addr, &backend, &mac, &nas).await;
}

/// Browser connections that close return their NAS slot: far more browser
/// connections than slots pass through one after another, and while every
/// slot is held the next connection gets nothing rather than a leaked slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closed_browser_connection_returns_its_slot() {
    let backend = backend().await;
    let mac = mac().await;
    let side = NasSide::forwarding(&mac, &backend);
    let nas = side.spawn(fresh_seed(), NetworkConfig::direct_only()).await;
    let session = open_to(&mac, &nas).await.expect("available");
    let served = Served::start(session);
    let addr = served.addr;

    for round in 0..SLOTS * 3 {
        connect_served(addr, &format!("/{round}")).await;
    }
    // The bridge's own check is gone, so all SLOTS can be held by browsers;
    // one more is refused by the NAS (busy) and is closed without a page.
    let mut held = Vec::new();
    for round in 0..SLOTS {
        held.push(connect_served(addr, &format!("/held{round}")).await);
    }
    let mut extra = TcpStream::connect(addr).await.unwrap();
    extra.write_all(b"GET /extra HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
    tcp_ends(&mut extra, STEP).await;

    // One browser leaves; its slot serves the next one.
    drop(held.pop());
    let deadline = tokio::time::Instant::now() + STEP;
    loop {
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        tcp.write_all(b"GET /again HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut answer = Vec::new();
        let _ = tokio::time::timeout(STEP, tcp.read_to_end(&mut answer)).await;
        if String::from_utf8_lossy(&answer).contains("page:/again") {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "the freed slot never came back");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    drop(held);
    served.close().await;
    nothing_is_left(addr, &backend, &mac, &nas).await;
}

/// The Mac app (or the CLI) goes away without a word while pages and a
/// WebSocket are open: the control connection drops, and the session, its
/// listener and every bridged connection go with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_mac_app_terminating_ends_the_session_with_browsers_open() {
    let backend = backend().await;
    let mac = mac().await;
    let side = NasSide::forwarding(&mac, &backend);
    let nas = side.spawn(fresh_seed(), NetworkConfig::direct_only()).await;

    for how in ["drop", "any byte"] {
        let session = open_to(&mac, &nas).await.expect("available");
        let addr = session.local_addr();
        let (mut client, mut daemon_side) = tokio::io::duplex(64);
        let serving = tokio::spawn(async move {
            serve_for_connection(session, &mut daemon_side).await;
        });
        let mut page = TcpStream::connect(addr).await.unwrap();
        assert_eq!(get(&mut page, "/open").await, "page:/open");
        let mut socket = websocket(addr).await;
        echo(&mut socket, "open").await;

        if how == "drop" {
            drop(client);
        } else {
            client.write_all(b"x").await.unwrap();
        }
        ended(serving).await;
        socket_ends(&mut socket, STEP).await;
        tcp_ends(&mut page, STEP).await;
        nothing_is_left(addr, &backend, &mac, &nas).await;
    }
}

/// Opening and closing sessions over and over leaves nothing behind: every
/// port is gone, every NAS slot is free, and the NAS holds no connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repeated_sessions_leave_no_listener_and_no_slot() {
    let backend = backend().await;
    let mac = mac().await;
    let side = NasSide::forwarding(&mac, &backend);
    let nas = side.spawn(fresh_seed(), NetworkConfig::direct_only()).await;
    let mut ports = Vec::new();
    for round in 0..8 {
        let session = open_to(&mac, &nas).await.expect("available");
        let served = Served::start(session);
        let mut page = TcpStream::connect(served.addr).await.unwrap();
        assert_eq!(get(&mut page, &format!("/{round}")).await, format!("page:/{round}"));
        ports.push(served.addr);
        served.close().await;
    }
    for port in &ports {
        assert!(!accepts(*port).await, "a listener is left on {port}");
    }
    nothing_is_left(*ports.last().unwrap(), &backend, &mac, &nas).await;
}

/// The NAS's management page stops while a session is open: the page the
/// browser holds ends, the next browser connection gets nothing (no other
/// service answers), and a new Manage reads as unavailable. The session
/// closes cleanly and leaves no listener.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_admin_page_stopping_ends_its_connections_and_nothing_else_answers() {
    let dir = tempfile::tempdir().unwrap();
    let config = yadorilink_http_api::HttpApiConfig {
        #[cfg(unix)]
        control_socket_path: dir.path().join("absent.sock"),
        #[cfg(windows)]
        control_pipe_name: r"\\.\pipe\yadorilink-absent-for-lifecycle-test".to_string(),
        token_path: dir.path().join("http-api-token"),
        port_path: dir.path().join("http-api-port"),
        port: 0,
        extra_allowed_origins: Vec::new(),
    };
    let handle = yadorilink_http_api::bind(&config).await.unwrap();
    let dashboard = Dashboard { streams: Some(handle.peer_streams()) };
    let serving = tokio::spawn(yadorilink_http_api::run(handle));
    // A service that would answer if the dashboard's failure were papered
    // over: it must never see a connection.
    let decoy = backend().await;

    let mac = mac().await;
    let side = NasSide::new(&mac, Arc::new(dashboard));
    let nas = side.spawn(fresh_seed(), NetworkConfig::direct_only()).await;
    let session = open_to(&mac, &nas).await.expect("the dashboard is available");
    let served = Served::start(session);
    let addr = served.addr;

    let mut page = TcpStream::connect(addr).await.unwrap();
    page.write_all(format!("GET /api/status HTTP/1.1\r\nHost: {addr}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut first = [0u8; 16];
    let n = tokio::time::timeout(STEP, page.read(&mut first)).await.unwrap().unwrap();
    assert!(n > 0, "the dashboard answers while it runs");

    serving.abort();
    let _ = serving.await;
    tcp_ends(&mut page, STEP).await;

    let mut next = TcpStream::connect(addr).await.unwrap();
    next.write_all(format!("GET / HTTP/1.1\r\nHost: {addr}\r\n\r\n").as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(STEP, next.read_to_end(&mut answer)).await;
    assert!(answer.is_empty(), "nothing answers in the dashboard's place: {answer:?}");
    assert_eq!(open_to(&mac, &nas).await.err(), Some(OpenFailure::Unavailable));
    assert_eq!(decoy.live.load(Ordering::SeqCst), 0);

    served.close().await;
    assert!(!accepts(addr).await);
}
