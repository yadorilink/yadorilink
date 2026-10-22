//! The dialling side on real endpoints: a "Mac" node opens a session to a
//! "NAS" node that answers the management ALPN, and a browser is played by
//! plain TCP clients on the session's local address.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use yadorilink_sync_substrate::{
    AdmitNone, NasAdminAuthorizer, NasAdminEndpoint, NasAdminLimits, NasAdminService,
    NasAdminStream, NetworkConfig, PeerId, SubstrateNode,
};

use super::*;

const STEP: Duration = Duration::from_secs(15);

/// A key no other node in this test binary uses: tests run in parallel, and
/// two live endpoints sharing an identity would make every dial ambiguous.
fn fresh_seed() -> [u8; 32] {
    static NEXT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);
    let mut seed = [0x5au8; 32];
    seed[0] = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    seed
}

/// Admits everyone or no one.
#[derive(Debug)]
struct Allow(bool);

impl NasAdminAuthorizer for Allow {
    fn authorize(
        &self,
        _peer: PeerId,
    ) -> std::pin::Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        let allowed = self.0;
        Box::pin(async move { allowed })
    }
}

/// A management service that copies each stream to a local test server, or
/// one that is not running (`None`).
struct Forward(Option<SocketAddr>);

impl NasAdminEndpoint for Forward {
    fn available(&self) -> bool {
        self.0.is_some()
    }

    fn deliver(&self, mut stream: NasAdminStream) {
        let Some(target) = self.0 else { return };
        tokio::spawn(async move {
            let Ok(mut tcp) = TcpStream::connect(target).await else { return };
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
        });
    }
}

async fn mac() -> SubstrateNode {
    SubstrateNode::spawn_as_device(fresh_seed(), NetworkConfig::direct_only(), Arc::new(AdmitNone))
        .await
        .expect("substrate starts")
        .0
}

/// A NAS answering the management ALPN with `endpoint`, admitting whoever
/// `allow` says.
async fn nas(endpoint: Arc<dyn NasAdminEndpoint>, allow: bool) -> SubstrateNode {
    let authorizer: Arc<dyn NasAdminAuthorizer> = Arc::new(Allow(allow));
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let (node, _) = SubstrateNode::spawn_as_device(
        fresh_seed(),
        NetworkConfig::direct_only().with_nas_admin(authorizer.clone(), tx),
        Arc::new(AdmitNone),
    )
    .await
    .expect("substrate starts");
    let service = NasAdminService::new(authorizer, endpoint, NasAdminLimits::default());
    tokio::spawn(async move {
        while let Some(connection) = rx.recv().await {
            tokio::spawn(service.clone().serve(connection));
        }
    });
    node
}

/// A NAS that does not answer the management ALPN at all: an older build.
async fn old_nas() -> SubstrateNode {
    SubstrateNode::spawn_as_device(fresh_seed(), NetworkConfig::direct_only(), Arc::new(AdmitNone))
        .await
        .expect("substrate starts")
        .0
}

async fn open(
    mac: &SubstrateNode,
    nas: &SubstrateNode,
    limits: BridgeLimits,
) -> Result<BridgeSession, OpenFailure> {
    BridgeSession::open(mac.connect_nas_admin(&nas.local_address()), limits).await
}

fn quick() -> BridgeLimits {
    BridgeLimits { step: Duration::from_secs(10), ..BridgeLimits::default() }
}

/// One HTTP exchange with `Connection: close`, as a browser would send it to
/// the page address.
async fn http_get(addr: SocketAddr, path: &str) -> String {
    let mut tcp = TcpStream::connect(addr).await.expect("the session accepts");
    let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    tcp.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(STEP, tcp.read_to_end(&mut response))
        .await
        .expect("response in time")
        .unwrap();
    String::from_utf8_lossy(&response).into_owned()
}

/// Whether anything still accepts on `addr`.
async fn accepts(addr: SocketAddr) -> bool {
    TcpStream::connect(addr).await.is_ok()
}

/// Waits for a spawned session to end on its own.
async fn ended(serving: tokio::task::JoinHandle<()>) {
    tokio::time::timeout(STEP, serving).await.expect("the session ends").unwrap();
}

/// End to end: the session's local page address serves the NAS's real
/// dashboard, the page and its API, with no token. The address is loopback
/// and ephemeral, and names nothing but the port.
#[tokio::test(flavor = "multi_thread")]
async fn the_local_page_address_serves_the_nas_dashboard_on_loopback() {
    let dir = tempfile::tempdir().unwrap();
    let config = yadorilink_http_api::HttpApiConfig {
        #[cfg(unix)]
        control_socket_path: dir.path().join("absent.sock"),
        #[cfg(windows)]
        control_pipe_name: r"\\.\pipe\yadorilink-absent-for-bridge-test".to_string(),
        token_path: dir.path().join("http-api-token"),
        port_path: dir.path().join("http-api-port"),
        port: 0,
        extra_allowed_origins: Vec::new(),
    };
    let handle = yadorilink_http_api::bind(&config).await.unwrap();
    let dashboard = crate::nas_admin::Dashboard { streams: Some(handle.peer_streams()) };
    tokio::spawn(yadorilink_http_api::run(handle));
    let (mac, nas) = (mac().await, nas(Arc::new(dashboard), true).await);

    let session = open(&mac, &nas, quick()).await.expect("the dashboard is available");
    let addr = session.local_addr();
    assert_eq!(addr.ip(), std::net::IpAddr::from(Ipv4Addr::LOCALHOST), "loopback only");
    assert_ne!(addr.port(), 0);
    assert_eq!(session.local_url(), format!("http://127.0.0.1:{}/", addr.port()));
    tokio::spawn(session.serve(std::future::pending()));

    let page = http_get(addr, "/").await;
    assert!(page.starts_with("HTTP/1.1 200"), "{page}");
    assert!(page.contains("<html") || page.contains("<!doctype"), "the dashboard page: {page}");
    let api = http_get(addr, "/api/status").await;
    assert!(
        !api.starts_with("HTTP/1.1 401") && !api.starts_with("HTTP/1.1 403"),
        "a device-authorized request needs no token: {api}"
    );
}

/// Echoes every text and binary frame of one WebSocket connection.
async fn echo_websocket(tcp: TcpStream) {
    let Ok(mut socket) = tokio_tungstenite::accept_async(tcp).await else { return };
    while let Some(Ok(message)) = socket.next().await {
        if message.is_text() || message.is_binary() {
            let _ = socket.send(message).await;
        }
    }
}

/// A WebSocket and a server-sent event stream pass through the byte copy:
/// frames both ways after the upgrade, and events as they are sent.
#[tokio::test(flavor = "multi_thread")]
async fn websocket_and_server_sent_events_pass_through() {
    // WebSocket echo.
    let ws = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ws_addr = ws.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = ws.accept().await {
            tokio::spawn(echo_websocket(tcp));
        }
    });
    let mac = mac().await;
    let nas_ws = nas(Arc::new(Forward(Some(ws_addr))), true).await;
    let session = open(&mac, &nas_ws, quick()).await.expect("available");
    let addr = session.local_addr();
    tokio::spawn(session.serve(std::future::pending()));

    let tcp = TcpStream::connect(addr).await.unwrap();
    let (mut socket, _) =
        tokio_tungstenite::client_async(format!("ws://{addr}/socket"), tcp).await.unwrap();
    socket.send(Message::text("hello")).await.unwrap();
    assert_eq!(socket.next().await.unwrap().unwrap(), Message::text("hello"));
    socket.send(Message::binary(vec![0u8, 1, 2, 255])).await.unwrap();
    assert_eq!(socket.next().await.unwrap().unwrap(), Message::binary(vec![0u8, 1, 2, 255]));
    drop(socket);
    nas_ws.shutdown().await;

    // Server-sent events: the second event is only written once the first
    // has reached the browser.
    let sse = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sse_addr = sse.local_addr().unwrap();
    let (first_seen_tx, first_seen) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        // The availability check's stream reaches the service too, and
        // ends without a request; the browser's is the one that sends one.
        let mut tcp = loop {
            let (mut tcp, _) = sse.accept().await.unwrap();
            let mut request = [0u8; 1024];
            if matches!(tcp.read(&mut request).await, Ok(n) if n > 0) {
                break tcp;
            }
        };
        tcp.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: one\n\n")
            .await
            .unwrap();
        let _ = first_seen.await;
        tcp.write_all(b"data: two\n\n").await.unwrap();
        let _ = tcp.shutdown().await;
    });
    let nas_sse = nas(Arc::new(Forward(Some(sse_addr))), true).await;
    let session = open(&mac, &nas_sse, quick()).await.expect("available");
    let addr = session.local_addr();
    tokio::spawn(session.serve(std::future::pending()));
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(format!("GET /events HTTP/1.1\r\nHost: {addr}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut received = Vec::new();
    while !String::from_utf8_lossy(&received).contains("data: one\n\n") {
        let mut chunk = [0u8; 256];
        let n = tokio::time::timeout(STEP, tcp.read(&mut chunk)).await.unwrap().unwrap();
        assert_ne!(n, 0, "the stream ended before the first event");
        received.extend_from_slice(&chunk[..n]);
    }
    assert!(!String::from_utf8_lossy(&received).contains("two"));
    first_seen_tx.send(()).unwrap();
    tokio::time::timeout(STEP, tcp.read_to_end(&mut received)).await.unwrap().unwrap();
    assert!(String::from_utf8_lossy(&received).ends_with("data: two\n\n"));
}

/// A server that accepts and then never sends a byte.
async fn silent_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((tcp, _)) = listener.accept().await {
            held.push(tcp);
        }
    });
    addr
}

/// A bridged connection on which nothing moves is closed by the bridge
/// itself, and a session with no connection left ends and closes its
/// listener.
#[tokio::test(flavor = "multi_thread")]
async fn idle_connections_and_idle_sessions_are_closed() {
    let (mac, nas) = (mac().await, nas(Arc::new(Forward(Some(silent_server().await))), true).await);
    let limits = BridgeLimits {
        connection_idle: Duration::from_millis(400),
        session_idle: Duration::from_millis(800),
        ..quick()
    };
    let session = open(&mac, &nas, limits).await.expect("available");
    let addr = session.local_addr();
    let serving = tokio::spawn(session.serve(std::future::pending()));

    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let mut rest = Vec::new();
    let read = tokio::time::timeout(STEP, tcp.read_to_end(&mut rest)).await;
    assert!(read.is_ok(), "an idle bridged connection must be closed by the bridge");
    assert!(rest.is_empty());

    ended(serving).await;
    assert!(!accepts(addr).await, "an idle session's listener is gone");
}

/// Ending a session closes its listener: the port no longer accepts, and a
/// connection already bridged ends with it.
#[tokio::test(flavor = "multi_thread")]
async fn closing_a_session_removes_its_listener() {
    let (mac, nas) = (mac().await, nas(Arc::new(Forward(Some(silent_server().await))), true).await);
    let session = open(&mac, &nas, quick()).await.expect("available");
    let addr = session.local_addr();
    let (close, closed) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn(session.serve(async {
        let _ = closed.await;
    }));
    assert!(accepts(addr).await);
    let mut held = TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    close.send(()).unwrap();
    ended(serving).await;
    assert!(!accepts(addr).await, "a closed session's port must not accept");
    let mut rest = Vec::new();
    let read = tokio::time::timeout(STEP, held.read_to_end(&mut rest)).await;
    assert!(read.is_ok(), "a bridged connection ends with its session");
}

/// The session lives exactly as long as the control connection it was
/// opened on: a client that exits, crashes or closes it ends the session.
#[tokio::test(flavor = "multi_thread")]
async fn dropping_the_control_connection_ends_the_session() {
    let (mac, nas) = (mac().await, nas(Arc::new(Forward(Some(silent_server().await))), true).await);
    let session = open(&mac, &nas, quick()).await.expect("available");
    let addr = session.local_addr();
    let (client, mut daemon_side) = tokio::io::duplex(64);
    let serving = tokio::spawn(async move {
        serve_for_connection(session, &mut daemon_side).await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(accepts(addr).await, "the session is open while its client is");

    drop(client);
    ended(serving).await;
    assert!(!accepts(addr).await, "the client went away, so the listener did too");
}

/// The managed device going away (daemon stopped, connection ended) ends the
/// session too: nothing is left listening for a device that is gone.
#[tokio::test(flavor = "multi_thread")]
async fn the_device_connection_ending_ends_the_session() {
    let (mac, nas) = (mac().await, nas(Arc::new(Forward(Some(silent_server().await))), true).await);
    let session = open(&mac, &nas, quick()).await.expect("available");
    let addr = session.local_addr();
    let serving = tokio::spawn(session.serve(std::future::pending()));
    nas.shutdown().await;
    ended(serving).await;
    assert!(!accepts(addr).await);
}

/// At most `connections` browser connections are bridged at once; the next
/// one waits until a slot frees instead of opening another stream.
#[tokio::test(flavor = "multi_thread")]
async fn bridged_connections_are_bounded() {
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = echo.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = tcp.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    let (mac, nas) = (mac().await, nas(Arc::new(Forward(Some(echo_addr))), true).await);
    let session =
        open(&mac, &nas, BridgeLimits { connections: 1, ..quick() }).await.expect("available");
    let addr = session.local_addr();
    tokio::spawn(session.serve(std::future::pending()));

    let mut first = TcpStream::connect(addr).await.unwrap();
    first.write_all(b"a").await.unwrap();
    let mut byte = [0u8; 1];
    tokio::time::timeout(STEP, first.read_exact(&mut byte)).await.unwrap().unwrap();

    let mut second = TcpStream::connect(addr).await.unwrap();
    second.write_all(b"b").await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(500), second.read_exact(&mut byte))
            .await
            .is_err(),
        "a connection beyond the bound is not bridged yet"
    );
    drop(first);
    tokio::time::timeout(STEP, second.read_exact(&mut byte)).await.unwrap().unwrap();
    assert_eq!(&byte, b"b");
}

/// Each way a device can fail to be managed is one of the three states, and
/// nothing is bound for a failed session.
#[tokio::test(flavor = "multi_thread")]
async fn each_failure_is_one_of_the_three_states() {
    let mac = mac().await;

    let stopped = nas(Arc::new(Forward(None)), true).await;
    assert_eq!(open(&mac, &stopped, quick()).await.err(), Some(OpenFailure::Unavailable));

    let refusing = nas(Arc::new(Forward(Some(silent_server().await))), false).await;
    assert_eq!(
        open(&mac, &refusing, quick()).await.err(),
        Some(OpenFailure::CouldNotOpen),
        "an unauthorized device gets the generic failure"
    );

    // A device that does not answer the management protocol (an older build,
    // or a desktop, which does not offer it) reads as not available.
    let old = old_nas().await;
    assert_eq!(open(&mac, &old, quick()).await.err(), Some(OpenFailure::Unavailable));

    let never = std::future::pending::<Result<NasAdminConnection, NasAdminError>>();
    let limits = BridgeLimits { step: Duration::from_millis(300), ..quick() };
    assert_eq!(
        BridgeSession::open(never, limits).await.err(),
        Some(OpenFailure::Offline),
        "a dial that does not finish is an offline device"
    );

    let gone = nas(Arc::new(Forward(Some(silent_server().await))), true).await;
    let address = gone.local_address();
    gone.shutdown().await;
    let limits = BridgeLimits { step: Duration::from_secs(5), ..quick() };
    assert_eq!(
        BridgeSession::open(mac.connect_nas_admin(&address), limits).await.err(),
        Some(OpenFailure::Offline)
    );
}

/// The page address is chosen here and only here: one bind, on loopback,
/// on an ephemeral port. No caller passes a host or a port.
#[test]
fn the_listener_is_bound_once_on_loopback_with_an_ephemeral_port() {
    let source = include_str!("../nas_admin_bridge.rs");
    let code: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(code.matches("bind(").count(), 1, "one listener");
    assert!(code.contains("TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))"));
    for forbidden in ["UNSPECIFIED", "0.0.0.0", "Ipv6Addr", "PORT_FILE_NAME", "TcpStream::connect"]
    {
        assert!(!code.contains(forbidden), "nas_admin_bridge.rs must not use {forbidden}");
    }
}

/// Admits the connection and the availability check, then stops answering:
/// every later stream waits on the authorizer for ever.
#[derive(Debug, Default)]
struct StallAfterOpen(std::sync::atomic::AtomicBool);

impl NasAdminAuthorizer for StallAfterOpen {
    fn authorize(
        &self,
        _peer: PeerId,
    ) -> std::pin::Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        let stalled = self.0.load(std::sync::atomic::Ordering::SeqCst);
        Box::pin(async move {
            if stalled {
                std::future::pending::<()>().await;
            }
            true
        })
    }
}

/// A device that takes the browser connection's stream and never answers
/// must not hold its slot: the browser connection is closed once
/// `stream_open` has passed, and the slot serves the next one.
#[tokio::test(flavor = "multi_thread")]
async fn a_device_that_never_answers_a_stream_does_not_hold_the_connection() {
    let stall = Arc::new(StallAfterOpen::default());
    let authorizer: Arc<dyn NasAdminAuthorizer> = stall.clone();
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let (nas, _) = SubstrateNode::spawn_as_device(
        fresh_seed(),
        NetworkConfig::direct_only().with_nas_admin(authorizer.clone(), tx),
        Arc::new(AdmitNone),
    )
    .await
    .expect("substrate starts");
    let service = NasAdminService::new(
        authorizer,
        Arc::new(Forward(Some(silent_server().await))),
        NasAdminLimits::default(),
    );
    tokio::spawn(async move {
        while let Some(connection) = rx.recv().await {
            tokio::spawn(service.clone().serve(connection));
        }
    });
    let mac = mac().await;
    let limits =
        BridgeLimits { connections: 1, stream_open: Duration::from_millis(300), ..quick() };
    // The check needs a running service to answer `Ready`.
    let session = match open(&mac, &nas, limits).await {
        Ok(session) => session,
        Err(failure) => panic!("the check should pass before the stall: {failure:?}"),
    };
    stall.0.store(true, std::sync::atomic::Ordering::SeqCst);
    let addr = session.local_addr();
    tokio::spawn(session.serve(std::future::pending()));

    for _ in 0..2 {
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        tcp.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let mut rest = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut rest)).await;
        assert!(read.is_ok(), "the stalled stream must be given up on, freeing the slot");
        assert!(rest.is_empty());
    }
}

/// A listener whose accept always fails, counting the attempts.
struct FailingAccept(Arc<std::sync::atomic::AtomicUsize>);

impl Accept for FailingAccept {
    async fn accept(&self) -> std::io::Result<TcpStream> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(std::io::Error::other("out of descriptors"))
    }
}

/// A persistently failing accept is retried with a growing pause, not in a
/// hot loop, and the session still ends when asked to.
#[tokio::test(flavor = "multi_thread")]
async fn a_failing_accept_backs_off_instead_of_spinning() {
    let (mac, nas) = (mac().await, nas(Arc::new(Forward(Some(silent_server().await))), true).await);
    let session = open(&mac, &nas, quick()).await.expect("available");
    let BridgeSession { connection, limits, .. } = session;
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let until = tokio::time::sleep(Duration::from_millis(600));
    tokio::time::timeout(
        STEP,
        serve_on(connection, FailingAccept(attempts.clone()), limits, until),
    )
    .await
    .expect("the session ends when asked, whatever accept does");
    let attempts = attempts.load(std::sync::atomic::Ordering::SeqCst);
    assert!(attempts >= 3, "accept is retried: {attempts}");
    assert!(attempts <= 15, "accept must back off, not spin: {attempts}");
}

mod lifecycle;
