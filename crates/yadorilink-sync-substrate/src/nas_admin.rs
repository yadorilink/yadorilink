//! NAS management over the device's own authenticated endpoint.
//!
//! One fixed service, named by its ALPN ([`YADORI_NAS_ADMIN_ALPN`]) and by
//! nothing else. The wire carries no host, no port and no service name: a
//! connection negotiated on this ALPN can only ever reach the one local
//! management service the answering device chose for it. There is nothing a
//! dialler can send that selects another target, so this cannot be turned
//! into a port forward, a SOCKS proxy or a tunnel to an arbitrary local port.
//!
//! # Shape
//!
//! ```text
//! connect(ALPN = yadorilink/nas-admin/v1)    TLS: both sides prove their device key
//!   answerer: authorize(peer)                refused -> close(1, "unauthorized device")
//! per browser TCP connection, one stream:
//!   dialler -> open_bi(), 1 byte OpenService(NAS_ADMIN)
//!   answerer -> 1 status byte                Ready / Unavailable / Busy
//!   Ready: raw bytes both ways until either side finishes
//!   otherwise: answerer finishes; nothing else is sent
//! ```
//!
//! Those two bytes are the whole protocol. The dialler's byte names the
//! service, and only one value is defined; it exists because a QUIC stream
//! is invisible to the peer until its opener sends something, and a dialler
//! checking availability has nothing else to send yet. Nothing after the
//! status byte is read or framed here; HTTP, keep-alive, WebSocket and
//! server-sent events pass through as bytes.
//!
//! # Versions
//!
//! The ALPN is the version. A device that does not answer this ALPN refuses
//! the handshake ([`NasAdminError::Unsupported`]), which is how a dialler
//! tells "needs a newer version" apart from "offline" and from "refused".
//! A future incompatible change is a new ALPN, not a field.
//!
//! # Authorization
//!
//! Asked through [`NasAdminAuthorizer`], separately from every other
//! protocol's admission: being a sync peer (a folder-sharing device, possibly
//! on another account) says nothing about whether a device may manage this
//! one. The authorizer is asked once when the connection arrives and again
//! for every stream, so a device whose authority is withdrawn cannot open
//! another stream on a connection it already holds.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};

use crate::address::PeerAddress;
use crate::peer::PeerId;

/// ALPN for NAS management. The `v1` is the protocol version.
pub const YADORI_NAS_ADMIN_ALPN: &[u8] = b"yadorilink/nas-admin/v1";

/// Close code for a remote that authenticated but may not manage this
/// device. Same value and meaning as every other protocol's refusal.
const REFUSED_UNAUTHORIZED: u32 = 1;

/// The TLS alert a server sends when it answers none of the offered ALPNs
/// (RFC 7301 `no_application_protocol`), as QUIC carries it: a CRYPTO_ERROR
/// transport close.
const NO_APPLICATION_PROTOCOL_ALERT: u8 = 120;

/// The one byte a dialler writes first on every stream: `OpenService` with
/// the only service this protocol has. Any other value is refused by
/// resetting the stream.
pub const OPEN_NAS_ADMIN: u8 = 1;

/// How long an answering device waits for a new stream's first byte.
const OPEN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The one byte the answering device writes first on every stream.
///
/// Closed: an unknown value is a protocol error, never a state to guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NasAdminStatus {
    /// The local management service took the stream. Raw bytes follow.
    Ready,
    /// The local management service is not running. Nothing follows, and
    /// the device does not offer anything in its place.
    Unavailable,
    /// The device is already carrying its maximum number of management
    /// streams.
    Busy,
}

impl NasAdminStatus {
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Ready => 0,
            Self::Unavailable => 1,
            Self::Busy => 2,
        }
    }

    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Ready),
            1 => Some(Self::Unavailable),
            2 => Some(Self::Busy),
            _ => None,
        }
    }
}

/// Why a management stream could not be opened, as the dialler sees it.
///
/// Closed; each variant is something a dialler can tell apart on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NasAdminError {
    /// No connection could be made: the device is not reachable.
    #[error("the device could not be reached")]
    Unreachable,
    /// The device answered but does not speak this protocol version.
    #[error("the device does not offer management at this protocol version")]
    Unsupported,
    /// The device refused this one as not allowed to manage it.
    #[error("the device refused management from this device")]
    Unauthorized,
    /// The device's local management service is not running.
    #[error("the device's management service is not running")]
    Unavailable,
    /// The device is carrying its maximum number of management streams.
    #[error("the device is carrying its maximum number of management streams")]
    Busy,
    /// The connection ended, or the device answered something this protocol
    /// does not define.
    #[error("the management stream failed")]
    Failed,
}

/// Who may manage this device. Asked of live state, never of a snapshot
/// taken when the node started, so that withdrawing a device's authority
/// takes effect on its next connection and its next stream.
///
/// Asynchronous because the authoritative answer may need a round trip;
/// an implementation must bound how often it makes one, since an
/// authenticated stranger can make the question be asked.
pub trait NasAdminAuthorizer: std::fmt::Debug + Send + Sync + 'static {
    /// `true` if `peer`, authenticated by its device key, may manage this
    /// device. Any doubt is `false`.
    fn authorize(&self, peer: PeerId) -> Pin<Box<dyn Future<Output = bool> + Send + '_>>;
}

/// The local management service an authorized stream is handed to.
///
/// Takes a byte stream and nothing else: there is no parameter through which
/// a caller could name an address, so an implementation serves exactly one
/// service.
pub trait NasAdminEndpoint: Send + Sync + 'static {
    /// Whether the service is running right now.
    fn available(&self) -> bool;

    /// Hands over a stream the device has already told the dialler is
    /// `Ready`. A service that stopped in between drops it, which the
    /// dialler sees as the stream ending.
    fn deliver(&self, stream: NasAdminStream);
}

/// One accepted management connection, already authorized once.
#[derive(Debug, Clone)]
pub struct NasAdminConnection {
    peer: PeerId,
    connection: iroh::endpoint::Connection,
}

impl NasAdminConnection {
    fn new(connection: iroh::endpoint::Connection) -> Self {
        Self { peer: PeerId::from_bytes(*connection.remote_id().as_bytes()), connection }
    }

    /// The remote's authenticated identity: the key it proved during the
    /// handshake, never anything it says afterwards.
    pub fn peer(&self) -> PeerId {
        self.peer
    }

    /// Opens one management stream and reads the device's status byte.
    ///
    /// Only a `Ready` stream is returned; every other answer is an error and
    /// the stream is dropped.
    pub async fn open_stream(&self) -> Result<NasAdminStream, NasAdminError> {
        let (mut send, mut recv) =
            self.connection.open_bi().await.map_err(|err| self.classify_closed(&err))?;
        if send.write_all(&[OPEN_NAS_ADMIN]).await.is_err() {
            return Err(self.closed_reason().unwrap_or(NasAdminError::Failed));
        }
        let mut status = [0u8; 1];
        if recv.read_exact(&mut status).await.is_err() {
            return Err(self.closed_reason().unwrap_or(NasAdminError::Failed));
        }
        match NasAdminStatus::from_byte(status[0]) {
            Some(NasAdminStatus::Ready) => Ok(NasAdminStream { send, recv, _slot: None }),
            Some(NasAdminStatus::Unavailable) => Err(NasAdminError::Unavailable),
            Some(NasAdminStatus::Busy) => Err(NasAdminError::Busy),
            None => Err(NasAdminError::Failed),
        }
    }

    /// Resolves once the connection has ended, from either side. A dialler
    /// holding a connection for a session ends the session with it.
    pub async fn closed(&self) {
        self.connection.closed().await;
    }

    /// Closes the connection. Idempotent.
    pub fn close(&self) {
        self.connection.close(0u32.into(), b"closed");
    }

    fn classify_closed(&self, err: &iroh::endpoint::ConnectionError) -> NasAdminError {
        match err {
            iroh::endpoint::ConnectionError::ApplicationClosed(close)
                if close.error_code == REFUSED_UNAUTHORIZED.into() =>
            {
                NasAdminError::Unauthorized
            }
            _ => NasAdminError::Failed,
        }
    }

    fn closed_reason(&self) -> Option<NasAdminError> {
        self.connection.close_reason().map(|err| self.classify_closed(&err))
    }
}

/// One management stream: raw bytes both ways.
///
/// On the answering side it carries the slot it occupies, released when the
/// stream is dropped, so the service it is handed to cannot hold more
/// streams than the bound however long it keeps them.
#[derive(Debug)]
pub struct NasAdminStream {
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
    _slot: Option<Slot>,
}

impl AsyncRead for NasAdminStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for NasAdminStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

/// How many management streams a device carries, and how often it asks
/// again whether a connected device may still manage it.
#[derive(Debug, Clone, Copy)]
pub struct NasAdminLimits {
    /// Streams across every connection. A browser opens a handful per
    /// page; the default leaves room for a few tabs.
    pub total: usize,
    /// Streams from any one device, so a single device -- one whose
    /// authority is about to be withdrawn included -- cannot take every slot.
    pub per_device: usize,
    /// How often an open connection is re-authorized even when it opens no
    /// new stream. A refusal closes the connection, ending every stream on
    /// it, so withdrawn authority reaches long-lived streams too.
    pub recheck: Duration,
}

impl Default for NasAdminLimits {
    fn default() -> Self {
        Self { total: 32, per_device: 12, recheck: Duration::from_secs(30) }
    }
}

/// Serves management connections: re-authorizes, answers each stream with
/// its status byte, and hands `Ready` ones to the endpoint.
pub struct NasAdminService {
    authorizer: Arc<dyn NasAdminAuthorizer>,
    endpoint: Arc<dyn NasAdminEndpoint>,
    limits: NasAdminLimits,
    total: Arc<Semaphore>,
    per_device: Arc<Mutex<HashMap<PeerId, usize>>>,
}

impl NasAdminService {
    pub fn new(
        authorizer: Arc<dyn NasAdminAuthorizer>,
        endpoint: Arc<dyn NasAdminEndpoint>,
        limits: NasAdminLimits,
    ) -> Arc<Self> {
        Arc::new(Self {
            authorizer,
            endpoint,
            limits,
            total: Arc::new(Semaphore::new(limits.total)),
            per_device: Arc::default(),
        })
    }

    /// Serves one accepted connection until it ends or its device is no
    /// longer authorized.
    pub async fn serve(self: Arc<Self>, connection: NasAdminConnection) {
        let mut recheck = tokio::time::interval_at(
            tokio::time::Instant::now() + self.limits.recheck,
            self.limits.recheck,
        );
        loop {
            tokio::select! {
                accepted = connection.connection.accept_bi() => {
                    let Ok((send, recv)) = accepted else { return };
                    // Each stream on its own task, so one slow stream never
                    // holds up the next.
                    let service = self.clone();
                    let connection = connection.clone();
                    tokio::spawn(async move {
                        service.serve_stream(&connection, send, recv).await;
                    });
                }
                _ = recheck.tick() => {
                    if !self.authorizer.authorize(connection.peer).await {
                        refuse_connection(&connection);
                        return;
                    }
                }
            }
        }
    }

    async fn serve_stream(
        &self,
        connection: &NasAdminConnection,
        mut send: iroh::endpoint::SendStream,
        mut recv: iroh::endpoint::RecvStream,
    ) {
        if !self.authorizer.authorize(connection.peer).await {
            refuse_connection(connection);
            return;
        }
        let mut open = [0u8; 1];
        match tokio::time::timeout(OPEN_TIMEOUT, recv.read_exact(&mut open)).await {
            Ok(Ok(_)) if open[0] == OPEN_NAS_ADMIN => {}
            _ => {
                let _ = send.reset(0u32.into());
                return;
            }
        }
        // No fallback: an absent service is reported, never substituted.
        // Asked before taking a slot, so refusals never occupy one.
        if !self.endpoint.available() {
            refuse(send, NasAdminStatus::Unavailable).await;
            return;
        }
        let Some(slot) = self.take_slot(connection.peer) else {
            refuse(send, NasAdminStatus::Busy).await;
            return;
        };
        if send.write_all(&[NasAdminStatus::Ready.to_byte()]).await.is_err() {
            return;
        }
        self.endpoint.deliver(NasAdminStream { send, recv, _slot: Some(slot) });
    }

    fn take_slot(&self, peer: PeerId) -> Option<Slot> {
        let mut per_device = self.per_device.lock().unwrap_or_else(|p| p.into_inner());
        let held = per_device.entry(peer).or_insert(0);
        if *held >= self.limits.per_device {
            return None;
        }
        let permit = self.total.clone().try_acquire_owned().ok()?;
        *held += 1;
        Some(Slot { _permit: permit, per_device: self.per_device.clone(), peer })
    }
}

/// Closes a connection whose device is no longer authorized.
fn refuse_connection(connection: &NasAdminConnection) {
    connection.connection.close(REFUSED_UNAUTHORIZED.into(), b"unauthorized device");
    tracing::debug!(
        peer = ?connection.peer,
        "closed a management connection whose device is no longer authorized"
    );
}

/// One stream's place in both bounds, given back when the stream is dropped.
#[derive(Debug)]
struct Slot {
    _permit: OwnedSemaphorePermit,
    per_device: Arc<Mutex<HashMap<PeerId, usize>>>,
    peer: PeerId,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut per_device = self.per_device.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(held) = per_device.get_mut(&self.peer) {
            *held = held.saturating_sub(1);
            if *held == 0 {
                per_device.remove(&self.peer);
            }
        }
    }
}

/// Answers a stream with a refusal and ends it.
async fn refuse(mut send: iroh::endpoint::SendStream, status: NasAdminStatus) {
    if send.write_all(&[status.to_byte()]).await.is_ok() {
        let _ = send.finish();
        // Wait (briefly) for the byte to be acknowledged so dropping the
        // stream right after cannot race it.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), send.stopped()).await;
    }
}

/// Where accepted management connections go, and who may open one.
#[derive(Debug, Clone)]
pub(crate) struct NasAdminAccept {
    pub(crate) authorizer: Arc<dyn NasAdminAuthorizer>,
    pub(crate) inbound: mpsc::Sender<NasAdminConnection>,
}

/// The router's handler for [`YADORI_NAS_ADMIN_ALPN`].
#[derive(Debug, Clone)]
pub(crate) struct NasAdminHandler {
    pub(crate) accept: NasAdminAccept,
}

impl iroh::protocol::ProtocolHandler for NasAdminHandler {
    async fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        let accepted = NasAdminConnection::new(connection.clone());
        // Authenticated is not authorized. Refused before anything can be
        // opened on it. The router runs each accept on its own task, so an
        // authorizer's round trip delays only this connection.
        if !self.accept.authorizer.authorize(accepted.peer()).await {
            connection.close(REFUSED_UNAUTHORIZED.into(), b"unauthorized device");
            tracing::debug!(peer = ?accepted.peer(), "refused an inbound management connection");
            return Ok(());
        }
        if self.accept.inbound.send(accepted).await.is_err() {
            connection.close(0u32.into(), b"shutting down");
            return Ok(());
        }
        connection.closed().await;
        Ok(())
    }
}

/// Dial `address` on [`YADORI_NAS_ADMIN_ALPN`].
///
/// The addresses in `address` are hints added to whatever the endpoint's own
/// lookup knows.
pub(crate) async fn connect(
    endpoint: &iroh::Endpoint,
    address: &PeerAddress,
) -> Result<NasAdminConnection, NasAdminError> {
    let id = iroh::EndpointId::from_bytes(address.peer().as_bytes())
        .map_err(|_| NasAdminError::Unreachable)?;
    let mut target = iroh::EndpointAddr::new(id);
    for direct in address.direct_addrs() {
        target = target.with_ip_addr(*direct);
    }
    for relay in address.relay_urls() {
        if let Ok(url) = relay.parse::<iroh::RelayUrl>() {
            target = target.with_relay_url(url);
        }
    }
    let connection =
        endpoint.connect(target, YADORI_NAS_ADMIN_ALPN).await.map_err(|err| classify_dial(&err))?;
    Ok(NasAdminConnection::new(connection))
}

/// A failed dial, in the terms a dialler acts on: a handshake the remote
/// refused for want of this ALPN is a version problem; anything else that
/// stopped the connection from forming is reachability.
fn classify_dial(err: &iroh::endpoint::ConnectError) -> NasAdminError {
    use iroh::endpoint::{ConnectError, ConnectingError, ConnectionError, TransportErrorCode};
    let closed = match err {
        ConnectError::Connection { source, .. } => Some(source),
        ConnectError::Connecting {
            source: ConnectingError::ConnectionError { source, .. },
            ..
        } => Some(source),
        _ => None,
    };
    match closed {
        Some(ConnectionError::ConnectionClosed(close))
            if close.error_code == TransportErrorCode::crypto(NO_APPLICATION_PROTOCOL_ALERT) =>
        {
            NasAdminError::Unsupported
        }
        Some(ConnectionError::ApplicationClosed(close))
            if close.error_code == REFUSED_UNAUTHORIZED.into() =>
        {
            NasAdminError::Unauthorized
        }
        _ => NasAdminError::Unreachable,
    }
}

#[cfg(test)]
mod tests;
