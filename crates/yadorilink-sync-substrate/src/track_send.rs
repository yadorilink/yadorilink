//! Track Send's own protocol on this node's endpoint.
//!
//! One iroh endpoint, one router, two protocols told apart by ALPN: the sync
//! protocol ([`crate::YADORI_SYNC_ALPN`]) and one-shot file sending
//! ([`YADORI_SEND_ALPN`]). A connection negotiated for one is never handed to
//! the other's handler, so a Track Send peer cannot open a sync lane and a
//! sync peer cannot make an offer through the sync protocol.
//!
//! Each protocol also has its own admission. Being one of this device's sync
//! peers says nothing about whether a peer may send it a file, and being
//! allowed to send a file says nothing about any folder: the node is given a
//! separate [`PeerAdmission`](crate::PeerAdmission) for this ALPN, and the
//! sync admission is never consulted for it (nor this one for sync).
//!
//! What crosses this boundary is a plain bidirectional-stream connection. The
//! Track Send wire format -- length-prefixed protobuf messages, chunk bodies
//! -- is the caller's; nothing here reads it.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use crate::error::SubstrateError;
use crate::peer::PeerId;

/// ALPN for Track Send.
pub const YADORI_SEND_ALPN: &[u8] = b"yadorilink/send/v1";

/// Close code for a remote that authenticated but may not use Track Send
/// with this device. Same value and meaning as the sync handler's refusal.
const REFUSED_UNAUTHORIZED: u32 = 1;

/// Close reason for a live Track Send connection ended because its device's
/// authority was withdrawn after it was admitted.
const CLOSED_REVOKED: &[u8] = b"device revoked";

/// One authenticated Track Send connection.
///
/// Cheap to clone; clones share the connection.
#[derive(Debug, Clone)]
pub struct TrackSendConnection {
    peer: PeerId,
    connection: iroh::endpoint::Connection,
}

impl TrackSendConnection {
    fn new(connection: iroh::endpoint::Connection) -> Self {
        Self { peer: PeerId::from_bytes(*connection.remote_id().as_bytes()), connection }
    }

    /// The remote's authenticated identity: the key it proved it holds
    /// during the handshake, never anything it claims afterwards.
    pub fn peer(&self) -> PeerId {
        self.peer
    }

    /// Open a stream as the initiating side.
    pub async fn open_stream(&self) -> Result<(TrackSendWriter, TrackSendReader), SubstrateError> {
        let (send, recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|err| SubstrateError::TrackSend(err.to_string()))?;
        Ok((TrackSendWriter { inner: send }, TrackSendReader { inner: recv }))
    }

    /// Accept the next stream the remote opens. An error means the
    /// connection is gone.
    pub async fn accept_stream(
        &self,
    ) -> Result<(TrackSendWriter, TrackSendReader), SubstrateError> {
        let (send, recv) = self
            .connection
            .accept_bi()
            .await
            .map_err(|err| SubstrateError::TrackSend(err.to_string()))?;
        Ok((TrackSendWriter { inner: send }, TrackSendReader { inner: recv }))
    }

    /// Close the connection with an application close code and reason.
    /// Idempotent.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.connection.close(code.into(), reason);
    }
}

/// Every Track Send connection a node holds, accepted or dialled, so a
/// device whose authority is withdrawn can have the ones it already has
/// closed.
///
/// Admission is asked once, when a connection is accepted; nothing asks it
/// again for the life of that connection. Withdrawing a device therefore
/// refuses its NEXT connection and says nothing to the one already up --
/// this is what reaches that one.
///
/// Holds weak handles only: whoever uses a connection decides how long it
/// lives, and being listed here must not keep it open. Cheap to clone;
/// clones share the list.
#[derive(Debug, Clone, Default)]
pub struct TrackSendConnections {
    held: Arc<Mutex<Vec<(PeerId, iroh::endpoint::WeakConnectionHandle)>>>,
}

impl TrackSendConnections {
    fn hold(&self, connection: &TrackSendConnection) {
        let mut held = self.held.lock().unwrap_or_else(|p| p.into_inner());
        held.retain(|(_, weak)| weak.upgrade().is_some_and(|c| c.close_reason().is_none()));
        held.push((connection.peer, connection.connection.weak_handle()));
    }

    /// Close every live Track Send connection to or from `peer`, and return
    /// how many were closed.
    ///
    /// The caller withdraws the authority first: an accepted connection is
    /// listed BEFORE its admission is asked, so one accepted concurrently
    /// with this call is either closed here or refused by admission, never
    /// neither.
    pub fn close_to(&self, peer: &PeerId) -> usize {
        let mut held = self.held.lock().unwrap_or_else(|p| p.into_inner());
        let mut closed = 0;
        held.retain(|(held_peer, weak)| {
            let Some(connection) = weak.upgrade().filter(|c| c.close_reason().is_none()) else {
                return false;
            };
            if held_peer != peer {
                return true;
            }
            connection.close(REFUSED_UNAUTHORIZED.into(), CLOSED_REVOKED);
            closed += 1;
            false
        });
        closed
    }
}

/// The writing half of a Track Send stream.
#[derive(Debug)]
pub struct TrackSendWriter {
    inner: iroh::endpoint::SendStream,
}

impl TrackSendWriter {
    /// Signal that nothing further will be written on this stream.
    pub fn finish(&mut self) -> Result<(), SubstrateError> {
        self.inner.finish().map_err(|err| SubstrateError::TrackSend(err.to_string()))
    }

    /// Wait, at most `limit`, for the peer to have received everything
    /// written and finished on this stream (or to have stopped it, or for
    /// the connection to end).
    ///
    /// `finish` only queues the end of the stream; closing the connection
    /// straight after can race the queued bytes, so a caller about to close
    /// after a final message waits here first. Bounded because a peer that
    /// never acknowledges would otherwise hold the caller forever; running
    /// out of time is not an error, only the end of the wait.
    pub async fn flushed(&mut self, limit: Duration) {
        let _ = tokio::time::timeout(limit, self.inner.stopped()).await;
    }
}

impl AsyncWrite for TrackSendWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.inner), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.inner), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.inner), cx)
    }
}

/// The reading half of a Track Send stream.
#[derive(Debug)]
pub struct TrackSendReader {
    inner: iroh::endpoint::RecvStream,
}

impl AsyncRead for TrackSendReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.inner), cx, buf)
    }
}

/// Where accepted Track Send connections go, and who may open one.
#[derive(Debug, Clone)]
pub(crate) struct TrackSendAccept {
    pub(crate) admission: Arc<dyn crate::PeerAdmission>,
    pub(crate) inbound: mpsc::Sender<TrackSendConnection>,
}

/// The router's handler for [`YADORI_SEND_ALPN`].
#[derive(Debug, Clone)]
pub(crate) struct TrackSendHandler {
    pub(crate) accept: TrackSendAccept,
    pub(crate) open: TrackSendConnections,
}

impl iroh::protocol::ProtocolHandler for TrackSendHandler {
    async fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        let accepted = TrackSendConnection::new(connection.clone());
        let peer = accepted.peer();
        // Listed first and admitted second, so a revocation racing this
        // accept either finds it listed or has already withdrawn what
        // admission reads.
        self.open.hold(&accepted);
        // Authenticated is not authorized, exactly as for sync -- but asked
        // of this protocol's own policy. Refused before the connection is
        // handed to anything.
        if !self.accept.admission.admit(&peer) {
            connection.close(REFUSED_UNAUTHORIZED.into(), b"unauthorized device");
            tracing::debug!(?peer, "refused an inbound Track Send connection");
            return Ok(());
        }
        if self.accept.inbound.send(accepted).await.is_err() {
            connection.close(0u32.into(), b"shutting down");
            return Ok(());
        }
        // Held open for as long as the Track Send side uses it, as the sync
        // handler does.
        connection.closed().await;
        Ok(())
    }
}

/// Dial `address` on [`YADORI_SEND_ALPN`] from `endpoint`.
///
/// The addresses in `address` are hints added to whatever the endpoint's own
/// lookup knows: a Track Send peer need not be a sync peer, so the
/// coordination directory may have nothing for it.
pub(crate) async fn connect(
    endpoint: &iroh::Endpoint,
    open: &TrackSendConnections,
    address: &crate::PeerAddress,
) -> Result<TrackSendConnection, SubstrateError> {
    let id = iroh::EndpointId::from_bytes(address.peer().as_bytes())
        .map_err(|err| SubstrateError::Connect(err.to_string()))?;
    let mut target = iroh::EndpointAddr::new(id);
    for direct in address.direct_addrs() {
        target = target.with_ip_addr(*direct);
    }
    for relay in address.relay_urls() {
        match relay.parse::<iroh::RelayUrl>() {
            Ok(url) => target = target.with_relay_url(url),
            Err(_) => tracing::debug!(%relay, "dropping an unparseable relay URL"),
        }
    }
    let connection = endpoint
        .connect(target, YADORI_SEND_ALPN)
        .await
        .map_err(|err| SubstrateError::Connect(err.to_string()))?;
    let connection = TrackSendConnection::new(connection);
    open.hold(&connection);
    Ok(connection)
}
