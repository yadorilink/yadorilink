//! The native-replication protocol's own ALPN on this node's endpoint.
//!
//! Exactly Track Send's shape (`track_send.rs`), for a different purpose:
//! one iroh endpoint, one router, native-replication traffic told apart by its
//! own ALPN ([`YADORI_NATIVE_REPLICATION_ALPN`]), never handed to the sync
//! protocol's handler or vice versa. This crate has zero workspace
//! dependencies (`.config/architecture.toml`), so -- exactly as Track Send's own
//! module doc says of its wire format -- nothing here reads protocol 5's
//! bytes; this module only ever hands a caller above this crate a plain
//! bidirectional-stream connection. Decoding protocol 5 messages and
//! calling native admission is that caller's job (the daemon layer, which
//! depends on both this crate and the domain/storage crates protocol 5 and
//! native admission live in).
//!
//! Its own admission is independent of both the sync protocol's and Track
//! Send's: being one of this device's sync peers says nothing about
//! whether a peer may open a native-replication connection. In this generation
//! it is expected to be configured with the SAME [`PeerAdmission`] policy
//! the sync protocol uses (same peers, same revocation), but that is the
//! caller's choice, not something this module assumes.
//!
//! A native-replication connection has its own lifecycle, independent of the
//! block lane's flow control: a failure here must never close or affect the
//! sync connection to the same peer, and this module enforces nothing about
//! content -- it is exactly as blind to protocol 5's bytes as Track Send is
//! to its own.

use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use crate::error::SubstrateError;
use crate::peer::PeerId;

/// ALPN for the native-replication protocol (protocol 5).
pub const YADORI_NATIVE_REPLICATION_ALPN: &[u8] = b"yadorilink/native-replication/v5";

/// Close code for a remote that authenticated but may not use the
/// native-replication protocol with this device. Same value and meaning as the
/// sync handler's and Track Send's refusal.
const REFUSED_UNAUTHORIZED: u32 = 1;

/// Close reason for a live native-replication connection ended because its
/// device's authority was withdrawn after it was admitted.
const CLOSED_REVOKED: &[u8] = b"device revoked";

/// One authenticated native-replication connection.
///
/// Cheap to clone; clones share the connection.
#[derive(Debug, Clone)]
pub struct NativeReplicationConnection {
    peer: PeerId,
    connection: iroh::endpoint::Connection,
}

impl NativeReplicationConnection {
    fn new(connection: iroh::endpoint::Connection) -> Self {
        Self { peer: PeerId::from_bytes(*connection.remote_id().as_bytes()), connection }
    }

    /// The remote's authenticated identity: the key it proved it holds
    /// during the handshake, never anything it claims afterwards.
    pub fn peer(&self) -> PeerId {
        self.peer
    }

    /// Open a stream as the initiating side.
    pub async fn open_stream(
        &self,
    ) -> Result<(NativeReplicationWriter, NativeReplicationReader), SubstrateError> {
        let (send, recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|err| SubstrateError::NativeReplication(err.to_string()))?;
        Ok((NativeReplicationWriter { inner: send }, NativeReplicationReader { inner: recv }))
    }

    /// Accept the next stream the remote opens. An error means the
    /// connection is gone.
    pub async fn accept_stream(
        &self,
    ) -> Result<(NativeReplicationWriter, NativeReplicationReader), SubstrateError> {
        let (send, recv) = self
            .connection
            .accept_bi()
            .await
            .map_err(|err| SubstrateError::NativeReplication(err.to_string()))?;
        Ok((NativeReplicationWriter { inner: send }, NativeReplicationReader { inner: recv }))
    }

    /// Close the connection with an application close code and reason.
    /// Idempotent.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.connection.close(code.into(), reason);
    }
}

/// Every native-replication connection a node holds, accepted or dialled, so a
/// device whose authority is withdrawn can have the ones it already has
/// closed. Same shape and same discipline as [`crate::TrackSendConnections`].
#[derive(Debug, Clone, Default)]
pub struct NativeReplicationConnections {
    held: Arc<Mutex<Vec<(PeerId, iroh::endpoint::WeakConnectionHandle)>>>,
}

impl NativeReplicationConnections {
    fn hold(&self, connection: &NativeReplicationConnection) {
        let mut held = self.held.lock().unwrap_or_else(|p| p.into_inner());
        held.retain(|(_, weak)| weak.upgrade().is_some_and(|c| c.close_reason().is_none()));
        held.push((connection.peer, connection.connection.weak_handle()));
    }

    /// How many live native-replication connections this node currently holds
    /// to or from `peer`, WITHOUT closing or removing any of them --
    /// unlike [`Self::close_to`], which mutates as it counts. A caller
    /// that wants to observe the count before deciding whether to act
    /// (e.g. asserting a connection is live before a later step that
    /// itself is expected to close it) must use this, not `close_to`,
    /// or the observation itself pre-empts whatever it was checking for.
    pub fn live_count(&self, peer: &PeerId) -> usize {
        let held = self.held.lock().unwrap_or_else(|p| p.into_inner());
        held.iter()
            .filter(|(held_peer, weak)| {
                held_peer == peer && weak.upgrade().is_some_and(|c| c.close_reason().is_none())
            })
            .count()
    }

    /// Close every live native-replication connection to or from `peer`, and
    /// return how many were closed.
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

/// The writing half of a native-replication stream.
#[derive(Debug)]
pub struct NativeReplicationWriter {
    inner: iroh::endpoint::SendStream,
}

impl NativeReplicationWriter {
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), SubstrateError> {
        self.inner
            .write_all(buf)
            .await
            .map_err(|err| SubstrateError::NativeReplication(err.to_string()))
    }

    /// Signal that nothing further will be written on this stream.
    pub fn finish(&mut self) -> Result<(), SubstrateError> {
        self.inner.finish().map_err(|err| SubstrateError::NativeReplication(err.to_string()))
    }

    /// Wait, at most `limit`, for the peer to have received everything
    /// written and finished on this stream (or to have stopped it, or for
    /// the connection to end). Same reason as Track Send's own
    /// `TrackSendWriter::flushed`: `finish` only queues the end of the
    /// stream, so a caller about to close the connection right after a
    /// final message waits here first to avoid racing the queued bytes.
    pub async fn flushed(&mut self, limit: std::time::Duration) {
        let _ = tokio::time::timeout(limit, self.inner.stopped()).await;
    }
}

/// The reading half of a native-replication stream.
#[derive(Debug)]
pub struct NativeReplicationReader {
    inner: iroh::endpoint::RecvStream,
}

impl NativeReplicationReader {
    /// Reads at most `max_len` bytes total (bounded, since this crate must
    /// not trust a remote to ever finish a stream): `Ok(None)` at a clean
    /// end of stream, `Ok(Some(bytes))` otherwise, `Err` on any I/O fault
    /// or on exceeding `max_len` before the stream ends.
    pub async fn read_to_end(&mut self, max_len: usize) -> Result<Vec<u8>, SubstrateError> {
        self.inner
            .read_to_end(max_len)
            .await
            .map_err(|err| SubstrateError::NativeReplication(err.to_string()))
    }
}

/// Where accepted native-replication connections go, and who may open one.
#[derive(Debug, Clone)]
pub(crate) struct NativeReplicationAccept {
    pub(crate) admission: Arc<dyn crate::PeerAdmission>,
    pub(crate) inbound: mpsc::Sender<NativeReplicationConnection>,
}

/// The router's handler for [`YADORI_NATIVE_REPLICATION_ALPN`].
#[derive(Debug, Clone)]
pub(crate) struct NativeReplicationHandler {
    pub(crate) accept: NativeReplicationAccept,
    pub(crate) open: NativeReplicationConnections,
}

impl iroh::protocol::ProtocolHandler for NativeReplicationHandler {
    async fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        let accepted = NativeReplicationConnection::new(connection.clone());
        let peer = accepted.peer();
        self.open.hold(&accepted);
        if !self.accept.admission.admit(&peer) {
            connection.close(REFUSED_UNAUTHORIZED.into(), b"unauthorized device");
            tracing::debug!(?peer, "refused an inbound native-replication connection");
            return Ok(());
        }
        if self.accept.inbound.send(accepted).await.is_err() {
            connection.close(0u32.into(), b"shutting down");
            return Ok(());
        }
        // A native-replication connection's failure must never affect the sync
        // connection to the same peer: held open only for as long as the
        // caller above this crate uses it, exactly as the sync handler and
        // Track Send hold theirs, and closed independently of anything else.
        connection.closed().await;
        Ok(())
    }
}

/// Dial `address` on [`YADORI_NATIVE_REPLICATION_ALPN`] from `endpoint`.
pub(crate) async fn connect(
    endpoint: &iroh::Endpoint,
    open: &NativeReplicationConnections,
    address: &crate::PeerAddress,
) -> Result<NativeReplicationConnection, SubstrateError> {
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
        .connect(target, YADORI_NATIVE_REPLICATION_ALPN)
        .await
        .map_err(|err| SubstrateError::Connect(err.to_string()))?;
    let connection = NativeReplicationConnection::new(connection);
    open.hold(&connection);
    Ok(connection)
}
