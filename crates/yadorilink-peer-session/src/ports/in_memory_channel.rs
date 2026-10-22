//! An in-memory pair of block and service stream lanes, for tests that
//! want two real `PeerSyncSession`s talking to each other with no socket in
//! between. This crate's own tests cannot use the real substrate-backed
//! transports (see `SessionTransports`'s doc comment), so the protocol and
//! convergence logic need a transport they can be tested against on their
//! own.
//!
//! Deliberately free of timers, wall-clock reads and randomness: everything
//! here is a bounded queue and a message copy, so a simulated run that uses
//! it is reproducible from its seed alone.

use std::sync::Arc;

use tokio::io::DuplexStream;
use tokio::sync::{mpsc, Mutex};
use yadorilink_transport::block_stream::{read_length_prefixed, write_length_prefixed};
use yadorilink_transport::TransportError;

use super::{
    BlockStreamTransport, PeerBlockStream, PeerServiceStream, ServiceStreamTransport,
    SessionTransports,
};

/// How many opened-but-not-yet-accepted streams one end may queue.
const QUEUE_DEPTH: usize = 64;

/// Buffer capacity of one in-memory block stream's byte pipe.
///
/// A real QUIC stream has flow control, so a writer that gets ahead of its
/// reader eventually blocks; a pipe with a bound reproduces that, and one
/// without would let a test pass that a real stream would deadlock on. The
/// value only has to be small relative to a block and large relative to a
/// header, so the two directions of the exchange each exercise the blocking
/// path at least once for any block worth transferring.
const BLOCK_STREAM_PIPE_BYTES: usize = 64 * 1024;

/// One end of an in-memory link. Obtain a connected pair from
/// [`InMemoryPeerChannel::connected_pair`].
pub struct InMemoryPeerChannel {
    /// The *peer's* queue of block streams this end has opened, and this
    /// end's own queue of streams the peer opened. `Mutex` because the
    /// transport takes `&self` while `mpsc::Receiver::recv` needs `&mut`.
    /// Opening a stream is a handoff; the pipe underneath it is what carries
    /// the bytes.
    outbound_block_streams: mpsc::Sender<InMemoryBlockStream>,
    inbound_block_streams: Mutex<mpsc::Receiver<InMemoryBlockStream>>,
    /// Same shape again, for service RPC streams -- see
    /// `ServiceStreamTransport`'s own doc comment. Nothing in this crate's
    /// own unit tests currently drains `inbound_service_streams` (they
    /// exercise local convergence, not the service RPC lane), but `open`
    /// below still hands the far end to a real queue rather than dropping
    /// it, so a future test that does call a service-RPC method gets a
    /// stream a peer-side accept loop could actually read, not a disguised
    /// failure.
    outbound_service_streams: mpsc::Sender<InMemoryServiceStream>,
    // Held, never read: it keeps the queue `open` sends into alive (see above).
    #[allow(dead_code)]
    inbound_service_streams: Mutex<mpsc::Receiver<InMemoryServiceStream>>,
}

impl InMemoryPeerChannel {
    /// Two ends of one link: what `a` sends, `b` receives, and vice versa.
    pub fn connected_pair() -> (Arc<Self>, Arc<Self>) {
        let (a_streams_tx, a_streams_rx) = mpsc::channel(QUEUE_DEPTH);
        let (b_streams_tx, b_streams_rx) = mpsc::channel(QUEUE_DEPTH);
        let (a_service_tx, a_service_rx) = mpsc::channel(QUEUE_DEPTH);
        let (b_service_tx, b_service_rx) = mpsc::channel(QUEUE_DEPTH);
        (
            Arc::new(Self {
                outbound_block_streams: b_streams_tx,
                inbound_block_streams: Mutex::new(a_streams_rx),
                outbound_service_streams: b_service_tx,
                inbound_service_streams: Mutex::new(a_service_rx),
            }),
            Arc::new(Self {
                outbound_block_streams: a_streams_tx,
                inbound_block_streams: Mutex::new(b_streams_rx),
                outbound_service_streams: a_service_tx,
                inbound_service_streams: Mutex::new(b_service_rx),
            }),
        )
    }
}

/// One in-memory block stream: a byte pipe, framed exactly the way the QUIC
/// one is.
///
/// It reuses the transport's own framing functions rather than
/// reimplementing them, which is the point of having them shared: a test
/// double whose framing has drifted from the wire's proves nothing about
/// the protocol it is standing in for. What it does not reproduce is QUIC's
/// reset-on-drop, so an abandoned stream here reads as a clean end rather
/// than an error -- the exchange treats both as a failed fetch.
pub struct InMemoryBlockStream {
    pipe: DuplexStream,
}

#[async_trait::async_trait]
impl PeerBlockStream for InMemoryBlockStream {
    async fn send_message(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        write_length_prefixed(&mut self.pipe, payload).await
    }

    async fn recv_message(&mut self, max_len: usize) -> Result<Vec<u8>, TransportError> {
        read_length_prefixed(&mut self.pipe, max_len).await
    }

    async fn send_body(&mut self, body: &[u8]) -> Result<(), TransportError> {
        use tokio::io::AsyncWriteExt as _;
        if !body.is_empty() {
            self.pipe.write_all(body).await.map_err(TransportError::Io)?;
        }
        self.pipe.shutdown().await.map_err(TransportError::Io)
    }

    async fn recv_body(&mut self, len: usize) -> Result<Vec<u8>, TransportError> {
        use tokio::io::AsyncReadExt as _;
        let mut body = vec![0u8; len];
        if len > 0 {
            self.pipe.read_exact(&mut body).await.map_err(TransportError::Io)?;
        }
        // Same end-of-stream check the real stream makes, for the same
        // reason: the declared size has to be binding, not advisory.
        let mut extra = [0u8; 1];
        match self.pipe.read(&mut extra).await {
            Ok(0) => Ok(body),
            Ok(_) => Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "peer sent more body bytes than its response header declared",
            ))),
            Err(error) => Err(TransportError::Io(error)),
        }
    }

    fn finish_send(&mut self) {
        // A `DuplexStream` is one object for both directions, so shutting
        // the write half here would close the read half the requester still
        // needs. The FIN this stands in for is an optimization on the wire,
        // not something either side's correctness depends on, so the double
        // does nothing rather than doing something destructive.
    }
}

/// One in-memory service RPC stream: a request written, a response read,
/// same framing as [`InMemoryBlockStream`] and the same reasoning for
/// reusing the transport's own length-prefix functions rather than
/// reimplementing them.
pub struct InMemoryServiceStream {
    pipe: DuplexStream,
}

#[async_trait::async_trait]
impl PeerServiceStream for InMemoryServiceStream {
    async fn send_request(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        write_length_prefixed(&mut self.pipe, payload).await
    }

    async fn recv_message(&mut self, max_len: usize) -> Result<Vec<u8>, TransportError> {
        read_length_prefixed(&mut self.pipe, max_len).await
    }

    async fn send_response(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        write_length_prefixed(&mut self.pipe, payload).await
    }
}

#[async_trait::async_trait]
impl BlockStreamTransport for InMemoryPeerChannel {
    async fn open(&self, _group_id: &str) -> Result<Box<dyn PeerBlockStream>, TransportError> {
        // This in-memory channel carries only one peer's worth of streams
        // to begin with, so there is no group to route on -- unlike the
        // real substrate lane, which multiplexes many groups over one
        // connection.
        let (near, far) = tokio::io::duplex(BLOCK_STREAM_PIPE_BYTES);
        self.outbound_block_streams
            .send(InMemoryBlockStream { pipe: far })
            .await
            .map_err(|_| TransportError::ChannelClosed)?;
        Ok(Box::new(InMemoryBlockStream { pipe: near }))
    }
}

#[async_trait::async_trait]
impl ServiceStreamTransport for InMemoryPeerChannel {
    async fn open(&self, _group_id: &str) -> Result<Box<dyn PeerServiceStream>, TransportError> {
        let (near, far) = tokio::io::duplex(BLOCK_STREAM_PIPE_BYTES);
        self.outbound_service_streams
            .send(InMemoryServiceStream { pipe: far })
            .await
            .map_err(|_| TransportError::ChannelClosed)?;
        Ok(Box::new(InMemoryServiceStream { pipe: near }))
    }
}

/// This crate's own `SessionTransports` fixture: a real block-stream and
/// service-stream port backed by `channel`'s own connected-pair queues (so
/// a stream opened through it really is something the far end could
/// accept).
///
/// `yadorilink-lane-ports`'s `testing::TestPeerNode` is the *real*
/// substrate-backed fixture other crates use, and this crate's own
/// integration tests (`tests/peer_session.rs`) use it too -- but this
/// crate's own `#[cfg(test)]` unit tests cannot: `yadorilink-lane-ports`
/// depends on `yadorilink-peer-session`, so a dev-dependency back from this
/// crate onto it would compile this crate twice under `cargo test --lib`,
/// and the two resulting instances of `PeerBlockStream`/
/// `BlockStreamTransport`/etc. would be distinct types that fail each
/// other's trait bounds. Every unit test in this crate that constructs a
/// `PeerSyncSession` directly (as opposed to `tests/peer_session.rs`'s
/// external integration binary) uses this instead.
///
/// Not a null/deny stub: `blocks`/`service` are real in-memory pipes, so a
/// test that exercises `fetch_block` or a service RPC through a session
/// built this way gets a stream a peer-side accept loop could genuinely read.
pub fn in_memory_transports(channel: &Arc<InMemoryPeerChannel>) -> SessionTransports {
    SessionTransports { blocks: channel.clone(), service: channel.clone() }
}

impl InMemoryPeerChannel {
    /// The next block stream the peer has opened, or `None` once the
    /// channel has closed.
    ///
    /// Not on any port: a `PeerSyncSession` never accepts a block stream
    /// itself (see
    /// `PeerSyncSession::serve_block_stream`'s own doc comment) -- inbound
    /// block traffic arrives on the substrate's block lane in production,
    /// with no in-memory equivalent to that lane. A test that wires two real
    /// sessions through a connected pair and wants one of them to actually
    /// serve blocks calls this directly on the concrete channel and feeds
    /// what it returns to `serve_block_stream` itself, standing in for
    /// `sync_stack.rs`'s `serve_peer_lanes`.
    pub async fn accept_block_stream(&self) -> Option<Box<dyn PeerBlockStream>> {
        let stream = self.inbound_block_streams.lock().await.recv().await?;
        Some(Box::new(stream))
    }
}
