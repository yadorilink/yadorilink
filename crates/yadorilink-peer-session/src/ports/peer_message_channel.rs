//! The transport surface `PeerSyncSession` (`peer_session.rs`) needs to
//! reach one peer: block streams and service RPC streams, bundled in
//! [`SessionTransports`]. There is no message channel: everything a session
//! exchanges with its peer rides one of these streams.

use std::sync::Arc;

use yadorilink_transport::TransportError;

/// One block request's stream, from whichever side is driving it.
///
/// Deliberately narrow: two length-prefixed header messages and one raw
/// body, which is the entire block exchange. It is not a general byte-pipe
/// abstraction, because a general byte pipe would invite protocols that the
/// framing bound and the declared-length check below could not police.
#[async_trait::async_trait]
pub trait PeerBlockStream: Send {
    /// Writes one length-prefixed header message.
    async fn send_message(&mut self, payload: &[u8]) -> Result<(), TransportError>;

    /// Reads one length-prefixed header message, refusing a declared length
    /// above `max_len` before allocating for it.
    async fn recv_message(&mut self, max_len: usize) -> Result<Vec<u8>, TransportError>;

    /// Writes the raw body bytes and ends this direction of the stream. An
    /// empty body just ends it, which is how every non-`Found` response
    /// finishes.
    async fn send_body(&mut self, body: &[u8]) -> Result<(), TransportError>;

    /// Reads exactly `len` raw body bytes, where `len` is the size the
    /// response header declared and the caller has already bounded against
    /// its own maximum block size.
    async fn recv_body(&mut self, len: usize) -> Result<Vec<u8>, TransportError>;

    /// Ends this side's sending direction with nothing further to send --
    /// what the requester does immediately after its header.
    fn finish_send(&mut self);
}

/// One service RPC: a request written, a response read, the stream done.
///
/// Deliberately not a channel with a receive loop behind it. A QUIC stream is
/// already the correlation between a request and its response, so there is no
/// request id to allocate, no pending map to hold it in, and no way for two
/// RPCs to be matched to each other's answers. A slow RPC delays only itself.
#[async_trait::async_trait]
pub trait PeerServiceStream: Send {
    /// Writes one length-prefixed message and ends this direction — a service
    /// request is a single message, so nothing further is ever sent.
    async fn send_request(&mut self, payload: &[u8]) -> Result<(), TransportError>;

    /// Reads one length-prefixed message, refusing a declared length above
    /// `max_len` before allocating for it.
    async fn recv_message(&mut self, max_len: usize) -> Result<Vec<u8>, TransportError>;

    /// Writes one length-prefixed message and ends this direction — the
    /// responder's single answer.
    async fn send_response(&mut self, payload: &[u8]) -> Result<(), TransportError>;
}

/// Where this session's service RPC streams come from.
///
/// Peer-bound like [`BlockStreamTransport`], for the same reason: the caller
/// cannot pass the wrong peer because it passes none.
#[async_trait::async_trait]
pub trait ServiceStreamTransport: Send + Sync {
    /// `group_id` names the group the stream's hello declares, which is what
    /// the far end authorizes against. It is a parameter rather than
    /// something the transport remembers because one session can share
    /// several groups with a peer, and each RPC belongs to exactly one.
    async fn open(&self, group_id: &str) -> Result<Box<dyn PeerServiceStream>, TransportError>;
}

/// Where this session's block streams come from.
///
/// Block traffic rides the reconciliation substrate's block lane, and this
/// is the seam (see `SessionTransports`'s own doc comment).
///
/// Bound to one peer, like the session that holds it, so there is no peer
/// argument to get wrong.
#[async_trait::async_trait]
pub trait BlockStreamTransport: Send + Sync {
    /// See [`ServiceStreamTransport::open`] for why the group is a parameter.
    async fn open(&self, group_id: &str) -> Result<Box<dyn PeerBlockStream>, TransportError>;
}

/// Everything a `PeerSyncSession` needs to reach its peer: where its block
/// and service RPC streams come from. A REQUIRED constructor parameter (see
/// `PeerSyncSession::over_substrate`'s own doc comment) -- there is no
/// path meaning "no transport wired yet" or "fall back to something else",
/// because a session that could exist without a real way to reach its peer
/// is exactly the state this generation's cutover removes. Every field is
/// therefore a live capability, never an `Option`: a caller with nothing
/// real to wire (this crate's own unit tests that never exercise a
/// transport at all) must still pass something that actually implements the
/// port -- see `crate::ports::in_memory_channel`'s in-memory pair for the
/// one this crate's own tests use, since they cannot depend on
/// `yadorilink-lane-ports`'s real substrate-backed fixture (that crate
/// depends on this one, so a dev-dependency back would compile this crate
/// twice under `cargo test --lib` and produce two incompatible instances of
/// every port type here -- a classic dev-dependency cycle, not a reason to
/// make this `Option`-typed).
#[derive(Clone)]
pub struct SessionTransports {
    pub blocks: Arc<dyn BlockStreamTransport>,
    pub service: Arc<dyn ServiceStreamTransport>,
}
