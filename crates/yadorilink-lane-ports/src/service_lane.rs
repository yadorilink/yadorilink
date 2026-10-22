//! Service RPCs on the substrate's service lane.
//!
//! One stream per logical RPC. The alternative — one shared stream, a receive
//! loop, and a request-id map — is the shape the lane classes exist to remove,
//! and rebuilding it here would put it straight back: a slow RPC would delay
//! every other one, and the correlation table would be another thing that can
//! mismatch, leak or grow. A QUIC stream already is the correlation.
//!
//! What rides here is classified by shape, not by which legacy frame used to
//! carry it:
//!
//! ```text
//!   small request / control metadata  →  Service   (this lane)
//!   content bytes                     →  Block
//! ```
//!
//! So a version-present *request* and the answer to it belong here; the
//! objects they name do not.

use yadorilink_peer_session::ports::PeerServiceStream;
use yadorilink_sync_substrate::LaneStream;
use yadorilink_transport::TransportError;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The largest service message either side will read.
///
/// Generous for control metadata and far below anything that belongs on
/// another lane. A payload approaching this is a sign something bulk has been
/// misclassified onto this lane rather than a reason to raise it.
pub const MAX_SERVICE_MESSAGE_BYTES: usize = 1 << 20;

/// One service RPC exchange, carried on a service-lane stream.
pub struct LaneServiceStream {
    stream: LaneStream,
}

impl LaneServiceStream {
    pub fn new(stream: LaneStream) -> Self {
        Self { stream }
    }

    async fn send_and_finish(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        if payload.len() > MAX_SERVICE_MESSAGE_BYTES {
            return Err(TransportError::MessageTooLarge(payload.len(), MAX_SERVICE_MESSAGE_BYTES));
        }
        self.stream.write_all(&(payload.len() as u32).to_be_bytes()).await?;
        self.stream.write_all(payload).await?;
        self.stream.flush().await?;
        // Ending the direction is part of the message: each side sends exactly
        // one, so the far end knows the request or response is complete
        // without a terminator of its own.
        let _ = self.stream.finish();
        Ok(())
    }
}

#[async_trait::async_trait]
impl PeerServiceStream for LaneServiceStream {
    async fn send_request(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        self.send_and_finish(payload).await
    }

    async fn send_response(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        self.send_and_finish(payload).await
    }

    async fn recv_message(&mut self, max_len: usize) -> Result<Vec<u8>, TransportError> {
        // A declared length is a claim from a peer, checked against the
        // caller's ceiling and this lane's own before a byte is reserved.
        let ceiling = max_len.min(MAX_SERVICE_MESSAGE_BYTES);
        let mut header = [0u8; 4];
        self.stream.read_exact(&mut header).await?;
        let declared = u32::from_be_bytes(header) as usize;
        if declared > ceiling {
            return Err(TransportError::MessageTooLarge(declared, ceiling));
        }
        let mut payload = vec![0u8; declared];
        self.stream.read_exact(&mut payload).await?;
        Ok(payload)
    }
}
