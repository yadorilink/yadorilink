//! Block traffic on the substrate's block lane.
//!
//! The block protocol was already transport-agnostic: it speaks
//! [`PeerBlockStream`], a length-prefixed header followed by a raw body, on a
//! stream of its own. Nothing about it assumed the legacy QUIC channel. So
//! moving it onto the reconciliation substrate is a matter of presenting a
//! lane stream through that same port — the protocol above does not change,
//! and does not learn which transport it is on.
//!
//! Its own lane, rather than sharing one, is the whole reason [`Lane::Block`]
//! was reserved: a block body is large and slow, and a service RPC stuck
//! behind one would make its latency a function of transfer size. Two lanes,
//! two independent flow-control domains, one connection.

use yadorilink_peer_session::ports::PeerBlockStream;
use yadorilink_sync_substrate::LaneStream;
use yadorilink_transport::TransportError;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// One block request/response exchange, carried on a block-lane stream.
pub struct LaneBlockStream {
    stream: LaneStream,
}

impl LaneBlockStream {
    pub fn new(stream: LaneStream) -> Self {
        Self { stream }
    }
}

/// A declared length is a claim from a peer, checked against the caller's
/// ceiling before anything is reserved for it — the same rule the bundle
/// codec follows, applied here because this stream is just as untrusted.
async fn read_len(stream: &mut LaneStream, max_len: usize) -> Result<usize, TransportError> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let declared = u32::from_be_bytes(header) as usize;
    if declared > max_len {
        return Err(TransportError::MessageTooLarge(declared, max_len));
    }
    Ok(declared)
}

#[async_trait::async_trait]
impl PeerBlockStream for LaneBlockStream {
    async fn send_message(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        self.stream.write_all(&(payload.len() as u32).to_be_bytes()).await?;
        self.stream.write_all(payload).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn recv_message(&mut self, max_len: usize) -> Result<Vec<u8>, TransportError> {
        let len = read_len(&mut self.stream, max_len).await?;
        let mut payload = vec![0u8; len];
        self.stream.read_exact(&mut payload).await?;
        Ok(payload)
    }

    async fn send_body(&mut self, body: &[u8]) -> Result<(), TransportError> {
        if !body.is_empty() {
            self.stream.write_all(body).await?;
        }
        self.stream.flush().await?;
        // Ending the direction is what tells the far end the body is complete;
        // an empty body is just an immediate end, which is how every
        // non-`Found` response finishes.
        let _ = self.stream.finish();
        Ok(())
    }

    async fn recv_body(&mut self, len: usize) -> Result<Vec<u8>, TransportError> {
        // `len` is the size the response header declared and the caller has
        // already bounded against its own maximum block size, so this does not
        // re-bound it — it must not, or the two ceilings could disagree.
        let mut body = vec![0u8; len];
        self.stream.read_exact(&mut body).await?;
        Ok(body)
    }

    fn finish_send(&mut self) {
        let _ = self.stream.finish();
    }
}
