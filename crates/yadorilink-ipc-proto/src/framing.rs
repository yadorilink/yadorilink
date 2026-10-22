//! Current-only length-prefixed protobuf framing, shared by local non-gRPC
//! channels in the project (for example the daemon control socket).
//!
//! YadoriLink is not released yet, so development-build wire compatibility is
//! deliberately not preserved. Every frame starts with an explicit magic /
//! framing-generation marker. Bytes emitted by a pre-marker build are rejected
//! before protobuf decoding instead of being interpreted through unknown-field
//! or zero-default compatibility behavior.

use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const FRAME_MAGIC: [u8; 8] = *b"YDLK\0\0\0\x01";

/// The largest protobuf body one frame may carry. Public so a message
/// builder can size its own output against the real limit instead of a
/// guess -- see `RewindPreviewResponse`'s listing budget for the case that
/// needs it.
pub const MAX_FRAME_LEN: u32 = 1024 * 1024;

/// Refuses to emit a frame the reader below would reject anyway.
///
/// The limit was previously enforced on read only, so a writer could emit
/// an oversized frame and the failure surfaced at the far end as an opaque
/// "frame too large" on a message the reader could no longer identify.
/// Checked before any byte is written, so the stream is left clean and the
/// caller can respond with something smaller instead (the control socket
/// does exactly that).
pub async fn write_message<T: Message>(
    stream: &mut (impl AsyncWrite + Unpin),
    msg: &T,
) -> std::io::Result<()> {
    let body = msg.encode_to_vec();
    if body.len() > MAX_FRAME_LEN as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "refusing to write an oversized frame: {} bytes exceeds {MAX_FRAME_LEN}",
                body.len()
            ),
        ));
    }
    stream.write_all(&FRAME_MAGIC).await?;
    stream.write_all(&(body.len() as u32).to_be_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await
}

/// Returns `Ok(None)` on a clean EOF between frames.
pub async fn read_message<T: Message + Default>(
    stream: &mut (impl AsyncRead + Unpin),
) -> std::io::Result<Option<T>> {
    let mut magic = [0u8; FRAME_MAGIC.len()];
    match stream.read_exact(&mut magic).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    if magic != FRAME_MAGIC {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported YadoriLink framing generation",
        ));
    }

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame too large: {len} bytes"),
        ));
    }
    let mut body = vec![0u8; len as usize];
    stream.read_exact(&mut body).await?;
    T::decode(body.as_slice())
        .map(Some)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests;
