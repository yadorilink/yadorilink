//! Length framing for the peer protocol's block and service lanes.
//!
//! A block request is one bidirectional lane stream:
//!
//! ```text
//! open lane
//!   requester -> length-prefixed BlockRequestHeader, FIN
//!   responder -> length-prefixed BlockResponseHeader
//!   responder -> raw body bytes (only when the header says Found), FIN
//! ```
//!
//! The two headers are length-prefixed with a `u32` big-endian prefix,
//! checked against a ceiling before anything is allocated. The body is not
//! framed at all: its length is declared in the response header the receiver
//! has already read, so the receiver knows exactly how many bytes to expect
//! and reads exactly that many. FIN is what makes an abandoned or truncated
//! response observable as an error rather than as a hang.
//!
//! Every stream type that carries this protocol uses the helpers here, so
//! there is one implementation of the framing rather than one per transport.

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::error::TransportError;

/// Bytes of length prefix in front of each header message.
const LENGTH_PREFIX_BYTES: usize = 4;

/// The largest header message either direction will send or accept.
///
/// Both headers are small and bounded by construction: a folder group id, a
/// path (itself capped at 4 KiB by the domain's own `MAX_PATH_BYTES`), a
/// 32-byte hash, and a handful of scalars. 64 KiB is far above anything
/// legitimate while still being a bound a hostile peer cannot turn four
/// bytes into a large allocation with.
pub const MAX_BLOCK_STREAM_HEADER_BYTES: usize = 64 * 1024;

/// The largest block body this device will read off a stream.
///
/// Restated here rather than imported from the domain crate that owns it
/// (`yadorilink_replica_domain::limits::MAX_BLOCK_SIZE_BYTES`): the constant
/// belongs to a crate that depends on this one, and the dependency must not
/// be inverted just to hold a number.
///
/// This is a backstop, not the real check. The caller knows the exact size
/// the response header declared and passes it in, and it also knows what
/// its own protocol considers a legal block; this ceiling exists so that a
/// caller which ever forgets to bound the declared size cannot turn a
/// peer's claim into an unbounded allocation here.
pub const MAX_BLOCK_STREAM_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Writes `payload` behind a `u32` big-endian length prefix.
///
/// Shared rather than reimplemented per stream type: the lane streams and
/// the in-memory channel the sync session's own tests use speak this same
/// framing, and a second copy of it is a second thing that can drift from
/// the one on the wire.
pub async fn write_length_prefixed<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<(), TransportError> {
    let Ok(length) = u32::try_from(payload.len()) else {
        return Err(TransportError::MessageTooLarge(payload.len(), u32::MAX as usize));
    };
    // One write for prefix and body together: two writes would let a
    // header reach the peer
    // arbitrarily long before its body, which is the state a reader would
    // otherwise have to hold an allocation open across.
    let mut framed = Vec::with_capacity(LENGTH_PREFIX_BYTES + payload.len());
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(payload);
    write_raw(writer, &framed).await
}

/// Writes every byte of `bytes`, as a `TransportError` rather than an
/// `io::Error` so every path in this module reports failures the same way.
async fn write_raw<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
) -> Result<(), TransportError> {
    writer.write_all(bytes).await.map_err(TransportError::Io)
}

/// Reads exactly `len` bytes, or reports the stream ending early.
async fn read_raw<R: AsyncRead + Unpin>(
    reader: &mut R,
    len: usize,
) -> Result<Vec<u8>, TransportError> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut buffer = vec![0u8; len];
    reader.read_exact(&mut buffer).await.map_err(TransportError::Io)?;
    Ok(buffer)
}

/// Reads one `u32` big-endian length-prefixed message, refusing a declared
/// length above `max_len` *before* allocating for it.
pub async fn read_length_prefixed<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_len: usize,
) -> Result<Vec<u8>, TransportError> {
    let mut length = [0u8; LENGTH_PREFIX_BYTES];
    reader.read_exact(&mut length).await.map_err(TransportError::Io)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > max_len {
        return Err(TransportError::MessageTooLarge(length, max_len));
    }
    read_raw(reader, length).await
}

#[cfg(test)]
mod tests;
