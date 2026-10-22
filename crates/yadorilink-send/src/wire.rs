//! Track Send's own stream framing: length-prefixed protobuf messages on a
//! bidirectional stream of a Track Send connection, using the exact same generic length-prefix
//! helpers (`write_length_prefixed`/`read_length_prefixed`) the sync
//! protocol's own `yadorilink_transport::block_stream` already exports for
//! this -- reused directly rather than re-implemented, since they operate
//! on any `AsyncRead`/`AsyncWrite` and carry no sync-specific framing of
//! their own.

use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};
use yadorilink_transport::block_stream::{read_length_prefixed, write_length_prefixed};

use crate::error::Result;

/// Ceiling for one `SendEnvelope`/`SendManifestAck`/`ChunkStreamMessage`
/// read -- generous enough for a manifest describing thousands of files
/// (each entry carries one SHA-256 hash per chunk), unlike the sync
/// protocol's small 64 KiB control-header ceiling
/// (`yadorilink_transport::MAX_BLOCK_STREAM_HEADER_BYTES`), which a large
/// directory's manifest would blow through.
pub const MAX_SEND_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

pub async fn write_message<W: AsyncWrite + Unpin, M: Message>(
    writer: &mut W,
    message: &M,
) -> Result<()> {
    let encoded = message.encode_to_vec();
    write_length_prefixed(writer, &encoded).await?;
    Ok(())
}

pub async fn read_message<R: AsyncRead + Unpin, M: Message + Default>(reader: &mut R) -> Result<M> {
    let bytes = read_length_prefixed(reader, MAX_SEND_MESSAGE_BYTES).await?;
    Ok(M::decode(bytes.as_slice())?)
}
