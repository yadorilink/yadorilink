//! Opening and accepting a lane: the hello frame that names its group.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::ProtocolError;
use crate::ports::GroupId;
use crate::wire::{self, MAX_GROUP_BYTES};

/// Announce what a freshly opened lane is for.
///
/// A lane stream carries no context of its own. The opener says which
/// protocol version it speaks and which group the lane is about, because the
/// accepting side needs the group in hand before it can decide whether this
/// peer may be told anything about it — and that has to be settled before a
/// fingerprint is computed, not after.
pub async fn open_lane<S: AsyncWrite + Unpin>(
    stream: &mut S,
    group: &GroupId,
) -> Result<(), ProtocolError> {
    write_frame(stream, &wire::encode_hello(group.as_str())?).await?;
    stream.flush().await?;
    Ok(())
}

/// Read what an accepted lane is for.
pub async fn accept_lane<S: AsyncRead + Unpin>(stream: &mut S) -> Result<GroupId, ProtocolError> {
    let Some(body) = read_frame(stream, MAX_GROUP_BYTES + 16).await? else {
        return Err(ProtocolError::NoHello);
    };
    Ok(GroupId(wire::decode_hello(&body)?))
}

// --- framing i/o -----------------------------------------------------------

async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    frame: &[u8],
) -> Result<(), ProtocolError> {
    stream.write_all(frame).await?;
    Ok(())
}

/// Read one length-prefixed frame, or `None` at a clean end of stream.
///
/// The declared length is checked against `max` before anything is allocated:
/// a length is a claim by the peer, not an instruction.
async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    max: usize,
) -> Result<Option<Vec<u8>>, ProtocolError> {
    let mut length = [0u8; 4];
    match stream.read_exact(&mut length).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }

    let declared = u32::from_be_bytes(length) as usize;
    if declared > max {
        return Err(ProtocolError::FrameTooLarge { declared, limit: max });
    }

    let mut body = vec![0u8; declared];
    stream.read_exact(&mut body).await?;
    Ok(Some(body))
}
