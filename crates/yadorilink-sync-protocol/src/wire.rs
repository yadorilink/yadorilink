//! Framing for the lane hello.
//!
//! Every length is checked against a hard bound before a byte is allocated:
//! a declared length is a claim by the peer, never an instruction.

use crate::error::WireError;

/// Bumped if the hello encoding ever changes. A peer speaking a different
/// version fails the handshake rather than silently misreading frames.
pub const PROTOCOL_VERSION: u32 = 4;

pub const MAX_GROUP_BYTES: usize = 512;

// --- handshake -------------------------------------------------------------

/// Encode the opening of a lane: which protocol version, and which group.
///
/// A lane stream carries no context of its own, so the side that opens it has
/// to say what it is for before anything else happens. The receiving side
/// needs the group in hand to decide whether this peer may be told anything
/// about it, which has to be settled before a fingerprint is computed.
pub fn encode_hello(group: &str) -> Result<Vec<u8>, WireError> {
    if group.len() > MAX_GROUP_BYTES {
        return Err(WireError::GroupTooLong { declared: group.len(), limit: MAX_GROUP_BYTES });
    }

    let mut body = Vec::with_capacity(6 + group.len());
    body.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    body.extend_from_slice(&(group.len() as u16).to_be_bytes());
    body.extend_from_slice(group.as_bytes());

    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Decode a hello. A version this node does not speak is refused outright
/// rather than being parsed on the hope that the parts it recognises still
/// mean what they used to.
pub fn decode_hello(body: &[u8]) -> Result<String, WireError> {
    let mut cursor = Cursor::new(body);
    let version = cursor.u32()?;
    if version != PROTOCOL_VERSION {
        return Err(WireError::UnsupportedVersion { theirs: version, ours: PROTOCOL_VERSION });
    }

    let length = cursor.u16()? as usize;
    if length > MAX_GROUP_BYTES {
        return Err(WireError::GroupTooLong { declared: length, limit: MAX_GROUP_BYTES });
    }
    let bytes = cursor.take(length)?;
    if !cursor.is_exhausted() {
        return Err(WireError::TrailingBytes(cursor.remaining()));
    }

    String::from_utf8(bytes.to_vec()).map_err(|_| WireError::MalformedGroupId)
}

pub(crate) struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    pub(crate) fn require(&self, count: usize) -> Result<(), WireError> {
        if self.bytes.len() - self.at < count {
            return Err(WireError::Truncated {
                needed: count,
                available: self.bytes.len() - self.at,
            });
        }
        Ok(())
    }

    pub(crate) fn take(&mut self, count: usize) -> Result<&'a [u8], WireError> {
        self.require(count)?;
        let slice = &self.bytes[self.at..self.at + count];
        self.at += count;
        Ok(slice)
    }

    pub(crate) fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("2 bytes")))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("4 bytes")))
    }

    pub(crate) fn is_exhausted(&self) -> bool {
        self.at == self.bytes.len()
    }

    pub(crate) fn remaining(&self) -> usize {
        self.bytes.len() - self.at
    }
}

#[cfg(test)]
mod tests;
