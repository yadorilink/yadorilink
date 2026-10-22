//! Canonical encoding primitives shared by every domain type with a
//! hand-specified byte layout (`FileVersion`, and — once it moves here too
//! — `Change`). The byte layout must be reproducible on any device and any
//! future version, because a `FileVersion`/`Change`'s identity *is* the
//! SHA-256 of its canonical encoding; this is why these primitives are
//! hand-written rather than derived from serde or protobuf, whose output is
//! not canonical across implementations.

/// Rejection reasons for the pure model/crypto layer. Callers that admit
/// changes (the peer session) decide how a rejection surfaces and log it.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChangeError {
    #[error("change encoding is malformed: {0}")]
    Encoding(String),
    /// The domain tag's identifying prefix matched but its trailing
    /// generation byte did not: these are well-formed bytes from a
    /// different encoding generation, not damage. Kept distinct from
    /// [`ChangeError::Encoding`] precisely because the two call for
    /// opposite responses — a generation mismatch points at a peer or a
    /// stored row this build does not speak, while an encoding error points
    /// at corruption. There is no compatibility path: a mismatched
    /// generation is refused outright, never reinterpreted, because every
    /// field after the tag would be read at the wrong offset.
    #[error("change encoding generation {theirs} is not this build's generation {ours}")]
    UnsupportedGeneration { theirs: u8, ours: u8 },
    #[error("change hash does not match its encoded bytes")]
    HashMismatch,
    #[error("file version block sizes do not sum to the declared total size")]
    BlockSizeMismatch,
    /// The version's canonical encoding is larger than one replication item
    /// can carry, so it could never be delivered to a peer.
    #[error("file version too large to sync: encoded size {encoded_bytes} exceeds {max_bytes}")]
    VersionTooLarge { encoded_bytes: usize, max_bytes: usize },
    #[error("structurally invalid change or file version: {0}")]
    Malformed(String),
    #[error("change signature does not verify against the claimed device key")]
    BadSignature,
    #[error("device is not authorized to write to this group")]
    Unauthorized,
    #[error("signing key material is invalid")]
    InvalidKey,
}

pub fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}
pub fn put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}
pub fn put_i64(buf: &mut Vec<u8>, v: i64) {
    // Two's-complement big-endian — identical to the `u64` layout of the
    // same bit pattern, so a negative pre-epoch mtime is still deterministic.
    buf.extend_from_slice(&v.to_be_bytes());
}
pub fn put_len_bytes(buf: &mut Vec<u8>, b: &[u8]) {
    put_u32(buf, b.len() as u32);
    buf.extend_from_slice(b);
}
pub fn put_str(buf: &mut Vec<u8>, s: &str) {
    put_len_bytes(buf, s.as_bytes());
}

/// A forward-only cursor over a canonical encoding. Every read is bounds
/// checked, so a truncated or oversized length prefix is a clean
/// `ChangeError::Encoding` rather than a panic.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], ChangeError> {
        if self.remaining() < n {
            return Err(ChangeError::Encoding(format!(
                "expected {n} more bytes, {} remaining",
                self.remaining()
            )));
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }
    pub fn u32(&mut self) -> Result<u32, ChangeError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Result<u64, ChangeError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn i64(&mut self) -> Result<i64, ChangeError> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn u8(&mut self) -> Result<u8, ChangeError> {
        Ok(self.take(1)?[0])
    }
    pub fn len_bytes(&mut self) -> Result<Vec<u8>, ChangeError> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    pub fn string(&mut self) -> Result<String, ChangeError> {
        let bytes = self.len_bytes()?;
        String::from_utf8(bytes).map_err(|e| ChangeError::Encoding(e.to_string()))
    }
    pub fn array16(&mut self) -> Result<[u8; 16], ChangeError> {
        Ok(self.take(16)?.try_into().unwrap())
    }
    pub fn array32(&mut self) -> Result<[u8; 32], ChangeError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    /// Reads a `u32` collection count and rejects it before it can size an
    /// allocation: it must not exceed `max`, nor the number of entries the
    /// remaining bytes could possibly encode (each entry is at least
    /// `min_entry_size` bytes). This makes a following `with_capacity(count)`
    /// safe against a hostile length prefix.
    pub fn bounded_count(
        &mut self,
        min_entry_size: usize,
        max: usize,
    ) -> Result<usize, ChangeError> {
        let count = self.u32()? as usize;
        if count > max {
            return Err(ChangeError::Malformed(format!("count {count} exceeds bound {max}")));
        }
        if min_entry_size > 0 && count > self.remaining() / min_entry_size {
            return Err(ChangeError::Encoding(format!(
                "count {count} exceeds the {} entries the remaining bytes can hold",
                self.remaining() / min_entry_size
            )));
        }
        Ok(count)
    }
    pub fn expect_end(&self) -> Result<(), ChangeError> {
        if self.remaining() != 0 {
            return Err(ChangeError::Encoding(format!(
                "{} trailing bytes after change",
                self.remaining()
            )));
        }
        Ok(())
    }
}
