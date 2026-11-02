//! The on-disk shape of a segment file.
//!
//! A segment is an append-only sequence of self-describing records after a
//! fixed file header. The persistent index -- not this framing -- is what
//! the normal read path consults, so the framing exists for exactly two
//! jobs and is kept no larger than they require:
//!
//! 1. **Offline repair.** `fsck`/index-rebuild has to be able to recover
//!    every record in a segment from the bytes alone, with no index at all,
//!    which means every record carries its own hash and length and can be
//!    validated independently of its neighbours.
//! 2. **Tail classification after a crash.** Recovery has to distinguish
//!    "a complete record" from "the first bytes of a record that was being
//!    written when the machine went down", without trusting either one.
//!    The header checksum is what makes that decidable: a torn header
//!    fails it, so a half-written record can never be mistaken for a real
//!    one whose payload merely looks wrong.
//!
//! Integrity on the ordinary read path is still the content hash itself --
//! the payload checksum here is a cheap early-out that says *which* of a
//! segment's bytes went bad, which a content-hash mismatch alone cannot.
//!
//! The checksum is XXH3-64 (see [`checksum64`]).

use crate::error::StorageError;

/// `"YLSG"` -- segment file magic, at offset 0.
const SEGMENT_MAGIC: u32 = 0x594c_5347;
/// `"YLBR"` -- block record magic, at the start of every record.
const RECORD_MAGIC: u32 = 0x594c_4252;

/// The only segment layout this build writes or reads. A file stamped with
/// anything else is refused rather than guessed at. Version 2 checksums records with XXH3-64
/// (version 1 used CRC-32), which also made the checksums 8 bytes wide.
pub(crate) const SEGMENT_FORMAT_VERSION: u16 = 2;

/// Bytes reserved at the start of every segment file. `durable_end` for a
/// brand-new segment is exactly this.
pub(crate) const SEGMENT_HEADER_LEN: u64 = 16;

/// Fixed bytes before a record's payload: magic(4) + version(2) + flags(2)
/// + hash(32) + payload_len(4) + header_checksum(8).
pub(crate) const RECORD_HEADER_LEN: usize = 52;
/// Width of a checksum on disk.
const CHECKSUM_LEN: usize = 8;
/// Fixed bytes after a record's payload: payload_checksum(8).
pub(crate) const RECORD_TRAILER_LEN: usize = CHECKSUM_LEN;
/// What one block costs on top of its own bytes.
pub(crate) const RECORD_OVERHEAD: usize = RECORD_HEADER_LEN + RECORD_TRAILER_LEN;

/// Raw (not hex) content hash width. The index keys on these directly
/// rather than on 64-character hex, halving every key it stores and
/// compares.
pub(crate) const RAW_HASH_LEN: usize = 32;

/// The total on-disk size of a record holding `payload_len` bytes.
pub(crate) fn record_len(payload_len: usize) -> u64 {
    (RECORD_OVERHEAD + payload_len) as u64
}

/// Builds the 16-byte header every segment file opens with.
pub(crate) fn encode_segment_header(segment_id: u64) -> [u8; SEGMENT_HEADER_LEN as usize] {
    let mut out = [0u8; SEGMENT_HEADER_LEN as usize];
    out[0..4].copy_from_slice(&SEGMENT_MAGIC.to_le_bytes());
    out[4..6].copy_from_slice(&SEGMENT_FORMAT_VERSION.to_le_bytes());
    // bytes 6..8 reserved, left zero.
    out[8..16].copy_from_slice(&segment_id.to_le_bytes());
    out
}

/// Validates a segment file header and returns the id it claims. A header
/// that does not validate is a corrupt or foreign file, never something to
/// interpret leniently.
pub(crate) fn decode_segment_header(bytes: &[u8]) -> Result<u64, StorageError> {
    if bytes.len() < SEGMENT_HEADER_LEN as usize {
        return Err(StorageError::CorruptStore("segment file shorter than its header".into()));
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().expect("4 bytes"));
    if magic != SEGMENT_MAGIC {
        return Err(StorageError::CorruptStore(format!(
            "segment file magic {magic:#010x} is not a yadorilink segment"
        )));
    }
    let version = u16::from_le_bytes(bytes[4..6].try_into().expect("2 bytes"));
    if version != SEGMENT_FORMAT_VERSION {
        return Err(StorageError::CorruptStore(format!(
            "segment format v{version} is not v{SEGMENT_FORMAT_VERSION}"
        )));
    }
    Ok(u64::from_le_bytes(bytes[8..16].try_into().expect("8 bytes")))
}

/// The layout version a file's first bytes declare, when they are a segment file's header at all
/// (right magic); `None` for anything else. A caller that has to tell "a segment of another layout"
/// from "not a segment" before it decides what may be touched uses this instead of
/// [`decode_segment_header`], which refuses both alike.
pub(crate) fn declared_segment_layout(header: &[u8]) -> Option<u16> {
    if header.len() < SEGMENT_HEADER_LEN as usize {
        return None;
    }
    let magic = u32::from_le_bytes(header[0..4].try_into().expect("4 bytes"));
    if magic != SEGMENT_MAGIC {
        return None;
    }
    Some(u16::from_le_bytes(header[4..6].try_into().expect("2 bytes")))
}

/// Builds a record's fixed header for `hash`/`payload`.
///
/// Separate from the payload on purpose: a record is written as header,
/// payload, trailer, and the payload is the caller's own buffer. Producing
/// the header alone is what lets the write path hand the kernel a pointer
/// to that buffer instead of copying a gigabyte of it into an
/// intermediate one first.
pub(crate) fn frame_header(hash: &[u8; RAW_HASH_LEN], payload_len: u32) -> [u8; RECORD_HEADER_LEN] {
    let mut header = [0u8; RECORD_HEADER_LEN];
    header[0..4].copy_from_slice(&RECORD_MAGIC.to_le_bytes());
    header[4..6].copy_from_slice(&SEGMENT_FORMAT_VERSION.to_le_bytes());
    // bytes 6..8 are flags, left zero.
    header[8..8 + RAW_HASH_LEN].copy_from_slice(hash);
    header[40..44].copy_from_slice(&payload_len.to_le_bytes());
    let header_checksum = checksum64(&header[..RECORD_HEADER_LEN - CHECKSUM_LEN]);
    header[RECORD_HEADER_LEN - CHECKSUM_LEN..].copy_from_slice(&header_checksum.to_le_bytes());
    header
}

/// The checksum written after a record's payload.
pub(crate) fn frame_trailer(payload: &[u8]) -> [u8; RECORD_TRAILER_LEN] {
    checksum64(payload).to_le_bytes()
}

/// Appends one complete record for `hash`/`payload` to `out` -- the
/// contiguous form, for callers that want the bytes in one buffer.
#[cfg(test)]
pub(crate) fn encode_record(out: &mut Vec<u8>, hash: &[u8; RAW_HASH_LEN], payload: &[u8]) {
    out.extend_from_slice(&frame_header(hash, payload.len() as u32));
    out.extend_from_slice(payload);
    out.extend_from_slice(&frame_trailer(payload));
}

/// What a record's header says about it, once the header itself has been
/// proven intact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecordHeader {
    pub(crate) hash: [u8; RAW_HASH_LEN],
    pub(crate) payload_len: u32,
}

impl RecordHeader {
    /// The whole record's on-disk size, header and trailer included.
    pub(crate) fn record_len(&self) -> u64 {
        record_len(self.payload_len as usize)
    }
}

/// Why a record header could not be accepted. Recovery treats every
/// variant the same way (the segment's durable content ends before this
/// record) but reports them apart, because "the tail was being written"
/// and "a sealed record's header rotted" are different incidents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeaderReject {
    /// Fewer bytes remain in the file than a header needs.
    Truncated,
    /// The record magic is absent -- unwritten (zero) or foreign bytes.
    BadMagic,
    /// Magic matched but the header's own checksum did not: a torn header.
    BadChecksum,
    /// A payload length that cannot fit in what remains of the file.
    LengthOverrunsFile,
}

/// Reads the record header at the start of `bytes`, given that `remaining`
/// bytes (header included) are left in the file. Never trusts
/// `payload_len` before the header checksum has validated it, which is
/// what stops a torn header from steering recovery into an arbitrary
/// offset.
pub(crate) fn decode_record_header(
    bytes: &[u8],
    remaining: u64,
) -> Result<RecordHeader, HeaderReject> {
    if bytes.len() < RECORD_HEADER_LEN || remaining < RECORD_HEADER_LEN as u64 {
        return Err(HeaderReject::Truncated);
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().expect("4 bytes"));
    if magic != RECORD_MAGIC {
        return Err(HeaderReject::BadMagic);
    }
    let stored_checksum = u64::from_le_bytes(
        bytes[RECORD_HEADER_LEN - CHECKSUM_LEN..RECORD_HEADER_LEN].try_into().expect("8 bytes"),
    );
    if checksum64(&bytes[..RECORD_HEADER_LEN - CHECKSUM_LEN]) != stored_checksum {
        return Err(HeaderReject::BadChecksum);
    }
    let mut hash = [0u8; RAW_HASH_LEN];
    hash.copy_from_slice(&bytes[8..8 + RAW_HASH_LEN]);
    let payload_len = u32::from_le_bytes(bytes[40..44].try_into().expect("4 bytes"));
    let header = RecordHeader { hash, payload_len };
    if header.record_len() > remaining {
        return Err(HeaderReject::LengthOverrunsFile);
    }
    Ok(header)
}

/// Whether `payload` matches the trailer checksum that followed it.
pub(crate) fn payload_checksum_matches(payload: &[u8], trailer: &[u8]) -> bool {
    trailer.len() == RECORD_TRAILER_LEN
        && checksum64(payload) == u64::from_le_bytes(trailer.try_into().expect("8 bytes"))
}

/// XXH3-64 (seed 0, no secret), as stored in every record header and trailer.
///
/// This is `xxhash-rust`'s pure-Rust XXH3, which uses the CPU's vector instructions where they are
/// available and gives the same value everywhere. It replaced CRC-32 (itself a replacement for a
/// hand-written table walk) because it is several times faster per byte on the sizes blocks come
/// in, every block passes through it three times (the write, the read-back that verifies the
/// commit, and each read), and a 64-bit check is a much smaller chance of passing damaged bytes
/// than a 32-bit one. It is not a cryptographic hash and is not used as one: it frames records and
/// finds damage by the medium. Content integrity is the SHA-256 content hash, and a record that is
/// consistent with itself but whose bytes are not the block it names is found only where that hash
/// is checked.
pub(crate) fn checksum64(data: &[u8]) -> u64 {
    xxhash_rust::xxh3::xxh3_64(data)
}

#[cfg(test)]
mod tests;
