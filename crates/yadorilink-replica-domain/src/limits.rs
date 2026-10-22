//! Domain-level bounds the canonical `Change` encoding and its
//! constituent records enforce on untrusted input. These are not
//! implementation details of any one component that happens to also
//! respect them (the local chunker, for instance) -- they are the actual
//! contract a peer's encoded bytes must satisfy to be admitted at all, so
//! this crate owns them.

/// The largest single block a `VersionBlock`/`BlockInfo` may declare.
pub const MAX_BLOCK_SIZE_BYTES: u32 = 16 * 1024 * 1024;

/// The largest number of `Op`s a single `Change` may carry.
pub const MAX_OPS: usize = 1 << 16;

/// The largest number of blocks a single file version may declare.
pub const MAX_BLOCKS: usize = 1 << 20;

/// The largest canonical encoding, in bytes, of a single `FileVersion`. A
/// version travels as one item of a replication batch, so this is bounded by
/// (and must not exceed) that per-item budget; a version over it can never be
/// sent, so it is refused at authoring and at admission rather than admitted
/// and then never delivered.
pub const MAX_ENCODED_VERSION_BYTES: usize = 4 * 1024 * 1024;

/// Bytes one block adds to a version's canonical encoding: a length-prefixed
/// 32-byte hash plus the 4-byte size.
pub const VERSION_BLOCK_ENCODED_BYTES: usize = 4 + 32 + 4;

/// Encoding headroom reserved for everything in a version except its block
/// list (size, mode, mtime, symlink target, extended attributes).
pub const VERSION_META_RESERVE_BYTES: usize = 64 * 1024;

/// The most blocks a regular file may be split into and still be syncable:
/// the largest block list that, with [`VERSION_META_RESERVE_BYTES`] of
/// metadata, stays within [`MAX_ENCODED_VERSION_BYTES`]. Tighter than
/// [`MAX_BLOCKS`], which only bounds untrusted decode allocation.
pub const MAX_SYNCABLE_BLOCKS: usize =
    (MAX_ENCODED_VERSION_BYTES - VERSION_META_RESERVE_BYTES) / VERSION_BLOCK_ENCODED_BYTES;

/// The largest encoded length, in bytes, of a single path.
pub const MAX_PATH_BYTES: usize = 4096;

/// The largest number of `/`-separated segments a single path may have.
pub const MAX_PATH_SEGMENTS: usize = 255;

/// The largest number of extended attributes a single `FileMeta` may
/// carry. Real allow-listed xattr sets are always small (a
/// handful of app-set attributes at most); this is an untrusted-input
/// bound on a peer's encoded bytes, matching `MAX_BLOCKS`'s own
/// reasoning, not a real-world capacity estimate.
pub const MAX_XATTRS: usize = 256;
