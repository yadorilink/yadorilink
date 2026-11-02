//! File and file-version records -- the projected and content-addressed
//! representations of one path's content and metadata.

use sha2::{Digest, Sha256};

use crate::codec::{put_i64, put_len_bytes, put_u32, ChangeError, Reader};
use crate::ids::{BlockHash, VersionHash};
use crate::limits::{
    MAX_BLOCKS, MAX_BLOCK_SIZE_BYTES, MAX_ENCODED_VERSION_BYTES, VERSION_BLOCK_ENCODED_BYTES,
};

/// Domain tag of [`FileVersion::content_identity`], distinct from the version
/// tag so an identity can never equal a version hash.
const CONTENT_DOMAIN_TAG: &[u8; 8] = b"YLNKcnt\x01";

/// Domain tag for a `FileVersion`'s canonical encoding. Version 2 carries a
/// per-block size alongside each block hash, so v1 and v2 encodings of the
/// same content are distinct byte strings and distinct hashes. Version 3
/// replaced the single owner-exec bit with the full `unix_mode` permission
/// word (see `FileMeta::unix_mode`), so v2 and v3 encodings of otherwise
/// identical metadata are also distinct. Version 4 added `xattrs`, so v3
/// and v4 encodings of otherwise identical metadata are also distinct. Version 5 replaced the permission
/// word by the execute flag (`FileMeta::exec`) and dropped `xattrs`: neither extended attributes nor the
/// permission bits other than execute are replicated.
const VERSION_DOMAIN_TAG: &[u8; 8] = b"YLNKver\x05";

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockInfo {
    pub hash: Vec<u8>,
    pub offset: u64,
    pub size: u32,
}

fn unknown_persisted_enum(kind: &str, value: &str) -> ! {
    panic!("corrupt local state: unknown persisted {kind} value {value:?}")
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RecordKind {
    #[default]
    File,
    Directory,
    Symlink,
}

impl RecordKind {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
        }
    }

    pub fn from_db_str(value: &str) -> Self {
        match value {
            "file" => Self::File,
            "directory" => Self::Directory,
            "symlink" => Self::Symlink,
            other => unknown_persisted_enum("record kind", other),
        }
    }
}

/// Current projected content state for one path.
///
/// Causality is intentionally absent: it is represented by the authoring change
/// hash, never by per-file counters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRecord {
    pub path: String,
    pub size: u64,
    pub mtime_unix_nanos: i64,
    pub blocks: Vec<BlockInfo>,
    pub deleted: bool,
}

/// Per-file metadata carried by a `FileVersion` — everything that is part of
/// a file's identity beyond its block content. `mtime` participates in
/// version identity (a metadata-only touch is a distinct version) but never
/// in causality: causality is exclusively the recorded delta ancestry, and the deterministic
/// tie-break among concurrent changes uses `lamport`, never wall-clock.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FileMeta {
    pub mtime_unix_nanos: i64,
    /// Whether the file is executable: the only part of the permission model this sync tool replicates.
    /// A platform that cannot express it (Windows, iOS) authors `false` for what it creates and carries the
    /// previous version's value over when it edits a file; a receiver gives the file the mode its own
    /// environment gives a new file and adds `x` where this is set. Always `false` for a directory or a
    /// symlink (the encoder writes it, the decoder and `validate_structure` refuse anything else).
    pub exec: bool,
    /// The symlink's raw, unresolved target, as the *exact* bytes the
    /// platform's own symlink target representation holds — never lossily
    /// converted to/from UTF-8. On Unix this is the target's raw OS bytes
    /// (a symlink target has no UTF-8 requirement there). On Windows this is
    /// the target's UTF-16 code units serialized little-endian, matching
    /// `fs_identity`'s own `target_to_bytes` — the same representation that
    /// already has to survive an unpaired surrogate, which is valid in an
    /// `OsString` there but not valid UTF-8 or UTF-16. `None` for anything
    /// but a symlink. See `Change::encode_into`/`decode` for why the
    /// canonical encoding stores this as a raw length-prefixed byte string
    /// rather than a string field.
    pub symlink_target: Option<Vec<u8>>,
    pub record_kind: RecordKind,
}

/// One block of a file: its content hash and its exact byte length. The size
/// is load-bearing under content-defined chunking — block boundaries are not
/// recoverable from hashes alone — so a receiver can lay out block offsets
/// (prefix sums of these sizes) and validate each fetched block against its
/// declared length. The sum of a version's block sizes must equal the
/// version's total `size`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct VersionBlock {
    pub hash: BlockHash,
    pub size: u32,
}

/// A content-addressed description of one file's bytes plus metadata. Its
/// `version_hash` is the SHA-256 of the canonical encoding of everything
/// *else* in this struct — derived, never itself part of the encoding.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FileVersion {
    pub version_hash: VersionHash,
    pub blocks: Vec<VersionBlock>,
    pub size: u64,
    pub meta: FileMeta,
}

fn record_kind_byte(kind: RecordKind) -> u8 {
    match kind {
        RecordKind::File => 0,
        RecordKind::Directory => 1,
        RecordKind::Symlink => 2,
    }
}
fn record_kind_from_byte(b: u8) -> Result<RecordKind, ChangeError> {
    match b {
        0 => Ok(RecordKind::File),
        1 => Ok(RecordKind::Directory),
        2 => Ok(RecordKind::Symlink),
        other => Err(ChangeError::Encoding(format!("unknown record kind {other}"))),
    }
}

impl FileMeta {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.push(record_kind_byte(self.record_kind));
        buf.push(u8::from(self.exec));
        put_i64(buf, self.mtime_unix_nanos);
        // Raw length-prefixed bytes, not a string put — a symlink target is
        // not required to be valid UTF-8 (see `FileMeta::symlink_target`'s
        // doc), and this canonical encoding must have a representation for
        // every byte string a real target can be, not just ones that happen
        // to be valid UTF-8.
        match &self.symlink_target {
            None => buf.push(0),
            Some(target) => {
                buf.push(1);
                put_len_bytes(buf, target);
            }
        }
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ChangeError> {
        let record_kind = record_kind_from_byte(r.u8()?)?;
        let exec = match r.u8()? {
            0 => false,
            1 => true,
            other => return Err(ChangeError::Encoding(format!("bad exec flag {other}"))),
        };
        let mtime_unix_nanos = r.i64()?;
        let symlink_target = match r.u8()? {
            0 => None,
            1 => Some(r.len_bytes()?),
            other => return Err(ChangeError::Encoding(format!("bad symlink flag {other}"))),
        };
        Ok(FileMeta { record_kind, exec, mtime_unix_nanos, symlink_target })
    }
}

/// What a stored block list must satisfy whatever the record kind is: at most `MAX_BLOCKS` blocks,
/// none of zero length or over `MAX_BLOCK_SIZE_BYTES`, and, when there are blocks, sizes that add
/// up to the file size. An empty list passes (a directory, a symlink, an empty file); the rules that
/// depend on the kind stay in `FileVersion::validate_structure`.
///
/// Run on every row written to the ledger and by the audit that re-reads stored rows, so a row that
/// fails is refused at commit and a row damaged afterwards is found.
///
/// # Errors
/// [`ChangeError::Malformed`] for a count or a block out of bounds, [`ChangeError::BlockSizeMismatch`]
/// when the sizes do not add up.
pub fn check_block_list(size: u64, blocks: &[BlockInfo]) -> Result<(), ChangeError> {
    check_block_sizes(size, blocks.len(), blocks.iter().map(|b| b.size))
}

/// [`check_block_list`] over the block sizes alone, so a version's own block type shares it.
///
/// # Errors
/// As [`check_block_list`].
pub fn check_block_sizes(
    size: u64,
    count: usize,
    block_sizes: impl Iterator<Item = u32>,
) -> Result<(), ChangeError> {
    if count > MAX_BLOCKS {
        return Err(ChangeError::Malformed(format!("block count {count} exceeds {MAX_BLOCKS}")));
    }
    let mut sum: u64 = 0;
    for block_size in block_sizes {
        if block_size == 0 {
            return Err(ChangeError::Malformed("zero-length block".into()));
        }
        if block_size > MAX_BLOCK_SIZE_BYTES {
            return Err(ChangeError::Malformed(format!(
                "block size {block_size} exceeds {MAX_BLOCK_SIZE_BYTES}"
            )));
        }
        sum += u64::from(block_size);
    }
    if count > 0 && sum != size {
        return Err(ChangeError::BlockSizeMismatch);
    }
    Ok(())
}

impl FileVersion {
    /// Builds a version from its parts and fills in the derived
    /// `version_hash` by hashing the canonical encoding of everything else.
    pub fn new(blocks: Vec<VersionBlock>, size: u64, meta: FileMeta) -> Self {
        let mut v = FileVersion { version_hash: VersionHash([0u8; 32]), blocks, size, meta };
        v.version_hash = v.compute_hash();
        v
    }

    /// The canonical version of a directory: no blocks, size 0, mtime 0, no symlink target, not
    /// executable. A directory's mode is not replicated at all, so every directory has this one version.
    pub fn directory() -> FileVersion {
        let meta = FileMeta {
            mtime_unix_nanos: 0,
            exec: false,
            symlink_target: None,
            record_kind: RecordKind::Directory,
        };
        FileVersion::new(Vec::new(), 0, meta)
    }

    /// Structural validation of a `FileVersion`'s shape: the block layout,
    /// and its `record_kind`/`symlink_target` consistency.
    ///
    /// Block layout -- bounded block count always; then, for a regular
    /// file, every block is non-empty and within the chunker's ceiling,
    /// the block list is empty iff the file is empty, and the per-block
    /// sizes sum to the declared total. A symlink or directory version
    /// carries no content blocks — a symlink's `size` is metadata (its
    /// on-disk length), not a sum of block sizes, and a directory's is
    /// always 0 — so only the "no blocks" invariant applies to the block
    /// list. Content hashes are validated
    /// elsewhere (block fetch); this is the size/shape contract a
    /// receiver relies on to derive offsets safely.
    ///
    /// `record_kind`/`symlink_target` consistency: a `RecordKind::Symlink`
    /// version with no recorded target is rejected here, at the
    /// decode/admission boundary, rather than only handled defensively
    /// much further downstream by the local materialize path (a policy
    /// skip, not a rejection). Enforced symmetrically rather than as a
    /// one-off check for a single combination: `Symlink` requires `Some(target)`,
    /// and every other kind requires `None` (a `File`/`Directory` version
    /// claiming a symlink target it can never use is exactly as malformed
    /// as a targetless symlink).
    fn validate_structure(&self) -> Result<(), ChangeError> {
        if self.blocks.len() > MAX_BLOCKS {
            return Err(ChangeError::Malformed(format!(
                "block count {} exceeds {MAX_BLOCKS}",
                self.blocks.len()
            )));
        }
        self.validate_encoded_len()?;
        match self.meta.record_kind {
            RecordKind::File => {
                if self.blocks.is_empty() != (self.size == 0) {
                    return Err(ChangeError::Malformed(
                        "an empty file must carry no blocks and a non-empty file must carry blocks"
                            .into(),
                    ));
                }
                check_block_sizes(
                    self.size,
                    self.blocks.len(),
                    self.blocks.iter().map(|b| b.size),
                )?;
            }
            RecordKind::Symlink | RecordKind::Directory => {
                if !self.blocks.is_empty() {
                    return Err(ChangeError::Malformed(
                        "a symlink or directory version must carry no content blocks".into(),
                    ));
                }
            }
        }
        // A directory's size and mtime are what the local filesystem
        // reports about its children (entry-table size, last child
        // change), not state of the directory itself. Letting either into
        // the identity would re-author a directory on every child change
        // and turn two concurrent `mkdir`s of one name into a conflict.
        // `Self::directory` / `Self::from_index_row` produce the one
        // canonical form; anything else is not an honest encoding.
        if self.meta.record_kind == RecordKind::Directory
            && (self.size != 0 || self.meta.mtime_unix_nanos != 0)
        {
            return Err(ChangeError::Malformed(
                "a directory version must carry size 0 and mtime 0".into(),
            ));
        }
        match self.meta.record_kind {
            RecordKind::Symlink => {
                if self.meta.symlink_target.is_none() {
                    return Err(ChangeError::Malformed(
                        "a symlink version must carry a recorded target".into(),
                    ));
                }
            }
            RecordKind::File | RecordKind::Directory => {
                if self.meta.symlink_target.is_some() {
                    return Err(ChangeError::Malformed(
                        "only a symlink version may carry a symlink target".into(),
                    ));
                }
            }
        }
        // Execute is a property of a regular file only; for a directory or a symlink the one honest
        // encoding is `false`, so two devices cannot author different versions of the same thing.
        if matches!(self.meta.record_kind, RecordKind::Symlink | RecordKind::Directory)
            && self.meta.exec
        {
            return Err(ChangeError::Malformed(
                "a symlink or directory version must not be marked executable".into(),
            ));
        }
        Ok(())
    }

    /// Size in bytes of [`Self::canonical_encoding`].
    pub fn encoded_len(&self) -> usize {
        self.canonical_encoding().len()
    }

    /// Refuses a version whose canonical encoding exceeds
    /// [`MAX_ENCODED_VERSION_BYTES`]: one that large cannot ride in a
    /// replication item, so admitting it would leave a head whose version
    /// never arrives.
    pub fn validate_encoded_len(&self) -> Result<(), ChangeError> {
        // Cheap lower bound first: the block list alone decides the common case.
        let blocks_floor = self.blocks.len().saturating_mul(VERSION_BLOCK_ENCODED_BYTES);
        let encoded_bytes = if blocks_floor > MAX_ENCODED_VERSION_BYTES {
            blocks_floor
        } else {
            self.encoded_len()
        };
        if encoded_bytes > MAX_ENCODED_VERSION_BYTES {
            return Err(ChangeError::VersionTooLarge {
                encoded_bytes,
                max_bytes: MAX_ENCODED_VERSION_BYTES,
            });
        }
        Ok(())
    }

    /// The canonical byte layout hashed to form `version_hash`. Does not
    /// include `version_hash` itself.
    pub fn canonical_encoding(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(VERSION_DOMAIN_TAG);
        crate::codec::put_u64(&mut buf, self.size);
        put_u32(&mut buf, self.blocks.len() as u32);
        for block in &self.blocks {
            // Block order is meaningful (it is the file's byte order), so it
            // is preserved, not sorted. Each block carries its exact byte
            // length after its content hash.
            put_len_bytes(&mut buf, &block.hash.0);
            put_u32(&mut buf, block.size);
        }
        self.meta.encode_into(&mut buf);
        buf
    }

    /// The identity of what this version holds, apart from its modification
    /// time: the hash of the canonical encoding with `mtime` zeroed under a
    /// domain tag of its own. It is a function of the verified block list and
    /// the replicated metadata (kind, size, exec, symlink target), so
    /// two versions with equal identities hold the same bytes and the same
    /// replicated metadata and differ at most in `mtime`. A size, a name or an
    /// mtime never stands in for it.
    pub fn content_identity(&self) -> crate::ids::ContentIdentity {
        let mut zeroed = self.clone();
        zeroed.meta.mtime_unix_nanos = 0;
        let mut hasher = Sha256::new();
        hasher.update(CONTENT_DOMAIN_TAG);
        hasher.update(zeroed.canonical_encoding());
        crate::ids::ContentIdentity(hasher.finalize().into())
    }

    pub fn compute_hash(&self) -> VersionHash {
        VersionHash(Sha256::digest(self.canonical_encoding()).into())
    }

    /// Reconstructs the `FileVersion` a stored `files` index row describes —
    /// its block list (in file-byte order, each with its declared size), its
    /// total size, and its metadata — and derives `version_hash` from it via
    /// [`Self::compute_hash`]. This is the sole place a `files` row is turned
    /// back into a canonical version identity: both the durability-root
    /// enumeration and the peer version-present responder go through this
    /// rather than each re-deriving the byte layout, so the exact-version
    /// identifier used for durability is always the same
    /// `FileVersion::compute_hash()` every replica hashes versions
    /// with — never a separate, ad hoc hash over a subset of these fields.
    ///
    /// For a directory row, the stored `size` and `mtime_unix_nanos` are
    /// filesystem observations and are replaced by the canonical 0, and any
    /// blocks it still holds from a file that stood at the path before are
    /// dropped (see [`Self::directory`]); every other field is taken as
    /// stored, so a row
    /// that is malformed in another way still yields a version that
    /// validation refuses.
    #[allow(clippy::too_many_arguments)]
    pub fn from_index_row(
        blocks: Vec<BlockInfo>,
        size: u64,
        mtime_unix_nanos: i64,
        record_kind: RecordKind,
        exec: bool,
        symlink_target: Option<Vec<u8>>,
    ) -> FileVersion {
        // A directory's row can still hold what the file before it at the
        // same path held; none of it is state of the directory.
        let directory = record_kind == RecordKind::Directory;
        let blocks = if directory { Vec::new() } else { blocks }
            .into_iter()
            .map(|b| VersionBlock { hash: BlockHash(b.hash), size: b.size })
            .collect();
        let (size, mtime_unix_nanos) = if directory { (0, 0) } else { (size, mtime_unix_nanos) };
        let exec = exec && record_kind == RecordKind::File;
        let meta = FileMeta { mtime_unix_nanos, exec, symlink_target, record_kind };
        FileVersion::new(blocks, size, meta)
    }

    /// Recomputes the hash and checks it matches the stored `version_hash`,
    /// then applies the full block-layout validation. Both the hash and the
    /// structural invariants must hold for a stored or received version.
    pub fn verify_hash(&self) -> Result<(), ChangeError> {
        if self.compute_hash() != self.version_hash {
            return Err(ChangeError::HashMismatch);
        }
        self.validate_structure()
    }

    /// Parses the `canonical_encoding` form back into a `FileVersion`,
    /// re-deriving `version_hash` from the parsed bytes (it is never part of
    /// the encoding). This is the inverse used when a version is read back
    /// from its stored/wire canonical bytes: because the hash is recomputed
    /// here rather than trusted from an external source, the returned
    /// version's `version_hash` always describes its own content, and a
    /// lookup keyed by a referenced hash only matches a version whose bytes
    /// actually hash to it.
    pub fn from_canonical_encoding(bytes: &[u8]) -> Result<FileVersion, ChangeError> {
        let mut r = Reader::new(bytes);
        let tag = r.take(8)?;
        if tag != VERSION_DOMAIN_TAG {
            return Err(ChangeError::Encoding("bad version domain tag".into()));
        }
        let size = r.u64()?;
        // A block encodes at least a 4-byte length prefix and a 4-byte size,
        // so a count larger than the bytes that remain (or than the absolute
        // cap) is malformed — reject before allocating.
        let block_count = r.bounded_count(8, MAX_BLOCKS)?;
        let mut blocks = Vec::with_capacity(block_count);
        for _ in 0..block_count {
            let hash = BlockHash(r.len_bytes()?);
            let block_size = r.u32()?;
            blocks.push(VersionBlock { hash, size: block_size });
        }
        let meta = FileMeta::decode(&mut r)?;
        r.expect_end()?;
        let version = FileVersion::new(blocks, size, meta);
        // Enforce the full block-layout contract on untrusted bytes: hashes
        // pin block content, but only this validation ties the block sizes to
        // the file's size and bounds each block, so a receiver can trust the
        // offsets it derives from them.
        version.validate_structure()?;
        Ok(version)
    }
}

#[cfg(test)]
mod file_meta_decode_tests;

#[cfg(test)]
mod record_kind_symlink_target_consistency_tests;

#[cfg(test)]
mod directory_version_canonical_tests;

#[cfg(test)]
mod encoded_len_tests;

#[cfg(test)]
mod content_identity_tests;
