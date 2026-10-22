#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("block not found: {0}")]
    NotFound(String),

    #[error("checksum mismatch for block {expected}: computed {actual}")]
    ChecksumMismatch { expected: String, actual: String },

    #[error("invalid path: {0}")]
    InvalidPath(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// An operation on the user's own source file failed: the open, its `fstat`, or a read of its
    /// bytes (an EIO partway through, a network volume dropping). Every failure whose origin is
    /// the source is this variant, and none of the block store's is. Deliberately not `Io` and never built via `#[from]`: `Io` is also
    /// what the block store reports for its own faults, and a caller that has to decide whether to
    /// skip the file or stop the pass needs the two told apart by type, not guessed from the
    /// error's shape.
    #[error("could not read the source file: {0}")]
    SourceRead(std::io::Error),

    /// A block write was rejected before any bytes were written because
    /// completing it would breach the configured free-space headroom on the
    /// volume hosting the block-store root — deliberately a distinct
    /// variant (not `Io`, and never constructed via `#[from]`) so callers
    /// can tell "disk is full, back off differently" from a transient I/O
    /// error and retry accordingly.
    #[error(
        "insufficient free space to write block at {path:?}: {available_bytes} bytes available \
         on {volume:?}, headroom requires at least {headroom_bytes} bytes free"
    )]
    DiskPressure {
        /// The block file path the write would have gone to (never
        /// created — the check runs before any temp file exists).
        path: std::path::PathBuf,
        /// The volume the headroom check was evaluated against — the
        /// block-store root for this variant.
        volume: std::path::PathBuf,
        available_bytes: u64,
        headroom_bytes: u64,
    },

    /// A materialization write/delete target resolved outside its
    /// designated root (a symlinked intermediate path component, planted
    /// locally or raced in) -- defense-in-depth, distinct from `InvalidPath`
    /// so callers can tell "this specific escape check refused it" apart
    /// from a generically malformed path.
    #[error(
        "materialization target {0:?} resolved outside its sync root (symlinked path component?)"
    )]
    PathEscapesRoot(String),

    /// `chunker::chunk_file`/`chunk_file_content_defined` decode a
    /// content-store `put` result (a hex-encoded content hash) back into
    /// raw bytes for `BlockInfo::hash` -- this is that decode failing.
    /// Distinct from `Io` so a caller can tell "the store returned a
    /// malformed hash" apart from a filesystem failure.
    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),

    /// `chunker::chunk_file_content_defined`: an error from the `fastcdc`
    /// streaming chunker (I/O failure reading the source file, or an
    /// internal chunker error) -- distinct from `Io` since it's
    /// specifically about the CDC chunk-boundary-finding process, not a
    /// bare filesystem call.
    #[error("content-defined chunking error: {0}")]
    Chunking(String),

    /// The block store's persistent index could not be read or written.
    /// Distinct from `Io` because the index is the store's canonical
    /// metadata: an index failure means the store cannot answer what it
    /// holds, which is a different thing for a caller to handle than one
    /// block's bytes being unreadable.
    #[error("block index error: {0}")]
    Index(String),

    /// The store's own on-disk structure is inconsistent -- a segment
    /// stamped with a format this build does not write, a file header that
    /// does not validate, a segment shorter than its index says. Always
    /// fail-closed: the store never guesses at a structure it does not
    /// recognise.
    #[error("block store is corrupt: {0}")]
    CorruptStore(String),

    /// Removing bytes was refused because the volume holding them is not known to offer durable
    /// namespace changes. Nothing was removed.
    #[error("byte deletion refused: {0}")]
    DeletionRefused(String),
}

impl StorageError {
    /// An equivalent error value, for the one place a single failure has
    /// to be reported to several callers: a group commit shares one
    /// durability barrier between every caller whose blocks were in it, so
    /// a failure is genuinely every one of their failures.
    ///
    /// `std::io::Error` is not `Clone` (it can carry an arbitrary boxed
    /// payload), so the copy preserves what a caller can actually act on
    /// -- the kind and the message -- rather than the original's identity.
    pub(crate) fn duplicate(&self) -> StorageError {
        match self {
            StorageError::NotFound(hash) => StorageError::NotFound(hash.clone()),
            StorageError::ChecksumMismatch { expected, actual } => StorageError::ChecksumMismatch {
                expected: expected.clone(),
                actual: actual.clone(),
            },
            StorageError::InvalidPath(message) => StorageError::InvalidPath(message.clone()),
            StorageError::Io(error) => {
                StorageError::Io(std::io::Error::new(error.kind(), error.to_string()))
            }
            StorageError::SourceRead(error) => {
                StorageError::SourceRead(std::io::Error::new(error.kind(), error.to_string()))
            }
            StorageError::DiskPressure { path, volume, available_bytes, headroom_bytes } => {
                StorageError::DiskPressure {
                    path: path.clone(),
                    volume: volume.clone(),
                    available_bytes: *available_bytes,
                    headroom_bytes: *headroom_bytes,
                }
            }
            StorageError::PathEscapesRoot(path) => StorageError::PathEscapesRoot(path.clone()),
            StorageError::Hex(error) => StorageError::Hex(*error),
            StorageError::Chunking(message) => StorageError::Chunking(message.clone()),
            StorageError::Index(message) => StorageError::Index(message.clone()),
            StorageError::CorruptStore(message) => StorageError::CorruptStore(message.clone()),
            StorageError::DeletionRefused(message) => {
                StorageError::DeletionRefused(message.clone())
            }
        }
    }
}
