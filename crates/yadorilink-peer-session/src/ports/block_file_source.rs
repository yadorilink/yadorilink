//! A file of the user's folder as a source for the blocks it holds.
//!
//! Serving a block to a peer reads it from the block store. A device that does not keep a store
//! copy of a block it holds (a received file written straight to its place, a block the store
//! reclaimed) can still serve it from the file, provided the bytes are checked against the hash
//! before they are sent. This port is that read; the runtime that composes the session implements
//! it against its file index and the folder.

use crate::error::PeerSessionError;

/// What reading one block from a file gave.
#[derive(Debug, PartialEq, Eq)]
pub enum FileBlockRead {
    /// The bytes of the block, checked against its hash.
    Found(Vec<u8>),
    /// The file cannot be a source for this block right now (no such record, not fully present,
    /// busy, not readable without recalling it); nothing is wrong with it.
    Absent,
    /// The file is no longer the version the record describes (its length or its bytes differ).
    /// The implementation has already arranged for it to be looked at again.
    Changed,
}

/// The block-reading seam a session needs besides the block store.
pub trait BlockFileSourcePort: Send + Sync {
    /// Reads the block `hash` that the current record of `path` in `group_id` lists, from the file
    /// itself, and returns it only if its SHA-256 is `hash`.
    ///
    /// Authorization has been decided by the caller; this decides only whether the file can supply
    /// the bytes. Blocking: the caller runs it on the blocking pool.
    fn read_block(
        &self,
        group_id: &str,
        path: &str,
        hash: &[u8],
    ) -> Result<FileBlockRead, PeerSessionError>;
}
