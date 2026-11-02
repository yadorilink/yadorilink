//! Whether capture puts a file's blocks into the block store, or only hashes them.
//!
//! The block store has been the place every captured version was copied to. A device that can
//! serve a block from the user's own file does not need that copy: writing a gigabyte into the
//! store before its first byte can be announced is most of the time a large transfer waits.
//! [`Ingest::FileOnly`] skips the copy; the file is then the only holder of the version until
//! something replaces it, and what makes that safe is the rule of the retention proof (a sync that
//! replaces the version reads it from the file into the store first) and the barrier in
//! `record_builder`: the file is flushed, and checked unchanged, before the record that names it
//! may commit.
//!
//! Which mode a file gets is decided by an [`IngestPolicy`] the owner of the processor supplies.
//! The default, [`AlwaysIngest`], keeps every file in the store as before.

/// How capture takes one file's blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ingest {
    /// Put every block into the store and record the group's provenance for it.
    Store,
    /// Hash the blocks only. The file is flushed to disk and checked unchanged before the record
    /// commits; nothing is put into the store.
    FileOnly,
}

/// Chooses the [`Ingest`] mode of one file.
pub trait IngestPolicy: Send + Sync {
    /// `size` is the file's length when capture classified it; a file that grows while it is read
    /// keeps the mode chosen here.
    fn ingest_for(&self, group_id: &str, path: &str, size: u64) -> Ingest;
}

/// Every file goes into the store.
#[derive(Debug, Default, Clone, Copy)]
pub struct AlwaysIngest;

impl IngestPolicy for AlwaysIngest {
    fn ingest_for(&self, _group_id: &str, _path: &str, _size: u64) -> Ingest {
        Ingest::Store
    }
}
