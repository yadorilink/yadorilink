use std::collections::HashSet;
use std::sync::Arc;
use std::time::SystemTime;

use sha2::{Digest, Sha256};

use crate::error::StorageError;
use crate::free_space::VolumeFreeSpace;

/// Hex-encoded SHA-256 content hash, used as the sole addressing key for
/// stored blocks (per `local-storage` spec: "content-derived keys, not
/// user-supplied paths").
pub type ContentHash = String;

/// The one place block bytes get SHA-256'd for `ContentHash` purposes —
/// `SegmentBlockStore::put`/`hash_bytes` and `LocallyHashedBlock::from_bytes`
/// both call this, so there is exactly one hash implementation to keep in
/// sync, not two that could silently drift.
pub fn hash_block_bytes(data: &[u8]) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// A block this process hashed itself, from bytes it holds directly — the
/// only ways to construct one are [`from_bytes`](Self::from_bytes) and
/// [`from_arc_bytes`](Self::from_arc_bytes), which differ only in how the
/// caller hands over ownership of the buffer and both hash fresh, so a
/// `LocallyHashedBlock` is always a genuine `(hash, bytes)` pair a caller
/// cannot spoof by pairing a real hash with different bytes (or vice
/// versa) through this type's public surface.
///
/// Exists to hash a freshly-chunked block exactly ONCE and feed
/// that single `(hash, bytes)` pair to every downstream consumer that
/// needs it (a per-block callback, `BlockStore::put_prepared`'s
/// durable commit, `BlockInfo`'s own hash field) — before this type
/// existed, `chunker.rs`'s CDC loop only had `BlockStore::put`, which
/// always hashes internally as part of committing, forcing a caller that
/// needs the hash before that commit finishes (a speculative
/// a callback) into hashing the same bytes a second time, or serializing
/// entirely behind the durable commit's own fsync latency. See
/// `chunk_file_content_defined_with_callback`'s own doc comment for the
/// real, measured cost this closes.
///
/// This type is deliberately NOT constructible from peer-supplied/wire
/// data — `bytes` field holds content only THIS process has hashed
/// itself, fresh, in `from_bytes`. Wire-received bytes with a
/// peer-claimed hash must keep going through the existing independent
/// verify-then-trust path (this crate's `BlockStore::put`, which
/// re-derives the hash from the bytes rather than trusting a caller's
/// claim) — never through this type, which has no verification step of
/// its own precisely because it doesn't need one: it only ever sees bytes
/// this process already possesses and hashes on the spot.
#[derive(Clone)]
pub struct LocallyHashedBlock {
    hash: ContentHash,
    bytes: Arc<[u8]>,
}

impl LocallyHashedBlock {
    /// Hashes `bytes` once, right now, and pairs the result with them.
    /// Like `from_arc_bytes`, there is no way here to build a
    /// `LocallyHashedBlock` from a hash this process did not just compute
    /// itself from these exact bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self::from_arc_bytes(Arc::from(bytes))
    }

    /// `from_bytes` for a caller that can already produce an `Arc<[u8]>`
    /// directly — copying a slice straight into the shared allocation
    /// this type stores, rather than into a `Vec` that `from_bytes` must
    /// then copy a second time (`Arc<[u8]>: From<Vec<u8>>` reallocates,
    /// because a `Vec`'s allocation has no room for the refcount header).
    /// For a 2 MiB block off the wire that second copy is not free.
    ///
    /// This weakens nothing: the hash is still computed here, by this
    /// process, from exactly the bytes being stored, and the caller has
    /// no way to supply one. `Arc<[u8]>` is immutable, so the bytes
    /// cannot change out from under the hash afterwards either.
    pub fn from_arc_bytes(bytes: Arc<[u8]>) -> Self {
        let hash = hash_block_bytes(&bytes);
        Self { hash, bytes }
    }

    pub fn hash(&self) -> &ContentHash {
        &self.hash
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// A cheap (refcount-bump, not a data copy) handle to the same
    /// underlying bytes — for a second consumer (e.g. a per-block callback)
    /// that needs its own owned reference without paying for another
    /// deep copy of a potentially large block.
    pub fn bytes_arc(&self) -> Arc<[u8]> {
        Arc::clone(&self.bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StorageUsage {
    pub block_count: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GcReport {
    pub blocks_deleted: u64,
    pub bytes_reclaimed: u64,
}

/// Storage backend interface used by the sync engine on each device.
/// Implementations MUST NOT resolve any path outside their configured
/// storage root, regardless of what `list_by_prefix` prefixes are supplied.
pub trait BlockStore: Send + Sync {
    /// The directory whose volume holds this store's bytes, `None` when unknown. Deleting local
    /// bytes is allowed only where that volume is known to be durable.
    fn storage_root(&self) -> Option<&std::path::Path> {
        None
    }

    /// Makes the store's own index database stand alone on disk (its write-ahead log folded
    /// into the main file), for a stop that wants nothing left in a log. A store without an
    /// index has nothing to do.
    fn checkpoint(&self) -> Result<(), StorageError> {
        Ok(())
    }

    /// Stores `data`, returning its content hash. Storing a block whose
    /// hash already exists is a no-op that still returns the same hash
    /// (identical content is stored once).
    fn put(&self, data: &[u8]) -> Result<ContentHash, StorageError>;

    /// Same effect as `put`, but for a block this caller already hashed
    /// itself (`LocallyHashedBlock`) — skips re-deriving the hash from
    /// `data`, so a caller that needs the hash before committing (e.g. to
    /// hand it to a callback concurrently with the commit) never pays
    /// for hashing the same bytes twice. The default implementation just
    /// calls `put` and discards its returned hash (recomputing it, same
    /// as before this method existed) — correct for any implementor that
    /// hasn't overridden this, just not the performance win a real
    /// override (like `SegmentBlockStore`'s) provides. Discards the hash
    /// `LocallyHashedBlock` already carries in its default form
    /// specifically so implementors are never tempted to trust it
    /// unverified in a context where that would be unsafe; an override
    /// that skips re-hashing is an explicit, audited opt-in per
    /// implementor, not something a generic default should do quietly.
    fn put_prepared(&self, prepared: &LocallyHashedBlock) -> Result<(), StorageError> {
        self.put(prepared.bytes()).map(|_| ())
    }

    /// Commits every block in `prepared` as one durability batch instead
    /// of `prepared.len()` independent commits.
    ///
    /// This is the method that matters for a small-file workload. A block
    /// store's cost is barriers, not bytes -- a folder of 100,000 tiny
    /// files is a few megabytes of content and a hundred thousand
    /// durability barriers -- so what a real override does with this slice
    /// is make one barrier serve all of it. See the `segment_store` module
    /// doc for how, and for the `staged -> durable -> authoritative`
    /// contract that the override preserves: returning `Ok` means every
    /// block here is durable, and nothing upstream may become
    /// authoritative before it does.
    ///
    /// The default implementation is exactly what calling `put_prepared`
    /// once per block, in order, already does -- correct for any
    /// implementor that hasn't overridden it (the same fallback shape
    /// `put_prepared` itself established), just without the barrier
    /// coalescing. Stops at the first error, same as a plain per-block
    /// loop would.
    fn put_prepared_batch(&self, prepared: &[LocallyHashedBlock]) -> Result<(), StorageError> {
        for block in prepared {
            self.put_prepared(block)?;
        }
        Ok(())
    }

    /// Reads back a block by hash, verifying its checksum. Returns
    /// `StorageError::ChecksumMismatch` if the stored bytes don't hash to
    /// the requested key (corruption), and `NotFound` if absent.
    fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError>;

    /// Reads back a block by hash WITHOUT re-verifying its checksum
    /// against the stored bytes (`sync-performance` ).
    ///
    /// # Safety contract (not a Rust `unsafe fn` — a correctness contract)
    ///
    /// This is a performance fast path, not a general-purpose substitute
    /// for [`get`](Self::get). Callers MUST only use it when integrity is
    /// *already independently guaranteed* for this exact read, e.g.:
    /// - re-serving bytes that this same process already checksum-verified
    ///   earlier in the same request/response flow (no intervening
    ///   untrusted write to that path), or
    /// - reading content this process just wrote via [`put`](Self::put) in
    ///   the same operation, before any possibility of external tampering
    ///   or corruption of that specific write.
    ///
    /// Any path that handles peer-supplied bytes or content this process
    /// has not itself verified during this run (a "first read") MUST keep
    /// using `get`, per `security-hardening` — `get`'s mandatory
    /// verify-on-read is what limits to a DoS vector instead of a
    /// silent-corruption/integrity vector, and `get_unchecked` does not
    /// preserve that guarantee.
    ///
    /// The default implementation simply delegates to `get`, so it is
    /// always at least as safe as `get` unless a backend explicitly
    /// overrides it to skip verification (as `SegmentBlockStore` does). No
    /// call site in this repository calls `get_unchecked` yet as of this
    /// change — it is added for a future, deliberate opt-in at specific
    /// call sites.
    fn get_unchecked(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        self.get(hash)
    }

    fn delete(&self, hash: &str) -> Result<(), StorageError>;

    fn exists(&self, hash: &str) -> Result<bool, StorageError>;

    /// Lists stored content hashes beginning with `prefix`.
    fn list_by_prefix(&self, prefix: &str) -> Result<Vec<ContentHash>, StorageError>;

    /// Reports current block-store usage. Backends with direct metadata
    /// access should override this to avoid reading block contents; the
    /// default stays correct for in-memory/test implementations using
    /// only the trait's existing API surface.
    fn usage(&self) -> Result<StorageUsage, StorageError> {
        let hashes = self.list_by_prefix("")?;
        let mut usage = StorageUsage { block_count: hashes.len() as u64, total_bytes: 0 };
        for hash in hashes {
            usage.total_bytes += self.get_unchecked(&hash)?.len() as u64;
        }
        Ok(usage)
    }

    /// Mark-and-sweep — deletes every stored block not in `live` and older
    /// (by on-disk mtime) than `grace_cutoff`, or (`dry_run`) reports what
    /// would be deleted without calling [`delete`](Self::delete). No
    /// default implementation: the grace-window check is inherently
    /// backend-specific (it keys off on-disk mtime, which only a real
    /// filesystem backend has), so unlike `usage` above there is no
    /// generically-correct fallback. This
    /// lives on the trait — mirroring `set_headroom_enforced`'s doc
    /// comment's own precedent — because `yadorilink-daemon`'s
    /// `DaemonState` only ever holds an `Arc<dyn BlockStore>`, never the
    /// concrete `SegmentBlockStore`, and the periodic/on-demand GC scheduler
    /// needs to call this through that trait object.
    fn sweep(
        &self,
        live: &HashSet<ContentHash>,
        grace_cutoff: SystemTime,
        dry_run: bool,
    ) -> Result<GcReport, StorageError>;

    /// Reclaims (deletes) a specific set of cached blocks, freeing their
    /// real on-disk space, and reports how many blocks/bytes were freed.
    ///
    /// This is deliberately distinct from [`sweep`](Self::sweep). `sweep`
    /// enforces the version-liveness rule: a block referenced by any
    /// retained version is kept alive. This method is the single, explicit
    /// exception to that rule — the reclamation of an on-demand device's
    /// block cache. On such a device the block store for non-hydrated,
    /// non-pinned content is a cache: those blocks may be deleted to free
    /// space even though a retained version still references them, because
    /// the content is durably held elsewhere (a full-replica device for the
    /// group). The block store itself cannot see that liveness or custody
    /// context, so this method deletes exactly the hashes it is given and
    /// makes no liveness decision of its own: the caller is responsible for
    /// having established, fail-closed, that (a) this device syncs the group
    /// as a reclaimable cache rather than a full replica, (b) a full replica
    /// is confirmed to hold these blocks, and (c) no locally hydrated or
    /// pinned file still needs them. `sweep` must never be given this
    /// exception; a full-replica device (and any hydrated/pinned file) keeps
    /// the ordinary version-liveness guarantee and is never reclaimed this
    /// way.
    ///
    /// Idempotent per hash: a hash already absent contributes nothing to the
    /// report rather than erroring, so a retried or partially-completed
    /// reclamation is safe. The default implementation sizes each block
    /// before deleting it; a backend with direct metadata access should
    /// override this to avoid reading block contents (as `SegmentBlockStore`
    /// does).
    fn reclaim_cached_blocks(&self, hashes: &[ContentHash]) -> Result<GcReport, StorageError> {
        let mut report = GcReport::default();
        for hash in hashes {
            let bytes = match self.get_unchecked(hash) {
                Ok(block) => block.len() as u64,
                Err(StorageError::NotFound(_)) => continue,
                Err(e) => return Err(e),
            };
            self.delete(hash)?;
            report.blocks_deleted += 1;
            report.bytes_reclaimed += bytes;
        }
        Ok(report)
    }

    /// Reports, for each of `hashes` (in the same order), whether it's
    /// already present locally — `on-demand-sync`: lets a caller
    /// (hydration, in particular) know which of a file's blocks it still
    /// needs to fetch from a peer without probing them one at a time.
    /// Default implementation checks each hash individually via `exists`;
    /// a backend with an indexed batch-lookup path may override this for
    /// efficiency, but the default is always correct.
    ///
    /// `sync-performance` this is called from async call sites
    /// (`peer_session.rs`, `hydration.rs`) without an intervening
    /// `.await`, so an override MUST NOT synchronously perform a large
    /// amount of blocking filesystem work directly on a tokio worker
    /// thread without compensating for it (e.g. via
    /// `tokio::task::block_in_place` when actually running on a
    /// multi-threaded tokio runtime) — see `SegmentBlockStore::present_blocks`
    /// for the pattern this repo uses, kept behind this same sync
    /// signature so existing callers need no changes.
    fn present_blocks(&self, hashes: &[ContentHash]) -> Result<Vec<bool>, StorageError> {
        hashes.iter().map(|h| self.exists(h.as_str())).collect()
    }

    /// Turns this backend's disk-space headroom preflight on `put` on or
    /// off. Exposed on the trait (rather than only on the concrete
    /// `SegmentBlockStore`) so
    /// `yadorilink-daemon`'s `DaemonState`, which only ever holds an
    /// `Arc<dyn BlockStore>` (not the concrete type), can wire governance
    /// config into whatever backend is actually running. Default: a no-op
    /// — a backend with no real disk-headroom concept (e.g. an in-memory
    /// test double) simply ignores this; only `SegmentBlockStore` overrides it
    /// with real enforcement. See `SegmentBlockStore::headroom_enforced`'s doc
    /// comment for why enforcement itself defaults to off.
    fn set_headroom_enforced(&self, _enforced: bool) {}

    /// Sets or clears an explicit headroom override (`None` = the default
    /// default headroom formula (`free_space`)). Default: a no-op, mirroring
    /// `set_headroom_enforced`.
    fn set_headroom_override_bytes(&self, _headroom_bytes: Option<u64>) {}

    /// This backend's current free-space snapshot (available/total/headroom
    /// bytes, from which the caller can derive the ok/low/critical
    /// classification via `VolumeFreeSpace::classify` — ), for
    /// `yadorilink status`'s per-volume reporting. `None` when this backend
    /// has no real underlying volume to report on. Default: `None` — an
    /// in-memory/test double has no real disk concept; only `SegmentBlockStore`
    /// overrides this with a real query.
    fn free_space(&self) -> Result<Option<VolumeFreeSpace>, StorageError> {
        Ok(None)
    }

    /// The directory holding this backend's data, when it has one on a real volume. Default:
    /// `None`, like [`Self::free_space`].
    fn data_dir(&self) -> Option<&std::path::Path> {
        None
    }
}
