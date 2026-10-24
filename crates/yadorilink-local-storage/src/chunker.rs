//! Fixed-size block splitting (Syncthing-proven fixed-size blocks,
//! content-defined chunking deferred by default) is the default, plus an
//! opt-in, size-gated content-defined chunking (CDC) path for large files
//! edited internally rather than appended to or replaced wholesale (VM
//! images, databases, large project files), where fixed-size blocks
//! re-transfer everything after an edit point due to boundary shift.
//! Blocks are content-addressed and stored via
//! [`crate::BlockContentStore`], giving free local dedup: an identical
//! block from any other file/version is only ever stored once, regardless
//! of which chunking method produced it. `unix_mode_from_metadata` (a
//! 6-line `std::fs::Metadata` read, zero dependencies of its own) moved
//! alongside for the same reason: it feeds exactly the same file-capture
//! call sites `chunk_file`/ `chunk_file_content_defined` do.

use std::fs;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::io_diag::{self, Op};
use crate::BlockContentStore;
use crate::LocallyHashedBlock;
use crate::StorageError;
use yadorilink_replica_domain::file::BlockInfo;

/// Default block size (128 KiB), matching Syncthing's default.
pub const DEFAULT_BLOCK_SIZE: usize = 128 * 1024;
/// Upper bound blocks scale to for very large files, matching Syncthing's
/// max (16 MiB), so a huge file doesn't produce an unwieldy block count.
const MAX_BLOCK_SIZE: usize = yadorilink_replica_domain::limits::MAX_BLOCK_SIZE_BYTES as usize;
/// Target upper bound on block count per file before scaling the block
/// size up (doubling), keeping index/request overhead bounded.
const TARGET_MAX_BLOCKS: u64 = 2000;

/// Chunk-size parameters targeting Borg/restic's large-binary-backup range
/// (512 KiB-8 MiB, ~2 MiB target) rather than Xet's ML-model-weights range
/// (~64 KiB target) — yadorilink's CDC use case (VM images, databases,
/// large project files) doesn't need Xet's finer granularity, and a
/// coarser target keeps block counts (and therefore index/request
/// overhead) reasonable for multi-gigabyte files.
pub const CDC_MIN_SIZE: usize = 512 * 1024;
pub const CDC_AVG_SIZE: usize = 2 * 1024 * 1024;
pub const CDC_MAX_SIZE: usize = 8 * 1024 * 1024;

/// Files smaller than this always use fixed-size chunking regardless of a
/// link's chunking policy — CDC's rolling-hash cost isn't justified until
/// there's enough content for boundary-shift resilience to actually
/// matter. Comfortably above the fixed chunker's own default block size.
pub const CDC_SIZE_THRESHOLD: u64 = 32 * 1024 * 1024;

/// Picks a block size for a file of `file_size` bytes: the default, unless
/// that would produce more than `TARGET_MAX_BLOCKS` blocks, in which case
/// it doubles (power-of-two steps) up to `MAX_BLOCK_SIZE`.
pub fn block_size_for(file_size: u64) -> usize {
    let mut size = DEFAULT_BLOCK_SIZE;
    while file_size / (size as u64) > TARGET_MAX_BLOCKS && size < MAX_BLOCK_SIZE {
        size *= 2;
    }
    size
}

/// Reads `path`, splits it into fixed-size blocks, stores each block via
/// `store` (deduplicating against anything already held), and returns the
/// block list describing how to reconstruct the file.
pub fn chunk_file(
    store: &dyn BlockContentStore,
    path: &Path,
) -> Result<Vec<BlockInfo>, StorageError> {
    chunk_open_file(store, &open_source(path)?)
}

/// [`chunk_file`] over a handle the caller already opened, sized from that
/// handle's own `fstat`. A caller that needs to know whether the file
/// changed while it was read brackets this call with `fstat`s of the same
/// handle -- see [`chunk_file`]'s callers in local capture.
pub fn chunk_open_file(
    store: &dyn BlockContentStore,
    file: &fs::File,
) -> Result<Vec<BlockInfo>, StorageError> {
    let block_size = block_size_for(file.metadata().map_err(StorageError::SourceRead)?.len());

    let mut file = file;
    let mut blocks = Vec::new();
    let mut offset: u64 = 0;
    let mut buf = vec![0u8; block_size];

    loop {
        let n = read_up_to(&mut file, &mut buf).map_err(StorageError::SourceRead)?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        let hash_hex = store.put(chunk)?;
        blocks.push(BlockInfo { hash: hex::decode(&hash_hex)?, offset, size: n as u32 });
        offset += n as u64;
        if n < block_size {
            break; // short read = end of file
        }
    }

    Ok(blocks)
}

/// Reads `path`, splits it into content-defined (variable-size) blocks
/// using `fastcdc`'s Gear-hash CDC algorithm, stores each via `store`, and
/// returns the block list in the same shape `chunk_file` produces —
/// `reconstruct_file` needs no changes since it already handles arbitrary,
/// variable block sizes. Intended for files at or above
/// `CDC_SIZE_THRESHOLD`; the caller decides when to use this versus
/// `chunk_file` (policy plus size gate).
pub fn chunk_file_content_defined(
    store: &dyn BlockContentStore,
    path: &Path,
) -> Result<Vec<BlockInfo>, StorageError> {
    chunk_file_content_defined_with_callback(store, path, |_, _: Arc<[u8]>| {})
}

/// `chunk_file_content_defined`, generalized so a caller can act on each
/// block AS IT IS PRODUCED rather than only once the whole file has been
/// scanned. `on_block` is invoked synchronously, once per block.
///
/// `chunk_file_content_defined` above is this function with a no-op
/// callback — every existing caller/test keeps its exact prior behavior
/// unchanged.
///
/// `on_block` fires BEFORE this loop's own durable commit for that block,
/// not after — and the block is hashed exactly ONCE, via
/// `LocallyHashedBlock::from_bytes`, with that same `(hash, bytes)` pair
/// feeding both `on_block` and the commit. Two real, measured problems
/// this closes together:
/// - Ordering: the previous shape called `store.put()` (hash + durable
///   commit, fsync included) FIRST and only invoked `on_block` once that
///   fully returned — so a callback's own work could never overlap with
///   this device's local durability I/O for that same block, only ever
///   start strictly after it. An A/B diagnostic (a real callback attached
///   vs. not) measured source-side capture as slower with one attached,
///   specifically because its work was serialized behind, not
///   overlapping, each block's fsync.
/// - Redundant hashing: `store.put()` always derives the hash from `data`
///   internally, so a caller needing the hash before that commit
///   finished had no way to get it without either waiting for `put()` to
///   return (the ordering problem above) or hashing the same bytes a
///   second time by hand. `LocallyHashedBlock`/`BlockStore::put_prepared`
///   close this: hash once, thread that one hash through both consumers.
///
/// `on_block` receives an `Arc<[u8]>`, not an owned `Vec<u8>` — a cheap
/// (refcount bump) clone of `LocallyHashedBlock`'s own buffer, not a deep
/// copy. This still avoids the `.to_vec()` cost this signature's own
/// history already found and fixed once (an owned-`Vec<u8>`-by-value
/// callback measured as a real ~3.5s regression when every implementation
/// needed its own owned copy for an async handoff) — an
/// `Arc` clone gets ownership just as cheaply, without also constraining
/// this function to hand out its *only* copy of the bytes before it can
/// commit them.
/// Total bytes (summed across every batch currently queued but not
/// yet durably committed) the chunk producer is allowed to run ahead of the
/// single background durability worker before `submit` blocks it. A
/// COUNT-based bound (e.g. "3 batches") would not work: CDC
/// blocks scale up to `CDC_MAX_SIZE` (8 MiB) each, so a 32-block batch can
/// legitimately be anywhere from a few KiB to ~256 MiB -- a fixed batch
/// COUNT gives no real memory bound. This is a budget, not a hard cap: a
/// single batch larger than the whole budget is still let through rather
/// than deadlocking (see `submit`'s own doc comment).
const DURABILITY_QUEUE_BYTE_BUDGET: usize = 128 * 1024 * 1024;

/// The byte budget actually in force.
///
/// Measurement seam, not a tuning knob: sweeping the budget is the only
/// way to distinguish "the producer is throttled by this bound" from "the
/// producer would run at the same speed with an unbounded queue", and the
/// two have opposite fixes. Unset -- which is every production process,
/// since nothing in the shipping binaries sets it -- is exactly
/// `DURABILITY_QUEUE_BYTE_BUDGET`, so behaviour is unchanged. `OnceLock`
/// so `submit` never pays for an environment lookup per batch. A value
/// that does not parse, or parses to zero, is ignored rather than
/// honoured: zero would make every `submit` past the first block wait for
/// the queue to drain completely, which is a deadlock-adjacent
/// configuration nobody wants to reach by typo.
fn durability_queue_byte_budget() -> usize {
    match QUEUE_BUDGET_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed) {
        0 => DURABILITY_QUEUE_BYTE_BUDGET,
        bytes => bytes,
    }
}

/// The measurement override of [`DURABILITY_QUEUE_BYTE_BUDGET`]; `0` is no override.
static QUEUE_BUDGET_OVERRIDE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Overrides the byte budget for this process; `None` (or zero) restores the default. A
/// measurement seam only a process that arms diagnostics (the desktop daemon, from its
/// environment) calls: an embedded host never does, so it always runs the default.
pub fn set_durability_queue_byte_budget(bytes: Option<usize>) {
    QUEUE_BUDGET_OVERRIDE.store(bytes.unwrap_or(0), std::sync::atomic::Ordering::Relaxed);
}

/// A bounded, single-producer-single-consumer queue plus ONE background
/// worker thread that calls `store.put_prepared_batch`, so a
/// chunk-producing loop (CDC or fixed-size) can keep producing the NEXT
/// batch's blocks while the CURRENT (and up to `DURABILITY_QUEUE_BYTE_
/// BUDGET` bytes of further queued) batch's durability I/O is still in
/// flight, instead of blocking on it inline. This is the fix for a real,
/// measured serialization: a fair FastCDC-vs-fixed-chunking A/B found
/// `capture -> chunk EOF` statistically identical between the two boundary
/// algorithms (~13.4s mean, both), and a direct CPU-cost check confirmed
/// SHA-256/allocation cost was under 5% of that -- the dominant cost was
/// `put_prepared_batch` itself, called synchronously inline inside the SAME
/// loop that produces chunks, blocking chunk production on every batch's
/// barrier.
///
/// Deliberately ONE worker thread, not several. This queue's job is to
/// overlap batch N's durability I/O with batch N+1's CHUNKING, and nothing
/// else: the store's own durability coordinator is already the single
/// writer for every caller in the process, so adding threads here would
/// only queue more callers behind the same barrier, not issue more of them
/// in parallel. What extra concurrent callers DO buy is a wider group --
/// the store batches whatever is waiting when a commit finishes -- and
/// that benefit is available to genuinely independent producers, not to
/// one file's chunk loop split across threads.
///
/// Extends the store's `staged -> durable -> authoritative` contract to
/// the whole file, not just one batch: `submit` only means "queued for
/// commit," never "durable" -- nothing about a successful `submit` call
/// tells a caller anything about whether that batch's blocks have actually
/// hit disk yet. Only `finish()` returning `Ok(())` means EVERY submitted
/// batch, not just the last one, has been committed durably; only then may
/// a caller proceed to whatever "authoritative" means for it (a source's
/// `FileRecord`/native state publish, a receiver's group provenance commit). If any
/// batch's commit fails, `finish()` returns that error and the whole
/// chunking operation fails -- a caller must never treat a file as fully
/// captured while any batch failed, even if failure was detected only
/// after later batches had already been chunked (chunking a file with a
/// batch already known to have failed is wasted work, not a correctness
/// problem, since `finish()` still surfaces the failure either way; the
/// `should_stop` check below exists purely to avoid that waste, not for
/// correctness).
struct DurabilityQueueState {
    queue: std::collections::VecDeque<Vec<LocallyHashedBlock>>,
    pending_bytes: usize,
    producer_done: bool,
}

struct BackgroundBatchCommitter<'scope> {
    state: &'scope Mutex<DurabilityQueueState>,
    not_empty: &'scope std::sync::Condvar,
    not_full: &'scope std::sync::Condvar,
    handle: Option<std::thread::ScopedJoinHandle<'scope, ()>>,
    error: &'scope Mutex<Option<StorageError>>,
    stop: &'scope AtomicBool,
}

/// A producer that leaves its scope early (a failed read of the source) never reaches `finish`;
/// without this the worker would wait for more batches forever and the scope would never join.
impl Drop for BackgroundBatchCommitter<'_> {
    fn drop(&mut self) {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).producer_done = true;
        self.not_empty.notify_one();
    }
}

impl<'scope> BackgroundBatchCommitter<'scope> {
    #[allow(clippy::too_many_arguments)]
    fn spawn<'env>(
        scope: &'scope std::thread::Scope<'scope, 'env>,
        store: &'env (dyn BlockContentStore + 'env),
        state: &'scope Mutex<DurabilityQueueState>,
        not_empty: &'scope std::sync::Condvar,
        not_full: &'scope std::sync::Condvar,
        error: &'scope Mutex<Option<StorageError>>,
        stop: &'scope AtomicBool,
    ) -> Self {
        let handle = scope.spawn(move || loop {
            let batch = {
                let mut guard = state.lock().unwrap_or_else(|p| p.into_inner());
                loop {
                    if let Some(batch) = guard.queue.pop_front() {
                        break batch;
                    }
                    if guard.producer_done {
                        return; // queue drained and producer will never submit more
                    }
                    let idle_start = io_diag::enabled().then(std::time::Instant::now);
                    guard = not_empty.wait(guard).unwrap_or_else(|p| p.into_inner());
                    if let Some(started) = idle_start {
                        io_diag::record(Op::CommitterIdle, started.elapsed().as_nanos() as u64, 0);
                    }
                }
            };
            let batch_bytes: usize = batch.iter().map(|b| b.bytes().len()).sum();
            if let Err(e) = io_diag::time(Op::CommitBatch, batch_bytes as u64, || {
                store.put_prepared_batch(&batch)
            }) {
                let mut slot = error.lock().unwrap_or_else(|p| p.into_inner());
                if slot.is_none() {
                    *slot = Some(e);
                }
                stop.store(true, Ordering::Release);
                // Fall through to the same byte-budget release below even
                // on failure: a batch that failed to commit is still gone
                // from the queue and its bytes must be released, or a
                // producer waiting on `not_full` for room this failed
                // batch's bytes would have freed could wait forever.
            }
            {
                let mut guard = state.lock().unwrap_or_else(|p| p.into_inner());
                guard.pending_bytes = guard.pending_bytes.saturating_sub(batch_bytes);
                not_full.notify_one();
            }
        });
        Self { state, not_empty, not_full, handle: Some(handle), error, stop }
    }

    /// Queues a batch for background durable commit, blocking only if the
    /// queue's pending-byte budget is already full AND at least one batch
    /// is already queued (a single batch larger than the whole budget is
    /// let through rather than deadlocking against a worker that can never
    /// make room for it any other way). Never itself durable by the time
    /// this returns -- see this type's own doc comment.
    fn submit(&self, batch: Vec<LocallyHashedBlock>) {
        let batch_bytes: usize = batch.iter().map(|b| b.bytes().len()).sum();
        let budget = durability_queue_byte_budget();
        let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if io_diag::enabled() {
            io_diag::record(Op::Submit, 0, batch_bytes as u64);
        }
        // The timer starts only if this call is actually going to park --
        // the point of the counter is "how long was the chunk producer
        // stalled behind durability", so a submit that never waits must
        // contribute nothing, not a clock-read's worth of noise.
        let blocked_start = (io_diag::enabled()
            && guard.pending_bytes + batch_bytes > budget
            && !guard.queue.is_empty())
        .then(std::time::Instant::now);
        while guard.pending_bytes + batch_bytes > budget && !guard.queue.is_empty() {
            guard = self.not_full.wait(guard).unwrap_or_else(|p| p.into_inner());
        }
        if let Some(started) = blocked_start {
            io_diag::record(Op::SubmitBlocked, started.elapsed().as_nanos() as u64, 0);
        }
        guard.pending_bytes += batch_bytes;
        guard.queue.push_back(batch);
        self.not_empty.notify_one();
    }

    /// Whether a background commit has already failed -- checked by the
    /// producer between blocks (not on every byte) purely to stop wasting
    /// time producing more chunks for a file that's already known to fail;
    /// `finish()` is still the only thing that authoritatively surfaces
    /// the error.
    fn should_stop(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    /// Waits for every submitted batch to finish committing (or fail) and
    /// returns the first error encountered, if any. This is the ONLY
    /// operation that means "durable" for every batch `submit` was ever
    /// called with -- see this type's own doc comment.
    fn finish(mut self) -> Result<(), StorageError> {
        {
            let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
            guard.producer_done = true;
            self.not_empty.notify_one(); // wake the worker if it's parked waiting for more
        }
        if let Some(handle) = self.handle.take() {
            let drain_start = io_diag::enabled().then(std::time::Instant::now);
            let _ = handle.join();
            if let Some(started) = drain_start {
                io_diag::record(Op::FinishDrain, started.elapsed().as_nanos() as u64, 0);
            }
        }
        self.error.lock().unwrap_or_else(|p| p.into_inner()).take().map_or(Ok(()), Err)
    }
}

pub fn chunk_file_content_defined_with_callback(
    store: &dyn BlockContentStore,
    path: &Path,
    on_block: impl FnMut(&BlockInfo, Arc<[u8]>),
) -> Result<Vec<BlockInfo>, StorageError> {
    chunk_open_file_content_defined_with_callback(store, &open_source(path)?, on_block)
}

/// [`chunk_file_content_defined_with_callback`] over a handle the caller
/// already opened.
pub fn chunk_open_file_content_defined_with_callback(
    store: &dyn BlockContentStore,
    file: &fs::File,
    mut on_block: impl FnMut(&BlockInfo, Arc<[u8]>),
) -> Result<Vec<BlockInfo>, StorageError> {
    let chunker = fastcdc::v2020::StreamCDC::new(file, CDC_MIN_SIZE, CDC_AVG_SIZE, CDC_MAX_SIZE);

    let mut blocks = Vec::new();
    // Blocks accumulate here instead of each being durably
    // committed (`put_prepared`) the instant it's chunked -- that
    // per-block commit (write plus its own durability barrier) was the worst-case
    // serialization on this loop: CDC scan, callback and durable commit
    // could never overlap because the loop wouldn't even START chunking
    // the next block until the current one's full durability barrier had
    // returned. `on_block` still fires immediately per block, unchanged
    // -- only the DURABLE commit is deferred to a
    // batch boundary via `put_prepared_batch`. See `BlockStore::
    // put_prepared_batch`'s own doc comment for what a real
    // (`SegmentBlockStore`) override does with the batch, and the
    // `segment_store` module doc for the `staged -> durable ->
    // authoritative` contract
    // this composes with (a block callback firing here says nothing
    // about durability -- only this function's own successful return,
    // via `BackgroundBatchCommitter::finish` below, meaning every
    // accumulated batch flushed, does).
    let mut pending: Vec<LocallyHashedBlock> = Vec::with_capacity(CDC_BULK_INGEST_BATCH_SIZE);
    // Phase-timing diagnostic: narrows down which phase
    // of source capture actually dominates T_detect, since a storage-
    // backend comparison alone can't distinguish "storage
    // durability is the bottleneck" from "the CDC/hash/stage pipeline
    // itself is the bottleneck and changing storage wouldn't move the
    // number either way". Remove once the phase breakdown this produces
    // has been used to decide the next investigation.
    let mut first_chunk_logged = false;
    let mut first_batch_logged = false;

    let error = Mutex::new(None);
    let stop = AtomicBool::new(false);
    let queue_state = Mutex::new(DurabilityQueueState {
        queue: std::collections::VecDeque::new(),
        pending_bytes: 0,
        producer_done: false,
    });
    let not_empty = std::sync::Condvar::new();
    let not_full = std::sync::Condvar::new();
    let commit_result = std::thread::scope(|scope| -> Result<(), StorageError> {
        let committer = BackgroundBatchCommitter::spawn(
            scope,
            store,
            &queue_state,
            &not_empty,
            &not_full,
            &error,
            &stop,
        );
        for result in chunker {
            if committer.should_stop() {
                break;
            }
            let chunk = result.map_err(chunking_error)?;
            if !first_chunk_logged {
                tracing::debug!("phase T_cdc_first: first CDC block boundary produced");
                first_chunk_logged = true;
            }
            let prepared = LocallyHashedBlock::from_bytes(chunk.data);
            if blocks.is_empty() {
                tracing::debug!("phase T_hash_first: first PreparedBlock hash complete");
            }
            let block = BlockInfo {
                hash: hex::decode(prepared.hash())?,
                offset: chunk.offset,
                size: chunk.length as u32,
            };
            // Fire the callback FIRST, before this block's own durable
            // commit — see this function's own doc comment for why
            // ordering (not just avoiding a double hash) is the point: a
            // callback sees every block the instant it is chunked,
            // regardless of when (or on which thread) the batch it lands
            // in actually gets committed.
            on_block(&block, prepared.bytes_arc());
            blocks.push(block);
            pending.push(prepared);
            if pending.len() >= CDC_BULK_INGEST_BATCH_SIZE {
                if !first_batch_logged {
                    tracing::debug!(
                        "phase T_store_first: first bulk batch submitted for background commit"
                    );
                    first_batch_logged = true;
                }
                committer.submit(std::mem::replace(
                    &mut pending,
                    Vec::with_capacity(CDC_BULK_INGEST_BATCH_SIZE),
                ));
            }
        }
        tracing::debug!("phase T_chunking_eof: chunk producer reached EOF");
        if !pending.is_empty() {
            if !first_batch_logged {
                tracing::debug!(
                    "phase T_store_first: first bulk batch submitted for background commit"
                );
            }
            committer.submit(pending);
        }
        committer.finish()
    });
    commit_result?;
    tracing::debug!("phase T_all_staged: all source blocks staged/durably committed");

    Ok(blocks)
}

/// How many CDC-chunked blocks `chunk_file_content_defined_with_callback`
/// accumulates before handing them to the store as one
/// `put_prepared_batch` call, instead of one `put_prepared` per block.
/// Matches `PREWARM_PROVENANCE_BATCH_SIZE` (`peer_session.rs`) so the
/// source-side commit batch and the receiver-side provenance batch land
/// on the same natural cadence -- not a hard requirement, just avoids an
/// arbitrary mismatch between two batch sizes that both exist for the
/// same reason on opposite ends of the same transfer.
///
/// This is a *handoff* size, not a durability-group size: the store
/// decides how many blocks share a barrier, and a caller's batch is only
/// one of the inputs to that decision. Blocks of this size are large
/// enough that a barrier is never paid per block, which is all this
/// constant has to achieve.
const CDC_BULK_INGEST_BATCH_SIZE: usize = 32;

/// Diagnostic: `chunk_file`, generalized the exact same way `chunk_
/// file_content_defined` was generalized into `chunk_file_content_defined_
/// with_callback` -- same callback-before-durable-commit ordering,
/// same `LocallyHashedBlock`/hash-once, same `put_prepared_batch` bulk
/// commit, same batch size. The ONLY difference from the CDC callback
/// function is boundary selection: fixed-size (`block_size_for`) instead
/// of `fastcdc`'s rolling Gear hash.
///
/// Exists to answer one specific question this session's own phase-timing
/// diagnostic raised: `capture -> chunk EOF` (the CDC/hash pipeline) was
/// found to be 73-86% of a real 1 GiB transfer's `T_detect`, consistent
/// across both loose and packed storage backends -- ruling storage out as
/// the dominant cost. The leading remaining hypothesis is `fastcdc`'s own
/// rolling-hash boundary computation, not hashing/staging/callback
/// themselves (all of which this function shares byte-for-byte with the
/// CDC path). Comparing THIS function against the CDC callback function,
/// with every other pipeline stage held identical, isolates that one
/// variable. Comparing the OLD bare `chunk_file` (no callback, no
/// `LocallyHashedBlock`, no batch, no callback overlap) against `chunk_
/// file_content_defined_with_callback` would have confounded "boundary
/// algorithm cost" with "pipeline architecture difference" -- exactly the
/// kind of measurement error a `T_firstbyte` accounting bug already cost
/// real investigation time earlier this session.
///
/// Diagnostic-only for now (wired behind `YADORILINK_DIAGNOSTIC_FORCE_
/// FIXED_CHUNKING` in `yadorilink-local-capture`) -- not a production
/// chunking-policy change. `chunk_file` (the original, still used by every
/// existing non-CDC call site) is intentionally untouched.
pub fn chunk_file_fixed_with_callback(
    store: &dyn BlockContentStore,
    path: &Path,
    on_block: impl FnMut(&BlockInfo, Arc<[u8]>),
) -> Result<Vec<BlockInfo>, StorageError> {
    chunk_open_file_fixed_with_callback(store, &open_source(path)?, on_block)
}

/// [`chunk_file_fixed_with_callback`] over a handle the caller already
/// opened, sized from that handle's own `fstat`.
pub fn chunk_open_file_fixed_with_callback(
    store: &dyn BlockContentStore,
    file: &fs::File,
    mut on_block: impl FnMut(&BlockInfo, Arc<[u8]>),
) -> Result<Vec<BlockInfo>, StorageError> {
    let block_size = block_size_for(file.metadata().map_err(StorageError::SourceRead)?.len());

    let mut file = file;
    let mut blocks = Vec::new();
    let mut offset: u64 = 0;
    let mut buf = vec![0u8; block_size];

    let mut pending: Vec<LocallyHashedBlock> = Vec::with_capacity(CDC_BULK_INGEST_BATCH_SIZE);
    let mut first_chunk_logged = false;
    let mut first_batch_logged = false;

    let error = Mutex::new(None);
    let stop = AtomicBool::new(false);
    let queue_state = Mutex::new(DurabilityQueueState {
        queue: std::collections::VecDeque::new(),
        pending_bytes: 0,
        producer_done: false,
    });
    let not_empty = std::sync::Condvar::new();
    let not_full = std::sync::Condvar::new();
    let commit_result = std::thread::scope(|scope| -> Result<(), StorageError> {
        let committer = BackgroundBatchCommitter::spawn(
            scope,
            store,
            &queue_state,
            &not_empty,
            &not_full,
            &error,
            &stop,
        );
        loop {
            if committer.should_stop() {
                break;
            }
            let n = read_up_to(&mut file, &mut buf).map_err(StorageError::SourceRead)?;
            if n == 0 {
                break;
            }
            if !first_chunk_logged {
                tracing::debug!("phase T_cdc_first: first CDC block boundary produced");
                first_chunk_logged = true;
            }
            // `buf[..n]` is reused across iterations (unlike `fastcdc`'s
            // own per-block `Vec` in the CDC path), so this loop cannot
            // hand out ownership of its own read buffer and ONE copy out
            // of it is genuinely unavoidable. Two are not, which is what
            // `from_bytes(buf[..n].to_vec())` used to cost here: the
            // `to_vec` copies the slice into a fresh `Vec`, and
            // `from_bytes` then copies that `Vec` a second time, because
            // `Arc<[u8]>: From<Vec<u8>>` has to reallocate to make room
            // for the refcount header. `from_arc_bytes` takes the one
            // allocation this type stores directly, so the slice is copied
            // straight into it and hashed in place -- one copy per block
            // instead of two, on a loop that runs once per block of the
            // whole file.
            let prepared = LocallyHashedBlock::from_arc_bytes(Arc::from(&buf[..n]));
            if blocks.is_empty() {
                tracing::debug!("phase T_hash_first: first PreparedBlock hash complete");
            }
            let block = BlockInfo { hash: hex::decode(prepared.hash())?, offset, size: n as u32 };
            on_block(&block, prepared.bytes_arc());
            blocks.push(block);
            pending.push(prepared);
            if pending.len() >= CDC_BULK_INGEST_BATCH_SIZE {
                if !first_batch_logged {
                    tracing::debug!(
                        "phase T_store_first: first bulk batch submitted for background commit"
                    );
                    first_batch_logged = true;
                }
                committer.submit(std::mem::replace(
                    &mut pending,
                    Vec::with_capacity(CDC_BULK_INGEST_BATCH_SIZE),
                ));
            }
            offset += n as u64;
            if n < block_size {
                break; // short read = end of file
            }
        }
        tracing::debug!("phase T_chunking_eof: chunk producer reached EOF");
        if !pending.is_empty() {
            if !first_batch_logged {
                tracing::debug!(
                    "phase T_store_first: first bulk batch submitted for background commit"
                );
            }
            committer.submit(pending);
        }
        committer.finish()
    });
    commit_result?;
    tracing::debug!("phase T_all_staged: all source blocks staged/durably committed");

    Ok(blocks)
}

/// Produces every block of `path` — each as its `BlockInfo` plus the
/// `LocallyHashedBlock` carrying the bytes and the hash this pass just
/// computed from them — and hands each to `on_block`, WITHOUT committing
/// any of them to a block store.
///
/// The one thing this does that no other function here can: it lets a
/// caller batch block durability across FILE boundaries. Every other
/// producer in this module owns the commit itself and therefore cannot
/// batch wider than the single file it was called on — `chunk_file` commits
/// per block, and the two `_with_callback` producers commit per
/// `CDC_BULK_INGEST_BATCH_SIZE` blocks *within one file*, which for a folder
/// of small files degenerates to exactly one one-block batch per file.
/// Pooling blocks across files is what lets a folder of small files reach
/// the store as groups of thousands rather than as thousands of groups of
/// one -- and since the group is the durability unit, that difference is
/// the whole cost of a small-file import.
///
/// Handing the block out instead of committing it moves that decision to
/// the caller, who is the only one that knows where the file boundary is
/// and whether crossing it is safe. It also moves a real obligation there:
/// **a block handed to `on_block` is not durable**, and nothing derived
/// from it may be treated as authoritative until the caller has itself
/// committed it (`BlockStore::put_prepared_batch`) and that call has
/// returned `Ok`. `chunk_file`'s own contract — every returned block is
/// already durably stored — does NOT hold for this function, deliberately.
///
/// Block boundaries, sizes, offsets and hashes are identical to what
/// `chunk_file` (`content_defined == false`) and
/// `chunk_file_content_defined` (`true`) produce for the same file, so a
/// record built from this function's output is byte-for-byte the record
/// those produce — see `hash_file_blocks_matches_chunk_file*` in this
/// module's tests, which pin exactly that.
///
/// Generic over the sink's error so the caller's own error type (which is
/// what a commit failure inside `on_block` will produce) propagates
/// unwrapped; this function's own I/O errors arrive through
/// `E: From<StorageError>`.
pub fn hash_file_blocks<E>(
    path: &Path,
    content_defined: bool,
    on_block: impl FnMut(&BlockInfo, LocallyHashedBlock) -> Result<(), E>,
) -> Result<Vec<BlockInfo>, E>
where
    E: From<StorageError>,
{
    let file = open_source(path).map_err(E::from)?;
    hash_open_file_blocks(&file, content_defined, on_block)
}

/// [`hash_file_blocks`] over a handle the caller already opened, sized
/// from that handle's own `fstat`.
pub fn hash_open_file_blocks<E>(
    file: &fs::File,
    content_defined: bool,
    on_block: impl FnMut(&BlockInfo, LocallyHashedBlock) -> Result<(), E>,
) -> Result<Vec<BlockInfo>, E>
where
    E: From<StorageError>,
{
    if content_defined {
        hash_file_content_defined(file, on_block)
    } else {
        hash_file_fixed(file, on_block)
    }
}

/// `hash_file_blocks`' fixed-size half — the same read loop, block sizing
/// and boundary placement as `chunk_file`, with `store.put` replaced by the
/// caller's sink.
fn hash_file_fixed<E>(
    file: &fs::File,
    mut on_block: impl FnMut(&BlockInfo, LocallyHashedBlock) -> Result<(), E>,
) -> Result<Vec<BlockInfo>, E>
where
    E: From<StorageError>,
{
    let block_size =
        block_size_for(file.metadata().map_err(|e| E::from(StorageError::SourceRead(e)))?.len());

    let mut file = file;
    let mut blocks = Vec::new();
    let mut offset: u64 = 0;
    let mut buf = vec![0u8; block_size];

    loop {
        let n =
            read_up_to(&mut file, &mut buf).map_err(|e| E::from(StorageError::SourceRead(e)))?;
        if n == 0 {
            break;
        }
        // One copy out of the reused read buffer, hashed in place — the
        // same single-copy shape `chunk_file_fixed_with_callback` settled
        // on, and for the same reason (`from_bytes(buf[..n].to_vec())`
        // copies twice).
        let prepared = LocallyHashedBlock::from_arc_bytes(Arc::from(&buf[..n]));
        let block = BlockInfo {
            hash: hex::decode(prepared.hash()).map_err(storage_err::<E>)?,
            offset,
            size: n as u32,
        };
        on_block(&block, prepared)?;
        blocks.push(block);
        offset += n as u64;
        if n < block_size {
            break; // short read = end of file
        }
    }

    Ok(blocks)
}

/// `hash_file_blocks`' content-defined half — the same `StreamCDC`
/// configuration and boundary placement as
/// `chunk_file_content_defined`, with the durable commit replaced by the
/// caller's sink.
fn hash_file_content_defined<E>(
    file: &fs::File,
    mut on_block: impl FnMut(&BlockInfo, LocallyHashedBlock) -> Result<(), E>,
) -> Result<Vec<BlockInfo>, E>
where
    E: From<StorageError>,
{
    let chunker = fastcdc::v2020::StreamCDC::new(file, CDC_MIN_SIZE, CDC_AVG_SIZE, CDC_MAX_SIZE);

    let mut blocks = Vec::new();
    for result in chunker {
        let chunk = result.map_err(|e| E::from(chunking_error(e)))?;
        let prepared = LocallyHashedBlock::from_bytes(chunk.data);
        let block = BlockInfo {
            hash: hex::decode(prepared.hash()).map_err(storage_err::<E>)?,
            offset: chunk.offset,
            size: chunk.length as u32,
        };
        on_block(&block, prepared)?;
        blocks.push(block);
    }

    Ok(blocks)
}

/// A failure of the content-defined chunker: a failed read of the source is the source's, anything
/// else is the chunker's own.
fn chunking_error(error: fastcdc::v2020::Error) -> StorageError {
    match error {
        fastcdc::v2020::Error::IoError(error) => StorageError::SourceRead(error),
        other => StorageError::Chunking(other.to_string()),
    }
}

/// Opens the user's source file; a failure is the source's (`SourceRead`), never the block
/// store's `Io`.
fn open_source(path: &Path) -> Result<fs::File, StorageError> {
    fs::File::open(path).map_err(StorageError::SourceRead)
}

/// Lifts one of this module's own I/O/decode failures into the sink's error
/// type, for the two `hash_file_*` loops above.
fn storage_err<E: From<StorageError>>(e: impl Into<StorageError>) -> E {
    E::from(e.into())
}

/// Reads the replicated permission bits
/// (`yadorilink_replica_domain::file:: REPLICATED_MODE_MASK`,
/// owner/group/other read-write-execute) `chunker`'s own callers capture
/// alongside a file's content — the read-side counterpart to
/// `materialize_write::apply_unix_mode`. `None` on any platform with no
/// Unix permission-bits model (Windows); real content on Unix always has
/// some mode, so this is always `Some` there, never a stand- in for "not
/// yet known".
#[cfg(unix)]
pub fn unix_mode_from_metadata(metadata: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(metadata.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
pub fn unix_mode_from_metadata(_metadata: &std::fs::Metadata) -> Option<u32> {
    None
}

/// Reads this regular file's ALLOW-LISTED extended attributes, sorted by
/// name -- the read-side counterpart to `materialize_write::apply_xattrs`. Takes an open file (via
/// its
/// raw fd, `flistxattr`/`fgetxattr`), not a path: this crate's own capture
/// paths already read `unix_mode_from_metadata` from an already-open
/// handle rather than a fresh path lookup specifically to avoid a TOCTOU
/// race against the file changing between the two, and xattr reads join
/// that same "same-handle guarantee" rather than reopening by path.
///
/// Deliberately NOT every xattr a file happens to carry — only an
/// explicit per-platform allow-list, the same reasoning
/// `REPLICATED_MODE_MASK` already applies to permission bits: a
/// security-context or OS-internal attribute is either meaningless or
/// actively dangerous to replicate onto a different device, never a
/// filesystem-fidelity feature (see `yadorilink_replica_domain::file::
/// FileMeta::xattrs`'s own doc comment for the full reasoning and the
/// exact namespaces excluded). Best-effort like `unix_mode_from_
/// metadata`'s own Windows fallback: any failure to list or read an
/// attribute (permission denied, a filesystem with no xattr support at
/// all) is treated as "no attributes," never surfaced as an error -- a
/// missing xattr is not a capture failure the way a missing block would
/// be.
///
/// Never called for anything but a regular file: directories and
/// symlinks report no xattrs in this identity model (both capture paths
/// -- `single_pass_capture.rs`/`local_change.rs` -- simply never call
/// this for those record kinds, mirroring `symlink_target`'s own
/// "`None` for anything but a symlink" convention in reverse).
#[cfg(target_os = "linux")]
pub fn read_replicated_xattrs(file: &fs::File) -> Vec<(String, Vec<u8>)> {
    const LINUX_ALLOWED_PREFIX: &str = "user.";
    read_xattrs_filtered(file, |name| name.starts_with(LINUX_ALLOWED_PREFIX))
}

/// Conservative v1 scope: every common macOS xattr namespace has a real
/// complication (`com.apple.quarantine` is security-relevant --
/// replicating it either defeats Gatekeeper on the receiving machine or,
/// stripped, silently changes Gatekeeper behavior; `com.apple.
/// ResourceFork` is a separate, harder problem of its own; `com.apple.
/// metadata:*` is Spotlight-managed Finder state with no cross-platform
/// meaning), so none is included by default. `read_xattrs_filtered`
/// below is already fully generic; adding a real macOS namespace later
/// is a one-line predicate change, not a redesign.
#[cfg(not(target_os = "linux"))]
pub fn read_replicated_xattrs(_file: &fs::File) -> Vec<(String, Vec<u8>)> {
    Vec::new()
}

#[cfg(target_os = "linux")]
fn read_xattrs_filtered(file: &fs::File, allow: impl Fn(&str) -> bool) -> Vec<(String, Vec<u8>)> {
    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    let Some(names) = list_xattr_names(fd) else { return Vec::new() };
    let mut out: Vec<(String, Vec<u8>)> = names
        .into_iter()
        .filter(|name| allow(name))
        .filter_map(|name| {
            let value = get_xattr_value(fd, &name)?;
            Some((name, value))
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Strict counterpart of [`read_replicated_xattrs`], for the exactness-
/// proof gate (`materialize_write::verify_replicated_xattrs_exact`): a
/// real `listxattr`/`getxattr` failure is `Err`, never silently folded
/// into "no attributes" the way every best-effort reader above this
/// point in the file does -- the exactness proof must never mistake
/// "could not check" for "matches."
#[cfg(target_os = "linux")]
pub fn read_replicated_xattrs_strict(file: &fs::File) -> std::io::Result<Vec<(String, Vec<u8>)>> {
    const LINUX_ALLOWED_PREFIX: &str = "user.";
    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    let names = list_xattr_names_strict(fd)?;
    let mut out = Vec::with_capacity(names.len());
    for name in names.into_iter().filter(|name| name.starts_with(LINUX_ALLOWED_PREFIX)) {
        let value = get_xattr_value_strict(fd, &name)?;
        out.push((name, value));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Bounds the ERANGE re-probe loop `list_xattr_names_strict`/
/// `get_xattr_value_strict` both run: a set genuinely growing between
/// every probe and read (a local actor continuously rewriting xattrs)
/// must eventually surface as a real `Err`, not spin this exactness-proof
/// gate forever.
// Both readers that consult this bound are `#[cfg(target_os = "linux")]`, so the
// constant has to carry the same gate to stay used on every other target.
#[cfg(target_os = "linux")]
const MAX_ERANGE_RETRIES: u32 = 3;

/// The one decision both strict readers make about a fresh size an
/// ERANGE re-probe just returned -- pulled out as its own pure function
/// (no syscalls) specifically so it has a direct unit test: the real
/// `flistxattr`/`fgetxattr` calls cannot be reliably driven into a
/// genuine size-changed-on-every-call race from a portable test.
///
/// `size < 0` is a genuine re-probe failure and must be `Err` -- an
/// earlier version of both callers instead folded this into
/// `Ok(Vec::new())`, exactly like the best-effort `list_xattr_names`/
/// `get_xattr_value` this reader exists to be a STRICT counterpart to;
/// a caller that cannot even re-confirm the current size must never
/// read that as "matches." `size == 0` legitimately means the attribute
/// set/value was cleared since the first probe -- a real answer, not a
/// failure. `size > 0` means retry the read with a buffer of that size.
#[cfg(target_os = "linux")]
fn resolve_erange_reprobe(size: libc::ssize_t) -> std::io::Result<Option<usize>> {
    if size < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if size == 0 {
        return Ok(None);
    }
    Ok(Some(size as usize))
}

/// Strict counterpart of `list_xattr_names`: a real syscall failure
/// propagates as `Err` instead of `None`.
#[cfg(target_os = "linux")]
fn list_xattr_names_strict(fd: std::os::unix::io::RawFd) -> std::io::Result<Vec<String>> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let size = unsafe { libc::flistxattr(fd, std::ptr::null_mut(), 0) };
    if size < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if size == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; size as usize];
    let mut retries = 0u32;
    loop {
        let ret = unsafe { libc::flistxattr(fd, buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
        if ret < 0 {
            let error = std::io::Error::last_os_error();
            // Same size-grew-between-probe-and-read race
            // `list_xattr_names` tolerates -- re-probe and retry, up to
            // the bound above.
            if error.raw_os_error() == Some(libc::ERANGE) {
                retries += 1;
                if retries > MAX_ERANGE_RETRIES {
                    return Err(error);
                }
                let reprobed_size = unsafe { libc::flistxattr(fd, std::ptr::null_mut(), 0) };
                match resolve_erange_reprobe(reprobed_size)? {
                    None => return Ok(Vec::new()),
                    Some(new_size) => {
                        buf = vec![0u8; new_size];
                        continue;
                    }
                }
            }
            return Err(error);
        }
        buf.truncate(ret as usize);
        break;
    }
    Ok(buf
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| OsStr::from_bytes(s).to_string_lossy().into_owned())
        .collect())
}

/// Strict counterpart of `get_xattr_value`: a real syscall failure, or an
/// attribute that vanished between `list_xattr_names_strict` and this
/// call (`ENODATA`), propagates as `Err` instead of being silently
/// skipped -- the exactness gate must never drop an attribute it cannot
/// currently confirm.
#[cfg(target_os = "linux")]
fn get_xattr_value_strict(fd: std::os::unix::io::RawFd, name: &str) -> std::io::Result<Vec<u8>> {
    let c_name = std::ffi::CString::new(name)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let size = unsafe { libc::fgetxattr(fd, c_name.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if size == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; size as usize];
    let mut retries = 0u32;
    loop {
        let ret = unsafe {
            libc::fgetxattr(fd, c_name.as_ptr(), buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        };
        if ret < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ERANGE) {
                retries += 1;
                if retries > MAX_ERANGE_RETRIES {
                    return Err(error);
                }
                let reprobed_size =
                    unsafe { libc::fgetxattr(fd, c_name.as_ptr(), std::ptr::null_mut(), 0) };
                match resolve_erange_reprobe(reprobed_size)? {
                    None => return Ok(Vec::new()),
                    Some(new_size) => {
                        buf = vec![0u8; new_size];
                        continue;
                    }
                }
            }
            return Err(error);
        }
        buf.truncate(ret as usize);
        return Ok(buf);
    }
}

/// Lists every xattr name this open file currently carries. `None` on any
/// failure (permission denied, no xattr support) -- the caller treats
/// that identically to "no attributes."
#[cfg(target_os = "linux")]
fn list_xattr_names(fd: std::os::unix::io::RawFd) -> Option<Vec<String>> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let mut size = unsafe { libc::flistxattr(fd, std::ptr::null_mut(), 0) };
    if size < 0 {
        return None;
    }
    if size == 0 {
        return Some(Vec::new());
    }
    let mut buf = vec![0u8; size as usize];
    loop {
        let ret = unsafe { libc::flistxattr(fd, buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
        if ret < 0 {
            // The attribute set grew between the size probe above and this
            // call -- re-probe once and retry with the new size, matching
            // the same race this whole "probe then read" pattern always
            // has to tolerate for a live filesystem object.
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ERANGE) {
                size = unsafe { libc::flistxattr(fd, std::ptr::null_mut(), 0) };
                if size <= 0 {
                    return Some(Vec::new());
                }
                buf = vec![0u8; size as usize];
                continue;
            }
            return None;
        }
        buf.truncate(ret as usize);
        break;
    }
    // The kernel returns a NUL-separated list of names, not a JSON/length-
    // prefixed structure -- split on NUL, drop the trailing empty segment.
    Some(
        buf.split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| OsStr::from_bytes(s).to_string_lossy().into_owned())
            .collect(),
    )
}

/// Reads one xattr's raw value from this open file. `None` on any
/// failure, including the attribute having vanished between `listxattr`
/// and this call (`ENODATA` is not distinguished from any other failure
/// -- both mean "cannot report this attribute right now," and skipping
/// it is the only sensible outcome).
#[cfg(target_os = "linux")]
fn get_xattr_value(fd: std::os::unix::io::RawFd, name: &str) -> Option<Vec<u8>> {
    let c_name = std::ffi::CString::new(name).ok()?;
    let mut size = unsafe { libc::fgetxattr(fd, c_name.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        return None;
    }
    if size == 0 {
        return Some(Vec::new());
    }
    let mut buf = vec![0u8; size as usize];
    loop {
        let ret = unsafe {
            libc::fgetxattr(fd, c_name.as_ptr(), buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        };
        if ret < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ERANGE) {
                size = unsafe { libc::fgetxattr(fd, c_name.as_ptr(), std::ptr::null_mut(), 0) };
                if size <= 0 {
                    return Some(Vec::new());
                }
                buf = vec![0u8; size as usize];
                continue;
            }
            return None;
        }
        buf.truncate(ret as usize);
        return Some(buf);
    }
}

/// `materialize_write::apply_xattrs`'s own name-listing need: the same
/// `flistxattr` probe `list_xattr_names` already implements, just returning
/// an empty `Vec` rather than `None` on any failure -- the write side has
/// no separate "could not determine" case to distinguish, it always ends
/// up removing/setting nothing for a name it cannot enumerate.
#[cfg(target_os = "linux")]
pub(crate) fn list_xattr_names_for_apply(fd: std::os::unix::io::RawFd) -> Vec<String> {
    list_xattr_names(fd).unwrap_or_default()
}

fn read_up_to(file: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        let n = file.read(&mut buf[total..])?;
        if n == 0 {
            break;
        }
        total += n;
    }
    Ok(total)
}

#[cfg(test)]
mod tests;
