//! Measurement-only I/O and pipeline counters for the block store's
//! durability path.
//!
//! Exists for one question: for a large-file capture, `capture ->
//! producer_EOF` is dominated by something that is *not* chunk production
//! (chunking is ~1.8 s per GiB; the phase is ~11.2 s). Wall-clock totals
//! cannot distinguish "the producer is blocked behind durability" from
//! "durability is bandwidth-bound" from "durability is metadata-bound" --
//! and those three have completely different fixes. This module counts
//! calls, bytes and nanoseconds per *operation class* so the breakdown is
//! observed rather than inferred.
//!
//! **Off by default and inert.** Every recording site is guarded by a
//! single `Ordering::Relaxed` load of [`ENABLED`], which nothing in the
//! production binaries ever sets: only the crate's own `examples/` and
//! tests call [`set_enabled`]. When disabled, the cost of an
//! instrumentation site is that one atomic load -- no `Instant::now()`,
//! no atomic increment, no allocation. Nothing here changes control flow,
//! ordering, error handling or durability semantics whether it is on or
//! off.
//!
//! Only counters for the durability path proper live here -- the
//! percentile histogram in particular exists because totals cannot
//! separate "every barrier got slower" from "a few got much slower", and
//! those have different causes and different fixes.
//!
//! No unit tests of the counters live here on purpose: every counter is
//! process-global, and Rust runs a crate's tests in parallel threads of
//! one binary, so a test that armed [`set_enabled`] would both perturb and
//! be perturbed by whatever the store's own tests were committing at that
//! moment. The module's behaviour is exercised end to end by
//! `examples/block_durability_bench.rs` instead, which owns its whole
//! process.
//!
//! Deliberately process-global rather than threaded through the store:
//! the operations being timed sit several layers down inside the segment
//! writer and the persistent index, and the pipeline counters sit inside
//! `chunker.rs`'s scoped background committer. Plumbing a handle to both
//! would have meant changing several production signatures for a
//! diagnostic, which is a worse trade than a global that is switched off.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

/// One measured operation class. Ordering is the reporting order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Op {
    // ---- producer / queue pipeline (chunker.rs) ----
    /// `BackgroundBatchCommitter::submit` calls (all of them).
    Submit = 0,
    /// Time the chunk producer spent parked on `not_full`, i.e. blocked
    /// because the durability queue's byte budget was already full. Calls
    /// = number of `submit`s that actually had to wait at all.
    SubmitBlocked = 1,
    /// Time the single background committer thread spent parked on
    /// `not_empty` with nothing to commit, i.e. starved by the producer.
    /// The mirror image of `SubmitBlocked`: if this is large and
    /// `SubmitBlocked` is small, the queue is not the bottleneck.
    CommitterIdle = 2,
    /// Wall time inside `store.put_prepared_batch`, wherever it is called
    /// from: `chunker.rs`'s per-file background committer thread, or a
    /// reconciliation scan's own cross-file bulk flush
    /// (`yadorilink-local-capture`'s `ScanBlockStaging`), which does its
    /// own batching and uses none of the queue counters above. Bytes =
    /// batch bytes, so `calls` against `bytes` is what says which shape
    /// produced them: one call per file's worth of blocks versus one per
    /// several thousand blocks pooled across files.
    ///
    /// This counts a *caller's* batch, which is not the same thing as a
    /// durability group: several callers' batches can share one group, and
    /// one caller's batch can span more than one. [`Op::GroupCommit`] is
    /// the group count.
    CommitBatch = 3,
    /// Wall time the producer spent in `BackgroundBatchCommitter::finish`
    /// after reaching EOF, waiting for whatever is still queued to commit.
    /// This is the tail that sits *after* the producer is done, so it is
    /// the part of durability cost that never blocks chunk production --
    /// the phase breakdown's `producer_EOF -> drain_done`, not its
    /// `capture -> producer_EOF`. Separating the two matters: shrinking
    /// the tail does not speed up capture, and shrinking the blocking does
    /// not shrink the tail.
    FinishDrain = 13,

    // ---- group durability path (segment_store) ----
    /// One durability group: dedup, append, barrier, index transaction.
    /// **This is the durability-barrier count.** The whole point of the
    /// segment store is that this number tracks group commits rather than
    /// blocks, so `calls` here against the blocks committed in the same
    /// run is the single number that says whether the design is doing what
    /// it exists to do. Bytes = payload bytes submitted.
    GroupCommit = 4,
    /// The group's deduplication query against the persistent index --
    /// one indexed lookup per distinct hash in the group. Separated from
    /// `IndexCommit` because a read that scales with group size and a
    /// write that costs one WAL barrier have nothing in common.
    IndexDedupe = 5,
    /// The index transaction that records a group's mappings. One SQLite
    /// commit -- and, under `synchronous = FULL`, one WAL barrier -- per
    /// group, whatever the group holds.
    IndexCommit = 6,
    /// `open(O_CREAT|O_EXCL)` of a new segment file. Once per segment, not
    /// once per group and never once per block.
    SegmentCreate = 7,
    /// `fsync` of `segments/`, publishing a newly created segment's
    /// directory entry. Once per segment created.
    SegmentDirFsync = 8,
    /// `write_all` of a whole group's records into a segment -- one call
    /// per touched segment per group. Bytes = record bytes, so this is
    /// where real write bandwidth shows.
    SegmentAppend = 9,
    /// `fdatasync` of a segment: **the** durability barrier. Normally
    /// exactly one per group; more only when a group spanned a roll-over.
    /// Comparing `calls` here with `GroupCommit`'s is how you see whether
    /// segments are rolling over more than they should.
    SegmentFsync = 10,
    /// One block read back out of a segment (`pread` plus framing
    /// validation). Bytes = payload length.
    BlockRead = 11,
    /// One block read during compaction, verified before it is copied.
    CompactionRead = 12,
    /// `check_headroom`: a free-space `statvfs` when headroom enforcement
    /// is on, a single relaxed atomic load when it is off (the default).
    HeadroomCheck = 14,

    // ---- [`Op::BlockRead`], split by who asked for it ----
    //
    // [`Op::BlockRead`] is recorded inside the store's own read path,
    // which knows a block was read and nothing about why. That is enough
    // to see read amplification and not enough to do anything about it: a
    // measured run delivering the same 2000 new files to progressively
    // larger folders read 3,180 then 11,290 then 21,141 blocks, and the
    // question that decides whether that is a bug or the cost of the
    // feature is which caller grew. These count the same reads as
    // `BlockRead`, partitioned by [`ReadReason`]; their sum is `BlockRead`
    // minus whatever ran with no reason set.
    /// Rebuilding a file's bytes from its blocks.
    BlockReadReconstruct = 15,
    /// Serving a block to a peer over a sync session.
    BlockReadPeerServe = 16,
    /// Serving a block for a one-shot Send transfer.
    BlockReadSendServe = 17,
    /// Reading a block back to check it against its own hash.
    BlockReadValidate = 18,
    /// Relocating a block while compacting a segment.
    BlockReadCompaction = 19,
    /// Proving durable custody of a version by re-reading and re-hashing
    /// every one of its blocks -- `holds_version_durably` step 6, which
    /// answers a peer's `VersionPresent` query and is deliberately a full
    /// verification rather than an existence check.
    BlockReadCustodyEvidence = 21,
    /// A read from a caller that set no reason. Not a residual to ignore:
    /// a large count here means the attribution is incomplete, and the
    /// split above is not yet a partition of anything.
    BlockReadOther = 20,

    // ---- receive-side file publication ----
    //
    // Each of these sits on the path that turns a received version into a
    // visible file: they say where a receive's wall time goes between "the
    // bytes are in the block store" and "the file is published".
    /// `sync_all` of the finished temp file, before it is renamed into place.
    FileFsync = 22,
    /// `fsync` of the destination's parent directory after a rename (also
    /// after a placeholder publish). Calls against
    /// [`distinct_parent_dirs`] says how much a coalescing of these could
    /// save.
    DirFsync = 23,
    /// The temp-file-to-final-name rename of a reconstructed file.
    Rename = 24,
}

const OP_COUNT: usize = 25;

const OP_NAMES: [&str; OP_COUNT] = [
    "submit",
    "submit_blocked",
    "committer_idle",
    "commit_batch",
    "group_commit",
    "index_dedupe",
    "index_commit",
    "segment_create",
    "segment_dir_fsync",
    "segment_append",
    "segment_fsync",
    "block_read",
    "compaction_read",
    "finish_drain",
    "headroom_check",
    "block_read_reconstruct",
    "block_read_peer_serve",
    "block_read_send_serve",
    "block_read_validate",
    "block_read_compaction",
    "block_read_other",
    "block_read_custody_evidence",
    "file_fsync",
    "dir_fsync",
    "rename",
];

/// Who asked for a block read. Set by the caller, read by the store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadReason {
    Reconstruct,
    PeerServe,
    SendServe,
    Validate,
    Compaction,
    CustodyEvidence,
    /// Nobody said. Counted separately rather than folded into any of the
    /// above, so an unattributed read is visible instead of misfiled.
    Unattributed,
}

impl ReadReason {
    fn op(self) -> Op {
        match self {
            ReadReason::Reconstruct => Op::BlockReadReconstruct,
            ReadReason::PeerServe => Op::BlockReadPeerServe,
            ReadReason::SendServe => Op::BlockReadSendServe,
            ReadReason::Validate => Op::BlockReadValidate,
            ReadReason::Compaction => Op::BlockReadCompaction,
            ReadReason::CustodyEvidence => Op::BlockReadCustodyEvidence,
            ReadReason::Unattributed => Op::BlockReadOther,
        }
    }
}

thread_local! {
    /// Thread-local rather than threaded through the store's signatures:
    /// the read site sits several layers below every caller, and the same
    /// argument that made the counters themselves a global applies here.
    ///
    /// Thread-local and not task-local deliberately. Every attributed read
    /// is a synchronous `pread` -- on a blocking thread where it is one
    /// (`spawn_blocking`), inside a straight-line loop where it is not --
    /// so the guard's scope never spans an await and a work-stealing
    /// runtime has nothing to move out from under it. A future caller that
    /// holds this across an await would misattribute, which is why
    /// [`ReadReason::Unattributed`] is counted rather than assumed empty.
    static READ_REASON: std::cell::Cell<ReadReason> =
        const { std::cell::Cell::new(ReadReason::Unattributed) };
}

/// Restores the previous reason when dropped, so nested scopes compose.
pub struct ReadReasonGuard(ReadReason);

impl Drop for ReadReasonGuard {
    fn drop(&mut self) {
        READ_REASON.with(|r| r.set(self.0));
    }
}

/// Attributes every block read taken on this thread, until the returned
/// guard drops, to `reason`.
///
/// Costs one thread-local store whether or not recording is armed. That is
/// deliberate: making it conditional would mean the reason could be stale
/// from an earlier armed run, and a wrong attribution is worse than a
/// missing one.
#[must_use = "attribution lasts only as long as the guard is held"]
pub fn attribute_reads(reason: ReadReason) -> ReadReasonGuard {
    ReadReasonGuard(READ_REASON.with(|r| r.replace(reason)))
}

/// Times one block read, recording it both in the [`Op::BlockRead`] total
/// and against whichever [`ReadReason`] is in scope on this thread.
#[inline]
pub fn time_block_read<T>(bytes: u64, f: impl FnOnce() -> T) -> T {
    if !enabled() {
        return f();
    }
    let start = Instant::now();
    let out = f();
    let nanos = start.elapsed().as_nanos() as u64;
    record(Op::BlockRead, nanos, bytes);
    let reason = READ_REASON.with(std::cell::Cell::get);
    record(reason.op(), nanos, bytes);
    if reason == ReadReason::Unattributed {
        probe_unattributed_caller();
    }
    out
}

/// How many unattributed-read backtraces to print. Enough to name the
/// caller; not so many that the log becomes the bottleneck.
const UNATTRIBUTED_PROBE_LIMIT: u64 = 6;
static UNATTRIBUTED_PROBED: AtomicU64 = AtomicU64::new(0);

/// Prints a backtrace for the first few reads that reached the store with
/// no reason set.
///
/// A temporary probe, and deliberately crude: the alternative was another
/// round of grepping for callers, which had already produced a plausible
/// and incomplete answer once -- the first attribution pass covered five
/// call sites and still left the growing reader unaccounted for. A
/// backtrace names it instead of narrowing it.
///
/// Only runs under `YADORILINK_DIAGNOSTIC_BLOCK_READ_PROBE=1`, and only
/// while counters are armed.
fn probe_unattributed_caller() {
    if UNATTRIBUTED_PROBED.load(Ordering::Relaxed) >= UNATTRIBUTED_PROBE_LIMIT {
        return;
    }
    static ARMED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if !ARMED.get_or_init(|| {
        std::env::var("YADORILINK_DIAGNOSTIC_BLOCK_READ_PROBE").as_deref() == Ok("1")
    }) {
        return;
    }
    let n = UNATTRIBUTED_PROBED.fetch_add(1, Ordering::Relaxed);
    if n >= UNATTRIBUTED_PROBE_LIMIT {
        return;
    }
    eprintln!("BLOCK_READ_UNATTRIBUTED #{n}\n{}", std::backtrace::Backtrace::force_capture());
}

/// Sub-buckets per power of two in the latency histogram. 8 gives ~12%
/// resolution, which is what it takes to tell a 3.6ms fsync from a 5.0ms
/// one -- plain log2 buckets put both in `[2.1ms, 4.2ms)` and answer the
/// question with "no change" no matter what happened.
const HIST_SUB_BITS: u32 = 3;
const HIST_SUB: usize = 1 << HIST_SUB_BITS;
/// Covers 1ns .. ~9.8 hours; anything longer saturates the last bucket.
const HIST_BUCKETS: usize = 64 * HIST_SUB;

/// Which bucket a duration falls in. Below `HIST_SUB` nanoseconds the
/// bucketing is exact (one bucket per nanosecond); above it, `exp` selects
/// the octave and the next `HIST_SUB_BITS` significant bits select the
/// sub-bucket.
#[inline]
fn hist_bucket(nanos: u64) -> usize {
    if nanos < HIST_SUB as u64 {
        return nanos as usize;
    }
    let exp = 63 - nanos.leading_zeros() as usize;
    let sub = (nanos >> (exp - HIST_SUB_BITS as usize)) as usize & (HIST_SUB - 1);
    (((exp - HIST_SUB_BITS as usize) + 1) * HIST_SUB + sub).min(HIST_BUCKETS - 1)
}

/// The lower bound of `bucket`, in nanoseconds -- what a percentile read
/// out of the histogram reports. Reporting the lower bound rather than a
/// midpoint keeps every quoted percentile a value the workload actually
/// reached or exceeded.
fn hist_bucket_floor(bucket: usize) -> u64 {
    if bucket < HIST_SUB {
        return bucket as u64;
    }
    let octave = (bucket / HIST_SUB) - 1;
    let sub = (bucket % HIST_SUB) as u64;
    (HIST_SUB as u64 + sub) << octave
}

static ENABLED: AtomicBool = AtomicBool::new(false);
static CALLS: [AtomicU64; OP_COUNT] = [const { AtomicU64::new(0) }; OP_COUNT];
static NANOS: [AtomicU64; OP_COUNT] = [const { AtomicU64::new(0) }; OP_COUNT];
static BYTES: [AtomicU64; OP_COUNT] = [const { AtomicU64::new(0) }; OP_COUNT];
/// Per-op latency distribution. Totals alone cannot distinguish "every
/// call got slower" from "a few calls got much slower", and those have
/// different causes -- a queue-depth sweep in particular is a question
/// about the SHAPE of fsync latency, not its mean.
static HIST: [[AtomicU64; HIST_BUCKETS]; OP_COUNT] =
    [const { [const { AtomicU64::new(0) }; HIST_BUCKETS] }; OP_COUNT];

/// Whether recording is armed. A single relaxed load; this is the entire
/// cost of an instrumentation site in a production binary.
#[inline(always)]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Arms or disarms recording process-wide. Only examples and tests call
/// this.
pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
}

/// Parents of directories fsynced after a publish, by path hash: how many
/// DISTINCT directories the run's publishes touched. Only touched when
/// armed, and only by the publish path, so the lock is off the hot path of
/// an unarmed process.
static PUBLISH_PARENTS: std::sync::Mutex<ParentSet> =
    std::sync::Mutex::new(ParentSet { set: None, saturated: false });

/// Most distinct directories remembered. Past it nothing more is inserted
/// and the count is a lower bound (see [`parent_dirs_saturated`]).
const PARENT_CAP: usize = 1_000_000;

struct ParentSet {
    set: Option<std::collections::HashSet<u64>>,
    saturated: bool,
}

impl ParentSet {
    fn note(&mut self, hash: u64, cap: usize) {
        let set = self.set.get_or_insert_with(Default::default);
        if set.len() >= cap {
            if !set.contains(&hash) {
                self.saturated = true;
            }
            return;
        }
        set.insert(hash);
    }

    fn count(&self) -> u64 {
        self.set.as_ref().map_or(0, |s| s.len() as u64)
    }
}

/// Notes that a directory fsync was issued for `dir`. No-op when unarmed.
pub fn note_dir_fsync(dir: &std::path::Path) {
    if !enabled() {
        return;
    }
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    dir.hash(&mut hasher);
    PUBLISH_PARENTS.lock().unwrap_or_else(|p| p.into_inner()).note(hasher.finish(), PARENT_CAP);
}

/// How many distinct directories [`note_dir_fsync`] has seen; a lower bound
/// when [`parent_dirs_saturated`].
pub fn distinct_parent_dirs() -> u64 {
    PUBLISH_PARENTS.lock().unwrap_or_else(|p| p.into_inner()).count()
}

/// Whether the directory set hit its cap and stopped growing.
pub fn parent_dirs_saturated() -> bool {
    PUBLISH_PARENTS.lock().unwrap_or_else(|p| p.into_inner()).saturated
}

#[cfg(test)]
mod parent_set_tests {
    use super::ParentSet;

    #[test]
    fn the_set_stops_growing_at_its_cap_and_reports_saturation() {
        let mut p = ParentSet { set: None, saturated: false };
        for h in 0..3 {
            p.note(h, 3);
        }
        p.note(1, 3);
        assert!(!p.saturated, "a repeat at the cap is not an overflow");
        p.note(99, 3);
        assert!(p.saturated);
        assert_eq!(p.count(), 3);
    }
}

/// Zeroes every counter. Call between measured runs.
pub fn reset() {
    *PUBLISH_PARENTS.lock().unwrap_or_else(|p| p.into_inner()) =
        ParentSet { set: None, saturated: false };
    for i in 0..OP_COUNT {
        CALLS[i].store(0, Ordering::Relaxed);
        NANOS[i].store(0, Ordering::Relaxed);
        BYTES[i].store(0, Ordering::Relaxed);
        for bucket in &HIST[i] {
            bucket.store(0, Ordering::Relaxed);
        }
    }
}

/// Latency percentiles for one op, in nanoseconds, as bucket floors.
/// `quantiles` are fractions in `0.0..=1.0`. An op with no recorded calls
/// reports zeros.
pub fn percentiles(op: Op, quantiles: &[f64]) -> Vec<u64> {
    let i = op as usize;
    let counts: Vec<u64> = HIST[i].iter().map(|b| b.load(Ordering::Relaxed)).collect();
    let total: u64 = counts.iter().sum();
    if total == 0 {
        return vec![0; quantiles.len()];
    }
    quantiles
        .iter()
        .map(|q| {
            // Rank is 1-based: q=0.5 of 100 calls is the 50th call, not
            // the 50th index, so a p50 can never report a bucket the
            // workload only reached once.
            let target = ((q.clamp(0.0, 1.0) * total as f64).ceil() as u64).max(1);
            let mut seen = 0u64;
            for (bucket, count) in counts.iter().enumerate() {
                seen += count;
                if seen >= target {
                    return hist_bucket_floor(bucket);
                }
            }
            hist_bucket_floor(HIST_BUCKETS - 1)
        })
        .collect()
}

/// Records one occurrence of `op`. Cheap enough to call unconditionally
/// once `enabled()` has already been checked.
#[inline]
pub fn record(op: Op, nanos: u64, bytes: u64) {
    let i = op as usize;
    CALLS[i].fetch_add(1, Ordering::Relaxed);
    NANOS[i].fetch_add(nanos, Ordering::Relaxed);
    BYTES[i].fetch_add(bytes, Ordering::Relaxed);
    HIST[i][hist_bucket(nanos)].fetch_add(1, Ordering::Relaxed);
}

/// Runs `f`, timing it as `op` when recording is armed. When it is not,
/// this is `f()` plus one relaxed atomic load -- in particular no
/// `Instant::now()`, which is the only part with a cost worth avoiding on
/// a per-block path.
#[inline]
pub fn time<T>(op: Op, bytes: u64, f: impl FnOnce() -> T) -> T {
    if !enabled() {
        return f();
    }
    let start = Instant::now();
    let out = f();
    record(op, start.elapsed().as_nanos() as u64, bytes);
    out
}

/// One operation class's totals.
#[derive(Clone, Copy, Debug)]
pub struct OpStat {
    pub name: &'static str,
    pub calls: u64,
    pub nanos: u64,
    pub bytes: u64,
}

/// Reads every counter. Not atomic across ops -- take it while the
/// measured work is finished, not while it is running.
pub fn snapshot() -> Vec<OpStat> {
    (0..OP_COUNT)
        .map(|i| OpStat {
            name: OP_NAMES[i],
            calls: CALLS[i].load(Ordering::Relaxed),
            nanos: NANOS[i].load(Ordering::Relaxed),
            bytes: BYTES[i].load(Ordering::Relaxed),
        })
        .collect()
}

/// Reads a single counter.
pub fn stat(op: Op) -> OpStat {
    let i = op as usize;
    OpStat {
        name: OP_NAMES[i],
        calls: CALLS[i].load(Ordering::Relaxed),
        nanos: NANOS[i].load(Ordering::Relaxed),
        bytes: BYTES[i].load(Ordering::Relaxed),
    }
}

#[cfg(test)]
mod tests;
