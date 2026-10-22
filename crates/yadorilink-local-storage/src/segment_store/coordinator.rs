//! Group commit: the one writer that turns many callers' blocks into one
//! durability barrier.
//!
//! # Why there is exactly one writer
//!
//! Durability cost here is not bandwidth, it is *barriers*. A 100k
//! small-file import writes about 5 MB of payload and pays for it with
//! 100,000 `fsync`s, at 3.6-4.8 ms each on the reference host. Hashing and
//! reading can be as parallel as the caller likes; the append order and
//! the barrier cannot, because the whole saving is that N blocks share one
//! barrier. Concentrating appends in one writer is also what structurally
//! removes the append-offset race a multi-writer packed store has to
//! defend against: there is no shared offset to race for.
//!
//! # Leader/follower, not a background thread
//!
//! A submitting caller either finds a commit already in progress -- and
//! waits, its blocks joining the group that commit's successor will take
//! -- or becomes the leader and commits the group itself. No dedicated
//! thread exists, so there is nothing to start, stop, supervise, or
//! schedule, and a store that is idle costs nothing. Batching comes from
//! the physics: while the leader is inside its `fsync`, every other
//! producer's blocks pile up behind it, and the next leader takes all of
//! them.
//!
//! # The three bounds
//!
//! - **blocks** ([`GroupCommitLimits::max_blocks`]) is what binds for tiny
//!   files, where a group is thousands of blocks and a few hundred KiB;
//! - **bytes** ([`GroupCommitLimits::max_bytes`]) is what binds for large
//!   files, where a handful of blocks is already tens of MiB;
//! - **delay** ([`GroupCommitLimits::max_delay`]) bounds how long a leader
//!   will linger for more work before committing what it has.
//!
//! Lingering is *conditional*, and deliberately so: a leader waits only
//! when the previous group actually absorbed more than one caller, i.e.
//! when there is live evidence of concurrent producers. A lone interactive
//! write therefore waits for its own barrier and nothing else, while a
//! saturated import keeps forming full groups. An unconditional linger
//! would tax exactly the workload that cannot benefit from batching.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use crate::error::StorageError;
use crate::io_diag::{self, Op};
use crate::segment_store::fault::{fault_error, CommitPoint, FaultPlan};
use crate::segment_store::format::{
    record_len, RAW_HASH_LEN, RECORD_HEADER_LEN, SEGMENT_HEADER_LEN,
};
use crate::segment_store::index::{
    BlockIndex, BlockLocation, GroupCommitPlan, NewBlockRow, RelocationPlan, SegmentAppend,
    SegmentState,
};
use crate::segment_store::segment::{
    read_record_payload, segment_path, RecordFrame, RecordReadError, SegmentWriter, SEGMENTS_DIR,
};
use crate::segment_store::{remove_judged, VolumeVerdict};
use crate::traits::{ContentHash, LocallyHashedBlock};

/// Proof that one block is durable: it names where the bytes are, and it
/// exists only on the far side of the segment `fsync` and the index
/// transaction that recorded it. Nothing upstream -- a `FileRecord`, a native state
/// change, group provenance -- may become authoritative before its blocks'
/// receipts are in hand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableReceipt {
    pub hash: ContentHash,
    pub segment_id: u64,
    /// Offset of the block's payload within its segment file.
    pub offset: u64,
    pub length: u32,
    /// Whether the store already held this content, so this commit wrote
    /// no new bytes for it. Durability is identical either way -- the
    /// existing copy was itself durable before it was ever indexed.
    pub deduplicated: bool,
}

/// The three bounds a group commit forms under. Not per-workload tuning:
/// each bound exists because a different shape of workload reaches it
/// first, and all three are in force for every workload.
#[derive(Debug, Clone, Copy)]
pub struct GroupCommitLimits {
    pub max_blocks: usize,
    pub max_bytes: u64,
    pub max_delay: Duration,
    /// Bytes allowed to sit in the queue before a submitter is made to
    /// wait. Backpressure, not a batch bound: it caps the memory a burst
    /// of producers can pin, and never makes a single oversized request
    /// undeliverable.
    pub queue_max_bytes: u64,
    /// Roll over to a new segment once one reaches this size. Large enough
    /// that roll-over is rare (so almost every group costs exactly one
    /// barrier), small enough that compacting one segment is a bounded
    /// amount of work.
    pub segment_target_bytes: u64,
}

impl Default for GroupCommitLimits {
    fn default() -> Self {
        Self {
            max_blocks: 4096,
            max_bytes: 64 * 1024 * 1024,
            max_delay: Duration::from_millis(5),
            queue_max_bytes: 256 * 1024 * 1024,
            segment_target_bytes: 1024 * 1024 * 1024,
        }
    }
}

impl GroupCommitLimits {
    /// The defaults, with any bound a diagnostic environment variable
    /// overrides.
    ///
    /// A **measurement seam, not a tuning knob**. Whether a given host's
    /// storage absorbs a wider group is a property of that storage, and
    /// the only way to find out is to sweep it there, on a real workload,
    /// with one binary -- so that "different build" is never a variable in
    /// the comparison. Hard-coding whatever one machine's sweep liked is
    /// precisely the mistake this exists to avoid, which is why nothing in
    /// a shipping binary sets any of these and unset is exactly
    /// [`GroupCommitLimits::default`].
    ///
    /// A value that does not parse, or parses to zero, is ignored rather
    /// than honoured: zero would make every group empty or every segment
    /// roll over on its first record.
    pub fn from_env() -> Self {
        fn override_usize(name: &str, default: usize) -> usize {
            std::env::var(name)
                .ok()
                .and_then(|raw| raw.trim().parse::<usize>().ok())
                .filter(|&value| value > 0)
                .unwrap_or(default)
        }
        fn override_u64(name: &str, default: u64) -> u64 {
            std::env::var(name)
                .ok()
                .and_then(|raw| raw.trim().parse::<u64>().ok())
                .filter(|&value| value > 0)
                .unwrap_or(default)
        }
        let defaults = Self::default();
        Self {
            max_blocks: override_usize(
                "YADORILINK_DIAGNOSTIC_GROUP_MAX_BLOCKS",
                defaults.max_blocks,
            ),
            max_bytes: override_u64("YADORILINK_DIAGNOSTIC_GROUP_MAX_BYTES", defaults.max_bytes),
            max_delay: Duration::from_micros(override_u64(
                "YADORILINK_DIAGNOSTIC_GROUP_MAX_DELAY_US",
                defaults.max_delay.as_micros() as u64,
            )),
            queue_max_bytes: override_u64(
                "YADORILINK_DIAGNOSTIC_GROUP_QUEUE_MAX_BYTES",
                defaults.queue_max_bytes,
            ),
            segment_target_bytes: override_u64(
                "YADORILINK_DIAGNOSTIC_SEGMENT_TARGET_BYTES",
                defaults.segment_target_bytes,
            ),
        }
    }
}

/// One caller's outstanding submission.
struct PendingRequest {
    id: u64,
    blocks: Arc<Vec<LocallyHashedBlock>>,
    bytes: u64,
}

#[derive(Default)]
struct QueueState {
    pending: VecDeque<PendingRequest>,
    pending_bytes: u64,
    leader_active: bool,
    completed: HashMap<u64, Result<Vec<DurableReceipt>, StorageError>>,
    next_request_id: u64,
    /// Whether the previous group absorbed more than one caller -- the
    /// only evidence a leader uses to decide whether lingering can pay.
    linger_next: bool,
}

/// State only whoever holds writer leadership may touch.
struct WriterState {
    active: Option<SegmentWriter>,
    next_segment_id: u64,
}

/// The store's single durability writer.
pub(crate) struct DurabilityCoordinator {
    root: PathBuf,
    index: Arc<BlockIndex>,
    limits: GroupCommitLimits,
    queue: Mutex<QueueState>,
    /// Signalled on every enqueue and on every leadership handover.
    ready: Condvar,
    /// Signalled whenever a group leaves the queue, freeing its bytes.
    not_full: Condvar,
    writer: Mutex<WriterState>,
    fault: Mutex<Option<Arc<FaultPlan>>>,
    /// Test hook run after a group's new blocks are durable and before its dedup hits are
    /// stamped.
    before_dedup_stamp_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// Set when an injected crash fires. Models the process being gone:
    /// nothing else this handle is asked to do may succeed afterwards.
    halted: AtomicBool,
    /// Whether the volume of the segments directory may have bytes deleted from it; asked at
    /// every rollback truncation or unlink (see [`Self::roll_back_one`]).
    volume_durable: Mutex<VolumeVerdict>,
}

impl DurabilityCoordinator {
    pub(crate) fn new(
        root: PathBuf,
        index: Arc<BlockIndex>,
        limits: GroupCommitLimits,
        next_segment_id: u64,
        volume_durable: VolumeVerdict,
    ) -> Self {
        Self {
            volume_durable: Mutex::new(volume_durable),
            root,
            index,
            limits,
            queue: Mutex::new(QueueState::default()),
            ready: Condvar::new(),
            not_full: Condvar::new(),
            writer: Mutex::new(WriterState { active: None, next_segment_id }),
            fault: Mutex::new(None),
            before_dedup_stamp_hook: Mutex::new(None),
            halted: AtomicBool::new(false),
        }
    }

    pub(crate) fn set_volume_verdict(&self, verdict: VolumeVerdict) {
        *self.volume_durable.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = verdict;
    }

    fn volume_verdict(&self) -> VolumeVerdict {
        Arc::clone(&*self.volume_durable.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
    }

    pub(crate) fn limits(&self) -> GroupCommitLimits {
        self.limits
    }

    pub(crate) fn arm_fault(&self, plan: Option<Arc<FaultPlan>>) {
        *self.fault.lock().unwrap_or_else(|p| p.into_inner()) = plan;
    }

    pub(crate) fn install_before_dedup_stamp_hook(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        *self.before_dedup_stamp_hook.lock().unwrap_or_else(|p| p.into_inner()) = Some(hook);
    }

    pub(crate) fn is_halted(&self) -> bool {
        self.halted.load(Ordering::Acquire)
    }

    fn ensure_running(&self) -> Result<(), StorageError> {
        if self.is_halted() {
            return Err(StorageError::Io(std::io::Error::other(
                "block store halted by an injected crash; a real process would be gone",
            )));
        }
        Ok(())
    }

    /// Consults the armed fault plan at one boundary. Returns the error to
    /// fail with, having already halted the store if the plan models a
    /// crash rather than a survivable I/O failure.
    fn check_fault(&self, point: CommitPoint) -> Option<StorageError> {
        let plan = self.fault.lock().unwrap_or_else(|p| p.into_inner()).clone()?;
        if !plan.take_firing(point) {
            return None;
        }
        if !plan.is_survivable() {
            self.halted.store(true, Ordering::Release);
        }
        Some(fault_error(point, plan.is_survivable()))
    }

    fn take_rollback_index_read_fault(&self) -> bool {
        let plan = self.fault.lock().unwrap_or_else(|p| p.into_inner()).clone();
        plan.is_some_and(|plan| plan.take_rollback_index_read_failure())
    }

    fn armed_partial_append(&self, buffered: usize) -> Option<usize> {
        let plan = self.fault.lock().unwrap_or_else(|p| p.into_inner()).clone()?;
        (plan.point() == CommitPoint::MidRecordAppend).then(|| plan.partial_bytes(buffered))
    }

    /// Submits `blocks` for durable commit and returns only once every one
    /// of them is durable (or the group failed). The caller's own blocks
    /// are what the returned receipts describe; whichever other callers'
    /// blocks shared the barrier are invisible here.
    pub(crate) fn submit(
        &self,
        blocks: Arc<Vec<LocallyHashedBlock>>,
    ) -> Result<Vec<DurableReceipt>, StorageError> {
        self.ensure_running()?;
        if blocks.is_empty() {
            return Ok(Vec::new());
        }
        let bytes: u64 = blocks.iter().map(|block| block.bytes().len() as u64).sum();

        let mut queue = self.queue.lock().unwrap_or_else(|p| p.into_inner());
        // Backpressure. A single request larger than the whole budget is
        // admitted rather than parked forever: the queue can only drain by
        // committing, and there is nothing else in it to commit.
        while queue.pending_bytes + bytes > self.limits.queue_max_bytes && !queue.pending.is_empty()
        {
            queue = self.not_full.wait(queue).unwrap_or_else(|p| p.into_inner());
        }
        let id = queue.next_request_id;
        queue.next_request_id += 1;
        queue.pending.push_back(PendingRequest { id, blocks, bytes });
        queue.pending_bytes += bytes;
        self.ready.notify_all();

        loop {
            if let Some(result) = queue.completed.remove(&id) {
                return result;
            }
            if !queue.leader_active {
                queue.leader_active = true;
                let (guard, group) = self.take_group(queue);
                drop(guard);

                // Leadership is released by a guard, not by the line after
                // the commit: a panic anywhere in the commit path would
                // otherwise leave `leader_active` set forever, and every
                // caller that ever submits again -- including the ones
                // already parked -- would wait on a leader that no longer
                // exists. A wedged store is a worse outcome than a
                // propagated panic.
                let leadership = Leadership { coordinator: self };
                let outcome = self.commit_group(&group);
                drop(leadership);

                let mut relocked = self.queue.lock().unwrap_or_else(|p| p.into_inner());
                relocked.linger_next = group.len() >= 2;
                self.publish_group_results(&mut relocked, &group, outcome);
                self.ready.notify_all();
                queue = relocked;
                continue;
            }
            queue = self.ready.wait(queue).unwrap_or_else(|p| p.into_inner());
        }
    }

    /// Closes the segment currently being appended to. The next group
    /// starts a fresh one, and the sealed segment becomes eligible for
    /// compaction -- which never touches an active segment, since its dead
    /// ratio is not yet meaningful.
    pub(crate) fn seal_active_segment(&self) -> Result<(), StorageError> {
        self.with_writer_leadership(|coordinator, handle| {
            let Some(active) = handle.state.active.take() else { return Ok(()) };
            coordinator.index.set_segment_state(active.segment_id, SegmentState::Sealed)
        })
    }

    /// Runs `body` with exclusive writer leadership, serialized against
    /// every group commit. Compaction uses this so relocation appends land
    /// in the same single-writer order as ingest appends and can never
    /// interleave with one.
    pub(crate) fn with_writer_leadership<T>(
        &self,
        body: impl FnOnce(&Self, &mut WriterHandle<'_>) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        self.ensure_running()?;
        let mut queue = self.queue.lock().unwrap_or_else(|p| p.into_inner());
        while queue.leader_active {
            queue = self.ready.wait(queue).unwrap_or_else(|p| p.into_inner());
        }
        queue.leader_active = true;
        drop(queue);

        // Released by the guard -- see the same guard's use in `submit`
        // for why a panic here must not wedge every future caller.
        let leadership = Leadership { coordinator: self };
        let result = {
            let mut writer = self.writer.lock().unwrap_or_else(|p| p.into_inner());
            let mut handle = WriterHandle { state: &mut writer };
            body(self, &mut handle)
        };
        drop(leadership);
        result
    }

    /// Takes the next group out of the queue, lingering for late arrivals
    /// only under the conditions this module's doc comment describes.
    fn take_group<'a>(
        &self,
        mut queue: MutexGuard<'a, QueueState>,
    ) -> (MutexGuard<'a, QueueState>, Vec<PendingRequest>) {
        let deadline = Instant::now() + self.limits.max_delay;
        let mut group: Vec<PendingRequest> = Vec::new();
        let mut blocks = 0usize;
        let mut bytes = 0u64;
        loop {
            while let Some(front) = queue.pending.front() {
                let would_exceed = blocks + front.blocks.len() > self.limits.max_blocks
                    || bytes + front.bytes > self.limits.max_bytes;
                if would_exceed && !group.is_empty() {
                    break;
                }
                let request = queue.pending.pop_front().expect("front was Some");
                blocks += request.blocks.len();
                bytes += request.bytes;
                queue.pending_bytes -= request.bytes;
                group.push(request);
            }
            self.not_full.notify_all();

            let full = blocks >= self.limits.max_blocks || bytes >= self.limits.max_bytes;
            if full || !queue.linger_next || group.is_empty() {
                break;
            }
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let (woken, _) =
                self.ready.wait_timeout(queue, deadline - now).unwrap_or_else(|p| p.into_inner());
            queue = woken;
            if queue.pending.is_empty() {
                break;
            }
        }
        (queue, group)
    }

    /// Hands each request in the group its own receipts, or a faithful
    /// copy of the group's failure.
    fn publish_group_results(
        &self,
        queue: &mut QueueState,
        group: &[PendingRequest],
        outcome: Result<HashMap<[u8; RAW_HASH_LEN], DurableReceipt>, StorageError>,
    ) {
        match outcome {
            Ok(receipts) => {
                for request in group {
                    let mut own = Vec::with_capacity(request.blocks.len());
                    let mut failure = None;
                    for block in request.blocks.iter() {
                        match raw_hash(block.hash()).ok().and_then(|raw| receipts.get(&raw)) {
                            Some(receipt) => own.push(receipt.clone()),
                            None => {
                                failure = Some(StorageError::Io(std::io::Error::other(format!(
                                    "group commit produced no receipt for block {}",
                                    block.hash()
                                ))));
                                break;
                            }
                        }
                    }
                    queue.completed.insert(request.id, failure.map_or(Ok(own), Err));
                }
            }
            Err(error) => {
                for request in group {
                    queue.completed.insert(request.id, Err(error.duplicate()));
                }
            }
        }
    }

    /// The whole ordered commit sequence, for one group.
    ///
    /// 1. deduplicate within the group,
    /// 2. deduplicate against the index,
    /// 3. append every remaining record to a segment,
    /// 4. `fsync` each touched segment (normally exactly one),
    /// 5. commit the mappings and segment accounting in one transaction,
    /// 6. only then return receipts.
    ///
    /// Reversing 4 and 5 would be the one change that breaks the store's
    /// central invariant, so the two are adjacent here and nothing may be
    /// inserted between them that can fail independently.
    fn commit_group(
        &self,
        group: &[PendingRequest],
    ) -> Result<HashMap<[u8; RAW_HASH_LEN], DurableReceipt>, StorageError> {
        self.ensure_running()?;
        let payload_bytes: u64 = group.iter().map(|request| request.bytes).sum();
        io_diag::time(Op::GroupCommit, payload_bytes, || self.commit_group_inner(group))
    }

    fn commit_group_inner(
        &self,
        group: &[PendingRequest],
    ) -> Result<HashMap<[u8; RAW_HASH_LEN], DurableReceipt>, StorageError> {
        // (1) Within-group deduplication. Two callers asking for the same
        // content in one group must produce one record and two identical
        // receipts, never two records.
        let mut unique_hashes: Vec<[u8; RAW_HASH_LEN]> = Vec::new();
        let mut unique_blocks: Vec<&LocallyHashedBlock> = Vec::new();
        let mut seen: HashSet<[u8; RAW_HASH_LEN]> = HashSet::new();
        for request in group {
            for block in request.blocks.iter() {
                let raw = raw_hash(block.hash())?;
                if seen.insert(raw) {
                    unique_hashes.push(raw);
                    unique_blocks.push(block);
                }
            }
        }

        // (2) Deduplication against what the store already holds.
        let existing =
            io_diag::time(Op::IndexDedupe, 0, || self.index.lookup_many(&unique_hashes))?;

        let mut receipts: HashMap<[u8; RAW_HASH_LEN], DurableReceipt> = HashMap::new();
        let mut to_write: Vec<([u8; RAW_HASH_LEN], &LocallyHashedBlock)> = Vec::new();
        let mut hits: Vec<([u8; RAW_HASH_LEN], &LocallyHashedBlock, BlockLocation)> = Vec::new();
        let mut damaged_segments: Vec<u64> = Vec::new();
        for ((hash, block), location) in
            unique_hashes.iter().zip(unique_blocks.iter()).zip(existing.iter())
        {
            match location {
                // A hit is only a hit if the stored copy reads back as these bytes. If the
                // row is there but its bytes are not, this put carries the correct ones:
                // retract the claim and write them afresh.
                Some(location) if self.mapping_is_damaged(hash, block, location)? => {
                    tracing::error!(
                        block = block.hash().as_str(),
                        "indexed block does not read back on a dedup hit; rewriting it"
                    );
                    damaged_segments.push(location.segment_id);
                    if self.index.remove_block_at(hash, location)? {
                        to_write.push((*hash, block));
                    } else {
                        // The row moved since it was looked up (repaired by someone else):
                        // not ours to retract. Treat it as a hit; the stamp below reads
                        // the current location, and rewrites only if it is gone.
                        hits.push((*hash, *block, *location));
                    }
                }
                Some(location) => hits.push((*hash, *block, *location)),
                None => to_write.push((*hash, block)),
            }
        }

        // A hit verified in a segment that another hit of this group found damaged is read
        // back once more (the file may have vanished in between); only a copy that no longer
        // reads back is retracted and rewritten, a healthy one stays a hit.
        let mut verified_hits = Vec::with_capacity(hits.len());
        for (hash, block, location) in hits {
            if damaged_segments.contains(&location.segment_id)
                && self.mapping_is_damaged(&hash, block, &location)?
                && self.index.remove_block_at(&hash, &location)?
            {
                to_write.push((hash, block));
            } else {
                verified_hits.push((hash, block));
            }
        }
        let hits = verified_hits;

        if !damaged_segments.is_empty() {
            // Never append through the open handle of a segment found damaged (its file may
            // be gone, and a write to an unlinked handle is durable nowhere): seal it and
            // let the rewrite open a fresh segment.
            let mut writer = self.writer.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(active) =
                writer.active.take_if(|active| damaged_segments.contains(&active.segment_id))
            {
                self.index.set_segment_state(active.segment_id, SegmentState::Sealed)?;
            }
        }

        if !to_write.is_empty() {
            if let Some(error) = self.check_fault(CommitPoint::BeforeAppend) {
                return Err(error);
            }
            let mut writer = self.writer.lock().unwrap_or_else(|p| p.into_inner());
            self.append_and_record(&mut writer, &to_write, &mut receipts)?;
        }

        // A block this put found already stored is stamped as added now, after everything
        // else the group did, in the transaction that reads its location: the grace window
        // it is promised starts when the receipt is about to be returned, not when the group
        // began, and a sweep that removes blocks checks the stamp again. A block that is gone
        // by then is written afresh.
        if !hits.is_empty() {
            let hook =
                self.before_dedup_stamp_hook.lock().unwrap_or_else(|p| p.into_inner()).clone();
            if let Some(hook) = hook {
                hook();
            }
            let hit_hashes: Vec<[u8; RAW_HASH_LEN]> = hits.iter().map(|(hash, _)| *hash).collect();
            let stamped = io_diag::time(Op::IndexDedupe, 0, || {
                self.index.lookup_many_refreshing(&hit_hashes, unix_nanos_now())
            })?;
            let mut gone: Vec<([u8; RAW_HASH_LEN], &LocallyHashedBlock)> = Vec::new();
            for ((hash, block), location) in hits.iter().zip(stamped.iter()) {
                match location {
                    Some(location) => {
                        receipts.insert(
                            *hash,
                            DurableReceipt {
                                hash: block.hash().clone(),
                                segment_id: location.segment_id,
                                offset: location.payload_offset(),
                                length: location.length,
                                deduplicated: true,
                            },
                        );
                    }
                    None => gone.push((*hash, *block)),
                }
            }
            if !gone.is_empty() {
                let mut writer = self.writer.lock().unwrap_or_else(|p| p.into_inner());
                self.append_and_record(&mut writer, &gone, &mut receipts)?;
            }
        }
        Ok(receipts)
    }

    /// Whether the bytes behind an indexed location are missing or do not read back as the
    /// block `block` carries. A dedup hit is only a hit if the stored copy is good; anything
    /// but a clean read of identical bytes is damage (a real I/O error is returned instead).
    fn mapping_is_damaged(
        &self,
        raw: &[u8; RAW_HASH_LEN],
        block: &LocallyHashedBlock,
        location: &BlockLocation,
    ) -> Result<bool, StorageError> {
        let file = match std::fs::File::open(segment_path(&self.root, location.segment_id)) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(e) => return Err(StorageError::Io(e)),
        };
        match read_record_payload(&file, location, raw) {
            Ok(payload) => Ok(payload != block.bytes()),
            Err(RecordReadError::Io(e)) => Err(e),
            Err(_) => Ok(true),
        }
    }

    /// Steps (3)-(5): lay the records out, write them, one barrier per
    /// touched segment, one transaction.
    fn append_and_record(
        &self,
        writer: &mut WriterState,
        to_write: &[([u8; RAW_HASH_LEN], &LocallyHashedBlock)],
        receipts: &mut HashMap<[u8; RAW_HASH_LEN], DurableReceipt>,
    ) -> Result<(), StorageError> {
        // `lay_out_and_commit` takes the open segment out of `writer` and
        // carries it -- along with any further segment a roll-over opened
        // -- through the group. Handing them all back here is what lets
        // the failure path undo *every* segment the group touched, not
        // just the last one.
        let mut batches = Vec::new();
        let outcome = self.lay_out_and_commit(writer, to_write, receipts, &mut batches);
        self.finish_batches(writer, batches, outcome.is_err());
        outcome
    }

    /// Settles the segments a group touched, once it has either committed
    /// or failed.
    ///
    /// On success the last one stays open for the next group. On a
    /// survivable failure every one of them is rolled back to what the
    /// index records -- which for a segment the group created means
    /// deleting it, and for the segment it continued means truncating the
    /// group's bytes away. Handling only the last would leave an orphan
    /// tail on the first whenever a group rolled over, which is exactly
    /// the physical/logical divergence the retired packed-store prototype
    /// had: a failed append that left the file longer than the metadata
    /// said, serving wrong bytes from the next offset until a restart.
    ///
    /// A *crash* rolls nothing back, deliberately. Undoing is work a dead
    /// process cannot do, so pretending otherwise would test a recovery
    /// path that never runs. Recovery truncates the tail at the next open.
    fn finish_batches(
        &self,
        writer: &mut WriterState,
        mut batches: Vec<OpenBatch<'_>>,
        failed: bool,
    ) {
        if !failed || self.is_halted() {
            writer.active = batches.pop().map(|batch| batch.writer);
            return;
        }
        // Earliest first, so the survivor -- if there is one, it is the
        // segment this group continued rather than created -- is the one
        // that stays open.
        let mut survivor = None;
        for batch in batches {
            if let Some(segment) = self.roll_back_one(batch) {
                survivor = survivor.or(Some(segment));
            }
        }
        writer.active = survivor;
    }

    /// Undoes one segment's share of a failed group, returning the segment
    /// if it is still usable afterwards.
    ///
    /// Bytes are only ever deleted on proof. The segment file is removed
    /// only when this very batch created it *and* the index was read
    /// successfully and holds no row for it. A segment with a committed row
    /// is cut back to that row's `durable_end`; if the truncation fails it
    /// is sealed and left to recovery, which has to handle an orphan tail
    /// regardless. An index read failure, or a pre-existing segment the
    /// index does not know, is uncertainty about committed state and
    /// preserves the file: recovery truncates or reports it at the next
    /// open, never this path by deletion.
    fn roll_back_one(&self, batch: OpenBatch<'_>) -> Option<SegmentWriter> {
        let created = batch.created;
        let mut segment = batch.writer;
        let segment_id = segment.segment_id;
        let lookup = if self.take_rollback_index_read_fault() {
            Err(StorageError::Io(std::io::Error::other("injected index read failure in rollback")))
        } else {
            self.index.segment(segment_id)
        };
        match lookup {
            Ok(Some(row)) => {
                // Cutting bytes needs the verdict of the volume this open file is on. Refused
                // (or failed): seal and leave the tail to recovery, which is gated the same way.
                let verdict = self.volume_verdict();
                let judged = segment
                    .judge_volume(&segment_path(&self.root, segment_id), |dir| verdict(Some(dir)));
                if judged && segment.truncate(row.durable_end).is_ok() {
                    Some(segment)
                } else {
                    let _ = self.index.set_segment_state(segment_id, SegmentState::Sealed);
                    None
                }
            }
            Ok(None) if created => {
                let path = segment_path(&self.root, segment_id);
                drop(segment);
                let _ = remove_judged(&self.volume_verdict(), &path);
                None
            }
            Ok(None) | Err(_) => {
                // Preserve the bytes; best-effort seal so no writer
                // continues into a segment whose committed prefix is
                // unproven.
                drop(segment);
                let _ = self.index.set_segment_state(segment_id, SegmentState::Sealed);
                None
            }
        }
    }

    fn lay_out_and_commit<'a>(
        &self,
        writer: &mut WriterState,
        to_write: &[([u8; RAW_HASH_LEN], &'a LocallyHashedBlock)],
        receipts: &mut HashMap<[u8; RAW_HASH_LEN], DurableReceipt>,
        batches: &mut Vec<OpenBatch<'a>>,
    ) -> Result<(), StorageError> {
        let added_at = unix_nanos_now();
        let mut sealed: Vec<u64> = Vec::new();

        // Destructured by value, not by reference: `block` has to come out
        // as the `&'a LocallyHashedBlock` the slice holds, so the payload
        // slice a frame borrows lives as long as the caller's blocks do
        // rather than only as long as this loop's borrow of the slice.
        for &(hash, block) in to_write {
            let payload = block.bytes();
            let needed = record_len(payload.len());

            // Roll-over has to be decided against whichever segment this
            // record would actually land in: the batch this group already
            // opened, or -- for the group's first record -- the segment
            // left open by an earlier group. Checking only the former is
            // the mistake that lets a store fed one block at a time grow a
            // single unbounded segment, since such a group's first record
            // is also its last and never sees an already-open batch.
            let roll_over = match batches.last() {
                Some(batch) => batch.would_overflow(needed, &self.limits),
                None => writer
                    .active
                    .as_ref()
                    .is_some_and(|active| would_overflow(active.write_end(), needed, &self.limits)),
            };
            if roll_over {
                if let Some(error) = self.check_fault(CommitPoint::DuringRollover) {
                    return Err(error);
                }
                let outgoing = match batches.last() {
                    Some(batch) => batch.writer.segment_id,
                    None => writer.active.as_ref().expect("checked above").segment_id,
                };
                sealed.push(outgoing);
            }
            if batches.is_empty() || roll_over {
                let batch = self.open_batch(writer, roll_over)?;
                batches.push(batch);
            }

            let batch = batches.last_mut().expect("just ensured");
            let record_offset = batch.next_offset();
            batch.stage(
                RecordFrame::new(&hash, payload),
                NewBlockRow {
                    hash,
                    record_offset,
                    payload_len: payload.len() as u32,
                    record_len: needed,
                    added_at_nanos: added_at,
                },
            );
        }

        // (3)+(4). Every batch is written and fsynced before the index
        // transaction begins, which is the ordering the whole design rests
        // on.
        if let Some(error) = self.check_fault(CommitPoint::MidRecordAppend) {
            let staged: usize = batches.iter().map(|batch| batch.staged_bytes as usize).sum();
            let mut left = self.armed_partial_append(staged).unwrap_or(staged / 2);
            for batch in batches.iter_mut() {
                batch.writer.append_partial_frames_for_tests(&batch.frames, left)?;
                left = left.saturating_sub(batch.staged_bytes as usize);
            }
            return Err(error);
        }
        for batch in batches.iter_mut() {
            let frames = std::mem::take(&mut batch.frames);
            batch.writer.append_frames(&frames)?;
        }
        if let Some(error) = self.check_fault(CommitPoint::AfterAppendBeforeFsync) {
            return Err(error);
        }
        for batch in batches.iter() {
            batch.writer.sync()?;
        }
        if let Some(error) = self.check_fault(CommitPoint::AfterFsyncBeforeIndex) {
            return Err(error);
        }

        // (5).
        let plan = GroupCommitPlan {
            appends: batches
                .iter()
                .map(|batch| SegmentAppend {
                    segment_id: batch.writer.segment_id,
                    created: batch.created,
                    durable_end: batch.writer.write_end(),
                    blocks: batch.rows.clone(),
                })
                .collect(),
            sealed,
            next_segment_id: writer.next_segment_id,
        };
        let mid_transaction =
            || self.check_fault(CommitPoint::DuringIndexTransaction).map(|e| e.to_string());
        io_diag::time(Op::IndexCommit, 0, || self.index.commit_group(&plan, &mid_transaction))?;

        if let Some(error) = self.check_fault(CommitPoint::AfterIndexCommitBeforeReceipt) {
            return Err(error);
        }

        for batch in batches.iter() {
            for row in &batch.rows {
                receipts.insert(
                    row.hash,
                    DurableReceipt {
                        hash: hex::encode(row.hash),
                        segment_id: batch.writer.segment_id,
                        offset: row.record_offset + RECORD_HEADER_LEN as u64,
                        length: row.payload_len,
                        deduplicated: false,
                    },
                );
            }
        }

        Ok(())
    }

    /// Opens the batch the next records go into: the already-open active
    /// segment, or a brand new one (whose directory entry this publishes
    /// before any record is written into it).
    fn open_batch<'a>(
        &self,
        writer: &mut WriterState,
        force_new: bool,
    ) -> Result<OpenBatch<'a>, StorageError> {
        if !force_new {
            if let Some(active) = writer.active.take() {
                return Ok(OpenBatch::existing(active));
            }
        } else {
            writer.active = None;
        }
        let segment_id = writer.next_segment_id;
        writer.next_segment_id += 1;
        let segment = self.create_segment(segment_id)?;
        Ok(OpenBatch::created(segment))
    }

    /// A brand-new segment, published under its name with its header on disk.
    ///
    /// Where the volume offers durable moves the file is staged under a
    /// reserved name beside its final one, its header flushed, and published
    /// by a durable move, so the name never refers to a file without a whole
    /// header and is on disk when this returns. Elsewhere it is created in
    /// place and the directory is synced. A file whose directory entry is not
    /// durable is not reachable after a crash, however well fsynced its own
    /// contents are; one such barrier per segment created, not per group and
    /// not per block.
    fn create_segment(&self, segment_id: u64) -> Result<SegmentWriter, StorageError> {
        let path = segment_path(&self.root, segment_id);
        let Some(ns) = crate::fs_ops::durable_namespace_beside(&path)? else {
            let segment = SegmentWriter::create(&self.root, segment_id)?;
            if let Some(error) = self.check_fault(CommitPoint::AfterSegmentStaged) {
                return Err(error);
            }
            io_diag::time(Op::SegmentDirFsync, 0, || {
                crate::fs_ops::sync_directory(&self.root.join(SEGMENTS_DIR))
            })?;
            if let Some(error) = self.check_fault(CommitPoint::AfterSegmentPublished) {
                return Err(error);
            }
            return Ok(segment);
        };
        let staged = SegmentWriter::stage(&self.root, segment_id)?;
        if let Some(error) = self.check_fault(CommitPoint::AfterSegmentStaged) {
            return Err(error);
        }
        let segment = io_diag::time(Op::SegmentDirFsync, 0, || staged.publish(&ns))?;
        if let Some(error) = self.check_fault(CommitPoint::AfterSegmentPublished) {
            return Err(error);
        }
        Ok(segment)
    }

    /// Appends relocated copies of `blocks` and swaps every mapping onto
    /// them in one transaction -- compaction's commit, using the same
    /// append-fsync-then-index ordering an ingest commit uses.
    pub(crate) fn commit_relocation(
        &self,
        handle: &mut WriterHandle<'_>,
        sources: &[u64],
        blocks: &[(ContentHash, [u8; RAW_HASH_LEN], Vec<u8>)],
    ) -> Result<usize, StorageError> {
        if blocks.is_empty() {
            return Ok(0);
        }
        let added_at = unix_nanos_now();
        let mut batches: Vec<OpenBatch<'_>> = Vec::new();
        let mut sealed = Vec::new();
        for (_, raw, payload) in blocks {
            let needed = record_len(payload.len());
            let roll_over =
                batches.last().is_some_and(|batch| batch.would_overflow(needed, &self.limits));
            if roll_over {
                sealed.push(batches.last().expect("checked").writer.segment_id);
            }
            if batches.is_empty() || roll_over {
                batches.push(self.open_batch(handle.state, roll_over)?);
            }
            let batch = batches.last_mut().expect("just ensured");
            let record_offset = batch.next_offset();
            batch.stage(
                RecordFrame::new(raw, payload),
                NewBlockRow {
                    hash: *raw,
                    record_offset,
                    payload_len: payload.len() as u32,
                    record_len: needed,
                    added_at_nanos: added_at,
                },
            );
        }

        let result = (|| -> Result<usize, StorageError> {
            for batch in &mut batches {
                let frames = std::mem::take(&mut batch.frames);
                batch.writer.append_frames(&frames)?;
            }
            if let Some(error) = self.check_fault(CommitPoint::AfterAppendBeforeFsync) {
                return Err(error);
            }
            for batch in &batches {
                batch.writer.sync()?;
            }
            if let Some(error) = self.check_fault(CommitPoint::AfterFsyncBeforeIndex) {
                return Err(error);
            }
            let plan = RelocationPlan {
                group: GroupCommitPlan {
                    appends: batches
                        .iter()
                        .map(|batch| SegmentAppend {
                            segment_id: batch.writer.segment_id,
                            created: batch.created,
                            durable_end: batch.writer.write_end(),
                            blocks: batch.rows.clone(),
                        })
                        .collect(),
                    sealed: sealed.clone(),
                    next_segment_id: handle.state.next_segment_id,
                },
                sources: sources.to_vec(),
            };
            let mid_transaction =
                || self.check_fault(CommitPoint::DuringIndexTransaction).map(|e| e.to_string());
            self.index.commit_relocation(&plan, &mid_transaction)?;
            Ok(blocks.len())
        })();

        self.finish_batches(handle.state, batches, result.is_err());
        result
    }
}

/// Holds writer leadership for as long as it lives, and hands it back on
/// the way out -- including while a panic unwinds.
///
/// Leadership is what serializes every append in the process, so a leader
/// that stops existing without clearing the flag stops the store
/// permanently: the queue keeps filling, and everyone waits on a leader
/// that is gone. Tying the release to a scope rather than to a statement
/// is what makes "the leader finished, however it finished" the condition
/// that matters.
struct Leadership<'a> {
    coordinator: &'a DurabilityCoordinator,
}

impl Drop for Leadership<'_> {
    fn drop(&mut self) {
        let mut queue = self.coordinator.queue.lock().unwrap_or_else(|p| p.into_inner());
        queue.leader_active = false;
        drop(queue);
        self.coordinator.ready.notify_all();
    }
}

/// Exclusive access to the writer's own state, handed to whoever holds
/// leadership. Exists so compaction can append without the coordinator
/// exposing its internals to the whole module tree.
pub(crate) struct WriterHandle<'a> {
    state: &'a mut WriterState,
}

/// One segment's share of a group: the writer, the record frames destined
/// for it, and the index rows those records will become.
///
/// Frames rather than one contiguous buffer: a frame borrows its payload
/// from the caller's own block, so laying out a group costs the framing
/// bytes and nothing else, however large the payloads are.
struct OpenBatch<'a> {
    writer: SegmentWriter,
    created: bool,
    frames: Vec<RecordFrame<'a>>,
    staged_bytes: u64,
    rows: Vec<NewBlockRow>,
}

impl<'a> OpenBatch<'a> {
    fn existing(writer: SegmentWriter) -> Self {
        Self { writer, created: false, frames: Vec::new(), staged_bytes: 0, rows: Vec::new() }
    }

    fn created(writer: SegmentWriter) -> Self {
        Self { writer, created: true, frames: Vec::new(), staged_bytes: 0, rows: Vec::new() }
    }

    /// Where the next record in this batch will land.
    fn next_offset(&self) -> u64 {
        self.writer.write_end() + self.staged_bytes
    }

    fn stage(&mut self, frame: RecordFrame<'a>, row: NewBlockRow) {
        self.staged_bytes += frame.len();
        self.frames.push(frame);
        self.rows.push(row);
    }

    /// Whether one more record of `needed` bytes would carry this segment
    /// past its target size.
    fn would_overflow(&self, needed: u64, limits: &GroupCommitLimits) -> bool {
        would_overflow(self.next_offset(), needed, limits)
    }
}

/// Whether appending `needed` more bytes to a segment that currently ends
/// at `end` should roll over instead.
///
/// A segment that holds nothing yet never overflows, however large the
/// record is: a record is never split across segments, so rolling over an
/// empty one would loop forever on any block bigger than the target.
fn would_overflow(end: u64, needed: u64, limits: &GroupCommitLimits) -> bool {
    end > SEGMENT_HEADER_LEN && end + needed > limits.segment_target_bytes
}

/// Decodes a hex content hash into the raw key the index and the record
/// framing both use.
pub(crate) fn raw_hash(hex_hash: &str) -> Result<[u8; RAW_HASH_LEN], StorageError> {
    if hex_hash.len() != RAW_HASH_LEN * 2
        || !hex_hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(StorageError::InvalidPath(format!("not a valid content hash: {hex_hash:?}")));
    }
    let mut out = [0u8; RAW_HASH_LEN];
    hex::decode_to_slice(hex_hash, &mut out)?;
    Ok(out)
}

fn unix_nanos_now() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

/// The store root's `segments/` directory, created and published once at
/// open so no group commit ever has to.
pub(crate) fn ensure_segments_directory(root: &Path) -> Result<(), StorageError> {
    let segments = root.join(SEGMENTS_DIR);
    if !segments.exists() {
        crate::fs_ops::create_dir_all_durably(&segments)?;
        crate::fs_ops::sync_directory(root)?;
    }
    Ok(())
}
