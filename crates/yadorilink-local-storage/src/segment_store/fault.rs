//! A test-only seam for stopping a group commit dead at any one of its
//! ordered boundaries, leaving the on-disk state exactly as a power loss
//! at that instant would.
//!
//! Crash safety here is entirely a property of an *ordering* -- append,
//! fsync the segment, commit the index, only then report durability -- so
//! the only way to test it is to cut the sequence at each boundary and
//! reopen the store. Nothing about that can be observed from the outside
//! after the fact: a store that recovered correctly and a store that never
//! crashed look identical, which is the point.
//!
//! When a fault trips, the commit returns an error **and the store is
//! poisoned**: every later call fails. That is what makes the injection
//! faithful. A real crash does not unwind, does not truncate its own
//! half-written record, and does not get to run another commit -- so
//! neither does this. The test then drops the poisoned handle and opens a
//! fresh store over the same directory, which is exactly what a restart
//! does.
//!
//! Not `#[cfg(test)]`-gated: the crash matrix lives in this crate's
//! `tests/` directory (a separate compilation unit) and other crates'
//! durability-ordering tests reach for the same seam. The cost in a
//! shipping binary is one `Option` check per boundary, against a field
//! nothing ever sets.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::error::StorageError;

/// The ordered boundaries of one group commit. The sequence is fixed and
/// total -- every commit passes through these in exactly this order -- so
/// injecting at each in turn covers the whole crash surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommitPoint {
    /// Before any byte of the group is written.
    BeforeAppend,
    /// A new segment file exists (staged under a reserved name where the
    /// volume offers durable moves) but is not published under its name.
    AfterSegmentStaged,
    /// The new segment is published under its name and that is durable; no
    /// records written.
    AfterSegmentPublished,
    /// Part of the group's records reached the file. See
    /// [`FaultPlan::partial_append_bytes`].
    MidRecordAppend,
    /// Every record is written, none of it is fsynced.
    AfterAppendBeforeFsync,
    /// The segment is fsynced; the index transaction has not begun.
    AfterFsyncBeforeIndex,
    /// Inside the index transaction, after some rows are staged.
    DuringIndexTransaction,
    /// The index transaction committed; the caller has not been told.
    AfterIndexCommitBeforeReceipt,
    /// Mid-roll-over: the old segment is full and being sealed.
    DuringRollover,
}

impl CommitPoint {
    /// Every boundary, for a test that sweeps the whole sequence.
    pub const ALL: [CommitPoint; 9] = [
        CommitPoint::BeforeAppend,
        CommitPoint::AfterSegmentStaged,
        CommitPoint::AfterSegmentPublished,
        CommitPoint::MidRecordAppend,
        CommitPoint::AfterAppendBeforeFsync,
        CommitPoint::AfterFsyncBeforeIndex,
        CommitPoint::DuringIndexTransaction,
        CommitPoint::AfterIndexCommitBeforeReceipt,
        CommitPoint::DuringRollover,
    ];
}

/// One armed injection.
#[derive(Debug)]
pub struct FaultPlan {
    point: CommitPoint,
    /// For [`CommitPoint::MidRecordAppend`]: how many bytes of the group's
    /// record buffer actually reach the file before the crash. `None`
    /// means half of it, rounded down, which lands inside a record for any
    /// group of more than one block and inside the payload for one.
    partial_append_bytes: Option<usize>,
    /// How many more times this plan fires. A commit that must survive its
    /// own retry arms more than one.
    remaining: AtomicUsize,
    /// Whether a real I/O error is raised instead of a clean halt -- the
    /// ENOSPC/EIO shape, where the process keeps running and the store must
    /// stay usable and honest.
    survivable: bool,
    /// Whether the rollback's segment-index lookup fails once, modelling a
    /// transient index read error during cleanup of a failed commit.
    fail_rollback_index_read: AtomicBool,
}

impl FaultPlan {
    /// A crash at `point`: the commit fails and the store stops serving.
    pub fn crash_at(point: CommitPoint) -> Self {
        Self {
            point,
            partial_append_bytes: None,
            remaining: AtomicUsize::new(1),
            survivable: false,
            fail_rollback_index_read: AtomicBool::new(false),
        }
    }

    /// An I/O failure at `point` that the process survives: the commit
    /// fails, nothing is reported durable, and the store must remain
    /// correct and usable afterwards.
    pub fn io_failure_at(point: CommitPoint) -> Self {
        Self {
            point,
            partial_append_bytes: None,
            remaining: AtomicUsize::new(1),
            survivable: true,
            fail_rollback_index_read: AtomicBool::new(false),
        }
    }

    /// How much of the group's record buffer reaches disk before a
    /// [`CommitPoint::MidRecordAppend`] crash.
    #[must_use]
    pub fn with_partial_append_bytes(mut self, bytes: usize) -> Self {
        self.partial_append_bytes = Some(bytes);
        self
    }

    /// Also makes the rollback's segment-index lookup fail once, so a test
    /// can prove that an index read error never grants deletion authority.
    #[must_use]
    pub fn with_rollback_index_read_failure(self) -> Self {
        self.fail_rollback_index_read.store(true, Ordering::Relaxed);
        self
    }

    pub(crate) fn take_rollback_index_read_failure(&self) -> bool {
        self.fail_rollback_index_read.swap(false, Ordering::AcqRel)
    }

    /// Arms this plan for `count` commits rather than one.
    #[must_use]
    pub fn firing(self, count: usize) -> Self {
        self.remaining.store(count, Ordering::Relaxed);
        self
    }

    pub(crate) fn point(&self) -> CommitPoint {
        self.point
    }

    pub(crate) fn is_survivable(&self) -> bool {
        self.survivable
    }

    pub(crate) fn partial_bytes(&self, buffered: usize) -> usize {
        self.partial_append_bytes.unwrap_or(buffered / 2).min(buffered)
    }

    /// Consumes one firing, returning whether this call is the one that
    /// trips.
    pub(crate) fn take_firing(&self, point: CommitPoint) -> bool {
        if point != self.point {
            return false;
        }
        self.remaining
            .try_update(Ordering::AcqRel, Ordering::Acquire, |left| {
                left.checked_sub(1).filter(|_| left > 0)
            })
            .is_ok()
    }
}

/// The error a tripped fault raises. Deliberately an ordinary
/// `StorageError::Io`, because the production paths that have to stay
/// correct under it are the ones that handle real I/O failure -- a bespoke
/// variant would let a caller distinguish an injected failure from a real
/// one, which is the opposite of what this is for.
pub(crate) fn fault_error(point: CommitPoint, survivable: bool) -> StorageError {
    let shape = if survivable { "recoverable I/O failure" } else { "crash" };
    StorageError::Io(std::io::Error::other(format!("injected block-store {shape} at {point:?}")))
}
