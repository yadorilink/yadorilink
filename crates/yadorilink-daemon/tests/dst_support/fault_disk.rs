//! A deterministic, seed-driven disk-fault decorator for any `BlockStore`.
//! Disk faults in DST scenarios used to be hand-wired per scenario: each
//! scenario grew its own bespoke faulting store with an ad hoc schedule,
//! which both duplicated code and made the fault behavior non-portable
//! between scenarios. `FaultingBlockStore` is the shared, reusable seam:
//! it wraps *any* `BlockStore` (an `Arc<SegmentBlockStore>` or an `Arc<dyn
//! BlockStore + Send + Sync>`) and injects the storage-layer fault classes
//! on a deterministic predicate over `(op, per-op sequence, seed)` — never
//! wall-clock time and never a live RNG at apply time, so a run replays
//! byte-for-byte from the serialized `DiskFaultPlan` alone. This mirrors
//! the network-side decorator's discipline: a pure, fully unit-testable
//! decision engine (`DiskFaultPlan::decide`) sits behind a thin wrapper
//! that applies the decision at the real trait seam. The fault classes
//! (from the shared IR's `DiskFault`) map as follows: - `Enospc` -> `put`
//! returns the crate's disk-full error (`StorageError::DiskPressure`),
//! before any bytes are written. - `Eio` -> an I/O error on `put` or
//! `get`. - `TornWrite` -> `put` reports success and returns the *correct*
//! content hash, but the block is persisted truncated/corrupted, so a
//! later `get` reads back short/wrong bytes (a `ChecksumMismatch` from the
//! verifying read, short bytes from `get_unchecked`). This is what
//! exercises the no-silent-corruption oracle. - `SlowIo` -> a
//! deterministic `tokio::time::sleep` before the op that advances only the
//! simulated clock. Because `BlockStore` is a synchronous trait, a sync
//! method cannot `.await`; the delay is applied by the async wrappers
//! (`put_faulted`/`get_faulted`), exactly as the network decorator returns
//! a `Delay` decision for its async caller to apply. Through the plain
//! synchronous trait a `SlowIo` decision degrades to a transparent
//! pass-through (documented on each method). - `FsyncFail` is
//! intentionally NOT implemented here: the `BlockStore` trait exposes no
//! separate durability/flush/fsync step to fail (a write is
//! durable-or-erroring as one call), so there is no honest surface for it
//! at this layer. It is left to a future backend that exposes an explicit
//! sync point. - `SqliteBusy` / `SqliteLocked` are index-database faults,
//! not block-store faults; they belong to a future faulting `SyncState`
//! wrapper and are deliberately out of scope for this decorator.

#![allow(dead_code)] // not every op/wrapper has a producer in every scenario

use std::collections::HashMap;
use std::collections::HashSet;
use std::io::{Error as IoError, ErrorKind};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use yadorilink_local_storage::free_space::VolumeFreeSpace;
use yadorilink_local_storage::{BlockStore, ContentHash, GcReport, StorageError, StorageUsage};

use super::content_hash;
use super::fault_schedule::{FaultClass, ScheduledInjectors};

/// Which block-store operation a decision is being made for. The fault
/// predicate keys off this so, e.g., "torn write" only ever applies to a
/// write and "disk full" never applies to a read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiskOp {
    Put,
    Get,
    Delete,
    Exists,
    List,
}

impl DiskOp {
    /// A write op — the only kind that can run out of space or tear.
    fn is_write(self) -> bool {
        matches!(self, DiskOp::Put)
    }
    /// An op that moves block bytes to/from disk, and so can raise EIO.
    fn is_io(self) -> bool {
        matches!(self, DiskOp::Put | DiskOp::Get)
    }
}

/// What should happen to one block-store operation. Precedence, when a
/// single op matches more than one rule, is `Enospc` > `Eio` > `Torn` >
/// `Slow` > `Proceed` (a hard failure wins over a slow success), mirroring
/// the network decorator's drop > duplicate > delay ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskDecision {
    /// Run the op against the wrapped store, unmodified.
    Proceed,
    /// Reject a write with the disk-full error before writing any bytes.
    Enospc,
    /// Fail the op with an I/O error.
    Eio,
    /// Persist the block truncated/corrupted while reporting success, so a
    /// later read observes the tear.
    Torn,
    /// Sleep `nanos` of simulated time before running the op (advances the
    /// virtual clock only). Only applied through the async wrappers.
    Slow { nanos: i64 },
}

/// The seed-driven disk-fault schedule a `FaultingBlockStore` replays.
///
/// Deliberately schedule-based, not RNG-at-apply-time: "every Nth op of a
/// class" is exactly reproducible from these numbers alone, so a replay
/// faults the same operations in the same order without re-deriving an RNG
/// stream. A generator seeds the `*_every` values; from there application
/// is pure. `Default` (all zero) injects no faults, so a scenario that
/// wants a clean store just wraps it with `DiskFaultPlan::default()`.
///
/// Serializable so a recorded corpus entry fully describes its disk
/// behavior and replays identically, matching the network plan's shape.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskFaultPlan {
    /// Reject every Nth write with the disk-full error (0 = never).
    pub enospc_every: u32,
    /// Fail every Nth read/write with an I/O error (0 = never).
    pub eio_every: u32,
    /// Tear every Nth write — persist it corrupted while reporting success
    /// (0 = never).
    pub torn_write_every: u32,
    /// Slow every Nth op by `slow_io_nanos` of simulated time (0 = never).
    pub slow_io_every: u32,
    /// The simulated delay a slowed op waits before running.
    pub slow_io_nanos: i64,
}

impl DiskFaultPlan {
    /// Decides the fate of the `seq`-th op of kind `op` (1-based per op
    /// kind). Pure and side-effect-free: the same `(op, seq)` against the
    /// same plan always yields the same decision — the property that makes
    /// a replay exact. Op eligibility gates each class (a read can neither
    /// run out of space nor tear), then precedence resolves overlaps.
    pub fn decide(&self, op: DiskOp, seq: u64) -> DiskDecision {
        if op.is_write() && hits(self.enospc_every, seq) {
            return DiskDecision::Enospc;
        }
        if op.is_io() && hits(self.eio_every, seq) {
            return DiskDecision::Eio;
        }
        if op.is_write() && hits(self.torn_write_every, seq) {
            return DiskDecision::Torn;
        }
        if hits(self.slow_io_every, seq) {
            return DiskDecision::Slow { nanos: self.slow_io_nanos };
        }
        DiskDecision::Proceed
    }
}

fn hits(every: u32, n: u64) -> bool {
    every != 0 && n % every as u64 == 0
}

/// Truncates/corrupts `data` so the result never re-hashes to the original
/// content hash — i.e. a genuinely observable tear regardless of input
/// length (an empty or single-byte block is corrupted by a byte flip, a
/// longer one by keeping only its first half).
fn tear(data: &[u8]) -> Vec<u8> {
    if data.len() > 1 {
        data[..data.len() / 2].to_vec()
    } else {
        vec![data.first().copied().unwrap_or(0) ^ 0xFF]
    }
}

fn io_error(msg: &str) -> StorageError {
    StorageError::Io(IoError::new(ErrorKind::Other, msg))
}

/// Per-op 1-based sequence counters. Each op kind advances independently so
/// "every Nth put" stays well-defined regardless of interleaved reads.
#[derive(Default)]
struct OpCounters {
    put: AtomicU64,
    get: AtomicU64,
    delete: AtomicU64,
    exists: AtomicU64,
    list: AtomicU64,
}

impl OpCounters {
    fn next(&self, op: DiskOp) -> u64 {
        let counter = match op {
            DiskOp::Put => &self.put,
            DiskOp::Get => &self.get,
            DiskOp::Delete => &self.delete,
            DiskOp::Exists => &self.exists,
            DiskOp::List => &self.list,
        };
        counter.fetch_add(1, Ordering::SeqCst) + 1
    }
}

/// A `BlockStore` decorator that injects `DiskFaultPlan`'s faults onto a
/// wrapped store. `S` is `?Sized` so the same type wraps both a concrete
/// `Arc<SegmentBlockStore>` and a type-erased `Arc<dyn BlockStore + Send + Sync>`
/// with no changes at the call site.
///
/// Torn blocks live in an in-decorator overlay rather than the wrapped
/// store: a torn write never becomes a valid durable block underneath, so
/// the overlay both records the corrupted bytes a later read must observe
/// and lets `exists` report the (corrupt) block as present, modelling "the
/// block file is there but its contents are bad".
pub struct FaultingBlockStore<S: BlockStore + ?Sized = dyn BlockStore + Send + Sync> {
    inner: Arc<S>,
    plan: DiskFaultPlan,
    counters: OpCounters,
    torn: Mutex<HashMap<ContentHash, Vec<u8>>>,
    /// The scheduled injectors this store reads its live plan from and
    /// credits at decision time. `None` for a fixed-plan store.
    seam: Option<ScheduledInjectors>,
}

impl<S: BlockStore + ?Sized> FaultingBlockStore<S> {
    /// A fixed-plan store. It reports to no ledger, so a gated test that uses
    /// it earns no credit: use [`scheduled`](Self::scheduled).
    pub fn new(inner: Arc<S>, plan: DiskFaultPlan) -> Self {
        Self {
            inner,
            plan,
            counters: OpCounters::default(),
            torn: Mutex::new(HashMap::new()),
            seam: None,
        }
    }

    /// A store bound to the scheduler's live plan: each operation is decided
    /// against the plan open at that moment and credits the ledger entry whose
    /// window is open at that moment, from here and not from the caller.
    pub fn scheduled(inner: Arc<S>, injectors: &ScheduledInjectors) -> Self {
        let mut store = Self::new(inner, injectors.disk_plan());
        store.seam = Some(injectors.clone());
        store
    }

    /// The one decision point: advances the per-op sequence, decides against
    /// the live plan (if bound) and credits the ledger.
    fn decide(&self, op: DiskOp, delay_applies: bool) -> DiskDecision {
        let seq = self.counters.next(op);
        let decision = match &self.seam {
            Some(seam) => seam.disk_plan().decide(op, seq),
            None => self.plan.decide(op, seq),
        };
        if let Some(seam) = &self.seam {
            let class = match decision {
                DiskDecision::Proceed => None,
                DiskDecision::Enospc => Some(FaultClass::DiskEnospc),
                DiskDecision::Eio => Some(FaultClass::DiskEio),
                DiskDecision::Torn => Some(FaultClass::DiskTorn),
                // A slow decision is a fault only where the delay is really applied
                // (the async wrappers); the sync trait methods pass it through.
                DiskDecision::Slow { .. } => delay_applies.then_some(FaultClass::DiskSlow),
            };
            if let Some(class) = class {
                seam.credit(class);
            }
        }
        decision
    }

    /// The plan this decorator replays.
    pub fn plan(&self) -> &DiskFaultPlan {
        &self.plan
    }

    fn torn_lock(&self) -> std::sync::MutexGuard<'_, HashMap<ContentHash, Vec<u8>>> {
        self.torn.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// If `hash` names a torn block, returns the read result it must yield:
    /// a `ChecksumMismatch` under a verifying read (the corrupt bytes no
    /// longer hash to `hash`), or the raw short bytes when `verify` is off
    /// (the `get_unchecked` fast path, faithfully returning corruption).
    fn torn_read(&self, hash: &str, verify: bool) -> Option<Result<Vec<u8>, StorageError>> {
        let map = self.torn_lock();
        let bytes = map.get(hash)?;
        if verify {
            let actual = content_hash(bytes);
            if actual != hash {
                return Some(Err(StorageError::ChecksumMismatch {
                    expected: hash.to_string(),
                    actual,
                }));
            }
        }
        Some(Ok(bytes.clone()))
    }

    /// Applies a write decision (all but the async-only `Slow` delay, which
    /// the caller has already awaited when relevant).
    fn apply_put(&self, decision: DiskDecision, data: &[u8]) -> Result<ContentHash, StorageError> {
        match decision {
            DiskDecision::Enospc => Err(StorageError::DiskPressure {
                path: PathBuf::from("<faulted-block>"),
                volume: PathBuf::from("<simulated-volume>"),
                available_bytes: 0,
                headroom_bytes: (data.len() as u64).max(1),
            }),
            DiskDecision::Eio => Err(io_error("simulated I/O failure on put")),
            DiskDecision::Torn => {
                // Report success with the correct hash, but persist the
                // block corrupted so a later read observes the tear.
                let hash = content_hash(data);
                self.torn_lock().insert(hash.clone(), tear(data));
                Ok(hash)
            }
            DiskDecision::Slow { .. } | DiskDecision::Proceed => self.inner.put(data),
        }
    }

    /// Applies a read decision.
    fn apply_get(&self, decision: DiskDecision, hash: &str) -> Result<Vec<u8>, StorageError> {
        match decision {
            DiskDecision::Eio => Err(io_error("simulated I/O failure on get")),
            // Enospc/Torn are not eligible for reads; Slow/Proceed both run.
            _ => self.inner.get(hash),
        }
    }

    /// Async, full-fidelity `put`: applies the whole decision including a
    /// `SlowIo` virtual-time delay that the synchronous trait cannot. A
    /// scenario running on the simulated runtime uses this to exercise
    /// `SlowIo`; code holding only `&dyn BlockStore` gets the synchronous
    /// faults through the trait `put`.
    pub async fn put_faulted(&self, data: &[u8]) -> Result<ContentHash, StorageError> {
        let decision = self.decide(DiskOp::Put, true);
        if let DiskDecision::Slow { nanos } = decision {
            tokio::time::sleep(Duration::from_nanos(nanos.max(0) as u64)).await;
        }
        self.apply_put(decision, data)
    }

    /// Async, full-fidelity `get` (see [`put_faulted`](Self::put_faulted)).
    pub async fn get_faulted(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        if let Some(result) = self.torn_read(hash, true) {
            return result;
        }
        let decision = self.decide(DiskOp::Get, true);
        if let DiskDecision::Slow { nanos } = decision {
            tokio::time::sleep(Duration::from_nanos(nanos.max(0) as u64)).await;
        }
        self.apply_get(decision, hash)
    }
}

impl<S: BlockStore + ?Sized> BlockStore for FaultingBlockStore<S> {
    fn put(&self, data: &[u8]) -> Result<ContentHash, StorageError> {
        // A `Slow` decision degrades to a pass-through here: a sync method
        // cannot await the simulated-clock sleep — use `put_faulted` for
        // the time-domain fault.
        let decision = self.decide(DiskOp::Put, false);
        self.apply_put(decision, data)
    }

    fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        if let Some(result) = self.torn_read(hash, true) {
            return result;
        }
        // `Slow` degrades to a pass-through (see `put`).
        let decision = self.decide(DiskOp::Get, false);
        self.apply_get(decision, hash)
    }

    fn get_unchecked(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        // Faithful to the trait's "no re-verification" fast path: no fault
        // is scheduled here, but a torn block still reads back its raw
        // short/corrupt bytes.
        if let Some(result) = self.torn_read(hash, false) {
            return result;
        }
        self.inner.get_unchecked(hash)
    }

    fn delete(&self, hash: &str) -> Result<(), StorageError> {
        self.torn_lock().remove(hash);
        self.inner.delete(hash)
    }

    fn exists(&self, hash: &str) -> Result<bool, StorageError> {
        if self.torn_lock().contains_key(hash) {
            return Ok(true);
        }
        self.inner.exists(hash)
    }

    fn list_by_prefix(&self, prefix: &str) -> Result<Vec<ContentHash>, StorageError> {
        self.inner.list_by_prefix(prefix)
    }

    fn usage(&self) -> Result<StorageUsage, StorageError> {
        self.inner.usage()
    }

    fn sweep(
        &self,
        live: &HashSet<ContentHash>,
        grace_cutoff: SystemTime,
        dry_run: bool,
    ) -> Result<GcReport, StorageError> {
        self.inner.sweep(live, grace_cutoff, dry_run)
    }

    fn present_blocks(&self, hashes: &[ContentHash]) -> Result<Vec<bool>, StorageError> {
        self.inner.present_blocks(hashes)
    }

    fn set_headroom_enforced(&self, enforced: bool) {
        self.inner.set_headroom_enforced(enforced);
    }

    fn set_headroom_override_bytes(&self, headroom_bytes: Option<u64>) {
        self.inner.set_headroom_override_bytes(headroom_bytes);
    }

    fn free_space(&self) -> Result<Option<VolumeFreeSpace>, StorageError> {
        self.inner.free_space()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_local_storage::SegmentBlockStore;

    fn fs_store() -> (tempfile::TempDir, Arc<SegmentBlockStore>) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(SegmentBlockStore::new(dir.path()).unwrap());
        (dir, store)
    }

    // ---- pure decision-engine tests (no I/O, no async) ----

    #[test]
    fn each_fault_fires_on_its_scheduled_ordinal_and_is_a_noop_otherwise() {
        let plan = DiskFaultPlan {
            enospc_every: 4,
            eio_every: 3,
            torn_write_every: 2,
            slow_io_every: 5,
            slow_io_nanos: 100,
        };
        // Writes, by ordinal, resolving precedence enospc>eio>torn>slow:
        assert_eq!(plan.decide(DiskOp::Put, 1), DiskDecision::Proceed);
        assert_eq!(plan.decide(DiskOp::Put, 2), DiskDecision::Torn); // 2%2==0
        assert_eq!(plan.decide(DiskOp::Put, 3), DiskDecision::Eio); // 3%3==0
        assert_eq!(plan.decide(DiskOp::Put, 4), DiskDecision::Enospc); // 4%4==0 wins over torn(4%2==0)
        assert_eq!(plan.decide(DiskOp::Put, 5), DiskDecision::Slow { nanos: 100 });
        // ordinal 6 trips both eio (6%3==0) and torn (6%2==0); eio precedes.
        assert_eq!(plan.decide(DiskOp::Put, 6), DiskDecision::Eio);
    }

    #[test]
    fn eio_precedes_torn_on_a_write_that_matches_both() {
        // ordinal 6: eio_every=3 (6%3==0) and torn_write_every=2 (6%2==0);
        // eio has precedence.
        let plan = DiskFaultPlan { eio_every: 3, torn_write_every: 2, ..Default::default() };
        assert_eq!(plan.decide(DiskOp::Put, 6), DiskDecision::Eio);
    }

    #[test]
    fn reads_can_only_eio_or_slow_never_enospc_or_tear() {
        let plan = DiskFaultPlan {
            enospc_every: 1,
            eio_every: 3,
            torn_write_every: 1,
            slow_io_every: 2,
            slow_io_nanos: 7,
        };
        // enospc/torn are write-only, so a read on an ordinal that would
        // trip them still only sees the read-eligible classes.
        assert_eq!(plan.decide(DiskOp::Get, 1), DiskDecision::Proceed); // enospc/torn ineligible
        assert_eq!(plan.decide(DiskOp::Get, 2), DiskDecision::Slow { nanos: 7 });
        assert_eq!(plan.decide(DiskOp::Get, 3), DiskDecision::Eio);
        // A non-io op (delete/exists/list) can only ever be slowed.
        assert_eq!(plan.decide(DiskOp::Delete, 3), DiskDecision::Proceed);
        assert_eq!(plan.decide(DiskOp::Delete, 2), DiskDecision::Slow { nanos: 7 });
    }

    #[test]
    fn the_same_plan_replays_an_identical_decision_sequence() {
        let plan = DiskFaultPlan {
            enospc_every: 4,
            eio_every: 3,
            torn_write_every: 2,
            slow_io_every: 5,
            slow_io_nanos: 100,
        };
        let run = |p: &DiskFaultPlan| {
            (1..=12u64)
                .flat_map(|n| [p.decide(DiskOp::Put, n), p.decide(DiskOp::Get, n)])
                .collect::<Vec<_>>()
        };
        assert_eq!(run(&plan), run(&plan), "the same DiskFaultPlan must replay identically");
    }

    #[test]
    fn disk_fault_plan_round_trips_through_json() {
        let plan = DiskFaultPlan {
            enospc_every: 9,
            eio_every: 0,
            torn_write_every: 3,
            slow_io_every: 2,
            slow_io_nanos: 250,
        };
        let json = serde_json::to_string(&plan).unwrap();
        let restored: DiskFaultPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(plan, restored);
    }

    // ---- synchronous trait-seam tests (Enospc/Eio/TornWrite) ----

    #[test]
    fn a_default_plan_is_a_transparent_passthrough() {
        let (_dir, fs) = fs_store();
        let store = FaultingBlockStore::new(fs, DiskFaultPlan::default());
        let hash = store.put(b"clean bytes").unwrap();
        assert_eq!(store.get(&hash).unwrap(), b"clean bytes");
        assert!(store.exists(&hash).unwrap());
    }

    #[test]
    fn enospc_makes_a_scheduled_put_return_the_disk_full_error() {
        let (_dir, fs) = fs_store();
        let store =
            FaultingBlockStore::new(fs, DiskFaultPlan { enospc_every: 1, ..Default::default() });
        match store.put(b"needs space") {
            Err(StorageError::DiskPressure { .. }) => {}
            other => panic!("expected DiskPressure, got {other:?}"),
        }
    }

    #[test]
    fn eio_surfaces_on_both_put_and_get() {
        // put path: first put faults.
        let (_dir, fs) = fs_store();
        let store = FaultingBlockStore::new(
            fs.clone(),
            DiskFaultPlan { eio_every: 1, ..Default::default() },
        );
        assert!(matches!(store.put(b"x"), Err(StorageError::Io(_))));

        // get path: seed a real block directly through the inner store (no
        // fault), then read it through a decorator that faults every get.
        let (_dir2, fs2) = fs_store();
        let hash = fs2.put(b"readable").unwrap();
        let store2 =
            FaultingBlockStore::new(fs2, DiskFaultPlan { eio_every: 1, ..Default::default() });
        assert!(matches!(store2.get(&hash), Err(StorageError::Io(_))));
    }

    #[test]
    fn a_torn_write_reports_success_but_is_observable_by_a_subsequent_get() {
        let (_dir, fs) = fs_store();
        let store = FaultingBlockStore::new(
            fs,
            DiskFaultPlan { torn_write_every: 1, ..Default::default() },
        );
        let data = b"the full, intact block payload";
        // The write "succeeds" and returns the correct hash of the full data.
        let hash = store.put(data).unwrap();
        assert_eq!(hash, content_hash(data), "torn write still returns the true content hash");

        // A verifying read observes the corruption as a checksum mismatch.
        match store.get(&hash) {
            Err(StorageError::ChecksumMismatch { expected, .. }) => assert_eq!(expected, hash),
            other => panic!("expected ChecksumMismatch, got {other:?}"),
        }
        // The unchecked fast path returns the raw short/corrupt bytes.
        let raw = store.get_unchecked(&hash).unwrap();
        assert_ne!(raw.as_slice(), data.as_slice(), "torn bytes differ from what was written");
        assert!(raw.len() < data.len(), "the block was truncated");
        // The corrupt block still reports as present.
        assert!(store.exists(&hash).unwrap());
    }

    #[test]
    fn works_drop_in_through_a_type_erased_block_store() {
        // Proves the decorator wraps `Arc<dyn BlockStore + Send + Sync>`,
        // not just the concrete backend.
        let dir = tempfile::tempdir().unwrap();
        let inner: Arc<dyn BlockStore + Send + Sync> =
            Arc::new(SegmentBlockStore::new(dir.path()).unwrap());
        let store = FaultingBlockStore::new(inner, DiskFaultPlan::default());
        let hash = store.put(b"erased").unwrap();
        assert_eq!(store.get(&hash).unwrap(), b"erased");
    }

    // ---- async seam test (SlowIo advances the simulated clock only) ----

    #[test]
    fn slow_io_delays_the_op_on_the_simulated_clock() {
        super::super::sim::block_on(1, || async {
            let (_dir, fs) = fs_store();
            let hash = fs.put(b"slow bytes").unwrap();
            let store = FaultingBlockStore::new(
                fs,
                DiskFaultPlan {
                    slow_io_every: 1,
                    slow_io_nanos: 250_000_000,
                    ..Default::default()
                },
            );
            let start = tokio::time::Instant::now();
            let got = store.get_faulted(&hash).await.unwrap();
            let elapsed = start.elapsed();
            assert_eq!(got, b"slow bytes");
            assert!(
                elapsed >= Duration::from_millis(250),
                "the simulated clock advanced by the scheduled SlowIo delay, got {elapsed:?}"
            );
        });
    }
}
