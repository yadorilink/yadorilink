//! Deterministic SQLite `BUSY`/`LOCKED` fault injection for the index
//! layer — the database-fault complement to the network and block-store
//! fault surfaces. Where those inject faults into the transport and the
//! content store, this one models transient contention on the sqlite
//! index (`SyncState`): the write path returning `SQLITE_BUSY` /
//! `SQLITE_LOCKED` because another writer holds the database, exactly the
//! condition production's `busy_timeout` + retry loop is meant to absorb.
//!
//! Two pieces, mirroring the network fault surface's plan/decide split:
//!
//!   * `SqliteFaultPlan` — a pure, serde-serializable decision engine.
//!     `decide(op, seq)` is a total function of an op class and that op's
//!     per-op sequence number; it never consults the wall clock, an RNG,
//!     or any hidden state, so replaying the same (op, seq) stream against
//!     the same plan always yields the same faults. A plan persisted to
//!     the corpus replays a failing schedule verbatim.
//!
//!   * `FaultingSyncState` — a thin wrapper that owns a per-op sequence
//!     counter and a plan and sits *above* `SyncState`'s public API. Each
//!     guarded call bumps that op's sequence, asks the plan whether this
//!     one faults, and either returns a synthesized `SQLITE_BUSY` /
//!     `SQLITE_LOCKED` error *without touching the real index* (so the op
//!     genuinely did not commit) or delegates transparently to the real
//!     `SyncState`. Outside a scheduled fault window it is an exact
//!     pass-through.
//!
//! Why a wrapper above the API rather than a faulting connection beneath
//! it: `SyncState` owns its `r2d2` pool privately and offers no seam to
//! substitute a connection or pool that could return `BUSY` on a
//! schedule, so intercepting below the public API would require a new
//! production constructor. The op class a DST scenario actually drives is
//! the public method it calls, so guarding at that boundary needs no
//! production change and still exercises the real retry/no-silent-loss
//! path: the scenario sees a transient failure, retries, and the write
//! must ultimately land in the index.
//!
//! Faults model *transient* contention: a bounded run of consecutive
//! faulting ops followed by success, matching a `busy_timeout` that
//! eventually clears, not a permanent hard failure.

#![cfg(turmoil)]
#![allow(dead_code)] // not every scenario drives every op/kind yet

use std::collections::HashMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_daemon::sync_error::SyncError;
use yadorilink_replica_domain::file::FileRecord;

use super::fault_schedule::{FaultClass, ScheduledInjectors};

/// The index operation classes a DST scenario drives through the wrapper.
/// A fault schedule is keyed by op class so a fault on one op (e.g. the
/// write path) never perturbs the sequence of an unrelated op (e.g. a
/// read), matching how real contention hits one statement, not the whole
/// index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SqliteOp {
    UpsertFile,
    GetFile,
    ListFiles,
    GetUnixMode,
    SetUnixMode,
    SetMaterializationState,
}

/// Which transient error a fault synthesizes. Both are what production's
/// retry logic and SQLite's own `busy_timeout` are designed to recover
/// from; kept distinct so a scenario can target the exact code it wants to
/// prove the caller retries (`Locked` is the code production's index retry
/// loop treats as retryable; `Busy` is what a `busy_timeout` expiry
/// surfaces to the caller).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SqliteFaultKind {
    Busy,
    Locked,
}

impl SqliteFaultKind {
    /// Builds the `SyncError` a real faulting index call would produce for
    /// this kind. `rusqlite::ffi::Error::new` maps the primary result code
    /// to its `ErrorCode`, so a `Locked` fault carries
    /// `ErrorCode::DatabaseLocked` and a `Busy` fault
    /// `ErrorCode::DatabaseBusy` — indistinguishable to a caller from a
    /// genuinely contended database.
    pub fn to_error(self) -> SyncError {
        let (primary, message) = match self {
            SqliteFaultKind::Busy => (
                rusqlite::ffi::SQLITE_BUSY,
                "database is locked (SQLITE_BUSY) [deterministic fault]",
            ),
            SqliteFaultKind::Locked => (
                rusqlite::ffi::SQLITE_LOCKED,
                "database table is locked (SQLITE_LOCKED) [deterministic fault]",
            ),
        };
        SyncError::Db(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(primary),
            Some(message.to_string()),
        ))
    }
}

/// One scheduled run of transient faults: for op `op`, the calls whose
/// per-op sequence numbers fall in `[first_seq, first_seq + run_len)`
/// fault with `kind`; every call before and after that window passes
/// through. `run_len == 0` is an inert entry (never fires). Sequence
/// numbers are 1-based: the first guarded call of an op is seq 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledFault {
    pub op: SqliteOp,
    pub first_seq: u64,
    pub run_len: u64,
    pub kind: SqliteFaultKind,
}

impl ScheduledFault {
    fn covers(&self, op: SqliteOp, seq: u64) -> bool {
        self.op == op
            && self.run_len > 0
            && seq >= self.first_seq
            && seq < self.first_seq.saturating_add(self.run_len)
    }
}

/// A deterministic SQLite fault schedule. Pure and stateless: `decide` is
/// a function of `(op, seq)` alone, so the same plan replayed against the
/// same op/sequence stream always injects the same faults. Serde-round-
/// trips so a schedule that reproduced a failure can live in the corpus.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqliteFaultPlan {
    pub faults: Vec<ScheduledFault>,
}

impl SqliteFaultPlan {
    pub fn new() -> Self {
        Self::default()
    }

    /// Schedules a transient fault run of `run_len` consecutive faulting
    /// calls of `op`, beginning at that op's `first_seq`-th call.
    pub fn with_run(
        mut self,
        op: SqliteOp,
        first_seq: u64,
        run_len: u64,
        kind: SqliteFaultKind,
    ) -> Self {
        self.faults.push(ScheduledFault { op, first_seq, run_len, kind });
        self
    }

    /// The single fault decision for one call: does the `seq`-th call of
    /// `op` fault, and if so with what kind. The first matching scheduled
    /// run wins; earlier `faults` entries take precedence on overlap.
    pub fn decide(&self, op: SqliteOp, seq: u64) -> Option<SqliteFaultKind> {
        self.faults.iter().find(|f| f.covers(op, seq)).map(|f| f.kind)
    }
}

/// Wraps a real `SyncState`, injecting `plan`'s faults into the index
/// calls a scenario routes through it. Transparent outside a scheduled
/// fault window. The per-op sequence counters are the only mutable state;
/// the plan itself never changes, so a fault decision depends solely on
/// how many times each op has been driven — never on timing.
pub struct FaultingSyncState<'a> {
    inner: &'a ReplicaCoordinator,
    plan: SqliteFaultPlan,
    seqs: Mutex<HashMap<SqliteOp, u64>>,
    /// The scheduled injectors this wrapper reads its live plan from and
    /// credits at decision time. `None` for a fixed-plan wrapper.
    seam: Option<ScheduledInjectors>,
}

impl<'a> FaultingSyncState<'a> {
    /// A fixed-plan wrapper. It reports to no ledger, so a gated test that
    /// uses it earns no credit: use [`scheduled`](Self::scheduled).
    pub fn new(inner: &'a ReplicaCoordinator, plan: SqliteFaultPlan) -> Self {
        Self { inner, plan, seqs: Mutex::new(HashMap::new()), seam: None }
    }

    /// A wrapper bound to the scheduler's live plan: each guarded call is
    /// decided against the plan open at that moment and credits the ledger
    /// entry whose window is open at that moment.
    pub fn scheduled(inner: &'a ReplicaCoordinator, injectors: &ScheduledInjectors) -> Self {
        Self {
            inner,
            plan: injectors.sqlite_plan(),
            seqs: Mutex::new(HashMap::new()),
            seam: Some(injectors.clone()),
        }
    }

    /// The underlying real index, for reads a scenario wants to make
    /// without going through the fault surface (e.g. an oracle's final
    /// no-silent-data-loss check, which must see ground truth).
    pub fn inner(&self) -> &ReplicaCoordinator {
        self.inner
    }

    fn next_seq(&self, op: SqliteOp) -> u64 {
        let mut seqs = self.seqs.lock().unwrap_or_else(|p| p.into_inner());
        let entry = seqs.entry(op).or_insert(0);
        *entry += 1;
        *entry
    }

    /// Advances `op`'s sequence and returns `Err` if the plan schedules a
    /// fault for this call, without performing the op. A scenario guarding
    /// a `SyncState` method the wrapper does not expose directly calls this
    /// first, then the real method only on `Ok`.
    pub fn guard(&self, op: SqliteOp) -> Result<(), SyncError> {
        let seq = self.next_seq(op);
        let decision = match &self.seam {
            Some(seam) => seam.sqlite_plan().decide(op, seq),
            None => self.plan.decide(op, seq),
        };
        match decision {
            Some(kind) => {
                if let Some(seam) = &self.seam {
                    seam.credit(match kind {
                        SqliteFaultKind::Busy => FaultClass::SqliteBusy,
                        SqliteFaultKind::Locked => FaultClass::SqliteLocked,
                    });
                }
                Err(kind.to_error())
            }
            None => Ok(()),
        }
    }

    // --- Transparent passthroughs for the common file-index ops ---
    // Each guards, then delegates only when no fault fired, so a faulted
    // call leaves the real index untouched (the write genuinely did not
    // happen), which is what lets a scenario prove the retried write is
    // never silently lost.

    pub fn upsert_file(&self, group_id: &str, record: &FileRecord) -> Result<(), SyncError> {
        self.guard(SqliteOp::UpsertFile)?;
        Ok(self.inner.file_index_repository().upsert_file(
            group_id,
            record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )?)
    }

    pub fn get_file(&self, group_id: &str, path: &str) -> Result<Option<FileRecord>, SyncError> {
        self.guard(SqliteOp::GetFile)?;
        Ok(self.inner.file_index_repository().get_file(group_id, path)?)
    }

    pub fn list_files(&self, group_id: &str) -> Result<Vec<FileRecord>, SyncError> {
        self.guard(SqliteOp::ListFiles)?;
        Ok(self.inner.file_index_repository().list_files(group_id)?)
    }

    pub fn get_unix_mode(&self, group_id: &str, path: &str) -> Result<Option<u32>, SyncError> {
        self.guard(SqliteOp::GetUnixMode)?;
        Ok(self.inner.file_index_repository().get_unix_mode(group_id, path)?)
    }
}

/// The text only [`JournalFault`]'s trigger can put in an error.
pub const JOURNAL_FAULT_MARKER: &str = "injected journal fault";

/// A real failure of the durable dirty-journal write, installed in the index
/// file itself: a `BEFORE INSERT` trigger on `local_dirty_paths` that aborts
/// the statement. The product's own write path hits it, so no decorator sits
/// above the API (the processor takes the index as a port, which this fault
/// does not need to wrap).
///
/// The credit still comes from the seam, not from the test: [`observe`]
/// credits the ledger only for an error that carries the marker the trigger
/// raised, so a run in which the journal write never happened, or happened
/// after [`heal`], earns nothing.
///
/// [`observe`]: Self::observe
/// [`heal`]: Self::heal
pub struct JournalFault {
    db: std::path::PathBuf,
    injectors: ScheduledInjectors,
}

impl JournalFault {
    pub fn new(db: &std::path::Path, injectors: &ScheduledInjectors) -> Self {
        Self { db: db.to_path_buf(), injectors: injectors.clone() }
    }

    fn conn(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(&self.db).expect("open the index file")
    }

    /// Every insert into the journal now aborts.
    pub fn engage(&self) {
        self.conn()
            .execute_batch(&format!(
                "CREATE TRIGGER IF NOT EXISTS inject_journal_fault \
                 BEFORE INSERT ON local_dirty_paths \
                 BEGIN SELECT RAISE(ABORT, '{JOURNAL_FAULT_MARKER}'); END;"
            ))
            .expect("install the journal fault");
    }

    pub fn heal(&self) {
        self.conn()
            .execute_batch("DROP TRIGGER IF EXISTS inject_journal_fault;")
            .expect("remove the journal fault");
    }

    /// Passes `result` through, crediting a journal-write refusal the
    /// database itself raised.
    pub fn observe<T, E: std::fmt::Display>(&self, result: Result<T, E>) -> Result<T, E> {
        if let Err(error) = &result {
            if error.to_string().contains(JOURNAL_FAULT_MARKER) {
                self.injectors.credit(FaultClass::SqliteBusy);
            }
        }
        result
    }
}

/// Whether `err` is a transient SQLite contention error a caller is
/// expected to recover from by retrying — the class `retry_transient`
/// loops on. Mirrors the production index retry predicate (which treats a
/// locked database as retryable) and additionally covers `BUSY`, the code
/// a `busy_timeout` expiry surfaces.
pub fn is_transient_sqlite_error(err: &SyncError) -> bool {
    matches!(
        err,
        SyncError::Db(rusqlite::Error::SqliteFailure(e, _))
            if e.code == rusqlite::ErrorCode::DatabaseBusy
                || e.code == rusqlite::ErrorCode::DatabaseLocked
    )
}

/// Runs `op`, retrying up to `max_attempts` total tries while it fails
/// with a transient SQLite contention error, then returning the last
/// result. Models the caller-side retry loop that a `busy_timeout` +
/// bounded-run fault schedule is designed to be recovered by: a scenario
/// wraps its index writes in this and asserts the write still lands, so a
/// transient fault run costs a retry but never silent data loss. Backoff
/// is intentionally omitted — retries are deterministic and immediate, not
/// clock-driven.
pub fn retry_transient<T>(
    max_attempts: u32,
    mut op: impl FnMut() -> Result<T, SyncError>,
) -> Result<T, SyncError> {
    let mut attempt: u32 = 1;
    loop {
        match op() {
            Ok(value) => return Ok(value),
            Err(e) if attempt < max_attempts && is_transient_sqlite_error(&e) => {
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GROUP: &str = "fault-sqlite-test-group";

    fn setup() -> (ReplicaCoordinator, tempfile::TempDir) {
        let root = tempfile::tempdir().unwrap();
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        state.link_repository().add_link(&root.path().to_string_lossy(), GROUP).unwrap();
        (state, root)
    }

    fn record(path: &str) -> FileRecord {
        FileRecord {
            path: path.to_string(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: Vec::new(),
            deleted: false,
        }
    }

    #[test]
    fn a_scheduled_busy_fires_exactly_on_its_window_and_clears_after() {
        // A run of length 2 starting at seq 2 on UpsertFile: seq 1 clean,
        // seqs 2 and 3 fault, seq 4 onward clean again.
        let plan =
            SqliteFaultPlan::new().with_run(SqliteOp::UpsertFile, 2, 2, SqliteFaultKind::Busy);

        assert_eq!(plan.decide(SqliteOp::UpsertFile, 1), None);
        assert_eq!(plan.decide(SqliteOp::UpsertFile, 2), Some(SqliteFaultKind::Busy));
        assert_eq!(plan.decide(SqliteOp::UpsertFile, 3), Some(SqliteFaultKind::Busy));
        assert_eq!(plan.decide(SqliteOp::UpsertFile, 4), None);
        assert_eq!(plan.decide(SqliteOp::UpsertFile, 100), None);
    }

    #[test]
    fn faults_are_keyed_per_op_and_do_not_bleed_across_ops() {
        let plan =
            SqliteFaultPlan::new().with_run(SqliteOp::UpsertFile, 1, 5, SqliteFaultKind::Locked);
        // The scheduled op faults from its first call...
        assert_eq!(plan.decide(SqliteOp::UpsertFile, 1), Some(SqliteFaultKind::Locked));
        // ...but an unrelated op with the same sequence numbers is clean.
        assert_eq!(plan.decide(SqliteOp::GetFile, 1), None);
        assert_eq!(plan.decide(SqliteOp::ListFiles, 3), None);
    }

    #[test]
    fn zero_length_run_never_fires() {
        let plan =
            SqliteFaultPlan::new().with_run(SqliteOp::UpsertFile, 1, 0, SqliteFaultKind::Busy);
        for seq in 1..=10 {
            assert_eq!(plan.decide(SqliteOp::UpsertFile, seq), None);
        }
    }

    #[test]
    fn wrapper_is_a_transparent_passthrough_with_an_empty_plan() {
        let (state, _root) = setup();
        let faulting = FaultingSyncState::new(&state, SqliteFaultPlan::new());

        faulting.upsert_file(GROUP, &record("a.txt")).unwrap();
        let got = faulting.get_file(GROUP, "a.txt").unwrap();
        assert!(got.is_some(), "empty plan must not alter behavior");
        assert_eq!(faulting.list_files(GROUP).unwrap().len(), 1);
    }

    #[test]
    fn a_faulted_upsert_returns_the_scheduled_kind_and_does_not_commit() {
        let (state, _root) = setup();
        // First upsert of the path faults; nothing should reach the index.
        let plan =
            SqliteFaultPlan::new().with_run(SqliteOp::UpsertFile, 1, 1, SqliteFaultKind::Locked);
        let faulting = FaultingSyncState::new(&state, plan);

        let err = faulting.upsert_file(GROUP, &record("a.txt")).unwrap_err();
        assert!(is_transient_sqlite_error(&err), "{err:?}");
        // The synthesized error carries the exact code production's index
        // retry loop treats as retryable.
        match &err {
            SyncError::Db(rusqlite::Error::SqliteFailure(e, _)) => {
                assert_eq!(e.code, rusqlite::ErrorCode::DatabaseLocked);
            }
            other => panic!("unexpected error shape: {other:?}"),
        }
        // The faulted write genuinely did not land: ground truth is empty.
        assert!(state.file_index_repository().get_file(GROUP, "a.txt").unwrap().is_none());
    }

    #[test]
    fn a_retry_after_the_transient_run_succeeds_with_no_silent_loss() {
        let (state, root) = setup();
        // Two transient faults, then success — a busy_timeout that clears.
        let plan =
            SqliteFaultPlan::new().with_run(SqliteOp::UpsertFile, 1, 2, SqliteFaultKind::Busy);
        let faulting = FaultingSyncState::new(&state, plan);

        std::fs::write(root.path().join("a.txt"), b"hello").unwrap();
        // The caller's retry loop absorbs the transient run (needs 3 tries:
        // 2 faults + 1 success).
        retry_transient(4, || faulting.upsert_file(GROUP, &record("a.txt"))).unwrap();

        // The write is not silently lost: it is present in the real index.
        let got = state.file_index_repository().get_file(GROUP, "a.txt").unwrap();
        assert!(got.is_some(), "retried write must reach the index");
    }

    #[test]
    fn a_run_longer_than_the_retry_budget_surfaces_the_error() {
        let (state, _root) = setup();
        let plan =
            SqliteFaultPlan::new().with_run(SqliteOp::UpsertFile, 1, 5, SqliteFaultKind::Busy);
        let faulting = FaultingSyncState::new(&state, plan);

        // Only 3 attempts against a 5-long fault run: the transient error
        // must propagate rather than be silently swallowed.
        let result = retry_transient(3, || faulting.upsert_file(GROUP, &record("a.txt")));
        assert!(matches!(result, Err(ref e) if is_transient_sqlite_error(e)));
        assert!(state.file_index_repository().get_file(GROUP, "a.txt").unwrap().is_none());
    }

    #[test]
    fn replay_of_the_same_op_sequence_is_deterministic() {
        let plan = SqliteFaultPlan::new()
            .with_run(SqliteOp::UpsertFile, 2, 2, SqliteFaultKind::Busy)
            .with_run(SqliteOp::GetFile, 1, 1, SqliteFaultKind::Locked);

        let stream = [
            (SqliteOp::UpsertFile, 1u64),
            (SqliteOp::GetFile, 1),
            (SqliteOp::UpsertFile, 2),
            (SqliteOp::UpsertFile, 3),
            (SqliteOp::GetFile, 2),
            (SqliteOp::UpsertFile, 4),
        ];
        let first: Vec<_> = stream.iter().map(|(op, seq)| plan.decide(*op, *seq)).collect();
        let second: Vec<_> = stream.iter().map(|(op, seq)| plan.decide(*op, *seq)).collect();
        assert_eq!(first, second, "decide must be a pure function of (op, seq)");
        assert_eq!(
            first,
            vec![
                None,
                Some(SqliteFaultKind::Locked),
                Some(SqliteFaultKind::Busy),
                Some(SqliteFaultKind::Busy),
                None,
                None,
            ]
        );
    }

    #[test]
    fn wrapper_per_op_sequencing_matches_the_plan() {
        let (state, _root) = setup();
        // Fault only the 2nd upsert; the 1st and 3rd pass through.
        let plan =
            SqliteFaultPlan::new().with_run(SqliteOp::UpsertFile, 2, 1, SqliteFaultKind::Busy);
        let faulting = FaultingSyncState::new(&state, plan);

        assert!(faulting.upsert_file(GROUP, &record("a.txt")).is_ok());
        assert!(faulting.upsert_file(GROUP, &record("b.txt")).is_err());
        assert!(faulting.upsert_file(GROUP, &record("c.txt")).is_ok());
        // Reads are a different op class, unaffected by the upsert schedule.
        assert!(faulting.get_file(GROUP, "a.txt").is_ok());
    }

    #[test]
    fn plan_round_trips_through_json() {
        let plan = SqliteFaultPlan::new()
            .with_run(SqliteOp::UpsertFile, 3, 2, SqliteFaultKind::Busy)
            .with_run(SqliteOp::SetMaterializationState, 1, 4, SqliteFaultKind::Locked);

        let json = serde_json::to_string(&plan).unwrap();
        let restored: SqliteFaultPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(plan, restored);
        // And the restored plan decides identically.
        assert_eq!(restored.decide(SqliteOp::UpsertFile, 3), Some(SqliteFaultKind::Busy));
        assert_eq!(
            restored.decide(SqliteOp::SetMaterializationState, 4),
            Some(SqliteFaultKind::Locked)
        );
        assert_eq!(restored.decide(SqliteOp::SetMaterializationState, 5), None);
    }
}
