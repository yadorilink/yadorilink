use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;

use crate::error::{DatabaseError, SqlOperationError};
use crate::job_fence::JobFence;
use crate::pool::{
    build_pool, checkout, retry_on_database_locked, CloseBarrier, ConnectionPool, Connections,
    BUSY_TIMEOUT, STATEMENT_CACHE_CAPACITY,
};

// `stats`/`reset`/`record_gate_acquisition` below are a small, permanent
// writer-gate observability primitive. Repository-level tests
// (e.g. `materialization_job_repository`'s `enqueue_pending_writer_gate_
// tests`) rely on `reset()`/`stats()` to assert that a specific operation
// does or does not take the process-wide write lock at all -- a property
// no amount of row-state inspection alone can observe, since a no-op SQL
// UPDATE and a call that never opens a transaction leave identical
// on-disk state.
//
// `call_sites`/`record_call_site`/`call_site_stats` below are permanent
// too; see their own doc comment for why.
//
// `record_gate_hold`/`hold_site_stats` are permanent too, for a reason the
// wait-side counters structurally cannot cover: `record_gate_acquisition`
// times how long a caller WAITED, which by construction never names the
// caller that was holding the gate and made it wait. Every writer-gate
// starvation investigated on this codebase so far has turned on exactly that
// question, and answering it by inference from a wait histogram wasted real
// time twice. Cost is one `Instant::elapsed` and one hash-map update per
// write transaction, inside the gate the caller already holds.
//
// All three key on `(file, line)` borrowed from the caller's own
// `&'static Location`, never on a formatted `String`. They run on every
// write, so an owned key would be a heap allocation per write for a
// counter -- and `record_call_site` in particular is taken BEFORE the
// writer gate rather than under it, so its cost is not absorbed by a lock
// the caller was holding anyway.
pub mod writer_gate_stats {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    static GATE_ACQUISITIONS: AtomicU64 = AtomicU64::new(0);
    static GATE_WAIT_NANOS: AtomicU64 = AtomicU64::new(0);

    pub(crate) fn record_gate_acquisition(wait: Duration) {
        GATE_ACQUISITIONS.fetch_add(1, Ordering::Relaxed);
        GATE_WAIT_NANOS.fetch_add(wait.as_nanos() as u64, Ordering::Relaxed);
        if wait > Duration::from_millis(500) {
            tracing::warn!(
                wait_ms = wait.as_millis() as u64,
                "writer_gate acquisition took a long time"
            );
        }
    }

    /// Total `locked_write` invocations (one per fsync-backed DB write
    /// transaction, regardless of how many rows/paths the caller's closure
    /// covers) and cumulative time spent waiting to acquire `writer_gate`,
    /// since process start or the last [`reset`].
    pub fn stats() -> (u64, Duration) {
        (
            GATE_ACQUISITIONS.load(Ordering::Relaxed),
            Duration::from_nanos(GATE_WAIT_NANOS.load(Ordering::Relaxed)),
        )
    }

    /// Zeroes every counter in this module -- call before a measured storm so
    /// [`stats`], [`call_site_stats`] and [`hold_site_stats`] all reflect only
    /// that run, not whatever earlier setup did.
    pub fn reset() {
        GATE_ACQUISITIONS.store(0, Ordering::Relaxed);
        GATE_WAIT_NANOS.store(0, Ordering::Relaxed);
        call_sites().lock().unwrap_or_else(|p| p.into_inner()).clear();
        hold_sites().lock().unwrap_or_else(|p| p.into_inner()).clear();
        reset_split();
    }

    // Per-call-site attribution. It costs a `#[track_caller]` plus one
    // hash-map update inside a lock the caller already holds, and every
    // writer-gate contention question needs it again, so it is permanent. `record_gate_acquisition` above only counts and
    // times acquisitions in aggregate, which cannot say WHICH of
    // `SyncDatabase::write`/`write_immediate`'s many call sites is
    // actually driving that volume. `#[track_caller]` on both public
    // entry points (and on this function) makes `Location::caller()`
    // resolve to the caller's own call site (file:line), not this
    // module's -- recorded here, inside `locked_write`'s own already-held
    // `writer_gate`, so this adds no additional lock contention beyond
    // what already exists.
    type SiteKey = (&'static str, u32);

    fn call_sites() -> &'static std::sync::Mutex<std::collections::HashMap<SiteKey, u64>> {
        static SITES: std::sync::OnceLock<
            std::sync::Mutex<std::collections::HashMap<SiteKey, u64>>,
        > = std::sync::OnceLock::new();
        SITES.get_or_init(Default::default)
    }

    /// Takes the caller's location rather than resolving it itself, so the
    /// write path computes `Location::caller()` once and hands the same
    /// value to both this and the writer gate.
    pub(crate) fn record_call_site(location: &'static std::panic::Location<'static>) {
        let mut sites = call_sites().lock().unwrap_or_else(|p| p.into_inner());
        *sites.entry((location.file(), location.line())).or_insert(0) += 1;
    }

    // Per-call-site writer_gate HOLD time -- the other half of
    // `record_gate_acquisition` above, which can only ever say that a caller
    // waited, never who made it wait. See this module's own header comment.
    fn hold_sites() -> &'static std::sync::Mutex<std::collections::HashMap<SiteKey, (u64, u128)>> {
        static SITES: std::sync::OnceLock<
            std::sync::Mutex<std::collections::HashMap<SiteKey, (u64, u128)>>,
        > = std::sync::OnceLock::new();
        SITES.get_or_init(Default::default)
    }

    pub(crate) fn record_gate_hold(
        location: &'static std::panic::Location<'static>,
        held: Duration,
    ) {
        let mut sites = hold_sites().lock().unwrap_or_else(|p| p.into_inner());
        let entry = sites.entry((location.file(), location.line())).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += held.as_micros();
        if held > Duration::from_millis(500) {
            tracing::warn!(
                held_ms = held.as_millis() as u64,
                call_site = %location,
                "writer_gate was HELD for a long time"
            );
        }
    }

    /// Every distinct `write`/`write_immediate` call site seen since process
    /// start or the last [`reset`], with `(count, total_held_micros)`, sorted
    /// by total held time descending.
    pub fn hold_site_stats() -> Vec<(String, u64, u128)> {
        let sites = hold_sites().lock().unwrap_or_else(|p| p.into_inner());
        let mut v: Vec<(String, u64, u128)> = sites
            .iter()
            .map(|((file, line), (n, micros))| (format!("{file}:{line}"), *n, *micros))
            .collect();
        v.sort_by_key(|a| std::cmp::Reverse(a.2));
        v
    }

    // Body/commit split per call site. Off unless armed (see
    // `set_split_enabled`): an armed `write_immediate` costs two extra
    // `Instant::now()` and one map update inside the gate it already
    // holds; a disarmed one costs a single relaxed load.
    static SPLIT_ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    static BODY_HIST: crate::diag_hist::Log2Hist = crate::diag_hist::Log2Hist::new();
    static COMMIT_HIST: crate::diag_hist::Log2Hist = crate::diag_hist::Log2Hist::new();

    /// Totals for one write call site, split into the statements the
    /// caller's closure ran (`body`) and the explicit `COMMIT` that follows
    /// (`commit`: WAL append plus its fsync under `synchronous = FULL`).
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct SplitSiteStat {
        pub site: String,
        pub calls: u64,
        pub body_nanos: u128,
        /// Calls that had an explicit commit to time. `write` closures run
        /// autocommit statements, so their commit cost is inside `body`
        /// and they add to `calls` but not here.
        pub commit_calls: u64,
        pub commit_nanos: u128,
        pub commit_max_nanos: u64,
    }

    pub fn set_split_enabled(on: bool) {
        SPLIT_ENABLED.store(on, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn split_enabled() -> bool {
        SPLIT_ENABLED.load(Ordering::Relaxed)
    }

    fn split_sites() -> &'static std::sync::Mutex<std::collections::HashMap<SiteKey, SplitSiteStat>>
    {
        static SITES: std::sync::OnceLock<
            std::sync::Mutex<std::collections::HashMap<SiteKey, SplitSiteStat>>,
        > = std::sync::OnceLock::new();
        SITES.get_or_init(Default::default)
    }

    pub(crate) fn record_split(
        location: &'static std::panic::Location<'static>,
        body: Duration,
        commit: Option<Duration>,
    ) {
        let body_nanos = body.as_nanos().min(u64::MAX as u128) as u64;
        BODY_HIST.record(body_nanos);
        let commit_nanos = commit.map(|c| c.as_nanos().min(u64::MAX as u128) as u64);
        if let Some(nanos) = commit_nanos {
            COMMIT_HIST.record(nanos);
        }
        let mut sites = split_sites().lock().unwrap_or_else(|p| p.into_inner());
        let entry = sites.entry((location.file(), location.line())).or_default();
        entry.calls += 1;
        entry.body_nanos += body_nanos as u128;
        if let Some(nanos) = commit_nanos {
            entry.commit_calls += 1;
            entry.commit_nanos += nanos as u128;
            entry.commit_max_nanos = entry.commit_max_nanos.max(nanos);
        }
    }

    /// Every call site that recorded a split, longest total (body plus
    /// commit) first.
    pub fn split_site_stats() -> Vec<SplitSiteStat> {
        let sites = split_sites().lock().unwrap_or_else(|p| p.into_inner());
        let mut v: Vec<SplitSiteStat> = sites
            .iter()
            .map(|((file, line), stat)| SplitSiteStat {
                site: format!("{file}:{line}"),
                ..stat.clone()
            })
            .collect();
        v.sort_by_key(|s| std::cmp::Reverse(s.body_nanos + s.commit_nanos));
        v
    }

    /// `(body, commit)` latency percentile (bucket floor, nanoseconds)
    /// across every armed write transaction.
    pub fn split_percentile_nanos(q: f64) -> (u64, u64) {
        (BODY_HIST.percentile(q), COMMIT_HIST.percentile(q))
    }

    pub fn reset_split() {
        split_sites().lock().unwrap_or_else(|p| p.into_inner()).clear();
        BODY_HIST.reset();
        COMMIT_HIST.reset();
    }
}

thread_local! {
    /// Set while this thread is inside a write transaction (it holds the
    /// writer gate, or runs under a holder of it on the same thread).
    static IN_WRITE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether the calling thread is inside a write transaction of any
/// `SyncDatabase`, i.e. holds a writer gate. Waiting for another thread's
/// database job from such a thread can deadlock on the gate it holds.
pub fn current_thread_in_write_transaction() -> bool {
    IN_WRITE.with(|f| f.get())
}

pub struct SyncDatabase {
    /// Each call checks out its own pooled connection (`r2d2` +
    /// `r2d2_sqlite`) against a WAL-mode database, so multiple readers
    /// (and a reader alongside a writer) proceed concurrently instead of
    /// blocking on each other -- SQLite's own WAL concurrency model, not
    /// an in-process lock, governs access. Writers still serialize against
    /// each other (SQLite allows only one writer at a time even in WAL
    /// mode), handled by `BUSY_TIMEOUT` rather than an in-process mutex.
    pool: ConnectionPool,
    /// Declared right after `pool` so it is dropped right after it: dropping the database returns
    /// only once every connection is closed, including one a pool worker was still opening.
    _close_barrier: CloseBarrier,
    /// In-process writer gate: every write transaction issued through this
    /// handle acquires this before touching SQLite, so two of the SAME
    /// process's own threads can never race for SQLite's single writer
    /// slot at all -- the `SQLITE_BUSY`/`SQLITE_LOCKED` family between our
    /// own writers becomes structurally impossible rather than merely
    /// retried (`BUSY_TIMEOUT` and `retry_on_database_locked`'s bounded
    /// retry remain as defense-in-depth for anything external and for
    /// shared-cache table locks). A thread-local re-entrancy check (see
    /// `locked_write`) makes a nested write from within a write closure
    /// run gate-free instead of deadlocking.
    writer_gate: Mutex<()>,
    /// Outer write transactions through THIS handle -- the per-database
    /// counterpart of `writer_gate_stats::stats().0`, which is process-wide
    /// and so also counts every other database's writes. See
    /// [`Self::write_transaction_count`].
    write_transactions: AtomicU64,
    /// Whether this database carries the provider tables, so every write TRANSACTION reconciles
    /// provider item liveness before it commits (a connection-level autocommit write only records
    /// the changed paths, atomically with the change; provider reads settle them first; see
    /// [`crate::schema::reconcile_provider_liveness`]). Decided once, after the schema
    /// bootstrap.
    provider_liveness: bool,
}

/// Open-time durability options.
///
/// `flush_drive_cache` adds `PRAGMA fullfsync` and `PRAGMA checkpoint_fullfsync` to
/// `synchronous = FULL`. On Apple platforms SQLite's plain `fsync` does not flush the drive's write
/// cache; only these pragmas make it issue `F_FULLFSYNC` for a commit and for a WAL checkpoint, so
/// without them an acknowledged commit can be lost to a power cut. The cost is a few milliseconds
/// per commit (single-row autocommit on an Apple-silicon Mac, APFS: about 0.03-0.16 ms without,
/// about 4-5 ms with; a 100-row transaction about 0.3-0.6 ms vs 5-6 ms; large transactions
/// amortize it), so the default enables it on every Apple platform (macOS and iOS) and off
/// elsewhere, where `fsync` already reaches stable storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenOptions {
    pub flush_drive_cache: bool,
}

#[allow(clippy::derivable_impls)] // derivable only off Apple platforms; their default is `true`
impl Default for OpenOptions {
    fn default() -> Self {
        Self { flush_drive_cache: cfg!(target_vendor = "apple") }
    }
}

/// The per-connection durability settings. They are connection-local, so every connection that can
/// write must run this.
fn apply_durability_pragmas(conn: &Connection, options: OpenOptions) -> rusqlite::Result<()> {
    conn.pragma_update(None, "synchronous", "FULL")?;
    if options.flush_drive_cache {
        conn.pragma_update(None, "fullfsync", "ON")?;
        conn.pragma_update(None, "checkpoint_fullfsync", "ON")?;
    }
    Ok(())
}

impl SyncDatabase {
    /// Opens (creating if needed) a file-backed database with WAL mode
    /// enabled -- WAL lets readers proceed without blocking behind the
    /// single writer SQLite allows at a time, unlike the default
    /// rollback-journal mode. Every pooled connection additionally gets
    /// `BUSY_TIMEOUT` so two of this process's own writers waiting on each
    /// other resolve by retrying, not erroring, and `synchronous = FULL`
    /// so a committed transaction survives an OS crash or power loss.
    /// Bootstraps on a single, unpooled connection BEFORE the pool exists
    /// at all -- deliberately not the previous shape (build the pool, then
    /// run the WAL pragma and schema bootstrap through `with_init` on
    /// whichever pooled connections happen to get established). Switching
    /// `journal_mode` to WAL is itself a mode change requiring SQLite's
    /// exclusive lock, and `r2d2::Pool::new`/`Pool::builder().build(..)`'s
    /// default `min_idle` eagerly establishes connections up to the pool's
    /// max size at build time, in the background -- so the previous shape
    /// let several of THIS PROCESS's OWN connections race each other to
    /// switch journal mode on the same file concurrently, before
    /// `writer_gate` (or anything else) existed to order them. Confirmed
    /// as a real source of `database is locked` errors observed at
    /// process-startup under load (multiple `SyncDatabase::open` calls in
    /// the same process, e.g. one per simulated device in a multi-device
    /// test). journal_mode is a property persisted in the database FILE
    /// itself (survives connection close), so switching it once here,
    /// before any pooled connection is ever established, means every later
    /// pooled connection simply observes WAL mode already in effect -- no
    /// per-connection WAL pragma is needed or issued by the pool's own
    /// `with_init` any more, only the two purely per-connection settings
    /// (`busy_timeout`, `synchronous`) that carry no mode-switch race.
    /// Schema bootstrap also moves onto this same bootstrap connection for
    /// the identical reason: it used to run on whichever pooled connection
    /// `checkout` happened to hand back, itself racing the same
    /// pool-startup fan-out. `schema_init` is the caller's complete
    /// schema-bootstrap step, run on the bootstrap connection before
    /// `open` returns -- the sole place schema initialization happens.
    /// This crate knows no domain-specific name (native state, filesystem
    /// transaction, materialization job, ...) here or anywhere else.
    pub fn open(
        path: impl AsRef<Path>,
        schema_init: impl FnOnce(&Connection) -> Result<(), DatabaseError>,
    ) -> Result<Self, DatabaseError> {
        Self::open_with_options(path, OpenOptions::default(), schema_init)
    }

    /// [`Self::open`] with explicit durability options.
    pub fn open_with_options(
        path: impl AsRef<Path>,
        options: OpenOptions,
        schema_init: impl FnOnce(&Connection) -> Result<(), DatabaseError>,
    ) -> Result<Self, DatabaseError> {
        let path = path.as_ref();
        let provider_liveness;
        {
            let conn = Connection::open(path)?;
            conn.busy_timeout(BUSY_TIMEOUT)?;
            conn.set_prepared_statement_cache_capacity(STATEMENT_CACHE_CAPACITY);
            // journal_mode is itself a query (it returns the mode that
            // was actually applied), hence `pragma_update_and_check`
            // rather than `pragma_update`.
            conn.pragma_update_and_check(None, "journal_mode", "WAL", |_row| Ok(()))?;
            // This database is the durable source of truth for what
            // content exists, so it must not depend on SQLite's
            // compile-time default for `synchronous` (only NORMAL under
            // WAL). FULL fsyncs the WAL before reporting a commit,
            // closing the window where an OS crash or power loss could
            // lose the last committed transaction. Set here too (not just
            // in the pool's own per-connection init below), since this
            // bootstrap connection is also the one `schema_init` runs on.
            apply_durability_pragmas(&conn, options)?;
            // Schema generation is the CALLER's policy, not this crate's.
            // Three different databases open through here -- the replica
            // index, the segment block store's index, and the Send store --
            // and only the first stamps `user_version`. Enforcing the
            // replica's generation here forced a blanket `user_version == 0`
            // carve-out so the other two could open at all, and that
            // carve-out also admitted any replica database written before
            // stamping existed. Each owner now declares its own generation
            // in its `schema_init`.
            schema_init(&conn)?;
            provider_liveness = crate::schema::has_provider_liveness(&conn)?;
        }
        let manager = SqliteConnectionManager::file(path).with_init(move |conn| {
            conn.busy_timeout(BUSY_TIMEOUT)?;
            conn.set_prepared_statement_cache_capacity(STATEMENT_CACHE_CAPACITY);
            // No journal_mode pragma here -- see this method's own doc
            // comment for why the bootstrap connection above already
            // switched it once, durably, before this pool (or any pooled
            // connection) existed.
            apply_durability_pragmas(conn, options)?;
            Ok(())
        });
        let connections = Arc::new(Connections::default());
        let pool = build_pool(manager, Arc::clone(&connections))?;
        Ok(Self {
            pool,
            _close_barrier: CloseBarrier(connections),
            writer_gate: Mutex::new(()),
            write_transactions: AtomicU64::new(0),
            provider_liveness,
        })
    }

    /// Opens an in-memory database, pooled just like the file-backed case.
    /// Plain SQLite `:memory:` databases are private to the single
    /// connection that opened them, so naively pooling one would give
    /// each checkout its own empty database and silently break every
    /// write-then-read call pattern. `r2d2_sqlite`'s
    /// `SqliteConnectionManager::memory` avoids that: it opens
    /// `file:<uuid>?mode=memory&cache=shared` (a *named*, shared-cache
    /// in-memory database) so every pooled connection attaches to the
    /// *same* in-memory database, and it internally keeps one extra
    /// connection alive for the manager's lifetime so the database isn't
    /// dropped the instant every checked-out connection happens to be
    /// idle (shared-cache `:memory:` databases are freed when their last
    /// connection closes). WAL mode is skipped here: SQLite doesn't
    /// support WAL for in-memory databases (the pragma is a no-op), only
    /// `BUSY_TIMEOUT` is needed so pooled writers don't race each other
    /// into `SQLITE_BUSY`.
    pub fn open_in_memory(
        schema_init: impl FnOnce(&Connection) -> Result<(), DatabaseError>,
    ) -> Result<Self, DatabaseError> {
        let manager = SqliteConnectionManager::memory().with_init(|conn| {
            conn.busy_timeout(BUSY_TIMEOUT)?;
            conn.set_prepared_statement_cache_capacity(STATEMENT_CACHE_CAPACITY);
            Ok(())
        });
        Self::open_with_manager(manager, schema_init)
    }

    fn open_with_manager(
        manager: SqliteConnectionManager,
        schema_init: impl FnOnce(&Connection) -> Result<(), DatabaseError>,
    ) -> Result<Self, DatabaseError> {
        let connections = Arc::new(Connections::default());
        let pool = build_pool(manager, Arc::clone(&connections))?;
        let conn = checkout::<DatabaseError>(&pool)?;
        // Defense-in-depth -- see `Self::open`'s identical call and
        // `check_schema_version_supported`'s own doc comment for why.
        crate::schema::check_schema_version_supported(&conn)?;
        schema_init(&conn)?;
        let provider_liveness = crate::schema::has_provider_liveness(&conn)?;
        drop(conn);
        Ok(Self {
            pool,
            _close_barrier: CloseBarrier(connections),
            writer_gate: Mutex::new(()),
            write_transactions: AtomicU64::new(0),
            provider_liveness,
        })
    }

    #[cfg(test)]
    pub(crate) fn connections_for_test(&self) -> Arc<Connections> {
        Arc::clone(&self._close_barrier.0)
    }

    #[cfg(any(test, feature = "test-support"))]
    /// Test-only raw pool access, for a fixture that needs multiple
    /// concurrently-held raw connections (a deliberate lock-contention
    /// test) or that corrupts the schema directly (`DROP TABLE ...`) --
    /// neither expressible through `read`/`write`/`write_immediate`'s
    /// one-shot closures. Production code must never call this; every real
    /// read or write goes through the three methods below, which is what
    /// keeps `pool` itself private.
    #[cfg(any(test, feature = "test-support"))]
    pub fn pool_for_test(&self) -> &ConnectionPool {
        &self.pool
    }

    /// Outer (non-reentrant) write transactions this handle has run since it
    /// was opened -- one per `write`/`write_immediate` call that took the
    /// writer gate, however many rows its closure touched. Unlike the
    /// process-wide `writer_gate_stats` counters, no other database's
    /// writes move it, so a caller can measure one database's gate traffic
    /// with a before/after difference while anything else in the process
    /// keeps writing.
    pub fn write_transaction_count(&self) -> u64 {
        self.write_transactions.load(Ordering::Relaxed)
    }

    /// A read, retried on a transient SQLITE_BUSY/SQLITE_LOCKED (external
    /// process, shared-cache table lock) but NOT serialized against this
    /// process's own writer_gate -- concurrent reads are safe and should not
    /// contend with each other.
    pub fn read<T, E: SqlOperationError>(
        &self,
        mut operation: impl FnMut(&Connection) -> Result<T, E>,
    ) -> Result<T, E> {
        retry_on_database_locked(|| {
            let conn = checkout::<E>(&self.pool)?;
            operation(&conn)
        })
    }

    /// A read that sees ONE snapshot for its whole duration.
    ///
    /// [`read`](Self::read) opens no transaction: it checks out a connection
    /// and runs the closure, so every statement inside is its own implicit
    /// transaction and a multi-statement read can observe a different database
    /// between one statement and the next. For a single query that is
    /// irrelevant. For anything that reads a value and then reads more state
    /// *derived from* that value, it is not: the result describes a database
    /// that never existed at any single instant.
    ///
    /// This opens a DEFERRED transaction, which takes its snapshot at the
    /// first read and holds it until the closure returns. In WAL mode that
    /// costs no writer exclusion at all — writers proceed alongside — so a
    /// long analytical read is safe here in a way it would not be under an
    /// IMMEDIATE transaction.
    ///
    /// The transaction is rolled back on the way out. Nothing here may write.
    pub fn read_snapshot<T, E: SqlOperationError>(
        &self,
        mut operation: impl FnMut(&Connection) -> Result<T, E>,
    ) -> Result<T, E> {
        retry_on_database_locked(|| {
            let conn = checkout::<E>(&self.pool)?;
            let snapshot = conn.unchecked_transaction().map_err(E::from)?;
            let result = operation(&snapshot)?;
            // Reads only: dropping rolls back, which is what we want.
            drop(snapshot);
            Ok(result)
        })
    }

    /// A single-statement (or few-statement, no explicit transaction needed)
    /// write, serialized against this process's own writer_gate AND retried
    /// on a transient lock error -- the same guarantee `locked_write`
    /// already gives multi-statement transactional writers, now available to
    /// callers that just need one `execute`/`query_row` without opening
    /// their own transaction.
    #[track_caller]
    pub fn write<T, E: SqlOperationError>(
        &self,
        mut operation: impl FnMut(&mut Connection) -> Result<T, E>,
    ) -> Result<T, E> {
        let caller = std::panic::Location::caller();
        writer_gate_stats::record_call_site(caller);
        self.locked_write(caller, || {
            let mut conn = checkout::<E>(&self.pool)?;
            if !writer_gate_stats::split_enabled() {
                return operation(&mut conn);
            }
            let started = std::time::Instant::now();
            let result = operation(&mut conn);
            writer_gate_stats::record_split(caller, started.elapsed(), None);
            result
        })
    }

    /// Folds the write-ahead log into the database file and truncates it
    /// (`wal_checkpoint(TRUNCATE)`), serialized with this process's writers.
    /// After it returns `Ok` every committed transaction is in the main file,
    /// so the file stands alone without its `-wal` sibling.
    ///
    /// # Errors
    /// SQLite reports the checkpoint could not finish (a reader still holds
    /// the log: SQLITE_BUSY) or failed; nothing is lost, the log simply stays.
    /// A database that is not in WAL mode has nothing to fold and returns `Ok`.
    #[track_caller]
    pub fn checkpoint_truncate(&self) -> Result<(), DatabaseError> {
        self.write(|conn| {
            let (busy, _log_frames, _checkpointed): (i64, i64, i64) =
                conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?;
            if busy == 0 {
                Ok(())
            } else {
                Err(DatabaseError::Sqlite(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
                    Some("the write-ahead log could not be checkpointed: a reader holds it".into()),
                )))
            }
        })
    }

    /// A multi-statement write that must commit atomically -- opens an
    /// IMMEDIATE transaction (see `new_immediate_write_transaction`'s own
    /// doc comment for why IMMEDIATE, not the rusqlite default DEFERRED),
    /// serialized against the writer_gate and retried, commits on `Ok`.
    #[track_caller]
    pub fn write_immediate<T, E: SqlOperationError>(
        &self,
        operation: impl FnMut(&rusqlite::Transaction<'_>) -> Result<T, E>,
    ) -> Result<T, E> {
        self.write_immediate_at(std::panic::Location::caller(), operation)
    }

    /// [`Self::write_immediate`] on the blocking pool, so the calling task
    /// keeps polling while the commit (the writer gate, the statements, the
    /// fsync) runs on another thread.
    ///
    /// The returned future owns a [`JobFence`] wait: if it is dropped before
    /// the job has finished (the awaiting task was cancelled), its `Drop`
    /// blocks until the job has committed or rolled back, so whatever the
    /// caller's frames still hold for this write (path locks, root
    /// operations, claims) is released only after the outcome is decided. The
    /// job itself needs nothing from the dropper: it owns its closure and
    /// takes only the writer gate, which no dropping side holds (a drop on a
    /// thread that is itself inside a write transaction does not wait, since
    /// waiting there could deadlock on the gate).
    ///
    /// A panic in `operation` rolls the transaction back, signals the fence
    /// and is re-raised in the awaiting task, as the inline call would.
    #[track_caller]
    pub fn write_immediate_offloaded<T, E>(
        self: &std::sync::Arc<Self>,
        operation: impl FnMut(&rusqlite::Transaction<'_>) -> Result<T, E> + Send + 'static,
    ) -> impl std::future::Future<Output = Result<T, E>> + Send
    where
        T: Send + 'static,
        E: SqlOperationError + Send + 'static,
    {
        let caller = std::panic::Location::caller();
        let database = std::sync::Arc::clone(self);
        async move {
            let fence = JobFence::new();
            let completion = fence.completion();
            let handle = tokio::task::spawn_blocking(move || {
                let _completion = completion;
                let _scope = _completion.enter();
                database.write_immediate_at(caller, operation)
            });
            let _wait = fence.waiter();
            match handle.await {
                Ok(result) => result,
                Err(join) => match join.try_into_panic() {
                    Ok(payload) => std::panic::resume_unwind(payload),
                    Err(_) => Err(E::from(rusqlite::Error::SqliteFailure(
                        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_INTERRUPT),
                        Some("the commit job was cancelled before it ran".to_owned()),
                    ))),
                },
            }
        }
    }

    fn write_immediate_at<T, E: SqlOperationError>(
        &self,
        caller: &'static std::panic::Location<'static>,
        mut operation: impl FnMut(&rusqlite::Transaction<'_>) -> Result<T, E>,
    ) -> Result<T, E> {
        writer_gate_stats::record_call_site(caller);
        self.locked_write(caller, || {
            let mut conn = checkout::<E>(&self.pool)?;
            let tx = new_immediate_write_transaction(&mut conn)?;
            let body_started = writer_gate_stats::split_enabled().then(std::time::Instant::now);
            let result = operation(&tx)?;
            // After the COMPLETE semantic mutation, before the commit: liveness reads the
            // final state, never an intermediate one.
            if self.provider_liveness {
                crate::schema::reconcile_provider_liveness(&tx).map_err(E::from)?;
            }
            let commit_started = body_started.map(|body| (body, std::time::Instant::now()));
            tx.commit().map_err(E::from)?;
            if let Some((body_started, commit_started)) = commit_started {
                writer_gate_stats::record_split(
                    caller,
                    commit_started.duration_since(body_started),
                    Some(commit_started.elapsed()),
                );
            }
            Ok(result)
        })
    }

    /// Runs one write operation with the in-process writer gate held: our
    /// own threads are serialized BEFORE SQLite ever sees a second writer,
    /// making own-process `SQLITE_BUSY`/`SQLITE_LOCKED` contention
    /// structurally impossible instead of retried-until-lucky. The bounded
    /// `retry_on_database_locked` stays underneath as defense-in-depth
    /// (external processes, shared-cache table locks held by readers). A
    /// write closure that re-enters another `locked_write` on the SAME
    /// thread (nested helper calls) is detected via a thread-local flag and
    /// runs gate-free -- already serialized by the outer holder -- so the
    /// non-reentrant mutex can never self-deadlock. The closures never
    /// `.await`, so the flag cannot leak across tasks on a work-stealing
    /// runtime; a panicking closure restores it via the drop guard.
    fn locked_write<T, E: SqlOperationError>(
        &self,
        caller_location: &'static std::panic::Location<'static>,
        op: impl FnMut() -> Result<T, E>,
    ) -> Result<T, E> {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                IN_WRITE.with(|f| f.set(false));
            }
        }
        if IN_WRITE.with(|f| f.get()) {
            return retry_on_database_locked(op);
        }
        // PERMANENT writer-gate observability (see this module's `writer_gate_stats`
        // header comment): total write-transaction count and cumulative
        // time spent waiting to acquire `writer_gate` -- one outer
        // (non-reentrant) `locked_write` call is exactly one fsync-backed
        // commit, regardless of how many rows or paths the caller's
        // closure covers, so this count directly answers "how many DB
        // write transactions has this process done, and how much time did
        // callers spend waiting for the gate" for any future writer-gate
        // contention investigation, not just the one that motivated it.
        let gate_wait_started = std::time::Instant::now();
        let _gate = self.writer_gate.lock().unwrap_or_else(|p| p.into_inner());
        let gate_wait_elapsed = gate_wait_started.elapsed();
        writer_gate_stats::record_gate_acquisition(gate_wait_elapsed);
        crate::job_fence::mark_running_current();
        self.write_transactions.fetch_add(1, Ordering::Relaxed);
        IN_WRITE.with(|f| f.set(true));
        let _reset = Reset;
        let gate_held_started = std::time::Instant::now();
        let result = retry_on_database_locked(op);
        writer_gate_stats::record_gate_hold(caller_location, gate_held_started.elapsed());
        result
    }
}

/// One half of the fix for a real, previously-diagnosed
/// `SQLITE_LOCKED: database table is locked` failure class.
/// `rusqlite::Connection::transaction` opens a `DEFERRED` transaction by
/// default, which only acquires SQLite's write (`RESERVED`) lock lazily,
/// on the *first write statement actually executed inside it* -- not at
/// `BEGIN` time. A read-then-write first statement inside a transaction
/// (e.g. `UPDATE ... RETURNING`), under this crate's connection pool (many
/// pooled connections concurrently doing independent work), can lose a
/// `SHARED`-to-`RESERVED` lock-upgrade race against another pooled
/// connection's concurrent read -- SQLite's classic deferred-transaction
/// lock-upgrade pitfall. Opening the transaction `IMMEDIATE` instead
/// acquires the `RESERVED` write lock immediately at `BEGIN`, closing that
/// specific upgrade-race window.
///
/// **This alone was not sufficient** -- see `retry_on_database_locked` in
/// `pool.rs` for the other half, and why: `SQLITE_LOCKED` can also arise
/// from SQLite's shared-cache table-locking directly (independent of the
/// deferred-transaction upgrade problem this function closes), which
/// `open_in_memory` deliberately opts into (`cache=shared`, required for
/// pooled connections to see the same in-memory database at all) -- so
/// both mitigations are needed together, not either alone.
fn new_immediate_write_transaction(
    conn: &mut Connection,
) -> Result<rusqlite::Transaction<'_>, rusqlite::Error> {
    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
}

#[cfg(test)]
mod tests;
