//! Connection pool construction and the bounded SQLITE_BUSY/SQLITE_LOCKED retry helper. Pure, stateless
//! machinery -- no `SyncDatabase` fields live here; `SyncDatabase` owns
//! its own `pool`/`writer_gate` and calls back into this module.

use std::time::Duration;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use crate::error::SqlOperationError;

/// every connection made by the pool waits at
/// most this long for the SQLite write lock (`PRAGMA busy_timeout`)
/// before giving up with `SQLITE_BUSY`, instead of erroring immediately.
pub const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// How many prepared statements each connection keeps cached, up from
/// rusqlite's default of 16.
///
/// Admitting one change runs a few dozen fixed statements through
/// `prepare_cached`. The cache is least-recently-used, and a fixed cycle of
/// statements longer than the cache never hits it: each one is evicted
/// before it comes round again, so every statement would be parsed afresh
/// on every admission, which is the cost the cache exists to remove.
///
/// A bulk local capture commit runs about forty distinct statement texts per
/// file, well inside the capacity; a statement on that path that skips the
/// cache is parsed once per file instead.
pub const STATEMENT_CACHE_CAPACITY: usize = 128;

/// The connection pool backing a [`crate::SyncDatabase`].
pub type ConnectionPool = Pool<SqliteConnectionManager>;

/// Checks out a connection from `pool`, converting whichever concrete
/// error type the `r2d2::Pool` produces into the caller's own error type
/// `E`.
pub(crate) fn checkout<E: SqlOperationError>(pool: &ConnectionPool) -> Result<PooledConnection, E> {
    pool.get().map(PooledConnection).map_err(E::from)
}

pub(crate) struct PooledConnection(r2d2::PooledConnection<SqliteConnectionManager>);

impl std::ops::Deref for PooledConnection {
    type Target = rusqlite::Connection;
    fn deref(&self) -> &rusqlite::Connection {
        &self.0
    }
}

impl std::ops::DerefMut for PooledConnection {
    fn deref_mut(&mut self) -> &mut rusqlite::Connection {
        &mut self.0
    }
}

/// Builds the connection pool for a `SyncDatabase`.
pub(crate) fn build_pool(
    manager: SqliteConnectionManager,
) -> Result<ConnectionPool, crate::error::DatabaseError> {
    // `Pool::new` (a bare `Pool::builder().build(..)`) defaults `min_idle`
    // to `None`, which r2d2 documents as "maintain as many idle connections
    // as `max_size`" -- i.e. it eagerly establishes connections up to the
    // pool's max size at build time, on background threads, all racing
    // each other against the same file. `SyncDatabase::open`'s own
    // bootstrap connection (see its doc comment) has already put the file
    // into WAL mode before this pool is ever built, so none of these
    // connections' own per-connection init needs to perform a mode switch
    // any more -- but capping the eager fill to 1 still cuts the number of
    // connections concurrently opening the same file at startup, for
    // exactly the same reason `open`'s bootstrap step exists: fewer
    // concurrent openers is strictly safer than more, even once the
    // specific WAL-switch race is closed.
    Ok(Pool::builder().min_idle(Some(1)).thread_pool(worker_pool()).build(manager)?)
}

/// The background workers of one pool: the same three named threads r2d2
/// builds by default, but ones that exit as soon as the pool is dropped.
///
/// r2d2's default worker pool completes every pending *scheduled* job
/// before its threads exit, and every pool always has one pending: the
/// idle-connection reaper, rescheduled every 30 seconds. So each dropped
/// pool kept its three threads alive for up to 30 seconds after the last
/// handle went away. Nothing a dropped pool's workers could still do
/// matters -- the reaper and any pending connection refill only act on
/// the pool, and it is gone -- so discarding them loses nothing. It
/// matters wherever many databases are opened and dropped in quick
/// succession: the daemon's test binary opens several per test, and on
/// macOS the lingering workers alone exceeded the per-process thread
/// limit, failing every later thread spawn with `EAGAIN`.
fn worker_pool() -> std::sync::Arc<scheduled_thread_pool::ScheduledThreadPool> {
    std::sync::Arc::new(
        scheduled_thread_pool::ScheduledThreadPool::builder()
            .num_threads(3)
            .thread_name_pattern("r2d2-worker-{}")
            .on_drop_behavior(scheduled_thread_pool::OnPoolDropBehavior::DiscardPendingScheduled)
            .build(),
    )
}

/// The other half of the `SQLITE_LOCKED` fix (see
/// [`crate::database::new_immediate_write_transaction`]'s doc comment for
/// the first half and the full diagnostic story). SQLite's own
/// documentation is explicit that `SQLITE_LOCKED` arising from shared-cache
/// table locking (as opposed to schema corruption or a genuinely permanent
/// conflict) is meant to be handled by the *caller* retrying the whole
/// failed transaction after a short wait. Wraps `op` (expected to be a
/// self-contained "check out a connection, open a transaction, do the
/// work, commit" closure -- safe to call more than once, since a failed
/// transaction rolls back and leaves no partial state to retry against)
/// and retries it on `SQLITE_LOCKED`/`SQLITE_BUSY` specifically (via
/// `E::is_locked`), up to a small bounded number of attempts with a short
/// linear backoff. Every other error (any genuine data error) propagates
/// immediately, unretried.
///
/// The backoff blocks the calling thread (`std::thread::sleep`), for up to
/// 225ms across a fully contended call, and this is deliberate on both
/// counts:
///
/// * Blocking, because every entry point into this crate
///   (`SyncDatabase::read`/`write`/`write_immediate`) is synchronous, as
///   are the ~200 repository call sites that reach them. There is no
///   runtime here to yield to -- this crate has no dependency on tokio or
///   any other async runtime, by design, since it is shared by callers
///   that are not async at all.
/// * 225ms, because that worst case only materializes when the lock
///   genuinely stayed held for that long, in which case the alternative to
///   waiting is failing. This window has already been widened once in
///   response to a reproduced convergence gap where real concurrent load
///   pushed `SQLITE_BUSY` straight past it; shortening it trades a bounded
///   wait for an unbounded correctness risk.
///
/// What follows for callers: an async caller must not reach `read`/
/// `write`/`write_immediate` inline on a runtime worker. A worker blocked
/// here is not parked -- it runs no other task at all for the duration,
/// which surfaces as time-to-schedule for everything else sharing that
/// runtime, up to and including this device's own QUIC endpoint driver
/// missing the window to send an ack promptly, provoking the peer's own
/// loss detection into retransmitting a datagram that was never lost.
/// Async callers must wrap these calls in
/// `block_in_place` or `spawn_blocking`, on their own side, where the
/// runtime is actually visible.
pub(crate) fn retry_on_database_locked<T, E: SqlOperationError>(
    mut op: impl FnMut() -> Result<T, E>,
) -> Result<T, E> {
    const MAX_ATTEMPTS: u32 = 10;
    let mut attempt: u32 = 0;
    loop {
        match op() {
            Ok(value) => return Ok(value),
            Err(e) if attempt + 1 < MAX_ATTEMPTS && e.is_locked() => {
                attempt += 1;
                std::thread::sleep(Duration::from_millis(5 * attempt as u64));
            }
            Err(e) => return Err(e),
        }
    }
}
