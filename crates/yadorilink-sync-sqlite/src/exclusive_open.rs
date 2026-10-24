//! Opening the replica database for a host with no daemon in front of it.
//!
//! The desktop daemon opens under OS locks it holds for its lifetime
//! (`SyncDatabase::open_process_locked`). A host that cannot hold a lock across suspension
//! proves ownership with a writer lease instead, and the database records the lease's
//! generation, so a writer that outlived its lease cannot reopen what its successor owns.

use rusqlite::Connection;
use yadorilink_root_authority::writer_lease::WriterLease;
use yadorilink_sqlite_runtime::{
    record_writer_generation_in_transaction, DatabaseError, SyncDatabase,
};

/// Opens the database at `path` only while `lease` still proves this process is the data
/// area's one writer, and records the lease's generation in it. A stale or expired lease is
/// refused before the file is touched. A database that already records a newer generation is
/// refused with [`DatabaseError::StaleWriter`] before `schema_init` runs.
///
/// The open runs in two steps. A read-only peek refuses an obviously stale writer cheaply. Then,
/// on the open's own connection, one immediate transaction reads the recorded generation,
/// refuses if it is newer, records this lease's, runs `schema_init`, verifies the lease once
/// more and only then commits; any failure rolls all of it back. Holding the write lock from the
/// record to the commit means no successor can record a newer generation in between, and the
/// final verify means a writer that lost its lease while initializing commits nothing.
///
/// `schema_init` therefore runs inside that transaction: it must not begin one of its own (a
/// savepoint nests) and must not do anything SQLite refuses inside a transaction.
///
/// Residual window: a stall between the final lease verify and the commit, bounded by the
/// lease term, and a stall after this returns before a later commit, which only the commit-time
/// fence stops. The connection's own setup before the transaction (journal mode and
/// durability pragmas) is idempotent and carries no data.
///
/// # Errors
/// [`DatabaseError::WriterLease`] when the lease does not hold (at the start or just before the
/// commit), [`DatabaseError::StaleWriter`] when a newer writer already opened the database,
/// otherwise whatever the open or `schema_init` reports.
pub fn open_exclusive(
    path: impl AsRef<std::path::Path>,
    lease: &WriterLease,
    schema_init: impl FnOnce(&Connection) -> Result<(), DatabaseError>,
) -> Result<SyncDatabase, DatabaseError> {
    open_exclusive_with(path, lease, schema_init, &Seams::default())
}

/// Points where a test interleaves another writer or the end of the lease.
#[derive(Default)]
struct Seams<'a> {
    after_peek: Option<&'a dyn Fn()>,
    after_record: Option<&'a dyn Fn()>,
    before_commit: Option<&'a dyn Fn()>,
}

fn run(seam: Option<&dyn Fn()>) {
    if let Some(seam) = seam {
        seam();
    }
}

fn open_exclusive_with(
    path: impl AsRef<std::path::Path>,
    lease: &WriterLease,
    schema_init: impl FnOnce(&Connection) -> Result<(), DatabaseError>,
    seams: &Seams<'_>,
) -> Result<SyncDatabase, DatabaseError> {
    lease.verify().map_err(|e| DatabaseError::WriterLease(e.to_string()))?;
    let presented = lease.generation();
    if let Some(recorded) = SyncDatabase::peek_writer_generation(path.as_ref())? {
        if recorded > presented {
            return Err(DatabaseError::StaleWriter { recorded, presented });
        }
    }
    run(seams.after_peek);
    SyncDatabase::open_process_locked(path, |conn| {
        // Dropped without a commit on any early return, which rolls everything back.
        let tx =
            rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
        record_writer_generation_in_transaction(&tx, presented)?;
        run(seams.after_record);
        schema_init(conn)?;
        run(seams.before_commit);
        lease.verify().map_err(|e| DatabaseError::WriterLease(e.to_string()))?;
        tx.commit()?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use yadorilink_root_authority::writer_lease::FakeLeaseClock;

    use super::*;

    const TERM: Duration = Duration::from_secs(60);

    fn lease(dir: &std::path::Path, clock: &Arc<FakeLeaseClock>) -> WriterLease {
        WriterLease::acquire(dir, TERM, clock.clone()).expect("acquire")
    }

    fn open(path: &std::path::Path, lease: &WriterLease) -> Result<SyncDatabase, DatabaseError> {
        open_exclusive(path, lease, |_| Ok(()))
    }

    #[test]
    fn open_records_the_lease_generation_and_a_later_lease_raises_it() {
        let dir = tempfile::tempdir().unwrap();
        let area = dir.path().join("area");
        let db_path = dir.path().join("db.sqlite3");
        let clock = FakeLeaseClock::new(1_000);

        let first = lease(&area, &clock);
        let db = open(&db_path, &first).unwrap();
        assert_eq!(db.recorded_writer_generation().unwrap(), Some(first.generation()));
        drop(db);
        first.release();

        let second = lease(&area, &clock);
        assert!(second.generation() > 1);
        let db = open(&db_path, &second).unwrap();
        assert_eq!(db.recorded_writer_generation().unwrap(), Some(second.generation()));
    }

    #[test]
    fn a_lease_older_than_the_recorded_generation_is_refused_as_stale() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("db.sqlite3");
        let clock = FakeLeaseClock::new(1_000);

        // A lease in another area that was taken several times, so its generation is high.
        let newer_area = dir.path().join("newer");
        let mut newer = lease(&newer_area, &clock);
        for _ in 0..3 {
            newer.release();
            newer = lease(&newer_area, &clock);
        }
        drop(open(&db_path, &newer).unwrap());

        let older = lease(&dir.path().join("older"), &clock);
        assert!(older.generation() < newer.generation());
        let refused = open(&db_path, &older);
        assert!(matches!(refused, Err(DatabaseError::StaleWriter { .. })), "{:?}", refused.err());
        let db = open(&db_path, &newer).unwrap();
        assert_eq!(db.recorded_writer_generation().unwrap(), Some(newer.generation()));
    }

    #[test]
    fn a_stale_writer_cannot_run_initialization_that_writes() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("db.sqlite3");
        let clock = FakeLeaseClock::new(1_000);
        let newer_area = dir.path().join("newer");
        let mut newer = lease(&newer_area, &clock);
        for _ in 0..3 {
            newer.release();
            newer = lease(&newer_area, &clock);
        }
        drop(open(&db_path, &newer).unwrap());

        let older = lease(&dir.path().join("older"), &clock);
        let refused = open_exclusive(&db_path, &older, |conn| {
            conn.execute_batch("CREATE TABLE written_by_stale_writer (x INTEGER)")?;
            Ok(())
        });
        assert!(matches!(refused, Err(DatabaseError::StaleWriter { .. })), "{:?}", refused.err());

        let db = open(&db_path, &newer).unwrap();
        let tables: i64 = db
            .read::<_, DatabaseError>(|conn| {
                Ok(conn.query_row(
                    "SELECT count(*) FROM sqlite_master WHERE name = 'written_by_stale_writer'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(tables, 0, "the refused writer's initialization must not have run");
    }

    #[test]
    fn a_writer_superseded_between_the_peek_and_the_open_initializes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("db.sqlite3");
        let clock = FakeLeaseClock::new(1_000);
        let older = lease(&dir.path().join("older"), &clock);
        drop(open(&db_path, &older).unwrap());

        let initialized = std::cell::Cell::new(false);
        let successor = || {
            let successor = SyncDatabase::open_process_locked(&db_path, |_| Ok(())).unwrap();
            successor.record_writer_generation(older.generation() + 5).unwrap();
        };
        let refused = open_exclusive_with(
            &db_path,
            &older,
            |_| {
                initialized.set(true);
                Ok(())
            },
            &Seams { after_peek: Some(&successor), ..Seams::default() },
        );
        assert!(matches!(refused, Err(DatabaseError::StaleWriter { .. })), "{:?}", refused.err());
        assert!(!initialized.get(), "the stale writer's initialization must never run");
        let db = SyncDatabase::open_process_locked(&db_path, |_| Ok(())).unwrap();
        assert_eq!(db.recorded_writer_generation().unwrap(), Some(older.generation() + 5));
    }

    fn unchanged(db_path: &std::path::Path) -> (Option<u64>, i64) {
        let db = SyncDatabase::open_process_locked(db_path, |_| Ok(())).unwrap();
        let init_tables = db
            .read::<_, DatabaseError>(|conn| {
                Ok(conn.query_row(
                    "SELECT count(*) FROM sqlite_master WHERE name = 'init_effect'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        (db.recorded_writer_generation().unwrap(), init_tables)
    }

    #[test]
    fn a_successor_cannot_record_between_the_record_and_the_initialization() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("db.sqlite3");
        let clock = FakeLeaseClock::new(1_000);
        let held = lease(&dir.path().join("area"), &clock);
        // The record table already exists (committed), so the only thing that can stop the
        // seam's write is the open's lock.
        SyncDatabase::open_process_locked(&db_path, |_| Ok(()))
            .unwrap()
            .record_writer_generation(0)
            .unwrap();

        // The seam sits between the record and the initialization and tries what a successor
        // would: record a newer generation on its own connection. The open's write lock is held
        // across both steps, so the attempt cannot get in.
        let blocked = std::cell::Cell::new(false);
        let successor = || {
            let other = Connection::open(&db_path).unwrap();
            other.busy_timeout(Duration::ZERO).unwrap();
            let attempt =
                other.execute_batch("UPDATE writer_generation SET generation = 99 WHERE id = 1");
            blocked.set(attempt.is_err_and(|e| e.to_string().contains("locked")));
        };
        let db = open_exclusive_with(
            &db_path,
            &held,
            |conn| {
                conn.execute_batch("CREATE TABLE init_effect (x INTEGER)")?;
                Ok(())
            },
            &Seams { after_record: Some(&successor), ..Seams::default() },
        )
        .unwrap();
        assert!(blocked.get(), "a second writer must not get in between record and init");
        assert_eq!(db.recorded_writer_generation().unwrap(), Some(held.generation()));
    }

    #[test]
    fn a_lease_lost_during_initialization_commits_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("db.sqlite3");
        let clock = FakeLeaseClock::new(1_000);
        let held = lease(&dir.path().join("area"), &clock);

        let expire = || clock.advance(TERM * 2);
        let refused = open_exclusive_with(
            &db_path,
            &held,
            |conn| {
                conn.execute_batch("CREATE TABLE init_effect (x INTEGER)")?;
                Ok(())
            },
            &Seams { before_commit: Some(&expire), ..Seams::default() },
        );
        assert!(matches!(refused, Err(DatabaseError::WriterLease(_))), "{:?}", refused.err());
        assert_eq!(unchanged(&db_path), (None, 0), "neither the record nor the init survived");
    }

    #[test]
    fn a_failing_initialization_rolls_the_record_back() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("db.sqlite3");
        let clock = FakeLeaseClock::new(1_000);
        let held = lease(&dir.path().join("area"), &clock);

        let refused = open_exclusive(&db_path, &held, |conn| {
            conn.execute_batch("CREATE TABLE init_effect (x INTEGER)")?;
            Err(DatabaseError::CorruptSchema("init failed".into()))
        });
        assert!(matches!(refused, Err(DatabaseError::CorruptSchema(_))));
        assert_eq!(unchanged(&db_path), (None, 0));
    }

    #[test]
    fn a_fresh_replica_database_initializes_after_the_generation_is_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("db.sqlite3");
        let clock = FakeLeaseClock::new(1_000);
        let held = lease(&dir.path().join("area"), &clock);
        let init = |conn: &Connection| {
            crate::init_replica_schema(conn)
                .map_err(|e| DatabaseError::CorruptSchema(format!("{e:?}")))
        };
        drop(open_exclusive(&db_path, &held, init).unwrap());
        // A reopen finds the stamped schema and the record, and accepts both.
        let db = open_exclusive(&db_path, &held, init).unwrap();
        assert_eq!(db.recorded_writer_generation().unwrap(), Some(held.generation()));
    }

    #[test]
    fn an_expired_lease_is_refused_before_the_file_is_created() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("db.sqlite3");
        let clock = FakeLeaseClock::new(1_000);
        let held = lease(&dir.path().join("area"), &clock);
        clock.advance(TERM * 2);

        let refused = open(&db_path, &held);
        assert!(matches!(refused, Err(DatabaseError::WriterLease(_))), "{:?}", refused.err());
        assert!(!db_path.exists(), "a refused open must not create the database");
    }
}
