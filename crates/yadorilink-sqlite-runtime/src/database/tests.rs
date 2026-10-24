#![cfg(test)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::*;

fn schema_init(conn: &Connection) -> Result<(), DatabaseError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS admitted_changes (group_id TEXT NOT NULL, change_hash BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS group_history_bases (group_id TEXT NOT NULL, history_base BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS history_base_path_heads (group_id TEXT NOT NULL, base_hash BLOB NOT NULL, change_hash BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS history_base_carried_authors (group_id TEXT NOT NULL, base_hash BLOB NOT NULL, change_hash BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS native_authoring_witness (group_id TEXT NOT NULL, identity BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS published_evidence (change_hash BLOB NOT NULL, checkpoint_hash BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS authorization_checkpoints (checkpoint_hash BLOB NOT NULL, group_id TEXT NOT NULL);",
    )?;
    crate::schema::init_schema(conn)
}

fn open_test_db(path: &std::path::Path) -> SyncDatabase {
    SyncDatabase::open(path, schema_init).expect("open")
}

#[test]
fn repositories_sharing_database_do_not_race_independent_writer_gates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let database = Arc::new(open_test_db(&dir.path().join("writer-gate-regression.sqlite3")));

    database
        .write::<_, DatabaseError>(|conn: &mut Connection| {
            Ok(conn.execute_batch(
                "CREATE TABLE a (id INTEGER PRIMARY KEY); CREATE TABLE b (id INTEGER PRIMARY KEY);",
            )?)
        })
        .expect("create tables");

    let long_writer_started = Arc::new(AtomicBool::new(false));
    let long_writer_database = database.clone();
    let long_writer_flag = long_writer_started.clone();
    let long_writer = std::thread::spawn(move || {
        long_writer_database.write_immediate::<_, DatabaseError>(|tx| {
            tx.execute("INSERT INTO a (id) VALUES (1)", [])?;
            long_writer_flag.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(200));
            Ok::<(), DatabaseError>(())
        })
    });

    while !long_writer_started.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(5));
    }

    // While the long writer_immediate transaction on table `a` is still
    // held, a short write on table `b` through the SAME shared
    // `SyncDatabase` must still succeed -- serialized behind the
    // writer_gate, never `SQLITE_LOCKED`.
    let short_write_result = database.write::<_, DatabaseError>(|conn: &mut Connection| {
        Ok(conn.execute("INSERT INTO b (id) VALUES (2)", [])?)
    });

    long_writer.join().expect("long writer thread panicked").expect("long writer");
    short_write_result.expect(
        "a write on one table must succeed while another write_immediate transaction is \
         held on a different table through the same shared writer_gate, not \
         SQLITE_LOCKED/SQLITE_BUSY",
    );

    let b_count: i64 = database
        .read::<i64, DatabaseError>(|conn| {
            Ok(conn.query_row("SELECT COUNT(*) FROM b", [], |row| row.get(0))?)
        })
        .expect("read back");
    assert_eq!(b_count, 1);
}

/// The writer_gate must release even when the write closure itself
/// returns an error -- otherwise one failed write would permanently
/// wedge every subsequent write on this `SyncDatabase`.
#[test]
fn writer_gate_releases_after_an_operation_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let database = open_test_db(&dir.path().join("writer-gate-error-release.sqlite3"));
    database
        .write::<_, DatabaseError>(|conn: &mut Connection| {
            Ok(conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)")?)
        })
        .expect("create table");

    let failing: Result<(), DatabaseError> =
        database.write::<_, DatabaseError>(|conn: &mut Connection| {
            conn.execute("INSERT INTO t (id) VALUES (1)", [])?;
            Err(DatabaseError::CorruptSchema("deliberate test failure".into()))
        });
    assert!(failing.is_err());

    // The gate must not be wedged: this write must still go through.
    database
        .write::<_, DatabaseError>(|conn: &mut Connection| {
            Ok(conn.execute("INSERT INTO t (id) VALUES (2)", [])?)
        })
        .expect("writer_gate must have been released after the prior error");
}

/// `write_immediate` must leave no partial write behind on failure --
/// the transaction rolls back rather than committing a half-applied
/// operation.
#[test]
fn write_immediate_leaves_no_partial_write_on_failure() {
    let dir = tempfile::tempdir().expect("tempdir");
    let database = open_test_db(&dir.path().join("write-immediate-rollback.sqlite3"));
    database
        .write::<_, DatabaseError>(|conn: &mut Connection| {
            Ok(conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)")?)
        })
        .expect("create table");

    let failing: Result<(), DatabaseError> = database.write_immediate::<_, DatabaseError>(|tx| {
        tx.execute("INSERT INTO t (id) VALUES (1)", [])?;
        Err(DatabaseError::CorruptSchema("deliberate test failure".into()))
    });
    assert!(failing.is_err());

    let count: i64 = database
        .read::<i64, DatabaseError>(|conn| {
            Ok(conn.query_row("SELECT COUNT(*) FROM t", [], |row| row.get(0))?)
        })
        .expect("read back");
    assert_eq!(count, 0, "a failed write_immediate must not leave a partial row committed");
}

/// Data and schema must both survive a close-and-reopen of the same
/// file-backed database.
#[test]
fn data_and_schema_survive_a_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("reopen-survives.sqlite3");
    {
        let database = open_test_db(&path);
        database
            .write::<_, DatabaseError>(|conn: &mut Connection| {
                conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)")?;
                Ok(conn.execute("INSERT INTO t (id) VALUES (42)", [])?)
            })
            .expect("create + insert");
    }

    let reopened = open_test_db(&path);
    let value: i64 = reopened
        .read::<i64, DatabaseError>(|conn| {
            Ok(conn.query_row("SELECT id FROM t", [], |row| row.get(0))?)
        })
        .expect("read back after reopen");
    assert_eq!(value, 42);
}

/// Opening the same database twice in a row (schema already present)
/// must not fail -- `init_schema`'s own `CREATE TABLE IF NOT EXISTS`
/// migrations must be idempotent, not just safe to run once.
#[test]
fn schema_initialization_is_idempotent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("idempotent-init.sqlite3");
    let _first = open_test_db(&path);
    let _second = open_test_db(&path);
}

/// Armed, `write_immediate` records one body/commit split against its own
/// call site, and the commit is a separately timed, non-zero step. A
/// disarmed instrument records nothing for the same call.
#[test]
fn split_stats_record_body_and_commit_for_an_armed_write_immediate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let database = open_test_db(&dir.path().join("split.sqlite3"));
    database
        .write::<_, DatabaseError>(|conn| Ok(conn.execute_batch("CREATE TABLE s (id INTEGER)")?))
        .expect("create");

    // `fmt` may wrap the call, so match any line within the statement.
    let find = |line: u32| {
        writer_gate_stats::split_site_stats().into_iter().find(|s| {
            s.site
                .rsplit_once("tests.rs:")
                .and_then(|(_, n)| n.parse::<u32>().ok())
                .is_some_and(|n| (line..line + 4).contains(&n))
        })
    };

    writer_gate_stats::set_split_enabled(false);
    let off_line = line!() + 1;
    database
        .write_immediate::<_, DatabaseError>(|tx| Ok(tx.execute("INSERT INTO s VALUES (1)", [])?))
        .expect("off");
    assert!(find(off_line).is_none(), "a disarmed instrument records nothing");

    writer_gate_stats::set_split_enabled(true);
    let on_line = line!() + 1;
    database
        .write_immediate::<_, DatabaseError>(|tx| Ok(tx.execute("INSERT INTO s VALUES (2)", [])?))
        .expect("on");
    writer_gate_stats::set_split_enabled(false);

    let stat = find(on_line).expect("armed write_immediate records its call site");
    assert_eq!(stat.calls, 1);
    assert_eq!(stat.commit_calls, 1);
    assert!(stat.commit_nanos > 0, "the commit is timed separately from the body");
    assert!(stat.body_nanos > 0);
    let (_, commit_p99) = writer_gate_stats::split_percentile_nanos(0.99);
    assert!(commit_p99 > 0);
}

// -- `write_immediate_offloaded` and its job fence ---------------------------

/// A table to commit into and a way to see what landed.
fn offload_db(dir: &std::path::Path) -> Arc<SyncDatabase> {
    let database = Arc::new(open_test_db(&dir.join("offload.sqlite3")));
    database
        .write::<_, DatabaseError>(|conn: &mut Connection| {
            Ok(conn.execute_batch("CREATE TABLE offloaded (id INTEGER PRIMARY KEY, who TEXT);")?)
        })
        .expect("create table");
    database
}

fn offloaded_rows(database: &SyncDatabase) -> Vec<String> {
    database
        .read::<_, DatabaseError>(|conn| {
            let mut stmt = conn.prepare("SELECT who FROM offloaded ORDER BY id")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
        .expect("read rows")
}

/// A guard that records when it is dropped, standing for the path lock, the
/// root operations and the claim a file's frames hold around its commit.
struct StampOnDrop(Arc<Mutex<Option<std::time::Instant>>>);

impl Drop for StampOnDrop {
    fn drop(&mut self) {
        *self.0.lock().unwrap() = Some(std::time::Instant::now());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_offloaded_write_commits_and_returns_its_value() {
    let dir = tempfile::tempdir().unwrap();
    let database = offload_db(dir.path());
    let id = database
        .write_immediate_offloaded::<_, DatabaseError>(|tx| {
            tx.execute("INSERT INTO offloaded (who) VALUES ('a')", [])?;
            Ok(tx.last_insert_rowid())
        })
        .await
        .unwrap();
    assert_eq!(id, 1);
    assert_eq!(offloaded_rows(&database), vec!["a".to_string()]);
}

/// Dropping the awaiting future mid-job keeps what its caller's frames hold
/// until the commit has landed: the guard (declared before the call, so it
/// is a caller-frame resource) is dropped only after the job committed, and
/// the job still commits although nobody awaits it any more.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_awaiting_future_keeps_the_callers_guards_until_the_commit_lands() {
    let dir = tempfile::tempdir().unwrap();
    let database = offload_db(dir.path());
    let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let committed_at: Arc<Mutex<Option<std::time::Instant>>> = Arc::default();
    let guard_dropped_at: Arc<Mutex<Option<std::time::Instant>>> = Arc::default();

    let task = tokio::spawn({
        let database = database.clone();
        let (committed_at, guard_dropped_at) = (committed_at.clone(), guard_dropped_at.clone());
        let release_rx = Mutex::new(release_rx);
        async move {
            let _guard = StampOnDrop(guard_dropped_at);
            let entered_tx = Mutex::new(entered_tx);
            database
                .write_immediate_offloaded::<_, DatabaseError>(move |tx| {
                    tx.execute("INSERT INTO offloaded (who) VALUES ('job')", [])?;
                    entered_tx.lock().unwrap().send(()).unwrap();
                    release_rx.lock().unwrap().recv().unwrap();
                    *committed_at.lock().unwrap() = Some(std::time::Instant::now());
                    Ok(())
                })
                .await
        }
    });
    tokio::task::spawn_blocking(move || entered_rx.recv().unwrap()).await.unwrap();

    // Release the job after the awaiting task has been aborted and is stuck
    // in its fence.
    let releaser = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        release_tx.send(()).unwrap();
    });
    task.abort();
    let _ = task.await;
    releaser.join().unwrap();

    let committed = committed_at.lock().unwrap().expect("the job still ran to its end");
    let released = guard_dropped_at.lock().unwrap().expect("the guard was dropped");
    assert!(released >= committed, "the caller's guard was released before the commit landed");
    assert_eq!(offloaded_rows(&database), vec!["job".to_string()]);
}

/// A panic in the job rolls the transaction back, completes the fence (the
/// writer gate is free again and a dropped waiter would not hang) and is
/// raised in the awaiting task, as the inline call would.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panic_in_the_job_rolls_back_and_completes_the_fence() {
    let dir = tempfile::tempdir().unwrap();
    let database = offload_db(dir.path());
    let task = tokio::spawn({
        let database = database.clone();
        async move {
            database
                .write_immediate_offloaded::<(), DatabaseError>(|tx| {
                    tx.execute("INSERT INTO offloaded (who) VALUES ('doomed')", [])?;
                    panic!("injected panic inside the commit");
                })
                .await
        }
    });
    let joined = task.await;
    assert!(joined.is_err_and(|error| error.is_panic()), "the panic must reach the awaiting task");
    assert!(offloaded_rows(&database).is_empty(), "the transaction must roll back");
    // The gate was released: a later write is not blocked.
    database
        .write_immediate_offloaded::<_, DatabaseError>(|tx| {
            tx.execute("INSERT INTO offloaded (who) VALUES ('after')", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(offloaded_rows(&database), vec!["after".to_string()]);
}

/// The job takes nothing the dropping side holds: with a lock held by the
/// side that drops the awaiting future, the job still commits, and the lock
/// is still held when it has.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_job_never_waits_for_what_the_dropping_side_holds() {
    let dir = tempfile::tempdir().unwrap();
    let database = offload_db(dir.path());
    let held_by_dropper = Arc::new(Mutex::new(()));
    let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let task = tokio::spawn({
        let database = database.clone();
        let release_rx = Mutex::new(release_rx);
        async move {
            let entered_tx = Mutex::new(entered_tx);
            database
                .write_immediate_offloaded::<_, DatabaseError>(move |tx| {
                    entered_tx.lock().unwrap().send(()).unwrap();
                    release_rx.lock().unwrap().recv().unwrap();
                    tx.execute("INSERT INTO offloaded (who) VALUES ('job')", [])?;
                    Ok(())
                })
                .await
        }
    });
    tokio::task::spawn_blocking(move || entered_rx.recv().unwrap()).await.unwrap();

    // This thread holds the lock while the awaiting future is dropped from a
    // thread of its own; the job is released only afterwards.
    let held = held_by_dropper.lock().unwrap();
    let dropper = std::thread::spawn(move || {
        task.abort();
    });
    dropper.join().unwrap();
    release_tx.send(()).unwrap();
    drop(held);
    for _ in 0..200 {
        if offloaded_rows(&database).len() == 1 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the job did not commit while the dropper held its lock");
}

/// A waiter dropped inside a write transaction while its job is still live
/// is detected and fail-stops (the guards it covers must not be released
/// under a live job, and waiting could deadlock on the gate this thread
/// holds); with a finished job it is fine.
#[test]
fn a_fence_wait_dropped_inside_a_write_transaction_with_a_live_job_fail_stops() {
    let dir = tempfile::tempdir().unwrap();
    let database = offload_db(dir.path());
    let live = JobFence::new();
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let sink = seen.clone();
    live.set_test_hooks(
        move |reason| sink.lock().unwrap().push(reason.to_owned()),
        |_| {},
        Duration::from_secs(60),
    );
    let live_completion = live.completion();
    let finished = JobFence::new();
    drop(finished.completion());
    database
        .write_immediate::<_, DatabaseError>(|tx| {
            tx.execute("INSERT INTO offloaded (who) VALUES ('x')", [])?;
            drop(finished.waiter());
            assert!(seen.lock().unwrap().is_empty(), "a finished job is not a fault");
            drop(live.waiter());
            Ok(())
        })
        .unwrap();
    assert_eq!(seen.lock().unwrap().len(), 1, "a live job under a write transaction");
    drop(live_completion);
}

/// `synchronous = FULL` asks SQLite to `fsync`, and on Apple platforms `fsync` does not flush the
/// drive's write cache. `fullfsync` / `checkpoint_fullfsync` do, so when requested every pooled
/// connection must carry them; by default they are on for Apple platforms (macOS and iOS).
fn fullfsync_pragmas(options: Option<OpenOptions>) -> Vec<(i64, i64, i64)> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("fullfsync.sqlite3");
    let database = match options {
        Some(options) => SyncDatabase::open_with_options(&path, options, |_| Ok(())),
        None => SyncDatabase::open(&path, |_| Ok(())),
    }
    .expect("open");
    // Hold several pooled connections at once so the check is not one lucky connection.
    let held: Vec<_> =
        (0..3).map(|_| database.pool_for_test().get().expect("connection")).collect();
    held.iter()
        .map(|pooled| {
            let pragma = |name: &str| -> i64 {
                pooled.query_row(&format!("PRAGMA {name}"), [], |row| row.get(0)).expect(name)
            };
            (pragma("synchronous"), pragma("fullfsync"), pragma("checkpoint_fullfsync"))
        })
        .collect()
}

#[test]
fn requested_drive_cache_flush_applies_to_every_pooled_connection() {
    for pragmas in fullfsync_pragmas(Some(OpenOptions { flush_drive_cache: true })) {
        assert_eq!(pragmas, (2, 1, 1), "synchronous FULL + fullfsync + checkpoint_fullfsync");
    }
}

#[test]
fn drive_cache_flush_is_off_unless_requested_and_default_is_apple_only() {
    for pragmas in fullfsync_pragmas(Some(OpenOptions { flush_drive_cache: false })) {
        assert_eq!(pragmas, (2, 0, 0));
    }
    let expected = i64::from(cfg!(target_vendor = "apple"));
    for pragmas in fullfsync_pragmas(None) {
        assert_eq!(pragmas, (2, expected, expected), "default open");
    }
}

#[test]
fn a_checkpoint_folds_the_log_into_the_database_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("checkpoint.sqlite3");
    let database = open_test_db(&path);
    database
        .write::<_, DatabaseError>(|conn: &mut Connection| {
            Ok(conn.execute_batch(
                "CREATE TABLE t (id INTEGER PRIMARY KEY); INSERT INTO t (id) VALUES (1), (2), (3);",
            )?)
        })
        .expect("write");
    let log = path.with_file_name("checkpoint.sqlite3-wal");
    assert!(std::fs::metadata(&log).map(|m| m.len()).unwrap_or(0) > 0, "writes sit in the log");

    database.checkpoint_truncate().expect("checkpoint");
    assert_eq!(std::fs::metadata(&log).map(|m| m.len()).unwrap_or(0), 0, "the log is truncated");

    // The main file stands alone: a second open sees the rows even with the log removed.
    drop(database);
    let _ = std::fs::remove_file(&log);
    let reopened = open_test_db(&path);
    let rows: i64 = reopened
        .read::<_, DatabaseError>(|conn| {
            Ok(conn.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))?)
        })
        .expect("count");
    assert_eq!(rows, 3);
}

#[test]
fn a_checkpoint_of_an_in_memory_database_is_a_no_op() {
    let database = SyncDatabase::open_in_memory(schema_init).expect("open");
    database.checkpoint_truncate().expect("nothing to fold");
}

#[test]
fn dropping_the_database_waits_for_a_connection_a_pool_worker_is_still_opening() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("closing.sqlite3");
    let database = SyncDatabase::open(&path, |_| Ok(())).expect("open");
    let connections = database.connections_for_test();
    // Taking the idle connection makes the pool open a replacement on a worker thread; make that
    // slow, then drop the database while it is still opening.
    connections.delay_connects_for_test(std::time::Duration::from_millis(400));
    database
        .read::<_, DatabaseError>(
            |conn| Ok(conn.query_row("SELECT 1", [], |r| r.get::<_, i64>(0))?),
        )
        .expect("read");
    drop(database);
    assert_eq!(connections.live(), 0, "a connection outlived the database");
    // Every connection is closed, so SQLite has removed the write-ahead log it kept for them.
    assert!(!dir.path().join("closing.sqlite3-wal").exists());
    assert!(!dir.path().join("closing.sqlite3-shm").exists());
}

mod writer_generation {
    use super::*;

    #[test]
    fn a_generation_is_recorded_and_a_higher_one_replaces_it() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_test_db(&dir.path().join("db.sqlite3"));
        assert_eq!(db.recorded_writer_generation().unwrap(), None);
        db.record_writer_generation(3).unwrap();
        assert_eq!(db.recorded_writer_generation().unwrap(), Some(3));
        db.record_writer_generation(3).unwrap();
        db.record_writer_generation(7).unwrap();
        assert_eq!(db.recorded_writer_generation().unwrap(), Some(7));
    }

    #[test]
    fn an_older_generation_is_refused_and_leaves_the_record_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite3");
        open_test_db(&path).record_writer_generation(7).unwrap();

        let db = open_test_db(&path);
        let refused = db.record_writer_generation(6);
        assert!(
            matches!(refused, Err(DatabaseError::StaleWriter { recorded: 7, presented: 6 })),
            "{refused:?}"
        );
        assert_eq!(db.recorded_writer_generation().unwrap(), Some(7));
    }
}
