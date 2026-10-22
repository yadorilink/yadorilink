//! What the root-set generation triggers cost the write path.
//!
//! The generation counter is the one part of the background-custody redesign
//! that touches the hot import path: every `files` insert, update and delete
//! now also upserts a single row in `file_root_set_generation`. A group's
//! row is the same row every time, so the contention is on one B-tree page
//! that stays hot — but "should be cheap" is not a measurement, and this
//! repository has been wrong before about which half of a write dominated.
//!
//! So this measures the added cost directly, on the same database, in the
//! same transaction shape an import uses, rather than inferring it from an
//! end-to-end run where a dozen other things also change. The end-to-end
//! import canary still has to be run; this says what it should expect to
//! find, and localises a regression if it finds something else.
//!
//! `#[ignore]`d: it writes 100k rows twice, to real files, on a real disk.
//! An ignored test still has to COMPILE, which is the part CI is for here.
//!
//! Run with:
//!   YADORILINK_BENCH_DIR=/some/path/on/a/real/disk \
//!   cargo test -p yadorilink-sync-sqlite --release --test \
//!       root_set_generation_write_cost -- --ignored --nocapture
//!
//! Release, not debug: the thing being measured is SQLite's work, and a
//! debug build's rusqlite overhead is a constant added to both arms that
//! makes the ratio look better than it is.
//!
//! **`YADORILINK_BENCH_DIR` is required, and is checked.** The default
//! temporary directory on the machines this runs on is a tmpfs, and a
//! tmpfs-backed SQLite benchmark measures memcpy. It would report a
//! flattering ratio for a change whose entire cost is page writes, and it
//! would report it confidently. The same mistake has already cost this
//! repository a whole measurement round, in the other direction: a
//! rotational scratch disk once made an unchanged binary look 8x slower.
//! So the location is named explicitly and refused if it is a tmpfs.

use std::time::{Duration, Instant};

use rusqlite::Connection;
use yadorilink_replica_domain::file::BlockInfo;
use yadorilink_sqlite_runtime::init_schema;

const ROWS: usize = 100_000;
const ROWS_PER_TRANSACTION: usize = 1_000;

fn dag_tables(conn: &Connection) {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS changes (
             group_id TEXT NOT NULL, change_hash BLOB NOT NULL
         );
         CREATE TABLE IF NOT EXISTS pruned_changes (
             group_id TEXT NOT NULL, change_hash BLOB NOT NULL
         );
         CREATE TABLE IF NOT EXISTS group_history_bases (
             group_id TEXT NOT NULL, history_base BLOB NOT NULL
         );
         CREATE TABLE IF NOT EXISTS history_base_path_heads (
             group_id TEXT NOT NULL, base_hash BLOB NOT NULL, change_hash BLOB NOT NULL
         );
         CREATE TABLE IF NOT EXISTS history_base_carried_authors (
             group_id TEXT NOT NULL, base_hash BLOB NOT NULL, change_hash BLOB NOT NULL
         );",
    )
    .unwrap();
}

/// A file-backed database with the production schema, WAL on, in `dir`.
///
/// File-backed and not in-memory on purpose: the counter's cost is a page
/// write, and an in-memory database has no page writes to speak of. It would
/// report whatever ratio the CPU happened to produce and none of the I/O the
/// question is about.
fn open(dir: &std::path::Path, with_triggers: bool) -> Connection {
    let conn = Connection::open(dir.join("index.sqlite3")).unwrap();
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;").unwrap();
    dag_tables(&conn);
    init_schema(&conn).unwrap();
    if !with_triggers {
        conn.execute_batch(
            "DROP TRIGGER IF EXISTS files_root_set_generation_on_insert;
             DROP TRIGGER IF EXISTS files_root_set_generation_on_update;
             DROP TRIGGER IF EXISTS files_root_set_generation_on_delete;",
        )
        .unwrap();
    }
    conn
}

fn insert_rows(conn: &mut Connection) -> Duration {
    let started = Instant::now();
    let mut written = 0;
    while written < ROWS {
        let tx = conn.transaction().unwrap();
        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, \
                     deleted, version_seq, state, origin_device_id, record_kind) \
                     VALUES ('g', ?1, 1, 1, '[]', 0, 1, 'current', 'device-a', 'file')",
                )
                .unwrap();
            for i in written..(written + ROWS_PER_TRANSACTION).min(ROWS) {
                stmt.execute([format!("f{i:07}.bin")]).unwrap();
            }
        }
        tx.commit().unwrap();
        written += ROWS_PER_TRANSACTION;
    }
    started.elapsed()
}

/// The directory both arms write their databases into, from
/// `YADORILINK_BENCH_DIR`, refusing anything that is not a real filesystem.
///
/// Panics rather than falling back. A benchmark that quietly relocates
/// itself to RAM still prints a number, and the number is about RAM.
fn bench_dir() -> std::path::PathBuf {
    let raw = std::env::var("YADORILINK_BENCH_DIR").expect(
        "YADORILINK_BENCH_DIR must name a directory on a real disk -- the default temporary \
         directory here is a tmpfs, and this benchmark's whole subject is page writes",
    );
    let dir = std::path::PathBuf::from(raw);
    std::fs::create_dir_all(&dir).expect("create the benchmark directory");

    let fstype = std::process::Command::new("stat")
        .args(["-f", "-c", "%T"])
        .arg(&dir)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    assert!(
        fstype != "tmpfs" && fstype != "ramfs",
        "YADORILINK_BENCH_DIR is on {fstype:?}; a memory-backed filesystem cannot measure the \
         cost of a page write"
    );
    println!("benchmark directory: {} (fs: {fstype})", dir.display());
    println!("load average at start: {}", load_average());
    dir
}

/// The 1-minute load average, printed alongside every result.
///
/// Not decoration. The first run of this file was taken on an idle machine
/// and the second while a parallel build saturated the box: the same binary
/// against the same directory reported 0.32s and 1.42s, a 4.5x spread, and
/// the RATIO moved too -- contention inflates both arms and so shrinks the
/// share a fixed per-row cost takes. A number from this file without the
/// load it was taken under is not comparable to any other number from it.
fn load_average() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(str::to_string))
        .unwrap_or_else(|| "unknown".into())
}

#[test]
#[ignore = "writes 100k rows twice to a real disk; run explicitly"]
fn the_generation_triggers_cost_the_import_path_this_much() {
    let base = bench_dir();
    let with_dir = tempfile::tempdir_in(&base).unwrap();
    let without_dir = tempfile::tempdir_in(&base).unwrap();

    // Without first, so the with-triggers arm cannot benefit from a page
    // cache the other arm warmed. Both arms then run against a cold, empty
    // database of their own.
    let mut without = open(without_dir.path(), false);
    let baseline = insert_rows(&mut without);

    let mut with = open(with_dir.path(), true);
    let measured = insert_rows(&mut with);

    let generation: i64 = with
        .query_row(
            "SELECT generation FROM file_root_set_generation WHERE group_id = 'g'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        generation as usize, ROWS,
        "the arm that was supposed to have triggers must actually have had them -- a benchmark \
         whose treatment silently did nothing reports a flattering ratio and means nothing"
    );

    let overhead = measured.as_secs_f64() / baseline.as_secs_f64();
    println!(
        "{ROWS} rows, {ROWS_PER_TRANSACTION} per transaction (load {}):\n  \
         without triggers: {:.3}s\n  \
         with triggers:    {:.3}s\n  \
         ratio:            {overhead:.3}x",
        load_average(),
        baseline.as_secs_f64(),
        measured.as_secs_f64(),
    );

    // Deliberately generous, and deliberately present. The number this
    // prints is what a reader wants; the assertion exists so that a change
    // making the counter cost several times the write it observes fails
    // here rather than in an end-to-end import run where a dozen other
    // things also moved.
    assert!(
        overhead < 2.0,
        "the generation counter must not dominate the write it observes (measured {overhead:.3}x)"
    );
}

/// What a background cycle's LOCAL half costs at scale, and what the memo
/// saves.
///
/// The peer-facing half of a cycle is one round-trip per group and is
/// already pinned at zero per-root requests by the daemon's own scale test.
/// The half that is genuinely new cost is this one: on a memo miss, the
/// summary is an indexed scan plus a version-hash recomputation per root,
/// and `file_root_set_generation` is the one row read that decides whether
/// that happens at all.
///
/// So the two numbers worth having are the memo-key read (must not grow with
/// the group) and the recomputation (must be linear, not quadratic, in it) —
/// measured at two sizes an order of magnitude apart, because a single size
/// cannot tell linear from quadratic and a ratio can.
#[test]
#[ignore = "builds 8k- and 80k-row databases on a real disk; run explicitly"]
fn the_local_summary_is_linear_and_the_memo_key_is_flat() {
    let base = bench_dir();

    let mut rows = Vec::new();
    for size in [8_000usize, 80_000usize] {
        let dir = tempfile::tempdir_in(&base).unwrap();
        let mut conn = open(dir.path(), true);
        insert_n(&mut conn, size);

        // The memo key. Read on every cycle, whether or not anything moved.
        let started = Instant::now();
        for _ in 0..100 {
            let _: i64 = conn
                .query_row(
                    "SELECT generation FROM file_root_set_generation WHERE group_id = 'g'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
        }
        let generation_us = started.elapsed().as_secs_f64() * 1e6 / 100.0;

        // The recomputation, which a cycle pays only when the root set has
        // actually moved since the last one.
        let started = Instant::now();
        let summary =
            yadorilink_sync_sqlite::file_index::group_root_set_summary_on_conn(&conn, "g", 0)
                .unwrap();
        let summary_ms = started.elapsed().as_secs_f64() * 1e3;
        // `roots_count` spans all three retained states, so it is the
        // current rows plus the superseded ones `insert_n` adds for every
        // tenth path -- not `size`. Asserted rather than assumed, because a
        // scan that silently saw a different set than intended would report
        // a scaling curve for the wrong workload.
        let expected_roots = size + size.div_ceil(10);
        assert_eq!(
            summary.roots_count as usize, expected_roots,
            "the scan must have seen every retained row"
        );
        assert_eq!(summary.current_count as usize, size);

        println!(
            "{size} roots: memo-key read {generation_us:.1}us, \
             summary recompute {summary_ms:.1}ms ({:.2}us/root), load {}",
            summary_ms * 1e3 / size as f64,
            load_average(),
        );
        rows.push((size, generation_us, summary_ms));
    }

    let (small_n, small_key, small_summary) = rows[0];
    let (big_n, big_key, big_summary) = rows[1];
    let n_ratio = big_n as f64 / small_n as f64;

    // The key read is one indexed row and must not notice the group at all.
    // Generous, because at microsecond scale the measurement is mostly
    // noise -- what it would catch is the key becoming a scan.
    assert!(
        big_key < small_key * 4.0,
        "the memo key must not grow with the group: {small_key:.1}us at {small_n} vs \
         {big_key:.1}us at {big_n}"
    );

    // Linear, not quadratic. At a 10x size a linear scan costs ~10x; a
    // quadratic one costs ~100x. The bound sits between them by enough that
    // ordinary variance cannot reach it.
    let summary_ratio = big_summary / small_summary;
    println!("summary scaling: {summary_ratio:.2}x for {n_ratio:.0}x the roots");
    assert!(
        summary_ratio < n_ratio * 3.0,
        "the summary recompute must be linear in the root count, not quadratic: \
         {summary_ratio:.2}x for {n_ratio:.0}x the roots"
    );
}

/// Inserts `n` current rows plus one superseded version for every tenth
/// path, so the two digests the summary computes are over genuinely
/// different sets rather than the same one twice.
fn insert_n(conn: &mut Connection, n: usize) {
    let mut written = 0;
    while written < n {
        let tx = conn.transaction().unwrap();
        {
            let mut current = tx
                .prepare(
                    "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, \
                     deleted, version_seq, state, origin_device_id, record_kind) \
                     VALUES ('g', ?1, 1, 1, ?2, 0, 2, 'current', 'device-a', 'file')",
                )
                .unwrap();
            let mut superseded = tx
                .prepare(
                    "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, \
                     deleted, version_seq, state, origin_device_id, record_kind) \
                     VALUES ('g', ?1, 1, 1, ?2, 0, 1, 'superseded', 'device-a', 'file')",
                )
                .unwrap();
            for i in written..(written + ROWS_PER_TRANSACTION).min(n) {
                let path = format!("f{i:07}.bin");
                // Serialised through `BlockInfo` itself rather than written
                // as a JSON literal. A hand-rolled literal got the `hash`
                // field's shape wrong -- it is a byte sequence, not a hex
                // string -- and the summary refused the whole row as corrupt
                // state, which is the right behaviour and a useless
                // benchmark.
                let mut hash = vec![0u8; 32];
                hash[..8].copy_from_slice(&(i as u64).to_be_bytes());
                let blocks =
                    serde_json::to_string(&vec![BlockInfo { hash, offset: 0, size: 4096 }])
                        .unwrap();
                current.execute(rusqlite::params![path, blocks]).unwrap();
                if i % 10 == 0 {
                    superseded.execute(rusqlite::params![path, blocks]).unwrap();
                }
            }
        }
        tx.commit().unwrap();
        written += ROWS_PER_TRANSACTION;
    }
}
