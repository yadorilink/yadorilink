//! Counts the SQL statements a bulk capture commit prepares. Every statement on the per-file path
//! goes through the connection's statement cache, so it is compiled once per connection and
//! executed from the cached program afterwards; a statement prepared per file is SQLite
//! re-compiling the same text for every file.

use std::collections::HashMap;
use std::ffi::{c_int, c_uint, c_void, CStr};
use std::sync::{Mutex, MutexGuard};

use ed25519_dalek::SigningKey;
use rusqlite::{ffi, Connection};

use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::file::{FileMeta, FileRecord, FileVersion, RecordKind};
use yadorilink_replica_domain::ids::{DeviceId, SyncPath};
use yadorilink_replica_domain::local_op::Op;
use yadorilink_replica_domain::session_state::{LocalFileMetaColumns, PreparedLocalMutation};
use yadorilink_sqlite_runtime::SyncDatabase;

use crate::error::SyncSqliteError;
use crate::file_index::{FileIndexRepository, SignedEmissionContext};
use crate::local_author::LocalAuthor;
use crate::native_authoring::BULK_DELTA_MAX_OPS;

/// Statement texts the commit prepares once for the whole batch, generous for the few dozen
/// distinct statements it runs.
const FIXED_PREPARES_BOUND: u64 = 80;

/// Statements each further signed run may prepare again (those run per delta, not per file).
const PREPARES_PER_EXTRA_RUN_BOUND: u64 = 16;

/// Per statement text: (executions, executions of a statement that had never run before, which
/// is a fresh prepare).
static STATEMENTS: Mutex<Option<HashMap<String, (u64, u64)>>> = Mutex::new(None);
static SERIAL: Mutex<()> = Mutex::new(());

fn statements() -> MutexGuard<'static, Option<HashMap<String, (u64, u64)>>> {
    STATEMENTS.lock().unwrap_or_else(|e| e.into_inner())
}

unsafe extern "C" fn on_trace(
    mask: c_uint,
    _ctx: *mut c_void,
    p: *mut c_void,
    x: *mut c_void,
) -> c_int {
    if mask != ffi::SQLITE_TRACE_STMT as c_uint {
        return 0;
    }
    // `x` is the unexpanded text of the statement, or a `-- ` comment naming a trigger body.
    let sql =
        unsafe { CStr::from_ptr(x as *const std::ffi::c_char) }.to_string_lossy().into_owned();
    if sql.starts_with("--") {
        return 0;
    }
    // The run counter is bumped after the trace callback, so a statement on its first run still
    // reads zero here and a re-run of a cached one reads at least one.
    let runs = unsafe {
        ffi::sqlite3_stmt_status(p as *mut ffi::sqlite3_stmt, ffi::SQLITE_STMTSTATUS_RUN, 0)
    };
    let mut guard = statements();
    let entry = guard.get_or_insert_with(HashMap::new).entry(sql).or_insert((0, 0));
    entry.0 += 1;
    if runs == 0 {
        entry.1 += 1;
    }
    0
}

fn install_trace(conn: &Connection) {
    unsafe {
        ffi::sqlite3_trace_v2(
            conn.handle(),
            ffi::SQLITE_TRACE_STMT as c_uint,
            Some(on_trace),
            std::ptr::null_mut(),
        );
    }
}

fn uninstall_trace(conn: &Connection) {
    unsafe {
        ffi::sqlite3_trace_v2(conn.handle(), 0, None, std::ptr::null_mut());
    }
}

fn author_id() -> AuthorId {
    AuthorId { device: DeviceId("device-a".into()), incarnation: IncarnationId([1u8; 16]) }
}

fn put(i: usize) -> PreparedLocalMutation {
    put_at(i, format!("dir/file-{i:06}"))
}

fn put_at(i: usize, path: String) -> PreparedLocalMutation {
    let mtime = i as i64 + 1;
    let version = FileVersion::new(
        Vec::new(),
        0,
        FileMeta {
            mtime_unix_nanos: mtime,
            exec: false,
            symlink_target: None,
            record_kind: RecordKind::File,
        },
    );
    PreparedLocalMutation::Upsert {
        record: FileRecord {
            path: path.clone(),
            size: 0,
            mtime_unix_nanos: mtime,
            blocks: Vec::new(),
            deleted: false,
        },
        op: Op::Put { path: SyncPath(path), version: version.version_hash },
        meta: Some(LocalFileMetaColumns {
            record_kind: RecordKind::File,
            symlink_target: None,
            symlink_out_of_root: false,
            exec: false,
        }),
        version,
        native_witness: None,
    }
}

/// What committing `n` new files through the production batch commit executed.
struct Counted {
    per_text: Vec<(String, u64, u64)>,
    wall: std::time::Duration,
}

impl Counted {
    fn executions(&self) -> u64 {
        self.per_text.iter().map(|(_, e, _)| e).sum()
    }
    fn prepares(&self) -> u64 {
        self.per_text.iter().map(|(_, _, p)| p).sum()
    }
}

fn commit_counted(n: usize, drop_triggers: bool) -> Counted {
    let db: std::sync::Arc<SyncDatabase> = crate::replica_tables::open_for_tests();
    if drop_triggers {
        db.write_immediate::<_, SyncSqliteError>(|tx| {
            let names: Vec<String> = tx
                .prepare("SELECT name FROM sqlite_master WHERE type = 'trigger'")?
                .query_map([], |row| row.get(0))?
                .collect::<Result<_, _>>()?;
            for name in names {
                tx.execute_batch(&format!("DROP TRIGGER \"{name}\""))?;
            }
            Ok(())
        })
        .unwrap();
    }
    let repo = FileIndexRepository::new(db.clone());
    let key = SigningKey::from_bytes(&[3u8; 32]);
    let local = LocalAuthor { author: author_id(), signing_key: &key, capture: None };
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    let mutations: Vec<_> = (0..n).map(put).collect();

    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    // The pool hands the one idle connection back to a lone sequential caller, so the trace set
    // here is on the connection the commit below uses.
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        install_trace(tx);
        Ok(())
    })
    .unwrap();
    *statements() = Some(HashMap::new());
    let started = std::time::Instant::now();
    repo.commit_local_mutations_batch(
        "g1",
        &mutations,
        &[],
        "device-a",
        SignedEmissionContext { author: &local, permit: &permit },
    )
    .unwrap();
    let wall = started.elapsed();
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        uninstall_trace(tx);
        Ok(())
    })
    .unwrap();
    let mut per_text: Vec<(String, u64, u64)> = statements()
        .take()
        .unwrap()
        .into_iter()
        .map(|(sql, (execs, prepares))| (sql, execs, prepares))
        .collect();
    per_text.sort_by(|a, b| b.2.cmp(&a.2).then(b.1.cmp(&a.1)));
    Counted { per_text, wall }
}

/// Wall time of a 100k-file import through the production batch commit, in batches of 1000: the
/// stored namespace trie's cost on the sender's import path. Release profile:
/// `cargo test -p yadorilink-sync-sqlite --release --lib -- --ignored bulk_import_wall_100k
/// --nocapture`.
#[test]
#[ignore = "100k-file measurement; run explicitly"]
fn bulk_import_wall_100k() {
    // `YL_BENCH_DB_DIR` names a directory for a file-backed database (synchronous = FULL, as the
    // daemon runs), where the cost of the rows written shows; unset, the database is in memory.
    let db: std::sync::Arc<SyncDatabase> = match std::env::var_os("YL_BENCH_DB_DIR") {
        Some(dir) => {
            let path = std::path::Path::new(&dir).join(format!("bulk-{}.db", std::process::id()));
            std::sync::Arc::new(
                SyncDatabase::open(path, |conn| {
                    crate::replica_tables::init_for_tests(conn).map_err(|e| {
                        yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string())
                    })
                })
                .expect("open the file-backed benchmark database"),
            )
        }
        None => crate::replica_tables::open_for_tests(),
    };
    let repo = FileIndexRepository::new(db.clone());
    let key = SigningKey::from_bytes(&[3u8; 32]);
    let local = LocalAuthor { author: author_id(), signing_key: &key, capture: None };
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    const FLUSH_EVERY: usize = 5;
    let mut flushing = std::time::Duration::ZERO;
    let total = std::time::Instant::now();
    let mut marks = Vec::new();
    for batch in 0..100usize {
        // Paths scattered over 4000 directories, as a real import's are, so that the files of one
        // batch do not share a subtree.
        let mutations: Vec<_> = (batch * 1000..(batch + 1) * 1000)
            .map(|i| put_at(i, format!("d{:04}/f{i:06}.dat", i.wrapping_mul(2654435761) % 4000)))
            .collect();
        let started = std::time::Instant::now();
        repo.commit_local_mutations_batch(
            "g1",
            &mutations,
            &[],
            "device-a",
            SignedEmissionContext { author: &local, permit: &permit },
        )
        .unwrap();
        if [0, 24, 49, 74, 99].contains(&batch) {
            marks.push((batch + 1, started.elapsed()));
        }
        // A summary exchange every `FLUSH_EVERY` batches patches the trie from the paths the
        // commits noted. (Absent from the baseline build, which has no stored trie.)
        if (batch + 1) % FLUSH_EVERY == 0 {
            let started = std::time::Instant::now();
            crate::native_namespace::flush_all(&db).unwrap();
            flushing += started.elapsed();
        }
    }
    eprintln!(
        "100k files in {:?} (of which patching the trie {flushing:?}); batch times {marks:?}",
        total.elapsed()
    );
}

fn one_line(sql: &str) -> String {
    let flat = sql.split_whitespace().collect::<Vec<_>>().join(" ");
    flat.chars().take(330).collect()
}

fn report(label: &str, n: usize, counted: &Counted) {
    let per_file = |x: u64| x as f64 / n as f64;
    eprintln!(
        "{label}: {n} files in {:?}; {} distinct statement texts; {:.2} executions/file; {:.3} \
         prepares/file",
        counted.wall,
        counted.per_text.len(),
        per_file(counted.executions()),
        per_file(counted.prepares()),
    );
    for (sql, execs, prepares) in counted.per_text.iter().take(60) {
        eprintln!("  prepares {prepares:>6} execs {execs:>6}  {}", one_line(sql));
    }
}

/// Compiles do not scale with the number of files: the same statement texts are prepared once per
/// connection, plus a few per signed run, so quadrupling the files adds compiles only in
/// proportion to the extra runs.
#[test]
fn bulk_capture_compiles_do_not_scale_with_the_number_of_files() {
    let runs = |n: usize| n.div_ceil(BULK_DELTA_MAX_OPS) as u64;
    let small = commit_counted(1000, false);
    let large = commit_counted(4000, false);
    report("bulk capture", 1000, &small);
    report("bulk capture", 4000, &large);
    assert!(small.executions() > 0, "the trace saw no statement: the probe is not installed");
    let (p_small, p_large) = (small.prepares(), large.prepares());
    let extra_runs = runs(4000) - runs(1000);
    assert!(
        p_large - p_small.min(p_large) <= PREPARES_PER_EXTRA_RUN_BOUND * extra_runs,
        "{p_small} statements prepared for 1000 files and {p_large} for 4000: {extra_runs} more \
         runs may add at most {PREPARES_PER_EXTRA_RUN_BOUND} each; the heaviest at 4000: {:?}",
        large.per_text.iter().take(5).map(|(s, _, p)| (one_line(s), *p)).collect::<Vec<_>>()
    );
    assert!(
        p_large <= FIXED_PREPARES_BOUND + PREPARES_PER_EXTRA_RUN_BOUND * runs(4000),
        "{p_large} statements prepared for 4000 files (bound {})",
        FIXED_PREPARES_BOUND + PREPARES_PER_EXTRA_RUN_BOUND * runs(4000)
    );
}

/// Statement executions per file the bulk commit may run, at either batch size.
const EXECUTIONS_PER_FILE_BOUND: f64 = 26.3;

/// Executions per file are bounded and flat: the fixed per-delta statements amortize away, so
/// quadrupling the batch must not raise the per-file cost.
#[test]
fn bulk_capture_executions_per_file_are_bounded_and_do_not_grow_with_the_batch() {
    let small = commit_counted(1000, false);
    let large = commit_counted(4000, false);
    report("bulk capture executions", 1000, &small);
    report("bulk capture executions", 4000, &large);
    let per_small = small.executions() as f64 / 1000.0;
    let per_large = large.executions() as f64 / 4000.0;
    assert!(
        per_small <= EXECUTIONS_PER_FILE_BOUND && per_large <= EXECUTIONS_PER_FILE_BOUND,
        "{per_small:.2} executions/file at 1000 and {per_large:.2} at 4000 (bound \
         {EXECUTIONS_PER_FILE_BOUND}); heaviest at 4000: {:?}",
        large.per_text.iter().take(5).map(|(s, e, _)| (one_line(s), *e)).collect::<Vec<_>>()
    );
    assert!(
        // The stored namespace trie is read one node per level it descends, so the per-file reads grow
        // with the log of the group (about 0.8 more at four times the files), not with the batch.
        per_large <= per_small + 1.5,
        "executions/file grew with the batch: {per_small:.2} at 1000, {per_large:.2} at 4000"
    );
}

/// The per-file reads of the receive path (the link gate, the root token, the volume identity
/// and the provider refusal) compile their SQL once per connection, however many files go
/// through them. `Connection::query_row` and `execute` prepare on every call; the reads here go
/// through the statement cache instead (10,000 small files spent a third of the receiver's CPU
/// re-parsing these before).
#[test]
fn per_file_link_reads_compile_once_per_connection() {
    let db: std::sync::Arc<SyncDatabase> = crate::replica_tables::open_for_tests();
    let links = crate::link::LinkRepository::new(db.clone());
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        install_trace(tx);
        Ok(())
    })
    .unwrap();
    *statements() = Some(HashMap::new());
    for _ in 0..200 {
        links.link_gate_for_group("g1").unwrap();
        links.link_root_token_for_group("g1").unwrap();
        links.capture_volume_identity_for_group("g1").unwrap();
    }
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        uninstall_trace(tx);
        Ok(())
    })
    .unwrap();
    let per_text = statements().take().unwrap();
    let executions: u64 = per_text.values().map(|(e, _)| e).sum();
    let prepares: u64 = per_text.values().map(|(_, p)| p).sum();
    assert!(executions >= 600, "the trace saw {executions} statements: the probe is not installed");
    assert!(
        prepares <= 12,
        "{prepares} statements prepared for 200 files ({executions} executed); a statement that \
         is prepared per call is not going through the statement cache: {:?}",
        per_text
            .iter()
            .filter(|(_, (_, p))| *p > 1)
            .map(|(s, v)| (one_line(s), *v))
            .collect::<Vec<_>>()
    );
}

/// The held-path listing reads the partial index of held rows, not every current row of the group
/// (the hazard re-check runs it after every materialization completion).
#[test]
fn the_held_path_listing_uses_the_held_index() {
    let db: std::sync::Arc<SyncDatabase> = crate::replica_tables::open_for_tests();
    let plan: String = db
        .read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "EXPLAIN QUERY PLAN SELECT path FROM files \
                 WHERE group_id = ?1 AND state = 'current' AND held_reason IS NOT NULL",
            )?;
            let rows: Vec<String> =
                stmt.query_map(["g1"], |r| r.get(3))?.collect::<Result<_, _>>()?;
            Ok(rows.join(" | "))
        })
        .unwrap();
    assert!(plan.contains("files_held"), "{plan}");
}
