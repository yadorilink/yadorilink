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
    let path = format!("dir/file-{i:06}");
    let mtime = i as i64 + 1;
    let version = FileVersion::new(
        Vec::new(),
        0,
        FileMeta {
            mtime_unix_nanos: mtime,
            unix_mode: Some(0o644),
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
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
            unix_mode: Some(0o644),
            xattrs: Vec::new(),
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
        per_large <= per_small + 0.5,
        "executions/file grew with the batch: {per_small:.2} at 1000, {per_large:.2} at 4000"
    );
}
