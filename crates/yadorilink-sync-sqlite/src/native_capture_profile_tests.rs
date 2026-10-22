//! Where the time of a bulk capture commit goes when it carries what a production capture carries:
//! one `Present` actual-state evidence per new file, observed from a real file. Every statement
//! the commit runs is timed (`SQLITE_TRACE_PROFILE`), recorded in execution order, and attributed
//! to the stage of the per-file chain that ran it.
//!
//! The default test pins the statements executed per file. Set `YADORILINK_CAPTURE_PROFILE` to a
//! comma-separated list of file counts (for example `2000,4000`) to print the timing table, each
//! count measured three times against a file-backed database in WAL mode.

use std::collections::HashMap;
use std::ffi::{c_int, c_uint, c_void, CStr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use rusqlite::{ffi, Connection};

use yadorilink_fs_platform::fs_identity::FileIdentity;
use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::file::{FileMeta, FileRecord, FileVersion, RecordKind};
use yadorilink_replica_domain::ids::{DeviceId, SyncPath};
use yadorilink_replica_domain::local_op::Op;
use yadorilink_replica_domain::session_state::{LocalFileMetaColumns, PreparedLocalMutation};
use yadorilink_sqlite_runtime::SyncDatabase;

use crate::error::SyncSqliteError;
use crate::file_index::{
    FileIndexRepository, LocalCaptureActualStateEvidence, SignedEmissionContext,
};
use crate::local_author::LocalAuthor;

/// Statement executions per new file a capture commit carrying `Present` evidence may run.
///
/// Measured at 18.1 per file against this bound of 19.0, so 0.9 statements per file of headroom.
/// The per-file figure includes per-chunk statements divided by the chunk's paths, so a change of
/// `PATHS_PER_QUERY` legitimately moves it; re-measure and reset the bound then, rather than
/// widening it blindly.
const EXECUTIONS_PER_FILE_BOUND: f64 = 19.0;

/// Every completed top-level statement, in completion order: text and nanoseconds. Time spent in
/// trigger bodies is inside the statement that fired them.
static LOG: Mutex<Vec<(String, u64)>> = Mutex::new(Vec::new());
static SERIAL: Mutex<()> = Mutex::new(());

/// When the statement now running started, in nanoseconds since [`epoch`]. The profile event's own
/// duration only has millisecond resolution, so each statement is timed between its start event and
/// its profile event instead. Top-level statements never overlap; trigger bodies run inside the
/// statement that fired them and report only a `-- ` comment, which is ignored.
static STARTED: AtomicU64 = AtomicU64::new(0);
/// When the previous statement finished, or zero before the first one of a run.
static LAST_END: AtomicU64 = AtomicU64::new(0);
/// For each logged statement, the time outside SQLite since the one before it finished: the Rust
/// code (and statement binding) between two statements, attributed to the statement that follows.
static GAPS: Mutex<Vec<u64>> = Mutex::new(Vec::new());

fn epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

fn now_nanos() -> u64 {
    epoch().elapsed().as_nanos() as u64
}

unsafe extern "C" fn on_trace(
    mask: c_uint,
    _ctx: *mut c_void,
    p: *mut c_void,
    x: *mut c_void,
) -> c_int {
    if mask == ffi::SQLITE_TRACE_STMT as c_uint {
        let text = unsafe { CStr::from_ptr(x as *const std::ffi::c_char) };
        if !text.to_bytes().starts_with(b"--") {
            let now = now_nanos();
            STARTED.store(now, Ordering::Relaxed);
            let last_end = LAST_END.load(Ordering::Relaxed);
            GAPS.lock().unwrap_or_else(|e| e.into_inner()).push(if last_end == 0 {
                0
            } else {
                now.saturating_sub(last_end)
            });
        }
        return 0;
    }
    if mask != ffi::SQLITE_TRACE_PROFILE as c_uint {
        return 0;
    }
    let end = now_nanos();
    LAST_END.store(end, Ordering::Relaxed);
    let nanos = end.saturating_sub(STARTED.load(Ordering::Relaxed));
    let stmt = p as *mut ffi::sqlite3_stmt;
    let sql_ptr = unsafe { ffi::sqlite3_sql(stmt) };
    if sql_ptr.is_null() {
        return 0;
    }
    let sql = unsafe { CStr::from_ptr(sql_ptr) }.to_string_lossy().into_owned();
    LOG.lock().unwrap_or_else(|e| e.into_inner()).push((sql, nanos));
    0
}

fn set_trace(conn: &Connection, on: bool) {
    unsafe {
        if on {
            ffi::sqlite3_trace_v2(
                conn.handle(),
                (ffi::SQLITE_TRACE_STMT | ffi::SQLITE_TRACE_PROFILE) as c_uint,
                Some(on_trace),
                std::ptr::null_mut(),
            );
        } else {
            ffi::sqlite3_trace_v2(conn.handle(), 0, None, std::ptr::null_mut());
        }
    }
}

fn author_id() -> AuthorId {
    AuthorId { device: DeviceId("device-a".into()), incarnation: IncarnationId([1u8; 16]) }
}

fn put(path: String, mtime: i64) -> PreparedLocalMutation {
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

/// `n` new empty files under `root`, each with the `Present` evidence a capture takes from the
/// real path immediately before the commit.
fn files_with_evidence(
    root: &Path,
    n: usize,
) -> (Vec<PreparedLocalMutation>, Vec<Option<LocalCaptureActualStateEvidence>>) {
    std::fs::create_dir_all(root.join("dir")).unwrap();
    let mut mutations = Vec::with_capacity(n);
    let mut evidence = Vec::with_capacity(n);
    for i in 0..n {
        let rel = format!("dir/file-{i:06}");
        let abs = root.join(&rel);
        std::fs::write(&abs, b"").unwrap();
        let filesystem_identity = FileIdentity::observe_path(&abs).unwrap();
        evidence.push(Some(LocalCaptureActualStateEvidence::Present { filesystem_identity }));
        mutations.push(put(rel, i as i64 + 1));
    }
    (mutations, evidence)
}

/// One commit of `n` new files: every statement in execution order, and the batch's wall time.
struct Run {
    log: Vec<(String, u64)>,
    gaps: Vec<u64>,
    wall: Duration,
}

fn open_database(file_backed: Option<&Path>) -> std::sync::Arc<SyncDatabase> {
    match file_backed {
        None => crate::replica_tables::open_for_tests(),
        Some(path) => {
            let database = SyncDatabase::open(path, |conn| {
                crate::replica_tables::init(conn).map_err(|err| match err {
                    crate::replica_schema::ReplicaSchemaError::Database(err) => err,
                    crate::replica_schema::ReplicaSchemaError::Store(err) => {
                        yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(err.to_string())
                    }
                })
            })
            .expect("open the file-backed replica test database");
            std::sync::Arc::new(database)
        }
    }
}

fn run_commit(n: usize, file_backed: bool, drop_triggers: bool) -> Run {
    let scratch = tempfile::tempdir().unwrap();
    let (mutations, evidence) = files_with_evidence(&scratch.path().join("root"), n);
    let db_path = scratch.path().join("replica.db");
    let db = open_database(file_backed.then_some(db_path.as_path()));
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

    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    // The pool hands its one idle connection back to a lone sequential caller, so the trace set
    // here is on the connection the commit below uses.
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        set_trace(tx, true);
        Ok(())
    })
    .unwrap();
    LOG.lock().unwrap_or_else(|e| e.into_inner()).clear();
    GAPS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    LAST_END.store(0, Ordering::Relaxed);
    let started = Instant::now();
    // The settlement's test-only cross-check against the database runs statements of its own.
    crate::new_path_rows::tests_support::without_cross_check(|| {
        repo.commit_local_mutations_batch(
            "g1",
            &mutations,
            &evidence,
            "device-a",
            SignedEmissionContext { author: &local, permit: &permit },
        )
    })
    .unwrap();
    let wall = started.elapsed();
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        set_trace(tx, false);
        Ok(())
    })
    .unwrap();
    let log = std::mem::take(&mut *LOG.lock().unwrap_or_else(|e| e.into_inner()));
    let gaps = std::mem::take(&mut *GAPS.lock().unwrap_or_else(|e| e.into_inner()));
    Run { log, gaps, wall }
}

/// The statement text with its whitespace flattened and its parameter lists collapsed, so one
/// statement keyed by a varying number of parameters reads as one text.
fn normalise(sql: &str) -> String {
    let flat = sql.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut out = String::with_capacity(flat.len());
    let mut rest = flat.as_str();
    while let Some(open) = rest.find("(?") {
        out.push_str(&rest[..open]);
        let tail = &rest[open..];
        let close = tail.find(')').unwrap_or(tail.len() - 1);
        let inner = &tail[1..close];
        if inner.split(',').all(|part| part.trim().starts_with('?')) {
            out.push_str("(?..)");
        } else {
            out.push_str(&tail[..=close]);
        }
        rest = &tail[close + 1..];
    }
    out.push_str(rest);
    out
}

/// The part of the per-file chain a statement belongs to. The chain runs in a fixed order per
/// file, so a statement is attributed by the last stage marker before it (the statements that
/// open each stage are distinctive), and before the first per-file marker by its own text.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
enum Stage {
    Authoring,
    FileVersions,
    Provenance,
    Obligations,
    FilesUpsert,
    Fence,
    MaterializationBasis,
    Generation,
    StampSettle,
    Commit,
}

fn stage_of_pre_loop(sql: &str) -> Stage {
    if sql.contains("file_versions") {
        Stage::FileVersions
    } else if sql.contains("native_local_capture") {
        Stage::Provenance
    } else if sql.contains("projection_obligation") {
        Stage::Obligations
    } else if sql.contains("native_authoring_witness")
        || sql.starts_with("INSERT INTO files")
        || sql.starts_with("SELECT path, size, mtime_unix_nanos")
    {
        Stage::FilesUpsert
    } else {
        Stage::Authoring
    }
}

/// The statements run per file open with the path's fence bump and end with the obligation
/// close (one statement for a whole chunk once the proofs are batched); the statements around them (authoring, the batched version, provenance, obligation and
/// row writes) run once per group chunk and are attributed by their own text.
fn stages(log: &[(String, u64)]) -> Vec<Stage> {
    let mut in_loop = false;
    let mut current = Stage::Authoring;
    let mut out = Vec::with_capacity(log.len());
    for (sql, _) in log {
        let flat = normalise(sql);
        if flat.starts_with("COMMIT") {
            in_loop = false;
            current = Stage::Commit;
        } else if flat.starts_with("INSERT INTO path_actual_mutation_fences") {
            in_loop = true;
            current = Stage::Fence;
        } else if in_loop && current == Stage::Fence {
            current = Stage::MaterializationBasis;
        } else if in_loop && flat.starts_with("INSERT INTO path_materialized_generations") {
            current = Stage::Generation;
        } else if in_loop && current == Stage::Generation {
            current = Stage::StampSettle;
        }
        out.push(if in_loop || current == Stage::Commit {
            current
        } else {
            stage_of_pre_loop(&flat)
        });
        if in_loop
            && (flat.starts_with("DELETE FROM projection_obligations")
                || flat.starts_with("WITH c(path, generation"))
        {
            in_loop = false;
        }
    }
    out
}

/// What a statement in the per-file chain re-reads. `A`: a fact the group's authoring step just
/// computed or wrote and holds in memory for a new path; `P`: a fact about other paths or earlier
/// state that one bulk read before the loop could supply; blank: not a re-read.
fn derive_kind(stage: Stage, flat: &str) -> &'static str {
    let in_chain = matches!(
        stage,
        Stage::FilesUpsert | Stage::MaterializationBasis | Stage::StampSettle | Stage::Generation
    );
    if !in_chain {
        return "";
    }
    if flat.starts_with("SELECT author, incarnation, seq, version, provenance FROM native_heads")
        || flat.starts_with("SELECT encoded FROM file_versions")
        || flat.starts_with("SELECT version FROM native_authoring_witness")
        || flat.starts_with("INSERT OR IGNORE INTO native_authoring_witness")
        || flat.starts_with("SELECT size, mtime_unix_nanos, blocks_json")
        || flat.starts_with("SELECT invalidation_generation, state, attempt_count")
    {
        "A"
    } else if flat.contains("FROM native_physical_placement")
        || flat.contains("native_stable_projection_binding")
        || flat.contains("native_head_keep")
        || flat.starts_with("SELECT EXISTS(SELECT 1 FROM native_heads")
        || flat.starts_with("SAVEPOINT native_placement_scope")
        || flat.starts_with("RELEASE native_placement_scope")
    {
        "P"
    } else {
        ""
    }
}

#[derive(Default, Clone)]
struct Stat {
    calls: u64,
    nanos: u64,
}

type Key = (Stage, String);

fn aggregate(run: &Run) -> HashMap<Key, Stat> {
    let stage = stages(&run.log);
    let mut by_key: HashMap<Key, Stat> = HashMap::new();
    for ((sql, nanos), stage) in run.log.iter().zip(stage) {
        let stat = by_key.entry((stage, normalise(sql))).or_default();
        stat.calls += 1;
        stat.nanos += nanos;
    }
    by_key
}

fn sql_nanos(run: &Run) -> u64 {
    run.log.iter().map(|(_, n)| n).sum()
}

/// The cost the probe adds to each statement, and the time outside SQLite a cached statement costs
/// its caller (lookup, binding, stepping): a trivial statement, timed the same way.
fn probe_floor_nanos() -> (u64, u64) {
    let db = crate::replica_tables::open_for_tests();
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        set_trace(tx, true);
        LOG.lock().unwrap_or_else(|e| e.into_inner()).clear();
        GAPS.lock().unwrap_or_else(|e| e.into_inner()).clear();
        LAST_END.store(0, Ordering::Relaxed);
        for _ in 0..20_000 {
            tx.prepare_cached("SELECT 1")?.query_row([], |row| row.get::<_, i64>(0))?;
        }
        set_trace(tx, false);
        Ok(())
    })
    .unwrap();
    let log = std::mem::take(&mut *LOG.lock().unwrap_or_else(|e| e.into_inner()));
    let gaps = std::mem::take(&mut *GAPS.lock().unwrap_or_else(|e| e.into_inner()));
    let count = log.len().max(1) as u64;
    (log.iter().map(|(_, n)| n).sum::<u64>() / count, gaps.iter().sum::<u64>() / count)
}

fn min_median(mut values: Vec<f64>) -> (f64, f64) {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    (values[0], values[values.len() / 2])
}

fn print_profile(n: usize, runs: &[Run]) {
    let rounds: Vec<HashMap<Key, Stat>> = runs.iter().map(aggregate).collect();
    let ms = |nanos: u64| nanos as f64 / 1e6;
    let (wall_min, wall_med) =
        min_median(runs.iter().map(|r| r.wall.as_secs_f64() * 1e3).collect());
    let (sql_min, sql_med) = min_median(runs.iter().map(|r| ms(sql_nanos(r))).collect());
    let (floor, floor_gap) = probe_floor_nanos();
    let statements = runs[0].log.len();
    eprintln!(
        "PROFILE n={n} wall_ms min/med={wall_min:.1}/{wall_med:.1} sql_ms min/med={sql_min:.1}/{sql_med:.1} \
         non_sql_ms(med)={:.1} statements={statements} ({:.1}/file) probe_floor_ns/stmt={floor} probe_caller_gap_ns/stmt={floor_gap}",
        wall_med - sql_med,
        statements as f64 / n as f64,
    );

    // Stage totals.
    let mut stage_gaps: HashMap<Stage, Vec<f64>> = HashMap::new();
    for run in runs {
        let mut per: HashMap<Stage, u64> = HashMap::new();
        for (stage, gap) in stages(&run.log).into_iter().zip(&run.gaps) {
            *per.entry(stage).or_default() += gap;
        }
        for (stage, nanos) in per {
            stage_gaps.entry(stage).or_default().push(ms(nanos));
        }
    }
    let mut stage_totals: HashMap<Stage, Vec<f64>> = HashMap::new();
    let mut stage_calls: HashMap<Stage, u64> = HashMap::new();
    for round in &rounds {
        let mut per: HashMap<Stage, u64> = HashMap::new();
        for ((stage, _), stat) in round {
            *per.entry(*stage).or_default() += stat.nanos;
        }
        for (stage, nanos) in per {
            stage_totals.entry(stage).or_default().push(ms(nanos));
        }
    }
    for ((stage, _), stat) in &rounds[0] {
        *stage_calls.entry(*stage).or_default() += stat.calls;
    }
    let mut stage_rows: Vec<_> = stage_totals.into_iter().collect();
    stage_rows.sort_by_key(|row| row.0);
    for (stage, values) in stage_rows {
        let (min, med) = min_median(values);
        let (_, gap_med) = min_median(stage_gaps.remove(&stage).unwrap_or_else(|| vec![0.0]));
        eprintln!(
            "STAGE\t{:?}\tcalls/file={:.2}\tsql ms min/med={min:.1}/{med:.1}\t%wall(med)={:.1}\trust-gap ms(med)={gap_med:.1}\t%wall={:.1}",
            stage,
            stage_calls[&stage] as f64 / n as f64,
            100.0 * med / wall_med,
            100.0 * gap_med / wall_med
        );
    }

    // Statement rows by median total time.
    let mut keys: Vec<&Key> = rounds[0].keys().collect();
    let medians: HashMap<&Key, (f64, f64)> = keys
        .iter()
        .map(|key| {
            let values: Vec<f64> =
                rounds.iter().map(|r| r.get(*key).map_or(0.0, |s| ms(s.nanos))).collect();
            (*key, min_median(values))
        })
        .collect();
    keys.sort_by(|a, b| medians[b].1.partial_cmp(&medians[a].1).unwrap());
    for key in keys.iter().take(40) {
        let stat = &rounds[0][*key];
        let (min, med) = medians[*key];
        eprintln!(
            "ROW\t{:?}\t{}\tcalls/file={:.2}\tms min/med={min:.1}/{med:.1}\t%wall={:.1}\tus/call={:.1}\t{}",
            key.0,
            derive_kind(key.0, &key.1),
            stat.calls as f64 / n as f64,
            100.0 * med / wall_med,
            med * 1e3 / stat.calls.max(1) as f64,
            key.1.chars().take(90).collect::<String>()
        );
    }
    // Derive-again totals.
    for kind in ["A", "P"] {
        let values: Vec<f64> = rounds
            .iter()
            .map(|round| {
                ms(round
                    .iter()
                    .filter(|((stage, sql), _)| derive_kind(*stage, sql) == kind)
                    .map(|(_, stat)| stat.nanos)
                    .sum())
            })
            .collect();
        let calls: u64 = rounds[0]
            .iter()
            .filter(|((stage, sql), _)| derive_kind(*stage, sql) == kind)
            .map(|(_, stat)| stat.calls)
            .sum();
        let (min, med) = min_median(values);
        eprintln!(
            "DERIVE {kind}\tcalls/file={:.2}\tms min/med={min:.1}/{med:.1}\t%wall(med)={:.1}",
            calls as f64 / n as f64,
            100.0 * med / wall_med
        );
    }
}

#[test]
fn bulk_capture_with_present_evidence_runs_a_bounded_number_of_statements_per_file() {
    let n = 1000;
    let run = run_commit(n, false, false);
    let per_file = run.log.len() as f64 / n as f64;
    assert!(!run.log.is_empty(), "the profile trace saw no statement");
    assert!(
        per_file <= EXECUTIONS_PER_FILE_BOUND,
        "{per_file:.2} statements per file with Present evidence (bound {EXECUTIONS_PER_FILE_BOUND})"
    );
}

#[test]
fn bulk_capture_profile_table() {
    let Ok(sizes) = std::env::var("YADORILINK_CAPTURE_PROFILE") else { return };
    for n in sizes.split(',').filter_map(|s| s.trim().parse::<usize>().ok()) {
        for drop_triggers in [false, true] {
            eprintln!("== triggers dropped: {drop_triggers}");
            let runs: Vec<Run> = (0..3).map(|_| run_commit(n, true, drop_triggers)).collect();
            print_profile(n, &runs);
        }
    }
}
