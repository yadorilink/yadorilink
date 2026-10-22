//! Pins that authoring a local mutation and installing a remote delta cost a
//! bounded number of `native_heads` rows each, however large the group
//! already is: the total work for N deltas at distinct paths must be linear
//! in N, never quadratic.

use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, FolderGroupId, SyncPath, VersionHash};
use yadorilink_replica_domain::local_op::Op;
use yadorilink_replica_domain::native_state::DeltaHash;
use yadorilink_replica_domain::signed_delta::{DeltaOp, DeltaPut, NativeDelta};

use crate::local_author::LocalAuthor;
use crate::native_store::{self, head_row_counters};

/// Head rows read plus written per delta: generous for the handful of rows
/// one delta legitimately touches, far below what a whole-group load or
/// replace costs at these sizes.
const ROWS_PER_DELTA_BOUND: u64 = 16;

/// How much the total may grow when N doubles: 2.0 for exactly linear work,
/// with headroom for fixed overhead. Quadratic work is 4.0.
const DOUBLING_RATIO_BOUND: f64 = 2.5;

const SMALL: usize = 2000;
const LARGE: usize = 4000;

fn group() -> FolderGroupId {
    FolderGroupId("g1".into())
}

fn conn() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    crate::replica_tables::init(&c).unwrap();
    c
}

/// What one run of N deltas cost.
struct Cost {
    /// `native_heads` rows read plus written.
    head_rows: u64,
    /// SQLite virtual-machine work (in units of 1000 instructions) over every
    /// statement of the run: it also sees a scan of some other table, or of an
    /// index, that the head row counters cannot.
    vm_work: u64,
}

/// Counts the SQLite work `c` does from now on.
fn count_vm_work(c: &Connection) -> std::sync::Arc<std::sync::atomic::AtomicU64> {
    let ticks = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let counter = ticks.clone();
    c.progress_handler(
        1000,
        Some(move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            false
        }),
    );
    ticks
}

fn author_id(device: &str) -> AuthorId {
    AuthorId { device: DeviceId(device.into()), incarnation: IncarnationId([1u8; 16]) }
}

/// Total head rows (read + written) to author `n` local puts at distinct
/// paths, as one batch inside one transaction.
fn authoring_cost(n: usize) -> Cost {
    let c = conn();
    let ticks = count_vm_work(&c);
    let key = SigningKey::from_bytes(&[3u8; 32]);
    let local = LocalAuthor { author: author_id("device-a"), signing_key: &key, capture: None };
    c.execute_batch("BEGIN").unwrap();
    head_row_counters::reset();
    for i in 0..n {
        let path = SyncPath(format!("dir/file-{i:06}"));
        let version = VersionHash([(i % 251) as u8 + 1; 32]);
        crate::native_authoring::author_op(
            &c,
            &group(),
            &local,
            &Op::Put { path: path.clone(), version },
        )
        .unwrap();
    }
    let (read, written) = head_row_counters::snapshot();
    let vm_work = ticks.load(std::sync::atomic::Ordering::Relaxed);
    c.execute_batch("COMMIT").unwrap();
    Cost { head_rows: read + written, vm_work }
}

/// Total head rows (read + written) to install `n` remote deltas, one per
/// distinct path, alternating between two authors.
fn remote_install_cost(n: usize) -> Cost {
    let c = conn();
    let ticks = count_vm_work(&c);
    let keys = [SigningKey::from_bytes(&[5u8; 32]), SigningKey::from_bytes(&[6u8; 32])];
    let authors = [author_id("device-b"), author_id("device-c")];
    let mut next_seq = [1u64; 2];
    let mut prev: [Option<DeltaHash>; 2] = [None, None];
    c.execute_batch("BEGIN").unwrap();
    head_row_counters::reset();
    for i in 0..n {
        let who = i % 2;
        let mut delta = NativeDelta {
            recursive_part: None,
            group_id: group(),
            author: authors[who].clone(),
            seq: AuthorSeq(next_seq[who]),
            prev: prev[who],
            ops: vec![DeltaOp {
                path: SyncPath(format!("dir/file-{i:06}")),
                removes: Vec::new(),
                put: Some(DeltaPut { version: VersionHash([(i % 251) as u8 + 1; 32]) }),
            }],
            signature: [0u8; 64],
        };
        delta.sign(&keys[who]);
        native_store::install_verified_delta(&c, &group(), &delta, &keys[who].verifying_key())
            .unwrap();
        prev[who] = Some(delta.delta_hash());
        next_seq[who] += 1;
    }
    let (read, written) = head_row_counters::snapshot();
    let vm_work = ticks.load(std::sync::atomic::Ordering::Relaxed);
    c.execute_batch("COMMIT").unwrap();
    Cost { head_rows: read + written, vm_work }
}

/// Total cost to admit `n` remote deltas, one per distinct path, alternating
/// between two authors, through remote admission (chain and context gates,
/// install, projection arming).
fn remote_admission_cost(n: usize) -> Cost {
    let c = conn();
    let ticks = count_vm_work(&c);
    let keys = [SigningKey::from_bytes(&[5u8; 32]), SigningKey::from_bytes(&[6u8; 32])];
    let authors = [author_id("device-b"), author_id("device-c")];
    let mut next_seq = [1u64; 2];
    let mut prev: [Option<DeltaHash>; 2] = [None, None];
    c.execute_batch("BEGIN").unwrap();
    head_row_counters::reset();
    for i in 0..n {
        let who = i % 2;
        let mut delta = NativeDelta {
            recursive_part: None,
            group_id: group(),
            author: authors[who].clone(),
            seq: AuthorSeq(next_seq[who]),
            prev: prev[who],
            ops: vec![DeltaOp {
                path: SyncPath(format!("dir/file-{i:06}")),
                removes: Vec::new(),
                put: Some(DeltaPut { version: VersionHash([(i % 251) as u8 + 1; 32]) }),
            }],
            signature: [0u8; 64],
        };
        delta.sign(&keys[who]);
        let admitted =
            crate::native_admission::admit_native_delta(&c, &group(), &delta, &|author| {
                authors.iter().position(|a| a == author).map(|i| keys[i].verifying_key())
            })
            .unwrap();
        assert!(matches!(admitted, crate::native_admission::NativeAdmission::Admitted { .. }));
        prev[who] = Some(delta.delta_hash());
        next_seq[who] += 1;
    }
    let (read, written) = head_row_counters::snapshot();
    let vm_work = ticks.load(std::sync::atomic::Ordering::Relaxed);
    c.execute_batch("COMMIT").unwrap();
    Cost { head_rows: read + written, vm_work }
}

/// Total cost to commit `n` new local files the way a scan's batch commit
/// does: each one's content version, its delta, and its `files` row, in one
/// transaction.
fn local_commit_cost(n: usize) -> Cost {
    use yadorilink_replica_domain::file::{FileMeta, FileRecord, FileVersion, RecordKind};
    use yadorilink_replica_domain::session_state::PreparedLocalMutation;

    let db = crate::replica_tables::open_for_tests();
    let key = SigningKey::from_bytes(&[3u8; 32]);
    let local = LocalAuthor { author: author_id("device-a"), signing_key: &key, capture: None };
    let mut cost = None;
    db.write_immediate::<_, crate::error::SyncSqliteError>(|tx| {
        let ticks = count_vm_work(tx);
        head_row_counters::reset();
        for i in 0..n {
            let path = format!("dir/file-{i:06}");
            let version = FileVersion::new(
                Vec::new(),
                0,
                FileMeta {
                    mtime_unix_nanos: i as i64 + 1,
                    unix_mode: Some(0o644),
                    symlink_target: None,
                    record_kind: RecordKind::File,
                    xattrs: Vec::new(),
                },
            );
            let mutation = PreparedLocalMutation::Upsert {
                record: FileRecord {
                    path: path.clone(),
                    size: 0,
                    mtime_unix_nanos: i as i64 + 1,
                    blocks: Vec::new(),
                    deleted: false,
                },
                op: Op::Put { path: SyncPath(path), version: version.version_hash },
                meta: Some(yadorilink_replica_domain::session_state::LocalFileMetaColumns {
                    record_kind: RecordKind::File,
                    symlink_target: None,
                    symlink_out_of_root: false,
                    unix_mode: Some(0o644),
                    xattrs: Vec::new(),
                }),
                version,
                native_witness: None,
            };
            crate::file_index::commit_local_mutation_in_tx(
                tx, "g1", &mutation, None, "device-a", &local,
            )?;
        }
        let (read, written) = head_row_counters::snapshot();
        cost = Some(Cost {
            head_rows: read + written,
            vm_work: ticks.load(std::sync::atomic::Ordering::Relaxed),
        });
        tx.progress_handler(0, None::<fn() -> bool>);
        Ok(())
    })
    .unwrap();
    cost.unwrap()
}

fn assert_linear(label: &str, cost: fn(usize) -> Cost) {
    let small = cost(SMALL);
    let large = cost(LARGE);
    let row_ratio = large.head_rows as f64 / small.head_rows as f64;
    let vm_ratio = large.vm_work as f64 / small.vm_work as f64;
    eprintln!(
        "{label}: {SMALL} deltas: {} head rows, {} vm work; {LARGE} deltas: {} head rows, {} vm \
         work (x{row_ratio:.2} rows, x{vm_ratio:.2} vm)",
        small.head_rows, small.vm_work, large.head_rows, large.vm_work
    );
    for (n, rows) in [(SMALL, small.head_rows), (LARGE, large.head_rows)] {
        assert!(
            rows <= ROWS_PER_DELTA_BOUND * n as u64,
            "{label}: {n} deltas touched {rows} head rows (bound {})",
            ROWS_PER_DELTA_BOUND * n as u64
        );
    }
    assert!(
        row_ratio <= DOUBLING_RATIO_BOUND,
        "{label}: doubling the delta count from {SMALL} to {LARGE} grew the head rows touched \
         from {} to {} (x{row_ratio:.2}, bound x{DOUBLING_RATIO_BOUND})",
        small.head_rows,
        large.head_rows
    );
    assert!(
        vm_ratio <= DOUBLING_RATIO_BOUND,
        "{label}: doubling the delta count from {SMALL} to {LARGE} grew SQLite's work from {} \
         to {} (x{vm_ratio:.2}, bound x{DOUBLING_RATIO_BOUND})",
        small.vm_work,
        large.vm_work
    );
}

#[test]
fn native_authoring_is_linear_in_the_number_of_deltas() {
    assert_linear("local authoring", authoring_cost);
}

#[test]
fn native_remote_install_is_linear_in_the_number_of_deltas() {
    assert_linear("remote install", remote_install_cost);
}

#[test]
fn local_commit_of_new_files_is_linear_in_the_number_of_files() {
    assert_linear("local commit", local_commit_cost);
}

#[test]
fn remote_admission_is_linear_in_the_number_of_deltas() {
    assert_linear("remote admission", remote_admission_cost);
}

/// A new-file upsert at `dir/file-{i:06}`: what a scan's batch commit prepares.
fn new_file_mutation(i: usize) -> yadorilink_replica_domain::session_state::PreparedLocalMutation {
    use yadorilink_replica_domain::file::{FileMeta, FileRecord, FileVersion, RecordKind};
    use yadorilink_replica_domain::session_state::{LocalFileMetaColumns, PreparedLocalMutation};
    let path = format!("dir/file-{i:06}");
    let version = FileVersion::new(
        Vec::new(),
        0,
        FileMeta {
            mtime_unix_nanos: i as i64 + 1,
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
            mtime_unix_nanos: i as i64 + 1,
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

/// What committing `n` new files through `commit_local_mutations_batch`, in
/// batches of `batch`, produced and cost.
struct BulkRun {
    deltas: u64,
    cost: Cost,
    wall: std::time::Duration,
}

fn bulk_capture_run(n: usize, batch: usize) -> BulkRun {
    let db = crate::replica_tables::open_for_tests();
    let repo = crate::file_index::FileIndexRepository::new(db.clone());
    let key = SigningKey::from_bytes(&[3u8; 32]);
    let local = LocalAuthor { author: author_id("device-a"), signing_key: &key, capture: None };
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    let emission = crate::file_index::SignedEmissionContext { author: &local, permit: &permit };
    let mutations: Vec<_> = (0..n).map(new_file_mutation).collect();
    let ticks = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    db.write_immediate::<_, crate::error::SyncSqliteError>(|tx| {
        let counter = ticks.clone();
        tx.progress_handler(
            1000,
            Some(move || {
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                false
            }),
        );
        Ok(())
    })
    .unwrap();
    head_row_counters::reset();
    let started = std::time::Instant::now();
    for chunk in mutations.chunks(batch) {
        repo.commit_local_mutations_batch("g1", chunk, &[], "device-a", emission).unwrap();
    }
    let wall = started.elapsed();
    let (read, written) = head_row_counters::snapshot();
    let vm_work = ticks.load(std::sync::atomic::Ordering::Relaxed);
    let deltas = db
        .write_immediate::<_, crate::error::SyncSqliteError>(|tx| {
            tx.progress_handler(0, None::<fn() -> bool>);
            Ok(tx.query_row("SELECT COUNT(*) FROM native_delta_log", [], |r| r.get::<_, i64>(0))?)
        })
        .unwrap() as u64;
    BulkRun { deltas, cost: Cost { head_rows: read + written, vm_work }, wall }
}

/// A bulk capture signs one bounded multi-op delta per batch, not one per
/// file: the deltas (and so the signatures, hashes and log rows) are
/// O(N / BULK_DELTA_MAX_OPS), and what each file costs stays flat.
#[test]
fn bulk_capture_signs_one_delta_per_batch_and_stays_linear() {
    let max_ops = crate::native_authoring::BULK_DELTA_MAX_OPS;
    let small = bulk_capture_run(SMALL, max_ops);
    let large = bulk_capture_run(LARGE, max_ops);
    eprintln!(
        "bulk capture: {SMALL} files: {} deltas, {} head rows, {} vm work, {:?}; {LARGE} files: \
         {} deltas, {} head rows, {} vm work, {:?}",
        small.deltas,
        small.cost.head_rows,
        small.cost.vm_work,
        small.wall,
        large.deltas,
        large.cost.head_rows,
        large.cost.vm_work,
        large.wall
    );
    for (n, run) in [(SMALL, &small), (LARGE, &large)] {
        let bound = n.div_ceil(max_ops) as u64 + 2;
        assert!(run.deltas <= bound, "{n} files signed {} deltas (bound {bound})", run.deltas);
        assert!(
            run.cost.head_rows <= ROWS_PER_DELTA_BOUND * n as u64,
            "{n} files touched {} head rows",
            run.cost.head_rows
        );
    }
    let row_ratio = large.cost.head_rows as f64 / small.cost.head_rows as f64;
    let vm_ratio = large.cost.vm_work as f64 / small.cost.vm_work as f64;
    assert!(row_ratio <= DOUBLING_RATIO_BOUND, "head rows grew x{row_ratio:.2}");
    assert!(vm_ratio <= DOUBLING_RATIO_BOUND, "vm work grew x{vm_ratio:.2}");
}
