//! Pins what answering a peer's summary costs: the namespace root is a stored row, patched with every
//! head write, so a summary reads no head row however large the group, and the stored trie always
//! equals the trie rebuilt from the rows.

use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, FolderGroupId, SyncPath, VersionHash};
use yadorilink_replica_domain::local_op::Op;
use yadorilink_replica_domain::native_state::DeltaHash;
use yadorilink_replica_domain::signed_delta::{DeltaOp, DeltaPut, HeadRef, NativeDelta};

use crate::local_author::LocalAuthor;
use crate::native_replication::{summary_roots, SummaryRoots};
use crate::native_store::{self, head_row_counters};
use crate::native_summary_cache::compute_summary_roots;

fn group() -> FolderGroupId {
    FolderGroupId("g1".into())
}

fn conn() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    crate::replica_tables::init(&c).unwrap();
    c
}

/// Fills a group with `heads` live heads (one per path) spread over `authors`
/// authors, with a matching context and frontier row per author, by raw SQL so
/// a large group is cheap to build.
fn populate(c: &Connection, heads: usize, authors: usize) {
    c.execute_batch("BEGIN").unwrap();
    {
        let mut head = c
            .prepare(
                "INSERT INTO native_heads (group_id, path, author, incarnation, seq, version, \
                 provenance) VALUES ('g1', ?1, ?2, zeroblob(16), ?3, ?4, ?5)",
            )
            .unwrap();
        for i in 0..heads {
            let author = format!("device-{}", i % authors);
            let hash = [(i % 251) as u8 + 1; 32];
            let mut provenance = hash;
            provenance[..8].copy_from_slice(&(i as u64).to_be_bytes());
            head.execute(rusqlite::params![
                format!("dir-{:04}/file-{i:07}", i % 1000),
                author,
                (i / authors + 1) as i64,
                hash.as_slice(),
                provenance.as_slice(),
            ])
            .unwrap();
        }
    }
    for a in 0..authors {
        let author = format!("device-{a}");
        c.execute(
            "INSERT INTO native_author_context (group_id, author, incarnation, seq) \
             VALUES ('g1', ?1, zeroblob(16), ?2)",
            rusqlite::params![author, (heads / authors) as i64],
        )
        .unwrap();
        c.execute(
            "INSERT INTO native_author_frontier (group_id, author, incarnation, seq, tip) \
             VALUES ('g1', ?1, zeroblob(16), ?2, zeroblob(32))",
            rusqlite::params![author, (heads / authors) as i64],
        )
        .unwrap();
    }
    // The head inserts only noted their paths; patching the trie from them is what a summary or a
    // seal does first.
    crate::native_namespace::flush_pending(c, &group()).unwrap();
    c.execute_batch("COMMIT").unwrap();
}

/// SQLite virtual-machine work (in units of 1000 instructions) `c` does from now on.
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

/// What one summary cost.
struct SummaryCost {
    head_rows: u64,
    vm_work: u64,
}

fn measure_summary(c: &Connection, ticks: &std::sync::atomic::AtomicU64) -> SummaryCost {
    ticks.store(0, std::sync::atomic::Ordering::Relaxed);
    head_row_counters::reset();
    summary_roots(c, &group()).unwrap();
    SummaryCost {
        head_rows: head_row_counters::snapshot().0,
        vm_work: ticks.load(std::sync::atomic::Ordering::Relaxed),
    }
}

/// A summary reads no head row and costs the same at every group size: the namespace root is one
/// stored row.
#[test]
fn a_summary_costs_the_same_however_large_the_group() {
    let mut work = Vec::new();
    for heads in [2000usize, 4000] {
        let c = conn();
        populate(&c, heads, 10);
        let ticks = count_vm_work(&c);
        for _ in 0..3 {
            let cost = measure_summary(&c, &ticks);
            assert_eq!(cost.head_rows, 0, "a summary of {heads} heads read head rows");
            work.push(cost.vm_work);
        }
    }
    // The author-state root is over 10 authors at both sizes.
    assert!(work.iter().all(|w| *w <= work[0] + 1), "summary cost grew with the group: {work:?}");
}

/// A changed group is answered from the patched trie: a write moves the root, a second summary is the
/// same, and neither read a head row.
#[test]
fn a_changed_group_is_answered_from_the_patched_trie() {
    let c = conn();
    populate(&c, 500, 5);
    let ticks = count_vm_work(&c);
    let before = summary_roots(&c, &group()).unwrap();
    let local_key = SigningKey::from_bytes(&[3u8; 32]);
    let local = LocalAuthor { author: author_id("local"), signing_key: &local_key, capture: None };
    let op = Op::Put { path: SyncPath("new/file".into()), version: VersionHash([9; 32]) };
    crate::native_authoring::author_op(&c, &group(), &local, &op).unwrap();
    assert!(summary_roots(&c, &group()).is_err(), "the write only noted its path");
    crate::native_namespace::flush_pending(&c, &group()).unwrap();
    let first = measure_summary(&c, &ticks);
    let after = summary_roots(&c, &group()).unwrap();
    assert_ne!(after, before);
    assert_eq!(after, fresh_roots(&c));
    assert_eq!(first.head_rows, 0);
    crate::native_namespace::check_integrity(&c, &group()).unwrap();
}

/// A deterministic pseudo-random sequence for the differential test.
struct Rng(u64);

impl Rng {
    fn next(&mut self, bound: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % bound as u64) as usize
    }
}

fn fresh_roots(c: &Connection) -> SummaryRoots {
    compute_summary_roots(c, &group()).unwrap()
}

/// The roots served from the stored trie are the roots rebuilt from the rows, and the stored nodes
/// are exactly what the root reaches, with exact reference counts.
fn assert_summary_matches_rows(c: &Connection, step: &str) {
    crate::native_namespace::flush_pending(c, &group()).unwrap();
    let fresh = fresh_roots(c);
    assert_eq!(summary_roots(c, &group()).unwrap(), fresh, "{step}: the summary is stale");
    crate::native_namespace::check_integrity(c, &group()).unwrap_or_else(|e| panic!("{step}: {e}"));
}

fn author_id(device: &str) -> AuthorId {
    AuthorId { device: DeviceId(device.into()), incarnation: IncarnationId([1u8; 16]) }
}

fn remote_delta(
    key: &SigningKey,
    author: &AuthorId,
    seq: u64,
    prev: Option<DeltaHash>,
    path: &str,
    removes: Vec<HeadRef>,
    version: u8,
) -> NativeDelta {
    let mut delta = NativeDelta {
        recursive_part: None,
        group_id: group(),
        author: author.clone(),
        seq: AuthorSeq(seq),
        prev,
        ops: vec![DeltaOp {
            path: SyncPath(path.into()),
            removes,
            put: Some(DeltaPut { version: VersionHash([version; 32]) }),
        }],
        signature: [0u8; 64],
    };
    delta.sign(key);
    delta
}

/// Random sequences of every kind of write -- local authoring, remote install,
/// closure, a whole-state and whole-frontier replacement, raw statements followed by a rebuild and
/// a rolled-back transaction -- and after each step the served roots equal the
/// roots recomputed from the rows and the stored nodes are exactly the reachable ones.
#[test]
fn served_roots_always_equal_the_roots_of_the_rows() {
    for seed in 1..=6u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let c = conn();
        let local_key = SigningKey::from_bytes(&[3u8; 32]);
        let local =
            LocalAuthor { author: author_id("local"), signing_key: &local_key, capture: None };
        let remote_keys = [SigningKey::from_bytes(&[5u8; 32]), SigningKey::from_bytes(&[6u8; 32])];
        let remotes = [author_id("remote-a"), author_id("remote-b")];
        let closing_key = SigningKey::from_bytes(&[7u8; 32]);
        let closing = author_id("remote-closing");
        let mut next_seq = [1u64; 2];
        let mut prev: [Option<DeltaHash>; 2] = [None, None];
        let mut installed = 0;
        assert_summary_matches_rows(&c, "empty group");
        for step in 0..60 {
            let path = format!("d{}/f{}", rng.next(3), rng.next(5));
            let label = format!("seed {seed} step {step}");
            match rng.next(9) {
                0 | 1 => {
                    let version = VersionHash([rng.next(200) as u8 + 1; 32]);
                    let op = Op::Put { path: SyncPath(path.clone()), version };
                    let _ = crate::native_authoring::author_op(&c, &group(), &local, &op);
                }
                2 => {
                    let op = Op::Delete { path: SyncPath(path.clone()) };
                    let _ = crate::native_authoring::author_op(&c, &group(), &local, &op);
                }
                3 | 4 => {
                    let who = rng.next(2);
                    // Sometimes supersede what the path holds, otherwise land
                    // beside it as a concurrent head.
                    let removes = if rng.next(2) == 0 {
                        native_store::native_heads_at(&c, &group(), &SyncPath(path.clone()))
                            .unwrap()
                            .into_iter()
                            .map(|head| HeadRef {
                                dot: head.dot,
                                provenance: head.payload.provenance,
                            })
                            .collect()
                    } else {
                        Vec::new()
                    };
                    let delta = remote_delta(
                        &remote_keys[who],
                        &remotes[who],
                        next_seq[who],
                        prev[who],
                        &path,
                        removes,
                        rng.next(200) as u8 + 1,
                    );
                    if native_store::install_verified_delta(
                        &c,
                        &group(),
                        &delta,
                        &remote_keys[who].verifying_key(),
                    )
                    .is_ok()
                    {
                        prev[who] = Some(delta.delta_hash());
                        next_seq[who] += 1;
                        installed += 1;
                    }
                }
                5 => {
                    // Close an author that nothing else installs for: it first
                    // lands one delta (so it closes at an entry), or is closed
                    // before its first one.
                    if rng.next(2) == 0 {
                        let delta = remote_delta(
                            &closing_key,
                            &closing,
                            AuthorSeq::FIRST.get(),
                            None,
                            &path,
                            Vec::new(),
                            rng.next(200) as u8 + 1,
                        );
                        let _ = native_store::install_verified_delta(
                            &c,
                            &group(),
                            &delta,
                            &closing_key.verifying_key(),
                        );
                    }
                    crate::native_closure::close_author_unverified(&c, &group(), &closing).unwrap();
                }
                6 => {
                    // A join installs the whole state and the whole frontier.
                    let mut state = native_store::load_state(&c, &group()).unwrap();
                    let victim = state.heads.keys().next().cloned();
                    if let Some(victim) = victim {
                        state.heads.remove(&victim);
                    }
                    native_store::install_state(&c, &group(), &state).unwrap();
                    let frontier = native_store::load_frontier(&c, &group()).unwrap();
                    native_store::install_frontier(&c, &group(), &frontier).unwrap();
                }
                7 => {
                    // A raw statement: the trigger notes the path like any other head write.
                    c.execute(
                        "DELETE FROM native_heads WHERE rowid IN \
                         (SELECT rowid FROM native_heads LIMIT 1 OFFSET ?1)",
                        [rng.next(4) as i64],
                    )
                    .unwrap();
                }
                _ => {
                    // A transaction that rolls back leaves the roots as they were.
                    crate::native_namespace::flush_pending(&c, &group()).unwrap();
                    let before = summary_roots(&c, &group()).unwrap();
                    c.execute_batch("BEGIN").unwrap();
                    let version = VersionHash([250; 32]);
                    let op = Op::Put { path: SyncPath(path.clone()), version };
                    let _ = crate::native_authoring::author_op(&c, &group(), &local, &op);
                    crate::native_namespace::flush_pending(&c, &group()).unwrap();
                    let inside = summary_roots(&c, &group()).unwrap();
                    assert_eq!(inside, fresh_roots(&c), "{label}: stale inside the transaction");
                    c.execute_batch("ROLLBACK").unwrap();
                    assert_eq!(summary_roots(&c, &group()).unwrap(), before, "{label}: rollback");
                }
            }
            assert_summary_matches_rows(&c, &label);
        }
        assert!(installed >= 3, "seed {seed}: only {installed} remote deltas installed");
    }
}

/// Every write of a head row, ordinary or a raw statement, notes its path (a trigger no writer can
/// skip), and a summary refuses to answer from a trie that is behind: it errors until the pending
/// paths are patched in, and then equals the trie rebuilt from the rows. The other root tables move
/// the roots without touching the trie.
#[test]
fn a_head_write_notes_its_path_and_a_summary_waits_for_the_patch() {
    let c = conn();
    populate(&c, 50, 3);
    let key = SigningKey::from_bytes(&[3u8; 32]);
    let local = LocalAuthor { author: author_id("local"), signing_key: &key, capture: None };
    let statements = [
        "UPDATE native_heads SET provenance = randomblob(32) WHERE path = 'dir-0003/file-0000003'",
        "DELETE FROM native_heads WHERE path = 'dir-0004/file-0000004'",
        "INSERT INTO native_heads (group_id, path, author, incarnation, seq, version, \
         provenance) VALUES ('g1', 'new/path', 'device-0', zeroblob(16), 99, \
         zeroblob(32), randomblob(32))",
        // Moving every head to another group changes the group it left.
        "UPDATE native_heads SET group_id = 'other'",
    ];
    let pending = |c: &Connection| -> i64 {
        c.query_row("SELECT COUNT(*) FROM native_namespace_pending", [], |r| r.get(0)).unwrap()
    };
    for statement in statements {
        assert_eq!(pending(&c), 0, "{statement}: nothing is pending between steps");
        c.execute(statement, []).unwrap();
        assert!(pending(&c) > 0, "{statement}: the write did not note its path");
        let err = summary_roots(&c, &group()).unwrap_err().to_string();
        assert!(err.contains("brought up to date"), "{statement}: {err}");
        // An ordinary delta on top adds its path and does not make the older one go away.
        let op = Op::Put {
            path: SyncPath(format!("elsewhere-{}", statement.len())),
            version: VersionHash([9; 32]),
        };
        crate::native_authoring::author_op(&c, &group(), &local, &op).unwrap();
        assert!(summary_roots(&c, &group()).is_err(), "{statement}");
        assert_summary_matches_rows(&c, statement);
    }
    let served = summary_roots(&c, &group()).unwrap();
    for statement in [
        "UPDATE native_author_frontier SET seq = seq + 1 WHERE author = 'device-1'",
        "DELETE FROM native_author_frontier WHERE author = 'device-2'",
        "INSERT INTO native_closed_authors (group_id, author, incarnation, \
         closed_at_unixtime) VALUES ('g1', 'device-0', zeroblob(16), 1)",
        "UPDATE native_closed_authors SET cutoff_seq = 1, cutoff_tip = randomblob(32)",
    ] {
        c.execute(statement, []).unwrap();
        assert_summary_matches_rows(&c, statement);
    }
    assert_ne!(summary_roots(&c, &group()).unwrap(), served);
}

/// A second connection to the same file sees the stored trie, and a copy of the database that diverges
/// keeps its own.
#[test]
fn another_connection_serves_the_stored_trie() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("index.db");
    let open = |path: &std::path::Path| {
        let c = Connection::open(path).unwrap();
        c.execute_batch("PRAGMA journal_mode = WAL").unwrap();
        crate::replica_tables::init(&c).unwrap();
        c
    };
    let (reader, writer) = (open(&path), open(&path));
    populate(&writer, 100, 4);
    let before = summary_roots(&reader, &group()).unwrap();
    assert_eq!(before, fresh_roots(&reader));
    let key = SigningKey::from_bytes(&[3u8; 32]);
    let local = LocalAuthor { author: author_id("local"), signing_key: &key, capture: None };
    let op = Op::Put { path: SyncPath("extra".into()), version: VersionHash([4; 32]) };
    crate::native_authoring::author_op(&writer, &group(), &local, &op).unwrap();
    crate::native_namespace::flush_pending(&reader, &group()).unwrap();
    let after = summary_roots(&reader, &group()).unwrap();
    assert_ne!(after, before);
    assert_eq!(after, fresh_roots(&reader));

    let copy_path = dir.path().join("copy.db");
    std::fs::copy(&path, &copy_path).unwrap();
    let copy = open(&copy_path);
    let op = Op::Put { path: SyncPath("copy-only".into()), version: VersionHash([5; 32]) };
    crate::native_authoring::author_op(&copy, &group(), &local, &op).unwrap();
    crate::native_namespace::flush_pending(&copy, &group()).unwrap();
    assert_eq!(summary_roots(&copy, &group()).unwrap(), fresh_roots(&copy));
    assert_ne!(summary_roots(&copy, &group()).unwrap(), after);
    assert_eq!(summary_roots(&reader, &group()).unwrap(), after);
}

/// Release-profile measurement of one summary at 100k heads and 10 authors:
/// `cargo test -p yadorilink-sync-sqlite --release --lib -- --ignored
/// summary_cost_at_100k --nocapture`.
#[test]
#[ignore = "100k-head measurement; run explicitly"]
fn summary_cost_at_100k_heads() {
    let c = conn();
    populate(&c, 100_000, 10);
    let ticks = count_vm_work(&c);
    for round in 0..3 {
        let started = std::time::Instant::now();
        let cost = measure_summary(&c, &ticks);
        let summary = started.elapsed();
        ticks.store(0, std::sync::atomic::Ordering::Relaxed);
        let started = std::time::Instant::now();
        crate::native_replication::unresolved_head_positions(&c, &group()).unwrap();
        let unresolved = started.elapsed();
        eprintln!(
            "round {round}: summary {summary:?} ({} head rows, {}k vm); \
             unresolved_head_positions {unresolved:?} ({}k vm)",
            cost.head_rows,
            cost.vm_work,
            ticks.load(std::sync::atomic::Ordering::Relaxed)
        );
        assert_eq!(cost.head_rows, 0, "round {round}");
    }
}

/// This process's resident set in MiB, from `ps`.
fn resident_mib() -> f64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().parse::<f64>().unwrap() / 1024.0
}

/// What the whole-group steps of a bootstrap join cost at 100k heads: the local
/// state is loaded, joined with the bundle's, and the result replaces the
/// group's rows. `cargo nextest run -p yadorilink-sync-sqlite --lib --run-ignored
/// only join_of_100k --no-capture`.
#[test]
#[ignore = "100k-head measurement; run explicitly"]
fn join_of_100k_heads_whole_group_steps() {
    let local = conn();
    populate(&local, 100_000, 10);
    let remote = conn();
    populate(&remote, 100_000, 10);
    // The remote has moved on: every tenth head is another write.
    remote
        .execute(
            "UPDATE native_heads SET seq = seq + 1000000, provenance = randomblob(32) \
             WHERE rowid % 10 = 0",
            [],
        )
        .unwrap();
    let rss_idle = resident_mib();
    head_row_counters::reset();
    let started = std::time::Instant::now();
    let local_state = native_store::load_state(&local, &group()).unwrap();
    let local_frontier = native_store::load_frontier(&local, &group()).unwrap();
    let remote_state = native_store::load_state(&remote, &group()).unwrap();
    let loaded = started.elapsed();
    let rss_loaded = resident_mib();
    let joined = yadorilink_replica_domain::native_state::join(&local_state, &remote_state)
        .expect("histories do not fork");
    let join_time = started.elapsed() - loaded;
    let rss_joined = resident_mib();
    let tx = local.unchecked_transaction().unwrap();
    let installing = std::time::Instant::now();
    native_store::install_state(&tx, &group(), &joined).unwrap();
    native_store::install_frontier(&tx, &group(), &local_frontier).unwrap();
    tx.commit().unwrap();
    let install_time = installing.elapsed();
    let (read, written) = head_row_counters::snapshot();
    eprintln!(
        "join at 100k heads: load {loaded:?}, join {join_time:?}, install {install_time:?}; \
         head rows read {read}, written {written}; resident {rss_idle:.0} MiB idle, \
         {rss_loaded:.0} MiB with both states loaded, {rss_joined:.0} MiB with the join; \
         peak growth {:.0} MiB for {} joined heads",
        rss_joined.max(resident_mib()) - rss_idle,
        joined.heads.values().map(|heads| heads.len()).sum::<usize>(),
    );
}

/// The live memory a summary and a rebuild hold does not grow with the group: a summary reads one
/// row, and a rebuild holds one chunk of paths and the nodes they make, not the group. The summary
/// of a 100k-path group used to hold its whole trie (1.7 GB live at the peak of a 100k import).
#[test]
fn summary_and_rebuild_memory_do_not_grow_with_the_group() {
    let mut summary_peaks = Vec::new();
    let mut rebuild_peaks = Vec::new();
    for heads in [5_000usize, 20_000] {
        let c = conn();
        populate(&c, heads, 10);
        let (roots, summary_peak) =
            crate::test_alloc::peak_during(|| summary_roots(&c, &group()).unwrap());
        assert_eq!(roots, fresh_roots(&c));
        // Every path pending against an empty trie: the largest flush there is.
        c.execute_batch("DELETE FROM native_namespace_node; DELETE FROM native_namespace_root")
            .unwrap();
        c.execute_batch(
            "INSERT OR IGNORE INTO native_namespace_pending (group_id, path) \
             SELECT DISTINCT group_id, path FROM native_heads",
        )
        .unwrap();
        c.execute_batch("BEGIN").unwrap();
        let (_, rebuild_peak) = crate::test_alloc::peak_during(|| {
            crate::native_namespace::flush_pending(&c, &group()).unwrap();
        });
        c.execute_batch("COMMIT").unwrap();
        eprintln!(
            "{heads} heads: summary peak {} KiB, rebuild peak {} KiB",
            summary_peak / 1024,
            rebuild_peak / 1024
        );
        summary_peaks.push(summary_peak);
        rebuild_peaks.push(rebuild_peak);
    }
    assert!(summary_peaks.iter().all(|p| *p < 1 << 20), "a summary held {summary_peaks:?} bytes");
    assert!(
        rebuild_peaks[1] <= rebuild_peaks[0] * 3 / 2,
        "the rebuild's peak grew with the group: {rebuild_peaks:?}"
    );
}

/// A bundle that cannot be built because a head's delta or publication evidence is not held is
/// refused before any work that grows with the group: the refusal is what a cold-joining requester
/// gets again and again while the sender is still importing, and each one used to load every head
/// and rebuild the roots with the writer gate held.
#[test]
fn a_bundle_that_cannot_be_built_is_refused_before_group_sized_work() {
    let c = conn();
    populate(&c, 20_000, 10);
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let (refused, peak) = crate::test_alloc::peak_during(|| {
        crate::native_bootstrap::build_native_recovery_bundle(&c, &group(), &key)
    });
    let error = refused.expect_err("a group whose heads have no evidence has no bundle");
    assert!(error.to_string().contains("is not retained"), "{error}");
    assert!(peak < 256 * 1024, "the refusal held {peak} bytes");
}

/// A copy of the database file at `path` (rollback journal, so the file alone is the whole state), so
/// every attempt starts from the same state.
fn clone_db(dir: &std::path::Path, path: &std::path::Path, n: u32) -> Connection {
    let copy = dir.join(format!("attempt-{n}.db"));
    std::fs::copy(path, &copy).unwrap();
    Connection::open(&copy).unwrap()
}

/// Runs `step` in a transaction on a copy of the database at `base_path`, cutting it short after
/// `ticks` SQLite instructions; true when it ran to the end (and committed), false when the cut
/// landed first (and the transaction is rolled back).
fn run_cut(
    dir: &std::path::Path,
    base_path: &std::path::Path,
    ticks: u32,
    step: impl FnOnce(&Connection) -> Result<(), crate::error::SyncSqliteError>,
) -> (Connection, bool) {
    let c = clone_db(dir, base_path, ticks);
    c.execute_batch("BEGIN").unwrap();
    let counter = std::sync::atomic::AtomicU32::new(0);
    c.progress_handler(
        1,
        Some(move || counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) >= ticks),
    );
    let outcome = step(&c);
    c.progress_handler(1, None::<fn() -> bool>);
    if outcome.is_err() {
        // An interrupt may already have rolled the transaction back; either way it is over.
        let _ = c.execute_batch("ROLLBACK");
        (c, false)
    } else {
        c.execute_batch("COMMIT").unwrap();
        (c, true)
    }
}

/// Cut points: every instruction at first, then 5 % further apart each time.
fn cut_points() -> impl Iterator<Item = u32> {
    std::iter::successors(Some(1u32), |t| Some(t + 1 + t / 20)).take_while(|t| *t < 20_000_000)
}

/// What the trie tables hold: the node rows with their counts, the root row, the pending paths.
/// The node rows (kind, digest, count), the root rows and the pending paths.
type TrieDump = (Vec<(i64, Vec<u8>, i64)>, Vec<Vec<u8>>, Vec<String>);

fn trie_dump(c: &Connection) -> TrieDump {
    let nodes = c
        .prepare("SELECT kind, digest, refs FROM native_namespace_node ORDER BY kind, digest")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let roots = c
        .prepare("SELECT root FROM native_namespace_root ORDER BY group_id")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let pending = c
        .prepare("SELECT path FROM native_namespace_pending ORDER BY path")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    (nodes, roots, pending)
}

/// A transaction cut short at every point of an install, and of the patch that follows it, rolls back
/// whole. The interrupt lands inside every statement of the install (heads and the pending paths its
/// trigger notes) and of the flush (the node rows, their counts, the root and the pending paths), in
/// turn, until the step completes. Rolled back, the heads, the trie tables and the pending set are
/// exactly those before; completed, the stored trie equals the one rebuilt from the rows.
#[test]
fn an_interrupted_install_or_patch_leaves_one_consistent_state() {
    let dir = tempfile::tempdir().unwrap();
    let base_path = dir.path().join("base.db");
    let base = Connection::open(&base_path).unwrap();
    crate::replica_tables::init(&base).unwrap();
    populate(&base, 300, 3);
    let local_key = SigningKey::from_bytes(&[3u8; 32]);
    let local = LocalAuthor { author: author_id("local"), signing_key: &local_key, capture: None };
    let before_roots = summary_roots(&base, &group()).unwrap();
    let before_trie = trie_dump(&base);
    let head_count = |c: &Connection| -> i64 {
        c.query_row("SELECT COUNT(*) FROM native_heads", [], |r| r.get(0)).unwrap()
    };
    let ops = [
        Op::Put { path: SyncPath("dir-0003/file-0000003".into()), version: VersionHash([77; 32]) },
        Op::Put { path: SyncPath("brand/new/path".into()), version: VersionHash([78; 32]) },
        Op::Put { path: SyncPath("dir-0005/file-0000005".into()), version: VersionHash([79; 32]) },
    ];
    for op in &ops {
        // The install: cut anywhere, nothing of it survives.
        let mut interrupted = 0;
        let mut completed = false;
        for ticks in cut_points() {
            let (c, done) = run_cut(dir.path(), &base_path, ticks, |c| {
                crate::native_authoring::author_op(c, &group(), &local, op).map(|_| ())
            });
            if done {
                assert_summary_matches_rows(&c, &format!("{op:?} installed after {ticks} ticks"));
                assert_ne!(summary_roots(&c, &group()).unwrap(), before_roots, "{op:?}");
                completed = true;
                break;
            }
            assert_eq!(head_count(&c), head_count(&base), "{op:?} cut at {ticks}: heads");
            assert_eq!(trie_dump(&c), before_trie, "{op:?} cut at {ticks}: trie tables");
            interrupted += 1;
        }
        assert!(completed, "{op:?} never completed within the tick budget");
        assert!(interrupted > 20, "{op:?}: only {interrupted} install cut points");

        // The patch: the install committed, its paths pending, the flush cut anywhere.
        let installed_path = dir.path().join("installed.db");
        std::fs::copy(&base_path, &installed_path).unwrap();
        let installed = Connection::open(&installed_path).unwrap();
        crate::native_authoring::author_op(&installed, &group(), &local, op).unwrap();
        let pending_trie = trie_dump(&installed);
        assert!(!pending_trie.2.is_empty(), "{op:?}: the install noted no path");
        let mut interrupted = 0;
        let mut completed = false;
        for ticks in cut_points() {
            let (c, done) = run_cut(dir.path(), &installed_path, ticks, |c| {
                crate::native_namespace::flush_pending(c, &group())
            });
            if done {
                assert!(trie_dump(&c).2.is_empty(), "{op:?}: paths still pending");
                assert_summary_matches_rows(&c, &format!("{op:?} patched after {ticks} ticks"));
                completed = true;
                break;
            }
            assert_eq!(trie_dump(&c), pending_trie, "{op:?} flush cut at {ticks}");
            assert!(
                summary_roots(&c, &group()).is_err(),
                "{op:?} cut at {ticks}: served a stale root"
            );
            interrupted += 1;
        }
        assert!(completed, "{op:?}: the flush never completed within the tick budget");
        assert!(interrupted > 20, "{op:?}: only {interrupted} flush cut points");
    }
}

/// What one installed delta costs at 100k heads, with a stored namespace trie to patch: single local
/// edits (existing paths and new ones) and one bulk commit, in wall time. Release profile:
/// `cargo test -p yadorilink-sync-sqlite --release --lib -- --ignored install_cost_at_100k --nocapture`.
#[test]
#[ignore = "100k-head measurement; run explicitly"]
fn install_cost_at_100k_heads() {
    let mut c = conn();
    populate(&c, 100_000, 10);
    let local_key = SigningKey::from_bytes(&[3u8; 32]);
    let local = LocalAuthor { author: author_id("local"), signing_key: &local_key, capture: None };
    // Statements one edit runs, by text, to see where a delta's trie work goes.
    {
        static RUNS: std::sync::Mutex<Option<std::collections::HashMap<String, u64>>> =
            std::sync::Mutex::new(None);
        fn note(sql: &str, _took: std::time::Duration) {
            let mut guard = RUNS.lock().unwrap();
            let map = guard.get_or_insert_with(Default::default);
            let key: String = sql.split_whitespace().collect::<Vec<_>>().join(" ");
            *map.entry(key.chars().take(70).collect()).or_default() += 1;
        }
        c.profile(Some(note));
        let op = Op::Put {
            path: SyncPath("dir-0009/file-0000009".into()),
            version: VersionHash([200; 32]),
        };
        crate::native_authoring::author_op(&c, &group(), &local, &op).unwrap();
        c.profile(None);
        let mut rows: Vec<_> = RUNS.lock().unwrap().take().unwrap().into_iter().collect();
        rows.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        let total: u64 = rows.iter().map(|(_, n)| n).sum();
        eprintln!("one edit runs {total} statements:");
        for (sql, n) in rows.iter().take(14) {
            eprintln!("  {n:>3}  {sql}");
        }
    }
    let timings = |label: &str, paths: Vec<String>| {
        let mut ms: Vec<f64> = Vec::new();
        for (i, path) in paths.iter().enumerate() {
            let op = Op::Put {
                path: SyncPath(path.clone()),
                version: VersionHash([(i % 250) as u8 + 1; 32]),
            };
            let started = std::time::Instant::now();
            crate::native_authoring::author_op(&c, &group(), &local, &op).unwrap();
            ms.push(started.elapsed().as_secs_f64() * 1000.0);
        }
        ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let mean = ms.iter().sum::<f64>() / ms.len() as f64;
        eprintln!(
            "{label}: n {} mean {mean:.3} ms, p50 {:.3}, p95 {:.3}, max {:.3}",
            ms.len(),
            ms[ms.len() / 2],
            ms[ms.len() * 95 / 100],
            ms[ms.len() - 1]
        );
    };
    timings(
        "edit existing path",
        (0..400).map(|i| format!("dir-{:04}/file-{:07}", (i * 7) % 1000, (i * 7) % 1000)).collect(),
    );
    timings("new path", (0..400).map(|i| format!("fresh/dir-{}/file-{i}", i % 50)).collect());
}
