//! Pins what answering a peer's summary costs: an idle group must not rebuild
//! the namespace trie and the frontier roots on every exchange, and the memo
//! that makes that so must never serve roots of a state that has since changed.

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
use crate::native_summary_cache::{compute_summary_roots, recompute_counter};

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

/// What one summary cost, and whether it computed the roots from rows.
struct SummaryCost {
    head_rows: u64,
    vm_work: u64,
    recomputed: bool,
}

fn measure_summary(c: &Connection, ticks: &std::sync::atomic::AtomicU64) -> SummaryCost {
    ticks.store(0, std::sync::atomic::Ordering::Relaxed);
    head_row_counters::reset();
    let before = recompute_counter::computed();
    summary_roots(c, &group()).unwrap();
    SummaryCost {
        head_rows: head_row_counters::snapshot().0,
        vm_work: ticks.load(std::sync::atomic::Ordering::Relaxed),
        recomputed: recompute_counter::computed() != before,
    }
}

#[test]
fn an_unchanged_group_costs_one_indexed_read_per_summary_however_large() {
    let mut hit_work = Vec::new();
    for heads in [2000usize, 4000] {
        let c = conn();
        populate(&c, heads, 10);
        let ticks = count_vm_work(&c);
        let first = measure_summary(&c, &ticks);
        assert!(first.recomputed, "the first summary of {heads} heads computes the roots");
        assert!(first.head_rows >= heads as u64);
        assert!(first.vm_work > 10, "the first summary is real work: {}", first.vm_work);
        for _ in 0..3 {
            let idle = measure_summary(&c, &ticks);
            assert!(!idle.recomputed, "an unchanged group of {heads} heads recomputed its roots");
            assert_eq!(idle.head_rows, 0, "an idle summary read head rows");
            hit_work.push(idle.vm_work);
        }
        eprintln!(
            "{heads} heads: first summary {} vm work, idle summaries {hit_work:?}",
            first.vm_work
        );
    }
    // A hit is a handful of statements, the same at both sizes.
    assert!(hit_work.iter().all(|work| *work <= 1), "idle summaries cost {hit_work:?} ticks");
}

#[test]
fn a_changing_group_recomputes_once_per_generation_whoever_asks() {
    let c = conn();
    populate(&c, 500, 5);
    let ticks = count_vm_work(&c);
    summary_roots(&c, &group()).unwrap();
    c.execute(
        "UPDATE native_heads SET provenance = randomblob(32) WHERE path = 'dir-0001/file-0000001'",
        [],
    )
    .unwrap();
    // Three peers ask for the changed group: one computation serves them all.
    let first = measure_summary(&c, &ticks);
    let second = measure_summary(&c, &ticks);
    let third = measure_summary(&c, &ticks);
    assert!(first.recomputed);
    assert!(!second.recomputed && !third.recomputed);
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

/// The roots the memo serves are the roots of the rows, asked twice so the
/// second is a hit.
fn assert_summary_matches_rows(c: &Connection, step: &str) {
    let fresh = fresh_roots(c);
    assert_eq!(summary_roots(c, &group()).unwrap(), fresh, "{step}: first summary is stale");
    assert_eq!(summary_roots(c, &group()).unwrap(), fresh, "{step}: repeated summary is stale");
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
/// closure, a whole-state and whole-frontier replacement, raw statements and
/// a rolled-back transaction -- and after each step the served roots equal the
/// roots recomputed from the rows.
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
                    // A raw statement that knows nothing of the memo.
                    c.execute(
                        "DELETE FROM native_heads WHERE rowid IN \
                         (SELECT rowid FROM native_heads LIMIT 1 OFFSET ?1)",
                        [rng.next(4) as i64],
                    )
                    .unwrap();
                }
                _ => {
                    // A transaction that rolls back leaves the roots as they were.
                    let before = summary_roots(&c, &group()).unwrap();
                    c.execute_batch("BEGIN").unwrap();
                    let version = VersionHash([250; 32]);
                    let op = Op::Put { path: SyncPath(path.clone()), version };
                    let _ = crate::native_authoring::author_op(&c, &group(), &local, &op);
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

/// Every table the roots are computed from, written by a raw statement that
/// knows nothing of the memo, changes what is served.
#[test]
fn a_raw_writer_to_any_root_table_cannot_leave_a_stale_summary() {
    let c = conn();
    populate(&c, 50, 3);
    let statements = [
        "UPDATE native_heads SET provenance = randomblob(32) WHERE path = 'dir-0003/file-0000003'",
        "DELETE FROM native_heads WHERE path = 'dir-0004/file-0000004'",
        "INSERT INTO native_heads (group_id, path, author, incarnation, seq, version, \
         provenance) VALUES ('g1', 'new/path', 'device-0', zeroblob(16), 99, \
         zeroblob(32), randomblob(32))",
        "UPDATE native_author_frontier SET seq = seq + 1 WHERE author = 'device-1'",
        "DELETE FROM native_author_frontier WHERE author = 'device-2'",
        "INSERT INTO native_closed_authors (group_id, author, incarnation, \
         closed_at_unixtime) VALUES ('g1', 'device-0', zeroblob(16), 1)",
        "UPDATE native_closed_authors SET cutoff_seq = 1, cutoff_tip = randomblob(32)",
        // The cutoff is part of the author-state root. The context is
        // not part of any root, but a write to it still changes the token, so nothing here relies
        // on knowing which tables matter.
        "UPDATE native_author_context SET seq = seq + 1 WHERE author = 'device-0'",
        "DELETE FROM native_author_context WHERE author = 'device-1'",
        // Moving every head to another group changes the group it left.
        "UPDATE native_heads SET group_id = 'other'",
    ];
    let mut served = summary_roots(&c, &group()).unwrap();
    for statement in statements {
        c.execute(statement, []).unwrap();
        assert_summary_matches_rows(&c, statement);
        let now = summary_roots(&c, &group()).unwrap();
        let affects_roots = !statement.contains("native_author_context");
        assert_eq!(now != served, affects_roots, "{statement}");
        served = now;
    }
}

/// A second connection to the same file, and a process that restarts, see the
/// token the database holds, never a memo of an older state; a diverged copy of
/// the database is not mistaken for the original.
#[test]
fn another_connection_never_serves_a_stale_summary() {
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
    writer.execute("DELETE FROM native_heads WHERE path = 'dir-0005/file-0000005'", []).unwrap();
    let after = summary_roots(&reader, &group()).unwrap();
    assert_ne!(after, before);
    assert_eq!(after, fresh_roots(&reader));

    let copy_path = dir.path().join("copy.db");
    std::fs::copy(&path, &copy_path).unwrap();
    let copy = open(&copy_path);
    copy.execute("DELETE FROM native_heads WHERE path = 'dir-0006/file-0000006'", []).unwrap();
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
            "round {round}: summary {summary:?} ({} head rows, {}k vm, recomputed {}); \
             unresolved_head_positions {unresolved:?} ({}k vm)",
            cost.head_rows,
            cost.vm_work,
            cost.recomputed,
            ticks.load(std::sync::atomic::Ordering::Relaxed)
        );
        // Only the first summary of an unchanged group computes the roots.
        assert_eq!(cost.recomputed, round == 0, "round {round}");
        if round > 0 {
            assert_eq!(cost.head_rows, 0);
        }
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
