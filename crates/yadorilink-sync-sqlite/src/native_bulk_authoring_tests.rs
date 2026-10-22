//! Bulk capture signs one multi-op delta per run of mutations at unrelated
//! paths. These tests pin that the grouped commit means exactly what
//! committing the same mutations one delta each means (the reference is
//! `commit_local_mutation_reference_in_tx`), that a peer admitting the grouped
//! deltas ends in the author's state and sees a consistent prefix, and that a
//! run stays within the wire bounds.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::file::{FileMeta, FileRecord, FileVersion, RecordKind};
use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, FolderGroupId, SyncPath, VersionHash};
use yadorilink_replica_domain::local_op::Op;
use yadorilink_replica_domain::native_state::DeltaHash;
use yadorilink_replica_domain::recursive_operation::RecursiveOperationKind;
use yadorilink_replica_domain::session_state::{LocalFileMetaColumns, PreparedLocalMutation};
use yadorilink_replica_domain::signed_delta::{DeltaOp, DeltaPut, NativeDelta};
use yadorilink_sqlite_runtime::SyncDatabase;

use crate::error::SyncSqliteError;
use crate::file_index::{FileIndexRepository, SignedEmissionContext};
use crate::local_author::LocalAuthor;
use crate::native_authoring::{bulk_groups, BulkOp, BULK_DELTA_MAX_OPS};
use crate::native_store;

fn group() -> FolderGroupId {
    FolderGroupId("g1".into())
}

fn author_id(device: &str) -> AuthorId {
    AuthorId { device: DeviceId(device.into()), incarnation: IncarnationId([1u8; 16]) }
}

fn local_key() -> SigningKey {
    SigningKey::from_bytes(&[3u8; 32])
}

fn remote_key() -> SigningKey {
    SigningKey::from_bytes(&[4u8; 32])
}

/// What a test asks the capture to do at a path.
#[derive(Clone, Debug)]
enum Spec {
    Put { path: String, salt: i64 },
    Delete { path: String },
}

impl Spec {
    fn path(&self) -> &str {
        match self {
            Spec::Put { path, .. } | Spec::Delete { path } => path,
        }
    }
}

/// One replica's database and the handles to commit through it.
struct Side {
    db: Arc<SyncDatabase>,
    repo: FileIndexRepository,
}

impl Side {
    fn new() -> Self {
        let db = crate::replica_tables::open_for_tests();
        Self { repo: FileIndexRepository::new(db.clone()), db }
    }

    /// The prepared mutation for `spec`, with the witness the row at its path
    /// shows now (what a capture just before the commit records).
    fn prepare(&self, spec: &Spec, witnessed: bool) -> PreparedLocalMutation {
        let witness = self
            .db
            .write_immediate::<_, SyncSqliteError>(|tx| {
                crate::native_capture::capture_native_witness(tx, &group(), spec.path())
            })
            .unwrap();
        let witness = witnessed.then_some(witness);
        match spec {
            Spec::Put { path, salt } => {
                let version = FileVersion::new(
                    Vec::new(),
                    0,
                    FileMeta {
                        mtime_unix_nanos: *salt,
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
                        mtime_unix_nanos: *salt,
                        blocks: Vec::new(),
                        deleted: false,
                    },
                    op: Op::Put { path: SyncPath(path.clone()), version: version.version_hash },
                    meta: Some(LocalFileMetaColumns {
                        record_kind: RecordKind::File,
                        symlink_target: None,
                        symlink_out_of_root: false,
                        unix_mode: Some(0o644),
                        xattrs: Vec::new(),
                    }),
                    version,
                    native_witness: witness,
                }
            }
            Spec::Delete { path } => PreparedLocalMutation::Delete {
                record: FileRecord {
                    path: path.clone(),
                    size: 0,
                    mtime_unix_nanos: 1,
                    blocks: Vec::new(),
                    deleted: true,
                },
                op: Op::Delete { path: SyncPath(path.clone()) },
                native_witness: witness,
            },
        }
    }

    fn prepare_all(&self, specs: &[Spec]) -> Vec<PreparedLocalMutation> {
        // A path a batch acts on again carries no witness for its later
        // mutations: what it showed at capture is replaced by the earlier one.
        let mut seen = std::collections::BTreeSet::new();
        specs.iter().map(|spec| self.prepare(spec, seen.insert(spec.path().to_owned()))).collect()
    }

    /// Commits through the production batch commit (grouped).
    fn commit_grouped(&self, specs: &[Spec]) -> Result<(), SyncSqliteError> {
        let key = local_key();
        let local = LocalAuthor { author: author_id("device-a"), signing_key: &key, capture: None };
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        let mutations = self.prepare_all(specs);
        self.repo.commit_local_mutations_batch(
            "g1",
            &mutations,
            &[],
            "device-a",
            SignedEmissionContext { author: &local, permit: &permit },
        )
    }

    /// Commits the same mutations one delta each, in one transaction.
    fn commit_one_by_one(&self, specs: &[Spec]) -> Result<(), SyncSqliteError> {
        let key = local_key();
        let local = LocalAuthor { author: author_id("device-a"), signing_key: &key, capture: None };
        let mutations = self.prepare_all(specs);
        self.db.write_immediate::<_, SyncSqliteError>(|tx| {
            for mutation in &mutations {
                crate::file_index::commit_local_mutation_reference_in_tx(
                    tx, "g1", mutation, None, "device-a", &local,
                )?;
            }
            Ok(())
        })
    }

    fn install_remote(&self, delta: &NativeDelta) {
        self.db
            .write_immediate::<_, SyncSqliteError>(|tx| {
                native_store::install_verified_delta(
                    tx,
                    &group(),
                    delta,
                    &remote_key().verifying_key(),
                )
                .map(|_| ())
            })
            .unwrap();
    }

    fn local_tip(&self) -> u64 {
        self.db
            .write_immediate::<_, SyncSqliteError>(|tx| {
                Ok(native_store::frontier_entry_get(tx, &group(), &author_id("device-a"))?
                    .map(|entry| entry.seq.get())
                    .unwrap_or(0))
            })
            .unwrap()
    }

    fn local_delta(&self, seq: u64) -> NativeDelta {
        let body = self
            .db
            .write_immediate::<_, SyncSqliteError>(|tx| {
                native_store::fetch_delta_body(tx, &group(), &author_id("device-a"), AuthorSeq(seq))
            })
            .unwrap()
            .expect("the delta body is stored");
        NativeDelta::from_wire_bytes(&body).expect("a peer decodes it")
    }

    fn state(&self) -> yadorilink_replica_domain::native_state::NativeState {
        self.db
            .write_immediate::<_, SyncSqliteError>(|tx| native_store::load_state(tx, &group()))
            .unwrap()
    }

    fn snapshot(&self) -> Snapshot {
        self.db.write_immediate::<_, SyncSqliteError>(|tx| Ok(Snapshot::of(tx))).unwrap()
    }
}

/// What a replica means by its state, without the identities (dots, seqs,
/// hashes) that depend on how many deltas the edits were signed in.
#[derive(Debug, PartialEq)]
struct Snapshot {
    /// Every live head: its path and content.
    heads: Vec<(String, Vec<u8>)>,
    /// Every `files` row.
    rows: Vec<(String, i64, i64, String, i64, String)>,
    /// The paths whose last capture authored a head.
    captured: Vec<String>,
    /// The content each authoring witness vouches for.
    witnessed: Vec<Vec<u8>>,
    /// Rows of the removal-operation bookkeeping.
    removal_operations: i64,
    /// The stored content versions.
    versions: Vec<Vec<u8>>,
    /// Each projection obligation's path, generation, state and origin.
    obligations: Vec<(String, i64, String, String)>,
}

impl Snapshot {
    fn of(c: &Connection) -> Self {
        let collect = |sql: &str| -> Vec<(String, Vec<u8>)> {
            let mut stmt = c.prepare(sql).unwrap();
            let rows = stmt
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            rows
        };
        let heads = collect("SELECT path, version FROM native_heads ORDER BY path, version");
        let mut stmt = c
            .prepare(
                "SELECT path, size, mtime_unix_nanos, blocks_json, deleted, state FROM files \
                 ORDER BY path, state",
            )
            .unwrap();
        let rows = stmt
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let captured = c
            .prepare("SELECT path FROM native_local_capture ORDER BY path")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let witnessed = c
            .prepare("SELECT version FROM native_authoring_witness ORDER BY version")
            .unwrap()
            .query_map([], |r| r.get::<_, Vec<u8>>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let removal_operations =
            c.query_row("SELECT COUNT(*) FROM native_removal_operation", [], |r| r.get(0)).unwrap();
        let versions = c
            .prepare("SELECT version_hash FROM file_versions ORDER BY version_hash")
            .unwrap()
            .query_map([], |r| r.get::<_, Vec<u8>>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let obligations = c
            .prepare(
                "SELECT path, invalidation_generation, state, origin FROM projection_obligations \
                 ORDER BY path",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        Self { heads, rows, captured, witnessed, removal_operations, versions, obligations }
    }
}

/// A remote author's delta putting `salt`'s content at `path`, concurrent with
/// whatever the local replica holds there.
struct Remote {
    seq: u64,
    prev: Option<DeltaHash>,
    deltas: Vec<NativeDelta>,
}

impl Remote {
    fn new() -> Self {
        Self { seq: 1, prev: None, deltas: Vec::new() }
    }

    fn put(&mut self, path: &str, salt: u8) -> NativeDelta {
        self.put_version(path, VersionHash([salt; 32]))
    }

    fn put_version(&mut self, path: &str, version: VersionHash) -> NativeDelta {
        let mut delta = NativeDelta {
            recursive_part: None,
            group_id: group(),
            author: author_id("device-b"),
            seq: AuthorSeq(self.seq),
            prev: self.prev,
            ops: vec![DeltaOp {
                path: SyncPath(path.into()),
                removes: Vec::new(),
                put: Some(DeltaPut { version }),
            }],
            signature: [0u8; 64],
        };
        delta.sign(&remote_key());
        self.prev = Some(delta.delta_hash());
        self.seq += 1;
        self.deltas.push(delta.clone());
        delta
    }
}

/// A replica that admits `remote` and then every delta `author` signed.
fn replay_on_a_peer(remote: &Remote, author: &Side) -> Connection {
    let peer = Connection::open_in_memory().unwrap();
    crate::replica_tables::init(&peer).unwrap();
    for delta in &remote.deltas {
        native_store::install_verified_delta(&peer, &group(), delta, &remote_key().verifying_key())
            .unwrap();
    }
    for seq in 1..=author.local_tip() {
        native_store::install_verified_delta(
            &peer,
            &group(),
            &author.local_delta(seq),
            &local_key().verifying_key(),
        )
        .unwrap();
    }
    peer
}

/// A deterministic pseudo-random sequence.
struct Rng(u64);

impl Rng {
    fn next(&mut self, bound: u64) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (self.0 >> 33) % bound
    }
}

const PATHS: [&str; 10] = ["a", "b", "c", "d/e", "d/f", "g", "g/h", "i/j/k", "i/j/l", "m"];

fn random_batch(rng: &mut Rng, salt: &mut i64) -> Vec<Spec> {
    let len = 1 + rng.next(12) as usize;
    (0..len)
        .map(|_| {
            let path = PATHS[rng.next(PATHS.len() as u64) as usize].to_string();
            *salt += 1;
            if rng.next(4) == 0 {
                Spec::Delete { path }
            } else {
                Spec::Put { path, salt: *salt }
            }
        })
        .collect()
}

/// For random batches (creates, edits over what the rows show, deletes,
/// repeated paths, paths under one another) mixed with concurrent remote
/// heads, the grouped commit leaves the same heads, rows, capture provenance,
/// witnesses and removal bookkeeping as committing one delta per mutation, and
/// a peer admitting the grouped deltas ends in the author's state.
#[test]
fn grouped_commit_means_what_one_delta_per_mutation_means() {
    let mut deltas_saved = 0u64;
    for seed in 0..40u64 {
        let mut rng = Rng(seed + 1);
        let (grouped, reference) = (Side::new(), Side::new());
        let mut remote = Remote::new();
        let mut salt = 0i64;
        let mut remote_paths = std::collections::BTreeSet::new();
        for round in 0..5 {
            // One remote head per path keeps the remote author within its own
            // head bound.
            let path = PATHS[rng.next(PATHS.len() as u64) as usize];
            if rng.next(2) == 0 && remote_paths.insert(path) {
                let delta = remote.put(path, 200 + (round * 10) as u8 + seed as u8 % 7);
                grouped.install_remote(&delta);
                reference.install_remote(&delta);
            }
            let batch = random_batch(&mut rng, &mut salt);
            grouped.commit_grouped(&batch).unwrap();
            reference.commit_one_by_one(&batch).unwrap();
            assert_eq!(
                grouped.snapshot(),
                reference.snapshot(),
                "seed {seed} round {round}: {batch:?}"
            );
        }
        deltas_saved += reference.local_tip() - grouped.local_tip();
        let peer = replay_on_a_peer(&remote, &grouped);
        assert_eq!(
            native_store::load_state(&peer, &group()).unwrap(),
            grouped.state(),
            "seed {seed}: a peer admitting the grouped deltas holds the author's state"
        );
    }
    assert!(deltas_saved > 0, "the batches were grouped into fewer deltas");
}

/// A lone mutation (a live edit) is signed exactly as one delta, the same
/// bytes the one-delta-per-mutation commit signs.
#[test]
fn a_single_mutation_signs_the_same_delta_as_before() {
    let (grouped, reference) = (Side::new(), Side::new());
    for specs in [
        vec![Spec::Put { path: "x".into(), salt: 5 }],
        vec![Spec::Put { path: "x".into(), salt: 6 }],
        vec![Spec::Delete { path: "x".into() }],
    ] {
        grouped.commit_grouped(&specs).unwrap();
        reference.commit_one_by_one(&specs).unwrap();
    }
    assert_eq!(grouped.local_tip(), 3);
    for seq in 1..=3 {
        assert_eq!(
            grouped.local_delta(seq).to_wire_bytes(),
            reference.local_delta(seq).to_wire_bytes(),
            "delta {seq}"
        );
    }
}

/// Runs that overlap are cut so each run is a complete edit set that depends
/// on no later one: a peer admitting a prefix of the author's deltas holds
/// exactly what the author held after the corresponding mutations.
#[test]
fn a_peer_admitting_a_prefix_of_the_runs_sees_a_consistent_state() {
    let batch = vec![
        Spec::Put { path: "a".into(), salt: 1 },
        Spec::Put { path: "b".into(), salt: 2 },
        Spec::Put { path: "a".into(), salt: 3 },
        Spec::Delete { path: "b".into() },
        Spec::Put { path: "c".into(), salt: 4 },
        Spec::Put { path: "c/x".into(), salt: 5 },
        Spec::Put { path: "d".into(), salt: 6 },
    ];
    let grouped = Side::new();
    grouped.commit_grouped(&batch).unwrap();
    // The runs the commit cut, from the mutations it was handed.
    let mutations = grouped.prepare_all(&batch);
    let items: Vec<BulkOp<'_>> =
        mutations.iter().map(|m| BulkOp { op: m.op(), witness: None }).collect();
    let runs = bulk_groups(&items);
    assert_eq!(
        runs,
        vec![0..2, 2..5, 5..7],
        "overlapping paths and a path under another start new runs"
    );
    assert_eq!(grouped.local_tip(), runs.len() as u64);

    let reference = Side::new();
    let peer = Connection::open_in_memory().unwrap();
    crate::replica_tables::init(&peer).unwrap();
    for (n, run) in runs.iter().enumerate() {
        reference.commit_one_by_one(&batch[run.clone()]).unwrap();
        native_store::install_verified_delta(
            &peer,
            &group(),
            &grouped.local_delta(n as u64 + 1),
            &local_key().verifying_key(),
        )
        .unwrap();
        let mut peer_heads: Vec<(String, Vec<u8>)> = Snapshot::of(&peer).heads;
        peer_heads.sort();
        assert_eq!(
            peer_heads,
            reference.snapshot().heads,
            "after admitting {} of {} runs",
            n + 1,
            runs.len()
        );
    }
}

/// A stale mutation inside a run refuses the whole batch and writes nothing,
/// as when each mutation was its own delta in the same transaction.
#[test]
fn a_stale_mutation_in_a_run_refuses_the_whole_batch() {
    let side = Side::new();
    side.commit_grouped(&[Spec::Put { path: "p".into(), salt: 1 }]).unwrap();
    // Captured now, then the row moves on before the batch commits.
    let stale = side.prepare(&Spec::Put { path: "p".into(), salt: 2 }, true);
    side.commit_grouped(&[Spec::Put { path: "p".into(), salt: 3 }]).unwrap();
    let before = (side.snapshot(), side.local_tip());
    let fresh = side.prepare(&Spec::Put { path: "q".into(), salt: 4 }, true);

    let key = local_key();
    let local = LocalAuthor { author: author_id("device-a"), signing_key: &key, capture: None };
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    let error = side
        .repo
        .commit_local_mutations_batch(
            "g1",
            &[fresh, stale],
            &[],
            "device-a",
            SignedEmissionContext { author: &local, permit: &permit },
        )
        .unwrap_err();
    assert!(matches!(error, SyncSqliteError::LocalWriteCaptureStale { .. }), "{error:?}");
    assert_eq!((side.snapshot(), side.local_tip()), before, "nothing of the batch was written");
}

fn put_run(n: usize) -> Vec<Spec> {
    (0..n).map(|i| Spec::Put { path: format!("dir/file-{i:06}"), salt: i as i64 + 1 }).collect()
}

/// A full run is one delta of `BULK_DELTA_MAX_OPS` ops that round-trips its
/// encoding, verifies, and admits on a second replica to the author's state.
#[test]
fn a_full_bulk_delta_round_trips_and_admits_on_a_peer() {
    let side = Side::new();
    side.commit_grouped(&put_run(BULK_DELTA_MAX_OPS)).unwrap();
    assert_eq!(side.local_tip(), 1, "one delta for the whole run");
    let delta = side.local_delta(1);
    assert_eq!(delta.ops.len(), BULK_DELTA_MAX_OPS);
    let bytes = delta.to_wire_bytes();
    assert_eq!(NativeDelta::from_wire_bytes(&bytes).unwrap(), delta);
    assert!(delta.verify_signature(&local_key().verifying_key()).is_ok());
    assert!(
        bytes.len() <= crate::native_authoring::BULK_DELTA_MAX_BYTES,
        "{} bytes for {} ops",
        bytes.len(),
        delta.ops.len()
    );
    let peer = replay_on_a_peer(&Remote::new(), &side);
    assert_eq!(native_store::load_state(&peer, &group()).unwrap(), side.state());
}

/// More mutations than one delta carries are signed as several deltas.
#[test]
fn a_batch_larger_than_a_run_is_signed_as_several_deltas() {
    let side = Side::new();
    side.commit_grouped(&put_run(BULK_DELTA_MAX_OPS + 5)).unwrap();
    assert_eq!(side.local_tip(), 2);
    assert_eq!(side.local_delta(1).ops.len(), BULK_DELTA_MAX_OPS);
    assert_eq!(side.local_delta(2).ops.len(), 5);
}

/// Paths long enough that a run would exceed the byte budget are signed as
/// more deltas, each within it, and a peer still ends in the author's state.
#[test]
fn long_paths_split_a_run_by_bytes() {
    let side = Side::new();
    let long = "x".repeat(200);
    let specs: Vec<Spec> = (0..1000)
        .map(|i| Spec::Put { path: format!("f-{i:05}/{long}/{long}/{long}/{long}"), salt: i + 1 })
        .collect();
    side.commit_grouped(&specs).unwrap();
    let tip = side.local_tip();
    assert!(tip > 1, "{tip}");
    for seq in 1..=tip {
        let bytes = side.local_delta(seq).to_wire_bytes().len();
        assert!(bytes <= 2 * crate::native_authoring::BULK_DELTA_MAX_BYTES, "{bytes}");
    }
    let peer = replay_on_a_peer(&Remote::new(), &side);
    assert_eq!(native_store::load_state(&peer, &group()).unwrap(), side.state());
}

fn mutation_at(path: &str, op: Op) -> PreparedLocalMutation {
    PreparedLocalMutation::Delete {
        record: FileRecord {
            path: path.into(),
            size: 0,
            mtime_unix_nanos: 1,
            blocks: Vec::new(),
            deleted: true,
        },
        op,
        native_witness: None,
    }
}

/// How consecutive mutations are cut into runs.
#[test]
fn runs_split_where_paths_interact() {
    let put = |p: &str| Op::Put { path: SyncPath(p.into()), version: VersionHash([1; 32]) };
    let mv = |from: &str, to: &str| Op::Move {
        from: SyncPath(from.into()),
        to: SyncPath(to.into()),
        version: VersionHash([1; 32]),
    };
    let runs = |cases: Vec<(&str, Op)>| {
        let mutations: Vec<_> = cases.into_iter().map(|(row, op)| mutation_at(row, op)).collect();
        let items: Vec<BulkOp<'_>> =
            mutations.iter().map(|m| BulkOp { op: m.op(), witness: None }).collect();
        bulk_groups(&items)
    };
    assert_eq!(runs(vec![("a", put("a")), ("b", put("b")), ("c", put("c"))]), vec![0..3]);
    assert_eq!(runs(vec![("a", put("a")), ("a", put("a"))]), vec![0..1, 1..2]);
    assert_eq!(runs(vec![("d", put("d")), ("d/x", put("d/x"))]), vec![0..1, 1..2]);
    assert_eq!(runs(vec![("d/x", put("d/x")), ("d", put("d"))]), vec![0..1, 1..2]);
    assert_eq!(runs(vec![("d/x", put("d/x")), ("dd", put("dd"))]), vec![0..2]);
    // A move touches both its ends.
    assert_eq!(runs(vec![("t", mv("f", "t")), ("f", put("f")), ("z", put("z"))]), vec![0..1, 1..3]);
}

/// No run is longer than one delta carries.
#[test]
fn runs_are_capped_at_the_delta_op_bound() {
    let mutations: Vec<_> = (0..2 * BULK_DELTA_MAX_OPS + 1)
        .map(|i| {
            let p = format!("f{i}");
            let op = Op::Put { path: SyncPath(p.clone()), version: VersionHash([1; 32]) };
            mutation_at(&p, op)
        })
        .collect();
    let items: Vec<BulkOp<'_>> =
        mutations.iter().map(|m| BulkOp { op: m.op(), witness: None }).collect();
    let lens: Vec<usize> = bulk_groups(&items).iter().map(|r| r.len()).collect();
    assert_eq!(lens, vec![BULK_DELTA_MAX_OPS, BULK_DELTA_MAX_OPS, 1]);
}

/// The set-based current-row read answers exactly what one read per path answers: live rows,
/// tombstones, absent paths, and more paths than one statement binds.
#[test]
fn the_set_based_current_row_read_matches_one_read_per_path() {
    let side = Side::new();
    let mut specs = put_run(700);
    specs.push(Spec::Delete { path: "dir/file-000003".into() });
    specs.push(Spec::Delete { path: "dir/file-000650".into() });
    side.commit_grouped(&specs).unwrap();
    let mut paths: Vec<String> = (0..700).map(|i| format!("dir/file-{i:06}")).collect();
    paths.extend(["absent".to_owned(), "dir".to_owned(), "dir/file-999999".to_owned()]);
    let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
    side.db
        .write_immediate::<_, SyncSqliteError>(|tx| {
            let set = crate::store::read_canonical_current_rows(tx, "g1", &refs)?;
            let mut present = 0;
            for path in &refs {
                let one = crate::store::read_canonical_current_row(tx, "g1", path)?;
                assert_eq!(
                    set.get(*path).map(|r| (r.snapshot.clone(), r.version_hash())),
                    one.as_ref().map(|r| (r.snapshot.clone(), r.version_hash())),
                    "{path}"
                );
                assert_eq!(
                    set.get(*path).map(|r| (&r.origin_device_id, r.symlink_out_of_root)),
                    one.as_ref().map(|r| (&r.origin_device_id, r.symlink_out_of_root)),
                    "{path}"
                );
                present += usize::from(one.is_some());
            }
            assert_eq!(present, 700);
            assert_eq!(set.len(), 700);
            Ok(())
        })
        .unwrap();
}

/// The heads read for a set of paths in few statements are the heads one read per path builds:
/// paths with one head, with concurrent heads, with none, and more paths than one statement binds.
#[test]
fn the_set_based_heads_read_matches_one_read_per_path() {
    let side = Side::new();
    side.commit_grouped(&put_run(700)).unwrap();
    let mut remote = Remote::new();
    for i in [0usize, 5, 499, 500, 650] {
        side.install_remote(&remote.put(&format!("dir/file-{i:06}"), 200 + i as u8 % 50));
    }
    let mut owned: Vec<SyncPath> = (0..700).map(|i| SyncPath(format!("dir/file-{i:06}"))).collect();
    owned.extend(["absent", "dir"].map(|p| SyncPath(p.to_owned())));
    owned.push(owned[5].clone());
    let paths: Vec<&SyncPath> = owned.iter().collect();
    side.db
        .write_immediate::<_, SyncSqliteError>(|tx| {
            let set = native_store::load_heads_at_paths(tx, &group(), &paths)?;
            let mut reference = yadorilink_replica_domain::native_state::NativeState::new();
            for path in &paths {
                for head in native_store::native_heads_at(tx, &group(), path)? {
                    reference
                        .heads
                        .entry((*path).clone())
                        .or_default()
                        .insert(head.dot, head.payload);
                }
            }
            assert_eq!(set, reference);
            assert_eq!(set.heads.len(), 700);
            assert_eq!(set.heads[&SyncPath("dir/file-000500".into())].len(), 2);
            Ok(())
        })
        .unwrap();
}

/// Storing a content version re-arms the paths whose heads name it, once, and only when the
/// version is new: a version already stored, or repeated inside one group, arms nothing more.
/// The grouped commit and the one-by-one reference leave the same obligations and versions.
#[test]
fn only_a_newly_stored_version_rearms_the_paths_naming_it() {
    let (grouped, reference) = (Side::new(), Side::new());
    let version_of = |salt: i64| match grouped.prepare(&Spec::Put { path: "x".into(), salt }, false)
    {
        PreparedLocalMutation::Upsert { version, .. } => version.version_hash,
        _ => unreachable!(),
    };
    let mut remote = Remote::new();
    // Heads at `y` and `z` name content nobody stored yet, and `w` names content stored below.
    for (path, salt) in [("y", 5), ("z", 6), ("w", 7)] {
        let delta = remote.put_version(path, version_of(salt));
        grouped.install_remote(&delta);
        reference.install_remote(&delta);
    }
    let batches = [
        // Version 5 is new and repeated inside the group; version 7 is new.
        vec![
            Spec::Put { path: "a".into(), salt: 5 },
            Spec::Put { path: "b".into(), salt: 5 },
            Spec::Put { path: "c".into(), salt: 7 },
        ],
        // Versions 5 and 7 are stored by now: nothing re-arms. Version 6 is new.
        vec![
            Spec::Put { path: "d".into(), salt: 5 },
            Spec::Put { path: "e".into(), salt: 6 },
            Spec::Put { path: "f".into(), salt: 7 },
        ],
    ];
    for batch in &batches {
        grouped.commit_grouped(batch).unwrap();
        reference.commit_one_by_one(batch).unwrap();
        assert_eq!(grouped.snapshot(), reference.snapshot(), "{batch:?}");
    }
    let obligations = grouped.snapshot().obligations;
    let generation = |path: &str| {
        obligations.iter().find(|o| o.0 == path).map(|o| o.1).expect("an obligation at the path")
    };
    for path in ["a", "b", "c", "d", "e", "f"] {
        let origin = obligations.iter().find(|o| o.0 == path).map(|o| o.3.as_str());
        assert_eq!(origin, Some("local"), "{path} was authored here");
    }
    assert_eq!(
        (generation("y"), generation("z"), generation("w")),
        (1, 1, 1),
        "each path naming a new version was armed once"
    );
}

/// A capture that passed its pause check before a pause landed must still be
/// refused at the commit: the commit is the only point that sees the pause
/// and the authoring atomically. Pausing between prepare and commit is
/// exactly that window, forced here without any timing.
#[test]
fn a_capture_prepared_before_a_pause_is_not_authored_after_it() {
    let side = Side::new();
    side.commit_grouped(&[Spec::Put { path: "dir/a".into(), salt: 1 }]).unwrap();
    let tip_before = side.local_tip();

    let mutations = side.prepare_all(&[
        Spec::Put { path: "dir/a".into(), salt: 2 },
        Spec::Put { path: "outside".into(), salt: 3 },
    ]);
    crate::paused_items::PausedItemRepository::new(side.db.clone()).pause("g1", "dir").unwrap();

    let key = local_key();
    let local = LocalAuthor { author: author_id("device-a"), signing_key: &key, capture: None };
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    let result = side.repo.commit_local_mutations_batch(
        "g1",
        &mutations,
        &[],
        "device-a",
        SignedEmissionContext { author: &local, permit: &permit },
    );
    assert!(
        matches!(result, Err(SyncSqliteError::PathPaused { .. })),
        "a mutation under a paused item must be refused at the commit: {result:?}"
    );
    assert_eq!(side.local_tip(), tip_before, "nothing was authored, not even the unpaused path");
}

impl Side {
    fn commit_recursive(
        &self,
        kind: RecursiveOperationKind,
        specs: &[Spec],
    ) -> Result<(), SyncSqliteError> {
        let key = local_key();
        let local = LocalAuthor { author: author_id("device-a"), signing_key: &key, capture: None };
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        self.repo.commit_recursive_operation(
            "g1",
            kind,
            &self.prepare_all(specs),
            &[],
            "device-a",
            SignedEmissionContext { author: &local, permit: &permit },
        )
    }
}

fn rm_tree(root: &str) -> RecursiveOperationKind {
    RecursiveOperationKind::RmTree { root: SyncPath(root.into()) }
}

fn rename_tree(from: &str, to: &str) -> RecursiveOperationKind {
    RecursiveOperationKind::RenameTree { from: SyncPath(from.into()), to: SyncPath(to.into()) }
}

fn assert_recursive_refused_when_paused(
    kind: impl Fn() -> RecursiveOperationKind,
    specs: &[Spec],
    paused: &str,
) {
    let side = Side::new();
    side.commit_grouped(&[
        Spec::Put { path: "dir/a".into(), salt: 1 },
        Spec::Put { path: "dir/b".into(), salt: 2 },
    ])
    .unwrap();
    let tip_before = side.local_tip();
    crate::paused_items::PausedItemRepository::new(side.db.clone()).pause("g1", paused).unwrap();

    let result = side.commit_recursive(kind(), specs);
    assert!(
        matches!(result, Err(SyncSqliteError::PathPaused { .. })),
        "a recursive operation touching paused {paused:?} must be refused: {result:?}"
    );
    assert_eq!(side.local_tip(), tip_before, "nothing was authored");
}

/// A recursive delete whose subtree is paused authors nothing.
#[test]
fn a_recursive_delete_of_a_paused_subtree_is_refused_at_the_commit() {
    assert_recursive_refused_when_paused(
        || rm_tree("dir"),
        &[Spec::Delete { path: "dir/a".into() }, Spec::Delete { path: "dir/b".into() }],
        "dir",
    );
}

/// One paused entry under the deleted root refuses the whole operation.
#[test]
fn a_recursive_delete_touching_one_paused_entry_is_refused_whole() {
    assert_recursive_refused_when_paused(
        || rm_tree("dir"),
        &[Spec::Delete { path: "dir/a".into() }, Spec::Delete { path: "dir/b".into() }],
        "dir/b",
    );
}

/// A rename out of a paused subtree is refused: its deletes cover paused paths.
#[test]
fn a_rename_out_of_a_paused_subtree_is_refused_at_the_commit() {
    assert_recursive_refused_when_paused(
        || rename_tree("dir", "moved"),
        &[
            Spec::Delete { path: "dir/a".into() },
            Spec::Delete { path: "dir/b".into() },
            Spec::Put { path: "moved/a".into(), salt: 5 },
            Spec::Put { path: "moved/b".into(), salt: 6 },
        ],
        "dir",
    );
}

/// A rename into a paused subtree is refused: its puts land on paused paths.
#[test]
fn a_rename_into_a_paused_subtree_is_refused_at_the_commit() {
    assert_recursive_refused_when_paused(
        || rename_tree("dir", "frozen/dir"),
        &[
            Spec::Delete { path: "dir/a".into() },
            Spec::Delete { path: "dir/b".into() },
            Spec::Put { path: "frozen/dir/a".into(), salt: 5 },
            Spec::Put { path: "frozen/dir/b".into(), salt: 6 },
        ],
        "frozen",
    );
}

/// The same operations commit when nothing is paused, so the refusals above
/// are the pause's and not an artefact of the fixture.
#[test]
fn the_same_recursive_operations_commit_when_nothing_is_paused() {
    let side = Side::new();
    side.commit_grouped(&[
        Spec::Put { path: "dir/a".into(), salt: 1 },
        Spec::Put { path: "dir/b".into(), salt: 2 },
    ])
    .unwrap();
    side.commit_recursive(
        rename_tree("dir", "moved"),
        &[
            Spec::Delete { path: "dir/a".into() },
            Spec::Delete { path: "dir/b".into() },
            Spec::Put { path: "moved/a".into(), salt: 5 },
            Spec::Put { path: "moved/b".into(), salt: 6 },
        ],
    )
    .unwrap();
    side.commit_recursive(
        rm_tree("moved"),
        &[Spec::Delete { path: "moved/a".into() }, Spec::Delete { path: "moved/b".into() }],
    )
    .unwrap();
}
