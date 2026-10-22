//! Brand-new paths are written as finished rows in one insert. These tests pin that the shortcut
//! changes nothing but the statements it saves: over random batches mixing new paths with
//! existing, tombstoned, scaffold, remotely-headed and nested paths, a commit that uses it leaves
//! every column of every table what the per-path chain leaves (the same group commit with the
//! shortcut off), and the same state the one-delta-per-mutation commit leaves; and that a path
//! anything already names is never taken by the shortcut.

use std::collections::BTreeMap;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use tempfile::TempDir;

use yadorilink_fs_platform::fs_identity::FileIdentity;
use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::file::{FileMeta, FileRecord, FileVersion, RecordKind};
use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, FolderGroupId, SyncPath, VersionHash};
use yadorilink_replica_domain::local_op::Op;
use yadorilink_replica_domain::native_state::DeltaHash;
use yadorilink_replica_domain::session_state::{LocalFileMetaColumns, PreparedLocalMutation};
use yadorilink_replica_domain::signed_delta::{DeltaOp, DeltaPut, NativeDelta};
use yadorilink_sqlite_runtime::SyncDatabase;

use crate::error::SyncSqliteError;
use crate::file_index::{
    commit_local_mutation_group_in_tx, FileIndexRepository, LocalCaptureActualStateEvidence,
    SignedEmissionContext,
};
use crate::local_author::LocalAuthor;
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

/// How a side commits a batch.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    /// The production grouped commit.
    Grouped,
    /// The grouped commit with the new-path shortcut off: every path takes the per-path chain.
    GroupedPerPath,
    /// The grouped commit with the rows written finished but each proof and close per path.
    GroupedRowsOnly,
    /// One delta per mutation, the reference the grouped commit is defined by.
    OneByOne,
}

/// The `Present` evidence every put carries: identities observed once from real files, so each
/// side commits byte-identical evidence.
struct Evidence {
    _dir: TempDir,
    identities: Vec<FileIdentity>,
}

impl Evidence {
    fn new(count: usize) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let identities = (0..count)
            .map(|i| {
                let path = dir.path().join(format!("f{i}"));
                std::fs::write(&path, format!("content {i}")).unwrap();
                FileIdentity::observe_path(&path).unwrap()
            })
            .collect();
        Self { _dir: dir, identities }
    }

    fn for_spec(&self, spec: &Spec, ordinal: usize) -> LocalCaptureActualStateEvidence {
        match spec {
            Spec::Put { .. } => LocalCaptureActualStateEvidence::Present {
                filesystem_identity: self.identities[ordinal % self.identities.len()],
            },
            Spec::Delete { .. } => LocalCaptureActualStateEvidence::Absent,
        }
    }
}

struct Side {
    db: Arc<SyncDatabase>,
    repo: FileIndexRepository,
    mode: Mode,
}

impl Side {
    fn new(mode: Mode) -> Self {
        let db = crate::replica_tables::open_for_tests();
        Self { repo: FileIndexRepository::new(db.clone()), db, mode }
    }

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
        // A path a batch acts on again carries no witness for its later mutations, and so does
        // every fourth first mutation (a capture that recorded none).
        let mut seen = std::collections::BTreeSet::new();
        specs
            .iter()
            .map(|spec| {
                let first = seen.insert(spec.path().to_owned());
                let recorded = !matches!(spec, Spec::Put { salt, .. } if salt % 4 == 0);
                self.prepare(spec, first && recorded)
            })
            .collect()
    }

    /// Commits `specs`, capturing them first and admitting `interference` (a remote head the
    /// capture never saw) between the capture and the commit.
    fn commit(
        &self,
        specs: &[Spec],
        evidence: &Evidence,
        interference: Option<&RemoteDelta>,
    ) -> Result<(), SyncSqliteError> {
        let key = local_key();
        let local = LocalAuthor { author: author_id("device-a"), signing_key: &key, capture: None };
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        let mutations = self.prepare_all(specs);
        if let Some(remote) = interference {
            self.install_remote(&remote.delta, remote.salt);
        }
        let evidence: Vec<Option<LocalCaptureActualStateEvidence>> =
            specs.iter().enumerate().map(|(i, s)| Some(evidence.for_spec(s, i))).collect();
        match self.mode {
            Mode::Grouped => self.repo.commit_local_mutations_batch(
                "g1",
                &mutations,
                &evidence,
                "device-a",
                SignedEmissionContext { author: &local, permit: &permit },
            ),
            Mode::GroupedPerPath => crate::new_path_rows::tests_support::without(|| {
                self.repo.commit_local_mutations_batch(
                    "g1",
                    &mutations,
                    &evidence,
                    "device-a",
                    SignedEmissionContext { author: &local, permit: &permit },
                )
            }),
            Mode::GroupedRowsOnly => {
                crate::new_path_rows::tests_support::without_settlement(|| {
                    self.repo.commit_local_mutations_batch(
                        "g1",
                        &mutations,
                        &evidence,
                        "device-a",
                        SignedEmissionContext { author: &local, permit: &permit },
                    )
                })
            }
            Mode::OneByOne => self.db.write_immediate::<_, SyncSqliteError>(|tx| {
                for (mutation, evidence) in mutations.iter().zip(&evidence) {
                    crate::file_index::commit_local_mutation_reference_in_tx(
                        tx,
                        "g1",
                        mutation,
                        evidence.as_ref(),
                        "device-a",
                        &local,
                    )?;
                }
                Ok(())
            }),
        }
    }

    /// One group commit of `specs` (which must touch pairwise unrelated paths), called directly so
    /// no batch-level hold refusal stands in front of it.
    fn commit_group_directly(
        &self,
        specs: &[Spec],
        evidence: &Evidence,
    ) -> Result<(), SyncSqliteError> {
        self.commit_group_directly_after(specs, evidence, None)
    }

    /// [`Self::commit_group_directly`] with `interference` (a remote head the capture never saw)
    /// admitted between the capture and the commit.
    fn commit_group_directly_after(
        &self,
        specs: &[Spec],
        evidence: &Evidence,
        interference: Option<&RemoteDelta>,
    ) -> Result<(), SyncSqliteError> {
        let key = local_key();
        let local = LocalAuthor { author: author_id("device-a"), signing_key: &key, capture: None };
        let mutations = self.prepare_all(specs);
        if let Some(remote) = interference {
            self.install_remote(&remote.delta, remote.salt);
        }
        let evidence: Vec<LocalCaptureActualStateEvidence> =
            specs.iter().enumerate().map(|(i, s)| evidence.for_spec(s, i)).collect();
        let evidence: Vec<Option<&LocalCaptureActualStateEvidence>> =
            evidence.iter().map(Some).collect();
        let run = |tx: &rusqlite::Transaction| {
            commit_local_mutation_group_in_tx(tx, "g1", &mutations, &evidence, "device-a", &local)
        };
        let write = || self.db.write_immediate::<_, SyncSqliteError>(run);
        if self.mode == Mode::GroupedPerPath {
            crate::new_path_rows::tests_support::without(write)
        } else {
            write()
        }
    }

    fn scaffold(&self, path: &str) {
        self.db
            .write_immediate::<_, SyncSqliteError>(|tx| {
                crate::file_index::ensure_bootstrap_row_for_metadata_in_tx(tx, "g1", path)
            })
            .unwrap();
    }

    fn hold(&self, path: &str) {
        self.db
            .write_immediate::<_, SyncSqliteError>(|tx| {
                crate::held_path::hold_in_tx(tx, "g1", path, 7)
            })
            .unwrap();
    }

    fn install_remote(&self, delta: &NativeDelta, salt: u8) {
        self.db
            .write_immediate::<_, SyncSqliteError>(|tx| {
                crate::dag_store::put_file_version(tx, "g1", &remote_version(salt))?;
                native_store::install_verified_delta(
                    tx,
                    &group(),
                    delta,
                    &remote_key().verifying_key(),
                )?;
                // Admission arms the paths.
                crate::native_desired_state::arm_projection_for_delta(tx, "g1", delta, false)
                    .map(|_| ())
            })
            .unwrap();
    }
}

/// The content a remote put at `path` carries, stored on every replica that admits it so the path
/// resolves.
fn remote_version(salt: u8) -> FileVersion {
    FileVersion::new(
        Vec::new(),
        0,
        FileMeta {
            mtime_unix_nanos: 10_000 + i64::from(salt),
            unix_mode: Some(0o600),
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

fn remote_put(seq: u64, prev: Option<DeltaHash>, path: &str, salt: u8) -> NativeDelta {
    let mut delta = NativeDelta {
        recursive_part: None,
        group_id: group(),
        author: author_id("device-b"),
        seq: AuthorSeq(seq),
        prev,
        ops: vec![DeltaOp {
            path: SyncPath(path.into()),
            removes: Vec::new(),
            put: Some(DeltaPut { version: remote_version(salt).version_hash }),
        }],
        signature: [0u8; 64],
    };
    delta.sign(&remote_key());
    delta
}

/// A remote delta and the salt of the content it puts.
struct RemoteDelta {
    delta: NativeDelta,
    salt: u8,
}

/// A remote author's chain of deltas, each putting content at a path beside whatever the local
/// replica holds there.
struct RemoteChain {
    seq: u64,
    prev: Option<DeltaHash>,
}

impl RemoteChain {
    fn new() -> Self {
        Self { seq: 1, prev: None }
    }

    fn put(&mut self, path: &str, salt: u8) -> RemoteDelta {
        let delta = remote_put(self.seq, self.prev, path, salt);
        self.prev = Some(delta.delta_hash());
        self.seq += 1;
        RemoteDelta { delta, salt }
    }
}

/// The columns whose value is the clock or a random identifier, which no two commits share.
const VOLATILE_COLUMNS: [&str; 8] = [
    "admitted_at_unix_nanos",
    "last_mutation_at",
    "generation_id",
    "updated_at_unix_nanos",
    "created_at",
    "updated_at",
    "next_attempt_at",
    "held_at_unix_nanos",
];

/// Change detectors that move on every row write (the root-set counter, and the state token the
/// native heads' triggers draw at random), so differ by construction: the shortcut writes each new
/// row once instead of three times.
const WRITE_COUNTING_TABLES: [&str; 2] = ["file_root_set_generation", "native_state_generation"];

/// Every column of every table, minus the volatile ones, sorted.
fn dump_all(conn: &Connection, skip_columns: &[&str]) -> BTreeMap<String, Vec<Vec<String>>> {
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let mut out = BTreeMap::new();
    for table in tables {
        if WRITE_COUNTING_TABLES.contains(&table.as_str()) {
            continue;
        }
        let columns: Vec<String> = conn
            .prepare(&format!("PRAGMA table_info(\"{table}\")"))
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .map(Result::unwrap)
            .filter(|c| {
                !VOLATILE_COLUMNS.contains(&c.as_str()) && !skip_columns.contains(&c.as_str())
            })
            .collect();
        if columns.is_empty() {
            continue;
        }
        let list = columns.iter().map(|c| format!("\"{c}\"")).collect::<Vec<_>>().join(", ");
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {list} FROM \"{table}\" ORDER BY {}",
                (1..=columns.len()).map(|i| i.to_string()).collect::<Vec<_>>().join(", ")
            ))
            .unwrap();
        let rows: Vec<Vec<String>> = stmt
            .query_map([], |r| {
                (0..columns.len())
                    .map(|i| r.get::<_, rusqlite::types::Value>(i).map(|v| format!("{v:?}")))
                    .collect()
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        out.insert(table, rows);
    }
    out
}

/// What the one-delta-per-mutation commit and the grouped commit agree on: everything that does
/// not name the dot or provenance a head was signed under, which depend on how many deltas the
/// edits were signed in.
const IDENTITY_COLUMNS: [&str; 10] = [
    "obligation_incarnation",
    "native_authoring_identity",
    "identity",
    "provenance",
    "reflected_heads",
    "seq",
    "prev",
    "tip",
    "signature",
    "body",
];

/// The tables whose rows are the delta log itself, which differs by construction between a
/// grouped and a one-by-one commit.
const DELTA_LOG_TABLES: [&str; 6] = [
    // Which of two concurrent heads a copy name is chosen for follows the ranks, which a grouped
    // delta draws once and one-by-one deltas draw each.
    "native_physical_placement",
    "native_stable_projection_binding",
    "native_author_frontier",
    "native_delta_bodies",
    "native_delta_log",
    "projection_obligation_incarnations",
];

fn semantic(dump: BTreeMap<String, Vec<Vec<String>>>) -> BTreeMap<String, Vec<Vec<String>>> {
    dump.into_iter().filter(|(table, _)| !DELTA_LOG_TABLES.contains(&table.as_str())).collect()
}

/// Asserts two dumps are equal, naming the tables that differ and a few of their differing rows.
fn assert_same(
    left: &BTreeMap<String, Vec<Vec<String>>>,
    right: &BTreeMap<String, Vec<Vec<String>>>,
    context: &str,
) {
    let mut report = String::new();
    for table in left.keys().chain(right.keys()).collect::<std::collections::BTreeSet<_>>() {
        let (l, r) = (left.get(table), right.get(table));
        if l == r {
            continue;
        }
        let (l, r) = (l.cloned().unwrap_or_default(), r.cloned().unwrap_or_default());
        let short = |row: &Vec<String>| {
            let text = row.join(" | ");
            text.chars().take(240).collect::<String>()
        };
        report.push_str(&format!("table {table}: {} rows vs {} rows\n", l.len(), r.len()));
        for row in l.iter().filter(|row| !r.contains(row)).take(3) {
            report.push_str(&format!("  only left: {}\n", short(row)));
        }
        for row in r.iter().filter(|row| !l.contains(row)).take(3) {
            report.push_str(&format!("  only right: {}\n", short(row)));
        }
    }
    assert!(report.is_empty(), "{context}\n{report}");
}

struct Rng(u64);

impl Rng {
    fn next(&mut self, bound: u64) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (self.0 >> 33) % bound
    }
}

/// Paths a batch draws from, by what the replica holds there before the batch.
struct Pool {
    new: Vec<String>,
    existing: Vec<String>,
    tombstoned: Vec<String>,
    scaffold: Vec<String>,
    remote: Vec<String>,
    /// A path that is the directory of an existing one.
    parent_of_existing: String,
    /// New paths under an existing file, which the new directory displaces.
    under_a_file: Vec<String>,
    /// Paths with no `files` row and no head that are held.
    held: Vec<String>,
}

fn pool() -> Pool {
    let names = |prefix: &str, n: usize| (0..n).map(|i| format!("{prefix}/f{i}")).collect();
    Pool {
        new: names("new", 24),
        existing: names("old", 4),
        tombstoned: names("gone", 3),
        scaffold: names("scaf", 3),
        remote: names("rem", 3),
        parent_of_existing: "nest".to_owned(),
        under_a_file: (0..3).map(|i| format!("anc/x{i}")).collect(),
        held: vec!["held/h0".to_owned(), "held/h1".to_owned()],
    }
}

/// The remote deltas every starting replica admits: one head at each remotely-headed path and a
/// head beside a local one at `col/f`.
fn seed_deltas(pool: &Pool, chain: &mut RemoteChain) -> Vec<RemoteDelta> {
    let mut deltas: Vec<RemoteDelta> =
        pool.remote.iter().enumerate().map(|(i, path)| chain.put(path, 200 + i as u8)).collect();
    deltas.push(chain.put("col/f", 230));
    deltas
}

/// Builds the same starting replica on `side`: existing rows, tombstones, scaffold rows, remote
/// heads, a nested path, a file with new paths to come below it and a contested path, all
/// committed the way `side` commits.
fn seed_state(side: &Side, pool: &Pool, evidence: &Evidence, deltas: &[RemoteDelta]) {
    let mut specs: Vec<Spec> = pool
        .existing
        .iter()
        .map(|path| Spec::Put { path: path.clone(), salt: 1 })
        .chain(pool.tombstoned.iter().map(|path| Spec::Put { path: path.clone(), salt: 2 }))
        .collect();
    specs.push(Spec::Put { path: format!("{}/child", pool.parent_of_existing), salt: 3 });
    specs.push(Spec::Put { path: "anc".into(), salt: 4 });
    specs.push(Spec::Put { path: "col/f".into(), salt: 5 });
    side.commit(&specs, evidence, None).unwrap();
    let deletes: Vec<Spec> =
        pool.tombstoned.iter().map(|path| Spec::Delete { path: path.clone() }).collect();
    side.commit(&deletes, evidence, None).unwrap();
    for path in &pool.scaffold {
        side.scaffold(path);
    }
    for remote in deltas {
        side.install_remote(&remote.delta, remote.salt);
    }
    for path in ["held/h0", "held/h1"] {
        side.hold(path);
    }
}

fn random_batch(rng: &mut Rng, pool: &Pool, salt: &mut i64) -> Vec<Spec> {
    let all: Vec<&String> = pool
        .new
        .iter()
        .chain(&pool.new)
        .chain(&pool.existing)
        .chain(&pool.tombstoned)
        .chain(&pool.scaffold)
        .chain(&pool.remote)
        .chain(&pool.under_a_file)
        .collect();
    let len = 4 + rng.next(30) as usize;
    let mut batch: Vec<Spec> = (0..len)
        .map(|_| {
            *salt += 1;
            let path = if rng.next(12) == 0 {
                pool.parent_of_existing.clone()
            } else {
                all[rng.next(all.len() as u64) as usize].clone()
            };
            if rng.next(8) == 0 {
                Spec::Delete { path }
            } else {
                Spec::Put { path, salt: *salt }
            }
        })
        .collect();
    // A held path refuses the whole batch, so only some batches carry one.
    if rng.next(6) == 0 {
        *salt += 1;
        let path = pool.held[rng.next(pool.held.len() as u64) as usize].clone();
        batch.push(Spec::Put { path, salt: *salt });
    }
    batch
}

/// For random batches, the commit that uses the new-path shortcut leaves every column of every
/// table what the per-path chain leaves over the same grouped authoring, and the same state, minus
/// the identities that depend on how the edits were signed, as the one-delta-per-mutation commit.
#[test]
fn new_path_rows_mean_what_the_per_path_chain_means() {
    let mut interferences = 0usize;
    let pool = pool();
    let evidence = Evidence::new(7);
    for seed in 0..24u64 {
        let mut rng = Rng(seed + 1);
        let (subject, per_path, reference, rows_only) = (
            Side::new(Mode::Grouped),
            Side::new(Mode::GroupedPerPath),
            Side::new(Mode::OneByOne),
            Side::new(Mode::GroupedRowsOnly),
        );
        let mut chain = RemoteChain::new();
        let deltas = seed_deltas(&pool, &mut chain);
        for side in [&subject, &per_path, &reference, &rows_only] {
            seed_state(side, &pool, &evidence, &deltas);
        }
        let mut salt = 100i64;
        let mut interfered = std::collections::BTreeSet::new();
        for round in 0..3 {
            let batch = random_batch(&mut rng, &pool, &mut salt);
            // Sometimes a remote head lands at a path of the batch after it was captured.
            let interference = (rng.next(2) == 0)
                .then(|| batch[rng.next(batch.len() as u64) as usize].path().to_owned())
                .filter(|path| pool.new.contains(path) && interfered.insert(path.clone()))
                .map(|path| chain.put(&path, 240 + round as u8));
            interferences += usize::from(interference.is_some());
            // The batch-level hold refusal is the grouped commit's: a batch with a held path
            // commits nothing there, while the one-delta-per-mutation reference has no such
            // refusal. The reference then skips the batch, and the sides must have refused it.
            let mut subject_refusal: Result<(), String> = Ok(());
            let held_batch = batch.iter().any(|spec| pool.held.iter().any(|p| p == spec.path()));
            let outcomes: Vec<Result<(), String>> = [&subject, &per_path, &reference, &rows_only]
                .iter()
                .map(|side| {
                    if held_batch && std::ptr::eq(*side, &reference) {
                        if let Some(remote) = &interference {
                            side.install_remote(&remote.delta, remote.salt);
                        }
                        return subject_refusal.clone();
                    }
                    let outcome = side
                        .commit(&batch, &evidence, interference.as_ref())
                        .map_err(|e| e.to_string());
                    if std::ptr::eq(*side, &subject) {
                        subject_refusal = outcome.clone();
                    }
                    outcome
                })
                .collect();
            assert!(!held_batch || outcomes[0].is_err(), "a held path was authored: {batch:?}");
            assert_eq!(outcomes[0], outcomes[1], "seed {seed} round {round}: {batch:?}");
            assert_eq!(outcomes[0], outcomes[2], "seed {seed} round {round}: {batch:?}");
            assert_eq!(outcomes[0], outcomes[3], "seed {seed} round {round}: {batch:?}");
            let dump = |side: &Side, skip: &[&str]| {
                side.db.write_immediate::<_, SyncSqliteError>(|tx| Ok(dump_all(tx, skip))).unwrap()
            };
            assert_same(
                &dump(&subject, &[]),
                &dump(&per_path, &[]),
                &format!("per-path chain, seed {seed} round {round}: {batch:?}"),
            );
            assert_same(
                &dump(&subject, &[]),
                &dump(&rows_only, &[]),
                &format!("per-path settlement, seed {seed} round {round}: {batch:?}"),
            );
            assert_same(
                &semantic(dump(&subject, &IDENTITY_COLUMNS)),
                &semantic(dump(&reference, &IDENTITY_COLUMNS)),
                &format!("one delta per mutation, seed {seed} round {round}: {batch:?}"),
            );
        }
    }
    // The batches reached what they were built to: rows written finished, proofs batched, remote
    // heads landing after capture.
    use crate::new_path_rows::tests_support::{PROOFS_BATCHED, ROWS_WRITTEN};
    let (rows, proofs) = (ROWS_WRITTEN.with(|n| n.get()), PROOFS_BATCHED.with(|n| n.get()));
    assert!(rows > 200 && proofs > 200, "{rows} rows and {proofs} proofs went the short way");
    assert!(interferences > 5, "{interferences} remote heads landed after capture");
}

/// A group committed directly, with a held path and a path with a remote head in it, leaves what
/// the per-path chain leaves.
#[test]
fn a_held_path_and_a_remotely_headed_path_in_a_group_mean_what_the_per_path_chain_means() {
    let pool = pool();
    let evidence = Evidence::new(7);
    let (subject, per_path) = (Side::new(Mode::Grouped), Side::new(Mode::GroupedPerPath));
    let deltas = seed_deltas(&pool, &mut RemoteChain::new());
    for side in [&subject, &per_path] {
        seed_state(side, &pool, &evidence, &deltas);
        side.hold("new/f0");
        side.hold("rem/f1");
        let group: Vec<Spec> =
            ["new/f0", "new/f1", "rem/f0", "rem/f1", "scaf/f0", "old/f0", "new/f2"]
                .iter()
                .enumerate()
                .map(|(i, path)| Spec::Put { path: (*path).to_owned(), salt: 50 + i as i64 })
                .collect();
        side.commit_group_directly(&group, &evidence).unwrap();
    }
    let dump = |side: &Side| {
        side.db.write_immediate::<_, SyncSqliteError>(|tx| Ok(dump_all(tx, &[]))).unwrap()
    };
    assert_same(&dump(&subject), &dump(&per_path), "a group with held and headed paths");
}

/// A remotely headed path (a head, no `files` row) in a group with new paths is left to the
/// per-path chain: the shortcut writes only the new paths, and the commit leaves what the per-path
/// chain leaves. Once with a capture that recorded no witness, so only the heads check stands in
/// front of the shortcut, and once with a head admitted after the capture, which the capture's
/// witness never saw.
#[test]
fn a_remotely_headed_path_in_a_group_of_new_paths_is_left_to_the_per_path_chain() {
    use crate::new_path_rows::tests_support::ROWS_WRITTEN;
    let pool = pool();
    let evidence = Evidence::new(7);
    let mut chain = RemoteChain::new();
    let deltas = seed_deltas(&pool, &mut chain);
    let late = chain.put("new/f3", 241);
    // Salts divisible by four record no witness at capture; the others record one.
    let spec = |path: &str, salt: i64| Spec::Put { path: path.to_owned(), salt };
    let unwitnessed =
        [spec("new/f0", 51), spec("rem/f0", 52), spec("new/f1", 53), spec("new/f2", 55)];
    let stale = [spec("new/f4", 57), spec("new/f3", 59), spec("new/f5", 61)];
    let mut dumps = Vec::new();
    let mut outcomes = Vec::new();
    for mode in [Mode::Grouped, Mode::GroupedPerPath] {
        let side = Side::new(mode);
        seed_state(&side, &pool, &evidence, &deltas);
        let before = ROWS_WRITTEN.with(|n| n.get());
        let first = side.commit_group_directly(&unwitnessed, &evidence).map_err(|e| e.to_string());
        let written = ROWS_WRITTEN.with(|n| n.get()) - before;
        if mode == Mode::Grouped {
            assert_eq!(written, 3, "the shortcut writes the three new paths and not rem/f0");
        } else {
            assert_eq!(written, 0, "the per-path side never writes a row the short way");
        }
        let second = side
            .commit_group_directly_after(&stale, &evidence, Some(&late))
            .map_err(|e| e.to_string());
        outcomes.push((first, second));
        dumps.push(
            side.db.write_immediate::<_, SyncSqliteError>(|tx| Ok(dump_all(tx, &[]))).unwrap(),
        );
    }
    assert_eq!(outcomes[0], outcomes[1]);
    assert!(outcomes[0].0.is_ok(), "the group with a headed path commits: {:?}", outcomes[0]);
    assert_same(&dumps[0], &dumps[1], "a headed path among new paths");
}

/// The shortcut takes a new path and leaves every other path of the chunk to the per-path chain:
/// each new path is current at version 1, `Present`, and cites the head it was authored as.
#[test]
fn a_new_path_is_written_as_a_finished_row() {
    let side = Side::new(Mode::Grouped);
    let evidence = Evidence::new(3);
    side.commit(&[Spec::Put { path: "fresh/a".into(), salt: 1 }], &evidence, None).unwrap();
    let row: (i64, String, String, i64, String, String, i64) = side
        .db
        .write_immediate::<_, SyncSqliteError>(|tx| {
            Ok(tx.query_row(
                "SELECT version_seq, state, materialization_state, deleted, record_kind, \
                 xattrs_json, native_authoring_identity IS NOT NULL FROM files \
                 WHERE group_id = 'g1' AND path = 'fresh/a'",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )?)
        })
        .unwrap();
    assert_eq!(row, (1, "current".into(), "present".into(), 0, "file".into(), "[]".into(), 1));
}

/// A path any table the shortcut relies on names is not new.
#[test]
fn a_path_anything_names_is_not_brand_new() {
    let side = Side::new(Mode::Grouped);
    let evidence = Evidence::new(3);
    side.commit(&[Spec::Put { path: "row".into(), salt: 1 }], &evidence, None).unwrap();
    side.scaffold("scaffold");
    side.hold("held");
    side.install_remote(&remote_put(1, None, "headed", 9), 9);
    let candidates = ["row", "scaffold", "held", "headed", "free"];
    let fresh = side
        .db
        .write_immediate::<_, SyncSqliteError>(|tx| {
            crate::new_path_rows::brand_new_paths(tx, "g1", &candidates)
        })
        .unwrap();
    assert_eq!(fresh, std::iter::once("free".to_owned()).collect());
}

/// A new path whose row would show another version than the head it cites is refused as the
/// per-path chain refuses it, and nothing is written.
#[test]
fn a_row_showing_another_version_than_its_head_is_refused_as_the_per_path_chain_refuses_it() {
    let evidence = Evidence::new(2);
    let mut outcomes = Vec::new();
    for mode in [Mode::Grouped, Mode::GroupedPerPath] {
        let side = Side::new(mode);
        let mut mutation = side.prepare(&Spec::Put { path: "liar".into(), salt: 1 }, true);
        if let PreparedLocalMutation::Upsert { op, .. } = &mut mutation {
            *op = Op::Put { path: SyncPath("liar".into()), version: VersionHash([9; 32]) };
        }
        let key = local_key();
        let local = LocalAuthor { author: author_id("device-a"), signing_key: &key, capture: None };
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        let present = Some(evidence.for_spec(&Spec::Put { path: "liar".into(), salt: 1 }, 0));
        let commit = || {
            side.repo.commit_local_mutations_batch(
                "g1",
                std::slice::from_ref(&mutation),
                std::slice::from_ref(&present),
                "device-a",
                SignedEmissionContext { author: &local, permit: &permit },
            )
        };
        let result = if mode == Mode::GroupedPerPath {
            crate::new_path_rows::tests_support::without(commit)
        } else {
            commit()
        };
        let rows: i64 = side
            .db
            .write_immediate::<_, SyncSqliteError>(|tx| {
                Ok(tx.query_row("SELECT COUNT(*) FROM files", [], |r| r.get(0))?)
            })
            .unwrap();
        outcomes.push((result.map_err(|e| e.to_string()), rows));
    }
    assert!(outcomes[0].0.is_err(), "the row shows another version than its head: {outcomes:?}");
    assert_eq!(outcomes[0], outcomes[1]);
}
