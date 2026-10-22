use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::file::{FileMeta, FileRecord, FileVersion, RecordKind};
use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, FolderGroupId, SyncPath, VersionHash};
use yadorilink_replica_domain::local_op::Op;
use yadorilink_replica_domain::rewind::{
    RewindPathAction, RewindPathEntry, RewindPlan, RewindRunState,
};
use yadorilink_replica_domain::session_state::{LocalFileMetaColumns, PreparedLocalMutation};
use yadorilink_replica_domain::signed_delta::{DeltaOp, DeltaPut, NativeDelta};
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sqlite_runtime::SyncDatabase;

use super::*;
use crate::error::SyncSqliteError;
use crate::file_index::{FileIndexRepository, SignedEmissionContext};
use crate::rewind_run::RewindRunRepository;

const GROUP: &str = "g1";

fn author_id(device: &str) -> AuthorId {
    AuthorId { device: DeviceId(device.into()), incarnation: IncarnationId([1u8; 16]) }
}

fn local_key() -> SigningKey {
    SigningKey::from_bytes(&[3u8; 32])
}

fn version(salt: i64) -> FileVersion {
    FileVersion::new(
        Vec::new(),
        0,
        FileMeta {
            mtime_unix_nanos: salt,
            unix_mode: Some(0o644),
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

/// One replica that authors its own edits, as local capture would.
struct Replica {
    db: Arc<SyncDatabase>,
    files: FileIndexRepository,
    runs: RewindRunRepository,
}

impl Replica {
    fn new() -> Self {
        let db = crate::replica_tables::open_for_tests();
        Self {
            files: FileIndexRepository::new(db.clone()),
            runs: RewindRunRepository::new(db.clone()),
            db,
        }
    }

    /// A local edit: `Some(salt)` puts content `salt` at `path`, `None`
    /// deletes it.
    fn edit(&self, path: &str, content: Option<i64>) {
        let key = local_key();
        let local = LocalAuthor { author: author_id("device-a"), signing_key: &key, capture: None };
        let permit = RootCommitPermit::for_tests();
        let witness = self
            .db
            .write_immediate::<_, SyncSqliteError>(|tx| {
                crate::native_capture::capture_native_witness(tx, &group(), path)
            })
            .unwrap();
        let mutation = match content {
            Some(salt) => {
                let version = version(salt);
                PreparedLocalMutation::Upsert {
                    record: FileRecord {
                        path: path.into(),
                        size: 0,
                        mtime_unix_nanos: salt,
                        blocks: Vec::new(),
                        deleted: false,
                    },
                    op: Op::Put { path: SyncPath(path.into()), version: version.version_hash },
                    meta: Some(LocalFileMetaColumns {
                        record_kind: RecordKind::File,
                        symlink_target: None,
                        symlink_out_of_root: false,
                        unix_mode: Some(0o644),
                        xattrs: Vec::new(),
                    }),
                    version,
                    native_witness: Some(witness),
                }
            }
            None => PreparedLocalMutation::Delete {
                record: FileRecord {
                    path: path.into(),
                    size: 0,
                    mtime_unix_nanos: 1,
                    blocks: Vec::new(),
                    deleted: true,
                },
                op: Op::Delete { path: SyncPath(path.into()) },
                native_witness: Some(witness),
            },
        };
        self.files
            .commit_local_mutations_batch(
                GROUP,
                &[mutation],
                &[],
                "device-a",
                SignedEmissionContext { author: &local, permit: &permit },
            )
            .unwrap();
    }

    /// A peer's concurrent put at `path` that superseded nothing here:
    /// admitted (its head is live) but not projected (the row is unchanged).
    fn admit_peer_put(&self, path: &str, content: VersionHash) {
        let key = SigningKey::from_bytes(&[4u8; 32]);
        let mut delta = NativeDelta {
            recursive_part: None,
            group_id: group(),
            author: author_id("device-b"),
            seq: AuthorSeq::FIRST,
            prev: None,
            ops: vec![DeltaOp {
                path: SyncPath(path.into()),
                removes: Vec::new(),
                put: Some(DeltaPut { version: content }),
            }],
            signature: [0u8; 64],
        };
        delta.sign(&key);
        self.db
            .write_immediate::<_, SyncSqliteError>(|tx| {
                crate::native_store::install_verified_delta(
                    tx,
                    &group(),
                    &delta,
                    &key.verifying_key(),
                )
                .map(|_| ())
            })
            .unwrap();
    }

    fn plan(&self, target: i64) -> RewindPlan {
        self.db
            .read::<_, SyncSqliteError>(|conn| {
                crate::rewind_plan::compute_rewind_plan(conn, GROUP, target, &|_| false)
            })
            .unwrap()
    }

    /// The live heads: path and content.
    fn heads(&self) -> Vec<(String, Vec<u8>)> {
        self.db
            .read::<_, SyncSqliteError>(|conn| {
                Ok(rows(conn, "SELECT path, version FROM native_heads ORDER BY path, version"))
            })
            .unwrap()
    }

    /// What a chunk writes: the heads, the deltas and the journal row.
    fn snapshot(&self) -> Snapshot {
        self.db
            .read::<_, SyncSqliteError>(|conn| {
                let deltas: i64 =
                    conn.query_row("SELECT count(*) FROM native_delta_log", [], |r| r.get(0))?;
                let mut stmt =
                    conn.prepare("SELECT state, chunks_done, restored FROM rewind_runs")?;
                let runs = stmt
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok((
                    rows(conn, "SELECT path, version FROM native_heads ORDER BY path, version"),
                    deltas,
                    runs,
                ))
            })
            .unwrap()
    }

    /// A recorded, prefetched run of `plan`.
    fn prefetched_run(&self, plan: &RewindPlan) -> Vec<Vec<RewindPathEntry>> {
        let chunks = rewind_chunks(plan);
        self.runs.begin_run("run", GROUP, plan.target_unix_nanos, &plan.plan_id(), 1).unwrap();
        self.runs.mark_prefetched("run", chunks.len() as u64).unwrap();
        chunks
    }

    fn commit(&self, index: u64, chunk: &[RewindPathEntry], writer: bool) -> RewindChunkOutcome {
        let key = local_key();
        let local = LocalAuthor { author: author_id("device-a"), signing_key: &key, capture: None };
        self.runs
            .commit_chunk(
                "run",
                GROUP,
                index,
                chunk,
                &local,
                &RootCommitPermit::for_tests(),
                writer,
            )
            .unwrap()
    }
}

/// What a chunk writes: the live heads (path, content), the number of
/// deltas, and each run's (state, chunks done, restored).
type Snapshot = (Vec<(String, Vec<u8>)>, i64, Vec<(String, i64, i64)>);

fn group() -> FolderGroupId {
    FolderGroupId(GROUP.into())
}

fn rows(conn: &Connection, sql: &str) -> Vec<(String, Vec<u8>)> {
    let mut stmt = conn.prepare(sql).unwrap();
    let out =
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().map(Result::unwrap).collect();
    out
}

fn now() -> i64 {
    std::thread::sleep(std::time::Duration::from_millis(2));
    let at = crate::file_index::now_unix_nanos_checked().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2));
    at
}

/// `a` edited, `b` deleted and `c` created after the target: one of each
/// action.
fn edited_after_target(replica: &Replica) -> i64 {
    replica.edit("a", Some(1));
    replica.edit("b", Some(2));
    let target = now();
    replica.edit("a", Some(3));
    replica.edit("b", None);
    replica.edit("c", Some(4));
    target
}

#[test]
fn chunks_restore_shallowest_first_then_remove_deepest_first_within_the_bulk_bound() {
    let entry = |path: &str, action| RewindPathEntry {
        path: path.into(),
        current_version_seq: 1,
        current_version_hash: VersionHash([0; 32]),
        action,
    };
    let put = || RewindPathAction::Create { version_seq: 1, version_hash: VersionHash([1; 32]) };
    let plan = RewindPlan {
        group_id: GROUP.into(),
        target_unix_nanos: 1,
        entries: vec![
            entry("d", RewindPathAction::Delete),
            entry("d/x", RewindPathAction::Delete),
            entry("e", put()),
            entry("e/y", put()),
            // A directory turning back into a file: put after what it holds
            // is removed.
            entry(
                "k",
                RewindPathAction::Replace {
                    to_version_seq: 1,
                    to_version_hash: VersionHash([2; 32]),
                },
            ),
            entry("k/z", RewindPathAction::Delete),
            entry("u", RewindPathAction::Unchanged),
        ],
        rename_candidates: Vec::new(),
    };
    let order: Vec<String> =
        rewind_chunks(&plan).into_iter().flatten().map(|entry| entry.path).collect();
    assert_eq!(order, ["e", "e/y", "k/z", "d/x", "d", "k"]);

    let many = RewindPlan {
        entries: (0..2 * BULK_DELTA_MAX_OPS + 1)
            .map(|i| entry(&format!("f{i:05}"), RewindPathAction::Delete))
            .collect(),
        ..plan
    };
    let sizes: Vec<usize> = rewind_chunks(&many).iter().map(Vec::len).collect();
    assert_eq!(sizes, [BULK_DELTA_MAX_OPS, BULK_DELTA_MAX_OPS, 1]);
}

/// A chunk authors ordinary signed changes that leave exactly the target
/// state's heads, and advances the journal in the same transaction.
#[test]
fn a_chunk_authors_exactly_the_plan_and_advances_the_journal() {
    let replica = Replica::new();
    let target = edited_after_target(&replica);
    let plan = replica.plan(target);
    let counts = plan.action_counts();
    assert_eq!((counts.create, counts.replace, counts.delete), (1, 1, 1));
    let chunks = replica.prefetched_run(&plan);
    let (_, deltas_before, _) = replica.snapshot();

    assert_eq!(replica.commit(0, &chunks[0], true), RewindChunkOutcome::Committed { done: true });

    // Exactly the target's content: `a` back to 1, `b` back as 2, no `c`.
    assert_eq!(
        replica.heads(),
        vec![
            ("a".to_string(), version(1).version_hash.0.to_vec()),
            ("b".to_string(), version(2).version_hash.0.to_vec()),
        ]
    );
    let (_, deltas_after, runs) = replica.snapshot();
    assert!(deltas_after > deltas_before, "the rewind is signed changes");
    assert_eq!(runs, vec![("done".to_string(), 1, 2)]);
    let run = replica.runs.get_run("run").unwrap().unwrap();
    assert_eq!((run.state, run.restored, run.deleted), (RewindRunState::Done, 2, 1));
    // The restored version is the historical one, mtime included.
    assert!(replica
        .db
        .read::<_, SyncSqliteError>(|conn| crate::dag_store::get_file_version(
            conn,
            GROUP,
            &version(1).version_hash
        ))
        .unwrap()
        .is_some_and(|stored| stored.meta.mtime_unix_nanos == 1));
}

/// A peer's change admitted after the preview but not in the folder yet
/// (the row still shows the approved version): the chunk commits nothing,
/// and the peer's change stays live.
#[test]
fn an_admitted_unprojected_peer_change_stops_the_chunk_with_nothing_written() {
    let replica = Replica::new();
    let target = edited_after_target(&replica);
    let plan = replica.plan(target);
    let chunks = replica.prefetched_run(&plan);
    replica.admit_peer_put("a", version(99).version_hash);
    let before = replica.snapshot();

    assert_eq!(
        replica.commit(0, &chunks[0], true),
        RewindChunkOutcome::Stopped(RewindChunkStop::FolderChanged { path: "a".into() })
    );
    assert_eq!(replica.snapshot(), before, "the whole chunk rolled back");
    assert!(replica.heads().contains(&("a".to_string(), version(99).version_hash.0.to_vec())));
}

/// Several live heads holding the approved content are one content class:
/// valid, and all of them are superseded.
#[test]
fn a_same_content_head_class_passes_and_is_wholly_superseded() {
    let replica = Replica::new();
    let target = edited_after_target(&replica);
    let plan = replica.plan(target);
    let chunks = replica.prefetched_run(&plan);
    replica.admit_peer_put("a", version(3).version_hash);
    assert_eq!(replica.heads().iter().filter(|(path, _)| path == "a").count(), 2);

    assert_eq!(replica.commit(0, &chunks[0], true), RewindChunkOutcome::Committed { done: true });
    let a: Vec<_> = replica.heads().into_iter().filter(|(path, _)| path == "a").collect();
    assert_eq!(a, vec![("a".to_string(), version(1).version_hash.0.to_vec())]);
}

/// An ordinary edit after the preview advances the row: stopped, nothing
/// written.
#[test]
fn an_edit_after_the_preview_stops_the_chunk() {
    let replica = Replica::new();
    let target = edited_after_target(&replica);
    let plan = replica.plan(target);
    let chunks = replica.prefetched_run(&plan);
    replica.edit("c", Some(5));
    let before = replica.snapshot();
    assert_eq!(
        replica.commit(0, &chunks[0], true),
        RewindChunkOutcome::Stopped(RewindChunkStop::FolderChanged { path: "c".into() })
    );
    assert_eq!(replica.snapshot(), before);
}

/// The commit path's refusals stop the chunk the same way: a held path, or
/// a device that is no longer a writer.
#[test]
fn a_held_path_or_a_lost_writer_role_refuses_the_chunk() {
    let replica = Replica::new();
    let target = edited_after_target(&replica);
    let plan = replica.plan(target);
    let chunks = replica.prefetched_run(&plan);
    let before = replica.snapshot();

    assert!(matches!(
        replica.commit(0, &chunks[0], false),
        RewindChunkOutcome::Stopped(RewindChunkStop::Refused { .. })
    ));
    replica
        .db
        .write_immediate::<_, SyncSqliteError>(|tx| crate::held_path::hold_in_tx(tx, GROUP, "b", 1))
        .unwrap();
    assert!(matches!(
        replica.commit(0, &chunks[0], true),
        RewindChunkOutcome::Stopped(RewindChunkStop::Refused { .. })
    ));
    let (heads, deltas, runs) = replica.snapshot();
    assert_eq!((heads, deltas, runs), before);
}

/// The historical row a restore names is gone (an exclusion erased the
/// path's rows): the chunk fails closed.
#[test]
fn a_restored_version_whose_row_is_gone_stops_the_chunk() {
    let replica = Replica::new();
    let target = edited_after_target(&replica);
    let plan = replica.plan(target);
    let chunks = replica.prefetched_run(&plan);
    replica
        .db
        .write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                "DELETE FROM files WHERE group_id = ?1 AND path = 'a' AND state != 'current'",
                [GROUP],
            )?)
        })
        .unwrap();
    assert_eq!(
        replica.commit(0, &chunks[0], true),
        RewindChunkOutcome::Stopped(RewindChunkStop::FolderChanged { path: "a".into() })
    );
}

/// The journal guards each chunk by its index: a chunk already committed
/// cannot be committed again, so a retried or replayed commit never signs
/// a second change.
#[test]
fn a_chunk_cannot_be_committed_twice() {
    let replica = Replica::new();
    let target = edited_after_target(&replica);
    let plan = replica.plan(target);
    let chunks = rewind_chunks(&plan);
    replica.runs.begin_run("run", GROUP, target, &plan.plan_id(), 1).unwrap();
    // As if the plan had a second chunk still to come.
    replica.runs.mark_prefetched("run", 2).unwrap();
    assert_eq!(replica.commit(0, &chunks[0], true), RewindChunkOutcome::Committed { done: false });
    let after_first = replica.snapshot();

    let key = local_key();
    let local = LocalAuthor { author: author_id("device-a"), signing_key: &key, capture: None };
    let again = replica.runs.commit_chunk(
        "run",
        GROUP,
        0,
        &chunks[0],
        &local,
        &RootCommitPermit::for_tests(),
        true,
    );
    assert!(matches!(again, Err(SyncSqliteError::CorruptState(_))), "{again:?}");
    assert_eq!(replica.snapshot(), after_first, "no second change");

    // A restart finds it mid-way: it needs a new preview, nothing resumes.
    assert_eq!(replica.runs.interrupt_unfinished_runs().unwrap(), 1);
    assert_eq!(replica.runs.get_run("run").unwrap().unwrap().state, RewindRunState::NeedsReplan);
}

/// An interruption after the first chunk leaves the restored content
/// present and nothing removed yet: both copies, never neither. Here the
/// restores fill the first chunk on their own, so after it commits and the
/// run is interrupted, every restore of that chunk is a live head and the
/// paths the rewind would remove are all still there.
#[test]
fn an_interruption_after_the_first_chunk_leaves_restores_present_and_nothing_removed() {
    let replica = Replica::new();
    let restored = BULK_DELTA_MAX_OPS + 3;
    for i in 0..restored {
        replica.edit(&format!("r{i:05}"), Some(i as i64 + 10));
    }
    let target = now();
    for i in 0..restored {
        replica.edit(&format!("r{i:05}"), None);
    }
    for junk in ["x1.locked", "x2.locked"] {
        replica.edit(junk, Some(7));
    }
    let plan = replica.plan(target);
    let counts = plan.action_counts();
    assert_eq!((counts.create, counts.delete), (restored as u64, 2));
    let chunks = replica.prefetched_run(&plan);
    assert_eq!(chunks.len(), 2);
    assert!(
        chunks[0].iter().all(|entry| matches!(entry.action, RewindPathAction::Create { .. })),
        "the first chunk restores only"
    );

    assert_eq!(replica.commit(0, &chunks[0], true), RewindChunkOutcome::Committed { done: false });
    assert_eq!(replica.runs.interrupt_unfinished_runs().unwrap(), 1);
    assert_eq!(replica.runs.get_run("run").unwrap().unwrap().state, RewindRunState::NeedsReplan);

    let heads = replica.heads();
    let live = |path: &str| heads.iter().any(|(head, _)| head == path);
    assert!(chunks[0].iter().all(|entry| live(&entry.path)), "restored content is present");
    assert!(live("x1.locked") && live("x2.locked"), "nothing removed yet");
}
