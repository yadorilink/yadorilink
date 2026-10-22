use std::collections::{BTreeMap, BTreeSet};

use rusqlite::Connection;

use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind};
use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId, SyncPath, VersionHash};
use yadorilink_replica_domain::native_plan::{
    NativeDesiredNode, NativeLevelPlan, NativePlannedNode,
};
use yadorilink_replica_domain::native_state::{DeltaHash, Dot, HeadPayload, NativeState};

use super::*;

fn group() -> FolderGroupId {
    FolderGroupId("g".to_string())
}

fn conn() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    crate::replica_tables::init(&c).unwrap();
    c
}

fn author(name: &str) -> AuthorId {
    AuthorId { device: DeviceId(name.to_string()), incarnation: IncarnationId([1; 16]) }
}

fn version(kind: RecordKind, mtime: i64) -> FileVersion {
    // A directory version carries no time.
    let mtime = if kind == RecordKind::Directory { 0 } else { mtime };
    FileVersion::new(
        Vec::new(),
        0,
        FileMeta {
            mtime_unix_nanos: mtime,
            unix_mode: Some(0o644),
            symlink_target: None,
            record_kind: kind,
            xattrs: Vec::new(),
        },
    )
}

/// The `n`-th file version in winner order: `file(1)` beats `file(2)`, which
/// beats `file(3)`, because the order of concurrent heads is the version hash.
fn file(n: i64) -> FileVersion {
    let mut pool: Vec<FileVersion> = (1..=16).map(|m| version(RecordKind::File, m)).collect();
    pool.sort_by_key(|v| std::cmp::Reverse(v.version_hash));
    pool.swap_remove(n as usize - 1).clone()
}

fn payload(v: &FileVersion) -> HeadPayload {
    HeadPayload { version: v.version_hash, provenance: DeltaHash(v.version_hash.0) }
}

fn store(c: &Connection, versions: &[&FileVersion]) {
    for v in versions {
        crate::dag_store::put_file_version(c, "g", v).unwrap();
    }
}

fn install(c: &Connection, state: &NativeState) {
    crate::native_store::install_state(c, &group(), state).unwrap();
}

fn level(c: &Connection, parent: &str) -> NativeLevelPlan {
    native_plan_level(c, "g", parent).unwrap()
}

fn entry_version(plan: &NativeLevelPlan, path: &str) -> VersionHash {
    match plan.nodes.get(&SyncPath(path.into())) {
        Some(NativePlannedNode::Entry { head, .. }) => head.version(),
        other => panic!("expected an entry at {path:?}, found {other:?}"),
    }
}

/// Two versions hold a path: it is contested, nothing is planned at it, and
/// nothing is created or removed until the loser's author moves its head.
#[test]
fn a_contested_path_is_not_planned() {
    let c = conn();
    let (win, lose) = (file(1), file(2));
    store(&c, &[&win, &lose]);
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("x".into()), &[], payload(&win)).unwrap();
    state.put(&author("b"), SyncPath("x".into()), &[], payload(&lose)).unwrap();
    install(&c, &state);

    let plan = level(&c, "");
    assert!(plan.nodes.is_empty(), "{plan:?}");
    assert_eq!(plan.contested, BTreeSet::from([SyncPath("x".into())]));
    assert!(matches!(native_plan_path(&c, "g", "x"), Err(SyncSqliteError::NotFound(_))));
    assert!(native_desired_path_state(&c, "g", "x").is_err());
}

/// After the loser's author forks its head, both versions are settled
/// entries, each at its own path.
#[test]
fn a_forked_contest_plans_both_versions_at_their_own_paths() {
    let c = conn();
    let (win, lose) = (file(1), file(2));
    store(&c, &[&win, &lose]);
    let copy = yadorilink_replica_domain::native_fork::copy_path("x", &lose.version_hash);
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("x".into()), &[], payload(&win)).unwrap();
    let loser_dot = state.put(&author("b"), SyncPath("x".into()), &[], payload(&lose)).unwrap();
    state.delete(&author("b"), SyncPath("x".into()), &[loser_dot]).unwrap();
    state.put(&author("b"), SyncPath(copy.clone()), &[], payload(&lose)).unwrap();
    install(&c, &state);

    let plan = level(&c, "");
    assert!(plan.contested.is_empty());
    assert_eq!(plan.nodes.len(), 2);
    assert_eq!(entry_version(&plan, "x"), win.version_hash);
    assert_eq!(entry_version(&plan, &copy), lose.version_hash);
}

#[test]
fn an_unresolvable_version_fails_closed_and_plans_nothing() {
    let c = conn();
    let missing = file(1);
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("x".into()), &[], payload(&missing)).unwrap();
    install(&c, &state);

    let err = native_desired_path_state(&c, "g", "x").unwrap_err();
    assert!(matches!(err, SyncSqliteError::NotFound(_)), "{err:?}");
    assert!(level(&c, "").nodes.is_empty());

    // Once the version is known the same query decides.
    store(&c, &[&missing]);
    assert_eq!(level(&c, "").nodes.len(), 1);
}

#[test]
fn a_descendants_missing_version_does_not_block_its_ancestors_level() {
    let c = conn();
    let dir = version(RecordKind::Directory, 1);
    let missing = file(2);
    store(&c, &[&dir]);
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("d".into()), &[], payload(&dir)).unwrap();
    state.put(&author("a"), SyncPath("d/x".into()), &[], payload(&missing)).unwrap();
    install(&c, &state);

    assert!(level(&c, "").nodes.contains_key(&SyncPath("d".into())));
    assert!(level(&c, "d").contested.contains(&SyncPath("d/x".into())));
}

#[test]
fn the_per_path_state_agrees_with_the_level_on_every_settled_path() {
    let c = conn();
    let (one, two) = (file(1), file(3));
    store(&c, &[&one, &two]);
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("x".into()), &[], payload(&one)).unwrap();
    state.put(&author("a"), SyncPath("y".into()), &[], payload(&two)).unwrap();
    install(&c, &state);

    let tree = level(&c, "");
    for path in ["x", "y", "missing"] {
        let expected = match tree.nodes.get(&SyncPath(path.into())) {
            Some(NativePlannedNode::Entry { head, kind }) => {
                DesiredPathState::Entry { kind: *kind, version: head.version() }
            }
            None => DesiredPathState::Absent,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(native_desired_path_state(&c, "g", path).unwrap(), expected, "{path}");
    }
}

fn obligation(
    c: &Connection,
    path: &str,
) -> Option<crate::projection_obligations::ProjectionObligation> {
    crate::projection_obligations::lookup_projection_obligation(c, "g", path).unwrap()
}

#[test]
fn a_versions_arrival_rearms_exactly_the_paths_that_waited_for_it() {
    let c = conn();
    let (waiting, other) = (file(1), file(2));
    store(&c, &[&other]);
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("waits".into()), &[], payload(&waiting)).unwrap();
    state.put(&author("a"), SyncPath("fine".into()), &[], payload(&other)).unwrap();
    install(&c, &state);
    assert!(
        level(&c, "").contested.contains(&SyncPath("waits".into())),
        "undecidable while the version is missing"
    );
    assert!(obligation(&c, "waits").is_none());

    // The same version arriving twice re-arms once: the second is no news.
    store(&c, &[&waiting]);
    let armed = obligation(&c, "waits").expect("arrival arms the waiting path");
    assert_eq!(armed.invalidation_generation, 1);
    assert!(obligation(&c, "fine").is_none(), "a path that never waited stays untouched");
    store(&c, &[&waiting]);
    assert_eq!(obligation(&c, "waits").unwrap().invalidation_generation, 1);

    assert_eq!(level(&c, "").nodes.len(), 2);
    assert!(level(&c, "").contested.is_empty());
}

#[test]
fn a_delta_arms_its_paths_and_marks_a_local_one_local() {
    use yadorilink_replica_domain::signed_delta::{DeltaOp, NativeDelta};
    let c = conn();
    let delta = NativeDelta {
        recursive_part: None,
        group_id: group(),
        author: author("a"),
        seq: yadorilink_replica_domain::ids::AuthorSeq(1),
        prev: None,
        ops: vec![
            DeltaOp { path: SyncPath("p".into()), removes: Vec::new(), put: None },
            DeltaOp { path: SyncPath("q".into()), removes: Vec::new(), put: None },
        ],
        signature: [0; 64],
    };
    arm_projection_for_delta(&c, "g", &delta, false).unwrap();
    assert_eq!(
        obligation(&c, "p").unwrap().origin,
        crate::projection_obligations::ObligationOrigin::Remote
    );
    arm_projection_for_delta(&c, "g", &delta, true).unwrap();
    let local = obligation(&c, "q").unwrap();
    assert_eq!(local.origin, crate::projection_obligations::ObligationOrigin::Local);
    assert_eq!(local.invalidation_generation, 2);
}

// ---------------------------------------------------------------------
// Randomized-history property checks. There is no second implementation to
// compare with byte for byte -- the projection rule is the reference -- so
// these assert what any correct plan has to satisfy.
// ---------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// The whole plan, gathered level by level from the root through every
/// directory node, with every contested path.
fn whole_plan(c: &Connection) -> (BTreeMap<SyncPath, NativePlannedNode>, BTreeSet<SyncPath>) {
    let mut out = BTreeMap::new();
    let mut contested = BTreeSet::new();
    let mut pending = vec![String::new()];
    while let Some(parent) = pending.pop() {
        let NativeLevelPlan { nodes, contested: here } =
            native_plan_level(c, "g", &parent).unwrap();
        contested.extend(here);
        for (path, node) in nodes {
            if !matches!(node, NativePlannedNode::Entry { .. }) {
                pending.push(path.as_str().to_owned());
            }
            out.insert(path, node);
        }
    }
    (out, contested)
}

#[test]
#[allow(clippy::too_many_lines)] // one scenario driver, read top to bottom
fn randomized_histories_always_yield_a_valid_native_plan() {
    use yadorilink_replica_domain::native_project::{
        blocked_by_pending, contests, project_tree, Projection,
    };
    const PATHS: [&str; 7] = ["a", "a/b", "a/b/c", "d", "d/e", "f", "f/g"];
    let files: Vec<FileVersion> = (1..=6).map(file).collect();
    let dirs: Vec<FileVersion> = vec![version(RecordKind::Directory, 0)];
    let kind_of = |hash: &VersionHash| -> Option<RecordKind> {
        Some(if dirs.iter().any(|d| d.version_hash == *hash) {
            RecordKind::Directory
        } else {
            RecordKind::File
        })
    };

    for seed in 1..=150u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let c = conn();
        store(&c, &files.iter().chain(dirs.iter()).collect::<Vec<_>>());
        let mut state = NativeState::new();
        let mut counter = 0u64;

        for _step in 0..14 {
            let path = SyncPath(PATHS[rng.below(PATHS.len())].to_owned());
            let who = author(["p", "q", "r"][rng.below(3)]);
            let live: Vec<Dot> = state.heads_at(&path).map(|h| h.dot).collect();
            if !live.is_empty() && rng.below(4) == 0 {
                let victim = live[rng.below(live.len())].clone();
                let _ = state.delete(&who, path.clone(), std::slice::from_ref(&victim));
            } else {
                counter += 1;
                let v = if rng.below(5) == 0 { &dirs[0] } else { &files[rng.below(files.len())] };
                let observed: Vec<Dot> = if rng.below(2) == 0 { live } else { Vec::new() };
                let mut p = payload(v);
                let mut provenance = [7u8; 32];
                provenance[..8].copy_from_slice(&counter.to_le_bytes());
                provenance[8..16].copy_from_slice(&seed.to_le_bytes());
                p.provenance = DeltaHash(provenance);
                if state.put(&who, path.clone(), &observed, p).is_err() {
                    continue;
                }
            }
            install(&c, &state);
            let (plan, contested) = whole_plan(&c);
            assert_eq!(whole_plan(&c).0, plan, "seed {seed}: a second evaluation must agree");

            // The planner agrees with the pure projection about what is
            // contested, and plans nothing at or below a contested path.
            let tree = project_tree(&state.heads, kind_of);
            let pending: BTreeSet<SyncPath> =
                contests(&tree).into_iter().map(|contest| contest.path).collect();
            let blocked = blocked_by_pending(&tree);
            for path in plan.keys() {
                assert!(
                    !blocked.contains(path),
                    "seed {seed}: {path:?} is planned under a contest"
                );
                assert!(!pending.contains(path), "seed {seed}: {path:?} is contested but planned");
            }
            assert!(
                contested.iter().all(|path| pending.contains(path)),
                "seed {seed}: contested {contested:?} is not within the contests {pending:?}"
            );

            // Every planned entry names a live head, once, at its own path.
            let mut stood_for: BTreeSet<(SyncPath, Dot)> = BTreeSet::new();
            for (planned_path, node) in &plan {
                if let NativePlannedNode::Entry { head, .. } = node {
                    let live = state
                        .heads
                        .get(&head.source_path)
                        .and_then(|heads| heads.get(head.dot()))
                        .unwrap_or_else(|| {
                            panic!("seed {seed}: {planned_path:?} names a head that is not live")
                        });
                    assert_eq!(live.version, head.version(), "seed {seed}");
                    assert_eq!(live.provenance, head.head.payload.provenance, "seed {seed}");
                    assert_eq!(&head.source_path, planned_path, "seed {seed}");
                    assert!(
                        stood_for.insert((head.source_path.clone(), head.dot().clone())),
                        "seed {seed}: one head stands for two entries ({planned_path:?})"
                    );
                }
            }
            // A settled path is planned as what the projection says.
            for (path, projection) in &tree {
                if blocked.contains(path) {
                    continue;
                }
                match (projection, plan.get(path)) {
                    (Projection::Settled(_), Some(_)) | (Projection::Absent, None) => {}
                    (Projection::Pending(_), None) => {}
                    other => panic!("seed {seed}: {path:?} projects {other:?}"),
                }
            }
            // Every node's parent is a directory node.
            for planned_path in plan.keys() {
                if let Some((parent, _)) = planned_path.as_str().rsplit_once('/') {
                    assert!(
                        matches!(
                            plan.get(&SyncPath(parent.to_owned())),
                            Some(
                                NativePlannedNode::StructuralDirectory
                                    | NativePlannedNode::ExplicitDirectory { .. }
                            )
                        ),
                        "seed {seed}: {planned_path:?} sits under {parent:?}, which is not a directory"
                    );
                }
            }
        }
    }
}

#[test]
fn a_winner_rewritten_with_the_same_content_is_a_different_plan() {
    let c = conn();
    let f = file(1);
    store(&c, &[&f]);
    let a = author("a");
    let mut state = NativeState::new();
    let first = state.put(&a, SyncPath("x".into()), &[], payload(&f)).unwrap();
    install(&c, &state);
    let before = native_plan_level(&c, "g", "").unwrap();
    assert_eq!(native_plan_level(&c, "g", "").unwrap(), before, "same state, same plan");

    // The same content rewritten by a later delta (a new dot): the
    // projection is unchanged, the plan is not -- prepared work must notice.
    let mut state = crate::native_store::load_state(&c, &group()).unwrap();
    state.put(&a, SyncPath("x".into()), std::slice::from_ref(&first), payload(&f)).unwrap();
    install(&c, &state);
    let after = native_plan_level(&c, "g", "").unwrap();
    assert_ne!(after, before);
    assert_eq!(level(&c, "").nodes.len(), 1);
}

#[test]
fn an_explicit_directory_plan_names_its_directory_head() {
    let c = conn();
    let dir = version(RecordKind::Directory, 1);
    store(&c, &[&dir]);
    let mut state = NativeState::new();
    let dot = state.put(&author("a"), SyncPath("d".into()), &[], payload(&dir)).unwrap();
    install(&c, &state);

    match native_plan_path(&c, "g", "d").unwrap() {
        NativeDesiredNode::ExplicitDirectory { head } => {
            assert_eq!((head.source_path.as_str(), head.dot()), ("d", &dot));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(native_plan_path(&c, "g", "nothing").unwrap(), NativeDesiredNode::Absent);
}

#[test]
fn an_unresolvable_version_fails_the_plan_instead_of_planning_an_absence() {
    let c = conn();
    let missing = file(1);
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("x".into()), &[], payload(&missing)).unwrap();
    install(&c, &state);

    assert!(matches!(native_plan_path(&c, "g", "x"), Err(SyncSqliteError::NotFound(_))));
    let plan = native_plan_level(&c, "g", "").unwrap();
    assert!(plan.nodes.is_empty(), "nothing is planned for it");
    assert!(plan.contested.contains(&SyncPath("x".into())));
}

#[test]
fn a_planned_entry_with_no_row_is_a_gap_until_its_row_exists() {
    use yadorilink_replica_domain::file::FileRecord;
    let mut c = conn();
    let (first, second) = (file(1), file(2));
    store(&c, &[&first, &second]);
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("d/x".into()), &[], payload(&first)).unwrap();
    state.put(&author("b"), SyncPath("d/y".into()), &[], payload(&second)).unwrap();
    install(&c, &state);

    // Nothing projected: both paths are owed.
    assert_eq!(
        native_plan_gap_paths(&c, "g").unwrap(),
        BTreeSet::from(["d/x".to_owned(), "d/y".to_owned()])
    );

    let tree = level(&c, "d");
    let tx = c.transaction().unwrap();
    for path in tree.nodes.keys() {
        let record = FileRecord {
            path: path.as_str().to_owned(),
            size: 0,
            mtime_unix_nanos: 1,
            blocks: Vec::new(),
            deleted: false,
        };
        crate::file_index::upsert_file_in_tx(&tx, "g", &record, "a").unwrap();
    }
    tx.commit().unwrap();
    assert!(native_plan_gap_paths(&c, "g").unwrap().is_empty());
}
